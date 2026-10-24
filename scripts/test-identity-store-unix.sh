#!/usr/bin/env bash
set -euo pipefail
# This entry point is limited to fresh GitHub-hosted VM fixtures.
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'A disposable GitHub-hosted runner is required.' >&2; exit 1;
}
[[ $# == 3 && $1 =~ ^(race|minimum|native)$ && $2 =~ ^(linux|darwin)$ && $3 =~ ^(amd64|arm64)$ ]] || exit 2
script_path=$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")
python_path=$(command -v python3)
if [[ $(id -u) != 0 ]]; then
  proof_path=$(mktemp -d "${RUNNER_TEMP:?}/ca8-store-proof.XXXXXXXX")
  printf 'evidence-path=%s\n' "$proof_path" >> "${GITHUB_OUTPUT:?}"
  exec sudo -n /usr/bin/env \
    "PATH=$PATH" "GITHUB_ACTIONS=$GITHUB_ACTIONS" \
    "RUNNER_ENVIRONMENT=$RUNNER_ENVIRONMENT" "CA8_PROOF_PATH=$proof_path" \
    "$python_path" - "$script_path" "$@" <<'PY'
import ctypes, errno, hashlib, json, os, pathlib, platform, plistlib, pwd
import re, selectors, shutil, signal, stat, struct, subprocess, sys, time, uuid

script, profile, expected_os, expected_arch = sys.argv[1:]
started = time.monotonic()
outer_deadline = started + 800
proof = pathlib.Path(os.environ['CA8_PROOF_PATH'])
caller_uid = int(os.environ.get('SUDO_UID', '-1'))
if os.geteuid() != 0 or caller_uid <= 0 or pwd.getpwuid(caller_uid).pw_uid != caller_uid:
    raise SystemExit('An actual elevated disposable caller and a different existing UID are required.')
if not proof.is_absolute() or proof.resolve() != proof or not proof.name.startswith('ca8-store-proof.'):
    raise SystemExit('Invalid owned proof location.')
initial = proof.stat()
if not stat.S_ISDIR(initial.st_mode) or initial.st_uid != caller_uid or stat.S_IMODE(initial.st_mode) != 0o700:
    raise SystemExit('Invalid actual proof owner or mode.')
os.umask(0o077)
root = pathlib.Path(script).resolve().parents[1]
actual_os = {'Linux':'linux', 'Darwin':'darwin'}.get(platform.system())
actual_arch = {'x86_64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(platform.machine())
if actual_os == 'darwin':
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    translated = ctypes.c_int(0); length = ctypes.c_size_t(ctypes.sizeof(translated))
    library.sysctlbyname.argtypes = [ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
    library.sysctlbyname.restype = ctypes.c_int
    queried = library.sysctlbyname(b'sysctl.proc_translated',ctypes.byref(translated),ctypes.byref(length),None,0)
    if queried == 0 and translated.value != 0: raise SystemExit('Emulated processes receive no native qualification.')
    if queried != 0 and ctypes.get_errno() != errno.ENOENT: raise SystemExit('Native architecture could not be checked.')
if (actual_os, actual_arch) != (expected_os, expected_arch):
    raise SystemExit('The actual native OS/architecture differs from the job target.')
nonce = uuid.uuid4().hex
mount = pathlib.Path('/Volumes' if actual_os == 'darwin' else '/') / ('ca8-store-run-' + nonce)
backing = proof / 'volume'
backing.mkdir(mode=0o700)
image = backing / ('fixture.sparseimage' if actual_os == 'darwin' else 'fixture.ext4')
steps, groups, native_rows, process_observers = [], [], [], []
mounted = False
volume_device = None
success = False
failure = None
index_before = None
index_owner_mode_preserved = False
source_hashes = {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in ['go.mod','go.sum']}
base_env = {k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','LC_ALL','TZ']}
base_env.update({'GOTOOLCHAIN':'local', 'GOENV':'off', 'GOWORK':'off',
                 'GOPRIVATE':'', 'GONOPROXY':'', 'GONOSUMDB':'',
                 'GOPROXY':'https://proxy.golang.org', 'GOSUMDB':'sum.golang.org',
                 'GIT_TERMINAL_PROMPT':'0', 'GIT_CONFIG_NOSYSTEM':'1',
                 'GIT_CONFIG_GLOBAL':'/dev/null',
                 'GIT_CONFIG_COUNT':'1', 'GIT_CONFIG_KEY_0':'safe.directory',
                 'GIT_CONFIG_VALUE_0':str(root), 'GIT_OPTIONAL_LOCKS':'0'})

def save(name, value):
    (proof/name).write_text(json.dumps(value, indent=2)+'\n')

def checkout_index_metadata():
    directory = root / '.git'
    if not stat.S_ISDIR(directory.lstat().st_mode): raise RuntimeError('Exact checkout Git directory required.')
    index = directory / 'index'
    info = index.lstat()
    if not stat.S_ISREG(info.st_mode): raise RuntimeError('Exact regular checkout index required.')
    return {'path':str(index),'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode)),
            'device':info.st_dev,'inode':info.st_ino,'links':info.st_nlink,'bytes':info.st_size,
            'mtimeNs':info.st_mtime_ns,'ctimeNs':info.st_ctime_ns}

def group_alive(pgid):
    try: os.killpg(pgid, 0); return True
    except ProcessLookupError: return False

# ps supplies only numeric PID/PPID/UID candidates. Native getsid/getpgid own association.
# The observer runs outside the test session and never receives fixture paths.
def process_inventory():
    observer = subprocess.Popen(['/bin/ps','-axo','pid=,ppid=,uid='], env=base_env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True)
    selector = selectors.DefaultSelector()
    raw = bytearray()
    outcome = {'pid':observer.pid,'sid':observer.pid,'empty':False,'status':None}
    process_observers.append(outcome)
    failure = None
    try:
        os.set_blocking(observer.stdout.fileno(),False)
        selector.register(observer.stdout,selectors.EVENT_READ)
        until = time.monotonic()+1
        while selector.get_map():
            if time.monotonic() >= until: raise RuntimeError('Process observation deadline expired.')
            for key, _ in selector.select(.02):
                chunk = os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj); continue
                if len(raw)+len(chunk) > 1024*1024: raise RuntimeError('Process inventory byte bound reached.')
                raw.extend(chunk)
        observer.wait(timeout=max(.001,until-time.monotonic()))
        if observer.returncode != 0: raise RuntimeError('Actual process inventory failed.')
    except BaseException as error:
        failure = error
    finally:
        # This fixed ps executable creates no children. Its own group is distinct.
        for sig in [signal.SIGTERM,signal.SIGKILL]:
            if observer.poll() is None:
                try:
                    if os.getsid(observer.pid) != observer.pid: raise RuntimeError('Process observer session changed.')
                    os.killpg(observer.pid,sig)
                except ProcessLookupError: pass
                except BaseException as error: failure = failure or error
            try: observer.wait(timeout=.25)
            except subprocess.TimeoutExpired: pass
        try: outcome['empty'] = not group_alive(observer.pid)
        except BaseException as error: failure = failure or error
        outcome['status'] = observer.poll()
        selector.close(); observer.stdout.close()
        if not outcome['empty']: failure = failure or RuntimeError('Process observer cleanup is uncertain.')
        outcome['failure'] = None if failure is None else str(failure)
        save('process-observers.json',process_observers)
    if failure is not None: raise failure
    rows = []
    seen = set()
    for line in raw.decode('ascii',errors='strict').splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdecimal() for field in fields[:2]) or not fields[2].removeprefix('-').isdecimal():
            raise RuntimeError('Uncertain PID/PPID inventory.')
        pid, ppid, uid = map(int,fields)
        if pid <= 0 or ppid < 0 or not -(1 << 31) <= uid < (1 << 32) or pid in seen: raise RuntimeError('Invalid PID/PPID inventory.')
        seen.add(pid); rows.append((pid,ppid,uid))
        if len(rows) > 65536: raise RuntimeError('Process inventory row bound reached.')
    return rows

def owned_session_members(session_id):
    if session_id <= 1 or session_id == os.getsid(0): raise RuntimeError('Refuse an unowned supervisor session.')
    rows = []
    until = time.monotonic()+1
    for pid, ppid, uid in process_inventory():
        # The wrapper is root and queries every UID. The proposed ordinary qualifier
        # creates only same-UID children and needs no access to other users' sessions.
        if os.geteuid() != 0 and uid % (1 << 32) != os.geteuid(): continue
        if time.monotonic() >= until: raise RuntimeError('Native session observation deadline expired.')
        try:
            sid = os.getsid(pid)
            if sid != session_id: continue
            pgid = os.getpgid(pid)
            # Recheck association after collecting the process group.
            if os.getsid(pid) != session_id: raise RuntimeError('Owned session association changed.')
        except ProcessLookupError: continue
        rows.append({'pid':pid,'ppid':ppid,'uid':uid,'reportedUID':uid,'pgid':pgid,'sid':sid})
        if len(rows) > 4096: raise RuntimeError('Owned session member bound reached.')
    return sorted(rows,key=lambda row:row['pid'])

def finish_session(process, session):
    observations, signals = [], []
    session.update({'observations':observations,'signals':signals})
    started = time.monotonic()
    prior_empty = False
    try:
        for _ in range(24):
            if time.monotonic()-started >= 5: break
            # Reap only the owned leader. Separate-PGID actors remain observable by SID.
            process.poll()
            members = owned_session_members(session['sid'])
            observations.append({'atMonotonic':time.monotonic(),'members':members})
            if not members:
                if prior_empty:
                    session['empty'] = all(row['empty'] for row in process_observers)
                    break
                prior_empty = True
            else:
                prior_empty = False
                sig = signal.SIGTERM if time.monotonic()-started < .5 else signal.SIGKILL
                for member in members:
                    pid = member['pid']
                    try:
                        sid = os.getsid(pid)
                        pgid = os.getpgid(pid)
                        if sid != session['sid']: raise RuntimeError('Owned process changed session before signal.')
                        os.kill(pid,sig)
                        signals.append({'pid':pid,'observedPPID':member['ppid'],'pgid':pgid,'sid':sid,'signal':int(sig)})
                    except ProcessLookupError: pass
            if time.monotonic()-started >= 5: break
            time.sleep(.02)
        if not session['empty']: session['failure'] = 'Owned session did not reach two complete empty observations.'
    except BaseException as error:
        session['failure'] = str(error)
        session['empty'] = False
    session['leaderStatus'] = process.poll()
    session['scope'] = 'Actual native actors retain the launched POSIX SID even when Setpgid selects a separate PGID.'
    save('groups.json',groups)
    return session['empty']

def run(argv, limit=30, env=None, capture=False, monitor_volume=True):
    if time.monotonic() >= outer_deadline: raise RuntimeError('Outer process deadline expired.')
    number = len(steps)
    if number >= 24: raise RuntimeError('Owned stage count bound reached.')
    executable = pathlib.Path(argv[0]).resolve(strict=True)
    row = {'argv':argv, 'executableSHA256':hashlib.sha256(executable.read_bytes()).hexdigest(), 'limitSeconds':limit, 'startMonotonic':time.monotonic()}
    steps.append(row); save('stages.json', steps)
    process = subprocess.Popen(argv, cwd=root, env=env or base_env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    session = {'sid':process.pid,'leaderPID':process.pid,'expectedRootPGID':process.pid,'launchMechanism':'Popen(start_new_session=True)','empty':False}
    groups.append(session); save('groups.json',groups)
    selector = selectors.DefaultSelector()
    streams = {}
    raw = bytearray()
    for name, stream in [('stdout',process.stdout), ('stderr',process.stderr)]:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
        streams[name] = [(proof/f'{number:02d}.{name}').open('wb'), 0]
    reason = None
    deadline = min(outer_deadline, time.monotonic()+limit)
    try:
        while selector.get_map():
            if time.monotonic() >= deadline: reason = 'PROCESS_DEADLINE'; break
            if mounted and monitor_volume and shutil.disk_usage(mount).free < 128*1024*1024:
                reason = 'OWNED_VOLUME_SPACE_FLOOR'; break
            if sum(v[1] for v in streams.values()) > 128*1024*1024:
                reason = 'OUTPUT_LIMIT'; break
            for key, _ in selector.select(.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk: selector.unregister(key.fileobj); continue
                stream = streams[key.data]
                remaining = 64*1024*1024-stream[1]
                stream[0].write(chunk[:max(0,remaining)]); stream[1] += len(chunk)
                if capture and key.data == 'stdout':
                    if len(raw)+len(chunk) > 4*1024*1024: reason = 'CAPTURE_LIMIT'; break
                    raw.extend(chunk)
                if stream[1] > 64*1024*1024: reason = 'OUTPUT_LIMIT'; break
            if reason: break
        if not reason:
            try: process.wait(timeout=max(.001, deadline-time.monotonic()))
            except subprocess.TimeoutExpired: reason = 'PROCESS_DEADLINE'
    finally:
        empty = finish_session(process,session)
        selector.close()
        for stream in streams.values(): stream[0].close()
        process.stdout.close(); process.stderr.close()
        row.update({'status':process.poll(),'reason':reason,'ownedSessionEmpty':empty,
                    'stdoutBytes':streams['stdout'][1], 'stderrBytes':streams['stderr'][1]})
        save('stages.json', steps); save('groups.json', groups)
    if reason or row['status'] != 0 or not empty: raise RuntimeError('A bounded stage failed; see raw evidence.')
    return bytes(raw)

def darwin_acl(fd, private):
    class Request(ctypes.Structure):
        _fields_ = [('maps',ctypes.c_uint16),('reserved',ctypes.c_uint16),
                    ('common',ctypes.c_uint32),('volume',ctypes.c_uint32),
                    ('directory',ctypes.c_uint32),('file',ctypes.c_uint32),('fork',ctypes.c_uint32)]
    if ctypes.sizeof(Request) != 24 or ctypes.sizeof(ctypes.c_void_p) != 8: raise RuntimeError('Unsupported Apple LP64 ABI.')
    api = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    api.fgetattrlist.argtypes = [ctypes.c_int32,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32]
    api.fgetattrlist.restype = ctypes.c_int32
    request, buffer = Request(5,0,0x00400000,0,0,0,0), ctypes.create_string_buffer(4096)
    if api.fgetattrlist(fd,ctypes.byref(request),buffer,4096,4) != 0: raise RuntimeError('Native ACL read failed.')
    data = buffer.raw
    total, offset, length = struct.unpack_from('<IiI',data)
    if not 12 <= total <= 4096: raise RuntimeError('Invalid ACL length.')
    if length == 0:
        if total != 12 or offset not in [0,8]: raise RuntimeError('Invalid absent ACL.')
        return data[:total].hex()
    start = 4+offset
    if offset < 8 or length < 44 or start+length != total: raise RuntimeError('Invalid native ACL span.')
    payload = data[start:total]
    magic, = struct.unpack_from('<I',payload)
    count, flags = struct.unpack_from('<II',payload,36)
    if magic != 0x012cc16d or flags & ~0x00030000: raise RuntimeError('Unknown ACL metadata.')
    if count == 0xffffffff: count = 0
    if count > 128 or len(payload) != 44+count*24: raise RuntimeError('Invalid ACL entries.')
    api.mbr_uid_to_uuid.argtypes = [ctypes.c_uint32,ctypes.c_void_p]
    api.mbr_uid_to_uuid.restype = ctypes.c_int32
    owner = ctypes.create_string_buffer(16)
    if api.mbr_uid_to_uuid(0,owner) != 0 or owner.raw == bytes(16): raise RuntimeError('Native root UUID unavailable.')
    read_rights = sum(1<<bit for bit in [1,3,7,9,11,20])
    for position in range(44,len(payload),24):
        principal = payload[position:position+16]
        entry_flags, rights = struct.unpack_from('<II',payload,position+16)
        kind = entry_flags & 15
        if kind not in [1,2] or entry_flags & ~0x1ff: raise RuntimeError('Unsupported ACL entry.')
        if kind == 1 and (private or rights & ~read_rights) and rights and principal != owner.raw:
            raise RuntimeError('Untrusted ancestor ACL mutation grant.')
    return data[:total].hex()

def inspect_chain(path, private=False):
    path = pathlib.Path(path)
    if not path.is_absolute() or path.resolve() != path: raise RuntimeError('Noncanonical fixture chain.')
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        parts = path.parts[1:]
        for index, name in enumerate(['']+list(parts)):
            if name:
                child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022 or info.st_mode & (stat.S_ISUID|stat.S_ISGID):
                raise RuntimeError('Unsafe actual fixture ancestor.')
            if private and index == len(parts) and stat.S_IMODE(info.st_mode) != 0o700: raise RuntimeError('Fixture root is not private.')
            if actual_os == 'darwin': acl = darwin_acl(fd,private and index == len(parts))
            else:
                try: acl = os.getxattr(fd,'system.posix_acl_access').hex()
                except OSError as error:
                    if error.errno != errno.ENODATA: raise
                    acl = None
            after = os.fstat(fd)
            if (info.st_dev,info.st_ino,info.st_uid,info.st_mode) != (after.st_dev,after.st_ino,after.st_uid,after.st_mode):
                raise RuntimeError('Fixture changed during native inspection.')
            native_rows.append({'path':str(pathlib.Path('/').joinpath(*parts[:index])), 'uid':info.st_uid,
                                'mode':oct(stat.S_IMODE(info.st_mode)), 'device':info.st_dev,'inode':info.st_ino,'acl':acl})
            save('native-inspection.json',native_rows)
    finally: os.close(fd)

try:
    index_before = checkout_index_metadata()
    save('checkout-index-before.json',index_before)
    inspect_chain(mount.parent)
    mount.mkdir(mode=0o700)
    if actual_os == 'linux':
        with image.open('xb') as file: file.truncate(4*1024*1024*1024)
        run(['/usr/sbin/mkfs.ext4','-q','-F',str(image)])
        volume_device = run(['/usr/sbin/losetup','--find','--show','--nooverlap',str(image)],capture=True).decode().strip()
        if not re.fullmatch(r'/dev/loop[0-9]+',volume_device): raise RuntimeError('Invalid owned loop device.')
        run(['/bin/mount','-o','nodev,nosuid',volume_device,str(mount)])
        mounted = True
        filesystem = json.loads(run(['/usr/bin/findmnt','--json','--target',str(mount),'--output','SOURCE,FSTYPE,TARGET'],capture=True))['filesystems']
        if len(filesystem) != 1 or filesystem[0] != {'source':volume_device,'fstype':'ext4','target':str(mount)}: raise RuntimeError('Owned ext4 mount mismatch.')
    else:
        run(['/usr/bin/hdiutil','create','-size','4g','-fs','APFS','-type','SPARSE','-volname','ca8-store-'+nonce,str(image)])
        attached = plistlib.loads(run(['/usr/bin/hdiutil','attach','-nobrowse','-owners','on','-mountpoint',str(mount),'-plist',str(image)],capture=True))
        entities = attached['system-entities']
        whole_devices = [entity['dev-entry'] for entity in entities if entity.get('content-hint') == 'GUID_partition_scheme']
        mounted_devices = [entity['dev-entry'] for entity in entities if entity.get('mount-point') == str(mount) and entity.get('volume-kind') == 'apfs']
        if len(whole_devices) != 1 or len(mounted_devices) != 1: raise RuntimeError('Ambiguous owned image attachment.')
        volume_device, mounted_device = whole_devices[0], mounted_devices[0]
        if not re.fullmatch(r'/dev/disk[0-9]+',volume_device) or not re.fullmatch(r'/dev/disk[0-9]+s[0-9]+',mounted_device): raise RuntimeError('Invalid owned image device.')
        mounted = True
        filesystem = plistlib.loads(run(['/usr/sbin/diskutil','info','-plist',str(mount)],capture=True))
        if filesystem.get('FilesystemType') != 'apfs' or filesystem.get('GlobalPermissionsEnabled') is not True or filesystem.get('MountPoint') != str(mount) or filesystem.get('DeviceNode') != mounted_device: raise RuntimeError('Owned APFS mount mismatch.')
    fixture = mount/('ca8-store-fixtures-'+nonce[:8]); fixture.mkdir(mode=0o700)
    evidence = mount/('ca8-store-evidence-'+nonce); evidence.mkdir(mode=0o700)
    temporary = mount/'tmp'; temporary.mkdir(mode=0o700)
    for directory in [fixture,evidence,temporary]: inspect_chain(directory,True)
    if any((parent/'node_modules').exists() for parent in [temporary,*temporary.parents]): raise RuntimeError('The external temporary chain contains node_modules.')
    cache = mount/'cache'; cache.mkdir(mode=0o700)
    base_env.update({'GOPATH':str(cache/'go'),'GOMODCACHE':str(cache/'modules'),'GOCACHE':str(cache/'build'),
                     'GOTMPDIR':str(temporary),'TMPDIR':str(temporary),'TMP':str(temporary),'TEMP':str(temporary),
                     'XDG_CACHE_HOME':str(cache/'xdg'),'NODE_COMPILE_CACHE':str(cache/'node'),
                     'OE_IDENTITY_STORE_FIXTURE_ROOT':str(fixture),'OE_IDENTITY_STORE_EVIDENCE_ROOT':str(evidence),
                     'OE_IDENTITY_STORE_PRIVILEGED_FIXTURES':'1','OE_IDENTITY_STORE_FOREIGN_UID':str(caller_uid),'OE_OPERATION_ID':''})
    go = shutil.which('go',path=base_env['PATH'])
    if not go: raise RuntimeError('The installed Go tool is missing.')
    save('native.json',{'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups(),'foreignUID':caller_uid,
                       'os':actual_os,'arch':actual_arch,'platform':platform.platform(),'filesystem':filesystem,
                       'ancestors':native_rows,'goPath':go,'goSHA256':hashlib.sha256(pathlib.Path(go).read_bytes()).hexdigest(),
                       'profile':profile,'sourceHashes':source_hashes,'volumeBytes':4*1024*1024*1024})
    host = json.loads(run([go,'env','-json','GOHOSTOS','GOHOSTARCH','GOVERSION'],capture=True))
    version = 'go1.26.10' if profile == 'minimum' else 'go1.27.3'
    if (host['GOHOSTOS'],host['GOHOSTARCH'],host['GOVERSION']) != (expected_os,expected_arch,version): raise RuntimeError('Go host/version is not the exact native target.')
    save('go-host.json',host)
    node = shutil.which('node',path=base_env['PATH'])
    if not node or run([node,'--version'],capture=True).decode().strip() != 'v24.22.1': raise RuntimeError('The maintained Node version is required.')
    git = shutil.which('git',path=base_env['PATH'])
    if not git: raise RuntimeError('The installed Git tool is missing.')
    tracked = run([git,'-c','safe.directory='+str(root),'ls-files','-z'],capture=True).decode().split('\0')
    source_files = {}
    for name in tracked:
        if not name: continue
        path = root/name
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents: raise RuntimeError('Uncertain tracked source input.')
        source_files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    save('source-inputs.json',{'head':run([git,'-c','safe.directory='+str(root),'rev-parse','HEAD'],capture=True).decode().strip(),'files':source_files, 'python':sys.version,'pythonSHA256':hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest()})
    run([go,'mod','download','-json'],120)
    if any(hashlib.sha256((root/p).read_bytes()).hexdigest() != value for p,value in source_hashes.items()): raise RuntimeError('Module preparation changed a frozen source file.')
    base_env.update({'GOPROXY':'off','GOSUMDB':'off','GOFLAGS':'-mod=readonly'})
    if profile == 'race':
        compiler = shutil.which('cc',path=base_env['PATH'])
        if actual_os != 'darwin' and not compiler: raise RuntimeError('An installed race compiler is required.')
        if compiler: base_env['CC'] = compiler
        base_env['CGO_ENABLED'] = '1'
        run([go,'test','-count=1','-json','-race','-timeout=9m','./...'],600)
    else:
        base_env['CGO_ENABLED'] = '0'
        run([go,'test','-count=1','-json','-timeout=9m','./...' if profile == 'minimum' else './internal/identityattempt'],600)
    if profile == 'minimum':
        for target_os in ['darwin','linux','windows']:
            for target_arch in ['amd64','arm64']:
                env = dict(base_env, GOOS=target_os,GOARCH=target_arch)
                run([go,'build','-trimpath','-o',str(cache/('oe-'+target_os+'-'+target_arch)),'./cmd/oe'],120,env)
    if any(hashlib.sha256((root/p).read_bytes()).hexdigest() != value for p,value in source_hashes.items()): raise RuntimeError('Module files changed.')
    success = True
except BaseException as error:
    failure = str(error)
finally:
    empty = all(row['empty'] for row in groups) and all(row['empty'] for row in process_observers)
    try: mounted = mounted or os.path.ismount(mount)
    except OSError as error: success = False; failure = (failure or '')+'; mount readback: '+str(error)
    if mounted and empty:
        try:
            if 'evidence' in globals(): shutil.copytree(evidence,proof/'native-evidence')
            if not success and 'fixture' in globals():
                # Only regular owned fixture files enter the bounded failure snapshot.
                copied = 0; snapshot = proof/'failed-fixtures'; snapshot.mkdir(mode=0o700)
                for path in sorted(fixture.rglob('*')):
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode): continue
                    copied += info.st_size
                    if copied > 128*1024*1024: raise RuntimeError('Failure snapshot bound reached; volume preserved.')
                    target = snapshot/path.relative_to(fixture); target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(path,target,follow_symlinks=False)
            if success:
                run((['/bin/umount',str(mount)] if actual_os == 'linux' else ['/usr/bin/hdiutil','detach',volume_device]),20,monitor_volume=False)
                if os.path.ismount(mount): raise RuntimeError('Owned mount remains after successful detach.')
                mounted = False
                if actual_os == 'linux': run(['/usr/sbin/losetup','--detach',volume_device],20)
                try: mount.rmdir()
                except FileNotFoundError:
                    if actual_os != 'darwin': raise
                shutil.rmtree(backing)
        except BaseException as error:
            success = False; failure = (failure or '')+'; cleanup: '+str(error)
    try:
        index_after = checkout_index_metadata()
        save('checkout-index-after.json',index_after)
        index_owner_mode_preserved = index_before is not None and all(index_before[key] == index_after[key] for key in ['uid','gid','mode'])
        save('checkout-index-preservation.json',{'ownerModePreserved':index_owner_mode_preserved,
             'changedFields':[] if index_before is None else [key for key in index_before if index_before[key] != index_after[key]]})
        if not index_owner_mode_preserved: raise RuntimeError('Checkout index owner or mode changed.')
    except BaseException as error:
        success = False; failure = (failure or '')+'; checkout index readback: '+str(error)
    empty = all(row['empty'] for row in groups) and all(row['empty'] for row in process_observers)
    success = success and empty
    save('result.json',{'success':success,'failure':failure,'groups':groups,'processObservers':process_observers,'ownedSessionsEmpty':empty,'mountedOwnedVolumePreserved':mounted,
                        'volumeDevice':volume_device,'mount':str(mount),'elapsedSeconds':time.monotonic()-started,
                        'checkoutIndexOwnerModePreserved':index_owner_mode_preserved,
                        'limits':'No ordinary-user/default-root, ENOSPC, hosted caller or hard-kernel-deadline qualification.'})
    # All files are new proof objects. Their final owner permits the runner's artifact step.
    for path in sorted(proof.rglob('*'),reverse=True):
        if path.is_symlink(): raise RuntimeError('Unexpected proof link.')
        os.chown(path,caller_uid,-1)
    os.chown(proof,caller_uid,-1)
raise SystemExit(0 if success else 1)
PY
fi
echo 'Run this wrapper as the disposable runner account; it elevates its own fixture process.' >&2
exit 1
