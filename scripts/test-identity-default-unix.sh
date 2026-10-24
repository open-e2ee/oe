#!/usr/bin/env bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'A fresh disposable GitHub-hosted VM is required.' >&2; exit 1;
}
[[ $# == 2 && $1 =~ ^(linux|darwin)$ && $2 =~ ^(amd64|arm64)$ && $(id -u) != 0 ]] || exit 2
script_path=$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")
exec python3 - "$script_path" "$@" <<'PY'
import ctypes, errno, hashlib, importlib.util, json, os, pathlib, platform, pwd
import re, shutil, stat, sys, time, uuid

script, expected_os, expected_arch = sys.argv[1:]
started = time.monotonic()
deadline = started+450
uid, gid = os.getuid(), os.getgid()
account = pwd.getpwuid(uid)
if uid <= 0 or uid != os.geteuid() or gid != os.getegid():
    raise SystemExit('An actual ordinary login identity is required.')
if os.environ.get('HOME') != account.pw_dir:
    raise SystemExit('Inherited HOME differs from the actual account record.')
actual_os = {'Linux':'linux','Darwin':'darwin'}.get(platform.system())
actual_arch = {'x86_64':'amd64','arm64':'arm64','aarch64':'arm64'}.get(platform.machine())
if (actual_os,actual_arch) != (expected_os,expected_arch):
    raise SystemExit('The native host differs from the requested target.')
if actual_os == 'darwin':
    native = ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    native.sysctlbyname.argtypes = [ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
    native.sysctlbyname.restype = ctypes.c_int
    translated = ctypes.c_int(); size = ctypes.c_size_t(ctypes.sizeof(translated))
    result = native.sysctlbyname(b'sysctl.proc_translated',ctypes.byref(translated),ctypes.byref(size),None,0)
    if result == 0 and translated.value or result != 0 and ctypes.get_errno() != errno.ENOENT:
        raise SystemExit('A native untranslated process is required.')
root = pathlib.Path(script).resolve().parents[1]
nonce = uuid.uuid4().hex
proof = pathlib.Path(os.environ['RUNNER_TEMP'])/('ca8-default-proof-'+nonce)
proof.mkdir(mode=0o700)
artifact = proof/'artifact'; artifact.mkdir(mode=0o700)
with open(os.environ['GITHUB_OUTPUT'],'a') as output:
    output.write('evidence-path='+str(artifact)+'\n')
os.umask(0o077)
environment = {key:value for key,value in os.environ.items() if key in ['PATH','HOME','XDG_CONFIG_HOME','LANG','LC_ALL','TZ']}
cache = proof/'cache'; cache.mkdir(mode=0o700)
temporary = proof/'temporary'; temporary.mkdir(mode=0o700)
environment.update({'GOTOOLCHAIN':'local','GOENV':'off','GOWORK':'off','CGO_ENABLED':'0',
    'GOPATH':str(cache/'go'),'GOMODCACHE':str(cache/'modules'),'GOCACHE':str(cache/'build'),
    'GOTMPDIR':str(temporary),'TMPDIR':str(temporary),'GOPRIVATE':'','GONOPROXY':'','GONOSUMDB':'',
    'GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org','GOVCS':'off','OE_OPERATION_ID':''})
environment.update({'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':str(root),
    'GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'})
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('identity_qualification_session',root/'scripts/identity-qualification-session.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
supervisor = module.IdentitySessionController(root,proof,environment,deadline,
    stream_limit=16*1024*1024,combined_limit=32*1024*1024,stage_limit=8)
success = False
failure = None
handoff_verified = False
source = {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['go.mod','go.sum']}
def save(name,value):
    (proof/name).write_text(json.dumps(value,indent=2)+'\n')
def owned_closed():
    return (all(row.get('ownedSessionEmpty') is True for row in supervisor.steps)
        and all(row.get('empty') is True for row in supervisor.groups)
        and all(row.get('empty') is True for row in supervisor.process_observers))
def read_owned_proof(path, maximum, expected=None):
    fd = os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        identity = {'device':before.st_dev % (1 << 64),'object':before.st_ino,'fileBytes':before.st_size}
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != uid or not 0 <= before.st_size <= maximum:
            raise RuntimeError('Proof is not a bounded ordinary owned file.')
        if expected is not None and (identity['device'] != expected['device'] or identity['object'] != expected['object'] or identity['fileBytes'] != expected.get('fileBytes',0)):
            raise RuntimeError('Proof differs from its native handoff identity.')
        data = bytearray()
        while True:
            chunk = os.read(fd,min(65536,maximum+1-len(data)))
            if not chunk: break
            data.extend(chunk)
            if len(data) > maximum: raise RuntimeError('Proof grew beyond its byte bound.')
        after = os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_uid,before.st_mode,before.st_nlink,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_uid,after.st_mode,after.st_nlink,after.st_mtime_ns,after.st_ctime_ns) or len(data) != before.st_size:
            raise RuntimeError('Proof changed during its native read.')
        return bytes(data), identity
    finally: os.close(fd)
def verify_standard_handoff(result):
    if not owned_closed(): raise RuntimeError('All owned sessions must close before handoff verification.')
    raw, identity = read_owned_proof(proof/'D06-handoff.json',1048576)
    manifest = json.loads(raw)
    expected_path = pathlib.Path(result['identity']['defaultAnchor']).joinpath('open-e2ee','oe','identity-attempts')
    if manifest['originalPath'] != str(expected_path) or manifest['copyDirectory'] != 'D06-handoff':
        raise RuntimeError('The handoff original locator differs from the actual default root.')
    if not all(manifest.get(key) is True for key in ['leasedWritersClosed','originalPreserved','copyBeforeControllerExit']):
        raise RuntimeError('The ordinary handoff lacks writer closure evidence.')
    if [row['action'] for row in manifest['closedActors']] != ['busy','retain','read','uncertain']:
        raise RuntimeError('The complete closed actor sequence is required.')
    for actor in manifest['closedActors']:
        observed = json.loads(read_owned_proof(proof/(actor['action']+'-process.json'),1048576)[0])
        if observed.get('exited') is not True or observed['pid'] != actor['pid'] or observed['stdoutTruncated'] or observed['stderrTruncated']:
            raise RuntimeError('A fixed namespace actor did not finish before handoff.')
    names = sorted(manifest['files'])
    locks = [name for name in names if re.fullmatch(r'locks/[a-f0-9]{64}\.lock',name)]
    if len(locks) != 1: raise RuntimeError('The synthetic handoff lock roster differs.')
    stem = locks[0][6:-5]
    if names != sorted(['root.lock','store.json.d06-witness','locks/'+stem+'.lock','v1/'+stem+'.json']):
        raise RuntimeError('The synthetic handoff contains an unexpected object.')
    rows, total = [], 0
    for name in names:
        entry = manifest['files'][name]
        if type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= 2097152:
            raise RuntimeError('The explicit synthetic byte count differs.')
        data, actual = read_owned_proof(proof/'D06-handoff'/name,2097152,entry['copy'])
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != entry['bytes'] or entry['source']['sha256'] != digest or entry['copy']['sha256'] != digest:
            raise RuntimeError('The standard-user handoff bytes differ.')
        total += len(data)
        if total > 16777216: raise RuntimeError('The synthetic handoff exceeds16MiB.')
        rows.append({'path':name,'original':entry['source'],'copy':actual,'sha256':digest})
    if total != manifest['bytes'] or read_owned_proof(proof/'D06-handoff.json',1048576,identity)[0] != raw:
        raise RuntimeError('The complete handoff manifest changed.')
    save('D06-copy-verification.json',{'originalPath':str(expected_path),'files':rows,'ownedSessionsEmpty':True,'originalNamespaceReads':False})
def collect_bounded_proof():
    pending = [(proof,artifact)]
    total, count = 0, 0
    while pending:
        source, destination = pending.pop()
        for entry in source.iterdir():
            if source == proof and entry.name in ['cache','temporary','probe','artifact','result.json']: continue
            info = entry.lstat(); count += 1
            if count > 127 or time.monotonic() > deadline+10: raise RuntimeError('Proof collection bound reached.')
            target = destination/entry.name
            if stat.S_ISDIR(info.st_mode):
                target.mkdir(mode=0o700); pending.append((entry,target))
            elif stat.S_ISREG(info.st_mode):
                data, _ = read_owned_proof(entry,16*1024*1024)
                total += len(data)
                if total > 127*1024*1024: raise RuntimeError('Proof payload exceeds127MiB. Source VM state remains preserved.')
                with target.open('xb') as writer: writer.write(data)
                if read_owned_proof(target,16*1024*1024)[0] != data:
                    raise RuntimeError('Proof copy differs from its source.')
            else: raise RuntimeError('Proof contains an unsupported object.')
try:
    go = shutil.which('go')
    if not go: raise RuntimeError('Go is unavailable.')
    host = json.loads(supervisor.run([go,'env','-json','GOHOSTOS','GOHOSTARCH','GOVERSION'],capture=True))
    if (host['GOHOSTOS'],host['GOHOSTARCH'],host['GOVERSION']) != (actual_os,actual_arch,'go1.27.3'):
        raise RuntimeError('The Go host is not the actual native target.')
    save('caller.json',{'uid':uid,'effectiveUID':os.geteuid(),'gid':gid,'effectiveGID':os.getegid(),
        'groups':os.getgroups(),'accountHome':account.pw_dir,'home':os.environ.get('HOME'),
        'xdgConfigHome':os.environ.get('XDG_CONFIG_HOME'),'os':actual_os,'architecture':actual_arch,'go':host})
    supervisor.run([go,'mod','download','-json'],120)
    environment.update({'GOPROXY':'off','GOSUMDB':'off','GOFLAGS':'-mod=readonly'})
    binary = proof/'probe'
    supervisor.run([go,'test','-c','-tags','identity_default_qualification','-o',str(binary),'./internal/identityattempt'],120)
    git = shutil.which('git')
    if not git: raise RuntimeError('Git source metadata is unavailable.')
    head = supervisor.run([git,'rev-parse','HEAD'],capture=True).decode().strip()
    tracked = supervisor.run([git,'ls-files','-z'],capture=True).decode().split('\0')
    inputs = {}
    for name in tracked:
        if not name: continue
        path = root/name
        if not path.is_file() or path.is_symlink() or root not in path.resolve().parents: raise RuntimeError('Uncertain source owner.')
        inputs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    save('source-inputs.json',{'head':head,'files':inputs})
    save('disposable.json',{'nonce':nonce,'identity':str(uid),'home':account.pw_dir,'os':actual_os,
        'architecture':actual_arch,'binarySHA256':hashlib.sha256(binary.read_bytes()).hexdigest(),'githubHosted':True})
    supervisor.run([str(binary),'-test.run=^TestIdentityDefaultQualification$','-test.timeout=120s','-test.v',
        '-identity-default-proof='+str(proof),'-identity-default-nonce='+nonce],130)
    result = json.loads((proof/'D-result.json').read_text())
    if not result.get('success') or result['cases']!=['D01','D02','D03','D04','D05','D06']:
        raise RuntimeError('All six default-location cases are required.')
    if not owned_closed(): raise RuntimeError('Owned session cleanup is uncertain.')
    verify_standard_handoff(result)
    handoff_verified = True
    if any(hashlib.sha256((root/name).read_bytes()).hexdigest()!=value for name,value in source.items()):
        raise RuntimeError('A frozen module owner changed.')
    success = True
except BaseException as error:
    failure = str(error)
finally:
    collection_complete = False
    try:
        if not owned_closed(): raise RuntimeError('Do not traverse proof with uncertain owned processes.')
        collect_bounded_proof()
        collection_complete = True
    except BaseException as error:
        success = False
        failure = (failure or '')+'; collection: '+str(error)
    terminal = {'success':success,'failure':failure,'elapsedSeconds':time.monotonic()-started,
        'ownedSessionsEmpty':owned_closed(),'standardHandoffVerified':handoff_verified,'collectionComplete':collection_complete,
        'defaultStatePreserved':True,'sourceProof':str(proof),
        'cleanup':'VM teardown owns removal of the original synthetic default namespace. No first-use reset.',
        'limits':'D01-D06 only. No public CLI, Console, Relay, provider or historical-client acceptance.'}
    raw = (json.dumps(terminal,indent=2)+'\n').encode()
    if len(raw) > 1048576: raise RuntimeError('The reserved terminal evidence bound was reached.')
    with (artifact/'result.json').open('xb') as output: output.write(raw)
    save('result.json',terminal)
    if not success: raise SystemExit('Default-location qualification failed. Preserve the owned VM state and bounded proof.')
PY
