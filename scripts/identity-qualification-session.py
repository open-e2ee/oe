"""Native POSIX session ownership for disposable identity qualification."""
import collections, hashlib, json, os, pathlib, selectors, signal, stat, subprocess, time

STAGE_FAILURE = 'A bounded stage failed; see raw evidence.'

class IdentitySessionController:
    def __init__(self, root, proof, base_env, outer_deadline, *, steps=None,
                 groups=None, process_observers=None, space_floor_reached=lambda: False,
                 stream_limit=64*1024*1024, combined_limit=128*1024*1024, stage_limit=24):
        self.root, self.proof, self.base_env = root, proof, base_env
        self.outer_deadline = outer_deadline
        self.steps = [] if steps is None else steps
        self.groups = [] if groups is None else groups
        self.process_observers = [] if process_observers is None else process_observers
        self.space_floor_reached = space_floor_reached
        self.stream_limit, self.combined_limit, self.stage_limit = stream_limit, combined_limit, stage_limit

    def save(self, name, value):
        (self.proof/name).write_text(json.dumps(value, indent=2)+'\n')

    def group_alive(self, pgid):
        try: os.killpg(pgid, 0); return True
        except ProcessLookupError: return False

    # ps supplies only numeric PID/PPID/UID candidates. Native getsid/getpgid own association.
    # The observer runs outside the test session and never receives fixture paths.
    def process_inventory(self, deadline=None):
        until = time.monotonic()+1
        if deadline is not None: until = min(until,deadline)
        if time.monotonic() >= until: raise RuntimeError('Process observation deadline expired.')
        observer = subprocess.Popen(['/bin/ps','-axo','pid=,ppid=,uid='], env=self.base_env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        selector = selectors.DefaultSelector()
        raw = bytearray()
        outcome = {'pid':observer.pid,'sid':observer.pid,'empty':False,'status':None}
        self.process_observers.append(outcome)
        failure = None
        try:
            os.set_blocking(observer.stdout.fileno(),False)
            selector.register(observer.stdout,selectors.EVENT_READ)
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
                remaining = .25 if deadline is None else max(0,min(.25,deadline-time.monotonic()))
                try: observer.wait(timeout=remaining)
                except subprocess.TimeoutExpired: pass
            try: outcome['empty'] = not self.group_alive(observer.pid)
            except BaseException as error: failure = failure or error
            outcome['status'] = observer.poll()
            selector.close(); observer.stdout.close()
            if not outcome['empty']: failure = failure or RuntimeError('Process observer cleanup is uncertain.')
            outcome['failure'] = None if failure is None else str(failure)
            self.save('process-observers.json',self.process_observers)
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

    def owned_session_members(self, session_id, deadline=None):
        if session_id <= 1 or session_id == os.getsid(0): raise RuntimeError('Refuse an unowned supervisor session.')
        rows = []
        until = time.monotonic()+1
        if deadline is not None: until = min(until,deadline)
        for pid, ppid, uid in self.process_inventory(deadline=until):
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

    def finish_session(self, process, session, deadline):
        observations, signals = [], []
        session.update({'observations':observations,'signals':signals})
        started = time.monotonic()
        prior_empty = False
        try:
            for _ in range(24):
                if time.monotonic() >= deadline: break
                # Reap only the owned leader. Separate-PGID actors remain observable by SID.
                process.poll()
                members = self.owned_session_members(session['sid'],deadline=deadline)
                observations.append({'atMonotonic':time.monotonic(),'members':members})
                if not members:
                    if prior_empty:
                        session['empty'] = all(row['empty'] for row in self.process_observers)
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
                remaining = deadline-time.monotonic()
                if remaining <= 0: break
                time.sleep(min(.02,remaining))
            if not session['empty']: session['failure'] = 'Owned session did not reach two complete empty observations.'
        except BaseException as error:
            session['failure'] = str(error)
            session['empty'] = False
        session['leaderStatus'] = process.poll()
        session['scope'] = 'Actual native actors retain the launched POSIX SID even when Setpgid selects a separate PGID.'
        self.save('groups.json',self.groups)
        return session['empty']

    def run(self, argv, limit=30, env=None, capture=False, monitor_volume=True, *,
            cwd=None, phase_deadline=None, progress=None):
        if time.monotonic() >= self.outer_deadline: raise RuntimeError('Outer process deadline expired.')
        number = len(self.steps)
        if number >= self.stage_limit: raise RuntimeError('Owned stage count bound reached.')
        executable = pathlib.Path(argv[0]).resolve(strict=True)
        row = {'argv':argv, 'executableSHA256':hashlib.sha256(executable.read_bytes()).hexdigest(), 'limitSeconds':limit, 'startMonotonic':time.monotonic()}
        self.steps.append(row); self.save('stages.json', self.steps)
        process = subprocess.Popen(argv, cwd=self.root if cwd is None else cwd, env=env or self.base_env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        session = {'sid':process.pid,'leaderPID':process.pid,'expectedRootPGID':process.pid,'launchMechanism':'Popen(start_new_session=True)','empty':False}
        self.groups.append(session); self.save('groups.json',self.groups)
        selector = selectors.DefaultSelector()
        streams = {}
        eof = {'stdout':False,'stderr':False}
        write_failed = {'stdout':False,'stderr':False}
        raw = bytearray()
        for name, stream in [('stdout',process.stdout), ('stderr',process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
            streams[name] = [(self.proof/f'{number:02d}.{name}').open('wb',buffering=0), 0, 0]
        reason = None
        secondary = []
        leader_waited = False
        leader_wait_status = None
        deadline = min(self.outer_deadline, time.monotonic()+limit)
        if phase_deadline is not None: deadline = min(deadline,phase_deadline)
        first_byte, last_byte = None, None
        next_progress = time.monotonic() if progress is not None else None
        def record_failure(code, detail=None):
            nonlocal reason
            if reason is None:
                reason = code
                if detail is not None: row['failureDetail'] = detail
            elif code != reason and not any(item['reason'] == code for item in secondary):
                secondary.append({'reason':code,'detail':detail})
        def read_ready(timeout):
            nonlocal first_byte, last_byte
            for key, _ in selector.select(timeout):
                chunk = os.read(key.fileobj.fileno(),65536)
                if not chunk:
                    eof[key.data] = True
                    selector.unregister(key.fileobj)
                    continue
                now = time.monotonic()
                if first_byte is None: first_byte = now
                last_byte = now
                stream = streams[key.data]
                remaining = max(0,min(self.stream_limit-stream[2],self.combined_limit-sum(value[2] for value in streams.values())))
                retained = chunk[:remaining]
                stream[1] += len(chunk)
                if retained and not write_failed[key.data]:
                    try:
                        written = stream[0].write(retained)
                        stream[2] += written
                        if written != len(retained):
                            write_failed[key.data] = True
                            record_failure('OUTPUT_WRITE_INCOMPLETE')
                    except OSError as error:
                        write_failed[key.data] = True
                        record_failure('OUTPUT_WRITE_FAILURE',str(error))
                if capture and key.data == 'stdout':
                    capacity = 4*1024*1024-len(raw)
                    raw.extend(chunk[:capacity])
                    if len(chunk) > capacity: record_failure('CAPTURE_LIMIT')
                if stream[1] > self.stream_limit or sum(value[1] for value in streams.values()) > self.combined_limit:
                    record_failure('OUTPUT_LIMIT')
        def report_progress(ended=False, before_settlement=False):
            if progress is None: return
            now = time.monotonic()
            snapshot = {'atMonotonic':now,'sid':process.pid,'stage':number,
                'startMonotonic':row['startMonotonic'],'effectiveDeadlineMonotonic':deadline,
                'firstByteMonotonic':first_byte,'lastByteMonotonic':last_byte,
                'stdoutBytes':streams['stdout'][1],'stderrBytes':streams['stderr'][1]}
            if before_settlement:
                snapshot.update({'beforeSettlement':True,'leaderStatusBeforeSettlement':process.poll()})
            if ended:
                snapshot.update({'endedMonotonic':now,'ownedSessionEmpty':session['empty'],
                    'stdoutEOF':eof['stdout'],'stderrEOF':eof['stderr'],'leaderWaited':leader_waited,
                    'closureComplete':session['empty'] and leader_waited and all(eof.values())})
            progress(snapshot)
        try:
            while selector.get_map():
                if time.monotonic() >= deadline: record_failure('PROCESS_DEADLINE'); break
                if monitor_volume and self.space_floor_reached():
                    record_failure('OWNED_VOLUME_SPACE_FLOOR'); break
                if progress is not None and time.monotonic() >= next_progress:
                    report_progress(); next_progress = time.monotonic()+10
                read_ready(max(0,min(.1,deadline-time.monotonic())))
                if reason: break
            if not reason:
                try:
                    leader_wait_status = process.wait(timeout=max(0,deadline-time.monotonic()))
                    leader_waited = True
                    if leader_wait_status != 0: record_failure('PROCESS_EXIT_NONZERO')
                except subprocess.TimeoutExpired: record_failure('PROCESS_DEADLINE')
        except BaseException as error:
            record_failure('PROCESS_IO_FAILURE',str(error))
        finally:
            closure_started = time.monotonic()
            closure_deadline = closure_started+5
            if progress is not None:
                try: report_progress(before_settlement=True)
                except BaseException as error: record_failure('NATIVE_DIAGNOSTIC_FAILURE',str(error))
            try: empty = self.finish_session(process,session,closure_deadline)
            except BaseException as error:
                empty = False
                session['empty'] = False
                session['failure'] = str(error)
            if not empty: record_failure('SESSION_CLOSURE_UNCERTAIN',session.get('failure'))
            try:
                leader_wait_status = process.wait(timeout=max(0,closure_deadline-time.monotonic()))
                leader_waited = True
            except subprocess.TimeoutExpired: record_failure('LEADER_WAIT_INCOMPLETE')
            except BaseException as error: record_failure('LEADER_WAIT_INCOMPLETE',str(error))
            while selector.get_map() and time.monotonic() < closure_deadline:
                try: read_ready(min(.1,max(0,closure_deadline-time.monotonic())))
                except BaseException as error:
                    record_failure('PIPE_DRAIN_FAILURE',str(error))
                    break
            if not all(eof.values()): record_failure('PIPE_EOF_INCOMPLETE')
            closure_ended = time.monotonic()
            if closure_ended > closure_deadline: record_failure('CLOSURE_DEADLINE')
            session.update({'leaderStatus':process.poll(),'leaderWaited':leader_waited,
                'leaderWaitStatus':leader_wait_status})
            if progress is not None:
                try: report_progress(ended=True)
                except BaseException as error:
                    record_failure('NATIVE_DIAGNOSTIC_FAILURE')
                    row['diagnosticFailure'] = str(error)
            try: selector.close()
            except BaseException as error: record_failure('STREAM_CLOSE_FAILURE',str(error))
            for stream in [value[0] for value in streams.values()]+[process.stdout,process.stderr]:
                try: stream.close()
                except BaseException as error: record_failure('STREAM_CLOSE_FAILURE',str(error))
            row.update({'status':process.poll(),'reason':reason,'ownedSessionEmpty':empty,
                        'stdoutBytes':streams['stdout'][1], 'stderrBytes':streams['stderr'][1],
                        'stdoutRetainedBytes':streams['stdout'][2],'stderrRetainedBytes':streams['stderr'][2],
                        'stdoutEOF':eof['stdout'],'stderrEOF':eof['stderr'],
                        'leaderWaited':leader_waited,'leaderWaitStatus':leader_wait_status,
                        'closureStartedMonotonic':closure_started,'closureDeadlineMonotonic':closure_deadline,
                        'closureEndedMonotonic':closure_ended,'secondaryFailures':secondary,
                        'closureComplete':empty and leader_waited and all(eof.values())})
            self.save('stages.json', self.steps); self.save('groups.json', self.groups)
        if reason or row['status'] != 0 or not row['closureComplete']: raise RuntimeError(STAGE_FAILURE)
        return bytes(raw)


def restored_build_cache(value, caller_uid, mount):
    """Return the build cache policy for the race and minimum profiles.

    The policy is restored only for an absolute canonical directory that caller_uid owns
    outside the owned mount. Every other value selects the fresh owned cache with a reason.
    """
    def fresh(reason): return {'policy':'fresh','reason':reason}
    if not value: return fresh('No restored GOCACHE value was supplied.')
    if not os.path.isabs(value): return fresh('The restored GOCACHE is not absolute.')
    if os.path.realpath(value) != value: return fresh('The restored GOCACHE is not canonical.')
    owned = os.path.realpath(mount)
    if os.path.commonpath([value,owned]) == owned: return fresh('The restored GOCACHE is under the owned mount.')
    try: info = os.lstat(value)
    except OSError as error: return fresh(f'The restored GOCACHE cannot be read: {error.strerror}.')
    if not stat.S_ISDIR(info.st_mode): return fresh('The restored GOCACHE is not a directory.')
    if info.st_uid != caller_uid: return fresh('The caller does not own the restored GOCACHE.')
    return {'policy':'restored','path':value}

def hand_back_build_cache(path, caller_uid):
    """Give caller_uid each entry under the restored build cache that another owner holds.

    Root runs Go under umask 077, so its new cache entries are root-owned 0600 files and
    0700 directories. The caller's later go vet, go build and cache save steps need them.
    The walk never follows a link.
    """
    def refuse(error): raise error
    entries = changed = 0
    for _, directories, files, directory_fd in os.fwalk(path,onerror=refuse,follow_symlinks=False):
        for name in directories+files:
            entries += 1
            info = os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
            if info.st_uid == caller_uid: continue
            os.chown(name,caller_uid,-1,dir_fd=directory_fd,follow_symlinks=False)
            needed = stat.S_IRWXU if stat.S_ISDIR(info.st_mode) else stat.S_IRUSR|stat.S_IWUSR
            if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & needed != needed:
                os.chmod(name,stat.S_IMODE(info.st_mode)|needed,dir_fd=directory_fd)
            changed += 1
    return {'entries':entries,'changedEntries':changed}


FAILURE_TEXT_LIMIT = 2000
FAILURE_OUTPUT_LINES = 5
FAILURE_ANNOTATION_TITLE = 'identity-store harness'

def workflow_command_message(value):
    """Encode a GitHub workflow-command message. Percent goes first."""
    return str(value).replace('%','%25').replace('\r','%0D').replace('\n','%0A')

def failure_annotation(failure_class, text):
    return '::error title='+FAILURE_ANNOTATION_TITLE+'::'+workflow_command_message(f'{failure_class}: {text}')

def _bounded_text(text):
    return text if len(text) <= FAILURE_TEXT_LIMIT else text[:FAILURE_TEXT_LIMIT-3]+'...'

def _stage_label(index, row):
    executable = str((row.get('argv') or ['unknown'])[0]).replace('\\','/').rsplit('/',1)[-1]
    return f"stage {index:02d} {executable} status={row.get('status')} reason={row.get('reason')}"

def _stage_clean(row):
    return (row.get('status') == 0 and row.get('reason') is None and row.get('closureComplete') is True
        and not row.get('secondaryFailures') and 'diagnosticFailure' not in row)

def _go_test_stage(argv):
    argv = [str(value) for value in argv or []]
    if len(argv) < 2 or argv[0].replace('\\','/').rsplit('/',1)[-1] not in ('go','go.exe'): return False
    return argv[1] == 'test' or argv[1:3] == ['tool','test2json']

def _framing_line(line):
    return line.startswith(('=== ','--- ','FAIL\t','ok ')) or line in ('FAIL','PASS')

def go_test_failures(path):
    """Failing test names and their last output lines from retained test2json stdout."""
    failed, packages, output = [], [], {}
    try:
        with open(path,'rb') as stream:
            for raw in stream:
                try: event = json.loads(raw)
                except ValueError: continue
                if not isinstance(event,dict): continue
                action, test = event.get('Action'), event.get('Test')
                # A build event names 'pkg [pkg.test]'. Its package is the first word.
                key = (str(event.get('Package') or event.get('ImportPath') or '').split(' ',1)[0], str(test) if test else None)
                if action in ('output','build-output'):
                    line = str(event.get('Output') or '').strip()
                    if line and not _framing_line(line):
                        output.setdefault(key,collections.deque(maxlen=FAILURE_OUTPUT_LINES)).append(line)
                elif action == 'fail' and key[1] is not None:
                    if key not in failed: failed.append(key)
                elif action in ('fail','build-fail'):
                    if key not in packages: packages.append(key)
    except OSError as error:
        return f'retained stdout unreadable: {error}'
    def name(key):
        package = key[0].rsplit('/',1)[-1]
        return f'{package}.{key[1]}' if key[1] is not None else f'{package} package'
    failing_packages = {key[0] for key in failed}
    packages = [key for key in packages if key[0] not in failing_packages]
    parts = []
    if failed: parts.append('failed: '+', '.join(name(key) for key in failed))
    for key in failed+packages:
        if output.get(key): parts.append(name(key)+': '+' | '.join(output[key]))
    if packages and not failed: parts.insert(0,'failed: '+', '.join(name(key) for key in packages))
    return '; '.join(parts) if parts else 'no test2json fail event was retained'

def failure_summary(steps, proof, failure, closed):
    """Return (failure_class, text). Only one closed nonzero go test stage is a test failure."""
    failed = [(index,row) for index,row in enumerate(steps) if not _stage_clean(row)]
    if closed is True and failure == STAGE_FAILURE and len(failed) == 1:
        index, row = failed[0]
        status = row.get('status')
        if (index == len(steps)-1 and _go_test_stage(row.get('argv')) and type(status) is int and status != 0
                and row.get('reason') == 'PROCESS_EXIT_NONZERO' and row.get('closureComplete') is True
                and not row.get('secondaryFailures') and 'diagnosticFailure' not in row):
            stdout = pathlib.Path(proof)/f'{index:02d}.stdout'
            return 'test', _bounded_text(_stage_label(index,row)+'; '+go_test_failures(stdout))
    parts = []
    if closed is not True:
        parts.append('Uncertain process or pipe closure prevents proof ownership handback. Preserve the owned VM state.')
    parts.append(failure if failure else 'no failure text was recorded')
    parts.extend(_stage_label(index,row) for index,row in failed)
    return 'harness', _bounded_text('; '.join(parts))
