"""Native POSIX session ownership for disposable identity qualification."""
import hashlib, json, os, pathlib, selectors, signal, subprocess, time

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
        def report_progress(ended=False):
            if progress is None: return
            now = time.monotonic()
            snapshot = {'atMonotonic':now,'sid':process.pid,'stage':number,
                'startMonotonic':row['startMonotonic'],'effectiveDeadlineMonotonic':deadline,
                'firstByteMonotonic':first_byte,'lastByteMonotonic':last_byte,
                'stdoutBytes':streams['stdout'][1],'stderrBytes':streams['stderr'][1]}
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
        if reason or row['status'] != 0 or not row['closureComplete']: raise RuntimeError('A bounded stage failed; see raw evidence.')
        return bytes(raw)

