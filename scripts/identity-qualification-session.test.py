"""Actual unprivileged child and pure backing-decision regressions."""
import ast
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('identity_qualification_session', ROOT / 'scripts/identity-qualification-session.py')
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get('OE_IDENTITY_SESSION_TEST_PROOF', '')
        cls.proof = pathlib.Path(value)
        if not value or not cls.proof.is_absolute() or cls.proof.exists():
            raise RuntimeError('A fresh absolute owned proof directory is required.')
        cls.proof.mkdir(mode=0o700)

    def setUp(self):
        self.directory = self.proof / self._testMethodName
        self.directory.mkdir(mode=0o700)
        temporary = self.directory / 'temporary'
        temporary.mkdir(mode=0o700)
        environment = {key:value for key,value in os.environ.items() if key in ['PATH','HOME','LANG','LC_ALL','TZ']}
        environment['TMPDIR'] = str(temporary)
        self.owner = OWNER.IdentitySessionController(self.directory,self.directory,environment,time.monotonic()+15,
            stream_limit=65536,combined_limit=131072,stage_limit=1)

    def run_child(self, source, limit=2, expected_failure=False, progress=None):
        argv = [sys.executable,'-I','-c',source]
        if expected_failure:
            with self.assertRaisesRegex(RuntimeError,'A bounded stage failed'):
                self.owner.run(argv,limit,progress=progress)
        else:
            self.owner.run(argv,limit,progress=progress)
        self.assertEqual(len(self.owner.steps),1)
        row = self.owner.steps[0]
        self.assertEqual(row['closureDeadlineMonotonic'],row['closureStartedMonotonic']+5)
        return row

    def assert_closed(self, row):
        self.assertTrue(row['ownedSessionEmpty'])
        self.assertTrue(row['stdoutEOF'])
        self.assertTrue(row['stderrEOF'])
        self.assertTrue(row['leaderWaited'])
        self.assertEqual(row['status'],row['leaderWaitStatus'])
        self.assertTrue(row['closureComplete'])
        self.assertTrue(all(value['empty'] and value['status'] == 0 and value['failure'] is None
            for value in self.owner.process_observers))
        self.assertEqual(self.owner.groups[0]['observations'][-1]['members'],[])
        self.assertEqual(self.owner.groups[0]['observations'][-2]['members'],[])

    def test_delayed_success_reads_both_eofs(self):
        row = self.run_child("import os,time; time.sleep(.05); os.write(1,b'ordinary\\n'); os.write(2,b'complete\\n')")
        self.assertIsNone(row['reason'])
        self.assertEqual(row['status'],0)
        self.assert_closed(row)
        self.assertEqual((self.directory/'00.stdout').read_bytes(),b'ordinary\n')
        self.assertEqual((self.directory/'00.stderr').read_bytes(),b'complete\n')

    def test_nonzero_busy_refusal_keeps_actual_status(self):
        row = self.run_child("import os; os.write(2,b'Resource busy\\n'); raise SystemExit(16)",expected_failure=True)
        self.assertEqual(row['status'],16)
        self.assertEqual(row['reason'],'PROCESS_EXIT_NONZERO')
        self.assert_closed(row)
        self.assertEqual((self.directory/'00.stderr').read_bytes(),b'Resource busy\n')

    def test_deadline_drains_term_tail_without_erasing_failure(self):
        source = """import os,signal,time
def terminate(signum, frame):
    os.write(1,b'term-tail\\n')
    os.write(2,b'term-error\\n')
    raise SystemExit(0)
signal.signal(signal.SIGTERM,terminate)
os.write(1,b'ready\\n')
time.sleep(20)
"""
        checkpoints = []
        row = self.run_child(source,expected_failure=True,progress=checkpoints.append)
        before = [item for item in checkpoints if item.get('beforeSettlement') is True]
        self.assertEqual(len(before),1)
        self.assertIsNone(before[0]['leaderStatusBeforeSettlement'])
        self.assertEqual(before[0]['stdoutBytes'],len(b'ready\n'))
        self.assertEqual(before[0]['stderrBytes'],0)
        self.assertLessEqual(before[0]['atMonotonic'],self.owner.groups[0]['observations'][0]['atMonotonic'])
        self.assertEqual(row['reason'],'PROCESS_DEADLINE')
        self.assertEqual(row['status'],0)
        self.assert_closed(row)
        self.assertEqual((self.directory/'00.stdout').read_bytes(),b'ready\nterm-tail\n')
        self.assertEqual((self.directory/'00.stderr').read_bytes(),b'term-error\n')

    def test_eof_does_not_replace_wait_for_live_leader(self):
        row = self.run_child('import os,time; os.close(1); os.close(2); time.sleep(20)',limit=1,expected_failure=True)
        self.assertEqual(row['reason'],'PROCESS_DEADLINE')
        self.assertEqual(row['status'],-signal.SIGTERM)
        self.assert_closed(row)

    def test_output_refusal_retains_bounded_bytes_and_actual_eof(self):
        self.owner.stream_limit,self.owner.combined_limit = 64,80
        row = self.run_child("import os; os.write(1,b'x'*1024); os.write(2,b'err')",expected_failure=True)
        self.assertEqual(row['reason'],'OUTPUT_LIMIT')
        self.assert_closed(row)
        self.assertEqual(row['stdoutBytes'],1024)
        self.assertEqual((self.directory/'00.stdout').read_bytes(),b'x'*64)
        self.assertLessEqual(row['stdoutRetainedBytes']+row['stderrRetainedBytes'],80)

    def test_combined_output_limit_keeps_the_global_bound(self):
        self.owner.stream_limit,self.owner.combined_limit = 64,80
        row = self.run_child("import os; os.write(1,b'x'*60); os.write(2,b'y'*60)",expected_failure=True)
        self.assertEqual(row['reason'],'OUTPUT_LIMIT')
        self.assert_closed(row)
        self.assertEqual(row['stdoutBytes']+row['stderrBytes'],120)
        self.assertEqual(row['stdoutRetainedBytes']+row['stderrRetainedBytes'],80)
        self.assertEqual((self.directory/'00.stdout').stat().st_size+(self.directory/'00.stderr').stat().st_size,80)

    def test_observation_failure_records_incomplete_wait_and_pipes(self):
        actual_popen = subprocess.Popen
        children = []
        def retain_child(*args, **kwargs):
            child = actual_popen(*args,**kwargs)
            children.append(child)
            return child
        try:
            with mock.patch.object(OWNER.subprocess,'Popen',side_effect=retain_child):
                with mock.patch.object(self.owner,'owned_session_members',side_effect=RuntimeError('Injected native census refusal')):
                    row = self.run_child('import time; time.sleep(20)',limit=1,expected_failure=True)
            self.assertEqual(len(children),1)
            self.assertEqual(row['reason'],'PROCESS_DEADLINE')
            self.assertFalse(row['ownedSessionEmpty'])
            self.assertFalse(row['leaderWaited'])
            self.assertFalse(row['stdoutEOF'])
            self.assertFalse(row['stderrEOF'])
            self.assertFalse(row['closureComplete'])
            self.assertIn('SESSION_CLOSURE_UNCERTAIN',[item['reason'] for item in row['secondaryFailures']])
            source = (ROOT/'scripts/test-identity-store-unix.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]
            tree = ast.parse(source)
            declarations = [node for node in tree.body if isinstance(node,ast.FunctionDef)
                and node.name == 'unclosed_diagnostic']
            classification = next(node for node in ast.walk(tree) if isinstance(node,ast.Assign)
                and isinstance(node.targets[0],ast.Tuple)
                and [item.id for item in node.targets[0].elts] == ['failure_class','failure_text'])
            guard = next(node for node in ast.walk(tree) if isinstance(node,ast.If)
                and isinstance(node.test,ast.UnaryOp) and isinstance(node.test.op,ast.Not)
                and isinstance(node.test.operand,ast.Name) and node.test.operand.id == 'closed')
            namespace = {'json':json,'closed':False,'success':False,'failure':'A bounded stage failed; see raw evidence.',
                'steps':self.owner.steps,'groups':self.owner.groups,'proof':self.directory,
                'process_observers':self.owner.process_observers,'session_module':OWNER}
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                exec(compile(ast.Module(body=declarations+[classification,guard],type_ignores=[]),'<actual closed guard>','exec'),namespace)
            self.assertEqual(raised.exception.code,3)
            printed = output.getvalue().splitlines()
            self.assertEqual(len(printed),2)
            self.assertEqual(namespace['failure_class'],'harness')
            self.assertTrue(printed[1].startswith('::error title=identity-store harness::harness: Uncertain process or pipe closure prevents proof ownership handback.'))
            self.assertIn('stage 00 python',printed[1])
            diagnostic = json.loads(printed[0])
            self.assertEqual(diagnostic['failure'],namespace['failure'])
            self.assertEqual(diagnostic['steps'][0]['reason'],'PROCESS_DEADLINE')
            self.assertFalse(diagnostic['steps'][0]['closureComplete'])
            self.assertFalse(diagnostic['groups'][0]['empty'])
            self.assertNotIn('argv',diagnostic['steps'][0])
            self.assertNotIn('import time; time.sleep(20)',output.getvalue())
            self.assertFalse(diagnostic['proofOwnershipHandback'])
            self.assertIsNone(children[0].poll(),'diagnostic reporting cannot substitute for owned cleanup')
        finally:
            # This fixture owns one actual direct child and no descendants.
            receipts = []
            for child in children:
                if child.poll() is None:
                    self.assertEqual(os.getsid(child.pid),child.pid)
                    os.killpg(child.pid,signal.SIGKILL)
                status = child.wait(timeout=2)
                try: os.killpg(child.pid,0)
                except ProcessLookupError: empty = True
                else: empty = False
                receipts.append({'pid':child.pid,'waitStatus':status,'groupEmpty':empty})
                self.assertTrue(empty)
            (self.directory/'fixture-cleanup.json').write_text(json.dumps(receipts,indent=2)+'\n')


class BackingDecisionTests(unittest.TestCase):
    def test_only_successful_closed_unmounted_detach_releases_backing(self):
        source = (ROOT/'scripts/test-identity-store-unix.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]
        tree = ast.parse(source)
        declaration = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'owned_volume_backing_removal_allowed')
        namespace = {}
        exec(compile(ast.Module(body=[declaration],type_ignores=[]),'<pure backing decision>','exec'),namespace)
        decision = namespace['owned_volume_backing_removal_allowed']
        cases = [
            (True,0,True,False,True),
            (False,0,True,False,False),
            (True,16,True,False,False),
            (True,-15,True,False,False),
            (True,None,True,False,False),
            (True,False,True,False,False),
            (True,0,False,False,False),
            (True,0,True,True,False),
            (True,0,True,None,False),
        ]
        for successful,status,closed,mounted,wanted in cases:
            with self.subTest(successful=successful,status=status,closed=closed,mounted=mounted):
                self.assertIs(decision(successful,status,closed,mounted),wanted)


def harness_source():
    return (ROOT/'scripts/test-identity-store-unix.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]


def stage(argv, status=0, reason=None, closed=True, secondary=()):
    return {'argv':list(argv),'status':status,'reason':reason,'closureComplete':closed,
        'secondaryFailures':list(secondary)}


def event(action, package='github.com/open-e2ee/oe/internal/identityattempt', test=None, output=None, **fields):
    value = {'Time':'2026-11-03T00:00:00Z','Action':action,'Package':package}
    if test is not None: value['Test'] = test
    if output is not None: value['Output'] = output
    value.update(fields)
    return json.dumps(value)


GO = '/opt/hostedtoolcache/go/1.27.3/x64/bin/go'
RACE = [GO,'test','-count=1','-json','-race','-timeout=9m','./...']
CANARY_STDOUT = '\n'.join([
    event('start'),
    event('run',test='TestPasses'),
    event('output',test='TestPasses',output='=== RUN   TestPasses\n'),
    event('output',test='TestPasses',output='--- PASS: TestPasses (0.00s)\n'),
    event('pass',test='TestPasses',Elapsed=0),
    event('run',test='TestCanary'),
    event('output',test='TestCanary',output='=== RUN   TestCanary\n'),
    event('output',test='TestCanary',output='    canary_test.go:12: canary\n'),
    event('output',test='TestCanary',output='--- FAIL: TestCanary (0.00s)\n'),
    event('fail',test='TestCanary',Elapsed=0),
    event('run',test='TestParent/child'),
    event('output',test='TestParent/child',output='    parent_test.go:20: child refused\n'),
    event('fail',test='TestParent/child',Elapsed=0),
    event('fail',test='TestParent',Elapsed=0),
    'not test2json output',
    event('output',output='FAIL\n'),
    event('output',output='FAIL\tgithub.com/open-e2ee/oe/internal/identityattempt\t0.1s\n'),
    event('fail',Elapsed=0.1),
    event('pass',package='github.com/open-e2ee/oe/internal/config',Elapsed=0.1),
])+'\n'


class FailureSummaryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.proof = pathlib.Path(directory.name)

    def retained(self, index, text):
        (self.proof/f'{index:02d}.stdout').write_text(text)

    def test_failure_class_go_stage_is_test(self):
        prefix = [stage(['/bin/mount','-o','nodev,nosuid']),stage([GO,'env','-json'])]
        cases = [
            ('race suite',RACE),
            ('native test2json',[GO,'tool','test2json','-t','-p','github.com/open-e2ee/oe/internal/identityattempt','/cache/identityattempt.test']),
            ('windows executable',['C:\\hostedtoolcache\\go\\bin\\go.exe','test','-count=1','-json','./internal/identityattempt']),
        ]
        for name,argv in cases:
            with self.subTest(name):
                self.retained(2,CANARY_STDOUT)
                steps = prefix+[stage(argv,status=1,reason='PROCESS_EXIT_NONZERO')]
                failure_class, text = OWNER.failure_summary(steps,self.proof,OWNER.STAGE_FAILURE,True)
                self.assertEqual(failure_class,'test')
                self.assertTrue(text.startswith(f"stage 02 {argv[0].replace(chr(92),'/').rsplit('/',1)[-1]} status=1 reason=PROCESS_EXIT_NONZERO; "),text)
                self.assertIn('canary',text)

    def test_failure_class_mount_stage_is_harness(self):
        steps = [stage(['/bin/mount','-o','nodev,nosuid','/dev/loop7','/ca8-store-run-x'],status=32,reason='PROCESS_EXIT_NONZERO')]
        failure_class, text = OWNER.failure_summary(steps,self.proof,OWNER.STAGE_FAILURE,True)
        self.assertEqual(failure_class,'harness')
        self.assertEqual(text,OWNER.STAGE_FAILURE+'; stage 00 mount status=32 reason=PROCESS_EXIT_NONZERO')
        # An exception outside every stage is a harness failure and keeps its own text.
        failure_class, text = OWNER.failure_summary([stage([GO,'env','-json'])],self.proof,
            'Go host/version is not the exact native target.',True)
        self.assertEqual((failure_class,text),('harness','Go host/version is not the exact native target.'))

    def test_failure_class_go_stage_with_harness_evidence_is_harness(self):
        self.retained(0,CANARY_STDOUT)
        failing = stage(RACE,status=1,reason='PROCESS_EXIT_NONZERO')
        cases = [
            ('appended cleanup text',[failing],OWNER.STAGE_FAILURE+'; native input readback: changed'),
            ('stage deadline',[stage(RACE,status=-15,reason='PROCESS_DEADLINE')],OWNER.STAGE_FAILURE),
            ('space floor',[stage(RACE,status=-15,reason='OWNED_VOLUME_SPACE_FLOOR')],OWNER.STAGE_FAILURE),
            ('output limit',[stage(RACE,status=1,reason='OUTPUT_LIMIT')],OWNER.STAGE_FAILURE),
            ('secondary closure failure',[stage(RACE,status=1,reason='PROCESS_EXIT_NONZERO',secondary=[{'reason':'CLOSURE_DEADLINE','detail':None}])],OWNER.STAGE_FAILURE),
            ('later stage',[failing,stage(['/bin/umount','/ca8-store-run-x'])],OWNER.STAGE_FAILURE),
            ('tool lookup',[stage([GO,'tool','-n','test2json'],status=1,reason='PROCESS_EXIT_NONZERO')],OWNER.STAGE_FAILURE),
            ('two failed stages',[stage(['/bin/mount'],status=32,reason='PROCESS_EXIT_NONZERO'),failing],OWNER.STAGE_FAILURE),
        ]
        for name,steps,failure in cases:
            with self.subTest(name):
                failure_class, text = OWNER.failure_summary(steps,self.proof,failure,True)
                self.assertEqual(failure_class,'harness')
                self.assertTrue(text.startswith(failure),text)
                self.assertNotIn('canary',text)

    def test_failure_class_unclosed_is_harness(self):
        self.retained(0,CANARY_STDOUT)
        for name,row in [('clean go failure',stage(RACE,status=1,reason='PROCESS_EXIT_NONZERO')),
                ('unclosed go stage',stage(RACE,status=None,reason='PROCESS_DEADLINE',closed=False))]:
            with self.subTest(name):
                failure_class, text = OWNER.failure_summary([row],self.proof,OWNER.STAGE_FAILURE,False)
                self.assertEqual(failure_class,'harness')
                self.assertTrue(text.startswith('Uncertain process or pipe closure prevents proof ownership handback. '),text)
                self.assertIn(OWNER.STAGE_FAILURE,text)

    def test_failure_summary_names_failing_test(self):
        self.retained(0,CANARY_STDOUT)
        failure_class, text = OWNER.failure_summary([stage(RACE,status=1,reason='PROCESS_EXIT_NONZERO')],
            self.proof,OWNER.STAGE_FAILURE,True)
        self.assertEqual(failure_class,'test')
        self.assertEqual(text,'stage 00 go status=1 reason=PROCESS_EXIT_NONZERO; '
            'failed: identityattempt.TestCanary, identityattempt.TestParent/child, identityattempt.TestParent; '
            'identityattempt.TestCanary: canary_test.go:12: canary; '
            'identityattempt.TestParent/child: parent_test.go:20: child refused')
        annotation = OWNER.failure_annotation(failure_class,text)
        self.assertTrue(annotation.startswith('::error title=identity-store harness::test: stage 00 go '))
        build = '\n'.join([
            event('build-output',package=None,ImportPath='github.com/open-e2ee/oe/internal/identityattempt [github.com/open-e2ee/oe/internal/identityattempt.test]',output='internal/identityattempt/canary_test.go:9:2: undefined: canary\n'),
            event('build-fail',package=None,ImportPath='github.com/open-e2ee/oe/internal/identityattempt [github.com/open-e2ee/oe/internal/identityattempt.test]'),
            event('output',output='FAIL\tgithub.com/open-e2ee/oe/internal/identityattempt [build failed]\n'),
            event('fail',Elapsed=0,FailedBuild='github.com/open-e2ee/oe/internal/identityattempt [github.com/open-e2ee/oe/internal/identityattempt.test]'),
        ])+'\n'
        self.retained(0,build)
        self.assertEqual(OWNER.go_test_failures(self.proof/'00.stdout'),
            'failed: identityattempt package; identityattempt package: internal/identityattempt/canary_test.go:9:2: undefined: canary')
        self.assertEqual(OWNER.go_test_failures(self.proof/'missing.stdout')[:27],'retained stdout unreadable:')

    def test_failure_summary_is_bounded(self):
        lines = []
        for number in range(400):
            name = f'TestBound{number:03d}'
            lines += [event('output',test=name,output='    bound_test.go:1: '+'x'*200+'\n'),event('fail',test=name)]
        self.retained(0,'\n'.join(lines)+'\n')
        failure_class, text = OWNER.failure_summary([stage(RACE,status=1,reason='PROCESS_EXIT_NONZERO')],
            self.proof,OWNER.STAGE_FAILURE,True)
        self.assertEqual(failure_class,'test')
        self.assertEqual(len(text),2000)
        self.assertTrue(text.endswith('...'))
        failure_class, text = OWNER.failure_summary([],self.proof,'y'*5000,True)
        self.assertEqual((failure_class,len(text)),('harness',2000))

    def test_workflow_command_encoding(self):
        self.assertEqual(OWNER.workflow_command_message('100% a\r\nb%0A'),'100%25 a%0D%0Ab%250A')
        annotation = OWNER.failure_annotation('harness','first\nsecond\r')
        self.assertEqual(annotation,'::error title=identity-store harness::harness: first%0Asecond%0D')
        self.assertNotIn('\n',annotation)
        self.assertNotIn('\r',annotation)

    def test_closed_exit_code_names_the_class(self):
        tree = ast.parse(harness_source())
        tail = tree.body[-2:]
        self.assertIsInstance(tail[1],ast.Raise)
        for success,failure_class,code,printed in [(True,None,0,''),(False,'test',1,'::error title=identity-store harness::test: x\n'),
                (False,'harness',3,'::error title=identity-store harness::harness: x\n')]:
            with self.subTest(failure_class=failure_class):
                namespace = {'success':success,'failure_class':failure_class,'failure_text':'x','session_module':OWNER}
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                    exec(compile(ast.Module(body=tail,type_ignores=[]),'<actual closed exit>','exec'),namespace)
                self.assertEqual(raised.exception.code,code)
                self.assertEqual(output.getvalue(),printed)


if __name__ == '__main__':
    unittest.main(failfast=True)
