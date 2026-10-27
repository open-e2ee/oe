"""Actual unprivileged child and pure backing-decision regressions."""
import ast
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
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

    def run_child(self, source, limit=2, expected_failure=False):
        argv = [sys.executable,'-I','-c',source]
        if expected_failure:
            with self.assertRaisesRegex(RuntimeError,'A bounded stage failed'):
                self.owner.run(argv,limit)
        else:
            self.owner.run(argv,limit)
        self.assertEqual(len(self.owner.steps),1)
        row = self.owner.steps[0]
        self.assertEqual(row['closureDeadlineMonotonic']-row['closureStartedMonotonic'],5)
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
        row = self.run_child(source,expected_failure=True)
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


if __name__ == '__main__':
    unittest.main(failfast=True)
