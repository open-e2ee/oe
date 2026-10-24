"""Pure admission and coverage contract for the reviewed native Intel roster."""
import hashlib
import json
import re
from collections import Counter


class IntelContractError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise IntelContractError(code)


def source_identity(value):
    require(isinstance(value, dict) and set(value) == {
        'binarySHA256', 'test2jsonSHA256', 'sourceSHA256'}, 'INTEL_SOURCE_SHAPE')
    require(all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v)
                for v in value.values()), 'INTEL_SOURCE_HASH')
    return dict(value)


def group_identity(value):
    require(isinstance(value, dict) and set(value) == {
        'stage', 'sid', 'leaderPID', 'expectedRootPGID', 'empty', 'leaderStatus'},
        'INTEL_GROUP_SHAPE')
    require(type(value['stage']) is int and 0 <= value['stage'] < 24
            and all(type(value[k]) is int and value[k] > 1
                    for k in ['sid', 'leaderPID', 'expectedRootPGID'])
            and value['sid'] == value['leaderPID'] == value['expectedRootPGID']
            and type(value['empty']) is bool and type(value['leaderStatus']) is int,
            'INTEL_GROUP_IDENTITY')
    return dict(value)


def checked_roster(value):
    require(isinstance(value, dict) and set(value) == {
        'schemaVersion', 'package', 'parents', 'nodes', 'partitions',
        'benchmarks', 'reference'}, 'INTEL_ROSTER_SHAPE')
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['package'] == 'github.com/open-e2ee/oe/internal/identityattempt',
            'INTEL_ROSTER_VERSION')
    parents, nodes, partitions = value['parents'], value['nodes'], value['partitions']
    require(isinstance(parents, list) and len(parents) == 128
            and all(isinstance(n, str) and re.fullmatch('(Test|Fuzz|Example)[A-Za-z0-9_]*', n)
                    for n in parents), 'INTEL_PARENT_ROSTER')
    require(len(set(parents)) == 128, 'INTEL_DUPLICATE_PARENT')
    require(isinstance(nodes, list) and len(nodes) == 853
            and all(isinstance(n, str) and n.split('/')[0] in parents for n in nodes)
            and len(set(nodes)) == 853 and set(parents) <= set(nodes), 'INTEL_NODE_ROSTER')
    require(isinstance(partitions, list) and len(partitions) == 3
            and all(isinstance(p, list) for p in partitions)
            and [len(p) for p in partitions] == [26, 17, 85]
            and sum(partitions, []) == parents, 'INTEL_PARTITION_UNION')
    benchmarks = value['benchmarks']
    require(isinstance(benchmarks, list) and not benchmarks, 'INTEL_BENCHMARK_POLICY')
    reference = value['reference']
    require(isinstance(reference, dict) and set(reference) == {
        'head', 'eventSHA256', 'orderedParentSHA256'}, 'INTEL_REFERENCE_SHAPE')
    require(isinstance(reference['head'], str) and isinstance(reference['eventSHA256'], str)
            and re.fullmatch('[a-f0-9]{40}', reference['head']) is not None
            and re.fullmatch('[a-f0-9]{64}', reference['eventSHA256']) is not None,
            'INTEL_REFERENCE_HASH')
    digest = hashlib.sha256(('\n'.join(parents)+'\n').encode()).hexdigest()
    require(reference['orderedParentSHA256'] == digest, 'INTEL_PARENT_HASH')
    return json.loads(json.dumps(value))


class IntelNativeCoverage:
    def __init__(self, roster, source):
        self.roster = checked_roster(roster)
        self.source = source_identity(source)
        self.listed = False
        self.active = None
        self.active_stage = None
        self.last_group = None
        self.next_partition = 1
        self.blocked = False
        self.admissions = []
        self.receipts = []

    def check_source(self, source):
        require(source_identity(source) == self.source, 'INTEL_SOURCE_CHANGED')

    def accept_listing(self, payload, source, group):
        self.check_source(source)
        group = group_identity(group)
        require(not self.listed and self.active is None and not self.blocked,
                'INTEL_LISTING_STATE')
        require(group['empty'] is True and group['leaderStatus'] == 0,
                'INTEL_LISTING_CLOSURE')
        require(isinstance(payload, bytes) and len(payload) <= 65536, 'INTEL_LISTING_BYTES')
        try:
            names = payload.decode('utf-8', errors='strict').splitlines()
        except UnicodeError:
            raise IntelContractError('INTEL_LISTING_ENCODING') from None
        parents = self.roster['parents']
        expected = [n for kind in ['Test', 'Fuzz', 'Example'] for n in parents
                    if n.startswith(kind)]
        require(expected == parents and names == expected and len(set(names)) == 128,
                'INTEL_COMPILED_ROSTER')
        self.listed = True
        self.last_group = group

    def admit(self, partition, source, predecessor, stage):
        self.check_source(source)
        predecessor = group_identity(predecessor)
        require(self.listed and not self.blocked and self.active is None
                and type(partition) is int and partition == self.next_partition
                and 1 <= partition <= 3, 'INTEL_PARTITION_ADMISSION')
        require(predecessor == self.last_group and predecessor['empty'] is True,
                'INTEL_PREDECESSOR_CLOSURE')
        require(type(stage) is int and predecessor['stage'] < stage < 24,
                'INTEL_STAGE_ORDER')
        names = self.roster['partitions'][partition-1]
        self.active = partition
        self.active_stage = stage
        self.admissions.extend(names)
        return '^('+'|'.join(names)+')$'

    def record(self, partition, source, group, status, payload, stage_ok):
        self.check_source(source)
        group = group_identity(group)
        require(type(partition) is int and partition == self.active,
                'INTEL_WRONG_ACTIVE_PARTITION')
        require(group['stage'] == self.active_stage, 'INTEL_WRONG_ACTIVE_GROUP')
        require(isinstance(payload, bytes) and len(payload) <= 64*1024*1024,
                'INTEL_EVENT_BYTES')
        parents = self.roster['partitions'][partition-1]
        expected = {n for n in self.roster['nodes'] if n.split('/')[0] in parents}
        runs, passes, failed, skipped = Counter(), Counter(), [], []
        faults, terminal = [], []
        package_starts = 0
        try:
            for line in payload.decode('utf-8', errors='strict').splitlines():
                event = json.loads(line)
                if not isinstance(event, dict) or event.get('Package') != self.roster['package']:
                    faults.append('INTEL_EVENT_PACKAGE'); continue
                action, name = event.get('Action'), event.get('Test')
                if action not in ['start', 'run', 'pass', 'fail', 'skip', 'output', 'pause', 'cont']:
                    faults.append('INTEL_EVENT_ACTION'); continue
                if name is None:
                    if action == 'start': package_starts += 1
                    elif action in ['pass', 'fail', 'skip']: terminal.append(action)
                    elif action != 'output': faults.append('INTEL_PACKAGE_EVENT')
                    continue
                if not isinstance(name, str) or name not in expected:
                    faults.append('INTEL_UNEXPECTED_NODE'); continue
                if terminal or package_starts != 1: faults.append('INTEL_EVENT_ORDER')
                if action == 'run':
                    if passes[name]: faults.append('INTEL_EVENT_ORDER')
                    runs[name] += 1
                elif action == 'pass':
                    if runs[name] != 1: faults.append('INTEL_EVENT_ORDER')
                    if any(passes[n] != 1 for n in expected if n.startswith(name+'/')):
                        faults.append('INTEL_DESCENDANT_ORDER')
                    passes[name] += 1
                elif action == 'fail': failed.append(name)
                elif action == 'skip': skipped.append(name)
        except (UnicodeError, ValueError, TypeError):
            faults.append('INTEL_EVENT_FORMAT')
        if package_starts != 1 or terminal != ['pass']: faults.append('INTEL_PACKAGE_RESULT')
        if set(runs) != expected or any(v != 1 for v in runs.values()):
            faults.append('INTEL_RUN_COVERAGE')
        if set(passes) != expected or any(v != 1 for v in passes.values()):
            faults.append('INTEL_PASS_COVERAGE')
        if failed or skipped: faults.append('INTEL_FAILED_OR_SKIPPED')
        if type(status) is not int or status != 0: faults.append('INTEL_PROCESS_STATUS')
        if stage_ok is not True: faults.append('INTEL_OWNED_STAGE_FAILURE')
        if group['leaderStatus'] != status: faults.append('INTEL_GROUP_STATUS')
        if group['empty'] is not True: faults.append('INTEL_NATIVE_CLOSURE')
        receipt = {'partition':partition,'source':dict(self.source),'group':group,
            'closed':group['empty'] is True,
            'status':status,'success':not faults,'faults':sorted(set(faults)),
            'started':sorted(runs),'passed':sorted(passes),'failed':failed,'skipped':skipped,
            'unrun':sorted(expected-set(runs)),'unpassed':sorted(expected-set(passes))}
        self.receipts.append(receipt)
        self.active = None
        self.active_stage = None
        self.last_group = group
        self.next_partition += 1
        self.blocked = group['empty'] is not True
        return json.loads(json.dumps(receipt))

    def snapshot(self):
        started = {n for r in self.receipts for n in r['started']}
        passed = {n for r in self.receipts for n in r['passed']}
        success = (self.listed and not self.blocked and self.active is None
            and self.next_partition == 4 and self.admissions == self.roster['parents']
            and len(self.receipts) == 3 and all(r['success'] for r in self.receipts)
            and passed == set(self.roster['nodes']))
        active = [] if self.active is None else self.roster['partitions'][self.active-1]
        return {'schemaVersion':1,'success':success,'listed':self.listed,
            'activePartition':self.active,'nextPartition':self.next_partition,
            'blocked':self.blocked,'source':dict(self.source),'admittedParents':list(self.admissions),
            'receipts':json.loads(json.dumps(self.receipts)),
            'unprocessedActiveParents':list(active),
            'unrunParents':[n for n in self.roster['parents'] if n not in started and n not in active],
            'unrunNodes':[n for n in self.roster['nodes'] if n not in started and n.split('/')[0] not in active],
            'unrunEvidence':'No run event in reconciled bounded output. Failed or partial output cannot prove absence of execution.',
            'unpassedNodes':[n for n in self.roster['nodes'] if n not in passed]}
