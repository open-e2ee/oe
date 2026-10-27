"""Offline metadata and path tests. This file never launches Go or the qualifier."""
import errno
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('identity_module_cache', ROOT / 'scripts/identity-module-cache.py')
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)
SOURCE = b'module example.org/fixture\ngo 1.26.0\nrequire example.org/Owner/Repo v1.2.3-RC1\n'


def diagnostic(directory, source=SOURCE):
    return CACHE.ModuleCacheDiagnostic(directory, source, hashlib.sha256(source).hexdigest())


class ModuleCacheTests(unittest.TestCase):
    def test_current_frozen_file_has_four_targets_per_requirement(self):
        source = (ROOT / 'go.mod').read_bytes()
        owner = diagnostic('/unused-module-cache', source)
        self.assertEqual(len(owner.targets), 14)
        self.assertEqual(sum(len(target['paths']) for target in owner.targets), 56)
        self.assertEqual(owner.targets[-1]['module'], 'golang.org/x/net')
        self.assertEqual(owner.targets[-1]['paths']['directory'], 'golang.org/x/net@v0.49.0')

    def test_require_blocks_comments_and_single_lines(self):
        source = (b'module example.org/main\ngo 1.26.0\n// comment\nrequire (\n'
                  b' example.org/one v1.0.0 // indirect\n example.org/two v2.0.0+incompatible\n)\n'
                  b'require example.org/three v0.0.0-20261027000000-abcdefabcdef\n')
        self.assertEqual(CACHE.required_modules(source), [
            ('example.org/one', 'v1.0.0'), ('example.org/two', 'v2.0.0+incompatible'),
            ('example.org/three', 'v0.0.0-20261027000000-abcdefabcdef')])

    def test_go_uppercase_escaping_and_fixed_cache_layout(self):
        target = diagnostic('/unused-module-cache').targets[0]
        prefix = 'cache/download/example.org/!owner/!repo/@v/v1.2.3-!r!c1'
        self.assertEqual(target['paths'], {
            'zip': prefix + '.zip', 'ziphash': prefix + '.ziphash', 'partial': prefix + '.partial',
            'directory': 'example.org/!owner/!repo@v1.2.3-!r!c1'})

    def test_changed_frozen_input_refuses(self):
        with self.assertRaisesRegex(ValueError, 'Frozen go.mod changed'):
            CACHE.ModuleCacheDiagnostic('/unused-module-cache', SOURCE + b'\n', hashlib.sha256(SOURCE).hexdigest())

    def test_unsupported_or_ambiguous_requirements_refuse(self):
        header = b'module example.org/main\ngo 1.26.0\n'
        cases = [
            b'require (\nexample.org/a v1.0.0\n',
            b'require example.org/a v1.0.0\nrequire example.org/a v1.1.0\n',
            b'require example.org/a v1.0.0\nreplace example.org/a => ../a\n',
            b'require example.org/a v1.0.0\nexclude example.org/a v1.0.0\n',
            b'require example.org/../a v1.0.0\n',
            b'require /example.org/a v1.0.0\n',
            b'require example.org/a v1.0.0/escape\n',
            b'require "example.org/a" v1.0.0\n',
            b'require example.org/!a v1.0.0\n',
            b'require example.org/a latest\n',
            b'',
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                CACHE.required_modules(header + case)

    def test_real_lstat_reports_files_directories_missing_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='oe-module-metadata-') as temporary:
            owner = diagnostic(temporary)
            paths = {key: pathlib.Path(temporary) / value for key, value in owner.targets[0]['paths'].items()}
            paths['zip'].parent.mkdir(parents=True)
            paths['zip'].write_bytes(b'zip')
            paths['ziphash'].symlink_to('absent-target')
            paths['directory'].mkdir(parents=True)
            # Real lstat remains active. Any module body open fails this test.
            with mock.patch.object(pathlib.Path, 'open', side_effect=AssertionError('Body read')):
                entries = owner.snapshot()[0]['entries']
            self.assertEqual(entries['zip'], {'present': True, 'type': 'file', 'bytes': 3, 'error': None})
            self.assertEqual(entries['ziphash']['type'], 'symlink')
            self.assertTrue(entries['ziphash']['present'])
            self.assertEqual(entries['partial'], {'present': False, 'type': None, 'bytes': None, 'error': None})
            self.assertEqual(entries['directory']['type'], 'directory')

    def test_metadata_errors_remain_errors_and_do_not_stop_other_targets(self):
        owner = diagnostic('/unused-module-cache')
        error = PermissionError(errno.EACCES, 'denied')
        with mock.patch.object(pathlib.Path, 'lstat', side_effect=error) as observed:
            entries = owner.snapshot()[0]['entries']
        self.assertEqual(observed.call_count, 4)
        for entry in entries.values():
            self.assertEqual(entry, {'present': None, 'type': None, 'bytes': None,
                                    'error': {'class': 'PermissionError', 'errno': errno.EACCES}})

    def test_parent_not_directory_is_not_reported_as_absent(self):
        with tempfile.TemporaryDirectory(prefix='oe-module-metadata-') as temporary:
            parent = pathlib.Path(temporary) / 'file'
            parent.write_bytes(b'')
            entry = CACHE.entry_metadata(parent / 'child')
            self.assertIsNone(entry['present'])
            self.assertEqual(entry['error'], {'class': 'NotADirectoryError', 'errno': errno.ENOTDIR})


if __name__ == '__main__':
    unittest.main()
