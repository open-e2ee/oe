"""Fixed-path metadata for the native qualifier's Go module preparation."""
import hashlib
import pathlib
import re
import stat


def required_modules(source):
    """Read the frozen file's unquoted require entries, without resolving a graph."""
    modules = []
    seen = set()
    block = False
    header = False
    for line in source.decode('utf-8').splitlines():
        fields = line.split('//', 1)[0].split()
        if not fields:
            continue
        if fields == [')'] and block:
            block = False
            continue
        if fields == ['require', '('] and not block:
            block = True
            continue
        if not block:
            if len(fields) == 2 and fields[0] in ('module', 'go', 'toolchain'):
                if fields[0] == 'module':
                    if header:
                        raise ValueError('Duplicate module declaration.')
                    header = True
                continue
            if fields[0] != 'require':
                raise ValueError('Unsupported module diagnostic syntax.')
            fields = fields[1:]
        if len(fields) != 2:
            raise ValueError('Invalid module requirement.')
        path, version = fields
        if (not re.fullmatch(r'[A-Za-z0-9._~/-]+', path)
                or any(part in ('', '.', '..') for part in path.split('/'))
                or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version)):
            raise ValueError('Unsupported module path or version.')
        if path in seen:
            raise ValueError('Duplicate module requirement.')
        seen.add(path)
        modules.append((path, version))
    if block or not header or not modules:
        raise ValueError('Incomplete module requirements.')
    return modules


def cache_escape(value):
    # Go module.EscapePath and EscapeVersion encode uppercase ASCII as !lower.
    return ''.join('!' + char.lower() if 'A' <= char <= 'Z' else char for char in value)


def entry_metadata(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False, 'type': None, 'bytes': None, 'error': None}
    except OSError as error:
        return {'present': None, 'type': None, 'bytes': None,
                'error': {'class': type(error).__name__, 'errno': error.errno}}
    kind = {stat.S_IFREG: 'file', stat.S_IFDIR: 'directory', stat.S_IFLNK: 'symlink',
            stat.S_IFIFO: 'fifo', stat.S_IFSOCK: 'socket', stat.S_IFCHR: 'character',
            stat.S_IFBLK: 'block'}.get(stat.S_IFMT(info.st_mode), 'unknown')
    return {'present': True, 'type': kind, 'bytes': info.st_size, 'error': None}


class ModuleCacheDiagnostic:
    def __init__(self, cache, source, expected_sha256):
        if hashlib.sha256(source).hexdigest() != expected_sha256:
            raise ValueError('Frozen go.mod changed before module preparation.')
        self.cache = pathlib.Path(cache)
        self.targets = []
        for module, version in required_modules(source):
            path, escaped_version = cache_escape(module), cache_escape(version)
            prefix = 'cache/download/' + path + '/@v/' + escaped_version
            self.targets.append({'module': module, 'version': version, 'paths': {
                'zip': prefix + '.zip', 'ziphash': prefix + '.ziphash',
                'partial': prefix + '.partial', 'directory': path + '@' + escaped_version}})

    def snapshot(self):
        return [{'module': target['module'], 'version': target['version'], 'entries': {
            name: entry_metadata(self.cache / relative)
            for name, relative in target['paths'].items()}} for target in self.targets]
