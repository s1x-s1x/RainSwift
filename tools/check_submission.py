#!/usr/bin/env python3
"""Verify the competition snapshot using only Python's standard library."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def inside(base, name):
    path = (base / name).resolve()
    require(path.is_relative_to(base.resolve()), 'Path outside snapshot: ' + name)
    return path


def read_hash_list(path):
    entries = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        require(match is not None, 'Invalid checksum line in ' + str(path))
        sha, name = match.groups()
        require(name not in entries, 'Duplicate checksum: ' + name)
        entries[name] = sha
        require(digest(inside(path.parent, name)) == sha, 'SHA-256 mismatch: ' + name)
    return entries


def verify(root):
    meta = json.loads((root / 'submission.json').read_text(encoding='utf-8'))
    require(meta['schema_version'] == 1, 'Unsupported metadata schema')
    require(meta['release_tag'] == 'v' + meta['version'], 'Version/tag mismatch')
    require(meta['paper_distribution'] == 'local_submission_package_only', 'Paper scope mismatch')
    for module in meta['modules']:
        require((root / module['path']).is_dir(), 'Missing module: ' + module['path'])
        require((root / module['entry']).is_file(), 'Missing entry: ' + module['entry'])
    for workflow in meta['workflows']:
        require((root / '.github/workflows' / (workflow + '.yml')).is_file(), 'Missing workflow: ' + workflow)

    data_list = root / meta['data']['hash_list']
    data_entries = read_hash_list(data_list)
    actual_data = {p.relative_to(data_list.parent).as_posix()
                   for p in data_list.parent.rglob('*') if p.is_file() and p != data_list}
    require(actual_data == set(data_entries), 'Data file inventory differs from checksum list')
    require(len(data_entries) == meta['data']['hashed_files'], 'Data file count mismatch')
    kats = read_hash_list(root / meta['kat_hash_list'])
    require(len(kats) == meta['kat_files'], 'KAT count mismatch')

    source = json.loads((root / meta['source_provenance']).read_text(encoding='utf-8'))
    overrides = {row['path']: row['repository_sha256']
                 for key in ('documentation_overrides', 'code_overrides') for row in source.get(key, [])}
    destinations = set()
    for row in source['files']:
        name = row['destination']
        require(name not in destinations, 'Duplicate imported source: ' + name)
        destinations.add(name)
        expected = overrides.get(name, row['source_sha256'])
        require(digest(inside(root, name)) == expected, 'Source provenance mismatch: ' + name)
    require(set(overrides) <= destinations, 'Override is outside imported source inventory')
    require(len(destinations) == meta['source_import_files'], 'Source count mismatch')

    links = 0
    for name in meta['documentation']:
        path = inside(root, name)
        content = path.read_text(encoding='utf-8')
        # Current entry documents use inline links with paths without parentheses.
        for target in re.findall(r'\]\(([^\s)]+)\)', content):
            parsed = urlsplit(target)
            if parsed.scheme or not parsed.path:
                continue
            linked = (path.parent / unquote(parsed.path)).resolve()
            require(linked.is_relative_to(root), 'Link leaves repository: ' + target)
            require(linked.exists(), 'Broken link in ' + name + ': ' + target)
            links += 1

    process = subprocess.run(
        [sys.executable, '-I', '-X', 'utf8', str(root / 'data/原语性能/核验性能数据.py')],
        cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=180)
    require(process.returncode == 0, 'Statistics check failed: ' + process.stdout + process.stderr)
    stats = json.loads(process.stdout)
    require(stats['status'] == 'PASS', 'Statistics reported failure')
    for key, expected in [('implementations', meta['data']['implementations']),
                          ('nonwarmup_samples', meta['data']['nonwarmup_samples']),
                          ('raw_files', meta['data']['raw_jsonl_files'])]:
        require(stats[key] == expected, 'Statistics count mismatch: ' + key)

    release = None
    manifest_path = root / 'RELEASE_MANIFEST.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        require(manifest['version'] == meta['version'], 'Release version mismatch')
        require(manifest['release_tag'] == meta['release_tag'], 'Release tag mismatch')
        require(re.fullmatch(r'[0-9a-f]{40}', manifest['git_commit']) is not None, 'Invalid release commit')
        release = read_hash_list(root / 'SHA256SUMS.txt')
        require(set(release) == set(manifest['files']) | {'RELEASE_MANIFEST.json'}, 'Release inventory mismatch')
        actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        require(actual == set(release) | {'SHA256SUMS.txt'}, 'Unexpected or missing release files')
        for name, row in manifest['files'].items():
            require(release[name] == row['sha256'], 'Manifest checksum mismatch: ' + name)
            require((root / name).stat().st_size == row['bytes'], 'Manifest size mismatch: ' + name)

    return {'status': 'PASS', 'version': meta['version'], 'data_files': len(data_entries),
            'imported_source_files': len(destinations), 'source_overrides': len(overrides),
            'kat_files': len(kats), 'documentation_links': links, 'statistics': stats,
            'release_files': len(release) if release is not None else None,
            'git_commit': manifest['git_commit'] if release is not None else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='Write a JSON report outside the verified snapshot')
    args = parser.parse_args()
    try:
        if args.report:
            require(not args.report.resolve().is_relative_to(ROOT), 'Write the report outside the snapshot')
        result = verify(ROOT)
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        result = {'status': 'FAIL', 'error': str(error)}
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.report and not args.report.resolve().is_relative_to(ROOT):
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
