#!/usr/bin/env python3
"""Export the clean current Git commit with a file manifest and checksums."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def write_entry(archive, name, content, timestamp, mode=0o100644):
    info = zipfile.ZipInfo('RainSwift/' + name, timestamp)
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error('Choose an output path outside the repository')
    if output.exists():
        parser.error('Output already exists; choose a new file')
    if git('status', '--porcelain', '--untracked-files=all').strip():
        parser.error('Commit changes before exporting this release')
    commit = git('rev-parse', 'HEAD').decode().strip()
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD'))
    timestamp = datetime.fromtimestamp(epoch, timezone.utc).timetuple()[:6]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rainswift-release-') as tmp:
        raw = Path(tmp) / 'git.zip'
        git('archive', '--format=zip', '--output=' + str(raw), 'HEAD')
        target = Path(tmp) / 'release.zip'
        with zipfile.ZipFile(raw) as source, zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            metadata = json.loads(source.read('submission.json'))
            manifest = {'schema_version': 1, 'project_id': metadata['project_id'],
                        'version': metadata['version'], 'release_tag': metadata['release_tag'],
                        'git_commit': commit, 'repository': metadata['repository'], 'files': {}}
            for item in sorted(source.infolist(), key=lambda row: row.filename):
                if item.is_dir():
                    continue
                name = item.filename
                content = source.read(item)
                manifest['files'][name] = {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}
                write_entry(archive, name, content, timestamp, (item.external_attr >> 16) or 0o100644)
            rendered = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
            write_entry(archive, 'RELEASE_MANIFEST.json', rendered, timestamp)
            sums = {name: row['sha256'] for name, row in manifest['files'].items()}
            sums['RELEASE_MANIFEST.json'] = hashlib.sha256(rendered).hexdigest()
            checksums = ''.join(sha + '  ' + name + '\n' for name, sha in sorted(sums.items()))
            write_entry(archive, 'SHA256SUMS.txt', checksums.encode('utf-8'), timestamp)
        with zipfile.ZipFile(target) as archive:
            bad = archive.testzip()
            if bad:
                raise ValueError('ZIP CRC mismatch: ' + bad)
        # Same filesystem temporary destination makes the final publication atomic.
        staging = output.with_suffix(output.suffix + '.tmp')
        if staging.exists():
            parser.error('Staging path already exists: ' + str(staging))
        import shutil
        shutil.copyfile(target, staging)
        staging.replace(output)
    sha = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(sha + '  ' + output.name + '\n', encoding='utf-8')
    print(json.dumps({'status': 'PASS', 'git_commit': commit, 'files': len(manifest['files']),
                      'zip_bytes': output.stat().st_size, 'sha256': sha}, indent=2))


if __name__ == '__main__':
    main()
