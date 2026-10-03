"""Build isolated optimized success-path probes before/after a local TLS change."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess

from measure_stack import ROOT, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    folder = ROOT / 'evidence' / ('read-comparison-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    folder.mkdir(parents=True)

    def run(command):
        command = [str(word) for word in command]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
        with (folder / 'commands.log').open('a') as log:
            log.write(shlex.join(command) + '\n' + result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout

    report = dict(passed=False, scope='Host optimized success-path comparison builds; historical baseline is not a release candidate')
    try:
        revision = run(['git', 'rev-parse', '--verify', args.baseline + '^{commit}']).strip()
        baseline = run(['git', 'show', revision + ':src/tls_stream.c']).encode()
        pins = json.loads((ROOT / 'dependencies.json').read_text())
        for name, pin in pins.items():
            assert run(['git', '-C', ROOT / '.deps' / name, 'rev-parse', 'HEAD']).strip() == pin['revision']
            assert not run(['git', '-C', ROOT / '.deps' / name, 'status', '--porcelain']).strip()
        report.update(baseline_revision=revision, current_revision=run(['git', 'rev-parse', 'HEAD']).strip(),
                      dependencies=pins, builds={}, environment=run(['uname', '-a']).strip(),
                      cpu=run(['lscpu']), compiler=run(['cc', '--version']).strip())
        files = [ROOT / name for name in ('CMakeLists.txt', 'dependencies.json', 'README.md', 'LICENSE.txt', '.gitignore')]
        for part in ('src', 'include', 'platform', 'config', 'tests', 'tools'):
            files.extend(path for path in (ROOT / part).rglob('*') if path.is_file() and '__pycache__' not in path.parts)
        for label in ('before', 'after'):
            source, build = folder / label / 'source', folder / label / 'build'
            for path in files:
                target = source / path.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
            if label == 'before':
                (source / 'src/tls_stream.c').write_bytes(baseline)
            (source / '.deps').symlink_to(ROOT / '.deps', target_is_directory=True)
            manifest = {str(path.relative_to(ROOT)): digest(source / path.relative_to(ROOT)) for path in files}
            (folder / label / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            run(['cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                 '-DCMAKE_C_FLAGS_RELEASE=-O2 -g', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'])
            rows = json.loads((build / 'compile_commands.json').read_text())
            assert all('-DNDEBUG' not in row['command'] and 'sanitize' not in row['command']
                       and '-O2' in shlex.split(row['command']) for row in rows)
            run(['cmake', '--build', build, '-j', '8'])
            report['builds'][label] = dict(binary=str(build / 'tls_probe'), binary_sha256=digest(build / 'tls_probe'),
                                           source_manifest=manifest, commands_sha256=digest(build / 'compile_commands.json'))
            print(f'{label}: optimized build complete; {build / "tls_probe"}', flush=True)
        changed = [name for name, value in report['builds']['before']['source_manifest'].items()
                   if report['builds']['after']['source_manifest'][name] != value]
        assert changed == ['src/tls_stream.c']
        report['passed'] = True
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'passed={report["passed"]}; evidence={folder}', flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
