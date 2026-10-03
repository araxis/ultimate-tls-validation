"""Compare compiler-reported TLS wrapper frames; not a task stack bound."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_flags(command):
    """Retain the actual target flags, removing only input/output bookkeeping."""
    words = shlex.split(command)
    if not words or Path(words[0]).name not in ('cc', 'gcc'):
        raise ValueError('This measurement requires a direct GCC command')
    flags, sources = [], []
    i = 1
    while i < len(words):
        word = words[i]
        if word in ('-o', '-MT', '-MF'):
            i += 2
            continue
        if word == '-c':
            sources.append(words[i + 1])
            i += 2
            continue
        if word not in ('-MD', '-MMD'):
            flags.append(word)
        i += 1
    if sources != [str(ROOT / 'src/tls_stream.c')] or any('sanitize' in flag or 'lto' in flag for flag in flags):
        raise ValueError('Use the ordinary non-LTO, non-sanitized TLS build')
    return words[0], flags


def frames(path):
    result = {}
    for line in path.read_text().splitlines():
        location, size, kind = line.split('\t')
        name = location.rsplit(':', 1)[1]
        if name in result:
            raise ValueError(f'Duplicate frame report: {name}')
        result[name] = dict(bytes=int(size), qualifier=kind)
    if 'tls_stream_read' not in result:
        raise ValueError('No TLS read frame in compiler output')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, default=ROOT / 'build')
    parser.add_argument('--baseline', required=True, help='Local Git revision before the change')
    args = parser.parse_args()
    build = args.build.resolve()
    directory = ROOT / 'evidence' / ('stack-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    directory.mkdir(parents=True)
    log = directory / 'commands.log'

    def run(command, cwd=ROOT, strip=True):
        completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=60)
        with log.open('a') as output:
            output.write(shlex.join([str(arg) for arg in command]) + '\n')
            output.write(completed.stdout + completed.stderr)
        completed.check_returncode()
        return completed.stdout.strip() if strip else completed.stdout

    report = dict(passed=False, scope='GCC direct function frames and object layout; no task/call-chain stack bound')
    try:
        files = [ROOT / name for name in ('CMakeLists.txt', 'dependencies.json', 'README.md', 'LICENSE.txt', '.gitignore')]
        for name in ('src', 'include', 'platform', 'config', 'tests', 'tools'):
            files.extend(path for path in (ROOT / name).rglob('*') if path.is_file() and '__pycache__' not in path.parts)
        manifest = {str(path.relative_to(ROOT)): digest(path) for path in sorted(files)}
        (directory / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        baseline = run(['git', 'rev-parse', '--verify', args.baseline + '^{commit}'])
        current = run(['git', 'rev-parse', 'HEAD'])
        before = run(['git', 'show', f'{baseline}:src/tls_stream.c'], strip=False).encode()
        command = run(['ninja', '-C', str(build), '-t', 'commands', 'CMakeFiles/tls_stream.dir/src/tls_stream.c.o'])
        if '\n' in command:
            raise ValueError('Expected one TLS compiler command')
        compiler, flags = compiler_flags(command)
        version = run([compiler, '--version'])
        if 'Free Software Foundation' not in version:
            raise ValueError('GCC stack-usage format is required')
        pins = json.loads((ROOT / 'dependencies.json').read_text())
        for name, pin in pins.items():
            assert run(['git', '-C', str(ROOT / '.deps' / name), 'rev-parse', 'HEAD']) == pin['revision']
            assert not run(['git', '-C', str(ROOT / '.deps' / name), 'status', '--porcelain'])
        report.update(baseline_revision=baseline, current_revision=current, dependencies=pins,
                      compiler=version, target=run([compiler, '-dumpmachine']),
                      original_command=command, profiles={})
        optimized_flags = [flag for flag in flags if not flag.startswith('-O')]
        for profile, options in [('as-built', flags), ('O2', optimized_flags + ['-O2']), ('Os', optimized_flags + ['-Os'])]:
            results = {}
            for label, source in [('before', before), ('after', (ROOT / 'src/tls_stream.c').read_bytes())]:
                folder = directory / profile / label
                folder.mkdir(parents=True)
                (folder / 'tls_stream.c').write_bytes(source)
                object_path = folder / 'tls_stream.o'
                run([compiler, *options, '-fstack-usage', '-c', str(folder / 'tls_stream.c'), '-o', str(object_path)], build)
                frame_report = frames(folder / 'tls_stream.su')
                sections = run(['size', '-A', str(object_path)])
                disassembly = run(['objdump', '-dr', str(object_path)])
                (folder / 'disassembly.txt').write_text(disassembly + '\n')
                (folder / 'sections.txt').write_text(sections + '\n')
                # Compile only; these diagnostic arrays never enter the executable.
                types = {'stream': 'struct tls_stream', 'ssl': 'mbedtls_ssl_context',
                         'config': 'mbedtls_ssl_config', 'random': 'mbedtls_ctr_drbg_context',
                         'root_node': 'mbedtls_x509_crt', 'pointer': 'void *'}
                layout = '#include "tls_stream.c"\n' + ''.join(
                    f'const unsigned char measured_{name}[sizeof({ctype})] = {{0}};\n' for name, ctype in types.items())
                (folder / 'layout.c').write_text(layout)
                run([compiler, *options, '-c', str(folder / 'layout.c'), '-o', str(folder / 'layout.o')], build)
                symbols = run(['nm', '-S', '--defined-only', str(folder / 'layout.o')])
                (folder / 'layout-symbols.txt').write_text(symbols + '\n')
                sizes = {parts[3][9:]: int(parts[1], 16) for line in symbols.splitlines()
                         if len(parts := line.split()) == 4 and parts[3].startswith('measured_')}
                if set(sizes) != set(types):
                    raise ValueError('Incomplete layout measurements')
                results[label] = dict(flags=options, frames=frame_report, sizes=sizes,
                                      source_sha256=digest(folder / 'tls_stream.c'), object_sha256=digest(object_path))
            results['read_frame_delta'] = results['after']['frames']['tls_stream_read']['bytes'] - results['before']['frames']['tls_stream_read']['bytes']
            results['object_layout_unchanged'] = results['before']['sizes'] == results['after']['sizes']
            report['profiles'][profile] = results
        report['passed'] = all(profile['object_layout_unchanged'] for profile in report['profiles'].values())
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    for name, profile in report.get('profiles', {}).items():
        before = profile['before']['frames']['tls_stream_read']
        after = profile['after']['frames']['tls_stream_read']
        print(f'{name}: read frame {before} -> {after}; delta={profile["read_frame_delta"]}; layout_unchanged={profile["object_layout_unchanged"]}')
    print(f'passed={report["passed"]}; evidence={directory}')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
