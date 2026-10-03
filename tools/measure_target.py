"""Compile isolated TLS objects with a saved ESP-IDF command; never link or flash."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess

from measure_stack import ROOT, digest, frames


def target_command(row):
    """Replace the original TLS include/source, retaining the target configuration."""
    words = row.get('arguments') or shlex.split(row['command'])
    compiler = Path(words[0])
    if compiler.name != 'xtensa-esp32s3-elf-gcc' or not compiler.is_absolute():
        raise ValueError('Expected a direct absolute ESP32-S3 GCC command')
    source = Path(row['file']).resolve()
    flags, removed, inputs = ['-I' + str(ROOT / 'include')], [], []
    i = 1
    while i < len(words):
        word = words[i]
        if word in ('-o', '-MT', '-MF', '-MQ'):
            removed.extend(words[i:i + 2])
            i += 2
            continue
        if word == '-c':
            inputs.append(words[i + 1])
            i += 2
            continue
        if word in ('-MD', '-MMD', '-MP') or word == '-I' + str(source.parent):
            removed.append(word)
        else:
            flags.append(word)
        i += 1
    if inputs != [str(source)] or any('sanitize' in flag or 'lto' in flag for flag in flags):
        raise ValueError('Expected one unsanitized, non-LTO source compilation')
    if '-DMBEDTLS_CONFIG_FILE="mbedtls/esp_config.h"' not in flags:
        raise ValueError('The saved command must select the ESP-IDF TLS configuration')
    return compiler, flags, removed


def dependencies(path, cwd):
    text = path.read_text().replace('\\\n', ' ')
    return [((cwd / name).resolve()) for name in shlex.split(text.split(':', 1)[1])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compile-commands', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    database, sdk = args.compile_commands.resolve(), args.sdk.resolve()
    directory = ROOT / 'evidence' / ('target-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    directory.mkdir(parents=True)

    def run(command, cwd=ROOT, check=True):
        command = [str(value) for value in command]
        process = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=60)
        with (directory / 'commands.log').open('a') as log:
            log.write(shlex.join(command) + '\n' + process.stdout + process.stderr)
        if check:
            process.check_returncode()
        return process.stdout

    report = dict(passed=False, scope='Isolated ESP32-S3 wrapper compile, direct frames and layout; no link, execution or task-stack bound')
    try:
        rows = [row for row in json.loads(database.read_text()) if Path(row['file']).name == 'tls_stream.c']
        if len(rows) != 1:
            raise ValueError('Expected exactly one TLS source entry')
        row = rows[0]
        build = Path(row['directory']).resolve()
        compiler, flags, removed = target_command(row)
        tool = lambda name: compiler.with_name(compiler.name[:-3] + name)
        baseline = run(['git', 'rev-parse', '--verify', args.baseline + '^{commit}']).strip()
        report.update(current_revision=run(['git', 'rev-parse', 'HEAD']).strip(), baseline_revision=baseline,
                      compiler=run([compiler, '--version']).strip(), compiler_sha256=digest(compiler),
                      target=run([compiler, '-dumpmachine']).strip(), original_entry=row,
                      database=str(database), database_sha256=digest(database), flags=flags, removed_arguments=removed,
                      sdk=str(sdk), sdk_revision=run(['git', '-C', sdk, 'rev-parse', 'HEAD'], check=False).strip() or None)
        (directory / 'compiler-entry.json').write_text(json.dumps(row, indent=2) + '\n')
        inputs = {}
        metadata = {
            'sdkconfig.h': build / 'config/sdkconfig.h',
            'sdkconfig.json': build / 'config/sdkconfig.json',
            'esp_idf_version.h': sdk / 'components/esp_common/include/esp_idf_version.h',
            'mbedtls_build_info.h': sdk / 'components/mbedtls/mbedtls/include/mbedtls/build_info.h',
            'freertos_task.h': sdk / 'components/freertos/FreeRTOS-Kernel/include/freertos/task.h',
            'freertos_portmacro.h': sdk / 'components/freertos/FreeRTOS-Kernel/portable/xtensa/include/freertos/portmacro.h',
        }
        for name, path in metadata.items():
            (directory / name).write_bytes(path.read_bytes())
            inputs[str(path)] = digest(path)
        config = json.loads(metadata['sdkconfig.json'].read_text())
        if config['IDF_TARGET'] != 'esp32s3':
            raise ValueError('Configuration is not for ESP32-S3')
        report['configuration'] = {key: value for key, value in config.items()
                                   if key.startswith(('MBEDTLS_', 'FREERTOS_', 'LWIP_TCPIP_TASK_')) or key == 'IDF_TARGET'}
        source_files = [path for part in ('src', 'include', 'tools') for path in (ROOT / part).rglob('*')
                        if path.is_file() and '__pycache__' not in path.parts]
        (directory / 'source-manifest.json').write_text(json.dumps(
            {str(path.relative_to(ROOT)): digest(path) for path in sorted(source_files)}, indent=2) + '\n')
        before = run(['git', 'show', baseline + ':src/tls_stream.c']).encode()
        report['measurements'] = {}
        for label, source in [('before', before), ('after', (ROOT / 'src/tls_stream.c').read_bytes())]:
            folder = directory / label
            folder.mkdir()
            (folder / 'tls_stream.c').write_bytes(source)
            run([compiler, *flags, '-fstack-usage', '-MD', '-MF', folder / 'tls_stream.d',
                 '-c', folder / 'tls_stream.c', '-o', folder / 'tls_stream.o'], build)
            consumed = dependencies(folder / 'tls_stream.d', build)
            if [path for path in consumed if path.name == 'tls_stream.h'] != [ROOT / 'include/tls_stream.h']:
                raise ValueError('Compilation did not use the standalone public header')
            if (metadata['sdkconfig.h'] not in consumed or metadata['mbedtls_build_info.h'] not in consumed
                    or sdk / 'components/mbedtls/port/include/mbedtls/esp_config.h' not in consumed):
                raise ValueError('Compilation did not consume the expected target configuration')
            for path in consumed:
                previous = inputs.setdefault(str(path), digest(path))
                if digest(path) != previous:
                    raise ValueError('Compilation input changed during measurement: ' + str(path))
            types = {'stream': 'struct tls_stream', 'ssl': 'mbedtls_ssl_context', 'config': 'mbedtls_ssl_config',
                     'random': 'mbedtls_ctr_drbg_context', 'root_node': 'mbedtls_x509_crt', 'pointer': 'void *'}
            (folder / 'layout.c').write_text('#include "tls_stream.c"\n' + ''.join(
                f'const unsigned char measured_{name}[sizeof({ctype})] = {{0}};\n' for name, ctype in types.items()))
            run([compiler, *flags, '-c', folder / 'layout.c', '-o', folder / 'layout.o'], build)
            symbols = run([tool('nm'), '-S', '--defined-only', folder / 'layout.o'])
            (folder / 'layout-symbols.txt').write_text(symbols)
            sizes = {parts[3][9:]: int(parts[1], 16) for line in symbols.splitlines()
                     if len(parts := line.split()) == 4 and parts[3].startswith('measured_')}
            if set(sizes) != set(types):
                raise ValueError('Incomplete object layout measurements')
            (folder / 'disassembly.txt').write_text(run([tool('objdump'), '-dr', folder / 'tls_stream.o']))
            (folder / 'sections.txt').write_text(run([tool('size'), '-A', folder / 'tls_stream.o']))
            report['measurements'][label] = dict(frames=frames(folder / 'tls_stream.su'), sizes=sizes,
                source_sha256=digest(folder / 'tls_stream.c'), object_sha256=digest(folder / 'tls_stream.o'))
        if any(digest(Path(path)) != expected for path, expected in inputs.items()):
            raise ValueError('An input changed during measurement')
        (directory / 'input-manifest.json').write_text(json.dumps(inputs, indent=2) + '\n')
        before, after = (report['measurements'][label] for label in ('before', 'after'))
        report['read_frame_delta'] = after['frames']['tls_stream_read']['bytes'] - before['frames']['tls_stream_read']['bytes']
        report['object_layout_unchanged'] = before['sizes'] == after['sizes']
        report['passed'] = report['object_layout_unchanged']
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    for label, data in report.get('measurements', {}).items():
        print(f'{label}: read={data["frames"]["tls_stream_read"]}; sizes={data["sizes"]}')
    print(f'passed={report["passed"]}; evidence={directory}')
    if 'failure' in report:
        print(report['failure'])
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
