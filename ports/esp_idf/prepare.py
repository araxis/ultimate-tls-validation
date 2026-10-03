"""Build a per-run emulator image with a private test root and fixture UTC."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from run_probe import make_certificate
from authentication import prepare_certificates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', required=True, type=Path)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--idf-python', required=True, type=Path)
    suite = parser.add_mutually_exclusive_group()
    suite.add_argument('--authentication', choices=('rsa', 'ecdsa'),
                        help='Build rejection/recovery cases for this certificate profile')
    suite.add_argument('--timing', action='store_true', help='Build handshake/read deadline and cancellation cases')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Build as a normal user; only run.py performs privileged TAP setup.')
    directory = ROOT / 'evidence' / ('esp32-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    directory.mkdir(parents=True)
    env = os.environ.copy()
    env.update(IDF_PATH=str(args.sdk.resolve()), IDF_TOOLS_PATH=str(args.tools.resolve()))
    report = {'prepared': False, 'commands': [], 'fixture': str(directory),
              'suite': 'timing' if args.timing else ('authentication' if args.authentication else 'smoke'),
              'profile': args.authentication or 'rsa'}

    def run(command, cwd=ROOT, timeout=600):
        result = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                                capture_output=True, text=True, timeout=timeout)
        report['commands'].append({'command': list(map(str, command)), 'cwd': str(cwd),
                                   'returncode': result.returncode})
        with (directory / 'build.log').open('a') as log:
            log.write(json.dumps(report['commands'][-1]) + '\n' + result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout.strip()

    try:
        exports = run([args.idf_python, args.sdk / 'tools/idf_tools.py', 'export', '--format', 'key-value'])
        for line in exports.splitlines():
            key, value = line.split('=', 1)
            env[key] = value.replace('$PATH', env['PATH'])
        files = [ROOT / n for n in ('CMakeLists.txt', 'dependencies.json', 'README.md', 'LICENSE.txt', '.gitignore')]
        for name in ('src', 'include', 'platform', 'config', 'tests', 'tools', 'ports'):
            files.extend(p for p in (ROOT / name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        manifest = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
        (directory / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        with zipfile.ZipFile(directory / 'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in manifest:
                archive.write(ROOT / name, name)
        if args.authentication:
            prepare_certificates(directory, args.authentication == 'ecdsa')
        else:
            make_certificate(directory, 'trusted')
            extension = directory / 'trusted.ext'
            extension.write_text(extension.read_text().replace('DNS:tls.lab.test', 'DNS:tls.lab.test,IP:192.0.2.1'))
            run(['openssl', 'x509', '-req', '-in', 'trusted.csr', '-CA', 'trusted-ca.pem',
                 '-CAkey', 'trusted-ca.key', '-set_serial', '1', '-days', '2',
                 '-out', 'trusted.pem', '-extfile', 'trusted.ext'], cwd=directory)
        report['certificate_verification'] = run(['openssl', 'verify', '-CAfile', 'trusted-ca.pem',
            '-no-CApath', '-no-CAstore', '-purpose', 'sslserver', '-verify_ip', '192.0.2.1', 'trusted.pem'], cwd=directory)
        utc = int(time.time())
        root = (directory / 'trusted-ca.pem').read_text()
        (directory / 'fixture.h').write_text(
            '#define LAB_RUN_ID ' + json.dumps(directory.name) + '\n' +
            '#define LAB_UTC_SECONDS ' + str(utc) + 'LL\n' +
            ('#define LAB_TIMING 1\n' if args.timing else '') +
            ('#define LAB_AUTHENTICATION 1\n#define LAB_ECDSA ' + str(int(args.authentication == 'ecdsa')) + '\n'
             if args.authentication else '') +
            'static const unsigned char lab_root[] = ' + json.dumps(root) + ';\n')
        report['fixture_utc_seconds'] = utc
        cache = Path.home() / '.cache/ultimate-tls-validation'
        cache.mkdir(parents=True, exist_ok=True)
        build = Path(tempfile.mkdtemp(prefix='idf-probe-', dir=cache))
        report['build_directory'] = str(build)
        run([args.idf_python, args.sdk / 'tools/idf.py', '-B', build,
             '-D', 'IDF_TARGET=esp32s3', '-D', 'SDKCONFIG=' + str(build / 'sdkconfig'),
             '-D', 'LAB_FIXTURE_DIR=' + str(directory), 'build'], cwd=ROOT / 'ports/esp_idf')
        run([args.idf_python, '-m', 'esptool', '--chip', 'esp32s3', 'merge_bin',
             '--fill-flash-size', '4MB', '-o', directory / 'flash.bin', '@flash_args'], cwd=build)
        for name in ('tls_port_probe.elf', 'tls_port_probe.map', 'compile_commands.json', 'sdkconfig',
                     'project_description.json', 'config/sdkconfig.json', 'config/sdkconfig.h'):
            shutil.copyfile(build / name, directory / Path(name).name)
        assert all(hashlib.sha256((ROOT / n).read_bytes()).hexdigest() == h for n, h in manifest.items())
        report['prepared'] = True
    except Exception as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['artifacts'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in directory.iterdir() if p.is_file()}
        (directory / 'build-result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'prepared': report['prepared'], 'evidence': str(directory),
                          'failure': report.get('failure')}, indent=2), flush=True)
    return 0 if report['prepared'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
