"""Fetch immutable dependency revisions without changing existing checkouts."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
for name, dependency in json.loads((root / 'dependencies.json').read_text()).items():
    path = root / '.deps' / name
    if path.exists():
        head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True)
        if head != dependency['revision'] or dirty:
            raise SystemExit(f'Refusing to change existing dependency: {path}')
    else:
        path.mkdir(parents=True)
        subprocess.run(['git', 'init', str(path)], check=True)
        subprocess.run(['git', '-C', str(path), 'fetch', '--depth=1', dependency['url'], dependency['revision']], check=True)
        subprocess.run(['git', '-C', str(path), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
    subprocess.run(['git', '-C', str(path), 'submodule', 'update', '--init', '--recursive', '--depth=1'], check=True)
    print(f'{name}: {dependency["revision"]}', flush=True)
