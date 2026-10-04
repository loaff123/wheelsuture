# Reproducing the bounded checks

Use a disposable Linux x86_64 workspace and the [complete repository checkout](https://github.com/loaff123/wheelsuture), including its public evidence directory. Source distributions omit the archived evidence ZIPs; those remain available at the same public repository. Product runtime only reads supplied wheels; the development installer oracle intentionally installs original inert fixtures into newly created disposable venvs. It never imports their payloads. Do not point qualification tooling at an existing user environment.

## Library tests and build

Python 3.11–3.14 is the library interpreter matrix, independent of the sole modeled installer profile. From a source checkout:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install . build jsonschema
python -m unittest discover -s tests -v
python -m build
```

Public CI runs those test/build steps separately on each declared interpreter. The final Actions result and commit identity determine which runs passed.

## Exact installer oracle

The historical gate requires official CPython **3.12.14**, controller pip **26.2.1**, packaging **26.3**, and PyPA installer **0.7.0**. Other versions are not qualified substitutes. Start with the exact interpreter installed by an official source and prepare a fresh controller:

```sh
python3.12 -m venv .qualification-controller
.qualification-controller/bin/python -m pip install pip==26.2.1 packaging==26.3
.qualification-controller/bin/python -c 'import platform; assert platform.python_version() == "3.12.14"'
mkdir -p qualification/tooling/downloads
.qualification-controller/bin/python -m pip download --no-deps --only-binary=:all: installer==0.7.0 -d qualification/tooling/downloads
echo '05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53  qualification/tooling/downloads/installer-0.7.0-py3-none-any.whl' | sha256sum -c -
.qualification-controller/bin/python -I -B qualification/build_fixtures.py
.qualification-controller/bin/python -I -B qualification/test_oracle.py
.qualification-controller/bin/python -I -B qualification/run_oracles.py --run-id my-fresh-oracle-run
.qualification-controller/bin/python -I -B qualification/verify_receipts.py qualification/evidence/my-fresh-oracle-run
```

The pinned installer wheel and its license/provenance are also inside the public oracle evidence ZIP. A new run refuses to overwrite an existing run ID. `--oracle-only`, `--mapping-only` and `--analysis-only` are reduced scopes and must not be represented as the full gate.

## Capacity and adversarial checks

Using the exact 3.12.14 controller with packaging installed:

```sh
PYTHONPATH=src .qualification-controller/bin/python qualification/capacity.py
PYTHONPATH=src .qualification-controller/bin/python -m unittest discover -s qualification -p test_capacity.py -v
PYTHONPATH=src .qualification-controller/bin/python -m unittest discover -s tests -v
```

Capacity timing depends on the actual host. The historical receipts describe two-CPU affinity and per-process address-space/CPU limits on a shared host, not a dedicated VM or guaranteed performance. Raw new tracebacks can contain your workspace paths; review and redact those paths before publishing copies, rebinding affected manifest hashes.

## Installed wheel and source-distribution gate

This gate expects six exact official wheels under `qualification/package-tooling`, a pinned build environment there, and candidate distributions under `dist/`. Prepare them before invoking `package_check.py`:

```sh
mkdir -p qualification/package-tooling
.qualification-controller/bin/python -m pip download --no-deps --only-binary=:all: -d qualification/package-tooling build==1.4.0 packaging==26.3 pyproject_hooks==1.2.0 ruff==0.16.10 setuptools==84.0.0 wheel==0.47.0
.qualification-controller/bin/python - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('qualification')
pins = json.loads((root / 'package-toolchain-sha256.json').read_text())
for name, expected in pins.items():
    actual = hashlib.sha256((root / 'package-tooling' / name).read_bytes()).hexdigest()
    assert actual == expected, name
print('All six official tool wheels match')
PY
.qualification-controller/bin/python -m venv qualification/package-tooling/build-env
qualification/package-tooling/build-env/bin/python -m pip install --no-index --find-links qualification/package-tooling build==1.4.0 packaging==26.3 pyproject_hooks==1.2.0 setuptools==84.0.0 wheel==0.47.0
qualification/package-tooling/build-env/bin/python -m build --no-isolation
.qualification-controller/bin/python -I qualification/package_check.py --run-id my-fresh-package-run --python313 /path/to/official/python3.13
```

The pinned Ruff filename is for Linux x86_64. An incompatible wheel, unavailable exact version, or hash mismatch is a blocker, not permission to change the recorded toolchain silently. Use CPython **3.13.5** for the third installed phase if reproducing that original result. If `--python313` is absent or points to a missing executable, the harness records that phase as unavailable; two passing phases do not establish a three-phase result.

This checkout contains publication-only documentation corrections, so freshly built artifacts have new hashes. Compare runtime/schema/fixture bytes and inspect your new artifact-specific receipts rather than expecting the original complete sdist container hash. Never label a partial or failed run as qualification.
