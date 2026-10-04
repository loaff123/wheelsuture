# WheelSuture

Offline rehearsal for a declared sequence of Python wheel changes. It explains which retained distributions lose their declared payloads, which operation caused the loss, and whether a conservative repair proposal satisfies the exact desired set.

**Alpha source candidate. No environment is inspected or changed.** WheelSuture reads local digest-pinned wheels and writes deterministic evidence. It does not install packages, import payloads, run entry points, resolve dependencies, download wheels, or execute repairs.

## Why lifecycle analysis?

Two distributions can install the same bytes at the same path without an immediate mismatch. Uninstalling either can then delete the other's still-required file, while its distribution metadata remains. A collision list alone misses the destructive transition. WheelSuture keeps immutable per-distribution claims separately from actual modeled contents and retains the causal event history.

This is a narrow packaging tool, not a vulnerability scanner or a guarantee of correct imports, dependencies, ABI, permissions, or application behavior. Existing tools include ModuleGuard, check-wheel-contents, pip check and installer collision warnings. No novelty or adoption claim is made.

## Quick start

Python 3.11+ on Linux/POSIX; the sole modeled target is separately pinned to pip 26.2.1 and CPython 3.12.14. From a source checkout, install into a fresh environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
wheelsuture check examples/same_forward.json --json report.json --html report.html
# Exit 1: retained base payload missing after the slim wheel is removed
wheelsuture repair-plan examples/same_forward.json --output repair.json
# Exit 0: independently checked proposal, no installer invocation
wheelsuture verify examples/same_forward.json --report report.json --repair repair.json
wheelsuture profiles --json
```

Output paths must not already exist unless `--overwrite` is explicit. Create-only publication is atomic even when another process creates the destination concurrently. Each file is atomic; a JSON/HTML pair is not a transaction. JSON commits last, and partial publication is disclosed.

Examples contain original inert fixture wheels. Their bytes are only read and hashed. The Python API exposes `load_plan`, `inventory_wheel`, `simulate`, `propose_repair`, `verify_report`, and convenience functions `analyze` and `create_repair`. Returned documents are immutable and `to_dict()` returns a detached copy.

## Input

Strict UTF-8 JSON supplies `schema_version: 1`, an exact `profile`, `wheels` with IDs/relative paths/SHA-256, ordered `initial` installs, ordered `transition` operations, and exact `desired` wheel IDs. Operations are install, remove, reinstall, and explicit same-name replace. See [the plan schema](src/wheelsuture/schemas/plan.schema.json) and [examples](examples/).

Use only a declared empty distribution payload layer over protected interpreter scaffolding, sequential successful operations, sanitized installer conditions, no imports/bytecode, and no unknown mutations. These are profile assumptions, not facts inferred from a live machine.

## Supported boundaries

- One physical symbolic POSIX prefix; root, purelib/platlib and `.data/data` aliases are checked together
- Copied regular bytes, rewritten-script tail tokens and declared entry-point provider tokens
- Ordinary 32-bit stored/deflate ZIPs; raw/local headers, bounded actual decompression, CRC, RECORD and metadata identities checked
- Exact universal `py3-none-any` wheels; no target-native ABI claim
- No ZIP64/data descriptors, symlinks/special members, ambiguous paths, startup hooks, `.pth`, bytecode, editable/legacy metadata, scaffolding writes, cross-history file/ancestor changes or mixed signature-kind overlaps
- Unequal generated-provider signatures are unsupported, not a proof that concrete wrapper bytes must differ
- Regenerated RECORD/INSTALLER/REQUESTED/direct_url controls are modeled for presence/deletion only, never exact-byte verified

The default repair removes every currently active modeled distribution before installing every desired artifact in canonical-name order. It is intentionally conservative and makes no minimum-change claim. It is independently reconstructed from the original final state, never from an empty reset. A genuine copied-byte or rewritten-tail contradiction produces a concrete conflict witness.

## Limits and results

Published implementation caps are deliberately lower than the initial design proposal: 32 wheels; 4,096 entries/claims/deletion paths/state slots; 32 MiB aggregate archive and decoded bytes; 4 MiB per member; 20,000 events; 4,096 findings; 256 user operations; 32 MiB canonical evidence. Additional metadata/path/JSON bounds are in `Limits` and every report. Consumers may lower caps, never raise them. See [qualification](docs/QUALIFICATION.md) for measured workload coverage and limitations.

`check`: 0 preserved final modeled requirements; 1 demonstrated breakage/identity mismatch; 2 invalid input; 3 unsupported/incomplete/limit; 4 I/O/publication; 5 inconsistent evidence; 70 internal failure; 130 interrupt. Historical findings remain even if later original operations restore the final requirements. `repair-plan`: 0 verified/already satisfied proposal, 1 conflict, 3 unknown. `verify`: 0 consistent evidence, including an honest broken report; 5 tampered/inconsistent evidence; 3 incomplete verification.

## Reproduction and evidence

[Public evidence](evidence/README.md) contains the measured installer, capacity and installed-package receipts. [Reproduction instructions](qualification/REPRODUCING.md) explain exact toolchain setup and distinguish the library CI matrix from the sole installer target. No private artifact is required to inspect these results.

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build
```

Runtime dependency: `packaging`. Installer oracles are development-only and use original benign generated wheels in disposable venvs. The verifier has separately authored archive reading, metadata/RECORD parsing, destination mapping and replay; canonical encoding, immutable value types and fixed constants are shared. This reduces correlated implementation errors but cannot prove the profile assumptions.

Original code, fixtures and documentation: MIT. See [LICENSE](LICENSE), [THIRD_PARTY](THIRD_PARTY.md), [design](docs/DESIGN.md), [exact contracts](docs/CONTRACTS.md), and [supported-profile refinements](docs/SUPPORTED_PROFILE.md).
