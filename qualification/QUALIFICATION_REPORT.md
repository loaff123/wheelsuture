# WheelSuture pinned installer qualification

## Final result

**PASS on the final captured candidate source.** Selected run: `evidence/qualified-rc2` (2026-10-03, cloud-only disposable environments).

- **17 pip scenarios**, checking **39 original-operation boundaries** and every complete original-plan final state
- **11 actionful verified repairs**, replaying the exact **26 proposed actions** after reconstructing each original history in a fresh replica venv; every repair boundary and full desired final set checked
- **5 already-satisfied cases**, independently reconstructed in fresh replica venvs with zero repair actions
- **1 incompatible desired-byte case**, correctly reported as conflict rather than a successful repair
- **9 PyPA installer mapping cases**, independently checking **44 copied, rewritten-script, and entry-point claims**
- **9 external-oracle helper tests**, including negative controls for missing/changed/unmodeled payloads, omitted findings, wrong providers/interpreters, and unknown file/directory symlinks
- Read-only receipt audit passed: **406 captured files and 273 sanitized subprocess commands**

All 19 runtime Python source files in the captured snapshot match the final source hashes in `final-runtime-sha256.json`, and the live source still matched those same hashes when the gate completed. The canonical sorted path→SHA-256 manifest of all 42 captured source/schema/example JSON files hashes to:

`373a4788402c0b999aae03e48caeb252c81c86733713d5f0d929f3316ebef26a`

The immutable captured source is under `evidence/qualified-rc2/product-source`. Its file hashes are independently bound by that run's `evidence-sha256.json`. The gate imports that copy, so changes in the working source cannot silently change the tested revision.

## Exact supported profile

`pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1`

The oracle used CPython **3.12.14**, host/controller pip **26.2.1** with `--python TARGET`, fresh venvs created `--without-pip`, and controller `--isolated --disable-pip-version-check`. Installation always used explicit original local wheel paths with `--no-deps --no-index --no-compile`; reinstall used `--force-reinstall`; remove used one exact canonical project name and `--yes`. Replace was explicit remove followed by install, including same-version/different-digest replacement.

Every command receives only the declared PATH, empty disposable HOME, LC_ALL, PIP_CONFIG_FILE, PYTHONNOUSERSITE, and PYTHONDONTWRITEBYTECODE values. No parent environment is merged. All Python driver commands additionally use `-I -B`; `-B` matters because isolated Python ignores PYTHON environment variables. The controlled cwd is empty and outside every payload directory. Each target's official pip scheme and empty isolated pip configuration are measured before any fixture is installed.

The known venv scaffold was measured, hashed, and preserved. It includes `lib64 -> lib`, interpreter links, activation files, and `pyvenv.cfg`; the model's protected destinations are consistent with that measured scaffold. No user environment was examined or changed.

## What was compared independently

`oracle.py` and the subprocess controller import no WheelSuture code. The only product adapter is `product_driver.py`, which reads the public `analyze` / `create_repair` API and serializes its output. Its audit hook rejects attempted subprocess, system, exec/spawn, or network operations by product code.

For every original boundary the oracle:

1. Applies the original operation with the pinned real installer
2. Scans the disposable prefix independently, including unmodeled ordinary files and unexpected symlinks, excluding only the unchanged measured scaffold
3. Compares every modeled state destination with physical presence and content: exact SHA-256 and size for copied files; exact target-interpreter shebang and tail digest/size for rewritten scripts; actual parsed import/call provider structure for generated entry-point scripts
4. Independently checks the product's inventory destinations/signatures against original fixture declarations
5. Checks exact active identities and wheel digests using installed metadata and local-wheel provenance
6. Compares every final missing/displaced finding in the boundary report to the observed defects

The full original report is then checked again. For successful repair proposals, another fresh venv replays the full original history, followed by the exact emitted actions. Every emitted repair event boundary is compared to the real filesystem, and all desired payload/provider requirements and exact desired identities are independently checked at the end. The proposal is never replayed from an empty state while skipping the original history.

Original fixture payloads, generated scripts, and entry points are never imported or executed. All 16 wheel files were authored for this qualification; no arbitrary downloaded distribution payload was installed.

## Coverage

The 17 scenarios cover equal and unequal shared-file overlap in both installation orders; compatible-survivor removal; incompatible desired owners; disjoint deep implicit namespace contributors with composed/decomposed Unicode paths; upgrade omission; same-version replacement; force-reinstall; root-is-purelib false; all five `.data` destinations; three-way root/platlib/prefix-data aliases; canonicalized header destinations; raw scripts with flags, CRLF, no final newline, and unchanged non-Python shebangs; shared transformed script tails and shared entry-point providers; exact desired identity addition/removal; and the empty case. Ten scenarios were independently authored held-out shapes rather than production unit-test fixtures.

## Independent second implementation

Official **PyPA installer 0.7.0** was loaded from its pinned wheel in development-only tooling:

`sha256:05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53`

Each mapping case used an explicit `SchemeDictionaryDestination`, `script_kind='posix'`, bytecode optimization levels `()`, and a fresh prefix. Its default behavior refuses existing destination files; no overwrite equivalence with pip is claimed. Its results are **mapping evidence only**. It was never used as an uninstall oracle.

The tooling provenance, hash-pinned requirement, and MIT license are retained under `qualification/tooling/` inside [the public oracle archive](../evidence/qualified-rc2-evidence.zip). The selected run also captures Python's PSF license/notices, pip's MIT and bundled vendor notices, and packaging **26.3**'s Apache-2.0-or-BSD-2-Clause license texts. None is a new WheelSuture runtime dependency except the already-declared packaging library.

## Limits and remaining boundaries

This is finite original-fixture qualification for the named target profile. It is not evidence for other pip/Python versions, uv, Windows, arbitrary wheels, hostile installer execution, imports, dependency resolution, callable validity, ABI/application behavior, executable-bit correctness, or a live environment. Capacity calibration, adversarial archive/parser tests, evidence tampering, packaging, and the full source unit suite are separate gates with separate receipts.

Earlier runs are preserved as development history. `qualified-001` predates later source review fixes; `qualified-final` predates the final JSON clone correction. Neither is the selected final candidate. No failed or earlier revision receipt was rewritten to present it as a final success.

## Reproduction and archival checks

From the project root, in the exact pinned toolchain:

```sh
python -I -B qualification/build_fixtures.py
python -I -B qualification/test_oracle.py
python -I -B qualification/run_oracles.py --run-id another-unique-run
python -I -B qualification/verify_receipts.py qualification/evidence/another-unique-run
```

The run refuses overwrites. The portable evidence archive includes the selected receipts, source snapshots, original fixtures and scripts, hashes, and applicable licenses. It excludes disposable venvs, interpreter symlinks, generated bytecode, unrelated earlier runs, and user data. No repository, release, registry upload, or public publication was performed.
