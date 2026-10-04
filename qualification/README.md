# Independent installer qualification

This directory contains development-only experiments. WheelSuture's runtime never invokes these scripts or an installer. All wheel payloads are original inert MIT-licensed fixtures, never imported or executed. The installer commands mutate only newly created disposable venvs in the evidence run.

## Exact scope

- CPython 3.12.14, host/controller pip 26.2.1 using `--python TARGET`, target created `--without-pip`
- Fresh explicit six-variable sanitized environment, no inherited variables, controlled nonpayload cwd, empty HOME, `/dev/null` pip config
- Every target's official pip scheme and empty isolated configuration are checked before installing a fixture
- Full independent filesystem scan after every original user-operation boundary; exact hashes for copied files, tail hashes for rewritten scripts, syntax/import/call checks for entry-point providers
- Product source is copied into each captured run before testing, so concurrent development cannot change the tested revision
- Fixture-declared destinations and signatures independently checked against all product inventories
- Every final missing/displaced finding compared to actual observed defects, exact distribution identities/digests checked against installed metadata and local-wheel provenance
- Every emitted repair action replayed in a fresh replica of the complete original history; each repair boundary checked against emitted events and the final desired set independently rechecked
- PyPA installer 0.7.0 used only as a second mapping implementation with explicit `SchemeDictionaryDestination`, no bytecode, and default refusal to overwrite existing paths. Each fixture receives a fresh prefix. It is not an uninstall oracle
- No dependency resolution, imports, callable validity, native behavior, application validity, permissions, or environment-security claim

The core corpus covers equal and unequal overlaps in both orders, incompatible desired files, disjoint deep Unicode namespaces, upgrade omission, same-version replacement, reinstall, all five `.data` schemes, purelib/platlib/prefix-data aliases, canonicalized headers, CRLF and no-LF rewritten scripts, shared rewritten scripts and entry-point providers, exact identity addition/removal, and the empty case. Ten of seventeen scenarios were held out from production implementation.

## Reproduce

Follow [REPRODUCING.md](REPRODUCING.md) to prepare the exact pinned official Python/pip environment and the generated fixture/tooling directories. The public oracle archive includes the official installer wheel, its hash-pinned requirement and MIT license. It is loaded only by the mapping driver and never installed into the user environment.

```sh
python -I qualification/build_fixtures.py
python -I qualification/test_oracle.py
python -I qualification/run_oracles.py --run-id new-unique-run
python -I qualification/verify_receipts.py qualification/evidence/new-unique-run
```

The harness refuses to overwrite a run. `--analysis-only` excludes repair qualification, `--oracle-only` excludes product comparison, and `--mapping-only` runs only PyPA mapping. A result from one of these reduced modes must not be represented as the full gate.

`product_driver.py` is the only adapter importing WheelSuture. `oracle.py`, the main subprocess harness, receipt verifier, and installer driver never import the product. Installed providers are parsed as text/AST, never run. The hash comparison has negative tests for missing, changed, and unmodeled files, omitted findings, incorrect providers, and unexpected symlinks.

## Evidence

Each run captures the command transcript, sanitized environment contract, toolchain and source hashes/licenses, exact empty-venv scaffold, per-boundary observations, product JSON, full repair proposals, and a SHA-256 manifest. Paths in receipts are portable placeholders. The `disposable/` subtree contains throwaway local venvs and must be excluded from archival bundles; it is not portable evidence. The archived receipts contain all observations necessary to inspect the result.

Early failed runs are retained as development history: the first mapping attempt mistakenly treated the known interpreter symlink as payload; the first differential attempt omitted an output-parent mkdir; the next attempt reached the verifier before its implementation was ready. These failures are not qualified results. Consult the final qualification report for the selected successful full run.
