# Independent package and installed-runtime review

Review date: 2026-10-03 UTC. Scope: wheel and source-distribution contents,
rebuildability, installed behavior, runtime side effects, deterministic output,
original fixture data, license notices and toolchain receipts. No package was
published. No fixture wheel was installed, imported, or executed in this review.
Only WheelSuture and its pinned official `packaging` dependency enter temporary
runtime environments; official build tools remain in a separate build environment.

## Findings addressed

The initial wheel omitted `THIRD_PARTY.md` and the three packaging license texts;
the initial source distribution omitted `requirements-test.txt` and this review's
reproduction harness. The initial artifact hashes and exact missing-file assertions
were recorded before the metadata/manifest fixes. Package metadata now uses the
PEP 639 `MIT` expression, explicitly includes the notices, and requires a build
backend version supporting that metadata. `packaging` remains an external runtime
dependency, not vendored implementation code. The copied license texts are checked
byte-for-byte against that official dependency wheel.

The new package contract tests detect missing schema data, modified fixture hashes,
and forbidden runtime imports. Each check was independently made to fail against a
modified disposable copy; source package files were left untouched. All three
checks pass against the unmodified source. Runtime source inspection found no
process/network/foreign-code execution imports or dynamic `exec`/`eval` calls.

## Release gate

Use a fresh unique run ID after rebuilding the frozen candidate:

```sh
python -I qualification/package_check.py --run-id package-qualified-001
```

The selected receipt must say `status: passed`. A failed or partial rehearsal is
not qualification. The final run captures candidate artifact hashes, every archive
member's size and SHA-256, source/test/build-input hashes, exact subprocess commands
and sanitized environments, runtime audit results, document hashes, and a receipt
manifest. Final hashes belong in these external receipts rather than in the
archives themselves, avoiding a self-referential hash claim. Build-tool wheel hashes
are also shipped in `qualification/package-toolchain-sha256.json`.

The harness fails unless all of these conditions hold:

- Both distributions contain six schemas, 17 example plans and 16 original
  digest-pinned fixture wheels. Sdist tests include their JSON golden vectors
- Distributed runtime bytes equal the frozen source bytes, and all wheel `RECORD`
  hashes and sizes agree. No caches, disposable environments, downloaded tooling,
  private-key blocks, or internal implementation plans/logs appear in the archives
- Both artifacts carry the original MIT license, third-party notices and packaging
  license texts. Metadata declares exactly the intended sole runtime dependency
- The source distribution builds a wheel in a freshly unpacked temporary directory,
  with network access disabled in pip and build isolation disabled in favor of the
  already-pinned official build environment. Rebuilt/direct wheels have identical
  logical file contents; ZIP container-byte reproducibility is not claimed
- The complete unit-test suite runs outside the source checkout against the direct
  wheel and the sdist-built wheel on CPython 3.12.14. The direct wheel is also tested
  on the available CPython 3.13.5 runtime. Python's isolated mode excludes source
  `PYTHONPATH` and user-site packages during installed-suite execution
- Runtime environments contain exactly WheelSuture and packaging 26.3, with no pip
  or build tools. Package imports resolve inside the installed environment
- All 17 examples analyze, propose repairs and independently verify; tampered
  reports return verification exit 5. All 16 fixture inventories are exercised
- Audit hooks reject process creation and network operations, a finder rejects all
  fixture-module imports, and archive-origin code execution is forbidden. The
  runtime audit exercises API analysis, repair, inventory, verification and HTML
- Console and module entry points, help/version, profile catalog, invalid command,
  and all example check/repair/verify CLI sequences have their expected exit codes
- All 67 JSON/HTML/inventory output files are byte-identical across three different
  working directories, hash seeds, locale/timezone settings and all installed
  phases. Hash-seed variants use `-P -s`, rather than `-I`, so the selected seed is
  actually honored; no `PYTHONPATH` is supplied

## Limits of this review

This gate qualifies package installation and the modeled offline library behavior,
not fixture imports, dependency resolution, native execution, an actual environment
repair, or security of arbitrary installed applications. The package declares
Python 3.11+, but Python 3.11 was not available for an executed compatibility check.
Testing 3.13 exercises the library runtime; the modeled installer target remains
the single separately pinned CPython 3.12.14/pip profile.

Static scanning and audited example execution are complementary bounded checks,
not a proof that every future input cannot cause an unintended side effect. The
suite includes additional adversarial archive, evidence, output-publication and
state-machine tests documented by their respective independent reviews.
