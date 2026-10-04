# Bounded qualification

WheelSuture 0.1.0a1 is an alpha source/package candidate. Its enabled profile asserts only exact final declared distribution identities and tracked payload/provider requirements under the documented preconditions. It does not establish import/application correctness, package safety or unknown live-environment state.

## Source checks

- Fresh complete source suite: 198 test methods passed on CPython 3.12.14
- Critical Ruff checks (`E9,F63,F7,F82`) and source byte-compilation passed
- All six strict JSON schemas ship with the package; all 17 original-fixture reports and repair documents, sample inventory and profile catalog validated
- Three published canonical golden vectors match
- Independent review covers archive parsing, state/repair causality, full-evidence tampering, output races, resource accounting and package contents

The separately authored verifier imports no production archive parser, inventory, mapping, reducer or repair algorithm. Shared encoding/hash routines, fixed constants, immutable values, accounting primitives and packaging normalization remain common dependencies. Complete canonical report and repair reconstruction is compared, including counters, IDs, events, findings and causes.

The state review checked 23,347 exhaustive reducer cases, 3,061 exhaustive synthetic repair cases, 64 held-out 20-operation histories, and a real-wheel unmocked repair/verifier integration case. Synthetic repair tests intentionally bypass only the certificate gate and do not count as installer qualification.

## Real installer and second mapping oracle

Final captured runtime revision: 19 source modules, matched before and after qualification. Snapshot manifest SHA-256: `373a4788402c0b999aae03e48caeb252c81c86733713d5f0d929f3316ebef26a`.

- CPython 3.12.14, official controller pip 26.2.1, `--python` targeting disposable `--without-pip` venvs
- 17 original-fixture cases and 39 original-operation boundaries, including 10 held-out cases
- 11 actionful verified repairs, 26 actual emitted repair actions; 5 already-satisfied replica histories; 1 incompatible-desired-byte conflict
- Every original and repair boundary compared to external filesystem/installed-record observations; exact copied bytes, rewritten tails, provider destinations and final desired identities checked
- Independent PyPA installer 0.7.0 mapping oracle: 9 layouts and 44 claims, explicit scheme, no bytecode, default refusal to overwrite
- 273 sanitized commands and 406 captured files passed the portable receipt audit

No fixture payload was imported or executed. Only original inert generated wheels were installed by the development oracle. Runtime audit guards reject product process/network calls. PyPA installer provides mapping evidence only, not pip uninstall semantics. Two pip versions from the earlier design study are not treated as two independent installer implementations.

Exact commands, toolchain/source hashes, scaffold manifests, observed states and reproducible original fixtures are in [the public evidence bundles](../evidence/README.md). Disposable venvs are excluded. The oracle archive includes the pinned official PyPA installer 0.7.0 wheel with its license and provenance; no third-party wheel is included in the installed WheelSuture package.

## Resource calibration

All 37 deterministic constrained recipes passed with unchanged runtime/harness hashes, including held-out dense aliases, UTF-8 long paths and many tiny members. Reachable exact boundaries and limit-plus-one outcomes include 32 wheels, 4,096 entries/claims/state slots, 32 MiB archive/actual decoded bytes, 4 MiB member, 20,000 events, 4,096 findings, 256 operations, 1 MiB aggregate path text and a 32 MiB canonical report. Some counters share a tighter first limit; the resource review states those relationships rather than inventing impossible simultaneous maxima.

Worst observed process RSS: 351,000 KiB (about 342.8 MiB). Worst whole-child elapsed time: 15.544 seconds, including original fixture generation, analysis, independent verification, proposal generation and repair verification. Maximum measured individual-stage CPU time: 5.487 seconds. These measurements do not promise throughput for every supported input.

Children used two-CPU affinity, a 2 GiB virtual-address-space limit, 60-second CPU limit and 120-second controller timeout. The host exposed nine CPUs and about 9.7 GiB RAM; cgroup quota files were unavailable. This is evidence for process-constrained runs on a shared Linux host, not a dedicated two-vCPU/two-GiB VM. Full hardware/clock/RSS meanings are documented in `reviews/resources-output.md`.

Canonical serialization is size-preflighted through encoded chunks before a complete over-limit wire document can be allocated. Other item/path/event caps bound the in-memory model. No hostile-input sandbox or universal worst-case proof is claimed. The much larger initial design maxima remain unqualified and are not enabled.

## Distribution checks and remaining limits

Final artifact-specific installation results and SHA-256 values are delivered beside the wheel/sdist in the package verification receipt. The gate installs the wheel and a wheel rebuilt from the sdist in clean cloud venvs, runs all shipped tests outside the source import path, exercises all bundled examples, checks CLI/API parity and determinism, verifies RECORD and archive contents, and audits licenses/privacy. Additional CPython 3.13.5 library results are identified in that receipt when completed.

The historical local qualification ran on CPython 3.12.14 and 3.13.5. The public repository separately runs its library test/build matrix on Python 3.11, 3.12, 3.13 and 3.14; consult the Actions result for the exact commit. A configured job alone is not a passing result. The target installer profile remains CPython 3.12.14/pip 26.2.1 regardless of the interpreter running the analysis library. ZIP64/data descriptors, native-target tags, unknown provider overlap, live environments, dependency resolution, concurrency and arbitrary installer behavior remain explicitly unsupported. No repository, registry, release tag or public site was created by this qualification.
