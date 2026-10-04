# Resource and output/CLI review

Scope: the implemented, deliberately reduced `Limits` profile, not the much larger proposed limits in the original design. Original deterministic data-only wheels are constructed by `qualification/capacity.py`; none are installed, imported, or executed. No user computer or publication service was used.

## Reproduction and evidence

```sh
PYTHONPATH=src python qualification/capacity.py
PYTHONPATH=src python -m unittest discover -s qualification -p test_capacity.py -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_output.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_cli*.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_canonical_limits.py' -v
```

The controller writes one JSON receipt per original recipe and a SHA-256 manifest in `qualification/evidence/capacity/`. Receipts include source wheel hashes, plan-file hash, fixture sizes calculated by the writer, exact analysis counters, serialized report hash and length, per-stage elapsed/CPU measurements, process high-water RSS, and input-preservation results. Generated wheels and reports live only in disposable temporary directories; recipes and digests make them reproducible without retaining large binary payloads. The manifest binds product source files and the harness and rejects source changes during the run. Failed recipes or unexpected outcomes make the controller exit nonzero.

Each fresh child applies `RLIMIT_AS = 2,147,483,648` bytes and `RLIMIT_CPU = 60` seconds before generating fixtures or importing the product. The controller has a 120-second timeout for the whole child. Available affinity is restricted to the first two allowed CPUs (0 and 1 on this host). These controls cover fixture creation, analysis, independent report verification, repair generation (including its independent check), and independent repair verification together.

Actual host: Linux x86_64, AMD EPYC 9V74, Python 3.12.14, nine visible CPUs, approximately 9.7 GiB visible RAM. Cgroup v2 memory/CPU quota files are unavailable in this environment. This is a shared cloud host with two-CPU affinity and per-process address-space/CPU limits, **not evidence of a dedicated two-vCPU/two-GiB VM**. `RLIMIT_AS` is a virtual-address-space ceiling, not a reserved-RAM allocation. Stage RSS is the process lifetime high-water mark; it is not isolated stage-only RSS. All benchmark timing remains outside canonical evidence documents.

## Final measured result

The final unchanged-source batch qualified **37/37 recipes**. All 19 runtime source hashes match `qualification/final-runtime-sha256.json`; the harness and every receipt hash were rechecked. All original inputs remained unchanged. Highest process RSS was **351,000 KiB (342.8 MiB)** and the slowest complete child took **15.544 seconds**, including fixture creation and all analysis/repair/verification stages. Maximum individual-stage CPU time was **5.487 seconds**. No child reached its 2-GiB address-space, 60-second CPU, or 120-second wall ceiling.

The accepted exact 32-MiB report was independently verified; the byte-limit +1 receipt records attempted size 33,554,433 at the streamed preflight. The largest combined over-limit shape is rejected with resource/incomplete status before full wire-document allocation. Twelve dedicated capacity/output review tests, sixteen publication tests, twenty CLI/HTML tests, and four canonical preallocation tests passed. Additional real closed-pipe probes cover help, version, profiles, and usage-error stderr; all exit 4 without interpreter-shutdown noise. `summary.json` provides machine-readable totals and runtime tool versions. Installed pip is recorded for environment context but is not invoked by these capacity runs.

## Reachable hard-cap boundaries

The suite has complete cases and exact +1 cases for all requested core capacities:

| Counter | Exact reachable accepted boundary | +1 behavior / interaction |
|---|---:|---|
| Unique wheels | 32 | 33 refused by plan validation before inventory |
| ZIP entries | 4,096 | 4,097 refused in directory preflight before entry-object construction |
| Mapped claims | 4,096 | 4,097 refused before claim insertion |
| Deletion paths | 4,096 | Tied to mapped claims; mapped-claims check is the first cap at +1 |
| State slots | 4,096 | Reached with disjoint claims; a new unique slot also requires a new claim, so default claim cap is the first tighter cap |
| Actual decoded bytes | 33,554,432 | Exactly 33,554,433 refused by actual-output accounting |
| Aggregate archive bytes | 33,554,432 | Exactly 33,554,433 refused before archive reading/decoding |
| Member bytes | 4,194,304 | Exactly 4,194,305 refused by actual-output accounting |
| Expanded events | 20,000 | Exactly 20,001 refused before event ID/object allocation |
| Findings | 4,096 | Exactly 4,097 refused before appending the finding |
| Initial + transition operations | 256 | 257 refused by plan validation |
| Aggregate path text | 1,048,576 | Exactly 1,048,577 refused |
| Canonical report including LF | 33,554,432 | Exactly 33,554,433 refused by streamed encoding-size preflight |

Limits are intentionally interdependent. A one-wheel, 4,090-payload-member case has 4,093 ZIP entries and 4,096 claims because the source RECORD is replaced by four generated controls. The entries-only boundary uses explicit structural directories. Maximum decoded bytes are measured using deflate; maximum archive bytes use original deterministic pseudorandom stored data, leaving decoded bytes below the archive cap. Long-path coverage reaches a 1,024-byte **mapped** destination with 255-byte components; a 1,025-byte destination is unsupported. Root members inherit the fixed 29-byte site-prefix-plus-slash overhead.

The exact report boundary is a valid original-plan report combining 19,851 events, 2,032 findings, long shared paths, and bounded operation IDs. One extra character in an operation ID produces the exact report-limit +1 case. It is not a fabricated JSON object or an enlarged runtime cap. A separate long-path 20,000-event case demonstrates why 20,000 events and 32 MiB report capacity are not independently additive. A larger combined shape hits the report cap while other counters remain within their caps.

The other defense-in-depth limits (central-directory bytes, structural text sizes, plan bytes, JSON nesting, and bounded errors) are checked by budget tests and the parser corpus; this review does not claim a maximal accepted independent fixture for every one of them. The fixed schema generally reaches depth three, so depth 32 is a rejection guard rather than a supported nested-plan feature. All budget counters also have direct at-cap/+1 tests proving a failed charge leaves prior usage unchanged.

## Held-out layouts and repair behavior

Development seeds are 11 and 23; held-out seeds are 101 and 103. Six fixed held-out recipes cover three layout combinations not used to tune report boundaries: 32 dense owners across root / `.data/purelib` / `.data/data` aliases; long paths mixing ASCII and multibyte ordinary Unicode; and many zero-to-seven-byte members spread across multiple directories. These are held-out recipes within supported families, not a claim that these entire shape families were absent from all development tests. The suite does not change expectations to make an observed result pass.

Complete accepted cases are independently verified, then passed through repair generation and independent proposal verification. This includes already-satisfied cases, a concrete incompatible-desired-set conflict, and a nonempty verified repair for original damage. A near-findings-limit repair correctly returns `unknown`: reconstructing original findings leaves insufficient room for collateral findings at an intermediate repair boundary. This is evidence of the stage cap working, not a false claim that repair is impossible.

## Findings resolved during review

1. **Actual broken pipe exit was 120, with interpreter-shutdown noise.** The in-process mocked test missed the final stdout flush. A subprocess with a genuinely closed read end reproduced the failure. Terminal failure handling was corrected, and `tests/test_cli_subprocess.py` now verifies exit 4 with no shutdown traceback.
2. **Independent deflate reader failed to drain zlib's buffered output.** A valid original member containing 65,537 repeated bytes was classified as a truncated stream, and member limit+1 returned invalid instead of incomplete. The independent implementation now drains bounded `decompress(b'', ceiling)` output while preserving actual-byte, EOF, tail, and CRC checks. The raw development RED transcript is not distributed; two tests in `test_capacity.py` verify the positive input and exact lowered member-cap +1.
3. **Report bytes were originally checked after full JSON allocation.** `finalize_document` previously serialized and parsed a whole report before checking its size. That path was replaced with a bounded `JSONEncoder.iterencode` size preflight before full canonical serialization. `tests/test_canonical_limits.py` proves an over-limit report raises without calling the unbounded serializer. JSON-type object cloning remains bounded by the other item/path/event caps; this is not a hostile-input OS sandbox.

## Output and CLI review

- Create-only publication stages complete same-directory private files, flushes/fsyncs them, and atomically links the final names. A competing file, symlink, or hardlink wins without being overwritten. There is no exists-check/replace race in create-only mode.
- Explicit overwrite uses replacement rather than writing through the existing inode. Existing input paths, input hardlink aliases, output-to-output aliases, symlink destinations, and symlink parent components are rejected. Input contents are rehashed in capacity runs.
- All requested outputs are staged before any commit. JSON is committed last. Injected second-commit, directory-fsync, and interrupt failures identify already-published paths. A moved parent directory is detected before the next commit; private temporary files are cleaned up.
- Independent file outputs are not a multi-file transaction. Hostile concurrent namespace mutation is explicitly outside the security guarantee; held directory descriptors prevent ordinary symlink-parent traversal during publication.
- Broken terminal output returns output failure even if an honest report has already been committed. The committed report is retained and partial paths are disclosed rather than replacing it with an error fragment.
- Error documents are bounded, use closed status/code fields, scrub surrogate failures, and do not include internal traceback details. Existing completed outputs are preserved on failed analyses. Report-path alias protections also apply to error publication.
- HTML contains fixed CSS, no JavaScript or remote assets, and escaped text values. Hash anchors are opaque. Existing tests plus an independent HTMLParser check feed script, SVG, iframe, attribute, and URL payloads through status, metadata, findings, events, diagnostics, filenames, and repair fields; no active elements, event attributes, or unsafe links are produced. Omitted HTML events are counted explicitly and retained in JSON.
- Terminal diagnostics escape newline, ANSI, bidi, and surrogate control text. `--help`, `--version`, and profiles are offline. Public commands expose no apply/install/execute option.

## Interpretation

These measurements qualify the reduced caps for the supplied original shapes under the enforced subprocess envelope; they are not universal throughput, adversarial-complexity, dedicated-host, or OS-sandbox guarantees. There is no evidence-based need to lower the core caps from these measurements. Final measured maxima and qualification status are in the manifest and receipts, rather than inferred from successful unit tests alone.
