# Implemented profile refinements

The original design document remains a specification baseline. This implementation intentionally narrows it; these restrictions are authoritative for 0.1.0a1.

- Only ordinary single-disk 32-bit ZIP stored/deflate archives without bit-3 data descriptors are accepted. ZIP64 and descriptors return unsupported. No guessed interpretation or success follows.
- Expanded filename/WHEEL tags must equal exactly `py3-none-any`.
- Unicode controls, surrogates and format characters in archive destinations are unsupported, including bidi format controls. Exact ordinary Unicode codepoints remain distinct.
- The known target's `lib64 -> lib` alias is wholly reserved; it is not treated as a disjoint prefix. `bin/activate`, `bin/activate.csh`, `bin/activate.fish`, `bin/Activate.ps1`, and scaffold directory `include/python3.12` are reserved with their file/ancestor relations.
- Hard caps are lowered as shown in `Limits`. No claim is made for the proposed design maxima.
- Unsupported analysis returns a bounded error document; partial-success report reconstruction is not offered in this release. It never returns preserved.
- No-overwrite publication uses atomic create-only hard-link publication of a complete same-directory temporary file. Explicit overwrite uses atomic replacement. There is no exists-check/replace race in create-only mode.
- Canonical conflict witnesses use the first incompatible pair by destination UTF-8 bytes and claim ID.
- Public Plan and inventory values are sealed to their immutable contents and provenance. Modified dataclass copies must be rejected by simulation.

These conservatisms trade accepted input breadth for a smaller auditable profile. Unsupported does not mean malicious or un-installable. Input/output race checks are bounded defenses, not a hostile-filesystem sandbox.
