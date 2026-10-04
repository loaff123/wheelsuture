"""Original inert byte-level fixtures for the bounded archive review.

The fixture writer below only emits test bytes. No payload is installed,
imported, executed, extracted, or read from an existing environment.
"""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from wheelsuture.constants import PROFILE_ID
from wheelsuture.errors import InvalidInput, LimitExceeded, UnsupportedInput
from wheelsuture.inventory import inventory_wheel
from wheelsuture.model import Budget, DEFAULT_LIMITS, Profile, WheelSource


def extra(code, data):
    return struct.pack('<HH', code, len(data)) + data


def review_members(payload=None, *, metadata=None, record_size=None, entrypoints=None, name='review'):
    """Small independently authored wheel declaration, with exact RECORD."""
    dist = name + '-1.0.dist-info'
    members = dict(payload if payload is not None else {'review/data.txt': b'inert original fixture\n'})
    members[dist + '/METADATA'] = metadata or ('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n\n').encode()
    members[dist + '/WHEEL'] = b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n'
    if entrypoints is not None:
        members[dist + '/entry_points.txt'] = entrypoints
    rows = []
    for name, data in members.items():
        token = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        rows.append([name, 'sha256=' + token, str(len(data))])
    if record_size is not None:
        rows[0][2] = record_size
    rows.append([dist + '/RECORD', '', ''])
    record = io.StringIO(newline='')
    csv.writer(record, lineterminator='\n').writerows(rows)
    members[dist + '/RECORD'] = record.getvalue().encode()
    return members


def review_zip(members, *, first=None, comment=b''):
    """Ordinary local/CD ZIP writer with deliberate first-entry disagreements."""
    local, central = bytearray(), bytearray()
    first = first or {}
    for index, (name, data) in enumerate(members.items()):
        opts = first if index == 0 else {}
        name_raw = name.encode('utf-8')
        flags = opts.get('flags', 0x800)
        method = opts.get('method', 8)
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(data) + compressor.flush() if method == 8 else data
        compressed = opts.get('stream', lambda value: value)(compressed)
        size = opts.get('decoded', len(data))
        crc = opts.get('crc', zlib.crc32(data) & 0xffffffff)
        offset = len(local)
        local_name = opts.get('local_name', name_raw)
        central_name = opts.get('central_name', name_raw)
        local_extra = opts.get('local_extra', b'')
        central_extra = opts.get('central_extra', b'')
        local += struct.pack('<4s5H3I2H', b'PK\x03\x04', opts.get('local_needed', 20),
                             opts.get('local_flags', flags), opts.get('local_method', method),
                             0, 0, opts.get('local_crc', crc), len(compressed), size,
                             len(local_name), len(local_extra))
        local += local_name + local_extra + compressed
        central += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', opts.get('made', 0x314),
                               opts.get('central_needed', 20), flags, method, 0, 0, crc,
                               len(compressed), size, len(central_name), len(central_extra),
                               0, 0, 0, opts.get('external', (0o40755 if name.endswith('/') else 0o100644) << 16),
                               opts.get('offset', offset))
        central += central_name + central_extra
    count = len(members)
    return bytes(local + central + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, count,
                 count, len(central), len(local), len(comment)) + comment)


class ReviewFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write_case(self, blob, *, install=True):
        wheel = self.root / 'review-1.0-py3-none-any.whl'
        wheel.write_bytes(blob)
        source = {'id': 'review', 'path': wheel.name, 'sha256': hashlib.sha256(blob).hexdigest()}
        plan = dict(schema_version=1, profile=PROFILE_ID, wheels=[source],
                    initial=[{'id': 'first', 'op': 'install', 'wheel': 'review'}] if install else [],
                    transition=[], desired=['review'] if install else [])
        plan_path = self.root / 'plan.json'
        plan_path.write_text(json.dumps(plan), encoding='utf-8')
        return source, plan_path

    def production(self, blob, *, limits=DEFAULT_LIMITS):
        source, _ = self.write_case(blob)
        return inventory_wheel(WheelSource(**source, base=self.root), Profile(PROFILE_ID), Budget(limits))


class ArchiveReviewTests(ReviewFixture):
    def test_original_fixture_is_accepted(self):
        value = self.production(review_zip(review_members())).to_dict()
        self.assertEqual(value['canonical_name'], 'review')
        self.assertEqual(value['member_count'], 4)

    def test_raw_header_contradictions_are_invalid(self):
        cases = [dict(local_name=b'review/data.txX'), dict(local_flags=0),
                 dict(local_method=0), dict(local_crc=0), dict(local_name=b'review/da\x00a.txt'),
                 dict(central_name=b'review/da\x00a.txt'), dict(offset=1)]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(InvalidInput):
                self.production(review_zip(review_members(), first=changed))

    def test_same_raw_name_with_different_encoding_flags_is_duplicate(self):
        members = review_members({'review/caf├⌐.txt': b'first', 'review/café.txt': b'second'})
        raw = b'review/caf\xc3\xa9.txt'
        with self.assertRaises(InvalidInput):
            self.production(review_zip(members, first={'flags': 0, 'central_name': raw, 'local_name': raw}))

    def test_deflate_extent_and_actual_size_are_fully_validated(self):
        cases = [dict(decoded=1), dict(stream=lambda b: b[:-1]),
                 dict(stream=lambda b: b + b'ignored'), dict(stream=lambda b: b + b)]
        for index, changed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(InvalidInput):
                self.production(review_zip(review_members(), first=changed))

    def test_hidden_deflate_output_hits_actual_budget(self):
        from dataclasses import replace
        blob = review_zip(review_members({'review/data.txt': b'x' * 10000}), first={'decoded': 1})
        with self.assertRaises(LimitExceeded):
            self.production(blob, limits=replace(DEFAULT_LIMITS, member_bytes=1024))

    def test_unknown_unicode_and_duplicate_extras_are_not_silently_used(self):
        cases = [(extra(0x7075, b'\x01\0\0\0\0alternate'), UnsupportedInput),
                 (extra(0xdead, b''), UnsupportedInput),
                 (extra(0x5455, b'\0') * 2, InvalidInput),
                 (b'\x55\x54\x09\x00\x00', InvalidInput)]
        for field in ('central_extra', 'local_extra'):
            for value, error in cases:
                with self.subTest(field=field, value=value), self.assertRaises(error):
                    self.production(review_zip(review_members(), first={field: value}))

    def test_timestamp_extras_must_match_their_header_context(self):
        # Central timestamp only includes mtime when flag 0 is set. Local has
        # every timestamp selected by the three flags, including atime/ctime.
        cases = [dict(central_extra=extra(0x5455, b'\x02' + b'\0' * 4)),
                 dict(local_extra=extra(0x5455, b'\x03' + b'\0' * 4))]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(InvalidInput):
                self.production(review_zip(review_members(), first=changed))

    def test_duplicate_ntfs_attribute_is_rejected(self):
        duplicate = extra(0x000a, b'\0' * 4 + (struct.pack('<HH', 1, 24) + b'\0' * 24) * 2)
        with self.assertRaises(UnsupportedInput):
            self.production(review_zip(review_members(), first={'central_extra': duplicate}))

    def test_reserved_include_python_directory_cannot_be_payload_file(self):
        # This is explicitly reserved by SUPPORTED_PROFILE.md.
        blob = review_zip(review_members({'review-1.0.data/data/include/python3.12': b'inert'}))
        with self.assertRaises(UnsupportedInput):
            self.production(blob)

    def test_stored_method_cannot_claim_deflate_option_bits(self):
        with self.assertRaises(UnsupportedInput):
            self.production(review_zip(review_members(), first={'method': 0, 'flags': 0x802}))

    def test_archive_trailing_bytes_and_prepended_stub_are_invalid(self):
        blob = review_zip(review_members())
        for changed in (blob + b'unknown trailer', b'stub' + blob):
            with self.subTest(length=len(changed)), self.assertRaises(InvalidInput):
                self.production(changed)

    def test_eocd_magic_inside_an_exact_comment_is_not_an_end_record(self):
        comments = (b'original comment PK\x05\x06 inert suffix',
                    b'original comment ' + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 0, 0, 0, 0, 0),
                    b'original comment ' + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 65535, 65535, 0, 0, 0))
        for comment in comments:
            with self.subTest(comment=comment):
                blob = review_zip(review_members(), comment=comment)
                self.assertEqual(self.production(blob).to_dict()['canonical_name'], 'review')
