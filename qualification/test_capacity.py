"""Fast capacity and output qualification checks, not timed benchmarks."""

import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capacity import build_case, canonical, case_specs, path_of_length
from wheelsuture.errors import LimitExceeded
from wheelsuture.model import Budget, DEFAULT_LIMITS, Limits
from wheelsuture import zipscan
from wheelsuture.output import publish_outputs


class CapacityTests(unittest.TestCase):
    def test_every_aggregate_counter_rejects_plus_one_without_changing_usage(self):
        for name, cap in DEFAULT_LIMITS.to_dict().items():
            if name == "error_bytes":
                continue
            with self.subTest(counter=name):
                budget = Budget()
                budget.charge(name, cap)
                with self.assertRaises(LimitExceeded):
                    budget.charge(name, 1)
                self.assertEqual(budget.usage[name], cap)

    def test_every_high_water_counter_rejects_plus_one_without_changing_usage(self):
        for name, cap in DEFAULT_LIMITS.to_dict().items():
            if name == "error_bytes":
                continue
            with self.subTest(counter=name):
                budget = Budget()
                budget.maximum(name, cap)
                with self.assertRaises(LimitExceeded):
                    budget.maximum(name, cap + 1)
                self.assertEqual(budget.usage[name], cap)

    def test_central_directory_entry_plus_one_stops_before_entry_construction(self):
        count = DEFAULT_LIMITS.entries + 1
        directory_size = count * 46
        raw = b"\0" * directory_size + struct.pack(
            "<4s4H2IH", b"PK\x05\x06", 0, 0, count, count, directory_size, 0, 0
        )
        budget = Budget()
        with patch.object(
            zipscan, "_Entry", side_effect=AssertionError("allocated an entry")
        ):
            with self.assertRaisesRegex(LimitExceeded, "entries"):
                zipscan._preflight(io.BytesIO(raw), len(raw), budget)
        self.assertEqual(budget.usage["entries"], 0)

    def test_event_plus_one_stops_before_event_id_or_object_creation(self):
        from wheelsuture import reducer

        replay = reducer.Replay.__new__(reducer.Replay)
        replay.budget = Budget(Limits(expanded_events=0))
        replay.slots = {}
        claim = {
            "destination": "payload/x.dat",
            "signature": {"kind": "bytes"},
            "kind": "copied",
        }
        with patch.object(
            reducer, "digest", side_effect=AssertionError("event allocation started")
        ):
            with self.assertRaisesRegex(LimitExceeded, "expanded_events"):
                replay._event({"operation_id": "x"}, claim, True, 0)
        self.assertEqual(replay.budget.usage["expanded_events"], 0)

    def test_long_paths_reach_claimed_lengths_with_bounded_components(self):
        for size in (30, 850, 950, 970, 997):
            p = path_of_length(123, size)
            self.assertEqual(len(p.encode()), size)
            self.assertTrue(all(len(x) <= 255 for x in p.split("/")))

    def test_independent_deflate_decoder_drains_buffered_output(self):
        from capacity import make_wheel
        from wheelsuture.verify._source import decode_archive

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, _ = make_wheel(root, "capdemo", {"payload/a.dat": b"x" * 65537})
            files, *_ = decode_archive((root / source["path"]).read_bytes(), Budget())
        self.assertEqual(files["payload/a.dat"], b"x" * 65537)

    def test_independent_deflate_limit_plus_one_is_resource_limit(self):
        from capacity import make_wheel
        from wheelsuture.verify._source import decode_archive

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, _ = make_wheel(root, "capdemo", {"payload/a.dat": b"x" * 65537})
            with self.assertRaisesRegex(LimitExceeded, "member_bytes"):
                decode_archive(
                    (root / source["path"]).read_bytes(),
                    Budget(Limits(member_bytes=65536)),
                )

    def test_capacity_fixture_bytes_are_reproducible(self):
        spec = {
            "name": "repro",
            "shape": "tiny",
            "n": 5,
            "seed": 101,
            "expected": "complete",
        }
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            _, one = build_case(Path(a), spec)
            _, two = build_case(Path(b), spec)
        self.assertEqual(one, two)

    def test_held_out_seeds_cover_three_fixed_shapes(self):
        specs = [s for s in case_specs() if s.get("held_out")]
        self.assertEqual({s["seed"] for s in specs}, {101, 103})
        self.assertEqual({s["shape"] for s in specs}, {"dense", "long", "tiny"})
        self.assertEqual(len(specs), 6)


class OutputReviewTests(unittest.TestCase):
    def test_create_only_concurrent_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.whl"
            source.write_bytes(b"original")
            dest = root / "output.json"
            real = os.link

            def race(src, dst, *args, **kwargs):
                dest.symlink_to(source)
                return real(src, dst, *args, **kwargs)

            with patch("wheelsuture.output.os.link", side_effect=race):
                with self.assertRaises(Exception):
                    publish_outputs({dest: b"report"}, inputs=[source])
            self.assertEqual(source.read_bytes(), b"original")
            self.assertTrue(dest.is_symlink())
            self.assertFalse(
                any(p.name.startswith(".wheelsuture-") for p in root.iterdir())
            )

    def test_create_only_concurrent_hardlink_is_not_clobbered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.whl"
            source.write_bytes(b"original")
            dest = root / "output.json"
            real = os.link

            def race(src, dst, *args, **kwargs):
                real(source, dest)
                return real(src, dst, *args, **kwargs)

            with patch("wheelsuture.output.os.link", side_effect=race):
                with self.assertRaises(Exception):
                    publish_outputs({dest: b"report"}, inputs=[source])
            self.assertEqual(source.read_bytes(), b"original")
            self.assertEqual(dest.read_bytes(), b"original")
            self.assertEqual(source.stat().st_ino, dest.stat().st_ino)

    def test_html_active_payloads_are_all_text_in_dom(self):
        from html.parser import HTMLParser
        from wheelsuture.report import render_html

        class Collect(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []
                self.attrs = []

            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                self.attrs.extend(attrs)

        bad = '"><svg/onload=alert(1)><iframe srcdoc="<script>x</script>"></iframe>&\u202e'
        report = dict(
            status=bad,
            profile=bad,
            case_id=bad,
            wheels=[{"name": bad}],
            operations=[{"operation_id": bad}],
            findings=[{"finding_id": bad, "kind": bad, "cause_event_id": bad}],
            events=[{"event_id": bad}],
            diagnostics=[bad],
            coverage={"excluded": [bad]},
        )
        parser = Collect()
        parser.feed(
            render_html(
                report, json_name=bad, repair={"status": bad, "actions": [bad]}
            ).decode()
        )
        self.assertFalse(
            set(parser.tags)
            & {"script", "svg", "iframe", "img", "form", "object", "embed", "link"}
        )
        self.assertFalse(any(k.startswith("on") for k, v in parser.attrs))
        self.assertTrue(
            all(v.startswith("#event-") for k, v in parser.attrs if k == "href")
        )


if __name__ == "__main__":
    unittest.main()
