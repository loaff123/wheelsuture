"""Publication regressions: failures must never damage prior data."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from wheelsuture import output
except ImportError:
    output = None


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def publish(self, outputs, **kwargs):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        return output.publish_outputs(outputs, **kwargs)

    def test_create_only_publishes_complete_bytes(self):
        dest = self.root / 'result.json'
        committed = self.publish({dest: b'{"complete":true}\n'})
        self.assertEqual(dest.read_bytes(), b'{"complete":true}\n')
        self.assertEqual(tuple(committed), (dest,))
        self.assertEqual(list(self.root.iterdir()), [dest])

    def test_existing_file_preserved_without_overwrite(self):
        dest = self.root / 'result.json'; dest.write_bytes(b'original')
        with self.assertRaises(Exception) as caught:
            self.publish({dest: b'replacement'})
        self.assertEqual(type(caught.exception).__name__, 'OutputError')
        self.assertEqual(dest.read_bytes(), b'original')
        self.assertEqual(set(self.root.iterdir()), {dest})

    def test_overwrite_explicitly_replaces_atomically(self):
        dest = self.root / 'result.json'; dest.write_bytes(b'old')
        self.publish({dest: b'new'}, overwrite=True)
        self.assertEqual(dest.read_bytes(), b'new')

    def test_create_only_race_keeps_concurrently_created_destination(self):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        dest = self.root / 'result.json'
        real_link = os.link
        def racing_link(src, dst, *args, **kwargs):
            dest.write_bytes(b'concurrent owner')
            return real_link(src, dst, *args, **kwargs)
        with patch.object(output.os, 'link', side_effect=racing_link):
            with self.assertRaises(Exception) as caught:
                self.publish({dest: b'our report'})
        self.assertEqual(type(caught.exception).__name__, 'OutputError')
        self.assertEqual(dest.read_bytes(), b'concurrent owner')
        self.assertEqual(set(self.root.iterdir()), {dest})

    def test_same_input_path_cannot_be_overwritten(self):
        source = self.root / 'source.whl'; source.write_bytes(b'input')
        with self.assertRaises(Exception):
            self.publish({source: b'new'}, inputs=[source], overwrite=True)
        self.assertEqual(source.read_bytes(), b'input')

    def test_hardlink_to_input_cannot_be_overwritten(self):
        source = self.root / 'source.whl'; source.write_bytes(b'input')
        dest = self.root / 'output'; os.link(source, dest)
        with self.assertRaises(Exception):
            self.publish({dest: b'new'}, inputs=[source], overwrite=True)
        self.assertEqual(source.read_bytes(), b'input')
        self.assertEqual(dest.read_bytes(), b'input')

    def test_symlink_destination_is_rejected_even_with_overwrite(self):
        source = self.root / 'source'; source.write_bytes(b'input')
        dest = self.root / 'result'; dest.symlink_to(source)
        with self.assertRaises(Exception):
            self.publish({dest: b'new'}, overwrite=True)
        self.assertTrue(dest.is_symlink())
        self.assertEqual(source.read_bytes(), b'input')

    def test_symlink_parent_is_rejected(self):
        actual = self.root / 'actual'; actual.mkdir()
        alias = self.root / 'alias'; alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(Exception):
            self.publish({alias / 'result': b'new'})
        self.assertEqual(list(actual.iterdir()), [])

    def test_output_hardlink_aliases_rejected(self):
        one = self.root / 'one'; one.write_bytes(b'old')
        two = self.root / 'two'; os.link(one, two)
        with self.assertRaises(Exception):
            self.publish({one:b'first', two:b'second'}, overwrite=True)
        self.assertEqual(one.read_bytes(), b'old')
        self.assertEqual(two.read_bytes(), b'old')

    def test_normalized_output_aliases_rejected(self):
        directory = self.root / 'dir'; directory.mkdir()
        one = self.root / 'out'; two = directory / '..' / 'out'
        with self.assertRaises(Exception):
            self.publish({one: b'first', two: b'second'})
        self.assertFalse(one.exists())

    def test_all_outputs_staged_before_any_publication(self):
        one = self.root / 'one'; two = self.root / 'missing' / 'two'
        with self.assertRaises(Exception):
            self.publish({one:b'first', two:b'second'})
        self.assertFalse(one.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_json_is_last_and_partial_outputs_are_disclosed(self):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        report = self.root / 'report.json'; html = self.root / 'report.html'
        real_link = os.link
        order = []
        def second_fails(src, dst, *args, **kwargs):
            order.append(Path(dst).name)
            if len(order) == 2:
                raise OSError('injected publication failure')
            return real_link(src, dst, *args, **kwargs)
        with patch.object(output.os, 'link', side_effect=second_fails):
            with self.assertRaises(Exception) as caught:
                self.publish({report:b'{}\n', html:b'<html></html>'}, authoritative=report)
        self.assertEqual(order, ['report.html', 'report.json'])
        self.assertEqual(tuple(caught.exception.partial_outputs), (str(html),))
        self.assertTrue(html.exists())
        self.assertFalse(report.exists())
        self.assertEqual(set(self.root.iterdir()), {html})

    def test_interruption_after_first_commit_reports_partial_output(self):
        one = self.root / 'one'; two = self.root / 'two'
        real_link = os.link
        calls = 0
        def interrupt_second(src, dst, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt()
            return real_link(src, dst, *args, **kwargs)
        with patch.object(output.os, 'link', side_effect=interrupt_second):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.publish({one:b'first', two:b'second'})
        self.assertEqual(tuple(getattr(caught.exception, 'partial_outputs', ())), (str(one),))
        self.assertEqual(one.read_bytes(), b'first')
        self.assertFalse(two.exists())
        self.assertEqual(set(self.root.iterdir()), {one})

    def test_parent_swap_between_commits_stops_with_partial_outputs(self):
        first = self.root / 'first'
        directory = self.root / 'directory'; directory.mkdir()
        moved = self.root / 'moved'
        second = directory / 'second'
        real_link = os.link
        calls = 0
        def swap_after_first(src, dst, *args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_link(src, dst, *args, **kwargs)
            if calls == 1:
                directory.rename(moved)
                directory.mkdir()
            return result
        with patch.object(output.os, 'link', side_effect=swap_after_first):
            with self.assertRaises(Exception) as caught:
                self.publish({first:b'first', second:b'second'})
        self.assertEqual(type(caught.exception).__name__, 'OutputError')
        self.assertEqual(tuple(caught.exception.partial_outputs), (str(first),))
        self.assertEqual(list(directory.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_staging_fsync_failure_publishes_nothing(self):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        dest = self.root / 'result'
        with patch.object(output.os, 'fsync', side_effect=OSError('fsync failed')):
            with self.assertRaises(Exception):
                self.publish({dest: b'new'})
        self.assertFalse(dest.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_directory_fsync_failure_lists_published_file(self):
        self.assertIsNotNone(output, 'atomic output publisher is not implemented')
        dest = self.root / 'result'
        real_fsync = os.fsync
        calls = 0
        def fail_second(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('directory fsync failed')
            return real_fsync(fd)
        with patch.object(output.os, 'fsync', side_effect=fail_second):
            with self.assertRaises(Exception) as caught:
                self.publish({dest:b'new'})
        self.assertEqual(dest.read_bytes(), b'new')
        self.assertEqual(tuple(caught.exception.partial_outputs), (str(dest),))


if __name__ == '__main__':
    unittest.main()
