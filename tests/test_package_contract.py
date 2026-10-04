"""Package data and runtime-boundary regressions, valid from an installed wheel.

These tests read original fixture wheels as bytes only. Removing package data,
loosening runtime imports, or losing digest bindings must fail these contracts.
"""
import ast
import hashlib
import json
import unittest
from importlib.resources import files
from pathlib import Path, PurePosixPath


class PackageContractTests(unittest.TestCase):
    def test_all_six_schema_resources_are_available(self):
        root = files('wheelsuture').joinpath('schemas')
        expected = {'error', 'inventory', 'plan', 'profiles', 'repair', 'report'}
        self.assertEqual({p.name for p in root.iterdir()},
                         {name + '.schema.json' for name in expected})
        for name in expected:
            schema = json.loads(root.joinpath(name + '.schema.json').read_bytes())
            self.assertIsInstance(schema, dict)
            self.assertIn('$schema', schema)

    def test_seventeen_plans_reference_sixteen_digest_pinned_fixture_wheels(self):
        root = Path(str(files('wheelsuture').joinpath('examples')))
        plans = sorted(root.glob('*.json'))
        self.assertEqual(len(plans), 17)
        wheels = set()
        for path in plans:
            with self.subTest(plan=path.name):
                plan = json.loads(path.read_bytes())
                for source in plan['wheels']:
                    relative = PurePosixPath(source['path'])
                    self.assertFalse(relative.is_absolute())
                    self.assertNotIn('..', relative.parts)
                    wheel = root / relative
                    self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(),
                                     source['sha256'])
                    wheels.add(wheel)
        self.assertEqual(len(wheels), 16)
        self.assertEqual(wheels, set(root.rglob('*.whl')))

    def test_runtime_has_no_process_network_or_foreign_execution_imports(self):
        root = Path(str(files('wheelsuture')))
        banned = {'subprocess', 'socket', 'requests', 'http', 'urllib',
                  'ftplib', 'telnetlib', 'ctypes', 'multiprocessing', 'pip', 'installer'}
        banned_calls = {'eval', 'exec', '__import__'}
        banned_os = {'system', 'popen', 'fork', 'forkpty', 'posix_spawn', 'posix_spawnp'}
        for path in root.rglob('*.py'):
            with self.subTest(module=str(path.relative_to(root))):
                for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                    if isinstance(node, ast.Import):
                        self.assertFalse({n.name.split('.')[0] for n in node.names} & banned)
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        self.assertNotIn((node.module or '').split('.')[0], banned)
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            self.assertNotIn(node.func.id, banned_calls)
                        elif isinstance(node.func, ast.Attribute):
                            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                                self.assertFalse(node.func.attr in banned_os or
                                                 node.func.attr.startswith(('exec', 'spawn')))


if __name__ == '__main__':
    unittest.main()
