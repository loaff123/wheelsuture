import hashlib
import importlib.util
import pathlib
import struct
import tempfile
import unittest
import zipfile
from inventory_fixtures import PROFILE, wheel_bytes, write_wheel, mutate_u16, mutate_u32

class InventoryTests(unittest.TestCase):
    def inventory(self, blob=None, *, filename='demo-1.0-py3-none-any.whl', limits=None):
        self.assertIsNotNone(importlib.util.find_spec('wheelsuture.inventory'), 'bounded inventory implementation is missing')
        from wheelsuture.inventory import inventory_wheel
        from wheelsuture.model import WheelSource, Profile, Budget, DEFAULT_LIMITS
        p,d=write_wheel(self.tmp.name, blob, filename)
        budget=Budget(limits or DEFAULT_LIMITS)
        result=inventory_wheel(WheelSource('demo', p.name, d, p.parent), Profile(PROFILE), budget)
        self.budget=budget
        return result.to_dict()
    def setUp(self): self.tmp=tempfile.TemporaryDirectory()
    def tearDown(self): self.tmp.cleanup()
    def rejection(self, blob, kind):
        self.assertIsNotNone(importlib.util.find_spec('wheelsuture.inventory'), 'bounded inventory implementation is missing')
        from wheelsuture import errors
        with self.assertRaises(getattr(errors,kind)): self.inventory(blob)
    def test_copied_payload_and_four_private_controls(self):
        w=self.inventory()
        self.assertEqual(w['canonical_name'],'demo')
        self.assertEqual(w['member_count'],4)
        claims={c['destination']:c for c in w['claims']}
        c=claims['lib/python3.12/site-packages/demo/__init__.py']
        self.assertEqual(c['signature'],{'kind':'bytes','sha256':hashlib.sha256(b'# original fixture\n').hexdigest(),'size':19})
        controls=[c for c in w['claims'] if c['kind']=='control']
        self.assertEqual({c['signature']['control'] for c in controls},{'RECORD','INSTALLER','REQUESTED','direct_url.json'})
        self.assertTrue(all(c['member'] is None and not c['checked'] for c in controls))
        self.assertEqual(w['deletion_paths'], sorted(claims,key=lambda p:p.encode()))
    def test_record_phantom_rejected(self):
        self.rejection(wheel_bytes(record_transform=lambda rs:rs+[['phantom','','']]),'InvalidInput')
    def test_record_digest_rejected(self):
        def corrupt(rs): rs[0][1]='sha256='+'A'*43; return rs
        self.rejection(wheel_bytes(record_transform=corrupt),'InvalidInput')
    def test_record_duplicate_rejected(self):
        self.rejection(wheel_bytes(record_transform=lambda rs:rs+[rs[0]]),'InvalidInput')
    def test_identity_mismatch_rejected(self):
        self.rejection(wheel_bytes(metadata=b'Metadata-Version: 2.1\nName: other\nVersion: 1.0\n\n'),'InvalidInput')
    def test_duplicate_metadata_identity_rejected(self):
        self.rejection(wheel_bytes(metadata=b'Metadata-Version: 2.1\nName: demo\nName: demo\nVersion: 1.0\n\n'),'InvalidInput')
    def test_path_and_startup_restrictions(self):
        for path in ('../escape','/rooted','a//b','a\\b','evil.pth','x/__pycache__/a.pyc','sitecustomize.so','demo-1.0.data/data/pyvenv.cfg','demo-1.0.data/data/lib/python3.12/site-packages/usercustomize/a'):
            with self.subTest(path=path): self.rejection(wheel_bytes({path:b'x'}),'UnsupportedInput')
    def test_mapped_alias_rejected(self):
        self.rejection(wheel_bytes({'x.py':b'x','demo-1.0.data/data/lib/python3.12/site-packages/x.py':b'x'}),'UnsupportedInput')
    def test_prefix_collision_rejected(self):
        self.rejection(wheel_bytes({'x':b'x','x/y':b'y'}),'UnsupportedInput')
    def test_mapping_and_script_tail(self):
        w=self.inventory(wheel_bytes({'demo-1.0.data/scripts/tool':b'#!pythonw -x\nTAIL\n','demo-1.0.data/headers/x.h':b'h','demo-1.0.data/data/etc/x':b'x'}))
        cs={c['destination']:c for c in w['claims']}
        self.assertIn('include/site/python3.12/demo/x.h',cs)
        self.assertIn('etc/x',cs)
        self.assertEqual(cs['bin/tool']['signature'],{'kind':'rewritten_script','tail_sha256':hashlib.sha256(b'TAIL\n').hexdigest(),'tail_size':5,'interpreter_token':'profile-interpreter','profile':PROFILE})
    def test_entry_point_provider_and_postmapping_guards(self):
        w=self.inventory(wheel_bytes({'demo-1.0.dist-info/entry_points.txt':b'[console_scripts]\ntool = demo.cli:main\n'}))
        c=next(c for c in w['claims'] if c['destination']=='bin/tool')
        self.assertEqual(c['kind'],'entry_point')
        self.assertEqual(c['signature']['module'],'demo.cli')
        self.assertEqual(c['member'],'demo-1.0.dist-info/entry_points.txt')
        for name in ('python3.12','tool.pyc','tool.pth','easy_install'):
            with self.subTest(name=name): self.rejection(wheel_bytes({'demo-1.0.dist-info/entry_points.txt':f'[console_scripts]\n{name} = demo:main\n'.encode()}),'UnsupportedInput')
    def test_provider_alias_is_not_silently_filtered(self):
        self.rejection(wheel_bytes({'demo-1.0.dist-info/entry_points.txt':b'[console_scripts]\ntool = demo:main\n','demo-1.0.data/scripts/tool.exe':b'x'}),'UnsupportedInput')
    def test_duplicate_zip_name_rejected(self):
        with __import__('warnings').catch_warnings():
            __import__('warnings').simplefilter('ignore')
            b=wheel_bytes(extra_entries=(('demo/__init__.py',b'x'),))
        self.rejection(b,'InvalidInput')
    def test_central_local_name_disagreement_rejected(self):
        b=bytearray(wheel_bytes()); b[30]=ord('x'); self.rejection(bytes(b),'InvalidInput')
    def test_local_size_disagreement_rejected(self):
        b=wheel_bytes(); self.rejection(mutate_u32(b,22,1),'InvalidInput')
    def test_crc_mismatch_rejected(self):
        b=wheel_bytes(compression=zipfile.ZIP_STORED); b=bytearray(b); b[30+len('demo/__init__.py')]=ord('!'); self.rejection(bytes(b),'InvalidInput')
    def test_hidden_deflate_output_rejected(self):
        b=wheel_bytes({'x':b'x'*100000}); b=mutate_u32(b,22,1); cd=b.index(b'PK\x01\x02'); b=mutate_u32(b,cd+24,1); self.rejection(b,'InvalidInput')
    def test_stream_overlap_rejected(self):
        b=wheel_bytes(); cd=b.index(b'PK\x01\x02'); second=b.index(b'PK\x01\x02',cd+4); b=mutate_u32(b,second+42,0); self.rejection(b,'InvalidInput')
    def test_stub_and_trailing_data_rejected(self):
        b=wheel_bytes(); self.rejection(b'X'+b,'InvalidInput'); self.rejection(b+b'X','InvalidInput')
    def test_encryption_and_descriptor_narrowing(self):
        b=wheel_bytes(); cd=b.index(b'PK\x01\x02')
        for flag in (1,8):
            x=mutate_u16(mutate_u16(b,6,flag),cd+8,flag)
            with self.subTest(flag=flag): self.rejection(x,'UnsupportedInput')
    def test_zip64_narrowing(self):
        b=wheel_bytes(); e=b.rindex(b'PK\x05\x06'); self.rejection(mutate_u16(b,e+10,65535),'UnsupportedInput')
    def test_resource_limits_stop_actual_decode(self):
        self.assertIsNotNone(importlib.util.find_spec('wheelsuture.inventory'), 'bounded inventory implementation is missing')
        from wheelsuture.model import Limits, DEFAULT_LIMITS
        from wheelsuture.errors import LimitExceeded
        values=DEFAULT_LIMITS.to_dict(); values['member_bytes']=1024
        with self.assertRaises(LimitExceeded): self.inventory(wheel_bytes({'x':b'x'*1025}),limits=Limits(**values))
        values=DEFAULT_LIMITS.to_dict(); values['entries']=3
        with self.assertRaises(LimitExceeded): self.inventory(limits=Limits(**values))

    def test_empty_explicit_directory_is_structural(self):
        b=wheel_bytes(extra_entries=(('empty/',b''),))
        w=self.inventory(b)
        self.assertEqual(w['member_count'],5)
        self.assertFalse(any(c['member']=='empty/' for c in w['claims']))
    def test_scaffold_symlink_alias_and_activation_rejected(self):
        for path in ('lib64/x','bin/activate','bin/activate.csh','bin/activate.fish','bin/Activate.ps1'):
            with self.subTest(path=path): self.rejection(wheel_bytes({'demo-1.0.data/data/'+path:b'x'}),'UnsupportedInput')
    def test_raw_deflate_output_request_obeys_lowered_limit(self):
        from unittest.mock import patch
        import zlib
        from wheelsuture.model import Limits, DEFAULT_LIMITS
        from wheelsuture.errors import LimitExceeded
        real=zlib.decompressobj; requested=[]
        class Metered:
            def __init__(self,*args): self.d=real(*args)
            def decompress(self,data,max_length=0):
                requested.append(max_length)
                return self.d.decompress(data,max_length)
            def __getattr__(self,name): return getattr(self.d,name)
        v=DEFAULT_LIMITS.to_dict(); v['member_bytes']=1024
        with patch('wheelsuture.zipscan.zlib.decompressobj',Metered):
            with self.assertRaises(LimitExceeded): self.inventory(wheel_bytes({'x':b'x'*100000}),limits=Limits(**v))
        self.assertTrue(requested)
        self.assertLessEqual(max(requested),1025)
    def test_all_zero_caps_fail_without_decompression(self):
        from wheelsuture.model import Limits, DEFAULT_LIMITS
        from wheelsuture.errors import LimitExceeded
        v=DEFAULT_LIMITS.to_dict(); v['archive_bytes']=0
        with self.assertRaises(LimitExceeded): self.inventory(limits=Limits(**v))
    def test_sha384_and_sha512_record_hashes(self):
        import base64
        for algorithm in ('sha384','sha512'):
            def transform(rows):
                rows[0][1]=algorithm+'='+base64.urlsafe_b64encode(getattr(hashlib,algorithm)(b'# original fixture\n').digest()).rstrip(b'=').decode()
                return rows
            with self.subTest(algorithm=algorithm): self.assertEqual(self.inventory(wheel_bytes(record_transform=transform))['name'],'demo')
    def test_bad_record_and_metadata_variants(self):
        for transform in (lambda rs:rs[:-1],lambda rs:[[rs[0][0],rs[0][1],'-1']]+rs[1:],lambda rs:rs+[['empty/','','']]):
            with self.subTest(transform=transform): self.rejection(wheel_bytes(record_transform=transform),'InvalidInput')
        def weak(rs): rs[0][1]='md5=invalid'; return rs
        self.rejection(wheel_bytes(record_transform=weak),'UnsupportedInput')
        self.rejection(wheel_bytes(metadata=b'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nBad Header\n'),'InvalidInput')
    def test_bundled_controls_signatures_and_foreign_metadata(self):
        for p in ('demo-1.0.dist-info/INSTALLER','demo-1.0.dist-info/RECORD.jws','demo-1.0.dist-info/scripts/x','demo-1.0.data/data/lib/python3.12/site-packages/other-1.0.dist-info/x','demo-1.0.data/data/lib/python3.12/site-packages/demo-1.0.dist-info/x'):
            with self.subTest(path=p): self.rejection(wheel_bytes({p:b'x'}),'UnsupportedInput')
    def test_special_file_kind_and_unknown_extra_rejected(self):
        import stat
        for mode in (stat.S_IFLNK,stat.S_IFIFO,stat.S_IFCHR,stat.S_IFSOCK):
            z=zipfile.ZipInfo('special'); z.create_system=3; z.external_attr=(mode|0o644)<<16
            with self.subTest(mode=mode): self.rejection(wheel_bytes(extra_entries=((z,b'x'),)),'UnsupportedInput')
        z=zipfile.ZipInfo('extra'); z.extra=struct.pack('<HH',0x7075,0)
        self.rejection(wheel_bytes(extra_entries=((z,b'x'),)),'UnsupportedInput')
    def test_nul_names_and_unsupported_compression_rejected(self):
        b=wheel_bytes(); cd=b.index(b'PK\x01\x02'); v=bytearray(b); v[30]=0;v[cd+46]=0
        self.rejection(bytes(v),'InvalidInput')
        b=mutate_u16(mutate_u16(b,8,12),cd+10,12)
        self.rejection(b,'UnsupportedInput')
    def test_inventory_budget_is_per_source_and_global(self):
        from wheelsuture.inventory import inventory_wheel
        from wheelsuture.model import WheelSource, Profile, Budget, DEFAULT_LIMITS
        p,h=write_wheel(self.tmp.name)
        b=Budget(DEFAULT_LIMITS)
        first=inventory_wheel(WheelSource('demo',p.name,h,p.parent),Profile(PROFILE),b)
        second=inventory_wheel(WheelSource('demo',p.name,h,p.parent),Profile(PROFILE),b)
        self.assertEqual(first.resource_usage,second.resource_usage)
        self.assertEqual(b.usage['decoded_bytes'],2*first.resource_usage['decoded_bytes'])
        self.assertEqual(b.usage['member_bytes'],first.resource_usage['member_bytes'])

    def test_deflate_truncation_trailing_and_concatenation(self):
        from inventory_fixtures import rewrite_first_compressed
        b=wheel_bytes()
        for transform in (lambda x:x[:-1],lambda x:x+b'X',lambda x:x+x):
            with self.subTest(transform=transform): self.rejection(rewrite_first_compressed(b,transform),'InvalidInput')
    def test_utf8_and_cp437_decoding(self):
        from inventory_fixtures import rebuild_names
        b=wheel_bytes({'café.py':b'x'})
        for raw in (b,rebuild_names(b)):
            with self.subTest(encoding=len(raw)):
                w=self.inventory(raw)
                self.assertTrue(any(c['member']=='café.py' for c in w['claims']))
    def test_duplicate_and_truncated_extra_fields(self):
        for extra in (struct.pack('<HHB',0x5455,1,0)*2,struct.pack('<HH',0x5455,10)+b'x',b'x'):
            z=zipfile.ZipInfo('extra');z.extra=extra
            with self.subTest(extra=extra): self.rejection(wheel_bytes(extra_entries=((z,b'x'),)),'InvalidInput')
    def test_generated_claim_limit_charged_before_insertion(self):
        from wheelsuture.model import Limits,DEFAULT_LIMITS
        from wheelsuture.errors import LimitExceeded
        v=DEFAULT_LIMITS.to_dict(); v['mapped_claims']=6
        with self.assertRaises(LimitExceeded): self.inventory(limits=Limits(**v))
    def test_profile_catalog_schema(self):
        from wheelsuture.profiles import profile_catalog
        catalog=profile_catalog()
        self.assertEqual(catalog['profiles'][0]['id'],PROFILE)
        self.assertEqual(catalog['profiles'][0]['qualification'],'enabled')
    def test_unknown_profile_rejected(self):
        from wheelsuture.inventory import inventory_wheel
        from wheelsuture.model import WheelSource,Profile,Budget
        from wheelsuture.errors import UnsupportedInput
        p,h=write_wheel(self.tmp.name)
        with self.assertRaises(UnsupportedInput): inventory_wheel(WheelSource('demo',p.name,h,p.parent),Profile('unknown'),Budget())
    def test_digest_pin_and_input_symlink_rejected(self):
        from wheelsuture.inventory import inventory_wheel
        from wheelsuture.model import WheelSource,Profile,Budget
        from wheelsuture.errors import InvalidInput
        p,h=write_wheel(self.tmp.name)
        with self.assertRaises(InvalidInput): inventory_wheel(WheelSource('demo',p.name,'0'*64,p.parent),Profile(PROFILE),Budget())
        alias=p.parent/'alias-1.0-py3-none-any.whl'; alias.symlink_to(p.name)
        with self.assertRaises(InvalidInput): inventory_wheel(WheelSource('demo',alias.name,h,p.parent),Profile(PROFILE),Budget())

    def test_entry_point_target_bounds_and_python_keywords(self):
        # The schema's provider components have an independent 1024-char bound.
        for target in ('x'*1025+':main','demo:'+('x'*1025),'for:main','demo:class'):
            with self.subTest(target=target[:40]): self.rejection(wheel_bytes({'demo-1.0.dist-info/entry_points.txt':('[console_scripts]\ntool = '+target+'\n').encode()}),'UnsupportedInput')
    def test_large_tag_expansion_is_bounded_before_parse(self):
        # Packaging expands the cartesian product; bounded metadata alone does
        # not bound this allocation. Reject outside the exact supported tag.
        value='.'.join(['py3']*100)+'-' + '.'.join(['none']*100)+'-' + '.'.join(['any']*100)
        self.rejection(wheel_bytes(wheel=('Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: '+value+'\n').encode()),'UnsupportedInput')

if __name__=='__main__': unittest.main()
