"""Original benign wheel fixtures, never imported or installed by unit tests."""
import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile

PROFILE = 'pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1'

def wheel_bytes(payload=None, *, name='demo', version='1.0', metadata=None,
                wheel=None, record_transform=None, compression=zipfile.ZIP_DEFLATED,
                extra_entries=()):
    stem = name.replace('-', '_') + '-' + version
    dist = stem + '.dist-info'
    files = dict(payload or {'demo/__init__.py': b'# original fixture\n'})
    files[dist + '/METADATA'] = metadata if metadata is not None else (
        f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n'.encode())
    files[dist + '/WHEEL'] = wheel if wheel is not None else (
        b'Wheel-Version: 1.0\nGenerator: original-test-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n')
    rows = [[p, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode(), str(len(b))] for p,b in files.items()]
    rows.append([dist + '/RECORD', '', ''])
    if record_transform:
        rows = record_transform(rows)
    s = io.StringIO(newline='')
    csv.writer(s, lineterminator='\n').writerows(rows)
    files[dist + '/RECORD'] = s.getvalue().encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as z:
        for p,b in list(files.items()) + list(extra_entries):
            i = p if isinstance(p, zipfile.ZipInfo) else zipfile.ZipInfo(p, date_time=(2020,1,1,0,0,0))
            i.compress_type = compression
            z.writestr(i,b)
    return out.getvalue()

def write_wheel(directory, blob=None, filename='demo-1.0-py3-none-any.whl'):
    p=Path(directory)/filename
    p.write_bytes(blob if blob is not None else wheel_bytes())
    return p, hashlib.sha256(p.read_bytes()).hexdigest()

def mutate_u16(blob, offset, value):
    import struct
    b=bytearray(blob); struct.pack_into('<H', b, offset, value); return bytes(b)

def mutate_u32(blob, offset, value):
    import struct
    b=bytearray(blob); struct.pack_into('<I', b, offset, value); return bytes(b)

def rewrite_first_compressed(blob, transform):
    """Change first raw compressed extent and consistently relocate later ZIP data."""
    import struct
    e=blob.rindex(b'PK\x05\x06'); count=struct.unpack_from('<H',blob,e+10)[0]
    cd=struct.unpack_from('<I',blob,e+16)[0]
    nlen,xlen=struct.unpack_from('<HH',blob,26); start=30+nlen+xlen
    old=struct.unpack_from('<I',blob,18)[0]
    raw=transform(blob[start:start+old]); delta=len(raw)-old
    b=bytearray(blob[:start]+raw+blob[start+old:])
    struct.pack_into('<I',b,18,len(raw))
    pos=cd+delta
    for i in range(count):
        if i==0: struct.pack_into('<I',b,pos+20,len(raw))
        else:
            offset=struct.unpack_from('<I',b,pos+42)[0]
            struct.pack_into('<I',b,pos+42,offset+delta)
        a,c,d=struct.unpack_from('<HHH',b,pos+28);pos+=46+a+c+d
    struct.pack_into('<I',b,e+delta+16,cd+delta)
    return bytes(b)

def rebuild_names(blob, encoding='cp437'):
    """Original compact ZIP writer for exact raw-name tests, stored only."""
    import struct
    import zlib
    local=bytearray(); central=bytearray(); count=0
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for info in z.infolist():
            data=z.read(info.filename); raw=info.filename.encode(encoding); flags=0 if encoding=='cp437' else 0x800
            crc=zlib.crc32(data)&0xffffffff; offset=len(local); size=len(data)
            local+=struct.pack('<4s5H3I2H',b'PK\x03\x04',20,flags,0,0,0,crc,size,size,len(raw),0)+raw+data
            central+=struct.pack('<4s6H3I5H2I',b'PK\x01\x02',20,20,flags,0,0,0,crc,size,size,len(raw),0,0,0,0,0,offset)+raw
            count+=1
    return bytes(local+central+struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,count,count,len(central),len(local),0))
