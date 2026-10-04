#!/usr/bin/env python3
"""Official PyPA installer mapping-only driver. No fixture import, no uninstall."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tooling/downloads/installer-0.7.0-py3-none-any.whl'))
from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelFile
wheel,prefix,name=sys.argv[1:]
root=Path(prefix)
site=root/'lib/python3.12/site-packages'
scheme={'purelib':str(site),'platlib':str(site),'scripts':str(root/'bin'),'headers':str(root/'include/site/python3.12'/name),'data':str(root)}
destination=SchemeDictionaryDestination(scheme_dict=scheme,interpreter=str(root/'bin/python'),script_kind='posix',bytecode_optimization_levels=())
with WheelFile.open(wheel) as source: install(source,destination,additional_metadata={'INSTALLER':b'installer\n'})
print(json.dumps({'installer':'0.7.0','bytecode_optimization_levels':[],'scheme':scheme,'overwrite_policy':'default refuses existing destination files; fresh prefix per wheel','mapping_only':True,'uninstall_oracle':False}))
