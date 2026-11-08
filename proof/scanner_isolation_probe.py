import hashlib,importlib.metadata,json,sys
from pathlib import Path
expected=sys.argv[1];scanner=[d for d in importlib.metadata.distributions() if d.metadata['Name'].lower()=='checkov'];assert len(scanner)==1
assert scanner[0].version==expected
local=Path('/opt/iac-guard-v/lib/python3.12/site-packages');assert not list(local.glob('checkov*'))
config=Path('/opt/iac-guard-v/pyvenv.cfg').read_text();assert 'include-system-site-packages = true' in config
assert importlib.metadata.version('iac-guard-v')=='1.0.4'
print(json.dumps({'product':'1.0.4','selected_checkov':expected,'visible_checkov_distributions':[{'version':d.version,'metadata_path':str(d._path)} for d in scanner],'product_local_checkov_paths':[str(p) for p in local.glob('checkov*')],'system_site_packages':True,'global_launcher_sha256':hashlib.sha256(Path('/usr/bin/checkov').read_bytes()).hexdigest(),'controlled_launcher_sha256':hashlib.sha256(Path('/opt/iac-guard-v/scanner/checkov').read_bytes()).hexdigest()},indent=2))
