"""Actual outer pre-commit cancellation, with a hash-bound prewarmed adapter."""
from pathlib import Path
import importlib.util,json,os,signal,subprocess,time,hashlib
spec=importlib.util.spec_from_file_location('owned_probe','/proof/evidence/cancellation-fixed-v3/harness.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
OUT=Path('/proof/evidence/precommit-cancellation-v2');OUT.mkdir()
source=Path('/source');revision=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
expected=hashlib.sha256((source/'src/pre_commit_terraform/terraform_iac_guard_v.py').read_bytes()).hexdigest()
adapters=list(Path('/evidence/precommit-cache').glob('repo*/py_env-python3.12/lib/python3.12/site-packages/pre_commit_terraform/terraform_iac_guard_v.py'))
assert adapters and all(hashlib.sha256(p.read_bytes()).hexdigest()==expected for p in adapters)
results=[]
for name,signum in [('sigint-group',signal.SIGINT),('sigterm-group',signal.SIGTERM)]:
 root=OUT/name;root.mkdir()
 for role,text in [('before',probe.BAD),('after',probe.BAD.replace('false','true'))]:
  (root/role).mkdir();(root/role/'main.tf').write_text(text)
 config={'repos':[{'repo':'/source','rev':revision,'hooks':[{'id':'terraform_iac_guard_v','args':['--iacgv-python=/opt/iac-guard-v/bin/python','--local-trusted','--before=before','--after=after','--framework=terraform','--target=CKV_AWS_3=aws_ebs_volume.target','--checkov-executable=/opt/iac-guard-v/scanner/checkov']}]}]}
 (root/'.pre-commit-config.yaml').write_text(json.dumps(config))
 subprocess.run(['git','init','-q'],cwd=root,check=True);subprocess.run(['git','add','.'],cwd=root,check=True)
 snapshots={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*/main.tf')}
 tracked={};row={'case':name,'revision':revision,'adapter_sha256':expected,'cache':'diagnostic reuse of exact installed adapter; no release proof claimed'}
 with (root/'stdout.log').open('w') as stdout,(root/'stderr.log').open('w') as stderr:
  process=subprocess.Popen(['/usr/bin/pre-commit','run','terraform_iac_guard_v','--all-files','--verbose'],cwd=root,env=dict(os.environ,PRE_COMMIT_HOME='/evidence/precommit-cache'),stdout=stdout,stderr=stderr,start_new_session=True)
  try:
   deadline=time.monotonic()+120;scanner=None
   while time.monotonic()<deadline and process.poll() is None:
    tree=probe.descendants(probe.process_table(),process.pid)
    tracked.update({p['pid']:p for p in tree})
    selected=[p for p in tree if probe.SCANNER in p['argv'] and 'iac_guard_v.cli' not in p['argv'] and 'pre_commit_terraform' not in p['argv'] and '--checkov-executable' not in p['argv']]
    if selected:
     scanner=selected[0];assert scanner['pgrp']==scanner['pid'] and scanner['pgrp']!=process.pid;os.killpg(scanner['pgrp'],signal.SIGSTOP);row['at_interrupt']=tree;break
    time.sleep(.01)
   assert scanner is not None,'scanner not observed'
   started=time.monotonic();os.killpg(process.pid,signum)
   row['precommit_exit']=process.wait(timeout=25)
   deadline=time.monotonic()+15
   while time.monotonic()<deadline:
    remaining=[now for old in tracked.values() if (now:=probe.proc(old['pid'])) and now['starttime']==old['starttime'] and now['state']!='Z']
    if not remaining:break
    time.sleep(.05)
   row.update(seconds_after_interrupt=time.monotonic()-started,live_owned_after=remaining,reports=[str(p) for p in root.glob('.git/iac-guard-v/runs/*/report.json')],snapshots_unchanged=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in snapshots.items()))
   assert row['precommit_exit']!=0 and not remaining and not row['reports'] and row['snapshots_unchanged'],row
  finally:
   for old in tracked.values():
    now=probe.proc(old['pid'])
    if now and now['starttime']==old['starttime'] and now['state']!='Z':
     try:os.kill(old['pid'],signal.SIGKILL)
     except ProcessLookupError:pass
   process.wait(timeout=5)
   (root/'result.json').write_text(json.dumps(row,indent=2)+'\n')
 results.append(row);print(json.dumps(row),flush=True)
(OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
