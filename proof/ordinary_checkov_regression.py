from pathlib import Path
import hashlib,json,os,subprocess,yaml
root=Path('/evidence/ordinary-checkov-consumer');root.mkdir()
subprocess.run(['git','init','-q',str(root)],check=True)
manifest=yaml.safe_load(Path('/source/.pre-commit-hooks.yaml').read_text())
hook=next(h for h in manifest if h['id']=='terraform_checkov')
hook['entry']='/source/'+hook['entry']
hook['args']=['--args=--framework=terraform','--args=--check=CKV_AWS_3']
(root/'.pre-commit-config.yaml').write_text(yaml.safe_dump({'repos':[{'repo':'local','hooks':[hook]}]}))
launcher=Path('/usr/bin/checkov');before=hashlib.sha256(launcher.read_bytes()).hexdigest()
results=[]
for encrypted,expected in [('true',0),('false',1)]:
 path=root/'main.tf';path.write_text('resource "aws_ebs_volume" "target" {\n availability_zone="us-east-1a"\n size=1\n encrypted='+encrypted+'\n}\n')
 snapshot=path.read_bytes();subprocess.run(['git','add','.'],cwd=root,check=True)
 p=subprocess.run(['/usr/bin/pre-commit','run','terraform_checkov','--all-files','--verbose'],cwd=root,capture_output=True,text=True,env=dict(os.environ,PRE_COMMIT_COLOR='never'),timeout=180)
 (root/f'{encrypted}.log').write_text(p.stdout+p.stderr)
 results.append({'encrypted':encrypted,'expected_exit':expected,'actual_exit':p.returncode,'input_unchanged':path.read_bytes()==snapshot,'iacgv_not_invoked':not(root/'.git/iac-guard-v').exists()})
 assert p.returncode==expected,(p.stdout,p.stderr)
 assert path.read_bytes()==snapshot and not(root/'.git/iac-guard-v').exists()
assert before==hashlib.sha256(launcher.read_bytes()).hexdigest()
Path('/evidence/ordinary-checkov-regression.json').write_text(json.dumps({'cases':results,'global_launcher_sha256':before,'launcher_unchanged':True},indent=2)+'\n')
print(json.dumps(results),flush=True)
