"""Read-only exact-runtime gate: real verdicts and observed descendant identities."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,time
ROOT=Path(os.environ['NORMAL_PROOF_ROOT']);PRODUCT=os.environ['NORMAL_PRODUCT'];SCANNER=os.environ['NORMAL_SCANNER'];HOOK=Path(os.environ['NORMAL_HOOK'])
BAD='resource "aws_ebs_volume" "target" {\n availability_zone = "us-east-1a"\n size = 1\n encrypted = false\n}\n'
def table():
 if sys.platform=='linux':
  rows=[]
  for path in Path('/proc').iterdir():
   if not path.name.isdigit():continue
   try:
    stat=(path/'stat').read_text();f=stat[stat.rfind(')')+2:].split();cmd=(path/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
    rows.append(dict(pid=int(path.name),ppid=int(f[1]),pgid=int(f[2]),state=f[0],identity=f[19],argv=cmd))
   except (OSError,ValueError):pass
  return rows
 result=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,state=,lstart=,command='],capture_output=True,text=True,check=True)
 rows=[]
 for line in result.stdout.splitlines():
  f=line.split(None,9)
  if len(f)==10:rows.append(dict(pid=int(f[0]),ppid=int(f[1]),pgid=int(f[2]),state=f[3],identity=' '.join(f[4:9]),argv=f[9]))
 return rows
def tree(rows,pid):
 ids={pid}
 while True:
  extra={r['pid'] for r in rows if r['ppid'] in ids}-ids
  if not extra:return [r for r in rows if r['pid'] in ids]
  ids.update(extra)
def hashes(directory):return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for name in ('before','after') for p in (directory/name).rglob('*') if p.is_file()}
def wrapper(case):
 directory=ROOT/case;os.chdir(directory)
 spec=importlib.util.spec_from_file_location('reviewed_hook',HOOK);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 args=argparse.Namespace(iacgv_python=Path(PRODUCT),local_trusted=True,before=Path('before'),after=Path('after'),framework='terraform',target=['CKV_AWS_3=aws_ebs_volume.target'],checkov_executable=Path(SCANNER))
 return module.invoke_cli_app(args)
def main():
 ROOT.mkdir(parents=True,exist_ok=False);results=[]
 for case,after,code,verdict in [('verified',BAD.replace('false','true'),0,'VERIFIED'),('failed',BAD+'# unchanged defect\n',1,'FAILED'),('inconclusive',BAD+BAD.replace('"target"','"other"').replace('false','true'),3,'INCONCLUSIVE')]:
  directory=ROOT/case;directory.mkdir()
  for name,text in [('before',BAD),('after',after)]:
   (directory/name).mkdir();(directory/name/'main.tf').write_text(text)
  subprocess.run(['git','init','-q',str(directory)],check=True);before=hashes(directory);tracked={};start=time.monotonic();cleanup=[];record={'case':case,'expected_exit':code,'expected_verdict':verdict}
  with (directory/'stdout.log').open('w') as out,(directory/'stderr.log').open('w') as err:
   p=subprocess.Popen([PRODUCT,'-IB',str(Path(__file__).resolve()),'--wrapper',case],stdout=out,stderr=err,start_new_session=True)
   try:
    deadline=start+600
    while p.poll() is None and time.monotonic()<deadline:
     for row in tree(table(),p.pid):tracked[(row['pid'],row['identity'])]=row
     time.sleep(.02 if sys.platform=='linux' else .05)
    if p.poll() is None:raise TimeoutError('normal verification exceeded 600s')
    p.wait(timeout=5)
    end=time.monotonic()+3
    while True:
     now=table();remaining=[r for r in now if (r['pid'],r['identity']) in tracked and r['pid']!=p.pid and not r['state'].startswith('Z')]
     if not remaining or time.monotonic()>end:break
     time.sleep(.05)
    scanners=[r for r in tracked.values() if SCANNER in r['argv'] and 'iac_guard_v.cli' not in r['argv'] and '--wrapper' not in r['argv'] and 'pre_commit_terraform' not in r['argv']]
    reports=list(directory.glob('.git/iac-guard-v/runs/run-*/report.json'));assert len(reports)==1,reports
    report=json.loads(reports[0].read_text());record.update(exit=p.returncode,verdict=report['verdict'],report_exit=report['exit_code'],seconds=time.monotonic()-start,tracked=list(tracked.values()),scanner_processes_observed=scanners,remaining_live=remaining,remaining_zombies=[r for r in now if (r['pid'],r['identity']) in tracked and r['state'].startswith('Z')],snapshots_unchanged=hashes(directory)==before)
    assert scanners,'no actual scanner process observed'
    assert p.returncode==code and report['verdict']==verdict and report['exit_code']==code,record
    owned_groups={r['pgid'] for r in scanners}
    group_survivors=[r for r in now if r['pgid'] in owned_groups and not r['state'].startswith('Z')]
    record['remaining_scanner_groups']=group_survivors
    assert not group_survivors,'scanner process group survived completed invocation'
    assert not remaining,'owned process survived completed invocation'
    assert record['snapshots_unchanged']
   finally:
    # Diagnostic failure cleanup only with matching PID/start identity; never recycle IDs.
    now=table()
    for row in now:
     if (row['pid'],row['identity']) in tracked and not row['state'].startswith('Z'):
      try:os.kill(row['pid'],signal.SIGKILL);cleanup.append(row)
      except ProcessLookupError:pass
    if p.poll() is None:p.kill()
    p.wait(timeout=5);record['diagnostic_cleanup']=cleanup
    (directory/'result.json').write_text(json.dumps(record,indent=2)+'\n')
  results.append(record);print(json.dumps({k:record[k] for k in ['case','exit','verdict','seconds','remaining_live','snapshots_unchanged']}),flush=True)
 (ROOT/'summary.json').write_text(json.dumps({'result':'PASS','platform':sys.platform,'hook_sha256':hashlib.sha256(HOOK.read_bytes()).hexdigest(),'cases':results},indent=2)+'\n')
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--wrapper':raise SystemExit(wrapper(sys.argv[2]))
 main()
