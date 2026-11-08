"""Keep bounded synthetic reports in job logs; no paid artifact storage requested."""
from pathlib import Path
import base64,hashlib,io,json,tarfile
root=Path('evidence');buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
 if root.exists():
  for p in sorted(root.rglob('*')):
   if p.is_file() and p.suffix in ['.json','.log','.txt','.tf'] and 'precommit-cache' not in p.parts and not p.is_symlink():archive.add(p,arcname=str(p.relative_to(root)),recursive=False)
data=buffer.getvalue();assert len(data)<=16*1024**2,'Evidence exceeds conservative job-log bound; preserve failure rather than truncate'
print('IACGV_EVIDENCE_SHA256='+hashlib.sha256(data).hexdigest());print('IACGV_EVIDENCE_BEGIN')
encoded=base64.b64encode(data).decode()
for index in range(0,len(encoded),76):print(encoded[index:index+76])
print('IACGV_EVIDENCE_END')
