#!/usr/bin/env bash
set -euo pipefail
proof_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_dir="$GITHUB_WORKSPACE/source"
evidence="$GITHUB_WORKSPACE/evidence"
mkdir "$evidence"
test "$(git -C "$source_dir" rev-parse HEAD)" = 9477c6466cdeda62b7ef102508b1ed472347fb8e
python3 -I -B - "$evidence" <<'SPACE'
import json,shutil,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]);data=Path(subprocess.check_output(['docker','info','--format','{{.DockerRootDir}}'],text=True).strip())
result={'workspace_free':shutil.disk_usage(root).free,'docker_data_free':shutil.disk_usage(data).free,'required_start_bytes':20*1024**3}
(root/'capacity.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
assert min(result['workspace_free'],result['docker_data_free'])>=result['required_start_bytes'],'Insufficient actual capacity: stop, never assume runner advertised storage meets replay requirement'
SPACE
uname -a > "$evidence/kernel.txt"
docker info > "$evidence/docker-info.txt"
python3 -I -B - "$evidence" <<'HASHES'
from pathlib import Path
import hashlib,json,sys,urllib.request
r=Path(sys.argv[1]);p=json.load(urllib.request.urlopen('https://pypi.org/pypi/iac-guard-v/1.0.4/json'))
expected={'iac_guard_v-1.0.4-py3-none-any.whl':'6155ec76424b18b51d1d604ec7d161c963bc35ba3ea0500c6b251b695b4b8972','iac_guard_v-1.0.4.tar.gz':'3c1e37e4206acdb74c4aad5f0ac266cb9843d6fc1f68d4d9443e810c27743a06'}
for f in p['urls']:
 assert f['digests']['sha256']==expected[f['filename']]
 data=urllib.request.urlopen(f['url']).read();assert hashlib.sha256(data).hexdigest()==expected[f['filename']]
(r/'approved-public-hashes.json').write_text(json.dumps(expected,indent=2))
HASHES
cd "$source_dir"
for selection in latest all; do
 python3 -I -B - "$evidence" <<'HEADROOM'
import shutil,sys
assert shutil.disk_usage(sys.argv[1]).free>=8*1024**3,'Stop before next build: headroom below8GiB'
HEADROOM
 args=(--build-arg CHECKOV_VERSION=latest --build-arg IAC_GUARD_V_VERSION=latest)
 if [[ $selection == all ]]; then args=(--build-arg INSTALL_ALL=true); fi
 docker build --no-cache --progress plain "${args[@]}" -t "iacgv-replay:$selection" . > "$evidence/build-$selection.log" 2>&1
 docker run --init --rm --entrypoint /opt/iac-guard-v/bin/python "iacgv-replay:$selection" -IBm iac_guard_v.cli doctor --mode local-trusted --checkov-executable /opt/iac-guard-v/scanner/checkov --format json > "$evidence/doctor-$selection.json"
 python3 -I -B - "$evidence/doctor-$selection.json" <<'DOCTOR'
import json,sys
p=json.load(open(sys.argv[1]));assert p['product_version']=='1.0.4' and p['checkov']['version']=='3.4.3' and p['checkov']['status']=='PASS' and p['validator_registry']['status']=='PASS'
DOCTOR
 mkdir "$evidence/acceptance-$selection"
 docker run --init --rm -v "$source_dir:/source:ro" -v "$evidence/acceptance-$selection:/evidence" -e IACGV_TEST_PRODUCT=/opt/iac-guard-v/bin/python -e IACGV_TEST_SCANNER=/opt/iac-guard-v/scanner/checkov -e IACGV_TEST_HOOK_REPO=/source -e IACGV_TEST_PRE_COMMIT=/usr/bin/pre-commit -e IACGV_TEST_DIRECTORY=/evidence --entrypoint sh "iacgv-replay:$selection" -c 'git config --global --add safe.directory /source; exec python3 -IB /source/tests/iac_guard_v_integration_test.py -v' > "$evidence/acceptance-$selection.log" 2>&1
 docker run --init --network none --rm -v "$proof_dir/scanner_isolation_probe.py:/probe.py:ro" --entrypoint /opt/iac-guard-v/bin/python "iacgv-replay:$selection" -IB /probe.py 3.4.3 > "$evidence/isolation-$selection.json"
done
mkdir "$evidence/cancellation-fixed-v3"
cp "$proof_dir/cancellation_harness.py" "$evidence/cancellation-fixed-v3/harness.py"
docker run --init --network none --rm -v "$evidence:/proof/evidence" -v "$source_dir:/proof/integration:ro" --entrypoint /opt/iac-guard-v/bin/python iacgv-replay:latest -IB /proof/evidence/cancellation-fixed-v3/harness.py > "$evidence/cancellation.log" 2>&1
cp "$proof_dir/precommit_cancellation_probe.py" "$evidence/precommit_cancellation_probe_v2.py"
docker run --init --network none --rm -v "$evidence:/proof/evidence" -v "$evidence/acceptance-latest:/evidence" -v "$source_dir:/source:ro" --entrypoint sh iacgv-replay:latest -c 'git config --global --add safe.directory /source; exec python3 -IB /proof/evidence/precommit_cancellation_probe_v2.py' > "$evidence/precommit-cancellation.log" 2>&1
docker run --init --network none --rm -v "$evidence:/evidence" -v "$source_dir:/source:ro" -v "$proof_dir/normal_completion_probe.py:/probe.py:ro" -e NORMAL_PROOF_ROOT=/evidence/normal-linux-public -e NORMAL_PRODUCT=/opt/iac-guard-v/bin/python -e NORMAL_SCANNER=/opt/iac-guard-v/scanner/checkov -e NORMAL_HOOK=/source/src/pre_commit_terraform/terraform_iac_guard_v.py --entrypoint /opt/iac-guard-v/bin/python iacgv-replay:latest -IB /probe.py > "$evidence/normal-linux-public.log" 2>&1
docker run --init --network none --rm -v "$source_dir:/source:ro" -v "$evidence:/evidence" -v "$proof_dir/ordinary_checkov_regression.py:/probe.py:ro" --entrypoint python3 iacgv-replay:all -IB /probe.py > "$evidence/ordinary-hook.log" 2>&1
curl --fail --location --silent --show-error https://github.com/GoogleContainerTools/container-structure-test/releases/download/v1.22.1/container-structure-test-linux-amd64 > "$evidence/container-structure-test"
printf '%s  %s\n' fa35e89512a8978585f76cf41397956d2e3a30c62c2ad3fb857b1597074d14ca "$evidence/container-structure-test" | sha256sum --check -
chmod +x "$evidence/container-structure-test"
"$evidence/container-structure-test" test --image iacgv-replay:all --config "$source_dir/.github/.container-structure-test-config.yaml" --output json > "$evidence/container-structure.json"
python3 -I -B - "$evidence" <<'FINAL'
from pathlib import Path
import json,sys
r=Path(sys.argv[1]);x=json.loads((r/'cancellation-fixed-v3/runtime/summary.json').read_text());assert len(x)==5 and all(p['wrapper_returncode']==3 and not p['scanner_alive_after_hook_return'] and not p['post_cleanup_live_processes'] and not p['targeted_cleanup'] and not p['reports'] for p in x)
bad='resource "aws_ebs_volume" "target" {\n  availability_zone = "us-east-1a"\n  size = 1\n  encrypted = false\n}\n'
for p in x:
 for role,text in [('before',bad),('after',bad.replace('false','true'))]:assert (r/'cancellation-fixed-v3/runtime'/p['case']/role/'main.tf').read_text()==text
(r/'result.json').write_text(json.dumps({'status':'PASS','source':'9477c6466cdeda62b7ef102508b1ed472347fb8e','public_product':'1.0.4','selected_checkov':'3.4.3','new_properties':False,'scope':'remaining latest/INSTALL_ALL, Linux public scanner cancellation, normal cleanup, ordinary hook and container checks'},indent=2))
FINAL
