# Isolated IaC-Guard-V 1.0.4 production verification

Owner-authorized verification controller, isolated from upstream PR1031. The branch-specific push starts its single standard public GitHub-hosted job; no product/default/PR branch is changed. It checks out exactly9477c6466cdeda62b7ef102508b1ed472347fb8e in a separate source directory.

The existing upstream CI already passed the pinned Checkov acceptance profiles. This controller completes latest/INSTALL_ALL repair requests, actual published-scanner cancellation, tracked normal exits, ordinary-hook regression and container checks. It uses only published1.0.4 artifacts and preserves existing property profiles;3.4.3 is Terraform CKV_AWS_3 only.

Actual workspace and Docker-root headroom must both be at least20GiB; later builds require8GiB. Insufficient space stops execution. No system/image/volume prune, paid runners, package publication or product-source changes occur. Evidence is compressed and retained in downloadable job logs with a SHA256. No separate artifact storage is requested.

The helper scripts use synthetic local Terraform snapshots, isolated process ownership and bounded waits. The90second adapter timeout in the cancellation probe is a declared diagnostic acceleration of the unchanged600second production limit. A failure or any corrective harness cleanup is never counted as successful cleanup.

AI tools assisted the verification controller and test helpers; the contributor owns and reviews these changes.
