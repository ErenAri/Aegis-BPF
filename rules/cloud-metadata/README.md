# Cloud Metadata

Protects cloud provider credential files and SDK configurations from
unauthorized reads. Complements network-level IMDS protection by securing
the on-disk credential caches that cloud SDKs create after authentication.

## Threat model

Cloud credential theft is one of the highest-impact post-compromise
objectives because it enables:

- Lateral movement from a single compromised instance to the entire
  cloud account.
- Data exfiltration from cloud storage (S3, GCS, Azure Blob).
- Privilege escalation via cloud IAM (creating new admin users, assuming
  roles).
- Infrastructure destruction or ransomware at the cloud control plane.

While IMDS abuse (169.254.169.254) is the most discussed vector, on-disk
credential files are equally dangerous and persist across reboots. Cloud
SDKs cache tokens and credentials in well-known dotfile locations.

## Coverage

- MITRE: T1552.005 (Cloud Instance Metadata API), T1552.001 (Credentials in Files)
- Scope: AWS, Azure, GCP, Docker, Kubernetes, Terraform credential files for
  root and common cloud-user accounts
- Out of scope:
  - IMDS network endpoint (requires network-level controls or iptables rules)
  - Non-standard home directories for cloud credentials
  - Application-embedded cloud credentials (environment variables, config files)
  - Instance profile/managed identity tokens in memory

## False-positive vectors

- Cloud SDK commands (aws, gcloud, az) that read credential files will be
  blocked. Exempt the application or admin cgroup via `allow_cgroup`.
- Terraform, Pulumi, and other IaC tools that read cloud credentials need
  cgroup exemption.
- CI/CD pipelines that authenticate to cloud providers will be blocked.
  Exempt the CI runner's cgroup.
- Monitoring agents that use cloud SDK credentials for metrics shipping
  require exemption.

## How to install

```sh
sudo aegisbpf policy validate rules/cloud-metadata/cloud-metadata.conf
sudo aegisbpf policy apply --reset rules/cloud-metadata/cloud-metadata.conf
```
