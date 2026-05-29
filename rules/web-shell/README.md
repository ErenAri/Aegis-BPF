# Web Shell

Blocks known web shell binaries and write-protects common web root
directories to prevent web shell deployment via application exploits.

## Threat model

Web shells are the most common persistence mechanism after exploiting a
public-facing web application. The attack flow is typically:

1. Exploit an upload vulnerability, LFI, or RCE in the web application.
2. Drop a PHP/JSP/ASPX web shell into the web root directory.
3. Access the web shell via HTTP for persistent interactive access.

This pack takes a two-layer approach:
- **deny_path** blocks execution of well-known web shell filenames at
  common staging directories (/tmp, /dev/shm, /var/tmp).
- **protect_path** write-protects standard web root directories to block
  the file upload step entirely.

## Coverage

- MITRE: T1505.003 (Web Shell), T1190 (Exploit Public-Facing Application)
- Scope: known web shell names, standard web roots (Apache, Nginx, Tomcat)
- Out of scope:
  - Web shells with randomized filenames
  - Web shells in non-standard web root locations
  - In-memory web shells (no file on disk)
  - Web shells uploaded to application-managed storage (S3, database BLOBs)

## False-positive vectors

- Legitimate web application deployments that write files to `/var/www/html`
  will be blocked. Exempt the deployment tool's cgroup via `allow_cgroup`.
- CI/CD pipelines deploying to web roots need cgroup exemption.
- CMS platforms (WordPress, Drupal) that write uploaded media or cache
  files to the web root require exemption for the web server's cgroup.
- Tomcat WAR file deployment via the manager application will be blocked.

## How to install

```sh
sudo aegisbpf policy validate rules/web-shell/web-shell.conf
sudo aegisbpf policy apply --reset rules/web-shell/web-shell.conf
```
