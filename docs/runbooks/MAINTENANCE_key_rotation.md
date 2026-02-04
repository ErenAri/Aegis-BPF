# MAINTENANCE: Key Rotation

## Alert Description and Severity
- **Use when:** scheduled annual rotation or emergency key compromise response
- **Severity:** planned change / high risk if mishandled
- **Impact:** affects policy signing trust chain.

## Diagnostic Steps
1. Inventory active trusted public keys:
   - `aegisbpf keys list`
2. Confirm current signing pipeline key in use.
3. Validate secure storage and permissions for new key material.
4. Prepare rollback key if rotation fails.

## Resolution Procedures
1. Generate new signing key pair in approved secure environment.
2. Add and distribute new public key to all agents (`aegisbpf keys add ...`).
3. Sign a canary policy with new key and apply using `--require-signature`.
4. Rotate production signing pipeline to new key.
5. Revoke/decommission old key after rollout window.

## Escalation Path
1. Security key custodian.
2. Platform owner for deployment orchestration.
3. Incident commander if emergency compromise scenario.

## Post-Incident Checklist
- [ ] Rotation evidence recorded (who/when/why)
- [ ] Old key revocation confirmed
- [ ] All environments validated
- [ ] Documentation and key inventory updated
