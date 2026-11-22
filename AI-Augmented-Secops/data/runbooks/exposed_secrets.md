# Runbook: Exposed Secrets Remediation

## Scope

This runbook covers findings where a credential has been detected outside an approved secret manager: cloud access keys, service account keys, API tokens, database connection strings, private keys and webhook URLs. Common locations are source repositories, container image layers, CI/CD logs, object storage, instance user data and configuration files on disk.

## Severity and SLA

- Critical: valid, active credential with write or administrative access, or any credential found in a public location. Revoke within 1 hour of confirmation.
- High: valid credential with read access to sensitive data, found in a private repository or internal system. Rotate within 24 hours.
- Medium: credential for a non-production or sandbox environment. Rotate within 7 days.
- Low: credential confirmed to be expired, revoked or a test fixture. Remove the file content within 30 days.

## Triage Steps

1. Identify the secret type and the system it authenticates to, using the detector name and the key prefix only. Do not paste the full secret into tickets, chat or logs.
2. Determine where the secret was found, who committed or created it, and when it first appeared. For repositories, review the full history, not just the latest commit.
3. Determine whether the secret is still valid by checking with the issuing system (for example the cloud IAM key last-used report), not by calling the target service with the credential.
4. Review the audit logs of the issuing system for use of the credential from unfamiliar addresses, unusual regions or unexpected API calls since the exposure time.
5. Determine the blast radius: the permissions of the credential and the data it can reach.

## Remediation Steps

1. Revoke or disable the credential at the issuer first. Rotation comes before cleanup, because removing the secret from a repository does not make it safe.
2. Issue a replacement credential and store it in the approved secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault or a self-hosted vault). Configure workloads to read it at runtime.
3. Where possible replace static credentials with short-lived identities such as workload identity, instance roles or OIDC federation from CI/CD.
4. Remove the secret from the source location. For git history, rewrite history with a tool such as git filter-repo, force the clean history after coordinating with contributors, and invalidate cached forks and pull request refs.
5. Purge the secret from build caches, container image layers, log archives and artifact stores. Rebuild affected images.
6. Add preventive controls: pre-commit secret scanning, push protection on the repository host, and CI pipeline scanning that fails the build.

## Verification

- Confirm that authentication with the old credential fails.
- Re-run the secret scanner across the repository history, images and storage locations and confirm no detections remain.
- Confirm that dependent services are healthy with the new credential.

## Escalation

Open a security incident when audit logs show use of the credential by an unknown party, when the secret granted access to regulated data, or when the secret was exposed in a public location. Notify the owning team and the incident response lead, preserve logs, and follow the breach notification procedure where required.

## References

- Cloud provider guidance for credential rotation
- Secret scanning tool documentation
