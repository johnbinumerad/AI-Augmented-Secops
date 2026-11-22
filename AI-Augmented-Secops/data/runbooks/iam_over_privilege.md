# Runbook: IAM Over-Privilege Remediation

## Scope

This runbook applies to CSPM findings in the `iam` category across AWS, GCP and Azure where a principal (user, role, service account or group) holds permissions beyond what its workload requires. Typical finding titles include "IAM policy allows wildcard actions", "Service account has Owner role", "Role grants iam:PassRole on all resources" and "Unused administrator access".

## Severity and SLA

- Critical: wildcard actions on wildcard resources, or administrator access on an internet-facing workload identity. Remediate within 24 hours.
- High: privilege escalation paths (for example `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam.serviceAccounts.actAs`) or cross-account trust without an external ID. Remediate within 7 days.
- Medium: broad service-level grants such as `s3:*` on a single account. Remediate within 30 days.
- Low: permissions unused for more than 90 days with no escalation path. Remediate within 90 days.

## Triage Steps

1. Identify the principal, the policy or role binding that grants the permission, and the owning team from the asset tags.
2. Check the last-used data for the principal. In AWS use IAM Access Advisor and CloudTrail; in GCP use the IAM Recommender and Policy Analyzer; in Azure use access reviews and sign-in logs.
3. Determine whether the principal is human or non-human, and whether it is attached to an internet-facing asset.
4. Look for escalation paths: the ability to modify IAM policies, create credentials, or assume more powerful roles.
5. Confirm whether an approved exception exists in the risk register before changing anything.

## Remediation Steps

1. Create a replacement policy that grants only the actions and resources seen in the last 90 days of activity, plus any documented seasonal usage confirmed with the owning team.
2. Replace wildcard resources with explicit resource identifiers or conditions (source VPC, tag-based conditions, MFA required for human principals).
3. Apply the new policy in a lower environment first and monitor for access denied errors for one full business cycle.
4. Detach the over-privileged policy or remove the role binding. Keep the old policy document in version control so it can be restored quickly.
5. For human users, move permissions to groups or roles that require MFA and short-lived sessions. Remove long-lived access keys that are no longer needed.
6. For service accounts, prefer workload identity federation over exported keys. Delete unused keys.
7. Add a permission boundary (AWS), organization policy constraint (GCP) or Azure Policy assignment so the same pattern cannot be reintroduced.

## Verification

- Re-run the CSPM scan and confirm the finding is closed.
- Confirm that the principal's effective permissions, as reported by the cloud provider policy simulator, no longer include the removed actions.
- Confirm there are no new access denied spikes for the workload in the 48 hours after the change.

## Escalation

Escalate to the cloud security lead if the principal is used by a production workload that cannot tolerate a permission change window, if an escalation path to administrator access has been exercised according to audit logs, or if the SLA is about to be breached. Record every exception with an expiry date and a named approver.

## References

- Least privilege principle and just-in-time access
- CIS Benchmarks for AWS, GCP and Azure identity sections
