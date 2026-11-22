# Runbook: Public Storage Bucket Remediation

## Scope

This runbook covers DSPM and CSPM findings where object storage (AWS S3, GCP Cloud Storage, Azure Blob Storage) is readable or writable by anonymous or all authenticated users. Typical finding titles include "S3 bucket allows public read via ACL", "Bucket policy grants principal *", "GCS bucket bound to allUsers" and "Blob container with anonymous access".

## Severity and SLA

- Critical: public bucket that contains sensitive data classes (personal data, credentials, financial records) or allows public write. Contain within 4 hours.
- High: public read on a bucket with internal, non-public data. Contain within 24 hours.
- Medium: public bucket intended for static website hosting that lacks a CDN or access logging. Remediate within 30 days.
- Low: public bucket that contains only approved public assets and has an owner-approved exception.

## Triage Steps

1. Identify the bucket, account or project, region and owning team from tags and the asset inventory.
2. Determine how access is granted: bucket ACL, bucket policy, object ACLs, IAM binding to allUsers or allAuthenticatedUsers, or a shared access signature.
3. Review the data classification results for the bucket. Note the data classes found and the approximate object count, without copying object contents into tickets.
4. Review access logs (S3 server access logs or CloudTrail data events, GCS audit logs, Azure Storage analytics) to see whether anonymous requests have occurred and from which source addresses.
5. Decide whether the bucket is intentionally public. A bucket is intentionally public only if an approved exception exists in the risk register.

## Containment Steps

1. Enable the account-level or organization-level public access block (AWS S3 Block Public Access, GCP public access prevention, Azure "allow blob public access" disabled on the storage account).
2. Remove the offending ACL entries, bucket policy statements or IAM bindings. Keep a copy of the previous configuration in the incident ticket.
3. If public write was possible, snapshot object versions and inspect recently written objects for unexpected content before restoring normal access.

## Remediation Steps

1. Grant access to the legitimate consumers through IAM roles, VPC endpoints or private endpoints, and signed URLs with short expiry for external sharing.
2. Enable default encryption with a customer-managed key for buckets holding sensitive data.
3. Enable object versioning, access logging and, where supported, object lock for critical data.
4. For static websites, place a CDN with origin access control in front of the bucket and keep the bucket itself private.
5. Add a preventive control such as a service control policy, organization policy or Azure Policy that denies creation of public buckets.

## Verification

- Re-run the CSPM and DSPM scans and confirm the finding is closed.
- Request an object with no credentials and confirm an access denied response.
- Confirm the public access block setting is reported as enabled for the account.

## Escalation and Notification

If access logs show anonymous reads of sensitive data, open a security incident and notify the privacy office and legal contacts according to the data breach procedure. Preserve logs for the retention period required by policy.

## References

- Cloud provider documentation for public access blocks
- CIS Benchmarks storage sections
