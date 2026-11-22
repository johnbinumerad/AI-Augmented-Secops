# Runbook: Unpatched Critical CVE Remediation

## Scope

This runbook applies to vulnerability findings with a CVSS base score of 9.0 or higher, or any CVE listed in the CISA Known Exploited Vulnerabilities catalog, on virtual machines, container images, managed Kubernetes nodes and serverless runtimes. Findings are identified by CVE identifier (for example CVE-2021-44228), affected package, installed version and fixed version.

## Severity and SLA

- Critical with known exploitation, on an internet-facing or high-criticality asset: remediate or mitigate within 72 hours.
- Critical without known exploitation, on a high-criticality asset: remediate within 7 days.
- Critical on a low-criticality or isolated asset: remediate within 14 days.
- SLA status values are on_track, at_risk (less than 25 percent of the window left) and breached. Breached findings require an escalation record.

## Triage Steps

1. Confirm the finding is valid: verify the installed package version, that the vulnerable code path is present, and that the scanner did not match on a backported fix.
2. Determine exposure: is the asset reachable from the internet, from other trust zones, or only from a management network? Review security groups, firewall rules and ingress configuration.
3. Check threat intelligence for public exploit code, active exploitation and the availability of vendor patches.
4. Identify the asset owner, the business criticality rating and the deployment method (image rebuild, in-place patching, managed service).
5. Search for indicators of compromise related to the CVE in logs from the time the vulnerability was introduced.

## Remediation Steps

1. Patch: upgrade the affected package to the fixed version. For container images, update the base image and rebuild, then redeploy through the normal pipeline. For managed services, apply the provider maintenance update.
2. If patching cannot happen inside the SLA window, apply a compensating control: restrict network exposure, deploy a WAF virtual patch, disable the vulnerable feature or module, or isolate the host in a restricted network segment.
3. Test the change in a staging environment and run the service smoke tests.
4. Roll out using a staged approach (canary, then remaining instances) with automated rollback.
5. Remove old images, snapshots and autoscaling templates that still contain the vulnerable version so that it cannot be redeployed.

## Verification

- Re-scan the asset and confirm the CVE no longer appears.
- Confirm that the running version matches the fixed version, not only the version recorded in the image tag.
- Update the finding status and record the remediation date to close the SLA clock.

## Escalation

Escalate to the vulnerability management lead when an asset owner requests an exception, when no vendor fix exists, or when the finding is within 24 hours of an SLA breach. Exceptions must carry a compensating control, a risk owner and an expiry date no later than 90 days.

## References

- NVD and vendor security advisories
- CISA Known Exploited Vulnerabilities catalog
