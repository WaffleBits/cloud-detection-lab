# Incident runbook

Every alert carries the actor, source IP, event ID, account and region. Start the
same way each time, then follow the section for the rule.

## First five minutes

1. Open the event in CloudTrail by its event ID and read the whole record.
2. Ask who made the call, from where, and whether a change ticket or a known
   person explains it.
3. List everything else that principal did in the last 24 hours:

   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue=<user> \
     --max-results 50
   ```

4. If nobody can explain it, treat it as compromise and contain first.

## Containment for a suspect principal

1. Deactivate the access key. Do not delete it, because the key ID is evidence.

   ```bash
   aws iam update-access-key --user-name <user> --access-key-id <key> --status Inactive
   ```

2. For a role, revoke active sessions by attaching a deny policy conditioned on
   `aws:TokenIssueTime`, then rotate whatever could assume it.
3. Record each action and its time as you go.

## By rule

### `root-console-login`

Root should almost never sign in. Confirm with the account owner. If unexplained,
reset the root password, rotate its MFA, and check for root access keys, which
should not exist.

### `console-login-without-mfa`

Confirm with the user and enroll MFA. If the source IP is unfamiliar, contain the
user and review their activity.

### `audit-logging-tampered`

Restore logging first, because everything after this point depends on it:

```bash
aws cloudtrail start-logging --name <trail>
aws cloudtrail get-event-selectors --trail-name <trail>
```

Then find the gap in the logs and check other accounts' sources for activity
during it. A denied attempt still means someone tried, so review that principal.

### `threat-detection-disabled`

Re-enable the detector and review the actor's activity since. Disabling detection
usually comes before something else.

### `access-key-for-another-user`

Attackers create a key on another user to keep access after losing their own.
Confirm with both users. If unexplained, deactivate the new key and contain the
actor.

### `admin-policy-attached`

Check who gained access and whether a change explains it. If not, detach the
policy, then review what the new administrator did while it was attached.

### `bucket-public-access-block-weakened`

Restore the block, then check the bucket policy and ACLs for public grants. Use
S3 access logs or CloudTrail data events, if enabled, to see whether objects were
read while it was open.

### `ingress-opened-to-world`

Revoke the rule, then check what the group protects and whether anything connected
through it. VPC flow logs answer that if they are enabled.

### `denied-call-burst`

Repeated denials usually mean a stolen credential being tested for what it can
reach. Identify the credential and check whether any calls from it succeeded.

## Afterwards

Write down what happened, how it was found, how long it took, and what would have
caught it sooner. Add a test event for anything the rules missed.
