# HIPAA Security Rule → implementation mapping

This maps the technical safeguards of the HIPAA Security Rule (45 CFR Part 164,
Subpart C) to specific resources in this repository. Where a control is
implemented, the row names the file and the resource so a reviewer can go and
read it. Where a control is out of scope for infrastructure code, the row says
so rather than claiming credit.

**Scope note.** This is a reference architecture, not a compliance attestation.
Under the AWS shared responsibility model, AWS is responsible for the security
*of* the cloud (physical safeguards, hypervisor, hardware); the customer is
responsible for security *in* the cloud, which is what this repository
addresses. Using it for real ePHI additionally requires a signed AWS Business
Associate Addendum, use limited to HIPAA-eligible services, and the
administrative safeguards under 45 CFR 164.308 — risk analysis, workforce
training, sanction policy, contingency planning — that cannot be expressed in
Terraform.

---

## § 164.312 — Technical safeguards

### Access Control — § 164.312(a)(1)

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Access Control** — general | Allow access to ePHI only to those persons and software programs that have been granted rights | **No SSH exists anywhere in this stack.** The launch template declares no `key_name` (`terraform/modules/compute/main.tf`), so no instance has an authorised SSH key, and no security group in the repository opens port 22 — the application SG has exactly one ingress rule, referencing the ALB's security group by ID on the app port only (`aws_vpc_security_group_ingress_rule.app_from_alb`). There is no bastion host and no VPN. Egress is enumerated too (443, DNS, and 5432 to the VPC CIDR) rather than left as allow-all, so a compromised instance cannot open an arbitrary outbound channel. Human access runs through the MFA-gated `operator` role, which can `ssm:StartSession` only against instances carrying `SSMSessionAccess=allowed` and is explicitly `Deny`d the port-forwarding documents that would let an operator tunnel the database port to a laptop (`terraform/modules/iam/main.tf`) | EC2 security groups, IAM, SSM Session Manager |
| Unique user identification (**required**) | Assign a unique name/number for tracking user identity | Every actor is a distinct IAM principal: the instance role, the CodeDeploy service role, the maintenance-window role and the operator role are separate identities with separate policies (`terraform/modules/iam/main.tf`). There are no shared OS accounts to log in as, because there is no OS login path; a Session Manager session is attributable to the IAM principal that opened it, and the transcript is keyed by session ID. The database uses `iam_database_authentication_enabled = true`, so application access carries an IAM identity rather than a shared password | IAM roles, SSM Session Manager, RDS IAM authentication |
| Emergency access procedure (**required**) | Obtain necessary ePHI during an emergency | The break-glass path is the `operator` role, which is standing infrastructure rather than something to be created under pressure, and works even if the application is down. RDS `deletion_protection` and `backup_retention_period = 35` with `copy_tags_to_snapshot` preserve a restorable copy; the CloudTrail bucket uses Object Lock in **GOVERNANCE** rather than COMPLIANCE mode specifically so that a holder of `s3:BypassGovernanceRetention` can remove data written in error, which COMPLIANCE mode would make impossible for anyone including account root (`terraform/modules/audit/cloudtrail.tf`). *The written emergency procedure itself is an administrative control this repo does not supply* | IAM, RDS automated backups, S3 Object Lock |
| Automatic logoff (**addressable**) | Terminate a session after a predetermined time of inactivity | `idleSessionTimeout` is set on the `SSM-SessionManagerRunShell` document (default 15 minutes) so an unattended shell on a host in the PHI subnet closes itself; the operator role additionally caps `max_session_duration` at 3600s and requires an MFA credential no older than an hour, so access expires rather than persisting (`terraform/modules/ssm/main.tf`, `terraform/modules/iam/main.tf`) | SSM Session Manager document, IAM role session duration |
| Encryption and decryption (**addressable**) | Encrypt and decrypt ePHI | Encryption at rest uses **customer-managed** KMS keys, not the AWS-managed defaults: RDS `storage_encrypted = true` with `kms_key_id` pointing at the app CMK, EBS root volumes encrypted with the same key in the launch template's `block_device_mappings`, SecureString parameters encrypted with it, and S3 buckets using `aws:kms` with it. The key policies are explicit about who may decrypt, and the IAM grants are narrowed further with `kms:ViaService` conditions so the instance role's `kms:Decrypt` works only through SSM (config) or S3 (deployment bundles) — it cannot be reused to read a snapshot. Two separate keys are used, application and audit, so application-key compromise does not expose the audit trail | KMS CMKs, RDS, EBS, S3 SSE-KMS, SSM Parameter Store |

### Audit Controls — § 164.312(b)

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Audit Controls** (**required**) | Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems containing ePHI | Five independent evidence streams, all created in code so none of them depends on someone enabling it in the console: (1) **CloudTrail**, multi-region with global service events, writing to a dedicated bucket and mirrored to CloudWatch Logs, with an `event_selector` capturing S3 **object-level** reads and writes, not just management events — that is what shows whether anyone actually touched a PHI object; (2) **Session Manager transcripts** — every admin keystroke and byte of output streamed to S3 and CloudWatch Logs, both encrypted; (3) **VPC flow logs** at one-minute aggregation, capturing accepted and rejected connections; (4) **ALB access logs**, every request with client IP, path, status and TLS cipher; (5) **RDS parameter group** with `log_connections`, `log_disconnections` and `log_statement = ddl` exported to CloudWatch Logs. Critically, the instance role can `logs:CreateLogStream` and `logs:PutLogEvents` but holds no `logs:Delete*` and no `s3:DeleteObject` on the transcript prefix — a compromised host cannot erase the record of its own compromise | CloudTrail, SSM Session Manager, VPC Flow Logs, ALB access logs, CloudWatch Logs, RDS log exports |
| Review of activity (see also § 164.308(a)(1)(ii)(D)) | Regularly review records of system activity | AWS Config runs a recorder plus managed rules that continuously re-evaluate the specific claims made here — `EC2_IMDSv2_CHECK`, `ENCRYPTED_VOLUMES`, `RDS_STORAGE_ENCRYPTED`, `RDS_INSTANCE_PUBLIC_ACCESS_CHECK`, `INCOMING_SSH_DISABLED`, `S3_BUCKET_PUBLIC_READ_PROHIBITED`, `CLOUD_TRAIL_ENABLED`, `IAM_USER_MFA_ENABLED`, `EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK` (`terraform/modules/audit/config.tf`). Drift surfaces as a `NON_COMPLIANT` finding rather than as an audit surprise. CloudWatch alarms on unhealthy hosts and 5xx rates feed the deployment rollback path and an SNS topic | AWS Config recorder + managed rules, CloudWatch alarms, SNS |

### Integrity — § 164.312(c)(1)

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Integrity** — general | Protect ePHI from improper alteration or destruction | Data: RDS storage is checksummed and replicated by the service, `multi_az = true` maintains a synchronous standby, automated backups run for 35 days, and `deletion_protection` blocks accidental teardown. Audit records: the CloudTrail bucket is versioned **and** has S3 Object Lock enabled at creation with a default GOVERNANCE retention, so a new object is write-once for the retention period — an overwrite or delete cannot silently destroy the prior record. Configuration: everything is Terraform, so a change to the environment is a reviewable diff rather than an undocumented console click, and blue/green deployment means running hosts are replaced rather than mutated | RDS Multi-AZ + automated backups, S3 versioning + Object Lock, Terraform, CodeDeploy blue/green |
| Mechanism to authenticate ePHI (**addressable**) | Corroborate that ePHI has not been altered or destroyed in an unauthorized manner | CloudTrail runs with `enable_log_file_validation = true`, which emits a signed digest file each hour; `aws cloudtrail validate-logs` can then prove after the fact that no log file was modified or deleted since delivery. S3 versioning plus Object Lock means the prior version of any object remains addressable for comparison. Deployment bundles are addressed by S3 object version, so what was deployed is provable, and the `ValidateService` hook verifies the deployed revision behaves correctly before it receives traffic | CloudTrail log file validation, S3 versioning + Object Lock, CodeDeploy revision versioning |

### Person or Entity Authentication — § 164.312(d)

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Person or Entity Authentication** (**required**) | Verify that a person or entity seeking access is the one claimed | Humans: the `operator` role's trust policy requires `aws:MultiFactorAuthPresent = true` **and** `aws:MultiFactorAuthAge < 3600`, so a stale session cannot be used to open a shell, and the `IAM_USER_MFA_ENABLED` Config rule watches for principals that lack MFA (`terraform/modules/iam/main.tf`, `terraform/modules/audit/config.tf`). Machines: instances authenticate with instance-profile credentials that IMDSv2 protects from SSRF extraction (`http_tokens = "required"`, hop limit 1); services authenticate through role trust policies scoped with `aws:SourceAccount`/`aws:SourceArn` confused-deputy conditions. Database: `iam_database_authentication_enabled = true` allows short-lived IAM auth tokens instead of a shared static password, and the master password is generated and held by Secrets Manager (`manage_master_user_password = true`) so it never reaches a variable, a tfvars file, or Terraform state | IAM MFA conditions, EC2 IMDSv2, RDS IAM authentication, AWS Secrets Manager |

### Transmission Security — § 164.312(e)(1)

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Transmission Security** — general | Guard against unauthorized access to ePHI transmitted over a network | The ALB terminates TLS with `ELBSecurityPolicy-TLS13-1-2-2021-06` (TLS 1.2 and 1.3 only) and, when a certificate is configured, port 80 does nothing but issue a 301 to HTTPS — no request body ever crosses the plaintext listener. `drop_invalid_header_fields = true` rejects malformed headers rather than forwarding them. Private-subnet traffic to AWS APIs stays on the AWS network via interface VPC endpoints for `ssm`, `ssmmessages`, `ec2messages`, `logs`, `monitoring` and `kms`, plus an S3 gateway endpoint, instead of transiting the NAT gateway (`terraform/modules/network/main.tf`) | ALB HTTPS listener + ACM, VPC endpoints |
| Integrity controls (**addressable**) | Ensure transmitted ePHI is not improperly modified without detection | TLS 1.2+ provides authenticated encryption (AEAD ciphers), so in-transit tampering is detectable at the protocol level. Session Manager sessions carry an additional KMS-based encryption layer (`kmsKeyId` in the session document). S3 uploads are integrity-checked by the service | TLS via ALB, SSM session encryption, S3 |
| Encryption (**addressable**) | Encrypt ePHI whenever deemed appropriate | Enforced at both ends rather than relied on by convention: `rds.force_ssl = 1` in the DB parameter group means the **engine itself** rejects any non-TLS connection, so encryption in transit does not depend on every client remembering to ask for it; `ca_cert_identifier` pins a current CA bundle for certificate validation. Every S3 bucket in the stack carries a bucket policy statement denying all actions when `aws:SecureTransport` is false, and the CloudTrail bucket additionally denies `PutObject` unless `s3:x-amz-server-side-encryption` is `aws:kms` | RDS parameter group, S3 bucket policies |

---

## § 164.308 / § 164.310 / § 164.316 — related safeguards touched by this repo

| Safeguard | Requirement (brief) | How this repo addresses it | AWS service / resource |
|---|---|---|---|
| **Protection from malicious software** — § 164.308(a)(5)(ii)(B) | Procedures for guarding against, detecting, and reporting malicious software | Patch Manager baseline for Amazon Linux 2023 auto-approves Security patches at `Critical`/`Important` severity after a 7-day soak, bound to instances by the `PatchGroup` tag applied at launch, and installed by a weekly maintenance window running `AWS-RunPatchBaseline` at 50% concurrency with `max_errors = 2` so a bad patch cannot take the fleet down. Patch compliance is then re-checked by an AWS Config rule. The launch template resolves the latest AL2023 AMI from the AWS SSM public parameter rather than pinning a stale image, and the ASG's `instance_refresh` rolls the fleet when it changes (`terraform/modules/ssm/main.tf`, `terraform/modules/compute/main.tf`) | SSM Patch Manager, maintenance windows, AWS Config |
| **Evaluation** — § 164.308(a)(8) | Periodic technical and non-technical evaluation of the security posture | AWS Config's continuous evaluation replaces point-in-time review for the controls it covers; the recorder captures full configuration history, so "what did this security group look like in March?" is answerable | AWS Config recorder + rules |
| **Contingency plan / data backup** — § 164.308(a)(7)(ii)(A) | Retrievable exact copies of ePHI | RDS automated backups retained 35 days with `delete_automated_backups = false`, `skip_final_snapshot = false` with a timestamped final snapshot, Multi-AZ standby, and storage autoscaling. Audit data is versioned in S3 with lifecycle transitions to Glacier rather than deletion. *A tested restore procedure — the part auditors actually ask about — is an operational control this repo does not supply* | RDS backups + Multi-AZ, S3 versioning + lifecycle |
| **Facility / physical safeguards** — § 164.310 | Physical access controls for systems housing ePHI | Inherited from AWS under the shared responsibility model and covered by AWS's SOC 2 / ISO 27001 reports and the BAA. Nothing in this repository can or should address it | AWS data centre controls (customer inherits) |
| **Documentation retention** — § 164.316(b)(2)(i) | Retain required documentation for six years | Audit retention defaults to 2557 days (~7 years) on the CloudTrail bucket via lifecycle configuration, with S3 Object Lock set to the same window so retention is enforced rather than merely configured. CloudWatch log groups have explicit `retention_in_days` (365 by default) rather than the "never expire" default, which is both a cost and a discoverability decision | S3 lifecycle + Object Lock, CloudWatch Logs retention |

---

## Deliberately not addressed here

Being precise about the gaps matters as much as the table above:

- **Administrative safeguards (§ 164.308)** — risk analysis, sanction policy,
  workforce clearance and termination procedures, security awareness training,
  incident response runbooks, and a tested contingency plan. These are
  organisational, and no Terraform module produces them.
- **Business Associate Agreements (§ 164.308(b))** — a signed BAA with AWS is a
  prerequisite, as are BAAs with any downstream processor. Only
  [HIPAA-eligible services](https://aws.amazon.com/compliance/hipaa-eligible-services-reference/)
  may touch ePHI under it.
- **Application-layer authorisation** — the sample app has no login, no
  role model and no record-level access control. In a real system, the
  minimum-necessary standard (§ 164.502(b)) is enforced largely in
  application code, not in the network.
- **De-identification, minimum necessary, and data lifecycle** — what fields are
  collected, how long records are kept, and when they are purged are product and
  legal decisions.
- **TLS is opt-in in this configuration.** With `certificate_arn` unset the ALB
  serves plain HTTP so the stack can be stood up in a sandbox without a domain.
  That is acceptable only for synthetic data; set `certificate_arn` before any
  environment sees real ePHI.
- **Region and service eligibility** — the default `us-east-1` is not a
  compliance decision. Confirm your region and every service you add are in
  scope of your BAA.
