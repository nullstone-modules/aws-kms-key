# KMS Key
#### nullstone/aws-kms-key

---

## What Does This Module Do?
Creates a customer-managed <a href="https://aws.amazon.com/kms/" target="_blank">KMS</a> key that other blocks connect to for encryption at rest.

The key is created with rotation enabled and a policy that keeps this account able to administer it. Other AWS accounts can be granted use of the key, which is what makes cross-account access to encrypted resources possible at all.

---

## When Should I Use This?
Whenever something encrypted needs to be read from outside the account that owns it.

AWS-managed keys such as `aws/s3` have an **immutable key policy** that grants only their owning account. They cannot be shared, so a resource encrypted with one can never be decrypted from another account. A customer-managed key is the only way to grant that access.

If nothing crosses an account boundary, you probably don't need this module — the AWS-managed key is free, requires no configuration, and grants its own account implicitly.

---

## Parameters
| Name                       | Type           | Default | Description                                                                                                              |
| -------------------------- | -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------ |
| `trusted_accounts`         | list(object)   | `[]`    | AWS accounts allowed to use this key, each with an access level of `read` or `write`. See [Sharing across AWS accounts](#sharing-across-aws-accounts). |
| `via_services`             | list(string)   | `[]`    | Restricts trusted accounts to using the key through specific AWS services, e.g. `["s3.us-east-1.amazonaws.com"]`. Empty means any service. |
| `enable_key_rotation`      | boolean        | `true`  | Rotates the key's backing material once a year. Transparent — data encrypted before a rotation stays readable.             |
| `deletion_window_in_days`  | number         | `30`    | How long KMS waits before destroying the key after deletion is requested, between 7 and 30.                                |

## Outputs
| Name              | Description                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------ |
| `kms_key_arn`     | The ARN of the key. Consumers grant `kms:Decrypt` on this, and S3 records it on every object it encrypts. |
| `kms_key_id`      | The UUID of the key.                                                                                    |
| `kms_key_alias`   | The alias of the key, in the form `alias/<name>`.                                                        |

---

## How Do I Use This?
Create this block, then connect it to whatever needs encrypting. An S3 bucket is the common case:

```yaml
blocks:
  usage-stats-key:
    module: nullstone/aws-kms-key
    vars:
      trusted_accounts:
        - { account_id: "490532603356", access_level: read }
      via_services: ["s3.us-east-1.amazonaws.com"]

datastores:
  usage-stats-archiver:
    module: nullstone/aws-s3-bucket
    connections:
      kms_key: usage-stats-key
```

---

## Sharing across AWS accounts

Cross-account KMS always takes **two** grants, and missing either produces the same `AccessDenied`:

1. **This key's policy** must name the other account — that's `trusted_accounts`.
2. **The other account's IAM policy** must grant `kms:Decrypt` to the principal making the request.

Listing an account here does not grant it anything on its own. It delegates, allowing that account's own IAM policies to grant access to the key. This is why a key policy alone never unblocks a cross-account read.

Nullstone capabilities handle the second half. `aws-s3-access` grants `kms:Decrypt` automatically when the datastore it connects to exposes a `kms_key_arn`, and `aws-kms-key-usage` does the same for a key referenced directly by ARN.

`read` grants `Decrypt` and `DescribeKey`. `write` adds `Encrypt`, `GenerateDataKey`, and `ReEncrypt*` — S3 encrypts each object under a data key it asks KMS to generate, so writing needs `GenerateDataKey` rather than `Encrypt`, and `ReEncrypt*` covers server-side copies including copy-in-place key migrations.

Accounts are grouped by level, so the policy holds at most three statements no matter how many accounts you list.

Set `via_services` when the key backs a single kind of resource. It confines trusted accounts to using the key through that service, so a leaked credential in a trusted account can't use the key for anything else. It never restricts this account's own administrative access.

### The account administration statement

Every policy this module renders begins with a statement granting `kms:*` to this account's root. This is not optional padding: KMS rejects a key policy that leaves its owning account no way back in, and there is **no break-glass path** once such a policy is applied — the key becomes permanently unadministrable. Removing it is unrecoverable.

### Limitations

Changing the key on an existing resource is **forward-only**. Encryption is recorded per object at write time, and AWS never re-encrypts in place. Data written under a previous key keeps that key and stays subject to that key's policy, so connecting this key to an existing bucket does not make its history readable cross-account. Migrating requires rewriting the objects.

Destroying this block schedules the key for deletion, which after the deletion window **permanently destroys everything encrypted under it**. The window is the only chance to cancel.
