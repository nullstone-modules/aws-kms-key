locals {
  // Grouped by access level so the document holds a fixed number of statements rather than one per
  // account. Write is a superset of read, so a write account appears only in the write statement.
  trusted_read_account_ids  = distinct([for a in var.trusted_accounts : a.account_id if a.access_level == "read"])
  trusted_write_account_ids = distinct([for a in var.trusted_accounts : a.account_id if a.access_level == "write"])

  // Reading an object encrypted under this key needs Decrypt. DescribeKey is what lets a caller
  // discover the key spec before it decrypts; the S3 console and several SDK paths call it.
  read_actions = [
    "kms:Decrypt",
    "kms:DescribeKey",
  ]

  // S3 encrypts each object under a data key it asks KMS to generate, so writing needs
  // GenerateDataKey rather than Encrypt. ReEncrypt covers server-side copies, including the
  // copy-in-place used to migrate objects from one key to another.
  write_actions = concat(local.read_actions, [
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
  ])

  // Names must be alias/<alphanumeric, dash, underscore, slash, colon>, and `alias/aws/` is reserved.
  sanitized_name = replace(lower(local.resource_name), "/[^a-z0-9/_:-]/", "-")
}

resource "aws_kms_key" "this" {
  description             = "Nullstone ${local.block_name}"
  policy                  = data.aws_iam_policy_document.this.json
  enable_key_rotation     = var.enable_key_rotation
  deletion_window_in_days = var.deletion_window_in_days
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.sanitized_name}"
  target_key_id = aws_kms_key.this.key_id
}

data "aws_iam_policy_document" "this" {
  // KMS rejects a key policy that leaves the owning account no way in, and there is no break-glass
  // path once one is applied -- a key locked out of its own account is unrecoverable. This statement
  // is what makes the key administrable by IAM in this account at all, including by the roles that
  // manage it through Nullstone.
  statement {
    sid       = "EnableAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"]
    }
  }

  // Naming an account root here delegates to that account rather than granting outright: the
  // principal still needs kms:Decrypt from its own identity policy. Cross-account KMS requires
  // both halves, which is why granting the bucket alone is never enough.
  dynamic "statement" {
    for_each = length(local.trusted_read_account_ids) > 0 ? [local.trusted_read_account_ids] : []

    content {
      sid       = "AllowTrustedAccountsRead"
      effect    = "Allow"
      actions   = local.read_actions
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [for id in statement.value : "arn:aws:iam::${id}:root"]
      }

      dynamic "condition" {
        for_each = length(var.via_services) > 0 ? [var.via_services] : []

        content {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = condition.value
        }
      }
    }
  }

  dynamic "statement" {
    for_each = length(local.trusted_write_account_ids) > 0 ? [local.trusted_write_account_ids] : []

    content {
      sid       = "AllowTrustedAccountsWrite"
      effect    = "Allow"
      actions   = local.write_actions
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [for id in statement.value : "arn:aws:iam::${id}:root"]
      }

      dynamic "condition" {
        for_each = length(var.via_services) > 0 ? [var.via_services] : []

        content {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = condition.value
        }
      }
    }
  }
}
