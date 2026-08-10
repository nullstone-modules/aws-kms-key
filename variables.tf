variable "trusted_accounts" {
  type = list(object({
    account_id   = string
    access_level = string
  }))
  default     = []
  description = <<EOF
A list of AWS accounts allowed to use this key, and how much access each one gets.
`account_id` is a 12-digit AWS account ID. `access_level` is either "read" or "write", where "write" also includes read.
This mirrors `trusted_access_points` on the S3 bucket using this key: an account that can read objects through an access point must also be able to decrypt with the key those objects were encrypted under, or every GetObject fails on the key rather than on the bucket.
Listing an account here does not by itself grant access. It allows that account to grant access, which its own IAM policies must then do.
EOF

  validation {
    condition     = alltrue([for a in var.trusted_accounts : contains(["read", "write"], a.access_level)])
    error_message = "access_level must be either \"read\" or \"write\"."
  }

  validation {
    condition     = alltrue([for a in var.trusted_accounts : can(regex("^[0-9]{12}$", a.account_id))])
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "via_services" {
  type        = list(string)
  default     = []
  description = <<EOF
Restricts the trusted accounts to using this key through specific AWS services (e.g. ["s3.us-east-1.amazonaws.com"]).
This is optional. If left empty, trusted accounts may use the key through any service, which is what you want for a key shared by more than one kind of resource.
Set it when the key backs a single service, so a leaked credential in a trusted account cannot use the key for anything else.
This never applies to this account's own administrative access.
EOF
}

variable "enable_key_rotation" {
  type        = bool
  default     = true
  description = <<EOF
Automatically rotates the key's backing material once a year.
Rotation is transparent: old material is retained, so objects encrypted before a rotation stay readable without being rewritten.
EOF
}

variable "deletion_window_in_days" {
  type        = number
  default     = 30
  description = <<EOF
How long KMS waits before destroying the key after a deletion is requested, between 7 and 30 days.
Destroying a key permanently destroys every object encrypted under it, so this window is the only chance to cancel.
EOF

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}
