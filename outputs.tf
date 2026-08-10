output "kms_key_arn" {
  value       = aws_kms_key.this.arn
  description = "string ||| The ARN of the KMS key. Consumers grant kms:Decrypt on this, and S3 records it on every object it encrypts."
}

output "kms_key_id" {
  value       = aws_kms_key.this.key_id
  description = "string ||| The UUID of the KMS key."
}

output "kms_key_alias" {
  value       = aws_kms_alias.this.name
  description = "string ||| The alias of the KMS key, in the form `alias/<name>`."
}
