variable "cluster_name" {
  description = "EKS cluster the operator runs in."
  type        = string
}

variable "namespace" {
  description = "Namespace of the operator's service account."
  type        = string
  default     = "secret-rotation-system"
}

variable "service_account" {
  description = "Name of the operator's service account."
  type        = string
  default     = "secret-rotation-controller-manager"
}

variable "role_name" {
  description = "Name of the IAM role to create."
  type        = string
  default     = "secret-rotation-operator"
}

variable "secret_name_prefix" {
  description = "Only Secrets Manager secrets whose names start with this prefix are writable, e.g. \"prod/\"."
  type        = string

  validation {
    condition     = length(var.secret_name_prefix) > 0
    error_message = "An empty prefix would grant access to every secret in the account."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key used by the secrets, if any."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to created resources."
  type        = map(string)
  default     = {}
}
