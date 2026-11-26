# IAM for the operator's AWS Secrets Manager sink on EKS (IRSA).
#
# Creates a role that only the operator's Kubernetes service account can
# assume, scoped to Secrets Manager secrets under a single name prefix.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_iam_openid_connect_provider" "this" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

locals {
  oidc_host  = replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
  secret_arn = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${var.secret_name_prefix}*"
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.this.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "secrets" {
  statement {
    sid = "WriteManagedSecrets"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:TagResource",
      "secretsmanager:DescribeSecret",
    ]
    resources = [local.secret_arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [var.kms_key_arn]
    content {
      sid       = "EncryptWithCMK"
      actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role" "operator" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "secrets" {
  name   = "secrets-manager-sink"
  role   = aws_iam_role.operator.id
  policy = data.aws_iam_policy_document.secrets.json
}
