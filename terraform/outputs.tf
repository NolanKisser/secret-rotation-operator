output "role_arn" {
  description = "Annotate the operator service account with eks.amazonaws.com/role-arn set to this value."
  value       = aws_iam_role.operator.arn
}
