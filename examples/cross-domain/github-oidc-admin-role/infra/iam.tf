resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"
      }
    }
  }
}
EOF
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id

  policy = <<EOF
{
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
EOF
}
