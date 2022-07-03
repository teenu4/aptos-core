# If Forge test framework is enabled on this testnet, also create and use
# an internal helm repository hosted on S3

resource "random_id" "helm-bucket" {
  count       = var.enable_forge ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "aptos-testnet-helm" {
  count  = var.enable_forge ? 1 : 0
  bucket = "aptos-testnet-${local.workspace}-helm-${random_id.helm-bucket[0].hex}"
}

resource "aws_s3_bucket_public_access_block" "aptos-testnet-helm" {
  count                   = var.enable_forge ? 1 : 0
  bucket                  = aws_s3_bucket.aptos-testnet-helm[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# access control
data "aws_iam_policy_document" "forge-assume-role" {
  count = var.enable_forge ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${module.validator.oidc_provider}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "${module.validator.oidc_provider}:sub"
      # the name of the default forge service account
      values = ["system:serviceaccount:default:forge"]
    }

    condition {
      test     = "StringEquals"
      variable = "${module.validator.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "forge" {
  count = var.enable_forge ? 1 : 0
  statement {
    sid = "HelmRead"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.aptos-testnet-helm[0].id}",
      "arn:aws:s3:::${aws_s3_bucket.aptos-testnet-helm[0].id}/*"
    ]
  }
}

resource "aws_iam_role" "forge" {
  count                = var.enable_forge ? 1 : 0
  name                 = "aptos-testnet-${local.workspace}-forge"
  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_policy
  assume_role_policy   = data.aws_iam_policy_document.forge-assume-role[0].json
}

resource "aws_iam_role_policy" "forge" {
  count  = var.enable_forge ? 1 : 0
  name   = "Helm"
  role   = aws_iam_role.forge[0].name
  policy = data.aws_iam_policy_document.forge[0].json
}

### Forge helm release


resource "helm_release" "forge" {
  count       = var.enable_forge ? 1 : 0
  name        = "forge"
  chart       = "${path.module}/../helm/forge"
  max_history = 2
  wait        = false

  values = [
    jsonencode({
      forge = {
        helmBucket = aws_s3_bucket.aptos-testnet-helm[0].bucket
        image = {
          tag = var.image_tag
        }
      }
      serviceAccount = {
        annotations = {
          "eks.amazonaws.com/role-arn" = aws_iam_role.forge[0].arn
        }
      }
    }),
    jsonencode(var.forge_helm_values),
  ]

  set {
    name  = "timestamp"
    value = timestamp()
  }
}

