resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/detector.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${var.name}-detector"
  retention_in_days = 30
}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "detector" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }
}

resource "aws_iam_role" "detector" {
  name               = "${var.name}-detector"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

resource "aws_iam_role_policy" "detector" {
  name   = "publish-alerts-and-logs"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

resource "aws_lambda_function" "detector" {
  function_name    = "${var.name}-detector"
  role             = aws_iam_role.detector.arn
  handler          = "detections.handler.handle"
  runtime          = "python3.12"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

# Generated from the rules by `python -m detections.export_events`, and checked
# by a test, so the filter cannot drift away from the detections.
resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name = "${var.name}-cloudtrail"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = jsondecode(file("${path.module}/event_names.json"))
    }
  })
}

resource "aws_cloudwatch_event_target" "detector" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "events" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail.arn
}
