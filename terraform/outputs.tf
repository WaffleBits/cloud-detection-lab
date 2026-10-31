output "trail_name" {
  value = aws_cloudtrail.lab.name
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "alert_topic" {
  value = aws_sns_topic.alerts.arn
}
