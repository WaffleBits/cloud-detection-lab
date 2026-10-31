variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "detection-lab"
}

variable "region" {
  description = "Stay in us-east-1: IAM and console sign-in events reach EventBridge there."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Address that receives alerts. Leave empty to skip the subscription."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail logs in S3."
  type        = number
  default     = 90
}
