package s3policy

deny[message] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    message := "S3 bucket cannot be publicaly readable (acl: public-read)"
}