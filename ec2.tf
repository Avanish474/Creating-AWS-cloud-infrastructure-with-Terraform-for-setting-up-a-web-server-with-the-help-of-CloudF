provider "aws" {
  region = "ap-south-1"
  profile= "avanish007"
}
#creating key
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  
  public_key = "${tls_private_key.example.public_key_openssh}"
}
resource "local_file" "mykey" {
content = "${tls_private_key.example.private_key_pem}"
filename="C:/Users/91893/Downloads/mykey2301.pem"
file_permission=0400
}

#creating security group
resource "aws_security_group" "allow_tlsp" {
  name        = "allow_tlsp"
  description = "Allow TLS inbound traffic"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }


  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
 ingress {
    description = "NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_tlsp"
  }
}

#creating aws instance
resource "aws_instance" "LinuxOS" {
  ami   ="ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name="${aws_key_pair.generated_key.key_name}"
  vpc_security_group_ids = ["${aws_security_group.allow_tlsp.id}"]
connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.example.private_key_pem
    host     = aws_instance.LinuxOS.public_ip
  }
 provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }
  tags = {
    Name = "Myfirstos"
  }
}






resource "aws_efs_file_system" "foo" {
depends_on = [
   aws_security_group.allow_tlsp,
   aws_key_pair.generated_key,
  ]

  creation_token = "my-product"

  tags = {
    Name = "MyProduct"
  }
}


resource "aws_efs_mount_target" "alpha" {
  file_system_id = "${aws_efs_file_system.foo.id}"
  subnet_id      = "${aws_instance.LinuxOS.subnet_id}"
   security_groups = ["${aws_security_group.allow_tlsp.id}"]
}

resource "null_resource" "nullremote3"  {
depends_on = [
    aws_efs_mount_target.alpha,
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.example.private_key_pem
    host     = aws_instance.LinuxOS.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo yum install amazon-efs-utils -y",
      "sudo echo ${aws_efs_file_system.foo.dns_name}:/var/www/html efs defaults,_netdev 0 0 >> sudo /etc/fstab",
      "sudo mount  ${aws_efs_file_system.foo.dns_name}:/  /var/www/html",
      "sudo git clone https://github.com/Avanish474/AWS-infrastructure-using-Terraform-without-manual-approach-.git /var/www/html/"
    ]
  }
}

#creating s3 bucket
resource "aws_s3_bucket" "b" {
  
  acl    = "private"
  
  website {
    index_document = "justice.jpg"
    error_document = "error.html"

    routing_rules = <<EOF
[{
    "Condition": {
        "KeyPrefixEquals": "docs/"
    },
    "Redirect": {
        "ReplaceKeyPrefixWith": "documents/"
    }
}]
EOF
  }
}

resource "aws_s3_bucket_public_access_block" "publicobject" {
  bucket = "${aws_s3_bucket.b.id}"

  block_public_acls   = false
  block_public_policy = false
}

#uploading files to the s3 bucket
resource "aws_s3_bucket_object" "object" {
  bucket = "${aws_s3_bucket.b.id}"
  key    = "justice_league.jpg"
  source = "C:/Users/91893/Pictures/justice.jpg"
  acl    = "public-read"
  content_type = "image/jpg"
}

#creating origin access identity
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Some comment"
}
data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.b.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.b.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "example" {
  bucket = "${aws_s3_bucket.b.id}"
  policy = "${data.aws_iam_policy_document.s3_policy.json}"
}
locals {
  s3_origin_id = "myS3Origin"
}

# creating cloudfront distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  
  origin {
    domain_name = aws_s3_bucket.b.website_endpoint
    origin_id   = "${local.s3_origin_id}"
custom_origin_config {
    origin_protocol_policy = "http-only"
    http_port              = 80
    https_port             = 443
    origin_ssl_protocols   = ["TLSv1.2", "TLSv1.1", "TLSv1"]
  }

   
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  logging_config {
    include_cookies = false
    bucket          = "avanish2302.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
	connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.example.private_key_pem
    host     = aws_instance.LinuxOS.public_ip
}
provisioner "remote-exec" {
inline=[
      "sudo su << EOF",
      "echo \"<img src='http://${aws_cloudfront_distribution.s3_distribution.domain_name}'>\" > /var/www/html/justice_league.html",
      "EOF"
  ]
     }
 }


#copying cloudfront url to a file and opening the url inside chrome
resource "null_resource" "nulllocal1"  {
depends_on = [
    aws_cloudfront_distribution.s3_distribution,
  ]
        provisioner "local-exec" {
	    command = "cd C:/Program Files (x86)/Google/Chrome/Application && chrome  ${aws_instance.LinuxOS.public_ip}/justice_league.html"
  	}
}












