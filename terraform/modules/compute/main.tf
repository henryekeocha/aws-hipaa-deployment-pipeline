# ---------------------------------------------------------------------------
# Compute module
#
# An Auto Scaling group of application instances in private subnets. The three
# properties that matter for the compliance story:
#
#   * no key pair is associated with the launch template, and no security group
#     anywhere in this repository opens port 22 -- interactive access is only
#     possible through SSM Session Manager, which is IAM-authenticated,
#     MFA-gated and recorded,
#   * IMDSv2 is required, so the instance metadata service cannot be reached
#     through a server-side request forgery in the application, and
#   * the root volume is encrypted with the customer-managed key, so a detached
#     or snapshotted volume is useless without a KMS grant.
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

# Latest Amazon Linux 2023 AMI, resolved at apply time from the AWS-published
# SSM public parameter. Pinning a hard-coded AMI ID would mean shipping an
# increasingly unpatched base image; the maintenance window in the ssm module
# handles patching between AMI refreshes.
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---------------------------------------------------------------------------
# Application security group
# ---------------------------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app-sg"
  description = "Application tier: ingress from the ALB only, tightly scoped egress"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-app-sg" })
}

# The ONLY ingress rule in the application tier. It references the load
# balancer's security group rather than a CIDR, so nothing else in the VPC can
# reach the application port even from inside the network.
#
# There is deliberately no port 22 rule here or anywhere else in this
# repository. If you are looking for the SSH rule: there isn't one, and adding
# one would invalidate the access-control claims in the HIPAA mapping doc.
resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Application traffic from the load balancer"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"
}

# Egress is enumerated rather than left as the usual allow-all. A compromised
# instance can reach AWS APIs over TLS, resolve DNS and talk to the database;
# it cannot open an arbitrary outbound channel on a port of the attacker's
# choosing.
resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs, VPC endpoints and package mirrors"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_postgres" {
  security_group_id = aws_security_group.app.id
  description       = "PostgreSQL to the data tier inside the VPC"
  cidr_ipv4         = var.vpc_cidr_block
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_dns_udp" {
  security_group_id = aws_security_group.app.id
  description       = "DNS to the VPC resolver"
  cidr_ipv4         = var.vpc_cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "app_dns_tcp" {
  security_group_id = aws_security_group.app.id
  description       = "DNS (TCP fallback) to the VPC resolver"
  cidr_ipv4         = var.vpc_cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "app" {
  name              = "${var.log_group_prefix}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "deployments" {
  name              = "${var.log_group_prefix}/codedeploy-agent"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# Launch template
# ---------------------------------------------------------------------------

resource "aws_launch_template" "app" {
  name_prefix   = "${var.name_prefix}-lt-"
  image_id      = data.aws_ssm_parameter.al2023.value
  instance_type = var.instance_type

  # NOTE: key_name is intentionally absent. Instances have no authorised SSH
  # key, so even if a port 22 rule were somehow added, there would be no
  # credential to use against it.

  iam_instance_profile {
    name = var.instance_profile_name
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  # IMDSv2 only. http_tokens = "required" forces the session-token handshake,
  # which defeats the classic SSRF-to-credential-theft chain where an
  # attacker coaxes the application into fetching 169.254.169.254 and returning
  # the instance role's temporary credentials. The hop limit of 1 additionally
  # prevents a container on the host from reaching the metadata service.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.root_volume_size
      volume_type           = "gp3"
      delete_on_termination = true

      # Encryption at rest with the customer-managed key. Snapshots and any
      # volume restored from them inherit the same key and key policy.
      encrypted  = true
      kms_key_id = var.kms_key_arn
    }
  }

  monitoring {
    enabled = true
  }

  user_data = base64encode(templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region               = data.aws_region.current.name
    app_port             = var.app_port
    app_log_group        = aws_cloudwatch_log_group.app.name
    agent_log_group      = aws_cloudwatch_log_group.deployments.name
    parameter_store_path = var.parameter_store_path
    metrics_namespace    = var.metrics_namespace
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name                           = "${var.name_prefix}-app"
      PatchGroup                     = var.patch_group
      (var.operator_session_tag_key) = var.operator_session_tag_value
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(var.tags, { Name = "${var.name_prefix}-app-root" })
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Auto Scaling group
# ---------------------------------------------------------------------------

resource "aws_autoscaling_group" "app" {
  name = "${var.name_prefix}-asg"

  # Private subnets only. Combined with map_public_ip_on_launch = false in the
  # network module, application instances never receive a public address.
  vpc_zone_identifier = var.private_subnet_ids

  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity

  target_group_arns = [aws_lb_target_group.app.arn]

  # ELB health checks (not just EC2 status checks) so an instance whose
  # application has failed is replaced even though the host itself is fine.
  health_check_type         = "ELB"
  health_check_grace_period = 300
  default_cooldown          = 120

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  # Rolls the fleet automatically when the launch template changes -- e.g. when
  # the AL2023 AMI parameter resolves to a newly patched image. Half the fleet
  # stays in service throughout, so a base-image refresh is not an outage.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances",
  ]

  dynamic "tag" {
    for_each = merge(var.tags, {
      Name                           = "${var.name_prefix}-app"
      PatchGroup                     = var.patch_group
      (var.operator_session_tag_key) = var.operator_session_tag_value
    })
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true

    # CodeDeploy blue/green owns capacity and target-group membership during a
    # deployment; without this, the next terraform apply would fight the
    # deployment controller and could pull the green fleet out of service.
    ignore_changes = [desired_capacity, target_group_arns, load_balancers]
  }
}

resource "aws_autoscaling_policy" "cpu_target_tracking" {
  name                   = "${var.name_prefix}-cpu-target-tracking"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60
  }
}

# ---------------------------------------------------------------------------
# Deployment guard rails
#
# These alarms are wired into the CodeDeploy deployment group, which stops and
# rolls back a deployment the moment either one fires. That turns "we noticed
# the release was bad" into an automatic, minutes-scale recovery rather than a
# manual one.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.name_prefix}-unhealthy-hosts"
  alarm_description   = "Target group has unhealthy application instances"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "http_5xx" {
  alarm_name          = "${var.name_prefix}-target-5xx"
  alarm_description   = "Application instances returning 5xx responses"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = var.tags
}
