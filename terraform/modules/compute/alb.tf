# ---------------------------------------------------------------------------
# Load balancer
#
# The ALB is the only component with a public address. It terminates TLS and
# forwards to instances that hold no public IP and sit in subnets with no route
# to an internet gateway.
# ---------------------------------------------------------------------------

locals {
  https_enabled = var.certificate_arn != ""
  # ALB and target group names are capped at 32 characters.
  alb_name = substr("${var.name_prefix}-alb", 0, 32)
  tg_name  = substr("${var.name_prefix}-tg", 0, 32)
}

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "Public HTTPS ingress to the load balancer"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count = local.https_enabled ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Port 80 exists only to bounce clients to 443 when TLS is configured; it never
# forwards a request to the application.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = local.https_enabled ? "HTTP from the internet (redirects to HTTPS)" : "HTTP from the internet (sandbox only)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

# The load balancer may talk to exactly one thing: the application tier, on the
# application port. It cannot be pivoted through to reach the database.
resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the application tier"
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"
}

resource "aws_lb" "main" {
  name               = local.alb_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  # Rejects requests with malformed headers rather than passing them through,
  # which closes a family of request-smuggling and header-injection tricks.
  drop_invalid_header_fields = true

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2               = true
  idle_timeout               = 60

  # Every request against the PHI-handling application is recorded, including
  # client IP, path, response code and TLS cipher.
  access_logs {
    bucket  = var.access_logs_bucket
    prefix  = var.access_logs_prefix
    enabled = true
  }

  tags = merge(var.tags, { Name = local.alb_name })
}

resource "aws_lb_target_group" "app" {
  name        = local.tg_name
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Blue/green shifts traffic between fleets, so targets must drain quickly
  # enough that a rollback is fast, but slowly enough not to cut live requests.
  deregistration_delay = 30

  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  stickiness {
    type    = "lb_cookie"
    enabled = false
  }

  tags = merge(var.tags, { Name = local.tg_name })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "https" {
  count = local.https_enabled ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  tags = var.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  # With a certificate configured, port 80 answers every request with a 301 to
  # HTTPS -- no ePHI can traverse the plaintext listener. Without one (sandbox
  # mode) it forwards, which is why certificate_arn should always be set for
  # any environment that handles real data.
  dynamic "default_action" {
    for_each = local.https_enabled ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = local.https_enabled ? [] : [1]
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.app.arn
    }
  }

  tags = var.tags
}
