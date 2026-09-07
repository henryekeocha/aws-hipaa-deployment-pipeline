# ---------------------------------------------------------------------------
# Network module
#
# Two-tier subnet layout across two availability zones:
#
#   public  -- ALB and NAT gateways only. Nothing that touches PHI lives here.
#   private -- application instances and the database. No route to an internet
#              gateway exists in these route tables, so a compromised instance
#              cannot be reached from the internet and cannot be turned into a
#              publicly addressable exfiltration endpoint. Outbound access, for
#              patching and for calling AWS APIs, goes through a NAT gateway.
#
# VPC flow logs record every accepted and rejected connection in the VPC and
# ship them to the audit bucket, giving network-level evidence to sit alongside
# the API-level evidence in CloudTrail.
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.availability_zone_count)

  # /20 per subnet out of the /16: 4096 addresses each, room to grow.
  public_subnet_cidrs  = [for i in range(var.availability_zone_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnet_cidrs = [for i in range(var.availability_zone_count) : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  nat_gateway_count = var.single_nat_gateway ? 1 : var.availability_zone_count
}

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Required for the RDS endpoint and for VPC endpoints to resolve by name.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

# The default security group of a VPC allows all intra-group traffic. Leaving
# it populated is a common finding, so it is explicitly emptied here: any
# resource that accidentally lands on the default SG gets no connectivity.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-default-sg-locked" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-igw" })
}

# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = var.availability_zone_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  # Instances are never launched into public subnets in this architecture, but
  # the flag is pinned to false so that a future misplaced launch does not
  # silently acquire a public IP.
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-${local.azs[count.index]}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  count = var.availability_zone_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-${local.azs[count.index]}"
    Tier = "private"
  })
}

# ---------------------------------------------------------------------------
# NAT gateways (outbound only)
# ---------------------------------------------------------------------------

resource "aws_eip" "nat" {
  count  = local.nat_gateway_count
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-nat-eip-${count.index}" })
}

resource "aws_nat_gateway" "main" {
  count = local.nat_gateway_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(var.tags, { Name = "${var.name_prefix}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.main]
}

# ---------------------------------------------------------------------------
# Route tables
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-public-rt" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count          = var.availability_zone_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One route table per private subnet so each AZ can point at its own NAT
# gateway when single_nat_gateway = false.
resource "aws_route_table" "private" {
  count = var.availability_zone_count

  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-private-rt-${local.azs[count.index]}" })
}

# NOTE: the only 0.0.0.0/0 route in a private route table points at a NAT
# gateway, never at the internet gateway. That asymmetry -- egress yes, ingress
# no -- is what keeps the PHI-handling tier unreachable from the internet.
resource "aws_route" "private_nat" {
  count = var.availability_zone_count

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
}

resource "aws_route_table_association" "private" {
  count          = var.availability_zone_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# VPC endpoints
#
# Session Manager, CloudWatch Logs and S3 traffic from the private subnets can
# stay on the AWS network rather than transiting the NAT gateway and the public
# internet. Interface endpoints terminate TLS inside the VPC, which both
# narrows the exposure of that traffic and removes the NAT gateway from the
# admin-access path.
# ---------------------------------------------------------------------------

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.name_prefix}-vpce-sg"
  description = "HTTPS from inside the VPC to interface VPC endpoints"
  vpc_id      = aws_vpc.main.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "vpc_endpoints_https" {
  security_group_id = aws_security_group.vpc_endpoints.id
  description       = "HTTPS from within the VPC only"
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-endpoint" })
}

locals {
  # ssm, ssmmessages and ec2messages are the three endpoints Session Manager
  # requires; logs and monitoring carry the CloudWatch agent traffic.
  interface_endpoints = toset([
    "ssm",
    "ssmmessages",
    "ec2messages",
    "logs",
    "monitoring",
    "kms",
  ])
}

data "aws_region" "current" {}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.value}-endpoint" })
}

# ---------------------------------------------------------------------------
# Flow logs
# ---------------------------------------------------------------------------

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${var.flow_logs_bucket_arn}/vpc-flow-logs/"

  # One-minute aggregation shortens the window between an event and its
  # appearance in the log, which matters during incident response.
  max_aggregation_interval = 60

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc-flow-logs" })
}
