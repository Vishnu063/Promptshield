# PromptShield — minimal ECS Fargate deployment.
#
# Cost-conscious by design for a portfolio/demo context:
#   - Fargate (no idle EC2 to pay for), smallest task size (0.25 vCPU / 512MB)
#   - Single NAT gateway only if you actually need private-subnet egress;
#     commented out here — task runs in a public subnet with a security
#     group instead, to avoid ~$32/mo NAT charges for a demo workload.
#   - No RDS / ElastiCache — this service is stateless by design.
#   - CloudWatch log retention capped at 14 days to avoid unbounded storage cost.
#
# Run `terraform plan` and read it before `apply`. This file is meant
# to demonstrate real IaC discipline (least-privilege IAM, encrypted
# logs, no public secrets) — not to be applied blindly against a
# production AWS account.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "container_image" {
  description = "Full image URI, e.g. <account>.dkr.ecr.<region>.amazonaws.com/promptshield:sha"
  type        = string
}

variable "upstream_api_key_secret_arn" {
  description = "ARN of an existing Secrets Manager secret holding the upstream LLM provider key. Created out-of-band — never put the key value in Terraform state."
  type        = string
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_ecs_cluster" "this" {
  name = "promptshield"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/promptshield"
  retention_in_days = 14
  # SSE with a customer-managed key is the "production" answer; using
  # the default AWS-managed key here to keep the demo cost/complexity down.
}

resource "aws_security_group" "service" {
  name_prefix = "promptshield-"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTPS from ALB / clients"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tighten to your ALB security group in prod
  }

  egress {
    description = "Outbound to upstream LLM provider + package/log endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- least-privilege IAM ---------------------------------------------------

resource "aws_iam_role" "execution" {
  name = "promptshield-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Task role: the running container's own permissions. Scoped to ONLY
# reading the one secret it needs — not wildcard secretsmanager:*.
resource "aws_iam_role" "task" {
  name = "promptshield-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "task_secret_read" {
  name = "promptshield-read-upstream-secret"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.upstream_api_key_secret_arn]
    }]
  })
}

# --- ECS service -------------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  family                   = "promptshield"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"  # 0.25 vCPU — smallest Fargate size
  memory                   = "512"  # 512 MB
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn             = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "promptshield"
      image     = var.container_image
      essential = true
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      readonlyRootFilesystem = true
      secrets = [
        {
          name      = "PROMPTSHIELD_UPSTREAM_API_KEY"
          valueFrom = var.upstream_api_key_secret_arn
        }
      ]
      environment = [
        { name = "PROMPTSHIELD_RATE_CAPACITY", value = "20" },
        { name = "PROMPTSHIELD_RATE_REFILL", value = "0.5" },
        { name = "PROMPTSHIELD_LOG_LEVEL", value = "INFO" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "promptshield"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = "promptshield"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = true # demo simplicity; use a private subnet + NAT/ALB in prod
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.this.name
}
