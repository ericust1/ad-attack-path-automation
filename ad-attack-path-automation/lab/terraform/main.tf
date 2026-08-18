terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "ad-lab-terraform-state"
    key    = "ad-attack-path/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "domain_name" {
  default = "LAB.LOCAL"
}

variable "admin_password" {
  description = "Domain admin password"
  sensitive   = true
}

variable "key_name" {
  default = "ad-lab-key"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

resource "aws_vpc" "ad_lab_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "ad-attack-path-lab"
    Environment = "security-lab"
  }
}

resource "aws_subnet" "ad_lab_subnet" {
  vpc_id                  = aws_vpc.ad_lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = {
    Name = "ad-lab-subnet"
  }
}

resource "aws_internet_gateway" "ad_lab_igw" {
  vpc_id = aws_vpc.ad_lab_vpc.id

  tags = {
    Name = "ad-lab-igw"
  }
}

resource "aws_route_table" "ad_lab_rt" {
  vpc_id = aws_vpc.ad_lab_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ad_lab_igw.id
  }

  tags = {
    Name = "ad-lab-rt"
  }
}

resource "aws_route_table_association" "ad_lab_rta" {
  subnet_id      = aws_subnet.ad_lab_subnet.id
  route_table_id = aws_route_table.ad_lab_rt.id
}

resource "aws_security_group" "ad_lab_sg" {
  name        = "ad-lab-sg"
  description = "Security group for AD lab instances"

  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "WinRM HTTPS"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "LDAP"
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "LDAP SSL"
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "SMB"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "Kerberos"
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ad-lab-sg"
  }
}

resource "aws_iam_role" "ad_lab_ssm_role" {
  name = "ad-lab-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ad_lab_ssm_policy" {
  role       = aws_iam_role.ad_lab_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ad_lab_profile" {
  name = "ad-lab-ssm-profile"
  role = aws_iam_role.ad_lab_ssm_role.name
}

data "aws_ami" "windows_server_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "domain_controller" {
  ami                  = data.aws_ami.windows_server_2022.id
  instance_type        = "t3.large"
  subnet_id            = aws_subnet.ad_lab_subnet.id
  vpc_security_group_ids = [aws_security_group.ad_lab_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ad_lab_profile.name
  key_name             = var.key_name

  user_data = <<-EOF
    <powershell>
    Set-ExecutionPolicy Bypass -Force
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Install-WindowsFeature -Name RSAT-AD-Tools -IncludeManagementTools
    </powershell>
  EOF

  tags = {
    Name = "ad-lab-dc01"
    Role = "DomainController"
  }
}

resource "aws_instance" "workstation" {
  ami                  = data.aws_ami.windows_server_2022.id
  instance_type        = "t3.medium"
  subnet_id            = aws_subnet.ad_lab_subnet.id
  vpc_security_group_ids = [aws_security_group.ad_lab_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ad_lab_profile.name
  key_name             = var.key_name
  count                = 3

  tags = {
    Name = "ad-lab-ws${count.index + 1}"
    Role = "Workstation"
  }
}

output "dc01_public_ip" {
  value = aws_instance.domain_controller.public_ip
}

output "workstation_public_ips" {
  value = aws_instance.workstation[*].public_ip
}
