terraform {
  required_version = ">= 0.12"
}

provider "alicloud" {
  access_key = var.access_key
  secret_key = var.secret_key
  region     = var.region
}

data "alicloud_zones" "default" {
}

data "alicloud_instance_types" "c4g16" {
  cpu_core_count       = 4
  memory_size          = 16
  network_type         = "Vpc"
  instance_type_family = "ecs.g6.xlarge"
  instance_charge_type = "PostPaid"

}


data "alicloud_instance_types" "c2g8" {
  cpu_core_count       = 2
  memory_size          = 8
  network_type         = "Vpc"
  instance_type_family = "ecs.g6.large"
  instance_charge_type = "PostPaid"
}

data "alicloud_images" "images_docker" {
  owners      = "self"
  name_regex  = "^starcoin_docker"
  most_recent = true
}

data "alicloud_images" "default" {
  name_regex  = "^ubuntu"
  most_recent = true
  owners      = "system"
}

