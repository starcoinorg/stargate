# region config
variable "region" {
#  default = "cn-huhehaote" 呼和浩特
  #张家口
  default = "cn-zhangjiakou"
}
variable "node_number" {
  description = "node number"
  default = "3"
}

variable "access_key" {
  type = string
  description = "deploy access_key"
}
variable "secret_key" {
  type = string
  description = "deploy secret_key"
}

variable "peer_ids" {
  type        = list(string)
  description = "List of validator PeerIds"
}

variable "docker_github_user_name" {
  type = string
  description = "docker_hub_user"
}

variable "docker_github_user_password" {
  type = string
  description = "docker_hub_password"
}

variable "docker_address" {
  type = string
  description = "git hub docker address"
  default = "registry.cn-zhangjiakou.aliyuncs.com"
}

variable "ssh_key_pair_file" {
  default = "alicloud_ssh_key.pem"
}

variable "key_name" {
  default = "key-pair-from-terraform"
}

variable "ecs_password" {
  default = "SGcoin12345"
}

variable "config_file_path" {
  description = "config file path"
  default     = "./sgchain/dev"
}

variable "exec_file_path" {
  description = "exec file path"
  default     = "../target/debug/sgchain"
}

variable "docker_image" {
  #default = "docker.pkg.github.com/starcoinorg/stargate/sgchain:cluster_deploy_new"
  default = "registry.cn-zhangjiakou.aliyuncs.com/starcoin/starcoin:v1218"
}
variable "validator_node_sources_ipv4" {
  type        = list(string)
  description = "List of IPv4 CIDR blocks from which to allow Validator Node access"
  default     = []
}

variable "validator_node_sources_ipv6" {
  type        = list(string)
  description = "List of IPv6 CIDR blocks from which to allow Validator Node access"
  default     = []
}

variable "validator_use_public_ip" {
  type    = bool
  default = false
}

variable "append_workspace_dns" {
  description = "Append Terraform workspace to DNS names created"
  default     = true
}

