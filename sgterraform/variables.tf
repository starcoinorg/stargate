# region config
variable "region" {
  #  default = "cn-huhehaote" 呼和浩特
  #张家口
  default = "cn-zhangjiakou"
}
variable "node_number" {
  description = "node number"
  default     = 3
}

variable "access_key" {
  type        = string
  description = "deploy access_key"
}
variable "secret_key" {
  type        = string
  description = "deploy secret_key"
}

variable "peer_ids" {
  type        = list(string)
  description = "List of validator PeerIds"
}

variable "docker_github_user_name" {
  type        = string
  description = "docker_hub_user"
}

variable "docker_github_user_password" {
  type        = string
  description = "docker_hub_password"
}

variable "docker_address" {
  type        = string
  description = "git hub docker address"
  default     = "registry.cn-zhangjiakou.aliyuncs.com"
}

variable "ssh_key_pair_file" {
  default = "terraform_starcoin.pem"
}

variable "key_name" {
  default = "terraform_starcoin"
}

variable "ecs_password" {
}

variable "config_file_path" {
  description = "config file path"
}

variable "docker_image" {
}

variable "docker_node_image" {
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

