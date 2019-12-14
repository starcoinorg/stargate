# vpc config
resource "alicloud_vpc" "vpc" {
  name = "tf_test_foo"
  cidr_block = "172.16.0.0/12"
}
# vswitch config
resource "alicloud_vswitch" "vsw" {
  vpc_id = "${alicloud_vpc.vpc.id}"
  cidr_block = "172.16.0.0/21"
  availability_zone = data.alicloud_zones.default.zones[0].id
}
# security group config
resource "alicloud_security_group" "default" {
  name = "default"
  description = "default"
  vpc_id = "${alicloud_vpc.vpc.id}"
}
# group rule config
resource "alicloud_security_group_rule" "allow_ssh_22" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "22/22"
  priority          = 1
  security_group_id = "${alicloud_security_group.default.id}"
  cidr_ip           = "0.0.0.0/0"
}
#private key pair
resource "alicloud_key_pair" "key_pair" {
  key_name = var.key_name
  key_file = var.ssh_key_pair_file
}