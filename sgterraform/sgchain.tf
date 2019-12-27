# Create  chain server
resource "alicloud_instance" "sgchain" {
  count                      = var.node_number
  image_id                   = data.alicloud_images.images_docker.images[0].id
  internet_charge_type       = "PayByBandwidth"
  spot_strategy              = "SpotAsPriceGo"
  spot_price_limit           = 0.45
  instance_type              = "ecs.g6.large"
  system_disk_category       = "cloud_efficiency"
  system_disk_size           = 50
  internet_max_bandwidth_out = 2
  password                   = var.ecs_password
  key_name                   = alicloud_key_pair.starcoin.id
  #depends_on = [alicloud_instance.compile]
  security_groups = [
  alicloud_security_group.default.id]
  instance_name = "sgchain-${count.index}"
  vswitch_id    = alicloud_vswitch.vsw.id
  tags = {
    Name      = "${terraform.workspace}-validator-${substr(var.peer_ids[count.index], 0, 8)}"
    Role      = "validator"
    Workspace = terraform.workspace
    PeerId    = var.peer_ids[count.index]
  }
}

#upload file and  install package
resource "null_resource" "install" {
  count = var.node_number
  depends_on = [
  alicloud_instance.sgchain, alicloud_key_pair.starcoin]
  ## trigger the instance inited
  triggers = {
    instance = alicloud_instance.sgchain.*.id[count.index]
  }

  ##copy config to chain node
  provisioner "file" {
    source      = "${var.config_file_path}/config.tar.gz"
    destination = "/opt/config.tar.gz"

    connection {
      host        = alicloud_instance.sgchain.*.public_ip[count.index]
      type        = "ssh"
      agent       = false
      user        = "root"
      private_key = file(var.ssh_key_pair_file)
    }
  }

  ##start sgchain
  provisioner "remote-exec" {
    connection {
      host = alicloud_instance.sgchain.*.public_ip[count.index]
      type = "ssh"
      agent = false
      user = "root"
      private_key = file(var.ssh_key_pair_file)
    }

    inline = [
      #command
      "mkdir -p /opt/starcoin",
      "cd /opt/starcoin",
      "tar xzvf ../config.tar.gz",
      "docker login --username=${var.docker_github_user_name} -p ${var.docker_github_user_password} ${var.docker_address}",
      "NODE_CONFIG=$(sed 's,{PEER_ID},${var.peer_ids[count.index]}', ./val/node.config.toml)",
      "SEED_PEERS=$(sed 's,{SEED_IP},${alicloud_instance.sgchain.*.private_ip[0]}', ./val/seed_peers.config.toml)",
      "NETWORK_KEYPAIRS=$(cat ./val/${var.peer_ids[count.index]}.network.keys.toml)",
      "NETWORK_PEERS=$(cat ./val/network_peers.config.toml)",
      "CONSENSUS_KEYPAIR=$(cat ./val/${var.peer_ids[count.index]}.consensus.keys.toml)",
      "CONSENSUS_PEERS=$(cat ./consensus_peers.config.toml)",
      "FULLNODE_KEYPAIRS=$(cat ./fullnode.keys.toml)",
      "export NODE_CONFIG SEED_PEERS NETWORK_KEYPAIRS NETWORK_PEERS CONSENSUS_KEYPAIR CONSENSUS_PEERS FULLNODE_KEYPAIRS",
      "docker run  -w `pwd` --env NODE_CONFIG --env SEED_PEERS --env NETWORK_KEYPAIRS --env NETWORK_PEERS --env CONSENSUS_KEYPAIR --env CONSENSUS_PEERS --env FULLNODE_KEYPAIRS  --expose 6180  --net=host --detach ${var.docker_image}",
    ]
  }
}