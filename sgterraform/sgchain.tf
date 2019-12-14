# Create  chain server
resource "alicloud_instance" "sgchain" {
  count = var.node_number
  image_id = "${data.alicloud_images.images_docker.images[0].id}"
  internet_charge_type = "PayByBandwidth"
  spot_strategy = "SpotAsPriceGo"
  spot_price_limit = 0.45
  instance_type = "ecs.g6.large"
  system_disk_category = "cloud_efficiency"
  internet_max_bandwidth_out = 10
  password = var.ecs_password
  key_name = alicloud_key_pair.key_pair.id
  #depends_on = [alicloud_instance.compile]
  security_groups = [
    "${alicloud_security_group.default.id}"]
  instance_name = "sgchain"
  vswitch_id = "${alicloud_vswitch.vsw.id}"
}

#upload file and  install package
resource "null_resource" "install" {
  count = var.node_number
  depends_on = [
    alicloud_instance.sgchain, alicloud_key_pair.key_pair ]
  ## trigger the instance inited
  triggers = {
    instance = alicloud_instance.sgchain.*.id[count.index]
  }
  ##copy ssh key to chain node
  provisioner "file" {
    source = var.ssh_key_pair_file
    destination = "/opt/"

    connection {
      host        = alicloud_instance.sgchain.*.public_ip[count.index]
      type        = "ssh"
      agent       = false
      user        = "root"
      private_key = file(var.ssh_key_pair_file)
    }
  }

  ##copy config to chain node
  provisioner "file" {
    source = "${var.config_file_path}/val/${count.index}.tar.gz"
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
      ##"docker login -u ${var.docker_hub_user_name} -p ${var.docker_hub_user_password}",
      ##"docker network create --subnet 172.16.0.0/24 testnet || true",
      "export NODE_CONFIG=$(sed 's,{CHAIN_IP},${alicloud_instance.sgchain.*.private_ip[count.index]}', ${count.index}/node.config.toml)",
      "export SEED_PEERS=$(sed 's,{SEED_IP},${alicloud_instance.sgchain.*.private_ip[0]}', ${count.index}/*.seed_peers.config.toml)",
      "export NETWORK_KEYPAIRS=$(cat ${count.index}/*.node.network.keys.toml)",
      "export NETWORK_PEERS=$(cat ${count.index}/*.network_peers.config.toml)",
      "export CONSENSUS_KEYPAIR=$(cat ${count.index}/*.node.consensus.keys.toml)",
      "export CONSENSUS_PEERS=$(cat ${count.index}/consensus_peers.config.toml)",
      "export FULLNODE_KEYPAIRS=$(cat ${count.index}/fullnode.keys.toml)",
      "docker run  -v `pwd`:`pwd` -w `pwd` --env NODE_CONFIG --env SEED_PEERS --env NETWORK_KEYPAIRS --env NETWORK_PEERS --env CONSENSUS_KEYPAIR --env CONSENSUS_PEERS --env FULLNODE_KEYPAIRS  --ip ${alicloud_instance.sgchain.*.private_ip[count.index]} --expose 60750  --network testnet --detach ${var.docker_image}"
    ]
  }
}