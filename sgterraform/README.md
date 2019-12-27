
## cluster deploy
1. generate config file 
./sgterraform/sgchain/build.sh dev -n 3

2. modify node.config.toml
    is_public_network = true
    enable_encryption_and_authentication = false
    is_permissioned = false
3. Run `terraform init`
4. Run `terraform apply` to startup the system in alicloud