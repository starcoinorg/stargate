##集群部署文档
###准备工作
1. 配置文件
	* 在项目跟目录直接执行build脚本
	
		```	
		./sgterraform/sgchain/build.sh dev -n 3
		```    	
		**注意**: 
		dev 输出路径，在/sgterraform/sgchain下建立
		-n 节点个数
		 	
2. 服务器相关资源（以阿里云为例）

	* 所在分区（比如：呼和浩特、张家口，对应：cn-huhehaote、cn-zhangjiakou）
	* 部署账号的access_key、secret
	* 远程访问的密钥
	
	**注意**：自动化部署采用terraform，修改sgterraform/variables.tf文件对应项即可.
	node_number：是第一步节点数保持一致，
	config_file_path：第一步的配置文件输出路径
	
3. 编译环境或者docker镜像

	为了方便部署，我们准备了以下docker镜像，也可以根据自己情况，参考docker构建脚本自己搭建编译服务器。目前我们通过github的ci环境自动构建docker镜像，参考：.github/workflows/build_docker.yml
	
	* 基础镜像，提供基本的rust编译环境，包括rust-toolchain，构建脚本参考：docker/build.Dockerfile
	* 主链镜像，提供一层主链的镜像，构建脚本参考：docker/validator/validator.Dockerfile
	* node节点镜像，提供二层node、wallnet镜像，构建脚本参考：docker/node/node.Dockerfile
	`如果自己不想构建，可以从我们官方github下载:`
	[主链镜像](https://github.com/starcoinorg/stargate/packages/81918)
	[节点镜像](https://github.com/starcoinorg/stargate/packages/90206)

	**注意**：
	镜像地址配置好后，修改sgterraform/variables.tf中的以下参数：
	docker_image
	docker_github_user_name
	docker_github_user_password	


###启动网络

启动网络直接用terraform：
	
1. 初始化：terraform init
2. 生成计划：terraform plan(可选，主要确认配置)
3. 启动： terraform apply

###环境验证
	
1. 检查组网是否成功
	
		```
			grep "Successfully connected to peer" /opt/starcoin/sgchain.log
		```
		
2. 用钱包、cli工具连接验证
		
		```
		wallet：
			target/debug/node -c wallet/ -f wallet/key -n 0
		cli：	 
			 target/debug/cli --chain_host {测试网ip} --chain_port {测试网端口} --host {wallet的ip} --port {wallet端口} -m wallet/key
		```
	**注意**：
    	wallet的配置参考config_template目录下面文件
	