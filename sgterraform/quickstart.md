###快速接入测试网

1. 参考准备工作，建立配置文件目录testnet，生成单个节点的配置：

    ```	
            ./sgterraform/sgchain/build.sh testnet -n 1
    ```     	 

2. 从上步生成的配置文件中找到节点ID，作为参数：NODE_ID,执行以下命令：

    ```	
            ./sgterraform/sgchain/quickstart.sh testnet {NODE_ID} {PUBLIC_IP}
    ```
    **注意**：
    1. 第二步本地需要要docker环境.
    2. 如果启动节点的服务器直接有公网ip，通过上述命令行参数直接指定；如果通过VIP或者网关NAT转换，那PUBLIC_IP就填写本机IP，防火墙要开启65206、8001端口。