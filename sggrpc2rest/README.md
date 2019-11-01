
Stargate项目grpc转rest API的实现

---
实现方式：通过grpc-gateway框架，将grpc服务代理提供rest API
## 实现接口
1. node/open_channel
2. /node/pay
3. /node/deposit
4. /node/withdraw
5. /node/channel_balance
6. /node/install_channel_script_package
7. /node/deploy_module
8. /node/execute_script
---
## 实现步骤
1. 建立grpc代理的go项目
2. 生成gateway本身和依赖的proto文件对应的go文件
   运行cmd/get.sh 获取proto文件
   运行cmd/gen_go.sh 生成go文件，相应修改--go_out=plugins=grpc,paths=source_relative:{{MODIFY_PATH}}
3. 修改gateway.go
    a. 修改node节点的监听地址和端口
    line 19: grpcServerEndpoint = flag.String("node-grpc-endpoint",  "**localhost:7000**", "gRPC server endpoint")
    b. 修改rest API的监听端口
    line 39： return http.ListenAndServe("**:8081**", mux)
4. 启动gateway-api
    go run gateway.go
## 定制
1. 增加接口
   a. 在proto文件增加接口定义，例如：
        rpc AddInterface1(Request) returns (Response) {
           option (google.api.http) = {
              post: "/interface1"
              body: "*"
           };
       }
   b. 生成go文件，参考cmd/gen_go.sh脚本
   c. 重启gateway-api
         
       
---
