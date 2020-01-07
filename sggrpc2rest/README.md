
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
9. /node/invoice/add
10. /node/channel_transaction_proposal
11. /node/query
---
## 实现步骤
1. 建立grpc网关的go项目，拷贝[go.mod](./go.mod)到新的项目中。

2. 生成gateway本身和依赖的proto文件对应的go文件。
    ```
       建立proto文件目录：mkdir proto
       运行cmd/get.sh 获取proto文件
       运行cmd/gen_go.sh 生成go文件，相应修改--go_out=plugins=grpc,paths=source_relative:{{MODIFY_PATH}}
    ```
   **注意**：
   运行gen_go.sh之前，确保https://github.com/grpc-ecosystem/grpc-gateway插件生成文件已经安装正确，验证方法：
        which protoc-gen-grpc-gateway (protoc-gen-swagger\protoc-gen-go)    
         
3. 修改gateway.go

    1. 修改node节点的监听地址和端口
    ```
    line 22: grpcServerEndpoint = flag.String("node-grpc-endpoint",  "**127.0.0.1:9000**", "gRPC server endpoint")
    ``` 
   2. 修改rest API的监听端口
    ```
    line 83： return http.ListenAndServe("**:8081**", mux)
    ```
4. 启动gateway-api（先建立glog的目录log）
    ```
    go run gateway.go --log_dir=./log
    ```

5.日志查看，glog的日志在log/gateway.INFO下面，如果想要看调用node的grpc接口的日志，可以在node.pb.gw.go里面加，举例：
    ```
        如果想加execute_script的日志：
        在RegisterNodeHandlerClient方法中：
            resp, md, err := request_Node_ExecuteScript_0(rctx, inboundMarshaler, client, req, pathParams)
              		ctx = runtime.NewServerMetadataContext(ctx, md)
              		if err != nil {
              			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
              			> glog.Errorln("exec error:", err)
              			return
              		}
              	> glog.Infoln("exec:", resp.String())
    ```          		    

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
