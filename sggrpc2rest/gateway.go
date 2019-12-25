package main

import (
  "context" // Use "golang.org/x/net/context" for Golang version <= 1.6
  "flag"
  "fmt"
  "net/http"

  "github.com/golang/glog"
  "github.com/grpc-ecosystem/grpc-gateway/runtime"
  "google.golang.org/grpc"

  gw "starcoin/node"
)

var (
  // command-line options:
  // gRPC server endpoint
  grpcServerEndpoint = flag.String("node-grpc-endpoint",  "127.0.0.1:9000", "gRPC server endpoint")
)

func run() error {
  ctx := context.Background()
  ctx, cancel := context.WithCancel(ctx)
  defer cancel()

  // Register gRPC server endpoint
  // Note: Make sure the gRPC server is running properly and accessible
  mux := runtime.NewServeMux()
  opts := []grpc.DialOption{grpc.WithInsecure()}
  //RegisterNodeHandlerFromEndpoint
  err := gw.RegisterNodeHandlerFromEndpoint(ctx, mux,  *grpcServerEndpoint, opts)
  if err != nil {
    return err
  }

  // Start HTTP server (and proxy calls to gRPC server endpoint)
  fmt.Printf("starcoin rest api server listening 8081......")
  return http.ListenAndServe(":8081", mux)
}

func main() {
  flag.Parse()
  defer glog.Flush()

  if err := run(); err != nil {
    glog.Fatal(err)
  }
}