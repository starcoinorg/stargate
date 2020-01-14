package main

import (
	"context" // Use "golang.org/x/net/context" for Golang version <= 1.6
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"

	gw "starcoin/node"
)

var (
	// command-line options:
	// gRPC server endpoint
	grpcServerEndpoint = flag.String("node-grpc-endpoint", "127.0.0.1:9000", "gRPC server endpoint")
)

func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		glog.Info("req:", r)
		if origin := r.Header.Get("Origin"); origin != "" {
			fmt.Println("orign:%v", origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
				preflightHandler(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
func preflightHandler(w http.ResponseWriter, r *http.Request) {
	headers := []string{"Content-Type", "Accept", "Authorization"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	glog.Infof("preflight request for %s", r.URL.Path)
}

func run(gatewayaddr ,nodeaddr string) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register gRPC server endpoint
	// Note: Make sure the gRPC server is running properly and accessible
	//mux := runtime.NewServeMux()
	mux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{OrigName: true, EmitDefaults: true}))
	opts := []grpc.DialOption{grpc.WithInsecure()}

	//RegisterNodeHandlerFromEndpoint
	err := gw.RegisterNodeHandlerFromEndpoint(ctx, mux, nodeaddr, opts)
	if err != nil {
		glog.Errorln("connect to node grpc error:", err)
		return err
	}

	s := &http.Server{
		Addr:    gatewayaddr,
		Handler: allowCORS(mux),
	}
	fmt.Println("Starting listening at :", s.Addr)
	if err := s.ListenAndServe(); err != http.ErrServerClosed {
		glog.Errorf("Failed to listen and serve: %v", err)
		return err
	}
	return nil
}

func main() {
	var gateway_port, node_port  string
	flag.StringVar(&gateway_port,"gateway_addr", ":8081", "gateway listening addr and port")
	flag.StringVar(&node_port,"node_addr", "127.0.0.1:9000", "wallet node listening addr and port")
	flag.Parse()
	defer glog.Flush()

	if err := run(gateway_port, node_port); err != nil {
		glog.Fatal(err)
	}
}
