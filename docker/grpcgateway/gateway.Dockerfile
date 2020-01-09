FROM golang:1.13.4

ENV GOPROXY https://goproxy.cn
ENV GO111MODULE on
# Warm apt cache and install dependencies
RUN apt-get update && \
    apt-get install -y unzip

# Install protoc
ENV PROTOC_VERSION 3.10.1
RUN wget https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
    -O /protoc-${PROTOC_VERSION}-linux-x86_64.zip && \
    unzip /protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local/ && \
    rm -f /protoc-${PROTOC_VERSION}-linux-x86_64.zip

# Clean up
RUN apt-get autoremove -y && \
    apt-get remove -y unzip && \
    rm -rf /var/lib/apt/lists/*

# get grpc gateway exec file
RUN go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway && \
    go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger && \
    go get -u github.com/golang/protobuf/protoc-gen-go

# gateway port
EXPOSE 8081

# copy go project file
WORKDIR /gateway
COPY grpcgateway/g* /gateway/
COPY grpcgateway/libra/go.mod /gateway/libra/


#gen go file by protoc
RUN cd /gateway && mkdir proto node sgtypes log && \
    cd proto && mkdir types sgtypes && \
    cd /gateway/libra && mkdir types
COPY libra/types/src/proto/*.proto /gateway/proto/types/
COPY sgtypes/src/proto/*.proto /gateway/proto/sgtypes/
COPY node/node_proto/src/proto/node.proto /gateway/proto/
COPY node/node_proto/src/proto/google/api     /gateway/proto/google/api/
COPY node/node_proto/src/proto/google/rpc     /gateway/proto/google/rpc/

# start gateway
COPY docker/grpcgateway/docker-run.sh /gateway
CMD /gateway/docker-run.sh