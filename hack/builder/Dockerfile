FROM ubuntu:xenial

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && \
    apt-get install -y build-essential make cmake g++ gcc libc6-dev pkg-config \
        libattr1-dev git curl wget jq ruby ruby-dev rubygems lintian unzip bison flex clang llvm && \
    rm -rf /var/lib/apt/lists/*

RUN gem install --no-ri --no-rdoc fpm

### FROM golang:1.9.1
ENV GOLANG_VERSION 1.9.1

RUN set -eux; \
    goRelSha256='07d81c6b6b4c2dcf1b5ef7c27aaebd3691cdb40548500941f92b221147c5d9c7'; \
	url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz"; \
	wget -O go.tgz "$url"; \
	echo "${goRelSha256} *go.tgz" | sha256sum -c -; \
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz; \
	export PATH="/usr/local/go/bin:$PATH"; \
	go version

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
###

# We install libnl(-dev) from source here, because the version (3.2) in Ubuntu
# produces compiler warnings in the headers, but the ABI / API should be preserved
ENV LIBNL_DOWNLOAD_SHA256 b7287637ae71c6db6f89e1422c995f0407ff2fe50cecd61a312b6a9b0921f5bf
ENV LIBNL_DOWNLOAD_URL https://github.com/thom311/libnl/releases/download/libnl3_4_0/libnl-3.4.0.tar.gz

RUN curl -fsSL $LIBNL_DOWNLOAD_URL -o libnl.tar.gz \
	&& echo "$LIBNL_DOWNLOAD_SHA256 libnl.tar.gz" | sha256sum -c - \
	&& tar -xf libnl.tar.gz && cd libnl-3.4.0 && ./configure \
	&& make && make install

### protobuf
ARG PROTOC_VERSION=3.4.0
RUN cd /tmp ;\
    curl -L -O https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip &&\
    unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local ;\
    rm -f protoc-${PROTOC_VERSION}-linux-x86_64.zip
RUN chmod a+x /usr/local/bin/protoc
RUN go get -u google.golang.org/grpc
RUN go get -u github.com/gogo/protobuf/proto
RUN go get -u github.com/gogo/protobuf/protoc-gen-gogo
RUN go get -u github.com/gogo/protobuf/gogoproto
RUN go get -u github.com/gogo/protobuf/protoc-gen-gogofast
RUN go get -u github.com/gogo/protobuf/protoc-gen-gogoslick
###

RUN go get -u github.com/kardianos/govendor
RUN go get -u golang.org/x/tools/cmd/goimports
RUN go get -u github.com/mitchellh/gox
RUN go get -u github.com/alecthomas/gometalinter
RUN gometalinter --install

RUN go get -u github.com/jteeuwen/go-bindata/...

VOLUME /tmp
VOLUME /src
VOLUME /dist

COPY titus-executor-builder.sh /usr/local/bin/build

CMD ["/usr/local/bin/build"]
