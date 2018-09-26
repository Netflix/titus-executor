FROM ubuntu:artful

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && \
    apt-get install -y build-essential make cmake g++ gcc libc6-dev pkg-config \
        libattr1-dev git curl wget jq ruby ruby-dev rubygems lintian unzip bison flex clang llvm && \
    rm -rf /var/lib/apt/lists/*

RUN gem install --no-ri --no-rdoc fpm

COPY --from=golang:1.11-stretch /usr/local/go /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN go version

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

RUN go get -u github.com/kardianos/govendor
RUN go get -u golang.org/x/tools/cmd/goimports
RUN go get -u github.com/mitchellh/gox

# gometalinter 2.0.11:
ENV GOMETALINTER_DOWNLOAD_SHA256 97d8bd0a4d024740964c7fc2ae41276cf5f839ccf0749528ca900942f656d201
ENV GOMETALINTER_DOWNLOAD_URL https://github.com/alecthomas/gometalinter/releases/download/v2.0.11/gometalinter-2.0.11-linux-amd64.tar.gz

RUN mkdir /gometalinter && cd /gometalinter \
    && curl -fsSL $GOMETALINTER_DOWNLOAD_URL -o gometalinter.tar.gz \
	&& echo "$GOMETALINTER_DOWNLOAD_SHA256 gometalinter.tar.gz" | sha256sum -c - \
	&& tar --strip-components=1 -xf gometalinter.tar.gz \
	&& rm gometalinter.tar.gz && mv * $GOPATH/bin && cd && rm -rf /gometalinter

RUN go get -u github.com/jteeuwen/go-bindata/...

RUN chmod -R a+rw /go/src
COPY titus-executor-builder.sh /usr/local/bin/build

CMD ["/usr/local/bin/build"]
