FROM ubuntu:bionic

# titus-agent-ci includes debs for ci-related stuff
# Specifically the linux-libc-dev package was downloaded from
# https://packages.debian.org/experimental/linux-libc-dev
# and then manually uploaded to https://packagecloud.io/netflix/titus-agent-ci
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y install curl && \
    curl https://packagecloud.io/install/repositories/netflix/titus-agent-ci/script.deb.sh | bash

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && \
    apt-get install -y build-essential make cmake g++ gcc libc6-dev pkg-config \
        libattr1-dev git curl wget jq ruby ruby-dev rubygems lintian unzip bison flex clang llvm musl-tools \
        linux-libc-dev=5.17.1-1~exp1 libcap-dev libseccomp-dev && \
    rm -rf /var/lib/apt/lists/*

RUN gem install --no-ri --no-rdoc fpm

COPY --from=golang:1.16-stretch /usr/local/go /usr/local/go
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

RUN go get -u github.com/mitchellh/gox

RUN chmod -R a+rw /go/src
COPY titus-executor-builder.sh /usr/local/bin/build
RUN mkdir -p /builds
WORKDIR /builds

CMD ["/usr/local/bin/build"]
