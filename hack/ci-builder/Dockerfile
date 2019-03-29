FROM ubuntu:artful


RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y apt-transport-https ca-certificates curl software-properties-common && apt-get clean
COPY docker-repo.gpg /tmp
RUN apt-key add /tmp/docker-repo.gpg
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y wget build-essential docker-ce ruby ruby-dev ruby-bundler gcc g++ make pkg-config && apt-get clean
COPY --from=golang:1.11-stretch /usr/local/go /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN go version
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# gometalinter 2.0.11:
ENV GOMETALINTER_DOWNLOAD_SHA256 97d8bd0a4d024740964c7fc2ae41276cf5f839ccf0749528ca900942f656d201
ENV GOMETALINTER_DOWNLOAD_URL https://github.com/alecthomas/gometalinter/releases/download/v2.0.11/gometalinter-2.0.11-linux-amd64.tar.gz

RUN mkdir /gometalinter && cd /gometalinter \
    && curl -fsSL $GOMETALINTER_DOWNLOAD_URL -o gometalinter.tar.gz \
	&& echo "$GOMETALINTER_DOWNLOAD_SHA256 gometalinter.tar.gz" | sha256sum -c - \
	&& tar --strip-components=1 -xf gometalinter.tar.gz \
	&& rm gometalinter.tar.gz && mv * $GOPATH/bin && cd && rm -rf /gometalinter

RUN go get -u github.com/kardianos/govendor
RUN go get github.com/mitchellh/gox
