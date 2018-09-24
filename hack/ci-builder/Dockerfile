FROM ubuntu:artful


RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y apt-transport-https ca-certificates curl software-properties-common && apt-get clean
COPY docker-repo.gpg /tmp
RUN apt-key add /tmp/docker-repo.gpg
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y wget build-essential docker-ce ruby ruby-dev ruby-bundler gcc g++ make pkg-config && apt-get clean
COPY --from=golang:1.10.4-stretch /usr/local/go /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN go version
RUN go get -u github.com/alecthomas/gometalinter
RUN gometalinter --install
RUN go get -u github.com/kardianos/govendor
RUN go get github.com/mattn/goveralls
RUN go get github.com/mitchellh/gox
