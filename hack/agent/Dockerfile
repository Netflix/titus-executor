## This produces a docker container with everything required on a titus-agent instance,
#  including systemd, dbus and docker itself (docker-in-docker).
#  Its purpose is to provide a titus-agent environment with a docker daemon, that standalone (integration)
#  tests can run against.

# systemd pieces were inspired by solita/docker-systemd (MIT License)
FROM ubuntu:xenial-20171006

### systemd
ENV container docker

# Don't start any optional services except for the few we need.
RUN find /etc/systemd/system \
         /lib/systemd/system \
         -path '*.wants/*' \
         -not -name '*journald*' \
         -not -name '*systemd-tmpfiles*' \
         -not -name '*systemd-user-sessions*' \
         -exec rm \{} \;

RUN systemctl set-default multi-user.target
STOPSIGNAL SIGRTMIN+3
###
RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y apt-transport-https ca-certificates

RUN echo "deb [arch=amd64] https://apt.dockerproject.org/repo ubuntu-xenial main" > /etc/apt/sources.list.d/docker.list
RUN apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update &&\
    apt-get install -y build-essential make cmake libattr1-dev dbus docker-engine wget

### FROM golang:1.10.1
# see: https://github.com/docker-library/golang/blob/906e04de73168f643c5c2b40dca0877a14d2377c/1.10/alpine3.7/Dockerfile
ENV GOLANG_VERSION 1.10.1

RUN set -eux; \
    goRelSha256='72d820dec546752e5a8303b33b009079c15c2390ce76d67cf514991646c6127b'; \
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

RUN systemctl enable dbus.service
RUN systemctl enable docker.service

# TODO(fabio): detect what storage-driver to use at runtime
RUN mkdir -p /etc/docker
COPY hack/agent/daemon.json /etc/docker/daemon.json
COPY hack/agent/titus-shared.env /etc/titus-shared.env
COPY hack/agent/10-disable-atlas-agent.conf /etc/systemd/system/atlas-titus-agent@.service.d/10-disable-atlas-agent.conf


# Directories that the executor needs access to, which will be available with --volumes-from
VOLUME /run
VOLUME /var/lib/docker
VOLUME /var/lib/titus-container-logs
VOLUME /var/lib/titus-inits
VOLUME /var/lib/titus-environments
VOLUME /var/tmp

# this assumes there is a deb file (or symlink) with the _latest suffix
# build scripts are expected to produce it
COPY build/distributions/titus-executor*.deb /var/cache/apt/archives/
RUN dpkg -i /var/cache/apt/archives/titus-executor_latest.deb

# Workaround for docker/docker#27202, technique based on comments from docker/docker#9212
CMD ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"]

