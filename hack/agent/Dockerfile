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

RUN echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable" > /etc/apt/sources.list.d/docker.list
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 9DC858229FC7DD38854AE2D88D81803C0EBFCD88

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update &&\
    apt-get install -y build-essential make cmake libattr1-dev dbus docker-ce=5:18.09.1~3-0~ubuntu-xenial wget

COPY --from=golang:1.12-stretch /usr/local/go /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN go version

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
###

RUN systemctl enable dbus.service
RUN systemctl enable docker.service

# TODO(fabio): detect what storage-driver to use at runtime
RUN mkdir -p /etc/docker /run/metatron/certificates
COPY hack/agent/daemon.json /etc/docker/daemon.json
COPY hack/agent/titus-shared.env /etc/titus-shared.env
COPY hack/agent/10-disable-atlas-agent.conf /etc/systemd/system/atlas-titus-agent@.service.d/10-disable-atlas-agent.conf

RUN wget -O /tmp/apparmor.deb http://launchpadlibrarian.net/381273068/apparmor_2.12-4ubuntu7_amd64.deb
RUN dpkg -i /tmp/apparmor.deb

# Directories that the executor needs access to, which will be available with --volumes-from
VOLUME /run
VOLUME /var/lib/docker
VOLUME /var/lib/titus-container-logs
VOLUME /var/lib/titus-inits
VOLUME /var/lib/titus-environments
VOLUME /var/tmp

# This is for the in-container SSHd configuration
RUN touch /etc/ssh/titus_user_ssh_key_cas.pub

# this assumes there is a deb file (or symlink) with the _latest suffix
# build scripts are expected to produce it
COPY build/distributions/titus-executor*.deb /var/cache/apt/archives/
RUN dpkg -i /var/cache/apt/archives/titus-executor_latest.deb

# Test Metatron certificates - these are needed for running standalone tests that
# test the metadata server's task identity endpoint:
COPY hack/agent/certs/* /metatron/certificates/

# Workaround for docker/docker#27202, technique based on comments from docker/docker#9212
CMD ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"]

