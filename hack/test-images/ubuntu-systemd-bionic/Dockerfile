FROM ubuntu:bionic

LABEL "com.netflix.titus.systemd"="true"
ENV container docker
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y dbus systemd locales curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8
ENV LC_ALL en_US.UTF-8

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
COPY running-test.service /lib/systemd/system
RUN systemctl enable running-test.service

CMD ["/lib/systemd/systemd", "--log-level=debug", "--log-target=journal"]
