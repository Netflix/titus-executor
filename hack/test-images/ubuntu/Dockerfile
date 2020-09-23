FROM registry.svc.ci.openshift.org/coreos/cosa-buildroot as builder-negative-seccomp
WORKDIR /srv
COPY negative-seccomp.c .
RUN gcc -static -Wall -g -o negative-seccomp negative-seccomp.c

FROM registry.svc.ci.openshift.org/coreos/cosa-buildroot as builder-cve
WORKDIR /srv
COPY cve-cap-net-raw.c .
RUN gcc -Wall -o cve-cap-net-raw cve-cap-net-raw.c

FROM ubuntu:bionic
RUN apt-get update && apt-get install -y curl libcap2-bin grep iproute2 httpie iputils-ping stress schedtool coreutils netcat libcap2-bin
COPY --from=builder-negative-seccomp /srv/negative-seccomp /usr/bin/negative-seccomp
COPY --from=builder-cve /srv/cve-cap-net-raw /usr/bin/cve-2020-14386
RUN setcap cap_net_raw+ep /usr/bin/cve-2020-14386
