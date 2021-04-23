FROM busybox as builder

RUN mkdir /downloads
WORKDIR /downloads

RUN wget https://github.com/minos-org/minos-static/raw/master/static-get
RUN chmod +x static-get

RUN mkdir -p /titus/sshd
RUN ./static-get --extract openssh-6.1p1-3
RUN cp -a openssh-6.1p1-3/* /titus/sshd/

RUN mkdir -p /titus/sshd/etc/ssh
RUN mkdir /etc/ssh/
RUN /titus/sshd/usr/bin/ssh-keygen -A
RUN cp -a /etc/ssh/* /titus/sshd/etc/ssh/
RUN ln -s /etc/resolv.conf /titus/sshd/etc/
RUN ln -s /etc/passwd /titus/sshd/etc/
RUN ln -sf /titus/etc/ssh/sshd_config /titus/sshd/etc/ssh/sshd_config
ADD run-titus-sshd /titus/sshd/run-titus-sshd

RUN mkdir -p /titus/sshd/bin/
RUN cp /bin/busybox /titus/sshd/bin/
RUN cd /titus/sshd/bin/ && /titus/sshd/bin/busybox --install -s .

FROM scratch
COPY --from=builder /titus/sshd /titus/sshd
