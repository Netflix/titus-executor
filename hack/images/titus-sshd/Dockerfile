FROM gentoo/stage3-amd64 as builder
RUN emerge-webrsync
RUN emerge --sync
RUN echo 'MAKEOPTS="-j32"' >> /etc/portage/make.conf
RUN echo 'USE="-pam -gdbm -berkdb -bindist"' >> /etc/portage/make.conf
# This is because Docker builds don't have CAP_SYS_PTRACE
RUN echo 'FEATURES="-sandbox -usersandbox"' >> /etc/portage/make.conf
RUN echo "=sys-auth/libnss-compat-1.2 ~amd64" >> /etc/portage/package.accept_keywords
RUN emerge -C openssh
# We want to re-emerge openssl with the new USE flags, because the old USE flags can confuse portage
RUN emerge -v --oneshot openssl
# you need nss on the host to build nss in the prefix
RUN emerge patchelf repoman nss
# sys-kernel/linux-headers is a build-time dependency of glibc
RUN mkdir -p /titus/sshd/bin /titus/sshd/usr/bin
RUN ln -s /bin/bash /titus/sshd/bin/
RUN ln -s /usr/bin/perl /titus/sshd/usr/bin/
RUN emerge --prefix=/titus/sshd --oneshot sys-kernel/linux-headers
RUN emerge --prefix=/titus/sshd --buildpkg glibc
# Some of the packages which get build here turn into deps that are part of openssh
#RUN USE="-ssl" emerge --prefix=/titus/sshd --oneshot --buildpkg python:3.6 bash
RUN ln -s /usr/bin/python3.6 /titus/sshd/usr/bin/
RUN sed -i s/with-privsep-user=sshd/with-privsep-user=nobody/ /usr/portage/net-misc/openssh/*.ebuild # |grep =ssh
RUN cd /usr/portage/net-misc/openssh && repoman manifest
RUN emerge --prefix=/titus/sshd --buildpkg openssh nss libnss-compat busybox
# Now we want to discard our temp build dir
RUN rm -r /titus/sshd
RUN emerge --prefix=/titus/sshd --nodeps -K glibc
RUN emerge --prefix=/titus/sshd -K glibc openssh nss libnss-compat busybox
RUN ln -s /etc/hosts /titus/sshd/etc/
# Here, the LD_LIBRARY_PATH under /titus/sshd is are the primary ones we look at, and if those don't work,
# we fall back to the ubuntu ones
RUN for i in $(scanelf --recursive --mount --symlink --etype ET_DYN --perms 0700 --nobanner --format '%F' /titus/sshd/bin /titus/sshd/sbin /titus/sshd/usr/bin/ /titus/sshd/usr/sbin/  /titus/sshd/usr/lib64/misc/); do \
      xargs patchelf --set-interpreter /titus/sshd/lib64/ld-linux-x86-64.so.2 --set-rpath /titus/sshd/lib64:/titus/sshd/usr/lib64:/usr/local/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu ${i}; \
    done
# We might want to get rid of this later:
RUN /titus/sshd/usr/bin/ssh-keygen -A
RUN ln -s /etc/resolv.conf /titus/sshd/etc/
RUN ln -s /etc/passwd /titus/sshd/etc/
RUN rm /titus/sshd/etc/ssh/sshd_config && ln -s /titus/etc/ssh/sshd_config /titus/sshd/etc/ssh/sshd_config
FROM scratch
COPY --from=builder /titus/sshd /titus/sshd
