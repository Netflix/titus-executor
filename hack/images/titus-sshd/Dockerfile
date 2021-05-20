# Welcome to the titus-sshd Dockerfile!
#
# This image uses gentoo to get fine-grained control over the
# sshd binary and to relocate it to /titus/sshd, *even though*
# it is still dynamically linked!
#
# First we setup a gentoo environment that can run *in* docker:
FROM gentoo/stage3-amd64 as builder
RUN emerge-webrsync
RUN emerge --sync
RUN echo 'MAKEOPTS="-j32"' >> /etc/portage/make.conf
RUN echo 'USE="-pam -gdbm -berkdb -bindist"' >> /etc/portage/make.conf
# This is because Docker builds don't have CAP_SYS_PTRACE and cannot unshare
# Note: For some reason we cannot strip our binaries. Not sure why...
RUN echo 'FEATURES="-sandbox -usersandbox -ipc-sandbox -network-sandbox -pid-sandbox nostrip"' >> /etc/portage/make.conf
RUN emerge --unmerge openssh
# We want to re-emerge openssl with the new USE flags, because the old USE flags can confuse portage
RUN emerge --oneshot openssl
# you need nss on the host to build nss in the prefix
RUN PYTHON_TARGETS="python3_7" emerge patchelf repoman nss


# Next Stage: We build up dependencies and binary gentoo packages for the things
# we want to eventually be in /titus/sshd
# We use the special `emerge --prefix=/titus/sshd` so that all the things
# we build will have paths (just like one might do /usr/local/) in /titus/sshd
#
# These symlinks are required, as many configure scripts require
# them to even get off the ground and compile
RUN mkdir -p /titus/sshd/bin /titus/sshd/usr/bin
RUN ln -s /bin/bash /titus/sshd/bin/
RUN ln -s /usr/bin/perl /titus/sshd/usr/bin/
RUN ln -s /usr/bin/python3.7 /titus/sshd/usr/bin/
RUN ln -s /bin/sh /titus/sshd/bin/
RUN ln -s /bin/fgrep /titus/sshd/bin/
RUN ln -s /usr/bin/env /titus/sshd/usr/bin/
# sys-kernel/linux-headers is a build-time dependency of glibc
RUN emerge --prefix=/titus/sshd --oneshot sys-kernel/linux-headers
RUN emerge --prefix=/titus/sshd --buildpkg glibc
# For openssh itself, in titus we can't assume that the gentoo convention of having an 'sshd' user is valid
# Instead we depend on the 'nobody' user, and in titus if we don't even have *that*
# we can create the nobody user ourselves at startup time
RUN sed -i s/with-privsep-user=sshd/with-privsep-user=nobody/ /var/db/repos/gentoo/net-misc/openssh/*.ebuild # |grep =ssh
RUN cd /var/db/repos/gentoo/net-misc/openssh/ && repoman manifest
RUN emerge --prefix=/titus/sshd --buildpkg openssh nss busybox

# Now we want to discard our temp build dir and re-build
# This time we can do `--usepkgonly` to save time and use the packages we built above
# This gives us a very clean /titus/sshd with only what we need
RUN rm -r /titus/sshd
RUN emerge --prefix=/titus/sshd --nodeps --usepkgonly glibc
RUN emerge --prefix=/titus/sshd --usepkgonly glibc openssh nss busybox

# Here we *relocate* the /titus/sshd binaries using the patchelf command.
# This forces the linker to use *our* /titus/sshd/lib64/ld-linux-x86-64.so.2 as
# Here, the LD_LIBRARY_PATH under /titus/sshd is are the primary ones we look at
RUN for i in $(scanelf --recursive --mount --symlink --etype ET_DYN --perms 0700 --nobanner --format '%F' /titus/sshd/bin /titus/sshd/sbin /titus/sshd/usr/bin/ /titus/sshd/usr/sbin/  /titus/sshd/usr/lib64/misc/); do \
      xargs -n1 patchelf --set-interpreter /titus/sshd/lib64/ld-linux-x86-64.so.2 --set-rpath /titus/sshd/lib64:/titus/sshd/usr/lib64:/usr/local/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu ${i}; \
    done

RUN /titus/sshd/usr/bin/ssh-keygen -A
RUN ln -s /etc/resolv.conf /titus/sshd/etc/
RUN ln -s /etc/passwd /titus/sshd/etc/
RUN ln -s /etc/hosts /titus/sshd/etc/
RUN ln -s /titus/sshd/bin/busybox /titus/sshd/bin/sh
ADD run-titus-sshd /titus/sshd/run-titus-sshd
# The /titus/sshd volume is considered immutable, but sshd_config is generated
# dynamically from the titus-agent, so we symlink it in from /titus/etc
RUN rm /titus/sshd/etc/ssh/sshd_config && ln -s /titus/etc/ssh/sshd_config /titus/sshd/etc/ssh/sshd_config

# Finally, as a multi-stage build, we want an image that *only* has /titus/sshd and none
# of the stuff we started with:
FROM scratch
COPY --from=builder /titus/sshd /titus/sshd
