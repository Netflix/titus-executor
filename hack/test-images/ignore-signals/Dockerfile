FROM ubuntu:xenial
COPY trap.sh /
RUN chmod 755 /trap.sh
STOPSIGNAL SIGTERM
HEALTHCHECK --timeout=5s --interval=1s --start-period=1s CMD /bin/true
CMD ["/trap.sh"]
