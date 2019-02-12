FROM ubuntu:bionic
# Make sure that we can use `runc` to enter containers that have USER set to non-root
RUN addgroup app && adduser --ingroup app app
USER app
# Confirm that we can run a command as the user
RUN ls /home/app
CMD ["/bin/bash" "-c"]
