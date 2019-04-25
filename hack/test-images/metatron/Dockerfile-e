FROM ubuntu:bionic as builder

COPY --from=golang:1.12-stretch /usr/local/go /usr/local/go
RUN apt-get update && apt-get install busybox-static
ENV GOPATH /go
ENV EXECUTOR_DIR "$GOPATH/src/github.com/Netflix/titus-executor"
ENV DESTDIR "$EXECUTOR_DIR/hack/test-images/metatron"

ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$DESTDIR" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
COPY ./hack/test-images/metatron $DESTDIR
COPY ./api $EXECUTOR_DIR/api
COPY ./vendor $EXECUTOR_DIR/vendor

# `-tags netgo` forces the net package to use the go resolver, rather than using cgo and linking against system libraries
RUN cd $DESTDIR/metatron-identity && go build -tags netgo -o metatron-identity main.go

FROM scratch
ENV DESTDIR "/go/src/github.com/Netflix/titus-executor/hack/test-images/metatron"
COPY --from=builder $DESTDIR/metatron-identity/metatron-identity /titus/metatron/bin/metatron-identity
COPY --from=builder /bin/busybox /titus/metatron/bin/busybox
COPY ./hack/test-images/metatron/titus-metatrond /titus/metatron/bin/titus-metatrond
