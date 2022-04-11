FROM golang:1.16-stretch as builder

RUN apt-get update && apt-get install busybox-static

# `-tags netgo` forces the net package to use the go resolver, rather than using cgo and linking against system libraries
RUN mkdir /build
COPY . /build
RUN cd /build && go build -tags netgo -o /build/metatron-identity ./hack/test-images/metatron/metatron-identity/

FROM scratch
ENV DESTDIR "/go/src/github.com/Netflix/titus-executor/hack/test-images/metatron"
COPY --from=builder /build/metatron-identity /titus/metatron/bin/metatron-identity
COPY --from=builder /bin/busybox /titus/metatron/bin/busybox
COPY ./hack/test-images/metatron/titus-metatrond /titus/metatron/bin/titus-metatrond
