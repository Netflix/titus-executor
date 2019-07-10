FROM golang:1.12-stretch as builder

ENV GOPATH /go
ENV EXECUTOR_DIR "$GOPATH/src/github.com/Netflix/titus-executor"
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$EXECUTOR_DIR" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
COPY . $EXECUTOR_DIR
WORKDIR $EXECUTOR_DIR
RUN go build -o titus-logviewer cmd/titus-logviewer/main.go

FROM scratch

ENV GOPATH /go
ENV EXECUTOR_DIR "$GOPATH/src/github.com/Netflix/titus-executor"
COPY --from=builder $EXECUTOR_DIR/titus-logviewer /titus/logviewer/bin/titus-logviewer
