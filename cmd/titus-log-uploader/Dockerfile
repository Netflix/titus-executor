FROM golang:1-alpine as builder

WORKDIR /usr/app
COPY  . .
RUN go build -mod=vendor ./cmd/titus-log-uploader/

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /usr/app/titus-log-uploader ./titus-log-uploader

CMD ["./titus-log-uploader"]
