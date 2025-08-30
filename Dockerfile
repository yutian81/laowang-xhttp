FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./

RUN go mod download

COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates curl bash \
    && rm -rf /var/cache/apk/*

WORKDIR /root/

COPY --from=builder /app/app .

RUN chmod +x app

EXPOSE 3000

CMD ["./app"]
