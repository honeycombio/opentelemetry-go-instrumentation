# to be built from docker-compose
FROM golang:1.20 AS build
WORKDIR /src
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

COPY go.mod .
COPY ./main.go .
RUN go build -gcflags=-l -o /out/foobar-service .

FROM scratch AS bin
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/foobar-service /app/
CMD ["/app/foobar-service"]
