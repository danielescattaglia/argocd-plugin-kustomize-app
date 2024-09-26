FROM golang:1.23-alpine AS  builder
ENV CGO_ENABLED=0
WORKDIR /go/src/
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags '-w -s' -v -o /usr/local/bin/esops ./

FROM alpine
RUN apk add kustomize=5.3.0-r6 
COPY --from=builder /usr/local/bin/esops /usr/local/bin/esops
RUN chmod +x /usr/local/bin/esops
ENTRYPOINT ["esops"]

