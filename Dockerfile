FROM golang:1.27.3-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/threat-api ./cmd/app

FROM alpine:3.22
RUN apk --no-cache add ca-certificates && adduser -D -H app
COPY --from=build /out/threat-api /usr/local/bin/threat-api
USER app
EXPOSE 8080
ENTRYPOINT ["threat-api"]
