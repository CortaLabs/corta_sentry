FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cortasentry ./cmd/cortasentry

FROM alpine:3.21
RUN addgroup -S cortasentry && adduser -S -G cortasentry -h /data cortasentry
COPY --from=build /out/cortasentry /usr/local/bin/cortasentry
COPY rules /usr/local/share/cortasentry/rules
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8088
USER cortasentry
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O- http://127.0.0.1:8088/healthz || exit 1
ENTRYPOINT ["cortasentry"]
CMD ["serve"]
