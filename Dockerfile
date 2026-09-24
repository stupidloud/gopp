# 内嵌 PHP 版 gopp（-tags frankenphp）。libphp 是动态库，运行镜像须与构建镜像的 PHP 版本一致。
# 需要额外的 PHP 扩展时在派生镜像中执行 install-php-extensions。
ARG FRANKENPHP_VERSION=1.12.7
ARG PHP_VERSION=8.4

FROM dunglas/frankenphp:${FRANKENPHP_VERSION}-builder-php${PHP_VERSION} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 \
    CGO_CFLAGS="$(php-config --includes)" \
    CGO_LDFLAGS="$(php-config --ldflags) $(php-config --libs)" \
    go build -tags frankenphp,nowatcher,nomercure -trimpath -ldflags="-s -w" -o /gopp .

FROM dunglas/frankenphp:${FRANKENPHP_VERSION}-php${PHP_VERSION}
COPY --from=builder /gopp /usr/local/bin/gopp
ENTRYPOINT ["gopp", "-config", "/etc/gopp/config.yaml"]
