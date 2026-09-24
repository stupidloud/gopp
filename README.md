# gopp

gopp 是一个用 Go 编写的 PHP-FPM 前端：直接提供静态文件，其余请求通过 FastCGI 交给 PHP-FPM，并支持 nginx 风格的 `X-Accel-Redirect` 受保护文件下载与按用户限速。

gopp 不做 TLS 终止，应部署在 nginx / Cloudflare / HAProxy 等反向代理之后。

## 请求处理流程

1. 路径中有以 `.` 开头的段（`.env`、`.git/` 等，`.well-known` 除外）→ 403
2. `doc_root` 下存在对应的文件（且不以 `.php` 结尾）→ 直接返回该文件
3. 以 `.php` 结尾 → 执行该脚本（不存在返回 404）；其他请求（包括目录）→ 执行 `main_php_file`
4. PHP 响应带 `X-Accel-Redirect` 头 → 丢弃 PHP 响应体，改为发送 `accel_root` 下的对应文件

访问文件时跟随软链接，但指向根目录之外或使用绝对路径的软链接一律拒绝（403）。

## X-Accel-Redirect 下载

PHP 通过响应头控制下载：

| 响应头 | 说明 |
|---|---|
| `X-Accel-Redirect` | 要发送的文件，相对 `accel_root` 的路径，如 `/videos/a.mp4` |
| `X-Accel-Limit-Rate` | 限速，字节/秒；不设置或为 0 表示不限速 |
| `X-Accel-Token-Id` | 限速归属（如用户 ID）：同一 token 的所有连接共享速率；不设置时只限制当前连接 |

以上头不会发给客户端。PHP 设置的其他头（如 `Content-Disposition`）会保留；`Content-Type` 为 PHP 默认的 `text/html` 时改为按扩展名推断。Range、多段 Range、If-Range、If-None-Match、HEAD 均按 HTTP 标准处理，文件通过 `sendfile(2)` 零拷贝发送。

```php
<?php
// 鉴权后……
header('Content-Disposition: attachment; filename="report.pdf"');
header('X-Accel-Redirect: /reports/2026/report.pdf');
header('X-Accel-Token-Id: user-' . $userId);
header('X-Accel-Limit-Rate: 1048576'); // 1 MB/s
```

文件不存在返回 404，指向目录或经软链接指向 `accel_root` 之外返回 403；路径中的 `..` 不会越出 `accel_root`。

### 多实例限速

- `redis_backend: false`：每个实例独立限速；同一 token 的连接分散到 N 个实例时，总速率最高为 N 倍
- `redis_backend: true`：全局令牌桶保存在 Redis 中（Lua 脚本，要求 Redis ≥ 5，无需额外模块），所有实例共享速率。Redis 不可用时自动退回本地限速并记录错误日志，恢复后自动切回

## 配置

默认读取当前目录下的 `config.yaml`（不存在时使用默认配置），也可用 `-config` 指定路径。各项说明及默认值见 [config.yaml](config.yaml)。

| 项 | 说明 |
|---|---|
| `listen_addr` | 监听地址 |
| `fpm_network` / `fpm_address` | PHP-FPM 地址：`tcp` + `127.0.0.1:9000`，或 `unix` + socket 路径 |
| `doc_root` | PHP 与静态文件的根目录 |
| `accel_root` | `X-Accel-Redirect` 文件的根目录，应放在 `doc_root` 之外 |
| `main_php_file` | 主入口脚本 |
| `trusted_proxies` | 反向代理的地址（CIDR 或 IP）。只有直连地址属于其中时才采信 `X-Forwarded-For` / `X-Real-IP`，据此设置 `REMOTE_ADDR` |
| `redis_*` | 见上文多实例限速 |
| `php_threads` / `php_worker_file` / `php_worker_num` | 仅内嵌 PHP 版，见下文 |
| `log_level` | `debug` / `info` / `warn` / `error` |

收到 SIGTERM / SIGINT 时停止接受新连接，等待进行中的请求完成（最多 30 秒）后退出。

## 内嵌 PHP 版（实验）

以 `-tags frankenphp` 构建时，gopp 通过 [FrankenPHP](https://frankenphp.dev) 在进程内执行 PHP，不再需要 PHP-FPM（`fpm_*` 配置不再使用）。路由、静态文件、X-Accel-Redirect（仍为 sendfile 零拷贝）、限速均与 FPM 版相同。

- `php_threads`：PHP 线程数，0 为 CPU 数的 2 倍
- `php_worker_file`：worker 模式入口（相对 `doc_root`）。设置后，原本交给 `main_php_file` 的请求改由常驻的 worker 处理，应用只需启动一次（入口写法见 FrankenPHP 文档中的 `frankenphp_handle_request`）；直接请求的其他 `.php` 仍按普通方式执行
- `php_worker_num`：worker 线程数，0 为 CPU 数的 2 倍，须小于 `php_threads`

需要开启 ZTS 与 embed SAPI 的 libphp，产物动态链接 `libphp.so`，因此以 Docker 镜像交付：

```sh
docker build -t gopp-embed .
docker run -v /srv:/srv -v /etc/gopp/config.yaml:/etc/gopp/config.yaml gopp-embed
```

PHP 扩展需在派生镜像中用 `install-php-extensions` 安装。注意：PHP 扩展崩溃会导致整个 gopp 进程退出（FPM 版只影响一个 worker 进程）。

## 构建与测试

需要 Go 1.26+。

```sh
go build -o gopp .
./gopp -config /etc/gopp/config.yaml

go vet ./...
go test -race ./...   # Redis 相关测试需要 Redis（默认 127.0.0.1:6379，可用 GOPP_TEST_REDIS 指定），不可达时跳过
```
