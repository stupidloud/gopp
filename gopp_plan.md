# Go HTTP 代理服务器 - 核心需求

## 目标

使用 Go 语言构建一个 HTTP 代理服务器。

## 核心技术栈

*   **HTTP 服务器/客户端**: `net/http` 标准库
*   **数据流传输**: `io.Copy` 标准库函数

## 关键功能需求

1.  **PHP-FPM 后端支持**:
    *   代理服务器需要能够将接收到的 HTTP 请求，通过 FastCGI 协议转发给后端的 PHP-FPM 服务。
    *   接收并处理来自 PHP-FPM 的 FastCGI 响应。
2.  **`X-Accel-Redirect` 支持**:
    *   检查来自 PHP-FPM 响应中的 `X-Accel-Redirect` Header。
    *   如果存在该 Header，代理服务器需根据其值（内部路径）读取服务器本地对应的文件，并将文件内容直接返回给客户端，而不是返回 PHP-FPM 的原始响应。
3.  **`sendfile` 优化**:
    *   在处理 `X-Accel-Redirect` 导致的文件发送场景时，应利用操作系统的 `sendfile` 机制（Go 标准库如 `http.ServeFile` 或 `io.Copy` 在特定条件下会自动尝试使用）来提高文件传输效率。