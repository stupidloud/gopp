<?php
// 获取请求的 URI 路径部分，例如 "/123.zip"
$requestUri = $_SERVER['REQUEST_URI'];

// 移除开头的斜杠，得到文件名 "123.zip"
$filename = ltrim($requestUri, '/');

// 检查文件名是否安全 (防止路径遍历)
if (strpos($filename, '..') !== false || strpos($filename, '/') !== false) {
    http_response_code(400); // Bad Request
    echo "Invalid filename.";
    exit;
}

// 假设你的 zip 文件都放在 accelRoot 目录下
header('X-Accel-Redirect: ' . $filename);

// 你仍然可以设置 Token ID 和速率限制
header('X-Accel-Token-Id: ' . '123455');
header('X-Accel-Limit-Rate: 6000000');

header('Custom-Header: 123456');

// PHP 脚本本身不需要输出任何内容
exit;
?>
