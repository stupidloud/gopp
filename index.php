<?php
// 获取请求的 URI 路径部分，例如 "/123.zip"
$requestUri = $_SERVER['REQUEST_URI'];

// 移除开头的斜杠，得到文件名 "123.zip"
$filename = ltrim($requestUri, '/');

// (可选) 在这里可以添加逻辑来检查文件是否存在、用户是否有权限下载等
// 例如：检查 $filename 是否真的是一个 zip 文件，或者是否存在于允许下载的列表

// 检查文件名是否安全 (防止路径遍历)
if (strpos($filename, '..') !== false || strpos($filename, '/') !== false) {
    http_response_code(400); // Bad Request
    echo "Invalid filename.";
    exit;
}

// 假设你的 zip 文件都放在 accelRoot 目录下
// 设置 X-Accel-Redirect 指向请求的文件
header('X-Accel-Redirect: ' . $filename);

// 你仍然可以设置 Token ID 和速率限制
header('X-Accel-Token-Id: ' . '123456'); // 使用文件名生成一个简单的 Token ID
header('X-Accel-Limit-Rate: 1048576'); // 1MB/s

// PHP 脚本本身不需要输出任何内容
exit;
?>
