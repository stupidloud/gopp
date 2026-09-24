#!/usr/bin/env bash
# 压缩 $1 并上传到 litterbox（catbox 的临时文件服务，保留 72 小时），把链接写入步骤输出与工作流摘要
set -euo pipefail
gzip -c "$1" > "$1.gz"
UPLOAD_URL=$(curl -sS --fail --retry 3 -F reqtype=fileupload -F time=72h -F "fileToUpload=@$1.gz" \
  https://litterbox.catbox.moe/resources/internals/api.php)

# 返回的不是链接（如服务关闭时返回的说明文字）则失败
case "$UPLOAD_URL" in
  https://*) ;;
  *) echo "::error::上传失败，返回：$UPLOAD_URL"; exit 1 ;;
esac
echo "Uploaded to: $UPLOAD_URL"
echo "artifact_url=$UPLOAD_URL" >> "$GITHUB_OUTPUT"
echo "### $1 下载链接（72 小时内有效）" >> "$GITHUB_STEP_SUMMARY"
echo "$UPLOAD_URL" >> "$GITHUB_STEP_SUMMARY"
