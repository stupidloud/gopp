#!/usr/bin/env bash
# 编译内嵌 PHP 的单文件 gopp：musl + static-php-cli，完全静态链接，不依赖任何 .so，可在任意 x86_64 / arm64 Linux 上直接运行。
#
# 依赖：Go、gcc、make、cmake、re2c 等基础编译工具。首次运行时 static-php-cli 会把 musl 工具链装到 /usr/local/musl，
# 并在 .spc/ 下下载、编译 PHP 及依赖库（4 核约 6 分钟），之后只要 PHP 版本和扩展不变就直接复用。
#
# 环境变量：
#   PHP_VERSION     PHP 版本（默认 8.4）
#   PHP_EXTENSIONS  PHP 扩展，逗号分隔（默认 pdo_mysql,mbstring,curl,opcache,redis,apcu；依赖的扩展会自动加入）
#   OUTPUT          输出文件（默认 gopp-static）
#
# ./build-static.sh test 改为以相同方式链接并运行测试。
set -euo pipefail
cd "$(dirname "$0")"

PHP_VERSION=${PHP_VERSION:-8.4}
PHP_EXTENSIONS=${PHP_EXTENSIONS:-pdo_mysql,mbstring,curl,opcache,redis,apcu}
PHP_LIBS=mimalloc # musl 自带的 malloc 在多线程下很慢
OUTPUT=${OUTPUT:-gopp-static}
ROOT=$PWD
SPC_DIR=$ROOT/.spc

mkdir -p "$SPC_DIR"
cd "$SPC_DIR"
if [ ! -x spc ]; then
	curl -fsSL --retry 3 -o spc "https://dl.static-php.dev/static-php-cli/spc-bin/nightly/spc-linux-$(uname -m)"
	chmod +x spc
fi

musl=/usr/local/musl/bin/$(uname -m)-linux-musl
if [ ! -x "$musl-gcc" ]; then
	./spc doctor --auto-fix
fi

# PHP 版本或扩展变化时重新编译 libphp
stamp="$PHP_VERSION $PHP_EXTENSIONS $PHP_LIBS"
if [ ! -f buildroot/lib/libphp.a ] || [ "$(cat libphp.stamp 2>/dev/null)" != "$stamp" ]; then
	./spc doctor --auto-fix
	./spc download --with-php="$PHP_VERSION" --for-extensions="$PHP_EXTENSIONS" --for-libs="$PHP_LIBS" --prefer-pre-built --retry 5
	# musl 下 opcache JIT 不可用
	SPC_DEFAULT_C_FLAGS="-fPIC -O2" \
		SPC_CMD_VAR_PHP_MAKE_EXTRA_CFLAGS="-fPIE -fstack-protector-strong -O2 -w -s" \
		./spc build --enable-zts --build-embed --disable-opcache-jit "$PHP_EXTENSIONS" --with-libs="$PHP_LIBS"
	echo "$stamp" >libphp.stamp
fi

export CC=$musl-gcc CXX=$musl-g++ CGO_ENABLED=1
export CGO_CFLAGS="$(./spc spc-config "$PHP_EXTENSIONS" --with-libs="$PHP_LIBS" --includes)"
export CGO_LDFLAGS="$(./spc spc-config "$PHP_EXTENSIONS" --with-libs="$PHP_LIBS" --libs)"

cd "$ROOT"
tags=frankenphp,nowatcher,nomercure,netgo,osusergo
# musl 默认线程栈只有 128KB，PHP 线程需要更大的栈
ldflags="-linkmode=external -extldflags '-static-pie -Wl,-z,stack-size=0x80000'"
if [ "${1:-}" = test ]; then
	go vet -tags "$tags" ./...
	go test -tags "$tags" -buildmode=pie -ldflags "$ldflags" -count=1 ./...
	exit
fi
go build -tags "$tags" -trimpath -buildmode=pie -ldflags "-s -w $ldflags" -o "$OUTPUT" .
echo "已生成 $OUTPUT"
