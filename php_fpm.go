//go:build !frankenphp

package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/yookoala/gofast"
)

// fpmBackend 通过 FastCGI 把请求交给外部的 PHP-FPM（默认构建）
type fpmBackend struct {
	appCtx  *AppContext
	handler http.Handler
}

func newPHPBackend(appCtx *AppContext) (phpBackend, error) {
	appCtx.Logger.Info("后端 PHP-FPM", "network", appCtx.Config.FPMNetwork, "address", appCtx.Config.FPMAddress)
	connFactory := gofast.SimpleConnFactory(appCtx.Config.FPMNetwork, appCtx.Config.FPMAddress)

	phpSessionHandler := gofast.Chain(
		gofast.BasicParamsMap,                   // 基本 CGI 参数
		mapHeader,                               // HTTP 请求头
		basicFastCGISetupSessionHandler(appCtx), // 设置 DOCUMENT_ROOT, REMOTE_ADDR 等
		phpScriptRouterSessionHandler(appCtx),   // 设置 SCRIPT_FILENAME, SCRIPT_NAME
	)(gofast.BasicSession) // 处理 FastCGI 通信

	return &fpmBackend{
		appCtx:  appCtx,
		handler: gofast.NewHandler(phpSessionHandler, gofast.SimpleClientFactory(connFactory)),
	}, nil
}

func (b *fpmBackend) ServePHP(w http.ResponseWriter, r *http.Request, script phpScript) {
	b.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), phpScriptKey{}, script)))
}

func (b *fpmBackend) Close() {}

type phpScriptKey struct{}

// phpScriptRouterSessionHandler 按 resolvePHPScript 的结果设置 SCRIPT_FILENAME 和 SCRIPT_NAME
func phpScriptRouterSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			script := req.Raw.Context().Value(phpScriptKey{}).(phpScript)
			req.Params["SCRIPT_FILENAME"] = script.filename
			req.Params["SCRIPT_NAME"] = script.name
			appCtx.Logger.Debug("PHP 脚本路由", "script_filename", script.filename, "script_name", script.name)

			return inner(client, req)
		}
	}
}

// mapHeader 将请求头映射为 HTTP_* 参数（替代 gofast.MapHeader）：
//   - 丢弃名称含下划线的请求头：Client-Ip 与 Client_Ip 都会映射为 HTTP_CLIENT_IP，
//     取值将由 map 遍历顺序决定，还可借此覆盖代理设置的头（与 nginx underscores_in_headers off 一致）
//   - 丢弃 Proxy 头，防止 httpoxy：HTTP_PROXY 会被不少 PHP HTTP 客户端当作出站代理配置
//   - 多个 Cookie 头以 "; " 连接（gofast 用 ","，PHP 无法正确解析）
func mapHeader(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
		r := req.Raw
		if r.Host != "" {
			req.Params["HTTP_HOST"] = r.Host
		}
		for k, v := range r.Header {
			if dropHeader(k) {
				continue
			}
			key := strings.ReplaceAll(strings.ToUpper(k), "-", "_")
			if key == "CONTENT_TYPE" || key == "CONTENT_LENGTH" {
				continue // 已由 BasicParamsMap 设置
			}
			sep := ","
			if key == "COOKIE" {
				sep = "; "
			}
			req.Params["HTTP_"+key] = strings.Join(v, sep)
		}
		return inner(client, req)
	}
}

// basicFastCGISetupSessionHandler 设置基本的 FastCGI 参数，如 DOCUMENT_ROOT 和 REMOTE_ADDR。
func basicFastCGISetupSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			req.Params["DOCUMENT_ROOT"] = appCtx.Config.DocRoot

			realIP := GetRealIP(req.Raw, appCtx.Config.trustedProxyNets)
			req.Params["REMOTE_ADDR"] = realIP
			appCtx.Logger.Debug("设置基本 FastCGI 参数", "doc_root", appCtx.Config.DocRoot, "remote_addr", realIP)

			return inner(client, req)
		}
	}
}
