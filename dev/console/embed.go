package console

import "embed"

// FS 内嵌控制台静态资源（HTML + JS），使中枢二进制自包含——不再依赖运行目录下
// 的 console/ 是否存在，也不受进程工作目录影响。
//
// 背景：此前 handleConsole 用 http.ServeFile(w, r, "console/index.html") 读取外部
// 相对路径文件，而发布包（build-hub job）从不打包 console/ 目录 → 生产安装目录里
// 没有 console/index.html → 访问 / 返回 404。同时 handleConsole 缺 /auth.js 路由，
// 控制台页面引用的 auth.js 同样 404。本包把全部静态资源编译进二进制，消除这两处。
//
//go:embed *.html *.js
var FS embed.FS
