# VLESS-XHTTP golang 版

高性能xhttp协议实现

## 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `UUID` | `a2056d0d-c98e-4aeb-9aab-37f64edd5710` | UUID |
| `NEZHA_SERVER` | `` | 哪吒服务器地址 |
| `NEZHA_PORT` | `` | 哪吒端口 (v0版本使用) |
| `NEZHA_KEY` | `` | 哪吒密钥 |
| `AUTO_ACCESS` | `false` | 自动保活开关 |
| `XPATH` | UUID前8位 | XHTTP路径 |
| `SUB_PATH` | `sub` | 订阅路径 |
| `DOMAIN` | 自动获取 | 服务器域名或IP |
| `NAME` | `Xhttp` | 节点名称 |
| `PORT` | `3000` | HTTP服务端口 |
| `LOG_LEVEL` | `none` | 日志级别 (none/debug/info/warn/error) |


### 温馨提示
* 如果使用的是IP:端口或域名:端口形式访问首页，请关闭节点的tls，并将节点端口改为运行的端口
* 如果需要使用CDN功能，将IP解析到cloudflared，并设置端口回源，然后将节点的host和sni改为解析的域名
