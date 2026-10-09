# Check ProxyIP

基于 Cloudflare Workers 的 ProxyIP 检测工具。提供网页界面和 JSON 接口，支持单个或批量检测、域名解析、出口信息查看和结果导出。

本文档对应 `worker.js`（外部检测接口版）。

## 功能

- 单目标和批量检测，批量模式会自动识别粘贴文本里的 IPv4、IPv6 和域名
- 域名通过 DoH（Cloudflare DNS）解析 A、AAAA、TXT 记录，每个解析出的地址单独检测
- 同一个域名同时有 IPv4 和 IPv6 出口时，筛选里归入「IPv4&IPv6」
- 显示检测机房、出口 IP、出口国家、出口城市、ASN、组织、响应时间
- 按状态（有效、失败、OnlyIPv4、OnlyIPv6、IPv4&IPv6）和出口国家筛选
- 复制有效结果，导出 TXT 或 CSV；IPv6 复制时自动补 `[]`
- 单目标模式记住最近 8 条输入（保存在浏览器 localStorage）
- 也能有效检测出Cloudflare 官网反代
- 支持复制有效结果、复制失败结果、复制筛选结果、导出 TXT、导出 CSV
- 支持检测目标和检测结果顺序一致

## 部署

1. 打开 Cloudflare 控制台，进入 Workers & Pages，创建一个 Worker
2. 把 `worker.js` 的全部内容粘贴进去并部署
3. 访问 Worker 域名即可使用，不需要绑定 KV、D1 等资源，也不需要环境变量

## 使用

### 网页

打开 Worker 域名，输入目标后点「开始检测」。

- 单目标：按 Enter 开始
- 批量：Ctrl/⌘ + Enter 开始，可导入或直接拖入 `.txt`、`.csv` 文件，一次最多检测 500 个
- 没写端口的目标默认按 443 处理

### 接口

| 请求 | 说明 |
| --- | --- |
| `/?ip=1.1.1.1:443` | 检测一个或多个目标，多个用英文逗号分隔 |
| `/?ip=proxy.example.com&resolve=1` | 只解析域名，返回待检测任务列表，不做检测 |
| `/?ip=1.1.1.1:443&direct=1` | 只检测这一个目标，不做域名展开 |

示例：

```
/?ip=1.1.1.1,1.0.0.1:443,[2606:4700::]:443,proxy.example.com
```

返回 JSON 数组，有效目标示例：

```json
{
  "目标": "[2001:db8::1]:443",
  "有效ProxyIP": true,
  "ip": "[2001:db8::1]",
  "端口": 443,
  "出口ip": "2001:db8::1",
  "出口类型": "ipv6",
  "数据中心": "LAX",
  "出口国家": "HK",
  "出口城市": "Tung Chung",
  "ASN": "139659",
  "组织": "...",
  "响应时间": "155ms"
}
```

无效目标返回 `"有效ProxyIP": false` 和 `"失败原因"`。

## 工作方式

1. 浏览器先把输入发给 Worker（`resolve=1`），拿到展开后的任务列表
2. 浏览器直接请求外部检测接口，同时最多 3 个任务并行
3. 浏览器直连失败（网络错误、被拦截等）时，改由 Worker 代为请求同一个接口
4. 结果显示在卡片里，可筛选和导出



## 关于显示的位置

- 「检测机房」是发起检测的 Cloudflare 机房，不是 ProxyIP 的位置
- 「出口国家」「出口城市」才是 ProxyIP 出口的位置
- 响应时间是检测机房到 ProxyIP 的延迟，不是你本机到它的延迟

## 可调参数

| 参数 | 位置 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `TRACE_TIMEOUT` | Worker | 10000 ms | 请求外部接口的超时 |
| `FAST_PROBE_TIMEOUT_MS` | Worker | 12000 ms | 单个目标的总超时 |
| `MAX_TARGETS_PER_DOMAIN` | Worker | 9999 | 单个域名最多展开的目标数 |
| `MAX_BATCH_TARGETS` | 前端 | 500 | 批量模式单次上限 |
| `BATCH_CONCURRENCY` | 前端 | 3 | 前端并发数 |
| `CLIENT_PROBE_TIMEOUT_MS` | 前端 | 10000 ms | 浏览器直连接口的超时 |
| `DEBUG_PROBE` | Worker | true | 是否在日志里打印探测失败详情 |

## 注意事项

- 请只检测你有权检测的目标，并遵守外部接口和 Cloudflare 的使用条款
- 批量检测会向外部接口发起大量请求，建议控制数量
- 目标里 `#` 后面的内容（如 `1.1.1.1:443#sni`）在这个版本里会被忽略，不支持自定义 SNI
- 端口范围是 1 到 65535，超出范围的目标会被忽略
- 更多 http、https、proxyip、socks5、turn、TG代理 请关注OTC分享群频道 [@otcfxq](https://t.me/otcfxq)
- 感谢600佬赞助 cloudflare snippets [@Six600NotLao](https://t.me/Six600NotLao)
