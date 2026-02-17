# mock-demo.json 全功能说明与 cURL 示例

本说明对应 **examples/mock-demo.json**，按配置结构逐项说明含义，并给出可直接复制的 cURL 请求示例。新用户可据此理解每个功能如何配置与调用。



Mock 服务监听 **8080**，Admin 控制台 

---

## 1. listen（监听）

**作用**：配置 Mock 服务监听的地址、端口与协议（HTTP/HTTPS）。可配置多组，每组一个 Server。

**配置说明**：

- `host`：监听地址，如 `0.0.0.0`（本机+局域网）、`127.0.0.1`（仅本机）。
- `port`：端口号。
- `protocols`：`["http"]` 或 `["https"]` 或两者。若含 `https`，需同时配置 `cert_file`、`key_file`。

**本示例**：仅 HTTP，`0.0.0.0:8080`。

**cURL**：无需单独测 listen，后续所有请求即通过该端口访问。

---

## 2. static（静态资源）

**作用**：将 URL 前缀映射到本地目录，对外提供静态文件（HTML/图片/附件等）。支持自定义响应头、是否强制下载、允许的 HTTP 方法。

**配置说明**：

- `mount`：URL 前缀，如 `/demo-static/`。
- `dir`：本地目录，如 `./files`。
- `download`：`true` 时响应带 `Content-Disposition: attachment`，触发下载。
- `index_files`：请求目录时依次尝试的默认文件。
- `allow_methods`：允许的方法，如 `["GET","HEAD"]`。
- `headers`：对所有静态响应追加的头部。

**本示例**：

- `/demo-static/` → `./files`，不下载，带自定义头。
- `/download/` → `./files`，`download: true`，用于下载文件。

**cURL**：

```bash
# 访问静态目录下的文件（GET）
curl -s http://127.0.0.1:8080/demo-static/index.html

# 查看响应头（含 X-Demo-Static、Cache-Control）
curl -sI http://127.0.0.1:8080/demo-static/demo.png

# 触发下载（/download/ 下 download: true）
curl -sI http://127.0.0.1:8080/download/demo.png
```

---

## 3. routes（HTTP 路由）— 按条说明

### 3.1 路径参数与模板变量

**路径**：`GET /api/demo/user/{id}`  

**作用**：演示路径参数。URL 中的 `{id}` 会注入为变量 `param.id`，在响应 body/headers 中可用 `{{param.id}}` 引用。

**cURL**：

```bash
curl -s http://127.0.0.1:8080/api/demo/user/42
# 返回示例：{"id":"42","message":"路径参数 param.id 已注入"}
```

---

### 3.2 Query 与强类型占位符

**路径**：`GET /api/demo/query`  

**作用**：演示从 Query 取参，以及 **强类型占位符** `{{@int:query.age}}`、`{{@bool:query.vip}}`，使 JSON 中该字段为数字/布尔而非字符串。

**cURL**：

```bash
curl -s "http://127.0.0.1:8080/api/demo/query?name=alice&age=18&vip=true"
# age_str 为字符串 "18"，age_int 为数字 18，vip 为布尔 true
```

---

### 3.3 路由级 when（不满足则 403）

**路径**：`GET /api/demo/route-when`  

**作用**：在**路由**上配置 `when`，只有条件满足才处理请求，否则直接返回 **403**。本示例要求 `query.role=admin`。

**cURL**：

```bash
# 不满足 → 403
curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/api/demo/route-when"
# 403

# 满足
curl -s "http://127.0.0.1:8080/api/demo/route-when?role=admin"
# {"ok":true,"msg":"路由级 when 通过：query.role=admin"}
```

---

### 3.4 match（headers + query 正则）

**路径**：`GET /api/demo/match`  

**作用**：**match** 在进入响应前做预过滤；不满足则 **404**。本示例要求 Header `X-Api-Key` 匹配正则 `^key-.+`，Query `env` 匹配 `^(dev|test)$`。

**cURL**：

```bash
# 缺 Header 或 env 不匹配 → 404
curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/api/demo/match?env=prod"
# 404

curl -s -H "X-Api-Key: key-abc" "http://127.0.0.1:8080/api/demo/match?env=dev"
# {"ok":true,"msg":"match 通过：Header X-Api-Key 正则 + Query env 正则"}
```

---

### 3.5 match.body（请求体点路径 + 正则/等值）

**路径**：`POST /api/demo/match-body`  

**作用**：**match.body** 按点路径读取 JSON body，对指定字段做正则或等值匹配。本示例要求 `type` 匹配 `^(login|register)$`，`version` 等值 `v1`。

**cURL**：

```bash
curl -s -X POST http://127.0.0.1:8080/api/demo/match-body \
  -H "Content-Type: application/json" \
  -d '{"type":"login","version":"v1"}'
# {"ok":true,"msg":"match.body 点路径匹配通过"}
```

---

### 3.6 extract（从 body 提取变量）

**路径**：`POST /api/demo/extract`  

**作用**：**extract** 从 body/query/header 按点路径提取字段，写入 `extract.<key>`，供后续响应 body/headers/模板使用。本示例从 body 提取 `data.userId`、`data.profile.level`。

**cURL**：

```bash
curl -s -X POST http://127.0.0.1:8080/api/demo/extract \
  -H "Content-Type: application/json" \
  -d '{"data":{"userId":"u123","profile":{"level":5}}}'
# {"echo_userId":"u123","echo_level":"5"}
```

---

### 3.7 多响应分支（when：等值、>、~ 正则、兜底）

**路径**：`GET /api/demo/branch/{id}`  

**作用**：**responses** 为数组时，按顺序匹配每条 response 的 **when**；when 支持等值、`>`、`<`、`~`（正则）、`contains`。第一条满足即返回，否则走兜底。

**cURL**：

```bash
# when param.id=007
curl -s http://127.0.0.1:8080/api/demo/branch/007

# when param.id>100
curl -s http://127.0.0.1:8080/api/demo/branch/200

# when param.id 匹配正则 [a-z]+
curl -s http://127.0.0.1:8080/api/demo/branch/abc

# 兜底
curl -s http://127.0.0.1:8080/api/demo/branch/50
```

---

### 3.8 响应：status / headers / cookies / delay_ms

**路径**：`GET /api/demo/response-full`  

**作用**：演示单条 response 的 **status**、**headers**（可含模板变量）、**cookies**（name/value/path/max_age/http_only/same_site 等）、**delay_ms**（模拟延迟）。

**cURL**：

```bash
curl -s -c - -b - "http://127.0.0.1:8080/api/demo/response-full?name=alice&uid=u1" -v
# 观察：状态 201、响应头 X-Custom: alice、Set-Cookie demo_token、约 100ms 延迟
```

---

### 3.9 响应直接回文件（file）

**路径**：`GET /api/demo/file`  

**作用**：**responses[].file** 指定本地文件路径（可含模板变量），直接将文件内容作为响应体返回。

**cURL**：

```bash
curl -s -o /tmp/out.png http://127.0.0.1:8080/api/demo/file
# 保存为图片；需确保项目下存在 ./files/demo.png
```

---

### 3.10 模板文件（template）

**路径**：`GET /api/demo/template/{name}`  

**作用**：**responses[].template** 指定一个本地文件路径，读取文件内容后对其中 `{{...}}` 做变量替换再返回。本示例使用 **extract** 从 query 提取 `uid`，模板文件中有 `{{param.name}}`、`{{query.uid}}`、`{{extract.userId}}`。

**cURL**：

```bash
curl -s "http://127.0.0.1:8080/api/demo/template/bob?uid=query-123"
# 返回 examples/payloads/welcome.json 经替换后的内容（含 param.name=bob, query.uid, extract.uid 等）
```

---

### 3.11 body 从文件读取（@filename）

**路径**：`POST /api/demo/body-at-file`  

**作用**：**responses[].body** 若为以 `@` 开头的路径，则从该文件读取内容并做变量替换后作为响应 body。本示例用 `@examples/payloads/welcome.json`，可配合 POST body 得到 `body.name` 等。

**cURL**：

```bash
curl -s -X POST "http://127.0.0.1:8080/api/demo/body-at-file?uid=1" \
  -H "Content-Type: application/json" \
  -d '{"name":"file-alice"}'
# 返回 welcome.json 内容，其中 body.name、query.uid 等被替换
```

---

### 3.12 表单与文件上传（form.*）

**路径**：`POST /api/demo/form`  

**作用**：对 `multipart/form-data` 或 `application/x-www-form-urlencoded` 自动解析，注入 **form.xxx**、**form.xxx.filename**、**form.xxx.size**，可在响应中引用。

**cURL**：

```bash
# 表单
curl -s -X POST http://127.0.0.1:8080/api/demo/form \
  -F "username=alice" \
  -F "avatar=@./files/demo.png"
# 返回 username、file_name、file_size 等
```

---

### 3.13 method: ANY

**路径**：`ANY /api/demo/any`  

**作用**：**method** 为 `ANY` 时不限制 HTTP 方法，任意方法均可命中同一路由。

**cURL**：

```bash
curl -s http://127.0.0.1:8080/api/demo/any
curl -s -X POST http://127.0.0.1:8080/api/demo/any
curl -s -X DELETE http://127.0.0.1:8080/api/demo/any
# 均返回同一响应
```

---

## 4. websockets（WebSocket Mock）

**作用**：按 **path** 提供 WebSocket 端点，**match** 在建立连接前校验 query/headers（支持正则）；**script** 按顺序执行：send（可含模板变量）、await（等客户端消息，支持正则或 JSON 等值）、delay_ms、timeout_ms、close。

**本示例**：path `/ws/demo/{room}`，要求 query 带 `token`、Header `Sec-WebSocket-Protocol: demo`；剧本：欢迎 → 延迟 500ms 发 ping → 等待 type=pong → 发 ok → 关闭。

**cURL**（需支持 WebSocket；以下为概念性，实际可用浏览器或 `websocat`）：

```bash
# 使用 websocat（若已安装）示例
websocat "ws://127.0.0.1:8080/ws/demo/room1?token=abc" -H "Sec-WebSocket-Protocol: demo"
# 连接后先收到 welcome、ping；发送 {"type":"pong"} 后收到 ok 并关闭
```

**浏览器或 Postman**：建立 WebSocket 连接至 `ws://127.0.0.1:8080/ws/demo/room1?token=abc`，子协议选 `demo`，按剧本收发消息即可验证。

---

## 5. sse（Server-Sent Events）

**作用**：按 **path** 提供 SSE 流；可配置 **method**、**match**、**headers**、**status**、**cookies**；**events** 为事件列表，每条可含 id、event、data、retry、delay_ms；**repeat** 为是否循环推送。

**本示例**：path `/sse/demo/{topic}`，要求 query 带 `client`；响应头 X-Topic 为路径参数；设置 Cookie；依次发送 hello、ping、done。

**cURL**：

```bash
curl -s -N "http://127.0.0.1:8080/sse/demo/news?client=curl" \
  -H "Accept: text/event-stream"
# 观察事件流：id:1 event:hello data:topic=news；event:ping；data:done 等
```

---

## 6. 功能与配置对照速查

| 功能 | 配置位置 | 说明 |
|------|----------|------|
| 多端口/HTTPS | listen | host, port, protocols, cert_file, key_file |
| 静态目录 | static | mount, dir, download, index_files, allow_methods, headers |
| 路径参数 | routes[].path | `/api/foo/{id}` → `param.id` |
| 路由级条件 | routes[].when | 不满足返回 403 |
| 请求预匹配 | routes[].match | headers/query/body 正则或等值，不满足 404 |
| 变量提取 | routes[].extract | from: body/query/header, rules 点路径 → extract.* |
| 响应分支 | routes[].responses[].when | 等值或 >、<、~、contains |
| 状态/头/Cookie/延迟 | responses[].status/headers/cookies/delay_ms | 均支持模板变量 |
| 强类型占位符 | body 中 | `{{@int:key}}`、`{{@float:key}}`、`{{@bool:key}}` |
| 响应为文件 | responses[].file | 本地路径，直接作为响应体 |
| 模板文件 | responses[].template | 读取文件后做变量替换 |
| body 从文件 | responses[].body | 值以 `@` 开头则读文件并替换 |
| 表单变量 | 自动 | form.xxx、form.xxx.filename、form.xxx.size |
| 任意方法 | routes[].method | `ANY` |
| WebSocket | websockets[] | path, match, script: send/await/delay_ms/timeout_ms/close |
| SSE | sse[] | path, method, match, headers, status, cookies, events, repeat |

---

mock-demo-02.json 请求

curl --location --request POST 'http://127.0.0.1:8080/user/demo/8?age=88' \
--header 'Token-Value: req-token-data' \
--header 'Content-Type: application/json' \
--header 'Cookie: test-body=zhangsan-data-data; test-helder=req-token-data-data; test-param=8-data; test-query=88-data' \
--data-raw '{
    "root": {
        "users": [
            {
                "name": "张三",
                "info": {
                    "data": "zhangsan-data"
                },
                "phones": [
                    "13311111111",
                    "13311111112"
                ]
            },
            {
                "name": "李四",
                "info": {
                    "data": "lisi-data"
                },
                "phones": [
                    "18811111111",
                    "18811111112"
                ]
            }
        ]
    },
    "items": [
        {
            "id": 10,
            "version": 1
        },
        {
            "id": 12,
            "version": 2
        }
    ],
    "desc": "user_data"
}'





使用本演示配置时，请在项目根目录执行并确保存在 `./files/demo.png`、`./files/index.html` 以及 `examples/payloads/welcome.json`，以便静态与模板相关示例均可正常返回。
