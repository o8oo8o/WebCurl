# 🚀 WebCurl - 极简网页版API调试及Mock神器

> **⚡ 一个文件搞定所有API请求和Mock服务需求 | 🎯 轻量级选择 | 🔒 数据本地化，安全无忧**

[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS%20%7C%20ARM-lightgrey.svg)]()

> **联系我: QQ 774309635**

## ✨ 为什么选择 WebCurl？

还在为API调试工具而烦恼吗？传统工具太臃肿？curl命令行太复杂？试试 **WebCurl** 吧！

🎉 **一个8MB的二进制文件 = 完整的API测试和Mock解决方案**

💡 **源码极简**：仅几个文件实现完整功能

### 🌟 核心优势对比

| 特性 | WebCurl | PostXXX | curl |
|------|---------|---------|------|
| **安装复杂度** | ⭐ 一个文件 | ⭐⭐⭐ 需要安装 | ⭐⭐ 命令行 |
| **跨域支持** | ✅ 完美解决 | ✅ 原生支持 | ✅ 原生支持 |
| **文件大小** | 8MB        | 200MB+      | 系统自带 |
| **离线使用** | ✅ 完全离线 | ❌ 需要登录 | ✅ 完全离线 |
| **数据安全** | ✅ 本地存储 | ❌ 云端同步 | ✅ 本地存储 |
| **信创兼容** | ✅ 完美支持 | ❌ 有限支持 | ✅ 完美支持 |
| **IPv6支持** | ✅ 完美支持 | ✅ 支持 | ✅ 原生支持 |
| **源码简洁** | ✅ 仅4个文件 | ❌ 复杂项目 | ❌ 复杂项目 |
| **实时通信** | ✅ WebSocket+SSE | ❌ 仅HTTP | ❌ 仅HTTP |
| **调试接口** | ✅ 内置EchoServer | ❌ 需额外工具 | ❌ 需额外工具 |
| **Mock服务** | ✅ 支持自定义 | ❌ 需额外工具 | ❌ 需额外工具 |

## 📖 简介

本项目是一个极致轻量、跨平台、无依赖的 HTTP 请求转发与调试工具，**本质上就是一个网页版的API测试及Mock调试工具**，适合接口开发、调试、测试等多种场景。

- **前端**：纯原生 HTML+JS+CSS，无任何第三方库或依赖，开箱即用，加载速度极快。
- **后端**：仅使用 Golang 标准库，无任何第三方依赖，安全可靠。
- **源码极简**：整个项目仅包含4个文件，代码结构清晰，易于理解和维护。
- **产物**：编译后仅有一个约 8M 的单一二进制文件（含前端页面），无需安装、无需环境、无需依赖，直接运行。
- **平台支持**：支持 Windows、Linux、MacOS、ARM、x86_64、信创（国产芯片/操作系统）等主流及国产平台，真正做到"一次编译，到处运行"。
- **网络支持**：完美支持 IPv4 和 IPv6 网络协议，适应各种网络环境。
- **实时通信**：原生支持 WebSocket 和 SSE（Server-Sent Events），满足实时数据推送需求。
- **内置调试服务**：集成强大的EchoServer，提供完整的请求回显和响应控制功能。
- **适用场景**：接口联调、API 测试、前端跨域调试、信创环境接口测试、离线/内网环境接口调试等。
- **数据本地化存储,保障安全**：所有接口信息、历史记录、变量、全局头等均仅存储于本地浏览器（localStorage），不会同步到云端或外部服务器，保障接口数据的私密性与安全性，适合企业内网、敏感环境使用。

**主要用途**：API 测试与调试,替代某些需要登录才能使用工具(xxxxMan,xxxFox)

- 支持多种请求体格式（form-data、x-www-form-urlencoded、json、text、xml、binary）
- 支持文件上传、下载
- 支持请求重试、超时、SSL 验证、重定向等高级选项
- 支持 WebSocket 和 SSE（Server-Sent Events）实时通信
- 内置美观易用的前端页面，支持接口历史、变量、全局头、接口集合管理
- 支持命令行参数自定义监听端口、静态目录、日志、SSL 等
- **内置EchoServer调试服务**：提供完整的请求回显、响应控制、流式通信功能

---

![演示截图](https://gitee.com/o8oo8o/public/raw/master/webcurl/20260217_001.jpg)

---

![演示截图](https://gitee.com/o8oo8o/public/raw/master/webcurl/20260217_002.jpg)

---

![演示截图](https://gitee.com/o8oo8o/public/raw/master/webcurl/20260217_003.jpg)

---

### 打赏我：
* **每一个开源项目的背后，都有一群默默付出、充满激情的开发者。他们用自己的业余时间，不断地优化代码、修复bug、撰写文档，只为让项目变得更好。如果您觉得我的项目对您有所帮助，如果您认可我的努力和付出，那么请考虑给予我一点小小的打赏，友情提示:打赏不退，怕被媳妇查到大额支出🤡，如果需要技术支持，需要收费哦**
<br/>
<br/>

![打赏二维码](https://gitee.com/o8oo8o/public/raw/master/pay.png)

[项目推荐: https://github.com/o8oo8o/WebSSH 一个网页版的SSH管理工具](https://github.com/o8oo8o/WebSSH "一个网页版的SSH管理工具")

<br/>


## 🛠️ 功能特性

### 🔥 核心功能
- **🌐 网页版 体验**：无需安装客户端，浏览器即用，界面美观，功能丰富。
- **🔄 HTTP 请求转发**：前端通过 `/api/forward` 接口将请求参数提交给后端，后端代为转发并返回结果，突破浏览器跨域限制。
- **支持 HTTP CONNECT 代理隧道**：支持 HTTP CONNECT 方法，可作为 HTTPS/SSH 等协议的代理隧道，适用于 curl、ssh、ncat 等工具的代理转发。
- **📁 多种请求体支持**：支持 `form-data`（含多文件上传）、`x-www-form-urlencoded`、`json`、`text`、`xml`、`binary`。
- **🔧 请求头自定义**：支持自定义任意请求头。
- **📤 文件上传/下载**：支持多文件上传，响应内容可直接下载。
- **🔄 请求重试与超时**：可配置重试次数、重试间隔、超时时间。
- **🔒 SSL 验证与重定向**：可选择是否校验 SSL 证书、是否自动跟随重定向。
- **📚 前端功能丰富**：接口历史、接口集合、变量替换、全局请求头、导入导出等。
- **⚙️ 命令行灵活配置**：支持自定义监听地址、端口、静态目录、日志、SSL 证书等。
- **⚡ 极致轻量**：单一二进制文件，体积仅约 10M，部署、迁移、分发极其方便。
- **💾 无依赖、易运维**：无需数据库、无需外部依赖，直接运行。
- **🖥️ 跨平台/信创兼容**：支持主流操作系统及国产软硬件平台，适合信创环境、内网、离线等特殊场景。
- **🌐 网络协议支持**：完美支持 IPv4 和 IPv6 网络协议，适应各种网络环境。
- **🔌 实时通信支持**：原生支持 WebSocket 和 SSE（Server-Sent Events），满足实时数据推送需求。

### 🎯 EchoServer 调试服务
- **🔄 智能请求回显**：自动解析并回显请求的URL、方法、请求头、请求体（文本、表单、文件、二进制等）。
- **🎛️ 灵活响应控制**：支持通过自定义请求头或URL参数灵活控制响应内容和行为。
- **📊 多种响应格式**：支持JSON、XML、Text等多种响应格式。
- **⏱️ 响应延迟控制**：可自定义响应延迟时间，模拟网络延迟场景。
- **📥 下载响应控制**：支持将响应内容作为文件下载。
- **🔌 流式通信支持**：SSE和WebSocket接口支持流式数据推送。
- **🎯 自定义数据队列**：支持预设响应数据，实现自定义流式推送。
- **🛡️ 健壮性保障**：内置panic恢复机制，防止服务崩溃。

### 🌐 静态文件服务器
- **📁 完整文件服务**：类似Nginx的静态文件服务器功能，支持所有常见文件类型。
- **🎨 丰富MIME支持**：自动识别HTML、CSS、JS、图片、音频、视频、字体等文件类型。
- **🔒 安全防护**：防止路径遍历攻击，确保文件访问安全。
- **⚡ 高性能**：支持大文件传输，内置缓存控制。
- **🌍 CORS支持**：内置跨域资源共享支持，适合前端开发。
- **📱 移动友好**：支持移动设备访问，响应式设计。



### 🌍 Mock服务

- **支持 Web 配置**：内置 Admin 控制台（默认 `/mock/`），在浏览器中拉取、编辑、格式化 `mock.json`，无需改本地文件即可改配置。
- **支持 Web 热重载**：在 Admin 中提交配置后，服务将新 JSON 写入文件并热重启 Mock 服务，无需手动重启进程。
- **支持 Web 启停控制**：通过 Admin 的 Start / Stop / Restart 控制 Mock 服务生命周期，Admin 自身常驻，Mock 停止后仍可管理。
- **纯 JSON 配置**：所有 Mock 行为由一份 `mock.json` 定义，无代码即可增删路由、改响应、挂静态资源与 WebSocket/SSE。
- **多端口多协议监听**：`listen` 支持多组 host/port，每组可配 `http` 与 `https`，并支持 `cert_file`/`key_file` 配置 TLS。
- **REST 路径参数**：路由 path 支持 gorilla/mux 风格（如 `/api/user/{id}`），路径参数自动注入为 `param.*` 供模板与条件使用。
- **请求预匹配（match）**：可按 headers / query / body 配置 match 条件（headers/query 支持正则，body 支持点路径与正则），全部满足才命中路由，否则 404。
- **路由级与响应级 when**：路由可配 `when` 不满足则 403；响应可配多条 `when` 分支，按顺序匹配选一条返回，实现条件分流。
- **when 表达式**：when 的 value 支持等值或操作符前缀：`=`、`!=`、`>`、`<`、`~`（正则）、`contains`，可写如 `"query.age": ">18"`、`"header.X-Role": "~^admin$"`。
- **变量提取（extract）**：从 body/query/header 按点路径提取字段到 `extract.*`，供 when、响应 body/headers/cookies、模板统一使用。
- **多响应分支**：单路由下可配置多条 response，每条可有自己的 when、status、headers、cookies、body、file、delay_ms，按 when 顺序命中即返回。
- **模板变量**：响应 body、headers、cookies、file 路径、template 内容中支持 `{{param.xxx}}`、`{{query.xxx}}`、`{{header.xxx}}`、`{{body.xxx}}`、`{{form.xxx}}`、`{{extract.xxx}}` 等命名空间。
- **强类型占位符**：支持 `{{@int:key}}`、`{{@float:key}}`、`{{@bool:key}}`，在 JSON 响应中输出数字或布尔类型而非字符串。
- **模板文件（@filename）**：body 或 template 可写 `@payloads/xxx.json`，从本地文件读取内容并做变量替换后返回，便于维护大块响应。
- **响应直接回文件**：`responses[].file` 可指定本地文件路径（可含模板变量），直接将文件内容作为 HTTP 响应体返回。
- **响应延迟（delay_ms）**：可为单条 response 配置毫秒级延迟，用于模拟慢接口或超时场景。
- **文件下载限速（speed_kbps）**：可为文件下载配置速率限制（单位 KB/s），模拟慢速网络环境。
- **缓冲式下载（buffered）**：支持缓冲式下载模式，先读取整个文件到内存再发送，适用于需要完整响应体的场景。
- **响应重定向**：通过 `status: 301/302` + `headers.Location` 实现重定向，模拟页面跳转场景。
- **响应压缩（compress）**：支持 gzip/deflate 压缩响应，可配置 `auto` 根据客户端 Accept-Encoding 自动选择。
- **分块传输（chunks）**：支持配置分块发送响应体，每块可单独设置延迟，模拟流式 API。
- **计数器模式（counter）**：支持按请求次数返回不同响应，模拟重试场景、服务恢复场景。
- **概率响应（probability）**：支持按概率权重随机返回响应，模拟不稳定服务、A/B 测试。
- **请求日志持久化（log）**：支持将请求日志持久化到文件，支持日志轮转和格式配置。
- **响应 Cookie**：支持在 response 中配置 cookies 数组（name/value/path/domain/expires/max_age/secure/http_only/same_site），值支持模板变量。
- **静态资源托管**：`static` 可将 URL 前缀映射到本地目录，支持自定义 headers、allow_methods、download 模式（Content-Disposition: attachment）。
- **CORS 预检兜底**：对 OPTIONS 请求做统一 CORS 头兜底，便于前端跨域调用 Mock。
- **表单与文件上传**：自动解析 `multipart/form-data` 与 `application/x-www-form-urlencoded`，注入 `form.xxx` 及 `form.xxx.filename`/`form.xxx.size`，可在 when 与模板中使用。
- **WebSocket Mock**：可配置 websockets 数组，path 支持路径参数，按 script 剧本顺序执行 send、await（正则或 JSON 等值）、delay_ms、timeout_ms、close，消息内容支持模板变量。
- **SSE（Server-Sent Events）**：可配置 sse 数组，支持 path/method/match/headers/status/cookies，events 可配 id/event/data/retry/delay_ms，data 支持模板，可选 repeat 循环推送。
- **无配置文件启动**：若 `mock.json` 不存在，以空配置 `{}` 启动，仅开放 Admin，便于首次在 Web 中编辑并保存配置。



### 🧰 常用工具（WebTools 工具箱）

访问 `http://localhost:4444/tool` 即可使用以下工具：

#### 📝 文本/编码类
- **JWT解析**：一键解析 JWT Token，查看 Header 和 Payload 信息
- **UUID生成**：批量生成标准 UUID，支持一键复制
- **时间戳转换**：时间戳与日期时间互转，支持秒/毫秒
- **Base64编解码**：文本编码/解码，支持文件转Base64、Base64转文件下载
- **URL编解码**：URL编码/解码，支持URL参数解析
- **正则表达式测试器**：实时匹配测试，支持 g/i/m/s 标志，显示捕获组

#### 🔐 加密/安全类
- **Hash计算**：支持文本和文件的 SHA-256/SHA-1/SHA-384/SHA-512 哈希计算
- **对称加密/解密**：
  - 支持 AES-GCM/CBC/CTR 三种模式
  - 支持 128/192/256 位密钥长度
  - 支持文本和文件加密/解密
- **RSA 密钥生成**：生成 2048/4096 位公私钥对（PEM格式）
- **RSA-OAEP 加密/解密**：公钥加密、私钥解密，支持文本和小文件
- **HMAC 消息认证码**：支持 SHA-256/384/512，生成和验证消息认证码
- **数字签名**：
  - 支持 RSA-PSS、RSASSA-PKCS1-v1_5、ECDSA、Ed25519
  - 生成密钥对、签名、验证
- **密钥交换**：ECDH P-256/384/521、X25519，双方协商共享密钥
- **密钥派生**：PBKDF2/HKDF，从密码派生加密密钥
- **Token生成器**：自定义长度和字符类型，生成随机 Token

#### 📊 数据格式类
- **JSON格式化**：JSON美化、压缩、转义/反转义

#### 🎨 图像/多媒体类
- **图片处理**：
  - 图片压缩（可调质量，支持 JPEG/PNG/WebP）
  - 尺寸调整（支持保持宽高比）
  - 图片裁剪（自定义区域）
- **录屏录像**：
  - 屏幕录制（支持系统音频）
  - 摄像头录像（支持选择设备）
  - 录制列表管理（播放/下载/删除）

#### 🎨 其他工具
- **颜色转换器**：HEX/RGB/HSL 颜色互转
- **客户端信息**：
  - 浏览器信息（UA、平台、语言、硬件并发数等）
  - 屏幕信息（分辨率、色深、像素比）
  - 网络状态（网络类型、下行速度、RTT延迟）
  - 媒体设备（摄像头、麦克风、扬声器）
  - 电池状态（电量、充电状态）
- **服务端信息**：
  - 时间信息（服务器时间、客户端时间、时间差异）
  - 操作系统（类型、架构、家族）
  - Go运行时（版本、Goroutines、GC状态）
  - CPU信息（核心数、字节序）
  - 系统内存（总内存、可用内存、使用率）
  - 网络接口（所有网卡信息、IP地址）
  - 进程信息（PID、工作目录、执行路径）
  - 用户信息（UID、GID、用户名）
  - 环境变量（所有环境变量列表）


---

## 🚀 快速开始

### 1️⃣ 编译 & 运行（30秒搞定）

**源码结构极简**：
```
WebCurl/
├── index.html    # 前端界面 WebCurl（纯原生HTML+JS+CSS）
├── main.go       # 后端服务 WebCurl
├── mock.html     # 前端界面 WebMock（纯原生HTML+JS+CSS）
├── mock.go       # 后端服务 WebMock
├── tool.html     # 前端界面 WebTools（纯原生HTML+JS+CSS）
├── tool.go       # 后端服务 WebTools
├── ws.go         # 后端服务 WebSocket
└── mux.go        # 后端服务 Mux路由
```

```bash
# 编译
go build
# 也可以使用 sh build.sh 命令

# 运行（默认 0.0.0.0:4444，内嵌前端页面）
./WebCurl

# 浏览器访问
http://localhost:4444
```

> **注** ：构建所有平台可执行文件，请使用 `sh build.sh all` 命令，构建完成后在build目录下查找对应平台可执行文件。

### 2️⃣ 命令行参数

| 参数                | 说明                                   | 默认值                |
|---------------------|----------------------------------------|-----------------------|
| `--host`            | 监听地址                               | 0.0.0.0               |
| `--port`            | 监听端口                               | 4444                  |
| `--webroot`         | 静态文件根目录（为空用内嵌 index.html）| 空                    |
| `--daemon`          | 后台运行（支持 Windows/Linux/Mac）     | false                 |
| `--echo-server`     | 是否开启EchoServer调试服务              | true                  |
| `--log-level`       | 日志级别（error, info, debug）         | error                 |
| `--log-file`        | 日志文件路径                           | post_api.log          |
| `--log-size`        | 日志文件大小限制（K/M/G）              | 100M                  |
| `--ssl-cert`        | SSL 证书文件路径                       | ssl_cert.pem          |
| `--ssl-cert-key`    | SSL 证书密钥路径                       | ssl_cert.key          |
| `--upload-dir`      | form-data上传文件保存目录（为空仅透传） | 空                    |
| `--stdout-log`      | 是否在控制台打印日志，true为同时输出到控制台和文件，false仅输出到文件 | true                  |

#### 启动示例

```bash
# 默认（0.0.0.0:4444，内嵌index.html，开启EchoServer）
./WebCurl

# 指定端口和host
./WebCurl --host 127.0.0.1 --port 8888

# 指定静态目录
./WebCurl --webroot /tmp/www

# 控制日志是否输出到控制台
./WebCurl --stdout-log=false

# 开启静态文件服务器模式（指定目录）
./WebCurl --webroot /mnt/webroot

# 关闭EchoServer调试服务
./WebCurl --echo-server=false

# 后台运行（Linux/MacOS/Windows）
./WebCurl --daemon

# 组合
./WebCurl --host 0.0.0.0 --port 9000 --webroot /tmp/www --daemon --stdout-log=false

```

### 🐳 容器化部署 · 极速上云

### 🚀 一键 Docker 部署

WebCurl 天生适合容器化，支持 Docker/Kubernetes 等主流云原生环境，轻松实现弹性扩展与自动化运维！

#### 1️⃣ Docker 镜像构建与运行

```bash
# 构建镜像
docker build -t webcurl:2.2 .

# 运行容器（默认 0.0.0.0:4444）
docker run -d -p:4444:4444 --name webcurl  webcurl:2.2

# 指定数据/静态目录挂载
docker run -d --name webcurl -p 4444:4444 -v /usr/share/nginx/html/:/usr/local/WebCurl/webroot webcurl:2.2 /usr/local/WebCurl/WebCurl --webroot=/usr/local/WebCurl/webroot
```

#### 2️⃣ Kubernetes 极速部署

WebCurl 完美兼容 K8S，支持无状态部署、弹性伸缩、健康检查等企业级需求。

**示例 Deployment 配置：**

```yaml
######################################
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webcurl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webcurl
  template:
    metadata:
      labels:
        app: webcurl
    spec:
      containers:
      - name: webcurl
        image: webcurl:2.2
        ports:
        - containerPort: 4444
#        args: ["/usr/local/WebCurl/WebCurl","--echo-server=true","--port=4444"]
---
apiVersion: v1
kind: Service
metadata:
  name: webcurl
spec:
  type: NodePort
  ports:
    - port: 4444
      targetPort: 4444
      nodePort: 30444
  selector:
    app: webcurl
######################################
```

> 只需 `kubectl apply -f webcurl.yaml`，即可在 K8s 集群中弹性部署 WebCurl！

### 🌈 容器化优势

- **极致轻量**：单一二进制+极简镜像，启动快、资源占用低
- **云原生友好**：无状态设计，天然适配 K8S、Docker、OpenShift 等平台
- **弹性扩展**：支持副本横向扩展，轻松应对高并发
- **自动化运维**：支持健康检查、日志挂载、配置注入
- **一键迁移**：镜像即服务，随时随地部署到任意云/集群/本地

---

**WebCurl，让 API 调试与测试像部署静态网站一样简单，轻松上云，随时随地，安全高效！**

---

## 🎯 适用场景

### 💼 企业级应用
- **内网环境**：数据不出内网，安全可控
- **信创环境**：完美支持国产芯片和操作系统
- **离线部署**：无网络环境也能正常使用
- **团队协作**：配置可导出分享，便于团队统一

### 👨‍💻 开发者日常
- **接口联调**：前后端接口调试必备
- **API测试**：自动化测试前的接口验证
- **跨域调试**：完美解决前端跨域问题
- **文件上传测试**：支持多文件上传测试
- **接口调试**：EchoServer提供完整的请求回显和响应控制

### 🔧 运维测试
- **接口监控**：定期测试关键接口状态
- **性能测试**：支持重试和超时配置
- **SSL测试**：SSL证书验证测试
- **重定向测试**：自动跟随重定向测试
- **实时通信测试**：WebSocket连接和SSE事件流测试
- **网络延迟模拟**：EchoServer支持响应延迟控制

### 🌐 静态文件服务
- **网站托管**：快速部署静态网站，支持HTML、CSS、JS等
- **文件分享**：企业内部文件分享和下载服务
- **开发环境**：前端开发时的本地文件服务器
- **文档服务**：API文档、技术文档的在线访问
- **资源托管**：图片、视频、音频等多媒体资源托管
- **CDN替代**：小型项目的CDN服务替代方案

---

## 📖 前端使用说明

### 1. 访问页面

启动后，浏览器访问 `http://localhost:4444`，即可进入 WebCurl 风格的调试页面。
启动后，浏览器访问 `http://localhost:4444/tool`，即可进入 WebTools 页面, 提供一些常用的工具。
启动后，浏览器访问 `http://localhost:4444/mock`，即可进入 Mock 服务器json配置页面，详细配置见下文。
启动后，浏览器访问 `http://localhost:4444/doc`，即可下载 WebCurl 文档readme.md文件。

### 2. 请求模式自动切换

- 前端会自动请求 `/api/mode`，如返回 `{ "mode": "proxy" }`，则所有请求将通过后端 `/api/forward` 转发，解决跨域问题。
- 否则，前端直接用 fetch 发起请求。

### 3. 发送请求（代理模式）

- 支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS 等方法
- 支持多种请求体格式、文件上传、请求头自定义
- 支持变量替换、全局头、接口集合、历史记录等
- 支持请求参数、重试、超时、SSL 验证、重定向等高级选项

---

## 🔧 后端接口说明

### 1. `/api/forward`（POST）

用于前端通过 form-data 方式提交请求参数，由后端转发到目标接口。

#### 支持的 form-data 字段

| 字段名         | 类型/说明         | 示例/说明                                         |
|----------------|------------------|------------------------------------------------|
| url            | string           | 目标接口地址                                     |
| time_out       | int              | 超时时间（秒），0为不超时                          |
| retry_count    | int              | 重试次数，0为不重试                               |
| retry_delay    | int              | 重试间隔（秒），0为无间隔                          |
| method         | string           | 请求方法，默认 GET                               |
| body_type      | string           | 请求体类型，见下表                                |
| headers        | json字符串        | `[{"name":"X-Token","value":"abc"}]`           |
| file_info      | json字符串        | `[{"field_name":"files","file_name":"a.txt"}]` |
| files          | 文件              | 支持多文件上传                                   |
| body           | string           | 请求体内容（json/xml/text等）                     |
| verify_ssl     | Y/N              | 是否校验SSL，默认Y                               |
| follow_redirect| Y/N              | 是否自动跟随重定向，默认Y                          |
| stream         | boolean          | 是否流式响应，默认false                           |

#### body_type 支持

- `form-data`：多文件上传，表单参数
- `x-www-form-urlencoded`：标准表单
- `json`：application/json
- `text`：text/plain
- `xml`：application/xml
- `binary`：二进制文件上传
- `none`：无请求体

### 2. `/api/mode`（GET）

返回当前后端模式，前端据此判断是否需要通过后端转发。

**返回示例**

```json
{ "mode": "proxy" }
```

### 3. EchoServer 调试接口

#### 3.1 `/api/echo`（所有HTTP方法）

**功能**：智能请求回显，支持灵活的响应控制。

**特性**：
- 支持所有HTTP方法（GET、POST、PUT、DELETE、PATCH、HEAD、OPTIONS等）
- 自动解析并回显请求的URL、方法、请求头、请求体
- 支持文本、表单、文件上传、二进制等多种请求体类型
- 支持通过自定义请求头或URL参数灵活控制响应

**响应控制参数**：

| 请求头                  | 作用                                                | 示例值                         |
|-------------------------|---------------------------------------------------|--------------------------------|
| X-Response-Status-Code  | 控制HTTP响应状态码                                | 201、404、500                  |
| X-Response-Location     | 设置响应Location头                               | https://www.xx.com             |
| X-Response-Headers      | 批量设置响应头（JSON字符串，键值对）              | {"X-Foo":"Bar"}              |
| X-Response-Type         | 控制响应体格式（json/xml/text）                 | json、xml、text                      |
| X-Response-Sleep        | 控制响应延迟（单位：毫秒）                       | 200、1000                      |
| X-Response-Body         | 指定Base64编码的响应body内容（优先级最高）        | `eyJtc2ciOiJoZWxsbyJ9`         |
| X-Response-Download     | 控制响应为下载，指定下载文件名                     | data.txt、result.json          |

**参数传递方式**：
- 支持请求头方式：`curl -H "X-Response-Status-Code: 202" http://localhost:4444/api/echo`
- 支持URL参数方式：`curl "http://localhost:4444/api/echo?X-Response-Status-Code=202"`
- **请求头优先级高于URL参数**

**基本用法示例**：
```bash
# 普通请求
curl -X GET http://localhost:4444/api/echo
curl -X POST -d 'Hello World' http://localhost:4444/api/echo

# 表单与文件上传
curl -X POST -F 'text=Hello' -F 'file=@/path/to/file' http://localhost:4444/api/echo

# 控制响应状态码
curl -H "X-Response-Status-Code: 202" http://localhost:4444/api/echo

# 控制响应类型
curl -H "X-Response-Type: xml" http://localhost:4444/api/echo
curl -H "X-Response-Type: text" -d "a simple text body" http://localhost:4444/api/echo

# 控制响应延迟
curl -H "X-Response-Sleep: 500" http://localhost:4444/api/echo

# 自定义响应体（Base64编码）
curl -H "X-Response-Body: eyJtc2ciOiJoZWxsbyJ9" http://localhost:4444/api/echo

# 下载响应内容
curl -H "X-Response-Download: data.txt" http://localhost:4444/api/echo -OJ
```

**响应结构**：
```json
{
  "method": "POST",
  "url": "http://localhost:4444/api/echo",
  "headers": [
    {"key": "Content-Type", "value": "application/json"},
    ...
  ],
  "body": "Hello World"
}
```

#### 3.2 `/api/sse/echo`（SSE流式接口）

**功能**：Server-Sent Events流式回显，适合前端流式消费。

**特性**：
- 支持所有HTTP方法
- 返回SSE流，每条消息为JSON
- 支持自定义响应参数
- 支持流式数据推送

**额外参数**：
- `X-Response-Sse-Count`：SSE消息条数，默认100
- `X-Response-Sleep`：每条SSE消息间隔（毫秒），默认500

**用法示例**：
```bash
# 基本SSE请求
curl http://localhost:4444/api/sse/echo

# POST带body
curl -X POST -d 'Hello SSE' http://localhost:4444/api/sse/echo

# 控制SSE消息条数和间隔
curl -H "X-Response-Sse-Count: 5" -H "X-Response-Sleep: 1000" http://localhost:4444/api/sse/echo

# SSE上传文件
curl -X POST -F 'file=@/path/to/file' http://localhost:4444/api/sse/echo
```

#### 3.3 `/api/ws/echo`（WebSocket接口）

**功能**：WebSocket流式回显，适合前端WebSocket流式消费。

**特性**：
- 支持WebSocket协议，升级连接后推送多条消息
- 支持所有HTTP方法（WebSocket仅升级GET，其他方法通过header传递）
- 支持自定义响应参数

**额外参数**：
- `X-Response-Websocket-Count`：WebSocket消息条数，默认100
- `X-Response-Sleep`：每条消息间隔（毫秒），默认500

**用法示例**：
```bash
# WebSocket基本请求（需WebSocket客户端）
wscat -c ws://localhost:4444/api/ws/echo

# 控制消息条数和间隔
wscat -c "ws://localhost:4444/api/ws/echo?X-Response-Websocket-Count=5&X-Response-Sleep=1000"

# WebSocket自定义响应内容（Base64）
wscat -c "ws://localhost:4444/api/ws/echo?X-Response-Body=eyJtc2ciOiJoZWxsbyB3cyJ9"
```

#### 3.4 自定义数据队列接口

**`POST /api/sse/set`**：设置SSE响应的消息队列
**`POST /api/ws/set`**：设置WebSocket响应的消息队列

**功能**：预设响应数据，实现自定义流式推送。

**请求体格式**：
```json
[
  {"value": {"v": 1, "data": "mydata"}},
  {"value": {"v": 2, "data": 123}},
  {"value": "mydata"},
  {"value": null},
  {"value": 123}
]
```

#### 3.5 响应模式控制

通过请求头 `X-Response-Mode` 控制SSE/WS响应行为：

- `default`（默认）：原有回显逻辑，自动回显请求内容
- `user`：从预设队列中依次取出value作为响应体
- `react`：连接建立后等待用户推送数据（WebSocket专用）

**用法示例**：
```bash
# 设置SSE队列
curl -X POST -H "Content-Type: application/json" \
  -d '[{"value":{"v":1,"data":"mydata"}}, {"value":{"v":2,"data":123}}]' \
  http://localhost:4444/api/sse/set

# SSE user模式消费
curl -H "X-Response-Mode: user" http://localhost:4444/api/sse/echo

# 设置WS队列
curl -X POST -H "Content-Type: application/json" \
  -d '[{"value":{"v":1,"data":"mydata"}}, {"value":{"v":2,"data":123}}]' \
  http://localhost:4444/api/ws/set

# WS user模式消费
wscat -c "ws://localhost:4444/api/ws/echo?X-Response-Mode=user"
```

### 4. HTTP CONNECT 代理隧道支持

**功能**：支持 HTTP CONNECT 方法，可作为 HTTPS/SSH 等协议的代理隧道。

- 可直接作为 curl、ssh、ncat 等工具的 HTTP 代理服务器。
- 通过 CONNECT 建立 TCP 隧道，支持 HTTPS、WebSocket、SSH 等协议的转发。
- 适合企业内网、开发测试等需要代理隧道的场景。

**用法示例**：

```bash
# curl 通过 HTTP 代理访问 HTTPS 站点
curl -k -x http://localhost:4444 https://www.example.com

# ssh 通过 HTTP 代理
ssh -o "ProxyCommand ncat --proxy 127.0.0.1:4444 --proxy-type http %h %p" user@host
```

- 该功能无需额外配置，服务启动后自动支持。
- 日志中会记录 CONNECT 隧道的建立与关闭。

---

## 🎨 前端高级功能

- **📊 接口历史**：自动保存最近 50 条请求历史，支持一键加载、导入导出、清空
- **📚 接口集合**：支持多集合管理，接口保存、导入导出、删除
- **🔧 变量管理**：支持变量定义与替换，便于环境切换
- **🎛️ 全局请求头**：支持全局头配置，自动合并到每次请求
- **⚙️ 请求配置**：支持 SSL 验证、重定向、超时、重试、缓存、mode、credentials、referrerPolicy 等高级 fetch 选项
- **💾 导入导出**：支持全部配置一键导入导出，便于迁移和备份
- **🪝 Hook脚本**：支持前置脚本和后置脚本，可在请求发送前和响应返回后执行自定义逻辑

---

## 🪝 Hook 脚本功能

Hook 脚本功能允许你在请求发送前（Pre-Request）和响应返回后（Post-Response）执行自定义 JavaScript 代码，实现动态修改请求参数、提取响应数据、自动保存变量等高级功能。

### 📍 入口位置

在请求区域点击 **"脚本"** 标签页，可以看到：
- **Pre-Request Hook（前置脚本）**：请求发送前执行
- **Post-Response Hook（后置脚本）**：响应返回后执行
- **控制台输出**：显示脚本执行日志

### 🔧 Pre-Request Hook（前置脚本）

前置脚本在请求发送前执行，可以动态修改请求参数。

#### 函数签名

```javascript
function preRequest(request) {
    // request 包含以下属性：
    // - url: 请求URL（可修改）
    // - method: 请求方法（可修改）
    // - headers: 请求头对象（可修改）
    // - body: 请求体（可修改）
    // - bodyType: 请求体类型
    // - settings: 请求设置
    // - variables: 当前所有变量（只读）
    // - utils: 工具函数集
    
    return request;  // 必须返回 request 对象
}
```

#### request 对象详解

| 属性 | 类型 | 可修改 | 说明 |
|------|------|--------|------|
| `url` | string | ✅ | 请求的完整URL |
| `method` | string | ✅ | HTTP方法：GET/POST/PUT/DELETE/PATCH等 |
| `headers` | object | ✅ | 请求头键值对对象 |
| `body` | string | ✅ | 请求体内容 |
| `bodyType` | string | ❌ | 请求体类型：none/json/text/xml/form/formdata/binary |
| `settings` | object | ✅ | 请求配置：timeout、retry_count等 |
| `variables` | object | ❌ | 当前所有启用的变量 |
| `utils` | object | ❌ | 工具函数集（详见下文） |

#### 使用示例

**示例1：动态添加时间戳签名**

```javascript
function preRequest(request) {
    const timestamp = Date.now();
    const nonce = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    
    // 添加签名相关请求头
    request.headers['X-Timestamp'] = timestamp;
    request.headers['X-Nonce'] = nonce;
    request.headers['X-Signature'] = 'your_sign_algorithm_here';
    
    request.utils.log('签名已生成');
    return request;
}
```

**示例2：动态Token注入**

```javascript
function preRequest(request) {
    // 从变量中获取token
    const token = request.utils.getVariable('auth_token');
    
    if (token) {
        request.headers['Authorization'] = 'Bearer ' + token;
        request.utils.log('已注入Token:', token.substring(0, 20) + '...');
    } else {
        request.utils.warn('未找到auth_token变量，请先登录');
    }
    
    return request;
}
```

**示例3：环境切换**

```javascript
function preRequest(request) {
    const env = request.utils.getVariable('current_env') || 'dev';
    
    const baseUrls = {
        dev: 'http://localhost:8080',
        test: 'http://test.example.com',
        prod: 'https://api.example.com'
    };
    
    const baseUrl = baseUrls[env] || baseUrls.dev;
    
    // 替换URL中的占位符
    request.url = request.url.replace('{{base_url}}', baseUrl);
    request.utils.log('当前环境:', env, 'BaseURL:', baseUrl);
    
    return request;
}
```

**示例4：修改请求体**

```javascript
function preRequest(request) {
    if (request.body && request.bodyType === 'json') {
        try {
            const body = JSON.parse(request.body);
            body.timestamp = Date.now();
            body.clientId = 'web-app';
            request.body = JSON.stringify(body);
            request.utils.log('请求体已修改');
        } catch (e) {
            request.utils.error('JSON解析失败:', e.message);
        }
    }
    return request;
}
```

---

### 📤 Post-Response Hook（后置脚本）

后置脚本在响应返回后执行，可以处理响应数据、提取变量等。

#### 函数签名

```javascript
function postResponse(response) {
    // response 包含以下属性：
    // - status: HTTP状态码（只读）
    // - statusText: 状态文本（只读）
    // - headers: 响应头对象（只读）
    // - body: 响应体字符串（可修改显示内容）
    // - duration: 响应耗时ms（只读）
    // - contentType: 内容类型（只读）
    // - json: JSON解析后的对象（只读，仅JSON响应时可用）
    // - utils: 工具函数集
    
    return response;  // 必须返回 response 对象
}
```

#### response 对象详解

| 属性 | 类型 | 可修改 | 说明 |
|------|------|--------|------|
| `status` | number | ❌ | HTTP状态码：200、404、500等 |
| `statusText` | string | ❌ | 状态文本：OK、Not Found等 |
| `headers` | object | ❌ | 响应头键值对对象 |
| `body` | string | ✅ | 响应体内容 |
| `duration` | number | ❌ | 响应耗时（毫秒） |
| `contentType` | string | ❌ | Content-Type响应头值 |
| `json` | object | ❌ | JSON解析后的对象（仅当响应是JSON时） |
| `utils` | object | ❌ | 工具函数集（详见下文） |

#### 使用示例

**示例1：自动提取并保存Token**

```javascript
function postResponse(response) {
    const utils = response.utils;
    
    // 检查响应是否成功
    if (response.status === 200 && response.json) {
        // 尝试从不同位置提取token
        const token = response.json.token || 
                      response.json.data?.token ||
                      response.json.access_token ||
                      response.json.result?.accessToken;
        
        if (token) {
            utils.setVariable('auth_token', token);
            utils.success('Token已提取并保存');
        }
    }
    
    // 检测token过期
    if (response.status === 401) {
        utils.warn('Token可能已过期，请重新登录');
        utils.setVariable('token_expired', 'true');
    }
    
    return response;
}
```

**示例2：响应日志记录**

```javascript
function postResponse(response) {
    const utils = response.utils;
    
    utils.info('=== 响应信息 ===');
    utils.info('状态码:', response.status);
    utils.info('状态文本:', response.statusText);
    utils.info('响应耗时:', response.duration, 'ms');
    utils.info('内容类型:', response.contentType);
    
    if (response.json) {
        utils.info('JSON数据:', JSON.stringify(response.json, null, 2));
    } else if (response.body) {
        utils.info('响应体长度:', response.body.length, '字符');
    }
    
    return response;
}
```

**示例3：自动保存响应字段**

```javascript
function postResponse(response) {
    const utils = response.utils;
    
    if (response.json && response.json.data) {
        const data = response.json.data;
        
        // 自动保存常用字段到变量
        const fieldsToSave = ['id', 'userId', 'userName', 'email', 'roleId'];
        
        fieldsToSave.forEach(field => {
            if (data[field] !== undefined) {
                utils.setVariable('last_' + field, data[field]);
            }
        });
        
        utils.success('已自动保存响应字段到变量');
    }
    
    return response;
}
```

**示例4：错误处理与重试标记**

```javascript
function postResponse(response) {
    const utils = response.utils;
    
    if (response.status >= 400) {
        utils.error('请求失败:', response.status);
        
        // 保存错误信息
        utils.setVariable('last_error_status', response.status);
        utils.setVariable('last_error_time', new Date().toISOString());
        
        if (response.json && response.json.message) {
            utils.error('错误信息:', response.json.message);
            utils.setVariable('last_error_msg', response.json.message);
        }
    } else {
        utils.success('请求成功');
        utils.setVariable('last_error_status', '');
    }
    
    return response;
}
```

---

### 🛠️ 工具函数集（utils）

Hook 脚本中可通过 `request.utils` 或 `response.utils` 访问工具函数集。

#### 日志函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `log(...args)` | 输出普通日志（蓝色） | `utils.log('消息')` |
| `info(...args)` | 输出信息日志（蓝色） | `utils.info('信息')` |
| `success(...args)` | 输出成功日志（绿色） | `utils.success('成功!')` |
| `warn(...args)` | 输出警告日志（黄色） | `utils.warn('警告')` |
| `error(...args)` | 输出错误日志（红色） | `utils.error('错误')` |

#### 变量操作函数

| 函数 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `setVariable(name, value)` | name: 变量名, value: 变量值 | void | 设置变量（自动刷新变量表格） |
| `getVariable(name)` | name: 变量名 | string\|undefined | 获取变量值（仅启用的变量） |
| `getAllVariables()` | 无 | object | 获取所有启用的变量 |

**变量操作示例：**

```javascript
// 设置变量
utils.setVariable('api_key', 'sk-xxx');
utils.setVariable('user_id', '12345');

// 获取变量
const apiKey = utils.getVariable('api_key');
const userId = utils.getVariable('user_id');

// 获取所有变量
const allVars = utils.getAllVariables();
// 返回: { api_key: 'sk-xxx', user_id: '12345', ... }
```

#### 全局请求头操作函数

| 函数 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `setGlobalHeader(name, value)` | name: 请求头名, value: 请求头值 | void | 设置全局请求头（自动刷新请求头表格） |
| `getGlobalHeader(name)` | name: 请求头名 | string\|undefined | 获取全局请求头值（仅启用的） |
| `getAllGlobalHeaders()` | 无 | object | 获取所有启用的全局请求头 |

**全局请求头操作示例：**

```javascript
// 设置全局请求头
utils.setGlobalHeader('Authorization', 'Bearer token_xxx');
utils.setGlobalHeader('X-API-Key', 'key_xxx');

// 获取全局请求头
const auth = utils.getGlobalHeader('Authorization');

// 获取所有全局请求头
const allHeaders = utils.getAllGlobalHeaders();
// 返回: { Authorization: 'Bearer token_xxx', ... }
```

---

### 📝 完整使用示例

#### 场景1：OAuth2 自动化认证

```javascript
// === Pre-Request Hook ===
function preRequest(request) {
    const utils = request.utils;
    const token = utils.getVariable('oauth_token');
    const tokenExpire = utils.getVariable('token_expire_time');
    const now = Date.now();
    
    // 检查token是否存在且未过期
    if (token && tokenExpire && now < parseInt(tokenExpire)) {
        request.headers['Authorization'] = 'Bearer ' + token;
        utils.log('使用缓存的Token');
    } else {
        utils.warn('Token不存在或已过期，需要重新获取');
        // 可以设置标记，让后续流程处理
        utils.setVariable('need_refresh_token', 'true');
    }
    
    return request;
}

// === Post-Response Hook ===
function postResponse(response) {
    const utils = response.utils;
    
    // 如果是登录接口，自动保存token
    if (response.json && response.json.access_token) {
        const token = response.json.access_token;
        const expiresIn = response.json.expires_in || 3600;
        
        utils.setVariable('oauth_token', token);
        utils.setVariable('token_expire_time', Date.now() + expiresIn * 1000);
        utils.success('Token已保存，有效期:', expiresIn, '秒');
    }
    
    // 如果返回401，清除token
    if (response.status === 401) {
        utils.setVariable('oauth_token', '');
        utils.setVariable('token_expire_time', '');
        utils.warn('Token已失效，请重新登录');
    }
    
    return response;
}
```

#### 场景2：API签名认证

```javascript
// === Pre-Request Hook ===
function preRequest(request) {
    const utils = request.utils;
    
    // 获取API密钥
    const appId = utils.getVariable('app_id') || 'your_app_id';
    const appSecret = utils.getVariable('app_secret') || 'your_app_secret';
    
    // 生成签名参数
    const timestamp = Date.now().toString();
    const nonce = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    
    // 简单签名示例（实际使用时建议使用更安全的算法）
    const signStr = appId + timestamp + nonce + appSecret;
    
    // 设置签名请求头
    request.headers['X-App-Id'] = appId;
    request.headers['X-Timestamp'] = timestamp;
    request.headers['X-Nonce'] = nonce;
    request.headers['X-Signature'] = signStr;  // 实际使用时应该用MD5/SHA256等
    
    utils.log('签名参数已生成');
    utils.log('AppId:', appId);
    utils.log('Timestamp:', timestamp);
    utils.log('Nonce:', nonce);
    
    return request;
}
```

#### 场景3：接口测试断言

```javascript
// === Post-Response Hook ===
function postResponse(response) {
    const utils = response.utils;
    let passCount = 0;
    let failCount = 0;
    
    // 断言函数
    function assert(condition, message) {
        if (condition) {
            utils.success('✓ ' + message);
            passCount++;
        } else {
            utils.error('✗ ' + message);
            failCount++;
        }
    }
    
    utils.info('===== 开始断言测试 =====');
    
    // 状态码断言
    assert(response.status === 200, `状态码应为200，实际为${response.status}`);
    
    // 响应时间断言
    assert(response.duration < 1000, `响应时间应小于1000ms，实际为${response.duration}ms`);
    
    // JSON结构断言
    if (response.json) {
        assert(response.json.code !== undefined, '响应应包含code字段');
        assert(response.json.code === 0, `业务码应为0，实际为${response.json.code}`);
        assert(response.json.data !== undefined, '响应应包含data字段');
        
        // 数据字段断言
        if (response.json.data) {
            assert(response.json.data.id !== undefined, 'data应包含id字段');
            assert(typeof response.json.data.id === 'string', 'id应为字符串类型');
        }
    }
    
    utils.info('===== 断言测试完成 =====');
    utils.info(`通过: ${passCount}, 失败: ${failCount}`);
    
    // 保存测试结果
    utils.setVariable('test_pass_count', passCount.toString());
    utils.setVariable('test_fail_count', failCount.toString());
    
    return response;
}
```

---

### 💾 数据持久化

Hook 脚本会随接口一起保存：

1. **历史记录**：发送请求后，Hook 脚本会保存到历史记录中
2. **接口集合**：保存接口到集合时，Hook 脚本会一起保存
3. **导入导出**：导出配置时会包含所有 Hook 脚本

---

### ⚠️ 注意事项

1. **必须返回对象**：`preRequest` 必须返回 `request`，`postResponse` 必须返回 `response`
2. **异步支持**：脚本支持 async/await，可以使用 Promise
3. **错误处理**：脚本执行出错不会影响请求，错误信息会显示在控制台
4. **安全限制**：脚本在浏览器沙箱中执行，无法访问敏感 API
5. **变量作用域**：`setVariable` 设置的变量可在后续请求中使用 `{{变量名}}` 引用

---
</br>

# Mock 服务器

**Mock** 是一个基于 Go 的 API Mock 服务：通过一份 JSON 配置即可提供 REST 接口、静态资源、WebSocket、SSE 等能力，并支持路径参数、条件匹配、模板变量、热重载与内置 Admin 控制台。


## 配置文件顶层结构（mock.json）

```jsonc
{
  "listen":     [ /* 服务监听：host/port/protocols/cert/key */ ],
  "static":     [ /* 静态目录挂载 */ ],
  "routes":     [ /* HTTP API Mock */ ],
  "websockets": [ /* WebSocket 剧本 */ ],
  "sse":        [ /* Server-Sent Events */ ]
}
```

- 各顶层字段均可为空数组。
- 推荐在 Admin 中编辑（带校验与运行态同步），也可本地编辑后通过 Reload 或重启生效。
- JSON 中数字会解析为 `float64`，书写布尔/整型时注意类型。

---

## 监听服务（listen）

用于配置 Mock 服务监听的地址与协议。

```json
{
  "listen": [
    {
      "host": "0.0.0.0",
      "port": 8080,
      "protocols": ["http", "https"],
      "cert_file": "./certs/mock.crt",
      "key_file": "./certs/mock.key"
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `host` | 监听地址：`localhost`、`127.0.0.1`、`::1`、域名或内网 IP |
| `port` | 端口 |
| `protocols` | 可同时包含 `http` 与 `https`；每个 listen 项会启动一个 Server |
| `cert_file` / `key_file` | HTTPS 证书与私钥路径；启用 `https` 时必填，否则启动会报错 |

---

## 静态资源（static）

将 URL 前缀映射到本地目录，用于托管 Swagger、图片、附件等。

```json
{
  "static": [
    {
      "mount": "/assets/",
      "dir": "./public",
      "download": false,
      "index_files": ["index.html", "home.html"],
      "allow_methods": ["GET", "HEAD"],
      "headers": { "Cache-Control": "max-age=86400" }
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `mount` | URL 前缀；不以 `/` 结尾时会自动补尾斜杠并做 301 重定向 |
| `dir` | 本地目录；请求 `/assets/app.js` 对应 `./public/app.js` |
| `download` | `true` 时所有响应带 `Content-Disposition: attachment` |
| `index_files` | 目录默认首页的查找顺序（可选） |
| `allow_methods` | 允许的 HTTP 方法，如只允许 GET/HEAD；未配置则不限制方法 |
| `headers` | 对静态响应统一添加的头部 |

---

## HTTP 路由（routes）

### 最小示例

```json
{
  "method": "GET",
  "path": "/api/user/{id}",
  "responses": [
    { "status": 200, "body": { "id": "{{param.id}}", "ok": true } }
  ]
}
```

访问 `GET /api/user/42` 得到：`{ "id": "42", "ok": true }`。

### 方法、路径与 ANY

- `method`：`GET`、`POST`、`PUT`、`PATCH`、`DELETE` 等；配置会转为大写匹配。
- `method: "ANY"` 或空字符串：不限制 HTTP 方法。
- `path`：支持 gorilla/mux 路径，如 `/api/user/{id}/info/{section}`，`{id}` 等会注入为 `param.id`、`param.section`。

### 请求匹配（match）

在进入响应分支前，可要求 **headers / query / body** 同时满足条件；未配置 `match` 则视为通过。

```json
"match": {
  "headers": { "x-token": "^test-" },
  "query":   { "env": "^(dev|qa)$" },
  "body":    { "meta.version": "^v\\d+$", "items.0.type": "vip" }
}
```

| 维度 | 说明 |
|------|------|
| `headers` / `query` | 值为**正则**；若只做等值，建议写 `^value$` |
| `body` | 键为点路径或带索引路径：`foo.bar`、`items.0.id` 或 `items[0].id`；值可为正则或等值（非字符串会转成字符串比较） |

全部满足才命中该 route；否则返回 404。

### 路由级条件（when）

在 route 上可配置 `when`，与响应分支的 when 同语义：不通过则返回 403。

```json
"when": {
  "query.age": ">18",
  "header.X-Role": "~^admin|root$"
}
```

when 的 value 支持等值或操作符前缀：`=`、`!=`、`>`、`<`、`~`（正则）、`contains`（字符串包含）。

### 变量提取（extract）

从请求 body/query/header 中按「点路径」提取字段，注入为 `extract.<key>`，供响应/模板使用。

```json
"extract": {
  "from": "body",
  "rules": {
    "customerId": "customer.id",
    "ip": "X-Real-IP"
  }
}
```

- `from`：`body`、`query`、`header` 之一。
- `rules`：键为变量名，值为**点路径**（如 `customer.id`、`root.users.0.info.data`），**不要**使用 `$.` 前缀。
- 提取结果在模板中以 `{{extract.customerId}}`、`{{extract.ip}}` 使用。

### 变量命名空间

以下变量可在 `when`、`headers`、`cookies`、`body`、`file`、`template` 中使用。

| 命名空间 | 来源 | 说明 |
|----------|------|------|
| `param.xxx` | 路径参数 `/foo/{id}` | mux 自动注入 |
| `query.xxx` | URL 查询参数 | 多值取第一个 |
| `header.xxx` | 请求头 | 与客户端一致（大小写） |
| `body.xxx` | JSON 请求体顶层字段 | 嵌套需通过 extract 或 match.body 点路径 |
| `form.xxx` | 表单字段 | `multipart/form-data`、`application/x-www-form-urlencoded` |
| `form.xxx.filename` / `form.xxx.size` | 上传文件信息 | 仅 multipart 时可用 |
| `extract.xxx` | extract 规则结果 | 来自 `extract.rules` |

引用时建议带命名空间，如 `{{param.id}}`、`{{query.env}}`、`{{body.name}}`、`{{extract.customerId}}`。

### 内置函数模板（func）

除了从请求中提取变量，还支持在模板中调用内置函数，动态生成值。语法为 `{{func.函数名()}}` 或 `{{func.函数名(参数)}}`。

#### 支持的函数列表

| 函数 | 用法 | 说明 |
|------|------|------|
| `uuid` | `{{func.uuid()}}` | 生成 UUID v4 字符串 |
| `timestamp` | `{{func.timestamp()}}` | 获取当前时间戳（秒） |
| `timestamp_sec` | `{{func.timestamp_sec()}}` | 获取当前时间戳（秒） |
| `timestamp_ms` | `{{func.timestamp_ms()}}` | 获取当前时间戳（毫秒） |
| `now` | `{{func.now()}}` | 获取当前时间，默认格式 `2006-01-02 15:04:05` |
| `now` | `{{func.now(2006-01-02)}}` | 获取当前时间，自定义格式 |
| `date` | `{{func.date()}}` | 获取当前日期，默认格式 `2006-01-02` |
| `date` | `{{func.date(01/02/2006)}}` | 获取当前日期，自定义格式 |
| `time` | `{{func.time()}}` | 获取当前时间，默认格式 `15:04:05` |
| `time` | `{{func.time(15:04)}}` | 获取当前时间，自定义格式 |
| `random_int` | `{{func.random_int()}}` | 生成随机整数，默认范围 0-1000 |
| `random_int` | `{{func.random_int(1, 100)}}` | 生成随机整数，指定范围 |
| `random_string` | `{{func.random_string()}}` | 生成随机字符串，默认长度 16 |
| `random_string` | `{{func.random_string(32)}}` | 生成随机字符串，指定长度 |

#### 使用示例

```json
{
  "path": "/api/order/create",
  "method": "POST",
  "responses": [
    {
      "status": 200,
      "headers": {
        "Content-Type": "application/json",
        "X-Request-Id": "{{func.uuid()}}"
      },
      "body": {
        "code": 0,
        "message": "success",
        "data": {
          "orderId": "{{func.uuid()}}",
          "orderNo": "ORD{{func.timestamp()}}",
          "createdAt": "{{func.now(2006-01-02 15:04:05)}}",
          "timestamp": {{func.timestamp()}},
          "token": "{{func.random_string(32)}}",
          "luckyNumber": {{func.random_int(1, 100)}}
        }
      }
    }
  ]
}
```

#### 时间格式说明

Go 语言的时间格式使用特定的参考时间 `2006-01-02 15:04:05`，常用格式：

| 格式字符串 | 输出示例 |
|-----------|---------|
| `2006-01-02` | 2024-01-15 |
| `15:04:05` | 14:30:45 |
| `2006-01-02 15:04:05` | 2024-01-15 14:30:45 |
| `2006/01/02` | 2024/01/15 |
| `01/02/2006` | 01/15/2024 |
| `20060102150405` | 20240115143045 |

### 多响应分支（when）

`responses` 为数组时，按**顺序**匹配：每条 response 的 `when` 全满足则选中并返回；都不满足则使用第一条。

```json
"responses": [
  {
    "when": { "param.id": "007" },
    "status": 200,
    "body": { "msg": "for james bond" }
  },
  {
    "when": { "query.age": ">18" },
    "headers": { "X-Adult": "true" },
    "body": { "ok": true }
  },
  {
    "status": 404,
    "body": { "error": "not found" }
  }
]
```

- **when**：支持 `param.*`、`query.*`、`header.*`、`body.*`、`extract.*`、`form.*`；多键需全部满足。
- **value 写法**：  
  - 等值：`"param.id": "007"`；  
  - 表达式（操作符前缀）：`"query.age": ">18"`、`"header.X-Role": "~^admin|root$"`、`"body.name": "contains:alice"`。  
  支持操作符：`=`、`!=`、`>`、`<`、`~`（正则）、`contains`。
- 若所有分支都不满足，实现上会回退到第一条 response，因此建议最后一条写兜底。

### 响应字段说明

| 字段 | 说明 |
|------|------|
| `status` | HTTP 状态码；可省略，默认 200 |
| `headers` | 任意响应头；值支持模板变量 |
| `cookies` | Cookie 数组，见下表；会做模板替换 |
| `delay_ms` | 延迟若干毫秒再返回，用于模拟慢接口 |
| `body` | 字符串或对象；递归替换模板变量后输出 |
| `file` | 本地文件路径（可含变量）；直接将该文件作为响应体 |
| `template` | 模板文件名（无需写 `@`）；读取文件内容后做变量替换再返回 |
| `speed_kbps` | 文件下载限速（单位 KB/s）；模拟慢速网络环境 |
| `buffered` | 是否使用缓冲式下载（默认 false 流式）；true 时先读取整个文件到内存再发送 |
| `compress` | 压缩方式：`gzip`、`deflate`、`auto`（根据客户端 Accept-Encoding 自动选择） |
| `chunks` | 分块传输配置数组；每块可设置 data 和 delay_ms |
| `counter` | 计数器配置；按请求次数选择不同响应 |
| `probability` | 概率权重（0-100）；用于概率响应选择 |

**Cookie 配置**（下划线命名）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` / `value` | string | 名称与值 |
| `path` / `domain` | string | 可选 |
| `expires` | string | 建议 RFC3339 |
| `max_age` | int | 秒 |
| `secure` / `http_only` | bool | 仅 HTTPS / 不可被 JS 读取 |
| `same_site` | string | `lax` / `strict` / `none` |

### 强类型模板占位符（int / float / bool）

默认 `{{key}}` 替换为字符串。若要在 JSON 中输出**数字**或**布尔**，可使用：

- `{{@int:key}}` → 整型（int64）
- `{{@float:key}}` → 浮点（float64）
- `{{@bool:key}}` → 布尔

规则：

- 若**整串**仅为一个强类型占位符（如 `"{{@int:query.age}}"`），则该字段在 JSON 中为对应类型（如 `123`、`true`）。
- 若与其它文字混用（如 `"age={{@int:query.age}}"`），则按字符串替换（如 `"age=77"`）。
- 解析失败时退化为普通字符串替换。

### 模板文件（@filename）

当 `body` 或 `template` 的值为以 `@` 开头的路径时，系统会读取该文件并做 `{{ }}` 替换后返回。

- 示例：`"body": "@payloads/small.json"`，文件内容可为 JSON/XML/文本。
- 若文件不存在，响应为 `"template file not found"`。

### 文件下载配置示例

支持三种下载模式：流式下载（默认）、缓冲式下载、限速下载。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/download/normal",
      "responses": [{
        "file": "./files/test.zip",
        "status": 200,
        "headers": {
          "Content-Disposition": "attachment; filename=test.zip"
        }
      }]
    },
    {
      "method": "GET",
      "path": "/download/buffered",
      "responses": [{
        "file": "./files/test.zip",
        "status": 200,
        "buffered": true,
        "headers": {
          "Content-Disposition": "attachment; filename=test.zip"
        }
      }]
    },
    {
      "method": "GET",
      "path": "/download/slow",
      "responses": [{
        "file": "./files/test.zip",
        "status": 200,
        "speed_kbps": 100,
        "headers": {
          "Content-Disposition": "attachment; filename=test.zip"
        }
      }]
    },
    {
      "method": "GET",
      "path": "/download/delayed-slow",
      "responses": [{
        "file": "./files/test.zip",
        "status": 200,
        "delay_ms": 3000,
        "speed_kbps": 50,
        "buffered": true,
        "headers": {
          "Content-Disposition": "attachment; filename=test.zip"
        }
      }]
    }
  ]
}
```

**下载模式说明**：

| 模式 | 配置 | 特点 |
|------|------|------|
| 流式下载 | 默认（不配置） | 支持断点续传，内存占用小，适合大文件 |
| 缓冲式下载 | `buffered: true` | 先读取整个文件到内存再发送，适合小文件 |
| 限速下载 | `speed_kbps: 100` | 按 100KB/s 速率发送，模拟慢速网络 |
| 延时+限速 | `delay_ms` + `speed_kbps` | 先延时再限速下载 |

### 7.11 响应重定向

通过 `status` 和 `headers.Location` 实现重定向，模拟页面跳转场景。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/redirect/demo",
      "responses": [{
        "status": 302,
        "headers": {
          "Location": "https://example.com/target"
        }
      }]
    },
    {
      "method": "GET",
      "path": "/redirect/old-api/{path}",
      "responses": [{
        "status": 301,
        "headers": {
          "Location": "/api/v2{{param.path}}"
        }
      }]
    }
  ]
}
```

**重定向状态码**：
- `301`：永久重定向
- `302`：临时重定向
- `307`：临时重定向（保持请求方法）
- `308`：永久重定向（保持请求方法）

### 7.12 响应压缩

支持 gzip 和 deflate 压缩响应，可自动根据客户端 Accept-Encoding 选择。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/api/compressed",
      "responses": [{
        "compress": "gzip",
        "body": {
          "message": "这是一个被压缩的响应",
          "data": "大量数据..."
        }
      }]
    },
    {
      "method": "GET",
      "path": "/api/auto-compress",
      "responses": [{
        "compress": "auto",
        "body": {
          "message": "根据客户端 Accept-Encoding 自动选择压缩方式"
        }
      }]
    }
  ]
}
```

### 7.13 分块传输

支持配置分块发送响应体，每块可单独设置延迟，模拟流式 API。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/api/stream",
      "responses": [{
        "status": 200,
        "headers": {
          "Content-Type": "text/plain"
        },
        "chunks": [
          { "data": "第一块数据\n", "delay_ms": 0 },
          { "data": "第二块数据\n", "delay_ms": 1000 },
          { "data": "第三块数据\n", "delay_ms": 1000 },
          { "data": "第四块数据\n", "delay_ms": 1000 },
          { "data": "完成", "delay_ms": 500 }
        ]
      }]
    },
    {
      "method": "GET",
      "path": "/api/stream-json",
      "responses": [{
        "status": 200,
        "headers": {
          "Content-Type": "application/x-ndjson"
        },
        "chunks": [
          { "data": "{\"event\":\"start\"}\n" },
          { "data": "{\"event\":\"data\",\"value\":1}\n", "delay_ms": 500 },
          { "data": "{\"event\":\"data\",\"value\":2}\n", "delay_ms": 500 },
          { "data": "{\"event\":\"end\"}\n", "delay_ms": 200 }
        ]
      }]
    }
  ]
}
```

### 7.14 计数器模式

支持按请求次数返回不同响应，模拟重试场景、服务恢复场景。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/api/flaky",
      "responses": [
        {
          "counter": { "key": "flaky-api", "max": 100, "loop": true },
          "status": 500,
          "body": { "error": "服务暂时不可用，请重试" }
        },
        {
          "status": 502,
          "body": { "error": "服务暂时不可用，网关错误，请重试" }
        },
        {
          "status": 200,
          "body": { "message": "服务已恢复", "counter": "{{counter}}" }
        }
      ]
    },
    {
      "method": "POST",
      "path": "/api/counter/reset",
      "responses": [{
        "counter": { "key": "flaky-api", "reset": true },
        "body": { "message": "计数器已重置" }
      }]
    }
  ]
}
```

**计数器配置**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `key` | string | 计数器唯一标识；不同路由可共享同一计数器 |
| `max` | int | 最大值；达到后根据 loop 决定是否循环 |
| `loop` | bool | 是否循环；true 时达到 max 后重置为 1 |
| `reset` | bool | 是否重置；true 时将计数器重置为 0 |

**计数器变量**：
- `{{counter}}`：当前计数器值
- `{{counter.<key>}}`：指定 key 的计数器值

### 7.15 概率响应

支持按概率权重随机返回响应，模拟不稳定服务、A/B 测试。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/api/ab-test",
      "responses": [
        {
          "probability": 70,
          "body": { "version": "A", "message": "70% 概率返回此响应" }
        },
        {
          "probability": 30,
          "body": { "version": "B", "message": "30% 概率返回此响应" }
        }
      ]
    },
    {
      "method": "GET",
      "path": "/api/unstable",
      "responses": [
        {
          "probability": 80,
          "status": 200,
          "body": { "success": true }
        },
        {
          "probability": 15,
          "status": 500,
          "body": { "error": "内部错误" }
        },
        {
          "probability": 5,
          "status": 503,
          "body": { "error": "服务不可用" }
        }
      ]
    }
  ]
}
```

**概率说明**：
- `probability` 取值范围 0-100
- 概率权重按相对比例计算，不要求总和为 100
- 未设置 `probability` 的响应作为默认兜底

### 7.16 请求日志持久化

支持将请求日志持久化到文件，支持日志轮转和格式配置。

```json
{
  "log": {
    "enable": true,
    "dir": "./logs",
    "max_size": 10,
    "max_files": 5,
    "format": "json"
  },
  "routes": [
    {
      "method": "GET",
      "path": "/api/test",
      "responses": [{ "body": { "message": "test" } }]
    }
  ]
}
```

**日志配置**：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | false | 是否启用日志持久化 |
| `dir` | string | ./logs | 日志文件目录 |
| `max_size` | int | 10 | 单个日志文件最大大小（MB） |
| `max_files` | int | 5 | 保留的日志文件数量 |
| `format` | string | json | 日志格式：json 或 text |

### 7.17 表单与文件上传

- 对 `multipart/form-data` 与 `application/x-www-form-urlencoded` 会自动解析并注入 `form.xxx`。
- 上传文件会额外提供 `form.<field>.filename`、`form.<field>.size`。
- 可在响应或模板中引用这些变量。multipart 解析大小受 `-max-multipart` 限制。

---

## WebSocket Mock

基于 gorilla/websocket，路径与 mux 一致，支持路径参数与模板变量。

```json
{
  "websockets": [
    {
      "path": "/ws/{room}",
      "match": {
        "query": { "token": ".+" },
        "headers": { "Sec-WebSocket-Protocol": "^chat$" }
      },
      "script": [
        { "send": "{\"type\":\"welcome\",\"room\":\"{{param.room}}\"}" },
        { "await": { "type": "auth" }, "timeout_ms": 5000 },
        { "send": "{\"type\":\"ok\"}" },
        { "delay_ms": 1000, "send": "{\"type\":\"broadcast\"}" },
        { "close": true }
      ]
    }
  ]
}
```

| 项 | 说明 |
|----|------|
| `path` | 与 HTTP 路由相同，可含 `{param}` |
| `match` | 建立连接前校验 headers/query（支持正则）；不满足则 404 |
| `script` | 按顺序执行的动作序列 |

**script 动作**：

| 键 | 说明 |
|----|------|
| `send` | 发送一条文本消息（可 JSON 字符串）；支持模板变量 |
| `await` | 阻塞等待客户端一条消息：值为**字符串**时按正则匹配整条文本；值为**对象**时按 JSON 字段等值匹配 |
| `timeout_ms` | 与 `await` 配合，超时后向客户端返回错误并结束 |
| `delay_ms` | 本动作执行前延迟（毫秒） |
| `close` | 为 `true` 时发送正常关闭帧并结束脚本 |

---

## Server-Sent Events（SSE）

```json
{
  "sse": [
    {
      "path": "/sse/{topic}",
      "method": "GET",
      "match": { "query": { "client": ".+" } },
      "headers": { "X-Topic": "{{param.topic}}" },
      "status": 200,
      "cookies": [],
      "events": [
        { "id": "1", "event": "hello", "data": "topic={{param.topic}}", "retry": 1500 },
        { "event": "keepalive", "data": "ping", "delay_ms": 2000 },
        { "data": "done" }
      ],
      "repeat": false
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `path` | 路径，可含路径参数 |
| `method` | 默认 `GET`，也可 `POST` 等 |
| `match` | 同 route：headers/query/body 全部满足才建立流 |
| `headers` / `cookies` / `status` | 可选；支持模板变量 |
| `events` | 事件列表；每条可含 `id`、`event`、`data`、`retry`、`delay_ms`；`data` 支持模板 |
| `repeat` | `true` 时 events 发送完后从头循环 |

---

## 模板变量与生命周期

变量注入顺序（与代码一致）：

1. 路径参数 → `param.*`
2. Query → `query.*`，Header → `header.*`
3. 若方法允许 body，读取 JSON → `body.*`
4. 若为表单/上传 → `form.*`、`form.*.filename`、`form.*.size`
5. 按 `extract` 规则 → `extract.*`

同一请求中，`when`、`headers`、`cookies`、`body`、`file`、`template` 共用这一套变量表。

---

## 管理控制台（Admin UI）

- **地址**：`http://127.0.0.1:4444/mock/`
- **功能**：
  - **拉取配置**：GET 当前 `mock.json` 内容及服务是否运行
  - **Reload**：POST 新配置（JSON 字符串），写入文件并热重启 Mock 服务
  - **Start / Stop / Restart**：控制 Mock 服务进程（Admin 自身常驻，不随 Mock 停止）

**API**：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/mock/api/config` | 返回 `{ "config": "<JSON 字符串>", "running": bool }` |
| POST | `/mock/api/reload` | Body：`{ "config": "<完整 JSON 字符串>" }`，写入并重启 |
| POST | `/mock/api/start` / `stop` / `restart` | 启停/重启 Mock 服务 |

推荐流程：拉取配置 → 编辑/格式化 → Reload → 根据返回与日志确认是否 `ok`。

---

## 匹配与分流细则

- **路由**：gorilla/mux 逐条注册，路径参数 `{id}` 等自动注入 `param.*`。
- **match（预过滤）**：
  - `match.headers` / `match.query`：值按**正则**匹配；等值请写 `^value$`。
  - `match.body`：键为点路径（含数组索引）；值若为字符串则按正则，否则按字符串化后等值；全部满足才命中，否则 404。
- **when（分支/路由级条件）**：支持 `param.*`、`query.*`、`header.*`、`body.*`、`extract.*`、`form.*`；多键全部满足才通过。value 可为等值或带操作符前缀：`=`、`!=`、`>`、`<`、`~`（正则）、`contains`；比较前会尝试数值解析（>、<）。
- **extract**：仅支持点路径（如 `customer.id`、`root.users.0.info`），不支持 `$.` 前缀；结果通过 `{{extract.<key>}}` 使用。
- **模板替换范围**：`body`、`headers`、`cookies` 各字段及 `@模板文件` 内容均会替换。

---

## 运行时行为与日志

- 启动时会按条输出 `Register route: <METHOD> <PATH>`，便于确认路由加载。
- 请求会打印路径参数注入结果（如 `DEBUG param injection`），便于排查模板未替换问题。
- 静态/WebSocket/SSE 注册、HTTPS 证书错误、Reload 失败等会在日志中输出。
- 长期运行建议配合 supervisor、systemd 或 Docker 做进程守护。

---

## Mock常见问题排查

| 现象 | 可能原因与处理 |
|------|----------------|
| 命中不到路由 | 检查 method 是否与配置一致（配置会转大写）；`match.headers`/query 正则是否过严或大小写不一致 |
| 模板没替换 | 确认使用 `{{param.id}}` 等带命名空间写法；确认请求中确实带对应 query/header/body；看日志中的 `vars` 输出 |
| when 不生效 | when 的 value 支持等值或操作符前缀（`>`、`<`、`~`、`contains`）；确保 body/form/extract 已注入（正常 HTTP 已内置） |
| 返回文件 404 | `responses[].file` 为相对路径时相对进程工作目录；可改为与 `mock.json` 同目录或绝对路径；Windows 注意反斜杠 |
| WebSocket await 超时 | 确认客户端按 script 顺序发消息；可增大 `timeout_ms`；查看日志中的 upgrade/await 相关输出 |
| CORS 预检 | 服务对 OPTIONS 做了兜底，返回常用 CORS 头；如需定制可在响应 `headers` 或静态 headers 中补充 |


---

## 🔍 项目常见问题

### ❓ 为什么需要后端转发？
> 由于浏览器同源策略，前端直接请求第三方接口会遇到 CORS 限制。通过本工具的后端转发，前端只需请求本地服务即可，后端再代为请求目标接口，绕过跨域限制。

### ❓ WebCurl变量如何使用,变量替换支持位置？
> 支持请求url,请求头,全局头替换，使用{{xxx}}引用定义的变量。

### ❓ 如何上传多个文件？
> 在前端选择 `form-data`，每个文件都可单独选择，支持多文件上传。后端会自动处理。

### ❓ 如何保存上传的文件到指定目录？
> 启动时通过 `--upload-dir=/your/path` 参数指定目录，form-data上传的文件会自动保存到该目录（存在则覆盖）。目录需提前创建并有写权限。

### ❓ 如何自定义请求头？
> 在前端"请求头"标签页添加即可，支持变量替换。

### ❓ 如何切换为直接请求（不走代理）？
> 只需关闭后端服务或修改 `/api/mode` 返回内容，前端会自动切换为直连模式。

### ❓ 数据安全吗？
> 所有数据仅存储在浏览器本地（localStorage），不会上传到任何服务器。企业内网、敏感环境使用无忧。

### ❓ 支持哪些平台？
> 支持Windows、Linux、MacOS、ARM架构，包括国产信创平台。一次编译，到处运行。同时完美支持IPv4和IPv6网络协议。

### ❓ 支持哪些通信协议？
> 除了传统的HTTP/HTTPS请求，还原生支持WebSocket（双向通信）和SSE（Server-Sent Events，单向实时推送），满足各种实时通信需求。

### ❓ MockServer和EchoServer有啥区别？
> EchoServer返回的内容相对固定，MockServer完全支持自定义,支持根据条件动态构建响应内容。

### ❓ EchoServer有什么用？
> EchoServer提供完整的请求回显和响应控制功能，适合接口调试、自动化测试、网络延迟模拟等场景。支持多种响应格式和流式通信。

### ❓ 如何关闭EchoServer？
> 启动时添加 `--echo-server=false` 参数即可关闭EchoServer调试服务。

### ❓ 如何开启静态文件服务器模式？
> 使用 `--webroot` 参数启动静态文件服务器模式。所有API接口将失效，变成一个纯静态文件服务器。

### ❓ 静态文件服务器支持哪些文件类型？
> 支持所有常见文件类型：HTML、CSS、JS、图片（PNG/JPG/GIF/SVG）、音频（MP3/WAV）、视频（MP4）、字体文件、PDF、压缩包等。会自动设置正确的MIME类型。

---

## 🤝 贡献与反馈

- 🐛 欢迎提交 issue 或 PR，完善功能和文档。
- 💡 如有建议或 bug，欢迎反馈！

---

## 📄 License

MIT

---

如需进一步定制或有疑问，欢迎联系作者。

---

**⭐ 如果这个项目对你有帮助，请给我们一个Star！**

**💬 有任何问题或建议，欢迎在GitHub上讨论！**

---

*让API调试变得简单而优雅* ✨
