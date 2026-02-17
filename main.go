package main

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"math/rand"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Header 定义HTTP请求头结构体，用于JSON序列化和反序列化
type Header struct {
	Name  string `json:"name"`  // 请求头名称
	Value string `json:"value"` // 请求头值
}

// FileInfo 定义文件信息结构体，用于文件上传功能
type FileInfo struct {
	FieldName string `json:"field_name"` // 表单字段名
	FileName  string `json:"file_name"`  // 文件名
}

// ForwardParams 定义转发参数结构体，用于存储WebSocket和SSE连接的参数
type ForwardParams struct {
	URL            string // 目标URL地址
	Headers        string // 请求头JSON字符串
	VerifySSL      string // SSL验证选项 (Y/N)
	FollowRedirect string // 重定向跟随选项 (Y/N)
	Timeout        int    // 超时时间（秒）
	RetryCount     int    // 重试次数
	RetryDelay     int    // 重试延迟（秒）
}

// wsConnParams 存储WebSocket连接的参数映射表
// 键为connect_id，值为ForwardParams
var wsConnParams sync.Map

// sseConnParams 存储SSE连接的参数映射表
// 键为connect_id，值为ForwardParams
var sseConnParams sync.Map

// DetachedProcess Windows系统进程标志，用于后台运行
var DetachedProcess uint32 = 0

// CreateNewProcessGroup Windows系统进程组标志，用于后台运行
var CreateNewProcessGroup uint32 = 0

// controlParams 定义控制参数白名单，用于过滤不需要转发的参数
// 这些参数是WebCurl内部使用的，不应该转发到目标服务器
var controlParams = map[string]bool{
	"url":             true, // 目标URL
	"time_out":        true, // 超时时间
	"retry_count":     true, // 重试次数
	"retry_delay":     true, // 重试延迟
	"method":          true, // 请求方法
	"body_type":       true, // 请求体类型
	"headers":         true, // 请求头
	"body":            true, // 请求体
	"file_info":       true, // 文件信息
	"files":           true, // 文件数据
	"follow_redirect": true, // 重定向跟随
	"verify_ssl":      true, // SSL验证
}

// webroot 静态文件根目录路径，为空时使用内嵌的index.html
var webroot = ""

// form-data上传文件目录
var uploadDir = ""

// embeddedFS 内嵌的前端文件系统，包含index.html和favicon.ico
//
//go:embed index.html mock.html tool.html favicon.ico README.md
var embeddedFS embed.FS

// logger 全局日志记录器
var logger *slog.Logger

// server 全局HTTP服务器实例，用于优雅退出
var server *http.Server

// shutdownWg 等待组，用于等待所有goroutine完成
var shutdownWg sync.WaitGroup

// ParseMultipartForm 16G
var maxMemory int64 = 16 << 30

// genConnectID 生成32位随机连接ID
// 用于WebSocket和SSE连接的唯一标识
func genConnectID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

/*
字段	含义	示例
/C	国家	CN
/ST	省/州	Guangdong
/L	城市	Shenzhen
/O	组织	MyCompany
/OU	部门	Tech
/CN	域名或名称	*.test.com
*/
// parseCertInfo 解析 --cert-info 参数，格式如 "/C=CN/ST=Shanghai/L=Pudong/O=Test/OU=Ops/CN=app.example.net"
func parseCertInfo(certInfo string) pkix.Name {
	name := pkix.Name{}
	if certInfo == "" {
		return name
	}
	fields := strings.Split(certInfo, "/")
	for _, field := range fields {
		if field == "" {
			continue
		}
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			name.CommonName = value
		}
	}
	return name
}

// generateSSLCertificateToDir 生成自签名SSL证书到指定目录，支持自定义主题
// subject: 证书主题信息（可为空，使用默认）
func generateSSLCertificateToDir(dir string, subject pkix.Name) error {
	// 生成2048位RSA私钥
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}

	// 创建证书模板，设置有效期和基本信息
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10年有效期

	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if subject.CommonName != "" {
		template.DNSNames = append(template.DNSNames, subject.CommonName)
	}

	// 确保目标目录存在
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 设置证书和私钥文件路径
	keyPath := filepath.Join(dir, "ssl_cert.key")
	certPath := filepath.Join(dir, "ssl_cert.pem")

	// 将私钥编码为PEM格式并保存到文件
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyPEM), 0600); err != nil {
		return fmt.Errorf("保存私钥失败: %v", err)
	}

	// 创建X.509证书
	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %v", err)
	}

	// 将证书编码为PEM格式并保存到文件
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(certPEM), 0644); err != nil {
		return fmt.Errorf("保存证书失败: %v", err)
	}

	return nil
}

// setupLogger 初始化日志系统
// logLevelStr: 日志级别 (debug/info/warn/error)
// logFilePath: 日志文件路径，为空时使用默认路径
// maxLogSize: 日志文件最大大小（字节）
// stdoutLog: 是否在控制台打印日志，默认true
func setupLogger(logLevelStr, logFilePath string, maxLogSize int64, stdoutLog bool) {
	// 根据字符串设置日志级别
	var lvl = slog.LevelWarn
	switch strings.ToLower(logLevelStr) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	default:
		lvl = slog.LevelError
	}

	// 如果未指定日志文件路径，使用默认路径
	if logFilePath == "" {
		exe, err := os.Executable()
		if err != nil {
			logFilePath = "WebCurl.log"
		} else {
			dir := filepath.Dir(exe)
			logFilePath = filepath.Join(dir, "WebCurl.log")
		}
	}

	// 检查日志文件大小，超过限制则清空文件
	if info, err := os.Stat(logFilePath); err == nil && info.Size() > maxLogSize {
		if f, err := os.OpenFile(logFilePath, os.O_TRUNC|os.O_WRONLY, 0644); err == nil {
			_ = f.Close()
		}
	}

	// 创建日志文件或使用控制台输出
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	var handler slog.Handler
	if err != nil {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
		fmt.Printf("无法打开日志文件: %v,日志输出到控制台\n", err)
	} else {
		if stdoutLog {
			handler = slog.NewTextHandler(io.MultiWriter(logFile, os.Stdout), &slog.HandlerOptions{Level: lvl})
		} else {
			handler = slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: lvl})
		}
	}
	logger = slog.New(handler)
	logger.Info("日志初始化", "level", lvl, "file", logFilePath, "stdout", stdoutLog)
}

// daemonizeIfNeeded 跨平台后台运行功能
// daemon: 是否启用后台运行
func daemonizeIfNeeded(daemon bool) {
	if !daemon {
		return
	}
	// 检查是否已经是子进程
	if os.Getenv("GO_DAEMON_MODE_WEB_CURL") == "1" {
		// 已经是子进程
		return
	}

	// 获取可执行文件路径和参数
	exe, _ := os.Executable()
	args := os.Args[1:]
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "GO_DAEMON_MODE_WEB_CURL=1")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	// 设置进程属性，实现跨平台后台运行
	attr := &syscall.SysProcAttr{}
	rv := reflect.ValueOf(attr).Elem()

	if runtime.GOOS == "windows" {
		// Windows系统：使用反射设置CreationFlags
		if flags := rv.FieldByName("CreationFlags"); flags.IsValid() && flags.CanSet() {
			flags.SetUint(uint64(CreateNewProcessGroup | DetachedProcess))
		}
	} else {
		// Unix系统：使用反射设置SetSid
		if setsid := rv.FieldByName("Setsid"); setsid.IsValid() && setsid.CanSet() {
			setsid.SetBool(true)
		}
	}
	cmd.SysProcAttr = attr

	// 启动后台进程并退出当前进程
	_ = cmd.Start()
	fmt.Println("已切换到后台运行,PID:", cmd.Process.Pid)
	os.Exit(0)
}

// printAndLogConfig 打印并记录服务启动配置信息
func printAndLogConfig(host, port, webroot string, daemon, echoServer bool, logLevel, logFile, logSize, sslCert, sslCertKey, uploadDir string, stdoutLog bool) {
	// 获取默认日志文件路径
	defaultLogFile := "WebCurl.log"
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		defaultLogFile = filepath.Join(dir, "WebCurl.log")
	}

	// 构建配置映射表
	config := map[string]any{
		"--host":         host,
		"--port":         port,
		"--webroot":      webroot,
		"--daemon":       daemon,
		"--echo-server":  echoServer,
		"--log-level":    logLevel,
		"--log-file":     logFile,
		"--log-size":     logSize,
		"--ssl-cert":     sslCert,
		"--ssl-cert-key": sslCertKey,
		"--upload-dir":   uploadDir,
		"--stdout-log":   stdoutLog,
	}

	// 打印配置信息到控制台
	fmt.Println("服务启动配置：")
	for k, v := range config {
		// 对于空字符串，显示默认值
		if str, ok := v.(string); ok && str == "" {
			if k == "--log-file" {
				fmt.Printf("  %-25s: %s (默认)\n", k, defaultLogFile)
			} else if k == "--webroot" {
				fmt.Printf("  %-25s: 使用内嵌index.html (默认)\n", k)
			} else if k == "--ssl-cert" {
				fmt.Printf("  %-25s: ssl_cert.pem (默认)\n", k)
			} else if k == "--ssl-cert-key" {
				fmt.Printf("  %-25s: ssl_cert.key (默认)\n", k)
			} else if k == "--upload-dir" {
				fmt.Printf("  %-25s: <空> (仅透传)\n", k)
			} else {
				fmt.Printf("  %-25s: <空>\n", k)
			}
		} else {
			fmt.Printf("  %-25s: %v\n", k, v)
		}
	}

	// 记录配置信息到日志
	logger.Info("服务启动配置", "config", config)
}

// handleRoot 处理根路径请求，提供静态文件服务
// 优先使用webroot目录，如果为空则使用内嵌的index.html
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if webroot != "" {
		// 优先使用webroot目录
		path := filepath.Join(webroot, r.URL.Path)
		info, err := os.Stat(path)
		if err == nil {
			if info.IsDir() {
				// 如果是目录，尝试查找 index.html
				indexPath := filepath.Join(path, "index.html")
				if _, err := os.Stat(indexPath); err == nil {
					http.ServeFile(w, r, indexPath)
					return
				}
				// 如果没有 index.html，返回 404
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("404 not found"))
				return
			}
			// 如果是文件，直接提供
			http.ServeFile(w, r, path)
			return
		}
		// 如果文件不存在，返回 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
		return
	}

	// 如果没有指定 webroot，使用内嵌的 index.html
	if r.URL.Path == "/" {
		data, err := embeddedFS.ReadFile("index.html")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("index.html not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found"))
}

// handleMode 处理模式检测请求，返回当前服务模式
func handleMode(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"mode": "proxy"}`))
}

// handleDoc 处理文档下载请求，返回README.md文件
func handleDoc(w http.ResponseWriter, _ *http.Request) {
	data, err := embeddedFS.ReadFile("README.md")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("README.md not found"))
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=README.md")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleFavicon 处理favicon.ico请求
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedFS.ReadFile("favicon.ico")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleForward 处理HTTP请求转发，支持多种请求体格式和文件上传
func handleForward(w http.ResponseWriter, r *http.Request) {
	// 只允许POST方法
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		logger.Error("拒绝非POST请求", "method", r.Method, "url", r.URL.String())
		return
	}

	logger.Info("收到请求", "method", r.Method, "url", r.URL.String())
	logger.Debug("请求Header", "header", r.Header)

	// 解析multipart/form-data请求，支持最大16GB
	err := r.ParseMultipartForm(maxMemory)
	if err != nil {
		http.Error(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		logger.Error("解析请求失败", "err", err)
		return
	}

	// 获取并验证目标URL
	forwardURL := r.FormValue("url")
	if forwardURL == "" {
		http.Error(w, "缺少目标URL", http.StatusBadRequest)
		logger.Error("缺少目标URL参数")
		return
	}

	logger.Debug("转发目标URL", "url", forwardURL)
	logger.Debug("Form参数", "form", r.Form)

	// 获取SSL验证参数，默认启用
	verifySSL := r.FormValue("verify_ssl")
	if verifySSL == "" {
		verifySSL = "Y"
	}

	// 获取重定向跟随参数，默认启用
	followRedirect := r.FormValue("follow_redirect")
	if followRedirect == "" {
		followRedirect = "Y"
	}

	// 解析超时时间参数
	timeOut := 0
	if timeoutStr := r.FormValue("time_out"); timeoutStr != "" {
		timeOut, err = strconv.Atoi(timeoutStr)
		if err != nil {
			http.Error(w, "无效的超时时间", http.StatusBadRequest)
			return
		}
	}

	// 解析重试次数参数
	retryCount := 0
	if retryStr := r.FormValue("retry_count"); retryStr != "" {
		retryCount, err = strconv.Atoi(retryStr)
		if err != nil {
			http.Error(w, "无效的重试次数", http.StatusBadRequest)
			return
		}
	}

	// 解析重试延迟参数
	retryDelay := 0
	if delayStr := r.FormValue("retry_delay"); delayStr != "" {
		retryDelay, err = strconv.Atoi(delayStr)
		if err != nil {
			http.Error(w, "无效的重试延迟", http.StatusBadRequest)
			return
		}
	}

	// 获取请求方法，默认为GET
	method := r.FormValue("method")
	if method == "" {
		method = http.MethodGet
	}

	// 获取请求体类型，默认为none
	bodyType := r.FormValue("body_type")
	if bodyType == "" {
		bodyType = "none"
	}

	// 解析请求头JSON
	var headers []Header
	if headersStr := r.FormValue("headers"); headersStr != "" {
		if err := json.Unmarshal([]byte(headersStr), &headers); err != nil {
			http.Error(w, "解析请求头失败: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 解析文件信息JSON
	var filesInfo []FileInfo
	if filesInfoStr := r.FormValue("file_info"); filesInfoStr != "" {
		if err := json.Unmarshal([]byte(filesInfoStr), &filesInfo); err != nil {
			http.Error(w, "解析文件信息失败: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 处理WebSocket连接请求
	if method == "WS" {
		params := ForwardParams{
			URL:            forwardURL,
			Headers:        r.FormValue("headers"),
			VerifySSL:      verifySSL,
			FollowRedirect: followRedirect,
			Timeout:        timeOut,
			RetryCount:     retryCount,
			RetryDelay:     retryDelay,
		}
		connectID := genConnectID()
		wsConnParams.Store(connectID, params)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"connect_id":"%s","code":0,"msg":"OK"}`, connectID)))
		return
	}

	// 处理SSE连接请求
	if method == "SSE" {
		params := ForwardParams{
			URL:            forwardURL,
			Headers:        r.FormValue("headers"),
			VerifySSL:      verifySSL,
			FollowRedirect: followRedirect,
			Timeout:        timeOut,
			RetryCount:     retryCount,
			RetryDelay:     retryDelay,
		}
		connectID := genConnectID()
		sseConnParams.Store(connectID, params)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"connect_id":"%s","code":0,"msg":"OK"}`, connectID)))
		return
	}

	// 准备请求体数据
	var requestBodyBytes []byte
	var contentType string

	// 创建文件映射：字段名 -> 文件信息列表
	fieldToFiles := make(map[string][]FileInfo)
	for _, fi := range filesInfo {
		fieldToFiles[fi.FieldName] = append(fieldToFiles[fi.FieldName], fi)
	}

	// 根据请求体类型处理数据
	switch strings.ToLower(bodyType) {
	case "form-data":
		// 处理multipart/form-data格式
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)

		// 添加普通表单字段
		for key, values := range r.MultipartForm.Value {
			if !controlParams[key] {
				for _, value := range values {
					_ = bodyWriter.WriteField(key, value)
				}
			}
		}

		// 处理文件上传
		for fieldName, files := range fieldToFiles {
			for _, fileInfo := range files {
				// 在原始请求中查找匹配的文件
				var foundFile *multipart.FileHeader
				for _, fileHeaders := range r.MultipartForm.File {
					for _, fh := range fileHeaders {
						if fh.Filename == fileInfo.FileName {
							foundFile = fh
							break
						}
					}
					if foundFile != nil {
						break
					}
				}

				if foundFile == nil {
					http.Error(w, "文件未上传: "+fileInfo.FileName, http.StatusBadRequest)
					return
				}

				file, err := foundFile.Open()
				if err != nil {
					http.Error(w, "打开文件失败: "+err.Error(), http.StatusInternalServerError)
					return
				}

				// 使用流式处理避免大文件内存占用
				filePart, err := bodyWriter.CreateFormFile(fieldName, fileInfo.FileName)
				if err != nil {
					_ = file.Close()
					http.Error(w, "创建表单文件失败: "+err.Error(), http.StatusInternalServerError)
					return
				}

				if _, err := io.Copy(filePart, file); err != nil {
					_ = file.Close()
					http.Error(w, "写入文件数据失败: "+err.Error(), http.StatusInternalServerError)
					return
				}
				// 立即关闭文件，避免在循环中累积文件句柄
				_ = file.Close()
			}
		}

		// 完成multipart写入
		if err := bodyWriter.Close(); err != nil {
			http.Error(w, "关闭multipart写入器失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		contentType = bodyWriter.FormDataContentType()
		requestBodyBytes = bodyBuf.Bytes()

	case "x-www-form-urlencoded":
		// 处理application/x-www-form-urlencoded格式
		data := url.Values{}
		for key, values := range r.MultipartForm.Value {
			if !controlParams[key] {
				for _, value := range values {
					data.Add(key, value)
				}
			}
		}
		contentType = "application/x-www-form-urlencoded"
		requestBodyBytes = []byte(data.Encode())

	case "json":
		// 处理application/json格式
		jsonBody := r.FormValue("body")
		contentType = "application/json"
		requestBodyBytes = []byte(jsonBody)

	case "text":
		// 处理text/plain格式
		textBody := r.FormValue("body")
		contentType = "text/plain"
		requestBodyBytes = []byte(textBody)

	case "xml":
		// 处理application/xml格式
		xmlBody := r.FormValue("body")
		contentType = "application/xml"
		requestBodyBytes = []byte(xmlBody)

	case "binary":
		// 处理二进制文件上传
		if files := r.MultipartForm.File["files"]; len(files) > 0 {
			file, err := files[0].Open()
			if err != nil {
				http.Error(w, "打开文件失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer file.Close()

			fileData, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, "读取文件失败: "+err.Error(), http.StatusBadRequest)
				return
			}

			contentType = "application/octet-stream"
			requestBodyBytes = fileData
		}

	case "none", "":
		// 无请求体
		requestBodyBytes = nil

	default:
		http.Error(w, "不支持的请求体类型: "+bodyType, http.StatusBadRequest)
		return
	}

	// 创建目标URL
	targetURL, err := url.Parse(forwardURL)
	if err != nil {
		http.Error(w, "无效的目标URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 设置HTTP客户端
	client := &http.Client{}
	if timeOut > 0 {
		client.Timeout = time.Duration(timeOut) * time.Second
	}
	// 如果 verify_ssl == "N",跳过 SSL 验证
	if verifySSL == "N" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	// 如果 follow_redirect == "N",不跟随 3XX 跳转
	if followRedirect == "N" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 执行请求重试逻辑
	var resp *http.Response
	for i := 0; i <= retryCount; i++ {
		if i > 0 && retryDelay > 0 {
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}

		// 准备请求体读取器
		var bodyReader io.Reader
		if requestBodyBytes != nil {
			bodyReader = bytes.NewReader(requestBodyBytes)
		} else {
			bodyReader = nil
		}

		// 创建HTTP请求
		httpReq, err := http.NewRequest(method, targetURL.String(), bodyReader)
		if err != nil {
			if i == retryCount {
				http.Error(w, "创建HTTP请求失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			continue
		}

		// 设置请求头
		if contentType != "" {
			httpReq.Header.Set("Content-Type", contentType)
		}

		// 添加用户自定义的请求头
		for _, header := range headers {
			httpReq.Header.Set(header.Name, header.Value)
		}

		// 发送请求
		resp, err = client.Do(httpReq)
		if err == nil && resp.StatusCode < 500 {
			logger.Info("转发成功", "method", method, "target", targetURL.String(), "status", resp.StatusCode)
			logger.Debug("响应Header", "header", resp.Header)
			break
		}

		if err != nil && i == retryCount {
			http.Error(w, "转发请求失败: "+err.Error(), http.StatusInternalServerError)
			logger.Error("转发请求失败", "err", err)
			return
		}

	}

	// 确保resp不为nil
	if resp == nil {
		http.Error(w, "转发请求失败: 没有有效的响应", http.StatusInternalServerError)
		logger.Error("转发请求失败: 没有有效的响应")
		return
	}
	defer resp.Body.Close()

	// 将响应头复制到响应写入器
	// 创建一个映射来存储所有响应头
	responseHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		// 将每个响应头添加到响应中
		for _, value := range values {
			w.Header().Add(key, value)
		}
		// 同时将响应头存储在映射中
		responseHeaders[key] = values
	}

	// 添加一个特殊的响应头来传递所有头信息
	if headersJSON, err := json.Marshal(responseHeaders); err == nil {
		w.Header().Set("X-Response-Headers", string(headersJSON))
	}

	// 设置状态码并复制响应体
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, "复制响应体失败: "+err.Error(), http.StatusInternalServerError)
	}
}

// websocketForward 实现WebSocket双向转发功能
// ws1: 客户端WebSocket连接
// ws2: 目标服务器WebSocket连接
func websocketForward(ws1, ws2 *Conn) {
	// 添加到等待组，确保优雅退出时等待所有连接完成
	shutdownWg.Add(1)
	defer shutdownWg.Done()

	var wg sync.WaitGroup
	wg.Add(2)

	// 定义转发函数，用于双向数据转发
	forward := func(dst, src *Conn, name string) {
		defer wg.Done()
		defer func() { _ = dst.Close(); _ = src.Close() }()

		// 设置无超时
		_ = src.SetReadDeadline(time.Time{})
		_ = dst.SetWriteDeadline(time.Time{})

		// 设置ping/pong处理器
		src.SetPingHandler(func(data string) error {
			return dst.WriteControl(PongMessage, []byte(data), time.Now().Add(10*time.Second))
		})
		src.SetPongHandler(func(string) error { return nil })

		// 持续转发消息
		for {
			messageType, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			if err := dst.WriteMessage(messageType, data); err != nil {
				return
			}
		}
	}

	// 启动两个goroutine进行双向转发
	go forward(ws1, ws2, "ws1<-->ws2")
	go forward(ws2, ws1, "ws2<-->ws1")
	wg.Wait()
}

// handleForwardWS 处理WebSocket转发请求
func handleForwardWS(w http.ResponseWriter, r *http.Request) {
	// 获取连接ID
	connectID := r.URL.Query().Get("connect_id")
	if connectID == "" {
		http.Error(w, "缺少connect_id", http.StatusBadRequest)
		return
	}
	defer wsConnParams.Delete(connectID)

	// 获取连接参数
	v, ok := wsConnParams.Load(connectID)
	if !ok {
		http.Error(w, "无效的connect_id", http.StatusBadRequest)
		return
	}
	params := v.(ForwardParams)

	// 升级HTTP连接为WebSocket连接
	wsUpgrade := Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clientConn, err := wsUpgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer clientConn.Close()

	// 解析请求头
	headers := http.Header{}
	if params.Headers != "" {
		var hs []Header
		_ = json.Unmarshal([]byte(params.Headers), &hs)
		for _, h := range hs {
			headers.Set(h.Name, h.Value)
		}
	}

	// 配置WebSocket拨号器
	dialer := Dialer{}
	if params.VerifySSL == "N" {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if params.Timeout > 0 {
		dialer.HandshakeTimeout = time.Duration(params.Timeout) * time.Second
	}

	// 重试机制连接目标WebSocket
	var targetConn *Conn
	var resp *http.Response
	var dialErr error
	for i := 0; i <= params.RetryCount; i++ {
		if i > 0 && params.RetryDelay > 0 {
			time.Sleep(time.Duration(params.RetryDelay) * time.Second)
		}
		targetConn, resp, dialErr = dialer.Dial(params.URL, headers)
		if dialErr == nil {
			break
		}
	}

	if dialErr != nil {
		_ = clientConn.WriteMessage(TextMessage, []byte("连接目标WS失败: "+dialErr.Error()))
		_ = clientConn.Close()
		return
	}

	// 发送响应头信息
	if resp != nil {
		defer resp.Body.Close()
		headerMap := map[string][]string{}
		for k, v := range resp.Header {
			headerMap[k] = v
		}
		headerJson, _ := json.Marshal(headerMap)
		_ = clientConn.WriteMessage(TextMessage, []byte(`{"type":"headers","headers":`+string(headerJson)+`}`))
	}
	defer targetConn.Close()

	// 开始双向转发
	websocketForward(clientConn, targetConn)
}

// handleForwardSSE 处理SSE（Server-Sent Events）转发请求
func handleForwardSSE(w http.ResponseWriter, r *http.Request) {
	// 添加到等待组，确保优雅退出时等待所有连接完成
	shutdownWg.Add(1)
	defer shutdownWg.Done()

	// 获取连接ID
	connectID := r.URL.Query().Get("connect_id")
	if connectID == "" {
		http.Error(w, "缺少connect_id", http.StatusBadRequest)
		return
	}
	defer sseConnParams.Delete(connectID)

	// 获取连接参数
	v, ok := sseConnParams.Load(connectID)
	if !ok {
		http.Error(w, "无效的connect_id", http.StatusBadRequest)
		return
	}
	params := v.(ForwardParams)

	// 创建SSE请求
	req, err := http.NewRequest("GET", params.URL, nil)
	if err != nil {
		http.Error(w, "创建SSE请求失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置请求头
	if params.Headers != "" {
		var hs []Header
		_ = json.Unmarshal([]byte(params.Headers), &hs)
		for _, h := range hs {
			req.Header.Set(h.Name, h.Value)
		}
	}

	// 配置HTTP客户端
	client := &http.Client{}
	tr := &http.Transport{}
	if params.VerifySSL == "N" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client.Transport = tr
	if params.Timeout > 0 {
		client.Timeout = time.Duration(params.Timeout) * time.Second
	}

	// 配置重定向处理
	if params.FollowRedirect == "N" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 重试机制连接目标SSE
	var resp *http.Response
	var sseErr error
	for i := 0; i <= params.RetryCount; i++ {
		if i > 0 && params.RetryDelay > 0 {
			time.Sleep(time.Duration(params.RetryDelay) * time.Second)
		}
		resp, sseErr = client.Do(req)
		if sseErr == nil {
			break
		}
	}

	if sseErr != nil {
		http.Error(w, "连接目标SSE失败: "+sseErr.Error(), http.StatusInternalServerError)
		return
	}

	if resp == nil {
		http.Error(w, "SSE response is null", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 设置SSE响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// 获取响应刷新器
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// 发送响应头信息
	headerMap := map[string][]string{}
	for k, v := range resp.Header {
		headerMap[k] = v
	}
	headerJson, _ := json.Marshal(headerMap)
	_, _ = w.Write([]byte("event: x-web-curl-headers\ndata: " + string(headerJson) + "\n\n"))
	flusher.Flush()

	// 逐行读取并转发SSE消息
	reader := bufio.NewReader(resp.Body)
	var msgLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// 空行，表示一个完整SSE消息结束
			if len(msgLines) > 0 {
				msg := strings.Join(msgLines, "\n")
				_, _ = w.Write([]byte(msg + "\n\n"))
				flusher.Flush()
				msgLines = msgLines[:0]
			}
		} else {
			msgLines = append(msgLines, line)
		}
		if err != nil {
			break
		}
	}
}

// gracefulShutdown 优雅退出处理函数
// 清理所有连接和资源，确保程序安全退出
func gracefulShutdown(ctx context.Context) {
	logger.Info("开始关闭程序...")

	// 清理WebSocket连接参数
	wsConnParams.Range(func(key, value interface{}) bool {
		logger.Info("清理WebSocket连接参数", "connect_id", key)
		wsConnParams.Delete(key)
		return true
	})

	// 清理SSE连接参数
	sseConnParams.Range(func(key, value interface{}) bool {
		logger.Info("清理SSE连接参数", "connect_id", key)
		sseConnParams.Delete(key)
		return true
	})

	// 等待所有goroutine完成
	logger.Info("等待所有goroutine完成...")
	shutdownWg.Wait()

	// 关闭HTTP服务器
	if server != nil {
		logger.Info("关闭HTTP服务器...")
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("关闭HTTP服务器失败", "err", err)
		} else {
			logger.Info("HTTP服务器已关闭")
		}
	}

	logger.Info("优雅退出完成")
}

// recoverMiddleware 全局panic恢复中间件
// 参考gin框架的recovery实现，提供完善的panic处理机制
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 检查是否为连接断开错误
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					var se *os.SyscallError
					if errors.As(ne, &se) {
						seStr := strings.ToLower(se.Error())
						if strings.Contains(seStr, "broken pipe") ||
							strings.Contains(seStr, "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				// 记录panic信息
				stack := getStack(3)
				httpRequest, _ := httputil.DumpRequest(r, false)
				headers := strings.Split(string(httpRequest), "\r\n")
				maskAuthorization(headers)
				headersToStr := strings.Join(headers, "\r\n")

				if brokenPipe {
					logger.Error("disconnect_panic", "err", err, "headers", headersToStr)
				} else {
					logger.Error("panic_recover",
						"time", time.Now().Format("2006-01-02T15:04:05"),
						"headers", headersToStr,
						"err", err,
						"stack", string(stack))
				}

				// 如果连接断开，无法写入响应
				if brokenPipe {
					return
				}

				// 防止写入响应头后再次写入
				if w.Header().Get("Content-Length") == "" {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()
		// 处理 HTTP CONNECT 请求方法
		/*
			协议规范要求 (RFC 7231)：
			CONNECT 请求必须指定 host:port，不能包含路径
			语法：CONNECT host:port HTTP/1.1
			示例：CONNECT example.com:443 HTTP/1.1

			设计本质：
			CONNECT 是建立 TCP 隧道，不是资源访问
			隧道建立后传输的是原始字节流（可能是 TLS/SSL、SSH 等协议）
			路由路径属于应用层概念，与传输层隧道不兼容
		*/
		if r.Method == http.MethodConnect && r.URL.Path == "" {
			logger.Info("HTTP CONNECT PROXY")
			handleConnect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getStack 获取格式化的调用栈信息
func getStack(skip int) []byte {
	buf := new(bytes.Buffer)
	var lines [][]byte
	var lastFile string

	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		_, _ = fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		_, _ = fmt.Fprintf(buf, "\t%s: %s\n", getFunctionName(pc), getSourceLine(lines, line))
	}
	return buf.Bytes()
}

// getFunctionName 获取函数名称
func getFunctionName(pc uintptr) string {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "???"
	}
	name := fn.Name()

	// 移除包路径前缀
	if lastSlash := strings.LastIndexByte(name, '/'); lastSlash >= 0 {
		name = name[lastSlash+1:]
	}
	if period := strings.IndexByte(name, '.'); period >= 0 {
		name = name[period+1:]
	}
	name = strings.ReplaceAll(name, "·", ".")
	return name
}

// getSourceLine 获取源代码行
func getSourceLine(lines [][]byte, n int) []byte {
	n-- // 栈跟踪中行号从1开始，但数组从0开始
	if n < 0 || n >= len(lines) {
		return []byte("???")
	}
	return bytes.TrimSpace(lines[n])
}

// maskAuthorization 隐藏敏感的头信息
func maskAuthorization(headers []string) {
	for idx, header := range headers {
		key, _, _ := strings.Cut(header, ":")
		if strings.EqualFold(key, "Authorization") {
			headers[idx] = key + ": *"
		}
	}
}

// handleTestPanic 测试panic恢复的处理器
func handleTestPanic(_ http.ResponseWriter, r *http.Request) {
	// 根据查询参数决定触发不同类型的panic
	panicType := r.URL.Query().Get("type")

	switch panicType {
	case "string":
		panic("测试字符串panic")
	case "error":
		panic(errors.New("测试错误panic"))
	case "nil":
		var s *string
		*s = "触发空指针panic" // 这会触发panic
	case "array":
		arr := []int{1, 2, 3}
		_ = arr[10] // 数组越界panic
	default:
		panic("默认测试panic")
	}
}

// init 初始化函数，设置Windows系统特定的进程标志
func init() {
	if runtime.GOOS == "windows" {
		DetachedProcess = 0x00000008
		CreateNewProcessGroup = 0x00000200
	}
}

// main 主函数，程序入口点
func main() {
	// 定义命令行参数
	host := flag.String("host", "0.0.0.0", "监听地址")
	port := flag.String("port", "4444", "监听端口")
	webrootFlag := flag.String("webroot", "", "静态文件根目录(为空则用内嵌index.html)")
	daemon := flag.Bool("daemon", false, "后台运行(Linux/MacOS/Windows均支持)")
	echoServer := flag.Bool("echo-server", true, "是否开启一个echoServer模拟Web服务器")
	logLevelFlag := flag.String("log-level", "info", "日志级别: error, info, warn, debug")
	logFileFlag := flag.String("log-file", "", "日志文件路径,未指定则在可执行文件同目录 WebCurl.log")
	logSizeFlag := flag.String("log-size", "100M", "日志文件大小限制,支持单位：K|M|G,默认100M")
	sslCertFlag := flag.String("ssl-cert", "ssl_cert.pem", "SSL证书文件路径")
	sslCertKeyFlag := flag.String("ssl-cert-key", "ssl_cert.key", "SSL证书密钥文件路径")
	genCertDir := flag.String("gen-cert", "", "生成SSL证书文件到指定目录（如 --gen-cert ./certs）")
	certInfoFlag := flag.String("cert-info", "", "自定义证书主题信息,如: /C=CN/ST=Beijing/L=ShunYi/O=Test/OU=Ops/CN=app.example.com")
	uploadDirFlag := flag.String("upload-dir", "", "form-data上传文件保存目录(为空不保存,仅透传)")
	stdoutLogFlag := flag.Bool("stdout-log", true, "是否在控制台打印日志，默认true")
	flag.Parse()

	// 如果指定了生成证书，则生成证书后退出
	if *genCertDir != "" {
		dir := *genCertDir
		if dir == "." || dir == "./" {
			dir, _ = os.Getwd()
		}
		subject := parseCertInfo(*certInfoFlag)
		if reflect.DeepEqual(subject, pkix.Name{}) {
			subject = pkix.Name{
				Organization: []string{"WebCurl Self-Signed Certificate"},
				Country:      []string{"CN"},
				Province:     []string{"Unknown"},
				Locality:     []string{"Unknown"},
				CommonName:   "localhost",
			}
		}
		if err := generateSSLCertificateToDir(dir, subject); err != nil {
			fmt.Printf("生成SSL证书失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SSL证书生成成功: %s/ssl_cert.pem, %s/ssl_cert.key\n", dir, dir)
		fmt.Println("证书有效期: 10年")
		os.Exit(0)
	}

	// 设置全局变量
	webroot = *webrootFlag
	uploadDir = *uploadDirFlag

	// 解析日志大小参数,默认100MB
	maxLogSize := int64(100 * 1024 * 1024)
	if *logSizeFlag != "" {
		size := *logSizeFlag
		unit := size[len(size)-1:]
		num, err := strconv.ParseInt(size[:len(size)-1], 10, 64)
		if err == nil {
			switch strings.ToUpper(unit) {
			case "K":
				maxLogSize = num * 1024
			case "M":
				maxLogSize = num * 1024 * 1024
			case "G":
				maxLogSize = num * 1024 * 1024 * 1024
			default:
				// 默认按MB处理
				maxLogSize = num * 1024 * 1024
			}
		}
	}

	// 初始化日志系统
	setupLogger(*logLevelFlag, *logFileFlag, maxLogSize, *stdoutLogFlag)

	// 检查SSL证书配置
	useSSL := false
	sslCert := *sslCertFlag
	sslCertKey := *sslCertKeyFlag

	// 如果用户没有指定证书路径，尝试在当前目录查找默认证书
	if sslCert == "ssl_cert.pem" && sslCertKey == "ssl_cert.key" {
		exe, err := os.Executable()
		if err == nil {
			dir := filepath.Dir(exe)
			defaultCert := filepath.Join(dir, "ssl_cert.pem")
			defaultKey := filepath.Join(dir, "ssl_cert.key")
			if _, err := os.Stat(defaultCert); err == nil {
				if _, err := os.Stat(defaultKey); err == nil {
					sslCert = defaultCert
					sslCertKey = defaultKey
					useSSL = true
				}
			}
		}
	} else {
		// 用户指定了证书路径，检查文件是否存在
		if _, err := os.Stat(sslCert); err == nil {
			if _, err := os.Stat(sslCertKey); err == nil {
				useSSL = true
			}
		}
	}

	// 打印并记录配置信息
	printAndLogConfig(*host, *port, webroot, *daemon, *echoServer, *logLevelFlag, *logFileFlag, *logSizeFlag, sslCert, sslCertKey, uploadDir, *stdoutLogFlag)

	// 跨平台后台运行
	daemonizeIfNeeded(*daemon)

	// 注册HTTP路由处理器
	// 正常模式
	http.HandleFunc("/", handleRoot)                      // 静态文件服务
	http.HandleFunc("/favicon.ico", handleFavicon)        // favicon图标
	http.HandleFunc("/doc", handleDoc)                    // 文档下载
	http.HandleFunc("/api/forward", handleForward)        // HTTP请求转发
	http.HandleFunc("/api/mode", handleMode)              // 模式检测
	http.HandleFunc("/api/forward-ws", handleForwardWS)   // WebSocket转发
	http.HandleFunc("/api/forward-sse", handleForwardSSE) // SSE转发
	http.HandleFunc("/api/test-panic", handleTestPanic)   // 测试panic恢复

	if *echoServer {
		http.HandleFunc("/api/echo", handleEchoRequest)
		http.HandleFunc("/api/sse/echo", handleSSEEchoRequest)
		http.HandleFunc("/api/ws/echo", handleWebSocketEchoRequest)
		http.HandleFunc("/api/sse/set", handleSSESet)
		http.HandleFunc("/api/ws/set", handleWSSet)
	}

	// 构建监听地址
	addr := fmt.Sprintf("%s:%s", *host, *port)

	// 运行MockServer
	StartMockServer()

	// 运行ToolServer
	StartToolServer()

	// 创建HTTP服务器实例，使用recover中间件包装默认的ServeMux
	server = &http.Server{
		Addr: addr,
		// 使用recover中间件包装
		Handler: recoverMiddleware(http.DefaultServeMux),
	}

	// 设置信号处理，实现优雅退出
	sigChan := make(chan os.Signal, 1)
	// Windows下需要监听更多信号类型
	if runtime.GOOS == "windows" {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	} else {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	}

	// 启动服务器协程
	go func() {
		if useSSL {
			fmt.Printf("HTTPS服务启动在 https://%s\n", addr)
			logger.Info("HTTPS服务启动", "addr", addr, "cert", sslCert, "key", sslCertKey)
			if err := server.ListenAndServeTLS(sslCert, sslCertKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTPS服务启动失败", "err", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("HTTP服务启动在 http://%s\n", addr)
			logger.Info("HTTP服务启动", "addr", addr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTP服务启动失败", "err", err)
				os.Exit(1)
			}
		}
	}()

	// 添加调试信息
	fmt.Printf("\n程序启动完成，按 Ctrl+C 退出; OS:[ %s ]; PID:[ %d ];\n\n", runtime.GOOS, os.Getpid())
	logger.Info(fmt.Sprintf("程序启动完成;OS:[ %s ]; PID:[ %d ];\n\n", runtime.GOOS, os.Getpid()))

	sig := <-sigChan
	logger.Warn("收到退出信号", "signal", sig.String(), "os", runtime.GOOS)

	// 创建超时上下文，30秒内完成优雅退出
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 执行优雅退出
	gracefulShutdown(ctx)

	logger.Info("程序退出")
}

//====================================================================================================
//
// Web EchoServer 服务
//
//====================================================================================================

// 全局存储 SSE/WS 队列
var (
	sseUserQueue = struct {
		sync.Mutex
		Items []any
	}{}
	wsUserQueue = struct {
		sync.Mutex
		Items []any
	}{}
)

// WS react模式下的channel
var wsReactCh = make(chan any, 100)

func handleEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 支持 CORS 预检请求
	if r.Method == "OPTIONS" {
		// w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Response-Status-Code, X-Response-Status-Text, X-Response-Location, X-Response-Headers, X-Response-Type, X-Response-Sleep, X-Response-Body, X-Response-Download")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 1. 解析自定义响应参数，优先Header
	statusCode := http.StatusOK
	if sc := getParam(r, "X-Response-Status-Code"); sc != "" {
		if code, err := parseStatusCode(sc); err == nil {
			statusCode = code
		}
	}

	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			time.Sleep(time.Duration(duration) * time.Millisecond)
		}
	}

	location := getParam(r, "X-Response-Location")
	respType := strings.ToLower(getParam(r, "X-Response-Type"))
	customHeaders := getParam(r, "X-Response-Headers")
	customBodyHeader := getParam(r, "X-Response-Body")
	downloadName := getParam(r, "X-Response-Download")

	// 2. 设置CORS和默认响应头
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 3. 设置Location头
	if location != "" {
		w.Header().Set("Location", location)
	}

	// 4. 解析并设置自定义响应头
	if customHeaders != "" {
		headersMap := map[string]string{}
		err := json.Unmarshal([]byte(customHeaders), &headersMap)
		if err == nil {
			for k, v := range headersMap {
				w.Header().Set(k, v)
			}
		}
	}

	// 5. 设置Content-Type
	if respType == "xml" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	} else if respType == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}

	// 6. 设置下载响应头
	if downloadName != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", downloadName))
	}

	// 7. 写响应状态码
	w.WriteHeader(statusCode)

	// HEAD 请求只返回响应头，不写响应体
	if r.Method == http.MethodHead {
		return
	}

	// 8. 响应体输出
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
		} else {
			_, _ = w.Write(decodedBody)
			return
		}
	}

	// 9. 处理请求
	response, _ := processRequest(r)
	if respType == "xml" {
		if xmlData, err := toXML(response); err == nil {
			_, _ = w.Write(xmlData)
		} else {
			_, _ = w.Write([]byte("<error>xml encode error</error>"))
		}
	} else if respType == "text" {
		_, _ = w.Write([]byte(response.String()))
	} else {
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Error("JSON encoding error", "err_msg", err)
		}
	}
}

// SSE Echo 处理
func handleSSEEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 记录连接建立
	logger.Info("SSE连接建立",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"url", r.URL.String(),
		"user_agent", r.UserAgent(),
	)

	// 记录连接断开
	defer func() {
		logger.Info("SSE连接断开",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
		)
	}()

	// 支持 CORS 预检请求
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Response-Status-Code, X-Response-Status-Text, X-Response-Location, X-Response-Headers, X-Response-Type, X-Response-Sleep, X-Response-Body, X-Response-Sse-Count, X-Response-Mode")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 1. 解析自定义响应参数，优先Header
	statusCode := http.StatusOK
	if sc := getParam(r, "X-Response-Status-Code"); sc != "" {
		if code, err := parseStatusCode(sc); err == nil {
			statusCode = code
		}
	}

	location := getParam(r, "X-Response-Location")

	customBodyHeader := getParam(r, "X-Response-Body")
	sseCount := 100
	if cnt := getParam(r, "X-Response-Sse-Count"); cnt != "" {
		if c, err := strconv.Atoi(cnt); err == nil && c > 0 {
			sseCount = c
		}
	}
	sleepMs := 500
	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			sleepMs = duration
		}
	}

	mode := strings.ToLower(getParam(r, "X-Response-Mode"))
	if mode == "" {
		mode = "default"
	}

	// 2. 设置CORS和SSE响应头
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if location != "" {
		w.Header().Set("Location", location)
	}

	customHeaders := getParam(r, "X-Response-Headers")
	if customHeaders != "" {
		headersInfo, err := base64.StdEncoding.DecodeString(customHeaders)
		if err != nil {
			logger.Error("X-Response-Headers base64 decoding failed", "error", err)
			return
		}
		logger.Debug(string(headersInfo))
		headersMap := map[string]string{}
		err = json.Unmarshal(headersInfo, &headersMap)
		if err != nil {
			logger.Error("Unmarshal X-Response-Headers failed", "error", err)
			return
		}
		for k, v := range headersMap {
			w.Header().Set(k, v)
		}
	}

	w.WriteHeader(statusCode)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// 3. 处理自定义Body（优先级最高）
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
			return
		}
		for i := 0; i < sseCount; i++ {
			logger.Debug("customBodyHeader", "data", string(decodedBody))
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}

	// 4. 处理请求体和回显
	response, _ := processRequest(r)
	if mode == "react" {
		// SSE 不支持 react，自动降级为 user
		mode = "user"
	}
	if mode == "user" {
		// user模式，从队列取
		sseUserQueue.Lock()
		items := append([]any(nil), sseUserQueue.Items...)
		sseUserQueue.Unlock()
		for i := 0; i < sseCount && i < len(items); i++ {
			msgBytes, _ := json.Marshal(items[i])
			logger.Debug(string(msgBytes))
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else {
		// default模式，恢复原有逻辑
		for i := 0; i < sseCount; i++ {
			msg := map[string]any{
				"method":    response.Method,
				"url":       response.URL,
				"headers":   response.Headers,
				"body":      response.Body,
				"sse_index": i + 1,
				"sse_count": sseCount,
			}
			event := "message"
			if i%2 == 0 {
				event = "huang"
			}

			msgBytes, _ := json.Marshal(msg)
			_, _ = fmt.Fprintf(w, "id: %d\n", i)
			_, _ = fmt.Fprintf(w, "event: %s\n", event)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msgBytes)
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}
}

// WebSocket Echo 处理
func handleWebSocketEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 记录连接建立
	logger.Info("WebSocket连接建立",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"url", r.URL.String(),
		"user_agent", r.UserAgent(),
	)

	upgrader := Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	responseHeader := http.Header{}
	customHeaders := getParam(r, "X-Response-Headers")
	if customHeaders != "" {
		headersInfo, err := base64.StdEncoding.DecodeString(customHeaders)
		if err != nil {
			logger.Error("X-Response-Headers base64 decoding failed", "error", err)
			return
		}
		logger.Debug(string(headersInfo))
		headersMap := map[string]string{}
		err = json.Unmarshal(headersInfo, &headersMap)
		if err != nil {
			logger.Error("Unmarshal X-Response-Headers failed", "error", err)
			return
		}
		for k, v := range headersMap {
			responseHeader.Set(k, v)
		}
	}

	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		logger.Error("WebSocket升级失败",
			"remote_addr", r.RemoteAddr,
			"error", err,
		)
		logger.Error("WebSocket upgrade error", "error_msg", err)
		return
	}
	defer func() {
		logger.Info("WebSocket连接断开",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
		)
		_ = conn.Close()
	}()

	// 设置 Ping 处理函数
	conn.SetPingHandler(func(appData string) error {
		logger.Debug("收到 Ping,回复 Pong:", "data", appData)
		// 可以在此处添加自定义逻辑
		return nil
	})

	// 设置 Pong 处理函数
	conn.SetPongHandler(func(appData string) error {
		logger.Debug("收到 Pong，连接正常:", "data", appData)
		// 更新连接的最后活动时间
		return nil
	})

	go func() {
		// 定期发送 Ping 帧
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				logger.Debug("send_ping")
				// 发送 Ping 帧
				if err := conn.WriteControl(PingMessage, []byte("my-heartbeat"), time.Now().Add(10*time.Second)); err != nil {
					logger.Error("send ping failed", "error_msg", err)
					return
				}
			}
		}
	}()

	// 解析自定义参数
	customBodyHeader := getParam(r, "X-Response-Body")
	wsCount := 100
	if cnt := getParam(r, "X-Response-Websocket-Count"); cnt != "" {
		if c, err := strconv.Atoi(cnt); err == nil && c > 0 {
			wsCount = c
		}
	}
	sleepMs := 500
	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			sleepMs = duration
		}
	}

	mode := strings.ToLower(getParam(r, "X-Response-Mode"))
	if mode == "" {
		mode = "default"
	}

	// WebSocket只支持GET方法，其他方法通过header传递
	// 处理自定义Body（优先级最高）
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
			return
		}
		for i := 0; i < wsCount; i++ {
			err := conn.WriteMessage(TextMessage, decodedBody)
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}

	// 处理请求体和回显
	response, _ := processRequest(r)
	if mode == "react" {
		// 新增：前端发消息，服务端收到后写入 wsReactCh
		go func() {
			for {
				type_, msg, err := conn.ReadMessage()
				if err != nil {
					logger.Info("WebSocket客户端断开",
						"remote_addr", r.RemoteAddr,
						"error", err,
					)
					return
				}
				if type_ == TextMessage || type_ == BinaryMessage {
					logger.Info("WebSocket收到客户端消息",
						"remote_addr", r.RemoteAddr,
						"message_type", type_,
						"message_length", len(msg),
					)
					wsReactCh <- string(msg)
				}
			}
		}()
		for i := 0; i < wsCount; i++ {
			select {
			case v := <-wsReactCh:
				msgBytes, _ := json.Marshal(v)
				err := conn.WriteMessage(TextMessage, msgBytes)
				if err != nil {
					logger.Error("WebSocket写入失败",
						"remote_addr", r.RemoteAddr,
						"error", err,
					)
					logger.Error("WebSocket write error", "error_msg", err)
					return
				}
			case <-r.Context().Done():
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else if mode == "user" {
		go func() {
			defer conn.Close()
			for {
				// 注意：此处必须调用 ReadMessage 或类似方法
				// 否则控制帧（如 Pong）可能不会被触发
				_, _, err := conn.ReadMessage()
				if err != nil {
					logger.Error("read msg error", "error_msg", err)
					return
				}
			}
		}()

		wsUserQueue.Lock()
		items := append([]any(nil), wsUserQueue.Items...)
		wsUserQueue.Unlock()
		for i := 0; i < wsCount && i < len(items); i++ {
			msgBytes, _ := json.Marshal(items[i])
			err := conn.WriteMessage(TextMessage, msgBytes)
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else {

		go func() {
			defer conn.Close()
			for {
				// 注意：此处必须调用 ReadMessage 或类似方法
				// 否则控制帧（如 Pong）可能不会被触发
				_, _, err := conn.ReadMessage()
				if err != nil {
					logger.Error("WebSocket read error", "error_msg", err)
					return
				}
				// 处理消息内容
			}
		}()

		data, err := embeddedFS.ReadFile("favicon.ico")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// default模式，恢复原有逻辑
		for i := 0; i < wsCount; i++ {
			msg := map[string]any{
				"method":   response.Method,
				"url":      response.URL,
				"headers":  response.Headers,
				"body":     response.Body,
				"ws_index": i + 1,
				"ws_count": wsCount,
			}
			msgBytes, _ := json.Marshal(msg)
			var err error
			if i%2 == 0 {
				err = conn.WriteMessage(TextMessage, msgBytes)
			} else {
				err = conn.WriteMessage(BinaryMessage, data)
			}
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}
}

// 处理 CONNECT 请求
func handleConnect(w http.ResponseWriter, r *http.Request) {
	// 使用示例:
	// yum -y install nmap-ncat
	// ssh -o "ProxyCommand ncat --proxy 192.168.150.110:8080 --proxy-type http %h %p" root@192.168.150.88
	// curl -k -x http://192.168.150.110:8080 https://192.168.150.88:6443

	// 获取目标地址 (host:port)
	target := r.URL.Host
	logger.Info("Connect Proxy:", "target", target)
	if _, _, err := net.SplitHostPort(target); err != nil {
		// 补充默认端口
		if strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "443")
			logger.Info("Connect Proxy Https:", "target", target)
			fmt.Println("target-A->:", target)
		} else {
			target = net.JoinHostPort(target, "80")
			logger.Info("Connect Proxy Http:", "target", target)
		}
	}

	// 创建到目标服务器的连接
	dialer := net.Dialer{Timeout: 10 * time.Second}
	targetConn, err := dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "Failed to connect to target: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	// Hijack 获取原始客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 发送 CONNECT 成功响应
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	logger.Info("Connection established", "target", target)

	// 启动双向数据转发
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 客户端 -> 目标服务器
	go func() {
		defer cancel()
		_, _ = io.Copy(targetConn, clientConn)
	}()

	// 目标服务器 -> 客户端
	go func() {
		defer cancel()
		_, _ = io.Copy(clientConn, targetConn)
	}()

	// 等待连接结束
	<-ctx.Done()
	logger.Info("Connection closed", "target", target)
}

func processRequest(r *http.Request) (*EchoResponse, int) {
	// 获取请求完整URL
	fullURL := getFullURL(r)

	// 处理请求头
	var headers []HeaderKV
	for k, v := range r.Header {
		headers = append(headers, HeaderKV{Key: k, Value: strings.Join(v, ", ")})
	}

	// 检测请求体类型并处理
	contentType := r.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)

	// 处理不同类型请求体
	var bodyContent any
	bodySize := int64(0)

	// 当请求包含Body时（POST, PUT, PATCH等）
	if r.Body != http.NoBody {
		// 保存原始请求体以备后续读取
		bodyData, _ := io.ReadAll(r.Body)
		bodySize = int64(len(bodyData))
		r.Body = io.NopCloser(bytes.NewReader(bodyData))

		switch {
		case strings.HasPrefix(mediaType, "multipart/form-data"):
			bodyContent = processMultipartForm(r)
		case strings.HasPrefix(mediaType, "application/x-www-form-urlencoded"):
			bodyContent = processForm(r)
		case isTextContentType(mediaType) || contentType == "":
			bodyContent = string(bodyData)
		default:
			// 二进制或未知类型
			bodyContent = &BinaryBody{
				Size:       bodySize,
				SizeHuman:  formatSize(bodySize),
				ContentHex: fmt.Sprintf("%x", bodyData[:min(len(bodyData), 16)]),
			}
		}
	} else {
		bodyContent = nil
	}

	return &EchoResponse{
		Method:  r.Method,
		URL:     fullURL,
		Headers: headers,
		Body:    bodyContent,
	}, http.StatusOK
}

// EchoResponse Echo响应结构
type EchoResponse struct {
	XMLName xml.Name   `json:"-" xml:"response"`
	Method  string     `json:"method" xml:"method"`
	URL     string     `json:"url" xml:"url"`
	Headers []HeaderKV `json:"headers" xml:"headers>header"`
	Body    any        `json:"body,omitempty" xml:"body,omitempty"`
}

type HeaderKV struct {
	Key   string `json:"key" xml:"key,attr"`
	Value string `json:"value" xml:",chardata"`
}

// FileMetaInfo 文件信息结构
type FileMetaInfo struct {
	XMLName     xml.Name `json:"-" xml:"file"`
	Filename    string   `json:"filename" xml:"filename"`
	Size        int64    `json:"size" xml:"size"`
	SizeHuman   string   `json:"size_human" xml:"size_human"`
	ContentType string   `json:"content_type" xml:"content_type"`
}

// FormField 表单字段结构
type FormField struct {
	XMLName xml.Name `json:"-" xml:"field"`
	Name    string   `json:"name" xml:"name"`
	Value   any      `json:"value" xml:"value"`
}

// BinaryBody 二进制响应结构
type BinaryBody struct {
	XMLName    xml.Name `json:"-" xml:"binary"`
	Size       int64    `json:"size" xml:"size"`
	SizeHuman  string   `json:"size_human" xml:"size_human"`
	ContentHex string   `json:"content_hex" xml:"content_hex"`
}

// 处理multipart/form-data请求
func processMultipartForm(r *http.Request) map[string]any {
	// 解析multipart表单
	err := r.ParseMultipartForm(maxMemory)
	if err != nil {
		return map[string]any{"error": "Failed to parse form-data: " + err.Error()}
	}

	formContent := make(map[string]any)
	formContent["fields"] = []FormField{}
	formContent["files"] = []FileMetaInfo{}

	// 处理文本字段
	for name, values := range r.MultipartForm.Value {
		for _, value := range values {
			formContent["fields"] = append(formContent["fields"].([]FormField), FormField{
				Name:  name,
				Value: value,
			})
		}
	}

	// 处理文件字段
	for _, headers := range r.MultipartForm.File {
		for _, header := range headers {

			// 获取文件信息
			fileInfo := FileMetaInfo{
				Filename:    header.Filename,
				Size:        header.Size,
				SizeHuman:   formatSize(header.Size),
				ContentType: header.Header.Get("Content-Type"),
			}

			formContent["files"] = append(formContent["files"].([]FileMetaInfo), fileInfo)

			// 如指定了uploadDir且目录存在,则保存文件
			if uploadDir != "" {
				if info, err := os.Stat(uploadDir); err == nil && info.IsDir() {
					file, err := header.Open()
					if err == nil {
						outPath := filepath.Join(uploadDir, header.Filename)
						outFile, err := os.Create(outPath)
						if err == nil {
							_, _ = io.Copy(outFile, file)
							_ = outFile.Close()
						}
						_ = file.Close()
					}
				}
			}
		}
	}

	return formContent
}

// 处理x-www-form-urlencoded请求
func processForm(r *http.Request) map[string]any {
	err := r.ParseForm()
	if err != nil {
		return map[string]any{"error": "Failed to parse form: " + err.Error()}
	}

	formContent := make(map[string]any)
	formContent["fields"] = []FormField{}

	for name, values := range r.Form {
		for _, value := range values {
			formContent["fields"] = append(formContent["fields"].([]FormField), FormField{
				Name:  name,
				Value: value,
			})
		}
	}

	return formContent
}

// 获取完整URL（包含查询参数）
func getFullURL(r *http.Request) string {
	u := r.URL
	urlObj := &url.URL{
		Scheme:   "http", // 实际环境中应考虑HTTPS
		Host:     r.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}
	return urlObj.String()
}

// 检测是否为文本内容类型
func isTextContentType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" ||
		mediaType == "application/xml" ||
		mediaType == "application/javascript" ||
		mediaType == "application/xhtml+xml"
}

// 格式化字节大小
func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}

// 解析状态码
func parseStatusCode(s string) (int, error) {
	var code int
	_, err := fmt.Sscanf(s, "%d", &code)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("invalid status code")
	}
	return code, nil
}

// toXML使用encoding/xml
func toXML(v any) ([]byte, error) {
	return xml.MarshalIndent(v, "", "  ")
}

func (e *EchoResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Method: %s\n", e.Method))
	sb.WriteString(fmt.Sprintf("URL: %s\n", e.URL))
	sb.WriteString("\n--- Headers ---\n")
	for _, h := range e.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", h.Key, h.Value))
	}

	sb.WriteString("\n--- Body ---\n")
	if e.Body != nil {
		switch v := e.Body.(type) {
		case string:
			sb.WriteString(v)
		default:
			bodyBytes, err := json.MarshalIndent(e.Body, "", "  ")
			if err != nil {
				sb.WriteString(fmt.Sprintf("[Could not serialize body: %v]", err))
			} else {
				sb.Write(bodyBytes)
			}
		}
	} else {
		sb.WriteString("[empty]")
	}
	return sb.String()
}

// 获取参数优先级：Header > URL参数
func getParam(r *http.Request, key string) string {
	h := r.Header.Get(key)
	if h != "" {
		return h
	}
	return r.URL.Query().Get(key)
}

// /api/sse/set
func handleSSESet(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	sseUserQueue.Lock()
	sseUserQueue.Items = nil
	for _, item := range items {
		if v, ok := item["value"]; ok {
			sseUserQueue.Items = append(sseUserQueue.Items, v)
		}
	}
	sseUserQueue.Unlock()
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

// /api/ws/set
func handleWSSet(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	wsUserQueue.Lock()
	wsUserQueue.Items = nil
	for _, item := range items {
		if v, ok := item["value"]; ok {
			wsUserQueue.Items = append(wsUserQueue.Items, v)
		}
	}
	wsUserQueue.Unlock()
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}
