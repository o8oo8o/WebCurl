package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 配置结构体
// 覆盖 listen, static, routes

// ListenConfig 描述单个监听端口及协议的行为。
type ListenConfig struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Protocols []string `json:"protocols,omitempty"`
	CertFile  string   `json:"cert_file,omitempty"`
	KeyFile   string   `json:"key_file,omitempty"`
}

// StaticConfig 定义静态目录挂载的路径及行为。
type StaticConfig struct {
	Mount        string            `json:"mount"`
	Dir          string            `json:"dir"`
	Download     bool              `json:"download"`
	IndexFiles   []string          `json:"index_files,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	AllowMethods []string          `json:"allow_methods,omitempty"`
}

// RouteMatchCondition 控制请求在命中前需要满足的条件集合。
type RouteMatchCondition struct {
	Headers map[string]string `json:"headers,omitempty"`
	Query   map[string]string `json:"query,omitempty"`
	Body    map[string]any    `json:"body,omitempty"`
}

// CookieConf 用于在配置文件中以下划线风格描述 Cookie。
type CookieConf struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`   // 建议使用 RFC3339 格式字符串
	MaxAge   int    `json:"max_age,omitempty"`   // 单位：秒
	Secure   bool   `json:"secure,omitempty"`    // 是否仅在 HTTPS 传输
	HTTPOnly bool   `json:"http_only,omitempty"` // 是否前端 JS 不可读
	SameSite string `json:"same_site,omitempty"` // lax/strict/none
}

// RouteResponse 表示一条响应分支，支持 when/file/template。
type RouteResponse struct {
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     any               `json:"body"`
	File     string            `json:"file,omitempty"`
	DelayMs  int               `json:"delay_ms,omitempty"`
	Cookies  []CookieConf      `json:"cookies,omitempty"`
	When     map[string]any    `json:"when,omitempty"`
	Template string            `json:"template,omitempty"`
}

// RouteRule 定义单条 Mock API，包括请求方法、路径和响应集合。
type RouteRule struct {
	Method    string               `json:"method"`
	Path      string               `json:"path"`
	Match     *RouteMatchCondition `json:"match,omitempty"`
	Extract   *ExtractConf         `json:"extract,omitempty"`
	When      map[string]any       `json:"when,omitempty"`
	Responses []RouteResponse      `json:"responses"`
}

// ExtractConf 描述如何从请求中提取变量。
type ExtractConf struct {
	From  string            `json:"from"`
	Rules map[string]string `json:"rules"`
}

// WebsocketConfig 定义单个 WebSocket Mock 的剧本。
type WebsocketConfig struct {
	Path   string               `json:"path"`
	Script []map[string]any     `json:"script"`
	Match  *RouteMatchCondition `json:"match,omitempty"`
}

// SseEvent 表示 SSE 推送的单条消息。
type SseEvent struct {
	ID    string `json:"id,omitempty"`
	Event string `json:"event,omitempty"`
	Data  string `json:"data"`
	Retry int    `json:"retry,omitempty"`
	Delay int    `json:"delay_ms,omitempty"`
}

// SseConfig 定义一个 SSE 流的所有事件及控制参数。
type SseConfig struct {
	Path   string     `json:"path"`
	Events []SseEvent `json:"events"`
	Repeat bool       `json:"repeat,omitempty"`
	// 扩展：支持 method/match/headers/status/cookies
	Method  string               `json:"method,omitempty"`
	Match   *RouteMatchCondition `json:"match,omitempty"`
	Headers map[string]string    `json:"headers,omitempty"`
	Status  int                  `json:"status,omitempty"`
	Cookies []CookieConf         `json:"cookies,omitempty"`
}

// MockConfig 是整体配置的根节点，聚合所有特性。
type MockConfig struct {
	Listen     []ListenConfig    `json:"listen"`
	Static     []StaticConfig    `json:"static"`
	Routes     []RouteRule       `json:"routes"`
	Websockets []WebsocketConfig `json:"websockets,omitempty"`
	Sse        []SseConfig       `json:"sse,omitempty"`
}

// LoadConfig 从磁盘读取 JSON 配置并解析为 MockConfig。
func LoadConfig(path string) (*MockConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg MockConfig
	err = json.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

//go:embed mock.html
var mockIndex []byte

type serverItem struct {
	srv       *http.Server
	https     bool
	cert, key string
}

// RequestLog 表示一条请求日志记录
type RequestLog struct {
	Time    string            `json:"time"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Status  int               `json:"status,omitempty"`
}

// WSHub 管理 WebSocket 客户端连接和消息广播
type WSHub struct {
	clients    map[*Conn]bool
	broadcast  chan RequestLog
	register   chan *Conn
	unregister chan *Conn
	mu         sync.RWMutex
}

var wsHub = &WSHub{
	clients:    make(map[*Conn]bool),
	broadcast:  make(chan RequestLog, 100),
	register:   make(chan *Conn),
	unregister: make(chan *Conn),
}

// Run 启动 WebSocket Hub 的事件循环
func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			slog.Debug("WebSocket client connected", "total", len(h.clients))
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.mu.Unlock()
			slog.Debug("WebSocket client disconnected", "total", len(h.clients))
		case log := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				if err := client.WriteJSON(log); err != nil {
					client.Close()
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastRequest 广播请求日志到所有连接的客户端
func (h *WSHub) BroadcastRequest(log RequestLog) {
	select {
	case h.broadcast <- log:
	default:
	}
}

// AppManager 负责读取配置、生命周期管理以及热重载。
type AppManager struct {
	mu        sync.Mutex
	cfgPath   string
	configRaw []byte
	cfg       *MockConfig
	servers   []serverItem
	running   bool
}

// NewAppManager 根据给定配置路径构造 AppManager。
func NewAppManager(path string) *AppManager {
	return &AppManager{cfgPath: path}
}

// loadConfigFromDisk 读取配置文件原始字节，若不存在则使用空 JSON。
func (m *AppManager) loadConfigFromDisk() error {
	raw, err := os.ReadFile(m.cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			raw = []byte("{}")
		} else {
			return err
		}
	}
	m.configRaw = raw
	return nil
}

// parseConfig 将原始 JSON 解析为 MockConfig。
func (m *AppManager) parseConfig(raw []byte) (*MockConfig, error) {
	var cfg MockConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ensureConfig 确保 configRaw 已被填充。
func (m *AppManager) ensureConfig() error {
	if len(m.configRaw) > 0 {
		return nil
	}
	return m.loadConfigFromDisk()
}

// checkPortAvailable 检查端口是否可用
func checkPortAvailable(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	listener.Close()
	return nil
}

// Start 根据当前配置启动所有监听服务。
func (m *AppManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return errors.New("servers already running")
	}
	if err := m.ensureConfig(); err != nil {
		return err
	}
	cfg, err := m.parseConfig(m.configRaw)
	if err != nil {
		return err
	}
	return m.startWithConfigLocked(cfg, m.configRaw)
}

// startWithConfigLocked 按给定配置启动实际 HTTP 服务。
func (m *AppManager) startWithConfigLocked(cfg *MockConfig, raw []byte) error {
	router := BuildRouter(cfg)
	var servers []serverItem
	var occupiedPorts []string
	for _, l := range cfg.Listen {
		addr := fmt.Sprintf("%s:%d", l.Host, l.Port)
		slog.Debug("检查端口可用性", "addr", addr)
		if err := checkPortAvailable(addr); err != nil {
			occupiedPorts = append(occupiedPorts, strconv.Itoa(l.Port))
			slog.Warn("端口已被占用", "port", l.Port, "error", err)
			continue
		}
		slog.Debug("端口可用", "port", l.Port)
		hasHTTPS := slices.ContainsFunc(l.Protocols, func(p string) bool {
			return strings.EqualFold(p, "https")
		})
		srv := &http.Server{Addr: addr, Handler: router}
		item := serverItem{srv: srv, https: hasHTTPS, cert: l.CertFile, key: l.KeyFile}
		servers = append(servers, item)
		go func(it serverItem) {
			if it.https {
				slog.Info("Listening (HTTPS)", "addr", it.srv.Addr)
				if it.cert == "" || it.key == "" {
					slog.Error("HTTPS 需要配置 cert_file 与 key_file")
					return
				}
				if err := it.srv.ListenAndServeTLS(it.cert, it.key); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("HTTPS 启动失败", "error", err)
				}
			} else {
				slog.Info("Listening (HTTP)", "addr", it.srv.Addr)
				if err := it.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("HTTP 启动失败", "error", err)
				}
			}
		}(item)
	}
	if len(occupiedPorts) > 0 && len(servers) == 0 {
		return fmt.Errorf("端口被占用: %s", strings.Join(occupiedPorts, ", "))
	}
	if len(occupiedPorts) > 0 {
		slog.Warn("部分端口被占用", "ports", strings.Join(occupiedPorts, ", "))
	}
	if len(servers) == 0 {
		return errors.New("没有可用的监听配置")
	}
	m.cfg = cfg
	m.configRaw = raw
	m.servers = servers
	m.running = true
	slog.Info("Mock servers started")
	return nil
}

// Stop 关闭所有监听的 mock server。
func (m *AppManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

// stopLocked 在持有锁的前提下关闭服务器。
func (m *AppManager) stopLocked() error {
	if !m.running {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, it := range m.servers {
		if err := it.srv.Shutdown(ctx); err != nil {
			slog.Error("关闭失败", "addr", it.srv.Addr, "error", err)
		} else {
			slog.Info("已关闭", "addr", it.srv.Addr)
		}
	}
	m.servers = nil
	m.running = false
	return nil
}

// Reload 将新配置写入磁盘并重新加载。
func (m *AppManager) Reload(raw []byte) error {
	cfg, err := m.parseConfig(raw)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	currentPorts := make(map[string]bool)
	if m.running {
		for _, s := range m.servers {
			currentPorts[s.srv.Addr] = true
		}
	}
	var occupiedPorts []string
	for _, l := range cfg.Listen {
		addr := fmt.Sprintf("%s:%d", l.Host, l.Port)
		if currentPorts[addr] {
			continue
		}
		if err := checkPortAvailable(addr); err != nil {
			occupiedPorts = append(occupiedPorts, strconv.Itoa(l.Port))
		}
	}
	if len(occupiedPorts) > 0 {
		return fmt.Errorf("端口被占用: %s", strings.Join(occupiedPorts, ", "))
	}
	if err := os.WriteFile(m.cfgPath, raw, 0644); err != nil {
		return err
	}
	if err := m.stopLocked(); err != nil {
		return err
	}
	return m.startWithConfigLocked(cfg, raw)
}

// Restart 基于缓存的 configRaw 完全重启服务。
func (m *AppManager) Restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.configRaw) == 0 {
		if err := m.ensureConfig(); err != nil {
			return err
		}
	}
	cfg, err := m.parseConfig(m.configRaw)
	if err != nil {
		return err
	}
	if err := m.stopLocked(); err != nil {
		return err
	}
	return m.startWithConfigLocked(cfg, m.configRaw)
}

// Status 返回当前运行状态及原始配置。
func (m *AppManager) Status() (running bool, raw string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.configRaw) == 0 {
		if err := m.ensureConfig(); err != nil {
			return m.running, "", err
		}
	}
	return m.running, string(m.configRaw), nil
}

// SaveConfig 仅保存配置并刷新内存态，不触发重启。
func (m *AppManager) SaveConfig(raw []byte) error {
	if err := os.WriteFile(m.cfgPath, raw, 0644); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configRaw = raw
	cfg, err := m.parseConfig(raw)
	if err != nil {
		return err
	}
	m.cfg = cfg
	return nil
}

// staticHandler 根据 StaticConfig 返回一个静态资源处理器。
func staticHandler(static StaticConfig) http.Handler {
	fsys := os.DirFS(static.Dir)
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// method allow检查
		if len(static.AllowMethods) > 0 {
			if !slices.ContainsFunc(static.AllowMethods, func(m string) bool {
				return strings.EqualFold(m, r.Method)
			}) {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}
		// 静态目录头
		for k, v := range static.Headers {
			w.Header().Set(k, v)
		}
		if static.Download {
			w.Header().Set("Content-Disposition", "attachment")
		}
		// 调用静态资源
		fileServer.ServeHTTP(w, r)
	})
}

// methodHasBody 判断 HTTP 方法是否允许请求体。
func methodHasBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// --- 模板替换：支持所有命名空间（param, query, header, body, extract，form）变量 --- //
// 支持强类型占位符：{{@int:key}} / {{@float:key}} / {{@bool:key}}。
// - 若整串仅为一个强类型占位符，则返回对应 Go 类型（int64/float64/bool），用于生成 JSON 数字/布尔；
// - 若与其他文本混用，则按字符串替换。
var castPlaceholderRe = regexp.MustCompile(`{{@([a-zA-Z]+):([^}]+)}}`)

// funcPlaceholderRe 匹配 {{func.xxx()}} 或 {{func.xxx(args)}}
var funcPlaceholderRe = regexp.MustCompile(`{{func\.([a-zA-Z_][a-zA-Z0-9_]*)\(([^)]*)\)}}`)

// callFunc 根据函数名和参数调用对应的内置函数
func callFunc(name, args string) string {
	switch name {
	case "uuid":
		return generateUUID()
	case "timestamp":
		return fmt.Sprint(time.Now().Unix())
	case "timestamp_sec":
		return fmt.Sprint(time.Now().Unix())
	case "timestamp_ms":
		return fmt.Sprint(time.Now().UnixMilli())
	case "now":
		format := args
		if format == "" {
			format = "2006-01-02 15:04:05"
		}
		return time.Now().Format(format)
	case "date":
		format := args
		if format == "" {
			format = "2006-01-02"
		}
		return time.Now().Format(format)
	case "time":
		format := args
		if format == "" {
			format = "15:04:05"
		}
		return time.Now().Format(format)
	case "random_int":
		min, max := 0, 1000
		if args != "" {
			parts := strings.Split(args, ",")
			if len(parts) >= 1 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
					min = v
				}
			}
			if len(parts) >= 2 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					max = v
				}
			}
		}
		return fmt.Sprint(min + int(time.Now().UnixNano()%(int64(max-min+1))))
	case "random_string":
		length := 16
		if args != "" {
			if v, err := strconv.Atoi(strings.TrimSpace(args)); err == nil {
				length = v
			}
		}
		return generateRandomString(length)
	default:
		return "{{func." + name + "()}}"
	}
}

// generateUUID 生成一个 UUID v4 字符串
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateRandomString 生成指定长度的随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano()+int64(i))%len(charset)]
	}
	return string(b)
}

// replaceVars 递归遍历对象并替换字符串中的模板占位符。
func replaceVars(obj any, vars map[string]string) any {
	// 深层递归所有json结构与string，支持map、slice、string
	switch val := obj.(type) {
	case string:
		out := val

		// 1) 先处理强类型占位符 {{@int:key}} / {{@float:key}} / {{@bool:key}}
		matches := castPlaceholderRe.FindAllStringSubmatch(out, -1)
		if len(matches) > 0 {
			// 1.1 如果整串就是单个强类型占位符，则直接返回对应类型
			if len(matches) == 1 && matches[0][0] == out {
				typ := strings.ToLower(matches[0][1])
				key := matches[0][2]
				raw := vars[key]
				switch typ {
				case "int":
					if iv, err := strconv.ParseInt(raw, 10, 64); err == nil {
						return iv
					}
				case "float":
					if fv, err := strconv.ParseFloat(raw, 64); err == nil {
						return fv
					}
				case "bool":
					if bv, err := strconv.ParseBool(raw); err == nil {
						return bv
					}
				}
				// 解析失败则退化为普通字符串处理，继续向下执行
			} else {
				// 1.2 混在文本中的强类型占位符：用转换后的字符串值替换
				for _, m := range matches {
					full := m[0]
					typ := strings.ToLower(m[1])
					key := m[2]
					raw := vars[key]
					rep := raw
					switch typ {
					case "int":
						if iv, err := strconv.ParseInt(raw, 10, 64); err == nil {
							rep = fmt.Sprint(iv)
						}
					case "float":
						if fv, err := strconv.ParseFloat(raw, 64); err == nil {
							rep = fmt.Sprint(fv)
						}
					case "bool":
						if bv, err := strconv.ParseBool(raw); err == nil {
							rep = fmt.Sprint(bv)
						}
					}
					out = strings.ReplaceAll(out, full, rep)
				}
			}
		}

		// 2) 处理函数占位符 {{func.xxx()}} / {{func.xxx(args)}}
		funcMatches := funcPlaceholderRe.FindAllStringSubmatch(out, -1)
		for _, m := range funcMatches {
			full := m[0]
			funcName := m[1]
			funcArgs := m[2]
			result := callFunc(funcName, funcArgs)
			out = strings.ReplaceAll(out, full, result)
		}

		// 3) 最后处理普通 {{key}} 占位符（全部按字符串处理）
		for k, v := range vars {
			pat := "{{" + k + "}}"
			if strings.Contains(out, pat) {
				slog.Debug("[REPLACE] found", "pattern", pat, "value", v, "output", out)
			}
			out = strings.ReplaceAll(out, pat, v)
		}
		return out
	case map[string]any:
		newMap := make(map[string]any, len(val))
		for k, v2 := range val {
			newMap[k] = replaceVars(v2, vars)
		}
		return newMap
	case []any:
		for i, vv := range val {
			val[i] = replaceVars(vv, vars)
		}
		return val
	default:
		return val
	}
}

// replaceStringVars 仅处理 string 的模板替换。
func replaceStringVars(s string, vars map[string]string) string {
	if s == "" {
		return s
	}
	val := replaceVars(s, vars)
	if out, ok := val.(string); ok {
		return out
	}
	return fmt.Sprint(val)
}

// applyCookieTemplates 对 Cookie 的各字段执行模板替换。
func applyCookieTemplates(src http.Cookie, vars map[string]string) *http.Cookie {
	c := src
	c.Name = replaceStringVars(c.Name, vars)
	c.Value = replaceStringVars(c.Value, vars)
	c.Path = replaceStringVars(c.Path, vars)
	c.Domain = replaceStringVars(c.Domain, vars)
	c.Raw = replaceStringVars(c.Raw, vars)
	c.RawExpires = replaceStringVars(c.RawExpires, vars)
	return &c
}

// buildCookieFromConf 将配置中的 CookieConf 转换为 http.Cookie。
// 真实的模板替换由 applyCookieTemplates 完成，这里只负责结构映射与基础类型转换。
func buildCookieFromConf(conf CookieConf) http.Cookie {
	c := http.Cookie{
		Name:     conf.Name,
		Value:    conf.Value,
		Path:     conf.Path,
		Domain:   conf.Domain,
		MaxAge:   conf.MaxAge,
		Secure:   conf.Secure,
		HttpOnly: conf.HTTPOnly,
	}
	if conf.Expires != "" {
		// 优先按 RFC3339 解析，解析失败则忽略过期时间
		if t, err := time.Parse(time.RFC3339, conf.Expires); err == nil {
			c.Expires = t
		}
	}
	switch strings.ToLower(strings.TrimSpace(conf.SameSite)) {
	case "lax":
		c.SameSite = http.SameSiteLaxMode
	case "strict":
		c.SameSite = http.SameSiteStrictMode
	case "none":
		c.SameSite = http.SameSiteNoneMode
	}
	return c
}

// injectFormVars 解析表单/上传请求并写入 form.* 变量。
func injectFormVars(r *http.Request, vars map[string]string, bodyBytes []byte) {
	if len(bodyBytes) == 0 {
		return
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.Contains(ct, "multipart/form-data") && !strings.Contains(ct, "application/x-www-form-urlencoded") {
		return
	}
	resetBody := func() {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	resetBody()
	defer resetBody()

	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxMemory); err != nil {
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
	} else {
		if err := r.ParseForm(); err != nil {
			return
		}
	}
	for k, values := range r.PostForm {
		if len(values) > 0 {
			vars["form."+k] = values[0]
		}
	}
	if r.MultipartForm != nil {
		for k, files := range r.MultipartForm.File {
			if len(files) == 0 {
				continue
			}
			fh := files[0]
			vars["form."+k+".filename"] = fh.Filename
			if fh.Size > 0 {
				vars["form."+k+".size"] = fmt.Sprint(fh.Size)
			}
		}
	}
}

// serveResponseFile 将本地文件作为响应体回传。
func serveResponseFile(w http.ResponseWriter, r *http.Request, filePath string, status int) error {
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "response file not found", http.StatusNotFound)
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "response file unavailable", http.StatusInternalServerError)
		return err
	}
	if status > 0 {
		w.WriteHeader(status)
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
	return nil
}

// --- match 判定 --- //
// readJSONBodySafe 安全读取 JSON Body（不消耗原始 Body）。
func readJSONBodySafe(r *http.Request) map[string]any {
	var data map[string]any
	if r.Body == nil {
		return map[string]any{}
	}
	b, _ := io.ReadAll(r.Body)
	// 复位 Body 以便后续再次读取
	r.Body = io.NopCloser(bytes.NewReader(b))
	_ = json.Unmarshal(b, &data)
	if data == nil {
		data = map[string]any{}
	}
	return data
}

// matchRequest 根据 route.Match 条件判断请求是否命中。
func matchRequest(route RouteRule, r *http.Request) bool {
	if route.Match == nil {
		return true
	}
	// headers: 支持正则
	if route.Match.Headers != nil {
		for k, pattern := range route.Match.Headers {
			val := r.Header.Get(k)
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	// query: 支持正则
	if route.Match.Query != nil {
		vals := r.URL.Query()
		for k, pattern := range route.Match.Query {
			val := vals.Get(k)
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	// body: 支持点路径与正则
	if route.Match.Body != nil {
		data := readJSONBodySafe(r)
		for path, expect := range route.Match.Body {
			actual := getValueByPath(data, path)
			if sv, ok := expect.(string); ok {
				if matched, err := regexp.MatchString(sv, actual); err == nil {
					if !matched {
						return false
					}
				} else {
					if actual != sv {
						return false
					}
				}
			} else {
				if actual != fmt.Sprint(expect) {
					return false
				}
			}
		}
	}
	return true
}

// --- when 条件判定（统一：等值 + 操作符表达式） --- //
// getWhenActual 从 vars 或请求上下文中解析 when 的 key，返回实际值；未找到返回 ("", false)。
func getWhenActual(rawKey string, vars map[string]string, r *http.Request) (string, bool) {
	if val, ok := vars[rawKey]; ok {
		return val, true
	}
	parts := strings.SplitN(rawKey, ".", 2)
	if len(parts) != 2 {
		if val, ok := vars[rawKey]; ok {
			return val, true
		}
		return "", false
	}
	ns, field := parts[0], parts[1]
	key := ns + "." + field
	if val, ok := vars[key]; ok {
		return val, true
	}
	switch ns {
	case "param":
		return Vars(r)[field], true
	case "query":
		return r.URL.Query().Get(field), true
	case "header":
		return r.Header.Get(field), true
	default:
		return "", false
	}
}

// evalCondition 对实际值与期望（操作符+比较值）做比较，支持 = != > < ~ contains。
func evalCondition(actual, op, cmp string) bool {
	switch op {
	case "=":
		return actual == cmp
	case "!=":
		return actual != cmp
	case ">":
		fv, _ := strconv.ParseFloat(actual, 64)
		cv, _ := strconv.ParseFloat(cmp, 64)
		return fv > cv
	case "<":
		fv, _ := strconv.ParseFloat(actual, 64)
		cv, _ := strconv.ParseFloat(cmp, 64)
		return fv < cv
	case "~":
		matched, _ := regexp.MatchString(cmp, actual)
		return matched
	case "contains":
		return strings.Contains(actual, cmp)
	default:
		return actual == cmp
	}
}

// parseOp 解析 when 的 value：若为操作符前缀则返回 (op, 比较值)，否则视为等值 (=", value)。
func parseOp(v string) (string, string) {
	for _, op := range []string{"!=", ">", "<", "=", "~", "contains"} {
		if strings.HasPrefix(v, op) {
			return op, strings.TrimPrefix(v, op)
		}
	}
	return "=", v
}

// whenMatches 校验 when 条件，支持 param/query/header/body/extract/form。
// value 支持等值或操作符前缀：=、!=、>、<、~（正则）、contains。
func whenMatches(when map[string]any, vars map[string]string, r *http.Request) bool {
	if when == nil {
		return true
	}
	for rawKey, expect := range when {
		actual, ok := getWhenActual(rawKey, vars, r)
		if !ok {
			return false
		}
		expectedStr := fmt.Sprint(expect)
		op, cmp := parseOp(expectedStr)
		if !evalCondition(actual, op, cmp) {
			return false
		}
	}
	return true
}

// 支持类似 root.users.0.info.data 和 phones.1 路径递归提取嵌套字段
// getValueByPath 根据点路径提取嵌套值。
func getValueByPath(obj any, path string) string {
	parts := strings.Split(path, ".")
	curr := obj
	for _, part := range parts {
		// 支持数组索引 phones.0/info.data
		arrIdx := -1
		if idx := strings.Index(part, "["); idx > 0 && strings.HasSuffix(part, "]") {
			k := part[:idx]
			arrIdxStr := part[idx+1 : len(part)-1]
			arrIdx, _ = strconv.Atoi(arrIdxStr)
			part = k
		}
		switch val := curr.(type) {
		case map[string]any:
			curr = val[part]
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(val) {
				return ""
			}
			curr = val[idx]
			continue
		}
		if arrIdx >= 0 {
			if arr, ok := curr.([]any); ok && arrIdx >= 0 && arrIdx < len(arr) {
				curr = arr[arrIdx]
			} else {
				return ""
			}
		}
	}
	return fmt.Sprint(curr)
}

// 增强extractVars，允许多层body/query/header嵌套字段提取
// extractVariables 根据配置从请求中提取变量。
func extractVariables(ext *ExtractConf, r *http.Request, body map[string]any) map[string]string {
	out := map[string]string{}
	if ext == nil {
		return out
	}
	var src any
	switch ext.From {
	case "body":
		src = body
	case "query":
		m := map[string]any{}
		for k, v := range r.URL.Query() {
			m[k] = v[0]
		}
		src = m
	case "header":
		m := map[string]any{}
		for k, v := range r.Header {
			m[k] = v[0]
		}
		src = m
	default:
		return out
	}
	for key, path := range ext.Rules {
		out[key] = getValueByPath(src, path)
	}
	return out
}

// API 响应如 body/when/template字段为@filename，读取同目录模板并做简单替换
// renderTemplateIfNeeded 处理 @filename 语法并执行模板替换。
func renderTemplateIfNeeded(body any, params map[string]string) any {
	if s, ok := body.(string); ok && strings.HasPrefix(s, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(s, "@"))
		if err != nil {
			return "template file not found"
		}
		return replaceVars(string(b), params)
	}
	return body
}

// BuildRouter 读取 MockConfig 构造 Router。
func BuildRouter(cfg *MockConfig) *Router {
	r := NewRouter()
	// (1) 逐条注册所有 routes（包括 /api/...），确保 mux 路径参数变量可用
	for _, route := range cfg.Routes {
		method := strings.ToUpper(route.Method)
		slog.Debug("Register route", "method", method, "path", route.Path)
		// ANY 表示任意方法，不限制 Methods；其他则按方法限制
		if method == "ANY" || method == "" {
			r.HandleFunc(route.Path, singleRouteHandler(route))
		} else {
			r.HandleFunc(route.Path, singleRouteHandler(route)).Methods(method)
		}
	}
	// (2) 再注册所有静态PathPrefix，优先级在后
	for _, s := range cfg.Static {
		mount := s.Mount
		if !strings.HasSuffix(mount, "/") {
			mount += "/"
		}
		fileHandler := http.StripPrefix(mount, staticHandler(s))
		r.PathPrefix(mount).Handler(fileHandler)
		clean := strings.TrimSuffix(mount, "/")
		if len(clean) > 0 && clean != mount {
			r.Path(clean).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, mount, http.StatusMovedPermanently)
			})
		}
	}
	// WebSocket/SSE注册...（保持原有）
	if len(cfg.Websockets) > 0 {
		for _, wsConf := range cfg.Websockets {
			r.HandleFunc(wsConf.Path, gorillaWebsocketHandler(wsConf)).Methods("GET")
		}
	}
	if len(cfg.Sse) > 0 {
		for _, sseConf := range cfg.Sse {
			m := strings.ToUpper(strings.TrimSpace(sseConf.Method))
			if m == "" {
				m = "GET"
			}
			h := r.HandleFunc(sseConf.Path, muxSseHandler(sseConf))
			if m != "ANY" {
				h.Methods(m)
			}
		}
	}
	// 显式 OPTIONS 兜底，确保预检总能拿到 CORS 头（部分环境下中间件可能未触发）
	r.NewRoute().HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		reqHdr := r.Header.Get("Access-Control-Request-Headers")
		if reqHdr != "" {
			w.Header().Set("Access-Control-Allow-Headers", reqHdr)
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		reqMethod := r.Header.Get("Access-Control-Request-Method")
		if reqMethod == "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
		} else {
			w.Header().Set("Access-Control-Allow-Methods", reqMethod+", OPTIONS")
		}
		w.WriteHeader(http.StatusNoContent)
	}).Methods(http.MethodOptions)
	return r
}

// singleRouteHandler 针对单一 route 构造 handler，支持匹配/模板/提取。
func singleRouteHandler(route RouteRule) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		params := Vars(r)
		vars := map[string]string{}
		for k, v := range params {
			vars["param."+k] = v
		}
		slog.Debug("param injection", "vars", vars)
		for k, v := range r.URL.Query() {
			vars["query."+k] = v[0]
		}
		for k, v := range r.Header {
			vars["header."+k] = v[0]
		}
		// 安全读取并复位 Body，避免后续 match/extract 再读失败
		body := map[string]any{}
		var bodyBytes []byte
		if methodHasBody(r.Method) {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if len(bodyBytes) > 0 {
				_ = json.Unmarshal(bodyBytes, &body)
				for k, v := range body {
					vars["body."+k] = fmt.Sprint(v)
				}
			}
			injectFormVars(r, vars, bodyBytes)
			// 复位 Body 供后续 match/extract 使用
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// 记录请求日志
		reqHeaders := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				reqHeaders[k] = v[0]
			}
		}
		url := r.URL.Path
		if r.URL.RawQuery != "" {
			url += "?" + r.URL.RawQuery
		}
		reqLog := RequestLog{
			Time:    startTime.Format("15:04:05"),
			Method:  r.Method,
			URL:     url,
			Headers: reqHeaders,
			Body:    string(bodyBytes),
		}

		if route.Match != nil && !matchRequest(route, r) {
			reqLog.Status = 404
			wsHub.BroadcastRequest(reqLog)
			w.WriteHeader(404)
			return
		}
		if route.When != nil && !whenMatches(route.When, vars, r) {
			reqLog.Status = 403
			wsHub.BroadcastRequest(reqLog)
			w.WriteHeader(403)
			w.Write([]byte("route when failed"))
			return
		}
		extract := extractVariables(route.Extract, r, body)
		for k, v := range extract {
			vars["extract."+k] = v
		}
		if len(route.Responses) == 0 {
			reqLog.Status = http.StatusNotFound
			wsHub.BroadcastRequest(reqLog)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("no response configured"))
			return
		}
		resp := &route.Responses[0]
		for i := range route.Responses {
			res := &route.Responses[i]
			if whenMatches(res.When, vars, r) {
				resp = res
				break
			}
		}
		var bodyOut any
		if resp.Template != "" || (resp.Body != nil && fmt.Sprint(resp.Body) != "") {
			if resp.Template != "" {
				bodyOut = renderTemplateIfNeeded("@"+resp.Template, vars)
			} else {
				bodyOut = replaceVars(resp.Body, vars)
			}
		}
		if resp.DelayMs > 0 {
			time.Sleep(time.Duration(resp.DelayMs) * time.Millisecond)
		}
		for h, v := range resp.Headers {
			hv := replaceVars(v, vars)
			w.Header().Set(h, fmt.Sprint(hv))
		}
		for _, ck := range resp.Cookies {
			base := buildCookieFromConf(ck)
			http.SetCookie(w, applyCookieTemplates(base, vars))
		}
		if resp.File != "" {
			filePath := replaceStringVars(resp.File, vars)
			if err := serveResponseFile(w, r, filePath, resp.Status); err != nil {
				reqLog.Status = 500
				wsHub.BroadcastRequest(reqLog)
				return
			}
			reqLog.Status = resp.Status
			if reqLog.Status == 0 {
				reqLog.Status = 200
			}
			wsHub.BroadcastRequest(reqLog)
			return
		}
		status := resp.Status
		if status == 0 {
			status = 200
		}
		if resp.Status > 0 {
			w.WriteHeader(resp.Status)
		}
		if bodyOut != nil {
			switch val := bodyOut.(type) {
			case string:
				w.Write([]byte(val))
			default:
				json.NewEncoder(w).Encode(val)
			}
		}
		reqLog.Status = status
		wsHub.BroadcastRequest(reqLog)
	}
}

// gorillaWebsocketHandler 用 gorilla/websocket 实现 WS 剧本。
func gorillaWebsocketHandler(cfg WebsocketConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 连接前进行 match 校验（基于 headers/query）
		match := wsMatch(r, cfg.Match)
		if !match {
			w.WriteHeader(404)
			return
		}

		proto := r.Header.Get("Sec-WebSocket-Protocol")
		var protocols []string
		if proto != "" {
			protocols = strings.Split(proto, ",")
		}

		upgrader := Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
			Subprotocols:    protocols,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("ws upgrade fail", "error", err)
			return
		}
		defer conn.Close()
		params := Vars(r)
		// 统一构造变量字典：param.* / query.* / header.*，并兼容无命名空间路径参数
		wsVars := map[string]string{}
		for k, v := range params {
			wsVars[k] = v
			wsVars["param."+k] = v
		}
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				wsVars["query."+k] = v[0]
			}
		}
		for k, v := range r.Header {
			if len(v) > 0 {
				wsVars["header."+k] = v[0]
			}
		}
		// 剧本脚本驱动（send/await_json/close...）
		for _, act := range cfg.Script {
			// 动作级延迟：delay_ms
			if d, ok := act["delay_ms"]; ok {
				switch vv := d.(type) {
				case float64:
					time.Sleep(time.Duration(int(vv)) * time.Millisecond)
				case int:
					time.Sleep(time.Duration(vv) * time.Millisecond)
				}
			}
			if send, ok := act["send"]; ok {
				msg := replaceVars(send, wsVars) // 支持变量替换（含 param.*）
				conn.WriteMessage(TextMessage, []byte(fmt.Sprint(msg)))
			} else if aw, ok := act["await"]; ok {
				// 可配置超时
				if t, ok2 := act["timeout_ms"]; ok2 {
					switch vv := t.(type) {
					case float64:
						conn.SetReadDeadline(time.Now().Add(time.Duration(int(vv)) * time.Millisecond))
					case int:
						conn.SetReadDeadline(time.Now().Add(time.Duration(vv) * time.Millisecond))
					}
				}
				// 读取一条消息
				msgType, data, err := conn.ReadMessage()
				if err != nil {
					conn.WriteMessage(TextMessage, []byte(`{"error":"await timeout or read error"}`))
					break
				}
				// 清除超时
				conn.SetReadDeadline(time.Time{})
				matched := false
				switch want := aw.(type) {
				case string:
					// 正则匹配整条文本
					text := string(data)
					if msgType == BinaryMessage {
						// 二进制也按字节转字符串再匹配
					}
					if okReg, _ := regexp.MatchString(want, text); okReg {
						matched = true
					}
				case map[string]any:
					// JSON 等值匹配
					var req map[string]any
					_ = json.Unmarshal(data, &req)
					m := true
					for k, v := range want {
						if val, ok := req[k]; !ok || fmt.Sprint(val) != fmt.Sprint(v) {
							m = false
							break
						}
					}
					matched = m
				}
				if !matched {
					conn.WriteMessage(TextMessage, []byte(`{"error":"match failed"}`))
					break
				}
			} else if close, ok := act["close"]; ok && close.(bool) {
				conn.WriteControl(CloseMessage, FormatCloseMessage(CloseNormalClosure, "mock closed"), time.Now().Add(2*time.Second))
				break
			}
			// 其它可扩展
		}
	}
}

// wsMatch: 与 sseMatch 类似，支持 headers/query 的正则匹配
func wsMatch(r *http.Request, m *RouteMatchCondition) bool {
	if m == nil {
		return true
	}
	if m.Headers != nil {
		for k, pattern := range m.Headers {
			val := r.Header.Get(k)
			// 浏览器无法自定义 WS 头，允许使用 Sec-WebSocket-Protocol 作为替代承载
			if val == "" {
				val = r.Header.Get("Sec-WebSocket-Protocol")
			}
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	if m.Query != nil {
		q := r.URL.Query()
		for k, pattern := range m.Query {
			val := q.Get(k)
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	return true
}

// muxSseHandler（同上但基于mux路径匹配）
// sseMatch 校验 SSE 请求是否满足匹配条件。
func sseMatch(r *http.Request, m *RouteMatchCondition, vars map[string]string) bool {
	if m == nil {
		return true
	}
	// headers
	if m.Headers != nil {
		for k, pattern := range m.Headers {
			val := r.Header.Get(k)
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	// query
	if m.Query != nil {
		q := r.URL.Query()
		for k, pattern := range m.Query {
			val := q.Get(k)
			if matched, err := regexp.MatchString(pattern, val); err == nil {
				if !matched {
					return false
				}
			} else {
				if val != pattern {
					return false
				}
			}
		}
	}
	// body (点路径/正则)
	if m.Body != nil {
		data := readJSONBodySafe(r)
		for path, expect := range m.Body {
			actual := getValueByPath(data, path)
			if sv, ok := expect.(string); ok {
				if matched, err := regexp.MatchString(sv, actual); err == nil {
					if !matched {
						return false
					}
				} else {
					if actual != sv {
						return false
					}
				}
			} else {
				if actual != fmt.Sprint(expect) {
					return false
				}
			}
		}
	}
	return true
}

// muxSseHandler 将 SseConfig 转换为 SSE handler。
func muxSseHandler(cfg SseConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			w.WriteHeader(500)
			return
		}
		paramsRaw := Vars(r)
		// 构造模板变量：param./query./header./body.
		vars := map[string]string{}
		for k, v := range paramsRaw {
			vars["param."+k] = v
		}
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				vars["query."+k] = v[0]
			}
		}
		for k, v := range r.Header {
			if len(v) > 0 {
				vars["header."+k] = v[0]
			}
		}
		body := map[string]any{}
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(b))
			_ = json.Unmarshal(b, &body)
			for k, v := range body {
				vars["body."+k] = fmt.Sprint(v)
			}
		}
		// match
		if !sseMatch(r, cfg.Match, vars) {
			w.WriteHeader(404)
			return
		}
		// 标准 SSE 头
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		// 自定义头（变量替换）
		for h, v := range cfg.Headers {
			hv := replaceVars(v, vars)
			w.Header().Set(h, fmt.Sprint(hv))
		}
		// Cookies（变量替换）
		for _, ck := range cfg.Cookies {
			base := buildCookieFromConf(ck)
			http.SetCookie(w, applyCookieTemplates(base, vars))
		}
		if cfg.Status > 0 {
			w.WriteHeader(cfg.Status)
		}
		done := make(chan bool)
		go func() { <-r.Context().Done(); done <- true }()
		for {
			for _, evt := range cfg.Events {
				if evt.ID != "" {
					fmt.Fprintf(w, "id: %s\n", evt.ID)
				}
				if evt.Event != "" {
					fmt.Fprintf(w, "event: %s\n", evt.Event)
				}
				if evt.Retry > 0 {
					fmt.Fprintf(w, "retry: %d\n", evt.Retry)
				}
				fmt.Fprintf(w, "data: %s\n\n", replaceVars(evt.Data, vars))
				flusher.Flush()
				if evt.Delay > 0 {
					time.Sleep(time.Duration(evt.Delay) * time.Millisecond)
				}
				select {
				case <-done:
					return
				default:
				}
			}
			if !cfg.Repeat {
				break
			}
		}
	}
}

// --- Admin Web 控制台 --- //
// registerMockAdminRoute 注册mock相关路由
func registerMockAdminRoute(manager *AppManager) {

	http.HandleFunc("/mock/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(mockIndex)
	})
	http.HandleFunc("/mock", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mock/", http.StatusMovedPermanently)
	})
	http.HandleFunc("/mock/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			running, cfgTxt, err := manager.Status()
			if err != nil {
				writeJSONError(w, err)
				return
			}
			writeJSON(w, map[string]any{"config": cfgTxt, "running": running})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/mock/api/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, err)
			return
		}
		type req struct {
			Config string `json:"config"`
		}
		var payload req
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &payload); err != nil {
				writeJSONError(w, err)
				return
			}
		}
		if strings.TrimSpace(payload.Config) == "" {
			writeJSONError(w, errors.New("config 不能为空"))
			return
		}
		if err := manager.Reload([]byte(payload.Config)); err != nil {
			writeJSONError(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	http.HandleFunc("/mock/api/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := manager.Start(); err != nil {
			writeJSONError(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	http.HandleFunc("/mock/api/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := manager.Stop(); err != nil {
			writeJSONError(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	http.HandleFunc("/mock/api/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := manager.Restart(); err != nil {
			writeJSONError(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	http.HandleFunc("/mock/ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader := Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("WebSocket upgrade failed", "error", err)
			return
		}
		wsHub.register <- conn
		defer func() {
			wsHub.unregister <- conn
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	})
}

// writeJSON 写入 JSON 响应并设置 content-type。
func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// writeJSONError 用统一格式输出错误。
func writeJSONError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": err.Error(),
	})
}

// StartMockServer 入口负责解析 CLI 参数并启动 server 与管理端。
func StartMockServer() {
	configPath := flag.String("config", "mock.json", "path to mock config file")
	flag.Parse()

	go wsHub.Run()

	manager := NewAppManager(*configPath)
	if err := manager.Start(); err != nil {
		slog.Error("初始启动失败", "error", err)
	}
	registerMockAdminRoute(manager)
}
