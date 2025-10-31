package whois

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

const (
	defaultWhoisPort = "43"
	ianaWhoisServer  = "whois.iana.org"
)

// QueryResult WHOIS 查询结果
type QueryResult struct {
	RegistryResult  string `json:"registry_result"`
	RegistrarResult string `json:"registrar_result"`
}

// Client WHOIS 客户端
type Client struct {
	timeout  time.Duration
	proxy    *url.URL
	registry *TLDRegistry
	// 预编译的正则表达式，避免重复编译
	ianaWhoisRegexp     *regexp.Regexp
	registrarRegexps   []*regexp.Regexp
}

// NewClient 创建一个新的 WHOIS 客户端
func NewClient(timeout time.Duration, proxyURL *url.URL) (*Client, error) {
	registry, err := NewTLDRegistry()
	if err != nil {
		return nil, err
	}

	// 预编译正则表达式
	registrarPatterns := []string{
		`(?mi)^.*whois server.*$`,
		`(?mi)^.*registrar whois.*$`,
	}
	registrarRegexps := make([]*regexp.Regexp, 0, len(registrarPatterns))
	for _, pattern := range registrarPatterns {
		registrarRegexps = append(registrarRegexps, regexp.MustCompile(pattern))
	}

	return &Client{
		timeout:          timeout,
		proxy:            proxyURL,
		registry:         registry,
		ianaWhoisRegexp:  regexp.MustCompile(`(?mi)^.*whois:.*$`),
		registrarRegexps: registrarRegexps,
	}, nil
}

// Fetch 查询域名的 WHOIS 信息
func (c *Client) Fetch(domain string, whoisServer string) (*QueryResult, error) {
	// 域名标准化
	normalizedDomain, tld, err := c.parseDomain(domain)
	if err != nil {
		return nil, err
	}

	// 确定 WHOIS 服务器
	var selectedServer string
	if whoisServer != "" {
		selectedServer = whoisServer
	} else {
		selectedServer, err = c.findWhoisServer(tld)
		if err != nil {
			return nil, err
		}
	}

	// 查询注册局 WHOIS 服务器
	registryResult, err := c.query(normalizedDomain, selectedServer)
	if err != nil {
		return nil, err
	}

	// 尝试从注册局响应中提取注册商 WHOIS 服务器
	var registrarResult string
	registrarServer := c.extractRegistrarServer(registryResult)
	if registrarServer != "" {
		registrarResult, _ = c.query(normalizedDomain, registrarServer)
	}

	return &QueryResult{
		RegistryResult:  registryResult,
		RegistrarResult: registrarResult,
	}, nil
}

// parseDomain 解析域名，提取标准化的域名和 TLD
func (c *Client) parseDomain(domain string) (string, string, error) {
	// 去除协议
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.ToLower(strings.TrimSpace(domain))

	// 去除路径
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// 提取 TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", "", &BadDomainError{Domain: domain}
	}

	// 获取顶级域名（最后一部分）
	tld := parts[len(parts)-1]

	if tld == "" {
		return "", "", &BadDomainError{Domain: domain}
	}

	return domain, tld, nil
}

// findWhoisServer 查找 TLD 对应的 WHOIS 服务器
func (c *Client) findWhoisServer(tld string) (string, error) {
	// 先从本地注册表查找
	if server, ok := c.registry.GetWhoisServer(tld); ok {
		return server, nil
	}

	// 如果本地没有，从 IANA 查询
	return c.fetchWhoisServerFromIANA(tld)
}

// fetchWhoisServerFromIANA 从 IANA 查询 TLD 的 WHOIS 服务器
func (c *Client) fetchWhoisServerFromIANA(tld string) (string, error) {
	result, err := c.query(tld, ianaWhoisServer)
	if err != nil {
		return "", err
	}

	// 提取 WHOIS 服务器
	matches := c.ianaWhoisRegexp.FindStringSubmatch(result)
	if len(matches) == 0 {
		return "", &NoWhoisServerFoundError{TLD: tld}
	}

	parts := strings.Split(matches[0], ":")
	if len(parts) < 2 {
		return "", &NoWhoisServerFoundError{TLD: tld}
	}

	server := strings.TrimSpace(parts[1])

	// 缓存结果
	c.registry.SetWhoisServer(tld, server)

	return server, nil
}

// extractRegistrarServer 从注册局响应中提取注册商 WHOIS 服务器
func (c *Client) extractRegistrarServer(response string) string {
	for _, re := range c.registrarRegexps {
		matches := re.FindStringSubmatch(response)
		if len(matches) > 0 {
			parts := strings.Split(matches[0], ":")
			if len(parts) >= 2 {
				server := strings.TrimSpace(parts[1])
				server = strings.Trim(server, "/\\")
				if server != "" {
					return server
				}
			}
		}
	}

	return ""
}

// query 执行 WHOIS 查询
func (c *Client) query(domain, server string) (string, error) {
	// 建立连接
	conn, err := c.dial(server, defaultWhoisPort)
	if err != nil {
		return "", &SocketError{
			Server: server,
			Query:  domain,
			Err:    err,
		}
	}
	defer conn.Close()

	// 设置超时
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", &SocketError{
			Server: server,
			Query:  domain,
			Err:    err,
		}
	}

	// 发送查询
	query := domain + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", &SocketError{
			Server: server,
			Query:  domain,
			Err:    err,
		}
	}

	// 读取响应
	var result strings.Builder
	scanner := bufio.NewScanner(conn)
	// 使用较小的初始缓冲区和最大缓冲区，避免高并发时占用过多内存
	// 大多数WHOIS响应不会超过256KB
	scanner.Buffer(make([]byte, 4096), 256*1024) // 256KB max buffer

	for scanner.Scan() {
		result.WriteString(scanner.Text())
		result.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		// 尝试使用不同的编码
		return c.readWithEncoding(conn)
	}

	return result.String(), nil
}

// readWithEncoding 使用不同的编码读取响应
func (c *Client) readWithEncoding(conn net.Conn) (string, error) {
	// 重新读取所有数据
	// 限制最大读取大小，避免内存无限增长
	const maxReadSize = 512 * 1024 // 512KB最大限制
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			// 检查是否超过最大大小限制
			if len(buf)+n > maxReadSize {
				// 只读取到最大限制
				remaining := maxReadSize - len(buf)
				if remaining > 0 {
					buf = append(buf, tmp[:remaining]...)
				}
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	// 尝试不同的编码
	encodings := []encoding.Encoding{
		unicode.UTF8,
		charmap.ISO8859_1,
		charmap.Windows1252,
	}

	for _, enc := range encodings {
		decoder := enc.NewDecoder()
		decoded, err := decoder.Bytes(buf)
		if err == nil {
			return string(decoded), nil
		}
	}

	// 如果所有编码都失败，返回原始字符串（忽略无效字符）
	return string(buf), nil
}

// dial 建立到 WHOIS 服务器的连接
func (c *Client) dial(host, port string) (net.Conn, error) {
	address := net.JoinHostPort(host, port)

	// 如果配置了代理
	if c.proxy != nil {
		return c.dialWithProxy(address)
	}

	// 直接连接
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}
	return dialer.Dial("tcp", address)
}

// dialWithProxy 通过代理建立连接
func (c *Client) dialWithProxy(address string) (net.Conn, error) {
	if c.proxy == nil {
		return nil, &ProxyError{Message: "proxy not configured"}
	}

	var auth *proxy.Auth
	if c.proxy.User != nil {
		password, _ := c.proxy.User.Password()
		auth = &proxy.Auth{
			User:     c.proxy.User.Username(),
			Password: password,
		}
	}

	// 创建代理拨号器
	var dialer proxy.Dialer
	var err error
	if c.proxy.Scheme == "socks5" {
		dialer, err = proxy.SOCKS5("tcp", c.proxy.Host, auth, proxy.Direct)
	} else {
		// 对于 HTTP 代理，使用标准拨号
		dialer = &net.Dialer{Timeout: c.timeout}
	}

	if err != nil {
		return nil, &ProxyError{Message: "failed to create proxy dialer", Err: err}
	}

	// 通过代理连接
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, &ProxyError{
			Message: fmt.Sprintf("failed to connect via proxy %s", c.proxy.Host),
			Err:     err,
		}
	}

	return conn, nil
}
