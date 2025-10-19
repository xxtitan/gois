package whois

import "fmt"

// WhoisError 是所有 WHOIS 相关错误的基础类型
type WhoisError struct {
	Message string
	Err     error
}

func (e *WhoisError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *WhoisError) Unwrap() error {
	return e.Err
}

// NewWhoisError 创建一个新的 WhoisError
func NewWhoisError(message string, err error) *WhoisError {
	return &WhoisError{
		Message: message,
		Err:     err,
	}
}

// BadDomainError 无效域名错误
type BadDomainError struct {
	Domain string
}

func (e *BadDomainError) Error() string {
	return fmt.Sprintf("invalid domain: %s", e.Domain)
}

// NoWhoisServerFoundError WHOIS 服务器未找到错误
type NoWhoisServerFoundError struct {
	TLD string
}

func (e *NoWhoisServerFoundError) Error() string {
	return fmt.Sprintf("no whois server found for TLD: %s", e.TLD)
}

// SocketTimeoutError 连接超时错误
type SocketTimeoutError struct {
	Server string
	Query  string
}

func (e *SocketTimeoutError) Error() string {
	return fmt.Sprintf("timeout querying %s for %s", e.Server, e.Query)
}

// SocketError 连接错误
type SocketError struct {
	Server string
	Query  string
	Err    error
}

func (e *SocketError) Error() string {
	return fmt.Sprintf("error querying %s for %s: %v", e.Server, e.Query, e.Err)
}

func (e *SocketError) Unwrap() error {
	return e.Err
}

// TldsFileError TLDs 文件错误
type TldsFileError struct {
	Path string
	Err  error
}

func (e *TldsFileError) Error() string {
	return fmt.Sprintf("tld data file error at %s: %v", e.Path, e.Err)
}

func (e *TldsFileError) Unwrap() error {
	return e.Err
}

// ProxyError 代理错误
type ProxyError struct {
	Message string
	Err     error
}

func (e *ProxyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("proxy error: %s: %v", e.Message, e.Err)
	}
	return fmt.Sprintf("proxy error: %s", e.Message)
}

func (e *ProxyError) Unwrap() error {
	return e.Err
}
