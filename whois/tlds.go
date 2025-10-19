package whois

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed tlds.json
var tldsData []byte

// TLDRegistry 管理 TLD 到 WHOIS 服务器的映射
type TLDRegistry struct {
	tlds map[string]string
}

// NewTLDRegistry 创建一个新的 TLD 注册表
func NewTLDRegistry() (*TLDRegistry, error) {
	registry := &TLDRegistry{
		tlds: make(map[string]string),
	}

	// 先尝试解析为 map[string]interface{} 以处理可能的非字符串值
	var rawData map[string]interface{}
	if err := json.Unmarshal(tldsData, &rawData); err != nil {
		return nil, &TldsFileError{
			Path: "embedded tlds.json",
			Err:  err,
		}
	}

	// 转换所有值为字符串
	for key, value := range rawData {
		switch v := value.(type) {
		case string:
			registry.tlds[key] = v
		case float64:
			registry.tlds[key] = fmt.Sprintf("%.0f", v)
		case int:
			registry.tlds[key] = fmt.Sprintf("%d", v)
		default:
			registry.tlds[key] = fmt.Sprintf("%v", v)
		}
	}

	return registry, nil
}

// GetWhoisServer 获取指定 TLD 的 WHOIS 服务器
func (r *TLDRegistry) GetWhoisServer(tld string) (string, bool) {
	server, ok := r.tlds[tld]
	return server, ok
}

// SetWhoisServer 设置指定 TLD 的 WHOIS 服务器
func (r *TLDRegistry) SetWhoisServer(tld, server string) {
	r.tlds[tld] = server
}

// GetAllTLDs 获取所有已知的 TLD
func (r *TLDRegistry) GetAllTLDs() []string {
	tlds := make([]string, 0, len(r.tlds))
	for tld := range r.tlds {
		tlds = append(tlds, tld)
	}
	return tlds
}
