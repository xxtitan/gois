package whois

import (
	"regexp"
	"strings"
)

// DomainInfo 域名信息
type DomainInfo struct {
	Available      bool     `json:"available"`
	Registrar      string   `json:"registrar,omitempty"`
	CreationDate   string   `json:"creation_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
}

// Analyzer WHOIS 结果分析器
type Analyzer struct {
	availableKeywords  []string
	registeredKeywords []string
}

// NewAnalyzer 创建一个新的分析器
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		availableKeywords: []string{
			"no match",
			"not found",
			"no entries found",
			"no data found",
			"not registered",
			"available for registration",
			"status: free",
			"status: available",
			"no matching record",
			"nothing found",
			"no object found",
			"domain not found",
			"is available",
			"is free",
			"未找到",
			"无匹配",
		},
		registeredKeywords: []string{
			"registrar:",
			"registrant:",
			"creation date:",
			"created:",
			"expiration date:",
			"expires:",
			"expiry date:",
			"registry expiry date:",
			"domain status:",
			"name server:",
			"nameserver:",
			"dnssec:",
			"注册商",
			"注册人",
			"创建时间",
			"到期时间",
		},
	}
}

// IsDomainAvailable 判断域名是否可用（未注册）
func (a *Analyzer) IsDomainAvailable(result *QueryResult) bool {
	if result == nil {
		return false
	}

	// 合并两个结果
	combined := strings.ToLower(result.RegistryResult + "\n" + result.RegistrarResult)

	if strings.TrimSpace(combined) == "" {
		return false
	}

	// 检查可用关键词
	availableScore := 0
	for _, keyword := range a.availableKeywords {
		if strings.Contains(combined, strings.ToLower(keyword)) {
			availableScore++
		}
	}

	// 检查已注册关键词
	registeredScore := 0
	for _, keyword := range a.registeredKeywords {
		if strings.Contains(combined, strings.ToLower(keyword)) {
			registeredScore++
		}
	}

	// 如果有明确的可用标记，优先判断为可用
	if availableScore > 0 && registeredScore == 0 {
		return true
	}

	// 如果有明确的已注册标记
	if registeredScore > 0 {
		return false
	}

	// 如果两者都有，以已注册为准（保守判断）
	if availableScore > 0 && registeredScore > 0 {
		return false
	}

	// 默认判断为已注册（保守判断）
	return false
}

// ExtractRegistrar 提取注册商信息
func (a *Analyzer) ExtractRegistrar(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	patterns := []string{
		`(?mi)registrar:\s*(.+)`,
		`(?mi)sponsoring registrar:\s*(.+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractCreationDate 提取域名创建日期
func (a *Analyzer) ExtractCreationDate(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	patterns := []string{
		`(?mi)creation date:\s*(.+)`,
		`(?mi)created:\s*(.+)`,
		`(?mi)registered on:\s*(.+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractExpirationDate 提取域名过期日期
func (a *Analyzer) ExtractExpirationDate(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	patterns := []string{
		`(?mi)registry expiry date:\s*(.+)`,
		`(?mi)registrar registration expiration date:\s*(.+)`,
		`(?mi)expiration date:\s*(.+)`,
		`(?mi)expires:\s*(.+)`,
		`(?mi)expiry date:\s*(.+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractNameServers 提取域名服务器列表
func (a *Analyzer) ExtractNameServers(result *QueryResult) []string {
	if result == nil {
		return nil
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	patterns := []string{
		`(?mi)name server:\s*(.+)`,
		`(?mi)nameserver:\s*(.+)`,
		`(?mi)nserver:\s*(.+)`,
	}

	var nameServers []string
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(combined, -1)
		for _, match := range matches {
			if len(match) > 1 {
				ns := strings.TrimSpace(match[1])
				nsLower := strings.ToLower(ns)
				if !seen[nsLower] {
					seen[nsLower] = true
					nameServers = append(nameServers, ns)
				}
			}
		}
	}

	return nameServers
}

// GetDomainInfo 提取域名的完整信息
func (a *Analyzer) GetDomainInfo(result *QueryResult) *DomainInfo {
	return &DomainInfo{
		Available:      a.IsDomainAvailable(result),
		Registrar:      a.ExtractRegistrar(result),
		CreationDate:   a.ExtractCreationDate(result),
		ExpirationDate: a.ExtractExpirationDate(result),
		NameServers:    a.ExtractNameServers(result),
	}
}
