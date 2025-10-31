package cli

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// GenerateDomainsFromPattern 从模式生成域名流
// 支持的模式语法:
// - [a-z]: 小写字母 a-z
// - [A-Z]: 大写字母 A-Z
// - [0-9]: 数字 0-9
// - [abc]: 自定义字符集
// - {n}: 重复n次
//
// 示例:
// - [a-z]{3}.com: 生成所有3字符小写字母域名
// - test[0-9]{2}.net: test + 两位数字
// - [abc]{2}.org: abc的2字符组合
func GenerateDomainsFromPattern(pattern string) (<-chan string, uint64, error) {
	re := regexp.MustCompile(`\[([^\]]+)\](?:\{(\d+)\})?`)
	matches := re.FindAllStringSubmatch(pattern, -1)

	if len(matches) == 0 {
		return nil, 0, fmt.Errorf("无效的模式: %s。请使用 [字符集]{重复次数} 格式，例如 [a-z]{3}.com", pattern)
	}

	matchIndices := re.FindAllStringIndex(pattern, -1)
	var charsetGroups [][]string
	var totalCount uint64 = 1
	overflow := false

	for i, match := range matches {
		charsetDef := match[1]
		repeat := 1
		if match[2] != "" {
			repeat, _ = strconv.Atoi(match[2])
		}

		chars, err := expandCharset(charsetDef)
		if err != nil {
			return nil, 0, err
		}
		if len(chars) == 0 {
			return nil, 0, fmt.Errorf("字符集 [%s] 为空", charsetDef)
		}

		groupSize := uint64(len(chars))
		for j := 0; j < repeat; j++ {
			charsetGroups = append(charsetGroups, chars)
			if !overflow {
				if totalCount > math.MaxUint64/groupSize {
					totalCount = math.MaxUint64
					overflow = true
				} else {
					totalCount *= groupSize
				}
			}
		}

		_ = matchIndices[i]
	}

	if len(charsetGroups) == 0 {
		return nil, 0, fmt.Errorf("无法从模式生成域名: %s", pattern)
	}

	domainChan := make(chan string, 1024)
	go func() {
		defer close(domainChan)
		current := make([]string, len(charsetGroups))
		generateCombinationsStream(pattern, matches, matchIndices, charsetGroups, 0, current, domainChan)
	}()

	return domainChan, totalCount, nil
}

// generateCombinationsStream 递归生成所有组合并写入通道
func generateCombinationsStream(pattern string, matches [][]string, matchIndices [][]int, charsetGroups [][]string, groupIdx int, current []string, out chan<- string) {
	if groupIdx >= len(charsetGroups) {
		domain := buildDomain(pattern, matches, matchIndices, current)
		out <- domain
		return
	}

	for _, char := range charsetGroups[groupIdx] {
		current[groupIdx] = char
		generateCombinationsStream(pattern, matches, matchIndices, charsetGroups, groupIdx+1, current, out)
	}
}

// buildDomain 根据组合构建域名
func buildDomain(pattern string, matches [][]string, matchIndices [][]int, combo []string) string {
	domain := pattern

	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		indices := matchIndices[i]

		repeat := 1
		if match[2] != "" {
			repeat, _ = strconv.Atoi(match[2])
		}

		segmentIdx := 0
		for j := 0; j < i; j++ {
			r := 1
			if matches[j][2] != "" {
				r, _ = strconv.Atoi(matches[j][2])
			}
			segmentIdx += r
		}

		var sb strings.Builder
		for _, part := range combo[segmentIdx : segmentIdx+repeat] {
			sb.WriteString(part)
		}

		domain = domain[:indices[0]] + sb.String() + domain[indices[1]:]
	}

	return domain
}

// expandCharset 展开字符集定义
// 支持:
// - a-z: 小写字母
// - A-Z: 大写字母
// - 0-9: 数字
// - abc: 具体字符列表
func expandCharset(charset string) ([]string, error) {
	var chars []string
	i := 0

	for i < len(charset) {
		if i+2 < len(charset) && charset[i+1] == '-' {
			startChar := charset[i]
			endChar := charset[i+2]

			if startChar == 'a' && endChar == 'z' {
				for c := 'a'; c <= 'z'; c++ {
					chars = append(chars, string(c))
				}
			} else if startChar == 'A' && endChar == 'Z' {
				for c := 'A'; c <= 'Z'; c++ {
					chars = append(chars, string(c))
				}
			} else if startChar == '0' && endChar == '9' {
				for c := '0'; c <= '9'; c++ {
					chars = append(chars, string(c))
				}
			} else {
				for c := startChar; c <= endChar; c++ {
					chars = append(chars, string(c))
				}
			}

			i += 3
		} else {
			chars = append(chars, string(charset[i]))
			i++
		}
	}

	if len(chars) == 0 {
		return nil, fmt.Errorf("无效的字符集: [%s]", charset)
	}

	return chars, nil
}

// LoadDomainsFromFile 从文件加载域名列表
func LoadDomainsFromFile(filePath string) ([]string, error) {
	content, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var domains []string
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("文件中没有找到有效的域名")
	}

	return domains, nil
}

// readFile 读取文件内容
func readFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
