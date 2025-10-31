package cli

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gois/whois"
)

// QueryConfig 查询配置
type QueryConfig struct {
	Timeout     time.Duration
	Proxy       *url.URL
	OutputFile  string
	Mode        string // "normal" 或 "simple"
	MaxRetries  int
	Concurrency int
	WhoisServer string
}

// QueryResult 查询结果
type QueryResult struct {
	Domain  string
	Success bool
	Result  *whois.QueryResult
	Error   error
}

// CLI 命令行查询工具
type CLI struct {
	config   *QueryConfig
	client   *whois.Client
	analyzer *whois.Analyzer
	fileLock sync.Mutex
	outFile  *os.File
	logger   *slog.Logger
}

// NewCLI 创建新的 CLI 实例
func NewCLI(config *QueryConfig) (*CLI, error) {
	client, err := whois.NewClient(config.Timeout, config.Proxy)
	if err != nil {
		return nil, fmt.Errorf("初始化 WHOIS 客户端失败: %w", err)
	}

	// 初始化 logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cli := &CLI{
		config:   config,
		client:   client,
		analyzer: whois.NewAnalyzer(),
		logger:   logger,
	}

	// 初始化输出文件
	if config.OutputFile != "" {
		if err := cli.initOutputFile(); err != nil {
			return nil, err
		}
	}

	return cli, nil
}

// Close 关闭 CLI 资源
func (c *CLI) Close() error {
	if c.outFile != nil {
		return c.outFile.Close()
	}
	return nil
}

// initOutputFile 初始化输出文件
func (c *CLI) initOutputFile() error {
	file, err := os.Create(c.config.OutputFile)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}

	c.outFile = file

	// 写入文件头
	if c.config.Mode == "simple" {
		_, err = fmt.Fprintf(file, "domain,status\n")
	} else {
		_, err = fmt.Fprintf(file, "# WHOIS 查询结果\n")
		_, err = fmt.Fprintf(file, "# 查询时间: %s\n", time.Now().Format(time.RFC3339))
		_, err = fmt.Fprintf(file, "# 模式: %s\n", c.config.Mode)
		_, err = fmt.Fprintf(file, "%s\n\n", strings.Repeat("=", 80))
	}

	return err
}

// QuerySingleDomain 查询单个域名
func (c *CLI) QuerySingleDomain(domain string) *QueryResult {
	c.logger.Info("正在查询域名", "domain", domain)

	var lastErr error
	for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
		result, err := c.client.Fetch(domain, c.config.WhoisServer)
		if err == nil {
			// 查询成功
			c.printResult(domain, result)
			c.writeResult(domain, result, nil)

			return &QueryResult{
				Domain:  domain,
				Success: true,
				Result:  result,
			}
		}

		lastErr = err
		if attempt < c.config.MaxRetries-1 {
			c.logger.Warn("查询失败，正在重试",
				"domain", domain,
				"attempt", attempt+1,
				"max_retries", c.config.MaxRetries,
				"error", err)
			time.Sleep(time.Second * 2)
		}
	}

	// 所有重试都失败
	c.logger.Error("域名查询失败", "domain", domain, "error", lastErr)
	c.writeResult(domain, nil, lastErr)

	return &QueryResult{
		Domain:  domain,
		Success: false,
		Error:   lastErr,
	}
}

// QueryBatchDomains 批量查询域名
func (c *CLI) QueryBatchDomains(domains []string) []*QueryResult {
	c.logger.Info("开始批量查询",
		"total_domains", len(domains),
		"concurrency", c.config.Concurrency)

	results := make([]*QueryResult, 0, len(domains))
	// 使用较小的固定缓冲区，避免预分配大量内存
	// 缓冲区大小为并发数的2倍，足以避免goroutine阻塞
	bufferSize := c.config.Concurrency * 2
	if bufferSize > 100 {
		bufferSize = 100 // 限制最大缓冲区大小
	}
	resultChan := make(chan *QueryResult, bufferSize)
	semaphore := make(chan struct{}, c.config.Concurrency)

	var wg sync.WaitGroup

	// 启动查询任务
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := c.QuerySingleDomain(d)
			resultChan <- result
		}(domain)
	}

	// 等待所有任务完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	completed := 0
	for result := range resultChan {
		results = append(results, result)
		completed++
		c.logger.Info("查询进度", "completed", completed, "total", len(domains))
	}

	// 输出统计信息
	c.printStatistics(results)

	return results
}

// printResult 打印查询结果
func (c *CLI) printResult(domain string, result *whois.QueryResult) {
	if c.config.Mode == "simple" {
		statusCode := c.analyzer.GetDomainStatus(result)
		var status string
		switch statusCode {
		case "available":
			status = "可用"
		case "registered":
			status = "已注册"
		case "unknown":
			status = "未知"
		default:
			status = "未知"
		}
		c.logger.Info("查询结果", "domain", domain, "status", status)
	} else {
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("域名: %s\n", domain)
		fmt.Println(strings.Repeat("-", 80))

		if result.RegistrarResult != "" {
			fmt.Println("\n注册商 WHOIS 结果:")
			fmt.Println(result.RegistrarResult)
		}

		if result.RegistryResult != "" {
			fmt.Println("\n注册局 WHOIS 结果:")
			fmt.Println(result.RegistryResult)
		}

		fmt.Println(strings.Repeat("=", 80))
	}
}

// writeResult 将结果写入文件
func (c *CLI) writeResult(domain string, result *whois.QueryResult, err error) {
	if c.outFile == nil {
		return
	}

	c.fileLock.Lock()
	defer c.fileLock.Unlock()

	if c.config.Mode == "simple" {
		status := "unknown"
		if err == nil && result != nil {
			status = c.analyzer.GetDomainStatus(result)
		}
		fmt.Fprintf(c.outFile, "%s,%s\n", domain, status)
	} else {
		fmt.Fprintf(c.outFile, "\n%s\n", strings.Repeat("=", 80))
		fmt.Fprintf(c.outFile, "域名: %s\n", domain)
		fmt.Fprintf(c.outFile, "查询时间: %s\n", time.Now().Format(time.RFC3339))

		if err != nil {
			fmt.Fprintf(c.outFile, "错误: %v\n", err)
		} else if result != nil {
			fmt.Fprintf(c.outFile, "\n注册商 WHOIS 服务器结果:\n")
			fmt.Fprintf(c.outFile, "%s\n", strings.Repeat("-", 80))
			if result.RegistrarResult != "" {
				fmt.Fprintf(c.outFile, "%s\n", result.RegistrarResult)
			} else {
				fmt.Fprintf(c.outFile, "无数据\n")
			}

			fmt.Fprintf(c.outFile, "\n\n注册局 WHOIS 服务器结果:\n")
			fmt.Fprintf(c.outFile, "%s\n", strings.Repeat("-", 80))
			if result.RegistryResult != "" {
				fmt.Fprintf(c.outFile, "%s\n", result.RegistryResult)
			} else {
				fmt.Fprintf(c.outFile, "无数据\n")
			}
		}

		fmt.Fprintf(c.outFile, "\n%s\n", strings.Repeat("=", 80))
	}
}

// printStatistics 打印统计信息
func (c *CLI) printStatistics(results []*QueryResult) {
	successCount := 0
	availableCount := 0
	registeredCount := 0
	unknownCount := 0

	for _, result := range results {
		if result.Success {
			successCount++
			status := c.analyzer.GetDomainStatus(result.Result)
			switch status {
			case "available":
				availableCount++
			case "registered":
				registeredCount++
			case "unknown":
				unknownCount++
			}
		}
	}

	failCount := len(results) - successCount

	attrs := []any{
		"total", len(results),
		"success", successCount,
		"failed", failCount,
	}

	if c.config.Mode == "simple" {
		attrs = append(attrs, "available", availableCount, "registered", registeredCount, "unknown", unknownCount)
	}

	c.logger.Info("批量查询完成", attrs...)
}
