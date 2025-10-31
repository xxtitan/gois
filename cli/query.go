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

// BatchSummary 批量查询统计信息
type BatchSummary struct {
	Requested  int64
	Processed  int64
	Success    int64
	Failed     int64
	Available  int64
	Registered int64
	Unknown    int64
}

// HasFailures 是否存在失败
func (b *BatchSummary) HasFailures() bool {
	return b != nil && b.Failed > 0
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

// QueryBatchDomains 批量查询域名（使用内存中的域名列表）
func (c *CLI) QueryBatchDomains(domains []string) *BatchSummary {
	c.logger.Info("开始批量查询",
		"total_domains", len(domains),
		"concurrency", c.config.Concurrency)

	domainChan := make(chan string, c.channelBufferSize())
	go func() {
		for _, domain := range domains {
			domainChan <- domain
		}
		close(domainChan)
	}()

	return c.QueryBatchDomainsStream(domainChan, int64(len(domains)))
}

// QueryBatchDomainsStream 批量查询域名（使用流式域名来源）
func (c *CLI) QueryBatchDomainsStream(domains <-chan string, totalHint int64) *BatchSummary {
	workerCount := c.config.Concurrency
	if workerCount <= 0 {
		workerCount = 1
	}

	resultChan := make(chan *QueryResult, workerCount*2)
	var workerWG sync.WaitGroup

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for domain := range domains {
				resultChan <- c.QuerySingleDomain(domain)
			}
		}()
	}

	// 关闭结果通道
	go func() {
		workerWG.Wait()
		close(resultChan)
	}()

	summary := &BatchSummary{Requested: totalHint}
	progressInterval := int64(100)
	if totalHint > 0 {
		// 根据总量调节进度日志频率，防止刷屏
		switch {
		case totalHint >= 1_000_000:
			progressInterval = 10_000
		case totalHint >= 100_000:
			progressInterval = 1_000
		case totalHint >= 10_000:
			progressInterval = 500
		}
	}

	for result := range resultChan {
		summary.Processed++
		if result.Success {
			summary.Success++
			if c.config.Mode == "simple" && result.Result != nil {
				status := c.analyzer.GetDomainStatus(result.Result)
				switch status {
				case "available":
					summary.Available++
				case "registered":
					summary.Registered++
				case "unknown":
					summary.Unknown++
				}
			}
		} else {
			summary.Failed++
		}

		// 释放结果占用的内存
		result.Result = nil

		if progressInterval <= 1 || summary.Processed%progressInterval == 0 {
			attrs := []any{"completed", summary.Processed}
			if totalHint > 0 {
				attrs = append(attrs, "total", totalHint)
			}
			c.logger.Info("查询进度", attrs...)
		}
	}

	if summary.Requested < 0 {
		summary.Requested = summary.Processed
	}

	c.printStatistics(summary)

	return summary
}

func (c *CLI) channelBufferSize() int {
	bufferSize := c.config.Concurrency * 2
	if bufferSize < 1 {
		bufferSize = 1
	}
	if bufferSize > 100 {
		bufferSize = 100
	}
	return bufferSize
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
func (c *CLI) printStatistics(summary *BatchSummary) {
	if summary == nil {
		return
	}

	attrs := []any{
		"requested", summary.Requested,
		"processed", summary.Processed,
		"success", summary.Success,
		"failed", summary.Failed,
	}

	if c.config.Mode == "simple" {
		attrs = append(attrs,
			"available", summary.Available,
			"registered", summary.Registered,
			"unknown", summary.Unknown,
		)
	}

	c.logger.Info("批量查询完成", attrs...)
}
