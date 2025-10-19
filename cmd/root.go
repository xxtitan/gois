package cmd

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"gois/cli"

	"github.com/spf13/cobra"
)

var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

var (
	// 全局标志
	timeout     int
	proxy       string
	outputFile  string
	mode        string
	maxRetries  int
	concurrency int
	whoisServer string
)

var rootCmd = &cobra.Command{
	Use:   "gois",
	Short: "WHOIS 域名查询工具",
	Long: `gois - 功能完整的 WHOIS 域名查询命令行工具

支持单个域名查询、批量查询、域名生成、并发控制等功能。
使用 Golang 实现，提供高性能和易用性。`,
	Version: "1.0.0",
}

// Execute 执行根命令
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// 全局标志
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "查询超时时间（秒）")
	rootCmd.PersistentFlags().StringVarP(&proxy, "proxy", "p", "", "代理配置，格式: type://addr:port")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "结果输出文件路径")
	rootCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "normal", "查询模式: normal=完整信息, simple=仅判断可用性")
	rootCmd.PersistentFlags().IntVarP(&maxRetries, "retries", "r", 3, "查询失败时的重试次数")
	rootCmd.PersistentFlags().IntVarP(&concurrency, "concurrency", "c", 5, "批量查询时的并发数")
	rootCmd.PersistentFlags().StringVarP(&whoisServer, "whois-server", "w", "", "指定 WHOIS 服务器（可选）")
}

// createCLI 创建 CLI 实例
func createCLI() (*cli.CLI, error) {
	config := &cli.QueryConfig{
		Timeout:     time.Duration(timeout) * time.Second,
		OutputFile:  outputFile,
		Mode:        mode,
		MaxRetries:  maxRetries,
		Concurrency: concurrency,
		WhoisServer: whoisServer,
	}

	// 解析代理配置
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("代理配置解析失败: %w", err)
		}
		if proxyURL.Scheme == "" || proxyURL.Host == "" {
			return nil, fmt.Errorf("无效的代理格式: %s (需要格式: scheme://host:port)", proxy)
		}
		config.Proxy = proxyURL
	}

	return cli.NewCLI(config)
}
