# gois - WHOIS 域名查询命令行工具

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

一个功能完整、工程化的 WHOIS 域名查询命令行工具，使用 Golang 开发，支持单个查询、批量查询、域名生成、并发控制和多种输出模式。

## ✨ 功能特性

- ✅ **单个域名查询** - 快速查询任意域名的 WHOIS 信息
- ✅ **批量域名查询** - 从文件导入域名列表进行批量查询
- ✅ **域名生成** - 支持模式生成域名（如 `[a-z]{3}.com` 生成所有 3 字符域名）
- ✅ **并发控制** - 可自定义并发线程数，提高查询效率
- ✅ **两种查询模式**：
  - **normal**: 显示完整的 WHOIS 信息（注册商、注册局详细信息）
  - **simple**: 仅判断域名是否可用（未注册）
- ✅ **结果文件输出** - 查询结果实时同步写入文件
  - normal 模式：文本格式
  - simple 模式：CSV 格式（便于导入 Excel 等工具）
- ✅ **代理支持** - 支持 SOCKS5 代理
- ✅ **自定义超时** - 可设置查询超时时间
- ✅ **异常处理** - 完善的错误处理和提示信息
- ✅ **重试机制** - 查询失败自动重试
- ✅ **进度追踪** - 批量查询时显示实时进度

## 📦 安装

### 方式 1: 从源码编译

```bash
# 克隆仓库
git clone https://github.com/yourusername/gois.git
cd gois

# 编译
go build -o gois .

# 安装到系统路径（可选）
go install
```

### 方式 2: 下载预编译二进制

从 [Releases](https://github.com/yourusername/gois/releases) 页面下载适合你系统的二进制文件。

## 🚀 快速开始

### 1. 查询单个域名

```bash
# 普通模式 - 显示完整 WHOIS 信息
gois query github.com

# 简单模式 - 仅判断是否可用
gois query github.com -m simple
```

### 2. 批量查询域名

首先创建域名列表文件 `domains.txt`：

```text
github.com
google.com
python.org
```

然后执行批量查询：

```bash
# 批量查询（默认并发数 5）
gois batch domains.txt

# 指定并发数为 10
gois batch domains.txt -c 10

# 简单模式批量查询
gois batch domains.txt -m simple -c 10
```

### 3. 从模式生成域名并查询

```bash
# 生成所有 3 字符小写字母域名（共 17,576 个）
gois generate "[a-z]{3}.com" -m simple -c 10

# 生成自定义字符集域名（abc 的 2 字符组合，共 9 个）
gois generate "[abc]{2}.com" -m simple

# 生成混合模式域名（test + 两位数字，共 100 个）
gois generate "test[0-9]{2}.net" -m simple

# 生成并输出到文件
gois generate "[0-9]{4}.io" -m simple -o results.csv
```

### 4. 输出结果到文件

```bash
# 单个查询输出到文件
gois query github.com -o result.txt

# 批量查询输出到 CSV（simple 模式）
gois batch domains.txt -o results.csv -m simple
```

### 5. 使用代理

```bash
# SOCKS5 代理
gois query github.com -p socks5://localhost:7897

# 带用户认证的代理
gois query github.com -p socks5://user:pass@localhost:7897
```

## 📖 详细使用说明

### 命令列表

| 命令 | 说明 |
|------|------|
| `gois query [domain]` | 查询单个域名 |
| `gois batch [file]` | 批量查询域名 |
| `gois generate [pattern]` | 从模式生成域名并查询 |
| `gois help` | 显示帮助信息 |

### 全局参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--timeout` | `-t` | 查询超时时间（秒） | `10` |
| `--proxy` | `-p` | 代理配置 | 无 |
| `--output` | `-o` | 结果输出文件路径 | 无（仅输出到终端） |
| `--mode` | `-m` | 查询模式：`normal` / `simple` | `normal` |
| `--retries` | `-r` | 查询失败时的重试次数 | `3` |
| `--concurrency` | `-c` | 批量查询时的并发数 | `5` |
| `--whois-server` | `-w` | 指定 WHOIS 服务器 | 自动选择 |

### 域名生成模式语法

支持的模式语法：

- `[a-z]`: 小写字母 a-z
- `[A-Z]`: 大写字母 A-Z
- `[0-9]`: 数字 0-9
- `[abc]`: 自定义字符集
- `{n}`: 重复 n 次

示例：

| 模式 | 说明 | 生成数量 |
|------|------|----------|
| `[a-z]{3}.com` | 3 字符小写字母域名 | 17,576 |
| `test[0-9]{2}.net` | test + 两位数字 | 100 |
| `[abc]{2}.org` | abc 的 2 字符组合 | 9 |
| `[a-z]{2}[0-9].com` | 2 字母 + 1 数字 | 2,600 |

### 查看帮助

```bash
# 查看总体帮助
gois --help

# 查看特定命令的帮助
gois query --help
gois batch --help
gois generate --help
```

## 📊 输出格式

### Normal 模式

**终端输出：**

```
================================================================================
域名: github.com
--------------------------------------------------------------------------------

注册商 WHOIS 结果:
Domain Name: github.com
Registry Domain ID: 1264983250_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
...

注册局 WHOIS 结果:
   Domain Name: GITHUB.COM
   Registry Domain ID: 1264983250_DOMAIN_COM-VRSN
...
================================================================================
```

### Simple 模式

**终端输出：**

```
github.com: 已注册
google.com: 已注册
available-domain.com: 可用
```

**文件输出（CSV 格式）：**

```csv
domain,status
github.com,registered
google.com,registered
available-domain.com,available
```

## 💡 使用示例

### 示例 1: 检查域名是否可用

```bash
gois query myawesomedomainname.com -m simple
```

### 示例 2: 批量检查域名并导出 CSV

```bash
gois batch domains.txt -m simple -o available_domains.csv -c 10
```

**适用场景：** 域名选择、域名监控、批量检查域名可用性

### 示例 3: 通过代理查询完整 WHOIS 信息

```bash
gois query github.com -p socks5://localhost:7897 -o github_whois.txt
```

**适用场景：** 需要通过代理访问、避免 IP 限制

### 示例 4: 大批量域名生成与查询

```bash
gois generate "[a-z]{3}.com" -c 20 -m simple -o results.csv
```

**适用场景：** 域名抢注、域名投资

### 示例 5: 自定义字符集域名查询

```bash
gois generate "[0123456789]{4}.cn" -c 15 -m simple -o cn_numbers.csv
```

**适用场景：** 特定类型域名批量检查

## 🏗️ 项目结构

```
gois/
├── cmd/                       # Cobra 命令行定义
│   ├── root.go               # 根命令
│   ├── query.go              # 查询命令
│   ├── batch.go              # 批量命令
│   └── generate.go           # 生成命令
├── pkg/                      # 公共包
│   └── whois/                # WHOIS 核心库
│       ├── client.go         # WHOIS 客户端
│       ├── analyzer.go       # 结果分析器
│       ├── errors.go         # 错误定义
│       ├── tlds.go           # TLD 注册表
│       └── tlds.json         # TLD 数据
├── internal/                 # 内部包
│   └── cli/                  # CLI 逻辑
│       ├── query.go          # 查询逻辑
│       └── generator.go      # 域名生成器
├── main.go                   # 入口
├── go.mod                    # Go 模块定义
└── README.md                 # 本文档
```

## 🔧 核心模块说明

### pkg/whois - WHOIS 核心库

主要功能：
- 建立 WHOIS 服务器连接
- 查询域名信息
- 代理支持
- TLD 自动识别
- 字符编码自动处理

核心类型：
- `Client`: WHOIS 客户端
- `Analyzer`: 结果分析器
- `TLDRegistry`: TLD 注册表

### internal/cli - CLI 逻辑

主要功能：
- 查询逻辑封装
- 并发控制
- 结果输出（终端 + 文件）
- 域名生成器
- 进度追踪

核心类型：
- `CLI`: 命令行工具类
- `QueryConfig`: 查询配置
- `QueryResult`: 查询结果

### cmd - Cobra 命令

主要功能：
- 命令行参数解析
- 子命令定义
- 帮助信息

## ⚠️ 注意事项

1. **WHOIS 服务器频率限制**
   - 大量查询时可能触发 WHOIS 服务器的频率限制
   - 建议控制并发数（推荐：5-10）
   - 可以使用代理分散请求

2. **超时设置**
   - 默认超时 10 秒，根据网络情况可适当调整
   - 网络较慢时建议增加到 15-30 秒

3. **代理配置**
   - 如遇到频率限制，可使用代理
   - 确保代理服务器正常运行

4. **域名生成**
   - 注意生成的域名数量，避免生成过多域名
   - 使用 `[a-z]{5}.com` 会生成 11,881,376 个域名！

5. **文件编码**
   - 所有文件使用 UTF-8 编码
   - Windows 终端可能显示中文乱码，但文件输出正常

## 🐛 故障排查

### 问题 1: 查询超时

**解决方案：**

```bash
# 增加超时时间到 30 秒
gois query example.com -t 30
```

### 问题 2: 代理连接失败

**解决方案：**

```bash
# 检查代理配置是否正确
# 确保代理服务器正在运行
gois query example.com -p socks5://localhost:7897
```

### 问题 3: 编译失败

**解决方案：**

```bash
# 确保 Go 版本 >= 1.18
go version

# 清理并重新获取依赖
go clean -modcache
go mod tidy
go build
```

### 问题 4: WHOIS 服务器无响应

**解决方案：**

```bash
# 尝试指定特定的 WHOIS 服务器
gois query example.com -w whois.verisign-grs.com
```

## 📚 API 使用

除了命令行工具，你也可以在 Go 代码中直接使用：

```go
package main

import (
    "fmt"
    "time"
    
    "gois/pkg/whois"
)

func main() {
    // 创建客户端
    client, err := whois.NewClient(10*time.Second, nil)
    if err != nil {
        panic(err)
    }
    
    // 查询域名
    result, err := client.Fetch("github.com", "")
    if err != nil {
        panic(err)
    }
    
    // 分析结果
    analyzer := whois.NewAnalyzer()
    status := analyzer.GetDomainStatus(result)
    
    fmt.Printf("域名状态: %s\n", status) // available, registered, unknown
    fmt.Printf("注册商: %s\n", analyzer.ExtractRegistrar(result))
}
```

## 📊 性能建议

1. **并发数设置**
   - 小批量（< 50 个域名）：并发 5-10
   - 中等批量（50-500 个）：并发 10-20
   - 大批量（> 500 个）：并发 20-30，建议使用代理

2. **超时时间**
   - 正常网络：10 秒
   - 较慢网络：15-20 秒
   - 代理网络：20-30 秒

## 🙏 致谢

本项目的 WHOIS 查询功能参考了 Python 项目 [Pois](https://github.com/mirhmousavi/Pois) 的实现。

感谢所有开源贡献者！

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📜 许可证

MIT License

---

**提示：** 本工具仅供合法用途，请遵守相关法律法规和 WHOIS 服务器的使用条款。

