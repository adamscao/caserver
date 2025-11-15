# SSH CA 签发服务 - 项目架构文档

## 1. 项目概述

本项目是一个基于 Go 语言实现的 SSH 证书签发服务（CA Server），提供统一的 SSH 用户证书签发和续签功能，配合 Nginx 提供 HTTPS 前端代理。

**技术栈：**
- 语言：Go 1.21+
- 数据库：SQLite 3
- Web 框架：Gin（或 Chi/Echo）
- 配置管理：YAML
- 依赖管理：Go Modules

---

## 2. 目录结构

```
caserver/
├── cmd/
│   ├── caserver/              # 主服务入口
│   │   └── main.go
│   └── admin/                 # 管理工具（创建用户、查询等）
│       └── main.go
├── internal/                  # 私有代码，不可被外部导入
│   ├── api/                   # HTTP API 处理器
│   │   ├── handlers/          # 各种 HTTP handler
│   │   │   ├── ca.go          # CA 公钥下载
│   │   │   ├── certs.go       # 证书签发和续签
│   │   │   ├── bootstrap.go   # 引导脚本下载
│   │   │   ├── register.go    # 服务器注册
│   │   │   └── admin.go       # 管理员接口
│   │   ├── middleware/        # 中间件
│   │   │   ├── auth.go        # 认证中间件
│   │   │   ├── ratelimit.go   # 限流中间件
│   │   │   └── logger.go      # 日志中间件
│   │   └── router.go          # 路由配置
│   ├── ca/                    # CA 核心逻辑
│   │   ├── keypair.go         # CA 密钥对管理
│   │   ├── signer.go          # 证书签发逻辑
│   │   └── cert.go            # 证书解析和验证
│   ├── auth/                  # 认证模块
│   │   ├── password.go        # 密码哈希和验证
│   │   ├── totp.go            # TOTP 生成和验证
│   │   └── token.go           # Renew Token 管理
│   ├── models/                # 数据模型
│   │   ├── user.go            # 用户模型
│   │   ├── cert.go            # 证书记录模型
│   │   ├── token.go           # Token 模型
│   │   ├── server.go          # 服务器模型
│   │   └── audit.go           # 审计日志模型
│   ├── db/                    # 数据库操作
│   │   ├── sqlite.go          # SQLite 连接管理
│   │   ├── migrations.go      # 数据库迁移
│   │   └── repository/        # 数据访问层
│   │       ├── user.go
│   │       ├── cert.go
│   │       ├── token.go
│   │       ├── server.go
│   │       └── audit.go
│   ├── config/                # 配置管理
│   │   ├── config.go          # 配置结构定义
│   │   └── loader.go          # 配置加载逻辑
│   ├── policy/                # 策略引擎
│   │   ├── validator.go       # 签发策略验证
│   │   └── ratelimit.go       # 频率限制
│   └── scripts/               # 内嵌脚本
│       ├── server.sh          # 服务器引导脚本模板
│       └── client.sh          # 客户端引导脚本模板
├── pkg/                       # 可导出的公共包（如需要）
│   └── sshutil/               # SSH 工具函数
│       └── fingerprint.go     # 公钥指纹计算
├── scripts/                   # 外部脚本和工具
│   ├── install.sh             # 一键安装脚本
│   └── systemd/               # systemd 服务配置
│       └── ssh-ca.service
├── configs/                   # 配置文件示例
│   └── config.yaml.example
├── deployments/               # 部署配置
│   └── nginx/
│       └── nginx.conf.example
├── test/                      # 集成测试
│   └── integration/
├── docs/                      # 文档
│   ├── api.md                 # API 文档
│   ├── deployment.md          # 部署文档
│   └── development.md         # 开发文档
├── requirement.txt            # 需求文档
├── architecture.md            # 本文档
├── database_schema.md         # 数据库设计
├── go.mod                     # Go 模块定义
├── go.sum                     # 依赖校验
├── Makefile                   # 构建脚本
└── README.md                  # 项目说明
```

---

## 3. 模块职责

### 3.1 cmd/caserver - 主服务

**职责：**
- 程序入口
- 初始化配置
- 初始化数据库连接
- 初始化 CA 密钥对（自动生成）
- 启动 HTTP 服务器
- 优雅关闭处理

**主要流程：**
```
启动 → 加载配置 → 初始化数据库 → 检查/生成 CA 密钥 → 运行数据库迁移 → 启动 HTTP 服务
```

### 3.2 cmd/admin - 管理工具

**职责：**
- 提供命令行管理工具
- 用户管理（创建、禁用、查看）
- TOTP 种子生成
- 审计日志查询
- 服务器列表查询

**示例命令：**
```bash
# 创建用户
./admin user create --username adams --password xxx --generate-totp

# 查看用户
./admin user list

# 查看审计日志
./admin audit list --username adams --limit 100

# 查看已注册服务器
./admin server list
```

### 3.3 internal/api - HTTP API 层

**职责：**
- 定义所有 HTTP 接口
- 请求参数验证
- 响应格式化
- 错误处理

**关键组件：**

#### handlers/ca.go
- `GET /v1/ca/user` - 返回 CA 公钥内容

#### handlers/certs.go
- `POST /v1/certs/issue` - 首次签发
  - 验证用户名/密码/TOTP
  - 检查签发策略
  - 调用 CA signer 签发证书
  - 生成 renew_token
  - 记录审计日志

- `POST /v1/certs/renew` - 续签
  - 验证 renew_token
  - 检查公钥指纹匹配
  - 检查频率限制
  - 签发新证书

#### handlers/bootstrap.go
- `GET /v1/bootstrap/server.sh` - 返回服务器引导脚本
- `GET /v1/bootstrap/client.sh` - 返回客户端引导脚本

#### handlers/register.go
- `POST /v1/register/server` - 接收服务器注册信息

#### handlers/admin.go
- `POST /v1/admin/users` - 创建用户（需管理员 token）

#### middleware/auth.go
- 管理员 token 验证中间件
- 用户认证中间件（如需要）

#### middleware/ratelimit.go
- IP 级别限流
- 用户级别限流

#### middleware/logger.go
- 请求日志记录
- 响应时间统计

### 3.4 internal/ca - 证书签发核心

**职责：**
- CA 密钥对管理
- SSH 证书签发
- 证书解析和验证

**关键文件：**

#### keypair.go
```go
type KeyPair struct {
    PrivateKey crypto.Signer
    PublicKey  []byte
}

// LoadOrGenerateKeyPair 加载或生成 CA 密钥对
func LoadOrGenerateKeyPair(path string, keyType string) (*KeyPair, error)

// SaveKeyPair 保存密钥对到文件
func SaveKeyPair(kp *KeyPair, path string) error
```

#### signer.go
```go
type SignRequest struct {
    PublicKey      string
    Principal      string
    ValidityPeriod time.Duration
    SerialNumber   uint64
    KeyID          string
}

// SignCertificate 签发 SSH 证书
func SignCertificate(kp *KeyPair, req *SignRequest) ([]byte, error)
```

#### cert.go
```go
// ParseCertificate 解析 SSH 证书
func ParseCertificate(certData []byte) (*ssh.Certificate, error)

// ValidateCertificate 验证证书是否由本 CA 签发
func ValidateCertificate(cert *ssh.Certificate, caPubKey []byte) error

// GetFingerprint 获取公钥指纹
func GetFingerprint(pubkey []byte) (string, error)
```

### 3.5 internal/auth - 认证模块

**职责：**
- 密码哈希和验证
- TOTP 生成和验证
- Renew Token 管理

**关键文件：**

#### password.go
```go
// HashPassword 使用 Argon2id 哈希密码
func HashPassword(password string) (string, error)

// VerifyPassword 验证密码
func VerifyPassword(password, hash string) (bool, error)
```

#### totp.go
```go
// GenerateTOTPSecret 生成 TOTP 种子
func GenerateTOTPSecret() (string, error)

// GenerateQRCodeURL 生成 QR 码 URL
func GenerateQRCodeURL(secret, username, issuer string) string

// ValidateTOTP 验证 TOTP 码（考虑时间偏移）
func ValidateTOTP(secret, code string) (bool, error)
```

#### token.go
```go
// GenerateRenewToken 生成续签 token
func GenerateRenewToken() (string, error)

// HashToken 哈希 token 用于存储
func HashToken(token string) string

// VerifyToken 验证 token
func VerifyToken(token, hash string) (bool, error)
```

### 3.6 internal/models - 数据模型

**职责：**
- 定义所有数据结构

**关键模型：**

#### user.go
```go
type User struct {
    ID              int64
    Username        string
    PasswordHash    string
    TOTPSecret      string    // 加密存储
    Enabled         bool
    MaxCertsPerDay  int
    CreatedAt       time.Time
    UpdatedAt       time.Time
}
```

#### cert.go
```go
type CertificateRecord struct {
    ID              int64
    UserID          int64
    PublicKeyFP     string    // 公钥指纹
    SerialNumber    uint64
    Principal       string
    ValidFrom       time.Time
    ValidTo         time.Time
    ClientIP        string
    ClientHostname  string
    UserAgent       string
    IssuedAt        time.Time
}
```

#### token.go
```go
type RenewToken struct {
    ID          int64
    UserID      int64
    TokenHash   string
    PublicKeyFP string
    CreatedAt   time.Time
    ExpiresAt   time.Time
    LastUsedAt  *time.Time
}
```

#### server.go
```go
type RegisteredServer struct {
    ID              int64
    Hostname        string
    OS              string
    Kernel          string
    Arch            string
    IPAddresses     string    // JSON array
    SSHVersion      string
    AnsibleUser     string
    AnsiblePubkey   string
    Labels          string    // JSON array
    CATrusted       bool
    RegisteredAt    time.Time
    LastSeenAt      time.Time
}
```

#### audit.go
```go
type AuditLog struct {
    ID          int64
    Timestamp   time.Time
    Action      string    // issue, renew, admin_create_user, etc.
    Username    string
    ClientIP    string
    UserAgent   string
    Success     bool
    ErrorMsg    string
    Details     string    // JSON
}
```

### 3.7 internal/db - 数据访问层

**职责：**
- 数据库连接管理
- 数据库迁移
- CRUD 操作封装

**关键文件：**

#### sqlite.go
```go
type DB struct {
    *sql.DB
}

// NewDB 创建数据库连接
func NewDB(path string) (*DB, error)

// Close 关闭连接
func (db *DB) Close() error
```

#### migrations.go
```go
// RunMigrations 执行数据库迁移
func RunMigrations(db *DB) error
```

#### repository/*.go
实现各个模型的数据访问方法：
- `CreateUser`, `GetUserByUsername`, `UpdateUser`
- `CreateCertRecord`, `GetUserCertCountToday`
- `CreateRenewToken`, `ValidateRenewToken`, `GetTokenByHash`
- `CreateServerRecord`, `GetServerByHostname`
- `CreateAuditLog`, `ListAuditLogs`

### 3.8 internal/config - 配置管理

**职责：**
- 加载 YAML 配置文件
- 环境变量覆盖
- 配置验证

**关键文件：**

#### config.go
```go
type Config struct {
    Server       ServerConfig
    Database     DatabaseConfig
    CA           CAConfig
    Policy       PolicyConfig
    RenewToken   RenewTokenConfig
    Admin        AdminConfig
    Logging      LoggingConfig
}

type ServerConfig struct {
    ListenAddr string `yaml:"listen_addr"`
}

type PolicyConfig struct {
    DefaultValidity  string `yaml:"default_validity"`
    MaxValidity      string `yaml:"max_validity"`
    MaxCertsPerDay   int    `yaml:"max_certs_per_day"`
}

// ... 其他配置结构
```

#### loader.go
```go
// Load 从文件加载配置
func Load(path string) (*Config, error)

// LoadWithEnv 加载配置并应用环境变量覆盖
func LoadWithEnv(path string) (*Config, error)
```

### 3.9 internal/policy - 策略引擎

**职责：**
- 验证签发请求是否符合策略
- 频率限制检查

**关键文件：**

#### validator.go
```go
type PolicyValidator struct {
    config *config.PolicyConfig
    db     *db.DB
}

// ValidateIssueRequest 验证签发请求
func (v *PolicyValidator) ValidateIssueRequest(
    user *models.User,
    principal string,
    validity time.Duration,
) error

// ValidateRenewRequest 验证续签请求
func (v *PolicyValidator) ValidateRenewRequest(
    user *models.User,
    token *models.RenewToken,
) error
```

### 3.10 internal/scripts - 内嵌脚本

**职责：**
- 存储引导脚本模板
- 使用 `//go:embed` 内嵌到二进制

**关键文件：**

#### server.sh
完整的服务器引导脚本（根据 requirement.txt 第 8.3 节）

#### client.sh
完整的客户端引导脚本（根据 requirement.txt 第 9.3 节）

---

## 4. 关键流程

### 4.1 首次签发流程

```
客户端请求
    ↓
API Handler (certs.go)
    ↓
验证用户名/密码 (auth/password.go)
    ↓
验证 TOTP (auth/totp.go)
    ↓
策略验证 (policy/validator.go)
    ├── 检查每日签发次数
    ├── 验证 principal 与用户名一致
    └── 调整有效期（如超限）
    ↓
签发证书 (ca/signer.go)
    ↓
生成 RenewToken (auth/token.go)
    ↓
保存证书记录 (db/repository/cert.go)
    ↓
保存 RenewToken (db/repository/token.go)
    ↓
记录审计日志 (db/repository/audit.go)
    ↓
返回响应（证书 + token）
```

### 4.2 续签流程

```
客户端请求（带 renew_token）
    ↓
API Handler (certs.go)
    ↓
验证 RenewToken (db/repository/token.go)
    ├── 检查 token 是否存在
    ├── 检查是否过期
    └── 检查公钥指纹匹配
    ↓
策略验证 (policy/validator.go)
    └── 检查签发频率限制
    ↓
签发新证书 (ca/signer.go)
    ↓
保存证书记录
    ↓
更新 token 最后使用时间
    ↓
记录审计日志
    ↓
返回响应（新证书）
```

### 4.3 服务器注册流程

```
服务器运行引导脚本
    ↓
下载 CA 公钥 (GET /v1/ca/user)
    ↓
配置 sshd_config
    ↓
生成 ansible SSH key
    ↓
收集系统信息
    ↓
POST /v1/register/server
    ↓
API Handler (register.go)
    ↓
保存到数据库 (db/repository/server.go)
    ↓
返回 server_id
```

---

## 5. 部署架构

### 5.1 单机部署

```
┌─────────────────────────────────────┐
│         Nginx (443 HTTPS)           │
│   - TLS 终止                         │
│   - 反向代理                         │
│   - 静态文件服务（可选）             │
└──────────────┬──────────────────────┘
               │
               ↓ 127.0.0.1:2025
┌─────────────────────────────────────┐
│      caserver (Go 服务)             │
│   - HTTP API                        │
│   - 证书签发                         │
│   - 认证逻辑                         │
└──────────────┬──────────────────────┘
               │
               ↓ SQLite
┌─────────────────────────────────────┐
│   /var/lib/ssh-ca/caserver.db       │
│   - 用户数据                         │
│   - 证书记录                         │
│   - 审计日志                         │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  /etc/ssl/ssh-ca/ssh_user_ca        │
│   - CA 私钥 (600)                    │
│   - CA 公钥                          │
└─────────────────────────────────────┘
```

### 5.2 文件权限

```
/etc/ssl/ssh-ca/
├── ssh_user_ca         (600, owner: ssh-ca)
└── ssh_user_ca.pub     (644, owner: ssh-ca)

/var/lib/ssh-ca/
└── caserver.db         (600, owner: ssh-ca)

/etc/ssh-ca/
└── config.yaml         (600, owner: ssh-ca)
```

### 5.3 Systemd 服务

```ini
[Unit]
Description=SSH CA Server
After=network.target

[Service]
Type=simple
User=ssh-ca
Group=ssh-ca
ExecStart=/usr/local/bin/caserver -config /etc/ssh-ca/config.yaml
Restart=on-failure
RestartSec=5s

# 安全强化
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ssh-ca

[Install]
WantedBy=multi-user.target
```

---

## 6. 构建和开发

### 6.1 构建命令

```makefile
# Makefile 示例

.PHONY: build test clean install

build:
	go build -o bin/caserver ./cmd/caserver
	go build -o bin/admin ./cmd/admin

test:
	go test -v ./...

test-integration:
	go test -v ./test/integration/...

clean:
	rm -rf bin/

install:
	install -m 755 bin/caserver /usr/local/bin/
	install -m 755 bin/admin /usr/local/bin/
	install -m 644 scripts/systemd/ssh-ca.service /etc/systemd/system/

run:
	go run ./cmd/caserver -config configs/config.yaml.example
```

### 6.2 开发环境

```bash
# 克隆项目
git clone <repo>
cd caserver

# 安装依赖
go mod download

# 创建测试配置
cp configs/config.yaml.example configs/config.yaml

# 运行服务
make run

# 创建测试用户
go run ./cmd/admin user create --username test --password test123
```

---

## 7. 依赖库选择

**核心依赖：**

```go
require (
    github.com/gin-gonic/gin v1.10.0           // Web 框架
    golang.org/x/crypto v0.x.x                 // SSH、密码哈希
    github.com/mattn/go-sqlite3 v1.14.x        // SQLite 驱动
    github.com/pquerna/otp v1.4.0              // TOTP 实现
    gopkg.in/yaml.v3 v3.0.x                    // YAML 解析
    github.com/spf13/cobra v1.8.x              // CLI 框架（admin 工具）
)
```

**可选依赖：**

```go
require (
    github.com/sirupsen/logrus v1.9.x          // 结构化日志
    github.com/stretchr/testify v1.9.x         // 测试工具
    github.com/golang-migrate/migrate/v4 v4.x  // 数据库迁移（如使用）
)
```

---

## 8. 安全考虑

### 8.1 密钥存储

- CA 私钥：文件系统，600 权限，专用用户
- 用户密码：Argon2id 哈希
- TOTP 种子：应用级加密（使用配置中的加密密钥）
- Renew Token：SHA-256 哈希存储

### 8.2 网络安全

- 仅监听 127.0.0.1（由 Nginx 暴露 HTTPS）
- Nginx 配置 TLS 1.2+ 强加密
- 限流防止暴力破解

### 8.3 进程隔离

- 专用用户运行（ssh-ca）
- Systemd 安全强化选项
- 最小权限原则

---

## 9. 扩展性考虑

虽然当前设计为单机部署，但架构已预留扩展空间：

1. **数据库切换**：Repository 模式便于切换到 PostgreSQL/MySQL
2. **分布式部署**：可引入 Redis 做 token 缓存和分布式锁
3. **高可用**：主从复制、读写分离
4. **多 CA 支持**：代码结构支持多 CA 实例管理

---

## 10. 监控和运维

### 10.1 日志

- 应用日志：结构化 JSON 输出到 stdout
- 审计日志：SQLite 持久化
- Nginx 访问日志：标准格式

### 10.2 健康检查

添加健康检查端点：
- `GET /health` - 服务健康状态
- `GET /readiness` - 就绪状态（数据库连接、CA 密钥加载）

### 10.3 备份

重要数据：
- SQLite 数据库：定期备份 `/var/lib/ssh-ca/caserver.db`
- CA 私钥：**极其重要**，必须安全备份

---

## 11. 下一步计划

1. 实现核心模块（ca、auth、db）
2. 实现 HTTP API
3. 编写单元测试
4. 实现引导脚本
5. 编写集成测试
6. 部署文档和示例配置
7. 性能测试和优化
