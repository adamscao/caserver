# SSH CA Server - 数据库 Schema 设计

## 1. 概述

本文档定义 SSH CA 签发服务的 SQLite 数据库结构。

**数据库文件：** `/var/lib/ssh-ca/caserver.db`

**Schema 版本：** 1.0

---

## 2. 表结构

### 2.1 users - 用户表

存储系统用户账号信息。

```sql
CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,              -- Argon2id 哈希
    totp_secret       TEXT NOT NULL,              -- Base32 编码的 TOTP 种子（加密存储）
    enabled           INTEGER NOT NULL DEFAULT 1, -- 1=启用, 0=禁用
    max_certs_per_day INTEGER NOT NULL DEFAULT 10,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_enabled ON users(enabled);
```

**字段说明：**

- `id`：用户唯一标识
- `username`：用户名（唯一），也是证书 principal
- `password_hash`：密码哈希值，使用 Argon2id
- `totp_secret`：TOTP 种子，Base32 编码，需加密存储
- `enabled`：账号状态，0=禁用，1=启用
- `max_certs_per_day`：每日最大签发次数限制
- `created_at`：账号创建时间
- `updated_at`：最后更新时间

**示例数据：**

```sql
INSERT INTO users (username, password_hash, totp_secret, enabled, max_certs_per_day)
VALUES (
    'adams',
    '$argon2id$v=19$m=65536,t=3,p=4$...',
    'JBSWY3DPEHPK3PXP',
    1,
    10
);
```

---

### 2.2 certificates - 证书签发记录表

存储所有已签发证书的审计记录。

```sql
CREATE TABLE certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    public_key_fp   TEXT NOT NULL,              -- SHA256 指纹
    serial_number   INTEGER NOT NULL UNIQUE,    -- 证书序列号
    principal       TEXT NOT NULL,
    valid_from      DATETIME NOT NULL,
    valid_to        DATETIME NOT NULL,
    client_ip       TEXT NOT NULL,
    client_hostname TEXT,
    user_agent      TEXT,
    issued_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_certs_user_id ON certificates(user_id);
CREATE INDEX idx_certs_serial ON certificates(serial_number);
CREATE INDEX idx_certs_fp ON certificates(public_key_fp);
CREATE INDEX idx_certs_issued_at ON certificates(issued_at);
CREATE INDEX idx_certs_valid_to ON certificates(valid_to);
```

**字段说明：**

- `id`：记录 ID
- `user_id`：关联的用户 ID
- `public_key_fp`：公钥 SHA256 指纹（格式：`SHA256:xxxxx`）
- `serial_number`：证书序列号（全局唯一，递增）
- `principal`：证书主体（通常等于 username）
- `valid_from`：证书生效时间
- `valid_to`：证书过期时间
- `client_ip`：客户端 IP 地址
- `client_hostname`：客户端主机名（可选）
- `user_agent`：客户端 User-Agent
- `issued_at`：签发时间

**用途：**

- 审计追踪
- 统计每日签发次数
- 检测异常行为（如同一公钥频繁签发）

---

### 2.3 renew_tokens - 续签令牌表

存储用于自动续签的 token。

```sql
CREATE TABLE renew_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,       -- SHA256 哈希
    public_key_fp   TEXT NOT NULL,              -- 绑定的公钥指纹
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    last_used_at    DATETIME,                   -- 最后使用时间

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_tokens_user_id ON renew_tokens(user_id);
CREATE INDEX idx_tokens_hash ON renew_tokens(token_hash);
CREATE INDEX idx_tokens_fp ON renew_tokens(public_key_fp);
CREATE INDEX idx_tokens_expires_at ON renew_tokens(expires_at);
```

**字段说明：**

- `id`：Token ID
- `user_id`：关联的用户 ID
- `token_hash`：Token 的 SHA256 哈希值（不存储明文）
- `public_key_fp`：绑定的公钥指纹
- `created_at`：Token 创建时间
- `expires_at`：Token 过期时间
- `last_used_at`：最后一次使用时间（用于续签）

**说明：**

- 一个用户可以有多个有效 token（对应不同的机器/公钥）
- Token 以哈希形式存储，验证时需对客户端提供的 token 计算哈希后比对
- 过期的 token 可以定期清理

---

### 2.4 registered_servers - 已注册服务器表

存储通过引导脚本注册的服务器信息。

```sql
CREATE TABLE registered_servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL,
    os              TEXT,
    kernel          TEXT,
    arch            TEXT,
    ip_addresses    TEXT,                       -- JSON array: ["10.0.1.10", "192.168.1.50"]
    ssh_version     TEXT,
    ansible_user    TEXT,
    ansible_pubkey  TEXT,
    labels          TEXT,                       -- JSON array: ["prod", "web"]
    ca_trusted      INTEGER NOT NULL DEFAULT 0, -- 1=已配置 TrustedUserCAKeys
    registered_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_servers_hostname ON registered_servers(hostname);
CREATE INDEX idx_servers_registered_at ON registered_servers(registered_at);
```

**字段说明：**

- `id`：服务器 ID
- `hostname`：主机名
- `os`：操作系统（如 "Ubuntu 22.04"）
- `kernel`：内核版本
- `arch`：架构（x86_64, arm64 等）
- `ip_addresses`：IP 地址列表（JSON 数组）
- `ssh_version`：SSH 版本（如 "OpenSSH_9.6p1"）
- `ansible_user`：Ansible 用户名
- `ansible_pubkey`：Ansible 公钥
- `labels`：标签（JSON 数组，用于分类）
- `ca_trusted`：是否已配置 CA 信任
- `registered_at`：首次注册时间
- `last_seen_at`：最后上报时间

**用途：**

- 服务器资产管理
- 生成 Ansible inventory
- 监控服务器接入情况

---

### 2.5 audit_logs - 审计日志表

存储所有重要操作的审计日志。

```sql
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action      TEXT NOT NULL,              -- issue, renew, admin_create_user, etc.
    username    TEXT,                       -- 操作的用户（可能为空，如服务器注册）
    client_ip   TEXT NOT NULL,
    user_agent  TEXT,
    success     INTEGER NOT NULL,           -- 1=成功, 0=失败
    error_msg   TEXT,                       -- 失败原因
    details     TEXT                        -- JSON 格式的详细信息
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_success ON audit_logs(success);
CREATE INDEX idx_audit_client_ip ON audit_logs(client_ip);
```

**字段说明：**

- `id`：日志 ID
- `timestamp`：时间戳
- `action`：操作类型
  - `cert_issue`：首次签发证书
  - `cert_renew`：续签证书
  - `admin_create_user`：管理员创建用户
  - `server_register`：服务器注册
  - `auth_failed`：认证失败
- `username`：关联的用户名
- `client_ip`：客户端 IP
- `user_agent`：User-Agent
- `success`：操作是否成功
- `error_msg`：失败时的错误消息
- `details`：JSON 格式的详细信息

**示例数据：**

```sql
INSERT INTO audit_logs (action, username, client_ip, success, details)
VALUES (
    'cert_issue',
    'adams',
    '192.168.1.100',
    1,
    '{"public_key_fp": "SHA256:xxx", "principal": "adams", "validity": "24h"}'
);

INSERT INTO audit_logs (action, username, client_ip, success, error_msg)
VALUES (
    'auth_failed',
    'adams',
    '192.168.1.100',
    0,
    'Invalid TOTP code'
);
```

---

## 3. 初始化 SQL

完整的数据库初始化脚本：

```sql
-- Schema version tracking
CREATE TABLE schema_version (
    version INTEGER NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_version (version) VALUES (1);

-- Users table
CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    totp_secret       TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    max_certs_per_day INTEGER NOT NULL DEFAULT 10,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_enabled ON users(enabled);

-- Certificates table
CREATE TABLE certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    public_key_fp   TEXT NOT NULL,
    serial_number   INTEGER NOT NULL UNIQUE,
    principal       TEXT NOT NULL,
    valid_from      DATETIME NOT NULL,
    valid_to        DATETIME NOT NULL,
    client_ip       TEXT NOT NULL,
    client_hostname TEXT,
    user_agent      TEXT,
    issued_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_certs_user_id ON certificates(user_id);
CREATE INDEX idx_certs_serial ON certificates(serial_number);
CREATE INDEX idx_certs_fp ON certificates(public_key_fp);
CREATE INDEX idx_certs_issued_at ON certificates(issued_at);
CREATE INDEX idx_certs_valid_to ON certificates(valid_to);

-- Renew tokens table
CREATE TABLE renew_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    public_key_fp   TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    last_used_at    DATETIME,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_tokens_user_id ON renew_tokens(user_id);
CREATE INDEX idx_tokens_hash ON renew_tokens(token_hash);
CREATE INDEX idx_tokens_fp ON renew_tokens(public_key_fp);
CREATE INDEX idx_tokens_expires_at ON renew_tokens(expires_at);

-- Registered servers table
CREATE TABLE registered_servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL,
    os              TEXT,
    kernel          TEXT,
    arch            TEXT,
    ip_addresses    TEXT,
    ssh_version     TEXT,
    ansible_user    TEXT,
    ansible_pubkey  TEXT,
    labels          TEXT,
    ca_trusted      INTEGER NOT NULL DEFAULT 0,
    registered_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_servers_hostname ON registered_servers(hostname);
CREATE INDEX idx_servers_registered_at ON registered_servers(registered_at);

-- Audit logs table
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action      TEXT NOT NULL,
    username    TEXT,
    client_ip   TEXT NOT NULL,
    user_agent  TEXT,
    success     INTEGER NOT NULL,
    error_msg   TEXT,
    details     TEXT
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_success ON audit_logs(success);
CREATE INDEX idx_audit_client_ip ON audit_logs(client_ip);
```

---

## 4. 常用查询示例

### 4.1 查询用户今日签发次数

```sql
SELECT COUNT(*) as count
FROM certificates
WHERE user_id = ?
  AND DATE(issued_at) = DATE('now');
```

### 4.2 查询即将过期的证书

```sql
SELECT c.*, u.username
FROM certificates c
JOIN users u ON c.user_id = u.id
WHERE c.valid_to < DATETIME('now', '+24 hours')
  AND c.valid_to > DATETIME('now')
ORDER BY c.valid_to ASC;
```

### 4.3 查询用户的有效 Token

```sql
SELECT *
FROM renew_tokens
WHERE user_id = ?
  AND expires_at > DATETIME('now')
ORDER BY created_at DESC;
```

### 4.4 验证 Renew Token

```sql
SELECT rt.*, u.username
FROM renew_tokens rt
JOIN users u ON rt.user_id = u.id
WHERE rt.token_hash = ?
  AND rt.expires_at > DATETIME('now')
  AND u.enabled = 1;
```

### 4.5 查询最近的审计日志

```sql
SELECT *
FROM audit_logs
WHERE username = ?
ORDER BY timestamp DESC
LIMIT 100;
```

### 4.6 统计每日签发量

```sql
SELECT DATE(issued_at) as date, COUNT(*) as count
FROM certificates
WHERE issued_at >= DATE('now', '-30 days')
GROUP BY DATE(issued_at)
ORDER BY date DESC;
```

### 4.7 查询失败的认证尝试

```sql
SELECT *
FROM audit_logs
WHERE action = 'auth_failed'
  AND timestamp >= DATETIME('now', '-1 hour')
ORDER BY timestamp DESC;
```

### 4.8 清理过期 Token

```sql
DELETE FROM renew_tokens
WHERE expires_at < DATETIME('now', '-30 days');
```

---

## 5. 数据维护

### 5.1 定期清理

**建议清理策略：**

1. **过期的 Renew Token**（保留 30 天）：
   ```sql
   DELETE FROM renew_tokens
   WHERE expires_at < DATETIME('now', '-30 days');
   ```

2. **旧的审计日志**（可选，根据合规要求）：
   ```sql
   -- 仅在日志过大时执行，建议保留至少 1 年
   DELETE FROM audit_logs
   WHERE timestamp < DATETIME('now', '-1 year');
   ```

3. **过期的证书记录**（可选）：
   ```sql
   -- 历史证书记录建议永久保留用于审计
   -- 如需清理，至少保留 1 年
   DELETE FROM certificates
   WHERE valid_to < DATETIME('now', '-1 year');
   ```

### 5.2 数据库优化

```sql
-- 定期执行 VACUUM 优化数据库
VACUUM;

-- 重建索引
REINDEX;

-- 分析统计信息
ANALYZE;
```

### 5.3 备份

```bash
# 备份数据库
sqlite3 /var/lib/ssh-ca/caserver.db ".backup /backup/caserver-$(date +%Y%m%d).db"

# 导出为 SQL
sqlite3 /var/lib/ssh-ca/caserver.db .dump > /backup/caserver-$(date +%Y%m%d).sql
```

---

## 6. 数据加密

### 6.1 TOTP Secret 加密

用户的 `totp_secret` 字段应使用应用级加密：

**加密方式：**
- 算法：AES-256-GCM
- 密钥来源：配置文件或环境变量（`SSH_CA_ENCRYPTION_KEY`）
- 存储格式：Base64(nonce + ciphertext + tag)

**示例（伪代码）：**

```go
// 存储时加密
encryptedSecret := encrypt(plaintextSecret, encryptionKey)
db.Exec("INSERT INTO users (totp_secret, ...) VALUES (?, ...)", encryptedSecret)

// 读取时解密
var encryptedSecret string
db.QueryRow("SELECT totp_secret FROM users WHERE id=?", userID).Scan(&encryptedSecret)
plaintextSecret := decrypt(encryptedSecret, encryptionKey)
```

### 6.2 密钥管理

**加密密钥（Encryption Key）：**
- 32 字节随机密钥
- 存储在配置文件或环境变量
- 生成示例：`openssl rand -hex 32`

---

## 7. 迁移策略

### 7.1 Schema 版本控制

使用 `schema_version` 表跟踪版本：

```sql
SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1;
```

### 7.2 迁移示例

假设需要添加新字段：

```sql
-- Migration: v1 -> v2
-- Add email field to users table

ALTER TABLE users ADD COLUMN email TEXT;

INSERT INTO schema_version (version) VALUES (2);
```

在代码中实现：

```go
func runMigrations(db *sql.DB) error {
    currentVersion := getCurrentVersion(db)

    migrations := []Migration{
        {Version: 1, SQL: initialSchema},
        {Version: 2, SQL: addEmailField},
        // ... more migrations
    }

    for _, m := range migrations {
        if m.Version > currentVersion {
            if err := m.Apply(db); err != nil {
                return err
            }
        }
    }

    return nil
}
```

---

## 8. 性能考虑

### 8.1 索引策略

所有频繁查询的字段都已建立索引：
- 用户名查找：`idx_users_username`
- 证书序列号：`idx_certs_serial`（唯一性约束）
- Token 查找：`idx_tokens_hash`
- 时间范围查询：`idx_audit_timestamp`, `idx_certs_issued_at`

### 8.2 查询优化

1. 使用 prepared statements 防止 SQL 注入并提升性能
2. 批量插入时使用事务
3. 定期执行 `ANALYZE` 更新统计信息

### 8.3 并发控制

SQLite 默认支持并发读，单一写入。对于本项目场景（签发服务）：
- 读操作：CA 公钥下载、审计查询（高频）
- 写操作：证书签发、日志记录（中等频率）

**建议配置：**

```sql
PRAGMA journal_mode = WAL;  -- Write-Ahead Logging，提升并发性能
PRAGMA synchronous = NORMAL; -- 平衡性能和安全性
PRAGMA cache_size = -64000;  -- 64MB 缓存
PRAGMA temp_store = MEMORY;  -- 临时表使用内存
```

在 Go 代码中设置：

```go
db.Exec("PRAGMA journal_mode = WAL")
db.Exec("PRAGMA synchronous = NORMAL")
db.Exec("PRAGMA cache_size = -64000")
db.Exec("PRAGMA temp_store = MEMORY")
```

---

## 9. 数据完整性

### 9.1 外键约束

确保启用外键支持：

```go
db.Exec("PRAGMA foreign_keys = ON")
```

### 9.2 约束检查

- `username` UNIQUE：防止重复用户
- `serial_number` UNIQUE：防止证书序列号冲突
- `token_hash` UNIQUE：防止 token 哈希冲突
- NOT NULL 约束：确保关键字段非空

---

## 10. 安全建议

1. **数据库文件权限**：600，仅服务进程用户可读写
2. **定期备份**：每日备份数据库文件
3. **审计日志**：永久保留，定期归档
4. **敏感数据加密**：TOTP secret 应用级加密
5. **SQL 注入防护**：使用 prepared statements
6. **最小权限**：服务进程仅需读写数据库文件

---

## 附录 A：完整 Schema DDL

见第 3 节的初始化 SQL。

## 附录 B：数据字典

| 表名 | 用途 | 关键字段 | 估计增长率 |
|------|------|----------|------------|
| users | 用户账号 | username | 低（手动创建） |
| certificates | 证书记录 | serial_number, user_id | 中（每次签发） |
| renew_tokens | 续签令牌 | token_hash | 中（每次首次签发） |
| registered_servers | 服务器资产 | hostname | 低（手动注册） |
| audit_logs | 审计日志 | action, timestamp | 高（每次请求） |

**预估数据量（以 100 用户、1 年运行为例）：**

- users: ~100 行
- certificates: ~36,500 行（100 用户 × 365 天 × 1 次/天）
- renew_tokens: ~200 行（每用户 2 个 token）
- registered_servers: ~50 行
- audit_logs: ~100,000 行（包括失败请求）

**数据库大小估算：** < 100 MB

---

**文档版本：** 1.0
**最后更新：** 2025-11-15
