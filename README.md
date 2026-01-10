# Gemini Business OpenAI Gateway

将 Google Gemini Business API (Widget Interface) 转换为 OpenAI 格式的网关服务。支持 **真流式 (True Streaming)** 输出，**多账号负载均衡**，**Web 管理后台**，像官网一样逐字显示。

## ✨ 核心特性

### 🚀 真流式响应
- 基于 HTTP SSE (Server-Sent Events) 实现，实时输出 Token，告别等待
- **🧠 智能过滤**: 自动识别并屏蔽 "Assessing the Request", "Generating Response" 等内部思考日志，保持输出纯净
- **🌏 编码修复**: 内置增量 UTF-8 解码器，完美解决流式传输中的中文乱码问题
- **⚡️ 高性能解析**: 优化的 JSON 流解析器，低 CPU 占用

### 👥 多账号管理
- **账号池 (Account Pool)**: 支持多个 Gemini Business 账号轮换使用
- **Failover 策略**: 优先使用第一个可用账号，确保稳定性
- **会话持久化**: 自动管理会话 ID，支持多轮对话上下文
- **模型粘性 (Model Stickiness)**: 为用户自动升级并记住模型偏好
- **PostgreSQL 存储**: 账号信息持久化存储，支持动态增删改查

### 🎛 Web 管理后台
- **可视化界面**: 现代化暗色主题管理控制台 (`/admin`)
- **账号管理**: 通过 UI 添加/编辑/删除账号，无需手动修改配置文件
- **批量导入**: 支持粘贴式快速导入账号配置
- **状态监控**: 查看账号最后使用时间、启用状态等信息
- **安全认证**: API Key 保护，防止未授权访问

### 🖼 多模态支持
- 支持 `gpt-4-vision` 格式的图片上传与理解
- Base64 图片编码自动处理
- 支持 MIME 类型: `image/jpeg`, `image/png`, `image/webp`, `image/gif`

### 🔒 安全特性
- API Key 认证机制
- 管理后台独立鉴权
- Cookie 安全存储
- 代理请求支持

## 🛠 配置说明

### 方式一: 环境变量配置 (单账号模式)

在项目根目录创建 `.env` 文件：

```env
# ---------- 核心认证 (必需) ----------
# 从浏览器 Cookie 获取 (business.gemini.google.com)
SECURE_C_SES=your_secure_c_ses_value
CSESIDX=your_csesidx_value
CONFIG_ID=your_config_id_value   # 通常在网络请求 Payload 中可见

# ---------- 选填配置 ----------
# 主机认证 Cookie (部分账号可能需要)
HOST_C_OSES=

# 服务访问密钥 (OpenAI Client 用于认证的 Key)
API_KEY=sk-my-secret-key

# HTTP 代理 
PROXY=http://127.0.0.1:7890

# 健康检查间隔 (秒)，默认300秒 (5分钟)
HEALTH_CHECK_INTERVAL=300
# 是否启用健康检查，默认true
HEALTH_CHECK_ENABLED=true
# 健康检查超时时间(秒)，默认30秒
HEALTH_CHECK_TIMEOUT=30
# 健康检查重试次数，默认2次
HEALTH_CHECK_RETRY_COUNT=2
# 并发健康检查数量限制，默认5个
HEALTH_CHECK_CONCURRENT_LIMIT=5
# 检测到异常时是否自动禁用账号，默认true
HEALTH_CHECK_AUTO_DISABLE=true
# 网络错误连续失败阈值，默认3次
HEALTH_CHECK_NETWORK_ERROR_THRESHOLD=3

# ---------- 数据库配置 (多账号模式需要) ----------
DATABASE_URL=postgresql://user:password@localhost:5432/gemini_db
```

### 方式二: 数据库多账号模式 (推荐)

1. **配置数据库**：在 `.env` 中设置 `DATABASE_URL`
2. **启动服务**：服务会自动创建 `gemini_accounts` 表
3. **访问管理后台**：浏览器打开 `http://localhost:7860/admin`
4. **添加账号**：通过 UI 批量添加多个 Gemini Business 账号

> 如果未配置数据库，服务将回退到 `.env` 中的单账号模式

## 🏥 健康检查机制

### 自动健康检查
- **启动检查**：服务启动时自动检查所有启用账号的健康状态
- **定时检查**：按配置的 `HEALTH_CHECK_INTERVAL` 间隔定期检查账号状态
- **智能禁用**：检测到账号异常时自动禁用（可通过 `HEALTH_CHECK_AUTO_DISABLE` 控制）
- **并发检查**：支持多账号并行健康检查（通过 `HEALTH_CHECK_CONCURRENT_LIMIT` 限制并发数）
- **重试机制**：失败时自动重试（通过 `HEALTH_CHECK_RETRY_COUNT` 配置重试次数）
- **超时控制**：单次检查超时时间（通过 `HEALTH_CHECK_TIMEOUT` 配置）
- **网络容错**：连续网络错误达到阈值时标记为异常（通过 `HEALTH_CHECK_NETWORK_ERROR_THRESHOLD` 配置）

### 手动健康检查
可以通过API手动触发健康检查：

```bash
# 触发全局健康检查
POST /api/admin/health-check
Authorization: Bearer <API_KEY>

# 检查特定账号
POST /api/admin/accounts/{id}/health-check
Authorization: Bearer <API_KEY>
```

### 健康检查日志
健康检查过程会详细记录日志，便于监控和调试：
- ✅ 账号健康检查通过
- ⚠️ 账号健康检查失败
- ❌ 账号JWT刷新失败
- 🏥 健康检查完成统计（成功/失败/禁用数量）

## 🚀 快速启动

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置账号信息

选择上述两种配置方式之一，建议使用数据库模式以支持多账号管理。

### 3. 启动服务

```bash
python main.py
```

服务将运行在: `http://0.0.0.0:7860`

### 4. 访问管理后台 (可选)

访问 `http://localhost:7860/admin`，使用 `.env` 中配置的 `API_KEY` 登录。

## 🔌 调用示例

### 使用 cURL

```bash
curl -X POST http://localhost:7860/v1/chat/completions \
  -H "Authorization: Bearer sk-my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-3-pro-preview",
    "messages": [
        {"role": "user", "content": "写一首关于春天的五言绝句"}
    ],
    "stream": true
  }'
```

### 使用 OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:7860/v1",
    api_key="sk-my-secret-key"
)

response = client.chat.completions.create(
    model="gemini-3-pro-preview",
    messages=[{"role": "user", "content": "你好，介绍一下你自己"}],
    stream=True
)

for chunk in response:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

### 图片理解示例

```python
import base64

with open("image.jpg", "rb") as f:
    img_base64 = base64.b64encode(f.read()).decode()

response = client.chat.completions.create(
    model="gemini-3-pro-preview",
    messages=[{
        "role": "user",
        "content": [
            {"type": "text", "text": "这张图片里有什么？"},
            {
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/jpeg;base64,{img_base64}"
                }
            }
        ]
    }],
    stream=True
)
```

## 🤖 支持的模型

目前映射了以下模型名称：
- `gemini-auto` (默认，自动选择)
- `gemini-2.5-flash` (快速版本)
- `gemini-2.5-pro` (专业版本)
- `gemini-3-pro-preview` (推荐，最新预览版)

> **智能升级**: 客户端请求的模型可能会被自动升级到更好的版本，日志会记录升级信息。

## 📦 部署

### Docker Compose 部署 (推荐)

```bash
docker-compose up -d
```

### 手动 Docker 部署

```bash
# 构建镜像（已优化Dockerfile，构建更高效）
docker build -t gemini-gateway .

# 运行容器
docker run -d -p 7860:7860 --env-file .env gemini-gateway
```

### Dockerfile 优化特性
- **依赖缓存优化**：先复制 `requirements.txt` 单独安装依赖，利用Docker层缓存
- **构建效率提升**：合并文件复制操作，减少Docker层数
- **镜像体积优化**：清理构建过程中安装的临时包

## 🗄 数据库管理

### 创建 PostgreSQL 数据库

```bash
# 使用 Docker
docker run -d \
  --name gemini-postgres \
  -e POSTGRES_DB=gemini_db \
  -e POSTGRES_USER=gemini \
  -e POSTGRES_PASSWORD=your_password \
  -p 5432:5432 \
  postgres:15
```

### 账号表结构

```sql
CREATE TABLE gemini_accounts (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    secure_c_ses TEXT NOT NULL,
    host_c_oses TEXT,
    csesidx TEXT NOT NULL,
    config_id TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 📊 管理 API

### 账号管理

#### 获取所有账号
```bash
GET /api/admin/accounts
Authorization: Bearer <API_KEY>
```

#### 添加账号
```bash
POST /api/admin/accounts
Authorization: Bearer <API_KEY>
Content-Type: application/json

{
  "name": "Account 1",
  "secure_c_ses": "...",
  "host_c_oses": "...",
  "csesidx": "...",
  "config_id": "..."
}
```

#### 更新账号
```bash
PUT /api/admin/accounts/{id}
Authorization: Bearer <API_KEY>
Content-Type: application/json

{
  "is_active": false
}
```

#### 删除账号
```bash
DELETE /api/admin/accounts/{id}
Authorization: Bearer <API_KEY>
```

### 健康检查 API

#### 全局健康检查
```bash
POST /api/admin/health-check
Authorization: Bearer <API_KEY>
```

#### 单账号健康检查
```bash
POST /api/admin/accounts/{id}/health-check
Authorization: Bearer <API_KEY>
```

#### 获取健康检查状态
```bash
GET /api/admin/health-status
Authorization: Bearer <API_KEY>
```

## 🔧 技术栈

- **FastAPI**: 高性能异步 Web 框架
- **httpx**: 异步 HTTP 客户端
- **asyncpg**: 异步 PostgreSQL 驱动
- **Pydantic**: 数据验证
- **Vue.js 3**: 管理后台前端
- **TailwindCSS**: UI 样式

## 📝 日志特性

- **请求追踪**: 每个请求有唯一 ID
- **模型升级通知**: 自动记录模型变更
- **错误诊断**: 详细的错误堆栈和上下文
- **性能监控**: 响应时间、会话管理等

## ⚠️ 免责声明

**仅供学习研究使用**

本项目仅用于技术学习和个人研究目的。使用者应：
1. 确保遵守 Google Gemini Business 的使用条款
2. 妥善保管自己的认证信息 (`SECURE_C_SES` 等) 和 API Key
3. **不要在生产环境中使用**，本项目不保证稳定性
4. 理解使用第三方 API 可能带来的风险

作者不对任何因使用本项目导致的账号封禁、数据丢失或服务中断负责。请在合理合规范围内使用。

## 📄 License

MIT License - 详见 [LICENSE](LICENSE) 文件

---

**⭐ 如果这个项目对你有帮助，欢迎 Star！**
