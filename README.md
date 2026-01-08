# Gemini Business OpenAI Gateway

将 Google Gemini Business API 转换为 OpenAI 格式的网关服务。

## 功能特性

- ✅ OpenAI 兼容的 `/v1/chat/completions` 接口
- ✅ 流式响应支持
- ✅ 多模态支持（图片上传）
- ✅ API Key 验证

## 配置说明

在 `.env` 文件中配置以下环境变量：

```env
# Gemini Business 认证（必需）
SECURE_C_SES=your_secure_c_ses_value
CSESIDX=your_csesidx_value
CONFIG_ID=your_config_id_value

# API Key 验证（可选，未配置则不验证）
API_KEY=your_secret_key_here

# 代理配置（可选）
PROXY=http://127.0.0.1:7890
```

## 快速启动

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务
python main.py
```

服务默认运行在 `http://localhost:8000`

## 调用示例

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer your_secret_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-auto",
    "messages": [{"role": "user", "content": "你好"}],
    "stream": false
  }'
```

## 免责声明

**仅供学习研究使用**

本项目仅用于技术学习和个人研究目的。使用者应：

1. 确保遵守 Google Gemini Business 的使用条款
2. 妥善保管自己的认证信息和 API Key
3. 理解任何不当使用可能导致账号风险

作者不对以下情况负责：
- 任何因使用本项目导致的账号问题
- 任何数据损失或服务中断
- 任何违反使用条款的行为

请在合理合规范围内使用本项目。
