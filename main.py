import json, time, hmac, hashlib, base64, os, asyncio, uuid, ssl, re
from datetime import datetime
from typing import List, Optional, Union, Dict, Any
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from dotenv import load_dotenv
# Load .env file first
load_dotenv()

from database import db  # Import database instance
from cache_manager import init_session_pool, get_session_pool

# ---------- 日志配置 ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gemini")

# ---------- 配置 ----------
API_KEY      = os.getenv("API_KEY")
# Fallsback ENV variables (customary support)
ENV_SECURE_C_SES = os.getenv("SECURE_C_SES")
ENV_HOST_C_OSES  = os.getenv("HOST_C_OSES")
ENV_CSESIDX      = os.getenv("CSESIDX")
ENV_CONFIG_ID    = os.getenv("CONFIG_ID")

PROXY        = os.getenv("PROXY") or None
TIMEOUT_SECONDS = 600 

# 健康检查配置
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "300"))  # 5分钟
HEALTH_CHECK_ENABLED = os.getenv("HEALTH_CHECK_ENABLED", "true").lower() == "true"
HEALTH_CHECK_TIMEOUT = int(os.getenv("HEALTH_CHECK_TIMEOUT", "30"))  # 30秒超时
HEALTH_CHECK_RETRY_COUNT = int(os.getenv("HEALTH_CHECK_RETRY_COUNT", "2"))  # 重试次数
HEALTH_CHECK_CONCURRENT_LIMIT = int(os.getenv("HEALTH_CHECK_CONCURRENT_LIMIT", "5"))  # 并发限制
HEALTH_CHECK_AUTO_DISABLE = os.getenv("HEALTH_CHECK_AUTO_DISABLE", "true").lower() == "true"  # 自动禁用
HEALTH_CHECK_NETWORK_ERROR_THRESHOLD = int(os.getenv("HEALTH_CHECK_NETWORK_ERROR_THRESHOLD", "3"))  # 网络错误阈值

# 会话池配置
SESSION_POOL_CONFIG = {
    'CACHE_HOT_SIZE': int(os.getenv("CACHE_HOT_SIZE", "5000")),
    'CACHE_WARM_SIZE': int(os.getenv("CACHE_WARM_SIZE", "3000")),
    'CACHE_COLD_SIZE': int(os.getenv("CACHE_COLD_SIZE", "2000")),
    'SESSION_TTL': int(os.getenv("SESSION_TTL", "7200")),
    'CACHE_CLEANUP_INTERVAL': int(os.getenv("CACHE_CLEANUP_INTERVAL", "300")),
    'MEMORY_WARNING_THRESHOLD': float(os.getenv("MEMORY_WARNING_THRESHOLD", "0.8")),
    'MEMORY_CRITICAL_THRESHOLD': float(os.getenv("MEMORY_CRITICAL_THRESHOLD", "0.9"))
}

# ---------- 模型映射配置 ----------
MODEL_MAPPING = {
    "gemini-auto": None,
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-3-flash-preview": "gemini-3-flash-preview",
    "gemini-3-pro-preview": "gemini-3-pro-preview"
}

# ---------- HTTP 客户端 ----------
http_client = httpx.AsyncClient(
    proxy=PROXY,
    verify=False,
    http2=False,
    timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=60.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
)

# ---------- 账号池管理 ----------

# ---------- 健康检查器 ----------
class HealthChecker:
    """账号健康检查器"""
    
    # 需要自动禁用的错误码
    AUTO_DISABLE_ERROR_CODES = [401, 403, 429]
    
    # 需要自动禁用的错误关键词
    AUTO_DISABLE_ERROR_KEYWORDS = [
        "authentication failed",
        "unauthorized", 
        "forbidden",
        "rate limit",
        "quota exceeded",
        "account suspended",
        "invalid credentials",
        "token expired",
        "session expired"
    ]
    
    @staticmethod
    async def check_account_health(account) -> dict:
        """检查单个账号的健康状态"""
        start_time = time.time()
        
        try:
            logger.info(f"🏥 开始检查账号 [{account.id}] {account.name} 的健康状态")
            
            # 尝试获取JWT
            jwt = await account.get_jwt()
            
            # 尝试创建测试会话
            session_name = await create_google_session(account)
            
            # 计算检查耗时
            check_duration = round((time.time() - start_time) * 1000, 2)
            
            # 更新健康状态为健康
            await db.update_health_status(account.id, "healthy")
            
            logger.info(f"✅ 账号 [{account.id}] 健康检查通过，耗时 {check_duration}ms")
            
            return {
                "status": "success",
                "account_id": account.id,
                "account_name": account.name,
                "message": "账号健康",
                "check_duration_ms": check_duration,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except HTTPException as e:
            status_code = e.status_code
            error_msg = str(e)
            check_duration = round((time.time() - start_time) * 1000, 2)
            
            # 直接禁用账号（按用户要求）
            reason = f"HEALTH_CHECK_{status_code}: {error_msg[:200]}"  # 限制原因长度
            await db.disable_account_with_reason(account.id, reason)
            logger.warning(f"🚫 账号 [{account.id}] 健康检查失败，已自动禁用: {reason}")
            
            return {
                "status": "failed",
                "account_id": account.id,
                "account_name": account.name,
                "error_code": status_code,
                "message": f"账号自动禁用: {error_msg}",
                "disabled": True,
                "check_duration_ms": check_duration,
                "timestamp": datetime.utcnow().isoformat()
            }
                
        except Exception as e:
            # 其他异常 - 直接禁用账号（按用户要求）
            error_msg = str(e)
            check_duration = round((time.time() - start_time) * 1000, 2)
            
            reason = f"HEALTH_CHECK_EXCEPTION: {error_msg[:200]}"  # 限制原因长度
            await db.disable_account_with_reason(account.id, reason)
            logger.warning(f"🚫 账号 [{account.id}] 健康检查异常，已自动禁用: {reason}")
            
            return {
                "status": "failed",
                "account_id": account.id,
                "account_name": account.name,
                "message": f"账号自动禁用: {error_msg}",
                "disabled": True,
                "check_duration_ms": check_duration,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    async def check_account_with_timeout(account) -> dict:
        """带超时的账号健康检查"""
        try:
            return await asyncio.wait_for(
                HealthChecker.check_account_health(account),
                timeout=HEALTH_CHECK_TIMEOUT
            )
        except asyncio.TimeoutError:
            check_duration = HEALTH_CHECK_TIMEOUT * 1000
            logger.warning(f"⏰ 账号 [{account.id}] 健康检查超时 ({HEALTH_CHECK_TIMEOUT}秒)")
            
            # 检查网络错误阈值
            network_error_count = await db.increment_network_error_count(account.id)
            should_disable = network_error_count >= HEALTH_CHECK_NETWORK_ERROR_THRESHOLD
            
            if should_disable:
                reason = f"HEALTH_CHECK_TIMEOUT_{network_error_count}: 连续超时{network_error_count}次"
                await db.disable_account_with_reason(account.id, reason)
                await db.reset_network_error_count(account.id)  # 重置计数器
                
                return {
                    "status": "failed",
                    "account_id": account.id,
                    "account_name": account.name,
                    "message": f"账号因连续超时被自动禁用",
                    "disabled": True,
                    "check_duration_ms": check_duration,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                await db.update_health_status(account.id, "unhealthy")
                
                return {
                    "status": "failed",
                    "account_id": account.id,
                    "account_name": account.name,
                    "message": f"健康检查超时 ({network_error_count}/{HEALTH_CHECK_NETWORK_ERROR_THRESHOLD})",
                    "disabled": False,
                    "check_duration_ms": check_duration,
                    "timestamp": datetime.utcnow().isoformat()
                }
    
    @staticmethod
    async def run_health_check_all():
        """运行所有账号的健康检查（并发版本）"""
        logger.info("🏥 开始执行全局健康检查...")
        
        # 修改：只检查数据库中状态为正常的账号
        accounts_to_check = await db.get_healthy_accounts_for_health_check()
        if not accounts_to_check:
            logger.info("📭 没有需要检查的账号")
            return []  # 返回空列表而不是None
        
        logger.info(f"📋 将检查 {len(accounts_to_check)} 个账号，并发限制: {HEALTH_CHECK_CONCURRENT_LIMIT}")
        
        results = []
        
        # 使用信号量控制并发数量
        semaphore = asyncio.Semaphore(HEALTH_CHECK_CONCURRENT_LIMIT)
        
        async def check_with_semaphore(account_data):
            async with semaphore:
                account = Account(account_data)
                try:
                    result = await HealthChecker.check_account_with_timeout(account)
                    return result
                except Exception as e:
                    # 兜底异常处理
                    logger.error(f"❌ 账号 [{account.id}] 检查过程异常: {e}")
                    return {
                        "status": "failed",
                        "account_id": account.id,
                        "account_name": account.name,
                        "message": f"检查过程异常: {str(e)}",
                        "disabled": False,
                        "timestamp": datetime.utcnow().isoformat()
                    }
        
        # 并发执行健康检查
        tasks = [check_with_semaphore(account_data) for account_data in accounts_to_check]
        
        # 使用 asyncio.gather 收集结果，即使有部分失败也继续
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"❌ 账号检查任务异常: {result}")
                processed_results.append({
                    "status": "failed",
                    "account_id": accounts_to_check[i].get("id", "unknown"),
                    "account_name": accounts_to_check[i].get("name", "unknown"),
                    "message": f"任务异常: {str(result)}",
                    "disabled": False,
                    "timestamp": datetime.utcnow().isoformat()
                })
            else:
                processed_results.append(result)
        
        # 统计结果
        success_count = sum(1 for r in processed_results if r["status"] == "success")
        failed_count = len(processed_results) - success_count
        disabled_count = sum(1 for r in processed_results if r.get("disabled", False))
        
        logger.info(f"🏥 健康检查完成: 成功 {success_count}, 失败 {failed_count}, 禁用 {disabled_count}")
        
        return processed_results

# ---------- 工具函数 ----------
def get_common_headers(jwt: str) -> dict:
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "x-server-timeout": "1800",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }

def urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def kq_encode(s: str) -> str:
    b = bytearray()
    for ch in s:
        v = ord(ch)
        if v > 255:
            b.append(v & 255)
            b.append(v >> 8)
        else:
            b.append(v)
    return urlsafe_b64encode(bytes(b))

def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
    payload = {
        "iss": "https://business.gemini.google",
        "aud": "https://biz-discoveryengine.googleapis.com",
        "sub": f"csesidx/{csesidx}",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }
    header_b64  = kq_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = kq_encode(json.dumps(payload, separators=(",", ":")))
    message     = f"{header_b64}.{payload_b64}"
    sig         = hmac.new(key_bytes, message.encode(), hashlib.sha256).digest()
    return f"{message}.{urlsafe_b64encode(sig)}"

# ---------- JWT 管理 (Per Account) ----------
class JWTManager:
    def __init__(self, account_data: dict) -> None:
        self.account = account_data
        self.jwt: str = ""
        self.expires: float = 0
        self._lock = asyncio.Lock()

    async def get(self) -> str:
        async with self._lock:
            if time.time() > self.expires:
                await self._refresh()
            return self.jwt

    async def _refresh(self) -> None:
        cookie = f"__Secure-C_SES={self.account['secure_c_ses']}"
        if self.account.get('host_c_oses'):
            cookie += f"; __Host-C_OSES={self.account['host_c_oses']}"
        
        logger.debug(f"🔑 [{self.account['id']}] 正在刷新 JWT...")
        try:
            r = await http_client.get(
                "https://business.gemini.google/auth/getoxsrf",
                params={"csesidx": self.account['csesidx']},
                headers={
                    "cookie": cookie,
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
                    "referer": "https://business.gemini.google/"
                },
            )
            if r.status_code != 200:
                logger.error(f"❌ [{self.account['id']}] getoxsrf 失败: {r.status_code} {r.text}")
                raise HTTPException(r.status_code, "getoxsrf failed")
            
            txt = r.text[4:] if r.text.startswith(")]}'") else r.text
            data = json.loads(txt)

            key_bytes = base64.urlsafe_b64decode(data["xsrfToken"] + "==")
            self.jwt     = create_jwt(key_bytes, data["keyId"], self.account['csesidx'])
            self.expires = time.time() + 270
            logger.info(f"✅ [{self.account['id']}] JWT 刷新成功")
        except Exception as e:
            logger.error(f"❌ [{self.account['id']}] JWT Refresh Error: {e}")
            raise e

# ---------- 账号与会话管理 ----------
class Account:
    def __init__(self, data: dict):
        self.id = data.get("id") or 0
        self.name = data.get("name") or f"Account-{self.id}"
        self.secure_c_ses = data["secure_c_ses"]
        self.host_c_oses = data.get("host_c_oses")
        self.csesidx = data["csesidx"]
        self.config_id = data["config_id"]
        self.is_active = data.get("is_active", True)
        
        self.jwt_mgr = JWTManager(data)
        self.lock = asyncio.Lock() # For account-level operations if needed

    async def get_jwt(self):
        return await self.jwt_mgr.get()

class AccountPool:
    def __init__(self):
        self.accounts: List[Account] = []
        self._current_index = 0
        self._lock = asyncio.Lock()

    async def load_accounts(self):
        try:
            await db.connect()
            rows = await db.fetch_active_accounts()
            if rows:
                self.accounts = [Account(row) for row in rows]
                logger.info(f"📚 已从数据库加载 {len(self.accounts)} 个账号")
            else:
                logger.info("⚠️ 数据库中无可用账号，尝试使用环境变量 fallback")
                await self._load_fallback()
        except Exception as e:
            logger.error(f"❌ 加载账号失败: {e}")
            await self._load_fallback()

    async def _load_fallback(self):
        if all([ENV_SECURE_C_SES, ENV_CSESIDX, ENV_CONFIG_ID]):
            fallback_data = {
                "id": 0,
                "name": "Env-Fallback",
                "secure_c_ses": ENV_SECURE_C_SES,
                "host_c_oses": ENV_HOST_C_OSES,
                "csesidx": ENV_CSESIDX,
                "config_id": ENV_CONFIG_ID
            }
            self.accounts = [Account(fallback_data)]
            logger.info("✅ 已加载环境变量 fallback 账号")
        else:
            logger.warning("❌ 未找到任何可用账号配置")

    async def get_next_account(self) -> Optional[Account]:
        """Failover Mode: Always return the first active account."""
        async with self._lock:
            if not self.accounts: return None

            # 重新从数据库加载最新的账号状态，确保获取最新的 is_active 状态
            try:
                await db.connect()
                active_accounts_data = await db.fetch_active_accounts()
                if not active_accounts_data:
                    logger.warning("⚠️ 数据库中没有活跃账号")
                    return None
                
                # 更新内存中的账号列表和状态
                self.accounts = [Account(data) for data in active_accounts_data]
                logger.info(f"🔄 已刷新账号池，当前有 {len(self.accounts)} 个活跃账号")
                
                # 返回第一个活跃账号
                if self.accounts:
                    account = self.accounts[0]
                    logger.info(f"🛡️ [Primary/Sticky] Using Account: [{account.id}] {account.name}")
                    return account
                else:
                    return None
                    
            except Exception as e:
                logger.error(f"❌ 刷新账号池失败: {e}")
                # 如果刷新失败，使用内存中的账号列表，但要检查 is_active 状态
                for acc in self.accounts:
                    if acc.is_active:
                        logger.info(f"🛡️ [Fallback] Using Account: [{acc.id}] {acc.name}")
                        return acc
                return None

    async def ensure_account_availability(self) -> bool:
        """确保有可用的活跃账号"""
        try:
            await db.connect()
            active_accounts_data = await db.fetch_active_accounts()
            return len(active_accounts_data) > 0
        except Exception as e:
            logger.error(f"❌ 检查账号可用性失败: {e}")
            return False

    def get_account_by_id(self, account_id: int) -> Optional[Account]:
        for acc in self.accounts:
            if acc.id == account_id:
                return acc
        return None

account_pool = AccountPool()

# 用户模型偏好缓存 (Model Stickiness)
# Key: client_ip
# Value: last_stream_model_name
USER_MODEL_PREF: Dict[str, str] = {}
GLOBAL_LAST_MODEL_NAME: Optional[str] = None

async def create_google_session(account: Account) -> str:
    jwt = await account.get_jwt()
    headers = get_common_headers(jwt)
    body = {
        "configId": account.config_id,
        "additionalParams": {"token": "-"},
        "createSessionRequest": {
            "session": {"name": "", "displayName": ""}
        }
    }
    
    logger.debug(f"🌐 [{account.name}] 申请新 Session...")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession",
        headers=headers,
        json=body,
    )
    if r.status_code != 200:
        logger.error(f"❌ createSession 失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, "createSession failed")
    sess_name = r.json()["session"]["name"]
    return sess_name

async def upload_context_file(account: Account, session_name: str, mime_type: str, base64_content: str) -> str:
    """上传文件到指定 Session，返回 fileId"""
    jwt = await account.get_jwt()
    headers = get_common_headers(jwt)
    
    # 生成随机文件名
    ext = mime_type.split('/')[-1] if '/' in mime_type else "bin"
    file_name = f"upload_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"

    body = {
        "configId": account.config_id,
        "additionalParams": {"token": "-"},
        "addContextFileRequest": {
            "name": session_name,
            "fileName": file_name,
            "mimeType": mime_type,
            "fileContents": base64_content
        }
    }

    logger.info(f"📤 [{account.name}] 上传图片 [{mime_type}] 到 Session...")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile",
        headers=headers,
        json=body,
    )

    if r.status_code != 200:
        logger.error(f"❌ 上传文件失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, f"Upload failed: {r.text}")
    
    data = r.json()
    file_id = data.get("addContextFileResponse", {}).get("fileId")
    logger.info(f"✅ 图片上传成功, ID: {file_id}")
    return file_id

# ---------- API Key 验证 ----------
async def verify_api_key(request: Request) -> None:
    if API_KEY is None: return
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer ") or auth_header[7:] != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

# ---------- 消息处理逻辑 ----------
def get_conversation_key(messages: List[dict]) -> str:
    if not messages: return "empty"
    # 仅使用第一条消息的内容生成指纹，忽略图片数据防止指纹过大
    first_msg = messages[0].copy()
    if isinstance(first_msg.get("content"), list):
        # 如果第一条是多模态，只取文本部分做 Hash
        text_part = "".join([x["text"] for x in first_msg["content"] if x["type"] == "text"])
        first_msg["content"] = text_part
    
    key_str = json.dumps(first_msg, sort_keys=True)
    return hashlib.md5(key_str.encode()).hexdigest()

def parse_last_message(messages: List['Message']):
    """解析最后一条消息，分离文本和图片"""
    if not messages:
        return "", []
    
    last_msg = messages[-1]
    content = last_msg.content
    
    text_content = ""
    images = [] # List of {"mime": str, "data": str_base64}

    if isinstance(content, str):
        text_content = content
    elif isinstance(content, list):
        for part in content:
            if part.get("type") == "text":
                text_content += part.get("text", "")
            elif part.get("type") == "image_url":
                url = part.get("image_url", {}).get("url", "")
                # 解析 Data URI: data:image/png;base64,xxxxxx
                match = re.match(r"data:(image/[^;]+);base64,(.+)", url)
                if match:
                    images.append({"mime": match.group(1), "data": match.group(2)})
                else:
                    logger.warning(f"⚠️ 暂不支持非 Base64 图片链接: {url[:30]}...")

    return text_content, images

def build_full_context_text(messages: List['Message']) -> str:
    """仅拼接历史文本，图片只处理当次请求的。兼容处理 Tool Messages。"""
    prompt = ""
    for msg in messages:
        role = msg.role
        if role in ["user", "system"]:
            role_name = "User"
        elif role == "assistant":
            role_name = "Assistant"
        elif role == "tool":
            role_name = "Tool Output"
        else:
            role_name = "User" # Fallback

        content_str = ""
        if msg.content:
            if isinstance(msg.content, str):
                content_str = msg.content
            elif isinstance(msg.content, list):
                for part in msg.content:
                    if part.get("type") == "text":
                        content_str += part.get("text", "")
                    elif part.get("type") == "image_url":
                        content_str += "[图片]"
        
        # Helper for tool calls in assistant message
        if msg.tool_calls:
            for tc in msg.tool_calls:
                func_name = tc.get("function", {}).get("name", "unknown")
                args = tc.get("function", {}).get("arguments", "{}")
                content_str += f"\n[Call Tool: {func_name}({args})]"

        prompt += f"{role_name}: {content_str}\n\n"
    return prompt

# ---------- 定时健康检查任务 ----------
async def run_startup_health_check():
    """启动时执行一次健康检查"""
    if not HEALTH_CHECK_ENABLED:
        logger.info("🏥 启动健康检查已禁用")
        return
    
    logger.info("🏥 执行启动时健康检查...")
    try:
        results = await HealthChecker.run_health_check_all()
        success_count = sum(1 for r in results if r["status"] == "success")
        failed_count = len(results) - success_count
        disabled_count = sum(1 for r in results if r.get("disabled", False))
        logger.info(f"🏥 启动健康检查完成: 成功 {success_count}, 失败 {failed_count}, 禁用 {disabled_count}")
    except Exception as e:
        logger.error(f"❌ 启动健康检查失败: {e}")

async def scheduled_health_check():
    """定时健康检查任务"""
    if not HEALTH_CHECK_ENABLED:
        logger.info("🏥 定时健康检查已禁用")
        return
    
    logger.info(f"🏥 定时健康检查任务启动，间隔: {HEALTH_CHECK_INTERVAL}秒")
    
    while True:
        try:
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
            await HealthChecker.run_health_check_all()
        except asyncio.CancelledError:
            logger.info("🏥 定时健康检查任务已停止")
            break
        except Exception as e:
            logger.error(f"❌ 定时健康检查任务异常: {e}")
            # 继续运行，不中断定时任务"

# ---------- 账号自动禁用工具函数 ----------
def should_disable_account_for_error(error: Exception) -> tuple[bool, str]:
    """
    判断是否需要因错误而禁用账号，并返回禁用原因
    
    Args:
        error: 捕获的异常对象
        
    Returns:
        tuple[bool, str]: (是否禁用, 禁用原因)
    """
    disable_reason = ""
    
    # 检查异常类型
    if isinstance(error, HTTPException):
        status_code = error.status_code
        error_detail = str(error)
        if status_code in [401, 403, 302, 429]:
            disable_reason = f"HTTP_{status_code}: {error_detail[:200]}"
            return True, disable_reason
    else:
        # 检查异常信息
        error_detail = str(error)
        error_lower = error_detail.lower()
        if any(keyword in error_lower for keyword in [
            "authentication failed",
            "unauthorized", 
            "forbidden",
            "session expired",
            "token expired",
            "invalid credentials",
            "getoxsrf failed",
            "302"
        ]):
            disable_reason = f"EXCEPTION: {error_detail[:200]}"
            return True, disable_reason
    
    return False, disable_reason

async def auto_disable_account_if_needed(account: Account, error: Exception, session_pool, error_context: str = "API_CALL"):
    """
    根据错误自动禁用账号（如果需要）
    
    Args:
        account: 账号对象
        error: 捕获的异常对象
        session_pool: 会话池对象
        error_context: 错误上下文标识（如 "SESSION_CREATE", "API_CALL" 等）
    """
    if not account or account.id <= 0:
        return
    
    should_disable, base_reason = should_disable_account_for_error(error)
    if should_disable:
        disable_reason = f"{error_context}_{base_reason}"
        logger.warning(f"🚫 账号 [{account.id}] {error_context.lower()}失败，自动禁用: {disable_reason}")
        try:
            await db.disable_account_with_reason(account.id, disable_reason)
            await account_pool.load_accounts()  # 重新加载账号池
            # 清理该账号的所有会话
            session_pool.clear_account_sessions(account.id)
            logger.info(f"✅ 已自动禁用账号 [{account.id}] 并清理相关会话")
        except Exception as db_err:
            logger.error(f"❌ 更新数据库失败: {db_err}")

# ---------- FastAPI App & Lifespan ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await account_pool.load_accounts()
    
    # 初始化会话池
    session_pool = init_session_pool(SESSION_POOL_CONFIG)
    await session_pool.start()
    app.state.session_pool = session_pool
    logger.info("🚀 会话池已初始化")
    
    # 启动时执行健康检查
    if HEALTH_CHECK_ENABLED:
        await run_startup_health_check()
    
    # 启动定时健康检查任务
    if HEALTH_CHECK_ENABLED:
        health_check_task = asyncio.create_task(scheduled_health_check())
        app.state.health_check_task = health_check_task
        logger.info("🏥 定时健康检查任务已启动")
    
    yield
    
    # Shutdown
    if HEALTH_CHECK_ENABLED and hasattr(app.state, 'health_check_task'):
        app.state.health_check_task.cancel()
        try:
            await app.state.health_check_task
        except asyncio.CancelledError:
            pass
        logger.info("🏥 定时健康检查任务已停止")
    
    # 停止会话池
    if hasattr(app.state, 'session_pool'):
        await app.state.session_pool.stop()
        logger.info("🛑 会话池已停止")
    
    await db.disconnect()

# ---------- OpenAI 兼容接口 ----------
app = FastAPI(title="Gemini-Business OpenAI Gateway", lifespan=lifespan)
# Mount static files for Admin UI
app.mount("/admin", StaticFiles(directory="static/admin", html=True), name="static")

# Admin API Models
class AccountCreate(BaseModel):
    name: str = "New Account"
    secure_c_ses: str
    host_c_oses: Optional[str] = None
    csesidx: str
    config_id: str

class AccountUpdate(BaseModel):
    name: Optional[str] = None
    secure_c_ses: Optional[str] = None
    host_c_oses: Optional[str] = None
    csesidx: Optional[str] = None
    config_id: Optional[str] = None
    is_active: Optional[bool] = None

# Admin API Routes
from fastapi import Depends

@app.get("/api/admin/accounts", dependencies=[Depends(verify_api_key)])
async def admin_list_accounts():
    return await db.get_all_accounts()

@app.post("/api/admin/accounts", dependencies=[Depends(verify_api_key)])
async def admin_add_account(acc: AccountCreate):
    await db.add_account(
        name=acc.name,
        secure_c_ses=acc.secure_c_ses,
        host_c_oses=acc.host_c_oses,
        csesidx=acc.csesidx,
        config_id=acc.config_id
    )
    await account_pool.load_accounts() # Refresh pool
    return {"status": "ok"}

@app.put("/api/admin/accounts/{id}", dependencies=[Depends(verify_api_key)])
async def admin_update_account(id: int, acc: AccountUpdate):
    data = acc.dict(exclude_unset=True)
    if not data: return {"status": "no change"}
    await db.update_account(id, data)
    await account_pool.load_accounts() # Refresh pool
    return {"status": "ok"}

@app.delete("/api/admin/accounts/{id}", dependencies=[Depends(verify_api_key)])
async def admin_delete_account(id: int):
    await db.delete_account(id)
    await account_pool.load_accounts() # Refresh pool
    return {"status": "ok"}

@app.post("/api/admin/accounts/{id}/test", dependencies=[Depends(verify_api_key)])
async def admin_test_account(id: int):
    """测试指定账号是否可用"""
    account = account_pool.get_account_by_id(id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    try:
        # 尝试获取 JWT
        jwt = await account.get_jwt()
        
        # 尝试创建 Session
        session_name = await create_google_session(account)
        
        # 清理测试 Session
        return {
            "status": "success",
            "message": "账号测试成功",
            "account_id": id,
            "account_name": account.name
        }
    except Exception as e:
        status_code = e.status_code if isinstance(e, HTTPException) else 500
        error_msg = str(e)
        
        # 如果是 401 错误，自动禁用账号
        if status_code == 401:
            reason = f"API_TEST_401: {error_msg}"
            await db.disable_account_with_reason(id, reason)
            await account_pool.load_accounts()
            logger.warning(f"🚫 测试失败，已自动禁用账号 [{id}]: {reason}")
        
        raise HTTPException(
            status_code=400,
            detail={
                "status": "failed",
                "message": f"账号测试失败: {error_msg}",
                "account_id": id,
                "error_code": status_code
            }
        )

# ---------- 健康检查API端点 ----------
@app.post("/api/admin/health-check", dependencies=[Depends(verify_api_key)])
async def admin_run_health_check():
    """手动触发全局健康检查"""
    try:
        results = await HealthChecker.run_health_check_all()
        return {
            "status": "completed",
            "message": "健康检查完成",
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ 健康检查执行失败: {e}")
        raise HTTPException(status_code=500, detail=f"健康检查执行失败: {str(e)}")

@app.post("/api/admin/accounts/{id}/health-check", dependencies=[Depends(verify_api_key)])
async def admin_check_account_health(id: int):
    """检查指定账号的健康状态"""
    # 从数据库直接获取账号信息，而不是从account_pool（因为被禁用的账号不在pool中）
    all_accounts = await db.get_all_accounts()
    account_data = next((acc for acc in all_accounts if acc['id'] == id), None)
    
    if not account_data:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # 创建Account对象进行健康检查
    account = Account(account_data)
    result = await HealthChecker.check_account_health(account)
    return result

@app.get("/api/admin/health-status", dependencies=[Depends(verify_api_key)])
async def admin_get_health_status():
    """获取所有账号的健康状态"""
    try:
        accounts = await db.get_all_accounts()
        summary = await db.get_health_summary()
        
        return {
            "summary": summary,
            "accounts": accounts,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ 获取健康状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取健康状态失败: {str(e)}")

@app.post("/api/admin/accounts/{id}/enable", dependencies=[Depends(verify_api_key)])
async def admin_enable_account(id: int):
    """手动启用账号"""
    try:
        await db.enable_account(id)
        await account_pool.load_accounts()
        
        return {
            "status": "success",
            "message": f"账号 [{id}] 已启用",
            "account_id": id
        }
    except Exception as e:
        logger.error(f"❌ 启用账号失败: {e}")
        raise HTTPException(status_code=500, detail=f"启用账号失败: {str(e)}")

# ---------- 缓存管理API端点 ----------
@app.get("/api/admin/cache/stats", dependencies=[Depends(verify_api_key)])
async def admin_get_cache_stats():
    """获取缓存统计信息"""
    try:
        session_pool = get_session_pool()
        if not session_pool:
            raise HTTPException(status_code=503, detail="会话池未初始化")
        
        stats = session_pool.get_detailed_stats()
        return {
            "status": "success",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ 获取缓存统计失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取缓存统计失败: {str(e)}")

@app.post("/api/admin/cache/clear", dependencies=[Depends(verify_api_key)])
async def admin_clear_cache(account_id: Optional[int] = None):
    """清理缓存"""
    try:
        session_pool = get_session_pool()
        if not session_pool:
            raise HTTPException(status_code=503, detail="会话池未初始化")
        
        if account_id:
            # 清理指定账号的会话
            cleared = session_pool.clear_account_sessions(account_id)
            message = f"已清理账号 [{account_id}] 的 {cleared} 个会话"
        else:
            # 清理所有缓存
            session_pool.hot_cache.clear()
            session_pool.warm_cache.clear()
            session_pool.cold_cache.clear()
            message = "已清理所有缓存"
        
        logger.info(f"🧹 {message}")
        
        return {
            "status": "success",
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ 清理缓存失败: {e}")
        raise HTTPException(status_code=500, detail=f"清理缓存失败: {str(e)}")

@app.post("/api/admin/cache/cleanup", dependencies=[Depends(verify_api_key)])
async def admin_force_cleanup():
    """强制执行缓存清理"""
    try:
        session_pool = get_session_pool()
        if not session_pool:
            raise HTTPException(status_code=503, detail="会话池未初始化")
        
        await session_pool._perform_cleanup()
        
        return {
            "status": "success",
            "message": "强制清理已完成",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ 强制清理失败: {e}")
        raise HTTPException(status_code=500, detail=f"强制清理失败: {str(e)}")

class Message(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]], None] = None
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None

class ChatRequest(BaseModel):
    model: str = "gemini-auto"
    messages: List[Message]
    stream: bool = False
    temperature: Optional[float] = 0.7
    top_p: Optional[float] = 1.0
    # OpenAI Compatibility Fields (Optional)
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    max_tokens: Optional[int] = None
    n: Optional[int] = 1
    presence_penalty: Optional[float] = 0
    frequency_penalty: Optional[float] = 0
    stop: Optional[Union[str, List[str]]] = None

def create_chunk(id: str, created: int, model: str, delta: dict, finish_reason: Union[str, None]) -> str:
    chunk = {
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason
        }]
    }
    return json.dumps(chunk)

@app.get("/v1/models")
async def list_models(request: Request):
    await verify_api_key(request)
    data = []
    now = int(time.time())
    for m in MODEL_MAPPING.keys():
        data.append({
            "id": m,
            "object": "model",
            "created": now,
            "owned_by": "google",
            "permission": []
        })
    return {"object": "list", "data": data}

@app.get("/health")
async def health():
    session_pool = get_session_pool()
    cache_stats = None
    if session_pool:
        metrics = session_pool.get_metrics()
        cache_stats = {
            "total_sessions": metrics.total_sessions,
            "hit_rate": round(metrics.hit_rate, 2),
            "memory_usage_mb": round(metrics.memory_usage_mb, 2)
        }
    
    return {
        "status": "ok", 
        "time": datetime.utcnow().isoformat(),
        "accounts_loaded": len(account_pool.accounts),
        "cache_stats": cache_stats
    }

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest, request: Request):
    await verify_api_key(request)
    # 1. 模型校验
    # 推断请求意图 (Intent Inference)
    intent = "💬 主动对话 (Chat)" if req.stream else "🤖 后台任务 (Background/Title)"
    
    # DEBUG: Log raw received model with Intent
    logger.info(f"📨 请求收到 | 类型: {intent} | 模型: [{req.model}] | 流式: {req.stream}")
    
    # --- 模型粘性与一致性策略 (Model Stickiness) ---
    # 策略：以流式请求(Stream=True)为准，因为那是用户正在进行的真实对话。
    # 非流式(Stream=False)通常是后台任务(如标题生成/摘要)，往往使用降级模型(2.5)。
    # 我们记录用户最后一次流式请求使用的模型，并强制后续的非流式请求保持一致。
    
    client_ip = request.client.host if request.client else "global"
    
    global GLOBAL_LAST_MODEL_NAME
    
    if req.stream:
        # 用户显式发起对话 -> 更新首选模型记录
        USER_MODEL_PREF[client_ip] = req.model
        GLOBAL_LAST_MODEL_NAME = req.model
    else:
        # 后台任务 -> 检查是否通过
        preferred = USER_MODEL_PREF.get(client_ip)
        if not preferred and GLOBAL_LAST_MODEL_NAME:
            preferred = GLOBAL_LAST_MODEL_NAME
        
        if preferred and req.model != preferred:
             # 如果后台请求的模型(如2.5)与用户首选(如3)不一致，强制升级
             # 特例：如果用户真的想用2.5发非流式，这里会被误伤，但权衡之下，一致性优先
             if "gemini-2.5" in req.model and "gemini-3" in preferred:
                 logger.info(f"✨ [自动升级] 检测到后台降级请求 ({req.model}) -> 已自动修正为用户首选 ({preferred})")
                 req.model = preferred

    if req.model not in MODEL_MAPPING:
        # Auto-map common aliases if needed, but for now strict check
        raise HTTPException(status_code=404, detail=f"Model '{req.model}' not found.")

    # 1.1 Compatibility Warning
    if req.tools:
        logger.warning(f"⚠️ 工具调用被忽略: 上游 Gemini Widget 接口暂不支持 Client-Side Tools")

    # 2. 解析请求内容
    last_text, current_images = parse_last_message(req.messages)
    
    # 3. 锚定 Session
    # Fix Pydantic V2 deprecation warning
    conv_key = get_conversation_key([m.model_dump() for m in req.messages])
    
    # 使用新的会话池
    session_pool = get_session_pool()
    if not session_pool:
        raise HTTPException(status_code=503, detail="会话池未初始化")
    
    cached_session = session_pool.get_session(conv_key)
    
    account: Optional[Account] = None
    google_session: str = ""
    is_retry_mode = False

    # 3.1 尝试从缓存恢复
    if cached_session:
        account = account_pool.get_account_by_id(cached_session.account_id)
        
        # 检查账号是否仍然可用（活跃且健康）
        if account and await db.fetch_active_accounts() and any(acc['id'] == cached_session.account_id for acc in await db.fetch_active_accounts()):
            google_session = cached_session.session_id
            text_to_send = last_text
            logger.info(f"♻️ 延续旧对话 [{req.model}][Acc:{account.id}]: {google_session[-12:]}")
        else:
            logger.warning(f"⚠️ 缓存账号 ID {cached_session.account_id} 不可用，强制开启新对话")
            cached_session = None # Treat as new

    # 3.2 开启新会话 (如果需要)
    if not cached_session:
        # 检查是否有可用的活跃账号
        if not await account_pool.ensure_account_availability():
            logger.error("❌ 没有可用的活跃账号")
            raise HTTPException(status_code=503, detail="No active accounts available")
        
        account = await account_pool.get_next_account()
        if not account:
            raise HTTPException(status_code=503, detail="No active accounts available")
        
        logger.info(f"🛡️ [Primary/Sticky] Using Account: [{account.id}] {account.name}")
        logger.info(f"🆕 开启新对话 [{req.model}][Acc:{account.id}]")
        try:
            google_session = await create_google_session(account)
            # 新对话使用全量文本上下文 (图片只传当前的)
            text_to_send = build_full_context_text(req.messages)
            
            # 存储到会话池
            session_pool.put_session(conv_key, google_session, account.id)
            is_retry_mode = True
        except Exception as e:
            logger.error(f"❌ 开启会话失败: {e}")
            
            # 🔥 使用通用函数处理自动禁用
            await auto_disable_account_if_needed(account, e, session_pool, "SESSION_CREATE")
            
            raise HTTPException(status_code=500, detail=f"Failed to create session: {e}")

    chat_id = f"chatcmpl-{uuid.uuid4()}"
    created_time = int(time.time())

    # 封装生成器 (含图片上传和重试逻辑)
    async def response_wrapper():
        retry_count = 0
        max_retries = 2
        
        # Increment Request Tracking (Once per logical request)
        if account and account.id > 0:
            asyncio.create_task(db.increment_account_usage(account.id))
        
        current_text = text_to_send
        current_retry_mode = is_retry_mode
        
        # Important: Capture mutable variables for retry logic
        current_sess = google_session
        current_acc = account
        current_file_ids = []

        while retry_count <= max_retries:
            try:
                # A. 如果有图片且还没上传到当前 Session，先上传
                if current_images and not current_file_ids:
                    for img in current_images:
                        fid = await upload_context_file(current_acc, current_sess, img["mime"], img["data"])
                        current_file_ids.append(fid)

                # B. 准备文本 (重试模式下发全文)
                if current_retry_mode:
                    current_text = build_full_context_text(req.messages)

                # C. 发起对话
                async for chunk in stream_chat_generator(
                    current_acc,
                    current_sess, 
                    current_text, 
                    current_file_ids, 
                    req.model, 
                    chat_id, 
                    created_time, 
                    req.stream
                ):
                    yield chunk
                break 

            except (httpx.ConnectError, httpx.ReadTimeout, ssl.SSLError, HTTPException) as e:
                retry_count += 1
                status_code = e.status_code if isinstance(e, HTTPException) else None
                error_detail = str(e)
                
                logger.warning(f"⚠️ 请求异常 (重试 {retry_count}/{max_retries}): {error_detail}")

                # 🔥 使用通用函数处理自动禁用
                if retry_count >= max_retries:
                    await auto_disable_account_if_needed(current_acc, e, session_pool, "API_CALL")

                if retry_count <= max_retries:
                    # 尝试切换账号或重建 Session
                    if status_code == 401 and current_acc.id > 0:
                        # 401 错误：尝试切换到其他可用账号
                        logger.info("🔄 检测到 401，尝试切换账号...")
                        new_acc = await account_pool.get_next_account()
                        if new_acc and new_acc.id != current_acc.id:
                            logger.info(f"✅ 切换到账号 [{new_acc.id}] {new_acc.name}")
                            current_acc = new_acc
                        else:
                            logger.warning("⚠️ 无其他可用账号，继续重建 Session")
                    else:
                        # 其他错误：重建 Session
                        logger.info("🔄 尝试重建 Session...")
                    
                    try:
                        new_sess = await create_google_session(current_acc)
                        
                        # 更新会话池
                        session_pool.put_session(conv_key, new_sess, current_acc.id)
                        
                        current_sess = new_sess
                        current_retry_mode = True 
                        current_file_ids = [] 
                    except Exception as create_err:
                        logger.error(f"❌ 重建失败: {create_err}")
                        if req.stream: yield f"data: {json.dumps({'error': {'message': 'Session Recovery Failed'}})}\n\n"
                        return
                else:
                    if req.stream: yield f"data: {json.dumps({'error': {'message': f'Final Error: {error_detail}'}})}\n\n"
                    return

    if req.stream:
        return StreamingResponse(response_wrapper(), media_type="text/event-stream")
    
    full_content = ""
    async for chunk_str in response_wrapper():
        if chunk_str.startswith("data: [DONE]"): break
        if chunk_str.startswith("data: "):
            try:
                data = json.loads(chunk_str[6:])
                delta = data["choices"][0]["delta"]
                if "content" in delta: full_content += delta["content"]
            except: pass

    return {
        "id": chat_id,
        "object": "chat.completion",
        "created": created_time,
        "model": req.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": full_content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }

# ---------- JSON Stream Parser ----------
class JSONStreamParser:
    def __init__(self):
        self.buffer_list = [] # Optimization: Use list for O(1) appends
        self.brace_count = 0
        self.in_string = False
        self.escape = False
        self.started = False 

    def process_chunk(self, chunk: str) -> List[str]:
        results = []
        for char in chunk:
            if not self.started:
                if char == '{':
                    self.started = True
                    self.brace_count = 1
                    self.buffer_list = ["{"]
                continue
            
            self.buffer_list.append(char)
            
            if self.in_string:
                if self.escape:
                    self.escape = False
                elif char == '\\':
                    self.escape = True
                elif char == '"':
                    self.in_string = False
            else:
                if char == '"':
                    self.in_string = True
                elif char == '{':
                    self.brace_count += 1
                elif char == '}':
                    self.brace_count -= 1
                    if self.brace_count == 0:
                        results.append("".join(self.buffer_list))
                        self.buffer_list = []
                        self.started = False
        return results

async def stream_chat_generator(account: Account, session: str, text_content: str, file_ids: List[str], model_name: str, chat_id: str, created_time: int, is_stream: bool = True):
    jwt = await account.get_jwt()
    headers = get_common_headers(jwt)
    
    body = {
        "configId": account.config_id,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": session,
            "query": {"parts": [{"text": text_content}]},
            "filter": "",
            "fileIds": file_ids, 
            "answerGenerationMode": "NORMAL",
            "toolsSpec": {
                "webGroundingSpec": {},
                "toolRegistry": "default_tool_registry",
                "imageGenerationSpec": {},
                "videoGenerationSpec": {}
            },
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Asia/Shanghai"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    target_model_id = MODEL_MAPPING.get(model_name)
    if target_model_id:
        body["streamAssistRequest"]["assistGenerationConfig"] = {
            "modelId": target_model_id
        }

    if is_stream:
        chunk = create_chunk(chat_id, created_time, model_name, {"role": "assistant"}, None)
        yield f"data: {chunk}\n\n"

    parser = JSONStreamParser()
    
    # Use incremental decoder to handle multi-byte characters split across chunks
    import codecs
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    try:
        async with http_client.stream(
            "POST",
            "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist",
            headers=headers,
            json=body,
        ) as response:
            if response.status_code != 200:
                await response.aread()
                raise HTTPException(status_code=response.status_code, detail=f"Upstream Error {response.text}")

            # Smoothness Optimization:
            # The upstream API might return multiple JSON objects in a single chunk or split them.
            # We want to yield as soon as we have a displayable character.
            has_started_responding = False
            
            async for chunk_bytes in response.aiter_bytes(chunk_size=1024): # Try smaller chunks
                # Decode bytes incrementally
                chunk_str = decoder.decode(chunk_bytes, final=False)
                if not chunk_str:
                    continue
                    
                json_objects = parser.process_chunk(chunk_str)
                
                for json_str in json_objects:
                    try:
                        data = json.loads(json_str)
                        # Process the data immediately
                        for reply in data.get("streamAssistResponse", {}).get("answer", {}).get("replies", []):
                            content_obj = reply.get("groundedContent", {}).get("content", {})
                            text = content_obj.get("text", "")
                            
                            is_thought = reply.get("thought", False)
                            
                            # Optimized Filter Logic:
                            # If we haven't started responding yet (first token), we aggressively hide thoughts.
                            # Once valid text appears, we let everything through for speed.
                            
                            if not has_started_responding:
                                if text:
                                    clean_text = text.strip()
                                    # Very basic check for thought markers
                                    if clean_text.startswith("**") and clean_text.endswith("**") and len(clean_text) < 80:
                                        # Likely a thought header like "**Thought**"
                                        is_thought = True
                                    else:
                                        # Passed the filter
                                        has_started_responding = True
                            
                            # If filtered, log debug but don't yield (increases perceived latency but cleans output)
                            if is_thought and not has_started_responding:
                                logger.debug(f"💭 Skipping thought: {text[:20]}...")
                                continue
                            
                            if text:
                                has_started_responding = True 
                                chunk = create_chunk(chat_id, created_time, model_name, {"content": text}, None)
                                if is_stream:
                                    yield f"data: {chunk}\n\n"
                                    # Anti-glitch: Small sleep 0 to force IO flush? 
                                    # Usually not needed in asyncio, but good for tight loops
                                    # await asyncio.sleep(0) 
                                else:
                                    pass
                    except json.JSONDecodeError:
                        logger.warning(f"⚠️ 解析 JSON 失败: {json_str[:50]}...")
                        continue

    except Exception as e:
        logger.error(f"❌ 流式请求异常: {e}")
        error_chunk = create_chunk(chat_id, created_time, model_name, {"content": f"\n[Error: {str(e)}]"}, "stop")
        if is_stream:
            yield f"data: {error_chunk}\n\n"
        raise e
    
    if is_stream:
        final_chunk = create_chunk(chat_id, created_time, model_name, {}, "stop")
        yield f"data: {final_chunk}\n\n"
        yield "data: [DONE]\n\n"

if __name__ == "__main__":
    if not (API_KEY):
        print("Error: Missing API_KEY variables.")
        exit(1)
    
    # Initialize Check
    if not (ENV_SECURE_C_SES or os.getenv("DATABASE_URL")):
         print("Warning: No Account Configs Found (ENV or DB).")

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
