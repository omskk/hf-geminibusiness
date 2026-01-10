
import os
import asyncpg
import logging
from typing import List, Optional
import asyncio

logger = logging.getLogger("gemini.db")

class DatabaseManager:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.database_url = os.getenv("DATABASE_URL")

    async def connect(self):
        if not self.database_url:
            logger.warning("DATABASE_URL not set. Database features disabled.")
            return

        try:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=1,
                max_size=10
            )
            await self._init_schema()
            logger.info("✅ Database connected successfully")
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            raise e

    async def _init_schema(self):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS gemini_accounts (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255),
                    secure_c_ses TEXT NOT NULL,
                    host_c_oses TEXT,
                    csesidx TEXT NOT NULL,
                    config_id TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    request_count BIGINT DEFAULT 0,
                    last_used_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    disabled_reason TEXT,
                    health_check_time TIMESTAMP,
                    health_status VARCHAR(20) DEFAULT 'unknown'
                );
                
                -- Migration: Add new columns if not exist
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS disabled_reason TEXT;
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS health_check_time TIMESTAMP;
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS health_status VARCHAR(20) DEFAULT 'unknown';
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS request_count BIGINT DEFAULT 0;
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS network_error_count INTEGER DEFAULT 0;
                ALTER TABLE gemini_accounts ADD COLUMN IF NOT EXISTS last_network_error_time TIMESTAMP;
                
                -- Create indexes for faster lookups
                CREATE INDEX IF NOT EXISTS idx_accounts_active ON gemini_accounts(is_active);
                CREATE INDEX IF NOT EXISTS idx_accounts_health_status ON gemini_accounts(health_status);
            """)

    async def disconnect(self):
        if self.pool:
            await self.pool.close()

    async def fetch_active_accounts(self) -> List[dict]:
        if not self.pool:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM gemini_accounts 
                WHERE is_active = TRUE 
                ORDER BY last_used_at ASC NULLS FIRST
            """)
            return [dict(row) for row in rows]

    async def increment_account_usage(self, account_id: int):
        if not self.pool:
            return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET last_used_at = NOW(), request_count = request_count + 1
                WHERE id = $1
            """, account_id)

    async def update_account_usage(self, account_id: int):
        # Legacy method, redirect to increment if needed, or just update timestamp
        # For now, let's just update timestamp to not break compatibility if called elsewhere without intent to increment count
        if not self.pool:
            return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET last_used_at = NOW() 
                WHERE id = $1
            """, account_id)

    async def add_account(self, name: str, secure_c_ses: str, host_c_oses: str, csesidx: str, config_id: str):
        if not self.pool:
            return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO gemini_accounts (name, secure_c_ses, host_c_oses, csesidx, config_id)
                VALUES ($1, $2, $3, $4, $5)
            """, name, secure_c_ses, host_c_oses, csesidx, config_id)

    async def get_all_accounts(self) -> List[dict]:
        if not self.pool: return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM gemini_accounts ORDER BY id ASC")
            return [dict(row) for row in rows]

    async def update_account(self, id: int, data: dict):
        if not self.pool: return
        set_clauses = []
        values = []
        idx = 1
        for key in ["name", "secure_c_ses", "host_c_oses", "csesidx", "config_id", "is_active"]:
            if key in data:
                set_clauses.append(f"{key} = ${idx}")
                values.append(data[key])
                idx += 1
        
        if not set_clauses: return
        
        values.append(id)
        query = f"UPDATE gemini_accounts SET {', '.join(set_clauses)} WHERE id = ${idx}"
        
        async with self.pool.acquire() as conn:
            await conn.execute(query, *values)

    async def delete_account(self, id: int):
        if not self.pool: return
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM gemini_accounts WHERE id = $1", id)

    # ---------- 健康检查相关方法 ----------
    async def disable_account_with_reason(self, account_id: int, reason: str):
        """禁用账号并记录原因"""
        if not self.pool: return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET is_active = FALSE, 
                    disabled_reason = $1, 
                    health_status = 'unhealthy',
                    health_check_time = NOW()
                WHERE id = $2
            """, reason, account_id)
        logger.info(f"🚫 账号 [{account_id}] 已禁用，原因: {reason}")

    async def update_health_status(self, account_id: int, status: str):
        """更新账号健康状态"""
        if not self.pool: return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET health_status = $1, health_check_time = NOW()
                WHERE id = $2
            """, status, account_id)

    async def enable_account(self, account_id: int):
        """启用账号"""
        if not self.pool: return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET is_active = TRUE, 
                    disabled_reason = NULL, 
                    health_status = 'healthy'
                WHERE id = $1
            """, account_id)
        logger.info(f"✅ 账号 [{account_id}] 已启用")

    async def get_healthy_accounts_for_health_check(self) -> List[dict]:
        """获取需要健康检查的账号（只检查 is_active = TRUE 的账号）"""
        if not self.pool: return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM gemini_accounts 
                WHERE is_active = TRUE
                ORDER BY health_check_time ASC NULLS FIRST
            """)
            return [dict(row) for row in rows]

    async def get_health_summary(self) -> dict:
        """获取健康状态摘要"""
        if not self.pool: return {}
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_active = TRUE) as active,
                    COUNT(*) FILTER (WHERE is_active = FALSE) as disabled,
                    COUNT(*) FILTER (WHERE health_status = 'healthy') as healthy,
                    COUNT(*) FILTER (WHERE health_status = 'unhealthy') as unhealthy,
                    COUNT(*) FILTER (WHERE health_status = 'unknown') as unknown
                FROM gemini_accounts
            """)
            return dict(row)

    async def increment_network_error_count(self, account_id: int) -> int:
        """增加网络错误计数并返回当前计数"""
        if not self.pool: return 0
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET network_error_count = network_error_count + 1,
                    last_network_error_time = NOW()
                WHERE id = $1
            """, account_id)
            
            # 获取更新后的计数
            row = await conn.fetchrow("""
                SELECT network_error_count FROM gemini_accounts WHERE id = $1
            """, account_id)
            
            return row['network_error_count'] if row else 0

    async def reset_network_error_count(self, account_id: int):
        """重置网络错误计数"""
        if not self.pool: return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE gemini_accounts 
                SET network_error_count = 0,
                    last_network_error_time = NULL
                WHERE id = $1
            """, account_id)
        logger.info(f"🔄 账号 [{account_id}] 网络错误计数已重置")

db = DatabaseManager()
