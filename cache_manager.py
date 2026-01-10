import time
import asyncio
import logging
from collections import OrderedDict
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, field
from threading import RLock
import weakref
import gc

logger = logging.getLogger("gemini.cache")

@dataclass
class SessionInfo:
    """会话信息数据类"""
    session_id: str
    account_id: int
    created_at: float
    updated_at: float
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    
    def update_access(self):
        """更新访问信息"""
        self.access_count += 1
        self.last_accessed = time.time()
        self.updated_at = time.time()

@dataclass
class CacheMetrics:
    """缓存统计信息"""
    total_sessions: int = 0
    active_sessions: int = 0
    hot_cache_size: int = 0
    warm_cache_size: int = 0
    cold_cache_size: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    sessions_created: int = 0
    sessions_evicted: int = 0
    memory_usage_mb: float = 0.0
    
    @property
    def hit_rate(self) -> float:
        """缓存命中率"""
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0
    
    @property
    def total_requests(self) -> int:
        """总请求数"""
        return self.cache_hits + self.cache_misses

class LRUCache:
    """线程安全的LRU缓存实现"""
    
    def __init__(self, max_size: int, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, SessionInfo] = OrderedDict()
        self._lock = RLock()
        self._last_cleanup = time.time()
        
    def get(self, key: str) -> Optional[SessionInfo]:
        """获取缓存项"""
        with self._lock:
            if key not in self._cache:
                return None
            
            session_info = self._cache[key]
            
            # 检查是否过期
            if time.time() - session_info.created_at > self.ttl:
                del self._cache[key]
                return None
            
            # 移动到末尾（最近使用）
            self._cache.move_to_end(key)
            session_info.update_access()
            
            return session_info
    
    def put(self, key: str, session_info: SessionInfo) -> None:
        """存储缓存项"""
        with self._lock:
            # 如果已存在，更新并移动到末尾
            if key in self._cache:
                self._cache[key] = session_info
                self._cache.move_to_end(key)
                return
            
            # 检查容量限制
            while len(self._cache) >= self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            
            self._cache[key] = session_info
            self._cache.move_to_end(key)
    
    def remove(self, key: str) -> bool:
        """删除缓存项"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def cleanup_expired(self) -> int:
        """清理过期项"""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key, session_info in self._cache.items():
                if current_time - session_info.created_at > self.ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
            
            self._last_cleanup = current_time
            return len(expired_keys)
    
    def size(self) -> int:
        """获取缓存大小"""
        with self._lock:
            return len(self._cache)
    
    def keys(self) -> List[str]:
        """获取所有键"""
        with self._lock:
            return list(self._cache.keys())
    
    def clear(self) -> None:
        """清空缓存"""
        with self._lock:
            self._cache.clear()

class MemorySessionPool:
    """高性能内存会话池"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # 三级缓存
        self.hot_cache = LRUCache(
            max_size=config.get('CACHE_HOT_SIZE', 5000),
            ttl=config.get('SESSION_TTL', 7200)
        )
        self.warm_cache = LRUCache(
            max_size=config.get('CACHE_WARM_SIZE', 3000),
            ttl=config.get('SESSION_TTL', 7200) * 2
        )
        self.cold_cache = LRUCache(
            max_size=config.get('CACHE_COLD_SIZE', 2000),
            ttl=config.get('SESSION_TTL', 7200) * 4
        )
        
        # 统计信息
        self.metrics = CacheMetrics()
        self._metrics_lock = RLock()
        
        # 清理任务
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # 预热任务
        self._prewarmed_sessions: Dict[int, List[str]] = {}
        
    async def start(self):
        """启动会话池"""
        if self._running:
            return
        
        self._running = True
        
        # 启动清理任务
        cleanup_interval = self.config.get('CACHE_CLEANUP_INTERVAL', 300)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop(cleanup_interval))
        
        logger.info("🚀 内存会话池已启动")
    
    async def stop(self):
        """停止会话池"""
        if not self._running:
            return
        
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # 清理所有缓存
        self.hot_cache.clear()
        self.warm_cache.clear()
        self.cold_cache.clear()
        
        logger.info("🛑 内存会话池已停止")
    
    def get_session(self, conv_key: str) -> Optional[SessionInfo]:
        """获取会话信息"""
        # 按优先级查找：热 -> 温 -> 冷
        session_info = self.hot_cache.get(conv_key)
        if session_info:
            self._increment_hit()
            return session_info
        
        session_info = self.warm_cache.get(conv_key)
        if session_info:
            # 提升到热缓存
            self.hot_cache.put(conv_key, session_info)
            self.warm_cache.remove(conv_key)
            self._increment_hit()
            return session_info
        
        session_info = self.cold_cache.get(conv_key)
        if session_info:
            # 提升到温缓存
            self.warm_cache.put(conv_key, session_info)
            self.cold_cache.remove(conv_key)
            self._increment_hit()
            return session_info
        
        self._increment_miss()
        return None
    
    def put_session(self, conv_key: str, session_id: str, account_id: int) -> None:
        """存储会话信息"""
        session_info = SessionInfo(
            session_id=session_id,
            account_id=account_id,
            created_at=time.time(),
            updated_at=time.time()
        )
        
        # 新会话直接放入热缓存
        self.hot_cache.put(conv_key, session_info)
        
        with self._metrics_lock:
            self.metrics.sessions_created += 1
        
        logger.debug(f"💾 新会话已缓存: {conv_key[:12]}... -> {session_id[-12:]}")
    
    def remove_session(self, conv_key: str) -> bool:
        """删除会话"""
        removed = False
        if self.hot_cache.remove(conv_key):
            removed = True
        if self.warm_cache.remove(conv_key):
            removed = True
        if self.cold_cache.remove(conv_key):
            removed = True
        
        if removed:
            with self._metrics_lock:
                self.metrics.sessions_evicted += 1
        
        return removed
    
    def get_account_sessions(self, account_id: int) -> List[Tuple[str, SessionInfo]]:
        """获取指定账号的所有会话"""
        sessions = []
        
        # 搜索所有缓存层
        for cache in [self.hot_cache, self.warm_cache, self.cold_cache]:
            for conv_key, session_info in cache._cache.items():
                if session_info.account_id == account_id:
                    sessions.append((conv_key, session_info))
        
        return sessions
    
    def clear_account_sessions(self, account_id: int) -> int:
        """清理指定账号的所有会话"""
        cleared = 0
        
        for cache in [self.hot_cache, self.warm_cache, self.cold_cache]:
            keys_to_remove = []
            for conv_key, session_info in cache._cache.items():
                if session_info.account_id == account_id:
                    keys_to_remove.append(conv_key)
            
            for key in keys_to_remove:
                if cache.remove(key):
                    cleared += 1
        
        logger.info(f"🧹 已清理账号 [{account_id}] 的 {cleared} 个会话")
        return cleared
    
    async def _cleanup_loop(self, interval: int):
        """定期清理循环"""
        while self._running:
            try:
                await asyncio.sleep(interval)
                await self._perform_cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ 清理任务异常: {e}")
    
    async def _perform_cleanup(self):
        """执行清理操作"""
        total_cleaned = 0
        
        # 清理过期会话
        total_cleaned += self.hot_cache.cleanup_expired()
        total_cleaned += self.warm_cache.cleanup_expired()
        total_cleaned += self.cold_cache.cleanup_expired()
        
        # 内存压力检查
        memory_threshold = self.config.get('MEMORY_WARNING_THRESHOLD', 0.8)
        if self._get_memory_usage_ratio() > memory_threshold:
            # 强制清理最旧的会话
            total_cleaned += self._emergency_cleanup()
        
        # 更新统计信息
        self._update_metrics()
        
        # 垃圾回收
        if total_cleaned > 0:
            gc.collect()
            logger.debug(f"🧹 清理完成: {total_cleaned} 个过期会话")
    
    def _emergency_cleanup(self) -> int:
        """紧急清理（内存压力时）"""
        cleaned = 0
        
        # 从冷缓存开始清理
        while self.cold_cache.size() > 0 and cleaned < 100:
            oldest_key = next(iter(self.cold_cache._cache))
            if self.cold_cache.remove(oldest_key):
                cleaned += 1
        
        # 如果还不够，清理温缓存
        if self._get_memory_usage_ratio() > 0.9:
            while self.warm_cache.size() > 0 and cleaned < 200:
                oldest_key = next(iter(self.warm_cache._cache))
                if self.warm_cache.remove(oldest_key):
                    cleaned += 1
        
        return cleaned
    
    def _get_memory_usage_ratio(self) -> float:
        """估算内存使用比例"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return memory.percent / 100.0
        except ImportError:
            # 如果没有psutil，使用缓存大小估算
            total_capacity = (self.hot_cache.max_size + 
                            self.warm_cache.max_size + 
                            self.cold_cache.max_size)
            current_usage = (self.hot_cache.size() + 
                           self.warm_cache.size() + 
                           self.cold_cache.size())
            return current_usage / total_capacity if total_capacity > 0 else 0.0
        except Exception:
            # 如果获取失败，返回0
            return 0.0
    
    def _increment_hit(self):
        """增加缓存命中"""
        with self._metrics_lock:
            self.metrics.cache_hits += 1
    
    def _increment_miss(self):
        """增加缓存未命中"""
        with self._metrics_lock:
            self.metrics.cache_misses += 1
    
    def _update_metrics(self):
        """更新统计信息"""
        with self._metrics_lock:
            self.metrics.total_sessions = (
                self.hot_cache.size() + 
                self.warm_cache.size() + 
                self.cold_cache.size()
            )
            self.metrics.hot_cache_size = self.hot_cache.size()
            self.metrics.warm_cache_size = self.warm_cache.size()
            self.metrics.cold_cache_size = self.cold_cache.size()
            
            # 估算内存使用
            self.metrics.memory_usage_mb = self._estimate_memory_usage()
    
    def _estimate_memory_usage(self) -> float:
        """估算内存使用量（MB）"""
        import sys
        
        total_size = 0
        for cache in [self.hot_cache, self.warm_cache, self.cold_cache]:
            for session_info in cache._cache.values():
                total_size += sys.getsizeof(session_info)
                total_size += sys.getsizeof(session_info.session_id)
        
        return total_size / (1024 * 1024)  # 转换为MB
    
    def get_metrics(self) -> CacheMetrics:
        """获取统计信息"""
        self._update_metrics()
        return self.metrics
    
    def get_detailed_stats(self) -> Dict[str, Any]:
        """获取详细统计信息"""
        metrics = self.get_metrics()
        
        return {
            "cache_metrics": {
                "total_sessions": metrics.total_sessions,
                "active_sessions": metrics.active_sessions,
                "hot_cache_size": metrics.hot_cache_size,
                "warm_cache_size": metrics.warm_cache_size,
                "cold_cache_size": metrics.cold_cache_size,
                "cache_hits": metrics.cache_hits,
                "cache_misses": metrics.cache_misses,
                "hit_rate": round(metrics.hit_rate, 2),
                "total_requests": metrics.total_requests,
                "sessions_created": metrics.sessions_created,
                "sessions_evicted": metrics.sessions_evicted,
                "memory_usage_mb": round(metrics.memory_usage_mb, 2)
            },
            "cache_config": {
                "hot_cache_max": self.hot_cache.max_size,
                "warm_cache_max": self.warm_cache.max_size,
                "cold_cache_max": self.cold_cache.max_size,
                "session_ttl": self.hot_cache.ttl,
                "cleanup_interval": self.config.get('CACHE_CLEANUP_INTERVAL', 300)
            },
            "system_info": {
                "memory_usage_ratio": round(self._get_memory_usage_ratio() * 100, 2),
                "cleanup_task_running": self._running,
                "prewarmed_sessions": len(self._prewarmed_sessions)
            }
        }

# 全局会话池实例
session_pool: Optional[MemorySessionPool] = None

def init_session_pool(config: Dict[str, Any]) -> MemorySessionPool:
    """初始化会话池"""
    global session_pool
    session_pool = MemorySessionPool(config)
    return session_pool

def get_session_pool() -> Optional[MemorySessionPool]:
    """获取会话池实例"""
    return session_pool
