import json
import time
import logging
from typing import Any, Optional, Dict, List
import redis
from app.config import settings

logger = logging.getLogger(__name__)

class CacheManager:
    def __init__(self, host='localhost', port=6379, db=0, password=None):
        self.enabled = settings.enable_redis
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.redis_client = None
        
        if self.enabled:
            try:
                self.redis_client = redis.StrictRedis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    password=self.password,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                # Test connection
                self.redis_client.ping()
                logger.info(f"Connected to Redis at {self.host}:{self.port}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. Using in-memory fallback.")
                self.enabled = False
                self.in_memory_cache = {}
        else:
            self.in_memory_cache = {}
    
    def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        """Set a value in the cache."""
        try:
            serialized_value = json.dumps(value, default=str)
            
            if self.enabled and self.redis_client:
                if expire:
                    self.redis_client.setex(key, expire, serialized_value)
                else:
                    self.redis_client.set(key, serialized_value)
            else:
                self.in_memory_cache[key] = {
                    'value': serialized_value,
                    'expire': time.time() + expire if expire else float('inf')
                }
            
            return True
        except Exception as e:
            logger.error(f"Error setting cache value for key {key}: {e}")
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        try:
            if self.enabled and self.redis_client:
                serialized_value = self.redis_client.get(key)
                if serialized_value:
                    return json.loads(serialized_value)
            else:
                cache_entry = self.in_memory_cache.get(key)
                if cache_entry:
                    if cache_entry['expire'] > time.time():
                        return json.loads(cache_entry['value'])
                    else:
                        # Expired, remove from cache
                        del self.in_memory_cache[key]
            
            return None
        except Exception as e:
            logger.error(f"Error getting cache value for key {key}: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete a value from the cache."""
        try:
            if self.enabled and self.redis_client:
                self.redis_client.delete(key)
            else:
                if key in self.in_memory_cache:
                    del self.in_memory_cache[key]
            
            return True
        except Exception as e:
            logger.error(f"Error deleting cache value for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        try:
            if self.enabled and self.redis_client:
                return self.redis_client.exists(key)
            else:
                return key in self.in_memory_cache and self.in_memory_cache[key]['expire'] > time.time()
        except Exception as e:
            logger.error(f"Error checking cache existence for key {key}: {e}")
            return False
    
    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a counter in the cache."""
        try:
            if self.enabled and self.redis_client:
                return self.redis_client.incr(key, amount)
            else:
                current_value = self.get(key) or 0
                new_value = current_value + amount
                self.set(key, new_value)
                return new_value
        except Exception as e:
            logger.error(f"Error incrementing counter for key {key}: {e}")
            return None
    
    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time for a key."""
        try:
            if self.enabled and self.redis_client:
                return self.redis_client.expire(key, seconds)
            else:
                if key in self.in_memory_cache:
                    self.in_memory_cache[key]['expire'] = time.time() + seconds
                    return True
                return False
        except Exception as e:
            logger.error(f"Error setting expiration for key {key}: {e}")
            return False
    
    def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a pattern."""
        try:
            if self.enabled and self.redis_client:
                return self.redis_client.keys(pattern)
            else:
                return [key for key in self.in_memory_cache.keys() if self.in_memory_cache[key]['expire'] > time.time()]
        except Exception as e:
            logger.error(f"Error getting keys with pattern {pattern}: {e}")
            return []
    
    def flush(self) -> bool:
        """Clear all keys from the cache."""
        try:
            if self.enabled and self.redis_client:
                self.redis_client.flushdb()
            else:
                self.in_memory_cache.clear()
            return True
        except Exception as e:
            logger.error(f"Error flushing cache: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        try:
            if self.enabled and self.redis_client:
                info = self.redis_client.info()
                return {
                    'type': 'Redis',
                    'connected_clients': info.get('connected_clients'),
                    'used_memory': info.get('used_memory_human'),
                    'keyspace_hits': info.get('keyspace_hits'),
                    'keyspace_misses': info.get('keyspace_misses')
                }
            else:
                return {
                    'type': 'In-Memory',
                    'keys': len(self.in_memory_cache),
                    'expired_keys': sum(1 for entry in self.in_memory_cache.values() if entry['expire'] <= time.time())
                }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {'type': 'Unknown', 'error': str(e)}

# Global cache instance
cache_manager = CacheManager()