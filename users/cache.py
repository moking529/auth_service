"""
Redis缓存服务模块
提供用户信息和权限的缓存管理功能
"""
import json
import redis
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class RedisCacheService:
    """
    Redis缓存服务类
    用于管理用户信息和权限的缓存操作
    """
    
    def __init__(self):
        """
        初始化Redis连接
        """
        try:
            # 从配置中获取Redis连接参数
            redis_config = getattr(settings, 'REDIS_CONFIG', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('HOST', 'localhost'),
                port=redis_config.get('PORT', 6379),
                db=redis_config.get('DB', 0),
                password=redis_config.get('PASSWORD', None),
                decode_responses=True
            )
            # 测试连接
            self.redis_client.ping()
        except (redis.ConnectionError, redis.TimeoutError) as e:
            raise ImproperlyConfigured(f"无法连接到Redis服务器: {str(e)}")
        except Exception as e:
            raise ImproperlyConfigured(f"Redis初始化失败: {str(e)}")
    
    def cache_user_info(self, access_token: str, user_data: dict, expire_seconds: int = 7200):
        """
        缓存用户信息
        
        Args:
            access_token: JWT访问令牌，用作缓存键
            user_data: 用户数据字典，包含用户名、角色、权限列表等
            expire_seconds: 过期时间，默认7200秒（2小时）
        
        Returns:
            bool: 缓存是否成功
        """
        try:
            key = f"user:info:{access_token}"
            self.redis_client.setex(
                key,
                expire_seconds,
                json.dumps(user_data, ensure_ascii=False)
            )
            return True
        except Exception as e:
            print(f"缓存用户信息失败: {str(e)}")
            return False
    
    def get_cached_user_info(self, access_token: str) -> dict:
        """
        获取缓存的用户信息
        
        Args:
            access_token: JWT访问令牌
        
        Returns:
            dict: 用户信息字典，如果缓存不存在返回None
        """
        try:
            key = f"user:info:{access_token}"
            data = self.redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            print(f"获取缓存用户信息失败: {str(e)}")
            return None
    
    def delete_user_info_cache(self, access_token: str) -> bool:
        """
        删除用户信息缓存
        
        Args:
            access_token: JWT访问令牌
        
        Returns:
            bool: 删除是否成功
        """
        try:
            key = f"user:info:{access_token}"
            return bool(self.redis_client.delete(key))
        except Exception as e:
            print(f"删除用户缓存失败: {str(e)}")
            return False
    
    def cache_user_permissions(self, access_token: str, permissions: list, expire_seconds: int = 7200):
        """
        缓存用户权限列表
        
        Args:
            access_token: JWT访问令牌
            permissions: 权限列表
            expire_seconds: 过期时间，默认7200秒（2小时）
        
        Returns:
            bool: 缓存是否成功
        """
        try:
            key = f"user:permissions:{access_token}"
            self.redis_client.setex(
                key,
                expire_seconds,
                json.dumps(permissions, ensure_ascii=False)
            )
            return True
        except Exception as e:
            print(f"缓存用户权限失败: {str(e)}")
            return False
    
    def get_cached_user_permissions(self, access_token: str) -> list:
        """
        获取缓存的用户权限列表
        
        Args:
            access_token: JWT访问令牌
        
        Returns:
            list: 权限列表，如果缓存不存在返回None
        """
        try:
            key = f"user:permissions:{access_token}"
            data = self.redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            print(f"获取缓存用户权限失败: {str(e)}")
            return None


# 创建全局缓存服务实例
cache_service = None

def get_cache_service():
    """
    获取Redis缓存服务实例
    
    Returns:
        RedisCacheService: 缓存服务实例
    """
    global cache_service
    if cache_service is None:
        cache_service = RedisCacheService()
    return cache_service