"""
缓存模块测试
测试cache.py中的Redis缓存服务功能
"""
import json
import time
from unittest.mock import patch, Mock
from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from users.cache import RedisCacheService, get_cache_service


class RedisCacheServiceTest(TestCase):
    """RedisCacheService缓存服务测试"""
    
    def setUp(self):
        """设置测试环境"""
        # 保存原始Redis配置以便测试后恢复
        self.original_redis_config = getattr(settings, 'REDIS_CONFIG', {})
        setattr(settings, 'REDIS_CONFIG', {
            'HOST': 'localhost',
            'PORT': 6379,
            'DB': 0,
            'PASSWORD': None
        })
    
    def tearDown(self):
        """清理测试环境"""
        # 恢复原始Redis配置
        setattr(settings, 'REDIS_CONFIG', self.original_redis_config)
        # 清除全局缓存实例
        import users.cache
        users.cache.cache_service = None
    
    @patch('redis.Redis')
    def test_redis_client_initialization(self, mock_redis_class):
        """测试Redis客户端初始化"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 验证Redis客户端初始化和ping调用
        mock_redis_class.assert_called_with(
            host='localhost',
            port=6379,
            db=0,
            password=None,
            decode_responses=True
        )
        mock_redis.ping.assert_called_once()
    
    @patch('redis.Redis')
    def test_redis_connection_failure(self, mock_redis_class):
        """测试Redis连接失败的处理"""
        # 模拟Redis连接异常
        mock_redis_class.side_effect = Exception("Redis connection error")
        
        # 测试初始化时的异常处理
        with self.assertRaises(Exception):
            RedisCacheService()
    
    @patch('redis.Redis')
    def test_cache_user_info(self, mock_redis_class):
        """测试缓存用户信息功能"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 测试数据
        token = 'test_token'
        user_data = {'username': 'testuser', 'role': 'admin', 'permissions': ['view', 'create']}
        
        # 执行缓存操作
        result = cache_service.cache_user_info(token, user_data)
        
        # 验证结果
        self.assertTrue(result)
        mock_redis.setex.assert_called_once_with(
            'user:info:test_token',
            7200,
            json.dumps(user_data, ensure_ascii=False)
        )
    
    @patch('redis.Redis')
    def test_cache_user_info_with_custom_expiration(self, mock_redis_class):
        """测试使用自定义过期时间缓存用户信息"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 测试数据
        token = 'test_token'
        user_data = {'username': 'testuser', 'role': 'admin'}
        custom_expiration = 3600
        
        # 执行缓存操作，使用自定义过期时间
        result = cache_service.cache_user_info(token, user_data, expire_seconds=custom_expiration)
        
        # 验证结果
        self.assertTrue(result)
        mock_redis.setex.assert_called_once_with(
            'user:info:test_token',
            custom_expiration,
            json.dumps(user_data, ensure_ascii=False)
        )
    
    @patch('redis.Redis')
    def test_cache_user_info_error(self, mock_redis_class):
        """测试缓存用户信息失败的情况"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.setex.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行缓存操作
        result = cache_service.cache_user_info('test_token', {'username': 'testuser'})
        
        # 验证结果
        self.assertFalse(result)
    
    @patch('redis.Redis')
    def test_get_cached_user_info(self, mock_redis_class):
        """测试获取缓存的用户信息"""
        # 设置模拟对象
        mock_redis = Mock()
        user_data = {'username': 'testuser', 'role': 'admin'}
        mock_redis.get.return_value = json.dumps(user_data, ensure_ascii=False)
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_info('test_token')
        
        # 验证结果
        self.assertEqual(result, user_data)
        mock_redis.get.assert_called_once_with('user:info:test_token')
    
    @patch('redis.Redis')
    def test_get_cached_user_info_nonexistent(self, mock_redis_class):
        """测试获取不存在的用户信息缓存"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.get.return_value = None
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_info('nonexistent_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    @patch('redis.Redis')
    def test_get_cached_user_info_error(self, mock_redis_class):
        """测试获取用户信息缓存失败的情况"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.get.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_info('test_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    @patch('redis.Redis')
    def test_delete_user_info_cache(self, mock_redis_class):
        """测试删除用户信息缓存"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.delete.return_value = 1  # 表示成功删除一条记录
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行删除操作
        result = cache_service.delete_user_info_cache('test_token')
        
        # 验证结果
        self.assertTrue(result)
        mock_redis.delete.assert_called_once_with('user:info:test_token')
    
    @patch('redis.Redis')
    def test_delete_user_info_cache_nonexistent(self, mock_redis_class):
        """测试删除不存在的用户信息缓存"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.delete.return_value = 0  # 表示没有删除任何记录
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行删除操作
        result = cache_service.delete_user_info_cache('nonexistent_token')
        
        # 验证结果
        self.assertFalse(result)
    
    @patch('redis.Redis')
    def test_delete_user_info_cache_error(self, mock_redis_class):
        """测试删除用户信息缓存失败的情况"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.delete.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行删除操作
        result = cache_service.delete_user_info_cache('test_token')
        
        # 验证结果
        self.assertFalse(result)
    
    @patch('redis.Redis')
    def test_cache_user_permissions(self, mock_redis_class):
        """测试缓存用户权限列表"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 测试数据
        token = 'test_token'
        permissions = [
            {'resource_type': 'user', 'action': 'view'},
            {'resource_type': 'product', 'action': 'create'}
        ]
        
        # 执行缓存操作
        result = cache_service.cache_user_permissions(token, permissions)
        
        # 验证结果
        self.assertTrue(result)
        mock_redis.setex.assert_called_once_with(
            'user:permissions:test_token',
            7200,
            json.dumps(permissions, ensure_ascii=False)
        )
    
    @patch('redis.Redis')
    def test_cache_user_permissions_with_custom_expiration(self, mock_redis_class):
        """测试使用自定义过期时间缓存用户权限"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 测试数据
        token = 'test_token'
        permissions = [{'resource_type': 'user', 'action': 'view'}]
        custom_expiration = 3600
        
        # 执行缓存操作，使用自定义过期时间
        result = cache_service.cache_user_permissions(token, permissions, expire_seconds=custom_expiration)
        
        # 验证结果
        self.assertTrue(result)
        mock_redis.setex.assert_called_once_with(
            'user:permissions:test_token',
            custom_expiration,
            json.dumps(permissions, ensure_ascii=False)
        )
    
    @patch('redis.Redis')
    def test_cache_user_permissions_error(self, mock_redis_class):
        """测试缓存用户权限失败的情况"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.setex.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行缓存操作
        result = cache_service.cache_user_permissions('test_token', [{'resource_type': 'user', 'action': 'view'}])
        
        # 验证结果
        self.assertFalse(result)
    
    @patch('redis.Redis')
    def test_get_cached_user_permissions(self, mock_redis_class):
        """测试获取缓存的用户权限列表"""
        # 设置模拟对象
        mock_redis = Mock()
        permissions = [{'resource_type': 'user', 'action': 'view'}]
        mock_redis.get.return_value = json.dumps(permissions, ensure_ascii=False)
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_permissions('test_token')
        
        # 验证结果
        self.assertEqual(result, permissions)
        mock_redis.get.assert_called_once_with('user:permissions:test_token')
    
    @patch('redis.Redis')
    def test_get_cached_user_permissions_nonexistent(self, mock_redis_class):
        """测试获取不存在的用户权限缓存"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.get.return_value = None
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_permissions('nonexistent_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    @patch('redis.Redis')
    def test_get_cached_user_permissions_error(self, mock_redis_class):
        """测试获取用户权限缓存失败的情况"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis.get.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 执行获取操作
        result = cache_service.get_cached_user_permissions('test_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    @patch('redis.Redis')
    def test_complex_data_types(self, mock_redis_class):
        """测试复杂数据类型的缓存"""
        # 设置模拟对象
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        # 创建缓存服务实例
        cache_service = RedisCacheService()
        
        # 测试复杂用户数据
        complex_data = {
            'username': 'testuser',
            'role': 'admin',
            'active': True,
            'permissions': ['view', 'create', 'delete'],
            'settings': {
                'theme': 'dark',
                'notifications': True
            }
        }
        
        # 执行缓存操作
        cache_service.cache_user_info('test_token', complex_data)
        
        # 验证调用
        mock_redis.setex.assert_called_once()
        # 验证序列化后的数据可以正确解析
        args, kwargs = mock_redis.setex.call_args
        key, expiration, serialized_data = args
        self.assertEqual(key, 'user:info:test_token')
        self.assertEqual(expiration, 7200)
        
        # 验证可以反序列化
        try:
            parsed_data = json.loads(serialized_data)
            self.assertEqual(parsed_data['username'], 'testuser')
            self.assertEqual(parsed_data['role'], 'admin')
            self.assertEqual(parsed_data['permissions'], ['view', 'create', 'delete'])
        except json.JSONDecodeError:
            self.fail("序列化的数据不是有效的JSON格式")


class GetCacheServiceTest(TestCase):
    """get_cache_service函数测试"""
    
    def setUp(self):
        """设置测试环境"""
        # 清除之前可能存在的缓存实例
        import users.cache
        users.cache.cache_service = None
    
    @patch('users.cache.RedisCacheService')
    def test_singleton_pattern(self, mock_redis_service_class):
        """测试单例模式实现"""
        # 模拟RedisCacheService构造函数
        mock_instance = Mock()
        mock_redis_service_class.return_value = mock_instance
        
        # 获取两次缓存服务实例
        instance1 = get_cache_service()
        instance2 = get_cache_service()
        
        # 验证是同一个实例
        self.assertIs(instance1, instance2)
        
        # 验证只创建了一个实例
        mock_redis_service_class.assert_called_once()
    
    @patch('users.cache.RedisCacheService')
    def test_cache_service_creation(self, mock_redis_service_class):
        """测试缓存服务创建"""
        # 模拟RedisCacheService构造函数
        mock_instance = Mock()
        mock_redis_service_class.return_value = mock_instance
        
        # 获取缓存服务
        result = get_cache_service()
        
        # 验证RedisCacheService被调用
        mock_redis_service_class.assert_called_once()
        self.assertEqual(result, mock_instance)
    
    @patch('users.cache.RedisCacheService')
    def test_multiple_calls_return_same_instance(self, mock_redis_service_class):
        """测试多次调用返回相同实例"""
        # 模拟RedisCacheService构造函数
        mock_instance = Mock()
        mock_redis_service_class.return_value = mock_instance
        
        # 多次调用
        get_cache_service()
        get_cache_service()
        get_cache_service()
        
        # 验证只创建了一个实例
        mock_redis_service_class.assert_called_once()
    
    @patch('users.cache.RedisCacheService')
    def test_global_instance_reused(self, mock_redis_service_class):
        """测试全局实例被重用"""
        # 模拟RedisCacheService构造函数
        mock_instance = Mock()
        mock_redis_service_class.return_value = mock_instance
        
        # 第一次调用创建实例
        import users.cache
        users.cache.cache_service = None  # 确保之前没有实例
        
        # 第一次调用
        get_cache_service()
        
        # 验证创建了实例
        self.assertEqual(mock_redis_service_class.call_count, 1)
        
        # 再次调用，不应该创建新实例
        mock_redis_service_class.reset_mock()
        get_cache_service()
        
        # 验证没有再次创建实例
        mock_redis_service_class.assert_not_called()