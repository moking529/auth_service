"""
中间件和缓存模块测试
测试服务认证中间件和Redis缓存服务的功能
"""
import json
import sys
from unittest.mock import patch, Mock, MagicMock
from django.test import TestCase, RequestFactory
from django.http import JsonResponse
from users.middleware import ServiceAuthenticationMiddleware
from users.cache import RedisCacheService, get_cache_service
from users.models import Service


class MiddlewareTest(TestCase):
    """服务认证中间件测试类"""
    
    def setUp(self):
        """设置测试环境"""
        self.factory = RequestFactory()
        # 为中间件提供mock的get_response函数
        self.mock_get_response = Mock()
        self.mock_get_response.return_value = None
        self.middleware = ServiceAuthenticationMiddleware(self.mock_get_response)
        
        # 创建测试服务
        self.service = Service.objects.create(
            name='test_service',
            is_enabled=True
        )
        # 生成服务密钥
        self.service_secret = self.service.generate_secret()
        self.service.save()
    
    def test_should_exclude_path(self):
        """测试排除路径检查功能"""
        # 测试应该排除的路径
        self.assertTrue(self.middleware._should_exclude_path('/admin/'))
        self.assertTrue(self.middleware._should_exclude_path('/api/users/register/'))
        self.assertTrue(self.middleware._should_exclude_path('/api/users/login/'))
        self.assertTrue(self.middleware._should_exclude_path('/api/users/logout/'))
        
        # 测试不应该排除的路径
        self.assertFalse(self.middleware._should_exclude_path('/api/users/'))
        self.assertFalse(self.middleware._should_exclude_path('/api/permission-groups/'))
    
    @patch('sys.argv', ['manage.py'])
    @patch('users.middleware.Service')
    def test_valid_service_authentication(self, mock_service_class):
        """测试有效的服务认证"""
        # 模拟服务验证
        mock_service = Mock()
        mock_service.is_enabled = True
        mock_service.verify_secret.return_value = True
        mock_service_class.objects.get.return_value = mock_service
        
        # 创建请求
        request = self.factory.get('/api/protected/')
        request.headers = {
            'X-Service-Name': 'test_service',
            'X-Service-Secret': 'valid_secret'
        }
        
        # 确保中间件不返回响应（即通过认证）
        response = self.middleware.process_request(request)
        self.assertIsNone(response)
        
        # 验证请求对象中存储了服务信息
        self.assertEqual(request.service, mock_service)
    
    @patch('sys.argv', ['manage.py'])
    def test_missing_authentication_headers(self):
        """测试缺少认证头的情况"""
        # 创建没有认证头的请求
        request = self.factory.get('/api/protected/')
        request.headers = {}
        
        # 验证返回401错误
        response = self.middleware.process_request(request)
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 401)
        # 解码响应内容并比较字典，避免编码格式差异问题
        response_data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(response_data, {
            'code': 401,
            'message': '服务认证失败：缺少必要的认证头',
            'data': None
        })
    
    @patch('sys.argv', ['manage.py'])
    def test_invalid_service_name(self):
        """测试无效的服务名称"""
        # 创建请求
        request = self.factory.get('/api/protected/')
        request.headers = {
            'X-Service-Name': 'nonexistent_service',
            'X-Service-Secret': 'some_secret'
        }
        
        # 验证返回401错误
        response = self.middleware.process_request(request)
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 401)
    
    @patch('sys.argv', ['manage.py'])
    @patch('users.middleware.Service')
    def test_disabled_service(self, mock_service_class):
        """测试禁用的服务"""
        # 模拟禁用的服务
        mock_service = Mock()
        mock_service.is_enabled = False
        mock_service_class.objects.get.return_value = mock_service
        
        # 创建请求
        request = self.factory.get('/api/protected/')
        request.headers = {
            'X-Service-Name': 'test_service',
            'X-Service-Secret': 'test_secret'
        }
        
        # 验证返回403错误
        response = self.middleware.process_request(request)
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 403)
    
    @patch('sys.argv', ['manage.py'])
    @patch('users.middleware.Service')
    def test_invalid_secret(self, mock_service_class):
        """测试无效的服务密钥"""
        # 模拟密钥验证失败
        mock_service = Mock()
        mock_service.is_enabled = True
        mock_service.verify_secret.return_value = False
        mock_service_class.objects.get.return_value = mock_service
        
        # 创建请求
        request = self.factory.get('/api/protected/')
        request.headers = {
            'X-Service-Name': 'test_service',
            'X-Service-Secret': 'invalid_secret'
        }
        
        # 验证返回401错误
        response = self.middleware.process_request(request)
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 401)
    
    @patch('sys.argv', ['manage.py'])
    @patch('users.middleware.Service.objects.get')
    def test_exception_handling(self, mock_get):
        """测试异常处理"""
        # 模拟抛出异常
        mock_get.side_effect = Exception('Database error')
        
        # 创建请求
        request = self.factory.get('/api/protected/')
        request.headers = {
            'X-Service-Name': 'test_service',
            'X-Service-Secret': 'test_secret'
        }
        
        # 验证返回500错误
        response = self.middleware.process_request(request)
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 500)


class CacheServiceTest(TestCase):
    """Redis缓存服务测试类"""
    
    @patch('redis.Redis')
    def setUp(self, mock_redis):
        """设置测试环境"""
        # 模拟Redis连接
        self.mock_redis_client = Mock()
        self.mock_redis_client.ping.return_value = True
        mock_redis.return_value = self.mock_redis_client
        
        # 创建缓存服务实例
        self.cache_service = RedisCacheService()
    
    def test_cache_user_info(self):
        """测试缓存用户信息"""
        # 测试数据
        access_token = 'test_token'
        user_data = {'username': 'testuser', 'role': 'admin'}
        
        # 调用方法
        result = self.cache_service.cache_user_info(access_token, user_data)
        
        # 验证调用
        self.mock_redis_client.setex.assert_called_once_with(
            'user:info:test_token',
            7200,
            json.dumps(user_data, ensure_ascii=False)
        )
        self.assertTrue(result)
    
    def test_get_cached_user_info(self):
        """测试获取缓存用户信息"""
        # 模拟返回数据
        user_data = {'username': 'testuser', 'role': 'admin'}
        self.mock_redis_client.get.return_value = json.dumps(user_data)
        
        # 调用方法
        result = self.cache_service.get_cached_user_info('test_token')
        
        # 验证结果
        self.mock_redis_client.get.assert_called_once_with('user:info:test_token')
        self.assertEqual(result, user_data)
    
    def test_get_cached_user_info_none(self):
        """测试获取不存在的缓存用户信息"""
        # 模拟返回None
        self.mock_redis_client.get.return_value = None
        
        # 调用方法
        result = self.cache_service.get_cached_user_info('test_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    def test_delete_user_info_cache(self):
        """测试删除用户信息缓存"""
        # 模拟删除成功
        self.mock_redis_client.delete.return_value = 1
        
        # 调用方法
        result = self.cache_service.delete_user_info_cache('test_token')
        
        # 验证结果
        self.mock_redis_client.delete.assert_called_once_with('user:info:test_token')
        self.assertTrue(result)
    
    def test_cache_user_permissions(self):
        """测试缓存用户权限"""
        # 测试数据
        access_token = 'test_token'
        permissions = ['read', 'write']
        
        # 调用方法
        result = self.cache_service.cache_user_permissions(access_token, permissions)
        
        # 验证调用
        self.mock_redis_client.setex.assert_called_once_with(
            'user:permissions:test_token',
            7200,
            json.dumps(permissions, ensure_ascii=False)
        )
        self.assertTrue(result)
    
    def test_get_cached_user_permissions(self):
        """测试获取缓存用户权限"""
        # 模拟返回数据
        permissions = ['read', 'write']
        self.mock_redis_client.get.return_value = json.dumps(permissions)
        
        # 调用方法
        result = self.cache_service.get_cached_user_permissions('test_token')
        
        # 验证结果
        self.mock_redis_client.get.assert_called_once_with('user:permissions:test_token')
        self.assertEqual(result, permissions)
    
    def test_get_cached_user_permissions_none(self):
        """测试获取不存在的缓存用户权限"""
        # 模拟返回None
        self.mock_redis_client.get.return_value = None
        
        # 调用方法
        result = self.cache_service.get_cached_user_permissions('test_token')
        
        # 验证结果
        self.assertIsNone(result)
    
    def test_cache_service_singleton(self):
        """测试缓存服务的单例模式"""
        # 清除全局实例
        from users.cache import cache_service
        import users.cache
        users.cache.cache_service = None
        
        # 获取实例两次
        instance1 = get_cache_service()
        instance2 = get_cache_service()
        
        # 验证是同一个实例
        self.assertIs(instance1, instance2)
    
    @patch('redis.Redis')
    def test_exception_handling(self, mock_redis):
        """测试异常处理"""
        # 模拟Redis连接失败
        mock_redis.side_effect = Exception('Connection error')
        
        # 测试创建实例时的异常
        from django.core.exceptions import ImproperlyConfigured
        with self.assertRaises(ImproperlyConfigured):
            RedisCacheService()
        
        # 恢复正常的Mock
        mock_redis.side_effect = None
        mock_redis.return_value = self.mock_redis_client