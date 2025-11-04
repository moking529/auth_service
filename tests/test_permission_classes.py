"""
权限类测试
直接测试permissions.py中定义的权限类
"""
import sys
from unittest.mock import patch, Mock, MagicMock
from django.test import TestCase, RequestFactory
from django.conf import settings
from users.permissions import (
    IsAdminOrReadOnly,
    IsOwnerOrAdmin,
    ResourcePermission,
    ProductPermission
)
from users.models import User


class IsAdminOrReadOnlyTest(TestCase):
    """IsAdminOrReadOnly权限类测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.permission = IsAdminOrReadOnly()
        self.factory = RequestFactory()
        
        # 创建用户
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123',
            role='admin',
            phone_number='13800138000'
        )
        
        self.normal_user = User.objects.create_user(
            username='user',
            password='user123',
            role='user',
            phone_number='13800138001'
        )
        
        self.superuser = User.objects.create_superuser(
            username='superadmin',
            password='superadmin123',
            phone_number='13800138002'
        )
    
    def test_safe_methods_allowed_for_authenticated_users(self):
        """测试安全方法（GET等）对所有认证用户开放"""
        # GET请求应该被允许
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        with patch('sys.argv', ['manage.py']):  # 非测试模式
            self.assertTrue(self.permission.has_permission(request, Mock()))
    
    def test_admin_can_perform_all_actions(self):
        """测试管理员可以执行所有操作"""
        # DELETE请求应该被管理员允许
        request = self.factory.delete('/test/')
        request.user = self.admin_user
        
        with patch('sys.argv', ['manage.py']):  # 非测试模式
            self.assertTrue(self.permission.has_permission(request, Mock()))
    
    def test_normal_user_cannot_perform_write_actions(self):
        """测试普通用户不能执行写操作"""
        # POST请求不应该被普通用户允许
        request = self.factory.post('/test/')
        request.user = self.normal_user
        
        with patch('sys.argv', ['manage.py']):  # 非测试模式
            self.assertFalse(self.permission.has_permission(request, Mock()))
    
    def test_unauthenticated_user_cannot_access(self):
        """测试未认证用户不能访问"""
        request = self.factory.get('/test/')
        request.user = Mock(is_authenticated=False)
        
        with patch('sys.argv', ['manage.py']):  # 非测试模式
            self.assertFalse(self.permission.has_permission(request, Mock()))
    
    def test_test_environment_allows_authenticated(self):
        """测试测试环境允许所有认证用户"""
        request = self.factory.post('/test/')
        request.user = self.normal_user
        
        with patch('sys.argv', ['manage.py', 'test']):  # 测试模式
            self.assertTrue(self.permission.has_permission(request, Mock()))
    
    @patch('users.permissions.get_cache_service')
    def test_get_cached_permissions_with_token(self, mock_get_cache):
        """测试带token的缓存权限获取"""
        mock_cache_service = Mock()
        mock_cache_service.get_cached_user_permissions.return_value = [{'perm': 'test'}]
        mock_get_cache.return_value = mock_cache_service
        
        # 临时启用缓存设置
        original_setting = getattr(settings, 'CACHE_ENABLED', False)
        setattr(settings, 'CACHE_ENABLED', True)
        
        try:
            request = self.factory.get('/test/')
            request.headers = {'Authorization': 'Bearer test_token'}
            
            # 调用私有方法（这里我们通过has_permission间接调用）
            with patch('sys.argv', ['manage.py']):
                self.permission.has_permission(request, Mock())
                
            mock_cache_service.get_cached_user_permissions.assert_called_with('test_token')
        finally:
            # 恢复原始设置
            setattr(settings, 'CACHE_ENABLED', original_setting)


class IsOwnerOrAdminTest(TestCase):
    """IsOwnerOrAdmin权限类测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.permission = IsOwnerOrAdmin()
        self.factory = RequestFactory()
        
        # 创建用户
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123',
            role='admin',
            phone_number='13800138000'
        )
        
        self.normal_user = User.objects.create_user(
            username='user',
            password='user123',
            role='user',
            phone_number='13800138001'
        )
        
        self.superuser = User.objects.create_superuser(
            username='superadmin',
            password='superadmin123',
            phone_number='13800138002'
        )
    
    def test_superuser_can_access_any_object(self):
        """测试超级用户可以访问任何对象"""
        request = self.factory.get('/test/')
        request.user = self.superuser
        
        # 创建一个模拟对象
        obj = Mock()
        obj.id = 999
        
        # 使用更简单的视图对象
        view = object()
        
        self.assertTrue(self.permission.has_object_permission(request, view, obj))
    
    def test_admin_can_access_any_object(self):
        """测试管理员可以访问任何对象"""
        request = self.factory.get('/test/')
        request.user = self.admin_user
        
        # 创建一个模拟对象
        obj = Mock()
        obj.id = 999
        
        self.assertTrue(self.permission.has_object_permission(request, Mock(), obj))
    
    def test_user_can_access_own_object(self):
        """测试用户可以访问自己的对象"""
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        # 创建一个模拟对象，ID与用户ID相同
        obj = Mock()
        obj.id = self.normal_user.id
        
        self.assertTrue(self.permission.has_object_permission(request, Mock(), obj))
    
    def test_user_cannot_access_other_objects(self):
        """测试用户不能访问其他用户的对象"""
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        # 创建一个模拟对象，ID与用户ID不同
        obj = Mock()
        obj.id = self.admin_user.id  # 另一个用户的ID
        
        # 使用简单对象作为视图
        view = object()
        
        # 模拟用户没有view权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=False):
            self.assertFalse(self.permission.has_object_permission(request, view, obj))
    
    def test_user_with_permission_can_access_own_object(self):
        """测试拥有权限的用户可以访问自己的对象"""
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        # 创建一个模拟对象
        obj = Mock()
        obj.id = self.normal_user.id
        
        # 使用简单对象作为视图
        view = object()
        
        # 模拟用户有view权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=True):
            self.assertTrue(self.permission.has_object_permission(request, view, obj))


class ResourcePermissionTest(TestCase):
    """ResourcePermission权限类测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.factory = RequestFactory()
        
        # 创建用户
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123',
            role='admin',
            phone_number='13800138000'
        )
        
        self.normal_user = User.objects.create_user(
            username='user',
            password='user123',
            role='user',
            phone_number='13800138001'
        )
        
        self.superuser = User.objects.create_superuser(
            username='superadmin',
            password='superadmin123',
            phone_number='13800138002'
        )
    
    def test_superuser_has_all_permissions(self):
        """测试超级用户拥有所有权限"""
        permission = ResourcePermission(resource_type='product', action_type='delete')
        request = self.factory.delete('/test/')
        request.user = self.superuser
        
        # 使用简单对象作为视图
        view = object()
        
        self.assertTrue(permission.has_permission(request, view))
    
    def test_admin_has_all_permissions(self):
        """测试管理员拥有所有权限"""
        permission = ResourcePermission(resource_type='product', action_type='delete')
        request = self.factory.delete('/test/')
        request.user = self.admin_user
        
        # 使用简单对象作为视图
        view = object()
        
        self.assertTrue(permission.has_permission(request, view))
    
    def test_normal_user_with_permission(self):
        """测试有特定权限的普通用户"""
        permission = ResourcePermission(resource_type='product', action_type='view')
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        # 使用简单对象作为视图
        view = object()
        
        # 模拟用户有view权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=True):
            self.assertTrue(permission.has_permission(request, view))
    
    def test_normal_user_without_permission(self):
        """测试没有特定权限的普通用户"""
        permission = ResourcePermission(resource_type='product', action_type='delete')
        request = self.factory.delete('/test/')
        request.user = self.normal_user
        
        # 使用简单对象作为视图
        view = object()
        
        # 模拟用户没有delete权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=False):
            self.assertFalse(permission.has_permission(request, view))
    
    def test_unauthenticated_user(self):
        """测试未认证用户"""
        permission = ResourcePermission(resource_type='product', action_type='view')
        request = self.factory.get('/test/')
        request.user = Mock(is_authenticated=False)
        
        # 使用简单对象作为视图
        view = object()
        
        self.assertFalse(permission.has_permission(request, view))
    
    def test_missing_resource_or_action_type(self):
        """测试缺少资源类型或操作类型"""
        # 缺少资源类型
        permission1 = ResourcePermission(action_type='view', resource_type=None)
        request = self.factory.get('/test/')
        request.user = self.normal_user
        
        # 创建一个视图
        view = Mock()
        
        self.assertFalse(permission1.has_permission(request, view))
    
    @patch('users.permissions.get_cache_service')
    def test_cached_permissions(self, mock_get_cache):
        """测试使用缓存的权限"""
        # 设置模拟缓存服务
        mock_cache_service = Mock()
        mock_cache_service.get_cached_user_permissions.return_value = [
            {'resource_type': 'product', 'action': 'view'}
        ]
        mock_get_cache.return_value = mock_cache_service
        
        # 临时启用缓存设置
        original_setting = getattr(settings, 'CACHE_ENABLED', False)
        setattr(settings, 'CACHE_ENABLED', True)
        
        try:
            permission = ResourcePermission(resource_type='product', action_type='view')
            request = self.factory.get('/test/')
            request.user = self.normal_user
            request.headers = {'Authorization': 'Bearer test_token'}
            
            # 使用简单对象作为视图
            view = object()
            
            # 应该从缓存获取权限
            result = permission.has_permission(request, view)
            self.assertTrue(result)
            mock_cache_service.get_cached_user_permissions.assert_called_with('test_token')
        finally:
            # 恢复原始设置
            setattr(settings, 'CACHE_ENABLED', original_setting)
    
    def test_get_action_type(self):
        """测试_get_action_type方法"""
        permission = ResourcePermission()
        
        # 测试各种HTTP方法对应的操作类型
        self.assertEqual(permission._get_action_type('GET'), 'view')
        self.assertEqual(permission._get_action_type('POST'), 'create')
        self.assertEqual(permission._get_action_type('PUT'), 'update')
        self.assertEqual(permission._get_action_type('PATCH'), 'update')
        self.assertEqual(permission._get_action_type('DELETE'), 'delete')
        # 默认返回'view'
        self.assertEqual(permission._get_action_type('HEAD'), 'view')


class ProductPermissionTest(TestCase):
    """ProductPermission权限类测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.factory = RequestFactory()
        
        # 创建用户
        self.normal_user = User.objects.create_user(
            username='user',
            password='user123',
            role='user',
            phone_number='13800138001'
        )
    
    def test_product_permission_initialization(self):
        """测试ProductPermission初始化"""
        # 测试带操作类型的初始化
        permission1 = ProductPermission(action_type='view')
        self.assertEqual(permission1.resource_type, 'product')
        self.assertEqual(permission1.action_type, 'view')
        
        # 测试不带操作类型的初始化
        permission2 = ProductPermission()
        self.assertEqual(permission2.resource_type, 'product')
        self.assertIsNone(permission2.action_type)
    
    def test_product_permission_check(self):
        """测试ProductPermission权限检查"""
        permission = ProductPermission(action_type='view')
        request = self.factory.get('/products/1/')
        request.user = self.normal_user
        
        # 使用简单对象作为视图
        view = object()
        
        # 模拟用户有product:view权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=True):
            self.assertTrue(permission.has_permission(request, view))
        
        # 模拟用户没有product:view权限
        with patch.object(self.normal_user, 'has_resource_permission', return_value=False):
            self.assertFalse(permission.has_permission(request, view))