"""
用户应用URL配置模块
定义用户相关API的URL路径，包括权限验证和管理接口
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    register_user,
    CustomTokenObtainPairView,
    get_user_profile,
    UserViewSet,
    check_permission,
    PermissionGroupViewSet,
    ResourcePermissionViewSet,
    logout_user
)

# 创建路由器实例
router = DefaultRouter()
# 注册用户视图集
router.register(r'users', UserViewSet, basename='user')
# 注册权限组视图集
router.register(r'permission-groups', PermissionGroupViewSet, basename='permission-group')
# 注册资源权限视图集
router.register(r'resource-permissions', ResourcePermissionViewSet, basename='resource-permission')

urlpatterns = [
    # 用户注册
    path('register/', register_user, name='register'),
    
    # 用户登录
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    
    # 刷新令牌
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # 用户登出
    path('logout/', logout_user, name='logout'),
    
    # 获取当前用户信息
    path('profile/', get_user_profile, name='profile'),
    
    # 权限验证接口 - 供其他微服务调用
    path('check-permission/', check_permission, name='check_permission'),
    
    # 包含视图集的路由
    path('', include(router.urls)),
]