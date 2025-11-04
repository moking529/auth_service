"""
URL configuration for auth_service project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include

# 根路径欢迎视图
def welcome_view(request):
    """
    系统欢迎页面
    返回系统信息和API文档链接
    """
    return JsonResponse({
        'message': '欢迎使用企业直播管理系统权限分配服务',
        'version': '1.0.0',
        'api_docs': '/api/',
        'admin_panel': '/admin/',
        'status': 'running'
    })

urlpatterns = [
    # 根路径
    path('', welcome_view, name='welcome'),
    
    # Django管理后台
    path('admin/', admin.site.urls),
    
    # 用户认证和授权API
    path('api/', include('users.urls')),
]
