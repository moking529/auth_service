from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group as DjangoGroup
from django.db.models import Count
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.contrib import messages

from .models import User, PermissionGroup, ResourcePermission, ResourceType, ActionType, Service


class ResourcePermissionInline(admin.TabularInline):
    """
    权限组中内嵌的资源权限管理表格
    用于在权限组编辑页面直接管理该组的权限
    """
    model = PermissionGroup.resource_permissions.through
    extra = 1
    verbose_name = '资源权限'
    verbose_name_plural = '资源权限列表'
    raw_id_fields = ('resourcepermission',)
    autocomplete_fields = ('resourcepermission',)


@admin.register(ResourcePermission)
class ResourcePermissionAdmin(admin.ModelAdmin):
    """
    资源权限管理界面
    提供资源权限的CRUD操作，支持按资源类型和操作类型筛选
    """
    list_display = ('name', 'resource_type_display', 'action_type_display', 'description', 'created_at')
    search_fields = ('name', 'resource_type', 'action_type', 'description')
    list_filter = ('resource_type', 'action_type')
    ordering = ('resource_type', 'action_type')
    list_per_page = 20
    save_as = True  # 允许保存为新记录
    
    # 字段集配置
    fieldsets = (
        (_('权限基本信息'), {
            'fields': ('resource_type', 'action_type', 'description')
        }),
        (_('系统信息'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),  # 默认折叠
        }),
    )
    
    # 只读字段
    readonly_fields = ('created_at', 'updated_at', 'name', 'codename', 'content_type')
    
    def resource_type_display(self, obj):
        """
        显示资源类型的中文名称
        """
        return obj.resource_type
    resource_type_display.short_description = _('资源类型')
    resource_type_display.admin_order_field = 'resource_type'
    
    def action_type_display(self, obj):
        """
        显示操作类型的中文名称
        """
        return obj.action_type
    action_type_display.short_description = _('操作类型')
    action_type_display.admin_order_field = 'action_type'


@admin.register(PermissionGroup)
class PermissionGroupAdmin(admin.ModelAdmin):
    """
    权限组管理界面
    显示权限组信息，并支持内嵌管理资源权限
    """
    # 排除多对多字段，因为使用了内联表单
    exclude = ('resource_permissions',)
    
    # 内联表单
    inlines = [ResourcePermissionInline]
    
    # 列表显示
    list_display = ('name', 'description', 'user_count', 'permission_count', 'created_at')
    search_fields = ('name', 'description')
    list_per_page = 20
    ordering = ('name',)
    
    # 编辑页面字段配置
    fieldsets = (
        (_('基本信息'), {
            'fields': ('name', 'description')
        }),
        (_('系统信息'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )
    
    # 只读字段
    readonly_fields = ('created_at', 'updated_at')
    
    # 重写get_queryset以添加聚合信息
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(
            _user_count=Count('users', distinct=True),
            _permission_count=Count('resource_permissions', distinct=True)
        )
    
    def user_count(self, obj):
        """
        显示权限组中的用户数量
        """
        return getattr(obj, '_user_count', obj.users.count())
    user_count.short_description = _('用户数量')
    user_count.admin_order_field = '_user_count'
    
    def permission_count(self, obj):
        """
        显示权限组拥有的权限数量
        """
        return getattr(obj, '_permission_count', obj.resource_permissions.count())
    permission_count.short_description = _('权限数量')
    permission_count.admin_order_field = '_permission_count'
    
    # 提供查看权限组用户的快捷方式
    def view_users(self, obj):
        """
        提供查看属于该权限组的用户列表的链接
        """
        url = f"/admin/users/user/?permission_groups__id={obj.id}"
        return format_html('<a href="{0}">查看用户</a>', url)
    view_users.short_description = _('查看用户')


class PermissionGroupInline(admin.TabularInline):
    """
    用户编辑页面中内嵌的权限组管理表格
    """
    model = User.permission_groups.through
    extra = 1
    verbose_name = '权限组'
    verbose_name_plural = '权限组列表'
    raw_id_fields = ('permissiongroup',)
    autocomplete_fields = ('permissiongroup',)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    自定义用户管理界面
    支持查看和编辑用户信息，分配权限组
    """
    # 添加内联表单
    inlines = [PermissionGroupInline]
    
    # 排除多对多字段，因为使用了内联表单
    exclude = ('groups', 'permission_groups')
    
    # 列表显示
    list_display = (
        'username', 'email', 'phone_number', 'role', 'data_permission_display', 'is_active', 
        'is_staff', 'is_superuser', 'group_count', 'date_joined'
    )
    
    # 搜索字段
    search_fields = ('username', 'email', 'phone_number', 'first_name', 'last_name')
    
    # 过滤条件
    list_filter = ('role', 'is_active', 'is_staff', 'is_superuser', 'date_joined')
    
    # 分页
    list_per_page = 20
    
    # 编辑页面字段集
    fieldsets = (
        (_('基本信息'), {
            'fields': ('username', 'password', 'first_name', 'last_name', 'email', 'phone_number', 'role', 'data_permission')
        }),
        (_('权限'), {
            'fields': ('is_active', 'is_staff', 'is_superuser'),
            'classes': ('collapse',),
        }),
        (_('重要日期'), {
            'fields': ('last_login', 'date_joined'),
            'classes': ('collapse',),
        }),
    )
    
    # 添加页面字段集
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'role', 'data_permission', 'is_active'),
        }),
    )
    
    # 只读字段
    readonly_fields = ('last_login', 'date_joined')
    
    # 重写get_queryset以添加聚合信息
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(_group_count=Count('permission_groups', distinct=True))
    
    def group_count(self, obj):
        """
        显示用户所属的权限组数量
        """
        return getattr(obj, '_group_count', obj.permission_groups.count())
    group_count.short_description = _('权限组数量')
    group_count.admin_order_field = '_group_count'
    
    # 提供查看用户权限的快捷方式
    def view_permissions(self, obj):
        """
        提供查看用户所有权限的链接
        """
        url = f"/admin/users/resourcepermission/?user_set__id={obj.id}"
        return format_html('<a href="{0}">查看权限</a>', url)
    view_permissions.short_description = _('查看权限')
    
    def data_permission_display(self, obj):
        """
        显示数据权限的中文名称
        """
        return dict(obj.DATA_PERMISSION_CHOICES).get(obj.data_permission, obj.data_permission)
    data_permission_display.short_description = _('数据权限')
    data_permission_display.admin_order_field = 'data_permission'


# 取消默认的Group注册，避免冲突
if admin.site.is_registered(DjangoGroup):
    admin.site.unregister(DjangoGroup)


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    """
    服务管理界面
    用于管理微服务身份认证信息
    """
    # 列表显示字段
    list_display = ('name', 'description', 'is_enabled', 'created_at', 'updated_at')
    
    # 搜索字段
    search_fields = ('name', 'description')
    
    # 过滤条件
    list_filter = ('is_enabled', 'created_at')
    
    # 分页
    list_per_page = 20
    
    # 编辑页面字段集
    fieldsets = (
        (_('基本信息'), {
            'fields': ('name', 'description', 'is_enabled')
        }),
        (_('密钥管理'), {
            'fields': ('_generate_new_secret',),
            'description': _('点击按钮生成新的服务密钥，密钥只会显示一次，请妥善保存！'),
        }),
        (_('系统信息'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )
    
    # 只读字段
    readonly_fields = ('created_at', 'updated_at', '_generate_new_secret')
    
    # 排除字段（不显示在表单中）
    exclude = ('secret_hash',)
    
    def _generate_new_secret(self, obj):
        """
        生成新密钥的按钮
        """
        return format_html(
            '<button type="button" class="button" onclick="document.getElementById(\'generate_secret\').value=\'true\';">生成新密钥</button>'
        )
    _generate_new_secret.short_description = _('生成新密钥')
    
    def save_model(self, request, obj, form, change):
        """
        保存模型时处理密钥生成
        """
        # 检查是否需要生成新密钥
        if request.POST.get('generate_secret') == 'true':
            # 生成新密钥
            secret = obj.generate_secret()
            # 显示成功消息，包含生成的密钥
            messages.success(
                request,
                _(f'服务密钥已生成：{secret}。请妥善保存此密钥，它只会显示一次！')
            )
        
        # 保存对象
        super().save_model(request, obj, form, change)
    
    def get_form(self, request, obj=None, **kwargs):
        """
        自定义表单，添加隐藏字段用于密钥生成
        """
        form = super().get_form(request, obj, **kwargs)
        # 添加隐藏字段用于标记生成密钥
        self.save_on_top = True  # 在顶部显示保存按钮
        return form
    
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        """
        渲染变更表单时添加隐藏字段
        """
        # 添加隐藏字段到上下文
        context.update({
            'media': context.get('media') + format_html('<input type="hidden" id="generate_secret" name="generate_secret" value="false">'),
        })
        return super().render_change_form(request, context, add, change, form_url, obj)
    
    def response_add(self, request, obj, post_url_continue=None):
        """
        添加新对象后的响应处理
        """
        # 如果是新创建的服务，显示生成的密钥
        if obj._generated_secret:
            messages.success(
                request,
                _(f'服务已创建成功！服务密钥：{obj._generated_secret}。请妥善保存此密钥，它只会显示一次！')
            )
        return super().response_add(request, obj, post_url_continue)
