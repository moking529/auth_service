from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
import enum
import secrets
import hashlib


class ResourceType(enum.Enum):
    """
    资源类型枚举
    定义系统中可访问的各类资源
    """
    PRODUCT = '商品'  # 商品
    USER = '用户'  # 用户
    ORDER = '订单'  # 订单
    LIVE = '直播'  # 直播
    SYSTEM = '系统'  # 系统配置
    CONTENT = '内容'  # 内容
    REPORT = '报表'  # 报表
    ROLE = '角色'  # 角色权限


class ActionType(enum.Enum):
    """
    操作类型枚举
    定义对资源可执行的各类操作
    """
    VIEW = '查看'  # 查看
    CREATE = '创建'  # 创建
    UPDATE = '更新'  # 更新
    DELETE = '删除'  # 删除
    IMPORT = '导入'  # 导入
    EXPORT = '导出'  # 导出
    APPROVE = '审批'  # 审批
    REJECT = '拒绝'  # 拒绝


class PermissionGroup(Group):
    """
    权限组模型，扩展Django内置的Group模型
    用于管理角色组及其权限
    """
    description = models.TextField(blank=True, null=True, verbose_name='权限组描述')
    created_at = models.DateTimeField(null=True, verbose_name='创建时间')
    updated_at = models.DateTimeField(null=True, verbose_name='更新时间')
    resource_permissions = models.ManyToManyField(
        'ResourcePermission',
        blank=True,
        related_name='permission_groups',
        help_text='角色组拥有的资源权限'
    )
    
    class Meta:
        verbose_name = '权限组'
        verbose_name_plural = '权限组管理'


class ResourcePermission(Permission):
    """资源权限模型，用于管理细粒度的资源操作权限
    继承自Django的Permission模型，以确保与Django的权限系统兼容
    """
    # 实际使用的资源权限字段
    resource_type = models.CharField(
        max_length=50,
        choices=[(rt.value, rt.name) for rt in ResourceType],
        help_text='资源类型'
    )
    action_type = models.CharField(
        max_length=50,
        choices=[(at.value, at.name) for at in ActionType],
        help_text='操作类型'
    )
    description = models.CharField(max_length=255, blank=True, null=True, help_text='权限描述')
    created_at = models.DateTimeField(null=True, verbose_name='创建时间')
    updated_at = models.DateTimeField(null=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = '资源权限'
        verbose_name_plural = '资源权限'
        unique_together = ('resource_type', 'action_type')
    
    def save(self, *args, **kwargs):
        """保存方法，设置创建和更新时间
        同时确保name和codename基于resource_type和action_type生成
        """
        from django.utils import timezone
        # 生成标准化的codename（使用英文作为内部编码）
        if not self.codename:
            # 获取枚举键名作为英文编码
            resource_key = next((rt.name for rt in ResourceType if rt.value == self.resource_type), self.resource_type)
            action_key = next((at.name for at in ActionType if at.value == self.action_type), self.action_type)
            self.codename = f"{action_key.lower()}_{resource_key.lower()}"
        
        # 生成可读的name（直接使用中文值）
        if not self.name:
            self.name = f"{self.action_type} {self.resource_type}"
        
        # 设置时间
        if not self.id:
            self.created_at = timezone.now()
        self.updated_at = timezone.now()
        
        # 确保content_type被设置（Django Permission模型要求）
        if not hasattr(self, 'content_type_id') or self.content_type_id is None:
            from django.contrib.contenttypes.models import ContentType
            try:
                # 使用self的content_type
                self.content_type = ContentType.objects.get_for_model(self.__class__)
            except (ContentType.DoesNotExist, AttributeError):
                # 如果获取不到，尝试使用用户模型的content_type
                try:
                    from django.contrib.auth.models import User as DjangoUser
                    self.content_type = ContentType.objects.get_for_model(DjangoUser)
                except (ContentType.DoesNotExist, AttributeError):
                    # 如果仍然获取不到，让Django的默认机制处理
                    pass
                
        super().save(*args, **kwargs)
        
    def __str__(self):
        """
        资源权限的字符串表示
        
        Returns:
            str: 资源权限的可读描述
        """
        return f"{self.get_resource_type_display()} - {self.get_action_type_display()}"


class UserManager(BaseUserManager):
    """
    自定义用户管理器，用于创建普通用户和超级用户
    """
    def create_user(self, username, password=None, phone_number=None, role='user', data_permission='own', **extra_fields):
        """
        创建并保存普通用户
        
        Args:
            username: 用户名
            password: 密码
            phone_number: 手机号（可选）
            role: 角色，默认'user'普通用户
            data_permission: 数据权限，默认'own'仅自己创建的数据
            **extra_fields: 额外字段
            
        Returns:
            User: 创建的用户对象
        """
        if not username:
            raise ValueError('用户名必须提供')
        
        # 确保data_permission存在于额外字段中
        if 'data_permission' not in extra_fields:
            extra_fields['data_permission'] = data_permission
        
        user = self.model(username=username, phone_number=phone_number, role=role, **extra_fields)
        user.set_password(password)  # 密码加密存储
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, password=None, **extra_fields):
        """
        创建并保存超级用户
        
        Args:
            username: 用户名
            password: 密码
            **extra_fields: 额外字段
            
        Returns:
            User: 创建的超级用户对象
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        
        return self.create_user(username, password, **extra_fields)


class User(AbstractUser):
    """
    自定义用户模型，扩展Django内置User模型
    集成权限组和细粒度权限支持
    """
    # 用户角色选择
    ROLE_CHOICES = (
        ('user', '普通用户'),
        ('admin', '管理员'),
    )
    
    # 数据权限选择
    DATA_PERMISSION_CHOICES = (
        ('all', '全部数据'),
        ('own', '自己创建的数据'),
    )
    
    # 额外字段
    phone_number = models.CharField(max_length=11, blank=True, null=True, verbose_name='手机号')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user', verbose_name='角色')
    data_permission = models.CharField(max_length=10, choices=DATA_PERMISSION_CHOICES, default='own', verbose_name='数据权限')
    
    # 多对多关系到权限组
    groups = models.ManyToManyField(
        PermissionGroup,
        verbose_name='权限组',
        blank=True,
        help_text='用户所属的权限组',
        related_name='user_set',
        related_query_name='user'
    )
    
    # 额外的多对多关系到权限组
    permission_groups = models.ManyToManyField(
        'PermissionGroup',
        blank=True,
        related_name='users',
        help_text='用户所属的角色组'
    )
    
    # 多对多关系到资源权限
    user_permissions = models.ManyToManyField(
        ResourcePermission,
        verbose_name='用户权限',
        blank=True,
        help_text='用户拥有的具体权限',
        related_name='user_set',
        related_query_name='user'
    )
    
    # 使用自定义管理器
    objects = UserManager()
    
    # 字段元信息
    class Meta:
        verbose_name = '用户'
        verbose_name_plural = '用户管理'
    
    def has_resource_permission(self, resource_type, action_type):
        """
        检查用户是否有特定资源的特定操作权限
        
        Args:
            resource_type: 资源类型
            action_type: 操作类型
            
        Returns:
            bool: 是否有权限
        """
        # 检查用户是否为管理员，管理员拥有所有权限
        if self.role == 'admin':
            return True
            
        # 检查用户直接拥有的资源权限
        if self.user_permissions.filter(
            resource_type=resource_type,
            action_type=action_type
        ).exists():
            return True
            
        # 检查用户所属的权限组是否拥有该权限
        for group in self.permission_groups.all():
            if group.resource_permissions.filter(
                resource_type=resource_type,
                action_type=action_type
            ).exists():
                return True
                
        return False
            
    def get_effective_data_permission(self):
        """
        获取用户的有效数据权限
        管理员始终拥有全部数据权限，不受data_permission字段限制
        
        Returns:
            str: 数据权限类型 ('all' 或 'own')
        """
        if self.role == 'admin':
            return 'all'
        return self.data_permission
    
    def __str__(self):
        """
        用户对象的字符串表示
        
        Returns:
            str: 用户名
        """
        return self.username


class Service(models.Model):
    """
    服务模型，用于服务间认证
    记录微服务的身份信息，支持服务间安全通信
    """
    # 服务名称，唯一标识
    name = models.CharField(
        max_length=100,
        unique=True,
        verbose_name='服务名称',
        help_text='服务的唯一标识符'
    )
    
    # 服务描述
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name='服务描述',
        help_text='服务的详细描述信息'
    )
    
    # 服务密钥哈希值
    # 存储的是密钥的哈希值，而不是密钥本身
    secret_hash = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name='服务密钥哈希',
        help_text='服务密钥的哈希值，用于验证服务身份'
    )
    
    # 服务状态
    is_enabled = models.BooleanField(
        default=True,
        verbose_name='是否启用',
        help_text='控制服务是否可以进行身份认证'
    )
    
    # 创建和更新时间
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='创建时间'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='更新时间'
    )
    
    # 生成的密钥（临时存储，不保存到数据库）
    _generated_secret = None
    
    class Meta:
        verbose_name = '服务'
        verbose_name_plural = '服务管理'
        ordering = ['name']
    
    def generate_secret(self):
        """
        生成新的服务密钥
        
        Returns:
            str: 生成的服务密钥
        """
        # 生成一个随机的服务密钥
        secret = secrets.token_urlsafe(32)
        self._generated_secret = secret
        # 计算密钥的哈希值并存储
        self.secret_hash = self._hash_secret(secret)
        return secret
    
    def _hash_secret(self, secret):
        """
        对服务密钥进行哈希处理
        
        Args:
            secret: 原始服务密钥
            
        Returns:
            str: 密钥的哈希值
        """
        # 使用SHA-256进行哈希，并返回十六进制表示
        return hashlib.sha256(secret.encode()).hexdigest()
    
    def verify_secret(self, secret):
        """
        验证服务密钥是否正确
        
        Args:
            secret: 需要验证的服务密钥
            
        Returns:
            bool: 密钥是否正确
        """
        # 计算提供的密钥的哈希值，并与存储的哈希值比较
        return self.secret_hash == self._hash_secret(secret)
    
    def save(self, *args, **kwargs):
        """
        保存服务信息
        """
        # 如果是新记录且没有设置密钥哈希，生成一个新的密钥
        if not self.pk and not self.secret_hash:
            self.generate_secret()
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        """
        服务对象的字符串表示
        
        Returns:
            str: 服务名称
        """
        return self.name
