"""
用户序列化器模块
用于处理用户数据的序列化和反序列化，以及权限管理
"""
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, PermissionGroup, ResourcePermission, ResourceType, ActionType


class UserSerializer(serializers.ModelSerializer):
    """
    用户序列化器
    用于用户信息的序列化和反序列化
    """
    # 添加权限组字段
    permission_groups = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=PermissionGroup.objects.all(),
        required=False
    )
    
    # 添加数据权限字段
    data_permission = serializers.ChoiceField(
        choices=User.DATA_PERMISSION_CHOICES,
        required=False,
        default='own'
    )
    
    class Meta:
        model = User
        # 定义需要序列化/反序列化的字段
        fields = ['id', 'username', 'email', 'phone_number', 'role', 'is_active', 'permission_groups', 'data_permission']
        # 只读字段
        read_only_fields = ['id', 'is_active']
    
    def create(self, validated_data):
        """
        创建用户时处理权限组关联和数据权限
        
        Args:
            validated_data: 验证通过的数据
            
        Returns:
            User: 创建的用户实例
        """
        permission_groups = validated_data.pop('permission_groups', [])
        # 从validated_data中获取data_permission（如果提供）
        # create_user方法会处理data_permission字段
        user = User.objects.create_user(**validated_data)
        user.permission_groups.set(permission_groups)
        return user
    
    def update(self, instance, validated_data):
        """
        更新用户时处理权限组关联和数据权限
        
        Args:
            instance: 要更新的用户实例
            validated_data: 验证通过的数据
            
        Returns:
            User: 更新后的用户实例
        """
        permission_groups = validated_data.pop('permission_groups', None)
        # 从validated_data中获取data_permission（如果提供）
        # 注意：不需要单独处理data_permission，因为super().update会自动处理所有其他字段
        
        user = super().update(instance, validated_data)
        
        # 如果提供了权限组，则更新
        if permission_groups is not None:
            user.permission_groups.set(permission_groups)
            
        return user


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    用户注册序列化器
    用于用户注册时的数据验证和处理
    """
    # 密码字段不返回
    password = serializers.CharField(write_only=True, required=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['username', 'password', 'confirm_password', 'email', 'phone_number', 'role']
        # 角色默认为普通用户，可选管理员
        extra_kwargs = {
            'role': {'default': 'user', 'required': False}
        }
    
    def validate(self, attrs):
        """
        验证密码是否一致
        
        Args:
            attrs: 输入的字段数据
            
        Returns:
            dict: 验证通过的数据
            
        Raises:
            serializers.ValidationError: 密码不一致时抛出错误
        """
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("密码和确认密码不一致")
        return attrs
    
    def create(self, validated_data):
        """
        创建新用户
        
        Args:
            validated_data: 验证通过的数据
            
        Returns:
            User: 创建的用户对象
        """
        # 移除confirm_password字段
        validated_data.pop('confirm_password')
        # 创建用户（密码会在UserManager中自动加密）
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    用户登录序列化器
    用于用户登录时的验证和令牌生成
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, attrs):
        """
        验证用户凭据
        
        Args:
            attrs: 包含username和password的字典
            
        Returns:
            dict: 验证通过的用户信息
            
        Raises:
            serializers.ValidationError: 认证失败时抛出错误
        """
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # 尝试认证用户
            user = authenticate(username=username, password=password)
            
            if user:
                # 检查用户是否激活
                if user.is_active:
                    attrs['user'] = user
                    return attrs
                else:
                    raise serializers.ValidationError('用户账号已被禁用')
            else:
                raise serializers.ValidationError('用户名或密码错误')
        else:
            raise serializers.ValidationError('必须提供用户名和密码')
    
    def create(self, validated_data):
        """
        生成JWT令牌
        
        Args:
            validated_data: 包含认证用户的验证数据
            
        Returns:
            dict: 包含用户信息和令牌的数据
        """
        user = validated_data['user']
        refresh = RefreshToken.for_user(user)
        
        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'phone_number': user.phone_number,
                'role': user.role,
                'is_active': user.is_active
            },
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class UserProfileSerializer(serializers.ModelSerializer):
    """
    用户个人信息序列化器
    用于获取当前登录用户的详细信息
    """
    # 展示用户所属的权限组
    permission_groups = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name'
    )
    
    # 添加数据权限字段
    data_permission = serializers.CharField(read_only=True)
    
    # 添加有效数据权限字段（考虑管理员权限）
    effective_data_permission = serializers.SerializerMethodField()
    
    def get_effective_data_permission(self, obj):
        """
        获取用户的有效数据权限
        
        Args:
            obj: User对象
            
        Returns:
            str: 有效数据权限
        """
        return obj.get_effective_data_permission()
    
    # 获取数据权限的中文描述
    data_permission_display = serializers.SerializerMethodField()
    
    def get_data_permission_display(self, obj):
        """
        获取数据权限的中文描述
        
        Args:
            obj: User对象
            
        Returns:
            str: 数据权限的中文描述
        """
        return dict(User.DATA_PERMISSION_CHOICES).get(obj.data_permission, obj.data_permission)
    
    # 获取有效数据权限的中文描述
    effective_data_permission_display = serializers.SerializerMethodField()
    
    def get_effective_data_permission_display(self, obj):
        """
        获取有效数据权限的中文描述
        
        Args:
            obj: User对象
            
        Returns:
            str: 有效数据权限的中文描述
        """
        effective_perm = obj.get_effective_data_permission()
        return dict(User.DATA_PERMISSION_CHOICES).get(effective_perm, effective_perm)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'phone_number', 'role', 'date_joined', 'last_login', 
            'permission_groups', 'data_permission', 'data_permission_display',
            'effective_data_permission', 'effective_data_permission_display'
        ]
        read_only_fields = [
            'id', 'username', 'role', 'date_joined', 'last_login',
            'permission_groups', 'data_permission', 'effective_data_permission'
        ]


class ResourcePermissionSerializer(serializers.ModelSerializer):
    """
    资源权限序列化器
    用于管理"资源+操作"类型的权限
    """
    # 使用枚举值的选择器
    resource_type = serializers.ChoiceField(
        choices=[(rt.value, rt.value) for rt in ResourceType]
    )
    action_type = serializers.ChoiceField(
        choices=[(at.value, at.value) for at in ActionType]
    )
    
    class Meta:
        model = ResourcePermission
        fields = ['id', 'name', 'description', 'resource_type', 'action_type', 'created_at']
        read_only_fields = ['created_at']
    
    def validate(self, attrs):
        """
        验证资源权限的唯一性
        """
        # 检查是否已存在相同的资源权限
        existing = ResourcePermission.objects.filter(
            resource_type=attrs['resource_type'],
            action_type=attrs['action_type']
        ).exists()
        
        if existing:
            raise serializers.ValidationError({
                'error': f'资源权限 {attrs["resource_type"]}-{attrs["action_type"]} 已存在'
            })
        
        return attrs


class PermissionGroupSerializer(serializers.ModelSerializer):
    """
    权限组序列化器
    用于管理角色组及其关联的资源权限
    """
    # 资源权限的嵌套序列化
    resource_permissions = ResourcePermissionSerializer(many=True, read_only=True)
    # 用于创建/更新时的权限分配
    resource_permission_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ResourcePermission.objects.all(),
        source='resource_permissions',
        write_only=True,
        required=False
    )
    
    class Meta:
        model = PermissionGroup
        fields = ['id', 'name', 'description', 'resource_permissions', 
                 'resource_permission_ids', 'created_at']
        read_only_fields = ['created_at']
    
    def create(self, validated_data):
        """
        创建权限组并关联资源权限
        """
        # 创建权限组
        group = PermissionGroup.objects.create(
            name=validated_data['name'],
            description=validated_data.get('description', '')
        )
        
        # 设置资源权限
        if 'resource_permissions' in validated_data:
            group.resource_permissions.set(validated_data['resource_permissions'])
        
        return group
    
    def update(self, instance, validated_data):
        """
        更新权限组信息
        """
        # 更新基本信息
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        
        # 更新资源权限关联
        if 'resource_permissions' in validated_data:
            instance.resource_permissions.set(validated_data['resource_permissions'])
        
        return instance


class CheckPermissionSerializer(serializers.Serializer):
    """
    权限验证请求序列化器
    用于验证权限检查请求的数据格式
    """
    resource_type = serializers.CharField(required=True)
    action_type = serializers.CharField(required=True)
    
    def validate_resource_type(self, value):
        """
        验证资源类型是否有效
        """
        valid_types = [rt.value for rt in ResourceType]
        if value not in valid_types:
            raise serializers.ValidationError(f'无效的资源类型，有效类型为: {valid_types}')
        return value
    
    def validate_action_type(self, value):
        """
        验证操作类型是否有效
        """
        valid_actions = [at.value for at in ActionType]
        if value not in valid_actions:
            raise serializers.ValidationError(f'无效的操作类型，有效类型为: {valid_actions}')
        return value