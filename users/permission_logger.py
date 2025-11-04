#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
权限验证日志模块

用于记录系统中的权限验证请求，包括服务名、用户名、权限名称、验证结果、请求时间和IP地址等信息。
日志按日期分割，每天生成一个日志文件，保存在项目的logs文件夹中。
"""

import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from django.conf import settings


class PermissionLogger:
    """
    权限验证日志记录器
    
    提供统一的权限验证日志记录接口，支持按日期分割日志文件。
    """
    
    def __init__(self):
        """
        初始化权限日志记录器
        """
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """
        配置日志记录器
        
        Returns:
            logging.Logger: 配置好的日志记录器实例
        """
        # 日志文件名格式：permissions_YYYY-MM-DD.log
        log_filename = os.path.join(settings.BASE_DIR, 'logs', 'permissions.log')
        
        # 创建日志记录器
        logger = logging.getLogger('permission_logger')
        logger.setLevel(logging.INFO)
        
        # 检查是否已经添加过处理器，避免重复添加
        if not logger.handlers:
            # 创建TimedRotatingFileHandler，按天分割日志
            handler = TimedRotatingFileHandler(
                log_filename,
                when='midnight',  # 在午夜切换到新日志文件
                interval=1,       # 每1天切换一次
                backupCount=30,   # 保留30天的日志
                encoding='utf-8'  # 使用UTF-8编码
            )
            
            # 设置日志格式
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - [服务:%(service)s] - [用户:%(username)s] - [权限:%(permission)s] - [结果:%(result)s] - [IP:%(ip)s] - [详情:%(details)s]'
            )
            handler.setFormatter(formatter)
            
            # 添加处理器到记录器
            logger.addHandler(handler)
        
        return logger
    
    def log_permission_check(self, request, permission_name, result, service_name='auth_service', details=None):
        """
        记录权限验证请求
        
        Args:
            request: HTTP请求对象，用于获取用户信息和IP地址
            permission_name: 权限名称
            result: 验证结果，True表示通过，False表示拒绝
            service_name: 服务名称，默认为'auth_service'
            details: 额外的详情信息（可选）
        """
        # 获取用户名，如果用户未认证则为'AnonymousUser'
        username = 'AnonymousUser'
        if hasattr(request, 'user') and request.user.is_authenticated:
            username = request.user.username
        
        # 获取IP地址
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        
        # 记录日志
        self.logger.info(
            '',
            extra={
                'service': service_name,
                'username': username,
                'permission': permission_name,
                'result': 'ALLOWED' if result else 'DENIED',
                'ip': ip,
                'details': details or ''
            }
        )


# 创建全局权限日志记录器实例
permission_logger = PermissionLogger()


def log_permission(request, permission_name, result, service_name='auth_service', details=None):
    """
    记录权限验证的便捷函数
    
    Args:
        request: HTTP请求对象
        permission_name: 权限名称
        result: 验证结果
        service_name: 服务名称
        details: 额外详情
    """
    permission_logger.log_permission_check(request, permission_name, result, service_name, details)