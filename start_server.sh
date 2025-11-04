#!/bin/bash
# 企业直播管理系统权限分配模块 - 虚拟环境启动脚本

# 检查是否在虚拟环境中
if [ -z "$VIRTUAL_ENV" ]; then
    echo "请先激活虚拟环境！"
    echo "运行命令: source venv/bin/activate"
    exit 1
fi

echo "企业直播管理系统权限分配模块启动中..."

# 收集静态文件
echo "正在收集静态文件..."
python3 manage.py collectstatic --noinput

# 运行数据库迁移
echo "正在运行数据库迁移..."
python3 manage.py migrate

# 启动开发服务器
echo "正在启动开发服务器..."
python3 manage.py runserver 0.0.0.0:8000