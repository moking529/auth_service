@echo off
REM 企业直播管理系统权限分配模块 - 虚拟环境启动脚本

REM 检查是否在虚拟环境中
if not defined VIRTUAL_ENV (
    echo 请先激活虚拟环境！
    echo 运行命令: venv\Scripts\activate
    pause
    exit /b 1
)

echo 企业直播管理系统权限分配模块启动中...

REM 收集静态文件
echo 正在收集静态文件...
python manage.py collectstatic --noinput

REM 运行数据库迁移
echo 正在运行数据库迁移...
python manage.py migrate

REM 启动开发服务器
echo 正在启动开发服务器...
python manage.py runserver 0.0.0.0:8000

pause