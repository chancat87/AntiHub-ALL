#!/bin/bash
# AntiHub-ALL 一键部署脚本
# 适用于 Linux 系统

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_prompt() {
    echo -e "${BLUE}[INPUT]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 未安装，请先安装 $1"
        exit 1
    fi
}

# 生成随机密钥
generate_random_key() {
    if command -v openssl &> /dev/null; then
        openssl rand -hex 32
        return
    fi

    # 仅装了 Docker 的环境：用容器生成随机值，避免依赖宿主机 openssl
    docker run --rm python:3.11-alpine python -c "import secrets; print(secrets.token_hex(32))"
}

# 生成 Fernet 密钥（用于 PLUGIN_API_ENCRYPTION_KEY）
generate_fernet_key() {
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
    docker run --rm python:3.11-alpine python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
}

# 读取用户输入（带默认值）
read_with_default() {
    local prompt="$1"
    local default="$2"
    local value

    read -p "$prompt [$default]: " value
    echo "${value:-$default}"
}

# 读取密码（不显示输入）
read_password() {
    local prompt="$1"
    local password
    local password_confirm

    while true; do
        read -s -p "$prompt: " password
        echo
        read -s -p "确认密码: " password_confirm
        echo

        if [ "$password" = "$password_confirm" ]; then
            if [ -z "$password" ]; then
                log_error "密码不能为空"
                continue
            fi
            echo "$password"
            break
        else
            log_error "两次密码输入不一致，请重新输入"
        fi
    done
}

# 主函数
main() {
    log_info "开始部署 AntiHub-ALL..."
    echo ""

    # 1. 检查依赖
    log_info "检查系统依赖..."
    check_command docker
    if ! command -v openssl &> /dev/null; then
        log_warn "openssl 未安装，将用 Docker 生成随机密钥（可能会额外拉取 python:3.11-alpine 镜像）"
    fi

    # 检测 docker compose 命令（优先使用新版本）
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
    else
        log_error "docker-compose 或 docker compose 未安装"
        exit 1
    fi
    log_info "使用命令: $DOCKER_COMPOSE"

    # 检查 Docker 是否运行
    if ! docker info &> /dev/null; then
        log_error "Docker 未运行，请先启动 Docker 服务"
        exit 1
    fi

    # 2. 检查 .env 文件
    if [ -f .env ]; then
        log_warn ".env 文件已存在"
        read -p "是否覆盖现有配置？(y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "保留现有配置，跳过环境变量生成"
            ENV_EXISTS=true
        else
            ENV_EXISTS=false
        fi
    else
        ENV_EXISTS=false
    fi

    # 3. 生成环境变量配置
    if [ "$ENV_EXISTS" = false ]; then
        log_info "开始配置部署参数..."
        echo ""

        if [ ! -f .env.example ]; then
            log_error ".env.example 文件不存在"
            exit 1
        fi

        cp .env.example .env

        # 3.1 配置端口
        log_info "=== 端口配置 ==="
        log_prompt "配置服务端口（直接回车使用默认值）"
        echo ""

        WEB_PORT=$(read_with_default "Web 前端端口（对外暴露）" "3000")
        BACKEND_PORT=$(read_with_default "Backend 后端端口（仅本地）" "8000")
        POSTGRES_PORT=$(read_with_default "PostgreSQL 数据库端口（仅本地）" "5432")

        echo ""
        log_info "端口配置完成："
        echo "  Web: $WEB_PORT (0.0.0.0:$WEB_PORT)"
        echo "  Backend: $BACKEND_PORT (127.0.0.1:$BACKEND_PORT)"
        echo "  PostgreSQL: $POSTGRES_PORT (127.0.0.1:$POSTGRES_PORT)"
        echo ""

        # 3.2 配置管理员账户
        log_info "=== 管理员账户配置 ==="
        ADMIN_USERNAME=$(read_with_default "管理员用户名" "admin")
        log_prompt "设置管理员密码"
        ADMIN_PASSWORD=$(read_password "管理员密码")
        echo ""
        log_info "管理员账户配置完成"
        echo ""

        # 3.3 生成密钥
        log_info "生成安全密钥..."
        JWT_SECRET=$(generate_random_key)
        ADMIN_API_KEY="sk-admin-$(generate_random_key | cut -c1-32)"
        POSTGRES_PASSWORD=$(generate_random_key | cut -c1-24)
        PLUGIN_DB_PASSWORD=$(generate_random_key | cut -c1-24)

        log_info "生成 Fernet 加密密钥..."
        ENCRYPTION_KEY=$(generate_fernet_key)

        # 3.4 替换 .env 中的占位符（兼容 Linux 和 macOS）
        log_info "写入配置文件..."

        if sed --version 2>&1 | grep -q GNU; then
            # GNU sed (Linux)
            sed -i "s|^WEB_PORT=.*|WEB_PORT=${WEB_PORT}|g" .env
            sed -i "s|^BACKEND_PORT=.*|BACKEND_PORT=${BACKEND_PORT}|g" .env
            sed -i "s|^# POSTGRES_PORT=.*|POSTGRES_PORT=${POSTGRES_PORT}|g" .env
            sed -i "s|^ADMIN_USERNAME=.*|ADMIN_USERNAME=${ADMIN_USERNAME}|g" .env
            sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PASSWORD}|g" .env
            sed -i "s|JWT_SECRET_KEY=please-change-me|JWT_SECRET_KEY=${JWT_SECRET}|g" .env
            sed -i "s|PLUGIN_ADMIN_API_KEY=sk-admin-please-change-me|PLUGIN_ADMIN_API_KEY=${ADMIN_API_KEY}|g" .env
            sed -i "s|POSTGRES_PASSWORD=please-change-me|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|g" .env
            sed -i "s|PLUGIN_DB_PASSWORD=please-change-me|PLUGIN_DB_PASSWORD=${PLUGIN_DB_PASSWORD}|g" .env
            sed -i "s|PLUGIN_API_ENCRYPTION_KEY=please-generate-a-valid-fernet-key|PLUGIN_API_ENCRYPTION_KEY=${ENCRYPTION_KEY}|g" .env
            sed -i "s|postgresql+asyncpg://antihub:please-change-me@postgres:5432/antihub|postgresql+asyncpg://antihub:${POSTGRES_PASSWORD}@postgres:5432/antihub|g" .env
        else
            # BSD sed (macOS)
            sed -i '' "s|^WEB_PORT=.*|WEB_PORT=${WEB_PORT}|g" .env
            sed -i '' "s|^BACKEND_PORT=.*|BACKEND_PORT=${BACKEND_PORT}|g" .env
            sed -i '' "s|^# POSTGRES_PORT=.*|POSTGRES_PORT=${POSTGRES_PORT}|g" .env
            sed -i '' "s|^ADMIN_USERNAME=.*|ADMIN_USERNAME=${ADMIN_USERNAME}|g" .env
            sed -i '' "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PASSWORD}|g" .env
            sed -i '' "s|JWT_SECRET_KEY=please-change-me|JWT_SECRET_KEY=${JWT_SECRET}|g" .env
            sed -i '' "s|PLUGIN_ADMIN_API_KEY=sk-admin-please-change-me|PLUGIN_ADMIN_API_KEY=${ADMIN_API_KEY}|g" .env
            sed -i '' "s|POSTGRES_PASSWORD=please-change-me|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|g" .env
            sed -i '' "s|PLUGIN_DB_PASSWORD=please-change-me|PLUGIN_DB_PASSWORD=${PLUGIN_DB_PASSWORD}|g" .env
            sed -i '' "s|PLUGIN_API_ENCRYPTION_KEY=please-generate-a-valid-fernet-key|PLUGIN_API_ENCRYPTION_KEY=${ENCRYPTION_KEY}|g" .env
            sed -i '' "s|postgresql+asyncpg://antihub:please-change-me@postgres:5432/antihub|postgresql+asyncpg://antihub:${POSTGRES_PASSWORD}@postgres:5432/antihub|g" .env
        fi

        log_info "环境变量配置已生成"
        echo ""
    fi

    # 4. 拉取镜像
    log_info "拉取 Docker 镜像..."
    $DOCKER_COMPOSE pull

    # 5. 停止旧容器（如果存在）
    log_info "停止旧容器..."
    $DOCKER_COMPOSE down 2>/dev/null || true

    # 6. 启动服务
    log_info "启动服务..."
    $DOCKER_COMPOSE up -d

    # 7. 等待服务启动
    log_info "等待服务启动..."
    sleep 5

    # 检查 PostgreSQL 健康状态
    log_info "检查 PostgreSQL 状态..."
    POSTGRES_USER_CHECK=$(grep "^POSTGRES_USER=" .env | cut -d'=' -f2 || echo "antihub")
    for i in {1..30}; do
        if $DOCKER_COMPOSE exec -T postgres pg_isready -U "$POSTGRES_USER_CHECK" &> /dev/null; then
            log_info "PostgreSQL 已就绪"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL 启动超时"
            exit 1
        fi
        sleep 2
    done

    # 确保 Plugin 数据库/用户已正确初始化（避免只改端口/重写 .env 后出现密码不一致）
    log_info "同步 PostgreSQL 中的 plugin 数据库/用户..."
    POSTGRES_USER_ENV=$(grep "^POSTGRES_USER=" .env | cut -d'=' -f2 || echo "antihub")
    POSTGRES_PASSWORD_ENV=$(grep "^POSTGRES_PASSWORD=" .env | cut -d'=' -f2- || echo "please-change-me")
    PLUGIN_DB_NAME_ENV=$(grep "^PLUGIN_DB_NAME=" .env | cut -d'=' -f2 || echo "antigravity")
    PLUGIN_DB_USER_ENV=$(grep "^PLUGIN_DB_USER=" .env | cut -d'=' -f2 || echo "antigravity")
    PLUGIN_DB_PASSWORD_ENV=$(grep "^PLUGIN_DB_PASSWORD=" .env | cut -d'=' -f2- || echo "please-change-me")

    $DOCKER_COMPOSE exec -T postgres psql -v ON_ERROR_STOP=1 \
        -U "$POSTGRES_USER_ENV" -d postgres \
        -v su_user="$POSTGRES_USER_ENV" -v su_pass="$POSTGRES_PASSWORD_ENV" \
        -v plugin_db="$PLUGIN_DB_NAME_ENV" -v plugin_user="$PLUGIN_DB_USER_ENV" -v plugin_pass="$PLUGIN_DB_PASSWORD_ENV" <<-'EOSQL'
DO $$
BEGIN
    -- 让数据库里的密码与 .env 保持一致（覆盖式配置也能正常连上旧数据卷）
    EXECUTE format('ALTER USER %I WITH PASSWORD %L', :'su_user', :'su_pass');

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'plugin_user') THEN
        EXECUTE format('CREATE USER %I WITH PASSWORD %L', :'plugin_user', :'plugin_pass');
    ELSE
        EXECUTE format('ALTER USER %I WITH PASSWORD %L', :'plugin_user', :'plugin_pass');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'plugin_db') THEN
        EXECUTE format('CREATE DATABASE %I OWNER %I', :'plugin_db', :'plugin_user');
    ELSE
        EXECUTE format('ALTER DATABASE %I OWNER TO %I', :'plugin_db', :'plugin_user');
    END IF;

    EXECUTE format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', :'plugin_db', :'plugin_user');
END $$;
EOSQL

    $DOCKER_COMPOSE exec -T postgres psql -v ON_ERROR_STOP=1 \
        -U "$POSTGRES_USER_ENV" -d "$PLUGIN_DB_NAME_ENV" \
        -v plugin_user="$PLUGIN_DB_USER_ENV" <<-'EOSQL'
DO $$
BEGIN
    EXECUTE format('GRANT ALL ON SCHEMA public TO %I', :'plugin_user');
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %I', :'plugin_user');
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %I', :'plugin_user');
END $$;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
EOSQL

    # 如果 plugin/backend 因为数据库密码/库不存在启动失败，这里统一重启一次
    $DOCKER_COMPOSE restart plugin backend &> /dev/null || true

    # 检查服务状态
    log_info "检查服务状态..."
    sleep 3

    FAILED_SERVICES=$($DOCKER_COMPOSE ps --services --filter "status=exited")
    if [ -n "$FAILED_SERVICES" ]; then
        log_error "以下服务启动失败："
        echo "$FAILED_SERVICES"
        log_info "查看日志："
        $DOCKER_COMPOSE logs --tail=50
        exit 1
    fi

    # 8. 输出部署信息
    echo ""
    log_info "=========================================="
    log_info "AntiHub-ALL 部署完成！"
    log_info "=========================================="
    echo ""

    # 读取端口配置
    WEB_PORT=$(grep "^WEB_PORT=" .env | cut -d'=' -f2 || echo "3000")
    BACKEND_PORT=$(grep "^BACKEND_PORT=" .env | cut -d'=' -f2 || echo "8000")
    POSTGRES_PORT=$(grep "^POSTGRES_PORT=" .env | cut -d'=' -f2 || echo "5432")
    ADMIN_USERNAME=$(grep "^ADMIN_USERNAME=" .env | cut -d'=' -f2 || echo "admin")
    ADMIN_PASSWORD=$(grep "^ADMIN_PASSWORD=" .env | cut -d'=' -f2)

    # 获取服务器 IP
    SERVER_IP=$(hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")

    log_info "访问地址："
    echo "  前端（对外）: http://${SERVER_IP}:${WEB_PORT}"
    echo "  前端（本地）: http://localhost:${WEB_PORT}"
    echo "  后端（仅本地）: http://localhost:${BACKEND_PORT}"
    echo ""
    log_info "管理员账号："
    echo "  用户名: ${ADMIN_USERNAME}"
    echo "  密码: ${ADMIN_PASSWORD}"
    echo ""
    log_info "数据库信息（仅本地访问）："
    echo "  PostgreSQL: localhost:${POSTGRES_PORT}"
    echo "  数据库: antihub, antigravity"
    echo ""
    log_info "常用命令："
    echo "  查看日志: $DOCKER_COMPOSE logs -f"
    echo "  停止服务: $DOCKER_COMPOSE down"
    echo "  重启服务: $DOCKER_COMPOSE restart"
    echo "  查看状态: $DOCKER_COMPOSE ps"
    echo ""
    log_warn "重要提示："
    echo "  1. 请妥善保管 .env 文件中的密钥"
    echo "  2. Web 端口已对外暴露，建议配置防火墙"
    echo "  3. Backend 和数据库仅本地访问（127.0.0.1）"
    echo "  4. 生产环境建议配置反向代理（Nginx/Caddy）并启用 HTTPS"
    echo ""
}

# 执行主函数
main
