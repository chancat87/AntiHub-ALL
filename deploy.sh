#!/bin/bash
# AntiHub-ALL 一键部署脚本
# 适用于 Linux 系统

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 未安装，请先安装 $1"
        exit 1
    fi
}

# 生成随机密钥
generate_random_key() {
    openssl rand -hex 32
}

# 生成 Fernet 密钥（用于 PLUGIN_API_ENCRYPTION_KEY）
generate_fernet_key() {
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
    docker run --rm python:3.11-alpine python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
}

# 主函数
main() {
    log_info "开始部署 AntiHub-ALL..."

    # 1. 检查依赖
    log_info "检查系统依赖..."
    check_command docker
    check_command openssl

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
        log_info "生成环境变量配置..."

        if [ ! -f .env.example ]; then
            log_error ".env.example 文件不存在"
            exit 1
        fi

        cp .env.example .env

        # 生成密钥
        log_info "生成安全密钥..."
        JWT_SECRET=$(generate_random_key)
        ADMIN_API_KEY="sk-admin-$(generate_random_key | cut -c1-32)"
        POSTGRES_PASSWORD=$(generate_random_key | cut -c1-24)
        PLUGIN_DB_PASSWORD=$(generate_random_key | cut -c1-24)

        log_info "生成 Fernet 加密密钥..."
        ENCRYPTION_KEY=$(generate_fernet_key)

        # 生成管理员密码
        ADMIN_PASS=$(generate_random_key | cut -c1-16)

        # 替换 .env 中的占位符（兼容 Linux 和 macOS）
        if sed --version 2>&1 | grep -q GNU; then
            # GNU sed (Linux)
            sed -i "s|JWT_SECRET_KEY=please-change-me|JWT_SECRET_KEY=${JWT_SECRET}|g" .env
            sed -i "s|PLUGIN_ADMIN_API_KEY=sk-admin-please-change-me|PLUGIN_ADMIN_API_KEY=${ADMIN_API_KEY}|g" .env
            sed -i "s|POSTGRES_PASSWORD=please-change-me|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|g" .env
            sed -i "s|PLUGIN_DB_PASSWORD=please-change-me|PLUGIN_DB_PASSWORD=${PLUGIN_DB_PASSWORD}|g" .env
            sed -i "s|PLUGIN_API_ENCRYPTION_KEY=please-generate-a-valid-fernet-key|PLUGIN_API_ENCRYPTION_KEY=${ENCRYPTION_KEY}|g" .env
            sed -i "s|ADMIN_PASSWORD=please-change-me-to-strong-password|ADMIN_PASSWORD=${ADMIN_PASS}|g" .env
            sed -i "s|postgresql+asyncpg://antihub:please-change-me@|postgresql+asyncpg://antihub:${POSTGRES_PASSWORD}@|g" .env
        else
            # BSD sed (macOS)
            sed -i '' "s|JWT_SECRET_KEY=please-change-me|JWT_SECRET_KEY=${JWT_SECRET}|g" .env
            sed -i '' "s|PLUGIN_ADMIN_API_KEY=sk-admin-please-change-me|PLUGIN_ADMIN_API_KEY=${ADMIN_API_KEY}|g" .env
            sed -i '' "s|POSTGRES_PASSWORD=please-change-me|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|g" .env
            sed -i '' "s|PLUGIN_DB_PASSWORD=please-change-me|PLUGIN_DB_PASSWORD=${PLUGIN_DB_PASSWORD}|g" .env
            sed -i '' "s|PLUGIN_API_ENCRYPTION_KEY=please-generate-a-valid-fernet-key|PLUGIN_API_ENCRYPTION_KEY=${ENCRYPTION_KEY}|g" .env
            sed -i '' "s|ADMIN_PASSWORD=please-change-me-to-strong-password|ADMIN_PASSWORD=${ADMIN_PASS}|g" .env
            sed -i '' "s|postgresql+asyncpg://antihub:please-change-me@|postgresql+asyncpg://antihub:${POSTGRES_PASSWORD}@|g" .env
        fi

        log_info "环境变量配置已生成"
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
    for i in {1..30}; do
        if $DOCKER_COMPOSE exec -T postgres pg_isready -U antihub &> /dev/null; then
            log_info "PostgreSQL 已就绪"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL 启动超时"
            exit 1
        fi
        sleep 2
    done

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
    ADMIN_USERNAME=$(grep "^ADMIN_USERNAME=" .env | cut -d'=' -f2 || echo "admin")
    ADMIN_PASSWORD=$(grep "^ADMIN_PASSWORD=" .env | cut -d'=' -f2)

    log_info "访问地址："
    echo "  前端: http://localhost:${WEB_PORT}"
    echo "  后端: http://localhost:${BACKEND_PORT}"
    echo ""
    log_info "管理员账号："
    echo "  用户名: ${ADMIN_USERNAME}"
    echo "  密码: ${ADMIN_PASSWORD}"
    echo ""
    log_info "常用命令："
    echo "  查看日志: $DOCKER_COMPOSE logs -f"
    echo "  停止服务: $DOCKER_COMPOSE down"
    echo "  重启服务: $DOCKER_COMPOSE restart"
    echo "  查看状态: $DOCKER_COMPOSE ps"
    echo ""
    log_warn "重要提示："
    echo "  1. 请妥善保管 .env 文件中的密钥"
    echo "  2. 生产环境请修改默认管理员密码"
    echo "  3. 建议配置反向代理（Nginx/Caddy）并启用 HTTPS"
    echo ""
}

# 执行主函数
main
