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
    # 兼容某些终端/粘贴会带 CR（\r）的情况：避免后续写入 .env / 解析变量时出错
    value=${value//$'\r'/}
    echo "${value:-$default}"
}

# 读取密码（明文输入一次）
read_password() {
    local prompt="$1"
    local password

    while true; do
        # 按用户需求：明文输入一次，不再二次确认
        read -p "$prompt: " password
        password=${password//$'\r'/}
        if [ -z "$password" ]; then
            log_error "密码不能为空"
            continue
        fi
        echo "$password"
        break
    done
}

# 写入 .env：不依赖 sed（避免特殊字符/终端粘贴导致 sed 解析报错）
write_env_file() {
    local env_file="$1"
    local tmp_file="${env_file}.tmp"

    local postgres_user
    local postgres_db
    postgres_user=$(grep "^POSTGRES_USER=" "$env_file" | cut -d'=' -f2- 2>/dev/null || true)
    postgres_db=$(grep "^POSTGRES_DB=" "$env_file" | cut -d'=' -f2- 2>/dev/null || true)
    postgres_user=${postgres_user//$'\r'/}
    postgres_db=${postgres_db//$'\r'/}
    postgres_user=${postgres_user:-antihub}
    postgres_db=${postgres_db:-antihub}

    while IFS= read -r line || [ -n "$line" ]; do
        line=${line//$'\r'/}
        case "$line" in
            WEB_PORT=*)
                printf '%s\n' "WEB_PORT=$WEB_PORT"
                ;;
            BACKEND_PORT=*)
                printf '%s\n' "BACKEND_PORT=$BACKEND_PORT"
                ;;
            \#\ POSTGRES_PORT=*|\#POSTGRES_PORT=*|POSTGRES_PORT=*)
                printf '%s\n' "POSTGRES_PORT=$POSTGRES_PORT"
                ;;
            ADMIN_USERNAME=*)
                printf '%s\n' "ADMIN_USERNAME=$ADMIN_USERNAME"
                ;;
            ADMIN_PASSWORD=*)
                printf '%s\n' "ADMIN_PASSWORD=$ADMIN_PASSWORD"
                ;;
            JWT_SECRET_KEY=*)
                printf '%s\n' "JWT_SECRET_KEY=$JWT_SECRET"
                ;;
            PLUGIN_ADMIN_API_KEY=*)
                printf '%s\n' "PLUGIN_ADMIN_API_KEY=$ADMIN_API_KEY"
                ;;
            POSTGRES_PASSWORD=*)
                printf '%s\n' "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
                ;;
            PLUGIN_DB_USER=*)
                # 简化：plugin 直接复用 PostgreSQL 超管用户
                printf '%s\n' "PLUGIN_DB_USER=$postgres_user"
                ;;
            PLUGIN_DB_PASSWORD=*)
                # 简化：plugin 直接复用 PostgreSQL 超管密码
                printf '%s\n' "PLUGIN_DB_PASSWORD=$POSTGRES_PASSWORD"
                ;;
            PLUGIN_API_ENCRYPTION_KEY=*)
                printf '%s\n' "PLUGIN_API_ENCRYPTION_KEY=$ENCRYPTION_KEY"
                ;;
            DATABASE_URL=*)
                printf '%s\n' "DATABASE_URL=postgresql+asyncpg://${postgres_user}:${POSTGRES_PASSWORD}@postgres:5432/${postgres_db}"
                ;;
            *)
                printf '%s\n' "$line"
                ;;
        esac
    done < "$env_file" > "$tmp_file"

    mv "$tmp_file" "$env_file"
}

get_env_value() {
    local file="$1"
    local key="$2"
    if [ ! -f "$file" ]; then
        return 0
    fi
    local value
    value=$(grep -m 1 "^${key}=" "$file" 2>/dev/null | cut -d'=' -f2- || true)
    value=${value//$'\r'/}
    printf '%s' "$value"
}

# 修复 docker 目录权限（解决 NAS 等环境下的权限问题）
fix_permissions() {
    log_info "修复 docker 目录权限..."

    # 获取脚本所在目录（即项目根目录）
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # 仅处理 docker 目录，避免误改 .env / 仓库其它文件权限
    TARGET_DIR="$SCRIPT_DIR/docker"
    if [ ! -d "$TARGET_DIR" ]; then
        log_warn "未找到 docker 目录，跳过权限修复"
        return 0
    fi

    # 目录设置为 755 (rwxr-xr-x)
    find "$TARGET_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true

    # 普通文件设置为 644 (rw-r--r--)
    find "$TARGET_DIR" -type f -exec chmod 644 {} \; 2>/dev/null || true

    # 脚本文件设置为 755 (rwxr-xr-x)
    find "$TARGET_DIR" -name "*.sh" -type f -exec chmod 755 {} \; 2>/dev/null || true

    log_info "docker 目录权限修复完成"
}

# 主函数
main() {
    log_info "开始部署 AntiHub-ALL..."
    echo ""

    # 0. 修复权限（解决 NAS 等环境下的权限问题）
    fix_permissions

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

    # 组合 docker compose 文件：基础 compose + 数据库初始化 compose（可选）
    DB_INIT_COMPOSE_FILE="docker/docker-compose.db-init.yml"
    COMPOSE_FILES="-f docker-compose.yml"
    if [ -f "$DB_INIT_COMPOSE_FILE" ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f $DB_INIT_COMPOSE_FILE"
    fi

    compose() {
        $DOCKER_COMPOSE $COMPOSE_FILES "$@"
    }

    # 检查 Docker 是否运行
    if ! docker info &> /dev/null; then
        log_error "Docker 未运行，请先启动 Docker 服务"
        exit 1
    fi

    # 2. 检查 .env 文件
    ENV_BACKUP_FILE=""
    if [ -f .env ]; then
        log_warn ".env 文件已存在"
        read -p "是否覆盖现有配置？(y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "保留现有配置，跳过环境变量生成"
            ENV_EXISTS=true
        else
            ENV_EXISTS=false
            ENV_BACKUP_FILE=".env.bak.$(date +\"%Y%m%d_%H%M%S\")"
            cp .env "$ENV_BACKUP_FILE"
            log_info "已备份原 .env 到 ${ENV_BACKUP_FILE}"
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
        OLD_JWT_SECRET=$(get_env_value "$ENV_BACKUP_FILE" "JWT_SECRET_KEY")
        OLD_ADMIN_API_KEY=$(get_env_value "$ENV_BACKUP_FILE" "PLUGIN_ADMIN_API_KEY")
        OLD_POSTGRES_PASSWORD=$(get_env_value "$ENV_BACKUP_FILE" "POSTGRES_PASSWORD")
        OLD_ENCRYPTION_KEY=$(get_env_value "$ENV_BACKUP_FILE" "PLUGIN_API_ENCRYPTION_KEY")

        if [ -n "$OLD_JWT_SECRET" ] && [ "$OLD_JWT_SECRET" != "please-change-me" ]; then
            JWT_SECRET="$OLD_JWT_SECRET"
        else
            JWT_SECRET=$(generate_random_key)
        fi

        if [ -n "$OLD_ADMIN_API_KEY" ] && [ "$OLD_ADMIN_API_KEY" != "sk-admin-please-change-me" ]; then
            ADMIN_API_KEY="$OLD_ADMIN_API_KEY"
        else
            ADMIN_API_KEY="sk-admin-$(generate_random_key | cut -c1-32)"
        fi

        if [ -n "$OLD_POSTGRES_PASSWORD" ] && [ "$OLD_POSTGRES_PASSWORD" != "please-change-me" ]; then
            POSTGRES_PASSWORD="$OLD_POSTGRES_PASSWORD"
        else
            POSTGRES_PASSWORD=$(generate_random_key | cut -c1-24)
        fi

        # 简化：plugin 直接复用 PostgreSQL 超管密码
        PLUGIN_DB_PASSWORD="$POSTGRES_PASSWORD"

        log_info "生成 Fernet 加密密钥..."
        if [ -n "$OLD_ENCRYPTION_KEY" ] && [ "$OLD_ENCRYPTION_KEY" != "please-generate-a-valid-fernet-key" ]; then
            ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY"
        else
            ENCRYPTION_KEY=$(generate_fernet_key)
        fi

        # 3.4 替换 .env 中的占位符（兼容 Linux 和 macOS）
        log_info "写入配置文件..."
        write_env_file ".env"

        log_info "环境变量配置已生成"
        echo ""
    fi

    # 4. 拉取镜像
    log_info "拉取 Docker 镜像..."
    compose pull

    # 5. 停止旧容器（如果存在）
    log_info "停止旧容器..."
    compose down 2>/dev/null || true

    # 6. 先启动基础依赖（数据库 / 缓存），并完成数据库初始化，再启动主容器
    log_info "启动数据库与缓存（postgres/redis）..."
    compose up -d postgres redis

    log_info "检查 PostgreSQL 状态..."
    POSTGRES_USER_CHECK=$(grep "^POSTGRES_USER=" .env | cut -d'=' -f2 || echo "antihub")
    for i in {1..30}; do
        if compose exec -T postgres pg_isready -U "$POSTGRES_USER_CHECK" &> /dev/null; then
            log_info "PostgreSQL 已就绪"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL 启动超时"
            exit 1
        fi
        sleep 2
    done

    # 初始化/同步两个数据库（antihub / plugin）
    log_info "初始化数据库（antihub / plugin）..."
    POSTGRES_USER_ENV=$(grep "^POSTGRES_USER=" .env | cut -d'=' -f2 || echo "antihub")
    POSTGRES_PASSWORD_ENV=$(grep "^POSTGRES_PASSWORD=" .env | cut -d'=' -f2- || echo "please-change-me")
    POSTGRES_DB_ENV=$(grep "^POSTGRES_DB=" .env | cut -d'=' -f2 || echo "antihub")
    PLUGIN_DB_NAME_ENV=$(grep "^PLUGIN_DB_NAME=" .env | cut -d'=' -f2 || echo "antigravity")
    PLUGIN_DB_USER_ENV=$(grep "^PLUGIN_DB_USER=" .env | cut -d'=' -f2 || echo "$POSTGRES_USER_ENV")
    PLUGIN_DB_PASSWORD_ENV=$(grep "^PLUGIN_DB_PASSWORD=" .env | cut -d'=' -f2- || echo "$POSTGRES_PASSWORD_ENV")

    compose exec -T postgres psql -X -v ON_ERROR_STOP=1 \
        -U "$POSTGRES_USER_ENV" -d postgres \
        -v su_user="$POSTGRES_USER_ENV" -v su_pass="$POSTGRES_PASSWORD_ENV" \
        -v main_db="$POSTGRES_DB_ENV" \
        -v plugin_db="$PLUGIN_DB_NAME_ENV" -v plugin_user="$PLUGIN_DB_USER_ENV" -v plugin_pass="$PLUGIN_DB_PASSWORD_ENV" <<-'EOSQL'
SELECT format('ALTER USER %I WITH PASSWORD %L', :'su_user', :'su_pass') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'main_db', :'su_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'main_db') \gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', :'main_db', :'su_user')
WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname = :'main_db') \gexec

SELECT format('CREATE USER %I WITH PASSWORD %L', :'plugin_user', :'plugin_pass')
WHERE :'plugin_user' <> :'su_user'
  AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'plugin_user') \gexec

SELECT format('ALTER USER %I WITH PASSWORD %L', :'plugin_user', :'plugin_pass')
WHERE :'plugin_user' <> :'su_user'
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'plugin_user') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'plugin_db', :'plugin_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'plugin_db') \gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', :'plugin_db', :'plugin_user')
WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname = :'plugin_db') \gexec

SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', :'plugin_db', :'plugin_user') \gexec
EOSQL

    compose exec -T postgres psql -X -v ON_ERROR_STOP=1 \
        -U "$POSTGRES_USER_ENV" -d "$PLUGIN_DB_NAME_ENV" \
        -v plugin_user="$PLUGIN_DB_USER_ENV" <<-'EOSQL'
SELECT format('GRANT ALL ON SCHEMA public TO %I', :'plugin_user') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %I', :'plugin_user') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %I', :'plugin_user') \gexec

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
EOSQL

    log_info "启动主服务（plugin/backend/web）..."
    compose up -d plugin backend web

    # 检查服务状态
    log_info "检查服务状态..."
    sleep 3

    FAILED_SERVICES=$(compose ps --services --filter "status=exited")
    if [ -n "$FAILED_SERVICES" ]; then
        log_error "以下服务启动失败："
        echo "$FAILED_SERVICES"
        log_info "查看日志："
        compose logs --tail=50
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
    ADMIN_PASSWORD=$(grep "^ADMIN_PASSWORD=" .env | cut -d'=' -f2-)

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
    echo "  查看日志: $DOCKER_COMPOSE $COMPOSE_FILES logs -f"
    echo "  停止服务: $DOCKER_COMPOSE $COMPOSE_FILES down"
    echo "  重启服务: $DOCKER_COMPOSE $COMPOSE_FILES restart"
    echo "  查看状态: $DOCKER_COMPOSE $COMPOSE_FILES ps"
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
