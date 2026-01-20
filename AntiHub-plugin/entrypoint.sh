#!/bin/sh
# ============================================
# AntiHub Plugin - Docker Entry Point
# ============================================
# 从环境变量生成 config.json
# 每次启动覆盖生成 config.json（避免旧配置残留）
# 自动检测并初始化数据库
# ============================================

CONFIG_FILE="/app/config.json"
SCHEMA_FILE="/app/schema.sql"

# ============================================
# 1. 自动检测并初始化数据库
# ============================================
echo "检查数据库初始化状态..."

# 构建数据库连接字符串
PGHOST="${DB_HOST:-localhost}"
PGPORT="${DB_PORT:-5432}"
PGDATABASE="${DB_NAME:-antigravity}"
PGUSER="${DB_USER:-postgres}"
PGPASSWORD="${DB_PASSWORD:-postgres}"
export PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD

# 如果你用的是本项目 docker-compose.yml 自带 postgres，容器内端口永远是 5432（别跟宿主机映射端口混了）
if [ "$PGHOST" = "postgres" ] && [ "$PGPORT" != "5432" ]; then
    echo "⚠️  检测到 DB_HOST=postgres 但 DB_PORT=$PGPORT；容器内连接 postgres 应使用 5432，将回退为 5432"
    PGPORT="5432"
    export PGPORT
fi

# 等待数据库可连接（避免启动时序导致误判）
i=0
last_err=""
while [ $i -lt 30 ]; do
    out=$(psql -tAc "SELECT 1" 2>&1)
    if [ $? -eq 0 ]; then
        last_err=""
        break
    fi
    last_err="$out"
    i=$((i + 1))
    sleep 2
done

if [ -n "$last_err" ]; then
    echo "❌ 无法连接数据库：${PGHOST}:${PGPORT}/${PGDATABASE}（user=${PGUSER}）"
    echo "$last_err"
    exit 1
fi

# 检查 users 表是否存在
table_exists_out=$(psql -tAc "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users');" 2>&1)
if [ $? -ne 0 ]; then
    echo "❌ 无法检查数据库初始化状态："
    echo "$table_exists_out"
    exit 1
fi

TABLE_EXISTS=$(echo "$table_exists_out" | tr -d '[:space:]')

if [ "$TABLE_EXISTS" = "t" ]; then
    echo "✅ 数据库已初始化（users 表已存在）"
else
    echo "📊 数据库未初始化，开始导入 schema.sql..."

    if [ -f "$SCHEMA_FILE" ]; then
        schema_out=$(psql -v ON_ERROR_STOP=1 -f "$SCHEMA_FILE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "✅ 数据库初始化成功！"
        else
            echo "❌ 数据库初始化失败！请检查数据库连接和配置。"
            echo "$schema_out"
            echo "如果数据库还未创建，请先创建数据库："
            echo "  CREATE DATABASE $PGDATABASE;"
            exit 1
        fi
    else
        echo "❌ 找不到 schema.sql 文件！"
        exit 1
    fi
fi

echo ""

# ============================================
# 2. 生成 config.json
# ============================================

# 每次启动都从环境变量重新生成（覆盖）config.json，避免旧版本残留导致行为不一致
echo "从环境变量生成配置文件（覆盖）: $CONFIG_FILE"

if ! (cat > "$CONFIG_FILE" << EOF
{
  "server": {
    "port": "${PORT:-8045}",
    "host": "0.0.0.0"
  },
  "database": {
    "host": "${DB_HOST:-localhost}",
    "port": ${DB_PORT:-5432},
    "database": "${DB_NAME:-antigravity}",
    "user": "${DB_USER:-postgres}",
    "password": "${DB_PASSWORD:-postgres}",
    "max": 20,
    "idleTimeoutMillis": 30000,
    "connectionTimeoutMillis": 2000
  },
  "redis": {
    "host": "${REDIS_HOST:-localhost}",
    "port": ${REDIS_PORT:-6379},
    "password": "${REDIS_PASSWORD:-}",
    "db": 0
  },
  "oauth": {
    "callbackUrl": "${OAUTH_CALLBACK_URL:-http://localhost:8045/api/oauth/callback}"
  },
  "defaults": {
    "temperature": 1,
    "top_p": 0.85,
    "top_k": 50,
    "max_tokens": 8096
  },
  "security": {
    "maxRequestSize": "50mb",
    "adminApiKey": "${ADMIN_API_KEY:-sk-admin-default-key}"
  },
  "systemInstructionShort": "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.**Absolute paths only****Proactiveness**",
  "systemInstruction": ""
}
EOF
); then
    echo "ERROR: 无法写入 $CONFIG_FILE（可能被挂载为只读或权限不足），请移除挂载或调整权限"
    exit 1
fi

echo "配置文件已生成: $CONFIG_FILE"
cat "$CONFIG_FILE"

echo ""
echo "启动 AntiHub API 服务..."
echo "================================"

# 启动主应用
exec node src/server/index.js
