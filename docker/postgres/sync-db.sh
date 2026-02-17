#!/bin/sh
# 同步/初始化 Backend 主库（可重复执行）
#
# 背景：PostgreSQL 官方镜像的 /docker-entrypoint-initdb.d 只会在“首次初始化数据目录”时执行。
# 当你复用旧数据卷但重写了 .env（例如生成新密码/改库名）时，可能出现连接失败或库不存在。
#
# 该脚本会：
# - 确保 POSTGRES_USER 的密码与 .env 一致
# - 创建/修正 POSTGRES_DB 的归属

set -e

strip_cr() {
    printf '%s' "$1" | tr -d '\r'
}

POSTGRES_USER=$(strip_cr "${POSTGRES_USER:-antihub}")
POSTGRES_PASSWORD=$(strip_cr "${POSTGRES_PASSWORD:-please-change-me}")
POSTGRES_DB=$(strip_cr "${POSTGRES_DB:-antihub}")

export PGPASSWORD="$POSTGRES_PASSWORD"

echo "[db-init] sync postgres user & database..."

psql -h postgres -U "$POSTGRES_USER" -d postgres -X -v ON_ERROR_STOP=1 \
    -v su_user="$POSTGRES_USER" -v su_pass="$POSTGRES_PASSWORD" \
    -v main_db="$POSTGRES_DB" <<'EOSQL'
SELECT format('ALTER USER %I WITH PASSWORD %L', :'su_user', :'su_pass') \gexec

SELECT CASE
    WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = :'main_db') THEN
        format('ALTER DATABASE %I OWNER TO %I', :'main_db', :'su_user')
    ELSE
        format('CREATE DATABASE %I OWNER %I', :'main_db', :'su_user')
END \gexec
EOSQL

echo "[db-init] done."

