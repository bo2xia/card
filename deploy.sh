#!/bin/bash

# 卡密查询系统 - Docker部署脚本
# 版本: 3.0.0 - SSL支持版本
# 支持: HTTP/HTTPS双模式，自动SSL证书生成，Docker容器化
# 新增: SSL证书管理，Nginx反向代理，生产环境配置
# 智能: 自动检测容器状态，支持快速修复和完全重建

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置变量
PROJECT_NAME="card-query-system"
CONTAINER_NAME="card-query-app"
NGINX_CONTAINER_NAME="card-query-nginx"
IMAGE_NAME="card-system"
APP_PORT="${APP_PORT:-5000}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"
DOMAIN="${DOMAIN:-localhost}"

# 日志函数
log_info() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] ✅ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ❌ $1${NC}"
}

log_step() {
    echo -e "${CYAN}[$(date '+%H:%M:%S')] 🚀 $1${NC}"
}

print_header() {
    echo -e "${PURPLE}"
    echo "=========================================================="
    echo "    🎯 卡密查询系统 - Docker部署脚本 v3.0"
    echo "    🚀 SQLite数据库 + Docker容器化"
    echo "    🔒 HTTP/HTTPS双模式 + SSL证书自动生成"
    echo "    🌐 Nginx反向代理 + 生产环境优化"
    echo "    🧠 智能修复 + 多模式部署 + 命令行参数"
    echo "=========================================================="
    echo -e "${NC}"
}

# 检查系统环境
check_system() {
    log_step "检查系统环境..."

    # 检查操作系统
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log_error "此脚本仅支持Linux系统，当前系统: $OSTYPE"
        exit 1
    fi

    # 检查Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker未安装，请先安装Docker"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker服务未运行，请启动Docker服务"
        exit 1
    fi

    # 检查docker compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose未安装或版本过低，请安装Docker Compose V2"
        exit 1
    fi

    # 检查可用空间
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # 1GB
        log_warn "可用磁盘空间不足1GB，建议释放更多空间"
    fi

    log_info "系统环境检查通过"
}

# 验证项目文件
verify_project_files() {
    log_step "验证项目文件..."

    # 检查必要文件
    local required_files=("app.py" "requirements.txt" "docker-compose.yml" "docker-compose.prod.yml" "Dockerfile" "healthcheck.py" ".env")
    local missing_files=()

    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done

    if [ ${#missing_files[@]} -ne 0 ]; then
        log_error "缺少必要文件: ${missing_files[*]}"
        exit 1
    fi

    # 检查templates目录和关键模板文件
    if [ ! -d "templates" ]; then
        log_error "templates目录不存在"
        exit 1
    fi

    local required_templates=("login.html" "error.html" "dashboard.html" "query.html" "cards_dashboard.html" "accounts_dashboard.html" "batch_generate_dashboard.html" "change_password_dashboard.html" "notice_manage_dashboard.html")
    local missing_templates=()

    for template in "${required_templates[@]}"; do
        if [ ! -f "templates/$template" ]; then
            missing_templates+=("$template")
        fi
    done

    if [ ${#missing_templates[@]} -ne 0 ]; then
        log_error "缺少模板文件: ${missing_templates[*]}"
        exit 1
    fi

    # 检查static目录和关键静态文件
    if [ ! -d "static" ]; then
        log_error "static目录不存在"
        exit 1
    fi

    local required_static=("bootstrap.min.css" "bootstrap.bundle.min.js" "common.js" "dashboard.css")
    local missing_static=()

    for static_file in "${required_static[@]}"; do
        if [ ! -f "static/$static_file" ]; then
            missing_static+=("$static_file")
        fi
    done

    if [ ${#missing_static[@]} -ne 0 ]; then
        log_error "缺少静态文件: ${missing_static[*]}"
        exit 1
    fi

    # 验证Dockerfile中的基本结构
    if ! grep -q "FROM python:" Dockerfile; then
        log_error "Dockerfile格式不正确"
        exit 1
    fi

    log_info "项目文件验证通过"
}

# 生成SSL证书
generate_ssl_certificates() {
    log_step "生成SSL证书..."

    # 创建SSL目录
    mkdir -p ssl

    # 检查是否已存在证书
    if [ -f "ssl/cert.pem" ] && [ -f "ssl/key.pem" ]; then
        log_info "SSL证书已存在，跳过生成"
        return 0
    fi

    log_info "生成自签名SSL证书..."

    # 检查OpenSSL
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL 未安装，无法生成SSL证书。请安装openssl或手动提供ssl/cert.pem和ssl/key.pem"
        return 1
    fi

    # 生成私钥
    openssl genrsa -out ssl/key.pem 2048 2>/dev/null

    # 生成证书
    openssl req -new -x509 -key ssl/key.pem -out ssl/cert.pem -days 365 -subj "/C=CN/ST=Beijing/L=Beijing/O=CardSystem/OU=IT/CN=${DOMAIN}" 2>/dev/null

    # 设置权限
    chmod 600 ssl/key.pem
    chmod 644 ssl/cert.pem

    log_info "SSL证书生成完成"
    log_info "证书域名: ${DOMAIN}"
    log_info "证书有效期: 365天"
}

# 创建目录
create_directories() {
    log_step "创建项目目录..."

    mkdir -p data logs backups ssl instance
    chmod 755 data logs backups ssl instance

    # 创建Nginx日志目录
    mkdir -p logs/nginx
    chmod 755 logs/nginx

    # 创建SQLite数据库文件
    if [ ! -f "data/card_query.db" ]; then
        touch data/card_query.db
        chmod 666 data/card_query.db
        log_info "SQLite数据库文件已创建"
    fi

    log_info "目录创建完成"
}

# 清理旧部署
cleanup_old() {
    log_step "清理旧部署..."

    # 使用docker compose停止服务
    if [ -f "docker-compose.yml" ]; then
        docker compose down --remove-orphans 2>/dev/null || true
        log_info "开发环境Docker Compose服务已停止"
    fi

    if [ -f "docker-compose.prod.yml" ]; then
        docker compose -f docker-compose.prod.yml down --remove-orphans 2>/dev/null || true
        log_info "生产环境Docker Compose服务已停止"
    fi

    # 查找并停止相关容器
    local containers=$(docker ps -a --format "{{.Names}}" | grep -E "(card-query|card-system)" || true)
    if [ ! -z "$containers" ]; then
        echo "$containers" | while read container; do
            log_info "停止并删除容器: $container"
            docker stop "$container" 2>/dev/null || true
            docker rm "$container" 2>/dev/null || true
        done
    fi

    # 清理悬空镜像
    local dangling_images=$(docker images -f "dangling=true" -q)
    if [ ! -z "$dangling_images" ]; then
        log_info "清理悬空镜像..."
        docker rmi $dangling_images 2>/dev/null || true
    fi

    # 清理构建缓存
    log_info "清理Docker构建缓存..."
    docker builder prune -f 2>/dev/null || true

    # 清理网络
    log_info "清理Docker网络..."
    docker network prune -f 2>/dev/null || true

    # 清理项目缓存文件
    log_info "清理项目缓存..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true

    # 清理日志文件（保留目录结构）
    if [ -d "./logs" ]; then
        find ./logs -name "*.log" -type f -delete 2>/dev/null || true
        touch ./logs/.gitkeep
        # 清理Nginx日志
        if [ -d "./logs/nginx" ]; then
            find ./logs/nginx -name "*.log" -type f -delete 2>/dev/null || true
        fi
    fi

    log_info "旧部署清理完成"
}

# 构建镜像
build_image() {
    log_step "构建Docker镜像..."

    if [ ! -f "Dockerfile" ]; then
        log_error "Dockerfile 不存在"
        exit 1
    fi

    log_info "开始构建镜像..."

    if docker build \
        -t "${IMAGE_NAME}" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VERSION="3.0.0" \
        --progress=plain \
        . ; then
        log_info "Docker镜像构建成功"

        # 显示镜像信息
        log_info "镜像信息:"
        docker images "${IMAGE_NAME}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

        # 验证镜像中的文件结构
        log_info "验证镜像中的文件结构..."
        if docker run --rm "${IMAGE_NAME}" ls -la /app/templates/ > /dev/null 2>&1; then
            log_info "✅ templates目录验证通过"
        else
            log_error "❌ templates目录验证失败"
            exit 1
        fi

        if docker run --rm "${IMAGE_NAME}" ls -la /app/static/ > /dev/null 2>&1; then
            log_info "✅ static目录验证通过"
        else
            log_error "❌ static目录验证失败"
            exit 1
        fi

        # 验证关键模板文件
        local key_templates=("login.html" "error.html" "dashboard.html")
        for template in "${key_templates[@]}"; do
            if docker run --rm "${IMAGE_NAME}" test -f "/app/templates/$template"; then
                log_info "✅ $template 存在"
            else
                log_error "❌ $template 不存在"
                exit 1
            fi
        done

        # 验证健康检查脚本
        if docker run --rm "${IMAGE_NAME}" test -f "/app/healthcheck.py"; then
            log_info "✅ healthcheck.py 存在"
        else
            log_error "❌ healthcheck.py 不存在"
            exit 1
        fi

    else
        log_error "Docker镜像构建失败"
        exit 1
    fi
}

# 选择部署模式
choose_deployment_mode() {
    if [ -z "$DEPLOYMENT_MODE" ]; then
        echo ""
        echo "选择部署模式:"
        echo "1. 开发模式 (HTTP only, 端口 5000)"
        echo "2. 生产模式 (HTTP + HTTPS, 端口 80/443, Nginx反向代理)"
        echo ""
        read -p "请选择 [1/2]: " mode_choice

        case $mode_choice in
            1)
                DEPLOYMENT_MODE="dev"
                ;;
            2)
                DEPLOYMENT_MODE="prod"
                ;;
            *)
                log_info "无效选择，默认使用开发模式"
                DEPLOYMENT_MODE="dev"
                ;;
        esac
    fi

    log_info "选择的部署模式: $DEPLOYMENT_MODE"
}

# 启动服务
start_service() {
    log_step "启动应用服务..."

    # 设置环境变量
    export APP_PORT="${APP_PORT}"
    export HTTP_PORT="${HTTP_PORT}"
    export HTTPS_PORT="${HTTPS_PORT}"
    export DOMAIN="${DOMAIN}"

    # 如果指定了域名，则更新nginx.conf中的server_name（幂等）
    if [ -n "$DOMAIN" ] && [ -f nginx.conf ]; then
        if grep -q "server_name" nginx.conf; then
            sed -i.bak -E "s/server_name[[:space:]]+[^;]+;/server_name ${DOMAIN};/g" nginx.conf || true
        fi
    fi

    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        if [ ! -f "docker-compose.prod.yml" ]; then
            log_error "docker-compose.prod.yml 不存在"
            exit 1
        fi

        log_info "启动生产环境服务 (HTTP + HTTPS)..."
        if docker compose -f docker-compose.prod.yml up -d; then
            log_info "生产环境服务启动成功"
        else
            log_error "生产环境服务启动失败"
            exit 1
        fi
    else
        if [ ! -f "docker-compose.yml" ]; then
            log_error "docker-compose.yml 不存在"
            exit 1
        fi

        log_info "启动开发环境服务 (HTTP only)..."
        if docker compose up -d; then
            log_info "开发环境服务启动成功"
        else
            log_error "开发环境服务启动失败"
            exit 1
        fi
    fi
}

# 等待服务就绪
wait_service() {
    log_step "等待服务启动..."

    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if [ "$DEPLOYMENT_MODE" = "prod" ]; then
            # 生产模式：检查HTTPS和HTTP
            if curl -f -s -k "https://localhost:${HTTPS_PORT}/" > /dev/null 2>&1; then
                log_info "HTTPS服务已就绪"
                if curl -f -s "http://localhost:${HTTP_PORT}/" > /dev/null 2>&1; then
                    log_info "HTTP服务已就绪 (重定向到HTTPS)"
                fi
                return 0
            fi
        else
            # 开发模式：只检查HTTP
            if curl -f -s "http://localhost:${APP_PORT}/" > /dev/null 2>&1; then
                log_info "HTTP服务已就绪"
                return 0
            fi
        fi

        if [ $((attempt % 10)) -eq 0 ]; then
            log_info "等待服务启动... (${attempt}/${max_attempts})"
        fi

        sleep 2
        ((attempt++))
    done

    log_error "服务启动超时"

    # 显示容器日志以便调试
    log_info "显示容器日志:"
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        docker compose -f docker-compose.prod.yml logs --tail=20
    else
        docker compose logs --tail=20
    fi

    return 1
}

# 验证容器内文件
verify_container_files() {
    log_step "验证容器内文件结构..."

    # 根据部署模式确定容器名称
    local app_container="${CONTAINER_NAME}"
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        app_container="${CONTAINER_NAME}"
    fi

    # 检查容器是否运行
    if ! docker ps | grep -q "${app_container}"; then
        log_error "应用容器未运行"
        return 1
    fi

    # 验证工作目录
    log_info "检查容器工作目录..."
    docker exec "${app_container}" ls -la /app/ > /dev/null 2>&1 || {
        log_error "无法访问容器工作目录"
        return 1
    }

    # 验证templates目录
    log_info "检查templates目录..."
    if docker exec "${app_container}" ls -la /app/templates/ > /dev/null 2>&1; then
        log_info "✅ templates目录存在"

        # 检查关键模板文件
        local templates=("login.html" "error.html" "dashboard.html" "query.html")
        for template in "${templates[@]}"; do
            if docker exec "${app_container}" test -f "/app/templates/$template"; then
                log_info "✅ $template 存在"
            else
                log_error "❌ $template 不存在"
                return 1
            fi
        done
    else
        log_error "❌ templates目录不存在"
        return 1
    fi

    # 验证static目录
    log_info "检查static目录..."
    if docker exec "${app_container}" ls -la /app/static/ > /dev/null 2>&1; then
        log_info "✅ static目录存在"
    else
        log_error "❌ static目录不存在"
        return 1
    fi

    # 测试Flask应用能否正常导入
    log_info "测试Flask应用导入..."
    if docker exec "${app_container}" python -c "import app; print('Flask应用导入成功')" > /dev/null 2>&1; then
        log_info "✅ Flask应用导入成功"
    else
        log_error "❌ Flask应用导入失败"
        docker exec "${app_container}" python -c "import app; print('Flask应用导入成功')" || true
        return 1
    fi

    # 验证健康检查脚本
    if docker exec "${app_container}" python healthcheck.py > /dev/null 2>&1; then
        log_info "✅ 健康检查脚本正常"
    else
        log_warn "⚠️ 健康检查脚本可能有问题"
    fi

    log_info "容器内文件验证通过"
    return 0
}

# 修复当前运行的容器
fix_running_container() {
    log_step "修复当前运行的容器..."

    # 根据部署模式确定容器名称
    local app_container="${CONTAINER_NAME}"

    # 检查容器是否运行
    if ! docker ps | grep -q "${app_container}"; then
        log_error "应用容器未运行，无法修复"
        return 1
    fi

    log_info "发现运行中的容器，开始修复..."

    # 手动初始化数据库（使用正确的应用上下文）
    log_info "手动初始化数据库..."
    if docker exec "${app_container}" python -c "
from app import app, init_db
with app.app_context():
    if init_db():
        print('数据库初始化成功')
    else:
        print('数据库初始化失败')
" > /dev/null 2>&1; then
        log_info "✅ 数据库初始化完成"
    else
        log_warn "⚠️ 数据库可能已经初始化过"
    fi

    # 测试健康检查端点
    log_info "测试健康检查端点..."

    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        # 生产模式：测试HTTPS和HTTP
        if curl -f -s -k "https://localhost:${HTTPS_PORT}/" > /dev/null 2>&1; then
            log_info "✅ HTTPS健康检查通过"
            log_info "🌐 系统运行在生产模式 (HTTPS)"
            return 0
        elif curl -f -s "http://localhost:${HTTP_PORT}/" > /dev/null 2>&1; then
            log_info "✅ HTTP健康检查通过"
            log_info "🌐 系统运行在生产模式 (HTTP重定向)"
            return 0
        fi
    else
        # 开发模式：测试HTTP
        if curl -f -s "http://localhost:${APP_PORT}/" > /dev/null 2>&1; then
            log_info "✅ HTTP健康检查通过"
            log_info "🌐 系统运行在开发模式 (HTTP)"
            return 0
        fi
    fi

    log_error "❌ 健康检查失败"
    log_info "查看容器日志:"
    docker logs --tail=20 "${app_container}"
    return 1
}

# 初始化数据库
init_database() {
    log_step "初始化数据库..."

    # 根据部署模式确定容器名称
    local app_container="${CONTAINER_NAME}"

    sleep 5

    if docker exec "${app_container}" python -c "from app import app, init_db; app.app_context().push(); init_db(); print('数据库初始化完成')"; then
        log_info "数据库初始化完成"
    else
        log_warn "数据库可能已经初始化过"
    fi
}

# 显示结果
show_result() {
    echo ""
    echo -e "${CYAN}=========================================================="
    echo -e "    🎉 部署完成！卡密查询系统已启动"
    echo -e "==========================================================${NC}"
    echo ""

    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        echo -e "${GREEN}📱 访问地址 (生产模式):${NC}"
        echo "  🔒 HTTPS主页:     https://localhost:${HTTPS_PORT}"
        echo "  🔒 HTTPS管理后台: https://localhost:${HTTPS_PORT}/admin/login"
        echo "  🔒 HTTPS卡密查询: https://localhost:${HTTPS_PORT}/query"
        echo "  🌐 HTTP主页:      http://localhost:${HTTP_PORT} (自动重定向到HTTPS)"
        echo ""
        echo -e "${GREEN}🛠️  管理命令 (生产模式):${NC}"
        echo "  📊 查看状态: docker compose -f docker-compose.prod.yml ps"
        echo "  📋 查看应用日志: docker compose -f docker-compose.prod.yml logs card-query-app"
        echo "  📋 查看Nginx日志: docker compose -f docker-compose.prod.yml logs nginx"
        echo "  ⏹️  停止服务: docker compose -f docker-compose.prod.yml down"
        echo "  🔄 重启服务: docker compose -f docker-compose.prod.yml restart"
    else
        echo -e "${GREEN}📱 访问地址 (开发模式):${NC}"
        echo "  🌐 主页:        http://localhost:${APP_PORT}"
        echo "  🔐 管理后台:    http://localhost:${APP_PORT}/admin/login"
        echo "  🔍 卡密查询:    http://localhost:${APP_PORT}/query"
        echo ""
        echo -e "${GREEN}🛠️  管理命令 (开发模式):${NC}"
        echo "  📊 查看状态: docker compose ps"
        echo "  📋 查看日志: docker compose logs"
        echo "  ⏹️  停止服务: docker compose down"
        echo "  🔄 重启服务: docker compose restart"
    fi

    echo ""
    echo -e "${GREEN}🔑 默认账号:${NC}"
    echo "  👤 用户名: admin"
    echo "  🔒 密码:   admin123"
    echo ""
    echo -e "${GREEN}💾 数据文件:${NC}"
    echo "  📁 数据库: ./data/card_query.db"
    echo "  📋 应用日志: ./logs/app.log"
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        echo "  📋 Nginx日志: ./logs/nginx/"
        echo "  🔒 SSL证书: ./ssl/"
    fi
    echo "  💾 备份:   ./backups/"
    echo ""
    echo -e "${YELLOW}⚠️  重要提示:${NC}"
    echo "  1. 🔐 请立即修改默认管理员密码"
    echo "  2. 💾 定期备份数据库文件"
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        echo "  3. 🔒 当前使用自签名SSL证书，生产环境建议使用正式证书"
        echo "  4. 🌐 HTTP请求会自动重定向到HTTPS"
        echo "  5. 🔧 可通过修改.env文件调整配置"
    else
        echo "  3. 🌐 当前为开发模式，仅支持HTTP访问"
        echo "  4. 🚀 生产环境请使用生产模式部署"
    fi
    echo ""
    echo -e "${GREEN}🎉 部署成功！系统已准备就绪！${NC}"
    echo ""
}

# 主函数
main() {
    local start_time=$(date +%s)

    print_header

    # 根据模式和容器状态决定操作
    local container_running=false
    if docker ps | grep -q "${CONTAINER_NAME}"; then
        container_running=true
        log_info "检测到运行中的容器: ${CONTAINER_NAME}"
    fi

    # 处理不同模式
    case "${MODE:-auto}" in
        "fix")
            if [ "$container_running" = true ]; then
                log_info "执行修复模式..."
                if fix_running_container; then
                    show_result
                    local end_time=$(date +%s)
                    local duration=$((end_time - start_time))
                    echo -e "${CYAN}⏱️  修复耗时: ${duration} 秒${NC}"
                    return 0
                else
                    log_error "修复失败"
                    exit 1
                fi
            else
                log_error "没有运行中的容器可以修复"
                exit 1
            fi
            ;;
        "rebuild")
            log_info "执行强制重新部署模式..."
            ;;
        "quiet")
            if [ "$container_running" = true ]; then
                log_info "静默修复模式..."
                if fix_running_container; then
                    show_result
                    local end_time=$(date +%s)
                    local duration=$((end_time - start_time))
                    echo -e "${CYAN}⏱️  修复耗时: ${duration} 秒${NC}"
                    return 0
                else
                    log_warn "修复失败，执行完全重新部署"
                fi
            fi
            ;;
        "auto"|*)
            if [ "$container_running" = true ]; then
                echo ""
                echo "选择操作模式:"
                echo "1. 修复当前容器（推荐，快速）"
                echo "2. 完全重新部署（清理并重建）"
                echo ""
                read -p "请选择 [1/2]: " choice

                case $choice in
                    1)
                        log_info "选择修复模式..."
                        if fix_running_container; then
                            show_result
                            local end_time=$(date +%s)
                            local duration=$((end_time - start_time))
                            echo -e "${CYAN}⏱️  修复耗时: ${duration} 秒${NC}"
                            return 0
                        else
                            log_error "修复失败，将执行完全重新部署"
                            echo ""
                        fi
                        ;;
                    2)
                        log_info "选择完全重新部署模式..."
                        ;;
                    *)
                        log_info "无效选择，默认使用修复模式..."
                        if fix_running_container; then
                            show_result
                            local end_time=$(date +%s)
                            local duration=$((end_time - start_time))
                            echo -e "${CYAN}⏱️  修复耗时: ${duration} 秒${NC}"
                            return 0
                        else
                            log_error "修复失败，将执行完全重新部署"
                            echo ""
                        fi
                        ;;
                esac
            fi
            ;;
    esac

    # 执行完整部署步骤
    check_system
    verify_project_files
    choose_deployment_mode
    create_directories

    # 如果是生产模式，优先检测Let’s Encrypt证书；不存在则提示运行acme_issue；如需自签名可选择继续
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        # 证书预计在 ./letsencrypt/live/${DOMAIN}/ 下
        LE_CHAIN="./letsencrypt/live/${DOMAIN}/fullchain.pem"
        LE_KEY="./letsencrypt/live/${DOMAIN}/privkey.pem"
        if [ -f "$LE_CHAIN" ] && [ -f "$LE_KEY" ]; then
            log_info "检测到Let’s Encrypt证书，将直接使用：$LE_CHAIN $LE_KEY"
        else
            echo ""
            echo -e "${YELLOW}未检测到Let’s Encrypt证书：${NC}"
            echo "  1) 推荐：先运行一次 ACME 签发（DNS-01 / Dynadot）："
            echo "     docker compose -f docker-compose.acme.yml run --rm acme_issue"
            echo "  2) 或使用自签名证书（临时）：继续生成 ssl/cert.pem ssl/key.pem"
            echo ""
            read -p "是否现在生成自签名证书以继续部署? (y/N): " gen_self
            if [ "$gen_self" = "y" ] || [ "$gen_self" = "Y" ]; then
                generate_ssl_certificates
            else
                log_warn "建议先签发正式证书后再运行部署。"
            fi
        fi
    fi

    cleanup_old
    build_image
    start_service
    wait_service
    verify_container_files
    init_database

    # 显示结果
    show_result

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo -e "${CYAN}⏱️  总耗时: ${duration} 秒${NC}"
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help       显示此帮助信息"
    echo "  -f, --fix        仅修复当前运行的容器"
    echo "  -r, --rebuild    强制完全重新部署"
    echo "  -q, --quiet      静默模式（自动选择修复）"
    echo "  -d, --dev        强制使用开发模式"
    echo "  -p, --prod       强制使用生产模式"
    echo "  --domain DOMAIN  设置SSL证书域名（默认: localhost）"
    echo "  --http-port PORT 设置HTTP端口（默认: 80）"
    echo "  --https-port PORT 设置HTTPS端口（默认: 443）"
    echo ""
    echo "环境变量:"
    echo "  DOMAIN           SSL证书域名"
    echo "  HTTP_PORT        HTTP端口"
    echo "  HTTPS_PORT       HTTPS端口"
    echo "  APP_PORT         应用端口（开发模式，默认: 5000）"
    echo ""
    echo "示例:"
    echo "  $0                    # 交互式部署（选择模式）"
    echo "  $0 --dev              # 开发模式部署"
    echo "  $0 --prod             # 生产模式部署"
    echo "  $0 --prod --domain example.com  # 生产模式，指定域名"
    echo "  $0 --fix              # 仅修复当前容器"
    echo "  $0 --rebuild          # 强制重新部署"
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -f|--fix)
                MODE="fix"
                shift
                ;;
            -r|--rebuild)
                MODE="rebuild"
                shift
                ;;
            -q|--quiet)
                MODE="quiet"
                shift
                ;;
            -d|--dev)
                DEPLOYMENT_MODE="dev"
                shift
                ;;
            -p|--prod)
                DEPLOYMENT_MODE="prod"
                shift
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --http-port)
                HTTP_PORT="$2"
                shift 2
                ;;
            --https-port)
                HTTPS_PORT="$2"
                shift 2
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

# 子命令：certbot-init（Standalone模式签发Let’s Encrypt证书）
if [[ "$1" == "certbot-init" ]]; then
  shift
  # 默认值
  DOMAIN_ARG="${DOMAIN:-km.videox.xyz}"
  EMAIL_ARG="${ACME_EMAIL:-}" # 优先读 .env 中的 ACME_EMAIL

  # 解析可选参数
  while [[ $# -gt 0 ]]; do
    case $1 in
      --domain)
        DOMAIN_ARG="$2"; shift 2;;
      --email)
        EMAIL_ARG="$2"; shift 2;;
      *)
        log_warn "忽略未知参数: $1"; shift;;
    esac
  done

  if [[ -z "$EMAIL_ARG" ]]; then
    if [[ -f .env ]]; then
      # 从 .env 读取 ACME_EMAIL
      EMAIL_ARG=$(grep -E '^ACME_EMAIL=' .env | head -n1 | cut -d'=' -f2-)
    fi
  fi

  if [[ -z "$EMAIL_ARG" ]]; then
    log_error "未提供邮箱。用法: ./deploy.sh certbot-init --domain your.domain --email you@example.com（或在 .env 设置 ACME_EMAIL）"; exit 1
  fi

  log_step "使用 Certbot Standalone 签发证书: 域名=$DOMAIN_ARG 邮箱=$EMAIL_ARG"
  mkdir -p letsencrypt

  # 确保 80 端口空闲
  if lsof -i :80 -sTCP:LISTEN -P -n >/dev/null 2>&1; then
    log_error "80端口被占用，请先停止占用 80 的服务后重试"; exit 1
  fi

  docker run --rm -p 80:80 \
    -v "$(pwd)/letsencrypt:/etc/letsencrypt" \
    certbot/certbot certonly --standalone \
    -d "$DOMAIN_ARG" -d "www.$DOMAIN_ARG" \
    --email "$EMAIL_ARG" --agree-tos --non-interactive

  log_info "证书签发流程结束。路径: ./letsencrypt/live/$DOMAIN_ARG/"
  exit 0
fi

# 子命令：prod-oneclick（一键生产部署：签发证书 → 启动生产栈 → 启动续期）
if [[ "$1" == "prod-oneclick" ]]; then
  shift
  DOMAIN_ARG="${DOMAIN:-km.videox.xyz}"
  EMAIL_ARG="${ACME_EMAIL:-}"

  # 可选传参
  while [[ $# -gt 0 ]]; do
    case $1 in
      --domain)
        DOMAIN_ARG="$2"; shift 2;;
      --email)
        EMAIL_ARG="$2"; shift 2;;
      *)
        log_warn "忽略未知参数: $1"; shift;;
    esac
  done

  # 从 .env 读取邮箱（如未提供）
  if [[ -z "$EMAIL_ARG" && -f .env ]]; then
    EMAIL_ARG=$(grep -E '^ACME_EMAIL=' .env | head -n1 | cut -d'=' -f2-)
  fi
  if [[ -z "$EMAIL_ARG" ]]; then
    log_error "未提供邮箱。用法: ./deploy.sh prod-oneclick --domain your.domain --email you@example.com（或在 .env 设置 ACME_EMAIL）"; exit 1
  fi

  print_header
  check_system
  verify_project_files
  create_directories

  # 1) 证书检测/签发
  LE_CHAIN="./letsencrypt/live/$DOMAIN_ARG/fullchain.pem"
  LE_KEY="./letsencrypt/live/$DOMAIN_ARG/privkey.pem"
  if [[ -f "$LE_CHAIN" && -f "$LE_KEY" ]]; then
    log_info "检测到证书已存在，跳过签发：$LE_CHAIN"
  else
    log_step "[1/3] 签发Let’s Encrypt证书 (Standalone)"
    if lsof -i :80 -sTCP:LISTEN -P -n >/dev/null 2>&1; then
      log_error "80端口被占用，请先停止占用 80 的服务后重试"; exit 1
    fi
    mkdir -p letsencrypt
    docker run --rm -p 80:80 \
      -v "$(pwd)/letsencrypt:/etc/letsencrypt" \
      certbot/certbot certonly --standalone \
      -d "$DOMAIN_ARG" -d "www.$DOMAIN_ARG" \
      --email "$EMAIL_ARG" --agree-tos --non-interactive
  fi

  # 2) 启动生产栈
  log_step "[2/3] 启动生产栈 (Nginx + 应用)"
  docker compose -f docker-compose.prod.yml --env-file .env up -d --build

  # 3) 启动续期服务（webroot 模式）
  log_step "[3/3] 启动证书自动续期 (webroot)"
  docker compose -f docker-compose.certbot.yml up -d certbot_renew

  # 打印容器状态与关键日志指引
  log_info "容器状态："
  docker compose -f docker-compose.prod.yml ps
  echo ""
  log_info "查看Nginx日志: docker compose -f docker-compose.prod.yml logs -f nginx"
  log_info "查看应用日志: docker compose -f docker-compose.prod.yml logs -f card-query-app"

  log_info "一键生产部署完成： https://$DOMAIN_ARG/"
  exit 0
fi

}

# 错误处理
trap 'log_error "部署失败，请检查错误信息"; exit 1' ERR

# 解析参数并执行主函数
parse_args "$@"
main
