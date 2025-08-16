import os
import sys
import logging
import random
import time
import hashlib
import zipfile
import shutil
import glob
from datetime import datetime, timedelta, timezone
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
import secrets
import csv
import io
import json
from werkzeug.utils import secure_filename

# HTTPS配置
HTTPS_AVAILABLE = os.getenv('HTTPS_ENABLED', 'false').lower() == 'true'
FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'false').lower() == 'true'

def configure_https_app(app):
    """配置HTTPS相关设置"""
    if HTTPS_AVAILABLE or FORCE_HTTPS:
        # 强制HTTPS重定向中间件
        @app.before_request
        def force_https():
            if FORCE_HTTPS and not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
                # 排除健康检查和内部请求
                if request.endpoint not in ['health_check'] and not request.remote_addr in ['127.0.0.1', 'localhost']:
                    return redirect(request.url.replace('http://', 'https://'), code=301)

        # 设置安全头
        @app.after_request
        def set_security_headers(response):
            if HTTPS_AVAILABLE or FORCE_HTTPS:
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

            # 通用安全头（HTTP和HTTPS都需要）
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net"

            return response

    return app

def run_https_server(app, **kwargs):
    """运行HTTPS服务器"""
    if not HTTPS_AVAILABLE:
        return False

    try:
        import ssl
        cert_file = os.getenv('SSL_CERT_PATH', 'cert.pem')
        key_file = os.getenv('SSL_KEY_PATH', 'key.pem')

        if os.path.exists(cert_file) and os.path.exists(key_file):
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(cert_file, key_file)

            https_port = int(os.getenv('HTTPS_PORT', 443))
            logger.info(f"🔒 启动HTTPS服务器在端口 {https_port}")

            app.run(
                debug=kwargs.get('debug', False),
                host=kwargs.get('host', '0.0.0.0'),
                port=https_port,
                ssl_context=context,
                threaded=True
            )
            return True
        else:
            logger.warning(f"SSL证书文件不存在: {cert_file}, {key_file}")
            return False
    except Exception as e:
        logger.error(f"HTTPS服务器启动失败: {e}")
        return False

# 环境配置 - 必须在日志配置之前
ENV = os.getenv('FLASK_ENV', 'development')
DEBUG = ENV == 'development'

# 北京时间转换函数
def utc_to_beijing(utc_dt):
    """将UTC时间转换为北京时间"""
    if utc_dt is None:
        return None
    return utc_dt + timedelta(hours=8)

def utc_now():
    """获取当前UTC时间（替代已弃用的datetime.utcnow）"""
    return datetime.now(timezone.utc)

def beijing_now():
    """获取当前北京时间"""
    return utc_now() + timedelta(hours=8)

def reset_database_connection():
    """重置数据库连接"""
    try:
        # 关闭所有现有连接
        db.session.close()
        db.engine.dispose()

        # 重新创建所有表（如果不存在）
        with app.app_context():
            db.create_all()

        logger.info("数据库连接已重置")
        return True
    except Exception as e:
        logger.error(f"重置数据库连接失败: {e}")
        return False

def check_database_integrity():
    """检查数据库完整性"""
    try:
        # 简单检查数据库连接
        db.session.execute(db.text("SELECT 1")).close()
        logger.info("数据库结构检查通过")
        return True
    except Exception as e:
        logger.error(f"数据库完整性检查失败: {e}")
        return False

def format_beijing_time(utc_dt):
    """格式化UTC时间为北京时间字符串"""
    if utc_dt is None:
        return ''
    beijing_time = utc_to_beijing(utc_dt)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')




# 密码安全函数
def hash_password(password: str) -> str:
    """使用SHA-256哈希密码"""
    if not password:
        raise ValueError("密码不能为空")
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """验证密码"""
    if not password or not hashed:
        return False
    return hash_password(password) == hashed

def validate_password_strength(password: str) -> tuple[bool, str]:
    """验证密码强度"""
    if len(password) < 8:
        return False, "密码长度至少8位"

    if len(password) > 128:
        return False, "密码长度不能超过128位"

    # 检查是否包含数字
    if not any(c.isdigit() for c in password):
        return False, "密码必须包含至少一个数字"

    # 检查是否包含字母
    if not any(c.isalpha() for c in password):
        return False, "密码必须包含至少一个字母"

    # 检查常见弱密码
    weak_passwords = ['12345678', 'password', 'admin123', '11111111', '00000000']
    if password.lower() in weak_passwords:
        return False, "密码过于简单，请使用更复杂的密码"

    return True, "密码强度符合要求"

def sanitize_input(input_str: str, max_length: int = 255) -> str:
    """清理和验证输入"""
    if not input_str:
        return ""

    # 移除前后空格
    cleaned = input_str.strip()

    # 限制长度
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]

    # 移除潜在的危险字符
    import re
    cleaned = re.sub(r'[<>"\']', '', cleaned)

    return cleaned

# 简单的内存缓存
cache = {}
CACHE_TIMEOUT = 300  # 5分钟缓存

def get_cache(key):
    """获取缓存"""
    if key in cache:
        value, timestamp = cache[key]
        if time.time() - timestamp < CACHE_TIMEOUT:
            return value
        else:
            del cache[key]
    return None

def set_cache(key, value):
    """设置缓存"""
    cache[key] = (value, time.time())

def clear_cache_pattern(pattern):
    """清除匹配模式的缓存"""
    keys_to_delete = [key for key in cache.keys() if pattern in key]
    for key in keys_to_delete:
        del cache[key]

# 生产环境日志配置
import logging.handlers

# 配置日志
log_level = logging.DEBUG if DEBUG else logging.INFO
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# 创建日志目录
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

# 配置根日志记录器
logging.basicConfig(
    level=log_level,
    format=log_format,
    handlers=[
        logging.StreamHandler(),  # 控制台输出
        logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
    ]
)

logger = logging.getLogger(__name__)
logger.info(f"日志系统初始化完成，日志级别: {logging.getLevelName(log_level)}")

# 初始化 Flask app - 生产环境配置
app = Flask(__name__)

# 记录应用启动时间
app.start_time = time.time()

# HTTPS配置（启用HTTPS支持）
configure_https_app(app)

# 全局错误处理器
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404错误: {request.url} - IP: {request.remote_addr}")
    return render_template('error.html',
                         error_code=404,
                         error_message="页面未找到"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500错误: {request.url} - IP: {request.remote_addr} - Error: {error}")
    db.session.rollback()
    return render_template('error.html',
                         error_code=500,
                         error_message="服务器内部错误"), 500

@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f"403错误: {request.url} - IP: {request.remote_addr}")
    return render_template('error.html',
                         error_code=403,
                         error_message="访问被拒绝"), 403


# 向模板暴露常用格式化函数（在 app 初始化后）
@app.context_processor
def inject_formatters():
    return {
        'format_beijing_time': format_beijing_time
    }

# 确保数据目录存在
data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(data_dir, exist_ok=True)

# 默认SQLite数据库路径
default_db_path = f"sqlite:///{os.path.join(data_dir, 'card_query.db')}"

# 获取数据库URL - 优先使用SQLite
database_url = os.getenv('DATABASE_URL', default_db_path)

# 如果是PostgreSQL URL但希望使用SQLite，则覆盖
if os.getenv('USE_SQLITE', 'true').lower() == 'true':
    database_url = default_db_path

# 数据库连接配置优化
def get_engine_options():
    """根据数据库类型获取引擎配置"""
    if 'sqlite' in database_url:
        # SQLite配置
        return {
            'pool_timeout': 20,
            'pool_recycle': -1,
            'connect_args': {
                'check_same_thread': False,  # 允许多线程访问
                'timeout': 20  # 数据库锁超时
            }
        }
    else:
        # PostgreSQL配置
        base_options = {
            'pool_size': int(os.getenv('DB_POOL_SIZE', '10')),
            'pool_timeout': int(os.getenv('DB_POOL_TIMEOUT', '30')),
            'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', '3600')),
            'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', '20')),
            'pool_pre_ping': True,  # 启用连接预检查
        }

        if 'postgresql' in database_url:
            base_options['connect_args'] = {
                'connect_timeout': 10,
                'application_name': 'card_query_system',
                'options': '-c timezone=UTC'  # 设置时区为UTC
            }

        return base_options

app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS=get_engine_options(),
    DEBUG=DEBUG,
    # 会话配置 - 根据HTTPS状态动态配置
    SESSION_COOKIE_SECURE=HTTPS_AVAILABLE or FORCE_HTTPS,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax' if not (HTTPS_AVAILABLE or FORCE_HTTPS) else 'Strict',
    SESSION_COOKIE_NAME='card_query_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv('SESSION_TIMEOUT', '24'))),
    # 安全配置
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # CSRF令牌1小时有效
    # 上传限制
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
)
db = SQLAlchemy(app)

# 简单的请求频率限制
request_counts = {}
REQUEST_LIMIT = 100  # 每分钟最大请求数
TIME_WINDOW = 60  # 时间窗口（秒）

def check_rate_limit():
    """检查请求频率限制"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    current_time = time.time()

    # 清理过期记录
    expired_ips = [ip for ip, (count, timestamp) in request_counts.items()
                   if current_time - timestamp > TIME_WINDOW]
    for ip in expired_ips:
        del request_counts[ip]

    # 检查当前IP的请求频率
    if client_ip in request_counts:
        count, timestamp = request_counts[client_ip]
        if current_time - timestamp < TIME_WINDOW:
            if count >= REQUEST_LIMIT:
                return False
            request_counts[client_ip] = (count + 1, timestamp)
        else:
            request_counts[client_ip] = (1, current_time)
    else:
        request_counts[client_ip] = (1, current_time)

    return True

# 添加请求日志记录
@app.before_request
def log_request_info():
    """记录请求信息并检查频率限制"""
    # 跳过静态文件和健康检查的频率限制
    if request.endpoint not in ['static', 'health']:
        # 检查频率限制
        if not check_rate_limit():
            logger.warning(f"频率限制触发: {request.remote_addr} - {request.url}")
            return jsonify({'error': '请求过于频繁，请稍后重试'}), 429

        logger.info(f"请求: {request.method} {request.url} - IP: {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")

@app.after_request
def log_response_info(response):
    """记录响应信息"""
    if request.endpoint not in ['static', 'health']:
        logger.info(f"响应: {response.status_code} - {request.method} {request.url}")
    return response

# 添加安全头
@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    # 基础安全头
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # 内容安全策略
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp_policy

    # 权限策略
    response.headers['Permissions-Policy'] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )

    # 生产环境额外安全头
    if ENV == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Expect-CT'] = 'max-age=86400, enforce'

    # 缓存控制
    if request.endpoint in ['static']:
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    return response

# 简化表单定义 - 去除复杂验证
class LoginForm:
    def __init__(self):
        self.account = None
        self.password = None

    def validate_on_submit(self):
        self.account = request.form.get('account', '').strip()
        self.password = request.form.get('password', '').strip()
        return bool(self.account and self.password)

class AccountForm:
    def __init__(self):
        self.account = None
        self.new_account = None
        self.password = None
        self.action = None

    def validate_on_submit(self):
        self.account = request.form.get('account', '').strip()
        self.new_account = request.form.get('new_account', '').strip()
        self.password = request.form.get('password', '').strip()
        self.action = request.form.get('action', '').strip()

        if self.action == 'add':
            return bool(self.new_account and self.password)
        elif self.action == 'modify_random':
            return bool(self.account)
        return False

class BatchGenerateForm:
    def __init__(self):
        self.account = None
        self.count = None
        self.max_query_count = None
        self.duration_hours = None

    def validate_on_submit(self):
        self.account = request.form.get('account', '').strip()
        self.count = request.form.get('count', '').strip()
        self.max_query_count = request.form.get('max_query_count', '').strip()
        self.duration_hours = request.form.get('duration_hours', '').strip()

        try:
            self.count = int(self.count) if self.count else 0
            self.max_query_count = int(self.max_query_count) if self.max_query_count else 0
            self.duration_hours = int(self.duration_hours) if self.duration_hours else 0
            return bool(self.account and self.count > 0 and self.max_query_count > 0 and self.duration_hours > 0)
        except ValueError:
            return False

class ChangePasswordForm:
    def __init__(self):
        self.current_password = None
        self.new_password = None
        self.confirm_password = None

    def validate_on_submit(self):
        self.current_password = request.form.get('current_password', '').strip()
        self.new_password = request.form.get('new_password', '').strip()
        self.confirm_password = request.form.get('confirm_password', '').strip()
        return bool(self.current_password and self.new_password and
                   self.new_password == self.confirm_password)

class SmsVerificationForm:
    def __init__(self):
        self.phone = None
        self.code = None

    def validate_on_submit(self):
        self.phone = request.form.get('phone', '').strip()
        self.code = request.form.get('code', '').strip()
        return bool(self.phone and self.code and len(self.phone) == 11 and len(self.code) == 6)

# 简化数据模型
# 数据模型 - SQLite兼容性优化
class Admin(db.Model):
    __tablename__ = 'admins'
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(255), nullable=False)   # 支持哈希密码
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Account(db.Model):
    __tablename__ = 'accounts'
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(255), nullable=False)   # 支持长密码
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    vip_expiry = db.Column(db.DateTime, default=lambda: utc_now() + timedelta(days=30), nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    notes = db.Column(db.Text, nullable=True, default='')  # 备注字段

    def __repr__(self):
        return f'<Account {self.username}>'

class Card(db.Model):
    __tablename__ = 'cards'
    card_key = db.Column(db.String(16), primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('accounts.username', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    first_used_at = db.Column(db.DateTime, nullable=True, index=True)
    query_count = db.Column(db.Integer, default=0, nullable=False)
    max_query_count = db.Column(db.Integer, default=10, nullable=False)
    duration_hours = db.Column(db.Integer, default=720, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # 添加关系
    account = db.relationship('Account', backref=db.backref('cards', lazy=True, cascade='all, delete-orphan'))

    def __repr__(self):
        return f'<Card {self.card_key}>'

    @property
    def is_expired(self):
        """检查卡密是否已过期"""
        if not self.first_used_at:
            return False
        expiry_time = self.first_used_at + timedelta(hours=self.duration_hours)
        return utc_now().replace(tzinfo=None) > expiry_time

    @property
    def remaining_queries(self):
        """获取剩余查询次数"""
        return max(0, self.max_query_count - self.query_count)



class SmsVerification(db.Model):
    __tablename__ = 'sms_verifications'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    phone = db.Column(db.String(15), nullable=False, index=True)  # 支持国际号码格式
    code = db.Column(db.String(10), nullable=False)  # 支持更长验证码
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    is_used = db.Column(db.Boolean, default=False, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)  # 支持IPv6



# 说明栏模型 - 用于查询页面显示使用说明和验证码提示
class Notice(db.Model):
    __tablename__ = 'query_notices'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(200), nullable=False, default='使用说明')
    content = db.Column(db.Text, nullable=False, default='请输入卡密进行查询')
    captcha_notice = db.Column(db.Text, nullable=False, default='点击"查看验证码"获取最新的6位验证码')
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

# 提取记录模型 - 记录每个卡密被提取的时间与操作者，防止重复提取
class ExtractionRecord(db.Model):
    __tablename__ = 'extraction_records'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    card_key = db.Column(db.String(16), db.ForeignKey('cards.card_key', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    assigned_account = db.Column(db.String(50), nullable=True, index=True)
    extracted_by = db.Column(db.String(50), nullable=False)
    extracted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

# 轻量级Schema自修复，兼容旧备份数据库
# 仅在SQLite下执行需要的ADD COLUMN操作，避免引入外部迁移依赖

def ensure_schema():
    try:
        # 仅针对SQLite执行
        if not str(db.engine.url).startswith('sqlite'):  # 其他数据库可扩展
            return
        from sqlalchemy import text
        with db.engine.connect() as conn:
            # accounts.notes 列（旧库缺少）
            cols = [row[1] for row in conn.execute(text('PRAGMA table_info(accounts);'))]
            if 'notes' not in cols:
                conn.execute(text("ALTER TABLE accounts ADD COLUMN notes TEXT DEFAULT ''"))
                logger.info("已为旧数据库添加列: accounts.notes")
            # extraction_records 表
            rec_cols = [row[1] for row in conn.execute(text('PRAGMA table_info(extraction_records);'))]
            if not rec_cols:
                conn.execute(text('''
                    CREATE TABLE IF NOT EXISTS extraction_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        card_key VARCHAR(16) NOT NULL UNIQUE,
                        assigned_account VARCHAR(50),
                        extracted_by VARCHAR(50) NOT NULL,
                        extracted_at DATETIME NOT NULL
                    )
                '''))
                logger.info("已创建表: extraction_records")
    except Exception as e:
        logger.error(f"ensure_schema 失败: {e}")

# 简化助手函数
def generate_card_key() -> str:
    """生成固定16位卡密，数字+小写字母组合，避免混淆字符"""
    import random

    # 数字：去除 0, 1
    digits = '23456789'
    # 小写字母：去除 o, i, l, q, g
    lowercase = 'abcdefhjkmnprstuvwxyz'

    # 卡密固定16位，数字和小写字母组合
    characters = digits + lowercase
    return ''.join(random.choice(characters) for _ in range(16))

def generate_random_password(length: int = 12) -> str:
    """生成账号密码，大写+小写+数字，避免混淆字符"""
    import random

    # 数字：去除 0, 1, 9
    digits = '23456789'
    # 小写字母：去除 o, i, l, q, g
    lowercase = 'abcdefhjkmnprstuvwxyz'
    # 大写字母：去除 O, I, L, Q, G
    uppercase = 'ABCDEFHJKMNPRSTUVWXYZ'

    # 确保至少包含每种字符类型
    password = []
    password.append(random.choice(digits))      # 至少1个数字
    password.append(random.choice(lowercase))   # 至少1个小写字母
    password.append(random.choice(uppercase))   # 至少1个大写字母

    # 剩余位数随机选择
    all_chars = digits + lowercase + uppercase
    for _ in range(length - 3):
        password.append(random.choice(all_chars))

    # 打乱顺序
    random.shuffle(password)
    return ''.join(password)

def check_admin_credentials(account: str, password: str) -> bool:
    """验证管理员凭据"""
    logger.info(f"验证管理员凭据: {account}")

    admin = Admin.query.filter_by(username=account).first()
    if not admin:
        logger.warning(f"管理员账号不存在: {account}")
        return False

    logger.info(f"找到管理员账号: {account}, 密码长度: {len(admin.password)}")

    # 兼容旧的明文密码和新的哈希密码
    password_valid = False
    if len(admin.password) == 64:  # SHA-256哈希长度
        logger.info(f"使用哈希密码验证: {account}")
        password_valid = verify_password(password, admin.password)
    else:
        logger.info(f"使用明文密码验证: {account}")
        # 明文密码，验证后转换为哈希
        if admin.password == password:
            logger.info(f"明文密码验证成功: {account}")
            password_valid = True
            # 自动升级为哈希密码
            admin.password = hash_password(password)
            try:
                db.session.commit()
                logger.info(f"管理员 {account} 密码已升级为哈希格式")
            except Exception as e:
                logger.error(f"密码升级失败: {e}")
                db.session.rollback()
        else:
            logger.warning(f"明文密码验证失败: {account}")

    if password_valid:
        logger.info(f"管理员 {account} 密码验证成功")
        # 更新最后登录时间
        admin.last_login = utc_now()
        try:
            db.session.commit()
            logger.info(f"管理员 {account} 登录时间已更新")
        except Exception as e:
            logger.error(f"更新管理员登录时间失败: {e}")
            db.session.rollback()
        return True
    else:
        logger.warning(f"管理员 {account} 密码验证失败")
        return False

def ensure_admin_session():
    logger.info(f"检查管理员会话，当前session: {dict(session)}")
    if 'admin' not in session:
        logger.warning("管理员会话不存在，重定向到登录页面")
        return redirect(url_for('login'))
    logger.info(f"管理员会话有效: {session['admin']}")
    return None

def flash_message(message: str, category: str = 'success') -> None:
    flash(message, category)

def get_card_usage_info(username: str) -> str:
    """获取账号的卡密使用信息，返回格式：已使用/总数"""
    cache_key = f"card_usage_{username}"
    cached_result = get_cache(cache_key)
    if cached_result:
        return cached_result

    try:
        # 使用更高效的查询
        total_count = Card.query.filter_by(username=username).count()
        used_count = Card.query.filter_by(username=username).filter(Card.query_count > 0).count()

        result = f"{used_count}/{total_count}"
        set_cache(cache_key, result)
        return result
    except Exception as e:
        logger.error(f"获取卡密使用信息失败: {e}")
        return "0/0"

def auto_delete_expired_cards():
    """自动删除到期7天后的卡密"""
    try:
        # 计算7天前的时间（移除时区信息以匹配数据库格式）
        seven_days_ago = utc_now().replace(tzinfo=None) - timedelta(days=7)

        # 查找需要删除的卡密（已使用且到期超过7天的）
        # 使用数据库无关的时间计算方式
        expired_cards = []

        # 获取所有已使用的卡密
        used_cards = Card.query.filter(Card.first_used_at.isnot(None)).all()

        for card in used_cards:
            # 计算过期时间
            expiry_time = card.first_used_at + timedelta(hours=card.duration_hours)
            # 检查是否过期超过7天
            if expiry_time < seven_days_ago:
                expired_cards.append(card)

        deleted_count = 0
        for card in expired_cards:
            db.session.delete(card)
            deleted_count += 1

        if deleted_count > 0:
            db.session.commit()
            logger.info(f"自动删除了 {deleted_count} 个过期卡密")

        return deleted_count
    except Exception as e:
        logger.error(f"自动删除过期卡密失败: {e}")
        db.session.rollback()
        return 0

# 短信验证码功能
def generate_sms_code():
    """生成6位数字验证码"""
    return str(random.randint(100000, 999999))

def send_sms_code(phone, code):
    """发送短信验证码（模拟实现）"""
    # 这里应该集成真实的短信服务商API
    # 比如阿里云短信、腾讯云短信等
    logger.info(f"模拟发送短信验证码到 {phone}: {code}")

    # 模拟发送成功
    return True

def create_sms_verification(phone, ip_address=None):
    """创建短信验证码记录"""
    try:
        # 检查频率限制（同一手机号1分钟内只能发送一次）
        one_minute_ago = utc_now() - timedelta(minutes=1)
        recent_sms = SmsVerification.query.filter(
            SmsVerification.phone == phone,
            SmsVerification.created_at > one_minute_ago
        ).first()

        if recent_sms:
            return False, "发送过于频繁，请稍后再试"

        # 生成验证码
        code = generate_sms_code()
        expires_at = utc_now() + timedelta(minutes=5)  # 5分钟有效期

        # 保存到数据库
        sms_record = SmsVerification(
            phone=phone,
            code=code,
            expires_at=expires_at,
            ip_address=ip_address
        )
        db.session.add(sms_record)
        db.session.commit()

        # 发送短信
        if send_sms_code(phone, code):
            return True, "验证码发送成功"
        else:
            # 发送失败，删除记录
            db.session.delete(sms_record)
            db.session.commit()
            return False, "短信发送失败，请稍后重试"

    except Exception as e:
        logger.error(f"创建短信验证码失败: {e}")
        return False, "系统错误，请稍后重试"

def verify_sms_code(phone, code):
    """验证短信验证码"""
    try:
        # 查找有效的验证码
        sms_record = SmsVerification.query.filter(
            SmsVerification.phone == phone,
            SmsVerification.code == code,
            SmsVerification.is_used == False,
            SmsVerification.expires_at > utc_now().replace(tzinfo=None)
        ).first()

        if not sms_record:
            return False, "验证码无效或已过期"

        # 标记为已使用
        sms_record.is_used = True
        db.session.commit()

        return True, "验证成功"

    except Exception as e:
        logger.error(f"验证短信验证码失败: {e}")
        return False, "验证失败，请重试"

# 简化路由
@app.route('/')
def index():
    """根路径 - 智能重定向"""
    # 如果已经是管理员登录状态，跳转到仪表盘
    if session.get('admin'):
        return redirect(url_for('admin_dashboard'))
    # 否则跳转到查询页面
    else:
        return redirect(url_for('query'))

@app.route('/health', methods=['GET'])
def health():
    """健康检查端点 - 提供详细的系统状态信息"""
    health_data = {
        "status": "healthy",
        "timestamp": utc_now().isoformat(),
        "uptime": time.time() - app.start_time if hasattr(app, 'start_time') else 0,
        "version": "1.0.0",
        "environment": ENV
    }

    # 数据库连接检查
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        health_data["database"] = {
            "status": "connected",
            "type": "postgresql" if 'postgresql' in database_url else "sqlite"
        }
    except Exception as e:
        health_data["database"] = {
            "status": "disconnected",
            "error": str(e)
        }
        health_data["status"] = "unhealthy"

    # 系统统计
    try:
        health_data["statistics"] = {
            "total_accounts": Account.query.count(),
            "total_cards": Card.query.count(),
            "active_cards": Card.query.filter_by(is_active=True).count(),
            "cache_size": len(cache)
        }
    except Exception as e:
        health_data["statistics"] = {"error": str(e)}

    # 可用路由
    health_data["routes"] = [
        "/",
        "/admin/login",
        "/admin",
        "/query",
        "/health"
    ]

    status_code = 200 if health_data["status"] == "healthy" else 503
    return jsonify(health_data), status_code

@app.route('/admin/debug_status')
def debug_status():
    """调试状态页面 - 帮助诊断导入和显示问题"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 获取数据库统计
        total_accounts = Account.query.count()
        total_cards = Card.query.count()

        # 获取最近的账号（按创建时间倒序）
        recent_accounts = Account.query.order_by(Account.created_at.desc()).limit(10).all()

        debug_info = {
            'database_stats': {
                'total_accounts': total_accounts,
                'total_cards': total_cards,
                'database_url': os.getenv('DATABASE_URL', 'sqlite:///card_system.db')[:50] + '...'
            },
            'recent_accounts': [
                {
                    'username': acc.username,
                    'password': acc.password[:10] + '...' if len(acc.password) > 10 else acc.password,
                    'created_at': acc.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'notes': acc.notes or '无备注',
                    'is_active': acc.is_active
                }
                for acc in recent_accounts
            ],
            'session_info': {
                'admin': session.get('admin'),
                'session_keys': list(session.keys()),
                'has_admin_session': bool(session.get('admin'))
            },
            'system_info': {
                'timestamp': utc_now().strftime('%Y-%m-%d %H:%M:%S'),
                'debug_mode': app.debug,
                'environment': os.getenv('ENV', 'development')
            }
        }

        return jsonify(debug_info)

    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': utc_now().strftime('%Y-%m-%d %H:%M:%S')
        }), 500

@app.route('/test')
def test():
    """测试页面，用于验证应用是否正常工作"""
    # 检查数据库状态
    db_status = "❌ 未连接"
    admin_exists = False
    account_count = 0

    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        db_status = "✅ 已连接"

        # 检查管理员账号是否存在
        admin = Admin.query.filter_by(username='admin').first()
        admin_exists = admin is not None

        # 检查账号数量
        account_count = Account.query.count()

    except Exception as e:
        db_status = f"❌ 连接失败: {str(e)}"

    return f"""
    <html>
    <head><title>卡密查询系统 - 测试页面</title></head>
    <body style="font-family: Arial, sans-serif; margin: 40px;">
        <h1>🎉 卡密查询系统运行正常！</h1>
        <p><strong>当前时间:</strong> {beijing_now().strftime('%Y-%m-%d %H:%M:%S')} 北京时间</p>
        <p><strong>应用状态:</strong> ✅ 正常运行</p>
        <p><strong>数据库状态:</strong> {db_status}</p>
        <p><strong>管理员账号:</strong> {'✅ 已创建' if admin_exists else '❌ 未创建'}</p>
        <p><strong>账号数量:</strong> {account_count}</p>

        <h2>🔗 可用链接:</h2>
        <ul>
            <li><a href="/">首页 (重定向到登录)</a></li>
            <li><a href="/admin/login">管理员登录</a></li>
            <li><a href="/query">卡密查询</a></li>
            <li><a href="/health">健康检查 (API)</a></li>
            <li><a href="/init-db">初始化数据库</a></li>
        </ul>

        <h2>🔧 管理员信息:</h2>
        <p><strong>用户名:</strong> admin</p>
        <p><strong>密码:</strong> admin123</p>

        <h2>✨ 最新更新:</h2>
        <ul>
            <li>✅ 账号管理页面现在显示密码</li>
            <li>✅ 密码旁边有复制按钮</li>
            <li>✅ 默认操作改为修改密码</li>
            <li>✅ 改进了复制功能的兼容性</li>
        </ul>

        <p><em>如果您看到此页面，说明应用已成功部署并运行！</em></p>

        {'<p style="color: red;"><strong>⚠️ 如果管理员账号未创建，请点击 <a href="/init-db">初始化数据库</a></strong></p>' if not admin_exists else ''}
    </body>
    </html>
    """





@app.route('/init-db')
def init_database_route():
    """手动初始化数据库的路由"""
    try:
        if init_db():
            return """
            <html>
            <head><title>数据库初始化成功</title></head>
            <body style="font-family: Arial, sans-serif; margin: 40px;">
                <h1>✅ 数据库初始化成功！</h1>
                <p>数据库表已创建，默认管理员账号已设置。</p>
                <p><strong>管理员账号:</strong> admin</p>
                <p><strong>管理员密码:</strong> admin123</p>
                <p><a href="/admin/login">立即登录</a> | <a href="/test">返回测试页面</a></p>
            </body>
            </html>
            """
        else:
            return """
            <html>
            <head><title>数据库初始化失败</title></head>
            <body style="font-family: Arial, sans-serif; margin: 40px;">
                <h1>❌ 数据库初始化失败！</h1>
                <p>请检查数据库连接和配置。</p>
                <p><a href="/test">返回测试页面</a></p>
            </body>
            </html>
            """
    except Exception as e:
        return f"""
        <html>
        <head><title>数据库初始化错误</title></head>
        <body style="font-family: Arial, sans-serif; margin: 40px;">
            <h1>❌ 数据库初始化错误！</h1>
            <p>错误信息: {str(e)}</p>
            <p><a href="/test">返回测试页面</a></p>
        </body>
        </html>
        """

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"400错误: {request.url} - {error}")
    return render_template('error.html', error='请求参数错误'), 400

@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"403错误: {request.url} - {request.remote_addr}")
    return render_template('error.html', error='访问被拒绝'), 403

@app.errorhandler(404)
def not_found(error):
    logger.info(f"404错误: {request.url} - {request.remote_addr}")
    return render_template('error.html', error='页面未找到'), 404

@app.errorhandler(429)
def too_many_requests(error):
    logger.warning(f"429错误: {request.url} - {request.remote_addr}")
    return render_template('error.html', error='请求过于频繁，请稍后重试'), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500错误: {request.url} - {error}", exc_info=True)
    db.session.rollback()  # 回滚数据库事务
    return render_template('error.html', error='服务器内部错误，请稍后重试'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    # 记录未捕获的异常
    logger.error(f"未捕获的异常: {request.url} - {e}", exc_info=True)
    db.session.rollback()
    return render_template('error.html', error='系统错误，请稍后重试'), 500

@app.route('/admin', methods=['GET'])
def admin():
    if redirect_response := ensure_admin_session():
        return redirect_response
    # 重定向到新的仪表盘
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        logger.info(f"收到登录请求，表单数据: account={request.form.get('account')}")

        if form.validate_on_submit():
            logger.info(f"表单验证通过，账号: {form.account}")

            if check_admin_credentials(form.account, form.password):
                logger.info(f"管理员 {form.account} 登录成功")
                session['admin'] = form.account
                logger.info(f"会话已设置: {dict(session)}")
                return redirect(url_for('admin'))
            else:
                logger.warning(f"管理员 {form.account} 登录失败：密码错误")
                flash_message('账号或密码错误', 'danger')
        else:
            logger.warning(f"表单验证失败，账号: {request.form.get('account')}, 密码长度: {len(request.form.get('password', ''))}")
            flash_message('请输入账号和密码', 'danger')

    return render_template('login.html', form=form)

@app.route('/admin/logout', methods=['GET'])
def logout():
    session.pop('admin', None)
    flash_message('已退出登录')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    """管理员仪表盘"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 获取统计数据
        total_accounts = Account.query.count()
        active_accounts = Account.query.filter_by(is_active=True).count()
        total_cards = Card.query.count()
        used_cards = Card.query.filter(Card.first_used_at.isnot(None)).count()
        unused_cards = total_cards - used_cards

        # 获取最近7天的数据
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        recent_accounts = Account.query.filter(Account.created_at >= seven_days_ago).count()
        recent_cards = Card.query.filter(Card.created_at >= seven_days_ago).count()

        # 获取即将到期的VIP账号（7天内）
        seven_days_later = now + timedelta(days=7)
        expiring_accounts = Account.query.filter(
            Account.vip_expiry <= seven_days_later,
            Account.vip_expiry >= now,
            Account.is_active == True
        ).count()

        stats = {
            'total_accounts': total_accounts,
            'active_accounts': active_accounts,
            'total_cards': total_cards,
            'used_cards': used_cards,
            'unused_cards': unused_cards,
            'recent_accounts': recent_accounts,
            'recent_cards': recent_cards,
            'expiring_accounts': expiring_accounts
        }

        return render_template('dashboard.html', stats=stats)

    except Exception as e:
        logger.error(f"获取仪表盘数据失败: {e}")
        flash_message('获取统计数据失败', 'danger')
        return render_template('dashboard.html', stats={})

@app.route('/admin/accounts', methods=['GET', 'POST'])
def accounts():
    if redirect_response := ensure_admin_session():
        return redirect_response
    form = AccountForm()

    if request.method == 'POST':
        action = request.form.get('action')
        account_name = request.form.get('account')
        new_account = request.form.get('new_account')
        password = request.form.get('password')
        vip_expiry_str = request.form.get('vip_expiry')

        if action == 'add' and new_account and password:
            # 验证输入
            if len(new_account.strip()) < 3:
                flash_message('账号名至少3个字符', 'danger')
            elif len(password.strip()) < 6:
                flash_message('密码至少6个字符', 'danger')
            elif Account.query.filter_by(username=new_account.strip()).first():
                flash_message('账号已存在', 'danger')
            else:
                try:
                    # 默认VIP 1个月
                    vip_expiry = utc_now() + timedelta(days=30)
                    account = Account(
                        username=new_account.strip(),
                        password=password.strip(),
                        created_at=utc_now(),
                        vip_expiry=vip_expiry
                    )
                    db.session.add(account)
                    db.session.commit()
                    # 清理相关缓存
                    clear_cache_pattern(f"card_usage_{new_account.strip()}")
                    flash_message(f'账号 {new_account.strip()} 添加成功，VIP到期时间：{format_beijing_time(vip_expiry)}', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash_message(f'数据库错误：{str(e)}', 'danger')
        elif action == 'add':
            flash_message('请填写完整的账号信息', 'danger')

        elif action == 'modify_random' and account_name:
            account = Account.query.filter_by(username=account_name).first()
            if account:
                new_password = generate_random_password()  # 使用密码生成函数
                account.password = new_password
                db.session.commit()
                flash_message(f'账号 {account_name} 密码已重置为: {new_password}')
            else:
                flash_message('账号不存在', 'danger')

        elif action == 'edit_vip' and account_name and vip_expiry_str:
            account = Account.query.filter_by(username=account_name).first()
            if account:
                try:
                    # 解析时间字符串
                    vip_expiry = datetime.fromisoformat(vip_expiry_str.replace('T', ' '))
                    account.vip_expiry = vip_expiry
                    db.session.commit()
                    flash_message(f'账号 {account_name} VIP到期时间已更新为: {format_beijing_time(vip_expiry)}')
                except ValueError:
                    flash_message('时间格式错误', 'danger')
                except Exception as e:
                    db.session.rollback()
                    flash_message('数据库错误，请稍后重试', 'danger')
            else:
                flash_message('账号不存在', 'danger')

        # 导入功能已移至 /admin/import_accounts 路由

    # 简化账号列表显示
    accounts_list = Account.query.all()
    account_list = [
        {
            'index': i + 1,
            'username': account.username,  # 统一使用username字段
            'password': account.password,  # 添加密码显示
            'created_at': format_beijing_time(account.created_at),
            'vip_expiry': format_beijing_time(account.vip_expiry) if account.vip_expiry else '未设置',
            'card_count': get_card_usage_info(account.username),
            'notes': account.notes or '',  # 添加备注字段
            'is_active': account.is_active  # 添加活跃状态
        }
        for i, account in enumerate(accounts_list)
    ]
    return render_template('accounts_dashboard.html', accounts=account_list)

@app.route('/admin/export_accounts', methods=['GET'])
def export_accounts():
    """导出账号数据为CSV格式"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        from flask import make_response
        import csv
        from io import StringIO

        # 获取所有账号数据
        accounts_list = Account.query.all()

        # 创建CSV内容
        output = StringIO()
        writer = csv.writer(output)

        # 写入表头
        writer.writerow(['账号', '密码', '创建时间', 'VIP到期时间', '状态', '备注'])

        # 写入数据
        for account in accounts_list:
            status = '正常' if account.is_active else '禁用'
            writer.writerow([
                account.username,
                account.password,
                format_beijing_time(account.created_at),
                format_beijing_time(account.vip_expiry) if account.vip_expiry else '未设置',
                status,
                account.notes or ''
            ])

        # 创建响应
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'

        # 生成文件名（使用URL编码避免中文问题）
        from datetime import datetime
        from urllib.parse import quote
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        filename = f'accounts_data_{timestamp}.csv'
        filename_encoded = quote(filename.encode('utf-8'))
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{filename_encoded}'

        return response

    except Exception as e:
        logger.error(f"导出账号失败: {str(e)}")
        flash_message('导出失败，请稍后重试', 'danger')
        return redirect(url_for('accounts'))

@app.route('/admin/import_accounts', methods=['POST'])
def import_accounts():
    """导入账号数据"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        import csv
        from io import StringIO

        # 检查是否有上传文件
        if 'import_file' not in request.files:
            flash_message('请选择要导入的文件', 'danger')
            return redirect(url_for('accounts'))

        file = request.files['import_file']
        if file.filename == '':
            flash_message('请选择要导入的文件', 'danger')
            return redirect(url_for('accounts'))

        # 检查文件类型
        if not file.filename.lower().endswith('.csv'):
            flash_message('只支持CSV格式文件', 'danger')
            return redirect(url_for('accounts'))

        # 读取文件内容，处理编码问题
        try:
            content = file.read().decode('utf-8')
        except UnicodeDecodeError:
            try:
                file.seek(0)
                content = file.read().decode('gbk')
            except UnicodeDecodeError:
                flash_message('文件编码错误，请使用UTF-8或GBK编码保存CSV文件', 'danger')
                return redirect(url_for('accounts'))

        csv_reader = csv.reader(StringIO(content))

        # 跳过表头
        headers = next(csv_reader, None)
        if not headers:
            flash_message('文件格式错误：文件为空', 'danger')
            return redirect(url_for('accounts'))

        # 验证表头格式（支持多种格式）
        expected_headers = ['账号', '密码', '创建时间', 'VIP到期时间', '状态', '备注']
        alternative_headers = ['username', 'password', 'created_time', 'vip_expiry', 'status', 'notes']

        # 清理表头（去除空格和特殊字符）
        cleaned_headers = [h.strip() for h in headers]

        # 检查是否匹配任一格式
        if cleaned_headers != expected_headers and cleaned_headers != alternative_headers:
            # 尝试部分匹配（至少包含账号和密码）
            if len(cleaned_headers) < 2 or not any('账号' in h or 'username' in h.lower() for h in cleaned_headers):
                flash_message(f'文件格式错误：表头应包含账号和密码字段。当前表头：{", ".join(cleaned_headers)}', 'danger')
                return redirect(url_for('accounts'))
            else:
                # 记录表头不完全匹配的警告
                logger.warning(f"表头格式不标准，当前：{cleaned_headers}，期望：{expected_headers}")
                flash_message(f'表头格式不标准，将尝试解析。建议使用标准格式：{", ".join(expected_headers)}', 'warning')

        # 统计信息
        success_count = 0
        error_count = 0
        skip_count = 0
        errors = []

        # 逐行处理数据
        for row_num, row in enumerate(csv_reader, start=2):
            try:
                # 跳过空行
                if not row or all(not cell.strip() for cell in row):
                    continue

                # 确保至少有2列（账号和密码）
                if len(row) < 2:
                    error_count += 1
                    errors.append(f'第{row_num}行：数据不完整，至少需要账号和密码')
                    continue

                # 灵活解析数据，支持不同列数
                username = row[0].strip() if len(row) > 0 else ''
                password = row[1].strip() if len(row) > 1 else ''
                created_time_str = row[2].strip() if len(row) > 2 else ''
                vip_expiry_str = row[3].strip() if len(row) > 3 else ''
                status = row[4].strip() if len(row) > 4 else '正常'
                note = row[5].strip() if len(row) > 5 else ''

                # 验证必填字段
                if not username.strip() or not password.strip():
                    error_count += 1
                    errors.append(f'第{row_num}行：账号或密码不能为空')
                    continue

                # 检查账号是否已存在
                existing_account = Account.query.filter_by(username=username.strip()).first()
                if existing_account:
                    skip_count += 1
                    continue

                # 解析时间
                try:
                    # 创建时间
                    if created_time_str and created_time_str != '未设置':
                        created_at = datetime.strptime(created_time_str, '%Y-%m-%d %H:%M:%S')
                    else:
                        created_at = utc_now()

                    # VIP到期时间
                    if vip_expiry_str and vip_expiry_str != '未设置':
                        vip_expiry = datetime.strptime(vip_expiry_str, '%Y-%m-%d %H:%M:%S')
                    else:
                        vip_expiry = utc_now() + timedelta(days=30)

                except ValueError as e:
                    error_count += 1
                    errors.append(f'第{row_num}行：时间格式错误')
                    continue

                # 创建账号
                account = Account(
                    username=username.strip(),
                    password=password.strip(),
                    created_at=created_at,
                    vip_expiry=vip_expiry,
                    is_active=(status == '正常'),
                    notes=note.strip() if note else None
                )

                db.session.add(account)
                success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f'第{row_num}行：{str(e)}')

        # 提交数据库更改
        if success_count > 0:
            try:
                db.session.commit()
                logger.info(f"管理员 {session['admin']} 导入账号：成功{success_count}个，跳过{skip_count}个，错误{error_count}个")
                flash_message(f'导入完成！成功：{success_count}，跳过：{skip_count}，错误：{error_count}', 'success')
            except Exception as e:
                db.session.rollback()
                logger.error(f"账号导入数据库提交失败: {str(e)}")
                flash_message(f'数据库错误：{str(e)}', 'danger')
        else:
            logger.warning(f"管理员 {session['admin']} 账号导入失败：没有成功导入任何数据，跳过{skip_count}个，错误{error_count}个")
            flash_message('没有成功导入任何数据', 'warning')

        # 显示错误详情（最多显示前5个错误）
        if errors:
            error_msg = '错误详情：' + '；'.join(errors[:5])
            if len(errors) > 5:
                error_msg += f'...（还有{len(errors)-5}个错误）'
            flash_message(error_msg, 'warning')

    except Exception as e:
        logger.error(f"账号导入失败: {str(e)}")
        flash_message(f'导入失败：{str(e)}', 'danger')

    return redirect(url_for('accounts'))

@app.route('/admin/batch_update_accounts', methods=['POST'])
def batch_update_accounts():
    """批量更新账号"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '请求数据为空'})

        usernames = data.get('usernames', [])
        operation = data.get('operation', '')

        if not usernames:
            return jsonify({'success': False, 'message': '未选择任何账号'})

        if not operation:
            return jsonify({'success': False, 'message': '未选择操作类型'})

        success_count = 0
        error_count = 0
        errors = []

        if operation == 'randomPassword':
            # 批量随机密码
            for username in usernames:
                try:
                    account = Account.query.filter_by(username=username).first()
                    if not account:
                        error_count += 1
                        errors.append(f'账号 {username} 不存在')
                        continue

                    # 生成随机密码（使用与单个修改相同的规则）
                    new_password = generate_random_password()

                    account.password = new_password
                    success_count += 1

                except Exception as e:
                    error_count += 1
                    errors.append(f'账号 {username} 更新失败: {str(e)}')
                    continue

            try:
                db.session.commit()
                logger.info(f"管理员 {session['admin']} 批量修改了 {success_count} 个账号的密码")

                result_message = f'成功修改 {success_count} 个账号的密码'
                if error_count > 0:
                    result_message += f'，{error_count} 个失败'

                return jsonify({
                    'success': True,
                    'message': result_message,
                    'details': {
                        'success_count': success_count,
                        'error_count': error_count,
                        'errors': errors[:5]  # 只返回前5个错误
                    }
                })

            except Exception as e:
                db.session.rollback()
                logger.error(f"批量更新账号失败: {str(e)}")
                return jsonify({'success': False, 'message': f'数据库更新失败: {str(e)}'})

        else:
            return jsonify({'success': False, 'message': '不支持的操作类型'})

    except Exception as e:
        logger.error(f"批量更新账号失败: {str(e)}")
        return jsonify({'success': False, 'message': f'操作失败: {str(e)}'})

@app.route('/admin/batch_random_password', methods=['POST'])
def batch_random_password():
    """批量随机密码"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        data = request.get_json()
        usernames = data.get('usernames', [])

        if not usernames:
            return jsonify({'success': False, 'message': '请选择要操作的账号'})

        updated_accounts = []
        for username in usernames:
            account = Account.query.filter_by(username=username).first()
            if account:
                new_password = generate_random_password()
                account.password = new_password
                updated_accounts.append({
                    'username': username,
                    'new_password': new_password
                })

        db.session.commit()

        logger.info(f"管理员 {session['admin']} 批量随机密码，影响账号: {len(updated_accounts)} 个")
        return jsonify({
            'success': True,
            'message': f'成功为 {len(updated_accounts)} 个账号生成随机密码',
            'updated_accounts': updated_accounts
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"批量随机密码失败: {str(e)}")
        return jsonify({'success': False, 'message': f'操作失败: {str(e)}'})

@app.route('/admin/batch_delete_accounts', methods=['POST'])
def batch_delete_accounts():
    """批量删除账号"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '请求数据为空'})

        usernames = data.get('usernames', [])

        if not usernames:
            return jsonify({'success': False, 'message': '未选择任何账号'})

        success_count = 0
        error_count = 0
        errors = []

        # 批量删除账号
        for username in usernames:
            try:
                account = Account.query.filter_by(username=username).first()
                if not account:
                    error_count += 1
                    errors.append(f'账号 {username} 不存在')
                    continue

                # 删除账号关联的所有卡密
                Card.query.filter_by(username=username).delete()

                # 删除账号
                db.session.delete(account)
                success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f'账号 {username} 删除失败: {str(e)}')
                continue

        try:
            db.session.commit()
            logger.info(f"管理员 {session['admin']} 批量删除了 {success_count} 个账号")

            result_message = f'成功删除 {success_count} 个账号'
            if error_count > 0:
                result_message += f'，{error_count} 个失败'

            return jsonify({
                'success': True,
                'message': result_message,
                'details': {
                    'success_count': success_count,
                    'error_count': error_count,
                    'errors': errors[:5]  # 只返回前5个错误
                }
            })

        except Exception as e:
            db.session.rollback()
            logger.error(f"批量删除账号失败: {str(e)}")
            return jsonify({'success': False, 'message': f'数据库操作失败: {str(e)}'})

    except Exception as e:
        logger.error(f"批量删除账号失败: {str(e)}")
        return jsonify({'success': False, 'message': f'操作失败: {str(e)}'})

@app.route('/admin/update_account_notes', methods=['POST'])
def update_account_notes():
    """更新账号备注"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '请求数据为空'})

        username = data.get('username', '').strip()
        notes = data.get('notes', '').strip()

        if not username:
            return jsonify({'success': False, 'message': '账号名不能为空'})

        # 限制备注长度
        if len(notes) > 200:
            return jsonify({'success': False, 'message': '备注长度不能超过200个字符'})

        # 查找账号
        account = Account.query.filter_by(username=username).first()
        if not account:
            return jsonify({'success': False, 'message': '账号不存在'})

        # 更新备注
        account.notes = notes
        db.session.commit()

        logger.info(f"管理员 {session['admin']} 更新了账号 {username} 的备注")

        return jsonify({
            'success': True,
            'message': '备注更新成功',
            'notes': notes
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"更新账号备注失败: {str(e)}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'})

@app.route('/admin/delete_account/<account>', methods=['POST'])
def delete_account(account: str):
    if redirect_response := ensure_admin_session():
        return jsonify({'success': False, 'message': '未授权访问'})
    try:
        account_obj = db.session.get(Account, account)
        if account_obj:
            Card.query.filter_by(username=account).delete()
            db.session.delete(account_obj)
            db.session.commit()
            logger.info(f"管理员 {session.get('admin')} 删除了账号 {account}")
            return jsonify({'success': True, 'message': f'账号 {account} 删除成功'})
        else:
            return jsonify({'success': False, 'message': '账号不存在'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除账号失败: {str(e)}")
        return jsonify({'success': False, 'message': '删除失败，请稍后重试'})

@app.route('/admin/update_vip_expiry', methods=['POST'])
def update_vip_expiry():
    """更新账号VIP到期时间"""
    if redirect_response := ensure_admin_session():
        return jsonify({'success': False, 'message': '未授权访问'})

    try:
        data = request.get_json()
        username = data.get('username')
        vip_expiry_str = data.get('vip_expiry', '').strip()

        if not username:
            return jsonify({'success': False, 'message': '用户名不能为空'})

        account = db.session.get(Account, username)
        if not account:
            return jsonify({'success': False, 'message': '账号不存在'})

        # 处理VIP到期时间
        if vip_expiry_str:
            try:
                # 解析datetime-local格式的时间
                vip_expiry = datetime.fromisoformat(vip_expiry_str.replace('T', ' '))
                # 转换为UTC时间存储
                account.vip_expiry = vip_expiry
            except ValueError:
                return jsonify({'success': False, 'message': '时间格式不正确'})
        else:
            # 如果为空，设置为默认30天后
            account.vip_expiry = utc_now() + timedelta(days=30)

        db.session.commit()

        logger.info(f"管理员 {session['admin']} 更新了账号 {username} 的VIP到期时间")
        return jsonify({'success': True, 'message': 'VIP到期时间更新成功'})

    except Exception as e:
        db.session.rollback()
        logger.error(f"更新VIP到期时间失败: {str(e)}")
        return jsonify({'success': False, 'message': '更新失败，请稍后重试'})

@app.route('/admin/account_cards/<account_name>', methods=['GET'])
def get_account_cards(account_name):
    """获取指定账号的卡密信息"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 检查账号是否存在
        account = Account.query.filter_by(username=account_name).first()
        if not account:
            return jsonify({'success': False, 'message': '账号不存在'})

        # 获取该账号的所有卡密
        cards = Card.query.filter_by(username=account_name).all()

        # 该账号下已提取的卡集合
        extracted_set = set(
            k for (k,) in db.session.query(ExtractionRecord.card_key).filter(
                ExtractionRecord.card_key.in_([c.card_key for c in cards])
            ).all()
        )

        card_list = []
        for i, card in enumerate(cards, 1):
            # 计算状态
            if card.first_used_at:
                expiry_time = card.first_used_at + timedelta(hours=card.duration_hours)
                if utc_now().replace(tzinfo=None) > expiry_time:
                    status = '已过期'
                    status_class = 'danger'
                else:
                    status = '使用中'
                    status_class = 'success'

                start_time = format_beijing_time(card.first_used_at)
                expiry_date = format_beijing_time(expiry_time)
            else:
                status = '未使用'
                status_class = 'secondary'
                start_time = '未启用'
                expiry_date = '未开始计时'

            card_info = {
                'index': i,
                'card_key': card.card_key,
                'duration_hours': card.duration_hours,
                'status': status,
                'status_class': status_class,
                'start_time': start_time,
                'expiry_date': expiry_date,
                'query_count': card.query_count,
                'max_query_count': card.max_query_count,
                'extracted': (card.card_key in extracted_set)
            }
            card_list.append(card_info)

        return jsonify({
            'success': True,
            'account_name': account_name,
            'cards': card_list,
            'total_cards': len(card_list)
        })

    except Exception as e:
        logger.error(f"获取账号卡密信息失败: {e}")
        return jsonify({'success': False, 'message': '获取信息失败，请重试'})

@app.route('/admin/extract', methods=['GET', 'POST'])
def extract_cards():
    if redirect_response := ensure_admin_session():
        return redirect_response
    extracted = None
    accounts = Account.query.filter_by(is_active=True).all()

    if request.method == 'POST':
        selected_account = request.form.get('account', '').strip()
        only_active = request.form.get('only_active', '1') == '1'
        q = Card.query
        if selected_account:
            q = q.filter_by(username=selected_account)
        if only_active:
            q = q.filter_by(is_active=True)
        # 排除已提取过的卡密
        q = q.filter(~Card.card_key.in_(db.session.query(ExtractionRecord.card_key)))
        # 选取一个最早创建的
        card = q.order_by(Card.created_at.asc()).first()
        if card:
            try:
                rec = ExtractionRecord(
                    card_key=card.card_key,
                    assigned_account=card.username,
                    extracted_by=session.get('admin','admin')
                )
                db.session.add(rec)
                db.session.commit()
                # PRG: 将本次结果存入session并重定向，避免刷新重复提交
                session['last_extract_results'] = [{
                    'card_key': card.card_key,
                    'username': card.username,
                    'created_at': format_beijing_time(card.created_at)
                }]
                flash_message(f'成功提取卡密: {card.card_key}')
                return redirect(url_for('extract_cards'))
            except Exception as e:
                db.session.rollback()
                flash_message(f'提取失败: {e}', 'danger')
        else:
            flash_message('没有可提取的卡密', 'warning')

    # 最近记录 + 本次批量结果（读取后即清空，避免刷新再次弹窗）
    records = ExtractionRecord.query.order_by(ExtractionRecord.extracted_at.desc()).limit(50).all()
    last_results = session.pop('last_extract_results', [])
    return render_template('extract_cards.html', accounts=accounts, extracted=None, records=records, last_results=last_results)

@app.route('/admin/extract/batch', methods=['POST'])
def extract_cards_batch():
    if redirect_response := ensure_admin_session():
        return redirect_response
    try:
        count = int(request.form.get('count', '1'))
    except ValueError:
        count = 1
    count = max(1, min(100, count))

    selected_account = request.form.get('account', '').strip()
    only_active = request.form.get('only_active', '1') == '1'

    q = Card.query
    if selected_account:
        q = q.filter_by(username=selected_account)
    if only_active:
        q = q.filter_by(is_active=True)
    q = q.filter(~Card.card_key.in_(db.session.query(ExtractionRecord.card_key)))

    picked = q.order_by(Card.created_at.asc()).limit(count).all()

    results = []
    if picked:
        try:
            for c in picked:
                db.session.add(ExtractionRecord(
                    card_key=c.card_key,
                    assigned_account=c.username,
                    extracted_by=session.get('admin','admin')
                ))
                results.append({'card_key': c.card_key, 'username': c.username, 'created_at': format_beijing_time(c.created_at)})
            db.session.commit()
            flash_message(f'成功提取 {len(results)} 个卡密')
        except Exception as e:
            db.session.rollback()
            flash_message(f'批量提取失败: {e}', 'danger')
    else:
        flash_message('没有可提取的卡密', 'warning')

    # 将结果暂存到 session 方便导出
    session['last_extract_results'] = results
    return redirect(url_for('extract_cards'))

@app.route('/admin/extract/export_results', methods=['GET'])
def export_extract_results():
    if redirect_response := ensure_admin_session():
        return redirect_response
    from flask import make_response
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['card_key','username','created_at'])
    results = session.get('last_extract_results', []) or []
    for r in results:
        writer.writerow([r.get('card_key',''), r.get('username',''), r.get('created_at','')])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename=extract_results.csv'
    return resp

@app.route('/admin/extract/records/export', methods=['GET'])
def export_extract_records():
    if redirect_response := ensure_admin_session():
        return redirect_response
    from flask import make_response
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['card_key','assigned_account','extracted_by','extracted_at'])
    records = ExtractionRecord.query.order_by(ExtractionRecord.extracted_at.desc()).limit(500).all()
    for r in records:
        writer.writerow([r.card_key, r.assigned_account or '', r.extracted_by, format_beijing_time(r.extracted_at)])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename=extract_records.csv'
    return resp

@app.route('/admin/extract/revoke/<card_key>', methods=['POST'])
def revoke_extract(card_key):
    if redirect_response := ensure_admin_session():
        return redirect_response
    try:
        rec = ExtractionRecord.query.filter_by(card_key=card_key).first()
        if not rec:
            return jsonify({'success': False, 'message': '记录不存在'})
        db.session.delete(rec)
        db.session.commit()
        return jsonify({'success': True, 'message': '已撤销提取，可重新分配'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'撤销失败: {e}'})



@app.route('/admin/cards', methods=['GET'])
def cards():
    if redirect_response := ensure_admin_session():
        return redirect_response

    # 自动删除过期卡密
    deleted_count = auto_delete_expired_cards()
    if deleted_count > 0:
        flash_message(f'自动删除了 {deleted_count} 个过期7天以上的卡密', 'info')

    # 获取搜索参数
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 每页显示10条

    # 构建查询
    query = Card.query

    if search_query:
        # 搜索卡密或账号 - 数据库兼容的搜索方式
        search_pattern = f'%{search_query}%'
        if 'postgresql' in database_url:
            # PostgreSQL使用ilike进行不区分大小写搜索
            query = query.filter(
                db.or_(
                    Card.card_key.ilike(search_pattern),
                    Card.username.ilike(search_pattern)
                )
            )
        else:
            # SQLite使用like
            query = query.filter(
                db.or_(
                    Card.card_key.like(search_pattern),
                    Card.username.like(search_pattern)
                )
            )

    # 分页查询
    pagination = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    cards_list = pagination.items

    # 已提取集合（用于标记）
    extracted_keys = set(k for (k,) in db.session.query(ExtractionRecord.card_key).all())

    card_list = [
        {
            'index': (page - 1) * per_page + i + 1,
            'card_number': card.card_key,
            'username': card.username,
            'duration_hours': card.duration_hours,
            'created_at': format_beijing_time(card.created_at),
            'first_used_at': format_beijing_time(card.first_used_at) if card.first_used_at else None,
            'expiry_date': format_beijing_time(card.first_used_at + timedelta(hours=card.duration_hours)) if card.first_used_at else '未开始计时',
            'query_count': card.query_count,
            'max_query_count': card.max_query_count,
            'is_expired': card.first_used_at and (utc_now().replace(tzinfo=None) > card.first_used_at + timedelta(hours=card.duration_hours)),
            'extracted': (card.card_key in extracted_keys)
        }
        for i, card in enumerate(cards_list)
    ]

    # 获取所有可用账号
    available_accounts = Account.query.all()

    return render_template('cards_dashboard.html',
                          cards=card_list,
                          available_accounts=available_accounts,
                          pagination=pagination,
                          search_query=search_query)

@app.route('/admin/delete_cards', methods=['POST'])
def delete_cards():
    """批量删除卡密"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        data = request.get_json()
        card_keys = data.get('card_keys', [])

        if not card_keys:
            return jsonify({'success': False, 'message': '请选择要删除的卡密'})

        # 删除选中的卡密
        deleted_count = 0
        for card_key in card_keys:
            card = Card.query.filter_by(card_key=card_key).first()
            if card:
                db.session.delete(card)
                deleted_count += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'成功删除 {deleted_count} 个卡密'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"批量删除卡密失败: {e}")
        return jsonify({'success': False, 'message': '删除失败，请重试'})

@app.route('/admin/add_card', methods=['POST'])
def add_card():
    """添加单个卡密"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        username = request.form.get('username', '').strip()
        card_number = request.form.get('card_number', '').strip()
        max_query_count = int(request.form.get('max_query_count', 10))
        duration_hours = int(request.form.get('duration_hours', 720))

        # 验证账号是否存在
        account = Account.query.filter_by(username=username).first()
        if not account:
            flash_message('选择的账号不存在', 'danger')
            return redirect(url_for('cards'))

        # 生成卡密（如果未提供）
        if not card_number:
            card_number = generate_card_key()

        # 检查卡密是否已存在
        if db.session.get(Card, card_number):
            flash_message('卡密已存在，请使用其他卡密', 'danger')
            return redirect(url_for('cards'))

        # 创建新卡密
        new_card = Card(
            card_key=card_number,
            username=username,
            max_query_count=max_query_count,
            duration_hours=duration_hours,
            created_at=utc_now()
        )

        db.session.add(new_card)
        db.session.commit()

        logger.info(f"管理员 {session['admin']} 添加卡密: {card_number} (账号: {username})")
        flash_message(f'卡密 {card_number} 添加成功', 'success')

    except ValueError:
        flash_message('请输入有效的数字', 'danger')
    except Exception as e:
        db.session.rollback()
        logger.error(f"添加卡密失败: {e}")
        flash_message('添加卡密失败，请重试', 'danger')

    return redirect(url_for('cards'))

@app.route('/admin/rebind_card', methods=['POST'])
def rebind_card():
    """换绑卡密到新账号"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        card_numbers = request.form.get('card_numbers', '').split(',')
        new_account = request.form.get('new_account', '').strip()

        if not card_numbers or not new_account:
            flash_message('参数错误', 'danger')
            return redirect(url_for('cards'))

        # 验证新账号是否存在
        account = Account.query.filter_by(username=new_account).first()
        if not account:
            flash_message('目标账号不存在', 'danger')
            return redirect(url_for('cards'))

        success_count = 0
        for card_number in card_numbers:
            card_number = card_number.strip()
            if not card_number:
                continue

            card = db.session.get(Card, card_number)  # 使用主键查询
            if card:
                card.username = new_account
                success_count += 1

        db.session.commit()
        flash_message(f'成功换绑 {success_count} 个卡密到账号 {new_account}', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"换绑卡密失败: {str(e)}")
        flash_message('换绑失败，请稍后重试', 'danger')

    return redirect(url_for('cards'))

@app.route('/admin/batch_delete_cards', methods=['POST'])
def batch_delete_cards():
    """批量删除卡密"""
    if redirect_response := ensure_admin_session():
        return jsonify({'success': False, 'message': '未授权访问'})

    try:
        data = request.get_json()
        card_numbers = data.get('card_numbers', [])

        if not card_numbers:
            return jsonify({'success': False, 'message': '未选择要删除的卡密'})

        success_count = 0
        for card_number in card_numbers:
            card = db.session.get(Card, card_number)  # 使用主键查询
            if card:
                db.session.delete(card)
                success_count += 1

        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'成功删除 {success_count} 个卡密'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"批量删除卡密失败: {str(e)}")
        return jsonify({'success': False, 'message': '删除失败，请稍后重试'})

@app.route('/admin/export_cards', methods=['GET'])
def export_cards():
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        from flask import make_response
        import csv
        from io import StringIO

        # 获取所有卡密数据
        cards_list = Card.query.all()

        # 创建CSV内容
        output = StringIO()
        writer = csv.writer(output)

        # 写入表头
        writer.writerow(['序号', '卡密', '账号', '状态', '创建时间', '首次使用', '到期时间', '查询次数'])

        # 写入数据
        for i, card in enumerate(cards_list, 1):
            # 判断状态
            if not card.first_used_at:
                status = '未使用'
            elif card.first_used_at and (utc_now().replace(tzinfo=None) > card.first_used_at + timedelta(hours=card.duration_hours)):
                status = '已过期'
            else:
                status = '使用中'

            writer.writerow([
                i,
                card.card_key,
                card.username,
                status,
                format_beijing_time(card.created_at),
                format_beijing_time(card.first_used_at) if card.first_used_at else '未使用',
                format_beijing_time(card.first_used_at + timedelta(hours=card.duration_hours)) if card.first_used_at else '未开始计时',
                f"{card.query_count}/{card.max_query_count}"
            ])

        # 创建响应
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'

        # 生成文件名（使用URL编码避免中文问题）
        from datetime import datetime
        from urllib.parse import quote
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        filename = f'cards_data_{timestamp}.csv'
        filename_encoded = quote(filename.encode('utf-8'))
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{filename_encoded}'

        return response

    except Exception as e:
        flash_message('导出失败，请稍后重试', 'danger')
        return redirect(url_for('cards'))

@app.route('/admin/import_cards', methods=['POST'])
def import_cards():
    """导入卡密数据"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        import csv
        from io import StringIO

        # 检查是否有上传文件
        if 'import_file' not in request.files:
            flash_message('请选择要导入的文件', 'danger')
            return redirect(url_for('cards'))

        file = request.files['import_file']
        if file.filename == '':
            flash_message('请选择要导入的文件', 'danger')
            return redirect(url_for('cards'))

        # 检查文件类型
        if not file.filename.lower().endswith('.csv'):
            flash_message('只支持CSV格式文件', 'danger')
            return redirect(url_for('cards'))

        # 读取文件内容，处理编码问题
        try:
            content = file.read().decode('utf-8')
        except UnicodeDecodeError:
            try:
                file.seek(0)
                content = file.read().decode('gbk')
            except UnicodeDecodeError:
                flash_message('文件编码错误，请使用UTF-8或GBK编码保存CSV文件', 'danger')
                return redirect(url_for('cards'))

        csv_reader = csv.reader(StringIO(content))

        # 跳过表头
        headers = next(csv_reader, None)
        if not headers:
            flash_message('文件格式错误：文件为空', 'danger')
            return redirect(url_for('cards'))

        # 验证表头格式（去除空格并转换为小写比较）
        expected_headers = ['序号', '卡密', '账号', '状态', '创建时间', '首次使用', '到期时间', '查询次数']
        # 清理表头中的空格和特殊字符
        cleaned_headers = [header.strip() for header in headers]

        if cleaned_headers != expected_headers:
            flash_message(f'文件格式错误：表头应为 {", ".join(expected_headers)}，当前表头为 {", ".join(cleaned_headers)}', 'danger')
            return redirect(url_for('cards'))

        # 统计信息
        success_count = 0
        error_count = 0
        skip_count = 0
        errors = []

        # 逐行处理数据
        for row_num, row in enumerate(csv_reader, start=2):
            try:
                if len(row) < 8:
                    error_count += 1
                    errors.append(f'第{row_num}行：数据不完整')
                    continue

                seq_num, card_key, username, status, created_time_str, first_used_str, expiry_time_str, query_info = row

                # 验证必填字段
                if not card_key.strip() or not username.strip():
                    error_count += 1
                    errors.append(f'第{row_num}行：卡密或账号不能为空')
                    continue

                # 检查卡密是否已存在
                existing_card = Card.query.filter_by(card_key=card_key.strip()).first()
                if existing_card:
                    skip_count += 1
                    continue

                # 检查账号是否存在
                account = Account.query.filter_by(username=username.strip()).first()
                if not account:
                    error_count += 1
                    errors.append(f'第{row_num}行：账号 {username.strip()} 不存在')
                    continue

                # 解析时间
                try:
                    # 创建时间
                    if created_time_str and created_time_str != '未设置':
                        created_at = datetime.strptime(created_time_str, '%Y-%m-%d %H:%M:%S')
                    else:
                        created_at = utc_now()

                    # 首次使用时间
                    first_used_at = None
                    if first_used_str and first_used_str != '未使用':
                        first_used_at = datetime.strptime(first_used_str, '%Y-%m-%d %H:%M:%S')

                except ValueError as e:
                    error_count += 1
                    errors.append(f'第{row_num}行：时间格式错误')
                    continue

                # 解析查询次数
                try:
                    if '/' in query_info:
                        query_count_str, max_query_count_str = query_info.split('/')
                        query_count = int(query_count_str)
                        max_query_count = int(max_query_count_str)
                    else:
                        query_count = 0
                        max_query_count = 10
                except ValueError:
                    query_count = 0
                    max_query_count = 10

                # 创建卡密
                card = Card(
                    card_key=card_key.strip(),
                    username=username.strip(),
                    created_at=created_at,
                    first_used_at=first_used_at,
                    query_count=query_count,
                    max_query_count=max_query_count,
                    duration_hours=720,  # 默认30天
                    is_active=(status != '已过期')
                )

                db.session.add(card)
                success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f'第{row_num}行：{str(e)}')

        # 提交数据库更改
        if success_count > 0:
            try:
                db.session.commit()
                flash_message(f'导入完成！成功：{success_count}，跳过：{skip_count}，错误：{error_count}', 'success')
            except Exception as e:
                db.session.rollback()
                flash_message(f'数据库错误：{str(e)}', 'danger')
        else:
            flash_message('没有成功导入任何数据', 'warning')

        # 显示错误详情（最多显示前5个错误）
        if errors:
            error_msg = '错误详情：' + '；'.join(errors[:5])
            if len(errors) > 5:
                error_msg += f'...（还有{len(errors)-5}个错误）'
            flash_message(error_msg, 'warning')

    except Exception as e:
        logger.error(f"卡密导入失败: {str(e)}")
        flash_message(f'导入失败：{str(e)}', 'danger')

    return redirect(url_for('cards'))

@app.route('/admin/change_card_account', methods=['POST'])
def change_card_account():
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        card_key = request.form.get('card_key')
        new_account = request.form.get('new_account')

        if not card_key or not new_account:
            flash_message('参数不完整', 'danger')
            return redirect(url_for('cards'))

        # 检查卡密是否存在
        card = db.session.get(Card, card_key)
        if not card:
            flash_message('卡密不存在', 'danger')
            return redirect(url_for('cards'))

        # 检查新账号是否存在
        account = Account.query.filter_by(username=new_account).first()
        if not account:
            flash_message('目标账号不存在', 'danger')
            return redirect(url_for('cards'))

        # 记录原账号
        old_account = card.username

        # 更新卡密的账号
        card.username = new_account
        db.session.commit()

        flash_message(f'卡密 {card_key} 已从账号 {old_account} 换绑到 {new_account}')

    except Exception as e:
        db.session.rollback()
        flash_message('换绑失败，请稍后重试', 'danger')

    return redirect(url_for('cards'))

@app.route('/admin/delete_card/<card_key>', methods=['POST'])
def delete_card(card_key: str):
    if redirect_response := ensure_admin_session():
        return jsonify({'success': False, 'message': '未授权访问'})
    try:
        card = db.session.get(Card, card_key)
        if card:
            db.session.delete(card)
            db.session.commit()
            return jsonify({'success': True, 'message': f'卡密 {card_key} 删除成功'})
        else:
            return jsonify({'success': False, 'message': '卡密不存在'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除卡密失败: {str(e)}")
        return jsonify({'success': False, 'message': '删除失败，请稍后重试'})

@app.route('/admin/batch_generate', methods=['GET', 'POST'])
def batch_generate():
    if redirect_response := ensure_admin_session():
        return redirect_response
    form = BatchGenerateForm()

    if request.method == 'POST':
        try:
            # 获取表单数据
            account = request.form.get('account')
            count = int(request.form.get('count', 1))
            max_query_count = int(request.form.get('max_query_count', 10))
            duration_hours = int(request.form.get('duration_hours', 720))

            # 验证数据
            if not account or count < 1 or count > 100:
                flash_message('请检查输入参数', 'danger')
            else:
                # 生成卡密（固定16位）
                cards = []
                for _ in range(count):
                    card_key = generate_card_key()  # 固定16位
                    # 确保卡密唯一
                    while db.session.get(Card, card_key):
                        card_key = generate_card_key()

                    card = Card(
                        card_key=card_key,
                        username=account,
                        max_query_count=max_query_count,
                        duration_hours=duration_hours,
                        created_at=utc_now()
                    )
                    cards.append(card)

                # 批量添加到数据库
                for card in cards:
                    db.session.add(card)
                db.session.commit()
                flash_message(f'成功生成 {count} 个16位卡密（数字+字母组合，避免混淆字符）')

        except Exception as e:
            db.session.rollback()
            flash_message('数据库错误，请稍后重试', 'danger')

    # 获取账号列表供选择
    accounts = Account.query.all()
    return render_template('batch_generate_dashboard.html', form=form, accounts=accounts)

@app.route('/admin/change_password', methods=['GET', 'POST'])
def change_password():
    if redirect_response := ensure_admin_session():
        return redirect_response
    form = ChangePasswordForm()

    if request.method == 'POST' and form.validate_on_submit():
        admin = Admin.query.filter_by(username=session['admin']).first()
        if admin:
            # 验证当前密码（兼容明文和哈希密码）
            password_valid = False
            if len(admin.password) == 64:  # SHA-256哈希长度
                password_valid = verify_password(form.current_password, admin.password)
            else:
                # 明文密码直接比较
                password_valid = (admin.password == form.current_password)

            if password_valid:
                # 设置新密码为哈希格式
                admin.password = hash_password(form.new_password)
                db.session.commit()
                flash_message('密码修改成功')
                logger.info(f"管理员 {session['admin']} 修改密码成功")
                return redirect(url_for('admin'))
            else:
                flash_message('当前密码错误', 'danger')
                logger.warning(f"管理员 {session['admin']} 修改密码失败：当前密码错误")
        else:
            flash_message('管理员账号不存在', 'danger')

    return render_template('change_password_dashboard.html', form=form)

# 数据备份和恢复路由
@app.route('/admin/backup', methods=['POST'])
def create_backup():
    """创建数据备份"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 创建备份目录
        backup_dir = os.path.join('data', 'backups')
        os.makedirs(backup_dir, exist_ok=True)

        # 生成备份文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'backup_{timestamp}.zip'
        backup_path = os.path.join(backup_dir, backup_filename)

        # 创建ZIP备份文件
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 备份数据库文件
            db_path = os.path.join('data', 'card_query.db')
            if os.path.exists(db_path):
                zipf.write(db_path, 'card_query.db')

            # 仅备份数据库与备份信息（移除旧版本附带的额外文件）

            # 添加备份信息文件
            backup_info = {
                'timestamp': timestamp,
                'created_by': session.get('admin', 'unknown'),
                'database_size': os.path.getsize(db_path) if os.path.exists(db_path) else 0,
                'backup_type': 'manual'
            }
            zipf.writestr('backup_info.json', json.dumps(backup_info, indent=2))

        logger.info(f"管理员 {session['admin']} 创建数据备份: {backup_filename}")
        return jsonify({
            'success': True,
            'message': '数据备份创建成功',
            'filename': backup_filename,
            'size': os.path.getsize(backup_path)
        })

    except Exception as e:
        logger.error(f"创建备份失败: {str(e)}")
        return jsonify({'success': False, 'message': f'备份失败: {str(e)}'})

@app.route('/admin/backups', methods=['GET'])
def list_backups():
    """获取备份列表"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        backup_dir = os.path.join('data', 'backups')
        if not os.path.exists(backup_dir):
            return jsonify({'success': True, 'backups': []})

        backups = []
        for backup_file in glob.glob(os.path.join(backup_dir, 'backup_*.zip')):
            filename = os.path.basename(backup_file)
            file_size = os.path.getsize(backup_file)
            file_time = datetime.fromtimestamp(os.path.getmtime(backup_file))

            # 尝试读取备份信息
            backup_info = {}
            try:
                with zipfile.ZipFile(backup_file, 'r') as zipf:
                    if 'backup_info.json' in zipf.namelist():
                        backup_info = json.loads(zipf.read('backup_info.json').decode('utf-8'))
            except:
                pass

            backups.append({
                'filename': filename,
                'size': file_size,
                'size_mb': round(file_size / 1024 / 1024, 2),
                'created_time': file_time.strftime('%Y-%m-%d %H:%M:%S'),
                'created_by': backup_info.get('created_by', 'unknown'),
                'backup_type': backup_info.get('backup_type', 'manual')
            })

        # 按创建时间倒序排列
        backups.sort(key=lambda x: x['created_time'], reverse=True)

        return jsonify({'success': True, 'backups': backups})

    except Exception as e:
        logger.error(f"获取备份列表失败: {str(e)}")
        return jsonify({'success': False, 'message': f'获取备份列表失败: {str(e)}'})

@app.route('/admin/backup/download/<filename>')
def download_backup(filename):
    """下载备份文件"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 安全检查文件名
        if not filename.startswith('backup_') or not filename.endswith('.zip'):
            return jsonify({'success': False, 'message': '无效的备份文件名'})

        backup_path = os.path.join('data', 'backups', secure_filename(filename))
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'message': '备份文件不存在'})

        logger.info(f"管理员 {session['admin']} 下载备份文件: {filename}")
        return send_file(backup_path, as_attachment=True, download_name=filename)

    except Exception as e:
        logger.error(f"下载备份文件失败: {str(e)}")
        return jsonify({'success': False, 'message': f'下载失败: {str(e)}'})

@app.route('/admin/backup/restore', methods=['POST'])
def restore_backup():
    """恢复数据备份"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        if 'backup_file' not in request.files:
            return jsonify({'success': False, 'message': '请选择备份文件'})

        file = request.files['backup_file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '请选择备份文件'})

        if not file.filename.endswith('.zip'):
            return jsonify({'success': False, 'message': '请选择有效的备份文件(.zip格式)'})

        # 创建临时目录
        temp_dir = os.path.join('data', 'temp_restore')
        os.makedirs(temp_dir, exist_ok=True)

        # 保存上传的文件
        temp_backup_path = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(temp_backup_path)

        # 验证备份文件
        with zipfile.ZipFile(temp_backup_path, 'r') as zipf:
            file_list = zipf.namelist()
            # 兼容旧备份：规范化条目名（处理反斜杠、驱动器号、前导./），优先匹配常见命名，其次选择体积最大的*.db/*.sqlite/*.sqlite3
            db_member = None

            def normalize_zip_name(name: str):
                n = name.replace('\\', '/').lstrip('./')
                # 去掉类似 C:/ 前缀
                if len(n) >= 3 and n[1] == ':' and (n[2] == '/' or n[2] == '\\'):
                    n = n[3:]
                return n

            name_infos = []  # (orig, norm, base, base_stripped)
            for name in file_list:
                norm = normalize_zip_name(name)
                base = norm.split('/')[-1]
                base_stripped = base.strip()
                name_infos.append((name, norm, base, base_stripped))

            preferred_basenames = {'card_query.db', 'card_system.db'}
            preferred_endpaths = {'data/card_query.db', 'instance/card_system.db'}

            # 优先匹配（去掉条目名两端的空白后再比较）
            for orig, norm, base, base_stripped in name_infos:
                if base_stripped in preferred_basenames or any(norm.endswith(p) or norm.rstrip().endswith(p) for p in preferred_endpaths):
                    db_member = orig
                    break

            # 回退：选出后缀为 .db/.sqlite/.sqlite3 的候选，取压缩条目中 size 最大者（也考虑去空白）
            if not db_member:
                candidates = []
                for info in zipf.infolist():
                    lname = info.filename.lower().replace('\\', '/').lstrip('./')
                    base = lname.split('/')[-1].strip()
                    if base.endswith('.db') or base.endswith('.sqlite') or base.endswith('.sqlite3'):
                        candidates.append((info.file_size, info.filename))
                if candidates:
                    candidates.sort(reverse=True)
                    db_member = candidates[0][1]

            if not db_member:
                os.remove(temp_backup_path)
                logger.error(f"备份文件不包含数据库：{file_list}")
                return jsonify({'success': False, 'message': '无效的备份文件：未找到数据库文件(.db/.sqlite/.sqlite3)'})

            # 创建当前数据的备份
            current_backup_dir = os.path.join('data', 'backups')
            os.makedirs(current_backup_dir, exist_ok=True)
            current_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            current_backup_filename = f'backup_before_restore_{current_timestamp}.zip'
            current_backup_path = os.path.join(current_backup_dir, current_backup_filename)

            with zipfile.ZipFile(current_backup_path, 'w', zipfile.ZIP_DEFLATED) as current_zipf:
                db_path = os.path.join('data', 'card_query.db')
                if os.path.exists(db_path):
                    current_zipf.write(db_path, 'card_query.db')

                backup_info = {
                    'timestamp': current_timestamp,
                    'created_by': session.get('admin', 'unknown'),
                    'backup_type': 'auto_before_restore'
                }
                current_zipf.writestr('backup_info.json', json.dumps(backup_info, indent=2))

            # 在覆盖数据库前，先关闭连接，避免Windows上的文件占用错误
            try:
                db.session.remove()
                db.session.close()
                db.engine.dispose()
                logger.info("数据库连接已关闭，准备写入恢复文件")
            except Exception as db_close_error:
                logger.warning(f"关闭数据库连接时出现警告: {db_close_error}")

            # 恢复数据：将定位到的数据库文件解压覆盖到 data/card_query.db
            extract_target = os.path.join('data', 'card_query.db')
            # 先确保 data 目录存在
            os.makedirs('data', exist_ok=True)
            # 临时解压到 data 目录
            zipf.extract(db_member, 'data')
            # 如果解压出的文件路径不在 data/card_query.db，则移动/覆盖
            extracted_path = os.path.join('data', db_member)
            # 处理 db_member 带子目录的情况
            if os.path.isdir(extracted_path):
                # 如果是目录，尝试在目录下寻找 .db
                for root, dirs, files in os.walk(extracted_path):
                    for fn in files:
                        if fn.lower().endswith('.db'):
                            extracted_path = os.path.join(root, fn)
                            break
                    break
            # 目标存在则先删除，避免跨盘移动时的PermissionError
            if os.path.exists(extract_target):
                try:
                    os.remove(extract_target)
                except Exception as rm_err:
                    logger.warning(f"覆盖目标前删除失败: {rm_err}")
            # 标准化目标
            if os.path.abspath(extracted_path) != os.path.abspath(extract_target):
                # 确保上级目录存在
                os.makedirs(os.path.dirname(extract_target), exist_ok=True)
                shutil.move(extracted_path, extract_target)
            else:
                # 如果正好解压到了目标位置，确保文件可写
                try:
                    os.utime(extract_target, None)
                except Exception:
                    pass
            # 清理可能解压出的多余目录结构
            base_dir_of_member = os.path.join('data', os.path.dirname(db_member))
            if os.path.isdir(base_dir_of_member) and base_dir_of_member != 'data':
                shutil.rmtree(base_dir_of_member, ignore_errors=True)

            # 恢复流程简化：本版本仅恢复数据库文件，不执行额外迁移脚本（旧版本遗留逻辑已移除）

            # 关闭数据库连接，准备重启
            try:
                # 关闭所有数据库连接
                db.session.remove()
                db.session.close()
                db.engine.dispose()
                logger.info("数据库连接已关闭，准备重启服务")
            except Exception as db_close_error:
                logger.warning(f"关闭数据库连接时出现警告: {db_close_error}")

        # 清理临时文件
        os.remove(temp_backup_path)
        shutil.rmtree(temp_dir, ignore_errors=True)

        logger.info(f"管理员 {session['admin']} 恢复数据备份: {file.filename}")
        return jsonify({
            'success': True,
            'message': '数据恢复成功！当前数据已自动备份。请重启服务以完成恢复过程。',
            'auto_backup': current_backup_filename,
            'restart_required': True
        })

    except Exception as e:
        logger.error(f"恢复备份失败: {str(e)}")
        return jsonify({'success': False, 'message': f'恢复失败: {str(e)}'})

@app.route('/admin/backup/delete/<filename>', methods=['DELETE'])
def delete_backup(filename):
    """删除备份文件"""
    if redirect_response := ensure_admin_session():
        return redirect_response

    try:
        # 安全检查文件名
        if not filename.startswith('backup_') or not filename.endswith('.zip'):
            return jsonify({'success': False, 'message': '无效的备份文件名'})

        backup_path = os.path.join('data', 'backups', secure_filename(filename))
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'message': '备份文件不存在'})

        os.remove(backup_path)
        logger.info(f"管理员 {session['admin']} 删除备份文件: {filename}")
        return jsonify({'success': True, 'message': '备份文件删除成功'})

    except Exception as e:
        logger.error(f"删除备份文件失败: {str(e)}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'})

# 短信验证码相关路由
@app.route('/sms/send', methods=['POST'])
def send_sms():
    """发送短信验证码"""
    try:
        data = request.get_json()
        phone = data.get('phone', '').strip()

        # 验证手机号格式
        if not phone or len(phone) != 11 or not phone.isdigit():
            return jsonify({'success': False, 'message': '请输入正确的手机号'}), 400

        # 获取客户端IP
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

        # 创建验证码
        success, message = create_sms_verification(phone, ip_address)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"发送短信验证码失败: {e}")
        return jsonify({'success': False, 'message': '系统错误，请稍后重试'}), 500

@app.route('/sms/verify', methods=['POST'])
def verify_sms():
    """验证短信验证码"""
    try:
        data = request.get_json()
        phone = data.get('phone', '').strip()
        code = data.get('code', '').strip()

        # 验证输入
        if not phone or not code:
            return jsonify({'success': False, 'message': '请输入手机号和验证码'}), 400

        # 验证验证码
        success, message = verify_sms_code(phone, code)

        if success:
            # 验证成功，可以在这里设置session或其他逻辑
            session['sms_verified'] = True
            session['verified_phone'] = phone
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"验证短信验证码失败: {e}")
        return jsonify({'success': False, 'message': '系统错误，请稍后重试'}), 500

# @app.route('/sms-demo', methods=['GET'])
# def sms_demo():
#     """短信验证码演示页面"""
#     return render_template('sms_demo.html')

@app.route('/get-captcha', methods=['POST'])
def get_captcha():
    """获取外部验证码并扣减查询次数"""
    try:
        data = request.get_json()
        card_key = data.get('card_key', '').strip()
        last_captcha = data.get('last_captcha', '').strip()  # 获取上次的验证码

        if not card_key:
            return jsonify({'success': False, 'message': '请先输入卡密'})

        # 查找卡密
        card = Card.query.filter_by(card_key=card_key).first()
        if not card:
            return jsonify({'success': False, 'message': '卡密不存在'})

        # 检查是否已过期
        if card.first_used_at:
            expiry_time = card.first_used_at + timedelta(hours=card.duration_hours)
            if utc_now().replace(tzinfo=None) > expiry_time:
                return jsonify({'success': False, 'message': '卡密已过期'})

        # 检查查询次数
        if card.query_count >= card.max_query_count:
            return jsonify({'success': False, 'message': '查询次数已用完'})

        # 获取验证码
        import requests
        response = requests.get('http://1.15.137.19:3000/', timeout=10)
        if response.status_code == 200:
            captcha_code = response.text.strip()
            # 验证是否为6位数字
            if len(captcha_code) == 6 and captcha_code.isdigit():

                # 检查验证码是否与上次相同
                code_changed = (captcha_code != last_captcha)

                # 只有验证码变化时才扣减次数
                if code_changed:
                    card.query_count += 1
                    if not card.first_used_at:
                        card.first_used_at = utc_now()
                    db.session.commit()
                    message_suffix = ""
                else:
                    message_suffix = " (验证码未变化，未扣减次数)"

                # 计算剩余次数
                remaining_count = card.max_query_count - card.query_count

                # 计算到期时间
                if card.first_used_at:
                    expiry_time = card.first_used_at + timedelta(hours=card.duration_hours)
                    expiry_date = format_beijing_time(expiry_time)
                else:
                    expiry_date = '首次查看验证码时开始计时'

                return jsonify({
                    'success': True,
                    'code': captcha_code,
                    'query_count': card.query_count,
                    'max_query_count': card.max_query_count,
                    'remaining_count': remaining_count,
                    'code_changed': code_changed,
                    'expiry_date': expiry_date,
                    'message': f'验证码获取成功{message_suffix}'
                })
            else:
                return jsonify({'success': False, 'message': '验证码格式错误'})
        else:
            return jsonify({'success': False, 'message': '获取验证码失败'})
    except Exception as e:
        logger.error(f"获取验证码失败: {e}")
        return jsonify({'success': False, 'message': '网络错误，请稍后重试'})

@app.route('/query', methods=['GET'])
def query():
    # 获取说明信息（使用缓存）
    cache_key = "notice_content"
    cached_notice = get_cache(cache_key)
    if cached_notice:
        notice_content, captcha_notice = cached_notice
    else:
        notice = Notice.query.filter_by(is_active=True).first()
        notice_content = notice.content if notice else '请输入卡密进行查询'
        captcha_notice = notice.captcha_notice if notice else '点击"查看验证码"获取最新的6位验证码'
        set_cache(cache_key, (notice_content, captcha_notice))

    card_key = request.args.get('card_key')
    if not card_key:
        return render_template('query.html', error='请输入卡密', notice=notice_content, captcha_notice=captcha_notice)

    card = db.session.get(Card, card_key)
    if not card:
        return render_template('query.html', error='卡密无效', notice=notice_content, captcha_notice=captcha_notice)

    # 检查是否过期（但不扣减查询次数）
    if card.first_used_at:
        expiry = card.first_used_at + timedelta(hours=card.duration_hours)
        if utc_now().replace(tzinfo=None) > expiry:
            return render_template('query.html', error='卡密已过期', notice=notice_content, captcha_notice=captcha_notice)

    # 获取账号信息（不扣减查询次数）
    account = db.session.get(Account, card.username)
    if not account:
        return render_template('query.html', error='关联账号不存在', notice=notice_content, captcha_notice=captcha_notice)

    # 计算过期时间
    if card.first_used_at:
        expiry_date = format_beijing_time(card.first_used_at + timedelta(hours=card.duration_hours))
    else:
        expiry_date = '首次查看验证码时开始计时'

    return render_template('query.html',
                          account=account.username,
                          password=account.password,
                          expiry_date=expiry_date,
                          card_key=card_key,
                          notice=notice_content,
                          captcha_notice=captcha_notice,
                          query_count=card.query_count,
                          max_query_count=card.max_query_count)

# 说明栏管理路由
@app.route('/admin/notice', methods=['GET', 'POST'])
def manage_notice():
    """管理说明栏"""
    redirect_response = ensure_admin_session()
    if redirect_response:
        return redirect_response

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        captcha_notice = request.form.get('captcha_notice', '').strip()

        if content and captcha_notice:
            # 获取或创建说明记录
            notice = Notice.query.filter_by(is_active=True).first()
            if notice:
                notice.content = content
                notice.captcha_notice = captcha_notice
                notice.updated_at = utc_now()
            else:
                notice = Notice(content=content, captcha_notice=captcha_notice)
                db.session.add(notice)

            try:
                db.session.commit()
                flash_message('说明栏更新成功', 'success')
            except Exception as e:
                db.session.rollback()
                flash_message('更新失败，请重试', 'danger')
                logger.error(f"更新说明栏失败: {e}")
        else:
            flash_message('说明内容和验证码提示都不能为空', 'warning')

    # 获取当前说明
    notice = Notice.query.filter_by(is_active=True).first()
    current_content = notice.content if notice else '请输入卡密进行查询'
    current_captcha_notice = notice.captcha_notice if notice else '点击"查看验证码"获取最新的6位验证码'

    return render_template('notice_manage_dashboard.html',
                          content=current_content,
                          captcha_notice=current_captcha_notice)

# 初始化数据库
def init_db():
    try:
        # 创建表
        db.create_all()
        # 轻量Schema自修复（兼容旧备份）
        ensure_schema()

        # 初始化提取记录表的唯一性约束（保证卡密只被记录一次）
        try:
            from sqlalchemy import text as _sa_text
            db.session.execute(_sa_text('CREATE UNIQUE INDEX IF NOT EXISTS ux_extraction_card_key ON extraction_records(card_key)'))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # 创建默认管理员账号
        if not Admin.query.filter_by(username='admin').first():
            admin = Admin(username='admin', password=hash_password('admin123'))
            db.session.add(admin)
            db.session.commit()
            logger.info("默认管理员账号已创建: admin/admin123")

        # 创建默认说明栏
        if not Notice.query.filter_by(is_active=True).first():
            default_notice = Notice(
                title='使用说明',
                content='欢迎使用卡密查询系统！\n\n使用步骤：\n1. 输入您的16位卡密（数字+字母组合）\n2. 点击查询获取账号密码\n3. 点击"查看验证码"获取6位验证码\n4. 每次查看或刷新验证码会消耗1次查询次数\n\n注意：查询次数仅在查看验证码时扣减，查询账号密码不消耗次数。',
                captcha_notice='⚠️ 重要：每次查看或刷新验证码会消耗1次查询次数'
            )
            db.session.add(default_notice)
            db.session.commit()
            logger.info("默认说明栏已创建")

        logger.info("数据库初始化成功")
        return True
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        return False

# 在应用启动时自动初始化数据库
def initialize_database():
    """初始化数据库"""
    try:
        with app.app_context():
            init_db()
        logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")

if __name__ == '__main__':
    # 在应用上下文中初始化数据库
    with app.app_context():
        if init_db():
            # 获取端口配置
            http_port = int(os.getenv('PORT', 5000))
            logger.info(f"启动应用，端口: {http_port}, 调试模式: {DEBUG}")

            # 尝试启动HTTPS服务器
            if HTTPS_AVAILABLE and run_https_server(app, debug=DEBUG, host='0.0.0.0'):
                logger.info("🔒 HTTPS服务器启动成功")
                if FORCE_HTTPS:
                    logger.info("🔄 HTTP请求将自动重定向到HTTPS")
            else:
                logger.info("🌐 启用HTTP模式")
                logger.info(f"HTTP服务器启动在端口 {http_port}")
                # 启动HTTP服务器
                app.run(debug=DEBUG, host='0.0.0.0', port=http_port, threaded=True)


        else:
            logger.error("应用启动失败：数据库初始化失败")
            exit(1)