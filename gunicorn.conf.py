# Gunicorn配置文件
import os
import multiprocessing

# 服务器配置
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2

# SSL配置
if os.getenv('HTTPS_ENABLED', 'false').lower() == 'true':
    keyfile = os.getenv('SSL_KEY_PATH', 'key.pem')
    certfile = os.getenv('SSL_CERT_PATH', 'cert.pem')
    if os.path.exists(keyfile) and os.path.exists(certfile):
        ssl_version = 2  # TLSv1_2
        ciphers = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'

# 进程配置
preload_app = True
daemon = False
user = None
group = None
tmp_upload_dir = None

# 日志配置
accesslog = os.getenv('ACCESS_LOG', 'logs/access.log')
errorlog = os.getenv('ERROR_LOG', 'logs/error.log')
loglevel = os.getenv('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# 性能配置
worker_tmp_dir = '/dev/shm'  # 使用内存文件系统（Linux）
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# 进程管理
pidfile = 'logs/gunicorn.pid'
proc_name = 'card-query-system'

# 钩子函数
def on_starting(server):
    """服务器启动时调用"""
    server.log.info("Card Query System is starting...")

def on_reload(server):
    """服务器重载时调用"""
    server.log.info("Card Query System is reloading...")

def worker_int(worker):
    """工作进程收到SIGINT信号时调用"""
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    """工作进程fork之前调用"""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    """工作进程fork之后调用"""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def worker_abort(worker):
    """工作进程异常退出时调用"""
    worker.log.info("Worker received SIGABRT signal")
