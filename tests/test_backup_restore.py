import os
import io
import json
import zipfile
import shutil
from contextlib import contextmanager

# 为确保使用项目默认的SQLite文件，直接使用默认 data/card_query.db
# 如果需要自定义测试数据库，可在导入 app 前设置环境变量：
# os.environ["USE_SQLITE"] = "false"
# os.environ["DATABASE_URL"] = "sqlite:///./data/test_card_query.db"

from app import app, init_db


def ensure_dirs():
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data/backups', exist_ok=True)


@contextmanager
def admin_session(client, username='admin'):
    """在Flask测试客户端中设置管理员会话。"""
    with client.session_transaction() as sess:
        sess['admin'] = username
    yield


def setup_module(module):
    """测试前初始化数据库和目录。"""
    ensure_dirs()
    # 可选：清理旧的备份文件，避免断言误判
    for f in os.listdir('data/backups'):
        if f.startswith('backup_') and f.endswith('.zip'):
            try:
                os.remove(os.path.join('data', 'backups', f))
            except OSError:
                pass
    # 初始化数据库（创建默认管理员等）
    with app.app_context():
        init_db()


def test_backup_and_restore_flow():
    client = app.test_client()

    # 1) 模拟管理员登录（直接设置session）
    with admin_session(client):
        # 2) 创建备份
        resp = client.post('/admin/backup')
        assert resp.status_code == 200, f"backup status: {resp.status_code} body={resp.data!r}"
        data = resp.get_json()
        assert data and data.get('success') is True, f"backup json: {data}"
        backup_filename = data.get('filename')
        assert backup_filename and backup_filename.startswith('backup_') and backup_filename.endswith('.zip')

        # 3) 列出备份并验证此备份存在
        resp = client.get('/admin/backups')
        assert resp.status_code == 200
        listing = resp.get_json()
        assert listing and listing.get('success') is True
        names = [b.get('filename') for b in listing.get('backups', [])]
        assert backup_filename in names, f"{backup_filename} not in {names}"

        # 4) 下载备份
        resp = client.get(f'/admin/backup/download/{backup_filename}')
        assert resp.status_code == 200
        content = resp.data
        assert len(content) > 0
        # 校验是ZIP（以PK开头）
        assert content[:2] == b'PK', "downloaded file is not a ZIP"

        # 5) 恢复备份（使用刚下载的数据流）
        file_storage = (io.BytesIO(content), backup_filename)
        resp = client.post('/admin/backup/restore', data={'backup_file': file_storage}, content_type='multipart/form-data')
        assert resp.status_code == 200, f"restore status: {resp.status_code} body={resp.data!r}"
        result = resp.get_json()
        assert result and result.get('success') is True, f"restore json: {result}"
        assert result.get('restart_required') is True
        assert result.get('auto_backup', '').startswith('backup_before_restore_')

        # 6) 简单验证恢复后的数据库文件存在
        assert os.path.exists(os.path.join('data', 'card_query.db'))


if __name__ == '__main__':
    # 允许直接运行脚本进行手工验证
    setup_module(None)
    test_backup_and_restore_flow()
    print('Backup/Restore E2E test passed.')

