#!/usr/bin/env python3
"""
Docker健康检查脚本
用于检查Flask应用是否正常运行
"""

import requests
import sys
import os

def health_check():
    """执行健康检查"""
    try:
        # 检查应用是否响应
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            print("Health check passed")
            return 0
        else:
            print(f"Health check failed: HTTP {response.status_code}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Health check failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(health_check())
