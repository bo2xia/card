/**
 * 通用JavaScript功能库
 * 用于卡密查询系统的前端功能
 */

// 全局变量
window.CardSystem = window.CardSystem || {};

/**
 * 复制功能 - 支持多种环境和浏览器
 */
window.CardSystem.copyToClipboard = function(text) {
    console.log('copyToClipboard called with:', text);
    
    if (!text) {
        console.error('No text provided to copy');
        window.CardSystem.showMessage('没有可复制的内容', 'danger');
        return;
    }
    
    // 确保text是字符串
    text = String(text).trim();
    if (!text) {
        console.error('Empty text after trimming');
        window.CardSystem.showMessage('复制内容为空', 'danger');
        return;
    }
    
    // 检测环境
    const env = {
        hasClipboard: !!navigator.clipboard,
        isSecureContext: window.isSecureContext,
        protocol: window.location.protocol,
        hostname: window.location.hostname
    };
    
    console.log('Environment:', env);
    
    // 方法1: 尝试现代Clipboard API
    if (env.hasClipboard && env.isSecureContext) {
        console.log('Using Clipboard API...');
        navigator.clipboard.writeText(text).then(() => {
            console.log('Clipboard API success');
            window.CardSystem.showMessage('复制成功', 'success');
        }).catch(err => {
            console.error('Clipboard API failed:', err);
            console.log('Falling back to execCommand method...');
            if (window.CardSystem.fallbackCopy(text)) {
                window.CardSystem.showMessage('复制成功', 'success');
            } else {
                window.CardSystem.showMessage('复制失败，请手动复制', 'danger');
            }
        });
    } else {
        // 方法2: 传统execCommand方法
        console.log('Using fallback copy method...');
        if (window.CardSystem.fallbackCopy(text)) {
            // 在非安全环境中，即使execCommand返回true，也可能没有真正复制
            if (!env.isSecureContext && env.protocol === 'http:') {
                window.CardSystem.showCopySuccessWithManualOption(text);
            } else {
                window.CardSystem.showMessage('复制成功', 'success');
            }
        } else {
            window.CardSystem.showManualCopyDialog(text);
        }
    }
};

/**
 * 降级复制方法 - 使用execCommand
 */
window.CardSystem.fallbackCopy = function(text) {
    console.log('fallbackCopy called with:', text);
    
    try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        
        // 设置样式确保不可见但可操作
        textArea.style.cssText = `
            position: fixed !important;
            left: -999999px !important;
            top: -999999px !important;
            width: 1px !important;
            height: 1px !important;
            opacity: 0 !important;
            border: none !important;
            outline: none !important;
            box-shadow: none !important;
            background: transparent !important;
        `;
        textArea.setAttribute('readonly', '');
        textArea.setAttribute('tabindex', '-1');
        
        document.body.appendChild(textArea);
        console.log('Textarea created and appended');
        
        // 确保元素获得焦点
        textArea.focus();
        textArea.select();
        
        // 移动端兼容
        if (textArea.setSelectionRange) {
            textArea.setSelectionRange(0, text.length);
        }

        // 执行复制（增加重试机制）
        let successful = false;
        for (let i = 0; i < 3; i++) {
            try {
                successful = document.execCommand('copy');
                console.log(`execCommand attempt ${i + 1}:`, successful);
                if (successful) break;
            } catch (e) {
                console.warn(`execCommand attempt ${i + 1} failed:`, e);
            }
        }
        
        document.body.removeChild(textArea);
        console.log('Textarea removed');
        
        return successful;
    } catch (err) {
        console.error('fallbackCopy error:', err);
        return false;
    }
};

/**
 * 显示消息提示
 */
window.CardSystem.showMessage = function(message, type = 'info') {
    console.log('Showing message:', message, type);
    
    // 移除现有的提示
    const existingToasts = document.querySelectorAll('.card-system-toast');
    existingToasts.forEach(toast => toast.remove());

    // 创建临时提示
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} position-fixed card-system-toast`;
    toast.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 200px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    const iconMap = {
        success: 'fas fa-check-circle',
        danger: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    const icon = iconMap[type] || iconMap.info;
    toast.innerHTML = `<i class="${icon} me-2"></i>${message}`;
    document.body.appendChild(toast);

    // 3秒后自动移除
    setTimeout(() => {
        if (document.body.contains(toast)) {
            toast.style.opacity = '0';
            setTimeout(() => {
                if (document.body.contains(toast)) {
                    document.body.removeChild(toast);
                }
            }, 300);
        }
    }, 3000);
};

/**
 * 带手动选项的成功提示
 */
window.CardSystem.showCopySuccessWithManualOption = function(text) {
    console.log('Showing success with manual option for:', text);
    
    // 移除现有的提示
    const existingToasts = document.querySelectorAll('.card-system-toast');
    existingToasts.forEach(toast => toast.remove());

    // 创建带手动选项的提示
    const toast = document.createElement('div');
    toast.className = 'alert alert-warning position-fixed card-system-toast';
    toast.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    toast.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div>
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>复制可能未成功</strong><br>
                <small>如果粘贴时没有内容，请点击手动复制</small>
            </div>
            <div class="ms-2">
                <button class="btn btn-sm btn-outline-primary" onclick="window.CardSystem.showManualCopyDialog('${text}'); this.parentElement.parentElement.parentElement.remove();">
                    手动复制
                </button>
                <button class="btn btn-sm btn-outline-secondary ms-1" onclick="this.parentElement.parentElement.parentElement.remove();">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        </div>
    `;
    document.body.appendChild(toast);

    // 5秒后自动移除
    setTimeout(() => {
        if (document.body.contains(toast)) {
            toast.style.opacity = '0';
            setTimeout(() => {
                if (document.body.contains(toast)) {
                    document.body.removeChild(toast);
                }
            }, 300);
        }
    }, 5000);
};

/**
 * 手动复制对话框
 */
window.CardSystem.showManualCopyDialog = function(text) {
    console.log('Showing manual copy dialog for:', text);

    // 移除现有的对话框
    const existingDialog = document.getElementById('manualCopyDialog');
    if (existingDialog) {
        existingDialog.remove();
    }

    // 创建对话框
    const dialog = document.createElement('div');
    dialog.id = 'manualCopyDialog';
    dialog.className = 'modal fade show';
    dialog.style.cssText = `
        display: block !important;
        background: rgba(0,0,0,0.5);
        z-index: 10000;
    `;

    dialog.innerHTML = `
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header bg-warning text-dark">
                    <h5 class="modal-title">
                        <i class="fas fa-exclamation-triangle me-2"></i>手动复制
                    </h5>
                    <button type="button" class="btn-close" onclick="document.getElementById('manualCopyDialog').remove()"></button>
                </div>
                <div class="modal-body">
                    <p class="mb-3">
                        <strong>由于安全限制，无法自动复制到剪贴板。</strong><br>
                        请手动选择并复制以下内容：
                    </p>
                    <div class="alert alert-info">
                        <div class="d-flex justify-content-between align-items-center">
                            <code id="manualCopyText" style="font-size: 1.1em; font-weight: bold; user-select: all;">${text}</code>
                            <button class="btn btn-sm btn-outline-primary" onclick="window.CardSystem.selectAndHighlight('manualCopyText')">
                                <i class="fas fa-mouse-pointer me-1"></i>选择
                            </button>
                        </div>
                    </div>
                    <div class="alert alert-warning mb-0">
                        <small>
                            <strong>提示：</strong>
                            <ol class="mb-0 ps-3">
                                <li>点击"选择"按钮或手动选择上方文本</li>
                                <li>按 <kbd>Ctrl+C</kbd> (Windows) 或 <kbd>Cmd+C</kbd> (Mac) 复制</li>
                                <li>在需要的地方按 <kbd>Ctrl+V</kbd> 或 <kbd>Cmd+V</kbd> 粘贴</li>
                            </ol>
                        </small>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="document.getElementById('manualCopyDialog').remove()">
                        <i class="fas fa-times me-1"></i>关闭
                    </button>
                    <button type="button" class="btn btn-primary" onclick="window.CardSystem.selectAndHighlight('manualCopyText')">
                        <i class="fas fa-mouse-pointer me-1"></i>选择文本
                    </button>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(dialog);

    // 自动选择文本
    setTimeout(() => {
        window.CardSystem.selectAndHighlight('manualCopyText');
    }, 100);
};

/**
 * 选择并高亮文本
 */
window.CardSystem.selectAndHighlight = function(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        try {
            const range = document.createRange();
            range.selectNodeContents(element);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            element.focus();
            console.log('Text selected for manual copy');

            // 高亮效果
            element.style.background = '#ffeb3b';
            setTimeout(() => {
                element.style.background = '';
            }, 2000);
        } catch (e) {
            console.error('Failed to select text:', e);
        }
    }
};

// 向后兼容的全局函数
window.copyText = window.CardSystem.copyToClipboard;
window.copyToClipboard = window.CardSystem.copyToClipboard;
window.showMessage = window.CardSystem.showMessage;

console.log('CardSystem common.js loaded successfully');
