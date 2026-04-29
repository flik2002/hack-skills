# CDN 供应链投毒攻击补充 (from leavesongs.com)

> 本文档补充自 Phith0n 对 Apifox CDN 投毒事件的分析 [1]

## 攻击向量概述

不同于传统的依赖混淆（Dependency Confusion），CDN 供应链投毒针对的是前端应用加载的静态资源（JavaScript 埋点脚本、分析库等）。

### 典型攻击流程

```
攻击者获取 CDN 权限/凭证
        ↓
篡改静态资源（如埋点脚本 analytics.min.js）
        ↓
合法应用加载被投毒的 CDN 资源
        ↓
恶意代码在用户浏览器/桌面端执行
        ↓
窃取敏感数据（Token、SSH 密钥、凭据）
```

## 案例分析：Apifox CDN 投毒事件 (2026-03)

### 被篡改资源
- **URL**: `https://cdn.apifox.com/www/assets/js/apifox-app-event-tracking.min.js`
- **原始大小**: ~34KB
- **投毒后大小**: ~77KB（追加约 40KB 恶意载荷）

### 阶段一载荷分析

攻击采用多阶段加载机制，阶段一使用混淆技术（字符串数组洗牌、RC4、代理函数）：

**功能**:
1. **指纹收集**: 通过 `require('crypto')` 和 `require('os')` 读取 MAC 地址、CPU 型号、主机名、系统用户名
2. **身份关联**: 从 `localStorage` 获取 `common.accessToken`，调用 API 获取用户邮箱
3. **加密上报**: RSA-2048 加密敏感字段，SHA-256 生成机器指纹
4. **C2 通信**: 向 `apifox.it.com` 发起请求，接收下一阶段载荷

**持久化机制**:
```javascript
// 随机间隔 30 分钟 ~ 3 小时轮询
scheduleNext() {
    const delay = 30min + Math.random() * 2.5hours;
    setTimeout(loadAndExecute, delay);
}
```

### 阶段二与阶段三

**阶段二**: 返回 344 字节 RSA 密文，解密后向 `document.head` 插入脚本标签加载第三阶段

**阶段三（明文窃密）**:
- **macOS/Linux**: 读取 `~/.ssh/`、`.zsh_history`、`.bash_history`、`.git-credentials`，执行 `ps aux`
- **Windows**: 读取 `%USERPROFILE%\.ssh\`，执行 `tasklist`
- **加密外带**: scrypt 派生 AES-256-GCM 密钥，POST 到 `https://apifox.it.com/event/0/log`

## 检测与自查方法

### 1. 客户端存储检查 (Electron 应用)
```javascript
// 开发者工具 Console
localStorage.getItem('_rl_mc');      // 机器指纹
localStorage.getItem('_rl_headers'); // 加密后的头部信息
```

### 2. 离线数据目录检查

**Windows**:
```bash
# 标准安装
%APPDATA%\apifox\Network\Network Persistent State

# Scoop 安装
\apps\apifox\current\UserData\Network\Network Persistent State
```

**macOS**:
```bash
~/Library/Application Support/Apifox/Local Storage/leveldb
```

检查方法：使用 `strings` 或十六进制编辑器搜索 `apifox.it.com`

### 3. 网络日志分析

查找以下特征：
- 域名: `apifox.it.com`, `cdn.openroute.dev`, `upgrade.feishu.it.com`
- 路径: `/public/apifox-event.js`, `/event/0/log`

## 防御与修复建议

### 应急响应清单

| 优先级 | 动作 | 说明 |
|--------|------|------|
| P0 | 升级客户端 | 安装 2.8.19+，埋点改为安装包内资源 |
| P1 | SSH 密钥轮换 | 重新生成并部署密钥，审计 `auth.log` |
| P1 | Git 凭据清理 | 删除 `~/.git-credentials`，轮换 Access Token |
| P2 | Shell 历史审查 | 检查历史中的口令/API Key/AccessKey |
| P2 | 账号密码修改 | 修改 Apifox 账号密码并重新登录 |
| P3 | 网络阻断 | 防火墙/DNS 黑名单恶意域名 |

### 产品加固建议

1. **Subresource Integrity (SRI)**: 为 CDN 资源添加完整性校验
   ```html
   <script src="https://cdn.example.com/app.js"
           integrity="sha384-..."
           crossorigin="anonymous"></script>
   ```

2. **版本锁定**: 明确指定资源版本，避免自动拉取最新版本

3. **多 CDN 策略**: 关键资源同时部署到多个 CDN，异常时切换

4. **实时监控**: 监控 CDN 资源哈希变化，告警异常修改

## 参考

[1] Phith0n. "Apifox CDN 供应链投毒事件简单复盘". leavesongs.com. 2026-03-26.
    https://www.leavesongs.com/PENETRATION/apifox-supply-chain-attack-analysis.html
