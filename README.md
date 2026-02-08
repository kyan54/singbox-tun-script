# sing-box TUN 一键安装/卸载脚本

这个仓库包含两个脚本：
- `install-singbox-tun.sh`：安装 sing-box、生成配置、（可选）写入 systemd 单元并创建辅助命令
- `uninstall-singbox-tun.sh`：按当前安装方式卸载
- 本代码由AI生成

## 主要意图
在 WSL 或 Linux 中安装并启动 sing-box 的 TUN 模式，同时旁路本机与局域网 IP，方便在国内访问大模型 API。  
这样可以把网络接管限制在 WSL 内部，避免 Windows 端开启 TUN 后影响其他应用或日常娱乐。  
日常开发建议在 VS Code 连接 WSL 进行工作流，Windows 保持正常网络环境，做到“开发顺滑，AI Coding 时 Windows 还能随手娱乐”，让幸福感稳稳在线。

## 适用环境
- Linux / WSL（支持 `ip`、`tar`、`curl`）
- 可选：systemd（脚本会自动检测）

## 快速开始

```bash
chmod +x install-singbox-tun.sh
./install-singbox-tun.sh
```

安装过程中会提示输入关键参数。

## 自建服务端（VLESS + reality）环境搭建（可选）
如果你需要快速搭建 （VLESS + reality）环境，可使用以下脚本：

```bash
wget --no-check-certificate -O ${HOME}/Xray-script.sh https://raw.githubusercontent.com/zxcvos/Xray-script/main/install.sh && bash ${HOME}/Xray-script.sh
```

### 使用本地 tar.gz
如果脚本下载较慢或无法直连 GitHub，可先手动下载 release 包，再交给脚本复用：

1) 从发布页下载对应版本  
```
https://github.com/SagerNet/sing-box/releases
```
2) 将文件放到脚本目录并重命名为 `sing-box.tar.gz`

脚本会优先使用该文件并跳过下载；只有在本地不存在时才会从 GitHub 下载。


### 只输入一个 VLESS 链接
你可以直接粘贴完整的 VLESS URL，脚本会自动解析：

```bash
# 交互输入
./install-singbox-tun.sh
# 在提示 “VLESS URL (optional)” 处粘贴：
# vless://UUID@HOST:PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=...&fp=chrome&pbk=...&sid=...&spx=%2F&type=tcp&headerType=none
```

或非交互：

```bash
VLESS_URL='vless://UUID@HOST:PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=...&fp=chrome&pbk=...&sid=...&spx=%2F&type=tcp&headerType=none' \
  ./install-singbox-tun.sh
```

## systemd 模式
若系统支持 systemd，脚本会自动生成：
- `/etc/systemd/system/sing-box-tun.service`
- `/usr/local/lib/sing-box/sb-tun-route.sh`（路由切换）
- `~/.local/bin/sb-tun`（systemctl 的 wrapper）

常用命令：

```bash
sudo systemctl start sing-box-tun
sudo systemctl stop sing-box-tun
sudo systemctl status sing-box-tun
sudo journalctl -u sing-box-tun -n 120 --no-pager

# 或用 wrapper
~/.local/bin/sb-tun start
~/.local/bin/sb-tun logs
```

如需强制不使用 systemd：

```bash
USE_SYSTEMD=0 ./install-singbox-tun.sh
```

## 局域网访问（旁路）
脚本默认把以下网段走直连，避免 TUN 接管导致局域网不可达：

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `100.64.0.0/10`
- `169.254.0.0/16`

如需自定义：

```bash
BYPASS_CIDRS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,你的网段/掩码" \
  ./install-singbox-tun.sh
```

## 配置文件
默认路径：`/etc/sing-box-tun.json`

脚本会生成包含 `tun` inbound + `vless` outbound 的简化配置。

## 卸载

```bash
chmod +x uninstall-singbox-tun.sh
./uninstall-singbox-tun.sh
```

卸载脚本会：
- 停止并删除 systemd 单元（如存在）
- 删除路由脚本
- 按提示删除配置/二进制/日志/状态文件

## 常见问题

### 1) `reality verification failed`
通常是以下参数不匹配：
- `server_name (SNI)`
- `public_key`
- `short_id`

请确认你的客户端（例如 v2rayN）与脚本输入一致。

### 2) `sudo: a password is required`
脚本会调用 `sudo`，请确保有权限并已输入密码。

### 3) `Cannot find device "tun0"`
表示 sing-box 启动失败或 TUN 未创建。请查看日志：

```bash
sudo journalctl -u sing-box-tun -n 120 --no-pager
```

## 安全说明
脚本内的默认敏感参数已替换为占位符（`YOUR_*`）。
公开分享前请勿提交真实服务器信息。

---

如需扩展（自定义路由、DNS、开机自启等），可以直接修改 `/etc/sing-box-tun.json` 或在脚本中添加参数。
