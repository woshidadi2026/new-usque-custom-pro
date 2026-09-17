# new-usque-custom-pro

基于 [Usque Custom Pro](https://github.com/KJGX66F/usque-custom-pro) 的 Cloudflare Pages 方案。

在浏览器中一键注册 Cloudflare WARP / MASQUE，生成 Clash / Mihomo 等配置，并支持将配置推送到 **Cloudflare KV**，通过订阅链接拉取最新节点。

> **说明：** 原项目没有「在线订阅 / KV 持久化」功能。本仓库在原项目基础上，使用 AI 辅助改写与扩展，增加了订阅端点、注册信息与界面设置的 KV 存储及管理接口。核心注册与配置生成思路仍来自原项目。

---

## 功能

- 网页一键注册 WARP MASQUE（浏览器本地生成密钥）
- 生成 Clash / Mihomo、Shadowrocket、sing-box、VLESS 等格式
- 可选免费落地节点、分流与 MASQUE 高级参数
- **在线订阅**：Clash YAML 推送到 KV，客户端访问 `https://你的域名/<SUB_UUID>`
- **持久化**：`config.json` 与界面设置写入 KV，刷新可恢复
- 管理页密码保护（`ADMIN_PASSWORD`）

---

## 与原项目的关系

| 说明 | 链接 |
|------|------|
| 原项目 | [https://github.com/KJGX66F/usque-custom-pro](https://github.com/KJGX66F/usque-custom-pro) |

基础使用、注册流程请优先参考原项目说明与视频。本仓库主要增加：

1. Cloudflare KV 在线订阅（推送 / 拉取 / 清除）
2. 原生 `config.json`、前端设置写入 KV


---

## 部署教程

### 准备工作

1. 注册并登录 [Cloudflare](https://dash.cloudflare.com/)
2. 创建一个 **KV 命名空间**（名称可自定，例如 `usque-kv`）
3. 准备：
   - 管理页登录密码（强密码）
   - 订阅路径用的随机串（建议使用 UUID）

### 第一步：下载全部根目录文件

将本仓库**根目录下的全部文件**下载到**同一个本地文件夹**中。

不要只下载部分文件，也不要多余嵌套一层无用目录。上传或关联 Git 后，这些文件应位于 Pages 项目的**站点根目录**。

常见文件包括：

```text
_headers
_routes.json
_worker.js
app.js
index.html
style.css
usque-register.js
warp-egress-selector.py

```

### 第二步：创建 Pages 并部署

任选一种方式。

#### 方式 A：直接上传文件夹

1. 打开 Cloudflare Dashboard → **Workers & Pages**
2. **Create** → **Pages** → **Upload assets**
3. 选择上一步装有全部根目录文件的文件夹并上传
4. 创建项目，等待部署完成

#### 方式 B：连接 GitHub

1. 将本仓库（或你的 fork）推送到自己的 GitHub
2. Cloudflare Dashboard → **Workers & Pages** → **Create** → 连接 Git 仓库
3. 构建配置一般可保持默认：
   - **Build command**：留空
   - **Build output directory**：`/`（或按仓库实际根目录填写）
4. 保存并部署

### 第三步：绑定 KV

1. 进入该 Pages 项目 → **Settings** → **Bindings**
2. 添加 **KV namespace** 绑定：

| Binding 变量名 | 绑定到的 KV 命名空间 |
|----------------|----------------------|
| `USQUE_KV`     | 你创建的 KV（如 `usque-kv`） |

> **注意：变量名必须是 `USQUE_KV`**，与代码一致，否则订阅与配置持久化无效。

### 第四步：配置环境变量

在同一项目 → **Settings** → **Environment variables** 中添加：

| 变量名 | 是否必填 | 说明 |
|--------|----------|------|
| `ADMIN_PASSWORD` | **必填** | 管理页登录密码，请使用强密码 |
| `SUB_UUID` | 使用订阅时**必填** | 订阅路径 ID，建议 UUID，例如 `8e020q7f-f056-4618-b400-1fa470d91328`。完整订阅地址为 `https://你的域名/<SUB_UUID>` |
| `SUB_CONTENT` | 可选 | 无 KV 内容时的兜底 YAML；一般留空，改用后台「推送到在线订阅」 |

生产环境（Production）与预览环境（Preview）如需一致，请两边都配置。

### 第五步：重新部署

绑定 KV、修改环境变量后，到 **Deployments** 执行一次 **Retry deployment** 或重新上传/推送，使配置生效。

### 第六步：首次使用

1. 浏览器打开 `https://你的项目.pages.dev`
2. 使用 `ADMIN_PASSWORD` 登录
3. 勾选条款 → 点击 **一键注册**（或导入已有 `config.json`）
4. 按需调整设置 → **应用设置并重新生成**
5. 在第 4 步点击 **推送当前 Clash 到订阅**
6. 在 Clash Verge 等客户端添加订阅：

```text
https://你的域名/<SUB_UUID>
```

示例：

```text
https://myqdaeqwe.pages.dev/8e020a7f-f056-4648-b400-1fe470d9ch18
```

---

## 环境变量与绑定汇总

```text
ADMIN_PASSWORD  = 管理登录密码（必填）
SUB_UUID        = 订阅路径随机串（用在线订阅时必填）
USQUE_KV        = KV 绑定名（在 Bindings 中配置，不是普通字符串变量的“值”）
SUB_CONTENT     = 可选，环境变量兜底订阅正文
```

### KV 中主要键（了解即可）

| 键名 | 用途 |
|------|------|
| `usque:subscription:yaml` | 在线订阅 YAML |
| `usque:subscription:meta` | 订阅元数据 |
| `usque:config:json` | 注册得到的原生 config |
| `usque:settings:json` | 前端界面设置 |

---

## 目录说明

| 文件 | 说明 |
|------|------|
| `_worker.js` | 登录、WARP 中继、订阅与 KV API |
| `_routes.json` | 路由交给 Worker 处理 |
| `_headers` | 安全相关 HTTP 头 |
| `index.html` / `app.js` / `style.css` | 管理前端 |
| `usque-register.js` | 浏览器侧注册与密钥生成 |
| `warp-egress-selector.py` | 可选：本机出口检测脚本 |

---

## 常见问题

**订阅打开只有一段说明文字？**  
还没有推送过 Clash，或 KV 未绑定。登录后生成配置，再点「推送当前 Clash 到订阅」。

**提示未绑定 KV？**  
检查 Bindings 名称是否为 **`USQUE_KV`**，并重新部署。

**刷新后提示未注册？**  
确认 KV 已绑定；注册成功后应自动写入，也可用页面上的「手动保存注册信息到 KV」。



---

## 安全建议

- 订阅链接等同口令，勿发到公开群组或仓库
- `SUB_UUID` 使用长随机值（推荐 UUID）
- 使用强 `ADMIN_PASSWORD`
- 链接泄露后：更换 `SUB_UUID` 并重新部署
- 仅供学习与个人使用，请遵守 Cloudflare 及当地法规

---

## 致谢

- 原项目：[KJGX66F/usque-custom-pro](https://github.com/KJGX66F/usque-custom-pro)
- Cloudflare WARP / MASQUE、Mihomo、Clash Verge 等生态

本仓库在原项目之上增加了在线订阅与 KV 能力，部分实现由 AI 辅助改写；使用前请自行审查代码。

---

## 免责声明

本项目与 Cloudflare 官方无关。使用后果由使用者自行承担。请勿用于非法用途。
