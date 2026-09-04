<div align="center">

# AssetRadar

**站点资产与敏感信息测绘工具**

`OneForAll` · `Nmap` · `EHole` · `Katana` · `一键流水线` · `Excel 报表`

</div>

---

## 📖 简介

AssetRadar 是一款面向授权评估场景的资产测绘流水线工具。输入目标域名，自动完成 **子域收集 → 端口扫描 → 指纹识别 → Web 探测 → 敏感信息提取** 五个侦察阶段，最终整合为按风险评分排序的 Excel 报告，高危服务一目了然。

工具通过编排业界成熟的开源组件完成各阶段任务，自身提供 GUI、断点续跑、风险评分与结构化报表能力；同时支持将全部依赖组件打包内置，拷贝即用。

## ✨ 功能特性

| 阶段 | 能力 | 说明 |
|:---:|---|---|
| ① 子域收集 | OneForAll | 被动收集，过滤无效/泛解析；支持手工导入子域列表替代 |
| ② 端口扫描 | Nmap | 默认 top1000 端口，可切换 1-65535 全端口（--min-rate 加速） |
| ③ 指纹识别 | EHole | Web 框架 / 中间件 / 版本识别 |
| ④ Web 探测 | 内置 asyncio | 批量探测状态码、Title、Server 等响应头（无需 httpx） |
| ⑤ 信息提取 | Katana + Edge 无头渲染 + 内置正则 | API 端点提取；动态注入 JS 捕获；渲染后 DOM 与 JS 硬编码敏感数据扫描（9 类规则） |
| ⑥ 汇总报告 | 内置评分模型 | 风险评分 0-100，高危服务降序排列，Excel 五表输出 |

**其他特性**

- 🖥️ 图形界面：六阶段独立进度条、实时日志、一键执行
- ⏸️ 断点续跑：每阶段结果落盘，重跑可复用已完成阶段
- 🌐 动态渲染：Edge 无头后台执行页面 JS，覆盖 SPA/懒加载脚本的敏感信息检测
- 📦 便携部署：全部依赖工具可内置到 `tools\` 目录，拷贝到任何 Windows 机器即用
- 🔒 安全边界：仅 GET 请求、不登录、不爆破、不利用漏洞、不存储任何凭据

## 🚀 快速开始

### 环境要求

- Windows 10/11
- 内置工具的外部路径（或使用便携版，无需任何准备）

### 使用便携版（推荐）

1. 下载整个 `AssetRadar` 目录（含 `tools\` 子目录）
2. 双击 `AssetRadar.exe`
3. 输入目标域名 → 勾选授权确认 → 点击 **开始测绘**
4. 完成后点击 **打开输出目录**，查看 `output\<目标>\资产测绘报告_<目标>.xlsx`

### 从源码运行

```bash
git clone https://github.com/ZHJW2000/Firefly.git
cd Firefly
pip install -r requirements.txt
python run.py
```

### 从源码打包 exe

```bash
build_exe.bat          # 单文件 exe
python build_portable.py  # 便携目录版（需本机有各外部工具）
```

### 测试

```bash
python tests/mock_test.py           # 单元自测（不依赖外部工具）
python tests/integration_local.py   # 本机集成联调（仅扫 127.0.0.1）
python tests/e2e_local.py           # 六阶段端到端（仅扫 127.0.0.1）
```

## ⚙️ 配置说明

### 外部工具路径

| 阶段 | 工具 | 便携包内路径 |
|:---:|---|---|
| ① | OneForAll + Python 3.11 运行时 | `tools\oneforall\` + `tools\python311\` |
| ② | Nmap | `tools\nmap\nmap.exe` |
| ③ | EHole | `tools\ehole\EHole_windows_amd64.exe` |
| ⑤ | Katana | `tools\katana\katana.exe` |

- 程序按 **内置 `tools\` → 界面配置 → 默认路径** 顺序解析
- 「工具路径设置」对话框可覆盖任意路径；缺工具的阶段自动跳过并标红

### 扫描参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| Nmap 模式 | top1000 | 大网段摸底用默认值；重点 IP 可切全端口 |
| 探测并发 | 100 | Web 探测的 asyncio 并发数 |
| Katana 深度 | 2 | 爬取深度，越大越慢越全 |
| 无头渲染 | 开启 | Edge 后台执行页面 JS，捕获动态注入脚本；可关闭 |
| 渲染页面上限 | 100 | 超出部分跳过渲染，仅静态爬取 |
| 最大资产数 | 10000 | 子域收集的规模上限 |

配置持久化于 `%APPDATA%\AssetRadar\tools.json`。

## 📊 报表输出

Excel 报告（`output\<目标>\资产测绘报告_<目标>.xlsx`）包含六个工作表：

1. **评估说明** — 目标、统计概览
2. **高危服务总览** — 风险分降序，含风险原因、IP/域名、端口、指纹组件、Title、API 端点数、敏感数据数（≥60 标红 / 30-59 标黄）
3. **敏感信息明细** — JS 硬编码密钥/密码/连接串/内网 IP 等，每条含证据片段
4. **API 端点清单**
5. **端口服务清单**
6. **子域清单**

**风险评分模型**（0-100）：高危端口（Redis/RDP/数据库等，10-20 分）＋ 高危指纹组件（Shiro/WebLogic/ThinkPHP/用友/泛微等，合计封顶 40 分）＋ 敏感数据命中（每条 12 分，封顶 30）＋ 非标端口 Web 服务（5 分）。

## 📁 目录结构

```
AssetRadar/
├── assetmap/
│   ├── pipeline.py      # 六阶段编排：落盘/续跑/回调
│   ├── s1_subdomain.py  # ① OneForAll 子域收集
│   ├── s2_portscan.py   # ② Nmap 端口扫描
│   ├── s3_finger.py     # ③ EHole 指纹识别
│   ├── s4_probe.py      # ④ Web 探测（asyncio）
│   ├── s5_crawl.py      # ⑤ Katana 爬取 + 敏感数据扫描
│   ├── s6_report.py     # ⑥ Excel 报表生成
│   ├── risk.py          # 风险评分模型
│   ├── tools_cfg.py     # 工具路径解析（便携优先）
│   └── gui.py           # tkinter 界面
├── tests/               # 单元 / 集成 / 端到端测试
├── build_exe.bat        # 打包单文件 exe
├── build_portable.py    # 组装便携目录版
└── run.py               # 入口
```

## ❓ 常见问题

**Q：推送/克隆 GitHub 超时？**
走本地代理：`git config http.proxy http://127.0.0.1:7897`（按实际代理端口）。

**Q：某个阶段状态栏显示"缺工具"？**
在「工具路径设置」中修正路径，或改用包含完整 `tools\` 的便携版。

**Q：OneForAll 报 Python 兼容错误？**
OneForAll 与 Python 3.13 不兼容（`fire`/`exrex` 依赖已移除的标准库）。便携版已内置 Python 3.11 运行时；从源码运行请用 3.11/3.12。

**Q：全端口扫描要多久？**
单 IP 视网络情况 30-60 分钟，大网段建议先 top1000 摸底再对重点 IP 全端口。

**Q：敏感信息误报？**
正则方案固有局限（如前端密码校验逻辑会命中"硬编码密码"），报表定位为线索，请人工复核证据片段。规则可在 `assetmap/s5_crawl.py` 的 `SENSITIVE_RULES` 中增删。

## 🗺️ TODO

- [ ] 敏感数据规则白名单（降低误报）
- [ ] 报告截图存证
- [ ] 多任务队列与批量目标

## 🙏 致谢

- [OneForAll](https://github.com/shmilylty/OneForAll) — 子域收集
- [Nmap](https://nmap.org/) — 端口扫描
- [EHole](https://github.com/EdgeSecurityTeam/EHole) — 指纹识别
- [Katana](https://github.com/projectdiscovery/katana) — 端点爬取

> 本工具基于以上开源组件编排实现，感谢各项目作者的贡献。使用前请一并遵守各组件的开源协议。

---

## ⚠️ 免责声明

**本工具仅用于授权范围内的安全测试与学习研究。使用者应确保已获得目标系统所有者的明确授权，因非法使用造成的一切后果由使用者自行承担。**
