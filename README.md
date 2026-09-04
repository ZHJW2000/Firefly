# AssetRadar 资产测绘流水线 v2.0

授权范围内资产的自动化测绘工具：输入目标域名，自动完成子域收集 → 端口扫描 → 指纹识别 → Web 探测 → API 端点/敏感数据提取，最终输出按**高危服务优先**排序的 Excel 报表。

## 流水线

```
① OneForAll 子域收集（过滤无效/泛解析）
② Nmap 端口扫描（默认 top1000，可切 1-65535 全端口）
③ EHole 指纹识别（框架/中间件/版本）
④ 内置异步探测（状态码/Title/Server 等响应头）
⑤ Katana API 端点提取 + JS 硬编码敏感数据扫描
⑥ 风险评分整合 → Excel 报表（评分降序）
```

## 外部工具依赖与路径

**便携版（推荐）**：`dist\AssetRadar-portable\` 目录版发行包（约 340MB）已把四个工具全部内置到 `tools\` 子目录：

```
AssetRadar.exe
tools\
├── nmap\        (Nmap 主程序及数据文件)
├── katana\      (Katana)
├── ehole\       (EHole + finger.json + dict)
├── oneforall\   (OneForAll 源码)
└── python311\   (官方便携 Python 3.11 + OneForAll 全部依赖，开箱即用)
```

启动时自动优先使用内置工具，拷贝整个目录到任何 Windows 机器即可运行，不依赖 E 盘路径。注意：Nmap 的 `-sT` 连接扫描无需额外驱动；如需 SYN 扫描等原始套包功能需另装 Npcap。

| 阶段 | 工具 | 便携包内路径 |
|---|---|---|
| ① | OneForAll（Python 3.11 便携运行时） | `tools\oneforall\` + `tools\python311\` |
| ② | Nmap | `tools\nmap\nmap.exe` |
| ③ | EHole | `tools\ehole\EHole_windows_amd64.exe` |
| ⑤ | Katana | `tools\katana\katana.exe` |

无内置目录时回退到界面配置的路径（默认 E 盘）；「工具路径设置」可覆盖。缺工具的阶段自动跳过并在状态栏标红。

OneForAll 运行时说明：因 OneForAll 与 Python 3.13 不兼容（fire/pipes 等），便携包内置 Python 3.11.9 官方便携版 + SQLAlchemy 2.x（配套 OneForAll 自带的 records 模块）。重建命令见 `build_portable.py`。

## 使用

1. 双击 `AssetRadar.exe`
2. 输入目标域名（如 `xxx.edu.cn`），选择 Nmap 模式
3. 点「开始测绘」——六个阶段进度实时显示，日志可查
4. 完成后「打开输出目录」，报表为 `output/<目标>/资产测绘报告_<目标>.xlsx`

**断点续跑**：每个阶段结果保存在 `output/<目标>/stageN_*.json`，重跑时勾选对应阶段即可复用（比如改了报表逻辑只想重跑阶段⑥）。

**手工导入子域**：若不想跑 OneForAll，点「导入子域列表」载入 txt（每行一个子域/IP），阶段①自动跳过。

## 报表结构（Excel 六工作表）

1. **评估说明**：目标、各项统计
2. **高危服务总览**：风险分（0-100）降序，含风险原因、IP/域名、端口、服务、指纹组件、状态码、Title、API 端点数、敏感数据数；≥60 标红、30-59 标黄
3. **敏感信息明细**：JS 中硬编码的密钥/密码/数据库连接串/内网 IP 等（每条含证据片段）
4. **API 端点清单**
5. **端口服务清单**
6. **子域清单**

**风险评分构成**：高危端口（Redis/RDP/数据库等 10-20 分）+ 高危指纹组件（Shiro/WebLogic/ThinkPHP/用友/泛微等，合计封顶 40 分）+ 敏感数据命中（每条 12 分，封顶 30）+ 非标端口 Web 服务（5 分）。

## OneForAll venv（阶段①）

首次已通过 `setup` 创建独立 venv（`%APPDATA%\AssetRadar\oneforall-venv`）并修补了 Python 3.13 兼容问题（fire/pipes、exrex/sre_parse）。换机器重建：

```bash
python -m venv "%APPDATA%\AssetRadar\oneforall-venv"
%APPDATA%\AssetRadar\oneforall-venv\Scripts\pip install -r OneForAll\requirements.txt setuptools fire
# 修补 exrex（3.11+）：把 site-packages\exrex.py 中 `from re import sre_parse, U` 换成 try/except 兼容写法
```

## 从源码运行 / 打包

```bash
pip install -r requirements.txt
python run.py                    # GUI
python tests/mock_test.py        # 单元自测（不依赖外部工具）
python tests/integration_local.py  # 本机集成联调（只扫 127.0.0.1）
python tests/e2e_local.py        # 六阶段端到端（只扫 127.0.0.1）
build_exe.bat
```

## 授权与边界

- 仅对**有授权的资产**使用；工具不包含漏洞利用、不尝试登录、不存储任何凭据
- 敏感数据扫描只对公开可访问的 JS 文件做正则匹配并保留 ≤160 字符证据片段，用于定位问题，不完整保存文件
- 全端口模式（65535）对大网段可能耗时数小时，建议先 top1000 摸底再对重点 IP 全端口
