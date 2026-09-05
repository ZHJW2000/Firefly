"""六阶段流水线编排：顺序执行、结果落盘、断点复用、日志/进度回调。"""

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import s1_subdomain, s2_portscan, s3_finger, s4_probe, s5_crawl, s6_report

STAGES = [
    ("1-子域收集", s1_subdomain),
    ("2-端口扫描", s2_portscan),
    ("3-指纹识别", s3_finger),
    ("4-Web探测", s4_probe),
    ("5-端点爬取", s5_crawl),
    ("6-汇总报表", s6_report),
]


@dataclass
class Context:
    target: str
    outdir: str
    cfg: dict
    data: dict = field(default_factory=dict)  # 各阶段结果共享
    stop_event: Optional[threading.Event] = None
    targets: Optional[list] = None  # 批量目标；None 时回退 [target]

    def __post_init__(self):
        if not self.targets:
            self.targets = [self.target]

    def stage_file(self, idx: int) -> str:
        return os.path.join(self.outdir, f"stage{idx}_{STAGES[idx - 1][0].split('-')[1]}.json")

    def save(self, idx: int, payload: dict):
        with open(self.stage_file(idx), "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)

    def load(self, idx: int) -> Optional[dict]:
        p = self.stage_file(idx)
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def stop_requested(self) -> bool:
        return bool(self.stop_event and self.stop_event.is_set())


class Pipeline:
    """运行六阶段。reuse: set of stage idx 复用上次结果。

    回调（均在调用方线程语义上仅作状态通知，由 GUI 用队列转发）:
      log(msg), progress(stage_idx, done, total), stage_status(idx, text)
    """

    def __init__(self, ctx: Context, reuse: Optional[set] = None,
                 log: Callable[[str], None] = print,
                 progress: Callable[[int, int, int], None] = lambda *a: None,
                 stage_status: Callable[[int, str], None] = lambda *a: None):
        self.ctx = ctx
        self.reuse = reuse or set()
        self.log = log
        self.progress = progress
        self.stage_status = stage_status

    def run(self) -> dict:
        os.makedirs(self.ctx.outdir, exist_ok=True)
        tgt = self.ctx.target if len(self.ctx.targets) == 1 else \
            f"{self.ctx.target} 等 {len(self.ctx.targets)} 个目标"
        self.log(f"目标: {tgt}，输出目录: {self.ctx.outdir}")
        for idx, (name, module) in enumerate(STAGES, start=1):
            if self.ctx.stop_requested():
                self.log("已停止。")
                break
            if idx in self.reuse:
                payload = self.ctx.load(idx)
                if payload is not None:
                    self.ctx.data.update(payload.get("data", {}))
                    self.log(f"[阶段{idx}] {name}: 复用上次结果。")
                    self.stage_status(idx, "已复用")
                    continue
                self.log(f"[阶段{idx}] {name}: 无历史结果，重新执行。")
            self.stage_status(idx, "运行中…")
            t0 = time.time()
            self.log(f"[阶段{idx}] {name} 开始…")
            try:
                payload = module.run(
                    self.ctx,
                    log=lambda m, idx=idx: self.log(f"[阶段{idx}] {m}"),
                    progress=lambda done, total, idx=idx: self.progress(idx, done, total),
                    should_stop=self.ctx.stop_requested,
                )
            except Exception as e:
                import traceback
                self.log(f"[阶段{idx}] {name} 异常: {e}")
                self.log(traceback.format_exc(limit=3))
                self.stage_status(idx, f"失败: {e}")
                self.log(f"[阶段{idx}] 继续执行后续阶段（下游将跳过缺失数据）。")
            self.ctx.save(idx, payload)
            self.ctx.data.update(payload.get("data", {}))
            cost = time.time() - t0
            self.stage_status(idx, f"完成（{cost:.0f}s）")
            self.log(f"[阶段{idx}] {name} 完成，耗时 {cost:.0f}s。")
        # 阶段六产物：报表路径
        report = self.ctx.data.get("report_path")
        if report:
            self.log(f"报表已生成: {report}")
        return self.ctx.data


def default_outdir(base: str, target: str) -> str:
    safe = "".join(c for c in target if c.isalnum() or c in ".-_") or "target"
    return os.path.join(base, safe)
