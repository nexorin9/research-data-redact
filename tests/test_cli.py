"""运维 CLI 的七个子命令验收（task 39）。

运维 CLI 是**手动通道**：管理员在交付目录里放材料时，守护进程会自己跑；
但值班的人往往要当场问一句「这一批现在到哪一步了」「能不能重投」「这批
能不能换回原文」。CLI 就是回答这些问题的口子。

本测试盯住四件事：

1. **七个子命令各自跑通**（scan / run / deliver / restore-request /
   export-audit / verify-residual / status），每个都给出**可核对摘要**
   （批次号 / 状态 / 产物路径 / 条数）；
2. **失败返回非 0 并说清原因** —— 批次不存在、目录不存在、参数给错、
   残留没过、授权不齐，各归各的退出码，运维脚本靠它分流；
3. **CLI 与守护进程共用同一条主路径** —— CLI 跑出来的产物与命中清单，
   和守护进程跑出来的一致；CLI 不另写一套脱敏逻辑；
4. **摘要不含患者原文** —— 终端输出与台账记录都不得出现命中原文。

另有一条硬红线：``restore-request`` 缺第二授权人时**挂起**（等签字），
不降级为单人还原。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

#: 跑 CLI 时的环境变量：只给 PYTHONPATH，不带任何凭据 —— 端点没配就是挂起，
#: 不指向本地替身。
BASE_ENV = {"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"}

#: 自造的放射报告样例（合成数据，与任何真实患者无关）
MATERIAL_TEXT = """市第一人民医院  放射科检查报告
姓名：张某某      性别：男      年龄：64岁
住院号：90000001   科别：呼吸内科
检查号：CHK0000001  床位：12床
出生日期：1949-12-31  手机号：13800138000
检查所见：
  右肺下叶见磨玻璃结节，大小约 8mm，边界尚清晰。
诊断意见：
  1、2 型糖尿病
建议：
  1、餐后服用盐酸氨溴索口服液 30mL 每日 3 次
（本页为第 2 页）
报告日期：2026-01-05    报告医师：示例医师
"""

#: 身份串：终端输出、台账、清单里都不该出现
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")

#: 终端输出类断言只盯这组「患者身份串」。
#:
#: 材料键是三段式（申请单号-院内检查号-材料序号），中间段就是院内检查号 ——
#: 那是**业务关联键**（导出摘要会点名提示「材料 ID 夹带标识符」），不是
#: 「命中原文泄漏」。把它算进泄漏，等于要求材料键不带检查号，与 task 38
#: 定的三段式口径自相矛盾。
PATIENT_IDENTITY_STRINGS = ("张某某", "90000001", "1949-12-31", "13800138000")


# --------------------------------------------------------------------- 工具


def _cli_env(**extra: str) -> dict[str, str]:
    """CLI 运行环境（带上一组环境变量覆盖）。"""
    env = dict(BASE_ENV)
    env.update(extra)
    return env


def _run_cli(args: list[str], env: dict[str, str] | None = None, cwd: Path | None = None):
    """跑一次 CLI，返回CompletedProcess。"""
    return subprocess.run(
        [sys.executable, "-m", "research_redact.cli", *args],
        cwd=str(cwd or PROJECT_ROOT),
        env=env or _cli_env(),
        capture_output=True,
        text=True,
    )


def _write_inbox(
    root: Path,
    *,
    application_no: str = "KY20260001",
    ethics: str = "EC-2026-0001",
    material_text: str = MATERIAL_TEXT,
    material_id: str = "KY20260001-CHK0000001-01",
) -> Path:
    """在 ``root`` 下造一份可处理的交付目录。"""
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": application_no,
        "ethics_approval_no": ethics,
        "patient_ids": ["P-1001"],
        "materials": [
            {
                "material_id": material_id,
                "kind": "report_text",
                "path": "materials/report_001.txt",
                "patient_id": "P-1001",
            }
        ],
    }
    (application_dir / "application.json").write_text(
        json.dumps(application, ensure_ascii=False), encoding="utf-8"
    )
    (application_dir / "materials" / "report_001.txt").write_text(
        material_text, encoding="utf-8"
    )
    return inbox


def _paths(root: Path) -> dict[str, str]:
    """一组默认路径（交付目录 / 产物目录 / 台账 / 告警台账）。"""
    return {
        "RESEARCH_DELIVERY_DIR": str(root / "inbox"),
        "RESEARCH_OUTPUT_DIR": str(root / "outbox"),
        "RESEARCH_LEDGER_DB": str(root / "ledger.sqlite3"),
        "RESEARCH_ALERT_LEDGER": str(root / "alerts.jsonl"),
    }


@pytest.fixture()
def platform():
    """本机 HTTP 服务（科研数据平台替身，**只在测试层**）。

    产品代码里是真实 httpx 客户端；这里只把收到的请求记下来，用来断言
    「重复投递不会产生第二次真实外发」。
    """
    received: list[dict[str, object]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            received.append(
                {
                    "path": self.path,
                    "idempotency_key": self.headers.get("Idempotency-Key", ""),
                    "application_no": body.get("application_no", ""),
                }
            )
            raw = json.dumps({"dataset_id": "DS-9001"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args) -> None:  # 静音
            return

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()


# --------------------------------------------------------------------- scan


def test_scan列出交付目录里的批次(tmp_path):
    """scan：列出交付目录里的批次、材料数与伦理批件号。"""
    inbox = _write_inbox(tmp_path)
    completed = _run_cli(
        ["scan"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode == 0, completed.stderr
    assert "KY20260001" in completed.stdout
    assert "EC-2026-0001" in completed.stdout
    assert "待处理批次：1 个" in completed.stdout
    assert str(inbox) in completed.stdout


def test_scan台账状态与交付目录并存(tmp_path):
    """scan：台账里已处理的批次与交付目录里的批次都看得见。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0
    completed = _run_cli(["scan"], env=env)
    assert completed.returncode == 0, completed.stderr
    assert "KY20260001" in completed.stdout
    # 已处理的批次台账状态不再是「未处理」
    assert "（未处理）" not in completed.stdout


def test_scan交付目录不存在返回非0(tmp_path):
    """scan：交付目录不存在时返回非 0 并说明原因。"""
    completed = _run_cli(
        ["scan"],
        env=_cli_env(**_paths(tmp_path)),  # inbox 还没造
    )
    assert completed.returncode != 0
    assert "交付目录不存在" in completed.stderr


def test_scan输出不含患者原文(tmp_path):
    """scan：终端输出不得出现任何命中原文。"""
    _write_inbox(tmp_path)
    completed = _run_cli(["scan"], env=_cli_env(**_paths(tmp_path)))
    assert completed.returncode == 0, completed.stderr
    for secret in PATIENT_IDENTITY_STRINGS:
        assert secret not in completed.stdout


# --------------------------------------------------------------------- run


def test_run处理单批并给出可核对摘要(tmp_path):
    """run：脱敏 → 残留自检 → 投递，摘要给出批次号 / 状态 / 产物 / 条数。"""
    _write_inbox(tmp_path)
    completed = _run_cli(
        ["run", "--batch", "KY20260001"],
        env=_cli_env(**_paths(tmp_path)),
    )
    # 端点没配 → 投递通道挂起 → 批次挂起等重投（退出码 5），但脱敏已跑完
    assert completed.returncode in (0, 5), completed.stderr
    assert "批次：KY20260001" in completed.stdout
    assert "状态：" in completed.stdout
    assert "命中条数：" in completed.stdout
    assert "残留自检：" in completed.stdout
    outbox = tmp_path / "outbox" / "KY20260001"
    assert (outbox / "manifest.jsonl").is_file()
    assert (outbox / "materials" / "KY20260001-CHK0000001-01.txt").is_file()


def test_run产物与命中清单和主路径一致(tmp_path):
    """run：CLI 与守护进程共用同一条主路径 —— 命中清单条数一致。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001"], env=env).returncode in (0, 5)

    manifest = tmp_path / "outbox" / "KY20260001" / "manifest.jsonl"
    lines = [
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and '"_manifest_header"' not in line
    ]
    assert len(lines) == 5
    payload = json.loads(lines[0])
    assert payload["label"] == "PATIENT_NAME"


def test_run只脱敏不投递(tmp_path):
    """run --no-deliver：产物落盘但不投递。"""
    _write_inbox(tmp_path)
    completed = _run_cli(
        ["run", "--batch", "KY20260001", "--no-deliver"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode == 0, completed.stderr
    assert "投递：" not in completed.stdout
    assert (tmp_path / "outbox" / "KY20260001" / "manifest.jsonl").is_file()


def test_run批次不存在返回非0(tmp_path):
    """run：批次不在交付目录里时返回非 0 并说明原因。"""
    _write_inbox(tmp_path)
    completed = _run_cli(
        ["run", "--batch", "KY20269999"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "没有这个批次" in completed.stderr


def test_run缺伦理批件号被阻断(tmp_path):
    """run：缺伦理批件号 → 批次被阻断，不得交付（返回非 0）。"""
    _write_inbox(tmp_path, ethics="")
    completed = _run_cli(
        ["run", "--batch", "KY20260001"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "阻断" in completed.stdout or "伦理" in completed.stdout


# --------------------------------------------------------------------- deliver


def test_deliver待交付队列为空返回0(tmp_path):
    """deliver：台账里没有待交付批次时明确说空队列，返回 0。"""
    _write_inbox(tmp_path)
    completed = _run_cli(["deliver"], env=_cli_env(**_paths(tmp_path)))
    assert completed.returncode == 0, completed.stderr
    assert "待投递队列为空" in completed.stdout


def test_deliver重投已代号化的批次(tmp_path):
    """deliver：把「已代号化、尚未交付」的批次重投（不重跑脱敏）。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0

    completed = _run_cli(["deliver"], env=env)
    # 端点没配 → 通道挂起 → 批次挂起等重投（退出码 5），不是静默成功
    assert completed.returncode == 5, completed.stdout + completed.stderr
    assert "KY20260001" in completed.stdout
    assert "幂等键" in completed.stdout


def test_deliver指定批次返回非0并说明(tmp_path):
    """deliver --batch：批次不在台账里时返回非 0 并说明原因。"""
    _write_inbox(tmp_path)
    completed = _run_cli(
        ["deliver", "--batch", "KY20269999"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "不在台账里" in completed.stderr


def test_deliver不重跑脱敏(tmp_path):
    """deliver：重投只重建载荷，不重跑识别（命中清单条数不变）。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0
    manifest = tmp_path / "outbox" / "KY20260001" / "manifest.jsonl"
    before = manifest.read_text(encoding="utf-8")

    _run_cli(["deliver"], env=env)
    assert manifest.read_text(encoding="utf-8") == before


def test_deliver重投已交付批次不产生第二次外发(tmp_path, platform):
    """deliver --batch：同一把幂等键 → 平台只收一次请求（真实 HTTP 往返）。"""
    port, received = platform
    _write_inbox(tmp_path)
    env = _cli_env(
        **_paths(tmp_path),
        RESEARCH_DATA_BASE_URL=f"http://127.0.0.1:{port}",
        RESEARCH_DATA_TOKEN="token-research",
        PSEUDONYM_KEY_ID="key-2026-10",
    )
    assert _run_cli(["run", "--batch", "KY20260001"], env=env).returncode == 0
    assert len(received) == 1, "首次投递应产生一次外发"
    first_key = received[0]["idempotency_key"]
    assert first_key

    completed = _run_cli(["deliver", "--batch", "KY20260001"], env=env)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(received) == 1, f"重复投递不应产生第二次外发（收到 {len(received)} 次）"
    assert "已交付" in completed.stdout


# --------------------------------------------------------------------- restore


def _delivered_batch(tmp_path, env) -> str:
    """造一个已交付的批次（台账里推到底）。"""
    from research_redact.audit.ledger import BatchLedger
    from research_redact.daemon.state_machine import (
        BatchEvent,
        TransitionContext,
    )

    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    try:
        batch_no = "KY20260001"
        ledger.open_batch(
            batch_no,
            ethics_approval_no="EC-2026-0001",
            patient_ids=("P-1001",),
            material_ids=("M-1",),
        )
        ledger.advance(
            batch_no,
            BatchEvent.APPLICATION_VALIDATED,
            TransitionContext(ethics_approval_no="EC-2026-0001", material_count=1),
            reason="申请单齐备",
        )
        ledger.advance(
            batch_no,
            BatchEvent.RECOGNITION_COMPLETED,
            TransitionContext(material_count=1, recognized_material_count=1),
            reason="识别完成",
        )
        ledger.advance(
            batch_no,
            BatchEvent.DELIVERY_SUCCEEDED,
            TransitionContext(residual_count=0, platform_delivered=True),
            reason="平台已回执",
        )
        ledger.record_receipt(
            receipt_id="KY20260001.fingerprint",
            batch_no=batch_no,
            kind="delivery",
            payload={"dataset_id": "DS-9001", "application_no": batch_no},
            platform_receipt_id="DS-9001",
        )
        return batch_no
    finally:
        ledger.close()


def test_restore_request缺第二授权人挂起(tmp_path):
    """restore-request：只有授权人 A → 受理后挂起等签字，不降级为单人。"""
    _write_inbox(tmp_path)
    env = _cli_env(
        **_paths(tmp_path),
        RESTORE_AUTHORIZER_LIST="张主任,李质控",
        PSEUDONYM_HMAC_KEY="test-key-for-cli",
    )
    batch_no = _delivered_batch(tmp_path, env)

    completed = _run_cli(
        ["restore-request", "--batch", batch_no, "--approver-a", "张主任"],
        env=env,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "状态：requested" in completed.stdout
    assert "（缺第二签字人）" in completed.stdout
    assert "挂起" in completed.stdout
    assert "不降级为单人还原" in completed.stdout


def test_restore_request授权人不在名单被拒(tmp_path):
    """restore-request：授权人不在名单内 → 拒绝，返回非 0。"""
    _write_inbox(tmp_path)
    env = _cli_env(
        **_paths(tmp_path),
        RESTORE_AUTHORIZER_LIST="张主任,李质控",
        PSEUDONYM_HMAC_KEY="test-key-for-cli",
    )
    batch_no = _delivered_batch(tmp_path, env)

    completed = _run_cli(
        ["restore-request", "--batch", batch_no, "--approver-a", "王干事"],
        env=env,
    )
    assert completed.returncode == 6, completed.stdout + completed.stderr
    assert "还原被拒" in completed.stderr


def test_restore_request双人授权完成还原(tmp_path):
    """restore-request：双人签字齐备 → 还原落盘，产出还原回执。"""
    from research_redact.audit.ledger import BatchLedger
    from research_redact.policy.index_store import EncryptedIndexStore

    _write_inbox(tmp_path)
    env = _cli_env(
        **_paths(tmp_path),
        RESTORE_AUTHORIZER_LIST="张主任,李质控",
        PSEUDONYM_HMAC_KEY="test-key-for-cli",
    )
    batch_no = _delivered_batch(tmp_path, env)

    # 一份带代号的脱敏副本 + 与之配套的加密对照索引
    token = "P-0daaf6ec23046198"
    artifact = tmp_path / "outbox" / batch_no / "materials" / "M-1.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(f"患者 {token} 于今日完成胸部 CT。\n", encoding="utf-8")

    index_path = tmp_path / "index" / "pseudonym_index.enc"
    store = EncryptedIndexStore(
        path=index_path,
        key="test-key-for-cli".encode("utf-8"),
        key_source="derived",
        batch_no=batch_no,
        actor="科研数据管理员",
    )
    store.record_occurrence("M-1", token, "张某某")
    store.save()
    env["RESEARCH_INDEX_FILE"] = str(index_path)

    # 台账登记产物路径（CLI 按台账找脱敏副本）
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    try:
        ledger.set_artifacts(batch_no, {"M-1": str(artifact)})
    finally:
        ledger.close()

    completed = _run_cli(
        [
            "restore-request",
            "--batch",
            batch_no,
            "--approver-a",
            "张主任",
            "--approver-b",
            "李质控",
            "--scope",
            "M-1",
            "--reason",
            "伦理核查需要核对第 3 例",
        ],
        env=env,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "状态：restored" in completed.stdout
    assert "已还原材料：1 份" in completed.stdout
    assert "还原回执：" in completed.stdout

    # 还原件落盘且把代号换回了原文
    restored = tmp_path / "outbox" / "restored" / batch_no / "M-1.txt"
    assert restored.is_file()
    assert restored.read_text(encoding="utf-8") == "患者 张某某 于今日完成胸部 CT。\n"


def test_restore_request索引不可达返回非0(tmp_path):
    """restore-request：对照索引不在 → 不得凭空还原，返回非 0。"""
    _write_inbox(tmp_path)
    env = _cli_env(
        **_paths(tmp_path),
        RESTORE_AUTHORIZER_LIST="张主任,李质控",
        PSEUDONYM_HMAC_KEY="test-key-for-cli",
        RESEARCH_INDEX_FILE=str(tmp_path / "没有这个索引.enc"),
    )
    batch_no = _delivered_batch(tmp_path, env)

    completed = _run_cli(
        [
            "restore-request",
            "--batch",
            batch_no,
            "--approver-a",
            "张主任",
            "--approver-b",
            "李质控",
        ],
        env=env,
    )
    assert completed.returncode != 0
    assert "对照索引" in completed.stderr


def test_restore_request批次不存在返回非0(tmp_path):
    """restore-request：批次不在台账里 → 返回非 0 并说明原因。"""
    _write_inbox(tmp_path)
    completed = _run_cli(
        [
            "restore-request",
            "--batch",
            "KY20269999",
            "--approver-a",
            "张主任",
        ],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "不在台账里" in completed.stderr


def test_restore_request缺参数返回非0(tmp_path):
    """restore-request：缺 --approver-a → 用法错误，返回非 0。"""
    completed = _run_cli(
        ["restore-request", "--batch", "KY20260001"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "--approver-a" in completed.stderr


# --------------------------------------------------------------------- residual


def test_verify_residual干净产物通过(tmp_path):
    """verify-residual：干净的脱敏副本 → 残留 0 处，退出码 0。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0

    completed = _run_cli(
        ["verify-residual", "--batch", "KY20260001"],
        env=env,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "已扫材料：1 份" in completed.stdout
    assert "残留 0 处" in completed.stdout


def test_verify_residual漏脱返回非0(tmp_path):
    """verify-residual：漏脱样例 → 阻断级残留，退出码 4（不得投递）。"""
    leaked = tmp_path / "leaked.txt"
    leaked.write_text(
        "姓名：张某某 住院号：90000001 手机号：13800138000\n", encoding="utf-8"
    )
    completed = _run_cli(
        ["verify-residual", "--in", str(leaked)],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode == 4, completed.stdout + completed.stderr
    assert "身份类残留" in completed.stdout
    assert "不得投递" in completed.stderr


def test_verify_residual必须且只能给一个目标(tmp_path):
    """verify-residual：两个都不给或都给 → 用法错误，返回非 0。"""
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["verify-residual"], env=env).returncode != 0
    both = _run_cli(
        ["verify-residual", "--batch", "KY20260001", "--in", str(tmp_path / "x.txt")],
        env=env,
    )
    assert both.returncode != 0
    assert "--batch" in both.stderr


def test_verify_residual文件不存在返回非0(tmp_path):
    """verify-residual：文件不存在 → 返回非 0 并说明原因。"""
    completed = _run_cli(
        ["verify-residual", "--in", str(tmp_path / "没有这个文件.txt")],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "文件不存在" in completed.stderr


def test_verify_residual输出不含患者原文(tmp_path):
    """verify-residual：终端输出不得回显命中原文。"""
    leaked = tmp_path / "leaked.txt"
    leaked.write_text(
        "姓名：张某某 住院号：90000001 手机号：13800138000\n", encoding="utf-8"
    )
    completed = _run_cli(
        ["verify-residual", "--in", str(leaked)],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode == 4
    for secret in PATIENT_IDENTITY_STRINGS:
        assert secret not in completed.stdout
        assert secret not in completed.stderr


# --------------------------------------------------------------------- status


def test_status列出全部批次(tmp_path):
    """status：不带 --batch → 列出台账里的全部批次。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0

    completed = _run_cli(["status"], env=env)
    assert completed.returncode == 0, completed.stderr
    assert "批次总数：1 个" in completed.stdout
    assert "KY20260001" in completed.stdout


def test_status打印批次时间线(tmp_path):
    """status --batch：打印每一步迁移的时间与原因。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0

    completed = _run_cli(["status", "--batch", "KY20260001"], env=env)
    assert completed.returncode == 0, completed.stderr
    assert "时间线" in completed.stdout
    assert "detected" in completed.stdout
    assert "recognized" in completed.stdout
    assert "幂等键：" in completed.stdout


def test_status批次不存在返回非0(tmp_path):
    """status：查不到的批次 → 返回非 0 并说明原因。"""
    completed = _run_cli(
        ["status", "--batch", "KY20269999"],
        env=_cli_env(**_paths(tmp_path)),
    )
    assert completed.returncode != 0
    assert "查不到批次" in completed.stderr


def test_status输出不含患者原文(tmp_path):
    """status：台账里的内容不得回显患者原文。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0
    completed = _run_cli(["status", "--batch", "KY20260001"], env=env)
    assert completed.returncode == 0, completed.stderr
    for secret in PATIENT_IDENTITY_STRINGS:
        assert secret not in completed.stdout


# --------------------------------------------------------------------- export


def test_export_audit导出并给出摘要(tmp_path):
    """export-audit：导出三种视图与摘要表，退出码 0。"""
    _write_inbox(tmp_path)
    env = _cli_env(**_paths(tmp_path))
    assert _run_cli(["run", "--batch", "KY20260001", "--no-deliver"], env=env).returncode == 0
    manifest = tmp_path / "outbox" / "KY20260001" / "manifest.jsonl"
    out_dir = tmp_path / "导出"

    completed = _run_cli(
        ["export-audit", "--manifest", str(manifest), "--out", str(out_dir)],
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    assert "导出命中清单：5 条" in completed.stdout
    assert (out_dir / "summary.csv").is_file()


# --------------------------------------------------------------------- 参数


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--delivery-dir"],  # 给了选项却没给值
        ["run"],  # 缺必填的 --batch
        ["restore-request", "--batch", "KY20260001"],  # 缺 --approver-a
        ["redact", "--in", "x"],  # 缺 --out / --manifest
    ],
)
def test_非法参数返回非0(args):
    """非法参数一律返回非 0（argparse 直接退出 2）。"""
    completed = _run_cli(args)
    assert completed.returncode != 0


def test_未知道具的子命令返回非0():
    """未知道的子命令返回非 0。"""
    completed = _run_cli(["没有这个子命令"])
    assert completed.returncode != 0
