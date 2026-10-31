"""语料获取验收：合成语料规模够大、同种子可复现、公开集拿不到就降级不中断。

本测试盯住「语料是可信基准」这条纪律的五件事：

1. **规模够**：默认 500 份材料、覆盖 ≥50 名患者 —— 少于这个量，代号一致性 /
   身份残留率 / 串号率三项指标都在噪声里；
2. **可复现**：同一种子两次生成**逐字节一致** —— 基准数字要能被重跑复核；
3. **不掺真数据**：每份材料带「合成语料」横幅，患者主键 / 就诊号 / 检查号 /
   身份证全部落在约定的合成段里；语料自己的元数据（材料编号、随机种子）
   **不进正文** —— 它们长得像住院号与检查号，会把指标带偏；
4. **与产品对得上**：合成语料走一遍主路径，身份类残留必须是 0，病名 / 药名 /
   剂量 / 金额必须原样保留（语料要能当误伤回归的输入）；
5. **公开集是可选增强**：下载失败（网络不通 / 哈希对不上 / 拆不出材料）一律
   降级到合成语料并写明降级原因，**不抛异常、不中断流程**；下载成功时 sha256
   必须校验通过，来源与许可必须落到 ``SOURCE.md``。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_PROJECT = Path(__file__).resolve().parents[1]
_SCRIPTS = _PROJECT / "scripts"
for _path in (str(_SCRIPTS), str(_PROJECT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import fetch_public_set  # noqa: E402
import gen_corpus  # noqa: E402
from research_redact.daemon.pipeline import redact_batch  # noqa: E402
from research_redact.recognizers.assembly import build_default_registry  # noqa: E402

#: 默认语料规模（规模基准按 500 份验收）
LIMIT = 500

#: 语料横幅：每份材料首行都要有
BANNER_MARK = "【合成语料】"


# ---------------------------------------------------------------------------
# 合成语料
# ---------------------------------------------------------------------------


def test_合成语料规模不少于500例且覆盖至少50名患者(tmp_path: Path) -> None:
    artifacts = gen_corpus.build_corpus(seed=gen_corpus.DEFAULT_SEED, limit=LIMIT)
    out = gen_corpus.write_corpus(artifacts, tmp_path / "corpus")

    material_files = sorted(out.rglob("materials/*.txt"))
    assert len(material_files) == LIMIT
    assert artifacts.index["material_count"] == LIMIT
    assert artifacts.index["patient_count"] >= 50

    manifest = (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(manifest) == LIMIT
    rows = [json.loads(line) for line in manifest]
    assert len({row["material_id"] for row in rows}) == LIMIT


def test_同种子两次生成逐字节一致(tmp_path: Path) -> None:
    first = gen_corpus.write_corpus(
        gen_corpus.build_corpus(seed=4242, limit=60), tmp_path / "a"
    )
    second = gen_corpus.write_corpus(
        gen_corpus.build_corpus(seed=4242, limit=60), tmp_path / "b"
    )
    files_a = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(second) for p in second.rglob("*") if p.is_file())
    assert files_a == files_b
    assert files_a, "语料目录不该是空的"
    for rel in files_a:
        assert (first / rel).read_bytes() == (second / rel).read_bytes(), (
            f"同种子两次生成不一致：{rel}"
        )


def test_不同种子生成结果不同(tmp_path: Path) -> None:
    first = gen_corpus.write_corpus(
        gen_corpus.build_corpus(seed=1, limit=30), tmp_path / "a"
    )
    second = gen_corpus.write_corpus(
        gen_corpus.build_corpus(seed=2, limit=30), tmp_path / "b"
    )
    left = (first / "manifest.jsonl").read_bytes()
    right = (second / "manifest.jsonl").read_bytes()
    assert left != right, "换种子必须换语料 —— 否则种子根本没起作用"


def test_语料含同名异人且每份材料带合成语料横幅(tmp_path: Path) -> None:
    artifacts = gen_corpus.build_corpus(seed=20260101, limit=LIMIT)
    by_name: dict[str, set[str]] = {}
    for spec in artifacts.materials:
        by_name.setdefault(spec.patient.name, set()).add(spec.patient.patient_id)
    shared = {name: ids for name, ids in by_name.items() if len(ids) > 1}
    assert shared, "语料里必须出现同名不同人 —— 否则消歧逻辑没得测"

    out = gen_corpus.write_corpus(artifacts, tmp_path / "corpus")
    for path in sorted(out.rglob("materials/*.txt"))[:20]:
        text = path.read_text(encoding="utf-8")
        assert text.startswith(BANNER_MARK), f"材料缺合成语料横幅：{path}"
        assert "语料版本：corpus-v1" in text


def test_语料正文不含语料自身的编号与种子(tmp_path: Path) -> None:
    """语料元数据不该被识别层当成身份 —— 否则残留自检报的是噪声不是漏脱。"""
    artifacts = gen_corpus.build_corpus(seed=20260101, limit=40)
    for spec in artifacts.materials:
        assert spec.material_id not in spec.text
        assert str(artifacts.index["seed"]) not in spec.text
        # 患者主键要在（离线跑一致代号要用），但就诊号与检查号必须带标签
        assert spec.patient.patient_id in spec.text
        assert f"住院号：{spec.visit_no}" in spec.text
        assert f"检查号：{spec.exam_no}" in spec.text


def test_申请单字段齐备且与材料一一对应(tmp_path: Path) -> None:
    artifacts = gen_corpus.build_corpus(seed=20260101, limit=60)
    out = gen_corpus.write_corpus(artifacts, tmp_path / "corpus")

    applications = sorted(out.glob("batches/*/application.json"))
    assert applications
    for path in applications:
        application = json.loads(path.read_text(encoding="utf-8"))
        assert application["application_no"]
        assert application["ethics_approval_no"], "缺伦理批件号的申请单不得进语料"
        assert application["patient_ids"]
        for material in application["materials"]:
            assert len(material["material_id"].split("-")) == 3, "材料 ID 必须是三段式"
            assert material["kind"] in ("report_text", "report_json", "table", "dicom")
            assert (path.parent / material["path"]).is_file()

    # 合成主索引名单只收申请单声明的患者
    for path in applications:
        application = json.loads(path.read_text(encoding="utf-8"))
        index = json.loads(
            (path.parent / "patient_index.json").read_text(encoding="utf-8")
        )
        declared = set(application["patient_ids"])
        records = index["records"]
        assert records
        for record in records:
            assert record["patient_id"] in declared
            assert record["visit_no"]
            assert record["name"]
            assert len(record["id_card_masked"]) == 18
            assert record["id_card_masked"].count("*") == 8


def test_清单里的sha256与材料字节对得上(tmp_path: Path) -> None:
    artifacts = gen_corpus.build_corpus(seed=20260101, limit=40)
    out = gen_corpus.write_corpus(artifacts, tmp_path / "corpus")
    rows = [
        json.loads(line)
        for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    for row in rows:
        payload = (out / row["path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == row["sha256"]
        assert len(payload) == row["bytes"]


def test_合成语料走主路径后身份类残留为0且临床内容保留(tmp_path: Path) -> None:
    """语料要能当误伤回归的输入：身份脱干净，病名药名剂量金额一字不动。"""
    artifacts = gen_corpus.build_corpus(seed=20260101, limit=40)
    out = gen_corpus.write_corpus(artifacts, tmp_path / "corpus")
    rows = [
        json.loads(line)
        for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
    ][:10]
    texts = {
        row["material_id"]: (out / row["path"]).read_text(encoding="utf-8")
        for row in rows
    }

    batch = redact_batch("KY2026C0001", texts, registry=build_default_registry())
    assert batch.deliverable, batch.residual.summary if batch.residual else ""
    assert batch.residual is not None
    assert batch.residual.identity_count == 0

    for spec in artifacts.materials[:10]:
        redacted = next(
            outcome.redacted_text
            for outcome in batch.outcomes
            if outcome.material_id == spec.material_id
        )
        assert spec.patient.name not in redacted
        assert spec.visit_no not in redacted
        assert spec.patient.phone not in redacted
        assert spec.patient.id_card not in redacted
        assert spec.patient.birth_date not in redacted
        # 临床内容不得被脱过头：**不含身份的每一行都必须逐字保留**
        identity_values = (
            spec.patient.name,
            spec.visit_no,
            spec.exam_no,
            spec.patient.phone,
            spec.patient.id_card,
            spec.patient.birth_date,
            spec.patient.patient_id,
        )
        for line in spec.text.splitlines():
            if not line.strip() or any(value in line for value in identity_values):
                continue
            assert line in redacted, f"非身份行被改写了：{line[:40]!r}"


def test_命令行支持limit_seed_out并覆盖旧产物(tmp_path: Path) -> None:
    out = tmp_path / "corpus"
    first = subprocess.run(
        [sys.executable, str(_SCRIPTS / "gen_corpus.py"), "--limit", "12",
         "--seed", "7", "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert first.returncode == 0, first.stderr
    assert len(sorted(out.rglob("materials/*.txt"))) == 12

    second = subprocess.run(
        [sys.executable, str(_SCRIPTS / "gen_corpus.py"), "--limit", "3",
         "--seed", "7", "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert second.returncode == 0, second.stderr
    # 覆盖旧产物：上一轮的 12 份不能残留，否则语料规模与 --limit 对不上
    assert len(sorted(out.rglob("materials/*.txt"))) == 3


# ---------------------------------------------------------------------------
# 公开集下载与降级
# ---------------------------------------------------------------------------


def test_公开集下载失败降级到合成集且不抛异常(tmp_path: Path) -> None:
    outcome = fetch_public_set.fetch_public_set(
        out_dir=tmp_path / "public",
        url="http://127.0.0.1:1/never-reachable.jsonl",
        timeout=2.0,
        limit=20,
    )
    assert outcome.degraded is True
    assert outcome.ok is False
    assert outcome.reason, "降级必须写明原因"
    assert "127.0.0.1:1" in outcome.reason or "下载失败" in outcome.reason
    assert outcome.material_count == 20
    assert (tmp_path / "public" / "synthetic" / "manifest.jsonl").is_file()
    degraded = json.loads((tmp_path / "public" / "DEGRADED.json").read_text(encoding="utf-8"))
    assert degraded["degraded"] is True
    assert degraded["reason"]
    assert "降级" in outcome.summary()


def test_公开集候选源默认禁用且清单可读() -> None:
    sources = fetch_public_set.load_sources()
    assert sources, "候选源清单必须存在（哪怕条目全部禁用）"
    assert all(source.enabled is False for source in sources), (
        "sha256 未核对前一律禁用 —— 写一个没核对过的哈希比不写更危险"
    )
    assert all(source.sha256 == "" for source in sources)


def test_公开集下载成功时校验sha256并记录来源与许可(tmp_path: Path) -> None:
    payload = (
        '{"text": "姓名：张某某 住院号：90000001 检查号：CHK0000001"}\n'
        '{"text": "姓名：李某某 住院号：90000002 检查号：CHK0000002"}\n'
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 的命名
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:  # 静音
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        good = fetch_public_set.fetch_public_set(
            out_dir=tmp_path / "good",
            url=f"http://127.0.0.1:{port}/deid.jsonl",
            sha256=digest,
            name="本地公开集",
            license_="CC-BY-4.0",
            timeout=5.0,
        )
        assert good.ok is True and good.degraded is False
        assert good.material_count == 2
        assert good.observed_sha256 == digest
        source_md = (tmp_path / "good" / "SOURCE.md").read_text(encoding="utf-8")
        assert "CC-BY-4.0" in source_md
        assert digest in source_md
        assert "本地公开集" in source_md
        assert len(list((tmp_path / "good" / "materials").glob("*.json"))) == 2

        bad = fetch_public_set.fetch_public_set(
            out_dir=tmp_path / "bad",
            url=f"http://127.0.0.1:{port}/deid.jsonl",
            sha256="0" * 64,
            name="本地公开集",
            timeout=5.0,
            limit=5,
        )
        assert bad.ok is False and bad.degraded is True
        assert "sha256" in bad.reason
    finally:
        server.shutdown()
        server.server_close()


def test_公开集清单候选源不可达时逐个换源并降级(tmp_path: Path) -> None:
    sources = (
        fetch_public_set.PublicSource(
            name="候选甲", url="http://127.0.0.1:1/a.jsonl", enabled=True
        ),
        fetch_public_set.PublicSource(
            name="候选乙", url="http://127.0.0.1:2/b.jsonl", enabled=True
        ),
    )
    outcome = fetch_public_set.fetch_public_set(
        out_dir=tmp_path / "public", sources=sources, timeout=2.0, limit=10
    )
    assert outcome.degraded is True
    tried = {name for name, _ in outcome.attempts}
    assert "候选甲" in tried and "候选乙" in tried
    assert len(outcome.attempts) == 2
