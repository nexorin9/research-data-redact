"""DICOM tag 级去标识验收。

影像材料的身份有两处：一处在 tag（患者姓名 / 编号 / 出生日期 / 申请医师 /
机构名），一处在**像素**（画面角上烧录的姓名）。本轮只做 tag 级 —— 因此本测试
盯住四件事：

1. **身份 tag 被清空、私有 tag 全清**（私有区藏住院号是最典型的漏脱）；
2. **必要 tag 保留且逐字不变**（检查号 / 序列号 / 设备信息）—— 研究方还要用；
3. **逐处处置进清单、清单不含原值**（与文本材料同一红线）；
4. **二次自检**：产物再解析一遍，身份 tag 与私有 tag 必须都是零长度。

**首版明确不做像素烧录**：``(0028,0301) BurnedInAnnotation`` 旗标原样保留，
由登记员人工点检 —— 测试对此有断言，免得哪天「以为涂过了」。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research_redact.audit.manifest import ManifestWriter
from research_redact.materials.dicom_redact import (
    IDENTITY_TAGS,
    DicomConfig,
    DicomParseError,
    DicomUnsupportedError,
    DicomVerificationError,
    iter_elements,
    parse_dicom,
    redact_dicom_bytes,
    redact_dicom_file,
    serialize_dicom,
    verify_dicom,
)
from research_redact.policy.dicom import DicomConfigError
from research_redact.policy.table import PolicyTableError, load_policy_table

from .dicom_builder import build_dicom, build_dicom_implicit, element, sequence

# ----------------------------------------------------------------- 样例数据

PATIENT_NAME = "张某某"
PATIENT_ID = "P-1001"
BIRTH_DATE = "19491231"
REFERRING_PHYSICIAN = "申请医师^李"
INSTITUTION = "示例市第一人民医院"
PRIVATE_VISIT_NO = "90000001"
PRIVATE_MARK = "HOSP-PRI-001"
ADMISSION_ID = "ZY20260001"
ACCESSION_NO = "CHK0000001"
SERIES_NO = "1"
MODALITY = "CT"
MANUFACTURER = "示例影像设备厂"
MODEL_NAME = "CT-9000"
STATION_NAME = "CT01"
NESTED_NAME = "嵌套^姓名"
NESTED_ID = "P-9999"


def _gb(text: str) -> bytes:
    """中文取值按 GB18030 编码（国内设备导出常用）。"""
    return text.encode("gb18030")


def _padded(value: bytes, vr: str = "LO") -> bytes:
    """按 DICOM 规则补齐到偶数长度（UI 用 NULL 补，其余用空格）。"""
    if len(value) % 2 == 0:
        return value
    return value + (b"\x00" if vr == "UI" else b" ")


def _dataset() -> list[bytes]:
    """构造样例数据集（含身份 tag、私有 tag、必要 tag 与一个嵌套序列）。"""
    return [
        element(0x0008, 0x0005, "CS", b"GB18030"),
        element(0x0008, 0x0016, "UI", b"1.2.840.10008.5.1.4.1.1.2"),
        element(0x0008, 0x0018, "UI", b"1.2.826.0.1.3680043.8.498.1"),
        element(0x0008, 0x0020, "DA", b"20260105"),
        element(0x0008, 0x0050, "SH", ACCESSION_NO.encode()),
        element(0x0008, 0x0060, "CS", MODALITY.encode()),
        element(0x0008, 0x0070, "LO", _gb(MANUFACTURER)),
        element(0x0008, 0x0080, "LO", _gb(INSTITUTION)),
        element(0x0008, 0x0090, "PN", _gb(REFERRING_PHYSICIAN)),
        element(0x0008, 0x1010, "SH", STATION_NAME.encode()),
        element(0x0008, 0x1030, "LO", _gb("胸部CT平扫")),
        element(0x0008, 0x1090, "LO", MODEL_NAME.encode()),
        element(0x0010, 0x0010, "PN", _gb(PATIENT_NAME)),
        element(0x0010, 0x0020, "LO", PATIENT_ID.encode()),
        element(0x0010, 0x0030, "DA", BIRTH_DATE.encode()),
        element(0x0010, 0x0040, "CS", b"F"),
        element(0x0012, 0x0062, "CS", b"NO"),
        element(0x0020, 0x000D, "UI", b"1.2.826.0.1.3680043.8.498.11"),
        element(0x0020, 0x000E, "UI", b"1.2.826.0.1.3680043.8.498.12"),
        element(0x0020, 0x0011, "IS", SERIES_NO.encode()),
        element(0x0020, 0x0013, "IS", b"1"),
        element(0x0028, 0x0010, "US", b"\x40\x00"),
        element(0x0028, 0x0011, "US", b"\x40\x00"),
        element(0x0028, 0x0301, "CS", b"YES"),
        element(0x0038, 0x0010, "LO", ADMISSION_ID.encode()),
        # 私有区（奇数组 0009）：住院号就藏在里面
        element(0x0009, 0x0010, "LO", PRIVATE_VISIT_NO.encode()),
        element(0x0009, 0x1001, "SH", PRIVATE_MARK.encode()),
        # 嵌套序列里的身份 tag
        sequence(
            0x0040,
            0x0275,
            [
                element(0x0010, 0x0010, "PN", _gb(NESTED_NAME))
                + element(0x0010, 0x0020, "LO", NESTED_ID.encode())
            ],
        ),
    ]


def _sample() -> bytes:
    """一份完整的样例 DICOM 文件。"""
    return build_dicom(_dataset())


def _values(data: bytes) -> dict[str, bytes]:
    """取出产物里各 tag 的取值（按关键字索引；同名取第一个）。"""
    dataset = parse_dicom(data)
    values: dict[str, bytes] = {}
    for element_ in iter_elements(dataset.elements):
        values.setdefault(element_.name, element_.value)
    return values


def _tags(data: bytes) -> list[tuple[str, str]]:
    """取出产物里全部 tag 的（关键字, tag 号）。"""
    dataset = parse_dicom(data)
    return [(e.name, e.tag_text) for e in iter_elements(dataset.elements)]


# ------------------------------------------------------------------- 用例


def test_身份tag被清空():
    """姓名 / 患者编号 / 出生日期 / 申请医师 / 机构名 / 住院号全部清空。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["PatientName"] == b""
    assert values["PatientID"] == b""
    assert values["PatientBirthDate"] == b""
    assert values["ReferringPhysicianName"] == b""
    assert values["InstitutionName"] == b""
    assert values["AdmissionID"] == b""
    # tag 本身还在（值变零长度）—— 文件结构不塌，研究方仍能打开
    names = [name for name, _ in _tags(outcome.data)]
    for keyword in ("PatientName", "PatientID", "PatientBirthDate"):
        assert keyword in names


def test_私有tag全清():
    """私有区（奇数组）里的内容一律清空 —— 住院号就藏在里面。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["(0009,0010)"] == b""
    assert values["(0009,1001)"] == b""
    assert outcome.counts["private_cleared"] == 2
    # 私有 tag 的原值不得出现在产物里
    assert PRIVATE_VISIT_NO.encode() not in outcome.data
    assert PRIVATE_MARK.encode() not in outcome.data


def test_必要tag保留且逐字不变():
    """检查号 / 序列号 / 设备信息保留，取值一个字节都不许动。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["AccessionNumber"] == ACCESSION_NO.encode()
    assert values["SeriesNumber"] == _padded(SERIES_NO.encode(), "IS")
    assert values["InstanceNumber"] == _padded(b"1", "IS")
    assert values["Modality"] == MODALITY.encode()
    assert values["Manufacturer"] == _gb(MANUFACTURER)
    assert values["ManufacturerModelName"] == _padded(MODEL_NAME.encode())
    assert values["StationName"] == STATION_NAME.encode()
    assert outcome.counts["kept"] == 7


def test_影像参数与像素数据不受影响():
    """Rows / Columns 等影像参数原样保留 —— 去标识不该把片子改坏。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["Rows"] == b"\x40\x00"
    assert values["Columns"] == b"\x40\x00"
    assert values["SOPInstanceUID"] == _padded(b"1.2.826.0.1.3680043.8.498.1", "UI")
    assert values["StudyInstanceUID"] == _padded(b"1.2.826.0.1.3680043.8.498.11", "UI")


def test_像素烧录旗标保留待人工点检():
    """首版不做像素涂除：BurnedInAnnotation 旗标原样保留，不假装已涂除。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["BurnedInAnnotation"] == _padded(b"YES", "CS")
    summary = [e for e in outcome.entries if e.label == "DICOM_SUMMARY"][0]
    assert "像素烧录未处理" in summary.reason


def test_序列内嵌套身份tag也被清空():
    """RequestAttributesSequence 里的姓名 / 患者编号同样要清空。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")

    assert NESTED_ID.encode() not in outcome.data
    assert _gb(NESTED_NAME) not in outcome.data
    nested = [
        e
        for e in iter_elements(parse_dicom(outcome.data).elements)
        if e.keyword in ("PatientName", "PatientID")
    ]
    assert nested, "嵌套序列里的身份 tag 不应被整段丢掉"
    assert all(e.value == b"" for e in nested)


def test_写入去标识标记():
    """按 DICOM 标准写入 PatientIdentityRemoved 与去标识方法。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    values = _values(outcome.data)

    assert values["PatientIdentityRemoved"] == _padded(b"YES", "CS")
    assert b"ResearchRedact" in values["DeidentificationMethod"]


def test_清单逐处记录且不含原值():
    """每一处处置都进清单；清单全文不含任何 tag 原值。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    labels = [entry.label for entry in outcome.entries]

    assert "DICOM_PRIVATE_TAG" in labels
    assert "DICOM_TAG" in labels
    assert "DICOM_SUMMARY" in labels

    summary = [e for e in outcome.entries if e.label == "DICOM_SUMMARY"][0]
    assert "DICOM 私有 tag 已清空（2 个）" in summary.reason
    assert "身份 tag 已清空" in summary.reason
    assert "必要 tag 保留（7 个）" in summary.reason

    payload = "\n".join(entry.reason for entry in outcome.entries)
    for secret in (
        PATIENT_NAME,
        PATIENT_ID,
        BIRTH_DATE,
        REFERRING_PHYSICIAN,
        INSTITUTION,
        PRIVATE_VISIT_NO,
        PRIVATE_MARK,
        ADMISSION_ID,
        NESTED_NAME,
        NESTED_ID,
    ):
        assert secret not in payload, f"清单混进了原值：{secret}"


def test_清单条数与处置数一致():
    """清单条数 = 逐处处置 + 一条批次摘要。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    per_item = [
        entry
        for entry in outcome.entries
        if entry.label in ("DICOM_TAG", "DICOM_PRIVATE_TAG")
    ]
    summary = [entry for entry in outcome.entries if entry.label == "DICOM_SUMMARY"]

    assert len(summary) == 1
    assert len(per_item) + len(summary) == len(outcome.entries)
    assert (
        len(per_item)
        == outcome.counts["identity_cleared"]
        + outcome.counts["private_cleared"]
        + outcome.counts["replaced"]
        + outcome.counts["kept"]
    )


def test_二次自检通过():
    """产物再解析一遍：身份 tag 与私有 tag 都得是零长度。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    check = verify_dicom(outcome.data)

    assert check.passed
    assert check.findings == ()
    assert outcome.self_check.passed
    assert outcome.deliverable


def test_二次自检能抓回残留():
    """没脱过的原始文件，自检必须把身份 tag 与私有 tag 全报出来。"""
    check = verify_dicom(_sample())

    assert not check.passed
    keywords = {finding.keyword for finding in check.findings}
    assert "PatientName" in keywords
    assert "PatientID" in keywords
    assert "(0009,0010)" in keywords
    assert "自检未通过" in check.summary


def test_自检未通过时拒绝交付():
    """处置表没覆盖到身份 tag 时，宁可报错中止，也不交一份「看着脱过了」的文件。"""
    config = DicomConfig.from_policy(
        {"clear_tags": [], "keep_tags": ["AccessionNumber"]}, source="测试"
    )
    with pytest.raises(DicomVerificationError):
        redact_dicom_bytes(_sample(), "M-DICOM-1", config=config)


def test_非DICOM文件报错():
    """不是 DICOM 的文件明确报错，不静默产出「已脱敏」的空壳。"""
    with pytest.raises(DicomParseError):
        redact_dicom_bytes(b"this is not a dicom file at all", "M-BAD")


def test_不支持的传输语法报错():
    """Deflated / 大端传输语法明确报错 —— 不猜、不降级。"""
    payload = build_dicom(_dataset(), transfer_syntax="1.2.840.10008.1.2.1.99")
    with pytest.raises(DicomUnsupportedError):
        redact_dicom_bytes(payload, "M-DEFLATED")


def test_隐式VR小端也能处理():
    """隐式 VR 小端（老设备）同样能解析与去标识。"""
    payload = build_dicom_implicit(
        [
            (0x0008, 0x0050, ACCESSION_NO.encode()),
            (0x0010, 0x0010, _gb(PATIENT_NAME)),
            (0x0010, 0x0020, PATIENT_ID.encode()),
            (0x0009, 0x0010, PRIVATE_VISIT_NO.encode()),
        ]
    )
    outcome = redact_dicom_bytes(payload, "M-IMPLICIT")
    values = _values(outcome.data)

    assert values["PatientName"] == b""
    assert values["PatientID"] == b""
    assert values["(0009,0010)"] == b""
    assert values["AccessionNumber"] == ACCESSION_NO.encode()


def test_写回后仍可解析且结构完整():
    """产物必须还能被解析器读回来（写坏的文件等于没脱）。"""
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1")
    again = parse_dicom(outcome.data)

    assert again.transfer_syntax == "1.2.840.10008.1.2.1"
    assert again.explicit_vr is True
    assert len(again.elements) > 20
    assert serialize_dicom(again) == outcome.data


def test_替换取值处置():
    """replace_tags：tag 保留、取值换成指定值。"""
    config = DicomConfig.from_policy(
        {
            "clear_tags": sorted(IDENTITY_TAGS - {"PatientID"}),
            "replace_tags": {"PatientID": "<患者编号>"},
        },
        source="测试",
    )
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1", config=config)
    values = _values(outcome.data)

    assert values["PatientID"] == "<患者编号>".encode()
    # 顶层与嵌套序列里的患者编号各替换一处
    assert outcome.counts["replaced"] == 2
    assert PATIENT_ID.encode() not in outcome.data


def test_白名单口径清空未列入保留表的标准tag():
    """default_action=clear 时，不在保留表里的标准 tag 一律清空。"""
    config = DicomConfig.from_policy(
        {
            "keep_tags": ["AccessionNumber"],
            "default_action": "clear",
            "clear_private_tags": True,
        },
        source="测试",
    )
    outcome = redact_dicom_bytes(_sample(), "M-DICOM-1", config=config)
    values = _values(outcome.data)

    assert values["AccessionNumber"] == ACCESSION_NO.encode()
    assert values["Manufacturer"] == b""
    assert values["Modality"] == b""


def test_处置表非法配置报错():
    """处置冲突 / 未知道具键 / 非法 tag 名一律报错，不静默取默认值。"""
    with pytest.raises(DicomConfigError):
        DicomConfig.from_policy({"keep_tags": ["PatientName"], "clear_tags": ["PatientName"]})
    with pytest.raises(DicomConfigError):
        DicomConfig.from_policy({"未知键": 1})
    with pytest.raises(DicomConfigError):
        DicomConfig.from_policy({"keep_tags": ["patient name"]})
    with pytest.raises(DicomConfigError):
        DicomConfig.from_policy({"default_action": "随便"})


def test_策略表装配DICOM段():
    """策略表的 dicom 段装进策略表对象；非法即报错。"""
    table = load_policy_table()

    assert table.dicom.enabled is True
    assert "PatientName" in table.dicom.clear_tags
    assert "AccessionNumber" in table.dicom.keep_tags
    assert table.dicom.clear_private_tags is True

    with pytest.raises(PolicyTableError):
        load_policy_table("policy/does-not-exist.yaml")


def test_策略表覆盖全部身份tag():
    """策略表的清空项必须盖住模块自带的身份 tag 底线。

    少登记一个不会立刻出事（二次自检仍会兜住），但等于把「这个 tag 该不该
    清」的决定交给了某次配置改动 —— 底线清单与策略表必须一致。
    """
    table = load_policy_table()
    missing = sorted(IDENTITY_TAGS - set(table.dicom.clear_tags))

    assert not missing, f"策略表未清空的身份 tag：{'、'.join(missing)}"


# ------------------------------------------------------- 守护进程主路径接入


def test_批次里的DICOM材料走主路径(tmp_path):
    """DICOM 材料与文本材料同批处理：产物落盘、清单合并、批次可交付。"""
    from research_redact.audit.ledger import BatchLedger
    from research_redact.daemon.runner import BatchRunner
    from research_redact.daemon.watcher import InboxWatcher

    application_dir = tmp_path / "inbox" / "KY20260009"
    (application_dir / "materials").mkdir(parents=True)
    (application_dir / "application.json").write_text(
        json.dumps(
            {
                "application_no": "KY20260009",
                "ethics_approval_no": "EC-2026-0009",
                "patient_ids": ["P-1001"],
                "materials": [
                    {
                        "material_id": "M-DICOM-1",
                        "kind": "dicom",
                        "path": "materials/ct_001.dcm",
                        "patient_id": "P-1001",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (application_dir / "materials" / "ct_001.dcm").write_bytes(_sample())

    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = BatchRunner(output_dir=tmp_path / "outbox", ledger=ledger)
    watcher = InboxWatcher(tmp_path / "inbox")

    result = runner.process(watcher.poll()[0], via_event=True)

    assert result.processed is True
    assert result.deliverable is True

    # 脱敏副本落盘（.dcm），身份串与私有区内容都不在
    artifact = Path(result.artifacts["M-DICOM-1"])
    assert artifact.suffix == ".dcm"
    data = artifact.read_bytes()
    for secret in (
        PATIENT_NAME.encode("gb18030"),
        PATIENT_ID.encode(),
        PRIVATE_VISIT_NO.encode(),
        INSTITUTION.encode("gb18030"),
    ):
        assert secret not in data

    # 批次清单里能看到 DICOM 的逐处处置与摘要
    entries = ManifestWriter.read(result.artifacts["manifest"])
    labels = {entry["label"] for entry in entries}
    assert "DICOM_TAG" in labels
    assert "DICOM_PRIVATE_TAG" in labels
    assert "DICOM_SUMMARY" in labels
    payload = json.dumps(entries, ensure_ascii=False)
    for secret in (PATIENT_NAME, PATIENT_ID, PRIVATE_VISIT_NO, INSTITUTION):
        assert secret not in payload
