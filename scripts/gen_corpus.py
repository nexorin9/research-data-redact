#!/usr/bin/env python3
"""确定性合成中文放射语料生成器（真实院内数据不可得时的默认取数路径）。

**为什么需要它**：脱敏效果不能只在几条手写样例上看。代号一致性、身份残留率、
串号率这三项指标只有在**成百上千份**、字段形态各异的材料上才测得出来；院内
真实数据带患者标识、拿不出来，本脚本用固定规则合成等价语料。

**确定性**：同一种子两次生成的**每一个文件逐字节一致**。做到这一点靠三件事：
输出里不写时间戳与机器信息；所有遍历都按固定顺序；随机数一律取自
``random.Random(整数种子)`` 派生的子发生器（不依赖全局随机状态，也不依赖
字符串哈希 —— 后者受 ``PYTHONHASHSEED`` 影响，不稳定）。

**不掺真数据**：姓名一律「姓 + 某某 / 某甲」式占位；住院号、门诊号、检查号、
身份证、手机号全部从**保留段**按固定规则生成；身份证校验位按 GB 11643 真算
（因此一定能被校验位识别器判为身份，而不是「长得像」）；病名、药名、剂量、
金额取自自造词表。语料里不含任何真实患者可识别信息，每份材料首行都带
「合成语料」横幅，便于事后一眼分辨。

**产物形态**（``--out`` 目录，默认 ``var/corpus/``）::

    corpus_index.json              语料总账：种子、规模、词表规模（不含时间戳）
    manifest.jsonl                 一行一份材料：材料 ID、患者主键、路径、sha256
    README.md                      布局说明与用法（怎么直接投进交付目录）
    batches/KY2026C0001/
        application.json           申请单（可直接投进守护进程的交付目录）
        patient_index.json         合成主索引名单（离线跑「姓名 + 就诊号」绑定用）
        materials/<材料 ID>.txt     材料正文

用法::

    python scripts/gen_corpus.py --limit 500 --seed 20260101 --out var/corpus
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

# 让脚本能直接 import 产品包（src 布局，无需先 pip install -e .）
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from research_redact.recognizers.id_card import gb11643_check_char  # noqa: E402

__all__ = [
    "CORPUS_VERSION",
    "CorpusArtifacts",
    "MaterialSpec",
    "PatientProfile",
    "build_corpus",
    "main",
    "write_corpus",
]


#: 语料版本号。产物结构变了才动它 —— 变了就说明旧语料与新代码不匹配。
CORPUS_VERSION = "corpus-v1"

#: 默认种子（固定值：默认跑出来的语料每次都一样）。
DEFAULT_SEED = 20260101

#: 默认材料份数（下游规模基准按 500 份验收）。
DEFAULT_LIMIT = 500

#: 默认输出目录（相对项目根）。
DEFAULT_OUT = Path("var") / "corpus"

#: 一个批次装几份材料（一个批次 = 一张申请单）。
BATCH_SIZE = 10

#: 每位患者平均几份材料（用于把材料数摊到患者上）。
MATERIALS_PER_PATIENT = 8

#: 语料首行横幅 —— 每份材料都带，事后一眼能分辨「这是合成的」。
SYNTHETIC_BANNER = (
    "【合成语料】本文件由 scripts/gen_corpus.py 按固定种子确定性生成；"
    "人物、编号、日期、机构均为虚构，与任何真实患者信息无关。"
)

# ---------------------------------------------------------------------------
# 词表
#
# 姓名一律「姓 + 某某 / 某甲」式占位：既能被姓名识别器正常命中（形态与真实
# 姓名一致），又一眼看得出是占位符，不会被误当成真人。
# ---------------------------------------------------------------------------

SURNAMES: tuple[str, ...] = (
    "张", "李", "王", "赵", "刘", "陈", "杨", "黄", "周", "吴", "徐", "孙",
)

GIVEN_NAMES: tuple[str, ...] = (
    "某某", "某甲", "某乙", "某丙", "某丁", "某己",
)

#: 姓名池大小（决定同名异人的密度：患者数超过它就会出现同名不同人）。
NAME_POOL_SIZE = 20

SEXES: tuple[str, ...] = ("男", "女")

#: 身份证地址码（保留段示例值）。
REGION_CODES: tuple[str, ...] = (
    "110101", "110105", "120103", "310104", "310110",
    "320106", "330106", "420106", "440106", "510107",
)

PHONE_PREFIXES: tuple[str, ...] = (
    "138", "139", "137", "136", "135", "150", "151", "158", "186", "189", "199",
)

#: 检查项目与其对应解剖部位。
EXAM_ITEMS: tuple[tuple[str, str], ...] = (
    ("胸部CT平扫", "胸部"),
    ("胸部CT平扫+增强", "胸部"),
    ("头颅MRI平扫", "颅脑"),
    ("腹部CT平扫", "腹部"),
    ("腰椎X线正侧位", "腰椎"),
    ("心脏彩色多普勒超声", "心脏"),
    ("腹部彩色多普勒超声", "腹部"),
    ("胸部DR正侧位", "胸部"),
    ("骨盆CT", "骨盆"),
    ("颈部CT", "颈部"),
)

DEPARTMENTS: tuple[str, ...] = (
    "呼吸内科", "心血管内科", "消化内科", "神经内科", "内分泌科",
    "骨科", "普外科", "泌尿外科", "急诊科", "肿瘤科",
)

#: 检查所见句式（{size} 毫米、{hu} 窗值、{side} 侧别）。
FINDING_TEMPLATES: tuple[str, ...] = (
    "右肺上叶见类圆形结节影，边缘可见毛刺征，直径约 {size}mm，密度约 {hu}HU",
    "左肺下叶见磨玻璃结节影，边界尚清晰，直径约 {size}mm",
    "右肺下叶后基底段见片状实变影，边界模糊，密度约 {hu}HU",
    "双肺纹理增粗，肺门血管影增浓，未见明显肺门淋巴结肿大",
    "纵隔内未见明显肿大淋巴结影，心影不大",
    "双侧胸腔未见积液影，肋膈角锐利",
    "肝表面光滑，肝实质未见异常密度影",
    "胆囊大小形态正常，壁不厚，腔内未见结石影",
    "胰头大小形态正常，胰管未见明显扩张",
    "脾脏大小形态正常，实质未见异常信号",
    "双肾大小对称，皮髓质分界清楚，集合系统未见扩张",
    "胃壁稍增厚，胃腔内未见明显气液平面",
    "肠管未见扩张积气，腹膜后未见异常淋巴结影",
    "颅内未见明显出血灶，中线结构居中，脑沟脑池未见异常",
    "双侧基底节区见点状低密度影，边界欠清",
    "颈部软组织未见明显肿胀，气管居中",
    "领面部骨窗未见明显骨折线，骨质结构完整",
    "左侧肾盂内见点状高密度影，右肾未见异常",
    "前列腺体积稍大，膀胱壁不厚",
    "所示椎体骨质结构完整，未见压缩性骨折",
    "所示肋骨骨质完整，未见病理性骨折",
    "腹主动脉未见明显扩张，钙化斑块少许",
    "肝门静脉未见明显扩张，胆总管未见扩张",
    "未见明显积液及气体",
)

#: 影像学诊断句式（病名 —— 不得被当成身份类）。
DIAGNOSIS_TEMPLATES: tuple[str, ...] = (
    "右肺上叶磨玻璃结节，性质待定，建议 3 个月后随访复查",
    "2 型糖尿病",
    "原发性高血压 3 级（极高危）",
    "慢性阻塞性肺疾病",
    "肺炎",
    "脑梗死",
    "腰椎间盘突出",
    "胆囊结石",
    "慢性胃炎",
    "冠状动脉粥样硬化性心脏病",
    "继发性肺结核",
    "急性阑尾炎",
    "肾结石",
    "前列腺增生",
    "缺铁性贫血",
    "房间隔缺损",
)

#: 医嘱建议句式（含剂量与金额 —— 用来验证「脱过头」防线）。
ADVICE_TEMPLATES: tuple[str, ...] = (
    "餐后服用盐酸氨溴索口服液 30mL 每日 3 次",
    "疼痛时口服布洛芬缓释胶囊 0.3g",
    "抗感染治疗：阿莫西林胶囊 0.5g 每日 3 次",
    "降压治疗：硝苯地平控释片 30mg 每日 1 次",
    "降糖治疗：二甲双胍缓释片 0.5g 每日 2 次",
    "雾化吸入：布地奈德混悬液 2mL 每日 2 次",
    "补钙治疗：碳酸钙 D3 片 600mg 每日 1 次",
    "调脂治疗：阿托伐他汀钙片 20mg 每晚 1 次",
    "抗凝治疗：华法林钠片 2.5mg 每日 1 次",
    "建议多饮水，饮食清淡，避免辛辣刺激食物",
    "建议 3 个月后门诊复查，携带本次报告",
    "建议呼吸科门诊随诊，评估是否需要进一步检查",
)

#: 既往检查说明。刻意**不写具体日期** —— 报告日期与出生日期同形，
#: 裸日期会被出生日期形态误判，语料里不留这种噪声。
PRIOR_TEMPLATES: tuple[str, ...] = (
    "无",
    "外院资料未带",
    "同院既往资料未带",
)

#: 材料正文字节数目标区间（1–20 KB —— 与规模基准的验收区间一致）。
MIN_TARGET_BYTES = 1500
MAX_TARGET_BYTES = 18000


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatientProfile:
    """语料里的一位患者（全部字段都是合成的）。

    :param patient_id: 患者主索引主键（权威身份标识）。
    :param name: 姓名（占位式）。
    :param sex: 性别。
    :param birth_date: 出生日期（``YYYY-MM-DD``）。
    :param phone: 手机号。
    :param id_card: 身份证号（校验位按 GB 11643 真算）。
    :param region_code: 身份证地址码。
    """

    patient_id: str
    name: str
    sex: str
    birth_date: str
    phone: str
    id_card: str
    region_code: str


@dataclass(frozen=True)
class MaterialSpec:
    """语料里的一份材料。

    :param material_id: 材料 ID（三段式：申请单号-检查号-序号）。
    :param application_no: 所属申请单号。
    :param patient: 患者画像。
    :param visit_no: 就诊号（住院号或门诊号）。
    :param exam_no: 检查号。
    :param kind: 材料类型。
    :param rel_path: 相对语料根目录的路径。
    :param text: 材料正文。
    :param planted: 故意植入的身份类实体类别。
    """

    material_id: str
    application_no: str
    patient: PatientProfile
    visit_no: str
    exam_no: str
    kind: str
    rel_path: str
    text: str
    planted: tuple[str, ...]


@dataclass(frozen=True)
class CorpusArtifacts:
    """一次语料生成的产物。

    :param files: 相对路径 → 文件字节（**已排好序**，写盘顺序稳定）。
    :param index: ``corpus_index.json`` 的内容。
    :param materials: 材料清单（供下游脚本直接消费，不必回读文件）。
    """

    files: Mapping[str, bytes]
    index: Mapping[str, object]
    materials: tuple[MaterialSpec, ...]


# ---------------------------------------------------------------------------
# 生成
# ---------------------------------------------------------------------------


def _byte_len(text: str) -> int:
    """UTF-8 字节长度（语料大小按字节算，不是按字符数）。"""
    return len(text.encode("utf-8"))


def _patient_rng(seed: int, index: int) -> random.Random:
    """患者画像的随机源（整数种子派生，与全局随机状态无关）。"""
    return random.Random(seed * 7_919 + index)


def _material_rng(seed: int, index: int) -> random.Random:
    """单份材料的随机源（整数种子派生）。"""
    return random.Random(seed * 104_729 + index)


def _make_patient(seed: int, index: int) -> PatientProfile:
    """造一位患者。

    姓名取自姓名池（**故意让患者数超过姓名池** —— 同名异人是真实存在的，
    语料里必须有这种场景，绑定逻辑才测得出来）。
    """
    rng = _patient_rng(seed, index)
    patient_id = f"P-{1000 + index}"
    name_index = index % NAME_POOL_SIZE
    name = SURNAMES[name_index % len(SURNAMES)] + GIVEN_NAMES[name_index // len(SURNAMES)]
    sex = rng.choice(SEXES)
    year = rng.randint(1940, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    birth_date = f"{year:04d}-{month:02d}-{day:02d}"
    phone = rng.choice(PHONE_PREFIXES) + f"{rng.randint(0, 99999999):08d}"
    region = rng.choice(REGION_CODES)
    sequence = f"{(index * 7 + 13) % 1000:03d}"
    body17 = f"{region}{year:04d}{month:02d}{day:02d}{sequence}"
    id_card = body17 + gb11643_check_char(body17)
    return PatientProfile(
        patient_id=patient_id,
        name=name,
        sex=sex,
        birth_date=birth_date,
        phone=phone,
        id_card=id_card,
        region_code=region,
    )


def _age_at(birth_date: str, report_date: str) -> int:
    """按报告日期算周岁（出生月未到就减一岁）。"""
    born_y, born_m, born_d = (int(part) for part in birth_date.split("-"))
    rep_y, rep_m, rep_d = (int(part) for part in report_date.split("-"))
    age = rep_y - born_y
    if (rep_m, rep_d) < (born_m, born_d):
        age -= 1
    return max(age, 0)


def _render_report(
    *,
    patient: PatientProfile,
    visit_no: str,
    exam_no: str,
    department: str,
    exam_item: str,
    body_part: str,
    report_date: str,
    clinical_diagnosis: str,
    rng: random.Random,
) -> str:
    """渲染一份放射报告正文。

    正文里**故意混进**剂量、金额、页码、床号、序号、日期片段 —— 这些是
    「脱过头」的高发区（它们长得像住院号与身份证），语料里必须成规模出现，
    误伤回归才有意义。

    **正文里不写材料编号与随机种子**：材料编号里嵌着检查号、种子是 8 位纯数字
    —— 两者都会被编号形态识别器当成就诊编号候选。语料自己的元数据不该让
    识别层判成身份，否则残留自检会报出一堆「漏脱」，指标全被语料噪声带偏。
    材料编号与种子在 ``manifest.jsonl`` / ``corpus_index.json`` 里对得上。
    """
    age = _age_at(patient.birth_date, report_date)
    target_bytes = rng.randint(MIN_TARGET_BYTES, MAX_TARGET_BYTES)

    header = [
        SYNTHETIC_BANNER,
        f"语料版本：{CORPUS_VERSION}",
        "",
        "市第一人民医院  放射科检查报告",
        "=" * 80,
        f"姓名：{patient.name}    住院号：{visit_no}    性别：{patient.sex}    年龄：{age}岁",
        f"患者编号：{patient.patient_id}    科别：{department}",
        f"检查号：{exam_no}    床位：{rng.randint(1, 40)}床",
        f"出生日期：{patient.birth_date}    手机号：{patient.phone}",
        f"身份证号：{patient.id_card}",
        "=" * 80,
        f"检查项目：{exam_item}",
        f"检查部位：{body_part}",
        f"检查方法：螺旋扫描，层厚 {rng.choice(['1.0', '2.0', '3.0', '5.0'])}mm，"
        f"管电压 {rng.choice(['100', '120', '140'])}kV，管电流 {rng.choice(['150', '200', '250'])}mAs",
        f"检查日期：{report_date}",
        f"临床诊断：{clinical_diagnosis}",
        "检查所见：",
    ]

    findings: list[str] = []
    total = _byte_len("\n".join(header))
    # 前一轮把句式打乱再轮转：同一份报告里的相邻句式不重复，读起来像真报告
    order = rng.sample(FINDING_TEMPLATES, len(FINDING_TEMPLATES))
    index = 0
    while total < target_bytes:
        template = order[index % len(order)]
        line = "  " + template.format(
            size=rng.choice(["6", "8", "10", "12", "15", "18", "22", "26"]),
            hu=rng.choice(["-320", "-180", "-60", "30", "45", "60"]),
        )
        findings.append(line)
        total += _byte_len(line) + 1
        index += 1

    diagnoses = rng.sample(DIAGNOSIS_TEMPLATES, k=rng.randint(1, 3))
    advice = rng.sample(ADVICE_TEMPLATES, k=rng.randint(2, 4))

    tail = [
        "影像学诊断：",
    ]
    tail.extend(f"  {i}、{text}" for i, text in enumerate(diagnoses, start=1))
    tail.append("建议：")
    tail.extend(f"  {i}、{text}" for i, text in enumerate(advice, start=1))
    tail.append(f"既往检查：{rng.choice(PRIOR_TEMPLATES)}")
    tail.append(
        f"报告日期：{report_date}    报告医师：示例医师    审核医师：示例审核医师"
    )
    tail.append(f"（本页为第 {rng.randint(1, 6)} 页 / 共 {rng.randint(1, 6)} 页）")
    tail.append(f"本次检查费用合计 {rng.randint(80, 980)}.{rng.randint(0, 99):02d} 元")
    tail.append(f"住院总费用 {rng.randint(1000, 98000)}.{rng.randint(0, 99):02d} 元")

    return "\n".join(header + findings + tail) + "\n"


def _plan_materials(limit: int) -> list[tuple[int, int]]:
    """把材料摊到患者上（返回 ``(患者下标, 该患者第几份材料)`` 序列）。

    **轮转排布**：同一位患者的材料摊开到不同批次里 —— 一致代号要跨材料
    恒等，就得让同一个人出现在不同批次里，语料才有得验。
    """
    if limit <= 0:
        return []
    patient_count = max(1, (limit + MATERIALS_PER_PATIENT - 1) // MATERIALS_PER_PATIENT)
    base, remainder = divmod(limit, patient_count)
    counts = [base + (1 if i < remainder else 0) for i in range(patient_count)]
    plan: list[tuple[int, int]] = []
    for ordinal in range(max(counts)):
        for patient_index, count in enumerate(counts):
            if ordinal < count:
                plan.append((patient_index, ordinal))
    return plan


def build_corpus(*, seed: int = DEFAULT_SEED, limit: int = DEFAULT_LIMIT) -> CorpusArtifacts:
    """按种子与规模生成语料（**纯函数**：不碰磁盘，便于直接断言确定性）。"""
    if limit < 0:
        raise ValueError(f"材料数不能为负：{limit}")
    plan = _plan_materials(limit)
    patients = {index: _make_patient(seed, index) for index, _ in plan}

    materials: list[MaterialSpec] = []
    for material_index, (patient_index, ordinal) in enumerate(plan):
        patient = patients[patient_index]
        rng = _material_rng(seed, material_index)
        application_no = f"KY2026C{material_index // BATCH_SIZE + 1:04d}"
        sequence = material_index % BATCH_SIZE + 1
        exam_no = f"CHK{material_index + 1:07d}"
        material_id = f"{application_no}-{exam_no}-{sequence:02d}"
        # 住院号按「患者 + 就诊序」生成：同一患者的不同次住院拿到不同住院号
        # （一人多号），不同患者不会撞号。
        visit_no = f"{90000000 + patient_index * 100 + ordinal:08d}"
        department = DEPARTMENTS[(patient_index + ordinal) % len(DEPARTMENTS)]
        exam_item, body_part = EXAM_ITEMS[(patient_index + ordinal) % len(EXAM_ITEMS)]
        report_date = f"2025-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
        clinical_diagnosis = rng.choice(DIAGNOSIS_TEMPLATES)
        text = _render_report(
            patient=patient,
            visit_no=visit_no,
            exam_no=exam_no,
            department=department,
            exam_item=exam_item,
            body_part=body_part,
            report_date=report_date,
            clinical_diagnosis=clinical_diagnosis,
            rng=rng,
        )
        rel_path = (
            f"batches/{application_no}/materials/{material_id}.txt"
        )
        materials.append(
            MaterialSpec(
                material_id=material_id,
                application_no=application_no,
                patient=patient,
                visit_no=visit_no,
                exam_no=exam_no,
                kind="report_text",
                rel_path=rel_path,
                text=text,
                planted=(
                    "PATIENT_NAME",
                    "PATIENT_ID",
                    "VISIT_NO",
                    "EXAM_NO",
                    "PHONE",
                    "BIRTH_DATE",
                    "ID_CARD",
                ),
            )
        )

    files: dict[str, bytes] = {}
    manifest_lines: list[str] = []
    for spec in materials:
        payload = spec.text.encode("utf-8")
        files[spec.rel_path] = payload
        manifest_lines.append(
            json.dumps(
                {
                    "material_id": spec.material_id,
                    "application_no": spec.application_no,
                    "patient_id": spec.patient.patient_id,
                    "kind": spec.kind,
                    "path": spec.rel_path,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "planted": list(spec.planted),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )

    # 申请单与合成主索引名单：一个批次一份。
    batch_patients: dict[str, dict[str, PatientProfile]] = {}
    batch_visit_nos: dict[str, dict[str, list[str]]] = {}
    for spec in materials:
        slot = batch_patients.setdefault(spec.application_no, {})
        slot.setdefault(spec.patient.patient_id, spec.patient)
        visits = batch_visit_nos.setdefault(spec.application_no, {})
        visits.setdefault(spec.patient.patient_id, [])
        if spec.visit_no not in visits[spec.patient.patient_id]:
            visits[spec.patient.patient_id].append(spec.visit_no)

    for application_no in sorted(batch_patients):
        patients_in_batch = batch_patients[application_no]
        entries = []
        for patient_id in sorted(patients_in_batch):
            patient = patients_in_batch[patient_id]
            for visit_no in batch_visit_nos[application_no][patient_id]:
                entries.append(
                    {
                        "patient_id": patient.patient_id,
                        "visit_no": visit_no,
                        "name": patient.name,
                        "id_card_masked": _mask_id_card(patient.id_card),
                        "birth_date": patient.birth_date,
                        "sex": patient.sex,
                    }
                )
        application = {
            "application_no": application_no,
            "ethics_approval_no": f"EC-2026-C{application_no[-4:]}",
            "patient_ids": sorted(patients_in_batch),
            "materials": [
                {
                    "material_id": spec.material_id,
                    "kind": spec.kind,
                    "path": f"materials/{spec.material_id}.txt",
                    "patient_id": spec.patient.patient_id,
                }
                for spec in materials
                if spec.application_no == application_no
            ],
        }
        files[f"batches/{application_no}/application.json"] = (
            json.dumps(application, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        files[f"batches/{application_no}/patient_index.json"] = (
            json.dumps({"records": entries}, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")

    files["manifest.jsonl"] = ("\n".join(manifest_lines) + "\n").encode("utf-8")

    index = {
        "corpus_version": CORPUS_VERSION,
        "generator": "scripts/gen_corpus.py",
        "seed": seed,
        "limit": limit,
        "material_count": len(materials),
        "patient_count": len({spec.patient.patient_id for spec in materials}),
        "batch_count": len(batch_patients),
        "batch_size": BATCH_SIZE,
        "total_bytes": sum(
            len(payload)
            for path, payload in files.items()
            if "/materials/" in path
        ),
        "distinct_names": len({spec.patient.name for spec in materials}),
        "note": (
            "全部为程序合成数据，不含任何真实患者可识别信息；"
            "姓名取自占位姓名池，身份证校验位按 GB 11643 真算。"
        ),
    }
    files["corpus_index.json"] = (
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    files["README.md"] = _render_corpus_readme(index).encode("utf-8")

    return CorpusArtifacts(
        files={path: files[path] for path in sorted(files)},
        index=index,
        materials=tuple(materials),
    )


def _mask_id_card(id_card: str) -> str:
    """身份证掩码（与主索引读回格式一致：中间 8 位打码）。"""
    if len(id_card) != 18:
        return id_card
    return f"{id_card[:6]}********{id_card[14:]}"


def _render_corpus_readme(index: Mapping[str, object]) -> str:
    """语料目录内的布局说明。"""
    return f"""# 合成语料（{index['corpus_version']}）

本目录由 `scripts/gen_corpus.py` 按固定种子确定性生成，**不含任何真实患者
可识别信息**。同一种子重新生成，逐字节一致。

| 项目 | 值 |
|------|-----|
| 材料份数 | {index['material_count']} |
| 患者数 | {index['patient_count']} |
| 不同姓名数 | {index['distinct_names']} |
| 批次数（= 申请单数） | {index['batch_count']} |
| 生成种子 | {index['seed']} |

## 目录结构

```
corpus/
├── corpus_index.json        语料总账（种子、规模、词表规模）
├── manifest.jsonl           一行一份材料：材料 ID、患者主键、路径、sha256、植入的身份类别
├── README.md                本文件
└── batches/<申请单号>/
    ├── application.json     申请单（字段与真实申请单一致）
    ├── patient_index.json   合成主索引名单（离线跑「姓名 + 就诊号」绑定用）
    └── materials/<材料 ID>.txt
```

## 怎么用

**当作交付目录投给守护进程**（一个批次目录就是一个申请单）：

```bash
cp -r var/corpus/batches/KY2026C0001 var/inbox/
python -m research_redact.daemon --once
```

**离线跑识别与残留自检**（基线对比、规模基准都从这里取语料）：

```bash
python - <<'PY'
import json, pathlib
root = pathlib.Path("var/corpus")
rows = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
texts = {{r["material_id"]: (root / r["path"]).read_text(encoding="utf-8") for r in rows}}
print(len(texts))
PY
```

## 为什么要同名

姓名池比患者数小，语料里**必然出现同名不同人**（不同患者主键、不同就诊号、
同一个姓名）。这是真实病案里最常见的一类歧义 —— 绑定错了就是串号，
代号一致性与串号率这两项指标才有得测。
"""


def write_corpus(artifacts: CorpusArtifacts, out_dir: str | Path) -> Path:
    """把语料写盘。**覆盖旧产物**：目标目录先整体清掉再写。

    不清就写的话，上一轮多出来的材料会留在目录里 —— 语料规模就与
    ``--limit`` 对不上了，基准数字会飘。
    """
    target = Path(out_dir)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    for rel_path in sorted(artifacts.files):
        path = target / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(artifacts.files[rel_path])
    return target


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        prog="gen_corpus.py",
        description="确定性合成中文放射语料（真实院内数据不可得时的默认取数路径）",
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT, help="生成多少份材料（默认 500）"
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="随机种子（默认 20260101）"
    )
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="输出目录（默认 var/corpus）"
    )
    args = parser.parse_args(argv)

    artifacts = build_corpus(seed=args.seed, limit=args.limit)
    out = write_corpus(artifacts, args.out)
    index = artifacts.index
    print(f"语料已生成：{out}")
    print(
        f"  材料 {index['material_count']} 份 / 患者 {index['patient_count']} 名 / "
        f"批次 {index['batch_count']} 个 / 不同姓名 {index['distinct_names']} 个"
    )
    print(f"  种子 {index['seed']}；同种子重跑逐字节一致")
    print(f"  清单 var: {out / 'manifest.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
