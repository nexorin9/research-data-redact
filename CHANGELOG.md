# 变更日志

本文件由沌构机（ChaosForge）在每轮交付时自动生成与维护，**不需要人工编辑**。条目按交付顺序排列，面向「这个项目现在能做什么」。版本块最新的在最上方。

## [0.1.0] - 2026-10-31

**本轮目标**：科研数据管理员把一批按申请单装好的影像与报告放进交付目录，守护进程把患者身份换成跨材料一致的密文代号，交出一份逐处命中清单并做残留自检，随后交付到科研数据平台；核查需要把某几例换回原文时，必须双人授权并留下一条还原回执

| 给谁用 | 什么时候用 |
|--------|------------|
| 科研数据管理员 | 按伦理批件把一批影像与报告装进交付目录之后 |

### 跑通主干

- **项目脚手架：目录结构、依赖与凭据位模板、中文 README 完整骨架**
  建立项目子目录 research-data-redact/（与 task.json 顶层 project 逐字一致），落依赖清单、凭据位模板、策略表骨架、docs 目录与中文 README 完整章节骨架。所有项目文件只落在子目录内，round 根目录不建 src/ 或 README.md。README 首行用中文产品名「科研影像数据脱敏系统」，不得出现上游开源项目名
  - 证据：research-data-redact/ 子目录存在且含 README.md（338 行 / ## 13 / ### 18 / 表 59 行 / 代码块围栏 24）、qrcode.jpg、requirements.txt、pyproject.toml、conftest.py、.env.example、.gitignore、policy/research.yaml、src/research_re…

### 新增能力

- **识别引擎地基：实体区间模型、识别器基类、注册表（阈值 / 去重 / 白名单）**
  落地融合后产品主路径的第一段：识别引擎内核。参照 github_ref/presidio/presidio-analyzer/presidio_analyzer/analyzer_engine.py 的 AnalyzerEngine.analyze（注册表 → 逐识别器打分 → 阈值过滤 → 去重 → 白名单）与 __remove_low_scores、_remove_allow_list、EntityRecognizer.remov…
  - 证据：`pytest tests/test_registry.py -q` 通过（15 passed，日志 logs/task2-registry-test.log）：逐识别器阈值 0.80 覆盖全局阈值 0.50 生效（0.6 分命中降为 warning 档并写明阈值差距）；同段完全重合只保留 1 条且被折叠方记入 merged_duplicates=('VISIT_NO@visit_no',)；白…
- **最窄端到端主路径跑通：一份材料 → 脱敏副本 + 逐处命中清单**
  按最小切片纪律，前 3 个任务结束时主干必须端到端可运行。本任务把识别引擎接入管道：材料进 → 脱敏副本出 + 逐处命中清单出。管道主体放在 daemon/pipeline.py（守护进程与 CLI 共用同一主路径，守护进程入口在 task 11 接入），命中清单格式参照 github_ref/presidio/presidio-cli/presidio_cli/cli.py 的 Format.standard / parsable…
  - 证据：`pytest tests/test_end_to_end.py tests/test_audit_no_rawtext.py -q` → 16 passed（日志 logs/task3-end-to-end.log）；`python -m research_redact.cli redact --in fixtures/report_001.txt --out /tmp/redacted.tx…
- **识别器包（正则形态）：就诊编号与联系方式识别器**
  落地识别器包里的「正则形态」两类：就诊编号（住院号 / 门诊号 / 检查号）与联系方式（手机号 / 出生日期）。三种形态（正则 / 校验位 / 名单）中本任务只做正则形态 —— 校验位形态拆到 task 18（GB 11643）、名单形态拆到 task 17（患者身份锚定）、数字类歧义消解放到 task 19，避免单任务过载
  - 证据：`pytest tests/test_recognizers.py -q` → 21 passed（日志 logs/task4-recognizers-test.log）；全量回归 `pytest tests -q` → 52 passed；住院号 90000001 / 门诊号 MZ123456 / 检查号 CHK0000001 / 手机号 13800138000 / 出生日期 1949-12-…
- **邻近上下文加分首版：字符 n-gram 邻近窗口打分**
  源产品靠 spaCy lemma 做上下文加分，在不引语言模型的前提下不成立，本轮改写为字符 n-gram 邻近窗口打分。证据：github_ref/presidio/presidio-analyzer/presidio_analyzer/analyzer_engine.py::_enhance_using_context（:299-358）与 LemmaContextAwareEnhancer
  - 证据：`pytest tests/test_context_boost.py -q` 通过（23 passed，日志 logs/task5-context-boost.log）：窗口内低分命中 0.40→0.50 升为确认档且解释写明命中的上下文词；上下文词距命中 60 字符（窗口外）时分数保持 0.40、仍为告警档；相似度 0 时分数一字不动；加分封顶在生效阈值上（全局门槛 0.50、逐识别器门槛…
- **策略表与处置动作框架：实体类别 → replace / redact / keep**
  落地实体级处置策略表与 operator 框架。证据：github_ref/presidio/presidio-analyzer/presidio_analyzer/analyzer_engine_provider.py 的 YAML 装配形态（保留形态），与 github_ref/presidio/presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py::Anonym…
  - 证据：`pytest tests/test_policy_table.py -q` → 26 passed（日志 logs/task6-policy.log）；全量回归 `pytest tests -q` → 101 passed；新增 src/research_redact/policy/operators.py（replace / redact / keep 三种确定性动作 + OperatorR…
- **冲突区间合并与裁剪：同一段只替换一次**
  落地冲突区间处理，保证同一段文本只被替换一次。证据：github_ref/presidio/presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py::_remove_conflicts_and_get_text_manipulation_data（:133-222）与 _merge_entities_with_spaces_between（:224-238）
  - 证据：`pytest tests/test_conflict_merge.py -q` 通过（17 passed，日志 logs/task7-conflict-merge.log）；新增 src/research_redact/policy/conflicts.py（同类区间合并 + 按优先级冲突裁决：身份类 > 就诊编号类 > 通用数字类，同档按分数）与 policy/research.yaml 的…
- **结构化材料列级批处理：申请单 JSON / xlsx 按列策略处理**
  支持按申请单成批处理结构化材料与表格。证据：github_ref/presidio/presidio-analyzer/presidio_analyzer/batch_analyzer_engine.py::BatchAnalyzerEngine.analyze_dict 的 keys_to_skip 列跳过机制（保留）。本任务同时落地入站申请单格式校验：缺伦理批件号即阻断该批次
  - 证据：`pytest tests/test_column_policy.py -q` → 21 passed（日志 logs/task8-column-policy.log）；全量回归 `pytest tests -q` → 140 passed（触达共享底座 policy/table.py：新增可选 columns 段，装配方校验 4 类非法配置）。JSON 与 xlsx 两种申请单解析结果逐字段一…
- **残留自检：对脱敏输出二次扫描身份类残留**
  落地本轮差异化关键环：对脱敏输出再跑一遍身份类识别器做残留自检（源产品无此能力，本轮新建）。残留只统计身份类，通用数字类不计入。分级规则（身份类严格 / 通用数字类提示）、误报抑制与批次级聚合在 task 28 深化；与基础方案的基线对比拆到 task 30（深度落点 b）
  - 证据：`pytest tests/test_residual.py` → 18 passed；全量回归 `pytest tests` → 158 passed（日志 logs/task9-residual.log）。干净脱敏副本（fixtures/report_001.txt 经 daemon/pipeline.py 主路径脱敏）残留计数 0、deliverable=True、零告警；漏脱样例「姓名：…
- **批次状态机：10 态迁移守卫与 SQLite 台账**
  落地 spec.md「批次状态机」的批次状态机与台账：detected → recognized → pseudonymized → delivered → restore_pending → restored | restore_rejected，旁路态 blocked / suspended / pending_delivery。幂等键与重投防护拆到 task 33、断点续跑与崩溃恢复拆到 task 34、并发与重放防护拆到 ta…
  - 证据：`pytest tests/test_batch_state.py -q` → 33 passed（日志 logs/task10-state-machine.log）；全量回归 `pytest tests -q` → 191 passed（日志 logs/task10-full-regression.log）；新增 src/research_redact/daemon/state_machine…
- **守护进程主循环：目录监听 + 定时兜底扫描 + 待投递队列 + 指数退避重试**
  落地编排层锁定的事件驱动守护形态：常驻进程监听科研交付目录，事件到达即处理并推送到既有通道。队列与退避补上「事件驱动」的主循环骨架；500 例规模的耗时基准与条目数守恒由 task 31 落地，本任务只保证守护进程能常驻、能自动处理一批投递、能按退避重试
  - 证据：`pytest tests/test_daemon_watch.py` → 10 passed（日志 logs/task11-daemon-test.log）；全量回归 `pytest tests` → 201 passed（日志 logs/task11-full-regression.log）；常驻实测 `python -m research_redact.daemon`：投递目录投放申请单后…
- **出站对接层：HIS 患者主索引读、科研数据平台写、企业微信推送**
  落真实外发调用：出站读一（HIS 患者主索引）、出站写二（科研数据平台数据集 + 还原回执）、出站推一（企业微信机器人）。凭据全部从环境变量读；协议替身只出现在测试层，产品代码是真实客户端；缺端点配置时该通道置挂起并告警，不静默指向本地替身
  - 证据：`pytest tests/test_outbound_contract.py` → 15 passed（日志 logs/task12-outbound-contract.log）；全量回归 `pytest tests` → 216 passed（日志 logs/task12-full-regression.log）。契约逐字段核对 spec.md：主索引 GET {HIS_BASE_URL}/…
- **受控还原：双人授权 + 时效 + 还原回执 + 拒绝分支**
  落地 spec.md「批次状态机」的还原分支：delivered → restore_pending（授权人 A 在位）→ restored（授权人 B 签字，未过期）。证据：github_ref/presidio/presidio-anonymizer/presidio_anonymizer/deanonymize_engine.py::DeanonymizeEngine.deanonymize（:813-830）与 add_dea…
  - 证据：`pytest tests/test_restore_auth.py tests/test_restore_roundtrip.py -q` 通过（20 passed：授权闸门 13 + 往返 7；日志 logs/task13-restore.log）；全量回归 `pytest tests -q` → 236 passed（日志 logs/task13-full-regression.log）；…
- **患者身份锚定：主索引读回绑定、名单识别器、同名异人与一人多号消歧**
  把 spec.md「核心机制规格 4.1」的身份锚定做成独立能力。患者身份以 HIS 患者主索引主键为准；名单识别器只认主索引读回的主键与归一化姓名组合，单独姓名命中一律降为告警档。源产品不具备此能力（只认通用 PII 模式，不绑定权威患者实体），本轮新建。同名不同人靠主索引主键区分，一人多个住院号靠主索引归一；主索引不可达时批次 suspended，不降级为按姓名硬匹配
  - 证据：`pytest tests/test_entity_binding.py` → 17 passed（日志 logs/task17-entity-binding-test.log）；全量回归 `pytest tests` → 253 passed（此前 236 + 新增 17；日志 logs/task17-full-regression.log）。新增 src/research_redact/re…
- **GB 11643 身份证校验位识别器与正反例语料**
  落地身份证的校验位形态识别器（源产品 base.py 里的三种形态之一：正则 / 校验位 / 名单）。18 位身份证正则 + GB 11643 加权校验位；校验位不通过降为告警档而不是判定为身份，避免把 18 位数字误脱
  - 证据：`pytest tests/test_id_card.py` → 24 passed（日志 logs/task18-id-card.log）；全量回归 `pytest tests` → 277 passed（此前 253 + 新增 24）。新增 src/research_redact/recognizers/id_card.py（GB 11643 七段加权校验位 + 出生日期合法性校验 + 15…
- **数字类识别器边界治理：剂量 / 金额 / 页码 / 床号不被误判为身份**
  住院号、检查号、手机号与病历正文里的剂量、金额、页码、床号在字面上高度相似，是「脱过头」的主要来源。本任务用编号形态约束 + 邻近词 + 长度分段做消歧，明确哪些数字不得被当成身份
  - 证据：`pytest tests/test_numeric_boundary.py` → 31 passed（日志 logs/task19-numeric-boundary.log）；全量回归 `pytest tests` → 308 passed（触达共享底座 policy/research.yaml 与 recognizers/numeric_boundary.py）。消歧规则前移到识别之前（源产…
- **邻近窗口打分算法深化：n-gram 相似度定义、窗口半径与加分上限**
  源产品靠 spaCy lemma 做上下文加分（analyzer_engine.py::_enhance_using_context :299-358 与 LemmaContextAwareEnhancer），在 ai_role=none、不引语言模型的前提下不成立，本轮改写为字符 n-gram 邻近窗口打分。本任务把算法做实：相似度定义、窗口半径、加分权重与上限、可读解释
  - 证据：`pytest tests/test_context_boost.py` → 40 passed（此前 23 + 新增 17；日志 logs/task20-context-boost.log）；全量回归 `pytest tests` → 325 passed（此前 308 + 新增 17；日志 logs/task20-full-regression.log）。改写 src/research_re…
- **白名单机制与误伤回归语料库（病名 / 药名 / 科室名 / 检验项目名）**
  白名单是「脱过头」的主防线：检验项目名、科室名、药名、病名都不得被替换。本任务落地白名单的两种匹配形态（exact 与 regex）、放行记录的标注方式，并建可持续维护的误伤回归语料
  - 证据：`pytest tests/test_allowlist.py -v` 通过（13 passed，日志 logs/task21-allowlist.log）；全量回归 `pytest tests -v` → 338 passed（此前 325 + 新增 13，日志 logs/task21-full-regression.log）。policy/research.yaml 的 allow_list…
- **识别器注册表配置化装配、启停与逐项阈值覆盖**
  保留源产品 analyzer_engine_provider.py 的 YAML 装配形态：单份 YAML 装配识别器清单、逐识别器阈值、全局阈值、白名单与上下文词表，装配非法即报错。识别器启停与逐项阈值覆盖让科室能按院区关掉误伤多的识别器
  - 证据：`pytest tests/test_assembly.py -q` 通过（30 passed，日志 logs/task22-assembly.log）；全量回归 `pytest tests -q` → 368 passed（此前 338 + 新增 30，日志 logs/task22-full-regression.log）。源产品能力与代码证据：presidio-analyzer/presid…
- **实体区间去重与包含关系统一裁决（跨识别器重叠 / 包含 / 交叉）**
  源产品有 remove_duplicates 与 _remove_conflicts_and_get_text_manipulation_data 两处去重与冲突处理。本项目把裁决规则集中在一处：跨识别器的重叠、包含、交叉三类关系按统一优先级裁决，被裁剪方记入命中清单（不记原文）
  - 证据：`pytest tests/test_dedup_rules.py -v` 通过（22 passed，日志 logs/task23-dedup.log）；全量回归 `pytest tests -q` → 390 passed（此前 368 + 新增 22，日志 logs/task23-full-regression.log）。新增 src/research_redact/arbitration.…
- **一致代号 operator：HMAC-SHA256 over 患者主索引主键**
  一致代号是源产品不具备的能力（内置 hash / encrypt operator 不保证跨文档一致），本轮新建并作为商业楔子：同一患者跨材料代号恒等、不同主键不串号。证据对照 anonymizer_engine.py 的 operator 扩展点 add_anonymizer（:115-122）
  - 证据：`pytest tests/test_pseudonym.py` → 18 passed（日志 logs/task24-pseudonym.log）；全量回归 `pytest tests` → 408 passed（此前 390 + 新增 18；日志 logs/task24-full-regression.log）；端到端实跑日志 logs/task24-pseudonym-run.log。新增…
- **还原 operator 与脱敏↔还原往返一致性**
  源产品 deanonymize_engine.py::DeanonymizeEngine.deanonymize（:813-830）用 operator 留下的密文反解原文。本轮把可逆从附赠能力升为产品主线：还原 operator 与脱敏 operator 成对注册，脱敏↔还原往返逐字节一致
  - 证据：`pytest tests/test_restore_roundtrip.py` → 16 passed（此前 7 + 新增 9；日志 logs/task25-roundtrip.log）；全量回归 `pytest tests` → 417 passed（此前 408；日志 logs/task25-full-regression.log）。新增 src/research_redact/polic…
- **对照索引加密存储与访问留痕（与交付物分离、密钥分离）**
  受控还原必须有访问留痕与密钥分离（plan.md 风险表）。对照索引（代号 ↔ 身份）加密存储、与交付物分离存放，解密与查询均留痕；索引丢失时批次 suspended，不重建空索引放行
  - 证据：`pytest tests/test_index_store.py -q` → 23 passed（日志 logs/task26-index-store.log）：新增 src/research_redact/policy/index_store.py —— AES-256-GCM 加密对照索引（密钥经 HKDF-SHA256 派生，文件头 RDRIDX01 + 12 字节 nonce，原子写…
- **DICOM tag 级去标识：身份 tag 与私有 tag 清空并记入清单**
  影像材料的身份主要在 DICOM tag。首版明确只做 tag 级去标识（一律清空身份 tag 与全部私有 tag 并记入命中清单），像素烧录与 OCR 定位不在首版 —— 源产品 presidio-image-redactor 的 OCR + bbox 像素填充路径本轮不做（见 spec.md「开源对照」 对照表）
  - 证据：`pytest tests/test_dicom_redact.py -q` → 22 passed（日志 logs/task27-dicom.log）；全量回归 `pytest tests -q` → 462 passed（日志 logs/task27-full-regression.log）；新增 src/research_redact/materials/dicom_redact.py（最…
- **残留自检分级、误报抑制与批次级聚合**
  task 9 已落地残留自检基础版，本任务做实三件事：分级（身份类严格 / 通用数字类提示）、误报抑制规则（白名单区间与非身份上下文不计入阻断）、按批次聚合不逐处推送
  - 证据：`pytest tests/test_residual.py` → 31 passed（此前 18 + 新增 13；日志 logs/task28-residual.log）；全量回归 `pytest tests` → 475 passed（此前 462 + 新增 13；日志 logs/task28-full-regression.log）。分级：新增 policy/residual_policy…
- **语料获取：确定性合成中文放射语料生成器 + 公开去标识化数据集可选下载**
  真实院内数据不可得，本轮落两条脚本化取数路径：确定性合成中文放射 / 检验报告语料（默认路径，断网可用）+ 可选下载公开去标识化语料（联网时启用，断网降级到合成集）。fixtures/ 只作单测边界样例，不得当作语料来源
  - 证据：`pytest tests/test_corpus_scripts.py -v` → 13 passed（日志 logs/task29-corpus.log）；全量回归 `pytest tests` → 488 passed（此前 475 + 新增 13，日志 logs/task29-full-regression.log）。新增 scripts/gen_corpus.py（确定性合成生成器：固…
- **基线对比实验：代号一致性 / 身份残留率 / 串号率（对照朴素替换与无一致性 hash）**
  plan.md §4 深度落点 (b)：与「朴素查找替换 + 无一致性 hash 替换」在三项指标上跑可复现对比，产出 reports/baseline-comparison.md。指标定义与数字必须可复算，串号率必须来自真实语料而非写死常量
  - 证据：`pytest tests/test_baseline_metrics.py -q` → 15 passed（日志 logs/task30-baseline.log）；全量回归 `pytest tests -q` → 503 passed（此前 488 + 新增 15；日志 logs/task30-full-regression.log）。新增 scripts/compare_baseline.…
- **规模与性能验收：500 例材料识别 + 残留自检的可测基准**
  plan.md §4 深度落点 (c)：真实规模输入的可度量验收。500 例材料走完整识别 + 代号 + 残留自检路径，记录耗时分位、峰值内存与产出条目数，并验证条目数守恒（无截断）
  - 证据：`python3.11 -m pytest tests/test_scale_pipeline.py` → 9 passed（日志 logs/task31-scale.log）；全量回归 `python3.11 -m pytest tests` → 512 passed（此前 503 + 新增 9）。新增 scripts/bench_scale.py（500 例语料跑完整识别 + 一致代号 +…
- **命中清单导出与分组视图（按批次 / 按材料 / 按实体类别）**
  命中清单是交差产物。task 3 已落基础 JSONL，本任务做实三种视图导出与表格化摘要，并严格守住「不记命中原文」这条安全审计红线
  - 证据：`python3.11 -m pytest tests/test_manifest_export.py` → 29 passed（日志 logs/task32-manifest-export.log）；全量回归 `python3.11 -m pytest tests` → 541 passed（此前 512 + 新增 29；日志 logs/task32-full-regression.log）。…
- **幂等键设计与重投防护（重复投递不产生第二次真实外发）**
  幂等键 = 申请单号 + 材料集合指纹。重复投递同一批不得产生第二次交付（真实外发调用不重复）；材料集合发生变化时指纹随之变化，不得误判为重复批次
  - 证据：`pytest tests/test_idempotency.py` → 13 passed（日志 logs/task33-idempotency.log）；全量回归 `pytest tests` → 554 passed（此前 541 + 新增 13；日志 logs/task33-full-regression.log）。新增 src/research_redact/idempotency.p…
- **断点续跑与崩溃恢复（重启后从最后一步接续，不重跑已完成识别）**
  守护进程重启后从台账中未完成批次的最后一步接续，不重跑已完成的识别步骤；投递成功但回执未落库时，以外发幂等键判定，不重复创建数据集
  - 证据：`pytest tests/test_resume.py -q` → 8 passed（日志 logs/task34-resume.log）；全量回归 `pytest tests` → 562 passed（此前 554 + 新增 8；日志 logs/task34-full-regression.log）。新增 src/research_redact/daemon/resume.py（步骤台账…
- **并发与重放防护（同批次互斥、材料去重、清单追加去重）**
  同一批次被守护进程与运维 CLI 同时触发，或同一材料在材料集合中重复出现，都要有确定行为：要么互斥处理，要么复用已有结果，不得重复外发、不得重复替换
  - 证据：`pytest tests/test_concurrency.py -v` → 7 passed（日志 logs/task35-concurrency.log）；全量回归 `pytest tests` → 569 passed（此前 562 + 新增 7；日志 logs/task35-full-regression.log）。新增 src/research_redact/daemon/locks…
- **策略表版本快照与批次可复现**
  同一批次在策略表被修改后仍须可复现：每批留策略表版本号、阈值与白名单摘要快照，支持用快照重放并与原批次逐条比对
  - 证据：`pytest tests/test_policy_snapshot.py -q` → 13 passed（日志 logs/task36-snapshot.log）；全量回归 `pytest tests` → 582 passed（此前 569 + 新增 13；日志 logs/task36-full-regression.log）。新增 src/research_redact/policy/sn…
- **出站重试、错误分类与通道挂起告警**
  出站调用的超时、5xx 退避、错误码分类与通道挂起告警必须落在真实客户端代码里，不能靠上层重试掩盖；未配置端点的通道置挂起并告警，绝不静默改指本地替身
  - 证据：`pytest tests/test_outbound_retry.py` → 15 passed（日志 logs/task37-outbound-retry.log）；全量回归 `pytest tests` → 597 passed（此前 582 + 新增 15；日志 logs/task37-full-regression.log）。新增 src/research_redact/outboun…
- **出站字段规范校验层（校验不过不外发）**
  出站请求体与响应体按 spec.md「最小数据格式与字段要求」的字段规范逐字段校验（pydantic），校验不通过就不发起外发调用，避免把半成品交付到科研数据平台
  - 证据：`python3.11 -m pytest tests/test_outbound_schema.py` → 21 passed（日志 logs/task38-outbound-schema.log）；全量回归 `python3.11 -m pytest tests` → 618 passed（此前 597 + 新增 21；日志 logs/task38-full-regression.log）。…
- **运维 CLI 完整子命令面（scan / run / deliver / restore-request / export-audit / verify-residual / status）**
  运维通道与守护进程共用同一条主路径与同一张台账，不另写一份处理逻辑。7 个子命令各自返回可核对输出，失败返回非 0 并给明确原因
  - 证据：`pytest tests/test_cli.py -q` → 35 passed（日志 logs/task39-cli.log）；全量回归 `pytest tests -q` → 653 passed（此前 618 + 新增 35；日志 logs/task39-full-regression.log）。新增 src/research_redact/daemon/ops.py（守护进程与 CLI…
- **结构化运行日志、心跳与批次时间线**
  守护进程的可观测性：结构化日志字段、固定间隔心跳、批次时间线（从 detected 到 delivered 每一步的时间戳与原因），供信息科排查积压与失败批次
  - 证据：`pytest tests/test_structured_log.py -q` → 14 passed（日志 logs/task40-logging.log）；全量回归 `pytest tests -q` → 667 passed（此前 653 + 新增 14；日志 logs/task40-full-regression.log）。新增 src/research_redact/logging_…
- **采集真实运行截图到 docs/screenshots/**
  倒数第三个任务。采集真实运行证据：守护进程日志、CLI 批处理终端输出、导出的命中清单与交付回执片段，落到 research-data-redact/docs/screenshots/。禁止用概念图或设计稿冒充实测截图
  - 证据：docs/screenshots/ 下 4 张真实运行截图全部落盘：daemon-run.png / cli-redact.png / manifest-and-receipt.png / timeline-and-baseline.png（PNG，尺寸 1236x574 / 1236x574 / 1236x469 / 1236x1225，字节 161498 / 120148 / 97906 /…
- **README 补全：按丰度下限填实骨架、清除全部占位符**
  倒数第二个任务。把 Task 1 骨架里所有「（Phase 4 后续 task 补齐）」填实，补配置表、命令 / 端点表、错误与降级表、验收与自检表、完整目录树注释；README 必须是面向医院用户的产品说明，不得出现上游开源项目名、Phase 1–3 研究过程或 task 排期表
  - 证据：`pytest tests` → 667 passed in 25.35s（日志 logs/task15-full-regression.log，rc=0）；README.md 实测基数：`grep -c '^## '` = 13（≥10）、`grep -c '^### '` = 27（≥8）、表格行 88（≥5）、代码块围栏 38（19 块，≥8）、正文字符 24429（≥5000）、ASCI…

### 收尾与发布

- **发布前清理：删除运行时数据与缓存，保留源码与必要产物**
  最后一个任务。清理项目子目录中的运行时数据、日志、缓存、构建产物与临时文件，使 research-data-redact/ 可直接发布到 GitHub；保留源码、README.md、README_EN.md、LICENSE、docs/concepts/、docs/screenshots/、fixtures/ 最小样例与策略表模板
  - 证据：清理实测：项目子目录文件数 830 → 132、总占用 2.6M；残留扫描全部归零 —— `find . -type d -name '__pycache__' | wc -l` = 0、`*.pyc/*.pyo` = 0、`*.log/*.tmp/*.temp` = 0、缓存与构建目录（.pytest_cache/.benchmarks/.mypy_cache/.ruff_cache/cove…

### 交付证据

| 项 | 值 |
|----|----|
| 版本 | 0.1.0 |
| 轮次 | R021 |
| 任务完成 | 40/40 |
| 交付状态 | 全部完成 |
| 综合评分 | 7.5 |
| 发布 | https://github.com/nexorin9/research-data-redact |
