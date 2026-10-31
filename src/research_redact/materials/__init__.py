"""materials 子包：按材料形态走的处理路径。

- :mod:`research_redact.materials.dicom_redact` —— DICOM tag 级去标识
  （身份 tag 清空、私有 tag 一律清空、必要 tag 保留；**不做像素烧录**）。
"""

from .dicom_redact import (
    DicomConfig,
    DicomDataset,
    DicomElement,
    DicomError,
    DicomFinding,
    DicomItem,
    DicomParseError,
    DicomRedaction,
    DicomSelfCheck,
    DicomUnsupportedError,
    DicomVerificationError,
    default_dicom_config,
    iter_elements,
    parse_dicom,
    redact_dicom_bytes,
    redact_dicom_file,
    serialize_dicom,
    verify_dicom,
)

__all__ = [
    "DicomConfig",
    "DicomDataset",
    "DicomElement",
    "DicomError",
    "DicomFinding",
    "DicomItem",
    "DicomParseError",
    "DicomRedaction",
    "DicomSelfCheck",
    "DicomUnsupportedError",
    "DicomVerificationError",
    "default_dicom_config",
    "iter_elements",
    "parse_dicom",
    "redact_dicom_bytes",
    "redact_dicom_file",
    "serialize_dicom",
    "verify_dicom",
]
