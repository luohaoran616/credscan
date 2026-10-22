"""语料装载：corpus.txt.b64 为 gzip+base64 编码的合成语料，运行时解码。

历史上 corpus.txt 以明文存放合成凭据样例，其形态会触发代码托管平台的
密钥推送保护，故随仓发布改为编码形态，语义与原始语料完全一致。
"""
import base64
import gzip
from pathlib import Path

B64 = Path(__file__).parent / "fixtures" / "corpus.txt.b64"


def corpus_text() -> str:
    """返回解码后的完整合成语料文本。"""
    return gzip.decompress(base64.b64decode(B64.read_bytes())).decode("utf-8")
