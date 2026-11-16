# filetypes — magic-byte 文件类型识别与上传安全判定

纯 Python 标准库实现（无第三方依赖）。不看扩展名，从文件头 magic bytes
识别真实类型，并做多格式（polyglot）检测、图片内部校验和 ZIP 条目穿越
检查，最后按白名单给出 allow / reject 判定。

## 运行

    python demo/make_files.py                                   # 重新生成 10 个基线样本
    python -m filetypes.cli --dir demo/files --out out/report.json
    python -m unittest discover -s tests -v                     # 或: cd tests && python -m unittest test_filetypes -v

CLI 会在 stdout 打印一行摘要（files=10 allowed=8 rejected=2），并把逐文件
报告写入 JSON。每条记录含 5 个字段：file、detected（真实类型，全部命中）、
declared（扩展名声明类型）、verdict（allow/reject）、evidence（判定依据）。

## Magic bytes 签名表（filetypes/signatures.py）

| 类型   | 签名（偏移 0，除注明外）                  |
|--------|-------------------------------------------|
| png    | 89 50 4E 47 0D 0A 1A 0A                   |
| jpeg   | FF D8 FF                                  |
| gif    | GIF87a 或 GIF89a                          |
| pdf    | %PDF-                                     |
| zip    | 50 4B 03 04 或 50 4B 05 06（另见下）      |
| gzip   | 1F 8B                                     |
| elf    | 7F 45 4C 46（\x7fELF）                    |
| pe     | 4D 5A（MZ）                               |
| class  | CA FE BA BE                               |
| wav    | 偏移 0 为 RIFF 且偏移 8 为 WAVE           |
| text   | 无签名命中且内容不含 NUL 字节（兜底）     |
| binary | 无签名命中且内容含 NUL 字节（兜底）       |

ZIP 特殊：解压器靠文件尾部的 EOCD 记录定位归档，因此追加在别的格式后面
的 ZIP 数据依然能被解压。除偏移 0 外，还会扫描整个缓冲区的
PK\x03\x04 / PK\x05\x06 标记，用于识别「PNG 头 + ZIP 尾」这类双头文件。

## 判定规则（filetypes/rules.py）

按顺序评估，任一拒绝条件命中即 reject：

1. 多格式（polyglot）：同一文件命中两种及以上签名时一律拒绝，
   evidence 列出全部命中类型，不允许按其中任一类型放行。
2. 扩展名不符：扩展名推导出的声明类型与 magic bytes 真实类型不一致
   时拒绝，evidence 同时给出声明类型与真实类型。
3. 白名单：真实类型不在 {png, jpeg, gif, pdf, zip, gzip, elf, text}
   之内时拒绝（binary、pe、class、wav 等一律拒绝）。
4. 图片内部校验（见下）失败判损坏，拒绝。
5. ZIP 条目穿越（见下）存在违规条目名，拒绝。

## 图片内部校验（filetypes/imagecheck.py）

- PNG：校验 8 字节签名，且第一个 chunk 必须是 IHDR；从 IHDR 数据段
  （偏移 16 起，大端）读出宽、高，宽或高为 0 判损坏。宽高值写入 evidence。
- JPEG：必须以 SOI（FF D8）开头、以 EOI（FF D9）结尾，二者成对；
  去掉结尾 EOI 的截断文件判损坏。
- GIF：必须有 GIF87a/GIF89a 头，且以 trailer 标记 0x3B 结尾。

## 文本与二进制判定（filetypes/sniffer.py）

没有任何签名命中时按内容兜底：内容含 NUL（0x00）字节即判 binary，
否则判 text。因此向文本中间塞入 NUL 字节的文件会判为 binary，
与 .txt 声明类型不一致且不在白名单内，被拒绝。

## 归档条目穿越检查（filetypes/archive.py）

用标准库 zipfile 列出 ZIP 条目名，命中以下任一情况即报穿越并拒绝：

- 路径中含 .. 段（如 ../evil.txt，含反斜杠变体 ..\）
- 绝对路径（/etc/passwd）
- Windows 盘符路径（C:\...）

## 目录结构

    filetypes/            签名表、嗅探、图片校验、polyglot、归档、规则、报告、CLI
    demo/make_files.py    重新生成 demo/files/ 下 10 个基线样本
    demo/files/           10 个基线样本（8 放行 2 拒绝）
    tests/fixtures.py     夹具构造器（demo 与测试共用，全部按格式规范现造）
    tests/test_filetypes.py  9 条判定口径的 unittest
