# MIME 邮件归档指纹 API

基于 FastAPI + SQLite 的 RFC 5322 邮件归档服务：严格递归解析 MIME 结构，
为每封邮件生成**稳定内容指纹**，并把可查询的 MIME 树持久化到 SQLite。

## 特性

- **严格递归解析**：multipart 边界、传输编码（7bit/8bit/binary/base64/quoted-printable）、
  字符集解码，全部递归处理；解析器自研，不做静默修复。
- **稳定指纹**：同一封邮件仅换行（CRLF/LF）、头字段大小写、头字段顺序、
  boundary 取值、传输编码不同时，得到相同指纹（详见下文算法）。
- **结构化错误**：损坏边界、重复参数、无法解码的字符集等问题返回 HTTP 422，
  错误体中带有定位到节点的点分路径（如 `"path": "0.1"`）。
- **原子写入**：先完整解析并计算指纹，再在单个事务中写入消息行 + 全部节点；
  解析失败或写入失败都不会留下半成品数据。
- **幂等去重**：指纹唯一约束，重复投递返回已存在的记录（HTTP 200，`created: false`）。
- 启动时自动初始化数据库，监听 8000 端口。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
```

服务监听 <http://localhost:8000>，SQLite 数据库持久化在命名卷 `archive-data` 中。

### 本地开发

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --port 8000        # 启动时自动建库（默认 ./archive.db）
pytest                                  # 运行测试
```

环境变量 `ARCHIVE_DB_PATH` 指定数据库文件路径（容器内默认 `/data/archive.db`）。

交互式 API 文档：<http://localhost:8000/docs>

## API

### 归档邮件

```bash
curl -X POST http://localhost:8000/api/v1/messages \
     -H 'Content-Type: message/rfc822' \
     --data-binary @sample.eml
```

`201 Created`（新归档）或 `200 OK`（指纹已存在，幂等去重）：

```json
{
  "id": 1,
  "fingerprint": "sha256:aa17fca6…",
  "created": true,
  "node_count": 3,
  "size_bytes": 413
}
```

### 查询

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/api/v1/messages?limit=&offset=` | 分页列出消息 |
| `GET` | `/api/v1/messages/{fingerprint}` | 消息详情（含根节点头字段） |
| `GET` | `/api/v1/messages/{fingerprint}/tree` | 完整 MIME 树（嵌套 JSON） |
| `GET` | `/api/v1/nodes/{id}` | 节点详情（含解码后的 `leaf_text`） |

树节点示例：

```json
{
  "id": 3, "path": "0.1", "content_type": "application/octet-stream",
  "transfer_encoding": "base64", "filename": "report.bin",
  "is_multipart": false, "leaf_sha256": "…", "leaf_size": 8,
  "headers": [["Content-Type", "application/octet-stream; name=report.bin"]],
  "children": []
}
```

`path` 为零基点分路径：根为 `"0"`，根的第一个部件为 `"0.0"`，其内嵌套的
第二个部件为 `"0.0.1"`，依此类推。

### 错误响应

解析失败返回 `422`，`detail` 中包含错误码与节点路径；**不会写入任何数据**：

```json
{
  "detail": {
    "error": "boundary_not_found",
    "message": "boundary 'ghost' never appears in the body",
    "path": "0.1",
    "content_type": "multipart/mixed"
  }
}
```

错误码目录：

| `error` | 含义 |
| --- | --- |
| `boundary_not_found` | 声明的 boundary 在正文中从未出现 |
| `unterminated_multipart` | 缺少结束分隔符 `--boundary--` |
| `missing_boundary` / `invalid_boundary` | multipart 缺少 boundary 参数 / boundary 非法 |
| `duplicate_parameter` | Content-Type / Content-Disposition 中参数重复（大小写不敏感） |
| `duplicate_header` | Content-Type 等单例头字段出现多次 |
| `malformed_header` / `malformed_parameter` | 头行无冒号、参数缺少 `=`、引号未闭合等 |
| `invalid_content_type` | Content-Type 主值不是 `type/subtype` |
| `unknown_transfer_encoding` | 不支持的 Content-Transfer-Encoding |
| `invalid_transfer_encoding` | multipart 实体使用了 base64/QP 编码 |
| `invalid_base64` / `invalid_quoted_printable` | 传输解码失败（含定位偏移） |
| `unknown_charset` / `decode_failed` | 未知字符集 / 按声明字符集解码失败 |
| `nesting_too_deep` / `too_many_nodes` | 超过 50 层嵌套 / 10000 个节点 |
| `empty_message` / `message_too_large` | 空请求体 / 超过 25 MiB |

## 指纹算法

消息指纹 = 根节点指纹 = 对 MIME 树**规范化序列化**的 SHA-256（十六进制，带
`sha256:` 前缀）。节点指纹递归定义：

1. **头字段**：字段名小写化；值先展开折叠行、压缩连续空白；
   `Content-Type` / `Content-Disposition` 进一步规范化（主值与参数名小写、
   参数按名排序、`charset` 值小写、`boundary` 参数值置空——它是序列化产物）；
   `Content-Transfer-Encoding` 头**整体排除**（叶子内容按解码后形式哈希，
   线上编码方式不影响内容）。所有头按 `(名称, 值)` 排序后参与哈希，
   因此头字段顺序不影响指纹。
2. **multipart 节点**：按序拼接各子节点的指纹（preamble/epilogue 忽略）。
3. **叶子节点**：先按传输编码解码；`text/*` 再按声明字符集（缺省
   `us-ascii`）解码为 Unicode。哈希解码后的文本（UTF-8）或字节。
4. 解析前全文换行统一为 `\n`，故 CRLF 与 LF 序列化得到同一指纹。

由此保证：同一封邮件仅**换行方式、头字段大小写、头字段顺序、boundary
取值、传输编码**不同 → 指纹相同；正文或头字段内容有任何实质变化 → 指纹不同。

## 设计决策与限制

- **严格而非宽容**：Python 标准库 `email` 会静默修复结构问题，无法满足
  “损坏即报错并定位”的要求，因此解析器为自研实现。
- 分隔符前紧邻的 CRLF 按 RFC 2046 属于分隔符，不计入部件正文。
- 非 `text/*` 叶子（如 `application/octet-stream`）不做字符集解码，
  按解码后字节哈希与存储（仅存 SHA-256，不存原文）。
- 头字段值按 latin-1 解码保留原始字节；RFC 2047 编码词（`=?utf-8?Q?…?=`）
  与 RFC 2231 参数续段不做语义展开（按原样参与指纹）。
- 指纹不含 `Date`/`Received` 等头字段的特殊处理——所有头字段一视同仁地
  规范化后参与指纹；同一封邮件经不同 MTA 转发（新增 Received 头）会得到
  不同指纹，这属于“内容已变化”的预期行为。
- 单条消息上限 25 MiB、50 层嵌套、10000 个节点。

## 项目结构

```
app/
  main.py          FastAPI 应用、路由、启动时建库
  mime_parser.py   严格递归 MIME 解析器
  fingerprint.py   规范化与稳定指纹
  db.py            SQLite 持久化（单事务原子写入）
  errors.py        带节点路径的结构化错误
tests/test_api.py  34 个端到端测试
Dockerfile / docker-compose.yml / requirements*.txt
```
