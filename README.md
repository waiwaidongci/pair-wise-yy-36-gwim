# 企业排污许可与超标处置

汇总监测和工况，判断排放超标并跟踪复测、整改、执法与复查。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8313
```

默认端口为`8313`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `POST /api/audit/seals`：合规员按`request_id`封存当前审计链
- `POST /api/audit/verify`：主管或审计员按封存凭据做灾后核验

允许角色：operator（运行人员）、compliance_officer（合规员）、director（主管）、viewer（审计员）、device（现场设备）。按浓度与许可限值计算超标倍数，异常读数先进入评估；关闭前必须没有未完成整改项。

## 审计封存与灾后核验

合规员对当前审计链封存：`POST /api/audit/seals`，请求体`{"request_id": "REQ-..."}`。
同一`request_id`重复提交（含并发提交）始终返回首次凭据，只生成一份封存事件，凭据与当时链尾一致。
封存事件、凭据和请求编号在同一事务提交；任一步失败整体回滚，不留半条记录，故障排除后按同一请求编号重试即可。
凭据记录封存时间（`sealed_at`）、链尾事件编号（`tail_event_id`）和链尾哈希（`tail_hash`）。

封存不冻结审计链，封存后新事件照常追加。主管或审计员调用`POST /api/audit/verify`核验：

- 正常时返回`status:"consistent"`及`lag`，表示凭据落后当前链尾多少条事件（链尾之后追加的事件数）。
- 数据库被外部恢复（链被截断）或事件被改写（哈希链断裂、链尾哈希不符）时返回409，`status:"conflict"`并给出`first_breakpoint`首个断点（第几条、断点类型、期望与实际哈希）。
- 核验可只传`{"request_id": "..."}`读取库内凭据；凭据若由监管另行保存，也可直接提交`tail_event_id`、`tail_hash`、`sealed_at`正文。

`GET /api/audit`的读取范围：主管、审计员、合规员读全链；运行人员和现场设备只能读取`actor`等于自己`X-Actor`的事件。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
