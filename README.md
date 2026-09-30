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
- `POST /api/audit/seal`，提交`request_no`封存当前审计链（仅合规员），重复请求返回首次结果
- `GET /api/audit/verify?request_no=...`，核验凭据与链尾（主管或审计员），返回`lag`（落后条数）与首个断点
- `GET /api/audit/seals`

封存按请求编号幂等，并发只保留一份凭据且与链尾一致；封存、审计事件与凭据在同一事务内提交，失败回滚不留半条记录。核验会重算整条链的哈希：事件被改写返回`hash_mismatch`，链尾被删（库被恢复）返回`seal_tail_missing`，并指出首个断点。运行人员与现场设备只能读取自己产生的事件，主管、审计员与合规员可读取全部审计事件。

允许角色：operator, compliance_officer, director, viewer。按浓度与许可限值计算超标倍数，异常读数先进入评估；关闭前必须没有未完成整改项。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
