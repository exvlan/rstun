# 执行计划：运维面

> 前置：无（可与 TURN/其它子任务并行；指标项会随 TURN 落地补充标签）。
> 用户已定：T1（TURN）的实施方式为「子代理一次完成 + 冷复核」，与本任务无冲突。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | CLI/env：`--health-listen`、`--drain-timeout`、`RSTUN_*` 映射（CLI 优先） | 单测：env/flag 优先级、非法值失败 | 单 commit |
| 2 | 最小 HTTP/1.1：仅 `GET/HEAD`、路径白名单、1 请求 1 连接、超时 | 单测：GET/HEAD/405/404/带 body/超长 URI | 小 commit |
| 3 | listener supervisor：每个监听持 `AtomicBool`，任务退出置 false | 单测：模拟 listener 退出 → 状态翻转 | 小 commit |
| 4 | `/healthz`：全绿 200，任一 stale → 503（JSON 含 stale 列表） | e2e：正常/杀掉一个 listener | 小 commit |
| 5 | `/metrics`：与 `Counters` 共用；固定 HELP/TYPE；`build_info` | e2e：文本可被简单解析器解析；计数随请求增长 | 小 commit |
| 6 | 优雅 drain：SIGTERM → 停读/停 accept → 等在途（`--drain-timeout`，默认 5s）→ 退出 | e2e：在途请求完成；5s 内退出；统计完整 | 小 commit |
| 7 | 部署清单：systemd / compose / k8s / Helm | `kubeconform`/`helm lint`（若可用）；无则人工评审 | 新增文件 |
| 8 | README：运维节（health/metrics/env/drain/部署） | 人工评审 | 文档 commit |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all      # 42 项（不配 health 时零差异）
bash script/lab/rstun-abuse.sh            # 10 组
cargo tree -e normal --depth 1            # 不新增依赖
```

## 验收断言（必须）

- [ ] 不配 `--health-listen`：无新监听、`interop all` 42 项全绿、冻结测试通过
- [ ] `/healthz`：正常 200；任一 listener 退出 → 503 且列出 stale
- [ ] `/metrics`：`# TYPE` 与样本行可被 Prometheus 文本解析（用 regex 断言 3 条以上）
- [ ] `RSTUN_LISTEN` 生效且 CLI 覆盖它（同一场景两条用例）
- [ ] SIGTERM：在途请求完成、5s 内退出、退出统计与 `/metrics` 数值一致
- [ ] 部署清单至少一份能在本地起（compose 或 kind）
- [ ] HTTP 只读：`POST /metrics` → 405；带 body 的 GET → 400 并关闭

## 风险

| R | 缓解 |
| --- | --- |
| 自写 HTTP 有解析漏洞 | 只解析请求行 + 少量头；不读 body；1 请求 1 连接；超时 2s |
| 指标基数爆炸 | 标签固定枚举（transport/result/scope/direction）|
| drain 卡住 | 强制超时 + 第二次 SIGTERM 立即退出 |
| 清单与 CLI 漂移 | 清单里的参数在 README 有对照；CI 可选做 `rstun --help` 冒烟 |
