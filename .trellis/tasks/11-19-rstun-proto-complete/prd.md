# 协议闭环（500 / FINGERPRINT / ALTERNATE-SERVER / RFC 8489）

## Goal

补齐 RFC 5389 服务端在**错误路径**与**完整性校验**上的缺口，使「拒绝」也有明确语义。

## 需求

1. **500 Server Error**：内部失败（编码失败、socket 发送失败、超时）时回 `500` 并带 `ERROR-CODE`，
   不再只写日志；UDP/TCP 行为一致。
2. **FINGERPRINT 校验**（§15.5）：
   - 存在时必须**最后一个属性**，且 CRC32(消息含头) XOR `0x5354554e` 匹配；
   - 不匹配 → 400（可配置为静默丢弃，默认 400）；
   - 通过 `--check-fingerprint` 开启（默认关闭以保持字节兼容）。
3. **ALTERNATE-SERVER**（§15.11）：提供 `--alternate-server <addr>` 配置；满足条件（如非首选地址收到请求）时回 300 + ALTERNATE-SERVER。
4. **RFC 8489 属性**：
   - 收到 `MESSAGE-INTEGRITY-SHA256`/`PASSWORD-ALGORITHMS`/`USERHASH` 时的行为明确化
     （未开鉴权：忽略；开鉴权：见 auth 子任务）；
   - 文档写明支持的 RFC 子集。
5. 错误码矩阵补全：400 / 420 / 438 / 500 各自触发条件写入 README。

## 验收

- [ ] 单元测试：500 / 400(FINGERPRINT 错) / 300(ALTERNATE-SERVER) 各自构造并断言
- [ ] FINGERPRINT 正确时不改变正常响应字节（默认关闭时零差异）
- [ ] 300/500 解码由 `stun-types` 覆盖（矩阵新增用例）；pion / webrtc-rs 的夹具不解析错误响应类型
  （能力边界，已在 `docs/interop-matrix.md` §11 登记）
- [ ] 错误码矩阵文档化

## 风险

| R | 缓解 |
| --- | --- |
| FINGERPRINT 默认开启会改变现有客户端行为 | 默认关闭，灰度用配置 |
| 500 泄露内部细节 | 固定文案，不把 io error 写进响应 |
