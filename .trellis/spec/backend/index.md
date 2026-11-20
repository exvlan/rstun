# Backend Development Guidelines

> Best practices for backend development in this project.

---

## Overview

This directory contains guidelines for backend development. Fill in each file with your project's specific conventions.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Module organization and file layout | To fill |
| [Database Guidelines](./database-guidelines.md) | ORM patterns, queries, migrations | To fill |
| [Error Handling](./error-handling.md) | Error types, handling strategies | To fill |
| [Quality Guidelines](./quality-guidelines.md) | Code standards, forbidden patterns | To fill |
| [发布物契约](./release-artifacts.md) | Release 资产可执行位、tag↔资产↔digest、双架构 manifest、public 仓扫描 | Done |
| [抗滥用契约](./abuse-guard.md) | 放大上界 `max(len×ratio, len+32)`、省略 SOFTWARE 的域=防护域、默认关闭零变化、统计口径 | Done |
| [协议错误路径](./protocol-errors.md) | FINGERPRINT 的 Length/CRC 语义、300 优先级与放大面、500 映射、错误码矩阵 | Done |
| [鉴权契约](./auth.md) | 短期/长期 key 派生、USERHASH 32B、nonce 无状态、400 vs 401、响应签名与顺序 | Done |
| [运维面契约](./ops.md) | health/metrics 端点契约、整条连接总时限、并发上限、env 优先级、drain 语义 | Done |
| [质量门禁契约](./quality-gates.md) | 基准口径（p99 不可按 ±10% 复现）、混沌整数界 ≥3σ、缺计数硬失败、覆盖率排除、定时任务权限 | Done |
| [分发契约](./distribution.md) | 行为表单一真源、check-docs 守什么/不守什么、deb 走 musl、SBOM 全图、deny 与 audit 双门禁 | Done |
| [TURN 契约](./turn.md) | 5 元组/tid 幂等、441、Refresh 默认寿命、permission 容量 508、防回环（含通配与已知盲区）、有界 TCP 队列 | Done |
| [Logging Guidelines](./logging-guidelines.md) | Structured logging, log levels | To fill |

---

## How to Fill These Guidelines

For each guideline file:

1. Document your project's **actual conventions** (not ideals)
2. Include **code examples** from your codebase
3. List **forbidden patterns** and why
4. Add **common mistakes** your team has made

The goal is to help AI assistants and new team members understand how YOUR project works.

---

**Language**: All documentation should be written in **English**.
