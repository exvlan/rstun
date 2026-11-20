# rstun 容器镜像：独立 STUN/TURN（RFC 5389 Binding + RFC 5780 + RFC 8656）服务器。
#
# 镜像是 **full** 构建（`--features full`）：TURN over `turns:`(TLS) 与 DTLS 是容器
# 部署的常见用途，不该要求用户自己重编镜像。镜像里的二进制经下面的 LTO + strip 后约
# **4.8 MB**（lean 同参数约 2.35 MB；未 strip 的本地 release 是 7.9 MB，不是镜像体积）。
# 只要 lean 时：`cargo build --release`（不带 feature），或直接用 Release 里的
# `rstun-<platform>-<version>.zip`。
#
# 构建（context = **仓库根**：本 crate 是独立项目，没有 path 依赖）：
#   docker build -t rstun:dev .
#
# 可选把构建版本串编进二进制（`--version` 与响应 `SOFTWARE` 属性都会带 `+<sha6>`）：
#   docker build --build-arg RSTUN_BUILD_VERSION=26.410.100+abc123 -t rstun:dev .
# 不传则回落 crate 版本（`Cargo.toml` 的 `version`），与本地 `cargo build` 一致。
#
# 运行（`server` 子命令 + flags，端口 3478）：
#   docker run -d --name rstun -p 3478:3478/udp rstun:dev
#   docker run -d --name rstun -p 3478:3478/udp -p 3478:3478/tcp rstun:dev server --tcp
#
# RFC 5780（双 IP）**必须**用 host 网络：`-p` 的源地址 NAT 会把 change-ip /
# change-port 的回包改写成宿主机地址:发布端口，客户端对源地址的判据就失效了。
#   docker run -d --name rstun --network host rstun:dev server \
#     --listen <ip1>:3478 --alt-listen <ip2>:3478 --alt-port 3479
#
# 说明：
# - 一个容器只跑一个 rstun 进程；多地址用 `--listen` / `--listen-v6` 重复指定，
#   RFC 5780 则用 `--listen` + `--alt-listen`（镜像本身不用改）。
# - 镜像里没有 ca-certificates / curl / python：本服务不发起任何出站连接。
#   二进制**自带**可选的只读运维端点（`--health-listen` → `/healthz` + `/metrics`），
#   但镜像里没有能在容器内发 HTTP 的工具，所以**不设 HEALTHCHECK**：容器健康检查写在
#   编排层（见 `contrib/docker/compose.yaml` 用 bash `/dev/tcp`），STUN 回程仍从外部跑
#   `script/ci/rstun-smoke.sh`（见 README「运维面」）。
# - 二进制名是 `rstun`，**不能**叫 `stun`：Debian `stun-client` 已占用 `/usr/bin/stun`。

# ---------- build ----------
FROM rust:1-slim AS builder
WORKDIR /src

# 先只拷清单、用空 main 拉全量依赖：改源码不会让这一层失效。
# `Cargo.lock` 一起拷进来，依赖版本与发布二进制保持一致。
# **feature 必须与下面那次真实构建一致**（`--features full`），否则依赖层白拉、
# 真实构建要重编 rustls/webrtc-dtls 那一支。
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && printf 'fn main() {}\n' > src/main.rs \
 && cargo build --release --features full

# 再拷真实源码并强制重编本 crate（依赖已在上一层编好）。
# profile 用环境变量覆盖（本 crate 不写 `[profile.release]`，
# 镜像构建希望打开 LTO / strip）。
#
# 构建版本串（可选）：`RSTUN_BUILD_VERSION` 是本项目唯一的名字
# （`src/main.rs` 的 `option_env!` 优先读它），CI 用
# `<version>+<sha6>` 注入，镜像内 `--version` 与发布二进制同串。
# 声明在依赖层之后：换版本号不会让上面那层（依赖编译）失效。
ARG RSTUN_BUILD_VERSION=

COPY src ./src
# 空值必须 `unset`：`option_env!` 只判断「变量在不在」，`RSTUN_BUILD_VERSION=`
# 会让 `--version` 变成空串。不传 build-arg 时保持纯 crate 版本。
RUN touch src/main.rs \
 && if [ -n "${RSTUN_BUILD_VERSION:-}" ]; then \
      echo "injecting build version: ${RSTUN_BUILD_VERSION}"; \
    else \
      unset RSTUN_BUILD_VERSION; \
    fi \
 && CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=true \
    cargo build --release --features full

# ---------- runtime ----------
FROM debian:stable-slim AS runtime

# 非 root 运行；本服务不需要写任何文件。
RUN groupadd --system --gid 10001 rstun \
 && useradd --system --uid 10001 --gid rstun --home-dir /nonexistent --shell /usr/sbin/nologin rstun

COPY --from=builder /src/target/release/rstun /usr/local/bin/rstun

USER rstun

# STUN/TURN 的默认端口；UDP 是主用，TCP 需要 `server --tcp`。
EXPOSE 3478/udp
EXPOSE 3478/tcp
# `turns:` / DTLS 常用端口（不自动发布，只是让 `docker inspect` 看到意图）：
#   --turn-tls-listen 0.0.0.0:5349   （TCP，证书挂载进容器）
#   --turn-dtls-listen 0.0.0.0:5349  （UDP，同一对证书）
EXPOSE 5349/tcp
EXPOSE 5349/udp

# docker stop / systemd 都发 SIGTERM：二进制自己处理，打印统计后退出。
STOPSIGNAL SIGTERM

ENTRYPOINT ["rstun"]
# 默认只开 UDP；需要 TCP 时追加 `--tcp`（子命令 `server` 必须在首位）。
CMD ["server", "--listen", "0.0.0.0:3478"]
