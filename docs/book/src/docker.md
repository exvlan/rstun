# 容器（Docker）

镜像 `ghcr.io/exvlan/rstun`：`linux/amd64` + `linux/arm64` 双架构 manifest，**full 构建**
（`--features full`，含 `turns:` 与 DTLS），非 root（uid 10001），只读文件系统可跑。

```bash
# 发行版镜像（推荐）：版本号与 Release tag 的版本串一致
docker run -d --name rstun \
  -p 3478:3478/udp -p 3478:3478/tcp \
  ghcr.io/exvlan/rstun:26.410.106-dev.0 server --tcp

# 本地构建（context = 仓库根）
docker build -t rstun:dev .
docker run -d --name rstun -p 3478:3478/udp -p 3478:3478/tcp rstun:dev server --tcp
docker logs -f rstun        # 启动日志：listeners=N / UDP listener ready
docker stop rstun           # SIGTERM → 打印 received/answered/dropped 后退出
```

镜像细节：多阶段（`rust:1-slim` 构建 → `debian:stable-slim` 运行），`ENTRYPOINT ["rstun"]`，
`EXPOSE 3478/udp 3478/tcp 5349/tcp 5349/udp`，`STOPSIGNAL SIGTERM`。
镜像里的二进制经 LTO + strip 后约 **4.8 MB**（lean 同参数约 2.35 MB；未 strip 的本地
`cargo build --release --features full` 是 8.16 MB，别拿它对比镜像）。只要 lean 时用 Release 里的
`rstun-<platform>-<version>.zip`。

## 版本串注入

镜像内的 `--version` 由**构建期** `RSTUN_BUILD_VERSION` 决定（`src/main.rs` 的 `option_env!`）。
不传 `--build-arg` 时回落 crate 版本，所以本地 `docker build` 的行为不变：

```bash
docker build --build-arg RSTUN_BUILD_VERSION=26.410.100+abc123 -t rstun:dev .
docker run --rm rstun:dev --version     # rstun 26.410.100+abc123
```

代码里 `RSTUN_BUILD_VERSION` 优先，`EXVLAN_BUILD_VERSION` 只是**旧构建链路的兼容回落**
（历史原因保留，新构建不要再用）。

## 多架构

发布流水线用 `ubuntu-24.04` + `ubuntu-24.04-arm` 各自 native build 后
`docker manifest create` 合成 `linux/amd64` + `linux/arm64`；本地要单架构可以直接
`docker build --platform linux/arm64 .`。

对外报**manifest list digest**（不是单架构 digest），下游按 digest 校验才对得上。

## RFC 5780：必须 host 网络

`-p` 的源地址 NAT 会破坏 `change-ip` / `change-port` 的判据（见
[RFC 5780](nat-discovery.md)）：

```bash
docker run -d --name rstun --network host rstun:dev server \
  --listen 10.0.0.5:3478 --alt-listen 10.0.0.7:3478 --alt-port 3479
```

## 包可见性

`ghcr.io/exvlan/rstun` 新包默认 private：**有凭证可拉、匿名 401**。
「我这边能 pull」不等于公开可拉，验证一律用不带凭证的 `docker pull`。
