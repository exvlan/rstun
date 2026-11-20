#!/bin/sh
# .deb postinst：建系统用户/组 + 配置目录。幂等（重复安装不会失败）。
set -e

if ! getent group rstun >/dev/null; then
  groupadd --system rstun
fi
if ! getent passwd rstun >/dev/null; then
  useradd --system --gid rstun --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --comment "rstun" rstun
fi

# 只放一份可选的环境文件（EnvironmentFile=-/etc/rstun/rstun.env）。
install -d -m 0750 -o root -g rstun /etc/rstun

# 容器里没有 systemd（`policy-rc.d` 拒绝启动服务）；daemon-reload 只在真 systemd 下做。
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
