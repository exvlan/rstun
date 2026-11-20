#!/bin/sh
# .deb preremove：只做 daemon-reload，不删用户。
#
# 不删 `rstun` 用户/组是有意的：purge 之后重新安装时 /etc/rstun 里的文件（若有）仍属它，
# 直接删组会让下次安装留下无主文件。要彻底清理由管理员显式执行
# `deluser --system rstun && delgroup rstun`。
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
