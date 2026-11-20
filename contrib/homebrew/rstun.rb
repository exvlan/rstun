# Homebrew formula 模板 —— `script/ci/gen-brew.sh` 在**发布时**把三个占位符换成真值
# （版本串 + 三个平台 zip 的 sha256），产出 `dist/homebrew/rstun.rb`。
#
# 为什么不能在仓库里填死 sha256：zip 只有 Release 跑完才存在。
# 为什么不能本地 `brew install --build-from-source`：本 formula 装的是**预编译二进制**
# （zip 里就一个 `rstun`），没有源码可编；`--build-from-source` 对它没有意义。
# 本地能验的只有语法（`ruby -c`），安装验证是发布时的人工步骤（见 implement.md）。
#
# 只发 **lean** 构建：`turns:`(TLS)/DTLS 在 Release 的 `rstun-full-*` 与
# `ghcr.io/exvlan/rstun` 镜像里，不在包管理器里（避免同版本两个包）。
class Rstun < Formula
  desc "Standalone STUN/TURN server (RFC 5389, optional RFC 5780 and RFC 8656)"
  homepage "https://github.com/exvlan/rstun"
  version "__RSTUN_VERSION__"
  license "MPL-2.0"

  if OS.mac?
    # Release 只出 macOS x86_64（无 arm64 产物）：Apple Silicon 上走 Rosetta 2。
    url "https://github.com/exvlan/rstun/releases/download/rstun-v__RSTUN_VERSION__/rstun-macos-x86_64-__RSTUN_VERSION__.zip"
    sha256 "__SHA256_MACOS_X86_64__"
  elsif Hardware::CPU.arm?
    url "https://github.com/exvlan/rstun/releases/download/rstun-v__RSTUN_VERSION__/rstun-linux-aarch64-__RSTUN_VERSION__.zip"
    sha256 "__SHA256_LINUX_AARCH64__"
  else
    url "https://github.com/exvlan/rstun/releases/download/rstun-v__RSTUN_VERSION__/rstun-linux-x86_64-__RSTUN_VERSION__.zip"
    sha256 "__SHA256_LINUX_X86_64__"
  end

  def install
    bin.install "rstun"
  end

  def caveats
    <<~EOS
      这是 lean 构建：STUN + TURN(UDP/TCP) + TURN REST 临时凭据 + 带宽配额。
      要 turns:(TLS) 与 DTLS，用 Release 的 rstun-full-<platform>-<version>.zip，
      或容器镜像 ghcr.io/exvlan/rstun（full 构建）。
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rstun --version")
    assert_match "--turn-bandwidth", shell_output("#{bin}/rstun server --help")
  end
end
