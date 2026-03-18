#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_BIN="$SCRIPT_DIR/bin/ecapture"

echo "==> Building eCapture for Android arm64 via Docker"
echo "    Project: $SCRIPT_DIR"

# 检查 Docker 是否可用
if ! command -v docker &>/dev/null; then
  echo "[ERROR] Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
  exit 1
fi

if ! docker info &>/dev/null; then
  echo "[ERROR] Docker daemon is not running. Please start Docker Desktop."
  exit 1
fi

docker run --rm \
  --platform linux/arm64 \
  -v "$SCRIPT_DIR":/build/ecapture \
  -w /build/ecapture \
  ubuntu:22.04 bash -c '
set -e

echo "==> [1/5] Installing build dependencies..."
sed -i "s|http://ports.ubuntu.com/ubuntu-ports|http://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports|g" /etc/apt/sources.list
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential pkgconf libelf-dev \
  llvm-14 clang-14 linux-tools-common \
  make gcc git file wget flex bison bc \
  linux-headers-generic ca-certificates > /dev/null 2>&1

ln -sf /usr/bin/clang-14      /usr/bin/clang
ln -sf /usr/bin/llc-14        /usr/bin/llc
ln -sf /usr/bin/llvm-strip-14 /usr/bin/llvm-strip

echo "==> [2/5] Installing Go 1.24..."
wget -q https://golang.google.cn/dl/go1.24.3.linux-arm64.tar.gz
tar -C /usr/local -xzf go1.24.3.linux-arm64.tar.gz
export PATH=/usr/local/go/bin:$PATH
go version

echo "==> [3/5] Finding kernel headers..."
KERN_HEADERS=$(ls -d /usr/src/linux-headers-*-generic 2>/dev/null | sort -V | tail -1)
if [ -z "$KERN_HEADERS" ]; then
  echo "[ERROR] linux-headers-generic not installed. /usr/src contains:"
  ls /usr/src/
  exit 1
fi
echo "    Using: $KERN_HEADERS"

echo "==> [4/5] Compiling eCapture (Android arm64, nocore)..."
cd /build/ecapture
make clean > /dev/null 2>&1 || true
ANDROID=1 KERN_HEADERS="$KERN_HEADERS" make nocore

echo "==> [5/5] Done."
file bin/ecapture
'

echo ""
echo "======================================"
echo " Build complete: $OUT_BIN"
echo "======================================"
echo ""
echo "Deploy to device:"
echo "  adb push bin/ecapture /data/local/tmp/"
echo "  adb shell chmod +x /data/local/tmp/ecapture"
echo "  adb shell su -c \"/data/local/tmp/ecapture tls --help\""
