#!/bin/bash
set -euo pipefail

BOOTSTRAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_STAMP="$BOOTSTRAP_DIR/.bootstrap.$(uname -s | tr '[:upper:]' '[:lower:]').stamp"

configure_pkg_config_path() {
  local openssl_prefix candidate

  case "$(uname -s)" in
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        openssl_prefix="$(brew --prefix openssl@3 2>/dev/null || true)"
        if [ -n "$openssl_prefix" ]; then
          candidate="$openssl_prefix/lib/pkgconfig"
          if [ -d "$candidate" ]; then
            if [ -n "${PKG_CONFIG_PATH:-}" ]; then
              case ":$PKG_CONFIG_PATH:" in
                *":$candidate:"*) ;;
                *) export PKG_CONFIG_PATH="$candidate:$PKG_CONFIG_PATH" ;;
              esac
            else
              export PKG_CONFIG_PATH="$candidate"
            fi
          fi
        fi
      fi
      ;;
  esac
}

compiler_available() {
  if [ -n "${CC:-}" ]; then
    command -v "$CC" >/dev/null 2>&1
    return
  fi

  command -v cc >/dev/null 2>&1 ||
    command -v gcc >/dev/null 2>&1 ||
    command -v clang >/dev/null 2>&1
}

select_compiler() {
  local candidate

  if [ -n "${CC:-}" ] && command -v "$CC" >/dev/null 2>&1; then
    BUILD_CC="$CC"
    export BUILD_CC
    return 0
  fi

  for candidate in cc gcc clang; do
    if command -v "$candidate" >/dev/null 2>&1; then
      BUILD_CC="$candidate"
      export BUILD_CC
      return 0
    fi
  done

  return 1
}

need_install() {
  configure_pkg_config_path
  ! compiler_available ||
    ! command -v pkg-config >/dev/null 2>&1 ||
    ! pkg-config --exists openssl
}

install_linux_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y gcc make pkgconf-pkg-config openssl-devel
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y gcc make pkgconfig openssl-devel
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm base-devel pkgconf openssl
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y gcc make pkg-config libopenssl-devel
  else
    echo "Unsupported Linux package manager. Install gcc, pkg-config, and OpenSSL headers manually." >&2
    exit 1
  fi
}

install_macos_deps() {
  if ! compiler_available; then
    echo "macOS compiler tools are required before ChatSocket can build." >&2
    echo "Run: xcode-select --install" >&2
    exit 1
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required on macOS to install build dependencies." >&2
    echo "Install Homebrew from https://brew.sh and rerun this script." >&2
    exit 1
  fi

  brew install pkg-config openssl@3
  configure_pkg_config_path
}

ensure_build_prereqs() {
  if ! need_install; then
    select_compiler
    return
  fi

  echo "Build dependencies are missing." >&2
  echo "Review and run: $BOOTSTRAP_DIR/bootstrap.sh --install" >&2
  return 1
}

install_build_prereqs() {
  echo "Checking build dependencies..."
  if ! need_install; then
    select_compiler
    touch "$BOOTSTRAP_STAMP"
    return
  fi

  case "$(uname -s)" in
    Darwin)
      install_macos_deps
      ;;
    Linux)
      install_linux_deps
      ;;
    *)
      echo "Unsupported OS for automatic dependency installation." >&2
      exit 1
      ;;
  esac

  if need_install; then
    echo "Dependencies are still missing after the install attempt." >&2
    exit 1
  fi

  select_compiler
  touch "$BOOTSTRAP_STAMP"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "${1:-}" != "--install" || "$#" -ne 1 ]]; then
    echo "Usage: ./bootstrap.sh --install" >&2
    exit 1
  fi
  install_build_prereqs
fi
