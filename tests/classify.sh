#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT/php2shell-check.sh"

failures=0

expect() {
  local version="$1"
  local changelog="$2"
  local want="$3"
  local got
  got=$(classify_php "$version" "$changelog")
  if [[ "$got" != "$want" ]]; then
    echo "falhou: classify_php $(printf '%q' "$version") changelog=${changelog} → ${got}, esperado ${want}" >&2
    failures=$((failures + 1))
  fi
}

expect "8.3.29" 0 vulneravel
expect "8.3.35-1+ubuntu22.04.1+deb.sury.org+1" 0 vulneravel
expect "8.3.36" 0 corrigido
expect "8.3.36RC1" 0 vulneravel
expect "8.2.34" 0 vulneravel
expect "8.2.35" 0 corrigido
expect "8.4.26" 0 vulneravel
expect "8.4.27" 0 corrigido
expect "8.5.11" 0 vulneravel
expect "8.5.12" 0 corrigido
expect "8.3.36-1+ubuntu24.04.1+deb.sury.org+1" 0 corrigido
expect "1:7.4.33-8+ubuntu22.04.1+deb.sury.org+1" 0 vulneravel
expect "1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1" 0 backport
expect "1:7.4.33-31" 0 vulneravel
expect "7.4.33-8" 1 backport
expect "1:8.1.34-9+ubuntu22.04.1+deb.sury.org+1" 0 backport
expect "8.1.34-8+ubuntu22.04.1+deb.sury.org+1" 0 vulneravel
expect "8.1.34" 0 vulneravel
expect "5.6.40-104+ubuntu22.04.1+deb.sury.org+1" 0 backport
expect "5.6.40-103+ubuntu22.04.1+deb.sury.org+1" 0 vulneravel
expect "5.3.29" 0 nao_afetado
expect "5.4.0" 0 vulneravel
expect "8.6.0" 0 desconhecido
expect "8.6.0" 1 backport
expect "nao-e-versao" 0 desconhecido

if [[ "$failures" -ne 0 ]]; then
  echo "${failures} teste(s) falharam" >&2
  exit 1
fi

echo "ok"
