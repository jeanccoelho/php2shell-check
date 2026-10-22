#!/usr/bin/env bash
# Verifica o PHP instalado contra as releases que corrigem o PHP2Shell
# (CVE-2026-109618 e CVE-2026-109619) e, com --apply, atualiza só os
# pacotes do runtime pelo apt.
#
# Não envia requisição de ataque, não altera memory_limit e não trata
# regra de WAF como correção. A correção é o pacote novo do PHP.
set -euo pipefail

OFFICIAL_MIN_82="8.2.35"
OFFICIAL_MIN_83="8.3.36"
OFFICIAL_MIN_84="8.4.27"
OFFICIAL_MIN_85="8.5.12"

# Revisões deb.sury.org / ppa:ondrej/php publicadas em 2026-10-21.
# O número do PHP não muda; a revisão depois do hífen muda.
SURY_UPSTREAMS="5.6.40 7.0.33 7.1.33 7.2.34 7.3.33 7.4.33 8.0.30 8.1.34"
SURY_REVS="104 92 80 66 35 31 25 9"

APPLY=0
USE_SURY=0
STRICT=0
SKIP_DOCKER=0

usage() {
  cat <<'EOF'
Uso: php2shell-check.sh [--apply] [--use-sury] [--strict] [--no-docker]

  (sem flags)   mostra cada runtime e se a correção está no pacote
  --apply       atualiza pelo apt os pacotes de PHP já instalados e
                reinicia php-fpm e o Apache, se estiverem ativos
  --use-sury    junto com --apply, adiciona ppa:ondrej/php se o
                espelho atual ainda não tiver o pacote corrigido
  --strict      termina com erro também quando só há backport de ramo antigo
  --no-docker   não consulta containers locais

Códigos: 0 sem runtime vulnerável, 1 ainda há PHP sem correção comprovada,
         2 erro de uso ou de pacote.

A release oficial corrigida é 8.2.35, 8.3.36, 8.4.27 ou 8.5.12.
Em 8.1 e anteriores o php.net não publicou release nova. O script só
marca "backport" quando o changelog cita o CVE ou quando o pacote é
do deb.sury.org com a revisão de 2026-10-21 ou mais nova.
EOF
}

official_min() {
  case "$1" in
    8.2) printf '%s\n' "$OFFICIAL_MIN_82" ;;
    8.3) printf '%s\n' "$OFFICIAL_MIN_83" ;;
    8.4) printf '%s\n' "$OFFICIAL_MIN_84" ;;
    8.5) printf '%s\n' "$OFFICIAL_MIN_85" ;;
    *) return 1 ;;
  esac
}

sury_min_rev() {
  local upstream="$1"
  local item rev
  local i=1
  for item in $SURY_UPSTREAMS; do
    rev=$(echo "$SURY_REVS" | cut -d' ' -f"$i")
    if [[ "$item" == "$upstream" ]]; then
      printf '%s\n' "$rev"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

is_prerelease() {
  [[ "$1" =~ (RC|rc|alpha|beta|ALPHA|BETA|dev) ]]
}

version_triplet() {
  if [[ "$1" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  fi
  return 1
}

version_cmp() {
  local a b
  a=$(version_triplet "$1") || return 2
  b=$(version_triplet "$2") || return 2
  local a1 a2 a3 b1 b2 b3
  IFS=. read -r a1 a2 a3 <<<"$a"
  IFS=. read -r b1 b2 b3 <<<"$b"
  if ((10#$a1 != 10#$b1)); then
    ((10#$a1 > 10#$b1)) && echo 1 || echo -1
    return 0
  fi
  if ((10#$a2 != 10#$b2)); then
    ((10#$a2 > 10#$b2)) && echo 1 || echo -1
    return 0
  fi
  if ((10#$a3 != 10#$b3)); then
    ((10#$a3 > 10#$b3)) && echo 1 || echo -1
    return 0
  fi
  local pa=0 pb=0
  is_prerelease "$1" && pa=1
  is_prerelease "$2" && pb=1
  if ((pa == pb)); then
    echo 0
  elif ((pa == 1)); then
    echo -1
  else
    echo 1
  fi
}

version_ge() {
  local cmp
  cmp=$(version_cmp "$1" "$2") || return 1
  [[ "$cmp" != "-1" ]]
}

parse_deb_version() {
  local raw="${1#*:}"
  PARSED_UPSTREAM=""
  PARSED_DEB_NUM=""
  if [[ "$raw" == *-* ]]; then
    PARSED_UPSTREAM="${raw%%-*}"
    local deb="${raw#*-}"
    if [[ "$deb" =~ ^([0-9]+) ]]; then
      PARSED_DEB_NUM="${BASH_REMATCH[1]}"
    fi
  else
    PARSED_UPSTREAM="$raw"
  fi
}

# classify_php <versao> <changelog_tem_cve 0|1>
# Imprime: corrigido, backport, vulneravel, desconhecido ou nao_afetado.
classify_php() {
  local version_string="$1"
  local changelog="${2:-0}"
  local triplet branch min need cmp

  triplet=$(version_triplet "$version_string") || {
    echo desconhecido
    return 0
  }
  branch="${triplet%.*}"

  local floor
  floor=$(version_cmp "$triplet" "5.4.0") || floor=2
  if [[ "$floor" == "-1" ]]; then
    echo nao_afetado
    return 0
  fi

  if min=$(official_min "$branch"); then
    if version_ge "$version_string" "$min"; then
      echo corrigido
    else
      echo vulneravel
    fi
    return 0
  fi

  if [[ "$changelog" == "1" ]]; then
    echo backport
    return 0
  fi

  parse_deb_version "$version_string"
  if [[ "$version_string" == *deb.sury.org* ]] && need=$(sury_min_rev "$PARSED_UPSTREAM"); then
    if [[ -n "$PARSED_DEB_NUM" ]] && ((10#$PARSED_DEB_NUM >= 10#$need)); then
      echo backport
      return 0
    fi
    echo vulneravel
    return 0
  fi

  cmp=$(version_cmp "$triplet" "8.6.0" || true)
  if [[ "$cmp" != "-1" && "$cmp" != "" ]]; then
    echo desconhecido
    return 0
  fi

  echo vulneravel
}

branch_of_package() {
  local name="$1"
  if [[ "$name" =~ php([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$name" =~ libapache2-mod-php([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  return 1
}

is_runtime_package() {
  local name="$1"
  [[ "$name" =~ ^php[0-9]+\.[0-9]+($|-) ]] && return 0
  [[ "$name" =~ ^libapache2-mod-php ]] && return 0
  case "$name" in
    php | php-cli | php-fpm | php-cgi | php-common | libapache2-mod-php) return 0 ;;
  esac
  return 1
}

changelog_has_cve() {
  local branch="$1"
  local doc="/usr/share/doc/php${branch}-common/changelog.Debian.gz"
  [[ -f "$doc" ]] || return 1
  zgrep -qE 'CVE-2026-109618|CVE-2026-109619' "$doc"
}

advice_for() {
  local status="$1"
  local version_string="$2"
  local triplet branch min
  triplet=$(version_triplet "$version_string" || true)
  branch="${triplet%.*}"
  case "$status" in
    corrigido)
      printf '%s\n' "release oficial com a correção"
      ;;
    backport)
      printf '%s\n' "backport do mantenedor; a correção completa do php.net é ${OFFICIAL_MIN_82}, ${OFFICIAL_MIN_83}, ${OFFICIAL_MIN_84} ou ${OFFICIAL_MIN_85}"
      ;;
    vulneravel)
      if min=$(official_min "$branch"); then
        printf '%s\n' "atualize para ${min} ou mais novo neste ramo"
      else
        printf '%s\n' "sem release no php.net; instale o pacote corrigido do mantenedor ou suba para ${OFFICIAL_MIN_82}+"
      fi
      ;;
    desconhecido)
      printf '%s\n' "o changelog não cita CVE-2026-109618; não trate esta versão como corrigida"
      ;;
    nao_afetado)
      printf '%s\n' "anterior a 5.4, fora do intervalo publicado"
      ;;
    *)
      printf '%s\n' "sem classificação"
      ;;
  esac
}

record_result() {
  local label="$1"
  local version_string="$2"
  local changelog="${3:-0}"
  local status advice
  status=$(classify_php "$version_string" "$changelog")
  advice=$(advice_for "$status" "$version_string")
  printf '[%s] %s %s — %s\n' "$status" "$label" "$version_string" "$advice"
  case "$status" in
    vulneravel | desconhecido) FOUND_PROBLEM=1 ;;
    backport) FOUND_BACKPORT=1 ;;
  esac
  FOUND_ANY=1
}

package_version() {
  dpkg-query -W -f '${Version}' "$1" 2>/dev/null || true
}

package_installed() {
  local status
  status=$(dpkg-query -W -f '${Status}' "$1" 2>/dev/null || true)
  [[ "$status" == "install ok installed" ]]
}

check_host_packages() {
  command -v dpkg-query >/dev/null 2>&1 || return 0
  local name branch seen="" best version changelog
  local installed
  installed=$(dpkg-query -W -f '${Package}\t${Status}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null || true)
  local branches=""
  while IFS=$'\t' read -r name status; do
    [[ "$status" == "install ok installed" ]] || continue
    is_runtime_package "$name" || continue
    branch=$(branch_of_package "$name" || true)
    [[ -n "$branch" ]] || continue
    case " $branches " in
      *" $branch "*) ;;
      *) branches="$branches $branch" ;;
    esac
  done <<<"$installed"

  for branch in $branches; do
    best=""
    for name in \
      "php${branch}-cli" \
      "php${branch}-fpm" \
      "php${branch}-cgi" \
      "php${branch}-common" \
      "libapache2-mod-php${branch}" \
      "php${branch}"; do
      if package_installed "$name"; then
        best="$name"
        break
      fi
    done
    [[ -n "$best" ]] || continue
    version=$(package_version "$best")
    changelog=0
    if changelog_has_cve "$branch"; then
      changelog=1
    fi
    record_result "$best" "$version" "$changelog"
    seen="$seen $branch"
  done

  if command -v php >/dev/null 2>&1; then
    local bin resolved owner
    bin=$(command -v php)
    resolved=$(readlink -f "$bin" || printf '%s\n' "$bin")
    owner=$(dpkg-query -S "$resolved" 2>/dev/null | head -n 1 | cut -d: -f1 || true)
    if [[ -z "$owner" ]]; then
      local plain
      plain=$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)
      if [[ -n "$plain" ]]; then
        record_result "php (sem pacote)" "$plain" 0
      fi
    fi
  fi
}

check_docker() {
  [[ "$SKIP_DOCKER" == "1" ]] && return 0
  command -v docker >/dev/null 2>&1 || return 0
  docker info >/dev/null 2>&1 || return 0
  local id image name version
  while IFS='|' read -r id image name; do
    [[ -n "$id" ]] || continue
    version=$(timeout 5 docker exec "$id" php -r 'echo PHP_VERSION;' 2>/dev/null || true)
    [[ -n "$version" ]] || continue
    record_result "container ${name} (${image})" "$version" 0
  done < <(docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}' 2>/dev/null || true)
}

installed_runtime_packages() {
  command -v dpkg-query >/dev/null 2>&1 || return 0
  local name status
  while IFS=$'\t' read -r name status; do
    [[ "$status" == "install ok installed" ]] || continue
    is_runtime_package "$name" || continue
    printf '%s\n' "$name"
  done < <(dpkg-query -W -f '${Package}\t${Status}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null || true)
}

restart_runtimes() {
  command -v systemctl >/dev/null 2>&1 || {
    echo "systemctl ausente; reinicie php-fpm e o Apache para carregar o pacote novo." >&2
    return 0
  }
  local unit
  while read -r unit; do
    [[ -n "$unit" ]] || continue
    echo "reiniciando ${unit}"
    systemctl restart "$unit"
  done < <(systemctl list-units --type=service --state=active --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}')
  if systemctl is-active --quiet apache2 2>/dev/null; then
    echo "reiniciando apache2"
    systemctl restart apache2
  fi
}

enable_sury() {
  if ! command -v add-apt-repository >/dev/null 2>&1; then
    echo "add-apt-repository não está instalado (pacote software-properties-common)." >&2
    return 1
  fi
  add-apt-repository -y ppa:ondrej/php
}

apply_upgrade() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Para atualizar, rode de novo com sudo e --apply." >&2
    return 2
  fi
  local pkgs
  pkgs=$(installed_runtime_packages | sort -u)
  if [[ -z "$pkgs" ]]; then
    echo "Nenhum pacote de PHP do apt para atualizar. Containers ficam de fora de propósito." >&2
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  export APT_LISTCHANGES_FRONTEND=none
  apt-get update
  # shellcheck disable=SC2086
  apt-get install -y \
    -o Dpkg::Options::=--force-confold \
    --only-upgrade \
    $pkgs
  restart_runtimes
}

count_problems() {
  FOUND_PROBLEM=0
  FOUND_BACKPORT=0
  FOUND_ANY=0
  echo "script: $(readlink -f "$0")"
  echo "PHP2Shell — verificação de pacote (CVE-2026-109618, CVE-2026-109619)"
  check_host_packages
  check_docker
  if [[ "$FOUND_ANY" == "0" ]]; then
    echo "Nenhum PHP encontrado neste sistema nem em container em execução."
  fi
}

main() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --apply) APPLY=1 ;;
      --use-sury) USE_SURY=1 ;;
      --strict) STRICT=1 ;;
      --no-docker) SKIP_DOCKER=1 ;;
      -h | --help) usage; exit 0 ;;
      *)
        echo "Flag desconhecida: $arg" >&2
        usage >&2
        exit 2
        ;;
    esac
  done

  if [[ "$USE_SURY" == "1" && "$APPLY" != "1" ]]; then
    echo "--use-sury só vale junto com --apply." >&2
    exit 2
  fi

  count_problems
  if [[ "$APPLY" == "1" && "$FOUND_PROBLEM" == "1" ]]; then
    apply_upgrade || exit $?
    if [[ "$USE_SURY" == "1" ]]; then
      FOUND_PROBLEM=0
      FOUND_BACKPORT=0
      FOUND_ANY=0
      check_host_packages
      if [[ "$FOUND_PROBLEM" == "1" ]]; then
        enable_sury
        apply_upgrade || exit $?
      fi
    fi
    echo
    echo "Depois da atualização:"
    FOUND_PROBLEM=0
    FOUND_BACKPORT=0
    FOUND_ANY=0
    check_host_packages
    check_docker
  elif [[ "$APPLY" == "1" ]]; then
    echo "Nada para atualizar: não há runtime classificado como vulnerável ou desconhecido."
  fi

  if [[ "$FOUND_BACKPORT" == "1" ]]; then
    echo "Aviso: há PHP só com backport. O php.net corrigiu os ramos suportados em ${OFFICIAL_MIN_82}, ${OFFICIAL_MIN_83}, ${OFFICIAL_MIN_84} e ${OFFICIAL_MIN_85}." >&2
  fi
  if [[ "$FOUND_PROBLEM" == "1" ]]; then
    exit 1
  fi
  if [[ "$STRICT" == "1" && "$FOUND_BACKPORT" == "1" ]]; then
    exit 1
  fi
  exit 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
