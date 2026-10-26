#!/usr/bin/env bash
# ==============================================================================
# IPClean-Scanner | Interactive Cloudflare TLS Scanner for Iranian Network Testing
# Repository : https://github.com/XiliService/IPClean-Scanner
# Command    : cf-scanner
# Description: Interactive, step-by-step scanner that finds clean Cloudflare IPs
#              that can be tested from the current network. Cross-operator
#              status is never inferred without verified remote probes.
#              All results are displayed directly in the terminal.
# ==============================================================================

set -u

# ------------------------------------------------------------------------------
# Global Metadata & Constants
# ------------------------------------------------------------------------------
SCRIPT_VERSION="1.0.1"
REPO_OWNER="XiliService"
REPO_NAME="IPClean-Scanner"
DEFAULT_BRANCH="main"
BIN_NAME="cf-scanner"

# Terminal Colors
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[0;34m'
    C_MAGENTA=$'\033[0;35m'
    C_CYAN=$'\033[0;36m'
    C_WHITE=$'\033[1;37m'
else
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_MAGENTA=""
    C_CYAN=""
    C_WHITE=""
fi

# Temporary in-memory workspace (auto-deleted on exit; never leaves files behind)
WORK_DIR=""
cleanup() {
    if [ -n "${WORK_DIR:-}" ] && [ -d "${WORK_DIR}" ]; then
        rm -rf "${WORK_DIR}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

init_workdir() {
    cleanup
    if [ -d "/dev/shm" ] && [ -w "/dev/shm" ]; then
        WORK_DIR="$(mktemp -d "/dev/shm/cf-scanner.XXXXXX")"
    else
        WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cf-scanner.XXXXXX")"
    fi
}

# ------------------------------------------------------------------------------
# Curated IPv4 CIDR Lists (Embedded - Zero External Files Needed)
# ------------------------------------------------------------------------------
# Curated Cloudflare candidate ranges. Reachability can vary by ISP, location,
# time, and SNI; these CIDRs are not a compatibility guarantee.
GOLDEN_RANGES=(
    "188.114.96.0/22"
    "188.114.98.0/23"
    "162.159.128.0/21"
    "162.159.135.0/24"
    "162.159.152.0/22"
    "162.159.192.0/22"
    "172.64.80.0/20"
    "172.64.128.0/20"
    "172.67.128.0/20"
    "172.67.160.0/20"
    "104.16.128.0/20"
    "104.17.64.0/20"
    "104.18.32.0/20"
    "104.19.128.0/20"
    "104.21.16.0/20"
    "108.162.192.0/20"
    "141.101.64.0/20"
    "198.41.192.0/20"
)

# Official Cloudflare IPv4 CIDRs
OFFICIAL_RANGES=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

CF_HTTPS_PORTS=(443 2053 2083 2087 2096 8443)

# ------------------------------------------------------------------------------
# Helper Functions: Input, Printing, Version Comparison
# ------------------------------------------------------------------------------
prompt_input() {
    local prompt_text="$1"
    local var_name="$2"
    local default_val="${3:-}"
    local input_val=""

    printf "%b" "${prompt_text}"
    if [ -t 0 ]; then
        read -r input_val || true
    elif { true < /dev/tty; } 2>/dev/null; then
        read -r input_val < /dev/tty || true
    else
        read -r input_val || true
    fi

    # Strip leading/trailing whitespace
    input_val="$(printf "%s" "${input_val}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ -z "${input_val}" ] && [ -n "${default_val}" ]; then
        input_val="${default_val}"
    fi
    printf -v "${var_name}" "%s" "${input_val}"
}

pause_enter() {
    local dummy=""
    printf "\n%b" "${C_DIM}Press [Enter] to return to the main menu...${C_RESET}"
    prompt_input "" dummy ""
}

print_banner() {
    clear 2>/dev/null || true
    printf "%b\n" "${C_CYAN}${C_BOLD}==============================================================================${C_RESET}"
    printf "%b\n" "${C_WHITE}${C_BOLD}          IPClean-Scanner | Cloudflare Clean IP & TLS Scanner                 ${C_RESET}"
    printf "%b\n" "${C_CYAN}          Operator Columns: MCI (Hamrah-e Aval) | MTN (Irancell) | Broadband  ${C_RESET}"
    printf "%b\n" "${C_DIM}          Version: v${SCRIPT_VERSION}  |  Command: ${BIN_NAME}  |  Repo: ${REPO_OWNER}/${REPO_NAME}${C_RESET}"
    printf "%b\n" "${C_CYAN}${C_BOLD}==============================================================================${C_RESET}"
}

print_step_header() {
    local step_num="$1"
    local step_total="$2"
    local step_title="$3"
    printf "\n%b\n" "${C_BLUE}${C_BOLD}------------------------------------------------------------------------------${C_RESET}"
    printf "%b\n" "${C_YELLOW}${C_BOLD}  [Step ${step_num}/${step_total}] ${step_title}${C_RESET}"
    printf "%b\n" "${C_BLUE}${C_BOLD}------------------------------------------------------------------------------${C_RESET}"
}

print_stage_header() {
    local stage_num="$1"
    local stage_total="$2"
    local stage_title="$3"
    printf "\n%b\n" "${C_MAGENTA}${C_BOLD}>>> [Stage ${stage_num}/${stage_total}] ${stage_title}${C_RESET}"
}

# Semantic version comparison: returns 0 (true) if $1 > $2, else 1 (false)
version_gt() {
    local v1="${1#v}"
    local v2="${2#v}"
    if [ "${v1}" = "${v2}" ]; then
        return 1
    fi
    awk -v a="${v1}" -v b="${v2}" '
    BEGIN {
        na = split(a, arr_a, ".")
        nb = split(b, arr_b, ".")
        max_n = (na > nb) ? na : nb
        for (i = 1; i <= max_n; i++) {
            va = (i <= na) ? arr_a[i] + 0 : 0
            vb = (i <= nb) ? arr_b[i] + 0 : 0
            if (va > vb) exit 0
            if (va < vb) exit 1
        }
        exit 1
    }'
}

# ------------------------------------------------------------------------------
# Installation & CLI Management (cf-scanner command)
# ------------------------------------------------------------------------------
get_install_path() {
    if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && [ -w "${PREFIX}/bin" ]; then
        # Termux environment
        printf "%s/bin/%s" "${PREFIX}" "${BIN_NAME}"
    elif [ -w "/usr/local/bin" ]; then
        printf "/usr/local/bin/%s" "${BIN_NAME}"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        printf "/usr/local/bin/%s" "${BIN_NAME}"
    else
        mkdir -p "${HOME}/.local/bin" 2>/dev/null || true
        printf "%s/.local/bin/%s" "${HOME}" "${BIN_NAME}"
    fi
}

install_script_file() {
    local src_file="$1"
    local target_path
    target_path="$(get_install_path)"
    local target_dir
    target_dir="$(dirname "${target_path}")"

    if [ -w "${target_dir}" ]; then
        cp "${src_file}" "${target_path}" && chmod +x "${target_path}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo cp "${src_file}" "${target_path}" && sudo chmod +x "${target_path}"
    else
        mkdir -p "${HOME}/.local/bin" 2>/dev/null || true
        target_path="${HOME}/.local/bin/${BIN_NAME}"
        cp "${src_file}" "${target_path}" && chmod +x "${target_path}"
    fi

    # Ensure ~/.local/bin is in shell rc if installed there
    if [[ "${target_path}" == "${HOME}/.local/bin/"* ]]; then
        if [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
            export PATH="${HOME}/.local/bin:${PATH}"
            for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
                if [ -f "${rc}" ] && ! grep -q '\.local/bin' "${rc}" 2>/dev/null; then
                    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "${rc}" 2>/dev/null || true
                fi
            done
        fi
    fi

    printf "%s" "${target_path}"
}

ensure_cli_installed() {
    local target_path
    target_path="$(get_install_path)"

    # Check if already installed and up-to-date
    if command -v "${BIN_NAME}" >/dev/null 2>&1; then
        local existing_bin
        existing_bin="$(command -v "${BIN_NAME}")"
        local existing_ver
        existing_ver="$(grep -m1 '^SCRIPT_VERSION=' "${existing_bin}" 2>/dev/null | cut -d'"' -f2 || true)"
        if [ "${existing_ver}" = "${SCRIPT_VERSION}" ]; then
            return 0
        fi
    fi

    init_workdir
    local temp_self="${WORK_DIR}/self_scanner.sh"

    # Case 1: Running from a regular file on disk
    if [ -f "${BASH_SOURCE[0]:-$0}" ] && [[ "${BASH_SOURCE[0]:-$0}" != /dev/fd/* ]] && [[ "${BASH_SOURCE[0]:-$0}" != /proc/* ]]; then
        cp "${BASH_SOURCE[0]:-$0}" "${temp_self}" 2>/dev/null || true
    fi

    # Case 2: Running via bash <(curl ...) process substitution -> fetch from GitHub
    if [ ! -s "${temp_self}" ] || ! grep -q "IPClean-Scanner" "${temp_self}" 2>/dev/null; then
        local raw_main="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${DEFAULT_BRANCH}/scanner.sh"
        curl -fsSL --connect-timeout 5 --max-time 15 "${raw_main}" -o "${temp_self}" 2>/dev/null || true
    fi

    if [ -s "${temp_self}" ] && grep -q "IPClean-Scanner" "${temp_self}" 2>/dev/null; then
        local installed_to
        installed_to="$(install_script_file "${temp_self}" 2>/dev/null || true)"
        if [ -n "${installed_to}" ] && [ -x "${installed_to}" ]; then
            printf "%b\n" "${C_GREEN}[+] Installed CLI command '${C_BOLD}${BIN_NAME}${C_RESET}${C_GREEN}' at: ${installed_to}${C_RESET}"
            printf "%b\n" "${C_CYAN}[i] Next time, simply run '${C_BOLD}${BIN_NAME}${C_RESET}${C_CYAN}' from anywhere in your terminal.${C_RESET}"
            sleep 1
        fi
    fi
}

uninstall_cli() {
    print_banner
    printf "\n%b\n" "${C_YELLOW}${C_BOLD}>>> Uninstall ${BIN_NAME}${C_RESET}"
    local found_paths=()
    for p in "/usr/local/bin/${BIN_NAME}" "${HOME}/.local/bin/${BIN_NAME}" "${PREFIX:-/usr}/bin/${BIN_NAME}"; do
        if [ -f "${p}" ]; then
            found_paths+=("${p}")
        fi
    done

    if [ "${#found_paths[@]}" -eq 0 ]; then
        printf "%b\n" "${C_YELLOW}[!] '${BIN_NAME}' is not currently installed in standard system paths.${C_RESET}"
        pause_enter
        return 0
    fi

    printf "%b\n" "Found installed binary at: ${C_WHITE}${found_paths[*]}${C_RESET}"
    local confirm=""
    prompt_input "${C_YELLOW}Are you sure you want to remove ${BIN_NAME}? [y/N]: ${C_RESET}" confirm "n"
    if [[ "${confirm}" =~ ^[Yy]$ ]]; then
        for p in "${found_paths[@]}"; do
            if [ -w "$(dirname "${p}")" ]; then
                rm -f "${p}"
            elif command -v sudo >/dev/null 2>&1; then
                sudo rm -f "${p}"
            fi
        done
        printf "%b\n" "${C_GREEN}[+] '${BIN_NAME}' has been uninstalled successfully.${C_RESET}"
    else
        printf "%b\n" "${C_CYAN}[i] Uninstall cancelled.${C_RESET}"
    fi
    pause_enter
}

# ------------------------------------------------------------------------------
# Live GitHub Update Engine (Option 5)
# Checks `main` first; if `main` version <= current version (or unavailable),
# prompts user for a custom branch name or branch URL to pull the latest script.
# ------------------------------------------------------------------------------
normalize_branch_to_raw_url() {
    local user_input="$1"
    user_input="$(printf "%s" "${user_input}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

    # 1. Direct raw.githubusercontent.com URL
    if [[ "${user_input}" =~ ^https?://raw\.githubusercontent\.com/ ]]; then
        printf "%s" "${user_input}"
        return 0
    fi

    # 2. GitHub tree URL: https://github.com/Owner/Repo/tree/<branch>
    if [[ "${user_input}" =~ ^https?://github\.com/([^/]+)/([^/]+)/tree/(.+)$ ]]; then
        local owner="${BASH_REMATCH[1]}"
        local repo="${BASH_REMATCH[2]}"
        local branch="${BASH_REMATCH[3]%/}"
        printf "https://raw.githubusercontent.com/%s/%s/%s/scanner.sh" "${owner}" "${repo}" "${branch}"
        return 0
    fi

    # 3. GitHub blob URL: https://github.com/Owner/Repo/blob/<branch>/scanner.sh
    if [[ "${user_input}" =~ ^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$ ]]; then
        local owner="${BASH_REMATCH[1]}"
        local repo="${BASH_REMATCH[2]}"
        local rest="${BASH_REMATCH[3]}"
        printf "https://raw.githubusercontent.com/%s/%s/%s" "${owner}" "${repo}" "${rest}"
        return 0
    fi

    # 4. General GitHub repo URL with branch or plain branch name
    user_input="${user_input#origin/}"
    printf "https://raw.githubusercontent.com/%s/%s/%s/scanner.sh" "${REPO_OWNER}" "${REPO_NAME}" "${user_input}"
}

update_script_live() {
    print_banner
    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> Live Script Updater (GitHub: ${REPO_OWNER}/${REPO_NAME})${C_RESET}"
    printf "%b\n" "Current Running Version : ${C_WHITE}${C_BOLD}v${SCRIPT_VERSION}${C_RESET}"
    printf "%b\n" "Default Update Branch   : ${C_CYAN}${DEFAULT_BRANCH}${C_RESET}"

    init_workdir
    local tmp_download="${WORK_DIR}/scanner_update.sh"
    local main_url="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${DEFAULT_BRANCH}/scanner.sh"

    printf "\n%b\n" "${C_DIM}[*] Checking latest version on branch '${DEFAULT_BRANCH}'...${C_RESET}"

    local http_code="000"
    http_code="$(curl -sSL -w "%{http_code}" --connect-timeout 6 --max-time 15 "${main_url}" -o "${tmp_download}" 2>/dev/null || true)"

    local main_version=""
    if [ "${http_code}" = "200" ] && [ -s "${tmp_download}" ] && grep -q '^SCRIPT_VERSION=' "${tmp_download}" 2>/dev/null; then
        main_version="$(grep -m1 '^SCRIPT_VERSION=' "${tmp_download}" | cut -d'"' -f2)"
    fi

    if [ -n "${main_version}" ] && version_gt "${main_version}" "${SCRIPT_VERSION}"; then
        printf "%b\n" "${C_GREEN}[+] New version found on '${DEFAULT_BRANCH}': v${main_version} (Current: v${SCRIPT_VERSION})${C_RESET}"
        apply_downloaded_update "${tmp_download}" "${main_version}" "${DEFAULT_BRANCH}"
        return 0
    fi

    # If main version is equal to or older than running version (or not yet on main)
    if [ -n "${main_version}" ]; then
        printf "%b\n" "${C_YELLOW}[!] Version on '${DEFAULT_BRANCH}' (v${main_version}) is equal to or older than running version (v${SCRIPT_VERSION}).${C_RESET}"
    else
        printf "%b\n" "${C_YELLOW}[!] Script was not found on '${DEFAULT_BRANCH}' (HTTP ${http_code}) or version could not be read.${C_RESET}"
    fi

    printf "%b\n" "${C_CYAN}[i] Please enter the branch name or branch URL to pull the latest version from.${C_RESET}"
    printf "%b\n" "${C_DIM}    Examples: dev | arena/0152535f-ipclean-scanner | https://github.com/${REPO_OWNER}/${REPO_NAME}/tree/branch${C_RESET}"

    local custom_branch=""
    prompt_input "${C_WHITE}Target Branch Name or URL (Press Enter to cancel): ${C_RESET}" custom_branch ""

    if [ -z "${custom_branch}" ]; then
        printf "%b\n" "${C_YELLOW}[i] Update cancelled.${C_RESET}"
        pause_enter
        return 0
    fi

    local target_raw_url
    target_raw_url="$(normalize_branch_to_raw_url "${custom_branch}")"
    printf "\n%b\n" "${C_DIM}[*] Fetching script from: ${target_raw_url}${C_RESET}"

    rm -f "${tmp_download}"
    http_code="$(curl -sSL -w "%{http_code}" --connect-timeout 6 --max-time 15 "${target_raw_url}" -o "${tmp_download}" 2>/dev/null || true)"

    if [ "${http_code}" != "200" ] || [ ! -s "${tmp_download}" ] || ! grep -q '^SCRIPT_VERSION=' "${tmp_download}" 2>/dev/null; then
        printf "%b\n" "${C_RED}[-] Failed to fetch valid scanner script from '${custom_branch}' (HTTP ${http_code}).${C_RESET}"
        pause_enter
        return 1
    fi

    local branch_version
    branch_version="$(grep -m1 '^SCRIPT_VERSION=' "${tmp_download}" | cut -d'"' -f2)"
    printf "%b\n" "${C_GREEN}[+] Retrieved script version v${branch_version} from '${custom_branch}'.${C_RESET}"
    apply_downloaded_update "${tmp_download}" "${branch_version}" "${custom_branch}"
}

apply_downloaded_update() {
    local new_file="$1"
    local new_ver="$2"
    local source_label="$3"

    local installed_path
    installed_path="$(install_script_file "${new_file}")"

    # Also update current script file if invoked directly from a writable local file
    local self_path="${BASH_SOURCE[0]:-$0}"
    if [ -f "${self_path}" ] && [ -w "${self_path}" ] && [[ "${self_path}" != /dev/fd/* ]]; then
        if [ "${self_path}" != "${installed_path}" ]; then
            cp "${new_file}" "${self_path}" && chmod +x "${self_path}"
        fi
    fi

    printf "%b\n" "${C_GREEN}${C_BOLD}[+] Successfully updated ${BIN_NAME} to v${new_ver} from '${source_label}'!${C_RESET}"
    printf "%b\n" "${C_CYAN}[i] Updated binary path: ${installed_path}${C_RESET}"

    local reload_choice=""
    prompt_input "${C_WHITE}Reload into the updated script now? [Y/n]: ${C_RESET}" reload_choice "y"
    if [[ "${reload_choice}" =~ ^[Yy]$ ]]; then
        cleanup
        exec "${installed_path}"
    fi
}

# ------------------------------------------------------------------------------
# System & Network Diagnostics (Option 4)
# ------------------------------------------------------------------------------
check_dependencies() {
    local missing=()
    for cmd in curl awk sed grep sort head tr cut; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        printf "%b\n" "${C_RED}[-] Missing required tools: ${missing[*]}${C_RESET}"
        printf "%b\n" "${C_YELLOW}[!] Please install them using your package manager (apt/yum/brew/pkg).${C_RESET}"
        return 1
    fi
    return 0
}

detect_local_isp() {
    local meta_json=""
    meta_json="$(curl -fsSL --connect-timeout 3 --max-time 5 "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,query" 2>/dev/null || true)"
    if [ -n "${meta_json}" ] && printf "%s" "${meta_json}" | grep -q '"status":"success"'; then
        local ip country isp asn
        ip="$(printf "%s" "${meta_json}" | sed -n 's/.*"query":"\([^"]*\)".*/\1/p')"
        country="$(printf "%s" "${meta_json}" | sed -n 's/.*"countryCode":"\([^"]*\)".*/\1/p')"
        isp="$(printf "%s" "${meta_json}" | sed -n 's/.*"isp":"\([^"]*\)".*/\1/p')"
        asn="$(printf "%s" "${meta_json}" | sed -n 's/.*"as":"\([^"]*\)".*/\1/p')"
        printf "%s|%s|%s|%s" "${ip:-Unknown}" "${country:-Unknown}" "${isp:-Unknown}" "${asn:-Unknown}"
    else
        printf "Unknown|Unknown|Direct Local Connection|Unknown"
    fi
}

run_diagnostics() {
    print_banner
    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> System & Network Diagnostics${C_RESET}\n"

    printf "%b\n" "${C_WHITE}1. Core CLI Utilities:${C_RESET}"
    for tool in bash curl openssl ping awk sed grep sort xargs; do
        if command -v "${tool}" >/dev/null 2>&1; then
            printf "   [ %bOK%b ] %-10s -> %s\n" "${C_GREEN}" "${C_RESET}" "${tool}" "$(command -v "${tool}")"
        else
            printf "   [ %bMISS%b ] %-10s -> Not installed\n" "${C_YELLOW}" "${C_RESET}" "${tool}"
        fi
    done

    printf "\n%b\n" "${C_WHITE}2. Local Network & Operator Info:${C_RESET}"
    local net_info
    net_info="$(detect_local_isp)"
    IFS='|' read -r pub_ip country_code isp_name asn_info <<< "${net_info}"
    printf "   Public IP    : %b%s%b\n" "${C_CYAN}" "${pub_ip}" "${C_RESET}"
    printf "   Country Code : %b%s%b\n" "${C_CYAN}" "${country_code}" "${C_RESET}"
    printf "   Detected ISP : %b%s%b\n" "${C_CYAN}" "${isp_name}" "${C_RESET}"
    printf "   ASN          : %b%s%b\n" "${C_CYAN}" "${asn_info}" "${C_RESET}"

    printf "\n%b\n" "${C_WHITE}3. CLI Installation Status:${C_RESET}"
    if command -v "${BIN_NAME}" >/dev/null 2>&1; then
        printf "   Command '${BIN_NAME}' is active at: %b%s%b\n" "${C_GREEN}" "$(command -v "${BIN_NAME}")" "${C_RESET}"
    else
        printf "   Command '${BIN_NAME}' is %bnot in PATH%b\n" "${C_YELLOW}" "${C_RESET}"
    fi

    pause_enter
}

# ------------------------------------------------------------------------------
# Stage 1: CIDR Expansion & Smart Subnet Sampling (Pure AWK - Fast & Portable)
# ------------------------------------------------------------------------------
generate_candidate_ips() {
    local max_ips="$1"
    shift
    local cidrs=("$@")

    # Expand CIDRs into /24 base prefixes and sample random host IPs (1..254)
    printf "%s\n" "${cidrs[@]}" | awk -v target_count="${max_ips}" -v seed="${RANDOM:-12345}" '
    BEGIN {
        srand(seed)
        total_subnets = 0
    }
    function ip2int(ip,   a) {
        split(ip, a, ".")
        return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
    }
    function int2ip(n,   d, c, b, a) {
        d = n % 256; n = int(n / 256)
        c = n % 256; n = int(n / 256)
        b = n % 256; a = int(n / 256)
        return a "." b "." c "." d
    }
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {
        if (index($0, "/") == 0) {
            single_ips[++single_count] = $0
            next
        }
        split($0, parts, "/")
        ip_str = parts[1]
        prefix = parts[2] + 0
        if (prefix < 8 || prefix > 32) next

        if (prefix == 32) {
            single_ips[++single_count] = ip_str
            next
        }

        base_int = ip2int(ip_str)
        host_bits = 32 - prefix
        block_size = 2 ^ host_bits
        net_int = int(base_int / block_size) * block_size

        if (prefix >= 24) {
            subnets[++total_subnets] = net_int ":" block_size
        } else {
            # Break large CIDR into /24 chunks (cap at 256 chunks per CIDR to stay fast)
            num_24 = int(block_size / 256)
            step = (num_24 > 256) ? int(num_24 / 256) : 1
            for (i = 0; i < num_24; i += step) {
                subnets[++total_subnets] = (net_int + i * 256) ":256"
            }
        }
    }
    END {
        out_count = 0
        # First emit any explicit /32 single IPs
        for (i = 1; i <= single_count && out_count < target_count; i++) {
            if (!(single_ips[i] in seen)) {
                seen[single_ips[i]] = 1
                print single_ips[i]
                out_count++
            }
        }

        if (total_subnets == 0) exit 0

        # Fisher-Yates shuffle on subnets for wide geographic/range diversity
        for (i = total_subnets; i > 1; i--) {
            j = int(rand() * i) + 1
            tmp = subnets[i]
            subnets[i] = subnets[j]
            subnets[j] = tmp
        }

        attempts = 0
        max_attempts = target_count * 10
        idx = 1
        while (out_count < target_count && attempts < max_attempts) {
            attempts++
            split(subnets[idx], sb, ":")
            s_base = sb[1] + 0
            s_size = sb[2] + 0
            if (s_size > 2) {
                offset = int(rand() * (s_size - 2)) + 1
            } else {
                offset = 0
            }
            cand_ip = int2ip(s_base + offset)
            if (!(cand_ip in seen)) {
                seen[cand_ip] = 1
                print cand_ip
                out_count++
            }
            idx++
            if (idx > total_subnets) idx = 1
        }
    }'
}

# ------------------------------------------------------------------------------
# Stage 2: Parallel Ping, Packet Loss & Jitter Measurement
# Automatically falls back to TCP connect timing if ICMP is blocked in container
# ------------------------------------------------------------------------------
measure_ip_ping() {
    local ip="$1"
    local port="$2"
    local max_ping_ms="$3"
    local out_file="$4"

    local ping_out=""
    local os_type
    os_type="$(uname -s 2>/dev/null || printf "Linux")"

    if command -v ping >/dev/null 2>&1; then
        if [ "${os_type}" = "Darwin" ]; then
            ping_out="$(ping -n -c 3 -W 1000 "${ip}" 2>/dev/null || true)"
        else
            ping_out="$(ping -n -c 3 -i 0.2 -W 1 "${ip}" 2>/dev/null || true)"
        fi
    fi

    # Parse ICMP ping if we received replies
    if [ -n "${ping_out}" ] && printf "%s" "${ping_out}" | grep -q "time="; then
        local stats
        stats="$(printf "%s\n" "${ping_out}" | awk '
        /time=/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^time=/) {
                    sub(/^time=/, "", $i)
                    t = $i + 0
                    times[++n] = t
                    sum += t
                }
            }
        }
        END {
            if (n == 0) {
                print "FAIL"
                exit
            }
            avg = sum / n
            loss = int(((3 - n) / 3) * 100)
            if (loss < 0) loss = 0
            jitter_sum = 0
            if (n > 1) {
                for (i = 2; i <= n; i++) {
                    diff = times[i] - times[i-1]
                    if (diff < 0) diff = -diff
                    jitter_sum += diff
                }
                jitter = jitter_sum / (n - 1)
            } else {
                jitter = 1.0
            }
            printf "%.0f|%.1f|%d\n", avg, jitter, loss
        }')"

        if [ "${stats}" != "FAIL" ] && [ -n "${stats}" ]; then
            local avg_ms jitter_ms loss_pct
            IFS='|' read -r avg_ms jitter_ms loss_pct <<< "${stats}"
            if [ "${avg_ms}" -le "${max_ping_ms}" ] && [ "${loss_pct}" -le 50 ]; then
                printf "%s|%s|%s|%s\n" "${ip}" "${avg_ms}" "${jitter_ms}" "${loss_pct}" > "${out_file}"
                return 0
            fi
        fi
    fi

    # Fallback: TCP connect timing (for networks/containers where ICMP is filtered)
    local tcp_times=()
    local ok_count=0
    local i
    for i in 1 2; do
        local t_conn
        t_conn="$(curl -s -o /dev/null -w "%{time_connect}" --connect-timeout 1 --max-time 2 "http://${ip}:${port}" 2>/dev/null || true)"
        local ms
        ms="$(awk -v t="${t_conn}" 'BEGIN { m = int(t * 1000 + 0.5); print (m > 0) ? m : 0 }')"
        if [ "${ms}" -gt 0 ] && [ "${ms}" -le "${max_ping_ms}" ]; then
            tcp_times+=("${ms}")
            ok_count=$((ok_count + 1))
        fi
    done

    if [ "${ok_count}" -gt 0 ]; then
        local stats_tcp
        stats_tcp="$(printf "%s\n" "${tcp_times[@]}" | awk -v total="2" '
        {
            times[++n] = $1 + 0
            sum += $1
        }
        END {
            avg = sum / n
            loss = int(((total - n) / total) * 100)
            jitter = (n > 1) ? ((times[2] > times[1]) ? (times[2] - times[1]) : (times[1] - times[2])) : 1.0
            printf "%.0f|%.1f|%d\n", avg, jitter, loss
        }')"
        local avg_ms jitter_ms loss_pct
        IFS='|' read -r avg_ms jitter_ms loss_pct <<< "${stats_tcp}"
        printf "%s|%s|%s|%s\n" "${ip}" "${avg_ms}" "${jitter_ms}" "${loss_pct}" > "${out_file}"
        return 0
    fi

    return 1
}

# ------------------------------------------------------------------------------
# Stage 3: Real TLS 1.3 / HTTP2 Handshake & DPI Pass-Through Verification
# Tests actual SNI resolution, TLS handshake completion, Cloudflare signature,
# and extracts Cloudflare edge datacenter (COLO) from headers or trace body.
# ------------------------------------------------------------------------------
verify_ip_tls() {
    local ip="$1"
    local port="$2"
    local sni="$3"
    local req_path="$4"
    local tls_timeout="$5"
    local ping_ms="$6"
    local jitter_ms="$7"
    local loss_pct="$8"
    local out_file="$9"

    local hdr_file="${out_file}.hdr"
    local body_file="${out_file}.body"
    local error_file="${out_file}.err"
    local fail_file="${out_file}.fail"
    local target_url="https://${sni}:${port}${req_path}"
    local curl_metrics=""
    local curl_exit=0

    # Preserve curl's write-out metrics even when the HTTP transfer fails.
    # Appending synthetic defaults here corrupts the last parsed field and can
    # incorrectly turn a completed TLS handshake into an apparent TLS failure.
    curl_metrics="$(curl -sS -L --max-redirs 0 \
        --resolve "${sni}:${port}:${ip}" \
        --connect-timeout "${tls_timeout}" \
        --max-time "$((tls_timeout + 2))" \
        --tlsv1.2 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -D "${hdr_file}" \
        -o "${body_file}" \
        -w "%{http_code}|%{time_appconnect}|%{time_starttransfer}|%{ssl_verify_result}" \
        "${target_url}" 2>"${error_file}")" || curl_exit=$?

    local http_code="000" t_tls="0" t_ttfb="0" ssl_verify="99"
    IFS='|' read -r http_code t_tls t_ttfb ssl_verify <<< "${curl_metrics}"

    local tls_ms ttfb_ms
    tls_ms="$(awk -v t="${t_tls:-0}" 'BEGIN { printf "%d", int(t * 1000 + 0.5) }')"
    ttfb_ms="$(awk -v t="${t_ttfb:-0}" 'BEGIN { printf "%d", int(t * 1000 + 0.5) }')"

    local failure_reason=""
    if [ "${tls_ms}" -le 0 ]; then
        failure_reason="TLS_HANDSHAKE_FAILED"
    elif [ "${ssl_verify:-99}" != "0" ]; then
        failure_reason="CERTIFICATE_VALIDATION_FAILED"
    elif [ "${http_code:-000}" = "000" ]; then
        failure_reason="TLS_OK_HTTP_NO_RESPONSE"
    fi

    if [ -n "${failure_reason}" ]; then
        printf "%s|%s|%s|%s|%s|%s\n" \
            "${failure_reason}" "${ip}" "${port}" "${tls_ms}" "${http_code:-000}" "${curl_exit}" > "${fail_file}"
        rm -f "${hdr_file}" "${body_file}" "${error_file}" 2>/dev/null || true
        return 1
    fi

    # Verify Cloudflare presence and extract COLO (e.g. FRA, AMS, MUC, LHR).
    local colo=""
    if [ -f "${body_file}" ]; then
        colo="$(sed -n 's/^colo=\([A-Za-z0-9_-]*\).*/\1/p' "${body_file}" 2>/dev/null | head -n1 | tr -d '\r\n')"
    fi
    if [ -z "${colo}" ] && [ -f "${hdr_file}" ]; then
        colo="$(grep -i '^cf-ray:' "${hdr_file}" 2>/dev/null | head -n1 | sed -n 's/.*-\([A-Za-z]\{3\}\).*/\1/p' | tr '[:lower:]' '[:upper:]' | tr -d '\r\n')"
    fi

    local is_cf=0
    if [ -n "${colo}" ]; then
        is_cf=1
    elif [ -f "${hdr_file}" ] && grep -qiE '^(server:[[:space:]]*cloudflare|cf-ray:|cf-cache-status:)' "${hdr_file}" 2>/dev/null; then
        is_cf=1
        colo="CF"
    fi

    # For custom paths, confirm the edge with the standard Cloudflare trace path.
    if [ "${is_cf}" -eq 0 ]; then
        local trace_out=""
        trace_out="$(curl -fsSL --resolve "${sni}:${port}:${ip}" --connect-timeout 2 --max-time 3 "https://${sni}:${port}/cdn-cgi/trace" 2>/dev/null || true)"
        if printf "%s" "${trace_out}" | grep -q "colo="; then
            is_cf=1
            colo="$(printf "%s\n" "${trace_out}" | sed -n 's/^colo=\([A-Za-z0-9_-]*\).*/\1/p' | head -n1 | tr -d '\r\n')"
        fi
    fi

    rm -f "${hdr_file}" "${body_file}" "${error_file}" 2>/dev/null || true

    if [ "${is_cf}" -eq 0 ]; then
        printf "%s|%s|%s|%s|%s|%s\n" \
            "HTTP_RESPONSE_NOT_CONFIRMED_CLOUDFLARE" "${ip}" "${port}" "${tls_ms}" "${http_code}" "${curl_exit}" > "${fail_file}"
        return 1
    fi

    printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
        "${ip}" "${port}" "${ping_ms}" "${jitter_ms}" "${loss_pct}" "${tls_ms}" "${ttfb_ms}" "${colo:-CF}" "${http_code}" > "${out_file}"
    return 0
}

# ------------------------------------------------------------------------------
# Stage 4: Final ranking; remote operator probes are not assumed available.
# Cross-operator results remain unavailable unless independently tested on
# those networks; local latency must never be presented as remote ISP evidence.
# ------------------------------------------------------------------------------
verify_iran_operators() {
    local ip="$1"
    local port="$2"
    local sni="$3"
    local ping_ms="$4"
    local jitter_ms="$5"
    local loss_pct="$6"
    local tls_ms="$7"
    local ttfb_ms="$8"
    local colo="$9"
    local out_file="${10}"

    # A local scan cannot truthfully infer reachability from other Iranian ISPs.
    # Keep those fields explicitly unavailable instead of fabricating ISP results
    # from latency thresholds on the current connection.
    local mci_status="N/A"
    local mtn_status="N/A"
    local fxd_status="N/A"

    # Local quality score only; it does not represent cross-operator performance.
    local score
    score="$(awk -v p="${ping_ms}" -v t="${tls_ms}" -v j="${jitter_ms}" -v l="${loss_pct}" '
    BEGIN {
        p_score = 40 - (p / 10.0)
        if (p_score < 0) p_score = 0
        if (p_score > 40) p_score = 40
        t_score = 40 - (t / 30.0)
        if (t_score < 0) t_score = 0
        if (t_score > 40) t_score = 40
        s_score = 20 - (j * 0.5) - (l * 0.3)
        if (s_score < 0) s_score = 0
        if (s_score > 20) s_score = 20
        print int(p_score + t_score + s_score + 0.5)
    }')"

    printf "%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \\
        "${score}" "${ip}" "${port}" "${ping_ms}" "${jitter_ms}" "${loss_pct}" \\
        "${tls_ms}" "${ttfb_ms}" "${colo}" "${mci_status}" "${mtn_status}" "${fxd_status}" > "${out_file}"
}

# ------------------------------------------------------------------------------
# Progress Bar Renderer
# ------------------------------------------------------------------------------
draw_progress() {
    local current="$1"
    local total="$2"
    local label="$3"
    local width=28
    if [ "${total}" -le 0 ]; then total=1; fi
    local pct=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    local bar_filled=""
    local bar_empty=""
    local i
    for ((i = 0; i < filled; i++)); do bar_filled="${bar_filled}#"; done
    for ((i = 0; i < empty; i++)); do bar_empty="${bar_empty}-"; done

    printf "\r  %b[%s%s] %3d%% (%d/%d) - %s%b" \
        "${C_CYAN}" "${bar_filled}" "${bar_empty}" "${pct}" "${current}" "${total}" "${label}" "${C_RESET}"
}

# Wait for a completed worker without turning a worker failure into a full wait.
# Bash 3.2 (the system Bash on older macOS) lacks `wait -n`, so use batches there.
wait_for_worker() {
    if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )); then
        wait -n 2>/dev/null || true
        active_jobs=$((active_jobs - 1))
    else
        wait || true
        active_jobs=0
    fi
}

# ------------------------------------------------------------------------------
# Main 4-Stage Execution Pipeline
# ------------------------------------------------------------------------------
execute_scan_pipeline() {
    local target_sni="$1"
    local req_path="$2"
    local ports_csv="$3"
    local max_ping="$4"
    local tls_timeout="$5"
    local candidate_count="$6"
    local concurrency="$7"
    shift 7
    local selected_cidrs=("$@")

    init_workdir

    printf "\n%b\n" "${C_CYAN}${C_BOLD}==============================================================================${C_RESET}"
    printf "%b\n" "${C_WHITE}${C_BOLD}  SCAN CONFIGURATION SUMMARY${C_RESET}"
    printf "%b\n" "${C_CYAN}==============================================================================${C_RESET}"
    printf "  Target SNI / Host   : %b%s%b\n" "${C_GREEN}${C_BOLD}" "${target_sni}" "${C_RESET}"
    printf "  Request Path        : %b%s%b\n" "${C_CYAN}" "${req_path}" "${C_RESET}"
    printf "  TLS Port(s)         : %b%s%b\n" "${C_CYAN}" "${ports_csv}" "${C_RESET}"
    printf "  Candidate IP Pool   : %b%d IPs (from %d CIDR blocks)%b\n" "${C_CYAN}" "${candidate_count}" "${#selected_cidrs[@]}" "${C_RESET}"
    printf "  Max Acceptable Ping : %b%d ms%b  |  TLS Timeout: %b%d s%b  |  Workers: %b%d%b\n" \
        "${C_CYAN}" "${max_ping}" "${C_RESET}" "${C_CYAN}" "${tls_timeout}" "${C_RESET}" "${C_CYAN}" "${concurrency}" "${C_RESET}"
    printf "%b\n" "${C_CYAN}==============================================================================${C_RESET}"

    # --------------------------------------------------------------------------
    # STAGE 1: Generate Candidate IPs
    # --------------------------------------------------------------------------
    print_stage_header 1 4 "Generating Candidate IPs from Subnets"
    local candidates_file="${WORK_DIR}/candidates.txt"
    generate_candidate_ips "${candidate_count}" "${selected_cidrs[@]}" > "${candidates_file}"

    local total_candidates
    total_candidates="$(wc -l < "${candidates_file}" | tr -d ' ')"
    if [ "${total_candidates}" -eq 0 ]; then
        printf "%b\n" "${C_RED}[-] No valid candidate IPs could be generated from the provided ranges.${C_RESET}"
        pause_enter
        return 1
    fi
    printf "  %b[+] Generated %d diverse candidate IPs across selected Cloudflare subnets.%b\n" \
        "${C_GREEN}" "${total_candidates}" "${C_RESET}"

    # Parse ports list
    local ports_arr=()
    IFS=',' read -r -a ports_arr <<< "${ports_csv}"
    local primary_port="${ports_arr[0]:-443}"

    # --------------------------------------------------------------------------
    # STAGE 2: Parallel Ping, Jitter & Packet Loss Filtering
    # --------------------------------------------------------------------------
    print_stage_header 2 4 "Testing Ping, Jitter & Packet Loss (Parallel Workers: ${concurrency})"
    local ping_dir="${WORK_DIR}/ping_results"
    mkdir -p "${ping_dir}"

    local idx=0
    local active_jobs=0
    while IFS= read -r ip; do
        [ -z "${ip}" ] && continue
        idx=$((idx + 1))
        measure_ip_ping "${ip}" "${primary_port}" "${max_ping}" "${ping_dir}/${idx}.res" &
        active_jobs=$((active_jobs + 1))

        if [ "${active_jobs}" -ge "${concurrency}" ]; then
            wait_for_worker
            draw_progress "${idx}" "${total_candidates}" "Pinging IPs..."
        fi
    done < "${candidates_file}"
    wait
    draw_progress "${total_candidates}" "${total_candidates}" "Ping sweep complete."
    printf "\n"

    local ping_alive_file="${WORK_DIR}/ping_alive.txt"
    cat "${ping_dir}"/*.res > "${ping_alive_file}" 2>/dev/null || true
    local alive_count
    alive_count="$(wc -l < "${ping_alive_file}" 2>/dev/null | tr -d ' ' || printf "0")"

    if [ "${alive_count}" -eq 0 ]; then
        printf "  %b[-] No IPs responded within %d ms ping threshold. Try relaxing ping threshold or changing ranges.%b\n" \
            "${C_RED}" "${max_ping}" "${C_RESET}"
        pause_enter
        return 1
    fi
    printf "  %b[+] %d / %d IPs passed ping & packet loss check.%b\n" \
        "${C_GREEN}" "${alive_count}" "${total_candidates}" "${C_RESET}"

    # --------------------------------------------------------------------------
    # STAGE 3: Real TLS Handshake & SNI Verification
    # --------------------------------------------------------------------------
    print_stage_header 3 4 "Verifying Real TLS Handshake & DPI Pass-Through (SNI: ${target_sni})"
    local tls_dir="${WORK_DIR}/tls_results"
    mkdir -p "${tls_dir}"

    local total_tls_tasks=$((alive_count * ${#ports_arr[@]}))
    local tls_idx=0
    active_jobs=0

    while IFS='|' read -r ip ping_ms jitter_ms loss_pct; do
        [ -z "${ip}" ] && continue
        for p in "${ports_arr[@]}"; do
            tls_idx=$((tls_idx + 1))
            verify_ip_tls "${ip}" "${p}" "${target_sni}" "${req_path}" "${tls_timeout}" \
                "${ping_ms}" "${jitter_ms}" "${loss_pct}" "${tls_dir}/${tls_idx}.tls" &
            active_jobs=$((active_jobs + 1))

            if [ "${active_jobs}" -ge "${concurrency}" ]; then
                wait_for_worker
                draw_progress "${tls_idx}" "${total_tls_tasks}" "Testing TLS Handshake..."
            fi
        done
    done < "${ping_alive_file}"
    wait
    draw_progress "${total_tls_tasks}" "${total_tls_tasks}" "TLS verification complete."
    printf "\n"

    local tls_passed_file="${WORK_DIR}/tls_passed.txt"
    cat "${tls_dir}"/*.tls > "${tls_passed_file}" 2>/dev/null || true
    local tls_passed_count
    tls_passed_count="$(wc -l < "${tls_passed_file}" 2>/dev/null | tr -d ' ' || printf "0")"

    if [ "${tls_passed_count}" -eq 0 ]; then
        local tls_fail_file="${WORK_DIR}/tls_failures.txt"
        cat "${tls_dir}"/*.fail > "${tls_fail_file}" 2>/dev/null || true
        printf "  %b[-] No endpoint passed TLS, HTTP, and Cloudflare verification for SNI '${target_sni}'.%b\n" "${C_RED}" "${C_RESET}"

        local fail_reason fail_count
        for fail_reason in TLS_HANDSHAKE_FAILED CERTIFICATE_VALIDATION_FAILED TLS_OK_HTTP_NO_RESPONSE HTTP_RESPONSE_NOT_CONFIRMED_CLOUDFLARE; do
            fail_count="$(awk -F'|' -v reason="${fail_reason}" '$1 == reason { n++ } END { print n + 0 }' "${tls_fail_file}")"
            if [ "${fail_count}" -gt 0 ]; then
                case "${fail_reason}" in
                    TLS_HANDSHAKE_FAILED) printf "  %b- TLS connection/handshake failed: %d endpoint(s).%b\n" "${C_YELLOW}" "${fail_count}" "${C_RESET}" ;;
                    CERTIFICATE_VALIDATION_FAILED) printf "  %b- TLS connected, but certificate validation failed: %d endpoint(s).%b\n" "${C_YELLOW}" "${fail_count}" "${C_RESET}" ;;
                    TLS_OK_HTTP_NO_RESPONSE)
                        printf "  %b- TLS handshake and certificate passed, but no HTTP response arrived: %d endpoint(s).%b\n" "${C_YELLOW}" "${fail_count}" "${C_RESET}"
                        awk -F'|' '$1 == "TLS_OK_HTTP_NO_RESPONSE" && shown < 3 { printf "      %s:%s (TLS %sms, curl exit %s)", $2, $3, $4, $6; print ""; shown++ }' "${tls_fail_file}"
                        ;;
                    HTTP_RESPONSE_NOT_CONFIRMED_CLOUDFLARE) printf "  %b- HTTP responded, but Cloudflare could not be confirmed: %d endpoint(s).%b\n" "${C_YELLOW}" "${fail_count}" "${C_RESET}" ;;
                esac
            fi
        done
        printf "  %b[i] This separates TLS handshake success from successful HTTPS data exchange; inspect the SNI, request path, and network filtering.%b\n" "${C_CYAN}" "${C_RESET}"
        pause_enter
        return 1
    fi
    printf "  %b[+] %d IP:Port endpoints passed TLS, HTTP, and Cloudflare verification.%b\n" \
        "${C_GREEN}" "${tls_passed_count}" "${C_RESET}"

    # Sort locally tested endpoints by (latency + TLS time) and limit the final table.
    local top_tls_file="${WORK_DIR}/top_tls.txt"
    awk -F'|' '{ print ($3 + $6) "|" $0 }' "${tls_passed_file}" | sort -t'|' -k1,1n | head -n 25 | cut -d'|' -f2- > "${top_tls_file}"
    local top_count
    top_count="$(wc -l < "${top_tls_file}" | tr -d ' ')"

    # --------------------------------------------------------------------------
    # STAGE 4: Final ranking and results display
    # --------------------------------------------------------------------------
    print_stage_header 4 4 "Ranking Top ${top_count} Locally Verified Clean IPs"
    local final_dir="${WORK_DIR}/final_results"
    mkdir -p "${final_dir}"

    printf "  %b[i] Cross-operator checks are marked N/A: this run has no verified remote probes.%b\n" "${C_YELLOW}" "${C_RESET}"

    local op_idx=0
    active_jobs=0
    while IFS='|' read -r ip port ping_ms jitter_ms loss_pct tls_ms ttfb_ms colo http_code; do
        [ -z "${ip}" ] && continue
        op_idx=$((op_idx + 1))
        verify_iran_operators "${ip}" "${port}" "${target_sni}" \
            "${ping_ms}" "${jitter_ms}" "${loss_pct}" "${tls_ms}" "${ttfb_ms}" "${colo}" \
            "${final_dir}/${op_idx}.fin" &
        active_jobs=$((active_jobs + 1))

        if [ "${active_jobs}" -ge 10 ]; then
            wait_for_worker
            draw_progress "${op_idx}" "${top_count}" "Ranking local results..."
        fi
    done < "${top_tls_file}"
    wait
    draw_progress "${top_count}" "${top_count}" "Final ranking complete."
    printf "\n"

    local final_sorted="${WORK_DIR}/final_sorted.txt"
    cat "${final_dir}"/*.fin 2>/dev/null | sort -t'|' -k1,1nr -k4,4n -k7,7n > "${final_sorted}"

    render_terminal_results "${final_sorted}" "${target_sni}"
    pause_enter
}

# ------------------------------------------------------------------------------
# Terminal Results Table Renderer (Zero Files Saved to Disk)
# ------------------------------------------------------------------------------
render_terminal_results() {
    local results_file="$1"
    local tested_sni="$2"

    if [ ! -s "${results_file}" ]; then
        printf "\n%b[-] No clean IPs found matching all criteria.%b\n" "${C_RED}" "${C_RESET}"
        return 1
    fi

    printf "\n%b\n" "${C_GREEN}${C_BOLD}====================================================================================================================${C_RESET}"
    printf "%b\n" "${C_WHITE}${C_BOLD}  CLEAN CLOUDFLARE IPs RANKED BY LOCAL QUALITY  |  Verified SNI: ${C_CYAN}${tested_sni}${C_RESET}"
    printf "%b\n" "${C_GREEN}${C_BOLD}====================================================================================================================${C_RESET}"
    printf "${C_BOLD}%-4s | %-15s | %-5s | %-7s | %-7s | %-8s | %-5s | %-13s | %-13s | %-13s | %-5s${C_RESET}\n" \
        "Rank" "IP Address" "Port" "Ping" "Jitter" "TLS Time" "Colo" "MCI (Hamrah)" "MTN (Irancell)" "Broadband" "Score"
    printf "%s\n" "-----+-----------------+-------+---------+---------+----------+-------+---------------+---------------+---------------+------"

    local rank=0
    local top_ips=()
    local top_ip_ports=()

    while IFS='|' read -r score ip port ping_ms jitter_ms loss_pct tls_ms ttfb_ms colo mci mtn fxd; do
        [ -z "${ip}" ] && continue
        rank=$((rank + 1))
        if [ "${rank}" -le 15 ]; then
            case " ${top_ips[*]} " in
                *" ${ip} "*) ;;
                *) top_ips+=("${ip}") ;;
            esac
            top_ip_ports+=("${ip}:${port}")
        fi

        local score_color="${C_GREEN}"
        if [ "${score}" -lt 70 ]; then
            score_color="${C_YELLOW}"
        fi
        if [ "${score}" -lt 50 ]; then
            score_color="${C_RED}"
        fi

        printf "%-4d | %b%-15s%b | %-5s | %4sms  | %4sms  | %5sms  | %-5s | %-13s | %-13s | %-13s | %b%3d%%%b\n" \
            "${rank}" "${C_WHITE}${C_BOLD}" "${ip}" "${C_RESET}" "${port}" \
            "${ping_ms}" "${jitter_ms}" "${tls_ms}" "${colo}" \
            "${mci}" "${mtn}" "${fxd}" \
            "${score_color}${C_BOLD}" "${score}" "${C_RESET}"
    done < "${results_file}"

    printf "%b\n" "${C_GREEN}${C_BOLD}====================================================================================================================${C_RESET}"
    printf "%b\n" "${C_YELLOW}Note: MCI, Irancell, and Broadband show N/A unless independently tested from those networks.${C_RESET}"

    # Quick Copy Section directly in terminal
    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> Quick Copy List (Top Clean IPs for Cloudflare CDN Configs):${C_RESET}"
    printf "%b\n" "${C_DIM}------------------------------------------------------------${C_RESET}"
    for item in "${top_ips[@]}"; do
        printf "%b%s%b\n" "${C_WHITE}" "${item}" "${C_RESET}"
    done
    printf "%b\n" "${C_DIM}------------------------------------------------------------${C_RESET}"

    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> Comma-Separated Clean IPs (For Panels / Load Balancers):${C_RESET}"
    local IFS=','
    printf "%b%s%b\n" "${C_GREEN}" "${top_ips[*]}" "${C_RESET}"

    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> Verified IP:Port Endpoints:${C_RESET}"
    printf "%b\n" "${C_DIM}------------------------------------------------------------${C_RESET}"
    for item in "${top_ip_ports[@]}"; do
        printf "%b%s%b\n" "${C_WHITE}" "${item}" "${C_RESET}"
    done
}

# ------------------------------------------------------------------------------
# Interactive Menu Option 1: Quick Auto Scan (Guided 2-Step)
# ------------------------------------------------------------------------------
menu_quick_scan() {
    print_banner
    printf "\n%b\n" "${C_GREEN}${C_BOLD}>>> [Option 1] Quick Auto Scan (Golden Ranges + Port 443)${C_RESET}"

    # Step 1/2: Target SNI selection
    print_step_header 1 2 "Select Target SNI / Domain for Real TLS Verification"
    printf "  %b[1]%b Enter your Custom Cloudflare CDN Domain / Worker SNI (Recommended)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Use Default Cloudflare Endpoint (speed.cloudflare.com)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local sni_choice=""
    local target_sni="speed.cloudflare.com"
    local req_path="/cdn-cgi/trace"
    prompt_input "\n${C_WHITE}Select option [1-2] or type your domain directly [Default: 2]: ${C_RESET}" sni_choice "2"

    if [ "${sni_choice}" = "1" ]; then
        prompt_input "${C_YELLOW}Enter your Cloudflare CDN domain (e.g., sub.yourdomain.com): ${C_RESET}" target_sni "speed.cloudflare.com"
        target_sni="${target_sni#https://}"
        target_sni="${target_sni#http://}"
        target_sni="${target_sni%%/*}"
        target_sni="${target_sni%%:*}"
    elif [ "${sni_choice}" != "2" ] && [[ "${sni_choice}" == *.* ]]; then
        target_sni="${sni_choice#https://}"
        target_sni="${target_sni#http://}"
        target_sni="${target_sni%%/*}"
        target_sni="${target_sni%%:*}"
    fi

    # Step 2/2: Scan Intensity
    print_step_header 2 2 "Select Scan Speed & Sample Size"
    printf "  %b[1]%b Fast Scan     (36 candidate IPs  | ~15-25 sec)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Balanced Scan (72 candidate IPs  | ~30-45 sec) [Recommended]\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Deep Scan     (144 candidate IPs | ~60-90 sec)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local speed_choice=""
    prompt_input "\n${C_WHITE}Select option [1-3] [Default: 2]: ${C_RESET}" speed_choice "2"

    local cand_count=72
    local workers=30
    case "${speed_choice}" in
        1) cand_count=36; workers=24 ;;
        2) cand_count=72; workers=30 ;;
        3) cand_count=144; workers=40 ;;
        *) cand_count=72; workers=30 ;;
    esac

    execute_scan_pipeline "${target_sni}" "${req_path}" "443" 250 3 "${cand_count}" "${workers}" "${GOLDEN_RANGES[@]}"
}

# ------------------------------------------------------------------------------
# Interactive Menu Option 2: Custom Step-by-Step Scan (Guided 5-Step)
# ------------------------------------------------------------------------------
menu_custom_scan() {
    print_banner
    printf "\n%b\n" "${C_GREEN}${C_BOLD}>>> [Option 2] Custom Step-by-Step Scan${C_RESET}"

    # Step 1/5: SNI & Path
    print_step_header 1 5 "Configure Target SNI & HTTP Request Path"
    printf "  %b[1]%b Custom Cloudflare Domain (Checks /cdn-cgi/trace on your domain)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Custom Cloudflare Domain + Custom Path (e.g. /ws or /health)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Standard Cloudflare Endpoint (speed.cloudflare.com)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local step1_opt=""
    local target_sni="speed.cloudflare.com"
    local req_path="/cdn-cgi/trace"
    prompt_input "\n${C_WHITE}Select option [1-3] [Default: 1]: ${C_RESET}" step1_opt "1"

    if [ "${step1_opt}" = "1" ] || [ "${step1_opt}" = "2" ]; then
        prompt_input "${C_YELLOW}Enter your Cloudflare CDN domain (e.g. cdn.example.com): ${C_RESET}" target_sni "speed.cloudflare.com"
        target_sni="${target_sni#https://}"
        target_sni="${target_sni#http://}"
        target_sni="${target_sni%%/*}"
        target_sni="${target_sni%%:*}"
        if [ "${step1_opt}" = "2" ]; then
            prompt_input "${C_YELLOW}Enter request path [Default: /]: ${C_RESET}" req_path "/"
            [[ "${req_path}" != /* ]] && req_path="/${req_path}"
        fi
    fi

    # Step 2/5: IP Range Selection
    print_step_header 2 5 "Select Cloudflare IP Range Source"
    printf "  %b[1]%b Iran Golden Ranges (Candidate list; not a cross-ISP guarantee)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Official Cloudflare IPv4 Ranges (All global announcements)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Combined (Iran Golden + Official Ranges)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[4]%b Specific Popular Subnet Family (188.114.x / 162.159.x / 172.64.x / 104.x)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[5]%b Enter Custom CIDR Range(s)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local range_opt=""
    prompt_input "\n${C_WHITE}Select option [1-5] [Default: 1]: ${C_RESET}" range_opt "1"

    local chosen_ranges=()
    case "${range_opt}" in
        1) chosen_ranges=("${GOLDEN_RANGES[@]}") ;;
        2) chosen_ranges=("${OFFICIAL_RANGES[@]}") ;;
        3) chosen_ranges=("${GOLDEN_RANGES[@]}" "${OFFICIAL_RANGES[@]}") ;;
        4)
            printf "\n  %bSelect Subnet Family:%b\n" "${C_YELLOW}" "${C_RESET}"
            printf "    [1] 188.114.96.0/20   (Candidate addresses from this Cloudflare block)\n"
            printf "    [2] 162.159.128.0/17  (Low latency across Broadband & Mobile)\n"
            printf "    [3] 172.64.0.0/13     (Modern Cloudflare Anycast blocks)\n"
            printf "    [4] 104.16.0.0/13     (Large Cloudflare Anycast pool)\n"
            local fam_opt=""
            prompt_input "  ${C_WHITE}Select family [1-4] [Default: 1]: ${C_RESET}" fam_opt "1"
            case "${fam_opt}" in
                1) chosen_ranges=("188.114.96.0/20") ;;
                2) chosen_ranges=("162.159.128.0/17") ;;
                3) chosen_ranges=("172.64.0.0/13") ;;
                4) chosen_ranges=("104.16.0.0/13") ;;
                *) chosen_ranges=("188.114.96.0/20") ;;
            esac
            ;;
        5)
            local custom_cidr_input=""
            prompt_input "${C_YELLOW}Enter CIDR(s) separated by space (e.g. 188.114.96.0/22 162.159.192.0/24): ${C_RESET}" custom_cidr_input "188.114.96.0/22"
            read -r -a chosen_ranges <<< "${custom_cidr_input}"
            ;;
        *) chosen_ranges=("${GOLDEN_RANGES[@]}") ;;
    esac

    # Step 3/5: Port Selection
    print_step_header 3 5 "Select Cloudflare TLS Port(s)"
    printf "  %b[1]%b Port 443  (Standard HTTPS - Recommended)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Port 2053\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Port 2083\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[4]%b Port 2087\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[5]%b Port 2096\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[6]%b Port 8443\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[7]%b All Cloudflare HTTPS Ports (443,2053,2083,2087,2096,8443)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local port_opt=""
    prompt_input "\n${C_WHITE}Select option [1-7] [Default: 1]: ${C_RESET}" port_opt "1"
    local selected_ports="443"
    case "${port_opt}" in
        1) selected_ports="443" ;;
        2) selected_ports="2053" ;;
        3) selected_ports="2083" ;;
        4) selected_ports="2087" ;;
        5) selected_ports="2096" ;;
        6) selected_ports="8443" ;;
        7) selected_ports="443,2053,2083,2087,2096,8443" ;;
        *) selected_ports="443" ;;
    esac

    # Step 4/5: Latency & TLS Strictness
    print_step_header 4 5 "Select Latency & TLS Strictness Profile"
    printf "  %b[1]%b Strict   (Max Ping: 160ms | TLS Timeout: 2s - Ultra Low Latency)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Balanced (Max Ping: 250ms | TLS Timeout: 3s - Recommended)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Relaxed  (Max Ping: 380ms | TLS Timeout: 4s - For Congested Links)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local strict_opt=""
    prompt_input "\n${C_WHITE}Select option [1-3] [Default: 2]: ${C_RESET}" strict_opt "2"
    local max_ping=250
    local tls_timeout=3
    case "${strict_opt}" in
        1) max_ping=160; tls_timeout=2 ;;
        2) max_ping=250; tls_timeout=3 ;;
        3) max_ping=380; tls_timeout=4 ;;
        *) max_ping=250; tls_timeout=3 ;;
    esac

    # Step 5/5: Depth & Parallel Workers
    print_step_header 5 5 "Select Scan Depth & Parallelism"
    printf "  %b[1]%b Quick    (30 IPs  | 20 Parallel Workers)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[2]%b Standard (60 IPs  | 30 Parallel Workers) [Default]\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[3]%b Deep     (120 IPs | 40 Parallel Workers)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"
    printf "  %b[4]%b Extreme  (240 IPs | 50 Parallel Workers)\n" "${C_CYAN}${C_BOLD}" "${C_RESET}"

    local depth_opt=""
    prompt_input "\n${C_WHITE}Select option [1-4] [Default: 2]: ${C_RESET}" depth_opt "2"
    local cand_count=60
    local workers=30
    case "${depth_opt}" in
        1) cand_count=30; workers=20 ;;
        2) cand_count=60; workers=30 ;;
        3) cand_count=120; workers=40 ;;
        4) cand_count=240; workers=50 ;;
        *) cand_count=60; workers=30 ;;
    esac

    execute_scan_pipeline "${target_sni}" "${req_path}" "${selected_ports}" \
        "${max_ping}" "${tls_timeout}" "${cand_count}" "${workers}" "${chosen_ranges[@]}"
}

# ------------------------------------------------------------------------------
# Interactive Menu Option 3: Test Specific IP or CIDR Subnet
# ------------------------------------------------------------------------------
menu_test_specific_ip() {
    print_banner
    printf "\n%b\n" "${C_GREEN}${C_BOLD}>>> [Option 3] Test Specific IP or CIDR Subnet${C_RESET}"

    print_step_header 1 3 "Enter Target IP Address or CIDR Subnet"
    local user_ip_input=""
    prompt_input "${C_YELLOW}Enter IP or CIDR (e.g. 188.114.97.3 or 188.114.97.0/24): ${C_RESET}" user_ip_input ""
    if [ -z "${user_ip_input}" ]; then
        printf "%b\n" "${C_RED}[-] No IP or subnet entered.${C_RESET}"
        pause_enter
        return 1
    fi

    print_step_header 2 3 "Enter Target SNI / Domain"
    local target_sni=""
    prompt_input "${C_YELLOW}Enter Cloudflare SNI domain [Default: speed.cloudflare.com]: ${C_RESET}" target_sni "speed.cloudflare.com"
    target_sni="${target_sni#https://}"
    target_sni="${target_sni#http://}"
    target_sni="${target_sni%%/*}"
    target_sni="${target_sni%%:*}"

    print_step_header 3 3 "Select TLS Port"
    local target_port=""
    prompt_input "${C_YELLOW}Enter Cloudflare HTTPS Port [Default: 443]: ${C_RESET}" target_port "443"

    local sample_size=25
    if [[ "${user_ip_input}" != */* ]] || [[ "${user_ip_input}" == */32 ]]; then
        sample_size=1
    fi

    execute_scan_pipeline "${target_sni}" "/cdn-cgi/trace" "${target_port}" 400 4 "${sample_size}" 20 "${user_ip_input}"
}

# ------------------------------------------------------------------------------
# Non-Interactive CLI Flag Support (for quick testing / automation)
# ------------------------------------------------------------------------------
handle_cli_flags() {
    case "${1:-}" in
        --version|-v)
            printf "IPClean-Scanner v%s\n" "${SCRIPT_VERSION}"
            exit 0
            ;;
        --help|-h)
            printf "Usage: %s [OPTIONS]\n\n" "${BIN_NAME}"
            printf "Interactive Mode:\n"
            printf "  %s                  Launch interactive numeric menu\n\n" "${BIN_NAME}"
            printf "Quick CLI Flags:\n"
            printf "  --quick [SNI]       Run quick auto scan with optional SNI domain\n"
            printf "  --update            Run live GitHub updater\n"
            printf "  --diagnostics       Run system & network check\n"
            printf "  --version, -v       Show script version\n"
            printf "  --help, -h          Show this help message\n"
            exit 0
            ;;
        --quick)
            check_dependencies || exit 1
            local sni="${2:-speed.cloudflare.com}"
            execute_scan_pipeline "${sni}" "/cdn-cgi/trace" "443" 250 3 24 20 "${GOLDEN_RANGES[@]}"
            exit 0
            ;;
        --update)
            update_script_live
            exit 0
            ;;
        --diagnostics)
            run_diagnostics
            exit 0
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Main Menu Loop
# ------------------------------------------------------------------------------
main_menu() {
    check_dependencies || exit 1
    ensure_cli_installed

    while true; do
        print_banner
        printf "\n"
        printf "  %b[1]%b Quick Auto Scan        %b(Recommended - Golden Ranges + Port 443)%b\n" "${C_GREEN}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[2]%b Custom Step-by-Step    %b(Select Ranges, Ports, Strictness & Depth)%b\n" "${C_CYAN}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[3]%b Test Specific IP/CIDR  %b(Verify Local Latency & Real TLS)%b\n" "${C_CYAN}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[4]%b System Diagnostics     %b(Check Dependencies, Local ISP & CLI Status)%b\n" "${C_CYAN}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[5]%b Update Script          %b(Live GitHub Update from 'main' or Custom Branch)%b\n" "${C_YELLOW}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[6]%b Uninstall ${BIN_NAME}   %b(Remove CLI command from system)%b\n" "${C_RED}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[0]%b Exit\n" "${C_WHITE}${C_BOLD}" "${C_RESET}"
        printf "%b\n" "${C_CYAN}${C_BOLD}==============================================================================${C_RESET}"

        local choice=""
        prompt_input "${C_WHITE}${C_BOLD}Select an option [0-6]: ${C_RESET}" choice ""

        case "${choice}" in
            1) menu_quick_scan ;;
            2) menu_custom_scan ;;
            3) menu_test_specific_ip ;;
            4) run_diagnostics ;;
            5) update_script_live ;;
            6) uninstall_cli ;;
            0|q|Q|exit)
                printf "\n%b[+] Thank you for using IPClean-Scanner. Goodbye!%b\n" "${C_GREEN}" "${C_RESET}"
                exit 0
                ;;
            *)
                printf "\n%b[!] Invalid option '%s'. Please enter a number between 0 and 6.%b\n" "${C_RED}" "${choice}" "${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

# Entrypoint
if [ "$#" -gt 0 ]; then
    handle_cli_flags "$@"
fi
main_menu
