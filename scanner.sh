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
SCRIPT_VERSION="1.3.0"
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
    printf "%b\n" "${C_WHITE}${C_BOLD}          IPClean-Scanner | Cloudflare VLESS/XHTTP IP Scanner                 ${C_RESET}"
    printf "%b\n" "${C_CYAN}          Run on the target network: MCI | Irancell | Fixed Broadband            ${C_RESET}"
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
# Required command checks
# ------------------------------------------------------------------------------
check_dependencies() {
    local missing=()
    for cmd in curl awk sed grep sort head tr cut python3; do
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
# VLESS/XHTTP Quick Scan: parse a local share link and test through Xray Core
# ------------------------------------------------------------------------------
prompt_secret() {
    local prompt_text="$1"
    local var_name="$2"
    local value=""
    printf "%b" "${prompt_text}"
    if [ -r /dev/tty ]; then
        IFS= read -r -s value < /dev/tty || true
        printf "\n"
    else
        IFS= read -r value || true
    fi
    printf -v "${var_name}" "%s" "${value}"
}

find_xray_binary() {
    local candidate=""
    if [ -n "${XRAY_BIN:-}" ] && [ -x "${XRAY_BIN}" ]; then
        printf "%s" "${XRAY_BIN}"
        return 0
    fi
    candidate="$(command -v xray 2>/dev/null || true)"
    if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
        printf "%s" "${candidate}"
        return 0
    fi
    candidate="${HOME}/.local/share/cf-scanner/xray"
    if [ -x "${candidate}" ]; then
        printf "%s" "${candidate}"
        return 0
    fi
    return 1
}

install_xray_core() {
    local arch asset_name api_json asset_info asset_url asset_digest expected_sha actual_sha zip_file extract_dir xray_file install_dir
    case "$(uname -m 2>/dev/null)" in
        x86_64|amd64) asset_name="Xray-linux-64.zip" ;;
        aarch64|arm64) asset_name="Xray-linux-arm64-v8a.zip" ;;
        armv7l|armv7) asset_name="Xray-linux-arm32-v7a.zip" ;;
        *)
            printf "%b\n" "${C_RED}[-] Automatic Xray installation does not support this CPU architecture.${C_RESET}"
            return 1
            ;;
    esac

    if ! command -v python3 >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        printf "%b\n" "${C_RED}[-] Install python3 and unzip first, then run the scanner again.${C_RESET}"
        return 1
    fi

    api_json="${WORK_DIR}/xray_release.json"
    zip_file="${WORK_DIR}/${asset_name}"
    extract_dir="${WORK_DIR}/xray_extract"
    printf "%b\n" "${C_DIM}[*] Checking the latest official Xray Core release...${C_RESET}"
    if ! curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest" -o "${api_json}"; then
        printf "%b\n" "${C_RED}[-] Could not reach the official Xray Core release API.${C_RESET}"
        return 1
    fi

    asset_info="$(python3 - "${api_json}" "${asset_name}" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    asset = next(a for a in data.get("assets", []) if a.get("name") == sys.argv[2])
    print(asset["browser_download_url"] + "|" + (asset.get("digest") or ""))
except Exception:
    raise SystemExit(1)
PY
)" || true
    IFS='|' read -r asset_url asset_digest <<< "${asset_info}"
    if [ -z "${asset_url}" ] || [[ ! "${asset_digest}" =~ ^sha256:[A-Fa-f0-9]{64}$ ]]; then
        printf "%b\n" "${C_RED}[-] The official release asset or its SHA-256 digest is unavailable.${C_RESET}"
        return 1
    fi

    printf "%b\n" "${C_DIM}[*] Downloading Xray Core from the official XTLS/Xray-core GitHub release...${C_RESET}"
    if ! curl -fsSL --connect-timeout 10 --max-time 180 "${asset_url}" -o "${zip_file}"; then
        printf "%b\n" "${C_RED}[-] Xray Core download failed.${C_RESET}"
        return 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        printf "%b\n" "${C_RED}[-] sha256sum is required to verify the Xray Core download.${C_RESET}"
        return 1
    fi
    expected_sha="${asset_digest#sha256:}"
    actual_sha="$(sha256sum "${zip_file}" | awk '{print $1}')"
    if [ "${actual_sha}" != "${expected_sha}" ]; then
        printf "%b\n" "${C_RED}[-] Xray Core SHA-256 verification failed; the archive was rejected.${C_RESET}"
        return 1
    fi
    mkdir -p "${extract_dir}"
    if ! unzip -oq "${zip_file}" -d "${extract_dir}" >/dev/null 2>&1; then
        printf "%b\n" "${C_RED}[-] The downloaded Xray Core archive could not be extracted.${C_RESET}"
        return 1
    fi
    xray_file="$(find "${extract_dir}" -type f -name xray 2>/dev/null | head -n1)"
    if [ -z "${xray_file}" ]; then
        printf "%b\n" "${C_RED}[-] No Xray executable was found in the release archive.${C_RESET}"
        return 1
    fi

    install_dir="${HOME}/.local/share/cf-scanner"
    mkdir -p "${install_dir}" || return 1
    cp "${xray_file}" "${install_dir}/xray" || return 1
    chmod 700 "${install_dir}/xray" || return 1
    XRAY_BIN="${install_dir}/xray"
    printf "%b\n" "${C_GREEN}[+] Xray Core is ready at ${XRAY_BIN}.${C_RESET}"
}

ensure_xray_core() {
    XRAY_BIN="$(find_xray_binary 2>/dev/null || true)"
    if [ -n "${XRAY_BIN}" ]; then
        printf "%b\n" "${C_GREEN}[+] Using Xray Core: ${XRAY_BIN}${C_RESET}"
        return 0
    fi

    printf "\n%b\n" "${C_YELLOW}Xray Core was not found inside WSL.${C_RESET}"
    printf "  [1] Download and install the official Linux Xray Core in WSL\n"
    printf "  [2] Enter the path to an existing Linux Xray executable\n"
    printf "  [0] Cancel scan\n"
    local choice=""
    prompt_input "${C_WHITE}Select an option [0-2]: ${C_RESET}" choice "1"
    case "${choice}" in
        1) install_xray_core ;;
        2)
            prompt_input "${C_YELLOW}Enter the Linux Xray executable path: ${C_RESET}" XRAY_BIN ""
            if [ ! -x "${XRAY_BIN}" ]; then
                printf "%b\n" "${C_RED}[-] The selected path is not an executable Linux Xray Core.${C_RESET}"
                return 1
            fi
            ;;
        *) printf "%b\n" "${C_YELLOW}[i] Scan cancelled. No configuration was saved.${C_RESET}"; return 1 ;;
    esac
}

parse_vless_share_link() {
    local link_file="$1"
    local profile_file="$2"
    python3 - "${link_file}" "${profile_file}" <<'PY'
import json
import sys
from urllib.parse import parse_qs, unquote, urlsplit

source, output = sys.argv[1:3]
raw = open(source, encoding="utf-8").read().strip()
if "\n" in raw:
    raw = next((line.strip() for line in raw.splitlines() if line.strip().lower().startswith("vless://")), raw)
try:
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "vless":
        raise ValueError("The pasted value is not a vless:// share link.")
    query = parse_qs(parsed.query, keep_blank_values=True)
    def get(*names, default=""):
        for name in names:
            values = query.get(name)
            if values:
                return values[0]
        return default
    address = parsed.hostname
    port = parsed.port
    user_id = unquote(parsed.username or "")
    if not address or not port or not user_id:
        raise ValueError("The VLESS link is missing its address, port, or user ID.")
    if not (1 <= port <= 65535):
        raise ValueError("The VLESS port is outside the valid range.")

    network = get("type", "network", default="tcp").lower()
    security = get("security", default="none").lower()
    if network not in ("xhttp", "splithttp"):
        raise ValueError("This Quick Scan currently supports VLESS over XHTTP only.")
    if security != "tls":
        raise ValueError("This Quick Scan currently supports TLS security only (not REALITY or plain TCP).")
    sni = get("sni", "serverName", default=address)
    host = get("host", default="")
    path = get("path", default="/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    alpn = [item.strip() for item in get("alpn", default="h2,http/1.1").split(",") if item.strip()]
    extra_raw = get("extra", default="")
    extra = json.loads(extra_raw) if extra_raw else None
    if extra is not None and not isinstance(extra, dict):
        raise ValueError("The XHTTP extra field must be a JSON object.")

    profile = {
        "address": address,
        "port": port,
        "id": user_id,
        "encryption": get("encryption", default="none") or "none",
        "flow": get("flow", default=""),
        "network": "xhttp",
        "security": security,
        "sni": sni,
        "fingerprint": get("fp", "fingerprint", default=""),
        "alpn": alpn,
        "host": host,
        "path": path,
        "mode": get("mode", default="auto") or "auto",
        "extra": extra,
        "allow_insecure": get("allowInsecure", default="false").lower() == "true",
        "packet_encoding": get("packetEncoding", default="")
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(profile, f)
    print("PROFILE_OK")
except Exception as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
PY
}

print_profile_summary() {
    python3 - "$1" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
print("  Address in link : %s" % p["address"])
print("  Port            : %s" % p["port"])
print("  Transport       : VLESS / XHTTP (%s)" % p["mode"])
print("  Host            : %s" % (p["host"] or "(not set)"))
print("  Path            : %s" % p["path"])
print("  TLS SNI         : %s" % p["sni"])
print("  Fingerprint     : %s" % (p["fingerprint"] or "Xray default"))
print("  User ID         : hidden")
enc = p.get("encryption", "none") or "none"
if enc == "none":
    print("  VLESS Encryption: none")
else:
    parts = enc.split(".")
    print("  VLESS Encryption: %s (remaining parameters hidden)" % ".".join(parts[:3]))
PY
}

write_xray_probe_config() {
    local profile_file="$1"
    local candidate_ip="$2"
    local socks_port="$3"
    local config_file="$4"
    python3 - "${profile_file}" "${candidate_ip}" "${socks_port}" "${config_file}" <<'PY'
import json, sys
profile_path, ip, socks_port, output = sys.argv[1:5]
p = json.load(open(profile_path, encoding="utf-8"))
settings = {
    "address": ip,
    "port": int(p["port"]),
    "id": p["id"],
    "encryption": p["encryption"]
}
if p.get("flow"):
    settings["flow"] = p["flow"]
if p.get("packet_encoding"):
    settings["packetEncoding"] = p["packet_encoding"]
xhttp = {"path": p["path"], "mode": p["mode"]}
if p.get("host"):
    xhttp["host"] = p["host"]
if p.get("extra"):
    xhttp["extra"] = p["extra"]
tls = {"serverName": p["sni"], "allowInsecure": bool(p["allow_insecure"])}
if p.get("fingerprint"):
    tls["fingerprint"] = p["fingerprint"]
if p.get("alpn"):
    tls["alpn"] = p["alpn"]
config = {
        "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "127.0.0.1",
        "port": int(socks_port),
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
        "tag": "local-socks"
    }],
    "outbounds": [{
        "protocol": "vless",
        "settings": settings,
        "streamSettings": {
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": tls,
            "xhttpSettings": xhttp
        },
        "tag": "vless-xhttp"
    }],
    "routing": {"rules": []}
}
with open(output, "w", encoding="utf-8") as f:
    json.dump(config, f, separators=(",", ":"))
PY
}

check_tcp_candidates() {
    local input_file="$1"
    local target_port="$2"
    local output_file="$3"
    python3 - "${input_file}" "${target_port}" <<'PY' > "${output_file}"
import concurrent.futures, socket, sys, time
source, port = sys.argv[1], int(sys.argv[2])
ips = [line.strip() for line in open(source, encoding="utf-8") if line.strip()]
def check(ip):
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return (time.monotonic() - started) * 1000, ip
    except OSError:
        return None
with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
    results = [r for r in pool.map(check, ips) if r is not None]
for elapsed, ip in sorted(results):
    print("%.1f|%s" % (elapsed, ip))
PY
}

check_single_tcp() {
    python3 - "$1" "$2" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
started = time.monotonic()
try:
    with socket.create_connection((host, port), timeout=2.0):
        print("%.1f" % ((time.monotonic() - started) * 1000))
except OSError:
    sys.exit(1)
PY
}

resolve_ipv4_addresses() {
    python3 - "$1" <<'PY'
import socket, sys
host = sys.argv[1]
seen = set()
try:
    for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
        address = item[4][0]
        if address not in seen:
            seen.add(address)
            print(address)
except OSError:
    pass
PY
}

probe_candidate_with_xray() {
    local profile_file="$1"
    local candidate_ip="$2"
    local tcp_ms="$3"
    local index="$4"
    local result_file="$5"
    local socks_port=$((42000 + index))
    local probe_dir="${WORK_DIR}/xray_probe_${index}"
    local config_file="${probe_dir}/config.json"
    local xray_log="${probe_dir}/xray.log"
    local response_file="${probe_dir}/response.txt"
    local curl_error="${probe_dir}/curl.err"
    local xray_pid=""
    local core_alive=0
    local curl_stats=""
    local curl_exit=0

    mkdir -m 700 -p "${probe_dir}" || return 1
    write_xray_probe_config "${profile_file}" "${candidate_ip}" "${socks_port}" "${config_file}" || return 1

    "${XRAY_BIN}" run -c "${config_file}" > "${xray_log}" 2>&1 &
    xray_pid=$!
    sleep 0.25

    # Use a real HTTPS transaction through the VLESS/XHTTP tunnel, not a raw curl
    # request to the CDN endpoint. This exercises the exact profile parameters.
    local attempt
    for attempt in 1 2 3; do
        curl_exit=0
        curl_stats="$(curl -sS -L --socks5-hostname "127.0.0.1:${socks_port}" \
            --connect-timeout 3 --max-time 8 \
            -o "${response_file}" -w "%{http_code}|%{time_total}" \
            "https://www.cloudflare.com/cdn-cgi/trace" 2>"${curl_error}")" || curl_exit=$?
        if [ "${curl_exit}" -ne 7 ]; then
            break
        fi
        sleep 0.25
    done

    if kill -0 "${xray_pid}" 2>/dev/null; then
        core_alive=1
        kill "${xray_pid}" 2>/dev/null || true
    fi
    wait "${xray_pid}" 2>/dev/null || true

    local http_code="000" total_seconds="0" colo=""
    IFS='|' read -r http_code total_seconds <<< "${curl_stats}"
    if [ "${curl_exit}" -eq 0 ] && [ "${http_code}" = "200" ] && [ -s "${response_file}" ]; then
        colo="$(sed -n 's/^colo=\([A-Za-z0-9_-]*\).*/\1/p' "${response_file}" | head -n1 | tr -d '\r\n')"
        if [ -n "${colo}" ]; then
            local total_ms
            total_ms="$(awk -v t="${total_seconds}" 'BEGIN { printf "%d", int(t * 1000 + 0.5) }')"
            printf "PASS|%s|%s|%s|%s|%s\n" "${candidate_ip}" "${tcp_ms}" "${total_ms}" "${colo}" "${http_code}" > "${result_file}"
            rm -f "${config_file}" "${xray_log}" "${response_file}" "${curl_error}"
            return 0
        fi
    fi

    local reason="TUNNEL_OR_EGRESS_FAILED"
    if [ "${core_alive}" -eq 0 ] && [ -s "${xray_log}" ]; then
        reason="XRAY_EXITED"
    fi
    printf "%s|%s|%s|%s|%s|%s\n" "${reason}" "${candidate_ip}" "${tcp_ms}" "${http_code}" "${curl_exit}" "${index}" > "${result_file}.fail"
    rm -f "${config_file}" "${response_file}"
    return 1
}

menu_quick_scan() {
    print_banner
    printf "\n%b\n" "${C_GREEN}${C_BOLD}>>> Quick Auto Scan | Real VLESS/XHTTP Profile Test${C_RESET}"
    printf "%b\n" "This scan tests through your actual VLESS/XHTTP profile. Keep WSL connected to the operator you want to test."
    printf "%b\n" "The share link contains credentials. It is read without echo, stored only in a temporary RAM-backed workspace, and removed on exit."

    local share_link=""
    prompt_secret "\n${C_YELLOW}Paste the v2rayN VLESS share link (hidden input), then press Enter: ${C_RESET}" share_link
    if [ -z "${share_link}" ]; then
        printf "%b\n" "${C_RED}[-] No share link was entered.${C_RESET}"
        pause_enter
        return 1
    fi

    init_workdir
    umask 077
    local share_file="${WORK_DIR}/profile.link"
    local profile_file="${WORK_DIR}/profile.json"
    printf "%s\n" "${share_link}" > "${share_file}"
    share_link=""

    if ! parse_vless_share_link "${share_file}" "${profile_file}" >/dev/null; then
        printf "%b\n" "${C_RED}[-] Could not read this share link as a supported VLESS/XHTTP/TLS profile.${C_RESET}"
        printf "%b\n" "${C_YELLOW}[i] In v2rayN, use Copy Share Link for the selected server. Do not paste the link into chat.${C_RESET}"
        pause_enter
        return 1
    fi

    printf "\n%b\n" "${C_CYAN}${C_BOLD}Profile settings detected (credentials are hidden):${C_RESET}"
    print_profile_summary "${profile_file}"
    printf "\n%b\n" "${C_YELLOW}Make sure this WSL session is connected through the target ISP (for example, MCI).${C_RESET}"

    if ! ensure_xray_core; then
        pause_enter
        return 1
    fi

    local candidate_count=96
    local worker_count=8
    local profile_port
    profile_port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "${profile_file}")"

    printf "\n%b\n" "${C_CYAN}${C_BOLD}Scan plan: 96 sampled Cloudflare IPs plus cloudflare.com DNS answers, port ${profile_port}, up to ${worker_count} real Xray tunnel tests at once.${C_RESET}"
    printf "  %b[1]%b Start scan\n" "${C_GREEN}${C_BOLD}" "${C_RESET}"
    printf "  %b[0]%b Cancel\n" "${C_WHITE}${C_BOLD}" "${C_RESET}"
    local start_choice=""
    prompt_input "${C_WHITE}Select an option [0-1] [Default: 1]: ${C_RESET}" start_choice "1"
    if [ "${start_choice}" != "1" ]; then
        printf "%b\n" "${C_YELLOW}[i] Scan cancelled.${C_RESET}"
        pause_enter
        return 0
    fi

    local candidates_file="${WORK_DIR}/candidates.txt"
    local random_candidates_file="${WORK_DIR}/random_candidates.txt"
    local dns_candidates_file="${WORK_DIR}/cloudflare_dns_ips.txt"
    local tcp_open_file="${WORK_DIR}/tcp_open.txt"
    local results_dir="${WORK_DIR}/xray_results"
    mkdir -p "${results_dir}"

    print_stage_header 1 3 "Sampling Cloudflare IPv4 Candidates"
    resolve_ipv4_addresses "cloudflare.com" > "${dns_candidates_file}"
    generate_candidate_ips "${candidate_count}" "${GOLDEN_RANGES[@]}" "${OFFICIAL_RANGES[@]}" > "${random_candidates_file}"
    { cat "${dns_candidates_file}" "${random_candidates_file}"; } | awk 'NF && !seen[$0]++' > "${candidates_file}"
    local generated_count dns_ip_count
    generated_count="$(wc -l < "${candidates_file}" | tr -d ' ')"
    dns_ip_count="$(wc -l < "${dns_candidates_file}" | tr -d ' ')"
    printf "  %b[+] Generated %d candidates: 96 sampled Cloudflare IPs plus %d current cloudflare.com DNS IPv4 answers (deduplicated).%b\n" "${C_GREEN}" "${generated_count}" "${dns_ip_count}" "${C_RESET}"
    if [ "${dns_ip_count}" -gt 0 ]; then
        printf "  Current cloudflare.com DNS answers included: %s\n" "$(paste -sd ',' "${dns_candidates_file}" | sed 's/,/, /g')"
    else
        printf "%b\n" "${C_YELLOW}[i] Could not resolve cloudflare.com IPv4 answers in WSL; continuing with sampled candidates.${C_RESET}"
    fi

    print_stage_header 2 3 "Checking TCP Reachability on the Profile Port ${profile_port}"
    check_tcp_candidates "${candidates_file}" "${profile_port}" "${tcp_open_file}"
    local tcp_count
    tcp_count="$(wc -l < "${tcp_open_file}" | tr -d ' ')"
    if [ "${tcp_count}" -eq 0 ]; then
        printf "%b\n" "${C_RED}[-] No sampled candidate accepted a TCP connection on port ${profile_port} from this network.${C_RESET}"
        printf "%b\n" "${C_YELLOW}[i] Check the selected ISP, profile port, and local routing before scanning again.${C_RESET}"
        pause_enter
        return 1
    fi
    printf "  %b[+] %d / %d candidates accepted TCP connections on the exact profile port.%b\n" "${C_GREEN}" "${tcp_count}" "${generated_count}" "${C_RESET}"

    local validation_config="${WORK_DIR}/validation.json"
    local first_ip
    first_ip="$(head -n1 "${tcp_open_file}" | cut -d'|' -f2)"
    write_xray_probe_config "${profile_file}" "${first_ip}" 41999 "${validation_config}" || {
        printf "%b\n" "${C_RED}[-] Could not build the temporary Xray profile.${C_RESET}"
        pause_enter
        return 1
    }
    if ! "${XRAY_BIN}" run -test -c "${validation_config}" >/dev/null 2>"${WORK_DIR}/xray_validation.err"; then
        printf "%b\n" "${C_RED}[-] This Xray Core cannot parse the copied profile. Its version may be too old or the share link may use unsupported fields.${C_RESET}"
        printf "%b\n" "${C_YELLOW}[i] No candidate test was run; the copied profile was not changed.${C_RESET}"
        pause_enter
        return 1
    fi
    rm -f "${validation_config}" "${WORK_DIR}/xray_validation.err"

    local baseline_address baseline_tcp_ms baseline_result baseline_curl_error baseline_xray_error
    baseline_address="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "${profile_file}")"
    printf "\n%b\n" "${C_CYAN}${C_BOLD}Control test: original profile address ${baseline_address}:${profile_port}${C_RESET}"
    if baseline_tcp_ms="$(check_single_tcp "${baseline_address}" "${profile_port}")"; then
        baseline_result="${WORK_DIR}/baseline.result"
        if probe_candidate_with_xray "${profile_file}" "${baseline_address}" "${baseline_tcp_ms}" 0 "${baseline_result}"; then
            printf "%b\n" "${C_GREEN}[+] Original-address control PASSED: this Xray/profile setup completed HTTPS on the current network.${C_RESET}"
        else
            printf "%b\n" "${C_YELLOW}[i] Original-address control did not complete HTTPS on this network; candidate scan will continue.${C_RESET}"
            baseline_curl_error="$(head -n1 "${WORK_DIR}/xray_probe_0/curl.err" 2>/dev/null | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
            baseline_xray_error="$(grep -Ei 'error|failed|timeout|rejected|handshake' "${WORK_DIR}/xray_probe_0/xray.log" 2>/dev/null | tail -n1 | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
            local baseline_user_id
            baseline_user_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${profile_file}")"
            [ -n "${baseline_user_id}" ] && baseline_xray_error="${baseline_xray_error//${baseline_user_id}/[hidden]}"
            [ -n "${baseline_curl_error}" ] && printf "  curl: %s\n" "${baseline_curl_error}"
            [ -n "${baseline_xray_error}" ] && printf "  Xray: %s\n" "${baseline_xray_error}"
        fi
    else
        printf "%b\n" "${C_YELLOW}[i] Original-address control is TCP-unreachable from this network; candidate scan will continue.${C_RESET}"
    fi

    local domain_control_tcp_ms domain_control_curl_error domain_control_xray_error domain_control_user_id
    printf "\n%b\n" "${C_CYAN}${C_BOLD}DNS control: cloudflare.com:${profile_port} (profile Host/SNI remain unchanged)${C_RESET}"
    if domain_control_tcp_ms="$(check_single_tcp "cloudflare.com" "${profile_port}")"; then
        if probe_candidate_with_xray "${profile_file}" "cloudflare.com" "${domain_control_tcp_ms}" 999 "${WORK_DIR}/cloudflare_domain.result"; then
            printf "%b\n" "${C_GREEN}[+] cloudflare.com domain control PASSED on this network.${C_RESET}"
        else
            printf "%b\n" "${C_YELLOW}[i] cloudflare.com resolved and accepted TCP, but the profile tunnel did not complete.${C_RESET}"
            domain_control_curl_error="$(head -n1 "${WORK_DIR}/xray_probe_999/curl.err" 2>/dev/null | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
            domain_control_xray_error="$(grep -Ei 'error|failed|timeout|rejected|handshake' "${WORK_DIR}/xray_probe_999/xray.log" 2>/dev/null | tail -n1 | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
            domain_control_user_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${profile_file}")"
            [ -n "${domain_control_user_id}" ] && domain_control_xray_error="${domain_control_xray_error//${domain_control_user_id}/[hidden]}"
            [ -n "${domain_control_curl_error}" ] && printf "  curl: %s\n" "${domain_control_curl_error}"
            [ -n "${domain_control_xray_error}" ] && printf "  Xray: %s\n" "${domain_control_xray_error}"
        fi
    else
        printf "%b\n" "${C_YELLOW}[i] cloudflare.com is TCP-unreachable on the profile port from this WSL network.${C_RESET}"
    fi

    print_stage_header 3 3 "Testing the Real VLESS/XHTTP Tunnel and HTTPS Egress"
    local idx=0
    local active_jobs=0
    while IFS='|' read -r tcp_ms candidate_ip; do
        [ -z "${candidate_ip}" ] && continue
        idx=$((idx + 1))
        probe_candidate_with_xray "${profile_file}" "${candidate_ip}" "${tcp_ms}" "${idx}" "${results_dir}/${idx}.result" &
        active_jobs=$((active_jobs + 1))
        if [ "${active_jobs}" -ge "${worker_count}" ]; then
            wait_for_worker
            draw_progress "${idx}" "${tcp_count}" "Testing VLESS/XHTTP..."
        fi
    done < "${tcp_open_file}"
    wait
    draw_progress "${tcp_count}" "${tcp_count}" "VLESS/XHTTP tests complete."
    printf "\n"

    local results_file="${WORK_DIR}/xray_passed.txt"
    cat "${results_dir}"/*.result 2>/dev/null | sort -t'|' -k4,4n > "${results_file}" || true
    local passed_count
    passed_count="$(wc -l < "${results_file}" | tr -d ' ')"
    if [ "${passed_count}" -eq 0 ]; then
        local fail_file="${WORK_DIR}/xray_failures.txt"
        cat "${results_dir}"/*.fail > "${fail_file}" 2>/dev/null || true
        local xray_exit_count tunnel_fail_count
        xray_exit_count="$(awk -F'|' '$1 == "XRAY_EXITED" { n++ } END { print n + 0 }' "${fail_file}")"
        tunnel_fail_count="$(awk -F'|' '$1 == "TUNNEL_OR_EGRESS_FAILED" { n++ } END { print n + 0 }' "${fail_file}")"
        printf "%b\n" "${C_RED}[-] No sampled IP completed a real VLESS/XHTTP request through the selected profile.${C_RESET}"
        printf "  Xray process failures: %d | VLESS or HTTPS egress failures: %d\n" "${xray_exit_count}" "${tunnel_fail_count}"
        if [ -s "${fail_file}" ]; then
            printf "%b\n" "  Sample failures (IP | TCP ms | HTTP code | curl exit):"
            awk -F'|' 'shown < 3 { printf "    %s | %sms | %s | %s", $2, $3, $4, $5; print ""; shown++ }' "${fail_file}"
            local failure_type failure_ip failure_tcp failure_http failure_curl failure_index curl_detail xray_detail profile_user_id
            profile_user_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${profile_file}")"
            while IFS='|' read -r failure_type failure_ip failure_tcp failure_http failure_curl failure_index; do
                [ -z "${failure_ip}" ] && continue
                curl_detail="$(head -n1 "${WORK_DIR}/xray_probe_${failure_index}/curl.err" 2>/dev/null | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
                xray_detail="$(grep -Ei 'error|failed|timeout|rejected|handshake' "${WORK_DIR}/xray_probe_${failure_index}/xray.log" 2>/dev/null | tail -n1 | sed 's/[|]/ /g;s/[[:cntrl:]]/ /g' | cut -c1-180)"
                if [ -n "${profile_user_id}" ]; then
                    xray_detail="${xray_detail//${profile_user_id}/[hidden]}"
                fi
                [ -n "${curl_detail}" ] && printf "      %s curl: %s\n" "${failure_ip}" "${curl_detail}"
                [ -n "${xray_detail}" ] && printf "      %s Xray: %s\n" "${failure_ip}" "${xray_detail}"
            done < <(head -n 3 "${fail_file}")
        fi
        printf "%b\n" "${C_YELLOW}[i] No IP is being labeled clean. Compare this same scan on the operator where the profile is known to work; this separates a profile/core issue from MCI filtering.${C_RESET}"
        pause_enter
        return 1
    fi

    printf "\n%b\n" "${C_GREEN}${C_BOLD}REAL VLESS/XHTTP-VERIFIED IPs (current network):${C_RESET}"
    printf "%-4s | %-15s | %-5s | %-10s | %-10s | %-6s\n" "Rank" "Address" "Port" "TCP connect" "HTTPS test" "Colo"
    printf "%s\n" "-----+-----------------+-------+------------+------------+-------"
    local rank=0
    local result_tag result_ip result_tcp result_total result_colo result_http
    while IFS='|' read -r result_tag result_ip result_tcp result_total result_colo result_http; do
        [ -z "${result_ip}" ] && continue
        rank=$((rank + 1))
        printf "%-4d | %-15s | %-5s | %7sms   | %7sms   | %-6s\n" \
            "${rank}" "${result_ip}" "${profile_port}" "${result_tcp}" "${result_total}" "${result_colo}"
    done < "${results_file}"

    printf "\n%b\n" "${C_CYAN}${C_BOLD}>>> Copy these addresses into the v2rayN Address field; keep all other profile fields unchanged:${C_RESET}"
    while IFS='|' read -r result_tag result_ip result_tcp result_total result_colo result_http; do
        [ -z "${result_ip}" ] && continue
        printf "%s\n" "${result_ip}"
    done < "${results_file}"
    printf "\n%b\n" "${C_YELLOW}Note: ICMP ping is not used as the pass criterion. A result passes only after Xray completes the VLESS/XHTTP profile and an HTTPS request succeeds through it.${C_RESET}"
    pause_enter
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
            printf "  --quick             Run the interactive v2rayN VLESS/XHTTP scan\n"
            printf "  --update            Run live GitHub updater\n"
            printf "  --version, -v       Show script version\n"
            printf "  --help, -h          Show this help message\n"
            exit 0
            ;;
        --quick)
            check_dependencies || exit 1
            menu_quick_scan
            exit 0
            ;;
        --update)
            update_script_live
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
        printf "  %b[1]%b Quick Auto Scan        %b(Test using your v2rayN VLESS/XHTTP profile)%b\n" "${C_GREEN}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[2]%b Update Script          %b(Live GitHub Update from 'main' or a custom branch)%b\n" "${C_YELLOW}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[3]%b Uninstall ${BIN_NAME}   %b(Remove the installed command)%b\n" "${C_RED}${C_BOLD}" "${C_RESET}" "${C_DIM}" "${C_RESET}"
        printf "  %b[0]%b Exit\n" "${C_WHITE}${C_BOLD}" "${C_RESET}"
        printf "%b\n" "${C_CYAN}${C_BOLD}==============================================================================${C_RESET}"

        local choice=""
        prompt_input "${C_WHITE}${C_BOLD}Select an option [0-3]: ${C_RESET}" choice ""

        case "${choice}" in
            1) menu_quick_scan ;;
            2) update_script_live ;;
            3) uninstall_cli ;;
            0|q|Q|exit)
                printf "\n%b[+] Thank you for using IPClean-Scanner. Goodbye!%b\n" "${C_GREEN}" "${C_RESET}"
                exit 0
                ;;
            *)
                printf "\n%b[!] Invalid option '%s'. Please enter 0, 1, 2, or 3.%b\n" "${C_RED}" "${choice}" "${C_RESET}"
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
