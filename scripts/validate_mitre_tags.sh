#!/usr/bin/env bash
# Validate MITRE ATT&CK tag headers in AegisBPF example policies.
#
# Schema is documented in docs/rules/MITRE_ATTACK_TAG_SCHEMA.md.
#
# Rules enforced:
#   * Each file in examples/policies/*.conf MUST contain a tag block that
#     starts with `#@aegis-tags` and ends with `#@end-tags`.
#   * The tag block MUST appear within the first 40 lines and BEFORE any
#     INI section header (a line beginning with `[`).
#   * Required fields: id, version, mitre, platform.
#   * `id` must be kebab-case and unique across all scanned files.
#   * `version` must be a positive integer.
#   * `mitre` tokens match `^T[0-9]{4}(\.[0-9]{3})?$` or the literal `-`
#     (for rules that deliberately do not map to an ATT&CK technique).
#   * Optional `tactic` tokens match `^TA[0-9]{4}$`.
#   * Optional `severity` in {info, low, medium, high, critical}.
#   * Optional `maturity` in {experimental, beta, stable}.
#
# Exit codes:
#   0  all good
#   1  validation failure
#   2  usage / environment error
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_DIR="${POLICY_DIR:-${ROOT_DIR}/examples/policies}"
HEADER_WINDOW="${HEADER_WINDOW:-40}"

if [[ ! -d "${POLICY_DIR}" ]]; then
    echo "validate_mitre_tags: policy directory not found: ${POLICY_DIR}" >&2
    exit 2
fi

shopt -s nullglob
policies=("${POLICY_DIR}"/*.conf)
shopt -u nullglob

if [[ ${#policies[@]} -eq 0 ]]; then
    echo "validate_mitre_tags: no *.conf files under ${POLICY_DIR}" >&2
    exit 2
fi

errors=0
declare -A seen_ids=()

note_error() {
    local file="$1" msg="$2"
    printf '  [FAIL] %s: %s\n' "${file#${ROOT_DIR}/}" "${msg}" >&2
    errors=$((errors + 1))
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "${s}"
}

validate_file() {
    local file="$1"
    local rel="${file#${ROOT_DIR}/}"

    # Pass 1: locate the tag block and guardrails.
    local tag_start=0 tag_end=0 first_section=0
    local lineno=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        lineno=$((lineno + 1))
        if [[ ${first_section} -eq 0 && "${line}" =~ ^\[ ]]; then
            first_section=${lineno}
        fi
        if [[ ${tag_start} -eq 0 && "${line}" =~ ^#@aegis-tags[[:space:]]*$ ]]; then
            tag_start=${lineno}
            continue
        fi
        if [[ ${tag_start} -ne 0 && ${tag_end} -eq 0 && "${line}" =~ ^#@end-tags[[:space:]]*$ ]]; then
            tag_end=${lineno}
        fi
    done < "${file}"

    if [[ ${tag_start} -eq 0 ]]; then
        note_error "${rel}" "missing '#@aegis-tags' header block"
        return
    fi
    if [[ ${tag_end} -eq 0 ]]; then
        note_error "${rel}" "tag block started at line ${tag_start} but never closed with '#@end-tags'"
        return
    fi
    if [[ ${tag_start} -gt ${HEADER_WINDOW} ]]; then
        note_error "${rel}" "tag block starts at line ${tag_start}; must be within first ${HEADER_WINDOW} lines"
    fi
    if [[ ${first_section} -ne 0 && ${tag_start} -gt ${first_section} ]]; then
        note_error "${rel}" "tag block (line ${tag_start}) appears after first INI section (line ${first_section})"
    fi

    # Pass 2: parse fields inside the block.
    local id="" version="" mitre="" platform="" tactic="" severity="" maturity=""
    lineno=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        lineno=$((lineno + 1))
        if (( lineno <= tag_start || lineno >= tag_end )); then
            continue
        fi
        # Skip blank comment lines inside the block.
        if [[ "${line}" =~ ^#@end-tags ]]; then
            continue
        fi
        if [[ ! "${line}" =~ ^#@ ]]; then
            note_error "${rel}:${lineno}" "non-'#@' line inside tag block: ${line}"
            continue
        fi
        # Strip '#@' prefix and split on first ':'.
        local body="${line#\#@}"
        if [[ "${body}" != *:* ]]; then
            note_error "${rel}:${lineno}" "missing ':' in tag line: ${line}"
            continue
        fi
        local key="${body%%:*}"
        local value="${body#*:}"
        key="$(trim "${key,,}")"
        value="$(trim "${value}")"
        case "${key}" in
            id)         id="${value}" ;;
            version)    version="${value}" ;;
            mitre)      mitre="${value}" ;;
            platform)   platform="${value}" ;;
            tactic)     tactic="${value}" ;;
            severity)   severity="${value}" ;;
            maturity)   maturity="${value}" ;;
            compliance|reference|author)
                : # free-form / validated downstream
                ;;
            *)
                note_error "${rel}:${lineno}" "unknown tag field '${key}'"
                ;;
        esac
    done < "${file}"

    # Required fields
    [[ -z "${id}" ]]       && note_error "${rel}" "required field '#@id' missing"
    [[ -z "${version}" ]]  && note_error "${rel}" "required field '#@version' missing"
    [[ -z "${mitre}" ]]    && note_error "${rel}" "required field '#@mitre' missing"
    [[ -z "${platform}" ]] && note_error "${rel}" "required field '#@platform' missing"

    # id: kebab-case + uniqueness
    if [[ -n "${id}" ]]; then
        if [[ ! "${id}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
            note_error "${rel}" "id '${id}' is not kebab-case (expected ^[a-z0-9]+(-[a-z0-9]+)*$)"
        fi
        if [[ -n "${seen_ids[${id}]:-}" ]]; then
            note_error "${rel}" "id '${id}' already used by ${seen_ids[${id}]}"
        else
            seen_ids[${id}]="${rel}"
        fi
    fi

    # version: positive integer
    if [[ -n "${version}" && ! "${version}" =~ ^[1-9][0-9]*$ ]]; then
        note_error "${rel}" "version '${version}' is not a positive integer"
    fi

    # mitre tokens
    if [[ -n "${mitre}" ]]; then
        local tok
        IFS=',' read -ra toks <<< "${mitre}"
        for tok in "${toks[@]}"; do
            tok="$(trim "${tok}")"
            if [[ -z "${tok}" ]]; then continue; fi
            if [[ "${tok}" == "-" ]]; then continue; fi
            if [[ ! "${tok}" =~ ^T[0-9]{4}(\.[0-9]{3})?$ ]]; then
                note_error "${rel}" "invalid MITRE technique '${tok}' (expected T#### or T####.### or '-')"
            fi
        done
    fi

    # tactic tokens (optional)
    if [[ -n "${tactic}" ]]; then
        IFS=',' read -ra toks <<< "${tactic}"
        for tok in "${toks[@]}"; do
            tok="$(trim "${tok}")"
            if [[ -z "${tok}" ]]; then continue; fi
            if [[ ! "${tok}" =~ ^TA[0-9]{4}$ ]]; then
                note_error "${rel}" "invalid MITRE tactic '${tok}' (expected TA####)"
            fi
        done
    fi

    # severity (optional)
    if [[ -n "${severity}" ]]; then
        case "${severity}" in
            info|low|medium|high|critical) ;;
            *) note_error "${rel}" "invalid severity '${severity}' (expected info|low|medium|high|critical)" ;;
        esac
    fi

    # maturity (optional)
    if [[ -n "${maturity}" ]]; then
        case "${maturity}" in
            experimental|beta|stable) ;;
            *) note_error "${rel}" "invalid maturity '${maturity}' (expected experimental|beta|stable)" ;;
        esac
    fi
}

echo "validate_mitre_tags: scanning ${#policies[@]} policy file(s) under ${POLICY_DIR#${ROOT_DIR}/}"
for f in "${policies[@]}"; do
    validate_file "${f}"
done

if [[ ${errors} -gt 0 ]]; then
    echo "validate_mitre_tags: FAILED with ${errors} error(s)" >&2
    exit 1
fi

echo "validate_mitre_tags: OK (${#policies[@]} file(s), ${#seen_ids[@]} unique ids)"
