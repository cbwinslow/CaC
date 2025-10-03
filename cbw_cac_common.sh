# Shared helpers for CBW-CAC
CBW_CAC_DATA_DIR="/var/lib/cbw-cac"
CBW_CAC_LOG_FILE="${CBW_CAC_DATA_DIR}/commands.jsonl"
CBW_CAC_FLOCK_FD=319

cbw_cac_redact() {
  local line="$*"
  line="${line//Authorization: Bearer [^ ]*/Authorization: Bearer ***REDACTED***}"
  line="${line//apikey=[^ &]*/apikey=***REDACTED***}"
  line="${line//api_key=[^ &]*/api_key=***REDACTED***}"
  line="${line//--password [^ ]*/--password ***REDACTED***}"
  line="${line//password=[^ &]*/password=***REDACTED***}"
  line="${line//--token [^ ]*/--token ***REDACTED***}"
  echo "$line"
}

cbw_cac_append_jsonl() {
  local status="$1" ts="$2" user="$3" shell="$4" cwd="$5" cmd="$6"
  [[ -e "${CBW_CAC_LOG_FILE}" ]] || return 0
  local escaped_cmd
  escaped_cmd=$(printf '%s' "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')
  local escaped_cwd
  escaped_cwd=$(printf '%s' "$cwd" | sed 's/\\/\\\\/g; s/"/\\"/g')
  local line
  line="{\"ts\":\"$ts\",\"user\":\"$user\",\"shell\":\"$shell\",\"cwd\":\"$escaped_cwd\",\"exit\":$status,\"cmd\":\"$escaped_cmd\"}"
  exec {CBW_CAC_FLOCK_FD}>>"${CBW_CAC_LOG_FILE}"
  flock -x "${CBW_CAC_FLOCK_FD}" bash -c "echo '$line' >> '${CBW_CAC_LOG_FILE}'"
  exec {CBW_CAC_FLOCK_FD}>&-
}
