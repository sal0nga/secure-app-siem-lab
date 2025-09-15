function safe(v)
  if v == nil or v == '' then return '-' end
  v = tostring(v):gsub('|','%7C'):gsub('\n',' '):gsub('\r',' ')
  return v
end

local function iso8601_from(ts, record_ts)
  if type(ts) == "table" and ts["sec"] then
    return os.date("!%Y-%m-%dT%H:%M:%SZ", ts["sec"])
  elseif type(ts) == "number" then
    return os.date("!%Y-%m-%dT%H:%M:%SZ", ts)
  elseif record_ts then
    return tostring(record_ts)
  else
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
  end
end

function make_leef(tag, ts, record)
  local sev      = record["sev"] or 5
  local usr      = record["user"] or record["usrName"] or "-"
  local src      = record["src_ip"] or record["src"] or "-"
  local path     = record["path"] or record["request"] or "-"
  local bytesOut = record["resp_bytes"] or record["bytesOut"] or "-"
  local outcome  = record["outcome"] or "-"

  local devTime  = iso8601_from(ts, record["ts"])

  local leef = string.format(
    "LEEF:1.0|%s|%s|%s|%s|cat=app|sev=%s|devTime=%s|usrName=%s|src=%s|request=%s|bytesOut=%s|outcome=%s",
    "ViLab", "WebApp", "1.0", "100",
    safe(sev), safe(devTime), safe(usr), safe(src), safe(path), safe(bytesOut), safe(outcome)
  )

  record["leef"] = leef
  return 1, ts, record
end