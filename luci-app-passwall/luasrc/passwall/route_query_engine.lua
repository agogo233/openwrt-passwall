local M = {}

function M.is_ipv4(s)
  if type(s) ~= "string" then return false end
  if s:find(":") then return false end
  local parts = {}
  for p in string.gmatch(s, "[^.]+") do
    table.insert(parts, p)
  end
  if #parts ~= 4 then return false end
  for _, p in ipairs(parts) do
    if not string.match(p, "^%d+$") then return false end
    local v = tonumber(p)
    if not v or v < 0 or v > 255 then return false end
  end
  return true
end

function M.is_ipv6(s)
  return type(s) == "string" and s:find(":") ~= nil
end

function M.family(s)
  if M.is_ipv6(s) then return "ipv6" end
  if M.is_ipv4(s) then return "ipv4" end
  return ""
end

function M.port_in(range, port)
  if not port then return true end
  local p = tonumber(port)
  if not p then return false end
  if not range or range == "" or range == "default" then return true end
  if range == "1:65535" or range == "1-65535" then return true end
  for tok in string.gmatch(range, "[^,]+") do
    tok = string.gsub(tok, "%s", "")
    local lo, hi = string.match(tok, "^(%d+)[%:%-](%d+)$")
    if lo then
      if p >= tonumber(lo) and p <= tonumber(hi) then return true end
    elseif string.match(tok, "^%d+$") then
      if p == tonumber(tok) then return true end
    end
  end
  return false
end

function M.make_hit(backend, env)
  local probe = env._probe
  if not probe then
    probe = function(cmd) return env.sys.call(cmd) end
  end
  return function(set_base, target)
    local is6 = M.family(target) == "ipv6"
    local vname = is6 and set_base .. "6" or set_base
    local sv = is6 and set_base .. "6_static" or set_base .. "_static"
    if backend == "nft" then
      if probe("nft get element inet passwall " .. vname .. " { " .. target .. " }") == 0 then return true end
      if probe("nft get element inet passwall " .. sv .. " { " .. target .. " }") == 0 then return true end
    else
      if probe("ipset -q test " .. vname .. " " .. target) == 0 then return true end
      if probe("ipset -q test " .. sv .. " " .. target) == 0 then return true end
    end
    return false
  end
end

function M.decide_ip(backend, hit, target, port, proto, cfg)
  cfg = cfg or {}
  local is6 = M.family(target) == "ipv6"
  local hitf = function(base)
    return hit(base, target)
  end
  if hitf("psw_lan") then
    return { decision = "direct", matched = "psw_lan", note_key = "lan" }
  end
  if hitf("psw_vps") then
    return { decision = "direct", matched = "psw_vps", note_key = "vps" }
  end
  local noredir = cfg.tcp_no_redir_ports
  if proto == "udp" and cfg.udp_no_redir_ports ~= nil and cfg.udp_no_redir_ports ~= "" then
    noredir = cfg.udp_no_redir_ports
  end
  if noredir and noredir ~= "" and noredir ~= "default"
       and port and port ~= "" and M.port_in(noredir, port) then
    return { decision = "direct", matched = "no_redir", note_key = "no_redir" }
  end
  local use_fakedns = cfg.use_fakedns == "1" or cfg.use_fakedns == true
  if use_fakedns and target:match("^198%.18%.") then
    return { decision = "proxy", matched = "198.18.0.0/16", note_key = "fakedns" }
  end
  if cfg.use_block_list == "1" or cfg.use_block_list == true then
    if hitf("psw_block") then
      return { decision = "block", matched = "psw_block", note_key = "block" }
    end
  end
  if cfg.use_direct_list == "1" or cfg.use_direct_list == true then
    if hitf("psw_white") then
      return { decision = "direct", matched = "psw_white", note_key = "white" }
    end
  end
  if cfg.use_proxy_list == "1" or cfg.use_proxy_list == true then
    if hitf("psw_black") then
      return { decision = "proxy", matched = "psw_black", note_key = "black" }
    end
  end
  if cfg.use_gfw_list == "1" or cfg.use_gfw_list == true then
    if hitf("psw_gfw") then
      return { decision = "proxy", matched = "psw_gfw", note_key = "gfw" }
    end
  end
  local chn = cfg.chn_list
  if chn and chn ~= "0" and hitf("psw_chn") then
    if chn == "proxy" then
      return { decision = "proxy", matched = "psw_chn", note_key = "chn_proxy" }
    end
    return { decision = "direct", matched = "psw_chn", note_key = "chn_direct" }
  end
  if (cfg.use_shunt_node == "1" or cfg.use_shunt_node == true) and hitf("psw_shunt") then
    return { decision = "proxy", matched = "psw_shunt", note_key = "shunt" }
  end
  local redir = cfg.tcp_redir_ports
  if proto == "udp" and cfg.udp_redir_ports ~= nil and cfg.udp_redir_ports ~= "" then
    redir = cfg.udp_redir_ports
  end
  local proxied = false
  if cfg.proxy_mode and cfg.proxy_mode ~= "disable" then
    if not port or port == "" then
      proxied = true
    else
      proxied = M.port_in(redir, port)
    end
  end
  if proxied then
    return { decision = "proxy", matched = "default", note_key = "default_proxy" }
  end
  return { decision = "direct", matched = "default", note_key = "default_direct" }
end

function M.set_decision(setname, cfg)
  local base = string.gsub(setname, "_static$", "")
  base = string.gsub(base, "%d+$", "")
  base = string.gsub(base, "^psw_", "")
  if base == "block" then return { decision = "block", note_key = "block" } end
  if base == "white" then return { decision = "direct", note_key = "white" } end
  if base == "black" then return { decision = "proxy", note_key = "black" } end
  if base == "gfw" then return { decision = "proxy", note_key = "gfw" } end
  if base == "shunt" then return { decision = "proxy", note_key = "shunt" } end
  if base == "chn" then
    if cfg and cfg.chn_list == "proxy" then
      return { decision = "proxy", note_key = "chn_proxy" }
    end
    return { decision = "direct", note_key = "chn_direct" }
  end
  return nil
end

function M.parse_mapping(raw)
  local list = {}
  if not raw then return list end
  for line in string.gmatch(raw, "([^\n]+)") do
    line = string.gsub(line, "\r", "")
    line = string.gsub(line, "^%s+", "")
    if line:find("=") then
      local dom = string.match(line, "=/%.%s*([^/]+)/")
      if not dom then dom = string.match(line, "=/%.%s*([^/]+)$") end
      if dom then
        dom = string.gsub(dom, "^%.+", "")
        local sets = {}
        for s in string.gmatch(line, "psw_%a[%a%d_]*") do
          table.insert(sets, s)
        end
        table.insert(list, { domain = dom, sets = sets })
      end
    end
  end
  return list
end

function M.domain_decision(domain, mappings, cfg)
  for _, e in ipairs(mappings) do
    if domain == e.domain
        or string.sub(domain, -(string.len(e.domain) + 1)) == "." .. e.domain then
      for _, setname in ipairs(e.sets) do
        local d = M.set_decision(setname, cfg)
        if d then
          return { decision = d.decision, matched = setname, note_key = d.note_key, source = "mapping" }
        end
      end
    end
  end
  return nil
end

function M.note_msgid(k)
  local map = {
    lan = "LAN local direct",
    vps = "VPS node direct",
    no_redir = "No-proxy port, direct",
    fakedns = "FakeDNS range, goes proxy",
    block = "Block list hit",
    white = "Direct list hit",
    black = "Proxy list hit",
    gfw = "GFW list hit",
    chn_proxy = "China list hit (proxy mode)",
    chn_direct = "China list hit (direct mode)",
    shunt = "Shunt node hit",
    default_proxy = "Default port goes proxy",
    default_direct = "Not matched any list, goes direct",
    no_rule = "No domain rule matched, judged by resolved IP",
    resolve_fail = "Domain resolution failed",
    client_cfg_notfound = "Proxy client running config (global.json) not found",
    client_predicted = "Estimated from configured route (reference only)",
    client_fallback = "No rule matched, uses fallback exit",
    acl_global = "Previewed with global config (device ACL rules not applied)",
  }
  return map[k] or k
end

function M.detect_backend(env)
  local exec = function(s) return env.sys.exec(s) end
  local fw4 = exec("command -v fw4 2>/dev/null"):gsub("%s+", "")
  if fw4 ~= "" then return "nft" end
  local dns_nft = exec("dnsmasq -v 2>/dev/null | grep -qw nftset && echo 1 || echo 0"):gsub("%s+", "") == "1"
  local dns_ipset = exec("dnsmasq -v 2>/dev/null | grep -qw ipset && echo 1 || echo 0"):gsub("%s+", "") == "1"
  local has_ipset = exec("command -v ipset 2>/dev/null"):gsub("%s+", "") ~= ""
  if dns_nft then return "nft" end
  if dns_ipset and has_ipset then return "ipset" end
  return "ipset"
end

function M.read_global_json(env)
  local path = env.global_path
  if not path then
    path = string.format("/tmp/etc/%s/acl/default/global.json", env.appname or "passwall")
  end
  return env.readfile(path)
end

function M.client_decide(env, target)
  local tr = env.tr or function(s) return s end
  local c = {
    available = false, core = "", rules_count = 0, rule = nil, outbound = nil,
    final = false, note_key = "client_cfg_notfound", note = "",
  }
  local raw = M.read_global_json(env)
  if not raw or raw == "" then
    c.note = tr(M.note_msgid(c.note_key))
    return c
  end
  if not env.jsonc_parse then
    c.note = tr(M.note_msgid(c.note_key))
    return c
  end
  local json = env.jsonc_parse(raw)
  if type(json) ~= "table" then
    c.note = tr(M.note_msgid(c.note_key))
    return c
  end
  if json.route and json.route.rules then
    c.core = "sing-box"
  elseif json.routing and json.routing.rules then
    c.core = "xray"
  end
  local rules
  if c.core == "sing-box" then
    rules = json.route and json.route.rules
  else
    rules = json.routing and json.routing.rules
  end
  if type(rules) ~= "table" then rules = {} end
  c.rules_count = #rules

  local default_out, final_out
  if c.core == "sing-box" then
    default_out = json.route and json.route.default_outbound
    final_out = json.route and json.route.final
  else
    default_out = json.routing and json.routing.default_outbound
    final_out = json.routing and json.routing.final
  end
  local predicted = nil
  local matched_rule = nil
  for _, r in ipairs(rules) do
    if r.domain then
      for _, d in ipairs(r.domain) do
        if d and not d:find("geosite") then
          local dom = string.gsub(d, "^%-?", "")
          dom = string.gsub(dom, "^%.", "")
          if target == dom or string.sub(target, -(string.len(dom) + 1)) == "." .. dom then
            if r.outbound and type(r.outbound) == "string" and string.len(r.outbound) > 0 then
              predicted = r.outbound
              matched_rule = r
            end
            break
          end
        end
      end
      if predicted then break end
    end
  end
  local out = predicted
  local fallback = false
  if not out then
    out = default_out
    if type(out) ~= "string" then out = final_out end
    fallback = true
  end
  c.outbound = out
  c.rule = matched_rule and (matched_rule["rule_no"] or matched_rule.id) or nil
  c.final = fallback
  c.note_key = fallback and "client_fallback" or "client_predicted"
  c.note = tr(M.note_msgid(c.note_key)) .. " (" .. tostring(out) .. ")"
  c.available = true
  return c
end

function M.query(opts, env)
  opts = opts or {}
  env = env or {}
  local tr = env.tr or function(s) return s end
  local target = opts.target or ""
  target = string.gsub(target, "^%s+", "")
  target = string.gsub(target, "%s+$", "")
  if target == "" then
    return { code = 0, message = tr("Please enter query content!") }
  end
  local port = opts.port or ""
  port = string.gsub(port, "^%s+", "")
  port = string.gsub(port, "%s+$", "")
  local proto = opts.proto or "tcp"
  local src = opts.src or ""
  src = string.gsub(src, "^%s+", "")
  src = string.gsub(src, "%s+$", "")

  local cfg = env.cfg or {}
  local family = M.family(target)
  local is_domain = family == ""

  local backend = env.backend
  if not backend then backend = M.detect_backend(env) end

  local resp = {
    code = 1, target = target,
    type = is_domain and "domain" or "ip",
    family = is_domain and "" or family,
    port = port == "" and nil or port,
    proto = proto,
  }
  local hit = M.make_hit(backend, env)
  local sys = { backend = backend }

  if is_domain then
    local mappings = M.parse_mapping(env.dns_mapping_raw or "")
    local dd = M.domain_decision(target, mappings, cfg)
    if dd then
      sys.decision = dd.decision
      sys.matched = dd.matched
      sys.note = tr(M.note_msgid(dd.note_key))
    else
      local ips = nil
      if env.resolve_domain then ips = env.resolve_domain(target) end
      if ips and #ips > 0 then
        local resolved = {}
        local first = nil
        local amb = false
        for _, ip in ipairs(ips) do
          local r = M.decide_ip(backend, hit, ip, port, proto, cfg)
          table.insert(resolved, { ip = ip, decision = r.decision, matched = r.matched, note_key = r.note_key })
          if first == nil then
            first = r
          elseif first.decision ~= r.decision then
            amb = true
          end
        end
        sys.resolved = resolved
        sys.dns_note = tr("DNS")
        if first and not amb then
          sys.decision = first.decision
          sys.matched = first.matched
          sys.note = tr(M.note_msgid("no_rule"))
        else
          sys.decision = "unknown"
          sys.note = tr(M.note_msgid("no_rule"))
        end
      else
        sys.note = tr(M.note_msgid("resolve_fail"))
      end
    end
  else
    local r = M.decide_ip(backend, hit, target, port, proto, cfg)
    sys.decision = r.decision
    sys.matched = r.matched
    sys.note = tr(M.note_msgid(r.note_key))
  end

  resp.system = sys
  resp.client = M.client_decide(env, target)
  if src ~= "" then
    resp.acl = {
      matched = true, name = "global", use_global_config = true,
      system = sys, client = resp.client,
      note = tr(M.note_msgid("acl_global")),
    }
  end
  return resp
end

return M
