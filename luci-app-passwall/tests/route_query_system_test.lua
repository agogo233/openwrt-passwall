local script_dir = string.match(arg and arg[0] or "", "^(.*[/\\])") or "."
local M = assert(dofile(script_dir .. "../luasrc/passwall/route_query_engine.lua"))

local fail = 0
local n = 0
local function check(name, cond)
  n = n + 1
  if cond then
    print("  ok " .. name)
  else
    fail = fail + 1
  end
end

local baseline = {
  use_block_list = "1", use_direct_list = "1", use_proxy_list = "1",
  use_gfw_list = "1", chn_list = "0", proxy_mode = "proxy",
  tcp_redir_ports = "1:65535",
}

local function merge(a, b)
  a = a or {}
  local out = {}
  for k, v in pairs(a) do out[k] = v end
  for k, v in pairs(b) do out[k] = v end
  return out
end

local function hit_of(...)
  local sets = {}
  for i = 1, select("#", ...) do
    sets[#sets + 1] = select(i, ...)
  end
  return function(base)
    for _, s in ipairs(sets) do
      if s == base then return true end
    end
    return false
  end
end

local function run(cfg, sets, target, port, proto)
  return M.decide_ip("nft", hit_of(unpack(sets)), target, port, proto, cfg)
end

print("[system] LAN early direct")
check("lan direct", run(baseline, {"psw_lan"}, "192.168.1.10", nil, "tcp").decision == "direct")

print("[system] VPS early direct")
check("vps direct", run(baseline, {"psw_vps"}, "93.184.216.34", nil, "tcp").decision == "direct")

print("[system] block wins over white")
local r = run(baseline, {"psw_block", "psw_white"}, "5.6.7.8", nil, "tcp")
check("block", r.decision == "block" and r.matched == "psw_block")

print("[system] white direct")
r = run(baseline, {"psw_white"}, "5.6.7.8", nil, "tcp")
check("white direct", r.decision == "direct" and r.matched == "psw_white")

print("[system] black proxy")
check("black proxy", run(baseline, {"psw_black"}, "5.6.7.8", nil, "tcp").decision == "proxy")

print("[system] gfw proxy")
check("gfw proxy", run(baseline, {"psw_gfw"}, "5.6.7.8", nil, "tcp").decision == "proxy")

print("[system] chn direct mode")
r = run(merge(baseline, {chn_list = "direct"}), {"psw_chn"}, "5.6.7.8", nil, "tcp")
check("chn direct -> direct", r.decision == "direct" and r.matched == "psw_chn")

print("[system] chn proxy mode")
r = run(merge(baseline, {chn_list = "proxy"}), {"psw_chn"}, "5.6.7.8", nil, "tcp")
check("chn proxy mode", r.decision == "proxy" and r.matched == "psw_chn")

print("[system] fakedns proxy")
r = run(merge(baseline, {use_fakedns = "1"}), {}, "198.18.0.1", nil, "tcp")
check("fakedns proxy", r.decision == "proxy" and r.note_key == "fakedns")

print("[system] default proxy")
r = run(baseline, {}, "1.1.1.1", nil, "tcp")
check("default proxy", r.decision == "proxy" and r.matched == "default")

print("[system] default direct when disabled")
r = run(merge(baseline, {proxy_mode = "disable"}), {}, "1.1.1.1", nil, "tcp")
check("disabled -> direct", r.decision == "direct" and r.matched == "default")

print("[system] default direct when port outside redir")
r = run(merge(baseline, {tcp_redir_ports = "443"}), {}, "1.1.1.1", "80", "tcp")
check("port outside redir -> direct", r.decision == "direct" and r.matched == "default")

print("[system] port_in")
check("port_in 443 in 443", M.port_in("443", "443"))
check("port_in 80 not in 443", not M.port_in("443", "80"))
check("port_in a-b", M.port_in("443:500", "444"))
check("port_in single", M.port_in("53", "53"))
check("port_in default empty", M.port_in("", "9999"))

print("[system] set_decision")
check("gfw", M.set_decision("psw_gfw", baseline).decision == "proxy")
check("block", M.set_decision("psw_block", baseline).decision == "block")
check("chn static", M.set_decision("psw_chn_static", baseline).decision == "direct")

print("[system] parse_mapping")
local raw = "nftset=/.google.com/4#inet#passwall#psw_gfw\n" ..
            "ipset=/.example.com/psw_white\n"
local list = M.parse_mapping(raw)
check("parse gfw mapping", list[1].domain == "google.com" and list[1].sets[1] == "psw_gfw")
check("parse white mapping", list[2].domain == "example.com" and list[2].sets[1] == "psw_white")

print("[system] domain_decision")
check("subdomain gfw", M.domain_decision("foo.google.com", list, baseline).matched == "psw_gfw")
check("exact white", M.domain_decision("example.com", list, baseline).matched == "psw_white")
check("no match", M.domain_decision("other.net", list, baseline) == nil)

print("[system] use_*_list = 0 (must be skipped, not truthy)")
r = run(merge(baseline, {use_block_list = "0", use_direct_list = "0", use_proxy_list = "0", use_gfw_list = "0"}),
        {"psw_block", "psw_white", "psw_black", "psw_gfw"}, "5.6.7.8", nil, "tcp")
check("all lists off -> default proxy", r.decision == "proxy" and r.matched == "default")

print("[system] fakedns /16 (not just /24)")
r = run(merge(baseline, {use_fakedns = "1"}), {}, "198.18.1.5", nil, "tcp")
check("fakedns 198.18.1.x -> proxy", r.decision == "proxy" and r.note_key == "fakedns")
r = run(merge(baseline, {use_fakedns = "1"}), {}, "198.18.255.9", nil, "tcp")
check("fakedns 198.18.255.x -> proxy", r.decision == "proxy" and r.note_key == "fakedns")

print("[system] udp port gating")
r = run(merge(baseline, {tcp_redir_ports = "443", udp_redir_ports = "5353"}), {}, "1.1.1.1", "53", "udp")
check("udp port 53 in udp_redir 5353? outside -> direct", r.decision == "direct")
r = run(merge(baseline, {tcp_redir_ports = "443", udp_redir_ports = "53"}), {}, "1.1.1.1", "53", "udp")
check("udp port 53 in udp_redir 53 -> proxy", r.decision == "proxy")
r = run(merge(baseline, {tcp_redir_ports = "53", udp_redir_ports = nil}), {}, "1.1.1.1", "53", "udp")
check("udp nil redir falls back to tcp ports", r.decision == "proxy")

print("[system] shunt node")
r = run(merge(baseline, {use_shunt_node = "1"}), {"psw_shunt"}, "5.6.7.8", nil, "tcp")
check("shunt proxy", r.decision == "proxy" and r.matched == "psw_shunt")
r = run(merge(baseline, {use_shunt_node = "0"}), {"psw_shunt"}, "5.6.7.8", nil, "tcp")
check("shunt off (0) -> not shunt", r.decision == "proxy" and r.matched == "default")

if fail == 0 then
  print("PASS system tests")
else
  print("FAILURES=" .. tostring(fail))
end
os.exit(fail == 0 and 0 or 1)
