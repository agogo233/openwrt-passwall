local here = (arg[0]:match("^(.*)[/\\]") or ".") .. "/../luasrc/passwall/"
package.path = here .. "?.lua;" .. package.path
local M = require "route_query_engine"

local pass, fail = 0, 0
local function chk(n, g, w) if g == w then pass = pass + 1 else fail = fail + 1; print("FAIL "..n..": "..tostring(g).." != "..tostring(w)) end end

local cfg = {
	use_block_list = "1", use_direct_list = "1", use_proxy_list = "1",
	use_gfw_list = "1", chn_list = "0", proxy_mode = "proxy",
	tcp_redir_ports = "1:65535",
}

local function make_env(hit_sets, mapping_raw, resolve_ips, json_tbl)
	local probe = function(cmd)
		for _, s in ipairs(hit_sets or {}) do
			if cmd:find(s) then return 0 end
		end
		return 1
	end
	return {
		backend = "nft",
		tr = function(s) return s end,
		_probe = probe,
		cfg = cfg,
		dns_mapping_raw = mapping_raw or "",
		resolve_domain = function(d) return resolve_ips or nil end,
		readfile = function(p) return json_tbl and '{}' or nil end,
		jsonc_parse = function(raw) return json_tbl end,
		appname = "passwall",
	}
end

-- IP in gfw set -> proxy
local env1 = make_env({"psw_gfw"})
local r1 = M.query({ target = "1.2.3.4", port = "", proto = "tcp" }, env1)
chk("ip gfw proxy", r1.system.decision, "proxy")
chk("ip gfw matched", r1.system.matched, "psw_gfw")
chk("ip type", r1.type, "ip")
chk("ip family", r1.family, "ipv4")

-- IP in block set -> block
local env2 = make_env({"psw_block"})
local r2 = M.query({ target = "5.6.7.8", port = "", proto = "tcp" }, env2)
chk("ip block", r2.system.decision, "block")

-- Domain in mapping -> proxy
local env3 = make_env({}, "nftset=/.google.com/4#inet#passwall#psw_gfw\n")
local r3 = M.query({ target = "www.google.com", port = "", proto = "tcp" }, env3)
chk("domain mapping proxy", r3.system.decision, "proxy")
chk("domain mapping matched", r3.system.matched, "psw_gfw")
chk("domain type", r3.type, "domain")

-- Domain not in mapping -> resolve to IP in gfw -> proxy
local env4 = make_env({"psw_gfw"}, "", { "1.2.3.4" })
local r4 = M.query({ target = "unknown.example", port = "", proto = "tcp" }, env4)
chk("domain resolve proxy", r4.system.decision, "proxy")
chk("domain resolve resolved", r4.system.resolved and #r4.system.resolved == 1, true)

-- Domain resolve fails -> no verdict
local env5 = make_env({}, "", nil)
local r5 = M.query({ target = "unknown.example", port = "", proto = "tcp" }, env5)
chk("domain resolve fail note", r5.system.note ~= nil, true)

-- Empty target -> code 0
local r6 = M.query({ target = "", port = "", proto = "tcp" }, env1)
chk("empty target code", r6.code, 0)

-- Client global.json present -> available
local json_sb = { route = { rules = {}, default_outbound = "0.direct", final = "direct" } }
local env7 = make_env({}, "", nil, json_sb)
local r7 = M.query({ target = "1.2.3.4", port = "", proto = "tcp" }, env7)
chk("client available", r7.client.available, true)
chk("client core", r7.client.core, "sing-box")

-- Client global.json absent -> not available
local env8 = make_env({}, "", nil, nil)
local r8 = M.query({ target = "1.2.3.4", port = "", proto = "tcp" }, env8)
chk("client not available", r8.client.available, false)

-- ACL with src -> acl block present
local r9 = M.query({ target = "1.2.3.4", port = "", proto = "tcp", src = "192.168.1.5" }, env1)
chk("acl present", r9.acl ~= nil, true)
chk("acl matched", r9.acl.matched, true)

print(string.format("flow-test: %d passed, %d failed", pass, fail))
return { pass = pass, fail = fail }
