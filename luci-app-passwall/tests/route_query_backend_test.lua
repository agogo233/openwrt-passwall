local here = (arg[0]:match("^(.*)[/\\]") or ".") .. "/../luasrc/passwall/"
package.path = here .. "?.lua;" .. package.path
local M = require "route_query_engine"

local pass, fail = 0, 0
local function chk(n, g, w) if g == w then pass = pass + 1 else fail = fail + 1; print("FAIL "..n..": "..tostring(g).." != "..tostring(w)) end end

-- fw4 present -> nft
local env1 = { sys = { exec = function() return "/usr/sbin/fw4" end } }
chk("fw4->nft", M.detect_backend(env1), "nft")

-- no fw4, dnsmasq reports nftset -> nft
local env2 = { sys = { exec = function(c)
  if c:find("fw4") then return "" end
  if c:find("nftset") then return "1" end
  if c:find("ipset") and c:find("dnsmasq") then return "0" end
  return ""
 end } }
chk("dnsmasq nftset->nft", M.detect_backend(env2), "nft")

-- no fw4, dnsmasq reports ipset, ipset binary present -> ipset
local env3 = { sys = { exec = function(c)
  if c:find("fw4") then return "" end
  if c:find("nftset") then return "0" end
  if c:find("dnsmasq") and c:find("ipset") then return "1" end
  if c:find("command -v ipset") then return "/usr/sbin/ipset" end
  return ""
 end } }
chk("dnsmasq ipset->ipset", M.detect_backend(env3), "ipset")

print(string.format("backend-test: %d passed, %d failed", pass, fail))
return { pass = pass, fail = fail }
