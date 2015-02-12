local json = require "dromozoa.json"
local unpack = table.unpack

local function iptables_scan(line)
  local i = 1
  local _1
  local _2

  local function scan(pattern)
    local a, b, c, d = line:find("^" .. pattern, i)
    if b == nil then
      return false
    else
      i = b + 1
      _1 = c
      _2 = d
      return true
    end
  end

  if scan "#%s*(.*)" then
    return {
      line = line;
      mode = "comment";
      comment = _1;
    }
  elseif scan "%*([^%s]*)" then
    return {
      line = line;
      mode = "filter";
      filter = _1;
    }
  elseif scan "%:(.-) (.-) " then
    return {
      line = line;
      mode = "policy";
      chain = _1;
      policy = _2;
    }
  elseif scan "%-A (.-) " then
    local chain = _1
    local source
    local destination
    local in_interface
    local out_interface
    local protocol
    while i <= #line do
      local j = i
      local invert = false
      if scan "! " then
        invert = true
      end
      if scan "%-s (.-) " then
        source = { invert, _1 }
      elseif scan "%-d (.-) " then
        destination = { invert, _1 }
      elseif scan "%-i (.-) " then
        in_interface = { invert, _1 }
      elseif scan "%-o (.-) " then
        out_interface = { invert, _1 }
      elseif scan "%-p (.-) " then
        protocol = { invert, _1 }
      else
        i = j
        break
      end
    end
    local append = {}
    while i <= #line do
      if scan "([^%s]+) " then
        append[#append + 1] = _1
      end
    end
    return {
      line = line;
      mode = "append";
      chain = chain;
      source = source;
      destination = destination;
      in_interface = in_interface;
      out_interface = out_interface;
      protocol = protocol;
      append = append;
    }
  elseif scan "COMMIT" then
    return {
      line = line;
      mode = "commit";
    }
  else
    error "could not scan"
  end
end

local function iptables_parse(handle)
  local scanned = {}
  for i in io.lines() do
    scanned[#scanned + 1] = iptables_scan(i)
  end
  print(json.encode(scanned))

  local chain = {}
  for i = 1, #scanned do
    local v = scanned[i]
    if v.mode == "policy" then
      chain[v.chain] = {
        policy = v.policy;
        append = {};
      }
    elseif v.mode == "append" then
      local jump
      local reject_with
      local match
      local match_state_new
      local match_tcp_dport
      local match_udp_dport
      for j = 1, #v.append do
        local a, b, c, d = unpack(v.append, j, j + 3)
        if a == "-j" then
          jump = b
        elseif a == "--reject-with" then
          reject_with = b
        elseif a == "-m" then
          match = true
          if b == "state" and c == "--state" and d == "NEW" then
            match_state_new = true
          elseif c == "--dport" then
            local min, max = d:match("^(%d+):(%d+)$")
            if max == nil then
              max = d:match("^%d+$")
              if max == nil then
                error "could not parse"
              end
              min = max
            end
            local min = tonumber(min)
            local max = tonumber(max)
            if b == "tcp" then
              match_tcp_dport = { min, max }
            elseif b == "udp" then
              match_udp_dport = { min, max }
            end
          end
        end
      end
      local append = chain[v.chain].append
      append[#append + 1] = {
        jump = jump;
        match = match;
        match_state_new = match_state_new;
        match_tcp_dport = match_tcp_dport;
        match_udp_dport = match_udp_dport;
        reject_with = reject_with;
      }
    end
  end
  return chain
end

local result = iptables_parse(io.stdin)
-- print(json.encode(result))

--[[
local result = parse(io.stdin)
local function is_tcp_dport_accepted(chain, port)
  local append = result[chain].append
  for i = 1, #append do
    local v = append[i]
    print(json.encode(v))
    if v.match_tcp_dport then
      if v.match_tcp_dport[1] <= port and port <= v.match_tcp_dport[2] then
        return true
      end
    end
  end
  return false
end

print(is_tcp_dport_accepted("RH-Firewall-1-INPUT", tonumber(arg[1])))
]]
