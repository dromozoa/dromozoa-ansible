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
    local result = {
      line = line;
      mode = "append";
      chain = _1;
    }
    while i <= #line do
      local j = i
      local invert = false
      if scan "! " then
        invert = true
      end
      if scan "%-s (.-) " then
        result.source = {
          invert = invert;
          address = _1;
        }
      elseif scan "%-d (.-) " then
        result.destination = {
          invert = invert;
          address = _1;
        }
      elseif scan "%-i (.-) " then
        result.in_interface = {
          invert = invert;
          interface = _1;
        }
      elseif scan "%-o (.-) " then
        result.out_interface = {
          invert = invert;
          interface = _1;
        }
      elseif scan "%-p (.-) " then
        result.protocol = {
          invert = invert;
          protocol = _1;
        }
      else
        i = j
        break
      end
    end
    local rule = {}
    while i <= #line do
      if scan "([^%s]+) " then
        rule[#rule + 1] = _1
      end
    end
    for i = 1, #rule do
      local a, b, c, d = unpack(rule, i, i + 3)
      if a == "-j" then
        result.jump = b
      elseif a == "--reject-with" then
        result.reject_with = b
      elseif a == "-m" then
        if b == "state" and c == "--state" then
          result.match_state = {}
          for j in d:gmatch("[^,]+") do
            result.match_state[j] = true
          end
        elseif c == "--dport" then
          local min, max = d:match("^(%d+):(%d+)$")
          if min == nil then
            local min = d:match("^%d+$")
            if min == nil then
              error "could not parse"
            end
            max = min
          end
          result.match_dport = {
            name = b;
            min = tonumber(min);
            max = tonumber(max);
          }
        end
      end
    end
    if rule[1] == "-j" then
      result.jump_only = true
    end
    result.rule = rule
    return result
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
  local line = {}
  for i in io.lines() do
    line[#line + 1] = iptables_scan(i)
  end

  local result = {}
  for i = 1, #line do
    local v = line[i]
    if v.mode == "policy" then
      result[v.chain] = {
        policy = v.policy;
        append = {};
      }
    elseif v.mode == "append" then
      local append = result[v.chain].append
      append[#append + 1] = v
    end
  end
  return result
end

local function iptables_check_tcp_dport(data, dport)
end

local result = iptables_parse(io.stdin)
print(json.encode(result))

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
