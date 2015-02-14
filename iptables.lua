local json = require "dromozoa.json"
local unpack = table.unpack

local function iptables_parse_line(line)
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
        result.address_or_interface = true
        result.source = {
          invert = invert;
          address = _1;
        }
      elseif scan "%-d (.-) " then
        result.address_or_interface = true
        result.destination = {
          invert = invert;
          address = _1;
        }
      elseif scan "%-i (.-) " then
        result.address_or_interface = true
        result.in_interface = {
          invert = invert;
          interface = _1;
        }
      elseif scan "%-o (.-) " then
        result.address_or_interface = true
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
        result.match = true
        if b == "state" and c == "--state" then
          result.match_state = {}
          for j in d:gmatch("[^,]+") do
            result.match_state[j] = true
          end
        elseif c == "--dport" then
          local min, max = d:match("^(%d+):(%d+)$")
          if min == nil then
            min = d:match("^%d+$")
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
  local result = {}
  for i in handle:lines() do
    local v = iptables_parse_line(i)
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

local function iptables_evaluate(data, chain, protocol, port)
  local append = data[chain].append
  for i = 1, #append do
    local v = append[i]
    if v.address_or_interface == nil then
      local pass = false
      if v.protocol == nil then
        pass = true
      else
        pass = v.protocol.protocol == protocol
        if v.protocol.invert then
          pass = not pass
        end
      end
      if pass then
        local pass = false
        if v.match_dport ~= nil then
          pass = v.match_dport.name == protocol and v.match_dport.min <= port and port <= v.match_dport.max
        elseif not v.match then
          pass = true
        end
        if pass then
          if data[v.jump] == nil then
            return v.jump, chain, i
          else
            return iptables_evaluate(data, v.jump, protocol, port)
          end
        end
      end
    end
  end
  return data[chain].policy, chain, 0
end

-- local data = iptables_parse(io.stdin)
-- print(json.encode(data))
-- print(iptables_evaluate(data, arg[1], arg[2], tonumber(arg[3])))

local function services_parse(handle)
  local result = {}
  for i in handle:lines() do
    local line = i:gsub("#.*", "")
    local a, b, service, port, protocol = line:find("^([^%s]+)%s+(%d+)/([^%s]+)%s*")
    if b ~= nil then
      local port = tonumber(port)
      local name = { service }
      for j in line:sub(b + 1):gmatch("[^%s]+") do
        name[#name + 1] = j
      end
      for j = 1, #name do
        local a = name[j]
        if result[a] == nil then
          result[a] = {}
        end
        local b = result[a]
        b[#b + 1] = {
          port = port;
          protocol = protocol;
        }
      end
    end
  end
  return result
end

local data = services_parse(io.stdin)
-- print(json.encode(data))
print(json.encode(data[arg[1]]))

