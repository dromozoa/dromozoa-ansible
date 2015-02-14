local json = require "dromozoa.json"
local shlex = require "dromozoa.shlex"

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
      address_or_interface = false;
      match = false;
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

    local args = {}
    for j in line:sub(i):gmatch("[^%s]+") do
      args[#args + 1] = j
    end
    result.match = false
    for j = 1, #args do
      local a, b, c, d = args[j], args[j + 1], args[j + 2], args[j + 3]
      if a == "-j" then
        result.jump = b
      elseif a == "--reject-with" then
        result.reject_with = b
      elseif a == "-m" then
        result.match = true
        if b == "state" and c == "--state" then
          result.match_state = d
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
    result.args = args
    return result
  elseif scan "COMMIT" then
    return {
      line = line;
      mode = "commit";
    }
  else
    error "could not parse"
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
      local t = result[v.chain].append
      t[#t + 1] = v
    end
  end
  return result
end

local function iptables_evaluate(data, chain, protocol, port)
  local t = data[chain].append
  for i = 1, #t do
    local v = t[i]
    if not v.address_or_interface then
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

local function services_parse(handle)
  local result = {}
  for i in handle:lines() do
    local line = i:gsub("#.*", "")
    local a, b, service, port, protocol = line:find("^([^%s]+)%s+(%d+)/([^%s]+)%s*")
    if b ~= nil then
      local port = tonumber(port)
      local t = { service }
      for j in line:sub(b + 1):gmatch("[^%s]+") do
        t[#t + 1] = j
      end
      for j = 1, #t do
        local v = t[j]
        if result[v] == nil then
          result[v] = {}
        end
        local t = result[v]
        t[#t + 1] = {
          port = port;
          protocol = protocol;
        }
      end
    end
  end
  return result
end

local function string_to_boolean(v)
  if v == "yes" or v == "on" or v == "1" or v == "true" then
    return true
  elseif v == "no" or v == "off" or v == "0" or v == "false" then
    return false
  else
    return nil
  end
end

local function is_root()
  local handle = assert(io.popen("id -u -r"))
  local euid = handle:read("*n")
  assert(handle:close())
  return euid == 0
end

local result, message = pcall(function (filename)
  local content
  if filename == nil then
    content = io.read("*a")
  else
    local handle = assert(io.open(filename))
    content = handle:read("*a")
    assert(handle:close())
  end

  local service
  local port
  local protocol
  local permanent
  local state

  local list = shlex.split(content)
  for i = 1, #list do
    local item = list[i]
    local k, v = item:match("^([^=]+)=(.*)")
    if k == "service" then
      service = v
    elseif k == "port" then
      port, protocol = v:match("^(%d+)/(.*)")
      if port == nil then
        error("bad argument " .. item)
      end
      port = tonumber(port)
    elseif k == "permanent" then
      permanent = string_to_boolean(v)
      if permanent == nil then
        error("bad argument " .. item)
      end
    elseif k == "state" then
      if v == "enabled" or v == "disabled" then
        state = v
      else
        error("bad argument " .. item)
      end
    else
      error("bad argument " .. item)
    end
  end

  if service == nil and port == nil then
    error "service or port is required"
  end
  if permanent == nil then
    error "permanent is required"
  end
  if state == nil then
    error "state is required"
  end

  local rule = {}
  if service ~= nil then
    local handle = assert(io.open("/etc/services"))
    local services = services_parse(handle)
    assert(handle:close())

    local t = services[service]
    for i = 1, #t do
      local v = t[i]
      rule[#rule + 1] = {
        port = v.port;
        protocol = v.protocol;
      }
    end
  end
  if port ~= nil then
    rule[#rule + 1] = {
      port = port;
      protocol = protocol;
    }
  end

  local handle = assert(io.popen([[env "PATH=$PATH:/usr/sbin:/sbin" iptables-save -t filter]]))
  local iptables = iptables_parse(handle)
  print(json.encode(iptables))
  assert(handle:close())

  for i = 1, #rule do
    local v = rule[i]
    print(iptables_evaluate(iptables, "INPUT", v.protocol, v.port))
  end

  print("rule", json.encode(rule))
  print("permanent", permanent)
  print("state", state)
end, ...)

if not result then
  io.write(json.encode {
    failed = true;
    msg = message;
  }, "\n")
end

print(is_root())
