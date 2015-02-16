local json = require "dromozoa.json"
local shlex = require "dromozoa.shlex"

local format = string.format

local PATH = os.getenv("PATH")
if PATH == nil or #PATH == 0 then
  PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
else
  PATH = PATH .. ":/usr/bin:/bin:/usr/sbin:/sbin"
end

local function execute(command)
  local result = os.execute(command)
  if type(result) == "boolean" then
    return result
  else
    return result == 0
  end
end

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
      mode = "comment";
      comment = _1;
    }
  elseif scan "%*([^%s]*)" then
    return {
      mode = "table";
      table = _1;
    }
  elseif scan "%:(.-) (.-) " then
    return {
      mode = "policy";
      chain = _1;
      policy = _2;
    }
  elseif scan "%-A (.-) " then
    local result = {
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
    local t = {}
    for j in line:sub(i):gmatch("[^%s]+") do
      t[#t + 1] = j
    end
    result.match = false
    for j = 1, #t do
      local a, b, c, d = t[j], t[j + 1], t[j + 2], t[j + 3]
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
    return result
  elseif scan "COMMIT" then
    return {
      mode = "commit";
    }
  else
    error "could not parse"
  end
end

local function iptables_parse()
  local result = {}
  local table
  local n = 0

  local handle = assert(io.popen(format([[env PATH="%s" iptables-save]], PATH)))
  for i in handle:lines() do
    local v = iptables_parse_line(i)
    if v.mode == "table" then
      table = v.table
      result[table] = {}
    elseif v.mode == "policy" then
      result[table][v.chain] = {
        policy = v.policy;
        append = {};
      }
    elseif v.mode == "append" then
      n = n + 1
      local t = result[table][v.chain].append
      t[#t + 1] = v
    end
  end
  handle:close()

  return result, n
end

local function iptables_evaluate(data, chain, protocol, port)
  local t = data[chain].append
  for i = 1, #t do
    local v = t[i]
    if not v.address_or_interface then
      local pass
      if v.protocol == nil then
        pass = true
      else
        if v.protocol.invert then
          pass = v.protocol.protocol ~= protocol
        else
          pass = v.protocol.protocol == protocol
        end
      end
      if pass then
        local pass
        if v.match_dport == nil then
          if not v.match then
            pass = "no_match"
          end
        elseif v.match_dport.name == protocol and v.match_dport.min <= port and port <= v.match_dport.max then
          if v.match_dport.min == v.match_dport.max then
            pass = "match_dport_single"
          else
            pass = "match_dport_range"
          end
        end
        if pass then
          if data[v.jump] == nil then
            return v.jump, chain, i, pass
          else
            return iptables_evaluate(data, v.jump, protocol, port)
          end
        end
      end
    end
  end
  return data[chain].policy, chain, 0
end

local function iptables_insert(chain, i, protocol, port, target)
  if protocol == "tcp" then
    assert(execute(format([[env PATH="%s" iptables -I "%s" %d -p tcp -m state --state NEW -m tcp --dport %d -j "%s" >/dev/null 2>&1]], PATH, chain, i, port, target)))
  else
    assert(execute(format([[env PATH="%s" iptables -I "%s" %d -p "%s" -m "%s" --dport %d -j "%s" >/dev/null 2>&1]], PATH, chain, i, protocol, protocol, port, target)))
  end
end

local function iptables_remove(chain, i)
  assert(execute(format([[env PATH="%s" iptables -D "%s" %d >/dev/null 2>&1]], PATH, chain, i)))
end

local function get_service_by_name(name)
  local result = {}

  local handle = assert(io.open("/etc/services"))
  for i in handle:lines() do
    local line = i:gsub("#.*", "")
    local a, b, s_name, s_port, s_protocol = line:find("^([^%s]+)%s+(%d+)/([^%s]+)%s*")
    if b ~= nil then
      local s = {
        port = tonumber(s_port);
        protocol = s_protocol;
      }
      if s_name == name then
        result[#result + 1] = s
      end
      for j in line:sub(b + 1):gmatch("[^%s]+") do
        if j == name then
          result[#result + 1] = s
        end
      end
    end
  end
  handle:close()

  if #result == 0 then
    return nil
  else
    return result
  end
end

local function get_euid()
  local handle = assert(io.popen(format([[env PATH="%s" id -u -r]], PATH)))
  local euid = handle:read("*n")
  handle:close()
  return euid
end

local string_to_boolean = {}
do
  local t = { "yes", "on", "1", "true" }
  for i = 1, #t do
    string_to_boolean[t[i]] = true
  end
  local t = { "no", "off", "0", "false" }
  for i = 1, #t do
    string_to_boolean[t[i]] = false
  end
end

local result, message = pcall(function (filename)
  local euid = get_euid()
  if euid ~= 0 then
    error "must be run as root"
  end

  local handle
  if filename == nil then
    handle = io.stdin
  else
    handle = assert(io.open(filename))
  end
  local content = handle:read("*a")
  handle:close()

  local service
  local permanent
  local state

  local list = shlex.split(content)
  for i = 1, #list do
    local item = list[i]
    local k, v = item:match("^([^=]+)=(.*)")
    if k == "service" then
      service = get_service_by_name(v)
      if service == nil then
        error("bad argument " .. item)
      end
    elseif k == "port" then
      local port, protocol = v:match("^(%d+)/(.*)")
      if port == nil then
        error("bad argument " .. item)
      end
      service = { {
        port = tonumber(port);
        protocol = protocol;
      } }
    elseif k == "permanent" then
      permanent = string_to_boolean[v]
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

  if service == nil then
    error "service or port is required"
  end
  if permanent == nil then
    error "permanent is required"
  end
  if state == nil then
    error "state is required"
  end

  local changed = false

  local iptables, n = iptables_parse()
  if n == 0 then
    assert(execute(format([[env PATH="%s" lokkit -q --enabled -p 22/tcp -f >/dev/null 2>&1]], PATH)))
    changed = true
    iptables = iptables_parse()
  end

  for i = 1, #service do
    local v = service[i]
    local target, chain, j, pass = iptables_evaluate(iptables.filter, "INPUT", v.protocol, v.port)
    if state == "enabled" and target == "REJECT" then
      local t = iptables.filter[chain].append[j]
      if pass == "match_dport_single" then
        iptables_remove(chain, j)
      else
        iptables_insert(chain, j, v.protocol, v.port, "ACCEPT")
      end
      changed = true
    elseif state == "disabled" and target == "ACCEPT" then
      local t = iptables.filter[chain].append[j]
      if pass == "match_dport_single" then
        iptables_remove(chain, j)
      else
        iptables_insert(chain, j, v.protocol, v.port, "REJECT")
      end
      changed = true
    end
  end

  if permanent and changed then
    assert(execute(format([[env PATH="%s" service iptables save >/dev/null 2>&1]], PATH)))
  end

  io.write(json.encode {
    changed = changed;
  }, "\n")
end, ...)

if not result then
  io.write(json.encode {
    failed = true;
    msg = message;
  }, "\n")
end
