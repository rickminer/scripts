local http = require "http"
local shortport = require "shortport"
local datetime = require "datetime"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local url = require "url"
local tls = require "tls"
local comm = require "comm"
local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local sslcert = require "sslcert"
local sslv2 = require "sslv2"

description = [[
This plugin is a combination of sslv2, ssl-enum-ciphers, http-headers. They have been combined and filtered to show compliance with BOD 18-01. Adding -v will show the needed information to troubleshoot any compliance issues. This plugin will struggle with any sites that require a client certificate, but it will still show the certificate and TLS ciphers.
Checks for BOD 18-01 Web compliance:

* HTTPS Only (with redirects)
* HSTS
* Certificate validation
* Cipher (SSLv2, SSLv3, RC4, 3DES) Checking

]]

---
-- @usage
-- nmap -p 80,443 --script http-bod1801 <target>
--
-- @output
-- 80/tcp  open  http
-- | http-bod1801:
-- |   BOD1801_Results:
-- |     Redirect: COMPLIANT.
-- |     HSTS: COMPLIANT
-- |_    Certificate: COMPLIANT
-- 443/tcp open  https
-- | http-bod1801:
-- |   BOD1801_Results:
-- |     Redirect: UNKNOWN, check HTTP port.
-- |     Ciphers: COMPLIANT
-- |     HSTS: COMPLIANT
-- |_    Certificate: COMPLIANT
--
--
-- @xmloutput
-- <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="51"/><service name="http" method="table" conf="3"/><script id="http-bod1801" output="&#xa;  BOD1801_Results: &#xa;    Redirect: COMPLIANT.&#xa;    HSTS: COMPLIANT&#xa;    Certificate: FAILED, hostname mismatch: *.darrp.noaa.gov"><table key="BOD1801_Results">
-- <elem>Redirect: COMPLIANT.</elem>
-- <elem>HSTS: COMPLIANT</elem>
-- <elem>Certificate: FAILED, hostname mismatch: *.darrp.noaa.gov</elem>
-- </table>
-- </script></port>
-- <port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="https" method="table" conf="3"/><script id="http-bod1801" output="&#xa;  BOD1801_Results: &#xa;    Redirect: UNKNOWN, check HTTP port.&#xa;    Ciphers: COMPLIANT&#xa;    HSTS: COMPLIANT&#xa;    Certificate: FAILED, hostname mismatch: *.darrp.noaa.gov"><table key="BOD1801_Results">
-- <elem>Redirect: UNKNOWN, check HTTP port.</elem>
-- <elem>Ciphers: COMPLIANT</elem>
-- <elem>HSTS: COMPLIANT</elem>
-- <elem>Certificate: FAILED, hostname mismatch: *.darrp.noaa.gov</elem>
-- </table>
-- </script></port>
-- </ports>
--
-- @args http-security-headers.path The URL path to request. The default path is "/".
---

author = {"Rick Miner"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

-- GLOBAL VARIABLES -- 
local is_ssl = false -- GLOBAL ssl check variable
local certificate -- Storing the certificate for later use
-- Test at most this many ciphersuites at a time.
-- http://seclists.org/nmap-dev/2012/q3/156
-- http://seclists.org/nmap-dev/2010/q1/859
local CHUNK_SIZE = 64
local have_ssl, openssl = pcall(require,'openssl')

-- RULES --
postrule = function() return (nmap.registry.BOD1801 ~= nil) end

portrule = function (host, port)
    local is_http = shortport.http
    if shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port) then
        is_ssl = true
        -- Only want HTTP services, but need to detect SSL as well. is_ssl is set, so return.
        return is_http
    end
    -- selected by name and we didn't detect something *not* SSL
    if (port.version.name_confidence <= 3 and nmap.version_intensity() == 9) then
      -- check whether it's an SSL service
      -- probes from nmap-service-probes
      for _, probe in ipairs({
          --TLSSessionReq
          "\x16\x03\0\0\x69\x01\0\0\x65\x03\x03U\x1c\xa7\xe4random1random2random3\z
          random4\0\0\x0c\0/\0\x0a\0\x13\x009\0\x04\0\xff\x01\0\0\x30\0\x0d\0,\0*\0\z
          \x01\0\x03\0\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\z
          \x03\x03\x03\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\z
          \x05\x03\x05\x02",
          -- SSLSessionReq
          "\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\z
          \x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\z
          \0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\z
          \x08\0\x06\0\x03\x01\0",
        }) do
        local status, resp = comm.exchange(host, port, probe)
        if status and resp and (
            resp:match("^\x16\x03[\0-\x03]..\x02...\x03[\0-\x03]") or
            resp:match("^\x15\x03[\0-\x03]\0\x02\x02[F\x28]")
            ) then
          is_ssl = true
          break
        end
      end
      -- Only want HTTP services, but need to detect SSL as well. is_ssl is set, so return.
      return is_http
    end
    -- Only want HTTP services, but need to detect SSL as well. is_ssl is set, so return.
    return is_http
  end

-- FUNCTIONS
--- put finding in the nmap registry for usage by other scripts
--@param host nmap host table
--@param key host key table
local add_value_to_registry = function( host, check, value )
  nmap.registry.BOD1801 = nmap.registry.BOD1801 or {}
  nmap.registry.BOD1801[stdnse.get_hostname(host)] = nmap.registry.BOD1801[stdnse.get_hostname(host)] or {}
  nmap.registry.BOD1801[stdnse.get_hostname(host)][check] = value
end

-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end

-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  local fragment
  return function ()
    local record
    i, record = tls.record_read(buffer, i, fragment)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then
        return nil, "done"
      end
    end
    fragment = record.fragment
    return record
  end
end

local function try_params(host, port, t)

  -- Use Nmap's own discovered timeout plus 5 seconds for host processing
  -- Default to 10 seconds total.
  local timeout = ((host.times and host.times.timeout) or 5) * 1000 + 5000

  -- Create socket.
  local status, sock, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", sock)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(timeout)

  -- Send request.
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    ctx_log(1, t.protocol, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record
    record, err = get_next_record()
    if not record then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      sock:close()
      return records
    end
    -- Collect message bodies into one record per type
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do -- no ipairs because we append below
      local b = record.body[j]
      done = ((record.type == "alert" and b.level == "fatal") or
        (record.type == "handshake" and b.type == "server_hello_done"))
      table.insert(records[record.type].body, b)
    end
    if done then
      sock:close()
      return records
    end
  end
end

local function sorted_keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  table.sort(ret)
  return ret
end

local function in_chunks(t, size)
  size = math.floor(size)
  if size < 1 then size = 1 end
  local ret = {}
  for i = 1, #t, size do
    local chunk = {}
    for j = i, i + size - 1 do
      chunk[#chunk+1] = t[j]
    end
    ret[#ret+1] = chunk
  end
  return ret
end

local function remove(t, e)
  for i, v in ipairs(t) do
    if v == e then
      table.remove(t, i)
      return i
    end
  end
  return nil
end

local function slice(t, i, j)
  local output = {}
  while i <= j do
    output[#output+1] = t[i]
    i = i + 1
  end
  return output
end

local function merge(a, b, cmp)
  local output = {}
  local i = 1
  local j = 1
  while i <= #a and j <= #b do
    local winner, err = cmp(a[i], b[j])
    if not winner then
      return nil, err
    end
    if winner == a[i] then
      output[#output+1] = a[i]
      i = i + 1
    else
      output[#output+1] = b[j]
      j = j + 1
    end
  end
  while i <= #a do
    output[#output+1] = a[i]
    i = i + 1
  end
  while j <= #b do
    output[#output+1] = b[j]
    j = j + 1
  end
  return output
end

local function merge_recursive(chunks, cmp)
  if #chunks == 0 then
    return {}
  elseif #chunks == 1 then
    return chunks[1]
  else
    local m = math.floor(#chunks / 2)
    local a, b = slice(chunks, 1, m), slice(chunks, m+1, #chunks)
    local am, err = merge_recursive(a, cmp)
    if not am then
      return nil, err
    end
    local bm, err = merge_recursive(b, cmp)
    if not bm then
      return nil, err
    end
    return merge(am, bm, cmp)
  end
end

-- https://bugzilla.mozilla.org/show_bug.cgi?id=946147
local function remove_high_byte_ciphers(t)
  local output = {}
  for i, v in ipairs(t) do
    if tls.CIPHERS[v] <= 255 then
      output[#output+1] = v
    end
  end
  return output
end

-- Get TLS extensions
local function base_extensions(host)
  local tlsname = tls.servername(host)
  return {
    -- Claim to support common elliptic curves
    ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](tls.DEFAULT_ELLIPTIC_CURVES),
    -- Enable SNI if a server name is available
    ["server_name"] = tlsname and tls.EXTENSION_HELPERS["server_name"](tlsname),
  }
end

-- Get a message body from a record which has the specified property set to value
local function get_body(record, property, value)
  for i, b in ipairs(record.body) do
    if b[property] == value then
      return b
    end
  end
  return nil
end

-- Score a ciphersuite implementation (including key exchange info)
local function score_cipher (kex_strength, cipher_info)
  local kex_score, cipher_score
  if not kex_strength or not cipher_info.size then
    return "unknown"
  end
  if kex_strength == 0 then
    return 0
  elseif kex_strength < 512 then
    kex_score = 0.2
  elseif kex_strength < 1024 then
    kex_score = 0.4
  elseif kex_strength < 2048 then
    kex_score = 0.8
  elseif kex_strength < 4096 then
    kex_score = 0.9
  else
    kex_score = 1.0
  end

  if cipher_info.size == 0 then
    return 0
  elseif cipher_info.size < 128 then
    cipher_score = 0.2
  elseif cipher_info.size < 256 then
    cipher_score = 0.8
  else
    cipher_score = 1.0
  end

  -- Based on SSL Labs' 30-30-40 rating without the first 30% (protocol support)
  return 0.43 * kex_score + 0.57 * cipher_score
end

local function letter_grade (score)
  if not tonumber(score) then return "unknown" end
  if score >= 0.80 then
    return "A"
  elseif score >= 0.65 then
    return "B"
  elseif score >= 0.50 then
    return "C"
  elseif score >= 0.35 then
    return "D"
  elseif score >= 0.20 then
    return "E"
  else
    return "F"
  end
end

-- Find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group, scores)
  local results = {}
  local t = {
    ["protocol"] = protocol,
    ["record_protocol"] = protocol, -- improve chances of immediate rejection
    ["extensions"] = base_extensions(host),
  }

  -- This is a hacky sort of tristate variable. There are three conditions:
  -- 1. false = either ciphers or protocol is bad. Keep trying with new ciphers
  -- 2. nil = The protocol is bad. Abandon thread.
  -- 3. true = Protocol works, at least some cipher must be supported.
  local protocol_worked = false
  while (next(group)) do
    t["ciphers"] = group

    local records = try_params(host, port, t)
    if not records then
      return nil
    end
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol mismatch (received %s)", alert.protocol)
          -- Sometimes this is not an actual rejection of the protocol. Check specifically:
          if get_body(alert, "description", "protocol_version") then
            protocol_worked = nil
          end
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d ciphers rejected.", #group)
          break
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d ciphers rejected. (No handshake)", #group)
      else
        ctx_log(1, protocol, "%d ciphers and/or protocol rejected. (No handshake)", #group)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected. cipher: %s", server_hello.cipher)
        -- Some implementations will do this if a cipher is supported in some
        -- other protocol version but not this one. Gotta keep trying.
        if not remove(group, server_hello.cipher) then
          -- But if we didn't even offer this cipher, then give up. Crazy!
          protocol_worked = protocol_worked or nil
        end
        break
      else
        protocol_worked = true
        local name = server_hello.cipher
        ctx_log(2, protocol, "Cipher %s chosen.", name)
        if not remove(group, name) then
          ctx_log(1, protocol, "chose cipher %s that was not offered.", name)
          ctx_log(1, protocol, "removing high-byte ciphers and trying again.")
          local size_before = #group
          group = remove_high_byte_ciphers(group)
          ctx_log(1, protocol, "removed %d high-byte ciphers.", size_before - #group)
          if #group == size_before then
            -- No changes... Server just doesn't like our offered ciphers.
            break
          end
        else
          -- Add cipher to the list of accepted ciphers.
          table.insert(results, name)
          if scores then
            local info = tls.cipher_info(name)
            -- Some warnings:
            if info.hash and info.hash == "MD5" then
              scores.warnings["Ciphersuite uses MD5 for message integrity"] = true
            end
            if info.mode and info.mode == "CBC" and info.block_size <= 64 then
              scores.warnings[("64-bit block cipher %s vulnerable to SWEET32 attack"):format(info.cipher)] = true
            end
            if protocol == "SSLv3" and  info.mode and info.mode == "CBC" then
              scores.warnings["CBC-mode cipher in SSLv3 (CVE-2014-3566)"] = true
            elseif info.cipher == "RC4" then
              scores.warnings["Broken cipher RC4 is deprecated by RFC 7465"] = true
            end
            local kex = tls.KEX_ALGORITHMS[info.kex]
            local extra, kex_strength
            if kex.anon then
              kex_strength = 0
            elseif kex.export then
              if info.kex:find("1024$") then
                kex_strength = 1024
              else
                kex_strength = 512
              end
            else
              if have_ssl and kex.pubkey then
                local certs = get_body(handshake, "type", "certificate")
                -- Assume RFC compliance:
                -- "The sender's certificate MUST come first in the list."
                -- This may not always be the case, so
                -- TODO: reorder certificates and validate entire chain
                -- TODO: certificate validation (date, self-signed, etc)
                local c, err
                if certs == nil then
                  err = "no certificate message"
                else
                   c, err = sslcert.parse_ssl_certificate(certs.certificates[1])
                end
                if not c then
                  stdnse.debug1("Failed to parse certificate: %s", err)
                elseif c.pubkey.type == kex.pubkey then
                  certificate = c;
                  local sigalg = c.sig_algorithm:match("([mM][dD][245])")
                  if sigalg then
                    -- MD2 and MD5 are broken
                    kex_strength = 0
                    scores.warnings["Insecure certificate signature: " .. string.upper(sigalg)] = true
                  else
                    sigalg = c.sig_algorithm:match("([sS][hH][aA]1)")
                    if sigalg then
                      -- TODO: Update this when SHA-1 is fully deprecated in 2017
                      if type(c.notBefore) == "table" and c.notBefore.year >= 2016 then
                        kex_strength = 0
                        scores.warnings["Deprecated SHA1 signature in certificate issued after January 1, 2016"] = true
                      end
                      scores.warnings["Weak certificate signature: SHA1"] = true
                    end
                    kex_strength = tls.rsa_equiv(kex.pubkey, c.pubkey.bits)
                    if c.pubkey.exponent then
                      if openssl.bignum_bn2dec(c.pubkey.exponent) == "1" then
                        kex_strength = 0
                        scores.warnings["Certificate RSA exponent is 1, score capped at F"] = true
                      end
                    end
                    if c.pubkey.ecdhparams then
                      if c.pubkey.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                        extra = c.pubkey.ecdhparams.curve_params.curve
                      else
                        extra = string.format("%s %d", c.pubkey.ecdhparams.curve_params.ec_curve_type, c.pubkey.bits)
                      end
                    else
                      extra = string.format("%s %d", kex.pubkey, c.pubkey.bits)
                    end
                  end
                end
              end
              local ske = get_body(handshake, "type", "server_key_exchange")
              if kex.server_key_exchange and ske then
                local kex_info = kex.server_key_exchange(ske.data, protocol)
                if kex_info.strength then
                  local rsa_bits = tls.rsa_equiv(kex.type, kex_info.strength)
                  local low_strength_warning = false
                  if kex_strength and kex_strength > rsa_bits then
                    kex_strength = rsa_bits
                    low_strength_warning = true
                  end
                  kex_strength = kex_strength or rsa_bits
                  if kex_info.ecdhparams then
                    if kex_info.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                      extra = kex_info.ecdhparams.curve_params.curve
                    else
                      extra = string.format("%s %d", kex_info.ecdhparams.curve_params.ec_curve_type, kex_info.strength)
                    end
                  else
                    extra = string.format("%s %d", kex.type, kex_info.strength)
                  end
                  if low_strength_warning then
                    scores.warnings[(
                        "Key exchange (%s) of lower strength than certificate key"
                      ):format(extra)] = true
                  end
                end
                if kex_info.rsa and kex_info.rsa.exponent == 1 then
                  kex_strength = 0
                  scores.warnings["Certificate RSA exponent is 1, score capped at F"] = true
                end
              end
            end
            scores[name] = {
              cipher_strength=info.size,
              kex_strength = kex_strength,
              extra = extra,
              letter_grade = letter_grade(score_cipher(kex_strength, info))
            }
          end
        end
      end
    end
  end
  return results, protocol_worked
end

local function get_chunk_size(host, protocol)
  -- Try to make sure we don't send too big of a handshake
  -- https://github.com/ssllabs/research/wiki/Long-Handshake-Intolerance
  local len_t = {
    protocol = protocol,
    ciphers = {},
    extensions = base_extensions(host),
  }
  local cipher_len_remaining = 255 - #tls.client_hello(len_t)
  -- if we're over 255 anyway, just go for it.
  -- Each cipher adds 2 bytes
  local max_chunks = cipher_len_remaining > 1 and cipher_len_remaining // 2 or CHUNK_SIZE
  -- otherwise, use the min
  return max_chunks < CHUNK_SIZE and max_chunks or CHUNK_SIZE
end

-- Break the cipher list into chunks of CHUNK_SIZE (for servers that can't
-- handle many client ciphers at once), and then call find_ciphers_group on
-- each chunk.
local function find_ciphers(host, port, protocol)

  local ciphers = in_chunks(sorted_keys(tls.CIPHERS), get_chunk_size(host, protocol))

  local results = {}
  local scores = {warnings={}}
  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    local chunk, protocol_worked = find_ciphers_group(host, port, protocol, group, scores)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
  end
  if not next(results) then return nil end

  return results, scores
end

local function find_compressors(host, port, protocol, good_ciphers)
  local compressors = sorted_keys(tls.COMPRESSORS)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = good_ciphers,
    ["extensions"] = base_extensions(host),
  }

  local results = {}

  -- Try every compressor.
  local protocol_worked = false
  while (next(compressors)) do
    -- Create structure.
    t["compressors"] = compressors

    -- Try connecting with compressor.
    local records = try_params(host, port, t)
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol rejected.")
          protocol_worked = nil
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d compressors rejected.", #compressors)
          -- Should never get here, because NULL should be good enough.
          -- The server may just not be able to handle multiple compressors.
          if #compressors > 1 then -- Make extra-sure it's not crazily rejecting the NULL compressor
            compressors[1] = "NULL"
            for i = 2, #compressors, 1 do
              compressors[i] = nil
            end
            -- try again.
          else
            break
          end
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d compressors rejected. (No handshake)", #compressors)
      else
        ctx_log(1, protocol, "%d compressors and/or protocol rejected. (No handshake)", #compressors)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected.")
        protocol_worked = (protocol_worked == nil) and nil or false
        break
      else
        protocol_worked = true
        local name = server_hello.compressor
        ctx_log(2, protocol, "Compressor %s chosen.", name)
        remove(compressors, name)

        -- Add compressor to the list of accepted compressors.
        table.insert(results, name)
        if name == "NULL" then
          break -- NULL is always last choice, and must be included
        end
      end
    end
  end

  return results
end

-- Offer two ciphers and return the one chosen by the server. Returns nil and
-- an error message in case of a server error.
local function compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = {cipher_a, cipher_b},
    ["extensions"] = base_extensions(host),
  }
  local records = try_params(host, port, t)
  local server_hello = records.handshake and get_body(records.handshake, "type", "server_hello")
  if server_hello then
    ctx_log(2, protocol, "compare %s %s -> %s", cipher_a, cipher_b, server_hello.cipher)
    return server_hello.cipher
  else
    ctx_log(2, protocol, "compare %s %s -> error", cipher_a, cipher_b)
    return nil, string.format("Error when comparing %s and %s", cipher_a, cipher_b)
  end
end

-- Try to find whether the server prefers its own ciphersuite order or that of
-- the client.
--
-- The return value is (preference, err). preference is a string:
--   "server": the server prefers its own order. In this case ciphers is non-nil.
--   "client": the server follows the client preference. ciphers is nil.
--   "indeterminate": returned when there are only 0 or 1 ciphers. ciphers is nil.
--   nil: an error ocurred during the test. err is non-nil.
-- err is an error message string that is non-nil when preference is nil or
-- indeterminate.
--
-- The algorithm tries offering two ciphersuites in two different orders. If
-- the server makes a different choice each time, "client" preference is
-- assumed. Otherwise, "server" preference is assumed.
local function find_cipher_preference(host, port, protocol, ciphers)
  -- Too few ciphers to make a decision?
  if #ciphers < 2 then
    return "indeterminate", "Too few ciphers supported"
  end

  -- Do a comparison in both directions to see if server ordering is consistent.
  local cipher_a, cipher_b = ciphers[1], ciphers[2]
  ctx_log(1, protocol, "Comparing %s to %s", cipher_a, cipher_b)
  local winner_forwards, err = compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  if not winner_forwards then
    return nil, err
  end
  local winner_backward, err = compare_ciphers(host, port, protocol, cipher_b, cipher_a)
  if not winner_backward then
    return nil, err
  end
  if winner_forwards ~= winner_backward then
    return "client", nil
  end
  return "server", nil
end

-- Sort ciphers according to server preference with a modified merge sort
local function sort_ciphers(host, port, protocol, ciphers)
  local chunks = {}
  for _, group in ipairs(in_chunks(ciphers, get_chunk_size(host, protocol))) do
    local size = #group
    local chunk = find_ciphers_group(host, port, protocol, group)
    if not chunk then
      return nil, "Network error"
    end
    if #chunk ~= size then
      ctx_log(1, protocol, "warning: %d ciphers offered but only %d accepted", size, #chunk)
    end
    table.insert(chunks, chunk)
  end

  -- The comparison operator for the merge is a 2-cipher ClientHello.
  local function cmp(cipher_a, cipher_b)
    return compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  end
  local sorted, err = merge_recursive(chunks, cmp)
  if not sorted then
    return nil, err
  end
  return sorted
end

local function try_protocol(host, port, protocol, upresults)
  local condvar = nmap.condvar(upresults)

  local results = stdnse.output_table()

  -- Find all valid ciphers.
  local ciphers, scores = find_ciphers(host, port, protocol)
  if ciphers == nil then
    condvar "signal"
    return nil
  end

  if #ciphers == 0 then
    results = {ciphers={},compressors={}}
    setmetatable(results,{
      __tostring=function(t) return "No supported ciphers found" end
    })
    upresults[protocol] = results
    condvar "signal"
    return nil
  end
  -- Find all valid compression methods.
  local compressors
  -- Reduce chunk size by 1 to allow extra room for the extra compressors (2 bytes)
  for _, c in ipairs(in_chunks(ciphers, get_chunk_size(host, protocol) - 1)) do
    compressors = find_compressors(host, port, protocol, c)
    -- I observed a weird interaction between ECDSA ciphers and DEFLATE compression.
    -- Some servers would reject the handshake if no non-ECDSA ciphers were available.
    -- Sending 64 ciphers at a time should be sufficient, but we'll try them all if necessary.
    if compressors and #compressors ~= 0 then
      break
    end
  end

  -- Note the server's cipher preference algorithm.
  local cipher_pref, cipher_pref_err = find_cipher_preference(host, port, protocol, ciphers)

  -- Order ciphers according to server preference, if possible
  if cipher_pref == "server" then
    local sorted, err = sort_ciphers(host, port, protocol, ciphers)
    if sorted then
      ciphers = sorted
    else
      -- Can't sort, fall back to alphabetical order
      table.sort(ciphers)
      cipher_pref_err = err
    end
  else
    -- fall back to alphabetical order
    table.sort(ciphers)
  end

  -- Add rankings to ciphers
  for i, name in ipairs(ciphers) do
    local outcipher = {name=name, kex_info=scores[name].extra, strength=scores[name].letter_grade}
    setmetatable(outcipher,{
      __tostring=function(t)
        if t.kex_info then
          return string.format("%s (%s) - %s", t.name, t.kex_info, t.strength)
        else
          return string.format("%s - %s", t.name, t.strength)
        end
      end
    })
    ciphers[i]=outcipher
  end

  results["ciphers"] = ciphers

  -- Format the compressor table.
  if compressors then
    table.sort(compressors)
  end
  results["compressors"] = compressors

  results["cipher preference"] = cipher_pref
  results["cipher preference error"] = cipher_pref_err
  if next(scores.warnings) then
    results["warnings"] = sorted_keys(scores.warnings)
  end

  upresults[protocol] = results
  condvar "signal"
  return nil
end

--- Return a table that yields elements sorted by key when iterated over with pairs()
--  Should probably put this in a formatting library later.
--  Depends on keys() function defined above.
--@param  t    The table whose data should be used
--@return out  A table that can be passed to pairs() to get sorted results
function sorted_by_key(t)
  local out = {}
  setmetatable(out, {
    __pairs = function(_)
      local order = sorted_keys(t)
      return coroutine.wrap(function()
        for i,k in ipairs(order) do
          coroutine.yield(k, t[k])
        end
      end)
    end
  })
  return out
end

local function fail (err) return stdnse.format_output(false, err) end

-- remove trailing and leading whitespace from string.
-- http://en.wikipedia.org/wiki/Trim_(programming)
local function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function name_to_table(name)
    local output = {}
    for k, v in pairs(name) do
        if type(k) == "table" then
            k = stdnse.strjoin(".", k)
        end
        output[k] = v
    end
    return output
end

local function check_hostname(hostname, cn, san)
    if hostname:match(cn:gsub("%.",'%%.'):gsub("%-",'%%-'):gsub("*",".+")) then return true end
    if not san then return false end
    for type, name in san:gmatch("(DNS):([^,]+)") do
        if hostname:match(name:gsub("%.",'%%.'):gsub("%-",'%%-'):gsub("*",".+")) then return true end
    end
    return false
end

local function makeTimeStamp(dateString)
    local pattern = "(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)"
    local xyear, xmonth, xday, xhour, xminute, xseconds = dateString:match(pattern)
    local convertedTimestamp = os.time({year = xyear, month = xmonth, day = xday, hour = xhour, min = xminute, sec = xseconds})
    return convertedTimestamp
end

local function getCertificate(host, port)
  if certificate then
      return true, certificate
  else
      -- This uses a host and port string, NOT the ones provided
      local s = nmap.new_socket()
      local status, error = s:connect(host, port, "ssl")
      local cert = nil
      if status then
          cert = s:get_ssl_certificate()
      else
          return false, "Failed to connect: " .. error
      end

      if cert == nil then
          return false, "Failed to get cert."
      else
          return true, cert
      end
  end
end

local function output_tab(cert)
    local o = stdnse.output_table()
    o.subject = name_to_table(cert.subject)["commonName"]
    o.issuer = name_to_table(cert.issuer)["commonName"]
    if cert.extensions then
        for _, e in ipairs(cert.extensions) do
            if e.name == "X509v3 Subject Alternative Name" then
            o.subject_alternative_name = e.value
            break
            end
        end
    end
    o.validity = {}
    for k, v in pairs(cert.validity) do
        if type(v)=="string" then
        o.validity[k] = v
        else
        o.validity[k] = datetime.format_timestamp(v)
        end
    end
    return o
end

function handle_redirect(host, port, path, options)
  local counter = 10
  local response, locations
  local u = { host = host, port = port, path = path }
  local options = options or {}
  if not options.redirect_ok then redirect_ok = 0 end
  repeat
    stdnse.debug1(string.format("URL path is %s.", u.path))
    response = http.get(u.host, u.port, u.path, options)
    stdnse.debug1(string.format("Status is %s.", trim(response["status-line"])))
    u = parse_redirect(u.host, u.port, u.path, response, options)
    if( not(u) ) then
      break
    end
    stdnse.debug1(string.format("Redirect is %s.", response.header.location))
    options.scheme = u.scheme or options.scheme
    locations = locations or {}
    table.insert(locations, url.build(u))
    stdnse.debug1(string.format("Locations added %s.", url.build(u)))
    counter = counter - 1
  until( counter <= 0 )
  response.location = locations
  return response
end

--- Handles a HTTP redirect
-- @param host table as received by the script action function
-- @param port table as received by the script action function
-- @param path string
-- @param response table as returned by http.get or http.head
-- @return url table as returned by <code>url.parse</code> or nil if there's no
--         redirect taking place
function parse_redirect(host, port, path, response, options)
  if ( not(tostring(response.status):match("^30[01237]$")) or
       not(response.header) or
       not(response.header.location) ) then
    return nil
  end
  port = ( "number" == type(port) ) and { number = port } or port
  local u = url.parse(response.header.location)
  if ( not(u.host) ) then
    -- we're dealing with a relative url
    u.host = stdnse.get_hostname(host)
    u.scheme = options.scheme
  end
  -- do port fixup
  u.port = u.port or url.get_default_port(u.scheme) or port.number
  if ( not(u.path) ) then
    u.path = "/"
  end
  u.path = url.absolute(path, u.path)
  if ( u.query ) then
    u.path = ("%s?%s"):format( u.path, u.query )
  end
  return u
end

portaction = function(host, port)
    local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
    local response
    local result
    local locations
    local uri
    local hsts
    local output_info = {}
    local hostID = host.targetname or host.ip
    local locations = {}
    local options = {redirect_ok=0, header={}}
    options['header']['User-Agent'] = 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17'

    result = http.get(host, port, path, options)
    stdnse.debug1(string.format("Initial request to %s.", url.build({host=stdnse.get_hostname(host), port=port.number, path=path})))

    output_info = stdnse.output_table()
    output_info.BOD1801_Results = {}

    if is_ssl then
      table.insert(output_info.BOD1801_Results, "Redirect: UNKNOWN, check HTTP port.")
      add_value_to_registry(host, "HTTPS", "COMPLIANT")
      if tostring( result.status ):match( "30%d" ) and result.header and result.header.location then
        response =  handle_redirect(host, port, path, options)
        local l = response.location
        uri = url.parse(l[#l])
      else
        response = result
        uri = url.parse("https://" .. stdnse.get_hostname(host) .. ":" .. port.number .. path)
      end
    else
      add_value_to_registry(host, "HTTP", "EXISTS")
      -- check for a redirect
      if nmap.verbosity() > 1 then
          output_info.Redirect_Info = {}
          table.insert(output_info.Redirect_Info, "HTTP Status: " .. trim(result["status-line"]))
      end
      if tostring( result.status ):match( "30%d" ) and result.header and result.header.location then
          -- This is a 30x redirect
          response = handle_redirect(host, port, path, options)
          if not (response and response.status) then
              table.insert(output_info.BOD1801_Results, "Redirect: FAILED, redirect failed. Could not connect to " .. result.header.location)
              add_value_to_registry(host, "Redirect", "FAILED")
              uri = url.parse("https://" .. stdnse.get_hostname(host) .. ":" .. port.number .. path)
          else
              locations = response.location
              stdnse.debug1(string.format("Result Header to %s.", trim(result["status-line"])))
              stdnse.debug1(string.format("Redirected to %s.", table.concat(locations, ", ")))
              if nmap.verbosity() > 1 then output_info.Redirect_Info.Locations = locations end
              uri = url.parse( locations[#locations] )
              if uri.scheme == "https" then
                  if uri.port == nil then uri.port = "443" end
                  table.insert(output_info.BOD1801_Results, "Redirect: COMPLIANT.")
                  add_value_to_registry(host, "Redirect", "COMPLIANT")
              else
                  if uri.port == nil then uri.port = "80" end
                  table.insert(output_info.BOD1801_Results, "Redirect: FAILED, redirect not HTTPS.")
                  add_value_to_registry(host, "Redirect", "FAILED")
              end
          end
      else
          -- This is not a redirect
          table.insert(output_info.BOD1801_Results, "Redirect: FAILED, not 301/302 redirect: " .. (result.status or "None"))
          add_value_to_registry(host, "Redirect", "FAILED")
          response = result
          uri = url.parse("https://" .. stdnse.get_hostname(host) .. ":" .. port.number .. path)
      end
    end

    if not (response and response.status) then
        table.insert(output_info.BOD1801_Results, "HTTP: FAILED, could not connect.")
    end

    -- Check Ciphers and get certificate
    if shortport.ssl(host,port) and is_ssl then
        -- Get Cipher information
        if not have_ssl then
            stdnse.verbose("OpenSSL not available; some cipher scores will be marked as unknown.")
        end

        local results = {}

        local condvar = nmap.condvar(results)
        local threads = {}

        -- Try SSLv3, TLS protocols; SSLv2 will come later
        for name, _ in pairs(tls.PROTOCOLS) do
            stdnse.debug1("Trying protocol %s.", name)
            local co = stdnse.new_thread(try_protocol, host, port, name, results)
            threads[co] = true
        end

        repeat
            for thread in pairs(threads) do
            if coroutine.status(thread) == "dead" then threads[thread] = nil end
            end
            if ( next(threads) ) then
            condvar "wait"
            end
        until next(threads) == nil

        if not next(results) then
            return nil
        end

        -- Make sure to test for SSLv2
        stdnse.debug1("Trying protocol %s.", "SSLv2")
        local ciphers = sslv2.test_sslv2(host, port)

        if ciphers then
            stdnse.debug1("Found ciphers %s.", ciphers)
            results["SSLv2"] = {ciphers={}}
            for i, name in ipairs(ciphers) do
                local outcipher = {name=name, strength="F"}
                setmetatable(outcipher,{
                  __tostring=function(t)
                    return string.format("%s - %s", t.name, t.strength)
                  end
                })
                results["SSLv2"].ciphers[i]=outcipher
              end
        end

        -- Calculate least strength and BOD compliance for SSLv2, SSLv3, RC4, 3DES
        local least = "A"
        local issues = ""
        local rc4 = ""
        local des = ""
        for p, r in pairs(results) do
            if p == "SSLv2" then 
                issues = issues .. "SSLv2,"
            elseif p == "SSLv3" then
                issues = issues .. "SSLv3,"
            end
            for i, c in ipairs(r.ciphers) do
                -- counter-intuitive: "A" < "B", so really looking for max
                least = least < c.strength and c.strength or least
                -- Look for 3DES and RC4
                if (c.name):find("RC4") then
                    rc4 = "RC4,"
                end
                if (c.name):find("DES") then
                    des = "3DES"
                end
            end
        end
        if rc4 then
            issues = issues .. rc4
        end
        if des then
            issues = issues .. des
        end
        results["least strength"] = least

        if issues:len() > 0 then
            table.insert(output_info.BOD1801_Results, "Ciphers: FAILED, " .. issues)
            add_value_to_registry(host, "Ciphers", "FAILED")
        else
            table.insert(output_info.BOD1801_Results, "Ciphers: COMPLIANT")
            add_value_to_registry(host, "Ciphers", "COMPLIANT")
        end
        if nmap.verbosity() > 1 then
            output_info.Cipher_Info = {}
            output_info.Cipher_Info = sorted_by_key(results)
        end
    end

    -- Check HSTS header
    if response and response.header['strict-transport-security'] then
        if nmap.verbosity() > 1 then
            output_info.HSTS_Info = {}
            table.insert(output_info.HSTS_Info, "Strict-Transport-Security: " .. response.header['strict-transport-security'])
        end
        hsts = tonumber(string.match(response.header['strict-transport-security'], "%d+"))
        if hsts >= 31536000 then
            table.insert(output_info.BOD1801_Results, "HSTS: COMPLIANT")
            add_value_to_registry(host, "HSTS", "COMPLIANT")
        else
            table.insert(output_info.BOD1801_Results, "HSTS: " .. hsts .. " is too short, 31536000 is min")
            add_value_to_registry(host, "HSTS", "FAILED")
        end
    elseif shortport.ssl(host,port) then
        table.insert(output_info.BOD1801_Results, "HSTS: FAILED, not configured.")
        add_value_to_registry(host, "HSTS", "FAILED")
        if nmap.verbosity() > 1 then
            output_info.HSTS_Info = {}
            table.insert(output_info.HSTS_Info, "HSTS not configured on HTTPS Server.")
        end
    end

    -- Get certificate information
    local status, cert = getCertificate(uri.host, uri.port)
    if ( not(status) ) then
        if is_ssl and nmap.verbosity() > 1 then
            output_info.Certificate_Info = {}
            table.insert(output_info.Certificate_Info, "Certificate: " .. cert)
        end
    else
        cert = output_tab(cert)
        local error_str = ""
        if not(check_hostname(uri.host, cert.subject, cert.subject_alternative_name)) then
            error_str = error_str .. ", hostname mismatch: " .. cert.subject
        end
        local expire = makeTimeStamp(cert.validity.notAfter)
        if expire - os.time() < 0 then error_str = error_str .. ", expired certificate: " .. datetime.format_timestamp(expire) end
        if error_str:len() > 0 then
            table.insert(output_info.BOD1801_Results, "Certificate: FAILED" .. error_str)
            add_value_to_registry(host, "Cert", "FAILED")
        else
            table.insert(output_info.BOD1801_Results, "Certificate: COMPLIANT")
            add_value_to_registry(host, "Cert", "COMPLIANT")
        end
        if nmap.verbosity() > 1 then
            output_info.Certificate_Info = {}
            output_info.Certificate_Info = cert
        end
    end

    return output_info, stdnse.format_output(true, output_info)

end

postaction = function()
  local out = {}
  table.insert(out, "Host: Overall,HTTPS,HSTS,CIPHER")
  -- create a reverse mapping key_fingerprint -> host(s)
  for host, checks in pairs(nmap.registry.BOD1801) do
    stdnse.debug1(string.format("Host is %s.", host))
    stdnse.debug1(string.format("HTTP is %s.", checks.HTTP))
    stdnse.debug1(string.format("HTTPS is %s.", checks.HTTPS))
    stdnse.debug1(string.format("Cert is %s.", checks.Cert))
    stdnse.debug1(string.format("Redirect is %s.", checks.Redirect))
    stdnse.debug1(string.format("HSTS is %s.", checks.HSTS))
    stdnse.debug1(string.format("Ciphers is %s.", checks.Ciphers))
    local overall
    local https
    local redirect
    -- www.example.com: OVERALL,HTTPS,HSTS,CIPHER
    -- Overall = HTTPS, HSTS, Cipher
    -- Redirect = if HTTP, then Redirect
    -- HTTPS = Cert, HTTPS, and Redirect
    -- HSTS
    -- Cipher
    if checks.HTTP == "EXISTS" then
      -- There is an HTTP server
      if checks.Redirect == "COMPLIANT" then
        redirect = true
      else
        redirect = false
      end
    else
      -- There is no HTTP server so the redirect is compliant
      redirect = true
    end 
    if checks.HTTPS == "COMPLIANT" and checks.Cert == "COMPLIANT" and redirect then
      https = "COMPLIANT"
    else
      https = "FAILED"
    end
    local hsts = checks.HSTS
    local ciphers = checks.Ciphers
    if https == "COMPLIANT" and hsts == "COMPLIANT" and ciphers == "COMPLIANT" then
      overall = "COMPLIANT"
    else
      overall = "FALIED"
    end

    table.insert(out, string.format("%s: %s,%s,%s,%s", host, overall, https, hsts, ciphers))
  end
  return stdnse.format_output(true, out)
end

local ActionsTable = {
  -- portrule: retrieve ssh hostkey
  portrule = portaction,
  -- postrule: look for duplicate hosts (same hostkey)
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end