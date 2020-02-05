local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Checks for the web portion of BOD 18-01:
  * All publicly accessible Federal websites and web services provide service through a secure connection (HTTPS-only, with HSTS),
  * SSLv2 and SSLv3 are disabled on web servers, and
  * 3DES and RC4 ciphers are disabled on web servers.

  References: https://cyber.dhs.gov/bod/18-01/
  https://https.cio.gov/guide/

]]

---
-- @usage
-- nmap -p <port> --script http-bod18-01 <target>
--
-- @output
---

author = {"Rick Miner"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
    local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
    local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
    local request_type = "HEAD"
    local status = false
    local result
  
    -- Check if the user didn't want HEAD to be used
    if(useget == nil) then
      -- Try using HEAD first
      status, result = http.can_use_head(host, port, nil, path)
    end
  
    -- If head failed, try using GET
    if(status == false) then
      stdnse.debug1("HEAD request failed, falling back to GET")
      result = http.get(host, port, path)
      request_type = "GET"
    end
  
    if not (result and result.status) then
      return fail("Header request failed")
    end
  
    table.insert(result.rawheader, "(Request type: " .. request_type .. ")")

    table.insert(result.rawheader, "(Status: " .. result['status'] .. ")")

    result.rawheader.Locations = result.location
  
    return stdnse.format_output(true, result.location)
  end