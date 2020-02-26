local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local url = require "url"
local tls = require "tls"

description = [[
Checks for BOD 18-01 Web compliance:

* HTTPS Only (with redirects)
* HSTS
* Certificate validation
* Cipher (SSLv2, SSLv3, RC4, 3DES) Checking

]]

---
-- @usage
-- nmap -p <port> --script http-bod1801 <target>
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-security-headers:
-- |   Strict_Transport_Security:
-- |     Header: Strict-Transport-Security: max-age=15552000; preload
--
--
-- @xmloutput
-- <table key="Strict_Transport_Policy">
-- <elem>Header: Strict-Transport-Security: max-age=31536000</elem>
-- </table>
-- <table key="Public_Key_Pins_Report_Only">
-- <elem>Header: Public-Key-Pins-Report-Only: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; report-uri="http://example.com/pkp-report"; max-age=10000; includeSubDomains</elem>
-- </table>
-- <table key="X_Frame_Options">
-- <elem>Header: X-Frame-Options: DENY</elem>
-- <elem>Description: The browser must not display this content in any frame.</elem>
-- </table>
--
-- @args http-security-headers.path The URL path to request. The default path is "/".
---

author = {"Rick Miner"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

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
    if hostname:match(cn:gsub("%.",'%%.'):gsub("*",".+")) then return true end
    for name in san:gmatch("DNS:(.-),") do
        if hostname:match(name:gsub("%.",'%%.'):gsub("*",".+")) then return true end
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
        o.validity[k] = stdnse.format_timestamp(v)
        end
    end
    return o
end

action = function(host, port)
    local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
    local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
    local request_type = "HEAD"
    local response
    local result
    local locations
    local uri
    local hsts
    local output_info = {}
    local req_opt = {redirect_ok=function(host,port)
        local c = 5
        return function(uri)
        if ( c==0 ) then return false end
        c = c - 1
        return true
        end
    end}

    -- Check if the user didn't want HEAD to be used
    if(useget == nil) then
        -- Try using HEAD first
        stdnse.debug1("Attempting to get HEAD first.")
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

    output_info = stdnse.output_table()
    output_info.BOD1801_Results = {}

    if shortport.ssl(host,port) then
        table.insert(output_info.BOD1801_Results, "Redirect: COMPLIANT, no HTTP")
        response = result
        uri = url.parse("https://" .. host.targetname .. ":" .. port.number .. path)
    else
        -- check for a redirect
        if nmap.verbosity() > 1 then
            output_info.Redirect_Info = {}
            table.insert(output_info.Redirect_Info, "HTTP Status: " .. trim(result["status-line"]))
        end
        if tostring( result.status ):match( "30%d" ) and result.header and result.header.location then
            -- This is a 30x redirect
            if request_type == "GET" then
                response = http.get(host, port, path, req_opt)
            else
                response = http.head(host, port, path, req_opt)
            end
            if not (response and response.status) then
                table.insert(output_info.BOD1801_Results, "Redirect: FAILED, redirect failed")
            else
                locations = response.location
                if nmap.verbosity() > 1 then output_info.Redirect_Info.Locations = locations end
                uri = url.parse( locations[#locations] )
                if uri.scheme == "https" then
                    if uri.port == nil then uri.port = "443" end
                    table.insert(output_info.BOD1801_Results, "Redirect: COMPLIANT")
                else
                    if uri.port == nil then uri.port = "80" end
                    table.insert(output_info.BOD1801_Results, "Redirect: FAILED, redirect not HTTPS")
                end
            end
        else
            -- This is not a redirect
            table.insert(output_info.BOD1801_Results, "Redirect: FAILED, not 301/302 redirect")
        end
    end

    -- Check HSTS header
    if response.header['strict-transport-security'] then
        if nmap.verbosity() > 1 then
            output_info.HSTS_Info = {}
            table.insert(output_info.HSTS_Info, "Strict-Transport-Security: " .. response.header['strict-transport-security'])
        end
        hsts = tonumber(string.match(response.header['strict-transport-security'], "%d+"))
        if hsts >= 31536000 then
            table.insert(output_info.BOD1801_Results, "HSTS: COMPLAINT")
        else
            table.insert(output_info.BOD1801_Results, "HSTS: " .. hsts .. " is too short, 31536000 is min")
        end
    elseif shortport.ssl(host,port) then
        if nmap.verbosity() > 1 then
            output_info.HSTS_Info = {}
            table.insert(output_info.HSTS_Info, "HSTS not configured on HTTPS Server")
        end
    end

    -- Get certificate information
    local status, cert = getCertificate(uri.host, uri.port)
    if ( not(status) ) then
        if nmap.verbosity() > 1 then
            output_info.Certificate_Info = {}
            table.insert(output_info.Certificate_Info, "Certificate: " .. cert)
        end
    else
        cert = output_tab(cert)
        local error_str = ""
        if not(check_hostname(uri.authority, cert.subject, cert.subject_alternative_name)) then
            error_str = error_str .. ", hostname mismatch"
        end
        local expire = makeTimeStamp(cert.validity.notAfter)
        if expire - os.time() < 0 then error_str = error_str .. ", expired certificate" end
        if error_str:len() > 0 then
            table.insert(output_info.BOD1801_Results, "Certificate: FAILED" .. error_str)
        else
            table.insert(output_info.BOD1801_Results, "Certificate: COMPLIANT")
        end
        if nmap.verbosity() > 1 then
            output_info.Certificate_Info = {}
            output_info.Certificate_Info = cert
        end
    end

    return output_info, stdnse.format_output(true, output_info)

end

