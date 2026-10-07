local ngx = ngx
local ngx_req = ngx.req
local ngx_header = ngx.header
local ngx_exit = ngx.exit
local NGX_HTTP_UNAUTHORIZED = ngx.HTTP_UNAUTHORIZED
local string_find = string.find
local string_sub = string.sub
local string_byte = string.byte
local base64_decode = ngx.decode_base64

-- WARNING: These are example credentials for demonstration purposes only.
-- In production, use a secure credential store and NEVER hardcode passwords.
local users = {
    admin = "admin123",
    user1 = "password1",
    test = "test123"
}

-- Constant-time string comparison to prevent timing attacks
local function constant_time_compare(a, b)
    if #a ~= #b then
        return false
    end
    local result = 0
    for i = 1, #a do
        result = bit.bor(result, bit.bxor(string_byte(a, i), string_byte(b, i)))
    end
    return result == 0
end

local function decode_base64_authorization(auth_header)
    if not auth_header then return nil end

    local prefix = "Basic "
    if string_find(auth_header, prefix) ~= 1 then
        return nil
    end

    local encoded = string_sub(auth_header, #prefix + 1)
    return base64_decode(encoded)
end

local function authenticate(credentials)
    if not credentials then return false end

    local colon_pos = string_find(credentials, ":")
    if not colon_pos then return false end

    local username = string_sub(credentials, 1, colon_pos - 1)
    local password = string_sub(credentials, colon_pos + 1)

    if users[username] and constant_time_compare(users[username], password) then
        return true
    end

    return false
end

local function basic_auth()
    local auth_header = ngx_req.get_headers()["Authorization"]

    if auth_header then
        local credentials = decode_base64_authorization(auth_header)
        if credentials and authenticate(credentials) then
            return false
        end
    end

    ngx_header["WWW-Authenticate"] = 'Basic realm="Secure Area"'
    ngx_exit(NGX_HTTP_UNAUTHORIZED)
    return true, true
end

local _M = {
    version = 0.1,
    name = "basic-auth",
    priority = 1
}

function _M.req_pre_filter(waf)
    return basic_auth()
end

return _M