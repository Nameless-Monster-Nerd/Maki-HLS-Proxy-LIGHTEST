local _M = {}

local ffi = require "ffi"
local C = ffi.C
local resty_random = require "resty.random"
local cjson = require "cjson.safe"

ffi.cdef[[
typedef struct EVP_CIPHER_CTX EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
const EVP_CIPHER *EVP_aes_256_cbc(void);
]]

local KEY_HEX = os.getenv("ENCRYPTION_KEY") or ""
local KEY_BUF = nil
local ENABLED = false

local function hex_to_bytes(hex)
    if not hex or #hex == 0 then return nil end
    if #hex % 2 ~= 0 then return nil end
    local bytes = {}
    for i = 1, #hex, 2 do
        local b = tonumber(hex:sub(i, i + 1), 16)
        if not b then return nil end
        bytes[#bytes + 1] = string.char(b)
    end
    return table.concat(bytes)
end

local raw_key = hex_to_bytes(KEY_HEX)
if raw_key and #raw_key == 32 then
    KEY_BUF = ffi.new("unsigned char[32]")
    ffi.copy(KEY_BUF, raw_key, 32)
    ENABLED = true
elseif KEY_HEX ~= "" then
    ngx.log(ngx.ERR, "ENCRYPTION_KEY must be 64 hex chars (32 bytes). Encryption disabled.")
end

function _M.enabled()
    return ENABLED
end

local function b64url_encode(s)
    local b64 = ngx.encode_base64(s)
    b64 = b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
    return b64
end

local function b64url_decode(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

local function aes_encrypt(plaintext, iv_bytes)
    local ctx = C.EVP_CIPHER_CTX_new()
    if ctx == nil then return nil, "ctx alloc failed" end

    local iv_buf = ffi.new("unsigned char[16]")
    ffi.copy(iv_buf, iv_bytes, 16)

    local cipher = C.EVP_aes_256_cbc()
    local out = ffi.new("unsigned char[?]", #plaintext + 32)
    local outl = ffi.new("int[1]")

    if C.EVP_EncryptInit_ex(ctx, cipher, nil, KEY_BUF, iv_buf) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "init failed"
    end

    if C.EVP_EncryptUpdate(ctx, out, outl, plaintext, #plaintext) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "update failed"
    end
    local total = tonumber(outl[0])

    if C.EVP_EncryptFinal_ex(ctx, out + total, outl) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "final failed"
    end
    total = total + tonumber(outl[0])

    C.EVP_CIPHER_CTX_free(ctx)
    return ffi.string(out, total)
end

local function aes_decrypt(ciphertext, iv_bytes)
    local ctx = C.EVP_CIPHER_CTX_new()
    if ctx == nil then return nil, "ctx alloc failed" end

    local iv_buf = ffi.new("unsigned char[16]")
    ffi.copy(iv_buf, iv_bytes, 16)

    local cipher = C.EVP_aes_256_cbc()
    local out = ffi.new("unsigned char[?]", #ciphertext + 16)
    local outl = ffi.new("int[1]")

    if C.EVP_DecryptInit_ex(ctx, cipher, nil, KEY_BUF, iv_buf) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "init failed"
    end

    if C.EVP_DecryptUpdate(ctx, out, outl, ciphertext, #ciphertext) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "update failed"
    end
    local total = tonumber(outl[0])

    if C.EVP_DecryptFinal_ex(ctx, out + total, outl) ~= 1 then
        C.EVP_CIPHER_CTX_free(ctx)
        return nil, "final failed (bad key or corrupt data)"
    end
    total = total + tonumber(outl[0])

    C.EVP_CIPHER_CTX_free(ctx)
    return ffi.string(out, total)
end

-- Encrypt a {url, headers} pair into a single opaque token
function _M.encrypt_payload(url, headers)
    if not ENABLED then return nil end
    local json = cjson.encode({ u = url, h = headers or {} })
    if not json then return nil end

    local iv = resty_random.bytes(16)
    if not iv or #iv ~= 16 then return nil end

    local ct, err = aes_encrypt(json, iv)
    if not ct then
        ngx.log(ngx.ERR, "encrypt failed: ", err)
        return nil
    end
    return b64url_encode(iv .. ct)
end

-- Decrypt a token into url, headers
function _M.decrypt_payload(token)
    if not ENABLED then return nil, nil, "encryption disabled" end
    if not token or token == "" then return nil, nil, "no token" end

    local blob = b64url_decode(token)
    if not blob or #blob <= 16 then return nil, nil, "bad token" end

    local iv = blob:sub(1, 16)
    local ct = blob:sub(17)

    local pt, err = aes_decrypt(ct, iv)
    if not pt then return nil, nil, err end

    local data = cjson.decode(pt)
    if not data or not data.u then return nil, nil, "bad payload" end
    return data.u, data.h or {}, nil
end

return _M
