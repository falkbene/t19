import dataclasses
import hashlib
from Crypto.Protocol.KDF import bcrypt

@dataclasses.dataclass
class HtpasswdEntry:
    username: str
    alg: str
    salt: bytes
    hash: bytes

# .htpasswd files use base64 encoding with different characters :/
sha1_basis_64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
bcrypt_basis_64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def base64_decode(h: str, basis_64):
    h = h.rstrip("=") # Remove padding
    conversion_num = [basis_64.index(x) for x in h]

    leftchar = 0
    leftbits  = 0
    out = bytearray()
    while conversion_num:
        i = conversion_num.pop(0)
        leftchar = leftchar << 6 | i
        leftbits += 6
        if leftbits >= 8:
            leftbits -= 8
            out.append(leftchar >> leftbits)
            leftchar &= ((1 << leftbits) -1)
    return bytes(out)

def base64_encode(data: bytes, basis_64):
    data = bytearray(data)
    encoded = ""
    for i in range(0, len(data), 3):
        chunk = data[i:i+3]

        encoded += basis_64[(chunk[0] >> 2) & 0x3f]
        if len(chunk) > 1:
            encoded += basis_64[((chunk[0] & 0x3) << 4) | ((chunk[1] & 0xf0) >> 4)]
            if len(chunk) > 2:
                encoded += basis_64[((chunk[1] & 0xf) << 2) | ((chunk[2] & 0xc0) >> 6)]
                encoded += basis_64[chunk[2] & 0x3f]
            else:
                encoded += basis_64[((chunk[1] & 0xf) << 2)]
                encoded += "="
        else:
            encoded += basis_64[((chunk[0] & 0x3) << 4)]
            encoded += "=="

    return encoded

def parse_htpasswd_line(line):
    user, pwdata = line.split(":")
    if pwdata[:4] == "$2y$":
        alg, salt, hash = "bcrypt", base64_decode(pwdata[7:7+22], bcrypt_basis_64), base64_decode(pwdata[7+22:], bcrypt_basis_64)
    elif pwdata[:6] == "$apr1$":
        alg, salt, hash = "md5", pwdata.split("$")[2], pwdata.split("$")[3]
    elif pwdata[:5] == "{SHA}":
        alg, salt, hash = "sha1", None, base64_decode(pwdata[5:], sha1_basis_64)
    else:
        raise Exception("Invalid htpasswd format")

    return HtpasswdEntry(user, alg, salt, hash)

def to64(v, n):
    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    encoded = ""
    for _ in range(n):
        encoded += itoa64[v & 0x3f]
        v >>= 6

    return encoded

def md5_hash(username, password, salt):
    """ Apache md5 variant that uses 1000 iterations to hash passwords"""
    # Apache also accepts the entire hash entry as "salt" parameter but we do not here, we simply expect the salt string 

    # Refine the salt first
    ctx = hashlib.md5()
    ctx.update(password.encode())
    ctx.update(b"$apr1$")
    ctx.update(salt.encode())

    ctx1 = hashlib.md5()
    ctx1.update(password.encode())
    ctx1.update(salt.encode())
    ctx1.update(password.encode())
    ctx1_dig = ctx1.digest()
    pl = len(password)
    while pl > 0:
        ctx.update(ctx1_dig[:16] if pl > 16 else ctx1_dig[:pl])
        pl -= 16

    i = len(password)
    while i != 0:

        if i & 1:
            ctx.update(b"\x00")
        else:
            ctx.update(password.encode()[:1])
        i >>= 1

    final = ctx.digest()

    for i in range(1000):
        ctx1 = hashlib.md5()
        if i & 1:
            ctx1.update(password.encode())
        else:
            ctx1.update(final)

        if i % 3:
            ctx1.update(salt.encode())

        if i % 7:
            ctx1.update(password.encode())

        if i & 1:
            ctx1.update(final)
        else:
            ctx1.update(password.encode())

        final = ctx1.digest()

    encoded_md5_hash = ""
    l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; encoded_md5_hash += to64(l, 4)
    l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; encoded_md5_hash += to64(l, 4)
    l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; encoded_md5_hash += to64(l, 4)
    l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; encoded_md5_hash += to64(l, 4)
    l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; encoded_md5_hash += to64(l, 4)
    l =                    final[11]                ; encoded_md5_hash += to64(l, 2)

    return f"{username}:$apr1${salt}${encoded_md5_hash}"

def bcrypt_hash(username, password, salt):
    bcrypt_hash = bcrypt(password, 5, salt).decode()
    
    # Fixup bcrypt version, $2a$ had a bug in the php implementation - not relevant here
    return f"{username}:{bcrypt_hash}".replace("$2a$", "$2y$")

def sha1_hash(username, password):
    sha1_hash = hashlib.sha1(password.encode()).digest()
    encoded_sha1_hash = base64_encode(sha1_hash, sha1_basis_64)
    return f"{username}:{{SHA}}{encoded_sha1_hash}"
