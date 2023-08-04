iv = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e
MAX = 2**32


def strtobin(msg):
    l = len(msg)
    s_dec = 0
    for m in msg:
        s_dec = s_dec << 8
        s_dec += ord(m)

    msg_bin = bin(s_dec)[2:].zfill(l * 8)
    return msg_bin


def inttobin(a, k):
    return bin(a)[2:].zfill(k)


def inttohex(a, k):
    return hex(a)[2:].zfill(k)


def bintohex(a, k):
    return hex(int(a, 2))[2:].zfill(k)


def msg_fill(msg_bin):
    l = len(msg_bin)
    k = 448 - (l + 1) % 512
    if k < 0:
        k += 512

    l_bin = inttobin(l, 64)
    msg_filled = msg_bin + '1' + '0' * k + l_bin

    return msg_filled


def iteration_func(msg):
    n = len(msg) // 512
    b = []
    for i in range(n):
        b.append(msg[512 * i:512 * (i + 1)])

    v = [inttobin(iv, 256)]
    for i in range(n):
        v.append(cf(v[i], b[i]))

    return bintohex(v[n], 64)


def msg_extension(bi):
    w = []
    for j in range(16):
        w.append(int(bi[j * 32:(j + 1) * 32], 2))

    for j in range(16, 68):
        w_j = p1(w[j - 16]
                 ^ w[j - 9] ^ rotate_left(w[j - 3], 15)) ^ rotate_left(
                     w[j - 13], 7) ^ w[j - 6]
        w.append(w_j)

    w1 = []
    for j in range(64):
        w1.append(w[j] ^ w[j + 4])

    return w, w1


def cf(vi, bi):
    w, w1 = msg_extension(bi)

    t = []
    for i in range(8):
        t.append(int(vi[i * 32:(i + 1) * 32], 2))
    a, b, c, d, e, f, g, h = t

    for j in range(64):
        ss1 = rotate_left(
            (rotate_left(a, 12) + e + rotate_left(t_j(j), j)) % MAX, 7)
        ss2 = ss1 ^ rotate_left(a, 12)
        tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) % MAX
        tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) % MAX
        d = c
        c = rotate_left(b, 9)
        b = a
        a = tt1
        h = g
        g = rotate_left(f, 19)
        f = e
        e = p0(tt2)

    vi_1 = inttobin(a, 32) + inttobin(b, 32) + inttobin(c, 32) + inttobin(d, 32) \
        + inttobin(e, 32) + inttobin(f, 32) + inttobin(g, 32) + inttobin(h, 32)
    vi_1 = int(vi_1, 2) ^ int(vi, 2)

    return inttobin(vi_1, 256)


def rotate_left(a, k):
    k = k % 32
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))


def p0(x):
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17)


def p1(x):
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23)


def t_j(j):
    return 0x79cc4519 if j < 16 else 0x7a879d8a


def ff(x, y, z, j):
    if j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)


def gg(x, y, z, j):
    if j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | ((x ^ 0xFFFFFFFF) & z)


def sm3_hash(msg):
    s_bin = strtobin(msg)

    s_fill = msg_fill(s_bin)

    s_sm3 = iteration_func(s_fill)

    return s_sm3
