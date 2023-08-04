from gmssl import sm3, func
import SM3
import struct

pad_str = ""
pad = []


def padding(msg):
    mlen = len(msg)
    msg.append(0x80)
    mlen += 1
    tail = mlen % 64
    range_end = 56
    if tail > range_end:
        range_end = range_end + 64
    for i in range(tail, range_end):
        msg.append(0x00)
    bit_len = (mlen - 1) * 8
    msg.extend([int(x) for x in struct.pack('>q', bit_len)])
    for j in range(int((mlen - 1) / 64) * 64 + (mlen - 1) % 64, len(msg)):
        global pad
        pad.append(msg[j])
        global pad_str
        pad_str += str(hex(msg[j]))
    return msg


def attack(msghash, length, msgappend):
    vectors = []
    message = ""
    for r in range(0, len(msghash), 8):
        vectors.append(int(msghash[r:r + 8], 16))

    if length > 64:
        for _ in range(0, int(length / 64) * 64):
            message += 'a'
    for _ in range(0, length % 64):
        message += 'a'
    message = func.bytes_to_list(bytes(message, encoding='utf-8'))
    message = padding(message)
    message.extend(func.bytes_to_list(bytes(msgappend, encoding='utf-8')))
    return SM3.sm3_hash(message, vectors)


def verify(msg, msgappend):
    msg = bytes(msg, encoding='utf-8')
    msgappend = bytes(msgappend, encoding='utf-8')
    return sm3.sm3_hash(func.bytes_to_list(msg + msgappend))


def main():

    msg = '000111'
    hashedMsg = sm3.sm3_hash(func.bytes_to_list(bytes(msg.encode())))
    length = len(msg)
    msgAppend = 'msgappend'

    newHash = attack(hashedMsg, length, msgAppend)
    newMsg = func.bytes_to_list(bytes(msg, encoding='utf-8'))
    newMsg.extend(pad)
    newMsg.extend(func.bytes_to_list(bytes(msgAppend, encoding='utf-8')))
    hashSupposed = sm3.sm3_hash(newMsg)

    print("Origin msg: ", msg)
    print("Origin hash: ", hashedMsg)
    print("New msg: ", (msg + msgAppend))
    print("New hash     : ", newHash)
    print("Supposed hash: ", hashSupposed)
    print(newHash == hashSupposed)


main()
