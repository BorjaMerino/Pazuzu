# RC4 random sbox
def rc4_sbox_random(value):
    print "[*] RC4 payload encryption... Random key: 0x%s" % value + value[::-1]
    key = [int(value[i:i + 2], 16) for i in range(0, len(value), 2)]
    # Change this as you please to get a key_len > 8
    key = key + key[::-1]
    key_len = key.__len__()
    sbox = range(256)
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % key_len]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


# RC4 keystreamm and XOR'ing
def rc4_encrypt(sbox, buffer):
    i = 0
    j = 0
    coded = []
    for x in range(len(buffer)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]  # swap

        r = sbox[(sbox[i] + sbox[j]) % 256]
        coded.append(ord(buffer[x]) ^ r)

    print "[*] Payload encrypted"
    return ''.join(chr(x) for x in coded)


def rc4_cipher(buffer, key):
    sbox = rc4_sbox_random(key)
    return rc4_encrypt(sbox, buffer)
