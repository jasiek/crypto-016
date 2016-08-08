MESSAGES = [m.rstrip().decode('hex') for m in open("messages").readlines()]
CIPHERTEXT = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

def hex2bin(hexstring):
    return hexstring.decode('hex')

def bin2hex(binstring):
    return binstring.encode('hex')

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

howmany = len(MESSAGES)
xored = {}

def similar(bina, binb):
    xored = strxor(bina, binb)

    def count_zeros(sum, char):
        if ord(char) == 0:
            return sum + 1
        else:
            return sum

    return reduce(count_zeros, xored, 0)

def sorted_by_difference():
    similarity = []
    for i in xrange(howmany):
        for j in xrange(i, howmany):
            similarity.append(i, j, similarity(MESSAGES[i], MESSAGES[j]))

    def metric(a):
        _, _, z = a
        return z

    return sorted(similarity, key=metric)

print sorted_by_difference()

    
