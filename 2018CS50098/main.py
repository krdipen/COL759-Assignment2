import gmpy2 as mp

def encryptVigenere(m, vigKey):
    l = len(vigKey)
    temp = ""
    chunks = []
    for i in range(0, len(m)):
        temp += m[i]
        if(len(temp) == l):
            chunks.append(temp)
            temp = ""
    if(len(temp) != 0):
        chunks.append(temp)
    ret = ""
    for i in range(0, len(chunks)):
        for j in range(0, len(chunks[i])):
            ret += chr((ord(chunks[i][j])+ord(vigKey[j]) - 2*ord('A'))%26 + ord('A'))
    return ret

def decryptVigenere(c, vigKey):
    l = len(vigKey)
    temp = ""
    chunks = []
    for i in range(0, len(m)):
        temp += c[i]
        if(len(temp) == l):
            chunks.append(temp)
            temp = ""
    if(len(temp) != 0):
        chunks.append(temp)
    ret = ""
    for i in range(0, len(chunks)):
        for j in range(0, len(chunks[i])):

            ret += chr((ord(chunks[i][j]) - ord(vigKey[j]))%26 + ord('A'))
    return ret



def signByCA(k, d, n):
    return mp.powmod(k, d, n)

def getStrongPrimeNo(size):
    ret = mp.next_prime(2**size)
    while True:
        if (mp.is_strong_bpsw_prp(ret)):
            break
        else:
            ret = mp.next_prime(ret)
    return ret

def RSAKeyGeneration(size):
    p = getStrongPrimeNo(round(size/2))
    q = getStrongPrimeNo(round(size/2)+1)
    n = mp.mul(p, q)
    phi = mp.mul(p-1, q-1)
    e = 2**445 + 1
    while True:
        if (mp.gcd(e, phi)==1):
            break
        else:
            e += 2
    d = mp.invert(e, phi)
    return (e, n, d, p, q)



def unsignByCA(k):
    file = open("./public/public_ca.txt")
    t = file.read().split()
    e = mp.mpz(t[0])
    n = mp.mpz(t[1])
    return mp.powmod(k, e, n)

def validate(e2ca, n2ca, e2, n2):
    a = unsignByCA(mp.mpz(e2ca))
    b = unsignByCA(mp.mpz(n2ca))
    a1 = mp.mpz(e2)
    b1 = mp.mpz(n2)
    if(a == a1 and b == b1):
        return True
    else:
        return False


def getMsgChunks(m, blockSize):
    temp = ""
    chunks = []
    for i in range(0, len(m)):
        temp += m[i]
        if(len(temp) == blockSize):
            chunks.append(temp)
            temp = ""
    if(len(temp) == 0):
        return chunks
    while(len(temp) != blockSize):
        temp += 'A'
    chunks.append(temp)
    return chunks


    
def enRSA(text, ch):
    if ch == 'd':
        file = open("./private/private_a.txt", "r")
        t = file.read().split()
        file.close()
        d1ca = t[0]
        n1ca = t[1]
        d1 = t[2]
        n1 = t[3]
        if(not validate(d1ca, n1ca, d1, n1)):
            print("could not validate1")
            exit(1)
        d = unsignByCA(mp.mpz(d1ca))
        n = unsignByCA(mp.mpz(n1ca))
        key = d
        # print("d : "+str(d))
        # print("n : "+str(n))
    if(ch == 'e'):    
        file = open("./public/public_b.txt", "r")
        t = file.read().split()
        file.close()
        e2ca = t[0]
        n2ca = t[1]
        e2 = t[2]
        n2 = t[3]
        if(not validate(e2ca, n2ca, e2, n2)):
            print("Could not validate2")
            exit(1)
        e = unsignByCA(mp.mpz(e2ca))
        n = unsignByCA(mp.mpz(n2ca))
        key = e

    blockSize = 0
    while mp.mpz(26)**blockSize < n:
        blockSize+=1
    blockSize-=1
    chunks = getMsgChunks(text, blockSize)
    ret = []
    for chunk in chunks:
        msg = 0
        for i in range(0, blockSize):
            msg += mp.mul((ord(chunk[i])-ord('A')), mp.mpz(26)**(blockSize-1-i))
        ret.append(mp.powmod(mp.t_mod(msg, n), key, n))
    blockSize+=1
    finalret = ""
    for m in ret:
        rem = m
        for i in range(0, blockSize):
            quot, rem = mp.t_divmod(rem, mp.mpz(26)**(blockSize-1-i))
            finalret += chr(quot+ord('A'))
    return finalret


def deRSA(text, ch):
    if(ch == 'd'):
        file = open("./private/private_b.txt", "r")
        t = file.read().split()
        file.close()
        d2ca = t[0]
        n2ca = t[1]
        d2 = t[2]
        n2 = t[3]
        if(not validate(d2ca, n2ca, d2, n2)):
            print("could not validate3")
            exit(1)
        d = unsignByCA(mp.mpz(d2ca))
        n = unsignByCA(mp.mpz(n2ca))
        key = d
    if ch == 'e':
        file = open("./public/public_a.txt", "r")
        t = file.read().split()
        e2ca = t[0]
        n2ca = t[1]
        e2 = t[2]
        n2 = t[3]
        if(not validate(e2ca, n2ca, e2, n2)):
            print("Could not validate4")
            exit(1)
        e = unsignByCA(mp.mpz(e2ca))
        n = unsignByCA(mp.mpz(n2ca))
        key = e
    blockSize = 0
    while mp.mpz(26)**blockSize < n:
        blockSize+=1
    
    chunks = getMsgChunks(text, blockSize)
    ret = []
    for chunk in chunks:
        msg = 0
        for i in range(0, blockSize):
            msg += mp.mul((ord(chunk[i])-ord('A')), mp.mpz(26)**(blockSize-1-i))
        ret.append(mp.powmod(mp.t_mod(msg, n), key, n))
    
    finalret = ""
    blockSize-=1
    for m in ret:
        rem = m
        for i in range(0, blockSize):
            quot, rem = mp.t_divmod(rem, mp.mpz(26)**(blockSize-1-i))
            finalret += chr(quot+ord('A'))
    return finalret  


if __name__ == "__main__":
    file = open("./Input/vigKey.txt", 'r')
    vigKey = file.read()
    vigKey = vigKey.upper()
    file = open("./Input/Inp.txt", 'r')
    m1 = file.read()
    m = ""
    for i in range(0, len(m1)):
        if((m1[i] >= 'a' and m1[i] <= 'z') or (m1[i]>='A' and m1[i] <='Z')):
            m += m1[i]
    
    m = m.upper()
    #Create RSA keys for A, B and CA
    (eca, nca, dca, pca, qca) = RSAKeyGeneration(1027)
    file = open("./public/"+"public_ca.txt", "w")
    file.write(str(eca)+" "+str(nca))
    file.close()
    file = open("./private/"+"private_ca.txt", "w")
    file.write(str(dca)+" "+str(nca))
    file.close()

    (e1, n1, d1, p1, q1) = RSAKeyGeneration(1024)
    e1ca = signByCA(e1, dca, nca)
    n1ca = signByCA(n1, dca, nca)
    d1ca = signByCA(d1, dca, nca)
    p1ca = signByCA(p1, dca, nca)
    q1ca = signByCA(q1, dca, nca)
    file = open("./public/"+"public_a.txt", "w")
    file.write(str(e1ca)+" "+str(n1ca) + " " +str(e1)+" "+str(n1))
    file = open("./private/"+"private_a.txt", "w")
    file.write(str(d1ca)+" "+str(n1ca)+" "+str(d1)+" "+str(n1))
    
    (e2, n2, d2, p2, q2) = RSAKeyGeneration(1024)
    e2ca = signByCA(e2, dca, nca)
    n2ca = signByCA(n2, dca, nca)
    d2ca = signByCA(d2, dca, nca)
    p2ca = signByCA(p2, dca, nca)
    q2ca = signByCA(q2, dca, nca)
    file = open("./public/"+"public_b.txt", "w")
    file.write(str(e2ca)+" "+str(n2ca) + " " +str(e2)+" "+str(n2))
    file = open("./private/"+"private_b.txt", "w")
    file.write(str(d2ca)+" "+str(n2ca)+" "+str(d2)+" "+str(n2))
    file.close()
    #vigenere cipher
    ev = encryptVigenere(m, vigKey)

    #sending message
    evWithKey = chr(len(vigKey)+ord('A'))
    evWithKey += vigKey
    evWithKey += ev
    # print(evWithKey)
    envWithPvtKey = enRSA(evWithKey, 'd')
    envWithPublicKey = enRSA(envWithPvtKey, 'e')
    file = open("./public/sent_from_A.txt", "w")
    # print(envWithPublicKey)
    file.write(envWithPublicKey)
    file.close()

    #receiving from B
    file = open("./public/sent_from_A.txt", "r")
    enc = file.read()
    # print(enc)
    msg1 = deRSA(enc, 'd')
    msg = deRSA(msg1, 'e')
    a = msg[0]
    vigKeyLen = ord(a)-ord('A')
    vigKey = msg[1:vigKeyLen+1]
    content = msg[vigKeyLen+1:]    
    m2 = decryptVigenere(content, vigKey)
    file = open("received_msg.txt", "w")
    file.write(m2)
    file.close()

