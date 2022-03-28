"""
Block ciphers, key recovery, and hash functions
"""
from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.function_family import *
from playcrypt.games.game_cr import GameCR
from playcrypt.simulator.cr_sim import CRSim
from playcrypt.ideal.block_cipher import BlockCipher


"""
Problem 1:
Let F be a family of functions  F:{0, 1}^k x {0, 1}^n --> {0, 1}^n.
Define Enc: {0, 1}^k x {0, 1}^(mn) --> {0, 1}^((m+2)*n) as shown below.
The message space of Enc is the set of all strings M whose length is an
integer multiple of n. 

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K\in{0,1}^k.
"""

def Enc(K, M):
    """
    Encryption algorithm Enc constructed from function family F.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    M = split(M,n_bytes)
    M= [chr(0)*n_bytes]+M
    R = [random_string(n_bytes) for i in range(2)]
    C = [R[i] for i in range(2)]
    d = [ord(R[1][-1]) % 2] # d[0] <- lsb(C[0] = lsb(R0||R1) = lsb(R1)
    for i in range(1,len(M)): 
        Wi = xor_strings(R[d[i-1]], M[i-1])
        Pi = F(K,Wi)
        C.append(xor_strings(Pi,M[i]))
        d.append(ord(C[-1][-1]) %2) # C[-1] denotes the last block of C. 
    return join(C)

"""
    Solutions
"""

"""
    Below is a decryption algorithm Dec such that SE = (K,Enc,Dec) is a 
    symmetric encryption scheme.
"""

def Dec(K,C):
    """
    :param K: This is the secret key for the decryption algorithm. It is an n-bit string
    :param C: This is the ciphertext to decrypt. 
    :return: return a plaintext string.
    """
    M = [chr(0)*n_bytes]
    R0 = C[:n_bytes]
    R1 = C[n_bytes:n_bytes*2] #<--- C = R0 || R1??
    CT = split(C[n_bytes*2:], n_bytes)
    R = [R0, R1]
    d = [ord(R[1][-1]) % 2]
    
    for i in range(1, len(CT)+1):
        Wi = xor_strings(R[d[i-1]], M[i-1])
        Pi = F(K,Wi)
        M.append(xor_strings(Pi, CT[i-1]))
        d.append(ord(CT[i-1][-1]) %2)
        
    return join(M[1:])
"""
    Below is a 1-query adversary A that has advantage Adv^ind-cpa_SE(A) >= 0.9
    and running time O(T_F + n).
"""

def A(fn):
    """
    :param fn: This is the LR oracle supplied by GameIND-CPA, you can call this
    oracle with two messages to get an "encryption" of either the left or right message.
    :return: return a bit that represents a guess of the secret bit b.
    """
    M = ["\x00"*n_bytes, "\x11"*n_bytes, "\x01"*n_bytes]
    C = fn(join(M), "\x00"*n_bytes*3)
    CT = split(C[n_bytes*2:], n_bytes)
    
    if (CT[0] == CT[1]):
        return 1
    if (CT[0] == CT[2]):
        return 1    
    if (CT[1] == CT[2]):
        return 1
    else: 
        return 0

"""
Problem 2:
Let E: {0,1}^k x {0,1}^l -> {0,1}^l be a block cipher (with inverse E_I) and let
T_E denote the time to compute E or E_I. Let D be the set of all strings whose
length is a positive multiple of l.

Define the hash function H1: {0,1}^k x D -> {0,1}^l via the CBC construction:
"""
"""
    Solutions
"""

def H1(K, M):
    """
    Hash function.

    :param K: Key used by the hash function, must be of size k_bytes
    :param M: Message hashed by the function, must be of length n * l_bytes
    """

    M = split(M, l_bytes)
    C = ["\x00" * l_bytes]

    for B in M:
        C += [E(K, xor_strings(C[-1], B))]

    return C[-1]

"""
    Below shows that H1 is not collision resistant by presenting an O(T_E + l) time
    adversary A1 with Adv^cr_H(A)=1.
"""

def A1(K):
    """
    :param K: This is the key used as the seed to the provided hash function
    :return: Return 2 messages, M1 and M2, that your adversary believes collide
    """

    return None, None

"""
Define the hash function H2: {0,1}^k x D -> {0,1}^l:
"""

def H2(K, M):
    """
    Hash function.

    :param K: Key used by the hash function, must be of size k_bytes
    :param M: Message hashed by the function, must be of length n * l_bytes
    """

    M = split(M, l_bytes)
    W = []
    C = ["\x00" * l_bytes]

    for B in M:
        W += [E(K, xor_strings(C[-1], B))]
        C += [E(K, xor_strings(W[-1], B))]

    return C[-1]

"""
    Below Shows that H2 is not collision resistant by presenting an O(T_E + l) time
    adversary A2 with Adv^cr_H(A)=1.
"""

def A2(K):
    """
    :param K: This is the key used as the seed to the provided hash function
    :return: Return 2 messages, M1 and M2, that your adversary believes collide
    """

    return None, None

"""
========================================================================================
Code below this line is used to test solution.
========================================================================================
"""
from playcrypt.games.game_lr import GameLR
from playcrypt.simulator.lr_sim import LRSim
from playcrypt.ideal.function_family import FunctionFamily

if __name__ == '__main__':
    print("--- Problem 1 ---")
    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k//8
    n_bytes = n//8

    FF = FunctionFamily(k_bytes, n_bytes, n_bytes)
    F = FF.evaluate

    g = GameLR(1, Enc, k_bytes)
    s = LRSim(g, A)

    # test decryption
    worked = True
    for j in range(100):
        K = random_string(k_bytes)
        num_blocks = random.randrange(n_bytes*8)
        M = random_string(num_blocks*n_bytes)
        C = Enc(K, M)
        if M != Dec(K, C):
            print ("Your decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your decryption function appears correct.")
    try:
        print ("The advantage of your adversary A1 is approximately " + str(s.compute_advantage(20)))
    except ValueError as e:
        print("Error computing advantage:", e)

    print()
    print("--- Problem 2 ---")

    # Case 1: k = l = 128
    k = 128
    l = 128
    k_bytes = k//8
    l_bytes = l//8
    EE = BlockCipher(k_bytes, l_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g1 = GameCR(H1, k_bytes)
    s1 = CRSim(g1, A1)

    g2 = GameCR(H2, k_bytes)
    s2 = CRSim(g2, A2)

    print("When k=128, l=128:")
    print("The advantage of your adversary A1 is ~" + str(s1.compute_advantage()))
    print("The advantage of your adversary A2 is ~" + str(s2.compute_advantage()))

    # Case 2: k = 64 ; l = 16
    k = 64
    l = 16
    k_bytes = k//8
    l_bytes = l//8
    EE = BlockCipher(k_bytes, l_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g1 = GameCR(H1, k_bytes)
    s1 = CRSim(g1, A1)

    g2 = GameCR(H2, k_bytes)
    s2 = CRSim(g2, A2)

    print("\nWhen k=64, l=16:")
    print("The advantage of your adversary A1 is ~" + str(s1.compute_advantage()))
    print("The advantage of your adversary A2 is ~" + str(s2.compute_advantage()))
