"""
Block Ciphers and Key Recovery Security Game
"""

import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *

"""
Problem: Let E be a blockcipher  E:{0, 1}^k x {0, 1}^n --> {0, 1}^n
and E_I be its inverse.
Define F: {0, 1}^k+n x {0, 1}^n --> {0, 1}^n as shown below.

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K1\in{0,1}^k and K2,M\in{0,1}^n
Adversaries are for the consistent key recovery game.
"""

def F(K, M):
    """
    Blockcipher F constructed from blockcipher E.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    K1 = K[:k_bytes]
    K2 = K[k_bytes:]

    C = E(K1, xor_strings(M, K2))
    return C

"""
    Solutions
"""

"""
    Below is a 1-query adversary A1 that has advantage
    Adv^kr_F(A1) = 1 and running time O(T_E + k + n).
"""

def A1(fn):
    """
    :param fn: This is the oracle supplied by GameKR; call this
    oracle to get an "encryption" of the data passed into it.
    """
    M = n_bytes * '\x00'
    C = fn(M)
    K1 = k_bytes * '\x01'
    K2 = xor_strings(E_I(K1, C),M)
    #print(K1)
    return K1 + K2

"""
    Below is a 3-query adversary A3 that has advantage Adv^kr_F(A3) = 1
    and running time O(2^k * (T_E + k + n)).
"""

def A3(fn):
    """
    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    """
    
    M1 = n_bytes * '\x00'
    M2 = n_bytes * '\x11'
    M3 = n_bytes * '\x01'
    
    C1 = fn(M1)
    C2 = fn(M2)
    C3 = fn(M3)
    
    for i in range(2**k):
        K1 = int_to_string(i, k_bytes)
        K2_1 = xor_strings(E_I(K1, C1), M1)
        K2_2 = xor_strings(E_I(K1, C2), M2)
        K2_3 = xor_strings(E_I(K1, C3), M3)
        
        if K2_1 == K2_2 and K2_2 == K2_3:
            return K1 + K2_1

    
"""
==============================================================================================
The following lines are used to test the adversary code
==============================================================================================
"""

from playcrypt.games.game_kr import GameKR
from playcrypt.simulator.kr_sim import KRSim

if __name__ == '__main__':

    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g1 = GameKR(1, F, k_bytes+n_bytes, n_bytes)
    s1 = KRSim(g1, A1)
    print("The advantage of your adversary A1 is approximately " + str(s1.compute_advantage(20)))

    # Smaller choices of k, n.
    k = 8
    n = 64
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g3 = GameKR(3, F, k_bytes+n_bytes, n_bytes)
    s3 = KRSim(g3, A3)
    print("The advantage of your adversary A3 is approximately " + str(s3.compute_advantage(20)))
