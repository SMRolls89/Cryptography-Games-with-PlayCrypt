import math
import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.new_tools import *
from playcrypt.games.game_ufcma import GameUFCMA
from playcrypt.simulator.ufcma_sim import UFCMASim

def ADD(a,b):
    return a+b
def MULT(a,b):
    return a*b
def INT_DIV(a,N):
    return (a//N, a%N)
def MOD(a,N):
    return a%N
def EXT_GCD(a,N):
    return egcd(a,N)
def MOD_INV(a,N):
    res = modinv(a,N)
    if res == None:
        raise ValueError("Inverse does not exist.")
    return res
def MOD_EXP(a,n,N):
    return exp(a,n,N)

"""
Problem 1:
Let p>=3 be a prime and g \in Z_p^* be a generator of Z_p^*.
We define below the key generation algorithm K1 and the encryption algorithm E1.
The message M must be in Z_p^*, meaning the message space is Z_p^I. Let k be the bit-length
"""

def K1():
    x = random_Z_N_star(p - 1)
    X = MOD_EXP(g, x, p)
    sk = x
    pk = X
    return (pk, sk)

def E1(pk,M):
    X = pk
    if not in_Z_N_star(M, p):           # if M not in Z_p^I then return fail
        raise ValueError("Message not in appropriate domain")
    y = random_Z_N_star(p - 1)          # Assign to y a random element of Z_{p-1}^*
    Y = MOD_EXP(g, y, p)                # Y <- g^y mod p
    Z = MOD_EXP(X, y, p)                # Z <- X^y mod p = (g^x)^y mod p
    W = MOD(Y * M, p)                   # W <- (Y * M) mod p
    return (Z, W)

"""
Let j be the bit-length of p. Specify an O(j^3)-time decryption algorithm D1 such that
AE1 = (K1, E1, D1) is an asymmetric encryption scheme satisfying the correct decryption
property.
"""
"""
    Solutions
"""

def D1(sk, C):
    """
    :param sk: The secret key used to decrypt the message
    :param C: The ciphertext to be decrypted
    :return: return the decryption on the ciphertext C
    """
    Z, W = C
    sk_inverse = MOD_INV(sk, p-1)    
    Y = MOD_EXP(Z, sk_inverse, p)
    Y_inverse = MOD_INV(Y, p)
    M = (W * Y_inverse) % p
    
    return M

"""
Problem 2:
Let q be a k-bit prime such that p = 2*q + 1 is also prime, and assume
k >= 2048. Let g \in Z_p^* be a generator of Z_p^*.(These are public quantities, known
to all parties including the adversary.) We will define variables p, q and g for you.
Consider the family of functions T : Z_{p-1}^* x Z_{p-1}^* -> Z_p^* defined below:
"""

def T(K, M):
    """
    :param K: The public key that is in Z_{p-1}^*
    :param M: The plaintext that must be in Z_{p-1}^*
    :return: return the output of the family of functions.
    """
    if not in_Z_N_star(M,p-1):
        raise ValueError("Message not in appropriate domain.")
    if not in_Z_N_star(K,p-1):
        raise ValueError("Key not in appropriate domain.")
    w = MOD(MULT(M,K), p-1)
    x = MOD_INV(w, p-1)
    Y = MOD_EXP(g,x,p)
    return Y

"""
The message M must be in Z_{p-1}^*, meaning only elements of Z_{p-1}^* are allowed as
messages. We let k be the bit-length of q.

Specify an O(k^3)-time adversary A making one Tag query such that Adv_{T}^{uf-cma}(A) = 1.
The message in the Tag query, and the one returned by A, must be in Z_{p-1}^*.
"""
"""
    Solutions
"""
def A(tag):
    """
    :param tag: This is an oracle supplied by GameUFCMA, you can call this
    oracle to get a "tag" for the data you pass into it.
    """
    z = MOD_INV(3,p-1)
    T_1 = tag(1)
    T_3 = MOD_EXP(T_1,z,p)
    return (3,T_3)  

"""
==============================================================================================
The following lines are used to test code.
==============================================================================================
"""
def V(K, M, t):
    if T(K, M) == t:
        return 1
    else:
        return 0

def kgen():
    return random_Z_N_star(p-1)

def main():
    print("When j=16:")
    j = 16
    global p,g
    p = prime_between(2**(j-1),2**j)
    g = find_generator_Z_N_star(p)

    worked = True
    for loop in range(100):
        (pk,sk) = K1()
        M = random_Z_N_star(p)
        C = E1(pk, M)
        if M != D1(sk, C):
            print ("Your first decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your first decryption function appears correct.")

    sys.setrecursionlimit(2000)

    s="%s%s%s%s%s%s%s%s%s" % (
        "105769031300962262347041907699188531986468080875168500291924909352726",
        "523514845129707954505966025516424111093772977370588541844230910553861",
        "654594521893564682962587494595327088018194062158369048764578647394423",
        "878171592936776203779788139029433508667038014539146349807292798552653",
        "558648914249755271208710270667471762323995019920493552915437914409534",
        "037901781078867071136428476829769041285776781721175931798108515586171",
        "194767580162162682727491216460561250733810235821601248338156562332774",
        "779512075289235506520068278611847500719701594730286561581764577491123",
        "045250981621775358501843358439025539644963902870293437315451576463")

    s1="%s%s%s%s%s%s%s%s%s" % (
        "528845156504811311735209538495942659932340404375842501459624546763632",
        "617574225648539772529830127582120555468864886852942709221154552769308",
        "272972609467823414812937472976635440090970310791845243822893236972119",
        "390857964683881018898940695147167543335190072695731749036463992763267",
        "793244571248776356043551353337358811619975099602467764577189572047670",
        "189508905394335355682142384148845206428883908605879658990542577930855",
        "973837900810813413637456082302806253669051179108006241690782811663873",
        "897560376446177532600341393059237503598507973651432807908822887455615",
        "22625490810887679250921679219512769822481951435146718657725788231")

    p = int(s)
    q = int(s1)
    g = 5

    gm = GameUFCMA(1, T, V, None, kgen)
    s = UFCMASim(gm, A)

    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))


if __name__ == "__main__":
    main()
