import math
import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.new_tools import *

from playcrypt.games.game_pke_lr import GamePKELR
from playcrypt.simulator.pke_lr_sim import PKELRSim

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
Problem:
Let K_rsa be a RSA generator with security parameter k >=1024.
Consider the key-generation algorithm K and encryption algorithm E defined below:
"""


def K():
    (N, p, q, e, d) = K_rsa(k)
    pk = (N, e)
    sk = (N, d)
    return (pk, sk)


def E(pk, M):
    """
    :param pk: The public key pk = (N, e) used to encrypt the message
    :param M: The plaintext to be encrypted, must be in Z_N^*
    :return: return the encryption of plaintext M
    """    
    (N, e) = pk                     # Parse pk as (N, e)
    if not in_Z_N_star(M, N):       # If M is not in Z_N^* 
        raise ValueError("Message not in appropriate domain.")     
    U = random_Z_N_star(N)          # Sample a random element U of Z_N^*
    V = MOD_EXP(U, e, N)            # V <- U^e mod N
    W = MOD(U * M, N)               # W <= (U * M) mod N
    return (V, W)

"""
Specify in pseudocode an O(k^3)-time decryption algorithm D such that
AE = (K, E, D) is an asymmetric encryption scheme satisfying the correct
decryption requirement, for messages that are in Z_N^* when the public key is (N, e).
"""
"""
    Solutions
"""
def D(sk, C):
    """
    :param sk: The secret key used to decrypt the message
    :param C: The ciphertext to be decrypted
    :return: return the decryption on the ciphertext C
    """
    (V, W) = C;
    (N, d) = sk
    V_p = MOD_EXP(V,d,N);
    W_p = MOD_INV(V_p, N);
    M = MOD(W * W_p, N);
    return M;

"""
Specify in pseudocode an O(k^3)-time adversary A1 making one query to
its LR oracle and achieving Adv_{AE}^{ind-cpa}(A1) = 1. Messages in the LR query
must be in Z_N^* when the public key is (N, e).
"""
"""
    Solutions
"""
def A1(lr, pk):
    """
    :param lr: This is the oracle supplied by the game.
    :param pk: This is the public key returned by the game's procedure Initialize.
    :return: return 1 to indicate your adversary believes it is the right world
    and return 0 to indicate that your adversary believes it is in the left world.
    """
    (N,e ) = pk;
    (V, W) = lr(2,1);
    if ( MOD_EXP(W,e,N) == V ):
        return 1;
    else:
        return 0;


"""
==============================================================================================
The following lines are used to test code.
==============================================================================================
"""
def main():
    def pk_gen():
            (pk,sk) = K()
            return pk

    worked = True
    global k
    k = 64
    for loop in range(100):
        (pk,sk) = K()
        (N,e) = pk
        M = random_Z_N_star(N)
        C = E(pk, M)
        if M != D(sk, C):
            print ("Your decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your decryption function appears correct.")

    gm = GamePKELR(1, 1, E, pk_gen)
    s = PKELRSim(gm, A1)
    print ("The advantage of your adversary A1 is approx. " + str(s.compute_advantage()))

if __name__ == "__main__":
    main()
