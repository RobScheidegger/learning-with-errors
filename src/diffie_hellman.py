import random

from homomorphic_encryption_scheme import *
from typing import Tuple
from number_theory import inverse


class DiffieHellman(HomomorphicEncryptionScheme):
    """
    Basic implementation of a (non-fully) homomorphic Diffie-Hellman Scheme.
    """
    
    def __init__(self, p: int, q: int, g: int) -> None:
        self.p = p
        self.q = q
        self.g = g
    
    def generate_keypair(self) -> Tuple[SecretKey, PublicKey]:
        a = random.randint(0, self.q)
        A = pow(self.g, a, self.p)
        return (a, A)
    
    def encrypt(self, k_p: PublicKey, m: Message) -> Ciphertext:
        r = random.randint(0, self.q)
        g_r = pow(self.g, r, self.p)
        h_r = pow(k_p, r, self.p)
        return (g_r, h_r * m % self.p)
    
    def decrypt(self, k_s: SecretKey, c: Ciphertext) -> Message:
        g_r, h_r_m = c
        h_r = pow(g_r, k_s, self.p)
        return (c * inverse(h_r, self.p)) % self.p
    
    def add(self, c_1: Ciphertext, c_2: Ciphertext) -> Message:
        c_11, c_12 = c_1
        c_21, c_22 = c_2
        return (c_11 * c_21 % self.p, c_12 * c_22 % self.p)
