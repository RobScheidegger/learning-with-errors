import random
import argparse

from abc import ABC, abstractmethod
from typing import TypeVar, Tuple, Type, Callable

Message = TypeVar("Message")
Ciphertext = TypeVar("Ciphertext")
SecretKey = TypeVar("SecretKey")
PublicKey = TypeVar("PublicKey")
SchemeParameters = TypeVar("SchemeParameters")

################# Number Theory Utilities #################

def inverse(a: int, m: int) -> int:
    """
    Computes the modular inverse of a modulo m.
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


class DiffieHellman:
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

# Type aliases for elements of polynomial rings for the BFW scheme.

def make_ring(n: int, m: int) -> Type:
    """
    Creates a polynomial ring R_n = Z_n[x]/(x^m + 1).
    """
    class R:
        """
        Representation of the polynomial ring R_n = Z_n[x]/(x^m + 1).
        """
        
        def __init__(self, coefficients: list[int]) -> None:
            """
            Coefficients are given in low-to-high order in terms of polynomial degree (i.e. [a_0, a_1, ..., a_{m-1}])
            """
            self.c = [(c + n) % n for c in coefficients]
            self.n = n
            self.m = m
            self.reduce_modulo()
            
        def reduce_modulo(self) -> None:
            """
            Reduces the coefficients so that the  
            """
            # The length of the coefficient should never be more than or equal to 2m at the start of this call.
            assert len(self.c) < 2 * self.m
            
            C = len(self.c)
            c_new = [0] * self.m
            for i in reversed(range(len(self.c))):
                if i >= self.m:
                    # We need to eliminate this part of the polynomial by reducing modulo x^m + 1.
                    # This means for every coefficient c_i, we need to add c_{i - m} * x^m to c_i.
                    # This really means that we subtract c_{i - m} from c_i.
                    c_new[i - self.m] -= self.c[i]
                else:
                    c_new[i] += self.c[i]
                    
            self.c = [c % self.n for c in c_new]
            
            assert len(self.c) == self.m
        
        def negate(self):
            """
            Negates the polynomial.
            """
            return R([(-a + n) % n for a in self.c])    
        
        def scalar_multiply(self, a: int):
            """
            Multiplies the polynomial by a scalar.
            """
            return R([(a * b) % self.n for b in self.c])
        
        def make_gaussian_error(sigma: float):
            """
            Generates a sample from the Gaussian error distribution that is gaussian in each polynomial coordinate of R_Q.
            """
            return lambda: R([int(random.gauss(0, sigma)) % n for _ in range(m)])
        
        def __add__(self, other):
            assert self.n == other.n
            return R([(a + b) % self.n for a, b in zip(self.c, other.c)])
        
        def __mul__(self, other):
            assert self.n == other.n
            new_c = [0] * (2 * self.m - 1)
            for i, a in enumerate(self.c):
                for j, b in enumerate(other.c):
                    new_c[i + j] += a * b
            return R(new_c)
        
        def __eq__(self, other):
            return self.c == other.c
        
        def __repr__(self):
            return f"R_{self.n}({self.c})"

    return R

def sample_gaussian_error(sigma: float, n: int, m: int) -> list[int]:
    """
    Generates a sample from the Gaussian error distribution that is gaussian in each polynomial coordinate of R_n.
    """
    return [abs(int(random.gauss(0, sigma))) % n for _ in range(m)]

def sample_from_ring(R, n, m) -> list[int]:
    """
    Generates a random sample from the ring R.
    """
    return R([random.randint(0, n - 1) for _ in range(m)])


class BFV:
    """
    Representation of the BFV encryption scheme.
    """
    
    def __init__(self, sigma: float, q: int, m: int, t: int) -> None:
        self.delta = q // t
        self.q = q
        self.m = m
        self.t = t
        
        self.R_Q = make_ring(q, m)
        self.R_T = make_ring(t, m)
        
        self.chi = lambda: self.R_Q(sample_gaussian_error(sigma, q, m))
        
    def generate_keypair(self) -> Tuple[SecretKey, PublicKey]:
        s = self.chi()
        a = sample_from_ring(self.R_Q, self.q, self.m)
        e = self.chi()
        
        pk = ((a * s + e).negate(), a)
        sk = s
        
        return (sk, pk)

    
    def encrypt(self, k_p: PublicKey, m: Message) -> Ciphertext:
        """
        Encrypts a message.
        """
        pk0, pk1 = k_p
        u = self.chi()
        e_1 = self.chi()
        e_2 = self.chi()
        m_in_q = self.R_Q(m.c)
        c1 = pk0 * u + e_1 + m_in_q.scalar_multiply(self.delta)
        c2 = pk1 * u + e_2
        
        return (c1, c2)

    def decrypt(self, k_s: SecretKey, c: Ciphertext) -> Message:
        """
        Decrypts a message.
        """
        s = k_s
        c_0, c_1 = c
        d = c_0 + c_1 * s
        
        coefficients = d.c
        reduced_coefficients = [round((c * self.t) / self.q) for c in coefficients]
        
        return self.R_T(reduced_coefficients)
    
    def add(self, c_1: Ciphertext, c_2: Ciphertext) -> Ciphertext:
        """
        Adds two ciphertexts.
        """
        return (c_1[0] + c_2[0], c_1[1] + c_2[1])

def make_graphs():
    print("Running experiments and making graphs...")
    
    import matplotlib.pyplot as plt
    
    
    
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser("BFV Encryption Scheme")
    arg_parser.add_argument("--sigma", type=float, default=4.0)
    arg_parser.add_argument("-q", type=int, default=40102)
    arg_parser.add_argument("-m", type=str, default="Test Message")
    arg_parser.add_argument("-t", type=int, default=256)
    arg_parser.add_argument("-g", default=False, action="store_true")
    
    args = arg_parser.parse_args()
    
    if args.g:
        make_graphs()
        exit()
    
    bfv = BFV(args.sigma, args.q, len(args.m), args.t)
    
    # Encode the message into R_T
    m = bfv.R_T([ord(c) for c in args.m])
    
    sk, pk = bfv.generate_keypair()
    c = bfv.encrypt(pk, m)
    m_prime = bfv.decrypt(sk, c)
    
    print("Encoded Message:", m)
    print("Encrypted Message:", c)
    print("Decrypted Message:", m_prime)
    print("Decoded Message:", "".join([chr(c) for c in m_prime.c]))
    