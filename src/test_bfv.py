from bfv import *

def test_ring_addition():
    R = make_ring(5, 3)
    a = R([1, 2, 3])
    b = R([4, 5, 6])
    c = a + b
    assert c.c == [0, 2, 4]
    
def test_ring_multiplication():
    R = make_ring(5, 3)
    a = R([1, 0, 1])
    b = R([0, 1, 0])
    c = a * b
    # (1 + x^2) x = x + x^3 = x - 1 = x + 4
    assert c.c == [4, 1, 0]
    
def test_basic_bfv():
    Q = 1382
    T = 10
    M = 3
    bfv = BFV(1.0, Q, M, T)
    sk, pk = bfv.generate_keypair()
    
    m = bfv.R_T([1, 2, 3])
    
    c = bfv.encrypt(pk, m)
    assert bfv.decrypt(sk, c) == m
    
def test_medium_bfv():
    Q = 1382413143
    T = 1124
    M = 6
    bfv = BFV(100.0, Q, M, T)
    sk, pk = bfv.generate_keypair()
    
    m = bfv.R_T([1, 2, 3, 4, 5, 6])
    c = bfv.encrypt(pk, m)
    assert bfv.decrypt(sk, c) == m
    
    # Test homomorphic addition
    m2 = bfv.R_T([6, 5, 4, 3, 2, 1])
    c2 = bfv.encrypt(pk, m2)
    c3 = bfv.add(c, c2)
    assert bfv.decrypt(sk, c3) == bfv.R_T([7, 7, 7, 7, 7, 7])
    
def test_random_addition():
    Q = 10**10
    T = 10**5
    M = 100
    bfv = BFV(100.0, Q, M, T)
    
    sk, pk = bfv.generate_keypair()
    
    for _ in range(10):
        m = bfv.R_T([random.randint(0, T - 1) for _ in range(M)])
        c = bfv.encrypt(pk, m)
        assert bfv.decrypt(sk, c) == m
        
        m2 = bfv.R_T([random.randint(0, T - 1) for _ in range(M)])
        c2 = bfv.encrypt(pk, m2)
        c3 = bfv.add(c, c2)
        assert bfv.decrypt(sk, c3) == (m + m2)
    