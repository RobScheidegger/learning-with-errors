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