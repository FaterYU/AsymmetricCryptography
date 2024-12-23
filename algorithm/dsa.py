import random
import hashlib


class DSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.generate_key()

    def is_prime(self, n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        def witness(a, d, n):
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                return True
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    return True
            return False

        for _ in range(k):
            a = random.randint(2, n - 2)
            if not witness(a, d, n):
                return False
        return True

    def get_prime(self, n):
        max_value = 2 ** (n - 1) - 1
        min_value = 2 ** (n - 2)
        while True:
            p = 1 + 2 * random.randint(min_value, max_value)
            if self.is_prime(p):
                return p

    def generate_key(self):
        self.hash = hashlib.sha256()
        L = 1024
        N = 160
        p = 0
        while not self.is_prime(p):
            q = self.get_prime(N)
            p = 2 * q + 1
        g = 0
        while True:
            h = random.randint(2, p - 1)
            g = pow(h, (p - 1) // q, p)
            if g != 1:
                break
        x = random.randint(1, q)
        y = pow(g, x, p)
        self.public_key = (p, q, g, y)
        self.private_key = x

    def sign(self, message):
        p, q, g, y = self.public_key
        x = self.private_key
        k = 0
        r = 0
        s = 0
        while True:
            while True:
                k = random.randint(1, q)
                r = pow(g, k, p) % q
                if r != 0:
                    break
            k_inv = pow(k, q - 2, q)
            m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
            s = (k_inv * (m + x * r)) % q
            if s != 0:
                break
        return (r, s)

    def verify(self, message, signature):
        p, q, g, y = self.public_key
        r, s = signature
        if r < 0 or r > q or s < 0 or s > q:
            return False
        w = pow(s, -1, q)
        m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        u1 = (m * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        return v == r


if __name__ == '__main__':

    message = 'Hello, world!'

    dsa = DSA()
    signature = dsa.sign(message)
    verify = dsa.verify(message, signature)

    print('Message:', message)
    print('Signature:', signature)
    print('Verify:', verify)
