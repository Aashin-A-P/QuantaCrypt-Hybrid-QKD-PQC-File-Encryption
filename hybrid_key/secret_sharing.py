import secrets

# Large prime > 2^512
PRIME = 2**521 - 1


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _random_coeffs(k: int) -> list[int]:
    return [secrets.randbelow(PRIME) for _ in range(k - 1)]


def _eval_poly(coeffs: list[int], x: int, secret_int: int) -> int:
    # p(x) = secret + a1*x + a2*x^2 + ... mod PRIME
    res = secret_int
    power = x
    for a in coeffs:
        res = (res + a * power) % PRIME
        power = (power * x) % PRIME
    return res


def make_shamir_shares(secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    """
    Generate n Shamir shares with threshold k.
    Returns list of (x, y_bytes)
    """
    if not (2 <= k <= n):
        raise ValueError("Require 2 <= k <= n")

    secret_int = _bytes_to_int(secret)
    if secret_int >= PRIME:
        raise ValueError("Secret too large for chosen field; increase PRIME")

    coeffs = _random_coeffs(k)
    share_bytes_len = (PRIME.bit_length() + 7) // 8

    shares: list[tuple[int, bytes]] = []
    for x in range(1, n + 1):
        y = _eval_poly(coeffs, x, secret_int)
        y_bytes = _int_to_bytes(y, share_bytes_len)
        shares.append((x, y_bytes))

    return shares


def _lagrange_interpolate_zero(points: list[tuple[int, int]]) -> int:
    """
    Lagrange interpolation at x=0 over field mod PRIME.
    points: list of (x_i, y_i)
    """
    total = 0
    k = len(points)

    for i in range(k):
        xi, yi = points[i]
        li_num = 1
        li_den = 1
        for j in range(k):
            if i == j:
                continue
            xj, _ = points[j]
            li_num = (li_num * (-xj)) % PRIME
            li_den = (li_den * (xi - xj)) % PRIME

        inv_den = pow(li_den, PRIME - 2, PRIME)  # Fermat inverse
        li = (li_num * inv_den) % PRIME
        total = (total + yi * li) % PRIME

    return total


def reconstruct_shamir_secret(
    shares: list[tuple[int, bytes]],
    k: int,
    out_length: int
) -> bytes:
    """
    Reconstruct the original secret from any k shares.
    shares: list of (x, y_bytes)
    """
    if len(shares) < k:
        raise ValueError("Insufficient shares for reconstruction")

    # Use only first k shares given
    subset = shares[:k]
    pts: list[tuple[int, int]] = []
    for x, y_bytes in subset:
        y = _bytes_to_int(y_bytes)
        pts.append((x, y))

    secret_int = _lagrange_interpolate_zero(pts)
    # Reduce into the required byte-length range
    secret_int = secret_int % (1 << (8 * out_length))

    return _int_to_bytes(secret_int, out_length)
