import gmpy2
from gmpy2 import mpfr, floor, next_prime
def convert_primes_cube_fractional_part_to_hex_constant(prime, hex_chars=8):
    """
    Note if you want the first 8 decimal (base=10) digits of a number,
    you multiply the fractional part by 10**8 and then look at the integer part 
    In this case we want first 8 hex digits, so multiply fractional part by 16**8
    and then look at integer part (and return in hexadecimal).
    """
    cube_root = mpfr(prime)**(1/mpfr(3))
    frac_part = cube_root - floor(cube_root)
    # format_str = '%%0%dx' % hex_chars  

    # format_str will be '%08x' if hex_chars=8 so always emits 
    # 8 zero-padded hex digits 
    # return format_str % floor(frac_part*(16**hex_chars))
    strRet = "{0:1a}".format(floor(frac_part*(16**hex_chars)))
    # 0xc.19bf174p+28
    strRet = strRet[2:]
    strRet = strRet.replace(".","")
    # c19bf174p+28
    strRet = strRet[:strRet.index("p+")]
    # c19bf174
    while(len(strRet) < 8):
        strRet = "0" + strRet
    return strRet;


def generate_n_primes(n=64):
    p = 2
    i = 0
    while i < n:
        yield p
        p = next_prime(p)
        i += 1

# SHA-256 constants
# for i,p in enumerate(generate_n_primes(64)):
#     if i % 8 == 0:
#         print("")
#     print(convert_primes_cube_fractional_part_to_hex_constant(p, hex_chars=8), end=" ")

# SHA-512 constants
gmpy2.get_context().precision=100
for i,p in enumerate(generate_n_primes(80)):
    if i % 4 == 0:
        print("")
    print(convert_primes_cube_fractional_part_to_hex_constant(p, hex_chars=16), end=" ")