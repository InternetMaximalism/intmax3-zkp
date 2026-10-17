from pathlib import Path
q = 2_013_265_921
n = 2048
t = 256
delta = q // t
assert q == t * delta + 1
per_term_error = 4*n + 2
num_terms = 65  # one fresh balance plus64 allowed added credits
max_error = num_terms * per_term_error
assert num_terms < t
assert max_error < delta // 2

def decode_digit(digit, error):
    value = (delta * digit + error) % q
    return ((value * t + q//2) // q) % t

# Independent signed-integer inequality for exact round-trip. The expression
# floor((256E - d + floor(q/2))/q) must be0. It is monotone in E,
# so checking both allowed endpoints proves every intermediate integer error.
for digit in range(t):
    assert 0 <= -t*max_error - digit + q//2
    assert t*max_error - digit + q//2 < q
    for error in [-max_error, -8194, -1, 0, 1, 8194, max_error]:
        assert decode_digit(digit,error) == digit
    for error in [-(delta//2-1), delta//2-1]:
        assert decode_digit(digit,error) == digit

# u128 accumulation used by decode_amount never overflows its accumulator.
max_weighted = (t-1)*((1<<64)-1)
assert max_weighted < (1<<72)
print(f'q={q}; t={t}; delta={delta}; remainder={q-t*delta}')
print(f'fresh noise bound={per_term_error};65-term noise bound={max_error}; strict common rounding radius={delta//2-1}')
print('PASS all256 digits: exact endpoint inequalities establish rounding for every error within the65-term budget')
print('PASS scalar native rounding formula at endpoints and representative errors; negative noise wraps to digit0')
print(f'PASS max weighted low64digit sum={max_weighted} <2^72 <2^128')
