# Curvy

Writeup by: josteitv

## Introduction

I have previously been into a lot of applied cryptography when RSA was the industry standard, but when we slowly shifted towards elliptic curves I kinda jumped off the bandwagon. Since I have never before dived into the details of elliptic curve cryptography this challenge was an excellent opportunity to learn something about elliptic curves and their weaknesses.

The README tells me that the supplied scripts are meant to be run with [SageMath](https://www.sagemath.org). I have no previous knowledge about this program, so I quickly decided to get some help with the syntax and possible functions from Claude. But before consulting Claude I wanted to see what was actually happening in the source code to be able to get a grip of what was going on.

## Part 1

I started by looking at the script and quickly understood that I needed to go backwards from the supplied output of the program. I had the Q and the R, and could then easily calculate P by just subtracting.

After calculating P, I assumed I could then calculate the flag by doing the inverse of `P = E.lift_x(Integer(flag.hex(), 16))`.

Because I didn't know the SageMath syntax, I asked Claude AI for some help and it explained to me that the inverse was simply `x_coord = int(P[0])`

The rest was simply converting the x coordinate to an ASCII string and print it out.

I ran the script using the online [SageMathCell](https://sagecell.sagemath.org).

### Solution
```Sage
from sage.all import *

### These parameters are just setting up the elliptic curve and is not required to solve the challenge

# Elliptic curve parameters for the equation y^2 = x^3 + a256*x +b256 over the prime field p256. This is a NIST curve without known vulnerabilities
p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a256 = p256 - 3
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# Base point (x, y)
gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Curve order (number of unique points on the curve)
qq = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

E = EllipticCurve(GF(p256), [a256, b256])
E.set_order(qq)
### End of parameters

# Points
Q = E(43913347275644785153464449863125855125379958083706430882296801761478476592419, 
      87918631137632055279958341837479029765235140217346982045811500319683853700187)
R = E(104815116867883818417432576260090330353182680342988101131628182143341649757099, 
      47754550443389744842102740890992438457952225542439338525446667288370728104693)

# Calculate P
P = R - Q

print(f"P: {P}")
print(f"P.x: {P[0]}")

# Convert x coordinate to flag
x_coord = int(P[0])

# Convert to bytes and then ascii
flag_bytes = x_coord.to_bytes((x_coord.bit_length() + 7) // 8, 'big')
flag_ascii = flag_bytes.decode('ascii')

print(f"Flag: {flag_ascii}")
```

### Output 
```
P: (6638942044317376293647499143514648480160982067620050783 : 5855555663584138157198678789940449720542272943543592799673214067288456377828 : 1)
P.x: 6638942044317376293647499143514648480160982067620050783
Flag: EPT{n0W_y0u_Kn0w_4_f3w_
```

## Part 2

Part 2 of this challenge contains a new set of parameters and we again have to get backwards from the output to find the flag. But this time we are multiplying the numbers, making it much more difficult to get back to the original flag. There is a hint in the text implying that there is some sort of strange parameters that could help us.

To solve the problem `P = G * flag`, given `P` and `G`, we have to look at algorithms for solving the [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm). Using large prime factors this problem is considered to be computationally intractable. But the hint leads us to believe that we are not using large prime factors. When using small prime factors the order of the elliptic curve is called [smooth](https://en.wikipedia.org/wiki/Smooth_number), and this is considered a vulnerability.

To solve the discrete logarithm problem where the order is smooth we can use the [Pohlig–Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).

Luckily the SageMath function for solving discrete logarithm automatically applies this algorithm when it detects a smooth order. Thus we only have to call [`discrete_log()`](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html#sage.groups.generic.discrete_log).

I once again tried the solution on the online SageMathCell, but the discrete log function is somewhat computationally intensive and I did not get an answer before it timed out. I therefore had to install SageMath locally on my computer using the following commands:

```bash
$ curl -L -O "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"
$ bash Miniforge3-$(uname)-$(uname -m).sh
$ eval "$(~/miniforge3/bin/conda shell.bash hook)"
$ conda create -n sage sage python=3.11
$ conda activate sage
```

I later discovered that I could have used the SageMath [`log()`](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html#sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field.log) function, which runs much faster than [`discrete_log()`](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html#sage.groups.generic.discrete_log).

### Solution

```Sage
from sage.all import *

### This time the parameters a quite strange. Maybe this leads to a weakness?
Fp = GF(3383548089654669391553203464102735171188512652843421334636584693433923760273487421671271923) # The prime used for the field

# Curve definition: y^2 = x^3 + 1*x + 0
E = EllipticCurve(Fp, [1, 0])
order = 2^2 * 3 * 18479537^2 * 785027357 * 2045936509 * 2067106871 * 2477515409 * 2952556279^2 * 3393346153^2
E.set_order(order)

# Generator point
G = E.gens()[0]

# Target point
P = E(1281118003088691942395276660159286361906554886534524987631212446305199953978223477605046101, 2234211546389151676823620323130996132849234235234456998130554403469861833832111773630470326)

print(f"Curve order: {order}")
print(f"Order factors: {factor(order)}")

# Solve discrete logarithm (using Pohlig-Hellman algorithm)
k = discrete_log(P, G, operation='+')
#k = P.log(G) # This is faster!

# Verify key
print(f"Verification: G * k == P? {G * k == P}")

# Convert key/flag to ascii and print
flag_bytes = k.to_bytes((k.bit_length() + 7) // 8, 'big')
flag_ascii = flag_bytes.decode('ascii')
print(f"Flag: {flag_ascii}")
```

### Output

```bash
$ sage solution-2.sage
Curve order: 3383548089654669391553203464102735171188512652843421334636584693433923760273487421671271924
Order factors: 2^2 * 3 * 18479537^2 * 785027357 * 2045936509 * 2067106871 * 2477515409 * 2952556279^2 * 3393346153^2
Verification: G * k == P? True
Flag: 7h1ng5_4b0UT_el1ipTiC_
```

## Part 3

The third part of this challange gives a big hint about being SMART. The word SMART indicates that we should take a look at [Nigel Smart's algorithm](https://link.springer.com/article/10.1007/s001459900052) for solving the discrete logarithm problem on anomalous elliptic curves in polynomial time.

The documentation for the SageMath [`log()`](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html#sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field.log) function states that for anomalous curves, the [`padic_elliptic_logarithm()`](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html#sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field.padic_elliptic_logarithm)  function is called, which is leveraging [Nigel Smart's algorithm](https://link.springer.com/article/10.1007/s001459900052).

Thus using the `log()` function will solve this part as well.

### Solution

```Sage
from sage.all import *

### Well, since you're so SMART, I will pick invincible parameters this time!

p = 0xcd2f8f8881c7953d8439dde00b7d82002c2257aa400a3965d4a4e7f62c85dca1
a = 0x27f99f93bcf80afc8a7cb4a9659c3cb4857b081cceea0e7ae883c7ac27167ffa
b = 0x94b0a239ba09589d7d433c378af909311145623c138d001574a25dd43e0e7ee2

# Curve
E = EllipticCurve(GF(p), [a, b])
order = E.order()
assert is_prime(order)

print(f"Order: {order}")
print(f"p:     {p}")

# Generator point
G = E(0x5d9312f4e40090425dbc2879c4d3a4c8e300c1aefd4c74406b0d866380921929, 0xaf06cb0cd32376072b1aee0cd04cb7f643fb13dcfb44ec3ccb13a7b0e1067db3)

# Target point
P = E(46149471738217762494682535578618395972032151610828362576737479435252149474916, 37982107063220654423079127989899636852928253416608021485195608149289400914538)

# Solve discrete logarithm (using Smart's algorithm)
k = P.log(G)
# The log() function is using padic_elliptic_logarithm internally like this:
# k = G.padic_elliptic_logarithm(P, p)

# Verify key
print(f"Verification: G * k == P? {G * k == P}")

# Convert key/flag to ascii and print
flag_bytes = k.to_bytes((k.bit_length() + 7) // 8, 'big')
flag_ascii = flag_bytes.decode('ascii')
print(f"Flag: {flag_ascii}")
```

### Output
```bash
$ sage solution-3.sage
Order: 92808166401561920760015063710124546174021544921457548344823943060799017573537
p:     92808166401561920760015063710124546174021544921457548344823943060799017573537
Verification: G * k == P? True
Flag: cUrVes_af137dc886badc}
```

# Final solution

Putting all the parts together gives the flag: EPT{n0W_y0u_Kn0w_4_f3w_7h1ng5_4b0UT_el1ipTiC_cUrVes_af137dc886badc}

This was a really exciting challange which made me learn a lot about elliptic curves and some known weaknesses when choosing vulnerable keys. It also made me learn a bit about the mathematical software [SageMath](https://www.sagemath.org).

Thanks for this excellent challenge! 🎉