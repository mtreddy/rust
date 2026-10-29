use std::env;

// Extended Euclid: returns (x, y) with a*x + b*y = gcd(a, b).
fn egcd(ia: i64, ib: i64) -> (i64, i64) {
    let mut a = ia;
    let mut b = ib;
    let mut x = 0;
    let mut last_x = 1;
    let mut y = 1;
    let mut last_y = 0;
    while b != 0 {
        let quot = a / b;
        (a, b) = (b, a % b);
        (x, last_x) = (last_x - quot * x, x);
        (y, last_y) = (last_y - quot * y, y);
    }
    (last_x, last_y)
}

// a / den mod p, i.e. a * den^-1 mod p (p prime, den not a multiple of p).
fn divmod(a: i64, den: i64, p: i64) -> i64 {
    let (inv, _) = egcd(den, p);
    (a * inv).rem_euclid(p)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(args);
    println!("coefs {:?}", egcd(240, 46));
    let q = divmod(3, 7, 11);
    println!("3 / 7 mod 11 = {q}  (check: 7 * {q} mod 11 = {})", 7 * q % 11);
}
