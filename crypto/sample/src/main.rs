use std::env;

fn egcd(ia:i32, ib:i32) ->(i32, i32){
    let mut a = ia;
    let mut b = ib;
    let mut x = 0;
    let mut last_x =1;
    let mut y = 1;
    let mut last_y = 0;
    while b != 0 {
        let quot = a/b;
        (a, b) = (b, a%b);
        (x, last_x) = (last_x - quot * x, x);
        (y, last_y) = (last_y - quot * y, y);

    }
        
        (last_x, last_y)
}
fn divmod(a:i32, den:i32, p:i32) {
    let pair:(i32, i32) = egcd(den, p);
    a * pair.0;
}

fn main() {
    println!("Hello, RNG!");
    let args: Vec<String> = env::args().collect();
    dbg!(args);
    println!("coefs {:?}",divmod(240, 46));
}
