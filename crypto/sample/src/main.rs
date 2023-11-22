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

fn main() {
    println!("Hello, RNG!");
    let args: Vec<String> = env::args().collect();
    dbg!(args);
    println!("coefs {:?}",egcd(240, 46));
}
