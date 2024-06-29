

// gcd
fn gcd(mut a: i32 , mut b: i32)->i32{
    let mut t: i32  = 0;
    while a > 0 && b > 0 {
        if a > b {
            t = b;
            b = a%b;
            a = t
        }
    }
    if a == 0 {
        b;
    }
    return a;
}


fn main() {
    println!("print math output");
    let mut var: i32 = 4;
    var = var.pow(4);
    println!("{}", var); 
    let mut a: i32 = 60;
    let mut b: i32 = 36;
    println!("gcd for {} {} is {}", a, b, gcd(a,b));
}
