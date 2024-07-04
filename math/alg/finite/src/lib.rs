use modulo::Mod;
use core::ops::Sub;
use core::ops::Add;
#[derive(Debug, Clone)]
pub struct Fele{
    pub num: u64,
    pub prime: u64,
}

impl Fele{
    pub fn new(num: u64 , prime: u64)->Self{
        if num >= prime {
            panic!("num {} is not in field range 0 to {}", num, prime-1);
        }
        Self {
            num,
            prime
        }
    }
}
impl PartialEq for Fele{
    fn eq(&self, other: &Fele)->bool {
        self.num == other.num && self.prime == other.prime
    }
}

impl Add for Fele{
    type Output = Self;
    //type outp = Self;
    fn add (self, inp: Self)->Self::Output{
        if self.prime != inp.prime {
            panic!("Can't two elements from different fields");
        }
        let num = (self.num + inp.num).modulo(self.prime);
        Self {
            num,
            prime: self.prime,
        }

    }
}
impl  Sub for Fele{
    type Output = Self;
    fn sub (self, inp: Self)->Self::Output{
        if self.prime != inp.prime {
            panic!("Can't two elements from different fields");
        }
        let num = (self.num - inp.num).modulo(self.prime);
        Self {
            num,
            prime: self.prime,
        }

    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_two_field_ele() {
        let a = Fele::new(7, 13);
        let b = Fele::new(6, 13);
        assert_ne!(a, b);
        assert_eq!(a, a);
    }
    #[test]
    fn test_add(){
        let a = Fele::new(7, 13);
        let b = Fele::new(12, 13);
        let c = Fele::new(6, 13);

        assert_eq!(a+b, c);
    }
}
