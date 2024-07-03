#[derive(Debug, Clone)]
pub struct Fele{
    pub num: u64,
    pub prime: u64,
}

impl Fele{
    pub fn new(num: u64 , prime: u64)->Fele{
        if num >= prime {
            panic!("num {} is not in field range 0 to {}", num, prime-1);
        }
        Fele {
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
}
