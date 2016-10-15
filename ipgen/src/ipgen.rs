// Generates list of IP address
use std::net::Ipv4Addr;
use std::iter;
use std::str::FromStr;

pub fn ip_range(from: Ipv4Addr, to: Ipv4Addr) -> IpIterator {
    IpIterator::new(from, to)
}

#[derive(Debug)]
pub struct IpIterator {
    from: u32,
    to: u32,
    shift: u32,
}

impl Iterator for IpIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        let ip = self.from
            .checked_add(self.shift)
            .and_then(|next_ip| if next_ip <= self.to {
                Some(next_ip)
            } else {
                None
            })
            .map(|next_ip| Ipv4Addr::from(self.from + self.shift));
        self.shift += 1;
        ip
    }
}

impl IpIterator {
    pub fn from_ip<T: Into<u32>>(from: T, length: u32) -> Option<IpIterator> {
        let from = from.into();
        from.checked_add(length).map(|last_ip| {
            IpIterator {
                from: from,
                to: last_ip - 1,
                shift: 0,
            }
        })
    }

    pub fn new<T: Into<u32>>(from: T, to: T) -> IpIterator {
        IpIterator {
            from: from.into(),
            to: to.into(),
            shift: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use ipgen::ip_range;
    use std::net::Ipv4Addr;
    use ipgen::IpIterator;

    #[test]
    fn ip_range_should_return_iterator_that_coluld_be_transformed_to_vec() {
        let ip_vec: Vec<Ipv4Addr> = ip_range(Ipv4Addr::new(192, 168, 1, 1),
                                             Ipv4Addr::new(192, 168, 1, 10))
            .collect();
        assert_eq!(ip_vec.len(), 10);
    }

    #[test]
    fn first_and_last_ip_included() {
        let ip_vec: Vec<Ipv4Addr> = ip_range(Ipv4Addr::new(192, 168, 1, 1),
                                             Ipv4Addr::new(192, 168, 1, 10))
            .collect();
        assert_eq!(ip_vec[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(*ip_vec.last().unwrap(), Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn could_be_generated_from_ip() {
        let ip_vec: Vec<Ipv4Addr> = IpIterator::from_ip(Ipv4Addr::new(192, 168, 1, 1), 30)
            .unwrap()
            .collect();
        assert_eq!(ip_vec.len(), 30);
    }

    #[test]
    fn could_be_iterated() {
        for ip in IpIterator::from_ip(Ipv4Addr::new(192, 168, 1, 1), 1).unwrap() {
            assert!(ip != Ipv4Addr::new(192, 168, 1, 2));
        }
    }
}
