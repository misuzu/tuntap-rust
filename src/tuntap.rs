use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::prelude::AsRawFd;
use std::path::Path;
use libc::{c_int, c_char, AF_INET, AF_INET6, SOCK_DGRAM, socket, ioctl, close,
           sockaddr_in, sa_family_t, sockaddr, in_addr, in6_addr};
use c_interop::*;

const DEVICE_PATH: &'static str = "/dev/net/tun";

const MTU_SIZE: usize = 1500;


#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TunTapType {
    Tun,
    Tap,
}

pub struct TunTap {
    pub file: File,
    if_name: [u8; IFNAMSIZ],
}

impl fmt::Debug for TunTap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tun({})", self.get_name())
    }
}

impl TunTap {
    pub fn new(typ: TunTapType, name: &str) -> TunTap {
        let (file, if_name) = TunTap::create_if(typ, name);
        TunTap {
            file: file,
            if_name: if_name,
        }
    }

    pub fn get_name(&self) -> String {
        let nul_pos = match self.if_name.iter().position(|x| *x == 0) {
            Some(p) => p,
            None => panic!("Device name should be null-terminated"),
        };
        CString::new(&self.if_name[..nul_pos]).unwrap().into_string().unwrap()
    }

    fn create_if(typ: TunTapType, name: &str) -> (File, [u8; IFNAMSIZ]) {
        let name_c = &CString::new(name).unwrap();
        let name_slice = name_c.as_bytes_with_nul();
        if name_slice.len() > IFNAMSIZ {
            panic!("Interface name too long, max length is {}", IFNAMSIZ - 1);
        }

        let path = Path::new(DEVICE_PATH);
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Err(why) => panic!("Couldn't open tun device '{}': {:?}", path.display(), why),
            Ok(file) => file,
        };

        let mut req = ioctl_flags_data {
            ifr_name: {
                let mut buffer = [0u8; IFNAMSIZ];
                buffer[..name_slice.len()].clone_from_slice(name_slice);
                buffer
            },
            ifr_flags: match typ {
                TunTapType::Tun => IFF_TUN | IFF_NO_PI,
                TunTapType::Tap => IFF_TAP | IFF_NO_PI,
            },
        };

        let res = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if res < 0 {
            panic!("{}", io::Error::last_os_error());
        }

        TunTap::up(req.ifr_name);

        (file, req.ifr_name)
    }

    fn create_socket(sock_type: i32) -> c_int {
        let sock = unsafe { socket(sock_type, SOCK_DGRAM, 0) };
        if sock < 0 {
            panic!("{}", io::Error::last_os_error());
        }
        sock
    }

    fn up(if_name: [u8; IFNAMSIZ]) {
        let sock = TunTap::create_socket(AF_INET);

        let mut req = ioctl_flags_data {
            ifr_name: if_name,
            ifr_flags: 0,
        };


        let res = unsafe { ioctl(sock, SIOCGIFFLAGS, &mut req) };
        if res < 0 {
            unsafe { close(sock) };
            panic!("{}", io::Error::last_os_error());
        }

        if req.ifr_flags & IFF_UP & IFF_RUNNING != 0 {
            // Already up
            return;
        }

        req.ifr_flags |= IFF_UP | IFF_RUNNING;

        let res = unsafe { ioctl(sock, SIOCSIFFLAGS, &mut req) };
        if res < 0 {
            unsafe { close(sock) };
            panic!("{}", io::Error::last_os_error());
        }
        unsafe { close(sock) };
    }

    pub fn add_ipv4_addr(&self, addr: Ipv4Addr) {
        let octets = addr.octets();
        let sock = TunTap::create_socket(AF_INET);
        let sock_addr = sockaddr_in {
            sin_family: AF_INET as sa_family_t,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: (((octets[0] as u32) << 24) |
                         ((octets[1] as u32) << 16) |
                         ((octets[2] as u32) <<  8) |
                          (octets[3] as u32)).to_be(),
            },
            sin_zero: [0, 0, 0, 0, 0, 0, 0, 0],
        };

        let mut req = in_ifreq {
            ifr_name: self.if_name,
            ifr_addr: sock_addr,
        };

        let res = unsafe { ioctl(sock, SIOCSIFADDR, &mut req) };
        if res < 0 {
            unsafe { close(sock) };
            panic!("{}", io::Error::last_os_error());
        }
        unsafe { close(sock) };
    }

    pub fn add_ipv6_addr(&self, addr: Ipv6Addr) {
        let segments = addr.segments();
        let mut ifr6_addr: in6_addr = unsafe { mem::zeroed() };
        ifr6_addr.s6_addr = [
            (segments[0] >> 8) as u8, segments[0] as u8,
            (segments[1] >> 8) as u8, segments[1] as u8,
            (segments[2] >> 8) as u8, segments[2] as u8,
            (segments[3] >> 8) as u8, segments[3] as u8,
            (segments[4] >> 8) as u8, segments[4] as u8,
            (segments[5] >> 8) as u8, segments[5] as u8,
            (segments[6] >> 8) as u8, segments[6] as u8,
            (segments[7] >> 8) as u8, segments[7] as u8,
        ];
        let sock = TunTap::create_socket(AF_INET6);
        let mut req = ioctl_ifindex_data {
            ifr_name: self.if_name,
            ifr_ifindex: -1,
        };
        let res = unsafe { ioctl(sock, SIOCGIFINDEX, &mut req) };
        if res < 0 {
            unsafe { close(sock) };
            let err = io::Error::last_os_error();
            panic!("{}", err);
        }
        let mut req = in6_ifreq {
            ifr6_addr: ifr6_addr,
            ifr6_prefixlen: 8,
            ifr6_ifindex: req.ifr_ifindex,
        };
        let res = unsafe { ioctl(sock, SIOCSIFADDR, &mut req) };
        if res < 0 {
            unsafe { close(sock) };
            panic!("{}", io::Error::last_os_error());
        }
        unsafe { close(sock) };
    }

    pub fn set_mac(&self, mac: [u8; 6]) {
        let sock = TunTap::create_socket(AF_INET);
        let mut req = ioctl_mac {
            ifr_name: self.if_name,
            ifr_addr: sockaddr {
                sa_family: 0x01 as sa_family_t,
                sa_data: [0; 14],
            },
        };
        for (i, b) in mac.iter().enumerate() {
            req.ifr_addr.sa_data[i] = *b as c_char;
        }
        let res = unsafe { ioctl(sock, SIOCSIFHWADDR, &req) };
        if res < 0 {
            unsafe { close(sock) };
            panic!("{}", io::Error::last_os_error());
        }
        unsafe { close(sock) };
    }

    pub fn add_address(&self, addr: IpAddr) {
        match addr {
            IpAddr::V4(value) => self.add_ipv4_addr(value),
            IpAddr::V6(value) => self.add_ipv6_addr(value),
        }
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(buffer.len() >= MTU_SIZE);

        let len = try!(self.file.read(buffer));
        Ok(len)
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)
    }
}
