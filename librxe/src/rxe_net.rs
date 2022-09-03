use std::cell::RefCell;
use std::mem::size_of;
use std::rc::Rc;

use crate::rxe_hdr::RxePktInfo;
use crate::rxe_opcode::{rxe_hdr_mask, RXE_OPCODE_INFO};
use crate::rxe_qp::RxeQueuePair;
use crate::rxe_verbs;
use bytes::BytesMut;
use etherparse::{IpHeader::*, PacketHeaders, TransportHeader::*, UdpHeader};
use nix::sys::socket::{self, MsgFlags};
use tracing::debug;

impl RxePktInfo {
    /// Receive UDP pacekt
    /// Separate IBA packet from UDP payload
    ///
    pub fn rxe_udp_recv(udp_skb: &[u8]) -> Self {
        let udp_hdr = UdpHeader::from_slice(udp_skb).unwrap();
        let iba_paylen = udp_hdr.0.length - (std::mem::size_of::<UdpHeader>() as u16);
        let mut pkt_info = RxePktInfo {
            rxe: None,
            qp: None,
            wqe: None,
            hdr: BytesMut::from(udp_hdr.1),
            mask: rxe_hdr_mask::RXE_GRH_MASK,
            psn: u32::MAX,
            pkey_index: u16::MAX,
            paylen: iba_paylen,
            port_num: 1,
            opcode: u8::MAX,
        };
        pkt_info.opcode = pkt_info.bth_opcode();
        pkt_info.psn = pkt_info.bth_psn();
        pkt_info.mask = pkt_info.mask | RXE_OPCODE_INFO[pkt_info.opcode as usize].mask;

        pkt_info
    }
}

pub(crate) const ROCE_V2_UDP_DPORT: u16 = 4791;
#[repr(C)]
#[derive(Default, Clone)]
pub struct RxeSkb {
    pub pkt_info: Rc<RefCell<RxePktInfo>>,
    // use RXE_NETWORK_TYPE_IPV4 and RXE_NETWORK_TYPE_IPV6
    pub protocol: u8,
    //pub eth_hdr: etherparse::Ethernet2Header,
    pub ipv4_hdr: etherparse::Ipv4Header,
    pub ipv6_hdr: etherparse::Ipv6Header,
    pub udp_hdr: etherparse::UdpHeader,
    pub pkt_len: usize,
}

impl RxeSkb {
    /// * src_port : UDP source port in big endian
    /// * dst_port : UDP dst port in big endian
    pub fn new(
        pkt_info: Rc<RefCell<RxePktInfo>>,
        qp: &RxeQueuePair,
        av: &librxe_sys::rxe_av,
    ) -> RxeSkb {
        // udp header
        let udphdr = etherparse::UdpHeader {
            destination_port: ROCE_V2_UDP_DPORT,
            source_port: qp.src_port,
            length: pkt_info.borrow().paylen + (size_of::<etherparse::UdpHeader>() as u16),
            checksum: 0,
        };
        let mut ipv4_hdr = etherparse::Ipv4Header::default();
        let ipv6_hdr = etherparse::Ipv6Header::default();
        let mut ip_hdr_len = ipv4_hdr.header_len();
        if av.network_type == rxe_verbs::RXE_NETWORK_TYPE_IPV4 {
            // ip header
            let src_addr = unsafe { av.sgid_addr._sockaddr_in.sin_addr.s_addr };
            let dst_addr = unsafe { av.dgid_addr._sockaddr_in.sin_addr.s_addr };
            // * src_addr : source IP address in big endian
            // * dst_addr : destination IP address in big endian
            // * proto: UDP
            // * tos: type of service
            // * ttl: time to live
            ipv4_hdr.protocol = libc::IPPROTO_UDP as u8;
            ipv4_hdr.differentiated_services_code_point = av.grh.traffic_class;
            ipv4_hdr.source = src_addr.to_be_bytes();
            ipv4_hdr.destination = dst_addr.to_be_bytes();
            ipv4_hdr.time_to_live = av.grh.hop_limit;
        } else if av.network_type == rxe_verbs::RXE_NETWORK_TYPE_IPV6 {
            // TODO
            ip_hdr_len = ipv6_hdr.header_len();
        }

        RxeSkb {
            pkt_info: pkt_info,
            protocol: av.network_type,
            ipv4_hdr: ipv4_hdr,
            ipv6_hdr: ipv6_hdr,
            pkt_len: ip_hdr_len + (udphdr.length as usize),
            udp_hdr: udphdr,
        }
    }
    /// construct a ip pakcet, including ip hedaer + udp header + udp payload
    pub fn write_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.pkt_len);
        let mut ip_bytes = if self.protocol == rxe_verbs::RXE_NETWORK_TYPE_IPV4 {
            let mut buf = Vec::with_capacity(self.ipv4_hdr.header_len());
            self.ipv4_hdr.write(&mut buf).unwrap();
            buf
        } else {
            let mut buf = Vec::with_capacity(self.ipv6_hdr.header_len());
            self.ipv6_hdr.write(&mut buf).unwrap();
            buf
        };
        res.append(&mut ip_bytes);
        let mut udp_bytes = Vec::with_capacity(self.udp_hdr.header_len());
        self.udp_hdr.write(&mut udp_bytes).unwrap();
        res.append(&mut udp_bytes);

        let mut iba_bytes = self.pkt_info.borrow().write_iba_bytes();
        res.append(&mut iba_bytes);

        res
    }

    pub fn rxe_xmit_packet(&self) {
        let ip_pkt = self.write_bytes();
        let sock = self.pkt_info.borrow().qp.as_ref().unwrap().borrow().sock_fd;
        let _dst_addr = self.ipv4_hdr.destination;
        assert_eq!(_dst_addr[0], 10);
        let dst_addr = socket::SockaddrIn::new(
            _dst_addr[3],
            _dst_addr[2],
            _dst_addr[1],
            _dst_addr[0],
            u16::from_be(self.udp_hdr.destination_port),
        );

        debug!("ip pkt {:#02X?}", ip_pkt);
        unsafe {
            crate::GLOBAL_IP_PKT_OUT = ip_pkt.to_vec();
        }
        socket::sendto(sock, &ip_pkt, &dst_addr, MsgFlags::empty()).unwrap();
    }
    pub fn rxe_udp_encap_recv(recv_buf: Vec<u8>) -> Self {
        let mut pkt_info = RxePktInfo::default();
        let mut skb = RxeSkb::default();
        let parsed = PacketHeaders::from_ip_slice(&recv_buf).unwrap();
        match parsed.ip {
            Some(Version4(value, _)) => {
                skb.protocol = rxe_verbs::RXE_NETWORK_TYPE_IPV4;
                skb.ipv4_hdr = value;
            }
            Some(Version6(value, _)) => {
                skb.protocol = rxe_verbs::RXE_NETWORK_TYPE_IPV6;
                skb.ipv6_hdr = value;
            }
            None => {}
        }
        match parsed.transport {
            Some(Udp(value)) => {
                skb.udp_hdr = value;
            }
            _ => {}
        }
        pkt_info.hdr = BytesMut::from(parsed.payload);
        pkt_info.port_num = 1;
        pkt_info.mask = rxe_hdr_mask::RXE_GRH_MASK;
        pkt_info.paylen = skb.udp_hdr.length - skb.udp_hdr.header_len() as u16;
        skb.pkt_info = Rc::new(RefCell::new(pkt_info.clone()));
        skb
    }
}

/// compare two slices
pub fn compare<T: Ord>(a: &[T], b: &[T]) -> std::cmp::Ordering {
    let mut iter_b = b.iter();
    for v in a {
        match iter_b.next() {
            Some(w) => match v.cmp(w) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            },
            None => break,
        }
    }
    return a.len().cmp(&b.len());
}
