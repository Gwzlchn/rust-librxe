use crate::{rxe_hdr::RxePktInfo, rxe_pd::RxePd, rxe_verbs};
use async_rdma::gid::Gid;
use librxe_sys::rxe_av;
use rdma_sys::{ibv_ah_attr, ibv_gid, ibv_qp_type, ibv_query_gid};
use std::{mem::MaybeUninit, ptr::NonNull};

// #[derive(Clone)]
// pub struct RxeAddrHandler {
//     pub ibv_ah: rdma_sys::ibv_ah,
//     pub av: librxe_sys::rxe_av,
//     pub ah_num: u32,
// }

// true:  addr is ipv4
// false: addr is ipv6
pub fn ipv6_addr_v4mapped(addr: &libc::in6_addr) -> bool {
    return if addr.s6_addr[0] == 0
        && addr.s6_addr[1] == 0
        && addr.s6_addr[2] == 0
        && addr.s6_addr[3] == 0
        && addr.s6_addr[4] == 0
        && addr.s6_addr[5] == 0
        && addr.s6_addr[6] == 0
        && addr.s6_addr[7] == 0
        && addr.s6_addr[8] == 0
        && addr.s6_addr[9] == 0
        && addr.s6_addr[10] == 0xFF
        && addr.s6_addr[11] == 0xFF
    {
        true
    } else {
        false
    };
}

pub fn gid_to_ipv4(gid: &rdma_sys::ibv_gid, sockaddr: &mut libc::sockaddr_in) {
    let addr_bytes = unsafe { [gid.raw[12], gid.raw[13], gid.raw[14], gid.raw[15]] };
    let ipv4_addr = libc::in_addr {
        s_addr: u32::from_be_bytes(addr_bytes),
    };
    *sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: ipv4_addr,
        sin_zero: [0; 8],
    };
}

pub fn gid_to_ipv6(gid: &rdma_sys::ibv_gid, sockaddr6: &mut libc::sockaddr_in6) {
    let ipv6_addr = libc::in6_addr {
        s6_addr: unsafe { gid.raw },
    };
    *sockaddr6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: ipv6_addr,
        sin6_scope_id: 0,
    };
}

///
pub fn rxe_init_av(attr: &ibv_ah_attr, pd: NonNull<RxePd>, av: &mut rxe_av) {
    let sgid = {
        let mut gid = MaybeUninit::<ibv_gid>::uninit();
        // SAFETY: ffi
        let errno = unsafe {
            ibv_query_gid(
                (*pd.as_ref().as_ptr()).context,
                attr.port_num,
                attr.grh.sgid_index as i32,
                gid.as_mut_ptr(),
            )
        };
        // SAFETY: ffi init
        Gid::from(unsafe { gid.assume_init() })
    };
    unsafe {
        let src_grh = std::mem::transmute::<rdma_sys::ibv_global_route, librxe_sys::rxe_global_route>(
            attr.grh,
        );
        // fill grh info
        std::ptr::copy(&src_grh, &mut av.grh, 1);
        // fill ip info
        let raw_ipaddr = libc::in6_addr {
            s6_addr: attr.grh.dgid.raw,
        };
        if ipv6_addr_v4mapped(&raw_ipaddr) {
            av.network_type = rxe_verbs::RXE_NETWORK_TYPE_IPV4;
            gid_to_ipv4(sgid.as_ref(), &mut av.sgid_addr._sockaddr_in);
            gid_to_ipv4(&attr.grh.dgid, &mut av.dgid_addr._sockaddr_in);
        } else {
            av.network_type = rxe_verbs::RXE_NETWORK_TYPE_IPV6;
            gid_to_ipv6(sgid.as_ref(), &mut av.sgid_addr._sockaddr_in6);
            gid_to_ipv6(&attr.grh.dgid, &mut av.dgid_addr._sockaddr_in6);
        }
    }
    // ignore mac address
}

// TODO: how to return a reference?
pub fn rxe_get_av(pkt: &RxePktInfo) -> Option<rxe_av> {
    if pkt.qp.is_none() {
        return None;
    }
    let qp = pkt.qp.as_ref().unwrap().borrow();
    if qp.qp_type() == ibv_qp_type::IBV_QPT_RC || qp.qp_type() == ibv_qp_type::IBV_QPT_UC {
        return unsafe { Some(qp.pri_av) };
    }
    // TODO if qp type is RD/UD
    return None;
}

#[test]
fn check_ipv6_addr_v4mapped() {
    let ipv4_addr = libc::in6_addr {
        s6_addr: [
            00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0xff, 0xff, 0x0a, 0x13, 00, 0x24,
        ],
    };
    let res = ipv6_addr_v4mapped(&ipv4_addr);
    assert!(res);
}
