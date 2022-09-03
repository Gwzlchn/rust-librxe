use crate::rxe_cq::RxeCompletionQueue;
use crate::rxe_mr::RxeMr;
use crate::rxe_pd::RxePd;
use crate::rxe_qp::RxeQueuePair;
use async_rdma::gid::Gid;
use nix::Error;
use raw_socket::prelude::*;
use rdma_sys::{ibv_context, ibv_device, ibv_gid, ibv_mtu::IBV_MTU_256, ibv_port_attr};
use std::{
    cell::RefCell, collections::HashMap, fmt::Debug, fs, net::Ipv6Addr, path::Path, ptr::NonNull,
    rc::Rc, str::FromStr,
};

pub struct RxeContext {
    pub ibv_dev: ibv_device,
    pub rxe_ctx: ibv_context,
    pub port_attr: ibv_port_attr,
    pub gid: Gid,

    // resource pool
    // Protected domain pool, key = handle, value = pd
    // pub pd_pool: HashMap<u32, Rc<RefCell<RxePd>>>,
    // Queue Pair Pool, key = qpn, val = qp
    pub qp_pool: HashMap<u32, Rc<RefCell<RxeQueuePair>>>,
    // Memory Region Pool, key = mr index(rket >> 8), val = qp
    pub mr_pool: HashMap<u32, Rc<RefCell<RxeMr>>>,

    // global socket for all queue pairs
    pub sock: RawSocket,
}

impl Debug for RxeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RxeDevice")
            .field("port_attr state", &self.port_attr.state)
            .field("port_attr MTU", &self.port_attr.active_mtu)
            .field("gid", &self.gid)
            .finish()
    }
}

impl RxeContext {
    /// Get the internal context pointer
    pub(crate) fn as_ptr(&mut self) -> *mut ibv_context {
        &mut self.rxe_ctx as *mut ibv_context
    }

    pub fn open(_dev_name: Option<&str>, _port_num: u8, _gid_index: usize) -> Result<Self, Error> {
        //let ibv_dev = unsafe { NonNull::new_unchecked(dev.ffi_ptr()) };
        let ibv_dev = unsafe {
            let mut ibv_dev = std::mem::MaybeUninit::<ibv_device>::uninit();
            std::ptr::write_bytes(ibv_dev.as_mut_ptr(), 0, 1);
            ibv_dev.assume_init()
        };
        let inner_ctx = unsafe {
            let mut ibv_ctx = std::mem::MaybeUninit::<ibv_context>::uninit();
            std::ptr::write_bytes(ibv_ctx.as_mut_ptr(), 0, 1);
            ibv_ctx.assume_init()
        };
        let mut inner_port_attr = unsafe {
            let mut port_attr = std::mem::MaybeUninit::<ibv_port_attr>::uninit();
            std::ptr::write_bytes(port_attr.as_mut_ptr(), 0, 1);
            port_attr.assume_init()
        };
        inner_port_attr.active_mtu = IBV_MTU_256;
        inner_port_attr.lid = 0;

        let gid_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("gid.txt");
        let gid_str = fs::read_to_string(gid_file.to_str().unwrap()).expect("no gid file found");
        let _gid_128: u128 = Ipv6Addr::from_str(&gid_str)
            .expect("parsed gid error")
            .into();
        let gid = unsafe {
            let mut _gid = std::mem::MaybeUninit::<ibv_gid>::uninit();
            std::ptr::write_bytes(_gid.as_mut_ptr(), 0, 1);
            let mut _gid = _gid.assume_init();
            _gid.raw = _gid_128.to_be_bytes();
            _gid
        };
        let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Some(Protocol::udp())).unwrap();
        let enable = 1;
        sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)
            .unwrap();

        Ok(RxeContext {
            ibv_dev: ibv_dev,
            rxe_ctx: inner_ctx,
            port_attr: inner_port_attr,
            gid: gid.into(),
            qp_pool: HashMap::with_capacity(1024),
            mr_pool: HashMap::with_capacity(1024),
            sock: sock,
        })
    }

    /// Get port Lid
    pub(crate) fn get_gid(&self) -> Gid {
        self.gid
    }

    /// Get port Lid
    pub(crate) fn get_lid(&self) -> u16 {
        self.port_attr.lid
    }

    /// Get the port MTU
    pub(crate) fn get_active_mtu(&self) -> u32 {
        self.port_attr.active_mtu
    }

    // create protected domain
    pub fn create_rxe_pd(self: &mut Self) -> Result<RxePd, Error> {
        let ctx_ptr = unsafe { NonNull::new_unchecked(self as *mut _) };
        RxePd::create(ctx_ptr)
    }

    // create cq
    pub fn create_completion_queue(
        &mut self,
        cq_szie: u32,
        max_cqe: i32,
    ) -> Result<RxeCompletionQueue, Error> {
        RxeCompletionQueue::create(self, cq_szie, max_cqe)
    }

    // resource pool
    pub fn rxe_pool_add_qp(&mut self, qpn: u32, qp: Rc<RefCell<RxeQueuePair>>) {
        self.qp_pool.insert(qpn, qp);
    }
    pub fn rxe_pool_count_qp(&self) -> usize {
        self.qp_pool.len()
    }
    pub fn rxe_pool_get_qp(&self, qpn: u32) -> Option<&Rc<RefCell<RxeQueuePair>>> {
        self.qp_pool.get(&qpn)
    }

    pub fn rxe_pool_add_mr(&mut self, index: u32, mr: Rc<RefCell<RxeMr>>) {
        self.mr_pool.insert(index, mr);
    }
    pub fn rxe_pool_count_mr(&self) -> usize {
        self.mr_pool.len()
    }
    pub fn rxe_pool_get_mr(&self, index: u32) -> Option<&Rc<RefCell<RxeMr>>> {
        self.mr_pool.get(&index)
    }
}

#[test]
fn open_rxe_device_test() {
    let dev = RxeContext::open(Some("rxe_0"), 1, 1);
    print!("dev info {:?}", dev);
}
