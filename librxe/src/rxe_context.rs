use crate::rxe_cq::RxeCompletionQueue;
use crate::rxe_mr::RxeMr;
use crate::rxe_pd::RxePd;
use crate::rxe_qp::RxeQueuePair;
use async_rdma::{device::DeviceList, gid::Gid};
use nix::Error;
use rdma_sys::{
    ibv_context, ibv_device, ibv_device_attr_ex, ibv_gid, ibv_open_device, ibv_port_attr,
    ibv_query_device_ex, ibv_query_gid,
};
use std::{
    cell::RefCell, collections::HashMap, fmt::Debug, mem::MaybeUninit, ptr::NonNull, rc::Rc,
};

#[derive(Clone)]
pub struct RxeContext {
    pub ibv_dev: NonNull<ibv_device>,
    pub rxe_ctx: NonNull<ibv_context>,
    pub dev_attr: ibv_device_attr_ex,
    pub port_attr: ibv_port_attr,
    pub gid: Gid,
    // resource pool
    // Queue Pair Pool, key = qpn, val = qp
    pub qp_pool: HashMap<u32, Rc<RefCell<RxeQueuePair>>>,
    // Memory Region Pool, key = rkey, val = qp
    pub mr_pool: HashMap<u32, Rc<RefCell<RxeMr>>>,
    // Memory Window Pool, key = rkey,val=mw
    // Address Handler Pool, key=ah_num, val= ah
}

impl Debug for RxeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RxeDevice")
            .field("ibv_dev", &self.ibv_dev)
            .field("rxe_ctx", &self.rxe_ctx)
            //.field("dev_attr", &self.dev_attr.)
            .field("port_attr state", &self.port_attr.state)
            .field("port_attr MTU", &self.port_attr.active_mtu)
            .field("gid", &self.gid)
            .finish()
    }
}

impl RxeContext {
    /// Get the internal context pointer
    pub(crate) const fn as_ptr(&self) -> *mut ibv_context {
        self.rxe_ctx.as_ptr()
    }

    pub fn open(dev_name: Option<&str>, port_num: u8, gid_index: usize) -> Result<Self, Error> {
        let dev_list = DeviceList::available().expect(
            "This is a basic verb that shouldn't fail, check if the module ib_uverbs is loaded.",
        );

        let dev = match dev_name {
            Some(name) => dev_list.iter().find(|&d| d.name() == name),
            None => dev_list.get(0),
        }
        .unwrap();

        // SAFETY: ffi
        // 1. `dev` is valid now.
        // 2. `*mut ibv_context` does not associate with the lifetime of `*mut ibv_device`.
        let inner_ctx = NonNull::new(unsafe { ibv_open_device(dev.ffi_ptr()) }).unwrap();
        let mut device_attr = unsafe { std::mem::zeroed() };
        let mut device_attr_ex_input = unsafe { std::mem::zeroed() };
        let err = unsafe {
            ibv_query_device_ex(
                inner_ctx.as_ptr(),
                &mut device_attr_ex_input,
                &mut device_attr,
            )
        };

        let gid = {
            let mut gid = MaybeUninit::<ibv_gid>::uninit();
            let gid_index = gid_index as i32;
            // SAFETY: ffi
            let errno =
                unsafe { ibv_query_gid(inner_ctx.as_ptr(), port_num, gid_index, gid.as_mut_ptr()) };
            // SAFETY: ffi init
            Gid::from(unsafe { gid.assume_init() })
        };

        // SAFETY: POD FFI type
        let mut inner_port_attr = unsafe { std::mem::zeroed() };
        let errno =
            unsafe { rdma_sys::___ibv_query_port(inner_ctx.as_ptr(), 1, &mut inner_port_attr) };

        let ibv_dev = unsafe { NonNull::new_unchecked(dev.ffi_ptr()) };
        Ok(RxeContext {
            ibv_dev: ibv_dev,
            rxe_ctx: inner_ctx,
            dev_attr: device_attr,
            port_attr: inner_port_attr,
            gid: gid,
            qp_pool: HashMap::new(),
            mr_pool: HashMap::new(),
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
        &self,
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

    pub fn rxe_pool_add_mr(&mut self, rkey: u32, mr: Rc<RefCell<RxeMr>>) {
        self.mr_pool.insert(rkey, mr);
    }
    pub fn rxe_pool_count_mr(&self) -> usize {
        self.mr_pool.len()
    }
    pub fn rxe_pool_get_mr(&self, rkey: u32) -> Option<&Rc<RefCell<RxeMr>>> {
        self.mr_pool.get(&rkey)
    }
}

#[test]
fn open_rxe_device_test() {
    let dev = RxeContext::open(Some("rxe_0"), 1, 1);
    print!("dev info {:?}", dev);
}
