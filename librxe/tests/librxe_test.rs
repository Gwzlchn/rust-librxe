use async_rdma::queue_pair::{QueuePairEndpoint, QueuePairInitAttr};
use librxe::{
    rxe_context::RxeContext, rxe_cq::RxeCompletionQueue, rxe_mr::RxeMr, rxe_qp::RxeQpState,
};
use rdma_sys::{ibv_access_flags, ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_state};
use tracing::info;
use tracing_test::traced_test;

const MINIMUM_COMPLETION_QUEUE_SIZE: u32 = 128;
const MAXIMUN_COMPLETION_QUEUE_ENTRY_SIZE: i32 = 128;

#[traced_test]
#[test]
fn librxe_check_reg_mr() {
    let mut rxe_cxt = RxeContext::open(Some("rxe_0"), 1, 1).unwrap();
    let mut pd = rxe_cxt.create_rxe_pd().unwrap();
    let flag = create_ibv_access_flag();

    // data buffer
    let len = 32;
    let mut data = Vec::<u64>::with_capacity(len);
    // memory region remote key
    let mr_rkey = pd
        .rxe_reg_mr(data.as_mut_ptr() as *mut _, len, flag)
        .unwrap()
        .rkey();
    // check resource pool
    assert_eq!(1, rxe_cxt.rxe_pool_count_mr());
    let mr_in_the_pool = rxe_cxt
        .rxe_pool_get_mr(mr_rkey)
        .expect("Couldn't find mr in the pool")
        .borrow();
    assert_eq!(mr_in_the_pool.rkey(), mr_rkey);
}

#[traced_test]
#[test]
fn librxe_check_create_qp() {
    let mut rxe_cxt = RxeContext::open(Some("rxe_0"), 1, 0).unwrap();
    let mut pd = rxe_cxt.create_rxe_pd().unwrap();

    let cq = rxe_cxt
        .create_completion_queue(
            MINIMUM_COMPLETION_QUEUE_SIZE,
            MAXIMUN_COMPLETION_QUEUE_ENTRY_SIZE,
        )
        .unwrap();

    let mut qp_init_attr = create_qp_init_attr(&cq);
    let qp = pd
        .rxe_create_qp(&mut qp_init_attr)
        .expect("create qp failed");

    let qpn = qp.qp_num();
    // check resource pool
    assert_eq!(1, rxe_cxt.rxe_pool_count_qp());
    let qp_in_the_pool = rxe_cxt
        .rxe_pool_get_qp(qpn)
        .expect("Couldn't find qp in the pool")
        .borrow();
    assert_eq!(qp_in_the_pool.qp_num(), qpn);
}

#[traced_test]
#[test]
fn librxe_check_modify_qp() {
    let loopback_gid_idx = 1u8;
    let mut rxe_cxt = RxeContext::open(Some("rxe_0"), 1, loopback_gid_idx as usize).unwrap();
    let mut pd = rxe_cxt.create_rxe_pd().unwrap();
    let cq = rxe_cxt
        .create_completion_queue(
            MINIMUM_COMPLETION_QUEUE_SIZE,
            MAXIMUN_COMPLETION_QUEUE_ENTRY_SIZE,
        )
        .unwrap();

    let mut qp_init_attr = create_qp_init_attr(&cq);
    let mut qp = pd
        .rxe_create_qp(&mut qp_init_attr)
        .expect("create qp failed");
    // it should be reset in default
    assert_eq!(qp.req.state, RxeQpState::QP_STATE_RESET);
    // modify to init
    let port_num = 1;

    let flag = create_ibv_access_flag();
    let (mut attr, attr_mask) = qp.generate_modify_to_init_attr(flag, port_num);
    qp.modify_qp(&mut attr, attr_mask).unwrap();
    assert_eq!(qp.req.state, RxeQpState::QP_STATE_INIT);

    // modify to rtr
    let local_endpoint = qp.endpoint();
    let recv_queue_start_psn = 0xABCD;
    let max_dest_rd_atomic = 1;
    let min_rnr_timer = 16;
    let (mut attr, attr_mask) = qp.generate_modify_to_rtr_attr(
        local_endpoint,
        recv_queue_start_psn,
        max_dest_rd_atomic,
        min_rnr_timer,
        port_num,
        loopback_gid_idx,
    );
    qp.modify_qp(&mut attr, attr_mask).unwrap();
    // check psn in recv queue
    assert_eq!(qp.resp.psn, 0xABCD);

    // modify to rts
    let timeout = 0x12;
    let retry_cnt = 1;
    let rnr_retry = 1;
    let send_queue_start_psn = 0xFF;
    let max_rd_atomic = 1;
    let (mut attr, attr_mask) = qp.generate_modify_to_rts_attr(
        timeout,
        retry_cnt,
        rnr_retry,
        send_queue_start_psn,
        max_rd_atomic,
    );
    qp.modify_qp(&mut attr, attr_mask);
    // check psn in send queue
    assert_eq!(qp.req.psn, 0xFF);
}

fn create_ibv_access_flag() -> ibv_access_flags {
    ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
        | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE
        | ibv_access_flags::IBV_ACCESS_REMOTE_READ
        | ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC
}

fn create_qp_init_attr(cq: &RxeCompletionQueue) -> QueuePairInitAttr {
    let mut qp_init_attr = QueuePairInitAttr::default();
    qp_init_attr.qp_init_attr_inner.recv_cq = cq.as_ptr();
    qp_init_attr.qp_init_attr_inner.send_cq = cq.as_ptr();
    qp_init_attr
}
