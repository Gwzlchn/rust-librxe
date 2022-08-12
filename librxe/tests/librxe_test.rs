use async_rdma::queue_pair::QueuePairInitAttr;
use librxe::{rxe_context::RxeContext, rxe_cq::RxeCompletionQueue, rxe_qp::RxeQpState};
use rdma_sys::{
    ibv_access_flags, ibv_wc, ibv_wc_opcode, ibv_wc_status, imm_data_invalidated_rkey_union_t,
};
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
        .rxe_reg_mr(
            data.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&data),
            flag,
        )
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
fn librxe_check_loopback() {
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
    let recv_queue_start_psn = 0xA;
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
    assert_eq!(qp.resp.psn, recv_queue_start_psn);

    // modify to rts
    let timeout = 0x12;
    let retry_cnt = 1;
    let rnr_retry = 1;
    let send_queue_start_psn = 0xA;
    let max_rd_atomic = 1;
    let (mut attr, attr_mask) = qp.generate_modify_to_rts_attr(
        timeout,
        retry_cnt,
        rnr_retry,
        send_queue_start_psn,
        max_rd_atomic,
    );
    qp.modify_qp(&mut attr, attr_mask).unwrap();
    // check psn in send queue
    assert_eq!(qp.req.psn, send_queue_start_psn);

    // data buffer
    const ARR_LEN: usize = 8;
    let mut data = [0u32; ARR_LEN];
    let data_bytes = std::mem::size_of_val(&data);
    assert_eq!(data_bytes, ARR_LEN * std::mem::size_of::<u32>());
    // memory region remote key
    let mr = pd
        .rxe_reg_mr(data.as_mut_ptr() as *mut _, data_bytes, flag)
        .unwrap();
    data[0] = 0xAAAAAAAA;
    data[1] = 0xBBBBBBBB;

    // loop back test
    // send  data[0..4] to data[16..20]
    const RECEIVE_REQUEST_ID: u64 = 1;
    const SEND_REQUEST_ID: u64 = 2;
    qp.post_receive(
        &mr,
        unsafe { (data.as_mut_ptr().add(ARR_LEN >> 1)) as *mut u8 },
        (data_bytes >> 1) as u32,
        RECEIVE_REQUEST_ID,
    )
    .unwrap();

    qp.post_send(
        &mr,
        data.as_mut_ptr() as *mut u8,
        (data_bytes >> 1) as u32,
        SEND_REQUEST_ID,
    )
    .unwrap();
    let mut completions = [create_default_ibv_wc(); MINIMUM_COMPLETION_QUEUE_SIZE as usize];
    let mut sent = false;
    let mut received = false;
    while !sent || !received {
        let completed = cq.poll(&mut completions[..]).unwrap();
        if completed.is_empty() {
            continue;
        }
        assert!(completed.len() <= 2);
        for wr in completed {
            match wr.wr_id {
                SEND_REQUEST_ID => {
                    assert!(!sent);
                    sent = true;
                    println!("sent : {}", data[0]);
                }
                RECEIVE_REQUEST_ID => {
                    assert!(!received);
                    received = true;
                    assert_eq!(data[ARR_LEN >> 1], data[0]);
                    assert_eq!(data[(ARR_LEN >> 1)+1], data[1]);
                    println!("received! :{}", data[ARR_LEN >> 1]);
                }
                _ => unreachable!(),
            }
        }
    }
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

fn create_default_ibv_wc() -> ibv_wc {
    ibv_wc {
        wr_id: 0,
        status: ibv_wc_status::IBV_WC_GENERAL_ERR,
        opcode: ibv_wc_opcode::IBV_WC_LOCAL_INV,
        vendor_err: 0,
        byte_len: 0,
        imm_data_invalidated_rkey_union: imm_data_invalidated_rkey_union_t { imm_data: 0 },
        qp_num: 0,
        src_qp: 0,
        wc_flags: 0,
        pkey_index: 0,
        slid: 0,
        sl: 0,
        dlid_path_bits: 0,
    }
}
