# EBully0

[ 2495.524770] BUG: unable to handle kernel NULL pointer dereference at 0000000000000020 
[ 2495.533511] PGD 0 P4D 0  
[ 2495.536337] Oops: 0000 [#1] SMP PTI 
[ 2495.540225] CPU: 20 PID: 7765 Comm: kworker/20:1H Kdump: loaded Tainted: G                 --------- -t - 4.18.0-309.el8.x86_64 #1 
[ 2495.553326] Hardware name: Dell Inc. PowerEdge R730/072T6D, BIOS 2.10.5 07/25/2019 
[ 2495.561775] Workqueue: nvme_tcp_wq nvme_tcp_io_work [nvme_tcp] 
[ 2495.568285] RIP: 0010:__rq_qos_done+0x10/0x30 
[ 2495.573144] Code: c0 74 0b 48 89 ee 48 89 df e8 3c bd 79 00 48 8b 5b 18 48 85 db 75 e0 5b 5d c3 0f 1f 44 00 00 55 48 89 f5 53 48 89 fb 48 8b 03 <48> 8b 40 20 48 85 c0 74 0b 48 89 ee 48 89 df e8 0c bd 79 00 48 8b 
[ 2495.594097] RSP: 0018:ffffba5c0453fd10 EFLAGS: 00010282 
[ 2495.599923] RAX: 0000000000000000 RBX: ffff9e5c06569c58 RCX: 0000000000000000 
[ 2495.607883] RDX: 0000000000000000 RSI: ffff9e58c9d1c410 RDI: ffff9e5c06569c58 
[ 2495.615844] RBP: ffff9e58c9d1c410 R08: ffff9e5886d20000 R09: ffffffffa0209320 
[ 2495.623805] R10: 00000000000000a2 R11: ffff9e5c2da30f00 R12: ffff9e5cb65a0a10 
[ 2495.631766] R13: ffff9e58ad580000 R14: ffff9e58c9d1c410 R15: ffff9e5cb5b71b90 
[ 2495.639727] FS:  0000000000000000(0000) GS:ffff9e5befc80000(0000) knlGS:0000000000000000 
[ 2495.648786] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 
[ 2495.655194] CR2: 0000000000000020 CR3: 0000000167c10006 CR4: 00000000003706e0 
[ 2495.663155] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 
[ 2495.671116] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 
[ 2495.679077] Call Trace: 
[ 2495.681805]  blk_mq_free_request+0x9c/0x120 
[ 2495.686470]  nvme_tcp_recv_skb+0x9f6/0xc00 [nvme_tcp] 
[ 2495.692106]  ? __switch_to_asm+0x35/0x70 
[ 2495.696478]  ? __switch_to_asm+0x41/0x70 
[ 2495.700850]  ? __switch_to_asm+0x35/0x70 
[ 2495.705223]  ? __switch_to_asm+0x41/0x70 
[ 2495.709596]  ? nvme_tcp_io_work+0xa0/0xa0 [nvme_tcp] 
[ 2495.715134]  tcp_read_sock+0x9b/0x1b0 
[ 2495.719215]  ? __switch_to_asm+0x35/0x70 
[ 2495.723587]  nvme_tcp_try_recv+0x68/0xa0 [nvme_tcp] 
[ 2495.729029]  ? __switch_to+0x10c/0x480 
[ 2495.733207]  nvme_tcp_io_work+0x66/0xa0 [nvme_tcp] 
[ 2495.738552]  process_one_work+0x1a7/0x360 
[ 2495.743023]  ? create_worker+0x1a0/0x1a0 
[ 2495.747395]  worker_thread+0x30/0x390 
[ 2495.751478]  ? create_worker+0x1a0/0x1a0 
[ 2495.755851]  kthread+0x116/0x130 
[ 2495.759449]  ? kthread_flush_work_fn+0x10/0x10 
[ 2495.764404]  ret_from_fork+0x35/0x40 
