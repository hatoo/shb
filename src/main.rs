use std::mem;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use io_uring::{IoUring, Submitter, cqueue, opcode, squeue, types};
use shiguredo_http11::{BodyKind, BodyProgress, HttpHead, Request, ResponseDecoder};

/// provided buffer ring の 1 バッファのサイズ
const RECV_BUF_SIZE: usize = 16 * 1024;
/// provided buffer ring のバッファグループ ID (ワーカーごとに 1 つ)
const BUF_GROUP: u16 = 0;
const TIMEOUT_USER_DATA: u64 = u64::MAX;

#[derive(Parser)]
#[command(name = "shb", about = "io_uring HTTP/1.1 benchmarker")]
struct Args {
    /// Target URL (http only), e.g. http://127.0.0.1:8080/
    url: String,

    /// Number of concurrent connections
    #[arg(short, long, default_value_t = 1)]
    connections: usize,

    /// Total number of requests
    #[arg(short = 'n', long, default_value_t = 100_000)]
    requests: u64,

    /// Run for this long instead of a fixed request count (e.g. 10s, 1m30s)
    #[arg(short = 'z', long, value_parser = humantime::parse_duration)]
    duration: Option<Duration>,

    /// Connection establishment timeout (e.g. 3s, 500ms)
    #[arg(long, default_value = "3s", value_parser = humantime::parse_duration)]
    connect_timeout: Duration,

    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = default_threads())]
    threads: usize,

    /// Print the report as JSON
    #[arg(short = 'j', long)]
    json: bool,
}

/// スレッド数のデフォルト値 (CPU 数)
fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// io_uring の Connect SQE に渡す sockaddr。SQE 完了まで移動しないよう保持する
struct SockAddrRaw {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl SockAddrRaw {
    fn new(addr: &SocketAddr) -> Self {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(a) => {
                let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = a.port().to_be();
                sin.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(a) => {
                let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = a.port().to_be();
                sin6.sin6_addr.s6_addr = a.ip().octets();
                sin6.sin6_flowinfo = a.flowinfo();
                sin6.sin6_scope_id = a.scope_id();
                mem::size_of::<libc::sockaddr_in6>()
            }
        };
        SockAddrRaw {
            storage,
            len: len as libc::socklen_t,
        }
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        &self.storage as *const _ as *const libc::sockaddr
    }
}

/// 未接続の TCP ソケットを作成し TCP_NODELAY を設定する
fn make_socket(addr: &SocketAddr) -> Result<RawFd> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket() failed");
    }
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        drop(unsafe { TcpStream::from_raw_fd(fd) });
        return Err(err).context("setsockopt(TCP_NODELAY) failed");
    }
    Ok(fd)
}

/// multishot recv 用の provided buffer ring
///
/// カーネルは受信のたびにこのリングからバッファを取り出して書き込み、
/// CQE の flags でバッファ ID を通知する。処理後は `recycle` で返却する。
/// リング領域とデータバッファはバッファグループの登録解除 (= io_uring の drop)
/// までカーネルが参照するため、この構造体は必ず ring より先に宣言して
/// 逆順 drop で ring より後に破棄されるようにすること。
struct BufRing {
    /// io_uring_buf エントリ配列 (ページ境界に確保、カーネルと共有)
    ring_ptr: *mut types::BufRingEntry,
    layout: std::alloc::Layout,
    entries: u16,
    mask: u16,
    /// ローカルの tail シャドウ。publish で共有領域に Release ストアする
    tail: u16,
    /// entries * RECV_BUF_SIZE の連続データバッファ (再確保しないこと)
    data: Vec<u8>,
}

impl BufRing {
    fn new(entries: u16) -> Result<Self> {
        assert!(entries.is_power_of_two());
        let layout = std::alloc::Layout::from_size_align(
            entries as usize * mem::size_of::<types::BufRingEntry>(),
            4096,
        )
        .context("invalid buffer ring layout")?;
        let ring_ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut types::BufRingEntry;
        if ring_ptr.is_null() {
            bail!("failed to allocate buffer ring");
        }
        let mut this = BufRing {
            ring_ptr,
            layout,
            entries,
            mask: entries - 1,
            tail: 0,
            data: vec![0u8; entries as usize * RECV_BUF_SIZE],
        };
        // 全バッファを初期投入する
        for bid in 0..entries {
            this.push_entry(bid);
        }
        this.publish();
        Ok(this)
    }

    fn push_entry(&mut self, bid: u16) {
        let idx = (self.tail & self.mask) as usize;
        unsafe {
            let entry = &mut *self.ring_ptr.add(idx);
            entry.set_addr(self.data.as_ptr() as u64 + bid as u64 * RECV_BUF_SIZE as u64);
            entry.set_len(RECV_BUF_SIZE as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// tail をカーネルへ公開する
    fn publish(&self) {
        unsafe {
            let tail_ptr = types::BufRingEntry::tail(self.ring_ptr) as *const AtomicU16;
            (*tail_ptr).store(self.tail, Ordering::Release);
        }
    }

    /// CQE で通知されたバッファのデータを参照する
    fn data(&self, bid: u16, len: usize) -> &[u8] {
        let off = bid as usize * RECV_BUF_SIZE;
        &self.data[off..off + len]
    }

    /// 処理し終えたバッファをリングに返却する
    fn recycle(&mut self, bid: u16) {
        self.push_entry(bid);
        self.publish();
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ring_ptr as *mut u8, self.layout) };
    }
}

struct Target {
    addr: SocketAddr,
    request_bytes: Vec<u8>,
}

fn parse_target(url: &str) -> Result<Target> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        bail!("missing host in URL");
    }
    // Host ヘッダーにはポートが 80 のとき authority をそのまま使う
    let (host_for_lookup, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || authority.starts_with('[') => {
            // IPv6 リテラルは [::1]:8080 形式のみポート付きとみなす
            if authority.starts_with('[') && !h.ends_with(']') {
                (authority, 80u16)
            } else {
                (h, p.parse::<u16>().context("invalid port")?)
            }
        }
        _ => (authority, 80u16),
    };
    let host_for_lookup = host_for_lookup
        .trim_start_matches('[')
        .trim_end_matches(']');

    let addr = (host_for_lookup, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {authority}"))?
        .next()
        .context("no address resolved")?;

    let request = Request::new("GET", path)
        .map_err(|e| anyhow::anyhow!("invalid request target: {e:?}"))?
        .header("Host", authority)
        .map_err(|e| anyhow::anyhow!("invalid Host header: {e:?}"))?;
    let request_bytes = request
        .encode()
        .map_err(|e| anyhow::anyhow!("failed to encode request: {e:?}"))?;

    Ok(Target {
        addr,
        request_bytes,
    })
}

/// レスポンス受信の進行状態
enum ParseOutcome {
    /// レスポンス 1 件完了。keep-alive 可能なら true
    Complete { keep_alive: bool },
    /// データ不足。recv を継続する
    NeedMoreData,
}

/// デコード済みヘッダーから抜き出した、現在のレスポンスのメタ情報
///
/// ResponseHead は decode_headers で消費されるため、完了時まで必要な値だけ残す。
struct ResponseMeta {
    body_kind: BodyKind,
    keep_alive: bool,
    /// ステータスコード (完了時に集計する)
    status_code: u16,
}

struct Conn {
    fd: RawFd,
    /// TCP 接続が確立済みか (Connect CQE 成功で true)
    connected: bool,
    decoder: ResponseDecoder,
    /// 部分送信の再開位置
    send_offset: usize,
    /// multishot recv が有効か (MORE フラグの落ちた CQE で無効になる)
    recv_armed: bool,
    /// 再接続世代。close のたびに増え、旧世代の CQE
    /// (取り消された multishot recv 等) を user_data で識別して無視する
    generation: u64,
    /// 現在のレスポンスのメタ情報 (None = ヘッダー未デコード)
    resp: Option<ResponseMeta>,
    request_start: Instant,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            connected: false,
            decoder: ResponseDecoder::new(),
            send_offset: 0,
            recv_armed: false,
            generation: 0,
            resp: None,
            request_start: Instant::now(),
        }
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            // TcpStream に戻して drop することで close する
            drop(unsafe { TcpStream::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.connected = false;
        self.recv_armed = false;
        // 旧接続向けオペレーションの CQE を無視できるよう世代を進める
        self.generation += 1;
    }

    /// 受信済みデータをデコーダーに与えた後の状態遷移を進める
    fn parse(&mut self) -> Result<ParseOutcome> {
        let meta = match &self.resp {
            Some(meta) => meta,
            None => match self
                .decoder
                .decode_headers()
                .map_err(|e| anyhow::anyhow!("decode error: {e:?}"))?
            {
                None => return Ok(ParseOutcome::NeedMoreData),
                Some((head, body_kind)) => &*self.resp.insert(ResponseMeta {
                    body_kind,
                    // close-delimited ボディは Connection ヘッダーに関わらず
                    // 接続終了がボディ終端なので keep-alive 不可
                    keep_alive: head.is_keep_alive()
                        && !matches!(body_kind, BodyKind::CloseDelimited),
                    status_code: head.status_code(),
                }),
            },
        };

        match meta.body_kind {
            BodyKind::None => Ok(ParseOutcome::Complete {
                keep_alive: meta.keep_alive,
            }),
            BodyKind::Tunnel => bail!("unexpected tunnel response"),
            _ => {
                let keep_alive = meta.keep_alive;
                loop {
                    let progress = if let Some(body) = self.decoder.peek_body() {
                        let len = body.len();
                        self.decoder
                            .consume_body(len)
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    } else {
                        self.decoder
                            .progress()
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    };
                    match progress {
                        BodyProgress::Complete { .. } => {
                            return Ok(ParseOutcome::Complete { keep_alive });
                        }
                        BodyProgress::Advanced => continue,
                        BodyProgress::NeedData => return Ok(ParseOutcome::NeedMoreData),
                    }
                }
            }
        }
    }

    /// 次のリクエストに向けて状態をリセット
    fn begin_request(&mut self) {
        self.send_offset = 0;
        self.resp = None;
        self.request_start = Instant::now();
    }
}

// user_data: 下位 2bit がオペレーション種別、次の CONN_IDX_BITS bit が
// コネクション番号、残りが再接続世代
const OP_SEND: u64 = 0;
const OP_RECV: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_CONNECT_TIMEOUT: u64 = 3;
const CONN_IDX_BITS: u64 = 20;

fn user_data(conn_idx: usize, generation: u64, op: u64) -> u64 {
    (generation << (2 + CONN_IDX_BITS)) | ((conn_idx as u64) << 2) | op
}

fn push_sqe(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    entry: squeue::Entry,
) -> Result<()> {
    unsafe {
        if sq.push(&entry).is_err() {
            // tail を公開して kernel に消化させ、head を取り直して再試行
            sq.sync();
            submitter.submit().context("io_uring submit failed")?;
            sq.sync();
            sq.push(&entry)
                .map_err(|_| anyhow::anyhow!("submission queue full after submit"))?;
        }
    }
    Ok(())
}

/// リンクされた 2 つの SQE を同一サブミッション内に投入する
///
/// IOSQE_IO_LINK のチェーンはサブミッション境界を跨げないため、
/// 空きが 2 スロット未満なら先に submit して空ける。
fn push_sqe_pair(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    first: squeue::Entry,
    second: squeue::Entry,
) -> Result<()> {
    unsafe {
        if sq.capacity() - sq.len() < 2 {
            sq.sync();
            submitter.submit().context("io_uring submit failed")?;
            sq.sync();
        }
        sq.push(&first)
            .map_err(|_| anyhow::anyhow!("submission queue full"))?;
        sq.push(&second)
            .map_err(|_| anyhow::anyhow!("submission queue full"))?;
    }
    Ok(())
}

/// 非同期 connect を開始する (Connect SQE + 接続タイムアウトの LinkTimeout)
///
/// 作成した fd はコネクション番号の固定ファイルスロットに登録し、
/// 以降の SQE はすべて `types::Fixed(conn_idx)` で参照する。
fn start_connect(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    addr: &SocketAddr,
    raw_addr: &SockAddrRaw,
    timeout: &types::Timespec,
) -> Result<()> {
    conn.fd = make_socket(addr)?;
    // スロット上書きにより旧 fd への登録参照も解放される
    submitter
        .register_files_update(conn_idx as u32, &[conn.fd])
        .context("register_files_update failed")?;
    let connect = opcode::Connect::new(
        types::Fixed(conn_idx as u32),
        raw_addr.as_ptr(),
        raw_addr.len,
    )
    .build()
    .flags(squeue::Flags::IO_LINK)
    .user_data(user_data(conn_idx, conn.generation, OP_CONNECT));
    let link_timeout = opcode::LinkTimeout::new(timeout as *const types::Timespec)
        .build()
        .user_data(user_data(conn_idx, conn.generation, OP_CONNECT_TIMEOUT));
    push_sqe_pair(submitter, sq, connect, link_timeout)
}

/// リクエストを送信する
///
/// 注: WriteFixed + registered buffer も試したが、ソケットの write 経路は
/// send 経路より遅く、100B 程度の送信では固定バッファの利得もないため
/// 約 4% の悪化だった (2026-08 計測)。Send のままにすること。
fn push_send(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &Conn,
    request: &[u8],
) -> Result<()> {
    let remaining = &request[conn.send_offset..];
    let entry = opcode::Send::new(
        types::Fixed(conn_idx as u32),
        remaining.as_ptr(),
        remaining.len() as u32,
    )
    .build()
    .user_data(user_data(conn_idx, conn.generation, OP_SEND));
    push_sqe(submitter, sq, entry)
}

/// multishot recv を投入する
///
/// 一度の投入で、MORE フラグが立つ間は受信のたびに CQE が届き続けるため、
/// レスポンスごとの Recv SQE が不要になる。受信バッファは provided buffer
/// ring からカーネルが選び、CQE の flags でバッファ ID が通知される。
fn push_recv_multi(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    let entry = opcode::RecvMulti::new(types::Fixed(conn_idx as u32), BUF_GROUP)
        .build()
        .user_data(user_data(conn_idx, conn.generation, OP_RECV));
    push_sqe(submitter, sq, entry)?;
    conn.recv_armed = true;
    Ok(())
}

struct Stats {
    completed: u64,
    errors: u64,
    connect_errors: u64,
    bytes_received: u64,
    latencies_ns: Vec<u64>,
    status_counts: Box<[u64; 600]>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            completed: 0,
            errors: 0,
            connect_errors: 0,
            bytes_received: 0,
            latencies_ns: Vec::new(),
            status_counts: Box::new([0u64; 600]),
        }
    }
}

impl Stats {
    fn record_success(&mut self, conn: &Conn) {
        self.completed += 1;
        if let Some(meta) = &conn.resp {
            self.status_counts[meta.status_code as usize] += 1;
        }
        self.latencies_ns
            .push(conn.request_start.elapsed().as_nanos() as u64);
    }

    fn merge(&mut self, other: Stats) {
        self.completed += other.completed;
        self.errors += other.errors;
        self.connect_errors += other.connect_errors;
        self.bytes_received += other.bytes_received;
        self.latencies_ns.extend(other.latencies_ns);
        for (a, b) in self
            .status_counts
            .iter_mut()
            .zip(other.status_counts.iter())
        {
            *a += *b;
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.connections == 0 {
        bail!("--connections must be >= 1");
    }
    if args.threads == 0 {
        bail!("--threads must be >= 1");
    }
    let target = parse_target(&args.url)?;

    let duration_limit = args.duration;

    // 1 スレッドには最低 1 コネクション割り当てる
    let threads = args.threads.min(args.connections);

    // コネクション数とリクエスト数をスレッドに分配する (余りは先頭から 1 ずつ)
    let conns_per_thread: Vec<usize> = (0..threads)
        .map(|i| args.connections / threads + usize::from(i < args.connections % threads))
        .collect();
    let requests_per_thread: Vec<u64> = if duration_limit.is_some() {
        // duration モードでは requests は上限なし扱い
        vec![u64::MAX; threads]
    } else {
        (0..threads)
            .map(|i| {
                args.requests / threads as u64
                    + u64::from((i as u64) < args.requests % threads as u64)
            })
            .collect()
    };

    let bench_start = Instant::now();
    let results: Vec<Result<Stats>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let target = &target;
                let connections = conns_per_thread[i];
                let max_requests = requests_per_thread[i];
                let connect_timeout = args.connect_timeout;
                s.spawn(move || {
                    run_worker(
                        target,
                        connections,
                        max_requests,
                        duration_limit,
                        connect_timeout,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h.join() {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("worker thread panicked")),
            })
            .collect()
    });
    let elapsed = bench_start.elapsed();

    let mut stats = Stats::default();
    for result in results {
        stats.merge(result?);
    }

    if args.json {
        print_json_report(&args, threads, &stats, elapsed)?;
    } else {
        print_report(&args, threads, &stats, elapsed);
    }
    Ok(())
}

/// 1 ワーカースレッド分のベンチマークループ
///
/// 専用の io_uring とコネクション群を持ち、他スレッドと状態を共有しない。
fn run_worker(
    target: &Target,
    connections: usize,
    max_requests: u64,
    duration_limit: Option<Duration>,
    connect_timeout: Duration,
) -> Result<Stats> {
    if connections == 0 || max_requests == 0 {
        return Ok(Stats::default());
    }
    if connections > 1 << CONN_IDX_BITS {
        bail!(
            "too many connections per thread (max {})",
            1u64 << CONN_IDX_BITS
        );
    }

    // buf_ring / conns は ring より先に宣言する。逆順 drop により ring
    // (teardown 時に in-flight オペレーションのキャンセル完了を待つ) が
    // 先に破棄され、kernel が参照するバッファの解放後に書き込まれる
    // use-after-free を防ぐ。
    let buf_entries = (connections * 2).next_power_of_two().clamp(64, 32768) as u16;
    let mut buf_ring = BufRing::new(buf_entries)?;
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        conns.push(Conn::new());
    }

    let entries = (connections * 2).next_power_of_two().max(256) as u32;
    // SINGLE_ISSUER: このリングは本スレッドしか触らない前提をカーネルに伝える
    // COOP_TASKRUN / DEFER_TASKRUN: ソケット完了の task work を任意タイミングの
    // 割り込みではなく io_uring_enter 時にまとめて実行させる (要 kernel 6.1+)
    // NO_SQARRAY: SQ の間接配列を除去 (要 kernel 6.6+)
    // CQSIZE: multishot recv がバーストで積む CQE のオーバーフローを防ぐ
    let mut ring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .setup_no_sqarray()
        .setup_cqsize(entries * 4)
        .build(entries)
        .or_else(|_| {
            // 古いカーネル向けフォールバック
            IoUring::new(entries)
        })
        .context("failed to create io_uring")?;

    // Submitter を持続させて enter に registered ring fd を使えるようにする
    // (submitter/sq/cq は ring から分離borrowされ、以後 ring 本体は触らない)
    let (mut submitter, mut sq, mut cq) = ring.split();

    // enter ごとのリング fd の fdget/fput を省く (5.18+、失敗しても動作は同じ)
    let _ = submitter.register_ring_fd();

    // コネクションごとに固定ファイルスロットを確保し、SQE では
    // types::Fixed(conn_idx) を使って fd 参照カウント操作を省く
    submitter
        .register_files_sparse(connections as u32)
        .context("register_files_sparse failed")?;

    // provided buffer ring を登録する (要 kernel 5.19+、RecvMulti は 6.0+)
    unsafe {
        submitter
            .register_buf_ring_with_flags(buf_ring.ring_ptr as u64, buf_ring.entries, BUF_GROUP, 0)
            .context("register_buf_ring failed")?;
    }

    // Connect SQE が参照する sockaddr / Timespec は完了まで安定したアドレスに置く
    let raw_addr = Box::new(SockAddrRaw::new(&target.addr));
    let connect_timeout = Box::new(types::Timespec::from(connect_timeout));

    let mut stats = Stats::default();
    if duration_limit.is_none() {
        stats.latencies_ns.reserve(max_requests as usize);
    }
    let mut started: u64 = 0;

    // duration モード: 期限は io_uring の Timeout CQE のみで検知する
    let timespec = duration_limit.map(|d| Box::new(types::Timespec::from(d)));
    if let Some(ts) = &timespec {
        let entry = opcode::Timeout::new(&**ts as *const types::Timespec)
            .build()
            .user_data(TIMEOUT_USER_DATA);
        push_sqe(&submitter, &mut sq, entry)?;
    }

    // 初回リクエスト投入 (接続確立も io_uring 経由の非同期 connect)
    for (i, conn) in conns.iter_mut().enumerate() {
        if started >= max_requests {
            break;
        }
        started += 1;
        conn.begin_request();
        start_connect(
            &submitter,
            &mut sq,
            i,
            conn,
            &target.addr,
            &raw_addr,
            &connect_timeout,
        )?;
    }

    let mut cqe_buf: Vec<(u64, i32, u32)> = Vec::with_capacity(entries as usize * 4);
    let mut stop = false;

    'outer: loop {
        if stats.completed + stats.errors >= max_requests {
            break;
        }
        // push 済み SQE の tail を公開してから submit する
        sq.sync();
        submitter
            .submit_and_wait(1)
            .context("submit_and_wait failed")?;

        cq.sync();
        cqe_buf.clear();
        for cqe in &mut cq {
            cqe_buf.push((cqe.user_data(), cqe.result(), cqe.flags()));
        }
        // 消費した CQE の head を公開する
        cq.sync();

        for &(ud, res, flags) in &cqe_buf {
            if ud == TIMEOUT_USER_DATA {
                stop = true;
                continue;
            }
            let op = ud & 0b11;
            let conn_idx = ((ud >> 2) & ((1 << CONN_IDX_BITS) - 1)) as usize;
            let generation = ud >> (2 + CONN_IDX_BITS);

            // 旧世代 (close 済み接続) のオペレーションの CQE は無視する。
            // 旧 multishot recv がバッファ付きで完了していた場合は返却だけ行う。
            if generation != conns[conn_idx].generation {
                if let Some(bid) = cqueue::buffer_select(flags) {
                    buf_ring.recycle(bid);
                }
                continue;
            }

            let mut request_finished = false;
            let mut keep_conn = true;

            match op {
                OP_CONNECT => {
                    if res < 0 {
                        // ECONNREFUSED / ECANCELED (LinkTimeout 発火) など
                        stats.errors += 1;
                        stats.connect_errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        let conn = &mut conns[conn_idx];
                        conn.connected = true;
                        // 接続と同時にコネクション寿命の multishot recv を張る
                        push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        // レイテンシは送信開始から測る (接続確立時間は含めない)
                        conn.request_start = Instant::now();
                        push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                    }
                }
                OP_CONNECT_TIMEOUT => {
                    // LinkTimeout の CQE は connect の成否に関わらず届く
                    // (connect 先行完了なら -ECANCELED、発火なら -ETIME)。
                    // 処理は OP_CONNECT 側で行うのでここでは何もしない。
                }
                OP_SEND => {
                    if res < 0 {
                        stats.errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        let conn = &mut conns[conn_idx];
                        conn.send_offset += res as usize;
                        if conn.send_offset < target.request_bytes.len() {
                            push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                        } else if !conn.recv_armed {
                            // ENOBUFS 等で multishot が終了していた場合の再投入
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        }
                    }
                }
                OP_RECV => {
                    let conn = &mut conns[conn_idx];
                    // MORE フラグの落ちた CQE でこの multishot recv は終了している
                    if !cqueue::more(flags) {
                        conn.recv_armed = false;
                    }
                    if res < 0 {
                        // 万一バッファが付いていたら返却する
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        if res == -libc::ENOBUFS {
                            // バッファ枯渇で multishot が止まっただけ。
                            // このバッチの処理でバッファは返却されるので再投入する
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        } else {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        }
                    } else if res == 0 {
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        // EOF: close-delimited ボディなら正常完了
                        // (is_close_delimited はヘッダーデコード済みを含意する)
                        if conn.decoder.is_close_delimited() {
                            conn.decoder.mark_eof();
                            match conn.parse() {
                                Ok(ParseOutcome::Complete { .. }) => stats.record_success(conn),
                                _ => stats.errors += 1,
                            }
                        } else {
                            stats.errors += 1;
                        }
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        stats.bytes_received += res as u64;
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        let feed_result = conn.decoder.feed(buf_ring.data(bid, res as usize));
                        buf_ring.recycle(bid);
                        if feed_result.is_err() {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        } else {
                            match conn.parse() {
                                Ok(ParseOutcome::Complete { keep_alive }) => {
                                    stats.record_success(conn);
                                    request_finished = true;
                                    keep_conn = keep_alive;
                                }
                                Ok(ParseOutcome::NeedMoreData) => {
                                    if !conn.recv_armed {
                                        push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                                    }
                                }
                                Err(_) => {
                                    stats.errors += 1;
                                    request_finished = true;
                                    keep_conn = false;
                                }
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            if request_finished {
                let conn = &mut conns[conn_idx];
                if !stop && started < max_requests {
                    started += 1;
                    conn.begin_request();
                    if keep_conn && conn.connected {
                        if !conn.recv_armed {
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        }
                        push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                    } else {
                        conn.close();
                        conn.decoder.reset();
                        if let Err(e) = start_connect(
                            &submitter,
                            &mut sq,
                            conn_idx,
                            conn,
                            &target.addr,
                            &raw_addr,
                            &connect_timeout,
                        ) {
                            eprintln!("reconnect failed: {e}");
                            break 'outer;
                        }
                    }
                } else if !keep_conn {
                    conn.close();
                }
            }
        }

        if stop {
            break;
        }
    }

    for conn in &mut conns {
        conn.close();
    }

    Ok(stats)
}

/// レイテンシ要約 (秒)
struct LatencySummary {
    min: f64,
    mean: f64,
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
}

fn latency_summary(latencies_ns: &[u64]) -> Option<LatencySummary> {
    if latencies_ns.is_empty() {
        return None;
    }
    let mut lat = latencies_ns.to_vec();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = ((lat.len() as f64 * p).ceil() as usize).saturating_sub(1);
        lat[idx.min(lat.len() - 1)] as f64 / 1e9
    };
    Some(LatencySummary {
        min: lat[0] as f64 / 1e9,
        mean: lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1e9,
        p50: pct(0.50),
        p90: pct(0.90),
        p99: pct(0.99),
        max: lat[lat.len() - 1] as f64 / 1e9,
    })
}

fn print_report(args: &Args, threads: usize, stats: &Stats, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let total = stats.completed + stats.errors;
    println!("URL:          {}", args.url);
    println!("Threads:      {threads}");
    println!("Connections:  {}", args.connections);
    println!(
        "Requests:     {} ({} ok, {} errors, of which {} connect) in {:.3}s",
        total, stats.completed, stats.errors, stats.connect_errors, secs
    );
    println!("Requests/sec: {:.1}", stats.completed as f64 / secs);
    println!(
        "Transfer:     {:.2} MB/s ({} bytes total)",
        stats.bytes_received as f64 / secs / (1024.0 * 1024.0),
        stats.bytes_received
    );

    let lines: Vec<String> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| format!("  [{code}] {n}"))
        .collect();
    if !lines.is_empty() {
        println!("Status codes:");
        for line in lines {
            println!("{line}");
        }
    }

    if let Some(l) = latency_summary(&stats.latencies_ns) {
        println!("Latency (ms):");
        println!(
            "  min {:.3}  mean {:.3}  p50 {:.3}  p90 {:.3}  p99 {:.3}  max {:.3}",
            l.min * 1e3,
            l.mean * 1e3,
            l.p50 * 1e3,
            l.p90 * 1e3,
            l.p99 * 1e3,
            l.max * 1e3,
        );
    }
}

fn print_json_report(args: &Args, threads: usize, stats: &Stats, elapsed: Duration) -> Result<()> {
    let secs = elapsed.as_secs_f64();
    let status_codes: serde_json::Map<String, serde_json::Value> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| (code.to_string(), n.into()))
        .collect();
    let latency = latency_summary(&stats.latencies_ns).map(|l| {
        serde_json::json!({
            "min": l.min,
            "mean": l.mean,
            "p50": l.p50,
            "p90": l.p90,
            "p99": l.p99,
            "max": l.max,
        })
    });
    let report = serde_json::json!({
        "url": args.url,
        "threads": threads,
        "connections": args.connections,
        "durationSeconds": secs,
        "requests": {
            "total": stats.completed + stats.errors,
            "ok": stats.completed,
            "errors": stats.errors,
            "connectErrors": stats.connect_errors,
        },
        "requestsPerSec": stats.completed as f64 / secs,
        "bytesReceived": stats.bytes_received,
        "bytesPerSec": stats.bytes_received as f64 / secs,
        "statusCodes": status_codes,
        "latencySeconds": latency,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
