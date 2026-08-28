use std::mem;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use io_uring::{IoUring, opcode, squeue, types};
use shiguredo_http11::{BodyKind, BodyProgress, HttpHead, Request, ResponseDecoder};

/// recv 書き込み枠の初期値。mut_buf はゼロ初期化を伴うため小さく始め、
/// 枠を使い切った recv が続く間だけ倍増させる (上限 RECV_WINDOW_MAX)
const RECV_WINDOW_INIT: usize = 4 * 1024;
/// recv 書き込み枠の上限 (デコーダーの max_buffer_size と同値)
const RECV_WINDOW_MAX: usize = 64 * 1024;
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
    /// 現在の recv 書き込み枠サイズ (適応的に増える)
    recv_window: usize,
    /// 直前の recv で確保した枠のサイズ (枠を使い切ったか判定用)
    last_recv_len: usize,
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
            recv_window: RECV_WINDOW_INIT,
            last_recv_len: 0,
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

// user_data: 下位 2bit がオペレーション種別、残りがコネクション番号
const OP_SEND: u64 = 0;
const OP_RECV: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_CONNECT_TIMEOUT: u64 = 3;

fn user_data(conn_idx: usize, op: u64) -> u64 {
    ((conn_idx as u64) << 2) | op
}

fn push_sqe(ring: &mut IoUring, entry: squeue::Entry) -> Result<()> {
    unsafe {
        if ring.submission().push(&entry).is_err() {
            ring.submit().context("io_uring submit failed")?;
            ring.submission()
                .push(&entry)
                .map_err(|_| anyhow::anyhow!("submission queue full after submit"))?;
        }
    }
    Ok(())
}

/// リンクされた 2 つの SQE を同一サブミッション内に投入する
///
/// IOSQE_IO_LINK のチェーンはサブミッション境界を跨げないため、
/// 空きが 2 スロット未満なら先に submit して空ける。
fn push_sqe_pair(ring: &mut IoUring, first: squeue::Entry, second: squeue::Entry) -> Result<()> {
    unsafe {
        {
            let sq = ring.submission();
            if sq.capacity() - sq.len() < 2 {
                drop(sq);
                ring.submit().context("io_uring submit failed")?;
            }
        }
        let mut sq = ring.submission();
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
    ring: &mut IoUring,
    conn_idx: usize,
    conn: &mut Conn,
    addr: &SocketAddr,
    raw_addr: &SockAddrRaw,
    timeout: &types::Timespec,
) -> Result<()> {
    conn.fd = make_socket(addr)?;
    // スロット上書きにより旧 fd への登録参照も解放される
    ring.submitter()
        .register_files_update(conn_idx as u32, &[conn.fd])
        .context("register_files_update failed")?;
    let connect = opcode::Connect::new(
        types::Fixed(conn_idx as u32),
        raw_addr.as_ptr(),
        raw_addr.len,
    )
    .build()
    .flags(squeue::Flags::IO_LINK)
    .user_data(user_data(conn_idx, OP_CONNECT));
    let link_timeout = opcode::LinkTimeout::new(timeout as *const types::Timespec)
        .build()
        .user_data(user_data(conn_idx, OP_CONNECT_TIMEOUT));
    push_sqe_pair(ring, connect, link_timeout)
}

fn push_send(ring: &mut IoUring, conn_idx: usize, conn: &Conn, request: &[u8]) -> Result<()> {
    let remaining = &request[conn.send_offset..];
    let entry = opcode::Send::new(
        types::Fixed(conn_idx as u32),
        remaining.as_ptr(),
        remaining.len() as u32,
    )
    .build()
    .user_data(user_data(conn_idx, OP_SEND));
    push_sqe(ring, entry)
}

/// デコーダー内部バッファに直接受信する Recv SQE を投入する (ゼロコピー)
///
/// `mut_buf` で確保した未確定領域に kernel が書き込み、完了時に
/// `advance_buf` で確定する。Recv の in-flight 中はこの Conn の decoder に
/// 一切触れないことがポインタ有効性の前提 (触れなければ内部 Vec は再確保されない)。
fn push_recv(ring: &mut IoUring, conn_idx: usize, conn: &mut Conn) -> Result<()> {
    let len = conn.decoder.available_buf().min(conn.recv_window);
    if len == 0 {
        bail!("decoder buffer full (response headers too large?)");
    }
    conn.last_recv_len = len;
    let buf = conn
        .decoder
        .mut_buf(len)
        .map_err(|e| anyhow::anyhow!("mut_buf failed: {e:?}"))?;
    let entry = opcode::Recv::new(
        types::Fixed(conn_idx as u32),
        buf.as_mut_ptr(),
        buf.len() as u32,
    )
    .build()
    .user_data(user_data(conn_idx, OP_RECV));
    push_sqe(ring, entry)
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
        for (a, b) in self.status_counts.iter_mut().zip(other.status_counts.iter()) {
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
                args.requests / threads as u64 + u64::from((i as u64) < args.requests % threads as u64)
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

    print_report(&args, threads, &stats, elapsed);
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

    // conns は ring より先に宣言する。逆順 drop により ring (teardown 時に
    // in-flight オペレーションのキャンセル完了を待つ) が先に破棄され、
    // in-flight recv が書き込むデコーダーバッファ (conns 内) の解放後に
    // kernel が書き込む use-after-free を防ぐ。
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        conns.push(Conn::new());
    }

    let entries = (connections * 2).next_power_of_two().max(256) as u32;
    // SINGLE_ISSUER: このリングは本スレッドしか触らない前提をカーネルに伝える
    // COOP_TASKRUN / DEFER_TASKRUN: ソケット完了の task work を任意タイミングの
    // 割り込みではなく io_uring_enter 時にまとめて実行させる (要 kernel 6.1+)
    let mut ring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .build(entries)
        .or_else(|_| {
            // 古いカーネル向けフォールバック
            IoUring::new(entries)
        })
        .context("failed to create io_uring")?;

    // コネクションごとに固定ファイルスロットを確保し、SQE では
    // types::Fixed(conn_idx) を使って fd 参照カウント操作を省く
    ring.submitter()
        .register_files_sparse(connections as u32)
        .context("register_files_sparse failed")?;

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
        push_sqe(&mut ring, entry)?;
    }

    // 初回リクエスト投入 (接続確立も io_uring 経由の非同期 connect)
    for i in 0..conns.len() {
        if started >= max_requests {
            break;
        }
        started += 1;
        conns[i].begin_request();
        start_connect(
            &mut ring,
            i,
            &mut conns[i],
            &target.addr,
            &raw_addr,
            &connect_timeout,
        )?;
    }

    let mut cqe_buf: Vec<(u64, i32)> = Vec::with_capacity(entries as usize);
    let mut stop = false;

    'outer: loop {
        if stats.completed + stats.errors >= max_requests {
            break;
        }
        ring.submit_and_wait(1).context("submit_and_wait failed")?;

        cqe_buf.clear();
        for cqe in ring.completion() {
            cqe_buf.push((cqe.user_data(), cqe.result()));
        }

        for &(ud, res) in &cqe_buf {
            if ud == TIMEOUT_USER_DATA {
                stop = true;
                continue;
            }
            let conn_idx = (ud >> 2) as usize;
            let op = ud & 0b11;
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
                        // レイテンシは送信開始から測る (接続確立時間は含めない)
                        conn.request_start = Instant::now();
                        push_send(&mut ring, conn_idx, conn, &target.request_bytes)?;
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
                            push_send(&mut ring, conn_idx, conn, &target.request_bytes)?;
                        } else {
                            push_recv(&mut ring, conn_idx, conn)?;
                        }
                    }
                }
                OP_RECV => {
                    let conn = &mut conns[conn_idx];
                    // mut_buf で確保した未確定領域を確定 (エラー/EOF 時は破棄)
                    conn.decoder
                        .advance_buf(if res > 0 { res as usize } else { 0 });
                    if res < 0 {
                        stats.errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else if res == 0 {
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
                        // 枠を使い切った = まだ受信データが残っている可能性が高い
                        if res as usize == conn.last_recv_len {
                            conn.recv_window = (conn.recv_window * 2).min(RECV_WINDOW_MAX);
                        }
                        match conn.parse() {
                            Ok(ParseOutcome::Complete { keep_alive }) => {
                                stats.record_success(conn);
                                request_finished = true;
                                keep_conn = keep_alive;
                            }
                            Ok(ParseOutcome::NeedMoreData) => {
                                if let Err(e) = push_recv(&mut ring, conn_idx, conn) {
                                    eprintln!("recv setup failed: {e}");
                                    stats.errors += 1;
                                    request_finished = true;
                                    keep_conn = false;
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
                _ => unreachable!(),
            }

            if request_finished {
                let conn = &mut conns[conn_idx];
                if !stop && started < max_requests {
                    started += 1;
                    conn.begin_request();
                    if keep_conn && conn.connected {
                        push_send(&mut ring, conn_idx, conn, &target.request_bytes)?;
                    } else {
                        conn.close();
                        conn.decoder.reset();
                        if let Err(e) = start_connect(
                            &mut ring,
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

    if !stats.latencies_ns.is_empty() {
        let mut lat = stats.latencies_ns.clone();
        lat.sort_unstable();
        let pct = |p: f64| -> f64 {
            let idx = ((lat.len() as f64 * p).ceil() as usize).saturating_sub(1);
            lat[idx.min(lat.len() - 1)] as f64 / 1e6
        };
        let mean = lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1e6;
        println!("Latency (ms):");
        println!(
            "  min {:.3}  mean {:.3}  p50 {:.3}  p90 {:.3}  p99 {:.3}  max {:.3}",
            lat[0] as f64 / 1e6,
            mean,
            pct(0.50),
            pct(0.90),
            pct(0.99),
            lat[lat.len() - 1] as f64 / 1e6,
        );
    }
}
