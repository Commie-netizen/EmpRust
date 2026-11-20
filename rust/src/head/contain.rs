//! Running a program with OS-enforced containment.
//!
//! On Linux, a contained run starts in new user, network and PID namespaces, created
//! without privileges. The process forked by the standard library (the "keeper") stays
//! outside the new PID namespace, becomes a child subreaper and forks the program, which is
//! PID 1 of the new namespace and dies with the keeper (`PR_SET_PDEATHSIG`). When PID 1 ends,
//! the kernel kills every process left in the namespace, `setsid` or not; the keeper reaps
//! them all, then reports the program's status and whether cleanup completed through a
//! private pipe. The network namespace has only a loopback interface, down: no network.
//!
//! The environment is exactly what the caller gives (cleared first), stdin is empty, and
//! stdout and stderr are drained and hashed in full. Capture is complete only when both
//! reach their end and the total stays within the bound.
//!
//! An uncontained run (asked for explicitly, or on a platform without this mechanism) is
//! never reported as contained: whoever uses its outcome must treat it as incomplete.
use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct RunSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    /// Output beyond this many bytes makes the capture incomplete (it is still hashed).
    pub max_output: u64,
    pub contain: bool,
    /// Keep stdout whole (up to max_output) for the caller, e.g. a list of files.
    pub keep_stdout: bool,
}

#[derive(Debug, Default)]
pub struct RunOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// SHA-256 of "stdout:" + hex SHA-256(stdout) + "\nstderr:" + hex SHA-256(stderr).
    pub output_sha256: String,
    pub output_bytes: u64,
    pub capture_complete: bool,
    pub contained: bool,
    pub network_isolated: bool,
    pub cleanup_confirmed: bool,
    pub problems: Vec<String>,
    /// The last bytes of stdout then stderr, for display only.
    pub tail: Vec<u8>,
    pub stdout: Vec<u8>,
}

impl RunOutcome {
    /// Exit 0, no timeout, complete capture, contained and cleaned up.
    pub fn clean_success(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out
            && self.capture_complete
            && self.contained
            && self.cleanup_confirmed
    }
}

/// Whether contained runs are available on this platform (Linux namespaces).
pub fn available() -> bool {
    cfg!(target_os = "linux")
}

const TAIL: usize = 4000;
const STATUS_BYTES: usize = 10;

pub fn run(spec: &RunSpec) -> Result<RunOutcome> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut outcome = RunOutcome::default();
    #[cfg(target_os = "linux")]
    let status_pipe = if spec.contain {
        Some(linux::prepare(&mut command, spec.timeout)?)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if spec.contain {
        outcome
            .problems
            .push("confinement indisponible sur cette plateforme".into());
        return Ok(outcome);
    }
    #[cfg(unix)]
    if !spec.contain {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let started = Instant::now();
    let mut child = command.spawn()?;
    #[cfg(target_os = "linux")]
    let status_reader = status_pipe.map(|p| p.after_spawn());
    let keep = spec.max_output;
    let keep_stdout = spec.keep_stdout;
    let (tx, rx) = mpsc::channel();
    let readers = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    for (index, reader) in readers.into_iter().enumerate() {
        let tx = tx.clone();
        let Some(mut reader) = reader else { continue };
        std::thread::spawn(move || {
            let mut hasher = Sha256::new();
            let mut tail: Vec<u8> = Vec::new();
            let mut whole: Vec<u8> = Vec::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 8192];
            let mut failed = false;
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buffer[..n]);
                        total += n as u64;
                        if index == 0 && keep_stdout && whole.len() as u64 + (n as u64) <= keep {
                            whole.extend_from_slice(&buffer[..n]);
                        }
                        tail.extend_from_slice(&buffer[..n]);
                        if tail.len() > TAIL {
                            let cut = tail.len() - TAIL;
                            tail.drain(..cut);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            let _ = tx.send((
                index,
                hex::encode(hasher.finalize()),
                total,
                tail,
                whole,
                failed,
            ));
        });
    }
    drop(tx);
    // The keeper enforces the timeout inside; this deadline is only a backstop for a
    // keeper that would not report (and the timeout itself for an uncontained run).
    let backstop = spec.timeout
        + if spec.contain {
            Duration::from_secs(30)
        } else {
            Duration::ZERO
        };
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= backstop {
            outcome.timed_out = true;
            if !spec.contain {
                kill_group(child.id());
            }
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !spec.contain {
        kill_group(child.id());
        outcome.exit_code = status.code();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            outcome.signal = status.signal();
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(reader) = status_reader {
        match reader.read_status() {
            Some(report) => {
                outcome.exit_code = report.exit_code;
                outcome.signal = report.signal;
                outcome.timed_out |= report.timed_out;
                outcome.cleanup_confirmed = report.cleanup && status.code() == Some(0);
                outcome.contained = true;
                outcome.network_isolated = true;
            }
            None => outcome
                .problems
                .push("le gardien du confinement n'a rien rapporté".into()),
        }
    }
    let mut streams: [(String, u64, Vec<u8>, Vec<u8>); 2] = Default::default();
    let mut complete = true;
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok((index, digest, total, tail, whole, failed)) => {
                complete &= !failed;
                streams[index] = (digest, total, tail, whole);
            }
            Err(_) => complete = false,
        }
    }
    outcome.output_bytes = streams[0].1 + streams[1].1;
    if !complete {
        outcome
            .problems
            .push("sortie non lue jusqu'au bout (un descendant la tient ouverte)".into());
    }
    if outcome.output_bytes > spec.max_output {
        outcome.problems.push(format!(
            "sortie de {} octets, au-delà de la borne de {}",
            outcome.output_bytes, spec.max_output
        ));
    }
    outcome.capture_complete = complete && outcome.output_bytes <= spec.max_output;
    if spec.contain && !outcome.cleanup_confirmed && outcome.contained {
        outcome
            .problems
            .push("nettoyage des descendants non confirmé".into());
    }
    if !spec.contain {
        outcome
            .problems
            .push("lancé sans confinement : descendants et réseau non contrôlés".into());
    }
    let combined = format!(
        "stdout:{}\nstderr:{}{}",
        streams[0].0,
        streams[1].0,
        if complete { "" } else { "\nincomplete" }
    );
    outcome.output_sha256 = hex::encode(Sha256::digest(combined.as_bytes()));
    let mut tail = std::mem::take(&mut streams[0].2);
    tail.extend_from_slice(&streams[1].2);
    outcome.tail = tail;
    outcome.stdout = std::mem::take(&mut streams[0].3);
    Ok(outcome)
}

#[cfg(unix)]
fn kill_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}
#[cfg(not(unix))]
fn kill_group(_pid: u32) {}

#[cfg(target_os = "linux")]
mod linux {
    use super::STATUS_BYTES;
    use anyhow::Result;
    use std::ffi::CString;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;

    pub struct Pipe {
        read: i32,
        write: i32,
    }
    pub struct StatusReader {
        read: i32,
    }
    pub struct Report {
        pub exit_code: Option<i32>,
        pub signal: Option<i32>,
        pub timed_out: bool,
        pub cleanup: bool,
    }

    impl Pipe {
        pub fn after_spawn(self) -> StatusReader {
            unsafe { libc::close(self.write) };
            StatusReader { read: self.read }
        }
    }

    impl StatusReader {
        pub fn read_status(self) -> Option<Report> {
            let mut buffer = [0u8; STATUS_BYTES];
            let mut got = 0;
            while got < STATUS_BYTES {
                let n = unsafe {
                    libc::read(
                        self.read,
                        buffer[got..].as_mut_ptr() as *mut libc::c_void,
                        STATUS_BYTES - got,
                    )
                };
                if n <= 0 {
                    break;
                }
                got += n as usize;
            }
            unsafe { libc::close(self.read) };
            if got != STATUS_BYTES {
                return None;
            }
            let code = i32::from_le_bytes(buffer[0..4].try_into().ok()?);
            let signal = i32::from_le_bytes(buffer[4..8].try_into().ok()?);
            Some(Report {
                exit_code: (signal == 0).then_some(code),
                signal: (signal != 0).then_some(signal),
                timed_out: buffer[8] == 1,
                cleanup: buffer[9] == 1,
            })
        }
    }

    fn write_all(fd: i32, bytes: &[u8]) -> bool {
        let mut done = 0;
        while done < bytes.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[done..].as_ptr() as *const libc::c_void,
                    bytes.len() - done,
                )
            };
            if n <= 0 {
                return false;
            }
            done += n as usize;
        }
        true
    }

    fn write_file(path: &CString, bytes: &[u8]) -> bool {
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return false;
        }
        let ok = write_all(fd, bytes);
        unsafe { libc::close(fd) };
        ok
    }

    fn monotonic_ms() -> i64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
    }

    fn nap() {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }

    /// Install the namespace set-up and the keeper in the child, before exec.
    pub fn prepare(command: &mut Command, timeout: Duration) -> Result<Pipe> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let (read, write) = (fds[0], fds[1]);
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let uid_line = format!("{uid} {uid} 1\n").into_bytes();
        let gid_line = format!("{gid} {gid} 1\n").into_bytes();
        let setgroups = CString::new("/proc/self/setgroups").unwrap();
        let uid_map = CString::new("/proc/self/uid_map").unwrap();
        let gid_map = CString::new("/proc/self/gid_map").unwrap();
        let timeout_ms = timeout.as_millis().min(i64::MAX as u128) as i64;
        unsafe {
            command.pre_exec(move || {
                // Everything here runs in the forked child: async-signal-safe calls only.
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWPID) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                write_file(&setgroups, b"deny\n");
                if !write_file(&uid_map, &uid_line) || !write_file(&gid_map, &gid_line) {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                // Bring up the namespace's own loopback (it starts down): programs can talk
                // to themselves; no other interface exists, so nothing leaves the machine.
                let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
                if sock >= 0 {
                    let mut request: libc::ifreq = std::mem::zeroed();
                    request.ifr_name[0] = b'l' as libc::c_char;
                    request.ifr_name[1] = b'o' as libc::c_char;
                    if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut request) == 0 {
                        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                        libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &mut request);
                    }
                    libc::close(sock);
                }
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
                let pid = libc::fork();
                if pid < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if pid == 0 {
                    // PID 1 of the new namespace: dies with the keeper, then execs the program.
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                    libc::close(write);
                    return Ok(());
                }
                // The keeper: hold no pipe the caller waits on, except the status pipe.
                for fd in 0..4096 {
                    if fd != write {
                        libc::close(fd);
                    }
                }
                let deadline = monotonic_ms() + timeout_ms;
                let mut status = 0i32;
                let mut timed_out = 0u8;
                loop {
                    let r = libc::waitpid(pid, &mut status, libc::WNOHANG);
                    if r == pid {
                        break;
                    }
                    if r < 0 {
                        status = -1;
                        break;
                    }
                    if timed_out == 0 && monotonic_ms() >= deadline {
                        libc::kill(pid, libc::SIGKILL);
                        timed_out = 1;
                    }
                    nap();
                }
                // PID 1 is gone: the kernel killed the rest of the namespace; reap them all.
                let reap_deadline = monotonic_ms() + 10_000;
                let mut cleanup = 0u8;
                loop {
                    let mut ignored = 0i32;
                    let r = libc::waitpid(-1, &mut ignored, libc::WNOHANG);
                    if r < 0 {
                        cleanup = 1; // no child left at all
                        break;
                    }
                    if r == 0 {
                        if monotonic_ms() >= reap_deadline {
                            break;
                        }
                        nap();
                    }
                }
                let (code, signal) = if status == -1 {
                    (-1, 0)
                } else if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), 0)
                } else if libc::WIFSIGNALED(status) {
                    (0, libc::WTERMSIG(status))
                } else {
                    (-1, 0)
                };
                let mut record = [0u8; STATUS_BYTES];
                record[0..4].copy_from_slice(&code.to_le_bytes());
                record[4..8].copy_from_slice(&signal.to_le_bytes());
                record[8] = timed_out;
                record[9] = cleanup;
                write_all(write, &record);
                libc::_exit(0);
            });
        }
        Ok(Pipe { read, write })
    }
}

/// A short description of a run's isolation, for results.
pub fn describe(outcome: &RunOutcome) -> serde_json::Value {
    serde_json::json!({
        "contained": outcome.contained,
        "network_isolated": outcome.network_isolated,
        "cleanup_confirmed": outcome.cleanup_confirmed,
        "capture_complete": outcome.capture_complete,
    })
}

pub fn error_outcome(reason: String) -> RunOutcome {
    RunOutcome {
        problems: vec![reason],
        ..Default::default()
    }
}

pub fn not_run(reason: &str) -> anyhow::Error {
    anyhow!("{reason}")
}
