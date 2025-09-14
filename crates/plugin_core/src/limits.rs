use std::process::Command;

use crate::protocol::Limits;

#[cfg(unix)]
#[allow(unsafe_code)]
pub fn apply_limits(cmd: &mut Command, limits: &Limits) {
    use libc::{rlimit, RLIMIT_AS, RLIMIT_CPU};
    use std::os::unix::process::CommandExt;

    let cpu = limits.cpu_ms;
    let mem = limits.mem_mb;
    // Safety: `pre_exec` runs after `fork` in the child process; within the
    // closure we only call the async-signal-safe `setrlimit` and access the
    // copied `limits` values, so no memory is shared with the parent and no
    // undefined behavior occurs.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(ms) = cpu {
                let secs = ms.div_ceil(1000);
                let lim = rlimit {
                    rlim_cur: secs,
                    rlim_max: secs,
                };
                if libc::setrlimit(RLIMIT_CPU, &lim) != 0 {
                    Err(std::io::Error::last_os_error())?;
                }
            }
            if let Some(mb) = mem {
                let bytes = mb * 1024 * 1024;
                let lim = rlimit {
                    rlim_cur: bytes,
                    rlim_max: bytes,
                };
                if libc::setrlimit(RLIMIT_AS, &lim) != 0 {
                    Err(std::io::Error::last_os_error())?;
                }
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub fn apply_limits(_cmd: &mut Command, _limits: &Limits) {}
