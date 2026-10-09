use nix::{
    sys::wait::{waitpid},
    unistd::{write, ForkResult, chdir, dup2_stdin, dup2_stdout, execvp, fork, pipe, sethostname},
    sched::{unshare, CloneFlags}
};
use std::process::ExitCode;
use std::ffi::{CStr, CString};

fn main() -> Result<ExitCode, std::io::Error> {

    match unsafe{fork()} {
       Ok(ForkResult::Parent { child, .. }) => {
           println!("Continuing execution in parent process, new child has pid: {}", child);
           waitpid(child, None).unwrap();
           return Ok(ExitCode::FAILURE);
       }
       Ok(ForkResult::Child) => {
           // Unsafe to use `println!` (or `unwrap`) here. See Safety.
           if let Err(_) = unshare(CloneFlags::CLONE_NEWUTS) {
               write(std::io::stdout(), "unshare error\n".as_bytes()).ok();
               unsafe { libc::_exit(1) };
           }

           if let Err(_) = sethostname("ericli") {
               write(std::io::stdout(), "sethostname error\n".as_bytes()).ok();
               unsafe { libc::_exit(1) };

           }
           let uname_c_string = CString::new("uname").unwrap();
           let uname_c_str = uname_c_string.as_c_str();

           let uname_arg_c_string = CString::new("-n").unwrap();
           let uname_arg_c_str = uname_arg_c_string.as_c_str();

           if let Err(_) = execvp(uname_c_str, &[uname_c_str, uname_arg_c_str]) {
               unsafe { libc::_exit(1) };
           }
           unsafe { libc::_exit(0) };
       }
       Err(_) => { return Ok(ExitCode::FAILURE); },
    }

}
