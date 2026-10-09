use nix::fcntl::OFlag;
use nix::fcntl::open;
use nix::sys::stat::Mode;
use nix::errno::Errno;
use nix::{
    sys::wait::{WaitStatus, waitpid},
    unistd::{chroot, ForkResult, Pid, chdir, dup2_stdin, dup2_stdout, execvp, fork, pipe, sethostname, write},
    sched::{unshare, CloneFlags},
    mount::{mount, MsFlags}
};
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::fd::OwnedFd;
use std::process::ExitCode;

struct RunConfig<'a> {
    envs: Vec<(&'a str, &'a str)>,
    command: &'a str,
    cwd: Option<&'a str>,
    args: Vec<&'a str>,
    stdout_redirect_path: Option<&'a str>,
}

#[derive(Debug)]
struct ConfigError;

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to read configuration")
    }
}
impl Error for ConfigError {}

fn parse_run_args<'a>(args: &[&'a str]) -> Result<RunConfig<'a>, ConfigError> {
    let mut arg_iter = args.iter();
    let mut envs: Vec<(&'a str, &'a str)> = vec![];
    let mut command: &'a str = "";
    let mut command_args: Vec<&'a str> = vec![];
    let mut cwd: Option<&'a str> = None;
    let mut stdout_redirect_path: Option<&'a str> = None;
    loop {
        match arg_iter.next() {
            Some(x) => {
                if command.is_empty() && *x == "--env" {
                    let Some(env) = arg_iter.next() else {
                        return Err(ConfigError {});
                    };

                    let Some((k, v)) = (*env).split_once("=") else {
                        return Err(ConfigError {});
                    };
                    envs.push((k, v));
                } else if command.is_empty() && cwd.is_none() && *x == "--cwd" {
                    let Some(cwd_arg) = arg_iter.next() else {
                        return Err(ConfigError {});
                    };
                    cwd = Some(*cwd_arg);
                } else if command.is_empty() && stdout_redirect_path.is_none() && *x == "--stdout" {
                    let Some(stdout_redirect_path_arg) = arg_iter.next() else {
                        return Err(ConfigError {});
                    };
                    stdout_redirect_path = Some(*stdout_redirect_path_arg);
                } else if command.is_empty() {
                    command = *x;
                } else {
                    command_args.push(*x);
                }
            }
            None => break,
        }
    }

    if command.is_empty() {
        return Err(ConfigError {});
    }

    Ok(RunConfig {
        envs,
        cwd,
        stdout_redirect_path,
        command,
        args: command_args,
    })
}

fn to_exit_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

fn run_command_with_pipe(configs: Vec<RunConfig>) -> Result<ExitCode, std::io::Error> {
    let mut pipes: Vec<(OwnedFd, OwnedFd)> = Vec::new();
    let mut children: Vec<Pid> = Vec::new();
    let mut status_codes: Vec<ExitCode> = Vec::new();

    for _ in 0..configs.len() - 1 {
        pipes.push(pipe().unwrap());
    }

    for (i, config) in configs.iter().enumerate() {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                children.push(child);
            }
            Ok(ForkResult::Child) => {
                if let Err(_) = unshare(CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID) {
                    write(std::io::stdout(), "unshare error\n".as_bytes()).ok();
                    unsafe { libc::_exit(1) };
                }

                if let Err(_) = sethostname("mini-container") {
                    write(std::io::stdout(), "sethostname error\n".as_bytes()).ok();
                    unsafe { libc::_exit(1) };

                }

                if let Err(_) = mount(Some("proc"), "/tmp/myroot/proc", Some("proc"), MsFlags::empty(), None::<&str>) {
                    write(std::io::stdout(), "mount error\n".as_bytes()).ok();
                    unsafe { libc::_exit(1) };
                }

                if let Err(_) = chroot("/tmp/myroot") {
                    write(std::io::stdout(), "chroot error\n".as_bytes()).ok();
                    unsafe { libc::_exit(1) };
                }

                if let Err(_) = chdir("/") {
                    write(std::io::stdout(), "chdir error\n".as_bytes()).ok();
                    unsafe { libc::_exit(1) };
                }

                let c_string = CString::new(config.command).unwrap();
                let command_c_str = c_string.as_c_str();

                let c_strings: Vec<CString> = config
                    .args
                    .iter()
                    .map(|s| CString::new(*s).unwrap())
                    .collect();

                let mut args_c_strs: Vec<&CStr> = c_strings.iter().map(|s| s.as_c_str()).collect();

                args_c_strs.insert(0, command_c_str);

                for (k, v) in &config.envs {
                    unsafe {
                        env::set_var(*k, *v);
                    }
                }

                if let Some(cwd) = config.cwd {
                    if let Err(e) = chdir(cwd) {
                        eprintln!(" chdir error occured: {}", e);
                        unsafe {
                            libc::_exit(1);
                        }
                    }
                }

                if let Some(path) = config.stdout_redirect_path {
                    let foo = open(
                        path,
                        OFlag::O_WRONLY | OFlag::O_TRUNC | OFlag::O_CREAT,
                        Mode::S_IRWXU,
                    )
                    .unwrap();
                    // Now our Stdout has been redirected to file foo
                    dup2_stdout(foo).unwrap();
                }

                if i == 0 {
                    let (_, wfd) = &pipes[i];
                    dup2_stdout(wfd).unwrap();
                } else if i == configs.len() - 1 {
                    let (rfd, _) = &pipes[i - 1];
                    dup2_stdin(rfd).unwrap();
                } else {
                    //
                    let (rfd, _) = &pipes[i - 1];
                    let (_, wfd) = &pipes[i];
                    dup2_stdin(rfd).unwrap();
                    dup2_stdout(wfd).unwrap();
                }
                drop(pipes);

                let Err(e) = execvp(command_c_str, &args_c_strs);

                eprintln!(" execvp error occured: {}", e);

                unsafe {
                    libc::_exit(1);
                }
            }
            Err(_) => return Ok(ExitCode::FAILURE),
        };
    }

    drop(pipes);
    for child in children {
        match waitpid(child, None) {
            Ok(status) => match status {
                WaitStatus::Exited(_, code) => {
                    status_codes.push(ExitCode::from(to_exit_code(code)));
                }
                WaitStatus::Signaled(_, _, _) => {
                    status_codes.push(ExitCode::FAILURE);
                }
                WaitStatus::Stopped(_, _) => {
                    status_codes.push(ExitCode::FAILURE);
                }
                _ => {
                    status_codes.push(ExitCode::FAILURE);
                }
            },
            Err(_) => status_codes.push(ExitCode::FAILURE),
        };
    }
    if let Some(last_status_code) = status_codes.last() {
        return Ok(*last_status_code);
    } else {
        return Ok(ExitCode::FAILURE);
    }
}


fn run_command(config: &RunConfig) -> Result<i32, std::io::Error> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let mut main_exit_code: Option<i32> = None;
            loop {
                match waitpid(None, None) {
                    Ok(WaitStatus::Exited(pid, code)) => {
                        if pid == child {
                            main_exit_code = Some(code);
                        }
                    }
                    Ok(WaitStatus::Signaled(pid, signal, _)) => {
                        if pid == child {
                            main_exit_code = Some(128 + signal as i32);
                        }
                    }
                    Err(Errno::ECHILD) => {
                        return Ok(main_exit_code.unwrap_or(1));

                    }
                    Err(Errno::EINTR) => {
                        continue;
                    }
                    Err(e) => {
                        return Err(std::io::Error::from_raw_os_error(e as i32));
                    }
                    _ => {
                        // 其他 process status 不代表
                        // 所有 child 都已經結束
                        continue;
                    }
                };
            }
        }
        Ok(ForkResult::Child) => {
            if let Err(_) = sethostname("mini-container") {
                write(std::io::stdout(), "sethostname error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };

            }

            if let Err(_) = mount(Some("proc"), "/tmp/myroot/proc", Some("proc"), MsFlags::empty(), None::<&str>) {
                write(std::io::stdout(), "mount error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };
            }

            if let Err(_) = chroot("/tmp/myroot") {
                write(std::io::stdout(), "chroot error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };
            }

            if let Err(_) = chdir("/") {
                write(std::io::stdout(), "chdir error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };
            }

            let c_string = CString::new(config.command).unwrap();
            let command_c_str = c_string.as_c_str();

            let c_strings: Vec<CString> = config
                .args
                .iter()
                .map(|s| CString::new(*s).unwrap())
                .collect();

            let mut args_c_strs: Vec<&CStr> = c_strings.iter().map(|s| s.as_c_str()).collect();

            args_c_strs.insert(0, command_c_str);

            for (k, v) in &config.envs {
                unsafe {
                    env::set_var(*k, *v);
                }
            }

            if let Some(cwd) = config.cwd {
                if let Err(e) = chdir(cwd) {
                    eprintln!(" chdir error occured: {}", e);
                    unsafe {
                        libc::_exit(1);
                    }
                }
            }

            if let Some(path) = config.stdout_redirect_path {
                let foo = open(
                    path,
                    OFlag::O_WRONLY | OFlag::O_TRUNC | OFlag::O_CREAT,
                    Mode::S_IRWXU,
                )
                .unwrap();
                // Now our Stdout has been redirected to file foo
                dup2_stdout(foo).unwrap();
            }

            let Err(e) = execvp(command_c_str, &args_c_strs);

            eprintln!(" execvp error occured: {}", e);

            unsafe {
                libc::_exit(1);
            }

        }
        Err(_) => {unsafe { libc::_exit(0) }},
    };

}


fn run_container(config: &RunConfig) -> Result<i32, std::io::Error> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            match waitpid(child, None) {
                Ok(status) => match status {
                    WaitStatus::Exited(pid, code) => {
                        return Ok(code);
                    }
                    WaitStatus::Signaled(_, _, _) => {
                        return Ok(1);
                    }
                    WaitStatus::Stopped(_, _) => {
                        return Ok(1);
                    }
                    _ => {
                        return Ok(1);
                    }
                },
                Err(_) => { return Ok(1)},
            };
        }
        Ok(ForkResult::Child) => {
            if let Ok(code) = run_command(config) {
                return Ok(code);
            } 
            return Ok(1);
        }
        Err(_) => {unsafe { libc::_exit(0) }},
    };

}

fn setup_child(config: &RunConfig) -> Result<ExitCode, std::io::Error> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            match waitpid(child, None) {
                Ok(status) => match status {
                    WaitStatus::Exited(_, code) => {
                        return Ok(ExitCode::from(to_exit_code(code)));
                    }
                    WaitStatus::Signaled(_, _, _) => {
                        return Ok(ExitCode::FAILURE);
                    }
                    WaitStatus::Stopped(_, _) => {
                        return Ok(ExitCode::FAILURE);
                    }
                    _ => {
                        return Ok(ExitCode::FAILURE);
                    }
                },
                Err(_) => return Ok(ExitCode::FAILURE),
            };
        }
        Ok(ForkResult::Child) => {
            if let Err(_) = unshare(CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID) {
                write(std::io::stdout(), "unshare error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };
            }

            if let Ok(code) = run_container(config) {
                unsafe { libc::_exit(code) };

            } else {
                unsafe { libc::_exit(1) };
            }

        }
        Err(_) => return Ok(ExitCode::FAILURE),
    };
}

fn main() -> Result<ExitCode, std::io::Error> {
    let args: Vec<String> = env::args().collect();

    let commands: Vec<&[String]> = args.split(|x| *x == "|").collect();

    let mut command_configs: Vec<RunConfig> = Vec::new();

    for c in commands {
        let args_str: Vec<&str> = c.iter().map(|s| s.as_str()).collect();

        let config = match args_str.as_slice() {
            [_, "run", run_args @ ..] => {
                let Ok(config) = parse_run_args(run_args) else {
                    return Ok(ExitCode::FAILURE);
                };

                config
            }
            [run_args @ ..] => {
                let Ok(config) = parse_run_args(run_args) else {
                    return Ok(ExitCode::FAILURE);
                };

                config
            }
        };
        command_configs.push(config);
    }

    if command_configs.len() > 1 {
        return run_command_with_pipe(command_configs);
    } else if command_configs.len() == 1 {
        return setup_child(&command_configs[0]);
    } else {
        return Ok(ExitCode::FAILURE);
    }
}
