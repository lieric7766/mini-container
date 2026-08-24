use nix::fcntl::OFlag;
use nix::fcntl::open;
use nix::sys::stat::Mode;
use nix::{
    sys::wait::{WaitStatus, waitpid},
    unistd::{ForkResult, chdir, dup2_stdout, execvp, fork},
};
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
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

fn main() -> Result<ExitCode, std::io::Error> {
    let args: Vec<String> = env::args().collect();

    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let config = match args_str.as_slice() {
        [_, "run", run_args @ ..] => {
            let Ok(config) = parse_run_args(run_args) else {
                return Ok(ExitCode::FAILURE);
            };

            config
        }
        _ => {
            eprintln!("usage: mini-container run [--env KEY=VALUE] <command> [args...]");
            return Ok(ExitCode::FAILURE);
        }
    };

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => match waitpid(child, None) {
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
        },
        Ok(ForkResult::Child) => {
            let c_string = CString::new(config.command).unwrap();
            let command_c_str = c_string.as_c_str();

            let c_strings: Vec<CString> = config
                .args
                .iter()
                .map(|s| CString::new(*s).unwrap())
                .collect();

            let mut args_c_strs: Vec<&CStr> = c_strings.iter().map(|s| s.as_c_str()).collect();

            args_c_strs.insert(0, command_c_str);

            for (k, v) in config.envs {
                unsafe {
                    env::set_var(k, v);
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
        Err(_) => return Ok(ExitCode::FAILURE),
    };
}
