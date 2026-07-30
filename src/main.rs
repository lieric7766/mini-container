use std::env;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::io::{self, Write};
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::thread;

struct RunConfig<'a> {
    envs: Vec<(&'a str, &'a str)>,
    command: &'a str,
    args: Vec<&'a str>,
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

    let mut child = Command::new(config.command)
        .args(config.args)
        .envs(config.envs)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let Some(mut stdin) = child.stdin.take() else {
        return Ok(ExitCode::FAILURE);
    };

    let Some(mut stdout) = child.stdout.take() else {
        return Ok(ExitCode::FAILURE);
    };

    let Some(mut stderr) = child.stderr.take() else {
        return Ok(ExitCode::FAILURE);
    };

    thread::spawn(move || {
        let mut buffer = [0_u8; 1024];

        loop {
            match io::stdin().read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = stdin.write_all(&buffer[..n]) {
                        eprintln!("stdin write failed: {}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        drop(stdin);
    });

    let handle1 = thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        loop {
            match stdout.read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = io::stdout().write_all(&buffer[..n]) {
                        eprintln!("stdout write failed: {}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        drop(stdout);
    });

    let handle2 = thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        loop {
            match stderr.read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = io::stderr().write_all(&buffer[..n]) {
                        eprintln!("stderr write failed: {}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        drop(stderr);
    });

    let status = child.wait()?;

    if let Err(_) = handle1.join() {
        eprintln!("stdout thread failed");
    }

    if let Err(_) = handle2.join() {
        eprintln!("sterr thread failed");
    };

    match status.code() {
        Some(code) => {
            return Ok(ExitCode::from(to_exit_code(code)));
        }
        None => {
            return Ok(ExitCode::FAILURE);
        }
    }
}
