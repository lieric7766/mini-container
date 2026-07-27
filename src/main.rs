use std::env;
use std::io::Read;
use std::io::{self, Write};
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;

fn to_exit_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

fn main() -> Result<ExitCode, std::io::Error> {
    let args: Vec<String> = env::args().collect();

    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    match args_str.as_slice() {
        [_, "run", command, tail @ ..] => {
            let mut child = Command::new(command)
                .args(tail)
                .stdout(Stdio::piped())
                .spawn()?;

            let Some(mut stdout) = child.stdout.take() else {
                return Ok(ExitCode::FAILURE);
            };

            let mut buffer = [0_u8; 1024];

            loop {
                let n = stdout.read(&mut buffer)?;

                if n == 0 {
                    break;
                }

                io::stdout().write_all(&buffer[..n])?;
            }

            let status = child.wait()?;

            match status.code() {
                Some(code) => {
                    return Ok(ExitCode::from(to_exit_code(code)));
                }
                None => {
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
        _ => {
            eprintln!("usage: [action] [command] [args...]");
            return Ok(ExitCode::FAILURE);
        }
    }
}
