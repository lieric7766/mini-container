use std::env;
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
            let status = Command::new(command)
                .args(tail)
                .stdin(Stdio::inherit())
                .stderr(Stdio::null())
                .stdout(Stdio::piped())
                .status()?;

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
