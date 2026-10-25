use nix::fcntl::OFlag;
use nix::fcntl::open;
use nix::sys::stat::Mode;
use nix::errno::Errno;
use nix::{
    sys::wait::{WaitStatus, waitpid},
    unistd::{chroot, ForkResult, Pid, chdir, dup2_stdin, dup2_stdout, execvp, fork, pipe, sethostname, write, read},
    sched::{unshare, CloneFlags},
    mount::{mount, MsFlags}
};
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::ExitCode;
use std::net::Ipv4Addr;

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

#[repr(C)]
#[derive(Default)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

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


fn append_attr(
    buff: &mut Vec<u8>,
    attr_type: u16,
    data: &[u8],
) {
    let attr = libc::rtattr {
        rta_len: (
            std::mem::size_of::<libc::rtattr>() + data.len()
        ) as u16,
        rta_type: attr_type,
    };

    let attr_bytes = unsafe {
        std::slice::from_raw_parts(
            &attr as *const libc::rtattr as *const u8,
            std::mem::size_of::<libc::rtattr>(),
        )
    };

    buff.extend_from_slice(attr_bytes);
    buff.extend_from_slice(data);

    // Netlink Attribute 必須以 4 bytes 對齊
    buff.resize((buff.len() + 3) & !3, 0);
}

fn send_netlink_request(buff: &[u8]) -> std::io::Result<()> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };

    if raw_fd == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // OwnedFd 在離開 scope 時自動 close()
    let sock_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut kernel_addr: libc::sockaddr_nl =
        unsafe { std::mem::zeroed() };

    kernel_addr.nl_family = libc::AF_NETLINK as u16;
    kernel_addr.nl_pid = 0;
    kernel_addr.nl_groups = 0;

    let sent = unsafe {
        libc::sendto(
            sock_fd.as_raw_fd(),
            buff.as_ptr().cast(),
            buff.len(),
            0,
            (&kernel_addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>()
                as libc::socklen_t,
        )
    };

    if sent == -1 {
        return Err(std::io::Error::last_os_error());
    }

    if sent as usize != buff.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "Incomplete Netlink send",
        ));
    }

    println!("Sent {} bytes to Kernel", sent);

    let mut recv_buf = [0u8; 4096];

    let received = unsafe {
        libc::recv(
            sock_fd.as_raw_fd(),
            recv_buf.as_mut_ptr().cast(),
            recv_buf.len(),
            0,
        )
    };

    if received == -1 {
        return Err(std::io::Error::last_os_error());
    }

    println!("Received {} bytes from Kernel", received);

    let header_size = std::mem::size_of::<libc::nlmsghdr>();

    if (received as usize) < header_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Netlink response too short",
        ));
    }

    let response_header = unsafe {
        std::ptr::read_unaligned(
            recv_buf.as_ptr().cast::<libc::nlmsghdr>(),
        )
    };

    println!("Response type: {}", response_header.nlmsg_type);
    println!("Response length: {}", response_header.nlmsg_len);

    if response_header.nlmsg_type != libc::NLMSG_ERROR as u16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unexpected Netlink response",
        ));
    }

    let msg_len = response_header.nlmsg_len as usize;

    if msg_len < header_size + std::mem::size_of::<i32>()
        || msg_len > received as usize
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid Netlink ACK length",
        ));
    }

    let error = i32::from_ne_bytes(
        recv_buf[header_size..header_size + 4]
            .try_into()
            .unwrap(),
    );

    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(-error));
    }

    println!("Kernel ACK: success!");

    Ok(())
}

fn move_veth_to_netns(
    ifname: &str,
    child_pid: libc::pid_t,
) -> std::io::Result<()> {
    // 1. 取得 Host Namespace 裡的介面 index
    let name = CString::new(ifname)
        .map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid interface name",
        ))?;

    let ifindex = unsafe {
        libc::if_nametoindex(name.as_ptr())
    };

    if ifindex == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. Netlink Header
    let mut header = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buff = Vec::<u8>::new();

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const libc::nlmsghdr).cast::<u8>(),
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    };
    buff.extend_from_slice(header_bytes);

    // 3. 指定要移動的介面
    let mut info: libc::ifinfomsg = unsafe {
        std::mem::zeroed()
    };

    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex as i32;

    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            (&info as *const libc::ifinfomsg).cast::<u8>(),
            std::mem::size_of::<libc::ifinfomsg>(),
        )
    };
    buff.extend_from_slice(info_bytes);

    // 4. 指定目標 Network Namespace 的 Process PID
    append_attr(
        &mut buff,
        libc::IFLA_NET_NS_PID,
        &child_pid.to_ne_bytes(),
    );

    // 5. 回填 Message 長度
    header.nlmsg_len = buff.len() as u32;
    buff[0..4].copy_from_slice(&header.nlmsg_len.to_ne_bytes());

    println!(
        "Moving {} (ifindex {}) to PID {} NetNS",
        ifname, ifindex, child_pid
    );

    // 6. 傳送給 Kernel，檢查 ACK
    send_netlink_request(&buff)
}

fn setup_veth_pair() -> std::io::Result<()> {
    let mut header = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: (
            libc::NLM_F_REQUEST
                | libc::NLM_F_ACK
                | libc::NLM_F_CREATE
                | libc::NLM_F_EXCL
        ) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buff: Vec<u8> = Vec::new();

    // nlmsghdr
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const libc::nlmsghdr).cast::<u8>(),
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    };
    buff.extend_from_slice(header_bytes);

    // ifinfomsg
    let info: libc::ifinfomsg = unsafe {
        std::mem::zeroed()
    };

    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            (&info as *const libc::ifinfomsg).cast::<u8>(),
            std::mem::size_of::<libc::ifinfomsg>(),
        )
    };
    buff.extend_from_slice(info_bytes);

    // veth-host
    append_attr(
        &mut buff,
        libc::IFLA_IFNAME,
        b"veth-host\0",
    );

    // IFLA_LINKINFO
    let linkinfo_start = buff.len();

    let linkinfo = libc::rtattr {
        rta_len: 0,
        rta_type: libc::IFLA_LINKINFO,
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&linkinfo as *const libc::rtattr).cast::<u8>(),
            std::mem::size_of::<libc::rtattr>(),
        )
    };
    buff.extend_from_slice(bytes);

    // IFLA_INFO_KIND = "veth"
    append_attr(
        &mut buff,
        libc::IFLA_INFO_KIND,
        b"veth\0",
    );

    // IFLA_INFO_DATA
    let info_data_start = buff.len();

    let info_data = libc::rtattr {
        rta_len: 0,
        rta_type: libc::IFLA_INFO_DATA,
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&info_data as *const libc::rtattr).cast::<u8>(),
            std::mem::size_of::<libc::rtattr>(),
        )
    };
    buff.extend_from_slice(bytes);

    // VETH_INFO_PEER
    let peer_start = buff.len();

    const VETH_INFO_PEER: u16 = 1;

    let peer_attr = libc::rtattr {
        rta_len: 0,
        rta_type: VETH_INFO_PEER,
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&peer_attr as *const libc::rtattr).cast::<u8>(),
            std::mem::size_of::<libc::rtattr>(),
        )
    };
    buff.extend_from_slice(bytes);

    // Peer ifinfomsg
    let peer_info: libc::ifinfomsg = unsafe {
        std::mem::zeroed()
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&peer_info as *const libc::ifinfomsg).cast::<u8>(),
            std::mem::size_of::<libc::ifinfomsg>(),
        )
    };
    buff.extend_from_slice(bytes);

    // Peer name
    append_attr(
        &mut buff,
        libc::IFLA_IFNAME,
        b"veth-cont\0",
    );

    // 回填 nested attribute lengths
    let peer_len = (buff.len() - peer_start) as u16;
    buff[peer_start..peer_start + 2]
        .copy_from_slice(&peer_len.to_ne_bytes());

    let info_data_len = (buff.len() - info_data_start) as u16;
    buff[info_data_start..info_data_start + 2]
        .copy_from_slice(&info_data_len.to_ne_bytes());

    let linkinfo_len = (buff.len() - linkinfo_start) as u16;
    buff[linkinfo_start..linkinfo_start + 2]
        .copy_from_slice(&linkinfo_len.to_ne_bytes());

    // 回填 Netlink Message Length
    header.nlmsg_len = buff.len() as u32;
    buff[0..4].copy_from_slice(&header.nlmsg_len.to_ne_bytes());

    assert_eq!(buff.len(), 104);

    send_netlink_request(&buff)
}

fn setup_loopback() -> std::io::Result<()> {
    let sock_fd =  socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
    let mut ifr: libc::ifreq = unsafe {
        std::mem::zeroed()
    };

    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    
    let ret = unsafe {
        libc::ioctl(
            sock_fd.as_raw_fd(),
            libc::SIOCGIFFLAGS,
            &mut ifr,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let flags = unsafe {
        ifr.ifr_ifru.ifru_flags
    };

    println!("lo flags: {:#x}", flags);

    let new_flags = flags | libc::IFF_UP as libc::c_short;

    println!("lo new flags: {:#x}", new_flags);

    ifr.ifr_ifru.ifru_flags = new_flags;

    let ret = unsafe {
        libc::ioctl(
            sock_fd.as_raw_fd(),
            libc::SIOCSIFFLAGS,
            &mut ifr,
        )
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn add_ipv4_address(
    ifname: &str,
    ip: Ipv4Addr,
    prefix_len: u8,
) -> std::io::Result<()> {
    if prefix_len > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid IPv4 prefix length",
        ));
    }

    // 1. Interface name -> ifindex
    let name = CString::new(ifname)
        .map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid interface name",
        ))?;

    let ifindex = unsafe {
        libc::if_nametoindex(name.as_ptr())
    };

    if ifindex == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buff = Vec::<u8>::new();

    // 2. Netlink Header
    let mut header = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWADDR,
        nlmsg_flags: (
            libc::NLM_F_REQUEST |
            libc::NLM_F_ACK |
            libc::NLM_F_CREATE |
            libc::NLM_F_EXCL
        ) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const libc::nlmsghdr).cast::<u8>(),
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    };
    buff.extend_from_slice(header_bytes);

    // 3. IPv4 Address Information
    let info = libc::ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix_len,
        ifa_flags: 0,
        ifa_scope: libc::RT_SCOPE_UNIVERSE,
        ifa_index: ifindex,
    };

    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            (&info as *const libc::ifaddrmsg).cast::<u8>(),
            std::mem::size_of::<libc::ifaddrmsg>(),
        )
    };
    buff.extend_from_slice(info_bytes);

    // 4. IFA_LOCAL = IPv4 Address
    append_attr(
        &mut buff,
        libc::IFA_LOCAL,
        &ip.octets(),
    );

    // 5. Update nlmsg_len
    header.nlmsg_len = buff.len() as u32;

    buff[0..4].copy_from_slice(
        &header.nlmsg_len.to_ne_bytes()
    );

    println!(
        "Adding {}/{} to {} (ifindex {})",
        ip, prefix_len, ifname, ifindex
    );

    // 6. Send to Kernel and check ACK
    send_netlink_request(&buff)
}

fn set_interface_up(ifname: &str) -> std::io::Result<()> {
    // 1. 取得目前 NetNS 中的 Interface Index
    let name = CString::new(ifname)
        .map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid interface name",
        ))?;

    let ifindex = unsafe {
        libc::if_nametoindex(name.as_ptr())
    };

    if ifindex == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. 建立 Netlink Header
    let mut header = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: (
            libc::NLM_F_REQUEST | libc::NLM_F_ACK
        ) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buff = Vec::<u8>::new();

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const libc::nlmsghdr).cast::<u8>(),
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    };

    buff.extend_from_slice(header_bytes);

    // 3. 建立 ifinfomsg
    let mut info: libc::ifinfomsg = unsafe {
        std::mem::zeroed()
    };

    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex as i32;

    // 核心：將介面設為 UP
    info.ifi_flags = libc::IFF_UP as u32;
    info.ifi_change = libc::IFF_UP as u32;

    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            (&info as *const libc::ifinfomsg).cast::<u8>(),
            std::mem::size_of::<libc::ifinfomsg>(),
        )
    };

    buff.extend_from_slice(info_bytes);

    // 4. 更新 Message Length
    header.nlmsg_len = buff.len() as u32;

    buff[0..4].copy_from_slice(
        &header.nlmsg_len.to_ne_bytes()
    );

    println!(
        "Setting {} (ifindex {}) UP",
        ifname, ifindex
    );

    // 5. 送給 Kernel 並檢查 ACK
    send_netlink_request(&buff)
}

fn add_default_route(
    ifname: &str,
    gateway: Ipv4Addr,
) -> std::io::Result<()> {
    let name = CString::new(ifname)
        .map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid interface name",
        ))?;

    let ifindex = unsafe {
        libc::if_nametoindex(name.as_ptr())
    };

    if ifindex == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let header = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWROUTE,
        nlmsg_flags: (
            libc::NLM_F_REQUEST
            | libc::NLM_F_ACK
            | libc::NLM_F_CREATE
            | libc::NLM_F_EXCL
        ) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buff = Vec::<u8>::new();

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const libc::nlmsghdr).cast::<u8>(),
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    };

    buff.extend_from_slice(header_bytes);

    // Routing message
    let route = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: libc::RT_TABLE_MAIN,
        rtm_protocol: libc::RTPROT_STATIC,
        rtm_scope: libc::RT_SCOPE_UNIVERSE,
        rtm_type: libc::RTN_UNICAST,
        rtm_flags: 0,
    };

    let route_bytes = unsafe {
        std::slice::from_raw_parts(
            (&route as *const RtMsg).cast::<u8>(),
            std::mem::size_of::<RtMsg>(),
        )
    };

    buff.extend_from_slice(route_bytes);

    // Next-hop Gateway
    append_attr(
        &mut buff,
        libc::RTA_GATEWAY,
        &gateway.octets(),
    );

    // Output Interface
    append_attr(
        &mut buff,
        libc::RTA_OIF,
        &ifindex.to_ne_bytes(),
    );

    let length = buff.len() as u32;
    buff[0..4].copy_from_slice(&length.to_ne_bytes());

    println!(
        "Adding default route via {} dev {}",
        gateway, ifname
    );

    send_netlink_request(&buff)
}

fn setup_child(config: &RunConfig) -> Result<ExitCode, std::io::Error> {

    let (ready_read, ready_write): (OwnedFd, OwnedFd) = pipe()?;

    let (done_read, done_write): (OwnedFd, OwnedFd) = pipe()?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            setup_veth_pair();
            drop(ready_write);
            drop(done_read);

            let mut buf = [0u8; 1];
            let n = read(&ready_read, &mut buf)?;

            if n != 1 || buf[0] != b'R' {
                return Err(std::io::Error::other("Child did not send READY").into());
            }

            println!("Parent: Received READY");

            move_veth_to_netns("veth-cont", child.as_raw());

            add_ipv4_address(
                "veth-host",
                Ipv4Addr::new(10, 200, 1, 1),
                24,
            )?;
            set_interface_up("veth-host")?;

            println!("Parent: Network setup complete");

            write(&done_write, b"D")?;
            println!("Parent: Sent DONE");



            drop(ready_read);
            drop(done_write);

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
            drop(ready_read);
            drop(done_write);

            if let Err(_) = unshare(CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNET) {
                write(std::io::stdout(), "unshare error\n".as_bytes()).ok();
                unsafe { libc::_exit(1) };
            }

            let _ = setup_loopback();
            write(&ready_write, b"R")?;

            let mut buf = [0u8; 1];
            let n = read(&done_read, &mut buf)?;

            if n != 1 || buf[0] != b'D' {
                return Err(std::io::Error::other("Parent did not send DONE").into());
            } 

            // 確認收到 DONE 後
            add_ipv4_address(
                "veth-cont",
                Ipv4Addr::new(10, 200, 1, 2),
                24,
            )?;

            set_interface_up("veth-cont")?;

            // 3. 新增 Default Route
            add_default_route(
                "veth-cont",
                Ipv4Addr::new(10, 200, 1, 1),
            )?;

            println!("Child: Received DONE");
            println!("Child: Continue container startup");

            drop(ready_write);
            drop(done_read);

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
