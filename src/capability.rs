use std::io;

#[cfg(target_os = "linux")]
pub fn drop_sys_admin_effective() -> io::Result<()> {
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    const CAP_SYS_ADMIN: u32 = 21;

    let mut hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 代表目前執行緒
    };

    let mut data = [CapUserData::default(); 2];
    let res = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let res = unsafe {
        libc::prctl(
            libc::PR_CAPBSET_DROP,
            CAP_SYS_ADMIN as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };

    if res == -1 {
        return Err(io::Error::last_os_error());
    }

    // 2. 清除 effective 中的 CAP_SYS_ADMIN (bit 21)
    data[0].effective &= !(1 << CAP_SYS_ADMIN);
    data[0].permitted &= !(1 << CAP_SYS_ADMIN);
    data[0].inheritable &= !(1 << CAP_SYS_ADMIN);

    // 3. 寫回修改後的 capabilities
    let res = unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())

}
