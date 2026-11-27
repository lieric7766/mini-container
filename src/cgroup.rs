use std::fs::write;
use std::fs::{create_dir, remove_dir};
use std::path::{Path, PathBuf};

pub struct CgroupManager {
    container_path: PathBuf,
}

impl CgroupManager {
    pub fn new(parent: &Path, container_name: &str) -> Self {
        Self {
            container_path: parent.join(container_name),
        }
    }

    pub fn create(&self) -> std::io::Result<()> {
        create_dir(&self.container_path)?;
        Ok(())
    }

    pub fn set_memory_limit(&self, bytes: u64) -> std::io::Result<()> {
        let mem_file = self.container_path.join("memory.max");
        write(mem_file, bytes.to_string())?;
        Ok(())
    }

    pub fn set_cpu_limit(&self, quota: u64, period: u64) -> std::io::Result<()> {
        let cpu_file = self.container_path.join("cpu.max");
        let quota_to_period = format!("{} {}", quota, period);
        write(cpu_file, quota_to_period)?;
        Ok(())
    }

    pub fn set_pid_limit(&self, pid_num: u64) -> std::io::Result<()> {
        let pid_file = self.container_path.join("pids.max");
        write(pid_file, pid_num.to_string())?;
        Ok(())
    }

    pub fn add_process(&self, pid: u32) -> std::io::Result<()> {
        let procs_file = self.container_path.join("cgroup.procs");
        write(procs_file, pid.to_string())?;
        Ok(())
    }

    pub fn cleanup(&self) -> std::io::Result<()> {
        remove_dir(&self.container_path)?;
        Ok(())
    }
}
