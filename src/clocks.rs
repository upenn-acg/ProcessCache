use std::collections::HashMap;
use nix::unistd::Pid;

#[derive(Debug, PartialOrd, PartialEq, Clone, Copy)]
pub struct LogicalTime(u64);

impl LogicalTime {
    fn new() -> LogicalTime {
        LogicalTime(0)
    }

    fn increment(&mut self) {
        self.0 = self.0 + 1;
    }
}

#[derive(Clone)]
pub struct ProcessClock {
    clock: HashMap<Pid, LogicalTime>,
    our_pid: Pid,
}

impl ProcessClock {
    pub fn get_current_time(&self, pid: &Pid) -> Option<LogicalTime> {
        self.clock.get(pid).cloned()
    }

    pub fn add_new_process(&mut self, pid: &Pid) {
        self.clock.insert(*pid, LogicalTime::new());
    }

    pub fn new(pid: Pid) -> ProcessClock {
        ProcessClock { clock: HashMap::new(), our_pid: pid }
    }

    pub fn update_entry(&mut self, pid: &Pid, new_time: LogicalTime) {
        self.clock.insert(*pid, new_time);
    }

    pub fn increment_time(&mut self, pid: &Pid) {
        let time = self.clock.get_mut(pid).
            expect("increment_time: Requested time not found.");
        time.increment();
    }

    pub fn increment_own_time(&mut self) {
        let pid = self.our_pid;
        self.increment_time(&pid);
    }

    pub fn iter(self) -> std::collections::hash_map::IntoIter<Pid, LogicalTime> {
        self.clock.into_iter()
    }
}

pub struct ResourceClock {
    read_clock: HashMap<Pid, LogicalTime>,
    write_clock: (Pid, LogicalTime),
}
