use nix::unistd::Pid;
use std::collections::HashMap;

#[derive(Debug, PartialOrd, PartialEq, Clone, Copy)]
pub struct LogicalTime(u64);

impl LogicalTime {
    fn new() -> LogicalTime {
        LogicalTime(0)
    }

    fn increment(&mut self) {
        self.0 += self.0;
    }
}

#[derive(Clone)]
pub struct ProcessClock {
    clock: HashMap<Pid, LogicalTime>,
    our_pid: Pid,
}

impl ProcessClock {
    // pub fn get_current_time(&self, pid: Pid) -> Option<LogicalTime> {
    //     self.clock.get(&pid).cloned()
    // }

    pub fn add_new_process(&mut self, pid: Pid) {
        self.clock.insert(pid, LogicalTime::new());
    }

    pub fn new(pid: Pid) -> ProcessClock {
        ProcessClock {
            clock: HashMap::new(),
            our_pid: pid,
        }
    }

    // pub fn update_entry(&mut self, pid: Pid, new_time: LogicalTime) {
    //     self.clock.insert(pid, new_time);
    // }

    pub fn increment_time(&mut self, pid: Pid) {
        let time = self
            .clock
            .get_mut(&pid)
            .expect("increment_time: Requested time not found.");
        time.increment();
    }

    pub fn increment_own_time(&mut self) {
        let pid = self.our_pid;
        self.increment_time(pid);
    }
}

impl IntoIterator for ProcessClock {
    type Item = (Pid, LogicalTime);
    type IntoIter = std::collections::hash_map::IntoIter<Pid, LogicalTime>;

    fn into_iter(self) -> Self::IntoIter {
        self.clock.into_iter()
    }
}

struct _ResourceClock {
    read_clock: HashMap<Pid, LogicalTime>,
    write_clock: (Pid, LogicalTime),
}
