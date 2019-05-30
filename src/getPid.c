#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/**
 * Get the .si_pid from a rust siginfo struct, as Rust does not have this
 * field for it's siginfo type. Needed for waitid().
 */
pid_t getPid(siginfo_t* infop) {
  return infop->si_pid;
}
