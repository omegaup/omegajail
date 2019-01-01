#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <utility>

#include "args.h"
#include "logging.h"
#include "minijail/scoped_minijail.h"
#include "util.h"

namespace {

constexpr int kLoggingFd = 3;
constexpr int kMetaFd = 4;
constexpr int kSigsysTracerFd = 5;

const std::map<int, std::string> kSignalMap = {
#define ENTRY(x) \
  { x, #x }
    ENTRY(SIGHUP),  ENTRY(SIGINT),    ENTRY(SIGQUIT), ENTRY(SIGILL),
    ENTRY(SIGTRAP), ENTRY(SIGABRT),   ENTRY(SIGBUS),  ENTRY(SIGFPE),
    ENTRY(SIGKILL), ENTRY(SIGUSR1),   ENTRY(SIGSEGV), ENTRY(SIGUSR2),
    ENTRY(SIGPIPE), ENTRY(SIGALRM),   ENTRY(SIGTERM), ENTRY(SIGSTKFLT),
    ENTRY(SIGCHLD), ENTRY(SIGCONT),   ENTRY(SIGSTOP), ENTRY(SIGTSTP),
    ENTRY(SIGTTIN), ENTRY(SIGTTOU),   ENTRY(SIGURG),  ENTRY(SIGXCPU),
    ENTRY(SIGXFSZ), ENTRY(SIGVTALRM), ENTRY(SIGPROF), ENTRY(SIGWINCH),
    ENTRY(SIGIO),   ENTRY(SIGPWR),    ENTRY(SIGSYS)
#undef ENTRY
};

struct InitPayload {
  ScopedMinijail jail;
  SigsysDetector sigsys_detector = SigsysDetector::SIGSYS_TRACER;
  std::string comm;
  std::string cgroup_path;
  ssize_t memory_limit_in_bytes;
  struct timespec timeout;
};

// from minijail/util.h
extern "C" const char* lookup_syscall_name(int nr);

int CloseLoggingFd(void* payload) {
  if (close(kLoggingFd)) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to close the logging fd";
    }
    return -errno;
  }
  return 0;
}

bool MoveToWellKnownFd(struct minijail* j, ScopedFD fd, int well_known_fd) {
  if (fd.get() == well_known_fd) {
    // Leak the FD so the child process can access it.
    fd.release();
  } else {
    if (dup2(fd.get(), well_known_fd) == -1)
      return false;
  }
  int ret = minijail_preserve_fd(j, well_known_fd, well_known_fd);
  if (ret) {
    errno = -ret;
    return false;
  }

  return true;
}

int RemountRootReadOnly(void* payload) {
  if (mount(nullptr, "/", nullptr, MS_RDONLY | MS_REMOUNT | MS_BIND, nullptr)) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to remount root read-only";
    }
    return -errno;
  }
  return 0;
}

int Chdir(void* payload) {
  const char* dir =
      reinterpret_cast<const char*>(const_cast<const void*>(payload));
  if (chdir(dir)) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to chdir to " << dir;
    }
    return -errno;
  }
  return 0;
}

ScopedFD OpenFile(const std::string& path, bool writable) {
  ScopedFD fd(
      open(path.c_str(), O_NOFOLLOW | (writable ? O_WRONLY : O_RDONLY)));
  if (fd || errno != ENXIO)
    return fd;

  // If we got here, it's a muxed stdio socket.
  fd.reset(socket(AF_UNIX, SOCK_SEQPACKET, 0));
  if (!fd)
    return fd;

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (connect(fd.get(), reinterpret_cast<const struct sockaddr*>(&addr),
              sizeof(addr)) == -1) {
    return ScopedFD();
  }
  if (shutdown(fd.get(), writable ? SHUT_RD : SHUT_WR) == -1)
    return ScopedFD();
  return fd;
}

int OpenStdio(const std::string& path, int expected_fd, bool writable) {
  ScopedFD fd = OpenFile(path, writable);
  if (!fd) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to open " << path << " as fd " << expected_fd;
    }
    return -errno;
  }
  if (fd.get() == expected_fd) {
    fd.release();
    return 0;
  }
  if (dup2(fd.get(), expected_fd) == -1) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to dup2 " << path << " as fd " << expected_fd;
    }
    return -errno;
  }
  return 0;
}

int RedirectStdio(void* payload) {
  Args* args = reinterpret_cast<Args*>(payload);
  if (!args->stdin_redirect.empty()) {
    int ret = OpenStdio("/mnt/stdio/stdin", STDIN_FILENO, false);
    if (ret)
      return ret;
  }
  if (!args->stdout_redirect.empty()) {
    int ret = OpenStdio("/mnt/stdio/stdout", STDOUT_FILENO, true);
    if (ret)
      return ret;
  }
  if (!args->stderr_redirect.empty()) {
    int ret = OpenStdio("/mnt/stdio/stderr", STDERR_FILENO, true);
    if (ret)
      return ret;
  }
  // Now that the fds are opened in the correct namespace, unmount the parent
  // so that the original paths are not disclosed in /proc/self/mountinfo.
  if (umount2("/mnt/stdio", MNT_DETACH)) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to detach /mnt/stdio";
    }
    return -errno;
  }
  return 0;
}

void InstallStdioRedirectOrDie(struct minijail* j,
                               const std::string& src,
                               const std::string& dest,
                               bool writeable) {
  ScopedFD fd;
  if (writeable) {
    fd.reset(
        open(src.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC, 0644));
  } else {
    fd.reset(open(src.c_str(), O_RDONLY | O_NOFOLLOW));
  }
  if (!fd && errno != ENXIO)
    PLOG(FATAL) << "Failed to open " << src;
  if (minijail_mount(j, src.c_str(), dest.c_str(), "",
                     MS_BIND | (writeable ? 0 : MS_RDONLY))) {
    LOG(FATAL) << "Failed to bind-mount " << src;
  }
}

void TimespecAdd(struct timespec* dst, const struct timespec* src) {
  dst->tv_nsec += src->tv_nsec;
  if (dst->tv_nsec > 1000000000l) {
    dst->tv_nsec -= 1000000000l;
    dst->tv_sec++;
  }
  dst->tv_sec += src->tv_sec;
}

void TimespecSub(struct timespec* dst, const struct timespec* src) {
  dst->tv_nsec -= src->tv_nsec;
  if (dst->tv_nsec < 0) {
    dst->tv_nsec += 1000000000l;
    dst->tv_sec--;
  }
  dst->tv_sec -= src->tv_sec;
}

int TimespecCmp(struct timespec* dst, const struct timespec* src) {
  if (dst->tv_sec < src->tv_sec)
    return -1;
  if (dst->tv_sec > src->tv_sec)
    return 1;
  if (dst->tv_nsec < src->tv_nsec)
    return -1;
  if (dst->tv_nsec > src->tv_nsec)
    return 1;
  return 0;
}

int MetaInit(void* raw_payload) {
  InitPayload* payload = reinterpret_cast<InitPayload*>(raw_payload);

  std::unique_ptr<ScopedCgroup> memory_cgroup;
  if (payload->memory_limit_in_bytes >= 0) {
    memory_cgroup.reset(new ScopedCgroup("/sys/fs/cgroup/memory/omegajail"));
    if (!*memory_cgroup) {
      {
        ScopedErrnoPreserver preserve_errno;
        PLOG(ERROR) << "Failed to create an omegajail memory cgroup";
      }
      return -errno;
    }
    std::string memory_limit_path =
        StringPrintf("%s/memory.limit_in_bytes", memory_cgroup->path().c_str());
    WriteFile(memory_limit_path,
              StringPrintf("%zd", payload->memory_limit_in_bytes));
    if (chmod(memory_limit_path.c_str(), 0444)) {
      {
        ScopedErrnoPreserver preserve_errno;
        PLOG(ERROR) << "Failed to make the cgroup memory limit read-only";
      }
      return -errno;
    }
  }

  std::unique_ptr<ScopedCgroup> pid_cgroup;
  if (!payload->cgroup_path.empty()) {
    pid_cgroup.reset(new ScopedCgroup(payload->cgroup_path));
    if (!*pid_cgroup) {
      {
        ScopedErrnoPreserver preserve_errno;
        PLOG(ERROR) << "Failed to create an omegajail memory cgroup";
      }
      return -errno;
    }
  }

  sigset_t mask;
  sigset_t orig_mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
    {
      ScopedErrnoPreserver preserve_errno;
      PLOG(ERROR) << "Failed to block SIGCHLD";
    }
    return -errno;
  }

  struct timespec t0, t1, t, deadline, timeout;
  clock_gettime(CLOCK_REALTIME, &t0);

  deadline = t0;
  TimespecAdd(&deadline, &payload->timeout);

  int child_pid = fork();
  if (child_pid < 0) {
    _exit(child_pid);
  } else if (child_pid == 0) {
    if (!payload->comm.empty())
      prctl(PR_SET_NAME, payload->comm.c_str());
    for (auto* cgroup_ptr : {&memory_cgroup, &pid_cgroup}) {
      auto& cgroup = *cgroup_ptr;
      if (!cgroup)
        continue;
      std::string tasks_path = StringPrintf("%s/tasks", cgroup->path().c_str());
      WriteFile(tasks_path.c_str(), "2\n", true);
      cgroup->release();
      if (chmod(tasks_path.c_str(), 0444)) {
        {
          ScopedErrnoPreserver preserve_errno;
          PLOG(ERROR) << "Failed to make the cgroup task list read-only";
        }
        return -errno;
      }
    }
    if (sigprocmask(SIG_SETMASK, &orig_mask, nullptr) < 0) {
      {
        ScopedErrnoPreserver preserve_errno;
        PLOG(ERROR) << "Failed to restore signals";
      }
      return -errno;
    }
    if (payload->sigsys_detector == SigsysDetector::PTRACE) {
      if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        {
          ScopedErrnoPreserver preserve_errno;
          PLOG(ERROR) << "Failed to PTRACE_TRACEME";
        }
        return -errno;
      }
      if (raise(SIGSTOP) < 0) {
        {
          ScopedErrnoPreserver preserve_errno;
          PLOG(ERROR) << "Failed to raise(SIGSTOP)";
        }
        return -errno;
      }
    } else if (payload->sigsys_detector == SigsysDetector::SIGSYS_TRACER) {
      if (close(kSigsysTracerFd) < 0) {
        {
          ScopedErrnoPreserver preserve_errno;
          PLOG(ERROR) << "Failed to close the sigsys_tracer FD";
        }
        return -errno;
      }
    }
    if (close(kMetaFd) < 0) {
      {
        ScopedErrnoPreserver preserve_errno;
        PLOG(ERROR) << "Failed to close the meta FD";
      }
      return -errno;
    }
    return 0;
  }

  // From here on, returns mean nothing. We should try as hard as possible to
  // keep going.

  prctl(PR_SET_NAME, "minijail-init");

  // Jail this process, too.
  minijail_enter(payload->jail.get());

  pid_t pid;
  bool init_exited = false;
  int status, init_exitstatus = 0;
  int init_exitsyscall = -1;
  int init_exitsignal = -1;
  struct rusage usage = {}, init_usage = {};
  siginfo_t info;
  t = t0;
  bool attached = false;

  do {
    timeout = deadline;
    TimespecSub(&timeout, &t);
    if (HANDLE_EINTR(sigtimedwait(&mask, &info, &timeout)) == -1) {
      clock_gettime(CLOCK_REALTIME, &t);
      break;
    }

    while ((pid = wait3(&status, __WALL | WNOHANG, &usage)) > 0) {
      if (WIFSTOPPED(status)) {
        if (!attached) {
          if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
                     PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL) == -1) {
            PLOG(ERROR) << "Failed to PTRACE_SETOPTIONS";
          }
          attached = true;
        }
        int stop_signal = WSTOPSIG(status);
        switch (stop_signal) {
          case SIGSYS:
            // For the SIGSYS case we want to get the syscall that caused it.
            if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &info) == -1)
              PLOG(ERROR) << "Failed to PTRACE_GETSIGINFO";
            init_exitsyscall = info.si_syscall;
            kill(pid, SIGKILL);
            break;

          case SIGXCPU:
          case SIGXFSZ:
            // Signals that are delivered due to exceeding a resource limit will
            // terminate the process.
            init_exitsignal = stop_signal;
            kill(pid, SIGKILL);
            break;

          case SIGSTOP:
          case SIGTRAP:
            // If the signal is SIGSTOP (the one we sent before the process
            // started) or SIGTRAP (a signal injected by ptrace(2)), stop
            // delivery of the signal.
            if (ptrace(PTRACE_CONT, pid, nullptr, 0) == -1)
              PLOG(ERROR) << "Failed to continue process";
            break;

          default:
            // Any other signal will be delivered normally.
            if (ptrace(PTRACE_CONT, pid, nullptr, stop_signal) == -1)
              PLOG(ERROR) << "Failed to continue process";
        }
        continue;
      }

      if (pid == child_pid) {
        init_exitstatus = status;
        init_usage = usage;
        init_exited = true;
      }
    }
    clock_gettime(CLOCK_REALTIME, &t);
  } while (!init_exited && TimespecCmp(&t, &deadline) < 0);

  if (TimespecCmp(&t, &deadline) >= 0)
    init_exitsignal = SIGXCPU;

  kill(-1, SIGKILL);
  while ((pid = wait3(&status, 0, &usage)) > 0) {
    if (init_exited || pid != child_pid)
      continue;
    init_exitstatus = status;
    init_usage = usage;
    init_exited = true;
  }

  clock_gettime(CLOCK_REALTIME, &t1);
  TimespecSub(&t1, &t0);

  if (payload->sigsys_detector == SigsysDetector::SIGSYS_TRACER) {
    SigsysTracerClient sigsys_tracer{ScopedFD(kSigsysTracerFd)};
    sigsys_tracer.Read(&init_exitsyscall);
  }

  memory_cgroup.reset();
  pid_cgroup.reset();

  FILE* meta_file = fdopen(kMetaFd, "w");
  fprintf(meta_file, "time:%ld\ntime-sys:%ld\ntime-wall:%ld\nmem:%ld\n",
          1000000 * init_usage.ru_utime.tv_sec + init_usage.ru_utime.tv_usec,
          1000000 * init_usage.ru_stime.tv_sec + init_usage.ru_stime.tv_usec,
          (1000000000L * t1.tv_sec + t1.tv_nsec) / 1000L,
          init_usage.ru_maxrss * 1024);
  int ret = 0;

  if (init_exitsyscall != -1) {
    const char* syscall_name = lookup_syscall_name(init_exitsyscall);
    if (syscall_name)
      fprintf(meta_file, "signal:SIGSYS\nsyscall:%s\n", syscall_name);
    else
      fprintf(meta_file, "signal:SIGSYS\nsyscall:#%d\n", init_exitsyscall);
    ret = SIGSYS;
  } else if (WIFSIGNALED(init_exitstatus) || init_exitsignal != -1) {
    if (init_exitsignal == -1)
      init_exitsignal = WTERMSIG(init_exitstatus);
    const auto& signal_name = kSignalMap.find(init_exitsignal);
    if (signal_name == kSignalMap.end())
      fprintf(meta_file, "signal_number:%d\n", init_exitsignal);
    else
      fprintf(meta_file, "signal:%s\n", signal_name->second.c_str());
    ret = init_exitsignal;
  } else if (WIFEXITED(init_exitstatus)) {
    fprintf(meta_file, "status:%d\n", WEXITSTATUS(init_exitstatus));
    ret = WEXITSTATUS(init_exitstatus);
  }
  fclose(meta_file);

  _exit(ret);
}

}  // namespace

int main(int argc, char* argv[]) {
  // We would really like to avoid running as root. If invoked from sudo, the
  // target program will be run as the user invoking sudo.
  bool from_sudo = false;
  char* caller = getenv("SUDO_USER");
  uid_t uid;
  gid_t gid;
  if (caller == nullptr) {
    uid = getuid();
    gid = getgid();
  } else {
    from_sudo = true;
    struct passwd* passwd = getpwnam(caller);
    if (passwd == nullptr)
      LOG(FATAL) << "User " << caller << "not found.";
    uid = passwd->pw_uid;
    gid = passwd->pw_gid;
  }

  if (from_sudo) {
    // Temporarily drop privileges to redirect files.
    if (setegid(gid))
      PLOG(FATAL) << "setegid";
    if (seteuid(uid))
      PLOG(FATAL) << "seteuid";
  }

  // Set a minimalistic environment
  clearenv();
  setenv("HOME", "/home", 1);
  setenv("LANG", "en_US.UTF-8", 1);
  setenv("PATH", "/usr/bin", 1);
  setenv("DOTNET_CLI_TELEMETRY_OPTOUT", "1", 1);

  ScopedMinijail j(minijail_new());

  // Redirect all logging to stderr.
  if (dup2(STDERR_FILENO, kLoggingFd) == -1) {
    PLOG(ERROR) << "Failed to setup the logging fd";
    return 1;
  }
  logging::Init(kLoggingFd, ERROR);
  minijail_log_to_fd(kLoggingFd, LOG_WARNING);
  int ret = minijail_preserve_fd(j.get(), kLoggingFd, kLoggingFd);
  if (ret) {
    LOG(ERROR) << "Failed to set up stderr redirect: " << strerror(-ret);
    return 1;
  }

  if (from_sudo) {
    // Change credentials to the original user so this never runs as root.
    minijail_change_uid(j.get(), uid);
    minijail_change_gid(j.get(), gid);
  } else {
    // Enter a user namespace. The current user will be user 1000.
    minijail_namespace_user(j.get());
    minijail_namespace_user_disable_setgroups(j.get());
    constexpr uid_t kTargetUid = 1000;
    constexpr gid_t kTargetGid = 1000;
    minijail_change_uid(j.get(), kTargetUid);
    minijail_change_gid(j.get(), kTargetGid);
    minijail_uidmap(j.get(), StringPrintf("%d %d 1", kTargetUid, uid).c_str());
    minijail_gidmap(j.get(), StringPrintf("%d %d 1", kTargetGid, gid).c_str());
  }

  // Perform some basic setup to tighten security as much as possible by
  // default.
  minijail_close_open_fds(j.get());
  minijail_mount_tmp(j.get());
  minijail_namespace_cgroups(j.get());
  minijail_namespace_ipc(j.get());
  minijail_namespace_net(j.get());
  minijail_namespace_pids(j.get());
  minijail_namespace_uts(j.get());
  minijail_namespace_set_hostname(j.get(), "omegajail");
  minijail_namespace_vfs(j.get());
  minijail_no_new_privs(j.get());
  minijail_set_ambient_caps(j.get());
  minijail_use_caps(j.get(), 0);
  minijail_reset_signal_mask(j.get());
  minijail_run_as_init(j.get());
  minijail_rlimit(j.get(), RLIMIT_STACK, RLIM_INFINITY, RLIM_INFINITY);
  if (minijail_mount(j.get(), "proc", "/proc", "proc",
                     MS_RDONLY | MS_NOEXEC | MS_NODEV | MS_NOSUID)) {
    LOG(ERROR) << "Failed to mount /proc";
    return 1;
  }
  if (minijail_mount_with_data(j.get(), "none", "/mnt/stdio", "tmpfs",
                               MS_NOEXEC | MS_NODEV | MS_NOSUID,
                               "size=4096,mode=555")) {
    LOG(ERROR) << "Failed to mount /mnt/stdio";
    return 1;
  }
  if (minijail_add_hook(j.get(), RemountRootReadOnly, nullptr,
                        MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS)) {
    PLOG(ERROR) << "Failed to add a hook to remount / read-only";
    return 1;
  }

  Args args;
  if (!args.Parse(argc, argv, j.get()))
    return 1;

  if (!args.chdir.empty()) {
    minijail_add_hook(j.get(), Chdir, const_cast<char*>(args.chdir.c_str()),
                      MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
  }
  if (!args.stdin_redirect.empty()) {
    InstallStdioRedirectOrDie(j.get(), args.stdin_redirect, "/mnt/stdio/stdin",
                              false);
  }
  if (!args.stdout_redirect.empty()) {
    InstallStdioRedirectOrDie(j.get(), args.stdout_redirect,
                              "/mnt/stdio/stdout", true);
  }
  if (!args.stderr_redirect.empty()) {
    InstallStdioRedirectOrDie(j.get(), args.stderr_redirect,
                              "/mnt/stdio/stderr", true);
  }
  if (args.memory_limit_in_bytes >= 0 &&
      minijail_mount(j.get(), "/sys/fs/cgroup/memory/omegajail",
                     "/sys/fs/cgroup/memory/omegajail", "", MS_BIND)) {
    LOG(ERROR) << "Failed to mount /sys/fs/cgroup/memory";
    return 1;
  }

  std::string cgroup_path;
  if (!args.script_basename.empty()) {
    cgroup_path = StringPrintf("/sys/fs/cgroup/pids/omegajail/%s",
                               args.script_basename.c_str());
    if (access(cgroup_path.c_str(), W_OK) != 0) {
      cgroup_path.clear();
    } else if (minijail_mount(j.get(), "/sys/fs/cgroup/pids/omegajail",
                              "/sys/fs/cgroup/pids/omegajail", "", MS_BIND)) {
      LOG(ERROR) << "Failed to mount /sys/fs/cgroup/pids";
      return 1;
    }
  }

  InitPayload payload;
  payload.memory_limit_in_bytes = args.memory_limit_in_bytes;
  payload.comm = args.comm;
  payload.cgroup_path = cgroup_path;
  payload.sigsys_detector = args.sigsys_detector;
  payload.timeout.tv_sec = args.wall_time_limit_msec / 1000;
  payload.timeout.tv_nsec = (args.wall_time_limit_msec % 1000) * 1000000ul;

  if (!args.meta.empty()) {
    ScopedFD meta_fd(open(args.meta.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (!meta_fd) {
      PLOG(ERROR) << "Failed to open meta file " << args.meta;
      return 1;
    }
    if (!MoveToWellKnownFd(j.get(), std::move(meta_fd), kMetaFd)) {
      PLOG(ERROR) << "Failed to dup meta fd";
      return 1;
    }

    SigsysTracerClient sigsys_tracer;
    if (args.sigsys_detector == SigsysDetector::SIGSYS_TRACER) {
      if (sigsys_tracer.Initialize()) {
        if (!MoveToWellKnownFd(j.get(), sigsys_tracer.TakeFD(),
                               kSigsysTracerFd)) {
          PLOG(ERROR) << "Failed to dup meta fd";
          return 1;
        }
      } else {
        // Fallback to using ptrace.
        payload.sigsys_detector = SigsysDetector::PTRACE;
      }
    }

    // Setup init's jail
    payload.jail.reset(minijail_new());
    if (from_sudo) {
      minijail_change_uid(payload.jail.get(), uid);
      minijail_change_gid(payload.jail.get(), gid);
    }
    minijail_no_new_privs(payload.jail.get());
    minijail_set_ambient_caps(payload.jail.get());
    minijail_use_caps(payload.jail.get(),
                      (payload.sigsys_detector == SigsysDetector::PTRACE)
                          ? (1 << CAP_SYS_PTRACE)
                          : 0);

    // Run MetaInit() as the container's init.
    ret = minijail_add_hook(j.get(), MetaInit, &payload,
                            MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
    if (ret) {
      LOG(ERROR) << "Failed to add hook: " << strerror(-ret);
      return 1;
    }
    minijail_run_as_init(j.get());
  }

  // This must be the last pre-drop caps hook to be run.
  if (!args.stdin_redirect.empty() || !args.stdout_redirect.empty() ||
      !args.stderr_redirect.empty()) {
    minijail_add_hook(j.get(), RedirectStdio, &args,
                      MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
  }

  // This must be added last to ensure that no other hooks are added
  // afterwards.
  minijail_add_hook(j.get(), CloseLoggingFd, nullptr,
                    MINIJAIL_HOOK_EVENT_PRE_EXECVE);

  if (from_sudo) {
    // Become root again to set the jail up.
    if (seteuid(0))
      PLOG(FATAL) << "seteuid";
    if (setegid(0))
      PLOG(FATAL) << "setegid";
  }

  ret = minijail_run_no_preload(
      j.get(), args.program.c_str(),
      const_cast<char* const*>(args.program_args.get()));
  if (ret < 0) {
    LOG(ERROR) << "Failed to run minijail: " << strerror(-ret);
    return 1;
  }

  return minijail_wait(j.get());
}
