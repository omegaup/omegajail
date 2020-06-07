#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <map>
#include <memory>

#include "logging.h"
#include "macros.h"
#include "util.h"

namespace {

constexpr char kEventIdPath[] =
    "/sys/kernel/debug/tracing/events/kprobes/sigsys_tracer/id";
constexpr char kReleaseAgentPath[] = "/usr/sbin/perf_event_release_agent.sh";
constexpr char kCgroupPath[] = "/sys/fs/cgroup/perf_event/omegajail";
constexpr char kSocketPath[] = "/run/sigsys_tracer.socket";

extern "C" struct __attribute__((__packed__)) sigsys_tracer_sample {
  struct perf_event_header header;
  uint32_t size;

  unsigned short common_type;
  unsigned short common_flags;
  int common_pid;

  uintptr_t __probe_ip;
  int64_t syscall;
};

static_assert(offsetof(sigsys_tracer_sample, __probe_ip) == 20,
              "Misaligned __probe_ip offset");
static_assert(offsetof(sigsys_tracer_sample, syscall) == 28,
              "Misaligned syscall offset");

extern "C" int perf_event_open(struct perf_event_attr* attr,
                               pid_t pid,
                               int cpu,
                               int group_fd,
                               unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

class AsyncHelper {
 public:
  AsyncHelper(ScopedFD fd) : fd_(std::move(fd)) {}
  virtual ~AsyncHelper() = default;

  virtual bool Initialize() { return true; }

  // Ready returns false if it should be removed from the list of helpers to
  // poll for updates.
  virtual bool Ready() = 0;

  int fd() const { return fd_.get(); }

 protected:
  ScopedFD fd_;
};

class EpollRunLoop {
 public:
  EpollRunLoop(ScopedFD epoll_fd) : epoll_fd_(std::move(epoll_fd)) {}

  bool Add(std::unique_ptr<AsyncHelper> helper) {
    if (!helper)
      return false;
    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = helper->fd();
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, helper->fd(), &ev)) {
      PLOG(ERROR) << "Failed to add client into epoll";
      return false;
    }
    int helper_fd = helper->fd();
    async_helpers_.emplace(std::make_pair(helper_fd, std::move(helper)));

    return true;
  }

  bool Remove(int fd) {
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, fd, nullptr)) {
      PLOG(ERROR) << "Failed to remove client from epoll";
      return false;
    }
    async_helpers_.erase(fd);
    return true;
  }

  bool* running() { return &running_; }

  void RunLoop() {
    struct epoll_event events[128];
    while (running_) {
      int nfds = HANDLE_EINTR(
          epoll_wait(epoll_fd_.get(), events, array_length(events), -1));

      if (nfds == -1) {
        PLOG(ERROR) << "epoll_wait";
        return;
      }

      for (int i = 0; i < nfds; i++) {
        const auto it = async_helpers_.find(events[i].data.fd);
        if (it == async_helpers_.end()) {
          LOG(ERROR) << "Received epoll_wait() notification from unknown fd "
                     << events[i].data.fd;
          Remove(events[i].data.fd);
          continue;
        }

        if (!it->second->Ready()) {
          Remove(events[i].data.fd);
        }
      }
    }
  }

 private:
  ScopedFD epoll_fd_;
  bool running_ = true;
  std::map<int, std::unique_ptr<AsyncHelper>> async_helpers_;

  DISALLOW_COPY_AND_ASSIGN(EpollRunLoop);
};

class SignalFdAsyncHelper : public AsyncHelper {
 public:
  SignalFdAsyncHelper(ScopedFD fd, bool* running)
      : AsyncHelper(std::move(fd)), running_(running) {}
  ~SignalFdAsyncHelper() override = default;

  bool Ready() override {
    struct signalfd_siginfo siginfo;
    HANDLE_EINTR(read(fd_.get(), &siginfo, sizeof(siginfo)));
    switch (siginfo.ssi_signo) {
      case SIGINT:
      case SIGTERM: {
        *running_ = false;
        break;
      }
    }

    // Keep polling.
    return true;
  }

 private:
  bool* const running_;

  DISALLOW_COPY_AND_ASSIGN(SignalFdAsyncHelper);
};

class ClientAsyncHelper : public AsyncHelper {
 public:
  ClientAsyncHelper(ScopedFD fd, uint64_t event_id, unsigned long page_size)
      : AsyncHelper(std::move(fd)),
        event_id_(event_id),
        page_size_(page_size) {}
  ~ClientAsyncHelper() override = default;

  bool Initialize() override {
    struct ucred ucred;
    socklen_t len = sizeof(ucred);
    if (getsockopt(fd_.get(), SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
      PLOG(ERROR) << "Failed to get SO_PEERCRED";
      return false;
    }
    pid_ = ucred.pid;

    cgroup_.reset(kCgroupPath);
    if (!cgroup_) {
      LOG(ERROR) << "Failed to create cgroup";
      ignore_result(write(fd_.get(), "NO\n", 3));
      return false;
    }

    if (!WriteFile(StringPrintf("%s/tasks", cgroup_.path().data()),
                   StringPrintf("%d", pid_))) {
      PLOG(ERROR) << "Failed to register task in cgroup";
      ignore_result(write(fd_.get(), "NO\n", 3));
      return false;
    }
    if (!WriteFile(StringPrintf("%s/notify_on_release", cgroup_.path().data()),
                   "1")) {
      PLOG(ERROR) << "Failed to set notify_on_release";
      ignore_result(write(fd_.get(), "NO\n", 3));
      return false;
    }

    {
      ScopedFD cgroup_fd(
          open(cgroup_.path().data(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
      if (!cgroup_fd) {
        PLOG(ERROR) << "Failed to get cgroup fd";
        ignore_result(write(fd_.get(), "NO\n", 3));
        return false;
      }

      struct perf_event_attr attr = {};
      attr.type = PERF_TYPE_TRACEPOINT;
      attr.size = sizeof(attr);
      attr.config = event_id_;
      attr.sample_type = PERF_SAMPLE_RAW;
      attr.sample_period = 1;
      perf_fd_.reset(
          perf_event_open(&attr, cgroup_fd.get(), 0, -1,
                          PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_CLOEXEC));
      if (!perf_fd_) {
        PLOG(ERROR) << "Failed to open perf_event";
        ignore_result(write(fd_.get(), "NO\n", 3));
        return false;
      }
    }

    event_mmap_.reset(
        mmap(nullptr, 2 * page_size_, PROT_READ, MAP_SHARED, perf_fd_.get(), 0),
        2 * page_size_);
    if (!event_mmap_) {
      PLOG(ERROR) << "Failed to mmap event data";
      ignore_result(write(fd_.get(), "NO\n", 3));
      return false;
    }
    ioctl(perf_fd_.get(), PERF_EVENT_IOC_ENABLE, 0);
    ignore_result(write(fd_.get(), "OK\n", 3));

    return true;
  }

  bool Ready() override {
    char byte;
    HANDLE_EINTR(read(fd_.get(), &byte, sizeof(byte)));
    ioctl(perf_fd_.get(), PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page* header =
        reinterpret_cast<struct perf_event_mmap_page*>(event_mmap_.get());

    uintptr_t offset = 0;
    uintptr_t base =
        reinterpret_cast<uintptr_t>(event_mmap_.get()) + header->data_offset;
    do {
      struct perf_event_header* header =
          reinterpret_cast<struct perf_event_header*>(base + offset);
      if (header->size == 0)
        break;
      switch (header->type) {
        case PERF_RECORD_SAMPLE:
          struct sigsys_tracer_sample* sample =
              reinterpret_cast<struct sigsys_tracer_sample*>(header);
          std::string syscall_str = StringPrintf("%d\n", sample->syscall);
          LOG(WARN) << "SIGSYS{pid=" << sample->common_pid
                    << ",syscall=" << sample->syscall << "}";
          ignore_result(
              write(fd_.get(), syscall_str.c_str(), syscall_str.size()));

          // We have been signaled once and we have finished our job.
          return false;
      }
      offset += header->size;
    } while (offset < header->data_size);

    // We have been signaled once and we have finished our job.
    ignore_result(write(fd_.get(), "-1", 2));
    return false;
  }

 private:
  const uint64_t event_id_;
  unsigned long page_size_;
  pid_t pid_;

  ScopedCgroup cgroup_;
  ScopedFD perf_fd_;
  ScopedMmap event_mmap_;

  DISALLOW_COPY_AND_ASSIGN(ClientAsyncHelper);
};

class ServerSocketAsyncHelper : public AsyncHelper {
 public:
  ServerSocketAsyncHelper(ScopedFD fd,
                          uint64_t event_id,
                          unsigned long page_size,
                          EpollRunLoop* run_loop)
      : AsyncHelper(std::move(fd)),
        event_id_(event_id),
        page_size_(page_size),
        run_loop_(run_loop) {}
  ~ServerSocketAsyncHelper() override = default;

  bool Ready() override {
    ScopedFD client_fd(HANDLE_EINTR(accept(fd_.get(), nullptr, nullptr)));
    if (!client_fd) {
      PLOG(ERROR) << "Failed to accept socket";
      // Even if there is an error, keep accepting new sockets.
      return true;
    }

    std::unique_ptr<AsyncHelper> client = std::make_unique<ClientAsyncHelper>(
        std::move(client_fd), event_id_, page_size_);

    if (!client->Initialize() || !run_loop_->Add(std::move(client))) {
      LOG(ERROR) << "Failed to initialize client";
    }

    return true;
  }

 private:
  const uint64_t event_id_;
  const unsigned long page_size_;
  EpollRunLoop* const run_loop_;

  DISALLOW_COPY_AND_ASSIGN(ServerSocketAsyncHelper);
};

bool EnsureReleaseAgentInstalled() {
  if (access(kReleaseAgentPath, X_OK | R_OK) != 0 &&
      !WriteFile(kReleaseAgentPath,
                 "#!/bin/sh\nrmdir /sys/fs/cgroup/perf_event/$1\n", false,
                 0775)) {
    LOG(ERROR) << "Could not create release agent";
    return false;
  }
  if (!WriteFile("/sys/fs/cgroup/perf_event/release_agent",
                 kReleaseAgentPath)) {
    LOG(ERROR) << "Failed to register the release agent";
    return false;
  }
  return true;
}

uint64_t GetEventId() {
  uint64_t event_id = 0;
  if (ReadUint64(kEventIdPath, &event_id)) {
    return event_id;
  }
  if (!WriteFile("/sys/kernel/debug/tracing/kprobe_events",
                 "p:sigsys_tracer audit_seccomp syscall=%di:u64", true)) {
    PLOG(ERROR) << "Error registering syscall_catcher kprobe";
    return event_id;
  }
  if (!ReadUint64(kEventIdPath, &event_id)) {
    PLOG(ERROR) << "Failed to read event id";
  }

  return event_id;
}

}  // namespace

int main() {
  if (!EnsureReleaseAgentInstalled()) {
    return 1;
  }

  // Ignore the SIGPIPE signal. This can happen if for some reason the client
  // processes die in the middle of the setup process.
  signal(SIGPIPE, SIG_IGN);

  uint64_t event_id = GetEventId();
  if (!event_id) {
    return 1;
  }

  if (mkdir(kCgroupPath, 0755) && errno != EEXIST) {
    PLOG(ERROR) << "Failed to create the omegajail perf_event cgroup";
    return 1;
  }

  ScopedFD epoll_fd(epoll_create1(EPOLL_CLOEXEC));
  if (!epoll_fd) {
    PLOG(ERROR) << "Failed to create epoll fd";
    return 1;
  }

  EpollRunLoop run_loop(std::move(epoll_fd));

  {
    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, &old_mask)) {
      PLOG(ERROR) << "Failed to block SIGINT";
      return 1;
    }

    ScopedFD signal_fd(signalfd(-1, &mask, SFD_CLOEXEC));
    if (!signal_fd) {
      PLOG(ERROR) << "Failed to create a signalfd";
      return 1;
    }

    if (!run_loop.Add(std::make_unique<SignalFdAsyncHelper>(
            std::move(signal_fd), run_loop.running()))) {
      return 1;
    }
  }

  ScopedUnlink socket_unlink(kSocketPath);
  {
    if (unlink(kSocketPath) && errno != ENOENT) {
      PLOG(ERROR) << "Failed to clean up stale socket";
      return 1;
    }

    ScopedFD server_socket_fd(socket(AF_UNIX, SOCK_STREAM, 0));
    if (!server_socket_fd) {
      PLOG(ERROR) << "Failed to create connection socket";
      return 1;
    }

    struct sockaddr_un name = {};
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, kSocketPath, sizeof(name.sun_path) - 1);
    if (bind(server_socket_fd.get(),
             reinterpret_cast<const struct sockaddr*>(&name), sizeof(name))) {
      PLOG(ERROR) << "Failed to bind to socket";
      return 1;
    }

    if (listen(server_socket_fd.get(), 20)) {
      PLOG(ERROR) << "Failed to listen to socket";
      return 1;
    }

    if (chmod(kSocketPath, 0666)) {
      PLOG(ERROR) << "Failed to set permissions on the socket";
      return 1;
    }

    long page_size = sysconf(_SC_PAGESIZE);

    if (!run_loop.Add(std::make_unique<ServerSocketAsyncHelper>(
            std::move(server_socket_fd), event_id, page_size, &run_loop))) {
      return 1;
    }
  }

  LOG(INFO) << "Listening for connections... kprobe event id: " << event_id;

  run_loop.RunLoop();

  LOG(INFO) << "Shutting down...";

  return 0;
}
