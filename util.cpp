#include "util.h"

#include <signal.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <utility>

#include "logging.h"

namespace {

extern "C" {

int seccomp(unsigned int operation, unsigned int flags, void* args) {
  return syscall(__NR_seccomp, operation, flags, args);
}

int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags) {
#if !defined(__NR_pidfd_send_signal)
  constexpr const int __NR_pidfd_send_signal = 424;
#endif
  return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

}  // extern "C"

// Valid operations for seccomp syscall.
#define SECCOMP_GET_NOTIF_SIZES    3

struct seccomp_data {
  int nr;
  __u32 arch;
  __u64 instruction_pointer;
  __u64 args[6];
};

struct seccomp_notif_sizes {
  __u16 seccomp_notif;
  __u16 seccomp_notif_resp;
  __u16 seccomp_data;
};

struct seccomp_notif {
  __u64 id;
  __u32 pid;
  __u32 flags;
  struct seccomp_data data;
};

#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IO(nr) _IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type) _IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type) _IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type) _IOWR(SECCOMP_IOC_MAGIC, nr, type)

// Flags for seccomp notification fd ioctl.
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOR(2, __u64)

}  // namespace

ScopedFD::ScopedFD(int fd) : fd_(fd) {}

ScopedFD::~ScopedFD() {
  reset();
}

ScopedFD::ScopedFD(ScopedFD&& fd) : fd_(kInvalidFd) {
  std::swap(fd_, fd.fd_);
}

ScopedFD& ScopedFD::operator=(ScopedFD&& fd) {
  reset();
  std::swap(fd_, fd.fd_);
  return *this;
}

int ScopedFD::get() const {
  return fd_;
}

int ScopedFD::release() {
  int ret = kInvalidFd;
  std::swap(ret, fd_);
  return ret;
}

void ScopedFD::reset(int fd) {
  std::swap(fd, fd_);
  if (fd == kInvalidFd)
    return;
  close(fd);
}

ScopedCgroup::ScopedCgroup(std::string_view subsystem) : path_() {
  reset(subsystem);
}

ScopedCgroup::~ScopedCgroup() {
  reset();
}

void ScopedCgroup::reset(std::string_view subsystem) {
  if (path_.size() > 0) {
    rmdir(path_.c_str());
    release();
  }
  if (subsystem.size() == 0)
    return;

  for (int attempts = 0; attempts <= 1000; ++attempts) {
    std::string path =
        StringPrintf("%s/omegajail_%d", subsystem.data(), attempts);
    if (mkdir(path.c_str(), 0755)) {
      if (errno == EEXIST)
        continue;
      return;
    }
    path_ = path;
    break;
  }
}

void ScopedCgroup::release() {
  path_ = std::string();
}

SigsysPipeThread::SigsysPipeThread(ScopedFD sigsys_socket_fd,
                                   ScopedFD user_notification_fd) {
  thread_ = std::thread([raw_sigsys_pipe_fd = sigsys_socket_fd.release(),
                         raw_user_notification_fd =
                             user_notification_fd.release()]() {
    ScopedFD sigsys_socket_fd(raw_sigsys_pipe_fd);
    ScopedFD user_notification_fd(raw_user_notification_fd);

    ScopedFD child_pid_fd = ReceiveFD(sigsys_socket_fd.get());
    if (!child_pid_fd) {
      PLOG(ERROR) << "Failed to read the exit syscall";
      return;
    }

    ScopedFD epoll_fd(epoll_create1(0));
    if (!epoll_fd) {
      PLOG(ERROR) << "Failed to call epoll_create1";
      return;
    }

    for (int fd : {user_notification_fd.get(), child_pid_fd.get()}) {
      struct epoll_event ev = {
          .events = EPOLLIN,
          .data = {.fd = fd},
      };
      if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_ADD, fd, &ev) == -1) {
        PLOG(ERROR) << "Failed to call epoll_ctl";
        return;
      }
    }

    // Discover the sizes of the structures that are used to receive
    // notifications and send notification responses, and allocate
    // buffers of those sizes.
    struct seccomp_notif_sizes sizes;
    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
      PLOG(ERROR) << "seccomp(SECCOMP_GET_NOTIF_SIZES)";
      return;
    }

    auto req_buf = std::make_unique<uint8_t[]>(sizes.seccomp_notif);
    struct seccomp_notif* req =
        reinterpret_cast<struct seccomp_notif*>(req_buf.get());

    while (true) {
      struct epoll_event events[2] = {};
      int nfds = epoll_wait(epoll_fd.get(), events, 2, -1);
      if (nfds == -1) {
        PLOG(ERROR) << "epoll_wait";
        return;
      }

      bool user_notification_fd_ready = false;
      for (int i = 0; i < nfds; ++i) {
        if (events[i].data.fd == child_pid_fd.get())
          return;

        if (events[i].data.fd == user_notification_fd.get())
          user_notification_fd_ready = true;
      }

      if (!user_notification_fd_ready) {
        LOG(ERROR) << "User notification FD was not ready";
        return;
      }

      memset(req, 0, sizes.seccomp_notif);
      if (ioctl(user_notification_fd.get(), SECCOMP_IOCTL_NOTIF_RECV, req) ==
          -1) {
        PLOG(ERROR) << "ioctl(SECCOMP_IOCTL_NOTIF_RECV)";
        return;
      }

      int init_exitsyscall = req->data.nr;
      if (HANDLE_EINTR(send(sigsys_socket_fd.get(), &init_exitsyscall,
                            sizeof(init_exitsyscall), MSG_NOSIGNAL)) < 0) {
        PLOG(ERROR) << "send(sigsys_socket_fd, init_exitsyscall)";
      }
      if (pidfd_send_signal(child_pid_fd.get(), SIGKILL, nullptr, 0))
        PLOG(ERROR) << "pidfd_send_signal(SIGKILL)";

      break;
    }
  });
}
SigsysPipeThread::~SigsysPipeThread() = default;

ScopedErrnoPreserver::ScopedErrnoPreserver() : errno_(errno) {}
ScopedErrnoPreserver::~ScopedErrnoPreserver() {
  errno = errno_;
}

bool AddToEpoll(int epoll_fd, int fd) {
  struct epoll_event ev = {};
  ev.events = EPOLLIN;
  ev.data.fd = fd;
  return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
}

bool AddToEpoll(int epoll_fd, EpollData* client_data) {
  struct epoll_event ev = {};
  ev.events = EPOLLIN;
  ev.data.ptr = client_data;
  return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_data->fd.get(), &ev) == 0;
}

bool RemoveFromEpoll(int epoll_fd,
                     EpollData* client_data,
                     std::vector<std::unique_ptr<EpollData>>* clients) {
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_data->fd.get(), nullptr))
    return false;

  for (size_t i = 0; i < clients->size(); i++) {
    if (clients->at(i).get() == client_data) {
      clients->erase(clients->cbegin() + i);
      break;
    }
  }
  return true;
}

std::string StringPrintf(const char* format, ...) {
  char path[4096];

  va_list ap;
  va_start(ap, format);
  ssize_t ret = vsnprintf(path, sizeof(path), format, ap);
  va_end(ap);

  return std::string(path, ret);
}

std::vector<std::string> StringSplit(const std::string_view input,
                                     ByChar delim) {
  std::vector<std::string> result;
  size_t pos = 0;

  while (true) {
    const size_t next = input.find(delim.delim, pos);
    if (next == std::string::npos)
      break;
    result.emplace_back(input.substr(pos, next - pos));
    pos = next + 1;
  }
  result.emplace_back(input.substr(pos));

  return result;
}

std::vector<std::string> StringSplit(const std::string_view input,
                                     ByAnyChar delim) {
  std::vector<std::string> result;
  size_t pos = 0;

  while (true) {
    size_t next = std::string::npos;
    for (const char sep : delim.delims) {
      const size_t candidate_pos = input.find(sep, pos);
      if (candidate_pos == std::string::npos)
        continue;
      if (next == std::string::npos || next > candidate_pos)
        next = candidate_pos;
    }
    if (next == std::string::npos)
      break;
    result.emplace_back(input.substr(pos, next - pos));
    pos = next + 1;
  }
  result.emplace_back(input.substr(pos));

  return result;
}

std::string StringJoin(const std::vector<std::string>& input,
                       std::string_view delim) {
  std::string result;
  bool first = true;
  for (const auto& piece : input) {
    if (first) {
      first = false;
    } else {
      result.append(delim);
    }
    result.append(piece);
  }
  return result;
}

std::string Clean(std::string_view path) {
  bool rooted = !path.empty() && path.front() == '/';
  std::string out;
  size_t r = 0, dotdot = 0;
  if (rooted) {
    out.append(1, '/');
    ++r;
    ++dotdot;
  }

  while (r < path.size()) {
    if (path[r] == '/') {
      // empty path element
      ++r;
      continue;
    }
    if (path[r] == '.' && (r + 1 == path.size() || path[r + 1] == '/')) {
      // . element
      ++r;
      continue;
    }
    if (path[r] == '.' && path[r + 1] == '.' &&
        (r + 2 == path.size() || path[r + 2] == '/')) {
      // .. element
      r += 2;
      if (out.size() > dotdot) {
        std::size_t previous_slash = out.find_last_of('/', out.size() - 1);
        if (previous_slash == std::string::npos)
          out.clear();
        else
          out.erase(std::max(dotdot, previous_slash));
      } else if (!rooted) {
        // cannot backtrack, but not rooted, so append .. element.
        if (!out.empty())
          out.append(1, '/');
        out.append("..");
        dotdot = out.size();
      }
    } else {
      // real path element.
      // add slash if needed
      if ((rooted && out.size() != 1) || (!rooted && out.size() != 0))
        out.append(1, '/');
      // copy element
      for (; r < path.size() && path[r] != '/'; r++)
        out.append(1, path[r]);
    }
  }

  // Turn empty string into "."
  if (out.empty())
    return ".";

  return out;
}

std::string Dirname(std::string_view path, std::size_t levels) {
  if (path.size() > 1 && path.back() == '/')
    path.remove_suffix(1);

  for (; levels > 0; --levels) {
    size_t basename_pos = path.find_last_of('/');
    if (basename_pos == std::string::npos) {
      // There are no more slashes in the path. We now need to produce a
      // relative path.
      if (levels == 1) {
        return "./";
      }

      std::string result("../");
      for (size_t i = 2; i < levels; ++i) {
        result.append("../");
      }
      return result;
    }
    if (basename_pos == 0 && !path.empty() && path.front() == '/')
      return "/";
    path = path.substr(0, basename_pos);
  }
  return std::string(path);
}

template <>
std::string PathJoin(std::string_view path, std::string_view component) {
  if (path.empty() || (!component.empty() && component.front() == '/'))
    return std::string(component);

  std::string result(path);
  if (result.back() != '/')
    result.append(1, '/');
  result.append(component.data(), component.size());
  return Clean(result);
}

bool WriteFile(std::string_view path,
               const std::string_view contents,
               bool append,
               mode_t mode) {
  LOG(DEBUG) << "Writing '" << contents << "' to " << path;

  ScopedFD fd(open(path.data(),
                   O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), mode));
  if (!fd)
    return false;
  if (write(fd.get(), contents.data(), contents.size()) !=
      static_cast<ssize_t>(contents.size())) {
    return false;
  }
  return true;
}

bool ReadUint64(std::string_view path, uint64_t* value) {
  std::ifstream is = std::ifstream(std::string(path));
  if (!is || !(is >> *value))
    return false;
  return true;
}

bool SendFD(int sockfd, ScopedFD fd) {
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } cmsg_buf;

  char data = 0;
  struct iovec iov = {
      .iov_base = &data,
      .iov_len = sizeof(data),
  };
  struct msghdr msg = {
      .msg_name = NULL,
      .msg_namelen = 0,
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = cmsg_buf.buf,
      .msg_controllen = sizeof(cmsg_buf.buf),
      .msg_flags = 0,
  };

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  int raw_fd = fd.get();
  memcpy(CMSG_DATA(cmsg), &raw_fd, sizeof(raw_fd));

  if (sendmsg(sockfd, &msg, MSG_NOSIGNAL) == -1)
    return false;

  return true;
}

ScopedFD ReceiveFD(int sockfd) {
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } cmsg_buf;

  char data = 0;
  struct iovec iov = {
      .iov_base = &data,
      .iov_len = sizeof(data),
  };
  struct msghdr msg = {
      .msg_name = NULL,
      .msg_namelen = 0,
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = cmsg_buf.buf,
      .msg_controllen = sizeof(cmsg_buf.buf),
      .msg_flags = 0,
  };

  if (recvmsg(sockfd, &msg,
              MSG_TRUNC | MSG_CTRUNC | MSG_CMSG_CLOEXEC | MSG_NOSIGNAL) == -1) {
    return ScopedFD();
  }

  if ((msg.msg_flags & MSG_TRUNC)) {
    errno = EMSGSIZE;
    return ScopedFD();
  }
  if ((msg.msg_flags & MSG_CTRUNC)) {
    errno = EMSGSIZE;
    return ScopedFD();
  }

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
      cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
    errno = EBADMSG;
    return ScopedFD();
  }

  int fd;
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
  return ScopedFD(fd);
}
