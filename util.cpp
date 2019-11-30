#include "util.h"

#include <stdarg.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <utility>

#include "logging.h"

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

ScopedDir::ScopedDir(std::string_view path, mode_t mode) : path_(path) {
  if (mkdir(path_.c_str(), mode) == -1)
    return;
  valid_ = true;
}

ScopedDir::~ScopedDir() {
  if (!valid_)
    return;
  if (rmdir(path_.c_str()) == -1)
    PLOG(ERROR) << "Failed to rmdir(" << path_ << ")";
}

ScopedKprobe::ScopedKprobe(std::string_view path,
                           std::string_view unregister_string)
    : path_(path), unregister_string_(unregister_string) {}

ScopedKprobe::~ScopedKprobe() {
  if (!WriteFile(path_, unregister_string_, true))
    PLOG(ERROR) << "Failed to unregister kprobe";
}

// static
std::unique_ptr<ScopedKprobe> ScopedKprobe::Create(
    std::string_view path,
    std::string_view register_string,
    std::string_view unregister_string) {
  if (!WriteFile(path, register_string, true)) {
    PLOG(ERROR) << "Failed to register kprobe";
    return std::unique_ptr<ScopedKprobe>();
  }
  return std::unique_ptr<ScopedKprobe>(
      new ScopedKprobe(path, unregister_string));
}

ScopedMmap::ScopedMmap(void* ptr, size_t size) : ptr_(ptr), size_(size) {}

ScopedMmap::~ScopedMmap() {
  reset();
}

void* ScopedMmap::get() {
  return ptr_;
}

const void* ScopedMmap::get() const {
  return ptr_;
}

void ScopedMmap::reset(void* ptr, size_t size) {
  std::swap(ptr, ptr_);
  std::swap(size, size_);
  if (ptr == MAP_FAILED)
    return;
  if (munmap(ptr, size))
    PLOG(ERROR) << "Failed to unmap memory";
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

ScopedUnlink::ScopedUnlink(std::string_view path) : path_(path) {}

ScopedUnlink::~ScopedUnlink() {
  reset();
}

void ScopedUnlink::reset(std::string_view path) {
  path_ = path;
  if (path.empty())
    return;
  unlink(path_.c_str());
}

void ScopedUnlink::release() {
  path_ = std::string();
}

SigsysTracerClient::SigsysTracerClient(ScopedFD fd) : fd_(std::move(fd)) {}
SigsysTracerClient::~SigsysTracerClient() = default;

bool SigsysTracerClient::Initialize() {
  ScopedFD sock(socket(AF_UNIX, SOCK_STREAM, 0));
  if (!sock) {
    PLOG(ERROR) << "Error allocating the socket for sigsys_tracer";
    return false;
  }

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "/run/sigsys_tracer.socket",
          sizeof(addr.sun_path) - 1);
  if (HANDLE_EINTR(connect(sock.get(),
                           reinterpret_cast<const struct sockaddr*>(&addr),
                           sizeof(addr)))) {
    PLOG(ERROR) << "Failed to connect. Falling back to ptrace";
    return false;
  }

  char buffer[1024];
  ssize_t bytes_read = HANDLE_EINTR(read(sock.get(), buffer, sizeof(buffer)));
  if (bytes_read == -1) {
    PLOG(ERROR) << "Failed to get initial OK";
    return false;
  }

  if (strncmp(buffer, "OK\n", 3)) {
    PLOG(ERROR) << "Failed to get OK from sigsys_tracer";
    return false;
  }

  fd_ = std::move(sock);
  return true;
}

bool SigsysTracerClient::Read(int* signal) {
  if (!fd_)
    return false;
  if (shutdown(fd_.get(), SHUT_WR)) {
    PLOG(ERROR) << "Failed to perform half-shutdown";
    return false;
  }

  char buffer[16] = {};
  ssize_t bytes_read = HANDLE_EINTR(read(fd_.get(), buffer, sizeof(buffer)));
  if (bytes_read <= 0) {
    PLOG(ERROR) << "Failed to read from server";
    return false;
  }

  errno = 0;
  long signal_long = strtol(buffer, nullptr, 10);
  if (errno) {
    PLOG(ERROR) << "Failed to parse reply from sigsys_tracer";
    return false;
  }

  *signal = static_cast<int>(signal_long);
  return true;
}

ScopedFD SigsysTracerClient::TakeFD() {
  return std::move(fd_);
}

ScopedErrnoPreserver::ScopedErrnoPreserver() : errno_(errno) {}
ScopedErrnoPreserver::~ScopedErrnoPreserver() {
  errno = errno_;
}

std::string StringPrintf(const char* format, ...) {
  char path[4096];

  va_list ap;
  va_start(ap, format);
  ssize_t ret = vsnprintf(path, sizeof(path), format, ap);
  va_end(ap);

  return std::string(path, ret);
}

std::vector<std::string> StringSplit(std::string_view input, char delim) {
  std::vector<std::string> result;
  size_t pos = 0;

  while (true) {
    size_t next = input.find(delim, pos);
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

bool WriteFile(std::string_view path, std::string_view contents, bool append) {
  LOG(DEBUG) << "Writing '" << contents << "' to " << path;

  ScopedFD fd(open(path.data(), O_WRONLY | (append ? O_APPEND : O_TRUNC)));
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
