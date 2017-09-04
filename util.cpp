#include "util.h"

#include <stdarg.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <utility>
#include <fstream>

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

ScopedDir::ScopedDir(const std::string& path, mode_t mode) : path_(path) {
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

ScopedKprobe::ScopedKprobe(const std::string& path,
                           const std::string& unregister_string)
    : path_(path), unregister_string_(unregister_string) {}

ScopedKprobe::~ScopedKprobe() {
  if (!WriteFile(path_, unregister_string_, true))
    PLOG(ERROR) << "Failed to unregister kprobe";
}

// static
std::unique_ptr<ScopedKprobe> ScopedKprobe::Create(
    const std::string& path,
    const std::string& register_string,
    const std::string& unregister_string) {
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

ScopedCgroup::ScopedCgroup(const std::string& subsystem) : path_() {
  reset(subsystem);
}

ScopedCgroup::~ScopedCgroup() {
  reset();
}

void ScopedCgroup::reset(const std::string& subsystem) {
  if (path_.size() > 0) {
    rmdir(path_.c_str());
    release();
  }
  if (subsystem.size() == 0)
    return;

  for (int attempts = 0; attempts <= 1000; ++attempts) {
    std::string path =
        StringPrintf("%s/omegajail_%d", subsystem.c_str(), attempts);
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

ScopedUnlink::ScopedUnlink(std::string path) : path_(std::move(path)) {}

ScopedUnlink::~ScopedUnlink() {
  reset();
}

void ScopedUnlink::reset(std::string path) {
  std::swap(path, path_);
  if (path.empty())
    return;
  unlink(path.c_str());
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

std::string StringPrintf(const char* format, ...) {
  char path[4096];

  va_list ap;
  va_start(ap, format);
  ssize_t ret = vsnprintf(path, sizeof(path), format, ap);
  va_end(ap);

  return std::string(path, ret);
}

bool WriteFile(const std::string& path,
               const std::string& contents,
               bool append) {
  LOG(DEBUG) << "Writing '" << contents << "' to " << path;

  ScopedFD fd(open(path.c_str(), O_WRONLY | (append ? O_APPEND : O_TRUNC)));
  if (!fd)
    return false;
  if (write(fd.get(), contents.c_str(), contents.size()) !=
      static_cast<ssize_t>(contents.size())) {
    return false;
  }
  return true;
}

bool ReadUint64(const std::string& path, uint64_t* value) {
  std::ifstream is(path);
  if (!is || !(is >> *value))
    return false;
  return true;
}
