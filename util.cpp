#include "util.h"

#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

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

  ScopedFD fd(open(path.c_str(), append ? O_WRONLY | O_APPEND : O_WRONLY));
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
