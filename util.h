#ifndef UTIL_H_
#define UTIL_H_

#include <sys/mman.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include "macros.h"

class ScopedFD {
 public:
  static constexpr int kInvalidFd = -1;

  explicit ScopedFD(int fd = kInvalidFd);
  ~ScopedFD();
  ScopedFD(ScopedFD&& fd);

  int get() const;
  int release();
  operator bool() const { return fd_ != kInvalidFd; }
  void reset(int fd = kInvalidFd);

 private:
  int fd_;

  DISALLOW_COPY_AND_ASSIGN(ScopedFD);
};

class ScopedDir {
 public:
  ScopedDir(const std::string& path, mode_t mode = 0755);
  ~ScopedDir();
  operator bool() const { return valid_; }

 private:
  const std::string path_;
  bool valid_;

  DISALLOW_COPY_AND_ASSIGN(ScopedDir);
};

class ScopedKprobe {
 public:
  static std::unique_ptr<ScopedKprobe> Create(
      const std::string& path,
      const std::string& register_string,
      const std::string& unregister_string);
  ~ScopedKprobe();

 private:
  ScopedKprobe(const std::string& path, const std::string& unregister_string);

  const std::string path_;
  const std::string unregister_string_;

  DISALLOW_COPY_AND_ASSIGN(ScopedKprobe);
};

class ScopedMmap {
 public:
  ScopedMmap(void* ptr = MAP_FAILED, size_t size = 0);
  ~ScopedMmap();

  operator bool() const { return ptr_ != MAP_FAILED; }
  void* get();
  const void* get() const;
  void reset(void* ptr = MAP_FAILED, size_t size = 0);

 private:
  void* ptr_;
  size_t size_;

  DISALLOW_COPY_AND_ASSIGN(ScopedMmap);
};

std::string StringPrintf(const char* format, ...);

bool ReadUint64(const std::string& path, uint64_t* value);

bool WriteFile(const std::string& path,
               const std::string& contents,
               bool append = false);

#endif  // UTIL_H_
