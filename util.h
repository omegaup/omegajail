#ifndef UTIL_H_
#define UTIL_H_

#include <sys/mman.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "macros.h"

class ScopedFD {
 public:
  static constexpr int kInvalidFd = -1;

  explicit ScopedFD(int fd = kInvalidFd);
  ~ScopedFD();
  ScopedFD(ScopedFD&& fd);
  ScopedFD& operator=(ScopedFD&& fd);

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
  ScopedDir(std::string_view path, mode_t mode = 0755);
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
      std::string_view path,
      std::string_view register_string,
      std::string_view unregister_string);
  ~ScopedKprobe();

 private:
  ScopedKprobe(std::string_view path, std::string_view unregister_string);

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

class ScopedCgroup {
 public:
  ScopedCgroup(std::string_view subsystem = std::string_view());
  ~ScopedCgroup();

  operator bool() const { return path_.size() > 0; }
  std::string_view path() const { return path_; }
  void reset(std::string_view subsystem = std::string_view());
  void release();

 private:
  std::string path_;

  DISALLOW_COPY_AND_ASSIGN(ScopedCgroup);
};

class ScopedUnlink {
 public:
  ScopedUnlink(std::string_view path = std::string_view());
  ~ScopedUnlink();

  operator bool() const { return !path_.empty(); }
  std::string_view path() const { return path_; }
  void reset(std::string_view path = std::string_view());
  void release();

 private:
  std::string path_;

  DISALLOW_COPY_AND_ASSIGN(ScopedUnlink);
};

class SigsysTracerClient {
 public:
  explicit SigsysTracerClient(ScopedFD fd = ScopedFD());
  ~SigsysTracerClient();

  operator bool() const { return fd_; }
  bool Initialize();
  bool Read(int* syscall);
  ScopedFD TakeFD();

 private:
  ScopedFD fd_;
  DISALLOW_COPY_AND_ASSIGN(SigsysTracerClient);
};

class ScopedErrnoPreserver {
 public:
  ScopedErrnoPreserver();
  ~ScopedErrnoPreserver();

 private:
  const int errno_;
  DISALLOW_COPY_AND_ASSIGN(ScopedErrnoPreserver);
};

std::string StringPrintf(const char* format, ...);

std::vector<std::string> StringSplit(std::string_view input, char delim);

bool ReadUint64(std::string_view path, uint64_t* value);

bool WriteFile(std::string_view path,
               std::string_view contents,
               bool append = false);

template <typename T>
inline void ignore_result(T /* unused result */) {}

#endif  // UTIL_H_
