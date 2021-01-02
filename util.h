#ifndef UTIL_H_
#define UTIL_H_

#include <sys/mman.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <string_view>
#include <thread>
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

class SigsysPipeThread {
 public:
  SigsysPipeThread(ScopedFD sigsys_socket_fd, ScopedFD user_notification_fd);
  ~SigsysPipeThread();

  void join() { thread_.join(); }

 private:
  std::thread thread_;
  DISALLOW_COPY_AND_ASSIGN(SigsysPipeThread);
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

struct ByChar {
  ByChar(char delim) : delim(delim) {}
  const char delim;
};
std::vector<std::string> StringSplit(std::string_view input, ByChar delim);

struct ByAnyChar {
  explicit ByAnyChar(std::string_view delims) : delims(delims) {}
  const std::string_view delims;
};
std::vector<std::string> StringSplit(std::string_view input, ByAnyChar delim);

std::string StringJoin(const std::vector<std::string>& input,
                       std::string_view delim);

// Clean returns the shortest path name equivalent to path
// by purely lexical processing. It applies the following rules
// iteratively until no further processing can be done:
//
//	1. Replace multiple Separator elements with a single one.
//	2. Eliminate each . path name element (the current directory).
//	3. Eliminate each inner .. path name element (the parent directory)
//	   along with the non-.. element that precedes it.
//	4. Eliminate .. elements that begin a rooted path:
//	   that is, replace "/.." by "/" at the beginning of a path,
//	   assuming Separator is '/'.
//
// The returned path ends in a slash only if it represents a root directory,
// such as "/" on Unix or `C:\` on Windows.
//
// Finally, any occurrences of slash are replaced by Separator.
//
// If the result of this process is an empty string, Clean
// returns the string ".".
//
// See also Rob Pike, ``Lexical File Names in Plan 9 or
// Getting Dot-Dot Right,''
// https://9p.io/sys/doc/lexnames.html
std::string Clean(std::string_view path);

std::string Dirname(std::string_view path, std::size_t levels = 1);

template <typename... Args>
std::string PathJoin(std::string_view path,
                     std::string_view component,
                     Args&&... args) {
  return PathJoin(path, PathJoin(component, std::forward<Args>(args)...));
}

template <>
std::string PathJoin(std::string_view path, std::string_view component);

bool ReadUint64(std::string_view path, uint64_t* value);

bool WriteFile(std::string_view path,
               std::string_view contents,
               bool append = false,
               mode_t mode = 0664);

bool SendFD(int sockfd, ScopedFD fd);
ScopedFD ReceiveFD(int sockfd);

template <typename T>
inline void ignore_result(T /* unused result */) {}

#endif  // UTIL_H_
