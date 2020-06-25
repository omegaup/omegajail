#ifndef ARGS_H_
#define ARGS_H_

#include <sys/resource.h>

#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

struct minijail;

enum class SigsysDetector {
  SIGSYS_TRACER,
  PTRACE,
  NONE,
};

struct ResourceLimit {
  __rlimit_resource resource;
  struct rlimit rlim;
};

struct Args {
  static constexpr uint64_t kMaxWallTimeLimitMsec =
      std::numeric_limits<uint64_t>::max();

  std::string comm;
  std::string program;
  std::string chdir;
  std::string stdin_redirect;
  std::string stdout_redirect;
  std::string stderr_redirect;
  std::string meta;
  std::string script_basename;
  ssize_t memory_limit_in_bytes = -1;
  size_t vm_memory_size_in_bytes = 0;
  uint64_t wall_time_limit_msec = kMaxWallTimeLimitMsec;
  SigsysDetector sigsys_detector = SigsysDetector::PTRACE;
  bool disable_sandboxing = false;
  std::vector<ResourceLimit> rlimits{
      ResourceLimit{RLIMIT_STACK, {RLIM_INFINITY, RLIM_INFINITY}}};
  std::unique_ptr<const char* []> program_args;

  bool Parse(int argc, char* argv[], struct minijail* j) throw();

 private:
  bool SetCompileFlags(std::string_view root,
                       std::string_view language,
                       std::string_view target,
                       const std::vector<std::string>& sources,
                       struct minijail* j);

  bool SetRunFlags(std::string_view root,
                   std::string_view language,
                   std::string_view target,
                   int64_t memory_limit_bytes,
                   struct minijail* j);

  void SetMemoryLimit(int64_t limit_bytes);

  std::string UseSeccompProgram(std::string_view seccomp_program_path,
                                struct minijail* j) const;

  bool EnterPivotRoot(std::string_view root, struct minijail* j) const;

  bool BindReadOnly(std::string_view source,
                    std::string_view target,
                    struct minijail* j) const;

  std::vector<std::string> program_args_holder;
};

#endif  // ARGS_H_
