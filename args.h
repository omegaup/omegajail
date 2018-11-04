#ifndef ARGS_H_
#define ARGS_H_

#include <limits>
#include <memory>
#include <string>
#include <vector>

struct minijail;

enum class SigsysDetector {
  SIGSYS_TRACER,
  PTRACE,
  NONE,
};

struct Args {
  static constexpr uint64_t kMaxWallTimeLimitMsec =
      std::numeric_limits<uint64_t>::max();

  std::string program;
  std::string chdir;
  std::string stdin_redirect;
  std::string stdout_redirect;
  std::string stderr_redirect;
  std::string meta;
  std::string script_basename;
  ssize_t memory_limit_in_bytes = -1;
  uint64_t wall_time_limit_msec = kMaxWallTimeLimitMsec;
  SigsysDetector sigsys_detector = SigsysDetector::PTRACE;
  std::unique_ptr<const char* []> program_args;

  bool Parse(int argc, char* argv[], struct minijail* j) throw();

 private:
  std::vector<std::string> program_args_holder;
};

#endif  // ARGS_H_
