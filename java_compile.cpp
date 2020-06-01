#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

#include "logging.h"
#include "util.h"

namespace {

std::string TrimJavaExtension(std::string_view filename) {
  static constexpr std::string_view java_extension = ".java";

  if (filename.size() >= java_extension.size() &&
      filename.compare(filename.size() - java_extension.size(),
                       std::string::npos, java_extension) == 0) {
    filename.remove_suffix(java_extension.size());
  }
  return std::string(filename);
}

[[noreturn]] void Exec(const std::vector<std::string>& args) {
  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (const std::string& arg : args)
    argv.emplace_back(const_cast<char*>(arg.data()));
  argv.emplace_back(nullptr);
  if (execve(argv[0], argv.data(), environ))
    PLOG(FATAL) << "Failed to execve `" << StringJoin(args, " ") << "`";
  abort();
}

int ForkExec(const std::vector<std::string>& args) {
  pid_t child = vfork();
  if (child == -1)
    PLOG(FATAL) << "Could not fork child";

  if (child == 0) {
    // This is the child process.
    Exec(args);
  }

  // Parent process.
  int wstatus;
  while (true) {
    if (waitpid(child, &wstatus, WUNTRACED | WCONTINUED) == -1)
      PLOG(FATAL) << "Failed to wait for child";

    if (WIFEXITED(wstatus))
      return WEXITSTATUS(wstatus);
    if (WIFSIGNALED(wstatus))
      return WTERMSIG(wstatus);
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 3)
    PLOG(FATAL) << argv[0] << " <target> <source> [<source> ...]";
  const char* target = argv[1];
  std::vector<std::string> javac_args = {
      "/usr/bin/javac",
      "-J-Xmx512M",
      "-d",
      ".",
  };
  std::vector<std::string> jaotc_args = {
      "/usr/bin/jaotc",
      "-J-Xmx512M",
      "-J-XX:+UseSerialGC",
      "-J-Xshare:on",
      "--output",
      StringPrintf("%s.so", target),
  };
  for (int i = 2; i < argc; ++i) {
    javac_args.emplace_back(argv[i]);
    jaotc_args.emplace_back(
        StringPrintf("%s.class", TrimJavaExtension(argv[i]).c_str()));
  }

  int status = ForkExec(javac_args);
  if (status != 0)
    return status;
  Exec(jaotc_args);
}
