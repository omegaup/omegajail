#include "args.h"

#include <fcntl.h>
#include <linux/filter.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cxxopts.hpp>

#include "logging.h"
#include "util.h"
#include "minijail/libminijail.h"

namespace {

std::vector<std::string> Split(const std::string& str, const std::string& sep) {
  std::vector<std::string> result;
  size_t pos = 0, sep_pos;

  while (true) {
    sep_pos = str.find(sep, pos);
    if (sep_pos == std::string::npos)
      break;
    result.push_back(str.substr(pos, sep_pos - pos));
    pos = sep_pos + sep.size();
  }

  result.push_back(str.substr(pos));

  return result;
}

std::string GetCWD() {
  char path[4096];
  if (!getcwd(path, sizeof(path)))
    PLOG(FATAL) << "Failed to get cwd";

  return std::string(path);
}

std::string MakeAbsolute(const std::string& path, const std::string& cwd) {
  if (path.size() && path[0] == '/')
    return path;

  return cwd + "/" + path;
}

}  // namespace

bool Args::Parse(int argc, char* argv[], struct minijail* j) throw() {
  cxxopts::Options options(argv[0], "The omegaUp sandbox");
  options.positional_help("-- program [args...]");

  // clang-format off
  options.add_options()
		("comm", "the reported name of the program",
		 cxxopts::value<std::string>(), "name")
		("b,bind", "binds a directory",
		 cxxopts::value<std::vector<std::string>>(), "src,dest[,1]")
		("d,chdir", "changes directory to |path|",
		 cxxopts::value<std::string>(), "path")
		("C,chroot", "sets the root of the chroot",
		 cxxopts::value<std::string>(), "path")
		("h,help", "prints this message")
		("S,seccomp-script",
		 "the filename of the seccomp script to load",
		 cxxopts::value<std::string>(), "filename")
		("seccomp-program",
		 "the filename of the seccomp BPF program to load",
		 cxxopts::value<std::string>(), "filename")
		("0,stdin", "redirects stdin", cxxopts::value<std::string>(),
		 "filename")
		("1,stdout", "redirects stdout",
		 cxxopts::value<std::string>(), "filename")
		("2,stderr", "redirects stderr",
		 cxxopts::value<std::string>(), "filename")
		("M,meta", "writes meta", cxxopts::value<std::string>(),
		 "filename")
		("t,time-limit", "sets the time limit",
		 cxxopts::value<uint64_t>(), "msec")
		("w,extra-wall-time-limit",
		 "sets the (additional) wall time limit",
		 cxxopts::value<uint64_t>()->default_value("1000"), "msec")
		("k,stack-limit", "sets the stack limit",
		 cxxopts::value<uint64_t>(), "bytes")
		("O,output-limit", "sets the output limit",
		 cxxopts::value<uint64_t>(), "bytes")
		("m,memory-limit", "sets the memory limit",
		 cxxopts::value<int64_t>(), "bytes")
		("cgroup-memory-limit", "sets the memory limit with cgroups",
		 cxxopts::value<ssize_t>(), "bytes")
		("sigsys-detector",
		 "one of 'sigsys_tracer' (default), 'ptrace', 'none'.",
		 cxxopts::value<std::string>())
		("program", "", cxxopts::value<std::vector<std::string>>());
  // clang-format on

  try {
    options.parse_positional("program");
    options.parse(argc, argv);
  } catch (cxxopts::option_not_exists_exception e) {
    std::cerr << "Invalid option: " << e.what() << std::endl;
    std::cerr << options.help({""}) << std::endl;
    return false;
  }

  if (options.count("help") || !options.count("program")) {
    std::cerr << options.help({""}) << std::endl;
    return false;
  }

  if (options.count("comm"))
    comm = options["comm"].as<std::string>() + "\n";

  for (const auto& bind_description :
       options["bind"].as<std::vector<std::string>>()) {
    auto bind = Split(bind_description, ",");

    if (bind.size() < 2 || bind.size() > 3) {
      std::cerr << "Invalid bind description: " << bind_description << std::endl
                << std::endl;
      std::cerr << options.help({""}) << std::endl;
      return false;
    }

    int ret = minijail_bind(j, bind[0].c_str(), bind[1].c_str(),
                            bind.size() == 3 && bind[2] == "1");
    if (ret) {
      std::cerr << "Bind \"" << bind_description
                << "\" failed: " << strerror(-ret) << std::endl;
      return false;
    }
  }

  if (options.count("chdir"))
    chdir = options["chdir"].as<std::string>();

  if (options.count("chroot")) {
    int ret = minijail_enter_pivot_root(
        j, options["chroot"].as<std::string>().c_str());
    if (ret) {
      std::cerr << "chroot to \"" << options["chroot"].as<std::string>()
                << "\" failed: " << strerror(-ret) << std::endl;
      return false;
    }
  }

  std::string cwd = GetCWD();

  if (options.count("stdin"))
    stdin_redirect = MakeAbsolute(options["stdin"].as<std::string>(), cwd);
  if (options.count("stdout"))
    stdout_redirect = MakeAbsolute(options["stdout"].as<std::string>(), cwd);
  if (options.count("stderr"))
    stderr_redirect = MakeAbsolute(options["stderr"].as<std::string>(), cwd);
  if (options.count("meta"))
    meta = options["meta"].as<std::string>();
  if (options.count("sigsys-detector")) {
    std::string detector = options["sigsys-detector"].as<std::string>();
    if (detector == "sigsys_tracer") {
      sigsys_detector = SigsysDetector::SIGSYS_TRACER;
    } else if (detector == "ptrace") {
      sigsys_detector = SigsysDetector::PTRACE;
    } else if (detector == "none") {
      sigsys_detector = SigsysDetector::NONE;
    } else {
      std::cerr << "invalid value for --sigsys-detector: \"" << detector
                << "\"";
      return false;
    }
  }

  if (options.count("seccomp-program")) {
    std::string seccomp_program_path =
        options["seccomp-program"].as<std::string>();
    size_t basename_pos = seccomp_program_path.find_last_of('/');
    if (basename_pos == std::string::npos)
      basename_pos = 0;
    else
      basename_pos++;
    struct sock_filter filter[BPF_MAXINSNS];
    struct sock_fprog seccomp_program;
    {
      ScopedFD program_fd(
          open(seccomp_program_path.c_str(), O_RDONLY | O_CLOEXEC));
      if (!program_fd)
        PLOG(FATAL) << "Failed to open BPF program";
      ssize_t bytes_read = read(program_fd.get(), filter, sizeof(filter));
      if (bytes_read < 0)
        PLOG(FATAL) << "Failed to read BPF program";
      if (bytes_read % sizeof(struct sock_filter) != 0)
        LOG(FATAL) << "Bad size: " << bytes_read;
      seccomp_program.filter = filter;
      seccomp_program.len = bytes_read / sizeof(struct sock_filter);
    }

    script_basename = seccomp_program_path.substr(
        basename_pos, seccomp_program_path.size() - basename_pos - 4);
    minijail_use_seccomp_filter(j);
    minijail_set_seccomp_filter_tsync(j);
    minijail_set_seccomp_filters(j, &seccomp_program);
  } else if (options.count("seccomp-script")) {
    std::string seccomp_script_path =
        options["seccomp-script"].as<std::string>();
    size_t basename_pos = seccomp_script_path.find_last_of('/');
    if (basename_pos == std::string::npos)
      basename_pos = 0;
    else
      basename_pos++;
    script_basename = seccomp_script_path.substr(basename_pos);
    minijail_use_seccomp_filter(j);
    minijail_set_seccomp_filter_tsync(j);
    minijail_parse_seccomp_filters(j, seccomp_script_path.c_str());
  }

  if (options.count("time-limit")) {
    uint64_t raw_limit_msec = options["time-limit"].as<uint64_t>();
    uint32_t limit_sec = static_cast<uint32_t>((999 + raw_limit_msec) / 1000);
    minijail_rlimit(j, RLIMIT_CPU, limit_sec, limit_sec + 1);
    wall_time_limit_msec =
        raw_limit_msec + options["extra-wall-time-limit"].as<uint64_t>();
  }
  if (options.count("memory-limit")) {
    int64_t limit_bytes = options["memory-limit"].as<int64_t>();
    if (limit_bytes != -1) {
      int ret = minijail_rlimit(j, RLIMIT_AS, limit_bytes, limit_bytes);
      if (ret) {
        std::cerr << "setting memory limit failed: " << strerror(-ret)
                  << std::endl;
        return false;
      }
    }
  }
  if (options.count("cgroup-memory-limit"))
    memory_limit_in_bytes = options["cgroup-memory-limit"].as<ssize_t>();
  if (options.count("output-limit")) {
    uint64_t limit_bytes = options["output-limit"].as<uint64_t>();
    int ret = minijail_rlimit(j, RLIMIT_FSIZE, limit_bytes, limit_bytes);
    if (ret) {
      std::cerr << "setting output limit failed: " << strerror(-ret)
                << std::endl;
      return false;
    }

    // Also disable core dumping when setting an output limit.
    ret = minijail_rlimit(j, RLIMIT_CORE, 0, 0);
    if (ret) {
      std::cerr << "setting output limit failed: " << strerror(-ret)
                << std::endl;
      return false;
    }
  }

  program_args_holder = options["program"].as<std::vector<std::string>>();
  program = program_args_holder.front();

  program_args.reset(new const char*[program_args_holder.size() + 1]);
  for (size_t i = 0; i < program_args_holder.size(); ++i)
    program_args[i] = program_args_holder[i].c_str();
  program_args[program_args_holder.size()] = nullptr;

  return true;
}
