#include "args.h"

#include <fcntl.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cxxopts.hpp>

#include "logging.h"
#include "minijail/libminijail.h"
#include "util.h"

namespace {

constexpr size_t kExtraMemorySizeInBytes = 16 * 1024 * 1024;
constexpr size_t kClrVmMemorySizeInBytes = 26 * 1024 * 1024;
constexpr size_t kJavaVmMemorySizeInBytes = 43 * 1024 * 1024;
constexpr size_t kJavaMinHeapSizeInBytes = 29 * 1024 * 1024;

std::vector<std::string> Split(std::string_view str, std::string_view sep) {
  std::vector<std::string> result;
  size_t pos = 0, sep_pos;

  while (true) {
    sep_pos = str.find(sep, pos);
    if (sep_pos == std::string::npos)
      break;
    result.push_back(std::string(str.substr(pos, sep_pos - pos)));
    pos = sep_pos + sep.size();
  }

  result.push_back(std::string(str.substr(pos)));

  return result;
}

std::string GetCWD() {
  char path[4096];
  if (!getcwd(path, sizeof(path)))
    PLOG(FATAL) << "Failed to get cwd";

  return std::string(path);
}

std::string MakeAbsolute(std::string_view path, std::string_view cwd) {
  return PathJoin(cwd, path);
}

std::string UseSeccompProgram(std::string_view seccomp_program_path,
                              struct minijail* j) {
  size_t basename_pos = seccomp_program_path.find_last_of('/');
  if (basename_pos == std::string::npos)
    basename_pos = 0;
  else
    basename_pos++;
  struct sock_filter filter[BPF_MAXINSNS];
  struct sock_fprog seccomp_program;
  {
    ScopedFD program_fd(
        open(seccomp_program_path.data(), O_RDONLY | O_CLOEXEC));
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

  minijail_use_seccomp_filter(j);
  minijail_set_seccomp_filter_tsync(j);
  minijail_set_seccomp_filters(j, &seccomp_program);
  return std::string(seccomp_program_path.substr(
      basename_pos, seccomp_program_path.size() - basename_pos - 4));
}

bool EnterPivotRoot(std::string_view root, struct minijail* j) {
  int ret = minijail_enter_pivot_root(j, root.data());
  if (ret) {
    std::cerr << "chroot to \"" << root << "\" failed: " << strerror(-ret)
              << std::endl;
    return false;
  }
  return true;
}

bool BindReadOnly(std::string_view source,
                  std::string_view target,
                  struct minijail* j) {
  int ret = minijail_bind(j, source.data(), target.data(), false);
  if (ret) {
    std::cerr << "bind \"" << source << "," << target
              << "\" failed: " << strerror(-ret) << std::endl;
    return false;
  }
  return true;
}

bool SetMemoryLimit(int64_t limit_bytes, struct minijail* j) {
  if (limit_bytes < 0)
    return true;
  int ret = minijail_rlimit(j, RLIMIT_AS, limit_bytes, limit_bytes);
  if (ret) {
    std::cerr << "setting memory limit to " << limit_bytes
              << " failed: " << strerror(-ret) << std::endl;
    return false;
  }
  return true;
}

}  // namespace

bool Args::Parse(int argc, char* argv[], struct minijail* j) throw() {
  cxxopts::Options options(argv[0], "The omegaUp sandbox");
  options.positional_help("-- program [args...]");

  std::string cwd = GetCWD();

  // clang-format off
  options.add_options()
    ("root", "root of the omegajail runtime",
     cxxopts::value<std::string>()->default_value(
       Dirname(PathJoin(cwd, argv[0]), 2)), "path")
    ("compile", "add the necessary flags to compile in the specified language",
     cxxopts::value<std::string>(), "language")
    ("compile-source", "add the file to the compilation",
     cxxopts::value<std::vector<std::string>>(), "path")
    ("compile-target", "target of the compilation",
     cxxopts::value<std::string>(), "path")
    ("run", "add the necessary flags to run in the specified language",
     cxxopts::value<std::string>(), "language")
    ("run-target", "set the target name to execute",
     cxxopts::value<std::string>(), "path")
    ("comm", "the reported name of the program",
     cxxopts::value<std::string>(), "name")
    ("b,bind", "binds a directory",
     cxxopts::value<std::vector<std::string>>(), "src,dest[,1]")
    ("d,chdir", "changes directory to |path|",
     cxxopts::value<std::string>(), "path")
    ("C,chroot", "sets the root of the chroot",
     cxxopts::value<std::string>(), "path")
    ("h,help", "prints this message")
    ("S,seccomp-script", "the filename of the seccomp script to load",
     cxxopts::value<std::string>(), "filename")
    ("seccomp-program", "the filename of the seccomp BPF program to load",
     cxxopts::value<std::string>(), "filename")
    ("0,stdin", "redirects stdin",
     cxxopts::value<std::string>(), "filename")
    ("1,stdout", "redirects stdout",
     cxxopts::value<std::string>(), "filename")
    ("2,stderr", "redirects stderr",
     cxxopts::value<std::string>(), "filename")
    ("M,meta", "writes meta",
     cxxopts::value<std::string>(), "filename")
    ("t,time-limit", "sets the time limit",
     cxxopts::value<uint64_t>(), "msec")
    ("w,extra-wall-time-limit", "sets the (additional) wall time limit",
     cxxopts::value<uint64_t>()->default_value("1000"), "msec")
    ("k,stack-limit", "sets the stack limit",
     cxxopts::value<uint64_t>(), "bytes")
    ("O,output-limit", "sets the output limit",
     cxxopts::value<uint64_t>(), "bytes")
    ("m,memory-limit", "sets the memory limit",
     cxxopts::value<int64_t>()->default_value("-1"), "bytes")
    ("cgroup-memory-limit", "sets the memory limit with cgroups",
     cxxopts::value<ssize_t>(), "bytes")
    ("sigsys-detector", "one of 'sigsys_tracer' (default), 'ptrace', 'none'.",
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

  if (options.count("help")) {
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
    script_basename =
        UseSeccompProgram(options["seccomp-program"].as<std::string>(), j);
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

  if (options.count("run")) {
    if (!SetRunFlags(options["root"].as<std::string>(),
                     options["run"].as<std::string>(),
                     options["run-target"].as<std::string>(),
                     options["memory-limit"].as<int64_t>(), j)) {
      return false;
    }
  } else {
    if (!SetMemoryLimit(options["memory-limit"].as<int64_t>(), j))
      return false;
    if (options.count("cgroup-memory-limit"))
      memory_limit_in_bytes = options["cgroup-memory-limit"].as<ssize_t>();

    if (options.count("compile")) {
      if (!SetCompileFlags(
              options["root"].as<std::string>(),
              options["compile"].as<std::string>(),
              options["compile-target"].as<std::string>(),
              options["compile-source"].as<std::vector<std::string>>(), j)) {
        return false;
      }
    }
  }

  if (options.count("program")) {
    const std::vector<std::string>& program_args =
        options["program"].as<std::vector<std::string>>();
    program_args_holder.insert(program_args_holder.end(), program_args.begin(),
                               program_args.end());
  }

  if (program_args_holder.empty()) {
    std::cerr << options.help({""}) << std::endl;
    return false;
  }

  program = program_args_holder.front();

  program_args =
      std::make_unique<const char* []>(program_args_holder.size() + 1);
  for (size_t i = 0; i < program_args_holder.size(); ++i)
    program_args[i] = program_args_holder[i].c_str();
  program_args[program_args_holder.size()] = nullptr;

  return true;
}

bool Args::SetCompileFlags(std::string_view root,
                           std::string_view language,
                           std::string_view target,
                           const std::vector<std::string>& sources,
                           struct minijail* j) {
  if (!EnterPivotRoot(PathJoin(root, "root-compilers"), j))
    return false;

  // Force-redirect stdin to an empty file.
  stdin_redirect = PathJoin(root, "root-compilers/dev/null");

  if (language == "c") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/gcc.bpf"), j);
    program_args_holder = {"/usr/bin/gcc", "-o", std::string(target),
                           "--std=c11", "-O2"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    program_args_holder.emplace_back("-lm");
    return true;
  }
  if (language == "cpp" || language == "cpp11") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/gcc.bpf"), j);
    program_args_holder = {"/usr/bin/g++", "--std=c++11", "-o",
                           std::string(target), "-O2"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    program_args_holder.emplace_back("-lm");
    return true;
  }
  if (language == "cpp17-gcc") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/gcc.bpf"), j);
    program_args_holder = {"/usr/bin/g++", "--std=c++17", "-o",
                           std::string(target), "-O2"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    program_args_holder.emplace_back("-lm");
    return true;
  }
  if (language == "cpp17-clang") {
    script_basename =
        UseSeccompProgram(PathJoin(root, "policies/clang.bpf"), j);
    program_args_holder = {"/usr/bin/clang++",  "--std=c++17", "-o",
                           std::string(target), "-O3",         "-march=native"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    program_args_holder.emplace_back("-lm");
    return true;
  }
  if (language == "pas") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/fpc.bpf"), j);
    program_args_holder = {
        "/usr/bin/fpc",
        "-Tlinux",
        "-O2",
        "-Mobjfpc",
        "-Sc",
        "-Sh",
        StringPrintf("-o%s", target.data()),
    };
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "lua") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/lua.bpf"), j);
    program_args_holder = {"/usr/bin/luac", "-o", std::string(target)};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "hs") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/ghc.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-hs"), "/usr/lib/ghc", j))
      return false;
    program_args_holder = {"/usr/lib/ghc/bin/ghc", "-B/usr/lib/ghc", "-O2",
                           "-o", std::string(target)};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "java") {
    script_basename =
        UseSeccompProgram(PathJoin(root, "policies/javac.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-openjdk"), "/usr/lib/jvm", j))
      return false;
    program_args_holder = {"/usr/bin/javac", "-J-Xmx512M", "-d", "."};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "py") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/pyc.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-python"), "/usr/lib/python2.7", j))
      return false;
    program_args_holder = {"/usr/bin/python", "-m", "py_compile"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "py3") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/pyc.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-python3"), "/usr/lib/python3.6", j))
      return false;
    program_args_holder = {"/usr/bin/python3", "-m", "py_compile"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "rb") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/ruby.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-ruby"), "/usr/lib/ruby", j))
      return false;
    program_args_holder = {"/usr/bin/ruby", "-wc"};
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "cs") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/csc.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-dotnet"), "/usr/share/dotnet", j))
      return false;
    program_args_holder = {
        "/usr/share/dotnet/dotnet",
        "/usr/share/dotnet/sdk/2.2.402/Roslyn/bincore/csc.dll",
        "-noconfig",
        "@/usr/share/dotnet/Release.rsp",
        StringPrintf("-out:%s.dll",
                     PathJoin(Dirname(sources.front()), target).c_str()),
        "-target:exe",
    };
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }
  if (language == "kp" || language == "kj") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/js.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-js"), "/opt/nodejs", j))
      return false;
    program_args_holder = {
        "/usr/bin/node",
        "/opt/nodejs/karel.js",
        "compile",
        language == "kp" ? "pascal" : "java",
        "-o",
        StringPrintf("%s.kx", target.data()),
    };
    program_args_holder.insert(program_args_holder.end(), sources.begin(),
                               sources.end());
    return true;
  }

  std::cerr << "Unknown compile language \"" << language << "\"" << std::endl;
  return false;
}

bool Args::SetRunFlags(std::string_view root,
                       std::string_view language,
                       std::string_view target,
                       int64_t memory_limit_bytes,
                       struct minijail* j) {
  if (!EnterPivotRoot(PathJoin(root, "root"), j))
    return false;

  if (language == "c" || language == "cpp" || language == "cpp11" ||
      language == "cpp17-gcc" || language == "cpp17-clang") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/cpp.bpf"), j);
    program_args_holder = {StringPrintf("./%s", target.data())};
    return true;
  }
  if (language == "pas") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/pas.bpf"), j);
    program_args_holder = {StringPrintf("./%s", target.data())};
    return true;
  }
  if (language == "lua") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/lua.bpf"), j);
    program_args_holder = {"/usr/bin/lua", StringPrintf("./%s", target.data())};
    return true;
  }
  if (language == "hs") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/hs.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-hs"), "/usr/lib/ghc", j))
      return false;
    program_args_holder = {StringPrintf("./%s", target.data())};
    return true;
  }
  if (language == "java") {
    script_basename = UseSeccompProgram(PathJoin(root, "policies/java.bpf"), j);
    vm_memory_size_in_bytes = kJavaVmMemorySizeInBytes;
    if (!BindReadOnly(PathJoin(root, "root-openjdk"), "/usr/lib/jvm", j))
      return false;
    program_args_holder = {"/usr/bin/java"};
    if (memory_limit_bytes > 0) {
      program_args_holder.push_back(StringPrintf(
          "-Xmx%" PRId64, memory_limit_bytes + kJavaMinHeapSizeInBytes));
    }
    program_args_holder.emplace_back(target);
    return true;
  }
  if (language == "py") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/py.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-python"), "/usr/lib/python2.7", j))
      return false;
    program_args_holder = {"/usr/bin/python",
                           StringPrintf("%s.py", target.data())};
    return true;
  }
  if (language == "py3") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/py.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-python3"), "/usr/lib/python3.6", j))
      return false;
    program_args_holder = {"/usr/bin/python3",
                           StringPrintf("%s.py3", target.data())};
    return true;
  }
  if (language == "rb") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/ruby.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-ruby"), "/usr/lib/ruby", j))
      return false;
    program_args_holder = {"/usr/bin/ruby",
                           StringPrintf("%s.rb", target.data())};
    return true;
  }
  if (language == "cs") {
    memory_limit_in_bytes =
        static_cast<ssize_t>(memory_limit_bytes + kClrVmMemorySizeInBytes);
    vm_memory_size_in_bytes = kClrVmMemorySizeInBytes;
    script_basename = UseSeccompProgram(PathJoin(root, "policies/cs.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-dotnet"), "/usr/share/dotnet", j))
      return false;
    program_args_holder = {"/usr/share/dotnet/dotnet",
                           StringPrintf("%s.dll", target.data())};
    return true;
  }
  if (language == "kp" || language == "kj") {
    if (!SetMemoryLimit(memory_limit_bytes + kExtraMemorySizeInBytes, j))
      return false;
    script_basename =
        UseSeccompProgram(PathJoin(root, "policies/karel.bpf"), j);
    if (!BindReadOnly(PathJoin(root, "root-js"), "/opt/nodejs", j))
      return false;
    program_args_holder = {"/opt/nodejs/karel.wasm",
                           StringPrintf("%s.kx", target.data())};
    return true;
  }

  std::cerr << "Unknown run language \"" << language << "\"" << std::endl;
  return false;
}
