#include <getopt.h>
#include <linux/net_tstamp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "logging.h"
#include "macros.h"
#include "util.h"

namespace {

constexpr int kCloseStdoutWhenReady = 129;
constexpr int kMapping = 130;
const struct option kLongOptions[] = {
    {"help", no_argument, 0, 'h'},
    {"output", required_argument, 0, 'o'},
    {"close-stdout-when-ready", no_argument, 0, kCloseStdoutWhenReady},
    {"mapping", required_argument, 0, kMapping},
    {0, 0, 0, 0}};

uint32_t stream_counter = 0;

struct EpollData {
  uint32_t stream_id;
  ScopedFD fd;
  std::string comm;
  bool has_limit;
  size_t limit;
  size_t written;
  ScopedFD redirect_fd;
};

struct Mapping {
  std::string comm;
  size_t limit;
  std::string path;
  size_t open_fds;
};

bool AddToEpoll(int epoll_fd, int fd) {
  struct epoll_event ev = {};
  ev.events = EPOLLIN;
  ev.data.fd = fd;
  return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
}

bool AddToEpoll(int epoll_fd, EpollData* client_data) {
  struct epoll_event ev = {};
  ev.events = EPOLLIN;
  ev.data.ptr = client_data;
  return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_data->fd.get(), &ev) == 0;
}

bool RemoveFromEpoll(int epoll_fd,
                     EpollData* client_data,
                     std::vector<std::unique_ptr<EpollData>>* clients) {
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_data->fd.get(), nullptr))
    return false;

  for (size_t i = 0; i < clients->size(); i++) {
    if (clients->at(i).get() == client_data) {
      clients->erase(clients->cbegin() + i);
      break;
    }
  }
  return true;
}

std::string GetProcessName(pid_t pid) {
  std::string path = StringPrintf("/proc/%d/comm", pid);
  ScopedFD f(open(path.c_str(), O_RDONLY));
  if (!f)
    return std::string();

  std::string buffer(128, '\0');
  if (HANDLE_EINTR(read(f.get(), const_cast<char*>(buffer.data()),
                        buffer.size() - 1)) < 0) {
    return std::string();
  }

  size_t nul_pos = buffer.find_first_of("\n\0", 0, 2);
  if (nul_pos != std::string::npos)
    buffer.resize(nul_pos);
  return buffer;
}

struct __attribute__((__packed__)) Header {
  uint32_t stream_id;
  uint16_t message_len;
  uint64_t timestamp : 48;
};

static_assert(sizeof(Header) == 12, "Header is not in the right layout");

bool WriteFully(int fd, const void* data, size_t length) {
  const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data);
  while (length) {
    ssize_t written = HANDLE_EINTR(write(fd, data_ptr, length));
    if (written <= 0)
      return false;
    data_ptr += written;
    length -= written;
  }

  return true;
}

bool WriteMessage(int fd,
                  uint32_t stream_id,
                  struct timeval* timestamp,
                  const char* message,
                  size_t message_len) {
  if (message_len > 4096)
    return false;
  Header header{stream_id, static_cast<uint16_t>(message_len),
                timestamp ? static_cast<uint64_t>(timestamp->tv_sec * 1000000 +
                                                  timestamp->tv_usec % 1000000)
                          : 0u};
  if (!WriteFully(fd, &header, sizeof(header)))
    return false;
  return WriteFully(fd, message, message_len);
}

void ShowUsage(const char* program_name) {
  fprintf(stderr,
          "Usage: %s [options...] <socket path>\n\n"
          "  -o, --output=FILE          Write the output to FILE.\n"
          "  --close-stdout-when-ready  Close stdout when the socket file is "
          "ready.\n"
          "                             Requires --output to be used.\n"
          "  --mapping=NAME:LIMIT:PATH  When a program with comm=NAME "
          "connects, write\n"
          "                             the output to PATH.{err,out} and limit "
          "its\n"
          "                             size to LIMIT bytes.\n",
          program_name);
}

}  // namespace

int main(int argc, char* argv[]) {
  ScopedFD output_fd;
  bool close_stdout_when_ready = false;

  std::map<std::string, Mapping> comm_mapping;

  while (true) {
    int c = getopt_long(argc, argv, "ho:", kLongOptions, nullptr);
    if (c == -1)
      break;
    switch (c) {
      case 'o':
        output_fd.reset(
            open(optarg, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644));
        if (!output_fd)
          PLOG(FATAL) << "Failed to open output file " << optarg
                      << " for writing";
        break;

      case kCloseStdoutWhenReady:
        close_stdout_when_ready = true;
        break;

      case kMapping: {
        auto tokens = StringSplit(optarg, ':');
        if (tokens.size() != 3) {
          ShowUsage(argv[0]);
          exit(1);
        }

        Mapping m;
        m.comm = tokens[0];
        char* end = nullptr;
        m.limit = strtoull(tokens[1].c_str(), &end, 10);
        if (*end != '\0') {
          ShowUsage(argv[0]);
          exit(1);
        }
        m.path = tokens[2];
        comm_mapping.emplace(m.comm, m);

        break;
      }

      case 'h':
      default:
        ShowUsage(argv[0]);
        return 0;
    }
  }
  if (optind == argc || (close_stdout_when_ready && !output_fd)) {
    ShowUsage(argv[0]);
    return 1;
  }

  ScopedFD server_sock(socket(AF_UNIX, SOCK_SEQPACKET, 0));
  if (!server_sock)
    PLOG(FATAL) << "Failed to create socket";

  struct sockaddr_un sun = {};
  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, argv[optind]);
  if (unlink(sun.sun_path) && errno != ENOENT)
    PLOG(FATAL) << "Failed to unlink previous socket";

  if (bind(server_sock.get(), reinterpret_cast<const struct sockaddr*>(&sun),
           sizeof(sun)) == -1) {
    PLOG(FATAL) << "Failed to bind socket";
  }

  if (listen(server_sock.get(), 16) == -1)
    PLOG(FATAL) << "Failed to listen for connections";

  ScopedFD epoll_fd(epoll_create1(EPOLL_CLOEXEC));
  if (!epoll_fd)
    PLOG(FATAL) << "Failed to create epoll fd";

  if (!AddToEpoll(epoll_fd.get(), server_sock.get()))
    PLOG(FATAL) << "Failed to add the server socket into epoll";

  sigset_t mask, old_mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);

  if (sigprocmask(SIG_BLOCK, &mask, &old_mask) == -1)
    PLOG(FATAL) << "Failed to block SIGINT";

  ScopedFD signal_fd(signalfd(-1, &mask, SFD_CLOEXEC));
  if (!signal_fd)
    PLOG(FATAL) << "Failed to create a signalfd";

  if (!AddToEpoll(epoll_fd.get(), signal_fd.get()))
    PLOG(FATAL) << "Failed to add signalfd into epoll";

  struct epoll_event events[128];
  bool running = true;

  char buffer[4096];
  char hdr_buffer[4096];
  struct msghdr msg = {};
  struct iovec iov = {};
  std::vector<std::unique_ptr<EpollData>> clients;

  while (running || !clients.empty()) {
    int nfds = HANDLE_EINTR(
        epoll_wait(epoll_fd.get(), events, array_length(events), -1));
    for (int i = 0; i < nfds; i++) {
      int fd = events[i].data.fd;
      if (fd == signal_fd.get()) {
        LOG(INFO) << "Received signal. Quitting";
        running = false;
      } else if (fd == server_sock.get()) {
        struct sockaddr_un client_addr = {};
        socklen_t client_addr_len = sizeof(client_addr);
        ScopedFD client(accept(server_sock.get(),
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &client_addr_len));
        if (!client) {
          PLOG(ERROR) << "Failed to accept new socket";
          continue;
        }
        int enabled = 1;
        if (setsockopt(client.get(), SOL_SOCKET, SO_TIMESTAMP, &enabled,
                       sizeof(enabled)) == -1) {
          PLOG(ERROR) << "Failed to set SO_TIMESTAMP";
        }
        struct ucred ucred = {};
        socklen_t ucred_len = sizeof(ucred);
        if (getsockopt(client.get(), SOL_SOCKET, SO_PEERCRED, &ucred,
                       &ucred_len) == -1) {
          PLOG(ERROR) << "Failed to get SO_PEERCRED";
        }
        if (shutdown(client.get(), SHUT_WR) == -1)
          PLOG(ERROR) << "Failed to shutdown writing to socket";

        auto client_data = std::make_unique<EpollData>(
            EpollData{++stream_counter, std::move(client),
                      GetProcessName(ucred.pid), false, 0, 0, ScopedFD{}});

        auto it = comm_mapping.find(client_data->comm);
        if (it != comm_mapping.end()) {
          auto path =
              StringPrintf("%s.%s", it->second.path.c_str(),
                           (it->second.open_fds % 2 == 0) ? "out" : "err");
          client_data->redirect_fd.reset(HANDLE_EINTR(open(
              path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644)));
          if (!client_data->redirect_fd)
            PLOG(ERROR) << "Failed to open redirect stream " << path;
          it->second.open_fds++;
          client_data->has_limit = true;
          client_data->limit = it->second.limit;
        } else {
          LOG(ERROR) << "Could not find a mapping for '" << client_data->comm
                     << "'";
        }

        if (!AddToEpoll(epoll_fd.get(), client_data.get())) {
          PLOG(ERROR) << "Failed to add client to epoll";
          continue;
        }
        if (!WriteMessage(output_fd ? output_fd.get() : STDOUT_FILENO,
                          client_data->stream_id, nullptr,
                          client_data->comm.data(), client_data->comm.size())) {
          PLOG(ERROR) << "Failed to write message";
        }
        clients.emplace_back(std::move(client_data));
      } else {
        auto client_data = reinterpret_cast<EpollData*>(events[i].data.ptr);

        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);
        if (client_data->has_limit && client_data->limit < sizeof(buffer))
          iov.iov_len = client_data->limit;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = hdr_buffer;
        msg.msg_controllen = sizeof(hdr_buffer);

        ssize_t read_bytes =
            HANDLE_EINTR(recvmsg(client_data->fd.get(), &msg, MSG_WAITALL));
        if (read_bytes <= 0) {
          if (read_bytes < 0)
            PLOG(ERROR) << "Failed to read from " << client_data->comm;
          if (!RemoveFromEpoll(epoll_fd.get(), client_data, &clients))
            PLOG(ERROR) << "Failed to remove client from epoll";
          break;
        }
        struct timeval timestamp = {};
        for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm != nullptr;
             cm = CMSG_NXTHDR(&msg, cm)) {
          if (SOL_SOCKET == cm->cmsg_level && SO_TIMESTAMP == cm->cmsg_type) {
            timestamp = *reinterpret_cast<const struct timeval*>(CMSG_DATA(cm));
          } else {
            LOG(INFO) << "ancillary message " << cm->cmsg_level << ", "
                      << cm->cmsg_type;
          }
        }
        if (!WriteMessage(output_fd ? output_fd.get() : STDOUT_FILENO,
                          client_data->stream_id, &timestamp, buffer,
                          read_bytes)) {
          PLOG(ERROR) << "Failed to write message";
        }
        if (client_data->redirect_fd &&
            !WriteFully(client_data->redirect_fd.get(), buffer, read_bytes)) {
          PLOG(ERROR) << "Failed to write to redirect fd";
        }
        if (client_data->has_limit) {
          client_data->limit -= read_bytes;
          if (client_data->limit == 0) {
            LOG(INFO) << "Output limit exceeded for " << client_data->comm;
            if (!RemoveFromEpoll(epoll_fd.get(), client_data, &clients)) {
              PLOG(ERROR) << "Failed to remove from epoll";
            }
            break;
          }
        }
      }
    }
  }

  unlink(sun.sun_path);
}
