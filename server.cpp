#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <cstring>
#include <map>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define BUFFER_SIZE 4096
constexpr const char *FIFO_REQUEST{"/tmp/stats_request_fifo"};
constexpr const char *FIFO_RESPONSE{"/tmp/stats_response_fifo"};

struct statistics
{
    uint32_t total_files = 0;
    uint32_t infected_files = 0;
    char patterns[10][64];
    uint32_t counts[10];
    int pattern_count;

    statistics() : total_files(0), infected_files(0), pattern_count(0)
    {
        memset(patterns, 0, sizeof(patterns));
        memset(counts, 0, sizeof(counts));
    }

    void add_file(bool is_infected, const std::vector<std::string> &found_patterns)
    {
        total_files++;
        if (is_infected)
        {
            infected_files++;
            for (const auto &pattern : found_patterns)
            {
                bool found = false;
                for (int i = 0; i < pattern_count; i++)
                {
                    if (strcmp(patterns[i], pattern.c_str()) == 0)
                    {
                        counts[i]++;
                        found = true;
                        break;
                    }
                }
                if (!found && pattern_count < 50)
                {
                    strncpy(patterns[pattern_count], pattern.c_str(), 63);
                    counts[pattern_count] = 1;
                    pattern_count++;
                }
            }
        }
    }

    std::string to_json() const
    {
        std::ostringstream oss;
        oss << "{\n";
        oss << " \"total_files\": " << total_files << ",\n";
        oss << " \"infected_files\": " << infected_files << ",\n";
        oss << " \"patterns\": {\n";

        bool first = true;
        for (int i = 0; i < pattern_count; i++)
        {
            if (!first)
                oss << ",\n";
            oss << "    \"" << patterns[i] << "\": " << counts[i];
            first = false;
        }
        oss << "\n  }\n}";
        return oss.str();
    }
};

statistics *g_stats = nullptr;

class Socket
{
    int fd;

public:
    Socket()
    {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (fd == -1)
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "failed to create socket");
        }
    }

    explicit Socket(int fd_) : fd(fd_) {}

    ~Socket()
    {
        if (fd != -1)
        {
            ::close(fd);
        }
    }

    Socket(const Socket &) = delete;

    Socket(Socket &&other) noexcept : fd(other.fd)
    {
        other.fd = -1;
    }

    Socket &operator=(Socket &&other) noexcept
    {
        if (this != &other)
        {
            if (fd != -1)
                close(fd);
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }

    int get_fd() const noexcept
    {
        return fd;
    }

    void set_reuse_addr()
    {
        int opt = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
        {
            throw std::system_error(errno, std::system_category(), "setsockopt failed");
        }
    }

    void bind(const struct sockaddr_in &addr)
    {
        int result = ::bind(fd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
        if (result == -1)
        {
            throw std::system_error(errno, std::system_category(), "bind failed");
        }
    }

    void listen(int backlog)
    {
        int result = ::listen(fd, backlog);
        if (result == -1)
        {
            throw std::system_error(errno, std::system_category(), "listen failed");
        }
    }

    Socket accept(struct sockaddr_in *client_addr, socklen_t *addr_len)
    {
        int client_fd = ::accept(fd, reinterpret_cast<struct sockaddr *>(client_addr), addr_len);
        if (client_fd == -1)
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "accept failed");
        }
        return Socket(client_fd);
    }

    int send(const char *buf, size_t len, int flags = 0)
    {

        int result = ::send(fd, buf, len, flags);

        if (result == -1)
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "send failed");
        }

        return result;
    }

    int recv(char *buf, size_t len, int flags = 0)
    {
        int result = ::recv(fd, buf, len, flags);

        if (result == -1)
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "recv failed");
        }
        return result;
    }
};

sockaddr_in make_server_address(const char *ip, int port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        throw std::invalid_argument("invalid ip " + std::string(ip));
    }
    return addr;
}

struct file_request
{
    uint32_t file_size = 0;
    uint32_t filename_length = 0;
    std::string filename;
    std::string content;

    bool deserialize(const std::string &data)
    {
        if (data.size() < 8)
            return false;
        size_t pos = 0;

        std::memcpy(&file_size, data.data() + pos, sizeof(file_size));
        pos += sizeof(file_size);

        std::memcpy(&filename_length, data.data() + pos, sizeof(filename_length));
        pos += sizeof(filename_length);

        if (data.size() < pos + file_size + filename_length)
            return false;

        filename = data.substr(pos, filename_length);
        pos += filename_length;

        content = data.substr(pos, file_size);
        return true;
    }
};

struct scan_result
{
    bool is_clean = true;
    std::string message = "clean";
    std::vector<std::string> threats;

    std::string serialize() const
    {
        std::ostringstream oss;
        oss << message << std::endl;
        for (const auto &threat : threats)
        {
            oss << threat << std::endl;
        }
        return oss.str();
    }
};

struct server_config
{
    std::vector<std::string> patterns;
    bool loaded = false;
    std::string error_msg;
};

server_config load_config(const std::string &filepath)
{
    server_config config;
    if (!std::filesystem::exists(filepath))
    {
        config.error_msg = "config not found " + filepath;
        return config;
    }

    std::ifstream file(filepath);
    if (!file)
    {
        config.error_msg = "file is not opened" + filepath;
        return config;
    }

    std::string content((std::istreambuf_iterator<char>(file)), {});

    size_t start = content.find("\"patterns\"");
    if (start == std::string::npos)
    {
        config.error_msg = "no patterns";
        return config;
    }

    size_t arr_start = content.find('[', start);
    size_t arr_end = content.find(']', arr_start);

    std::string arr = content.substr(arr_start + 1, arr_end - arr_start - 1);

    size_t pos = 0;
    while ((pos = arr.find('"', pos)) != std::string::npos)
    {
        size_t end = arr.find('"', pos + 1);
        std::string p = arr.substr(pos + 1, end - pos - 1);
        config.patterns.push_back(p);
        pos = end + 1;
    }

    config.loaded = !config.patterns.empty();
    return config;
}

struct server_args
{
    std::string config_path;
    int port = 0;
    bool valid = false;
    std::string error_msg;
};

server_args parse_args(const std::vector<std::string> &args)
{
    server_args result;

    if (args.size() != 3)
    {
        result.error_msg = "server config.json port";
        return result;
    }

    result.config_path = args[1];
    if (!std::filesystem::exists(result.config_path))
    {
        result.error_msg = "invalid config";
        return result;
    }

    try
    {
        result.port = std::stoi(args[2]);
        if (result.port < 1 || result.port > 65535)
        {
            result.error_msg = "invalid port";
            return result;
        }
    }
    catch (...)
    {
        result.error_msg = "invalid port";
        return result;
    }

    result.valid = true;
    return result;
}

scan_result scan_file(const std::string &content, const std::vector<std::string> &patterns)
{
    scan_result result;
    for (const auto &pattern : patterns)
    {
        if (content.find(pattern) != std::string::npos)
        {
            result.is_clean = false;
            result.message = "infected";
            result.threats.push_back(pattern);
        }
    }
    return result;
}

void handle_client(Socket client_socket, const server_config &config, const std::string &client_ip)
{
    try
    {
        std::cout << client_ip << " PID: " << getpid() << std::endl;

        std::string data;
        char buffer[BUFFER_SIZE];
        while (true)
        {
            int bytes = client_socket.recv(buffer, sizeof(buffer));
            if (bytes <= 0)
                break;
            data.append(buffer, bytes);

            if (data.size() >= 8)
            {
                uint32_t fs, fl;
                std::memcpy(&fs, data.data(), sizeof(fs));
                std::memcpy(&fl, data.data() + 4, sizeof(fl));
                if (data.size() >= 8 + fl + fs)
                    break;
            }
        }

        if (data.empty())
        {
            std::cout << "empty request" << std::endl;
            return;
        }

        file_request request;
        if (!request.deserialize(data))
        {
            std::cerr << "invalid request";
            scan_result err;
            err.is_clean = false;
            err.message = "invalid format";
            client_socket.send(err.serialize().c_str(), err.serialize().size());
            return;
        }

        scan_result result = scan_file(request.content, config.patterns);

        std::string response = result.serialize();
        client_socket.send(response.c_str(), response.size());

        g_stats->add_file(!result.is_clean, result.threats);

        std::cout << result.message << std::endl;
        if (!result.threats.empty())
        {
            std::cout << "threats: ";
            for (const auto &threat : result.threats)
                std::cout << threat << " ";
            std::cout << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "error: " << e.what() << std::endl;
    }
}

volatile sig_atomic_t g_running = true;
volatile sig_atomic_t g_children = 0;

void handleFIFO()
{
    mkfifo(FIFO_REQUEST, 0666);
    mkfifo(FIFO_RESPONSE, 0666);

    int req_fd = open(FIFO_REQUEST, O_RDONLY);
    if (req_fd == -1)
        return;

    while (g_running)
    {
        char buffer[64] = {};
        int bytes = read(req_fd, buffer, sizeof(buffer) - 1);
        if (bytes <= 0)
            continue;

        std::string request(buffer, bytes);
        if (request.find("GET_STATS") != std::string::npos)
        {
            int resp_fd = open(FIFO_RESPONSE, O_WRONLY);
            if (resp_fd != -1)
            {
                std::string json = g_stats->to_json();
                write(resp_fd, json.c_str(), json.size());
                close(resp_fd);
            }
        }
    }
    close(req_fd);
}

pid_t g_fifo_pid = 0;

void signal_handler(int sig)
{
    std::cout << "signal shutting down: " << sig << std::endl;
    g_running = false;
    if (g_fifo_pid > 0)
    {
        kill(g_fifo_pid, SIGTERM);
        g_fifo_pid = 0;
    }
}

void child_handler(int)
{
    while (waitpid(-1, nullptr, WNOHANG) > 0)
        g_children--;
}

int main(int arg_count, char *arg_values[])
{
    std::vector<std::string> args(arg_values, arg_values + arg_count);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGCHLD, child_handler);
    signal(SIGHUP, signal_handler);

    server_args parsed = parse_args(args);
    if (!parsed.valid)
    {
        std::cerr << "error: " << parsed.error_msg << std::endl;
        return 1;
    }

    int shm_fd = shm_open("/antivirus_stats", O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1)
    {
        std::cerr << "shm_open failed: " << strerror(errno) << std::endl;
        return 1;
    }

    if (ftruncate(shm_fd, sizeof(statistics)) == -1)
    {
        std::cerr << "ftruncate failed: " << strerror(errno) << std::endl;
        return 1;
    }

    g_stats = (statistics *)mmap(nullptr, sizeof(statistics),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (g_stats == MAP_FAILED)
    {
        std::cerr << "mmap failed: " << strerror(errno) << std::endl;
        return 1;
    }

    new (g_stats) statistics();

    server_config config = load_config(parsed.config_path);
    if (!config.loaded)
    {
        std::cerr << "error: " << config.error_msg << std::endl;
        return 1;
    }

    std::cout << "patterns loaded" << std::endl;

    try
    {
        Socket server;
        server.set_reuse_addr();
        server.bind(make_server_address("0.0.0.0", parsed.port));
        server.listen(SOMAXCONN);

        std::cout << "listening on 0.0.0.0:" << parsed.port << std::endl;
        std::cout << "PID: " << getpid() << std::endl
                  << std::endl;

        mkfifo(FIFO_REQUEST, 0666);
        mkfifo(FIFO_RESPONSE, 0666);
        int fifo_req_fd = open(FIFO_REQUEST, O_RDONLY | O_NONBLOCK);

        while (g_running)
        {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(server.get_fd(), &readfds);
            FD_SET(fifo_req_fd, &readfds);

            int max_fd = std::max(server.get_fd(), fifo_req_fd);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 10000;

            int ret = select(max_fd + 1, &readfds, nullptr, nullptr, &tv);

            if (ret > 0)
            {

                if (FD_ISSET(server.get_fd(), &readfds))
                {
                    sockaddr_in client_addr{};
                    socklen_t client_len = sizeof(client_addr);

                    Socket client;
                    try
                    {
                        client = server.accept(&client_addr, &client_len);
                    }
                    catch (...)
                    {
                        if (errno == EINTR)
                            continue;
                        throw;
                    }

                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
                    std::string client_ip(ip_str);

                    pid_t pid = fork();
                    if (pid < 0)
                    {
                        std::cerr << "fork() failed\n";
                        continue;
                    }

                    if (pid == 0)
                    {
                        std::cout << client_ip << " PID: " << getpid() << std::endl;
                        handle_client(std::move(client), config, client_ip);
                        exit(0);
                    }
                    else
                    {
                        g_children++;
                    }
                }

                if (FD_ISSET(fifo_req_fd, &readfds))
                {
                    char buffer[64] = {};
                    int n = read(fifo_req_fd, buffer, sizeof(buffer) - 1);
                    if (n > 0)
                    {
                        std::string request(buffer, n);
                        if (request.find("GET_STATS") != std::string::npos)
                        {
                            int resp_fd = open(FIFO_RESPONSE, O_WRONLY);
                            if (resp_fd != -1)
                            {
                                std::string json = g_stats->to_json();
                                write(resp_fd, json.c_str(), json.size());
                                close(resp_fd);
                            }
                        }
                    }
                }
            }
        }

        while (g_children > 0)
        {
            pid_t pid = waitpid(-1, nullptr, WNOHANG);
            if (pid > 0)
            {
                g_children--;
            }
            else
            {
                usleep(10000);
            }
        }

        close(fifo_req_fd);
        unlink(FIFO_REQUEST);
        unlink(FIFO_RESPONSE);

        std::cout << "final stats:" << std::endl;
        std::cout << g_stats->to_json() << std::endl;

        munmap(g_stats, sizeof(statistics));
        close(shm_fd);
        shm_unlink("/antivirus_stats");

        std::cout << "server stopped" << std::endl;

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}