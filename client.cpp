#include <iostream>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <algorithm>
#include <filesystem>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define BUFFER_SIZE 4096
#define DEFAULT_IP "127.0.0.1"

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

    ~Socket()
    {
        if (fd != -1)
        {
            close(fd);
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

    void connect(const struct sockaddr_in &addr)
    {
        int result = ::connect(
            fd,
            reinterpret_cast<const struct sockaddr *>(&addr),
            sizeof(addr));

        if (result == -1)
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "connection failed");
        }
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

    int result = inet_pton(AF_INET, ip, &addr.sin_addr);

    if (result <= 0)
    {
        if (result == 0)
        {
            throw std::invalid_argument(std::string("invalid ipv4: ") + ip);
        }
        else
        {
            throw std::system_error(
                errno,
                std::system_category(),
                "inet_pton failed");
        }
    }

    return addr;
}

std::string read_file(const std::string &filepath)
{
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);

    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open " + filepath);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string content(static_cast<size_t>(size), '\0');
    file.read(content.data(), size);

    return content;
}

namespace protocol
{

    struct file_request
    {
        uint32_t file_size;
        uint32_t filename_length;
        std::string filename;
        std::string content;

        std::string serialize() const
        {
            std::ostringstream oss(std::ios::binary);
            oss.write(reinterpret_cast<const char *>(&file_size), sizeof(file_size));

            oss.write(reinterpret_cast<const char *>(&filename_length), sizeof(filename_length));
            oss << filename << content;
            return oss.str();
        }
    };

    struct scan_result
    {
        bool is_clean;
        std::string message;
        std::vector<std::string> threats;

        bool parse(const std::string &data)
        {
            if (data.empty())
                return false;

            std::istringstream iss(data);
            std::string line;

            if (std::getline(iss, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                message = line;
                is_clean = (line == "clean");
            }

            while (std::getline(iss, line))
            {
                if (!line.empty())
                {
                    if (line.back() == '\r')
                        line.pop_back();
                    threats.push_back(line);
                }
            }
            return true;
        }
    };
}

class Client
{
    Socket socket;
    std::string server_ip;
    int server_port;
    bool connected;

public:
    Client(const std::string &ip, int port) : socket(), server_ip(ip), server_port(port), connected(false) {}

    bool connect()
    {
        std::cout << "connecting to " << server_ip << " through " << server_port << std::endl;
        sockaddr_in addr = make_server_address(server_ip.c_str(), server_port);
        socket.connect(addr);
        connected = true;
        std::cout << "connected" << std::endl;
        return true;
    }

    protocol::scan_result scan_file(const std::string &filepath)
    {
        if (!connected)
            throw std::runtime_error("not connected");

        std::cout << "reading file " << filepath << std::endl;

        std::string content = read_file(filepath);
        std::cout << "read" << std::endl;

        protocol::file_request request;
        request.file_size = static_cast<uint32_t>(content.size());

        request.filename = std::filesystem::path(filepath).filename().string();

        request.filename_length = static_cast<uint32_t>(request.filename.size());

        request.content = content;

        std::string data = request.serialize();
        std::cout << "sending" << std::endl;

        socket.send(data.c_str(), data.size());
        std::cout << "sent" << std::endl;

        std::vector<char> buffer(BUFFER_SIZE);
        int received = socket.recv(buffer.data(), buffer.size());

        if (received == 0)
        {
            throw std::runtime_error("server disconnected");
        }

        protocol::scan_result result;
        std::string response(buffer.begin(), buffer.begin() + received);
        result.parse(response);

        return result;
    }

    bool is_connected() const { return connected; }
};

struct Client_args
{
    std::string filepath;
    int port;
    bool valid;
    std::string error_msg;

    Client_args() : port(0), valid(false) {}
};

Client_args parse_args(const std::vector<std::string> &args)
{
    Client_args result;

    if (args.size() != 3)
    {
        result.error_msg = "client file port";
        return result;
    }

    result.filepath = args[1];

    if (!std::filesystem::exists(result.filepath))
    {
        result.error_msg = "file not found " + result.filepath;
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
    catch (const std::exception &)
    {
        result.error_msg = "invalid port " + args[2];
        return result;
    }

    result.valid = true;
    return result;
}

int main(int arg_count, char *arg_values[])
{

    std::vector<std::string> args(arg_values, arg_values + arg_count);

    Client_args parsed = parse_args(args);

    if (!parsed.valid)
    {
        std::cerr << parsed.error_msg << std::endl;
        std::cout << "user " << args[0] << std::endl;
        return 1;
    }

    try
    {
        Client client(DEFAULT_IP, parsed.port);
        client.connect();

        auto result = client.scan_file(parsed.filepath);

        std::cout << (result.is_clean ? "clean" : "threats found") << std::endl;
        std::cout << result.message << std::endl;

        if (!result.threats.empty())
        {
            for (const auto &threat : result.threats)
            {
                std::cout << threat << std::endl;
            }
        }

        return result.is_clean ? 0 : 1;
    }
    catch (const std::system_error &err)
    {
        std::cerr << "system error" << err.what() << std::endl;
        return 1;
    }
    catch (const std::exception &err)
    {
        std::cerr << "error" << err.what() << std::endl;
        return 1;
    }
}