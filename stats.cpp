#include <iostream>
#include <string>
#include <iomanip>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

constexpr const char* FIFO_REQUEST {"/tmp/stats_request_fifo"};
constexpr const char* FIFO_RESPONSE {"/tmp/stats_response_fifo"};

int main() {
    
    if (access(FIFO_REQUEST, F_OK) != 0 || 
        access(FIFO_RESPONSE, F_OK) != 0) {
        std::cerr << "Server not running (FIFO not found)\n";
        return 1;
    }
    
    int req_fd = open(FIFO_REQUEST, O_WRONLY);
    if (req_fd == -1) {
        std::cerr << "Cannot open request FIFO\n";
        return 1;
    }
    write(req_fd, "GET_STATS", 9);
    close(req_fd);
    
    int resp_fd = open(FIFO_RESPONSE, O_RDONLY);
    if (resp_fd == -1) {
        std::cerr << "Cannot open response FIFO\n";
        return  1;
    }
    
    char buffer[4096] = {};
    int n = read(resp_fd, buffer, sizeof(buffer) - 1);
    close(resp_fd);
    
    if (n <= 0) {
        std::cerr << "No data received\n";
        return 1;
    }
    
    std::cout << "Statistics:\n\n";
    std::string json(buffer, n);
    
    auto getVal = [&](const std::string& key) -> std::string {
        std::string s = "\"" + key + "\":";
        size_t p = json.find(s);
        if (p == std::string::npos) return "N/A";
        p += s.length();
        while (p < json.size() && (json[p] == ' ' || json[p] == '\n')) p++;
        size_t e = json.find_first_of(",\n}", p);
        return json.substr(p, e - p);
    };
    

    std::cout << "checked: " <<  getVal("total_files") << std::endl;
    std::cout << "infected: " << getVal("infected_files") << std::endl;
    
    std::cout << "Patterns found:\n";
    size_t p = json.find("\"patterns\"");
    if (p != std::string::npos) {
        size_t start = json.find('{', p), end = json.find('}', start);
        std::string pat = json.substr(start, end - start + 1);
        size_t pos = 0;
        while ((pos = pat.find('"', pos)) != std::string::npos) {
            size_t ne = pat.find('"', pos + 1);
            if (ne == std::string::npos) break;
            std::string name = pat.substr(pos + 1, ne - pos - 1);
            size_t cpos = pat.find(':', ne);
            size_t cend = pat.find_first_of(",}", cpos);
            std::string cnt = pat.substr(cpos + 1, cend - cpos - 1);
            while (!cnt.empty() && (cnt.front() == ' ' || cnt.front() == '\n')) cnt.erase(0, 1);
            std::cout << "  • " << name << ": " << cnt << "\n";
            pos = cend + 1;
        }
    }
    
    std::cout << "\n";
    return 0;
}