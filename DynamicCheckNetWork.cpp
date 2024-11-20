#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <wininet.h>
#include <wlanapi.h>
#include <sstream>
#include <vector>
#include <fstream>
#include <regex>
#include <ctime>
#include <iomanip>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wlanapi.lib")

std::atomic<bool> lastNetworkState(false);
std::string lastWiFiName = "N/A";
std::string lastAdapterInfo;
bool lastMessageSent = false;
// Function declaration
std::string executeCommand(const char* cmd);

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD request);
void monitorNetworkChanges(); // Assume this function is defined elsewhere

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    hStatus = RegisterServiceCtrlHandler(TEXT("DynamicCheckNetWork"), ServiceCtrlHandler);
    if (!hStatus) {
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(hStatus, &ServiceStatus);

    // Report running status
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    // Your service code
    monitorNetworkChanges();

    // Service cleanup
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    default:
        break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);
}
std::string getExecutablePath() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string::size_type pos = std::string(path).find_last_of("\\/");
    return std::string(path).substr(0, pos);
}
// Helper function to convert std::wstring to std::string
std::string wstringToString(const std::wstring& wstr) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string str(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], len, NULL, NULL);
    return str;
}

// Trim function for std::string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

void logOutputToFile(const std::string& output) {
    std::string logFilePath = getExecutablePath() + "\\log.txt";
    std::ofstream logFile(logFilePath, std::ios_base::app);
    if (logFile.is_open()) {
        // 获取当前时间
        std::time_t now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);

        // 格式化时间
        logFile << std::put_time(localTime, "[%Y-%m-%d %H:%M:%S] ") << output << std::endl;
        logFile.close();
    }
    else {
        std::cerr << "Unable to open log file: " << logFilePath << std::endl;
    }
}


// Function to get the current Wi-Fi name
std::string getWiFiName() {
    std::string output = executeCommand("netsh wlan show interfaces");
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("SSID") != std::string::npos) {
            size_t pos = line.find(":");
            if (pos != std::string::npos) {
                return trim(line.substr(pos + 1));
            }
        }
    }
    return "N/A";
}

// Function to check if the network is connected
bool isNetworkConnected() {
    DWORD flags = 0;
    return InternetGetConnectedState(&flags, 0);
}

// Function to check if a port is open
bool isPortOpen(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Use inet_pton instead of inet_addr
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    bool result = connect(sock, (SOCKADDR*)&addr, sizeof(addr)) != SOCKET_ERROR;
    closesocket(sock);
    WSACleanup();
    return result;
}

// Function to execute a command and return the output
std::string executeCommand(const char* cmd) {
    std::string result;

    // Create pipes for the process's stdin and stdout
    HANDLE hStdOutRead, hStdOutWrite;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0))
        return "ERROR";

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0))
        return "ERROR";

    // Set up the start up info struct.
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hStdOutWrite;
    si.hStdOutput = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Hide the window
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    // Create the child process.
    if (!CreateProcessA(NULL, const_cast<char*>(cmd), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdOutRead);
        return "ERROR";
    }

    // Close the write end of the pipe before reading from the read end of the pipe.
    CloseHandle(hStdOutWrite);

    // Read output from the child process's pipe for STDOUT
    char buffer[128];
    DWORD bytesRead;
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    // Cleanup
    CloseHandle(hStdOutRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}


// Function to check if an adapter is a virtual adapter
bool isVirtualAdapter(const std::string& name) {
    std::vector<std::string> virtualKeywords = { "Virtual", "TAP", "Hyper-V", "VMware", "VBox", "Microsoft" };
    for (const auto& keyword : virtualKeywords) {
        if (name.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Function to check if an adapter is a local adapter
bool isLocalAdapter(const std::string& name) {
    std::vector<std::string> localKeywords = { "Intel", "Realtek", "Broadcom", "Atheros", "Marvell", "Qualcomm" };
    for (const auto& keyword : localKeywords) {
        if (name.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Function to parse and validate IPv4 address using regex
std::string parseIPv4Address(const std::string& line) {
    std::regex ipRegex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    std::smatch match;
    if (std::regex_search(line, match, ipRegex)) {
        return match[0];
    }
    return "";
}

// Function to print adapter information
std::string getAdapterInfo() {
    std::string output = executeCommand("ipconfig /all");
    std::istringstream iss(output);
    std::string line;
    std::string currentAdapterName;
    std::string currentAdapterDescription;
    std::string currentIPAddress;
    std::string adapterInfo;

    while (std::getline(iss, line)) {
        // Check for new adapter section
        if (line.find("以太网适配器") != std::string::npos ||
            line.find("无线局域网适配器") != std::string::npos ||
            line.find("Ethernet adapter") != std::string::npos ||
            line.find("Wireless LAN adapter") != std::string::npos) {
            // Process the previous adapter if it exists and has a valid IP address
            if (!currentAdapterName.empty() && !currentIPAddress.empty()) {
                if (!isVirtualAdapter(currentAdapterDescription) && isLocalAdapter(currentAdapterDescription)) {
                    adapterInfo += "Adapter name: " + currentAdapterName + "\n";
                    adapterInfo += "Adapter description: " + currentAdapterDescription + "\n";
                    adapterInfo += "IP Address: " + currentIPAddress + "\n";
                    adapterInfo += "\n"; // Separate adapter information
                }
            }
            currentAdapterName.clear();
            currentAdapterDescription.clear();
            currentIPAddress.clear();
            currentAdapterName = trim(line.substr(line.find("适配器") + 6));
            if (currentAdapterName.empty()) {
                currentAdapterName = trim(line.substr(line.find("adapter") + 7));
            }
        }
        // Extract adapter description
        else if (line.find("描述") != std::string::npos ||
            line.find("Description") != std::string::npos) {
            currentAdapterDescription = trim(line.substr(line.find(":") + 2));
        }
        // Extract IP address
        else if (line.find("IPv4 地址") != std::string::npos ||
            line.find("IPv4 Address") != std::string::npos) {
            std::string ipAddress = parseIPv4Address(line);
            if (!ipAddress.empty()) {
                currentIPAddress = ipAddress;
            }
        }
    }

    // Process the last adapter if it exists and has a valid IP address
    if (!currentAdapterName.empty() && !currentIPAddress.empty() && !isVirtualAdapter(currentAdapterDescription) && isLocalAdapter(currentAdapterDescription)) {
        adapterInfo += "Adapter name: " + currentAdapterName + "\n";
        adapterInfo += "Adapter description: " + currentAdapterDescription + "\n";
        adapterInfo += "IP Address: " + currentIPAddress + "\n";
        adapterInfo += "\n"; // Separate adapter information
    }

    return adapterInfo;
}

// Function to send a webhook to DingTalk
void webhook(const std::string& message) {
    std::string webhookurl = "https://oapi.dingtalk.com/robot/send?access_token=Your_Token_Here";
    logOutputToFile(message);
    HINTERNET hInternet = InternetOpenA("WebhookClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::string errorMessage = "InternetOpenA failed with error: " + std::to_string(GetLastError());
        logOutputToFile(errorMessage);
        return;
    }

    HINTERNET hConnect = InternetConnectA(hInternet, "oapi.dingtalk.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        std::string errorMessage = "InternetConnectA failed with error: " + std::to_string(GetLastError());
        logOutputToFile(errorMessage);
        InternetCloseHandle(hInternet);
        return;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/robot/send?access_token=Your_Token_Here", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        std::string errorMessage = "HttpOpenRequestA failed with error: " + std::to_string(GetLastError());
        logOutputToFile(errorMessage);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    std::string json = "{\"msgtype\": \"text\", \"text\": {\"content\": \"" + message + "\"}}";
    const char* headers = "Content-Type: application/json";
    if (!HttpSendRequestA(hRequest, headers, -1, (LPVOID)json.c_str(), json.length())) {
        std::string errorMessage = "HttpSendRequestA failed with error: " + std::to_string(GetLastError());
        logOutputToFile(errorMessage);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // Read response
    char buffer[1024];
    DWORD bytesRead;
    std::string response;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response.append(buffer);
    }
    std::string errorMessage = "Server response: " + response;
    logOutputToFile(errorMessage);

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Main monitoring loop
void monitorNetworkChanges() {
    while (true) {
        std::string message;
        bool currentNetworkState = isNetworkConnected();
        std::string currentWiFiName = getWiFiName();
        std::string currentAdapterInfo = getAdapterInfo();

        if (currentNetworkState != lastNetworkState || currentWiFiName != lastWiFiName || currentAdapterInfo != lastAdapterInfo) {
            message += "Network state changed:\n";
            lastNetworkState = currentNetworkState;
            lastWiFiName = currentWiFiName;
            lastAdapterInfo = currentAdapterInfo;
            lastMessageSent = true; // Mark that a message was sent
        }
        else {
            message += "Network state unchanged:\n";
            lastMessageSent = false; // Reset the flag
        }

        message += "Current state: " + std::string(currentNetworkState ? "Connected" : "Disconnected") + "\n";
        

        if (currentNetworkState) {
            message += "Current WiFi Name: " + currentWiFiName + "\n";
            message += currentAdapterInfo;

            if (isPortOpen(3389)) {
                message += "Port 3389 Status: Open\n";
            }
            else {
                message += "Port 3389 Status: Closed\n";
            }
        }
        else {
            lastMessageSent = false;
        }
        if (lastMessageSent) {
             webhook(message);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { TEXT("DynamicCheckNetWork"), (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        logOutputToFile("Service failed to start");
        return -1;
    }
    else {
        logOutputToFile("Service Successful to start");
    }
    return 0;
}