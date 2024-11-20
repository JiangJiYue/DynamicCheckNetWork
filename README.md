# 动态网络监控服务
动态网络监控服务是一个 Windows 服务应用程序，用于监控网络变化、WiFi连接和特定端口状态。它将信息记录到日志文件中，并在网络状态发生变化时通过钉钉发送通知。

## 功能
- 监控网络连接状态。
- 检查 Wi-Fi 网络连接的变化。
- 收集并记录网络适配器信息。
- 检查特定端口（如 3389 端口）是否开放。
- 通过钉钉 webhook 在网络状态变化时发送通知。

## 前提条件
- Windows 操作系统。
- Visual Studio 或其他 C++ 开发环境。
- 安装和管理 Windows 服务的权限（管理员权限）。
- [钉钉账号及 WebHook 的访问令牌。](https://fanyibo2009.github.io/2021/07/29/dingtalk_webhook/)

## 安装
1. **克隆仓库：**
    ```bash
     git clone <repository-url>
    ```
2. **构建项目：**
   在 Visual Studio 中打开项目并进行构建。确保所有必要的库（`iphlpapi.lib`, `ws2_32.lib`, `wininet.lib`, `wlanapi.lib`）已链接。
3. **注册服务：**
   以管理员权限打开命令提示符，并使用 `sc` 命令注册服务：
    ```bash
     sc create DynamicCheckNetWork binPath="C:\path\to\your\executable.exe"
    ```
4. **启动服务：**
   使用以下命令启动服务：
   ```bash
   sc start DynamicCheckNetWork
   ```
## 使用

服务启动后，它会持续监控网络状态。信息将记录在与可执行文件相同目录下的名为 `log.txt` 的文件中。当检测到变化时，它将使用配置的`WebHook URL`向钉钉发送通知。

### 配置

- 钉钉 Webhook URL:

  在源代码中更新 `webhookurl` 以包含您的钉钉访问令牌，以发送通知：

  ```cpp
  // 330行
  std::string webhookurl = "https://oapi.dingtalk.com/robot/send?access_token=Your_Token_Here";
  // 348行
  HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/robot/send?access_token=Your_Token_Here", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
  ```

解决方案属性可参考[CS-开发环境配置及exe处理](https://jiangjiyue.github.io/2024/10/28/ce454855/).

## 日志

日志存储在与服务可执行文件相同目录下的 `log.txt` 文件中：

- 日志文件将包含带时间戳的网络状态条目。
- 如果出现错误，例如无法连接到互联网或发送 WebHook，错误信息也会记录在日志中。

## 故障排除

- 确保服务具有运行和访问网络的适当权限。
- 验证钉钉 WebHook URL 是否配置正确。
- 如果服务无法启动，请检查 Windows 事件查看器中的错误信息。

**注意：** 该服务需要管理员权限进行安装和管理。确保您了解在系统上运行此类服务的安全影响。
