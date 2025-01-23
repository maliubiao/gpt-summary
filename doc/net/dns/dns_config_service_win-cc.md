Response:
Let's break down the thought process for analyzing the given C++ code and generating the detailed explanation.

**1. Initial Understanding and Goal:**

The core request is to analyze `net/dns/dns_config_service_win.cc`. This immediately tells us it's a Chromium networking component specifically for Windows, dealing with DNS configuration. The key is to understand its functionalities, connections to JavaScript (if any), logical reasoning with examples, common user/programming errors, and how user actions lead to this code.

**2. High-Level Structure and Key Components:**

I first skimmed the code to get a general idea of its structure. I noticed the `#include` directives, namespace declarations (`net`, `net::internal`), and several classes like `RegistryWatcher`, `Watcher`, `ConfigReader`, and `HostsReader`. This suggests a modular design with specific responsibilities. The copyright notice and license information confirm it's part of Chromium.

**3. Functionality Identification - Top-Down and Bottom-Up:**

* **Top-Down (From Class Names and Overall Structure):**
    * `DnsConfigServiceWin`: This is the main class. It likely manages the overall process of getting DNS configuration. The name suggests it's a "service."
    * `Watcher`: This class probably monitors changes to the system's DNS configuration. The name suggests it's observing something.
    * `ConfigReader`: This class seems responsible for reading the DNS configuration. The name suggests it's reading settings.
    * `HostsReader`: This class likely reads the `hosts` file.
    * `RegistryWatcher`: This appears to be a helper class for watching specific registry keys.
    * Helper functions like `ParseDomainASCII`, `ParseSearchList`, `ConvertSettingsToDnsConfig`, `GetNameServers`, etc., perform specific parsing and conversion tasks.

* **Bottom-Up (From specific code snippets):**
    * Registry key paths (e.g., `kTcpipPath`, `kDnscachePath`):  This confirms interaction with the Windows Registry.
    * `GetAdaptersAddresses`:  This Windows API function is used to retrieve network adapter information, including DNS server addresses.
    * `GetHostsPath`:  This clearly points to the `hosts` file.
    * `NetworkChangeNotifier`: This indicates the code reacts to network changes.
    * Histograms (`base::UmaHistogramEnumeration`):  This shows metrics are being collected, likely for debugging and analysis.
    * `DnsConfig`: This structure (likely defined elsewhere) represents the collected DNS configuration.

Combining these perspectives, I could start forming a comprehensive list of functionalities.

**4. JavaScript Relationship:**

This required thinking about how Chromium's networking stack interacts with the browser's rendering engine (which runs JavaScript). The DNS configuration obtained by this C++ code directly influences how the browser resolves domain names. Therefore:

* **Direct Impact:** The fetched DNS settings are used when JavaScript code (e.g., through `fetch` or `XMLHttpRequest`) tries to access a website.
* **Example:**  A simple `fetch('https://www.example.com')` relies on the DNS configuration managed by this code to find the IP address of `www.example.com`.

**5. Logical Reasoning, Assumptions, and Examples:**

For each significant function or process, I considered:

* **Inputs:** What data does the function receive? (e.g., registry values, adapter information, content of the `hosts` file).
* **Processing:** What transformations or decisions are made? (e.g., parsing strings, filtering addresses, applying policy rules).
* **Outputs:** What is the result of the function? (e.g., a `DnsConfig` object, a list of IP addresses).

I then created simple "what if" scenarios to illustrate the logic:

* **`ConfigureSuffixSearch`:** What happens if the registry contains a specific search list? What if it's empty? What if there's a policy setting?
* **`ConvertSettingsToDnsConfig`:** What happens if no DNS servers are found? What if a VPN is active?
* **`AddLocalhostEntriesTo`:** What if the `hosts` file doesn't have entries for `localhost`?

**6. User and Programming Errors:**

I thought about common mistakes related to DNS configuration:

* **User Errors:**  Incorrect DNS server settings, typos in the `hosts` file, VPN interference.
* **Programming Errors:**  Not handling errors when reading the registry, assuming a specific registry key exists, incorrect parsing of configuration values.

**7. User Action Trace and Debugging:**

This required tracing the user's journey that eventually involves this code:

1. User enters a URL in the browser.
2. The browser needs to resolve the domain name.
3. The networking stack (including this code) is invoked to get the DNS configuration.
4. The DNS resolver uses this configuration to query DNS servers.

For debugging, I listed common steps like checking network settings, examining the `hosts` file, and using network diagnostic tools.

**8. Structure and Clarity:**

Finally, I organized the information logically using headings, bullet points, and code formatting to make it easy to read and understand. I made sure to address each part of the original request directly. I tried to use precise language while also explaining technical terms clearly.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this code directly interacts with JavaScript.
* **Correction:** Realized the interaction is indirect. The C++ code provides the *configuration*, which the browser's networking layer then *uses* when JavaScript makes network requests.
* **Initial thought:** Focus heavily on individual functions in isolation.
* **Refinement:**  Emphasized the overall flow and how the different components work together.
* **Initial thought:** Provide very technical explanations of each Windows API.
* **Refinement:**  Focused on the *purpose* of using those APIs rather than a deep dive into their intricacies. The target audience is likely interested in the higher-level functionality.

By following this systematic approach, I could generate a comprehensive and accurate explanation of the `dns_config_service_win.cc` file.
这个文件 `net/dns/dns_config_service_win.cc` 是 Chromium 网络栈中负责在 Windows 平台上获取和监控系统 DNS 配置的组件。它的主要功能是：

**1. 读取 Windows 系统 DNS 配置:**

*   **读取注册表:**  它读取 Windows 注册表中的多个键值，这些键值存储了 DNS 服务器地址、域名搜索列表、域名后缀、DNS 策略等信息。相关的注册表路径包括：
    *   `SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters`: 包含基本的 TCP/IP 配置，如 DNS 服务器、域名等。
    *   `SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters`: 包含 IPv6 相关的 TCP/IP 配置。
    *   `SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters`: 包含 DNS 缓存服务的配置，如域名 devolution 设置。
    *   `SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient`: 包含通过组策略设置的 DNS 客户端策略。
*   **使用 Windows API:**  它使用 `GetAdaptersAddresses` 等 Windows API 来获取网络适配器的详细信息，包括已配置的 DNS 服务器地址和连接特定的 DNS 后缀。
*   **读取 HOSTS 文件:** 它读取并解析系统 `hosts` 文件 (`drivers\\etc\\hosts`)，将主机名映射到 IP 地址。

**2. 监控 DNS 配置变化:**

*   **注册表监控:** 它使用 `RegistryWatcher` 类监控上述关键注册表路径的变化。当这些键值发生更改时，它会接收到通知。
*   **HOSTS 文件监控:** 它使用 `base::FilePathWatcher` 监控 `hosts` 文件的修改。
*   **网络状态变化监控:** 它作为 `NetworkChangeNotifier::IPAddressObserver` 监听网络接口的 IP 地址变化，这可能间接影响 DNS 配置。

**3. 将系统配置转换为 Chromium 内部的 `DnsConfig` 对象:**

*   它将从注册表、API 和 `hosts` 文件读取到的信息转换为 Chromium 网络栈内部使用的 `DnsConfig` 数据结构。这个结构包含了 DNS 服务器列表、域名搜索列表、ndots 值（在尝试使用搜索列表前需要包含的点号数量）等。

**4. 处理一些 Windows 特有的 DNS 配置和兼容性问题:**

*   它会检测一些可能与 Chromium DNS 解析不兼容的 Windows 配置，例如：
    *   名称解析策略 (NRPT)。
    *   使用了代理服务器。
    *   使用了 VPN 连接。
    *   适配器特定的 DNS 服务器设置。
*   对于检测到的不兼容情况，它会设置 `DnsConfig` 中的 `unhandled_options` 标志，以便 Chromium 的其他部分可以采取相应的措施。
*   它会尝试自动添加 `localhost` 和计算机名称到 `DnsHosts`，以确保即使 `hosts` 文件中没有这些条目，也能正确解析。

**与 JavaScript 功能的关系:**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它提供的 DNS 配置信息对于 JavaScript 在浏览器中的网络请求至关重要。

*   **域名解析:** 当 JavaScript 代码尝试访问一个域名（例如，使用 `fetch` API 或 `XMLHttpRequest`），浏览器需要将域名解析为 IP 地址。`DnsConfigServiceWin` 提供的 DNS 配置（包括 DNS 服务器地址和搜索列表）会直接影响浏览器的域名解析过程。
*   **HOSTS 文件覆盖:** 如果 `hosts` 文件中定义了某个域名的 IP 地址，JavaScript 发起的请求会直接连接到该 IP 地址，而不会查询 DNS 服务器。`DnsConfigServiceWin` 负责读取并提供 `hosts` 文件的信息。

**举例说明:**

假设 JavaScript 代码尝试访问 `www.example.com`。

1. 浏览器的网络栈需要解析 `www.example.com`。
2. `DnsConfigServiceWin` 已经从 Windows 系统读取了 DNS 配置，包括配置的 DNS 服务器地址（例如 `8.8.8.8` 和 `8.8.4.4`）以及可能的域名搜索列表（例如 `example.com`, `corp.example.com`）。
3. 如果 `hosts` 文件中没有 `www.example.com` 的条目，浏览器会使用 `DnsConfig` 中提供的 DNS 服务器地址向 DNS 服务器发送查询请求。
4. 如果配置了域名搜索列表，并且 `www` 不能直接解析，浏览器可能会尝试解析 `www.example.com`, `www.corp.example.com` 等。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

*   **注册表 `Tcpip\\Parameters\\NameServer`:** `"192.168.1.1,8.8.8.8"`
*   **注册表 `Tcpip\\Parameters\\SearchList`:** `"local.net,example.com"`
*   **HOSTS 文件:**
    ```
    127.0.0.1 localhost
    ```

**输出 1:**

*   `DnsConfig.nameservers`: `[{address: "192.168.1.1", port: 53}, {address: "8.8.8.8", port: 53}]`
*   `DnsConfig.search`: `["local.net", "example.com"]`
*   `DnsHosts`: `{{"localhost", ADDRESS_FAMILY_IPV4}: "127.0.0.1"}` (可能还包含 IPv6 的 localhost 条目和计算机名称的条目，取决于系统配置)

**假设输入 2:**

*   **注册表 `Tcpip\\Parameters\\NameServer`:** 空白
*   **注册表 `Tcpip\\Parameters\\SearchList`:** 空白
*   **HOSTS 文件:**
    ```
    127.0.0.1 localhost
    ::1 localhost
    192.168.10.10 mycomputer
    ```
*   **网络适配器配置:**  假设有一个活动的网络适配器，其 DNS 服务器配置为自动获取，并且 DHCP 服务器分配了 DNS 服务器 `10.0.0.1`。

**输出 2:**

*   `DnsConfig.nameservers`: `[{address: "10.0.0.1", port: 53}]` (从网络适配器获取)
*   `DnsConfig.search`: `[]`
*   `DnsHosts`: `{{"localhost", ADDRESS_FAMILY_IPV4}: "127.0.0.1", {"localhost", ADDRESS_FAMILY_IPV6}: "::1", {"mycomputer", ADDRESS_FAMILY_IPV4}: "192.168.10.10"}` (可能还包含 IPv6 的计算机名称条目)

**用户或编程常见的使用错误:**

*   **用户错误:**
    *   **手动配置错误的 DNS 服务器地址:** 用户可能在网络连接设置中输入了错误的 DNS 服务器 IP 地址，导致域名解析失败。
    *   **错误编辑 HOSTS 文件:** 用户可能在 `hosts` 文件中将域名映射到错误的 IP 地址，导致访问网站时连接到错误的服务器。例如，将 `www.google.com` 错误地指向本地回环地址。
    *   **VPN 连接问题:**  某些 VPN 连接可能会修改系统的 DNS 设置，导致 Chromium 的 DNS 解析行为异常。
*   **编程错误 (在 Chromium 开发中):**
    *   **未正确处理异步回调:**  读取注册表和网络适配器信息通常是异步操作，如果没有正确处理回调，可能会导致获取到的 DNS 配置不完整或过时。
    *   **假设特定的注册表键存在:** 代码需要处理某些注册表键不存在的情况，因为用户的系统配置可能不同。
    *   **忽略错误返回值:**  调用 Windows API 时，应该检查返回值以确保操作成功，并处理可能出现的错误情况。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户启动 Chromium 浏览器:**  在启动过程中，Chromium 的网络栈会初始化，并尝试获取系统的 DNS 配置。`DnsConfigServiceWin::ReadConfigNow()` 会被调用来立即读取配置。
2. **用户在地址栏输入一个域名并访问 (例如 `www.example.com`):**
    *   浏览器需要解析这个域名。
    *   Chromium 的 DNS 解析器会检查本地缓存和 `hosts` 文件。`DnsConfigServiceWin` 负责提供 `hosts` 文件的信息。
    *   如果域名不在缓存或 `hosts` 文件中，DNS 解析器会使用 `DnsConfigServiceWin` 提供的 DNS 服务器地址发起 DNS 查询。
3. **用户更改了网络连接设置 (例如，修改了 DNS 服务器地址):**
    *   Windows 系统会发出网络配置变化的通知。
    *   `NetworkChangeNotifier` 会接收到这个通知。
    *   `DnsConfigServiceWin::Watcher` 作为 `NetworkChangeNotifier::IPAddressObserver` 会收到通知，并触发重新读取 DNS 配置。
4. **用户修改了 HOSTS 文件:**
    *   `DnsConfigServiceWin::Watcher` 使用 `base::FilePathWatcher` 监控 `hosts` 文件。
    *   当 `hosts` 文件被修改时，`Watcher::OnHostsFilePathWatcherChange` 会被调用，并触发重新读取 `hosts` 文件。
5. **用户安装或卸载 VPN 软件:**
    *   VPN 软件的安装或卸载可能会修改系统的 DNS 设置和网络适配器配置。
    *   这会导致网络配置变化，从而触发 `DnsConfigServiceWin` 重新读取配置。

**调试线索:**

*   **检查网络连接设置:**  确认 Windows 系统中配置的 DNS 服务器地址是否正确。
*   **检查 HOSTS 文件:** 查看 `C:\Windows\System32\drivers\etc\hosts` 文件，确认其中是否存在与要访问的域名相关的条目，以及这些条目是否正确。
*   **使用 Chromium 的内部网络工具:**  在 Chromium 中访问 `chrome://net-internals/#dns` 可以查看 Chromium 当前使用的 DNS 配置、缓存以及 DNS 查询的详细信息。
*   **查看 Chromium 的日志:**  启用 Chromium 的网络日志 (通过命令行参数或环境变量)，可以查看 `DnsConfigServiceWin` 读取配置的详细过程和可能的错误信息。
*   **使用 Windows 的网络诊断工具:**  例如 `ipconfig /all` 命令可以查看当前网络适配器的 DNS 配置。`nslookup` 命令可以用来测试 DNS 解析。
*   **断点调试:**  对于 Chromium 的开发者，可以在 `DnsConfigServiceWin` 的关键函数中设置断点，例如在读取注册表、解析 `hosts` 文件或处理网络配置变化的回调函数中，来跟踪代码的执行流程和变量的值。

总而言之，`net/dns/dns_config_service_win.cc` 是 Chromium 在 Windows 平台上获取系统 DNS 配置的核心组件，它通过读取注册表、使用 Windows API 和监控文件变化来获取最新的 DNS 信息，并将其转换为 Chromium 可以使用的格式，从而保证浏览器能够正确地解析域名并建立网络连接。

### 提示词
```
这是目录为net/dns/dns_config_service_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_config_service_win.h"

#include <sysinfoapi.h>

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_path_watcher.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/free_deleter.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/ranges/algorithm.h"
#include "base/sequence_checker.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/types/expected.h"
#include "base/win/registry.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_types.h"
#include "net/base/ip_address.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/dns_hosts.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/serial_worker.h"
#include "url/url_canon.h"

namespace net {

namespace internal {

namespace {

// Registry key paths.
const wchar_t kTcpipPath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
const wchar_t kTcpip6Path[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters";
const wchar_t kDnscachePath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters";
const wchar_t kPolicyPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DnsWindowsCompatibility {
  kCompatible = 0,
  kIncompatibleResolutionPolicy = 1,
  kIncompatibleProxy = 1 << 1,
  kIncompatibleVpn = 1 << 2,
  kIncompatibleAdapterSpecificNameserver = 1 << 3,

  KAllIncompatibleFlags = (1 << 4) - 1,
  kMaxValue = KAllIncompatibleFlags
};

inline constexpr DnsWindowsCompatibility operator|(DnsWindowsCompatibility a,
                                                   DnsWindowsCompatibility b) {
  return static_cast<DnsWindowsCompatibility>(static_cast<int>(a) |
                                              static_cast<int>(b));
}

inline DnsWindowsCompatibility& operator|=(DnsWindowsCompatibility& a,
                                           DnsWindowsCompatibility b) {
  return a = a | b;
}

// Wrapper for GetAdaptersAddresses to get unicast addresses.
// Returns nullptr if failed.
std::unique_ptr<IP_ADAPTER_ADDRESSES, base::FreeDeleter>
ReadAdapterUnicastAddresses() {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  std::unique_ptr<IP_ADAPTER_ADDRESSES, base::FreeDeleter> out;
  ULONG len = 15000;  // As recommended by MSDN for GetAdaptersAddresses.
  UINT rv = ERROR_BUFFER_OVERFLOW;
  // Try up to three times.
  for (unsigned tries = 0; (tries < 3) && (rv == ERROR_BUFFER_OVERFLOW);
       tries++) {
    out.reset(static_cast<PIP_ADAPTER_ADDRESSES>(malloc(len)));
    memset(out.get(), 0, len);
    rv = GetAdaptersAddresses(AF_UNSPEC,
                              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER |
                              GAA_FLAG_SKIP_MULTICAST |
                              GAA_FLAG_SKIP_FRIENDLY_NAME,
                              nullptr, out.get(), &len);
  }
  if (rv != NO_ERROR)
    out.reset();
  return out;
}

// Default address of "localhost" and local computer name can be overridden
// by the HOSTS file, but if it's not there, then we need to fill it in.
bool AddLocalhostEntriesTo(DnsHosts& in_out_hosts) {
  IPAddress loopback_ipv4 = IPAddress::IPv4Localhost();
  IPAddress loopback_ipv6 = IPAddress::IPv6Localhost();

  // This does not override any pre-existing entries from the HOSTS file.
  in_out_hosts.emplace(DnsHostsKey("localhost", ADDRESS_FAMILY_IPV4),
                       loopback_ipv4);
  in_out_hosts.emplace(DnsHostsKey("localhost", ADDRESS_FAMILY_IPV6),
                       loopback_ipv6);

  wchar_t buffer[MAX_PATH];
  DWORD size = MAX_PATH;
  if (!GetComputerNameExW(ComputerNameDnsHostname, buffer, &size))
    return false;
  std::string localname = ParseDomainASCII(buffer);
  if (localname.empty())
    return false;
  localname = base::ToLowerASCII(localname);

  bool have_ipv4 =
      in_out_hosts.count(DnsHostsKey(localname, ADDRESS_FAMILY_IPV4)) > 0;
  bool have_ipv6 =
      in_out_hosts.count(DnsHostsKey(localname, ADDRESS_FAMILY_IPV6)) > 0;

  if (have_ipv4 && have_ipv6)
    return true;

  std::unique_ptr<IP_ADAPTER_ADDRESSES, base::FreeDeleter> addresses =
      ReadAdapterUnicastAddresses();
  if (!addresses.get())
    return false;

  // The order of adapters is the network binding order, so stick to the
  // first good adapter for each family.
  for (const IP_ADAPTER_ADDRESSES* adapter = addresses.get();
       adapter != nullptr && (!have_ipv4 || !have_ipv6);
       adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp)
      continue;
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;

    for (const IP_ADAPTER_UNICAST_ADDRESS* address =
             adapter->FirstUnicastAddress;
         address != nullptr; address = address->Next) {
      IPEndPoint ipe;
      if (!ipe.FromSockAddr(address->Address.lpSockaddr,
                            address->Address.iSockaddrLength)) {
        return false;
      }
      if (!have_ipv4 && (ipe.GetFamily() == ADDRESS_FAMILY_IPV4)) {
        have_ipv4 = true;
        in_out_hosts[DnsHostsKey(localname, ADDRESS_FAMILY_IPV4)] =
            ipe.address();
      } else if (!have_ipv6 && (ipe.GetFamily() == ADDRESS_FAMILY_IPV6)) {
        have_ipv6 = true;
        in_out_hosts[DnsHostsKey(localname, ADDRESS_FAMILY_IPV6)] =
            ipe.address();
      }
    }
  }
  return true;
}

// Watches a single registry key for changes.
class RegistryWatcher {
 public:
  typedef base::RepeatingCallback<void(bool succeeded)> CallbackType;
  RegistryWatcher() {}

  RegistryWatcher(const RegistryWatcher&) = delete;
  RegistryWatcher& operator=(const RegistryWatcher&) = delete;

  ~RegistryWatcher() { DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_); }

  bool Watch(const wchar_t key[], const CallbackType& callback) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK(!callback.is_null());
    DCHECK(callback_.is_null());
    callback_ = callback;
    if (key_.Open(HKEY_LOCAL_MACHINE, key, KEY_NOTIFY) != ERROR_SUCCESS)
      return false;

    return key_.StartWatching(base::BindOnce(&RegistryWatcher::OnObjectSignaled,
                                             base::Unretained(this)));
  }

  void OnObjectSignaled() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK(!callback_.is_null());
    if (key_.StartWatching(base::BindOnce(&RegistryWatcher::OnObjectSignaled,
                                          base::Unretained(this)))) {
      callback_.Run(true);
    } else {
      key_.Close();
      callback_.Run(false);
    }
  }

 private:
  CallbackType callback_;
  base::win::RegKey key_;

  SEQUENCE_CHECKER(sequence_checker_);
};

// Returns the path to the HOSTS file.
base::FilePath GetHostsPath() {
  wchar_t buffer[MAX_PATH];
  UINT rc = GetSystemDirectory(buffer, MAX_PATH);
  DCHECK(0 < rc && rc < MAX_PATH);
  return base::FilePath(buffer).Append(
      FILE_PATH_LITERAL("drivers\\etc\\hosts"));
}

void ConfigureSuffixSearch(const WinDnsSystemSettings& settings,
                           DnsConfig& in_out_config) {
  // SearchList takes precedence, so check it first.
  if (settings.policy_search_list.has_value()) {
    std::vector<std::string> search =
        ParseSearchList(settings.policy_search_list.value());
    if (!search.empty()) {
      in_out_config.search = std::move(search);
      return;
    }
    // Even if invalid, the policy disables the user-specified setting below.
  } else if (settings.tcpip_search_list.has_value()) {
    std::vector<std::string> search =
        ParseSearchList(settings.tcpip_search_list.value());
    if (!search.empty()) {
      in_out_config.search = std::move(search);
      return;
    }
  }

  // In absence of explicit search list, suffix search is:
  // [primary suffix, connection-specific suffix, devolution of primary suffix].
  // Primary suffix can be set by policy (primary_dns_suffix) or
  // user setting (tcpip_domain).
  //
  // The policy (primary_dns_suffix) can be edited via Group Policy Editor
  // (gpedit.msc) at Local Computer Policy => Computer Configuration
  // => Administrative Template => Network => DNS Client => Primary DNS Suffix.
  //
  // The user setting (tcpip_domain) can be configurred at Computer Name in
  // System Settings
  std::string primary_suffix;
  if (settings.primary_dns_suffix.has_value())
    primary_suffix = ParseDomainASCII(settings.primary_dns_suffix.value());
  if (primary_suffix.empty() && settings.tcpip_domain.has_value())
    primary_suffix = ParseDomainASCII(settings.tcpip_domain.value());
  if (primary_suffix.empty())
    return;  // No primary suffix, hence no devolution.
  // Primary suffix goes in front.
  in_out_config.search.insert(in_out_config.search.begin(), primary_suffix);

  // Devolution is determined by precedence: policy > dnscache > tcpip.
  // |enabled|: UseDomainNameDevolution and |level|: DomainNameDevolutionLevel
  // are overridden independently.
  WinDnsSystemSettings::DevolutionSetting devolution =
      settings.policy_devolution;

  if (!devolution.enabled.has_value())
    devolution.enabled = settings.dnscache_devolution.enabled;
  if (!devolution.enabled.has_value())
    devolution.enabled = settings.tcpip_devolution.enabled;
  if (devolution.enabled.has_value() && (devolution.enabled.value() == 0))
    return;  // Devolution disabled.

  // By default devolution is enabled.

  if (!devolution.level.has_value())
    devolution.level = settings.dnscache_devolution.level;
  if (!devolution.level.has_value())
    devolution.level = settings.tcpip_devolution.level;

  // After the recent update, Windows will try to determine a safe default
  // value by comparing the forest root domain (FRD) to the primary suffix.
  // See http://support.microsoft.com/kb/957579 for details.
  // For now, if the level is not set, we disable devolution, assuming that
  // we will fallback to the system getaddrinfo anyway. This might cause
  // performance loss for resolutions which depend on the system default
  // devolution setting.
  //
  // If the level is explicitly set below 2, devolution is disabled.
  if (!devolution.level.has_value() || devolution.level.value() < 2)
    return;  // Devolution disabled.

  // Devolve the primary suffix. This naive logic matches the observed
  // behavior (see also ParseSearchList). If a suffix is not valid, it will be
  // discarded when the fully-qualified name is converted to DNS format.

  unsigned num_dots = base::ranges::count(primary_suffix, '.');

  for (size_t offset = 0; num_dots >= devolution.level.value(); --num_dots) {
    offset = primary_suffix.find('.', offset + 1);
    in_out_config.search.push_back(primary_suffix.substr(offset + 1));
  }
}

std::optional<std::vector<IPEndPoint>> GetNameServers(
    const IP_ADAPTER_ADDRESSES* adapter) {
  std::vector<IPEndPoint> nameservers;
  for (const IP_ADAPTER_DNS_SERVER_ADDRESS* address =
           adapter->FirstDnsServerAddress;
       address != nullptr; address = address->Next) {
    IPEndPoint ipe;
    if (ipe.FromSockAddr(address->Address.lpSockaddr,
                         address->Address.iSockaddrLength)) {
      if (WinDnsSystemSettings::IsStatelessDiscoveryAddress(ipe.address()))
        continue;
      // Override unset port.
      if (!ipe.port())
        ipe = IPEndPoint(ipe.address(), dns_protocol::kDefaultPort);
      nameservers.push_back(ipe);
    } else {
      return std::nullopt;
    }
  }
  return nameservers;
}

bool CheckAndRecordCompatibility(bool have_name_resolution_policy,
                                 bool have_proxy,
                                 bool uses_vpn,
                                 bool has_adapter_specific_nameservers) {
  DnsWindowsCompatibility compatibility = DnsWindowsCompatibility::kCompatible;
  if (have_name_resolution_policy)
    compatibility |= DnsWindowsCompatibility::kIncompatibleResolutionPolicy;
  if (have_proxy)
    compatibility |= DnsWindowsCompatibility::kIncompatibleProxy;
  if (uses_vpn)
    compatibility |= DnsWindowsCompatibility::kIncompatibleVpn;
  if (has_adapter_specific_nameservers) {
    compatibility |=
        DnsWindowsCompatibility::kIncompatibleAdapterSpecificNameserver;
  }
  base::UmaHistogramEnumeration("Net.DNS.DnsConfig.Windows.Compatibility",
                                compatibility);
  return compatibility == DnsWindowsCompatibility::kCompatible;
}

}  // namespace

std::string ParseDomainASCII(std::wstring_view widestr) {
  if (widestr.empty())
    return "";

  // Check if already ASCII.
  if (base::IsStringASCII(base::AsStringPiece16(widestr))) {
    return std::string(widestr.begin(), widestr.end());
  }

  // Otherwise try to convert it from IDN to punycode.
  const int kInitialBufferSize = 256;
  url::RawCanonOutputT<char16_t, kInitialBufferSize> punycode;
  if (!url::IDNToASCII(base::AsStringPiece16(widestr), &punycode)) {
    return "";
  }

  // |punycode_output| should now be ASCII; convert it to a std::string.
  // (We could use UTF16ToASCII() instead, but that requires an extra string
  // copy. Since ASCII is a subset of UTF8 the following is equivalent).
  std::string converted;
  bool success =
      base::UTF16ToUTF8(punycode.data(), punycode.length(), &converted);
  DCHECK(success);
  DCHECK(base::IsStringASCII(converted));
  return converted;
}

std::vector<std::string> ParseSearchList(std::wstring_view value) {
  if (value.empty())
    return {};

  std::vector<std::string> output;

  // If the list includes an empty hostname (",," or ", ,"), it is terminated.
  // Although nslookup and network connection property tab ignore such
  // fragments ("a,b,,c" becomes ["a", "b", "c"]), our reference is getaddrinfo
  // (which sees ["a", "b"]). WMI queries also return a matching search list.
  for (std::wstring_view t : base::SplitStringPiece(
           value, L",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
    // Convert non-ASCII to punycode, although getaddrinfo does not properly
    // handle such suffixes.
    std::string parsed = ParseDomainASCII(t);
    if (parsed.empty())
      break;
    output.push_back(std::move(parsed));
  }
  return output;
}

base::expected<DnsConfig, ReadWinSystemDnsSettingsError>
ConvertSettingsToDnsConfig(
    const base::expected<WinDnsSystemSettings, ReadWinSystemDnsSettingsError>&
        settings_or_error) {
  if (!settings_or_error.has_value()) {
    return base::unexpected(settings_or_error.error());
  }
  const WinDnsSystemSettings& settings = *settings_or_error;
  bool uses_vpn = false;
  bool has_adapter_specific_nameservers = false;

  DnsConfig dns_config;

  std::set<IPEndPoint> previous_nameservers_set;

  // Use GetAdapterAddresses to get effective DNS server order and
  // connection-specific DNS suffix. Ignore disconnected and loopback adapters.
  // The order of adapters is the network binding order, so stick to the
  // first good adapter.
  for (const IP_ADAPTER_ADDRESSES* adapter = settings.addresses.get();
       adapter != nullptr; adapter = adapter->Next) {
    // Check each adapter for a VPN interface. Even if a single such interface
    // is present, treat this as an unhandled configuration.
    if (adapter->IfType == IF_TYPE_PPP) {
      uses_vpn = true;
    }

    std::optional<std::vector<IPEndPoint>> nameservers =
        GetNameServers(adapter);
    if (!nameservers) {
      return base::unexpected(
          ReadWinSystemDnsSettingsError::kGetNameServersFailed);
    }

    if (!nameservers->empty() && (adapter->OperStatus == IfOperStatusUp)) {
      // Check if the |adapter| has adapter specific nameservers.
      std::set<IPEndPoint> nameservers_set(nameservers->begin(),
                                           nameservers->end());
      if (!previous_nameservers_set.empty() &&
          (previous_nameservers_set != nameservers_set)) {
        has_adapter_specific_nameservers = true;
      }
      previous_nameservers_set = std::move(nameservers_set);
    }

    // Skip disconnected and loopback adapters. If a good configuration was
    // previously found, skip processing another adapter.
    if (adapter->OperStatus != IfOperStatusUp ||
        adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
        !dns_config.nameservers.empty())
      continue;

    dns_config.nameservers = std::move(*nameservers);

    // IP_ADAPTER_ADDRESSES in Vista+ has a search list at |FirstDnsSuffix|,
    // but it came up empty in all trials.
    // |DnsSuffix| stores the effective connection-specific suffix, which is
    // obtained via DHCP (regkey: Tcpip\Parameters\Interfaces\{XXX}\DhcpDomain)
    // or specified by the user (regkey: Tcpip\Parameters\Domain).
    std::string dns_suffix = ParseDomainASCII(adapter->DnsSuffix);
    if (!dns_suffix.empty())
      dns_config.search.push_back(std::move(dns_suffix));
  }

  if (dns_config.nameservers.empty()) {
    return base::unexpected(ReadWinSystemDnsSettingsError::kNoNameServerFound);
  }

  // Windows always tries a multi-label name "as is" before using suffixes.
  dns_config.ndots = 1;

  if (!settings.append_to_multi_label_name.has_value()) {
    dns_config.append_to_multi_label_name = false;
  } else {
    dns_config.append_to_multi_label_name =
        (settings.append_to_multi_label_name.value() != 0);
  }

  if (settings.have_name_resolution_policy) {
    // TODO(szym): only set this to true if NRPT has DirectAccess rules.
    dns_config.use_local_ipv6 = true;
  }

  if (!CheckAndRecordCompatibility(settings.have_name_resolution_policy,
                                   settings.have_proxy, uses_vpn,
                                   has_adapter_specific_nameservers)) {
    dns_config.unhandled_options = true;
  }

  ConfigureSuffixSearch(settings, dns_config);
  return dns_config;
}

// Watches registry and HOSTS file for changes. Must live on a sequence which
// allows IO.
class DnsConfigServiceWin::Watcher
    : public NetworkChangeNotifier::IPAddressObserver,
      public DnsConfigService::Watcher {
 public:
  explicit Watcher(DnsConfigServiceWin& service)
      : DnsConfigService::Watcher(service) {}

  Watcher(const Watcher&) = delete;
  Watcher& operator=(const Watcher&) = delete;

  ~Watcher() override { NetworkChangeNotifier::RemoveIPAddressObserver(this); }

  bool Watch() override {
    CheckOnCorrectSequence();

    RegistryWatcher::CallbackType callback =
        base::BindRepeating(&Watcher::OnConfigChanged, base::Unretained(this));

    bool success = true;

    // The Tcpip key must be present.
    if (!tcpip_watcher_.Watch(kTcpipPath, callback)) {
      LOG(ERROR) << "DNS registry watch failed to start.";
      success = false;
    }

    // Watch for IPv6 nameservers.
    tcpip6_watcher_.Watch(kTcpip6Path, callback);

    // DNS suffix search list and devolution can be configured via group
    // policy which sets this registry key. If the key is missing, the policy
    // does not apply, and the DNS client uses Tcpip and Dnscache settings.
    // If a policy is installed, DnsConfigService will need to be restarted.
    // BUG=99509

    dnscache_watcher_.Watch(kDnscachePath, callback);
    policy_watcher_.Watch(kPolicyPath, callback);

    if (!hosts_watcher_.Watch(
            GetHostsPath(), base::FilePathWatcher::Type::kNonRecursive,
            base::BindRepeating(&Watcher::OnHostsFilePathWatcherChange,
                                base::Unretained(this)))) {
      LOG(ERROR) << "DNS hosts watch failed to start.";
      success = false;
    } else {
      // Also need to observe changes to local non-loopback IP for DnsHosts.
      NetworkChangeNotifier::AddIPAddressObserver(this);
    }
    return success;
  }

 private:
  void OnHostsFilePathWatcherChange(const base::FilePath& path, bool error) {
    if (error)
      NetworkChangeNotifier::RemoveIPAddressObserver(this);
    OnHostsChanged(!error);
  }

  // NetworkChangeNotifier::IPAddressObserver:
  void OnIPAddressChanged() override {
    // Need to update non-loopback IP of local host.
    OnHostsChanged(true);
  }

  RegistryWatcher tcpip_watcher_;
  RegistryWatcher tcpip6_watcher_;
  RegistryWatcher dnscache_watcher_;
  RegistryWatcher policy_watcher_;
  base::FilePathWatcher hosts_watcher_;
};

// Reads config from registry and IpHelper. All work performed in ThreadPool.
class DnsConfigServiceWin::ConfigReader : public SerialWorker {
 public:
  explicit ConfigReader(DnsConfigServiceWin& service)
      : SerialWorker(/*max_number_of_retries=*/3), service_(&service) {}
  ~ConfigReader() override {}

  // SerialWorker::
  std::unique_ptr<SerialWorker::WorkItem> CreateWorkItem() override {
    return std::make_unique<WorkItem>();
  }

  bool OnWorkFinished(std::unique_ptr<SerialWorker::WorkItem>
                          serial_worker_work_item) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK(serial_worker_work_item);
    DCHECK(!IsCancelled());

    WorkItem* work_item = static_cast<WorkItem*>(serial_worker_work_item.get());
    base::UmaHistogramEnumeration(
        base::StrCat({"Net.DNS.DnsConfig.Windows.ReadSystemSettings",
                      base::NumberToString(GetFailureCount())}),
        work_item->dns_config_or_error_.has_value()
            ? ReadWinSystemDnsSettingsError::kOk
            : work_item->dns_config_or_error_.error());

    if (work_item->dns_config_or_error_.has_value()) {
      service_->OnConfigRead(
          std::move(work_item->dns_config_or_error_).value());
      return true;
    } else {
      LOG(WARNING) << "Failed to read DnsConfig.";
      return false;
    }
  }

 private:
  class WorkItem : public SerialWorker::WorkItem {
   public:
    ~WorkItem() override = default;

    void DoWork() override {
      dns_config_or_error_ =
          ConvertSettingsToDnsConfig(ReadWinSystemDnsSettings());
    }

   private:
    friend DnsConfigServiceWin::ConfigReader;
    base::expected<DnsConfig, ReadWinSystemDnsSettingsError>
        dns_config_or_error_;
  };

  raw_ptr<DnsConfigServiceWin> service_;
  // Written in DoWork(), read in OnWorkFinished(). No locking required.
};

// Extension of DnsConfigService::HostsReader that fills in localhost and local
// computer name if necessary.
class DnsConfigServiceWin::HostsReader : public DnsConfigService::HostsReader {
 public:
  explicit HostsReader(DnsConfigServiceWin& service)
      : DnsConfigService::HostsReader(GetHostsPath().value(), service) {}

  ~HostsReader() override = default;

  HostsReader(const HostsReader&) = delete;
  HostsReader& operator=(const HostsReader&) = delete;

  // SerialWorker:
  std::unique_ptr<SerialWorker::WorkItem> CreateWorkItem() override {
    return std::make_unique<WorkItem>(GetHostsPath());
  }

 private:
  class WorkItem : public DnsConfigService::HostsReader::WorkItem {
   public:
    explicit WorkItem(base::FilePath hosts_file_path)
        : DnsConfigService::HostsReader::WorkItem(
              std::make_unique<DnsHostsFileParser>(
                  std::move(hosts_file_path))) {}

    ~WorkItem() override = default;

    bool AddAdditionalHostsTo(DnsHosts& in_out_dns_hosts) override {
      base::ScopedBlockingCall scoped_blocking_call(
          FROM_HERE, base::BlockingType::MAY_BLOCK);
      return AddLocalhostEntriesTo(in_out_dns_hosts);
    }
  };
};

DnsConfigServiceWin::DnsConfigServiceWin()
    : DnsConfigService(GetHostsPath().value(),
                       std::nullopt /* config_change_delay */) {
  // Allow constructing on one sequence and living on another.
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

DnsConfigServiceWin::~DnsConfigServiceWin() {
  if (config_reader_)
    config_reader_->Cancel();
  if (hosts_reader_)
    hosts_reader_->Cancel();
}

void DnsConfigServiceWin::ReadConfigNow() {
  if (!config_reader_)
    config_reader_ = std::make_unique<ConfigReader>(*this);
  config_reader_->WorkNow();
}

void DnsConfigServiceWin::ReadHostsNow() {
  if (!hosts_reader_)
    hosts_reader_ = std::make_unique<HostsReader>(*this);
  hosts_reader_->WorkNow();
}

bool DnsConfigServiceWin::StartWatching() {
  DCHECK(!watcher_);
  // TODO(szym): re-start watcher if that makes sense. http://crbug.com/116139
  watcher_ = std::make_unique<Watcher>(*this);
  return watcher_->Watch();
}

}  // namespace internal

// static
std::unique_ptr<DnsConfigService> DnsConfigService::CreateSystemService() {
  return std::make_unique<internal::DnsConfigServiceWin>();
}

}  // namespace net
```