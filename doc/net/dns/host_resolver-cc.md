Response:
Let's break down the thought process to analyze the `host_resolver.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to JavaScript, examples of logical reasoning, common user/programming errors, and debugging information.

2. **Initial Skim for High-Level Functionality:**  Quickly read through the file, paying attention to class names, function names, and included headers. Keywords like "HostResolver", "DNS", "ResolveHost", "Probe", "Cache", "AddressList", "Endpoint" immediately stand out. This suggests the file is responsible for resolving hostnames to IP addresses and related operations within the Chromium network stack.

3. **Identify Key Classes:** Note down the major classes defined: `HostResolver`, `ResolveHostRequest`, `ProbeRequest`, `ServiceEndpointRequest`, `Host`, `HttpsSvcbOptions`, `ManagerOptions`. These are the building blocks of the resolver functionality.

4. **Analyze Core Functionality - `ResolveHost` and `Probe`:**  The names `ResolveHostRequest` and `ProbeRequest` are self-explanatory. They represent requests to resolve a hostname and to probe network connectivity, respectively. Look for the `Start()` methods in the `FailingRequestImpl`. This class is a placeholder and helps understand the basic structure of these request objects. The `GetAddressResults()`, `GetEndpointResults()`, etc., indicate the types of data returned after a successful resolution.

5. **Examine Supporting Structures:**  `Host` encapsulates the hostname and potentially the scheme/port. `HttpsSvcbOptions` relates to the experimental HTTPS SVCB feature for optimized connection establishment. `ManagerOptions` likely controls the behavior of the underlying resolver manager.

6. **Look for Interactions with External Systems:** Headers like `<net/dns/...>`, `<net/base/...>`, and `#include "url/scheme_host_port.h"` indicate interaction with the DNS system, core networking concepts, and URL parsing. The `#if BUILDFLAG(IS_ANDROID)` section hints at platform-specific handling, likely related to Android's DNS resolution.

7. **Identify Potential JavaScript Relationship:**  Think about how JavaScript interacts with networking in a browser. JavaScript uses APIs like `fetch()` or `XMLHttpRequest` which ultimately need to resolve hostnames. The `HostResolver` is a core component in this process. The examples should focus on initiating network requests from JavaScript and how the browser's underlying resolver comes into play.

8. **Consider Logical Reasoning and Assumptions:**  Look for conditional logic and data transformations. The `EndpointResultToAddressList` function is a good example. It takes endpoint results and converts them into an `AddressList`. The assumption is that a "non-protocol" endpoint represents the basic IP address information. The `SquashErrorCode` function demonstrates a deliberate decision to map certain errors to `ERR_NAME_NOT_RESOLVED`.

9. **Think About User/Programming Errors:**  What mistakes could developers or users make that would involve the `HostResolver`?  Incorrect hostnames, network configuration issues, and reliance on specific DNS features that might be disabled are all possibilities.

10. **Trace User Actions to the `HostResolver`:**  Consider the steps a user takes to trigger hostname resolution. Typing a URL in the address bar, clicking a link, or a website making an API call all involve DNS resolution.

11. **Debugging Clues:**  Think about the information available within the `HostResolver` that would be helpful for debugging. Error codes, cached results, and configuration options are important.

12. **Structure the Answer:** Organize the findings into the requested categories: Functionality, JavaScript relationship, logical reasoning, user errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the detailed implementation within the `ContextHostResolver`. **Correction:** Realize the request is about `host_resolver.cc`, which is the abstract base class and factory. Shift focus to the broader responsibilities and interactions.
* **Initial thought:**  Directly link JavaScript code to C++ function calls. **Correction:**  Explain the *conceptual* relationship – JavaScript uses browser APIs that *internally* rely on the `HostResolver`.
* **Initial thought:**  Provide overly technical explanations of DNS concepts. **Correction:** Keep the explanations accessible and focus on the role of `host_resolver.cc`.
* **Initial thought:** Miss the significance of the `FailingRequestImpl`. **Correction:** Realize it's a crucial example for understanding the structure of request objects and use it to illustrate basic functionality.

By following these steps and being willing to refine the approach as needed, we can arrive at a comprehensive and accurate analysis of the `host_resolver.cc` file.
好的，让我们详细分析一下 `net/dns/host_resolver.cc` 文件的功能和相关方面。

**文件功能概述:**

`net/dns/host_resolver.cc` 文件是 Chromium 网络栈中 **主机名解析器 (Host Resolver)** 的核心实现。它的主要功能是将主机名（例如：`www.google.com`）解析为网络地址（例如：IPv4 地址 `172.217.160.142` 或 IPv6 地址 `2a00:1450:4001:81d::200e`）。  它抽象了底层的 DNS 查询过程，并提供了统一的接口供 Chromium 的其他网络组件使用。

更具体地说，这个文件定义了以下关键部分：

1. **`HostResolver` 类:**
   - 这是一个抽象基类，定义了主机名解析器的通用接口。
   - 声明了用于发起解析请求 (`ResolveHost`) 和探测网络连通性 (`Probe`) 的方法。
   - 定义了用于处理服务端点发现 (`ResolveServiceEndpoints`) 的方法。
   - 提供了获取主机缓存 (`GetHostCache`) 和 DNS 配置 (`GetDnsConfigAsValue`) 的方法。
   - 定义了嵌套类 `ResolveHostRequest`, `ProbeRequest`, `ServiceEndpointRequest` 等，用于表示不同的解析请求。
   - 定义了用于配置解析行为的结构体，如 `HttpsSvcbOptions` 和 `ManagerOptions`。

2. **`FailingRequestImpl` 类:**
   - 这是一个辅助类，用于创建总是立即失败的解析请求对象。这主要用于错误处理或测试场景。

3. **`FailingServiceEndpointRequestImpl` 类:**
   - 类似于 `FailingRequestImpl`，但专门用于创建总是失败的服务端点解析请求对象。

4. **静态工厂方法:**
   - 提供了创建不同类型的 `HostResolver` 实例的静态工厂方法，例如 `CreateResolver`, `CreateStandaloneResolver`, `CreateStandaloneContextResolver`, `CreateStandaloneNetworkBoundResolver`。这些方法允许根据不同的配置和环境创建合适的解析器。

5. **辅助函数:**
   - 包含一些辅助函数，例如：
     - `EndpointResultToAddressList`: 将服务端点解析结果转换为 `AddressList` 对象。
     - `ParametersToHostResolverFlags`: 将 `ResolveHostParameters` 转换为 `HostResolverFlags`。
     - `SquashErrorCode`: 将一些错误码映射到更通用的 `ERR_NAME_NOT_RESOLVED`。
     - `DnsQueryTypeSetToAddressFamily`: 根据 DNS 查询类型确定地址族。

**与 JavaScript 功能的关系:**

`net/dns/host_resolver.cc` 中的功能与 JavaScript 功能有着密切的关系，尽管 JavaScript 代码本身并不直接调用这个 C++ 文件中的函数。  当 JavaScript 代码发起网络请求时，例如通过以下方式：

* **`fetch()` API:** 这是现代 Web 开发中常用的发起 HTTP(S) 请求的 API。
* **`XMLHttpRequest` (XHR):**  较早期的 API，用于在不刷新页面的情况下与服务器交换数据。
* **`WebSocket`:** 用于建立持久的双向通信连接。
* **`navigator.sendBeacon()`:** 用于异步发送少量数据到 Web 服务器。

这些 JavaScript API 在底层都会调用 Chromium 浏览器内核的网络栈来处理网络请求。  **主机名解析是发起任何基于主机名的网络请求的第一步。**

**举例说明:**

假设你在 JavaScript 中使用 `fetch()` API 请求 `https://www.example.com/data`:

```javascript
fetch('https://www.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

当这段 JavaScript 代码执行时，以下步骤（简化版）会发生，其中会涉及到 `net/dns/host_resolver.cc` 的功能：

1. **JavaScript 发起请求:** `fetch()` 函数被调用，指定了目标 URL `https://www.example.com/data`。
2. **浏览器网络栈介入:**  浏览器内核的网络组件接收到这个请求。
3. **主机名解析:** 网络栈需要知道 `www.example.com` 对应的 IP 地址才能建立连接。  **这里就会调用 `HostResolver` 的 `ResolveHost` 方法 (或者其实现类的相应方法)。**
4. **DNS 查询:** `HostResolver` 内部会发起 DNS 查询，查找 `www.example.com` 的 IP 地址。这可能涉及到查询本地缓存、操作系统的 DNS 解析器、或者配置的 DNS 服务器。
5. **IP 地址返回:** DNS 查询成功后，`HostResolver` 会得到 `www.example.com` 的 IP 地址。
6. **建立连接:**  网络栈使用解析得到的 IP 地址与服务器建立 TCP 连接（如果是 HTTPS，还会进行 TLS 握手）。
7. **发送请求和接收响应:**  浏览器发送 HTTP 请求到服务器，并接收服务器的响应。
8. **JavaScript 处理响应:** `fetch()` API 的 Promise 会 resolve，JavaScript 代码可以处理从服务器返回的数据。

**逻辑推理的例子 (假设输入与输出):**

考虑 `EndpointResultToAddressList` 函数。

**假设输入:**

* `endpoints`: 一个包含 `HostResolverEndpointResult` 对象的 span，其中一个对象的 `ip_endpoints` 包含两个 `IPEndPoint`：`192.168.1.1:80` 和 `[::1]:8080`，并且该对象被 `EndpointResultIsNonProtocol` 判定为 true。
* `aliases`: 一个包含字符串 "alias1" 和 "alias2" 的 set。

**逻辑推理:**

函数会找到 `endpoints` 中 `EndpointResultIsNonProtocol` 返回 true 的那个元素。  然后，它会：

1. 将该元素的 `ip_endpoints` 赋值给 `AddressList` 的 endpoints。
2. 将 `aliases` set 中的字符串复制到一个新的 `std::vector<std::string>`。
3. 调用 `list.SetDnsAliases()` 将这个 vector 设置为 `AddressList` 的 DNS 别名。

**预期输出:**

一个 `AddressList` 对象，其中：

* `endpoints` 包含两个 `IPEndPoint` 对象：`192.168.1.1:80` 和 `[::1]:8080`。
* DNS 别名列表包含 "alias1" 和 "alias2"。

**用户或编程常见的使用错误举例:**

1. **配置了错误的 DNS 服务器:** 用户可能在其操作系统或浏览器中配置了无法正常工作的 DNS 服务器地址。这会导致 `HostResolver` 无法解析主机名，从而导致网络请求失败，通常会看到 `ERR_NAME_NOT_RESOLVED` 错误。

   **用户操作步骤:** 用户在操作系统网络设置中手动配置了错误的 DNS 服务器 IP 地址。当浏览器尝试访问一个网站时，`HostResolver` 使用这些错误的 DNS 服务器进行查询，结果查询失败。

2. **网络连接问题:**  用户的设备可能没有连接到互联网，或者网络连接不稳定。即使 DNS 配置正确，也无法进行 DNS 查询。

   **用户操作步骤:** 用户断开了 Wi-Fi 连接或网线连接。当浏览器尝试访问网站时，由于没有网络连接，DNS 查询无法发送或接收响应，导致解析失败。

3. **使用了不正确的或不存在的主机名:** 程序员在代码中使用了错误的域名或根本不存在的域名。

   **编程错误示例:**  JavaScript 代码中使用了错误的 URL：`fetch('https://www.exampllle.com/data')` (注意 `example` 被拼写错误)。 `HostResolver` 会尝试解析 `www.exampllle.com`，但由于该域名不存在或拼写错误，DNS 查询会失败。

4. **依赖于特定的 DNS 功能，但该功能未启用或配置错误:**  例如，程序员可能期望 HTTPS SVCB 记录能被解析，但相关的浏览器配置或 DNS 服务器不支持。

   **编程错误示例:** 代码期望通过 HTTPS SVCB 记录优化连接，但用户或网络环境禁用了该功能，导致连接建立过程并非最优。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户遇到了一个网站无法访问的问题，并且你想调试是否是 DNS 解析的问题。以下是可能到达 `net/dns/host_resolver.cc` 的调试线索：

1. **用户尝试访问网站:** 用户在浏览器地址栏输入 URL（例如 `https://www.example.com`）或点击了一个链接。
2. **浏览器发起请求:** 浏览器内核的网络栈开始处理该请求。
3. **主机名解析启动:** 网络栈发现需要解析 `www.example.com` 的 IP 地址。
4. **调用 `HostResolver`:** 网络栈会调用 `HostResolver` 接口的 `ResolveHost` 方法（或者其具体实现类的方法）。
5. **DNS 查询过程:** `HostResolver` 内部会执行 DNS 查询。

**调试线索:**

* **网络错误信息:** 浏览器可能会显示 `ERR_NAME_NOT_RESOLVED` 或类似的 DNS 解析错误。这表明问题可能出在 `HostResolver` 及其底层的 DNS 查询过程中。
* **Chrome 的 `net-internals` 工具 (`chrome://net-internals/#dns`):**  这个工具可以查看 Chromium 的 DNS 缓存、正在进行的 DNS 查询、以及查询历史。你可以查看是否成功解析了主机名，以及解析花费的时间。如果解析失败，可以看到错误信息。
* **抓包工具 (如 Wireshark):**  你可以使用抓包工具捕获网络数据包，查看 DNS 查询请求和响应，以确定 DNS 服务器是否返回了错误，或者是否存在网络通信问题。
* **断点调试:**  如果你有 Chromium 的源代码并进行本地编译，可以在 `net/dns/host_resolver.cc` 中的关键函数（例如 `ResolveHost` 的实现）设置断点，查看解析过程中的变量值和执行流程，从而深入了解问题所在。

总而言之，`net/dns/host_resolver.cc` 是 Chromium 网络栈中至关重要的组件，它负责将用户可读的主机名转换为计算机可识别的网络地址，是所有基于主机名的网络通信的基础。理解其功能有助于诊断和解决网络连接问题。

### 提示词
```
这是目录为net/dns/host_resolver.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/dns/host_resolver.h"

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time_delta_from_string.h"
#include "base/values.h"
#include "net/base/address_list.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/context_host_resolver.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/resolve_context.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#include "net/android/network_library.h"
#endif  // BUILDFLAG(IS_ANDROID)

namespace net {

namespace {

// The experiment settings of features::kUseDnsHttpsSvcb. See the comments in
// net/base/features.h for more details.
const char kUseDnsHttpsSvcbEnable[] = "enable";
const char kUseDnsHttpsSvcbInsecureExtraTimeMax[] = "insecure_extra_time_max";
const char kUseDnsHttpsSvcbInsecureExtraTimePercent[] =
    "insecure_extra_time_percent";
const char kUseDnsHttpsSvcbInsecureExtraTimeMin[] = "insecure_extra_time_min";
const char kUseDnsHttpsSvcbSecureExtraTimeMax[] = "secure_extra_time_max";
const char kUseDnsHttpsSvcbSecureExtraTimePercent[] =
    "secure_extra_time_percent";
const char kUseDnsHttpsSvcbSecureExtraTimeMin[] = "secure_extra_time_min";

// An implementation of HostResolver::{ResolveHost,Probe}Request that always
// fails immediately.
class FailingRequestImpl : public HostResolver::ResolveHostRequest,
                           public HostResolver::ProbeRequest {
 public:
  explicit FailingRequestImpl(int error) : error_(error) {}

  FailingRequestImpl(const FailingRequestImpl&) = delete;
  FailingRequestImpl& operator=(const FailingRequestImpl&) = delete;

  ~FailingRequestImpl() override = default;

  int Start(CompletionOnceCallback callback) override { return error_; }
  int Start() override { return error_; }

  AddressList* GetAddressResults() const override { return nullptr; }

  std::vector<HostResolverEndpointResult>* GetEndpointResults() const override {
    return nullptr;
  }

  const std::vector<std::string>* GetTextResults() const override {
    return nullptr;
  }

  const std::vector<HostPortPair>* GetHostnameResults() const override {
    return nullptr;
  }

  const std::set<std::string>* GetDnsAliasResults() const override {
    return nullptr;
  }

  ResolveErrorInfo GetResolveErrorInfo() const override {
    return ResolveErrorInfo(error_);
  }

  const std::optional<HostCache::EntryStaleness>& GetStaleInfo()
      const override {
    static const std::optional<HostCache::EntryStaleness> nullopt_result;
    return nullopt_result;
  }

 private:
  const int error_;
};

// Similar to FailingRequestImpl, but for ServiceEndpointRequest.
class FailingServiceEndpointRequestImpl
    : public HostResolver::ServiceEndpointRequest {
 public:
  explicit FailingServiceEndpointRequestImpl(int error) : error_(error) {}

  FailingServiceEndpointRequestImpl(const FailingServiceEndpointRequestImpl&) =
      delete;
  FailingServiceEndpointRequestImpl& operator=(
      const FailingServiceEndpointRequestImpl&) = delete;

  ~FailingServiceEndpointRequestImpl() override = default;

  int Start(Delegate* delegate) override { return error_; }

  const std::vector<ServiceEndpoint>& GetEndpointResults() override {
    static const base::NoDestructor<std::vector<ServiceEndpoint>> kEmptyResult;
    return *kEmptyResult.get();
  }

  const std::set<std::string>& GetDnsAliasResults() override {
    static const base::NoDestructor<std::set<std::string>> kEmptyResult;
    return *kEmptyResult.get();
  }

  bool EndpointsCryptoReady() override { return false; }

  ResolveErrorInfo GetResolveErrorInfo() override {
    return ResolveErrorInfo(error_);
  }

  void ChangeRequestPriority(RequestPriority priority) override {}

 private:
  const int error_;
};

bool EndpointResultIsNonProtocol(const HostResolverEndpointResult& result) {
  return result.metadata.supported_protocol_alpns.empty();
}

void GetTimeDeltaFromDictString(const base::Value::Dict& args,
                                std::string_view key,
                                base::TimeDelta* out) {
  const std::string* value_string = args.FindString(key);
  if (!value_string)
    return;
  *out = base::TimeDeltaFromString(*value_string).value_or(*out);
}

}  // namespace

HostResolver::Host::Host(absl::variant<url::SchemeHostPort, HostPortPair> host)
    : host_(std::move(host)) {
#if DCHECK_IS_ON()
  if (absl::holds_alternative<url::SchemeHostPort>(host_)) {
    DCHECK(absl::get<url::SchemeHostPort>(host_).IsValid());
  } else {
    DCHECK(absl::holds_alternative<HostPortPair>(host_));
    DCHECK(!absl::get<HostPortPair>(host_).IsEmpty());
  }
#endif  // DCHECK_IS_ON()
}

HostResolver::Host::~Host() = default;

HostResolver::Host::Host(const Host&) = default;

HostResolver::Host& HostResolver::Host::operator=(const Host&) = default;

HostResolver::Host::Host(Host&&) = default;

HostResolver::Host& HostResolver::Host::operator=(Host&&) = default;

bool HostResolver::Host::HasScheme() const {
  return absl::holds_alternative<url::SchemeHostPort>(host_);
}

const std::string& HostResolver::Host::GetScheme() const {
  DCHECK(absl::holds_alternative<url::SchemeHostPort>(host_));
  return absl::get<url::SchemeHostPort>(host_).scheme();
}

std::string HostResolver::Host::GetHostname() const {
  if (absl::holds_alternative<url::SchemeHostPort>(host_)) {
    return absl::get<url::SchemeHostPort>(host_).host();
  } else {
    DCHECK(absl::holds_alternative<HostPortPair>(host_));
    return absl::get<HostPortPair>(host_).HostForURL();
  }
}

std::string_view HostResolver::Host::GetHostnameWithoutBrackets() const {
  if (absl::holds_alternative<url::SchemeHostPort>(host_)) {
    std::string_view hostname = absl::get<url::SchemeHostPort>(host_).host();
    if (hostname.size() > 2 && hostname.front() == '[' &&
        hostname.back() == ']') {
      return hostname.substr(1, hostname.size() - 2);
    } else {
      return hostname;
    }
  } else {
    DCHECK(absl::holds_alternative<HostPortPair>(host_));
    return absl::get<HostPortPair>(host_).host();
  }
}

uint16_t HostResolver::Host::GetPort() const {
  if (absl::holds_alternative<url::SchemeHostPort>(host_)) {
    return absl::get<url::SchemeHostPort>(host_).port();
  } else {
    DCHECK(absl::holds_alternative<HostPortPair>(host_));
    return absl::get<HostPortPair>(host_).port();
  }
}

std::string HostResolver::Host::ToString() const {
  if (absl::holds_alternative<url::SchemeHostPort>(host_)) {
    return absl::get<url::SchemeHostPort>(host_).Serialize();
  } else {
    DCHECK(absl::holds_alternative<HostPortPair>(host_));
    return absl::get<HostPortPair>(host_).ToString();
  }
}

const url::SchemeHostPort& HostResolver::Host::AsSchemeHostPort() const {
  const url::SchemeHostPort* scheme_host_port =
      absl::get_if<url::SchemeHostPort>(&host_);
  DCHECK(scheme_host_port);
  return *scheme_host_port;
}

HostResolver::HttpsSvcbOptions::HttpsSvcbOptions() = default;

HostResolver::HttpsSvcbOptions::HttpsSvcbOptions(
    const HttpsSvcbOptions& other) = default;
HostResolver::HttpsSvcbOptions::HttpsSvcbOptions(HttpsSvcbOptions&& other) =
    default;

HostResolver::HttpsSvcbOptions::~HttpsSvcbOptions() = default;

// static
HostResolver::HttpsSvcbOptions HostResolver::HttpsSvcbOptions::FromDict(
    const base::Value::Dict& dict) {
  net::HostResolver::HttpsSvcbOptions options;
  options.enable =
      dict.FindBool(kUseDnsHttpsSvcbEnable).value_or(options.enable);
  GetTimeDeltaFromDictString(dict, kUseDnsHttpsSvcbInsecureExtraTimeMax,
                             &options.insecure_extra_time_max);

  options.insecure_extra_time_percent =
      dict.FindInt(kUseDnsHttpsSvcbInsecureExtraTimePercent)
          .value_or(options.insecure_extra_time_percent);
  GetTimeDeltaFromDictString(dict, kUseDnsHttpsSvcbInsecureExtraTimeMin,
                             &options.insecure_extra_time_min);

  GetTimeDeltaFromDictString(dict, kUseDnsHttpsSvcbSecureExtraTimeMax,
                             &options.secure_extra_time_max);

  options.secure_extra_time_percent =
      dict.FindInt(kUseDnsHttpsSvcbSecureExtraTimePercent)
          .value_or(options.secure_extra_time_percent);
  GetTimeDeltaFromDictString(dict, kUseDnsHttpsSvcbSecureExtraTimeMin,
                             &options.secure_extra_time_min);

  return options;
}

// static
HostResolver::HttpsSvcbOptions HostResolver::HttpsSvcbOptions::FromFeatures() {
  net::HostResolver::HttpsSvcbOptions options;
  options.enable = base::FeatureList::IsEnabled(features::kUseDnsHttpsSvcb);
  options.insecure_extra_time_max =
      features::kUseDnsHttpsSvcbInsecureExtraTimeMax.Get();
  options.insecure_extra_time_percent =
      features::kUseDnsHttpsSvcbInsecureExtraTimePercent.Get();
  options.insecure_extra_time_min =
      features::kUseDnsHttpsSvcbInsecureExtraTimeMin.Get();
  options.secure_extra_time_max =
      features::kUseDnsHttpsSvcbSecureExtraTimeMax.Get();
  options.secure_extra_time_percent =
      features::kUseDnsHttpsSvcbSecureExtraTimePercent.Get();
  options.secure_extra_time_min =
      features::kUseDnsHttpsSvcbSecureExtraTimeMin.Get();
  return options;
}

HostResolver::ManagerOptions::ManagerOptions() = default;

HostResolver::ManagerOptions::ManagerOptions(const ManagerOptions& other) =
    default;
HostResolver::ManagerOptions::ManagerOptions(ManagerOptions&& other) = default;

HostResolver::ManagerOptions::~ManagerOptions() = default;

const std::vector<bool>*
HostResolver::ResolveHostRequest::GetExperimentalResultsForTesting() const {
  NOTREACHED();
}

std::unique_ptr<HostResolver> HostResolver::Factory::CreateResolver(
    HostResolverManager* manager,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  return HostResolver::CreateResolver(manager, host_mapping_rules,
                                      enable_caching);
}

std::unique_ptr<HostResolver> HostResolver::Factory::CreateStandaloneResolver(
    NetLog* net_log,
    const ManagerOptions& options,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  return HostResolver::CreateStandaloneResolver(
      net_log, options, host_mapping_rules, enable_caching);
}

HostResolver::ResolveHostParameters::ResolveHostParameters() = default;

HostResolver::~HostResolver() = default;

std::unique_ptr<HostResolver::ProbeRequest>
HostResolver::CreateDohProbeRequest() {
  // Should be overridden in any HostResolver implementation where this method
  // may be called.
  NOTREACHED();
}

std::unique_ptr<HostResolver::MdnsListener> HostResolver::CreateMdnsListener(
    const HostPortPair& host,
    DnsQueryType query_type) {
  // Should be overridden in any HostResolver implementation where this method
  // may be called.
  NOTREACHED();
}

HostCache* HostResolver::GetHostCache() {
  return nullptr;
}

base::Value::Dict HostResolver::GetDnsConfigAsValue() const {
  return base::Value::Dict();
}

void HostResolver::SetRequestContext(URLRequestContext* request_context) {
  // Should be overridden in any HostResolver implementation where this method
  // may be called.
  NOTREACHED();
}

HostResolverManager* HostResolver::GetManagerForTesting() {
  // Should be overridden in any HostResolver implementation where this method
  // may be called.
  NOTREACHED();
}

const URLRequestContext* HostResolver::GetContextForTesting() const {
  // Should be overridden in any HostResolver implementation where this method
  // may be called.
  NOTREACHED();
}

handles::NetworkHandle HostResolver::GetTargetNetworkForTesting() const {
  return handles::kInvalidNetworkHandle;
}

// static
std::unique_ptr<HostResolver> HostResolver::CreateResolver(
    HostResolverManager* manager,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  DCHECK(manager);

  auto resolve_context = std::make_unique<ResolveContext>(
      nullptr /* url_request_context */, enable_caching);

  auto resolver = std::make_unique<ContextHostResolver>(
      manager, std::move(resolve_context));

  if (host_mapping_rules.empty())
    return resolver;
  auto remapped_resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver));
  remapped_resolver->SetRulesFromString(host_mapping_rules);
  return remapped_resolver;
}

// static
std::unique_ptr<HostResolver> HostResolver::CreateStandaloneResolver(
    NetLog* net_log,
    std::optional<ManagerOptions> options,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  std::unique_ptr<ContextHostResolver> resolver =
      CreateStandaloneContextResolver(net_log, std::move(options),
                                      enable_caching);

  if (host_mapping_rules.empty())
    return resolver;
  auto remapped_resolver =
      std::make_unique<MappedHostResolver>(std::move(resolver));
  remapped_resolver->SetRulesFromString(host_mapping_rules);
  return remapped_resolver;
}

// static
std::unique_ptr<ContextHostResolver>
HostResolver::CreateStandaloneContextResolver(
    NetLog* net_log,
    std::optional<ManagerOptions> options,
    bool enable_caching) {
  auto resolve_context = std::make_unique<ResolveContext>(
      nullptr /* url_request_context */, enable_caching);

  return std::make_unique<ContextHostResolver>(
      std::make_unique<HostResolverManager>(
          std::move(options).value_or(ManagerOptions()),
          NetworkChangeNotifier::GetSystemDnsConfigNotifier(), net_log),
      std::move(resolve_context));
}

// static
std::unique_ptr<HostResolver>
HostResolver::CreateStandaloneNetworkBoundResolver(
    NetLog* net_log,
    handles::NetworkHandle target_network,
    std::optional<ManagerOptions> options,
    std::string_view host_mapping_rules,
    bool enable_caching) {
#if BUILDFLAG(IS_ANDROID)
  // Note that the logic below uses Android APIs that don't work on a sandboxed
  // process: This is not problematic because this function is used only by
  // Cronet which doesn't enable sandboxing.

  auto resolve_context = std::make_unique<ResolveContext>(
      nullptr /*url_request_context */, enable_caching);
  auto manager_options = std::move(options).value_or(ManagerOptions());
  // Support the use of the built-in resolver when possible.
  bool is_builtin_resolver_supported =
      manager_options.insecure_dns_client_enabled &&
      base::android::BuildInfo::GetInstance()->sdk_int() >=
          base::android::SDK_VERSION_P;
  if (is_builtin_resolver_supported) {
    // Pre-existing DnsConfigOverrides is currently ignored, consider extending
    // if a use case arises.
    DCHECK(manager_options.dns_config_overrides == DnsConfigOverrides());

    std::vector<IPEndPoint> dns_servers;
    bool dns_over_tls_active;
    std::string dns_over_tls_hostname;
    std::vector<std::string> search_suffixes;
    if (android::GetDnsServersForNetwork(&dns_servers, &dns_over_tls_active,
                                         &dns_over_tls_hostname,
                                         &search_suffixes, target_network)) {
      DnsConfigOverrides dns_config_overrides =
          DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
      dns_config_overrides.nameservers = dns_servers;
      // Android APIs don't specify whether to use DoT or DoH. So, leave the
      // decision to `DnsConfig::allow_dns_over_https_upgrade` default value.
      dns_config_overrides.dns_over_tls_active = dns_over_tls_active;
      dns_config_overrides.dns_over_tls_hostname = dns_over_tls_hostname;
      dns_config_overrides.search = search_suffixes;

      manager_options.dns_config_overrides = dns_config_overrides;
      // Regardless of DoH vs DoT, the important contract to respect is not to
      // perform insecure DNS lookups if `dns_over_tls_active` == true.
      manager_options.additional_types_via_insecure_dns_enabled =
          !dns_over_tls_active;
    } else {
      // Disable when android::GetDnsServersForNetwork fails.
      is_builtin_resolver_supported = false;
    }
  }

  manager_options.insecure_dns_client_enabled = is_builtin_resolver_supported;
  return std::make_unique<ContextHostResolver>(
      HostResolverManager::CreateNetworkBoundHostResolverManager(
          manager_options, target_network, net_log),
      std::move(resolve_context));
#else   // !BUILDFLAG(IS_ANDROID)
  NOTIMPLEMENTED();
  return nullptr;
#endif  // BUILDFLAG(IS_ANDROID)
}

// static
AddressFamily HostResolver::DnsQueryTypeSetToAddressFamily(
    DnsQueryTypeSet dns_query_types) {
  DCHECK(HasAddressType(dns_query_types));
  // If the set of query types contains A and AAAA, defer the choice of address
  // family. Otherwise, pick the corresponding address family.
  if (dns_query_types.HasAll({DnsQueryType::A, DnsQueryType::AAAA}))
    return ADDRESS_FAMILY_UNSPECIFIED;
  if (dns_query_types.Has(DnsQueryType::AAAA))
    return ADDRESS_FAMILY_IPV6;
  DCHECK(dns_query_types.Has(DnsQueryType::A));
  return ADDRESS_FAMILY_IPV4;
}

// static
HostResolverFlags HostResolver::ParametersToHostResolverFlags(
    const ResolveHostParameters& parameters) {
  HostResolverFlags flags = 0;
  if (parameters.include_canonical_name)
    flags |= HOST_RESOLVER_CANONNAME;
  if (parameters.loopback_only)
    flags |= HOST_RESOLVER_LOOPBACK_ONLY;
  if (parameters.avoid_multicast_resolution)
    flags |= HOST_RESOLVER_AVOID_MULTICAST;
  return flags;
}

// static
int HostResolver::SquashErrorCode(int error) {
  // TODO(crbug.com/40668952): Consider squashing ERR_INTERNET_DISCONNECTED.
  if (error == OK || error == ERR_IO_PENDING ||
      error == ERR_INTERNET_DISCONNECTED || error == ERR_NAME_NOT_RESOLVED ||
      error == ERR_DNS_NAME_HTTPS_ONLY) {
    return error;
  } else {
    return ERR_NAME_NOT_RESOLVED;
  }
}

// static
AddressList HostResolver::EndpointResultToAddressList(
    base::span<const HostResolverEndpointResult> endpoints,
    const std::set<std::string>& aliases) {
  AddressList list;

  auto non_protocol_endpoint =
      base::ranges::find_if(endpoints, &EndpointResultIsNonProtocol);
  if (non_protocol_endpoint == endpoints.end())
    return list;

  list.endpoints() = non_protocol_endpoint->ip_endpoints;

  std::vector<std::string> aliases_vector(aliases.begin(), aliases.end());
  list.SetDnsAliases(std::move(aliases_vector));

  return list;
}

// static
bool HostResolver::MayUseNAT64ForIPv4Literal(HostResolverFlags flags,
                                             HostResolverSource source,
                                             const IPAddress& ip_address) {
  return !(flags & HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6) &&
         ip_address.IsValid() && ip_address.IsIPv4() &&
         (source != HostResolverSource::LOCAL_ONLY);
}

HostResolver::HostResolver() = default;

// static
std::unique_ptr<HostResolver::ResolveHostRequest>
HostResolver::CreateFailingRequest(int error) {
  return std::make_unique<FailingRequestImpl>(error);
}

// static
std::unique_ptr<HostResolver::ProbeRequest>
HostResolver::CreateFailingProbeRequest(int error) {
  return std::make_unique<FailingRequestImpl>(error);
}

// static
std::unique_ptr<HostResolver::ServiceEndpointRequest>
HostResolver::CreateFailingServiceEndpointRequest(int error) {
  return std::make_unique<FailingServiceEndpointRequestImpl>(error);
}

}  // namespace net
```