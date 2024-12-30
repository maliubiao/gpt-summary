Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive response.

**1. Initial Understanding and Goal:**

The first step is to understand the purpose of the file. The filename `host_resolver_system_task.cc` and the surrounding namespace `net::dns` immediately suggest this file is part of the Chromium networking stack and deals with resolving hostnames using the operating system's underlying DNS mechanisms. The goal is to analyze its functionalities, identify connections to JavaScript (if any), explore logical reasoning within, pinpoint potential user/programming errors, and trace how user actions might lead to this code being executed.

**2. Deconstructing the Code:**

Next, I'd go through the code section by section, paying attention to key components:

* **Includes:** These reveal the dependencies and related functionalities. Seeing includes like `<memory>`, `<utility>`, `<vector>`, `base/`, `net/base/`, `net/dns/` confirms this is core networking logic. Specific includes like `net/base/features.h` and `net/dns/public/host_resolver_source.h` hint at feature flags and the source of resolution requests.
* **Namespaces:** `net` confirms the general area. The anonymous namespace contains helper functions, keeping the main namespace clean.
* **Constants:** `kTtl` suggests a caching mechanism.
* **Global Variables/Functions:**  `GetSystemDnsResolutionTaskRunnerOverride`, `GetSystemDnsResolverOverride`, `SetSystemDnsResolverOverride`, and `SystemHostResolverCall` are clearly important for customization and core resolution.
* **Class `HostResolverSystemTask`:** This is the central class. I'd examine its members (private and public), constructors, destructor, and methods like `Start`, `StartLookupAttempt`, `OnLookupComplete`, `MaybeCacheResults`, `CacheEndpoints`, and `CacheAlias`. The names suggest the lifecycle of a DNS resolution attempt.
* **Helper Functions:**  `ResolveOnWorkerThread`, `NetLogHostResolverSystemTaskFailedParams`, `AddressFamilyToAF`.
* **Platform-Specific Code:** The `#if BUILDFLAG(IS_WIN)` and `#elif BUILDFLAG(IS_POSIX)` blocks indicate platform differences in how DNS resolution is handled.

**3. Identifying Core Functionalities:**

Based on the code structure and names, I would identify the key functionalities:

* **Initiating System DNS Resolution:** The `Start` and `StartLookupAttempt` methods, along with the interaction with `PostSystemDnsResolutionTaskAndReply`, are clearly responsible for kicking off the DNS query using the OS.
* **Asynchronous Operations:** The use of `base::OnceCallback`, `base::BindOnce`, `base::ThreadPool::PostTaskAndReplyWithResult`, and `weak_ptr_factory_` indicates asynchronous operations and the need for cancellation management.
* **Retries:** The `attempt_number_` and `params_.max_retry_attempts` suggest a retry mechanism for unreliable DNS resolution.
* **Caching:** The `MaybeCacheResults`, `CacheEndpoints`, and `CacheAlias` methods, coupled with the `cache_params_` member and the inclusion of `net/dns/host_resolver_cache.h`, confirm a caching layer.
* **Net Logging:**  The `net_log_` member and the calls to `BeginEvent`, `EndEvent`, and `AddEventWithIntParams` indicate the integration with Chromium's network logging system for debugging and monitoring.
* **Overrides/Customization:**  The `SystemDnsResolverOverrideCallback` and related functions allow for intercepting and overriding the default system DNS resolution process (primarily for testing).
* **Error Handling:** The checks for errors and the logging of `net_error` and `os_error` are essential for robust operation.
* **Platform Abstraction:** `SystemHostResolverCall` serves as an abstraction over the platform-specific `getaddrinfo` (or equivalent) calls.

**4. Examining Relationships with JavaScript:**

This requires understanding how Chromium's networking stack interacts with the rendering engine (Blink), which executes JavaScript. The key connection points are:

* **`fetch()` API:** The most direct link. JavaScript's `fetch()` API (or `XMLHttpRequest`) triggers network requests, which eventually lead to hostname resolution.
* **Navigation:** When a user enters a URL in the address bar, the browser needs to resolve the hostname to connect to the server.
* **WebSockets:**  Establishing a WebSocket connection also involves resolving the hostname.
* **WebRTC:** Peer-to-peer connections often rely on DNS resolution to find other peers.

I'd explain how these JavaScript functionalities initiate network requests, which then utilize the C++ networking stack, including the `HostResolverSystemTask`.

**5. Logical Reasoning and Examples:**

This involves tracing the flow of execution within the `HostResolverSystemTask`.

* **Assumptions:** A hostname to resolve, the desired address family, and potentially some resolver flags.
* **Input:** A hostname string (e.g., "www.example.com"), `ADDRESS_FAMILY_IPV4`, and no special flags.
* **Steps:**  `Start` -> `StartLookupAttempt` -> `PostSystemDnsResolutionTaskAndReply` (or the override) -> worker thread calls `ResolveOnWorkerThread` (which calls `SystemHostResolverCall` or the overridden proc) -> system's DNS resolution -> `OnLookupComplete` -> `MaybeCacheResults` -> results are returned via the callback.
* **Output:** An `AddressList` containing the IP addresses for the hostname, a potential OS error code, and a net error code.

I would provide an example with successful resolution and another with a failure (e.g., non-existent domain).

**6. Identifying Potential User/Programming Errors:**

This requires considering common mistakes and edge cases.

* **Invalid Hostnames:** Users might enter typos or invalid domain names.
* **Network Connectivity Issues:** The user might be offline or have a faulty network connection.
* **Firewall Restrictions:** The firewall might block DNS queries.
* **Incorrect DNS Configuration:** The user's DNS settings might be wrong.
* **Programming Errors:** Using incorrect flags, not handling errors properly, or misconfiguring the resolver.

I'd illustrate these with examples.

**7. Tracing User Actions:**

This connects the high-level user actions to the low-level code execution. I'd provide a step-by-step breakdown:

* User types "www.example.com" in the address bar.
* Browser initiates a navigation.
* The networking stack needs to resolve "www.example.com".
* A `HostResolverImpl` (or similar) creates a `HostResolverSystemTask`.
* The `Start` method of the `HostResolverSystemTask` is called.
* The code execution flow continues as described in the "Logical Reasoning" section.

**8. Refinement and Structure:**

Finally, I would organize the information logically, using clear headings and bullet points for readability. I'd ensure the language is precise and avoids jargon where possible. I'd review the response to make sure it addresses all aspects of the prompt.

This systematic approach helps to thoroughly analyze the code, connect it to relevant concepts, and generate a comprehensive and informative response.
这个文件 `net/dns/host_resolver_system_task.cc` 是 Chromium 网络栈中负责使用操作系统底层 DNS 解析机制来解析主机名的核心组件。 它的主要功能是创建一个任务，该任务会在后台线程中执行系统级别的 DNS 查询，并将结果返回给调用者。

以下是其功能的详细列表：

**主要功能:**

1. **发起系统 DNS 查询:**  该类封装了一个特定主机名的 DNS 查询请求，并使用操作系统的 `getaddrinfo` (或 Windows 上的类似 API) 来执行实际的解析。
2. **异步执行:** DNS 查询在后台线程池中执行，避免阻塞主线程，从而保证浏览器界面的响应性。
3. **重试机制:**  如果 DNS 查询在一定时间内没有响应，该类可以配置为重试多次。重试的延迟可以通过参数进行调整。
4. **结果回调:**  一旦 DNS 查询完成（成功或失败），结果（IP 地址列表、错误码等）会通过回调函数返回给调用者。
5. **缓存交互 (可选):**  如果创建 `HostResolverSystemTask` 时提供了 `CacheParams`，则在 DNS 查询成功后，会将结果缓存到 `HostResolverCache` 中，以加速后续相同主机名的解析。
6. **NetLog 集成:**  该类集成了 Chromium 的 NetLog 系统，用于记录 DNS 查询的详细信息，包括开始、结束、重试、成功和失败等事件，方便调试和性能分析。
7. **网络隔离 (Network Isolation):**  可以指定在哪个网络句柄上执行 DNS 查询，这对于处理多网络接口或网络命名空间的情况很有用。
8. **覆盖机制 (Override):** 提供了覆盖系统 DNS 解析行为的机制，主要用于测试目的。

**与 JavaScript 的关系:**

`net/dns/host_resolver_system_task.cc` 本身不直接包含任何 JavaScript 代码，它是一个纯粹的 C++ 文件。然而，它的功能对于 JavaScript 在浏览器中的网络请求至关重要。 当 JavaScript 代码发起一个网络请求（例如使用 `fetch()` API 或 `XMLHttpRequest`），浏览器需要将主机名解析为 IP 地址才能建立连接。  这个解析过程会间接地涉及到 `HostResolverSystemTask`。

**举例说明:**

1. **用户在地址栏输入 URL:** 当用户在浏览器的地址栏中输入一个 URL（例如 `www.example.com`）并按下回车键，浏览器需要解析 `www.example.com` 这个主机名。
2. **JavaScript 发起 `fetch()` 请求:**  一个网页中的 JavaScript 代码可能使用 `fetch('https://api.example.com/data')` 发起一个请求。浏览器需要解析 `api.example.com`。

在这些场景下，浏览器网络栈会创建并执行 `HostResolverSystemTask` 来完成主机名到 IP 地址的转换。  JavaScript 代码本身并不直接调用 `HostResolverSystemTask` 的方法，而是通过浏览器提供的更高级别的 API（例如 `fetch()` 的实现）来触发这个过程。

**逻辑推理与假设输入输出:**

假设我们创建一个 `HostResolverSystemTask` 来解析主机名 "www.google.com"，并且网络连接正常。

**假设输入:**

* `hostname_`: "www.google.com"
* `address_family_`: `ADDRESS_FAMILY_IPV4` (假设只请求 IPv4 地址)
* `flags_`: 0 (没有特殊标志)
* `params_`: 使用默认参数
* 网络连接正常

**逻辑推理步骤:**

1. `Start()` 方法被调用，开始 DNS 解析任务。
2. `StartLookupAttempt()` 方法被调用，发起第一次解析尝试。
3. `PostSystemDnsResolutionTaskAndReply()` 将一个任务发布到后台线程池。
4. 后台线程执行 `ResolveOnWorkerThread()`，最终调用操作系统的 `getaddrinfo("www.google.com", AF_INET, ...)`。
5. 操作系统 DNS 解析器查询 DNS 服务器，获取 "www.google.com" 的 IPv4 地址。
6. `OnLookupComplete()` 方法在主线程被调用，接收到解析结果。
7. 如果解析成功，`results` 参数包含 `www.google.com` 的 IPv4 地址列表， `error` 为 `OK`， `os_error` 为 0。
8. `MaybeCacheResults()` 会将结果缓存到 `HostResolverCache` 中 (如果提供了 `CacheParams`)。
9. `results_cb_` 回调函数被执行，将解析结果传递给调用者。

**假设输出 (成功情况):**

* `results`:  包含一个或多个 `IPEndPoint` 对象，例如 `[216.58.212.142:0]`
* `os_error`: 0
* `error`: `net::OK` (0)

**假设输入 (失败情况):**

* `hostname_`: "nonexistent.example.com"
* 其他参数与成功情况相同

**逻辑推理步骤:**

1. 与成功情况类似，但操作系统 DNS 解析器无法找到 "nonexistent.example.com" 的 IP 地址。
2. `OnLookupComplete()` 方法在主线程被调用，接收到解析结果。
3. `results` 参数为空， `error` 为 `net::ERR_NAME_NOT_RESOLVED`， `os_error` 可能是一个与 DNS 查询失败相关的操作系统错误码。
4. `MaybeCacheResults()` 会将解析失败的结果缓存起来 (如果提供了 `CacheParams`)。
5. `results_cb_` 回调函数被执行，将解析失败的信息传递给调用者。

**假设输出 (失败情况):**

* `results`: 空
* `os_error`:  例如，Linux 上可能是 `EAI_NONAME` 或 Windows 上可能是 `WSAHOST_NOT_FOUND`。
* `error`: `net::ERR_NAME_NOT_RESOLVED` (-105)

**用户或编程常见的使用错误:**

1. **网络连接问题:** 用户的网络连接断开，导致 DNS 查询无法到达 DNS 服务器。这将导致 `SystemHostResolverCall` 返回 `ERR_INTERNET_DISCONNECTED`。
   * **用户操作:** 拔掉网线，禁用 Wi-Fi。
   * **调试线索:**  `OnLookupComplete` 中的 `error` 会是 `ERR_INTERNET_DISCONNECTED`。

2. **DNS 服务器问题:** 用户配置的 DNS 服务器不可用或无法解析该主机名。这会导致 `SystemHostResolverCall` 返回 `ERR_NAME_NOT_RESOLVED`，并且 `os_error` 会包含与 DNS 解析失败相关的系统错误码。
   * **用户操作:**  使用了错误的 DNS 服务器地址。
   * **调试线索:** `OnLookupComplete` 中的 `error` 会是 `ERR_NAME_NOT_RESOLVED`，并且 `os_error` 会指示 DNS 解析失败的原因。

3. **主机名拼写错误:** 用户输入的 URL 中包含拼写错误的主机名。
   * **用户操作:** 在地址栏输入 `ww.example.com` (少了 "w")。
   * **调试线索:**  `HostResolverSystemTask` 会尝试解析错误的 hostname，最终 `OnLookupComplete` 返回 `ERR_NAME_NOT_RESOLVED`。

4. **编程错误：使用了错误的主机名或配置:**  开发者在代码中使用了错误的 hostname 或者错误的 `HostResolverFlags`。
   * **编程操作:**  `HostResolver::Resolve()` 调用时传入了错误的 hostname 字符串。
   * **调试线索:**  NetLog 中会记录尝试解析的 hostname，检查 NetLog 可以帮助发现问题。

**用户操作如何一步步的到达这里，作为调试线索:**

让我们以用户在地址栏输入 URL 为例，逐步追踪用户操作如何触发 `HostResolverSystemTask` 的执行：

1. **用户在浏览器地址栏输入 URL 并按下回车键。** 例如，输入 `www.example.com`。
2. **浏览器 UI 线程接收到导航请求。**
3. **Navigation 模块开始处理导航请求。**
4. **Navigation 模块需要解析主机名 `www.example.com`。**
5. **Navigation 模块或其依赖的模块（例如 `HostResolverImpl`）创建一个 `HostResolverSystemTask` 对象。**  在创建时，会传入要解析的 hostname (`www.example.com`)、地址族 (`ADDRESS_FAMILY_UNSPECIFIED` 或根据配置)、以及其他相关参数。
6. **`HostResolverSystemTask::Start()` 方法被调用。**  这将启动 DNS 解析过程。
7. **`HostResolverSystemTask` 将 DNS 查询任务提交到后台线程池。**
8. **后台线程执行系统级别的 DNS 查询（通过 `SystemHostResolverCall`）。**
9. **操作系统进行 DNS 解析。**
10. **解析结果返回给 `HostResolverSystemTask` 的回调函数 `OnLookupComplete()`。**
11. **`OnLookupComplete()` 处理解析结果，可能缓存结果，并通过回调函数将结果传递回调用者（例如 `HostResolverImpl`）。**
12. **`HostResolverImpl` 将解析结果传递给 Navigation 模块。**
13. **Navigation 模块使用解析得到的 IP 地址建立与服务器的连接。**
14. **浏览器开始加载网页内容。**

**作为调试线索:**

* **NetLog:**  最直接的调试线索。启用浏览器的 NetLog (chrome://net-export/)，重现用户操作，可以查看与该 DNS 解析任务相关的详细事件，包括开始时间、结束时间、尝试次数、返回的 IP 地址、错误码等。
* **断点调试:**  在 `HostResolverSystemTask::Start()`, `StartLookupAttempt()`, `OnLookupComplete()`, `SystemHostResolverCall()` 等关键方法上设置断点，可以逐步跟踪代码执行流程，查看变量的值，理解 DNS 解析的具体过程。
* **检查网络配置:**  确保用户的网络连接正常，DNS 服务器配置正确。
* **查看操作系统 DNS 缓存:**  清除操作系统的 DNS 缓存 (例如 `ipconfig /flushdns` 在 Windows 上， `sudo systemd-resolve --flush-caches` 或 `sudo killall -HUP mDNSResponder` 在 macOS 上) 可以排除本地 DNS 缓存导致的问题。
* **使用网络抓包工具:**  例如 Wireshark，可以捕获 DNS 查询请求和响应报文，分析 DNS 查询过程中的网络交互。

总而言之，`net/dns/host_resolver_system_task.cc` 是 Chromium 网络栈中一个至关重要的低级组件，负责与操作系统进行交互以执行 DNS 解析，为浏览器中所有的网络请求提供基础的主机名到 IP 地址的转换服务。 理解它的功能和工作原理对于调试网络相关问题至关重要。

Prompt: 
```
这是目录为net/dns/host_resolver_system_task.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_system_task.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/dcheck_is_on.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ref.h"
#include "base/metrics/field_trial_params.h"
#include "base/no_destructor.h"
#include "base/notreached.h"
#include "base/sequence_checker.h"
#include "base/sequence_checker_impl.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/time/time.h"
#include "base/types/pass_key.h"
#include "dns_reloader.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_interfaces.h"
#include "net/base/sys_addrinfo.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/dns/address_info.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/host_resolver_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/public/host_resolver_source.h"

#if BUILDFLAG(IS_WIN)
#include "net/base/winsock_init.h"
#endif

namespace net {

namespace {

// System resolver results give no TTL, so a default caching time is needed.
// Pick 1 minute to match the minimum cache time for built-in resolver results
// because this is only serving as a secondary cache to the caching done by the
// system. Additionally, this matches the long-standing historical behavior from
// previous implementations of HostResolver caching.
constexpr base::TimeDelta kTtl = base::Minutes(1);

// Returns nullptr in the common case, or a task runner if the default has
// been overridden.
scoped_refptr<base::TaskRunner>& GetSystemDnsResolutionTaskRunnerOverride() {
  static base::NoDestructor<scoped_refptr<base::TaskRunner>>
      system_dns_resolution_task_runner(nullptr);
  return *system_dns_resolution_task_runner;
}

// Posts a synchronous callback to a thread pool task runner created with
// MayBlock, USER_BLOCKING, and CONTINUE_ON_SHUTDOWN. This task runner can be
// overridden by assigning to GetSystemDnsResolutionTaskRunnerOverride().
// `results_cb` will be called later on the current sequence with the results of
// the DNS resolution.
void PostSystemDnsResolutionTaskAndReply(
    base::OnceCallback<int(AddressList* addrlist, int* os_error)>
        system_dns_resolution_callback,
    SystemDnsResultsCallback results_cb) {
  auto addr_list = std::make_unique<net::AddressList>();
  net::AddressList* addr_list_ptr = addr_list.get();
  auto os_error = std::make_unique<int>();
  int* os_error_ptr = os_error.get();

  // This callback owns |addr_list| and |os_error| and just calls |results_cb|
  // with the results.
  auto call_with_results_cb = base::BindOnce(
      [](SystemDnsResultsCallback results_cb,
         std::unique_ptr<net::AddressList> addr_list,
         std::unique_ptr<int> os_error, int net_error) {
        std::move(results_cb).Run(std::move(*addr_list), *os_error, net_error);
      },
      std::move(results_cb), std::move(addr_list), std::move(os_error));

  scoped_refptr<base::TaskRunner> system_dns_resolution_task_runner =
      GetSystemDnsResolutionTaskRunnerOverride();
  if (!system_dns_resolution_task_runner) {
    // In production this will run on every call, otherwise some tests will
    // leave a stale task runner around after tearing down their task
    // environment. This should not be less performant than the regular
    // base::ThreadPool::PostTask().
    system_dns_resolution_task_runner = base::ThreadPool::CreateTaskRunner(
        {base::MayBlock(), base::TaskPriority::USER_BLOCKING,
         base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN});
  }
  system_dns_resolution_task_runner->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(std::move(system_dns_resolution_callback), addr_list_ptr,
                     os_error_ptr),
      std::move(call_with_results_cb));
}

int ResolveOnWorkerThread(scoped_refptr<HostResolverProc> resolver_proc,
                          std::optional<std::string> hostname,
                          AddressFamily address_family,
                          HostResolverFlags flags,
                          handles::NetworkHandle network,
                          AddressList* addrlist,
                          int* os_error) {
  std::string hostname_str = hostname ? *std::move(hostname) : GetHostName();
  if (resolver_proc) {
    return resolver_proc->Resolve(hostname_str, address_family, flags, addrlist,
                                  os_error, network);
  } else {
    return SystemHostResolverCall(hostname_str, address_family, flags, addrlist,
                                  os_error, network);
  }
}

// Creates NetLog parameters when the resolve failed.
base::Value::Dict NetLogHostResolverSystemTaskFailedParams(
    uint32_t attempt_number,
    int net_error,
    int os_error) {
  base::Value::Dict dict;
  if (attempt_number)
    dict.Set("attempt_number", base::saturated_cast<int>(attempt_number));

  dict.Set("net_error", net_error);

  if (os_error) {
    dict.Set("os_error", os_error);
#if BUILDFLAG(IS_WIN)
    // Map the error code to a human-readable string.
    LPWSTR error_string = nullptr;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  nullptr,  // Use the internal message table.
                  os_error,
                  0,  // Use default language.
                  (LPWSTR)&error_string,
                  0,         // Buffer size.
                  nullptr);  // Arguments (unused).
    dict.Set("os_error_string", base::WideToUTF8(error_string));
    LocalFree(error_string);
#elif BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)
    dict.Set("os_error_string", gai_strerror(os_error));
#endif
  }

  return dict;
}

using SystemDnsResolverOverrideCallback =
    base::RepeatingCallback<void(const std::optional<std::string>& host,
                                 AddressFamily address_family,
                                 HostResolverFlags host_resolver_flags,
                                 SystemDnsResultsCallback results_cb,
                                 handles::NetworkHandle network)>;

SystemDnsResolverOverrideCallback& GetSystemDnsResolverOverride() {
  static base::NoDestructor<SystemDnsResolverOverrideCallback> dns_override;

#if DCHECK_IS_ON()
  if (*dns_override) {
    // This should only be called on the main thread, so DCHECK that it is.
    // However, in unittests this may be called on different task environments
    // in the same process so only bother sequence checking if an override
    // exists.
    static base::NoDestructor<base::SequenceCheckerImpl> sequence_checker;
    base::ScopedValidateSequenceChecker scoped_validated_sequence_checker(
        *sequence_checker);
  }
#endif

  return *dns_override;
}

}  // namespace

void SetSystemDnsResolverOverride(
    SystemDnsResolverOverrideCallback dns_override) {
  GetSystemDnsResolverOverride() = std::move(dns_override);
}

HostResolverSystemTask::Params::Params(
    scoped_refptr<HostResolverProc> resolver_proc,
    size_t in_max_retry_attempts)
    : resolver_proc(std::move(resolver_proc)),
      max_retry_attempts(in_max_retry_attempts),
      unresponsive_delay(kDnsDefaultUnresponsiveDelay) {
  // Maximum of 4 retry attempts for host resolution.
  static const size_t kDefaultMaxRetryAttempts = 4u;
  if (max_retry_attempts == kDefaultRetryAttempts)
    max_retry_attempts = kDefaultMaxRetryAttempts;
}

HostResolverSystemTask::Params::Params(const Params& other) = default;

HostResolverSystemTask::Params::~Params() = default;

HostResolverSystemTask::CacheParams::CacheParams(
    HostResolverCache& cache,
    NetworkAnonymizationKey network_anonymization_key)
    : cache(base::raw_ref(cache)),
      network_anonymization_key(std::move(network_anonymization_key)) {}

HostResolverSystemTask::CacheParams::CacheParams(const CacheParams&) = default;

HostResolverSystemTask::CacheParams::CacheParams(CacheParams&&) = default;

HostResolverSystemTask::CacheParams::~CacheParams() = default;

// static
std::unique_ptr<HostResolverSystemTask> HostResolverSystemTask::Create(
    std::string hostname,
    AddressFamily address_family,
    HostResolverFlags flags,
    const Params& params,
    const NetLogWithSource& job_net_log,
    handles::NetworkHandle network,
    std::optional<CacheParams> cache_params) {
  return std::make_unique<HostResolverSystemTask>(
      std::move(hostname), address_family, flags, params, job_net_log, network,
      std::move(cache_params));
}

// static
std::unique_ptr<HostResolverSystemTask>
HostResolverSystemTask::CreateForOwnHostname(
    AddressFamily address_family,
    HostResolverFlags flags,
    const Params& params,
    const NetLogWithSource& job_net_log,
    handles::NetworkHandle network) {
  return std::make_unique<HostResolverSystemTask>(
      std::nullopt, address_family, flags, params, job_net_log, network,
      /*cache_params=*/std::nullopt);
}

HostResolverSystemTask::HostResolverSystemTask(
    std::optional<std::string> hostname,
    AddressFamily address_family,
    HostResolverFlags flags,
    const Params& params,
    const NetLogWithSource& job_net_log,
    handles::NetworkHandle network,
    std::optional<CacheParams> cache_params)
    : hostname_(std::move(hostname)),
      address_family_(address_family),
      flags_(flags),
      params_(params),
      net_log_(job_net_log),
      network_(network),
      cache_params_(std::move(cache_params)) {
  // Must have hostname if results are to be cached.
  CHECK(!cache_params_.has_value() || hostname_.has_value());

  if (hostname_) {
    // `hostname` should be a valid domain name. HostResolverManager has checks
    // to fail early if this is not the case.
    DCHECK(dns_names_util::IsValidDnsName(*hostname_))
        << "Invalid hostname: " << *hostname_;
  }
  // If a resolver_proc has not been specified, try to use a default if one is
  // set, as it may be in tests.
  if (!params_.resolver_proc.get())
    params_.resolver_proc = HostResolverProc::GetDefault();
}

// Cancels this HostResolverSystemTask. Any outstanding resolve attempts cannot
// be cancelled, but they will post back to the current thread before checking
// their WeakPtrs to find that this task is cancelled.
HostResolverSystemTask::~HostResolverSystemTask() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // If this is cancellation, log the EndEvent (otherwise this was logged in
  // OnLookupComplete()).
  if (!was_completed())
    net_log_.EndEvent(NetLogEventType::HOST_RESOLVER_SYSTEM_TASK);
}

void HostResolverSystemTask::Start(SystemDnsResultsCallback results_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(results_cb);
  DCHECK(!results_cb_);
  results_cb_ = std::move(results_cb);
  net_log_.BeginEvent(NetLogEventType::HOST_RESOLVER_SYSTEM_TASK);
  StartLookupAttempt();
}

void HostResolverSystemTask::StartLookupAttempt() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!was_completed());
  ++attempt_number_;

  net_log_.AddEventWithIntParams(
      NetLogEventType::HOST_RESOLVER_MANAGER_ATTEMPT_STARTED, "attempt_number",
      attempt_number_);

  // If the results aren't received within a given time, RetryIfNotComplete
  // will start a new attempt if none of the outstanding attempts have
  // completed yet.
  // Use a WeakPtr to avoid keeping the HostResolverSystemTask alive after
  // completion or cancellation.
  if (attempt_number_ <= params_.max_retry_attempts) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&HostResolverSystemTask::StartLookupAttempt,
                       weak_ptr_factory_.GetWeakPtr()),
        params_.unresponsive_delay *
            std::pow(params_.retry_factor, attempt_number_ - 1));
  }

  auto lookup_complete_cb =
      base::BindOnce(&HostResolverSystemTask::OnLookupComplete,
                     weak_ptr_factory_.GetWeakPtr(), attempt_number_);

  // If a hook has been installed, call it instead of posting a resolution task
  // to a worker thread.
  if (GetSystemDnsResolverOverride()) {
    GetSystemDnsResolverOverride().Run(hostname_, address_family_, flags_,
                                       std::move(lookup_complete_cb), network_);
    // Do not add code below. `lookup_complete_cb` may have already deleted
    // `this`.
  } else {
    base::OnceCallback<int(AddressList * addrlist, int* os_error)> resolve_cb =
        base::BindOnce(&ResolveOnWorkerThread, params_.resolver_proc, hostname_,
                       address_family_, flags_, network_);
    PostSystemDnsResolutionTaskAndReply(std::move(resolve_cb),
                                        std::move(lookup_complete_cb));
  }
}

// Callback for when DoLookup() completes.
void HostResolverSystemTask::OnLookupComplete(const uint32_t attempt_number,
                                              const AddressList& results,
                                              const int os_error,
                                              int error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!was_completed());

  TRACE_EVENT0(NetTracingCategory(),
               "HostResolverSystemTask::OnLookupComplete");

  // Invalidate WeakPtrs to cancel handling of all outstanding lookup attempts
  // and retries.
  weak_ptr_factory_.InvalidateWeakPtrs();

  // If results are empty, we should return an error.
  bool empty_list_on_ok = (error == OK && results.empty());
  if (empty_list_on_ok)
    error = ERR_NAME_NOT_RESOLVED;

  if (error != OK && NetworkChangeNotifier::IsOffline())
    error = ERR_INTERNET_DISCONNECTED;

  if (error != OK) {
    net_log_.EndEvent(NetLogEventType::HOST_RESOLVER_SYSTEM_TASK, [&] {
      return NetLogHostResolverSystemTaskFailedParams(0, error, os_error);
    });
    net_log_.AddEvent(NetLogEventType::HOST_RESOLVER_MANAGER_ATTEMPT_FINISHED,
                      [&] {
                        return NetLogHostResolverSystemTaskFailedParams(
                            attempt_number, error, os_error);
                      });
  } else {
    net_log_.EndEvent(NetLogEventType::HOST_RESOLVER_SYSTEM_TASK,
                      [&] { return results.NetLogParams(); });
    net_log_.AddEventWithIntParams(
        NetLogEventType::HOST_RESOLVER_MANAGER_ATTEMPT_FINISHED,
        "attempt_number", attempt_number);
  }

  MaybeCacheResults(results);

  std::move(results_cb_).Run(results, os_error, error);
  // Running |results_cb_| can delete |this|.
}

void HostResolverSystemTask::MaybeCacheResults(
    const AddressList& address_list) {
  if (address_list.empty() || !cache_params_.has_value() ||
      !base::FeatureList::IsEnabled(features::kUseHostResolverCache)) {
    return;
  }
  CHECK(hostname_.has_value());

  // Split out IPv4 and IPv6 endpoints while keeping them in the received order.
  std::vector<IPEndPoint> ipv4;
  std::vector<IPEndPoint> ipv6;
  for (const IPEndPoint& endpoint : address_list) {
    switch (endpoint.GetFamily()) {
      case ADDRESS_FAMILY_IPV4:
        ipv4.push_back(endpoint);
        break;
      case ADDRESS_FAMILY_IPV6:
        ipv6.push_back(endpoint);
        break;
      default:
        // Expect only IPv4 and IPv6 endpoints from system resolver.
        NOTREACHED();
    }
  }
  CHECK(!ipv4.empty() || !ipv6.empty());

  std::string_view domain_name = hostname_.value();
  if (!address_list.dns_aliases().empty()) {
    // Expect at most one alias from system resolver.
    CHECK_EQ(address_list.dns_aliases().size(), 1u);

    // Save one alias cache entry for each query type.
    CacheAlias(std::string(domain_name), DnsQueryType::A,
               address_list.dns_aliases().front());
    CacheAlias(std::string(domain_name), DnsQueryType::AAAA,
               address_list.dns_aliases().front());

    domain_name = address_list.dns_aliases().front();
  }

  CacheEndpoints(std::string(domain_name), std::move(ipv4), DnsQueryType::A);
  CacheEndpoints(std::string(domain_name), std::move(ipv6), DnsQueryType::AAAA);
}

void HostResolverSystemTask::CacheEndpoints(std::string domain_name,
                                            std::vector<IPEndPoint> endpoints,
                                            DnsQueryType query_type) {
  if (endpoints.empty()) {
    cache_params_.value().cache->Set(
        std::make_unique<HostResolverInternalErrorResult>(
            std::move(domain_name), query_type, base::TimeTicks::Now() + kTtl,
            base::Time::Now() + kTtl,
            HostResolverInternalResult::Source::kUnknown,
            ERR_NAME_NOT_RESOLVED),
        cache_params_.value().network_anonymization_key,
        HostResolverSource::SYSTEM, /*secure=*/false);
  } else {
    cache_params_.value().cache->Set(
        std::make_unique<HostResolverInternalDataResult>(
            std::move(domain_name), query_type, base::TimeTicks::Now() + kTtl,
            base::Time::Now() + kTtl,
            HostResolverInternalResult::Source::kUnknown, std::move(endpoints),
            std::vector<std::string>{}, std::vector<HostPortPair>{}),
        cache_params_.value().network_anonymization_key,
        HostResolverSource::SYSTEM, /*secure=*/false);
  }
}

void HostResolverSystemTask::CacheAlias(std::string domain_name,
                                        DnsQueryType query_type,
                                        std::string target_name) {
  cache_params_.value().cache->Set(
      std::make_unique<HostResolverInternalAliasResult>(
          std::move(domain_name), query_type, base::TimeTicks::Now() + kTtl,
          base::Time::Now() + kTtl,
          HostResolverInternalResult::Source::kUnknown, std::move(target_name)),
      cache_params_.value().network_anonymization_key,
      HostResolverSource::SYSTEM, /*secure=*/false);
}

void EnsureSystemHostResolverCallReady() {
  EnsureDnsReloaderInit();
#if BUILDFLAG(IS_WIN)
  EnsureWinsockInit();
#endif
}

namespace {

int AddressFamilyToAF(AddressFamily address_family) {
  switch (address_family) {
    case ADDRESS_FAMILY_IPV4:
      return AF_INET;
    case ADDRESS_FAMILY_IPV6:
      return AF_INET6;
    case ADDRESS_FAMILY_UNSPECIFIED:
      return AF_UNSPEC;
  }
}

}  // namespace

int SystemHostResolverCall(const std::string& host,
                           AddressFamily address_family,
                           HostResolverFlags host_resolver_flags,
                           AddressList* addrlist,
                           int* os_error_opt,
                           handles::NetworkHandle network) {
  struct addrinfo hints = {0};
  hints.ai_family = AddressFamilyToAF(address_family);

#if BUILDFLAG(IS_WIN)
  // DO NOT USE AI_ADDRCONFIG ON WINDOWS.
  //
  // The following comment in <winsock2.h> is the best documentation I found
  // on AI_ADDRCONFIG for Windows:
  //   Flags used in "hints" argument to getaddrinfo()
  //       - AI_ADDRCONFIG is supported starting with Vista
  //       - default is AI_ADDRCONFIG ON whether the flag is set or not
  //         because the performance penalty in not having ADDRCONFIG in
  //         the multi-protocol stack environment is severe;
  //         this defaulting may be disabled by specifying the AI_ALL flag,
  //         in that case AI_ADDRCONFIG must be EXPLICITLY specified to
  //         enable ADDRCONFIG behavior
  //
  // Not only is AI_ADDRCONFIG unnecessary, but it can be harmful.  If the
  // computer is not connected to a network, AI_ADDRCONFIG causes getaddrinfo
  // to fail with WSANO_DATA (11004) for "localhost", probably because of the
  // following note on AI_ADDRCONFIG in the MSDN getaddrinfo page:
  //   The IPv4 or IPv6 loopback address is not considered a valid global
  //   address.
  // See http://crbug.com/5234.
  //
  // OpenBSD does not support it, either.
  hints.ai_flags = 0;
#else
  // On other operating systems, AI_ADDRCONFIG may reduce the amount of
  // unnecessary DNS lookups, e.g. getaddrinfo() will not send a request for
  // AAAA records if the current machine has no IPv6 addresses configured and
  // therefore could not use the resulting AAAA record anyway. On some ancient
  // routers, AAAA DNS queries won't be handled correctly and will cause
  // multiple retransmitions and large latency spikes.
  hints.ai_flags = AI_ADDRCONFIG;
#endif

  // On Linux AI_ADDRCONFIG doesn't consider loopback addresses, even if only
  // loopback addresses are configured. So don't use it when there are only
  // loopback addresses. See loopback_only.h and
  // https://fedoraproject.org/wiki/QA/Networking/NameResolution/ADDRCONFIG for
  // a description of some of the issues AI_ADDRCONFIG can cause.
  if (host_resolver_flags & HOST_RESOLVER_LOOPBACK_ONLY) {
    hints.ai_flags &= ~AI_ADDRCONFIG;
  }

  if (host_resolver_flags & HOST_RESOLVER_CANONNAME)
    hints.ai_flags |= AI_CANONNAME;

#if BUILDFLAG(IS_WIN)
  // See crbug.com/1176970. Flag not documented (other than the declaration
  // comment in ws2def.h) but confirmed by Microsoft to work for this purpose
  // and be safe.
  if (host_resolver_flags & HOST_RESOLVER_AVOID_MULTICAST)
    hints.ai_flags |= AI_DNS_ONLY;
#endif  // BUILDFLAG(IS_WIN)

  // Restrict result set to only this socket type to avoid duplicates.
  hints.ai_socktype = SOCK_STREAM;

  // This function can block for a long time. Use ScopedBlockingCall to increase
  // the current thread pool's capacity and thus avoid reducing CPU usage by the
  // current process during that time.
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::WILL_BLOCK);
  DnsReloaderMaybeReload();

  auto [ai, err, os_error] = AddressInfo::Get(host, hints, nullptr, network);
  bool should_retry = false;
  // If the lookup was restricted (either by address family, or address
  // detection), and the results where all localhost of a single family,
  // maybe we should retry.  There were several bugs related to these
  // issues, for example http://crbug.com/42058 and http://crbug.com/49024
  if ((hints.ai_family != AF_UNSPEC || hints.ai_flags & AI_ADDRCONFIG) && ai &&
      ai->IsAllLocalhostOfOneFamily()) {
    if (host_resolver_flags & HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6) {
      hints.ai_family = AF_UNSPEC;
      should_retry = true;
    }
    if (hints.ai_flags & AI_ADDRCONFIG) {
      hints.ai_flags &= ~AI_ADDRCONFIG;
      should_retry = true;
    }
  }
  if (should_retry) {
    std::tie(ai, err, os_error) =
        AddressInfo::Get(host, hints, nullptr, network);
  }

  if (os_error_opt)
    *os_error_opt = os_error;

  if (!ai)
    return err;

  *addrlist = ai->CreateAddressList();
  return OK;
}

void SetSystemDnsResolutionTaskRunnerForTesting(  // IN-TEST
    scoped_refptr<base::TaskRunner> task_runner) {
  GetSystemDnsResolutionTaskRunnerOverride() = task_runner;
}

}  // namespace net

"""

```