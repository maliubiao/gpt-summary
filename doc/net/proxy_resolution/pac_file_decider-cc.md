Response:
Let's break down the thought process for analyzing this `PacFileDecider.cc` file.

1. **Understand the Core Purpose:** The filename itself gives a strong hint: `pac_file_decider`. This suggests a component responsible for *deciding* which PAC file to use. The surrounding directory `net/proxy_resolution` further confirms this is part of the proxy resolution mechanism.

2. **Identify Key Dependencies:** Look at the `#include` statements. These reveal the other components this class interacts with:
    * `PacFileFetcher`:  For fetching PAC files from URLs.
    * `DhcpPacFileFetcher`: For fetching PAC files via DHCP.
    * `NetLog`: For logging events, crucial for debugging.
    * `HostResolver`: For resolving hostnames, used in the WPAD DNS check.
    * `URLRequestContext`: Provides context for network requests, including the `HostResolver`.
    * Standard C++ and Chromium base libraries (`utility`, `functional`, `string`, `base/values`, etc.):  For general utility and data structures.

3. **Analyze the Class Structure:** Examine the `PacFileDecider` class itself:
    * **Constructor/Destructor:** How is it initialized and cleaned up?  Note the injection of `PacFileFetcher` and `DhcpPacFileFetcher`.
    * **`Start()` method:** This is likely the main entry point. What are its inputs (ProxyConfig, wait delay, fetch bytes, callback) and what does it seem to initiate?
    * **State Machine:** The presence of `next_state_` and the `DoLoop()` method strongly indicate a state machine. This is a common pattern for managing asynchronous operations. List the states and try to infer their purpose based on their names (e.g., `STATE_WAIT`, `STATE_FETCH_PAC_SCRIPT`).
    * **`OnIOCompletion()`:** This suggests handling asynchronous completion of I/O operations.
    * **Helper Methods:** Identify methods like `BuildPacSourcesFallbackList()`, `DetermineURL()`, `TryToFallbackPacSource()`. These provide insights into the decision-making logic.
    * **Data Members:** Understand the purpose of members like `pac_sources_`, `effective_config_`, `script_data_`, `wait_timer_`, `resolve_request_`.

4. **Focus on Functionality and Relationships to JavaScript:**
    * **`LooksLikePacScript()`:** This function is a direct connection to JavaScript. It performs a simple heuristic check for the presence of "FindProxyForURL," the entry point of a PAC script.
    * **PAC Script Fetching:** The core purpose is to obtain PAC scripts. Explain the different methods (DHCP, DNS WPAD, custom URL).
    * **PAC Script Content:** Emphasize that the fetched content is *interpreted* by a JavaScript engine later in the process (though this file doesn't handle that interpretation).

5. **Identify Logic and Decision-Making:**
    * **Fallback Mechanism:** The `pac_sources_` list and `TryToFallbackPacSource()` clearly demonstrate a fallback strategy if one method of getting the PAC file fails.
    * **WPAD (Web Proxy Auto-Discovery):** Explain the two WPAD methods (DHCP and DNS) and the order they are attempted. Note the special handling of the "wpad" hostname.
    * **`quick_check_enabled_`:** Explain the purpose of this optimization – a quick DNS check for WPAD before fully fetching the script.
    * **Wait Delay:**  Understand why there's a potential wait delay before starting the PAC resolution process.

6. **Consider User and Programming Errors:**
    * **Incorrect PAC URL:** A common user error.
    * **Network Issues:**  Problems fetching the PAC file due to network connectivity.
    * **Invalid PAC Script:** While this file does a basic check, more complex syntax errors would be handled later.
    * **Misconfigured WPAD:** Issues with DHCP or DNS WPAD setup.
    * **Programming Errors (Internal):**  Focus on `DCHECK` statements and potential issues with state transitions.

7. **Trace User Actions (Debugging Clues):**
    * Start from the user needing proxy settings.
    * Explain how the system might be configured to use automatic proxy detection.
    * Describe the sequence of events that lead to `PacFileDecider::Start()` being called.

8. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Start with a high-level summary and then delve into specifics.

9. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any technical jargon that needs further explanation. Make sure the examples are helpful and easy to understand. For example, initially, I might have just listed the states, but then I would go back and add a brief description of what happens in each state. Similarly, I might initially forget to explicitly mention that this code *doesn't* interpret the JavaScript.

By following this systematic approach, we can effectively dissect the provided source code and address all the requirements of the prompt. The key is to break down the problem into smaller, manageable pieces and focus on understanding the purpose and interactions of each component.
好的，我们来分析一下 `net/proxy_resolution/pac_file_decider.cc` 这个 Chromium 网络栈的源代码文件。

**功能概述:**

`PacFileDecider` 类的主要功能是决定如何获取和验证代理自动配置（PAC）文件。它负责尝试不同的方法来定位 PAC 文件，并在找到后进行基本的验证。 这个过程是异步的，并可能涉及多个步骤和网络请求。

**具体功能分解:**

1. **管理 PAC 文件获取的策略:** 它维护了一个 PAC 文件来源的优先级列表 (`pac_sources_`)，这些来源包括：
   - **WPAD (Web Proxy Auto-Discovery) via DHCP:**  通过 DHCP 协议查找 PAC 文件。
   - **WPAD via DNS:** 通过 DNS 查询 `wpad` 主机来定位 PAC 文件。
   - **自定义 PAC URL:** 使用用户或系统配置中指定的 PAC 文件 URL。

2. **异步获取 PAC 文件:** 使用 `PacFileFetcher` 和 `DhcpPacFileFetcher` 接口来实际执行网络请求，获取 PAC 文件的内容。

3. **快速检查 (Quick Check) WPAD via DNS (可选):**  在尝试通过 DNS 获取 WPAD 文件之前，可以选择执行一个快速的 DNS 查询来检查 `wpad` 主机是否存在。这可以避免在 `wpad` 不存在时等待较长的超时时间。

4. **基本的 PAC 文件内容验证:**  它使用一个简单的启发式方法 `LooksLikePacScript` 来检查获取到的内容是否看起来像一个 JavaScript PAC 脚本（通过查找 "FindProxyForURL" 字符串）。

5. **回退机制:** 如果当前尝试的 PAC 文件来源失败，它会尝试列表中的下一个来源。

6. **处理等待延迟:** 在开始 PAC 文件获取过程之前，可以配置一个等待延迟。

7. **记录日志:** 使用 `net::NetLog` 记录 PAC 文件决策过程中的各种事件，用于调试和分析。

8. **提供最终配置:**  一旦成功获取并验证了 PAC 文件（或者决定不使用 PAC 文件），它会生成最终的 `ProxyConfigWithAnnotation` 对象，其中包含了 PAC 文件的信息。

**与 JavaScript 的关系及举例说明:**

`PacFileDecider` 本身并不执行 JavaScript 代码。它的职责是获取 PAC 文件的内容。然而，PAC 文件本身是用 JavaScript 编写的，包含一个名为 `FindProxyForURL(url, host)` 的函数，用于决定给定 URL 应该使用哪个代理服务器。

**举例说明:**

假设获取到的 PAC 文件内容如下：

```javascript
function FindProxyForURL(url, host) {
  if (host == "www.example.com") {
    return "PROXY proxy1.example.net:8080";
  } else if (shExpMatch(url, "https:*")) {
    return "PROXY proxy2.example.net:8080; DIRECT";
  } else {
    return "DIRECT";
  }
}
```

`PacFileDecider` 的作用是获取这段文本内容，并将其传递给网络栈的其他部分（例如 `ProxyResolver`），由 `ProxyResolver` 内部的 JavaScript 引擎来解释执行这段代码，从而决定特定请求的代理设置。

`LooksLikePacScript` 函数通过检查是否存在 `FindProxyForURL` 字符串来初步判断获取到的内容是否是 PAC 脚本。虽然简单，但对于快速排除非 PAC 文件很有用。

**逻辑推理及假设输入与输出:**

**假设输入:**

- **`config` (ProxyConfigWithAnnotation):** 配置信息，指定了自动检测代理设置并可能包含自定义 PAC URL。
  ```
  ProxyConfigValue:
    auto_detect: true
    pac_url: "http://custom.pac/file.pac"
    pac_mandatory: false
  ```
- **网络环境:**  假设 DHCP 服务器上没有配置 WPAD 信息，但 DNS 中存在 `wpad` 主机的 A 记录指向一个提供 PAC 文件的服务器。

**执行流程和输出:**

1. `PacFileDecider::Start` 被调用。
2. `BuildPacSourcesFallbackList` 构建 PAC 文件来源列表：WPAD DHCP, WPAD DNS, Custom PAC URL。
3. **尝试 WPAD DHCP:** `DoFetchPacScript` 调用 `dhcp_pac_file_fetcher_->Fetch`，假设失败（DHCP 上没有配置）。
4. **回退到 WPAD DNS:** `TryToFallbackPacSource` 将尝试下一个来源。 `DoQuickCheck` 被调用（如果启用）。假设 `DoQuickCheckComplete` 返回 OK (成功解析了 `wpad` 主机)。
5. **尝试 WPAD DNS 获取:** `DoFetchPacScript` 调用 `pac_file_fetcher_->Fetch`，使用 URL `http://wpad/wpad.dat`。
6. **假设成功获取 PAC 文件:** `DoFetchPacScriptComplete` 返回 OK。
7. **验证 PAC 脚本:** `DoVerifyPacScript` 调用 `LooksLikePacScript`，假设返回 true。
8. **构建有效配置:** `DoVerifyPacScriptComplete` 构建 `effective_config_`，其中包含通过 WPAD DNS 获取到的 PAC 文件信息。
9. **最终输出:** `effective_config_` 将包含 `ProxyConfig`，指示使用自动检测到的 PAC 文件 (来自 `http://wpad/wpad.dat`)。

**用户或编程常见的使用错误及举例说明:**

1. **用户配置错误的自定义 PAC URL:**
   - **错误:** 用户在系统设置中配置了一个不存在或无法访问的 PAC 文件 URL，例如 `http://invalid.pac/file.pac`。
   - **结果:** `PacFileDecider` 会尝试连接该 URL，`PacFileFetcher` 可能会返回错误，例如 `ERR_NAME_NOT_RESOLVED` 或 `ERR_CONNECTION_REFUSED`。最终可能回退到其他 PAC 来源或直接连接。

2. **网络环境问题导致 WPAD 失败:**
   - **错误:**  在期望通过 WPAD 获取 PAC 文件的网络环境中，DHCP 或 DNS 配置不正确，导致无法找到 `wpad` 主机或 PAC 文件。
   - **结果:** `PacFileDecider` 会尝试 WPAD DHCP 和 WPAD DNS，但都失败。如果配置了自定义 PAC URL，则会尝试该 URL。如果所有来源都失败，最终可能使用直接连接。

3. **PAC 文件内容错误:**
   - **错误:**  获取到的 PAC 文件不是有效的 JavaScript 代码，或者不包含 `FindProxyForURL` 函数。
   - **结果:** `LooksLikePacScript` 可能会返回 false，导致 `DoVerifyPacScriptComplete` 返回 `ERR_PAC_SCRIPT_FAILED`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户修改操作系统或浏览器代理设置:** 用户在操作系统或浏览器的设置界面中选择了 "自动检测代理设置" 或 "使用 PAC 脚本"。

2. **浏览器发起网络请求:** 当用户尝试访问一个网页时，浏览器需要确定该请求应该使用哪个代理服务器。

3. **ProxyService 初始化:**  网络栈的 `ProxyService` 组件负责管理代理设置。当需要解析代理时，它会检查当前配置。

4. **PacFileDecider 的创建和启动:** 如果配置指示使用自动检测或 PAC 脚本，并且之前没有有效的 PAC 文件信息，`ProxyService` 会创建 `PacFileDecider` 实例。

5. **调用 `PacFileDecider::Start`:** `ProxyService` 调用 `PacFileDecider::Start` 方法，传入当前的代理配置。

6. **PacFileDecider 尝试获取 PAC 文件:**  `PacFileDecider` 按照其配置的策略（WPAD DHCP, WPAD DNS, 自定义 URL）异步地尝试获取 PAC 文件。

7. **网络请求:**  `PacFileFetcher` 和 `DhcpPacFileFetcher` 执行实际的网络请求来下载 PAC 文件。 这些请求会经过 Chromium 的网络栈，包括 DNS 解析、连接建立等过程。

8. **回调和状态转换:**  当网络请求完成时，`PacFileDecider` 的回调函数 (`OnIOCompletion`) 会被调用，驱动状态机 (`DoLoop`) 进入下一个状态。

9. **最终结果:**  `PacFileDecider` 最终会生成 `effective_config_`，指示应该如何为后续的请求选择代理。这个配置会被传递回 `ProxyService`，然后用于实际的代理解析过程。

**调试线索:**

- **NetLog:** 查看 Chromium 的 NetLog (可以通过 `chrome://net-export/` 或 `chrome://net-internals/#events` 获取) 可以追踪 `PacFileDecider` 的执行过程，包括尝试哪些 PAC 来源，网络请求的结果，以及发生的错误。相关的 NetLog 事件类型包括 `PAC_FILE_DECIDER`, `PAC_FILE_DECIDER_FETCH_PAC_SCRIPT` 等。

- **断点调试:**  在 `PacFileDecider.cc` 的关键方法（如 `Start`, `DoLoop`, `DoFetchPacScript`, `TryToFallbackPacSource`) 设置断点，可以逐步查看 PAC 文件决策的流程和变量的值。

- **检查网络配置:**  确认目标网络环境中 DHCP 和 DNS 是否正确配置了 WPAD 信息。

- **检查自定义 PAC URL:** 如果使用了自定义 PAC URL，请确保该 URL 可以访问，并且返回的是有效的 PAC 脚本。

希望以上分析对您有所帮助！

### 提示词
```
这是目录为net/proxy_resolution/pac_file_decider.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/proxy_resolution/pac_file_decider.h"

#include <utility>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/isolation_info.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/proxy_resolution/dhcp_pac_file_fetcher.h"
#include "net/proxy_resolution/pac_file_fetcher.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

bool LooksLikePacScript(const std::u16string& script) {
  // Note: this is only an approximation! It may not always work correctly,
  // however it is very likely that legitimate scripts have this exact string,
  // since they must minimally define a function of this name. Conversely, a
  // file not containing the string is not likely to be a PAC script.
  //
  // An exact test would have to load the script in a javascript evaluator.
  return script.find(u"FindProxyForURL") != std::u16string::npos;
}

// This is the hard-coded location used by the DNS portion of web proxy
// auto-discovery.
//
// Note that we not use DNS devolution to find the WPAD host, since that could
// be dangerous should our top level domain registry  become out of date.
//
// Instead we directly resolve "wpad", and let the operating system apply the
// DNS suffix search paths. This is the same approach taken by Firefox, and
// compatibility hasn't been an issue.
//
// For more details, also check out this comment:
// http://code.google.com/p/chromium/issues/detail?id=18575#c20
const char kWpadUrl[] = "http://wpad/wpad.dat";
const int kQuickCheckDelayMs = 1000;

}  // namespace

PacFileDataWithSource::PacFileDataWithSource() = default;
PacFileDataWithSource::~PacFileDataWithSource() = default;
PacFileDataWithSource::PacFileDataWithSource(const PacFileDataWithSource&) =
    default;
PacFileDataWithSource& PacFileDataWithSource::operator=(
    const PacFileDataWithSource&) = default;

base::Value::Dict PacFileDecider::PacSource::NetLogParams(
    const GURL& effective_pac_url) const {
  base::Value::Dict dict;
  std::string source;
  switch (type) {
    case PacSource::WPAD_DHCP:
      source = "WPAD DHCP";
      break;
    case PacSource::WPAD_DNS:
      source = "WPAD DNS: ";
      source += effective_pac_url.possibly_invalid_spec();
      break;
    case PacSource::CUSTOM:
      source = "Custom PAC URL: ";
      source += effective_pac_url.possibly_invalid_spec();
      break;
  }
  dict.Set("source", source);
  return dict;
}

PacFileDecider::PacFileDecider(PacFileFetcher* pac_file_fetcher,
                               DhcpPacFileFetcher* dhcp_pac_file_fetcher,
                               NetLog* net_log)
    : pac_file_fetcher_(pac_file_fetcher),
      dhcp_pac_file_fetcher_(dhcp_pac_file_fetcher),
      net_log_(NetLogWithSource::Make(net_log,
                                      NetLogSourceType::PAC_FILE_DECIDER)) {}

PacFileDecider::~PacFileDecider() {
  if (next_state_ != STATE_NONE)
    Cancel();
}

int PacFileDecider::Start(const ProxyConfigWithAnnotation& config,
                          const base::TimeDelta wait_delay,
                          bool fetch_pac_bytes,
                          CompletionOnceCallback callback) {
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(!callback.is_null());
  DCHECK(config.value().HasAutomaticSettings());

  net_log_.BeginEvent(NetLogEventType::PAC_FILE_DECIDER);

  fetch_pac_bytes_ = fetch_pac_bytes;

  // Save the |wait_delay| as a non-negative value.
  wait_delay_ = wait_delay;
  if (wait_delay_.is_negative())
    wait_delay_ = base::TimeDelta();

  pac_mandatory_ = config.value().pac_mandatory();
  have_custom_pac_url_ = config.value().has_pac_url();

  pac_sources_ = BuildPacSourcesFallbackList(config.value());
  DCHECK(!pac_sources_.empty());

  traffic_annotation_ =
      net::MutableNetworkTrafficAnnotationTag(config.traffic_annotation());
  next_state_ = STATE_WAIT;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);
  else
    DidComplete();

  return rv;
}

void PacFileDecider::OnShutdown() {
  // Don't do anything if idle.
  if (next_state_ == STATE_NONE)
    return;

  // Just cancel any pending work.
  Cancel();
}

const ProxyConfigWithAnnotation& PacFileDecider::effective_config() const {
  DCHECK_EQ(STATE_NONE, next_state_);
  return effective_config_;
}

const PacFileDataWithSource& PacFileDecider::script_data() const {
  DCHECK_EQ(STATE_NONE, next_state_);
  return script_data_;
}

// Initialize the fallback rules.
// (1) WPAD (DHCP).
// (2) WPAD (DNS).
// (3) Custom PAC URL.
PacFileDecider::PacSourceList PacFileDecider::BuildPacSourcesFallbackList(
    const ProxyConfig& config) const {
  PacSourceList pac_sources;
  if (config.auto_detect()) {
    pac_sources.push_back(PacSource(PacSource::WPAD_DHCP, GURL(kWpadUrl)));
    pac_sources.push_back(PacSource(PacSource::WPAD_DNS, GURL(kWpadUrl)));
  }
  if (config.has_pac_url())
    pac_sources.push_back(PacSource(PacSource::CUSTOM, config.pac_url()));
  return pac_sources;
}

void PacFileDecider::OnIOCompletion(int result) {
  DCHECK_NE(STATE_NONE, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    DidComplete();
    std::move(callback_).Run(rv);
  }
}

int PacFileDecider::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);
  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_WAIT:
        DCHECK_EQ(OK, rv);
        rv = DoWait();
        break;
      case STATE_WAIT_COMPLETE:
        rv = DoWaitComplete(rv);
        break;
      case STATE_QUICK_CHECK:
        DCHECK_EQ(OK, rv);
        rv = DoQuickCheck();
        break;
      case STATE_QUICK_CHECK_COMPLETE:
        rv = DoQuickCheckComplete(rv);
        break;
      case STATE_FETCH_PAC_SCRIPT:
        DCHECK_EQ(OK, rv);
        rv = DoFetchPacScript();
        break;
      case STATE_FETCH_PAC_SCRIPT_COMPLETE:
        rv = DoFetchPacScriptComplete(rv);
        break;
      case STATE_VERIFY_PAC_SCRIPT:
        DCHECK_EQ(OK, rv);
        rv = DoVerifyPacScript();
        break;
      case STATE_VERIFY_PAC_SCRIPT_COMPLETE:
        rv = DoVerifyPacScriptComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

int PacFileDecider::DoWait() {
  next_state_ = STATE_WAIT_COMPLETE;

  // If no waiting is required, continue on to the next state.
  if (wait_delay_.ToInternalValue() == 0)
    return OK;

  // Otherwise wait the specified amount of time.
  wait_timer_.Start(FROM_HERE, wait_delay_, this,
                    &PacFileDecider::OnWaitTimerFired);
  net_log_.BeginEvent(NetLogEventType::PAC_FILE_DECIDER_WAIT);
  return ERR_IO_PENDING;
}

int PacFileDecider::DoWaitComplete(int result) {
  DCHECK_EQ(OK, result);
  if (wait_delay_.ToInternalValue() != 0) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::PAC_FILE_DECIDER_WAIT,
                                      result);
  }
  if (quick_check_enabled_ && current_pac_source().type == PacSource::WPAD_DNS)
    next_state_ = STATE_QUICK_CHECK;
  else
    next_state_ = GetStartState();
  return OK;
}

int PacFileDecider::DoQuickCheck() {
  DCHECK(quick_check_enabled_);
  if (!pac_file_fetcher_ || !pac_file_fetcher_->GetRequestContext() ||
      !pac_file_fetcher_->GetRequestContext()->host_resolver()) {
    // If we have no resolver, skip QuickCheck altogether.
    next_state_ = GetStartState();
    return OK;
  }

  std::string host = current_pac_source().url.host();

  HostResolver::ResolveHostParameters parameters;
  // We use HIGHEST here because proxy decision blocks doing any other requests.
  parameters.initial_priority = HIGHEST;
  // Only resolve via the system resolver for maximum compatibility with DNS
  // suffix search paths, because for security, we are relying on suffix search
  // paths rather than WPAD-standard DNS devolution.
  parameters.source = HostResolverSource::SYSTEM;

  // For most users, the WPAD DNS query will have no results. Allowing the query
  // to go out via LLMNR or mDNS (which usually have no quick negative response)
  // would therefore typically result in waiting the full timeout before
  // `quick_check_timer_` fires. Given that a lot of Chrome requests could be
  // blocked on completing these checks, it is better to avoid multicast
  // resolution for WPAD.
  // See crbug.com/1176970.
  parameters.avoid_multicast_resolution = true;

  HostResolver* host_resolver =
      pac_file_fetcher_->GetRequestContext()->host_resolver();
  resolve_request_ = host_resolver->CreateRequest(
      HostPortPair(host, 80),
      pac_file_fetcher_->isolation_info().network_anonymization_key(), net_log_,
      parameters);

  CompletionRepeatingCallback callback = base::BindRepeating(
      &PacFileDecider::OnIOCompletion, base::Unretained(this));

  next_state_ = STATE_QUICK_CHECK_COMPLETE;
  quick_check_timer_.Start(FROM_HERE, base::Milliseconds(kQuickCheckDelayMs),
                           base::BindOnce(callback, ERR_NAME_NOT_RESOLVED));

  return resolve_request_->Start(callback);
}

int PacFileDecider::DoQuickCheckComplete(int result) {
  DCHECK(quick_check_enabled_);
  resolve_request_.reset();
  quick_check_timer_.Stop();
  if (result != OK)
    return TryToFallbackPacSource(result);
  next_state_ = GetStartState();
  return result;
}

int PacFileDecider::DoFetchPacScript() {
  DCHECK(fetch_pac_bytes_);

  next_state_ = STATE_FETCH_PAC_SCRIPT_COMPLETE;

  const PacSource& pac_source = current_pac_source();

  GURL effective_pac_url;
  DetermineURL(pac_source, &effective_pac_url);

  net_log_.BeginEvent(NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT, [&] {
    return pac_source.NetLogParams(effective_pac_url);
  });

  if (pac_source.type == PacSource::WPAD_DHCP) {
    if (!dhcp_pac_file_fetcher_) {
      net_log_.AddEvent(NetLogEventType::PAC_FILE_DECIDER_HAS_NO_FETCHER);
      return ERR_UNEXPECTED;
    }

    return dhcp_pac_file_fetcher_->Fetch(
        &pac_script_,
        base::BindOnce(&PacFileDecider::OnIOCompletion, base::Unretained(this)),
        net_log_, NetworkTrafficAnnotationTag(traffic_annotation_));
  }

  if (!pac_file_fetcher_) {
    net_log_.AddEvent(NetLogEventType::PAC_FILE_DECIDER_HAS_NO_FETCHER);
    return ERR_UNEXPECTED;
  }

  return pac_file_fetcher_->Fetch(
      effective_pac_url, &pac_script_,
      base::BindOnce(&PacFileDecider::OnIOCompletion, base::Unretained(this)),
      NetworkTrafficAnnotationTag(traffic_annotation_));
}

int PacFileDecider::DoFetchPacScriptComplete(int result) {
  DCHECK(fetch_pac_bytes_);

  net_log_.EndEventWithNetErrorCode(
      NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT, result);
  if (result != OK)
    return TryToFallbackPacSource(result);

  next_state_ = STATE_VERIFY_PAC_SCRIPT;
  return result;
}

int PacFileDecider::DoVerifyPacScript() {
  next_state_ = STATE_VERIFY_PAC_SCRIPT_COMPLETE;

  // This is just a heuristic. Ideally we would try to parse the script.
  if (fetch_pac_bytes_ && !LooksLikePacScript(pac_script_))
    return ERR_PAC_SCRIPT_FAILED;

  return OK;
}

int PacFileDecider::DoVerifyPacScriptComplete(int result) {
  if (result != OK)
    return TryToFallbackPacSource(result);

  const PacSource& pac_source = current_pac_source();

  // Extract the current script data.
  script_data_.from_auto_detect = pac_source.type != PacSource::CUSTOM;
  if (fetch_pac_bytes_) {
    script_data_.data = PacFileData::FromUTF16(pac_script_);
  } else {
    script_data_.data = pac_source.type == PacSource::CUSTOM
                            ? PacFileData::FromURL(pac_source.url)
                            : PacFileData::ForAutoDetect();
  }

  // Let the caller know which automatic setting we ended up initializing the
  // resolver for (there may have been multiple fallbacks to choose from.)
  ProxyConfig config;
  if (current_pac_source().type == PacSource::CUSTOM) {
    config = ProxyConfig::CreateFromCustomPacURL(current_pac_source().url);
    config.set_pac_mandatory(pac_mandatory_);
  } else {
    if (fetch_pac_bytes_) {
      GURL auto_detected_url;

      switch (current_pac_source().type) {
        case PacSource::WPAD_DHCP:
          auto_detected_url = dhcp_pac_file_fetcher_->GetPacURL();
          break;

        case PacSource::WPAD_DNS:
          auto_detected_url = GURL(kWpadUrl);
          break;

        default:
          NOTREACHED();
      }

      config = ProxyConfig::CreateFromCustomPacURL(auto_detected_url);
    } else {
      // The resolver does its own resolution so we cannot know the
      // URL. Just do the best we can and state that the configuration
      // is to auto-detect proxy settings.
      config = ProxyConfig::CreateAutoDetect();
    }
  }

  effective_config_ = ProxyConfigWithAnnotation(
      config, net::NetworkTrafficAnnotationTag(traffic_annotation_));

  return OK;
}

int PacFileDecider::TryToFallbackPacSource(int error) {
  DCHECK_LT(error, 0);

  if (current_pac_source_index_ + 1 >= pac_sources_.size()) {
    // Nothing left to fall back to.
    return error;
  }

  // Advance to next URL in our list.
  ++current_pac_source_index_;

  net_log_.AddEvent(
      NetLogEventType::PAC_FILE_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE);
  if (quick_check_enabled_ && current_pac_source().type == PacSource::WPAD_DNS)
    next_state_ = STATE_QUICK_CHECK;
  else
    next_state_ = GetStartState();

  return OK;
}

PacFileDecider::State PacFileDecider::GetStartState() const {
  return fetch_pac_bytes_ ? STATE_FETCH_PAC_SCRIPT : STATE_VERIFY_PAC_SCRIPT;
}

void PacFileDecider::DetermineURL(const PacSource& pac_source,
                                  GURL* effective_pac_url) {
  DCHECK(effective_pac_url);

  switch (pac_source.type) {
    case PacSource::WPAD_DHCP:
      break;
    case PacSource::WPAD_DNS:
      *effective_pac_url = GURL(kWpadUrl);
      break;
    case PacSource::CUSTOM:
      *effective_pac_url = pac_source.url;
      break;
  }
}

const PacFileDecider::PacSource& PacFileDecider::current_pac_source() const {
  DCHECK_LT(current_pac_source_index_, pac_sources_.size());
  return pac_sources_[current_pac_source_index_];
}

void PacFileDecider::OnWaitTimerFired() {
  OnIOCompletion(OK);
}

void PacFileDecider::DidComplete() {
  net_log_.EndEvent(NetLogEventType::PAC_FILE_DECIDER);
}

void PacFileDecider::Cancel() {
  DCHECK_NE(STATE_NONE, next_state_);

  net_log_.AddEvent(NetLogEventType::CANCELLED);

  switch (next_state_) {
    case STATE_QUICK_CHECK_COMPLETE:
      resolve_request_.reset();
      break;
    case STATE_WAIT_COMPLETE:
      wait_timer_.Stop();
      break;
    case STATE_FETCH_PAC_SCRIPT_COMPLETE:
      pac_file_fetcher_->Cancel();
      break;
    default:
      break;
  }

  next_state_ = STATE_NONE;

  // This is safe to call in any state.
  if (dhcp_pac_file_fetcher_)
    dhcp_pac_file_fetcher_->Cancel();

  DCHECK(!resolve_request_);

  DidComplete();
}

}  // namespace net
```