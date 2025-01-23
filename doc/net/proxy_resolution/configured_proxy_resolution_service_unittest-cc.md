Response:
My goal is to analyze the provided C++ code snippet for the `configured_proxy_resolution_service_unittest.cc` file and address the user's request. Here's a breakdown of the thinking process:

1. **Understand the Core Functionality:** The file name itself is a strong clue: "configured_proxy_resolution_service_unittest". This immediately tells me the file contains unit tests for a class named `ConfiguredProxyResolutionService`. The "proxy resolution" part indicates this service is responsible for determining how network requests should be routed through proxies.

2. **Identify Key Classes and Concepts:**  Scanning the includes and the code reveals important classes:
    * `ConfiguredProxyResolutionService`: The central class being tested.
    * `ProxyConfigService`: Provides the proxy configuration (e.g., direct, PAC script, manual proxy settings).
    * `ProxyResolver`:  Responsible for evaluating PAC scripts or other proxy configurations to determine the appropriate proxy server(s).
    * `MockProxyConfigService`, `MockPacFileFetcher`, `MockProxyResolver`: Mock implementations used for testing in isolation.
    * `ProxyResolutionRequest`: Represents an individual request to resolve proxy settings for a URL.
    * `ProxyInfo`: Holds the result of proxy resolution (direct connection or a list of proxy servers).
    * `PacFileFetcher`:  Fetches the contents of PAC files.
    * `ProxyDelegate`: Allows external code to intercept and modify proxy resolution decisions.

3. **Determine the Purpose of the Unit Tests:** Unit tests aim to verify the behavior of individual components in isolation. This file likely tests various scenarios related to:
    * Resolving proxies based on different configurations (direct, manual, PAC script).
    * Handling PAC script fetching and execution.
    * Managing concurrent proxy resolution requests.
    * Handling errors during proxy resolution.
    * Interactions with the `ProxyDelegate`.
    * Testing background PAC script polling (although the provided snippet seems to focus on disabling it for general tests).

4. **Analyze Specific Code Sections:**
    * **Polling Policies (`ImmediatePollPolicy`, `NeverPollPolicy`, `ImmediateAfterActivityPollPolicy`):** These classes control how often the service checks for updates to PAC scripts. The `NeverPollPolicy` is used in the main test fixture to prevent flakiness.
    * **`ConfiguredProxyResolutionServiceTest`:** The main test fixture, setting up and tearing down the testing environment, including disabling PAC polling.
    * **`MockProxyConfigService`:** A simple mock to provide different proxy configurations to the service.
    * **`TestResolveProxyDelegate` and `TestProxyFallbackProxyDelegate`:**  These are concrete implementations of `ProxyDelegate` used to verify that the service correctly calls the delegate's methods.
    * **Helper Functions (`GetJobsForURLs`, `GetPendingJobsForURLs`, `GetCancelledJobsForURLs`):** These are utility functions to make assertions about the state of the mock proxy resolver's pending and cancelled jobs.
    * **Individual `TEST_F` functions:** Each test function focuses on a specific aspect of the service's behavior (e.g., resolving direct connections, interaction with `ProxyDelegate`, handling callbacks).

5. **Address the User's Specific Questions:**

    * **Functionality:**  Synthesize the information gathered into a concise summary of the file's purpose.
    * **Relationship with JavaScript:** Recognize that PAC scripts are JavaScript code. Explain how the tests indirectly relate to JavaScript by verifying the service's ability to fetch, interpret (through the `ProxyResolver`), and handle PAC scripts. Provide a concrete example using `kValidPacScript1`.
    * **Logical Reasoning (Input/Output):** Choose a simple test case (like the `Direct` test) and explain the expected input (a direct proxy configuration, a URL) and the output (a `ProxyInfo` indicating a direct connection).
    * **User/Programming Errors:** Identify potential errors related to misconfigured proxy settings or issues with PAC scripts. Provide examples like incorrect PAC script syntax leading to `ERR_PAC_SCRIPT_ERROR`.
    * **User Operation to Reach Here (Debugging Clue):** Describe a general scenario where a user might encounter proxy-related issues, leading a developer to investigate the `ConfiguredProxyResolutionService`. Focus on the steps involved in network requests and proxy configuration.
    * **Summary of Part 1:**  Focus on the core purpose of the first part of the file: setting up the testing infrastructure and testing basic scenarios like direct connections and interactions with the `ProxyDelegate`.

6. **Structure the Response:** Organize the information logically, using headings and bullet points for clarity. Start with a high-level summary and then delve into the specifics.

7. **Refine and Review:** Ensure the explanation is accurate, clear, and easy to understand. Double-check for any technical inaccuracies or ambiguities. For example, initially, I might have just said "tests proxy resolution", but refining it to include "handling PAC scripts, manual configurations, and direct connections" provides more detail. Also, making the JavaScript connection more explicit with an example PAC script strengthens that point.
好的，让我们来分析一下 `net/proxy_resolution/configured_proxy_resolution_service_unittest.cc` 文件的功能。

**文件功能归纳 (第 1 部分):**

这个文件的主要功能是为 Chromium 网络栈中的 `ConfiguredProxyResolutionService` 类提供单元测试。 `ConfiguredProxyResolutionService` 负责根据当前的代理配置（例如，直接连接、手动配置的代理服务器、PAC 脚本）来解析给定 URL 的代理信息。

这个文件的第一部分主要关注以下几个方面：

1. **测试框架的搭建和辅助类的定义:**
   - 定义了辅助的测试类，例如 `ImmediatePollPolicy`, `NeverPollPolicy`, `ImmediateAfterActivityPollPolicy`，用于控制 PAC 脚本的轮询行为，以便在测试中控制时间依赖性。
   - 定义了主要的测试夹具 `ConfiguredProxyResolutionServiceTest`，用于设置和清理测试环境，并默认禁用 PAC 脚本的轮询。
   - 定义了 `MockProxyConfigService`，一个用于模拟 `ProxyConfigService` 的类，可以返回预设的代理配置，方便测试不同配置下的行为。
   - 定义了 `TestResolveProxyDelegate` 和 `TestProxyFallbackProxyDelegate`，这两个类模拟了 `ProxyDelegate` 接口，用于测试 `ConfiguredProxyResolutionService` 与 `ProxyDelegate` 的交互。

2. **测试基本的代理解析场景:**
   - 测试了在直接连接配置下，`ConfiguredProxyResolutionService` 能否正确地返回直接连接的信息。
   - 测试了 `ProxyDelegate` 的 `OnResolveProxy` 回调函数是否被正确调用，以及是否能修改代理解析的结果（例如，添加或移除代理服务器）。

3. **测试异步代理解析请求的管理:**
   - 定义了辅助函数 `GetJobsForURLs`, `GetPendingJobsForURLs`, `GetCancelledJobsForURLs`，用于检查 `MockAsyncProxyResolver` 中待处理和取消的代理解析任务。
   - 测试了在代理解析过程中，如果回调函数删除了其他的代理解析请求，`ConfiguredProxyResolutionService` 是否能正确处理。
   - 测试了在代理解析过程中，如果回调函数删除了自身，`ConfiguredProxyResolutionService` 是否能正确处理。
   - 测试了当 `ConfiguredProxyResolutionService` 对象在代理解析请求完成之前被销毁时，请求的回调是否会被调用，以及调用的结果。

**与 JavaScript 功能的关系：**

这个文件与 JavaScript 的功能有间接的关系，因为它测试了与 PAC (Proxy Auto-Config) 脚本相关的代理解析逻辑。PAC 脚本本身就是用 JavaScript 编写的，浏览器会执行这些脚本来动态地确定给定 URL 的代理服务器。

**举例说明：**

在代码中，定义了 `kValidPacScript1` 和 `kValidPacScript2` 这样的常量：

```c++
const char kValidPacScript1[] = "pac-script-v1-FindProxyForURL";
const char16_t kValidPacScript116[] = u"pac-script-v1-FindProxyForURL";
const char kValidPacScript2[] = "pac-script-v2-FindProxyForURL";
const char16_t kValidPacScript216[] = u"pac-script-v2-FindProxyForURL";
```

虽然这些只是简单的字符串，但在实际使用中，它们代表的是更复杂的 JavaScript 代码。`ConfiguredProxyResolutionService` 会使用 `ProxyResolver` 来执行这些 PAC 脚本。例如，当测试代码设置 `MockProxyConfigService` 返回一个包含 PAC 文件 URL 的配置时，`ConfiguredProxyResolutionService` 就会去获取并执行这个 PAC 脚本（在测试中，通常会使用 `MockPacFileFetcher` 和 `MockAsyncProxyResolver` 来模拟这个过程）。

**假设输入与输出（逻辑推理）：**

**假设输入：**

1. **代理配置：** 一个 `MockProxyConfigService` 实例，配置为使用一个 PAC 文件，例如，PAC 文件的 URL 是 "http://foopy/proxy.pac"。
2. **PAC 文件内容：** 一个简单的 PAC 脚本，例如：
   ```javascript
   function FindProxyForURL(url, host) {
     if (host == "www.google.com") {
       return "PROXY proxy1:8080; PROXY proxy2:8080";
     }
     return "DIRECT";
   }
   ```
3. **请求的 URL：** "http://www.google.com/"

**预期输出：**

`ConfiguredProxyResolutionService` 解析的结果 (`ProxyInfo`) 应该包含代理服务器 "proxy1:8080" 和 "proxy2:8080"。

**假设输入：**

1. **代理配置：** 一个 `MockProxyConfigService` 实例，配置为使用一个 PAC 文件，例如，PAC 文件的 URL 是 "http://foopy/proxy.pac"。
2. **PAC 文件内容：**  一个总是返回 DIRECT 的 PAC 脚本：
   ```javascript
   function FindProxyForURL(url, host) {
     return "DIRECT";
   }
   ```
3. **请求的 URL：** "http://www.example.com/"

**预期输出：**

`ConfiguredProxyResolutionService` 解析的结果 (`ProxyInfo`) 应该指示直接连接。

**用户或编程常见的使用错误：**

1. **错误的 PAC 脚本语法：** 用户可能会在 PAC 脚本中编写不正确的 JavaScript 代码，导致 `ProxyResolver` 解析失败。这在 Chromium 中通常会返回 `net::ERR_PAC_SCRIPT_ERROR` 错误。
   ```c++
   TEST_F(ConfiguredProxyResolutionServiceTest, PacScriptError) {
     // ...
     resolver.pending_jobs()[0]->CompleteNowWithError(ERR_PAC_SCRIPT_ERROR);
     // ...
     EXPECT_THAT(callback.WaitForResult(), IsError(ERR_PAC_SCRIPT_ERROR));
   }
   ```

2. **错误的代理服务器配置：**  用户可能手动配置了无法连接的代理服务器，导致连接失败。这在 Chromium 中会触发代理重试机制和 `ProxyDelegate` 的 `OnFallback` 回调。

3. **忘记处理异步回调：** 开发者可能会忘记正确处理 `ConfiguredProxyResolutionService::ResolveProxy` 的异步回调，导致程序逻辑错误或者资源泄漏。这个文件中的测试用例就涵盖了这种情况，例如测试回调函数删除请求自身或其它请求的情况。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户报告网络连接问题：** 用户在使用 Chrome 浏览器时遇到无法访问网页或其他网络资源的问题。
2. **怀疑代理配置问题：** 用户或支持人员怀疑是代理配置导致了问题。
3. **检查代理设置：** 用户或支持人员会检查 Chrome 的代理设置（可以通过 `chrome://settings/` 或者操作系统的网络设置）。
4. **配置代理设置：** 用户可能尝试更改代理设置，例如切换到直接连接、手动配置代理服务器或使用 PAC 脚本 URL。
5. **发起网络请求：** 当用户尝试访问网页时，Chrome 会使用 `ConfiguredProxyResolutionService` 来解析该 URL 的代理信息。
6. **`ConfiguredProxyResolutionService` 工作：**
   - 如果配置为直接连接，则直接返回。
   - 如果配置为手动代理，则返回配置的代理服务器列表。
   - 如果配置为 PAC 脚本，则会：
     - 获取 PAC 脚本（通过 `PacFileFetcher`）。
     - 使用 `ProxyResolver` 执行 PAC 脚本中的 `FindProxyForURL` 函数。
     - 根据 PAC 脚本的返回值确定代理服务器。
7. **调试开始：** 如果代理解析过程中出现问题（例如，PAC 脚本错误、无法连接代理服务器），开发人员可能会查看 `ConfiguredProxyResolutionService` 的相关代码和日志，以定位问题。这个单元测试文件 `configured_proxy_resolution_service_unittest.cc` 就是用来验证 `ConfiguredProxyResolutionService` 各种场景下的行为是否正确的。

**总结 (第 1 部分的功能):**

这个文件的第一部分主要建立了 `ConfiguredProxyResolutionService` 的单元测试框架，并测试了服务在基本场景下的行为，例如直接连接以及与 `ProxyDelegate` 的交互。它还开始探索了异步代理解析请求的管理以及在回调函数中删除请求的场景。通过使用 mock 对象，这些测试能够隔离地验证 `ConfiguredProxyResolutionService` 的逻辑，确保其在不同的代理配置下都能正确工作。

### 提示词
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/configured_proxy_resolution_service.h"

#include <cstdarg>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/time/time.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_isolation_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/schemeful_site.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/dhcp_pac_file_fetcher.h"
#include "net/proxy_resolution/mock_pac_file_fetcher.h"
#include "net/proxy_resolution/mock_proxy_resolver.h"
#include "net/proxy_resolution/pac_file_fetcher.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_resolution_request.h"
#include "net/proxy_resolution/proxy_resolver.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using testing::ElementsAre;
using testing::Key;

using net::test::IsError;
using net::test::IsOk;

// TODO(eroman): Write a test which exercises
//              ConfiguredProxyResolutionService::SuspendAllPendingRequests().
namespace net {
namespace {

// This polling policy will decide to poll every 1 ms.
class ImmediatePollPolicy
    : public ConfiguredProxyResolutionService::PacPollPolicy {
 public:
  ImmediatePollPolicy() = default;

  ImmediatePollPolicy(const ImmediatePollPolicy&) = delete;
  ImmediatePollPolicy& operator=(const ImmediatePollPolicy&) = delete;

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::Milliseconds(1);
    return MODE_USE_TIMER;
  }
};

// This polling policy chooses a fantastically large delay. In other words, it
// will never trigger a poll
class NeverPollPolicy : public ConfiguredProxyResolutionService::PacPollPolicy {
 public:
  NeverPollPolicy() = default;

  NeverPollPolicy(const NeverPollPolicy&) = delete;
  NeverPollPolicy& operator=(const NeverPollPolicy&) = delete;

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::Days(60);
    return MODE_USE_TIMER;
  }
};

// This polling policy starts a poll immediately after network activity.
class ImmediateAfterActivityPollPolicy
    : public ConfiguredProxyResolutionService::PacPollPolicy {
 public:
  ImmediateAfterActivityPollPolicy() = default;

  ImmediateAfterActivityPollPolicy(const ImmediateAfterActivityPollPolicy&) =
      delete;
  ImmediateAfterActivityPollPolicy& operator=(
      const ImmediateAfterActivityPollPolicy&) = delete;

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::TimeDelta();
    return MODE_START_AFTER_ACTIVITY;
  }
};

// This test fixture is used to partially disable the background polling done by
// the ConfiguredProxyResolutionService (which it uses to detect whenever its
// PAC script contents or WPAD results have changed).
//
// We disable the feature by setting the poll interval to something really
// large, so it will never actually be reached even on the slowest bots that run
// these tests.
//
// We disable the polling in order to avoid any timing dependencies in the
// tests. If the bot were to run the tests very slowly and we hadn't disabled
// polling, then it might start a background re-try in the middle of our test
// and confuse our expectations leading to flaky failures.
//
// The tests which verify the polling code re-enable the polling behavior but
// are careful to avoid timing problems.
class ConfiguredProxyResolutionServiceTest : public ::testing::Test,
                                             public WithTaskEnvironment {
 protected:
  ConfiguredProxyResolutionServiceTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    testing::Test::SetUp();
    previous_policy_ =
        ConfiguredProxyResolutionService::set_pac_script_poll_policy(
            &never_poll_policy_);
  }

  void TearDown() override {
    // Restore the original policy.
    ConfiguredProxyResolutionService::set_pac_script_poll_policy(
        previous_policy_);
    testing::Test::TearDown();
  }

 private:
  NeverPollPolicy never_poll_policy_;
  raw_ptr<const ConfiguredProxyResolutionService::PacPollPolicy>
      previous_policy_;
};

const char kValidPacScript1[] = "pac-script-v1-FindProxyForURL";
const char16_t kValidPacScript116[] = u"pac-script-v1-FindProxyForURL";
const char kValidPacScript2[] = "pac-script-v2-FindProxyForURL";
const char16_t kValidPacScript216[] = u"pac-script-v2-FindProxyForURL";

class MockProxyConfigService : public ProxyConfigService {
 public:
  explicit MockProxyConfigService(const ProxyConfig& config)
      : config_(
            ProxyConfigWithAnnotation(config, TRAFFIC_ANNOTATION_FOR_TESTS)) {}

  explicit MockProxyConfigService(const std::string& pac_url)
      : config_(ProxyConfig::CreateFromCustomPacURL(GURL(pac_url)),
                TRAFFIC_ANNOTATION_FOR_TESTS) {}

  void AddObserver(Observer* observer) override {
    observers_.AddObserver(observer);
  }

  void RemoveObserver(Observer* observer) override {
    observers_.RemoveObserver(observer);
  }

  ConfigAvailability GetLatestProxyConfig(
      ProxyConfigWithAnnotation* results) override {
    if (availability_ == CONFIG_VALID)
      *results = config_;
    return availability_;
  }

  void SetConfig(const ProxyConfigWithAnnotation& config) {
    availability_ = CONFIG_VALID;
    config_ = config;
    for (auto& observer : observers_)
      observer.OnProxyConfigChanged(config_, availability_);
  }

  void SetPacUrlConfig(std::string_view pac_url) {
    SetConfig(ProxyConfigWithAnnotation(
        ProxyConfig::CreateFromCustomPacURL(GURL(pac_url)),
        TRAFFIC_ANNOTATION_FOR_TESTS));
  }

 private:
  ConfigAvailability availability_ = CONFIG_VALID;
  ProxyConfigWithAnnotation config_;
  base::ObserverList<Observer, true>::Unchecked observers_;
};

// A test network delegate that exercises the OnResolveProxy callback.
class TestResolveProxyDelegate : public ProxyDelegate {
 public:
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {
    method_ = method;
    num_resolve_proxy_called_++;
    network_anonymization_key_ = network_anonymization_key;
    proxy_retry_info_ = proxy_retry_info;
    DCHECK(!add_proxy_ || !remove_proxy_);
    if (add_proxy_) {
      result->UseNamedProxy("delegate_proxy.com");
    } else if (remove_proxy_) {
      result->UseDirect();
    }
  }

  int num_resolve_proxy_called() const { return num_resolve_proxy_called_; }

  const std::string& method() const { return method_; }

  void set_add_proxy(bool add_proxy) { add_proxy_ = add_proxy; }

  void set_remove_proxy(bool remove_proxy) { remove_proxy_ = remove_proxy; }

  NetworkAnonymizationKey network_anonymization_key() const {
    return network_anonymization_key_;
  }

  const ProxyRetryInfoMap& proxy_retry_info() const {
    return proxy_retry_info_;
  }

  void OnSuccessfulRequestAfterFailures(
      const ProxyRetryInfoMap& proxy_retry_info) override {}

  void OnFallback(const ProxyChain& bad_chain, int net_error) override {}

  Error OnBeforeTunnelRequest(const ProxyChain& proxy_chain,
                              size_t chain_index,
                              HttpRequestHeaders* extra_headers) override {
    return OK;
  }

  Error OnTunnelHeadersReceived(
      const ProxyChain& proxy_chain,
      size_t chain_index,
      const HttpResponseHeaders& response_headers) override {
    return OK;
  }

  void SetProxyResolutionService(
      ProxyResolutionService* proxy_resolution_service) override {}

 private:
  int num_resolve_proxy_called_ = 0;
  bool add_proxy_ = false;
  bool remove_proxy_ = false;
  std::string method_;
  NetworkAnonymizationKey network_anonymization_key_;
  ProxyRetryInfoMap proxy_retry_info_;
};

// A test network delegate that exercises the OnProxyFallback callback.
class TestProxyFallbackProxyDelegate : public ProxyDelegate {
 public:
  // ProxyDelegate implementation:
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {}

  void OnSuccessfulRequestAfterFailures(
      const ProxyRetryInfoMap& proxy_retry_info) override {
    last_proxy_retry_info_ = proxy_retry_info;
  }

  void OnFallback(const ProxyChain& bad_chain, int net_error) override {
    proxy_chain_ = bad_chain;
    last_proxy_fallback_net_error_ = net_error;
    num_proxy_fallback_called_++;
  }

  Error OnBeforeTunnelRequest(const ProxyChain& proxy_chain,
                              size_t chain_index,
                              HttpRequestHeaders* extra_headers) override {
    return OK;
  }

  Error OnTunnelHeadersReceived(
      const ProxyChain& proxy_chain,
      size_t chain_index,
      const HttpResponseHeaders& response_headers) override {
    return OK;
  }

  void SetProxyResolutionService(
      ProxyResolutionService* proxy_resolution_service) override {}

  bool num_proxy_fallback_called() const { return num_proxy_fallback_called_; }

  const ProxyChain& proxy_chain() const { return proxy_chain_; }

  int last_proxy_fallback_net_error() const {
    return last_proxy_fallback_net_error_;
  }

  const ProxyRetryInfoMap& last_proxy_retry_info() const {
    return last_proxy_retry_info_;
  }

 private:
  int num_proxy_fallback_called_ = 0;
  ProxyChain proxy_chain_;
  int last_proxy_fallback_net_error_ = OK;
  ProxyRetryInfoMap last_proxy_retry_info_;
};

using JobMap = std::map<GURL, MockAsyncProxyResolver::Job*>;

// Given a jobmap and a list of target URLs |urls|, asserts that the set of URLs
// of the jobs appearing in |list| is exactly the set of URLs in |urls|.
JobMap GetJobsForURLs(const JobMap& map, const std::vector<GURL>& urls) {
  size_t a = urls.size();
  size_t b = map.size();
  if (a != b) {
    ADD_FAILURE() << "map size (" << map.size() << ") != urls size ("
                  << urls.size() << ")";
    return map;
  }
  for (const auto& it : urls) {
    if (map.count(it) != 1U) {
      ADD_FAILURE() << "url not in map: " << it.spec();
      break;
    }
  }
  return map;
}

// Given a MockAsyncProxyResolver |resolver| and some GURLs, validates that the
// set of pending request URLs for |resolver| is exactly the supplied list of
// URLs and returns a map from URLs to the corresponding pending jobs.
JobMap GetPendingJobsForURLs(const MockAsyncProxyResolver& resolver,
                             const GURL& url1 = GURL(),
                             const GURL& url2 = GURL(),
                             const GURL& url3 = GURL()) {
  std::vector<GURL> urls;
  if (!url1.is_empty())
    urls.push_back(url1);
  if (!url2.is_empty())
    urls.push_back(url2);
  if (!url3.is_empty())
    urls.push_back(url3);

  JobMap map;
  for (MockAsyncProxyResolver::Job* it : resolver.pending_jobs()) {
    DCHECK(it);
    map[it->url()] = it;
  }

  return GetJobsForURLs(map, urls);
}

// Given a MockAsyncProxyResolver |resolver| and some GURLs, validates that the
// set of cancelled request URLs for |resolver| is exactly the supplied list of
// URLs and returns a map from URLs to the corresponding cancelled jobs.
JobMap GetCancelledJobsForURLs(const MockAsyncProxyResolver& resolver,
                               const GURL& url1 = GURL(),
                               const GURL& url2 = GURL(),
                               const GURL& url3 = GURL()) {
  std::vector<GURL> urls;
  if (!url1.is_empty())
    urls.push_back(url1);
  if (!url2.is_empty())
    urls.push_back(url2);
  if (!url3.is_empty())
    urls.push_back(url3);

  JobMap map;
  for (const std::unique_ptr<MockAsyncProxyResolver::Job>& it :
       resolver.cancelled_jobs()) {
    DCHECK(it);
    map[it->url()] = it.get();
  }

  return GetJobsForURLs(map, urls);
}

}  // namespace

TEST_F(ConfiguredProxyResolutionServiceTest, Direct) {
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateDirect()),
      std::move(factory), nullptr, /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  RecordingNetLogObserver net_log_observer;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                &info, callback.callback(), &request,
                                NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  EXPECT_TRUE(info.is_direct());
  EXPECT_TRUE(info.proxy_resolve_start_time().is_null());
  EXPECT_TRUE(info.proxy_resolve_end_time().is_null());

  // Check the NetLog was filled correctly.
  auto entries = net_log_observer.GetEntries();

  EXPECT_EQ(3u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::PROXY_RESOLUTION_SERVICE));
  EXPECT_TRUE(LogContainsEvent(
      entries, 1, NetLogEventType::PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries, 2,
                                  NetLogEventType::PROXY_RESOLUTION_SERVICE));
}

TEST_F(ConfiguredProxyResolutionServiceTest, OnResolveProxyCallbackAddProxy) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("badproxy:8080,foopy1:8080");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
      /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");
  GURL bypass_url("http://internet.org");

  ProxyInfo info;
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);

  // First, warm up the ConfiguredProxyResolutionService and fake an error to
  // mark the first server as bad.
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, net_log_with_source);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("[badproxy:8080]", info.proxy_chain().ToDebugString());

  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  service.ReportSuccess(info);

  // Verify that network delegate is invoked.
  TestResolveProxyDelegate delegate;
  service.SetProxyDelegate(&delegate);
  rv = service.ResolveProxy(url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_EQ(1, delegate.num_resolve_proxy_called());
  EXPECT_THAT(delegate.proxy_retry_info(),
              ElementsAre(Key(ProxyChain(ProxyUriToProxyChain(
                  "badproxy:8080", ProxyServer::SCHEME_HTTP)))));
  EXPECT_EQ(delegate.method(), "GET");

  // Verify that the ProxyDelegate's behavior is stateless across
  // invocations of ResolveProxy. Start by having the callback add a proxy
  // and checking that subsequent jobs are not affected.
  delegate.set_add_proxy(true);

  // Callback should interpose:
  rv = service.ResolveProxy(url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[delegate_proxy.com:80]", info.proxy_chain().ToDebugString());
  delegate.set_add_proxy(false);

  // Check non-bypassed URL:
  rv = service.ResolveProxy(url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Check bypassed URL:
  rv = service.ResolveProxy(bypass_url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_TRUE(info.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       OnResolveProxyCallbackRemoveProxy) {
  // Same as OnResolveProxyCallbackAddProxy, but verify that the
  // ProxyDelegate's behavior is stateless across invocations after it
  // *removes* a proxy.
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
      /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");
  GURL bypass_url("http://internet.org");

  ProxyInfo info;
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);

  // First, warm up the ConfiguredProxyResolutionService.
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, net_log_with_source);
  EXPECT_THAT(rv, IsOk());

  TestResolveProxyDelegate delegate;
  service.SetProxyDelegate(&delegate);
  delegate.set_remove_proxy(true);

  // Callback should interpose:
  rv = service.ResolveProxy(url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_TRUE(info.is_direct());
  delegate.set_remove_proxy(false);

  // Check non-bypassed URL:
  rv = service.ResolveProxy(url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Check bypassed URL:
  rv = service.ResolveProxy(bypass_url, "GET", NetworkAnonymizationKey(), &info,
                            callback.callback(), &request, net_log_with_source);
  EXPECT_TRUE(info.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest, OnResolveProxyHasNak) {
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateDirect()),
      std::move(factory), nullptr, /*quick_check_enabled=*/true);

  auto proxy_delegate = TestResolveProxyDelegate();
  service.SetProxyDelegate(&proxy_delegate);

  GURL url("http://www.google.com/");
  NetworkAnonymizationKey network_anonymization_key =
      NetworkAnonymizationKey::CreateCrossSite(
          SchemefulSite(GURL("http://example.com")));

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  service.ResolveProxy(url, std::string(), network_anonymization_key, &info,
                       callback.callback(), &request,
                       NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_EQ(network_anonymization_key,
            proxy_delegate.network_anonymization_key());
}

// Test callback that deletes an item when called.  This is used to test various
// permutations of important objects being deleted in the middle of a series of
// requests.
template <typename T>
class DeletingCallback : public TestCompletionCallbackBase {
 public:
  explicit DeletingCallback(std::unique_ptr<T>* deletee);

  DeletingCallback(const DeletingCallback&) = delete;
  DeletingCallback& operator=(const DeletingCallback&) = delete;

  ~DeletingCallback() override;

  CompletionOnceCallback callback() {
    return base::BindOnce(&DeletingCallback::DeleteItem,
                          base::Unretained(this));
  }

 private:
  void DeleteItem(int result) {
    deletee_->reset();
    SetResult(result);
  }

  raw_ptr<std::unique_ptr<T>> deletee_;
};

template <typename T>
DeletingCallback<T>::DeletingCallback(std::unique_ptr<T>* deletee)
    : deletee_(deletee) {}

template <typename T>
DeletingCallback<T>::~DeletingCallback() = default;

// Test that the ConfiguredProxyResolutionService correctly handles the case
// where a request callback deletes another request.
TEST_F(ConfiguredProxyResolutionServiceTest, CallbackDeletesRequest) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  std::unique_ptr<ConfiguredProxyResolutionService> service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(config_service), std::move(factory), nullptr,
          /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");
  GURL url2("http://www.example.com/");

  ProxyInfo info;
  std::unique_ptr<ProxyResolutionRequest> request, request2;
  DeletingCallback<ProxyResolutionRequest> callback(&request2);
  net::CompletionOnceCallback callback2 =
      base::BindOnce([](int result) { ASSERT_FALSE(true); });

  int rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback.callback(), &request,
                                 NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = service->ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                             &info, std::move(callback2), &request2,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Run pending requests.
  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(2u, resolver.pending_jobs().size());
  // Job order is nondeterministic, as requests are stored in an std::set, so
  // this loop figures out which one is the correct one to start.
  int deleting_job = 2;
  for (int i = 0; i < 2; i++) {
    if (resolver.pending_jobs()[i]->url() == url) {
      deleting_job = i;
      break;
    }
    ASSERT_LE(i, 1);  // The loop should never actually make it to the end.
  }

  // Set the result in proxy resolver.
  resolver.pending_jobs()[deleting_job]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[deleting_job]->CompleteNow(OK);

  //// Only one of the callbacks should have been run:
  EXPECT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_EQ(0u, resolver.pending_jobs().size());
  ASSERT_EQ(1u, resolver.cancelled_jobs().size());
  ASSERT_EQ(url2, resolver.cancelled_jobs()[0]->url());
}

// Test that the ConfiguredProxyResolutionService correctly handles the case
// where a request callback deletes another request.  (Triggered by the loop in
// ConfiguredProxyResolutionService's destructor).
TEST_F(ConfiguredProxyResolutionServiceTest,
       CallbackDeletesRequestDuringDestructor) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);

  std::unique_ptr<ConfiguredProxyResolutionService> service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(config_service), std::move(factory), nullptr,
          /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  std::unique_ptr<ProxyResolutionRequest> request, request2;
  DeletingCallback<ProxyResolutionRequest> callback(&request2),
      callback2(&request);

  int rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback.callback(), &request,
                                 NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback2.callback(), &request2,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Make sure that ProxyResolutionServices is deleted before the requests, as
  // this triggers completion of the pending requests.
  service.reset();

  // Only one of the callbacks should have been run:
  EXPECT_TRUE(callback.have_result() ^ callback2.have_result());

  // Callbacks run during destruction of ConfiguredProxyResolutionService for
  // Requests that have not been started are called with net::ERR_ABORTED
  if (callback.have_result()) {
    EXPECT_THAT(callback.WaitForResult(),
                IsError(net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  }
  if (callback2.have_result()) {
    EXPECT_THAT(callback2.WaitForResult(),
                IsError(net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  }
}

// Test that the ConfiguredProxyResolutionService correctly handles the case
// where a request callback deletes its own handle.
TEST_F(ConfiguredProxyResolutionServiceTest, CallbackDeletesSelf) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  std::unique_ptr<ConfiguredProxyResolutionService> service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(config_service), std::move(factory), nullptr,
          /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");
  ProxyInfo info;

  std::unique_ptr<ProxyResolutionRequest> request1;
  TestCompletionCallback callback1;
  int rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback1.callback(), &request1,
                                 NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  GURL url2("http://www.example.com/");
  std::unique_ptr<ProxyResolutionRequest> request2;
  DeletingCallback<ProxyResolutionRequest> callback2(&request2);
  rv = service->ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                             &info, callback2.callback(), &request2,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  std::unique_ptr<ProxyResolutionRequest> request3;
  TestCompletionCallback callback3;
  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback3.callback(), &request3,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(3u, resolver.pending_jobs().size());
  // Job order is nondeterministic, as requests are stored in an std::set, so
  // this loop figures out which one is the correct one to start.
  int self_deleting_job = 3;
  for (int i = 0; i < 3; i++) {
    if (resolver.pending_jobs()[i]->url() == url2) {
      self_deleting_job = i;
      break;
    }
    ASSERT_LE(i, 2);  // The loop should never actually make it to the end.
  }

  // Set the result in proxy resolver.
  resolver.pending_jobs()[self_deleting_job]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[self_deleting_job]->CompleteNow(OK);

  ASSERT_EQ(2u, resolver.pending_jobs().size());
  ASSERT_EQ(0u, resolver.cancelled_jobs().size());
  ASSERT_EQ(url, resolver.pending_jobs()[0]->url());
  ASSERT_EQ(url, resolver.pending_jobs()[1]->url());
}

// Test that the ConfiguredProxyResolutionService correctly handles the case
// where a request callback deletes its own handle, when triggered by
// ConfiguredProxyResolutionService's destructor.
TEST_F(ConfiguredProxyResolutionServiceTest,
       CallbackDeletesSelfDuringDestructor) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);

  std::unique_ptr<ConfiguredProxyResolutionService> service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(config_service), std::move(factory), nullptr,
          /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");
  ProxyInfo info;

  std::unique_ptr<ProxyResolutionRequest> request1;
  TestCompletionCallback callback1;
  int rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback1.callback(), &request1,
                                 NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  std::unique_ptr<ProxyResolutionRequest> request2;
  DeletingCallback<ProxyResolutionRequest> callback2(&request2);
  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback2.callback(), &request2,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  std::unique_ptr<ProxyResolutionRequest> request3;
  TestCompletionCallback callback3;
  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback3.callback(), &request3,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  service.reset();

  EXPECT_THAT(callback1.WaitForResult(),
              IsError(net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  EXPECT_THAT(callback2.WaitForResult(),
              IsError(net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  EXPECT_THAT(callback3.WaitForResult(),
              IsError(net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyServiceDeletedBeforeRequest) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;

  int rv;
  {
    ConfiguredProxyResolutionService service(std::move(config_service),
                                             std::move(factory), nullptr,
                                             /*quick_check_enabled=*/true);
    rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                              &info, callback.callback(), &request,
                              NetLogWithSource::Make(NetLogSourceType::NONE));
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    E
```