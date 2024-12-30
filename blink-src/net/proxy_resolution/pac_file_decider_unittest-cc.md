Response:
Let's break down the thought process for analyzing the given C++ unittest file.

1. **Understand the Goal:** The request asks for the functionality of `pac_file_decider_unittest.cc`, its relation to JavaScript, logical inferences with examples, common usage errors, and debugging steps. Essentially, it's about understanding what this test file is *testing*.

2. **Identify the Core Component:** The filename `pac_file_decider_unittest.cc` immediately points to the central component being tested: `PacFileDecider`. This class is part of the Chromium network stack.

3. **Analyze Includes:** The `#include` directives provide clues about the dependencies and related functionalities. Key includes are:
    * `net/proxy_resolution/pac_file_decider.h`: Confirms the focus on `PacFileDecider`.
    * `net/proxy_resolution/pac_file_fetcher.h`, `net/proxy_resolution/dhcp_pac_file_fetcher.h`: Indicates that `PacFileDecider` interacts with classes responsible for fetching PAC files.
    * `net/proxy_resolution/proxy_config.h`: Suggests that `PacFileDecider` makes decisions based on proxy configurations.
    * `net/log/...`:  Implies logging is important for understanding `PacFileDecider`'s behavior.
    * `net/url_request/...`: Shows involvement with URL requests, a fundamental part of network operations.
    * `testing/gtest/...`:  Confirms that this is a unit test file using the Google Test framework.

4. **Examine Test Structure:**  The file uses `TEST` macros from gtest. Each `TEST` case focuses on a specific scenario or aspect of `PacFileDecider`'s behavior. Reading the names of the tests gives a high-level overview of what's being tested (e.g., `CustomPacSucceeds`, `AutodetectSuccess`, `CustomPacFails1`).

5. **Dissect Individual Tests:**  Select a few representative tests to understand the testing methodology. For example:
    * **`CustomPacSucceeds`:**  This test sets up a `ProxyConfig` with a specific PAC URL. It uses a mock `PacFileFetcher` (`RuleBasedPacFileFetcher`) to simulate a successful download. It then verifies that `PacFileDecider` correctly fetches the script and that the effective configuration reflects the custom PAC URL. It also checks NetLog entries.
    * **`AutodetectSuccess`:** This test simulates a successful automatic proxy detection (WPAD). It verifies that `PacFileDecider` attempts to fetch `http://wpad/wpad.dat` and succeeds.
    * **Tests with "Fails":**  These tests explore error scenarios like failed downloads (`CustomPacFails1`) and parsing errors (`CustomPacFails2`).
    * **Tests involving `MockDhcpPacFileFetcher`:** These tests examine how `PacFileDecider` handles DHCP-based PAC file discovery.
    * **Tests with `QuickCheck`:** These tests focus on an optimization where `PacFileDecider` tries to quickly determine if a PAC file exists before fully attempting auto-detection.

6. **Identify Key Mock Objects:** The file defines custom mock classes like `RuleBasedPacFileFetcher`, `MockDhcpPacFileFetcher`, and `MockPacFileFetcher`. These mocks are crucial for isolating the `PacFileDecider` and controlling the behavior of its dependencies during testing.

7. **Relate to JavaScript:**  PAC files contain JavaScript code (specifically, the `FindProxyForURL` function). The tests indirectly relate to JavaScript because they verify that `PacFileDecider` can successfully fetch and process the *content* of these JavaScript files. The `Rule::text()` method demonstrates how the test constructs a simulated PAC script containing `FindProxyForURL`. The parsing failures indicate scenarios where the JavaScript in the PAC file is invalid.

8. **Infer Logical Reasoning:** Observe how the tests set up different `ProxyConfig` objects (with custom PAC URLs, auto-detection enabled, etc.) and then check the resulting `effective_config()` and `script_data()`. This demonstrates the logic `PacFileDecider` uses to choose a PAC file source. Consider the "fallback" scenarios where auto-detection fails and a custom PAC URL is then tried.

9. **Consider User and Programming Errors:**  Think about how misconfigurations or coding errors might lead to the failure scenarios tested. For instance, a user entering an incorrect PAC URL, a network issue preventing PAC file download, or a malformed PAC script would all be reasons for failures that these tests cover. The test where the `PacFileFetcher` is `nullptr` demonstrates a clear programming error.

10. **Trace User Actions (Debugging Clues):**  Imagine the user journey leading to `PacFileDecider` being invoked. This could involve:
    * Manually configuring proxy settings in the browser or OS.
    * The system automatically detecting proxy settings via WPAD/DHCP.
    * A website's server requiring a proxy.
    * A network administrator setting proxy policies.

11. **Synthesize and Organize:**  Group the findings into the requested categories: functionality, JavaScript relation, logical inferences, usage errors, and debugging clues. Use clear and concise language. Provide concrete examples based on the test cases.

12. **Review and Refine:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check for any ambiguities or missing information. For example, initially, one might focus too much on the technical details of the C++ code and miss the connection to the JavaScript content of PAC files. A review helps catch such omissions.
The file `net/proxy_resolution/pac_file_decider_unittest.cc` is a unit test file for the `PacFileDecider` class in Chromium's network stack. Its primary function is to **thoroughly test the logic and behavior of the `PacFileDecider` class**. This class is responsible for determining the source and content of the Proxy Auto-Config (PAC) file that will be used for proxy resolution.

Here's a breakdown of its functionalities and relationships:

**Core Functionality Under Test: `PacFileDecider`**

The `PacFileDecider` class orchestrates the process of finding a PAC file based on different configuration options:

* **Explicit PAC URL:** If a specific PAC URL is provided in the proxy settings, `PacFileDecider` attempts to fetch it.
* **Auto-detection (WPAD):** If auto-detection is enabled, `PacFileDecider` attempts to discover a PAC file using the Web Proxy Auto-Discovery (WPAD) protocol, which involves:
    * **DHCP:** Checking if a PAC URL is provided via DHCP.
    * **DNS:** Performing DNS lookups for `WPAD` to find a PAC file hosted on the network.

**Functionalities Tested by the Unit Tests:**

The tests in this file cover various scenarios and edge cases related to `PacFileDecider`'s behavior:

* **Successful retrieval of PAC files:**
    * From a custom (explicitly configured) URL.
    * Through successful auto-detection (WPAD via DNS).
    * Through successful auto-detection (WPAD via DHCP).
* **Failure scenarios for PAC file retrieval:**
    * **Download failures:**  Simulating network errors while fetching a PAC file.
    * **Parsing failures:** Simulating errors when the fetched PAC file contains invalid JavaScript.
    * **DNS resolution failures:**  Testing scenarios where the DNS lookup for WPAD fails.
    * **DHCP failures:**  Testing scenarios where DHCP doesn't provide a PAC URL or provides an invalid one.
* **Interaction with dependencies:**
    * Testing with mock implementations of `PacFileFetcher` (for fetching from URLs) and `DhcpPacFileFetcher` (for fetching via DHCP). This allows for controlled simulation of different outcomes.
* **Quick check optimization:** Testing an optimization where `PacFileDecider` quickly checks if a WPAD host exists before proceeding with full auto-detection.
* **Handling of delays:** Testing how `PacFileDecider` behaves with specified delays before attempting to fetch PAC files.
* **Cancellation and shutdown:** Ensuring that `PacFileDecider` correctly handles cancellation requests and shutdowns, especially during asynchronous operations.
* **NetLog integration:** Verifying that `PacFileDecider` logs relevant events to the NetLog for debugging and monitoring.
* **Effective configuration:** Checking that `PacFileDecider` correctly updates the effective proxy configuration based on the chosen PAC file source.

**Relationship with JavaScript:**

The `PacFileDecider` is directly related to JavaScript because **PAC files contain JavaScript code**. The primary purpose of a PAC file is to define the `FindProxyForURL(url, host)` JavaScript function. This function determines which proxy server (or direct connection) should be used for a given URL.

The tests demonstrate this relationship in the following ways:

* **Simulating Successful PAC Scripts:** The `Rules` class and `RuleBasedPacFileFetcher` are used to create mock PAC file content. The `Rule::text()` method constructs strings like `"http://custom/proxy.pac!FindProxyForURL"`. This implicitly acknowledges that a valid PAC file will contain the `FindProxyForURL` function.
    ```c++
    std::u16string text() const {
      if (is_valid_script)
        return base::UTF8ToUTF16(url.spec() + "!FindProxyForURL");
      // ...
    }
    ```
    Here, the test doesn't execute the JavaScript, but it verifies that the `PacFileDecider` successfully retrieves the *content* that is expected to be a JavaScript function.

* **Simulating Parsing Failures:** The tests include scenarios where the `is_valid_script` flag is false, or specific "fail parsing" rules are added. This represents cases where the fetched PAC file contains invalid JavaScript that the PAC engine would fail to parse.
    ```c++
    if (fetch_error == OK)
      return base::UTF8ToUTF16(url.spec() + "!invalid-script");
    ```
    This line simulates a scenario where the download is successful (fetch_error is OK), but the content is deliberately set to something that would not be valid JavaScript.

**Examples of Logical Inferences (with Assumptions):**

Let's consider the `AutodetectSuccess` test:

* **Assumption:** The network is configured such that a DNS lookup for `wpad` resolves to a server hosting a valid PAC file at `http://wpad/wpad.dat`.
* **Input:**  A `ProxyConfig` with `auto_detect` set to `true`.
* **Output:** The `PacFileDecider` successfully fetches the content of `http://wpad/wpad.dat`, and `decider.script_data().data->utf16()` will contain the content of that file (e.g., something like `"function FindProxyForURL(url, host) { return "DIRECT"; }" `). `decider.script_data().from_auto_detect` will be `true`.

Consider the `CustomPacFails1` test:

* **Assumption:** The server at `http://custom/proxy.pac` is either down or returns an error that results in `ERR_CONNECTION_CLOSED`.
* **Input:** A `ProxyConfig` with `pac_url` set to `http://custom/proxy.pac`.
* **Output:** The `PacFileDecider` fails to download the PAC file, and the `Start` method returns `IsError(kFailedDownloading)`. `decider.script_data().data` will be `nullptr`.

**Common Usage Errors (User or Programming):**

* **User Error:**
    * **Incorrect PAC URL:** A user might manually enter an incorrect or non-existent PAC URL in their proxy settings. Tests like `CustomPacFails1` simulate this scenario.
    * **Network issues preventing PAC download:**  If a user's network has problems connecting to the PAC file server, the download will fail. This is also covered by tests like `CustomPacFails1`.
* **Programming Error:**
    * **Incorrectly implementing `PacFileFetcher`:** If a custom implementation of `PacFileFetcher` has errors in its `Fetch` method, it could lead to unexpected failures.
    * **Not handling PAC parsing errors:** If the code using the `PacFileDecider` doesn't properly handle cases where the PAC script is invalid, it could lead to application errors. The tests with "FailParsing" highlight this.
    * **Passing `nullptr` for `PacFileFetcher`:** The `HasNullPacFileFetcher` test explicitly checks for this error.

**User Operations to Reach This Code (Debugging Clues):**

To reach the `PacFileDecider`, the following user operations (or system configurations) could occur:

1. **Manual Proxy Configuration:**
   * A user opens their operating system or browser settings.
   * They navigate to the proxy configuration section.
   * They select "Manual proxy configuration" or similar.
   * They enter a "PAC script URL" or "Automatic proxy configuration URL". This URL is then used by the `PacFileDecider`.

2. **Automatic Proxy Detection (WPAD):**
   * A user's network is configured to automatically provide proxy settings via WPAD.
   * The user's operating system or browser is configured to "Automatically detect settings".
   * The system will then attempt to discover the PAC file using DHCP and/or DNS, triggering the logic within `PacFileDecider`.

3. **Policy Enforcement:**
   * In a managed environment (e.g., a corporate network), proxy settings, including PAC URLs or auto-detection settings, might be enforced through group policies or other management tools. The system will then use these enforced settings, leading to the `PacFileDecider` being invoked.

4. **Programmatic Proxy Configuration:**
   * An application might programmatically configure proxy settings using APIs provided by the operating system or browser. This configuration could include a PAC URL, leading to `PacFileDecider`'s involvement.

**As a Debugging Clue:** If a user is experiencing issues with proxy settings, a developer might investigate the behavior of the `PacFileDecider` by:

* **Examining NetLog:** The NetLog captures events related to proxy resolution, including the attempts made by `PacFileDecider` to fetch and process PAC files. This can reveal whether the PAC URL is being fetched correctly, if there are DNS resolution errors, or if the PAC script is failing to parse. The tests in this file demonstrate how to verify the NetLog output.
* **Stepping through the code:** Using a debugger, a developer can step through the `PacFileDecider`'s logic to see exactly how it's attempting to find and process the PAC file based on the current configuration. The unit tests themselves serve as examples of how different scenarios are handled.
* **Reproducing test cases:** Developers can use the unit tests in this file to reproduce specific error scenarios locally to understand the root cause of a user's problem.

In summary, `net/proxy_resolution/pac_file_decider_unittest.cc` is a crucial component for ensuring the correctness and robustness of Chromium's proxy auto-configuration functionality. It meticulously tests various aspects of `PacFileDecider`, including its interaction with PAC files (and thus JavaScript), its handling of different configuration options, and its behavior under various error conditions.

Prompt: 
```
这是目录为net/proxy_resolution/pac_file_decider_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/dhcp_pac_file_fetcher.h"
#include "net/proxy_resolution/mock_pac_file_fetcher.h"
#include "net/proxy_resolution/pac_file_decider.h"
#include "net/proxy_resolution/pac_file_fetcher.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_resolver.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

enum Error {
  kFailedDownloading = ERR_CONNECTION_CLOSED,
  kFailedParsing = ERR_PAC_SCRIPT_FAILED,
};

class Rules {
 public:
  struct Rule {
    Rule(const GURL& url, int fetch_error, bool is_valid_script)
        : url(url),
          fetch_error(fetch_error),
          is_valid_script(is_valid_script) {}

    std::u16string text() const {
      if (is_valid_script)
        return base::UTF8ToUTF16(url.spec() + "!FindProxyForURL");
      if (fetch_error == OK)
        return base::UTF8ToUTF16(url.spec() + "!invalid-script");
      return std::u16string();
    }

    GURL url;
    int fetch_error;
    bool is_valid_script;
  };

  Rule AddSuccessRule(const char* url) {
    Rule rule(GURL(url), OK /*fetch_error*/, true);
    rules_.push_back(rule);
    return rule;
  }

  void AddFailDownloadRule(const char* url) {
    rules_.push_back(
        Rule(GURL(url), kFailedDownloading /*fetch_error*/, false));
  }

  void AddFailParsingRule(const char* url) {
    rules_.push_back(Rule(GURL(url), OK /*fetch_error*/, false));
  }

  const Rule& GetRuleByUrl(const GURL& url) const {
    for (const auto& rule : rules_) {
      if (rule.url == url)
        return rule;
    }
    LOG(FATAL) << "Rule not found for " << url;
  }

 private:
  typedef std::vector<Rule> RuleList;
  RuleList rules_;
};

class RuleBasedPacFileFetcher : public PacFileFetcher {
 public:
  explicit RuleBasedPacFileFetcher(const Rules* rules) : rules_(rules) {}

  virtual void SetRequestContext(URLRequestContext* context) {
    request_context_ = context;
  }

  // PacFileFetcher implementation.
  int Fetch(const GURL& url,
            std::u16string* text,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag traffic_annotation) override {
    const Rules::Rule& rule = rules_->GetRuleByUrl(url);
    int rv = rule.fetch_error;
    EXPECT_NE(ERR_UNEXPECTED, rv);
    if (rv == OK)
      *text = rule.text();
    return rv;
  }

  void Cancel() override {}

  void OnShutdown() override { request_context_ = nullptr; }

  URLRequestContext* GetRequestContext() const override {
    return request_context_;
  }

 private:
  raw_ptr<const Rules> rules_;
  raw_ptr<URLRequestContext, DanglingUntriaged> request_context_ = nullptr;
};

// A mock retriever, returns asynchronously when CompleteRequests() is called.
class MockDhcpPacFileFetcher : public DhcpPacFileFetcher {
 public:
  MockDhcpPacFileFetcher();

  MockDhcpPacFileFetcher(const MockDhcpPacFileFetcher&) = delete;
  MockDhcpPacFileFetcher& operator=(const MockDhcpPacFileFetcher&) = delete;

  ~MockDhcpPacFileFetcher() override;

  int Fetch(std::u16string* utf16_text,
            CompletionOnceCallback callback,
            const NetLogWithSource& net_log,
            const NetworkTrafficAnnotationTag traffic_annotation) override;
  void Cancel() override;
  void OnShutdown() override;
  const GURL& GetPacURL() const override;

  virtual void SetPacURL(const GURL& url);

  virtual void CompleteRequests(int result, const std::u16string& script);

 private:
  CompletionOnceCallback callback_;
  raw_ptr<std::u16string> utf16_text_;
  GURL gurl_;
};

MockDhcpPacFileFetcher::MockDhcpPacFileFetcher() = default;

MockDhcpPacFileFetcher::~MockDhcpPacFileFetcher() = default;

int MockDhcpPacFileFetcher::Fetch(
    std::u16string* utf16_text,
    CompletionOnceCallback callback,
    const NetLogWithSource& net_log,
    const NetworkTrafficAnnotationTag traffic_annotation) {
  utf16_text_ = utf16_text;
  callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

void MockDhcpPacFileFetcher::Cancel() {}

void MockDhcpPacFileFetcher::OnShutdown() {}

const GURL& MockDhcpPacFileFetcher::GetPacURL() const {
  return gurl_;
}

void MockDhcpPacFileFetcher::SetPacURL(const GURL& url) {
  gurl_ = url;
}

void MockDhcpPacFileFetcher::CompleteRequests(int result,
                                              const std::u16string& script) {
  *utf16_text_ = script;
  std::move(callback_).Run(result);
}

// Succeed using custom PAC script.
TEST(PacFileDeciderTest, CustomPacSucceeds) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  RecordingNetLogObserver observer;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, net::NetLog::Get());
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsOk());
  EXPECT_EQ(rule.text(), decider.script_data().data->utf16());
  EXPECT_FALSE(decider.script_data().from_auto_detect);

  // Check the NetLog was filled correctly.
  auto entries = observer.GetEntries();

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PAC_FILE_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PAC_FILE_DECIDER));

  EXPECT_TRUE(decider.effective_config().value().has_pac_url());
  EXPECT_EQ(config.pac_url(), decider.effective_config().value().pac_url());
}

// Fail downloading the custom PAC script.
TEST(PacFileDeciderTest, CustomPacFails1) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  RecordingNetLogObserver observer;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, net::NetLog::Get());
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(kFailedDownloading));
  EXPECT_FALSE(decider.script_data().data);

  // Check the NetLog was filled correctly.
  auto entries = observer.GetEntries();

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PAC_FILE_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PAC_FILE_DECIDER));

  EXPECT_FALSE(decider.effective_config().value().has_pac_url());
}

// Fail parsing the custom PAC script.
TEST(PacFileDeciderTest, CustomPacFails2) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailParsingRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(kFailedParsing));
  EXPECT_FALSE(decider.script_data().data);
}

// Fail downloading the custom PAC script, because the fetcher was NULL.
TEST(PacFileDeciderTest, HasNullPacFileFetcher) {
  Rules rules;
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  TestCompletionCallback callback;
  PacFileDecider decider(nullptr, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(ERR_UNEXPECTED));
  EXPECT_FALSE(decider.script_data().data);
}

// Succeeds in choosing autodetect (WPAD DNS).
TEST(PacFileDeciderTest, AutodetectSuccess) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);

  Rules::Rule rule = rules.AddSuccessRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsOk());
  EXPECT_EQ(rule.text(), decider.script_data().data->utf16());
  EXPECT_TRUE(decider.script_data().from_auto_detect);

  EXPECT_TRUE(decider.effective_config().value().has_pac_url());
  EXPECT_EQ(rule.url, decider.effective_config().value().pac_url());
}

class PacFileDeciderQuickCheckTest : public ::testing::Test,
                                     public WithTaskEnvironment {
 public:
  PacFileDeciderQuickCheckTest()
      : WithTaskEnvironment(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        rule_(rules_.AddSuccessRule("http://wpad/wpad.dat")),
        fetcher_(&rules_) {
    auto builder = CreateTestURLRequestContextBuilder();
    builder->set_host_resolver(std::make_unique<MockHostResolver>());
    request_context_ = builder->Build();
  }

  void SetUp() override {
    fetcher_.SetRequestContext(request_context_.get());
    config_.set_auto_detect(true);
    decider_ =
        std::make_unique<PacFileDecider>(&fetcher_, &dhcp_fetcher_, nullptr);
  }

  int StartDecider() {
    return decider_->Start(
        ProxyConfigWithAnnotation(config_, TRAFFIC_ANNOTATION_FOR_TESTS),
        base::TimeDelta(), true, callback_.callback());
  }

  MockHostResolver& host_resolver() {
    // This cast is safe because we set a MockHostResolver in the constructor.
    return *static_cast<MockHostResolver*>(request_context_->host_resolver());
  }

 protected:
  Rules rules_;
  Rules::Rule rule_;
  TestCompletionCallback callback_;
  RuleBasedPacFileFetcher fetcher_;
  ProxyConfig config_;
  DoNothingDhcpPacFileFetcher dhcp_fetcher_;
  std::unique_ptr<PacFileDecider> decider_;

 private:
  std::unique_ptr<URLRequestContext> request_context_;
};

// Fails if a synchronous DNS lookup success for wpad causes QuickCheck to fail.
TEST_F(PacFileDeciderQuickCheckTest, SyncSuccess) {
  host_resolver().set_synchronous_mode(true);
  host_resolver().rules()->AddRule("wpad", "1.2.3.4");

  EXPECT_THAT(StartDecider(), IsOk());
  EXPECT_EQ(rule_.text(), decider_->script_data().data->utf16());
  EXPECT_TRUE(decider_->script_data().from_auto_detect);

  EXPECT_TRUE(decider_->effective_config().value().has_pac_url());
  EXPECT_EQ(rule_.url, decider_->effective_config().value().pac_url());
}

// Fails if an asynchronous DNS lookup success for wpad causes QuickCheck to
// fail.
TEST_F(PacFileDeciderQuickCheckTest, AsyncSuccess) {
  host_resolver().set_ondemand_mode(true);
  host_resolver().rules()->AddRule("wpad", "1.2.3.4");

  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(host_resolver().has_pending_requests());

  // The DNS lookup should be pending, and be using the same
  // NetworkAnonymizationKey as the PacFileFetcher, so wpad fetches can reuse
  // the DNS lookup result from the wpad quick check, if it succeeds.
  ASSERT_EQ(1u, host_resolver().last_id());
  EXPECT_EQ(fetcher_.isolation_info().network_anonymization_key(),
            host_resolver().request_network_anonymization_key(1));

  host_resolver().ResolveAllPending();
  callback_.WaitForResult();
  EXPECT_FALSE(host_resolver().has_pending_requests());
  EXPECT_EQ(rule_.text(), decider_->script_data().data->utf16());
  EXPECT_TRUE(decider_->script_data().from_auto_detect);
  EXPECT_TRUE(decider_->effective_config().value().has_pac_url());
  EXPECT_EQ(rule_.url, decider_->effective_config().value().pac_url());
}

// Fails if an asynchronous DNS lookup failure (i.e. an NXDOMAIN) still causes
// PacFileDecider to yield a PAC URL.
TEST_F(PacFileDeciderQuickCheckTest, AsyncFail) {
  host_resolver().set_ondemand_mode(true);
  host_resolver().rules()->AddRule("wpad", ERR_NAME_NOT_RESOLVED);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(host_resolver().has_pending_requests());

  // The DNS lookup should be pending, and be using the same
  // NetworkAnonymizationKey as the PacFileFetcher, so wpad fetches can reuse
  // the DNS lookup result from the wpad quick check, if it succeeds.
  ASSERT_EQ(1u, host_resolver().last_id());
  EXPECT_EQ(fetcher_.isolation_info().network_anonymization_key(),
            host_resolver().request_network_anonymization_key(1));

  host_resolver().ResolveAllPending();
  callback_.WaitForResult();
  EXPECT_FALSE(decider_->effective_config().value().has_pac_url());
}

// Fails if a DNS lookup timeout either causes PacFileDecider to yield a PAC
// URL or causes PacFileDecider not to cancel its pending resolution.
TEST_F(PacFileDeciderQuickCheckTest, AsyncTimeout) {
  host_resolver().set_ondemand_mode(true);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(host_resolver().has_pending_requests());
  FastForwardUntilNoTasksRemain();
  callback_.WaitForResult();
  EXPECT_FALSE(host_resolver().has_pending_requests());
  EXPECT_FALSE(decider_->effective_config().value().has_pac_url());
}

// Fails if DHCP check doesn't take place before QuickCheck.
TEST_F(PacFileDeciderQuickCheckTest, QuickCheckInhibitsDhcp) {
  MockDhcpPacFileFetcher dhcp_fetcher;
  const char* kPac = "function FindProxyForURL(u,h) { return \"DIRECT\"; }";
  std::u16string pac_contents = base::UTF8ToUTF16(kPac);
  GURL url("http://foobar/baz");
  dhcp_fetcher.SetPacURL(url);
  decider_ =
      std::make_unique<PacFileDecider>(&fetcher_, &dhcp_fetcher, nullptr);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  dhcp_fetcher.CompleteRequests(OK, pac_contents);
  EXPECT_TRUE(decider_->effective_config().value().has_pac_url());
  EXPECT_EQ(decider_->effective_config().value().pac_url(), url);
}

// Fails if QuickCheck still happens when disabled. To ensure QuickCheck is not
// happening, we add a synchronous failing resolver, which would ordinarily
// mean a QuickCheck failure, then ensure that our PacFileFetcher is still
// asked to fetch.
TEST_F(PacFileDeciderQuickCheckTest, QuickCheckDisabled) {
  const char* kPac = "function FindProxyForURL(u,h) { return \"DIRECT\"; }";
  host_resolver().set_synchronous_mode(true);
  MockPacFileFetcher fetcher;
  decider_ =
      std::make_unique<PacFileDecider>(&fetcher, &dhcp_fetcher_, nullptr);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(fetcher.has_pending_request());
  fetcher.NotifyFetchCompletion(OK, kPac);
}

TEST_F(PacFileDeciderQuickCheckTest, ExplicitPacUrl) {
  const char* kCustomUrl = "http://custom/proxy.pac";
  config_.set_pac_url(GURL(kCustomUrl));
  Rules::Rule rule = rules_.AddSuccessRule(kCustomUrl);
  host_resolver().rules()->AddRule("wpad", ERR_NAME_NOT_RESOLVED);
  host_resolver().rules()->AddRule("custom", "1.2.3.4");
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  callback_.WaitForResult();
  EXPECT_TRUE(decider_->effective_config().value().has_pac_url());
  EXPECT_EQ(rule.url, decider_->effective_config().value().pac_url());
}

TEST_F(PacFileDeciderQuickCheckTest, ShutdownDuringResolve) {
  host_resolver().set_ondemand_mode(true);

  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver().has_pending_requests());

  decider_->OnShutdown();
  EXPECT_FALSE(host_resolver().has_pending_requests());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback_.have_result());
}

// Regression test for http://crbug.com/409698.
// This test lets the state machine get into state QUICK_CHECK_COMPLETE, then
// destroys the decider, causing a cancel.
TEST_F(PacFileDeciderQuickCheckTest, CancelPartway) {
  host_resolver().set_ondemand_mode(true);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  decider_.reset(nullptr);
}

// Fails at WPAD (downloading), but succeeds in choosing the custom PAC.
TEST(PacFileDeciderTest, AutodetectFailCustomSuccess1) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsOk());
  EXPECT_EQ(rule.text(), decider.script_data().data->utf16());
  EXPECT_FALSE(decider.script_data().from_auto_detect);

  EXPECT_TRUE(decider.effective_config().value().has_pac_url());
  EXPECT_EQ(rule.url, decider.effective_config().value().pac_url());
}

// Fails at WPAD (no DHCP config, DNS PAC fails parsing), but succeeds in
// choosing the custom PAC.
TEST(PacFileDeciderTest, AutodetectFailCustomSuccess2) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));
  config.proxy_rules().ParseFromString("unused-manual-proxy:99");

  rules.AddFailParsingRule("http://wpad/wpad.dat");
  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  RecordingNetLogObserver observer;

  PacFileDecider decider(&fetcher, &dhcp_fetcher, net::NetLog::Get());
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsOk());
  EXPECT_EQ(rule.text(), decider.script_data().data->utf16());
  EXPECT_FALSE(decider.script_data().from_auto_detect);

  // Verify that the effective configuration no longer contains auto detect or
  // any of the manual settings.
  EXPECT_TRUE(decider.effective_config().value().Equals(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://custom/proxy.pac"))));

  // Check the NetLog was filled correctly.
  // (Note that various states are repeated since both WPAD and custom
  // PAC scripts are tried).
  auto entries = observer.GetEntries();

  EXPECT_EQ(10u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PAC_FILE_DECIDER));
  // This is the DHCP phase, which fails fetching rather than parsing, so
  // there is no pair of SET_PAC_SCRIPT events.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEvent(
      entries, 3,
      NetLogEventType::PAC_FILE_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE,
      NetLogEventPhase::NONE));
  // This is the DNS phase, which attempts a fetch but fails.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 4, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 5, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEvent(
      entries, 6,
      NetLogEventType::PAC_FILE_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE,
      NetLogEventPhase::NONE));
  // Finally, the custom PAC URL phase.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 7, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 8, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 9, NetLogEventType::PAC_FILE_DECIDER));
}

// Fails at WPAD (downloading), and fails at custom PAC (downloading).
TEST(PacFileDeciderTest, AutodetectFailCustomFails1) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(kFailedDownloading));
  EXPECT_FALSE(decider.script_data().data);
}

// Fails at WPAD (downloading), and fails at custom PAC (parsing).
TEST(PacFileDeciderTest, AutodetectFailCustomFails2) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  rules.AddFailParsingRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(kFailedParsing));
  EXPECT_FALSE(decider.script_data().data);
}

// This is a copy-paste of CustomPacFails1, with the exception that we give it
// a 1 millisecond delay. This means it will now complete asynchronously.
// Moreover, we test the NetLog to make sure it logged the pause.
TEST(PacFileDeciderTest, CustomPacFails1_WithPositiveDelay) {
  base::test::TaskEnvironment task_environment;

  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;

  RecordingNetLogObserver observer;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, net::NetLog::Get());
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::Milliseconds(1), true, callback.callback()),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsError(kFailedDownloading));
  EXPECT_FALSE(decider.script_data().data);

  // Check the NetLog was filled correctly.
  auto entries = observer.GetEntries();

  EXPECT_EQ(6u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PAC_FILE_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 1,
                                    NetLogEventType::PAC_FILE_DECIDER_WAIT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 2, NetLogEventType::PAC_FILE_DECIDER_WAIT));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 3, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 4, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 5, NetLogEventType::PAC_FILE_DECIDER));
}

// This is a copy-paste of CustomPacFails1, with the exception that we give it
// a -5 second delay instead of a 0 ms delay. This change should have no effect
// so the rest of the test is unchanged.
TEST(PacFileDeciderTest, CustomPacFails1_WithNegativeDelay) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  DoNothingDhcpPacFileFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  RecordingNetLogObserver observer;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, net::NetLog::Get());
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::Seconds(-5), true, callback.callback()),
              IsError(kFailedDownloading));
  EXPECT_FALSE(decider.script_data().data);

  // Check the NetLog was filled correctly.
  auto entries = observer.GetEntries();

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PAC_FILE_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PAC_FILE_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PAC_FILE_DECIDER));
}

class SynchronousSuccessDhcpFetcher : public DhcpPacFileFetcher {
 public:
  explicit SynchronousSuccessDhcpFetcher(const std::u16string& expected_text)
      : gurl_("http://dhcppac/"), expected_text_(expected_text) {}

  SynchronousSuccessDhcpFetcher(const SynchronousSuccessDhcpFetcher&) = delete;
  SynchronousSuccessDhcpFetcher& operator=(
      const SynchronousSuccessDhcpFetcher&) = delete;

  int Fetch(std::u16string* utf16_text,
            CompletionOnceCallback callback,
            const NetLogWithSource& net_log,
            const NetworkTrafficAnnotationTag traffic_annotation) override {
    *utf16_text = expected_text_;
    return OK;
  }

  void Cancel() override {}

  void OnShutdown() override {}

  const GURL& GetPacURL() const override { return gurl_; }

  const std::u16string& expected_text() const { return expected_text_; }

 private:
  GURL gurl_;
  std::u16string expected_text_;
};

// All of the tests above that use PacFileDecider have tested
// failure to fetch a PAC file via DHCP configuration, so we now test
// success at downloading and parsing, and then success at downloading,
// failure at parsing.

TEST(PacFileDeciderTest, AutodetectDhcpSuccess) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  SynchronousSuccessDhcpFetcher dhcp_fetcher(u"http://bingo/!FindProxyForURL");

  ProxyConfig config;
  config.set_auto_detect(true);

  rules.AddSuccessRule("http://bingo/");
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsOk());
  EXPECT_EQ(dhcp_fetcher.expected_text(), decider.script_data().data->utf16());
  EXPECT_TRUE(decider.script_data().from_auto_detect);

  EXPECT_TRUE(decider.effective_config().value().has_pac_url());
  EXPECT_EQ(GURL("http://dhcppac/"),
            decider.effective_config().value().pac_url());
}

TEST(PacFileDeciderTest, AutodetectDhcpFailParse) {
  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);
  SynchronousSuccessDhcpFetcher dhcp_fetcher(u"http://bingo/!invalid-script");

  ProxyConfig config;
  config.set_auto_detect(true);

  rules.AddFailParsingRule("http://bingo/");
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  PacFileDecider decider(&fetcher, &dhcp_fetcher, nullptr);
  // Since there is fallback to DNS-based WPAD, the final error will be that
  // it failed downloading, not that it failed parsing.
  EXPECT_THAT(decider.Start(ProxyConfigWithAnnotation(
                                config, TRAFFIC_ANNOTATION_FOR_TESTS),
                            base::TimeDelta(), true, callback.callback()),
              IsError(kFailedDownloading));
  EXPECT_FALSE(decider.script_data().data);

  EXPECT_FALSE(decider.effective_config().value().has_pac_url());
}

class AsyncFailDhcpFetcher final : public DhcpPacFileFetcher {
 public:
  AsyncFailDhcpFetcher() = default;
  ~AsyncFailDhcpFetcher() override = default;

  int Fetch(std::u16string* utf16_text,
            CompletionOnceCallback callback,
            const NetLogWithSource& net_log,
            const NetworkTrafficAnnotationTag traffic_annotation) override {
    callback_ = std::move(callback);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AsyncFailDhcpFetcher::CallbackWithFailure,
                                  weak_ptr_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  void Cancel() override { callback_.Reset(); }

  void OnShutdown() override {}

  const GURL& GetPacURL() const override { return dummy_gurl_; }

  void CallbackWithFailure() {
    if (!callback_.is_null())
      std::move(callback_).Run(ERR_PAC_NOT_IN_DHCP);
  }

 private:
  GURL dummy_gurl_;
  CompletionOnceCallback callback_;
  base::WeakPtrFactory<AsyncFailDhcpFetcher> weak_ptr_factory_{this};
};

TEST(PacFileDeciderTest, DhcpCancelledByDestructor) {
  // This regression test would crash before
  // http://codereview.chromium.org/7044058/
  // Thus, we don't care much about actual results (hence no EXPECT or ASSERT
  // macros below), just that it doesn't crash.
  base::test::TaskEnvironment task_environment;

  Rules rules;
  RuleBasedPacFileFetcher fetcher(&rules);

  auto dhcp_fetcher = std::make_unique<AsyncFailDhcpFetcher>();

  ProxyConfig config;
  config.set_auto_detect(true);
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;

  // Scope so PacFileDecider gets destroyed early.
  {
    PacFileDecider decider(&fetcher, dhcp_fetcher.get(), nullptr);
    decider.Start(
        ProxyConfigWithAnnotation(config, TRAFFIC_ANNOTATION_FOR_TESTS),
        base::TimeDelta(), true, callback.callback());
  }

  // Run the message loop to let the DHCP fetch complete and post the results
  // back. Before the fix linked to above, this would try to invoke on
  // the callback object provided by PacFileDecider after it was
  // no longer valid.
  base::RunLoop().RunUntilIdle();
}

}  // namespace
}  // namespace net

"""

```