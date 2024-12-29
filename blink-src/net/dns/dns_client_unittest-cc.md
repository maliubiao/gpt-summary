Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Skim and Identification of Core Functionality:**

The filename `dns_client_unittest.cc` immediately signals that this is a *test file*. It's designed to test the functionality of something called `DnsClient`. The `#include` statements confirm this, particularly `#include "net/dns/dns_client.h"`. Other includes like `gtest/gtest.h` and `testing/gmock/include/gmock/gmock.h` reinforce the testing nature.

**2. Understanding the Test Structure:**

The code uses the Google Test framework (`TEST_F`). The `DnsClientTest` class inherits from `net::TestWithTaskEnvironment`, which sets up a controlled environment for testing asynchronous operations. The `SetUp()` method is crucial – it initializes the `DnsClient` and related objects (`URLRequestContext`, `ResolveContext`).

**3. Analyzing Individual Tests:**

The core of the analysis involves going through each `TEST_F` function and understanding what it's trying to verify. Here's a step-by-step approach for each test:

* **Read the test name:**  The name often hints at the functionality being tested (e.g., `NoConfig`, `InvalidConfig`, `CanUseSecureDnsTransactions_NoDohServers`).
* **Examine the `client_->Set...` calls:** These lines configure the `DnsClient` with specific settings (e.g., enabling/disabling insecure DNS, setting system configuration, setting overrides). This defines the *input* or the *setup* for the test.
* **Analyze the `EXPECT_...` calls:** These are the *assertions*. They check if the `DnsClient` behaves as expected under the given configuration. Key methods being tested are:
    * `CanUseSecureDnsTransactions()`:  Checks if secure DNS can be used.
    * `FallbackFromSecureTransactionPreferred()`: Checks if falling back from secure DNS is preferred.
    * `CanUseInsecureDnsTransactions()`: Checks if insecure DNS can be used.
    * `FallbackFromInsecureTransactionPreferred()`: Checks if falling back from insecure DNS is preferred.
    * `GetEffectiveConfig()`: Gets the currently active DNS configuration.
    * `GetHosts()`: Checks if host overrides are available (not directly tested for functionality but for existence).
    * `GetTransactionFactory()`: Checks if a DNS transaction factory exists.
    * `GetCurrentSession()`: Gets the current DNS session.
    * `CanQueryAdditionalTypesViaInsecureDns()`: Checks if querying for additional record types over insecure DNS is enabled.
    * `GetPresetAddrs()`: Checks if preset IP addresses for DoH servers are retrieved correctly.
* **Infer the expected behavior:** Based on the setup and the assertions, deduce what aspect of the `DnsClient`'s logic is being tested. For example, if `SetSystemConfig` is called with an empty `DnsConfig`, and `EXPECT_FALSE(client_->GetEffectiveConfig())` follows, the test verifies that an invalid configuration is handled correctly.

**4. Identifying Relationships with JavaScript (Instruction 2):**

This requires understanding where DNS functionality intersects with the browser's behavior as experienced by a web developer using JavaScript. The key link is how the browser resolves domain names for network requests initiated by JavaScript code (e.g., using `fetch`, `XMLHttpRequest`, or even `<img src="...">`). The `DnsClient` is part of the mechanism that makes this resolution happen. No direct JavaScript code exists in this C++ file, but its *impact* on JavaScript is important.

**5. Logical Reasoning and Input/Output (Instruction 3):**

For each test, consider the *input* as the configuration settings applied to the `DnsClient` and the *output* as the values asserted by the `EXPECT_...` calls. This helps understand the conditions under which different behaviors are expected.

**6. User/Programming Errors (Instruction 4):**

Think about how a developer using the `DnsClient` API (though not directly exposed to typical web developers) or a system administrator configuring DNS settings could make mistakes that would lead to the tested scenarios. For example, providing an invalid DNS server address, configuring DoH incorrectly, or forgetting to enable insecure DNS when necessary.

**7. User Operations and Debugging (Instruction 5):**

Consider the sequence of user actions in the browser that would trigger DNS lookups. This involves:

* Typing a URL in the address bar.
* Clicking a link.
* JavaScript code making network requests.
* The browser's internal processes then using the `DnsClient` to resolve the domain name in the URL. Debugging would involve tracing the code execution path in Chromium's networking stack to see how the `DnsClient` is being used in these scenarios.

**8. Code-Specific Observations (e.g., `AlwaysFailSocketFactory`):**

Notice custom components like `AlwaysFailSocketFactory`. This class is used in tests to simulate socket creation failures, which is a specific scenario to test error handling.

**Self-Correction/Refinement During Analysis:**

* **Initial assumptions might be wrong:**  If a test's assertions don't make sense initially, reread the test name and the configuration steps carefully. Perhaps a subtle detail was missed.
* **Group related tests:** Notice patterns in the test names and setups. For example, several tests focus on secure DNS (DoH) and fallback behavior. This helps understand the overall purpose of that set of tests.
* **Connect the dots:**  Relate the individual tests back to the high-level functionality of the `DnsClient`. How do these individual checks contribute to ensuring the `DnsClient` works correctly in various configurations and scenarios?

By following this structured approach, we can effectively analyze the C++ unit test code and understand its purpose, its relationship to higher-level concepts like JavaScript, and how it contributes to the overall robustness of the Chromium networking stack.
This C++ source code file, `dns_client_unittest.cc`, contains **unit tests for the `DnsClient` class in the Chromium network stack**. Its primary function is to ensure the `DnsClient` class behaves correctly under various conditions and configurations.

Here's a breakdown of its functionalities:

**Core Functionality Being Tested:**

* **Initialization and Configuration:** Tests how the `DnsClient` is created and how it handles different DNS configurations (e.g., valid, invalid, with and without DNS-over-HTTPS (DoH)).
* **Enabling/Disabling DNS Features:** Tests the effects of enabling or disabling insecure DNS and the querying of additional DNS record types.
* **Secure DNS (DoH) Functionality:** Verifies the logic for using secure DNS transactions when DoH is configured, including fallback mechanisms and probing for server availability.
* **Insecure DNS Functionality:** Checks the behavior when using traditional insecure DNS, including fallback logic and handling of failures.
* **Configuration Overrides:** Tests the ability to override system-level DNS configurations with specific settings.
* **Session Management:**  Verifies the creation and replacement of DNS sessions.
* **Retrieving Preset DoH Server Addresses:** Tests the ability to extract preset IP addresses for DoH servers from the configuration.

**Relationship with JavaScript Functionality:**

While this C++ code itself doesn't contain JavaScript, the `DnsClient` plays a crucial role in the functionality that JavaScript relies on for network requests. Here's how they are related:

* **Domain Name Resolution:** When JavaScript code running in a web page (e.g., using `fetch()` or `XMLHttpRequest`) makes a request to a domain name (like `www.example.com`), the browser needs to resolve that domain name to an IP address. The `DnsClient` is a key component in this resolution process.
* **Secure DNS for Privacy:** If the user has enabled secure DNS in their browser settings, the `DnsClient` (or its underlying mechanisms) will attempt to perform the DNS lookup over a secure protocol like HTTPS (DoH), enhancing privacy. This affects how JavaScript network requests are handled behind the scenes.

**Example:**

Imagine a JavaScript snippet:

```javascript
fetch('https://www.example.com/api/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

When this code executes, the browser needs to resolve `www.example.com`. The `DnsClient`, based on the browser's configuration (which this test file exercises), will determine whether to use a regular DNS lookup or a secure DoH lookup. The outcome of these tests ensures the `DnsClient` makes the correct decision.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's take the `TEST_F(DnsClientTest, CanUseSecureDnsTransactions_ProbeSuccess)` test as an example:

* **Assumption:**  If a DoH server is initially considered available but later confirmed to be working through a successful probe, the `DnsClient` should indicate that secure DNS transactions can be used and fallback is not preferred.
* **Input:**
    * A `DnsClient` instance is created.
    * A `ResolveContext` is created to manage DNS resolution state.
    * The `DnsClient` is configured with a DoH-only configuration (`ValidConfigWithDoh(true /* doh_only */)`).
    * The DNS caches are invalidated.
    * A "server success" is recorded for the DoH server.
* **Output (Assertions):**
    * `EXPECT_TRUE(client_->CanUseSecureDnsTransactions());` -  The client should be able to use secure DNS.
    * `EXPECT_FALSE(client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));` - Fallback from secure DNS is not preferred after a successful probe.

**User or Programming Common Usage Errors (and how tests prevent them):**

* **Incorrect DoH Configuration:** A user might manually configure DoH servers with incorrect URLs or without specifying IP addresses. Tests like `TEST_F(DnsClientTest, GetPresetAddrs)` ensure that the `DnsClient` correctly parses and extracts information from DoH configurations, preventing connection errors due to bad configurations.
* **Assuming Secure DNS is Always Available:**  A developer might assume that secure DNS will always work. Tests that cover fallback scenarios (e.g., `TEST_F(DnsClientTest, FallbackFromInsecureTransactionPreferred_Failures)`) highlight the importance of handling cases where secure DNS might fail and the system needs to fall back to insecure DNS.
* **Forgetting to Enable Insecure DNS when DoH Fails:** If a user or the system disables insecure DNS entirely but DoH is not working, no DNS resolution will occur. Tests like `TEST_F(DnsClientTest, InsecureNotEnabled)` ensure that the `DnsClient` respects these settings and behaves as expected.

**User Operations and Debugging Lineage:**

Here's how a user action can lead to the code being tested, serving as a debugging line:

1. **User Action:** A user types a website address (e.g., `https://www.example.com`) into the Chrome address bar or clicks a link.
2. **Browser Initiates Navigation:** Chrome starts the process of loading the webpage.
3. **DNS Lookup Required:** The browser needs to resolve `www.example.com` to an IP address.
4. **URLRequestContext Involvement:** The `URLRequestContext` (which is set up in the test) is responsible for handling network requests, including DNS resolution.
5. **DnsClient Interaction:** The `URLRequestContext` utilizes the `DnsClient` (the class being tested) to perform the DNS lookup.
6. **Configuration Check:** The `DnsClient` checks its current configuration (system settings, overrides) to determine how to perform the lookup (secure or insecure). This is where the logic tested in this file comes into play (e.g., `CanUseSecureDnsTransactions()`, `GetEffectiveConfig()`).
7. **DNS Transaction:** The `DnsClient` creates a DNS transaction (potentially using a `DnsSession`, also tested here) to send a DNS query to a DNS server.
8. **Test Coverage:** The unit tests in `dns_client_unittest.cc` simulate various configurations and scenarios that can occur during this DNS lookup process, ensuring the `DnsClient` handles them correctly.

**Debugging Scenario:**

If a user reports that a website isn't loading, and the error message suggests a DNS resolution issue, a developer might:

1. **Check Chrome's DNS settings:** Examine the user's Chrome settings related to secure DNS.
2. **Inspect Network Logs:** Use Chrome's developer tools to examine network requests and see if DNS resolution is failing.
3. **Consider DnsClient Logic:**  If the logs indicate issues with secure DNS or fallback, a developer might need to investigate the `DnsClient` code. The unit tests in this file become crucial for understanding how the `DnsClient` is *supposed* to behave under different configurations, helping identify potential bugs or unexpected behavior in the actual implementation. By running these tests, developers can isolate if the issue lies within the `DnsClient` logic itself.

In summary, `dns_client_unittest.cc` is a foundational part of ensuring the reliability and correctness of DNS resolution within the Chromium browser. It tests a wide range of scenarios to prevent errors and ensure a smooth browsing experience for users, especially in the context of modern DNS features like DoH.

Prompt: 
```
这是目录为net/dns/dns_client_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_client.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/rand_util.h"
#include "base/test/task_environment.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_session.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/resolve_context.h"
#include "net/socket/socket_test_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"

namespace net {

class ClientSocketFactory;

namespace {

class AlwaysFailSocketFactory : public MockClientSocketFactory {
 public:
  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      NetLog* net_log,
      const NetLogSource& source) override {
    return std::make_unique<MockUDPClientSocket>();
  }
};

class DnsClientTest : public TestWithTaskEnvironment {
 protected:
  DnsClientTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    client_ = DnsClient::CreateClient(nullptr /* net_log */);
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    request_context_ = context_builder->Build();
    resolve_context_ = std::make_unique<ResolveContext>(
        request_context_.get(), false /* enable_caching */);
  }

  DnsConfig BasicValidConfig() {
    DnsConfig config;
    config.nameservers = {IPEndPoint(IPAddress(2, 3, 4, 5), 123)};
    return config;
  }

  DnsConfig ValidConfigWithDoh(bool doh_only) {
    DnsConfig config;
    if (!doh_only) {
      config = BasicValidConfig();
    }
    config.doh_config =
        *net::DnsOverHttpsConfig::FromString("https://www.doh.com/");
    return config;
  }

  DnsConfigOverrides BasicValidOverrides() {
    DnsConfigOverrides config;
    config.nameservers.emplace({IPEndPoint(IPAddress(1, 2, 3, 4), 123)});
    return config;
  }

  std::unique_ptr<URLRequestContext> request_context_;
  std::unique_ptr<ResolveContext> resolve_context_;
  std::unique_ptr<DnsClient> client_;
  AlwaysFailSocketFactory socket_factory_;
};

TEST_F(DnsClientTest, NoConfig) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);

  EXPECT_FALSE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_FALSE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_FALSE(client_->GetEffectiveConfig());
  EXPECT_FALSE(client_->GetHosts());
  EXPECT_FALSE(client_->GetTransactionFactory());
  EXPECT_FALSE(client_->GetCurrentSession());
}

TEST_F(DnsClientTest, InvalidConfig) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  client_->SetSystemConfig(DnsConfig());

  EXPECT_FALSE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_FALSE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_FALSE(client_->GetEffectiveConfig());
  EXPECT_FALSE(client_->GetHosts());
  EXPECT_FALSE(client_->GetTransactionFactory());
  EXPECT_FALSE(client_->GetCurrentSession());
}

TEST_F(DnsClientTest, CanUseSecureDnsTransactions_NoDohServers) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  client_->SetSystemConfig(BasicValidConfig());

  EXPECT_FALSE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->CanQueryAdditionalTypesViaInsecureDns());
  EXPECT_FALSE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(BasicValidConfig()));
  EXPECT_TRUE(client_->GetHosts());
  EXPECT_TRUE(client_->GetTransactionFactory());
  EXPECT_EQ(client_->GetCurrentSession()->config(), BasicValidConfig());
}

TEST_F(DnsClientTest, InsecureNotEnabled) {
  client_->SetInsecureEnabled(/*enabled=*/false,
                              /*additional_types_enabled=*/false);
  client_->SetSystemConfig(ValidConfigWithDoh(false /* doh_only */));

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_FALSE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(ValidConfigWithDoh(false /* doh_only */)));
  EXPECT_TRUE(client_->GetHosts());
  EXPECT_TRUE(client_->GetTransactionFactory());
  EXPECT_EQ(client_->GetCurrentSession()->config(),
            ValidConfigWithDoh(false /* doh_only */));
}

TEST_F(DnsClientTest, RespectsAdditionalTypesDisabled) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/false);
  client_->SetSystemConfig(BasicValidConfig());

  EXPECT_FALSE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
  EXPECT_FALSE(client_->CanQueryAdditionalTypesViaInsecureDns());
  EXPECT_FALSE(client_->FallbackFromInsecureTransactionPreferred());
}

TEST_F(DnsClientTest, UnhandledOptions) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  DnsConfig config = ValidConfigWithDoh(false /* doh_only */);
  config.unhandled_options = true;
  client_->SetSystemConfig(config);

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_FALSE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  DnsConfig expected_config = config;
  expected_config.nameservers.clear();
  EXPECT_THAT(client_->GetEffectiveConfig(), testing::Pointee(expected_config));
  EXPECT_TRUE(client_->GetHosts());
  EXPECT_TRUE(client_->GetTransactionFactory());
  EXPECT_EQ(client_->GetCurrentSession()->config(), expected_config);
}

TEST_F(DnsClientTest, CanUseSecureDnsTransactions_ProbeSuccess) {
  client_->SetSystemConfig(ValidConfigWithDoh(true /* doh_only */));
  resolve_context_->InvalidateCachesAndPerSessionData(
      client_->GetCurrentSession(), true /* network_change */);

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));

  resolve_context_->RecordServerSuccess(0u /* server_index */,
                                        true /* is_doh_server */,
                                        client_->GetCurrentSession());
  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_FALSE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
}

TEST_F(DnsClientTest, DnsOverTlsActive) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  DnsConfig config = ValidConfigWithDoh(false /* doh_only */);
  config.dns_over_tls_active = true;
  client_->SetSystemConfig(config);

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_FALSE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_THAT(client_->GetEffectiveConfig(), testing::Pointee(config));
  EXPECT_TRUE(client_->GetHosts());
  EXPECT_TRUE(client_->GetTransactionFactory());
  EXPECT_EQ(client_->GetCurrentSession()->config(), config);
}

TEST_F(DnsClientTest, AllAllowed) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  client_->SetSystemConfig(ValidConfigWithDoh(false /* doh_only */));
  resolve_context_->InvalidateCachesAndPerSessionData(
      client_->GetCurrentSession(), false /* network_change */);
  resolve_context_->RecordServerSuccess(0u /* server_index */,
                                        true /* is_doh_server */,
                                        client_->GetCurrentSession());

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_FALSE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->CanQueryAdditionalTypesViaInsecureDns());
  EXPECT_FALSE(client_->FallbackFromInsecureTransactionPreferred());

  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(ValidConfigWithDoh(false /* doh_only */)));
  EXPECT_TRUE(client_->GetHosts());
  EXPECT_TRUE(client_->GetTransactionFactory());
  EXPECT_EQ(client_->GetCurrentSession()->config(),
            ValidConfigWithDoh(false /* doh_only */));
}

TEST_F(DnsClientTest, FallbackFromInsecureTransactionPreferred_Failures) {
  client_->SetInsecureEnabled(/*enabled=*/true,
                              /*additional_types_enabled=*/true);
  client_->SetSystemConfig(ValidConfigWithDoh(false /* doh_only */));

  for (int i = 0; i < DnsClient::kMaxInsecureFallbackFailures; ++i) {
    EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
    EXPECT_TRUE(client_->FallbackFromSecureTransactionPreferred(
        resolve_context_.get()));
    EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
    EXPECT_TRUE(client_->CanQueryAdditionalTypesViaInsecureDns());
    EXPECT_FALSE(client_->FallbackFromInsecureTransactionPreferred());

    client_->IncrementInsecureFallbackFailures();
  }

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->CanQueryAdditionalTypesViaInsecureDns());
  EXPECT_TRUE(client_->FallbackFromInsecureTransactionPreferred());

  client_->ClearInsecureFallbackFailures();

  EXPECT_TRUE(client_->CanUseSecureDnsTransactions());
  EXPECT_TRUE(
      client_->FallbackFromSecureTransactionPreferred(resolve_context_.get()));
  EXPECT_TRUE(client_->CanUseInsecureDnsTransactions());
  EXPECT_TRUE(client_->CanQueryAdditionalTypesViaInsecureDns());
  EXPECT_FALSE(client_->FallbackFromInsecureTransactionPreferred());
}

TEST_F(DnsClientTest, GetPresetAddrs) {
  DnsConfig config;
  config.doh_config = *net::DnsOverHttpsConfig::FromString(R"(
    {
      "servers": [{
        "template": "https://www.doh.com/",
        "endpoints": [{
          "ips": ["4.3.2.1"]
        }, {
          "ips": ["4.3.2.2"]
        }]
      }]
    }
  )");
  client_->SetSystemConfig(config);

  EXPECT_FALSE(client_->GetPresetAddrs(
      url::SchemeHostPort("https", "otherdomain.com", 443)));
  EXPECT_FALSE(
      client_->GetPresetAddrs(url::SchemeHostPort("http", "www.doh.com", 443)));
  EXPECT_FALSE(client_->GetPresetAddrs(
      url::SchemeHostPort("https", "www.doh.com", 9999)));

  std::vector<IPEndPoint> expected({{{4, 3, 2, 1}, 443}, {{4, 3, 2, 2}, 443}});

  EXPECT_THAT(
      client_->GetPresetAddrs(url::SchemeHostPort("https", "www.doh.com", 443)),
      testing::Optional(expected));
}

TEST_F(DnsClientTest, Override) {
  client_->SetSystemConfig(BasicValidConfig());
  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(BasicValidConfig()));
  EXPECT_EQ(client_->GetCurrentSession()->config(), BasicValidConfig());

  client_->SetConfigOverrides(BasicValidOverrides());
  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(
                  BasicValidOverrides().ApplyOverrides(BasicValidConfig())));
  EXPECT_EQ(client_->GetCurrentSession()->config(),
            BasicValidOverrides().ApplyOverrides(BasicValidConfig()));

  client_->SetConfigOverrides(DnsConfigOverrides());
  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(BasicValidConfig()));
  EXPECT_EQ(client_->GetCurrentSession()->config(), BasicValidConfig());
}

// Cannot apply overrides without a system config unless everything is
// overridden
TEST_F(DnsClientTest, OverrideNoConfig) {
  client_->SetConfigOverrides(BasicValidOverrides());
  EXPECT_FALSE(client_->GetEffectiveConfig());
  EXPECT_FALSE(client_->GetCurrentSession());

  auto override_everything =
      DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
  override_everything.nameservers.emplace(
      {IPEndPoint(IPAddress(1, 2, 3, 4), 123)});
  client_->SetConfigOverrides(override_everything);
  EXPECT_THAT(
      client_->GetEffectiveConfig(),
      testing::Pointee(override_everything.ApplyOverrides(DnsConfig())));
  EXPECT_EQ(client_->GetCurrentSession()->config(),
            override_everything.ApplyOverrides(DnsConfig()));
}

TEST_F(DnsClientTest, OverrideInvalidConfig) {
  client_->SetSystemConfig(DnsConfig());
  EXPECT_FALSE(client_->GetEffectiveConfig());
  EXPECT_FALSE(client_->GetCurrentSession());

  client_->SetConfigOverrides(BasicValidOverrides());
  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(
                  BasicValidOverrides().ApplyOverrides(BasicValidConfig())));
  EXPECT_EQ(client_->GetCurrentSession()->config(),
            BasicValidOverrides().ApplyOverrides(DnsConfig()));
}

TEST_F(DnsClientTest, OverrideToInvalid) {
  client_->SetSystemConfig(BasicValidConfig());
  EXPECT_THAT(client_->GetEffectiveConfig(),
              testing::Pointee(BasicValidConfig()));
  EXPECT_EQ(client_->GetCurrentSession()->config(), BasicValidConfig());

  DnsConfigOverrides overrides;
  overrides.nameservers.emplace();
  client_->SetConfigOverrides(std::move(overrides));

  EXPECT_FALSE(client_->GetEffectiveConfig());
  EXPECT_FALSE(client_->GetCurrentSession());
}

TEST_F(DnsClientTest, ReplaceCurrentSession) {
  client_->SetSystemConfig(BasicValidConfig());

  base::WeakPtr<DnsSession> session_before =
      client_->GetCurrentSession()->GetWeakPtr();
  ASSERT_TRUE(session_before);

  client_->ReplaceCurrentSession();

  EXPECT_FALSE(session_before);
  EXPECT_TRUE(client_->GetCurrentSession());
}

TEST_F(DnsClientTest, ReplaceCurrentSession_NoSession) {
  ASSERT_FALSE(client_->GetCurrentSession());

  client_->ReplaceCurrentSession();

  EXPECT_FALSE(client_->GetCurrentSession());
}

}  // namespace

}  // namespace net

"""

```