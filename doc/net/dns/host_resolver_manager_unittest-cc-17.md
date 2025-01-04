Response:
The user wants a summary of the functionality of the provided C++ code snippet from `host_resolver_manager_unittest.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename strongly suggests this file contains unit tests for the `HostResolverManager` component in Chromium's network stack. Specifically, the tests seem to focus on how the resolver handles DNS queries, especially related to HTTPS and SVCB records.

2. **Analyze Individual Tests:** Each `TEST_F` block represents a distinct test case. Examine the setup and assertions within each test. Look for patterns and common themes.

3. **Focus on Key Concepts:**  The code heavily uses terms like "HTTPS", "SVCB", "timeout", "secure DNS", "insecure", "address query". These are central to the functionality being tested.

4. **Pay Attention to Feature Flags:** The `base::test::ScopedFeatureList` is used to enable/disable and configure feature flags, particularly `features::kUseDnsHttpsSvcb`. This indicates that the tests are validating behavior related to this specific feature.

5. **Observe Mocking:** The code utilizes `MockDnsClientRuleList` and `MockDnsClient`. This signifies that the tests are designed to isolate the `HostResolverManager` and control the responses from the underlying DNS client.

6. **Identify Test Scenarios:** Each test seems to be exploring different timeout configurations (min, max, relative), secure vs. insecure queries, and the interaction with SVCB records.

7. **Relate to JavaScript (if applicable):**  While the C++ code itself isn't directly JavaScript, consider how DNS resolution impacts web browsing, which is initiated by JavaScript in a browser. The resolution process ultimately determines where the browser sends network requests.

8. **Infer Logic and Assumptions:**  Based on the setups and assertions, deduce what the expected behavior is for different input configurations (e.g., different timeout settings).

9. **Identify Potential User Errors:** Consider how a user's browser settings or network configuration might interact with the DNS resolution process and lead to unexpected outcomes.

10. **Trace User Actions:** Think about the steps a user might take in a browser that would trigger a DNS resolution, leading to this code being executed.

11. **Context from Part Number:**  Knowing this is part 18 of 21 suggests the file likely focuses on a specific aspect of the `HostResolverManager`'s functionality, rather than being a general overview.

**Pre-computation and Pre-analysis (Mental Walkthrough):**

* **Test Naming Convention:** The test names are descriptive (e.g., `HttpsInSecureAddressQueryWithOnlyMinTimeout`). This is a strong clue about what each test is verifying.
* **`ResolveHostResponseHelper`:** This class appears to be a utility for simplifying asynchronous DNS resolution testing.
* **`FastForwardBy`:**  This method simulates the passage of time, crucial for testing timeout behavior.
* **`EXPECT_FALSE(response.complete())` and `EXPECT_TRUE(response.complete())`:** These assertions check whether the DNS resolution process has finished.
* **Assertions on Results:** The `EXPECT_THAT` assertions verify the content of the DNS responses (address results, endpoint results, etc.).

By following these steps, we can arrive at a comprehensive understanding of the code's purpose and its implications.
This section of the `host_resolver_manager_unittest.cc` file primarily focuses on testing the **timeout mechanisms specifically related to HTTPS DNS queries when using SVCB (Service Binding) records**. It meticulously examines how different timeout configurations (minimum, maximum, and relative timeouts) affect the resolution process, both for secure and insecure DNS lookups.

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Testing HTTPS DNS Query Timeouts:** The tests verify that the `HostResolverManager` correctly applies timeouts when resolving hostnames for HTTPS connections, especially when SVCB records are involved.
* **Secure vs. Insecure Context:**  The tests differentiate between secure (DoH/DoT) and insecure (traditional DNS) contexts for HTTPS queries and how timeouts are applied in each scenario.
* **SVCB Record Handling:** The tests implicitly validate the interaction between the resolver and SVCB records, ensuring that the timeout logic considers the potential for additional queries triggered by these records.
* **Configuration via Feature Flags:**  The tests utilize feature flags (`features::kUseDnsHttpsSvcb`) to enable and configure specific timeout parameters. This allows for testing various timeout strategies.
* **Mocking DNS Responses:**  The tests employ `MockDnsClientRuleList` to simulate DNS server responses with specific delays, enabling precise control over the timing of DNS transactions and the triggering of timeouts.
* **Verification of Results:** Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`) are used to verify whether the resolution completes within the expected timeframe, and the correctness of the resolved addresses and endpoint information.

**Relationship to JavaScript:**

While the C++ code itself isn't JavaScript, it directly impacts how web browsers (which heavily rely on JavaScript) perform network requests.

* **Impact on `fetch()` and `XMLHttpRequest`:** When JavaScript code in a browser uses functions like `fetch()` or `XMLHttpRequest` to make HTTPS requests, the browser's network stack (including the `HostResolverManager`) is responsible for resolving the hostname. The timeouts tested in this code directly affect how long the browser will wait for a successful DNS resolution before potentially timing out and reporting an error to the JavaScript code.
* **Error Handling in JavaScript:** If a DNS resolution times out due to the mechanisms tested here, the JavaScript code might receive an error (e.g., a network error or a specific DNS resolution error). JavaScript developers can then implement error handling logic to inform the user or retry the request.

**Example:**

Imagine a JavaScript application tries to fetch data from `https://example.com`.

1. The JavaScript `fetch()` call triggers a DNS resolution for `example.com`.
2. The `HostResolverManager` initiates DNS queries, potentially including queries for SVCB records if the feature is enabled.
3. If the DNS server is slow to respond or if there are network issues, the timeouts configured and tested in this C++ code will determine when the resolution attempt is abandoned.
4. If a timeout occurs, the `fetch()` promise in the JavaScript code will likely reject with an error.

**Logical Inference (Hypothetical Input and Output):**

**Scenario:**  An HTTPS request to `https://slow-dns.test` where the DNS server takes a long time to respond with SVCB records. The `UseDnsHttpsSvcbSecureExtraTimeMax` feature is set to "10s".

**Hypothetical Input:**

* Request for `https://slow-dns.test`.
* DNS server configured to delay the response for the SVCB record by 8 seconds and the A/AAAA records by another 5 seconds.
* `UseDnsHttpsSvcbSecureExtraTimeMax` is set to "10s".

**Expected Output:**

* The initial SVCB query will take 8 seconds.
* The A/AAAA queries will start.
* After an additional 2 seconds (reaching the 10-second maximum timeout), the resolution will likely complete with the available address results, even if the A/AAAA queries are still ongoing in the mock. The `response.complete()` would eventually become true, and `response.result_error()` would be `IsOk()`. The endpoint results would reflect the information from the successfully resolved SVCB record.

**User or Programming Common Usage Errors:**

* **Incorrect Timeout Configuration:**  Users (through command-line flags or enterprise policies) or developers (through feature flag configurations) might set excessively short timeouts for HTTPS DNS queries when using SVCB. This could lead to premature timeouts, especially if the DNS servers are slow or the network has high latency, even if the servers would eventually return a valid response. For example, setting `UseDnsHttpsSvcbSecureExtraTimeMax` to a very small value like "1s" in a network with typical DNS latency could cause many HTTPS requests to fail unnecessarily.
* **Assuming Immediate DNS Responses:** Developers might write code that assumes DNS resolutions are always instantaneous. When using SVCB, especially with secure DNS, the resolution process can involve multiple queries and take longer. Not accounting for this latency can lead to race conditions or unexpected behavior in applications.
* **Ignoring DNS Error Handling:**  Failing to implement proper error handling for DNS resolution failures in JavaScript applications can lead to a poor user experience. If a timeout occurs, the application should gracefully handle the error and potentially offer the user options like retrying or providing more information.

**User Operations to Reach This Code (Debugging Clues):**

1. **User Enters an HTTPS URL:** The user types an HTTPS address into the browser's address bar or clicks on an HTTPS link.
2. **Browser Initiates DNS Resolution:** The browser's network stack starts the process of resolving the hostname in the URL.
3. **Feature Flags Enabled:** If the `chrome://flags` page or enterprise policies have enabled the `UseDnsHttpsSvcb` feature, the resolver will attempt to fetch SVCB records.
4. **Secure DNS Configuration:** If the user has enabled secure DNS (DoH or DoT) in the browser's settings, the resolution might involve secure DNS queries, potentially triggering the secure timeout logic tested in this code.
5. **Slow DNS Server/Network Issues:** If the user's configured DNS server is slow to respond or there are network connectivity problems, the resolution process might take longer, leading to the timeout mechanisms being triggered.
6. **Code Execution:** Under these circumstances, the code within `HostResolverManagerDnsTest` related to HTTPS SVCB timeouts would be executed during unit testing to verify the correct behavior of the resolver. In a live browser, the corresponding production code would be running.

**Summary of Functionality (Part 18 of 21):**

This section of the unit tests specifically focuses on verifying the **correct implementation and behavior of timeout mechanisms for HTTPS DNS queries when the `UseDnsHttpsSvcb` feature is enabled.** It thoroughly tests different timeout configurations (min, max, relative) in both secure and insecure DNS contexts to ensure that the `HostResolverManager` handles delays in DNS responses appropriately when fetching SVCB records. This ensures a balance between responsiveness and allowing sufficient time for potentially longer secure DNS resolutions with SVCB.

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第18部分，共21部分，请归纳一下它的功能

"""
he request to not
  // complete because it is waiting on the transaction, where the mock is
  // delaying completion.
  FastForwardBy(base::Hours(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::IsEmpty()));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInSecureAddressQueryWithOnlyMinTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "30m"},
       // Set a Secure absolute timeout of 10 minutes via the "min" param.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "10m"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1 second before expected timeout.
  FastForwardBy(base::Minutes(10) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Exceed expected timeout.
  FastForwardBy(base::Seconds(2));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInSecureAddressQueryWithOnlyMaxTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "30m"},
       // Set a Secure absolute timeout of 10 minutes via the "max" param.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "10m"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1 second before expected timeout.
  FastForwardBy(base::Minutes(10) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Exceed expected timeout.
  FastForwardBy(base::Seconds(2));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInSecureAddressQueryWithRelativeTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "30m"},
       // Set a Secure relative timeout of 10%.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "10"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Complete final address transaction after 100 seconds total.
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(
      mock_dns_client_->CompleteOneDelayedTransactionOfType(DnsQueryType::A));
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(mock_dns_client_->CompleteOneDelayedTransactionOfType(
      DnsQueryType::AAAA));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect timeout at additional 10 seconds.
  FastForwardBy(base::Seconds(9));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  FastForwardBy(base::Seconds(2));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInSecureAddressQueryWithMaxTimeoutFirst) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       // Set a Secure max timeout of 30s and a relative timeout of 100%.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "30s"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "100"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "10s"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Complete final address transaction after 4 minutes total.
  FastForwardBy(base::Minutes(2));
  ASSERT_TRUE(
      mock_dns_client_->CompleteOneDelayedTransactionOfType(DnsQueryType::A));
  FastForwardBy(base::Minutes(2));
  ASSERT_TRUE(mock_dns_client_->CompleteOneDelayedTransactionOfType(
      DnsQueryType::AAAA));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1 second before expected timeout (from the max timeout).
  FastForwardBy(base::Seconds(29));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Exceed expected timeout.
  FastForwardBy(base::Seconds(2));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryWithRelativeTimeoutFirst) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       // Set a Secure max timeout of 20 minutes and a relative timeout of 10%.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "20m"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "10"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "1s"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Complete final address transaction after 100 seconds total.
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(
      mock_dns_client_->CompleteOneDelayedTransactionOfType(DnsQueryType::A));
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(mock_dns_client_->CompleteOneDelayedTransactionOfType(
      DnsQueryType::AAAA));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect timeout at additional 10 seconds (from the relative timeout).
  FastForwardBy(base::Seconds(9));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  FastForwardBy(base::Seconds(2));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryWithRelativeTimeoutShorterThanMinTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       // Set a Secure min timeout of 1 minute and a relative timeout of 10%.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "20m"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "10"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "1m"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Complete final address transaction after 100 seconds total.
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(
      mock_dns_client_->CompleteOneDelayedTransactionOfType(DnsQueryType::A));
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(mock_dns_client_->CompleteOneDelayedTransactionOfType(
      DnsQueryType::AAAA));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect timeout at additional 1 minute (from the min timeout).
  FastForwardBy(base::Minutes(1) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  FastForwardBy(base::Seconds(2));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInInsecureAddressQueryWithOnlyMinTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Set an Insecure absolute timeout of 10 minutes via the "min" param.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "10m"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1 second before expected timeout.
  FastForwardBy(base::Minutes(10) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Exceed expected timeout.
  FastForwardBy(base::Seconds(2));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInInsecureAddressQueryWithOnlyMaxTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Set an Insecure absolute timeout of 10 minutes via the "max" param.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "10m"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1 second before expected timeout.
  FastForwardBy(base::Minutes(10) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Exceed expected timeout.
  FastForwardBy(base::Seconds(2));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInInsecureAddressQueryWithRelativeTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Set an Insecure relative timeout of 10%.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "10"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Complete final address transaction after 100 seconds total.
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(
      mock_dns_client_->CompleteOneDelayedTransactionOfType(DnsQueryType::A));
  FastForwardBy(base::Seconds(50));
  ASSERT_TRUE(mock_dns_client_->CompleteOneDelayedTransactionOfType(
      DnsQueryType::AAAA));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect timeout at additional 10 seconds.
  FastForwardBy(base::Seconds(9));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  FastForwardBy(base::Seconds(2));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Test that HTTPS timeouts are not used when fatal for the request.
TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryWaitsWithoutTimeoutIfFatal) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Set timeouts but also enforce secure responses.
       {"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "20m"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait an absurd amount of time (1 hour) and expect the request to not
  // complete because it is waiting on the transaction, where the mock is
  // delaying completion.
  FastForwardBy(base::Hours(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(
              testing::SizeIs(2),
              ExpectConnectionEndpointMetadata(
                  testing::ElementsAre(dns_protocol::kHttpsServiceDefaultAlpn),
                  testing::IsEmpty(), kName)),
          ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

// Test that HTTPS timeouts are always respected for insecure requests.
TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryAlwaysRespectsTimeoutsForInsecure) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Set timeouts but also enforce secure responses.
       {"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "20m"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nu
"""


```