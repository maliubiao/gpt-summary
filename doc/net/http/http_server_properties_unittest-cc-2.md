Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for `HttpServerProperties` in Chromium's networking stack.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Class Being Tested:** The file name `http_server_properties_unittest.cc` and the class name `AlternateProtocolServerPropertiesTest` clearly indicate that the code tests the functionality related to storing and managing alternative protocols for servers. Specifically, it's testing how `HttpServerProperties` handles alternative services.

2. **Analyze the Test Function Names:** The names of the test functions provide strong clues about the specific features being tested:
    * `SetAlternativeService`:  Testing setting alternative services.
    * `GetAlternativeService`: Testing retrieving alternative services.
    * `HasAlternativeService`: Testing if an alternative service exists.
    * `MarkAlternativeServiceBroken`: Testing marking an alternative service as broken.
    * `ClearBroken`: Testing clearing the broken status of an alternative service.
    * `MarkRecentlyBroken`: Testing marking an alternative service as recently broken.
    * `MarkBrokenUntilDefaultNetworkChanges`: Testing marking an alternative service as broken until the network changes.
    * `OnDefaultNetworkChanged`: Testing how the system reacts to network changes.
    * `Canonical`: Testing how canonical alternative services are handled.
    * `ClearCanonical`: Testing clearing canonical alternative services.
    * `WithNetworkIsolationKey`:  These tests, present in multiple variations, clearly indicate testing the behavior when network isolation keys are enabled.

3. **Examine the Test Logic (Assertions and Setup):**  The tests use `EXPECT_TRUE`, `EXPECT_FALSE`, and `ASSERT_TRUE` to verify the expected behavior of the `HttpServerProperties` class. They set up scenarios with different alternative services, mark them as broken or recently broken, and then check the state. The use of `NetworkAnonymizationKey` and the conditional logic based on the `kPartitionConnectionsByNetworkIsolationKey` feature flag are also significant.

4. **Identify Key Concepts:** From the test names and logic, identify the key concepts being tested:
    * **Alternative Services:**  The core concept.
    * **Broken/Recently Broken Status:**  Tracking the health of alternative services.
    * **Network Isolation Keys:** How alternative services are partitioned based on network context.
    * **Canonical Alternative Services:**  Alternative services that apply to a broader scope of hosts.
    * **Network Changes:** How the system handles changes in the network.

5. **Relate to Browser Functionality (if applicable):** Consider how these concepts relate to a user's browsing experience. Alternative services (like HTTP/2 or QUIC) are used to speed up connections. Marking services as broken prevents the browser from repeatedly trying to use a failing connection. Network isolation keys relate to privacy and security.

6. **Consider Potential User/Programming Errors:** Think about how a developer might misuse these APIs or how a user might encounter situations where this functionality is relevant (e.g., network issues, website configuration).

7. **Infer User Actions:**  Trace back how a user's actions could lead to this code being executed (e.g., visiting a website that advertises alternative services, experiencing connection problems).

8. **Structure the Response:** Organize the findings into a clear and concise summary, addressing all the points requested by the user:
    * Overall functionality.
    * Relationship to JavaScript (if any).
    * Logical inference examples.
    * Common user/programming errors.
    * User steps to reach this code.
    * Summary of the current part.

9. **Refine and Elaborate:** Add details and examples to make the explanation more understandable. For instance, explain what "broken" means in this context. Provide concrete examples of input and expected output for the logical inferences.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the individual test functions.
* **Correction:**  Realize that the tests collectively paint a picture of the overall functionality of managing alternative services. Group related tests thematically.
* **Initial thought:**  Assume a direct link to JavaScript.
* **Correction:** Acknowledge that while not directly interacting with JavaScript in *this* code, the functionality impacts how network requests are made, which is certainly relevant to web development and JavaScript's interaction with the network. Shift the focus to the impact on network performance.
* **Initial thought:** Provide only a high-level summary.
* **Correction:** Include more specific examples and details to illustrate the different features being tested.

By following these steps, and iterating as needed, the detailed and informative response can be generated.
Based on the provided C++ code snippet, here's a breakdown of its functionality, relationship to JavaScript, logical inferences, potential errors, user interaction, and a summary of this part:

**Functionality of `net/http/http_server_properties_unittest.cc` (Part 3):**

This part of the unit test file focuses on testing the functionality of `HttpServerProperties` related to managing the **broken status of alternative services**. Specifically, it tests:

* **Marking Alternative Services as Broken:** How to mark an alternative service (like HTTP/2 or QUIC on a different port) as broken, indicating it's currently not working. This prevents the browser from repeatedly trying to connect using that broken alternative.
* **Clearing the Broken Status:** How to clear the broken status of an alternative service, potentially after a period of time or a network change.
* **Marking Alternative Services as Recently Broken:** A distinction might exist between simply broken and *recently* broken, possibly influencing retry logic.
* **Marking Alternative Services as Broken Until Default Network Changes:**  This feature allows marking an alternative service as broken specifically for the current network. When the user switches networks (e.g., from Wi-Fi to cellular), the broken status might be cleared.
* **Handling Network Isolation Keys:** The tests extensively cover how these broken statuses are managed when Network Isolation Keys (or Network Anonymization Keys) are enabled. This means the broken status can be specific to a particular network context (e.g., a specific website embedded on another website).
* **Canonical Alternative Services and Broken Status:** How the broken status of alternative services is handled when canonical alternative services are involved (where one domain might advertise alternative services for related subdomains).
* **The `OnDefaultNetworkChanged` Event:** Testing how the `HttpServerProperties` class reacts when the default network changes, particularly in relation to alternative services marked as broken until a network change.

**Relationship to JavaScript:**

While this C++ code doesn't directly interact with JavaScript, the functionality it tests has a significant impact on how web browsers (and thus JavaScript running within them) interact with web servers.

* **Performance:**  By correctly managing alternative services, the browser can establish faster connections (e.g., using HTTP/2 or QUIC), leading to faster page load times and a better user experience for web applications built with JavaScript.
* **Reliability:** Marking broken alternative services prevents JavaScript applications from experiencing repeated connection failures and delays when the browser keeps trying a non-functional connection method.
* **Security and Privacy (with Network Isolation Keys):**  Network Isolation Keys, as tested here, help prevent certain types of cross-site tracking. JavaScript making requests to different origins will be subject to these isolation rules, and the management of alternative services respects these boundaries.

**Example:**

Imagine a website `https://example.com` that also offers HTTP/2 on port 443.

* **Scenario:** The user's network has a temporary issue connecting to `example.com` on HTTP/2.
* **C++ Logic (tested here):** The browser's network stack (using `HttpServerProperties`) would mark the alternative service (HTTP/2 on port 443) as broken.
* **JavaScript Impact:** Subsequent requests from JavaScript on that page to `example.com` would likely fall back to HTTP/1.1 for a while, avoiding the failing HTTP/2 connection. The user might experience slightly slower loading but won't get stuck with repeated connection errors.
* **Later:** Once the network issue resolves, the broken status might be cleared (either after a timeout or a network change), and future JavaScript requests could again use the faster HTTP/2 connection.

**Logical Inference (Hypothetical Input and Output):**

**Test Case: `MarkAlternativeServiceBroken`**

* **Hypothetical Input:**
    * `server`: `http://test.example.com:80`
    * `alternative_service`: `AlternativeService(kProtoHTTP2, "test.example.com", 443)`
    * Action: Call `impl_.MarkAlternativeServiceBroken(alternative_service, NetworkAnonymizationKey())`

* **Expected Output:**
    * `impl_.IsAlternativeServiceBroken(alternative_service, NetworkAnonymizationKey())` returns `true`.
    * `impl_.WasAlternativeServiceRecentlyBroken(alternative_service, NetworkAnonymizationKey())` returns `true`.

**Test Case: `OnDefaultNetworkChanged` with `MarkBrokenUntilDefaultNetworkChanges`**

* **Hypothetical Input:**
    * `server`: `http://another.example.com:80`
    * `alternative_service`: `AlternativeService(kProtoQUIC, "another.example.com", 1234)`
    * Action 1: `impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(alternative_service, NetworkAnonymizationKey())`
    * Action 2: `impl_.OnDefaultNetworkChanged()`

* **Expected Output:**
    * Before `OnDefaultNetworkChanged`: `impl_.IsAlternativeServiceBroken(alternative_service, NetworkAnonymizationKey())` returns `true`.
    * After `OnDefaultNetworkChanged`: `impl_.IsAlternativeServiceBroken(alternative_service, NetworkAnonymizationKey())` returns `false`.

**Common User or Programming Errors:**

* **Incorrectly configured servers:** If a server advertises an alternative service that is not actually available or is misconfigured, the browser will correctly mark it as broken. However, the underlying problem lies with the server configuration.
* **Network issues:** Temporary network glitches can lead to alternative services being incorrectly marked as broken. This is usually temporary and resolves itself.
* **Aggressive marking as broken:** A potential (though less likely) programming error in the browser's network stack could lead to incorrectly marking healthy alternative services as broken, hindering performance. The tests here aim to prevent such errors.
* **Forgetting to consider Network Isolation Keys:** When implementing or debugging features related to alternative services, developers need to be mindful of how Network Isolation Keys affect the storage and retrieval of this information. The tests highlight this complexity.

**User Operations to Reach This Code (Debugging Scenario):**

Imagine a user reports that a website seems slow or unreliable. A developer might investigate, and here's how they could end up looking at this part of the code:

1. **User reports slow loading of `https://my-slow-website.com`.**
2. **Developer suspects issues with HTTP/2 or QUIC.**
3. **The developer might enable network logging in the browser (e.g., using `chrome://net-export/`).**
4. **The logs show attempts to connect via HTTP/2 or QUIC failing intermittently.**
5. **The developer might then look at the code responsible for managing the broken status of alternative services to understand why the browser might be falling back to older protocols or experiencing connection issues.**
6. **This leads them to the `HttpServerProperties` class and potentially these unit tests to understand the logic and verify its correctness.**
7. **They might even run these unit tests to reproduce a specific scenario or to test a potential fix.**

**Summary of Part 3's Functionality:**

This section of the `http_server_properties_unittest.cc` file specifically tests the mechanisms within Chromium's networking stack for:

* **Tracking and managing the "broken" status of alternative network protocols (like HTTP/2 and QUIC) for specific servers.**
* **Ensuring that this broken status is correctly updated, cleared, and influenced by factors like network changes and the presence of Network Isolation Keys.**
* **Verifying the logic for marking services as broken temporarily until a network change occurs.**

In essence, this part is crucial for ensuring the browser intelligently avoids using non-functional connection methods, leading to a more reliable and efficient browsing experience.

### 提示词
```
这是目录为net/http/http_server_properties_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(broken_alternative_service,
                                               NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearBroken) {
  url::SchemeHostPort test_server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service);
  impl_.MarkAlternativeServiceBroken(alternative_service,
                                     NetworkAnonymizationKey());
  ASSERT_TRUE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  // SetAlternativeServices should leave a broken alternative service marked
  // as such.
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       MarkBrokenWithNetworkIsolationKey) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  const base::Time expiration = test_clock_.Now() + base::Days(1);

  // Without NetworkIsolationKeys enabled, the NetworkAnonymizationKey parameter
  // should be ignored.
  impl_.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                   alternative_service, expiration);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.MarkAlternativeServiceBroken(alternative_service,
                                     network_anonymization_key1_);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               network_anonymization_key1_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               network_anonymization_key2_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.ConfirmAlternativeService(alternative_service,
                                  network_anonymization_key2_);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                        alternative_service, expiration);
  properties.SetHttp2AlternativeService(server, network_anonymization_key2_,
                                        alternative_service, expiration);

  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceBroken(alternative_service,
                                          network_anonymization_key1_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceBroken(alternative_service,
                                          network_anonymization_key2_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key1_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key2_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));
}

TEST_F(AlternateProtocolServerPropertiesTest, MarkRecentlyBroken) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(server, alternative_service);

  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceRecentlyBroken(alternative_service,
                                             NetworkAnonymizationKey());
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.ConfirmAlternativeService(alternative_service,
                                  NetworkAnonymizationKey());
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       MarkRecentlyBrokenWithNetworkIsolationKey) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  const base::Time expiration = test_clock_.Now() + base::Days(1);

  // Without NetworkIsolationKeys enabled, the NetworkAnonymizationKey parameter
  // should be ignored.
  impl_.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                   alternative_service, expiration);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.MarkAlternativeServiceRecentlyBroken(alternative_service,
                                             network_anonymization_key1_);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.ConfirmAlternativeService(alternative_service,
                                  network_anonymization_key2_);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                        alternative_service, expiration);
  properties.SetHttp2AlternativeService(server, network_anonymization_key2_,
                                        alternative_service, expiration);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceRecentlyBroken(alternative_service,
                                                  network_anonymization_key1_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceRecentlyBroken(alternative_service,
                                                  network_anonymization_key2_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key1_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key2_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       MarkBrokenUntilDefaultNetworkChanges) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(server, alternative_service);

  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.ConfirmAlternativeService(alternative_service,
                                  NetworkAnonymizationKey());
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       MarkBrokenUntilDefaultNetworkChangesWithNetworkIsolationKey) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  const base::Time expiration = test_clock_.Now() + base::Days(1);

  // Without NetworkIsolationKeys enabled, the NetworkAnonymizationKey parameter
  // should be ignored.
  impl_.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                   alternative_service, expiration);

  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, network_anonymization_key1_);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               network_anonymization_key1_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               network_anonymization_key2_));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  impl_.ConfirmAlternativeService(alternative_service,
                                  network_anonymization_key2_);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key1_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                network_anonymization_key2_));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                        alternative_service, expiration);
  properties.SetHttp2AlternativeService(server, network_anonymization_key2_,
                                        alternative_service, expiration);

  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, network_anonymization_key1_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, network_anonymization_key2_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key1_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.ConfirmAlternativeService(alternative_service,
                                       network_anonymization_key2_);
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));
}

TEST_F(AlternateProtocolServerPropertiesTest, OnDefaultNetworkChanged) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);

  SetAlternativeService(server, alternative_service);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // Default network change clears alt svc broken until default network changes.
  impl_.OnDefaultNetworkChanged();
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceBroken(alternative_service,
                                     NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // Default network change doesn't affect alt svc that was simply marked broken
  // most recently.
  impl_.OnDefaultNetworkChanged();
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // Default network change clears alt svc that was marked broken until default
  // network change most recently even if the alt svc was initially marked
  // broken.
  impl_.OnDefaultNetworkChanged();
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       OnDefaultNetworkChangedWithNetworkIsolationKey) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  const base::Time expiration = test_clock_.Now() + base::Days(1);
  properties.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                        alternative_service, expiration);
  properties.SetHttp2AlternativeService(server, network_anonymization_key2_,
                                        alternative_service, expiration);

  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  properties.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, network_anonymization_key1_);
  properties.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, network_anonymization_key2_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  // Default network change clears alt svc broken until default network changes.
  properties.OnDefaultNetworkChanged();
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));
}

TEST_F(AlternateProtocolServerPropertiesTest, Canonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));

  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  EXPECT_FALSE(
      HasAlternativeService(canonical_server, NetworkAnonymizationKey()));

  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService canonical_alternative_service1(
      kProtoQUIC, "bar.c.youtube.com", 1234);
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          canonical_alternative_service1, expiration,
          DefaultSupportedQuicVersions()));
  const AlternativeService canonical_alternative_service2(kProtoHTTP2, "", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          canonical_alternative_service2, expiration));
  impl_.SetAlternativeServices(canonical_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  // Since |test_server| does not have an alternative service itself,
  // GetAlternativeServiceInfos should return those of |canonical_server|.
  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(canonical_alternative_service1,
            alternative_service_info_vector2[0].alternative_service());

  // Since |canonical_alternative_service2| has an empty host,
  // GetAlternativeServiceInfos should substitute the hostname of its |origin|
  // argument.
  EXPECT_EQ(test_server.host(),
            alternative_service_info_vector2[1].alternative_service().host);
  EXPECT_EQ(canonical_alternative_service2.protocol,
            alternative_service_info_vector2[1].alternative_service().protocol);
  EXPECT_EQ(canonical_alternative_service2.port,
            alternative_service_info_vector2[1].alternative_service().port);

  // Verify the canonical suffix.
  EXPECT_EQ(".c.youtube.com",
            *impl_.GetCanonicalSuffixForTesting(test_server.host()));
  EXPECT_EQ(".c.youtube.com",
            *impl_.GetCanonicalSuffixForTesting(canonical_server.host()));
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  impl_.SetAlternativeServices(canonical_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       CanonicalWithNetworkIsolationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  EXPECT_FALSE(HasAlternativeService(test_server, network_anonymization_key1_));

  url::SchemeHostPort canonical_server1("https", "bar.c.youtube.com", 443);
  EXPECT_FALSE(
      HasAlternativeService(canonical_server1, network_anonymization_key1_));

  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService canonical_alternative_service1(
      kProtoQUIC, "bar.c.youtube.com", 1234);
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          canonical_alternative_service1, expiration,
          DefaultSupportedQuicVersions()));
  const AlternativeService canonical_alternative_service2(kProtoHTTP2, "", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          canonical_alternative_service2, expiration));
  properties.SetAlternativeServices(canonical_server1,
                                    network_anonymization_key1_,
                                    alternative_service_info_vector);

  // Since |test_server| does not have an alternative service itself,
  // GetAlternativeServiceInfos should return those of |canonical_server|.
  AlternativeServiceInfoVector alternative_service_info_vector2 =
      properties.GetAlternativeServiceInfos(test_server,
```