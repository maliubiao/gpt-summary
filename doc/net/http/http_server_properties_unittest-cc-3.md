Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test for the `HttpServerProperties` class in Chromium's network stack. I need to identify the core functionalities being tested and explain them clearly. Specifically, I need to address the following:

1. **Core Functionality:** What is the primary purpose of the code?
2. **JavaScript Relationship:** Is there any interaction with JavaScript?
3. **Logical Reasoning (Assumptions/Output):** Can I create hypothetical inputs and expected outputs for any of the tested functions?
4. **Common User/Programming Errors:** Are there any typical mistakes users or programmers might make related to the tested features?
5. **User Journey (Debugging):** How might a user end up interacting with this code in a real-world scenario, leading to debugging?
6. **Overall Functionality (Summary):** A concise summary of the code's purpose.

Let's break down the code section by section:

* **Canonical Alternative Services and Network Isolation Keys:** Tests how alternative service information is stored and retrieved based on canonical servers and network isolation keys. It verifies that information is correctly isolated between different network contexts.
* **Marking Alternative Services as Broken:** Examines the mechanisms for marking alternative services as unusable and the impact on retrieving alternative service information. It also tests time-based expiration of the "broken" state.
* **Overriding Canonical Information:** Checks how setting alternative services for a specific host affects canonical host associations.
* **Clearing Data:** Verifies the clearing of alternative service data, including cases involving canonical servers.
* **Time-Based Expiration of Broken Services:** Focuses on testing the expiration logic for broken alternative services, including the use of network isolation keys.
* **Regression Tests for Expiration:** Addresses specific bugs related to the expiration of broken alternative services.
* **Delayed Expiration of Broken Services:** Tests the functionality for setting up delayed expiration of broken alternative services, with different delay strategies.
* **Getting Alternative Service Info as a Value:** Checks the functionality to retrieve alternative service information in a structured format (likely for debugging or logging).
* **Tracking Last Local Address When QUIC Worked:**  Tests the functionality for storing and retrieving the last local IP address that successfully established a QUIC connection.
* **Server Network Statistics:** Examines the storage and retrieval of server network performance statistics (like RTT and bandwidth).

**JavaScript Relationship:**  While the underlying data managed by `HttpServerProperties` might influence how a browser interacts with websites (e.g., choosing to use an alternative protocol), this specific unit test code doesn't directly interact with JavaScript.

**Logical Reasoning:** I can devise examples for the "broken" service testing.

**User/Programming Errors:**  Misunderstanding how canonical servers and network isolation keys interact could lead to incorrect configuration or unexpected behavior.

**User Journey:** A user experiencing connection problems might trigger debugging that eventually leads to inspecting the state of alternative service information.

**Overall Functionality:** The code primarily tests the storage, retrieval, and management of alternative service information and server network statistics within the `HttpServerProperties` class, with a focus on correct behavior under different scenarios, including network isolation and handling of broken connections.
这是对 `net/http/http_server_properties_unittest.cc` 文件中 `AlternateProtocolServerPropertiesTest` 测试套件的第四部分代码的功能归纳。 这部分代码主要关注 **备用协议（Alternative Service）信息的管理，特别是涉及到“canonical（规范）”服务器和网络隔离密钥（Network Isolation Key）的场景，以及标记和过期备用协议为“broken（不可用）”状态的功能。**

下面对这部分代码的功能进行更详细的列举和说明：

**功能列举:**

1. **备用服务和规范服务器与网络隔离密钥的交互:**
   - 测试了在存在规范服务器的情况下，如何根据不同的网络隔离密钥来存储和检索备用服务信息。
   - 验证了针对特定网络隔离密钥设置的备用服务信息，不会被其他网络隔离密钥或没有网络隔离密钥的请求所访问到。
   - 演示了为一个规范服务器的不同网络隔离密钥设置不同的备用服务信息。
   - 验证了清除特定网络隔离密钥下规范服务器的备用服务状态，只会影响该网络隔离密钥。

2. **标记规范服务器的备用服务为不可用 (Broken):**
   - 测试了将规范服务器的某个备用服务标记为不可用后，即使请求的服务器不是规范服务器本身，也无法获取到该备用服务信息。

3. **标记规范服务器的备用服务为在默认网络改变前不可用:**
   - 类似于标记为不可用，但这种状态会持续到默认网络发生改变。

4. **备用服务覆盖规范服务器的信息:**
   - 测试了为新主机添加备用服务时，会覆盖从规范服务器继承来的备用服务信息。

5. **清除包含规范服务器的备用服务信息:**
   - 验证了清除所有备用服务信息会同时清除包括通过规范服务器关联的备用服务信息。

6. **过期不可用的备用协议映射:**
   - 测试了可以设置备用协议的不可用状态过期时间。
   - 验证了过期时间到达后，该备用协议将不再被认为是不可用，并且可以被重新使用。
   - 测试了在启用网络隔离密钥的情况下，过期操作会针对特定的网络隔离密钥生效。

7. **回归测试：移除过期的不可用备用服务:**
   - 包含了多个回归测试，用于验证在特定情况下，过期的不可用备用服务能够被正确移除，避免潜在的 bug。 例如：
     - 确保即使存在没有 `alternative_services` 值的 `ServerInfo` 条目，过期操作也不会挂起。
     - 验证在多个备用服务被标记为不可用并设置不同过期时间的情况下，能够正确处理过期。

8. **设置不可用备用服务的延迟参数:**
   - 测试了可以设置备用服务被标记为不可用后，延迟多久重新变为可用的机制。
   - 验证了不同的延迟策略（例如指数退避）的实现。

9. **获取备用服务信息作为 Value 对象:**
   - 测试了将备用服务信息（包括是否不可用及其过期时间）转换为 `base::Value` 对象的功能，这通常用于调试或序列化。

**与 Javascript 的关系:**

这段 C++ 代码本身并不直接与 Javascript 交互。 然而，它所管理的数据会影响浏览器在网络请求中的行为，而这些行为可能由 Javascript 发起。

**举例说明:**

假设一个网站 `https://foo.c.youtube.com` 的规范服务器是 `https://bar.c.youtube.com`，并且 `https://bar.c.youtube.com` 声明了一个 QUIC 备用协议。

* **假设输入:** 用户通过不同的网络环境访问 `https://foo.c.youtube.com`。每个网络环境对应一个 `NetworkAnonymizationKey`。
* **输出:**  `HttpServerProperties` 能够为每个 `NetworkAnonymizationKey` 存储和检索针对 `https://bar.c.youtube.com` 的备用协议信息。如果在一个网络环境下，QUIC 连接失败，该备用协议会被标记为不可用，并且只在该网络环境下生效。在另一个网络环境下，如果 QUIC 连接正常，则备用协议仍然可用。

**用户或编程常见的使用错误举例:**

* **用户错误:** 用户可能会在网络环境不稳定时遇到某些网站的连接问题。 这可能是因为备用协议被错误地标记为不可用，导致浏览器回退到传统的 TCP 连接，而 TCP 连接可能存在问题。用户可能无法直接感知到备用协议的状态，但会感受到网页加载速度变慢或连接失败。
* **编程错误:**  开发者在实现网络功能时，可能会错误地假设所有网络环境下的备用协议状态都是一致的，而没有考虑到 `NetworkAnonymizationKey` 的隔离性。 或者，在测试网络代码时，没有考虑到备用协议被标记为不可用后的行为，导致测试结果不准确。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户访问网站:** 用户在 Chrome 浏览器中输入网址或点击链接访问一个网站 (例如 `https://foo.c.youtube.com`)。
2. **浏览器发起网络请求:** Chrome 的网络栈开始处理该请求。
3. **查询备用协议信息:** `HttpServerProperties` 组件会被查询，以获取该网站是否有可用的备用协议 (例如 QUIC 或 HTTP/3)。
4. **备用协议连接尝试 (可能):** 如果存在备用协议，浏览器可能会尝试使用该协议建立连接。
5. **连接失败 (可能):** 如果备用协议连接失败，例如由于网络问题或服务器配置错误，`HttpServerProperties` 会将该备用协议标记为不可用。
6. **调试:** 当用户遇到连接问题时，开发者可能会查看 Chrome 的内部日志 (`chrome://net-export/`) 或使用调试工具来分析网络请求过程。 通过查看日志，他们可能会发现备用协议尝试失败，并且被标记为不可用。 此时，他们可能会查看 `net/http/http_server_properties_unittest.cc` 中的相关测试用例，来理解备用协议状态管理的逻辑，并排查可能的 bug 或配置问题。

**功能归纳 (第 4 部分):**

这部分代码主要测试了 `HttpServerProperties` 类中关于备用协议信息管理的核心逻辑，特别是关注以下几个方面： **在存在规范服务器和网络隔离密钥的情况下，如何正确地存储、检索和隔离备用协议信息；以及如何标记和管理备用协议的不可用状态，包括设置过期时间，确保浏览器能够及时恢复使用之前不可用的备用协议。**  这些测试确保了备用协议功能的正确性和可靠性，对于提升网络连接性能和用户体验至关重要。

### 提示词
```
这是目录为net/http/http_server_properties_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
network_anonymization_key1_);
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(canonical_alternative_service1,
            alternative_service_info_vector2[0].alternative_service());

  // Canonical information should not be visible for other NetworkIsolationKeys.
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(test_server, network_anonymization_key2_)
          .empty());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  // Now add an alternative service entry for network_anonymization_key2_ for a
  // different server and different NetworkAnonymizationKey, but with the same
  // canonical suffix.
  url::SchemeHostPort canonical_server2("https", "shrimp.c.youtube.com", 443);
  properties.SetAlternativeServices(canonical_server2,
                                    network_anonymization_key2_,
                                    {alternative_service_info_vector[0]});

  // The canonical server information should reachable, and different, for both
  // NetworkIsolationKeys.
  EXPECT_EQ(1u, properties
                    .GetAlternativeServiceInfos(test_server,
                                                network_anonymization_key2_)
                    .size());
  EXPECT_EQ(2u, properties
                    .GetAlternativeServiceInfos(test_server,
                                                network_anonymization_key1_)
                    .size());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  // Clearing the alternate service state of network_anonymization_key1_'s
  // canonical server should only affect network_anonymization_key1_.
  properties.SetAlternativeServices(canonical_server1,
                                    network_anonymization_key1_, {});
  EXPECT_EQ(1u, properties
                    .GetAlternativeServiceInfos(test_server,
                                                network_anonymization_key2_)
                    .size());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(test_server, network_anonymization_key1_)
          .empty());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());
}

TEST_F(AlternateProtocolServerPropertiesTest, CanonicalBroken) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  EXPECT_TRUE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
  impl_.MarkAlternativeServiceBroken(canonical_alternative_service,
                                     NetworkAnonymizationKey());
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       CanonicalBrokenUntilDefaultNetworkChanges) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  EXPECT_TRUE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      canonical_alternative_service, NetworkAnonymizationKey());
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
}

// Adding an alternative service for a new host overrides canonical host.
TEST_F(AlternateProtocolServerPropertiesTest, CanonicalOverride) {
  url::SchemeHostPort foo_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort bar_server("https", "bar.c.youtube.com", 443);
  AlternativeService bar_alternative_service(kProtoQUIC, "bar.c.youtube.com",
                                             1234);
  SetAlternativeService(bar_server, bar_alternative_service);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(foo_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(bar_alternative_service,
            alternative_service_info_vector[0].alternative_service());

  url::SchemeHostPort qux_server("https", "qux.c.youtube.com", 443);
  AlternativeService qux_alternative_service(kProtoQUIC, "qux.c.youtube.com",
                                             443);
  SetAlternativeService(qux_server, qux_alternative_service);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(foo_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(qux_alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearWithCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  impl_.Clear(base::OnceClosure());
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       ExpireBrokenAlternateProtocolMappings) {
  url::SchemeHostPort server("https", "foo", 443);
  AlternativeService alternative_service(kProtoQUIC, "foo", 443);
  SetAlternativeService(server, alternative_service);
  EXPECT_TRUE(HasAlternativeService(server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  base::TimeTicks past = test_tick_clock_->NowTicks() - base::Seconds(42);
  HttpServerPropertiesPeer::AddBrokenAlternativeServiceWithExpirationTime(
      &impl_, alternative_service, past);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                               NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  HttpServerPropertiesPeer::ExpireBrokenAlternateProtocolMappings(&impl_);
  EXPECT_FALSE(HasAlternativeService(server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       ExpireBrokenAlternateProtocolMappingsWithNetworkIsolationKey) {
  url::SchemeHostPort server("https", "foo", 443);
  AlternativeService alternative_service(kProtoHTTP2, "foo", 444);
  base::TimeTicks past = test_tick_clock_->NowTicks() - base::Seconds(42);
  base::TimeTicks future = test_tick_clock_->NowTicks() + base::Seconds(42);
  const base::Time alt_service_expiration = test_clock_.Now() + base::Days(1);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetHttp2AlternativeService(server, network_anonymization_key1_,
                                        alternative_service,
                                        alt_service_expiration);
  properties.SetHttp2AlternativeService(server, network_anonymization_key2_,
                                        alternative_service,
                                        alt_service_expiration);

  EXPECT_FALSE(
      properties.GetAlternativeServiceInfos(server, network_anonymization_key1_)
          .empty());
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(
      properties.GetAlternativeServiceInfos(server, network_anonymization_key2_)
          .empty());
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  // Set broken alternative service with expiration date in the past for
  // |network_anonymization_key1_|.
  HttpServerPropertiesPeer::AddBrokenAlternativeServiceWithExpirationTime(
      &properties, alternative_service, past, network_anonymization_key1_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_FALSE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  // Set broken alternative service with expiration date in the future for
  // |network_anonymization_key1_|.
  HttpServerPropertiesPeer::AddBrokenAlternativeServiceWithExpirationTime(
      &properties, alternative_service, future, network_anonymization_key2_);
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));

  // Only the broken entry for |network_anonymization_key1_| should be expired.
  HttpServerPropertiesPeer::ExpireBrokenAlternateProtocolMappings(&properties);
  EXPECT_TRUE(
      properties.GetAlternativeServiceInfos(server, network_anonymization_key1_)
          .empty());
  EXPECT_FALSE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key1_));
  EXPECT_FALSE(
      properties.GetAlternativeServiceInfos(server, network_anonymization_key2_)
          .empty());
  EXPECT_TRUE(properties.IsAlternativeServiceBroken(
      alternative_service, network_anonymization_key2_));
  EXPECT_TRUE(properties.WasAlternativeServiceRecentlyBroken(
      alternative_service, network_anonymization_key2_));
}

// Regression test for https://crbug.com/505413.
TEST_F(AlternateProtocolServerPropertiesTest, RemoveExpiredBrokenAltSvc) {
  url::SchemeHostPort foo_server("https", "foo", 443);
  AlternativeService bar_alternative_service(kProtoQUIC, "bar", 443);
  SetAlternativeService(foo_server, bar_alternative_service);
  EXPECT_TRUE(HasAlternativeService(foo_server, NetworkAnonymizationKey()));

  url::SchemeHostPort bar_server1("http", "bar", 80);
  AlternativeService nohost_alternative_service(kProtoQUIC, "", 443);
  SetAlternativeService(bar_server1, nohost_alternative_service);
  EXPECT_TRUE(HasAlternativeService(bar_server1, NetworkAnonymizationKey()));

  url::SchemeHostPort bar_server2("https", "bar", 443);
  AlternativeService baz_alternative_service(kProtoQUIC, "baz", 1234);
  SetAlternativeService(bar_server2, baz_alternative_service);
  EXPECT_TRUE(HasAlternativeService(bar_server2, NetworkAnonymizationKey()));

  // Mark "bar:443" as broken.
  base::TimeTicks past = test_tick_clock_->NowTicks() - base::Seconds(42);
  HttpServerPropertiesPeer::AddBrokenAlternativeServiceWithExpirationTime(
      &impl_, bar_alternative_service, past);

  // Expire brokenness of "bar:443".
  HttpServerPropertiesPeer::ExpireBrokenAlternateProtocolMappings(&impl_);

  // "foo:443" should have no alternative service now.
  EXPECT_FALSE(HasAlternativeService(foo_server, NetworkAnonymizationKey()));
  // "bar:80" should have no alternative service now.
  EXPECT_FALSE(HasAlternativeService(bar_server1, NetworkAnonymizationKey()));
  // The alternative service of "bar:443" should be unaffected.
  EXPECT_TRUE(HasAlternativeService(bar_server2, NetworkAnonymizationKey()));

  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(
      bar_alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(
      baz_alternative_service, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       SetBrokenAlternativeServicesDelayParams1) {
  url::SchemeHostPort server("https", "foo", 443);
  AlternativeService alternative_service(kProtoQUIC, "foo", 443);
  SetAlternativeService(server, alternative_service);

  const base::TimeDelta initial_delay = base::Seconds(1);
  impl_.SetBrokenAlternativeServicesDelayParams(initial_delay, true);
  for (int i = 0; i < 10; ++i) {
    impl_.MarkAlternativeServiceBroken(alternative_service,
                                       NetworkAnonymizationKey());
    // |impl_| should have posted task to expire the brokenness of
    // |alternative_service|
    EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
    EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                 NetworkAnonymizationKey()));

    // Advance time by just enough so that |alternative_service|'s brokenness
    // expires.
    FastForwardBy(initial_delay * (1 << i));

    // Ensure brokenness of |alternative_service| has expired.
    EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
    EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                  NetworkAnonymizationKey()));
  }
}

TEST_F(AlternateProtocolServerPropertiesTest,
       SetBrokenAlternativeServicesDelayParams2) {
  url::SchemeHostPort server("https", "foo", 443);
  AlternativeService alternative_service(kProtoQUIC, "foo", 443);
  SetAlternativeService(server, alternative_service);

  const base::TimeDelta initial_delay = base::Seconds(5);
  impl_.SetBrokenAlternativeServicesDelayParams(initial_delay, false);
  for (int i = 0; i < 10; ++i) {
    impl_.MarkAlternativeServiceBroken(alternative_service,
                                       NetworkAnonymizationKey());
    // |impl_| should have posted task to expire the brokenness of
    // |alternative_service|
    EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
    EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                 NetworkAnonymizationKey()));

    // Advance time by just enough so that |alternative_service|'s brokenness
    // expires.
    if (i == 0) {
      FastForwardBy(initial_delay);
    } else {
      FastForwardBy(base::Seconds(300) * (1 << (i - 1)));
    }

    // Ensure brokenness of |alternative_service| has expired.
    EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
    EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service,
                                                  NetworkAnonymizationKey()));
  }
}

// Regression test for https://crbug.com/724302
TEST_F(AlternateProtocolServerPropertiesTest, RemoveExpiredBrokenAltSvc2) {
  // This test will mark an alternative service A that has already been marked
  // broken many times, then immediately mark another alternative service B as
  // broken for the first time. Because A's been marked broken many times
  // already, its brokenness will be scheduled to expire much further in the
  // future than B, even though it was marked broken before B. This test makes
  // sure that even though A was marked broken before B, B's brokenness should
  // expire before A.

  url::SchemeHostPort server1("https", "foo", 443);
  AlternativeService alternative_service1(kProtoQUIC, "foo", 443);
  SetAlternativeService(server1, alternative_service1);

  url::SchemeHostPort server2("https", "bar", 443);
  AlternativeService alternative_service2(kProtoQUIC, "bar", 443);
  SetAlternativeService(server2, alternative_service2);

  // Repeatedly mark alt svc 1 broken and wait for its brokenness to expire.
  // This will increase its time until expiration.
  for (int i = 0; i < 3; ++i) {
    impl_.MarkAlternativeServiceBroken(alternative_service1,
                                       NetworkAnonymizationKey());

    // |impl_| should have posted task to expire the brokenness of
    // |alternative_service1|
    EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
    EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                                 NetworkAnonymizationKey()));

    // Advance time by just enough so that |alternative_service1|'s brokenness
    // expires.
    FastForwardBy(BROKEN_ALT_SVC_EXPIRE_DELAYS[i]);

    // Ensure brokenness of |alternative_service1| has expired.
    EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
    EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                                  NetworkAnonymizationKey()));
  }

  impl_.MarkAlternativeServiceBroken(alternative_service1,
                                     NetworkAnonymizationKey());
  impl_.MarkAlternativeServiceBroken(alternative_service2,
                                     NetworkAnonymizationKey());

  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service2,
                                               NetworkAnonymizationKey()));

  // Advance time by just enough so that |alternative_service2|'s brokennness
  // expires.
  FastForwardBy(BROKEN_ALT_SVC_EXPIRE_DELAYS[0]);

  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service2,
                                                NetworkAnonymizationKey()));

  // Advance time by enough so that |alternative_service1|'s brokenness expires.
  FastForwardBy(BROKEN_ALT_SVC_EXPIRE_DELAYS[3] -
                BROKEN_ALT_SVC_EXPIRE_DELAYS[0]);

  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                                NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service2,
                                                NetworkAnonymizationKey()));
}

// Regression test for https://crbug.com/994537. Having a ServerInfo entry
// without a populated |alternative_services| value would cause
// OnExpireBrokenAlternativeService() to hang..
TEST_F(AlternateProtocolServerPropertiesTest, RemoveExpiredBrokenAltSvc3) {
  // Add an altertive service entry.
  const url::SchemeHostPort kServer1("https", "foo", 443);
  const AlternativeService kAltService(kProtoQUIC, "bar", 443);
  SetAlternativeService(kServer1, kAltService);
  EXPECT_TRUE(HasAlternativeService(kServer1, NetworkAnonymizationKey()));

  // Add an entry to ServerInfo for another server, without an alternative
  // service value.
  const url::SchemeHostPort kServer2("http", "bar", 80);
  impl_.SetSupportsSpdy(kServer2, NetworkAnonymizationKey(), false);

  // Mark kAltService as broken.
  base::TimeTicks past = test_tick_clock_->NowTicks() - base::Seconds(42);
  HttpServerPropertiesPeer::AddBrokenAlternativeServiceWithExpirationTime(
      &impl_, kAltService, past);

  // Expire brokenness of kAltService. This call should not hang.
  HttpServerPropertiesPeer::ExpireBrokenAlternateProtocolMappings(&impl_);

  EXPECT_FALSE(HasAlternativeService(kServer1, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       GetAlternativeServiceInfoAsValue) {
  constexpr base::Time::Exploded kNowExploded = {.year = 2018,
                                                 .month = 1,
                                                 .day_of_week = 3,
                                                 .day_of_month = 24,
                                                 .hour = 15,
                                                 .minute = 12,
                                                 .second = 53};
  base::Time now;
  bool result = base::Time::FromLocalExploded(kNowExploded, &now);
  DCHECK(result);
  test_clock_.SetNow(now);

  AlternativeServiceInfoVector alternative_service_info_vector;
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foo", 443), now + base::Minutes(1)));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          AlternativeService(kProtoQUIC, "bar", 443), now + base::Hours(1),
          DefaultSupportedQuicVersions()));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          AlternativeService(kProtoQUIC, "baz", 443), now + base::Hours(1),
          DefaultSupportedQuicVersions()));

  impl_.SetAlternativeServices(url::SchemeHostPort("https", "youtube.com", 443),
                               NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  impl_.MarkAlternativeServiceBroken(AlternativeService(kProtoQUIC, "bar", 443),
                                     NetworkAnonymizationKey());

  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      AlternativeService(kProtoQUIC, "baz", 443), NetworkAnonymizationKey());

  alternative_service_info_vector.clear();
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foo2", 443), now + base::Days(1)));
  impl_.SetAlternativeServices(url::SchemeHostPort("http", "test.com", 80),
                               NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  const char expected_json[] =
      "["
      "{"
      "\"alternative_service\":"
      "[\"h2 foo2:443, expires 2018-01-25 15:12:53\"],"
      "\"network_anonymization_key\":\"null\","
      "\"server\":\"http://test.com\""
      "},"
      "{"
      "\"alternative_service\":"
      "[\"h2 foo:443, expires 2018-01-24 15:13:53\","
      "\"quic bar:443, expires 2018-01-24 16:12:53"
      " (broken until 2018-01-24 15:17:53)\","
      "\"quic baz:443, expires 2018-01-24 16:12:53"
      " (broken until 2018-01-24 15:17:53)\"],"
      "\"network_anonymization_key\":\"null\","
      "\"server\":\"https://youtube.com\""
      "}"
      "]";

  base::Value alternative_service_info_value =
      impl_.GetAlternativeServiceInfoAsValue();
  std::string alternative_service_info_json;
  base::JSONWriter::Write(alternative_service_info_value,
                          &alternative_service_info_json);
  EXPECT_EQ(expected_json, alternative_service_info_json);
}

TEST_F(HttpServerPropertiesTest, LoadLastLocalAddressWhenQuicWorked) {
  const IPAddress kEmptyAddress;
  const IPAddress kValidAddress1 = IPAddress::IPv4Localhost();
  const IPAddress kValidAddress2 = IPAddress::IPv6Localhost();

  // Check by initializing empty address.
  impl_.OnLastLocalAddressWhenQuicWorkedForTesting(kEmptyAddress);
  EXPECT_FALSE(impl_.HasLastLocalAddressWhenQuicWorked());
  // Empty address should not be considered an address that was used when QUIC
  // worked.
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Check by initializing with a valid address.
  impl_.OnLastLocalAddressWhenQuicWorkedForTesting(kValidAddress1);
  EXPECT_TRUE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_TRUE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Try another valid address.
  impl_.OnLastLocalAddressWhenQuicWorkedForTesting(kValidAddress2);
  EXPECT_TRUE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_TRUE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // And loading an empty address clears the current one.
  // TODO(mmenke): This seems like a bug, since if we've learned the current
  // network supports QUIC, surely we want to save that to disk? Seems like a
  // pre-existing value should take precedence, if non-empty, since if the
  // current network is already known to support QUIC, the loaded value is no
  // longer relevant.
  impl_.OnLastLocalAddressWhenQuicWorkedForTesting(kEmptyAddress);
  EXPECT_FALSE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));
}

TEST_F(HttpServerPropertiesTest, SetLastLocalAddressWhenQuicWorked) {
  const IPAddress kEmptyAddress;
  const IPAddress kValidAddress1 = IPAddress::IPv4Localhost();
  const IPAddress kValidAddress2 = IPAddress::IPv6Localhost();

  EXPECT_FALSE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Set to a valid address.
  impl_.SetLastLocalAddressWhenQuicWorked(kValidAddress1);
  EXPECT_TRUE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_TRUE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Clear only this value.
  impl_.ClearLastLocalAddressWhenQuicWorked();
  EXPECT_FALSE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Try another valid address.
  impl_.SetLastLocalAddressWhenQuicWorked(kValidAddress2);
  EXPECT_TRUE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_TRUE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));

  // Clear all values.
  impl_.Clear(base::OnceClosure());
  EXPECT_FALSE(impl_.HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kEmptyAddress));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress1));
  EXPECT_FALSE(impl_.WasLastLocalAddressWhenQuicWorked(kValidAddress2));
}

TEST_F(HttpServerPropertiesTest, LoadServerNetworkStats) {
  url::SchemeHostPort google_server("https", "www.google.com", 443);

  // Check by initializing empty ServerNetworkStats.
  std::unique_ptr<HttpServerProperties::ServerInfoMap> load_server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  impl_.OnServerInfoLoadedForTesting(std::move(load_server_info_map));
  const ServerNetworkStats* stats =
      impl_.GetServerNetworkStats(google_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, stats);

  // Check by initializing with www.google.com:443.
  ServerNetworkStats stats_google;
  stats_google.srtt = base::Microseconds(10);
  stats_google.bandwidth_estimate = quic::QuicBandwidth::FromBitsPerSecond(100);
  load_server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  load_server_info_map->GetOrPut(CreateSimpleKey(google_server))
      ->second.server_network_stats = stats_google;
  impl_.OnServerInfoLoadedForTesting(std::move(load_server_info_map));

  // Verify data for www.google.com:443.
  ASSERT_EQ(1u, impl_.server_info_map_for_testing().size());
  EXPECT_EQ(stats_google, *(impl_.GetServerNetworkStats(
                              google_server, NetworkAnonymizationKey())));

  // Test recency order and overwriting of data.
  //
  // |docs_server| has a ServerNetworkStats, which will be overwritten by
  // OnServerInfoLoadedForTesting(), because |server_network_stats_map| has an
  // entry for |docs_server|.
  url::SchemeHostPort docs_server("https", "docs.google.com", 443);
  ServerNetworkStats stats_docs;
  stats_docs.srtt = base::Microseconds(20);
  stats_docs.bandwidth_estimate = quic::QuicBandwidth::FromBitsPerSecond(200);
  // Recency order will be |docs_server| and |google_server|.
  impl_.SetServerNetworkStats(docs_server, NetworkAnonymizationKey(),
                              stats_docs);

  // Prepare |server_info_map| to be loaded by OnServerInfoLoadedForTesting().
  std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();

  // Change the values for |docs_server|.
  ServerNetworkStats new_stats_docs;
  new_stats_docs.srtt = base::Microseconds(25);
  new_stats_docs.bandwidth_estimate =
      quic::QuicBandwidth::FromBitsPerSecond(250);
  server_info_map->GetOrPut(CreateSimpleKey(docs_server))
      ->second.server_network_stats = new_stats_docs;
  // Add data for mail.google.com:443.
  url::SchemeHostPort mail_server("https", "mail.google.com", 443);
  ServerNetworkStats stats_mail;
  stats_mail.srtt = base::Microseconds(30);
  stats_mail.bandwidth_estimate = quic::QuicBandwidth::FromBitsPerSecond(300);
  server_info_map->GetOrPut(CreateSimpleKey(mail_server))
      ->second.server_network_stats = stats_mail;

  // Recency order will be |docs_server|, |google_server| and |mail_server|.
  impl_.OnServerInfoLoadedForTesting(std::move(server_info_map));

  const HttpServerProperties::ServerInfoMap& map =
      impl_.server_info_map_for_testing();
  ASSERT_EQ(3u, map.size());
  auto map_it = map.begin();

  EXPECT_EQ(docs_server, map_it->first.server);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.server_network_stats.has_value());
  EXPECT_EQ(new_stats_docs, *map_it->second.server_network_stats);
  ++map_it;
  EXPECT_EQ(google_server, map_it->first.server);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.server_network_stats.has_value());
  EXPECT_EQ(stats_google, *map_it->second.server_network_stats);
  ++map_it;
  EXPECT_EQ(mail_server, map_it->first.server);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.server_network_stats.has_value());
  EXPECT_EQ(stats_mail, *map_it->second.server_network_stats);
}

TEST_F(HttpServerPropertiesTest, SetServerNetworkStats) {
  url::SchemeHostPort foo_http_server("http", "foo", 443);
  url::SchemeHostPort foo_https_server("https", "foo", 443);
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_http_server,
                                                 NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_https_server,
                                                 NetworkAnonymizationKey()));

  ServerNetworkStats stats1;
  stats1.srtt = base::Microseconds(10);
  stats1.bandwidth_estimate = quic::QuicBandwidth::FromBitsPerSecond(100);
  impl_.SetServerNetworkStats(foo_http_server, NetworkAnonymizationKey(),
                              stats1);

  const ServerNetworkStats* stats2 =
      impl_.GetServerNetworkStats(foo_http_server, NetworkAnonymizationKey());
  EXPECT_EQ(10, stats2->srtt.ToInternalValue());
  EXPECT_EQ(100, stats2->bandwidth_estimate.ToBitsPerSecond());
  /
```