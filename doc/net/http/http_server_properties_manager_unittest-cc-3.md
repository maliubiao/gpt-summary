Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the code and identify its purpose, paying attention to the following aspects as requested:

1. **Functionality:** What does this code do?
2. **Relationship to JavaScript:** Does it interact with or affect JavaScript functionality? If so, how?
3. **Logic and Reasoning:** Are there any logical deductions being made? If so, provide examples with hypothetical inputs and outputs.
4. **User/Programming Errors:** What common mistakes could users or developers make related to this code?
5. **User Journey:** How might a user's actions lead to this code being executed (for debugging)?
6. **Overall Function:**  A concise summary of the code's purpose.

Based on the code, it appears to be testing the `HttpServerPropertiesManager` class, specifically focusing on how it handles data persistence and the impact of `NetworkAnonymizationKey`. The tests involve setting and retrieving various properties (like support for SPDY, alternative services, and QUIC server info) under different `NetworkAnonymizationKey` configurations and verifying that these properties are correctly saved and loaded from preferences.

Here's a breakdown of the code's actions:

* **Feature Flags:** The code uses `base::test::ScopedFeatureList` to enable or disable the `kPartitionConnectionsByNetworkIsolationKey` feature, which is related to `NetworkAnonymizationKey`.
* **`HttpServerProperties`:** It creates and manipulates instances of `HttpServerProperties`, the class being tested.
* **`MockPrefDelegate`:** It uses a mock object `MockPrefDelegate` to simulate the storage and retrieval of preferences.
* **`NetworkAnonymizationKey`:**  The tests extensively use `NetworkAnonymizationKey` with and without opaque origins to test how properties are partitioned based on this key.
* **Persistence Testing:** The core of the tests involves setting properties, waiting for them to be written to the mock preferences, creating a new `HttpServerProperties` instance, loading the saved preferences, and verifying the properties were loaded correctly.
* **Specific Property Tests:**  The tests focus on:
    * `SetSupportsSpdy` and `GetSupportsSpdy`
    * `SetAlternativeServices` and `GetAlternativeServiceInfos`
    * `MarkAlternativeServiceBroken` and related methods
    * `SetQuicServerInfo` and `GetQuicServerInfo`
* **Canonical Suffixes:** One test (`CanonicalSuffixRoundTripWithNetworkAnonymizationKey`) specifically verifies the logic for canonical suffixes and how `NetworkAnonymizationKey` interacts with it.
* **Opaque Origins:** The tests check how properties associated with opaque origins are handled (specifically, they are not persisted).
* **Feature Flag Variation:**  The `NetworkAnonymizationKeyBrokenAltServiceRoundTrip` and `NetworkAnonymizationKeyQuicServerInfoRoundTrip` tests iterate through different `NetworkAnonymizationKeyMode` settings to ensure the persistence and retrieval logic works correctly under various feature configurations.

Now, let's consider the specific requirements of the prompt:

* **JavaScript Relationship:** The code directly doesn't execute JavaScript. However, the functionality it tests (managing HTTP server properties) indirectly affects how the browser interacts with web servers, which in turn impacts JavaScript running on web pages. For example, knowing that a server supports HTTP/2 or QUIC can affect the performance and behavior of network requests initiated by JavaScript.
* **Logical Reasoning:** The code demonstrates logical reasoning in its assertions (e.g., `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`). It sets up certain conditions and then verifies the expected outcomes.
* **User/Programming Errors:** There are potential errors related to the correct usage of `NetworkAnonymizationKey` and understanding its impact on data isolation.
* **User Journey:**  A user's browsing activity can trigger the saving and loading of HTTP server properties.
* **Summary:**  The code tests the persistence and `NetworkAnonymizationKey`-based partitioning of HTTP server properties in Chromium.
这是Chromium网络栈中 `net/http/http_server_properties_manager_unittest.cc` 文件的第四部分，主要功能是**测试 `HttpServerPropertiesManager` 类在启用 `NetworkAnonymizationKey` 特性时的行为，特别是涉及持久化存储（通过 `MockPrefDelegate` 模拟）各种 HTTP 服务器属性，例如 SPDY 支持、备用服务（Alternative Services）和 QUIC 服务器信息。**

**具体功能归纳如下：**

1. **`NetworkAnonymizationKeyIntegration` 测试:**
   - 测试了在启用 `kPartitionConnectionsByNetworkIsolationKey` 特性后，`HttpServerProperties` 如何使用 `NetworkAnonymizationKey` 来隔离和存储服务器属性。
   - 验证了使用特定的 `NetworkAnonymizationKey` 设置的属性，只能通过相同的 `NetworkAnonymizationKey` 获取，并且不会与其他 `NetworkAnonymizationKey` 或未设置 `NetworkAnonymizationKey` 的情况混淆。
   - 特别测试了不透明来源（opaque origins，例如 `data:` URL）的 `NetworkAnonymizationKey`，确认这些来源相关的服务器属性不会被持久化到磁盘。

2. **`CanonicalSuffixRoundTripWithNetworkAnonymizationKey` 测试:**
   - 测试了当启用 `kPartitionConnectionsByNetworkIsolationKey` 特性时，对于具有相同规范后缀（canonical suffix）的不同服务器，`HttpServerProperties` 如何使用 `NetworkAnonymizationKey` 来存储和检索备用服务信息。
   - 验证了针对特定服务器和 `NetworkAnonymizationKey` 设置的备用服务信息，对于具有相同规范后缀的其他服务器，只有在相同的 `NetworkAnonymizationKey` 下才能被检索到。

3. **`NetworkAnonymizationKeyBrokenAltServiceRoundTrip` 测试:**
   - 这是一个更全面的测试，涵盖了在启用 `NetworkAnonymizationKey` 特性后，标记备用服务为“已损坏”（broken）并在不同 `NetworkAnonymizationKeyMode` 下进行持久化和恢复的过程。
   - `NetworkAnonymizationKeyMode` 模拟了该特性启用、禁用和仅用于写入的不同状态，测试了跨不同模式保存和加载数据时的行为。
   - 验证了当 `NetworkAnonymizationKey` 启用时，不同 `NetworkAnonymizationKey` 之间的“已损坏”状态不会互相干扰。
   - 强调了当保存时 `NetworkAnonymizationKey` 被禁用时，所有信息都将使用空的 `NetworkAnonymizationKey` 保存，这在加载时需要考虑兼容性。

4. **`NetworkAnonymizationKeyBrokenAltServiceOpaqueOrigin` 测试:**
   - 专门测试了当使用不透明来源的 `NetworkAnonymizationKey` 标记备用服务为“已损坏”时，这些信息是否会被持久化。
   - 验证了与不透明来源相关的“已损坏”的备用服务信息不会被保存到磁盘。

5. **`NetworkAnonymizationKeyQuicServerInfoRoundTrip` 测试:**
   - 测试了在启用 `NetworkAnonymizationKey` 特性后，`HttpServerProperties` 如何存储和检索 QUIC 服务器信息，并考虑了隐私模式（`PRIVACY_MODE_DISABLED` 和 `PRIVACY_MODE_ENABLED`）。
   - 同样，该测试覆盖了不同的 `NetworkAnonymizationKeyMode`，验证了跨模式保存和加载 QUIC 服务器信息的行为。
   - 确认了 QUIC 服务器信息会根据 `NetworkAnonymizationKey` 进行隔离存储。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它测试的功能直接影响着浏览器如何与服务器建立连接，这会间接影响到 JavaScript 的执行。

* **性能优化:** `HttpServerProperties` 存储了服务器是否支持 SPDY/HTTP/2/HTTP/3 或 QUIC，以及备用服务信息。这些信息允许浏览器在后续连接中直接使用更高效的协议或连接到备用服务，从而减少延迟，提升页面加载速度，这直接有利于 JavaScript 应用的性能。
* **网络隔离:** `NetworkAnonymizationKey` 的引入是为了增强隐私，防止不同站点之间的信息泄露。当 JavaScript 发起网络请求时，浏览器会根据请求的上下文（例如，发起请求的页面来源）应用相应的 `NetworkAnonymizationKey`。`HttpServerProperties` 中存储的服务器属性也会基于此 Key 进行隔离，确保了不同站点的网络偏好设置不会互相影响。

**JavaScript 举例说明：**

假设一个 JavaScript 应用尝试连接到 `https://foo.test/`。

```javascript
fetch('https://foo.test/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在执行这段代码时，浏览器会查找 `HttpServerProperties` 中是否存储了关于 `foo.test` 的信息。如果 `NetworkAnonymizationKeyIntegration` 测试覆盖的功能正常，浏览器会正确地根据当前页面的 `NetworkAnonymizationKey` 来查找对应的服务器属性，例如是否支持 HTTP/3 或存在可用的备用 QUIC 服务。这会影响浏览器选择使用哪个协议来建立连接，从而影响 `fetch` 请求的性能。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `NetworkAnonymizationKeyIntegration` 测试):**

1. 启用了 `kPartitionConnectionsByNetworkIsolationKey` 特性。
2. 针对服务器 `https://baz.test:443` 和 `NetworkAnonymizationKey` 为 `SameSite(https://foo.test/)` 设置 `supportsSpdy` 为 `true`。
3. 尝试获取服务器 `https://baz.test:443` 在以下 `NetworkAnonymizationKey` 下的 `supportsSpdy` 状态：
   - `SameSite(https://foo.test/)`
   - `SameSite(data:text/plain,Hello World)`
   - `空 NetworkAnonymizationKey`

**预期输出:**

- 对于 `SameSite(https://foo.test/)`，`GetSupportsSpdy` 返回 `true`。
- 对于 `SameSite(data:text/plain,Hello World)`，`GetSupportsSpdy` 返回 `false`。
- 对于 `空 NetworkAnonymizationKey`，`GetSupportsSpdy` 返回 `false`。

**用户或编程常见的使用错误：**

1. **误解 `NetworkAnonymizationKey` 的作用:** 开发者可能不理解 `NetworkAnonymizationKey` 的隔离作用，认为在没有显式设置的情况下，某些服务器属性（例如备用服务）应该对所有来源都生效。实际上，启用该特性后，需要考虑 `NetworkAnonymizationKey` 的上下文。
2. **持久化数据不一致:**  如果在不同的 Chromium 版本或配置下，`NetworkAnonymizationKey` 的生成逻辑发生变化，可能会导致之前持久化的服务器属性无法正确加载或匹配，从而引发意外的网络行为。
3. **不正确地处理不透明来源:** 开发者可能会期望与不透明来源相关的服务器属性能够被持久化和共享，但实际上出于隐私考虑，这些信息通常不会被保存。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在使用 Chrome 浏览器浏览网页时遇到网络连接问题，并且怀疑是浏览器缓存的服务器属性导致了问题。作为开发者或高级用户，可能会采取以下步骤来调试：

1. **用户浏览特定网站:** 用户访问了 `https://foo.test/` 这个网站。
2. **浏览器尝试建立连接:** Chrome 尝试与 `foo.test` 的服务器建立连接。
3. **查找服务器属性:**  在建立连接的过程中，网络栈会查询 `HttpServerPropertiesManager` 中是否存储了关于 `foo.test` 的信息，例如是否支持 HTTP/3，是否有可用的备用 QUIC 服务。
4. **`NetworkAnonymizationKey` 的应用:** 如果启用了 `kPartitionConnectionsByNetworkIsolationKey`，浏览器会使用与 `foo.test` 关联的 `NetworkAnonymizationKey` 来查找对应的服务器属性。
5. **可能触发持久化:** 如果连接成功或失败，或者服务器发送了新的协议支持信息，`HttpServerPropertiesManager` 可能会更新并持久化这些信息到本地存储（通过 `MockPrefDelegate` 模拟的场景）。
6. **调试工具:** 开发者可能会使用 Chrome 的 `net-internals` 工具 (通过在地址栏输入 `chrome://net-internals/#http_server_properties`) 来查看和清除缓存的 HTTP 服务器属性，以便排查问题。
7. **源代码调试:** 如果问题难以排查，开发者可能会查看 `net/http/http_server_properties_manager.cc` 和相关的单元测试文件，例如当前文件，来理解属性的存储和检索逻辑，以及 `NetworkAnonymizationKey` 的作用。

**总结一下它的功能（第4部分）：**

这段代码是 `HttpServerPropertiesManager` 的单元测试的一部分，专门测试了在启用 `NetworkAnonymizationKey` 特性后，服务器属性（SPDY 支持、备用服务、QUIC 服务器信息）如何根据 `NetworkAnonymizationKey` 进行隔离、持久化和恢复。它涵盖了普通来源和不透明来源，以及在不同 `NetworkAnonymizationKeyMode` 下的行为，确保了该特性在存储和检索服务器属性时的正确性和隐私性。

### 提示词
```
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
pServerPropertiesManagerTest, NetworkAnonymizationKeyIntegration) {
  const SchemefulSite kSite(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const url::SchemeHostPort kServer("https", "baz.test", 443);

  const SchemefulSite kOpaqueSite(GURL("data:text/plain,Hello World"));
  const auto kOpaqueSiteNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kOpaqueSite);
  const url::SchemeHostPort kServer2("https", "zab.test", 443);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Create and initialize an HttpServerProperties with no state.
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  std::unique_ptr<HttpServerProperties> properties =
      std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                             /*net_log=*/nullptr,
                                             GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(base::Value::Dict());

  // Set a values using kNetworkAnonymizationKey.
  properties->SetSupportsSpdy(kServer, kNetworkAnonymizationKey, true);
  EXPECT_TRUE(properties->GetSupportsSpdy(kServer, kNetworkAnonymizationKey));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer, kOpaqueSiteNetworkAnonymizationKey));
  EXPECT_FALSE(properties->GetSupportsSpdy(kServer, NetworkAnonymizationKey()));

  // Opaque origins should works with HttpServerProperties, but not be persisted
  // to disk.
  properties->SetSupportsSpdy(kServer2, kOpaqueSiteNetworkAnonymizationKey,
                              true);
  EXPECT_FALSE(properties->GetSupportsSpdy(kServer2, kNetworkAnonymizationKey));
  EXPECT_TRUE(properties->GetSupportsSpdy(kServer2,
                                          kOpaqueSiteNetworkAnonymizationKey));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));

  // Wait until the data's been written to prefs, and then tear down the
  // HttpServerProperties.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  base::Value::Dict saved_value =
      unowned_pref_delegate->GetServerProperties().Clone();
  properties.reset();

  // Create a new HttpServerProperties using the value saved to prefs above.
  pref_delegate = std::make_unique<MockPrefDelegate>();
  unowned_pref_delegate = pref_delegate.get();
  properties = std::make_unique<HttpServerProperties>(
      std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(std::move(saved_value));

  // The information set using kNetworkAnonymizationKey on the original
  // HttpServerProperties should also be set on the restored
  // HttpServerProperties.
  EXPECT_TRUE(properties->GetSupportsSpdy(kServer, kNetworkAnonymizationKey));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer, kOpaqueSiteNetworkAnonymizationKey));
  EXPECT_FALSE(properties->GetSupportsSpdy(kServer, NetworkAnonymizationKey()));

  // The information set using kOpaqueSiteNetworkAnonymizationKey should not
  // have been restored.
  EXPECT_FALSE(properties->GetSupportsSpdy(kServer2, kNetworkAnonymizationKey));
  EXPECT_FALSE(properties->GetSupportsSpdy(kServer2,
                                           kOpaqueSiteNetworkAnonymizationKey));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));
}

// Tests a full round trip to prefs and back in the canonical suffix case.
// Enable NetworkAnonymizationKeys, as they have some interactions with the
// canonical suffix logic.
TEST_F(HttpServerPropertiesManagerTest,
       CanonicalSuffixRoundTripWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  // Three servers with the same canonical suffix (".c.youtube.com").
  const url::SchemeHostPort kServer1("https", "foo.c.youtube.com", 443);
  const url::SchemeHostPort kServer2("https", "bar.c.youtube.com", 443);
  const url::SchemeHostPort kServer3("https", "baz.c.youtube.com", 443);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Create three alt service vectors of different lengths.
  base::Time expiration = base::Time::Now() + base::Days(1);
  AlternativeServiceInfo alt_service1 =
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          AlternativeService(kProtoQUIC, "foopy.c.youtube.com", 1234),
          expiration, DefaultSupportedQuicVersions());
  AlternativeServiceInfo alt_service2 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foopy.c.youtube.com", 443),
          expiration);
  AlternativeServiceInfo alt_service3 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foopy2.c.youtube.com", 443),
          expiration);
  AlternativeServiceInfoVector alt_service_vector1 = {alt_service1};
  AlternativeServiceInfoVector alt_service_vector2 = {alt_service1,
                                                      alt_service2};
  AlternativeServiceInfoVector alt_service_vector3 = {
      alt_service1, alt_service2, alt_service3};

  // Create and initialize an HttpServerProperties with no state.
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  std::unique_ptr<HttpServerProperties> properties =
      std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                             /*net_log=*/nullptr,
                                             GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(base::Value::Dict());

  // Set alternative services for kServer1 using kNetworkAnonymizationKey1. That
  // information should be retrieved when fetching information for any server
  // with the same canonical suffix, when using kNetworkAnonymizationKey1.
  properties->SetAlternativeServices(kServer1, kNetworkAnonymizationKey1,
                                     alt_service_vector1);
  EXPECT_EQ(
      1u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      1u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      1u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      0u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey2)
              .size());

  // Set different alternative services for kServer2 using
  // kNetworkAnonymizationKey1. It should not affect information retrieved for
  // kServer1, but should for kServer2 and kServer3.
  properties->SetAlternativeServices(kServer2, kNetworkAnonymizationKey1,
                                     alt_service_vector2);
  EXPECT_EQ(
      1u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      0u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey2)
              .size());

  // Set different information for kServer1 using kNetworkAnonymizationKey2. It
  // should not affect information stored for kNetworkAnonymizationKey1.
  properties->SetAlternativeServices(kServer1, kNetworkAnonymizationKey2,
                                     alt_service_vector3);
  EXPECT_EQ(
      1u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey2)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey2)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey2)
              .size());

  // Wait until the data's been written to prefs, and then tear down the
  // HttpServerProperties.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  base::Value::Dict saved_value =
      unowned_pref_delegate->GetServerProperties().Clone();
  properties.reset();

  // Create a new HttpServerProperties using the value saved to prefs above.
  pref_delegate = std::make_unique<MockPrefDelegate>();
  unowned_pref_delegate = pref_delegate.get();
  properties = std::make_unique<HttpServerProperties>(
      std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(std::move(saved_value));

  // Only the last of the values learned for kNetworkAnonymizationKey1 should
  // have been saved, and the value for kNetworkAnonymizationKey2 as well. The
  // canonical suffix logic should still be respected.
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      2u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey1)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer1, kNetworkAnonymizationKey2)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer2, kNetworkAnonymizationKey2)
              .size());
  EXPECT_EQ(
      3u, properties
              ->GetAlternativeServiceInfos(kServer3, kNetworkAnonymizationKey2)
              .size());
}

// Tests a full round trip with a NetworkAnonymizationKey, using the
// HttpServerProperties interface and setting alternative services as broken.
TEST_F(HttpServerPropertiesManagerTest,
       NetworkAnonymizationKeyBrokenAltServiceRoundTrip) {
  const SchemefulSite kSite1(GURL("https://foo1.test/"));
  const SchemefulSite kSite2(GURL("https://foo2.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  const AlternativeService kAlternativeService1(kProtoHTTP2,
                                                "alt.service1.test", 443);
  const AlternativeService kAlternativeService2(kProtoHTTP2,
                                                "alt.service2.test", 443);

  for (auto save_network_anonymization_key_mode :
       kNetworkAnonymizationKeyModes) {
    SCOPED_TRACE(static_cast<int>(save_network_anonymization_key_mode));

    // Save prefs using |save_network_anonymization_key_mode|.
    base::Value::Dict saved_value;
    {
      // Configure the the feature.
      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(save_network_anonymization_key_mode);

      // Create and initialize an HttpServerProperties, must be done after
      // setting the feature.
      std::unique_ptr<MockPrefDelegate> pref_delegate =
          std::make_unique<MockPrefDelegate>();
      MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
      std::unique_ptr<HttpServerProperties> properties =
          std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                                 /*net_log=*/nullptr,
                                                 GetMockTickClock());
      unowned_pref_delegate->InitializePrefs(base::Value::Dict());

      // Set kAlternativeService1 as broken in the context of
      // kNetworkAnonymizationKey1, and kAlternativeService2 as broken in the
      // context of the empty NetworkAnonymizationKey2, and recently broken in
      // the context of the empty NetworkAnonymizationKey.
      properties->MarkAlternativeServiceBroken(kAlternativeService1,
                                               kNetworkAnonymizationKey1);
      properties->MarkAlternativeServiceRecentlyBroken(
          kAlternativeService2, NetworkAnonymizationKey());
      properties->MarkAlternativeServiceBroken(kAlternativeService2,
                                               kNetworkAnonymizationKey2);

      // Verify values were set.
      EXPECT_TRUE(properties->IsAlternativeServiceBroken(
          kAlternativeService1, kNetworkAnonymizationKey1));
      EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
          kAlternativeService1, kNetworkAnonymizationKey1));
      // When NetworkAnonymizationKeys are disabled, kAlternativeService2 is
      // marked as broken regardless of the values passed to
      // NetworkAnonymizationKey's constructor.
      EXPECT_EQ(save_network_anonymization_key_mode ==
                    NetworkAnonymizationKeyMode::kDisabled,
                properties->IsAlternativeServiceBroken(
                    kAlternativeService2, NetworkAnonymizationKey()));
      EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
          kAlternativeService2, NetworkAnonymizationKey()));
      EXPECT_TRUE(properties->IsAlternativeServiceBroken(
          kAlternativeService2, kNetworkAnonymizationKey2));
      EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
          kAlternativeService2, kNetworkAnonymizationKey2));

      // If NetworkAnonymizationKeys are enabled, there should be no
      // cross-contamination of the NetworkAnonymizationKeys.
      if (save_network_anonymization_key_mode !=
          NetworkAnonymizationKeyMode::kDisabled) {
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService2, kNetworkAnonymizationKey1));
        EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService2, kNetworkAnonymizationKey1));
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService1, NetworkAnonymizationKey()));
        EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService1, NetworkAnonymizationKey()));
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService1, kNetworkAnonymizationKey2));
        EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService1, kNetworkAnonymizationKey2));
      }

      // Wait until the data's been written to prefs, and then create a copy of
      // the prefs data.
      FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
      saved_value = unowned_pref_delegate->GetServerProperties().Clone();
    }

    // Now try and load the data in each of the feature modes.
    for (auto load_network_anonymization_key_mode :
         kNetworkAnonymizationKeyModes) {
      SCOPED_TRACE(static_cast<int>(load_network_anonymization_key_mode));

      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(load_network_anonymization_key_mode);

      // Create a new HttpServerProperties, loading the data from before.
      std::unique_ptr<MockPrefDelegate> pref_delegate =
          std::make_unique<MockPrefDelegate>();
      MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
      std::unique_ptr<HttpServerProperties> properties =
          std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                                 /*net_log=*/nullptr,
                                                 GetMockTickClock());
      unowned_pref_delegate->InitializePrefs(saved_value.Clone());

      if (save_network_anonymization_key_mode ==
          NetworkAnonymizationKeyMode::kDisabled) {
        // If NetworkAnonymizationKey was disabled when saving, it was saved
        // with an empty NetworkAnonymizationKey, which should always be loaded
        // successfully. This is needed to continue to support consumers that
        // don't use NetworkAnonymizationKeys.
        EXPECT_TRUE(properties->IsAlternativeServiceBroken(
            kAlternativeService1, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService1, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->IsAlternativeServiceBroken(
            kAlternativeService2, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService2, NetworkAnonymizationKey()));
      } else if (save_network_anonymization_key_mode ==
                 load_network_anonymization_key_mode) {
        // If the save and load modes are the same, the load should succeed, and
        // the network anonymization keys should match.
        EXPECT_TRUE(properties->IsAlternativeServiceBroken(
            kAlternativeService1, kNetworkAnonymizationKey1));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService1, kNetworkAnonymizationKey1));
        // When NetworkAnonymizationKeys are disabled, kAlternativeService2 is
        // marked as broken regardless of the values passed to
        // NetworkAnonymizationKey's constructor.
        EXPECT_EQ(save_network_anonymization_key_mode ==
                      NetworkAnonymizationKeyMode::kDisabled,
                  properties->IsAlternativeServiceBroken(
                      kAlternativeService2, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService2, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->IsAlternativeServiceBroken(
            kAlternativeService2, kNetworkAnonymizationKey2));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService2, kNetworkAnonymizationKey2));

        // If NetworkAnonymizationKeys are enabled, there should be no
        // cross-contamination of the NetworkAnonymizationKeys.
        if (save_network_anonymization_key_mode !=
            NetworkAnonymizationKeyMode::kDisabled) {
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService2, kNetworkAnonymizationKey1));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService2, kNetworkAnonymizationKey1));
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService1, NetworkAnonymizationKey()));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService1, NetworkAnonymizationKey()));
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService1, kNetworkAnonymizationKey2));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService1, kNetworkAnonymizationKey2));
        }
      } else {
        // Otherwise, only the values set with an empty NetworkAnonymizationKey
        // should have been loaded successfully.
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService1, kNetworkAnonymizationKey1));
        EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService1, kNetworkAnonymizationKey1));
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService2, NetworkAnonymizationKey()));
        EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
            kAlternativeService2, NetworkAnonymizationKey()));
        EXPECT_FALSE(properties->IsAlternativeServiceBroken(
            kAlternativeService2, kNetworkAnonymizationKey2));
        // If the load mode is NetworkAnonymizationKeyMode::kDisabled,
        // kNetworkAnonymizationKey2 is NetworkAnonymizationKey().
        EXPECT_EQ(load_network_anonymization_key_mode ==
                      NetworkAnonymizationKeyMode::kDisabled,
                  properties->WasAlternativeServiceRecentlyBroken(
                      kAlternativeService2, kNetworkAnonymizationKey2));

        // There should be no cross-contamination of NetworkAnonymizationKeys,
        // if NetworkAnonymizationKeys are enabled.
        if (load_network_anonymization_key_mode !=
            NetworkAnonymizationKeyMode::kDisabled) {
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService2, kNetworkAnonymizationKey1));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService2, kNetworkAnonymizationKey1));
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService1, NetworkAnonymizationKey()));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService1, NetworkAnonymizationKey()));
          EXPECT_FALSE(properties->IsAlternativeServiceBroken(
              kAlternativeService1, kNetworkAnonymizationKey2));
          EXPECT_FALSE(properties->WasAlternativeServiceRecentlyBroken(
              kAlternativeService1, kNetworkAnonymizationKey2));
        }
      }
    }
  }
}

// Make sure broken alt services with opaque origins aren't saved.
TEST_F(HttpServerPropertiesManagerTest,
       NetworkAnonymizationKeyBrokenAltServiceOpaqueOrigin) {
  const SchemefulSite kOpaqueSite(GURL("data:text/plain,Hello World"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kOpaqueSite);
  const AlternativeService kAlternativeService(kProtoHTTP2, "alt.service1.test",
                                               443);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Create and initialize an HttpServerProperties, must be done after
  // setting the feature.
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  std::unique_ptr<HttpServerProperties> properties =
      std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                             /*net_log=*/nullptr,
                                             GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(base::Value::Dict());

  properties->MarkAlternativeServiceBroken(kAlternativeService,
                                           kNetworkAnonymizationKey);

  // Verify values were set.
  EXPECT_TRUE(properties->IsAlternativeServiceBroken(kAlternativeService,
                                                     kNetworkAnonymizationKey));
  EXPECT_TRUE(properties->WasAlternativeServiceRecentlyBroken(
      kAlternativeService, kNetworkAnonymizationKey));

  // Wait until the data's been written to prefs, and then create a copy of
  // the prefs data.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());

  // No information should have been saved to prefs.
  std::string preferences_json;
  base::JSONWriter::Write(unowned_pref_delegate->GetServerProperties(),
                          &preferences_json);
  EXPECT_EQ("{\"servers\":[],\"version\":5}", preferences_json);
}

// Tests a full round trip with a NetworkAnonymizationKey, using the
// HttpServerProperties interface and setting QuicServerInfo.
TEST_F(HttpServerPropertiesManagerTest,
       NetworkAnonymizationKeyQuicServerInfoRoundTrip) {
  const SchemefulSite kSite1(GURL("https://foo1.test/"));
  const SchemefulSite kSite2(GURL("https://foo2.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  const quic::QuicServerId kServer1("foo", 443);
  const quic::QuicServerId kServer2("foo", 443);

  const char kQuicServerInfo1[] = "info1";
  const char kQuicServerInfo2[] = "info2";
  const char kQuicServerInfo3[] = "info3";

  for (auto save_network_anonymization_key_mode :
       kNetworkAnonymizationKeyModes) {
    SCOPED_TRACE(static_cast<int>(save_network_anonymization_key_mode));

    // Save prefs using |save_network_anonymization_key_mode|.
    base::Value::Dict saved_value;
    {
      // Configure the the feature.
      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(save_network_anonymization_key_mode);

      // Create and initialize an HttpServerProperties, must be done after
      // setting the feature.
      std::unique_ptr<MockPrefDelegate> pref_delegate =
          std::make_unique<MockPrefDelegate>();
      MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
      std::unique_ptr<HttpServerProperties> properties =
          std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                                 /*net_log=*/nullptr,
                                                 GetMockTickClock());
      unowned_pref_delegate->InitializePrefs(base::Value::Dict());

      // Set kServer1 to kQuicServerInfo1 in the context of
      // kNetworkAnonymizationKey1, Set kServer2 to kQuicServerInfo2 in the
      // context of kNetworkAnonymizationKey2, and kServer1 to kQuicServerInfo3
      // in the context of NetworkAnonymizationKey().
      properties->SetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                    kNetworkAnonymizationKey1,
                                    kQuicServerInfo1);
      properties->SetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                    kNetworkAnonymizationKey2,
                                    kQuicServerInfo2);
      properties->SetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                    NetworkAnonymizationKey(),
                                    kQuicServerInfo3);

      // Verify values were set.
      if (save_network_anonymization_key_mode !=
          NetworkAnonymizationKeyMode::kDisabled) {
        EXPECT_EQ(kQuicServerInfo1, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        kNetworkAnonymizationKey1));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                                kNetworkAnonymizationKey2));
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));

        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                kNetworkAnonymizationKey1));
        EXPECT_EQ(kQuicServerInfo2,
                  *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                 kNetworkAnonymizationKey2));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                NetworkAnonymizationKey()));
      } else {
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));
        EXPECT_EQ(kQuicServerInfo2,
                  *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                 NetworkAnonymizationKey()));
      }

      // Wait until the data's been written to prefs, and then create a copy of
      // the prefs data.
      FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
      saved_value = unowned_pref_delegate->GetServerProperties().Clone();
    }

    // Now try and load the data in each of the feature modes.
    for (auto load_network_anonymization_key_mode :
         kNetworkAnonymizationKeyModes) {
      SCOPED_TRACE(static_cast<int>(load_network_anonymization_key_mode));

      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(load_network_anonymization_key_mode);

      // Create a new HttpServerProperties, loading the data from before.
      std::unique_ptr<MockPrefDelegate> pref_delegate =
          std::make_unique<MockPrefDelegate>();
      MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
      std::unique_ptr<HttpServerProperties> properties =
          std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                                 /*net_log=*/nullptr,
                                                 GetMockTickClock());
      unowned_pref_delegate->InitializePrefs(saved_value.Clone());

      if (save_network_anonymization_key_mode ==
          NetworkAnonymizationKeyMode::kDisabled) {
        // If NetworkAnonymizationKey was disabled when saving, entries were
        // saved with an empty NetworkAnonymizationKey, which should always be
        // loaded successfully. This is needed to continue to support consumers
        // that don't use NetworkAnonymizationKeys.
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));
        EXPECT_EQ(kQuicServerInfo2,
                  *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                 NetworkAnonymizationKey()));
        if (load_network_anonymization_key_mode !=
            NetworkAnonymizationKeyMode::kDisabled) {
          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer1, PRIVACY_MODE_DISABLED,
                                 kNetworkAnonymizationKey1));
          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer1, PRIVACY_MODE_DISABLED,
                                 kNetworkAnonymizationKey2));

          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer2, PRIVACY_MODE_ENABLED,
                                 kNetworkAnonymizationKey1));
          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer2, PRIVACY_MODE_ENABLED,
                                 kNetworkAnonymizationKey2));
        }
      } else if (save_network_anonymization_key_mode ==
                 load_network_anonymization_key_mode) {
        // If the save and load modes are the same, the load should succeed, and
        // the network anonymization keys should match.
        EXPECT_EQ(kQuicServerInfo1, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        kNetworkAnonymizationKey1));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                                kNetworkAnonymizationKey2));
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));

        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                kNetworkAnonymizationKey1));
        EXPECT_EQ(kQuicServerInfo2,
                  *properties->GetQuicServerInfo(kSer
```