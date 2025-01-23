Response:
My thought process for analyzing the provided code snippet goes like this:

1. **Identify the Core Functionality:** The file name `http_server_properties_unittest.cc` immediately tells me this is a unit test file. Looking at the code, I see a lot of `TEST_F` macros, which confirm this. The class `AlternateProtocolServerPropertiesTest` further narrows down the focus. The code is clearly testing the `HttpServerProperties` class, specifically its ability to manage alternative service information (like HTTP/2, QUIC).

2. **Examine the Test Cases:**  I start reading the individual test cases to understand what specific aspects of `HttpServerProperties` are being tested. I look for keywords like `Set`, `Get`, `MarkBroken`, `Clear`, etc., which indicate the operations being tested.

3. **Group Related Tests:** As I read through the tests, I try to group them by functionality. For example, several tests deal with setting and getting alternative services, some focus on broken services, others on network isolation keys, and some specifically on WebSocket related behavior. This helps in understanding the overall capabilities being verified.

4. **Focus on the "Why":**  For each test, I try to understand *why* it's being tested. What specific behavior or edge case is this test trying to validate?  For instance, the "SetWebSockets" test is verifying that HTTP/HTTPS and WS/WSS are treated as related servers for alternative service announcements. The "SetWithNetworkIsolationKey" test checks how network isolation keys affect the storage and retrieval of alternative service information.

5. **Look for Interactions with External Concepts:**  I pay attention to mentions of specific protocols (HTTP/2, QUIC), data structures (`AlternativeServiceInfoVector`), and concepts like canonical hosts and network isolation keys. This helps build a more complete picture of the system being tested.

6. **Consider JavaScript Relevance (If Any):** I specifically look for any hints or connections to JavaScript functionality. In this particular snippet, I didn't find any direct references to JavaScript APIs or behavior. However, I know that network features in Chromium ultimately impact web page loading, which is triggered by JavaScript. So, while there's no direct code interaction shown here, the *effect* of this code is definitely relevant to how JavaScript-initiated requests behave.

7. **Analyze Logic and Data Flow (for specific tests):** When a test seems to involve more complex logic (like the `OnServerInfoLoadedForTesting` tests or those involving canonical hosts), I mentally trace the data flow. What data is being set up? What actions are being performed? What are the expected outcomes? This helps understand the assumptions and validations within the test.

8. **Infer User Actions and Debugging:** I consider how a user's actions might lead to this code being executed. For example, a user visiting a website that advertises alternative services will trigger the storage of this information, which is what these tests are verifying. For debugging, the tests themselves offer clues about potential issues, like how broken services are handled or how caching works.

9. **Synthesize a Summary:**  Finally, I combine my observations into a concise summary of the file's functionality. This involves highlighting the key areas being tested and the overall purpose of the unit test file. I aim to capture the essence of what the code does and why it's important.

**Applying this to the provided snippet (Part 2):**

* **Initial Scan:**  Recognize the `TEST_F` structure and the class name.
* **Test Case Breakdown:**
    * `SetWebSockets`: Focuses on the relationship between HTTP/HTTPS and WS/WSS for alternative services.
    * `SetWithNetworkIsolationKey`:  Examines how network isolation affects alternative service storage.
    * `SetWithEmptyHostname`: Tests a specific edge case related to empty hostnames in alternative service data.
    * `EmptyVector`:  Checks how empty alternative service lists are handled and cleaned up.
    * `EmptyVectorForCanonical`:  Similar to the above but specifically for canonical host scenarios.
    * `ClearServerWithCanonical`: Tests clearing alternative services for a server when a canonical host is involved.
    * `MRUOfGetAlternativeServiceInfos`: Verifies that `GetAlternativeServiceInfos` updates the Most Recently Used order of alternative service data.
    * `SetBroken`:  Tests the functionality of marking alternative services as broken.
    * `SetBrokenUntilDefaultNetworkChanges`: Tests marking services as broken until the network changes.
    * `MaxAge`: Verifies that expired alternative services are not returned.
    * `MaxAgeCanonical`: Similar to above, but for canonical hosts.
    * `AlternativeServiceWithScheme`: Tests how alternative services are stored and retrieved for different schemes (HTTP/HTTPS).
    * `ClearAlternativeServices`: Tests the clearing of all alternative services for a host.
    * `BrokenShadowsCanonical`: Checks if a broken alternative service for a specific host prevents the use of alternative services for its canonical host.

* **JavaScript Connection:** None directly apparent in this code, but the outcome (faster connections) impacts JavaScript performance.

* **Logic and Data Flow:** Analyze the assertions (`EXPECT_EQ`, `ASSERT_TRUE`, `ASSERT_EQ`) to understand the expected inputs and outputs for each test.

* **User Actions and Debugging:**  Infer scenarios where this code might be relevant (user visiting websites with alternative service support). The tests highlight potential issues like incorrect handling of empty lists or broken services.

* **Synthesize Summary:** Combine the findings into a concise description of the functionality being tested in this specific part of the unit test file.
这是 `net/http/http_server_properties_unittest.cc` 文件的一部分，主要功能是**测试 `HttpServerProperties` 类中关于替代服务 (Alternative Services) 的管理功能**。 这部分代码着重测试了设置、获取、清除和标记失效的替代服务，以及与 WebSocket 和网络隔离键 (Network Isolation Key) 相关的逻辑。

**具体功能归纳：**

* **测试替代服务的设置和获取:** 验证了 `SetAlternativeServices` 和 `GetAlternativeServiceInfos` 方法的正确性，包括添加、覆盖和读取替代服务信息。
* **测试 WebSocket 的特殊处理:**  确认了 HTTP/HTTPS 和 WS/WSS 协议的服务器在替代服务管理中被视为相同的实体。
* **测试网络隔离键的影响:**  检验了在启用和禁用网络隔离键特性时，`SetAlternativeServices` 和 `GetAlternativeServiceInfos` 如何处理 `NetworkAnonymizationKey` 参数。
* **测试处理空主机名的情况:**  确保在加载服务器信息时，即使存在空主机名也不会导致崩溃。
* **测试处理空替代服务列表的情况:**  验证了当服务器的替代服务列表为空时，`GetAlternativeServiceInfos` 的行为，以及 `SetAlternativeServices` 在此情况下的稳定性。
* **测试针对规范主机 (Canonical Host) 的处理:**  检验了替代服务信息在规范主机场景下的设置、获取和清除逻辑。
* **测试最近使用 (MRU) 顺序:**  验证了 `GetAlternativeServiceInfos` 会更新替代服务信息的最近使用顺序。
* **测试标记替代服务失效:**  测试了 `MarkAlternativeServiceBroken` 和 `IsAlternativeServiceBroken` 方法，以及失效的替代服务如何在设置和获取中被处理。
* **测试标记替代服务在网络变更前失效:**  检验了 `MarkAlternativeServiceBrokenUntilDefaultNetworkChanges` 方法的功能。
* **测试替代服务的过期机制:**  验证了 `GetAlternativeServiceInfos` 不会返回已过期的替代服务。
* **测试带有 Scheme 的替代服务:**  确认了替代服务信息是基于 Scheme 进行存储和检索的 (例如，HTTP 和 HTTPS 的替代服务是分开的)。
* **测试清除替代服务:**  验证了 `SetAlternativeServices` 可以用来清除指定服务器的所有替代服务信息。
* **测试失效的替代服务对规范主机的遮蔽:** 验证了为一个特定主机设置的失效替代服务会阻止使用其规范主机的替代服务。

**与 Javascript 的关系：**

这段 C++ 代码直接操作的是 Chromium 浏览器的网络栈底层，JavaScript 代码本身无法直接访问或操作这些数据。但是，`HttpServerProperties` 管理的替代服务信息会直接影响浏览器加载网页的性能和安全性，这最终会体现在 JavaScript 代码的执行效率上。

**举例说明:**

假设一个网站 `https://www.example.com` 通过 HTTP 头部或者 DNS 记录声明了支持 HTTP/3 协议，并且指定了另一个主机 `alt.example.com:443` 作为 HTTP/3 的接入点。

1. **用户操作:** 用户在浏览器地址栏输入 `https://www.example.com` 并访问。
2. **网络请求:** 浏览器发起对 `www.example.com` 的 HTTPS 请求。
3. **替代服务发现:** 服务器响应中包含了声明 HTTP/3 替代服务的信息。
4. **`HttpServerProperties` 存储:**  这段 C++ 代码负责的 `HttpServerProperties` 类会将 `alt.example.com:443` (使用 QUIC 协议) 记录为 `www.example.com` 的一个有效的替代服务。
5. **后续请求优化:**  当 JavaScript 代码在当前页面发起对 `www.example.com` 的**后续请求**时，浏览器会查找 `HttpServerProperties` 中存储的替代服务信息。
6. **HTTP/3 连接:** 如果 `alt.example.com:443` 当前可用且网络条件允许，浏览器会尝试使用 HTTP/3 协议连接到 `alt.example.com:443` 来发送请求，而不是建立新的 TCP+TLS 连接。
7. **JavaScript 体验:**  由于 HTTP/3 的特性 (例如，多路复用，更好的拥塞控制)，JavaScript 发起的请求可能会更快完成，提升用户体验。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `test_server1`:  `http://foo1:80`
* `alternative_service1`: `h2://foo1:443`
* `test_server2`:  `http://foo2:80`
* `alternative_service2`: `h2://foo2:1234`

**代码片段执行流程 (基于 `MRUOfGetAlternativeServiceInfos` 测试):**

1. 使用 `SetAlternativeService` 为 `test_server1` 设置 `alternative_service1`。
2. 使用 `SetAlternativeService` 为 `test_server2` 设置 `alternative_service2`。此时，`test_server2` 的信息由于是最近添加的，应该在内部数据结构的前面。
3. 调用 `GetAlternativeServiceInfos(test_server1)`。

**预期输出:**

* 在调用 `GetAlternativeServiceInfos` 之后，内部存储的替代服务信息顺序应该发生变化，`test_server1` 的信息会移动到前面，因为它被最近访问过。

**用户或编程常见的使用错误:**

* **用户错误:** 用户无法直接与这段代码交互。但是，如果用户的网络环境不稳定，或者防火墙阻止了对替代服务端口的访问，会导致替代服务连接失败，即使 `HttpServerProperties` 中存储了正确的信息。
* **编程错误:**  开发者在服务器端配置替代服务信息时，如果配置错误 (例如，指定了错误的端口或协议)，会导致浏览器无法正确利用替代服务。 另外，如果浏览器自身的替代服务缓存机制存在 bug，也可能导致问题，但这属于浏览器内部的错误，与用户的直接操作无关。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问网站:** 用户在 Chrome 浏览器中输入一个网址并访问，例如 `https://www.example.com`。
2. **服务器发送 Alt-Svc 头部:** `www.example.com` 的服务器在 HTTP 响应头中包含了 `Alt-Svc` 信息，声明了其支持的替代服务，例如 HTTP/3。
3. **网络栈接收响应:** Chrome 浏览器的网络栈接收到这个包含 `Alt-Svc` 头部的响应。
4. **解析 Alt-Svc 头部:** 网络栈中的代码会解析 `Alt-Svc` 头部的信息，提取出替代服务的协议、主机和端口。
5. **调用 `HttpServerProperties::SetAlternativeServices`:**  网络栈的代码会调用 `HttpServerProperties` 类的 `SetAlternativeServices` 方法，将解析出的替代服务信息存储起来。 这就是这段单元测试代码所测试的核心功能。
6. **后续请求查找替代服务:** 当用户在同一个网站上进行后续操作，浏览器需要发起新的网络请求时，网络栈会先查询 `HttpServerProperties` 中是否存储了该域名的有效替代服务信息。
7. **调用 `HttpServerProperties::GetAlternativeServiceInfos`:**  网络栈的代码会调用 `GetAlternativeServiceInfos` 方法来获取存储的替代服务信息。

**总结 (针对第2部分):**

这部分单元测试代码主要集中在 **验证 `HttpServerProperties` 类管理替代服务信息的核心功能，包括设置、获取、处理 WebSocket 特殊情况、考虑网络隔离键、处理空值和过期情况，以及维护最近使用的顺序**。  这些测试确保了 `HttpServerProperties` 能够正确地存储和检索替代服务信息，为浏览器利用这些信息进行连接优化奠定了基础。虽然与 JavaScript 没有直接的代码交互，但其功能直接影响了 JavaScript 发起的网络请求的性能。

### 提示词
```
这是目录为net/http/http_server_properties_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
est_server2, test_server1, test_server3.
  impl_.OnServerInfoLoadedForTesting(std::move(server_info_map));

  // Verify server_info_map.
  const HttpServerProperties::ServerInfoMap& map =
      impl_.server_info_map_for_testing();
  ASSERT_EQ(3u, map.size());
  auto map_it = map.begin();

  EXPECT_EQ(test_server2, map_it->first.server);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.alternative_services.has_value());
  const AlternativeServiceInfoVector* service_info =
      &map_it->second.alternative_services.value();
  ASSERT_EQ(1u, service_info->size());
  EXPECT_EQ(alternative_service3, (*service_info)[0].alternative_service());
  EXPECT_EQ(expiration3, (*service_info)[0].expiration());

  ++map_it;
  EXPECT_EQ(test_server1, map_it->first.server);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.alternative_services.has_value());
  service_info = &map_it->second.alternative_services.value();
  ASSERT_EQ(1u, service_info->size());
  EXPECT_EQ(alternative_service1, (*service_info)[0].alternative_service());
  EXPECT_EQ(expiration1, (*service_info)[0].expiration());

  ++map_it;
  EXPECT_EQ(map_it->first.server, test_server3);
  EXPECT_TRUE(map_it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(map_it->second.alternative_services.has_value());
  service_info = &map_it->second.alternative_services.value();
  ASSERT_EQ(1u, service_info->size());
  EXPECT_EQ(alternative_service4, (*service_info)[0].alternative_service());
  EXPECT_EQ(expiration4, (*service_info)[0].expiration());
}

TEST_F(AlternateProtocolServerPropertiesTest, SetWebSockets) {
  // The https and wss servers should be treated as the same server, as should
  // the http and ws servers.
  url::SchemeHostPort https_server("https", "www.test.com", 443);
  url::SchemeHostPort wss_server("wss", "www.test.com", 443);
  url::SchemeHostPort http_server("http", "www.test.com", 443);
  url::SchemeHostPort ws_server("ws", "www.test.com", 443);

  AlternativeService alternative_service(kProtoHTTP2, "bar", 443);

  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(wss_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u, impl_.GetAlternativeServiceInfos(ws_server, NetworkAnonymizationKey())
              .size());

  SetAlternativeService(wss_server, alternative_service);
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(wss_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u, impl_.GetAlternativeServiceInfos(ws_server, NetworkAnonymizationKey())
              .size());

  SetAlternativeService(http_server, alternative_service);
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(wss_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u, impl_.GetAlternativeServiceInfos(ws_server, NetworkAnonymizationKey())
              .size());

  impl_.SetAlternativeServices(https_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(wss_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      1u, impl_.GetAlternativeServiceInfos(ws_server, NetworkAnonymizationKey())
              .size());

  impl_.SetAlternativeServices(ws_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(wss_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      0u, impl_.GetAlternativeServiceInfos(ws_server, NetworkAnonymizationKey())
              .size());
}

TEST_F(AlternateProtocolServerPropertiesTest, SetWithNetworkIsolationKey) {
  const url::SchemeHostPort kServer("https", "foo.test", 443);
  const AlternativeServiceInfoVector kAlternativeServices(
      {AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foo", 443),
          base::Time::Now() + base::Days(1) /* expiration */)});

  EXPECT_TRUE(
      impl_.GetAlternativeServiceInfos(kServer, network_anonymization_key1_)
          .empty());
  EXPECT_TRUE(
      impl_.GetAlternativeServiceInfos(kServer, NetworkAnonymizationKey())
          .empty());

  // Without network isolation keys enabled for HttpServerProperties, passing in
  // a NetworkAnonymizationKey should have no effect on behavior.
  for (const auto& network_anonymization_key_to_set :
       {NetworkAnonymizationKey(), network_anonymization_key1_}) {
    impl_.SetAlternativeServices(kServer, network_anonymization_key_to_set,
                                 kAlternativeServices);
    EXPECT_EQ(kAlternativeServices, impl_.GetAlternativeServiceInfos(
                                        kServer, network_anonymization_key1_));
    EXPECT_EQ(kAlternativeServices, impl_.GetAlternativeServiceInfos(
                                        kServer, NetworkAnonymizationKey()));

    impl_.SetAlternativeServices(kServer, network_anonymization_key_to_set,
                                 AlternativeServiceInfoVector());
    EXPECT_TRUE(
        impl_.GetAlternativeServiceInfos(kServer, network_anonymization_key1_)
            .empty());
    EXPECT_TRUE(
        impl_.GetAlternativeServiceInfos(kServer, NetworkAnonymizationKey())
            .empty());
  }

  // Check that with network isolation keys enabled for HttpServerProperties,
  // the NetworkAnonymizationKey argument is respected.

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  properties.SetAlternativeServices(kServer, network_anonymization_key1_,
                                    kAlternativeServices);
  EXPECT_EQ(kAlternativeServices, properties.GetAlternativeServiceInfos(
                                      kServer, network_anonymization_key1_));
  EXPECT_TRUE(
      properties.GetAlternativeServiceInfos(kServer, NetworkAnonymizationKey())
          .empty());

  properties.SetAlternativeServices(kServer, NetworkAnonymizationKey(),
                                    kAlternativeServices);
  EXPECT_EQ(kAlternativeServices, properties.GetAlternativeServiceInfos(
                                      kServer, network_anonymization_key1_));
  EXPECT_EQ(kAlternativeServices, properties.GetAlternativeServiceInfos(
                                      kServer, NetworkAnonymizationKey()));

  properties.SetAlternativeServices(kServer, network_anonymization_key1_,
                                    AlternativeServiceInfoVector());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(kServer, network_anonymization_key1_)
          .empty());
  EXPECT_EQ(kAlternativeServices, properties.GetAlternativeServiceInfos(
                                      kServer, NetworkAnonymizationKey()));

  properties.SetAlternativeServices(kServer, NetworkAnonymizationKey(),
                                    AlternativeServiceInfoVector());
  EXPECT_TRUE(
      properties
          .GetAlternativeServiceInfos(kServer, network_anonymization_key1_)
          .empty());
  EXPECT_TRUE(
      properties.GetAlternativeServiceInfos(kServer, NetworkAnonymizationKey())
          .empty());
}

// Regression test for https://crbug.com/504032:
// OnServerInfoLoadedForTesting() should not crash if there is an
// empty hostname is the mapping.
TEST_F(AlternateProtocolServerPropertiesTest, SetWithEmptyHostname) {
  url::SchemeHostPort server("https", "foo", 443);
  const AlternativeService alternative_service_with_empty_hostname(kProtoHTTP2,
                                                                   "", 1234);
  const AlternativeService alternative_service_with_foo_hostname(kProtoHTTP2,
                                                                 "foo", 1234);
  SetAlternativeService(server, alternative_service_with_empty_hostname);
  impl_.MarkAlternativeServiceBroken(alternative_service_with_foo_hostname,
                                     NetworkAnonymizationKey());

  std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  impl_.OnServerInfoLoadedForTesting(std::move(server_info_map));

  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(
      alternative_service_with_foo_hostname, NetworkAnonymizationKey()));
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service_with_foo_hostname,
            alternative_service_info_vector[0].alternative_service());
}

// GetAlternativeServiceInfos() should remove |server_info_map_|
// elements with empty value.
TEST_F(AlternateProtocolServerPropertiesTest, EmptyVector) {
  url::SchemeHostPort server("https", "foo", 443);
  const AlternativeService alternative_service(kProtoHTTP2, "bar", 443);
  base::Time expiration = test_clock_.Now() - base::Days(1);
  const AlternativeServiceInfo alternative_service_info =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration);
  std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  server_info_map->GetOrPut(CreateSimpleKey(server))
      ->second.alternative_services = AlternativeServiceInfoVector(
      /*size=*/1, alternative_service_info);

  // Prepare |server_info_map_| with a single key that has a single
  // AlternativeServiceInfo with identical hostname and port.
  impl_.OnServerInfoLoadedForTesting(std::move(server_info_map));

  // GetAlternativeServiceInfos() should remove such AlternativeServiceInfo from
  // |server_info_map_|, emptying the AlternativeServiceInfoVector
  // corresponding to |server|.
  ASSERT_TRUE(
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey())
          .empty());

  // GetAlternativeServiceInfos() should remove this key from
  // |server_info_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(
      server, NetworkAnonymizationKey(),
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // There should still be no alternative service assigned to |server|.
  ASSERT_TRUE(
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey())
          .empty());
}

// Regression test for https://crbug.com/516486 for the canonical host case.
TEST_F(AlternateProtocolServerPropertiesTest, EmptyVectorForCanonical) {
  url::SchemeHostPort server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  const AlternativeService alternative_service(kProtoHTTP2, "", 443);
  base::Time expiration = test_clock_.Now() - base::Days(1);
  const AlternativeServiceInfo alternative_service_info =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration);
  std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  server_info_map->GetOrPut(CreateSimpleKey(canonical_server))
      ->second.alternative_services =
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info);

  // Prepare |server_info_map_| with a single key that has a single
  // AlternativeServiceInfo with identical hostname and port.
  impl_.OnServerInfoLoadedForTesting(std::move(server_info_map));

  // GetAlternativeServiceInfos() should remove such AlternativeServiceInfo from
  // |server_info_map_|, emptying the AlternativeServiceInfoVector
  // corresponding to |canonical_server|, even when looking up
  // alternative services for |server|.
  ASSERT_TRUE(
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey())
          .empty());

  // GetAlternativeServiceInfos() should remove this key from
  // |server_info_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(
      canonical_server, NetworkAnonymizationKey(),
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // There should still be no alternative service assigned to
  // |canonical_server|.
  ASSERT_TRUE(impl_
                  .GetAlternativeServiceInfos(canonical_server,
                                              NetworkAnonymizationKey())
                  .empty());
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearServerWithCanonical) {
  url::SchemeHostPort server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  const AlternativeService alternative_service(kProtoQUIC, "", 443);
  base::Time expiration = test_clock_.Now() + base::Days(1);
  const AlternativeServiceInfo alternative_service_info =
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions());

  impl_.SetAlternativeServices(
      canonical_server, NetworkAnonymizationKey(),
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // Make sure the canonical service is returned for the other server.
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);

  // Now clear the alternatives for the other server and make sure it stays
  // cleared.
  // GetAlternativeServices() should remove this key from
  // |server_info_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());

  ASSERT_TRUE(
      impl_.GetAlternativeServiceInfos(server, NetworkAnonymizationKey())
          .empty());
}

TEST_F(AlternateProtocolServerPropertiesTest, MRUOfGetAlternativeServiceInfos) {
  url::SchemeHostPort test_server1("http", "foo1", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "foo1", 443);
  SetAlternativeService(test_server1, alternative_service1);
  url::SchemeHostPort test_server2("http", "foo2", 80);
  const AlternativeService alternative_service2(kProtoHTTP2, "foo2", 1234);
  SetAlternativeService(test_server2, alternative_service2);

  const HttpServerProperties::ServerInfoMap& map =
      impl_.server_info_map_for_testing();
  auto it = map.begin();
  EXPECT_EQ(test_server2, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.alternative_services.has_value());
  ASSERT_EQ(1u, it->second.alternative_services->size());
  EXPECT_EQ(alternative_service2,
            it->second.alternative_services.value()[0].alternative_service());

  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server1, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());

  // GetAlternativeServices should reorder the AlternateProtocol map.
  it = map.begin();
  EXPECT_EQ(test_server1, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.alternative_services.has_value());
  ASSERT_EQ(1u, it->second.alternative_services->size());
  EXPECT_EQ(alternative_service1,
            it->second.alternative_services.value()[0].alternative_service());
}

TEST_F(AlternateProtocolServerPropertiesTest, SetBroken) {
  url::SchemeHostPort test_server("http", "foo", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service1);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                                NetworkAnonymizationKey()));

  // GetAlternativeServiceInfos should return the broken alternative service.
  impl_.MarkAlternativeServiceBroken(alternative_service1,
                                     NetworkAnonymizationKey());
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));

  // SetAlternativeServices should add a broken alternative service to the map.
  AlternativeServiceInfoVector alternative_service_info_vector2;
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "foo", 1234);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, expiration));
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector2);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector[1].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service2,
                                                NetworkAnonymizationKey()));

  // SetAlternativeService should add a broken alternative service to the map.
  SetAlternativeService(test_server, alternative_service1);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       SetBrokenUntilDefaultNetworkChanges) {
  url::SchemeHostPort test_server("http", "foo", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service1);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                                NetworkAnonymizationKey()));

  // Mark the alternative service as broken until the default network changes.
  impl_.MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service1, NetworkAnonymizationKey());
  // The alternative service should be persisted and marked as broken.
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));

  // SetAlternativeServices should add a broken alternative service to the map.
  AlternativeServiceInfoVector alternative_service_info_vector2;
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "foo", 1234);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, expiration));
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector2);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector[1].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service2,
                                                NetworkAnonymizationKey()));

  // SetAlternativeService should add a broken alternative service to the map.
  SetAlternativeService(test_server, alternative_service1);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1,
                                               NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest, MaxAge) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time now = test_clock_.Now();
  base::TimeDelta one_day = base::Days(1);

  // First alternative service expired one day ago, should not be returned by
  // GetAlternativeServiceInfos().
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, now - one_day));

  // Second alterrnative service will expire one day from now, should be
  // returned by GetAlternativeSerices().
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, now + one_day));

  url::SchemeHostPort test_server("http", "foo", 80);
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[0].alternative_service());
}

TEST_F(AlternateProtocolServerPropertiesTest, MaxAgeCanonical) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time now = test_clock_.Now();
  base::TimeDelta one_day = base::Days(1);

  // First alternative service expired one day ago, should not be returned by
  // GetAlternativeServiceInfos().
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, now - one_day));

  // Second alterrnative service will expire one day from now, should be
  // returned by GetAlternativeSerices().
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, now + one_day));

  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  impl_.SetAlternativeServices(canonical_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[0].alternative_service());
}

TEST_F(AlternateProtocolServerPropertiesTest, AlternativeServiceWithScheme) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, expiration));
  // Set Alt-Svc list for |http_server|.
  url::SchemeHostPort http_server("http", "foo", 80);
  impl_.SetAlternativeServices(http_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  const HttpServerProperties::ServerInfoMap& map =
      impl_.server_info_map_for_testing();
  auto it = map.begin();
  EXPECT_EQ(http_server, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.alternative_services.has_value());
  ASSERT_EQ(2u, it->second.alternative_services->size());
  EXPECT_EQ(alternative_service1,
            it->second.alternative_services.value()[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            it->second.alternative_services.value()[1].alternative_service());

  // Check Alt-Svc list should not be set for |https_server|.
  url::SchemeHostPort https_server("https", "foo", 80);
  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());

  // Set Alt-Svc list for |https_server|.
  impl_.SetAlternativeServices(https_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);
  EXPECT_EQ(
      2u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      2u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());

  // Clear Alt-Svc list for |http_server|.
  impl_.SetAlternativeServices(http_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());

  EXPECT_EQ(
      0u,
      impl_.GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .size());
  EXPECT_EQ(
      2u,
      impl_.GetAlternativeServiceInfos(https_server, NetworkAnonymizationKey())
          .size());
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearAlternativeServices) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  base::Time expiration = test_clock_.Now() + base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, expiration));
  url::SchemeHostPort test_server("http", "foo", 80);
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  const HttpServerProperties::ServerInfoMap& map =
      impl_.server_info_map_for_testing();
  auto it = map.begin();
  EXPECT_EQ(test_server, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.alternative_services.has_value());
  ASSERT_EQ(2u, it->second.alternative_services->size());
  EXPECT_EQ(alternative_service1,
            it->second.alternative_services.value()[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            it->second.alternative_services.value()[1].alternative_service());

  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               AlternativeServiceInfoVector());
  EXPECT_TRUE(map.empty());
}

// A broken alternative service in the mapping carries meaningful information,
// therefore it should not be ignored by SetAlternativeService().  In
// particular, an alternative service mapped to an origin shadows alternative
// services of canonical hosts.
TEST_F(AlternateProtocolServerPropertiesTest, BrokenShadowsCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);
  SetAlternativeService(canonical_server, canonical_alternative_service);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(canonical_alternative_service,
            alternative_service_info_vector[0].alternative_service());

  const AlternativeService broken_alternative_service(kProtoHTTP2, "foo", 443);
  impl_.MarkAlternativeServiceBroken(broken_alternative_service,
                                     NetworkAnonymizationKey());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(broken_alternative_service,
                                               NetworkAnonymizationKey()));

  SetAlternativeService(test_server, broken_alternative_service);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(broken_alternative_service,
```