Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a unit test file for `HttpServerPropertiesManager` in Chromium's network stack. I need to identify the features being tested and explain their purpose.

Here's a breakdown of the code and its functions:

1. **Setting and Verifying Various Properties:** The code sets and then verifies several HTTP server properties, such as alternative services (including QUIC), server network stats, QUIC server info, and whether QUIC is supported. It also checks if these settings are correctly persisted to preferences.

2. **Handling Advertised QUIC Versions:** The tests specifically examine how advertised QUIC versions are handled when setting alternative services and reading them from preferences.

3. **Updating Preferences:** The code verifies that changes to HTTP server properties trigger updates to the stored preferences.

4. **Reading and Applying Preferences:** The tests demonstrate how the `HttpServerPropertiesManager` reads and applies settings from the stored preferences, including broken alternative services and their expiration times.

5. **Interaction with Caching:** The tests show how the manager's cache interacts with the preferences, particularly for broken alternative services.

6. **ForceHTTP11 Handling:** There's a test to confirm that the "Force HTTP/1.1" setting is not persisted to preferences and doesn't interfere with loading or saving other settings.

7. **Network Anonymization Key:** The code includes tests related to the Network Anonymization Key, ensuring that server-specific information can be associated with specific network contexts.

Now, let's address the specific requirements:

*   **Functionality:** Summarize the tested functionalities.
*   **Relationship to JavaScript:** Determine if any of these features directly impact JavaScript.
*   **Logical Reasoning (Assumptions and Outputs):** Provide an example of setting a property and how it reflects in the persisted data.
*   **Common User/Programming Errors:** Identify potential mistakes related to using these features.
*   **User Steps to Reach the Code:** Explain how user actions can lead to the execution of this code.
*   **歸納功能 (Summarize Functionality):** Provide a concise summary.
这个`http_server_properties_manager_unittest.cc` 文件是 Chromium 网络栈中用于测试 `HttpServerPropertiesManager` 类的单元测试。`HttpServerPropertiesManager` 负责管理与 HTTP 服务器相关的属性，例如支持的协议、备用服务、网络统计信息等，并将这些信息持久化到本地偏好设置中。

**它的功能可以归纳为以下几点：**

1. **测试 HTTP 服务器属性的设置和获取:** 验证 `HttpServerPropertiesManager` 是否能够正确地设置和获取各种服务器属性，例如：
    *   备用服务 (Alternative Services)，包括 HTTP/2 和 QUIC。
    *   QUIC 备用服务的特定版本 (Advertised Versions)。
    *   服务器网络统计信息 (Server Network Stats)，例如 RTT。
    *   QUIC 服务器信息 (Quic Server Info)。
    *   是否支持 QUIC 协议 (SupportsQuic)。
    *   是否强制使用 HTTP/1.1 (ForceHTTP11)。

2. **测试属性的持久化和恢复:** 验证 `HttpServerPropertiesManager` 是否能够将这些服务器属性正确地保存到本地偏好设置中，并在重启后能够正确地从偏好设置中恢复这些属性。这涉及到将内存中的数据结构转换为 JSON 格式存储，并从 JSON 格式恢复到内存中。

3. **测试失效的备用服务 (Broken Alternative Services) 的管理:** 验证 `HttpServerPropertiesManager` 如何记录和管理被标记为失效的备用服务，包括设置失效时间和次数，以及如何从偏好设置中加载这些失效信息。

4. **测试网络匿名化密钥 (Network Anonymization Key) 的处理:** 验证 `HttpServerPropertiesManager` 如何将服务器属性与特定的 `Network Anonymization Key` 关联，以及在偏好设置中如何存储和加载这些关联信息。

**它与 JavaScript 的功能有关系：**

`HttpServerPropertiesManager` 管理的许多属性会影响浏览器与服务器之间的连接方式，而这最终会影响到网页的加载性能和行为。JavaScript 代码可以通过浏览器提供的 API（例如 `navigator.connection`，尽管这个 API 主要关注网络连接状态）间接地受到这些属性的影响。

**举例说明：**

假设一个网站 `https://www.example.com` 启用了 HTTP/3 (QUIC) 协议。

*   `HttpServerPropertiesManager` 会存储这个信息（通过 `SetAlternativeServices` 设置）。
*   当用户再次访问 `https://www.example.com` 时，浏览器会查询 `HttpServerPropertiesManager`，发现该服务器支持 QUIC。
*   浏览器可能会尝试使用 QUIC 建立连接。如果连接成功，那么 JavaScript 代码发起的网络请求 (例如通过 `fetch` API) 将会通过 QUIC 传输，这通常比 TCP 更快。

**假设输入与输出 (逻辑推理):**

**假设输入：**

1. 调用 `http_server_props_->SetAlternativeServices(server_www, NetworkAnonymizationKey(), alternative_service_info_vector)`，其中 `server_www` 是 `https://www.google.com:80`，`alternative_service_info_vector` 包含一个指向 `www.google.com:443` 的 HTTP/2 备用服务，有效期至 2036-12-01。
2. 等待偏好设置更新完成。

**输出：**

偏好设置中会包含一个 JSON 对象，其中 `servers` 数组中会有一个元素对应 `https://www.google.com:80`，并且其 `alternative_service` 属性会包含一个描述 HTTP/2 备用服务的对象，包括端口 `443`，协议 `h2`，以及转换后的有效期时间戳 `"13756212000000000"`。

**涉及用户或者编程常见的使用错误，举例说明:**

*   **用户清除浏览器数据:** 用户在浏览器设置中清除了 "Cookie 和其他网站数据" 或 "缓存的图片和文件"，这可能会清除 `HttpServerPropertiesManager` 管理的偏好设置数据。当用户再次访问之前存储了相关属性的网站时，浏览器需要重新进行协议协商和探测，可能会影响加载速度。
*   **编程错误：不正确地配置服务器:**  如果网站管理员配置了错误的备用服务信息 (例如，指定了不存在的端口或错误的协议)，`HttpServerPropertiesManager` 可能会存储这些错误信息。这会导致浏览器尝试连接错误的地址，从而导致连接失败或性能下降。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在地址栏输入网址并访问一个网站:** 这是最常见的触发网络请求的方式。
2. **浏览器发起连接:** 浏览器会根据缓存的 `HttpServerProperties` 信息来决定如何连接服务器。例如，如果缓存了该网站的 HTTP/2 或 QUIC 信息，浏览器可能会尝试使用这些协议。
3. **连接协商和协议升级:**  如果缓存信息不存在或不可用，浏览器会进行协议协商，尝试升级到更快的协议。
4. **如果连接过程中出现问题，或者需要调试与特定服务器的连接行为，开发者可能会查看网络面板 (Chrome DevTools)。**
5. **在网络面板中，开发者可以查看请求的协议、头部信息等，这些信息受到 `HttpServerPropertiesManager` 的影响。**
6. **如果怀疑 `HttpServerPropertiesManager` 的行为有问题，开发者可能会查看 Chromium 的内部页面 (例如 `chrome://net-internals/#http_server_properties`) 来查看当前存储的服务器属性。**
7. **如果需要深入了解 `HttpServerPropertiesManager` 的运行逻辑，或者怀疑代码存在 bug，那么开发者可能会查看或调试 `net/http/http_server_properties_manager_unittest.cc` 中的测试用例，来理解代码的预期行为。**

**归纳一下它的功能 (作为第 3 部分):**

作为系列测试的第 3 部分，这个文件主要关注 `HttpServerPropertiesManager` **持久化和恢复 HTTP 服务器属性**的能力，特别是：

*   验证各种服务器属性（包括备用服务、QUIC 信息、网络统计等）能够正确地**保存到偏好设置**中。
*   验证 `HttpServerPropertiesManager` 能够从偏好设置中**正确地加载**这些属性，并在重启后保持一致。
*   测试了**失效备用服务**信息的持久化和恢复。
*   开始涉及**网络匿名化密钥**对服务器属性存储的影响。

之前的测试部分可能侧重于 `HttpServerPropertiesManager` 的基本功能，例如在内存中设置和获取属性，而后续部分可能会涉及更复杂的功能，例如策略控制、过期处理等。

Prompt: 
```
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
com",
                                              444);
  base::Time expiration3 = base::Time::Max();
  http_server_props_->SetQuicAlternativeService(
      server_mail, NetworkAnonymizationKey(), mail_alternative_service,
      expiration3, advertised_versions_);
  // #3: Set ServerNetworkStats.
  ServerNetworkStats stats;
  stats.srtt = base::TimeDelta::FromInternalValue(42);
  http_server_props_->SetServerNetworkStats(server_mail,
                                            NetworkAnonymizationKey(), stats);

  // #4: Set quic_server_info string.
  quic::QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);

  // #5: Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);

  // Update Prefs.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Verify preferences with correct advertised version field.
  const char expected_json[] =
      "{\"quic_servers\":["
      "{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}],"
      "\"servers\":["
      "{\"alternative_service\":[{"
      "\"advertised_alpns\":[\"h3-Q046\"],\"expiration\":"
      "\"13756212000000000\","
      "\"port\":443,\"protocol_str\":\"quic\"},{\"advertised_alpns\":[],"
      "\"expiration\":\"13758804000000000\",\"host\":\"www.google.com\","
      "\"port\":1234,\"protocol_str\":\"h2\"}],"
      "\"anonymization\":[],"
      "\"server\":\"https://www.google.com:80\"},"
      "{\"alternative_service\":[{"
      "\"advertised_alpns\":[\"h3\"],"
      "\"expiration\":\"9223372036854775807\","
      "\"host\":\"foo.google.com\",\"port\":444,\"protocol_str\":\"quic\"}],"
      "\"anonymization\":[],"
      "\"network_stats\":{\"srtt\":42},"
      "\"server\":\"https://mail.google.com:80\"}],"
      "\"supports_quic\":{"
      "\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";

  const base::Value::Dict& http_server_properties =
      pref_delegate_->GetServerProperties();
  std::string preferences_json;
  EXPECT_TRUE(
      base::JSONWriter::Write(http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);
}

TEST_F(HttpServerPropertiesManagerTest, ReadAdvertisedVersionsFromPref) {
  InitializePrefs();

  base::Value::Dict server_dict = base::test::ParseJsonDict(
      "{\"alternative_service\":["
      "{\"port\":443,\"protocol_str\":\"quic\"},"
      "{\"port\":123,\"protocol_str\":\"quic\","
      "\"expiration\":\"9223372036854775807\","
      // Add 33 which we know is not supported, as regression test for
      // https://crbug.com/1061509
      "\"advertised_alpns\":[\"h3-Q033\",\"h3-Q050\",\"h3-Q046\"]}]}");

  const url::SchemeHostPort server("https", "example.com", 443);
  HttpServerProperties::ServerInfo server_info;
  EXPECT_TRUE(HttpServerPropertiesManager::ParseAlternativeServiceInfo(
      server, server_dict, &server_info));

  ASSERT_TRUE(server_info.alternative_services.has_value());
  AlternativeServiceInfoVector alternative_service_info_vector =
      server_info.alternative_services.value();
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  // Verify the first alternative service with no advertised version listed.
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  // Expiration defaults to one day from now, testing with tolerance.
  const base::Time now = base::Time::Now();
  const base::Time expiration = alternative_service_info_vector[0].expiration();
  EXPECT_LE(now + base::Hours(23), expiration);
  EXPECT_GE(now + base::Days(1), expiration);
  EXPECT_TRUE(alternative_service_info_vector[0].advertised_versions().empty());

  // Verify the second alterntaive service with two advertised versions.
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(123, alternative_service_info_vector[1].alternative_service().port);
  EXPECT_EQ(base::Time::Max(), alternative_service_info_vector[1].expiration());
  // Verify advertised versions.
  const quic::ParsedQuicVersionVector loaded_advertised_versions =
      alternative_service_info_vector[1].advertised_versions();
  ASSERT_EQ(1u, loaded_advertised_versions.size());
  EXPECT_EQ(quic::ParsedQuicVersion::Q046(), loaded_advertised_versions[0]);

  // No other fields should have been populated.
  server_info.alternative_services.reset();
  EXPECT_TRUE(server_info.empty());
}

TEST_F(HttpServerPropertiesManagerTest,
       UpdatePrefWhenAdvertisedVersionsChange) {
  InitializePrefs();

  const url::SchemeHostPort server_www("https", "www.google.com", 80);

  // #1: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  // Quic alternative service set with a single QUIC version: Q046.
  AlternativeService quic_alternative_service1(kProtoQUIC, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions_));
  http_server_props_->SetAlternativeServices(
      server_www, NetworkAnonymizationKey(), alternative_service_info_vector);

  // Set quic_server_info string.
  quic::QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);

  // Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);

  // Update Prefs.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Verify preferences with correct advertised version field.
  const char expected_json[] =
      "{\"quic_servers\":"
      "[{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}],"
      "\"servers\":["
      "{\"alternative_service\":[{"
      "\"advertised_alpns\":[\"h3\"],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"quic\"}],"
      "\"anonymization\":[],"
      "\"server\":\"https://www.google.com:80\"}],"
      "\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";

  const base::Value::Dict& http_server_properties =
      pref_delegate_->GetServerProperties();
  std::string preferences_json;
  EXPECT_TRUE(
      base::JSONWriter::Write(http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);

  // #2: Set AlternativeService with different advertised_versions for the same
  // AlternativeService.
  AlternativeServiceInfoVector alternative_service_info_vector_2;
  // Quic alternative service set with two advertised QUIC versions.
  quic::ParsedQuicVersionVector advertised_versions = {
      quic::ParsedQuicVersion::Q046(), quic::ParsedQuicVersion::Draft29()};
  alternative_service_info_vector_2.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions));
  http_server_props_->SetAlternativeServices(
      server_www, NetworkAnonymizationKey(), alternative_service_info_vector_2);

  // Update Prefs.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Verify preferences updated with new advertised versions.
  const char expected_json_updated[] =
      "{\"quic_servers\":"
      "[{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}],"
      "\"servers\":["
      "{\"alternative_service\":"
      "[{\"advertised_alpns\":[\"h3-Q046\",\"h3-29\"],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"quic\"}],"
      "\"anonymization\":[],"
      "\"server\":\"https://www.google.com:80\"}],"
      "\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";
  EXPECT_TRUE(
      base::JSONWriter::Write(http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json_updated, preferences_json);

  // #3: Set AlternativeService with same advertised_versions.
  AlternativeServiceInfoVector alternative_service_info_vector_3;
  // A same set of QUIC versions but listed in a different order.
  quic::ParsedQuicVersionVector advertised_versions_2 = {
      quic::ParsedQuicVersion::Draft29(), quic::ParsedQuicVersion::Q046()};
  alternative_service_info_vector_3.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions_2));
  http_server_props_->SetAlternativeServices(
      server_www, NetworkAnonymizationKey(), alternative_service_info_vector_3);

  // Change in version ordering causes prefs update.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Verify preferences updated with new advertised versions.
  const char expected_json_updated2[] =
      "{\"quic_servers\":"
      "[{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}],"
      "\"servers\":["
      "{\"alternative_service\":"
      "[{\"advertised_alpns\":[\"h3-29\",\"h3-Q046\"],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"quic\"}],"
      "\"anonymization\":[],"
      "\"server\":\"https://www.google.com:80\"}],"
      "\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";
  EXPECT_TRUE(
      base::JSONWriter::Write(http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json_updated2, preferences_json);
}

TEST_F(HttpServerPropertiesManagerTest, UpdateCacheWithPrefs) {
  AlternativeService cached_broken_service(kProtoQUIC, "cached_broken", 443);
  AlternativeService cached_broken_service2(kProtoQUIC, "cached_broken2", 443);
  AlternativeService cached_recently_broken_service(kProtoQUIC,
                                                    "cached_rbroken", 443);

  http_server_props_->MarkAlternativeServiceBroken(cached_broken_service,
                                                   NetworkAnonymizationKey());
  http_server_props_->MarkAlternativeServiceBroken(cached_broken_service2,
                                                   NetworkAnonymizationKey());
  http_server_props_->MarkAlternativeServiceRecentlyBroken(
      cached_recently_broken_service, NetworkAnonymizationKey());

  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  // There should be a task to remove remove alt services from the cache of
  // broken alt services. There should be no task to update the prefs, since the
  // prefs file hasn't been loaded yet.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());

  // Load the |pref_delegate_| with some JSON to verify updating the cache from
  // prefs. For the broken alternative services "www.google.com:1234" and
  // "cached_broken", the expiration time will be one day from now.

  std::string expiration_str =
      base::NumberToString(static_cast<int64_t>(one_day_from_now_.ToTimeT()));

  base::Value::Dict server_dict = base::test::ParseJsonDict(
      "{"
      "\"broken_alternative_services\":["
      "{\"broken_until\":\"" +
      expiration_str +
      "\","
      "\"host\":\"www.google.com\",\"anonymization\":[],"
      "\"port\":1234,\"protocol_str\":\"h2\"},"
      "{\"broken_count\":2,\"broken_until\":\"" +
      expiration_str +
      "\","
      "\"host\":\"cached_broken\",\"anonymization\":[],"
      "\"port\":443,\"protocol_str\":\"quic\"},"
      "{\"broken_count\":3,"
      "\"host\":\"cached_rbroken\",\"anonymization\":[],"
      "\"port\":443,\"protocol_str\":\"quic\"}],"
      "\"quic_servers\":["
      "{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}"
      "],"
      "\"servers\":["
      "{\"server\":\"https://www.google.com:80\","
      "\"anonymization\":[],"
      "\"alternative_service\":["
      "{\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"h2\"},"
      "{\"expiration\":\"13758804000000000\",\"host\":\"www.google.com\","
      "\"port\":1234,\"protocol_str\":\"h2\"}"
      "]"
      "},"
      "{\"server\":\"https://mail.google.com:80\","
      "\"anonymization\":[],"
      "\"alternative_service\":["
      "{\"expiration\":\"9223372036854775807\",\"host\":\"foo.google.com\","
      "\"port\":444,\"protocol_str\":\"h2\"}"
      "],"
      "\"network_stats\":{\"srtt\":42}"
      "}"
      "],"
      "\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},"
      "\"version\":5"
      "}");

  // Don't use the test fixture's InitializePrefs() method, since there are
  // pending tasks. Initializing prefs should queue a pref update task, since
  // prefs have been modified.
  pref_delegate_->InitializePrefs(std::move(server_dict));
  EXPECT_TRUE(http_server_props_->IsInitialized());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());

  // Run until prefs are updated.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());

  //
  // Verify alternative service info for https://www.google.com
  //
  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "www.google.com", 80),
          NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("www.google.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(
      "13756212000000000",
      base::NumberToString(
          alternative_service_info_vector[0].expiration().ToInternalValue()));

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("www.google.com",
            alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(1234,
            alternative_service_info_vector[1].alternative_service().port);
  EXPECT_EQ(
      "13758804000000000",
      base::NumberToString(
          alternative_service_info_vector[1].expiration().ToInternalValue()));

  //
  // Verify alternative service info for https://mail.google.com
  //
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "mail.google.com", 80),
          NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("foo.google.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(444, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(
      "9223372036854775807",
      base::NumberToString(
          alternative_service_info_vector[0].expiration().ToInternalValue()));

  //
  // Verify broken alternative services.
  //
  AlternativeService prefs_broken_service(kProtoHTTP2, "www.google.com", 1234);
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service2, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      prefs_broken_service, NetworkAnonymizationKey()));

  // Verify brokenness expiration times.
  // |cached_broken_service|'s expiration time should've been overwritten by the
  // prefs to be approximately 1 day from now. |cached_broken_service2|'s
  // expiration time should still be 5 minutes due to being marked broken.
  // |prefs_broken_service|'s expiration time should be approximately 1 day from
  // now which comes from the prefs.
  FastForwardBy(base::Minutes(5) -
                HttpServerProperties::GetUpdatePrefsDelayForTesting());
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service2, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      prefs_broken_service, NetworkAnonymizationKey()));
  FastForwardBy(base::Days(1));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service2, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      prefs_broken_service, NetworkAnonymizationKey()));

  // Now that |prefs_broken_service|'s brokenness has expired, it should've
  // been removed from the alternative services info vectors of all servers.
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "www.google.com", 80),
          NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  //
  // Verify recently broken alternative services.
  //

  // If an entry is already in cache, the broken count in the prefs should
  // overwrite the one in the cache.
  // |prefs_broken_service| should have broken-count 1 from prefs.
  // |cached_recently_broken_service| should have broken-count 3 from prefs.
  // |cached_broken_service| should have broken-count 2 from prefs.
  // |cached_broken_service2| should have broken-count 1 from being marked
  // broken.

  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      prefs_broken_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      cached_recently_broken_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      cached_broken_service2, NetworkAnonymizationKey()));
  // Make sure |prefs_broken_service| has the right expiration delay when marked
  // broken. Since |prefs_broken_service| had no broken_count specified in the
  // prefs, a broken_count value of 1 should have been assumed by
  // |http_server_props_|.
  http_server_props_->MarkAlternativeServiceBroken(prefs_broken_service,
                                                   NetworkAnonymizationKey());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardBy(base::Minutes(10) - base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      prefs_broken_service, NetworkAnonymizationKey()));
  FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      prefs_broken_service, NetworkAnonymizationKey()));
  // Make sure |cached_recently_broken_service| has the right expiration delay
  // when marked broken.
  http_server_props_->MarkAlternativeServiceBroken(
      cached_recently_broken_service, NetworkAnonymizationKey());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardBy(base::Minutes(40) - base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_recently_broken_service, NetworkAnonymizationKey()));
  FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_recently_broken_service, NetworkAnonymizationKey()));
  // Make sure |cached_broken_service| has the right expiration delay when
  // marked broken.
  http_server_props_->MarkAlternativeServiceBroken(cached_broken_service,
                                                   NetworkAnonymizationKey());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardBy(base::Minutes(20) - base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service, NetworkAnonymizationKey()));
  // Make sure |cached_broken_service2| has the right expiration delay when
  // marked broken.
  http_server_props_->MarkAlternativeServiceBroken(cached_broken_service2,
                                                   NetworkAnonymizationKey());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardBy(base::Minutes(10) - base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service2, NetworkAnonymizationKey()));
  FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      cached_broken_service2, NetworkAnonymizationKey()));

  //
  // Verify ServerNetworkStats.
  //
  const ServerNetworkStats* server_network_stats =
      http_server_props_->GetServerNetworkStats(
          url::SchemeHostPort("https", "mail.google.com", 80),
          NetworkAnonymizationKey());
  EXPECT_TRUE(server_network_stats);
  EXPECT_EQ(server_network_stats->srtt, base::TimeDelta::FromInternalValue(42));

  //
  // Verify QUIC server info.
  //
  const std::string* quic_server_info = http_server_props_->GetQuicServerInfo(
      quic::QuicServerId("mail.google.com", 80), PRIVACY_MODE_DISABLED,
      NetworkAnonymizationKey());
  EXPECT_EQ("quic_server_info1", *quic_server_info);

  //
  // Verify supports QUIC.
  //
  IPAddress actual_address(127, 0, 0, 1);
  EXPECT_TRUE(
      http_server_props_->WasLastLocalAddressWhenQuicWorked(actual_address));
  EXPECT_EQ(4, pref_delegate_->GetAndClearNumPrefUpdates());
}

// Check the interaction of ForceHTTP11 with saving/restoring settings.
// In particular, ForceHTTP11 is not saved, and it should not overwrite or be
// overitten by loaded data.
TEST_F(HttpServerPropertiesManagerTest, ForceHTTP11) {
  const url::SchemeHostPort kServer1("https", "foo.test", 443);
  const url::SchemeHostPort kServer2("https", "bar.test", 443);
  const url::SchemeHostPort kServer3("https", "baz.test", 443);

  // Create and initialize an HttpServerProperties with no state.
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  std::unique_ptr<HttpServerProperties> properties =
      std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                             /*net_log=*/nullptr,
                                             GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(base::Value::Dict());

  // Set kServer1 to support H2, but require HTTP/1.1.  Set kServer2 to only
  // require HTTP/1.1.
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(properties->RequiresHTTP11(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));
  EXPECT_FALSE(properties->RequiresHTTP11(kServer2, NetworkAnonymizationKey()));
  properties->SetSupportsSpdy(kServer1, NetworkAnonymizationKey(), true);
  properties->SetHTTP11Required(kServer1, NetworkAnonymizationKey());
  properties->SetHTTP11Required(kServer2, NetworkAnonymizationKey());
  EXPECT_TRUE(properties->GetSupportsSpdy(kServer1, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer2, NetworkAnonymizationKey()));

  // Wait until the data's been written to prefs, and then tear down the
  // HttpServerProperties.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  base::Value::Dict saved_value =
      unowned_pref_delegate->GetServerProperties().Clone();
  properties.reset();

  // Only information on kServer1 should have been saved to prefs.
  std::string preferences_json;
  base::JSONWriter::Write(saved_value, &preferences_json);
  EXPECT_EQ(
      "{\"servers\":["
      "{\"anonymization\":[],"
      "\"server\":\"https://foo.test\","
      "\"supports_spdy\":true}],"
      "\"version\":5}",
      preferences_json);

  // Create a new HttpServerProperties using the value saved to prefs above.
  pref_delegate = std::make_unique<MockPrefDelegate>();
  unowned_pref_delegate = pref_delegate.get();
  properties = std::make_unique<HttpServerProperties>(
      std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());

  // Before the data has loaded, set kServer1 and kServer3 as requiring
  // HTTP/1.1.
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(properties->RequiresHTTP11(kServer1, NetworkAnonymizationKey()));
  properties->SetHTTP11Required(kServer1, NetworkAnonymizationKey());
  properties->SetHTTP11Required(kServer3, NetworkAnonymizationKey());
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer1, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));
  EXPECT_FALSE(properties->RequiresHTTP11(kServer2, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer3, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer3, NetworkAnonymizationKey()));

  // The data loads.
  unowned_pref_delegate->InitializePrefs(std::move(saved_value));

  // The properties should contain a combination of the old and new data.
  EXPECT_TRUE(properties->GetSupportsSpdy(kServer1, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer1, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer2, NetworkAnonymizationKey()));
  EXPECT_FALSE(properties->RequiresHTTP11(kServer2, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties->GetSupportsSpdy(kServer3, NetworkAnonymizationKey()));
  EXPECT_TRUE(properties->RequiresHTTP11(kServer3, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, NetworkAnonymizationKeyServerInfo) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const SchemefulSite kOpaqueSite(GURL("data:text/plain,Hello World"));
  const url::SchemeHostPort kServer("https", "baz.test", 443);
  const url::SchemeHostPort kServer2("https", "zab.test", 443);

  HttpServerProperties::ServerInfo server_info;
  server_info.supports_spdy = true;

  for (auto save_network_anonymization_key_mode :
       kNetworkAnonymizationKeyModes) {
    SCOPED_TRACE(static_cast<int>(save_network_anonymization_key_mode));

    // Save prefs using |save_network_anonymization_key_mode|.
    base::Value::Dict saved_value;
    {
      // Configure the the feature.
      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(save_network_anonymization_key_mode);

      // This parameter is normally calculated by HttpServerProperties, but
      // this test doesn't use that class.
      bool use_network_anonymization_key =
          save_network_anonymization_key_mode !=
          NetworkAnonymizationKeyMode::kDisabled;

      HttpServerProperties::ServerInfoMap server_info_map;

      // Add server info entry using two origins with value of |server_info|.
      // NetworkAnonymizationKey's constructor takes the state of the
      // kAppendFrameOriginToNetworkAnonymizationKey feature into account, so
      // need to make sure to call the constructor after setting up the feature
      // above.
      HttpServerProperties::ServerInfoMapKey server_info_key(
          kServer, NetworkAnonymizationKey::CreateCrossSite(kSite1),
          use_network_anonymization_key);
      server_info_map.Put(server_info_key, server_info);

      // Also add an etry with an opaque origin, if
      // |use_network_anonymization_key| is true. This value should not be saved
      // to disk, since opaque origins are only meaningful within a browsing
      // session.
      if (use_network_anonymization_key) {
        HttpServerProperties::ServerInfoMapKey server_info_key2(
            kServer2, NetworkAnonymizationKey::CreateSameSite(kOpaqueSite),
            use_network_anonymization_key);
        server_info_map.Put(server_info_key2, server_info);
      }

      saved_value = ServerInfoMapToDict(server_info_map);
    }

    for (auto load_network_anonymization_key_mode :
         kNetworkAnonymizationKeyModes) {
      SCOPED_TRACE(static_cast<int>(load_network_anonymization_key_mode));

      std::unique_ptr<base::test::ScopedFeatureList> feature_list =
          SetNetworkAnonymizationKeyMode(load_network_anonymization_key_mode);
      std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map2 =
          DictToServerInfoMap(saved_value.Clone());
      ASSERT_TRUE(server_info_map2);
      if (save_network_anonymization_key_mode ==
          NetworkAnonymizationKeyMode::kDisabled) {
        // If NetworkAnonymizationKey was disabled when saving, it was saved
        // with an empty NetworkAnonymizationKey, which should always be loaded
        // successfully. This is needed to continue to support consumers that
        // don't use NetworkAnonymizationKeys.
        ASSERT_EQ(1u, server_info_map2->size());
        const HttpServerProperties::ServerInfoMapKey& server_info_key2 =
            server_info_map2->begin()->first;
        const HttpServerProperties::ServerInfo& server_info2 =
            server_info_map2->begin()->second;
        EXPECT_EQ(kServer, server_info_key2.server);
        EXPECT_EQ(NetworkAnonymizationKey(),
                  server_info_key2.network_anonymization_key);
        EXPECT_EQ(server_info, server_info2);
      } else if (save_network_anonymization_key_mode ==
                 load_network_anonymization_key_mode) {
        // If the save and load modes are the same, the load should succeed, and
        // the network anonymization keys should match.
        ASSERT_EQ(1u, server_info_map2->size());
        const HttpServerProperties::ServerInfoMapKey& server_info_key2 =
            server_info_map2->begin()->first;
        const HttpServerProperties::ServerInfo& server_info2 =
            server_info_map2->begin()->second;
        EXPECT_EQ(kServer, server_info_key2.server);
        EXPECT_EQ(NetworkAnonymizationKey::CreateCrossSite(kSite1),
                  server_info_key2.network_anonymization_key);
        EXPECT_EQ(server_info, server_info2);
      } else {
        // Otherwise, the NetworkAnonymizationKey doesn't make sense with the
        // current feature values, so the ServerInfo should be discarded.
        EXPECT_EQ(0u, server_info_map2->size());
      }
    }
  }
}

// Tests a full round trip with a NetworkAnonymizationKey, using the
// HttpServerProperties interface.
TEST_F(Htt
"""


```