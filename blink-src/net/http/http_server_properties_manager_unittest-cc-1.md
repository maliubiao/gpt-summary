Response:
The user wants me to analyze a C++ unittest file for Chromium's network stack. This is the second part of a five-part file.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** Look for the `TEST_F` macros. Each of these defines an individual test case. Analyze what each test case is verifying. This will reveal the primary functionalities being tested in this specific part of the file.

2. **Relate to the Class Under Test:**  The `TEST_F` macro usually takes the name of the test fixture. In this case, it's `HttpServerPropertiesManagerTest`. This tells us the tests are for the `HttpServerPropertiesManager` class (or a closely related component).

3. **Look for Interactions:** Observe how the tests interact with the `http_server_props_` member (which is likely an instance of `HttpServerPropertiesManager`). Note the methods being called and the expected outcomes (using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, etc.).

4. **JavaScript Relevance:**  Consider if the tested functionalities have any direct or indirect impact on how web browsers (which use Chromium) interact with web servers. Things like alternative services (like HTTP/2 or QUIC), broken connections, and server network statistics are relevant to network performance and browser behavior.

5. **Logical Reasoning and Examples:** For tests involving setting and getting properties, imagine what inputs would lead to specific outputs. Provide concrete examples of how these properties might be used in a real-world scenario.

6. **User/Programming Errors:**  Think about common mistakes a developer or user might make when interacting with the features being tested.

7. **Debugging Clues:**  Consider how the tested functionalities might manifest in user behavior and provide steps a developer could take to investigate related issues.

8. **Summarize Part 2's Functionality:** Combine the observations from the individual tests to provide a concise summary of what this section of the unittest is focused on.

**Mental Walkthrough of the Provided Code Snippet:**

* **`OnDefaultNetworkChanged` tests:** These verify how the `HttpServerPropertiesManager` handles network changes, specifically in relation to marking alternative services as broken and then resetting that status. One test considers a scenario where *only* broken services are affected.
* **`LastLocalAddressWhenQuicWorked` test:** This checks the functionality for storing and retrieving the last local IP address used when a QUIC connection was successful.
* **`ServerNetworkStats` test:**  This verifies the storage and retrieval of server network statistics (like SRTT - Smoothed Round-Trip Time).
* **`QuicServerInfo` test:** This checks the ability to store and retrieve opaque QUIC server information.
* **`Clear` test:** This verifies the functionality to clear all stored HTTP server properties.
* **`BadLastLocalAddressWhenQuicWorked` test:** Despite the name, this test seems to focus on correctly parsing a large number of alternative services from preferences and then verifying the "last local address when QUIC worked" setting. The "bad" likely refers to a previous bug where this interaction might have caused issues.
* **`UpdatePrefsWithCache` test:** This is a more comprehensive test that sets various HTTP server properties and then verifies that they are correctly written to the preferences. It also deals with the timing of preference updates.
* **`ParseAlternativeServiceInfo` test:** This checks the logic for parsing alternative service information from a dictionary.
* **`DoNotLoadAltSvcForInsecureOrigins` test:** This verifies that alternative services are not loaded for insecure (HTTP) origins.
* **`DoNotPersistExpiredAlternativeService` and `DoNotLoadExpiredAlternativeService` tests:** These tests confirm that expired alternative service entries are not persisted or loaded from disk.
* **`UpdatePrefsOnShutdown` test:** This verifies that preferences are updated when the `HttpServerPropertiesManager` is destroyed.
* **`PersistAdvertisedVersionsToPref` test:** This tests the persistence of advertised QUIC versions for alternative services.

Based on this, the core functionality of this part of the file appears to be testing the persistence and retrieval of various HTTP server properties, including alternative services, broken status, last local address for QUIC, server network statistics, and QUIC server information, with a focus on how these are handled during network changes, preference loading, and saving.
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件的第2部分，共5部分。根据提供的代码片段，我们可以归纳出以下功能：

**主要功能：测试 `HttpServerPropertiesManager` 类中关于持久化和管理 HTTP 服务器属性的功能，特别是与以下方面相关的：**

1. **备用服务（Alternative Services）：**
   - 测试标记和取消标记备用服务为不可用状态 (`MarkAlternativeServiceBroken`, `MarkAlternativeServiceBrokenUntilDefaultNetworkChanges`)。
   - 测试在默认网络改变时如何处理已标记为不可用的备用服务 (`OnDefaultNetworkChanged`)。
   - 测试备用服务最近是否不可用的状态 (`WasAlternativeServiceRecentlyBroken`)。
   - 测试从持久化数据中解析备用服务信息 (`ParseAlternativeServiceInfo`)。
   - 测试是否为不安全的来源加载备用服务 (`DoNotLoadAltSvcForInsecureOrigins`)。
   - 测试是否持久化过期的备用服务条目 (`DoNotPersistExpiredAlternativeService`) 以及是否加载过期的备用服务条目 (`DoNotLoadExpiredAlternativeService`)。
   - 测试持久化备用服务的通告版本信息 (`PersistAdvertisedVersionsToPref`)。

2. **QUIC 相关信息：**
   - 测试记录最近一次 QUIC 连接成功的本地 IP 地址 (`SetLastLocalAddressWhenQuicWorked`, `WasLastLocalAddressWhenQuicWorked`)。
   - 测试存储和检索 QUIC 服务器信息 (`SetQuicServerInfo`, `GetQuicServerInfo`)。

3. **服务器网络统计信息：**
   - 测试存储和检索服务器的网络统计信息，例如 SRTT (`SetServerNetworkStats`, `GetServerNetworkStats`)。
   - 测试清除服务器网络统计信息 (`ClearServerNetworkStats`)。

4. **通用数据清除：**
   - 测试清除所有 HTTP 服务器属性的功能 (`Clear`)。

5. **偏好设置（Preferences）更新：**
   - 测试偏好设置的更新机制，包括延迟更新和在特定事件发生时的更新（例如，在对象析构时 `UpdatePrefsOnShutdown`）。
   - 测试在更新偏好设置时如何处理缓存的数据 (`UpdatePrefsWithCache`)。

**与 Javascript 的关系：**

这些功能直接影响浏览器与服务器之间的网络连接性能和可靠性。虽然 C++ 代码本身不直接包含 Javascript，但这些功能会影响浏览器中 Javascript 发起的网络请求的行为。

**举例说明：**

- **备用服务：** 当一个网站支持 HTTP/2 或 QUIC 等新的协议时，浏览器可以通过备用服务信息尝试使用这些更快的协议。如果一个备用服务连接失败，浏览器会将其标记为不可用，并在一段时间内避免再次尝试。这提升了用户体验，避免了重复的连接失败。Javascript 可以通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求，而底层的网络栈会根据这些备用服务信息来优化连接。
- **QUIC 相关信息：**  QUIC 是谷歌推出的一种基于 UDP 的传输层协议，旨在提供更快的连接和更好的用户体验。记录最近一次 QUIC 连接成功的本地 IP 地址可以帮助浏览器在网络环境变化后更快地重新建立 QUIC 连接。Javascript 发起的 HTTPS 请求可能在底层使用 QUIC。
- **服务器网络统计信息：** 存储服务器的 SRTT 等信息可以帮助浏览器做出更明智的连接决策，例如选择更快的服务器。这对于用户访问速度有直接影响。
- **偏好设置更新：**  浏览器会将这些服务器属性信息持久化存储，以便在下次启动时能够快速恢复，而无需重新学习。这减少了初次访问的延迟。

**逻辑推理，假设输入与输出：**

**假设输入：**

1. **`OnDefaultNetworkChangedWithBrokenUntilDefaultNetworkChanges` 测试：**
   - 初始状态：`alternative_service` (例如，`h2://mail.google.com:443`) 未被标记为不可用。
   - 操作：调用 `MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(alternative_service)`.
   - 操作：调用 `OnDefaultNetworkChanged()`.

**预期输出：**

   - 调用 `MarkAlternativeServiceBrokenUntilDefaultNetworkChanges` 后，`IsAlternativeServiceBroken(alternative_service)` 和 `WasAlternativeServiceRecentlyBroken(alternative_service)` 返回 `true`。
   - 调用 `OnDefaultNetworkChanged()` 后， `IsAlternativeServiceBroken(alternative_service)` 和 `WasAlternativeServiceRecentlyBroken(alternative_service)` 返回 `false`。

2. **`ServerNetworkStats` 测试：**
   - 初始状态：没有关于 `mail.google.com:80` 的服务器网络统计信息。
   - 操作：调用 `SetServerNetworkStats(mail_server, stats1)`，其中 `stats1.srtt` 为 10 微秒。
   - 操作：调用 `GetServerNetworkStats(mail_server)`.

**预期输出：**

   - `GetServerNetworkStats(mail_server)` 返回的 `ServerNetworkStats` 对象的 `srtt` 值为 10 微秒。

**用户或编程常见的使用错误：**

1. **未能正确处理网络状态变化：** 开发者可能假设网络连接是稳定的，而没有考虑到网络切换或断开的情况。`HttpServerPropertiesManager` 帮助浏览器处理这些情况，但开发者在应用层也需要进行相应的处理，例如在网络断开后重新发起请求。
2. **过度依赖缓存的备用服务信息：**  开发者不应永久信任缓存的备用服务信息。服务器配置可能会发生变化，导致缓存的信息过时甚至错误。浏览器会定期更新这些信息，但开发者也应该处理连接失败的情况。
3. **错误地配置 HTTP 首部：**  服务器需要正确地发送 `Alt-Svc` 首部来告知浏览器支持的备用服务。配置错误可能导致浏览器无法发现或使用备用服务。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户报告一个网站加载速度很慢的问题，调试线索可能涉及以下步骤：

1. **用户访问网站：** 用户在浏览器地址栏输入网址或点击链接访问一个网站 (例如 `https://mail.google.com`)。
2. **浏览器发起连接：** 浏览器开始与服务器建立连接。
3. **查找备用服务信息：**  `HttpServerPropertiesManager` 会检查是否缓存了该域名的备用服务信息。
4. **尝试备用连接：** 如果有可用的备用服务 (例如 HTTP/2 或 QUIC)，浏览器可能会尝试使用这些协议建立连接。
5. **连接失败处理：** 如果备用连接失败，`HttpServerPropertiesManager` 可能会将该备用服务标记为不可用。
6. **回退到默认协议：** 浏览器可能回退到使用默认的 HTTP/1.1 协议进行连接。
7. **偏好设置更新：**  `HttpServerPropertiesManager` 可能会将备用服务的不可用状态持久化到偏好设置中。

**调试线索：**

- 检查浏览器的网络日志 (chrome://net-export/)，查看是否尝试了备用连接以及是否连接失败。
- 检查浏览器的内部状态 (chrome://net-internals/#http_server_properties) 查看 `HttpServerPropertiesManager` 中存储的备用服务信息和不可用状态。
- 如果备用服务被标记为不可用，可能是网络问题或服务器配置问题导致连接失败。
- 清除浏览器的网络缓存和 HTTP 服务器属性 (chrome://settings/clearBrowserData) 可以重置这些状态，以便排除缓存问题。

**总结 Part 2 的功能：**

总而言之，这段代码主要测试了 `HttpServerPropertiesManager` 中负责管理和持久化 HTTP 服务器属性的核心功能，特别是关于备用服务、QUIC 相关信息和服务器网络统计信息的管理，以及偏好设置的更新机制。这些功能对于提升浏览器网络连接的性能和用户体验至关重要。

Prompt: 
```
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
 EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  http_server_props_->MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // In addition to the pref update task, there's now a task to mark the
  // alternative service as no longer broken.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  http_server_props_->OnDefaultNetworkChanged();
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  // Run the task.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, OnDefaultNetworkChangedWithBrokenOnly) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail;
  AlternativeService alternative_service;

  spdy_server_mail = url::SchemeHostPort("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  alternative_service = AlternativeService(kProtoHTTP2, "mail.google.com", 443);

  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);
  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  http_server_props_->MarkAlternativeServiceBroken(alternative_service,
                                                   NetworkAnonymizationKey());
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // In addition to the pref update task, there's now a task to mark the
  // alternative service as no longer broken.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  http_server_props_->OnDefaultNetworkChanged();
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  // Run the task.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, LastLocalAddressWhenQuicWorked) {
  InitializePrefs();

  IPAddress actual_address(127, 0, 0, 1);
  EXPECT_FALSE(http_server_props_->HasLastLocalAddressWhenQuicWorked());
  EXPECT_FALSE(
      http_server_props_->WasLastLocalAddressWhenQuicWorked(actual_address));
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);
  // Another task should not be scheduled.
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_TRUE(
      http_server_props_->WasLastLocalAddressWhenQuicWorked(actual_address));

  // Another task should not be scheduled.
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
}

TEST_F(HttpServerPropertiesManagerTest, ServerNetworkStats) {
  InitializePrefs();

  url::SchemeHostPort mail_server("http", "mail.google.com", 80);
  const ServerNetworkStats* stats = http_server_props_->GetServerNetworkStats(
      mail_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, stats);
  ServerNetworkStats stats1;
  stats1.srtt = base::Microseconds(10);
  http_server_props_->SetServerNetworkStats(mail_server,
                                            NetworkAnonymizationKey(), stats1);
  // Another task should not be scheduled.
  http_server_props_->SetServerNetworkStats(mail_server,
                                            NetworkAnonymizationKey(), stats1);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Another task should not be scheduled.
  http_server_props_->SetServerNetworkStats(mail_server,
                                            NetworkAnonymizationKey(), stats1);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(GetPendingMainThreadTaskCount(), 0u);

  const ServerNetworkStats* stats2 = http_server_props_->GetServerNetworkStats(
      mail_server, NetworkAnonymizationKey());
  EXPECT_EQ(10, stats2->srtt.ToInternalValue());

  http_server_props_->ClearServerNetworkStats(mail_server,
                                              NetworkAnonymizationKey());

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_EQ(nullptr, http_server_props_->GetServerNetworkStats(
                         mail_server, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, QuicServerInfo) {
  InitializePrefs();

  quic::QuicServerId mail_quic_server_id("mail.google.com", 80);
  EXPECT_EQ(nullptr, http_server_props_->GetQuicServerInfo(
                         mail_quic_server_id, PRIVACY_MODE_DISABLED,
                         NetworkAnonymizationKey()));
  std::string quic_server_info1("quic_server_info1");
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);
  // Another task should not be scheduled.
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_EQ(quic_server_info1, *http_server_props_->GetQuicServerInfo(
                                   mail_quic_server_id, PRIVACY_MODE_DISABLED,
                                   NetworkAnonymizationKey()));

  // Another task should not be scheduled.
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
}

TEST_F(HttpServerPropertiesManagerTest, Clear) {
  InitializePrefs();

  const url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  const IPAddress actual_address(127, 0, 0, 1);
  const quic::QuicServerId mail_quic_server_id("mail.google.com", 80);
  const std::string quic_server_info1("quic_server_info1");
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               1234);
  const AlternativeService broken_alternative_service(
      kProtoHTTP2, "broken.google.com", 1234);

  AlternativeServiceInfoVector alt_svc_info_vector;
  alt_svc_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, one_day_from_now_));
  alt_svc_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          broken_alternative_service, one_day_from_now_));
  http_server_props_->SetAlternativeServices(
      spdy_server, NetworkAnonymizationKey(), alt_svc_info_vector);

  http_server_props_->MarkAlternativeServiceBroken(broken_alternative_service,
                                                   NetworkAnonymizationKey());
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);
  ServerNetworkStats stats;
  stats.srtt = base::Microseconds(10);
  http_server_props_->SetServerNetworkStats(spdy_server,
                                            NetworkAnonymizationKey(), stats);

  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);

  // Advance time by just enough so that the prefs update task is executed but
  // not the task to expire the brokenness of |broken_alternative_service|.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      broken_alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(HasAlternativeService(spdy_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      http_server_props_->WasLastLocalAddressWhenQuicWorked(actual_address));
  const ServerNetworkStats* stats1 = http_server_props_->GetServerNetworkStats(
      spdy_server, NetworkAnonymizationKey());
  EXPECT_EQ(10, stats1->srtt.ToInternalValue());
  EXPECT_EQ(quic_server_info1, *http_server_props_->GetQuicServerInfo(
                                   mail_quic_server_id, PRIVACY_MODE_DISABLED,
                                   NetworkAnonymizationKey()));

  // Clear http server data, which should instantly update prefs.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  bool callback_invoked_ = false;
  http_server_props_->Clear(base::BindOnce(
      [](bool* callback_invoked) {
        EXPECT_FALSE(*callback_invoked);
        *callback_invoked = true;
      },
      &callback_invoked_));
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_FALSE(callback_invoked_);
  std::move(pref_delegate_->GetSetPropertiesCallback()).Run();
  EXPECT_TRUE(callback_invoked_);

  EXPECT_FALSE(http_server_props_->IsAlternativeServiceBroken(
      broken_alternative_service, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(HasAlternativeService(spdy_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_props_->HasLastLocalAddressWhenQuicWorked());
  const ServerNetworkStats* stats2 = http_server_props_->GetServerNetworkStats(
      spdy_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, stats2);
  EXPECT_EQ(nullptr, http_server_props_->GetQuicServerInfo(
                         mail_quic_server_id, PRIVACY_MODE_DISABLED,
                         NetworkAnonymizationKey()));
}

// https://crbug.com/444956: Add 200 alternative_service servers followed by
// supports_quic and verify we have read supports_quic from prefs.
TEST_F(HttpServerPropertiesManagerTest, BadLastLocalAddressWhenQuicWorked) {
  base::Value::List servers_list;

  for (int i = 1; i <= 200; ++i) {
    // Set up alternative_service for www.google.com:i.
    base::Value::Dict server_dict;
    base::Value::Dict alternative_service_dict;
    alternative_service_dict.Set("protocol_str", "quic");
    alternative_service_dict.Set("port", i);
    base::Value::List alternative_service_list;
    alternative_service_list.Append(std::move(alternative_service_dict));
    server_dict.Set("alternative_service", std::move(alternative_service_list));
    server_dict.Set("server", StringPrintf("https://www.google.com:%d", i));
    server_dict.Set("anonymization", base::Value(base::Value::Type::LIST));
    servers_list.Append(std::move(server_dict));
  }

  // Set the server preference for http://mail.google.com server.
  base::Value::Dict server_dict2;
  server_dict2.Set("server", "https://mail.google.com");
  server_dict2.Set("anonymization", base::Value(base::Value::Type::LIST));
  servers_list.Append(std::move(server_dict2));

  base::Value::Dict http_server_properties_dict = DictWithVersion();
  http_server_properties_dict.Set("servers", std::move(servers_list));

  // Set up SupportsQuic for 127.0.0.1
  base::Value::Dict supports_quic;
  supports_quic.Set("used_quic", true);
  supports_quic.Set("address", "127.0.0.1");
  http_server_properties_dict.Set("supports_quic", std::move(supports_quic));

  // Set up the pref.
  InitializePrefs(std::move(http_server_properties_dict));

  // Verify alternative service.
  for (int i = 1; i <= 200; ++i) {
    GURL server_gurl;
      server_gurl = GURL(StringPrintf("https://www.google.com:%d", i));
    url::SchemeHostPort server(server_gurl);
    AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_props_->GetAlternativeServiceInfos(
            server, NetworkAnonymizationKey());
    ASSERT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_EQ(
        kProtoQUIC,
        alternative_service_info_vector[0].alternative_service().protocol);
    EXPECT_EQ(i, alternative_service_info_vector[0].alternative_service().port);
  }

  // Verify WasLastLocalAddressWhenQuicWorked.
  ASSERT_TRUE(http_server_props_->WasLastLocalAddressWhenQuicWorked(
      IPAddress::IPv4Localhost()));
}

TEST_F(HttpServerPropertiesManagerTest, UpdatePrefsWithCache) {
  InitializePrefs();

  const url::SchemeHostPort server_www("https", "www.google.com", 80);
  const url::SchemeHostPort server_mail("https", "mail.google.com", 80);

  // #1 & #2: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  AlternativeService www_alternative_service1(kProtoHTTP2, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          www_alternative_service1, expiration1));

  AlternativeService www_alternative_service2(kProtoHTTP2, "www.google.com",
                                              1234);
  base::Time expiration2;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-31 10:00:00", &expiration2));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          www_alternative_service2, expiration2));
  http_server_props_->SetAlternativeServices(
      server_www, NetworkAnonymizationKey(), alternative_service_info_vector);

  AlternativeService mail_alternative_service(kProtoHTTP2, "foo.google.com",
                                              444);
  base::Time expiration3 = base::Time::Max();
  http_server_props_->SetHttp2AlternativeService(
      server_mail, NetworkAnonymizationKey(), mail_alternative_service,
      expiration3);

  http_server_props_->MarkAlternativeServiceBroken(www_alternative_service2,
                                                   NetworkAnonymizationKey());
  http_server_props_->MarkAlternativeServiceRecentlyBroken(
      mail_alternative_service, NetworkAnonymizationKey());

  // #3: Set SPDY server map
  http_server_props_->SetSupportsSpdy(server_www, NetworkAnonymizationKey(),
                                      false);
  http_server_props_->SetSupportsSpdy(server_mail, NetworkAnonymizationKey(),
                                      true);
  http_server_props_->SetSupportsSpdy(
      url::SchemeHostPort("http", "not_persisted.com", 80),
      NetworkAnonymizationKey(), false);

  // #4: Set ServerNetworkStats.
  ServerNetworkStats stats;
  stats.srtt = base::TimeDelta::FromInternalValue(42);
  http_server_props_->SetServerNetworkStats(server_mail,
                                            NetworkAnonymizationKey(), stats);

  // #5: Set quic_server_info string.
  quic::QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_->SetQuicServerInfo(
      mail_quic_server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      quic_server_info1);

  // #6: Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_->SetLastLocalAddressWhenQuicWorked(actual_address);

  base::Time time_before_prefs_update = base::Time::Now();

  // Update Prefs.
  // The task runner has a remaining pending task to expire
  // |www_alternative_service2| in 5 minutes. Fast forward enough such
  // that the prefs update task is executed but not the task to expire
  // |broken_alternative_service|.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  base::Time time_after_prefs_update = base::Time::Now();

  // Verify |pref_delegate_|'s server dict.
  // In HttpServerPropertiesManager, broken alternative services' expiration
  // times are converted from TimeTicks to Time before being written to JSON by
  // using the difference between Time::Now() and TimeTicks::Now().
  // To verify these expiration times, |time_before_prefs_update| and
  // |time_after_prefs_update| provide lower and upper bounds for the
  // Time::Now() value used by the manager for this conversion.
  //
  // A copy of |pref_delegate_|'s server dict will be created, and the broken
  // alternative service's "broken_until" field is removed and verified
  // separately. The rest of the server dict copy is verified afterwards.
  base::Value::Dict server_dict = pref_delegate_->GetServerProperties().Clone();

  // Extract and remove the "broken_until" string for "www.google.com:1234".
  base::Value::List* broken_alt_svc_list =
      server_dict.FindList("broken_alternative_services");
  ASSERT_TRUE(broken_alt_svc_list);
  ASSERT_EQ(2u, broken_alt_svc_list->size());
  base::Value& broken_alt_svcs_list_entry = (*broken_alt_svc_list)[0];
  const std::string* broken_until_str =
      broken_alt_svcs_list_entry.GetDict().FindString("broken_until");
  ASSERT_TRUE(broken_until_str);
  const std::string expiration_string = *broken_until_str;
  broken_alt_svcs_list_entry.GetDict().Remove("broken_until");

  // Expiration time of "www.google.com:1234" should be 5 minutes minus the
  // update-prefs-delay from when the prefs were written.
  int64_t expiration_int64;
  ASSERT_TRUE(base::StringToInt64(expiration_string, &expiration_int64));
  base::TimeDelta expiration_delta =
      base::Minutes(5) - HttpServerProperties::GetUpdatePrefsDelayForTesting();
  time_t time_t_of_prefs_update = static_cast<time_t>(expiration_int64);
  EXPECT_LE((time_before_prefs_update + expiration_delta).ToTimeT(),
            time_t_of_prefs_update);
  EXPECT_GE((time_after_prefs_update + expiration_delta).ToTimeT(),
            time_t_of_prefs_update);

  // Verify all other preferences.
  const char expected_json[] =
      "{"
      "\"broken_alternative_services\":"
      "[{\"anonymization\":[],\"broken_count\":1,\"host\":\"www.google.com\","
      "\"port\":1234,\"protocol_str\":\"h2\"},"
      "{\"anonymization\":[],\"broken_count\":1,\"host\":\"foo.google.com\","
      "\"port\":444,\"protocol_str\":\"h2\"}],"
      "\"quic_servers\":"
      "[{\"anonymization\":[],"
      "\"server_id\":\"https://mail.google.com:80\","
      "\"server_info\":\"quic_server_info1\"}],"
      "\"servers\":["
      "{\"alternative_service\":[{\"advertised_alpns\":[],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"h2\"},"
      "{\"advertised_alpns\":[],\"expiration\":\"13758804000000000\","
      "\"host\":\"www.google.com\",\"port\":1234,\"protocol_str\":\"h2\"}],"
      "\"anonymization\":[],"
      "\"server\":\"https://www.google.com:80\"},"
      "{\"alternative_service\":[{\"advertised_alpns\":[],"
      "\"expiration\":\"9223372036854775807\",\"host\":\"foo.google.com\","
      "\"port\":444,\"protocol_str\":\"h2\"}],"
      "\"anonymization\":[],"
      "\"network_stats\":{\"srtt\":42},"
      "\"server\":\"https://mail.google.com:80\","
      "\"supports_spdy\":true}],"
      "\"supports_quic\":{\"address\":\"127.0.0.1\",\"used_quic\":true},"
      "\"version\":5}";

  std::string preferences_json;
  EXPECT_TRUE(base::JSONWriter::Write(server_dict, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);
}

TEST_F(HttpServerPropertiesManagerTest, ParseAlternativeServiceInfo) {
  InitializePrefs();

  base::Value::Dict server_dict = base::test::ParseJsonDict(
      "{\"alternative_service\":[{\"port\":443,\"protocol_str\":\"h2\"},"
      "{\"port\":123,\"protocol_str\":\"quic\","
      "\"expiration\":\"9223372036854775807\"},{\"host\":\"example.org\","
      "\"port\":1234,\"protocol_str\":\"h2\","
      "\"expiration\":\"13758804000000000\"}]}");

  const url::SchemeHostPort server("https", "example.com", 443);
  HttpServerProperties::ServerInfo server_info;
  EXPECT_TRUE(HttpServerPropertiesManager::ParseAlternativeServiceInfo(
      server, server_dict, &server_info));

  ASSERT_TRUE(server_info.alternative_services.has_value());
  AlternativeServiceInfoVector alternative_service_info_vector =
      server_info.alternative_services.value();
  ASSERT_EQ(3u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  // Expiration defaults to one day from now, testing with tolerance.
  const base::Time now = base::Time::Now();
  const base::Time expiration = alternative_service_info_vector[0].expiration();
  EXPECT_LE(now + base::Hours(23), expiration);
  EXPECT_GE(now + base::Days(1), expiration);

  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(123, alternative_service_info_vector[1].alternative_service().port);
  // numeric_limits<int64_t>::max() represents base::Time::Max().
  EXPECT_EQ(base::Time::Max(), alternative_service_info_vector[1].expiration());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[2].alternative_service().protocol);
  EXPECT_EQ("example.org",
            alternative_service_info_vector[2].alternative_service().host);
  EXPECT_EQ(1234,
            alternative_service_info_vector[2].alternative_service().port);
  base::Time expected_expiration;
  ASSERT_TRUE(
      base::Time::FromUTCString("2036-12-31 10:00:00", &expected_expiration));
  EXPECT_EQ(expected_expiration,
            alternative_service_info_vector[2].expiration());

  // No other fields should have been populated.
  server_info.alternative_services.reset();
  EXPECT_TRUE(server_info.empty());
}

// Regression test for https://crbug.com/615497.
TEST_F(HttpServerPropertiesManagerTest, DoNotLoadAltSvcForInsecureOrigins) {
  InitializePrefs();

  base::Value::Dict server_dict = base::test::ParseJsonDict(
      "{\"alternative_service\":[{\"port\":443,\"protocol_str\":\"h2\","
      "\"expiration\":\"9223372036854775807\"}]}");

  const url::SchemeHostPort server("http", "example.com", 80);
  HttpServerProperties::ServerInfo server_info;
  EXPECT_FALSE(HttpServerPropertiesManager::ParseAlternativeServiceInfo(
      server, server_dict, &server_info));
  EXPECT_TRUE(server_info.empty());
}

// Do not persist expired alternative service entries to disk.
TEST_F(HttpServerPropertiesManagerTest, DoNotPersistExpiredAlternativeService) {
  InitializePrefs();

  AlternativeServiceInfoVector alternative_service_info_vector;

  const AlternativeService broken_alternative_service(
      kProtoHTTP2, "broken.example.com", 443);
  const base::Time time_one_day_later = base::Time::Now() + base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          broken_alternative_service, time_one_day_later));
  // #1: MarkAlternativeServiceBroken().
  http_server_props_->MarkAlternativeServiceBroken(broken_alternative_service,
                                                   NetworkAnonymizationKey());

  const AlternativeService expired_alternative_service(
      kProtoHTTP2, "expired.example.com", 443);
  const base::Time time_one_day_ago = base::Time::Now() - base::Days(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          expired_alternative_service, time_one_day_ago));

  const AlternativeService valid_alternative_service(kProtoHTTP2,
                                                     "valid.example.com", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          valid_alternative_service, time_one_day_later));

  const url::SchemeHostPort server("https", "www.example.com", 443);
  // #2: SetAlternativeServices().
  http_server_props_->SetAlternativeServices(server, NetworkAnonymizationKey(),
                                             alternative_service_info_vector);

  // |net_test_task_runner_| has a remaining pending task to expire
  // |broken_alternative_service| at |time_one_day_later|. Fast forward enough
  // such that the prefs update task is executed but not the task to expire
  // |broken_alternative_service|.
  EXPECT_EQ(2U, GetPendingMainThreadTaskCount());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  EXPECT_EQ(1U, GetPendingMainThreadTaskCount());
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  const base::Value::Dict& pref_dict = pref_delegate_->GetServerProperties();

  const base::Value::List* servers_list = pref_dict.FindList("servers");
  ASSERT_TRUE(servers_list);
  auto it = servers_list->begin();
  const base::Value& server_pref_dict = *it;
  ASSERT_TRUE(server_pref_dict.is_dict());

  const std::string* server_str =
      server_pref_dict.GetDict().FindString("server");
  ASSERT_TRUE(server_str);
  EXPECT_EQ("https://www.example.com", *server_str);

  const base::Value* network_anonymization_key_value =
      server_pref_dict.GetDict().Find("anonymization");
  ASSERT_TRUE(network_anonymization_key_value);
  ASSERT_EQ(base::Value::Type::LIST, network_anonymization_key_value->type());
  EXPECT_TRUE(network_anonymization_key_value->GetList().empty());

  const base::Value::List* altsvc_list =
      server_pref_dict.GetDict().FindList("alternative_service");
  ASSERT_TRUE(altsvc_list);

  ASSERT_EQ(2u, altsvc_list->size());

  const base::Value& altsvc_entry = (*altsvc_list)[0];
  ASSERT_TRUE(altsvc_entry.is_dict());
  const std::string* hostname = altsvc_entry.GetDict().FindString("host");

  ASSERT_TRUE(hostname);
  EXPECT_EQ("broken.example.com", *hostname);

  const base::Value& altsvc_entry2 = (*altsvc_list)[1];
  ASSERT_TRUE(altsvc_entry.is_dict());
  hostname = altsvc_entry2.GetDict().FindString("host");
  ASSERT_TRUE(hostname);
  EXPECT_EQ("valid.example.com", *hostname);
}

// Test that expired alternative service entries on disk are ignored.
TEST_F(HttpServerPropertiesManagerTest, DoNotLoadExpiredAlternativeService) {
  InitializePrefs();

  base::Value::List alternative_service_list;
  base::Value::Dict expired_dict;
  expired_dict.Set("protocol_str", "h2");
  expired_dict.Set("host", "expired.example.com");
  expired_dict.Set("port", 443);
  base::Time time_one_day_ago = base::Time::Now() - base::Days(1);
  expired_dict.Set("expiration",
                   base::NumberToString(time_one_day_ago.ToInternalValue()));
  alternative_service_list.Append(std::move(expired_dict));

  base::Value::Dict valid_dict;
  valid_dict.Set("protocol_str", "h2");
  valid_dict.Set("host", "valid.example.com");
  valid_dict.Set("port", 443);
  valid_dict.Set("expiration",
                 base::NumberToString(one_day_from_now_.ToInternalValue()));
  alternative_service_list.Append(std::move(valid_dict));

  base::Value::Dict server_pref_dict;
  server_pref_dict.Set("alternative_service",
                       std::move(alternative_service_list));

  const url::SchemeHostPort server("https", "example.com", 443);
  HttpServerProperties::ServerInfo server_info;
  ASSERT_TRUE(HttpServerPropertiesManager::ParseAlternativeServiceInfo(
      server, server_pref_dict, &server_info));

  ASSERT_TRUE(server_info.alternative_services.has_value());
  AlternativeServiceInfoVector alternative_service_info_vector =
      server_info.alternative_services.value();
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("valid.example.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(one_day_from_now_, alternative_service_info_vector[0].expiration());

  // No other fields should have been populated.
  server_info.alternative_services.reset();
  EXPECT_TRUE(server_info.empty());
}

// Make sure prefs are updated on destruction.
TEST_F(HttpServerPropertiesManagerTest, UpdatePrefsOnShutdown) {
  InitializePrefs();

  int pref_updates = 0;
  pref_delegate_->set_extra_update_prefs_callback(
      base::BindRepeating([](int* updates) { (*updates)++; }, &pref_updates));
  http_server_props_.reset();
  EXPECT_EQ(1, pref_updates);
}

TEST_F(HttpServerPropertiesManagerTest, PersistAdvertisedVersionsToPref) {
  InitializePrefs();

  const url::SchemeHostPort server_www("https", "www.google.com", 80);
  const url::SchemeHostPort server_mail("https", "mail.google.com", 80);

  // #1 & #2: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  // Quic alternative service set with two advertised QUIC versions.
  AlternativeService quic_alternative_service1(kProtoQUIC, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  quic::ParsedQuicVersionVector advertised_versions = {
      quic::ParsedQuicVersion::Q046()};
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions));
  // HTTP/2 alternative service should not set any advertised version.
  AlternativeService h2_alternative_service(kProtoHTTP2, "www.google.com",
                                            1234);
  base::Time expiration2;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-31 10:00:00", &expiration2));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          h2_alternative_service, expiration2));
  http_server_props_->SetAlternativeServices(
      server_www, NetworkAnonymizationKey(), alternative_service_info_vector);

  // Set another QUIC alternative service with a single advertised QUIC version.
  AlternativeService mail_alternative_service(kProtoQUIC, "foo.google.
"""


```