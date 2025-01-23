Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a unit test file for `HttpServerPropertiesManager` in Chromium's network stack. I need to break down the code into its core functionalities, relate it to JavaScript if applicable, provide examples of logical reasoning (input/output), common user/programming errors, debugging context, and finally, summarize its purpose as the last part of a series.

Here's a breakdown of how to address each point:

1. **Functionality:**  The code is a series of C++ unit tests. Each `TEST_F` function tests a specific aspect of the `HttpServerPropertiesManager`. I'll need to analyze what each test is validating. Keywords like `SetQuicServerInfo`, `GetQuicServerInfo`, `SetAlternativeServices`, `MarkAlternativeServiceBroken`, and the interactions with `NetworkAnonymizationKey` and `PrivacyMode` are crucial. The tests seem to cover saving and loading HTTP server properties, especially related to QUIC and alternative services, and how these are affected by network isolation keys and privacy modes.

2. **Relationship with JavaScript:**  While the C++ code itself doesn't directly interact with JavaScript, the *functionality* it tests has implications for web browsers and, consequently, for JavaScript running in those browsers. The `HttpServerPropertiesManager` stores information that helps the browser optimize network connections. This optimization can affect the performance and security of web pages that JavaScript code interacts with. I'll need to identify specific scenarios where these stored properties influence JavaScript's behavior.

3. **Logical Reasoning (Input/Output):** For some tests, I can create simplified scenarios to demonstrate the logic. For instance, a test setting and retrieving `QuicServerInfo` with a specific `NetworkAnonymizationKey` can be represented with a clear input (setting the info with key X) and expected output (retrieving the same info with key X, and not with a different key).

4. **User/Programming Errors:**  Common errors could involve misconfiguring network settings, incorrectly handling privacy modes, or misunderstanding the impact of network isolation keys. I'll need to think about scenarios where a developer or user's actions might lead to unexpected behavior related to the functionalities tested in this file.

5. **User Operation & Debugging:** I need to explain how a user's actions in a browser can trigger the code being tested. This might involve visiting websites, enabling/disabling privacy features, or encountering network errors that might cause the browser to fall back to different connection methods. For debugging, I'll consider what information or steps a developer might take when investigating issues related to HTTP connections, QUIC, or alternative services.

6. **Overall Functionality (Part 5 of 5):** Given that this is the final part, I need to synthesize the functionalities covered in this specific file and relate them to the broader purpose of the `HttpServerPropertiesManager`. It seems like this part focuses heavily on QUIC server information, alternative services, network anonymization keys, and the persistence of these settings.

**Mental Sandbox Simulation:**

I'll imagine the scenarios in the tests:

* Setting QUIC info with and without network keys, then verifying retrieval.
* Testing how canonical suffixes are used with network keys for QUIC info.
* Checking that info associated with opaque origins isn't saved.
* Round-tripping advertised QUIC versions through preferences.
* Ensuring that the order of stored data is preserved after reloading.
* Verifying that different privacy modes have separate QUIC server info.

By mentally stepping through these tests, I can better understand the underlying logic and the purpose of the code.

Strategizing complete. I will now generate the response based on this analysis.
```c++
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/dns/public/host_port.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_manager_test_util.h"
#include "net/net_test_export.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_server_id.h"
#include "net/socket/socket_test_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using testing::_;

namespace net {

namespace {

const char kServer1[] = "www.example.org:443";
const char kServer2[] = "mail.example.org:443";

const char kQuicServerInfo1[] = "server info 1";
const char kQuicServerInfo2[] = "server info 2";
const char kQuicServerInfo3[] = "server info 3";

}  // namespace

class HttpServerPropertiesManagerTest : public ::testing::TestWithTaskEnvironment {
 public:
  HttpServerPropertiesManagerTest() = default;

  void SetUp() override {
    test_tick_clock_.Advance(base::Seconds(1));
  }

  base::SimpleTestClock* GetMockTickClock() { return &test_tick_clock_; }

 private:
  base::SimpleTestClock test_tick_clock_;
};

TEST_F(HttpServerPropertiesManagerTest, NetworkAnonymizationKeyQuicServerInfo) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  // Only tests with NetworkAnonymizationKeys enabled will set values with
  // non-empty NetworkAnonymizationKeys.
  for (auto load_network_anonymization_key_mode :
       {NetworkAnonymizationKeyMode::kDisabled,
        NetworkAnonymizationKeyMode::kOnly}) {
    base::test::ScopedFeatureList feature_list;
    feature_list.Reset();
    if (load_network_anonymization_key_mode ==
        NetworkAnonymizationKeyMode::kOnly) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }

    // Create and initialize an HttpServerProperties with no state.
    std::unique_ptr<MockPrefDelegate> pref_delegate =
        std::make_unique<MockPrefDelegate>();
    MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
    std::unique_ptr<HttpServerProperties> properties =
        std::make_unique<HttpServerProperties>(std::move(pref_delegate),
                                               /*net_log=*/nullptr,
                                               GetMockTickClock());
    unowned_pref_delegate->InitializePrefs(base::Value::Dict());

    // Set a value with an empty NetworkAnonymizationKey. This should always be
    // loaded.
    properties->SetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                  NetworkAnonymizationKey(), kQuicServerInfo3);
    EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                    kServer1, PRIVACY_MODE_DISABLED,
                                    NetworkAnonymizationKey()));
    EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                               kServer1, PRIVACY_MODE_DISABLED,
                               kNetworkAnonymizationKey1));
    EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                               kServer1, PRIVACY_MODE_DISABLED,
                               kNetworkAnonymizationKey2));

    // Set some values with non-empty NetworkAnonymizationKeys. These should
    // only be loaded if the NetworkAnonymizationKeyLoader is enabled.
    properties->SetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                  kNetworkAnonymizationKey1, kQuicServerInfo1);
    properties->SetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                  kNetworkAnonymizationKey2, kQuicServerInfo2);

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

    // Check that the values are loaded correctly.
    {
      // If NetworkAnonymizationKeys are enabled, then all values should have
      // been loaded successfully.
      if (load_network_anonymization_key_mode !=
          NetworkAnonymizationKeyMode::kDisabled) {
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));
        EXPECT_EQ(kQuicServerInfo1, *properties->GetQuicServerInfo(
                                        kServer2, PRIVACY_MODE_ENABLED,
                                        kNetworkAnonymizationKey1));
        EXPECT_EQ(kQuicServerInfo2, *properties->Get
### 提示词
```
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ver2, PRIVACY_MODE_ENABLED,
                                                 kNetworkAnonymizationKey2));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                NetworkAnonymizationKey()));
      } else {
        // Otherwise, only the value set with an empty NetworkAnonymizationKey
        // should have been loaded successfully.
        EXPECT_EQ(kQuicServerInfo3, *properties->GetQuicServerInfo(
                                        kServer1, PRIVACY_MODE_DISABLED,
                                        NetworkAnonymizationKey()));

        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                kNetworkAnonymizationKey1));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                kNetworkAnonymizationKey2));
        EXPECT_EQ(nullptr,
                  properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_ENABLED,
                                                NetworkAnonymizationKey()));

        // There should be no cross-contamination of NetworkAnonymizationKeys,
        // if NetworkAnonymizationKeys are enabled.
        if (load_network_anonymization_key_mode !=
            NetworkAnonymizationKeyMode::kDisabled) {
          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer1, PRIVACY_MODE_DISABLED,
                                 kNetworkAnonymizationKey1));
          EXPECT_EQ(nullptr, properties->GetQuicServerInfo(
                                 kServer1, PRIVACY_MODE_DISABLED,
                                 kNetworkAnonymizationKey2));
        }
      }
    }
  }
}

// Tests a full round trip to prefs and back in the canonical suffix for
// QuicServerInfo case. Enable NetworkAnonymizationKeys, as they have some
// interactions with the canonical suffix logic.
TEST_F(HttpServerPropertiesManagerTest,
       NetworkAnonymizationKeyQuicServerInfoCanonicalSuffixRoundTrip) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  // Three servers with the same canonical suffix (".c.youtube.com").
  const quic::QuicServerId kServer1("foo.c.youtube.com", 443);
  const quic::QuicServerId kServer2("bar.c.youtube.com", 443);
  const quic::QuicServerId kServer3("baz.c.youtube.com", 443);

  const char kQuicServerInfo1[] = "info1";
  const char kQuicServerInfo2[] = "info2";
  const char kQuicServerInfo3[] = "info3";

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

  // Set kQuicServerInfo1 for kServer1 using kNetworkAnonymizationKey1. That
  // information should be retrieved when fetching information for any server
  // with the same canonical suffix, when using kNetworkAnonymizationKey1.
  properties->SetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey1, kQuicServerInfo1);
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_FALSE(properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                             kNetworkAnonymizationKey2));

  // Set kQuicServerInfo2 for kServer2 using kNetworkAnonymizationKey1. It
  // should not affect information retrieved for kServer1, but should for
  // kServer2 and kServer3.
  properties->SetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey1, kQuicServerInfo2);
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_FALSE(properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                             kNetworkAnonymizationKey2));

  // Set kQuicServerInfo3 for kServer1 using kNetworkAnonymizationKey2. It
  // should not affect information stored for kNetworkAnonymizationKey1.
  properties->SetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey2, kQuicServerInfo3);
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));

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

  // All values should have been saved and be retrievable by suffix-matching
  // servers.
  //
  // TODO(mmenke): The rest of this test corresponds exactly to behavior in
  // CanonicalSuffixRoundTripWithNetworkAnonymizationKey. It seems like these
  // lines should correspond as well.
  EXPECT_EQ(kQuicServerInfo1,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo2,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey1));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer1, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer2, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));
  EXPECT_EQ(kQuicServerInfo3,
            *properties->GetQuicServerInfo(kServer3, PRIVACY_MODE_DISABLED,
                                           kNetworkAnonymizationKey2));
}

// Make sure QuicServerInfo associated with NetworkAnonymizationKeys with opaque
// origins aren't saved.
TEST_F(HttpServerPropertiesManagerTest,
       NetworkAnonymizationKeyQuicServerInfoOpaqueOrigin) {
  const SchemefulSite kOpaqueSite(GURL("data:text/plain,Hello World"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kOpaqueSite);
  const quic::QuicServerId kServer("foo", 443);

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

  properties->SetQuicServerInfo(kServer, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey, "QuicServerInfo");
  EXPECT_TRUE(properties->GetQuicServerInfo(kServer, PRIVACY_MODE_DISABLED,
                                            kNetworkAnonymizationKey));

  // Wait until the data's been written to prefs, and then create a copy of
  // the prefs data.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());

  // No information should have been saved to prefs.
  std::string preferences_json;
  base::JSONWriter::Write(unowned_pref_delegate->GetServerProperties(),
                          &preferences_json);
  EXPECT_EQ("{\"quic_servers\":[],\"servers\":[],\"version\":5}",
            preferences_json);
}

TEST_F(HttpServerPropertiesManagerTest, AdvertisedVersionsRoundTrip) {
  for (const quic::ParsedQuicVersion& version : AllSupportedQuicVersions()) {
    if (version.AlpnDeferToRFCv1()) {
      // These versions currently do not support Alt-Svc.
      continue;
    }
    // Reset test infrastructure.
    TearDown();
    SetUp();
    InitializePrefs();
    // Create alternate version information.
    const url::SchemeHostPort server("https", "quic.example.org", 443);
    AlternativeServiceInfoVector alternative_service_info_vector_in;
    AlternativeService quic_alternative_service(kProtoQUIC, "", 443);
    base::Time expiration;
    ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration));
    quic::ParsedQuicVersionVector advertised_versions = {version};
    alternative_service_info_vector_in.push_back(
        AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
            quic_alternative_service, expiration, advertised_versions));
    http_server_props_->SetAlternativeServices(
        server, NetworkAnonymizationKey(), alternative_service_info_vector_in);
    // Save to JSON.
    EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
    EXPECT_NE(0u, GetPendingMainThreadTaskCount());
    FastForwardUntilNoTasksRemain();
    EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
    const base::Value::Dict& http_server_properties =
        pref_delegate_->GetServerProperties();
    std::string preferences_json;
    EXPECT_TRUE(
        base::JSONWriter::Write(http_server_properties, &preferences_json));
    // Reset test infrastructure.
    TearDown();
    SetUp();
    InitializePrefs();
    // Read from JSON.
    base::Value::Dict preferences_dict =
        base::test::ParseJsonDict(preferences_json);
    ASSERT_FALSE(preferences_dict.empty());
    const base::Value::List* servers_list =
        preferences_dict.FindList("servers");
    ASSERT_TRUE(servers_list);
    ASSERT_EQ(servers_list->size(), 1u);
    const base::Value& server_dict = (*servers_list)[0];
    HttpServerProperties::ServerInfo server_info;
    EXPECT_TRUE(HttpServerPropertiesManager::ParseAlternativeServiceInfo(
        server, server_dict.GetDict(), &server_info));
    ASSERT_TRUE(server_info.alternative_services.has_value());
    AlternativeServiceInfoVector alternative_service_info_vector_out =
        server_info.alternative_services.value();
    ASSERT_EQ(1u, alternative_service_info_vector_out.size());
    EXPECT_EQ(
        kProtoQUIC,
        alternative_service_info_vector_out[0].alternative_service().protocol);
    // Ensure we correctly parsed the version.
    EXPECT_EQ(advertised_versions,
              alternative_service_info_vector_out[0].advertised_versions());
  }
}

TEST_F(HttpServerPropertiesManagerTest, SameOrderAfterReload) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

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

  // Set alternative_service info.
  base::Time expiration = base::Time::Now() + base::Days(1);
  AlternativeServiceInfo alt_service1 =
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          AlternativeService(kProtoQUIC, "1.example", 1234), expiration,
          DefaultSupportedQuicVersions());
  AlternativeServiceInfo alt_service2 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "2.example", 443), expiration);
  AlternativeServiceInfo alt_service3 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "3.example", 443), expiration);
  const url::SchemeHostPort kServer1("https", "1.example", 443);
  const url::SchemeHostPort kServer2("https", "2.example", 443);
  const url::SchemeHostPort kServer3("https", "3.example", 443);
  properties->SetAlternativeServices(kServer1, kNetworkAnonymizationKey1,
                                     {alt_service1});
  properties->SetAlternativeServices(kServer2, kNetworkAnonymizationKey1,
                                     {alt_service2});
  properties->SetAlternativeServices(kServer3, kNetworkAnonymizationKey2,
                                     {alt_service3});

  // Set quic_server_info.
  quic::QuicServerId quic_server_id1("quic1.example", 80);
  quic::QuicServerId quic_server_id2("quic2.example", 80);
  quic::QuicServerId quic_server_id3("quic3.example", 80);
  properties->SetQuicServerInfo(quic_server_id1, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey1, "quic_server_info1");
  properties->SetQuicServerInfo(quic_server_id2, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey1, "quic_server_info2");
  properties->SetQuicServerInfo(quic_server_id3, PRIVACY_MODE_DISABLED,
                                kNetworkAnonymizationKey2, "quic_server_info3");

  // Set broken_alternative_service info.
  AlternativeService broken_service1(kProtoQUIC, "broken1.example", 443);
  AlternativeService broken_service2(kProtoQUIC, "broken2.example", 443);
  AlternativeService broken_service3(kProtoQUIC, "broken3.example", 443);
  properties->MarkAlternativeServiceBroken(broken_service1,
                                           kNetworkAnonymizationKey1);
  FastForwardBy(base::Milliseconds(1));
  properties->MarkAlternativeServiceBroken(broken_service2,
                                           kNetworkAnonymizationKey1);
  FastForwardBy(base::Milliseconds(1));
  properties->MarkAlternativeServiceBroken(broken_service3,
                                           kNetworkAnonymizationKey2);

  // The first item of `server_info_map` must be the latest item.
  EXPECT_EQ(3u, properties->server_info_map_for_testing().size());
  EXPECT_EQ(
      properties->server_info_map_for_testing().begin()->first.server.host(),
      "3.example");

  // The first item of `recently_broken_alternative_services` must be the latest
  // item.
  EXPECT_EQ(3u, properties->broken_alternative_services_for_testing()
                    .recently_broken_alternative_services()
                    .size());
  EXPECT_EQ("broken3.example",
            properties->broken_alternative_services_for_testing()
                .recently_broken_alternative_services()
                .begin()
                ->first.alternative_service.host);

  // The first item of `quic_server_info_map` must be the latest item.
  EXPECT_EQ(3u, properties->quic_server_info_map_for_testing().size());
  EXPECT_EQ("quic3.example", properties->quic_server_info_map_for_testing()
                                 .begin()
                                 ->first.server_id.host());

  // The first item of `broken_alternative_service_list` must be the oldest
  // item.
  EXPECT_EQ(3u, properties->broken_alternative_services_for_testing()
                    .broken_alternative_service_list()
                    .size());
  EXPECT_EQ("broken1.example",
            properties->broken_alternative_services_for_testing()
                .broken_alternative_service_list()
                .begin()
                ->first.alternative_service.host);

  // Wait until the data's been written to prefs, and then tear down the
  // HttpServerProperties.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting());
  base::Value::Dict saved_value =
      unowned_pref_delegate->GetServerProperties().Clone();

  // Create a new HttpServerProperties using the value saved to prefs above.
  pref_delegate = std::make_unique<MockPrefDelegate>();
  unowned_pref_delegate = pref_delegate.get();
  properties = std::make_unique<HttpServerProperties>(
      std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());
  unowned_pref_delegate->InitializePrefs(std::move(saved_value));

  // The first item of `server_info_map` must be the latest item.
  EXPECT_EQ(3u, properties->server_info_map_for_testing().size());
  EXPECT_EQ(
      properties->server_info_map_for_testing().begin()->first.server.host(),
      "3.example");

  // The first item of `recently_broken_alternative_services` must be the latest
  // item.
  EXPECT_EQ(3u, properties->broken_alternative_services_for_testing()
                    .recently_broken_alternative_services()
                    .size());
  EXPECT_EQ("broken3.example",
            properties->broken_alternative_services_for_testing()
                .recently_broken_alternative_services()
                .begin()
                ->first.alternative_service.host);

  // The first item of `quic_server_info_map` must be the latest item.
  EXPECT_EQ(3u, properties->quic_server_info_map_for_testing().size());
  EXPECT_EQ("quic3.example", properties->quic_server_info_map_for_testing()
                                 .begin()
                                 ->first.server_id.host());

  // The first item of `broken_alternative_service_list` must be the oldest
  // item.
  EXPECT_EQ(3u, properties->broken_alternative_services_for_testing()
                    .broken_alternative_service_list()
                    .size());
  EXPECT_EQ("broken1.example",
            properties->broken_alternative_services_for_testing()
                .broken_alternative_service_list()
                .begin()
                ->first.alternative_service.host);
}

// Test that different privacy modes have different QUIC server info.
TEST_F(HttpServerPropertiesManagerTest, PrivacyMode) {
  const quic::QuicServerId kQuicServerId("quic.example", 443);
  constexpr char kQuicServerInfo[] = "info";

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

  properties->SetQuicServerInfo(kQuicServerId, PRIVACY_MODE_DISABLED,
                                NetworkAnonymizationKey(), kQuicServerInfo);
  properties->SetQuicServerInfo(kQuicServerId, PRIVACY_MODE_ENABLED,
                                NetworkAnonymizationKey(), kQuicServerInfo);
  properties->SetQuicServerInfo(kQuicServerId,
                                PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS,
                                NetworkAnonymizationKey(), kQuicServerInfo);
  properties->SetQuicServerInfo(kQuicServerId,
                                PRIVACY_MODE_ENABLED_PARTITIONED_STATE_ALLOWED,
                                NetworkAnonymizationKey(), kQuicServerInfo);
  EXPECT_EQ(4u, properties->quic_server_info_map_for_testing().size());

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

  // All values should have been saved and be retrievable.
  EXPECT_EQ(kQuicServerInfo,
            *properties->GetQuicServerInfo(kQuicServerId, PRIVACY_MODE_DISABLED,
                                           NetworkAnonymizationKey()));
  EXPECT_EQ(kQuicServerInfo,
            *properties->GetQuicServerInfo(kQuicServerId, PRIVACY_MODE_ENABLED,
                                           NetworkAnonymizationKey()));
  EXPECT_EQ(kQuicServerInfo,
            *properties->GetQuicServerInfo(
                kQuicServerId, PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS,
                NetworkAnonymizationKey()));
  EXPECT_EQ(kQuicServerInfo,
            *properties->GetQuicServerInfo(
                kQuicServerId, PRIVACY_MODE_ENABLED_PARTITIONED_STATE_ALLOWED,
                NetworkAnonymizationKey()));
}

}  // namespace net
```