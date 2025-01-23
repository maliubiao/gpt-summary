Response:
My thinking process to analyze the given C++ code and answer the user's request goes like this:

1. **Understand the Core Purpose:** The filename `http_server_properties_manager_unittest.cc` immediately tells me this is a *unit test* file. Unit tests verify the functionality of a specific unit of code in isolation. The "unit" being tested here is likely the `HttpServerPropertiesManager` class.

2. **Identify Key Classes and Concepts:**  I scan the `#include` directives and the code itself to identify the main classes and concepts involved:
    * `HttpServerPropertiesManager`: This is the class being tested. It likely manages the storage and retrieval of HTTP server-related properties.
    * `HttpServerProperties`: This class likely holds the actual server properties data.
    * `MockPrefDelegate`:  The "Mock" prefix indicates this is a test double. It simulates the interaction with a persistent storage mechanism (likely user preferences or a disk file).
    * `AlternativeService`, `AlternativeServiceInfo`:  These seem related to HTTP/2 and QUIC, allowing a server to advertise alternative ways to connect.
    * `NetworkAnonymizationKey`: This relates to network isolation, a security feature.
    * `Quic...`:  References to QUIC indicate this protocol is relevant.
    * `base::Value::Dict`:  This suggests the properties are stored in a dictionary-like structure, probably serialized to JSON.
    * `GURL`, `SchemeHostPort`, `HostPortPair`: These are URL and network address components.

3. **Analyze the Test Structure:** I look at the `TEST_F` macros. Each `TEST_F` function tests a specific aspect of the `HttpServerPropertiesManager`. I try to group related tests. For example, several tests focus on `SupportsSpdy`, `AlternativeService`, and how the manager interacts with the `MockPrefDelegate`.

4. **Infer Functionality from Test Names and Code:**  I read the names of the test cases (e.g., `BadCachedHostPortPair`, `SupportsSpdy`, `GetAlternativeServiceInfos`) and examine the code within each test. This helps me deduce the functionality being tested. For example:
    * `BadCachedHostPortPair`: Tests how the manager handles invalid port numbers.
    * `SupportsSpdy`: Verifies the ability to store and retrieve whether a server supports SPDY.
    * `GetAlternativeServiceInfos`: Checks how alternative service information is stored and retrieved.
    * Tests involving `MarkAlternativeServiceBroken` and `ConfirmAlternativeService` indicate the manager tracks broken alternative connections.

5. **Look for Interactions with External Systems:** The `MockPrefDelegate` is crucial. It shows how the `HttpServerPropertiesManager` interacts with persistent storage. The tests verify that updates to server properties are eventually written to the `MockPrefDelegate`.

6. **Consider Edge Cases and Error Handling:** Tests like `BadCachedHostPortPair` explicitly test how the manager handles invalid data.

7. **Address Specific User Questions:**

    * **Functionality Listing:** I summarize the inferred functionality based on the test analysis.
    * **JavaScript Relationship:** I consider how the tested functionality might impact web pages and JavaScript. For example, knowing if a server supports SPDY or has alternative services can affect the performance and security of network requests initiated by JavaScript. I look for concrete examples of how JavaScript might use this information (e.g., `fetch()` API potentially benefiting from HTTP/2 or QUIC).
    * **Logical Reasoning (Assumptions and Outputs):**  I select a test case (e.g., `SupportsSpdy`) and describe a simple scenario with an input (setting SPDY support for a host) and the expected output (the manager reporting SPDY support).
    * **User/Programming Errors:** I think about common mistakes developers might make when interacting with similar systems, like using incorrect port numbers or expecting immediate persistence of data.
    * **User Operation and Debugging:** I try to trace back user actions that could lead to the code being executed, focusing on browser actions like visiting websites. I also consider how the tests themselves can serve as debugging information (e.g., looking at pref values).

8. **Synthesize and Summarize:**  Finally, I combine all the information gathered to create a concise summary of the file's purpose, focusing on its role as a unit test suite for the `HttpServerPropertiesManager`.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on individual test cases. I then step back and try to identify the broader themes and functionalities being tested.
* If I'm unsure about the exact meaning of a class or method, I look for comments or related code within the file. If that's insufficient, I'd consider searching for the class name in the Chromium codebase.
* I constantly ask myself: "What is the purpose of this test?" and "What functionality is it verifying?" This helps me stay focused on the core purpose of the file.
* I make sure my explanations are clear and accessible to someone who might not be deeply familiar with the Chromium networking stack.

By following these steps, I can effectively analyze the C++ unit test file and provide a comprehensive answer to the user's request.
```c++
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/values_test_util.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/privacy_mode.h"
#include "net/base/schemeful_site.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/quic/quic_context.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using base::StringPrintf;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::StrictMock;

enum class NetworkAnonymizationKeyMode {
  kDisabled,
  kEnabled,
};

const NetworkAnonymizationKeyMode kNetworkAnonymizationKeyModes[] = {
    NetworkAnonymizationKeyMode::kDisabled,
    NetworkAnonymizationKeyMode::kEnabled,
};

std::unique_ptr<base::test::ScopedFeatureList> SetNetworkAnonymizationKeyMode(
    NetworkAnonymizationKeyMode mode) {
  auto feature_list = std::make_unique<base::test::ScopedFeatureList>();
  switch (mode) {
    case NetworkAnonymizationKeyMode::kDisabled:
      feature_list->InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
      break;
    case NetworkAnonymizationKeyMode::kEnabled:
      feature_list->InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
      break;
  }
  return feature_list;
}

class MockPrefDelegate : public HttpServerProperties::PrefDelegate {
 public:
  MockPrefDelegate() = default;

  MockPrefDelegate(const MockPrefDelegate&) = delete;
  MockPrefDelegate& operator=(const MockPrefDelegate&) = delete;

  ~MockPrefDelegate() override = default;

  // HttpServerProperties::PrefDelegate implementation.
  const base::Value::Dict& GetServerProperties() const override {
    return prefs_;
  }

  void SetServerProperties(base::Value::Dict dict,
                           base::OnceClosure callback) override {
    prefs_.clear();
    prefs_.Merge(std::move(dict));
    ++num_pref_updates_;
    if (!prefs_changed_callback_.is_null())
      std::move(prefs_changed_callback_).Run();
    if (!extra_prefs_changed_callback_.is_null())
      std::move(extra_prefs_changed_callback_).Run();
    set_properties_callback_ = std::move(callback);
  }

  void WaitForPrefLoad(base::OnceClosure callback) override {
    CHECK(prefs_changed_callback_.is_null());
    prefs_changed_callback_ = std::move(callback);
  }

  void InitializePrefs(base::Value::Dict dict) {
    ASSERT_FALSE(prefs_changed_callback_.is_null());
    prefs_ = std::move(dict);
    std::move(prefs_changed_callback_).Run();
  }

  int GetAndClearNumPrefUpdates() {
    int out = num_pref_updates_;
    num_pref_updates_ = 0;
    return out;
  }

  // Additional callback to call when prefs are updated, used to check prefs are
  // updated on destruction.
  void set_extra_update_prefs_callback(base::OnceClosure callback) {
    extra_prefs_changed_callback_ = std::move(callback);
  }

  // Returns the base::OnceCallback, if any, passed to the last call to
  // SetServerProperties().
  base::OnceClosure GetSetPropertiesCallback() {
    return std::move(set_properties_callback_);
  }

 private:
  base::Value::Dict prefs_;
  base::OnceClosure prefs_changed_callback_;
  base::OnceClosure extra_prefs_changed_callback_;
  int num_pref_updates_ = 0;

  base::OnceClosure set_properties_callback_;
};

// Converts |server_info_map| to a base::Value::Dict by running it through an
// HttpServerPropertiesManager. Other fields are left empty.
base::Value::Dict ServerInfoMapToDict(
    const HttpServerProperties::ServerInfoMap& server_info_map) {
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  // Callback that shouldn't be invoked - this method short-circuits loading
  // prefs by calling HttpServerPropertiesManager::WriteToPrefs() before prefs
  // are loaded.
  HttpServerPropertiesManager::OnPrefsLoadedCallback on_prefs_loaded_callback =
      base::BindOnce(
          [](std::unique_ptr<HttpServerProperties::ServerInfoMap>
                 server_info_map,
             const IPAddress& last_quic_address,
             std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
                 quic_server_info_map,
             std::unique_ptr<BrokenAlternativeServiceList>
                 broken_alternative_service_list,
             std::unique_ptr<RecentlyBrokenAlternativeServices>
                 recently_broken_alternative_services) { ADD_FAILURE(); });
  HttpServerPropertiesManager manager(
      std::move(pref_delegate), std::move(on_prefs_loaded_callback),
      10 /* max_server_configs_stored_in_properties */, nullptr /* net_log */,
      base::DefaultTickClock::GetInstance());
  manager.WriteToPrefs(
      server_info_map, HttpServerPropertiesManager::GetCannonicalSuffix(),
      IPAddress() /* last_quic_address */,
      HttpServerProperties::QuicServerInfoMap(10),
      BrokenAlternativeServiceList(), RecentlyBrokenAlternativeServices(10),
      base::OnceClosure());

  return unowned_pref_delegate->GetServerProperties().Clone();
}

// Does the inverse of ServerInfoMapToDict(). Ignores fields other than the
// ServerInfoMap.
std::unique_ptr<HttpServerProperties::ServerInfoMap> DictToServerInfoMap(
    base::Value::Dict dict) {
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();

  std::unique_ptr<HttpServerProperties::ServerInfoMap> out;
  bool callback_invoked = false;
  HttpServerPropertiesManager::OnPrefsLoadedCallback on_prefs_loaded_callback =
      base::BindLambdaForTesting(
          [&](std::unique_ptr<HttpServerProperties::ServerInfoMap>
                  server_info_map,
              const IPAddress& last_quic_address,
              std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
                  quic_server_info_map,
              std::unique_ptr<BrokenAlternativeServiceList>
                  broken_alternative_service_list,
              std::unique_ptr<RecentlyBrokenAlternativeServices>
                  recently_broken_alternative_services) {
            ASSERT_FALSE(callback_invoked);
            callback_invoked = true;
            out = std::move(server_info_map);
          });

  HttpServerPropertiesManager manager(
      std::move(pref_delegate), std::move(on_prefs_loaded_callback),
      10 /* max_server_configs_stored_in_properties */, nullptr /* net_log */,
      base::DefaultTickClock::GetInstance());

  unowned_pref_delegate->InitializePrefs(std::move(dict));
  EXPECT_TRUE(callback_invoked);
  return out;
}

}  // namespace

class HttpServerPropertiesManagerTest : public testing::Test,
                                        public WithTaskEnvironment {
 public:
  HttpServerPropertiesManagerTest(const HttpServerPropertiesManagerTest&) =
      delete;
  HttpServerPropertiesManagerTest& operator=(
      const HttpServerPropertiesManagerTest&) = delete;

 protected:
  HttpServerPropertiesManagerTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    one_day_from_now_ = base::Time::Now() + base::Days(1);
    advertised_versions_ = DefaultSupportedQuicVersions();
    auto pref_delegate = std::make_unique<MockPrefDelegate>();
    pref_delegate_ = pref_delegate.get();

    http_server_props_ = std::make_unique<HttpServerProperties>(
        std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());

    EXPECT_FALSE(http_server_props_->IsInitialized());
    EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
    EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  }

  // Wrapper around |pref_delegate_|'s InitializePrefs() method that has a
  // couple extra expectations about whether any tasks are posted, and if a pref
  // update is queued.
  //
  // |expect_pref_update| should be true if a pref update is expected to be
  // queued in response to the load.
  void InitializePrefs(base::Value::Dict dict = base::Value::Dict(),
                       bool expect_pref_update = false) {
    EXPECT_FALSE(http_server_props_->IsInitialized());
    pref_delegate_->InitializePrefs(std::move(dict));
    EXPECT_TRUE(http_server_props_->IsInitialized());
    if (!expect_pref_update) {
      EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
      EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
    } else {
      EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
      EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
      FastForwardUntilNoTasksRemain();
      EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
    }
  }

  void TearDown() override {
    // Run pending non-delayed tasks but don't FastForwardUntilNoTasksRemain()
    // as some delayed tasks may forever repost (e.g. because impl doesn't use a
    // mock clock and doesn't see timings as having expired, ref.
    // HttpServerProperties::
    //     ScheduleBrokenAlternateProtocolMappingsExpiration()).
    base::RunLoop().RunUntilIdle();
    http_server_props_.reset();
  }

  bool HasAlternativeService(
      const url::SchemeHostPort& server,
      const NetworkAnonymizationKey& network_anonymization_key) {
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_props_->GetAlternativeServiceInfos(
            server, network_anonymization_key);
    return !alternative_service_info_vector.empty();
  }

  // Returns a dictionary with only the version field populated.
  static base::Value::Dict DictWithVersion() {
    base::Value::Dict http_server_properties_dict;
    http_server_properties_dict.Set("version", 5);
    return http_server_properties_dict;
  }

  raw_ptr<MockPrefDelegate, DanglingUntriaged>
      pref_delegate_;  // Owned by HttpServerPropertiesManager.
  std::unique_ptr<HttpServerProperties> http_server_props_;
  base::Time one_day_from_now_;
  quic::ParsedQuicVersionVector advertised_versions_;
};

TEST_F(HttpServerPropertiesManagerTest, BadCachedHostPortPair) {
  base::Value::Dict server_pref_dict;

  // Set supports_spdy for www.google.com:65536.
  server_pref_dict.Set("supports_spdy", true);

  // Set up alternative_service for www.google.com:65536.
  base::Value::Dict alternative_service_dict;
  alternative_service_dict.Set("protocol_str", "h2");
  alternative_service_dict.Set("port", 80);
  base::Value::List alternative_service_list;
  alternative_service_list.Append(std::move(alternative_service_dict));
  server_pref_dict.Set("alternative_service",
                       std::move(alternative_service_list));

  // Set up ServerNetworkStats for www.google.com:65536.
  base::Value::Dict stats;
  stats.Set("srtt", 10);
  server_pref_dict.Set("network_stats", std::move(stats));

  // Set the server preference for www.google.com:65536.
  base::Value::Dict servers_dict;
  servers_dict.Set("www.google.com:65536", std::move(server_pref_dict));
  base::Value::List servers_list;
  servers_list.Append(std::move(servers_dict));
  base::Value::Dict http_server_properties_dict = DictWithVersion();
  http_server_properties_dict.Set("servers", std::move(servers_list));

  // Set quic_server_info for www.google.com:65536.
  base::Value::Dict quic_servers_dict;
  base::Value::Dict quic_server_pref_dict1;
  quic_server_pref_dict1.Set("server_info", "quic_server_info1");
  quic_servers_dict.Set("http://mail.google.com:65536",
                        std::move(quic_server_pref_dict1));

  http_server_properties_dict.Set("quic_servers", std::move(quic_servers_dict));

  // Set up the pref.
  InitializePrefs(std::move(http_server_properties_dict));

  // Verify that nothing is set.
  HostPortPair google_host_port_pair =
      HostPortPair::FromString("www.google.com:65536");
  url::SchemeHostPort gooler_server("http", google_host_port_pair.host(),
                                    google_host_port_pair.port());

  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      gooler_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(HasAlternativeService(gooler_server, NetworkAnonymizationKey()));
  const ServerNetworkStats* stats1 = http_server_props_->GetServerNetworkStats(
      gooler_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, stats1);
  EXPECT_EQ(0u, http_server_props_->quic_server_info_map().size());
}

TEST_F(HttpServerPropertiesManagerTest, BadCachedAltProtocolPort) {
  base::Value::Dict server_pref_dict;

  // Set supports_spdy for www.google.com:80.
  server_pref_dict.Set("supports_spdy", true);

  // Set up alternative_service for www.google.com:80.
  base::Value::Dict alternative_service_dict;
  alternative_service_dict.Set("protocol_str", "h2");
  alternative_service_dict.Set("port", 65536);
  base::Value::List alternative_service_list;
  alternative_service_list.Append(std::move(alternative_service_dict));
  server_pref_dict.Set("alternative_service",
                       std::move(alternative_service_list));

  // Set the server preference for www.google.com:80.
  base::Value::Dict servers_dict;
  servers_dict.Set("www.google.com:80", std::move(server_pref_dict));
  base::Value::List servers_list;
  servers_list.Append(std::move(servers_dict));
  base::Value::Dict http_server_properties_dict = DictWithVersion();
  http_server_properties_dict.Set("servers", std::move(servers_list));

  // Set up the pref.
  InitializePrefs(std::move(http_server_properties_dict));

  // Verify alternative service is not set.
  EXPECT_FALSE(
      HasAlternativeService(url::SchemeHostPort("http", "www.google.com", 80),
                            NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, SupportsSpdy) {
  InitializePrefs();

  // Add mail.google.com:443 as a supporting spdy server.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  // Setting the value to the same thing again should not trigger another pref
  // update.
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Setting the value to the same thing again should not trigger another pref
  // update.
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
}

// Regression test for crbug.com/670519. Test that there is only one pref update
// scheduled if multiple updates happen in a given time period. Subsequent pref
// update could also be scheduled once the previous scheduled update is
// completed.
TEST_F(HttpServerPropertiesManagerTest,
       SinglePrefUpdateForTwoSpdyServerCacheChanges) {
  InitializePrefs();

  // Post an update task. SetSupportsSpdy calls ScheduleUpdatePrefs with a delay
  // of 60ms.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  // The pref update task should be scheduled.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Move forward the task runner short by 20ms.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting() -
                base::Milliseconds(20));

  // Set another spdy server to trigger another call to
  // ScheduleUpdatePrefs. There should be no new update posted.
  url::SchemeHostPort spdy_server2("https", "drive.google.com", 443);
  http_server_props_->SetSupportsSpdy(spdy_server2, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Move forward the extra 20ms. The pref update should be executed.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardBy(base::Milliseconds(20));
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server2, NetworkAnonymizationKey()));
  // Set the third spdy server to trigger one more call to
  // ScheduleUpdatePrefs. A new update task should be posted now since the
  // previous one is completed.
  url::SchemeHostPort spdy_server3("https", "maps.google.com", 443);
  http_server_props_->SetSupportsSpdy(spdy_server3, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
}

TEST_F(HttpServerPropertiesManagerTest, GetAlternativeServiceInfos) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);
  // ExpectScheduleUpdatePrefs() should be called only once.
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

TEST_F(HttpServerPropertiesManagerTest, SetAlternativeServices) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "mail.google.com",
                                                443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, one_day_from_now_));
  const AlternativeService alternative_service2(kProtoQUIC, "mail.google.com",
                                                1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, one_day_from_now_, advertised_versions_));
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             alternative_service_info_vector);
  // ExpectScheduleUpdatePrefs() should be called only once.
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             alternative_service_info_vector);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector2 =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector2[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[1].alternative_service());
}

TEST_F(HttpServerPropertiesManagerTest, SetAlternativeServicesEmpty) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             AlternativeServiceInfoVector());

  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, ConfirmAlternativeService) {
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

  http_server_props_->ConfirmAlternativeService(alternative_service,
                                                NetworkAnonymizationKey());
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

// Check the case that prefs are loaded only after setting alternative service
// info. Prefs should not be written until after the load happens.
TEST_F(HttpServerPropertiesManagerTest, LateLoadAlternativeServiceInfo) {
  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonym
### 提示词
```
这是目录为net/http/http_server_properties_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/values_test_util.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/privacy_mode.h"
#include "net/base/schemeful_site.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/quic/quic_context.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using base::StringPrintf;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::StrictMock;

enum class NetworkAnonymizationKeyMode {
  kDisabled,
  kEnabled,
};

const NetworkAnonymizationKeyMode kNetworkAnonymizationKeyModes[] = {
    NetworkAnonymizationKeyMode::kDisabled,
    NetworkAnonymizationKeyMode::kEnabled,
};

std::unique_ptr<base::test::ScopedFeatureList> SetNetworkAnonymizationKeyMode(
    NetworkAnonymizationKeyMode mode) {
  auto feature_list = std::make_unique<base::test::ScopedFeatureList>();
  switch (mode) {
    case NetworkAnonymizationKeyMode::kDisabled:
      feature_list->InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
      break;
    case NetworkAnonymizationKeyMode::kEnabled:
      feature_list->InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
      break;
  }
  return feature_list;
}

class MockPrefDelegate : public HttpServerProperties::PrefDelegate {
 public:
  MockPrefDelegate() = default;

  MockPrefDelegate(const MockPrefDelegate&) = delete;
  MockPrefDelegate& operator=(const MockPrefDelegate&) = delete;

  ~MockPrefDelegate() override = default;

  // HttpServerProperties::PrefDelegate implementation.
  const base::Value::Dict& GetServerProperties() const override {
    return prefs_;
  }

  void SetServerProperties(base::Value::Dict dict,
                           base::OnceClosure callback) override {
    prefs_.clear();
    prefs_.Merge(std::move(dict));
    ++num_pref_updates_;
    if (!prefs_changed_callback_.is_null())
      std::move(prefs_changed_callback_).Run();
    if (!extra_prefs_changed_callback_.is_null())
      std::move(extra_prefs_changed_callback_).Run();
    set_properties_callback_ = std::move(callback);
  }

  void WaitForPrefLoad(base::OnceClosure callback) override {
    CHECK(prefs_changed_callback_.is_null());
    prefs_changed_callback_ = std::move(callback);
  }

  void InitializePrefs(base::Value::Dict dict) {
    ASSERT_FALSE(prefs_changed_callback_.is_null());
    prefs_ = std::move(dict);
    std::move(prefs_changed_callback_).Run();
  }

  int GetAndClearNumPrefUpdates() {
    int out = num_pref_updates_;
    num_pref_updates_ = 0;
    return out;
  }

  // Additional callback to call when prefs are updated, used to check prefs are
  // updated on destruction.
  void set_extra_update_prefs_callback(base::OnceClosure callback) {
    extra_prefs_changed_callback_ = std::move(callback);
  }

  // Returns the base::OnceCallback, if any, passed to the last call to
  // SetServerProperties().
  base::OnceClosure GetSetPropertiesCallback() {
    return std::move(set_properties_callback_);
  }

 private:
  base::Value::Dict prefs_;
  base::OnceClosure prefs_changed_callback_;
  base::OnceClosure extra_prefs_changed_callback_;
  int num_pref_updates_ = 0;

  base::OnceClosure set_properties_callback_;
};

// Converts |server_info_map| to a base::Value::Dict by running it through an
// HttpServerPropertiesManager. Other fields are left empty.
base::Value::Dict ServerInfoMapToDict(
    const HttpServerProperties::ServerInfoMap& server_info_map) {
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();
  // Callback that shouldn't be invoked - this method short-circuits loading
  // prefs by calling HttpServerPropertiesManager::WriteToPrefs() before prefs
  // are loaded.
  HttpServerPropertiesManager::OnPrefsLoadedCallback on_prefs_loaded_callback =
      base::BindOnce(
          [](std::unique_ptr<HttpServerProperties::ServerInfoMap>
                 server_info_map,
             const IPAddress& last_quic_address,
             std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
                 quic_server_info_map,
             std::unique_ptr<BrokenAlternativeServiceList>
                 broken_alternative_service_list,
             std::unique_ptr<RecentlyBrokenAlternativeServices>
                 recently_broken_alternative_services) { ADD_FAILURE(); });
  HttpServerPropertiesManager manager(
      std::move(pref_delegate), std::move(on_prefs_loaded_callback),
      10 /* max_server_configs_stored_in_properties */, nullptr /* net_log */,
      base::DefaultTickClock::GetInstance());
  manager.WriteToPrefs(
      server_info_map, HttpServerPropertiesManager::GetCannonicalSuffix(),
      IPAddress() /* last_quic_address */,
      HttpServerProperties::QuicServerInfoMap(10),
      BrokenAlternativeServiceList(), RecentlyBrokenAlternativeServices(10),
      base::OnceClosure());

  return unowned_pref_delegate->GetServerProperties().Clone();
}

// Does the inverse of ServerInfoMapToDict(). Ignores fields other than the
// ServerInfoMap.
std::unique_ptr<HttpServerProperties::ServerInfoMap> DictToServerInfoMap(
    base::Value::Dict dict) {
  std::unique_ptr<MockPrefDelegate> pref_delegate =
      std::make_unique<MockPrefDelegate>();
  MockPrefDelegate* unowned_pref_delegate = pref_delegate.get();

  std::unique_ptr<HttpServerProperties::ServerInfoMap> out;
  bool callback_invoked = false;
  HttpServerPropertiesManager::OnPrefsLoadedCallback on_prefs_loaded_callback =
      base::BindLambdaForTesting(
          [&](std::unique_ptr<HttpServerProperties::ServerInfoMap>
                  server_info_map,
              const IPAddress& last_quic_address,
              std::unique_ptr<HttpServerProperties::QuicServerInfoMap>
                  quic_server_info_map,
              std::unique_ptr<BrokenAlternativeServiceList>
                  broken_alternative_service_list,
              std::unique_ptr<RecentlyBrokenAlternativeServices>
                  recently_broken_alternative_services) {
            ASSERT_FALSE(callback_invoked);
            callback_invoked = true;
            out = std::move(server_info_map);
          });

  HttpServerPropertiesManager manager(
      std::move(pref_delegate), std::move(on_prefs_loaded_callback),
      10 /* max_server_configs_stored_in_properties */, nullptr /* net_log */,
      base::DefaultTickClock::GetInstance());

  unowned_pref_delegate->InitializePrefs(std::move(dict));
  EXPECT_TRUE(callback_invoked);
  return out;
}

}  // namespace

class HttpServerPropertiesManagerTest : public testing::Test,
                                        public WithTaskEnvironment {
 public:
  HttpServerPropertiesManagerTest(const HttpServerPropertiesManagerTest&) =
      delete;
  HttpServerPropertiesManagerTest& operator=(
      const HttpServerPropertiesManagerTest&) = delete;

 protected:
  HttpServerPropertiesManagerTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    one_day_from_now_ = base::Time::Now() + base::Days(1);
    advertised_versions_ = DefaultSupportedQuicVersions();
    auto pref_delegate = std::make_unique<MockPrefDelegate>();
    pref_delegate_ = pref_delegate.get();

    http_server_props_ = std::make_unique<HttpServerProperties>(
        std::move(pref_delegate), /*net_log=*/nullptr, GetMockTickClock());

    EXPECT_FALSE(http_server_props_->IsInitialized());
    EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
    EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  }

  // Wrapper around |pref_delegate_|'s InitializePrefs() method that has a
  // couple extra expectations about whether any tasks are posted, and if a pref
  // update is queued.
  //
  // |expect_pref_update| should be true if a pref update is expected to be
  // queued in response to the load.
  void InitializePrefs(base::Value::Dict dict = base::Value::Dict(),
                       bool expect_pref_update = false) {
    EXPECT_FALSE(http_server_props_->IsInitialized());
    pref_delegate_->InitializePrefs(std::move(dict));
    EXPECT_TRUE(http_server_props_->IsInitialized());
    if (!expect_pref_update) {
      EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
      EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
    } else {
      EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
      EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
      FastForwardUntilNoTasksRemain();
      EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
    }
  }

  void TearDown() override {
    // Run pending non-delayed tasks but don't FastForwardUntilNoTasksRemain()
    // as some delayed tasks may forever repost (e.g. because impl doesn't use a
    // mock clock and doesn't see timings as having expired, ref.
    // HttpServerProperties::
    //     ScheduleBrokenAlternateProtocolMappingsExpiration()).
    base::RunLoop().RunUntilIdle();
    http_server_props_.reset();
  }

  bool HasAlternativeService(
      const url::SchemeHostPort& server,
      const NetworkAnonymizationKey& network_anonymization_key) {
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_props_->GetAlternativeServiceInfos(
            server, network_anonymization_key);
    return !alternative_service_info_vector.empty();
  }

  // Returns a dictionary with only the version field populated.
  static base::Value::Dict DictWithVersion() {
    base::Value::Dict http_server_properties_dict;
    http_server_properties_dict.Set("version", 5);
    return http_server_properties_dict;
  }

  raw_ptr<MockPrefDelegate, DanglingUntriaged>
      pref_delegate_;  // Owned by HttpServerPropertiesManager.
  std::unique_ptr<HttpServerProperties> http_server_props_;
  base::Time one_day_from_now_;
  quic::ParsedQuicVersionVector advertised_versions_;
};

TEST_F(HttpServerPropertiesManagerTest, BadCachedHostPortPair) {
  base::Value::Dict server_pref_dict;

  // Set supports_spdy for www.google.com:65536.
  server_pref_dict.Set("supports_spdy", true);

  // Set up alternative_service for www.google.com:65536.
  base::Value::Dict alternative_service_dict;
  alternative_service_dict.Set("protocol_str", "h2");
  alternative_service_dict.Set("port", 80);
  base::Value::List alternative_service_list;
  alternative_service_list.Append(std::move(alternative_service_dict));
  server_pref_dict.Set("alternative_service",
                       std::move(alternative_service_list));

  // Set up ServerNetworkStats for www.google.com:65536.
  base::Value::Dict stats;
  stats.Set("srtt", 10);
  server_pref_dict.Set("network_stats", std::move(stats));

  // Set the server preference for www.google.com:65536.
  base::Value::Dict servers_dict;
  servers_dict.Set("www.google.com:65536", std::move(server_pref_dict));
  base::Value::List servers_list;
  servers_list.Append(std::move(servers_dict));
  base::Value::Dict http_server_properties_dict = DictWithVersion();
  http_server_properties_dict.Set("servers", std::move(servers_list));

  // Set quic_server_info for www.google.com:65536.
  base::Value::Dict quic_servers_dict;
  base::Value::Dict quic_server_pref_dict1;
  quic_server_pref_dict1.Set("server_info", "quic_server_info1");
  quic_servers_dict.Set("http://mail.google.com:65536",
                        std::move(quic_server_pref_dict1));

  http_server_properties_dict.Set("quic_servers", std::move(quic_servers_dict));

  // Set up the pref.
  InitializePrefs(std::move(http_server_properties_dict));

  // Verify that nothing is set.
  HostPortPair google_host_port_pair =
      HostPortPair::FromString("www.google.com:65536");
  url::SchemeHostPort gooler_server("http", google_host_port_pair.host(),
                                    google_host_port_pair.port());

  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      gooler_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(HasAlternativeService(gooler_server, NetworkAnonymizationKey()));
  const ServerNetworkStats* stats1 = http_server_props_->GetServerNetworkStats(
      gooler_server, NetworkAnonymizationKey());
  EXPECT_EQ(nullptr, stats1);
  EXPECT_EQ(0u, http_server_props_->quic_server_info_map().size());
}

TEST_F(HttpServerPropertiesManagerTest, BadCachedAltProtocolPort) {
  base::Value::Dict server_pref_dict;

  // Set supports_spdy for www.google.com:80.
  server_pref_dict.Set("supports_spdy", true);

  // Set up alternative_service for www.google.com:80.
  base::Value::Dict alternative_service_dict;
  alternative_service_dict.Set("protocol_str", "h2");
  alternative_service_dict.Set("port", 65536);
  base::Value::List alternative_service_list;
  alternative_service_list.Append(std::move(alternative_service_dict));
  server_pref_dict.Set("alternative_service",
                       std::move(alternative_service_list));

  // Set the server preference for www.google.com:80.
  base::Value::Dict servers_dict;
  servers_dict.Set("www.google.com:80", std::move(server_pref_dict));
  base::Value::List servers_list;
  servers_list.Append(std::move(servers_dict));
  base::Value::Dict http_server_properties_dict = DictWithVersion();
  http_server_properties_dict.Set("servers", std::move(servers_list));

  // Set up the pref.
  InitializePrefs(std::move(http_server_properties_dict));

  // Verify alternative service is not set.
  EXPECT_FALSE(
      HasAlternativeService(url::SchemeHostPort("http", "www.google.com", 80),
                            NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, SupportsSpdy) {
  InitializePrefs();

  // Add mail.google.com:443 as a supporting spdy server.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  // Setting the value to the same thing again should not trigger another pref
  // update.
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  // Setting the value to the same thing again should not trigger another pref
  // update.
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
}

// Regression test for crbug.com/670519. Test that there is only one pref update
// scheduled if multiple updates happen in a given time period. Subsequent pref
// update could also be scheduled once the previous scheduled update is
// completed.
TEST_F(HttpServerPropertiesManagerTest,
       SinglePrefUpdateForTwoSpdyServerCacheChanges) {
  InitializePrefs();

  // Post an update task. SetSupportsSpdy calls ScheduleUpdatePrefs with a delay
  // of 60ms.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  http_server_props_->SetSupportsSpdy(spdy_server, NetworkAnonymizationKey(),
                                      true);
  // The pref update task should be scheduled.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Move forward the task runner short by 20ms.
  FastForwardBy(HttpServerProperties::GetUpdatePrefsDelayForTesting() -
                base::Milliseconds(20));

  // Set another spdy server to trigger another call to
  // ScheduleUpdatePrefs. There should be no new update posted.
  url::SchemeHostPort spdy_server2("https", "drive.google.com", 443);
  http_server_props_->SetSupportsSpdy(spdy_server2, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Move forward the extra 20ms. The pref update should be executed.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardBy(base::Milliseconds(20));
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->SupportsRequestPriority(
      spdy_server2, NetworkAnonymizationKey()));
  // Set the third spdy server to trigger one more call to
  // ScheduleUpdatePrefs. A new update task should be posted now since the
  // previous one is completed.
  url::SchemeHostPort spdy_server3("https", "maps.google.com", 443);
  http_server_props_->SetSupportsSpdy(spdy_server3, NetworkAnonymizationKey(),
                                      true);
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
}

TEST_F(HttpServerPropertiesManagerTest, GetAlternativeServiceInfos) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);
  // ExpectScheduleUpdatePrefs() should be called only once.
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

TEST_F(HttpServerPropertiesManagerTest, SetAlternativeServices) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "mail.google.com",
                                                443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, one_day_from_now_));
  const AlternativeService alternative_service2(kProtoQUIC, "mail.google.com",
                                                1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, one_day_from_now_, advertised_versions_));
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             alternative_service_info_vector);
  // ExpectScheduleUpdatePrefs() should be called only once.
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             alternative_service_info_vector);

  // Run the task.
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector2 =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector2[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[1].alternative_service());
}

TEST_F(HttpServerPropertiesManagerTest, SetAlternativeServicesEmpty) {
  InitializePrefs();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetAlternativeServices(spdy_server_mail,
                                             NetworkAnonymizationKey(),
                                             AlternativeServiceInfoVector());

  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());

  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesManagerTest, ConfirmAlternativeService) {
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

  http_server_props_->ConfirmAlternativeService(alternative_service,
                                                NetworkAnonymizationKey());
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

// Check the case that prefs are loaded only after setting alternative service
// info. Prefs should not be written until after the load happens.
TEST_F(HttpServerPropertiesManagerTest, LateLoadAlternativeServiceInfo) {
  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);

  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());

  // Initializing prefs does not result in a task to write the prefs.
  InitializePrefs(base::Value::Dict(),
                  /*expect_pref_update=*/true);
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  EXPECT_EQ(1u, alternative_service_info_vector.size());

  // Updating the entry should result in a task to save prefs. Have to at least
  // double (or half) the lifetime, to ensure the change triggers a save to
  // prefs.
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_ + base::Days(2));
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  EXPECT_EQ(1u, alternative_service_info_vector.size());
}

// Check the case that prefs are cleared before they're loaded.
TEST_F(HttpServerPropertiesManagerTest,
       ClearPrefsBeforeLoadAlternativeServiceInfo) {
  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(
      HasAlternativeService(spdy_server_mail, NetworkAnonymizationKey()));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);

  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());

  // Clearing prefs should result in a task to write the prefs.
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
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  EXPECT_EQ(0u, alternative_service_info_vector.size());

  // Re-creating the entry should result in a task to save prefs.
  http_server_props_->SetHttp2AlternativeService(
      spdy_server_mail, NetworkAnonymizationKey(), alternative_service,
      one_day_from_now_);
  EXPECT_EQ(0, pref_delegate_->GetAndClearNumPrefUpdates());
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
  FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, pref_delegate_->GetAndClearNumPrefUpdates());
  alternative_service_info_vector =
      http_server_props_->GetAlternativeServiceInfos(spdy_server_mail,
                                                     NetworkAnonymizationKey());
  EXPECT_EQ(1u, alternative_service_info_vector.size());
}

TEST_F(HttpServerPropertiesManagerTest,
       ConfirmBrokenUntilDefaultNetworkChanges) {
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

  http_server_props_->MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(http_server_props_->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_TRUE(http_server_props_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  // In addition to the pref update task, there's now a task to mark the
  // alternative service as no longer broken.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  http_server_props_->ConfirmAlternativeService(alternative_service,
                                                NetworkAnonymizationKey());
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

TEST_F(HttpServerPropertiesManagerTest,
       OnDefaultNetworkChangedWithBrokenUntilDefaultNetworkChanges) {
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
```