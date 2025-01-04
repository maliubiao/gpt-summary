Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a unit test file for `net/http/http_server_properties.cc` in Chromium's network stack. I need to identify the key features being tested and how they relate to the `HttpServerProperties` class.

Here's a breakdown of the code and what it tests:

1. **SPDY Support:**  Tests the ability to set and retrieve whether a server supports the SPDY protocol. This includes handling different port numbers and the relationship between `https`/`wss` and `http`/`ws` schemes. It also tests the interaction with `NetworkAnonymizationKey`.

2. **Loading SPDY Support from Storage:** Tests how SPDY support information is loaded from persistent storage (represented by the `ServerInfoMap`). This includes verifying the Most Recently Used (MRU) order of the stored information and how loading from storage interacts with in-memory updates.

3. **Request Priority Support:** Tests whether the `SupportsRequestPriority` method correctly identifies servers that support request prioritization, which is tied to SPDY and QUIC support.

4. **Clearing SPDY Support:** Tests the functionality to clear all stored SPDY support information.

5. **MRU Behavior of Server Info:** Verifies the MRU behavior of the internal `ServerInfoMap` used to store server properties, specifically for SPDY support.

6. **Alternative Services:** Tests the ability to set, retrieve, and manage alternative service information (like HTTP/2 and QUIC). This includes handling the exclusion of the origin server itself from the alternative service list.

7. **Loading Alternative Services from Storage:**  Similar to SPDY, this tests how alternative service information is loaded from storage and how it interacts with in-memory updates.

8. **Broken Alternative Services:** Tests the mechanism for tracking and expiring broken alternative services.

Based on this analysis, the main function of this unit test file is to verify the correct behavior of the `HttpServerProperties` class, specifically in managing and persisting information about:

* Whether a server supports SPDY.
* Whether a server supports request prioritization.
* What alternative services (like HTTP/2 and QUIC) are available for a server.
* Which alternative services are currently considered broken.

Regarding the prompt's specific questions:

* **Relationship with JavaScript:** While the core logic is in C++, these properties influence how the browser makes network requests, which is triggered by JavaScript code. For example, if JavaScript initiates a fetch to a domain that `HttpServerProperties` indicates supports HTTP/2, the browser will attempt an HTTP/2 connection.
* **Logical Reasoning (Hypothetical Input/Output):** The tests themselves demonstrate this. For example, setting SPDY support for a specific origin and then retrieving it verifies the storage and retrieval logic.
* **Common Usage Errors:**  Incorrectly configuring or persisting this data could lead to suboptimal network performance (e.g., not using HTTP/2 when it's available) or connection failures if broken alternative services aren't handled properly.
* **User Operation and Debugging:** When a user navigates to a website, the browser checks `HttpServerProperties` to optimize the connection. If a website is unexpectedly slow or failing to load, inspecting the state of `HttpServerProperties` (e.g., through internal debugging tools) can provide clues about misconfigurations or issues with alternative service advertisements.
这个C++源代码文件 `net/http/http_server_properties_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/http/http_server_properties.h` 中定义的 `HttpServerProperties` 类的功能。

**它的主要功能是：**

1. **测试 SPDY 协议的支持情况:**
   - 测试设置和获取某个服务器是否支持 SPDY 协议的能力。
   - 验证对于 `https` 和 `wss`，以及 `http` 和 `ws` 协议头的服务器，其 SPDY 支持状态是否被正确地视为相同。
   - 测试在启用和禁用网络隔离键 (Network Isolation Key) 的情况下，`HttpServerProperties` 对 SPDY 支持状态的管理。
   - 测试从持久化存储加载 SPDY 支持信息的功能，并验证加载后数据的正确性和 MRU (Most Recently Used) 顺序。

2. **测试请求优先级支持:**
   - 测试 `SupportsRequestPriority` 方法是否能正确判断服务器是否支持请求优先级，这通常与 SPDY 或 QUIC 协议的支持相关。

3. **测试清除 SPDY 支持信息的功能:**
   - 验证 `Clear` 方法能够清除所有存储的 SPDY 支持信息。

4. **测试服务器信息映射的 MRU 特性:**
   - 验证内部用于存储服务器信息的映射 (ServerInfoMap) 是否按照 MRU 的顺序进行管理。

5. **测试备用协议 (Alternative Protocol) 的支持情况:**
   - 测试设置和获取服务器备用协议信息的能力，例如 HTTP/2 和 QUIC。
   - 验证设置备用协议时，是否会排除与原始服务器相同主机名和端口的 TCP 协议服务。
   - 测试从持久化存储加载备用协议信息的功能，并验证加载后数据的正确性。

6. **测试失效的备用服务 (Broken Alternative Service) 的管理:**
   - 测试添加和管理失效的备用服务的功能，以及失效时间的处理。
   - 模拟失效备用服务的过期过程。

**与 JavaScript 的功能关系：**

`HttpServerProperties` 存储的网络属性（如是否支持 SPDY、HTTP/2 或 QUIC）直接影响浏览器在与服务器建立连接时的行为。当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，网络栈会参考 `HttpServerProperties` 中的信息来决定使用哪种协议进行连接，从而优化网络性能。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 请求 `https://example.com/data.json`。

1. **假设输入：** `HttpServerProperties` 中存储了 `example.com:443` 支持 HTTP/2 的信息。
2. **逻辑推理：** 网络栈会读取 `HttpServerProperties`，发现该服务器支持 HTTP/2。
3. **输出：** 浏览器会尝试使用 HTTP/2 协议与 `example.com` 建立连接，而不是传统的 HTTP/1.1，从而可能获得更快的加载速度。

**逻辑推理的假设输入与输出：**

**场景：测试设置和获取 SPDY 支持**

* **假设输入：** 调用 `impl_.SetSupportsSpdy(https_www_server, NetworkAnonymizationKey(), true)`，其中 `https_www_server` 是 `("https", "www.google.com", 443)`。
* **输出：** 调用 `impl_.GetSupportsSpdy(https_www_server, NetworkAnonymizationKey())` 返回 `true`。

**场景：测试备用协议的设置和获取**

* **假设输入：** 调用 `SetAlternativeService(test_server, alternative_service)`，其中 `test_server` 是 `("http", "foo", 80)`，`alternative_service` 是 `(kProtoHTTP2, "foo", 443)`。
* **输出：** 调用 `impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())` 返回一个包含 `alternative_service` 信息的向量。

**涉及用户或编程常见的使用错误：**

虽然用户不会直接操作 `HttpServerProperties`，但编程错误或系统配置问题可能会导致其状态不正确，从而影响网络性能。

* **错误的持久化数据:** 如果持久化存储中的数据损坏或不一致，可能导致浏览器做出错误的连接决策。例如，一个服务器实际上不支持 HTTP/2，但 `HttpServerProperties` 中错误地记录了支持，会导致连接尝试失败或回退到 HTTP/1.1。
* **网络环境变化未及时更新:** 如果用户的网络环境发生变化（例如，某个备用服务变得不可用），但 `HttpServerProperties` 中的信息没有及时更新，可能会导致浏览器持续尝试连接失效的服务。

**用户操作如何一步步地到达这里，作为调试线索：**

当用户在浏览器中进行以下操作时，可能会触发对 `HttpServerProperties` 的访问和修改：

1. **首次访问一个网站:** 当用户首次访问一个网站时，如果服务器返回了指示支持 SPDY 或备用协议的 HTTP 头部（如 `Alt-Svc`），浏览器会将这些信息存储到 `HttpServerProperties` 中。
2. **后续访问同一个网站:** 当用户再次访问同一个网站时，浏览器会先查询 `HttpServerProperties`，看是否已经有该网站的 SPDY 或备用协议信息。如果有，浏览器会尝试使用这些协议进行连接，以提高效率。
3. **清除浏览器数据:** 用户清除浏览器的缓存和 Cookie 等数据时，可能会选择清除与网络相关的设置，这可能导致 `HttpServerProperties` 中的部分或全部数据被清除。
4. **网络连接失败或超时:** 如果浏览器尝试使用存储在 `HttpServerProperties` 中的备用协议连接失败，它会将该备用服务标记为失效，并记录失效时间。

**作为调试线索：**

如果用户遇到以下网络问题，可以考虑 `HttpServerProperties` 作为调试线索：

* **网站加载速度异常缓慢:** 可能由于浏览器错误地认为服务器支持某个协议但实际不支持，导致连接尝试失败或回退。
* **连接被拒绝或超时:**  可能由于浏览器持续尝试连接被标记为失效的备用服务。
* **间歇性的连接问题:** 可能与备用服务的可用性波动有关。

开发者可以使用 Chromium 提供的内部工具（如 `net-internals`）来查看 `HttpServerProperties` 的状态，以帮助诊断这些问题。

**归纳一下它的功能 (第 1 部分):**

这个单元测试文件的主要功能是 **验证 `HttpServerProperties` 类在管理和存储服务器的 SPDY 协议支持状态方面的正确性**。 它测试了设置、获取、加载和清除 SPDY 支持信息，并验证了相关逻辑在不同场景下的行为，包括处理不同的协议头、端口号和网络隔离键。 同时，它也初步涉及了服务器信息存储的 MRU 特性。

Prompt: 
```
这是目录为net/http/http_server_properties_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_server_properties.h"

#include <memory>
#include <string>
#include <vector>

#include "base/check.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/privacy_mode.h"
#include "net/base/schemeful_site.h"
#include "net/http/http_network_session.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

const base::TimeDelta BROKEN_ALT_SVC_EXPIRE_DELAYS[10] = {
    base::Seconds(300),    base::Seconds(600),   base::Seconds(1200),
    base::Seconds(2400),   base::Seconds(4800),  base::Seconds(9600),
    base::Seconds(19200),  base::Seconds(38400), base::Seconds(76800),
    base::Seconds(153600),
};

class HttpServerPropertiesPeer {
 public:
  static void AddBrokenAlternativeServiceWithExpirationTime(
      HttpServerProperties* impl,
      const AlternativeService& alternative_service,
      base::TimeTicks when,
      const NetworkAnonymizationKey network_anonymization_key =
          NetworkAnonymizationKey()) {
    BrokenAlternativeService broken_alternative_service(
        alternative_service, network_anonymization_key,
        true /* use_network_anonymization_key */);
    BrokenAlternativeServiceList::iterator unused_it;
    impl->broken_alternative_services_.AddToBrokenListAndMap(
        broken_alternative_service, when, &unused_it);
    auto it =
        impl->broken_alternative_services_.recently_broken_alternative_services_
            .Get(broken_alternative_service);
    if (it == impl->broken_alternative_services_
                  .recently_broken_alternative_services_.end()) {
      impl->broken_alternative_services_.recently_broken_alternative_services_
          .Put(broken_alternative_service, 1);
    } else {
      it->second++;
    }
  }

  static void ExpireBrokenAlternateProtocolMappings(
      HttpServerProperties* impl) {
    impl->broken_alternative_services_.ExpireBrokenAlternateProtocolMappings();
  }
};

namespace {

// Creates a ServerInfoMapKey without a NetworkAnonymizationKey.
HttpServerProperties::ServerInfoMapKey CreateSimpleKey(
    const url::SchemeHostPort& server) {
  return HttpServerProperties::ServerInfoMapKey(
      server, NetworkAnonymizationKey(),
      false /* use_network_anonymization_key */);
}

class HttpServerPropertiesTest : public TestWithTaskEnvironment {
 protected:
  HttpServerPropertiesTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        // Many tests assume partitioning is disabled by default.
        feature_list_(CreateFeatureListWithPartitioningDisabled()),
        test_tick_clock_(GetMockTickClock()),
        impl_(nullptr /* pref_delegate */,
              nullptr /* net_log */,
              test_tick_clock_,
              &test_clock_) {
    // Set |test_clock_| to some random time.
    test_clock_.Advance(base::Seconds(12345));

    SchemefulSite site1(GURL("https://foo.test/"));
    network_anonymization_key1_ =
        NetworkAnonymizationKey::CreateSameSite(site1);
    SchemefulSite site2(GURL("https://bar.test/"));
    network_anonymization_key2_ =
        NetworkAnonymizationKey::CreateSameSite(site2);
  }

  // This is a little awkward, but need to create and configure the
  // ScopedFeatureList before creating the HttpServerProperties.
  static std::unique_ptr<base::test::ScopedFeatureList>
  CreateFeatureListWithPartitioningDisabled() {
    std::unique_ptr<base::test::ScopedFeatureList> feature_list =
        std::make_unique<base::test::ScopedFeatureList>();
    feature_list->InitAndDisableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
    return feature_list;
  }

  bool HasAlternativeService(
      const url::SchemeHostPort& origin,
      const NetworkAnonymizationKey& network_anonymization_key) {
    const AlternativeServiceInfoVector alternative_service_info_vector =
        impl_.GetAlternativeServiceInfos(origin, network_anonymization_key);
    return !alternative_service_info_vector.empty();
  }

  void SetAlternativeService(const url::SchemeHostPort& origin,
                             const AlternativeService& alternative_service) {
    const base::Time expiration = test_clock_.Now() + base::Days(1);
    if (alternative_service.protocol == kProtoQUIC) {
      impl_.SetQuicAlternativeService(origin, NetworkAnonymizationKey(),
                                      alternative_service, expiration,
                                      DefaultSupportedQuicVersions());
    } else {
      impl_.SetHttp2AlternativeService(origin, NetworkAnonymizationKey(),
                                       alternative_service, expiration);
    }
  }

  void MarkBrokenAndLetExpireAlternativeServiceNTimes(
      const AlternativeService& alternative_service,
      int num_times) {}

  std::unique_ptr<base::test::ScopedFeatureList> feature_list_;

  raw_ptr<const base::TickClock> test_tick_clock_;
  base::SimpleTestClock test_clock_;

  // Two different non-empty network isolation keys for use in tests that need
  // them.
  NetworkAnonymizationKey network_anonymization_key1_;
  NetworkAnonymizationKey network_anonymization_key2_;

  HttpServerProperties impl_;
};

TEST_F(HttpServerPropertiesTest, SetSupportsSpdy) {
  // Check spdy servers are correctly set with SchemeHostPort key.
  url::SchemeHostPort https_www_server("https", "www.google.com", 443);
  url::SchemeHostPort http_photo_server("http", "photos.google.com", 80);
  url::SchemeHostPort https_mail_server("https", "mail.google.com", 443);
  // Servers with port equal to default port in scheme will drop port components
  // when calling Serialize().

  url::SchemeHostPort http_google_server("http", "www.google.com", 443);
  url::SchemeHostPort https_photos_server("https", "photos.google.com", 443);
  url::SchemeHostPort valid_google_server((GURL("https://www.google.com")));

  impl_.SetSupportsSpdy(https_www_server, NetworkAnonymizationKey(), true);
  impl_.SetSupportsSpdy(http_photo_server, NetworkAnonymizationKey(), true);
  impl_.SetSupportsSpdy(https_mail_server, NetworkAnonymizationKey(), false);
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(https_www_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.SupportsRequestPriority(https_www_server,
                                            NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(http_photo_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.SupportsRequestPriority(http_photo_server,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(https_mail_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.SupportsRequestPriority(https_mail_server,
                                             NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(http_google_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.SupportsRequestPriority(http_google_server,
                                             NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(https_photos_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.SupportsRequestPriority(https_photos_server,
                                             NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(valid_google_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.SupportsRequestPriority(valid_google_server,
                                            NetworkAnonymizationKey()));

  // Flip values of two servers.
  impl_.SetSupportsSpdy(https_www_server, NetworkAnonymizationKey(), false);
  impl_.SetSupportsSpdy(https_mail_server, NetworkAnonymizationKey(), true);
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(https_www_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.SupportsRequestPriority(https_www_server,
                                             NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(https_mail_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.SupportsRequestPriority(https_mail_server,
                                            NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, SetSupportsSpdyWebSockets) {
  // The https and wss servers should be treated as the same server, as should
  // the http and ws servers.
  url::SchemeHostPort https_server("https", "www.test.com", 443);
  url::SchemeHostPort wss_server("wss", "www.test.com", 443);
  url::SchemeHostPort http_server("http", "www.test.com", 443);
  url::SchemeHostPort ws_server("ws", "www.test.com", 443);

  EXPECT_FALSE(impl_.GetSupportsSpdy(https_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(wss_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(http_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(ws_server, NetworkAnonymizationKey()));

  impl_.SetSupportsSpdy(wss_server, NetworkAnonymizationKey(), true);
  EXPECT_TRUE(impl_.GetSupportsSpdy(https_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(wss_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(http_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(ws_server, NetworkAnonymizationKey()));

  impl_.SetSupportsSpdy(http_server, NetworkAnonymizationKey(), true);
  EXPECT_TRUE(impl_.GetSupportsSpdy(https_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(wss_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(http_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(ws_server, NetworkAnonymizationKey()));

  impl_.SetSupportsSpdy(https_server, NetworkAnonymizationKey(), false);
  EXPECT_FALSE(impl_.GetSupportsSpdy(https_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(wss_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(http_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.GetSupportsSpdy(ws_server, NetworkAnonymizationKey()));

  impl_.SetSupportsSpdy(ws_server, NetworkAnonymizationKey(), false);
  EXPECT_FALSE(impl_.GetSupportsSpdy(https_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(wss_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(http_server, NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.GetSupportsSpdy(ws_server, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, SetSupportsSpdyWithNetworkIsolationKey) {
  const url::SchemeHostPort kServer("https", "foo.test", 443);

  EXPECT_FALSE(impl_.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_FALSE(
      impl_.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_FALSE(impl_.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

  // Without network isolation keys enabled for HttpServerProperties, passing in
  // a NetworkAnonymizationKey should have no effect on behavior.
  for (const auto& network_anonymization_key_to_set :
       {NetworkAnonymizationKey(), network_anonymization_key1_}) {
    impl_.SetSupportsSpdy(kServer, network_anonymization_key_to_set, true);
    EXPECT_TRUE(impl_.GetSupportsSpdy(kServer, network_anonymization_key1_));
    EXPECT_TRUE(
        impl_.SupportsRequestPriority(kServer, network_anonymization_key1_));
    EXPECT_TRUE(impl_.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
    EXPECT_TRUE(
        impl_.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

    impl_.SetSupportsSpdy(kServer, network_anonymization_key_to_set, false);
    EXPECT_FALSE(impl_.GetSupportsSpdy(kServer, network_anonymization_key1_));
    EXPECT_FALSE(
        impl_.SupportsRequestPriority(kServer, network_anonymization_key1_));
    EXPECT_FALSE(impl_.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
    EXPECT_FALSE(
        impl_.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));
  }

  // With network isolation keys enabled for HttpServerProperties, the
  // NetworkAnonymizationKey argument should be respected.

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  HttpServerProperties properties(nullptr /* pref_delegate */,
                                  nullptr /* net_log */, test_tick_clock_,
                                  &test_clock_);

  EXPECT_FALSE(
      properties.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_FALSE(properties.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

  properties.SetSupportsSpdy(kServer, network_anonymization_key1_, true);
  EXPECT_TRUE(properties.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_TRUE(
      properties.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_FALSE(properties.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

  properties.SetSupportsSpdy(kServer, NetworkAnonymizationKey(), true);
  EXPECT_TRUE(properties.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_TRUE(
      properties.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_TRUE(properties.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      properties.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

  properties.SetSupportsSpdy(kServer, network_anonymization_key1_, false);
  EXPECT_FALSE(
      properties.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_TRUE(properties.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      properties.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));

  properties.SetSupportsSpdy(kServer, NetworkAnonymizationKey(), false);
  EXPECT_FALSE(
      properties.GetSupportsSpdy(kServer, network_anonymization_key1_));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, network_anonymization_key1_));
  EXPECT_FALSE(properties.GetSupportsSpdy(kServer, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      properties.SupportsRequestPriority(kServer, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, LoadSupportsSpdy) {
  HttpServerProperties::ServerInfo supports_spdy;
  supports_spdy.supports_spdy = true;
  HttpServerProperties::ServerInfo no_spdy;
  no_spdy.supports_spdy = false;

  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  url::SchemeHostPort spdy_server_photos("https", "photos.google.com", 443);
  url::SchemeHostPort spdy_server_docs("https", "docs.google.com", 443);
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);

  // Check by initializing empty spdy servers.
  std::unique_ptr<HttpServerProperties::ServerInfoMap> spdy_servers =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  impl_.OnServerInfoLoadedForTesting(std::move(spdy_servers));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));

  // Check by initializing www.google.com:443 and photos.google.com:443 as spdy
  // servers.
  std::unique_ptr<HttpServerProperties::ServerInfoMap> spdy_servers1 =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  spdy_servers1->Put(CreateSimpleKey(spdy_server_google), supports_spdy);
  spdy_servers1->Put(CreateSimpleKey(spdy_server_photos), no_spdy);
  impl_.OnServerInfoLoadedForTesting(std::move(spdy_servers1));
  // Note: these calls affect MRU order.
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_photos, NetworkAnonymizationKey()));

  // Verify google and photos are in the list in MRU order.
  ASSERT_EQ(2U, impl_.server_info_map_for_testing().size());
  auto it = impl_.server_info_map_for_testing().begin();
  EXPECT_EQ(spdy_server_photos, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_FALSE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);

  // Check by initializing mail.google.com:443 and docs.google.com:443.
  std::unique_ptr<HttpServerProperties::ServerInfoMap> spdy_servers2 =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  spdy_servers2->Put(CreateSimpleKey(spdy_server_mail), supports_spdy);
  spdy_servers2->Put(CreateSimpleKey(spdy_server_docs), supports_spdy);
  impl_.OnServerInfoLoadedForTesting(std::move(spdy_servers2));

  // Verify all the servers are in the list in MRU order. Note that
  // OnServerInfoLoadedForTesting will put existing spdy server entries in
  // front of newly added entries.
  ASSERT_EQ(4U, impl_.server_info_map_for_testing().size());
  it = impl_.server_info_map_for_testing().begin();
  EXPECT_EQ(spdy_server_photos, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_FALSE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_docs, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_mail, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);

  // Check these in reverse MRU order so that MRU order stays the same.
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_docs, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_photos, NetworkAnonymizationKey()));

  // Verify that old values loaded from disk take precedence over newer learned
  // values and also verify the recency list order is unchanged.
  std::unique_ptr<HttpServerProperties::ServerInfoMap> spdy_servers3 =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  spdy_servers3->Put(CreateSimpleKey(spdy_server_mail), no_spdy);
  spdy_servers3->Put(CreateSimpleKey(spdy_server_photos), supports_spdy);
  impl_.OnServerInfoLoadedForTesting(std::move(spdy_servers3));

  // Verify the entries are in the same order.
  ASSERT_EQ(4U, impl_.server_info_map_for_testing().size());
  it = impl_.server_info_map_for_testing().begin();
  EXPECT_EQ(spdy_server_photos, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_docs, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_TRUE(*it->second.supports_spdy);
  ++it;
  EXPECT_EQ(spdy_server_mail, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ASSERT_TRUE(it->second.supports_spdy.has_value());
  EXPECT_FALSE(*it->second.supports_spdy);

  // Verify photos server doesn't support SPDY and other servers support SPDY.
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_docs, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_photos, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, SupportsRequestPriority) {
  url::SchemeHostPort spdy_server_empty("https", std::string(), 443);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_empty,
                                             NetworkAnonymizationKey()));

  // Add www.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey(), true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google,
                                            NetworkAnonymizationKey()));

  // Add mail.google.com:443 as not supporting SPDY.
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail,
                                             NetworkAnonymizationKey()));

  // Add docs.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_docs("https", "docs.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_docs, NetworkAnonymizationKey(), true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs,
                                            NetworkAnonymizationKey()));

  // Add www.youtube.com:443 as supporting QUIC.
  url::SchemeHostPort youtube_server("https", "www.youtube.com", 443);
  const AlternativeService alternative_service1(kProtoQUIC, "www.youtube.com",
                                                443);
  SetAlternativeService(youtube_server, alternative_service1);
  EXPECT_TRUE(
      impl_.SupportsRequestPriority(youtube_server, NetworkAnonymizationKey()));

  // Add www.example.com:443 with two alternative services, one supporting QUIC.
  url::SchemeHostPort example_server("https", "www.example.com", 443);
  const AlternativeService alternative_service2(kProtoHTTP2, "", 443);
  SetAlternativeService(example_server, alternative_service2);
  SetAlternativeService(example_server, alternative_service1);
  EXPECT_TRUE(
      impl_.SupportsRequestPriority(example_server, NetworkAnonymizationKey()));

  // Verify all the entries are the same after additions.
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google,
                                            NetworkAnonymizationKey()));
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail,
                                             NetworkAnonymizationKey()));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs,
                                            NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.SupportsRequestPriority(youtube_server, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.SupportsRequestPriority(example_server, NetworkAnonymizationKey()));
}

TEST_F(HttpServerPropertiesTest, ClearSupportsSpdy) {
  // Add www.google.com:443 and mail.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey(), true);
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey(), true);

  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey()));

  base::RunLoop run_loop;
  bool callback_invoked_ = false;
  impl_.Clear(base::BindOnce(
      [](bool* callback_invoked, base::OnceClosure quit_closure) {
        *callback_invoked = true;
        std::move(quit_closure).Run();
      },
      &callback_invoked_, run_loop.QuitClosure()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  EXPECT_FALSE(
      impl_.GetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey()));

  // Callback should be run asynchronously.
  EXPECT_FALSE(callback_invoked_);
  run_loop.Run();
  EXPECT_TRUE(callback_invoked_);
}

TEST_F(HttpServerPropertiesTest, MRUOfServerInfoMap) {
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);

  // Add www.google.com:443 as supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey(), true);
  ASSERT_EQ(1u, impl_.server_info_map_for_testing().size());
  auto it = impl_.server_info_map_for_testing().begin();
  ASSERT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());

  // Add mail.google.com:443 as supporting SPDY. Verify mail.google.com:443 and
  // www.google.com:443 are in the list.
  impl_.SetSupportsSpdy(spdy_server_mail, NetworkAnonymizationKey(), true);
  ASSERT_EQ(2u, impl_.server_info_map_for_testing().size());
  it = impl_.server_info_map_for_testing().begin();
  ASSERT_EQ(spdy_server_mail, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ++it;
  ASSERT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());

  // Get www.google.com:443. It should become the most-recently-used server.
  EXPECT_TRUE(
      impl_.GetSupportsSpdy(spdy_server_google, NetworkAnonymizationKey()));
  ASSERT_EQ(2u, impl_.server_info_map_for_testing().size());
  it = impl_.server_info_map_for_testing().begin();
  ASSERT_EQ(spdy_server_google, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
  ++it;
  ASSERT_EQ(spdy_server_mail, it->first.server);
  EXPECT_TRUE(it->first.network_anonymization_key.IsEmpty());
}

typedef HttpServerPropertiesTest AlternateProtocolServerPropertiesTest;

TEST_F(AlternateProtocolServerPropertiesTest, Basic) {
  url::SchemeHostPort test_server("http", "foo", 80);
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));

  AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service);
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());

  impl_.Clear(base::OnceClosure());
  EXPECT_FALSE(HasAlternativeService(test_server, NetworkAnonymizationKey()));
}

TEST_F(AlternateProtocolServerPropertiesTest, ExcludeOrigin) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = test_clock_.Now() + base::Days(1);
  // Same hostname, same port, TCP: should be ignored.
  AlternativeServiceInfo alternative_service_info1 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foo", 443), expiration);
  alternative_service_info_vector.push_back(alternative_service_info1);
  // Different hostname: GetAlternativeServiceInfos should return this one.
  AlternativeServiceInfo alternative_service_info2 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "bar", 443), expiration);
  alternative_service_info_vector.push_back(alternative_service_info2);
  // Different port: GetAlternativeServiceInfos should return this one too.
  AlternativeServiceInfo alternative_service_info3 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          AlternativeService(kProtoHTTP2, "foo", 80), expiration);
  alternative_service_info_vector.push_back(alternative_service_info3);
  // QUIC: GetAlternativeServices should return this one too.
  AlternativeServiceInfo alternative_service_info4 =
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          AlternativeService(kProtoQUIC, "foo", 443), expiration,
          DefaultSupportedQuicVersions());
  alternative_service_info_vector.push_back(alternative_service_info4);

  url::SchemeHostPort test_server("https", "foo", 443);
  impl_.SetAlternativeServices(test_server, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  const AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey());
  ASSERT_EQ(3u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service_info2, alternative_service_info_vector2[0]);
  EXPECT_EQ(alternative_service_info3, alternative_service_info_vector2[1]);
  EXPECT_EQ(alternative_service_info4, alternative_service_info_vector2[2]);
}

TEST_F(AlternateProtocolServerPropertiesTest, Set) {
  // |test_server1| has an alternative service, which will not be
  // affected by OnServerInfoLoadedForTesting(), because
  // |server_info_map| does not have an entry for
  // |test_server1|.
  url::SchemeHostPort test_server1("http", "foo1", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "bar1", 443);
  const base::Time now = test_clock_.Now();
  base::Time expiration1 = now + base::Days(1);
  // 1st entry in the memory.
  impl_.SetHttp2AlternativeService(test_server1, NetworkAnonymizationKey(),
                                   alternative_service1, expiration1);

  // |test_server2| has an alternative service, which will be
  // overwritten by OnServerInfoLoadedForTesting(), because
  // |server_info_map| has an entry for |test_server2|.
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service2(kProtoHTTP2, "bar2", 443);
  base::Time expiration2 = now + base::Days(2);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service2, expiration2));
  url::SchemeHostPort test_server2("http", "foo2", 80);
  // 0th entry in the memory.
  impl_.SetAlternativeServices(test_server2, NetworkAnonymizationKey(),
                               alternative_service_info_vector);

  // Prepare |server_info_map| to be loaded by OnServerInfoLoadedForTesting().
  std::unique_ptr<HttpServerProperties::ServerInfoMap> server_info_map =
      std::make_unique<HttpServerProperties::ServerInfoMap>();
  const AlternativeService alternative_service3(kProtoHTTP2, "bar3", 123);
  base::Time expiration3 = now + base::Days(3);
  const AlternativeServiceInfo alternative_service_info1 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service3, expiration3);
  // Simulate updating data for 0th entry with data from Preferences.
  server_info_map->GetOrPut(CreateSimpleKey(test_server2))
      ->second.alternative_services =
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info1);

  url::SchemeHostPort test_server3("http", "foo3", 80);
  const AlternativeService alternative_service4(kProtoHTTP2, "bar4", 1234);
  base::Time expiration4 = now + base::Days(4);
  const AlternativeServiceInfo alternative_service_info2 =
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service4, expiration4);
  // Add an old entry from Preferences, this will be added to end of recency
  // list.
  server_info_map->GetOrPut(CreateSimpleKey(test_server3))
      ->second.alternative_services =
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info2);

  // MRU list will be t
"""


```