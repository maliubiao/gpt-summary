Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's networking stack and specifically deals with managing HTTP server properties.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `http_server_properties_manager.cc` and the class name `HttpServerPropertiesManager` strongly suggest this component is responsible for managing properties related to HTTP servers.

2. **Analyze the included headers:**  Headers like `net/http/http_server_properties.h`, `net/base/features.h`, `net/base/host_port_pair.h`, `net/base/ip_address.h`, `url/gurl.h`, and `base/values.h` confirm that this code deals with network-related data, specifically HTTP, and uses preferences/storage mechanisms (implied by `base/values.h`). The presence of `quiche/quic/platform/api/quic_hostname_utils.h` indicates involvement with the QUIC protocol.

3. **Examine the key data structures and constants:**
    * Constants like `kVersionNumber`, `kServersKey`, `kQuicServers`, `kBrokenAlternativeServicesKey`, etc., point to the types of server properties being managed.
    * The use of `base::Value::Dict` and `base::Value::List` suggests the properties are stored in a structured format suitable for serialization (e.g., to disk).
    * The nested structure (e.g., servers containing alternative services) is evident from the key names.

4. **Trace the data flow (read/write operations):**
    * The functions `ReadPrefs` and `WriteToPrefs` are crucial. `ReadPrefs` reads server properties from a persistent store (likely browser preferences). `WriteToPrefs` writes the current state of server properties back to the persistent store.
    * The `pref_delegate_` suggests an abstraction layer for accessing and modifying these preferences.
    * The `OnHttpServerPropertiesLoaded` callback indicates asynchronous loading of preferences.

5. **Identify the types of properties being managed:**
    * **SPDY/HTTP/2 support:** `kSupportsSpdyKey`
    * **QUIC support:** `kSupportsQuicKey`, `kQuicServers`
    * **Alternative services:** `kAlternativeServiceKey` (for faster connections)
    * **Broken alternative services:** `kBrokenAlternativeServicesKey` (to avoid failing connections)
    * **Network statistics:** `kNetworkStatsKey` (like SRTT)
    * **Network Anonymization Key:**  `kNetworkAnonymizationKey` (for privacy partitioning)

6. **Understand the logic within `ReadPrefs` and `WriteToPrefs`:**
    * **Versioning:** The `kVersionNumber` and the check in `ReadPrefs` ensure compatibility with the stored data format.
    * **Data parsing:**  Functions like `ParseAlternativeServiceInfo`, `ParseNetworkStats`, `QuicServerIdFromString` handle deserializing the stored data.
    * **Data serialization:** Functions like `SaveAlternativeServiceToServerPrefs`, `SaveNetworkStatsToServerPrefs`, `QuicServerIdToString` handle serializing the data for storage.
    * **Filtering/Validation:** The `GetAlternativeServiceToPersist` function shows logic to filter out expired or invalid alternative services before saving.
    * **LRU (Implicit):** The comment about `servers` being saved in LRU order suggests that older entries are removed when the maximum limit is reached, although the explicit LRU implementation might be in the underlying `HttpServerProperties` class.

7. **Look for specific features:**
    * **Broken alternative services:** The management of broken services, including a "recently broken" list, aims to improve connection reliability by avoiding known bad routes.

8. **Consider JavaScript interaction (if any):**  While the C++ code itself doesn't directly execute JavaScript, the data it manages *can* influence how the browser interacts with websites. For instance, knowing about alternative services or QUIC support will affect connection establishment initiated by JavaScript through browser APIs like `fetch` or `XMLHttpRequest`.

9. **Infer user actions leading to this code:**  User browsing activity (visiting websites, especially those using HTTPS, HTTP/2, or QUIC) will cause this code to be invoked to store and retrieve server connection properties.

10. **Formulate the summary:** Based on the above analysis, synthesize a concise summary that covers the main responsibilities of the `HttpServerPropertiesManager`.

11. **Address the specific questions in the prompt:**
    * **Functionality:**  List the key tasks the code performs.
    * **JavaScript relation:** Explain how the managed data impacts JavaScript's network requests.
    * **Logic inference (hypothesis):**  Create a simple example of data being read or written, highlighting the input and output.
    * **User/programming errors:** Identify potential issues like data corruption or incorrect preference handling.
    * **User steps to reach the code:** Describe typical browsing actions.
    * **Summary of functionality:**  Provide a high-level overview.

By following these steps, one can systematically understand the purpose and workings of the given C++ code snippet and address the user's request comprehensively.
好的，这是对 `net/http/http_server_properties_manager.cc` 文件功能的归纳总结（第 1 部分）：

**功能归纳:**

`HttpServerPropertiesManager` 类的主要职责是**管理和持久化 HTTP 服务器的各种属性**，以便 Chrome 浏览器可以记住并利用这些信息来优化未来的网络连接。  它充当了内存中的 `HttpServerProperties` 数据结构和持久化存储（通常是用户的偏好设置）之间的桥梁。

具体来说，在第 1 部分的代码中，其主要功能集中在 **读取和反序列化**  存储在偏好设置中的 HTTP 服务器属性数据。 这包括：

1. **读取版本信息:**  检查存储的数据版本号 (`kVersionNumber`)，以确保数据格式兼容。如果版本不匹配，则会清空所有已存储的属性。
2. **读取服务器支持的协议信息:**  解析服务器是否支持 SPDY (`kSupportsSpdyKey`)。
3. **读取替代服务 (Alternative Services) 信息:**  解析服务器声明的替代服务信息 (`kAlternativeServiceKey`)，用于建立更快的连接。这包括替代服务的协议、主机、端口和过期时间。
4. **读取 QUIC 服务器信息:**  解析已知的 QUIC 服务器信息 (`kQuicServers`)，包括服务器 ID 和相关的隐私模式。
5. **读取最近失败的替代服务信息:** 解析最近连接失败的替代服务信息 (`kBrokenAlternativeServicesKey`)，以便在一段时间内避免再次尝试连接这些服务。
6. **读取上次 QUIC 工作时的本地 IP 地址:**  解析上次 QUIC 协议成功工作时的本地 IP 地址 (`kSupportsQuicKey`, `kAddressKey`)。
7. **读取网络统计信息:** 解析与服务器相关的网络统计信息 (`kNetworkStatsKey`)，例如往返时间 (SRTT)。
8. **将读取的数据加载到内存:**  将从偏好设置中读取的数据填充到 `HttpServerProperties::ServerInfoMap` 和 `HttpServerProperties::QuicServerInfoMap` 等内存数据结构中。

**与 JavaScript 的关系 (可能存在，但此处未直接体现):**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它管理的数据 **直接影响**  JavaScript 发起的网络请求的行为。例如：

* **替代服务 (Alternative Services):**  如果 JavaScript 发起一个到某个域名的 HTTPS 请求，Chrome 会查找是否为此域名存储了有效的替代服务。如果存在，浏览器可能会尝试使用存储的替代服务（例如，通过不同的端口或主机使用 HTTP/3/QUIC）来建立连接，而无需 JavaScript 代码显式指定。这可以加快页面加载速度。
* **QUIC 支持:**  如果 JavaScript 发起一个到某个域名的 HTTPS 请求，并且该域名被标记为支持 QUIC，Chrome 可能会尝试使用 QUIC 协议建立连接。这对于 JavaScript 开发者来说是透明的，但可以显著提升网络性能。
* **避免失败的连接:**  存储的失败替代服务信息可以防止浏览器尝试已知会失败的连接，从而避免延迟和错误，即使 JavaScript 代码没有明确处理这些情况。

**逻辑推理 (假设输入与输出):**

**假设输入 (存储的偏好设置数据):**

```json
{
  "http_server_properties": {
    "version": 5,
    "servers": [
      {
        "https://example.com": {
          "supports_spdy": true,
          "alternative_service": [
            {
              "protocol_str": "h3",
              "port": 443,
              "expiration": "1678886400000000"
            }
          ]
        },
        "http://another-example.com:8080": {}
      }
    ],
    "quic_servers": [
      {
        "server_id": "https://quic-server.net",
        "server_info": "一些 QUIC 配置信息"
      }
    ],
    "broken_alternative_services": [
      {
        "protocol_str": "h2",
        "host": "broken.example.com",
        "port": 80,
        "broken_until": "1678800000",
        "broken_count": 3
      }
    ]
  }
}
```

**输出 (读取到内存的数据结构):**

* `server_info_map`:
    * 键: `https://example.com`
    * 值:
        * `supports_spdy`: `true`
        * `alternative_services`:  包含一个 `AlternativeServiceInfo` 对象，表示协议为 "h3"，端口为 443，过期时间为某个特定时间戳。
    * 键: `http://another-example.com:8080`
    * 值:  空 (因为没有其他属性)

* `quic_server_info_map`:
    * 键:  `quic::QuicServerId("quic-server.net", 443)`, `PRIVACY_MODE_DISABLED`
    * 值: "一些 QUIC 配置信息"

* `broken_alternative_service_list`:
    * 包含一个 `BrokenAlternativeService` 对象，表示协议为 "h2"，主机为 "broken.example.com"，端口为 80，直到某个特定时间戳之前都是失败的，并且失败次数为 3。

**用户或编程常见的使用错误 (可能导致问题):**

* **偏好设置数据损坏:**  用户手动修改或第三方软件损坏了 Chrome 的偏好设置文件，导致 `http_server_properties` 部分的数据格式不正确。这会导致 `ReadPrefs` 函数解析失败，可能会清空或忽略这些属性。
* **版本不匹配:**  如果在 Chrome 的不同版本之间偏好设置的格式发生了重大变化，旧版本的偏好设置可能会被新版本识别为无效，导致数据丢失或行为异常。
* **错误的类型转换:**  在解析偏好设置数据时，如果数据类型与代码期望的类型不符（例如，期望是整数但存储的是字符串），会导致解析错误。
* **缺少必要的字段:**  如果偏好设置中缺少某些必要的字段（例如，替代服务的协议或端口），会导致解析失败并可能忽略整个条目。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户启动 Chrome 浏览器:**  在启动时，Chrome 会加载用户的偏好设置，其中就包括 HTTP 服务器属性。
2. **用户访问一个 HTTPS 网站 (例如，`https://example.com`):**
3. **浏览器尝试建立连接:**  `HttpNetworkTransaction` 或其他网络组件会查找 `HttpServerProperties` 中是否存储了与 `example.com` 相关的属性。
4. **如果需要读取偏好设置 (通常是首次访问或缓存过期):**  `HttpServerPropertiesManager` 的 `ReadPrefs` 函数会被调用，从偏好设置中加载 HTTP 服务器属性。
5. **`ReadPrefs` 函数会按照以下步骤读取数据:**
    * 读取版本号。
    * 遍历 `servers` 列表，解析每个服务器的属性，包括 SPDY 支持和替代服务。
    * 遍历 `quic_servers` 列表，解析 QUIC 服务器信息。
    * 遍历 `broken_alternative_services` 列表，解析失败的替代服务信息。
6. **读取的数据被存储在内存中的 `HttpServerProperties` 对象中。**
7. **后续对 `example.com` 的请求可以使用这些缓存的属性来优化连接。**

**总结：**

`HttpServerPropertiesManager` 的核心功能是负责将持久化的 HTTP 服务器属性（如替代服务、QUIC 支持等）从用户的偏好设置中读取出来，并加载到内存中，供 Chrome 的网络栈在建立连接时使用，从而提升网络性能和用户体验。  第 1 部分的代码主要关注反序列化（读取）过程。

Prompt: 
```
这是目录为net/http/http_server_properties_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <algorithm>
#include <optional>
#include <utility>

#include "base/containers/adapters.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/http/http_server_properties.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_hostname_utils.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

// "version" 0 indicates, http_server_properties doesn't have "version"
// property.
const int kMissingVersion = 0;

// The version number of persisted http_server_properties.
const int kVersionNumber = 5;

// Persist at most 200 currently-broken alternative services to disk.
const int kMaxBrokenAlternativeServicesToPersist = 200;

const char kServerKey[] = "server";
const char kQuicServerIdKey[] = "server_id";
const char kNetworkAnonymizationKey[] = "anonymization";
const char kVersionKey[] = "version";
const char kServersKey[] = "servers";
const char kSupportsSpdyKey[] = "supports_spdy";
const char kSupportsQuicKey[] = "supports_quic";
const char kQuicServers[] = "quic_servers";
const char kServerInfoKey[] = "server_info";
const char kUsedQuicKey[] = "used_quic";
const char kAddressKey[] = "address";
const char kAlternativeServiceKey[] = "alternative_service";
const char kProtocolKey[] = "protocol_str";
const char kHostKey[] = "host";
const char kPortKey[] = "port";
const char kExpirationKey[] = "expiration";
const char kAdvertisedAlpnsKey[] = "advertised_alpns";
const char kNetworkStatsKey[] = "network_stats";
const char kSrttKey[] = "srtt";
const char kBrokenAlternativeServicesKey[] = "broken_alternative_services";
const char kBrokenUntilKey[] = "broken_until";
const char kBrokenCountKey[] = "broken_count";

// Utility method to return only those AlternativeServiceInfos that should be
// persisted to disk. In particular, removes expired and invalid alternative
// services. Also checks if an alternative service for the same canonical suffix
// has already been saved, and if so, returns an empty list.
AlternativeServiceInfoVector GetAlternativeServiceToPersist(
    const std::optional<AlternativeServiceInfoVector>& alternative_services,
    const HttpServerProperties::ServerInfoMapKey& server_info_key,
    base::Time now,
    const HttpServerPropertiesManager::GetCannonicalSuffix&
        get_canonical_suffix,
    std::set<std::pair<std::string, NetworkAnonymizationKey>>*
        persisted_canonical_suffix_set) {
  if (!alternative_services)
    return AlternativeServiceInfoVector();
  // Separate out valid, non-expired AlternativeServiceInfo entries.
  AlternativeServiceInfoVector notbroken_alternative_service_info_vector;
  for (const auto& alternative_service_info : alternative_services.value()) {
    if (alternative_service_info.expiration() < now ||
        !IsAlternateProtocolValid(
            alternative_service_info.alternative_service().protocol)) {
      continue;
    }
    notbroken_alternative_service_info_vector.push_back(
        alternative_service_info);
  }
  if (notbroken_alternative_service_info_vector.empty())
    return notbroken_alternative_service_info_vector;
  const std::string* canonical_suffix =
      get_canonical_suffix.Run(server_info_key.server.host());
  if (canonical_suffix) {
    // Don't save if have already saved information associated with the same
    // canonical suffix.
    std::pair<std::string, NetworkAnonymizationKey> index(
        *canonical_suffix, server_info_key.network_anonymization_key);
    if (persisted_canonical_suffix_set->find(index) !=
        persisted_canonical_suffix_set->end()) {
      return AlternativeServiceInfoVector();
    }
    persisted_canonical_suffix_set->emplace(std::move(index));
  }
  return notbroken_alternative_service_info_vector;
}

void AddAlternativeServiceFieldsToDictionaryValue(
    const AlternativeService& alternative_service,
    base::Value::Dict& dict) {
  dict.Set(kPortKey, alternative_service.port);
  if (!alternative_service.host.empty()) {
    dict.Set(kHostKey, alternative_service.host);
  }
  dict.Set(kProtocolKey, NextProtoToString(alternative_service.protocol));
}

// Fails in the case of NetworkAnonymizationKeys that can't be persisted to
// disk, like unique origins.
bool TryAddBrokenAlternativeServiceFieldsToDictionaryValue(
    const BrokenAlternativeService& broken_alt_service,
    base::Value::Dict& dict) {
  base::Value network_anonymization_key_value;
  if (!broken_alt_service.network_anonymization_key.ToValue(
          &network_anonymization_key_value)) {
    return false;
  }

  dict.Set(kNetworkAnonymizationKey,
           std::move(network_anonymization_key_value));
  AddAlternativeServiceFieldsToDictionaryValue(
      broken_alt_service.alternative_service, dict);
  return true;
}

static constexpr std::string_view kPrivacyModeDisabledPath = "/";
static constexpr std::string_view kPrivacyModeEnabledPath = "/private";
static constexpr std::string_view kPrivacyModeEnabledWithoutClientCertsPath =
    "/private_without_client_certs";
static constexpr std::string_view
    kPrivacyModeEnabledPartitionedStateAllowedPath =
        "/private_partitioned_state_allowed";

std::string_view PrivacyModeToPathString(PrivacyMode privacy_mode) {
  switch (privacy_mode) {
    case PRIVACY_MODE_DISABLED:
      NOTREACHED();
    case PRIVACY_MODE_ENABLED:
      return kPrivacyModeEnabledPath;
    case PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS:
      return kPrivacyModeEnabledWithoutClientCertsPath;
    case PRIVACY_MODE_ENABLED_PARTITIONED_STATE_ALLOWED:
      return kPrivacyModeEnabledPartitionedStateAllowedPath;
  }
}

std::optional<PrivacyMode> PrivacyModeFromPathString(std::string_view path) {
  if (path == kPrivacyModeDisabledPath) {
    return PRIVACY_MODE_DISABLED;
  } else if (path == kPrivacyModeEnabledPath) {
    return PRIVACY_MODE_ENABLED;
  } else if (path == kPrivacyModeEnabledWithoutClientCertsPath) {
    return PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  } else if (path == kPrivacyModeEnabledPartitionedStateAllowedPath) {
    return PRIVACY_MODE_ENABLED_PARTITIONED_STATE_ALLOWED;
  }
  return std::nullopt;
}

struct QuicServerIdAndPrivacyMode {
  quic::QuicServerId server_id;
  PrivacyMode privacy_mode = PRIVACY_MODE_DISABLED;
};

std::optional<QuicServerIdAndPrivacyMode> QuicServerIdFromString(
    const std::string& str) {
  GURL url(str);
  if (!url.is_valid()) {
    return std::nullopt;
  }
  std::optional<PrivacyMode> privacy_mode =
      PrivacyModeFromPathString(url.path_piece());
  if (!privacy_mode.has_value()) {
    return std::nullopt;
  }

  HostPortPair host_port_pair = HostPortPair::FromURL(url);

  return QuicServerIdAndPrivacyMode{
      quic::QuicServerId(host_port_pair.host(), host_port_pair.port()),
      *privacy_mode};
}

std::string QuicServerIdToString(const quic::QuicServerId& server_id,
                                 PrivacyMode privacy_mode) {
  return base::StrCat({"https://", server_id.ToHostPortString(),
                       privacy_mode == PRIVACY_MODE_DISABLED
                           ? ""
                           : PrivacyModeToPathString(privacy_mode)});
}

// Takes in a base::Value::Dict, and whether NetworkAnonymizationKeys are
// enabled for HttpServerProperties, and extracts the NetworkAnonymizationKey
// stored with the `kNetworkAnonymizationKey` in the dictionary, and writes it
// to `out_network_anonymization_key`. Returns false if unable to load a
// NetworkAnonymizationKey, or the NetworkAnonymizationKey is non-empty, but
// `use_network_anonymization_key` is false.
bool GetNetworkAnonymizationKeyFromDict(
    const base::Value::Dict& dict,
    bool use_network_anonymization_key,
    NetworkAnonymizationKey* out_network_anonymization_key) {
  const base::Value* network_anonymization_key_value =
      dict.Find(kNetworkAnonymizationKey);
  NetworkAnonymizationKey network_anonymization_key;
  if (!network_anonymization_key_value ||
      !NetworkAnonymizationKey::FromValue(*network_anonymization_key_value,
                                          &network_anonymization_key)) {
    return false;
  }

  // Fail if NetworkAnonymizationKeys are disabled, but the entry has a
  // non-empty NetworkAnonymizationKey.
  if (!use_network_anonymization_key && !network_anonymization_key.IsEmpty())
    return false;

  *out_network_anonymization_key = std::move(network_anonymization_key);
  return true;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//  HttpServerPropertiesManager

HttpServerPropertiesManager::HttpServerPropertiesManager(
    std::unique_ptr<HttpServerProperties::PrefDelegate> pref_delegate,
    OnPrefsLoadedCallback on_prefs_loaded_callback,
    size_t max_server_configs_stored_in_properties,
    NetLog* net_log,
    const base::TickClock* clock)
    : pref_delegate_(std::move(pref_delegate)),
      on_prefs_loaded_callback_(std::move(on_prefs_loaded_callback)),
      max_server_configs_stored_in_properties_(
          max_server_configs_stored_in_properties),
      clock_(clock),
      net_log_(
          NetLogWithSource::Make(net_log,
                                 NetLogSourceType::HTTP_SERVER_PROPERTIES)) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(pref_delegate_);
  DCHECK(on_prefs_loaded_callback_);
  DCHECK(clock_);

  pref_delegate_->WaitForPrefLoad(
      base::BindOnce(&HttpServerPropertiesManager::OnHttpServerPropertiesLoaded,
                     pref_load_weak_ptr_factory_.GetWeakPtr()));
  net_log_.BeginEvent(NetLogEventType::HTTP_SERVER_PROPERTIES_INITIALIZATION);
}

HttpServerPropertiesManager::~HttpServerPropertiesManager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void HttpServerPropertiesManager::ReadPrefs(
    std::unique_ptr<HttpServerProperties::ServerInfoMap>* server_info_map,
    IPAddress* last_local_address_when_quic_worked,
    std::unique_ptr<HttpServerProperties::QuicServerInfoMap>*
        quic_server_info_map,
    std::unique_ptr<BrokenAlternativeServiceList>*
        broken_alternative_service_list,
    std::unique_ptr<RecentlyBrokenAlternativeServices>*
        recently_broken_alternative_services) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  net_log_.EndEvent(NetLogEventType::HTTP_SERVER_PROPERTIES_INITIALIZATION);

  const base::Value::Dict& http_server_properties_dict =
      pref_delegate_->GetServerProperties();

  net_log_.AddEvent(NetLogEventType::HTTP_SERVER_PROPERTIES_UPDATE_CACHE,
                    [&] { return http_server_properties_dict.Clone(); });
  std::optional<int> maybe_version_number =
      http_server_properties_dict.FindInt(kVersionKey);
  if (!maybe_version_number.has_value() ||
      *maybe_version_number != kVersionNumber) {
    DVLOG(1) << "Missing or unsupported. Clearing all properties. "
             << maybe_version_number.value_or(kMissingVersion);
    return;
  }

  // For Version 5, data is stored in the following format.
  // `servers` are saved in LRU order (least-recently-used item is in the
  // front). `servers` are in the format flattened representation of
  // (scheme/host/port) where port might be ignored if is default with scheme.
  //
  // "http_server_properties": {
  //      "servers": [
  //          {"https://yt3.ggpht.com" : {...}},
  //          {"http://0.client-channel.google.com:443" : {...}},
  //          {"http://0-edge-chat.facebook.com" : {...}},
  //          ...
  //      ], ...
  // },
  const base::Value::List* servers_list =
      http_server_properties_dict.FindList(kServersKey);
  if (!servers_list) {
    DVLOG(1) << "Malformed http_server_properties for servers list.";
    return;
  }

  ReadLastLocalAddressWhenQuicWorked(http_server_properties_dict,
                                     last_local_address_when_quic_worked);

  *server_info_map = std::make_unique<HttpServerProperties::ServerInfoMap>();
  *quic_server_info_map =
      std::make_unique<HttpServerProperties::QuicServerInfoMap>(
          max_server_configs_stored_in_properties_);

  bool use_network_anonymization_key =
      NetworkAnonymizationKey::IsPartitioningEnabled();

  // Iterate `servers_list` (least-recently-used item is in the front) so that
  // entries are inserted into `server_info_map` from oldest to newest.
  for (const auto& server_dict_value : *servers_list) {
    if (!server_dict_value.is_dict()) {
      DVLOG(1) << "Malformed http_server_properties for servers dictionary.";
      continue;
    }
    AddServerData(server_dict_value.GetDict(), server_info_map->get(),
                  use_network_anonymization_key);
  }

  AddToQuicServerInfoMap(http_server_properties_dict,
                         use_network_anonymization_key,
                         quic_server_info_map->get());

  // Read list containing broken and recently-broken alternative services, if
  // it exists.
  const base::Value::List* broken_alt_svc_list =
      http_server_properties_dict.FindList(kBrokenAlternativeServicesKey);
  if (broken_alt_svc_list) {
    *broken_alternative_service_list =
        std::make_unique<BrokenAlternativeServiceList>();
    *recently_broken_alternative_services =
        std::make_unique<RecentlyBrokenAlternativeServices>(
            kMaxRecentlyBrokenAlternativeServiceEntries);

    // Iterate `broken_alt_svc_list` (least-recently-used item is in the front)
    // so that entries are inserted into `recently_broken_alternative_services`
    // from oldest to newest.
    for (const auto& broken_alt_svc_entry_dict_value : *broken_alt_svc_list) {
      if (!broken_alt_svc_entry_dict_value.is_dict()) {
        DVLOG(1) << "Malformed broken alterantive service entry.";
        continue;
      }
      AddToBrokenAlternativeServices(
          broken_alt_svc_entry_dict_value.GetDict(),
          use_network_anonymization_key, broken_alternative_service_list->get(),
          recently_broken_alternative_services->get());
    }
  }

  // Set the properties loaded from prefs on |http_server_properties_impl_|.

  UMA_HISTOGRAM_COUNTS_1000("Net.CountOfQuicServerInfos",
                            (*quic_server_info_map)->size());

  if (*recently_broken_alternative_services) {
    DCHECK(*broken_alternative_service_list);

    UMA_HISTOGRAM_COUNTS_1000("Net.CountOfBrokenAlternativeServices",
                              (*broken_alternative_service_list)->size());
    UMA_HISTOGRAM_COUNTS_1000("Net.CountOfRecentlyBrokenAlternativeServices",
                              (*recently_broken_alternative_services)->size());
  }
}

void HttpServerPropertiesManager::AddToBrokenAlternativeServices(
    const base::Value::Dict& broken_alt_svc_entry_dict,
    bool use_network_anonymization_key,
    BrokenAlternativeServiceList* broken_alternative_service_list,
    RecentlyBrokenAlternativeServices* recently_broken_alternative_services) {
  AlternativeService alt_service;
  if (!ParseAlternativeServiceDict(broken_alt_svc_entry_dict, false,
                                   "broken alternative services",
                                   &alt_service)) {
    return;
  }

  NetworkAnonymizationKey network_anonymization_key;
  if (!GetNetworkAnonymizationKeyFromDict(broken_alt_svc_entry_dict,
                                          use_network_anonymization_key,
                                          &network_anonymization_key)) {
    return;
  }

  // Each entry must contain either broken-count and/or broken-until fields.
  bool contains_broken_count_or_broken_until = false;

  // Read broken-count and add an entry for |alt_service| into
  // |recently_broken_alternative_services|.
  if (broken_alt_svc_entry_dict.Find(kBrokenCountKey)) {
    std::optional<int> broken_count =
        broken_alt_svc_entry_dict.FindInt(kBrokenCountKey);
    if (!broken_count.has_value()) {
      DVLOG(1) << "Recently broken alternative service has malformed "
               << "broken-count.";
      return;
    }
    if (broken_count.value() < 0) {
      DVLOG(1) << "Broken alternative service has negative broken-count.";
      return;
    }
    recently_broken_alternative_services->Put(
        BrokenAlternativeService(alt_service, network_anonymization_key,
                                 use_network_anonymization_key),
        broken_count.value());
    contains_broken_count_or_broken_until = true;
  }

  // Read broken-until and add an entry for |alt_service| in
  // |broken_alternative_service_list|.
  if (broken_alt_svc_entry_dict.Find(kBrokenUntilKey)) {
    const std::string* expiration_string =
        broken_alt_svc_entry_dict.FindString(kBrokenUntilKey);
    int64_t expiration_int64;
    if (!expiration_string ||
        !base::StringToInt64(*expiration_string, &expiration_int64)) {
      DVLOG(1) << "Broken alternative service has malformed broken-until "
               << "string.";
      return;
    }

    time_t expiration_time_t = static_cast<time_t>(expiration_int64);
    // Convert expiration from time_t to Time to TimeTicks
    base::TimeTicks expiration_time_ticks =
        clock_->NowTicks() +
        (base::Time::FromTimeT(expiration_time_t) - base::Time::Now());
    broken_alternative_service_list->emplace_back(
        BrokenAlternativeService(alt_service, network_anonymization_key,
                                 use_network_anonymization_key),
        expiration_time_ticks);
    contains_broken_count_or_broken_until = true;
  }

  if (!contains_broken_count_or_broken_until) {
    DVLOG(1) << "Broken alternative service has neither broken-count nor "
             << "broken-until specified.";
  }
}

void HttpServerPropertiesManager::AddServerData(
    const base::Value::Dict& server_dict,
    HttpServerProperties::ServerInfoMap* server_info_map,
    bool use_network_anonymization_key) {
  // Get server's scheme/host/pair.
  const std::string* server_str = server_dict.FindString(kServerKey);
  NetworkAnonymizationKey network_anonymization_key;
  // Can't load entry if server name missing, or if the network anonymization
  // key is missing or invalid.
  if (!server_str || !GetNetworkAnonymizationKeyFromDict(
                         server_dict, use_network_anonymization_key,
                         &network_anonymization_key)) {
    return;
  }

  url::SchemeHostPort spdy_server((GURL(*server_str)));
  if (spdy_server.host().empty()) {
    DVLOG(1) << "Malformed http_server_properties for server: " << server_str;
    return;
  }

  HttpServerProperties::ServerInfo server_info;

  server_info.supports_spdy = server_dict.FindBool(kSupportsSpdyKey);

  if (ParseAlternativeServiceInfo(spdy_server, server_dict, &server_info))
    ParseNetworkStats(spdy_server, server_dict, &server_info);

  if (!server_info.empty()) {
    server_info_map->Put(HttpServerProperties::ServerInfoMapKey(
                             std::move(spdy_server), network_anonymization_key,
                             use_network_anonymization_key),
                         std::move(server_info));
  }
}

bool HttpServerPropertiesManager::ParseAlternativeServiceDict(
    const base::Value::Dict& dict,
    bool host_optional,
    const std::string& parsing_under,
    AlternativeService* alternative_service) {
  // Protocol is mandatory.
  const std::string* protocol_str = dict.FindString(kProtocolKey);
  if (!protocol_str) {
    DVLOG(1) << "Malformed alternative service protocol string under: "
             << parsing_under;
    return false;
  }
  NextProto protocol = NextProtoFromString(*protocol_str);
  if (!IsAlternateProtocolValid(protocol)) {
    DVLOG(1) << "Invalid alternative service protocol string \"" << protocol_str
             << "\" under: " << parsing_under;
    return false;
  }
  alternative_service->protocol = protocol;

  // If host is optional, it defaults to "".
  std::string host = "";
  const std::string* hostp = nullptr;
  if (dict.Find(kHostKey)) {
    hostp = dict.FindString(kHostKey);
    if (!hostp) {
      DVLOG(1) << "Malformed alternative service host string under: "
               << parsing_under;
      return false;
    }
    host = *hostp;
  } else if (!host_optional) {
    DVLOG(1) << "alternative service missing host string under: "
             << parsing_under;
    return false;
  }
  alternative_service->host = host;

  // Port is mandatory.
  std::optional<int> maybe_port = dict.FindInt(kPortKey);
  if (!maybe_port.has_value() || !IsPortValid(maybe_port.value())) {
    DVLOG(1) << "Malformed alternative service port under: " << parsing_under;
    return false;
  }
  alternative_service->port = static_cast<uint32_t>(maybe_port.value());

  return true;
}

bool HttpServerPropertiesManager::ParseAlternativeServiceInfoDictOfServer(
    const base::Value::Dict& dict,
    const std::string& server_str,
    AlternativeServiceInfo* alternative_service_info) {
  AlternativeService alternative_service;
  if (!ParseAlternativeServiceDict(dict, true, "server " + server_str,
                                   &alternative_service)) {
    return false;
  }
  alternative_service_info->set_alternative_service(alternative_service);

  // Expiration is optional, defaults to one day.
  if (!dict.Find(kExpirationKey)) {
    alternative_service_info->set_expiration(base::Time::Now() + base::Days(1));
  } else {
    const std::string* expiration_string = dict.FindString(kExpirationKey);
    if (expiration_string) {
      int64_t expiration_int64 = 0;
      if (!base::StringToInt64(*expiration_string, &expiration_int64)) {
        DVLOG(1) << "Malformed alternative service expiration for server: "
                 << server_str;
        return false;
      }
      alternative_service_info->set_expiration(
          base::Time::FromInternalValue(expiration_int64));
    } else {
      DVLOG(1) << "Malformed alternative service expiration for server: "
               << server_str;
      return false;
    }
  }

  // Advertised versions list is optional.
  if (dict.Find(kAdvertisedAlpnsKey)) {
    const base::Value::List* versions_list = dict.FindList(kAdvertisedAlpnsKey);
    if (!versions_list) {
      DVLOG(1) << "Malformed alternative service advertised versions list for "
               << "server: " << server_str;
      return false;
    }
    quic::ParsedQuicVersionVector advertised_versions;
    for (const auto& value : *versions_list) {
      const std::string* version_string = value.GetIfString();
      if (!version_string) {
        DVLOG(1) << "Malformed alternative service version for server: "
                 << server_str;
        return false;
      }
      quic::ParsedQuicVersion version =
          quic::ParseQuicVersionString(*version_string);
      if (version != quic::ParsedQuicVersion::Unsupported()) {
        advertised_versions.push_back(version);
      }
    }
    alternative_service_info->set_advertised_versions(advertised_versions);
  }

  return true;
}

bool HttpServerPropertiesManager::ParseAlternativeServiceInfo(
    const url::SchemeHostPort& server,
    const base::Value::Dict& server_pref_dict,
    HttpServerProperties::ServerInfo* server_info) {
  DCHECK(!server_info->alternative_services.has_value());
  const base::Value::List* alternative_service_list =
      server_pref_dict.FindList(kAlternativeServiceKey);
  if (!alternative_service_list) {
    return true;
  }
  if (server.scheme() != "https") {
    return false;
  }

  AlternativeServiceInfoVector alternative_service_info_vector;
  for (const auto& alternative_service_list_item : *alternative_service_list) {
    if (!alternative_service_list_item.is_dict())
      return false;
    AlternativeServiceInfo alternative_service_info;
    if (!ParseAlternativeServiceInfoDictOfServer(
            alternative_service_list_item.GetDict(), server.Serialize(),
            &alternative_service_info)) {
      return false;
    }
    if (base::Time::Now() < alternative_service_info.expiration()) {
      alternative_service_info_vector.push_back(alternative_service_info);
    }
  }

  if (alternative_service_info_vector.empty()) {
    return false;
  }

  server_info->alternative_services = alternative_service_info_vector;
  return true;
}

void HttpServerPropertiesManager::ReadLastLocalAddressWhenQuicWorked(
    const base::Value::Dict& http_server_properties_dict,
    IPAddress* last_local_address_when_quic_worked) {
  const base::Value::Dict* supports_quic_dict =
      http_server_properties_dict.FindDict(kSupportsQuicKey);
  if (!supports_quic_dict) {
    return;
  }
  const base::Value* used_quic = supports_quic_dict->Find(kUsedQuicKey);
  if (!used_quic || !used_quic->is_bool()) {
    DVLOG(1) << "Malformed SupportsQuic";
    return;
  }
  if (!used_quic->GetBool())
    return;

  const std::string* address = supports_quic_dict->FindString(kAddressKey);
  if (!address ||
      !last_local_address_when_quic_worked->AssignFromIPLiteral(*address)) {
    DVLOG(1) << "Malformed SupportsQuic";
  }
}

void HttpServerPropertiesManager::ParseNetworkStats(
    const url::SchemeHostPort& server,
    const base::Value::Dict& server_pref_dict,
    HttpServerProperties::ServerInfo* server_info) {
  DCHECK(!server_info->server_network_stats.has_value());
  const base::Value::Dict* server_network_stats_dict =
      server_pref_dict.FindDict(kNetworkStatsKey);
  if (!server_network_stats_dict) {
    return;
  }
  std::optional<int> maybe_srtt = server_network_stats_dict->FindInt(kSrttKey);
  if (!maybe_srtt.has_value()) {
    DVLOG(1) << "Malformed ServerNetworkStats for server: "
             << server.Serialize();
    return;
  }
  ServerNetworkStats server_network_stats;
  server_network_stats.srtt = base::Microseconds(maybe_srtt.value());
  // TODO(rtenneti): When QUIC starts using bandwidth_estimate, then persist
  // bandwidth_estimate.
  server_info->server_network_stats = server_network_stats;
}

void HttpServerPropertiesManager::AddToQuicServerInfoMap(
    const base::Value::Dict& http_server_properties_dict,
    bool use_network_anonymization_key,
    HttpServerProperties::QuicServerInfoMap* quic_server_info_map) {
  const base::Value::List* quic_server_info_list =
      http_server_properties_dict.FindList(kQuicServers);
  if (!quic_server_info_list) {
    DVLOG(1) << "Malformed http_server_properties for quic_servers.";
    return;
  }

  for (const auto& quic_server_info_value : *quic_server_info_list) {
    const base::Value::Dict* quic_server_info_dict =
        quic_server_info_value.GetIfDict();
    if (!quic_server_info_dict)
      continue;

    const std::string* quic_server_id_str =
        quic_server_info_dict->FindString(kQuicServerIdKey);
    if (!quic_server_id_str || quic_server_id_str->empty())
      continue;

    std::optional<QuicServerIdAndPrivacyMode> result =
        QuicServerIdFromString(*quic_server_id_str);
    if (!result.has_value()) {
      DVLOG(1) << "Malformed http_server_properties for quic server: "
               << quic_server_id_str;
      continue;
    }
    auto [quic_server_id, privacy_mode] = *result;

    NetworkAnonymizationKey network_anonymization_key;
    if (!GetNetworkAnonymizationKeyFromDict(*quic_server_info_dict,
                                            use_network_anonymization_key,
                                            &network_anonymization_key)) {
      DVLOG(1) << "Malformed http_server_properties quic server dict: "
               << *quic_server_id_str;
      continue;
    }

    const std::string* quic_server_info =
        quic_server_info_dict->FindString(kServerInfoKey);
    if (!quic_server_info) {
      DVLOG(1) << "Malformed http_server_properties quic server info: "
               << *quic_server_id_str;
      continue;
    }
    quic_server_info_map->Put(
        HttpServerProperties::QuicServerInfoMapKey(
            quic_server_id, privacy_mode, network_anonymization_key,
            use_network_anonymization_key),
        *quic_server_info);
  }
}

void HttpServerPropertiesManager::WriteToPrefs(
    const HttpServerProperties::ServerInfoMap& server_info_map,
    const GetCannonicalSuffix& get_canonical_suffix,
    const IPAddress& last_local_address_when_quic_worked,
    const HttpServerProperties::QuicServerInfoMap& quic_server_info_map,
    const BrokenAlternativeServiceList& broken_alternative_service_list,
    const RecentlyBrokenAlternativeServices&
        recently_broken_alternative_services,
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // If loading prefs hasn't completed, don't call it, since this will overwrite
  // existing prefs.
  on_prefs_loaded_callback_.Reset();

  std::set<std::pair<std::string, NetworkAnonymizationKey>>
      persisted_canonical_suffix_set;
  const base::Time now = base::Time::Now();
  base::Value::Dict http_server_properties_dict;

  // Convert |server_info_map| to a list Value and add it to
  // |http_server_properties_dict|.
  base::Value::List servers_list;
  for (const auto& [key, server_info] : server_info_map) {
    // If can't convert the NetworkAnonymizationKey to a value, don't save to
    // disk. Generally happens because the key is for a unique origin.
    base::Value network_anonymization_key_value;
    if (!key.network_anonymization_key.ToValue(
            &network_anonymization_key_value)) {
      continue;
    }

    base::Value::Dict server_dict;

    bool supports_spdy = server_info.supports_spdy.value_or(false);
    if (supports_spdy)
      server_dict.Set(kSupportsSpdyKey, supports_spdy);

    AlternativeServiceInfoVector alternative_services =
        GetAlternativeServiceToPersist(server_info.alternative_services, key,
                                       now, get_canonical_suffix,
                                       &persisted_canonical_suffix_set);
    if (!alternative_services.empty())
      SaveAlternativeServiceToServerPrefs(alternative_services, server_dict);

    if (server_info.server_network_stats) {
      SaveNetworkStatsToServerPrefs(*server_info.server_network_stats,
                                    server_dict);
    }

    // Don't add empty entries. This can happen if, for example, all alternative
    // services are empty, or |supports_spdy| is set to false, and all other
    // fields are not set.
    if (server_dict.empty())
      continue;
    server_dict.Set(kServerKey, key.server.Serialize());
    server_dict.Set(kNetworkAnonymizationKey,
                    std::move(network_anonymization_key_value));
    servers_list.Append(std::move(server_dict));
  }
  // Reverse `servers_list`. The least recently used item will be in the front.
  std::reverse(servers_list.begin(), servers_list.end());

  http_server_properties_dict.Set(kServersKey, std::move(servers_list));

  http_server_properties_dict.Set(kVersionKey, kVersionNumber);

  SaveLastLocalAddressWhenQuicWorkedToPrefs(last_local_address_when_quic_worked,
                                            http_server_properties_dict);

  SaveQuicServerInfoMapToServerPrefs(quic_server_info_map,
                                     http_server_properties_dict);

  SaveBrokenAlternativeServicesToPrefs(
      broken_alternative_service_list, kMaxBrokenAlternativeServicesToPersist,
      recently_broken_alternative_services, http_server_properties_dict);

  net_log_.AddEvent(NetLogEventType::HTTP_SERVER_PROPERTIES_UPDATE_PREFS,
                    [&] { return http_server_properties_dict.Clone(); });

  pref_delegate_->SetServerProperties(std::move(http_server_properties_dict),
                                      std::move(callback));
}

void HttpServerPropertiesManager::SaveAlternativeServiceToServerPrefs(
    const AlternativeServiceInfoVector& alternative_service_info_vector,
    base::Value::Dict& server_pref_dict) {
  if (alternative_service_info_vector.empty()) {
    return;
  }
  base::Value::List alternative_service_list;
  for (const AlternativeServiceInfo& alternative_service_info :
       alternative_service_info_vector) {
    const AlternativeService& alternative_service =
        alternative_service_info.alternative_service();
    DCHECK(IsAlternateProtocolValid(alternative_service.protocol));
    base::Value::Dict alternative_service_dict;
    AddAlter
"""


```