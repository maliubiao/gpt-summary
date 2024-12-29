Response:
Let's break down the thought process for analyzing the given C++ code.

**1. Understanding the Goal:**

The primary goal is to analyze the `host_resolver_internal_result.cc` file from Chromium's network stack. This involves identifying its purpose, its relationship with JavaScript (if any), logical deductions, potential user errors, and debugging context.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable patterns and keywords:

* **Headers:** `#include` directives indicate dependencies. We see standard C++ headers (`<map>`, `<memory>`, etc.) and Chromium-specific headers (`base/...`, `net/...`, `url/...`). This immediately tells us it's part of Chromium's networking layer and likely deals with DNS resolution.
* **Namespaces:** The code is within the `net` namespace, reinforcing the networking aspect.
* **Class Names:** `HostResolverInternalResult`, `HostResolverInternalDataResult`, `HostResolverInternalMetadataResult`, `HostResolverInternalErrorResult`, `HostResolverInternalAliasResult`. The naming suggests a hierarchy of results from an internal host resolution process. The different suffixes (`Data`, `Metadata`, `Error`, `Alias`) hint at different types of resolution outcomes.
* **`FromValue` and `ToValue`:** These static methods strongly suggest a mechanism for serializing and deserializing these result objects to/from `base::Value`. `base::Value` is a common way in Chromium to represent structured data (like JSON).
* **Member Variables:**  Looking at the constructors and member initializations gives clues about the data each result type holds. For example, `HostResolverInternalDataResult` has `endpoints_`, `strings_`, and `hosts_`.
* **`MaybeCanonicalizeName`:** This function suggests handling domain name canonicalization, a common DNS-related task.
* **`DCHECK`:** These are debug-only checks, helping understand assumptions within the code.
* **Constants:** `kValueDomainNameKey`, `kValueQueryTypeKey`, etc. These string constants are likely used as keys when converting to/from `base::Value`. They resemble JSON keys.

**3. Identifying Core Functionality:**

Based on the initial scan, the core functionality seems to be:

* **Representing different outcomes of internal host resolution:**  Success with IP addresses, metadata (like HTTPS records), errors, or aliases (CNAMEs).
* **Data structure for these results:** The various `HostResolverInternal...Result` classes act as containers for this information.
* **Serialization/Deserialization:** The `FromValue` and `ToValue` methods enable converting these result objects to a common `base::Value` representation, likely for inter-process communication, caching, or logging.

**4. Analyzing Individual Result Types:**

Now, let's delve deeper into each result type:

* **`HostResolverInternalResult` (Base Class):**  Holds common information like the domain name, query type, expiration, and source of the resolution.
* **`HostResolverInternalDataResult`:** Represents a successful resolution with IP endpoints, strings (likely for SRV records), and host/port pairs.
* **`HostResolverInternalMetadataResult`:**  Stores metadata associated with the resolution, particularly HTTPS record priority and connection endpoint metadata.
* **`HostResolverInternalErrorResult`:**  Indicates a resolution failure, storing the specific network error code.
* **`HostResolverInternalAliasResult`:** Represents a CNAME record, storing the target hostname.

**5. Examining the `FromValue` and `ToValue` Logic:**

These methods are crucial. They reveal how the data is structured when serialized. Notice how they use the `kValue...Key` constants as keys in the `base::Value::Dict`. This confirms the likely use of a JSON-like structure.

**6. Considering the JavaScript Connection:**

Think about how DNS resolution interacts with the browser and JavaScript. JavaScript doesn't directly perform low-level DNS lookups. It relies on the browser's network stack. Therefore, this C++ code is *part of* the browser's network stack that *supports* JavaScript's networking needs.

* **Example:** When JavaScript uses `fetch()` to access a website, the browser's network stack (including the host resolver) will be involved in resolving the domain name. The results represented by these classes will be used internally.

**7. Developing Logical Inferences and Examples:**

Think about concrete scenarios:

* **Successful DNS Lookup (A record):** Input: "example.com", Type: A. Output: `HostResolverInternalDataResult` with IP addresses.
* **HTTPS Record Lookup:** Input: "example.com", Type: HTTPS. Output: `HostResolverInternalMetadataResult` with HTTPS record data.
* **Resolution Error:** Input: "nonexistent.com". Output: `HostResolverInternalErrorResult` with `net::ERR_NAME_NOT_RESOLVED`.
* **CNAME:** Input: "www.example.com" (CNAME to "example.net"). Output: `HostResolverInternalAliasResult` with target "example.net", followed by another resolution for "example.net".

**8. Identifying Potential User/Programming Errors:**

Focus on common mistakes related to DNS and networking:

* **Incorrect Hostnames:**  Typing a wrong website address.
* **Network Connectivity Issues:** If the device isn't connected to the internet, DNS resolution will fail.
* **Firewall/Proxy Issues:** These can block DNS queries.
* **Misconfigured Hosts File:** The `Source::kHosts` case highlights this.

**9. Tracing User Actions to the Code:**

Think about the steps a user takes that lead to DNS resolution:

1. **User types a URL in the address bar or clicks a link.**
2. **The browser parses the URL and extracts the hostname.**
3. **The network stack initiates host resolution for that hostname.**
4. **This code (`host_resolver_internal_result.cc`) is involved in representing the outcome of that resolution.**

**10. Structuring the Answer:**

Organize the findings into clear sections: Functionality, JavaScript Relationship, Logical Inferences, User Errors, and Debugging Context. Use clear and concise language, providing examples where necessary. Use formatting (like bullet points and code blocks) to enhance readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This might directly interface with JavaScript."  **Correction:** Realized it's an internal part of the browser's network stack that *supports* JavaScript's networking.
* **Initial thought:**  Focus heavily on the serialization format. **Refinement:**  Balance the focus on serialization with the overall purpose of representing different resolution outcomes.
* **Double-checking assumptions:**  Confirm that `base::Value` is indeed used for data serialization in Chromium.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive and accurate explanation of its functionality and context.
这个文件 `net/dns/host_resolver_internal_result.cc` 定义了一系列 C++ 类，用于表示 Chromium 网络栈内部主机名解析器的结果。 它的主要功能是作为一个结构化的容器，存储不同类型的 DNS 查询结果，以及与这些结果相关的元数据和错误信息。

**具体功能如下：**

1. **定义主机名解析的内部结果类型:**
   - `HostResolverInternalResult` 是一个基类，定义了所有主机名解析结果的通用属性，例如域名、查询类型、过期时间、结果类型 (数据、元数据、错误、别名) 和来源 (DNS、hosts 文件等)。
   - 派生类 `HostResolverInternalDataResult` 用于存储成功的 DNS 查询结果，包含 IP 地址列表、字符串列表（例如 SRV 记录的文本部分）和主机端口对列表。
   - 派生类 `HostResolverInternalMetadataResult` 用于存储与 DNS 查询结果相关的元数据，例如 HTTPS 记录的优先级和连接端点元数据。
   - 派生类 `HostResolverInternalErrorResult` 用于表示 DNS 查询失败的结果，包含具体的网络错误代码。
   - 派生类 `HostResolverInternalAliasResult` 用于表示 DNS 查询返回别名 (CNAME) 记录的结果，包含别名指向的目标域名。

2. **存储和管理 DNS 查询结果的信息:** 这些类作为数据结构，用于在主机名解析过程中传递和存储结果。它们封装了不同类型的 DNS 响应数据。

3. **支持结果的序列化和反序列化:** 提供了 `ToValue()` 方法将结果对象转换为 `base::Value` 对象，以及 `FromValue()` 静态方法从 `base::Value` 对象创建结果对象。`base::Value` 是 Chromium 中用于表示 JSON 数据的通用类，这使得可以将 DNS 查询结果进行序列化，例如用于缓存或日志记录。

4. **提供类型安全地访问结果数据的方法:**  通过 `AsData()`, `AsMetadata()`, `AsError()`, `AsAlias()` 等方法，可以类型安全地将基类指针或引用转换为对应的派生类，方便访问特定类型的结果数据。

5. **支持结果的克隆:** 提供了 `Clone()` 方法，用于创建结果对象的深拷贝。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所定义的数据结构和功能与 JavaScript 的网络请求密切相关。

当 JavaScript 代码通过浏览器发起网络请求（例如使用 `fetch()` API 或 `XMLHttpRequest`），浏览器底层会进行主机名解析以获取目标服务器的 IP 地址。 `HostResolverInternalResult` 及其派生类用于表示这个解析过程的结果。

**举例说明:**

假设 JavaScript 代码发起对 `www.example.com` 的请求：

1. 浏览器网络栈会启动主机名解析过程。
2. 如果 `www.example.com` 的 DNS 查询成功返回了 IP 地址，那么一个 `HostResolverInternalDataResult` 对象会被创建，其中包含了 `www.example.com` 对应的 IP 地址。
3. 这个结果对象可能会被用于后续的连接建立过程。
4. 如果需要将这个结果缓存起来，可以使用 `ToValue()` 方法将其序列化为 `base::Value` 对象。
5. 如果从缓存中读取到之前解析的结果，可以使用 `FromValue()` 方法从 `base::Value` 对象反序列化回 `HostResolverInternalDataResult` 对象。

**逻辑推理和假设输入/输出:**

**假设输入 (针对 `MaybeCanonicalizeName` 函数):**

* **输入 1:** `domain_name = "example.com"`
* **输出 1:** `"example.com"` (已是规范形式)

* **输入 2:** `domain_name = "ExAmPlE.CoM"`
* **输出 2:** `"example.com"` (转换为小写)

* **输入 3:** `domain_name = "example..com"`
* **输出 3:** `"example..com"` (无法规范化，返回原样)

**假设输入/输出 (针对 `FromValue` 和 `ToValue`):**

**场景：成功的 A 记录查询**

* **假设输入 (创建 `HostResolverInternalDataResult` 对象):**
    ```c++
    HostResolverInternalDataResult result(
        "example.com",
        DnsQueryType::kA,
        base::TimeTicks::Now(),
        base::Time::Now(),
        HostResolverInternalResult::Source::kDns,
        {IPEndPoint(net::IPAddress(192, 0, 2, 1), 80)},
        {},
        {});
    ```

* **假设输出 (`ToValue()` 结果，近似 JSON 格式):**
    ```json
    {
      "domain_name": "example.com",
      "query_type": "A",
      "type": "data",
      "source": "dns",
      "timed_expiration": "...", // 时间戳
      "endpoints": [
        {
          "address": "192.0.2.1",
          "port": 80
        }
      ],
      "strings": [],
      "hosts": []
    }
    ```

* **假设输入 (`FromValue()` 的输入，基于上述 `ToValue()` 输出):**  一个包含上述 JSON 结构的 `base::Value` 对象。
* **假设输出 (`FromValue()` 的结果):** 一个新创建的 `HostResolverInternalDataResult` 对象，其成员变量与原始对象相同。

**用户或编程常见的使用错误:**

1. **错误地假设结果类型:**  在处理 `HostResolverInternalResult` 指针时，如果没有检查其 `type_` 成员，就直接强制转换为某个派生类，可能会导致类型错误和程序崩溃。

   ```c++
   std::unique_ptr<HostResolverInternalResult> result = GetHostResolutionResult();
   // 错误的做法，没有检查类型
   HostResolverInternalDataResult& data_result = result->AsData();
   // 如果 result 的实际类型不是 kData，这里会触发 DCHECK 失败。
   ```

   **正确的做法:**

   ```c++
   std::unique_ptr<HostResolverInternalResult> result = GetHostResolutionResult();
   if (result->type() == HostResolverInternalResult::Type::kData) {
     HostResolverInternalDataResult& data_result = result->AsData();
     // 安全地访问数据
   } else if (result->type() == HostResolverInternalResult::Type::kError) {
     HostResolverInternalErrorResult& error_result = result->AsError();
     // 处理错误
   }
   ```

2. **忘记处理错误结果:**  在主机名解析失败时，`GetHostResolutionResult()` 可能会返回 `HostResolverInternalErrorResult` 对象。如果代码没有检查错误，就继续假设解析成功，可能会导致后续的网络操作失败。

3. **序列化/反序列化不匹配:**  如果修改了结果类的结构，但没有同步更新序列化和反序列化的逻辑，可能会导致 `FromValue()` 返回空指针或者创建的对象数据不完整。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入一个网址并按下回车，例如 `https://www.example.com`。**
2. **浏览器解析 URL，提取出主机名 `www.example.com`。**
3. **浏览器网络栈发起主机名解析请求。**
4. **Chromium 的 DNS 解析器 (Host Resolver) 开始工作。**
5. **内部的 DNS 查询过程可能会涉及到这个 `host_resolver_internal_result.cc` 文件中的类。**  例如，当 DNS 查询返回结果时，会创建一个对应的 `HostResolverInternalDataResult` 或其他派生类对象来存储结果。
6. **如果需要缓存 DNS 查询结果，`ToValue()` 方法会被调用将结果序列化。**
7. **后续如果再次访问相同的域名，并且缓存中存在结果，`FromValue()` 方法会被调用将缓存的 `base::Value` 反序列化为对应的结果对象。**
8. **如果 DNS 查询失败，会创建一个 `HostResolverInternalErrorResult` 对象，其中包含了错误信息。**  这可能会导致网页加载失败，浏览器显示错误页面。

**作为调试线索:**

* **当遇到与主机名解析相关的 bug 时，例如无法解析域名、连接超时等，可以查看是否有相关的 `HostResolverInternalResult` 对象被创建和传递。**
* **可以通过日志记录或断点调试来观察 `FromValue()` 和 `ToValue()` 方法的调用情况，以及序列化和反序列化的数据内容，以排查缓存或数据传输过程中的问题。**
* **检查 `HostResolverInternalErrorResult` 对象中的错误代码，可以帮助定位具体的 DNS 解析错误原因。**
* **查看 `HostResolverInternalResult` 对象的 `source_` 成员，可以了解 DNS 结果的来源，例如是来自 DNS 服务器还是本地的 hosts 文件，这有助于排查配置问题。**

总而言之，`host_resolver_internal_result.cc` 文件是 Chromium 网络栈中一个核心的数据结构定义文件，它为主机名解析的结果提供了一种结构化的表示方式，方便内部模块之间传递和处理 DNS 信息。 虽然 JavaScript 代码不会直接操作这些类，但它们是浏览器处理网络请求的基础，并且与 JavaScript 的网络 API 功能紧密相关。

Prompt: 
```
这是目录为net/dns/host_resolver_internal_result.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_internal_result.h"

#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/json/values_util.h"
#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_query_type.h"
#include "url/url_canon.h"
#include "url/url_canon_stdstring.h"

namespace net {

namespace {

// base::Value keys
constexpr std::string_view kValueDomainNameKey = "domain_name";
constexpr std::string_view kValueQueryTypeKey = "query_type";
constexpr std::string_view kValueTypeKey = "type";
constexpr std::string_view kValueSourceKey = "source";
constexpr std::string_view kValueTimedExpirationKey = "timed_expiration";
constexpr std::string_view kValueEndpointsKey = "endpoints";
constexpr std::string_view kValueStringsKey = "strings";
constexpr std::string_view kValueHostsKey = "hosts";
constexpr std::string_view kValueMetadatasKey = "metadatas";
constexpr std::string_view kValueMetadataWeightKey = "metadata_weight";
constexpr std::string_view kValueMetadataValueKey = "metadata_value";
constexpr std::string_view kValueErrorKey = "error";
constexpr std::string_view kValueAliasTargetKey = "alias_target";

// Returns `domain_name` as-is if it could not be canonicalized.
std::string MaybeCanonicalizeName(std::string domain_name) {
  std::string canonicalized;
  url::StdStringCanonOutput output(&canonicalized);
  url::CanonHostInfo host_info;

  url::CanonicalizeHostVerbose(domain_name.data(),
                               url::Component(0, domain_name.size()), &output,
                               &host_info);

  if (host_info.family == url::CanonHostInfo::Family::NEUTRAL) {
    output.Complete();
    return canonicalized;
  } else {
    return domain_name;
  }
}

base::Value EndpointMetadataPairToValue(
    const std::pair<HttpsRecordPriority, ConnectionEndpointMetadata>& pair) {
  base::Value::Dict dictionary;
  dictionary.Set(kValueMetadataWeightKey, pair.first);
  dictionary.Set(kValueMetadataValueKey, pair.second.ToValue());
  return base::Value(std::move(dictionary));
}

std::optional<std::pair<HttpsRecordPriority, ConnectionEndpointMetadata>>
EndpointMetadataPairFromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict)
    return std::nullopt;

  std::optional<int> weight = dict->FindInt(kValueMetadataWeightKey);
  if (!weight || !base::IsValueInRangeForNumericType<HttpsRecordPriority>(
                     weight.value())) {
    return std::nullopt;
  }

  const base::Value* metadata_value = dict->Find(kValueMetadataValueKey);
  if (!metadata_value)
    return std::nullopt;
  std::optional<ConnectionEndpointMetadata> metadata =
      ConnectionEndpointMetadata::FromValue(*metadata_value);
  if (!metadata)
    return std::nullopt;

  return std::pair(base::checked_cast<HttpsRecordPriority>(weight.value()),
                   std::move(metadata).value());
}

std::optional<DnsQueryType> QueryTypeFromValue(const base::Value& value) {
  const std::string* query_type_string = value.GetIfString();
  if (!query_type_string)
    return std::nullopt;
  const auto query_type_it =
      base::ranges::find(kDnsQueryTypes, *query_type_string,
                         &decltype(kDnsQueryTypes)::value_type::second);
  if (query_type_it == kDnsQueryTypes.end())
    return std::nullopt;

  return query_type_it->first;
}

base::Value TypeToValue(HostResolverInternalResult::Type type) {
  switch (type) {
    case HostResolverInternalResult::Type::kData:
      return base::Value("data");
    case HostResolverInternalResult::Type::kMetadata:
      return base::Value("metadata");
    case HostResolverInternalResult::Type::kError:
      return base::Value("error");
    case HostResolverInternalResult::Type::kAlias:
      return base::Value("alias");
  }
}

std::optional<HostResolverInternalResult::Type> TypeFromValue(
    const base::Value& value) {
  const std::string* string = value.GetIfString();
  if (!string)
    return std::nullopt;

  if (*string == "data") {
    return HostResolverInternalResult::Type::kData;
  } else if (*string == "metadata") {
    return HostResolverInternalResult::Type::kMetadata;
  } else if (*string == "error") {
    return HostResolverInternalResult::Type::kError;
  } else if (*string == "alias") {
    return HostResolverInternalResult::Type::kAlias;
  } else {
    return std::nullopt;
  }
}

base::Value SourceToValue(HostResolverInternalResult::Source source) {
  switch (source) {
    case HostResolverInternalResult::Source::kDns:
      return base::Value("dns");
    case HostResolverInternalResult::Source::kHosts:
      return base::Value("hosts");
    case HostResolverInternalResult::Source::kUnknown:
      return base::Value("unknown");
  }
}

std::optional<HostResolverInternalResult::Source> SourceFromValue(
    const base::Value& value) {
  const std::string* string = value.GetIfString();
  if (!string)
    return std::nullopt;

  if (*string == "dns") {
    return HostResolverInternalResult::Source::kDns;
  } else if (*string == "hosts") {
    return HostResolverInternalResult::Source::kHosts;
  } else if (*string == "unknown") {
    return HostResolverInternalResult::Source::kUnknown;
  } else {
    return std::nullopt;
  }
}

}  // namespace

// static
std::unique_ptr<HostResolverInternalResult>
HostResolverInternalResult::FromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict)
    return nullptr;

  const base::Value* type_value = dict->Find(kValueTypeKey);
  if (!type_value)
    return nullptr;
  std::optional<Type> type = TypeFromValue(*type_value);
  if (!type.has_value())
    return nullptr;

  switch (type.value()) {
    case Type::kData:
      return HostResolverInternalDataResult::FromValue(value);
    case Type::kMetadata:
      return HostResolverInternalMetadataResult::FromValue(value);
    case Type::kError:
      return HostResolverInternalErrorResult::FromValue(value);
    case Type::kAlias:
      return HostResolverInternalAliasResult::FromValue(value);
  }
}

const HostResolverInternalDataResult& HostResolverInternalResult::AsData()
    const {
  CHECK_EQ(type_, Type::kData);
  return *static_cast<const HostResolverInternalDataResult*>(this);
}

HostResolverInternalDataResult& HostResolverInternalResult::AsData() {
  CHECK_EQ(type_, Type::kData);
  return *static_cast<HostResolverInternalDataResult*>(this);
}

const HostResolverInternalMetadataResult&
HostResolverInternalResult::AsMetadata() const {
  CHECK_EQ(type_, Type::kMetadata);
  return *static_cast<const HostResolverInternalMetadataResult*>(this);
}

HostResolverInternalMetadataResult& HostResolverInternalResult::AsMetadata() {
  CHECK_EQ(type_, Type::kMetadata);
  return *static_cast<HostResolverInternalMetadataResult*>(this);
}

const HostResolverInternalErrorResult& HostResolverInternalResult::AsError()
    const {
  CHECK_EQ(type_, Type::kError);
  return *static_cast<const HostResolverInternalErrorResult*>(this);
}

HostResolverInternalErrorResult& HostResolverInternalResult::AsError() {
  CHECK_EQ(type_, Type::kError);
  return *static_cast<HostResolverInternalErrorResult*>(this);
}

const HostResolverInternalAliasResult& HostResolverInternalResult::AsAlias()
    const {
  CHECK_EQ(type_, Type::kAlias);
  return *static_cast<const HostResolverInternalAliasResult*>(this);
}

HostResolverInternalAliasResult& HostResolverInternalResult::AsAlias() {
  CHECK_EQ(type_, Type::kAlias);
  return *static_cast<HostResolverInternalAliasResult*>(this);
}

HostResolverInternalResult::HostResolverInternalResult(
    std::string domain_name,
    DnsQueryType query_type,
    std::optional<base::TimeTicks> expiration,
    std::optional<base::Time> timed_expiration,
    Type type,
    Source source)
    : domain_name_(MaybeCanonicalizeName(std::move(domain_name))),
      query_type_(query_type),
      type_(type),
      source_(source),
      expiration_(expiration),
      timed_expiration_(timed_expiration) {
  DCHECK(!domain_name_.empty());
  // If `expiration` has a value, `timed_expiration` must too.
  DCHECK(!expiration_.has_value() || timed_expiration.has_value());
}

HostResolverInternalResult::HostResolverInternalResult(
    const base::Value::Dict& dict)
    : domain_name_(*dict.FindString(kValueDomainNameKey)),
      query_type_(QueryTypeFromValue(*dict.Find(kValueQueryTypeKey)).value()),
      type_(TypeFromValue(*dict.Find(kValueTypeKey)).value()),
      source_(SourceFromValue(*dict.Find(kValueSourceKey)).value()),
      timed_expiration_(
          dict.contains(kValueTimedExpirationKey)
              ? base::ValueToTime(*dict.Find(kValueTimedExpirationKey))
              : std::optional<base::Time>()) {}

// static
bool HostResolverInternalResult::ValidateValueBaseDict(
    const base::Value::Dict& dict,
    bool require_timed_expiration) {
  const std::string* domain_name = dict.FindString(kValueDomainNameKey);
  if (!domain_name)
    return false;

  const std::string* query_type_string = dict.FindString(kValueQueryTypeKey);
  if (!query_type_string)
    return false;
  const auto query_type_it =
      base::ranges::find(kDnsQueryTypes, *query_type_string,
                         &decltype(kDnsQueryTypes)::value_type::second);
  if (query_type_it == kDnsQueryTypes.end())
    return false;

  const base::Value* type_value = dict.Find(kValueTypeKey);
  if (!type_value)
    return false;
  std::optional<Type> type = TypeFromValue(*type_value);
  if (!type.has_value())
    return false;

  const base::Value* source_value = dict.Find(kValueSourceKey);
  if (!source_value)
    return false;
  std::optional<Source> source = SourceFromValue(*source_value);
  if (!source.has_value())
    return false;

  std::optional<base::Time> timed_expiration;
  const base::Value* timed_expiration_value =
      dict.Find(kValueTimedExpirationKey);
  if (require_timed_expiration && !timed_expiration_value)
    return false;
  if (timed_expiration_value) {
    timed_expiration = base::ValueToTime(timed_expiration_value);
    if (!timed_expiration.has_value())
      return false;
  }

  return true;
}

base::Value::Dict HostResolverInternalResult::ToValueBaseDict() const {
  base::Value::Dict dict;

  dict.Set(kValueDomainNameKey, domain_name_);
  dict.Set(kValueQueryTypeKey, kDnsQueryTypes.at(query_type_));
  dict.Set(kValueTypeKey, TypeToValue(type_));
  dict.Set(kValueSourceKey, SourceToValue(source_));

  // `expiration_` is not serialized because it is TimeTicks.

  if (timed_expiration_.has_value()) {
    dict.Set(kValueTimedExpirationKey,
             base::TimeToValue(timed_expiration_.value()));
  }

  return dict;
}

// static
std::unique_ptr<HostResolverInternalDataResult>
HostResolverInternalDataResult::FromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict || !ValidateValueBaseDict(*dict, /*require_timed_expiration=*/true))
    return nullptr;

  const base::Value::List* endpoint_values = dict->FindList(kValueEndpointsKey);
  if (!endpoint_values)
    return nullptr;

  std::vector<IPEndPoint> endpoints;
  endpoints.reserve(endpoint_values->size());
  for (const base::Value& endpoint_value : *endpoint_values) {
    std::optional<IPEndPoint> endpoint = IPEndPoint::FromValue(endpoint_value);
    if (!endpoint.has_value())
      return nullptr;

    endpoints.push_back(std::move(endpoint).value());
  }

  const base::Value::List* string_values = dict->FindList(kValueStringsKey);
  if (!string_values)
    return nullptr;

  std::vector<std::string> strings;
  strings.reserve(string_values->size());
  for (const base::Value& string_value : *string_values) {
    const std::string* string = string_value.GetIfString();
    if (!string)
      return nullptr;

    strings.push_back(*string);
  }

  const base::Value::List* host_values = dict->FindList(kValueHostsKey);
  if (!host_values)
    return nullptr;

  std::vector<HostPortPair> hosts;
  hosts.reserve(host_values->size());
  for (const base::Value& host_value : *host_values) {
    std::optional<HostPortPair> host = HostPortPair::FromValue(host_value);
    if (!host.has_value())
      return nullptr;

    hosts.push_back(std::move(host).value());
  }

  // WrapUnique due to private constructor.
  return base::WrapUnique(new HostResolverInternalDataResult(
      *dict, std::move(endpoints), std::move(strings), std::move(hosts)));
}

HostResolverInternalDataResult::HostResolverInternalDataResult(
    std::string domain_name,
    DnsQueryType query_type,
    std::optional<base::TimeTicks> expiration,
    base::Time timed_expiration,
    Source source,
    std::vector<IPEndPoint> endpoints,
    std::vector<std::string> strings,
    std::vector<HostPortPair> hosts)
    : HostResolverInternalResult(std::move(domain_name),
                                 query_type,
                                 expiration,
                                 timed_expiration,
                                 Type::kData,
                                 source),
      endpoints_(std::move(endpoints)),
      strings_(std::move(strings)),
      hosts_(std::move(hosts)) {
  DCHECK(!endpoints_.empty() || !strings_.empty() || !hosts_.empty());
}

HostResolverInternalDataResult::~HostResolverInternalDataResult() = default;

std::unique_ptr<HostResolverInternalResult>
HostResolverInternalDataResult::Clone() const {
  CHECK(timed_expiration().has_value());
  return std::make_unique<HostResolverInternalDataResult>(
      domain_name(), query_type(), expiration(), timed_expiration().value(),
      source(), endpoints(), strings(), hosts());
}

base::Value HostResolverInternalDataResult::ToValue() const {
  base::Value::Dict dict = ToValueBaseDict();

  base::Value::List endpoints_list;
  endpoints_list.reserve(endpoints_.size());
  for (IPEndPoint endpoint : endpoints_) {
    endpoints_list.Append(endpoint.ToValue());
  }
  dict.Set(kValueEndpointsKey, std::move(endpoints_list));

  base::Value::List strings_list;
  strings_list.reserve(strings_.size());
  for (const std::string& string : strings_) {
    strings_list.Append(string);
  }
  dict.Set(kValueStringsKey, std::move(strings_list));

  base::Value::List hosts_list;
  hosts_list.reserve(hosts_.size());
  for (const HostPortPair& host : hosts_) {
    hosts_list.Append(host.ToValue());
  }
  dict.Set(kValueHostsKey, std::move(hosts_list));

  return base::Value(std::move(dict));
}

HostResolverInternalDataResult::HostResolverInternalDataResult(
    const base::Value::Dict& dict,
    std::vector<IPEndPoint> endpoints,
    std::vector<std::string> strings,
    std::vector<HostPortPair> hosts)
    : HostResolverInternalResult(dict),
      endpoints_(std::move(endpoints)),
      strings_(std::move(strings)),
      hosts_(std::move(hosts)) {}

// static
std::unique_ptr<HostResolverInternalMetadataResult>
HostResolverInternalMetadataResult::FromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict || !ValidateValueBaseDict(*dict, /*require_timed_expiration=*/true))
    return nullptr;

  const base::Value::List* metadata_values = dict->FindList(kValueMetadatasKey);
  if (!metadata_values)
    return nullptr;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas;
  for (const base::Value& metadata_value : *metadata_values) {
    std::optional<std::pair<HttpsRecordPriority, ConnectionEndpointMetadata>>
        metadata = EndpointMetadataPairFromValue(metadata_value);
    if (!metadata.has_value())
      return nullptr;
    metadatas.insert(std::move(metadata).value());
  }

  // WrapUnique due to private constructor.
  return base::WrapUnique(
      new HostResolverInternalMetadataResult(*dict, std::move(metadatas)));
}

HostResolverInternalMetadataResult::HostResolverInternalMetadataResult(
    std::string domain_name,
    DnsQueryType query_type,
    std::optional<base::TimeTicks> expiration,
    base::Time timed_expiration,
    Source source,
    std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas)
    : HostResolverInternalResult(std::move(domain_name),
                                 query_type,
                                 expiration,
                                 timed_expiration,
                                 Type::kMetadata,
                                 source),
      metadatas_(std::move(metadatas)) {}

HostResolverInternalMetadataResult::~HostResolverInternalMetadataResult() =
    default;

std::unique_ptr<HostResolverInternalResult>
HostResolverInternalMetadataResult::Clone() const {
  CHECK(timed_expiration().has_value());
  return std::make_unique<HostResolverInternalMetadataResult>(
      domain_name(), query_type(), expiration(), timed_expiration().value(),
      source(), metadatas());
}

base::Value HostResolverInternalMetadataResult::ToValue() const {
  base::Value::Dict dict = ToValueBaseDict();

  base::Value::List metadatas_list;
  metadatas_list.reserve(metadatas_.size());
  for (const std::pair<const HttpsRecordPriority, ConnectionEndpointMetadata>&
           metadata_pair : metadatas_) {
    metadatas_list.Append(EndpointMetadataPairToValue(metadata_pair));
  }
  dict.Set(kValueMetadatasKey, std::move(metadatas_list));

  return base::Value(std::move(dict));
}

HostResolverInternalMetadataResult::HostResolverInternalMetadataResult(
    const base::Value::Dict& dict,
    std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas)
    : HostResolverInternalResult(dict), metadatas_(std::move(metadatas)) {}

// static
std::unique_ptr<HostResolverInternalErrorResult>
HostResolverInternalErrorResult::FromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict ||
      !ValidateValueBaseDict(*dict, /*require_timed_expiration=*/false)) {
    return nullptr;
  }

  std::optional<int> error = dict->FindInt(kValueErrorKey);
  if (!error.has_value())
    return nullptr;

  // WrapUnique due to private constructor.
  return base::WrapUnique(
      new HostResolverInternalErrorResult(*dict, error.value()));
}

HostResolverInternalErrorResult::HostResolverInternalErrorResult(
    std::string domain_name,
    DnsQueryType query_type,
    std::optional<base::TimeTicks> expiration,
    std::optional<base::Time> timed_expiration,
    Source source,
    int error)
    : HostResolverInternalResult(std::move(domain_name),
                                 query_type,
                                 expiration,
                                 timed_expiration,
                                 Type::kError,
                                 source),
      error_(error) {}

std::unique_ptr<HostResolverInternalResult>
HostResolverInternalErrorResult::Clone() const {
  return std::make_unique<HostResolverInternalErrorResult>(
      domain_name(), query_type(), expiration(), timed_expiration(), source(),
      error());
}

base::Value HostResolverInternalErrorResult::ToValue() const {
  base::Value::Dict dict = ToValueBaseDict();

  dict.Set(kValueErrorKey, error_);

  return base::Value(std::move(dict));
}

HostResolverInternalErrorResult::HostResolverInternalErrorResult(
    const base::Value::Dict& dict,
    int error)
    : HostResolverInternalResult(dict), error_(error) {
  DCHECK_NE(error_, OK);
}

// static
std::unique_ptr<HostResolverInternalAliasResult>
HostResolverInternalAliasResult::FromValue(const base::Value& value) {
  const base::Value::Dict* dict = value.GetIfDict();
  if (!dict || !ValidateValueBaseDict(*dict, /*require_timed_expiration=*/true))
    return nullptr;

  const std::string* target = dict->FindString(kValueAliasTargetKey);
  if (!target)
    return nullptr;

  // WrapUnique due to private constructor.
  return base::WrapUnique(new HostResolverInternalAliasResult(*dict, *target));
}

HostResolverInternalAliasResult::HostResolverInternalAliasResult(
    std::string domain_name,
    DnsQueryType query_type,
    std::optional<base::TimeTicks> expiration,
    base::Time timed_expiration,
    Source source,
    std::string alias_target)
    : HostResolverInternalResult(std::move(domain_name),
                                 query_type,
                                 expiration,
                                 timed_expiration,
                                 Type::kAlias,
                                 source),
      alias_target_(MaybeCanonicalizeName(std::move(alias_target))) {
  DCHECK(!alias_target_.empty());
}

std::unique_ptr<HostResolverInternalResult>
HostResolverInternalAliasResult::Clone() const {
  CHECK(timed_expiration().has_value());
  return std::make_unique<HostResolverInternalAliasResult>(
      domain_name(), query_type(), expiration(), timed_expiration().value(),
      source(), alias_target());
}

base::Value HostResolverInternalAliasResult::ToValue() const {
  base::Value::Dict dict = ToValueBaseDict();

  dict.Set(kValueAliasTargetKey, alias_target_);

  return base::Value(std::move(dict));
}

HostResolverInternalAliasResult::HostResolverInternalAliasResult(
    const base::Value::Dict& dict,
    std::string alias_target)
    : HostResolverInternalResult(dict),
      alias_target_(MaybeCanonicalizeName(std::move(alias_target))) {}

}  // namespace net

"""

```