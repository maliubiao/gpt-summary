Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Understanding the Goal:**

The primary goal is to understand the purpose of the C++ file `host_resolver_internal_result_unittest.cc`. Specifically, the prompt asks for:

* **Functionality:** What does this code do?
* **Relationship to JavaScript:**  Is there any interaction with the JavaScript side?
* **Logic and I/O:** Can we infer input and output based on the tests?
* **Common Errors:** What mistakes might developers make when using this code?
* **Debugging:** How might a developer reach this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

First, I'd quickly scan the code for keywords and patterns that give clues about its purpose. I see:

* `#include`:  Indicates dependencies. Crucially, I see `#include "net/dns/host_resolver_internal_result.h"`. This is the core component being tested.
* `TEST(...)`:  This is a clear indicator of unit tests using the Google Test framework.
* `EXPECT_...`:  Assertions within the tests, confirming expected behavior.
* `HostResolverInternalResult`, `HostResolverInternalDataResult`, `HostResolverInternalMetadataResult`, `HostResolverInternalErrorResult`, `HostResolverInternalAliasResult`: These are the main classes/structures being tested. The naming strongly suggests they represent different outcomes of a DNS resolution process.
* `FromValue`, `ToValue`: These methods hint at serialization and deserialization, likely using `base::Value`.
* `Clone`:  Suggests the creation of copies.
* `DnsQueryType`, `IPEndpoint`, `HostPortPair`, `ConnectionEndpointMetadata`: These are data structures related to DNS and networking.
* `base::JSONReader`:  Indicates interaction with JSON data for serialization/deserialization.
* `net::ERR_...`: Network error codes.

**3. Deciphering the Test Structure:**

The `TEST` macros define individual test cases. The names of these tests are very descriptive:

* `DeserializeMalformedValue`: Tests handling of invalid input during deserialization.
* `DataResult`, `MetadataResult`, `ErrorResult`, `AliasResult`:  These tests focus on the specific types of results the `HostResolverInternalResult` can represent.
* `Clone...Result`: Tests the `Clone()` functionality for each result type.
* `Roundtrip...ResultThroughSerialization`: Tests the serialization and deserialization process, ensuring data integrity.
* `Serializep...Result`: Tests the output format of the serialization, likely for logging or debugging.
* `DeserializeMalformed...Value`: Tests how each specific result type handles invalid input during deserialization.

This structure makes it clear that the primary function of the file is to test the `HostResolverInternalResult` hierarchy and its ability to represent various DNS resolution outcomes, including successful data, metadata, errors, and aliases.

**4. Focusing on Key Functionality (and Potential JavaScript Relevance):**

The `FromValue` and `ToValue` methods are particularly interesting. They suggest a way to convert the internal C++ representation of DNS results into a more generic `base::Value`. `base::Value` is often used for inter-process communication or data exchange, and it can be easily converted to JSON. This is where the potential link to JavaScript emerges. JavaScript in a browser might receive DNS resolution information serialized in JSON format.

**5. Hypothesizing Input and Output (Logical Inference):**

By looking at the `EXPECT_EQ` and `EXPECT_THAT` assertions within the tests, I can infer the expected input and output for the functions being tested. For example, in `RoundtripDataResultThroughSerialization`, an object is created, serialized to `base::Value`, deserialized back, and then compared. This allows me to understand the structure of the serialized data.

**6. Identifying Potential Usage Errors:**

The "DeserializeMalformed..." tests directly address potential errors. They demonstrate what happens when invalid data is passed to the deserialization functions. This gives clues about the expected format and the kind of mistakes a programmer might make.

**7. Tracing User Actions (Debugging Clues):**

To understand how a user action might lead to this code, I need to think about the role of DNS resolution in a browser:

* A user types a URL in the address bar.
* The browser needs to find the IP address associated with the domain name in the URL.
* This triggers a DNS lookup.
* The `HostResolver` in the Chromium network stack is responsible for performing this lookup.
* The `HostResolverInternalResult` likely stores the outcome of this lookup, regardless of whether it was successful, resulted in an error, or found an alias.

Therefore, any user action that requires resolving a domain name (navigating to a website, loading resources, etc.) could potentially lead to the creation and manipulation of `HostResolverInternalResult` objects.

**8. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, addressing each part of the prompt:

* Start with a concise summary of the file's purpose.
* Explain the different result types.
* Detail the serialization and deserialization mechanisms and the potential link to JavaScript (emphasizing the `base::Value` and JSON connection).
* Provide concrete examples of input and output for the serialization/deserialization process.
* Illustrate common usage errors based on the "DeserializeMalformed..." tests.
* Explain the user actions that trigger DNS resolution and how this code fits into the larger process, offering debugging hints.

This systematic approach, starting with a broad overview and progressively diving into the details, helps in thoroughly analyzing the provided code snippet and answering the prompt effectively. The key is to leverage the information contained within the code itself (test names, assertions, data structures) to understand its purpose and behavior.
这个文件 `net/dns/host_resolver_internal_result_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/dns/host_resolver_internal_result.h` 中定义的类和结构体的功能。这些类和结构体用于表示 DNS 主机名解析的内部结果。

**主要功能:**

1. **定义和测试 DNS 解析的内部结果:** 该文件包含了对 `HostResolverInternalResult` 及其派生类的单元测试。这些派生类包括：
    * `HostResolverInternalDataResult`: 表示成功的 DNS 解析，包含 IP 地址、主机名等数据。
    * `HostResolverInternalMetadataResult`: 表示包含额外元数据的 DNS 解析结果，例如 HTTPS 记录中的 ALPN 协议列表。
    * `HostResolverInternalErrorResult`: 表示 DNS 解析失败的结果，包含错误代码。
    * `HostResolverInternalAliasResult`: 表示 DNS 解析返回别名 (CNAME) 的结果。

2. **测试结果对象的创建和属性访问:** 测试用例验证了可以正确地创建各种类型的 `HostResolverInternalResult` 对象，并能正确访问其成员变量，例如域名、查询类型、结果来源、过期时间等。

3. **测试结果对象的克隆:**  测试了 `Clone()` 方法，确保可以正确地复制 `HostResolverInternalResult` 对象，并且克隆后的对象与原始对象拥有相同的数据，但内存地址不同。

4. **测试结果对象的序列化和反序列化:**  重要的功能是测试了 `ToValue()` 方法将结果对象序列化为 `base::Value` 对象，以及 `FromValue()` 静态方法从 `base::Value` 对象反序列化回结果对象。这对于在 Chromium 内部传递和存储 DNS 解析结果非常重要，也方便了日志记录和调试。

5. **测试序列化结果的格式:**  部分测试用例 (以 `Serializep` 开头) 验证了序列化后的 `base::Value` 对象的具体 JSON 格式，确保了格式的稳定性和可预测性，这对于 NetLog 等依赖这些数据的组件非常重要。

6. **测试错误的反序列化处理:**  大量的测试用例 (以 `DeserializeMalformed` 开头) 专门测试了在反序列化过程中，如果 `base::Value` 对象格式不正确或缺少必要的字段时，`FromValue()` 方法是否能够正确地返回 `false`，防止程序崩溃或产生不可预测的行为。

**与 Javascript 的关系:**

该文件本身是 C++ 代码，直接与 Javascript 没有代码级别的交互。但是，它所测试的功能与 Javascript 的网络请求行为密切相关。

当 Javascript 代码 (例如在浏览器页面中运行) 发起一个网络请求时，浏览器需要将域名解析为 IP 地址。Chromium 的网络栈会执行这个 DNS 解析过程，而 `HostResolverInternalResult` 就是这个过程的内部结果表示。

* **Javascript 发起请求:**  例如，`fetch('https://www.example.com')`。
* **DNS 解析:** Chromium 的网络栈会尝试解析 `www.example.com` 的 IP 地址。
* **`HostResolverInternalResult`:**  解析的结果（成功、失败、别名等）会被存储在 `HostResolverInternalResult` 对象中。
* **数据传递 (间接):**  虽然 Javascript 不能直接访问 `HostResolverInternalResult` 对象，但解析的结果最终会影响 Javascript 网络请求的行为。例如，如果解析成功，请求会被发送到解析得到的 IP 地址；如果解析失败，`fetch` 会抛出错误。
* **NetLog (间接):**  `HostResolverInternalResult` 对象可以通过 `ToValue()` 方法序列化为 `base::Value`，然后可以被 NetLog 系统记录下来。开发者可以在浏览器的 `chrome://net-export/` 页面导出 NetLog，查看详细的网络事件，包括 DNS 解析的中间结果和最终结果。这些日志信息可以帮助开发者理解 Javascript 发起的网络请求背后的细节。

**举例说明 (假设的 Javascript 场景和 C++ 内部交互):**

1. **假设输入 (Javascript):** 用户在浏览器地址栏输入 `https://github.com` 并回车。

2. **C++ 内部处理 (假设):**
   * Chromium 的网络栈接收到对 `github.com` 的 DNS 查询请求。
   * Host Resolver 组件开始进行 DNS 解析。
   * **成功解析:** 如果 DNS 服务器返回了 `github.com` 的 IP 地址 (例如 `140.82.121.4`),  则会创建一个 `HostResolverInternalDataResult` 对象，包含域名 `github.com`，查询类型 (A 或 AAAA)，以及 IP 地址 `140.82.121.4`。
   * **解析失败:** 如果 DNS 服务器返回错误 (例如域名不存在)，则会创建一个 `HostResolverInternalErrorResult` 对象，包含域名 `github.com` 和错误代码 (例如 `ERR_NAME_NOT_RESOLVED`)。
   * **返回别名:** 如果 DNS 服务器返回 `github.com` 是 `github.map.fastly.net` 的别名，则会创建一个 `HostResolverInternalAliasResult` 对象，包含域名 `github.com` 和别名目标 `github.map.fastly.net`。

3. **输出 (影响 Javascript):**
   * **成功解析:**  浏览器会连接到 `140.82.121.4`，开始加载 `github.com` 的页面。Javascript 代码可以正常与服务器交互。
   * **解析失败:**  浏览器会显示一个错误页面，提示无法找到 `github.com` 的服务器。Javascript 代码的网络请求会失败。
   * **返回别名:**  Host Resolver 会继续解析 `github.map.fastly.net` 的 IP 地址，然后浏览器连接到 `github.map.fastly.net` 的 IP 地址。Javascript 代码感知不到这个中间的别名解析过程。

**逻辑推理 (假设输入与输出):**

**假设输入 (C++ 代码中 `HostResolverInternalDataResult` 的创建):**

```c++
auto result = std::make_unique<HostResolverInternalDataResult>(
    "example.org", DnsQueryType::A, base::TimeTicks::Now(), base::Time::Now(),
    HostResolverInternalResult::Source::kDns,
    std::vector<IPEndPoint>{IPEndPoint(IPAddress(192, 0, 2, 1), 80)},
    std::vector<std::string>{},
    std::vector<HostPortPair>{});
```

**假设输出 (测试用例中针对此对象的断言):**

```c++
EXPECT_EQ(result->domain_name(), "example.org");
EXPECT_EQ(result->query_type(), DnsQueryType::A);
EXPECT_THAT(result->endpoints(),
            ElementsAre(IPEndPoint(IPAddress(192, 0, 2, 1), 80)));
```

**假设输入 (序列化为 `base::Value`):**

```c++
base::Value value = result->ToValue();
```

**假设输出 (序列化后的 `base::Value` -  简化表示):**

```json
{
  "domain_name": "example.org",
  "endpoints": [
    {
      "address": "192.0.2.1",
      "port": 80
    }
  ],
  "query_type": "A",
  "source": "dns",
  "timed_expiration": "...",
  "type": "data"
}
```

**涉及用户或编程常见的使用错误 (举例说明):**

1. **反序列化时提供错误的 JSON 结构:**

   ```c++
   base::Value bad_json = base::JSONReader::Read(R"({"domain": "test.com"})").value();
   auto result = HostResolverInternalDataResult::FromValue(bad_json);
   EXPECT_FALSE(result); // 缺少 "domain_name" 等必要字段，反序列化会失败
   ```

   **用户操作如何到达这里 (调试线索):** 开发者可能在某个地方从配置文件或网络接收 DNS 解析结果的 JSON 数据，然后尝试反序列化。如果提供的数据格式不符合 `HostResolverInternalResult` 期望的格式，就会触发这种错误。

2. **假设反序列化的类型与实际类型不符:**

   ```c++
   base::Value alias_json = base::JSONReader::Read(R"({"type": "alias", "domain_name": "a.com", "alias_target": "b.com"})").value();
   auto data_result = HostResolverInternalDataResult::FromValue(alias_json);
   EXPECT_FALSE(data_result); // JSON 类型是 "alias"，尝试反序列化为 DataResult 会失败
   ```

   **用户操作如何到达这里 (调试线索):**  程序可能根据某些标记或约定来判断反序列化的类型，但判断逻辑有误，导致尝试将一个 Alias 结果反序列化为 Data 结果。

3. **修改或丢失了必要的序列化字段:**

   ```c++
   auto original_result = std::make_unique<HostResolverInternalDataResult>(/* ... */);
   base::Value serialized = original_result->ToValue();
   serialized.GetDict().Remove("domain_name"); // 错误地移除了 "domain_name" 字段
   auto deserialized_result = HostResolverInternalDataResult::FromValue(serialized);
   EXPECT_FALSE(deserialized_result);
   ```

   **用户操作如何到达这里 (调试线索):**  开发者可能在序列化和反序列化之间对 `base::Value` 对象进行了中间处理，例如修改或过滤字段，但错误地移除了必要的字段，导致反序列化失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问 `https://very.long.sub.domain.example.com`.

1. **用户输入 URL:** 用户在浏览器地址栏输入 `https://very.long.sub.domain.example.com` 并按下回车键。

2. **URL 解析:** 浏览器首先解析 URL，提取出主机名 `very.long.sub.domain.example.com`。

3. **Host Resolver 查询:** Chromium 的网络栈中的 Host Resolver 组件被调用，开始尝试解析这个主机名。这可能涉及到查询本地缓存、操作系统 DNS 缓存，或者向配置的 DNS 服务器发起查询。

4. **内部结果创建 (在 `host_resolver_internal_result.cc` 中测试的类):**
   * **如果 DNS 解析成功:**  会创建 `HostResolverInternalDataResult` 对象，存储解析得到的 IP 地址。
   * **如果 DNS 解析失败 (例如域名不存在):** 会创建 `HostResolverInternalErrorResult` 对象，存储错误代码 `ERR_NAME_NOT_RESOLVED`。
   * **如果 DNS 解析返回 CNAME:** 会创建 `HostResolverInternalAliasResult` 对象，存储别名目标。

5. **结果传递和使用:** `HostResolverInternalResult` 对象会被传递给网络栈的其他组件，用于建立连接。

6. **NetLog 记录 (可能的调试线索):**  如果启用了 NetLog，当 `HostResolverInternalResult` 对象被创建时，它的 `ToValue()` 方法会被调用，将结果序列化为 `base::Value`，然后被 NetLog 系统记录下来。开发者可以通过 `chrome://net-export/` 查看这些日志，了解 DNS 解析的详细过程，包括中间结果和最终结果。如果反序列化出现问题，NetLog 中可能也会记录相关的错误信息。

7. **测试用例覆盖的场景:** `host_resolver_internal_result_unittest.cc` 中的测试用例模拟了各种可能的 `HostResolverInternalResult` 对象的创建、克隆、序列化和反序列化过程，以及错误处理场景。开发者在修改或调试 Host Resolver 相关代码时，可以通过运行这些单元测试来验证代码的正确性，确保不会引入新的 bug，例如反序列化失败的问题。

因此，当用户在浏览器中进行网络操作（如访问网页）时，底层的 DNS 解析过程可能会涉及到 `net/dns/host_resolver_internal_result.h` 中定义的类，而 `net/dns/host_resolver_internal_result_unittest.cc` 就是用来确保这些类能够正常工作的关键保障。调试网络问题时，查看 NetLog 并理解这些内部结果的含义是非常重要的。

Prompt: 
```
这是目录为net/dns/host_resolver_internal_result_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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
#include <string>
#include <vector>

#include "base/json/json_reader.h"
#include "base/time/time.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_query_type.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::Optional;
using ::testing::Ref;

namespace net {
namespace {

TEST(HostResolverInternalResultTest, DeserializeMalformedValue) {
  base::Value non_dict(base::Value::Type::BOOLEAN);
  EXPECT_FALSE(HostResolverInternalResult::FromValue(non_dict));

  base::Value missing_type(base::Value::Type::DICT);
  EXPECT_FALSE(HostResolverInternalResult::FromValue(missing_type));

  base::Value bad_type(base::Value::Type::DICT);
  bad_type.GetDict().Set("type", "foo");
  EXPECT_FALSE(HostResolverInternalResult::FromValue(bad_type));
}

TEST(HostResolverInternalResultTest, DataResult) {
  auto result = std::make_unique<HostResolverInternalDataResult>(
      "domain.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::vector<IPEndPoint>{IPEndPoint(IPAddress(2, 2, 2, 2), 46)},
      std::vector<std::string>{"foo", "bar"},
      std::vector<HostPortPair>{HostPortPair("anotherdomain.test", 112)});

  EXPECT_EQ(result->domain_name(), "domain.test");
  EXPECT_EQ(result->query_type(), DnsQueryType::AAAA);
  EXPECT_EQ(result->type(), HostResolverInternalResult::Type::kData);
  EXPECT_EQ(result->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(result->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(result->timed_expiration(), Optional(base::Time()));

  EXPECT_THAT(result->AsData(), Ref(*result));

  EXPECT_THAT(result->endpoints(),
              ElementsAre(IPEndPoint(IPAddress(2, 2, 2, 2), 46)));
  EXPECT_THAT(result->strings(), ElementsAre("foo", "bar"));
  EXPECT_THAT(result->hosts(),
              ElementsAre(HostPortPair("anotherdomain.test", 112)));
}

TEST(HostResolverInternalResultTest, CloneDataResult) {
  auto result = std::make_unique<HostResolverInternalDataResult>(
      "domain.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::vector<IPEndPoint>{IPEndPoint(IPAddress(2, 2, 2, 2), 46)},
      std::vector<std::string>{"foo", "bar"},
      std::vector<HostPortPair>{HostPortPair("anotherdomain.test", 112)});

  std::unique_ptr<HostResolverInternalResult> copy = result->Clone();
  EXPECT_NE(copy.get(), result.get());

  EXPECT_EQ(copy->domain_name(), "domain.test");
  EXPECT_EQ(copy->query_type(), DnsQueryType::AAAA);
  EXPECT_EQ(copy->type(), HostResolverInternalResult::Type::kData);
  EXPECT_EQ(copy->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(copy->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(copy->timed_expiration(), Optional(base::Time()));
  EXPECT_THAT(copy->AsData().endpoints(),
              ElementsAre(IPEndPoint(IPAddress(2, 2, 2, 2), 46)));
  EXPECT_THAT(copy->AsData().strings(), ElementsAre("foo", "bar"));
  EXPECT_THAT(copy->AsData().hosts(),
              ElementsAre(HostPortPair("anotherdomain.test", 112)));
}

TEST(HostResolverInternalResultTest, RoundtripDataResultThroughSerialization) {
  auto result = std::make_unique<HostResolverInternalDataResult>(
      "domain.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::vector<IPEndPoint>{IPEndPoint(IPAddress(2, 2, 2, 2), 46)},
      std::vector<std::string>{"foo", "bar"},
      std::vector<HostPortPair>{HostPortPair("anotherdomain.test", 112)});

  base::Value value = result->ToValue();
  auto deserialized = HostResolverInternalResult::FromValue(value);
  ASSERT_TRUE(deserialized);
  ASSERT_EQ(deserialized->type(), HostResolverInternalResult::Type::kData);

  // Expect deserialized result to be the same as the original other than
  // missing non-timed expiration.
  EXPECT_EQ(deserialized->AsData(),
            HostResolverInternalDataResult(
                result->domain_name(), result->query_type(),
                /*expiration=*/std::nullopt, result->timed_expiration().value(),
                result->source(), result->endpoints(), result->strings(),
                result->hosts()));
}

// Expect results to serialize to a consistent base::Value format for
// consumption by NetLog and similar.
TEST(HostResolverInternalResultTest, SerializepDataResult) {
  auto result = std::make_unique<HostResolverInternalDataResult>(
      "domain.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::vector<IPEndPoint>{IPEndPoint(IPAddress(2, 2, 2, 2), 46)},
      std::vector<std::string>{"foo", "bar"},
      std::vector<HostPortPair>{HostPortPair("anotherdomain.test", 112)});
  base::Value value = result->ToValue();

  std::optional<base::Value> expected = base::JSONReader::Read(
      R"(
        {
          "domain_name": "domain.test",
          "endpoints": [
            {
              "address": "2.2.2.2",
              "port": 46
            }
          ],
          "hosts": [
            {
              "host": "anotherdomain.test",
              "port": 112
            }
          ],
          "query_type": "AAAA",
          "source": "dns",
          "strings": [
            "foo",
            "bar"
          ],
          "timed_expiration": "0",
          "type": "data"
        }
        )");
  ASSERT_TRUE(expected.has_value());

  EXPECT_EQ(value, expected.value());
}

TEST(HostResolverInternalResultTest, DeserializeMalformedDataValue) {
  auto result = std::make_unique<HostResolverInternalDataResult>(
      "domain.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::vector<IPEndPoint>{IPEndPoint(IPAddress(2, 2, 2, 2), 46)},
      std::vector<std::string>{"foo", "bar"},
      std::vector<HostPortPair>{HostPortPair("anotherdomain.test", 112)});
  base::Value valid_value = result->ToValue();
  ASSERT_TRUE(HostResolverInternalDataResult::FromValue(valid_value));

  base::Value missing_domain = valid_value.Clone();
  ASSERT_TRUE(missing_domain.GetDict().Remove("domain_name"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_domain));

  base::Value missing_qtype = valid_value.Clone();
  ASSERT_TRUE(missing_qtype.GetDict().Remove("query_type"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_qtype));
  base::Value unknown_qtype = valid_value.Clone();
  ASSERT_TRUE(unknown_qtype.GetDict().Set("query_type", "foo"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(unknown_qtype));

  base::Value missing_value_type = valid_value.Clone();
  ASSERT_TRUE(missing_value_type.GetDict().Remove("type"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_value_type));
  base::Value unknown_value_type = valid_value.Clone();
  ASSERT_TRUE(unknown_value_type.GetDict().Set("type", "foo"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(unknown_value_type));

  base::Value missing_source = valid_value.Clone();
  ASSERT_TRUE(missing_source.GetDict().Remove("source"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_source));
  base::Value unknown_source = valid_value.Clone();
  ASSERT_TRUE(unknown_source.GetDict().Set("source", "foo"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(unknown_source));

  base::Value missing_expiration = valid_value.Clone();
  ASSERT_TRUE(missing_expiration.GetDict().Remove("timed_expiration"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_expiration));
  base::Value invalid_expiration = valid_value.Clone();
  ASSERT_TRUE(invalid_expiration.GetDict().Set("timed_expiration", "foo"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(invalid_expiration));

  base::Value missing_endpoints = valid_value.Clone();
  ASSERT_TRUE(missing_endpoints.GetDict().Remove("endpoints"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_endpoints));
  base::Value invalid_endpoint = valid_value.Clone();
  invalid_endpoint.GetDict().FindList("endpoints")->front() =
      base::Value("foo");
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(invalid_endpoint));

  base::Value missing_strings = valid_value.Clone();
  ASSERT_TRUE(missing_strings.GetDict().Remove("strings"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_strings));
  base::Value invalid_string = valid_value.Clone();
  invalid_string.GetDict().FindList("strings")->front() = base::Value(5);
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(invalid_string));

  base::Value missing_hosts = valid_value.Clone();
  ASSERT_TRUE(missing_hosts.GetDict().Remove("hosts"));
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(missing_hosts));
  base::Value invalid_hosts = valid_value.Clone();
  invalid_hosts.GetDict().FindList("hosts")->front() = base::Value("foo");
  EXPECT_FALSE(HostResolverInternalDataResult::FromValue(invalid_hosts));
}

TEST(HostResolverInternalResultTest, MetadataResult) {
  const ConnectionEndpointMetadata kMetadata(
      /*supported_protocol_alpns=*/{"http/1.1", "h3"},
      /*ech_config_list=*/{0x01, 0x13},
      /*target_name*/ "target.test");
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      "domain1.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {4, kMetadata}});

  EXPECT_EQ(result->domain_name(), "domain1.test");
  EXPECT_EQ(result->query_type(), DnsQueryType::HTTPS);
  EXPECT_EQ(result->type(), HostResolverInternalResult::Type::kMetadata);
  EXPECT_EQ(result->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(result->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(result->timed_expiration(), Optional(base::Time()));

  EXPECT_THAT(result->AsMetadata(), Ref(*result));

  EXPECT_THAT(result->metadatas(), ElementsAre(std::pair(4, kMetadata)));
}

TEST(HostResolverInternalResultTest, CloneMetadataResult) {
  const ConnectionEndpointMetadata kMetadata(
      /*supported_protocol_alpns=*/{"http/1.1", "h3"},
      /*ech_config_list=*/{0x01, 0x13},
      /*target_name*/ "target.test");
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      "domain1.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {4, kMetadata}});

  std::unique_ptr<HostResolverInternalResult> copy = result->Clone();
  EXPECT_NE(copy.get(), result.get());

  EXPECT_EQ(copy->domain_name(), "domain1.test");
  EXPECT_EQ(copy->query_type(), DnsQueryType::HTTPS);
  EXPECT_EQ(copy->type(), HostResolverInternalResult::Type::kMetadata);
  EXPECT_EQ(copy->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(copy->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(copy->timed_expiration(), Optional(base::Time()));
  EXPECT_THAT(copy->AsMetadata().metadatas(),
              ElementsAre(std::make_pair(4, kMetadata)));
}

TEST(HostResolverInternalResultTest,
     RoundtripMetadataResultThroughSerialization) {
  const ConnectionEndpointMetadata kMetadata(
      /*supported_protocol_alpns=*/{"http/1.1", "h2", "h3"},
      /*ech_config_list=*/{0x01, 0x13, 0x15},
      /*target_name*/ "target1.test");
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      "domain2.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {2, kMetadata}});

  base::Value value = result->ToValue();
  auto deserialized = HostResolverInternalResult::FromValue(value);
  ASSERT_TRUE(deserialized);
  ASSERT_EQ(deserialized->type(), HostResolverInternalResult::Type::kMetadata);

  // Expect deserialized result to be the same as the original other than
  // missing non-timed expiration.
  EXPECT_EQ(deserialized->AsMetadata(),
            HostResolverInternalMetadataResult(
                result->domain_name(), result->query_type(),
                /*expiration=*/std::nullopt, result->timed_expiration().value(),
                result->source(), result->metadatas()));
}

// Expect results to serialize to a consistent base::Value format for
// consumption by NetLog and similar.
TEST(HostResolverInternalResultTest, SerializepMetadataResult) {
  const ConnectionEndpointMetadata kMetadata(
      /*supported_protocol_alpns=*/{"http/1.1", "h2", "h3"},
      /*ech_config_list=*/{0x01, 0x13, 0x15},
      /*target_name*/ "target1.test");
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      "domain2.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {2, kMetadata}});
  base::Value value = result->ToValue();

  // Note that the `ech_config_list` base64 encodes to "ARMV".
  std::optional<base::Value> expected = base::JSONReader::Read(
      R"(
        {
          "domain_name": "domain2.test",
          "metadatas": [
            {
              "metadata_value":
              {
                "ech_config_list": "ARMV",
                "supported_protocol_alpns": ["http/1.1", "h2", "h3"],
                "target_name": "target1.test"
              },
              "metadata_weight": 2
            }
          ],
          "query_type": "HTTPS",
          "source": "dns",
          "timed_expiration": "0",
          "type": "metadata"
        }
        )");
  ASSERT_TRUE(expected.has_value());

  EXPECT_EQ(value, expected.value());
}

TEST(HostResolverInternalResultTest, DeserializeMalformedMetadataValue) {
  const ConnectionEndpointMetadata kMetadata(
      /*supported_protocol_alpns=*/{"http/1.1", "h2", "h3"},
      /*ech_config_list=*/{0x01, 0x13, 0x15},
      /*target_name*/ "target1.test");
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      "domain2.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {2, kMetadata}});
  base::Value valid_value = result->ToValue();
  ASSERT_TRUE(HostResolverInternalMetadataResult::FromValue(valid_value));

  base::Value missing_domain = valid_value.Clone();
  ASSERT_TRUE(missing_domain.GetDict().Remove("domain_name"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(missing_domain));

  base::Value missing_qtype = valid_value.Clone();
  ASSERT_TRUE(missing_qtype.GetDict().Remove("query_type"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(missing_qtype));
  base::Value unknown_qtype = valid_value.Clone();
  ASSERT_TRUE(unknown_qtype.GetDict().Set("query_type", "foo"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(unknown_qtype));

  base::Value missing_value_type = valid_value.Clone();
  ASSERT_TRUE(missing_value_type.GetDict().Remove("type"));
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(missing_value_type));
  base::Value unknown_value_type = valid_value.Clone();
  ASSERT_TRUE(unknown_value_type.GetDict().Set("type", "foo"));
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(unknown_value_type));

  base::Value missing_source = valid_value.Clone();
  ASSERT_TRUE(missing_source.GetDict().Remove("source"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(missing_source));
  base::Value unknown_source = valid_value.Clone();
  ASSERT_TRUE(unknown_source.GetDict().Set("source", "foo"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(unknown_source));

  base::Value missing_expiration = valid_value.Clone();
  ASSERT_TRUE(missing_expiration.GetDict().Remove("timed_expiration"));
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(missing_expiration));
  base::Value invalid_expiration = valid_value.Clone();
  ASSERT_TRUE(invalid_expiration.GetDict().Set("timed_expiration", "foo"));
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(invalid_expiration));

  base::Value missing_metadatas = valid_value.Clone();
  ASSERT_TRUE(missing_metadatas.GetDict().Remove("metadatas"));
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(missing_metadatas));
  base::Value invalid_metadatas = valid_value.Clone();
  *invalid_metadatas.GetDict().Find("metadatas") = base::Value(4);
  EXPECT_FALSE(
      HostResolverInternalMetadataResult::FromValue(invalid_metadatas));

  base::Value missing_weight = valid_value.Clone();
  ASSERT_TRUE(missing_weight.GetDict()
                  .Find("metadatas")
                  ->GetList()
                  .front()
                  .GetDict()
                  .Remove("metadata_weight"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(missing_weight));
  base::Value invalid_weight = valid_value.Clone();
  *invalid_weight.GetDict()
       .Find("metadatas")
       ->GetList()
       .front()
       .GetDict()
       .Find("metadata_weight") = base::Value("foo");
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(invalid_weight));

  base::Value missing_value = valid_value.Clone();
  ASSERT_TRUE(missing_value.GetDict()
                  .Find("metadatas")
                  ->GetList()
                  .front()
                  .GetDict()
                  .Remove("metadata_value"));
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(missing_value));
  base::Value invalid_value = valid_value.Clone();
  *invalid_value.GetDict()
       .Find("metadatas")
       ->GetList()
       .front()
       .GetDict()
       .Find("metadata_value") = base::Value("foo");
  EXPECT_FALSE(HostResolverInternalMetadataResult::FromValue(invalid_value));
}

TEST(HostResolverInternalResultTest, ErrorResult) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain3.test", DnsQueryType::PTR, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kUnknown, ERR_NAME_NOT_RESOLVED);

  EXPECT_EQ(result->domain_name(), "domain3.test");
  EXPECT_EQ(result->query_type(), DnsQueryType::PTR);
  EXPECT_EQ(result->type(), HostResolverInternalResult::Type::kError);
  EXPECT_EQ(result->source(), HostResolverInternalResult::Source::kUnknown);
  EXPECT_THAT(result->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(result->timed_expiration(), Optional(base::Time()));

  EXPECT_THAT(result->AsError(), Ref(*result));

  EXPECT_EQ(result->error(), ERR_NAME_NOT_RESOLVED);
}

TEST(HostResolverInternalResultTest, CloneErrorResult) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain3.test", DnsQueryType::PTR, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kUnknown, ERR_NAME_NOT_RESOLVED);

  std::unique_ptr<HostResolverInternalResult> copy = result->Clone();
  EXPECT_NE(copy.get(), result.get());

  EXPECT_EQ(copy->domain_name(), "domain3.test");
  EXPECT_EQ(copy->query_type(), DnsQueryType::PTR);
  EXPECT_EQ(copy->type(), HostResolverInternalResult::Type::kError);
  EXPECT_EQ(copy->source(), HostResolverInternalResult::Source::kUnknown);
  EXPECT_THAT(copy->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(copy->timed_expiration(), Optional(base::Time()));
  EXPECT_EQ(copy->AsError().error(), ERR_NAME_NOT_RESOLVED);
}

TEST(HostResolverInternalResultTest, NoncachableErrorResult) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain3.test", DnsQueryType::PTR, /*expiration=*/std::nullopt,
      /*timed_expiration=*/std::nullopt,
      HostResolverInternalResult::Source::kUnknown, ERR_NAME_NOT_RESOLVED);

  EXPECT_EQ(result->domain_name(), "domain3.test");
  EXPECT_EQ(result->query_type(), DnsQueryType::PTR);
  EXPECT_EQ(result->type(), HostResolverInternalResult::Type::kError);
  EXPECT_EQ(result->source(), HostResolverInternalResult::Source::kUnknown);
  EXPECT_FALSE(result->expiration().has_value());
  EXPECT_FALSE(result->timed_expiration().has_value());

  EXPECT_THAT(result->AsError(), Ref(*result));

  EXPECT_EQ(result->error(), ERR_NAME_NOT_RESOLVED);
}

TEST(HostResolverInternalResultTest, RoundtripErrorResultThroughSerialization) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain4.test", DnsQueryType::A, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, ERR_DNS_SERVER_FAILED);

  base::Value value = result->ToValue();
  auto deserialized = HostResolverInternalResult::FromValue(value);
  ASSERT_TRUE(deserialized);
  ASSERT_EQ(deserialized->type(), HostResolverInternalResult::Type::kError);

  // Expect deserialized result to be the same as the original other than
  // missing non-timed expiration.
  EXPECT_EQ(deserialized->AsError(),
            HostResolverInternalErrorResult(
                result->domain_name(), result->query_type(),
                /*expiration=*/std::nullopt, result->timed_expiration().value(),
                result->source(), result->error()));
}

// Expect results to serialize to a consistent base::Value format for
// consumption by NetLog and similar.
TEST(HostResolverInternalResultTest, SerializepErrorResult) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain4.test", DnsQueryType::A, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, ERR_DNS_SERVER_FAILED);
  base::Value value = result->ToValue();

  std::optional<base::Value> expected = base::JSONReader::Read(
      R"(
        {
          "domain_name": "domain4.test",
          "error": -802,
          "query_type": "A",
          "source": "dns",
          "timed_expiration": "0",
          "type": "error"
        }
        )");
  ASSERT_TRUE(expected.has_value());

  EXPECT_EQ(value, expected.value());
}

TEST(HostResolverInternalResultTest, DeserializeMalformedErrorValue) {
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      "domain4.test", DnsQueryType::A, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, ERR_DNS_SERVER_FAILED);
  base::Value valid_value = result->ToValue();
  ASSERT_TRUE(HostResolverInternalErrorResult::FromValue(valid_value));

  base::Value missing_domain = valid_value.Clone();
  ASSERT_TRUE(missing_domain.GetDict().Remove("domain_name"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(missing_domain));

  base::Value missing_qtype = valid_value.Clone();
  ASSERT_TRUE(missing_qtype.GetDict().Remove("query_type"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(missing_qtype));
  base::Value unknown_qtype = valid_value.Clone();
  ASSERT_TRUE(unknown_qtype.GetDict().Set("query_type", "foo"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(unknown_qtype));

  base::Value missing_value_type = valid_value.Clone();
  ASSERT_TRUE(missing_value_type.GetDict().Remove("type"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(missing_value_type));
  base::Value unknown_value_type = valid_value.Clone();
  ASSERT_TRUE(unknown_value_type.GetDict().Set("type", "foo"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(unknown_value_type));

  base::Value missing_source = valid_value.Clone();
  ASSERT_TRUE(missing_source.GetDict().Remove("source"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(missing_source));
  base::Value unknown_source = valid_value.Clone();
  ASSERT_TRUE(unknown_source.GetDict().Set("source", "foo"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(unknown_source));

  base::Value invalid_expiration = valid_value.Clone();
  ASSERT_TRUE(invalid_expiration.GetDict().Set("timed_expiration", "foo"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(invalid_expiration));

  base::Value missing_error = valid_value.Clone();
  ASSERT_TRUE(missing_error.GetDict().Remove("error"));
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(missing_error));
  base::Value invalid_error = valid_value.Clone();
  *invalid_error.GetDict().Find("error") = base::Value("foo");
  EXPECT_FALSE(HostResolverInternalErrorResult::FromValue(invalid_error));
}

TEST(HostResolverInternalResultTest, AliasResult) {
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      "domain5.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, "alias_target.test");

  EXPECT_EQ(result->domain_name(), "domain5.test");
  EXPECT_EQ(result->query_type(), DnsQueryType::HTTPS);
  EXPECT_EQ(result->type(), HostResolverInternalResult::Type::kAlias);
  EXPECT_EQ(result->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(result->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(result->timed_expiration(), Optional(base::Time()));

  EXPECT_THAT(result->AsAlias(), Ref(*result));

  EXPECT_THAT(result->alias_target(), "alias_target.test");
}

TEST(HostResolverInternalResultTest, CloneAliasResult) {
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      "domain5.test", DnsQueryType::HTTPS, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, "alias_target.test");

  std::unique_ptr<HostResolverInternalResult> copy = result->Clone();
  EXPECT_NE(copy.get(), result.get());

  EXPECT_EQ(copy->domain_name(), "domain5.test");
  EXPECT_EQ(copy->query_type(), DnsQueryType::HTTPS);
  EXPECT_EQ(copy->type(), HostResolverInternalResult::Type::kAlias);
  EXPECT_EQ(copy->source(), HostResolverInternalResult::Source::kDns);
  EXPECT_THAT(copy->expiration(), Optional(base::TimeTicks()));
  EXPECT_THAT(copy->timed_expiration(), Optional(base::Time()));
  EXPECT_THAT(copy->AsAlias().alias_target(), "alias_target.test");
}

TEST(HostResolverInternalResultTest, RoundtripAliasResultThroughSerialization) {
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      "domain6.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, "alias_target1.test");

  base::Value value = result->ToValue();
  auto deserialized = HostResolverInternalResult::FromValue(value);
  ASSERT_TRUE(deserialized);
  ASSERT_EQ(deserialized->type(), HostResolverInternalResult::Type::kAlias);

  // Expect deserialized result to be the same as the original other than
  // missing non-timed expiration.
  EXPECT_EQ(deserialized->AsAlias(),
            HostResolverInternalAliasResult(
                result->domain_name(), result->query_type(),
                /*expiration=*/std::nullopt, result->timed_expiration().value(),
                result->source(), result->alias_target()));
}

// Expect results to serialize to a consistent base::Value format for
// consumption by NetLog and similar.
TEST(HostResolverInternalResultTest, SerializepAliasResult) {
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      "domain6.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, "alias_target1.test");
  base::Value value = result->ToValue();

  std::optional<base::Value> expected = base::JSONReader::Read(
      R"(
        {
          "alias_target": "alias_target1.test",
          "domain_name": "domain6.test",
          "query_type": "AAAA",
          "source": "dns",
          "timed_expiration": "0",
          "type": "alias"
        }
        )");
  ASSERT_TRUE(expected.has_value());

  EXPECT_EQ(value, expected.value());
}

TEST(HostResolverInternalResultTest, DeserializeMalformedAliasValue) {
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      "domain6.test", DnsQueryType::AAAA, base::TimeTicks(), base::Time(),
      HostResolverInternalResult::Source::kDns, "alias_target1.test");
  base::Value valid_value = result->ToValue();
  ASSERT_TRUE(HostResolverInternalAliasResult::FromValue(valid_value));

  base::Value missing_domain = valid_value.Clone();
  ASSERT_TRUE(missing_domain.GetDict().Remove("domain_name"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_domain));

  base::Value missing_qtype = valid_value.Clone();
  ASSERT_TRUE(missing_qtype.GetDict().Remove("query_type"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_qtype));
  base::Value unknown_qtype = valid_value.Clone();
  ASSERT_TRUE(unknown_qtype.GetDict().Set("query_type", "foo"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(unknown_qtype));

  base::Value missing_value_type = valid_value.Clone();
  ASSERT_TRUE(missing_value_type.GetDict().Remove("type"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_value_type));
  base::Value unknown_value_type = valid_value.Clone();
  ASSERT_TRUE(unknown_value_type.GetDict().Set("type", "foo"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(unknown_value_type));

  base::Value missing_source = valid_value.Clone();
  ASSERT_TRUE(missing_source.GetDict().Remove("source"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_source));
  base::Value unknown_source = valid_value.Clone();
  ASSERT_TRUE(unknown_source.GetDict().Set("source", "foo"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(unknown_source));

  base::Value missing_expiration = valid_value.Clone();
  ASSERT_TRUE(missing_expiration.GetDict().Remove("timed_expiration"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_expiration));
  base::Value invalid_expiration = valid_value.Clone();
  ASSERT_TRUE(invalid_expiration.GetDict().Set("timed_expiration", "foo"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(invalid_expiration));

  base::Value missing_alias = valid_value.Clone();
  ASSERT_TRUE(missing_alias.GetDict().Remove("alias_target"));
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(missing_alias));
  base::Value invalid_alias = valid_value.Clone();
  *invalid_alias.GetDict().Find("alias_target") = base::Value(5);
  EXPECT_FALSE(HostResolverInternalAliasResult::FromValue(invalid_alias));
}

}  // namespace
}  // namespace net

"""

```