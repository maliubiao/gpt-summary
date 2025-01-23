Response:
My goal is to analyze the provided C++ code and extract information based on the user's request. Here's a breakdown of the thought process:

1. **Understand the Core Functionality:** The filename `dns_response_result_extractor_unittest.cc` immediately suggests that this code is a unit test for a class named `DnsResponseResultExtractor`. The presence of `#include "net/dns/dns_response_result_extractor.h"` confirms this. Therefore, the primary function of this file is to test the functionality of `DnsResponseResultExtractor`.

2. **Identify the Tested Class's Purpose:** Examining the `#include` directives reveals that the `DnsResponseResultExtractor` likely deals with processing DNS responses (`net/dns/dns_response.h`) and extracting meaningful results, potentially for a host resolver (`net/dns/host_resolver_internal_result.h`). The name itself strongly implies this: it *extracts* *results* from a *DNS response*.

3. **Analyze the Test Cases:** The `TEST_F` macros define individual test cases. Scanning these test names provides valuable insights into the specific functionalities being tested. For example:
    * `ExtractsSingleARecord`: Tests extracting a single A record (IPv4 address).
    * `ExtractsSingleAAAARecord`: Tests extracting a single AAAA record (IPv6 address).
    * `ExtractsSingleARecordWithCname`: Tests handling CNAME records (aliases).
    * `ExtractsNxdomainAResponses`: Tests handling "Name Error" (NXDOMAIN) responses.
    * `ExtractsTxtResponses`: Tests extracting TXT records (arbitrary text).
    * `ExtractsPtrResponses`: Tests extracting PTR records (reverse DNS lookup).
    * `ExtractsSrvResponses`: Tests extracting SRV records (service location).
    * `RejectsMalformedARecord`: Tests how the extractor handles malformed records.
    * `RejectsWrongNameARecord`: Tests how the extractor handles records with incorrect names.
    * `IgnoresWrongTypeRecordsInAResponse`: Tests how the extractor handles records of the wrong type.

4. **Look for Connections to JavaScript:** The request specifically asks about JavaScript relevance. DNS resolution is a fundamental network operation. While this C++ code doesn't directly execute JavaScript, the *results* of DNS resolution are crucial for JavaScript running in a browser. When a JavaScript program (e.g., using `fetch()` or `XMLHttpRequest`) needs to connect to a server, the browser performs a DNS lookup. This C++ code plays a role in ensuring that the browser correctly interprets the DNS response and obtains the server's IP address.

5. **Consider Logic and Assumptions:** The tests often involve building a `DnsResponse` object with specific data and then using the `DnsResponseResultExtractor` to process it. The `EXPECT_THAT` macros verify the output against expected values. This allows me to infer the expected behavior of the extractor given different input DNS responses. For example, if a response has an A record, the extractor should return the corresponding IP address. If the response is NXDOMAIN, it should return an error.

6. **Identify Potential User Errors:**  The tests with names like "RejectsMalformed..." and "RejectsWrongName..." point to potential issues that could arise from invalid or unexpected DNS data. While *users* don't directly interact with this C++ code, developers configuring DNS servers or writing network applications might encounter these scenarios. A common user-facing error related to DNS is `ERR_NAME_NOT_RESOLVED`, which this code directly deals with in the NXDOMAIN and NODATA tests.

7. **Trace User Actions (Debugging Clues):**  To understand how a user's action might lead to this code being executed, I need to consider the browser's network stack. A user typing a URL into the address bar is a prime example. This triggers the following (simplified) sequence:
    * The browser parses the URL to extract the hostname.
    * The browser initiates a DNS query for that hostname.
    * The operating system or a configured DNS server responds with a DNS response.
    * The browser's network stack (where this C++ code resides) receives the DNS response.
    * The `DnsResponseResultExtractor` (the code being analyzed) is used to interpret the DNS response.
    * The extracted results (IP addresses, etc.) are used to establish a connection to the server.

8. **Synthesize a Summary:**  Finally, I need to synthesize a concise summary of the file's function. This involves stating that it's a unit test file for `DnsResponseResultExtractor` and outlining the key aspects of what the tested class does (extracting DNS results, handling different record types and error conditions).

By following these steps, I can systematically analyze the code and generate a comprehensive answer addressing all aspects of the user's request.
这是文件 `net/dns/dns_response_result_extractor_unittest.cc` 的第一部分，其主要功能是**测试 `DnsResponseResultExtractor` 类的功能**。

`DnsResponseResultExtractor` 的作用是从 DNS 响应中提取有用的信息，并将其转换为 `HostResolverInternalResult` 对象。这些结果随后会被用于 Chromium 的网络栈中进行主机名解析。

以下是对该文件功能的更详细归纳：

**核心功能：**

* **单元测试 `DnsResponseResultExtractor` 类:**  该文件包含了多个 `TEST_F` 宏定义的测试用例，用于验证 `DnsResponseResultExtractor` 类的各种提取逻辑是否正确。

**测试的场景包括：**

* **成功提取各种 DNS 记录:**
    * **A 记录 (IPv4 地址):** 测试提取单个 A 记录以及包含 CNAME 的 A 记录。
    * **AAAA 记录 (IPv6 地址):** 测试提取单个 AAAA 记录。
    * **TXT 记录 (文本信息):** 测试提取 TXT 记录，包括包含多个字符串的情况。
    * **PTR 记录 (反向 DNS 查询):** 测试提取 PTR 记录。
    * **SRV 记录 (服务位置):** 测试提取 SRV 记录，并验证其优先级和权重排序。
* **处理 DNS 错误响应:**
    * **NXDOMAIN (域名不存在):** 测试提取 NXDOMAIN 响应并转换为相应的错误结果。
    * **NODATA (请求的记录类型不存在):** 测试提取 NODATA 响应并转换为相应的错误结果。
* **处理异常情况:**
    * **格式错误的 DNS 记录:** 测试当 DNS 响应中包含格式错误的记录时，提取器是否能正确处理。
    * **名称不匹配的 DNS 记录:** 测试当 DNS 响应中的记录名称与请求的名称不匹配时，提取器是否能正确处理。
    * **包含错误类型的 DNS 记录:** 测试当 DNS 响应中包含与请求类型不符的记录时，提取器是否会忽略这些记录。
* **处理 TTL (Time To Live):** 测试提取 DNS 记录中的最小 TTL 值，并将其用于设置缓存过期时间。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它处理的 DNS 解析结果直接影响到 JavaScript 在浏览器中的网络请求行为。

**举例说明:**

假设一个 JavaScript 脚本尝试访问 `address.test`：

```javascript
fetch('http://address.test');
```

1. 浏览器会首先进行 DNS 查询，请求 `address.test` 的 A 记录。
2. DNS 服务器返回一个包含 `address.test` 的 A 记录的响应，例如 `192.168.0.1`。
3. Chromium 的网络栈接收到这个 DNS 响应。
4. **`DnsResponseResultExtractor` 类（就是这个测试文件测试的对象）会被用来解析这个 DNS 响应，并提取出 `192.168.0.1` 这个 IP 地址。**
5. Chromium 的网络栈使用提取出的 IP 地址 `192.168.0.1` 与服务器建立连接，完成 JavaScript 的 `fetch` 请求。

**逻辑推理：**

**假设输入:**  一个包含 `address.test` 的 A 记录的 DNS 响应，其 IP 地址为 `192.168.0.1`，TTL 为 3600 秒。

**预期输出:**  一个 `HostResolverInternalResult` 对象，包含以下信息：
* 主机名: `address.test`
* 查询类型: `A`
* 源: `kDnsSource`
* IP 地址: `192.168.0.1`
* 过期时间:  当前时间 + 3600 秒

**用户或编程常见的使用错误：**

虽然用户不会直接操作 `DnsResponseResultExtractor`，但 DNS 配置错误或服务器响应异常会导致这个提取器遇到问题，最终可能导致用户在浏览器中看到网络错误。

**举例说明：**

* **DNS 服务器配置错误：** 如果 DNS 服务器将 `address.test` 配置为指向错误的 IP 地址，`DnsResponseResultExtractor` 会提取到错误的 IP，导致用户的 JavaScript 代码连接到错误的服务器。
* **DNS 响应格式错误：** 如果 DNS 服务器返回的响应格式不符合标准，`DnsResponseResultExtractor` 可能会因为格式错误而无法解析，导致连接失败。 这也是该文件测试 "RejectsMalformedARecord" 等场景的原因。
* **域名不存在 (NXDOMAIN)：** 用户在浏览器中输入了一个不存在的域名，DNS 服务器会返回 NXDOMAIN 响应。 `DnsResponseResultExtractor` 会正确地提取这个错误信息，最终浏览器会显示 `ERR_NAME_NOT_RESOLVED` 错误。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入 URL 或点击链接：** 例如，用户输入 `http://address.test`。
2. **浏览器解析 URL 并提取主机名：** 浏览器识别出需要解析的主机名是 `address.test`。
3. **浏览器发起 DNS 查询：** 浏览器的网络栈会发起一个 DNS 查询请求 `address.test` 的 A 记录（或其他相关记录）。
4. **操作系统或配置的 DNS 解析器处理 DNS 查询：**  操作系统或用户配置的 DNS 服务器会处理这个查询。
5. **DNS 服务器返回 DNS 响应：** DNS 服务器根据查询结果返回一个 DNS 响应包。
6. **Chromium 网络栈接收 DNS 响应：** 浏览器接收到 DNS 响应包。
7. **`DnsResponseResultExtractor` 被调用：**  为了理解 DNS 响应的内容，`DnsResponseResultExtractor` 类会被实例化并用于解析这个响应包。
8. **提取结果被用于后续操作：** `DnsResponseResultExtractor` 提取出的 IP 地址或其他信息会被用于建立 TCP 连接，发送 HTTP 请求等后续网络操作。

**总结该部分的功能：**

这部分代码是 `DnsResponseResultExtractor` 类的单元测试，它通过模拟各种 DNS 响应（包括成功的记录和各种错误情况）来验证该类是否能够正确地从 DNS 响应中提取出所需的信息，并将其转换为适合 Chromium 网络栈使用的 `HostResolverInternalResult` 对象。  这保证了 Chromium 在处理 DNS 响应时的正确性和健壮性。

### 提示词
```
这是目录为net/dns/dns_response_result_extractor_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_response_result_extractor.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/ranges/algorithm.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/base/connection_endpoint_metadata_test_util.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/dns_query.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_internal_result_test_util.h"
#include "net/dns/host_resolver_results_test_util.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Ne;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::Pointee;
using ::testing::ResultOf;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

using ExtractionError = DnsResponseResultExtractor::ExtractionError;
using ResultsOrError = DnsResponseResultExtractor::ResultsOrError;

constexpr HostResolverInternalResult::Source kDnsSource =
    HostResolverInternalResult::Source::kDns;

class DnsResponseResultExtractorTest : public ::testing::Test {
 protected:
  base::SimpleTestClock clock_;
  base::SimpleTestTickClock tick_clock_;
};

TEST_F(DnsResponseResultExtractorTest, ExtractsSingleARecord) {
  constexpr char kName[] = "address.test";
  const IPAddress kExpected(192, 168, 0, 1);

  DnsResponse response = BuildTestDnsAddressResponse(kName, kExpected);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::A, kDnsSource,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  ElementsAre(IPEndPoint(kExpected, /*port=*/0))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsSingleAAAARecord) {
  constexpr char kName[] = "address.test";

  IPAddress expected;
  CHECK(expected.AssignFromIPLiteral("2001:4860:4860::8888"));

  DnsResponse response = BuildTestDnsAddressResponse(kName, expected);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::AAAA,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::AAAA, kDnsSource,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  ElementsAre(IPEndPoint(expected, /*port=*/0))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsSingleARecordWithCname) {
  const IPAddress kExpected(192, 168, 0, 1);
  constexpr char kName[] = "address.test";
  constexpr char kCanonicalName[] = "alias.test";

  DnsResponse response =
      BuildTestDnsAddressResponseWithCname(kName, kExpected, kCanonicalName);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalDataResult(
              kCanonicalName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              ElementsAre(IPEndPoint(kExpected, /*port=*/0)))),
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), kCanonicalName))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsARecordsWithCname) {
  constexpr char kName[] = "addresses.test";

  DnsResponse response = BuildTestDnsResponse(
      "addresses.test", dns_protocol::kTypeA,
      {
          BuildTestAddressRecord("alias.test", IPAddress(74, 125, 226, 179)),
          BuildTestAddressRecord("alias.test", IPAddress(74, 125, 226, 180)),
          BuildTestCnameRecord(kName, "alias.test"),
          BuildTestAddressRecord("alias.test", IPAddress(74, 125, 226, 176)),
          BuildTestAddressRecord("alias.test", IPAddress(74, 125, 226, 177)),
          BuildTestAddressRecord("alias.test", IPAddress(74, 125, 226, 178)),
      });
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(
      results.value(),
      UnorderedElementsAre(
          Pointee(ExpectHostResolverInternalDataResult(
              "alias.test", DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt),
              UnorderedElementsAre(
                  IPEndPoint(IPAddress(74, 125, 226, 179), /*port=*/0),
                  IPEndPoint(IPAddress(74, 125, 226, 180), /*port=*/0),
                  IPEndPoint(IPAddress(74, 125, 226, 176), /*port=*/0),
                  IPEndPoint(IPAddress(74, 125, 226, 177), /*port=*/0),
                  IPEndPoint(IPAddress(74, 125, 226, 178), /*port=*/0)))),
          Pointee(ExpectHostResolverInternalAliasResult(
              kName, DnsQueryType::A, kDnsSource,
              /*expiration_matcher=*/Ne(std::nullopt),
              /*timed_expiration_matcher=*/Ne(std::nullopt), "alias.test"))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNxdomainAResponses) {
  constexpr char kName[] = "address.test";
  constexpr auto kTtl = base::Hours(2);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)},
      /*additional=*/{}, dns_protocol::kRcodeNXDOMAIN);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::A, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataAResponses) {
  constexpr char kName[] = "address.test";
  constexpr auto kTtl = base::Minutes(15);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::A, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataAResponsesWithoutTtl) {
  constexpr char kName[] = "address.test";

  // Response without a TTL-containing SOA record.
  DnsResponse response =
      BuildTestDnsResponse(kName, dns_protocol::kTypeA, /*answers=*/{});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty result because not cacheable.
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, RejectsMalformedARecord) {
  constexpr char kName[] = "address.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA,
      {BuildTestDnsRecord(kName, dns_protocol::kTypeA,
                          "malformed rdata")} /* answers */);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::A,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMalformedRecord);
}

TEST_F(DnsResponseResultExtractorTest, RejectsWrongNameARecord) {
  constexpr char kName[] = "address.test";

  DnsResponse response = BuildTestDnsAddressResponse(
      kName, IPAddress(1, 2, 3, 4), "different.test");
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::A,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresWrongTypeRecordsInAResponse) {
  constexpr char kName[] = "address.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA,
      {BuildTestTextRecord("address.test", {"foo"} /* text_strings */)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty results because NODATA is not cacheable (due to no TTL).
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest,
       IgnoresWrongTypeRecordsMixedWithARecords) {
  constexpr char kName[] = "address.test";
  const IPAddress kExpected(8, 8, 8, 8);
  constexpr auto kTtl = base::Days(3);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA,
      {BuildTestTextRecord(kName, /*text_strings=*/{"foo"}, base::Hours(2)),
       BuildTestAddressRecord(kName, kExpected, kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::A, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ElementsAre(IPEndPoint(kExpected, /*port=*/0))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsMinATtl) {
  constexpr char kName[] = "name.test";
  constexpr base::TimeDelta kMinTtl = base::Minutes(4);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeA,
      {BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4), base::Hours(3)),
       BuildTestAddressRecord(kName, IPAddress(2, 3, 4, 5), kMinTtl),
       BuildTestAddressRecord(kName, IPAddress(3, 4, 5, 6),
                              base::Minutes(15))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::A,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::A, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kMinTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kMinTtl),
                  /*endpoints_matcher=*/SizeIs(3)))));
}

MATCHER_P(ContainsContiguousElements, elements, "") {
  return base::ranges::search(arg, elements) != arg.end();
}

TEST_F(DnsResponseResultExtractorTest, ExtractsTxtResponses) {
  constexpr char kName[] = "name.test";

  // Simulate two separate DNS records, each with multiple strings.
  std::vector<std::string> foo_records = {"foo1", "foo2", "foo3"};
  std::vector<std::string> bar_records = {"bar1", "bar2"};
  std::vector<std::vector<std::string>> text_records = {foo_records,
                                                        bar_records};

  DnsResponse response =
      BuildTestDnsTextResponse(kName, std::move(text_records));
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  // Order between separate DNS records is undefined, but each record should
  // stay in order as that order may be meaningful.
  EXPECT_THAT(
      results.value(),
      ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::TXT, kDnsSource,
          /*expiration_matcher=*/Ne(std::nullopt),
          /*timed_expiration_matcher=*/Ne(std::nullopt),
          /*endpoints_matcher=*/IsEmpty(),
          /*strings_matcher=*/
          AllOf(UnorderedElementsAre("foo1", "foo2", "foo3", "bar1", "bar2"),
                ContainsContiguousElements(foo_records),
                ContainsContiguousElements(bar_records))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNxdomainTxtResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Days(4);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)},
      /*additional=*/{}, dns_protocol::kRcodeNXDOMAIN);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::TXT, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataTxtResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Minutes(42);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      /*answers=*/{}, /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::TXT, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, RejectsMalformedTxtRecord) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestDnsRecord(kName, dns_protocol::kTypeTXT,
                          "malformed rdata")} /* answers */);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMalformedRecord);
}

TEST_F(DnsResponseResultExtractorTest, RejectsWrongNameTxtRecord) {
  constexpr char kName[] = "name.test";

  DnsResponse response =
      BuildTestDnsTextResponse(kName, {{"foo"}}, "different.test");
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::TXT,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresWrongTypeTxtResponses) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty results because NODATA is not cacheable (due to no TTL).
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, ExtractsMinTxtTtl) {
  constexpr char kName[] = "name.test";
  constexpr base::TimeDelta kMinTtl = base::Minutes(4);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeTXT,
      {BuildTestTextRecord(kName, {"foo"}, base::Hours(3)),
       BuildTestTextRecord(kName, {"bar"}, kMinTtl),
       BuildTestTextRecord(kName, {"baz"}, base::Minutes(15))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::TXT,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::TXT, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kMinTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kMinTtl),
                  /*endpoints_matcher=*/IsEmpty(),
                  /*strings_matcher=*/SizeIs(3)))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsPtrResponses) {
  constexpr char kName[] = "name.test";

  DnsResponse response =
      BuildTestDnsPointerResponse(kName, {"foo.com", "bar.com"});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::PTR,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::PTR, kDnsSource,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  /*endpoints_matcher=*/IsEmpty(),
                  /*strings_matcher=*/IsEmpty(),
                  /*hosts_matcher=*/
                  UnorderedElementsAre(HostPortPair("foo.com", 0),
                                       HostPortPair("bar.com", 0))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNxdomainPtrResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Hours(5);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypePTR, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)},
      /*additional=*/{}, dns_protocol::kRcodeNXDOMAIN);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::PTR,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::PTR, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataPtrResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Minutes(50);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypePTR, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::PTR,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::PTR, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, RejectsMalformedPtrRecord) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypePTR,
      {BuildTestDnsRecord(kName, dns_protocol::kTypePTR,
                          "malformed rdata")} /* answers */);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::PTR,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMalformedRecord);
}

TEST_F(DnsResponseResultExtractorTest, RejectsWrongNamePtrRecord) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsPointerResponse(
      kName, {"foo.com", "bar.com"}, "different.test");
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::PTR,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresWrongTypePtrResponses) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypePTR,
      {BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4))});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::PTR,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  // Expect empty results because NODATA is not cacheable (due to no TTL).
  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(), IsEmpty());
}

TEST_F(DnsResponseResultExtractorTest, ExtractsSrvResponses) {
  constexpr char kName[] = "name.test";

  const TestServiceRecord kRecord1 = {2, 3, 1223, "foo.com"};
  const TestServiceRecord kRecord2 = {5, 10, 80, "bar.com"};
  const TestServiceRecord kRecord3 = {5, 1, 5, "google.com"};
  const TestServiceRecord kRecord4 = {2, 100, 12345, "chromium.org"};

  DnsResponse response = BuildTestDnsServiceResponse(
      kName, {kRecord1, kRecord2, kRecord3, kRecord4});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::SRV,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::SRV, kDnsSource,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  /*endpoints_matcher=*/IsEmpty(),
                  /*strings_matcher=*/IsEmpty(),
                  /*hosts_matcher=*/
                  UnorderedElementsAre(HostPortPair("foo.com", 1223),
                                       HostPortPair("bar.com", 80),
                                       HostPortPair("google.com", 5),
                                       HostPortPair("chromium.org", 12345))))));

  // Expect ordered by priority, and random within a priority.
  std::vector<HostPortPair> result_hosts =
      (*results.value().begin())->AsData().hosts();
  auto priority2 =
      std::vector<HostPortPair>(result_hosts.begin(), result_hosts.begin() + 2);
  EXPECT_THAT(priority2, testing::UnorderedElementsAre(
                             HostPortPair("foo.com", 1223),
                             HostPortPair("chromium.org", 12345)));
  auto priority5 =
      std::vector<HostPortPair>(result_hosts.begin() + 2, result_hosts.end());
  EXPECT_THAT(priority5,
              testing::UnorderedElementsAre(HostPortPair("bar.com", 80),
                                            HostPortPair("google.com", 5)));
}

// 0-weight services are allowed. Ensure that we can handle such records,
// especially the case where all entries have weight 0.
TEST_F(DnsResponseResultExtractorTest, ExtractsZeroWeightSrvResponses) {
  constexpr char kName[] = "name.test";

  const TestServiceRecord kRecord1 = {5, 0, 80, "bar.com"};
  const TestServiceRecord kRecord2 = {5, 0, 5, "google.com"};

  DnsResponse response =
      BuildTestDnsServiceResponse(kName, {kRecord1, kRecord2});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::SRV,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalDataResult(
                  kName, DnsQueryType::SRV, kDnsSource,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  /*endpoints_matcher=*/IsEmpty(),
                  /*strings_matcher=*/IsEmpty(),
                  /*hosts_matcher=*/
                  UnorderedElementsAre(HostPortPair("bar.com", 80),
                                       HostPortPair("google.com", 5))))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNxdomainSrvResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Days(7);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeSRV, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)},
      /*additional=*/{}, dns_protocol::kRcodeNXDOMAIN);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::SRV,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::SRV, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, ExtractsNodataSrvResponses) {
  constexpr char kName[] = "name.test";
  constexpr auto kTtl = base::Hours(12);

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeSRV, /*answers=*/{},
      /*authority=*/
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSOA, "fake rdata", kTtl)});
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  ResultsOrError results =
      extractor.ExtractDnsResults(DnsQueryType::SRV,
                                  /*original_domain_name=*/kName,
                                  /*request_port=*/0);

  ASSERT_TRUE(results.has_value());
  EXPECT_THAT(results.value(),
              ElementsAre(Pointee(ExpectHostResolverInternalErrorResult(
                  kName, DnsQueryType::SRV, kDnsSource,
                  /*expiration_matcher=*/Eq(tick_clock_.NowTicks() + kTtl),
                  /*timed_expiration_matcher=*/Eq(clock_.Now() + kTtl),
                  ERR_NAME_NOT_RESOLVED))));
}

TEST_F(DnsResponseResultExtractorTest, RejectsMalformedSrvRecord) {
  constexpr char kName[] = "name.test";

  DnsResponse response = BuildTestDnsResponse(
      kName, dns_protocol::kTypeSRV,
      {BuildTestDnsRecord(kName, dns_protocol::kTypeSRV,
                          "malformed rdata")} /* answers */);
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::SRV,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kMalformedRecord);
}

TEST_F(DnsResponseResultExtractorTest, RejectsWrongNameSrvRecord) {
  constexpr char kName[] = "name.test";

  const TestServiceRecord kRecord = {2, 3, 1223, "foo.com"};
  DnsResponse response =
      BuildTestDnsServiceResponse(kName, {kRecord}, "different.test");
  DnsResponseResultExtractor extractor(response, clock_, tick_clock_);

  EXPECT_EQ(extractor
                .ExtractDnsResults(DnsQueryType::SRV,
                                   /*original_domain_name=*/kName,
                                   /*request_port=*/0)
                .error_or(ExtractionError::kOk),
            ExtractionError::kNameMismatch);
}

TEST_F(DnsResponseResultExtractorTest, IgnoresWron
```