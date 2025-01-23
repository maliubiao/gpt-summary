Response:
My thinking process to answer the request about `reporting_header_parser_unittest.cc` went like this:

1. **Understand the Core Purpose:** The filename itself gives a huge clue: `reporting_header_parser_unittest.cc`. This immediately tells me it's a unit test file for a component that *parses reporting headers*. The ".cc" signifies it's C++ code, and "unittest" confirms its purpose.

2. **Scan the Includes:**  The `#include` directives provide a high-level overview of the dependencies and what the code interacts with. I looked for key terms:
    * `reporting_header_parser.h`: This confirms the core component being tested.
    * `<optional>`, `<sstream>`, `<string>`, `<vector>`: Standard C++ utilities for data handling.
    * `base/functional/bind.h`, `base/json/json_reader.h`, `base/strings/...`:  Chromium's base library features, particularly JSON parsing and string manipulation.
    * `base/test/...`: Chromium's testing framework components (`histogram_tester`, `scoped_feature_list`, `simple_test_tick_clock`).
    * `net/base/...`: Core networking concepts like `features`, `isolation_info`, `network_anonymization_key`, `schemeful_site`.
    * `net/reporting/...`: Specific reporting-related classes like `mock_persistent_reporting_store`, `reporting_cache`, `reporting_endpoint`, etc. This signals the file is testing how headers are processed and affect these reporting mechanisms.
    * `testing/gtest/...`: Google Test framework for writing the unit tests.
    * `url/gurl.h`, `url/origin.h`: URL and Origin handling, crucial for web-related code.

3. **Analyze the `ReportingHeaderParserTestBase` Class:** This base class sets up the testing environment. Key observations:
    * It inherits from `ReportingTestBase` (likely providing common reporting test utilities) and `::testing::WithParamInterface<bool>` (indicating parameterized tests, where the boolean likely controls whether a mock persistent store is used).
    * It initializes a `ReportingPolicy`.
    * It conditionally creates a `MockPersistentReportingStore`. The use of a mock store is typical for unit tests to isolate the component being tested.
    * It has `SetUp` method that loads reporting clients from the mock store. This is important for simulating real-world scenarios.
    * It defines various constants for URLs, Origins, NetworkAnonymizationKeys, group names, etc. These are the test fixtures.

4. **Examine the `ReportingHeaderParserTest` Class:** This class derives from the base class and contains the actual test cases.
    * It enables the `kPartitionConnectionsByNetworkIsolationKey` feature. This hints at a specific feature the tests might be focusing on.
    * It has helper methods like `MakeEndpointGroup` and `ConstructHeaderGroupString` to create test data in a structured way. The `ConstructHeaderGroupString` function is particularly important as it shows how the expected header format is generated for testing.
    * The `ParseHeader` method uses `base::JSONReader::Read` and `ReportingHeaderParser::ParseReportToHeader`. This is the core action being tested – parsing a JSON string representing a reporting header.

5. **Look at the Test Cases (High-Level):** I quickly skimmed the test functions like `Invalid`, `Basic`, `PathAbsoluteURLEndpoint`, etc. to understand the range of scenarios being tested. I noticed tests for:
    * Invalid header formats.
    * Basic valid header parsing.
    * Different header options like `include_subdomains`, `priority`, `weight`, `max_age`.
    * Handling of multiple endpoints and groups.
    * Interactions with the persistent store (if enabled).

6. **Identify Key Functionality (Based on the Analysis):**  Based on the above points, I started listing the core functionalities:
    * Parsing "Report-To" headers.
    * Handling different directives within the header (max_age, endpoints, group, include_subdomains, priority, weight).
    * Validating header syntax and rejecting invalid formats.
    * Storing parsed information in the `ReportingCache`.
    * Interacting with a `MockPersistentReportingStore` (if configured).
    * Considering Network Isolation Keys and Origins.

7. **Consider Relationships with JavaScript:** I knew "Report-To" is a web standard, so I considered how JavaScript interacts with it:
    * JavaScript in a web page can trigger network requests that receive these headers.
    * The browser's networking stack (which Chromium's code is a part of) parses these headers.
    * The parsed information influences how the browser handles reporting errors.

8. **Think About Logical Reasoning (Assumptions & Outputs):**  For a simple test like `Basic`, I could infer the input (a specific header string) and the expected output (certain data stored in the cache). For invalid cases, the expectation is that nothing is stored in the cache.

9. **Identify Potential User/Programming Errors:** I thought about common mistakes developers make when working with "Report-To":
    * Incorrect JSON syntax.
    * Using insecure URLs for endpoints.
    * Providing invalid values for directives (e.g., negative `max_age`).

10. **Trace User Actions to the Code:** I imagined a user browsing a website:
    * User navigates to a page.
    * The server sends HTTP responses, including "Report-To" headers.
    * Chromium's network stack receives and parses these headers.
    * The parsing logic in `reporting_header_parser.cc` is invoked, and the unit tests in this file verify that logic.

11. **Synthesize the Summary:** Finally, I combined all the above observations to write a concise summary of the file's purpose.

Essentially, I approached it like investigating a system: looking at the inputs, the core component being tested, the outputs, and how it fits into the larger picture (the web browsing process). The code itself and the naming conventions within the Chromium project provide a lot of valuable information.
这是Chromium网络栈中名为 `reporting_header_parser_unittest.cc` 的源代码文件的第一部分，其主要功能是**测试 `net/reporting/reporting_header_parser.h` 中定义的 Reporting Header 解析器的功能**。

更具体地说，它测试了 `Report-To` HTTP 头部的解析逻辑，包括：

**核心功能归纳:**

1. **解析有效的 `Report-To` 头部:** 测试能够正确解析符合规范的 `Report-To` 头部，提取出端点组 (endpoint group) 和端点 (endpoint) 的信息，并将其存储到 `ReportingCache` 中。
2. **处理各种 `Report-To` 头部指令:** 测试对 `max_age`，`group`，`endpoints`，`include_subdomains`，`priority` 和 `weight` 等指令的解析和处理是否正确。
3. **处理无效的 `Report-To` 头部:** 测试能够识别并拒绝格式错误的 `Report-To` 头部，并且不会将其错误的信息存储到 `ReportingCache` 中。
4. **与持久化存储交互 (可选):**  测试在启用持久化存储的情况下，解析后的端点组和端点信息是否被正确地存储到 `MockPersistentReportingStore` 中。
5. **考虑网络隔离键 (Network Anonymization Key, NAK) 和 Origin:** 测试解析器在处理 `Report-To` 头部时是否考虑了请求的来源 (Origin) 和网络隔离键。

**与 JavaScript 的关系:**

`Report-To` 是一个 Web 标准，JavaScript 可以通过以下方式与之产生关系：

* **接收包含 `Report-To` 头部的 HTTP 响应:**  当浏览器中的 JavaScript 发起网络请求时，服务器的响应头可能包含 `Report-To` 头部。
* **浏览器解析 `Report-To` 头部并触发 Reporting API:** 浏览器接收到包含 `Report-To` 头部的响应后，其网络栈（包括这里测试的解析器）会解析该头部。解析后的信息会被浏览器用于后续的错误报告。开发者可以通过 Reporting API 监控和处理这些报告。

**举例说明:**

假设一个网站的服务器返回以下 HTTP 响应头：

```
Report-To: [{
    "group": "endpoint-group-1",
    "max_age": 3600,
    "endpoints": [{"url": "https://report-collector.example.com/report"}]
}]
```

当浏览器接收到这个响应头时，`reporting_header_parser_unittest.cc` 中测试的代码会验证 `ReportingHeaderParser` 是否能够正确解析出以下信息：

* **group:** "endpoint-group-1"
* **max_age:** 3600 秒
* **endpoints:** 一个 URL 为 "https://report-collector.example.com/report" 的端点。

这些信息会被存储在浏览器的 `ReportingCache` 中，后续当该网站发生符合条件的错误时，浏览器会向 "https://report-collector.example.com/report" 发送错误报告。

**逻辑推理 (假设输入与输出):**

**假设输入 (有效的 `Report-To` 头部字符串):**

```json
"[{\"group\": \"my-group\", \"max_age\": 60, \"endpoints\": [{\"url\": \"https://a.test/report\"}]}]"
```

**预期输出:**

* `ReportingCache` 中会新增一个端点组，其 `group_key` 的 `group_name` 为 "my-group"，`ttl` 为 60 秒。
* 该端点组包含一个端点，其 URL 为 "https://a.test/report"。
* 如果启用了 `MockPersistentReportingStore`，则会记录添加该端点组和端点的命令。

**假设输入 (无效的 `Report-To` 头部字符串，缺少 `url`):**

```json
"[{\"group\": \"my-group\", \"max_age\": 60, \"endpoints\": [{}]}]"
```

**预期输出:**

* `ReportingCache` 中不会新增任何端点组或端点。
* 相关的无效头部类型的直方图计数器会增加。
* 如果启用了 `MockPersistentReportingStore`，则不会记录任何添加操作。

**用户或编程常见的使用错误 (举例说明):**

1. **在 `Report-To` 头部中使用不安全的 HTTP URL:**

   ```
   Report-To: [{"group": "insecure", "max_age": 60, "endpoints": [{"url": "http://insecure.test/report"}]}]
   ```

   **错误:**  `ReportingHeaderParser` 会拒绝包含不安全 URL 的端点配置。

2. **`max_age`  不是一个正整数:**

   ```
   Report-To: [{"group": "invalid-age", "max_age": "abc", "endpoints": [{"url": "https://valid.test/report"}]}]
   ```

   **错误:** `ReportingHeaderParser` 会识别出 `max_age` 的类型错误，并拒绝该头部。

3. **`endpoints` 数组为空:**

   ```
   Report-To: [{"group": "no-endpoints", "max_age": 60, "endpoints": []}]
   ```

   **说明:** 虽然技术上有效，但这种配置没有实际意义，因为没有指定报告发送到哪里。

**用户操作到达这里的步骤 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL 并访问一个网站 (例如 `https://example.com`)。**
2. **网站的服务器返回 HTTP 响应，其中包含 `Report-To` 头部。**
3. **Chromium 浏览器接收到这个响应。**
4. **Chromium 的网络栈开始处理接收到的 HTTP 响应头。**
5. **`net/http/http_response_headers.cc` 等文件中的代码会检测到 `Report-To` 头部。**
6. **`net/reporting/reporting_header_parser.cc` 中的 `ParseReportToHeader` 函数会被调用，负责解析该头部。**
7. **为了确保 `ParseReportToHeader` 函数的正确性，开发人员编写了 `net/reporting/reporting_header_parser_unittest.cc` 文件中的单元测试。** 当代码被修改或出现问题时，运行这些单元测试可以帮助发现和修复错误。

**总结第一部分的功能:**

这部分 `reporting_header_parser_unittest.cc` 文件的主要功能是**建立测试基础环境和定义一些辅助方法，以便后续的测试用例能够方便地测试 `Report-To` 头部解析器的核心功能，包括解析有效头部、处理各种指令以及识别无效头部。** 它定义了基类 `ReportingHeaderParserTestBase` 来初始化测试环境，并定义了 `ReportingHeaderParserTest` 类来编写具体的测试用例。 这一部分已经开始测试一些基本的有效和无效的 `Report-To` 头部解析情况。

### 提示词
```
这是目录为net/reporting/reporting_header_parser_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_header_parser.h"

#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/reporting/mock_persistent_reporting_store.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_target_type.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

using CommandType = MockPersistentReportingStore::Command::Type;
using Dictionary = structured_headers::Dictionary;

constexpr char kReportingHeaderTypeHistogram[] = "Net.Reporting.HeaderType";

class ReportingHeaderParserTestBase
    : public ReportingTestBase,
      public ::testing::WithParamInterface<bool> {
 protected:
  ReportingHeaderParserTestBase() {
    ReportingPolicy policy;
    policy.max_endpoints_per_origin = 10;
    policy.max_endpoint_count = 20;
    UsePolicy(policy);

    std::unique_ptr<MockPersistentReportingStore> store;
    if (GetParam()) {
      store = std::make_unique<MockPersistentReportingStore>();
    }
    store_ = store.get();
    UseStore(std::move(store));
  }
  ~ReportingHeaderParserTestBase() override = default;

  void SetUp() override {
    // All ReportingCache methods assume that the store has been initialized.
    if (mock_store()) {
      mock_store()->LoadReportingClients(
          base::BindOnce(&ReportingCache::AddClientsLoadedFromStore,
                         base::Unretained(cache())));
      mock_store()->FinishLoading(true);
    }
  }

  MockPersistentReportingStore* mock_store() { return store_; }

  base::test::ScopedFeatureList feature_list_;
  const GURL kUrl1_ = GURL("https://origin1.test/path");
  const url::Origin kOrigin1_ = url::Origin::Create(kUrl1_);
  const GURL kUrl2_ = GURL("https://origin2.test/path");
  const url::Origin kOrigin2_ = url::Origin::Create(kUrl2_);
  const NetworkAnonymizationKey kNak_ =
      NetworkAnonymizationKey::CreateSameSite(SchemefulSite(kOrigin1_));
  const NetworkAnonymizationKey kOtherNak_ =
      NetworkAnonymizationKey::CreateSameSite(SchemefulSite(kOrigin2_));
  const IsolationInfo kIsolationInfo_ =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            kOrigin1_,
                            kOrigin1_,
                            SiteForCookies::FromOrigin(kOrigin1_));
  const GURL kUrlEtld_ = GURL("https://co.uk/foo.html/");
  const url::Origin kOriginEtld_ = url::Origin::Create(kUrlEtld_);
  const GURL kEndpoint1_ = GURL("https://endpoint1.test/");
  const GURL kEndpoint2_ = GURL("https://endpoint2.test/");
  const GURL kEndpoint3_ = GURL("https://endpoint3.test/");
  const GURL kEndpointPathAbsolute_ =
      GURL("https://origin1.test/path-absolute-url");
  const std::string kGroup1_ = "group1";
  const std::string kGroup2_ = "group2";
  // There are 2^3 = 8 of these to test the different combinations of matching
  // vs mismatching NAK, origin, and group.
  const ReportingEndpointGroupKey kGroupKey11_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin1_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey21_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin2_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey12_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin1_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey22_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin2_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);

 private:
  raw_ptr<MockPersistentReportingStore> store_;
};

// This test is parametrized on a boolean that represents whether to use a
// MockPersistentReportingStore.
class ReportingHeaderParserTest : public ReportingHeaderParserTestBase {
 protected:
  ReportingHeaderParserTest() {
    // This is a private API of the reporting service, so no need to test the
    // case kPartitionConnectionsByNetworkIsolationKey is disabled - the
    // feature is only applied at the entry points of the service.
    feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
  }

  ReportingEndpointGroup MakeEndpointGroup(
      const std::string& name,
      const std::vector<ReportingEndpoint::EndpointInfo>& endpoints,
      OriginSubdomains include_subdomains = OriginSubdomains::DEFAULT,
      base::TimeDelta ttl = base::Days(1),
      url::Origin origin = url::Origin()) {
    ReportingEndpointGroupKey group_key(kNak_ /* unused */,
                                        url::Origin() /* unused */, name,
                                        ReportingTargetType::kDeveloper);
    ReportingEndpointGroup group;
    group.group_key = group_key;
    group.include_subdomains = include_subdomains;
    group.ttl = ttl;
    group.endpoints = std::move(endpoints);
    return group;
  }

  // Constructs a string which would represent a single group in a Report-To
  // header. If |group_name| is an empty string, the group name will be omitted
  // (and thus default to "default" when parsed). Setting |omit_defaults| omits
  // the priority, weight, and include_subdomains fields if they are default,
  // otherwise they are spelled out fully.
  std::string ConstructHeaderGroupString(const ReportingEndpointGroup& group,
                                         bool omit_defaults = true) {
    std::ostringstream s;
    s << "{ ";

    if (!group.group_key.group_name.empty()) {
      s << "\"group\": \"" << group.group_key.group_name << "\", ";
    }

    s << "\"max_age\": " << group.ttl.InSeconds() << ", ";

    if (group.include_subdomains != OriginSubdomains::DEFAULT) {
      s << "\"include_subdomains\": true, ";
    } else if (!omit_defaults) {
      s << "\"include_subdomains\": false, ";
    }

    s << "\"endpoints\": [";
    for (const ReportingEndpoint::EndpointInfo& endpoint_info :
         group.endpoints) {
      s << "{ ";
      s << "\"url\": \"" << endpoint_info.url.spec() << "\"";

      if (!omit_defaults ||
          endpoint_info.priority !=
              ReportingEndpoint::EndpointInfo::kDefaultPriority) {
        s << ", \"priority\": " << endpoint_info.priority;
      }

      if (!omit_defaults ||
          endpoint_info.weight !=
              ReportingEndpoint::EndpointInfo::kDefaultWeight) {
        s << ", \"weight\": " << endpoint_info.weight;
      }

      s << " }, ";
    }
    if (!group.endpoints.empty())
      s.seekp(-2, s.cur);  // Overwrite trailing comma and space.
    s << "]";

    s << " }";

    return s.str();
  }

  void ParseHeader(const NetworkAnonymizationKey& network_anonymization_key,
                   const url::Origin& origin,
                   const std::string& json) {
    std::optional<base::Value> value = base::JSONReader::Read("[" + json + "]");
    if (value) {
      ReportingHeaderParser::ParseReportToHeader(
          context(), network_anonymization_key, origin, value->GetList());
    }
  }
};

// TODO(juliatuttle): Ideally these tests should be expecting that JSON parsing
// (and therefore header parsing) may happen asynchronously, but the entire
// pipeline is also tested by NetworkErrorLoggingEndToEndTest.

TEST_P(ReportingHeaderParserTest, Invalid) {
  static const struct {
    const char* header_value;
    const char* description;
  } kInvalidHeaderTestCases[] = {
      {"{\"max_age\":1, \"endpoints\": [{}]}", "missing url"},
      {"{\"max_age\":1, \"endpoints\": [{\"url\":0}]}", "non-string url"},
      {"{\"max_age\":1, \"endpoints\": [{\"url\":\"//scheme/relative\"}]}",
       "scheme-relative url"},
      {"{\"max_age\":1, \"endpoints\": [{\"url\":\"relative/path\"}]}",
       "path relative url"},
      {"{\"max_age\":1, \"endpoints\": [{\"url\":\"http://insecure/\"}]}",
       "insecure url"},
      {"{\"endpoints\": [{\"url\":\"https://endpoint/\"}]}", "missing max_age"},
      {"{\"max_age\":\"\", \"endpoints\": [{\"url\":\"https://endpoint/\"}]}",
       "non-integer max_age"},
      {"{\"max_age\":-1, \"endpoints\": [{\"url\":\"https://endpoint/\"}]}",
       "negative max_age"},
      {"{\"max_age\":1, \"group\":0, "
       "\"endpoints\": [{\"url\":\"https://endpoint/\"}]}",
       "non-string group"},

      // Note that a non-boolean include_subdomains field is *not* invalid, per
      // the spec.

      // Priority should be a nonnegative integer.
      {"{\"max_age\":1, "
       "\"endpoints\": [{\"url\":\"https://endpoint/\",\"priority\":\"\"}]}",
       "non-integer priority"},
      {"{\"max_age\":1, "
       "\"endpoints\": [{\"url\":\"https://endpoint/\",\"priority\":-1}]}",
       "negative priority"},

      // Weight should be a non-negative integer.
      {"{\"max_age\":1, "
       "\"endpoints\": [{\"url\":\"https://endpoint/\",\"weight\":\"\"}]}",
       "non-integer weight"},
      {"{\"max_age\":1, "
       "\"endpoints\": [{\"url\":\"https://endpoint/\",\"weight\":-1}]}",
       "negative weight"},

      {"[{\"max_age\":1, \"endpoints\": [{\"url\":\"https://a/\"}]},"
       "{\"max_age\":1, \"endpoints\": [{\"url\":\"https://b/\"}]}]",
       "wrapped in list"}};

  base::HistogramTester histograms;
  int invalid_case_count = 0;

  for (const auto& test_case : kInvalidHeaderTestCases) {
    ParseHeader(kNak_, kOrigin1_, test_case.header_value);
    invalid_case_count++;

    EXPECT_EQ(0u, cache()->GetEndpointCount())
        << "Invalid Report-To header (" << test_case.description << ": \""
        << test_case.header_value << "\") parsed as valid.";
    histograms.ExpectBucketCount(
        kReportingHeaderTypeHistogram,
        ReportingHeaderParser::ReportingHeaderType::kReportToInvalid,
        invalid_case_count);
    if (mock_store()) {
      mock_store()->Flush();
      EXPECT_EQ(0, mock_store()->StoredEndpointsCount());
      EXPECT_EQ(0, mock_store()->StoredEndpointGroupsCount());
    }
  }
  histograms.ExpectBucketCount(
      kReportingHeaderTypeHistogram,
      ReportingHeaderParser::ReportingHeaderType::kReportTo, 0);
}

TEST_P(ReportingHeaderParserTest, Basic) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};
  base::HistogramTester histograms;

  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  histograms.ExpectBucketCount(
      kReportingHeaderTypeHistogram,
      ReportingHeaderParser::ReportingHeaderType::kReportTo, 1);
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint.group_key.group_name);
  EXPECT_EQ(kEndpoint1_, endpoint.info.url);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, PathAbsoluteURLEndpoint) {
  std::string header =
      "{\"group\": \"group1\", \"max_age\":1, \"endpoints\": "
      "[{\"url\":\"/path-absolute-url\"}]}";
  base::HistogramTester histograms;

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  histograms.ExpectBucketCount(
      kReportingHeaderTypeHistogram,
      ReportingHeaderParser::ReportingHeaderType::kReportTo, 1);
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint =
      FindEndpointInCache(kGroupKey11_, kEndpointPathAbsolute_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint.group_key.group_name);
  EXPECT_EQ(kEndpointPathAbsolute_, endpoint.info.url);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(
        CommandType::ADD_REPORTING_ENDPOINT,
        ReportingEndpoint(kGroupKey11_, ReportingEndpoint::EndpointInfo{
                                            kEndpointPathAbsolute_}));
    expected_commands.emplace_back(
        CommandType::ADD_REPORTING_ENDPOINT_GROUP,
        CachedReportingEndpointGroup(
            kGroupKey11_, OriginSubdomains::DEFAULT /* irrelevant */,
            base::Time() /* irrelevant */, base::Time() /* irrelevant */));
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, OmittedGroupName) {
  ReportingEndpointGroupKey kGroupKey(kNak_, kOrigin1_, "default",
                                      ReportingTargetType::kDeveloper);
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(std::string(), endpoints));

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointGroupExistsInCache(kGroupKey, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ("default", endpoint.group_key.group_name);
  EXPECT_EQ(kEndpoint1_, endpoint.info.url);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, IncludeSubdomainsTrue) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};

  std::string header = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup1_, endpoints, OriginSubdomains::INCLUDE));
  ParseHeader(kNak_, kOrigin1_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::INCLUDE));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, IncludeSubdomainsFalse) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};

  std::string header = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup1_, endpoints, OriginSubdomains::EXCLUDE),
      false /* omit_defaults */);
  ParseHeader(kNak_, kOrigin1_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::EXCLUDE));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, IncludeSubdomainsEtldRejected) {
  ReportingEndpointGroupKey kGroupKey(kNak_, kOriginEtld_, kGroup1_,
                                      ReportingTargetType::kDeveloper);
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};

  std::string header = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup1_, endpoints, OriginSubdomains::INCLUDE));
  ParseHeader(kNak_, kOriginEtld_, header);

  EXPECT_EQ(0u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey, OriginSubdomains::INCLUDE));
  EXPECT_EQ(0u, cache()->GetEndpointCount());
  EXPECT_FALSE(EndpointExistsInCache(kGroupKey, kEndpoint1_));
}

TEST_P(ReportingHeaderParserTest, NonIncludeSubdomainsEtldAccepted) {
  ReportingEndpointGroupKey kGroupKey(kNak_, kOriginEtld_, kGroup1_,
                                      ReportingTargetType::kDeveloper);
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};

  std::string header = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup1_, endpoints, OriginSubdomains::EXCLUDE));
  ParseHeader(kNak_, kOriginEtld_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointGroupExistsInCache(kGroupKey, OriginSubdomains::EXCLUDE));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey, kEndpoint1_));
}

TEST_P(ReportingHeaderParserTest, IncludeSubdomainsNotBoolean) {
  std::string header =
      "{\"group\": \"" + kGroup1_ +
      "\", "
      "\"max_age\":86400, \"include_subdomains\": \"NotABoolean\", "
      "\"endpoints\": [{\"url\":\"" +
      kEndpoint1_.spec() + "\"}]}";
  ParseHeader(kNak_, kOrigin1_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, NonDefaultPriority) {
  const int kNonDefaultPriority = 10;
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {
      {kEndpoint1_, kNonDefaultPriority}};

  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));
  ParseHeader(kNak_, kOrigin1_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kNonDefaultPriority, endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, NonDefaultWeight) {
  const int kNonDefaultWeight = 10;
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {
      {kEndpoint1_, ReportingEndpoint::EndpointInfo::kDefaultPriority,
       kNonDefaultWeight}};

  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));
  ParseHeader(kNak_, kOrigin1_, header);

  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(kNonDefaultWeight, endpoint.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, MaxAge) {
  const int kMaxAgeSecs = 100;
  base::TimeDelta ttl = base::Seconds(kMaxAgeSecs);
  base::Time expires = clock()->Now() + ttl;

  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};

  std::string header = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup1_, endpoints, OriginSubdomains::DEFAULT, ttl));

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointGroupExistsInCache(kGroupKey11_,
                                         OriginSubdomains::DEFAULT, expires));

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, MultipleEndpointsSameGroup) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_},
                                                            {kEndpoint2_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(2u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint.group_key.group_name);
  EXPECT_EQ(kEndpoint1_, endpoint.info.url);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  ReportingEndpoint endpoint2 = FindEndpointInCache(kGroupKey11_, kEndpoint2_);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kOrigin1_, endpoint2.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint2.group_key.group_name);
  EXPECT_EQ(kEndpoint2_, endpoint2.info.url);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint2.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint2.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(2, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint2_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, MultipleEndpointsDifferentGroups) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {{kEndpoint1_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup2_, endpoints2));

  ParseHeader(kNak_, kOrigin1_, header);
  EXPECT_EQ(2u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));

  EXPECT_EQ(2u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint.group_key.group_name);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  ReportingEndpoint endpoint2 = FindEndpointInCache(kGroupKey12_, kEndpoint1_);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kOrigin1_, endpoint2.group_key.origin);
  EXPECT_EQ(kGroup2_, endpoint2.group_key.group_name);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint2.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint2.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(2, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(2, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey12_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey12_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, MultipleHeadersFromDifferentOrigins) {
  // First origin sets a header with two endpoints in the same group.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_},
                                                             {kEndpoint2_}};
  std::string header1 =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1));
  ParseHeader(kNak_, kOrigin1_, header1);

  // Second origin has two endpoint groups.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {{kEndpoint1_}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints3 = {{kEndpoint2_}};
  std::string header2 =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints2)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup2_, endpoints3));
  ParseHeader(kNak_, kOrigin2_, header2);

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin2_));

  EXPECT_EQ(3u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey21_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey22_, OriginSubdomains::DEFAULT));

  EXPECT_EQ(4u, cache()->GetEndpointCount());
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint2_));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey21_, kEndpoint1_));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey22_, kEndpoint2_));

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(4, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(3, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint2_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey21_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey22_, kEndpoint2_);
    expected_command
```