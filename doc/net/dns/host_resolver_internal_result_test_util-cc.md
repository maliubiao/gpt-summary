Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The core request is to analyze a C++ file within Chromium's network stack and explain its function, relationship to JavaScript (if any), provide examples with hypothetical input/output, highlight common usage errors, and trace a user's path to this code.

2. **Initial Skim and Keyword Identification:** The first step is to quickly read through the code, paying attention to keywords and structure. I see things like `#include`, `namespace net`, `class`, `Matcher`, `ExpectHostResolverInternal...`, `ostream& operator<<`, and terms like "HostResolverInternalResult", "DnsQueryType", "IPEndpoint", etc. This immediately tells me it's related to DNS resolution and testing.

3. **Identifying the Core Functionality:** The repeated pattern of classes ending in `Matcher` and functions starting with `ExpectHostResolverInternal...` strongly suggests this code is for *testing*. Specifically, it seems to be creating custom matchers for `HostResolverInternalResult` objects. Matchers are a common concept in testing frameworks like Google Test (which is explicitly included: `testing/gtest/include/gtest/gtest.h`).

4. **Analyzing the Matcher Classes:**  I then examine the structure of the matcher classes (`HostResolverInternalResultBaseMatcher`, `HostResolverInternalDataResultMatcher`, etc.).

    * **Base Class:** `HostResolverInternalResultBaseMatcher` seems to provide the foundational matching logic for common properties like `domain_name`, `query_type`, `source`, `expiration`, and `timed_expiration`. It uses the `Property` matcher from Google Mock.

    * **Derived Classes:** The derived classes (`HostResolverInternalDataResultMatcher`, `HostResolverInternalMetadataResultMatcher`, `HostResolverInternalErrorResultMatcher`, `HostResolverInternalAliasResultMatcher`) specialize the matching for different subtypes of `HostResolverInternalResult`. Each subtype has its own specific data members (like `endpoints`, `metadatas`, `error`, `alias_target`).

5. **Understanding `ExpectHostResolverInternal...` Functions:** These functions act as factory methods or convenience wrappers for creating instances of the matcher classes. They simplify the process of creating matchers with specific expectations.

6. **Analyzing the `operator<<` Overload:** The overloaded `operator<<` for `HostResolverInternalResult` indicates a way to easily print or log these result objects in a human-readable format (JSON in this case). This is useful for debugging and test output.

7. **Considering the Relationship with JavaScript:**  Given the nature of the code (C++, testing, network stack), the direct relationship with JavaScript is likely to be *indirect*. Chromium's network stack, implemented in C++, handles DNS resolution on behalf of the browser's JavaScript engine. The results of this C++ code's logic eventually influence what the JavaScript running in a web page can do (e.g., connect to a server).

8. **Constructing Examples:** To illustrate the functionality, I need to create hypothetical `HostResolverInternalResult` objects and show how the matchers would work. This involves picking different result types (data, error, alias) and specifying expected values for their properties. The output would be a boolean indicating whether the matcher matched the object.

9. **Identifying Common Usage Errors:**  The primary errors relate to mismatches between the expected values specified in the matcher and the actual values in the `HostResolverInternalResult` object being tested. Incorrect types, wrong values, and forgetting to check specific fields are all potential pitfalls.

10. **Tracing the User Path:** This requires thinking about how a user's action in the browser eventually leads to a DNS resolution request. Typing a URL, clicking a link, or JavaScript making a network request are all starting points. The request goes through various layers of Chromium's networking stack, eventually potentially involving the code this file helps to test.

11. **Structuring the Explanation:** Finally, I organize the analysis into clear sections based on the original request: functionality, relationship with JavaScript, input/output examples, common errors, and user path. I use clear and concise language, explaining technical terms where necessary.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual details of each matcher class. I realized that the overarching purpose is *testing* and that the matchers provide a way to express expectations about DNS resolution results.
* I considered the possibility of a more direct link to JavaScript (e.g., if this code exposed some API to JS), but given the file's location and content, the indirect relationship through the network stack seemed more accurate.
* I made sure to connect the examples back to the core concepts of DNS resolution (IP addresses, aliases, errors).
* When describing the user path, I tried to make it a plausible scenario that most users would understand.

By following this thought process, which involves understanding the code's purpose, analyzing its structure, considering its context within Chromium, and providing concrete examples, I can arrive at a comprehensive and informative explanation like the example you provided.
这个C++源代码文件 `net/dns/host_resolver_internal_result_test_util.cc` 的主要功能是 **为 Chromium 网络栈中的 `HostResolverInternalResult` 类提供测试工具和匹配器 (Matchers)**。

**具体功能拆解:**

1. **定义了一系列 GTest Matcher:**  该文件定义了多个自定义的 GTest 匹配器，用于方便地断言 `HostResolverInternalResult` 对象的各种属性。这些匹配器可以用于编写单元测试，验证 Host Resolver 内部结果是否符合预期。

   * **`HostResolverInternalResultBaseMatcher`**: 这是一个抽象基类，定义了匹配 `HostResolverInternalResult` 对象通用属性（如域名、查询类型、来源、过期时间等）的逻辑。
   * **`HostResolverInternalDataResultMatcher`**:  用于匹配 `HostResolverInternalResult` 的 `kData` 类型，它会检查与 DNS 数据记录相关的属性，例如 IP 地址列表 (`endpoints`)、字符串列表 (`strings`) 和主机端口对列表 (`hosts`)。
   * **`HostResolverInternalMetadataResultMatcher`**: 用于匹配 `HostResolverInternalResult` 的 `kMetadata` 类型，它会检查与 DNS 元数据记录相关的属性，例如 HTTPS 记录的优先级和连接端点元数据 (`metadatas`)。
   * **`HostResolverInternalErrorResultMatcher`**: 用于匹配 `HostResolverInternalResult` 的 `kError` 类型，它会检查 DNS 解析过程中发生的错误码 (`error`)。
   * **`HostResolverInternalAliasResultMatcher`**: 用于匹配 `HostResolverInternalResult` 的 `kAlias` 类型，它会检查 DNS 别名记录的目标域名 (`alias_target`)。

2. **提供创建 Matcher 的工厂函数:** 该文件提供了便捷的工厂函数来创建上述的匹配器，例如：
   * `ExpectHostResolverInternalDataResult(...)`
   * `ExpectHostResolverInternalMetadataResult(...)`
   * `ExpectHostResolverInternalErrorResult(...)`
   * `ExpectHostResolverInternalAliasResult(...)`
   这些函数接受期望的属性值作为参数，并返回相应的匹配器对象。

3. **重载 `operator<<`**:  该文件重载了 `operator<<` 运算符，使得可以直接将 `HostResolverInternalResult` 对象输出到 `std::ostream` 中。  它将 `HostResolverInternalResult` 对象转换为 JSON 字符串进行输出，方便调试和查看结果。

**与 JavaScript 的关系:**

该文件本身是用 C++ 编写的，**直接与 JavaScript 没有关联**。 但是，它间接地服务于 JavaScript 的功能，因为：

* **Chromium 的网络栈为浏览器中的 JavaScript 提供网络能力。** 当 JavaScript 代码（例如，通过 `fetch` API 或 `XMLHttpRequest`）发起网络请求时，底层的 DNS 解析工作由 Chromium 的网络栈来完成。
* **`HostResolverInternalResult` 存储了 DNS 解析的中间结果。** 这个文件提供的测试工具用于确保 DNS 解析的内部逻辑（在 C++ 中实现）正确无误。
* **正确的 DNS 解析是 JavaScript 代码能够成功连接到服务器的关键。** 如果 DNS 解析出现错误，JavaScript 的网络请求将会失败。

**举例说明:**

假设一个 JavaScript 代码尝试访问 `example.com`：

```javascript
fetch('https://example.com');
```

1. **JavaScript 发起请求:**  这段 JavaScript 代码调用 `fetch` API。
2. **浏览器将请求传递给网络栈:** 浏览器会将这个请求传递给底层的 Chromium 网络栈。
3. **网络栈进行 DNS 解析:** 网络栈中的 Host Resolver 组件会负责解析 `example.com` 的 IP 地址。
4. **生成 `HostResolverInternalResult`:** 在 DNS 解析的各个阶段，可能会生成不同类型的 `HostResolverInternalResult` 对象，例如：
   * 如果找到了 `example.com` 的 A 记录，可能会生成一个 `kData` 类型的 `HostResolverInternalResult`，包含解析到的 IP 地址。
   * 如果 `example.com` 有 CNAME 记录指向 `www.example.com`，可能会先生成一个 `kAlias` 类型的 `HostResolverInternalResult`，指向 `www.example.com`，然后再对 `www.example.com` 进行解析。
   * 如果解析过程中发生错误（例如域名不存在），可能会生成一个 `kError` 类型的 `HostResolverInternalResult`，包含错误码。
5. **该文件的作用:**  `host_resolver_internal_result_test_util.cc` 中定义的匹配器可以用于测试网络栈在这些内部阶段生成的 `HostResolverInternalResult` 对象是否符合预期。例如，一个测试用例可能会断言，对于 `example.com` 的 A 记录查询，应该生成一个 `kData` 类型的 `HostResolverInternalResult`，并且包含正确的 IP 地址。

**逻辑推理的假设输入与输出:**

假设我们有一个 `HostResolverInternalResult` 对象 `result`，它表示对 `example.com` 进行 A 记录查询的结果，并且成功解析到了 IP 地址 `93.184.216.34`。

**假设输入:**

```c++
net::HostResolverInternalResult result = net::HostResolverInternalResult::DataResult(
    "example.com", net::DnsQueryType::kA, net::HostResolverInternalResult::Source::kCache,
    base::TimeTicks::Now() + base::Seconds(3600), base::Time::Now() + base::Seconds(3600),
    {net::IPEndPoint(net::IPAddress(93, 184, 216, 34), 0)}, {}, {});
```

**使用该文件提供的匹配器进行断言：**

```c++
EXPECT_THAT(result, net::ExpectHostResolverInternalDataResult(
                        "example.com", net::DnsQueryType::kA,
                        net::HostResolverInternalResult::Source::kCache,
                        testing::_, testing::_,
                        testing::ElementsAre(net::IPEndPoint(net::IPAddress(93, 184, 216, 34), 0)),
                        testing::IsEmpty(), testing::IsEmpty()));
```

**假设输出:**  由于 `result` 对象的属性与 `ExpectHostResolverInternalDataResult` 中指定的期望值匹配，该断言将 **成功**。

**涉及用户或编程常见的使用错误:**

* **断言了错误的 Result 类型:** 开发者可能错误地使用了 `ExpectHostResolverInternalDataResult` 来断言一个 `kError` 类型的 `HostResolverInternalResult`，导致断言失败。
* **断言了错误的属性值:** 开发者可能期望 IP 地址是 `1.2.3.4`，但实际解析到的 IP 地址是 `93.184.216.34`，导致断言失败。
* **忘记了检查某些属性:**  开发者可能只关注了 IP 地址，而忽略了检查过期时间或来源等其他重要属性。
* **使用了不精确的 Matcher:**  例如，应该使用 `ElementsAre` 来精确匹配 IP 地址列表，却使用了 `Contains`，可能导致误判。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 `example.com` 并按下回车键。**
2. **浏览器进程的网络线程接收到这个导航请求。**
3. **网络线程需要解析 `example.com` 的 IP 地址。** 它会调用 Host Resolver 组件发起 DNS 查询。
4. **Host Resolver 组件会进行一系列操作，包括查找缓存、查询操作系统 DNS 服务、发起网络 DNS 请求等。**
5. **在这些内部操作的各个阶段，Host Resolver 可能会创建并操作 `HostResolverInternalResult` 对象来记录中间结果和状态。** 例如，缓存查找的结果、从 DNS 服务器返回的响应等都会被封装到 `HostResolverInternalResult` 对象中。
6. **如果开发者在调试 DNS 解析相关的 bug，他可能会希望查看这些内部的 `HostResolverInternalResult` 对象。**  这时，`host_resolver_internal_result_test_util.cc` 中提供的 `operator<<` 重载就非常有用，可以将这些对象以 JSON 格式输出到日志中进行查看。
7. **编写或修改与 Host Resolver 相关的单元测试时，开发者会使用该文件中定义的 Matcher 来验证 `HostResolverInternalResult` 对象的正确性。**  例如，测试缓存功能是否正确地返回了之前缓存的 DNS 结果。

总而言之，`net/dns/host_resolver_internal_result_test_util.cc` 是一个重要的测试辅助文件，它帮助 Chromium 开发者编写健壮的单元测试，确保 DNS 解析功能的正确性和稳定性，从而保证用户在使用浏览器访问网站时的网络连接正常工作。虽然它本身是 C++ 代码，但其功能直接影响到基于 JavaScript 的 Web 应用的网络能力。

Prompt: 
```
这是目录为net/dns/host_resolver_internal_result_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_internal_result_test_util.h"

#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/json/json_writer.h"
#include "base/time/time.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_query_type.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::MakeMatcher;
using ::testing::Matcher;
using ::testing::MatchResultListener;
using ::testing::PrintToString;
using ::testing::Property;
using ::testing::StringMatchResultListener;

namespace {

class HostResolverInternalResultBaseMatcher
    : public ::testing::MatcherInterface<const HostResolverInternalResult&> {
 public:
  HostResolverInternalResultBaseMatcher(
      std::string expected_domain_name,
      DnsQueryType expected_query_type,
      HostResolverInternalResult::Source expected_source,
      Matcher<std::optional<base::TimeTicks>> expiration_matcher,
      Matcher<std::optional<base::Time>> timed_expiration_matcher)
      : expected_domain_name_(std::move(expected_domain_name)),
        expected_query_type_(expected_query_type),
        expected_source_(expected_source),
        expiration_matcher_(std::move(expiration_matcher)),
        timed_expiration_matcher_(std::move(timed_expiration_matcher)) {}
  ~HostResolverInternalResultBaseMatcher() override = default;

  bool MatchAndExplain(const HostResolverInternalResult& result,
                       MatchResultListener* result_listener) const override {
    if (result.type() == GetSubtype()) {
      *result_listener << "which is type ";
      NameSubtype(*result_listener);
    } else {
      *result_listener << "which is not type ";
      NameSubtype(*result_listener);
      return false;
    }

    StringMatchResultListener base_listener;
    bool base_matches = MatchAndExplainBaseProperties(result, base_listener);
    StringMatchResultListener subtype_listener;
    bool subtype_matches =
        MatchAndExplainSubtypeProperties(result, subtype_listener);

    // If only one part mismatches, just explain that.
    if (!base_matches || subtype_matches) {
      *result_listener << ", and " << base_listener.str();
    }
    if (!subtype_matches || base_matches) {
      *result_listener << ", and " << subtype_listener.str();
    }

    return base_matches && subtype_matches;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "matches ";
    Describe(*os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not match ";
    Describe(*os);
  }

 protected:
  virtual HostResolverInternalResult::Type GetSubtype() const = 0;
  virtual void NameSubtype(MatchResultListener& result_listener) const = 0;
  virtual bool MatchAndExplainSubtypeProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const = 0;
  virtual void DescribeSubtype(std::ostream& os) const = 0;

 private:
  bool MatchAndExplainBaseProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const {
    return ExplainMatchResult(
        AllOf(Property("domain_name", &HostResolverInternalResult::domain_name,
                       Eq(expected_domain_name_)),
              Property("query_type", &HostResolverInternalResult::query_type,
                       Eq(expected_query_type_)),
              Property("source", &HostResolverInternalResult::source,
                       Eq(expected_source_)),
              Property("expiration", &HostResolverInternalResult::expiration,
                       expiration_matcher_),
              Property("timed_expiration",
                       &HostResolverInternalResult::timed_expiration,
                       timed_expiration_matcher_)),
        result, &result_listener);
  }

  void Describe(std::ostream& os) const {
    os << "\n    HostResolverInternalResult {";
    DescribeBase(os);
    DescribeSubtype(os);
    os << "\n    }\n";
  }

  void DescribeBase(std::ostream& os) const {
    StringMatchResultListener subtype_name_listener;
    NameSubtype(subtype_name_listener);

    os << "\n      domain_name: \"" << expected_domain_name_
       << "\"\n      query_type: " << kDnsQueryTypes.at(expected_query_type_)
       << "\n      type: " << subtype_name_listener.str()
       << "\n      source: " << static_cast<int>(expected_source_)
       << "\n      expiration: " << PrintToString(expiration_matcher_)
       << "\n      timed_expiration: "
       << PrintToString(timed_expiration_matcher_);
  }

  std::string expected_domain_name_;
  DnsQueryType expected_query_type_;
  HostResolverInternalResult::Source expected_source_;
  Matcher<std::optional<base::TimeTicks>> expiration_matcher_;
  Matcher<std::optional<base::Time>> timed_expiration_matcher_;
};

class HostResolverInternalDataResultMatcher
    : public HostResolverInternalResultBaseMatcher {
 public:
  HostResolverInternalDataResultMatcher(
      std::string expected_domain_name,
      DnsQueryType expected_query_type,
      HostResolverInternalResult::Source expected_source,
      Matcher<std::optional<base::TimeTicks>> expiration_matcher,
      Matcher<std::optional<base::Time>> timed_expiration_matcher,
      Matcher<std::vector<IPEndPoint>> endpoints_matcher,
      Matcher<std::vector<std::string>> strings_matcher,
      Matcher<std::vector<HostPortPair>> hosts_matcher)
      : HostResolverInternalResultBaseMatcher(
            std::move(expected_domain_name),
            expected_query_type,
            expected_source,
            std::move(expiration_matcher),
            std::move(timed_expiration_matcher)),
        endpoints_matcher_(std::move(endpoints_matcher)),
        strings_matcher_(std::move(strings_matcher)),
        hosts_matcher_(std::move(hosts_matcher)) {}

  ~HostResolverInternalDataResultMatcher() override = default;

  HostResolverInternalDataResultMatcher(
      const HostResolverInternalDataResultMatcher&) = default;
  HostResolverInternalDataResultMatcher& operator=(
      const HostResolverInternalDataResultMatcher&) = default;
  HostResolverInternalDataResultMatcher(
      HostResolverInternalDataResultMatcher&&) = default;
  HostResolverInternalDataResultMatcher& operator=(
      HostResolverInternalDataResultMatcher&&) = default;

 protected:
  HostResolverInternalResult::Type GetSubtype() const override {
    return HostResolverInternalResult::Type::kData;
  }

  void NameSubtype(MatchResultListener& result_listener) const override {
    result_listener << "kData";
  }

  bool MatchAndExplainSubtypeProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const override {
    return ExplainMatchResult(
        AllOf(Property("endpoints", &HostResolverInternalDataResult::endpoints,
                       endpoints_matcher_),
              Property("strings", &HostResolverInternalDataResult::strings,
                       strings_matcher_),
              Property("hosts", &HostResolverInternalDataResult::hosts,
                       hosts_matcher_)),
        result.AsData(), &result_listener);
  }

  void DescribeSubtype(std::ostream& os) const override {
    os << "\n      endpoints: " << PrintToString(endpoints_matcher_)
       << "\n      strings: " << PrintToString(strings_matcher_)
       << "\n      hosts: " << PrintToString(hosts_matcher_);
  }

 private:
  Matcher<std::vector<IPEndPoint>> endpoints_matcher_;
  Matcher<std::vector<std::string>> strings_matcher_;
  Matcher<std::vector<HostPortPair>> hosts_matcher_;
};

class HostResolverInternalMetadataResultMatcher
    : public HostResolverInternalResultBaseMatcher {
 public:
  HostResolverInternalMetadataResultMatcher(
      std::string expected_domain_name,
      DnsQueryType expected_query_type,
      HostResolverInternalResult::Source expected_source,
      Matcher<std::optional<base::TimeTicks>> expiration_matcher,
      Matcher<std::optional<base::Time>> timed_expiration_matcher,
      Matcher<std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>>
          metadatas_matcher)
      : HostResolverInternalResultBaseMatcher(
            std::move(expected_domain_name),
            expected_query_type,
            expected_source,
            std::move(expiration_matcher),
            std::move(timed_expiration_matcher)),
        metadatas_matcher_(std::move(metadatas_matcher)) {}

  ~HostResolverInternalMetadataResultMatcher() override = default;

  HostResolverInternalMetadataResultMatcher(
      const HostResolverInternalMetadataResultMatcher&) = default;
  HostResolverInternalMetadataResultMatcher& operator=(
      const HostResolverInternalMetadataResultMatcher&) = default;
  HostResolverInternalMetadataResultMatcher(
      HostResolverInternalMetadataResultMatcher&&) = default;
  HostResolverInternalMetadataResultMatcher& operator=(
      HostResolverInternalMetadataResultMatcher&&) = default;

 protected:
  HostResolverInternalResult::Type GetSubtype() const override {
    return HostResolverInternalResult::Type::kMetadata;
  }

  void NameSubtype(MatchResultListener& result_listener) const override {
    result_listener << "kMetadata";
  }

  bool MatchAndExplainSubtypeProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const override {
    return ExplainMatchResult(
        Property("metadatas", &HostResolverInternalMetadataResult::metadatas,
                 metadatas_matcher_),
        result.AsMetadata(), &result_listener);
  }

  void DescribeSubtype(std::ostream& os) const override {
    os << "\n      metadatas: " << PrintToString(metadatas_matcher_);
  }

 private:
  Matcher<std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>>
      metadatas_matcher_;
};

class HostResolverInternalErrorResultMatcher
    : public HostResolverInternalResultBaseMatcher {
 public:
  HostResolverInternalErrorResultMatcher(
      std::string expected_domain_name,
      DnsQueryType expected_query_type,
      HostResolverInternalResult::Source expected_source,
      Matcher<std::optional<base::TimeTicks>> expiration_matcher,
      Matcher<std::optional<base::Time>> timed_expiration_matcher,
      int expected_error)
      : HostResolverInternalResultBaseMatcher(
            std::move(expected_domain_name),
            expected_query_type,
            expected_source,
            std::move(expiration_matcher),
            std::move(timed_expiration_matcher)),
        expected_error_(expected_error) {}

  ~HostResolverInternalErrorResultMatcher() override = default;

  HostResolverInternalErrorResultMatcher(
      const HostResolverInternalErrorResultMatcher&) = default;
  HostResolverInternalErrorResultMatcher& operator=(
      const HostResolverInternalErrorResultMatcher&) = default;
  HostResolverInternalErrorResultMatcher(
      HostResolverInternalErrorResultMatcher&&) = default;
  HostResolverInternalErrorResultMatcher& operator=(
      HostResolverInternalErrorResultMatcher&&) = default;

 protected:
  HostResolverInternalResult::Type GetSubtype() const override {
    return HostResolverInternalResult::Type::kError;
  }

  void NameSubtype(MatchResultListener& result_listener) const override {
    result_listener << "kError";
  }

  bool MatchAndExplainSubtypeProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const override {
    return ExplainMatchResult(
        Property("error", &HostResolverInternalErrorResult::error,
                 Eq(expected_error_)),
        result.AsError(), &result_listener);
  }

  void DescribeSubtype(std::ostream& os) const override {
    os << "\n      error: " << expected_error_;
  }

 private:
  int expected_error_;
};

class HostResolverInternalAliasResultMatcher
    : public HostResolverInternalResultBaseMatcher {
 public:
  HostResolverInternalAliasResultMatcher(
      std::string expected_domain_name,
      DnsQueryType expected_query_type,
      HostResolverInternalResult::Source expected_source,
      Matcher<std::optional<base::TimeTicks>> expiration_matcher,
      Matcher<std::optional<base::Time>> timed_expiration_matcher,
      std::string expected_alias_target)
      : HostResolverInternalResultBaseMatcher(
            std::move(expected_domain_name),
            expected_query_type,
            expected_source,
            std::move(expiration_matcher),
            std::move(timed_expiration_matcher)),
        expected_alias_target_(std::move(expected_alias_target)) {}

  ~HostResolverInternalAliasResultMatcher() override = default;

  HostResolverInternalAliasResultMatcher(
      const HostResolverInternalAliasResultMatcher&) = default;
  HostResolverInternalAliasResultMatcher& operator=(
      const HostResolverInternalAliasResultMatcher&) = default;
  HostResolverInternalAliasResultMatcher(
      HostResolverInternalAliasResultMatcher&&) = default;
  HostResolverInternalAliasResultMatcher& operator=(
      HostResolverInternalAliasResultMatcher&&) = default;

 protected:
  HostResolverInternalResult::Type GetSubtype() const override {
    return HostResolverInternalResult::Type::kAlias;
  }

  void NameSubtype(MatchResultListener& result_listener) const override {
    result_listener << "kAlias";
  }

  bool MatchAndExplainSubtypeProperties(
      const HostResolverInternalResult& result,
      MatchResultListener& result_listener) const override {
    return ExplainMatchResult(
        Property("alias_target", &HostResolverInternalAliasResult::alias_target,
                 Eq(expected_alias_target_)),
        result.AsAlias(), &result_listener);
  }

  void DescribeSubtype(std::ostream& os) const override {
    os << "\n      target: \"" << expected_alias_target_ << "\"";
  }

 private:
  std::string expected_alias_target_;
};

}  // namespace

Matcher<const HostResolverInternalResult&> ExpectHostResolverInternalDataResult(
    std::string expected_domain_name,
    DnsQueryType expected_query_type,
    HostResolverInternalResult::Source expected_source,
    Matcher<std::optional<base::TimeTicks>> expiration_matcher,
    Matcher<std::optional<base::Time>> timed_expiration_matcher,
    Matcher<std::vector<IPEndPoint>> endpoints_matcher,
    Matcher<std::vector<std::string>> strings_matcher,
    Matcher<std::vector<HostPortPair>> hosts_matcher) {
  return MakeMatcher(new HostResolverInternalDataResultMatcher(
      std::move(expected_domain_name), expected_query_type, expected_source,
      std::move(expiration_matcher), std::move(timed_expiration_matcher),
      std::move(endpoints_matcher), std::move(strings_matcher),
      std::move(hosts_matcher)));
}

testing::Matcher<const HostResolverInternalResult&>
ExpectHostResolverInternalMetadataResult(
    std::string expected_domain_name,
    DnsQueryType expected_query_type,
    HostResolverInternalResult::Source expected_source,
    testing::Matcher<std::optional<base::TimeTicks>> expiration_matcher,
    testing::Matcher<std::optional<base::Time>> timed_expiration_matcher,
    testing::Matcher<
        std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>>
        metadatas_matcher) {
  return MakeMatcher(new HostResolverInternalMetadataResultMatcher(
      std::move(expected_domain_name), expected_query_type, expected_source,
      std::move(expiration_matcher), std::move(timed_expiration_matcher),
      std::move(metadatas_matcher)));
}

Matcher<const HostResolverInternalResult&>
ExpectHostResolverInternalErrorResult(
    std::string expected_domain_name,
    DnsQueryType expected_query_type,
    HostResolverInternalResult::Source expected_source,
    Matcher<std::optional<base::TimeTicks>> expiration_matcher,
    Matcher<std::optional<base::Time>> timed_expiration_matcher,
    int expected_error) {
  return MakeMatcher(new HostResolverInternalErrorResultMatcher(
      std::move(expected_domain_name), expected_query_type, expected_source,
      std::move(expiration_matcher), std::move(timed_expiration_matcher),
      expected_error));
}

Matcher<const HostResolverInternalResult&>
ExpectHostResolverInternalAliasResult(
    std::string expected_domain_name,
    DnsQueryType expected_query_type,
    HostResolverInternalResult::Source expected_source,
    Matcher<std::optional<base::TimeTicks>> expiration_matcher,
    Matcher<std::optional<base::Time>> timed_expiration_matcher,
    std::string expected_alias_target) {
  return MakeMatcher(new HostResolverInternalAliasResultMatcher(
      std::move(expected_domain_name), expected_query_type, expected_source,
      std::move(expiration_matcher), std::move(timed_expiration_matcher),
      std::move(expected_alias_target)));
}

std::ostream& operator<<(std::ostream& os,
                         const HostResolverInternalResult& result) {
  std::string json_string;
  CHECK(base::JSONWriter::Write(result.ToValue(), &json_string));
  return os << json_string;
}

}  // namespace net

"""

```