Response:
The user wants to understand the functionality of the provided C++ code, specifically the `http_no_vary_search_data_unittest.cc` file within the Chromium network stack. I need to:

1. **Summarize the file's purpose:** Identify what the code is testing.
2. **Check for JavaScript relevance:**  Determine if and how this C++ code interacts with JavaScript functionality.
3. **Provide logical reasoning examples:**  Illustrate the code's behavior with hypothetical inputs and outputs.
4. **Highlight common user/programming errors:** Give examples of mistakes related to the functionality being tested.
5. **Explain user steps to reach this code:** Describe how a user's actions in a browser might lead to this code being executed.
6. **Synthesize the overall functionality:**  Create a concise summary of what the code does.

**Breakdown of the code:**

* **Includes:** The file includes standard C++ libraries, base libraries from Chromium (like `flat_map`, `flat_set`, string utilities, testing frameworks), and network-specific headers (`http_no_vary_search_data.h`, `http_response_headers.h`, `http_util.h`).
* **Namespaces:** The code operates within the `net` namespace.
* **Test Fixtures:** The code uses Google Test (`TEST`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`) to define and run unit tests.
* **`HttpNoVarySearchCreateTest`:** Tests the creation of `HttpNoVarySearchData` objects using `CreateFromNoVaryParams` and `CreateFromVaryParams`. It checks the correct setting of `no_vary_params`, `vary_params`, `vary_on_key_order`, and `vary_by_default`.
* **`HttpNoVarySearchResponseHeadersTest`:**  Tests the parsing of the `No-Vary-Search` HTTP header. It defines test cases with different header values and expected outcomes for the parsed data. It uses `HttpNoVarySearchData::ParseFromHeaders`.
* **`HttpNoVarySearchResponseHeadersParseFailureTest`:** Tests scenarios where parsing the `No-Vary-Search` header fails, checking for specific error conditions.
* **`HttpNoVarySearchCompare`:** Tests the `AreEquivalent` method of `HttpNoVarySearchData`, which compares URLs based on the no-vary search parameters. It includes tests with special characters in URLs.

**JavaScript Relationship:**

The `No-Vary-Search` header affects how the browser caches resources. JavaScript, through mechanisms like `fetch` or `XMLHttpRequest`, can trigger network requests. The browser's caching behavior, influenced by this header, will impact how these requests are handled.

**Logical Reasoning Examples:**

I can create examples based on the test cases provided, showing how different `No-Vary-Search` header values lead to different interpretations of which search parameters should be considered for cache matching.

**User/Programming Errors:**

I can point out common mistakes in configuring the `No-Vary-Search` header on the server-side, which would lead to parsing errors or incorrect caching behavior.

**User Steps to Reach This Code:**

I need to describe a typical user interaction that results in a network request and involves caching.

**Overall Functionality Summary:**

The core purpose of this file is to test the functionality of the `HttpNoVarySearchData` class, which is responsible for parsing and interpreting the `No-Vary-Search` HTTP response header. This header controls how search parameters in a URL affect caching behavior.
好的，让我们来分析一下这个C++源代码文件 `http_no_vary_search_data_unittest.cc` 的功能。

**功能归纳**

这个文件是 Chromium 网络栈的一部分，它的主要功能是：

1. **单元测试 `net::HttpNoVarySearchData` 类:**  这个文件包含了针对 `HttpNoVarySearchData` 类的各种单元测试。`HttpNoVarySearchData` 类负责解析和存储 HTTP 响应头中的 `No-Vary-Search` 信息。

2. **测试 `HttpNoVarySearchData` 对象的创建:**  测试了使用 `CreateFromNoVaryParams` 和 `CreateFromVaryParams` 静态方法创建 `HttpNoVarySearchData` 对象的情况，验证了不同参数组合下，对象内部 `no_vary_params_`, `vary_params_`, `vary_on_key_order_` 和 `vary_by_default_` 成员变量是否被正确设置。

3. **测试 `No-Vary-Search` 响应头的解析:**  测试了 `HttpNoVarySearchData::ParseFromHeaders` 方法，该方法负责从 `HttpResponseHeaders` 对象中解析 `No-Vary-Search` 头信息。测试用例覆盖了各种有效的 `No-Vary-Search` 头的语法，以及不同参数组合（`params`，`except`，`key-order`）。

4. **测试 `No-Vary-Search` 响应头解析的错误处理:**  测试了当 `No-Vary-Search` 头格式不正确时，`ParseFromHeaders` 方法的错误处理机制，并验证了返回的错误类型是否符合预期。

5. **测试 URL 的比较:**  测试了 `HttpNoVarySearchData::AreEquivalent` 方法，该方法用于判断两个 URL 在考虑 `No-Vary-Search` 规则的情况下是否等价。这包括了对 URL 中特殊字符的处理。

**与 JavaScript 的关系**

`No-Vary-Search` HTTP 响应头会影响浏览器缓存的行为。当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest` 对象）时，浏览器会根据缓存策略来决定是否使用缓存的资源。`No-Vary-Search` 头指示了在判断缓存是否命中时，应该忽略哪些 URL 查询参数。

**举例说明:**

假设服务器返回了以下响应头：

```
HTTP/1.1 200 OK
Content-Type: text/plain
No-Vary-Search: params=("lang", "region")
```

这段头信息表示，对于该 URL，缓存的判断应该忽略 `lang` 和 `region` 这两个查询参数。

* **JavaScript 发起请求:**
  ```javascript
  fetch('https://example.com/data?lang=en&region=us&version=1');
  fetch('https://example.com/data?region=uk&lang=fr&version=1');
  fetch('https://example.com/data?lang=en&region=us&version=2');
  ```

* **缓存行为:**
    * 前两个 `fetch` 请求会被认为是相同的资源，因为 `lang` 和 `region` 参数被 `No-Vary-Search` 忽略。如果第一个请求成功并缓存了结果，第二个请求可能会直接从缓存中获取。
    * 第三个 `fetch` 请求则会被认为是不同的资源，因为它包含了一个未被 `No-Vary-Search` 声明的参数 `version`，且其值与前两个请求不同。

**逻辑推理，假设输入与输出**

**场景 1：成功解析 `No-Vary-Search` 头**

**假设输入 (HTTP 响应头):**

```
HTTP/1.1 200 OK
Content-Type: image/png
No-Vary-Search: params=("image_size", "quality"), key-order
```

**预期输出 (`HttpNoVarySearchData` 对象):**

* `no_vary_params`: {"image_size", "quality"}
* `vary_params`: {}
* `vary_on_key_order`: false (因为 `key-order` 存在)
* `vary_by_default`: true

**场景 2：解析 `No-Vary-Search` 头失败**

**假设输入 (HTTP 响应头):**

```
HTTP/1.1 200 OK
Content-Type: application/json
No-Vary-Search: params=("data" "id")  // 错误的语法，缺少逗号
```

**预期输出 (`HttpNoVarySearchData` 对象或错误信息):**

`HttpNoVarySearchData::ParseFromHeaders` 方法会返回一个错误，错误类型为 `HttpNoVarySearchData::ParseErrorEnum::kParamsNotStringList`，因为它期望 `params` 是一个由引号包围的字符串列表，且字符串之间用逗号分隔。

**用户或编程常见的使用错误**

1. **服务器配置错误：`No-Vary-Search` 头语法错误:**
   * **错误示例:** `No-Vary-Search: params=("param1" param2)` (缺少逗号)
   * **后果:** 浏览器可能无法正确解析该头，导致缓存行为不符合预期，或者直接忽略该头。在 Chromium 中，这会被 `HttpNoVarySearchResponseHeadersParseFailureTest` 中的测试用例捕获。

2. **服务器配置错误：`except` 指令在 `params` 为 `false` 或未设置时使用:**
   * **错误示例:**
     ```
     No-Vary-Search: except=("param1")
     ```
     或
     ```
     No-Vary-Search: params=?0, except=("param1")
     ```
   * **后果:** 这在逻辑上是矛盾的，因为 `except` 是用来指定在 "vary on all" 的情况下 *不* 参与 Vary 的参数。如果 `params` 没有设置为 true (或者 ?1)，那么 `except` 就没有意义。`HttpNoVarySearchResponseHeadersParseFailureTest` 中有相关的测试用例来验证这种情况。

3. **JavaScript 代码期望缓存行为与 `No-Vary-Search` 不符:**
   * **错误示例:**  开发者可能错误地认为即使设置了 `No-Vary-Search: params=("id")`，两个只有 `id` 参数不同的 URL 仍然会被视为不同的资源。
   * **后果:** 可能导致应用逻辑错误，例如重复请求数据。

**用户操作如何一步步的到达这里 (调试线索)**

1. **用户在浏览器中访问一个网页 (例如 `https://example.com/search?q=test&category=books`).**
2. **服务器响应请求，并在响应头中包含了 `No-Vary-Search` 头信息 (例如 `No-Vary-Search: params=("q")`).**
3. **浏览器接收到响应头，网络栈的代码开始解析这些头信息。**
4. **`net::HttpResponseHeaders::AddHeaderLine()` 等函数会处理接收到的原始头信息。**
5. **当需要获取 `No-Vary-Search` 信息时 (例如，在决定是否使用缓存时)，会调用 `net::HttpNoVarySearchData::ParseFromHeaders()` 方法。**
6. **如果头信息格式正确，`ParseFromHeaders()` 会成功解析并返回一个 `HttpNoVarySearchData` 对象。**
7. **如果头信息格式错误，`ParseFromHeaders()` 会返回一个错误，开发人员可以通过调试网络栈的代码（例如在这个 `_unittest.cc` 文件中设置断点）来查看具体的错误原因。**
8. **后续的缓存决策会基于 `HttpNoVarySearchData` 对象中的信息来执行。**

**功能总结 (针对第 1 部分)**

这部分代码主要专注于测试 `net::HttpNoVarySearchData` 类的创建和从 HTTP 响应头中解析 `No-Vary-Search` 信息的功能。它涵盖了各种合法的和非法的 `No-Vary-Search` 头的语法，并验证了在不同情况下 `HttpNoVarySearchData` 对象的状态和解析错误处理是否符合预期。 这确保了 Chromium 的网络栈能够正确理解和应用服务器端通过 `No-Vary-Search` 头指定的缓存策略。

Prompt: 
```
这是目录为net/http/http_no_vary_search_data_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_no_vary_search_data.h"

#include <string>
#include <string_view>

#include "base/containers/flat_map.h"
#include "base/containers/flat_set.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/string_util.h"
#include "base/test/gmock_expected_support.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/types/expected.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using testing::IsEmpty;
using testing::UnorderedElementsAreArray;

TEST(HttpNoVarySearchCreateTest, CreateFromNoVaryParamsNonEmptyVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromNoVaryParams({"a"}, true);
  EXPECT_THAT(no_vary_search.no_vary_params(),
              UnorderedElementsAreArray({"a"}));
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_TRUE(no_vary_search.vary_on_key_order());
  EXPECT_TRUE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest,
     CreateFromNoVaryParamsNonEmptyNoVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromNoVaryParams({"a"}, false);
  EXPECT_THAT(no_vary_search.no_vary_params(),
              UnorderedElementsAreArray({"a"}));
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_FALSE(no_vary_search.vary_on_key_order());
  EXPECT_TRUE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromNoVaryParamsEmptyNoVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromNoVaryParams({}, false);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_FALSE(no_vary_search.vary_on_key_order());
  EXPECT_TRUE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromNoVaryParamsEmptyVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromNoVaryParams({}, true);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_TRUE(no_vary_search.vary_on_key_order());
  EXPECT_TRUE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromVaryParamsNonEmptyVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromVaryParams({"a"}, true);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), UnorderedElementsAreArray({"a"}));
  EXPECT_TRUE(no_vary_search.vary_on_key_order());
  EXPECT_FALSE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromVaryParamsNonEmptyNoVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromVaryParams({"a"}, false);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), UnorderedElementsAreArray({"a"}));
  EXPECT_FALSE(no_vary_search.vary_on_key_order());
  EXPECT_FALSE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromVaryParamsEmptyNoVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromVaryParams({}, false);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_FALSE(no_vary_search.vary_on_key_order());
  EXPECT_FALSE(no_vary_search.vary_by_default());
}

TEST(HttpNoVarySearchCreateTest, CreateFromVaryParamsEmptyVaryOnKeyOrder) {
  const auto no_vary_search =
      HttpNoVarySearchData::CreateFromVaryParams({}, true);
  EXPECT_THAT(no_vary_search.no_vary_params(), IsEmpty());
  EXPECT_THAT(no_vary_search.vary_params(), IsEmpty());
  EXPECT_TRUE(no_vary_search.vary_on_key_order());
  EXPECT_FALSE(no_vary_search.vary_by_default());
}

struct TestData {
  const char* raw_headers;
  const base::flat_set<std::string> expected_no_vary_params;
  const base::flat_set<std::string> expected_vary_params;
  const bool expected_vary_on_key_order;
  const bool expected_vary_by_default;
};

class HttpNoVarySearchResponseHeadersTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<TestData> {};

TEST_P(HttpNoVarySearchResponseHeadersTest, ParsingSuccess) {
  const TestData test = GetParam();

  const std::string raw_headers =
      HttpUtil::AssembleRawHeaders(test.raw_headers);

  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  ASSERT_OK_AND_ASSIGN(const auto no_vary_search_data,
                       HttpNoVarySearchData::ParseFromHeaders(*parsed));

  EXPECT_EQ(no_vary_search_data.vary_on_key_order(),
            test.expected_vary_on_key_order);
  EXPECT_EQ(no_vary_search_data.vary_by_default(),
            test.expected_vary_by_default);

  EXPECT_EQ(no_vary_search_data.no_vary_params(), test.expected_no_vary_params);
  EXPECT_EQ(no_vary_search_data.vary_params(), test.expected_vary_params);
}

struct FailureData {
  const char* raw_headers;
  const HttpNoVarySearchData::ParseErrorEnum expected_error;
};

class HttpNoVarySearchResponseHeadersParseFailureTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<FailureData> {};

TEST_P(HttpNoVarySearchResponseHeadersParseFailureTest,
       ParsingFailureOrDefaultValue) {
  const std::string raw_headers =
      HttpUtil::AssembleRawHeaders(GetParam().raw_headers);

  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  const auto no_vary_search_data =
      HttpNoVarySearchData::ParseFromHeaders(*parsed);

  EXPECT_THAT(no_vary_search_data,
              base::test::ErrorIs(GetParam().expected_error))
      << "Headers = " << GetParam().raw_headers;
}

FailureData response_header_failed[] = {
    {// No No-Vary-Search Header case
     "HTTP/1.1 200 OK\r\n"
     "Set-Cookie: a\r\n"
     "Set-Cookie: b\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kOk},

    {// No-Vary-Search Header doesn't parse as a dictionary.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: "a")"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNotDictionary},

    {// No-Vary-Search Header doesn't parse as a dictionary.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: (a)\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNotDictionary},

    {// When except is specified, params cannot be a list of strings.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("b"),except=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// An unknown dictionary key should behave as if the key was not
     // specified.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: unknown-key\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kDefaultValue},

    {// params not a boolean or a list of strings.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params="a")"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kParamsNotStringList},

    {// params not a boolean or a list of strings.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=a\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kParamsNotStringList},

    {// params as an empty list of strings should behave as if the header was
     // not specified.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kDefaultValue},

    {// params not a boolean or a list of strings.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("a" b))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kParamsNotStringList},

    {// params defaulting to ?0 which is the same as no header.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("a"))"
     "\r\n"
     "No-Vary-Search: params=?0\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kDefaultValue},

    {// except without params.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: except=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except without params.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: except=()\r\n"
     R"(No-Vary-Search: except=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except without params.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: except=("a" "b"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("a"))"
     "\r\n"
     "No-Vary-Search: except=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=(),except=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params,except=(),params=())"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: except=("a" "b"))"
     "\r\n"
     R"(No-Vary-Search: params=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("a"),except=("b"))"
     "\r\n"
     "No-Vary-Search: except=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to false is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=?0,except=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except with params set to a list of strings is incorrect.
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params,except=("a" "b"))"
     "\r\n"
     R"(No-Vary-Search: params=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: key-order="a")"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order=a\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order=()\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order=(a)\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: key-order=("a"))"
     "\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order not a boolean
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order=(?1)\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kNonBooleanKeyOrder},

    {// key-order set to false should behave as if the
     // header was not specified at all
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order=?0\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kDefaultValue},

    {// params set to false should behave as if the
     // header was not specified at all
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=?0\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kDefaultValue},

    {// params set to false should behave as if the
     // header was not specified at all. except set to
     // a list of tokens is incorrect.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=?0\r\n"
     "No-Vary-Search: except=(\"a\")\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptWithoutTrueParams},

    {// except set to a list of tokens is incorrect.
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=?1\r\n"
     "No-Vary-Search: except=(a)\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptNotStringList},

    {// except set to true
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params=?1\r\n"
     "No-Vary-Search: except\r\n\r\n",
     HttpNoVarySearchData::ParseErrorEnum::kExceptNotStringList},
};

const TestData response_headers_tests[] = {
    // params set to a list of strings with one element.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a"))"
        "\r\n\r\n",  // raw_headers
        {"a"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // params set to a list of strings with one non-ASCII character.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("%C2%A2"))"
        "\r\n\r\n",  // raw_headers
        {"¢"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // params set to a list of strings with one ASCII and one non-ASCII
    // character.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("c%C2%A2"))"
        "\r\n\r\n",  // raw_headers
        {"c¢"},      // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // params set to a list of strings with one space and one non-ASCII
    // character.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("+%C2%A2"))"
        "\r\n\r\n",  // raw_headers
        {" ¢"},      // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // params set to true.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n\r\n",  // raw_headers
        {},                                // expected_no_vary_params
        {},                                // expected_vary_params
        true,                              // expected_vary_on_key_order
        false,                             // expected_vary_by_default
    },
    // params set to true.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params=?1\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {},                                   // expected_vary_params
        true,                                 // expected_vary_on_key_order
        false,                                // expected_vary_by_default
    },
    // params overridden by a list of strings.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a" b))"
        "\r\n"
        R"(No-Vary-Search: params=("c"))"
        "\r\n\r\n",  // raw_headers
        {"c"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // Vary on all with one excepted search param.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        "No-Vary-Search: except=()\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {},                                   // expected_vary_params
        true,                                 // expected_vary_on_key_order
        false,                                // expected_vary_by_default
    },
    // Vary on all with one excepted search param.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with one excepted non-ASCII search param.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("%C2%A2"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"¢"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with one excepted search param that includes non-ASCII
    // character.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("c+%C2%A2"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"c ¢"},     // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with one excepted search param. Set params as
    // part of the same header line.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params,except=("a"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with one excepted search param. Override except
    // on different header line.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params,except=("a" b))"
        "\r\n"
        R"(No-Vary-Search: except=("c"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"c"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with more than one excepted search param.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a" "b"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a", "b"},  // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all with more than one excepted search param. params appears
    // after except in header definition.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: except=("a" "b"))"
        "\r\n"
        "No-Vary-Search: params\r\n\r\n",  // raw_headers
        {},                                // expected_no_vary_params
        {"a", "b"},                        // expected_vary_params
        true,                              // expected_vary_on_key_order
        false,                             // expected_vary_by_default
    },
    // Vary on all with more than one excepted search param. Set params as
    // part of the same header line.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params,except=("a" "b"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a", "b"},  // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Don't vary on two search params.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a" "b"))"
        "\r\n\r\n",  // raw_headers
        {"a", "b"},  // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // Don't vary on search params order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: key-order\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {},                                   // expected_vary_params
        false,                                // expected_vary_on_key_order
        true,                                 // expected_vary_by_default
    },
    // Don't vary on search params order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: key-order=?1\r\n\r\n",  // raw_headers
        {},                                      // expected_no_vary_params
        {},                                      // expected_vary_params
        false,                                   // expected_vary_on_key_order
        true,                                    // expected_vary_by_default
    },
    // Don't vary on search params order and on two specific search params.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a" "b"))"
        "\r\n"
        "No-Vary-Search: key-order\r\n\r\n",  // raw_headers
        {"a", "b"},                           // expected_no_vary_params
        {},                                   // expected_vary_params
        false,                                // expected_vary_on_key_order
        true,                                 // expected_vary_by_default
    },
    // Don't vary on search params order and on two specific search params.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a" "b"))"
        "\r\n"
        "No-Vary-Search: key-order=?1\r\n\r\n",  // raw_headers
        {"a", "b"},                              // expected_no_vary_params
        {},                                      // expected_vary_params
        false,                                   // expected_vary_on_key_order
        true,                                    // expected_vary_by_default
    },
    // Vary on search params order and do not vary on two specific search
    // params.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a" "b"))"
        "\r\n"
        "No-Vary-Search: key-order=?0\r\n\r\n",  // raw_headers
        {"a", "b"},                              // expected_no_vary_params
        {},                                      // expected_vary_params
        true,                                    // expected_vary_on_key_order
        true,                                    // expected_vary_by_default
    },
    // Vary on all search params except one, and do not vary on search params
    // order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n"
        "No-Vary-Search: key-order\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {"a"},                                // expected_vary_params
        false,                                // expected_vary_on_key_order
        false,                                // expected_vary_by_default
    },
    // Vary on all search params except one, and do not vary on search params
    // order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params=?1\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n"
        "No-Vary-Search: key-order\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {"a"},                                // expected_vary_params
        false,                                // expected_vary_on_key_order
        false,                                // expected_vary_by_default
    },
    // Vary on all search params except one, and do not vary on search params
    // order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n"
        "No-Vary-Search: key-order=?1\r\n\r\n",  // raw_headers
        {},                                      // expected_no_vary_params
        {"a"},                                   // expected_vary_params
        false,                                   // expected_vary_on_key_order
        false,                                   // expected_vary_by_default
    },
    // Vary on all search params except one, and vary on search params order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params=?1\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n"
        "No-Vary-Search: key-order=?0\r\n\r\n",  // raw_headers
        {},                                      // expected_no_vary_params
        {"a"},                                   // expected_vary_params
        true,                                    // expected_vary_on_key_order
        false,                                   // expected_vary_by_default
    },
    // Vary on all search params except two, and do not vary on search params
    // order.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a" "b"))"
        "\r\n"
        "No-Vary-Search: key-order\r\n\r\n",  // raw_headers
        {},                                   // expected_no_vary_params
        {"a", "b"},                           // expected_vary_params
        false,                                // expected_vary_on_key_order
        false,                                // expected_vary_by_default
    },
    // Do not vary on one search params. Override params on a different header
    // line.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a"))"
        "\r\n"
        R"(No-Vary-Search: params=("b"))"
        "\r\n\r\n",  // raw_headers
        {"b"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // Do not vary on any search params. Override params on a different header
    // line.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a"))"
        "\r\n"
        "No-Vary-Search: params\r\n\r\n",  // raw_headers
        {},                                // expected_no_vary_params
        {},                                // expected_vary_params
        true,                              // expected_vary_on_key_order
        false,                             // expected_vary_by_default
    },
    // Do not vary on any search params except one. Override except on a
    // different header line.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n"
        R"(No-Vary-Search: except=("b"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"b"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params;unknown\r\n\r\n",  // raw_headers
        {},                                        // expected_no_vary_params
        {},                                        // expected_vary_params
        true,                                      // expected_vary_on_key_order
        false,                                     // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a");unknown)"
        "\r\n\r\n",  // raw_headers
        {"a"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params;unknown,except=("a");unknown)"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: key-order;unknown\r\n\r\n",  // raw_headers
        {},                                           // expected_no_vary_params
        {},                                           // expected_vary_params
        false,  // expected_vary_on_key_order
        true,   // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("a";unknown))"
        "\r\n\r\n",  // raw_headers
        {"a"},       // expected_no_vary_params
        {},          // expected_vary_params
        true,        // expected_vary_on_key_order
        true,        // expected_vary_by_default
    },
    // Allow extension via parameters.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params\r\n"
        R"(No-Vary-Search: except=("a";unknown))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Vary on all search params except one. Override except on a different
    // header line.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params,except=(a)\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    },
    // Continue parsing if an unknown key is in the dictionary.
    {
        "HTTP/1.1 200 OK\r\n"
        "No-Vary-Search: params,except=(a)\r\n"
        "No-Vary-Search: unknown-key\r\n"
        R"(No-Vary-Search: except=("a"))"
        "\r\n\r\n",  // raw_headers
        {},          // expected_no_vary_params
        {"a"},       // expected_vary_params
        true,        // expected_vary_on_key_order
        false,       // expected_vary_by_default
    }};

INSTANTIATE_TEST_SUITE_P(HttpNoVarySearchResponseHeadersTest,
                         HttpNoVarySearchResponseHeadersTest,
                         testing::ValuesIn(response_headers_tests));

INSTANTIATE_TEST_SUITE_P(HttpNoVarySearchResponseHeadersParseFailureTest,
                         HttpNoVarySearchResponseHeadersParseFailureTest,
                         testing::ValuesIn(response_header_failed));

struct NoVarySearchCompareTestData {
  const GURL request_url;
  const GURL cached_url;
  const std::string_view raw_headers;
  const bool expected_match;
};

TEST(HttpNoVarySearchCompare, CheckUrlEqualityWithSpecialCharacters) {
  // Use special characters in both `keys` and `values`.
  const base::flat_map<std::string, std::string> percent_encoding = {
      {"!", "%21"},    {"#", "%23"},    {"$", "%24"},    {"%", "%25"},
      {"&", "%26"},    {"'", "%27"},    {"(", "%28"},    {")", "%29"},
      {"*", R"(%2A)"}, {"+", R"(%2B)"}, {",", R"(%2C)"}, {"-", R"(%2D)"},
      {".", R"(%2E)"}, {"/", R"(%2F)"}, {":", R"(%3A)"}, {";", "%3B"},
      {"<", R"(%3C)"}, {"=", R"(%3D)"}, {">", R"(%3E)"}, {"?", R"(%3F)"},
      {"@", "%40"},    {"[", "%5B"},    {"]", R"(%5D)"}, {"^", R"(%5E)"},
      {"_", R"(%5F)"}, {"`", "%60"},    {"{", "%7B"},    {"|", R"(%7C)"},
      {"}", R"(%7D)"}, {"~", R"(%7E)"}, {"", ""}};
  const std::string_view raw_headers =
      "HTTP/1.1 200 OK\r\n"
      R"(No-Vary-Search: params=("c"))"
      "\r\n\r\n";
  const std::string headers = HttpUtil::AssembleRawHeaders(raw_headers);
  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  const auto no_vary_search_data =
      HttpNoVarySearchData::ParseFromHeaders(*parsed).value();

  for (const auto& [key, value] : percent_encoding) {
    std::string request_url_template =
        R"(https://a.test/index.html?$key=$value)";
    std::string cached_url_template =
        R"(https://a.test/index.html?c=3&$key=$value)";

    base::ReplaceSubstringsAfterOffset(&request_url_template, 0, "$key", value);
    base::ReplaceSubstringsAfterOffset(&request_url_template, 0, "$value",
                                       value);
    base::ReplaceSubstringsAfterOffset(&cached_url_template, 0, "$key", value);
    base::ReplaceSubstringsAfterOffset(&cached_url_template, 0, "$value",
                                       value);

    EXPECT_TRUE(no_vary_search_data.AreEquivalent(GURL(reques
"""


```