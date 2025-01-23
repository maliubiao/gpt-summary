Response:
The user wants a summary of the functionality of the provided C++ code, which is a unit test file for the `HttpNoVarySearchData` class in Chromium's network stack.

Here's a breakdown of the code and how to arrive at the summary:

1. **Identify the core functionality being tested:** The file name `http_no_vary_search_data_unittest.cc` strongly suggests that the code tests the behavior of the `HttpNoVarySearchData` class. The presence of `TEST` macros confirms this is a unit test file.

2. **Analyze the different test cases:**  Examine each `TEST` block to understand what specific aspect of `HttpNoVarySearchData` is being evaluated. Key things to look for:
    * The names of the tests (`CheckUrlEquality...`, `NoUnrecognizedKeys`, `UnrecognizedKeys`).
    * The setup within each test (creation of URLs, headers, and `HttpNoVarySearchData` objects).
    * The assertions being made (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`).

3. **Focus on the `AreEquivalent` method:**  Many tests involve comparing two URLs using `no_vary_search_data.AreEquivalent(...)`. This method is central to the functionality being tested. The tests aim to verify if this method correctly determines if two URLs are considered equivalent based on the `No-Vary-Search` header.

4. **Examine the `No-Vary-Search` header variations:**  Notice how different `No-Vary-Search` header values are used in the tests:
    * `params`: Ignores all query parameters.
    * `key-order`:  Considers the order of query parameters.
    * `params=("...")`: Ignores specific query parameters.
    * `params, except=("...")`: Considers all query parameters except the specified ones.

5. **Consider edge cases and special scenarios:** Look for tests that handle specific situations, like:
    * Percent-encoded characters in query parameters.
    * Different encodings of the same character.
    * Empty query parameters or keys.
    * Malformed or wrongly escaped characters.

6. **Identify the use of histograms:** The tests `NoUnrecognizedKeys` and `UnrecognizedKeys` demonstrate testing for the logging of metrics related to unrecognized keys in the `No-Vary-Search` header.

7. **Relate to JavaScript (if applicable):**  Think about how this server-side header (`No-Vary-Search`) might impact client-side behavior in a browser. JavaScript code making requests could be affected by how the browser handles caching based on this header.

8. **Infer user interaction and debugging:** Consider how a developer might encounter this code during debugging. What user actions would lead to a request with a `No-Vary-Search` header? How could a developer use these tests to understand the header's effects?

9. **Synthesize the findings into a concise summary.**

**Pre-computation and Pre-analysis (Internal Thought Process):**

* **Decomposition of the request:** The request has multiple parts: functionality, relation to JavaScript, logical inference (input/output), user errors, debugging, and finally a summary for part 2.
* **Core Concept Identification:** The central theme is the `No-Vary-Search` HTTP header and its impact on URL equivalence.
* **Test Structure Recognition:** The code is a series of unit tests. Each test sets up a scenario (URLs, headers) and asserts expected outcomes.
* **Keyword Spotting:** Terms like `AreEquivalent`, `No-Vary-Search`, `params`, `except`, `key-order`, `GURL`, `HttpResponseHeaders` are key to understanding the code.
* **JavaScript Connection Mapping:**  The `No-Vary-Search` header influences caching, which directly affects how JavaScript applications interact with the network.
* **Error Scenario Brainstorming:**  Common user errors involve misunderstanding the `No-Vary-Search` syntax or its implications for caching.
* **Debugging Path Construction:** A developer would likely encounter this during network issue debugging or when implementing caching logic.

By following these steps and analyzing the code structure and test cases, we can arrive at a comprehensive understanding of the file's purpose and generate the required summary.
好的，这是对 `net/http/http_no_vary_search_data_unittest.cc` 文件功能的归纳总结（第二部分）：

**功能归纳总结（第二部分）:**

该文件的主要功能是**测试 `HttpNoVarySearchData` 类中判断两个 URL 是否等价的逻辑，特别是当服务器响应头中包含 `No-Vary-Search` 指令时**。  这部分代码延续了第一部分的思路，通过构造不同的 URL 对和带有各种 `No-Vary-Search` 指令的 HTTP 响应头，来验证 `HttpNoVarySearchData::AreEquivalent()` 方法的正确性。

具体来说，这部分测试涵盖了以下几个方面：

* **处理包含非 ASCII 字符的查询参数键：**  测试了当 `No-Vary-Search` 指令中包含经过 percent 编码的非 ASCII 字符的查询参数键时，`AreEquivalent()` 方法是否能正确判断 URL 的等价性。包括 `except` 和不使用 `except` 两种情况。
* **更全面的 URL 等价性测试用例：** 通过 `HttpNoVarySearchCompare` 这个参数化测试类，涵盖了更多复杂的 URL 场景和 `No-Vary-Search` 指令组合。这些测试用例包括：
    * **用户认证信息差异：** 验证了即使 `No-Vary-Search: params` 存在，用户名和密码的差异仍然会导致 URL 不等价。
    * **路径差异：**  验证了即使 `No-Vary-Search: params` 存在，不同路径的 URL 仍然不等价。
    * **协议差异：** 验证了即使 `No-Vary-Search: params` 存在，不同协议的 URL 仍然不等价。
    * **域名差异：** 验证了即使 `No-Vary-Search: params` 存在，不同域名的 URL 仍然不等价。
    * **`key-order` 指令：** 测试了 `No-Vary-Search: key-order` 指令下，查询参数顺序改变对 URL 等价性的影响。同时测试了参数值不同时的情况。
    * **指定忽略的参数 (`params=("...")`)：**  验证了当 `No-Vary-Search` 指令指定忽略某些查询参数时，这些参数的差异不会影响 URL 的等价性。测试了忽略参数不存在的情况。
    * **指定需要变化的参数 (`params, except=("...")`)：** 验证了当 `No-Vary-Search` 指令指定需要变化的查询参数时，只有这些参数的值相同时，URL 才被认为是等价的。
    * **包含空值或空键的参数：** 测试了包含空值或空键的查询参数对 `key-order` 指令的影响。
    * **错误转义的参数：** 测试了当 URL 中包含错误转义的字符时，`AreEquivalent()` 的处理。
    * **以 percent 编码的空格开头的参数键：** 测试了处理以 `+`（percent 编码的空格）开头的参数键的情况。
    * **相同字符的不同表示形式：** 测试了 URL 中使用相同字符的不同 Unicode 表示形式时，`AreEquivalent()` 的行为，包括指定忽略和不忽略该参数的情况。涵盖了单码位、组合码位的情况。
* **记录未识别的 `No-Vary-Search` 指令:** 通过 `HttpNoVarySearchResponseHeadersParseHistogramTest` 测试用例，验证了当 `No-Vary-Search` 头包含无法识别的指令时，会记录相应的直方图数据（用于性能分析或监控）。

**与 JavaScript 的关系：**

尽管此代码是 C++ 实现，但它直接影响浏览器中 JavaScript 发出的网络请求的缓存行为。

* **Service Worker 和 HTTP 缓存:**  当 JavaScript 通过 `fetch` API 或 XMLHttpRequest 发起请求时，浏览器会利用 HTTP 缓存来提高性能。`No-Vary-Search` 响应头会影响浏览器如何判断是否可以使用缓存的响应。如果服务器返回了带有 `No-Vary-Search` 的响应，即使 JavaScript 发起的后续请求的 URL 只有部分查询参数不同，浏览器也可能认为可以复用之前的缓存，前提是这些差异的参数被 `No-Vary-Search` 指令所忽略。

**假设输入与输出：**

以下是一些假设输入和对应的输出，延续第一部分的例子：

**假设输入 1:**

* **请求 URL:** `https://example.com/search?q=apple&color=red`
* **缓存 URL:** `https://example.com/search?color=blue&q=apple`
* **响应头:** `HTTP/1.1 200 OK\r\nNo-Vary-Search: key-order\r\n\r\n`
* **预期输出:** `HttpNoVarySearchData::AreEquivalent()` 返回 `true` (因为 `key-order` 指令下，参数顺序不影响等价性，且参数值相同)。

**假设输入 2:**

* **请求 URL:** `https://example.com/search?q=apple&color=red`
* **缓存 URL:** `https://example.com/search?q=apple&size=large`
* **响应头:** `HTTP/1.1 200 OK\r\nNo-Vary-Search: params=("color")\r\n\r\n`
* **预期输出:** `HttpNoVarySearchData::AreEquivalent()` 返回 `true` (因为 `color` 参数被忽略，剩下的 `q` 参数值相同)。

**涉及用户或编程常见的使用错误：**

* **错误地配置 `No-Vary-Search`：** 开发者可能错误地配置 `No-Vary-Search` 指令，导致缓存行为不符合预期。例如，本想忽略某个参数，但语法写错，导致缓存策略失效。
    * **示例:**  开发者想忽略 `sort` 参数，但错误地写成了 `No-Vary-Search: params=sort` (缺少括号)。浏览器可能无法正确解析，导致缓存行为异常。
* **对 `key-order` 的误解：** 开发者可能认为 `key-order` 会忽略所有参数的顺序，但实际上它只考虑参数键值对的顺序，对于相同键的多个值，其顺序仍然重要。
* **Percent 编码的混淆：**  对于包含特殊字符的参数键，开发者可能不清楚是否需要进行 percent 编码，以及在 `No-Vary-Search` 指令中如何正确表示。

**用户操作如何到达这里 (调试线索):**

一个开发者在调试网络请求缓存相关问题时，可能会深入到 Chromium 的网络栈代码中，以理解浏览器是如何处理 `No-Vary-Search` 头的。可能的步骤如下：

1. **用户发现缓存行为异常：** 用户在浏览器中访问一个页面，发现缓存的资源与预期的不一致。
2. **开发者检查响应头：** 开发者打开浏览器的开发者工具，查看网络请求的响应头，发现存在 `No-Vary-Search` 字段。
3. **开发者怀疑 `No-Vary-Search` 的影响：**  开发者开始怀疑 `No-Vary-Search` 指令导致了非预期的缓存行为。
4. **源码追踪：** 开发者可能会搜索 Chromium 源码中与 `No-Vary-Search` 相关的代码，找到 `HttpNoVarySearchData` 类和相关的测试文件 `http_no_vary_search_data_unittest.cc`。
5. **查看单元测试：** 开发者通过阅读单元测试代码，了解 `HttpNoVarySearchData` 类是如何解析和处理 `No-Vary-Search` 指令的，以及各种场景下的 URL 等价性判断逻辑。这有助于开发者理解浏览器内部的实现，从而找到导致缓存问题的根本原因。
6. **断点调试：**  开发者可能在 Chromium 源码中设置断点，例如在 `HttpNoVarySearchData::ParseFromHeaders` 或 `HttpNoVarySearchData::AreEquivalent` 方法中，来跟踪具体的执行流程，查看请求头和 URL 的解析结果，以便定位问题。

总而言之，这个测试文件是理解 Chromium 如何实现和测试 `No-Vary-Search` 功能的重要入口，可以帮助开发者理解其工作原理，并排查相关的缓存问题。

### 提示词
```
这是目录为net/http/http_no_vary_search_data_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
t_url_template),
                                                  GURL(cached_url_template)));

    std::string header_template =
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params, except=("$key"))"
        "\r\n\r\n";
    base::ReplaceSubstringsAfterOffset(&header_template, 0, "$key", key);

    const auto parsed_header = base::MakeRefCounted<HttpResponseHeaders>(
        HttpUtil::AssembleRawHeaders(header_template));
    const auto no_vary_search_data_special_char =
        HttpNoVarySearchData::ParseFromHeaders(*parsed_header).value();

    EXPECT_TRUE(no_vary_search_data_special_char.AreEquivalent(
        GURL(request_url_template), GURL(cached_url_template)));
  }
}

constexpr std::pair<std::string_view, std::string_view>
    kPercentEncodedNonAsciiKeys[] = {
        {"¢", R"(%C2%A2)"},
        {"¢ ¢", R"(%C2%A2+%C2%A2)"},
        {"é 気", R"(%C3%A9+%E6%B0%97)"},
        {"é", R"(%C3%A9)"},
        {"気", R"(%E6%B0%97)"},
        {"ぁ", R"(%E3%81%81)"},
        {"𐨀", R"(%F0%90%A8%80)"},
};

TEST(HttpNoVarySearchCompare,
     CheckUrlEqualityWithPercentEncodedNonASCIICharactersExcept) {
  for (const auto& [key, value] : kPercentEncodedNonAsciiKeys) {
    std::string request_url_template = R"(https://a.test/index.html?$key=c)";
    std::string cached_url_template = R"(https://a.test/index.html?c=3&$key=c)";
    base::ReplaceSubstringsAfterOffset(&request_url_template, 0, "$key", key);
    base::ReplaceSubstringsAfterOffset(&cached_url_template, 0, "$key", key);
    std::string header_template =
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params, except=("$key"))"
        "\r\n\r\n";
    base::ReplaceSubstringsAfterOffset(&header_template, 0, "$key", value);

    const auto parsed_header = base::MakeRefCounted<HttpResponseHeaders>(
        HttpUtil::AssembleRawHeaders(header_template));
    const auto no_vary_search_data_special_char =
        HttpNoVarySearchData::ParseFromHeaders(*parsed_header).value();

    EXPECT_TRUE(no_vary_search_data_special_char.AreEquivalent(
        GURL(request_url_template), GURL(cached_url_template)))
        << "request_url = " << request_url_template
        << " cached_url = " << cached_url_template
        << " headers = " << header_template;
  }
}

TEST(HttpNoVarySearchCompare,
     CheckUrlEqualityWithPercentEncodedNonASCIICharacters) {
  for (const auto& [key, value] : kPercentEncodedNonAsciiKeys) {
    std::string request_url_template =
        R"(https://a.test/index.html?a=2&$key=c)";
    std::string cached_url_template = R"(https://a.test/index.html?$key=d&a=2)";
    base::ReplaceSubstringsAfterOffset(&request_url_template, 0, "$key", key);
    base::ReplaceSubstringsAfterOffset(&cached_url_template, 0, "$key", key);
    std::string header_template =
        "HTTP/1.1 200 OK\r\n"
        R"(No-Vary-Search: params=("$key"))"
        "\r\n\r\n";
    base::ReplaceSubstringsAfterOffset(&header_template, 0, "$key", value);

    const auto parsed_header = base::MakeRefCounted<HttpResponseHeaders>(
        HttpUtil::AssembleRawHeaders(header_template));
    const auto no_vary_search_data_special_char =
        HttpNoVarySearchData::ParseFromHeaders(*parsed_header).value();

    EXPECT_TRUE(no_vary_search_data_special_char.AreEquivalent(
        GURL(request_url_template), GURL(cached_url_template)))
        << "request_url = " << request_url_template
        << " cached_url = " << cached_url_template
        << " headers = " << header_template;
  }
}

class HttpNoVarySearchCompare
    : public ::testing::Test,
      public ::testing::WithParamInterface<NoVarySearchCompareTestData> {};

TEST_P(HttpNoVarySearchCompare, CheckUrlEqualityByNoVarySearch) {
  const auto& test_data = GetParam();

  const std::string headers =
      HttpUtil::AssembleRawHeaders(test_data.raw_headers);
  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  const auto no_vary_search_data =
      HttpNoVarySearchData::ParseFromHeaders(*parsed).value();

  EXPECT_EQ(no_vary_search_data.AreEquivalent(test_data.request_url,
                                              test_data.cached_url),
            test_data.expected_match)
      << "request_url = " << test_data.request_url
      << " cached_url = " << test_data.cached_url
      << " headers = " << test_data.raw_headers
      << " match = " << test_data.expected_match;
}

const NoVarySearchCompareTestData no_vary_search_compare_tests[] = {
    // Url's for same page with same username but different passwords.
    {GURL("https://owner:correct@a.test/index.html?a=2&b=3"),
     GURL("https://owner:incorrect@a.test/index.html?a=2&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     false},
    // Url's for same page with different username.
    {GURL("https://anonymous@a.test/index.html?a=2&b=3"),
     GURL("https://owner@a.test/index.html?a=2&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     false},
    // Url's for same origin with different path.
    {GURL("https://a.test/index.html?a=2&b=3"),
     GURL("https://a.test/home.html?a=2&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     false},
    // Url's for same page with different protocol.
    {GURL("http://a.test/index.html?a=2&b=3"),
     GURL("https://a.test/index.html?a=2&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     false},
    // Url's for different pages without the query and reference part
    // are not equivalent.
    {GURL("https://a.test/index.html?a=2&b=3"),
     GURL("https://b.test/index.html?b=4&c=5"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     false},
    // Cached page requested again with different order of query parameters with
    // the same values.
    {GURL("https://a.test/index.html?a=2&b=3"),
     GURL("https://a.test/index.html?b=3&a=2"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order\r\n\r\n",
     true},
    // Cached page requested again with different order of query parameters but
    // with different values.
    {GURL("https://a.test/index.html?a=2&c=5&b=3"),
     GURL("https://a.test/index.html?c=4&b=3&a=2"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order\r\n\r\n",
     false},
    // Cached page requested again with values in different order for the query
    // parameters with the same name. Key order is ignored.
    {GURL("https://a.test/index.html?d=6&a=4&b=5&b=3&c=5&a=3"),
     GURL("https://a.test/index.html?b=5&a=3&a=4&d=6&c=5&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order"
     "\r\n\r\n",
     false},
    // Cached page requested again with values in the same order for the query
    // parameters with the same name. Key order is ignored.
    {GURL("https://a.test/index.html?d=6&a=3&b=5&b=3&c=5&a=4"),
     GURL("https://a.test/index.html?b=5&a=3&a=4&d=6&c=5&b=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order"
     "\r\n\r\n",
     true},
    // Cached page requested again with different order of query parameters but
    // with one of the query parameters marked to be ignored.
    {GURL("https://a.test/index.html?a=2&c=3&b=2"),
     GURL("https://a.test/index.html?a=2&b=2&c=5"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("c"))"
     "\r\n\r\n",
     true},
    // Cached page requested again without any query parameters, but
    // the cached URL's query parameter marked to be ignored.
    {GURL("https://a.test/index.html"), GURL("https://a.test/index.html?a=2"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("a"))"
     "\r\n\r\n",
     true},
    // Cached page requested again with different values for the query
    // parameters that are marked to be ignored. Same value for the query
    // parameter that is marked as to vary.
    {GURL("https://a.test/index.html?a=1&b=2&c=3"),
     GURL("https://a.test/index.html?b=5&a=3&d=6&c=3"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("c"))"
     "\r\n\r\n",
     true},
    // Cached page requested again with different values for the query
    // parameters that are marked to be ignored. Different value for the query
    // parameter that is marked as to vary.
    {GURL("https://a.test/index.html?a=1&b=2&c=5"),
     GURL("https://a.test/index.html?b=5&a=3&d=6&c=3"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("c"))"
     "\r\n\r\n",
     false},
    // Cached page requested again with different values for the query
    // parameters that are marked to be ignored. Same values for the query
    // parameters that are marked as to vary.
    {GURL("https://a.test/index.html?d=6&a=1&b=2&c=5"),
     GURL("https://a.test/index.html?b=5&a=3&d=6&c=5"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("c" "d"))"
     "\r\n\r\n",
     true},
    // Cached page requested again with different values for the query
    // parameters that are marked to be ignored. Same values for the query
    // parameters that are marked as to vary. Some query parameters to be
    // ignored appear multiple times in the query.
    {GURL("https://a.test/index.html?d=6&a=1&a=2&b=2&b=3&c=5"),
     GURL("https://a.test/index.html?b=5&a=3&a=4&d=6&c=5"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("c" "d"))"
     "\r\n\r\n",
     true},
    // Cached page requested again with query parameters. All query parameters
    // are marked as to be ignored.
    {GURL("https://a.test/index.html?a=1&b=2&c=5"),
     GURL("https://a.test/index.html"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     true},
    // Cached page requested again with query parameters. All query parameters
    // are marked as to be ignored. Both request url and cached url have query
    // parameters.
    {GURL("https://a.test/index.html?a=1&b=2&c=5"),
     GURL("https://a.test/index.html?a=5&b=6&c=8&d=1"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: params\r\n\r\n",
     true},
    // Add test for when the keys are percent encoded.
    {GURL(R"(https://a.test/index.html?c+1=3&b+%202=2&a=1&%63%201=2&a=5)"),
     GURL(R"(https://a.test/index.html?a=1&b%20%202=2&%63%201=3&a=5&c+1=2)"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order\r\n\r\n",
     true},
    // Add test for when there are different representations of a character
    {GURL(R"(https://a.test/index.html?%C3%A9=f&a=2&c=4&é=b)"),
     GURL(R"(https://a.test/index.html?a=2&é=f&c=4&d=7&é=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("d"), key-order)"
     "\r\n\r\n",
     true},
    // Add test for when there are triple code point
    {GURL(R"(https://a.test/index.html?%E3%81%81=f&a=2&c=4&%E3%81%81=b)"),
     GURL(R"(https://a.test/index.html?a=2&%E3%81%81=f&c=4&d=7&%E3%81%81=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("d"), key-order)"
     "\r\n\r\n",
     true},
    // Add test for when there are quadruple code point
    {GURL(
         R"(https://a.test/index.html?%F0%90%A8%80=%F0%90%A8%80&a=2&c=4&%F0%90%A8%80=b)"),
     GURL(
         R"(https://a.test/index.html?a=2&%F0%90%A8%80=%F0%90%A8%80&c=4&d=7&%F0%90%A8%80=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("d"), key-order)"
     "\r\n\r\n",
     true},
    // Add test for when there are params with empty values / keys.
    {GURL("https://a.test/index.html?a&b&c&a=2&d&=5&=1&=3"),
     GURL("https://a.test/index.html?c&d&b&a&=5&=1&a=2&=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order\r\n\r\n",
     true},
    // Add test for when there are params with empty values / keys, an empty
    // key pair missing.
    {GURL("https://a.test/index.html?a&b&c&a=2&d&=5&=1&=3"),
     GURL("https://a.test/index.html?c&d&b&a&=5&a=2&=3"),
     "HTTP/1.1 200 OK\r\n"
     "No-Vary-Search: key-order\r\n\r\n",
     false},
    // Add test when there are params with keys / values that are wrongly
    // escaped.
    {GURL(R"(https://a.test/index.html?a=%3&%3=b)"),
     GURL(R"(https://a.test/index.html?a=%3&c=3&%3=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("c"))"
     "\r\n\r\n",
     true},
    // Add test when there is a param with key starting with a percent encoded
    // space (+).
    {GURL(R"(https://a.test/index.html?+a=3)"),
     GURL(R"(https://a.test/index.html?+a=2)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("+a"))"
     "\r\n\r\n",
     true},
    // Add test when there is a param with key starting with a percent encoded
    // space (+) and gets compared with same key without the leading space.
    {GURL(R"(https://a.test/index.html?+a=3)"),
     GURL(R"(https://a.test/index.html?a=2)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("+a"))"
     "\r\n\r\n",
     false},
    // Add test for when there are different representations of the character é
    // and we are ignoring that key.
    {GURL(R"(https://a.test/index.html?%C3%A9=g&a=2&c=4&é=b)"),
     GURL(R"(https://a.test/index.html?a=2&é=f&c=4&d=7&é=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params=("d" "%C3%A9"))"
     "\r\n\r\n",
     true},
    // Add test for when there are different representations of the character é
    // and we are not ignoring that key.
    {GURL(R"(https://a.test/index.html?%C3%A9=f&a=2&c=4&é=b)"),
     GURL(R"(https://a.test/index.html?a=2&é=f&c=4&d=7&é=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("%C3%A9"))"
     "\r\n\r\n",
     true},
    // Add test for when there are different representations of the character é
    // and we are not ignoring that key.
    {GURL(R"(https://a.test/index.html?%C3%A9=g&a=2&c=4&é=b)"),
     GURL(R"(https://a.test/index.html?a=2&é=f&c=4&d=7&é=b)"),
     "HTTP/1.1 200 OK\r\n"
     R"(No-Vary-Search: params, except=("%C3%A9"))"
     "\r\n\r\n",
     false},
};

INSTANTIATE_TEST_SUITE_P(HttpNoVarySearchCompare,
                         HttpNoVarySearchCompare,
                         testing::ValuesIn(no_vary_search_compare_tests));

TEST(HttpNoVarySearchResponseHeadersParseHistogramTest, NoUnrecognizedKeys) {
  base::HistogramTester histogram_tester;
  const std::string raw_headers = HttpUtil::AssembleRawHeaders(
      "HTTP/1.1 200 OK\r\nNo-Vary-Search: params\r\n\r\n");
  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  const auto no_vary_search_data =
      HttpNoVarySearchData::ParseFromHeaders(*parsed);
  EXPECT_THAT(no_vary_search_data, base::test::HasValue());
  histogram_tester.ExpectUniqueSample(
      "Net.HttpNoVarySearch.HasUnrecognizedKeys", false, 1);
}

TEST(HttpNoVarySearchResponseHeadersParseHistogramTest, UnrecognizedKeys) {
  base::HistogramTester histogram_tester;
  const std::string raw_headers = HttpUtil::AssembleRawHeaders(
      "HTTP/1.1 200 OK\r\nNo-Vary-Search: params, rainbows\r\n\r\n");
  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  const auto no_vary_search_data =
      HttpNoVarySearchData::ParseFromHeaders(*parsed);
  EXPECT_THAT(no_vary_search_data, base::test::HasValue());
  histogram_tester.ExpectUniqueSample(
      "Net.HttpNoVarySearch.HasUnrecognizedKeys", true, 1);
}

}  // namespace

}  // namespace net
```