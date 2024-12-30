Response:
The user wants to understand the functionality of the provided C++ code snippet from `balsa_headers_test.cc`. This file is part of the Chromium network stack and tests the `BalsaHeaders` class.

The request asks for:
1. **Functionality of the code:** What does this specific section of the test file do?
2. **Relation to JavaScript:**  Are there any connections to JavaScript functionality?
3. **Logical reasoning (input/output):** If there's a clear logic, what are the inputs and expected outputs of the tests?
4. **Common usage errors:** What mistakes might a developer make when using this code?
5. **User journey for debugging:** How does a user's action lead to this code being relevant for debugging?
6. **Summary of functionality (part 2 of 5):**  A concise overview of what this specific part tests.

Let's analyze the code step-by-step:

The code defines several test cases using the `TEST` macro from Google Test. Each test case focuses on a specific aspect of the `BalsaHeaders` class.

- `TEST(BalsaHeaders, HeaderHasValues)`:  This test checks if the `HeaderHasValue` and `HeaderHasValueIgnoreCase` methods correctly identify whether a header contains a specific value. It covers cases with commas, spaces, different capitalization, and empty values.
- `TEST(BalsaHeaders, TestNotDeletingBeyondString)`:  This test verifies that the `RemoveAllHeadersWithPrefix` method doesn't accidentally access memory beyond the bounds of the header string. This is important because `BalsaHeaders` might use a single large buffer.
- `TEST(BalsaHeaders, TestIteratingOverErasedHeaders)`: This test checks if iterating through the header lines works correctly after some headers have been removed using `RemoveAllOfHeader`. It verifies that the iterator correctly skips the removed entries.
- `TEST(BalsaHeaders, CanCompareIterators)`: This test confirms that the iterators provided by `BalsaHeaders::lines()` can be compared using standard comparison operators (`==`, `!=`, `<`, `<=`, `>`, `>=`).
- `TEST(BalsaHeaders, AppendHeaderAndTestThatYouCanEraseEverything)`: This test checks if it's possible to iterate through and erase all header lines.
- `TEST(BalsaHeaders, GetHeaderPositionWorksAsExpectedWithNoHeaderLines)`: Tests the `GetHeaderPosition` method when there are no headers.
- `TEST(BalsaHeaders, GetHeaderPositionWorksAsExpectedWithBalsaFrameProcessInput)`: Tests `GetHeaderPosition` after parsing headers from a string.
- `TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithNoHeaderLines)`: Tests `GetHeader` when there are no headers.
- `TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithNoHeaderLines)`: Tests `HasHeader` and `HasHeadersWithPrefix` when there are no headers.
- `TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithBalsaFrameProcessInput)`: Tests `HasHeader` and `HasHeadersWithPrefix` after parsing headers.
- `TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithBalsaFrameProcessInput)`: Tests `GetHeader` after parsing headers, checking retrieval of the first occurrence.
- `TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithAppendHeader)`: Tests `GetHeader` after appending headers.
- `TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithAppendHeader)`: Tests `HasHeader` and `HasHeadersWithPrefix` after appending headers.
- `TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithHeadersErased)`: Tests `GetHeader` after erasing headers.
- `TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithHeadersErased)`: Tests `HasHeader` and `HasHeadersWithPrefix` after erasing headers.
- `TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithNoHeaderLines)`: Tests `HasNonEmptyHeader` when there are no headers.
- `TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithAppendHeader)`: Tests `HasNonEmptyHeader` after appending headers.
- `TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithHeadersErased)`: Tests `HasNonEmptyHeader` after erasing headers.
- `TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithBalsaFrameProcessInput)`: Tests `HasNonEmptyHeader` after parsing headers.
- `TEST(BalsaHeaders, GetAllOfHeader)`: Tests `GetAllOfHeader` for retrieving all values of a header, considering case variations.
- `TEST(BalsaHeaders, GetAllOfHeaderDoesWhatItSays)`:  Further tests for `GetAllOfHeader` with multiple occurrences and empty values.
- `TEST(BalsaHeaders, GetAllOfHeaderWithPrefix)`: Tests `GetAllOfHeaderWithPrefix` for retrieving headers with a specific prefix.
- `TEST(BalsaHeaders, GetAllHeadersWithLimit)`: Tests `GetAllHeadersWithLimit` to retrieve a limited number of headers.
- `TEST(BalsaHeaders, RangeFor)`: Tests iterating through headers using a range-based for loop.
- `TEST(BalsaHeaders, GetAllOfHeaderWithNonExistentKey)`: Tests `GetAllOfHeader` for a non-existent header key.
- `TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation1)` to `TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation4)`: Various tests for `GetAllOfHeader` with empty header values.
- `TEST(BalsaHeaders, GetAllOfHeaderWithAppendHeaders)`: Tests `GetAllOfHeader` after appending new headers.
- `TEST(BalsaHeaders, GetAllOfHeaderWithRemoveHeaders)`: Tests `GetAllOfHeader` after removing headers.
- `TEST(BalsaHeaders, GetAllOfHeaderWithRemoveNonExistentHeaders)`: Tests `RemoveValue` for a non-existent value.
- `TEST(BalsaHeaders, GetAllOfHeaderWithEraseHeaders)`: Tests `GetAllOfHeader` after erasing headers.
- `TEST(BalsaHeaders, GetAllOfHeaderWithNoHeaderLines)`: Tests `GetAllOfHeader` when there are no headers.
- `TEST(BalsaHeaders, GetAllOfHeaderDoesWhatItSaysForVariousKeys)`: Tests `GetAllOfHeader` with different header keys.
- `TEST(BalsaHeaders, GetAllOfHeaderWithBalsaFrameProcessInput)`: Tests `GetAllOfHeader` after parsing headers from a string.
- `TEST(BalsaHeaders, GetAllOfHeaderIncludeRemovedDoesWhatItSays)`: Tests `GetAllOfHeaderIncludeRemoved`, which includes removed headers.
- `TEST(BalsaHeaders, GetAllOfHeaderIncludeRemovedWithNonExistentKey)`: Tests `GetAllOfHeaderIncludeRemoved` for a non-existent key.
- `TEST(BalsaHeaders, GetIteratorForKeyDoesWhatItSays)`: Tests `GetIteratorForKey` for retrieving an iterator to a specific header key.
这是文件 `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc` 的一部分，它主要包含了针对 `BalsaHeaders` 类的单元测试。这个类在 Chromium 的网络栈中用于处理 HTTP 头部。

**这个代码片段的功能归纳如下：**

这个代码片段主要测试了 `BalsaHeaders` 类中以下与 **获取和检查 HTTP 头部值** 相关的功能：

* **`HeaderHasValue(key, value)` 和 `HeaderHasValueIgnoreCase(key, value)`:**  测试是否区分大小写地检查特定的头部是否包含特定的值。
* **`RemoveAllHeadersWithPrefix(prefix)` 的边界情况:**  测试带有前缀移除所有头部时，不会越界访问内存。
* **在头部被移除后进行迭代:** 测试在移除头部后，迭代器是否还能正确地遍历剩余的头部。
* **迭代器的比较:** 测试 `BalsaHeaders` 的迭代器是否可以进行比较操作（`==`, `!=`, `<`, `>`, 等）。
* **移除所有头部:** 测试是否能通过迭代器删除所有的头部。
* **`GetHeaderPosition(key)`:** 测试获取指定头部第一次出现的位置的迭代器。
* **`GetHeader(key)`:** 测试获取指定头部的第一个值。
* **`HasHeader(key)` 和 `HasHeadersWithPrefix(prefix)`:** 测试检查是否存在指定头部或以指定前缀开头的头部。
* **`HasNonEmptyHeader(key)`:** 测试检查是否存在指定头部且其值不为空。
* **`GetAllOfHeader(key)`:** 测试获取指定头部的所有值。
* **`GetAllOfHeaderWithPrefix(prefix)`:** 测试获取所有以指定前缀开头的头部及其值。
* **`GetAllHeadersWithLimit(limit)`:** 测试获取指定数量的头部。
* **使用 range-for 循环迭代头部:** 测试是否可以使用 range-for 循环遍历头部。
* **`GetAllOfHeaderIncludeRemoved(key)`:** 测试获取指定头部的所有值，包括已被移除的头部的值。
* **`GetIteratorForKey(key)`:** 测试获取指向具有特定键的第一个头部的迭代器。

**与 JavaScript 功能的关系：**

HTTP 头部是 Web 通信的基础，与 JavaScript 的功能有密切关系，主要体现在以下几点：

* **请求和响应头部的访问:** JavaScript 可以通过 `XMLHttpRequest` 或 `fetch API` 发送 HTTP 请求，并可以访问服务器返回的响应头部。例如，可以使用 `response.headers.get('Content-Type')` 获取响应的 Content-Type。
* **设置请求头部:** 在发送请求时，JavaScript 可以设置自定义的请求头部，例如 `xhr.setRequestHeader('X-Custom-Header', 'value')`。
* **Cookie 处理:**  `Set-Cookie` 和 `Cookie` 头部在客户端（浏览器，运行 JavaScript 的环境）进行管理。JavaScript 可以通过 `document.cookie` 访问和操作 Cookie。
* **缓存控制:** HTTP 头部如 `Cache-Control`、`Expires` 等影响浏览器缓存行为，这直接影响 JavaScript 应用的性能和用户体验。
* **跨域请求 (CORS):**  与跨域资源共享相关的头部（如 `Access-Control-Allow-Origin`）对于运行在浏览器中的 JavaScript 应用至关重要。

**举例说明：**

假设一个 JavaScript 应用需要获取服务器提供的用户 ID，服务器通过一个名为 `X-User-Id` 的自定义头部返回：

**JavaScript 代码 (使用 fetch API):**

```javascript
fetch('/api/user-info')
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const userId = response.headers.get('X-User-Id');
    console.log('User ID:', userId);
    return response.json(); // 或者其他处理
  })
  .then(data => console.log('User Data:', data))
  .catch(error => console.error('Error fetching user info:', error));
```

在这个例子中，`BalsaHeaders` 类（在 Chromium 内部）会负责解析服务器返回的头部，而 JavaScript 代码则通过 `response.headers.get('X-User-Id')` 来访问这个头部的值。`BalsaHeaders` 的 `GetHeader` 方法的功能与 JavaScript 中 `Headers.get()` 方法的概念是对应的。

**逻辑推理，假设输入与输出：**

**假设输入：**

```
BalsaHeaders headers;
headers.AppendHeader("X-Forwarded-For", "1.1.1.1");
headers.AppendHeader("X-Forwarded-For", "2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6");
```

**预期输出 (对于 `GetAllOfHeader("X-Forwarded-For")`):**

一个包含两个元素的容器，分别是字符串 `"1.1.1.1"` 和 `"2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6"`。

**用户或编程常见的使用错误：**

* **大小写敏感性混淆:**  HTTP 头部名称通常是不区分大小写的，但某些头部的值可能是区分大小写的。开发者可能会错误地假设所有的比较都是大小写不敏感的，导致使用 `HeaderHasValue` 时出现错误。例如，期望 `headers.HeaderHasValue("key", "Value")` 返回 `true`，但实际上如果头部的值是 `"value"` 则会返回 `false`。
* **假设 `GetHeader` 返回所有值:**  `GetHeader` 方法只返回指定头部的第一个值。如果开发者期望获取所有值，应该使用 `GetAllOfHeader`。
* **忘记处理空值:**  头部的值可能为空字符串。开发者在处理头部值时需要注意检查空值的情况，避免出现空指针或空字符串相关的错误。
* **错误地使用前缀匹配:**  `HasHeadersWithPrefix` 和 `GetAllOfHeaderWithPrefix` 是基于前缀匹配的。开发者可能会错误地认为这是完全匹配，导致遗漏或错误地包含了某些头部。例如，使用 `HasHeadersWithPrefix("Content")` 会匹配到 "Content-Type" 和 "Content-Length"。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户报告了一个与 HTTP 头部相关的 Bug，例如：

1. **用户在使用 Chromium 浏览器访问某个网站时，发现网站的某些功能不正常。**
2. **开发者开始调试网络请求。** 使用 Chromium 的开发者工具 (DevTools)，他们可以查看浏览器发送的请求头和服务器返回的响应头。
3. **开发者怀疑某个特定的头部的值不正确，或者某个头部缺失。**  例如，用户反馈图片加载不出来，开发者查看响应头，发现 `Content-Type` 头部的值不正确。
4. **为了定位问题，开发者可能会查看 Chromium 网络栈的源代码。** 他们可能会怀疑 `BalsaHeaders` 类在解析或处理头部时出现了问题。
5. **开发者可能会查看 `balsa_headers_test.cc` 中的单元测试，以了解 `BalsaHeaders` 类的预期行为。**  如果发现相关的测试用例失败，或者没有覆盖到特定的场景，这可能会提供调试的线索。
6. **开发者可能会尝试编写新的单元测试来复现用户遇到的问题。** 这有助于更精确地定位 Bug 所在的代码。
7. **通过分析 `BalsaHeaders` 类的实现以及相关的单元测试，开发者可以逐步找到 Bug 的原因，并修复代码。**

**总结这个代码片段的功能：**

这个代码片段是 `balsa_headers_test.cc` 文件的一部分，它专注于测试 `BalsaHeaders` 类中 **获取和检查 HTTP 头部值** 的各种方法，包括区分大小写和不区分大小写的检查，获取单个或所有头部值，以及根据前缀进行匹配等功能。这些测试用例覆盖了正常情况、边界情况以及各种可能的用户输入和操作，确保 `BalsaHeaders` 类能够正确可靠地处理 HTTP 头部。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
.
  EXPECT_THAT(
      headers.GetAllOfHeader("X-Forwarded-For"),
      ElementsAre("1.1.1.1", "2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6"));
}

TEST(BalsaHeaders, HeaderHasValues) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  // Make sure we find values at the beginning, middle, and end, and we handle
  // multiple .find() calls correctly.
  headers.AppendHeader("key", "val1,val2val2,val2,val3");
  // Make sure we don't mess up comma/boundary checks for beginning, middle and
  // end.
  headers.AppendHeader("key", "val4val5val6");
  headers.AppendHeader("key", "val11 val12");
  headers.AppendHeader("key", "v val13");
  // Make sure we catch the line header
  headers.AppendHeader("key", "val7");
  // Make sure there's no out-of-bounds indexing on an empty line.
  headers.AppendHeader("key", "");
  // Make sure it works when there's spaces before or after a comma.
  headers.AppendHeader("key", "val8 , val9 , val10");
  // Make sure it works when val is surrounded by spaces.
  headers.AppendHeader("key", " val14 ");
  // Make sure other keys aren't used.
  headers.AppendHeader("key2", "val15");
  // Mixed case.
  headers.AppendHeader("key", "Val16");
  headers.AppendHeader("key", "foo, Val17, bar");

  // All case-sensitive.
  EXPECT_TRUE(headers.HeaderHasValue("key", "val1"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val2"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val3"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val7"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val8"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val9"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val10"));
  EXPECT_TRUE(headers.HeaderHasValue("key", "val14"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val4"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val5"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val6"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val11"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val12"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val13"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val15"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val16"));
  EXPECT_FALSE(headers.HeaderHasValue("key", "val17"));

  // All case-insensitive, only change is for val16 and val17.
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val1"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val2"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val3"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val7"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val8"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val9"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val10"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val14"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val4"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val5"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val6"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val11"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val12"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val13"));
  EXPECT_FALSE(headers.HeaderHasValueIgnoreCase("key", "val15"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val16"));
  EXPECT_TRUE(headers.HeaderHasValueIgnoreCase("key", "val17"));
}

// Because we're dealing with one giant buffer, make sure we don't go beyond
// the bounds of the key when doing compares!
TEST(BalsaHeaders, TestNotDeletingBeyondString) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");

  headers.RemoveAllHeadersWithPrefix("key1: value1");
  EXPECT_NE(headers.lines().begin(), headers.lines().end());
}

TEST(BalsaHeaders, TestIteratingOverErasedHeaders) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key2", "value2");
  headers.AppendHeader("key3", "value3");
  headers.AppendHeader("key4", "value4");
  headers.AppendHeader("key5", "value5");
  headers.AppendHeader("key6", "value6");

  headers.RemoveAllOfHeader("key6");
  headers.RemoveAllOfHeader("key5");
  headers.RemoveAllOfHeader("key4");

  BalsaHeaders::const_header_lines_iterator chli = headers.lines().begin();
  EXPECT_NE(headers.lines().end(), chli);
  EXPECT_EQ(headers.lines().begin(), chli);
  EXPECT_THAT(chli->first, StrEq("key1"));
  EXPECT_THAT(chli->second, StrEq("value1"));

  ++chli;
  EXPECT_NE(headers.lines().end(), chli);
  EXPECT_NE(headers.lines().begin(), chli);
  EXPECT_THAT(chli->first, StrEq("key2"));
  EXPECT_THAT(chli->second, StrEq("value2"));

  ++chli;
  EXPECT_NE(headers.lines().end(), chli);
  EXPECT_NE(headers.lines().begin(), chli);
  EXPECT_THAT(chli->first, StrEq("key3"));
  EXPECT_THAT(chli->second, StrEq("value3"));

  ++chli;
  EXPECT_EQ(headers.lines().end(), chli);
  EXPECT_NE(headers.lines().begin(), chli);

  headers.RemoveAllOfHeader("key1");
  headers.RemoveAllOfHeader("key2");
  chli = headers.lines().begin();
  EXPECT_THAT(chli->first, StrEq("key3"));
  EXPECT_THAT(chli->second, StrEq("value3"));
  EXPECT_NE(headers.lines().end(), chli);
  EXPECT_EQ(headers.lines().begin(), chli);

  ++chli;
  EXPECT_EQ(headers.lines().end(), chli);
  EXPECT_NE(headers.lines().begin(), chli);
}

TEST(BalsaHeaders, CanCompareIterators) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }
  {
    std::string key_2 = "key_2";
    std::string value_2 = "value_2";
    header.AppendHeader(key_2, value_2);
    key_2 = "garbage";
    value_2 = "garbage";
  }
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  BalsaHeaders::const_header_lines_iterator chlj = header.lines().begin();
  EXPECT_EQ(chli, chlj);
  ++chlj;
  EXPECT_NE(chli, chlj);
  EXPECT_LT(chli, chlj);
  EXPECT_LE(chli, chlj);
  EXPECT_LE(chli, chli);
  EXPECT_GT(chlj, chli);
  EXPECT_GE(chlj, chli);
  EXPECT_GE(chlj, chlj);
}

TEST(BalsaHeaders, AppendHeaderAndTestThatYouCanEraseEverything) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }
  {
    std::string key_2 = "key_2";
    std::string value_2 = "value_2";
    header.AppendHeader(key_2, value_2);
    key_2 = "garbage";
    value_2 = "garbage";
  }
  {
    std::string key_3 = "key_3";
    std::string value_3 = "value_3";
    header.AppendHeader(key_3, value_3);
    key_3 = "garbage";
    value_3 = "garbage";
  }
  EXPECT_NE(header.lines().begin(), header.lines().end());
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  while (chli != header.lines().end()) {
    header.erase(chli);
    chli = header.lines().begin();
  }
  ASSERT_EQ(header.lines().begin(), header.lines().end());
}

TEST(BalsaHeaders, GetHeaderPositionWorksAsExpectedWithNoHeaderLines) {
  BalsaHeaders header;
  BalsaHeaders::const_header_lines_iterator i = header.GetHeaderPosition("foo");
  EXPECT_EQ(i, header.lines().end());
}

TEST(BalsaHeaders, GetHeaderPositionWorksAsExpectedWithBalsaFrameProcessInput) {
  BalsaHeaders headers = CreateHTTPHeaders(
      true,
      "GET / HTTP/1.0\r\n"
      "key1: value_1\r\n"
      "key1: value_foo\r\n"  // this one cannot be fetched via GetHeader
      "key2: value_2\r\n"
      "key3: value_3\r\n"
      "a: value_a\r\n"
      "b: value_b\r\n"
      "\r\n");

  BalsaHeaders::const_header_lines_iterator header_position_b =
      headers.GetHeaderPosition("b");
  ASSERT_NE(header_position_b, headers.lines().end());
  absl::string_view header_key_b_value = header_position_b->second;
  ASSERT_FALSE(header_key_b_value.empty());
  EXPECT_EQ(std::string("value_b"), header_key_b_value);

  BalsaHeaders::const_header_lines_iterator header_position_1 =
      headers.GetHeaderPosition("key1");
  ASSERT_NE(header_position_1, headers.lines().end());
  absl::string_view header_key_1_value = header_position_1->second;
  ASSERT_FALSE(header_key_1_value.empty());
  EXPECT_EQ(std::string("value_1"), header_key_1_value);

  BalsaHeaders::const_header_lines_iterator header_position_3 =
      headers.GetHeaderPosition("key3");
  ASSERT_NE(header_position_3, headers.lines().end());
  absl::string_view header_key_3_value = header_position_3->second;
  ASSERT_FALSE(header_key_3_value.empty());
  EXPECT_EQ(std::string("value_3"), header_key_3_value);

  BalsaHeaders::const_header_lines_iterator header_position_2 =
      headers.GetHeaderPosition("key2");
  ASSERT_NE(header_position_2, headers.lines().end());
  absl::string_view header_key_2_value = header_position_2->second;
  ASSERT_FALSE(header_key_2_value.empty());
  EXPECT_EQ(std::string("value_2"), header_key_2_value);

  BalsaHeaders::const_header_lines_iterator header_position_a =
      headers.GetHeaderPosition("a");
  ASSERT_NE(header_position_a, headers.lines().end());
  absl::string_view header_key_a_value = header_position_a->second;
  ASSERT_FALSE(header_key_a_value.empty());
  EXPECT_EQ(std::string("value_a"), header_key_a_value);
}

TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithNoHeaderLines) {
  BalsaHeaders header;
  absl::string_view value = header.GetHeader("foo");
  EXPECT_TRUE(value.empty());
  value = header.GetHeader("");
  EXPECT_TRUE(value.empty());
}

TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithNoHeaderLines) {
  BalsaHeaders header;
  EXPECT_FALSE(header.HasHeader("foo"));
  EXPECT_FALSE(header.HasHeader(""));
  EXPECT_FALSE(header.HasHeadersWithPrefix("foo"));
  EXPECT_FALSE(header.HasHeadersWithPrefix(""));
}

TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithBalsaFrameProcessInput) {
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "key1: value_1\r\n"
                                           "key1: value_foo\r\n"
                                           "key2:\r\n"
                                           "\r\n");

  EXPECT_FALSE(headers.HasHeader("foo"));
  EXPECT_TRUE(headers.HasHeader("key1"));
  EXPECT_TRUE(headers.HasHeader("key2"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("foo"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("key"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("KEY"));
}

TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithBalsaFrameProcessInput) {
  BalsaHeaders headers = CreateHTTPHeaders(
      true,
      "GET / HTTP/1.0\r\n"
      "key1: value_1\r\n"
      "key1: value_foo\r\n"  // this one cannot be fetched via GetHeader
      "key2: value_2\r\n"
      "key3: value_3\r\n"
      "key4:\r\n"
      "a: value_a\r\n"
      "b: value_b\r\n"
      "\r\n");

  absl::string_view header_key_b_value = headers.GetHeader("b");
  ASSERT_FALSE(header_key_b_value.empty());
  EXPECT_EQ(std::string("value_b"), header_key_b_value);

  absl::string_view header_key_1_value = headers.GetHeader("key1");
  ASSERT_FALSE(header_key_1_value.empty());
  EXPECT_EQ(std::string("value_1"), header_key_1_value);

  absl::string_view header_key_3_value = headers.GetHeader("key3");
  ASSERT_FALSE(header_key_3_value.empty());
  EXPECT_EQ(std::string("value_3"), header_key_3_value);

  absl::string_view header_key_2_value = headers.GetHeader("key2");
  ASSERT_FALSE(header_key_2_value.empty());
  EXPECT_EQ(std::string("value_2"), header_key_2_value);

  absl::string_view header_key_a_value = headers.GetHeader("a");
  ASSERT_FALSE(header_key_a_value.empty());
  EXPECT_EQ(std::string("value_a"), header_key_a_value);

  EXPECT_TRUE(headers.GetHeader("key4").empty());
}

TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithAppendHeader) {
  BalsaHeaders header;

  header.AppendHeader("key1", "value_1");
  // note that this (following) one cannot be found using GetHeader.
  header.AppendHeader("key1", "value_2");
  header.AppendHeader("key2", "value_2");
  header.AppendHeader("key3", "value_3");
  header.AppendHeader("a", "value_a");
  header.AppendHeader("b", "value_b");

  absl::string_view header_key_b_value = header.GetHeader("b");
  absl::string_view header_key_1_value = header.GetHeader("key1");
  absl::string_view header_key_3_value = header.GetHeader("key3");
  absl::string_view header_key_2_value = header.GetHeader("key2");
  absl::string_view header_key_a_value = header.GetHeader("a");

  ASSERT_FALSE(header_key_1_value.empty());
  ASSERT_FALSE(header_key_2_value.empty());
  ASSERT_FALSE(header_key_3_value.empty());
  ASSERT_FALSE(header_key_a_value.empty());
  ASSERT_FALSE(header_key_b_value.empty());

  EXPECT_TRUE(header.HasHeader("key1"));
  EXPECT_TRUE(header.HasHeader("key2"));
  EXPECT_TRUE(header.HasHeader("key3"));
  EXPECT_TRUE(header.HasHeader("a"));
  EXPECT_TRUE(header.HasHeader("b"));

  EXPECT_TRUE(header.HasHeadersWithPrefix("key1"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key2"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key3"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("a"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("b"));

  EXPECT_EQ(std::string("value_1"), header_key_1_value);
  EXPECT_EQ(std::string("value_2"), header_key_2_value);
  EXPECT_EQ(std::string("value_3"), header_key_3_value);
  EXPECT_EQ(std::string("value_a"), header_key_a_value);
  EXPECT_EQ(std::string("value_b"), header_key_b_value);
}

TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithAppendHeader) {
  BalsaHeaders header;

  ASSERT_FALSE(header.HasHeader("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("K"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("ke"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key2"));
  header.AppendHeader("key1", "value_1");
  EXPECT_TRUE(header.HasHeader("key1"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("K"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("ke"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key2"));

  header.AppendHeader("key1", "value_2");
  EXPECT_TRUE(header.HasHeader("key1"));
  EXPECT_FALSE(header.HasHeader("key2"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("k"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("ke"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key2"));
}

TEST(BalsaHeaders, GetHeaderWorksAsExpectedWithHeadersErased) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_1");
  header.AppendHeader("key1", "value_2");
  header.AppendHeader("key2", "value_2");
  header.AppendHeader("key3", "value_3");
  header.AppendHeader("a", "value_a");
  header.AppendHeader("b", "value_b");

  header.erase(header.GetHeaderPosition("key2"));

  absl::string_view header_key_b_value = header.GetHeader("b");
  absl::string_view header_key_1_value = header.GetHeader("key1");
  absl::string_view header_key_3_value = header.GetHeader("key3");
  absl::string_view header_key_2_value = header.GetHeader("key2");
  absl::string_view header_key_a_value = header.GetHeader("a");

  ASSERT_FALSE(header_key_1_value.empty());
  ASSERT_TRUE(header_key_2_value.empty());
  ASSERT_FALSE(header_key_3_value.empty());
  ASSERT_FALSE(header_key_a_value.empty());
  ASSERT_FALSE(header_key_b_value.empty());

  EXPECT_EQ(std::string("value_1"), header_key_1_value);
  EXPECT_EQ(std::string("value_3"), header_key_3_value);
  EXPECT_EQ(std::string("value_a"), header_key_a_value);
  EXPECT_EQ(std::string("value_b"), header_key_b_value);

  // Erasing one makes the next one visible:
  header.erase(header.GetHeaderPosition("key1"));
  header_key_1_value = header.GetHeader("key1");
  ASSERT_FALSE(header_key_1_value.empty());
  EXPECT_EQ(std::string("value_2"), header_key_1_value);

  // Erase both:
  header.erase(header.GetHeaderPosition("key1"));
  ASSERT_TRUE(header.GetHeader("key1").empty());
}

TEST(BalsaHeaders, HasHeaderWorksAsExpectedWithHeadersErased) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_1");
  header.AppendHeader("key2", "value_2a");
  header.AppendHeader("key2", "value_2b");

  ASSERT_TRUE(header.HasHeader("key1"));
  ASSERT_TRUE(header.HasHeadersWithPrefix("key1"));
  ASSERT_TRUE(header.HasHeadersWithPrefix("key2"));
  ASSERT_TRUE(header.HasHeadersWithPrefix("kEY"));
  header.erase(header.GetHeaderPosition("key1"));
  EXPECT_FALSE(header.HasHeader("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key1"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key2"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("kEY"));

  ASSERT_TRUE(header.HasHeader("key2"));
  header.erase(header.GetHeaderPosition("key2"));
  ASSERT_TRUE(header.HasHeader("key2"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key1"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("key2"));
  EXPECT_TRUE(header.HasHeadersWithPrefix("kEY"));
  header.erase(header.GetHeaderPosition("key2"));
  EXPECT_FALSE(header.HasHeader("key2"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key1"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("key2"));
  EXPECT_FALSE(header.HasHeadersWithPrefix("kEY"));
}

TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithNoHeaderLines) {
  BalsaHeaders header;
  EXPECT_FALSE(header.HasNonEmptyHeader("foo"));
  EXPECT_FALSE(header.HasNonEmptyHeader(""));
}

TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithAppendHeader) {
  BalsaHeaders header;

  EXPECT_FALSE(header.HasNonEmptyHeader("key1"));
  header.AppendHeader("key1", "");
  EXPECT_FALSE(header.HasNonEmptyHeader("key1"));

  header.AppendHeader("key1", "value_2");
  EXPECT_TRUE(header.HasNonEmptyHeader("key1"));
  EXPECT_FALSE(header.HasNonEmptyHeader("key2"));
}

TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithHeadersErased) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_1");
  header.AppendHeader("key2", "value_2a");
  header.AppendHeader("key2", "");

  EXPECT_TRUE(header.HasNonEmptyHeader("key1"));
  header.erase(header.GetHeaderPosition("key1"));
  EXPECT_FALSE(header.HasNonEmptyHeader("key1"));

  EXPECT_TRUE(header.HasNonEmptyHeader("key2"));
  header.erase(header.GetHeaderPosition("key2"));
  EXPECT_FALSE(header.HasNonEmptyHeader("key2"));
  header.erase(header.GetHeaderPosition("key2"));
  EXPECT_FALSE(header.HasNonEmptyHeader("key2"));
}

TEST(BalsaHeaders, HasNonEmptyHeaderWorksAsExpectedWithBalsaFrameProcessInput) {
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "key1: value_1\r\n"
                                           "key2:\r\n"
                                           "key3:\r\n"
                                           "key3: value_3\r\n"
                                           "key4:\r\n"
                                           "key4:\r\n"
                                           "key5: value_5\r\n"
                                           "key5:\r\n"
                                           "\r\n");

  EXPECT_FALSE(headers.HasNonEmptyHeader("foo"));
  EXPECT_TRUE(headers.HasNonEmptyHeader("key1"));
  EXPECT_FALSE(headers.HasNonEmptyHeader("key2"));
  EXPECT_TRUE(headers.HasNonEmptyHeader("key3"));
  EXPECT_FALSE(headers.HasNonEmptyHeader("key4"));
  EXPECT_TRUE(headers.HasNonEmptyHeader("key5"));

  headers.erase(headers.GetHeaderPosition("key5"));
  EXPECT_FALSE(headers.HasNonEmptyHeader("key5"));
}

TEST(BalsaHeaders, GetAllOfHeader) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("Key", "value_2,value_3");
  header.AppendHeader("key", "");
  header.AppendHeader("KEY", "value_4");

  std::vector<absl::string_view> result;
  header.GetAllOfHeader("key", &result);
  ASSERT_EQ(4u, result.size());
  EXPECT_EQ("value_1", result[0]);
  EXPECT_EQ("value_2,value_3", result[1]);
  EXPECT_EQ("", result[2]);
  EXPECT_EQ("value_4", result[3]);

  EXPECT_EQ(header.GetAllOfHeader("key"), result);
}

TEST(BalsaHeaders, GetAllOfHeaderDoesWhatItSays) {
  BalsaHeaders header;
  // Multiple values for a given header.
  // Some values appear multiple times
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  header.AppendHeader("key", "");
  header.AppendHeader("key", "value_1");

  ASSERT_NE(header.lines().begin(), header.lines().end());
  std::vector<absl::string_view> out;

  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(4u, out.size());
  EXPECT_EQ("value_1", out[0]);
  EXPECT_EQ("value_2", out[1]);
  EXPECT_EQ("", out[2]);
  EXPECT_EQ("value_1", out[3]);

  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderWithPrefix) {
  BalsaHeaders header;
  header.AppendHeader("foo-Foo", "value_1");
  header.AppendHeader("Foo-bar", "value_2,value_3");
  header.AppendHeader("foo-Foo", "");
  header.AppendHeader("bar", "value_not");
  header.AppendHeader("fOO-fOO", "value_4");

  std::vector<std::pair<absl::string_view, absl::string_view>> result;
  header.GetAllOfHeaderWithPrefix("abc", &result);
  ASSERT_EQ(0u, result.size());

  header.GetAllOfHeaderWithPrefix("foo", &result);
  ASSERT_EQ(4u, result.size());
  EXPECT_EQ("foo-Foo", result[0].first);
  EXPECT_EQ("value_1", result[0].second);
  EXPECT_EQ("Foo-bar", result[1].first);
  EXPECT_EQ("value_2,value_3", result[1].second);
  EXPECT_EQ("", result[2].second);
  EXPECT_EQ("value_4", result[3].second);

  std::vector<std::pair<absl::string_view, absl::string_view>> result2;
  header.GetAllOfHeaderWithPrefix("FoO", &result2);
  ASSERT_EQ(4u, result2.size());
}

TEST(BalsaHeaders, GetAllHeadersWithLimit) {
  BalsaHeaders header;
  header.AppendHeader("foo-Foo", "value_1");
  header.AppendHeader("Foo-bar", "value_2,value_3");
  header.AppendHeader("foo-Foo", "");
  header.AppendHeader("bar", "value_4");
  header.AppendHeader("fOO-fOO", "value_5");

  std::vector<std::pair<absl::string_view, absl::string_view>> result;
  header.GetAllHeadersWithLimit(&result, 4);
  ASSERT_EQ(4u, result.size());
  EXPECT_EQ("foo-Foo", result[0].first);
  EXPECT_EQ("value_1", result[0].second);
  EXPECT_EQ("Foo-bar", result[1].first);
  EXPECT_EQ("value_2,value_3", result[1].second);
  EXPECT_EQ("", result[2].second);
  EXPECT_EQ("value_4", result[3].second);

  std::vector<std::pair<absl::string_view, absl::string_view>> result2;
  header.GetAllHeadersWithLimit(&result2, -1);
  ASSERT_EQ(5u, result2.size());
}

TEST(BalsaHeaders, RangeFor) {
  BalsaHeaders header;
  // Multiple values for a given header.
  // Some values appear multiple times
  header.AppendHeader("key1", "value_1a");
  header.AppendHeader("key1", "value_1b");
  header.AppendHeader("key2", "");
  header.AppendHeader("key3", "value_3");

  std::vector<std::pair<absl::string_view, absl::string_view>> out;
  for (const auto& line : header.lines()) {
    out.push_back(line);
  }
  const std::vector<std::pair<absl::string_view, absl::string_view>> expected =
      {{"key1", "value_1a"},
       {"key1", "value_1b"},
       {"key2", ""},
       {"key3", "value_3"}};
  EXPECT_EQ(expected, out);
}

TEST(BalsaHeaders, GetAllOfHeaderWithNonExistentKey) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  std::vector<absl::string_view> out;

  header.GetAllOfHeader("key_non_existent", &out);
  ASSERT_EQ(0u, out.size());

  EXPECT_EQ(header.GetAllOfHeader("key_non_existent"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation1) {
  BalsaHeaders header;
  header.AppendHeader("key", "");
  header.AppendHeader("key", "");
  header.AppendHeader("key", "v1");
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("", out[0]);
  EXPECT_EQ("", out[1]);
  EXPECT_EQ("v1", out[2]);

  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation2) {
  BalsaHeaders header;
  header.AppendHeader("key", "");
  header.AppendHeader("key", "v1");
  header.AppendHeader("key", "");
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("", out[0]);
  EXPECT_EQ("v1", out[1]);
  EXPECT_EQ("", out[2]);

  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation3) {
  BalsaHeaders header;
  header.AppendHeader("key", "");
  header.AppendHeader("key", "v1");
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(2u, out.size());
  EXPECT_EQ("", out[0]);
  EXPECT_EQ("v1", out[1]);

  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderEmptyValVariation4) {
  BalsaHeaders header;
  header.AppendHeader("key", "v1");
  header.AppendHeader("key", "");
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(2u, out.size());
  EXPECT_EQ("v1", out[0]);
  EXPECT_EQ("", out[1]);

  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderWithAppendHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  std::vector<absl::string_view> out;

  header.GetAllOfHeader("key_new", &out);
  ASSERT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("key_new"), out);

  // Add key_new to the header
  header.AppendHeader("key_new", "value_3");
  header.GetAllOfHeader("key_new", &out);
  ASSERT_EQ(1u, out.size());
  EXPECT_EQ("value_3", out[0]);
  EXPECT_EQ(header.GetAllOfHeader("key_new"), out);

  // Get the keys that are not modified
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("value_1", out[1]);
  EXPECT_EQ("value_2", out[2]);
  EXPECT_THAT(header.GetAllOfHeader("key"), ElementsAre("value_1", "value_2"));
}

TEST(BalsaHeaders, GetAllOfHeaderWithRemoveHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  header.AppendHeader("a", "va");

  header.RemoveAllOfHeader("key");
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("key"), out);

  header.GetAllOfHeader("a", &out);
  ASSERT_EQ(1u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("a"), out);

  out.clear();
  header.RemoveAllOfHeader("a");
  header.GetAllOfHeader("a", &out);
  ASSERT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("a"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderWithRemoveNonExistentHeaders) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("Accept-Encoding", "deflate,compress");
  EXPECT_EQ(0u, headers.RemoveValue("Accept-Encoding", "gzip(gfe)"));
  std::string accept_encoding_vals =
      headers.GetAllOfHeaderAsString("Accept-Encoding");
  EXPECT_EQ("deflate,compress", accept_encoding_vals);
}

TEST(BalsaHeaders, GetAllOfHeaderWithEraseHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  header.AppendHeader("a", "va");

  std::vector<absl::string_view> out;

  header.erase(header.GetHeaderPosition("key"));
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(1u, out.size());
  EXPECT_EQ("value_2", out[0]);
  EXPECT_EQ(header.GetAllOfHeader("key"), out);

  out.clear();
  header.erase(header.GetHeaderPosition("key"));
  header.GetAllOfHeader("key", &out);
  ASSERT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("key"), out);

  out.clear();
  header.GetAllOfHeader("a", &out);
  ASSERT_EQ(1u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("a"), out);

  out.clear();
  header.erase(header.GetHeaderPosition("a"));
  header.GetAllOfHeader("a", &out);
  ASSERT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderWithNoHeaderLines) {
  BalsaHeaders header;
  std::vector<absl::string_view> out;
  header.GetAllOfHeader("key", &out);
  EXPECT_EQ(0u, out.size());
  EXPECT_EQ(header.GetAllOfHeader("key"), out);
}

TEST(BalsaHeaders, GetAllOfHeaderDoesWhatItSaysForVariousKeys) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_11");
  header.AppendHeader("key2", "value_21");
  header.AppendHeader("key1", "value_12");
  header.AppendHeader("key2", "value_22");

  std::vector<absl::string_view> out;

  header.GetAllOfHeader("key1", &out);
  EXPECT_EQ("value_11", out[0]);
  EXPECT_EQ("value_12", out[1]);
  EXPECT_EQ(header.GetAllOfHeader("key1"), out);

  header.GetAllOfHeader("key2", &out);
  EXPECT_EQ("value_21", out[2]);
  EXPECT_EQ("value_22", out[3]);
  EXPECT_THAT(header.GetAllOfHeader("key2"),
              ElementsAre("value_21", "value_22"));
}

TEST(BalsaHeaders, GetAllOfHeaderWithBalsaFrameProcessInput) {
  BalsaHeaders header = CreateHTTPHeaders(true,
                                          "GET / HTTP/1.0\r\n"
                                          "key1: value_1\r\n"
                                          "key1: value_foo\r\n"
                                          "key2: value_2\r\n"
                                          "a: value_a\r\n"
                                          "key2: \r\n"
                                          "b: value_b\r\n"
                                          "\r\n");

  std::vector<absl::string_view> out;
  int index = 0;
  header.GetAllOfHeader("key1", &out);
  EXPECT_EQ("value_1", out[index++]);
  EXPECT_EQ("value_foo", out[index++]);
  EXPECT_EQ(header.GetAllOfHeader("key1"), out);

  header.GetAllOfHeader("key2", &out);
  EXPECT_EQ("value_2", out[index++]);
  EXPECT_EQ("", out[index++]);
  EXPECT_THAT(header.GetAllOfHeader("key2"), ElementsAre("value_2", ""));

  header.GetAllOfHeader("a", &out);
  EXPECT_EQ("value_a", out[index++]);
  EXPECT_THAT(header.GetAllOfHeader("a"), ElementsAre("value_a"));

  header.GetAllOfHeader("b", &out);
  EXPECT_EQ("value_b", out[index++]);
  EXPECT_THAT(header.GetAllOfHeader("b"), ElementsAre("value_b"));
}

TEST(BalsaHeaders, GetAllOfHeaderIncludeRemovedDoesWhatItSays) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_11");
  header.AppendHeader("key2", "value_21");
  header.AppendHeader("key1", "value_12");
  header.AppendHeader("key2", "value_22");
  header.AppendHeader("key1", "");

  std::vector<absl::string_view> out;
  header.GetAllOfHeaderIncludeRemoved("key1", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("value_11", out[0]);
  EXPECT_EQ("value_12", out[1]);
  EXPECT_EQ("", out[2]);
  header.GetAllOfHeaderIncludeRemoved("key2", &out);
  ASSERT_EQ(5u, out.size());
  EXPECT_EQ("value_21", out[3]);
  EXPECT_EQ("value_22", out[4]);

  header.erase(header.GetHeaderPosition("key1"));
  out.clear();
  header.GetAllOfHeaderIncludeRemoved("key1", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("value_12", out[0]);
  EXPECT_EQ("", out[1]);
  EXPECT_EQ("value_11", out[2]);
  header.GetAllOfHeaderIncludeRemoved("key2", &out);
  ASSERT_EQ(5u, out.size());
  EXPECT_EQ("value_21", out[3]);
  EXPECT_EQ("value_22", out[4]);

  header.RemoveAllOfHeader("key1");
  out.clear();
  header.GetAllOfHeaderIncludeRemoved("key1", &out);
  ASSERT_EQ(3u, out.size());
  EXPECT_EQ("value_11", out[0]);
  EXPECT_EQ("value_12", out[1]);
  EXPECT_EQ("", out[2]);
  header.GetAllOfHeaderIncludeRemoved("key2", &out);
  ASSERT_EQ(5u, out.size());
  EXPECT_EQ("value_21", out[3]);
  EXPECT_EQ("value_22", out[4]);

  header.Clear();
  out.clear();
  header.GetAllOfHeaderIncludeRemoved("key1", &out);
  ASSERT_EQ(0u, out.size());
  header.GetAllOfHeaderIncludeRemoved("key2", &out);
  ASSERT_EQ(0u, out.size());
}

TEST(BalsaHeaders, GetAllOfHeaderIncludeRemovedWithNonExistentKey) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  std::vector<absl::string_view> out;
  header.GetAllOfHeaderIncludeRemoved("key_non_existent", &out);
  ASSERT_EQ(0u, out.size());
}

TEST(BalsaHeaders, GetIteratorForKeyDoesWhatItSays) {
  BalsaHeaders header;
  // Multiple values for a given header.
  // Some values appear multiple times
  header.AppendHeader("key", "value_1");
  header.AppendHeader("Key", "value_2");
  header.AppendHeader("key", "");
  header.AppendHeader("KEY", "value_1");

  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key");
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key
"""


```