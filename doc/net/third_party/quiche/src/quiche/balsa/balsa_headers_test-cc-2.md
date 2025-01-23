Response:
The user is asking for an analysis of a C++ source code file related to HTTP header manipulation. This is part 3 of a 5-part series, so I should focus on the functionalities demonstrated in this specific code snippet.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The code primarily consists of unit tests for the `BalsaHeaders` class. The tests cover various operations related to getting iterators for specific header keys.

2. **List the Covered Operations:**  Go through each `TEST` function and summarize its purpose. This includes:
    * `GetIteratorForKey`: Basic retrieval of the first occurrence.
    * `GetIteratorForKeyCaseInsensitive`: Case-insensitive retrieval.
    * `GetIteratorForKeyMultipleValues`: Handling multiple headers with the same key.
    * `GetIteratorForKeyWithNonExistentKey`: Handling cases where the key doesn't exist.
    * `GetIteratorForKeyWithAppendHeaders`: Testing behavior after adding new headers.
    * `GetIteratorForKeyWithRemoveHeaders`: Testing behavior after removing headers.
    * `GetIteratorForKeyWithEraseHeaders`: Testing behavior after erasing headers.
    * `GetIteratorForKeyWithNoHeaderLines`: Handling empty headers.
    * `GetIteratorForKeyWithBalsaFrameProcessInput`: Testing with headers parsed from a string.

3. **Relate to JavaScript (If Applicable):** Consider if these operations have equivalents in JavaScript. HTTP headers are fundamental to web communication, so there's a strong connection. JavaScript's `Headers` API in `fetch` is a direct parallel. Provide concrete examples.

4. **Logical Reasoning (Input/Output):** For each test case, identify the setup (input - what headers are added) and the expected outcome (output - what the iterator should point to). Focus on the key assertions (`EXPECT_EQ`, `EXPECT_NE`).

5. **Common Usage Errors:** Think about how developers might misuse the `BalsaHeaders` class or the concepts demonstrated in the tests. Misspelling keys, assuming case sensitivity when it's not, or incorrect iterator usage are potential issues. Provide illustrative examples.

6. **Debugging Scenario:**  Construct a plausible scenario where a developer might need to examine this code. Start with a user action in a browser and trace it down to the network layer and header processing.

7. **Summarize the Functionality:** Based on the analysis of the individual tests, provide a concise overview of the main capabilities demonstrated in this code snippet. Emphasize the iterator-based access and manipulation of headers.

8. **Address the "Part 3" Instruction:**  Explicitly state that this analysis is based on the provided code snippet (part 3) and might not encompass all features of the `BalsaHeaders` class.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the C++ API.
* **Correction:** Remember the prompt asks about the relation to JavaScript, so ensure to include that aspect.
* **Initial thought:**  Provide very technical explanations of the C++ iterators.
* **Refinement:**  Balance the technical details with a higher-level explanation of what the tests are verifying (e.g., "correctly finds the header").
* **Initial thought:**  Just list the test names as functionalities.
* **Refinement:**  Describe *what* each test is testing (e.g., "retrieving an iterator for a key that appears multiple times").
* **Considered:** Should I explain the underlying implementation of `BalsaHeaders`?
* **Decision:** No, the prompt focuses on the *functionality* demonstrated by the tests, not the internal implementation details.

By following this structured approach, the generated response becomes comprehensive, addresses all parts of the prompt, and provides useful information about the code.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc` 文件的第三部分，主要功能是测试 `BalsaHeaders` 类中关于获取和操作 HTTP 头部迭代器的相关方法。具体来说，这部分代码着重测试了通过键（key）来获取头部行的迭代器的各种场景。

**主要功能归纳:**

这部分测试用例主要验证了 `BalsaHeaders` 类中以下与获取头部迭代器相关的功能：

* **`GetIteratorForKey(key)`:**  根据给定的键来获取指向第一个匹配该键的头部行的迭代器。
* **`lines(key)`:** 获取一个包含所有匹配给定键的头部行的范围（begin 和 end 迭代器）。
* **迭代器的正确性:**  验证返回的迭代器是否指向预期的头部行，以及在迭代过程中是否正确移动到下一个头部行。
* **大小写敏感性:** 验证在默认情况下，`GetIteratorForKey` 的键查找是大小写敏感的。
* **处理不存在的键:** 验证当请求一个不存在的键时，`GetIteratorForKey` 是否返回预期的结束迭代器。
* **在头部添加、删除、擦除后的行为:** 验证在对头部进行添加、删除或擦除操作后，`GetIteratorForKey` 是否仍然能正确找到剩余的头部行。
* **处理解析后的头部:** 验证从已解析的 HTTP 报文中获取头部迭代器的功能。
* **与 `RemoveAllOfHeader` 和 `erase` 的交互:** 验证在删除或擦除头部行后，获取迭代器是否能正确反映这些更改。
* **处理空头部:** 验证在没有头部行的情况下，获取迭代器的行为。

**与 JavaScript 的功能关系 (举例说明):**

HTTP 头部是 Web 通信的基础，因此 `BalsaHeaders` 的功能与 JavaScript 在处理网络请求和响应时使用的 `Headers` API 有着直接的联系。

**举例说明:**

在 JavaScript 的 `fetch` API 中，可以使用 `Headers` 对象来管理 HTTP 头部。`Headers` 对象提供了一些方法来获取和操作头部，例如 `get(name)` 获取指定名称的第一个头部值，`getAll(name)` 获取指定名称的所有头部值。

`BalsaHeaders::GetIteratorForKey` 的功能可以类比于 JavaScript 中遍历具有相同名称的多个头部值。虽然 JavaScript 的 `Headers` API 没有直接提供返回迭代器的方法，但我们可以通过 `getAll(name)` 获取所有值，然后手动遍历：

```javascript
// JavaScript 示例
fetch('https://example.com', {
  headers: {
    'Set-Cookie': 'cookie1=value1',
    'Set-Cookie': 'cookie2=value2'
  }
}).then(response => {
  const headers = response.headers;
  const setCookieValues = headers.getAll('Set-Cookie');
  console.log(setCookieValues); // 输出: ["cookie1=value1", "cookie2=value2"]
});
```

在 `BalsaHeaders` 中，`GetIteratorForKey("Set-Cookie")` 配合迭代器可以实现类似的功能，逐个访问 `Set-Cookie` 头部的值。

**逻辑推理 (假设输入与输出):**

**假设输入:** 一个 `BalsaHeaders` 对象，包含以下头部：

```
Key: value_1
Key: value_2
```

**测试用例:** `TEST(BalsaHeaders, GetIteratorForKeyMultipleValues)`

**假设输入:** 调用 `header.GetIteratorForKey("Key")`

**预期输出:**

* 第一次调用迭代器的 `operator*()` 应该返回 `std::pair<absl::string_view, absl::string_view>("Key", "value_1")`。
* 第一次递增迭代器后，再次调用 `operator*()` 应该返回 `std::pair<absl::string_view, absl::string_view>("Key", "value_2")`。
* 第二次递增迭代器后，迭代器应该等于 `header.lines().end()`。

**用户或编程常见的使用错误 (举例说明):**

1. **假设头部键是唯一的:**  用户可能错误地认为一个头部键只会对应一个值，而没有考虑到 HTTP 允许同一个键出现多次。如果他们只使用 `GetIteratorForKey` 并只访问返回的第一个迭代器，他们可能会错过后续相同键的头部值。

   ```c++
   // 错误用法示例
   BalsaHeaders header;
   header.AppendHeader("key", "value1");
   header.AppendHeader("key", "value2");

   auto it = header.GetIteratorForKey("key");
   if (it != header.lines().end()) {
     // 用户可能只处理了 "value1"，而忽略了 "value2"
     std::cout << it->second << std::endl;
   }
   ```

2. **大小写敏感性混淆:**  用户可能没有意识到 `GetIteratorForKey` 默认是大小写敏感的。他们可能使用错误的大小写来查找头部，导致找不到预期的头部。

   ```c++
   // 错误用法示例
   BalsaHeaders header;
   header.AppendHeader("Content-Type", "application/json");

   auto it = header.GetIteratorForKey("content-type"); // 注意大小写
   if (it == header.lines().end()) {
     std::cout << "Content-Type not found" << std::endl; // 可能会输出此消息
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chromium 浏览器浏览网页时遇到了与 HTTP 头部处理相关的问题，例如：

1. **用户在浏览器中访问一个网页 (例如 `https://example.com`)。**
2. **浏览器发起 HTTP 请求。**
3. **Chromium 网络栈处理该请求。**
4. **服务器返回 HTTP 响应，其中包含一系列头部。**
5. **`BalsaFrame` 或类似的类负责解析 HTTP 响应报文，并将头部信息存储在 `BalsaHeaders` 对象中。**
6. **在处理响应头部时，可能需要根据特定的头部键来查找或操作头部值。**
7. **开发人员在调试过程中，可能会检查 `BalsaHeaders` 对象中头部的信息，并尝试理解 `GetIteratorForKey` 等方法的行为，以排查头部处理逻辑中的错误。**

这段测试代码就是为了确保 `BalsaHeaders` 类的这些关键功能能够正确运行，从而保证 Chromium 网络栈在处理 HTTP 头部时的准确性和可靠性。如果测试失败，就意味着在获取或操作头部迭代器时存在 bug，需要进一步调查。

**这是第3部分，共5部分，请归纳一下它的功能:**

这部分（第 3 部分）的 `balsa_headers_test.cc` 文件主要专注于测试 `BalsaHeaders` 类中**通过键来获取 HTTP 头部行的迭代器**的功能。它详细验证了 `GetIteratorForKey` 和相关方法在各种场景下的正确性，包括处理单个和多个同名头部、大小写敏感性、添加/删除/修改头部后的行为，以及与底层解析器的集成。 简而言之，这部分测试确保了开发者能够可靠地通过键来访问和遍历 HTTP 头部。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
", key_it->first);
  EXPECT_EQ("value_1", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("Key", key_it->first);
  EXPECT_EQ("value_2", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key", key_it->first);
  EXPECT_EQ("", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("KEY", key_it->first);
  EXPECT_EQ("value_1", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
}

TEST(BalsaHeaders, GetIteratorForKeyWithNonExistentKey) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");

  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key_non_existent");
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
  const auto lines = header.lines("key_non_existent");
  EXPECT_EQ(lines.begin(), header.lines().end());
  EXPECT_EQ(lines.end(), header.header_lines_key_end());
}

TEST(BalsaHeaders, GetIteratorForKeyWithAppendHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");

  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key_new");
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  // Add key_new to the header
  header.AppendHeader("key_new", "value_3");
  key_it = header.GetIteratorForKey("key_new");
  const auto lines1 = header.lines("key_new");
  EXPECT_EQ(lines1.begin(), key_it);
  EXPECT_EQ(lines1.end(), header.header_lines_key_end());

  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key_new", key_it->first);
  EXPECT_EQ("value_3", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  // Get the keys that are not modified
  key_it = header.GetIteratorForKey("key");
  const auto lines2 = header.lines("key");
  EXPECT_EQ(lines2.begin(), key_it);
  EXPECT_EQ(lines2.end(), header.header_lines_key_end());
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key", key_it->first);
  EXPECT_EQ("value_1", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key", key_it->first);
  EXPECT_EQ("value_2", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
}

TEST(BalsaHeaders, GetIteratorForKeyWithRemoveHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  header.AppendHeader("a", "va");

  header.RemoveAllOfHeader("a");
  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key");
  EXPECT_NE(header.lines().end(), key_it);
  const auto lines1 = header.lines("key");
  EXPECT_EQ(lines1.begin(), key_it);
  EXPECT_EQ(lines1.end(), header.header_lines_key_end());
  EXPECT_EQ("value_1", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key", key_it->first);
  EXPECT_EQ("value_2", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  // Check that a typical loop works properly.
  for (BalsaHeaders::const_header_lines_key_iterator it =
           header.GetIteratorForKey("key");
       it != header.lines().end(); ++it) {
    EXPECT_EQ("key", it->first);
  }
}

TEST(BalsaHeaders, GetIteratorForKeyWithEraseHeaders) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  header.AppendHeader("a", "va");
  header.erase(header.GetHeaderPosition("key"));

  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key");
  EXPECT_NE(header.lines().end(), key_it);
  const auto lines1 = header.lines("key");
  EXPECT_EQ(lines1.begin(), key_it);
  EXPECT_EQ(lines1.end(), header.header_lines_key_end());
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key", key_it->first);
  EXPECT_EQ("value_2", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  header.erase(header.GetHeaderPosition("key"));
  key_it = header.GetIteratorForKey("key");
  const auto lines2 = header.lines("key");
  EXPECT_EQ(lines2.begin(), key_it);
  EXPECT_EQ(lines2.end(), header.header_lines_key_end());
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  key_it = header.GetIteratorForKey("a");
  const auto lines3 = header.lines("a");
  EXPECT_EQ(lines3.begin(), key_it);
  EXPECT_EQ(lines3.end(), header.header_lines_key_end());
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("a", key_it->first);
  EXPECT_EQ("va", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  header.erase(header.GetHeaderPosition("a"));
  key_it = header.GetIteratorForKey("a");
  const auto lines4 = header.lines("a");
  EXPECT_EQ(lines4.begin(), key_it);
  EXPECT_EQ(lines4.end(), header.header_lines_key_end());
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
}

TEST(BalsaHeaders, GetIteratorForKeyWithNoHeaderLines) {
  BalsaHeaders header;
  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("key");
  const auto lines = header.lines("key");
  EXPECT_EQ(lines.begin(), key_it);
  EXPECT_EQ(lines.end(), header.header_lines_key_end());
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
}

TEST(BalsaHeaders, GetIteratorForKeyWithBalsaFrameProcessInput) {
  BalsaHeaders header = CreateHTTPHeaders(true,
                                          "GET / HTTP/1.0\r\n"
                                          "key1: value_1\r\n"
                                          "Key1: value_foo\r\n"
                                          "key2: value_2\r\n"
                                          "a: value_a\r\n"
                                          "key2: \r\n"
                                          "b: value_b\r\n"
                                          "\r\n");

  BalsaHeaders::const_header_lines_key_iterator key_it =
      header.GetIteratorForKey("Key1");
  const auto lines1 = header.lines("Key1");
  EXPECT_EQ(lines1.begin(), key_it);
  EXPECT_EQ(lines1.end(), header.header_lines_key_end());
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key1", key_it->first);
  EXPECT_EQ("value_1", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("Key1", key_it->first);
  EXPECT_EQ("value_foo", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  key_it = header.GetIteratorForKey("key2");
  EXPECT_NE(header.lines().end(), key_it);
  const auto lines2 = header.lines("key2");
  EXPECT_EQ(lines2.begin(), key_it);
  EXPECT_EQ(lines2.end(), header.header_lines_key_end());
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key2", key_it->first);
  EXPECT_EQ("value_2", key_it->second);
  ++key_it;
  EXPECT_NE(header.lines().end(), key_it);
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("key2", key_it->first);
  EXPECT_EQ("", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  key_it = header.GetIteratorForKey("a");
  EXPECT_NE(header.lines().end(), key_it);
  const auto lines3 = header.lines("a");
  EXPECT_EQ(lines3.begin(), key_it);
  EXPECT_EQ(lines3.end(), header.header_lines_key_end());
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("a", key_it->first);
  EXPECT_EQ("value_a", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);

  key_it = header.GetIteratorForKey("b");
  EXPECT_NE(header.lines().end(), key_it);
  const auto lines4 = header.lines("b");
  EXPECT_EQ(lines4.begin(), key_it);
  EXPECT_EQ(lines4.end(), header.header_lines_key_end());
  EXPECT_NE(header.header_lines_key_end(), key_it);
  EXPECT_EQ("b", key_it->first);
  EXPECT_EQ("value_b", key_it->second);
  ++key_it;
  EXPECT_EQ(header.lines().end(), key_it);
  EXPECT_EQ(header.header_lines_key_end(), key_it);
}

TEST(BalsaHeaders, GetAllOfHeaderAsStringDoesWhatItSays) {
  BalsaHeaders header;
  // Multiple values for a given header.
  // Some values appear multiple times
  header.AppendHeader("key", "value_1");
  header.AppendHeader("Key", "value_2");
  header.AppendHeader("key", "");
  header.AppendHeader("KEY", "value_1");

  std::string result = header.GetAllOfHeaderAsString("key");
  EXPECT_EQ("value_1,value_2,,value_1", result);
}

TEST(BalsaHeaders, RemoveAllOfHeaderDoesWhatItSays) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  ASSERT_NE(header.lines().begin(), header.lines().end());
  header.RemoveAllOfHeader("key");
  ASSERT_EQ(header.lines().begin(), header.lines().end());
}

TEST(BalsaHeaders,
     RemoveAllOfHeaderDoesWhatItSaysEvenWhenThingsHaveBeenErased) {
  BalsaHeaders header;
  header.AppendHeader("key1", "value_1");
  header.AppendHeader("key1", "value_2");
  header.AppendHeader("key2", "value_3");
  header.AppendHeader("key1", "value_4");
  header.AppendHeader("key2", "value_5");
  header.AppendHeader("key1", "value_6");
  ASSERT_NE(header.lines().begin(), header.lines().end());

  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ++chli;
  ++chli;
  ++chli;
  header.erase(chli);

  chli = header.lines().begin();
  ++chli;
  header.erase(chli);

  header.RemoveAllOfHeader("key1");
  for (const auto& line : header.lines()) {
    EXPECT_NE(std::string("key1"), line.first);
  }
}

TEST(BalsaHeaders, RemoveAllOfHeaderDoesNothingWhenNoKeyOfThatNameExists) {
  BalsaHeaders header;
  header.AppendHeader("key", "value_1");
  header.AppendHeader("key", "value_2");
  ASSERT_NE(header.lines().begin(), header.lines().end());
  header.RemoveAllOfHeader("foo");
  int num_found = 0;
  for (const auto& line : header.lines()) {
    ++num_found;
    EXPECT_EQ(absl::string_view("key"), line.first);
  }
  EXPECT_EQ(2, num_found);
  EXPECT_NE(header.lines().begin(), header.lines().end());
}

TEST(BalsaHeaders, WriteHeaderEndingToBuffer) {
  BalsaHeaders header;
  SimpleBuffer simple_buffer;
  header.WriteHeaderEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq("\r\n"));
}

TEST(BalsaHeaders, WriteToBufferDoesntCrashWithUninitializedHeader) {
  BalsaHeaders header;
  SimpleBuffer simple_buffer;
  header.WriteHeaderAndEndingToBuffer(&simple_buffer);
}

TEST(BalsaHeaders, WriteToBufferWorksWithBalsaHeadersParsedByFramer) {
  std::string input =
      "GET / HTTP/1.0\r\n"
      "key_with_value: value\r\n"
      "key_with_continuation_value: \r\n"
      " with continuation\r\n"
      "key_with_two_continuation_value: \r\n"
      " continuation 1\r\n"
      " continuation 2\r\n"
      "a: foo    \r\n"
      "b-s:\n"
      " bar\t\n"
      "foo: \r\n"
      "bazzzzzzzleriffic!: snaps\n"
      "\n";
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "key_with_value: value\r\n"
      "key_with_continuation_value: with continuation\r\n"
      "key_with_two_continuation_value: continuation 1\r\n"
      " continuation 2\r\n"
      "a: foo\r\n"
      "b-s: bar\r\n"
      "foo: \r\n"
      "bazzzzzzzleriffic!: snaps\r\n"
      "\r\n";

  BalsaHeaders headers = CreateHTTPHeaders(true, input);
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders,
     WriteToBufferWorksWithBalsaHeadersParsedByFramerTabContinuations) {
  std::string input =
      "GET / HTTP/1.0\r\n"
      "key_with_value: value\r\n"
      "key_with_continuation_value: \r\n"
      "\twith continuation\r\n"
      "key_with_two_continuation_value: \r\n"
      "\tcontinuation 1\r\n"
      "\tcontinuation 2\r\n"
      "a: foo    \r\n"
      "b-s:\n"
      "\tbar\t\n"
      "foo: \r\n"
      "bazzzzzzzleriffic!: snaps\n"
      "\n";
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "key_with_value: value\r\n"
      "key_with_continuation_value: with continuation\r\n"
      "key_with_two_continuation_value: continuation 1\r\n"
      "\tcontinuation 2\r\n"
      "a: foo\r\n"
      "b-s: bar\r\n"
      "foo: \r\n"
      "bazzzzzzzleriffic!: snaps\r\n"
      "\r\n";

  BalsaHeaders headers = CreateHTTPHeaders(true, input);
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, WriteToBufferWorksWhenFirstlineSetThroughHeaders) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "\r\n";
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, WriteToBufferWorksWhenSetThroughHeaders) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key 2", "value\n 2");
  headers.AppendHeader("key\n 3", "value3");
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "key1: value1\r\n"
      "key 2: value\n"
      " 2\r\n"
      "key\n"
      " 3: value3\r\n"
      "\r\n";
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, WriteToBufferWorkWhensOnlyLinesSetThroughHeaders) {
  BalsaHeaders headers;
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key 2", "value\n 2");
  headers.AppendHeader("key\n 3", "value3");
  std::string expected =
      "\r\n"
      "key1: value1\r\n"
      "key 2: value\n"
      " 2\r\n"
      "key\n"
      " 3: value3\r\n"
      "\r\n";
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, WriteToBufferWorksWhenSetThroughHeadersWithElementsErased) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key 2", "value\n 2");
  headers.AppendHeader("key\n 3", "value3");
  headers.RemoveAllOfHeader("key1");
  headers.RemoveAllOfHeader("key\n 3");
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "key 2: value\n"
      " 2\r\n"
      "\r\n";
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, WriteToBufferWithManuallyAppendedHeaderLine) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key 2", "value\n 2");
  std::string expected =
      "GET / HTTP/1.0\r\n"
      "key1: value1\r\n"
      "key 2: value\n"
      " 2\r\n"
      "key 3: value 3\r\n"
      "\r\n";

  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteToBuffer(&simple_buffer);
  headers.WriteHeaderLineToBuffer(&simple_buffer, "key 3", "value 3",
                                  BalsaHeaders::CaseOption::kNoModification);
  headers.WriteHeaderEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected));
  EXPECT_EQ(expected_write_buffer_size + 16,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
}

TEST(BalsaHeaders, DumpToStringEmptyHeaders) {
  BalsaHeaders headers;
  std::string headers_str;
  headers.DumpToString(&headers_str);
  EXPECT_EQ("\n <empty header>\n", headers_str);
}

TEST(BalsaHeaders, DumpToStringParsedHeaders) {
  std::string input =
      "GET / HTTP/1.0\r\n"
      "Header1: value\r\n"
      "Header2: value\r\n"
      "\r\n";
  std::string output =
      "\n"
      " GET / HTTP/1.0\n"
      " Header1: value\n"
      " Header2: value\n";

  BalsaHeaders headers = CreateHTTPHeaders(true, input);
  std::string headers_str;
  headers.DumpToString(&headers_str);
  EXPECT_EQ(output, headers_str);
  EXPECT_TRUE(headers.FramerIsDoneWriting());
}

TEST(BalsaHeaders, DumpToStringPartialHeaders) {
  BalsaHeaders headers;
  BalsaFrame balsa_frame;
  balsa_frame.set_is_request(true);
  balsa_frame.set_balsa_headers(&headers);
  std::string input =
      "GET / HTTP/1.0\r\n"
      "Header1: value\r\n"
      "Header2: value\r\n";
  std::string output = absl::StrFormat("\n <incomplete header len: %d>\n ",
                                       static_cast<int>(input.size()));
  output += input;
  output += '\n';

  ASSERT_EQ(input.size(), balsa_frame.ProcessInput(input.data(), input.size()));
  ASSERT_FALSE(balsa_frame.MessageFullyRead());
  std::string headers_str;
  headers.DumpToString(&headers_str);
  EXPECT_EQ(output, headers_str);
  EXPECT_FALSE(headers.FramerIsDoneWriting());
}

TEST(BalsaHeaders, DumpToStringParsingNonHeadersData) {
  BalsaHeaders headers;
  BalsaFrame balsa_frame;
  balsa_frame.set_is_request(true);
  balsa_frame.set_balsa_headers(&headers);
  std::string input =
      "This is not a header. "
      "Just some random data to simulate mismatch.";
  std::string output = absl::StrFormat("\n <incomplete header len: %d>\n ",
                                       static_cast<int>(input.size()));
  output += input;
  output += '\n';

  ASSERT_EQ(input.size(), balsa_frame.ProcessInput(input.data(), input.size()));
  ASSERT_FALSE(balsa_frame.MessageFullyRead());
  std::string headers_str;
  headers.DumpToString(&headers_str);
  EXPECT_EQ(output, headers_str);
}

TEST(BalsaHeaders, Clear) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key 2", "value\n 2");
  headers.AppendHeader("key\n 3", "value3");
  headers.RemoveAllOfHeader("key1");
  headers.RemoveAllOfHeader("key\n 3");
  headers.Clear();
  EXPECT_TRUE(headers.first_line().empty());
  EXPECT_EQ(headers.lines().begin(), headers.lines().end());
  EXPECT_TRUE(headers.IsEmpty());
}

TEST(BalsaHeaders,
     TestSetFromStringPiecesWithInitialFirstlineInHeaderStreamAndNewToo) {
  BalsaHeaders headers = CreateHTTPHeaders(false,
                                           "HTTP/1.1 200 reason phrase\r\n"
                                           "content-length: 0\r\n"
                                           "\r\n");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));

  headers.SetResponseFirstline("HTTP/1.0", 404, "a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
  EXPECT_THAT(headers.response_code(), StrEq("404"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(404));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("a reason"));
  EXPECT_THAT(headers.first_line(), StrEq("HTTP/1.0 404 a reason"));
}

TEST(BalsaHeaders,
     TestSetFromStringPiecesWithInitialFirstlineInHeaderStreamButNotNew) {
  BalsaHeaders headers = CreateHTTPHeaders(false,
                                           "HTTP/1.1 200 reason phrase\r\n"
                                           "content-length: 0\r\n"
                                           "\r\n");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));

  headers.SetResponseFirstline("HTTP/1.000", 404000,
                               "supercalifragilisticexpealidocious");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.000"));
  EXPECT_THAT(headers.response_code(), StrEq("404000"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(404000));
  EXPECT_THAT(headers.response_reason_phrase(),
              StrEq("supercalifragilisticexpealidocious"));
  EXPECT_THAT(headers.first_line(),
              StrEq("HTTP/1.000 404000 supercalifragilisticexpealidocious"));
}

TEST(BalsaHeaders,
     TestSetFromStringPiecesWithFirstFirstlineInHeaderStreamButNotNew2) {
  SCOPED_TRACE(
      "This test tests the codepath where the new firstline is"
      " too large to fit within the space used by the original"
      " firstline, but large enuogh to space in the free space"
      " available in both firstline plus the space made available"
      " with deleted header lines (specifically, the first one");
  BalsaHeaders headers = CreateHTTPHeaders(
      false,
      "HTTP/1.1 200 reason phrase\r\n"
      "a: 0987123409871234078130948710938471093827401983740198327401982374\r\n"
      "content-length: 0\r\n"
      "\r\n");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));

  headers.erase(headers.lines().begin());
  headers.SetResponseFirstline("HTTP/1.000", 404000,
                               "supercalifragilisticexpealidocious");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.000"));
  EXPECT_THAT(headers.response_code(), StrEq("404000"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(404000));
  EXPECT_THAT(headers.response_reason_phrase(),
              StrEq("supercalifragilisticexpealidocious"));
  EXPECT_THAT(headers.first_line(),
              StrEq("HTTP/1.000 404000 supercalifragilisticexpealidocious"));
}

TEST(BalsaHeaders, TestSetFirstlineFromStringPiecesWithNoInitialFirstline) {
  BalsaHeaders headers;
  headers.SetResponseFirstline("HTTP/1.1", 200, "don't need a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(200));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("don't need a reason"));
  EXPECT_THAT(headers.first_line(), StrEq("HTTP/1.1 200 don't need a reason"));
}

TEST(BalsaHeaders, TestSettingFirstlineElementsWithOtherElementsMissing) {
  {
    BalsaHeaders headers;
    headers.SetRequestMethod("GET");
    headers.SetRequestUri("/");
    EXPECT_THAT(headers.first_line(), StrEq("GET / "));
  }
  {
    BalsaHeaders headers;
    headers.SetRequestMethod("GET");
    headers.SetRequestVersion("HTTP/1.1");
    EXPECT_THAT(headers.first_line(), StrEq("GET  HTTP/1.1"));
  }
  {
    BalsaHeaders headers;
    headers.SetRequestUri("/");
    headers.SetRequestVersion("HTTP/1.1");
    EXPECT_THAT(headers.first_line(), StrEq(" / HTTP/1.1"));
  }
}

TEST(BalsaHeaders, TestSettingMissingFirstlineElementsAfterBalsaHeadersParsed) {
  {
    BalsaHeaders headers = CreateHTTPHeaders(true, "GET /foo\r\n");
    ASSERT_THAT(headers.first_line(), StrEq("GET /foo"));

    headers.SetRequestVersion("HTTP/1.1");
    EXPECT_THAT(headers.first_line(), StrEq("GET /foo HTTP/1.1"));
  }
  {
    BalsaHeaders headers = CreateHTTPHeaders(true, "GET\r\n");
    ASSERT_THAT(headers.first_line(), StrEq("GET"));

    headers.SetRequestUri("/foo");
    EXPECT_THAT(headers.first_line(), StrEq("GET /foo "));
  }
}

// Here we exersize the codepaths involved in setting a new firstine when the
// previously set firstline is stored in the 'additional_data_stream_'
// variable, and the new firstline is larger than the previously set firstline.
TEST(BalsaHeaders,
     SetFirstlineFromStringPiecesFirstInAdditionalDataAndNewLarger) {
  BalsaHeaders headers;
  // This one will end up being put into the additional data stream
  headers.SetResponseFirstline("HTTP/1.1", 200, "don't need a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(200));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("don't need a reason"));
  EXPECT_THAT(headers.first_line(), StrEq("HTTP/1.1 200 don't need a reason"));

  // Now, we set it again, this time we're extending what exists
  // here.
  headers.SetResponseFirstline("HTTP/1.10", 2000, "REALLY don't need a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.10"));
  EXPECT_THAT(headers.response_code(), StrEq("2000"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(2000));
  EXPECT_THAT(headers.response_reason_phrase(),
              StrEq("REALLY don't need a reason"));
  EXPECT_THAT(headers.first_line(),
              StrEq("HTTP/1.10 2000 REALLY don't need a reason"));
}

// Here we exersize the codepaths involved in setting a new firstine when the
// previously set firstline is stored in the 'additional_data_stream_'
// variable, and the new firstline is smaller than the previously set firstline.
TEST(BalsaHeaders,
     TestSetFirstlineFromStringPiecesWithPreviousInAdditionalDataNewSmaller) {
  BalsaHeaders headers;
  // This one will end up being put into the additional data stream
  //
  headers.SetResponseFirstline("HTTP/1.10", 2000, "REALLY don't need a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.10"));
  EXPECT_THAT(headers.response_code(), StrEq("2000"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(2000));
  EXPECT_THAT(headers.response_reason_phrase(),
              StrEq("REALLY don't need a reason"));
  EXPECT_THAT(headers.first_line(),
              StrEq("HTTP/1.10 2000 REALLY don't need a reason"));

  // Now, we set it again, this time we're extending what exists
  // here.
  headers.SetResponseFirstline("HTTP/1.0", 200, "a reason");
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
  EXPECT_THAT(headers.response_code(), StrEq("200"));
  EXPECT_THAT(headers.parsed_response_code(), Eq(200));
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("a reason"));
  EXPECT_THAT(headers.first_line(), StrEq("HTTP/1.0 200 a reason"));
}

TEST(BalsaHeaders, CopyFrom) {
  BalsaHeaders headers1, headers2;
  absl::string_view method("GET");
  absl::string_view uri("/foo");
  absl::string_view version("HTTP/1.0");
  headers1.SetRequestFirstlineFromStringPieces(method, uri, version);
  headers1.AppendHeader("key1", "value1");
  headers1.AppendHeader("key 2", "value\n 2");
  headers1.AppendHeader("key\n 3", "value3");

  // "GET /foo HTTP/1.0"     // 17
  // "key1: value1\r\n"      // 14
  // "key 2: value\n 2\r\n"  // 17
  // "key\n 3: value3\r\n"   // 16

  headers2.CopyFrom(headers1);

  EXPECT_THAT(headers1.first_line(), StrEq("GET /foo HTTP/1.0"));
  BalsaHeaders::const_header_lines_iterator chli = headers1.lines().begin();
  EXPECT_THAT(chli->first, StrEq("key1"));
  EXPECT_THAT(chli->second, StrEq("value1"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key 2"));
  EXPECT_THAT(chli->second, StrEq("value\n 2"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key\n 3"));
  EXPECT_THAT(chli->second, StrEq("value3"));
  ++chli;
  EXPECT_EQ(headers1.lines().end(), chli);

  EXPECT_THAT(headers1.request_method(),
              StrEq((std::string(headers2.request_method()))));
  EXPECT_THAT(headers1.request_uri(),
              StrEq((std::string(headers2.request_uri()))));
  EXPECT_THAT(headers1.request_version(),
              StrEq((std::string(headers2.request_version()))));

  EXPECT_THAT(headers2.first_line(), StrEq("GET /foo HTTP/1.0"));
  chli = headers2.lines().begin();
  EXPECT_THAT(chli->first, StrEq("key1"));
  EXPECT_THAT(chli->second, StrEq("value1"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key 2"));
  EXPECT_THAT(chli->second, StrEq("value\n 2"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key\n 3"));
  EXPECT_THAT(chli->second, StrEq("value3"));
  ++chli;
  EXPECT_EQ(headers2.lines().end(), chli);

  version = absl::string_view("HTTP/1.1");
  int code = 200;
  absl::string_view reason_phrase("reason phrase asdf");

  headers1.RemoveAllOfHeader("key1");
  headers1.AppendHeader("key4", "value4");

  headers1.SetResponseFirstline(version, code, reason_phrase);

  headers2.CopyFrom(headers1);

  // "GET /foo HTTP/1.0"     // 17
  // "XXXXXXXXXXXXXX"        // 14
  // "key 2: value\n 2\r\n"  // 17
  // "key\n 3: value3\r\n"   // 16
  // "key4: value4\r\n"      // 14
  //
  //       ->
  //
  // "HTTP/1.1 200 reason phrase asdf"  // 31 = (17 + 14)
  // "key 2: value\n 2\r\n"             // 17
  // "key\n 3: value3\r\n"              // 16
  // "key4: value4\r\n"                 // 14

  EXPECT_THAT(headers1.request_method(),
              StrEq((std::string(headers2.request_method()))));
  EXPECT_THAT(headers1.request_uri(),
              StrEq((std::string(headers2.request_uri()))));
  EXPECT_THAT(headers1.request_version(),
              StrEq((std::string(headers2.request_version()))));

  EXPECT_THAT(headers2.first_line(), StrEq("HTTP/1.1 200 reason phrase asdf"));
  chli = headers2.lines().begin();
  EXPECT_THAT(chli->first, StrEq("key 2"));
  EXPECT_THAT(chli->second, StrEq("value\n 2"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key\n 3"));
  EXPECT_THAT(chli->second, StrEq("value3"));
  ++chli;
  EXPECT_THAT(chli->first, StrEq("key4"));
  EXPECT_THAT(chli->second, StrEq("value4"));
  ++chli;
  EXPECT_EQ(headers2.lines().end(), chli);
}

// Test BalsaHeaders move constructor and move assignment operator.
TEST(BalsaHeaders, Move) {
  BalsaHeaders headers1, headers3;
  absl::string_view method("GET");
  absl::string_view uri("/foo");
  absl::string_view version("HTTP/1.0");
  headers1.SetRequestFirstlineFromStringPieces(method, uri, version);
  headers1.AppendHeader("key1", "value1");
  headers1.AppendHeader("key 2", "value\n 2");
  headers1.AppendHeader("key\n 3", "value3");

  // "GET /foo HTTP/1.0"     // 17
  // "key1: value1\r\n"      // 14
  // "key 2: value\n 2\r\n"  // 17
  // "key\n 3: value3\r\n"   // 16

  BalsaHeaders headers2 = std::move(headers1);

  EXPECT_EQ("GET /foo HTTP/1.0", headers2.first_line());
  BalsaHeaders::const_header_lines_iterator chli = headers2.lines().begin();
  EXPECT_EQ("key1", chli->first);
  EXPECT_EQ("value1", chli->second);
  ++chli;
  EXPECT_EQ("key 2", chli->first);
  EXPECT_EQ("value\n 2", chli->second);
  ++chli;
  EXPECT_EQ("key\n 3", chli->first);
  EXPECT_EQ("value3", chli->second);
  ++chli;
  EXPECT_EQ(headers2.lines().end(), chli);

  EXPECT_EQ("GET", headers2.request_method());
  EXPECT_EQ("/foo", headers2.request_uri());
  EXPECT_EQ("HTTP/1.0", headers2.request_version());

  headers3 = std::move(headers2);
  version = absl::string_view("HTTP/1.1");
  int code = 200;
  absl::string_view reason_phrase("reason phrase asdf");

  headers3.RemoveAllOfHeader("key1");
  headers3.AppendHeader("key4", "value4");

  headers3.SetResponseFirstline(version, code, reason_phrase);

  BalsaHeaders headers4 = std::move(headers3);
```