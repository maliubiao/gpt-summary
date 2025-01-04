Response:
The user is asking for a summary of the provided C++ code, which is a test file for structured headers parsing and serialization. I need to extract the core functionality of the code, its relation to Javascript (if any), illustrate its logic with examples, highlight potential user errors, explain how a user might reach this code during debugging, and provide a final summary.

Here's a breakdown of the thought process:

1. **Identify the Purpose of the File:** The filename `structured_headers_generated_test.cc` and the inclusion of test macros (`TEST`) immediately signal that this is a test file. The "structured headers" part indicates it's about parsing and serializing HTTP structured headers.

2. **Analyze the Test Cases:** The code contains multiple test cases organized into arrays (`parameterized_item_test_cases`, `list_test_cases`, `dictionary_test_cases`). Each test case has:
    * `name`: A descriptive name.
    * `raw`: The raw header string to parse.
    * `raw_len`: The length of the raw string.
    * `expected`: The expected parsed structure.
    * `canonical`: An optional canonical representation of the serialized form.

3. **Determine the Functionality Being Tested:** The `TEST` macros call functions like `ParseItem`, `ParseList`, `ParseDictionary`, `SerializeItem`, `SerializeList`, and `SerializeDictionary`. This confirms the file's purpose is to test the parsing and serialization of structured headers (items, lists, and dictionaries).

4. **Assess Relevance to Javascript:** Structured headers are part of HTTP, a fundamental protocol for the web. Javascript running in browsers often interacts with HTTP headers. Therefore, there's a relationship. I need to provide a concrete example of how Javascript might encounter structured headers. The `fetch` API is a good candidate.

5. **Illustrate Logic with Examples:**  I need to pick a few representative test cases and show how the parsing works. Focus on cases with both successful and failing parses to demonstrate error handling.

6. **Identify Potential User Errors:**  The test cases that expect `std::nullopt` (no parsed value) often highlight invalid header formats. These are good candidates for illustrating user errors. Common mistakes include incorrect syntax, invalid characters, or missing delimiters.

7. **Explain Debugging Context:**  How would a developer end up looking at this test file? Typically, it happens when investigating issues related to how a web application or browser handles HTTP headers. I should describe a user action that leads to a network request, triggering the header parsing logic.

8. **Summarize the Overall Functionality:**  The file's main purpose is to ensure the correctness of the structured header parsing and serialization implementation. It acts as a comprehensive suite of examples covering various valid and invalid header formats.

9. **Structure the Output:**  Organize the information into the requested sections: functionality, relation to Javascript, logical examples, user errors, debugging context, and final summary. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Just describe the test functions.
* **Correction:**  Need to explain *what* they are testing, not just *that* they are testing. Focus on the concepts of parsing and serialization of structured headers.
* **Initial Thought:**  Javascript uses HTTP, so there's a connection.
* **Refinement:** Provide a specific Javascript API example (like `fetch` and `Headers` object) to make the connection tangible.
* **Initial Thought:**  Just list failing test cases as errors.
* **Refinement:**  Explain *why* those cases fail – focusing on the syntax rules of structured headers.
* **Initial Thought:**  Debugging happens when things break.
* **Refinement:** Describe a specific user action (e.g., a user clicking a link) that leads to a network request and how a developer might trace the header handling.

By following these steps, I can generate a comprehensive and accurate answer to the user's query.
这是位于 Chromium 网络栈中 `net/third_party/quiche/src/quiche/common/structured_headers_generated_test.cc` 的源代码文件，它是一个测试文件，专门用于验证 **结构化头部 (Structured Headers)** 的解析和序列化功能的正确性。

**功能:**

1. **解析测试 (Parsing Tests):**
   - 该文件包含了一系列的测试用例，用于测试结构化头部的解析器 (`ParseItem`, `ParseList`, `ParseDictionary`)。
   - 这些测试用例涵盖了各种有效的和无效的结构化头部字符串格式。
   - 对于每个测试用例，它会提供一个原始的头部字符串 (`raw`) 和期望的解析结果 (`expected`)。
   - 测试会调用解析函数，并将实际的解析结果与期望的结果进行比较，以验证解析器是否正确地将字符串转换为内部数据结构。

2. **序列化测试 (Serialization Tests):**
   - 文件也包含了针对结构化头部序列化器 (`SerializeItem`, `SerializeList`, `SerializeDictionary`) 的测试。
   - 对于每个测试用例，如果存在期望的解析结果 (`expected`)，测试会将其序列化回字符串。
   - 然后，将序列化后的字符串与原始字符串 (`raw`) 或规范化字符串 (`canonical`) 进行比较，以验证序列化器是否正确地将内部数据结构转换回字符串表示。
   - 规范化字符串用于处理一些在解析后可能进行格式调整的情况，例如添加或移除不必要的空格。

3. **覆盖各种数据类型:**
   - 测试用例涵盖了结构化头部规范中定义的各种数据类型，例如：
     - 整数 (Integer)
     - 浮点数 (Double)
     - 字符串 (String Token)
     - 布尔值 (Boolean Parameter)
     - 列表 (List)
     - 字典 (Dictionary)
     - 带参数的项 (Parameterized Item)
     - 带参数的列表项 (Parameterized List Item)

**与 Javascript 的关系:**

结构化头部是 HTTP 的一部分，用于在客户端和服务器之间传递结构化的信息。Javascript 在浏览器环境中通过 `fetch` API 或 `XMLHttpRequest` 与服务器进行通信时，会涉及到 HTTP 头部。

**举例说明:**

假设服务器发送了一个包含结构化头部的响应：

```
Content-Type: text/html
Link: <https://example.com/style.css>; rel="stylesheet"; type="text/css", <https://example.com/script.js>; rel="preload"; as="script"
```

这里的 `Link` 头部就是一个结构化头部。在 Javascript 中，你可以通过 `fetch` API 获取到这个头部：

```javascript
fetch('https://example.com')
  .then(response => {
    const linkHeader = response.headers.get('Link');
    console.log(linkHeader);
    // 输出: '<https://example.com/style.css>; rel="stylesheet"; type="text/css", <https://example.com/script.js>; rel="preload"; as="script"'
  });
```

Chromium 的网络栈负责解析这个 `Link` 头部。`structured_headers_generated_test.cc` 中的测试用例就是用来验证 Chromium 的结构化头部解析器是否能够正确地将像上面这样的字符串解析成 Javascript 可以理解的数据结构。虽然 Javascript 本身不直接调用这个 C++ 代码，但它依赖于 Chromium 网络栈提供的功能来处理 HTTP 头部。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对字典类型):**

```
raw = "abc=123;a=1;b=2, def=456, ghi=789;q=9;r=\"+w\""
```

**预期输出 (解析后的字典数据结构):**

```
{
  "abc": { value: 123, params: { "a": 1, "b": 2 } },
  "def": { value: 456, params: {} },
  "ghi": { value: 789, params: { "q": 9, "r": "+w" } }
}
```

**假设输入 (针对字典类型，包含错误):**

```
raw = "a{a=1"
```

**预期输出 (解析失败):**

```
std::nullopt
```

**用户或编程常见的使用错误 (以字典的键为例):**

用户或程序员在构造结构化头部字符串时，可能会犯一些错误，这些错误会被测试用例捕捉到。例如：

* **使用无效的字符作为字典的键:**

  ```
  // 错误: 字典的键不能以空格开头
  " a=1"
  ```

  测试用例会验证解析器是否能正确拒绝这种格式。

* **使用控制字符作为字典的键:**

  ```
  // 错误: 字典的键不能包含控制字符
  "\000a=1"
  ```

  测试用例会确保解析器不会将这样的字符串解析为有效的结构化头部。

* **缺少必要的分隔符:**

  ```
  // 错误: 字典的条目之间应该用逗号分隔
  "a=1 b=2"
  ```

  虽然这个例子没有在提供的代码片段中直接体现，但类似的测试用例会存在于其他部分。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了问题，例如某些功能无法正常工作，或者网页显示不正确。作为开发者，在排查问题时，可能会发现服务器返回的 HTTP 响应头包含一些格式不正确的结构化头部。

1. **用户访问网页:** 用户在 Chrome 浏览器中输入网址或点击链接，发起网络请求。
2. **浏览器发送请求:** Chrome 的网络栈负责构建 HTTP 请求并发送到服务器。
3. **服务器响应:** 服务器处理请求并返回 HTTP 响应，其中可能包含结构化头部。
4. **浏览器接收响应:** Chrome 的网络栈接收服务器的响应。
5. **解析头部:** 网络栈中的结构化头部解析器 (代码类似于 `structured_headers_generated_test.cc` 测试的代码) 尝试解析响应头。
6. **解析失败 (可能):** 如果响应头中的结构化头部格式不正确，解析器可能会失败。
7. **问题出现:**  解析失败可能导致浏览器无法正确理解服务器的指示，从而导致功能异常或显示错误。
8. **开发者调试:** 开发者可以使用 Chrome 的开发者工具 (Network 面板) 查看响应头，发现格式错误的结构化头部。
9. **源码分析 (可能):** 为了理解解析错误的原因，开发者可能会查看 Chromium 的源代码，包括 `structured_headers_generated_test.cc` 这样的测试文件，以了解哪些格式是被允许的，哪些是被拒绝的，以及解析器的行为。测试用例可以帮助开发者理解特定格式的头部是如何被解析的，以及可能出现的错误情况。

**归纳一下它的功能 (第5部分，共5部分):**

作为系列测试文件的最后一部分，这个文件 (`structured_headers_generated_test.cc`) 的主要功能是 **系统地、全面地测试结构化头部解析和序列化的各种场景，确保 Chromium 网络栈能够正确地处理符合和不符合规范的结构化头部字符串**。它通过大量的测试用例覆盖了不同的数据类型、语法规则和边界情况，是保证网络栈稳定性和互操作性的重要组成部分。这些测试用例驱动着结构化头部功能的开发和维护，帮助开发者及时发现和修复潜在的 Bug，并确保 Chromium 能够正确地与遵循结构化头部规范的服务器进行通信。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/structured_headers_generated_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
er(1), {}}}}}},
     nullptr},
    {"0x76 in dictionary key",
     "ava=1",
     5,
     {Dictionary{{{"ava", {Integer(1), {}}}}}},
     nullptr},
    {"0x77 in dictionary key",
     "awa=1",
     5,
     {Dictionary{{{"awa", {Integer(1), {}}}}}},
     nullptr},
    {"0x78 in dictionary key",
     "axa=1",
     5,
     {Dictionary{{{"axa", {Integer(1), {}}}}}},
     nullptr},
    {"0x79 in dictionary key",
     "aya=1",
     5,
     {Dictionary{{{"aya", {Integer(1), {}}}}}},
     nullptr},
    {"0x7a in dictionary key",
     "aza=1",
     5,
     {Dictionary{{{"aza", {Integer(1), {}}}}}},
     nullptr},
    {"0x7b in dictionary key", "a{a=1", 5, std::nullopt, nullptr},
    {"0x7c in dictionary key", "a|a=1", 5, std::nullopt, nullptr},
    {"0x7d in dictionary key", "a}a=1", 5, std::nullopt, nullptr},
    {"0x7e in dictionary key", "a~a=1", 5, std::nullopt, nullptr},
    {"0x7f in dictionary key", "a\177a=1", 5, std::nullopt, nullptr},
    {"0x00 starting an dictionary key", "\000a=1", 4, std::nullopt, nullptr},
    {"0x01 starting an dictionary key", "\001a=1", 4, std::nullopt, nullptr},
    {"0x02 starting an dictionary key", "\002a=1", 4, std::nullopt, nullptr},
    {"0x03 starting an dictionary key", "\003a=1", 4, std::nullopt, nullptr},
    {"0x04 starting an dictionary key", "\004a=1", 4, std::nullopt, nullptr},
    {"0x05 starting an dictionary key", "\005a=1", 4, std::nullopt, nullptr},
    {"0x06 starting an dictionary key", "\006a=1", 4, std::nullopt, nullptr},
    {"0x07 starting an dictionary key", "\aa=1", 4, std::nullopt, nullptr},
    {"0x08 starting an dictionary key", "\ba=1", 4, std::nullopt, nullptr},
    {"0x09 starting an dictionary key", "\ta=1", 4, std::nullopt, nullptr},
    {"0x0a starting an dictionary key", "\na=1", 4, std::nullopt, nullptr},
    {"0x0b starting an dictionary key", "\va=1", 4, std::nullopt, nullptr},
    {"0x0c starting an dictionary key", "\fa=1", 4, std::nullopt, nullptr},
    {"0x0d starting an dictionary key", "\ra=1", 4, std::nullopt, nullptr},
    {"0x0e starting an dictionary key", "\016a=1", 4, std::nullopt, nullptr},
    {"0x0f starting an dictionary key", "\017a=1", 4, std::nullopt, nullptr},
    {"0x10 starting an dictionary key", "\020a=1", 4, std::nullopt, nullptr},
    {"0x11 starting an dictionary key", "\021a=1", 4, std::nullopt, nullptr},
    {"0x12 starting an dictionary key", "\022a=1", 4, std::nullopt, nullptr},
    {"0x13 starting an dictionary key", "\023a=1", 4, std::nullopt, nullptr},
    {"0x14 starting an dictionary key", "\024a=1", 4, std::nullopt, nullptr},
    {"0x15 starting an dictionary key", "\025a=1", 4, std::nullopt, nullptr},
    {"0x16 starting an dictionary key", "\026a=1", 4, std::nullopt, nullptr},
    {"0x17 starting an dictionary key", "\027a=1", 4, std::nullopt, nullptr},
    {"0x18 starting an dictionary key", "\030a=1", 4, std::nullopt, nullptr},
    {"0x19 starting an dictionary key", "\031a=1", 4, std::nullopt, nullptr},
    {"0x1a starting an dictionary key", "\032a=1", 4, std::nullopt, nullptr},
    {"0x1b starting an dictionary key", "\033a=1", 4, std::nullopt, nullptr},
    {"0x1c starting an dictionary key", "\034a=1", 4, std::nullopt, nullptr},
    {"0x1d starting an dictionary key", "\035a=1", 4, std::nullopt, nullptr},
    {"0x1e starting an dictionary key", "\036a=1", 4, std::nullopt, nullptr},
    {"0x1f starting an dictionary key", "\037a=1", 4, std::nullopt, nullptr},
    {"0x20 starting an dictionary key",
     " a=1",
     4,
     {Dictionary{{{"a", {Integer(1), {}}}}}},
     "a=1"},
    {"0x21 starting an dictionary key", "!a=1", 4, std::nullopt, nullptr},
    {"0x22 starting an dictionary key", "\"a=1", 4, std::nullopt, nullptr},
    {"0x23 starting an dictionary key", "#a=1", 4, std::nullopt, nullptr},
    {"0x24 starting an dictionary key", "$a=1", 4, std::nullopt, nullptr},
    {"0x25 starting an dictionary key", "%a=1", 4, std::nullopt, nullptr},
    {"0x26 starting an dictionary key", "&a=1", 4, std::nullopt, nullptr},
    {"0x27 starting an dictionary key", "'a=1", 4, std::nullopt, nullptr},
    {"0x28 starting an dictionary key", "(a=1", 4, std::nullopt, nullptr},
    {"0x29 starting an dictionary key", ")a=1", 4, std::nullopt, nullptr},
    {"0x2a starting an dictionary key",
     "*a=1",
     4,
     {Dictionary{{{"*a", {Integer(1), {}}}}}},
     nullptr},
    {"0x2b starting an dictionary key", "+a=1", 4, std::nullopt, nullptr},
    {"0x2c starting an dictionary key", ",a=1", 4, std::nullopt, nullptr},
    {"0x2d starting an dictionary key", "-a=1", 4, std::nullopt, nullptr},
    {"0x2e starting an dictionary key", ".a=1", 4, std::nullopt, nullptr},
    {"0x2f starting an dictionary key", "/a=1", 4, std::nullopt, nullptr},
    {"0x30 starting an dictionary key", "0a=1", 4, std::nullopt, nullptr},
    {"0x31 starting an dictionary key", "1a=1", 4, std::nullopt, nullptr},
    {"0x32 starting an dictionary key", "2a=1", 4, std::nullopt, nullptr},
    {"0x33 starting an dictionary key", "3a=1", 4, std::nullopt, nullptr},
    {"0x34 starting an dictionary key", "4a=1", 4, std::nullopt, nullptr},
    {"0x35 starting an dictionary key", "5a=1", 4, std::nullopt, nullptr},
    {"0x36 starting an dictionary key", "6a=1", 4, std::nullopt, nullptr},
    {"0x37 starting an dictionary key", "7a=1", 4, std::nullopt, nullptr},
    {"0x38 starting an dictionary key", "8a=1", 4, std::nullopt, nullptr},
    {"0x39 starting an dictionary key", "9a=1", 4, std::nullopt, nullptr},
    {"0x3a starting an dictionary key", ":a=1", 4, std::nullopt, nullptr},
    {"0x3b starting an dictionary key", ";a=1", 4, std::nullopt, nullptr},
    {"0x3c starting an dictionary key", "<a=1", 4, std::nullopt, nullptr},
    {"0x3d starting an dictionary key", "=a=1", 4, std::nullopt, nullptr},
    {"0x3e starting an dictionary key", ">a=1", 4, std::nullopt, nullptr},
    {"0x3f starting an dictionary key", "?a=1", 4, std::nullopt, nullptr},
    {"0x40 starting an dictionary key", "@a=1", 4, std::nullopt, nullptr},
    {"0x41 starting an dictionary key", "Aa=1", 4, std::nullopt, nullptr},
    {"0x42 starting an dictionary key", "Ba=1", 4, std::nullopt, nullptr},
    {"0x43 starting an dictionary key", "Ca=1", 4, std::nullopt, nullptr},
    {"0x44 starting an dictionary key", "Da=1", 4, std::nullopt, nullptr},
    {"0x45 starting an dictionary key", "Ea=1", 4, std::nullopt, nullptr},
    {"0x46 starting an dictionary key", "Fa=1", 4, std::nullopt, nullptr},
    {"0x47 starting an dictionary key", "Ga=1", 4, std::nullopt, nullptr},
    {"0x48 starting an dictionary key", "Ha=1", 4, std::nullopt, nullptr},
    {"0x49 starting an dictionary key", "Ia=1", 4, std::nullopt, nullptr},
    {"0x4a starting an dictionary key", "Ja=1", 4, std::nullopt, nullptr},
    {"0x4b starting an dictionary key", "Ka=1", 4, std::nullopt, nullptr},
    {"0x4c starting an dictionary key", "La=1", 4, std::nullopt, nullptr},
    {"0x4d starting an dictionary key", "Ma=1", 4, std::nullopt, nullptr},
    {"0x4e starting an dictionary key", "Na=1", 4, std::nullopt, nullptr},
    {"0x4f starting an dictionary key", "Oa=1", 4, std::nullopt, nullptr},
    {"0x50 starting an dictionary key", "Pa=1", 4, std::nullopt, nullptr},
    {"0x51 starting an dictionary key", "Qa=1", 4, std::nullopt, nullptr},
    {"0x52 starting an dictionary key", "Ra=1", 4, std::nullopt, nullptr},
    {"0x53 starting an dictionary key", "Sa=1", 4, std::nullopt, nullptr},
    {"0x54 starting an dictionary key", "Ta=1", 4, std::nullopt, nullptr},
    {"0x55 starting an dictionary key", "Ua=1", 4, std::nullopt, nullptr},
    {"0x56 starting an dictionary key", "Va=1", 4, std::nullopt, nullptr},
    {"0x57 starting an dictionary key", "Wa=1", 4, std::nullopt, nullptr},
    {"0x58 starting an dictionary key", "Xa=1", 4, std::nullopt, nullptr},
    {"0x59 starting an dictionary key", "Ya=1", 4, std::nullopt, nullptr},
    {"0x5a starting an dictionary key", "Za=1", 4, std::nullopt, nullptr},
    {"0x5b starting an dictionary key", "[a=1", 4, std::nullopt, nullptr},
    {"0x5c starting an dictionary key", "\\a=1", 4, std::nullopt, nullptr},
    {"0x5d starting an dictionary key", "]a=1", 4, std::nullopt, nullptr},
    {"0x5e starting an dictionary key", "^a=1", 4, std::nullopt, nullptr},
    {"0x5f starting an dictionary key", "_a=1", 4, std::nullopt, nullptr},
    {"0x60 starting an dictionary key", "`a=1", 4, std::nullopt, nullptr},
    {"0x61 starting an dictionary key",
     "aa=1",
     4,
     {Dictionary{{{"aa", {Integer(1), {}}}}}},
     nullptr},
    {"0x62 starting an dictionary key",
     "ba=1",
     4,
     {Dictionary{{{"ba", {Integer(1), {}}}}}},
     nullptr},
    {"0x63 starting an dictionary key",
     "ca=1",
     4,
     {Dictionary{{{"ca", {Integer(1), {}}}}}},
     nullptr},
    {"0x64 starting an dictionary key",
     "da=1",
     4,
     {Dictionary{{{"da", {Integer(1), {}}}}}},
     nullptr},
    {"0x65 starting an dictionary key",
     "ea=1",
     4,
     {Dictionary{{{"ea", {Integer(1), {}}}}}},
     nullptr},
    {"0x66 starting an dictionary key",
     "fa=1",
     4,
     {Dictionary{{{"fa", {Integer(1), {}}}}}},
     nullptr},
    {"0x67 starting an dictionary key",
     "ga=1",
     4,
     {Dictionary{{{"ga", {Integer(1), {}}}}}},
     nullptr},
    {"0x68 starting an dictionary key",
     "ha=1",
     4,
     {Dictionary{{{"ha", {Integer(1), {}}}}}},
     nullptr},
    {"0x69 starting an dictionary key",
     "ia=1",
     4,
     {Dictionary{{{"ia", {Integer(1), {}}}}}},
     nullptr},
    {"0x6a starting an dictionary key",
     "ja=1",
     4,
     {Dictionary{{{"ja", {Integer(1), {}}}}}},
     nullptr},
    {"0x6b starting an dictionary key",
     "ka=1",
     4,
     {Dictionary{{{"ka", {Integer(1), {}}}}}},
     nullptr},
    {"0x6c starting an dictionary key",
     "la=1",
     4,
     {Dictionary{{{"la", {Integer(1), {}}}}}},
     nullptr},
    {"0x6d starting an dictionary key",
     "ma=1",
     4,
     {Dictionary{{{"ma", {Integer(1), {}}}}}},
     nullptr},
    {"0x6e starting an dictionary key",
     "na=1",
     4,
     {Dictionary{{{"na", {Integer(1), {}}}}}},
     nullptr},
    {"0x6f starting an dictionary key",
     "oa=1",
     4,
     {Dictionary{{{"oa", {Integer(1), {}}}}}},
     nullptr},
    {"0x70 starting an dictionary key",
     "pa=1",
     4,
     {Dictionary{{{"pa", {Integer(1), {}}}}}},
     nullptr},
    {"0x71 starting an dictionary key",
     "qa=1",
     4,
     {Dictionary{{{"qa", {Integer(1), {}}}}}},
     nullptr},
    {"0x72 starting an dictionary key",
     "ra=1",
     4,
     {Dictionary{{{"ra", {Integer(1), {}}}}}},
     nullptr},
    {"0x73 starting an dictionary key",
     "sa=1",
     4,
     {Dictionary{{{"sa", {Integer(1), {}}}}}},
     nullptr},
    {"0x74 starting an dictionary key",
     "ta=1",
     4,
     {Dictionary{{{"ta", {Integer(1), {}}}}}},
     nullptr},
    {"0x75 starting an dictionary key",
     "ua=1",
     4,
     {Dictionary{{{"ua", {Integer(1), {}}}}}},
     nullptr},
    {"0x76 starting an dictionary key",
     "va=1",
     4,
     {Dictionary{{{"va", {Integer(1), {}}}}}},
     nullptr},
    {"0x77 starting an dictionary key",
     "wa=1",
     4,
     {Dictionary{{{"wa", {Integer(1), {}}}}}},
     nullptr},
    {"0x78 starting an dictionary key",
     "xa=1",
     4,
     {Dictionary{{{"xa", {Integer(1), {}}}}}},
     nullptr},
    {"0x79 starting an dictionary key",
     "ya=1",
     4,
     {Dictionary{{{"ya", {Integer(1), {}}}}}},
     nullptr},
    {"0x7a starting an dictionary key",
     "za=1",
     4,
     {Dictionary{{{"za", {Integer(1), {}}}}}},
     nullptr},
    {"0x7b starting an dictionary key", "{a=1", 4, std::nullopt, nullptr},
    {"0x7c starting an dictionary key", "|a=1", 4, std::nullopt, nullptr},
    {"0x7d starting an dictionary key", "}a=1", 4, std::nullopt, nullptr},
    {"0x7e starting an dictionary key", "~a=1", 4, std::nullopt, nullptr},
    {"0x7f starting an dictionary key", "\177a=1", 4, std::nullopt, nullptr},
    // param-dict.json
    {"basic parameterised dict",
     "abc=123;a=1;b=2, def=456, ghi=789;q=9;r=\"+w\"",
     44,
     {Dictionary{{{"abc", {Integer(123), {Param("a", 1), Param("b", 2)}}},
                  {"def", {Integer(456), {}}},
                  {"ghi", {Integer(789), {Param("q", 9), Param("r", "+w")}}}}}},
     nullptr},
    {"single item parameterised dict",
     "a=b; q=1.0",
     10,
     {Dictionary{
         {{"a", {Item("b", Item::kTokenType), {DoubleParam("q", 1.000000)}}}}}},
     "a=b;q=1.0"},
    {"list item parameterised dictionary",
     "a=(1 2); q=1.0",
     14,
     {Dictionary{{{"a",
                   {{{Integer(1), {}}, {Integer(2), {}}},
                    {DoubleParam("q", 1.000000)}}}}}},
     "a=(1 2);q=1.0"},
    {"missing parameter value parameterised dict",
     "a=3;c;d=5",
     9,
     {Dictionary{
         {{"a", {Integer(3), {BooleanParam("c", true), Param("d", 5)}}}}}},
     nullptr},
    {"terminal missing parameter value parameterised dict",
     "a=3;c=5;d",
     9,
     {Dictionary{
         {{"a", {Integer(3), {Param("c", 5), BooleanParam("d", true)}}}}}},
     nullptr},
    {"no whitespace parameterised dict",
     "a=b;c=1,d=e;f=2",
     15,
     {Dictionary{{{"a", {Item("b", Item::kTokenType), {Param("c", 1)}}},
                  {"d", {Item("e", Item::kTokenType), {Param("f", 2)}}}}}},
     "a=b;c=1, d=e;f=2"},
    {"whitespace before = parameterised dict", "a=b;q =0.5", 10, std::nullopt,
     nullptr},
    {"whitespace after = parameterised dict", "a=b;q= 0.5", 10, std::nullopt,
     nullptr},
    {"whitespace before ; parameterised dict", "a=b ;q=0.5", 10, std::nullopt,
     nullptr},
    {"whitespace after ; parameterised dict",
     "a=b; q=0.5",
     10,
     {Dictionary{
         {{"a", {Item("b", Item::kTokenType), {DoubleParam("q", 0.500000)}}}}}},
     "a=b;q=0.5"},
    {"extra whitespace parameterised dict",
     "a=b;  c=1  ,  d=e; f=2; g=3",
     27,
     {Dictionary{
         {{"a", {Item("b", Item::kTokenType), {Param("c", 1)}}},
          {"d",
           {Item("e", Item::kTokenType), {Param("f", 2), Param("g", 3)}}}}}},
     "a=b;c=1, d=e;f=2;g=3"},
    {"two lines parameterised list",
     "a=b;c=1, d=e;f=2",
     16,
     {Dictionary{{{"a", {Item("b", Item::kTokenType), {Param("c", 1)}}},
                  {"d", {Item("e", Item::kTokenType), {Param("f", 2)}}}}}},
     "a=b;c=1, d=e;f=2"},
    {"trailing comma parameterised list", "a=b; q=1.0,", 11, std::nullopt,
     nullptr},
    {"empty item parameterised list", "a=b; q=1.0,,c=d", 15, std::nullopt,
     nullptr},
};

}  // namespace

TEST(StructuredHeaderGeneratedTest, ParseItem) {
  for (const auto& c : parameterized_item_test_cases) {
    if (c.raw) {
      SCOPED_TRACE(c.name);
      std::string raw{c.raw, c.raw_len};
      std::optional<ParameterizedItem> result = ParseItem(raw);
      EXPECT_EQ(result, c.expected);
    }
  }
}

TEST(StructuredHeaderGeneratedTest, ParseList) {
  for (const auto& c : list_test_cases) {
    if (c.raw) {
      SCOPED_TRACE(c.name);
      std::string raw{c.raw, c.raw_len};
      std::optional<List> result = ParseList(raw);
      EXPECT_EQ(result, c.expected);
    }
  }
}

TEST(StructuredHeaderGeneratedTest, ParseDictionary) {
  for (const auto& c : dictionary_test_cases) {
    if (c.raw) {
      SCOPED_TRACE(c.name);
      std::string raw{c.raw, c.raw_len};
      std::optional<Dictionary> result = ParseDictionary(raw);
      EXPECT_EQ(result, c.expected);
    }
  }
}

TEST(StructuredHeaderGeneratedTest, SerializeItem) {
  for (const auto& c : parameterized_item_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeItem(*c.expected);
      if (c.raw || c.canonical) {
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result.value(),
                  std::string(c.canonical ? c.canonical : c.raw));
      } else {
        EXPECT_FALSE(result.has_value());
      }
    }
  }
}

TEST(StructuredHeaderGeneratedTest, SerializeList) {
  for (const auto& c : list_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeList(*c.expected);
      if (c.raw || c.canonical) {
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result.value(),
                  std::string(c.canonical ? c.canonical : c.raw));
      } else {
        EXPECT_FALSE(result.has_value());
      }
    }
  }
}

TEST(StructuredHeaderGeneratedTest, SerializeDictionary) {
  for (const auto& c : dictionary_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeDictionary(*c.expected);
      if (c.raw || c.canonical) {
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result.value(),
                  std::string(c.canonical ? c.canonical : c.raw));
      } else {
        EXPECT_FALSE(result.has_value());
      }
    }
  }
}

}  // namespace structured_headers
}  // namespace quiche

"""


```