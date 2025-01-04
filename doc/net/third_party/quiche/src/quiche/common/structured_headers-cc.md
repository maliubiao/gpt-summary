Response:
Let's break down the thought process for analyzing the C++ code and answering the prompt.

1. **Understand the Core Task:** The request asks for the functionality of the `structured_headers.cc` file in Chromium's network stack. It also probes for relationships with JavaScript, logical inference examples, common errors, and debugging context.

2. **Initial Code Scan - Identify Key Components:**  Quickly scan the file for major structural elements:
    * `#include` directives:  Indicate dependencies and areas of functionality (string manipulation, containers, logging).
    * Namespaces (`quiche::structured_headers`):  Defines the scope of the code.
    * Macros (`DIGIT`, `LCALPHA`, etc.): Character set definitions hinting at parsing rules.
    * Constants (`kMaxInteger`, `kTooLargeDecimal`):  Boundary conditions and limitations.
    * Helper Functions (`StripLeft`): Utility for string manipulation.
    * Classes (`StructuredHeaderParser`, `StructuredHeaderSerializer`):  Core logic for parsing and serialization.
    * Structs/Classes (`Item`, `ParameterizedItem`, `List`, `Dictionary`, etc.): Data structures representing structured header components.
    * Standalone functions (`ParseItem`, `SerializeList`, etc.): Public interface for parsing and serialization.

3. **Focus on the Main Actors: Parser and Serializer:** The names `StructuredHeaderParser` and `StructuredHeaderSerializer` are highly suggestive. Analyze their methods:
    * **Parser:** Methods like `ReadList`, `ReadDictionary`, `ReadItem`, `ReadString`, `ReadNumber` clearly indicate the parsing of different structured header components. The `DraftVersion` enum and checks within the parser suggest handling of different specifications.
    * **Serializer:** Methods like `WriteList`, `WriteItem`, `WriteDictionary`, `WriteBareItem` indicate the process of converting data structures back into structured header strings.

4. **Infer Functionality - Connecting the Dots:** Based on the class names and method names, infer the overall functionality: This code is responsible for parsing and serializing HTTP Structured Headers as defined by RFC8941 and an older draft (SH09).

5. **JavaScript Relationship - HTTP Headers:** Consider where HTTP headers come into play in a web browser. JavaScript can interact with HTTP headers through:
    * `XMLHttpRequest` (XHR) and `fetch` APIs:  Reading response headers and setting request headers.
    * Browser developer tools: Inspecting headers.
    * Potentially through Service Workers.

    Therefore, this C++ code (handling header parsing/serialization) is crucial for how the *browser* interprets and constructs HTTP messages used by JavaScript. It doesn't directly *execute* JavaScript, but it's a foundational component for network communication.

6. **Logical Inference Examples - Input/Output:** Choose a simple structured header component and demonstrate the parsing and serialization process. An `Item` (like a string or integer) is a good starting point. Show how a string input is parsed into an `Item` object, and then how that `Item` object can be serialized back into a string.

7. **Common User/Programming Errors:** Think about typical mistakes when working with structured data:
    * **Invalid format:** Providing input that doesn't conform to the RFC.
    * **Incorrect data types:** Trying to serialize a C++ data type that doesn't map cleanly to a structured header type.
    * **Boundary conditions:** Exceeding the allowed limits for integers or decimals. The constants in the code provide hints here.

8. **Debugging Scenario - Tracing the User's Path:**  Imagine a scenario where a user encounters an issue related to structured headers. Trace the steps leading to this code:
    * User initiates a network request (clicks a link, JavaScript makes a `fetch` call).
    * Chromium's network stack processes the request.
    * If the request or response involves structured headers, the parsing logic in this file will be invoked. Setting breakpoints in the parser would be a natural debugging step.

9. **Refine and Structure the Answer:**  Organize the findings into clear sections, addressing each part of the prompt:
    * Functionality: Clearly state the purpose of the file.
    * JavaScript Relationship: Explain the indirect connection through HTTP communication.
    * Logical Inference: Provide concrete input/output examples for parsing and serialization.
    * Common Errors:  Illustrate with specific examples.
    * Debugging: Describe a user scenario and how it leads to this code.

10. **Review and Elaborate:**  Read through the generated answer, ensuring clarity, accuracy, and completeness. Add details where needed, such as mentioning specific RFC sections or elaborating on the different structured header types. For instance, explain the difference between `List`, `Dictionary`, and `Item`.

This systematic approach allows for a comprehensive understanding of the code's role and its interactions within the larger system. It involves code scanning, inference, applying knowledge of web technologies, and thinking from the perspective of a developer and a user.
这个文件 `net/third_party/quiche/src/quiche/common/structured_headers.cc` 是 Chromium 网络栈的一部分，它专门用于**解析和序列化 HTTP 结构化头部 (Structured Headers)**。 这些结构化头部是 HTTP 的一种扩展机制，允许将复杂的结构化数据编码到 HTTP 头部字段中。 这个文件实现了 RFC8941 中定义的结构化头部规范，同时也保留了对旧版本规范 (SH09) 的兼容性，主要用于 Web Packaging 等场景。

**主要功能:**

1. **解析 (Parsing):** 将 HTTP 头部字符串解析为结构化的 C++ 对象。这包括以下几种结构：
   - **Item:** 最基本的组成部分，可以是字符串、token、数字（整数或小数）、布尔值或字节序列。
   - **List:**  由多个 Item 或 Inner List 组成的有序列表。
   - **Inner List:**  嵌套在 List 中的由 Item 组成的列表，可以有自己的参数。
   - **Dictionary:**  由键值对组成的无序集合，值可以是 Item 或 Inner List，也可以带有参数。
   - **Parameters:**  附加在 Item 或 Inner List 上的键值对，用于传递元数据。

2. **序列化 (Serialization):** 将结构化的 C++ 对象转换为符合 RFC8941 规范的 HTTP 头部字符串。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它在浏览器处理 HTTP 请求和响应的过程中扮演着关键角色，而 JavaScript 代码可以通过多种方式与这些 HTTP 头部交互。

**举例说明:**

假设一个 HTTP 响应头包含以下结构化头部：

```
My-Structured-Header: tkn;param1=1, ("str" 2);param2
```

- 当浏览器接收到这个响应时，网络栈会调用 `structured_headers.cc` 中的解析逻辑来解析 `My-Structured-Header` 的值。
- 解析后，JavaScript 代码可以使用 `fetch` API 或 `XMLHttpRequest` API 获取到这个头部的值。然而，获取到的通常是原始的字符串形式。
- **更直接的关联（虽然目前 Chromium 可能没有直接暴露结构化头部解析后的对象给 JS）：**  理论上，浏览器可以提供 API，让 JavaScript 可以访问已经解析过的结构化数据，而不是仅仅是原始字符串。  例如，可以想象一个 API 像这样：

```javascript
fetch('/resource').then(response => {
  const structuredHeader = response.structuredHeaders.get('My-Structured-Header');
  console.log(structuredHeader); //  期望输出类似于：[{token: "tkn", params: {param1: 1}}, {innerList: ["str", 2], params: {param2: true}}]
});
```

**目前的 JavaScript 交互方式：**  通常，JavaScript 代码需要自己解析结构化头部的字符串值，或者依赖于浏览器内部对某些特定结构化头部的处理。

**逻辑推理的假设输入与输出:**

**假设输入 (解析):**

```
Input String:  "hello", 123;p=1.0, *YWFh*
```

**预期输出 (C++ 对象):**

```c++
std::vector<structured_headers::ParameterizedItem> items = {
  {structured_headers::Item("hello", structured_headers::Item::kStringType), {}},
  {structured_headers::Item(123), {{"p", structured_headers::Item(1.0)}}},
  {structured_headers::Item("aaa", structured_headers::Item::kByteSequenceType), {}}
};
```

**假设输入 (序列化):**

```c++
structured_headers::List my_list = {
  structured_headers::ParameterizedMember(structured_headers::Item("token", structured_headers::Item::kTokenType), {}),
  structured_headers::ParameterizedMember({
      structured_headers::ParameterizedItem(structured_headers::Item("inner"), {}),
      structured_headers::ParameterizedItem(structured_headers::Item(true), {})
  }, true, {{"param", structured_headers::Item("value", structured_headers::Item::kStringType)}})
};
```

**预期输出 (序列化后的字符串):**

```
Output String: token, (inner ?1);param="value"
```

**用户或编程常见的使用错误及举例说明:**

1. **格式错误的输入字符串:**  如果提供给解析器的字符串不符合 RFC8941 的语法，解析会失败。

   ```c++
   std::optional<structured_headers::List> result = structured_headers::ParseList("invalid,header;");
   // result 将会是 std::nullopt
   ```

2. **序列化不支持的类型:** 尝试序列化无法表示为结构化头部的值。

   ```c++
   structured_headers::Item my_item(std::numeric_limits<double>::infinity());
   std::optional<std::string> serialized = structured_headers::SerializeItem(my_item);
   // serialized 将会是 std::nullopt
   ```

3. **超出范围的数值:**  结构化头部对整数和浮点数有范围限制。

   ```c++
   structured_headers::Item large_int(10000000000000000LL); // 超出 kMaxInteger
   std::optional<std::string> serialized = structured_headers::SerializeItem(large_int);
   // serialized 将会是 std::nullopt
   ```

4. **使用旧的语法 (对于 `kFinal` 版本的解析器):**  例如，使用 `?T` 或 `?F` 表示布尔值，这在 RFC8941 中被 `?1` 和 `?0` 替代。

5. **不正确的转义:** 在字符串或字节序列中使用了错误的转义字符。

**用户操作如何一步步地到达这里，作为调试线索:**

1. **用户在浏览器中发起一个 HTTP 请求:** 这可能是通过点击链接、提交表单、或者 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发起请求。

2. **服务器返回一个包含结构化头部的 HTTP 响应:**  例如，服务器设置了一个 `Cache-Control` 头部，其中使用了结构化头部语法来表示缓存指令。

3. **Chromium 网络栈接收到响应:**  网络栈开始解析响应头。

4. **遇到需要解析的结构化头部:**  例如，解析器遇到了 `Cache-Control` 头部，并且判断其值需要按照结构化头部规范进行解析。

5. **调用 `structured_headers.cc` 中的解析函数:**  根据头部的类型和规范版本，会调用相应的解析函数，例如 `ParseList` 或 `ParseDictionary`。

6. **解析过程中出现错误 (如果存在):**  如果在解析过程中发现格式错误，解析函数可能会返回 `std::nullopt`，并且可能会有日志输出 (通过 `QUICHE_DVLOG`)。

**调试线索:**

- **检查 HTTP 响应头:** 使用浏览器开发者工具的网络面板查看服务器返回的原始响应头，确认结构化头部的值是否符合预期。
- **查看 Chromium 的网络日志:** 启用 Chromium 的网络日志 (可以使用 `--log-net-log` 命令行参数) 可以查看更详细的网络活动，包括头部解析的细节和可能的错误信息。
- **在 `structured_headers.cc` 中设置断点:**  如果怀疑是解析器本身的问题，可以在相关的解析函数 (如 `ReadList`, `ReadItem`, `ReadString` 等) 中设置断点，逐步跟踪解析过程，查看输入字符串和解析状态。
- **检查解析器的版本:**  `StructuredHeaderParser` 构造函数接受一个 `DraftVersion` 参数，确认解析器使用的是正确的版本 (例如，对于 RFC8941 应该使用 `kFinal`)。
- **检查相关的调用栈:**  查看是谁调用了 `structured_headers.cc` 中的函数，这可以帮助理解在哪个上下文发生了错误。

总而言之，`structured_headers.cc` 是 Chromium 网络栈中处理 HTTP 结构化头部的核心组件，它负责将复杂的头部信息转换为程序可以理解的数据结构，以及将这些数据结构转换回符合规范的字符串，从而使得 HTTP 头部能够表达更丰富的信息。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/structured_headers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/structured_headers.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quiche {
namespace structured_headers {

namespace {

#define DIGIT "0123456789"
#define LCALPHA "abcdefghijklmnopqrstuvwxyz"
#define UCALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define TCHAR DIGIT LCALPHA UCALPHA "!#$%&'*+-.^_`|~"
// https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-09#section-3.9
constexpr char kTokenChars09[] = DIGIT UCALPHA LCALPHA "_-.:%*/";
// https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.4
constexpr char kTokenChars[] = TCHAR ":/";
// https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-09#section-3.1
constexpr char kKeyChars09[] = DIGIT LCALPHA "_-";
// https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1.2
constexpr char kKeyChars[] = DIGIT LCALPHA "_-.*";
constexpr char kSP[] = " ";
constexpr char kOWS[] = " \t";
#undef DIGIT
#undef LCALPHA
#undef UCALPHA

// https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.1
constexpr int64_t kMaxInteger = 999'999'999'999'999L;
constexpr int64_t kMinInteger = -999'999'999'999'999L;

// Smallest value which is too large for an sh-decimal. This is the smallest
// double which will round up to 1e12 when serialized, which exceeds the range
// for sh-decimal. Any float less than this should round down. This behaviour is
// verified by unit tests.
constexpr double kTooLargeDecimal = 1e12 - 0.0005;

// Removes characters in remove from the beginning of s.
void StripLeft(absl::string_view& s, absl::string_view remove) {
  size_t i = s.find_first_not_of(remove);
  if (i == absl::string_view::npos) {
    i = s.size();
  }
  s.remove_prefix(i);
}

// Parser for (a subset of) Structured Headers for HTTP defined in [SH09] and
// [RFC8941]. [SH09] compatibility is retained for use by Web Packaging, and can
// be removed once that spec is updated, and users have migrated to new headers.
// [SH09] https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-09
// [RFC8941] https://www.rfc-editor.org/rfc/rfc8941.html
class StructuredHeaderParser {
 public:
  enum DraftVersion {
    kDraft09,
    kFinal,
  };
  explicit StructuredHeaderParser(absl::string_view str, DraftVersion version)
      : input_(str), version_(version) {
    // [SH09] 4.2 Step 1.
    // Discard any leading OWS from input_string.
    // [RFC8941] 4.2 Step 2.
    // Discard any leading SP characters from input_string.
    SkipWhitespaces();
  }
  StructuredHeaderParser(const StructuredHeaderParser&) = delete;
  StructuredHeaderParser& operator=(const StructuredHeaderParser&) = delete;

  // Callers should call this after ReadSomething(), to check if parser has
  // consumed all the input successfully.
  bool FinishParsing() {
    // [SH09] 4.2 Step 7.
    // Discard any leading OWS from input_string.
    // [RFC8941] 4.2 Step 6.
    // Discard any leading SP characters from input_string.
    SkipWhitespaces();
    // [SH09] 4.2 Step 8. [RFC8941] 4.2 Step 7.
    // If input_string is not empty, fail parsing.
    return input_.empty();
  }

  // Parses a List of Lists ([SH09] 4.2.4).
  std::optional<ListOfLists> ReadListOfLists() {
    QUICHE_CHECK_EQ(version_, kDraft09);
    ListOfLists result;
    while (true) {
      std::vector<Item> inner_list;
      while (true) {
        std::optional<Item> item(ReadBareItem());
        if (!item) return std::nullopt;
        inner_list.push_back(std::move(*item));
        SkipWhitespaces();
        if (!ConsumeChar(';')) break;
        SkipWhitespaces();
      }
      result.push_back(std::move(inner_list));
      SkipWhitespaces();
      if (!ConsumeChar(',')) break;
      SkipWhitespaces();
    }
    return result;
  }

  // Parses a List ([RFC8941] 4.2.1).
  std::optional<List> ReadList() {
    QUICHE_CHECK_EQ(version_, kFinal);
    List members;
    while (!input_.empty()) {
      std::optional<ParameterizedMember> member(ReadItemOrInnerList());
      if (!member) return std::nullopt;
      members.push_back(std::move(*member));
      SkipOWS();
      if (input_.empty()) break;
      if (!ConsumeChar(',')) return std::nullopt;
      SkipOWS();
      if (input_.empty()) return std::nullopt;
    }
    return members;
  }

  // Parses an Item ([RFC8941] 4.2.3).
  std::optional<ParameterizedItem> ReadItem() {
    std::optional<Item> item = ReadBareItem();
    if (!item) return std::nullopt;
    std::optional<Parameters> parameters = ReadParameters();
    if (!parameters) return std::nullopt;
    return ParameterizedItem(std::move(*item), std::move(*parameters));
  }

  // Parses a bare Item ([RFC8941] 4.2.3.1, though this is also the algorithm
  // for parsing an Item from [SH09] 4.2.7).
  std::optional<Item> ReadBareItem() {
    if (input_.empty()) {
      QUICHE_DVLOG(1) << "ReadBareItem: unexpected EOF";
      return std::nullopt;
    }
    switch (input_.front()) {
      case '"':
        return ReadString();
      case '*':
        if (version_ == kDraft09) return ReadByteSequence();
        return ReadToken();
      case ':':
        if (version_ == kFinal) return ReadByteSequence();
        return std::nullopt;
      case '?':
        return ReadBoolean();
      default:
        if (input_.front() == '-' || absl::ascii_isdigit(input_.front()))
          return ReadNumber();
        if (absl::ascii_isalpha(input_.front())) return ReadToken();
        return std::nullopt;
    }
  }

  // Parses a Dictionary ([RFC8941] 4.2.2).
  std::optional<Dictionary> ReadDictionary() {
    QUICHE_CHECK_EQ(version_, kFinal);
    Dictionary members;
    while (!input_.empty()) {
      std::optional<std::string> key(ReadKey());
      if (!key) return std::nullopt;
      std::optional<ParameterizedMember> member;
      if (ConsumeChar('=')) {
        member = ReadItemOrInnerList();
        if (!member) return std::nullopt;
      } else {
        std::optional<Parameters> parameters = ReadParameters();
        if (!parameters) return std::nullopt;
        member = ParameterizedMember{Item(true), std::move(*parameters)};
      }
      members[*key] = std::move(*member);
      SkipOWS();
      if (input_.empty()) break;
      if (!ConsumeChar(',')) return std::nullopt;
      SkipOWS();
      if (input_.empty()) return std::nullopt;
    }
    return members;
  }

  // Parses a Parameterised List ([SH09] 4.2.5).
  std::optional<ParameterisedList> ReadParameterisedList() {
    QUICHE_CHECK_EQ(version_, kDraft09);
    ParameterisedList items;
    while (true) {
      std::optional<ParameterisedIdentifier> item =
          ReadParameterisedIdentifier();
      if (!item) return std::nullopt;
      items.push_back(std::move(*item));
      SkipWhitespaces();
      if (!ConsumeChar(',')) return items;
      SkipWhitespaces();
    }
  }

 private:
  // Parses a Parameterised Identifier ([SH09] 4.2.6).
  std::optional<ParameterisedIdentifier> ReadParameterisedIdentifier() {
    QUICHE_CHECK_EQ(version_, kDraft09);
    std::optional<Item> primary_identifier = ReadToken();
    if (!primary_identifier) return std::nullopt;

    ParameterisedIdentifier::Parameters parameters;

    SkipWhitespaces();
    while (ConsumeChar(';')) {
      SkipWhitespaces();

      std::optional<std::string> name = ReadKey();
      if (!name) return std::nullopt;

      Item value;
      if (ConsumeChar('=')) {
        auto item = ReadBareItem();
        if (!item) return std::nullopt;
        value = std::move(*item);
      }
      if (!parameters.emplace(*name, std::move(value)).second) {
        QUICHE_DVLOG(1) << "ReadParameterisedIdentifier: duplicated parameter: "
                        << *name;
        return std::nullopt;
      }
      SkipWhitespaces();
    }
    return ParameterisedIdentifier(std::move(*primary_identifier),
                                   std::move(parameters));
  }

  // Parses an Item or Inner List ([RFC8941] 4.2.1.1).
  std::optional<ParameterizedMember> ReadItemOrInnerList() {
    QUICHE_CHECK_EQ(version_, kFinal);
    bool member_is_inner_list = (!input_.empty() && input_.front() == '(');
    if (member_is_inner_list) {
      return ReadInnerList();
    } else {
      auto item = ReadItem();
      if (!item) return std::nullopt;
      return ParameterizedMember(std::move(item->item),
                                 std::move(item->params));
    }
  }

  // Parses Parameters ([RFC8941] 4.2.3.2)
  std::optional<Parameters> ReadParameters() {
    Parameters parameters;
    absl::flat_hash_set<std::string> keys;

    while (ConsumeChar(';')) {
      SkipWhitespaces();

      std::optional<std::string> name = ReadKey();
      if (!name) return std::nullopt;
      bool is_duplicate_key = !keys.insert(*name).second;

      Item value{true};
      if (ConsumeChar('=')) {
        auto item = ReadBareItem();
        if (!item) return std::nullopt;
        value = std::move(*item);
      }
      if (is_duplicate_key) {
        for (auto& param : parameters) {
          if (param.first == name) {
            param.second = std::move(value);
            break;
          }
        }
      } else {
        parameters.emplace_back(std::move(*name), std::move(value));
      }
    }
    return parameters;
  }

  // Parses an Inner List ([RFC8941] 4.2.1.2).
  std::optional<ParameterizedMember> ReadInnerList() {
    QUICHE_CHECK_EQ(version_, kFinal);
    if (!ConsumeChar('(')) return std::nullopt;
    std::vector<ParameterizedItem> inner_list;
    while (true) {
      SkipWhitespaces();
      if (ConsumeChar(')')) {
        std::optional<Parameters> parameters = ReadParameters();
        if (!parameters) return std::nullopt;
        return ParameterizedMember(std::move(inner_list), true,
                                   std::move(*parameters));
      }
      auto item = ReadItem();
      if (!item) return std::nullopt;
      inner_list.push_back(std::move(*item));
      if (input_.empty() || (input_.front() != ' ' && input_.front() != ')'))
        return std::nullopt;
    }
    QUICHE_NOTREACHED();
    return std::nullopt;
  }

  // Parses a Key ([SH09] 4.2.2, [RFC8941] 4.2.3.3).
  std::optional<std::string> ReadKey() {
    if (version_ == kDraft09) {
      if (input_.empty() || !absl::ascii_islower(input_.front())) {
        LogParseError("ReadKey", "lcalpha");
        return std::nullopt;
      }
    } else {
      if (input_.empty() ||
          (!absl::ascii_islower(input_.front()) && input_.front() != '*')) {
        LogParseError("ReadKey", "lcalpha | *");
        return std::nullopt;
      }
    }
    const char* allowed_chars =
        (version_ == kDraft09 ? kKeyChars09 : kKeyChars);
    size_t len = input_.find_first_not_of(allowed_chars);
    if (len == absl::string_view::npos) len = input_.size();
    std::string key(input_.substr(0, len));
    input_.remove_prefix(len);
    return key;
  }

  // Parses a Token ([SH09] 4.2.10, [RFC8941] 4.2.6).
  std::optional<Item> ReadToken() {
    if (input_.empty() ||
        !(absl::ascii_isalpha(input_.front()) || input_.front() == '*')) {
      LogParseError("ReadToken", "ALPHA");
      return std::nullopt;
    }
    size_t len = input_.find_first_not_of(version_ == kDraft09 ? kTokenChars09
                                                               : kTokenChars);
    if (len == absl::string_view::npos) len = input_.size();
    std::string token(input_.substr(0, len));
    input_.remove_prefix(len);
    return Item(std::move(token), Item::kTokenType);
  }

  // Parses a Number ([SH09] 4.2.8, [RFC8941] 4.2.4).
  std::optional<Item> ReadNumber() {
    bool is_negative = ConsumeChar('-');
    bool is_decimal = false;
    size_t decimal_position = 0;
    size_t i = 0;
    for (; i < input_.size(); ++i) {
      if (i > 0 && input_[i] == '.' && !is_decimal) {
        is_decimal = true;
        decimal_position = i;
        continue;
      }
      if (!absl::ascii_isdigit(input_[i])) break;
    }
    if (i == 0) {
      LogParseError("ReadNumber", "DIGIT");
      return std::nullopt;
    }
    if (!is_decimal) {
      // [RFC8941] restricts the range of integers further.
      if (version_ == kFinal && i > 15) {
        LogParseError("ReadNumber", "integer too long");
        return std::nullopt;
      }
    } else {
      if (version_ != kFinal && i > 16) {
        LogParseError("ReadNumber", "float too long");
        return std::nullopt;
      }
      if (version_ == kFinal && decimal_position > 12) {
        LogParseError("ReadNumber", "decimal too long");
        return std::nullopt;
      }
      if (i - decimal_position > (version_ == kFinal ? 4 : 7)) {
        LogParseError("ReadNumber", "too many digits after decimal");
        return std::nullopt;
      }
      if (i == decimal_position) {
        LogParseError("ReadNumber", "no digits after decimal");
        return std::nullopt;
      }
    }
    std::string output_number_string(input_.substr(0, i));
    input_.remove_prefix(i);

    if (is_decimal) {
      // Convert to a 64-bit double, and return if the conversion is
      // successful.
      double f;
      if (!absl::SimpleAtod(output_number_string, &f)) return std::nullopt;
      return Item(is_negative ? -f : f);
    } else {
      // Convert to a 64-bit signed integer, and return if the conversion is
      // successful.
      int64_t n;
      if (!absl::SimpleAtoi(output_number_string, &n)) return std::nullopt;
      QUICHE_CHECK(version_ != kFinal ||
                   (n <= kMaxInteger && n >= kMinInteger));
      return Item(is_negative ? -n : n);
    }
  }

  // Parses a String ([SH09] 4.2.9, [RFC8941] 4.2.5).
  std::optional<Item> ReadString() {
    std::string s;
    if (!ConsumeChar('"')) {
      LogParseError("ReadString", "'\"'");
      return std::nullopt;
    }
    while (!ConsumeChar('"')) {
      size_t i = 0;
      for (; i < input_.size(); ++i) {
        if (!absl::ascii_isprint(input_[i])) {
          QUICHE_DVLOG(1) << "ReadString: non printable-ASCII character";
          return std::nullopt;
        }
        if (input_[i] == '"' || input_[i] == '\\') break;
      }
      if (i == input_.size()) {
        QUICHE_DVLOG(1) << "ReadString: missing closing '\"'";
        return std::nullopt;
      }
      s.append(std::string(input_.substr(0, i)));
      input_.remove_prefix(i);
      if (ConsumeChar('\\')) {
        if (input_.empty()) {
          QUICHE_DVLOG(1) << "ReadString: backslash at string end";
          return std::nullopt;
        }
        if (input_[0] != '"' && input_[0] != '\\') {
          QUICHE_DVLOG(1) << "ReadString: invalid escape";
          return std::nullopt;
        }
        s.push_back(input_.front());
        input_.remove_prefix(1);
      }
    }
    return s;
  }

  // Parses a Byte Sequence ([SH09] 4.2.11, [RFC8941] 4.2.7).
  std::optional<Item> ReadByteSequence() {
    char delimiter = (version_ == kDraft09 ? '*' : ':');
    if (!ConsumeChar(delimiter)) {
      LogParseError("ReadByteSequence", "delimiter");
      return std::nullopt;
    }
    size_t len = input_.find(delimiter);
    if (len == absl::string_view::npos) {
      QUICHE_DVLOG(1) << "ReadByteSequence: missing closing delimiter";
      return std::nullopt;
    }
    std::string base64(input_.substr(0, len));
    // Append the necessary padding characters.
    base64.resize((base64.size() + 3) / 4 * 4, '=');

    std::string binary;
    if (!absl::Base64Unescape(base64, &binary)) {
      QUICHE_DVLOG(1) << "ReadByteSequence: failed to decode base64: "
                      << base64;
      return std::nullopt;
    }
    input_.remove_prefix(len);
    ConsumeChar(delimiter);
    return Item(std::move(binary), Item::kByteSequenceType);
  }

  // Parses a Boolean ([RFC8941] 4.2.8).
  // Note that this only parses ?0 and ?1 forms from SH version 10+, not the
  // previous ?F and ?T, which were not needed by any consumers of SH version 9.
  std::optional<Item> ReadBoolean() {
    if (!ConsumeChar('?')) {
      LogParseError("ReadBoolean", "'?'");
      return std::nullopt;
    }
    if (ConsumeChar('1')) {
      return Item(true);
    }
    if (ConsumeChar('0')) {
      return Item(false);
    }
    return std::nullopt;
  }

  // There are several points in the specs where the handling of whitespace
  // differs between Draft 9 and the final RFC. In those cases, Draft 9 allows
  // any OWS character, while the RFC allows only a U+0020 SPACE.
  void SkipWhitespaces() {
    if (version_ == kDraft09) {
      StripLeft(input_, kOWS);
    } else {
      StripLeft(input_, kSP);
    }
  }

  void SkipOWS() { StripLeft(input_, kOWS); }

  bool ConsumeChar(char expected) {
    if (!input_.empty() && input_.front() == expected) {
      input_.remove_prefix(1);
      return true;
    }
    return false;
  }

  void LogParseError(const char* func, const char* expected) {
    QUICHE_DVLOG(1) << func << ": " << expected << " expected, got "
                    << (input_.empty()
                            ? "EOS"
                            : "'" + std::string(input_.substr(0, 1)) + "'");
  }

  absl::string_view input_;
  DraftVersion version_;
};

// Serializer for (a subset of) Structured Field Values for HTTP defined in
// [RFC8941]. Note that this serializer does not attempt to support [SH09].
class StructuredHeaderSerializer {
 public:
  StructuredHeaderSerializer() = default;
  ~StructuredHeaderSerializer() = default;
  StructuredHeaderSerializer(const StructuredHeaderSerializer&) = delete;
  StructuredHeaderSerializer& operator=(const StructuredHeaderSerializer&) =
      delete;

  std::string Output() { return output_.str(); }

  // Serializes a List ([RFC8941] 4.1.1).
  bool WriteList(const List& value) {
    bool first = true;
    for (const auto& member : value) {
      if (!first) output_ << ", ";
      if (!WriteParameterizedMember(member)) return false;
      first = false;
    }
    return true;
  }

  // Serializes an Item ([RFC8941] 4.1.3).
  bool WriteItem(const ParameterizedItem& value) {
    if (!WriteBareItem(value.item)) return false;
    return WriteParameters(value.params);
  }

  // Serializes an Item ([RFC8941] 4.1.3).
  bool WriteBareItem(const Item& value) {
    if (value.is_string()) {
      // Serializes a String ([RFC8941] 4.1.6).
      output_ << "\"";
      for (const char& c : value.GetString()) {
        if (!absl::ascii_isprint(c)) return false;
        if (c == '\\' || c == '\"') output_ << "\\";
        output_ << c;
      }
      output_ << "\"";
      return true;
    }
    if (value.is_token()) {
      // Serializes a Token ([RFC8941] 4.1.7).
      if (!IsValidToken(value.GetString())) {
        return false;
      }
      output_ << value.GetString();
      return true;
    }
    if (value.is_byte_sequence()) {
      // Serializes a Byte Sequence ([RFC8941] 4.1.8).
      output_ << ":";
      output_ << absl::Base64Escape(value.GetString());
      output_ << ":";
      return true;
    }
    if (value.is_integer()) {
      // Serializes an Integer ([RFC8941] 4.1.4).
      if (value.GetInteger() > kMaxInteger || value.GetInteger() < kMinInteger)
        return false;
      output_ << value.GetInteger();
      return true;
    }
    if (value.is_decimal()) {
      // Serializes a Decimal ([RFC8941] 4.1.5).
      double decimal_value = value.GetDecimal();
      if (!std::isfinite(decimal_value) ||
          fabs(decimal_value) >= kTooLargeDecimal)
        return false;

      // Handle sign separately to simplify the rest of the formatting.
      if (decimal_value < 0) output_ << "-";
      // Unconditionally take absolute value to ensure that -0 is serialized as
      // "0.0", with no negative sign, as required by spec. (4.1.5, step 2).
      decimal_value = fabs(decimal_value);
      double remainder = fmod(decimal_value, 0.002);
      if (remainder == 0.0005) {
        // Value ended in exactly 0.0005, 0.0025, 0.0045, etc. Round down.
        decimal_value -= 0.0005;
      } else if (remainder == 0.0015) {
        // Value ended in exactly 0.0015, 0.0035, 0,0055, etc. Round up.
        decimal_value += 0.0005;
      } else {
        // Standard rounding will work in all other cases.
        decimal_value = round(decimal_value * 1000.0) / 1000.0;
      }

      // Use standard library functions to write the decimal, and then truncate
      // if necessary to conform to spec.

      // Maximum is 12 integer digits, one decimal point, three fractional
      // digits, and a null terminator.
      char buffer[17];
      absl::SNPrintF(buffer, std::size(buffer), "%#.3f", decimal_value);

      // Strip any trailing 0s after the decimal point, but leave at least one
      // digit after it in all cases. (So 1.230 becomes 1.23, but 1.000 becomes
      // 1.0.)
      absl::string_view formatted_number(buffer);
      auto truncate_index = formatted_number.find_last_not_of('0');
      if (formatted_number[truncate_index] == '.') truncate_index++;
      output_ << formatted_number.substr(0, truncate_index + 1);
      return true;
    }
    if (value.is_boolean()) {
      // Serializes a Boolean ([RFC8941] 4.1.9).
      output_ << (value.GetBoolean() ? "?1" : "?0");
      return true;
    }
    return false;
  }

  // Serializes a Dictionary ([RFC8941] 4.1.2).
  bool WriteDictionary(const Dictionary& value) {
    bool first = true;
    for (const auto& [dict_key, dict_value] : value) {
      if (!first) output_ << ", ";
      if (!WriteKey(dict_key)) return false;
      first = false;
      if (!dict_value.member_is_inner_list && !dict_value.member.empty() &&
          dict_value.member.front().item.is_boolean() &&
          dict_value.member.front().item.GetBoolean()) {
        if (!WriteParameters(dict_value.params)) return false;
      } else {
        output_ << "=";
        if (!WriteParameterizedMember(dict_value)) return false;
      }
    }
    return true;
  }

 private:
  bool WriteParameterizedMember(const ParameterizedMember& value) {
    // Serializes a parameterized member ([RFC8941] 4.1.1).
    if (value.member_is_inner_list) {
      if (!WriteInnerList(value.member)) return false;
    } else {
      QUICHE_CHECK_EQ(value.member.size(), 1UL);
      if (!WriteItem(value.member[0])) return false;
    }
    return WriteParameters(value.params);
  }

  bool WriteInnerList(const std::vector<ParameterizedItem>& value) {
    // Serializes an inner list ([RFC8941] 4.1.1.1).
    output_ << "(";
    bool first = true;
    for (const ParameterizedItem& member : value) {
      if (!first) output_ << " ";
      if (!WriteItem(member)) return false;
      first = false;
    }
    output_ << ")";
    return true;
  }

  bool WriteParameters(const Parameters& value) {
    // Serializes a parameter list ([RFC8941] 4.1.1.2).
    for (const auto& param_name_and_value : value) {
      const std::string& param_name = param_name_and_value.first;
      const Item& param_value = param_name_and_value.second;
      output_ << ";";
      if (!WriteKey(param_name)) return false;
      if (!param_value.is_null()) {
        if (param_value.is_boolean() && param_value.GetBoolean()) continue;
        output_ << "=";
        if (!WriteBareItem(param_value)) return false;
      }
    }
    return true;
  }

  bool WriteKey(const std::string& value) {
    // Serializes a Key ([RFC8941] 4.1.1.3).
    if (value.empty()) return false;
    if (value.find_first_not_of(kKeyChars) != std::string::npos) return false;
    if (!absl::ascii_islower(value[0]) && value[0] != '*') return false;
    output_ << value;
    return true;
  }

  std::ostringstream output_;
};

}  // namespace

absl::string_view ItemTypeToString(Item::ItemType type) {
  switch (type) {
    case Item::kNullType:
      return "null";
    case Item::kIntegerType:
      return "integer";
    case Item::kDecimalType:
      return "decimal";
    case Item::kStringType:
      return "string";
    case Item::kTokenType:
      return "token";
    case Item::kByteSequenceType:
      return "byte sequence";
    case Item::kBooleanType:
      return "boolean";
  }
  return "[invalid type]";
}

bool IsValidToken(absl::string_view str) {
  // Validate Token value per [RFC8941] 4.1.7.
  if (str.empty() ||
      !(absl::ascii_isalpha(str.front()) || str.front() == '*')) {
    return false;
  }
  if (str.find_first_not_of(kTokenChars) != std::string::npos) {
    return false;
  }
  return true;
}

Item::Item() {}
Item::Item(std::string value, Item::ItemType type) {
  switch (type) {
    case kStringType:
      value_.emplace<kStringType>(std::move(value));
      break;
    case kTokenType:
      value_.emplace<kTokenType>(std::move(value));
      break;
    case kByteSequenceType:
      value_.emplace<kByteSequenceType>(std::move(value));
      break;
    default:
      QUICHE_CHECK(false);
      break;
  }
}
Item::Item(const char* value, Item::ItemType type)
    : Item(std::string(value), type) {}
Item::Item(int64_t value) : value_(value) {}
Item::Item(double value) : value_(value) {}
Item::Item(bool value) : value_(value) {}

bool operator==(const Item& lhs, const Item& rhs) {
  return lhs.value_ == rhs.value_;
}

ParameterizedItem::ParameterizedItem() = default;
ParameterizedItem::ParameterizedItem(const ParameterizedItem&) = default;
ParameterizedItem& ParameterizedItem::operator=(const ParameterizedItem&) =
    default;
ParameterizedItem::ParameterizedItem(Item id, Parameters ps)
    : item(std::move(id)), params(std::move(ps)) {}
ParameterizedItem::~ParameterizedItem() = default;

ParameterizedMember::ParameterizedMember() = default;
ParameterizedMember::ParameterizedMember(const ParameterizedMember&) = default;
ParameterizedMember& ParameterizedMember::operator=(
    const ParameterizedMember&) = default;
ParameterizedMember::ParameterizedMember(std::vector<ParameterizedItem> id,
                                         bool member_is_inner_list,
                                         Parameters ps)
    : member(std::move(id)),
      member_is_inner_list(member_is_inner_list),
      params(std::move(ps)) {}
ParameterizedMember::ParameterizedMember(std::vector<ParameterizedItem> id,
                                         Parameters ps)
    : member(std::move(id)),
      member_is_inner_list(true),
      params(std::move(ps)) {}
ParameterizedMember::ParameterizedMember(Item id, Parameters ps)
    : member({{std::move(id), {}}}),
      member_is_inner_list(false),
      params(std::move(ps)) {}
ParameterizedMember::~ParameterizedMember() = default;

ParameterisedIdentifier::ParameterisedIdentifier() = default;
ParameterisedIdentifier::ParameterisedIdentifier(
    const ParameterisedIdentifier&) = default;
ParameterisedIdentifier& ParameterisedIdentifier::operator=(
    const ParameterisedIdentifier&) = default;
ParameterisedIdentifier::ParameterisedIdentifier(Item id, Parameters ps)
    : identifier(std::move(id)), params(std::move(ps)) {}
ParameterisedIdentifier::~ParameterisedIdentifier() = default;

Dictionary::Dictionary() = default;
Dictionary::Dictionary(const Dictionary&) = default;
Dictionary::Dictionary(Dictionary&&) = default;
Dictionary::Dictionary(std::vector<DictionaryMember> members)
    : members_(std::move(members)) {}
Dictionary::~Dictionary() = default;
Dictionary::iterator Dictionary::begin() { return members_.begin(); }
Dictionary::const_iterator Dictionary::begin() const {
  return members_.begin();
}
Dictionary::iterator Dictionary::end() { return members_.end(); }
Dictionary::const_iterator Dictionary::end() const { return members_.end(); }
ParameterizedMember& Dictionary::operator[](std::size_t idx) {
  return members_[idx].second;
}
const ParameterizedMember& Dictionary::operator[](std::size_t idx) const {
  return members_[idx].second;
}
ParameterizedMember& Dictionary::at(std::size_t idx) { return (*this)[idx]; }
const ParameterizedMember& Dictionary::at(std::size_t idx) const {
  return (*this)[idx];
}
ParameterizedMember& Dictionary::operator[](absl::string_view key) {
  auto it = find(key);
  if (it != end()) return it->second;
  return members_.emplace_back(key, ParameterizedMember()).second;
}
ParameterizedMember& Dictionary::at(absl::string_view key) {
  auto it = find(key);
  QUICHE_CHECK(it != end()) << "Provided key not found in dictionary";
  return it->second;
}
const ParameterizedMember& Dictionary::at(absl::string_view key) const {
  auto it = find(key);
  QUICHE_CHECK(it != end()) << "Provided key not found in dictionary";
  return it->second;
}
Dictionary::const_iterator Dictionary::find(absl::string_view key) const {
  return absl::c_find_if(
      members_, [key](const auto& member) { return member.first == key; });
}
Dictionary::iterator Dictionary::find(absl::string_view key) {
  return absl::c_find_if(
      members_, [key](const auto& member) { return member.first == key; });
}
bool Dictionary::empty() const { return members_.empty(); }
std::size_t Dictionary::size() const { return members_.size(); }
bool Dictionary::contains(absl::string_view key) const {
  return find(key) != end();
}
void Dictionary::clear() { members_.clear(); }

std::optional<ParameterizedItem> ParseItem(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kFinal);
  std::optional<ParameterizedItem> item = parser.ReadItem();
  if (item && parser.FinishParsing()) return item;
  return std::nullopt;
}

std::optional<Item> ParseBareItem(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kFinal);
  std::optional<Item> item = parser.ReadBareItem();
  if (item && parser.FinishParsing()) return item;
  return std::nullopt;
}

std::optional<ParameterisedList> ParseParameterisedList(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kDraft09);
  std::optional<ParameterisedList> param_list = parser.ReadParameterisedList();
  if (param_list && parser.FinishParsing()) return param_list;
  return std::nullopt;
}

std::optional<ListOfLists> ParseListOfLists(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kDraft09);
  std::optional<ListOfLists> list_of_lists = parser.ReadListOfLists();
  if (list_of_lists && parser.FinishParsing()) return list_of_lists;
  return std::nullopt;
}

std::optional<List> ParseList(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kFinal);
  std::optional<List> list = parser.ReadList();
  if (list && parser.FinishParsing()) return list;
  return std::nullopt;
}

std::optional<Dictionary> ParseDictionary(absl::string_view str) {
  StructuredHeaderParser parser(str, StructuredHeaderParser::kFinal);
  std::optional<Dictionary> dictionary = parser.ReadDictionary();
  if (dictionary && parser.FinishParsing()) return dictionary;
  return std::nullopt;
}

std::optional<std::string> SerializeItem(const Item& value) {
  StructuredHeaderSerializer s;
  if (s.WriteItem(ParameterizedItem(value, {}))) return s.Output();
  return std::nullopt;
}

std::optional<std::string> SerializeItem(const ParameterizedItem& value) {
  StructuredHeaderSerializer s;
  if (s.WriteItem(value)) return s.Output();
  return std::nullopt;
}

std::optional<std::string> SerializeList(const List& value) {
  StructuredHeaderSerializer s;
  if (s.WriteList(value)) return s.Output();
  return std::nullopt;
}

std::optional<std::string> SerializeDictionary(const Dictionary& value) {
  StructuredHeaderSerializer s;
  if (s.WriteDictionary(value)) return s.Output();
  return std::nullopt;
}

}  // namespace structured_headers
}  // namespace quiche

"""

```