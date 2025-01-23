Response:
The user wants to understand the functionality of the C++ source code file `wtf_string_test.cc` within the Chromium Blink engine. I need to:

1. **Identify the primary purpose of the file:**  The file name strongly suggests it contains unit tests for the `wtf_string.h` header file, which likely defines a string class used within Blink.

2. **Analyze the test cases:** I need to go through each `TEST` macro and understand what aspect of the `String` class is being tested. This includes:
    * Creation of `String` objects
    * Comparison of `String` objects
    * Hashing of `String` objects
    * Case-insensitive comparisons
    * String manipulation functions (like `Replace`, `SimplifyWhiteSpace`)
    * Conversion to other types (like ASCII)
    * Special cases (empty strings, null strings, numbers)
    * Interactions with other WTF utilities (like `HashTraits`)

3. **Determine relationships to web technologies:**  Since this is part of a browser engine, I need to consider how the `String` class and its functionalities relate to JavaScript, HTML, and CSS. This involves thinking about:
    * How strings are used in representing HTML content (tags, attributes, text content).
    * How strings are used in CSS (selectors, property values).
    * How JavaScript interacts with strings (string manipulation, comparisons).

4. **Identify logical inferences and create examples:**  For tests that involve logical operations, I'll create example inputs and expected outputs to illustrate the behavior.

5. **Pinpoint potential user errors:** Based on the tested functionalities, I need to consider common mistakes developers might make when working with strings, especially in the context of web development.

**Detailed Breakdown of Steps:**

* **File Purpose Confirmation:** The `#include "testing/gtest/include/gtest/gtest.h"` at the top confirms this is a unit test file using the Google Test framework. The inclusion of `wtf_string.h` confirms it's testing the `String` class.

* **Test Case Analysis (Iterative):** I'll go through each `TEST` block:
    * `CreationFromLiteral`: Tests creating strings from string literals.
    * `CreationFromHashTraits`: Tests interaction with `HashTraits`, including empty/null strings and hashing.
    * `EqualHashTraits`: Tests equality comparisons through `HashTraits`.
    * `ASCII`: Tests conversion to ASCII.
    * `NumberToStringECMAScript...`: Tests converting numbers to ECMAScript string format (relevant to JavaScript).
    * `ReplaceWithLiteral`: Tests the `Replace` method with different replacement strings (empty, single char, multiple chars, not found).
    * `ComparisonOfSameStringVectors`: Tests comparing vectors of strings.
    * `LengthWithStrippedWhiteSpace`: Tests calculating string length after removing leading/trailing whitespace.
    * `SimplifyWhiteSpace`: Tests replacing multiple spaces/newlines with single spaces.
    * `StartsWithIgnoringUnicodeCase`, `StartsWithIgnoringASCIICase`, `EndsWithIgnoringASCIICase`, `EqualIgnoringASCIICase`, `FindIgnoringASCIICase`: Test case-insensitive string operations.
    * `DeprecatedLower`: Tests converting to lowercase (might be related to older standards).
    * `Ensure16Bit`: Tests ensuring a string is stored in 16-bit format (handles different internal string representations).
    * `StringPrinter`: Tests how `String` objects are printed to output streams (useful for debugging).
    * `FindWithCallback`: Tests finding characters using a custom predicate function.
    * `StartsWithIgnoringCaseAndAccents`: Tests case and accent insensitive string comparison.

* **Relating to Web Technologies:**
    * **HTML:** HTML uses strings for tag names (`<div>`, `<p>`), attributes (`class="container"`, `href="…" `), and text content.
    * **CSS:** CSS uses strings for selectors (`.class`, `#id`), property values (`color: red`, `font-family: "Arial"`), and URLs (`url(...)`).
    * **JavaScript:** JavaScript extensively uses strings for variables, manipulating DOM content, handling user input, and interacting with the browser. The ECMAScript number formatting is a direct link.

* **Logical Inference and Examples:**  For tests like `ReplaceWithLiteral`, I can create scenarios like:
    * Input: `String("aabbcc")`, replace 'b' with 'x'. Output: `"aaxxcc"`.
    * Input: `String("aabbcc")`, replace 'b' with "". Output: `"aacc"`.

* **Identifying User Errors:**
    * Incorrectly assuming case sensitivity/insensitivity in comparisons.
    * Not accounting for whitespace when comparing or processing strings.
    * Assuming ASCII-only characters when dealing with internationalized content.
    * Errors in number-to-string conversion when interacting with JavaScript.

By following these steps, I can generate a comprehensive explanation of the `wtf_string_test.cc` file's functionality and its relevance to web technologies, including illustrative examples and common user errors.
这个文件 `blink/renderer/platform/wtf/text/wtf_string_test.cc` 是 Chromium Blink 引擎中用于测试 `wtf_string.h` 中定义的 `String` 类的单元测试文件。它的主要功能是：

**1. 验证 `wtf::String` 类的各种功能和行为是否符合预期。**

    它包含了大量的测试用例，涵盖了 `String` 类的创建、比较、操作、转换等各个方面。

**2. 确保 `wtf::String` 类的稳定性和可靠性。**

    通过运行这些测试用例，开发者可以及时发现和修复 `String` 类中的 bug，防止这些问题影响到 Blink 引擎的其他部分。

**3. 为开发者提供 `wtf::String` 类的使用示例。**

    这些测试用例本身就是 `String` 类各种用法的示例，可以帮助开发者更好地理解和使用这个类。

**与 JavaScript, HTML, CSS 的功能关系：**

`wtf::String` 类在 Blink 引擎中扮演着非常核心的角色，因为它被广泛用于表示和处理文本数据。这与 JavaScript, HTML, CSS 三者都有密切关系：

* **JavaScript:**
    * **字符串表示:** JavaScript 中的字符串在 Blink 引擎内部很可能使用 `wtf::String` 来表示。
    * **字符串操作:** JavaScript 中大量的字符串操作（例如 `substring`, `indexOf`, `replace` 等）在 Blink 引擎的实现中可能会调用 `wtf::String` 提供的相应方法。
    * **与 DOM 交互:** 当 JavaScript 获取或设置 DOM 节点的文本内容、属性值时，这些字符串数据很可能以 `wtf::String` 的形式存在。

    **举例说明:**
    假设 JavaScript 代码 `const myString = "Hello World";` 在 Blink 引擎内部，`myString` 变量很可能关联着一个 `wtf::String` 对象。当 JavaScript 执行 `myString.length` 时，Blink 引擎会调用 `wtf::String` 的 `length()` 方法。

    **假设输入与输出:**
    假设 JavaScript 执行 `myString.replace("World", "Blink")`。
    * **假设输入:** 一个 `wtf::String` 对象，内容为 "Hello World"，以及要替换的子字符串 "World" 和替换字符串 "Blink"。
    * **逻辑推理:** `wtf::String` 的 `Replace` 方法会被调用，找到 "World" 并替换为 "Blink"。
    * **假设输出:** 一个新的 `wtf::String` 对象，内容为 "Hello Blink"。

* **HTML:**
    * **标签和属性:** HTML 标签名（如 `<div>`, `<p>`）、属性名（如 `class`, `id`）和属性值（如 `"container"`, `"my-id"`）都以字符串形式存在，在 Blink 引擎中可能使用 `wtf::String` 表示。
    * **文本内容:** HTML 元素包含的文本内容也是字符串，同样可能使用 `wtf::String` 表示。

    **举例说明:**
    当 Blink 引擎解析 HTML 代码 `<div class="container">Hello</div>` 时，`"div"`, `"class"`, `"container"`, `"Hello"` 这些字符串都可能被存储为 `wtf::String` 对象。

    **假设输入与输出:**
    假设 Blink 引擎正在解析 HTML 文本节点 "Hello World"。
    * **假设输入:** 一个表示文本内容的字符序列 "Hello World"。
    * **逻辑推理:**  Blink 引擎会创建一个 `wtf::String` 对象来存储这个文本内容。
    * **假设输出:** 一个 `wtf::String` 对象，内容为 "Hello World"。

* **CSS:**
    * **选择器:** CSS 选择器（如 `.class`, `#id`, `p`) 是字符串。
    * **属性值:** CSS 属性的值（如 `color: red`, `font-family: "Arial"`）也是字符串。
    * **URL:** CSS 中使用的 URL（如 `url("image.png")`）是字符串。

    **举例说明:**
    当 Blink 引擎解析 CSS 规则 `.my-class { color: red; }` 时，`".my-class"` 和 `"red"` 这两个字符串可能被存储为 `wtf::String` 对象。

    **假设输入与输出:**
    假设 Blink 引擎正在解析 CSS 属性值 `"bold"` 并尝试将其转换为字体粗细。
    * **假设输入:** 一个 `wtf::String` 对象，内容为 "bold"。
    * **逻辑推理:** Blink 引擎会使用 `wtf::String` 的比较方法来判断该字符串是否匹配预定义的关键字，例如 "bold", "normal" 等。
    * **假设输出:** 如果匹配 "bold"，则引擎会将其解释为粗体。

**涉及用户或者编程常见的使用错误：**

这个测试文件通过各种测试用例，也在间接地展示了用户或编程中可能遇到的关于字符串的常见错误：

* **大小写敏感性问题:**  `StartsWithIgnoringASCIICase`, `EndsWithIgnoringASCIICase`, `EqualIgnoringASCIICase`, `FindIgnoringASCIICase` 这些测试用例表明，在字符串比较时，是否考虑大小写是一个常见的问题。用户可能会错误地认为 "abc" 和 "ABC" 是相同的。

    **举例说明:**
    用户可能在 JavaScript 中使用 `string1 === string2` 进行比较，但没有意识到两个字符串的大小写不同，导致比较结果不符合预期。

* **空格处理问题:** `LengthWithStrippedWhiteSpace`, `SimplifyWhiteSpace` 这些测试用例说明，字符串中额外的空格可能会导致意想不到的结果。用户可能在比较或处理字符串时没有考虑到前导或尾随空格。

    **举例说明:**
    用户在 HTML 表单中输入 "  hello  "，后端程序在处理时如果没有去除首尾空格，可能会导致验证失败或数据存储错误。

* **编码问题 (虽然测试代码本身没有直接展示，但 `wtf::String` 的设计考虑了编码):**  虽然这个测试文件没有直接演示编码错误，但 `wtf::String` 需要处理不同的字符编码（如 UTF-8），用户在使用字符串时可能会遇到编码不一致导致乱码的问题。

    **举例说明:**
    用户在 HTML 文件中使用了错误的字符编码声明，导致浏览器无法正确解析包含非 ASCII 字符的文本。

* **空字符串和空指针问题:** `CreationFromHashTraits` 中测试了空字符串和空指针 (`IsNull()`) 的情况。用户可能会忘记检查字符串是否为空或为 null，导致程序崩溃或行为异常。

    **举例说明:**
    在 JavaScript 中，如果尝试访问一个 `null` 或 `undefined` 变量的字符串属性（例如 `myNullString.length`），会导致错误。在 C++ 中，如果不对空指针进行检查就尝试解引用，会导致程序崩溃。

* **字符串替换错误:** `ReplaceWithLiteral` 测试了字符串替换的各种情况，用户可能会错误地使用替换方法，例如替换的目标字符不存在，或者替换成的字符串不是预期的。

    **举例说明:**
    用户在 JavaScript 中使用 `string.replace('a', '')` 来删除所有 'a' 字符，但实际上 `replace` 方法默认只替换第一个匹配项。要替换所有匹配项，需要使用正则表达式或 `replaceAll` 方法。

总而言之，`wtf_string_test.cc` 这个文件通过各种细致的测试用例，确保了 `wtf::String` 类的正确性和健壮性，这对于 Blink 引擎正确地处理和渲染网页内容至关重要，同时也间接地反映了开发者在使用字符串时可能遇到的各种常见问题。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/wtf_string_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
﻿/*
 * Copyright (C) 2012 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

#include <limits>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_traits.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"

namespace WTF {

TEST(StringTest, CreationFromLiteral) {
  String string_from_literal("Explicit construction syntax");
  EXPECT_EQ(strlen("Explicit construction syntax"),
            string_from_literal.length());
  EXPECT_TRUE(string_from_literal == "Explicit construction syntax");
  EXPECT_TRUE(string_from_literal.Is8Bit());
  EXPECT_TRUE(String("Explicit construction syntax") == string_from_literal);
}

TEST(StringTest, CreationFromHashTraits) {
  String zero;
  EXPECT_TRUE(zero.IsNull());
  EXPECT_TRUE(zero.empty());
  EXPECT_TRUE(HashTraits<String>::IsEmptyValue(zero));
  EXPECT_EQ(zero, HashTraits<String>::EmptyValue());

  String empty = "";
  EXPECT_FALSE(empty.IsNull());
  EXPECT_TRUE(empty.empty());
  EXPECT_FALSE(HashTraits<String>::IsEmptyValue(empty));
  EXPECT_NE(empty, HashTraits<String>::EmptyValue());

  uint32_t hash = String("abc").Impl()->GetHash();
  EXPECT_EQ(hash, HashTraits<String>::GetHash(String("abc")));
  EXPECT_EQ(hash, HashTraits<String>::GetHash("abc"));
  EXPECT_EQ(hash,
            HashTraits<String>::GetHash(reinterpret_cast<const LChar*>("abc")));
  const UChar abc_wide[] = {'a', 'b', 'c', 0};
  EXPECT_EQ(hash, HashTraits<String>::GetHash(abc_wide));
}

TEST(StringTest, EqualHashTraits) {
  String abc = "abc";
  String def = "def";

  EXPECT_TRUE(HashTraits<String>::Equal(abc, abc));
  EXPECT_FALSE(HashTraits<String>::Equal(abc, def));

  EXPECT_TRUE(HashTraits<String>::Equal(abc, "abc"));
  EXPECT_FALSE(HashTraits<String>::Equal(abc, "def"));
  EXPECT_TRUE(HashTraits<String>::Equal("abc", abc));
  EXPECT_FALSE(HashTraits<String>::Equal("def", abc));

  EXPECT_TRUE(
      HashTraits<String>::Equal(abc, reinterpret_cast<const LChar*>("abc")));
  EXPECT_FALSE(
      HashTraits<String>::Equal(abc, reinterpret_cast<const LChar*>("def")));
  EXPECT_TRUE(
      HashTraits<String>::Equal(reinterpret_cast<const LChar*>("abc"), abc));
  EXPECT_FALSE(
      HashTraits<String>::Equal(reinterpret_cast<const LChar*>("def"), abc));

  const UChar abc_wide[] = {'a', 'b', 'c', 0};
  const UChar def_wide[] = {'d', 'e', 'f', 0};
  EXPECT_TRUE(HashTraits<String>::Equal(abc, abc_wide));
  EXPECT_FALSE(HashTraits<String>::Equal(abc, def_wide));
  EXPECT_TRUE(HashTraits<String>::Equal(abc_wide, abc));
  EXPECT_FALSE(HashTraits<String>::Equal(def_wide, abc));
}

TEST(StringTest, ASCII) {
  // Null String.
  EXPECT_EQ("", String().Ascii());

  // Empty String.
  EXPECT_EQ("", g_empty_string.Ascii());

  // Regular String.
  EXPECT_EQ("foobar", String("foobar").Ascii());
}

namespace {

void TestNumberToStringECMAScript(double number, const char* reference) {
  EXPECT_EQ(reference, String::NumberToStringECMAScript(number));
}

}  // anonymous namespace

TEST(StringTest, NumberToStringECMAScriptBoundaries) {
  typedef std::numeric_limits<double> Limits;

  // Infinity.
  TestNumberToStringECMAScript(Limits::infinity(), "Infinity");
  TestNumberToStringECMAScript(-Limits::infinity(), "-Infinity");

  // NaN.
  TestNumberToStringECMAScript(-Limits::quiet_NaN(), "NaN");

  // Zeros.
  TestNumberToStringECMAScript(0, "0");
  TestNumberToStringECMAScript(-0, "0");

  // Min-Max.
  TestNumberToStringECMAScript(Limits::min(), "2.2250738585072014e-308");
  TestNumberToStringECMAScript(Limits::max(), "1.7976931348623157e+308");
}

TEST(StringTest, NumberToStringECMAScriptRegularNumbers) {
  // Pi.
  TestNumberToStringECMAScript(kPiDouble, "3.141592653589793");
  TestNumberToStringECMAScript(kPiFloat, "3.1415927410125732");
  TestNumberToStringECMAScript(kPiOverTwoDouble, "1.5707963267948966");
  TestNumberToStringECMAScript(kPiOverTwoFloat, "1.5707963705062866");
  TestNumberToStringECMAScript(kPiOverFourDouble, "0.7853981633974483");
  TestNumberToStringECMAScript(kPiOverFourFloat, "0.7853981852531433");

  // e.
  const double kE = 2.71828182845904523536028747135266249775724709369995;
  TestNumberToStringECMAScript(kE, "2.718281828459045");

  // c, speed of light in m/s.
  const double kC = 299792458;
  TestNumberToStringECMAScript(kC, "299792458");

  // Golen ratio.
  const double kPhi = 1.6180339887498948482;
  TestNumberToStringECMAScript(kPhi, "1.618033988749895");
}

TEST(StringTest, ReplaceWithLiteral) {
  // Cases for 8Bit source.
  String test_string = "1224";
  EXPECT_TRUE(test_string.Is8Bit());
  test_string.Replace('2', "");
  EXPECT_EQ("14", test_string);

  test_string = "1224";
  EXPECT_TRUE(test_string.Is8Bit());
  test_string.Replace('2', "3");
  EXPECT_EQ("1334", test_string);

  test_string = "1224";
  EXPECT_TRUE(test_string.Is8Bit());
  test_string.Replace('2', "555");
  EXPECT_EQ("15555554", test_string);

  test_string = "1224";
  EXPECT_TRUE(test_string.Is8Bit());
  test_string.Replace('3', "NotFound");
  EXPECT_EQ("1224", test_string);

  // Cases for 16Bit source.
  // U+00E9 (=0xC3 0xA9 in UTF-8) is e with accent.
  test_string = String::FromUTF8("r\xC3\xA9sum\xC3\xA9");
  EXPECT_FALSE(test_string.Is8Bit());
  test_string.Replace(UChar(0x00E9), "e");
  EXPECT_EQ("resume", test_string);

  test_string = String::FromUTF8("r\xC3\xA9sum\xC3\xA9");
  EXPECT_FALSE(test_string.Is8Bit());
  test_string.Replace(UChar(0x00E9), "");
  EXPECT_EQ("rsum", test_string);

  test_string = String::FromUTF8("r\xC3\xA9sum\xC3\xA9");
  EXPECT_FALSE(test_string.Is8Bit());
  test_string.Replace('3', "NotFound");
  EXPECT_EQ("r\xC3\xA9sum\xC3\xA9", test_string.Utf8());
}

TEST(StringTest, ComparisonOfSameStringVectors) {
  Vector<String> string_vector;
  string_vector.push_back("one");
  string_vector.push_back("two");

  Vector<String> same_string_vector;
  same_string_vector.push_back("one");
  same_string_vector.push_back("two");

  EXPECT_EQ(string_vector, same_string_vector);
}

TEST(WTF, LengthWithStrippedWhiteSpace) {
  String stripped("Hello  world");
  EXPECT_EQ(stripped.LengthWithStrippedWhiteSpace(), stripped.length());
  EXPECT_EQ(String("  Hello  world  ").LengthWithStrippedWhiteSpace(),
            stripped.length());
  EXPECT_EQ(String("Hello  world  ").LengthWithStrippedWhiteSpace(),
            stripped.length());
  EXPECT_EQ(String("  Hello  world").LengthWithStrippedWhiteSpace(),
            stripped.length());
  EXPECT_EQ(String("\nHello\n world  ").LengthWithStrippedWhiteSpace(),
            stripped.length());
  EXPECT_EQ(String().LengthWithStrippedWhiteSpace(), 0u);
  EXPECT_EQ(String("").LengthWithStrippedWhiteSpace(), 0u);
  EXPECT_EQ(String("\n").LengthWithStrippedWhiteSpace(), 0u);
  EXPECT_EQ(String("\n\n").LengthWithStrippedWhiteSpace(), 0u);
  String only_spaces("   ");
  EXPECT_EQ(only_spaces.LengthWithStrippedWhiteSpace(), 0u);
}

TEST(WTF, SimplifyWhiteSpace) {
  String extra_spaces("  Hello  world  ");
  EXPECT_EQ(String("Hello world"), extra_spaces.SimplifyWhiteSpace());
  EXPECT_EQ(String("  Hello  world  "),
            extra_spaces.SimplifyWhiteSpace(WTF::kDoNotStripWhiteSpace));

  String extra_spaces_and_newlines(" \nHello\n world\n ");
  EXPECT_EQ(String("Hello world"),
            extra_spaces_and_newlines.SimplifyWhiteSpace());
  EXPECT_EQ(
      String("  Hello  world  "),
      extra_spaces_and_newlines.SimplifyWhiteSpace(WTF::kDoNotStripWhiteSpace));

  String extra_spaces_and_tabs(" \nHello\t world\t ");
  EXPECT_EQ(String("Hello world"), extra_spaces_and_tabs.SimplifyWhiteSpace());
  EXPECT_EQ(
      String("  Hello  world  "),
      extra_spaces_and_tabs.SimplifyWhiteSpace(WTF::kDoNotStripWhiteSpace));

  auto is_space_or_g = [](UChar character) {
    return character == ' ' || character == 'G';
  };
  String extra_spaces_and_gs(" GGG Hello G world G G");
  EXPECT_EQ(String("Hello world"),
            extra_spaces_and_gs.SimplifyWhiteSpace(is_space_or_g));
  EXPECT_EQ(String("     Hello   world    "),
            extra_spaces_and_gs.SimplifyWhiteSpace(is_space_or_g,
                                                   WTF::kDoNotStripWhiteSpace));
}

TEST(StringTest, StartsWithIgnoringUnicodeCase) {
  // [U+017F U+212A i a] starts with "sk".
  EXPECT_TRUE(
      String::FromUTF8("\xC5\xBF\xE2\x84\xAAia").StartsWithIgnoringCase("sk"));
}

TEST(StringTest, StartsWithIgnoringASCIICase) {
  String all_ascii("LINK");
  String all_ascii_lower_case("link");
  EXPECT_TRUE(all_ascii.StartsWithIgnoringASCIICase(all_ascii_lower_case));
  String all_ascii_mixed_case("lInK");
  EXPECT_TRUE(all_ascii.StartsWithIgnoringASCIICase(all_ascii_mixed_case));
  String all_ascii_different("foo");
  EXPECT_FALSE(all_ascii.StartsWithIgnoringASCIICase(all_ascii_different));
  String non_ascii = String::FromUTF8("LIN\xE2\x84\xAA");
  EXPECT_FALSE(all_ascii.StartsWithIgnoringASCIICase(non_ascii));
  EXPECT_TRUE(
      all_ascii.StartsWithIgnoringASCIICase(non_ascii.DeprecatedLower()));

  EXPECT_FALSE(non_ascii.StartsWithIgnoringASCIICase(all_ascii));
  EXPECT_FALSE(non_ascii.StartsWithIgnoringASCIICase(all_ascii_lower_case));
  EXPECT_FALSE(non_ascii.StartsWithIgnoringASCIICase(all_ascii_mixed_case));
  EXPECT_FALSE(non_ascii.StartsWithIgnoringASCIICase(all_ascii_different));
}

TEST(StringTest, EndsWithIgnoringASCIICase) {
  String all_ascii("LINK");
  String all_ascii_lower_case("link");
  EXPECT_TRUE(all_ascii.EndsWithIgnoringASCIICase(all_ascii_lower_case));
  String all_ascii_mixed_case("lInK");
  EXPECT_TRUE(all_ascii.EndsWithIgnoringASCIICase(all_ascii_mixed_case));
  String all_ascii_different("foo");
  EXPECT_FALSE(all_ascii.EndsWithIgnoringASCIICase(all_ascii_different));
  String non_ascii = String::FromUTF8("LIN\xE2\x84\xAA");
  EXPECT_FALSE(all_ascii.EndsWithIgnoringASCIICase(non_ascii));
  EXPECT_TRUE(all_ascii.EndsWithIgnoringASCIICase(non_ascii.DeprecatedLower()));

  EXPECT_FALSE(non_ascii.EndsWithIgnoringASCIICase(all_ascii));
  EXPECT_FALSE(non_ascii.EndsWithIgnoringASCIICase(all_ascii_lower_case));
  EXPECT_FALSE(non_ascii.EndsWithIgnoringASCIICase(all_ascii_mixed_case));
  EXPECT_FALSE(non_ascii.EndsWithIgnoringASCIICase(all_ascii_different));
}

TEST(StringTest, EqualIgnoringASCIICase) {
  String all_ascii("LINK");
  String all_ascii_lower_case("link");
  EXPECT_TRUE(EqualIgnoringASCIICase(all_ascii, all_ascii_lower_case));
  String all_ascii_mixed_case("lInK");
  EXPECT_TRUE(EqualIgnoringASCIICase(all_ascii, all_ascii_mixed_case));
  String all_ascii_different("foo");
  EXPECT_FALSE(EqualIgnoringASCIICase(all_ascii, all_ascii_different));
  String non_ascii = String::FromUTF8("LIN\xE2\x84\xAA");
  EXPECT_FALSE(EqualIgnoringASCIICase(all_ascii, non_ascii));
  EXPECT_TRUE(EqualIgnoringASCIICase(all_ascii, non_ascii.DeprecatedLower()));

  EXPECT_FALSE(EqualIgnoringASCIICase(non_ascii, all_ascii));
  EXPECT_FALSE(EqualIgnoringASCIICase(non_ascii, all_ascii_lower_case));
  EXPECT_FALSE(EqualIgnoringASCIICase(non_ascii, all_ascii_mixed_case));
  EXPECT_FALSE(EqualIgnoringASCIICase(non_ascii, all_ascii_different));
}

TEST(StringTest, FindIgnoringASCIICase) {
  String needle = String::FromUTF8("a\xCC\x88qa\xCC\x88");

  // Multiple matches, non-overlapping
  String haystack1 = String::FromUTF8(
      "aA\xCC\x88QA\xCC\x88sA\xCC\x88qa\xCC\x88rfi\xC3\xA4q\xC3\xA4");
  EXPECT_EQ(1u, haystack1.FindIgnoringASCIICase(needle));
  EXPECT_EQ(7u, haystack1.FindIgnoringASCIICase(needle, 2));
  EXPECT_EQ(kNotFound, haystack1.FindIgnoringASCIICase(needle, 8));

  // Multiple matches, overlapping
  String haystack2 = String::FromUTF8("aA\xCC\x88QA\xCC\x88qa\xCC\x88rfi");
  EXPECT_EQ(1u, haystack2.FindIgnoringASCIICase(needle));
  EXPECT_EQ(4u, haystack2.FindIgnoringASCIICase(needle, 2));
  EXPECT_EQ(kNotFound, haystack2.FindIgnoringASCIICase(needle, 5));
}

TEST(StringTest, DeprecatedLower) {
  EXPECT_EQ("link", String("LINK").DeprecatedLower());
  EXPECT_EQ("link", String("lInk").DeprecatedLower());
  EXPECT_EQ("lin\xE1k", String("lIn\xC1k").DeprecatedLower().Latin1());

  // U+212A -> k
  EXPECT_EQ("link",
            String::FromUTF8("LIN\xE2\x84\xAA").DeprecatedLower().Utf8());
}

TEST(StringTest, Ensure16Bit) {
  String string8("8bit");
  EXPECT_TRUE(string8.Is8Bit());
  string8.Ensure16Bit();
  EXPECT_FALSE(string8.Is8Bit());
  EXPECT_EQ("8bit", string8);

  String string16(reinterpret_cast<const UChar*>(u"16bit"));
  EXPECT_FALSE(string16.Is8Bit());
  string16.Ensure16Bit();
  EXPECT_FALSE(string16.Is8Bit());
  EXPECT_EQ("16bit", string16);

  String empty8(StringImpl::empty_);
  EXPECT_TRUE(empty8.Is8Bit());
  empty8.Ensure16Bit();
  EXPECT_FALSE(empty8.Is8Bit());
  EXPECT_TRUE(empty8.empty());
  EXPECT_FALSE(empty8.IsNull());

  String empty16(StringImpl::empty16_bit_);
  EXPECT_FALSE(empty16.Is8Bit());
  empty16.Ensure16Bit();
  EXPECT_FALSE(empty16.Is8Bit());
  EXPECT_TRUE(empty16.empty());
  EXPECT_FALSE(empty16.IsNull());

  String null_string;
  null_string.Ensure16Bit();
  EXPECT_TRUE(null_string.IsNull());
}

std::string ToStdStringThroughPrinter(const String& string) {
  std::ostringstream output;
  output << string;
  return output.str();
}

TEST(StringTest, StringPrinter) {
  EXPECT_EQ("\"Hello!\"", ToStdStringThroughPrinter("Hello!"));
  EXPECT_EQ("\"\\\"\"", ToStdStringThroughPrinter("\""));
  EXPECT_EQ("\"\\\\\"", ToStdStringThroughPrinter("\\"));
  EXPECT_EQ("\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\"",
            ToStdStringThroughPrinter(String(
                base::span_from_cstring("\x00\x01\x02\x03\x04\x05\x06\x07"))));
  EXPECT_EQ(
      "\"\\u0008\\t\\n\\u000B\\u000C\\r\\u000E\\u000F\"",
      ToStdStringThroughPrinter(String("\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F")));
  EXPECT_EQ(
      "\"\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\"",
      ToStdStringThroughPrinter(String("\x10\x11\x12\x13\x14\x15\x16\x17")));
  EXPECT_EQ(
      "\"\\u0018\\u0019\\u001A\\u001B\\u001C\\u001D\\u001E\\u001F\"",
      ToStdStringThroughPrinter(String("\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F")));
  EXPECT_EQ("\"\\u007F\\u0080\\u0081\"",
            ToStdStringThroughPrinter("\x7F\x80\x81"));
  EXPECT_EQ("\"\"", ToStdStringThroughPrinter(g_empty_string));
  EXPECT_EQ("<null>", ToStdStringThroughPrinter(String()));

  static const UChar kUnicodeSample[] = {0x30C6, 0x30B9,
                                         0x30C8};  // "Test" in Japanese.
  EXPECT_EQ("\"\\u30C6\\u30B9\\u30C8\"",
            ToStdStringThroughPrinter(String(base::span(kUnicodeSample))));
}

class TestMatcher {
 public:
  explicit TestMatcher(UChar target) : target_(target) {}

  bool IsTarget(UChar ch) { return ch == target_; }

 private:
  UChar target_;
};

TEST(StringTest, FindWithCallback) {
  String test_string1("abc");
  String test_string2("stu");

  // An instance method.
  TestMatcher matcher('t');
  // Unretained is safe because callback executes synchronously in Find().
  auto callback =
      WTF::BindRepeating(&TestMatcher::IsTarget, WTF::Unretained(&matcher));
  EXPECT_EQ(WTF::kNotFound, test_string1.Find(callback));
  EXPECT_EQ(1U, test_string2.Find(callback));
}

TEST(StringTest, StartsWithIgnoringCaseAndAccents) {
  EXPECT_TRUE(String(u"ÎÑŢÉRÑÅŢÎÖÑÅĻÎŽÅŢÎÖÑ")
                  .StartsWithIgnoringCaseAndAccents(String("international")));
}

TEST(StringTest, StartsWithIgnoringCaseAndAccents8Bit) {
  EXPECT_TRUE(String("PuPpY").StartsWithIgnoringCaseAndAccents(String("pup")));
}

TEST(StringTest, StartsWithIgnoringCaseAndAccentsExpanding) {
  EXPECT_TRUE(
      String(u"Straße").StartsWithIgnoringCaseAndAccents(String("STRASS")));
}

TEST(StringTest, StartsWithIgnoringCaseAndAccentsSuffixDiff) {
  EXPECT_FALSE(
      String("Donkey").StartsWithIgnoringCaseAndAccents(String("Donka")));
}

}  // namespace WTF
```