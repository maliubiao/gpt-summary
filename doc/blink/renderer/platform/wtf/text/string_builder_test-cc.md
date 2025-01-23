Response:
The user wants to understand the functionality of the `string_builder_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, focusing on the following:

1. **Core Functionality:** What does this file test?  It's a test file, so it should be testing the `StringBuilder` class.
2. **Relationship to Web Technologies:**  How does `StringBuilder` relate to JavaScript, HTML, and CSS?  Think about where string manipulation is important in these technologies.
3. **Logic and Examples:**  Identify specific test cases and provide examples of their inputs and expected outputs.
4. **Common Usage Errors:**  Based on the test cases, infer potential mistakes developers might make when using `StringBuilder`.
这个文件 `string_builder_test.cc` 是 Chromium Blink 引擎中 `StringBuilder` 类的单元测试文件。它的主要功能是：

**1. 测试 `StringBuilder` 类的各种功能:**

   这个文件包含了多个 `TEST` 宏定义的测试用例，每个用例针对 `StringBuilder` 类的不同方法和使用场景进行测试，例如：

   * **构造函数:** 测试默认构造函数的行为。
   * **Append:** 测试各种 `Append` 方法，包括追加字符串、字符、子串、Span 等。
   * **ToString:** 测试将 `StringBuilder` 的内容转换为 `String` 对象。
   * **ReleaseString:** 测试释放 `StringBuilder` 内部存储的字符串并返回 `String` 对象。
   * **Clear:** 测试清空 `StringBuilder` 内容。
   * **Array Access (operator[]):** 测试通过索引访问 `StringBuilder` 中的字符。
   * **Resize:** 测试调整 `StringBuilder` 的大小。
   * **Erase:** 测试删除 `StringBuilder` 中指定位置的字符。
   * **Equal (operator==, operator!=):** 测试 `StringBuilder` 对象之间的相等性比较以及与 `String` 对象的比较。
   * **ToAtomicString:** 测试将 `StringBuilder` 的内容转换为 `AtomicString` 对象。
   * **Substring:** 测试提取 `StringBuilder` 的子串。
   * **AppendNumber:** 测试追加数字类型。
   * **ReserveCapacity:** 测试预留 `StringBuilder` 的容量。
   * **DoesAppendCauseOverflow:** 测试追加操作是否会导致溢出。

**2. 验证 `StringBuilder` 的正确性和健壮性:**

   通过编写各种边界情况和正常情况的测试用例，来确保 `StringBuilder` 类的实现是正确的，并且能够处理各种输入。

**与 JavaScript, HTML, CSS 的关系：**

`StringBuilder` 类在 Blink 引擎中用于高效地构建字符串，这与 JavaScript、HTML 和 CSS 的处理密切相关。以下是一些例子：

* **JavaScript:**
    * **代码生成/拼接:**  当 JavaScript 引擎需要动态生成 JavaScript 代码或拼接字符串时，可以使用 `StringBuilder` 来提高效率，尤其是在循环中拼接大量字符串的情况下。
    * **DOM 操作:**  在某些 DOM 操作中，可能需要构建包含 HTML 片段的字符串，`StringBuilder` 可以用于高效构建这些字符串。
    * **例如：** 假设一个 JavaScript 函数需要动态生成一个包含多个列表项的 HTML 字符串：
      ```javascript
      function createList(items) {
        let builder = new StringBuilder(); // 假设 JavaScript 中有类似的 StringBuilder
        builder.append("<ul>");
        for (const item of items) {
          builder.append("<li>").append(item).append("</li>");
        }
        builder.append("</ul>");
        return builder.toString();
      }
      ```
      在 Blink 内部实现这个 `StringBuilder` 的功能时，就会用到 `wtf::StringBuilder`。

* **HTML:**
    * **HTML 解析和序列化:**  当 Blink 引擎解析 HTML 文档或将 DOM 树序列化为 HTML 字符串时，`StringBuilder` 可以用于高效地构建 HTML 字符串。
    * **例如：** 当一个 HTML 元素及其子元素需要被转换为 HTML 字符串时，可以逐步将标签和内容追加到 `StringBuilder` 中。
      **假设输入 (DOM 结构):**  一个包含 `<div><span>Hello</span></div>` 的简单 DOM 结构。
      **逻辑推理:**  Blink 引擎在序列化时，会遍历 DOM 树，并将每个节点的标签和内容添加到 `StringBuilder` 中。
      **假设输出 (HTML 字符串):** `<div><span>Hello</span></div>`

* **CSS:**
    * **CSS 解析和规则构建:**  当 Blink 引擎解析 CSS 样式表时，可能会使用 `StringBuilder` 来构建 CSS 规则的字符串表示。
    * **样式计算和应用:**  在某些情况下，可能需要动态构建 CSS 属性值，例如在处理 CSS 变量或计算样式时。
    * **例如：**  在处理 `transform` 属性时，可能需要将多个变换函数拼接成一个字符串。

**逻辑推理的假设输入与输出：**

* **测试用例 `TEST(StringBuilderTest, Append)` 中的一个场景:**
    * **假设输入:**  一个空的 `StringBuilder` 对象，然后依次调用 `Append("0123456789")`, `Append("abcd")`, `Append(base::byte_span_from_cstring("efgh").first(3u))`, `Append("")`, `Append('#')`。
    * **逻辑推理:**  每次 `Append` 调用都会将指定的字符串或字符添加到 `StringBuilder` 的末尾。空字符串不会改变 `StringBuilder` 的内容。
    * **假设输出:**  `StringBuilder` 的内容为 "0123456789abcdefg#"。

* **测试用例 `TEST(StringBuilderTest, Resize)`:**
    * **假设输入:** 一个 `StringBuilder` 对象，内容为 "0123456789"，然后调用 `Resize(8)`。
    * **逻辑推理:** `Resize(n)` 会将 `StringBuilder` 的长度调整为 `n`。如果新的长度小于当前长度，则会截断字符串。
    * **假设输出:** `StringBuilder` 的内容为 "01234567"。

**用户或编程常见的使用错误：**

* **过度依赖字符串拼接运算符 (+):**  在循环中频繁使用字符串拼接运算符会导致性能问题，因为每次拼接都会创建新的字符串对象。使用 `StringBuilder` 可以避免这个问题，因为它允许在内部缓冲区中高效地追加字符串。
    * **错误示例 (低效):**
      ```javascript
      let result = "";
      for (let i = 0; i < 1000; i++) {
        result += "item " + i + ", ";
      }
      ```
    * **正确示例 (使用 `StringBuilder` 的思想):**
      ```c++
      StringBuilder builder;
      for (int i = 0; i < 1000; i++) {
        builder.Append("item ");
        builder.AppendNumber(i);
        builder.Append(", ");
      }
      String result = builder.ToString();
      ```

* **忘记调用 `ToString()` 或 `ReleaseString()`:**  `StringBuilder` 对象本身不是一个 `String` 对象。如果需要将构建的字符串传递给需要 `String` 类型的函数或使用 `String` 的方法，需要显式调用 `ToString()` 或 `ReleaseString()` 进行转换。
    * **错误示例:**
      ```c++
      StringBuilder builder;
      builder.Append("hello");
      // SomeFunctionThatExpectsString(builder); // 错误！builder 是 StringBuilder 类型
      SomeFunctionThatExpectsString(builder.ToString()); // 正确
      ```

* **在 `ReleaseString()` 后继续使用 `StringBuilder` 的旧内容:**  调用 `ReleaseString()` 会释放 `StringBuilder` 内部的字符串缓冲区，并将所有权转移给返回的 `String` 对象。之后再访问或修改 `StringBuilder` 可能会导致未定义的行为。虽然测试用例表明 `ReleaseString()` 后可以复用，但需要注意这种行为，避免依赖释放前的状态。

* **不必要的预留容量 (`ReserveCapacity`)：** 虽然预留容量可以提高性能，但如果预留过多的容量而实际使用很少，则会浪费内存。应该根据实际情况合理预估所需容量。

总而言之， `string_builder_test.cc` 文件是确保 `StringBuilder` 类正确可靠的关键组成部分，而 `StringBuilder` 类本身在 Blink 引擎中扮演着高效字符串构建的重要角色，与 Web 前端技术息息相关。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/string_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#include <limits>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace WTF {

namespace {

void ExpectBuilderContent(const String& expected,
                          const StringBuilder& builder) {
  // Not using builder.toString() because it changes internal state of builder.
  if (builder.Is8Bit())
    EXPECT_EQ(expected, String(builder.Span8()));
  else
    EXPECT_EQ(expected, String(builder.Span16()));
}

void ExpectEmpty(const StringBuilder& builder) {
  EXPECT_EQ(0U, builder.length());
  EXPECT_TRUE(builder.empty());
  EXPECT_EQ(nullptr, builder.Span8().data());
}

}  // namespace

TEST(StringBuilderTest, DefaultConstructor) {
  StringBuilder builder;
  ExpectEmpty(builder);
}

TEST(StringBuilderTest, Append) {
  StringBuilder builder;
  builder.Append(String("0123456789"));
  ExpectBuilderContent("0123456789", builder);
  builder.Append("abcd");
  ExpectBuilderContent("0123456789abcd", builder);
  builder.Append(base::byte_span_from_cstring("efgh").first(3u));
  ExpectBuilderContent("0123456789abcdefg", builder);
  builder.Append("");
  ExpectBuilderContent("0123456789abcdefg", builder);
  builder.Append('#');
  ExpectBuilderContent("0123456789abcdefg#", builder);

  builder.ToString();  // Test after reifyString().
  StringBuilder builder1;
  builder.Append("");
  ExpectBuilderContent("0123456789abcdefg#", builder);
  builder1.Append(builder.Span8());
  builder1.Append("XYZ");
  builder.Append(builder1.Span8());
  ExpectBuilderContent("0123456789abcdefg#0123456789abcdefg#XYZ", builder);

  StringBuilder builder2;
  builder2.ReserveCapacity(100);
  builder2.Append("xyz");
  base::span<const LChar> characters = builder2.Span8();
  builder2.Append("0123456789");
  EXPECT_EQ(characters.data(), builder2.Span8().data());

  StringBuilder builder3;
  builder3.Append("xyz", 1, 2);
  ExpectBuilderContent("yz", builder3);

  StringBuilder builder4;
  builder4.Append("abc", 5, 3);
  ExpectEmpty(builder4);

  StringBuilder builder5;
  builder5.Append(StringView(StringView("def"), 1, 1));
  ExpectBuilderContent("e", builder5);

  // append() has special code paths for String backed StringView instead of
  // just char* backed ones.
  StringBuilder builder6;
  builder6.Append(String("ghi"), 1, 2);
  ExpectBuilderContent("hi", builder6);

  // Test appending UChar32 characters to StringBuilder.
  StringBuilder builder_for_u_char32_append;
  UChar32 fraktur_a_char = 0x1D504;
  // The fraktur A is not in the BMP, so it's two UTF-16 code units long.
  builder_for_u_char32_append.Append(fraktur_a_char);
  EXPECT_FALSE(builder_for_u_char32_append.Is8Bit());
  EXPECT_EQ(2U, builder_for_u_char32_append.length());
  builder_for_u_char32_append.Append(static_cast<UChar32>('A'));
  EXPECT_EQ(3U, builder_for_u_char32_append.length());
  const UChar result_array[] = {U16_LEAD(fraktur_a_char),
                                U16_TRAIL(fraktur_a_char), 'A'};
  ExpectBuilderContent(String(base::span(result_array)),
                       builder_for_u_char32_append);
}

TEST(StringBuilderTest, AppendSpan) {
  StringBuilder builder;

  // Append an empty span
  builder.Append(base::as_byte_span(base::span_from_cstring("")));
  EXPECT_EQ(0u, builder.length());
  builder.Append(base::span_from_cstring(u""));
  EXPECT_EQ(0u, builder.length());

  // Append to an 8-bit builder.
  builder.Append("a");
  builder.Append(base::as_byte_span(base::span_from_cstring("b")));
  EXPECT_TRUE(builder.Is8Bit());
  EXPECT_EQ(2u, builder.length());
  builder.Append(base::span_from_cstring(u"U"));
  EXPECT_TRUE(builder.Is8Bit());
  EXPECT_EQ(3u, builder.length());
  builder.Append(base::span_from_cstring(u"VV"));
  EXPECT_FALSE(builder.Is8Bit());
  EXPECT_EQ(5u, builder.length());

  // Append to a 16-bit builder.
  builder.Append(base::as_byte_span(base::span_from_cstring("c")));
  EXPECT_FALSE(builder.Is8Bit());
  EXPECT_EQ(6u, builder.length());
  builder.Append(base::span_from_cstring(u"W"));
  EXPECT_FALSE(builder.Is8Bit());
  EXPECT_EQ(7u, builder.length());
}

TEST(StringBuilderTest, AppendSharingImpl) {
  String string("abc");
  StringBuilder builder1;
  builder1.Append(string);
  EXPECT_EQ(string.Impl(), builder1.ToString().Impl());
  EXPECT_EQ(string.Impl(), builder1.ToAtomicString().Impl());

  StringBuilder builder2;
  builder2.Append(string, 0, string.length());
  EXPECT_EQ(string.Impl(), builder2.ToString().Impl());
  EXPECT_EQ(string.Impl(), builder2.ToAtomicString().Impl());
}

TEST(StringBuilderTest, ToString) {
  StringBuilder builder;
  builder.Append("0123456789");
  String string = builder.ToString();
  EXPECT_EQ(String("0123456789"), string);
  EXPECT_EQ(string.Impl(), builder.ToString().Impl());

  // Changing the StringBuilder should not affect the original result of
  // toString().
  builder.Append("abcdefghijklmnopqrstuvwxyz");
  EXPECT_EQ(String("0123456789"), string);

  // Changing the StringBuilder should not affect the original result of
  // toString() in case the capacity is not changed.
  builder.ReserveCapacity(200);
  string = builder.ToString();
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyz"), string);
  builder.Append("ABC");
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyz"), string);

  // Changing the original result of toString() should not affect the content of
  // the StringBuilder.
  String string1 = builder.ToString();
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyzABC"), string1);
  string1 = string1 + "DEF";
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyzABC"),
            builder.ToString());
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyzABCDEF"), string1);

  // Resizing the StringBuilder should not affect the original result of
  // toString().
  string1 = builder.ToString();
  builder.Resize(10);
  builder.Append("###");
  EXPECT_EQ(String("0123456789abcdefghijklmnopqrstuvwxyzABC"), string1);
}

TEST(StringBuilderTest, ReleaseString) {
  StringBuilder builder;
  builder.Append("0123456789");
  String string = builder.ReleaseString();
  EXPECT_EQ(String("0123456789"), string);

  ExpectEmpty(builder);

  // The builder can be reused after release.
  builder.Append("ABCDEFGH");
  String string2 = builder.ToString();
  EXPECT_EQ(String("ABCDEFGH"), string2);

  // Each call to ToString adds 1 to the ref count.
#if DCHECK_IS_ON()
  EXPECT_EQ(string2.Impl()->RefCountChangeCountForTesting(), 1u);
  String string3 = builder.ToString();
  EXPECT_EQ(string3.Impl()->RefCountChangeCountForTesting(), 2u);
  unsigned refcount = string2.Impl()->RefCountChangeCountForTesting();
#endif

  // StringImpl of the copied and released string should match
  String released = builder.ReleaseString();
  EXPECT_EQ(string2.Impl(), released.Impl());

  // Calling release doesn't increase the ref count.
#if DCHECK_IS_ON()
  EXPECT_EQ(refcount, released.Impl()->RefCountChangeCountForTesting());
#endif
}

TEST(StringBuilderTest, Clear) {
  StringBuilder builder;
  builder.Append("0123456789");
  builder.Clear();
  ExpectEmpty(builder);
}

TEST(StringBuilderTest, Array) {
  StringBuilder builder;
  builder.Append("0123456789");
  EXPECT_EQ('0', static_cast<char>(builder[0]));
  EXPECT_EQ('9', static_cast<char>(builder[9]));
  builder.ToString();  // Test after reifyString().
  EXPECT_EQ('0', static_cast<char>(builder[0]));
  EXPECT_EQ('9', static_cast<char>(builder[9]));
}

TEST(StringBuilderTest, Resize) {
  StringBuilder builder;
  builder.Append("0123456789");
  builder.Resize(10);
  EXPECT_EQ(10U, builder.length());
  ExpectBuilderContent("0123456789", builder);
  builder.Resize(8);
  EXPECT_EQ(8U, builder.length());
  ExpectBuilderContent("01234567", builder);

  builder.ToString();
  builder.Resize(7);
  EXPECT_EQ(7U, builder.length());
  ExpectBuilderContent("0123456", builder);
  builder.Resize(0);
  ExpectEmpty(builder);
}

TEST(StringBuilderTest, Erase) {
  StringBuilder builder;
  builder.Append(String("01234"));
  // Erase from String.
  builder.erase(3);
  ExpectBuilderContent("0124", builder);
  // Erase from buffer.
  builder.erase(1);
  ExpectBuilderContent("024", builder);
}

TEST(StringBuilderTest, Erase16) {
  StringBuilder builder;
  builder.Append(String(u"\uFF10\uFF11\uFF12\uFF13\uFF14"));
  // Erase from String.
  builder.erase(3);
  ExpectBuilderContent(u"\uFF10\uFF11\uFF12\uFF14", builder);
  // Erase from buffer.
  builder.erase(1);
  ExpectBuilderContent(u"\uFF10\uFF12\uFF14", builder);
}

TEST(StringBuilderTest, EraseLast) {
  StringBuilder builder;
  builder.Append("01234");
  builder.erase(4);
  ExpectBuilderContent("0123", builder);
}

TEST(StringBuilderTest, Equal) {
  StringBuilder builder1;
  StringBuilder builder2;
  EXPECT_TRUE(builder1 == builder2);
  EXPECT_TRUE(builder1 == String());
  EXPECT_TRUE(String() == builder1);
  EXPECT_TRUE(builder1 != String("abc"));

  builder1.Append("123");
  builder1.ReserveCapacity(32);
  builder2.Append("123");
  builder1.ReserveCapacity(64);
  EXPECT_TRUE(builder1 == builder2);
  EXPECT_TRUE(builder1 == String("123"));
  EXPECT_TRUE(String("123") == builder1);

  builder2.Append("456");
  EXPECT_TRUE(builder1 != builder2);
  EXPECT_TRUE(builder2 != builder1);
  EXPECT_TRUE(String("123") != builder2);
  EXPECT_TRUE(builder2 != String("123"));
  builder2.ToString();  // Test after reifyString().
  EXPECT_TRUE(builder1 != builder2);

  builder2.Resize(3);
  EXPECT_TRUE(builder1 == builder2);

  builder1.ToString();  // Test after reifyString().
  EXPECT_TRUE(builder1 == builder2);
}

TEST(StringBuilderTest, ToAtomicString) {
  StringBuilder builder;
  builder.Append("123");
  AtomicString atomic_string = builder.ToAtomicString();
  EXPECT_EQ(String("123"), atomic_string);

  builder.ReserveCapacity(256);
  for (int i = builder.length(); i < 128; i++)
    builder.Append('x');
  AtomicString atomic_string1 = builder.ToAtomicString();
  EXPECT_EQ(128u, atomic_string1.length());
  EXPECT_EQ('x', atomic_string1[127]);

  // Later change of builder should not affect the atomic string.
  for (int i = builder.length(); i < 256; i++)
    builder.Append('x');
  EXPECT_EQ(128u, atomic_string1.length());

  String string = builder.ToString();
  AtomicString atomic_string2 = builder.ToAtomicString();
  // They should share the same StringImpl.
  EXPECT_EQ(atomic_string2.Impl(), string.Impl());
}

TEST(StringBuilderTest, ToAtomicStringOnEmpty) {
  {  // Default constructed.
    StringBuilder builder;
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // With capacity.
    StringBuilder builder;
    builder.ReserveCapacity(64);
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // AtomicString constructed from a null string.
    StringBuilder builder;
    builder.Append(String());
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // AtomicString constructed from an empty string.
    StringBuilder builder;
    builder.Append(g_empty_string);
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // AtomicString constructed from an empty StringBuilder.
    StringBuilder builder;
    StringBuilder empty_builder;
    builder.Append(empty_builder);
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // AtomicString constructed from an empty char* string.
    StringBuilder builder;
    builder.Append("");
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
  {  // Cleared StringBuilder.
    StringBuilder builder;
    builder.Append("WebKit");
    builder.Clear();
    AtomicString atomic_string = builder.ToAtomicString();
    EXPECT_EQ(g_empty_atom, atomic_string);
  }
}

TEST(StringBuilderTest, Substring) {
  {  // Default constructed.
    StringBuilder builder;
    String substring = builder.Substring(0, 10);
    EXPECT_EQ(g_empty_string, substring);
  }
  {  // With capacity.
    StringBuilder builder;
    builder.ReserveCapacity(64);
    builder.Append("abc");
    String substring = builder.Substring(2, 10);
    EXPECT_EQ(String("c"), substring);
  }
}

TEST(StringBuilderTest, AppendNumberDoubleUChar) {
  const double kSomeNumber = 1.2345;
  StringBuilder reference;
  reference.Append(kReplacementCharacter);  // Make it UTF-16.
  reference.Append(String::Number(kSomeNumber));
  StringBuilder test;
  test.Append(kReplacementCharacter);
  test.AppendNumber(kSomeNumber);
  EXPECT_EQ(reference, test);
}

TEST(StringBuilderTest, ReserveCapacity) {
  StringBuilder builder;
  builder.ReserveCapacity(100);
  EXPECT_LE(100u, builder.Capacity());

  builder.Append(0x202B);
  ASSERT_FALSE(builder.Is8Bit());
  EXPECT_LE(100u, builder.Capacity());
}

TEST(StringBuilderTest, ReserveCapacityAfterEnsure16Bit) {
  StringBuilder builder;
  // |Ensure16Bit()| creates an inline buffer, so the subsequent
  // |ReserveCapacity()| should be an expansion.
  builder.Ensure16Bit();
  builder.ReserveCapacity(100);
  EXPECT_LE(100u, builder.Capacity());
}

TEST(StringBuilderTest, Reserve16BitCapacity) {
  StringBuilder builder;
  builder.Reserve16BitCapacity(100);
  EXPECT_FALSE(builder.Is8Bit());
  EXPECT_LE(100u, builder.Capacity());
}

TEST(StringBuilderTest, ReserveCapacityTwice) {
  StringBuilder builder;
  builder.ReserveCapacity(100);
  EXPECT_LE(100u, builder.Capacity());

  builder.ReserveCapacity(400);
  EXPECT_LE(400u, builder.Capacity());
}

TEST(StringBuilderTest, ReserveCapacityTwice16) {
  StringBuilder builder;
  builder.Ensure16Bit();
  builder.ReserveCapacity(100);
  EXPECT_LE(100u, builder.Capacity());

  builder.ReserveCapacity(400);
  EXPECT_LE(400u, builder.Capacity());
}

TEST(StringBuilderTest, DoesAppendCauseOverflow) {
  {
    StringBuilder builder;
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(0));
  }

  {
    StringBuilder builder;
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(1));
  }

  {
    StringBuilder builder;
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(
        std::numeric_limits<wtf_size_t>::max() / 4 - 1));
  }

  {
    StringBuilder builder;
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(
        std::numeric_limits<wtf_size_t>::max() / 4));
  }

  {
    StringBuilder builder;
    builder.Ensure16Bit();
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(
        std::numeric_limits<wtf_size_t>::max() / 8 - 1));
  }

  {
    StringBuilder builder;
    builder.Ensure16Bit();
    EXPECT_FALSE(builder.DoesAppendCauseOverflow(
        std::numeric_limits<wtf_size_t>::max() / 8));
  }
}

}  // namespace WTF
```