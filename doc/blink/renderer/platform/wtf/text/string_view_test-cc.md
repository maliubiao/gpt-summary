Response:
The user wants to understand the functionality of the C++ source code file `string_view_test.cc` within the Chromium Blink engine. I need to explain what this file does, how it relates to web technologies (JavaScript, HTML, CSS), provide examples of logical inferences, and point out common user/programming errors.

**Plan:**

1. **Identify the core purpose:** The file name `string_view_test.cc` strongly suggests it contains unit tests for the `StringView` class.
2. **Analyze the tests:**  Go through the `TEST` macros in the code to understand what aspects of `StringView` are being tested. These tests cover construction, comparison, properties (like `IsEmpty`, `Is8Bit`), and conversions.
3. **Connect to web technologies:**  Think about where string manipulation is crucial in the rendering engine. This involves representing text content in HTML, styling with CSS (especially string-based properties like font names), and interactions with JavaScript.
4. **Illustrate with examples:** Create concrete scenarios showing how `StringView` might be used internally when processing web content.
5. **Infer input/output:** For some tests, I can make assumptions about the input `StringView` and deduce the expected output based on the test's assertion.
6. **Highlight potential errors:**  Consider common mistakes developers might make when working with strings or views, such as incorrect indexing, out-of-bounds access, or misuse of methods.
这个文件 `string_view_test.cc` 是 Chromium Blink 渲染引擎中 `WTF::StringView` 类的单元测试文件。它的主要功能是 **验证 `StringView` 类的各种功能是否正常工作**。

具体来说，它通过编写一系列的测试用例，覆盖了 `StringView` 类的以下方面：

**1. 构造函数 (Construction):**

*   **从不同类型的字符串创建 `StringView`:**
    *   `StringImpl*` (Blink 内部的字符串实现类)
    *   `String&` (Blink 的字符串类)
    *   `AtomicString&` (Blink 的原子字符串类，用于表示不会改变的字符串)
    *   `StringView&` (已存在的 `StringView` 对象)
    *   `const char*` (C 风格的 8 位字符数组)
    *   `const LChar*` (Blink 特定的 8 位字符类型)
    *   `const UChar*` (Blink 特定的 16 位字符类型，用于 Unicode)
    *   `base::span<const LChar>` 和 `base::span<const UChar>` (表示字符数组的跨度)
*   **支持指定偏移量和长度来创建子串的 `StringView`。**
*   **验证创建的 `StringView` 对象的属性是否正确:**
    *   是否为 8 位 (`Is8Bit()`)
    *   是否为空 (`IsNull()`)
    *   字符指针 (`Characters8()`, `Characters16()`)
    *   长度 (`length()`)
    *   字符串内容是否一致 (通过直接比较或使用 `EXPECT_EQ`)

**2. 属性和方法 (Properties and Methods):**

*   **`IsEmpty()`:**  检查 `StringView` 是否为空。
*   **`ToString()`:** 将 `StringView` 转换为 `WTF::String` 对象。
*   **`ToAtomicString()`:** 将 `StringView` 转换为 `WTF::AtomicString` 对象。
*   **`IsNull()`:** 检查 `StringView` 是否为空 (null)。
*   **下标访问 `[]`:**  访问 `StringView` 中指定索引的字符。
*   **`SubstringContainsOnlyWhitespaceOrEmpty()`:** 检查 `StringView` 的子串是否只包含空白字符或为空。
*   **`NextCodePointOffset()`:**  获取下一个 Unicode 代码点的偏移量，用于处理多字节字符。
*   **字符串比较 (通过 `EXPECT_EQ`):** 验证 `StringView` 与其他字符串类型（`const char*`, `String`, `StringView`）的相等性。
*   **忽略 ASCII 大小的比较 (`EqualIgnoringASCIICase`):**  比较两个 `StringView` 在忽略 ASCII 字符大小写的情况下是否相等。
*   **已弃用的忽略大小写比较 (`DeprecatedEqualIgnoringCase`):**  测试一个已弃用的忽略大小写比较函数。

**3. 安全性 (Security):**

*   **测试构造函数和 `set` 方法中是否存在溢出 (Overflow):**  使用 `EXPECT_DEATH_IF_SUPPORTED` 宏来检查在提供非法长度时是否会触发断言或崩溃 (仅在 `ENABLE_SECURITY_ASSERT` 宏定义时启用)。

**与 JavaScript, HTML, CSS 的关系:**

`StringView` 在 Blink 渲染引擎中被广泛用于处理和操作文本数据，而文本数据是构成网页内容的基础。它与 JavaScript, HTML, CSS 的功能都有密切关系：

*   **HTML 解析:** 当浏览器解析 HTML 文档时，标签名、属性名、属性值以及文本节点的内容都可能以 `StringView` 的形式存在。例如，解析 `<div class="container">Hello</div>` 时，`"div"`, `"class"`, `"container"`, `"Hello"` 等都可以用 `StringView` 来表示。
    *   **假设输入:** HTML 字符串片段 `"<span>world</span>"`
    *   **内部处理:** HTML 解析器可能会使用 `StringView` 来引用 `"span"` 和 `"world"` 这两个字符串，而无需立即复制它们。

*   **CSS 解析:**  CSS 样式规则中的选择器、属性名、属性值等也是文本信息。例如，在解析 `".container { color: blue; }"` 时，`".container"`, `"color"`, `"blue"` 可以用 `StringView` 来表示。
    *   **假设输入:** CSS 字符串片段 `".title { font-size: 16px; }"`
    *   **内部处理:** CSS 解析器可能会使用 `StringView` 来引用 `".title"` 和 `"font-size"`。

*   **JavaScript 字符串操作:** 当 JavaScript 代码操作字符串时，例如获取子字符串、比较字符串等，Blink 引擎内部会将 JavaScript 字符串转换为 Blink 的字符串类型（可能涉及 `StringView`）。
    *   **假设输入:** JavaScript 代码 `const str = "example"; const sub = str.substring(2);`
    *   **内部处理:** 当执行 `substring(2)` 时，Blink 可能会创建一个指向 `"ample"` 的 `StringView`，而无需复制原始字符串。

*   **DOM 操作:**  当 JavaScript 代码访问或修改 DOM 节点的文本内容时，例如 `element.textContent`，Blink 引擎会使用 `StringView` 来表示这些文本内容。
    *   **假设输入:**  一个包含文本 "Blink" 的 HTML 元素。JavaScript 代码 `element.textContent`.
    *   **内部处理:**  `element.textContent` 的返回值在 Blink 内部可能先以 `StringView` 的形式存在。

**逻辑推理的假设输入与输出:**

*   **测试 `ConstructionStringImpl8`:**
    *   **假设输入:** 一个包含 "abcde" 的 `StringImpl` 对象。
    *   **`StringView(impl8_bit.get(), 2)` 的输出:**  一个指向 "cde" 的 `StringView` 对象。
    *   **`StringView(impl8_bit.get(), 2, 1)` 的输出:** 一个指向 "c" 的 `StringView` 对象。

*   **测试 `EqualIgnoringASCIICase`:**
    *   **假设输入:** `StringView("hello")` 和 `StringView("HELLO")`。
    *   **输出:** `EqualIgnoringASCIICase` 返回 `true`。
    *   **假设输入:** `StringView("hello")` 和 `StringView("hell")`。
    *   **输出:** `EqualIgnoringASCIICase` 返回 `false`。

*   **测试 `SubstringContainsOnlyWhitespaceOrEmpty`:**
    *   **假设输入:** `StringView("  \t\n")`.
    *   **`SubstringContainsOnlyWhitespaceOrEmpty(0, 4)` 的输出:** `true`.
    *   **假设输入:** `StringView("  a\n")`.
    *   **`SubstringContainsOnlyWhitespaceOrEmpty(0, 4)` 的输出:** `false`.

**用户或编程常见的使用错误:**

*   **越界访问:**  `StringView` 并不拥有它指向的字符串的内存。如果原始字符串被释放或修改，而 `StringView` 仍然指向它，则会导致未定义行为。
    *   **示例:**
        ```c++
        WTF::String createString() {
          return WTF::String("temporary");
        }

        void processStringView() {
          WTF::String str = createString();
          WTF::StringView view = str;
          // ... 一些操作 ...
        } // str 在这里被销毁

        void laterUse(WTF::StringView view) {
          // 尝试访问已经销毁的字符串，导致错误
          if (!view.IsNull()) {
            char firstChar = view[0];
          }
        }

        // 调用
        processStringView();
        // 稍后尝试使用 view，可能会崩溃或产生不可预测的结果
        // laterUse(view); // 假设 view 被传递到这里，这是错误的
        ```
    *   **正确做法:** 确保 `StringView` 的生命周期不超过其指向的字符串的生命周期。

*   **错误的偏移量或长度:** 在创建子串 `StringView` 时，如果提供的偏移量或长度超出原始字符串的范围，会导致错误，甚至可能触发断言 (如果启用了安全断言)。
    *   **示例:**
        ```c++
        WTF::String str = "example";
        WTF::StringView view = str;
        WTF::StringView subview = view.Substring(3, 10); // 长度 10 超出剩余字符串的长度
        ```
    *   **正确做法:**  在创建子串时，始终检查偏移量和长度的有效性。

*   **假设 `StringView` 持有字符串:**  新手可能会错误地认为 `StringView` 像 `WTF::String` 一样拥有字符串的内存。`StringView` 只是一个视图，不负责内存管理。
    *   **错误理解:**  修改 `StringView` 会修改原始字符串。
    *   **正确理解:** `StringView` 提供了对现有字符串的只读访问。

*   **在需要 `WTF::String` 的地方使用 `StringView` 而没有显式转换:** 虽然 `StringView` 可以隐式转换为 `WTF::String` 在某些上下文中，但并非所有 API 都接受 `StringView`。在需要 `WTF::String` 的情况下，应使用 `ToString()` 进行显式转换。

总而言之，`string_view_test.cc` 通过全面的测试用例，确保了 `StringView` 这一核心字符串视图工具在 Blink 引擎中的正确性和稳定性，这对于高效地处理网页内容至关重要。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/string_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_impl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace WTF {

const char kChars[] = "12345";
const char16_t kCharsU[] = u"12345";
const LChar* const kChars8 = reinterpret_cast<const LChar*>(kChars);
const UChar* const kChars16 = reinterpret_cast<const UChar*>(kCharsU);

TEST(StringViewTest, ConstructionStringImpl8) {
  scoped_refptr<StringImpl> impl8_bit = StringImpl::Create({kChars8, 5u});

  // StringView(StringImpl*);
  ASSERT_TRUE(StringView(impl8_bit.get()).Is8Bit());
  EXPECT_FALSE(StringView(impl8_bit.get()).IsNull());
  EXPECT_EQ(impl8_bit->Characters8(),
            StringView(impl8_bit.get()).Characters8());
  EXPECT_EQ(impl8_bit->length(), StringView(impl8_bit.get()).length());
  EXPECT_EQ(kChars, StringView(impl8_bit.get()));

  // StringView(StringImpl*, unsigned offset);
  ASSERT_TRUE(StringView(impl8_bit.get(), 2).Is8Bit());
  EXPECT_FALSE(StringView(impl8_bit.get(), 2).IsNull());
  EXPECT_EQ(impl8_bit->Characters8() + 2,
            StringView(impl8_bit.get(), 2).Characters8());
  EXPECT_EQ(3u, StringView(impl8_bit.get(), 2).length());
  EXPECT_EQ(StringView("345"), StringView(impl8_bit.get(), 2));
  EXPECT_EQ("345", StringView(impl8_bit.get(), 2));

  // StringView(StringImpl*, unsigned offset, unsigned length);
  ASSERT_TRUE(StringView(impl8_bit.get(), 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(impl8_bit.get(), 2, 1).IsNull());
  EXPECT_EQ(impl8_bit->Characters8() + 2,
            StringView(impl8_bit.get(), 2, 1).Characters8());
  EXPECT_EQ(1u, StringView(impl8_bit.get(), 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(impl8_bit.get(), 2, 1));
  EXPECT_EQ("3", StringView(impl8_bit.get(), 2, 1));
}

TEST(StringViewTest, ConstructionStringImpl16) {
  scoped_refptr<StringImpl> impl16_bit = StringImpl::Create({kChars16, 5u});

  // StringView(StringImpl*);
  ASSERT_FALSE(StringView(impl16_bit.get()).Is8Bit());
  EXPECT_FALSE(StringView(impl16_bit.get()).IsNull());
  EXPECT_EQ(impl16_bit->Characters16(),
            StringView(impl16_bit.get()).Characters16());
  EXPECT_EQ(impl16_bit->length(), StringView(impl16_bit.get()).length());
  EXPECT_EQ(kChars, StringView(impl16_bit.get()));

  // StringView(StringImpl*, unsigned offset);
  ASSERT_FALSE(StringView(impl16_bit.get(), 2).Is8Bit());
  EXPECT_FALSE(StringView(impl16_bit.get(), 2).IsNull());
  EXPECT_EQ(impl16_bit->Characters16() + 2,
            StringView(impl16_bit.get(), 2).Characters16());
  EXPECT_EQ(3u, StringView(impl16_bit.get(), 2).length());
  EXPECT_EQ(StringView("345"), StringView(impl16_bit.get(), 2));
  EXPECT_EQ("345", StringView(impl16_bit.get(), 2));

  // StringView(StringImpl*, unsigned offset, unsigned length);
  ASSERT_FALSE(StringView(impl16_bit.get(), 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(impl16_bit.get(), 2, 1).IsNull());
  EXPECT_EQ(impl16_bit->Characters16() + 2,
            StringView(impl16_bit.get(), 2, 1).Characters16());
  EXPECT_EQ(1u, StringView(impl16_bit.get(), 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(impl16_bit.get(), 2, 1));
  EXPECT_EQ("3", StringView(impl16_bit.get(), 2, 1));
}

TEST(StringViewTest, ConstructionStringImplRef8) {
  scoped_refptr<StringImpl> impl8_bit = StringImpl::Create({kChars8, 5u});

  // StringView(StringImpl&);
  ASSERT_TRUE(StringView(*impl8_bit).Is8Bit());
  EXPECT_FALSE(StringView(*impl8_bit).IsNull());
  EXPECT_EQ(impl8_bit->Characters8(), StringView(*impl8_bit).Characters8());
  EXPECT_EQ(impl8_bit->length(), StringView(*impl8_bit).length());
  EXPECT_EQ(kChars, StringView(*impl8_bit));

  // StringView(StringImpl&, unsigned offset);
  ASSERT_TRUE(StringView(*impl8_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(*impl8_bit, 2).IsNull());
  EXPECT_EQ(impl8_bit->Characters8() + 2,
            StringView(*impl8_bit, 2).Characters8());
  EXPECT_EQ(3u, StringView(*impl8_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(*impl8_bit, 2));
  EXPECT_EQ("345", StringView(*impl8_bit, 2));

  // StringView(StringImpl&, unsigned offset, unsigned length);
  ASSERT_TRUE(StringView(*impl8_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(*impl8_bit, 2, 1).IsNull());
  EXPECT_EQ(impl8_bit->Characters8() + 2,
            StringView(*impl8_bit, 2, 1).Characters8());
  EXPECT_EQ(1u, StringView(*impl8_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(*impl8_bit, 2, 1));
  EXPECT_EQ("3", StringView(*impl8_bit, 2, 1));
}

TEST(StringViewTest, ConstructionStringImplRef16) {
  scoped_refptr<StringImpl> impl16_bit = StringImpl::Create({kChars16, 5u});

  // StringView(StringImpl&);
  ASSERT_FALSE(StringView(*impl16_bit).Is8Bit());
  EXPECT_FALSE(StringView(*impl16_bit).IsNull());
  EXPECT_EQ(impl16_bit->Characters16(), StringView(*impl16_bit).Characters16());
  EXPECT_EQ(impl16_bit->length(), StringView(*impl16_bit).length());
  EXPECT_EQ(kChars, StringView(*impl16_bit));

  // StringView(StringImpl&, unsigned offset);
  ASSERT_FALSE(StringView(*impl16_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(*impl16_bit, 2).IsNull());
  EXPECT_EQ(impl16_bit->Characters16() + 2,
            StringView(*impl16_bit, 2).Characters16());
  EXPECT_EQ(3u, StringView(*impl16_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(*impl16_bit, 2));
  EXPECT_EQ("345", StringView(*impl16_bit, 2));

  // StringView(StringImpl&, unsigned offset, unsigned length);
  ASSERT_FALSE(StringView(*impl16_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(*impl16_bit, 2, 1).IsNull());
  EXPECT_EQ(impl16_bit->Characters16() + 2,
            StringView(*impl16_bit, 2, 1).Characters16());
  EXPECT_EQ(1u, StringView(*impl16_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(*impl16_bit, 2, 1));
  EXPECT_EQ("3", StringView(*impl16_bit, 2, 1));
}

TEST(StringViewTest, ConstructionString8) {
  String string8_bit = String(StringImpl::Create({kChars8, 5u}));

  // StringView(const String&);
  ASSERT_TRUE(StringView(string8_bit).Is8Bit());
  EXPECT_FALSE(StringView(string8_bit).IsNull());
  EXPECT_EQ(string8_bit.Characters8(), StringView(string8_bit).Characters8());
  EXPECT_EQ(string8_bit.length(), StringView(string8_bit).length());
  EXPECT_EQ(kChars, StringView(string8_bit));

  // StringView(const String&, unsigned offset);
  ASSERT_TRUE(StringView(string8_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(string8_bit, 2).IsNull());
  EXPECT_EQ(string8_bit.Characters8() + 2,
            StringView(string8_bit, 2).Characters8());
  EXPECT_EQ(3u, StringView(string8_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(string8_bit, 2));
  EXPECT_EQ("345", StringView(string8_bit, 2));

  // StringView(const String&, unsigned offset, unsigned length);
  ASSERT_TRUE(StringView(string8_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(string8_bit, 2, 1).IsNull());
  EXPECT_EQ(string8_bit.Characters8() + 2,
            StringView(string8_bit, 2, 1).Characters8());
  EXPECT_EQ(1u, StringView(string8_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(string8_bit, 2, 1));
  EXPECT_EQ("3", StringView(string8_bit, 2, 1));
}

TEST(StringViewTest, ConstructionString16) {
  String string16_bit = String(StringImpl::Create({kChars16, 5u}));

  // StringView(const String&);
  ASSERT_FALSE(StringView(string16_bit).Is8Bit());
  EXPECT_FALSE(StringView(string16_bit).IsNull());
  EXPECT_EQ(string16_bit.Characters16(),
            StringView(string16_bit).Characters16());
  EXPECT_EQ(string16_bit.length(), StringView(string16_bit).length());
  EXPECT_EQ(kChars, StringView(string16_bit));

  // StringView(const String&, unsigned offset);
  ASSERT_FALSE(StringView(string16_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(string16_bit, 2).IsNull());
  EXPECT_EQ(string16_bit.Characters16() + 2,
            StringView(string16_bit, 2).Characters16());
  EXPECT_EQ(3u, StringView(string16_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(string16_bit, 2));
  EXPECT_EQ("345", StringView(string16_bit, 2));

  // StringView(const String&, unsigned offset, unsigned length);
  ASSERT_FALSE(StringView(string16_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(string16_bit, 2, 1).IsNull());
  EXPECT_EQ(string16_bit.Characters16() + 2,
            StringView(string16_bit, 2, 1).Characters16());
  EXPECT_EQ(1u, StringView(string16_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(string16_bit, 2, 1));
  EXPECT_EQ("3", StringView(string16_bit, 2, 1));
}

TEST(StringViewTest, ConstructionAtomicString8) {
  AtomicString atom8_bit = AtomicString(StringImpl::Create({kChars8, 5u}));

  // StringView(const AtomicString&);
  ASSERT_TRUE(StringView(atom8_bit).Is8Bit());
  EXPECT_FALSE(StringView(atom8_bit).IsNull());
  EXPECT_EQ(atom8_bit.Characters8(), StringView(atom8_bit).Characters8());
  EXPECT_EQ(atom8_bit.length(), StringView(atom8_bit).length());
  EXPECT_EQ(kChars, StringView(atom8_bit));

  // StringView(const AtomicString&, unsigned offset);
  ASSERT_TRUE(StringView(atom8_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(atom8_bit, 2).IsNull());
  EXPECT_EQ(atom8_bit.Characters8() + 2,
            StringView(atom8_bit, 2).Characters8());
  EXPECT_EQ(3u, StringView(atom8_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(atom8_bit, 2));
  EXPECT_EQ("345", StringView(atom8_bit, 2));

  // StringView(const AtomicString&, unsigned offset, unsigned length);
  ASSERT_TRUE(StringView(atom8_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(atom8_bit, 2, 1).IsNull());
  EXPECT_EQ(atom8_bit.Characters8() + 2,
            StringView(atom8_bit, 2, 1).Characters8());
  EXPECT_EQ(1u, StringView(atom8_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(atom8_bit, 2, 1));
  EXPECT_EQ("3", StringView(atom8_bit, 2, 1));
}

TEST(StringViewTest, ConstructionAtomicString16) {
  AtomicString atom16_bit = AtomicString(StringImpl::Create({kChars16, 5u}));

  // StringView(const AtomicString&);
  ASSERT_FALSE(StringView(atom16_bit).Is8Bit());
  EXPECT_FALSE(StringView(atom16_bit).IsNull());
  EXPECT_EQ(atom16_bit.Characters16(), StringView(atom16_bit).Characters16());
  EXPECT_EQ(atom16_bit.length(), StringView(atom16_bit).length());
  EXPECT_EQ(kChars, StringView(atom16_bit));

  // StringView(const AtomicString&, unsigned offset);
  ASSERT_FALSE(StringView(atom16_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(atom16_bit, 2).IsNull());
  EXPECT_EQ(atom16_bit.Characters16() + 2,
            StringView(atom16_bit, 2).Characters16());
  EXPECT_EQ(3u, StringView(atom16_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(atom16_bit, 2));
  EXPECT_EQ("345", StringView(atom16_bit, 2));

  // StringView(const AtomicString&, unsigned offset, unsigned length);
  ASSERT_FALSE(StringView(atom16_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(atom16_bit, 2, 1).IsNull());
  EXPECT_EQ(atom16_bit.Characters16() + 2,
            StringView(atom16_bit, 2, 1).Characters16());
  EXPECT_EQ(1u, StringView(atom16_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(atom16_bit, 2, 1));
  EXPECT_EQ("3", StringView(atom16_bit, 2, 1));
}

TEST(StringViewTest, ConstructionStringView8) {
  StringView view8_bit = StringView(kChars8, 5u);

  // StringView(StringView&);
  ASSERT_TRUE(StringView(view8_bit).Is8Bit());
  EXPECT_FALSE(StringView(view8_bit).IsNull());
  EXPECT_EQ(view8_bit.Characters8(), StringView(view8_bit).Characters8());
  EXPECT_EQ(view8_bit.length(), StringView(view8_bit).length());
  EXPECT_EQ(kChars, StringView(view8_bit));

  // StringView(const StringView&, unsigned offset);
  ASSERT_TRUE(StringView(view8_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(view8_bit, 2).IsNull());
  EXPECT_EQ(view8_bit.Characters8() + 2,
            StringView(view8_bit, 2).Characters8());
  EXPECT_EQ(3u, StringView(view8_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(view8_bit, 2));
  EXPECT_EQ("345", StringView(view8_bit, 2));

  // StringView(const StringView&, unsigned offset, unsigned length);
  ASSERT_TRUE(StringView(view8_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(view8_bit, 2, 1).IsNull());
  EXPECT_EQ(view8_bit.Characters8() + 2,
            StringView(view8_bit, 2, 1).Characters8());
  EXPECT_EQ(1u, StringView(view8_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(view8_bit, 2, 1));
  EXPECT_EQ("3", StringView(view8_bit, 2, 1));
}

TEST(StringViewTest, ConstructionStringView16) {
  StringView view16_bit = StringView(kChars16, 5);

  // StringView(StringView&);
  ASSERT_FALSE(StringView(view16_bit).Is8Bit());
  EXPECT_FALSE(StringView(view16_bit).IsNull());
  EXPECT_EQ(view16_bit.Characters16(), StringView(view16_bit).Characters16());
  EXPECT_EQ(view16_bit.length(), StringView(view16_bit).length());
  EXPECT_EQ(kChars, StringView(view16_bit));

  // StringView(const StringView&, unsigned offset);
  ASSERT_FALSE(StringView(view16_bit, 2).Is8Bit());
  EXPECT_FALSE(StringView(view16_bit, 2).IsNull());
  EXPECT_EQ(view16_bit.Characters16() + 2,
            StringView(view16_bit, 2).Characters16());
  EXPECT_EQ(3u, StringView(view16_bit, 2).length());
  EXPECT_EQ(StringView("345"), StringView(view16_bit, 2));
  EXPECT_EQ("345", StringView(view16_bit, 2));

  // StringView(const StringView&, unsigned offset, unsigned length);
  ASSERT_FALSE(StringView(view16_bit, 2, 1).Is8Bit());
  EXPECT_FALSE(StringView(view16_bit, 2, 1).IsNull());
  EXPECT_EQ(view16_bit.Characters16() + 2,
            StringView(view16_bit, 2, 1).Characters16());
  EXPECT_EQ(1u, StringView(view16_bit, 2, 1).length());
  EXPECT_EQ(StringView("3"), StringView(view16_bit, 2, 1));
  EXPECT_EQ("3", StringView(view16_bit, 2, 1));
}

TEST(StringViewTest, SubstringContainsOnlyWhitespaceOrEmpty) {
  EXPECT_TRUE(StringView("  ").SubstringContainsOnlyWhitespaceOrEmpty(0, 1));
  EXPECT_TRUE(StringView("  ").SubstringContainsOnlyWhitespaceOrEmpty(0, 2));
  EXPECT_TRUE(StringView("\x20\x09\x0A\x0D")
                  .SubstringContainsOnlyWhitespaceOrEmpty(0, 4));
  EXPECT_FALSE(StringView(" a").SubstringContainsOnlyWhitespaceOrEmpty(0, 2));
  EXPECT_TRUE(StringView(" ").SubstringContainsOnlyWhitespaceOrEmpty(1, 1));
  EXPECT_TRUE(StringView("").SubstringContainsOnlyWhitespaceOrEmpty(0, 0));
  EXPECT_TRUE(
      StringView("  \nABC").SubstringContainsOnlyWhitespaceOrEmpty(0, 3));
  EXPECT_FALSE(StringView(" \u090A\n")
                   .SubstringContainsOnlyWhitespaceOrEmpty(
                       0, StringView(" \u090A\n").length()));
  EXPECT_FALSE(
      StringView("\n\x08\x1B").SubstringContainsOnlyWhitespaceOrEmpty(0, 3));
}

TEST(StringViewTest, ConstructionLiteral8) {
  // StringView(const LChar* chars);
  ASSERT_TRUE(StringView(kChars8).Is8Bit());
  EXPECT_FALSE(StringView(kChars8).IsNull());
  EXPECT_EQ(kChars8, StringView(kChars8).Characters8());
  EXPECT_EQ(5u, StringView(kChars8).length());
  EXPECT_EQ(kChars, StringView(kChars8));

  // StringView(const char* chars);
  ASSERT_TRUE(StringView(kChars).Is8Bit());
  EXPECT_FALSE(StringView(kChars).IsNull());
  EXPECT_EQ(kChars8, StringView(kChars).Characters8());
  EXPECT_EQ(5u, StringView(kChars).length());
  EXPECT_EQ(kChars, StringView(kChars));

  // StringView(const LChar* chars, unsigned length);
  ASSERT_TRUE(StringView(kChars8, 2u).Is8Bit());
  EXPECT_FALSE(StringView(kChars8, 2u).IsNull());
  EXPECT_EQ(2u, StringView(kChars8, 2u).length());
  EXPECT_EQ(StringView("12"), StringView(kChars8, 2u));
  EXPECT_EQ("12", StringView(kChars8, 2u));

  // StringView(const char* chars, unsigned length);
  ASSERT_TRUE(StringView(kChars, 2u).Is8Bit());
  EXPECT_FALSE(StringView(kChars, 2u).IsNull());
  EXPECT_EQ(2u, StringView(kChars, 2u).length());
  EXPECT_EQ(StringView("12"), StringView(kChars, 2u));
  EXPECT_EQ("12", StringView(kChars, 2u));
}

TEST(StringViewTest, ConstructionLiteral16) {
  // StringView(const UChar* chars);
  ASSERT_FALSE(StringView(kChars16).Is8Bit());
  EXPECT_FALSE(StringView(kChars16).IsNull());
  EXPECT_EQ(kChars16, StringView(kChars16).Characters16());
  EXPECT_EQ(5u, StringView(kChars16).length());
  EXPECT_EQ(String(kChars16), StringView(kChars16));

  // StringView(const UChar* chars, unsigned length);
  ASSERT_FALSE(StringView(kChars16, 2u).Is8Bit());
  EXPECT_FALSE(StringView(kChars16, 2u).IsNull());
  EXPECT_EQ(kChars16, StringView(kChars16, 2u).Characters16());
  EXPECT_EQ(StringView("12"), StringView(kChars16, 2u));
  EXPECT_EQ(StringView(reinterpret_cast<const UChar*>(u"12")),
            StringView(kChars16, 2u));
  EXPECT_EQ(2u, StringView(kChars16, 2u).length());
  EXPECT_EQ(String("12"), StringView(kChars16, 2u));
}

TEST(StringViewTest, ConstructionSpan8) {
  // StringView(base::span<const LChar> chars);
  const auto kCharsSpan8 = base::byte_span_from_cstring(kChars);
  ASSERT_TRUE(StringView(kCharsSpan8).Is8Bit());
  EXPECT_FALSE(StringView(kCharsSpan8).IsNull());
  EXPECT_EQ(kChars8, StringView(kCharsSpan8).Characters8());
  EXPECT_EQ(5u, StringView(kCharsSpan8).length());
  EXPECT_EQ(kChars, StringView(kCharsSpan8));
}

TEST(StringViewTest, ConstructionSpan16) {
  // StringView(base::span<const UChar> chars);
  const auto kCharsSpan16 = base::span_from_cstring(kCharsU);
  ASSERT_FALSE(StringView(kCharsSpan16).Is8Bit());
  EXPECT_FALSE(StringView(kCharsSpan16).IsNull());
  EXPECT_EQ(kChars16, StringView(kCharsSpan16).Characters16());
  EXPECT_EQ(5u, StringView(kCharsSpan16).length());
  EXPECT_EQ(String(kChars16), StringView(kCharsSpan16));
}

#if ENABLE_SECURITY_ASSERT
TEST(StringViewTest, OverflowInConstructor) {
  EXPECT_DEATH_IF_SUPPORTED(StringView(StringView("12"), 2, -1), "");
}

TEST(StringViewTest, OverflowInSet) {
  EXPECT_DEATH_IF_SUPPORTED(StringView(String("12"), 2, -1), "");
}
#endif  // ENABLE_SECURITY_ASSERT

TEST(StringViewTest, IsEmpty) {
  EXPECT_FALSE(StringView(kChars).empty());
  EXPECT_TRUE(StringView(kChars, 0).empty());
  EXPECT_FALSE(StringView(String(kChars)).empty());
  EXPECT_TRUE(StringView(String(kChars), 5).empty());
  EXPECT_TRUE(StringView(String(kChars), 4, 0).empty());
  EXPECT_TRUE(StringView().empty());
  EXPECT_TRUE(StringView("").empty());
  EXPECT_TRUE(StringView(reinterpret_cast<const UChar*>(u"")).empty());
  EXPECT_FALSE(StringView(kChars16).empty());
}

TEST(StringViewTest, ToString) {
  EXPECT_EQ(g_empty_string.Impl(), StringView("").ToString().Impl());
  EXPECT_EQ(g_null_atom.Impl(), StringView().ToString().Impl());
  // NOTE: All the construction tests also check toString().
}

TEST(StringViewTest, ToAtomicString) {
  EXPECT_EQ(g_null_atom.Impl(), StringView().ToAtomicString());
  EXPECT_EQ(g_empty_atom.Impl(), StringView("").ToAtomicString());
  EXPECT_EQ(AtomicString("12"), StringView(kChars8, 2u).ToAtomicString());
  // AtomicString will convert to 8bit if possible when creating the string.
  EXPECT_EQ(AtomicString("12").Impl(),
            StringView(kChars16, 2).ToAtomicString().Impl());
}

TEST(StringViewTest, ToStringImplSharing) {
  String string(kChars);
  EXPECT_EQ(string.Impl(), StringView(string).SharedImpl());
  EXPECT_EQ(string.Impl(), StringView(string).ToString().Impl());
  EXPECT_EQ(string.Impl(), StringView(string).ToAtomicString().Impl());
}

TEST(StringViewTest, NullString) {
  EXPECT_TRUE(StringView().IsNull());
  EXPECT_TRUE(StringView(String()).IsNull());
  EXPECT_TRUE(StringView(AtomicString()).IsNull());
  EXPECT_TRUE(StringView(static_cast<const char*>(nullptr)).IsNull());
  StringView view(kChars);
  EXPECT_FALSE(view.IsNull());
  view.Clear();
  EXPECT_TRUE(view.IsNull());
  EXPECT_EQ(String(), StringView());
  EXPECT_TRUE(StringView().ToString().IsNull());
  EXPECT_FALSE(EqualStringView(StringView(), ""));
  EXPECT_TRUE(EqualStringView(StringView(), StringView()));
  EXPECT_FALSE(EqualStringView(StringView(), "abc"));
  EXPECT_FALSE(EqualStringView("abc", StringView()));
  EXPECT_FALSE(EqualIgnoringASCIICase(StringView(), ""));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(), StringView()));
  EXPECT_FALSE(EqualIgnoringASCIICase(StringView(), "abc"));
  EXPECT_FALSE(EqualIgnoringASCIICase("abc", StringView()));
}

TEST(StringViewTest, IndexAccess) {
  StringView view8(kChars8);
  EXPECT_EQ('1', view8[0]);
  EXPECT_EQ('3', view8[2]);
  StringView view16(kChars16);
  EXPECT_EQ('1', view16[0]);
  EXPECT_EQ('3', view16[2]);
}

TEST(StringViewTest, EqualIgnoringASCIICase) {
  static const char* link8 = "link";
  static const char* link_caps8 = "LINK";
  static const char* non_ascii8 = "a\xE1";
  static const char* non_ascii_caps8 = "A\xE1";
  static const char* non_ascii_invalid8 = "a\xC1";

  static const UChar kLink16[5] = {0x006c, 0x0069, 0x006e, 0x006b, 0};  // link
  static const UChar kLinkCaps16[5] = {0x004c, 0x0049, 0x004e, 0x004b,
                                       0};                         // LINK
  static const UChar kNonASCII16[3] = {0x0061, 0x00e1, 0};         // a\xE1
  static const UChar kNonASCIICaps16[3] = {0x0041, 0x00e1, 0};     // A\xE1
  static const UChar kNonASCIIInvalid16[3] = {0x0061, 0x00c1, 0};  // a\xC1

  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(kLink16), link8));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(kLink16), kLinkCaps16));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(kLink16), link_caps8));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(link8), link_caps8));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(link8), kLink16));

  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(non_ascii8), non_ascii_caps8));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(non_ascii8), kNonASCIICaps16));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(kNonASCII16), kNonASCIICaps16));
  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(kNonASCII16), non_ascii_caps8));
  EXPECT_FALSE(
      EqualIgnoringASCIICase(StringView(non_ascii8), non_ascii_invalid8));
  EXPECT_FALSE(
      EqualIgnoringASCIICase(StringView(non_ascii8), kNonASCIIInvalid16));

  EXPECT_TRUE(EqualIgnoringASCIICase(StringView("link"), "lInK"));
  EXPECT_FALSE(EqualIgnoringASCIICase(StringView("link"), "INKL"));
  EXPECT_FALSE(
      EqualIgnoringASCIICase(StringView("link"), "link different length"));
  EXPECT_FALSE(
      EqualIgnoringASCIICase(StringView("link different length"), "link"));

  EXPECT_TRUE(EqualIgnoringASCIICase(StringView(""), ""));
}

TEST(StringViewTest, DeprecatedEqualIgnoringCase) {
  constexpr UChar kLongSAndKelvin[] = {0x017F, 0x212A, 0};
  EXPECT_TRUE(DeprecatedEqualIgnoringCase("SK", kLongSAndKelvin));
  EXPECT_TRUE(DeprecatedEqualIgnoringCase("sk", kLongSAndKelvin));

  // Turkish-specific mappings are not applied.
  constexpr UChar kSmallDotlessI[] = {0x0131, 0};
  constexpr UChar kCapitalDotI[] = {0x0130, 0};
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("i", kSmallDotlessI));
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("i", kCapitalDotI));

  // DeprecatedEqualIgnoringCase() has length-equality check.
  constexpr UChar kSmallSharpS[] = {0x00DF, 0};
  constexpr UChar kCapitalSharpS[] = {0x1E9E, 0};
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("ss", kSmallSharpS));
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("SS", kSmallSharpS));
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("ss", kCapitalSharpS));
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("SS", kCapitalSharpS));
  constexpr UChar kLigatureFFI[] = {0xFB03, 0};
  EXPECT_FALSE(DeprecatedEqualIgnoringCase("ffi", kLigatureFFI));

  constexpr UChar kLigatureFFIAndSSSS[] = {0xFB03, 's', 's', 's', 's', 0};
  constexpr UChar kFFIAndSharpSs[] = {'f', 'f', 'i', 0x00DF, 0x00DF, 0};
  EXPECT_TRUE(DeprecatedEqualIgnoringCase(kLigatureFFIAndSSSS, kFFIAndSharpSs));
}

TEST(StringViewTest, NextCodePointOffset) {
  StringView view8(kChars8);
  EXPECT_EQ(1u, view8.NextCodePointOffset(0));
  EXPECT_EQ(2u, view8.NextCodePointOffset(1));
  EXPECT_EQ(5u, view8.NextCodePointOffset(4));

  StringView view16(u"A\U0001F197X\U0001F232");
  ASSERT_EQ(6u, view16.length());
  EXPECT_EQ(1u, view16.NextCodePointOffset(0));
  EXPECT_EQ(3u, view16.NextCodePointOffset(1));
  EXPECT_EQ(3u, view16.NextCodePointOffset(2));
  EXPECT_EQ(4u, view16.NextCodePointOffset(3));
  EXPECT_EQ(6u, view16.NextCodePointOffset(4));

  const UChar kLead = 0xD800;
  StringView broken1(&kLead, 1);
  EXPECT_EQ(1u, broken1.NextCodePointOffset(0));

  const UChar kLeadAndNotTrail[] = {0xD800, 0x20, 0};
  StringView broken2(kLeadAndNotTrail);
  EXPECT_EQ(1u, broken2.NextCodePointOffset(0));
  EXPECT_EQ(2u, broken2.NextCodePointOffset(1));

  const UChar kTrail = 0xDC00;
  StringView broken3(&kTrail, 1);
  EXPECT_EQ(1u, broken3.NextCodePointOffset(0));
}

}  // namespace WTF
```