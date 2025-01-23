Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `counter_style_test.cc` immediately suggests it's testing the functionality related to CSS counter styles in the Blink rendering engine. The `#include "third_party/blink/renderer/core/css/counter_style.h"` confirms this.

2. **Examine the Test Structure:** The file uses the Google Test framework (evident by `TEST_F`). This means individual test cases are defined using `TEST_F(ClassName, TestName)`. The class `CounterStyleTest` inherits from `PageTestBase`, indicating it's setting up a test environment involving a Blink rendering context.

3. **Analyze Helper Functions:** The `protected` section reveals two key helper functions:
    * `GetCounterStyle(const char* name)`: This function retrieves a `CounterStyle` object, either from the document's author-defined styles or the user-agent's default styles. This is crucial for getting the counter styles to test.
    * `AddCounterStyle(const char* name, const String& descriptors)`: This function dynamically adds a `@counter-style` rule to the document. This allows for creating and testing custom counter styles. The `InsertStyleElement` and `UpdateAllLifecyclePhasesForTest` are standard Blink testing utilities for injecting CSS and ensuring the rendering engine processes it.

4. **Categorize the Tests:**  Go through each `TEST_F` block and identify the specific aspect of `CounterStyle` being tested. Look for keywords in the test names and the code within the tests. Common categories emerge:
    * **Algorithm Tests:**  Tests named after specific algorithms (`NumericAlgorithm`, `AdditiveAlgorithm`, `AlphabeticAlgorithm`, `CyclicAlgorithm`, `FixedAlgorithm`, `SymbolicAlgorithm`). These tests check the basic number-to-string conversion for each algorithm.
    * **Extends Functionality:** Tests with "Extends" in the name (`ExtendsAdditive`, `SymbolicWithExtendedRange`, `AdditiveWithExtendedRange`, `ExtendArmenianRangeToIncludeZero`, `ExtendArmenianRangeToAuto`). These check how custom counter styles inherit and modify properties from base styles.
    * **Descriptor Tests:** Tests focusing on specific CSS descriptor properties like `negative`, `pad`, `range`, `first-symbol`, `prefix`, `suffix`.
    * **Fallback Mechanism:** Tests specifically checking how counter styles fall back to the default 'decimal' or other specified fallback styles (`CyclicFallback`).
    * **Boundary/Edge Cases:** Tests involving extreme integer values (`ExtremeValuesCyclic`, `ExtremeValuesNumeric`, etc.) to see how the system handles limits.
    * **Specific Counter Style Tests:** Tests for built-in counter styles like 'hebrew', 'lower-armenian', 'upper-armenian', 'korean-hangul-formal', 'korean-hanja-formal', 'korean-hanja-informal', 'ethiopic-numeric'. These ensure the standard implementations are correct.
    * **Accessibility/Speech:**  The `GenerateTextAlternativeSpeakAsDisabled` test focuses on how counter styles are represented for screen readers.

5. **Connect to Web Technologies:**  Consider how `CounterStyle` relates to HTML, CSS, and JavaScript:
    * **CSS:**  The most direct relationship is with the `@counter-style` at-rule. The tests extensively use this to define and manipulate counter styles. The properties being tested (system, symbols, range, prefix, suffix, etc.) are all CSS counter style descriptors.
    * **HTML:** Counter styles are applied to HTML elements using the `list-style-type` CSS property (or the `counter()` function in `content`). The tests don't directly manipulate HTML, but the underlying functionality being tested *enables* this in a browser.
    * **JavaScript:** JavaScript can access and manipulate CSS styles, including `list-style-type`. While this test file is C++, JavaScript interaction is a logical consequence of the CSS functionality being tested.

6. **Reasoning with Input and Output (Hypothetical):** For each test, think about what input the `GenerateRepresentation` method receives and what output is expected. The tests themselves provide these examples through `EXPECT_EQ`. For instance, for `NumericAlgorithm`, inputting -123 expects "-123". For `CyclicAlgorithm`, inputting -1 expects "B".

7. **Identify Potential User/Programming Errors:**  Think about how a web developer might misuse counter styles and how these tests could catch those errors. Examples include:
    * **Invalid `system` values:** Though not directly tested here, this code is part of ensuring that the system handles this.
    * **Incorrect `symbols` or `additive-symbols`:** Leading to unexpected output.
    * **Conflicting or cyclical `fallback` definitions:** The `CyclicFallback` test specifically addresses this.
    * **Ranges that don't include zero for non-numeric systems:** The Armenian tests highlight this.
    * **Exceeding length limits for symbolic or additive systems:** Several tests demonstrate this fallback behavior.

8. **Trace User Actions (Debugging Clues):** Imagine a user seeing an incorrect list marker. How might they reach the code being tested?
    * They inspect the element in developer tools.
    * They see a `list-style-type` or `content: counter()` using a custom `@counter-style`.
    * If the counter is wrong, a browser developer might investigate the rendering engine's logic for that specific counter style. This test file would be a key resource in that debugging process. They could run these tests to isolate the issue.

9. **Refine and Organize:** Structure the analysis logically, covering the file's purpose, its relationship to web technologies, potential errors, and debugging implications. Use clear and concise language.

This systematic approach allows for a comprehensive understanding of the test file's function and its significance within the Blink rendering engine.
这个C++源代码文件 `counter_style_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `blink::CounterStyle` 类的功能。`CounterStyle` 类负责处理 CSS 中 `@counter-style` 规则定义的各种计数器样式。

**主要功能:**

1. **测试计数器样式的生成:**  该文件通过各种测试用例验证了 `CounterStyle` 类根据不同的系统（`system`）和描述符（descriptors）生成计数器表示形式的功能。这包括：
    * **数字算法 (Numeric):** 测试默认的十进制计数器。
    * **加法算法 (Additive):** 测试基于符号加法的计数器，例如罗马数字。
    * **继承加法算法 (Extends Additive):** 测试自定义计数器继承自加法计数器。
    * **加法算法的长度限制 (Additive Length Limit):** 测试加法计数器在达到长度限制时的回退行为。
    * **带有零的加法算法 (Additive With Zero):** 测试加法计数器包含零值符号的情况。
    * **字母算法 (Alphabetic):** 测试基于字母循环的计数器，例如 `lower-alpha`。
    * **循环算法 (Cyclic):** 测试符号循环的计数器。
    * **固定算法 (Fixed):** 测试使用固定数量符号的计数器。
    * **符号算法 (Symbolic):** 测试重复使用符号的计数器。
    * **循环回退 (Cyclic Fallback):** 测试当一个计数器样式无法表示一个值时回退到另一个计数器样式。
2. **测试自定义描述符:**  该文件测试了 `@counter-style` 规则中各种自定义描述符的功能：
    * **`negative` 描述符:** 测试自定义负数前缀和后缀。
    * **`pad` 描述符:** 测试自定义填充字符和长度。
    * **`range` 描述符:** 测试计数器样式生效的数值范围。
    * **`first-symbol` 描述符:** 测试自定义固定计数器的起始值。
    * **`prefix` 和 `suffix` 描述符:** 测试在计数器表示前后添加前缀和后缀的功能。
3. **测试极端值:**  该文件测试了各种计数器样式在处理非常大或非常小的整数时的行为，包括回退到默认的十进制计数器。
4. **测试内置计数器样式:** 该文件测试了一些预定义的计数器样式，例如 `hebrew` (希伯来文), `lower-armenian` (小亚美尼亚文), `upper-armenian` (大亚美尼亚文), `korean-hangul-formal` (韩文数字，正式), `korean-hanja-formal` (韩文汉字，正式), `korean-hanja-informal` (韩文汉字，非正式), 和 `ethiopic-numeric` (埃塞俄比亚数字)。
5. **测试可访问性 (Speak-as):**  测试了 `speak-as` 描述符在禁用时，`GenerateTextAlternative` 方法的输出，这涉及到屏幕阅读器如何呈现列表。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 该文件直接测试了 CSS 的 `@counter-style` 规则的实现。`@counter-style` 允许开发者自定义列表项的标记样式。例如：

   ```css
   @counter-style thumbs {
     system: cyclic;
     symbols: 👍, 👎;
     suffix: ' ';
   }

   ol {
     list-style-type: thumbs;
   }
   ```
   `counter_style_test.cc` 中的测试用例会验证 Blink 引擎是否正确解析并应用了这个自定义的 `thumbs` 计数器样式。例如，`TEST_F(CounterStyleTest, CyclicAlgorithm)` 就是在测试类似 `system: cyclic; symbols: A B C;` 的行为。

* **HTML:**  CSS 中定义的计数器样式会应用到 HTML 的有序列表 (`<ol>`) 或通过 CSS `counter()` 函数在伪元素中生成内容。例如：

   ```html
   <ol>
     <li>Item 1</li>
     <li>Item 2</li>
   </ol>

   <div class="numbered">This is item one.</div>
   ```

   ```css
   .numbered::before {
     content: counter(my-counter) ". ";
     counter-increment: my-counter;
   }
   ```
   虽然 `counter_style_test.cc` 不直接操作 HTML 元素，但它确保了 Blink 引擎能够正确渲染应用了这些计数器样式的 HTML 内容。

* **JavaScript:**  JavaScript 可以通过 DOM API 获取和修改元素的样式，包括 `list-style-type` 属性。开发者可以使用 JavaScript 动态地改变列表的计数器样式。 例如：

   ```javascript
   const orderedList = document.querySelector('ol');
   orderedList.style.listStyleType = 'upper-roman';
   ```
   `counter_style_test.cc` 中测试的 `CounterStyle` 类的功能是 Blink 引擎处理这些 JavaScript 操作的基础。

**逻辑推理的假设输入与输出:**

以 `TEST_F(CounterStyleTest, NumericAlgorithm)` 为例：

* **假设输入:**  `decimal` 计数器样式，以及整数 `-123`, `0`, `456`。
* **逻辑推理:** `decimal` 计数器样式应该直接将整数转换为字符串表示。
* **预期输出:** `"-123"`, `"0"`, `"456"`。

以 `TEST_F(CounterStyleTest, CyclicAlgorithm)` 为例：

* **假设输入:** 自定义计数器样式 `foo`，`system: cyclic; symbols: A B C;`，以及整数 `-100`, `-1`, `0`, `1`, `2`, `3`, `4`, `100`。
* **逻辑推理:** `cyclic` 系统会循环使用提供的符号。对于负数，它会从最后一个符号向前循环。
* **预期输出:** `"B"`, `"B"`, `"C"`, `"A"`, `"B"`, `"C"`, `"A"`, `"A"`。

**用户或编程常见的使用错误举例说明:**

1. **错误的 `system` 值:** 用户可能会在 `@counter-style` 中使用无效的 `system` 值，例如 `system: invalid-system;`。Blink 引擎需要能够识别并处理这种错误，可能回退到默认样式。虽然这个测试文件没有直接测试错误处理，但其目标是确保正确的 `system` 值能够正常工作。

2. **`fallback` 循环引用:** 用户可能定义了相互引用的 `fallback` 计数器样式，导致无限循环。例如：

   ```css
   @counter-style style-a {
     system: fixed;
     symbols: X;
     fallback: style-b;
   }

   @counter-style style-b {
     system: fixed;
     symbols: Y;
     fallback: style-a;
   }
   ```
   `TEST_F(CounterStyleTest, CyclicFallback)` 就是为了测试 Blink 引擎如何打破这种循环，通常会回退到 `decimal` 样式。

3. **`range` 限制导致无法表示:** 用户可能定义了 `range` 限制，使得某些数值无法被特定的计数器样式表示。例如：

   ```css
   @counter-style limited-roman {
     system: upper-roman;
     range: 1 10;
   }
   ```
   如果一个列表项的计数器值超过 10，`limited-roman` 将无法表示，Blink 引擎会根据规则（通常是回退到 `decimal`）来处理。测试用例中很多都覆盖了超出 `range` 的情况。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上看到一个有序列表的编号显示不正确，想要调试这个问题，可能的步骤如下：

1. **用户打开网页，发现列表编号错误。** 例如，应该显示罗马数字，却显示了阿拉伯数字。
2. **用户打开开发者工具 (通常按 F12)。**
3. **用户使用“检查元素”工具选中错误的列表项。**
4. **在“Elements”面板的“Styles”或“Computed”标签中，用户查看该列表项应用的 CSS 样式。**
5. **用户可能会看到 `list-style-type` 属性设置为某个自定义的 `@counter-style` 名称，或者是一个内置的计数器样式名称 (如 `upper-roman`)。**
6. **如果使用的是自定义的 `@counter-style`，用户会查看 `@counter-style` 的定义，检查 `system`，`symbols`，`range`，`fallback` 等属性是否正确。**
7. **如果问题涉及到 Blink 引擎对 `@counter-style` 的解析和渲染逻辑，开发人员可能会需要查看 Blink 的源代码。**  `blink/renderer/core/css/counter_style_test.cc` 文件就是在这个阶段作为调试线索出现的。
8. **开发人员可以运行 `counter_style_test.cc` 中的相关测试用例，来验证 Blink 引擎在该特定情况下的行为是否符合预期。** 例如，如果用户的问题是自定义的 `cyclic` 计数器显示错误，开发人员可以检查 `TEST_F(CounterStyleTest, CyclicAlgorithm)` 或与之相关的测试用例。
9. **通过阅读测试用例的代码和断言，开发人员可以理解 Blink 引擎是如何处理各种计数器样式及其描述符的。** 这有助于定位问题是出在 CSS 规则的定义上，还是 Blink 引擎的实现上。

总而言之，`counter_style_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 CSS 计数器样式的核心功能能够正确工作，从而保证了网页渲染的准确性，并为开发者提供了可靠的 CSS 计数器功能。

### 提示词
```
这是目录为blink/renderer/core/css/counter_style_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/counter_style.h"

#include "third_party/blink/renderer/core/css/counter_style_map.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class CounterStyleTest : public PageTestBase {
 protected:
  const CounterStyle& GetCounterStyle(const char* name) {
    AtomicString name_string(name);
    if (const CounterStyleMap* document_map =
            CounterStyleMap::GetAuthorCounterStyleMap(GetDocument())) {
      return *document_map->FindCounterStyleAcrossScopes(name_string);
    }
    return *CounterStyleMap::GetUACounterStyleMap()
                ->FindCounterStyleAcrossScopes(name_string);
  }

  const CounterStyle AddCounterStyle(const char* name,
                                     const String& descriptors) {
    StringBuilder declaration;
    declaration.Append("@counter-style ");
    declaration.Append(name);
    declaration.Append("{");
    declaration.Append(descriptors);
    declaration.Append("}");
    InsertStyleElement(declaration.ToString().Utf8());
    UpdateAllLifecyclePhasesForTest();
    return GetCounterStyle(name);
  }
};

TEST_F(CounterStyleTest, NumericAlgorithm) {
  const CounterStyle& decimal = GetCounterStyle("decimal");
  EXPECT_EQ("-123", decimal.GenerateRepresentation(-123));
  EXPECT_EQ("0", decimal.GenerateRepresentation(0));
  EXPECT_EQ("456", decimal.GenerateRepresentation(456));
}

TEST_F(CounterStyleTest, AdditiveAlgorithm) {
  const CounterStyle& upper_roman = GetCounterStyle("upper-roman");
  EXPECT_EQ("I", upper_roman.GenerateRepresentation(1));
  EXPECT_EQ("CDXLIV", upper_roman.GenerateRepresentation(444));
  EXPECT_EQ("MMMCMXCIX", upper_roman.GenerateRepresentation(3999));

  // Can't represent 0. Fallback to 'decimal'.
  EXPECT_EQ("0", upper_roman.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, ExtendsAdditive) {
  InsertStyleElement("@counter-style foo { system: extends upper-roman; }");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle("foo");
  EXPECT_EQ("I", foo.GenerateRepresentation(1));
  EXPECT_EQ("CDXLIV", foo.GenerateRepresentation(444));
  EXPECT_EQ("MMMCMXCIX", foo.GenerateRepresentation(3999));

  // Can't represent 0. Fallback to 'decimal'.
  EXPECT_EQ("0", foo.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, AdditiveLengthLimit) {
  InsertStyleElement(
      "@counter-style foo { system: additive; additive-symbols: 1 I; }");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle("foo");
  EXPECT_EQ("I", foo.GenerateRepresentation(1));
  EXPECT_EQ("II", foo.GenerateRepresentation(2));
  EXPECT_EQ("III", foo.GenerateRepresentation(3));

  // Length limit exceeded. Fallback to 'decimal'.
  EXPECT_EQ("1000000", foo.GenerateRepresentation(1000000));
}

TEST_F(CounterStyleTest, AdditiveWithZero) {
  InsertStyleElement(
      "@counter-style foo { system: additive; additive-symbols: 1 I, 0 O; }");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle("foo");
  EXPECT_EQ("O", foo.GenerateRepresentation(0));
  EXPECT_EQ("I", foo.GenerateRepresentation(1));
  EXPECT_EQ("II", foo.GenerateRepresentation(2));
  EXPECT_EQ("III", foo.GenerateRepresentation(3));
}

TEST_F(CounterStyleTest, AlphabeticAlgorithm) {
  const CounterStyle& lower_alpha = GetCounterStyle("lower-alpha");
  EXPECT_EQ("a", lower_alpha.GenerateRepresentation(1));
  EXPECT_EQ("ab", lower_alpha.GenerateRepresentation(28));
  EXPECT_EQ("cab", lower_alpha.GenerateRepresentation(26 + 26 * 26 * 3 + 2));
}

TEST_F(CounterStyleTest, CyclicAlgorithm) {
  InsertStyleElement("@counter-style foo { system: cyclic; symbols: A B C; }");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle("foo");
  EXPECT_EQ(String("B"), foo.GenerateRepresentation(-100));
  EXPECT_EQ(String("B"), foo.GenerateRepresentation(-1));
  EXPECT_EQ(String("C"), foo.GenerateRepresentation(0));
  EXPECT_EQ(String("A"), foo.GenerateRepresentation(1));
  EXPECT_EQ(String("B"), foo.GenerateRepresentation(2));
  EXPECT_EQ(String("C"), foo.GenerateRepresentation(3));
  EXPECT_EQ(String("A"), foo.GenerateRepresentation(4));
  EXPECT_EQ(String("A"), foo.GenerateRepresentation(100));
}

TEST_F(CounterStyleTest, FixedAlgorithm) {
  const CounterStyle& eb = GetCounterStyle("cjk-earthly-branch");
  EXPECT_EQ(String(u"\u5B50"), eb.GenerateRepresentation(1));
  EXPECT_EQ(String(u"\u4EA5"), eb.GenerateRepresentation(12));

  // Fallback to cjk-decimal
  EXPECT_EQ("-1", eb.GenerateRepresentation(-1));
  EXPECT_EQ(String(u"\u3007"), eb.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, SymbolicAlgorithm) {
  InsertStyleElement(R"HTML(
    @counter-style upper-alpha-legal {
      system: symbolic;
      symbols: A B C D E F G H I J K L M
               N O P Q R S T U V W X Y Z;
    }
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  const CounterStyle& legal = GetCounterStyle("upper-alpha-legal");

  EXPECT_EQ("A", legal.GenerateRepresentation(1));
  EXPECT_EQ("BB", legal.GenerateRepresentation(28));
  EXPECT_EQ("CCC", legal.GenerateRepresentation(55));

  // Length limit exceeded. Fallback to 'decimal'.
  EXPECT_EQ("1000000", legal.GenerateRepresentation(1000000));
}

TEST_F(CounterStyleTest, CyclicFallback) {
  InsertStyleElement(R"HTML(
    @counter-style foo {
      system: fixed;
      symbols: A B;
      fallback: bar;
    }

    @counter-style bar {
      system: fixed;
      symbols: C D E F;
      fallback: baz;
    }

    @counter-style baz {
      system: additive;
      additive-symbols: 5 V;
      fallback: foo;
    }
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const CounterStyle& foo = GetCounterStyle("foo");
  const CounterStyle& bar = GetCounterStyle("bar");
  const CounterStyle& baz = GetCounterStyle("baz");

  // foo -> bar
  EXPECT_EQ("E", foo.GenerateRepresentation(3));

  // bar -> baz
  EXPECT_EQ("V", bar.GenerateRepresentation(5));

  // baz -> foo
  EXPECT_EQ("A", baz.GenerateRepresentation(1));

  // baz -> foo -> bar
  EXPECT_EQ("F", baz.GenerateRepresentation(4));

  // foo -> bar -> baz -> foo. Break fallback cycle with 'decimal'.
  EXPECT_EQ("6", foo.GenerateRepresentation(6));
}

TEST_F(CounterStyleTest, CustomNegative) {
  InsertStyleElement(R"CSS(
    @counter-style financial-decimal {
      system: extends decimal;
      negative: '(' ')';
    }

    @counter-style extended {
      system: extends financial-decimal;
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Getting custom 'negative' directly from descriptor value.
  const CounterStyle& financial_decimal = GetCounterStyle("financial-decimal");
  EXPECT_EQ("(999)", financial_decimal.GenerateRepresentation(-999));
  EXPECT_EQ("(1)", financial_decimal.GenerateRepresentation(-1));
  EXPECT_EQ("0", financial_decimal.GenerateRepresentation(0));
  EXPECT_EQ("1", financial_decimal.GenerateRepresentation(1));
  EXPECT_EQ("99", financial_decimal.GenerateRepresentation(99));

  // Getting custom 'negative' indirectly by extending a counter style.
  const CounterStyle& extended = GetCounterStyle("extended");
  EXPECT_EQ("(999)", extended.GenerateRepresentation(-999));
  EXPECT_EQ("(1)", extended.GenerateRepresentation(-1));
  EXPECT_EQ("0", extended.GenerateRepresentation(0));
  EXPECT_EQ("1", extended.GenerateRepresentation(1));
  EXPECT_EQ("99", extended.GenerateRepresentation(99));
}

TEST_F(CounterStyleTest, CustomPad) {
  InsertStyleElement(R"CSS(
    @counter-style financial-decimal-pad {
      system: extends decimal;
      negative: '(' ')';
      pad: 4 '0';
    }

    @counter-style extended {
      system: extends financial-decimal-pad;
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Getting custom 'pad' directly from descriptor value.
  const CounterStyle& financial_decimal_pad =
      GetCounterStyle("financial-decimal-pad");
  EXPECT_EQ("(99)", financial_decimal_pad.GenerateRepresentation(-99));
  EXPECT_EQ("(01)", financial_decimal_pad.GenerateRepresentation(-1));
  EXPECT_EQ("0000", financial_decimal_pad.GenerateRepresentation(0));
  EXPECT_EQ("0001", financial_decimal_pad.GenerateRepresentation(1));
  EXPECT_EQ("0099", financial_decimal_pad.GenerateRepresentation(99));

  // Getting custom 'pad' indirectly by extending a counter style.
  const CounterStyle& extended = GetCounterStyle("extended");
  EXPECT_EQ("(99)", extended.GenerateRepresentation(-99));
  EXPECT_EQ("(01)", extended.GenerateRepresentation(-1));
  EXPECT_EQ("0000", extended.GenerateRepresentation(0));
  EXPECT_EQ("0001", extended.GenerateRepresentation(1));
  EXPECT_EQ("0099", extended.GenerateRepresentation(99));
}

TEST_F(CounterStyleTest, PadLengthLimit) {
  InsertStyleElement(R"CSS(
    @counter-style foo {
      system: extends decimal;
      pad: 1000 '0';
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Pad length is too long. Fallback to 'decimal'.
  const CounterStyle& foo = GetCounterStyle("foo");
  EXPECT_EQ("0", foo.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, SymbolicWithExtendedRange) {
  InsertStyleElement(R"CSS(
    @counter-style base {
      system: symbolic;
      symbols: A B;
    }

    @counter-style custom {
      system: extends base;
      range: infinite -2, 0 infinite;
    }

    @counter-style extended {
      system: extends custom;
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Getting custom 'range' directly from descriptor value.
  const CounterStyle& custom = GetCounterStyle("custom");
  EXPECT_EQ("-AA", custom.GenerateRepresentation(-3));
  EXPECT_EQ("-B", custom.GenerateRepresentation(-2));
  // -1 is out of 'range' value. Fallback to 'decimal'
  EXPECT_EQ("-1", custom.GenerateRepresentation(-1));
  // 0 is within 'range' but not representable. Fallback to 'decimal'.
  EXPECT_EQ("0", custom.GenerateRepresentation(0));
  EXPECT_EQ("A", custom.GenerateRepresentation(1));

  // Getting custom 'range' indirectly by extending a counter style.
  const CounterStyle& extended = GetCounterStyle("extended");
  EXPECT_EQ("-AA", extended.GenerateRepresentation(-3));
  EXPECT_EQ("-B", extended.GenerateRepresentation(-2));
  EXPECT_EQ("-1", extended.GenerateRepresentation(-1));
  EXPECT_EQ("0", extended.GenerateRepresentation(0));
  EXPECT_EQ("A", extended.GenerateRepresentation(1));
}

TEST_F(CounterStyleTest, AdditiveWithExtendedRange) {
  InsertStyleElement(R"CSS(
    @counter-style base {
      system: additive;
      additive-symbols: 2 B, 1 A;
    }

    @counter-style custom {
      system: extends base;
      range: infinite -2, 0 infinite;
    }

    @counter-style extended {
      system: extends custom;
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Getting custom 'range' directly from descriptor value.
  const CounterStyle& custom = GetCounterStyle("custom");
  EXPECT_EQ("-BA", custom.GenerateRepresentation(-3));
  EXPECT_EQ("-B", custom.GenerateRepresentation(-2));
  // -1 is out of 'range' value. Fallback to 'decimal'.
  EXPECT_EQ("-1", custom.GenerateRepresentation(-1));
  // 0 is within 'range' but not representable. Fallback to 'decimal'.
  EXPECT_EQ("0", custom.GenerateRepresentation(0));
  EXPECT_EQ("A", custom.GenerateRepresentation(1));

  // Getting custom 'range' indirectly by extending a counter style.
  const CounterStyle& extended = GetCounterStyle("extended");
  EXPECT_EQ("-BA", extended.GenerateRepresentation(-3));
  EXPECT_EQ("-B", extended.GenerateRepresentation(-2));
  EXPECT_EQ("-1", extended.GenerateRepresentation(-1));
  EXPECT_EQ("0", extended.GenerateRepresentation(0));
  EXPECT_EQ("A", extended.GenerateRepresentation(1));
}

TEST_F(CounterStyleTest, CustomFirstSymbolValue) {
  InsertStyleElement(R"CSS(
    @counter-style base {
      system: fixed 2;
      symbols: A B C;
    }

    @counter-style extended {
      system: extends base;
    }
  )CSS");
  UpdateAllLifecyclePhasesForTest();

  // Getting custom first symbol value directly from descriptor value.
  const CounterStyle& base = GetCounterStyle("base");
  EXPECT_EQ("1", base.GenerateRepresentation(1));
  EXPECT_EQ("A", base.GenerateRepresentation(2));
  EXPECT_EQ("B", base.GenerateRepresentation(3));
  EXPECT_EQ("C", base.GenerateRepresentation(4));
  EXPECT_EQ("5", base.GenerateRepresentation(5));

  // Getting custom first symbol value indirectly using 'extends'.
  const CounterStyle& extended = GetCounterStyle("extended");
  EXPECT_EQ("1", extended.GenerateRepresentation(1));
  EXPECT_EQ("A", extended.GenerateRepresentation(2));
  EXPECT_EQ("B", extended.GenerateRepresentation(3));
  EXPECT_EQ("C", extended.GenerateRepresentation(4));
  EXPECT_EQ("5", extended.GenerateRepresentation(5));
}

TEST_F(CounterStyleTest, ExtremeValuesCyclic) {
  const CounterStyle& cyclic =
      AddCounterStyle("cyclic", "system: cyclic; symbols: A B C;");
  EXPECT_EQ("A",
            cyclic.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("A",
            cyclic.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, ExtremeValuesNumeric) {
  const CounterStyle& numeric =
      AddCounterStyle("numeric",
                      "system: numeric; symbols: '0' '1' '2' '3' '4' '5' '6' "
                      "'7' '8' '9' A B C D E F");
  EXPECT_EQ("-80000000",
            numeric.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("7FFFFFFF",
            numeric.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, ExtremeValuesAlphabetic) {
  const CounterStyle& alphabetic = AddCounterStyle(
      "alphabetic",
      "system: alphabetic; symbols: A B C; range: infinite infinite;");
  EXPECT_EQ("-ABAABABBBAACCCACACCB",
            alphabetic.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("ABAABABBBAACCCACACCA",
            alphabetic.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, ExtremeValuesAdditive) {
  const CounterStyle& additive =
      AddCounterStyle("additive",
                      "system: additive; range: infinite infinite;"
                      "additive-symbols: 2000000000 '2B',"
                      "                   100000000 '1CM',"
                      "                    40000000 '4DM',"
                      "                     7000000 '7M',"
                      "                      400000 '4CK',"
                      "                       80000 '8DK',"
                      "                        3000 '3K',"
                      "                         600 '6C',"
                      "                          40 '4D',"
                      "                           8 '8I',"
                      "                           7 '7I';");
  EXPECT_EQ("-2B1CM4DM7M4CK8DK3K6C4D8I",
            additive.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("2B1CM4DM7M4CK8DK3K6C4D7I",
            additive.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, ExtremeValuesSymbolic) {
  // No symbolic counter style can possibly represent such large values without
  // exceeding the length limit. Always fallbacks to 'decimal'.
  const CounterStyle& symbolic = AddCounterStyle(
      "symbolic",
      "system: symbolic; symbols: A B C; range: infinite infinite;");
  EXPECT_EQ("-2147483648",
            symbolic.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("2147483647",
            symbolic.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, ExtremeValuesFixed) {
  const CounterStyle& fixed =
      AddCounterStyle("fixed", "system: fixed 2147483646; symbols: A B C D;");
  // An int subtraction would overflow and return 2 as the result.
  EXPECT_EQ("-2147483648",
            fixed.GenerateRepresentation(std::numeric_limits<int>::min()));
  EXPECT_EQ("B", fixed.GenerateRepresentation(std::numeric_limits<int>::max()));
}

TEST_F(CounterStyleTest, PrefixAndSuffix) {
  const CounterStyle& base = AddCounterStyle(
      "base", "system: symbolic; symbols: A; prefix: X; suffix: Y;");
  EXPECT_EQ("X", base.GetPrefix());
  EXPECT_EQ("Y", base.GetSuffix());

  const CounterStyle& extended =
      AddCounterStyle("extended", "system: extends base");
  EXPECT_EQ("X", extended.GetPrefix());
  EXPECT_EQ("Y", extended.GetSuffix());
}

TEST_F(CounterStyleTest, Hebrew) {
  // Verifies that our 'hebrew' implementation matches the spec in the
  // officially specified range 1-10999.
  // https://drafts.csswg.org/css-counter-styles-3/#hebrew
  const CounterStyle& hebrew_as_specced =
      AddCounterStyle("hebrew-as-specced", R"CSS(
    system: additive;
    range: 1 10999;
    additive-symbols: 10000 \5D9\5F3, 9000 \5D8\5F3, 8000 \5D7\5F3, 7000 \5D6\5F3, 6000 \5D5\5F3, 5000 \5D4\5F3, 4000 \5D3\5F3, 3000 \5D2\5F3, 2000 \5D1\5F3, 1000 \5D0\5F3, 400 \5EA, 300 \5E9, 200 \5E8, 100 \5E7, 90 \5E6, 80 \5E4, 70 \5E2, 60 \5E1, 50 \5E0, 40 \5DE, 30 \5DC, 20 \5DB, 19 \5D9\5D8, 18 \5D9\5D7, 17 \5D9\5D6, 16 \5D8\5D6, 15 \5D8\5D5, 10 \5D9, 9 \5D8, 8 \5D7, 7 \5D6, 6 \5D5, 5 \5D4, 4 \5D3, 3 \5D2, 2 \5D1, 1 \5D0;
  )CSS");
  const CounterStyle& hebrew_as_implemented = GetCounterStyle("hebrew");
  for (int value = 1; value <= 10999; ++value) {
    String expected = hebrew_as_specced.GenerateRepresentation(value);
    String actual = hebrew_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, LowerArmenian) {
  // Verifies that our 'lower-armenian' implementation matches the spec in the
  // officially specified range 1-9999.
  // https://drafts.csswg.org/css-counter-styles-3/#valdef-counter-style-name-lower-armenian
  const CounterStyle& lower_armenian_as_specced =
      AddCounterStyle("lower-armenian-as-specced", R"CSS(
    system: additive;
    range: 1 9999;
    additive-symbols: 9000 "\584", 8000 "\583", 7000 "\582", 6000 "\581", 5000 "\580", 4000 "\57F", 3000 "\57E", 2000 "\57D", 1000 "\57C", 900 "\57B", 800 "\57A", 700 "\579", 600 "\578", 500 "\577", 400 "\576", 300 "\575", 200 "\574", 100 "\573", 90 "\572", 80 "\571", 70 "\570", 60 "\56F", 50 "\56E", 40 "\56D", 30 "\56C", 20 "\56B", 10 "\56A", 9 "\569", 8 "\568", 7 "\567", 6 "\566", 5 "\565", 4 "\564", 3 "\563", 2 "\562", 1 "\561";
  )CSS");
  const CounterStyle& lower_armenian_as_implemented =
      GetCounterStyle("lower-armenian");
  for (int value = 1; value <= 9999; ++value) {
    String expected = lower_armenian_as_specced.GenerateRepresentation(value);
    String actual = lower_armenian_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, UpperArmenian) {
  // Verifies that our 'upper-armenian' implementation matches the spec in the
  // officially specified range 1-9999.
  // https://drafts.csswg.org/css-counter-styles-3/#valdef-counter-style-name-upper-armenian
  const CounterStyle& upper_armenian_as_specced =
      AddCounterStyle("upper-armenian-as-specced", R"CSS(
    system: additive;
    range: 1 9999;
    additive-symbols: 9000 \554, 8000 \553, 7000 \552, 6000 \551, 5000 \550, 4000 \54F, 3000 \54E, 2000 \54D, 1000 \54C, 900 \54B, 800 \54A, 700 \549, 600 \548, 500 \547, 400 \546, 300 \545, 200 \544, 100 \543, 90 \542, 80 \541, 70 \540, 60 \53F, 50 \53E, 40 \53D, 30 \53C, 20 \53B, 10 \53A, 9 \539, 8 \538, 7 \537, 6 \536, 5 \535, 4 \534, 3 \533, 2 \532, 1 \531;
  )CSS");
  const CounterStyle& upper_armenian_as_implemented =
      GetCounterStyle("upper-armenian");
  for (int value = 1; value <= 9999; ++value) {
    String expected = upper_armenian_as_specced.GenerateRepresentation(value);
    String actual = upper_armenian_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, ExtendArmenianRangeToIncludeZero) {
  // 'lower-armenian' and 'upper-armenian' counter styles cannot represent 0.
  // Even if we extend them to include 0 into the range, we still fall back.
  const CounterStyle& extends_lower_armenian =
      AddCounterStyle("extends-lower-armenian", R"CSS(
    system: extends lower-armenian;
    range: 0 infinity;
  )CSS");
  EXPECT_EQ("0", extends_lower_armenian.GenerateRepresentation(0));

  const CounterStyle& extends_upper_armenian =
      AddCounterStyle("extends-upper-armenian", R"CSS(
    system: extends upper-armenian;
    range: 0 infinity;
  )CSS");
  EXPECT_EQ("0", extends_upper_armenian.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, ExtendArmenianRangeToAuto) {
  // 'lower-armenian' and 'upper-armenian' counter styles cannot represent 0,
  // even if we extend their range to 'auto'.
  const CounterStyle& extends_lower_armenian =
      AddCounterStyle("extends-lower-armenian", R"CSS(
    system: extends lower-armenian;
    range: auto;
  )CSS");
  EXPECT_EQ("0", extends_lower_armenian.GenerateRepresentation(0));

  const CounterStyle& extends_upper_armenian =
      AddCounterStyle("extends-upper-armenian", R"CSS(
    system: extends upper-armenian;
    range: 0 auto;
  )CSS");
  EXPECT_EQ("0", extends_upper_armenian.GenerateRepresentation(0));
}

TEST_F(CounterStyleTest, KoreanHangulFormal) {
  // Verifies that our 'korean-hangul-formal' implementation matches the spec in
  // the officially specified range 1-9999.
  // https://drafts.csswg.org/css-counter-styles-3/#korean-hangul-formal
  const CounterStyle& korean_hangul_formal_as_specced =
      AddCounterStyle("korean-hangul-formal-as-specced", R"CSS(
    system: additive;
    range: -9999 9999;
    additive-symbols: 9000 \AD6C\CC9C, 8000 \D314\CC9C, 7000 \CE60\CC9C, 6000 \C721\CC9C, 5000 \C624\CC9C, 4000 \C0AC\CC9C, 3000 \C0BC\CC9C, 2000 \C774\CC9C, 1000 \C77C\CC9C, 900 \AD6C\BC31, 800 \D314\BC31, 700 \CE60\BC31, 600 \C721\BC31, 500 \C624\BC31, 400 \C0AC\BC31, 300 \C0BC\BC31, 200 \C774\BC31, 100 \C77C\BC31, 90 \AD6C\C2ED, 80 \D314\C2ED, 70 \CE60\C2ED, 60 \C721\C2ED, 50 \C624\C2ED, 40 \C0AC\C2ED, 30 \C0BC\C2ED, 20 \C774\C2ED, 10 \C77C\C2ED, 9 \AD6C, 8 \D314, 7 \CE60, 6 \C721, 5 \C624, 4 \C0AC, 3 \C0BC, 2 \C774, 1 \C77C, 0 \C601;
    negative: "\B9C8\C774\B108\C2A4  ";
  )CSS");
  const CounterStyle& korean_hangul_formal_as_implemented =
      GetCounterStyle("korean-hangul-formal");
  for (int value = -9999; value <= 9999; ++value) {
    String expected =
        korean_hangul_formal_as_specced.GenerateRepresentation(value);
    String actual =
        korean_hangul_formal_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, KoreanHanjaFormal) {
  // Verifies that our 'korean-hanja-formal' implementation matches the spec in
  // the officially specified range 1-9999.
  // https://drafts.csswg.org/css-counter-styles-3/#korean-hanja-formal
  const CounterStyle& korean_hanja_formal_as_specced =
      AddCounterStyle("korean-hanja-formal-as-specced", R"CSS(
    system: additive;
    range: -9999 9999;
    additive-symbols: 9000 \4E5D\4EDF, 8000 \516B\4EDF, 7000 \4E03\4EDF, 6000 \516D\4EDF, 5000 \4E94\4EDF, 4000 \56DB\4EDF, 3000 \53C3\4EDF, 2000 \8CB3\4EDF, 1000 \58F9\4EDF, 900 \4E5D\767E, 800 \516B\767E, 700 \4E03\767E, 600 \516D\767E, 500 \4E94\767E, 400 \56DB\767E, 300 \53C3\767E, 200 \8CB3\767E, 100 \58F9\767E, 90 \4E5D\62FE, 80 \516B\62FE, 70 \4E03\62FE, 60 \516D\62FE, 50 \4E94\62FE, 40 \56DB\62FE, 30 \53C3\62FE, 20 \8CB3\62FE, 10 \58F9\62FE, 9 \4E5D, 8 \516B, 7 \4E03, 6 \516D, 5 \4E94, 4 \56DB, 3 \53C3, 2 \8CB3, 1 \58F9, 0 \96F6;
    negative: "\B9C8\C774\B108\C2A4  ";
  )CSS");
  const CounterStyle& korean_hanja_formal_as_implemented =
      GetCounterStyle("korean-hanja-formal");
  for (int value = -9999; value <= 9999; ++value) {
    String expected =
        korean_hanja_formal_as_specced.GenerateRepresentation(value);
    String actual =
        korean_hanja_formal_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, KoreanHanjaInformal) {
  // Verifies that our 'korean-hanja-informal' implementation matches the spec
  // in the officially specified range 1-9999.
  // https://drafts.csswg.org/css-counter-styles-3/#korean-hanja-informal
  const CounterStyle& korean_hanja_informal_as_specced =
      AddCounterStyle("korean-hanja-informal-as-specced", R"CSS(
    system: additive;
    range: -9999 9999;
    additive-symbols: 9000 \4E5D\5343, 8000 \516B\5343, 7000 \4E03\5343, 6000 \516D\5343, 5000 \4E94\5343, 4000 \56DB\5343, 3000 \4E09\5343, 2000 \4E8C\5343, 1000 \5343, 900 \4E5D\767E, 800 \516B\767E, 700 \4E03\767E, 600 \516D\767E, 500 \4E94\767E, 400 \56DB\767E, 300 \4E09\767E, 200 \4E8C\767E, 100 \767E, 90 \4E5D\5341, 80 \516B\5341, 70 \4E03\5341, 60 \516D\5341, 50 \4E94\5341, 40 \56DB\5341, 30 \4E09\5341, 20 \4E8C\5341, 10 \5341, 9 \4E5D, 8 \516B, 7 \4E03, 6 \516D, 5 \4E94, 4 \56DB, 3 \4E09, 2 \4E8C, 1 \4E00, 0 \96F6;
    negative: "\B9C8\C774\B108\C2A4  ";
  )CSS");
  const CounterStyle& korean_hanja_informal_as_implemented =
      GetCounterStyle("korean-hanja-informal");
  for (int value = -9999; value <= 9999; ++value) {
    String expected =
        korean_hanja_informal_as_specced.GenerateRepresentation(value);
    String actual =
        korean_hanja_informal_as_implemented.GenerateRepresentation(value);
    EXPECT_EQ(expected, actual);
  }
}

TEST_F(CounterStyleTest, EthiopicNumeric) {
  const CounterStyle& style = GetCounterStyle("ethiopic-numeric");
  EXPECT_EQ(String(u"\u1369"), style.GenerateRepresentation(1));
  EXPECT_EQ(String(u"\u136A"), style.GenerateRepresentation(2));
  EXPECT_EQ(String(u"\u136B"), style.GenerateRepresentation(3));
  EXPECT_EQ(String(u"\u136C"), style.GenerateRepresentation(4));
  EXPECT_EQ(String(u"\u136D"), style.GenerateRepresentation(5));
  EXPECT_EQ(String(u"\u136E"), style.GenerateRepresentation(6));
  EXPECT_EQ(String(u"\u136F"), style.GenerateRepresentation(7));
  EXPECT_EQ(String(u"\u1370"), style.GenerateRepresentation(8));
  EXPECT_EQ(String(u"\u1371"), style.GenerateRepresentation(9));
  EXPECT_EQ(String(u"\u1372"), style.GenerateRepresentation(10));
  EXPECT_EQ(String(u"\u1372\u1369"), style.GenerateRepresentation(11));
  EXPECT_EQ(String(u"\u1372\u136A"), style.GenerateRepresentation(12));
  EXPECT_EQ(String(u"\u1375\u136B"), style.GenerateRepresentation(43));
  EXPECT_EQ(String(u"\u1378\u136F"), style.GenerateRepresentation(77));
  EXPECT_EQ(String(u"\u1379"), style.GenerateRepresentation(80));
  EXPECT_EQ(String(u"\u137A\u1371"), style.GenerateRepresentation(99));
  EXPECT_EQ(String(u"\u137B"), style.GenerateRepresentation(100));
  EXPECT_EQ(String(u"\u137B\u1369"), style.GenerateRepresentation(101));
  EXPECT_EQ(String(u"\u136A\u137B\u1373\u136A"),
            style.GenerateRepresentation(222));
  EXPECT_EQ(String(u"\u136D\u137B\u1375"), style.GenerateRepresentation(540));
  EXPECT_EQ(String(u"\u1371\u137B\u137A\u1371"),
            style.GenerateRepresentation(999));
  EXPECT_EQ(String(u"\u1372\u137B"), style.GenerateRepresentation(1000));
  EXPECT_EQ(String(u"\u1372\u137B\u136D"), style.GenerateRepresentation(1005));
  EXPECT_EQ(String(u"\u1372\u137B\u1377"), style.GenerateRepresentation(1060));
  EXPECT_EQ(String(u"\u1372\u137B\u1377\u136D"),
            style.GenerateRepresentation(1065));
  EXPECT_EQ(String(u"\u1372\u1370\u137B"), style.GenerateRepresentation(1800));
  EXPECT_EQ(String(u"\u1372\u1370\u137B\u1377"),
            style.GenerateRepresentation(1860));
  EXPECT_EQ(String(u"\u1372\u1370\u137B\u1377\u136D"),
            style.GenerateRepresentation(1865));
  EXPECT_EQ(String(u"\u1376\u1370\u137B\u1377\u136D"),
            style.GenerateRepresentation(5865));
  EXPECT_EQ(String(u"\u1378\u137B\u136D"), style.GenerateRepresentation(7005));
  EXPECT_EQ(String(u"\u1378\u1370\u137B"), style.GenerateRepresentation(7800));
  EXPECT_EQ(String(u"\u1378\u1370\u137B\u1377\u136C"),
            style.GenerateRepresentation(7864));
  EXPECT_EQ(String(u"\u137A\u1371\u137B\u137A\u1371"),
            style.GenerateRepresentation(9999));
  EXPECT_EQ(String(u"\u137C"), style.GenerateRepresentation(10000));
  EXPECT_EQ(String(u"\u1378\u1370\u137B\u1369\u137C\u137A\u136A"),
            style.GenerateRepresentation(78010092));
  EXPECT_EQ(String(u"\u137B\u137C\u1369"),
            style.GenerateRepresentation(1000001));
}

TEST_F(CounterStyleTest, GenerateTextAlternativeSpeakAsDisabled) {
  ScopedCSSAtRuleCounterStyleSpeakAsDescriptorForTest disabled(false);

  AddCounterStyle("base", R"CSS(
    system: fixed;
    symbols: 'One' 'Two' 'Three';
    suffix: '. ';
  )CSS");

  const CounterStyle& bullets = AddCounterStyle("bullets", R"CSS(
    system: extends base;
    speak-as: bullets;
  )CSS");
  EXPECT_EQ("One. ", bullets.GenerateTextAlternative(1));
  EXPECT_EQ("Two. ", bullets.GenerateTextAlternative(2));
  EXPECT_EQ("Three. ", bullets.GenerateTextAlternative(3));

  const CounterStyle& numbers = AddCounterStyle("numbers", R"CSS(
    system: extends base;
    speak-as: numbers;
  )CSS");
  EXPECT_EQ("One. ", numbers.GenerateTextAlternative(1));
  EXPECT_EQ("Two. ", numbers.GenerateTextAlternative(2));
  EXPECT_EQ("Three. ", numbers.GenerateTextAlternative(3));

  const CounterStyle& words = AddCounterStyle("words", R"CSS(
    system: extends base;
    speak-as: words;
  )CSS");
  EXPECT_EQ("One. ", words.GenerateTextAlternative(1));
  EXPECT_EQ("Two. ", words.GenerateTextAlternative(2));
  EXPECT_EQ("Three. ", words.GenerateTextAlternative(3));
}

}  // namespace blink
```