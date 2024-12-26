Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Scan and Keyword Identification:**

The first step is a quick read-through to identify key elements and their purpose. Keywords like `Copyright`, `#include`, `namespace`, `struct`, `static`, `const`, `uint16_t`, `char*`, `bool`, `switch`, and comments containing URLs and descriptions stand out. The file path `blink/renderer/platform/text/mathml_operator_dictionary.cc` immediately suggests this code is related to rendering text, specifically MathML operators.

**2. Understanding the Data Structures:**

The code defines two main data structures:

* `operators_2_ascii_chars`:  A simple array of C-style strings. The comment next to it gives a crucial clue: it lists two-character ASCII representations of MathML operators.
* `EntryRange`: A struct containing `entry` (a `uint16_t`) and `range_bounds_delta` (a 4-bit unsigned integer). The comments and the functions `ExtractKey` and `ExtractCategory` indicate that `entry` encodes both the key (operator) and its category. The `range_bounds_delta` suggests a way to represent ranges of operators efficiently.
* `compact_dictionary`: A `static const` array of `EntryRange`. The comment above it is vital, explaining that this is a compressed representation of the MathML operator dictionary, optimized for storage. It also points to the specification and the Python script used to generate it. This immediately tells us that this is the core data structure for looking up operator properties.

**3. Analyzing the `FindCategory` Function:**

This is the main function. Its purpose is clear from its name: to find the category of a given MathML operator. Let's analyze its steps:

* **Input:** It takes a `String` (presumably the operator's text content) and a `MathMLOperatorDictionaryForm` (prefix, infix, or postfix).
* **Special Cases (Early Exits):** The function first handles single and two-character operators. The 2-character case involves a binary search in `operators_2_ascii_chars`. This reveals a shortcut for common ASCII operators.
* **Compact Dictionary Lookup:**  If the initial checks don't find a match, the code proceeds to look up the operator in the `compact_dictionary`. This involves:
    * **Key Calculation:**  It calculates a `key` from the input `content`. This involves handling Unicode characters and potentially mapping them to a smaller range. The comments here are very important for understanding the mapping logic. The form (prefix/infix/postfix) is also encoded into the `key`.
    * **Binary Search:**  It performs a binary search on `compact_dictionary` using the calculated `key`.
    * **Range Check:** If a potential match is found, it checks if the `key` falls within the range defined by the `EntryRange`.
    * **Category Extraction:** If a match is confirmed, it extracts the category from the `EntryRange`.
* **Special Category Handling:**  Before the compact dictionary lookup, there are checks for specific operators (like `|`, `~`, `,`, `:`, `;`, and certain mathematical symbols) based on the `form`. These are special cases not directly encoded in the compact dictionary.
* **Return Value:** The function returns a `MathMLOperatorDictionaryCategory` enum value, indicating the category of the operator.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

This is where the understanding of the broader Blink/Chromium architecture comes in.

* **MathML in HTML:** MathML is an XML-based language for describing mathematical notation within HTML. The presence of this code strongly suggests that Blink supports rendering MathML.
* **CSS Styling:**  While this specific file doesn't directly interact with CSS parsing, the categories it determines likely influence how MathML operators are styled. For instance, different categories might have different default spacing or rendering properties.
* **JavaScript Interaction:** JavaScript can manipulate the DOM, including MathML elements. While JavaScript wouldn't directly call this C++ function, the behavior defined here affects how MathML is rendered in the browser, which is observable and manipulable by JavaScript. For example, JavaScript could dynamically create or modify MathML, and this dictionary would be used to interpret the operators within that MathML.

**5. Logical Inference and Examples:**

To illustrate the logic, creating simple examples is crucial:

* **Input/Output for 2-character ASCII operators:**  Pick a few examples from `operators_2_ascii_chars` and show how the function would find them.
* **Input/Output for single-character operators in the compact dictionary:** Choose examples from the `compact_dictionary` and trace the key calculation and lookup process. Demonstrate the range check.
* **Input/Output for special cases:** Show how operators like `|` in infix form are handled.

**6. Identifying Potential User/Programming Errors:**

Think about how this code might be misused or lead to unexpected behavior:

* **Incorrect MathML Syntax:** Users might write invalid MathML, and this dictionary might return `kNone` or an incorrect category, leading to rendering issues.
* **Incorrect Form:** If the `form` parameter is passed incorrectly, the function might misclassify an operator. This is more of an internal programming error within Blink.
* **Unsupported Operators:** If a MathML document contains operators not present in the dictionary, they won't be categorized correctly.

**7. Structuring the Explanation:**

Finally, organize the findings into a clear and comprehensive explanation, covering:

* **Purpose of the file.**
* **Key data structures and their function.**
* **Detailed explanation of the `FindCategory` function.**
* **Relationship to HTML, CSS, and JavaScript with concrete examples.**
* **Logical inference examples.**
* **Common errors.**

By following this structured approach, starting with a general understanding and gradually drilling down into the specifics of the code and its context, a thorough and informative explanation can be generated. The key is to connect the low-level C++ code to the higher-level concepts of web technologies and user interactions.
这个文件 `mathml_operator_dictionary.cc` 的主要功能是**定义和提供一个用于查找 MathML 运算符属性的字典**。  更具体地说，它负责确定给定 MathML 运算符（以字符串形式表示）的**类别 (Category)** 和其他相关信息，这对于正确渲染和处理 MathML 内容至关重要。

以下是该文件的详细功能分解：

**1. 存储运算符信息：**

* **`operators_2_ascii_chars` 数组:**  存储了由两个 ASCII 字符组成的常见 MathML 运算符的字符串表示，例如 `"!!"`, `"!="`, `"&&"` 等。这是一个小型的、优化的查找表，用于快速处理这些常见情况。
* **`compact_dictionary` 数组:**  这是一个更庞大、更复杂的数组，存储了大量 MathML 运算符的信息。 为了减少存储空间，它使用了一种紧凑的表示形式，将运算符的 Unicode 编码点和类别信息编码到一个 `EntryRange` 结构中。  这个字典是通过一个 Python 脚本从 MathML 规范生成的。

**2. 提供查找函数：**

* **`FindCategory(const String& content, MathMLOperatorDictionaryForm form)` 函数:** 这是该文件的核心函数。它的作用是：
    * 接收一个表示 MathML 运算符的字符串 `content` 和一个 `MathMLOperatorDictionaryForm` 枚举值 `form`（表示运算符是前缀、中缀还是后缀形式）。
    * 首先检查 `content` 的长度，如果是 2，则在 `operators_2_ascii_chars` 数组中进行二分查找。
    * 如果是单个字符或者不在 `operators_2_ascii_chars` 中，则根据字符的 Unicode 编码点，并结合 `form` 的信息，在 `compact_dictionary` 中进行二分查找。
    * 根据查找到的条目，返回一个 `MathMLOperatorDictionaryCategory` 枚举值，表示该运算符的类别。

**3. 辅助函数和结构体：**

* **`EntryRange` 结构体:** 用于在 `compact_dictionary` 中存储压缩的运算符信息，包含运算符的编码点和类别信息。
* **`ExtractKey` 和 `ExtractCategory` 静态内联函数:** 用于从 `EntryRange` 结构体中提取运算符的编码点（Key）和类别信息。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的一部分，直接服务于 MathML 的渲染过程。它不直接与 JavaScript, HTML, CSS 代码交互，但其功能对于在浏览器中正确显示 MathML 至关重要。

* **HTML:**  当 HTML 文档中包含 `<math>` 标签定义的 MathML 内容时，Blink 渲染引擎会解析这些内容。在解析过程中，会调用 `mathml_operator_dictionary.cc` 中的 `FindCategory` 函数来确定 MathML 运算符的类别。这些类别信息会影响运算符的布局、间距和渲染方式。

    **举例说明：** 假设 HTML 中有如下 MathML 代码：
    ```html
    <math>
      <mn>1</mn> <mo>+</mo> <mn>2</mn>
    </math>
    ```
    当渲染引擎处理 `<mo>+</mo>` 标签时，会调用 `FindCategory("+", MathMLOperatorDictionaryForm::kInfix)`。`FindCategory` 函数会在字典中查找 `+` 运算符，并返回其类别（例如，可能是 `kC`，表示是一个加法运算符）。渲染引擎会根据这个类别信息，在 `1` 和 `2` 之间正确地渲染 `+` 运算符，并设置适当的间距。

* **CSS:** CSS 可以用来样式化 MathML 元素，包括运算符。虽然 CSS 不直接操作 `mathml_operator_dictionary.cc` 的逻辑，但 `FindCategory` 函数返回的运算符类别可能会影响默认的样式规则。例如，不同类别的运算符可能具有不同的默认字体大小或粗细。

    **举例说明：** CSS 可以定义对特定类别的 MathML 运算符应用不同的样式。虽然不太常见直接通过类别选择器来做，但渲染引擎内部会使用这些类别信息来应用默认样式。

* **JavaScript:** JavaScript 可以操作 DOM，包括 MathML 元素。JavaScript 可以动态创建或修改 MathML 内容。当 JavaScript 创建包含运算符的 MathML 结构时，渲染引擎仍然会使用 `mathml_operator_dictionary.cc` 来确定这些运算符的属性并进行渲染。

    **举例说明：**  JavaScript 可以通过以下方式动态创建 MathML：
    ```javascript
    const mathElement = document.createElementNS('http://www.w3.org/1998/Math/MathML', 'math');
    const mn1 = document.createElementNS('http://www.w3.org/1998/Math/MathML', 'mn');
    mn1.textContent = '3';
    const mo = document.createElementNS('http://www.w3.org/1998/Math/MathML', 'mo');
    mo.textContent = '×';
    const mn2 = document.createElementNS('http://www.w3.org/1998/Math/MathML', 'mn');
    mn2.textContent = '4';

    mathElement.appendChild(mn1);
    mathElement.appendChild(mo);
    mathElement.appendChild(mn2);
    document.body.appendChild(mathElement);
    ```
    当浏览器渲染这段代码时，对于 `<mo>×</mo>` 元素，`FindCategory("×", MathMLOperatorDictionaryForm::kInfix)` 会被调用，以确定乘法运算符的类别并进行正确的渲染。

**逻辑推理的假设输入与输出：**

**假设输入 1:**
* `content`: "+"
* `form`: `MathMLOperatorDictionaryForm::kInfix`

**输出 1:**  `MathMLOperatorDictionaryCategory::kC` (假设加号被归类为 Category C，表示像加法或减法这样的二元运算符)

**假设输入 2:**
* `content`: "∑" (求和符号)
* `form`: `MathMLOperatorDictionaryForm::kPrefix`

**输出 2:**  `MathMLOperatorDictionaryCategory::kForG` (假设求和符号被归类为 Category F 或 G，表示像求和或积分这样的运算符)

**假设输入 3:**
* `content`: "!!"
* `form`: `MathMLOperatorDictionaryForm::kPostfix`

**输出 3:** `MathMLOperatorDictionaryCategory::kA` (假设双阶乘被归类为 Category A，表示像阶乘这样的后缀运算符)

**用户或编程常见的使用错误：**

虽然用户通常不会直接与这个 C++ 文件交互，但在编写或生成 MathML 代码时可能会犯一些错误，这些错误会导致 `FindCategory` 返回 `MathMLOperatorDictionaryCategory::kNone` 或错误的类别，从而导致渲染问题。

* **错误的运算符字符串：** 用户可能在 MathML 中使用了拼写错误的运算符，或者使用了不在 MathML 规范中的字符作为运算符。

    **举例说明：**  用户可能错误地输入 `<mo>+<mo>` 而不是 `<mo>+</mo>`，或者使用了自定义的、非标准的符号。`FindCategory` 可能无法识别这些字符串，并返回 `kNone`，导致该符号以默认方式渲染，可能不是预期的运算符样式。

* **未知的运算符：**  MathML 规范不断发展，可能会引入新的运算符。如果用户使用了最新的、但 Blink 引擎尚未支持的运算符，`FindCategory` 也可能返回 `kNone`。

* **内部编程错误（不太常见，但在开发过程中可能发生）：**  Blink 引擎的开发者在处理 MathML 元素时，可能会传递错误的 `MathMLOperatorDictionaryForm` 值给 `FindCategory` 函数。例如，将一个应该作为中缀运算符处理的符号，错误地以 `kPrefix` 的形式传递给 `FindCategory`。这会导致错误的类别判断。

**总结：**

`mathml_operator_dictionary.cc` 是 Blink 渲染引擎中一个关键的组件，它维护着 MathML 运算符的字典，并提供查找运算符类别信息的功能。这个功能对于正确渲染和处理 HTML 中嵌入的 MathML 内容至关重要，尽管用户和前端开发者不会直接与之交互，但其背后的逻辑影响着 MathML 在浏览器中的呈现效果。

Prompt: 
```
这是目录为blink/renderer/platform/text/mathml_operator_dictionary.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/mathml_operator_dictionary.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

// https://w3c.github.io/mathml-core/#operator-dictionary-compact-special-tables
const char* operators_2_ascii_chars[] = {"!!", "!=", "&&", "**", "*=", "++",
                                         "+=", "--", "-=", "->", "//", "/=",
                                         ":=", "<=", "<>", "==", ">=", "||"};

// https://w3c.github.io/mathml-core/#operator-dictionary-categories-hexa-table
struct EntryRange {
  uint16_t entry;
  unsigned range_bounds_delta : 4;
};
static inline uint16_t ExtractKey(const EntryRange& range) {
  return range.entry & 0x3FFF;
}
static inline uint16_t ExtractCategory(const EntryRange& range) {
  return range.entry >> 12;
}

// The following representation is taken from the spec, and reduces storage
// requirements by mapping codepoints and category to better make use of the
// available bytes. For details see
// https://w3c.github.io/mathml-core/#operator-dictionary.
// It was automatically generated from the spec's script:
// https://github.com/w3c/mathml-core/blob/main/tables/operator-dictionary.py
static const EntryRange compact_dictionary[] = {
    {0x8025, 0},  {0x802A, 0},  {0x402B, 0},  {0x402D, 0},  {0x802E, 0},
    {0x402F, 0},  {0x803F, 1},  {0xC05C, 0},  {0x805E, 0},  {0xC05F, 0},
    {0x40B1, 0},  {0x80B7, 0},  {0x80D7, 0},  {0x40F7, 0},  {0x4322, 0},
    {0x8323, 0},  {0x832E, 0},  {0x8422, 0},  {0x8443, 0},  {0x4444, 0},
    {0xC461, 3},  {0x0590, 5},  {0x059A, 15}, {0x05AA, 4},  {0x05B0, 5},
    {0x05B9, 0},  {0x05BC, 15}, {0x05CC, 9},  {0x05DA, 15}, {0x05EA, 6},
    {0x05F3, 12}, {0xC606, 0},  {0x4612, 4},  {0x8617, 2},  {0x4627, 3},
    {0x4636, 0},  {0x4638, 0},  {0x8640, 0},  {0x468C, 2},  {0x4693, 3},
    {0x8697, 0},  {0x4698, 0},  {0x8699, 2},  {0x469D, 2},  {0x86A0, 1},
    {0x86BA, 0},  {0x46BB, 2},  {0x86C4, 3},  {0x86C9, 3},  {0x46CE, 1},
    {0x46D2, 1},  {0x8705, 1},  {0x0B94, 0},  {0x4B95, 2},  {0x0B99, 0},
    {0x0B9B, 6},  {0x0BA5, 1},  {0x0BA8, 7},  {0x0BB1, 0},  {0x0BB3, 0},
    {0x0BB5, 0},  {0x0BB8, 0},  {0x0BBA, 4},  {0x8BCB, 0},  {0x8BCD, 0},
    {0x0BF0, 1},  {0x0BF4, 11}, {0x0D00, 15}, {0x0D10, 15}, {0x0D20, 0},
    {0x0D34, 3},  {0x0D42, 15}, {0x0D52, 15}, {0x0D62, 15}, {0x0D72, 3},
    {0x0D7C, 3},  {0x4DB8, 0},  {0x4DBC, 0},  {0x4DC4, 1},  {0x8DC6, 2},
    {0x8DD4, 3},  {0x8DE2, 0},  {0x4DF5, 6},  {0x8E1D, 1},  {0x4E1F, 15},
    {0x8E2F, 8},  {0x4E38, 2},  {0x8E3B, 2},  {0x4E3E, 0},  {0x8E3F, 0},
    {0x4E40, 15}, {0x8E50, 0},  {0x4E51, 15}, {0x4E61, 2},  {0x8E64, 1},
    {0x4EDB, 0},  {0x8EDC, 1},  {0x4EF6, 0},  {0x4EFB, 0},  {0x4EFD, 0},
    {0x8EFE, 0},  {0x0F04, 3},  {0x0F0C, 5},  {0x0F30, 14}, {0x0F40, 12},
    {0x0F60, 5},  {0x0F6A, 3},  {0x0F70, 3},  {0x0F7A, 3},  {0x0F80, 7},
    {0x0F95, 0},  {0x0FA0, 15}, {0x0FB8, 0},  {0x1021, 0},  {0x5028, 0},
    {0x102B, 0},  {0x102D, 0},  {0x505B, 0},  {0x507B, 1},  {0x10AC, 0},
    {0x10B1, 0},  {0x1331, 0},  {0x5416, 0},  {0x1418, 0},  {0x141C, 0},
    {0x1600, 1},  {0x1603, 1},  {0x1607, 0},  {0xD60F, 2},  {0x1612, 1},
    {0x161F, 3},  {0x962B, 8},  {0x1634, 1},  {0x163C, 0},  {0x16BE, 1},
    {0xD6C0, 3},  {0x5708, 0},  {0x570A, 0},  {0x1710, 0},  {0x1719, 0},
    {0x5729, 0},  {0x5B72, 0},  {0x1B95, 1},  {0x1BC0, 0},  {0x5BE6, 0},
    {0x5BE8, 0},  {0x5BEA, 0},  {0x5BEC, 0},  {0x5BEE, 0},  {0x5D80, 0},
    {0x5D83, 0},  {0x5D85, 0},  {0x5D87, 0},  {0x5D89, 0},  {0x5D8B, 0},
    {0x5D8D, 0},  {0x5D8F, 0},  {0x5D91, 0},  {0x5D93, 0},  {0x5D95, 0},
    {0x5D97, 0},  {0x5D99, 0},  {0x1D9B, 15}, {0x1DAB, 4},  {0x5DD8, 0},
    {0x5DDA, 0},  {0x5DFC, 0},  {0xDE00, 10}, {0x9E0B, 15}, {0x9E1B, 1},
    {0xDE1D, 1},  {0x1EEC, 1},  {0xDEFC, 0},  {0xDEFF, 0},  {0x2021, 1},
    {0x2025, 2},  {0x6029, 0},  {0x605D, 0},  {0xA05E, 1},  {0x2060, 0},
    {0x607C, 1},  {0xA07E, 0},  {0x20A8, 0},  {0xA0AF, 0},  {0x20B0, 0},
    {0x20B2, 2},  {0x20B8, 1},  {0xA2C6, 1},  {0xA2C9, 0},  {0x22CA, 1},
    {0xA2CD, 0},  {0x22D8, 2},  {0xA2DC, 0},  {0x22DD, 0},  {0xA2F7, 0},
    {0xA302, 0},  {0x2311, 0},  {0x2320, 0},  {0x2325, 0},  {0x2327, 0},
    {0x2331, 0},  {0x6416, 0},  {0x2419, 2},  {0x241D, 2},  {0x2432, 5},
    {0xA43E, 0},  {0x2457, 0},  {0x24DB, 1},  {0x6709, 0},  {0x670B, 0},
    {0xA722, 1},  {0x672A, 0},  {0xA7B4, 1},  {0x27CD, 0},  {0xA7DC, 5},
    {0x6B73, 0},  {0x6BE7, 0},  {0x6BE9, 0},  {0x6BEB, 0},  {0x6BED, 0},
    {0x6BEF, 0},  {0x6D80, 0},  {0x6D84, 0},  {0x6D86, 0},  {0x6D88, 0},
    {0x6D8A, 0},  {0x6D8C, 0},  {0x6D8E, 0},  {0x6D90, 0},  {0x6D92, 0},
    {0x6D94, 0},  {0x6D96, 0},  {0x6D98, 1},  {0x6DD9, 0},  {0x6DDB, 0},
    {0x6DFD, 0}};

}  // namespace

MathMLOperatorDictionaryCategory FindCategory(
    const String& content,
    MathMLOperatorDictionaryForm form) {
  DCHECK(!content.Is8Bit());
  // Handle special cases and calculate a BMP code point used for the key.
  uint16_t key{0};
  if (content.length() == 1) {
    UChar32 character = content[0];
    if (character < kCombiningMinusSignBelow ||
        character > kGreekCapitalReversedDottedLunateSigmaSymbol) {
      // Accept BMP characters that are not in the ranges where 2-ASCII-chars
      // operators are mapped below.
      key = character;
    }
  } else if (content.length() == 2) {
    UChar32 character = content.CharacterStartingAt(0);
    if (character == kArabicMathematicalOperatorMeemWithHahWithTatweel ||
        character == kArabicMathematicalOperatorHahWithDal) {
      // Special handling of non-BMP Arabic operators.
      if (form == MathMLOperatorDictionaryForm::kPostfix)
        return MathMLOperatorDictionaryCategory::kI;
      return MathMLOperatorDictionaryCategory::kNone;
    } else if (content[1] == kCombiningLongSolidusOverlay ||
               content[1] == kCombiningLongVerticalLineOverlay) {
      // If the second character is COMBINING LONG SOLIDUS OVERLAY or
      // COMBINING LONG VERTICAL LINE OVERLAY, then use the property of the
      // first character.
      key = content[0];
    } else {
      // Perform a binary search for 2-ASCII-chars operators.
      const char** last =
          operators_2_ascii_chars + std::size(operators_2_ascii_chars);
      const char** entry = std::lower_bound(
          operators_2_ascii_chars, last, content,
          [](const char* lhs, const String& rhs) -> bool {
            return lhs[0] < rhs[0] || (lhs[0] == rhs[0] && lhs[1] < rhs[1]);
          });
      if (entry != last && content == *entry)
        key = kCombiningMinusSignBelow + (entry - operators_2_ascii_chars);
    }
  }

  if (!key)
    return MathMLOperatorDictionaryCategory::kNone;

  // Handle special categories that are not encoded in the compact dictionary.
  // https://w3c.github.io/mathml-core/#operator-dictionary-categories-values
  if (form == MathMLOperatorDictionaryForm::kInfix &&
      (key == kVerticalLineCharacter || key == kTildeOperatorCharacter)) {
    return MathMLOperatorDictionaryCategory::kForceDefault;
  }
  if (form == MathMLOperatorDictionaryForm::kPrefix &&
      ((kDoubleStruckItalicCapitalDCharacter <= key &&
        key <= kDoubleStruckItalicSmallDCharacter) ||
       key == kPartialDifferential ||
       (kSquareRootCharacter <= key && key <= kFourthRootCharacter))) {
    return MathMLOperatorDictionaryCategory::kL;
  }
  if (form == MathMLOperatorDictionaryForm::kInfix &&
      (key == kComma || key == kColon || key == kSemiColon)) {
    return MathMLOperatorDictionaryCategory::kM;
  }
  // Calculate the key for the compact dictionary.
  if (kEnQuadCharacter <= key && key <= kHellschreiberPauseSymbol) {
    // Map above range (U+2000–U+2BFF) to (U+0400-0x0FFF) to fit into
    // 12 bits by decrementing with (U+2000 - U+0400) == 0x1C00.
    key -= 0x1C00;
  } else if (key > kGreekCapitalReversedDottedLunateSigmaSymbol) {
    return MathMLOperatorDictionaryCategory::kNone;
  }
  // Bitmasks used to set form 2-bits (infix=00, prefix=01, postfix=10).
  if (form == MathMLOperatorDictionaryForm::kPrefix)
    key |= 0x1000;
  else if (form == MathMLOperatorDictionaryForm::kPostfix)
    key |= 0x2000;
  DCHECK_LE(key, 0x2FFF);

  // Perform a binary search on the compact dictionary.
  const EntryRange* entry_range = std::upper_bound(
      compact_dictionary, compact_dictionary + std::size(compact_dictionary),
      key, [](uint16_t lhs, EntryRange rhs) -> bool {
        return lhs < ExtractKey(rhs);
      });

  if (entry_range == compact_dictionary)
    return MathMLOperatorDictionaryCategory::kNone;
  entry_range--;

  DCHECK_LE(ExtractKey(*entry_range), key);
  if (key > (ExtractKey(*entry_range) + entry_range->range_bounds_delta))
    return MathMLOperatorDictionaryCategory::kNone;

  // An entry is found: set the properties according the category.
  // https://w3c.github.io/mathml-core/#operator-dictionary-categories-values
  switch (ExtractCategory(*entry_range)) {
    case 0x0:
      return MathMLOperatorDictionaryCategory::kA;
    case 0x4:
      return MathMLOperatorDictionaryCategory::kB;
    case 0x8:
      return MathMLOperatorDictionaryCategory::kC;
    case 0x1:
    case 0x2:
    case 0xC:
      return MathMLOperatorDictionaryCategory::kDorEorK;
    case 0x5:
    case 0x6:
      return MathMLOperatorDictionaryCategory::kForG;
    case 0x9:
      return MathMLOperatorDictionaryCategory::kH;
    case 0xA:
      return MathMLOperatorDictionaryCategory::kI;
    case 0xD:
      return MathMLOperatorDictionaryCategory::kJ;
  }

  NOTREACHED();
}

}  // namespace blink

"""

```