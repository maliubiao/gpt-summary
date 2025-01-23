Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Identify the Core Purpose:** The filename `mathml_operator_dictionary_test.cc` immediately suggests that this file is a test suite for something related to MathML operators. The presence of `TEST` macros from `gtest` confirms this. The included header `"third_party/blink/renderer/platform/text/mathml_operator_dictionary.h"` tells us *what* is being tested.

2. **Understand the Testing Methodology:** The code uses Google Test (`gtest`). Key elements are:
    * `#include "testing/gtest/include/gtest/gtest.h"`: Includes the necessary gtest headers.
    * `TEST(TestSuiteName, TestName)`: Defines individual test cases.
    * `EXPECT_TRUE(condition)`:  A gtest assertion that checks if a condition is true. If the condition is false, the test fails.

3. **Analyze the Test Cases:**  The file has three main test cases: `Infix`, `Prefix`, and `Postfix`. This strongly suggests that the `MathMLOperatorDictionary` likely classifies operators based on their position relative to operands (infix, prefix, postfix).

4. **Examine the Data Structures:** The code defines several `static const UChar32 category_X[]` arrays. `UChar32` suggests these arrays hold Unicode code points. The names of the arrays (`category_a`, `category_b`, etc.) and their use within the test cases hint that these represent different categories of MathML operators.

5. **Trace the Logic within Each Test Case:**  All three test cases follow a similar structure:
    * Iterate through a range of Unicode code points (0 to `kMaxCodepoint`).
    * Convert the code point to a `String`.
    * Call a function `FindCategory(s, MathMLOperatorDictionaryForm::kForm)` with the string and a specific `MathMLOperatorDictionaryForm` (Infix, Prefix, or Postfix).
    * Compare the result of `FindCategory` with an expected `MathMLOperatorDictionaryCategory`. The `IsInCategory` helper function helps determine the expected category.

6. **Identify Key Functions and Enumerations:** By observing the test logic, we can infer the existence and purpose of:
    * `FindCategory(const String&, MathMLOperatorDictionaryForm)`:  This function likely takes a string (representing an operator) and a form (infix, prefix, postfix) and returns the category of that operator in that form.
    * `MathMLOperatorDictionaryForm`: An enumeration or enum class with values like `kInfix`, `kPrefix`, and `kPostfix`.
    * `MathMLOperatorDictionaryCategory`: An enumeration or enum class with values like `kA`, `kB`, `kC`, `kDorEorK`, `kM`, `kForG`, `kH`, `kJ`, `kL`, and `kNone`.

7. **Relate to Web Technologies (HTML, CSS, JavaScript):**  This is where domain knowledge comes in. MathML is a part of HTML5 for rendering mathematical equations. Therefore:
    * **HTML:** The existence of this code is crucial for browsers to correctly render MathML elements in HTML documents. Example:  `<math><mo>+</mo></math>` relies on the browser understanding that `+` is an infix operator.
    * **CSS:** While this C++ code doesn't directly interact with CSS, the *rendering* of MathML elements can be styled using CSS properties. The classification of operators might indirectly influence default styling or how certain CSS rules are applied.
    * **JavaScript:** JavaScript might interact with MathML by dynamically creating or manipulating MathML elements in the DOM. The correctness of the operator dictionary ensures that these dynamically added elements are rendered correctly.

8. **Infer Logic and Assumptions (Hypothetical Inputs and Outputs):** Based on the test cases, we can infer:
    * **Input:** A single Unicode character (represented as a `String`).
    * **Processing:** The `FindCategory` function uses the `MathMLOperatorDictionary` (defined in the `.h` file) to look up the category of the input character based on the provided `MathMLOperatorDictionaryForm`. This likely involves some kind of lookup table or algorithm.
    * **Output:** A `MathMLOperatorDictionaryCategory` value.
    * **Assumption:** The code assumes that the `MathMLOperatorDictionary` has pre-defined categories for various MathML operators.

9. **Consider User/Programming Errors:**  Since this is a test file, it's designed to *prevent* errors. However, thinking about potential errors in the *usage* of the `MathMLOperatorDictionary`:
    * **Incorrect Form:**  A developer might accidentally use the wrong `MathMLOperatorDictionaryForm` when trying to classify an operator, leading to unexpected behavior.
    * **Missing Operator:** If the `MathMLOperatorDictionary` doesn't contain information about a particular Unicode character used as an operator, it might be classified as `kNone`, potentially leading to incorrect rendering.

10. **Structure the Explanation:**  Finally, organize the findings into a clear and logical explanation covering the key aspects: functionality, relationship to web technologies, logic/assumptions, and potential errors. Use examples to illustrate the points.

Self-Correction/Refinement during the process:

* Initially, I might focus too much on the C++ syntax. It's important to quickly move beyond that to understand the *domain* – MathML operators.
* I need to be careful not to overstate the direct interaction with JavaScript or CSS. The relationship is more about providing the foundational logic for correct rendering.
* When describing logic, avoid getting bogged down in implementation details that aren't visible in the test file. Focus on the observable behavior (input and output).

By following these steps, I can effectively analyze the C++ test file and provide a comprehensive explanation of its purpose and relevance.
这个C++源代码文件 `mathml_operator_dictionary_test.cc` 是 Chromium Blink 引擎中用于测试 `MathMLOperatorDictionary` 功能的单元测试文件。它的主要功能是验证 `MathMLOperatorDictionary` 能否正确地将各种 Unicode 字符识别为 MathML 运算符，并根据其在数学表达式中的位置（前缀、中缀、后缀）将其归类到正确的类别。

**主要功能：**

1. **定义运算符类别：**  文件中定义了多个 `static const UChar32 category_X[]` 数组，例如 `category_a`、`category_b` 等。每个数组包含了一组 Unicode 码点，代表属于特定 MathML 运算符类别的字符。这些类别在 `MathMLOperatorDictionaryCategory` 枚举中定义（虽然在这个文件中没有直接看到该枚举的定义，但从使用方式可以推断出来）。

2. **测试中缀运算符分类 (Infix):** `TEST(MathOperatorDictionaryTest, Infix)` 测试用例遍历了所有可能的 Unicode 码点（0 到 `kMaxCodepoint`），并将每个码点转换为字符串。然后，它调用 `FindCategory(s, MathMLOperatorDictionaryForm::kInfix)` 函数，检查该字符作为中缀运算符时是否被归类到预期的类别。`EXPECT_TRUE` 宏用于断言结果是否为真。

3. **测试前缀运算符分类 (Prefix):** `TEST(MathOperatorDictionaryTest, Prefix)` 测试用例执行类似的操作，但调用的是 `FindCategory(s, MathMLOperatorDictionaryForm::kPrefix)`，用于测试字符作为前缀运算符的分类。

4. **测试后缀运算符分类 (Postfix):** `TEST(MathOperatorDictionaryTest, Postfix)` 测试用例同样遍历 Unicode 码点，并调用 `FindCategory(s, MathMLOperatorDictionaryForm::kPostfix)`，测试字符作为后缀运算符的分类。

5. **辅助函数：**
   - `IsInCategory`: 一个模板函数，用于检查给定的 Unicode 字符是否在指定的类别数组中。
   - `FromUChar32`: 一个将 `UChar32` 类型的 Unicode 码点转换为 `String` 的函数。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件所在的 `blink/renderer/platform/text/` 路径表明它属于 Blink 渲染引擎的底层平台代码，负责处理文本相关的操作，其中包括 MathML 的渲染。

* **HTML:** MathML 是一种用于在 HTML 页面中嵌入数学公式的标记语言。浏览器需要正确解析和渲染 MathML 元素，其中包括识别不同的运算符。`MathMLOperatorDictionary` 的作用就是提供这种运算符的分类信息，帮助渲染引擎正确理解 MathML 表达式的结构。例如，当 HTML 中包含 `<math><mn>1</mn><mo>+</mo><mn>2</mn></math>` 时，渲染引擎会使用 `MathMLOperatorDictionary` 来识别 `+` 是一个中缀运算符。

* **CSS:** CSS 可以用来样式化 MathML 元素，包括运算符的显示。虽然这个 C++ 文件本身不直接涉及 CSS，但 `MathMLOperatorDictionary` 的正确性对于 CSS 样式的应用至关重要。例如，CSS 可以设置不同类型运算符的间距或大小，而这需要基于运算符的正确分类。

* **JavaScript:** JavaScript 可以动态地生成和操作 HTML 元素，包括 MathML 元素。如果 JavaScript 代码动态创建包含特定运算符的 MathML 公式，`MathMLOperatorDictionary` 的正确性保证了这些动态生成的公式也能被正确渲染。例如，一个 JavaScript 库可能会根据用户的输入动态生成 MathML 公式，其中包含各种运算符，这些运算符需要被 `MathMLOperatorDictionary` 正确识别。

**逻辑推理 (假设输入与输出)：**

假设 `FindCategory` 函数的实现是基于查找表或某种算法，根据输入的 Unicode 字符和运算符形式（infix, prefix, postfix）返回对应的类别。

**假设输入：** Unicode 字符 `U+002B` (`+`) 和 `MathMLOperatorDictionaryForm::kInfix`。

**预期输出：** `MathMLOperatorDictionaryCategory::kB` （因为 `+` 在 `category_b` 中）。

**假设输入：** Unicode 字符 `U+2211` (`∑`) 和 `MathMLOperatorDictionaryForm::kPrefix`。

**预期输出：** `MathMLOperatorDictionaryCategory::kJ` （因为 `∑` 在 `category_j` 中）。

**假设输入：** Unicode 字符 `U+0021` (`!`) 和 `MathMLOperatorDictionaryForm::kPostfix`。

**预期输出：** `MathMLOperatorDictionaryCategory::kDorEorK` （因为 `!` 在 `category_e` 中）。

**涉及用户或者编程常见的使用错误：**

虽然这个文件是测试代码，但它可以帮助我们理解 `MathMLOperatorDictionary` 的使用场景，从而推断出可能的用户或编程错误：

1. **假设运算符形式错误：**  开发者在处理 MathML 时，可能会错误地假设某个运算符是前缀而不是中缀，或者反之。例如，他们可能错误地认为 `-` 在所有情况下都是前缀运算符（例如在 `-5` 中），而忽略了它也可以是中缀运算符（例如在 `3 - 2` 中）。`MathMLOperatorDictionary` 帮助明确了不同运算符在不同形式下的分类。

   **举例：** 一个渲染 MathML 的程序可能错误地将中缀的减号 `-` (U+002D) 当作前缀处理，导致公式的解析和渲染出现错误。例如，对于 `<math><mn>3</mn><mo>-</mo><mn>2</mn></math>`，如果错误地将其中的 `-` 视为前缀，可能会导致错误的排版或计算。

2. **未知的运算符：** 用户可能会在 MathML 中使用一些非常见或非标准的运算符。如果 `MathMLOperatorDictionary` 中没有包含这些运算符的定义，它们可能不会被正确分类，导致渲染不符合预期。

   **举例：** 如果用户使用了某个自定义的数学符号作为运算符，而该符号没有在 `MathMLOperatorDictionary` 中定义，浏览器可能无法正确识别其类型（前缀、中缀、后缀），从而导致渲染错误或无法应用正确的样式。

3. **Unicode 编码问题：** 在处理 MathML 字符串时，可能会出现 Unicode 编码错误，导致 `FindCategory` 函数接收到的字符与预期不符。

   **举例：**  如果 MathML 字符串的编码不正确，导致减号 `-` 被错误地表示为其他类似的字符，`MathMLOperatorDictionary` 可能无法正确识别，从而影响公式的渲染。

总而言之，`mathml_operator_dictionary_test.cc` 通过详尽的测试用例，确保 `MathMLOperatorDictionary` 能够准确地识别和分类各种 MathML 运算符，这对于 Chromium Blink 引擎正确渲染 HTML 中的 MathML 内容至关重要。它的正确性直接影响到用户在浏览器中看到的数学公式的呈现效果。

### 提示词
```
这是目录为blink/renderer/platform/text/mathml_operator_dictionary_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/mathml_operator_dictionary.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

static const UChar32 category_a[]{
    0x2190, 0x2191, 0x2192, 0x2193, 0x2194, 0x2195, 0x219A, 0x219B, 0x219C,
    0x219D, 0x219E, 0x219F, 0x21A0, 0x21A1, 0x21A2, 0x21A3, 0x21A4, 0x21A5,
    0x21A6, 0x21A7, 0x21A8, 0x21A9, 0x21AA, 0x21AB, 0x21AC, 0x21AD, 0x21AE,
    0x21B0, 0x21B1, 0x21B2, 0x21B3, 0x21B4, 0x21B5, 0x21B9, 0x21BC, 0x21BD,
    0x21BE, 0x21BF, 0x21C0, 0x21C1, 0x21C2, 0x21C3, 0x21C4, 0x21C5, 0x21C6,
    0x21C7, 0x21C8, 0x21C9, 0x21CA, 0x21CB, 0x21CC, 0x21CD, 0x21CE, 0x21CF,
    0x21D0, 0x21D1, 0x21D2, 0x21D3, 0x21D4, 0x21D5, 0x21DA, 0x21DB, 0x21DC,
    0x21DD, 0x21DE, 0x21DF, 0x21E0, 0x21E1, 0x21E2, 0x21E3, 0x21E4, 0x21E5,
    0x21E6, 0x21E7, 0x21E8, 0x21E9, 0x21EA, 0x21EB, 0x21EC, 0x21ED, 0x21EE,
    0x21EF, 0x21F0, 0x21F3, 0x21F4, 0x21F5, 0x21F6, 0x21F7, 0x21F8, 0x21F9,
    0x21FA, 0x21FB, 0x21FC, 0x21FD, 0x21FE, 0x21FF, 0x2794, 0x2799, 0x279B,
    0x279C, 0x279D, 0x279E, 0x279F, 0x27A0, 0x27A1, 0x27A5, 0x27A6, 0x27A8,
    0x27A9, 0x27AA, 0x27AB, 0x27AC, 0x27AD, 0x27AE, 0x27AF, 0x27B1, 0x27B3,
    0x27B5, 0x27B8, 0x27BA, 0x27BB, 0x27BC, 0x27BD, 0x27BE, 0x27F0, 0x27F1,
    0x27F4, 0x27F5, 0x27F6, 0x27F7, 0x27F8, 0x27F9, 0x27FA, 0x27FB, 0x27FC,
    0x27FD, 0x27FE, 0x27FF, 0x2900, 0x2901, 0x2902, 0x2903, 0x2904, 0x2905,
    0x2906, 0x2907, 0x2908, 0x2909, 0x290A, 0x290B, 0x290C, 0x290D, 0x290E,
    0x290F, 0x2910, 0x2911, 0x2912, 0x2913, 0x2914, 0x2915, 0x2916, 0x2917,
    0x2918, 0x2919, 0x291A, 0x291B, 0x291C, 0x291D, 0x291E, 0x291F, 0x2920,
    0x2934, 0x2935, 0x2936, 0x2937, 0x2942, 0x2943, 0x2944, 0x2945, 0x2946,
    0x2947, 0x2948, 0x2949, 0x294A, 0x294B, 0x294C, 0x294D, 0x294E, 0x294F,
    0x2950, 0x2951, 0x2952, 0x2953, 0x2954, 0x2955, 0x2956, 0x2957, 0x2958,
    0x2959, 0x295A, 0x295B, 0x295C, 0x295D, 0x295E, 0x295F, 0x2960, 0x2961,
    0x2962, 0x2963, 0x2964, 0x2965, 0x2966, 0x2967, 0x2968, 0x2969, 0x296A,
    0x296B, 0x296C, 0x296D, 0x296E, 0x296F, 0x2970, 0x2971, 0x2972, 0x2973,
    0x2974, 0x2975, 0x297C, 0x297D, 0x297E, 0x297F, 0x2B04, 0x2B05, 0x2B06,
    0x2B07, 0x2B0C, 0x2B0D, 0x2B0E, 0x2B0F, 0x2B10, 0x2B11, 0x2B30, 0x2B31,
    0x2B32, 0x2B33, 0x2B34, 0x2B35, 0x2B36, 0x2B37, 0x2B38, 0x2B39, 0x2B3A,
    0x2B3B, 0x2B3C, 0x2B3D, 0x2B3E, 0x2B40, 0x2B41, 0x2B42, 0x2B43, 0x2B44,
    0x2B45, 0x2B46, 0x2B47, 0x2B48, 0x2B49, 0x2B4A, 0x2B4B, 0x2B4C, 0x2B60,
    0x2B61, 0x2B62, 0x2B63, 0x2B64, 0x2B65, 0x2B6A, 0x2B6B, 0x2B6C, 0x2B6D,
    0x2B70, 0x2B71, 0x2B72, 0x2B73, 0x2B7A, 0x2B7B, 0x2B7C, 0x2B7D, 0x2B80,
    0x2B81, 0x2B82, 0x2B83, 0x2B84, 0x2B85, 0x2B86, 0x2B87, 0x2B95, 0x2BA0,
    0x2BA1, 0x2BA2, 0x2BA3, 0x2BA4, 0x2BA5, 0x2BA6, 0x2BA7, 0x2BA8, 0x2BA9,
    0x2BAA, 0x2BAB, 0x2BAC, 0x2BAD, 0x2BAE, 0x2BAF, 0x2BB8,
};

static const UChar32 category_b[]{
    0x002B, 0x002D, 0x002F, 0x00B1, 0x00F7, 0x0322, 0x2044, 0x2212, 0x2213,
    0x2214, 0x2215, 0x2216, 0x2227, 0x2228, 0x2229, 0x222A, 0x2236, 0x2238,
    0x228C, 0x228D, 0x228E, 0x2293, 0x2294, 0x2295, 0x2296, 0x2298, 0x229D,
    0x229E, 0x229F, 0x22BB, 0x22BC, 0x22BD, 0x22CE, 0x22CF, 0x22D2, 0x22D3,
    0x2795, 0x2796, 0x2797, 0x29B8, 0x29BC, 0x29C4, 0x29C5, 0x29F5, 0x29F6,
    0x29F7, 0x29F8, 0x29F9, 0x29FA, 0x29FB, 0x2A1F, 0x2A20, 0x2A21, 0x2A22,
    0x2A23, 0x2A24, 0x2A25, 0x2A26, 0x2A27, 0x2A28, 0x2A29, 0x2A2A, 0x2A2B,
    0x2A2C, 0x2A2D, 0x2A2E, 0x2A38, 0x2A39, 0x2A3A, 0x2A3E, 0x2A40, 0x2A41,
    0x2A42, 0x2A43, 0x2A44, 0x2A45, 0x2A46, 0x2A47, 0x2A48, 0x2A49, 0x2A4A,
    0x2A4B, 0x2A4C, 0x2A4D, 0x2A4E, 0x2A4F, 0x2A51, 0x2A52, 0x2A53, 0x2A54,
    0x2A55, 0x2A56, 0x2A57, 0x2A58, 0x2A59, 0x2A5A, 0x2A5B, 0x2A5C, 0x2A5D,
    0x2A5E, 0x2A5F, 0x2A60, 0x2A61, 0x2A62, 0x2A63, 0x2ADB, 0x2AF6, 0x2AFB,
    0x2AFD,
};

static const UChar32 category_c[]{
    0x0025, 0x002A, 0x002E, 0x003F, 0x0040, 0x005E, 0x00B7, 0x00D7,
    0x0323, 0x032E, 0x2022, 0x2043, 0x2217, 0x2218, 0x2219, 0x2240,
    0x2297, 0x2299, 0x229A, 0x229B, 0x22A0, 0x22A1, 0x22BA, 0x22C4,
    0x22C5, 0x22C6, 0x22C7, 0x22C9, 0x22CA, 0x22CB, 0x22CC, 0x2305,
    0x2306, 0x27CB, 0x27CD, 0x29C6, 0x29C7, 0x29C8, 0x29D4, 0x29D5,
    0x29D6, 0x29D7, 0x29E2, 0x2A1D, 0x2A1E, 0x2A2F, 0x2A30, 0x2A31,
    0x2A32, 0x2A33, 0x2A34, 0x2A35, 0x2A36, 0x2A37, 0x2A3B, 0x2A3C,
    0x2A3D, 0x2A3F, 0x2A50, 0x2A64, 0x2A65, 0x2ADC, 0x2ADD, 0x2AFE,
};

static const UChar32 category_d[]{
    0x0021, 0x002B, 0x002D, 0x00AC, 0x00B1, 0x0331, 0x2018, 0x201C, 0x2200,
    0x2201, 0x2203, 0x2204, 0x2207, 0x2212, 0x2213, 0x221F, 0x2220, 0x2221,
    0x2222, 0x2234, 0x2235, 0x223C, 0x22BE, 0x22BF, 0x2310, 0x2319, 0x2795,
    0x2796, 0x27C0, 0x299B, 0x299C, 0x299D, 0x299E, 0x299F, 0x29A0, 0x29A1,
    0x29A2, 0x29A3, 0x29A4, 0x29A5, 0x29A6, 0x29A7, 0x29A8, 0x29A9, 0x29AA,
    0x29AB, 0x29AC, 0x29AD, 0x29AE, 0x29AF, 0x2AEC, 0x2AED,
};

static const UChar32 category_e[]{
    0x0021, 0x0022, 0x0025, 0x0026, 0x0027, 0x0060, 0x00A8, 0x00B0,
    0x00B2, 0x00B3, 0x00B4, 0x00B8, 0x00B9, 0x02CA, 0x02CB, 0x02D8,
    0x02D9, 0x02DA, 0x02DD, 0x0311, 0x0320, 0x0325, 0x0327, 0x0331,
    0x2019, 0x201A, 0x201B, 0x201D, 0x201E, 0x201F, 0x2032, 0x2033,
    0x2034, 0x2035, 0x2036, 0x2037, 0x2057, 0x20DB, 0x20DC, 0x23CD,
};

static const UChar32 category_f[]{
    0x0028, 0x005B, 0x007B, 0x007C, 0x2016, 0x2308, 0x230A, 0x2329,
    0x2772, 0x27E6, 0x27E8, 0x27EA, 0x27EC, 0x27EE, 0x2980, 0x2983,
    0x2985, 0x2987, 0x2989, 0x298B, 0x298D, 0x298F, 0x2991, 0x2993,
    0x2995, 0x2997, 0x2999, 0x29D8, 0x29DA, 0x29FC,
};

static const UChar32 category_g[]{
    0x0029, 0x005D, 0x007C, 0x007D, 0x2016, 0x2309, 0x230B, 0x232A,
    0x2773, 0x27E7, 0x27E9, 0x27EB, 0x27ED, 0x27EF, 0x2980, 0x2984,
    0x2986, 0x2988, 0x298A, 0x298C, 0x298E, 0x2990, 0x2992, 0x2994,
    0x2996, 0x2998, 0x2999, 0x29D9, 0x29DB, 0x29FD,
};

static const UChar32 category_h[]{
    0x222B, 0x222C, 0x222D, 0x222E, 0x222F, 0x2230, 0x2231, 0x2232, 0x2233,
    0x2A0B, 0x2A0C, 0x2A0D, 0x2A0E, 0x2A0F, 0x2A10, 0x2A11, 0x2A12, 0x2A13,
    0x2A14, 0x2A15, 0x2A16, 0x2A17, 0x2A18, 0x2A19, 0x2A1A, 0x2A1B, 0x2A1C,
};

static const UChar32 category_i[]{
    0x005E, 0x005F, 0x007E, 0x00AF, 0x02C6, 0x02C7, 0x02C9, 0x02CD,
    0x02DC, 0x02F7, 0x0302, 0x203E, 0x2322, 0x2323, 0x23B4, 0x23B5,
    0x23DC, 0x23DD, 0x23DE, 0x23DF, 0x23E0, 0x23E1,
};

static const UChar32 category_j[]{
    0x220F, 0x2210, 0x2211, 0x22C0, 0x22C1, 0x22C2, 0x22C3, 0x2A00,
    0x2A01, 0x2A02, 0x2A03, 0x2A04, 0x2A05, 0x2A06, 0x2A07, 0x2A08,
    0x2A09, 0x2A0A, 0x2A1D, 0x2A1E, 0x2AFC, 0x2AFF,
};

static const UChar32 category_k[]{
    0x005C, 0x005F, 0x2061, 0x2062, 0x2063, 0x2064, 0x2206,
};

static const UChar32 category_l[]{
    0x2145, 0x2146, 0x2202, 0x221A, 0x221B, 0x221C,
};

static const UChar32 category_m[]{
    0x002C,
    0x003A,
    0x003B,
};

template <typename T, size_t N>
bool IsInCategory(const T (&table)[N], UChar32 character) {
  return std::binary_search(table, table + std::size(table), character);
}

String FromUChar32(UChar32 c) {
  StringBuilder input;
  input.Append(c);
  return input.ToString();
}

TEST(MathOperatorDictionaryTest, Infix) {
  for (UChar32 ch = 0; ch < kMaxCodepoint; ch++) {
    String s = FromUChar32(ch);
    s.Ensure16Bit();
    if (ch >= kCombiningMinusSignBelow &&
        ch <= kGreekCapitalReversedDottedLunateSigmaSymbol) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kNone);
    } else if (IsInCategory(category_a, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kA);
    } else if (IsInCategory(category_b, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kB);
    } else if (IsInCategory(category_c, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kC);
    } else if (IsInCategory(category_k, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kDorEorK);
    } else if (IsInCategory(category_m, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kInfix) ==
                  MathMLOperatorDictionaryCategory::kM);
    }
  }
}

TEST(MathOperatorDictionaryTest, Prefix) {
  for (UChar32 ch = 0; ch < kMaxCodepoint; ch++) {
    String s = FromUChar32(ch);
    s.Ensure16Bit();
    if (ch >= kCombiningMinusSignBelow &&
        ch <= kGreekCapitalReversedDottedLunateSigmaSymbol) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kNone);
    } else if (IsInCategory(category_d, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kDorEorK);
    } else if (IsInCategory(category_f, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kForG);
    } else if (IsInCategory(category_h, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kH);
    } else if (IsInCategory(category_j, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kJ);
    } else if (IsInCategory(category_l, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kL);
    } else {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPrefix) ==
                  MathMLOperatorDictionaryCategory::kNone);
    }
  }
}

TEST(MathOperatorDictionaryTest, Postfix) {
  for (UChar32 ch = 0; ch < kMaxCodepoint; ch++) {
    String s = FromUChar32(ch);
    s.Ensure16Bit();
    if (ch >= kCombiningMinusSignBelow &&
        ch <= kGreekCapitalReversedDottedLunateSigmaSymbol) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kNone);
    } else if (ch == kArabicMathematicalOperatorMeemWithHahWithTatweel ||
               ch == kArabicMathematicalOperatorHahWithDal) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kI);
    } else if (IsInCategory(category_e, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kDorEorK);
    } else if (IsInCategory(category_g, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kForG);
    } else if (IsInCategory(category_i, ch)) {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kI);
    } else {
      EXPECT_TRUE(FindCategory(s, MathMLOperatorDictionaryForm::kPostfix) ==
                  MathMLOperatorDictionaryCategory::kNone);
    }
  }
}

}  // namespace blink
```