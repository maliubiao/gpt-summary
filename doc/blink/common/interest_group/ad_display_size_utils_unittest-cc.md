Response: Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding - What is the purpose of this file?**

The filename `ad_display_size_utils_unittest.cc` immediately suggests this file tests utilities related to ad display sizes. The `unittest.cc` suffix is a strong convention for Google Test unit tests. The `blink/common/interest_group/` path hints at the context –  this likely relates to the Privacy Sandbox's Interest Group API (formerly FLEDGE/Protected Audience).

**2. High-Level Code Scan - Identify key components:**

* **Includes:** `ad_display_size_utils.h`, `<limits>`, `<string>`, `gtest/gtest.h`, `ad_display_size.h`. This tells us we're testing the functions declared in `ad_display_size_utils.h` and using Google Test for the test framework. The other includes provide standard C++ functionality.
* **Namespace:** `blink`. This confirms we're in the Chromium Blink rendering engine.
* **Helper Function:** The `RunTest` function looks like a parameterized test helper. It takes an input string, expected value, and expected unit, and then calls `ParseAdSizeString` to verify the output. This suggests the core functionality being tested is parsing strings representing ad sizes.
* **Test Suites:** `AdDisplaySizeUtilsTest`. This groups related tests.
* **Test Cases (within the suite):**  The names of the `TEST` macros (e.g., `ConvertAdSizeUnitToString`, `ParseSizeStringWithUnits`, `ValidAdSize`) clearly indicate what each test case is verifying. We see tests for:
    * Converting units and sizes to strings.
    * Parsing strings into numerical values and units.
    * Validating `AdSize` objects.

**3. Deeper Dive - Analyzing Specific Functionality and Tests:**

* **`ConvertAdSizeUnitToString`:**  Simple tests verifying the string representation of different `LengthUnit` enum values.
* **`ConvertAdSizeToString`:** Tests the conversion of `AdSize` structs (containing width and height with units) into comma-separated strings. Pay attention to how different unit combinations are handled (pixels, screen width/height).
* **`ConvertAdDimensionToString`:** Tests the conversion of a single dimension (value and unit) to a string.
* **`ParseAdSizeString` (inferred from `RunTest`):** This is the core function under test. The various `ParseSizeString...` tests provide comprehensive coverage, categorized into:
    * **Positive tests:**  Valid input formats, including those with units, without units (defaulting to pixels), and various spacing scenarios.
    * **Negative tests:**  Invalid input formats, such as missing values, negative values, incorrect units, invalid characters, and spacing errors. This is crucial for robustness.
* **`IsValidAdSize`:** Tests the validation logic for `AdSize` objects, checking for valid units, non-zero values, and finite values.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, based on the understanding of the tested functionality, we can connect it to web technologies:

* **Ad Display:** The core concept revolves around specifying the size of advertisements. This is directly relevant to how ads are rendered in web pages.
* **HTML:**  While this C++ code isn't directly used in HTML, the results of parsing and validating ad sizes *influence* how ad slots are defined in HTML. For example, a JavaScript function might use this logic to interpret size parameters passed from a server or defined in a configuration.
* **CSS:** Ad sizes can be expressed in CSS units (pixels, percentages of the viewport, etc.). The `sw` and `sh` units in the C++ code clearly map to the concept of screen width and screen height, which are related to CSS viewport units like `vw` and `vh`.
* **JavaScript:**  JavaScript code within a webpage (especially ad rendering scripts) might need to parse or generate strings representing ad sizes, potentially interacting with the underlying browser functionality that this C++ code provides. The Interest Group API itself is exposed to JavaScript.

**5. Logical Reasoning and Examples:**

The `RunTest` function embodies logical reasoning. For each test case, there's an *assumption* about what `ParseAdSizeString` should produce given a specific input string. The `EXPECT_EQ` assertions then verify this assumption. The examples provided in the initial prompt directly come from analyzing these `RunTest` calls.

**6. Common User/Programming Errors:**

The negative test cases are a goldmine for identifying potential errors:

* **Incorrect Unit Strings:**  Users might type "in" instead of "px".
* **Missing Values:**  Providing only the unit, like "px".
* **Invalid Characters:**  Including spaces within the number or unit.
* **Negative or Zero Values (when not allowed):**  Trying to specify a negative width or height.
* **Swapping Value and Unit:**  Typing "px100" instead of "100px".

**7. Structuring the Answer:**

Finally, organize the findings logically:

* Start with a concise summary of the file's purpose.
* Detail the key functionalities being tested.
* Explain the relationship to JavaScript, HTML, and CSS with concrete examples.
* Present the logical reasoning by showcasing input/output pairs.
* Highlight common errors based on the negative test cases.

This methodical approach, starting with the big picture and gradually drilling down into specifics, allows for a comprehensive understanding and accurate description of the C++ unittest file.
这个文件 `ad_display_size_utils_unittest.cc` 是 Chromium Blink 引擎中用于测试 `blink/common/interest_group/ad_display_size_utils.h` 文件中定义的实用工具函数的单元测试文件。 这些实用工具函数主要用于处理广告展示尺寸相关的字符串解析、转换和校验。

**功能列举:**

1. **`ConvertAdSizeUnitToString` 测试:**
   - 测试将 `AdSize::LengthUnit` 枚举值（例如 `kPixels`, `kScreenWidth`, `kScreenHeight`）转换为对应的字符串表示 ("px", "sw", "sh")。
   - 同时测试对于 `kInvalid` 单元返回空字符串。

2. **`ConvertAdSizeToString` 测试:**
   - 测试将 `AdSize` 结构体（包含宽度和高度以及它们的单位）转换为字符串表示。
   - 字符串格式为 "宽度值+宽度单位,高度值+高度单位"，例如 "10px,15px" 或 "0.5sw,0.2sh"。
   - 测试了不同的单位组合。

3. **`ConvertAdDimensionToString` 测试:**
   - 测试将单个尺寸值和单位转换为字符串表示，例如 "10px", "0.5sw", "0.5sh"。

4. **`ParseAdSizeString` 测试 (通过 `RunTest` 辅助函数):**
   - **正向测试用例:** 测试各种有效的广告尺寸字符串解析，包括：
     - 带有单位的字符串 (例如 "100px", "100sw", "100sh", "100.0px")。
     - 仅有数字的字符串 (默认单位为像素 "px")。
     - 带有前导、尾随或两者都有空格的数字字符串。
     - 带有前导、尾随或两者都有空格的带有单位的字符串。
     - 解析零值。
     - 解析带有小数的数值。
   - **负向测试用例:** 测试各种无效的广告尺寸字符串解析，预期返回无效的单位：
     - 仅有单位，没有数值。
     - 负数值。
     - 数字前导零（例如 "01px"）。
     - 单独的点号 "."。
     - 以点号开始的单位 (".px")。
     - 数字和单位之间有空格。
     - 数字后有小数点但没有后续数字。
     - 小数点前没有数字。
     - 无效的单位 (例如 "10in")。
     - 数值和单位顺序颠倒。
     - 空字符串或只包含空格的字符串。
     - 数字中间有空格。
     - 单位中间有空格。
     - 格式错误的字符串（包含字母、特殊字符等）。

5. **`IsValidAdSize` 测试:**
   - 测试 `IsValidAdSize` 函数，用于验证 `AdSize` 结构体是否有效。
   - 测试了有效的情况（非零值，有效的单位）。
   - 测试了无效的情况（无效的单位，零值，负值，无限大的值）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件中的功能与网页前端技术（JavaScript, HTML, CSS）有密切关系，因为它们涉及到网页中广告的尺寸定义和解析。

* **HTML:** HTML 中可能会使用自定义属性或 data 属性来存储广告的尺寸信息，这些信息可能以字符串形式存在，需要解析成结构化的数据。例如：
  ```html
  <div data-ad-size="300px,250px">...</div>
  ```
  JavaScript 代码需要解析 "300px,250px" 这个字符串。

* **CSS:** CSS 用于定义元素的样式，包括尺寸。虽然这里的单位 "sw" 和 "sh" 不是标准的 CSS 单位，但在 Privacy Sandbox 的上下文中，它们代表屏幕宽度和屏幕高度的百分比。这个 C++ 代码的功能可以帮助浏览器理解和处理这些非标准单位，并将它们转换为实际的像素值，以便在渲染时应用相应的 CSS 规则。例如，一个广告的尺寸可能被定义为占据屏幕宽度的一半和屏幕高度的 20%。

* **JavaScript:** JavaScript 是在网页中处理逻辑的主要语言。与此文件功能相关的 JavaScript 使用场景包括：
    - **解析来自服务器的广告尺寸信息:**  服务器可能会返回一个字符串描述广告的尺寸，例如 "0.8sw,0.5sh"，JavaScript 需要解析这个字符串来确定广告的实际尺寸。
    ```javascript
    const adSizeString = "0.8sw,0.5sh";
    // (假设存在一个与 C++ ParseAdSizeString 功能对应的 JavaScript 函数)
    const adSize = parseAdSizeString(adSizeString);
    console.log(adSize.widthValue, adSize.widthUnit); // 输出 0.8, "sw"
    console.log(adSize.heightValue, adSize.heightUnit); // 输出 0.5, "sh"
    ```
    - **根据用户屏幕尺寸动态调整广告尺寸:** JavaScript 可以获取用户的屏幕尺寸，并根据一定的规则生成或解析广告尺寸字符串。
    - **与 Privacy Sandbox API 交互:**  Interest Group API (Protected Audience API) 允许在竞价获胜后渲染广告。广告的尺寸信息可能需要被处理，而这个 C++ 文件提供的工具函数就在底层支持了这种处理。

**逻辑推理、假设输入与输出:**

`RunTest` 函数本身就体现了逻辑推理，它假设了对于特定的输入字符串，`ParseAdSizeString` 函数应该产生特定的输出（数值和单位）。

**示例:**

**假设输入:** `"150.5px"`
**预期输出:** `out_val = 150.5`, `out_units = blink::AdSize::LengthUnit::kPixels`

**假设输入:** `"0.7sh"`
**预期输出:** `out_val = 0.7`, `out_units = blink::AdSize::LengthUnit::kScreenHeight`

**假设输入:** `"  75  "`
**预期输出:** `out_val = 75.0`, `out_units = blink::AdSize::LengthUnit::kPixels` (默认单位)

**假设输入 (无效):** `"100 px"`
**预期输出:** `out_val = 0.0`, `out_units = blink::AdSize::LengthUnit::kInvalid`

**涉及用户或编程常见的使用错误:**

1. **拼写错误或使用非法的单位字符串:** 用户或开发者可能会错误地输入单位，例如 "pix" 而不是 "px"，或者使用不支持的单位。
   ```javascript
   const invalidSize = "200pix"; // 应该使用 "200px"
   // 解析后会得到无效的结果
   ```

2. **错误的数值格式:**  输入非法的数值格式，例如包含多个小数点或非数字字符。
   ```javascript
   const invalidSize = "100..5px"; // 错误的格式
   ```

3. **缺少数值或单位:**  只提供数值或只提供单位。
   ```javascript
   const invalidSize1 = "px"; // 缺少数值
   const invalidSize2 = "150"; // 缺少单位，但会被默认解析为像素
   ```

4. **数值和单位之间有空格:** 这是很常见的错误，用户可能会无意中在数值和单位之间添加空格。
   ```javascript
   const invalidSize = "100 px"; // 应该使用 "100px"
   ```

5. **使用负数或零作为尺寸值 (在某些上下文中可能不允许):** 虽然解析器可以处理零值，但在某些广告平台的规范中，尺寸必须是正数。
   ```javascript
   const invalidSize = "-50px"; // 负数尺寸
   ```

6. **混淆宽度和高度的顺序或分隔符:** 在解析包含宽度和高度的字符串时，使用了错误的分隔符或顺序。
   ```javascript
   const invalidSize = "100px-200px"; // 应该使用逗号分隔 "100px,200px"
   ```

这个单元测试文件通过大量的测试用例，覆盖了各种可能出现的输入情况，旨在确保 `ad_display_size_utils.h` 中的实用工具函数能够正确地解析和处理广告尺寸字符串，从而避免开发者在使用这些功能时遇到上述常见错误。

### 提示词
```
这是目录为blink/common/interest_group/ad_display_size_utils_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/interest_group/ad_display_size_utils.h"

#include <limits>
#include <string>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/interest_group/ad_display_size.h"

namespace blink {

namespace {

void RunTest(const std::string& input,
             double expected_val,
             blink::AdSize::LengthUnit expected_unit) {
  auto [out_val, out_units] = blink::ParseAdSizeString(input);
  EXPECT_EQ(out_val, expected_val);
  EXPECT_EQ(out_units, expected_unit);
}

}  // namespace

TEST(AdDisplaySizeUtilsTest, ConvertAdSizeUnitToString) {
  EXPECT_EQ("px",
            ConvertAdSizeUnitToString(blink::AdSize::LengthUnit::kPixels));
  EXPECT_EQ("sw",
            ConvertAdSizeUnitToString(blink::AdSize::LengthUnit::kScreenWidth));
  EXPECT_EQ("sh", ConvertAdSizeUnitToString(
                      blink::AdSize::LengthUnit::kScreenHeight));
  EXPECT_TRUE(
      ConvertAdSizeUnitToString(blink::AdSize::LengthUnit::kInvalid).empty());
}

TEST(AdDisplaySizeUtilsTest, ConvertAdSizeToString) {
  // clang-format off
  const AdSize kAdSize1(10, AdSize::LengthUnit::kPixels,
                        15, AdSize::LengthUnit::kPixels);
  EXPECT_EQ(ConvertAdSizeToString(kAdSize1), "10px,15px");

  const AdSize kAdSize2(0.5, AdSize::LengthUnit::kScreenWidth,
                        0.2, AdSize::LengthUnit::kScreenHeight);
  EXPECT_EQ(ConvertAdSizeToString(kAdSize2), "0.5sw,0.2sh");

  const AdSize kAdSize3(0.2, AdSize::LengthUnit::kScreenHeight,
                        0.5, AdSize::LengthUnit::kScreenWidth);
  EXPECT_EQ(ConvertAdSizeToString(kAdSize3), "0.2sh,0.5sw");

  const AdSize kAdSize4(10.5, AdSize::LengthUnit::kPixels,
                        11, AdSize::LengthUnit::kScreenWidth);
  EXPECT_EQ(ConvertAdSizeToString(kAdSize4), "10.5px,11sw");
  // clang-format on
}

TEST(AdDisplaySizeUtilsTest, ConvertAdDimensionToString) {
  EXPECT_EQ(ConvertAdDimensionToString(10, AdSize::LengthUnit::kPixels),
            "10px");
  EXPECT_EQ(ConvertAdDimensionToString(0.5, AdSize::LengthUnit::kScreenWidth),
            "0.5sw");
  EXPECT_EQ(ConvertAdDimensionToString(0.5, AdSize::LengthUnit::kScreenHeight),
            "0.5sh");
}

// Positive test cases.
TEST(AdDisplaySizeUtilsTest, ParseSizeStringWithUnits) {
  RunTest("100px", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("100sw", 100.0, blink::AdSize::LengthUnit::kScreenWidth);
  RunTest("100sh", 100.0, blink::AdSize::LengthUnit::kScreenHeight);
  RunTest("100.0px", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("100.0sw", 100.0, blink::AdSize::LengthUnit::kScreenWidth);
  RunTest("100.0sh", 100.0, blink::AdSize::LengthUnit::kScreenHeight);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringOnlyNumbers) {
  RunTest("100", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("100.0", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersTrailingSpaces) {
  RunTest("100 ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("100   ", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersLeadingSpaces) {
  RunTest(" 100", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersTrailingLeadingSpaces) {
  RunTest(" 100 ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100 ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest(" 100   ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100   ", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringPixelsTrailingSpace) {
  RunTest("100px ", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringPixelsLeadingSpace) {
  RunTest(" 100px", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100px", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringPixelsTrailingLeadingSpaces) {
  RunTest(" 100px ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100px ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest(" 100px   ", 100.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("   100px   ", 100.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeZeroPixel) {
  RunTest("0", 0.0, blink::AdSize::LengthUnit::kPixels);
  RunTest(" 0 ", 0.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("0.0", 0.0, blink::AdSize::LengthUnit::kPixels);
  RunTest(" 0.0 ", 0.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("0px", 0.0, blink::AdSize::LengthUnit::kPixels);
  RunTest("0.0px", 0.0, blink::AdSize::LengthUnit::kPixels);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersWithDecimal) {
  RunTest("0.1px", 0.1, blink::AdSize::LengthUnit::kPixels);
  RunTest("0.100px", 0.1, blink::AdSize::LengthUnit::kPixels);
}

// Negative test cases.
TEST(AdDisplaySizeUtilsTest, ParseSizeStringNoValue) {
  RunTest("px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest(" px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest(" px ", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNegativeValue) {
  RunTest("-100px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest(" -100px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest(" - 100px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("-0", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("-0px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersLeadingZero) {
  RunTest("01px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("00px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringSingleDot) {
  RunTest(".", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringSingleDotWithUnit) {
  RunTest(".px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringPixelsMiddleSpaces) {
  RunTest("100 px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100   px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersTrailingDot) {
  RunTest("100.px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringNumbersLeadingDot) {
  RunTest(".1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringInvalidUnit) {
  RunTest("10in", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringValueAndUnitSwapped) {
  RunTest("px100", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringEmptyString) {
  RunTest("", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringSingleSpace) {
  RunTest(" ", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringMultipleSpaces) {
  RunTest("   ", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringSpacesInNumbers) {
  RunTest("100 1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100. 1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100 1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100 1 px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100 1 . 1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("0 0px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("0 0", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringSpacesInUnit) {
  RunTest("100p x", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100s w", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ParseSizeStringWrongFormat) {
  RunTest("123abc456px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100%px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100pixels", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("varpx", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("var px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100/2px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("100..1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("10e3px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("2-1px", 0.0, blink::AdSize::LengthUnit::kInvalid);
  RunTest("2-1", 0.0, blink::AdSize::LengthUnit::kInvalid);
}

TEST(AdDisplaySizeUtilsTest, ValidAdSize) {
  AdSize ad_size(10.0, AdSize::LengthUnit::kPixels, 5.0,
                 AdSize::LengthUnit::kScreenWidth);
  EXPECT_TRUE(IsValidAdSize(ad_size));
}

TEST(AdDisplaySizeUtilsTest, AdSizeInvalidUnits) {
  AdSize ad_size(10.0, AdSize::LengthUnit::kInvalid, 5.0,
                 AdSize::LengthUnit::kScreenWidth);
  EXPECT_FALSE(IsValidAdSize(ad_size));
}

TEST(AdDisplaySizeUtilsTest, AdSizeZeroValue) {
  AdSize ad_size(0.0, AdSize::LengthUnit::kPixels, 5.0,
                 AdSize::LengthUnit::kScreenWidth);
  EXPECT_FALSE(IsValidAdSize(ad_size));
}

TEST(AdDisplaySizeUtilsTest, AdSizeNegativeValue) {
  AdSize ad_size(-1.0, AdSize::LengthUnit::kPixels, 5.0,
                 AdSize::LengthUnit::kScreenWidth);
  EXPECT_FALSE(IsValidAdSize(ad_size));
}

TEST(AdDisplaySizeUtilsTest, AdSizeInfiniteValue) {
  AdSize ad_size(std::numeric_limits<double>::infinity(),
                 AdSize::LengthUnit::kPixels, 5.0,
                 AdSize::LengthUnit::kScreenWidth);
  EXPECT_FALSE(IsValidAdSize(ad_size));
}

}  // namespace blink
```