Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The core request is to analyze a Chromium Blink engine source file, `cursor_position_test.cc`, and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), and provide examples of its logic and potential user/programming errors.

2. **Identify Key Components:**  The first step is to quickly scan the code for its most important parts. I see:
    * `#include` statements: These tell me about the dependencies and what kind of operations are likely being performed (e.g., `testing/gtest`, `platform/fonts/font.h`).
    * `namespace blink`:  This confirms it's part of the Blink rendering engine.
    * `class CursorPositionTest : public FontTestBase`: This is the main testing class, inheriting from `FontTestBase`, suggesting it's involved in testing font-related functionality.
    * `enum FontName`: Defines a set of font names, indicating that the tests will use these specific fonts.
    * `GetWidth()`: A method to get the width of a given text string using a specific font and text direction. This immediately suggests it's testing text layout.
    * `GetCharacter()`: A method to determine the character index at a given horizontal position within a text string. This is crucial for cursor positioning.
    * `TEST_F()` macros:  These are Google Test macros, signifying individual test cases.
    * Various `EXPECT_EQ()` and `EXPECT_NEAR()` calls within the `TEST_F` blocks: These are assertions, meaning the tests are verifying expected outcomes.

3. **Infer High-Level Functionality:** Based on the identified components, I can deduce that this file contains unit tests specifically for:
    * **Cursor positioning within text:** The names of the methods (`GetCharacter`, `OffsetForPosition`) and test cases (`LTRMouse`, `RTLMouse`) strongly suggest this.
    * **Text width calculation:** The `GetWidth` method confirms this.
    * **Handling of different text directions (LTR and RTL):** The boolean `ltr` parameter in `GetWidth` and `GetCharacter` and the `LTRMouse`/`RTLMouse` test cases point to this.
    * **Ligatures:** The `LTRLigatureMouse`, `RTLLigatureMouse`, `LTRLigature`, and `RTLLigature` test cases, along with the `FontDescription::VariantLigatures` usage, indicate that ligature handling is being tested.

4. **Connect to Web Technologies:** Now, I need to bridge the gap between this C++ code and the higher-level web technologies:
    * **JavaScript:**  JavaScript interacts with the rendered page, including text selection and cursor placement. This C++ code tests the underlying mechanisms that JavaScript relies on. Selecting text with the mouse or using arrow keys in a `<textarea>` or a contenteditable `<div>` ultimately uses logic similar to what's being tested here.
    * **HTML:** HTML provides the structure for text content. The rendering of that text, including how the cursor is positioned and how selections are made, is what this code tests. Consider a simple `<p>` tag with some text.
    * **CSS:** CSS styles the text, including the `direction` property (for RTL text) and font-family. The tests use different fonts, so they implicitly test how font properties affect cursor positioning. The `direction: rtl;` CSS property is a direct connection to the RTL testing.

5. **Illustrate with Examples:** To make the explanation clearer, I need concrete examples:
    * **JavaScript:**  `element.selectionStart`, `element.selectionEnd`, `caretPositionFromPoint()` are good examples of JavaScript APIs that rely on the underlying cursor positioning logic.
    * **HTML:**  `<textarea>`, `<input type="text">`, and contenteditable elements are the primary HTML elements where users interact with text and cursor placement.
    * **CSS:**  `font-family`, `direction`, and potentially even `letter-spacing` (though not directly tested here) influence text layout and cursor behavior.

6. **Reasoning and Assumptions:**  The `GetCharacter` function performs a kind of reverse mapping: given a horizontal position, it finds the corresponding character index. The `partial` parameter suggests handling cases where the click might fall within a glyph.

    * **Input for `GetCharacter`:** A string, a direction (LTR/RTL), a horizontal position, and a boolean indicating whether to include partial glyphs.
    * **Output for `GetCharacter`:** The index of the character at that position.

    * **Input for `GetWidth`:** A string, a direction, and optional start and end indices.
    * **Output for `GetWidth`:** The width of the substring.

7. **Identify Potential Errors:** Think about common mistakes developers or users might make related to cursor positioning:
    * **Incorrect RTL handling:** Forgetting to set `direction: rtl` in CSS for languages like Arabic or Hebrew.
    * **Font loading issues:** If a font isn't loaded correctly, the width calculations will be wrong. While the tests use test fonts, this is a real-world issue.
    * **Off-by-one errors:**  Cursor positioning often involves index calculations, so off-by-one errors are common.
    * **Ligature surprises:** Developers might not be fully aware of how ligatures affect character boundaries and cursor placement.

8. **Structure the Answer:**  Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Explain the core functionality provided by the `GetWidth` and `GetCharacter` methods.
    * Clearly connect the code to JavaScript, HTML, and CSS with examples.
    * Provide hypothetical input/output for the key functions.
    * Discuss common user/programming errors.
    * Use clear and concise language.

9. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Are the examples easy to understand? Is the connection to web technologies evident?  Is the explanation of potential errors practical?

By following these steps, I can arrive at a comprehensive and accurate explanation of the provided C++ code, fulfilling the requirements of the initial prompt. The process involves code analysis, logical deduction, knowledge of web technologies, and the ability to explain technical concepts clearly.
这是一个位于 Chromium Blink 引擎中 `blink/renderer/platform/fonts/` 目录下的测试文件，名为 `cursor_position_test.cc`。从其名称和包含的头文件可以推断，这个文件的主要功能是**测试光标在文本中的定位和选择功能**，特别是涉及到不同字体和文本方向（从左到右 LTR 和从右到左 RTL）的情况。

以下是该文件的具体功能分解：

**1. 核心功能：测试光标位置的计算**

   - **`GetWidth()` 方法:**  这个方法用于计算给定文本在特定字体下的宽度。它可以计算整个文本的宽度，也可以计算文本中指定起始和结束位置子串的宽度。这对于确定文本元素的尺寸和进行布局至关重要。
   - **`GetCharacter()` 方法:**  这个方法用于确定在给定的水平位置（position）上，光标应该落在哪个字符的边界。它可以处理两种情况：
      - `partial = false`:  只考虑完整字符的边界。
      - `partial = true`:  允许光标落在字符的中间（部分字形）。这对于鼠标点击等交互非常重要。

**2. 测试用例覆盖范围**

   - **LTR (从左到右) 和 RTL (从右到左) 文本:**  测试用例中包含了 `LTRMouse`、`RTLMouse`、`LTRText`、`RTLText` 等，明确地测试了两种不同的文本方向。
   - **不同字体:**  代码中定义了一个 `FontName` 枚举，包含了 `Ahem`、`Amiri`、`Megalopolis`、`Roboto` 等字体。测试用例会使用这些不同的字体进行测试，以确保光标定位的逻辑在不同字体的渲染下都能正常工作。
   - **连字 (Ligatures):**  测试用例中包含了 `LTRLigatureMouse`、`RTLLigatureMouse`、`LTRLigature`、`RTLLigature` 等，表明该文件专门测试了包含连字的文本的光标定位。连字是将多个字符组合成一个字形显示的特性，会影响光标的移动和选择。
   - **鼠标点击定位:** `*_Mouse` 测试用例模拟了鼠标点击在文本上的不同位置，并验证 `GetCharacter()` 方法是否能正确返回光标应该停留的字符索引。
   - **文本选择:** `*_Text` 测试用例通过 `GetWidth()` 方法验证了在不同起始和结束位置进行文本选择时，计算出的宽度是否正确。

**3. 与 JavaScript, HTML, CSS 的关系**

   这个测试文件虽然是用 C++ 编写的，但它直接关系到浏览器中 JavaScript, HTML, CSS 的功能，特别是涉及到文本渲染和用户交互的部分：

   - **JavaScript:**
      - 当 JavaScript 代码需要获取或设置光标在文本框（`<textarea>` 或 `<input type="text">`）或可编辑元素 (`contenteditable`) 中的位置时（例如使用 `selectionStart`, `selectionEnd` 属性），底层的渲染引擎就需要使用类似 `GetCharacter()` 的逻辑来确定在屏幕坐标系下的点击位置对应哪个字符。
      - JavaScript 可以通过 `document.caretPositionFromPoint()` 方法来获取指定屏幕坐标的光标位置信息，这个方法也会依赖类似的底层实现。
      - **举例说明:**  假设一个用户在网页的文本框中点击了某个位置，JavaScript 代码可能需要知道点击发生在哪个字符之后，以便插入新的文本或进行其他操作。这个测试文件中的 `GetCharacter()` 方法所测试的逻辑，正是实现这一功能的关键。

   - **HTML:**
      - HTML 定义了文本内容和结构。浏览器需要根据 HTML 中定义的文本内容，结合 CSS 样式，将其渲染到屏幕上。
      - 光标的显示和移动是用户与 HTML 文本内容交互的基本方式。测试确保了在不同文本方向和字体下，光标能够正确地定位和移动。
      - **举例说明:** 不同的 HTML 元素（如 `<p>`, `<div>`, `<span>`）包含的文本，光标在其间的定位都需要经过类似的计算。

   - **CSS:**
      - CSS 负责控制文本的样式，包括 `font-family`（字体）、`direction`（文本方向，如 `ltr` 或 `rtl`）、`letter-spacing` 等。
      - 这个测试文件使用不同的字体进行测试，验证了光标定位的逻辑是否能正确处理各种字体下的字符宽度和间距。
      - `direction: rtl;` CSS 属性会触发从右到左的文本渲染，测试文件中的 RTL 测试用例正是为了验证在这种情况下光标定位的正确性。
      - **举例说明:**  当 CSS 设置了 `direction: rtl;` 时，光标的行为和 `direction: ltr;` 是相反的，例如，使用键盘的左右方向键移动光标的方向会发生变化。这个测试文件确保了这种行为在底层实现上是正确的。

**4. 逻辑推理和假设输入输出**

   **假设输入 `GetCharacter(kAhem, "XXX", true, 125, true)`:**

   - **假设:**
      - `kAhem` 字体中，每个字符的宽度是 100 像素（从代码 `EXPECT_EQ(GetWidth(kAhem, "X", true, 0, 1), 100);` 推断）。
      - 文本 "XXX" 在 LTR 方向渲染。
      - 水平位置 `position` 为 125 像素。
      - `partial` 为 `true`，允许落在字符中间。
   - **逻辑推理:**
      - 第一个 "X" 的范围是 0 到 100 像素。
      - 第二个 "X" 的范围是 100 到 200 像素。
      - 位置 125 像素落在第二个 "X" 的中间。
      - 因为 `partial` 为 `true`，所以光标可以落在第二个字符的边界。
   - **预期输出:** `1` (第二个字符的索引，从 0 开始)。

   **假设输入 `GetWidth(kAmiri, u"تخ", false, 0, 1)`:**

   - **假设:**
      - `kAmiri` 字体被正确加载。
      - 文本 "تخ" (阿拉伯语) 在 RTL 方向渲染。
      - 我们要计算从起始位置 0 到 1 的子串的宽度，即第一个字符 "ت" 的宽度。
   - **逻辑推理:**
      - 在 RTL 文本中，第一个字符是显示在最右边的。
      - `GetWidth()` 方法会计算渲染后第一个字符 "ت" 的实际宽度。
   - **预期输出:**  大约 `55` 像素（从代码 `EXPECT_NEAR(GetWidth(kAmiri, u"تخ", false, 0, 1), kAboveKhaWidth, 1.0);` 和 `const float kAboveKhaWidth = 55;` 推断，这里有点混淆，因为测试用例中 "تخ" 的第一个字符是 "خ"，需要注意RTL的阅读顺序）。 **更正:** 由于是 RTL，索引 0 到 1 实际上对应的是 "خ" 的宽度，预期输出应该接近 `kAboveKhaWidth = 55`。

**5. 涉及用户或编程常见的使用错误**

   - **未设置正确的文本方向 (CSS):**
      - **错误:**  对于需要显示 RTL 文本的语言，忘记在 CSS 中设置 `direction: rtl;`。
      - **后果:**  文本显示顺序错误，光标移动和定位也会出现异常。
      - **举例:**  显示阿拉伯语文本时，如果 `direction` 没有设置为 `rtl`，文本会从左到右显示，光标会错误地出现在文本的左侧。

   - **字体加载失败或使用了错误的字体:**
      - **错误:**  网页中指定的字体没有成功加载，或者使用了不适合显示特定字符的字体。
      - **后果:**  浏览器可能会使用备用字体进行渲染，导致字符宽度计算不准确，光标定位错误。
      - **举例:**  如果一个网页尝试使用一个不包含阿拉伯字符的字体来显示阿拉伯语文本，浏览器会使用其他字体代替，这可能导致光标在预期字符的错误位置。

   - **对连字的理解不足:**
      - **错误:**  在处理包含连字的文本时，错误地认为每个字符都是独立的。
      - **后果:**  在计算字符偏移或进行文本操作时，可能会出现索引错误。
      - **举例:**  在 Roboto 字体中，"ffi" 可能渲染成一个连字。如果程序错误地认为 "ffi" 是三个独立的字符，那么在光标定位或文本选择时可能会出现意想不到的结果。

   - **在 JavaScript 中进行不精确的坐标计算:**
      - **错误:**  在 JavaScript 中使用基于像素的坐标来操作光标位置时，没有考虑到字体渲染的细节和浏览器的差异。
      - **后果:**  在不同的浏览器或不同的缩放级别下，光标定位可能不一致。
      - **举例:**  直接使用鼠标事件的坐标来设置光标位置，而没有经过适当的转换和校正，可能会导致光标落在错误的位置。

总而言之，`cursor_position_test.cc` 这个文件通过一系列细致的测试用例，确保了 Blink 渲染引擎在处理各种字体、文本方向和连字时，能够正确地计算光标的位置和文本的宽度，这对于提供准确的用户交互体验至关重要。它与 JavaScript、HTML 和 CSS 的功能紧密相关，是 Web 平台稳定运行的基石之一。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/cursor_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

using blink::test::CreateTestFont;

namespace blink {

class CursorPositionTest : public FontTestBase {
 public:
  enum FontName {
    kAhem,
    kAmiri,
    kMegalopolis,
    kRoboto,
  };

  float GetWidth(FontName font_name,
                 const String& text,
                 bool ltr,
                 int start = 0,
                 int end = -1) {
    FontDescription::VariantLigatures ligatures(
        FontDescription::kEnabledLigaturesState);
    Font font = CreateTestFont(
        AtomicString("TestFont"),
        test::PlatformTestDataPath(font_path.find(font_name)->value), 100,
        &ligatures);
    TextRun text_run(text, ltr ? TextDirection::kLtr : TextDirection::kRtl,
                     false);

    if (end == -1)
      end = text_run.length();
    DCHECK_GE(start, 0);
    DCHECK_LE(start, static_cast<int>(text_run.length()));
    DCHECK_GE(end, -1);
    DCHECK_LE(end, static_cast<int>(text_run.length()));
    gfx::RectF rect =
        font.SelectionRectForText(text_run, gfx::PointF(), 12, start, end);
    return rect.width();
  }

  int GetCharacter(FontName font_name,
                   const String& text,
                   bool ltr,
                   float position,
                   bool partial) {
    FontDescription::VariantLigatures ligatures(
        FontDescription::kEnabledLigaturesState);
    Font font = CreateTestFont(
        AtomicString("TestFont"),
        test::PlatformTestDataPath(font_path.find(font_name)->value), 100,
        &ligatures);
    TextRun text_run(text, ltr ? TextDirection::kLtr : TextDirection::kRtl,
                     false);

    return font.OffsetForPosition(
        text_run, position, partial ? kIncludePartialGlyphs : kOnlyFullGlyphs,
        BreakGlyphsOption(true));
  }

 private:
  HashMap<FontName, String> font_path = {
      {kAhem, "Ahem.woff"},
      {kAmiri, "third_party/Amiri/amiri_arabic.woff2"},
      {kMegalopolis, "third_party/MEgalopolis/MEgalopolisExtra.woff"},
      {kRoboto, "third_party/Roboto/roboto-regular.woff2"},
  };
};

TEST_F(CursorPositionTest, LTRMouse) {
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 0, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 0, true), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 10, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 10, true), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 60, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 60, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 100, false), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", true, 100, true), 1);

  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 10, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 10, true), 0);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 60, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 60, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 100, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 100, false), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 125, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 125, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 151, false), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 151, true), 2);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 175, false), 1);
  EXPECT_EQ(GetCharacter(kAhem, "XXX", true, 175, true), 2);
}

TEST_F(CursorPositionTest, LTRLigatureMouse) {
  const float kFUWidth = GetWidth(kMegalopolis, "FU", true);
  const float kRAWidth = GetWidth(kMegalopolis, "RA", true);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 4 - 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 4 - 1, true),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 4 + 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 4 + 1, true),
            1);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 2 - 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 2 - 1, true),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 2 + 1, false),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth / 2 + 1, true),
            1);

  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth * 3 / 4 - 1, false), 1);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth * 3 / 4 - 1, true), 1);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth * 3 / 4 + 1, false), 1);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth * 3 / 4 + 1, true), 2);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth - 1, false), 1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth - 1, true), 2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth + 1, false), 2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true, kFUWidth + 1, true), 2);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 4 - 1, false),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 4 - 1, true),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 4 + 1, false),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 4 + 1, true),
            3);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 2 - 1, false),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 2 - 1, true),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 2 + 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth / 2 + 1, true),
            3);

  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth * 3 / 4 - 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth * 3 / 4 - 1, true),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth * 3 / 4 + 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "FURA", true,
                         kFUWidth + kRAWidth * 3 / 4 + 1, true),
            4);

  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth + kRAWidth - 1, false),
      3);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth + kRAWidth - 1, true),
      4);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth + kRAWidth + 1, false),
      4);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "FURA", true, kFUWidth + kRAWidth + 1, true),
      4);
}

TEST_F(CursorPositionTest, RTLMouse) {
  // The widths below are from the final shaped version, not from the single
  // characters. They were extracted with "hb-shape --font-size=100"

  EXPECT_EQ(GetCharacter(kAhem, "X", false, 0, false), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 0, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 10, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 10, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 49, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 49, true), 1);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 51, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 51, true), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 60, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 60, true), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 100, false), 0);
  EXPECT_EQ(GetCharacter(kAhem, "X", false, 100, true), 0);

  const float kAloneTaWidth = GetWidth(kAmiri, u"ت", false);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, 0, false), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, 0, true), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, kAloneTaWidth / 4, false), 0);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, kAloneTaWidth / 4, true), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, kAloneTaWidth * 2 / 3, false), 0);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, kAloneTaWidth * 2 / 3, true), 0);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, 2 * kAloneTaWidth, false), 0);
  EXPECT_EQ(GetCharacter(kAmiri, u"ت", false, 2 * kAloneTaWidth, true), 0);

  const float kAboveTaWidth = 10;
  const float kAboveKhaWidth = 55;
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, 0, false), 2);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, 0, true), 2);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth / 4, false), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth / 4, true), 2);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth * 2 / 3, false),
            1);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth * 2 / 3, true), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth + 1, false), 0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false, kAboveTaWidth + 1, true), 1);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth / 4, false),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth / 4, true),
            1);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth * 2 / 3, false),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth * 2 / 3, true),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth + 1, false),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         kAboveTaWidth + kAboveKhaWidth + 1, true),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         2 * (kAboveTaWidth + kAboveKhaWidth), false),
            0);
  EXPECT_EQ(GetCharacter(kAmiri, u"تخ", false,
                         2 * (kAboveTaWidth + kAboveKhaWidth), true),
            0);
}

TEST_F(CursorPositionTest, RTLLigatureMouse) {
  const float kFUWidth = GetWidth(kMegalopolis, "FU", true);
  const float kRAWidth = GetWidth(kMegalopolis, "RA", true);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 4 - 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 4 - 1, true),
            4);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 4 + 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 4 + 1, true),
            3);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 2 - 1, false),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 2 - 1, true),
            3);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 2 + 1, false),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth / 2 + 1, true),
            3);

  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth * 3 / 4 - 1, false),
      2);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth * 3 / 4 - 1, true), 3);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth * 3 / 4 + 1, false),
      2);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth * 3 / 4 + 1, true), 2);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth - 1, false), 2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth - 1, true), 2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + 1, false), 1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + 1, true), 2);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 4 - 1, false),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 4 - 1, true),
            2);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 4 + 1, false),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 4 + 1, true),
            1);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 2 - 1, false),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 2 - 1, true),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 2 + 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth / 2 + 1, true),
            1);

  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth * 3 / 4 - 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth * 3 / 4 - 1, true),
            1);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth * 3 / 4 + 1, false),
            0);
  EXPECT_EQ(GetCharacter(kMegalopolis, "ARUF", false,
                         kFUWidth + kRAWidth * 3 / 4 + 1, true),
            0);

  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + kRAWidth - 1, false),
      0);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + kRAWidth - 1, true),
      0);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + kRAWidth + 1, false),
      0);
  EXPECT_EQ(
      GetCharacter(kMegalopolis, "ARUF", false, kFUWidth + kRAWidth + 1, true),
      0);
}

TEST_F(CursorPositionTest, LTRText) {
  EXPECT_EQ(GetWidth(kAhem, "X", true, 0, 1), 100);

  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 0, 1), 100);
  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 0, 2), 200);
  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 0, 3), 300);
  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 1, 2), 100);
  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 1, 3), 200);
  EXPECT_EQ(GetWidth(kAhem, "XXX", true, 2, 3), 100);
}

TEST_F(CursorPositionTest, LTRLigature) {
  const float kFUWidth = GetWidth(kMegalopolis, "FU", true);
  const float kRAWidth = GetWidth(kMegalopolis, "RA", true);

  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 0, 1), kFUWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 0, 2), kFUWidth, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 0, 3),
              kFUWidth + kRAWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 0, 4), kFUWidth + kRAWidth,
              1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 1, 2), kFUWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 1, 3),
              kFUWidth / 2 + kRAWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 1, 4),
              kFUWidth / 2 + kRAWidth, 1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 2, 3), kRAWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 2, 4), kRAWidth, 1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "FURA", true, 3, 4), kRAWidth / 2, 1.0);

  const float kFFIWidth = GetWidth(kRoboto, "ffi", true);
  const float kFFWidth = GetWidth(kRoboto, "ff", true);
  const float kIWidth = GetWidth(kRoboto, u"î", true);

  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 0, 1), kFFIWidth / 3.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 0, 2), kFFIWidth * 2.0 / 3.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 0, 3), kFFIWidth, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 1, 2), kFFIWidth / 3.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 1, 3), kFFIWidth * 2.0 / 3.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, "ffi", true, 2, 3), kFFIWidth / 3.0, 1.0);

  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 0, 1), kFFWidth / 2.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 0, 2), kFFWidth, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 0, 3), kFFWidth + kIWidth, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 1, 2), kFFWidth / 2.0, 1.0);
  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 1, 3), kFFWidth / 2.0 + kIWidth,
              1.0);
  EXPECT_NEAR(GetWidth(kRoboto, u"ffî", true, 2, 3), kIWidth, 1.0);
}

TEST_F(CursorPositionTest, RTLText) {
  // The widths below are from the final shaped version, not from the single
  // characters. They were extracted with "hb-shape --font-size=100"

  EXPECT_EQ(GetWidth(kAmiri, u"ت", false, 0, 1), 93);

  const float kAboveKhaWidth = 55;
  const float kAboveTaWidth = 10;
  EXPECT_NEAR(GetWidth(kAmiri, u"تخ", false, 0, 1), kAboveKhaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"تخ", false, 0, 2),
              kAboveKhaWidth + kAboveTaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"تخ", false, 1, 2), kAboveTaWidth, 1.0);

  const float kTaWidth = 75;
  const float kKhaWidth = 7;
  const float kLamWidth = 56;
  const float kAlifWidth = 22;
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 0, 1), kAlifWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 0, 2), kAlifWidth + kLamWidth,
              1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 0, 3),
              kAlifWidth + kLamWidth + kKhaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 0, 4),
              kAlifWidth + kLamWidth + kKhaWidth + kTaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 1, 2), kLamWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 1, 3), kLamWidth + kKhaWidth,
              1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 1, 4),
              kLamWidth + kKhaWidth + kTaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 2, 3), kKhaWidth, 1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 2, 4), kKhaWidth + kTaWidth,
              1.0);
  EXPECT_NEAR(GetWidth(kAmiri, u"الخط", false, 3, 4), kTaWidth, 1.0);

  const float kMeemWidth = GetWidth(kAmiri, u"م", false);
  EXPECT_EQ(GetWidth(kAmiri, u"مَ", false, 0, 1), kMeemWidth);
  EXPECT_EQ(GetWidth(kAmiri, u"مَ", false, 0, 2), kMeemWidth);
  EXPECT_EQ(GetWidth(kAmiri, u"مَ", false, 1, 2), kMeemWidth);
}

TEST_F(CursorPositionTest, RTLLigature) {
  const float kFUWidth = GetWidth(kMegalopolis, "FU", true);
  const float kRAWidth = GetWidth(kMegalopolis, "RA", true);

  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 0, 1), kRAWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 0, 2), kRAWidth, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 0, 3),
              kRAWidth + kFUWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 0, 4), kRAWidth + kFUWidth,
              1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 1, 2), kRAWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 1, 3),
              kRAWidth / 2 + kFUWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 1, 4),
              kRAWidth / 2 + kFUWidth, 1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 2, 3), kFUWidth / 2, 1.0);
  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 2, 4), kFUWidth, 1.0);

  EXPECT_NEAR(GetWidth(kMegalopolis, "ARUF", false, 3, 4), kFUWidth / 2, 1.0);
}

}  // namespace blink

"""

```