Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Scan and Purpose Identification:**

* **File Name:** `run_segmenter_test.cc` immediately suggests this file is about testing something called `RunSegmenter`. The `.cc` extension confirms it's C++ code.
* **Includes:** The included headers give strong clues:
    * `"third_party/blink/renderer/platform/fonts/shaping/run_segmenter.h"`: This is the header file for the class being tested. We now know `RunSegmenter` is related to font shaping.
    * `"testing/gtest/include/gtest/gtest.h"`: This indicates the use of Google Test, a common C++ testing framework. This tells us the file contains unit tests.
    * Other includes like `string`, `vector`, `StringBuilder`, `WTFString`, and `OrientationIterator.h` suggest the types of data and operations involved.

* **Namespace:** `namespace blink { ... }` tells us this code belongs to the Blink rendering engine.

**High-Level Understanding:** The file contains unit tests for the `RunSegmenter` class in Blink, which is involved in font shaping.

**2. Core Test Structure Analysis:**

* **Test Fixture:** The `RunSegmenterTest` class inherits from `testing::Test`. This is a standard Google Test pattern for grouping related tests.
* **Helper Functions:** The `protected` section contains helper functions:
    * `CheckRuns`, `CheckRunsMixed`, `CheckRunsHorizontal`: These functions seem to take a `Vector<SegmenterTestRun>` and an `orientation`, and then call `VerifyRuns`. This suggests a pattern for setting up test input and expected output.
    * `VerifyRuns`: This function takes a `RunSegmenter` object and a `Vector<SegmenterExpectedRun>`, then iterates through the `RunSegmenter`'s output and compares it to the expected output. This is the core assertion logic.

* **Test Cases (using `TEST_F`):**  The `TEST_F` macros define individual test cases. The names of the test cases (e.g., `Empty`, `LatinPunctuationSideways`) give hints about the scenarios being tested.

**3. Data Structures Deep Dive:**

* **`SegmenterTestRun`:** Represents a single input "run" of text with its properties (text content, script, orientation, fallback priority).
* **`SegmenterExpectedRun`:** Represents the expected output for a corresponding input run (start and end indices, script, orientation, fallback priority). The constructor makes it easy to create these expected values.

**4. Functionality Inference of `RunSegmenter`:**

Based on the tests and the data structures, we can infer the following about `RunSegmenter`:

* **Input:** Takes a string of text and a `FontOrientation`.
* **Output:**  Produces a sequence of "runs," where each run has:
    * `start` and `end`: Indicating the range of the run within the input text.
    * `script`: The Unicode script of the characters in the run.
    * `render_orientation`: How the text in the run should be rendered (horizontal, vertical, sideways, etc.).
    * `font_fallback_priority`:  Indicates the priority for choosing a font for this run (e.g., regular text, emoji).
* **Purpose:**  The `RunSegmenter` appears to be responsible for segmenting a piece of text into chunks (runs) based on properties like script, orientation, and fallback needs. This segmentation is essential for correct font selection and rendering.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **Font Selection (CSS):** The `font-family` CSS property allows specifying font preferences. The `RunSegmenter`'s output directly informs the browser's font selection process. Different runs might require different fonts.
* **Text Orientation (CSS):** CSS properties like `writing-mode` (horizontal-tb, vertical-rl, etc.) influence text orientation. The `RunSegmenter`'s `render_orientation` directly relates to how the browser will apply these styles.
* **Internationalization (HTML/JavaScript):** HTML's `lang` attribute and JavaScript's internationalization APIs (e.g., `Intl` object) deal with language and script-specific formatting. The `RunSegmenter` operates at a lower level, but its output is crucial for rendering text correctly according to these higher-level settings. For example, the script detection is a core part of internationalization.
* **Emoji Rendering:** The `FontFallbackPriority::kEmojiEmoji` suggests that the segmenter helps in identifying and handling emoji characters, which often require special font handling.

**6. Logic Inference and Examples:**

The tests themselves serve as excellent examples of assumed input and expected output. For example, the `ArabicHangul` test shows that when the input is "نص키스의", the segmenter correctly identifies two runs: one for Arabic and one for Hangul, with different orientations.

**7. Common Usage Errors (Developer Perspective):**

While this is a testing file and not directly used by developers, understanding its purpose can highlight potential errors when *implementing* or *using* related font shaping logic:

* **Incorrect Script Detection:** If the `RunSegmenter` incorrectly identifies the script of a character or sequence, the wrong font might be selected. This could lead to "tofu" (missing glyphs) or incorrect rendering.
* **Ignoring Orientation:** Failing to respect the `render_orientation` of a run would lead to text being displayed in the wrong direction (e.g., horizontal text in a vertical layout).
* **Incorrect Fallback Prioritization:**  If emoji are not given the correct priority, they might be rendered using a standard text font, resulting in a different visual appearance than intended.

**Self-Correction/Refinement During Analysis:**

Initially, one might just see "font shaping" and think it's just about making glyphs look nice. But analyzing the test cases reveals more nuanced functionality: script identification, orientation handling, and even prioritization of different types of content (like emoji). The test names and the structure of the expected output are key to understanding these specific functionalities. The connection to CSS properties like `writing-mode` and `font-family` becomes clearer as you see how the `RunSegmenter`'s output directly informs these rendering decisions.
这个文件 `run_segmenter_test.cc` 是 Chromium Blink 引擎中用于测试 `RunSegmenter` 类的单元测试文件。`RunSegmenter` 的主要功能是将一段文本根据其字符的属性（如 Unicode 脚本、书写方向等）分割成不同的“runs”（段落），每个 run 内的文本具有相同的渲染属性。

以下是该文件的功能详细说明：

**1. 测试 `RunSegmenter` 的核心功能：**

   - **文本分割 (Segmentation):**  验证 `RunSegmenter` 是否能正确地将输入的文本字符串分割成具有一致属性的段落（runs）。这些属性包括 Unicode 脚本 (UScriptCode)、渲染方向 (RenderOrientation) 和字体回退优先级 (FontFallbackPriority)。
   - **属性一致性:** 确保在同一个 run 内的所有字符都具有相同的脚本、渲染方向和字体回退优先级。
   - **边界确定:**  测试分割后的每个 run 的起始和结束位置是否正确。

**2. 测试不同文本组合的分割情况：**

   - **空字符串：** 测试处理空字符串的情况。
   - **拉丁字母和标点符号：** 测试拉丁文字符和标点符号的组合，并验证其在混合方向模式下的渲染方向。
   - **空格：** 测试单独空格的处理。
   - **不同脚本的混合：** 测试包含阿拉伯语、韩语、日语、梵文等不同 Unicode 脚本的文本分割。
   - **表情符号 (Emoji)：** 测试包含 emoji 表情符号的文本，并验证其特殊的字体回退优先级。
   - **组合字符：** 测试组合字符（如带附加符号的拉丁字母）的处理。
   - **特定符号：** 测试技术符号、通用符号和标点符号的处理。
   - **日文标点符号在日文文本中的处理：**  测试日文标点符号在日文文本中以及与其他日文文本相邻时的分割情况。
   - **ZWJ 序列 (Zero-Width Joiner Sequences)：** 测试由零宽度连接符连接的 emoji 序列的正确分割，确保它们被视为一个整体。
   - **类似于字母的符号：** 测试类似于字母的符号（如数学符号）在不同上下文中的处理。
   - **大小写：** 测试不同大小写字母对分割的影响。
   - **杂项符号和修饰符：** 测试 dingbats、杂项符号和修饰符的处理。
   - **亚美尼亚语和西里尔字母：** 测试这两种字符集以及它们的大小写。
   - **Emoji Subdivision Flags (国旗表情符号)：** 测试由多个 Unicode 字符组成的国旗 emoji 的处理。
   - **非 Emoji Presentation Symbols：** 测试不作为 emoji 显示的特定符号。
   - **CJK 括号：** 测试 CJK 括号在拉丁字母和括号前后的分割情况，以及括号嵌套的情况。

**与 JavaScript, HTML, CSS 功能的关系：**

`RunSegmenter` 的功能直接影响到浏览器如何渲染网页上的文本，这与 JavaScript, HTML, CSS 都有关系：

* **HTML:** HTML 结构定义了文本内容。`RunSegmenter` 处理的就是 HTML 中文本节点的内容。
* **CSS:** CSS 样式可以影响文本的渲染，例如 `writing-mode` 属性可以设置文本的书写方向（水平或垂直）。`RunSegmenter` 会考虑这些样式，并根据需要将文本分割成具有相应渲染方向的 runs。例如，如果 CSS 设置了垂直书写模式，某些标点符号的渲染方向可能会发生变化，`RunSegmenter` 需要正确识别并分割。
* **JavaScript:** JavaScript 可以动态地修改 HTML 内容。当 JavaScript 操作文本内容时，浏览器的渲染引擎会重新运行 `RunSegmenter` 来分割新的文本。此外，JavaScript 可以通过 DOM API 获取文本内容，这些内容最终会传递给渲染引擎进行处理。

**举例说明：**

假设有以下 HTML 片段：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .vertical-text {
    writing-mode: vertical-rl;
  }
</style>
</head>
<body>
  <div>Hello, こんにちは!</div>
  <div class="vertical-text">Hello, こんにちは!</div>
</body>
</html>
```

1. **第一个 `div` (水平文本):**
   - 输入到 `RunSegmenter` 的文本是 "Hello, こんにちは!"。
   - `RunSegmenter` 可能会将其分割成以下 runs：
     - "Hello, " (拉丁脚本, 水平方向, 普通优先级)
     - "こんにちは!" (日语脚本, 水平方向, 普通优先级)

2. **第二个 `div` (垂直文本):**
   - 输入到 `RunSegmenter` 的文本同样是 "Hello, こんにちは!"。
   - 由于 CSS 设置了 `writing-mode: vertical-rl;`，`RunSegmenter` 的分割可能会考虑垂直方向的渲染规则：
     - "H", "e", "l", "l", "o" (拉丁脚本, 垂直方向, 普通优先级) - 每个字母可能单独作为一个 run，或者根据更复杂的规则组合。
     - ",", " " (通用脚本, 垂直方向, 可能需要旋转渲染, 普通优先级)
     - "こ", "ん", "に", "ち", "は", "!" (日语脚本, 垂直方向, 普通优先级) -  日文通常在垂直模式下保持直立。

在这个例子中，`RunSegmenter` 的输出会影响到浏览器如何排布和渲染这些字符，例如标点符号在垂直模式下可能需要旋转。

**逻辑推理，假设输入与输出：**

**假设输入：** 字符串 "这是一段包含English和日本語的文本。" (UTF-8 编码)

**预期输出（水平方向）：**

| Start | Limit | Script         | Render Orientation        | Font Fallback Priority | Text Segment |
|-------|-------|----------------|---------------------------|------------------------|--------------|
| 0     | 6     | USCRIPT_HAN    | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 这是一段 |
| 6     | 14    | USCRIPT_LATIN  | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 包含English |
| 14    | 15    | USCRIPT_HAN    | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 和         |
| 15    | 21    | USCRIPT_JAPANESE | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 日本語     |
| 21    | 24    | USCRIPT_HAN    | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 的文本     |
| 24    | 25    | USCRIPT_COMMON | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText | 。         |

**假设输入：** 字符串 "👨‍👩‍👧‍👦你好" (包含 Emoji)

**预期输出：**

| Start | Limit | Script        | Render Orientation        | Font Fallback Priority   | Text Segment |
|-------|-------|---------------|---------------------------|------------------------|--------------|
| 0     | 7     | USCRIPT_COMMON| OrientationIterator::kOrientationKeep | FontFallbackPriority::kEmojiEmoji | 👨‍👩‍👧‍👦     |
| 7     | 9     | USCRIPT_HAN   | OrientationIterator::kOrientationKeep | FontFallbackPriority::kText       | 你好         |

**用户或编程常见的使用错误：**

由于 `run_segmenter_test.cc` 是测试代码，它本身不会被用户直接使用。然而，理解 `RunSegmenter` 的工作原理可以帮助开发者避免在相关领域的错误：

1. **假设文本具有单一属性：**  开发者可能会错误地假设一段文本的所有字符都应该使用相同的字体或渲染方式。`RunSegmenter` 的存在提醒我们，文本可能包含多种脚本和需要不同处理方式的部分。

2. **忽略书写方向：** 在处理国际化文本时，开发者可能会忘记考虑不同的书写方向（如从右到左的阿拉伯语）。`RunSegmenter` 的测试用例涵盖了不同的方向，这强调了处理文本方向的重要性。

3. **未正确处理 Emoji 和特殊符号：**  Emoji 和一些特殊符号可能需要特殊的字体和渲染处理。如果开发者没有意识到这一点，可能会导致这些字符显示不正确。`RunSegmenter` 中对 Emoji 的特殊处理 (如 `FontFallbackPriority::kEmojiEmoji`)  突出了这一点。

4. **在低级文本处理中手动分割文本：**  开发者可能会尝试自己编写逻辑来分割文本，但这样做容易出错且难以维护。`RunSegmenter` 这样的工具提供了经过良好测试和优化的解决方案。

总之，`run_segmenter_test.cc` 通过各种测试用例验证了 `RunSegmenter` 类的正确性，确保 Blink 引擎能够准确地将文本分割成具有一致渲染属性的段落，这对于正确地呈现各种语言和字符的网页至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/run_segmenter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/run_segmenter.h"

#include <string>
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/orientation_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

struct SegmenterTestRun {
  std::string text;
  UScriptCode script;
  OrientationIterator::RenderOrientation render_orientation;
  FontFallbackPriority font_fallback_priority;
};

struct SegmenterExpectedRun {
  unsigned start;
  unsigned limit;
  UScriptCode script;
  OrientationIterator::RenderOrientation render_orientation;
  FontFallbackPriority font_fallback_priority;

  SegmenterExpectedRun(
      unsigned the_start,
      unsigned the_limit,
      UScriptCode the_script,
      OrientationIterator::RenderOrientation the_render_orientation,
      FontFallbackPriority the_font_fallback_priority)
      : start(the_start),
        limit(the_limit),
        script(the_script),
        render_orientation(the_render_orientation),
        font_fallback_priority(the_font_fallback_priority) {}
};

class RunSegmenterTest : public testing::Test {
 protected:
  void CheckRuns(const Vector<SegmenterTestRun>& runs,
                 FontOrientation orientation) {
    StringBuilder text;
    text.Ensure16Bit();
    Vector<SegmenterExpectedRun> expect;
    for (auto& run : runs) {
      unsigned length_before = text.length();
      text.Append(String::FromUTF8(run.text.c_str()));
      expect.push_back(SegmenterExpectedRun(length_before, text.length(),
                                            run.script, run.render_orientation,
                                            run.font_fallback_priority));
    }
    RunSegmenter run_segmenter(text.Span16(), orientation);
    VerifyRuns(&run_segmenter, expect);
  }

  void CheckRunsMixed(const Vector<SegmenterTestRun>& runs) {
    CheckRuns(runs, FontOrientation::kVerticalMixed);
  }

  void CheckRunsHorizontal(const Vector<SegmenterTestRun>& runs) {
    CheckRuns(runs, FontOrientation::kHorizontal);
  }

  void VerifyRuns(RunSegmenter* run_segmenter,
                  const Vector<SegmenterExpectedRun>& expect) {
    RunSegmenter::RunSegmenterRange segmenter_range;
    size_t run_count = 0;
    while (run_segmenter->Consume(&segmenter_range)) {
      ASSERT_LT(run_count, expect.size());
      ASSERT_EQ(expect[run_count].start, segmenter_range.start);
      ASSERT_EQ(expect[run_count].limit, segmenter_range.end);
      ASSERT_EQ(expect[run_count].script, segmenter_range.script);
      ASSERT_EQ(expect[run_count].render_orientation,
                segmenter_range.render_orientation);
      ASSERT_EQ(expect[run_count].font_fallback_priority,
                segmenter_range.font_fallback_priority);
      ++run_count;
    }
    ASSERT_EQ(expect.size(), run_count);
  }
};

TEST_F(RunSegmenterTest, Empty) {
  String empty(g_empty_string16_bit);
  RunSegmenter::RunSegmenterRange segmenter_range = {
      0, 0, USCRIPT_INVALID_CODE, OrientationIterator::kOrientationKeep};
  RunSegmenter run_segmenter(empty.Span16(), FontOrientation::kVerticalMixed);
  DCHECK(!run_segmenter.Consume(&segmenter_range));
  ASSERT_EQ(segmenter_range.start, 0u);
  ASSERT_EQ(segmenter_range.end, 0u);
  ASSERT_EQ(segmenter_range.script, USCRIPT_INVALID_CODE);
  ASSERT_EQ(segmenter_range.render_orientation,
            OrientationIterator::kOrientationKeep);
  ASSERT_EQ(segmenter_range.font_fallback_priority,
            FontFallbackPriority::kText);
}

TEST_F(RunSegmenterTest, LatinPunctuationSideways) {
  CheckRunsMixed({{"Abc.;?Xyz", USCRIPT_LATIN,
                   OrientationIterator::kOrientationRotateSideways,
                   FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, OneSpace) {
  CheckRunsMixed(
      {{" ", USCRIPT_COMMON, OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, ArabicHangul) {
  CheckRunsMixed(
      {{"نص", USCRIPT_ARABIC, OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText},
       {"키스의", USCRIPT_HANGUL, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, JapaneseHindiEmojiMix) {
  CheckRunsMixed(
      {{"百家姓", USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"ऋषियों", USCRIPT_DEVANAGARI,
        OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText},
       {"🌱🌲🌳🌴", USCRIPT_DEVANAGARI, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kEmojiEmoji},
       {"百家姓", USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"🌱🌲", USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kEmojiEmoji}});
}

TEST_F(RunSegmenterTest, CombiningCirlce) {
  CheckRunsHorizontal(
      {{"◌́◌̀◌̈◌̂◌̄◌̊", USCRIPT_COMMON, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, HangulSpace) {
  CheckRunsMixed(
      {{"키스의", USCRIPT_HANGUL, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {" ", USCRIPT_HANGUL, OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText},
       {"고유조건은", USCRIPT_HANGUL, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, TechnicalCommonUpright) {
  CheckRunsMixed({{"⌀⌁⌂", USCRIPT_COMMON, OrientationIterator::kOrientationKeep,
                   FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, PunctuationCommonSideways) {
  CheckRunsMixed(
      {{".…¡", USCRIPT_COMMON, OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, JapanesePunctuationMixedInside) {
  CheckRunsMixed(
      {{"いろはに", USCRIPT_HIRAGANA, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {".…¡", USCRIPT_HIRAGANA,
        OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText},
       {"ほへと", USCRIPT_HIRAGANA, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, JapanesePunctuationMixedInsideHorizontal) {
  CheckRunsHorizontal(
      {{"いろはに.…¡ほへと", USCRIPT_HIRAGANA,
        OrientationIterator::kOrientationKeep, FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, PunctuationDevanagariCombining) {
  CheckRunsHorizontal(
      {{"क+े", USCRIPT_DEVANAGARI, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, EmojiZWJSequences) {
  CheckRunsHorizontal(
      {{"👩‍👩‍👧‍👦👩‍❤️‍💋‍👨", USCRIPT_LATIN,
        OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kEmojiEmoji},
       {"abcd", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"👩‍👩", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kEmojiEmoji},
       {"\U0000200D‍efg", USCRIPT_LATIN,
        OrientationIterator::kOrientationKeep, FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, JapaneseLetterlikeEnd) {
  CheckRunsMixed(
      {{"いろは", USCRIPT_HIRAGANA, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"ℐℒℐℒℐℒℐℒℐℒℐℒℐℒ", USCRIPT_HIRAGANA,
        OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, JapaneseCase) {
  CheckRunsMixed(
      {{"いろは", USCRIPT_HIRAGANA, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"aaAA", USCRIPT_LATIN, OrientationIterator::kOrientationRotateSideways,
        FontFallbackPriority::kText},
       {"いろは", USCRIPT_HIRAGANA, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, DingbatsMiscSymbolsModifier) {
  CheckRunsHorizontal({{"⛹🏻✍🏻✊🏼", USCRIPT_COMMON,
                        OrientationIterator::kOrientationKeep,
                        FontFallbackPriority::kEmojiEmoji}});
}

TEST_F(RunSegmenterTest, ArmenianCyrillicCase) {
  CheckRunsHorizontal(
      {{"աբգ", USCRIPT_ARMENIAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"αβγ", USCRIPT_GREEK, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"ԱԲԳ", USCRIPT_ARMENIAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, EmojiSubdivisionFlags) {
  CheckRunsHorizontal(
      {{"🏴󠁧󠁢󠁷󠁬󠁳󠁿🏴󠁧󠁢󠁳󠁣󠁴󠁿🏴󠁧󠁢"
        "󠁥󠁮󠁧󠁿",
        USCRIPT_COMMON, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kEmojiEmoji}});
}

TEST_F(RunSegmenterTest, NonEmojiPresentationSymbols) {
  CheckRunsHorizontal(
      {{"\U00002626\U0000262a\U00002638\U0000271d\U00002721\U00002627"
        "\U00002628\U00002629\U0000262b\U0000262c\U00002670"
        "\U00002671\U0000271f\U00002720",
        USCRIPT_COMMON, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, CJKBracketsAfterLatinLetter) {
  CheckRunsHorizontal(
      {{"A", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"\u300C"   // CJK LEFT CORNER BRACKET
        "\u56FD"   // CJK UNIFIED IDEOGRAPH
        "\u300D",  // CJK RIGHT CORNER BRACKET
        USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, CJKBracketsAfterLatinParenthesis) {
  CheckRunsHorizontal(
      {{"A(", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"\u300C"   // CJK LEFT CORNER BRACKET
        "\u56FD"   // CJK UNIFIED IDEOGRAPH
        "\u300D",  // CJK RIGHT CORNER BRACKET
        USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {")", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, CJKBracketsWithLatinParenthesisInside) {
  CheckRunsHorizontal(
      {{"A", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"\u300C"  // CJK LEFT CORNER BRACKET
        "\u56FD"  // CJK UNIFIED IDEOGRAPH
        "(",
        USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"A", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {")"
        "\u300D",  // CJK RIGHT CORNER BRACKET
        USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

TEST_F(RunSegmenterTest, CJKBracketsAfterUnmatchingLatinParenthesis) {
  CheckRunsHorizontal(
      {{"A((", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {"\u300C"   // CJK LEFT CORNER BRACKET
        "\u56FD"   // CJK UNIFIED IDEOGRAPH
        "\u300D",  // CJK RIGHT CORNER BRACKET
        USCRIPT_HAN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText},
       {")", USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText}});
}

}  // namespace blink

"""

```