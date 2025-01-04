Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The filename `forward_grapheme_boundary_state_machine_test.cc` immediately suggests the purpose: testing a state machine responsible for identifying grapheme boundaries when moving forward in text. The "forward" part is key.

2. **Identify Core Functionality:**  The code includes `<gtest/gtest.h>` which confirms it's a unit test using Google Test. The `#include` for the state machine itself (`forward_grapheme_boundary_state_machine.h`) tells us what's being tested. The inclusion of `state_machine_test_util.h` suggests there are helper functions to streamline the testing process.

3. **Decipher the Test Structure:** The file defines a namespace `forward_grapheme_boundary_state_machine_test`. Inside this, a test fixture class `ForwardGraphemeBoundaryStatemachineTest` inherits from `GraphemeStateMachineTestBase`. This inheritance suggests a common base class for testing related state machines. The `TEST_F` macro indicates individual test cases within the fixture.

4. **Analyze Individual Test Cases:**  Go through each `TEST_F` and infer its purpose from the name and the code within:
    * `DoNothingCase`:  Tests the initial state and ensures calling `FinalizeAndGetBoundaryOffset()` multiple times doesn't cause issues. The expected output is 0, indicating no movement.
    * `PrecedingText`:  Focuses on whether preceding text influences the grapheme boundary detection. The tests show that regardless of the characters before the cursor, the boundary after the initial position is always 1 (for single-character graphemes).
    * `BrokenSurrogatePair`:  Tests how the state machine handles invalid surrogate pairs. It correctly identifies a boundary after the broken surrogate.
    * `BreakImmediately_BMP` and `BreakImmediately_Supplementary`: These test the basic cases of moving past single BMP (Basic Multilingual Plane) and supplementary characters. The boundary offset is 1 for BMP and 2 for supplementary.
    * `NotBreakImmediatelyAfter_BMP_BMP`, `NotBreakImmediatelyAfter_Supplementary_BMP`, etc.: These test cases demonstrate scenarios where a grapheme consists of multiple code points (like base character + combining mark). The state machine should not break immediately after the first code point. The boundary offsets reflect the length of the combined grapheme.
    * `MuchLongerCase`: Tests a complex ZWJ (Zero-Width Joiner) sequence, showcasing the state machine's ability to handle combined emojis.
    * `singleFlags` and `twoFlags`: Test how regional indicator symbols (flags) are treated as graphemes. Two consecutive regional indicators form a single flag emoji.
    * `oddNumberedFlags`: Tests the case of an odd number of regional indicators, where the last one is treated as a separate grapheme.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider where grapheme boundaries are relevant in web contexts.
    * **JavaScript:** String manipulation, text rendering in canvas. Operations like `substring`, iteration over characters.
    * **HTML:**  Text content within elements, `<textarea>` input. Cursor positioning, text selection.
    * **CSS:** Line breaking (`word-break`, `overflow-wrap`), text justification.

6. **Infer Logic and Assumptions:** The tests implicitly reveal the logic of the state machine:
    * It correctly handles single-code-point characters.
    * It recognizes combining marks and variation selectors.
    * It understands surrogate pairs for supplementary characters.
    * It specifically handles regional indicator symbols for flags.
    * It correctly identifies ZWJ sequences as single graphemes.
    * The starting position of the cursor (`|`) is important for determining the *next* grapheme boundary.

7. **Identify Potential User/Programming Errors:** Think about common mistakes related to text and Unicode:
    * Incorrectly assuming one character equals one code point.
    * Not handling surrogate pairs properly.
    * Mishandling combining marks or variation selectors.
    * Issues with ZWJ sequences.

8. **Construct Debugging Scenarios:** Imagine a user interacting with a web page and how their actions might lead to this code being executed. Cursor movements, text input, text selection are prime examples.

9. **Refine and Organize:** Structure the analysis logically, covering functionality, relationships to web technologies, logic/assumptions, potential errors, and debugging. Use clear examples to illustrate the points.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on individual test cases without seeing the bigger picture. Stepping back to understand the overall purpose of the state machine is important.
* I might need to look up specific Unicode terms (like "grapheme," "surrogate pair," "combining mark," "variation selector," "ZWJ") to ensure accurate explanations.
* I might initially oversimplify the connection to web technologies. Thinking about specific APIs and CSS properties makes the connection clearer.
* Ensuring the input and output examples in the logical reasoning section are precise and reflect the test cases is crucial. The "SRF", "SRRF", etc., strings represent the state transitions and final state, providing a concise way to describe the machine's behavior.

By following these steps and iteratively refining the analysis, we can arrive at a comprehensive understanding of the test file and its implications.
这个C++源代码文件 `forward_grapheme_boundary_state_machine_test.cc` 是 Chromium Blink 引擎中用于测试 `ForwardGraphemeBoundaryStateMachine` 类的单元测试文件。它的主要功能是：

**功能：**

1. **测试 `ForwardGraphemeBoundaryStateMachine` 类的正确性：** 该状态机旨在确定在文本中向前移动时下一个字形（grapheme）边界的位置。字形是用户感知到的一个字符，可能由一个或多个 Unicode 码点组成。
2. **覆盖各种 Unicode 场景：** 测试用例涵盖了各种 Unicode 字符和组合，包括：
    * 基本多文种平面 (BMP) 字符
    * 补充平面字符（需要代理对表示）
    * 组合字符序列（如带有变体选择器的字符）
    * 地区指示符符号（用于表示国旗）
    * 零宽度连接符 (ZWJ) 序列（用于组合 emoji）
    * 破碎的代理对
3. **验证状态机的状态转换和边界计算：**  通过模拟不同的输入字符序列，测试用例验证状态机是否正确地转换状态并计算出正确的字形边界偏移量。
4. **使用 Google Test 框架：**  该文件使用 Google Test 框架来组织和执行测试用例，并提供断言来验证预期结果。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个 C++ 文件本身不是直接的 JavaScript, HTML, 或 CSS 代码，但它测试的 `ForwardGraphemeBoundaryStateMachine` 类在渲染引擎中扮演着关键角色，直接影响到这些技术对文本的处理：

* **JavaScript:**
    * **字符串操作：** JavaScript 中的字符串操作，如 `substring()`, `charAt()`, 遍历字符串等，都需要正确理解字符边界。如果 JavaScript 引擎底层使用了类似的字形边界检测机制，那么这个状态机的正确性直接影响到 JavaScript 字符串操作的准确性。例如，当需要截取字符串中前 N 个“字符”时，实际上需要截取前 N 个字形。
    * **文本渲染：** 当 JavaScript 代码在 Canvas 上绘制文本时，也需要知道每个字形的边界，以便正确渲染和布局文本。
    * **文本输入处理：** 当用户在 `<input>` 或 `<textarea>` 中输入文本时，JavaScript 可能需要处理光标移动、字符删除等操作，这依赖于对字形边界的理解。

    **举例说明：**
    ```javascript
    const text = "👨‍👩‍👧‍👦"; // 一个由多个 Unicode 码点组成的家庭 emoji
    console.log(text.length); // 输出可能是 7 或其他，取决于 JavaScript 引擎如何计算
    console.log(Array.from(text).length); // 输出 1，因为 Array.from() 可以正确处理 Unicode 字形
    ```
    这个 C++ 测试文件中的逻辑确保了 Blink 引擎在处理这样的 emoji 时能够正确识别为一个字形。

* **HTML:**
    * **文本渲染：** HTML 文档中的文本内容最终由渲染引擎进行渲染。字形边界的正确识别对于文本的换行、对齐、选择等至关重要。例如，当一个单词超出容器宽度需要换行时，应该在字形边界处进行。
    * **光标定位和文本选择：** 当用户在 HTML 元素中移动光标或选择文本时，渲染引擎需要根据字形边界来确定光标的位置和选区的范围。

    **举例说明：**
    考虑 HTML 中一个包含复杂 emoji 的段落 `<p>👨‍👩‍👧‍👦 text</p>`。`ForwardGraphemeBoundaryStateMachine` 的正确性保证了用户可以使用左右箭头键将光标作为一个整体移动到 emoji 的开头或结尾，而不是在 emoji 的每个组成部分之间移动。

* **CSS:**
    * **文本布局和换行：** CSS 的 `word-break`, `overflow-wrap` 等属性控制着文本的换行行为。渲染引擎需要准确识别字形边界才能正确地进行单词或字符级别的换行。
    * **文本选择样式：** 当用户选择文本时，CSS 会应用相应的选择样式。字形边界的准确性确保了选区能够正确地覆盖用户期望选择的字符。

    **举例说明：**
    如果 CSS 设置了 `word-break: break-all;`，渲染引擎会在任何可以断开的位置换行。但即使在这种情况下，也需要理解字形的概念，以避免将一个字形拆散显示。

**逻辑推理 (假设输入与输出):**

测试用例中使用了 `ProcessSequenceForward` 函数，它模拟了状态机处理一系列字符的过程。以下举例说明一些测试用例的假设输入和预期输出：

* **假设输入:**  `SOT + | + 'a' + 'a'` (文本开始，初始位置，字符 'a'，字符 'a')
    * **预期输出 (状态转换序列):** `"SRF"` (Start -> Regular -> Final)，表示状态机处理了两个字符并到达最终状态。
    * **预期边界偏移:** `1`，表示下一个字形边界在当前位置之后的一个字符处。

* **假设输入:** `SOT + | + U+1F441 + 'a'` (文本开始，初始位置，emoji '👁️'，字符 'a')
    * **预期输出 (状态转换序列):** `"SRRF"` (Start -> Regular -> Regular -> Final)，因为 emoji '👁️' 通常由两个码点组成（基本字符 + 变体选择器）。
    * **预期边界偏移:** `2`，表示下一个字形边界在当前位置之后的两个码点处。

* **假设输入:** `SOT + | + kRisU + kRisS` (文本开始，初始位置，地区指示符 U，地区指示符 S)
    * **预期输出 (状态转换序列):** `"SRRRF"` (Start -> Regular -> Regular -> Regular -> Final)，两个地区指示符组合成一个国旗 emoji。
    * **预期边界偏移:** `4`，因为两个地区指示符通常分别占用两个 UTF-16 代码单元。

**用户或编程常见的使用错误：**

* **错误地认为一个字符等于一个码点：**  这是最常见的错误。用户或开发者可能会假设字符串的长度等于字符的数量，但对于包含组合字符或补充平面字符的文本，这是不成立的。
    * **例子：**  一个 emoji 如 "👨‍👩‍👧‍👦" 可能由 7 个或更多的 Unicode 码点组成，但用户感知为一个字符。使用 `string.length` 可能会得到错误的字符数。
* **不正确地处理代理对：**  对于补充平面字符（码点大于 U+FFFF），需要使用代理对（两个 16 位的码元）来表示。错误地处理代理对会导致字符显示不正确或字符串操作出错。
    * **例子：**  尝试将代理对拆开处理，例如，只处理前导代理或后尾代理。
* **没有考虑到组合字符序列：**  某些字符是通过基本字符和组合字符（如变音符号）组合而成的。错误地将它们视为独立的字符会导致布局和选择问题。
    * **例子：**  字符 "é" 可以由 'e' 和组合尖音符 `\u0301` 组成。
* **对 ZWJ 序列的处理不当：**  ZWJ 用于将多个 emoji 组合成新的 emoji。如果不知道 ZWJ 的作用，可能会错误地将一个组合 emoji 分割开。
    * **例子：**  组合 emoji "👨‍👩‍👧‍👦" 中包含了多个 emoji 和 ZWJ。

**用户操作是如何一步步的到达这里，作为调试线索：**

这个测试文件是开发者在编写和维护 Blink 引擎代码时使用的。用户操作本身不会直接“到达”这个测试文件，但用户在浏览器中的各种操作会触发相关代码的执行，而这些代码的正确性依赖于像 `ForwardGraphemeBoundaryStateMachine` 这样的组件。

以下是一些可能导致相关代码执行的用户操作场景：

1. **用户在文本框中输入文本：**
    * 当用户输入字符时，浏览器需要判断光标的下一个位置，这涉及到字形边界的计算。
    * 输入组合字符、emoji、或者包含代理对的字符时，会触发更复杂的字形边界判断逻辑。
2. **用户在网页中移动光标：**
    * 使用键盘上的左右箭头键在文本中移动光标时，浏览器需要根据字形边界来确定光标应该移动到哪个位置。
    * 对于复杂的字形，如 emoji，光标应该一次移动整个字形。
3. **用户在网页中选择文本：**
    * 当用户拖动鼠标或使用 Shift 键加方向键选择文本时，浏览器需要根据字形边界来确定选区的开始和结束位置。
    * 正确的字形边界可以确保用户能够选择完整的字符，而不会只选中字符的一部分。
4. **用户复制和粘贴文本：**
    * 复制和粘贴操作涉及到文本的剪切和插入，都需要正确处理字形边界，以避免破坏字符的完整性。
5. **网页进行文本渲染和布局：**
    * 当浏览器渲染包含各种 Unicode 字符的网页时，需要使用字形边界信息来正确地进行换行、对齐等布局操作.

**调试线索:**

如果用户在浏览器中遇到与文本处理相关的 bug，例如：

* 光标在 emoji 或组合字符中移动不正常。
* 文本选择时选中了半个字符。
* 包含复杂字符的文本换行不正确。

作为开发者，可以从以下几个方面入手调试：

1. **检查渲染引擎中字形边界计算的相关代码：**  `forward_grapheme_boundary_state_machine_test.cc` 测试的 `ForwardGraphemeBoundaryStateMachine` 类就是关键组件之一。
2. **查看浏览器控制台的错误信息：**  虽然这个特定组件的错误可能不会直接暴露在控制台，但与文本处理相关的 JavaScript 错误或警告可能提供线索。
3. **使用浏览器的开发者工具检查 DOM 结构和样式：**  查看文本节点的具体内容，以及相关的 CSS 样式，特别是与文本布局和换行相关的属性。
4. **尝试不同的输入和操作：**  复现用户的操作步骤，并尝试不同的输入组合，以便找到导致问题的具体场景。
5. **查阅 Unicode 标准和相关文档：**  了解 Unicode 中关于字形、组合字符、代理对、ZWJ 等的定义和处理规则。
6. **运行相关的单元测试：**  执行 `forward_grapheme_boundary_state_machine_test.cc` 中的测试用例，确保该组件的基本功能是正常的。如果测试失败，则说明该组件存在 bug。

总之，`forward_grapheme_boundary_state_machine_test.cc` 这个文件虽然是幕后英雄，但它确保了 Chromium Blink 引擎能够正确处理各种复杂的 Unicode 文本，从而为用户提供一致且可靠的文本浏览和编辑体验。用户在浏览器中进行的各种文本相关的操作，其底层都离不开像这样的基础组件的支撑。

Prompt: 
```
这是目录为blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/state_machines/state_machine_test_util.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace forward_grapheme_boundary_state_machine_test {

// Notations:
// | indicates inidicates initial offset position.
// SOT indicates start of text.
// EOT indicates end of text.
// [Lead] indicates broken lonely lead surrogate.
// [Trail] indicates broken lonely trail surrogate.
// [U] indicates regional indicator symbol U.
// [S] indicates regional indicator symbol S.

// kWatch kVS16, kEye kVS16 are valid standardized variants.
const UChar32 kWatch = 0x231A;
const UChar32 kEye = WTF::unicode::kEyeCharacter;
const UChar32 kVS16 = 0xFE0F;

// kHanBMP KVS17, kHanSIP kVS17 are valie IVD sequences.
const UChar32 kHanBMP = 0x845B;
const UChar32 kHanSIP = 0x20000;
const UChar32 kVS17 = 0xE0100;

// Following lead/trail values are used for invalid surrogate pairs.
const UChar kLead = 0xD83D;
const UChar kTrail = 0xDC66;

// U+1F1FA is REGIONAL INDICATOR SYMBOL LETTER U
const UChar32 kRisU = 0x1F1FA;
// U+1F1F8 is REGIONAL INDICATOR SYMBOL LETTER S
const UChar32 kRisS = 0x1F1F8;

class ForwardGraphemeBoundaryStatemachineTest
    : public GraphemeStateMachineTestBase {
 public:
  ForwardGraphemeBoundaryStatemachineTest(
      const ForwardGraphemeBoundaryStatemachineTest&) = delete;
  ForwardGraphemeBoundaryStatemachineTest& operator=(
      const ForwardGraphemeBoundaryStatemachineTest&) = delete;

 protected:
  ForwardGraphemeBoundaryStatemachineTest() = default;
  ~ForwardGraphemeBoundaryStatemachineTest() override = default;
};

TEST_F(ForwardGraphemeBoundaryStatemachineTest, DoNothingCase) {
  ForwardGraphemeBoundaryStateMachine machine;

  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, PrecedingText) {
  ForwardGraphemeBoundaryStateMachine machine;
  // Preceding text should not affect the result except for flags.
  // SOT + | + 'a' + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRSRF", ProcessSequenceForward(&machine, AsCodePoints(kRisU),
                                            AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // U+0000 + | + 'a' + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(0),
                                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // U+0000 + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRSRF", ProcessSequenceForward(&machine, AsCodePoints(0, kRisU),
                                            AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // U+0000 + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(0, kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + | + 'a' + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints('a'),
                                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // 'a' + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRSRF", ProcessSequenceForward(&machine, AsCodePoints('a', kRisU),
                                            AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // 'a' + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + | + 'a' + 'a'
  EXPECT_EQ("RSRF", ProcessSequenceForward(&machine, AsCodePoints(kEye),
                                           AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // U+1F441 + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kEye, kRisU),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // U+1F441 + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kEye, kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // Broken surrogates in preceding text.

  // [Lead] + | + 'a' + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(kLead),
                                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // [Lead] + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kLead, kRisU),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // [Lead] + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kLead, kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + | + 'a' + 'a'
  EXPECT_EQ("RSRF", ProcessSequenceForward(&machine, AsCodePoints('a', kTrail),
                                           AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // 'a' + [Trail] + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kTrail, kRisU),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // 'a' + [Trail] + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRRSRF", ProcessSequenceForward(
                            &machine, AsCodePoints('a', kTrail, kRisU, kRisS),
                            AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + | + 'a' + 'a'
  EXPECT_EQ("RSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kTrail),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // [Trail] + [Trail] + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRRSRF", ProcessSequenceForward(
                          &machine, AsCodePoints(kTrail, kTrail, kRisU),
                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // [Trail] + [Trail] + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRRSRF",
            ProcessSequenceForward(&machine,
                                   AsCodePoints(kTrail, kTrail, kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + | + 'a' + 'a'
  EXPECT_EQ("RSRF", ProcessSequenceForward(&machine, AsCodePoints(kTrail),
                                           AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + [Trail] + [U] + | + 'a' + 'a'
  EXPECT_EQ("RRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kRisU),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + [Trail] + [U] + [S] + | + 'a' + 'a'
  EXPECT_EQ("RRRRRSRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kRisU, kRisS),
                                   AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, BrokenSurrogatePair) {
  ForwardGraphemeBoundaryStateMachine machine;
  // SOT + | + [Trail]
  EXPECT_EQ("SF", ProcessSequenceForward(&machine, AsCodePoints(),
                                         AsCodePoints(kTrail)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + | + [Lead] + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints(kLead, 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + | + [Lead] + [Lead]
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints(kLead, kLead)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
  // SOT + | + [Lead] + EOT
  EXPECT_EQ("SR", ProcessSequenceForward(&machine, AsCodePoints(),
                                         AsCodePoints(kLead)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, BreakImmediately_BMP) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+0000 + U+0000
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints(0, 0)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + 'a'
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints('a', 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + U+1F441
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints('a', kEye)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + EOT
  EXPECT_EQ("SR", ProcessSequenceForward(&machine, AsCodePoints(),
                                         AsCodePoints('a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + [Trail]
  EXPECT_EQ("SRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints('a', kTrail)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + [Lead] + 'a'
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints('a', kLead, 'a')));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + [Lead] + [Lead]
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints('a', kLead, kLead)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + 'a' + [Lead] + EOT
  EXPECT_EQ("SRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints('a', kLead)));
  EXPECT_EQ(1, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest,
       BreakImmediately_Supplementary) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+1F441 + 'a'
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kEye, 'a')));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+1F441
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kEye)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + EOT
  EXPECT_EQ("SRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints(kEye)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + [Trail]
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kEye, kTrail)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + [Lead] + 'a'
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kLead, 'a')));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + [Lead] + [Lead]
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kLead, kLead)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + [Lead] + EOT
  EXPECT_EQ("SRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kEye, kLead)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyAfter_BMP_BMP) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+231A + U+FE0F + 'a'
  EXPECT_EQ("SRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kWatch, kVS16, 'a')));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + U+1F441
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kWatch, kVS16, kEye)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + EOT
  EXPECT_EQ("SRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                          AsCodePoints(kWatch, kVS16)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + [Trail]
  EXPECT_EQ("SRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kWatch, kVS16, kTrail)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + [Lead] + 'a'
  EXPECT_EQ("SRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kWatch, kVS16, kLead, 'a')));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + [Lead] + [Lead]
  EXPECT_EQ("SRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kWatch, kVS16, kLead, kLead)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+231A + U+FE0F + [Lead] + EOT
  EXPECT_EQ("SRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kWatch, kVS16, kLead)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyAfter_Supplementary_BMP) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+1F441 + U+FE0F + 'a'
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kVS16, 'a')));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + U+1F441
  EXPECT_EQ("SRRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                             AsCodePoints(kEye, kVS16, kEye)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + EOT
  EXPECT_EQ("SRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kEye, kVS16)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + [Trail]
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kVS16, kTrail)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + [Lead] + 'a'
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kEye, kVS16, kLead, 'a')));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + [Lead] + [Lead]
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kEye, kVS16, kLead, kLead)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+1F441 + U+FE0F + [Lead] + EOT
  EXPECT_EQ("SRRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kEye, kVS16, kLead)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyAfter_BMP_Supplementary) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+845B + U+E0100 + 'a'
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kHanBMP, kVS17, 'a')));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + U+1F441
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanBMP, kVS17, kEye)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + EOT
  EXPECT_EQ("SRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                           AsCodePoints(kHanBMP, kVS17)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + [Trail]
  EXPECT_EQ("SRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanBMP, kVS17, kTrail)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + [Lead] + 'a'
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanBMP, kVS17, kLead, 'a')));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + [Lead] + [Lead]
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanBMP, kVS17, kLead, kLead)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+845B + U+E0100 + [Lead] + EOT
  EXPECT_EQ("SRRRR",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanBMP, kVS17, kLead)));
  EXPECT_EQ(3, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyAfter_Supplementary_Supplementary) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + U+20000 + U+E0100 + 'a'
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, 'a')));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + U+1F441
  EXPECT_EQ("SRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, kEye)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + EOT
  EXPECT_EQ("SRRRR", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kHanSIP, kVS17)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + [Trail]
  EXPECT_EQ("SRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, kTrail)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + [Lead] + 'a'
  EXPECT_EQ("SRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, kLead, 'a')));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + [Lead] + [Lead]
  EXPECT_EQ("SRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, kLead, kLead)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + U+20000 + U+E0100 + [Lead] + EOT
  EXPECT_EQ("SRRRRR",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kHanSIP, kVS17, kLead)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, MuchLongerCase) {
  ForwardGraphemeBoundaryStateMachine machine;

  const UChar32 kMan = WTF::unicode::kManCharacter;
  const UChar32 kZwj = WTF::unicode::kZeroWidthJoinerCharacter;
  const UChar32 kHeart = WTF::unicode::kHeavyBlackHeartCharacter;
  const UChar32 kKiss = WTF::unicode::kKissMarkCharacter;

  // U+1F468 U+200D U+2764 U+FE0F U+200D U+1F48B U+200D U+1F468 is a valid ZWJ
  // emoji sequence.
  // SOT + | + ZWJ Emoji Sequence + 'a'
  EXPECT_EQ("SRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + U+1F441
  EXPECT_EQ("SRRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, kEye)));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + EOT
  EXPECT_EQ("SRRRRRRRRRRR",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan)));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + [Trail]
  EXPECT_EQ("SRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, kTrail)));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + [Lead] + 'a'
  EXPECT_EQ("SRRRRRRRRRRRRF", ProcessSequenceForward(
                                  &machine, AsCodePoints(),
                                  AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                               kKiss, kZwj, kMan, kLead, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + [Lead] + [Lead]
  EXPECT_EQ(
      "SRRRRRRRRRRRRF",
      ProcessSequenceForward(&machine, AsCodePoints(),
                             AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                          kKiss, kZwj, kMan, kLead, kLead)));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("SRRRRRRRRRRRR",
            ProcessSequenceForward(&machine, AsCodePoints(),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, kLead)));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // Preceding text should not affect the result except for flags.
  // 'a' + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("SRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a'),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kEye),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("SRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kLead),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kTrail),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kTrail),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [U] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RRSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kRisU),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [U] + [S] + | + ZWJ Emoji Sequence + [Lead] + EOT
  EXPECT_EQ("RRRRSRRRRRRRRRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kRisU, kRisS),
                                   AsCodePoints(kMan, kZwj, kHeart, kVS16, kZwj,
                                                kKiss, kZwj, kMan, 'a')));
  EXPECT_EQ(11, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, singleFlags) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + | + [U] + [S]
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(),
                                            AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + | + [U] + [S]
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints('a'),
                                            AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + | + [U] + [S]
  EXPECT_EQ("RSRRRF", ProcessSequenceForward(&machine, AsCodePoints(kEye),
                                             AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + | + [U] + [S]
  EXPECT_EQ("SRRRF", ProcessSequenceForward(&machine, AsCodePoints(kLead),
                                            AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + | + [U] + [S]
  EXPECT_EQ("RSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kTrail),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + | + [U] + [S]
  EXPECT_EQ("RSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kTrail),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + | + [U] + [S]
  EXPECT_EQ("RSRRRF", ProcessSequenceForward(&machine, AsCodePoints(kTrail),
                                             AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, twoFlags) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kEye, kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kLead, kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRRSRRRF", ProcessSequenceForward(
                              &machine, AsCodePoints('a', kTrail, kRisU, kRisS),
                              AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRRSRRRF",
            ProcessSequenceForward(&machine,
                                   AsCodePoints(kTrail, kTrail, kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + [U] + [S] + | + [U] + [S]
  EXPECT_EQ("RRRRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kRisU, kRisS),
                                   AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(ForwardGraphemeBoundaryStatemachineTest, oddNumberedFlags) {
  ForwardGraphemeBoundaryStateMachine machine;

  // SOT + [U] + | + [S] + [S]
  EXPECT_EQ("RRSRRRF", ProcessSequenceForward(&machine, AsCodePoints(kRisU),
                                              AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [U] + | + [S] + [S]
  EXPECT_EQ("RRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kRisU),
                                   AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + [U] + | + [S] + [S]
  EXPECT_EQ("RRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kEye, kRisU),
                                   AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + [U] + | + [S] + [S]
  EXPECT_EQ("RRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kLead, kRisU),
                                   AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + [U] + | + [S] + [S]
  EXPECT_EQ("RRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints('a', kTrail, kRisU),
                                   AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + [U] + | + [S] + [S]
  EXPECT_EQ("RRRSRRRF", ProcessSequenceForward(
                            &machine, AsCodePoints(kTrail, kTrail, kRisU),
                            AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + [U] + | + [S] + [S]
  EXPECT_EQ("RRRSRRRF",
            ProcessSequenceForward(&machine, AsCodePoints(kTrail, kRisU),
                                   AsCodePoints(kRisS, kRisU)));
  EXPECT_EQ(2, machine.FinalizeAndGetBoundaryOffset());
}

}  // namespace forward_grapheme_boundary_state_machine_test

}  // namespace blink

"""

```