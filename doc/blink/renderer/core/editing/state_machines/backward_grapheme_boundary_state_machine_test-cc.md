Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The first step is to recognize that this is a *test file*. Test files in software development are designed to verify the correctness of specific pieces of code. The filename `backward_grapheme_boundary_state_machine_test.cc` immediately tells us that it's testing a state machine related to finding grapheme boundaries when moving *backwards* in a text string.

2. **Identify the Core Component:** The core component under test is the `BackwardGraphemeBoundaryStateMachine` class. This is clearly stated in the `#include` directive and the names of the test cases.

3. **Decipher the Test Structure:**  The file uses Google Test (gtest) framework conventions. We see:
    * `#include` directives to bring in necessary headers.
    * A namespace for the tests (`backward_grapheme_boundary_state_machine_test`).
    * A test fixture class `BackwardGraphemeBoundaryStatemachineTest` inheriting from `GraphemeStateMachineTestBase`. This suggests there's a common base class for grapheme-related tests.
    * `TEST_F` macros defining individual test cases. Each test case focuses on a specific scenario.
    * `EXPECT_EQ` assertions to check if the actual output of the state machine matches the expected output.

4. **Analyze the Test Cases (Key to Functionality):**  This is the most important part. Go through each test case and try to understand what it's testing:
    * `DoNothingCase`: Checks the initial state of the machine.
    * `BrokenSurrogatePair`: Tests how the machine handles invalid Unicode surrogate pairs. This is crucial for robust text processing.
    * `BreakImmediately_BMP`, `BreakImmediately_SupplementaryPlane`: These test cases explore scenarios where a grapheme boundary *should* be found immediately before a given character or sequence. They differentiate between Basic Multilingual Plane (BMP) characters and Supplementary Plane characters (above U+FFFF).
    * `NotBreakImmediatelyBefore_BMP_BMP`, `NotBreakImmediatelyBefore_Supplementary_BMP`, `NotBreakImmediatelyBefore_BMP_Supplementary`, `NotBreakImmediatelyBefore_Supplementary_Supplementary`: These test cases focus on situations where a grapheme boundary should *not* be found immediately before a specific combination of characters. They often involve combining characters like variation selectors (VS).
    * `MuchLongerCase`: Tests a more complex sequence involving ZWJ (Zero-Width Joiner) for emoji sequences.
    * `Flags_singleFlag`, `Flags_twoFlags`, `Flags_oddNumberedRIS`: These test cases specifically target the handling of Regional Indicator Symbols (RIS) used for flags. They check how the machine identifies grapheme boundaries within flag sequences.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):** Think about how grapheme boundaries are relevant in web contexts:
    * **Cursor Movement:** When a user presses the left or right arrow keys, the browser needs to move the cursor by one grapheme, not just one code point.
    * **Text Selection:**  Selecting text should ideally happen at grapheme boundaries.
    * **Line Breaking:**  While more complex, grapheme boundaries play a role in how text wraps to the next line.
    * **JavaScript String Manipulation:** JavaScript often needs to process strings at the grapheme level (though historically it had limitations). The browser's underlying engine (like Blink) needs to handle this correctly.

6. **Infer Logic and Assumptions:** Based on the test cases, you can infer the logic the `BackwardGraphemeBoundaryStateMachine` implements:
    * **Surrogate Pair Handling:**  It needs to recognize and correctly handle both valid and invalid surrogate pairs.
    * **Combining Characters:** It must understand combining characters (like variation selectors) and not break graphemes in the middle of such sequences.
    * **ZWJ Sequences:** It needs to handle ZWJ sequences for complex emoji.
    * **Regional Indicator Symbols:** It has specific logic for recognizing pairs of RIS as a single grapheme (flags).

7. **Identify Potential User/Programming Errors:** Think about what mistakes developers or users might make that would lead to this code being relevant:
    * **Incorrect String Indexing:** Programmers might try to access characters in a string based on code point index, which can break apart graphemes.
    * **Unexpected Cursor Behavior:** Users might experience unexpected cursor jumps or selection behavior if grapheme boundaries aren't handled correctly.
    * **Problems with Emoji and Complex Characters:**  Issues displaying or processing emoji or international text could arise from incorrect grapheme handling.

8. **Trace User Actions (Debugging Clues):**  Consider how a user might interact with a webpage that would trigger this code:
    * **Typing:**  Entering text, especially with emoji or characters requiring combining sequences.
    * **Moving the Cursor:** Using arrow keys or clicking within the text.
    * **Selecting Text:** Dragging the mouse to select a portion of text.
    * **Pasting Text:** Pasting content that includes complex characters.

9. **Interpret the Output of `ProcessSequenceBackward`:** The test code uses `ProcessSequenceBackward` and the output string like "RF", "RRF", etc. Recognize that "R" likely means "Reached Boundary" and "F" means "Finalized". The number of "R"s might correspond to how many code points were processed. The negative offset in `FinalizeAndGetBoundaryOffset()` indicates the position of the boundary *relative to the end* of the processed sequence.

10. **Iterative Refinement:** As you go through the analysis, you might need to revisit earlier steps. For example, understanding a later test case might provide more context for an earlier one.

By following these steps, you can systematically analyze a C++ test file like this and understand its purpose, its relation to web technologies, and its implications for users and developers.
这个C++源代码文件 `backward_grapheme_boundary_state_machine_test.cc` 是 Chromium Blink 引擎中用于测试 `BackwardGraphemeBoundaryStateMachine` 类的单元测试。 这个状态机的主要功能是 **判断文本中给定位置之前最近的一个字形簇（grapheme cluster）的边界**。 换句话说，它能够从一个位置向后查找，找到构成一个完整可显示的字符单元的起始位置。

让我们更详细地分解其功能和与 Web 技术的关系：

**1. 功能：**

* **向后查找字形簇边界：**  核心功能是实现了在文本中向后移动并识别字形簇边界的逻辑。字形簇是用户感知到的一个字符单元，可能由一个或多个 Unicode 码点组成。例如，一个表情符号可能由多个码点（基本字符 + 变体选择器，或者多个表情符号通过零宽度连接符连接）组成。
* **处理复杂字符：**  测试用例覆盖了各种复杂的 Unicode 场景，包括：
    * **代理对 (Surrogate Pairs)：** 用于表示 Unicode 辅助平面字符（大于 U+FFFF 的字符）。测试了正确处理不完整或错误的代理对。
    * **基本多文种平面 (BMP) 字符：**  常见的 Unicode 字符。
    * **辅助平面字符 (Supplementary Plane)：**  例如表情符号。
    * **变体序列 (Variation Sequences)：**  例如，在基本字符后加上变体选择器 (VS16, VS17) 来指定字符的特定样式。
    * **零宽度连接符 (ZWJ)：**  用于连接多个表情符号形成新的表情符号序列。
    * **地区指示符 (Regional Indicator Symbols)：**  用于表示国旗。两个连续的地区指示符构成一个国旗表情符号。
* **状态管理：**  `BackwardGraphemeBoundaryStateMachine` 内部维护状态，根据输入的字符逐步更新，最终确定边界位置。
* **测试驱动开发：**  这个测试文件是测试驱动开发的一个例子。通过编写各种测试用例，可以确保状态机在各种输入情况下都能正确工作。

**2. 与 JavaScript, HTML, CSS 的关系：**

这个 C++ 代码运行在浏览器引擎的底层，为 JavaScript、HTML 和 CSS 中处理文本的功能提供基础支持。虽然 JavaScript 等上层语言通常提供了处理字符串的方法，但浏览器引擎需要在底层实现字形簇的正确识别，才能保证上层 API 的行为符合预期。

* **JavaScript：**
    * **光标移动：** 当 JavaScript 代码控制文本输入框的光标移动时（例如，用户按下方向键），浏览器引擎会使用类似这样的状态机来确定光标应该移动多少距离，以保证一次移动一个完整的字形簇。
        * **假设输入：**  用户在一个包含 "👩‍👩‍👧‍👦" (一个由多个 Unicode 码点组成的家庭表情符号) 的文本框中，光标位于这个表情符号的末尾。
        * **用户操作：** 用户按下左方向键一次。
        * **`BackwardGraphemeBoundaryStateMachine` 的作用：**  状态机会向后查找，识别出整个 "👩‍👩‍👧‍👦" 是一个字形簇，因此光标会移动到这个表情符号的开头。
    * **文本选择：**  当用户使用鼠标或键盘选择文本时，浏览器需要以字形簇为单位进行选择，避免选中半个表情符号或变体序列。
        * **假设输入：** HTML 中有一段文本 "你好 world 🧑‍💻"。
        * **用户操作：** 用户从 "d" 开始向左拖动鼠标选择到 "好"。
        * **`BackwardGraphemeBoundaryStateMachine` 的作用：** 当向后扩展选择范围时，状态机会确保选择的边界在 "🧑‍💻" (程序员表情符号) 的开头，而不是中间。
    * **字符串长度和迭代：** 虽然 JavaScript 的字符串 length 属性返回的是 UTF-16 代码单元的数量，但在某些需要感知用户字符的场景下，浏览器引擎会使用类似机制来处理。
* **HTML：**
    * **文本渲染：** 浏览器在渲染 HTML 文本时，需要正确地将 Unicode 码点组合成用户可见的字符。字形簇的识别是正确渲染的基础。
    * **`contenteditable` 属性：** 当使用 `contenteditable` 让 HTML 元素可编辑时，浏览器需要处理用户的输入和光标移动，这依赖于底层的字形簇处理。
* **CSS：**
    * **文本换行：** 虽然文本换行的规则很复杂，但浏览器在决定哪里换行时，会考虑字形簇的边界，避免在字形簇的中间换行。
    * **文本相关的 CSS 属性：** 一些 CSS 属性可能涉及到文本的处理，底层的字形簇处理会影响这些属性的效果。

**3. 逻辑推理、假设输入与输出：**

测试用例中已经包含了大量的假设输入和期望输出。让我们以其中一个为例：

```c++
TEST_F(BackwardGraphemeBoundaryStatemachineTest, NotBreakImmediatelyBefore_BMP_BMP) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+231A + U+FE0F
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine,
                                           AsCodePoints('a', kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  // ... other cases ...
}
```

* **假设输入：** 字符序列 'a' (U+0061), ⌚ (U+231A, 手表表情符号), ︎ (U+FE0F, 变体选择器-16)。
* **`ProcessSequenceBackward` 的作用：**  这个函数模拟向状态机逐个输入字符（从后向前）。 "R" 可能表示状态机处理了一个字符并找到了一个潜在的边界， "F" 表示处理结束。  "RRF" 表示处理了三个字符。
* **`FinalizeAndGetBoundaryOffset()` 的作用：**  这个函数返回最终确定的边界相对于输入序列末尾的偏移量。 `-2` 表示边界在倒数第二个字符之前，也就是 'a' 和 ⌚ 之间。
* **逻辑推理：**  变体选择器 (U+FE0F) 通常会与其前面的基本字符组合成一个字形簇。因此，从后向前查找时，应该将 "⌚︎" 看作一个整体。这个测试用例验证了状态机在这种情况下不会在 'a' 和 "⌚︎" 之间立即断开，而是将边界放在 'a' 之前。

**4. 用户或编程常见的使用错误：**

* **编程错误：**
    * **按 Unicode 码点分割字符串：** 开发者如果错误地认为一个字符对应一个 Unicode 码点，并按码点数量分割字符串，可能会破坏字形簇，导致显示错误或功能异常。例如，将 "👩‍👩‍👧‍👦" 分割成多个单独的码点。
    * **不理解变体序列或 ZWJ 的作用：**  在处理文本时，如果没有考虑到变体序列或 ZWJ 对字形簇的影响，可能会导致错误的字符计数或处理。
* **用户操作错误（间接）：**
    * **输入包含复杂字符的文本：** 用户可能会输入包含表情符号、国旗等复杂字符的文本。如果底层的字形簇处理不正确，可能会导致光标跳跃不正常、选择错误等问题，用户会感知到软件的 bug。

**5. 用户操作如何一步步到达这里，作为调试线索：**

假设用户在使用一个网页上的文本编辑器时遇到了光标移动的 bug，当在包含 emoji 的文本中向左移动光标时，光标不是一次移动一个完整的 emoji，而是移动了半个。

1. **用户在文本编辑器中输入文本：** 例如 "Hello 😊 world"。
2. **用户将光标移动到 "world" 的开头。**
3. **用户按下左方向键。**
4. **浏览器引擎需要决定光标应该移动到哪里。** 这时会调用底层的字形簇边界查找机制。
5. **`BackwardGraphemeBoundaryStateMachine` 被调用，从当前光标位置向后查找字形簇边界。**
6. **如果状态机实现有 bug，可能无法正确识别 "😊" 是一个字形簇，而是在其内部的某个码点处停止，导致光标移动不符合预期。**

作为调试线索，开发者可能会：

* **查看浏览器控制台的错误信息。**  虽然这个特定的状态机错误可能不会直接抛出 JavaScript 错误，但相关的文本处理逻辑错误可能会。
* **使用浏览器的开发者工具，查看文本节点的结构和属性。**
* **在 Chromium 源代码中搜索与光标移动和字形簇处理相关的代码。** 发现 `BackwardGraphemeBoundaryStateMachine` 相关的代码和测试。
* **运行相关的单元测试，例如 `backward_grapheme_boundary_state_machine_test.cc` 中的测试用例，来验证状态机的行为。**  如果测试失败，说明状态机的实现存在问题。
* **使用断点调试状态机的代码，逐步跟踪字符的处理过程，找出状态转移的错误。**

总而言之，`backward_grapheme_boundary_state_machine_test.cc` 这个文件通过各种测试用例，确保了 Blink 引擎能够正确地识别文本中的字形簇边界，这对于在 Web 技术中处理包含复杂 Unicode 字符的文本至关重要，直接影响着用户的编辑体验和文本渲染的正确性。

### 提示词
```
这是目录为blink/renderer/core/editing/state_machines/backward_grapheme_boundary_state_machine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/state_machines/backward_grapheme_boundary_state_machine.h"

#include "third_party/blink/renderer/core/editing/state_machines/state_machine_test_util.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace backward_grapheme_boundary_state_machine_test {

// Notations:
// SOT indicates start of text.
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
// U+1F1F8 is REGIONAL INDICATOR SYMBOL LETTER S
const UChar32 kRisU = 0x1F1FA;
const UChar32 kRisS = 0x1F1F8;

class BackwardGraphemeBoundaryStatemachineTest
    : public GraphemeStateMachineTestBase {
 public:
  BackwardGraphemeBoundaryStatemachineTest(
      const BackwardGraphemeBoundaryStatemachineTest&) = delete;
  BackwardGraphemeBoundaryStatemachineTest& operator=(
      const BackwardGraphemeBoundaryStatemachineTest&) = delete;

 protected:
  BackwardGraphemeBoundaryStatemachineTest() = default;
  ~BackwardGraphemeBoundaryStatemachineTest() override = default;
};

TEST_F(BackwardGraphemeBoundaryStatemachineTest, DoNothingCase) {
  BackwardGraphemeBoundaryStateMachine machine;

  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, BrokenSurrogatePair) {
  BackwardGraphemeBoundaryStateMachine machine;

  // [Lead]
  EXPECT_EQ("F", ProcessSequenceBackward(&machine, AsCodePoints(kLead)));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail]
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints('a', kTrail)));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail]
  EXPECT_EQ("RF",
            ProcessSequenceBackward(&machine, AsCodePoints(kTrail, kTrail)));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail]
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints(kTrail)));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, BreakImmediately_BMP) {
  BackwardGraphemeBoundaryStateMachine machine;

  // U+0000 + U+0000
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints(0, 0)));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + 'a'
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints('a', 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + 'a'
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine, AsCodePoints(kEye, 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + 'a'
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints('a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Broken surrogates.
  // [Lead] + 'a'
  EXPECT_EQ("RF", ProcessSequenceBackward(&machine, AsCodePoints(kLead, 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + 'a'
  EXPECT_EQ("RRF",
            ProcessSequenceBackward(&machine, AsCodePoints('a', kTrail, 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + 'a'
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine,
                                           AsCodePoints(kTrail, kTrail, 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + 'a'
  EXPECT_EQ("RRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kTrail, 'a')));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest,
       BreakImmediately_SupplementaryPlane) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+1F441
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine, AsCodePoints('a', kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + U+1F441
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kEye, kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + U+1F441
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine, AsCodePoints(kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Broken surrogates.
  // [Lead] + U+1F441
  EXPECT_EQ("RRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kLead, kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + U+1F441
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints('a', kTrail, kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + U+1F441
  EXPECT_EQ("RRRF", ProcessSequenceBackward(
                        &machine, AsCodePoints(kTrail, kTrail, kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + U+1F441
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kTrail, kEye)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyBefore_BMP_BMP) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+231A + U+FE0F
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine,
                                           AsCodePoints('a', kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + U+231A + U+FE0F
  EXPECT_EQ("RRRF", ProcessSequenceBackward(&machine,
                                            AsCodePoints(kEye, kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + U+231A + U+FE0F
  EXPECT_EQ("RRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + U+231A + U+FE0F
  EXPECT_EQ("RRF", ProcessSequenceBackward(&machine,
                                           AsCodePoints(kLead, kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + U+231A + U+FE0F
  EXPECT_EQ("RRRF", ProcessSequenceBackward(
                        &machine, AsCodePoints('a', kTrail, kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + U+231A + U+FE0F
  EXPECT_EQ("RRRF", ProcessSequenceBackward(
                        &machine, AsCodePoints(kTrail, kTrail, kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + U+231A + U+FE0F
  EXPECT_EQ("RRRF", ProcessSequenceBackward(
                        &machine, AsCodePoints(kTrail, kWatch, kVS16)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyBefore_Supplementary_BMP) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+1F441 + U+FE0F
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints('a', kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + U+1F441 + U+FE0F
  EXPECT_EQ("RRRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kEye, kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + U+1F441 + U+FE0F
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + U+1F441 + U+FE0F
  EXPECT_EQ("RRRF", ProcessSequenceBackward(&machine,
                                            AsCodePoints(kLead, kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + U+1F441 + U+FE0F
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints('a', kTrail, kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + U+1F441 + U+FE0F
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kTrail, kTrail, kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + U+1F441 + U+FE0F
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kTrail, kEye, kVS16)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyBefore_BMP_Supplementary) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+845B + U+E0100
  EXPECT_EQ("RRRF", ProcessSequenceBackward(&machine,
                                            AsCodePoints('a', kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + U+845B + U+E0100
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kEye, kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + U+845B + U+E0100
  EXPECT_EQ("RRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + U+845B + U+E0100
  EXPECT_EQ("RRRF", ProcessSequenceBackward(
                        &machine, AsCodePoints(kLead, kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + U+845B + U+E0100
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints('a', kTrail, kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + U+845B + U+E0100
  EXPECT_EQ("RRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kTrail, kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + U+845B + U+E0100
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kTrail, kHanBMP, kVS17)));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest,
       NotBreakImmediatelyBefore_Supplementary_Supplementary) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + U+20000 + U+E0100
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints('a', kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + U+20000 + U+E0100
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints(kEye, kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + U+20000 + U+E0100
  EXPECT_EQ("RRRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + U+20000 + U+E0100
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kLead, kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + U+20000 + U+E0100
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints('a', kTrail, kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + U+20000 + U+E0100
  EXPECT_EQ("RRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kTrail, kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + U+20000 + U+E0100
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints(kTrail, kHanSIP, kVS17)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, MuchLongerCase) {
  const UChar32 kMan = WTF::unicode::kManCharacter;
  const UChar32 kZwj = WTF::unicode::kZeroWidthJoinerCharacter;
  const UChar32 kHeart = WTF::unicode::kHeavyBlackHeartCharacter;
  const UChar32 kKiss = WTF::unicode::kKissMarkCharacter;

  BackwardGraphemeBoundaryStateMachine machine;

  // U+1F468 U+200D U+2764 U+FE0F U+200D U+1F48B U+200D U+1F468 is a valid ZWJ
  // emoji sequence.
  // 'a' + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints('a', kMan, kZwj, kHeart, kVS16, kZwj,
                                       kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kEye, kMan, kZwj, kHeart, kVS16, kZwj,
                                       kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + ZWJ Emoji Sequence
  EXPECT_EQ(
      "RRRRRRRRRRRF",
      ProcessSequenceBackward(&machine, AsCodePoints(kMan, kZwj, kHeart, kVS16,
                                                     kZwj, kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kLead, kMan, kZwj, kHeart, kVS16, kZwj,
                                       kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints('a', kTrail, kMan, kZwj, kHeart, kVS16,
                                       kZwj, kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kTrail, kMan, kZwj, kHeart,
                                       kVS16, kZwj, kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + ZWJ Emoji Sequence
  EXPECT_EQ("RRRRRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kMan, kZwj, kHeart, kVS16, kZwj,
                                       kKiss, kZwj, kMan)));
  EXPECT_EQ(-11, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, Flags_singleFlag) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + [U] + [S]
  EXPECT_EQ("RRRRF",
            ProcessSequenceBackward(&machine, AsCodePoints('a', kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + [U] + [S]
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints(kEye, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [U] + [S]
  EXPECT_EQ("RRRRF",
            ProcessSequenceBackward(&machine, AsCodePoints(kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + [U] + [S]
  EXPECT_EQ("RRRRF", ProcessSequenceBackward(
                         &machine, AsCodePoints(kLead, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + [U] + [S]
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints('a', kTrail, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + [U] + [S]
  EXPECT_EQ("RRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kTrail, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + [U] + [S]
  EXPECT_EQ("RRRRRF", ProcessSequenceBackward(
                          &machine, AsCodePoints(kTrail, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, Flags_twoFlags) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints('a', kRisU, kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kEye, kRisU, kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRF",
            ProcessSequenceBackward(&machine,
                                    AsCodePoints(kRisU, kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kLead, kRisU, kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRRF", ProcessSequenceBackward(
                              &machine, AsCodePoints('a', kTrail, kRisU, kRisS,
                                                     kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRRF", ProcessSequenceBackward(
                              &machine, AsCodePoints(kTrail, kTrail, kRisU,
                                                     kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + [U] + [S] + [U] + [S]
  EXPECT_EQ("RRRRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kRisU, kRisS, kRisU, kRisS)));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
}

TEST_F(BackwardGraphemeBoundaryStatemachineTest, Flags_oddNumberedRIS) {
  BackwardGraphemeBoundaryStateMachine machine;

  // 'a' + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRF", ProcessSequenceBackward(
                           &machine, AsCodePoints('a', kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // U+1F441 + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRRF", ProcessSequenceBackward(
                            &machine, AsCodePoints(kEye, kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRF", ProcessSequenceBackward(
                           &machine, AsCodePoints(kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // [Lead] + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRF", ProcessSequenceBackward(
                           &machine, AsCodePoints(kLead, kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // 'a' + [Trail] + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints('a', kTrail, kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // [Trail] + [Trail] + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRRF",
            ProcessSequenceBackward(
                &machine, AsCodePoints(kTrail, kTrail, kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // SOT + [Trail] + [U] + [S] + [U]
  EXPECT_EQ("RRRRRRRF",
            ProcessSequenceBackward(&machine,
                                    AsCodePoints(kTrail, kRisU, kRisS, kRisU)));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

}  // namespace backward_grapheme_boundary_state_machine_test

}  // namespace blink
```