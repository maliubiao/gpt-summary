Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Scan and Understanding the Purpose:**

The first step is to quickly scan the file and its name. `backspace_state_machine_test.cc` located in `blink/renderer/core/editing/state_machines`. This immediately suggests the file is a unit test for a state machine related to backspace functionality within the Blink rendering engine's editing component. The `.cc` extension confirms it's C++ code.

**2. Identifying Key Components:**

Next, look for the main structural elements:

* **Includes:**  `#include ...` directives show dependencies. `gtest/gtest.h` strongly indicates this is a Google Test based unit test file. `backspace_state_machine.h` tells us which component is being tested. `unicode.h` suggests the tests involve different Unicode characters and their properties.

* **Namespaces:**  `namespace blink` and `namespace backspace_state_machine_test` help organize the code. The nested namespace is common for test files to avoid naming conflicts.

* **Constants:**  `kNeedMoreCodeUnit` and `kFinished` are likely states of the `BackspaceStateMachine`.

* **`TEST()` Macros:** This is the core of Google Test. Each `TEST()` defines an individual test case. The first argument is the test suite name (here, `BackspaceStateMachineTest`), and the second is the test case name (e.g., `DoNothingCase`, `SingleCharacter`).

* **`EXPECT_EQ()` Macros:** These are assertions within the tests. They compare expected values with actual results of the code being tested.

* **Instantiation and Method Calls:** Inside each test, a `BackspaceStateMachine` object is created (`BackspaceStateMachine machine;`). Methods like `FeedPrecedingCodeUnit()` and `FinalizeAndGetBoundaryOffset()` are called. `Reset()` is also frequently used.

**3. Inferring Functionality from Test Names and Assertions:**

Now, go through each test case and try to understand what it's testing:

* **`DoNothingCase`:**  Calls `FinalizeAndGetBoundaryOffset()` without feeding any input. This likely tests the initial state or a scenario where backspace is performed on an empty input. The expectation of `0` suggests no characters should be deleted.

* **`SingleCharacter`:**  Feeds single characters ('a', '-', '\t', Hiragana 'A') to `FeedPrecedingCodeUnit()` and then checks the result of `FinalizeAndGetBoundaryOffset()`. The expectation of `-1` suggests deleting a single character results in an offset of -1 relative to the current position. The `kFinished` result of `FeedPrecedingCodeUnit` implies that the state machine has processed a complete unit (in this case, a single character).

* **`SurrogatePair`:** This clearly tests handling of surrogate pairs (Unicode characters represented by two 16-bit code units). The `kNeedMoreCodeUnit` state and `-2` offset for a complete surrogate pair deletion indicate the state machine needs two code units to represent such characters and deletes both. The edge cases focus on broken or unpaired surrogates.

* **`CRLF`:** Tests the handling of carriage return (`\r`) and line feed (`\n`) combinations. The expectation is that `CRLF` is treated as a single unit for backspace.

* **Subsequent Tests (`KeyCap`, `EmojiModifier`, `RegionalIndicator`, `VariationSequence`, `ZWJSequence`):** These tests follow a similar pattern. They introduce specific Unicode concepts (keycaps, emoji modifiers, regional indicators, variation sequences, ZWJ sequences) and test how the `BackspaceStateMachine` handles them. The test names and the specific Unicode code points used in `FeedPrecedingCodeUnit()` provide clues about what's being tested. The `kNeedMoreCodeUnit` and `kFinished` states, along with the expected negative offsets, are crucial for understanding the state machine's logic.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

At this point, consider how this low-level C++ code relates to higher-level web technologies:

* **HTML Editing:** When a user types in a `<textarea>` or an element with `contenteditable="true"`, the browser needs to handle backspace presses correctly. This code is part of that process.

* **Text Rendering:**  The correct deletion of complex Unicode characters (like emojis, flags) is vital for proper text rendering. CSS might influence how these characters are displayed, but the underlying logic for deleting them is handled here.

* **JavaScript Interaction:** JavaScript can manipulate the DOM and the selection within editable elements. When JavaScript triggers a backspace-like action, it will eventually interact with this kind of low-level code.

**5. Logical Reasoning and Hypothesizing Input/Output:**

For each test case, you can perform logical reasoning:

* **Input:** The sequence of characters fed to `FeedPrecedingCodeUnit()`.
* **Processing:** The internal logic of the `BackspaceStateMachine` (which we don't see directly in this test file).
* **Output:** The `FinalizeAndGetBoundaryOffset()`, which indicates how many code units should be deleted.

**Example of Hypothesis (for `SurrogatePair`):**

* **Hypothesis Input:**  A trail surrogate followed by a lead surrogate.
* **Logical Reasoning:** The state machine recognizes this as a valid surrogate pair and should mark both code units for deletion.
* **Hypothesis Output:** `FinalizeAndGetBoundaryOffset()` should return -2.

**6. Identifying User/Programming Errors:**

Consider how users or developers might encounter issues related to this code:

* **User Error:**  A user might expect a single backspace press to delete a visually combined character (like an emoji with a skin tone modifier) but find that it deletes only part of it if the logic is flawed.

* **Programming Error:**  A bug in the `BackspaceStateMachine` could lead to incorrect deletion of characters, especially complex Unicode sequences. This unit test helps prevent such errors.

**7. Tracing User Actions:**

Think about the steps a user takes to reach this code:

1. User opens a web page with an editable text area.
2. User types some text, including potentially complex characters (emojis, etc.).
3. User presses the backspace key.
4. The browser's input handling mechanism detects the backspace.
5. The browser's editing component (where this code resides) processes the backspace.
6. The `BackspaceStateMachine` is invoked to determine the boundaries of the text to be deleted.

**8. Summarization (for Part 1):**

Finally, summarize the findings. The core functionality is testing the logic of the `BackspaceStateMachine` for various character combinations, including basic characters, surrogate pairs, and more complex Unicode sequences. It ensures that backspace deletes the correct number of code units to remove a visually complete character or grapheme.

This iterative process of scanning, identifying components, inferring functionality, connecting to web technologies, reasoning, identifying errors, and tracing user actions allows for a comprehensive understanding of the purpose and significance of the given C++ test file.
这是名为 `backspace_state_machine_test.cc` 的 C++ 源代码文件，它是 Chromium Blink 引擎的一部分，专门用于测试 `BackspaceStateMachine` 类的功能。 `BackspaceStateMachine` 的目的是确定在用户按下退格键时应该删除的文本边界。

以下是该文件的功能列表：

1. **单元测试框架:** 该文件使用 Google Test 框架（通过 `#include "testing/gtest/include/gtest/gtest.h"` 引入）来编写单元测试用例。

2. **测试 BackspaceStateMachine 的各种场景:**  该文件包含了多个 `TEST` 宏定义的测试用例，每个用例旨在验证 `BackspaceStateMachine` 在不同输入字符序列下的行为是否符合预期。

3. **模拟字符输入:**  每个测试用例都会创建一个 `BackspaceStateMachine` 实例，并使用 `FeedPrecedingCodeUnit()` 方法模拟输入（通常是按下退格键前的一个或多个字符）。  `FeedPrecedingCodeUnit()` 接收一个 Unicode 码位作为输入。

4. **验证边界偏移:**  每个测试用例会调用 `FinalizeAndGetBoundaryOffset()` 方法来获取 `BackspaceStateMachine` 计算出的需要删除的字符数量（以代码单元为单位）。负值表示需要删除前面的字符。

5. **测试不同的 Unicode 字符和组合:**  该文件覆盖了多种 Unicode 字符和组合，包括：
    * **单个字符:**  例如 'a', '-', '\t', 以及日文平假名 'あ' (0x3042)。
    * **代理对 (Surrogate Pair):** 用于表示 Unicode 补充平面字符，例如 U+20BB7。
    * **CRLF (Carriage Return Line Feed):**  Windows 风格的换行符。
    * **组合字符序列:** 例如：
        * **Keycap:**  数字或符号后跟组合字符 U+20E3。
        * **Emoji Modifier:** 表情符号后跟肤色修饰符。
        * **Regional Indicator:**  用于表示国家/地区旗帜的成对字符。
        * **Variation Sequence:**  基础字符后跟变体选择符。
        * **ZWJ Sequence (Zero Width Joiner):** 用于组合多个表情符号的特殊字符。

6. **测试边缘情况:**  除了常见的字符组合外，该文件还测试了一些边缘情况，例如：
    * **未配对的代理对:**  单独的前导或后尾代理项。
    * **不完整的组合字符序列:**  例如，只有 Keycap 组合字符而没有前面的数字。
    * **在序列的开头 (Sot - Start of Text) 就开始退格。**

7. **状态管理验证:**  测试用例通过断言 `FeedPrecedingCodeUnit()` 的返回值 (`kNeedMoreCodeUnit` 或 `kFinished`) 来验证状态机的内部状态转换是否正确。 `kNeedMoreCodeUnit` 表示需要更多的字符才能确定边界， `kFinished` 表示已经确定了边界。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它所测试的功能直接影响这些技术在 Web 浏览器中的行为：

* **HTML `<textarea>` 和 `contenteditable` 属性:** 当用户在可编辑的 HTML 元素中按下退格键时，Blink 引擎会调用 `BackspaceStateMachine` 来确定要删除的文本范围。这确保了用户在编辑器中按下退格键的行为符合预期，例如正确删除整个表情符号或组合字符。

    **举例说明:**
    假设 HTML 中有一个 `<textarea>` 元素，用户输入了 "👨‍👩‍👧‍👦" (一个使用 ZWJ 组合的家庭表情符号)。当用户按下退格键时，`BackspaceStateMachine` 应该能够识别这是一个单一的视觉单元，并返回一个偏移量，指示需要删除组成这个表情符号的所有代码单元，而不是只删除一部分，从而保证用户体验。

* **JavaScript 文本操作:** JavaScript 可以通过 DOM API 修改文本内容。理解 `BackspaceStateMachine` 的工作原理有助于开发者在使用 JavaScript 进行文本编辑时处理复杂的 Unicode 字符。

    **举例说明:**
    一个 JavaScript 富文本编辑器可能会模拟退格键的行为。理解不同 Unicode 组合的边界对于正确实现删除逻辑至关重要。例如，如果 JavaScript 代码错误地只删除了 Emoji Modifier 而保留了基础表情符号，就会导致显示错误。 `BackspaceStateMachine` 的测试确保了 Blink 引擎自身能够正确处理这些情况，为 JavaScript 提供了一个可靠的基础。

* **CSS 文本渲染:**  虽然 CSS 主要负责文本的样式和布局，但它依赖于浏览器内核（如 Blink）正确地处理和分割文本内容。`BackspaceStateMachine` 确保了文本删除操作不会破坏字符的完整性，从而间接地影响 CSS 渲染的正确性。

    **举例说明:**
    如果 `BackspaceStateMachine` 在删除一个 Regional Indicator 旗帜表情符号时只删除了一个代码单元，那么 CSS 渲染可能会显示一个错误的字符或者乱码。该测试确保了 `BackspaceStateMachine` 正确地将一对 Regional Indicator 识别为一个整体进行删除。

**逻辑推理、假设输入与输出:**

以下是一些测试用例的逻辑推理和假设输入输出示例：

* **假设输入:** 用户在输入 "a" 之后按下退格键。
    * **`FeedPrecedingCodeUnit('a')`** 会被调用。
    * `BackspaceStateMachine` 识别到这是一个单字符。
    * **预期输出:** `FinalizeAndGetBoundaryOffset()` 返回 -1，表示需要删除前一个代码单元。

* **假设输入:** 用户在输入 "👨‍👩‍👧‍👦" (由多个代码单元组成的 ZWJ 序列) 之后按下退格键。
    * `FeedPrecedingCodeUnit()` 会按相反的顺序接收组成该表情符号的多个代码单元和 ZWJ 字符。
    * `BackspaceStateMachine` 会识别这是一个完整的 ZWJ 序列。
    * **预期输出:** `FinalizeAndGetBoundaryOffset()` 返回一个负数，其绝对值等于组成该表情符号的**所有**代码单元的数量。

* **假设输入:** 用户在输入一个前导代理项 (Lead Surrogate) 后按下退格键。
    * **`FeedPrecedingCodeUnit(kLeadSurrogate)`** 会被调用。
    * `BackspaceStateMachine` 识别到这是一个不完整的代理对。
    * **预期输出:** `FinalizeAndGetBoundaryOffset()` 返回 -1，表示只删除这个不完整的前导代理项。

**用户或编程常见的使用错误:**

* **用户错误:** 用户可能会错误地认为退格键总是删除一个“字符”，但实际上对于复杂的 Unicode 字符，一个视觉上的“字符”可能由多个代码单元组成。`BackspaceStateMachine` 的作用就是确保在这种情况下删除的是整个视觉单元。

* **编程错误:**
    * **不正确的文本删除逻辑:**  开发者在实现自定义文本编辑器时，如果没有正确处理 Unicode 组合字符，可能会导致删除不完整。
    * **假设字符都是单代码单元:** 程序员可能会错误地假设所有字符都由单个代码单元表示，从而在处理包含代理对或组合字符的文本时出现错误。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中与可编辑内容交互:** 用户在一个网页上，该网页包含 `<textarea>` 元素或设置了 `contenteditable="true"` 的元素。
2. **用户输入文本:** 用户通过键盘或其他输入方式输入文本内容，可能包含各种 Unicode 字符，包括复杂的表情符号、组合字符等。
3. **用户按下退格键:** 用户按下键盘上的退格键，试图删除之前输入的字符。
4. **浏览器事件处理:** 浏览器捕获到退格键事件。
5. **Blink 引擎处理编辑操作:** Blink 引擎的编辑模块接收到退格键事件，并需要确定要删除的文本范围。
6. **调用 `BackspaceStateMachine`:** 编辑模块会创建一个 `BackspaceStateMachine` 实例，并将光标前的一个或多个字符（以代码单元为单位）逐个通过 `FeedPrecedingCodeUnit()` 方法输入到状态机。
7. **状态机分析:** `BackspaceStateMachine` 根据预定义的规则和状态转换，分析输入的字符序列，判断是否存在需要作为一个整体删除的组合字符或序列。
8. **确定删除边界:**  `BackspaceStateMachine` 通过 `FinalizeAndGetBoundaryOffset()` 方法返回需要删除的代码单元数量。
9. **执行删除操作:** Blink 引擎的编辑模块根据 `BackspaceStateMachine` 返回的偏移量，从文档模型中删除相应的文本。
10. **更新 UI:** 浏览器重新渲染页面，反映文本删除后的状态。

当开发者需要调试退格键在特定情况下的行为时，例如删除一个复杂的表情符号出现问题，他们可能会：

* **设置断点:** 在 `BackspaceStateMachine::FeedPrecedingCodeUnit()` 或 `BackspaceStateMachine::FinalizeAndGetBoundaryOffset()` 等关键方法中设置断点。
* **单步执行:**  模拟用户的输入和退格操作，观察状态机的状态变化和边界偏移的计算过程。
* **检查输入字符:** 确认传递给 `FeedPrecedingCodeUnit()` 的字符码位是否正确。
* **分析状态转换:**  理解状态机在接收不同字符时的状态转换逻辑。

**归纳一下它的功能 (第 1 部分):**

该文件是 `BackspaceStateMachine` 类的单元测试套件，旨在全面测试该类在处理各种 Unicode 字符和组合时的退格行为。它通过模拟字符输入并验证计算出的删除边界偏移量，确保 `BackspaceStateMachine` 能够正确识别和删除逻辑上的字符单元，包括单字符、代理对、组合字符序列（如 Keycap、Emoji Modifier、Regional Indicator、Variation Sequence 和 ZWJ Sequence）以及相关的边缘情况。这些测试对于保证 Web 浏览器在处理用户退格操作时的文本一致性和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/state_machines/backspace_state_machine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/state_machines/backspace_state_machine.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

namespace backspace_state_machine_test {

const TextSegmentationMachineState kNeedMoreCodeUnit =
    TextSegmentationMachineState::kNeedMoreCodeUnit;
const TextSegmentationMachineState kFinished =
    TextSegmentationMachineState::kFinished;

TEST(BackspaceStateMachineTest, DoNothingCase) {
  BackspaceStateMachine machine;
  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(0, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, SingleCharacter) {
  BackspaceStateMachine machine;
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('-'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('\t'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  // U+3042 HIRAGANA LETTER A.
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(0x3042));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, SurrogatePair) {
  BackspaceStateMachine machine;

  // U+20BB7 is \uD83D\uDDFA in UTF-16.
  const UChar kLeadSurrogate = 0xD842;
  const UChar kTrailSurrogate = 0xDFB7;

  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kTrailSurrogate));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kLeadSurrogate));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Edge cases
  // Unpaired trailing surrogate. Delete only broken trail surrogate.
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kTrailSurrogate));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kTrailSurrogate));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kTrailSurrogate));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kTrailSurrogate));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Unpaired leading surrogate. Delete only broken lead surrogate.
  machine.Reset();
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kLeadSurrogate));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, CRLF) {
  BackspaceStateMachine machine;

  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('\r'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit('\n'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit('\n'));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(' '));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // CR LF should be deleted at the same time.
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit('\n'));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('\r'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, KeyCap) {
  BackspaceStateMachine machine;

  const UChar kKeycap = 0x20E3;
  const UChar kVs16 = 0xFE0F;
  const UChar kNotKeycapBaseLead = 0xD83C;
  const UChar kNotKeycapBaseTrail = 0xDCCF;

  // keycapBase + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('0'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // keycapBase + VS + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('0'));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // Followings are edge cases. Remove only keycap character.
  // Not keycapBase + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not keycapBase + VS + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not keycapBase(surrogate pair) + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotKeycapBaseTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kNotKeycapBaseLead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not keycapBase(surrogate pair) + VS + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotKeycapBaseTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kNotKeycapBaseLead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + VS + keycap
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kKeycap));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, EmojiModifier) {
  BackspaceStateMachine machine;

  const UChar kEmojiModifierLead = 0xD83C;
  const UChar kEmojiModifierTrail = 0xDFFB;
  const UChar kEmojiModifierBase = 0x261D;
  const UChar kEmojiModifierBaseLead = 0xD83D;
  const UChar kEmojiModifierBaseTrail = 0xDC66;
  const UChar kNotEmojiModifierBaseLead = 0xD83C;
  const UChar kNotEmojiModifierBaseTrail = 0xDCCF;
  const UChar kVs16 = 0xFE0F;
  const UChar kOther = 'a';

  // EMOJI_MODIFIER_BASE + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierBase));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // EMOJI_MODIFIER_BASE(surrogate pairs) + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierBaseTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
          machine.FeedPrecedingCodeUnit(kEmojiModifierBaseLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // EMOJI_MODIFIER_BASE + VS + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kEmojiModifierBase));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // EMOJI_MODIFIER_BASE(surrogate pairs) + VS + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierBaseTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kEmojiModifierBaseLead));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // Followings are edge cases. Remove only emoji modifier.
  // Not EMOJI_MODIFIER_BASE + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not EMOJI_MODIFIER_BASE(surrogate pairs) + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotEmojiModifierBaseTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotEmojiModifierBaseLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not EMOJI_MODIFIER_BASE + VS + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not EMOJI_MODIFIER_BASE(surrogate pairs) + VS + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotEmojiModifierBaseTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotEmojiModifierBaseLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + VS + EMOJI_MODIFIER
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kEmojiModifierLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kVs16));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, RegionalIndicator) {
  BackspaceStateMachine machine;

  const UChar kRegionalIndicatorULead = 0xD83C;
  const UChar kRegionalIndicatorUTrail = 0xDDFA;
  const UChar kRegionalIndicatorSLead = 0xD83C;
  const UChar kRegionalIndicatorSTrail = 0xDDF8;
  const UChar kNotRegionalIndicatorLead = 0xD83C;
  const UChar kNotRegionalIndicatorTrail = 0xDCCF;

  // Not RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Not RI(surrogate pairs) + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorLead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Sot + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Not RI + RI + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Not RI(surrogate pairs) + RI + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorLead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Sot + RI + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // Followings are edge cases. Delete last regional indicator only.
  // Not RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not RI(surrogate pairs) + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not RI + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit('a'));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not RI(surrogate pairs) + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorTrail));
  EXPECT_EQ(kFinished,
            machine.FeedPrecedingCodeUnit(kNotRegionalIndicatorLead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + RI + RI + RI
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorSLead));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorUTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kRegionalIndicatorULead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, VariationSequencec) {
  BackspaceStateMachine machine;

  UChar vs01 = 0xFE00;
  UChar vs01_base = 0xA85E;
  UChar vs01_base_lead = 0xD802;
  UChar vs01_base_trail = 0xDEC6;

  UChar vs17_lead = 0xDB40;
  UChar vs17_trail = 0xDD00;
  UChar vs17_base = 0x3402;
  UChar vs17_base_lead = 0xD841;
  UChar vs17_base_trail = 0xDC8C;

  UChar mongolian_vs = 0x180B;
  UChar mongolian_vs_base = 0x1820;
  // Variation selectors can't be a base of variation sequence.
  UChar notvs_base = 0xFE00;
  UChar notvs_base_lead = 0xDB40;
  UChar notvs_base_trail = 0xDD01;

  // VS_BASE + VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(vs01_base));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // VS_BASE + VS(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_trail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_lead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(vs17_base));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // VS_BASE(surrogate pairs) + VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01_base_trail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(vs01_base_lead));
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-3, machine.FinalizeAndGetBoundaryOffset());

  // VS_BASE(surrogate pairs) + VS(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_trail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_lead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_base_trail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(vs17_base_lead));
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-4, machine.FinalizeAndGetBoundaryOffset());

  // mongolianVsBase + mongolianVs
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(mongolian_vs));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(mongolian_vs_base));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Followings are edge case. Delete only variation selector.
  // Not VS_BASE + VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not VS_BASE + VS(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_trail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_lead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not VS_BASE(surrogate pairs) + VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(notvs_base_trail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base_lead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not VS_BASE(surrogate pairs) + VS(surrogate pairs)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_trail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_lead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(notvs_base_trail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base_lead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Not VS_BASE + MONGOLIAN_VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(mongolian_vs));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Not VS_BASE(surrogate pairs) + MONGOLIAN_VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(mongolian_vs));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(notvs_base_trail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(notvs_base_lead));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs01));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());

  // Sot + VS(surrogate pair)
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_trail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(vs17_lead));
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-2, machine.FinalizeAndGetBoundaryOffset());

  // Sot + MONGOLIAN_VS
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(mongolian_vs));
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-1, machine.FinalizeAndGetBoundaryOffset());
}

TEST(BackspaceStateMachineTest, ZWJSequence) {
  BackspaceStateMachine machine;

  const UChar kZwj = 0x200D;
  const UChar kEyeLead = 0xD83D;
  const UChar kEyeTrail = 0xDC41;
  const UChar kLeftSpeachBubbleLead = 0xD83D;
  const UChar kLeftSpeachBubbleTrail = 0xDDE8;
  const UChar kManLead = 0xD83D;
  const UChar kManTrail = 0xDC68;
  const UChar kBoyLead = 0xD83D;
  const UChar kBoyTrail = 0xDC66;
  const UChar kHeart = 0x2764;
  const UChar kKissLead = 0xD83D;
  const UChar kKissTrail = 0xDC8B;
  const UChar kVs16 = 0xFE0F;
  const UChar kLightSkinToneLead = 0xD83C;
  const UChar kLightSkinToneTrail = 0xDFFB;
  const UChar kDarkSkinToneLead = 0xD83C;
  const UChar kDarkSkinToneTrail = 0xDFFF;
  const UChar kOther = 'a';
  const UChar kOtherLead = 0xD83C;
  const UChar kOtherTrail = 0xDCCF;

  // Followings are chosen from valid zwj sequcne.
  // See http://www.unicode.org/Public/emoji/2.0//emoji-zwj-sequences.txt

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use EYE + ZWJ + LEFT_SPEACH_BUBBLE
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // others(surrogate pairs) + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use EYE + ZWJ + LEFT_SPEACH_BUBBLE
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kOtherTrail));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOtherLead));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // Sot + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use EYE + ZWJ + LEFT_SPEACH_BUBBLE
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kLeftSpeachBubbleLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kEyeLead));
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-5, machine.FinalizeAndGetBoundaryOffset());

  // others + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI + ZWJ + ZWJ_EMOJI
  // As an example, use MAN + ZWJ + heart + ZWJ + MAN
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kHeart));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kZwj));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kFinished, machine.FeedPrecedingCodeUnit(kOther));
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());
  EXPECT_EQ(-7, machine.FinalizeAndGetBoundaryOffset());

  // others + EMOJI_MODIFIER_BASE + EMOJI_MODIFIER + ZWJ
  // + EMOJI_MODIFIER_BASE + EMOJI_MODIFIER + ZWJ + ...
  // As an example, use MAN + LIGHT_SKIN_TONE + ZWJ + heart + vs16
  // + ZWJ + kiss + ZWJ + MAN + DARK_SKIN_TONE
  machine.Reset();
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kDarkSkinToneTrail));
  EXPECT_EQ(kNeedMoreCodeUnit,
            machine.FeedPrecedingCodeUnit(kDarkSkinToneLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManTrail));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.FeedPrecedingCodeUnit(kManLead));
  EXPECT_EQ(kNeedMoreCodeUnit, machine.Fe
"""


```