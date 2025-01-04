Response:
Let's break down the thought process for analyzing this `BackspaceStateMachine` code.

1. **Understand the Core Purpose:** The file name `backspace_state_machine.cc` and the class name `BackspaceStateMachine` immediately suggest its purpose: to handle the logic of the backspace key press within a text editing context. The "state machine" part hints at a sequential, rule-based approach to determine what should be deleted.

2. **High-Level Functionality Identification:**  Read the initial comments and the definition of states (`FOR_EACH_BACKSPACE_STATE_MACHINE_STATE`). This gives a good overview of the different scenarios the state machine handles. Key things to notice:
    * Handling of line feeds (`kBeforeLF`)
    * Handling of special characters like keycaps (`kBeforeKeycap`), variation selectors (`kBeforeVS`), emoji modifiers (`kBeforeEmojiModifier`), and ZWJ (Zero Width Joiner) characters (`kBeforeZWJ`).
    * Handling of Regional Indicator Symbols (RIS) used for flag emojis (`kOddNumberedRIS`, `kEvenNumberedRIS`).
    * The concept of states (`kStart`, `kFinished`, and intermediate states).

3. **Detailed Examination of `FeedPrecedingCodeUnit`:** This is the heart of the logic. Go through each state and its corresponding actions:
    * **`kStart`:**  Determine the initial number of code units to delete based on the first character. Branch to different states based on the character type.
    * **`kBeforeLF`:** Check for a preceding carriage return (`\r`) to handle Windows-style line endings.
    * **`kBeforeKeycap`:** Look for a preceding variation selector or an emoji keycap base.
    * **`kBeforeVSAndKeycap`:**  Handle the case of a variation selector followed by an emoji keycap base.
    * **`kBeforeEmojiModifier`:** Similar to `kBeforeKeycap`, but for emoji modifiers.
    * **`kBeforeVSAndEmojiModifier`:** Similar to `kBeforeVSAndKeycap`, but for emoji modifiers.
    * **`kBeforeVS`:** Handle the case of a variation selector followed by an emoji or other characters.
    * **`kBeforeZWJEmoji`:** Check for a preceding ZWJ.
    * **`kBeforeZWJ`:** Look for a preceding emoji or variation selector.
    * **`kBeforeVSAndZWJ`:** Handle the case of a variation selector followed by a ZWJ and an emoji.
    * **`kOddNumberedRIS` and `kEvenNumberedRIS`:** Handle pairs of regional indicators.

4. **Analyze Other Functions:**
    * **`TellEndOfPrecedingText`:**  Handles the case where the input ends mid-character (e.g., an unpaired surrogate).
    * **`FeedFollowingCodeUnit`:**  Asserts that it should not be called, indicating this state machine only looks backward. This is important for understanding its scope.
    * **`FinalizeAndGetBoundaryOffset`:**  Returns the negative of the number of code units to delete, representing the offset change.
    * **`Reset`:** Resets the state machine to its initial state.
    * **`MoveToNextState` and `Finish`:** Helper functions for state transitions.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  Imagine a JavaScript text editor implementation. When the backspace key is pressed, the JavaScript code would need to figure out what to delete. This `BackspaceStateMachine` provides the *logic* for that decision. The JavaScript would interact with the DOM and might use this logic directly or indirectly.
    * **HTML:**  The text being edited is within HTML elements (e.g., `<textarea>`, `<div>` with `contenteditable`). The backspace operation modifies the content of these elements.
    * **CSS:** CSS affects the *appearance* of the text but doesn't directly dictate how backspace should behave. However, CSS properties like `direction: rtl;` (right-to-left) could influence how the backspace key *feels* to the user, although the underlying logic of this state machine might not change drastically.

6. **Identify Potential Issues/User Errors:** Think about situations where the backspace behavior might be unexpected or lead to errors:
    * Deleting parts of composed characters (like emojis or accented characters). The state machine is designed to prevent this.
    * Handling of unpaired surrogate characters.
    * Issues with complex scripts or character combinations.

7. **Trace User Interaction:**  Think about the sequence of events leading to the execution of this code:
    * User focuses on a text input field.
    * User types some text.
    * User presses the backspace key.
    * The browser's input handling system detects the key press.
    * The browser's editing engine (Blink in this case) uses the `BackspaceStateMachine` to determine how to modify the text content in the DOM.

8. **Construct Examples and Scenarios:** Create specific examples to illustrate the behavior of the state machine in different situations. This helps solidify understanding and identify potential edge cases.

9. **Review and Refine:**  Go back through the analysis and make sure everything is consistent and accurate. Check for any missing points or areas that need further clarification. For example, double-checking the Unicode properties used in the code (`UCHAR_VARIATION_SELECTOR`, `UCHAR_REGIONAL_INDICATOR`, etc.) ensures accurate interpretation.

This structured approach helps to systematically analyze the code and extract its key functionalities, relationships to other technologies, and potential implications.
这个 `backspace_state_machine.cc` 文件定义了一个名为 `BackspaceStateMachine` 的类，它是 Chromium Blink 引擎中负责处理退格键（Backspace）操作时文本删除逻辑的状态机。它的主要功能是**精确地确定在按下退格键时应该删除多少个代码单元（code units）**，尤其是在处理复杂的 Unicode 字符（如表情符号、组合字符等）时。

以下是该文件的功能分解和与其他 Web 技术的关系：

**核心功能:**

1. **状态管理:**  `BackspaceStateMachine` 是一个状态机，它通过不同的状态来跟踪当前退格操作的上下文。 这些状态定义了在遇到不同类型的字符时应该如何处理。 状态包括：
   - `kStart`: 初始状态。
   - `kBeforeLF`: 光标位于换行符之前。
   - `kBeforeKeycap`: 光标位于 keycap 字符（如 U+20E3 combining enclosing keycap）之前。
   - `kBeforeVSAndKeycap`: 光标位于变体选择器（Variation Selector）和 keycap 字符之前。
   - `kBeforeEmojiModifier`: 光标位于表情符号修饰符（Emoji Modifier）之前。
   - `kBeforeVSAndEmojiModifier`: 光标位于变体选择器和表情符号修饰符之前。
   - `kBeforeVS`: 光标位于变体选择器之前。
   - `kBeforeZWJEmoji`: 光标位于 ZWJ (Zero Width Joiner) 连接的表情符号序列之前。
   - `kBeforeZWJ`: 光标位于 ZWJ 字符之前。
   - `kBeforeVSAndZWJ`: 光标位于变体选择器和 ZWJ 字符之前。
   - `kOddNumberedRIS`: 从开头算起有奇数个区域指示符 (Regional Indicator Symbol)。
   - `kEvenNumberedRIS`: 从开头算起有偶数个区域指示符。
   - `kFinished`: 状态机完成。

2. **代码单元处理:**  该状态机逐个接收前导代码单元 (`FeedPrecedingCodeUnit`)，并根据当前状态和接收到的代码单元，判断需要删除的代码单元数量 (`code_units_to_be_deleted_`)。

3. **复杂字符处理:** 它的主要目的是正确处理需要多个代码单元表示的 Unicode 字符，例如：
   - **代理对 (Surrogate Pairs):**  处理 UTF-16 编码中需要两个代码单元表示的字符。
   - **组合字符:**  处理由基本字符和组合标记组成的字符，例如带音调的字母。
   - **表情符号:**  处理各种表情符号，包括由多个代码点组成的表情符号序列（例如，由基本表情符号、变体选择器、修饰符、ZWJ 等组成的复杂表情符号）。
   - **Keycap 表情符号:** 处理由基本字符后跟组合 keycap 字符形成的表情符号（如 "1️⃣"）。
   - **带有变体选择器的字符:**  处理带有变体选择器的字符，这些选择器可以改变字符的显示方式。
   - **ZWJ 表情符号序列:**  处理使用零宽度连接符 (ZWJ) 连接的多个表情符号，形成新的表情符号。
   - **区域指示符:** 处理用于表示国旗的成对区域指示符。

4. **确定删除边界:**  最终，`FinalizeAndGetBoundaryOffset` 方法返回一个负数，表示退格键操作应该将光标向后移动的偏移量（即需要删除的代码单元数量的负值）。

**与 JavaScript, HTML, CSS 的关系:**

此状态机是浏览器渲染引擎内部的组件，不直接与 JavaScript、HTML 或 CSS 交互。 然而，它的功能对于这些技术构建的 Web 应用的文本编辑功能至关重要：

* **JavaScript:** 当用户在 `contenteditable` 的 HTML 元素或 `<textarea>` 中按下退格键时，JavaScript 代码可能会触发相应的事件。 浏览器内部的编辑逻辑（包括这个状态机）会处理删除操作，然后更新 DOM 结构，JavaScript 可以监听这些 DOM 变化或通过 Selection API 获取光标位置的变化。
   * **举例:** 一个富文本编辑器可能使用 JavaScript 监听 `keydown` 事件，当检测到退格键时，浏览器的内部机制会调用 `BackspaceStateMachine` 来确定要删除的字符。编辑器可以使用 JavaScript 来进一步处理编辑后的内容或更新用户界面。

* **HTML:**  HTML 提供了用于文本输入的元素（如 `<textarea>` 和具有 `contenteditable` 属性的元素）。 当用户在这些元素中输入或删除文本时，浏览器会使用底层的编辑逻辑来处理这些操作，`BackspaceStateMachine` 是其中的一部分。
   * **举例:**  在一个 `<textarea>` 元素中输入 "👨‍👩‍👧‍👦"，这是一个由多个 Unicode 代码点组成的家庭表情符号。 当光标位于该表情符号之后并按下退格键时，`BackspaceStateMachine` 会识别这是一个 ZWJ 序列，并确定需要删除多个代码单元才能完整删除这个表情符号，保证不会只删除部分字符导致显示异常。

* **CSS:** CSS 负责文本的样式和布局，不直接参与退格键的逻辑。 然而，CSS 的渲染结果会影响光标的位置和文本的显示，这会间接地影响用户对退格键行为的感知。
   * **举例:**  CSS 的 `direction: rtl;` 属性可以将文本方向设置为从右到左。 虽然 CSS 改变了文本的显示方向，但 `BackspaceStateMachine` 的逻辑仍然保持一致，确保在从右到左的文本中按下退格键时，仍然按照正确的 Unicode 边界删除字符。

**逻辑推理举例 (假设输入与输出):**

假设当前光标位于文本 "你好👩‍👩‍👧‍👦" 的 "‍👦" 之后（"‍👦" 是家庭表情符号的一部分，包含 ZWJ）。

**输入:**  光标位于 "你好👩‍👩‍👧‍👦" 的末尾，状态机接收前导代码单元。

**状态机处理步骤:**

1. **初始状态 (kStart):** 接收到 "👦" 的最后一个代码单元。
2. **移动到 kBeforeEmojiModifier (假设):**  识别出这是一个表情符号修饰符。
3. **移动到 kBeforeZWJ:** 接收到 ZWJ 字符。
4. **移动到 kBeforeZWJEmoji:** 接收到前面的表情符号 "👧"。
5. **继续回溯:**  状态机继续接收 "👩‍" 的代码单元，最终确定需要删除整个 "👩‍👩‍👧‍👦" 表情符号。

**输出:** `FinalizeAndGetBoundaryOffset` 返回的值将是负的，其绝对值等于 "👩‍👩‍👧‍👦" 这个表情符号所占的代码单元数。

**用户或编程常见的使用错误:**

* **JavaScript 中手动删除字符的错误处理:**  如果开发者使用 JavaScript 手动操作 DOM 来删除字符，而没有考虑到复杂的 Unicode 字符，可能会导致删除不完整，破坏字符的完整性。 例如，使用 `string.slice()` 或类似方法按单个 JavaScript 字符（并非总是对应一个 Unicode 代码点）删除，可能会分割代理对或 ZWJ 序列。 `BackspaceStateMachine` 的存在就是为了避免这种底层错误。
   * **举例:**  如果一个 JavaScript 代码简单地删除光标前的一个 "字符"，但光标前是一个由代理对表示的生僻字，那么只删除一半的代理对会导致显示乱码。

* **不理解 Unicode 编码:** 程序员可能错误地认为一个字符总是对应一个代码单元。 在处理多语言文本或包含表情符号的文本时，这种假设会导致退格删除逻辑出现问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户聚焦输入框:** 用户点击或使用 Tab 键将焦点移动到 HTML 中的文本输入元素 (`<input>`, `<textarea>`) 或设置了 `contenteditable` 属性的元素上。

2. **用户输入文本:** 用户在输入框中输入文本，包括普通字符、特殊符号、表情符号等。

3. **用户按下退格键:** 当用户按下键盘上的退格键时，操作系统会捕获到这个按键事件。

4. **浏览器事件处理:** 浏览器接收到操作系统发送的退格键事件。

5. **Blink 引擎介入:** Blink 引擎的输入处理模块会识别这是一个文本编辑操作。

6. **调用编辑命令:** 浏览器会执行与退格键相关的编辑命令。

7. **`BackspaceStateMachine` 的初始化和调用:**  作为执行编辑命令的一部分，Blink 引擎会创建或使用现有的 `BackspaceStateMachine` 实例。

8. **`FeedPrecedingCodeUnit` 的调用:** 状态机开始向前回溯，逐个接收光标位置之前的代码单元，调用 `FeedPrecedingCodeUnit` 方法。

9. **状态转换和判断:**  状态机根据接收到的代码单元和当前状态进行状态转换，并更新需要删除的代码单元数量。

10. **`FinalizeAndGetBoundaryOffset` 的调用:**  当状态机确定了删除边界后，调用 `FinalizeAndGetBoundaryOffset` 获取偏移量。

11. **DOM 更新:** 浏览器根据计算出的偏移量，修改 DOM 结构，删除相应的文本内容。

12. **光标移动:** 光标移动到新的位置。

**调试线索:**

如果需要调试退格键行为，可以关注以下方面：

* **光标位置:**  确定按下退格键时，光标位于哪个字符或代码单元之间。
* **周围的字符:**  检查光标周围的字符，特别是它们是否是组合字符、代理对、表情符号序列等。
* **Unicode 编码:**  了解这些字符的 Unicode 编码，包括代码点和代码单元。
* **状态机的状态:**  在 Blink 引擎的调试版本中，可以跟踪 `BackspaceStateMachine` 的状态变化，了解它是如何一步步判断删除边界的。
* **事件监听:**  检查是否有 JavaScript 代码干扰了浏览器的默认退格键行为。

总而言之，`BackspaceStateMachine` 是 Blink 引擎中一个关键的组件，它确保了在按下退格键时，能够正确地删除各种复杂的 Unicode 字符，为用户提供一致且符合预期的文本编辑体验。

Prompt: 
```
这是目录为blink/renderer/core/editing/state_machines/backspace_state_machine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/state_machines/backspace_state_machine.h"

#include <array>
#include <ostream>

#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

#define FOR_EACH_BACKSPACE_STATE_MACHINE_STATE(V)                        \
  /* Initial state */                                                    \
  V(kStart)                                                              \
  /* The current offset is just before line feed. */                     \
  V(kBeforeLF)                                                           \
  /* The current offset is just before keycap. */                        \
  V(kBeforeKeycap)                                                       \
  /* The current offset is just before variation selector and keycap. */ \
  V(kBeforeVSAndKeycap)                                                  \
  /* The current offset is just before emoji modifier. */                \
  V(kBeforeEmojiModifier)                                                \
  /* The current offset is just before variation selector and emoji*/    \
  /* modifier. */                                                        \
  V(kBeforeVSAndEmojiModifier)                                           \
  /* The current offset is just before variation sequence. */            \
  V(kBeforeVS)                                                           \
  /* The current offset is just before ZWJ emoji. */                     \
  V(kBeforeZWJEmoji)                                                     \
  /* The current offset is just before ZWJ. */                           \
  V(kBeforeZWJ)                                                          \
  /* The current offset is just before variation selector and ZWJ. */    \
  V(kBeforeVSAndZWJ)                                                     \
  /* That there are odd numbered RIS from the beggining. */              \
  V(kOddNumberedRIS)                                                     \
  /* That there are even numbered RIS from the begging. */               \
  V(kEvenNumberedRIS)                                                    \
  /* This state machine has finished. */                                 \
  V(kFinished)

enum class BackspaceStateMachine::BackspaceState {
#define V(name) name,
  FOR_EACH_BACKSPACE_STATE_MACHINE_STATE(V)
#undef V
};

std::ostream& operator<<(std::ostream& os,
                         BackspaceStateMachine::BackspaceState state) {
  static const auto kTexts = std::to_array<const char*>({
#define V(name) #name,
      FOR_EACH_BACKSPACE_STATE_MACHINE_STATE(V)
#undef V
  });
  DCHECK_LT(static_cast<size_t>(state), kTexts.size())
      << "Unknown backspace value";
  return os << kTexts[static_cast<size_t>(state)];
}

BackspaceStateMachine::BackspaceStateMachine()
    : state_(BackspaceState::kStart) {}

TextSegmentationMachineState BackspaceStateMachine::FeedPrecedingCodeUnit(
    UChar code_unit) {
  DCHECK_NE(BackspaceState::kFinished, state_);
  uint32_t code_point = code_unit;
  if (U16_IS_LEAD(code_unit)) {
    if (trail_surrogate_ == 0) {
      // Unpaired lead surrogate. Aborting with deleting broken surrogate.
      ++code_units_to_be_deleted_;
      return TextSegmentationMachineState::kFinished;
    }
    code_point = U16_GET_SUPPLEMENTARY(code_unit, trail_surrogate_);
    trail_surrogate_ = 0;
  } else if (U16_IS_TRAIL(code_unit)) {
    if (trail_surrogate_ != 0) {
      // Unpaired trail surrogate. Aborting with deleting broken
      // surrogate.
      return TextSegmentationMachineState::kFinished;
    }
    trail_surrogate_ = code_unit;
    return TextSegmentationMachineState::kNeedMoreCodeUnit;
  } else {
    if (trail_surrogate_ != 0) {
      // Unpaired trail surrogate. Aborting with deleting broken
      // surrogate.
      return TextSegmentationMachineState::kFinished;
    }
  }

  switch (state_) {
    case BackspaceState::kStart:
      code_units_to_be_deleted_ = U16_LENGTH(code_point);
      if (code_point == kNewlineCharacter)
        return MoveToNextState(BackspaceState::kBeforeLF);
      if (u_hasBinaryProperty(code_point, UCHAR_VARIATION_SELECTOR))
        return MoveToNextState(BackspaceState::kBeforeVS);
      if (Character::IsRegionalIndicator(code_point))
        return MoveToNextState(BackspaceState::kOddNumberedRIS);
      if (Character::IsModifier(code_point))
        return MoveToNextState(BackspaceState::kBeforeEmojiModifier);
      if (Character::IsEmoji(code_point))
        return MoveToNextState(BackspaceState::kBeforeZWJEmoji);
      if (code_point == kCombiningEnclosingKeycapCharacter)
        return MoveToNextState(BackspaceState::kBeforeKeycap);
      return Finish();
    case BackspaceState::kBeforeLF:
      if (code_point == kCarriageReturnCharacter)
        ++code_units_to_be_deleted_;
      return Finish();
    case BackspaceState::kBeforeKeycap:
      if (u_hasBinaryProperty(code_point, UCHAR_VARIATION_SELECTOR)) {
        DCHECK_EQ(last_seen_vs_code_units_, 0);
        last_seen_vs_code_units_ = U16_LENGTH(code_point);
        return MoveToNextState(BackspaceState::kBeforeVSAndKeycap);
      }
      if (Character::IsEmojiKeycapBase(code_point))
        code_units_to_be_deleted_ += U16_LENGTH(code_point);
      return Finish();
    case BackspaceState::kBeforeVSAndKeycap:
      if (Character::IsEmojiKeycapBase(code_point)) {
        DCHECK_GT(last_seen_vs_code_units_, 0);
        DCHECK_LE(last_seen_vs_code_units_, 2);
        code_units_to_be_deleted_ +=
            last_seen_vs_code_units_ + U16_LENGTH(code_point);
      }
      return Finish();
    case BackspaceState::kBeforeEmojiModifier:
      if (u_hasBinaryProperty(code_point, UCHAR_VARIATION_SELECTOR)) {
        DCHECK_EQ(last_seen_vs_code_units_, 0);
        last_seen_vs_code_units_ = U16_LENGTH(code_point);
        return MoveToNextState(BackspaceState::kBeforeVSAndEmojiModifier);
      }
      if (Character::IsEmojiModifierBase(code_point)) {
        code_units_to_be_deleted_ += U16_LENGTH(code_point);
        return MoveToNextState(BackspaceState::kBeforeZWJEmoji);
      }
      return Finish();
    case BackspaceState::kBeforeVSAndEmojiModifier:
      if (Character::IsEmojiModifierBase(code_point)) {
        DCHECK_GT(last_seen_vs_code_units_, 0);
        DCHECK_LE(last_seen_vs_code_units_, 2);
        code_units_to_be_deleted_ +=
            last_seen_vs_code_units_ + U16_LENGTH(code_point);
      }
      return Finish();
    case BackspaceState::kBeforeVS:
      if (Character::IsEmoji(code_point)) {
        code_units_to_be_deleted_ += U16_LENGTH(code_point);
        return MoveToNextState(BackspaceState::kBeforeZWJEmoji);
      }
      if (!u_hasBinaryProperty(code_point, UCHAR_VARIATION_SELECTOR) &&
          u_getCombiningClass(code_point) == 0)
        code_units_to_be_deleted_ += U16_LENGTH(code_point);
      return Finish();
    case BackspaceState::kBeforeZWJEmoji:
      return code_point == kZeroWidthJoinerCharacter
                 ? MoveToNextState(BackspaceState::kBeforeZWJ)
                 : Finish();
    case BackspaceState::kBeforeZWJ:
      if (Character::IsEmoji(code_point)) {
        code_units_to_be_deleted_ += U16_LENGTH(code_point) + 1;  // +1 for ZWJ
        return Character::IsModifier(code_point)
                   ? MoveToNextState(BackspaceState::kBeforeEmojiModifier)
                   : MoveToNextState(BackspaceState::kBeforeZWJEmoji);
      }
      if (u_hasBinaryProperty(code_point, UCHAR_VARIATION_SELECTOR)) {
        DCHECK_EQ(last_seen_vs_code_units_, 0);
        last_seen_vs_code_units_ = U16_LENGTH(code_point);
        return MoveToNextState(BackspaceState::kBeforeVSAndZWJ);
      }
      return Finish();
    case BackspaceState::kBeforeVSAndZWJ:
      if (!Character::IsEmoji(code_point))
        return Finish();

      DCHECK_GT(last_seen_vs_code_units_, 0);
      DCHECK_LE(last_seen_vs_code_units_, 2);
      // +1 for ZWJ
      code_units_to_be_deleted_ +=
          U16_LENGTH(code_point) + 1 + last_seen_vs_code_units_;
      last_seen_vs_code_units_ = 0;
      return MoveToNextState(BackspaceState::kBeforeZWJEmoji);
    case BackspaceState::kOddNumberedRIS:
      if (!Character::IsRegionalIndicator(code_point))
        return Finish();
      code_units_to_be_deleted_ += 2;  // Code units of RIS
      return MoveToNextState(BackspaceState::kEvenNumberedRIS);
    case BackspaceState::kEvenNumberedRIS:
      if (!Character::IsRegionalIndicator(code_point))
        return Finish();
      code_units_to_be_deleted_ -= 2;  // Code units of RIS
      return MoveToNextState(BackspaceState::kOddNumberedRIS);
    case BackspaceState::kFinished:
      NOTREACHED() << "Do not call feedPrecedingCodeUnit() once it finishes.";
    default:
      NOTREACHED() << "Unhandled state: " << state_;
  }
}

TextSegmentationMachineState BackspaceStateMachine::TellEndOfPrecedingText() {
  if (trail_surrogate_ != 0) {
    // Unpaired trail surrogate. Removing broken surrogate.
    ++code_units_to_be_deleted_;
    trail_surrogate_ = 0;
  }
  return TextSegmentationMachineState::kFinished;
}

TextSegmentationMachineState BackspaceStateMachine::FeedFollowingCodeUnit(
    UChar code_unit) {
  NOTREACHED();
}

int BackspaceStateMachine::FinalizeAndGetBoundaryOffset() {
  if (trail_surrogate_ != 0) {
    // Unpaired trail surrogate. Removing broken surrogate.
    ++code_units_to_be_deleted_;
    trail_surrogate_ = 0;
  }
  if (state_ != BackspaceState::kFinished) {
    last_seen_vs_code_units_ = 0;
    state_ = BackspaceState::kFinished;
  }
  return -code_units_to_be_deleted_;
}

void BackspaceStateMachine::Reset() {
  code_units_to_be_deleted_ = 0;
  trail_surrogate_ = 0;
  state_ = BackspaceState::kStart;
  last_seen_vs_code_units_ = 0;
}

TextSegmentationMachineState BackspaceStateMachine::MoveToNextState(
    BackspaceState new_state) {
  DCHECK_NE(BackspaceState::kFinished, new_state) << "Use finish() instead.";
  DCHECK_NE(BackspaceState::kStart, new_state) << "Don't move to Start.";
  // Below |DCHECK_NE()| prevent us to infinite loop in state machine.
  DCHECK_NE(state_, new_state) << "State should be changed.";
  state_ = new_state;
  return TextSegmentationMachineState::kNeedMoreCodeUnit;
}

TextSegmentationMachineState BackspaceStateMachine::Finish() {
  DCHECK_NE(BackspaceState::kFinished, state_);
  state_ = BackspaceState::kFinished;
  return TextSegmentationMachineState::kFinished;
}

}  // namespace blink

"""

```