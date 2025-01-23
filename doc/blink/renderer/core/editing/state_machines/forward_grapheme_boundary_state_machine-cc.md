Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding of the Purpose:**

The filename `forward_grapheme_boundary_state_machine.cc` immediately suggests the core functionality:  identifying the next grapheme boundary in a forward direction within text. The "state machine" part indicates a design pattern for managing different processing stages based on input.

**2. Deconstructing the Code - Key Elements and Their Roles:**

* **Headers:** `#include` statements point to dependencies. `forward_grapheme_boundary_state_machine.h` is likely the corresponding header file defining the class interface. Other headers suggest text processing (`character.h`, `unicode.h`), state machine utilities (`state_machine_util.h`, `text_segmentation_machine_state.h`), and standard library components (`array`, `ostream`).
* **Namespace:** `namespace blink` and the anonymous namespace `namespace { ... }` are standard C++ for organizing code. The anonymous namespace likely holds constants or helper functions specific to this file.
* **`kUnsetCodePoint`:**  This constant suggests a way to represent an invalid or uninitialized code point, which is common when dealing with text processing.
* **`FOR_EACH_FORWARD_GRAPHEME_BOUNDARY_STATE` Macro:** This is a crucial piece. It defines the different states the state machine can be in. Analyzing the state names (`kCountRIS`, `kCountRISWaitLeadSurrogate`, `kStartForward`, etc.) provides clues about the different phases of the grapheme boundary detection process. The comments next to each state are particularly helpful. "RIS" likely stands for "Regional Indicator Symbol."
* **`enum class ForwardGraphemeBoundaryStateMachine::InternalState`:** This enum directly uses the states defined by the macro, making the state machine's internal logic explicit.
* **`operator<<` Overload:** This allows for easy printing of the `InternalState` enum, which is very useful for debugging and logging.
* **Constructor:** Initializes the state machine to `kCountRIS` and sets `prev_code_point_` to the unset value.
* **`FeedPrecedingCodeUnit`:** This function handles input from the text *before* the current position. The logic within this function deals primarily with counting preceding Regional Indicators. The `DCHECK` statements are important for understanding preconditions and detecting potential errors. The `MoveToNextState` calls indicate transitions between states.
* **`FeedFollowingCodeUnit`:** This function handles input from the text *after* the current position, which is the main part of the grapheme boundary detection. It processes code units based on the current state, checks for surrogate pairs, and calls `IsGraphemeBreak`.
* **`TellEndOfPrecedingText`:** This handles the case where there's no more preceding text. It forces a transition to the state where forward processing begins.
* **`FinalizeAndGetBoundaryOffset`:**  This function is called when the processing is complete. It returns the offset of the grapheme boundary. The `FinishWithEndOfText` call suggests handling the end of the input.
* **`Reset`:**  Resets the state machine to its initial state.
* **`Finish`, `MoveToNextState`, `StaySameState`:** These are helper functions for managing state transitions. The `DCHECK` statements enforce proper usage.
* **`FinishWithEndOfText`:** Handles the case where the end of the text is reached during processing.
* **`IsGraphemeBreak` (Implied):** The code calls `IsGraphemeBreak(prev_code_point_, code_unit)` and `IsGraphemeBreak(prev_code_point_, code_point)`. This indicates a dependency on a function (likely defined elsewhere) that determines if a grapheme break occurs between two code points. This is the core logic for grapheme segmentation.

**3. Identifying Functionality and Connections:**

Based on the code structure and the state names, the core functionality is clearly to find the next grapheme boundary. The connections to JavaScript, HTML, and CSS come from understanding *where* this code fits within the Blink rendering engine:

* **JavaScript:** When JavaScript manipulates text (e.g., getting substrings, iterating over characters), it needs to understand grapheme boundaries to avoid splitting combined characters. This state machine likely plays a role in those operations.
* **HTML:** HTML text content needs to be rendered correctly. Grapheme boundaries are important for line breaking, text selection, and cursor positioning within HTML.
* **CSS:** While CSS doesn't directly manipulate text content in the same way as JavaScript, CSS properties like `word-break` and text justification rely on understanding word and character boundaries, which are related to grapheme boundaries.

**4. Logic Inference and Examples:**

By examining the state transitions and the logic within each state, we can infer how the state machine works with specific inputs. The examples provided in the initial good answer are based on tracing the state changes for different character sequences.

**5. Identifying Potential Errors:**

The `DCHECK` statements are a strong indicator of potential usage errors. For example, calling `FeedPrecedingCodeUnit` after `kNeedFollowingCodeUnit` is returned is an error. The code also handles lonely surrogates, which are common sources of encoding errors.

**6. Tracing User Operations:**

To trace how a user operation reaches this code, consider actions that involve text manipulation within a web page:

* Typing text in a `<textarea>` or a content-editable element.
* Selecting text with the mouse or keyboard.
* Copying and pasting text.
* Using JavaScript to modify the text content of an element.

These actions eventually lead to the Blink engine processing the text, and this state machine is likely involved in determining grapheme boundaries for correct rendering and manipulation.

**7. Iterative Refinement:**

The process of understanding the code is often iterative. You might start with a high-level understanding and then delve into specific parts, referring back to the overall structure as needed. Reading the comments and paying attention to variable names are crucial. If something is unclear, searching for related code or documentation within the Chromium project can be helpful.
这个C++源代码文件 `forward_grapheme_boundary_state_machine.cc` 实现了 **向前查找文本中下一个字形簇（grapheme cluster）边界的状态机**。 字形簇是用户感知到的一个字符，可能由一个或多个 Unicode 代码点组成。

以下是该文件的功能详细说明：

**核心功能：**

1. **确定字形簇边界：**  该状态机的核心目标是接收一个字符序列（以 Unicode 代码单元为单位），并确定下一个字形簇的结束位置。
2. **处理复杂字符：** 它能够正确处理由多个代码单元组成的字符，例如：
   - **代理对 (Surrogate Pairs):**  表示 Unicode 补充平面的字符。
   - **组合字符序列 (Combining Character Sequences):** 例如，带有变音符号的字符。
   - **区域指示符 (Regional Indicators):** 用于表示国旗的字符。
3. **状态管理：**  使用状态机模式来管理查找过程，不同的状态代表着查找过程中的不同阶段，根据输入的代码单元进行状态转换。

**状态机的各个状态及其含义：**

* **`kCountRIS` (Counting preceding regional indicators):**  初始状态。该状态下，状态机正在计数前面出现的区域指示符的数量。这是为了正确处理偶数个区域指示符构成一个国旗表情的情况。
* **`kCountRISWaitLeadSurrogate` (Waiting lead surrogate during counting regional indicators):** 当在 `kCountRIS` 状态下遇到一个尾部代理项时，进入此状态，等待下一个前导代理项以构成完整的代理对。
* **`kStartForward` (Waiting first following code unit):**  在处理完前导的区域指示符后，或者没有前导区域指示符的情况下，进入此状态，等待接收要处理的第一个代码单元。
* **`kStartForwardWaitTrailSurrgate` (Waiting trail surrogate for the first following code point):** 当在 `kStartForward` 状态下遇到一个前导代理项时，进入此状态，等待接收其对应的尾部代理项。
* **`kSearch` (Searching grapheme boundary):**  接收到第一个完整的代码点后，进入此状态。状态机在此状态下继续接收后续的代码单元，并根据 Unicode 字形簇的构成规则判断是否到达了字形簇的边界。
* **`kSearchWaitTrailSurrogate` (Waiting trail surrogate during searching grapheme boundary):** 当在 `kSearch` 状态下遇到一个前导代理项时，进入此状态，等待接收其对应的尾部代理项。
* **`kFinished` (The state machine has stopped):**  状态机已经找到了字形簇的边界或者处理结束，进入此状态。

**与 JavaScript, HTML, CSS 的关系：**

该状态机虽然是用 C++ 实现的，但它在 Blink 渲染引擎中扮演着关键的角色，直接影响着 JavaScript、HTML 和 CSS 的功能，因为它们都涉及到文本的处理和渲染。

**1. JavaScript:**

* **字符串操作：** JavaScript 中的字符串操作，例如 `String.prototype.substring()`, `String.prototype.charAt()`,  以及正则表达式的匹配等，都需要正确识别字形簇的边界。 如果错误地将一个字形簇拆开，会导致显示错误或逻辑错误。
    * **例子：** 考虑一个包含表情符号的字符串，例如 "👩‍👩‍👧‍👦"。这个表情符号实际上由多个 Unicode 代码点组成。 如果 JavaScript 代码需要获取字符串的第一个“字符”，引擎会使用类似这样的状态机来确定 "👩‍👩‍👧‍👦" 是一个完整的字形簇，而不是将其分割开。
    * **假设输入：**  JavaScript 代码尝试获取字符串 "👩‍👩‍👧‍👦你好" 的第一个字符。
    * **输出：**  状态机经过一系列状态转换，最终确定 "👩‍👩‍👧‍👦" 是一个字形簇边界，JavaScript 会返回这个完整的表情符号。

* **文本光标移动和选择：** 当用户在文本框中移动光标或选择文本时，浏览器需要以字形簇为单位进行操作，而不是以单个代码单元为单位。
    * **用户操作：** 用户在包含组合字符的文本中，例如 "á" （由 'a' 和一个组合重音符组成），按一下右方向键。
    * **内部处理：**  这个状态机帮助确定 "á" 是一个字形簇，光标会一次移动到这个字形簇的末尾，而不是停留在 'a' 和重音符之间。

**2. HTML:**

* **文本渲染：** 浏览器在渲染 HTML 文本内容时，需要正确识别字形簇，以确保复杂的字符能够正确显示。
    * **例子：**  HTML 中包含像 "👨‍👩‍👧‍👦" 这样的复杂表情符号，浏览器会使用字形簇边界的信息来正确绘制这个表情，而不是将其拆分成单独的组件。
* **换行：**  浏览器在进行自动换行时，通常会尽量避免在一个字形簇的中间断开。
    * **HTML 内容：**  一段包含长串字符和表情符号的文本。
    * **浏览器行为：**  状态机帮助识别字形簇的边界，浏览器在换行时会尽量在字形簇的边界处进行，保持字符的完整性。

**3. CSS:**

* **`word-break` 和 `overflow-wrap` 属性：** 这些 CSS 属性控制着单词如何在容器中换行。 虽然主要关注单词边界，但在处理某些语言或特殊字符时，也可能涉及到对字形簇的考虑。
* **文本选择和高亮：**  当用户在浏览器中选择文本时，选择的单位通常是字形簇。
    * **用户操作：**  用户在网页上拖动鼠标选择包含 "👩‍⚕️" 表情符号的文本。
    * **内部处理：** 状态机帮助确定 "👩‍⚕️" 是一个字形簇，用户可以一次性选中整个表情符号，而不是只选中一部分代码单元。

**逻辑推理与假设输入输出：**

**假设输入 1:**  字符序列 "你好" (每个汉字是一个代码点)
* **状态流转：**
    1. 初始化: `kCountRIS`
    2. 输入 '你': `FeedFollowingCodeUnit('你')` -> `kStartForward` -> `kSearch` (prev_code_point_ = '你', boundary_offset_ = 1)
    3. 输入 '好': `FeedFollowingCodeUnit('好')` -> `IsGraphemeBreak('你', '好')` 返回 false (假设汉字之间不断开) -> `kSearch` (prev_code_point_ = '好', boundary_offset_ = 2)
    4. 假设到达文本末尾或需要下一个字形簇边界: `FinalizeAndGetBoundaryOffset()` -> 返回 `2`，表示下一个字形簇边界在偏移量 2 的位置（即整个字符串的末尾，因为 "你好" 是两个字形簇）。

**假设输入 2:** 字符序列 "áb" ( 'a' + 组合重音符 + 'b')
* **状态流转：**
    1. 初始化: `kCountRIS`
    2. 输入 'a': `FeedFollowingCodeUnit('a')` -> `kStartForward` -> `kSearch` (prev_code_point_ = 'a', boundary_offset_ = 1)
    3. 输入 组合重音符: `FeedFollowingCodeUnit(组合重音符)` -> `IsGraphemeBreak('a', 组合重音符)` 返回 false (组合字符不断开) -> `kSearch` (prev_code_point_ = 'á' 视为一个逻辑上的字符, boundary_offset_ 根据组合字符的实现可能为 2 或更多)
    4. 输入 'b': `FeedFollowingCodeUnit('b')` -> `IsGraphemeBreak('á', 'b')` 返回 true -> `kFinished`, `boundary_offset_` 为 'á' 的长度。

**用户或编程常见的错误使用：**

1. **逐个代码单元处理字符串而不考虑字形簇：**
   - **错误示例（JavaScript）：**  `const text = "👩‍👩‍👧‍👦"; console.log(text.length); // 输出 11 或其他取决于编码，但不是 1 (字形簇的数量)`
   - **说明：**  `String.prototype.length` 返回的是代码单元的数量，而不是字形簇的数量。直接使用代码单元数量进行字符串操作可能会导致错误。

2. **在需要完整字形簇的地方分割字符串：**
   - **错误示例（JavaScript）：**  错误地分割包含表情符号的字符串可能导致显示不全。
   - **用户操作：** 用户在富文本编辑器中输入 "你好👩‍⚕️世界"，然后尝试删除 "👩‍⚕️" 的一部分。
   - **内部错误：** 如果删除逻辑没有正确使用字形簇边界，可能会只删除表情符号的一部分代码单元，导致显示乱码。

3. **在 CSS 中假设字符是一个代码单元：**  虽然 CSS 通常处理的是渲染结果，但了解字形簇对于某些高级文本处理仍然重要。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在网页的文本输入框中输入文本：** 例如，在一个 `<textarea>` 元素或 `contenteditable` 属性的元素中输入包含复杂字符或表情符号的文本。
2. **浏览器接收用户输入事件：** 用户的键盘输入会触发浏览器的事件处理机制。
3. **Blink 引擎处理文本输入：**  Blink 引擎接收到输入事件后，需要更新内部的文本表示。
4. **光标移动或文本选择：** 如果用户移动光标或选择文本，引擎需要确定光标或选择的起始和结束位置，这需要以字形簇为单位。
5. **调用 `ForwardGraphemeBoundaryStateMachine`：**  在需要确定下一个字形簇边界时，相关的文本处理模块（例如，编辑或布局模块）会创建并使用 `ForwardGraphemeBoundaryStateMachine` 的实例。
6. **逐步馈送代码单元：**  需要处理的文本的 Unicode 代码单元会被逐个馈送到状态机的 `FeedPrecedingCodeUnit` 或 `FeedFollowingCodeUnit` 方法中。
7. **状态机根据输入进行状态转换：**  状态机根据接收到的代码单元和当前状态进行状态转换，直到找到字形簇的边界。
8. **返回边界偏移量：**  状态机最终会通过 `FinalizeAndGetBoundaryOffset()` 方法返回下一个字形簇边界的偏移量。
9. **更新 UI 或进行后续处理：**  Blink 引擎根据返回的边界信息更新用户界面（例如，移动光标，高亮选中文本）或进行其他文本相关的处理。

**调试线索：**

* **断点设置：** 在 `FeedPrecedingCodeUnit` 和 `FeedFollowingCodeUnit` 方法中设置断点，可以观察状态机如何处理不同的代码单元。
* **打印状态：**  利用 `operator<<` 重载，可以在调试时打印出状态机的当前状态，帮助理解状态的流转。
* **检查输入代码单元：**  确保输入到状态机的代码单元是正确的 Unicode 值。
* **分析状态转换逻辑：**  仔细阅读状态机各个状态的转换条件，理解为什么在特定的输入下会发生特定的状态转换。
* **查看 `IsGraphemeBreak` 的实现：**  `IsGraphemeBreak` 函数的实现逻辑是判断字形簇边界的关键，需要确保其遵循 Unicode 字形簇的定义。

总而言之，`forward_grapheme_boundary_state_machine.cc` 是 Blink 引擎中一个至关重要的组件，它负责准确地识别文本中的字形簇边界，这对于正确地处理和渲染各种语言和复杂的 Unicode 字符至关重要，直接影响着用户与网页文本交互的方方面面。

### 提示词
```
这是目录为blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine.h"

#include <array>
#include <ostream>

#include "third_party/blink/renderer/core/editing/state_machines/state_machine_util.h"
#include "third_party/blink/renderer/core/editing/state_machines/text_segmentation_machine_state.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {
namespace {
const UChar32 kUnsetCodePoint = WTF::unicode::kMaxCodepoint + 1;
}  // namespace

#define FOR_EACH_FORWARD_GRAPHEME_BOUNDARY_STATE(V)                    \
  /* Counting preceding regional indicators. This is initial state. */ \
  V(kCountRIS)                                                         \
  /* Waiting lead surrogate during counting regional indicators. */    \
  V(kCountRISWaitLeadSurrogate)                                        \
  /* Waiting first following code unit. */                             \
  V(kStartForward)                                                     \
  /* Waiting trail surrogate for the first following code point. */    \
  V(kStartForwardWaitTrailSurrgate)                                    \
  /* Searching grapheme boundary. */                                   \
  V(kSearch)                                                           \
  /* Waiting trail surrogate during searching grapheme boundary. */    \
  V(kSearchWaitTrailSurrogate)                                         \
  /* The state machine has stopped. */                                 \
  V(kFinished)

enum class ForwardGraphemeBoundaryStateMachine::InternalState {
#define V(name) name,
  FOR_EACH_FORWARD_GRAPHEME_BOUNDARY_STATE(V)
#undef V
};

std::ostream& operator<<(
    std::ostream& os,
    ForwardGraphemeBoundaryStateMachine::InternalState state) {
  static const auto kTexts = std::to_array<const char*>({
#define V(name) #name,
      FOR_EACH_FORWARD_GRAPHEME_BOUNDARY_STATE(V)
#undef V
  });
  DCHECK_LT(static_cast<size_t>(state), kTexts.size()) << "Unknown state value";
  return os << kTexts[static_cast<size_t>(state)];
}

ForwardGraphemeBoundaryStateMachine::ForwardGraphemeBoundaryStateMachine()
    : prev_code_point_(kUnsetCodePoint),
      internal_state_(InternalState::kCountRIS) {}

TextSegmentationMachineState
ForwardGraphemeBoundaryStateMachine::FeedPrecedingCodeUnit(UChar code_unit) {
  DCHECK_EQ(prev_code_point_, kUnsetCodePoint);
  DCHECK_EQ(boundary_offset_, 0);
  switch (internal_state_) {
    case InternalState::kCountRIS:
      DCHECK_EQ(pending_code_unit_, 0);
      if (U16_IS_TRAIL(code_unit)) {
        pending_code_unit_ = code_unit;
        return MoveToNextState(InternalState::kCountRISWaitLeadSurrogate);
      }
      return MoveToNextState(InternalState::kStartForward);
    case InternalState::kCountRISWaitLeadSurrogate:
      DCHECK_NE(pending_code_unit_, 0);
      if (U16_IS_LEAD(code_unit)) {
        const UChar32 code_point =
            U16_GET_SUPPLEMENTARY(code_unit, pending_code_unit_);
        pending_code_unit_ = 0;
        if (Character::IsRegionalIndicator(code_point)) {
          ++preceding_ris_count_;
          return MoveToNextState(InternalState::kCountRIS);
        }
      }
      pending_code_unit_ = 0;
      return MoveToNextState(InternalState::kStartForward);
    case InternalState::kStartForward:                   // Fallthrough
    case InternalState::kStartForwardWaitTrailSurrgate:  // Fallthrough
    case InternalState::kSearch:                         // Fallthrough
    case InternalState::kSearchWaitTrailSurrogate:       // Fallthrough
      NOTREACHED() << "Do not call feedPrecedingCodeUnit() once "
                   << TextSegmentationMachineState::kNeedFollowingCodeUnit
                   << " is returned. InternalState: " << internal_state_;
    case InternalState::kFinished:
      NOTREACHED() << "Do not call feedPrecedingCodeUnit() once it finishes.";
  }
  NOTREACHED() << "Unhandled state: " << internal_state_;
}

TextSegmentationMachineState
ForwardGraphemeBoundaryStateMachine::FeedFollowingCodeUnit(UChar code_unit) {
  switch (internal_state_) {
    case InternalState::kCountRIS:  // Fallthrough
    case InternalState::kCountRISWaitLeadSurrogate:
      NOTREACHED() << "Do not call feedFollowingCodeUnit() until "
                   << TextSegmentationMachineState::kNeedFollowingCodeUnit
                   << " is returned. InternalState: " << internal_state_;
    case InternalState::kStartForward:
      DCHECK_EQ(prev_code_point_, kUnsetCodePoint);
      DCHECK_EQ(boundary_offset_, 0);
      DCHECK_EQ(pending_code_unit_, 0);
      if (U16_IS_TRAIL(code_unit)) {
        // Lonely trail surrogate.
        boundary_offset_ = 1;
        return Finish();
      }
      if (U16_IS_LEAD(code_unit)) {
        pending_code_unit_ = code_unit;
        return MoveToNextState(InternalState::kStartForwardWaitTrailSurrgate);
      }
      prev_code_point_ = code_unit;
      boundary_offset_ = 1;
      return MoveToNextState(InternalState::kSearch);
    case InternalState::kStartForwardWaitTrailSurrgate:
      DCHECK_EQ(prev_code_point_, kUnsetCodePoint);
      DCHECK_EQ(boundary_offset_, 0);
      DCHECK_NE(pending_code_unit_, 0);
      if (U16_IS_TRAIL(code_unit)) {
        prev_code_point_ = U16_GET_SUPPLEMENTARY(pending_code_unit_, code_unit);
        boundary_offset_ = 2;
        pending_code_unit_ = 0;
        return MoveToNextState(InternalState::kSearch);
      }
      // Lonely lead surrogate.
      boundary_offset_ = 1;
      return Finish();
    case InternalState::kSearch:
      DCHECK_NE(prev_code_point_, kUnsetCodePoint);
      DCHECK_NE(boundary_offset_, 0);
      DCHECK_EQ(pending_code_unit_, 0);
      if (U16_IS_LEAD(code_unit)) {
        pending_code_unit_ = code_unit;
        return MoveToNextState(InternalState::kSearchWaitTrailSurrogate);
      }
      if (U16_IS_TRAIL(code_unit))
        return Finish();  // Lonely trail surrogate.
      if (IsGraphemeBreak(prev_code_point_, code_unit))
        return Finish();
      prev_code_point_ = code_unit;
      boundary_offset_ += 1;
      return StaySameState();
    case InternalState::kSearchWaitTrailSurrogate:
      DCHECK_NE(prev_code_point_, kUnsetCodePoint);
      DCHECK_NE(boundary_offset_, 0);
      DCHECK_NE(pending_code_unit_, 0);
      if (!U16_IS_TRAIL(code_unit))
        return Finish();  // Lonely lead surrogate.

      {
        const UChar32 code_point =
            U16_GET_SUPPLEMENTARY(pending_code_unit_, code_unit);
        pending_code_unit_ = 0;
        if (Character::IsRegionalIndicator(prev_code_point_) &&
            Character::IsRegionalIndicator(code_point)) {
          if (preceding_ris_count_ % 2 == 0) {
            // Odd numbered RI case, note that prev_code_point_ is also RI.
            boundary_offset_ += 2;
          }
          return Finish();
        }
        if (IsGraphemeBreak(prev_code_point_, code_point))
          return Finish();
        prev_code_point_ = code_point;
        boundary_offset_ += 2;
        return MoveToNextState(InternalState::kSearch);
      }
    case InternalState::kFinished:
      NOTREACHED() << "Do not call feedFollowingCodeUnit() once it finishes.";
  }
  NOTREACHED() << "Unhandled state: " << internal_state_;
}

TextSegmentationMachineState
ForwardGraphemeBoundaryStateMachine::TellEndOfPrecedingText() {
  DCHECK(internal_state_ == InternalState::kCountRIS ||
         internal_state_ == InternalState::kCountRISWaitLeadSurrogate)
      << "Do not call tellEndOfPrecedingText() once "
      << TextSegmentationMachineState::kNeedFollowingCodeUnit
      << " is returned. InternalState: " << internal_state_;

  // Clear pending code unit since preceding buffer may end with lonely trail
  // surrogate. We can just ignore it since preceding buffer is only used for
  // counting preceding regional indicators.
  pending_code_unit_ = 0;
  return MoveToNextState(InternalState::kStartForward);
}

int ForwardGraphemeBoundaryStateMachine::FinalizeAndGetBoundaryOffset() {
  if (internal_state_ != InternalState::kFinished)
    FinishWithEndOfText();
  DCHECK_GE(boundary_offset_, 0);
  return boundary_offset_;
}

void ForwardGraphemeBoundaryStateMachine::Reset() {
  pending_code_unit_ = 0;
  boundary_offset_ = 0;
  preceding_ris_count_ = 0;
  prev_code_point_ = kUnsetCodePoint;
  internal_state_ = InternalState::kCountRIS;
}

TextSegmentationMachineState ForwardGraphemeBoundaryStateMachine::Finish() {
  DCHECK_NE(internal_state_, InternalState::kFinished);
  internal_state_ = InternalState::kFinished;
  return TextSegmentationMachineState::kFinished;
}

TextSegmentationMachineState
ForwardGraphemeBoundaryStateMachine::MoveToNextState(InternalState next_state) {
  DCHECK_NE(next_state, InternalState::kFinished) << "Use finish() instead";
  DCHECK_NE(next_state, internal_state_) << "Use staySameSatate() instead";
  internal_state_ = next_state;
  if (next_state == InternalState::kStartForward)
    return TextSegmentationMachineState::kNeedFollowingCodeUnit;
  return TextSegmentationMachineState::kNeedMoreCodeUnit;
}

TextSegmentationMachineState
ForwardGraphemeBoundaryStateMachine::StaySameState() {
  DCHECK_EQ(internal_state_, InternalState::kSearch)
      << "Only Search can stay the same state.";
  return TextSegmentationMachineState::kNeedMoreCodeUnit;
}

void ForwardGraphemeBoundaryStateMachine::FinishWithEndOfText() {
  switch (internal_state_) {
    case InternalState::kCountRIS:                   // Fallthrough
    case InternalState::kCountRISWaitLeadSurrogate:  // Fallthrough
    case InternalState::kStartForward:               // Fallthrough
      return;  // Haven't search anything to forward. Just finish.
    case InternalState::kStartForwardWaitTrailSurrgate:
      // Lonely lead surrogate.
      boundary_offset_ = 1;
      return;
    case InternalState::kSearch:                    // Fallthrough
    case InternalState::kSearchWaitTrailSurrogate:  // Fallthrough
      return;
    case InternalState::kFinished:  // Fallthrough
      NOTREACHED() << "Do not call finishWithEndOfText() once it finishes.";
  }
  NOTREACHED() << "Unhandled state: " << internal_state_;
}
}  // namespace blink
```