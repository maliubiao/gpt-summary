Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an explanation of the `granularity_strategy.cc` file, focusing on its functionality, relationships with web technologies, logic, potential errors, and debugging.

2. **Initial Code Scan and High-Level Understanding:**  A quick read reveals keywords like "editing," "selection," "granularity," "character," "word," "position," and "DOM." This immediately suggests the file deals with how text selections are handled within the Blink rendering engine. The presence of "CharacterGranularityStrategy" and "DirectionGranularityStrategy" indicates different ways selections can be expanded or contracted.

3. **Identify Key Classes and Enums:**
    * `GranularityStrategy` (base class, abstract?)
    * `CharacterGranularityStrategy` (simple character-by-character selection)
    * `DirectionGranularityStrategy` (more complex, involving direction and granularity changes)
    * `BoundAdjust` (controls behavior at boundaries)
    * `SearchDirection` (specifies search direction)
    * `StrategyState` (for `DirectionGranularityStrategy`)
    * `TextGranularity` (character or word)

4. **Analyze `CharacterGranularityStrategy`:** This is the simpler one. Its `UpdateExtent` method takes a point, finds the corresponding DOM position, and updates the selection extent. The core logic is using `PositionForContentsPointRespectingEditingBoundary`. This suggests it's directly driven by mouse/touch events.

5. **Deep Dive into `DirectionGranularityStrategy`:** This is where the complexity lies.
    * **State Management:**  `state_`, `granularity_`, `offset_` indicate this strategy keeps track of its internal state.
    * **`UpdateExtent` Function:** This is the main logic. It involves:
        * **Offsetting:** Applying an `offset_` to the input point. This is a crucial part of how it remembers previous movements.
        * **Vertical Change Detection:**  The code checks for `vertical_change` and resets the offset and granularity. This hints at handling line breaks and potentially non-horizontal text.
        * **Word Boundary Logic:**  The use of `NextWordBound`, `StartOfWordPosition`, and `EndOfWordPosition` is central to the word-level granularity.
        * **State Transitions:** The `state_` variable (`kExpanding`, `kShrinking`) helps manage the behavior when the selection is growing or shrinking.
        * **Middle of Word Calculation:** The calculation of `x_middle_between_bounds` is key to deciding whether to extend to the beginning or end of a word.
    * **Relationship between `offset_` and Mouse Position:**  The `offset_` seems to be the horizontal difference between the current mouse position and the *intended* focus position based on previous movements.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  User interaction (mouse clicks, drags) trigger events that eventually lead to the `UpdateExtent` call. JavaScript code using the Selection API is directly affected by this logic. The examples provided illustrate this.
    * **HTML:** The structure of the HTML content is what the selection operates on. The examples show how different HTML structures affect selection.
    * **CSS:** CSS affects the layout and rendering, which in turn affects the coordinates used by the strategy. The rotated text example highlights this.

7. **Identify Logic and Assumptions:**  The code makes assumptions about how users interact with the text and the expected behavior of selections. The logic for switching between character and word granularity based on crossing word boundaries is a key assumption.

8. **Consider Potential Errors and User Mistakes:**
    * **Rapid Mouse Movement:**  The `offset_` mechanism might behave unexpectedly with very fast mouse movements.
    * **Interaction with Complex Layouts:**  Rotated text or unusual CSS transformations can expose limitations in the logic.
    * **Unexpected Cursor Placement:**  Clicking or dragging in unusual areas could lead to unexpected selection behavior.

9. **Trace User Actions:**  Think about the steps a user takes to trigger this code. This involves clicking, dragging, and potentially keyboard input. The debugging section was constructed by tracing a simple drag operation.

10. **Refine and Structure the Explanation:** Organize the findings into clear sections (Functionality, Web Technology Relation, Logic, Errors, Debugging). Use examples to illustrate the points. Ensure the language is understandable and avoids overly technical jargon where possible. Use formatting (bullet points, code blocks) to improve readability.

11. **Review and Iterate:** Read through the explanation to ensure accuracy and clarity. Are there any ambiguities? Are the examples clear? Could anything be explained better?  For example, initially, I might not have fully grasped the purpose of `diff_extent_point_from_extent_position_`. Reviewing the code and thinking about its use helped clarify its role in maintaining the relationship between the mouse position and the calculated extent position.

This iterative process of scanning, analyzing, connecting, and refining is key to understanding complex code like this and generating a comprehensive explanation.
这个 `granularity_strategy.cc` 文件是 Chromium Blink 渲染引擎中负责处理文本选择粒度策略的核心组件。它定义了在用户进行文本选择时，如何根据不同的策略来扩展或收缩选择范围。主要涉及字符级别和单词级别的选择。

**功能概览:**

1. **定义选择策略接口:** 文件中定义了抽象基类 `GranularityStrategy`，它提供了一个统一的接口 `UpdateExtent` 用于更新选择范围。

2. **实现字符粒度选择:** `CharacterGranularityStrategy` 是 `GranularityStrategy` 的一个具体实现，它实现了最基本的字符级别的选择。当用户拖动鼠标或使用键盘进行选择时，选择范围会以字符为单位进行扩展或收缩。

3. **实现方向性粒度选择 (DirectionGranularityStrategy):**  这是一个更复杂的策略，它允许根据用户的拖动方向和距离动态地在字符粒度和单词粒度之间切换。
    * **状态管理:** 它维护了内部状态 (`StrategyState`)，跟踪选择是正在扩展还是收缩。
    * **粒度动态切换:**  根据鼠标移动的距离和方向，以及是否跨越了单词边界，动态地将选择粒度从字符切换到单词，反之亦然。
    * **偏移量记录:** 它使用 `offset_` 来记住用户在同一行上的水平拖动距离，以便在后续的拖动中更好地判断是否应该切换到单词粒度。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接影响用户在浏览器中与网页文本交互时的选择行为，而这些交互通常是由 JavaScript 事件驱动，操作的是 HTML 结构中的文本内容，并受到 CSS 样式的渲染影响。

* **JavaScript:** 当用户在网页上进行鼠标按下、移动、释放等操作时，JavaScript 事件监听器可以捕获这些事件。这些事件最终会触发 Blink 渲染引擎的选择逻辑，而 `granularity_strategy.cc` 中的代码正是这个选择逻辑的一部分。例如，当用户拖动鼠标进行文本选择时，渲染引擎会根据当前的选择策略（`CharacterGranularityStrategy` 或 `DirectionGranularityStrategy`）来计算新的选择范围。JavaScript 的 `Selection` API 提供了操作和获取当前选择的能力，其底层实现就依赖于这类 C++ 代码。

   **举例说明:**
   假设用户在网页上使用鼠标拖动选择文本。JavaScript 代码可能会监听 `mousedown`, `mousemove`, `mouseup` 事件。在 `mousemove` 事件处理函数中，浏览器会调用 Blink 引擎的相应接口来更新选择范围，而 `UpdateExtent` 函数就是被调用的关键部分。

* **HTML:** HTML 定义了网页的结构和内容，包括文本内容。`granularity_strategy.cc` 中的代码需要遍历和操作 HTML 结构中的文本节点，以确定选择的边界。例如，在单词粒度选择时，代码需要识别单词的起始和结束位置，这需要理解 HTML 文本节点的结构。

   **举例说明:**
   考虑以下 HTML 片段：
   ```html
   <p>This is a sample text.</p>
   ```
   当用户使用双击或拖动的方式选择 "sample" 这个单词时，`DirectionGranularityStrategy` 中的逻辑会识别 "sample" 的起始和结束位置，并将其作为选择的边界。

* **CSS:** CSS 影响文本的布局和渲染，包括字体、字号、行高等。`granularity_strategy.cc` 中的代码需要考虑这些布局信息，才能准确地计算选择范围。例如，`PositionLocation` 函数使用 `AbsoluteSelectionBoundsOf` 来获取可视位置的边界，这会受到 CSS 样式的影响。对于一些特殊的 CSS 效果，例如文本旋转，`DirectionGranularityStrategy` 中也有相应的处理逻辑来避免出现不符合预期的行为。

   **举例说明:**
   如果 CSS 设置了 `word-break: break-all;`，那么单词的边界可能会被打破。`granularity_strategy.cc` 中的单词粒度选择逻辑需要考虑到这种特殊情况，可能不会按照空格来划分单词。  另外，如果文本被旋转，`DirectionGranularityStrategy` 会检测到垂直方向的变化，并可能会回退到字符粒度选择，因为它对非水平文本的处理可能有限。

**逻辑推理 (假设输入与输出):**

**情景 1: 使用 `CharacterGranularityStrategy`**

* **假设输入:**
    * 鼠标在文本 "Hello World" 的 'o' 字符之后按下。
    * 鼠标移动到 'r' 字符之后。
    * `extent_point` 参数对应于 'r' 字符之后的屏幕坐标。
    * `frame` 指向包含这段文本的 `LocalFrame`。
* **输出:**
    * `SelectionInDOMTree` 对象，其选择范围从初始点击位置（'o' 之后）扩展到当前鼠标位置 ('r' 之后），即选中 " Worl"。

**情景 2: 使用 `DirectionGranularityStrategy` (从字符到单词)**

* **假设输入:**
    * 鼠标在文本 "This is a sample text." 的 's' (is) 字符之后按下。
    * 鼠标向右拖动，跨越了 "is" 单词的边界。
    * `extent_point` 参数移动到 'a' (sample) 字符之前。
    * `frame` 指向包含这段文本的 `LocalFrame`。
* **输出:**
    * 在第一次跨越单词边界时，`granularity_` 可能会从 `TextGranularity::kCharacter` 切换到 `TextGranularity::kWord`。
    * `SelectionInDOMTree` 对象，其选择范围会扩展到包含整个 "is" 单词。
    * 如果继续拖动，选择范围可能会扩展到包含 "a" 或 "sample" 等完整的单词。

**用户或编程常见的使用错误:**

* **在非水平文本上依赖单词粒度选择:**  `DirectionGranularityStrategy` 中有提到，对于非水平文本（例如旋转的文本），单词粒度选择可能不准确或不可靠。开发者可能会期望在任何情况下都能进行精确的单词选择，但 CSS 变换可能会导致意外的结果。
    * **用户操作:** 用户在一个被 CSS 旋转的文本块上尝试双击选择单词，或者拖动鼠标进行单词级别的选择。
    * **错误现象:** 可能只会选中部分字符，而不是整个单词，或者选择范围看起来不符合预期。

* **快速连续的鼠标移动:** `DirectionGranularityStrategy` 使用 `offset_` 来优化水平方向的拖动。如果用户进行非常快速且不规则的鼠标移动，可能会导致 `offset_` 的计算出现偏差，从而影响粒度切换的判断。
    * **用户操作:** 用户快速地左右拖动鼠标进行选择。
    * **错误现象:**  选择粒度可能会在字符和单词之间频繁且不规律地切换，导致选择行为不稳定。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上进行文本选择操作:**  这是最基本的前提。用户可以通过以下方式进行文本选择：
   * **鼠标拖动:** 按下鼠标左键并在文本上拖动。
   * **双击/三击:** 双击选中一个单词，三击选中一行或一个段落。
   * **键盘操作:** 使用 Shift 键结合方向键进行选择。

2. **浏览器事件捕获和处理:** 用户的操作会触发浏览器中的事件，例如 `mousedown`, `mousemove`, `mouseup`, `keydown`, `keyup` 等。

3. **事件分发到渲染引擎:** 浏览器会将这些事件传递到 Blink 渲染引擎进行处理.

4. **选择控制器 (SelectionController) 接收事件:**  Blink 渲染引擎中的 `SelectionController` 负责管理用户的文本选择。它会接收到由用户操作触发的事件。

5. **选择策略的选择和调用:** `SelectionController` 会根据当前的上下文选择合适的 `GranularityStrategy` 对象（通常是 `CharacterGranularityStrategy` 或 `DirectionGranularityStrategy`）。当需要更新选择范围时，会调用策略对象的 `UpdateExtent` 方法。

6. **`UpdateExtent` 方法执行:**  `UpdateExtent` 方法接收鼠标的当前位置 (`extent_point`) 和相关的 `LocalFrame` 信息。

7. **计算新的选择范围:**
   * **`CharacterGranularityStrategy`:** 直接根据 `extent_point` 计算字符级别的选择范围。
   * **`DirectionGranularityStrategy`:**  会考虑之前的状态 (`offset_`, `granularity_`)，判断是否需要切换选择粒度，并计算新的选择范围。

8. **更新选择:**  计算出的新的选择范围会被应用到 DOM 树上，并更新用户界面的显示。

**调试线索:**

当需要调试与文本选择相关的问题时，可以按照以下步骤进行：

1. **确定问题的具体现象:**  例如，是选择范围不正确，还是选择粒度切换不符合预期？

2. **断点设置:** 在 `granularity_strategy.cc` 中的 `UpdateExtent` 方法入口处设置断点，可以观察每次鼠标移动或键盘操作时，该方法的调用情况和参数值。

3. **检查输入参数:**  查看 `extent_point` 的值，确认鼠标位置是否正确。检查 `frame` 指针是否有效。

4. **跟踪策略状态 (对于 `DirectionGranularityStrategy`):**  观察 `state_`, `granularity_`, `offset_` 的变化，理解策略是如何根据用户的操作改变其内部状态的。

5. **单步调试:**  逐步执行 `UpdateExtent` 方法中的代码，观察选择范围是如何计算的。特别是对于 `DirectionGranularityStrategy`，需要关注单词边界的判断逻辑和粒度切换的条件。

6. **检查与 HTML 和 CSS 的交互:**  如果怀疑布局或样式影响了选择，可以检查相关的 DOM 节点和 CSS 属性。使用浏览器的开发者工具可以帮助定位相关的 HTML 元素和应用的 CSS 样式。

7. **日志输出:**  在关键的代码段添加日志输出，记录关键变量的值，例如计算出的单词边界、选择范围等，以便分析问题。

通过以上分析，我们可以理解 `granularity_strategy.cc` 文件在 Chromium Blink 引擎中处理文本选择粒度的重要作用，以及它如何与 JavaScript, HTML, CSS 协同工作，共同实现用户在网页上的文本选择功能。

### 提示词
```
这是目录为blink/renderer/core/editing/granularity_strategy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/granularity_strategy.h"

#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"

namespace blink {

enum class BoundAdjust { kCurrentPosIfOnBound, kNextBoundIfOnBound };
enum class SearchDirection { kSearchBackwards, kSearchForward };

// We use the bottom-left corner of the selection rect to represent the
// location of a VisiblePosition. This way locations corresponding to
// VisiblePositions on the same line will all have the same y coordinate
// unless the text is transformed.
static gfx::Point PositionLocation(const VisiblePosition& vp) {
  return AbsoluteSelectionBoundsOf(vp).bottom_left();
}

// Order is specified using the same contract as comparePositions.
static bool ArePositionsInSpecifiedOrder(const VisiblePosition& vp1,
                                         const VisiblePosition& vp2,
                                         int specified_order) {
  int position_order = ComparePositions(vp1, vp2);
  if (specified_order == 0)
    return position_order == 0;
  return specified_order > 0 ? position_order > 0 : position_order < 0;
}

// Returns the next word boundary starting from |pos|. |direction| specifies
// the direction in which to search for the next bound. nextIfOnBound
// controls whether |pos| or the next boundary is returned when |pos| is
// located exactly on word boundary.
static Position NextWordBound(const Position& pos,
                              SearchDirection direction,
                              BoundAdjust word_bound_adjust) {
  bool next_bound_if_on_bound =
      word_bound_adjust == BoundAdjust::kNextBoundIfOnBound;
  if (direction == SearchDirection::kSearchForward) {
    WordSide word_side = next_bound_if_on_bound ? kNextWordIfOnBoundary
                                                : kPreviousWordIfOnBoundary;
    return EndOfWordPosition(pos, word_side);
  }
  WordSide word_side = next_bound_if_on_bound ? kPreviousWordIfOnBoundary
                                              : kNextWordIfOnBoundary;
  return StartOfWordPosition(pos, word_side);
}

GranularityStrategy::GranularityStrategy() = default;

GranularityStrategy::~GranularityStrategy() = default;

CharacterGranularityStrategy::CharacterGranularityStrategy() = default;

CharacterGranularityStrategy::~CharacterGranularityStrategy() = default;

SelectionStrategy CharacterGranularityStrategy::GetType() const {
  return SelectionStrategy::kCharacter;
}

void CharacterGranularityStrategy::Clear() {}

SelectionInDOMTree CharacterGranularityStrategy::UpdateExtent(
    const gfx::Point& extent_point,
    LocalFrame* frame) {
  const VisiblePosition& extent_position = CreateVisiblePosition(
      PositionForContentsPointRespectingEditingBoundary(extent_point, frame));
  const VisibleSelection& selection =
      frame->Selection().ComputeVisibleSelectionInDOMTree();
  if (extent_position.IsNull() || selection.VisibleAnchor().DeepEquivalent() ==
                                      extent_position.DeepEquivalent()) {
    return selection.AsSelection();
  }
  return SelectionInDOMTree::Builder()
      .Collapse(selection.Anchor())
      .Extend(extent_position.DeepEquivalent())
      .SetAffinity(selection.Affinity())
      .Build();
}

DirectionGranularityStrategy::DirectionGranularityStrategy()
    : state_(StrategyState::kCleared),
      granularity_(TextGranularity::kCharacter),
      offset_(0) {}

DirectionGranularityStrategy::~DirectionGranularityStrategy() = default;

SelectionStrategy DirectionGranularityStrategy::GetType() const {
  return SelectionStrategy::kDirection;
}

void DirectionGranularityStrategy::Clear() {
  state_ = StrategyState::kCleared;
  granularity_ = TextGranularity::kCharacter;
  offset_ = 0;
  diff_extent_point_from_extent_position_ = gfx::Vector2d();
}

SelectionInDOMTree DirectionGranularityStrategy::UpdateExtent(
    const gfx::Point& extent_point,
    LocalFrame* frame) {
  const VisibleSelection& selection =
      frame->Selection().ComputeVisibleSelectionInDOMTree();

  if (state_ == StrategyState::kCleared)
    state_ = StrategyState::kExpanding;

  const VisiblePosition& old_offset_focus_position = selection.VisibleFocus();
  gfx::Point old_focus_location = PositionLocation(old_offset_focus_position);

  gfx::Point old_offset_focus_point =
      old_focus_location + diff_extent_point_from_extent_position_;
  gfx::Point old_focus_point = gfx::Point(old_offset_focus_point.x() - offset_,
                                          old_offset_focus_point.y());

  // Apply the offset.
  gfx::Point new_offset_focus_point = extent_point;
  int dx = extent_point.x() - old_focus_point.x();
  if (offset_ != 0) {
    if (offset_ > 0 && dx > 0)
      offset_ = std::max(0, offset_ - dx);
    else if (offset_ < 0 && dx < 0)
      offset_ = std::min(0, offset_ - dx);
    new_offset_focus_point.Offset(offset_, 0);
  }

  VisiblePosition new_offset_focus_position =
      CreateVisiblePosition(PositionForContentsPointRespectingEditingBoundary(
          new_offset_focus_point, frame));
  if (new_offset_focus_position.IsNull()) {
    return selection.AsSelection();
  }
  gfx::Point new_offset_location = PositionLocation(new_offset_focus_position);

  // Reset the offset in case of a vertical change in the location (could be
  // due to a line change or due to an unusual layout, e.g. rotated text).
  bool vertical_change = new_offset_location.y() != old_focus_location.y();
  if (vertical_change) {
    offset_ = 0;
    granularity_ = TextGranularity::kCharacter;
    new_offset_focus_point = extent_point;
    new_offset_focus_position = CreateVisiblePosition(
        PositionForContentsPointRespectingEditingBoundary(extent_point, frame));
    if (new_offset_focus_position.IsNull()) {
      return selection.AsSelection();
    }
  }

  const VisiblePosition anchor = selection.VisibleAnchor();

  // Do not allow empty selection.
  if (new_offset_focus_position.DeepEquivalent() == anchor.DeepEquivalent()) {
    return selection.AsSelection();
  }

  // The direction granularity strategy, particularly the "offset" feature
  // doesn't work with non-horizontal text (e.g. when the text is rotated).
  // So revert to the behavior equivalent to the character granularity
  // strategy if we detect that the text's baseline coordinate changed
  // without a line change.
  if (vertical_change &&
      InSameLine(new_offset_focus_position, old_offset_focus_position)) {
    return SelectionInDOMTree::Builder()
        .Collapse(selection.Anchor())
        .Extend(new_offset_focus_position.DeepEquivalent())
        .SetAffinity(selection.Affinity())
        .Build();
  }

  int old_focus_anchor_order = selection.IsAnchorFirst() ? 1 : -1;

  int new_focus_anchor_order;
  bool this_move_shrunk_selection;
  if (new_offset_focus_position.DeepEquivalent() ==
      old_offset_focus_position.DeepEquivalent()) {
    if (granularity_ == TextGranularity::kCharacter)
      return selection.AsSelection();

    // If we are in Word granularity, we cannot exit here, since we may pass
    // the middle of the word without changing the position (in which case
    // the selection needs to expand).
    this_move_shrunk_selection = false;
    new_focus_anchor_order = old_focus_anchor_order;
  } else {
    bool selection_expanded = ArePositionsInSpecifiedOrder(
        new_offset_focus_position, old_offset_focus_position,
        old_focus_anchor_order);
    bool extent_base_order_switched =
        selection_expanded
            ? false
            : !ArePositionsInSpecifiedOrder(new_offset_focus_position, anchor,
                                            old_focus_anchor_order);
    new_focus_anchor_order = extent_base_order_switched
                                 ? -old_focus_anchor_order
                                 : old_focus_anchor_order;

    // Determine the word boundary, i.e. the boundary extending beyond which
    // should change the granularity to WordGranularity.
    Position word_boundary_position;
    if (extent_base_order_switched) {
      // Special case.
      // If the extent-base order was switched, then the selection is now
      // expanding in a different direction than before. Therefore we
      // calculate the word boundary in this new direction and based on
      // the |base| position.
      word_boundary_position = NextWordBound(
          anchor.DeepEquivalent(),
          new_focus_anchor_order > 0 ? SearchDirection::kSearchForward
                                     : SearchDirection::kSearchBackwards,
          BoundAdjust::kNextBoundIfOnBound);
      granularity_ = TextGranularity::kCharacter;
    } else {
      // Calculate the word boundary based on |oldExtentWithGranularity|.
      // If selection was shrunk in the last update and the extent is now
      // exactly on the word boundary - we need to take the next bound as
      // the bound of the current word.
      word_boundary_position = NextWordBound(
          old_offset_focus_position.DeepEquivalent(),
          old_focus_anchor_order > 0 ? SearchDirection::kSearchForward
                                     : SearchDirection::kSearchBackwards,
          state_ == StrategyState::kShrinking
              ? BoundAdjust::kNextBoundIfOnBound
              : BoundAdjust::kCurrentPosIfOnBound);
    }
    VisiblePosition word_boundary =
        CreateVisiblePosition(word_boundary_position);

    bool expanded_beyond_word_boundary;
    if (selection_expanded) {
      expanded_beyond_word_boundary = ArePositionsInSpecifiedOrder(
          new_offset_focus_position, word_boundary, new_focus_anchor_order);
    } else if (extent_base_order_switched) {
      expanded_beyond_word_boundary = ArePositionsInSpecifiedOrder(
          new_offset_focus_position, word_boundary, new_focus_anchor_order);
    } else {
      expanded_beyond_word_boundary = false;
    }

    // The selection is shrunk if the extent changes position to be closer to
    // the base, and the extent/base order wasn't switched.
    this_move_shrunk_selection =
        !extent_base_order_switched && !selection_expanded;

    if (expanded_beyond_word_boundary)
      granularity_ = TextGranularity::kWord;
    else if (this_move_shrunk_selection)
      granularity_ = TextGranularity::kCharacter;
  }

  VisiblePosition new_selection_extent = new_offset_focus_position;
  if (granularity_ == TextGranularity::kWord) {
    // Determine the bounds of the word where the extent is located.
    // Set the selection extent to one of the two bounds depending on
    // whether the extent is passed the middle of the word.
    VisiblePosition bound_before_extent = CreateVisiblePosition(NextWordBound(
        new_offset_focus_position.DeepEquivalent(),
        SearchDirection::kSearchBackwards, BoundAdjust::kCurrentPosIfOnBound));
    if (bound_before_extent.IsNull())
      return selection.AsSelection();
    VisiblePosition bound_after_extent = CreateVisiblePosition(NextWordBound(
        new_offset_focus_position.DeepEquivalent(),
        SearchDirection::kSearchForward, BoundAdjust::kCurrentPosIfOnBound));
    if (bound_after_extent.IsNull())
      return selection.AsSelection();
    int x_middle_between_bounds = (PositionLocation(bound_after_extent).x() +
                                   PositionLocation(bound_before_extent).x()) /
                                  2;
    bool offset_extent_before_middle =
        new_offset_focus_point.x() < x_middle_between_bounds;
    new_selection_extent =
        offset_extent_before_middle ? bound_before_extent : bound_after_extent;
    // Update the offset if selection expanded in word granularity.
    if (new_selection_extent.DeepEquivalent() !=
            old_offset_focus_position.DeepEquivalent() &&
        ((new_focus_anchor_order > 0 && !offset_extent_before_middle) ||
         (new_focus_anchor_order < 0 && offset_extent_before_middle))) {
      offset_ = PositionLocation(new_selection_extent).x() - extent_point.x();
    }
  }

  // Only update the state if the selection actually changed as a result of
  // this move.
  if (new_selection_extent.DeepEquivalent() !=
      old_offset_focus_position.DeepEquivalent()) {
    state_ = this_move_shrunk_selection ? StrategyState::kShrinking
                                        : StrategyState::kExpanding;
  }

  diff_extent_point_from_extent_position_ =
      extent_point + gfx::Vector2d(offset_, 0) -
      PositionLocation(new_selection_extent);
  return SelectionInDOMTree::Builder(selection.AsSelection())
      .Collapse(selection.Anchor())
      .Extend(new_selection_extent.DeepEquivalent())
      .Build();
}

}  // namespace blink
```