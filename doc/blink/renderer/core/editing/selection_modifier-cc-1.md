Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understanding the Goal:** The primary goal is to understand the functionality of the `SelectionModifier` class in the Chromium Blink engine, specifically the code within the provided snippet. This involves identifying its purpose, its relationship with web technologies, how it works logically, potential errors, and its role in the user interaction flow.

2. **Initial Code Scan and Keyword Recognition:**  The first step is to quickly scan the code, looking for recognizable keywords and patterns. Keywords like `SelectionModifyDirection`, `SelectionModifyAlteration`, `TextGranularity`, `SelectionInFlatTree`, `VisiblePositionInFlatTree`, `ModifyMovingRight`, `ModifyExtendingLeft`, etc., immediately suggest the class is involved in manipulating text selections. The presence of `kRight`, `kLeft`, `kForward`, `kBackward`, `kMove`, `kExtend`, `kWord`, `kLine`, `kParagraph` hints at various selection manipulation modes.

3. **Function-Level Analysis:**  Focus on the individual functions and their roles:

    * **`Modify(alter, direction, granularity)`:** This looks like the core function. It takes the type of modification (move or extend), the direction, and the granularity of the selection change. The `switch` statement based on `direction` and the nested `if` on `alter` indicate a decision-making process based on these parameters. The calls to functions like `ModifyMovingRight`, `ModifyExtendingLeft` suggest delegation of the actual modification logic. The code also checks `NeedsLayoutTreeUpdate` and uses `UpdateAllLifecyclePhasesExceptPaint`, indicating interaction with the rendering pipeline. The logic for `kExtend` is more complex and involves checking editor behavior and boundary conditions, which hints at platform-specific or configurable behavior.

    * **`ModifyWithPageGranularity(alter, vertical_distance, direction)`:** This function clearly handles selection modification by "pages" or vertical distance. The iterative approach with `PreviousLinePosition` and `NextLinePosition` suggests a line-by-line movement to achieve the page-level granularity. The `AbsoluteCaretY` function call indicates a concern with the vertical position of the caret.

    * **`AbsoluteCaretY(c, y)`:** This helper function calculates the vertical position of the caret.

    * **`LineDirectionPointForBlockDirectionNavigationOf(visible_position)`:** This function appears to calculate a reference point (X or Y coordinate depending on writing mode) for vertical navigation, considering the layout and potential text direction. The comment about ignoring transforms is important.

    * **`LineDirectionPointForBlockDirectionNavigation(pos)`:** This function manages the `x_pos_for_vertical_arrow_navigation_` member, likely caching the horizontal position to maintain consistency during vertical selection movements.

    * **`UpdateAllLifecyclePhasesExceptPaint()`:** This function interacts with the rendering lifecycle, ensuring layout and other phases are up-to-date before painting.

4. **Inferring Functionality and Relationships:** Based on the function analysis, we can start inferring the broader functionality:

    * **Core Selection Manipulation:** The primary function is to modify text selections based on various directions, granularities, and alteration types (moving or extending).
    * **Navigation:** The presence of "forward," "backward," "left," "right," and page granularity suggests the class handles navigation within the text content.
    * **Rendering Integration:** The calls to rendering-related functions indicate a close tie to how the selection is visually represented on the screen.
    * **Platform/Behavioral Differences:** The checks for editor behavior suggest that selection behavior can vary across platforms or be configurable.

5. **Connecting to Web Technologies:**  Consider how this C++ code relates to JavaScript, HTML, and CSS:

    * **JavaScript:** JavaScript events like `keydown` (arrow keys, Home/End, Page Up/Down) and mouse events (selection drag) are the likely triggers for calling these C++ functions. JavaScript interacts with the DOM, and the `Selection` API in JavaScript likely translates user actions into calls that eventually reach this C++ code.
    * **HTML:** The HTML structure defines the text content and elements upon which the selection is made. The C++ code needs to understand the DOM structure to correctly move and extend selections across elements.
    * **CSS:** CSS styling affects the visual presentation of the text and the layout. The C++ code needs to be aware of the layout (e.g., line breaks, writing modes) to accurately calculate selection boundaries. The `AbsoluteCaretBoundsOf` function hints at this interaction.

6. **Logical Reasoning and Assumptions:**  Consider scenarios and potential inputs/outputs:

    * **Assumption:**  User presses the right arrow key.
    * **Input:** `alter = kMove`, `direction = kRight`, `granularity = kCharacter`.
    * **Output:** The text cursor moves one character to the right.
    * **Assumption:** User holds Shift and presses the right arrow key.
    * **Input:** `alter = kExtend`, `direction = kRight`, `granularity = kCharacter`.
    * **Output:** The selection extends one character to the right.

7. **Identifying Potential Errors:** Think about common user or programming errors:

    * **User Error:**  Trying to select text in a non-selectable area.
    * **Programming Error:** Incorrectly calculating the new selection position, leading to unexpected selection behavior. For example, not handling edge cases like the beginning or end of a text node. Forgetting to update the rendering after modifying the selection could also be an error.

8. **Tracing User Interaction:**  Map user actions to the code:

    1. User presses the right arrow key.
    2. Browser detects the key press.
    3. An event handler (likely in JavaScript) is triggered.
    4. The JavaScript code might call a function related to selection manipulation.
    5. This call is eventually translated into a call to the `SelectionModifier::Modify` function in C++.

9. **Synthesizing and Summarizing:** Finally, combine all the information to create a concise summary of the code's functionality. Emphasize the core purpose, its interactions with web technologies, and its role in the overall user experience.

10. **Addressing the "Part 2" Request:**  Since this is part 2, the summarization should build upon the understanding gained from the previous part (although we don't have access to Part 1 in this case, we can still provide a comprehensive summary based on the provided snippet). The summary should focus on the functionality *within this specific snippet*.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive explanation of its functionality and its role in the Chromium Blink engine. The process involves code comprehension, logical reasoning, and knowledge of web technologies.
这是提供的 `blink/renderer/core/editing/selection_modifier.cc` 文件的第二部分，接续了第一部分的内容。从代码来看，它主要负责实现**修改文本选择**的功能，包括移动光标和扩展选择范围。

**归纳其功能:**

这部分代码主要实现了 `SelectionModifier` 类的以下功能：

1. **核心的 `Modify` 方法:**
   - 接收三个参数：修改类型 (`alter` - 移动或扩展)，修改方向 (`direction` - 上下左右前后) 和文本粒度 (`granularity` - 字符、单词、行、段落)。
   - 根据方向和修改类型，调用不同的内部方法 (`ModifyMovingRight`, `ModifyExtendingLeft` 等，这些方法在第一部分中定义)。
   - 在修改选择前，会调用 `PrepareToModifySelection` (也在第一部分) 来准备选择对象。
   - 考虑了空间导航 (spatial navigation) 的情况。
   - 对于行和段落粒度的修改，会调用 `UpdateAllLifecyclePhasesExceptPaint` 来更新布局信息。
   - 在扩展选择时，考虑了多种边界情况和浏览器行为差异，例如是否允许跨越锚点进行选择，以及在扩展到边界时是否始终增长选择范围。
   - 最终更新 `current_selection_` 成员变量。

2. **`ModifyWithPageGranularity` 方法:**
   - 实现按页或者指定垂直距离修改选择的功能。
   - 接收修改类型、垂直距离和垂直方向作为参数。
   - 通过循环迭代 `PreviousLinePosition` 和 `NextLinePosition` 来逐行移动，直到达到指定的垂直距离。
   - 使用 `AbsoluteCaretY` 方法获取光标的绝对垂直位置。
   - 在移动到新位置后，更新 `current_selection_`。

3. **`AbsoluteCaretY` 静态方法:**
   - 计算给定位置光标的绝对垂直中心坐标。

4. **`LineDirectionPointForBlockDirectionNavigationOf` 静态方法:**
   -  获取用于块方向导航（例如，上下方向键）的参考点的水平或垂直坐标。这个方法故意忽略了 CSS 转换 (transforms)，以便在转换过的文本中向上仍然是相对于文本的向上。

5. **`LineDirectionPointForBlockDirectionNavigation` 方法:**
   -  管理 `x_pos_for_vertical_arrow_navigation_` 成员变量，用于在垂直方向移动时保持水平位置的一致性。
   -  如果 `x_pos_for_vertical_arrow_navigation_` 没有设置，则调用 `LineDirectionPointForBlockDirectionNavigationOf` 计算并缓存。

6. **`UpdateAllLifecyclePhasesExceptPaint` 方法:**
   -  强制进行布局更新，但不包括最终的绘制阶段。这确保了选择修改操作基于最新的布局信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **功能关系:** JavaScript 可以通过 `document.getSelection()` API 获取和修改当前页面的文本选择。当用户在页面上进行选择操作（例如，拖动鼠标、使用键盘快捷键）时，浏览器会调用底层的 C++ 代码来执行选择修改。`SelectionModifier` 类就是处理这些请求的核心部分。
    - **举例说明:** 当 JavaScript 代码调用 `window.getSelection().modify('move', 'forward', 'word')` 时，最终会触发 `SelectionModifier::Modify` 方法，其中 `alter` 为 `kMove`，`direction` 为 `kForward`，`granularity` 为 `kWord`。

* **HTML:**
    - **功能关系:** HTML 结构定义了页面的内容，包括文本节点。`SelectionModifier` 需要理解 HTML 结构，以便正确地移动光标和扩展选择范围，例如跨越不同的 HTML 元素。
    - **举例说明:** 考虑以下 HTML 片段：`<p>This is <b>bold</b> text.</p>`。当用户选择 "is bo" 这部分文本时，`SelectionModifier` 需要知道 "is " 和 "bold" 属于不同的 HTML 节点，并能正确地处理跨节点的选择。

* **CSS:**
    - **功能关系:** CSS 样式影响文本的布局和渲染。`SelectionModifier` 需要考虑 CSS 的影响，例如文本的换行、行高、书写模式 (writing-mode) 等，才能准确地计算光标位置和选择范围。`LineDirectionPointForBlockDirectionNavigationOf` 方法中提到忽略 `transforms`，暗示了 `SelectionModifier` 需要与布局引擎紧密配合。
    - **举例说明:** 如果一段文本设置了 `word-break: break-all;` 样式，那么 `SelectionModifier` 在进行单词粒度的选择时，需要按照 CSS 定义的单词边界进行处理。

**逻辑推理、假设输入与输出:**

**假设输入 1:**

* `alter`: `SelectionModifyAlteration::kMove` (移动)
* `direction`: `SelectionModifyDirection::kRight` (向右)
* `granularity`: `TextGranularity::kCharacter` (字符)

**假设输出 1:**

光标向右移动一个字符的位置。如果当前光标位于 "abc" 的 'b' 之后，移动后将位于 'c' 之后。

**假设输入 2:**

* `alter`: `SelectionModifyAlteration::kExtend` (扩展)
* `direction`: `SelectionModifyDirection::kBackward` (向后)
* `granularity`: `TextGranularity::kWord` (单词)

**假设输出 2:**

选择范围向后扩展一个单词。如果当前选择是 "def" 中的 "e"，并且锚点在 'd' 之前，扩展后选择范围可能变为 "def"。

**用户或编程常见的使用错误:**

1. **编程错误:** 在实现自定义的文本编辑功能时，错误地计算或传递 `alter`、`direction` 或 `granularity` 参数，导致选择行为不符合预期。例如，本应是移动光标的操作，错误地设置为了扩展选择。
2. **用户错误 (间接):** 用户可能会在一些特殊情况下遇到非预期的选择行为，这可能是由于浏览器内部的逻辑复杂性导致的。例如，在复杂的富文本编辑器中，选择行为可能受到多种因素的影响。
3. **与异步操作的冲突:** 如果在 JavaScript 中异步修改了 DOM 结构，而 `SelectionModifier` 的操作依赖于旧的 DOM 结构，可能会导致错误的选择。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户进行选择操作:** 用户可能通过以下方式触发选择修改：
   - **键盘操作:** 按下方向键（配合 Shift 键进行选择扩展）、Home、End、Page Up、Page Down 等键。
   - **鼠标操作:** 点击并拖动鼠标来选中一段文本。
   - **使用浏览器的编辑功能:** 例如，在 `contenteditable` 元素中进行编辑。

2. **浏览器事件捕获:** 浏览器捕获用户的操作，例如 `keydown`、`mouseup`、`mousemove` 等事件。

3. **事件处理和 JavaScript 调用:** 浏览器的事件处理机制会触发相应的 JavaScript 代码。对于选择相关的操作，JavaScript 代码可能会调用 `document.getSelection()` API 获取 Selection 对象，并调用其 `modify()` 方法，或者直接操作 Selection 对象的 `anchorNode`、`focusNode` 等属性。

4. **Blink 渲染引擎接收请求:** JavaScript 的选择操作最终会传递到 Blink 渲染引擎的 C++ 代码中。

5. **调用 `SelectionModifier`:**  当需要修改选择时，相关的代码会创建或获取 `SelectionModifier` 对象，并调用其 `Modify` 或 `ModifyWithPageGranularity` 方法，传入相应的参数 (alter, direction, granularity 等)。

6. **执行选择修改逻辑:** `SelectionModifier` 根据传入的参数，执行相应的内部逻辑，更新选择范围。

7. **更新渲染:** 选择修改完成后，Blink 渲染引擎会更新页面的渲染，以反映新的选择状态。

**调试线索:**

* **断点设置:** 在 `SelectionModifier::Modify` 和 `SelectionModifier::ModifyWithPageGranularity` 方法入口处设置断点，可以观察传入的参数，了解是哪个用户操作触发了选择修改。
* **调用堆栈分析:** 查看调用堆栈，可以追溯到是哪个 JavaScript 代码或浏览器内部机制调用了 `SelectionModifier`。
* **日志输出:** 在关键路径上添加日志输出，记录选择修改的各个阶段的状态，例如修改前后的选择范围、光标位置等。
* **DOM 状态检查:** 在选择修改前后检查 DOM 结构，确认 DOM 结构是否符合预期，以及是否存在异步修改 DOM 导致的问题。

总而言之，这段代码是 Chromium Blink 引擎中处理文本选择修改的核心组件，它响应用户的交互，并与 JavaScript、HTML 和 CSS 紧密配合，确保用户在网页上的文本选择操作能够正确执行。

### 提示词
```
这是目录为blink/renderer/core/editing/selection_modifier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
on direction,
    TextGranularity granularity) {
  switch (direction) {
    case SelectionModifyDirection::kRight:
      if (alter == SelectionModifyAlteration::kMove)
        return ModifyMovingRight(granularity);
      return ModifyExtendingRight(granularity);
    case SelectionModifyDirection::kForward:
      if (alter == SelectionModifyAlteration::kExtend)
        return ModifyExtendingForward(granularity);
      return ModifyMovingForward(granularity);
    case SelectionModifyDirection::kLeft:
      if (alter == SelectionModifyAlteration::kMove)
        return ModifyMovingLeft(granularity);
      return ModifyExtendingLeft(granularity);
    case SelectionModifyDirection::kBackward:
      if (alter == SelectionModifyAlteration::kExtend)
        return ModifyExtendingBackward(granularity);
      return ModifyMovingBackward(granularity);
  }
  NOTREACHED() << static_cast<int>(direction);
}

bool SelectionModifier::Modify(SelectionModifyAlteration alter,
                               SelectionModifyDirection direction,
                               TextGranularity granularity) {
  DCHECK(!GetFrame().GetDocument()->NeedsLayoutTreeUpdate());
  if (granularity == TextGranularity::kLine ||
      granularity == TextGranularity::kParagraph)
    UpdateAllLifecyclePhasesExceptPaint();
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetFrame().GetDocument()->Lifecycle());

  selection_ = PrepareToModifySelection(alter, direction);
  if (selection_.IsNone())
    return false;

  bool was_range = selection_.IsRange();
  VisiblePositionInFlatTree original_start_position = selection_.VisibleStart();
  VisiblePositionInFlatTree position =
      ComputeModifyPosition(alter, direction, granularity);
  if (position.IsNull())
    return false;

  if (IsSpatialNavigationEnabled(&GetFrame())) {
    if (!was_range && alter == SelectionModifyAlteration::kMove &&
        position.DeepEquivalent() == original_start_position.DeepEquivalent())
      return false;
  }

  // Some of the above operations set an xPosForVerticalArrowNavigation.
  // Setting a selection will clear it, so save it to possibly restore later.
  // Note: the START position type is arbitrary because it is unused, it would
  // be the requested position type if there were no
  // xPosForVerticalArrowNavigation set.
  LayoutUnit x =
      LineDirectionPointForBlockDirectionNavigation(selection_.Start());

  switch (alter) {
    case SelectionModifyAlteration::kMove:
      current_selection_ = SelectionInFlatTree::Builder()
                               .Collapse(position.ToPositionWithAffinity())
                               .Build();
      break;
    case SelectionModifyAlteration::kExtend:

      if (!selection_.IsCaret() &&
          (granularity == TextGranularity::kWord ||
           granularity == TextGranularity::kParagraph ||
           granularity == TextGranularity::kLine) &&
          !GetFrame()
               .GetEditor()
               .Behavior()
               .ShouldExtendSelectionByWordOrLineAcrossCaret()) {
        // Don't let the selection go across the anchor position directly.
        // Needed to match mac behavior when, for instance, word-selecting
        // backwards starting with the caret in the middle of a word and then
        // word-selecting forward, leaving the caret in the same place where it
        // was, instead of directly selecting to the end of the word.
        const VisibleSelectionInFlatTree& new_selection =
            CreateVisibleSelection(
                SelectionInFlatTree::Builder(selection_.AsSelection())
                    .Extend(position.DeepEquivalent())
                    .Build());
        if (selection_.IsAnchorFirst() != new_selection.IsAnchorFirst()) {
          position = selection_.VisibleAnchor();
        }
      }

      // Standard Mac behavior when extending to a boundary is grow the
      // selection rather than leaving the anchor in place and moving the
      // focus. Matches NSTextView.
      if (!GetFrame()
               .GetEditor()
               .Behavior()
               .ShouldAlwaysGrowSelectionWhenExtendingToBoundary() ||
          selection_.IsCaret() || !IsBoundary(granularity)) {
        current_selection_ = SelectionInFlatTree::Builder()
                                 .Collapse(selection_.Anchor())
                                 .Extend(position.DeepEquivalent())
                                 .Build();
      } else {
        TextDirection text_direction = DirectionOfEnclosingBlock();
        if (direction == SelectionModifyDirection::kForward ||
            (text_direction == TextDirection::kLtr &&
             direction == SelectionModifyDirection::kRight) ||
            (text_direction == TextDirection::kRtl &&
             direction == SelectionModifyDirection::kLeft)) {
          current_selection_ =
              SelectionInFlatTree::Builder()
                  .Collapse(selection_.IsAnchorFirst()
                                ? selection_.Anchor()
                                : position.DeepEquivalent())
                  .Extend(selection_.IsAnchorFirst() ? position.DeepEquivalent()
                                                     : selection_.Focus())
                  .Build();
        } else {
          current_selection_ = SelectionInFlatTree::Builder()
                                   .Collapse(selection_.IsAnchorFirst()
                                                 ? position.DeepEquivalent()
                                                 : selection_.Anchor())
                                   .Extend(selection_.IsAnchorFirst()
                                               ? selection_.Focus()
                                               : position.DeepEquivalent())
                                   .Build();
        }
      }
      break;
  }

  if (granularity == TextGranularity::kLine ||
      granularity == TextGranularity::kParagraph)
    x_pos_for_vertical_arrow_navigation_ = x;

  return true;
}

// TODO(yosin): Maybe baseline would be better?
static bool AbsoluteCaretY(const PositionInFlatTreeWithAffinity& c, int& y) {
  gfx::Rect rect = AbsoluteCaretBoundsOf(c);
  if (rect.IsEmpty())
    return false;
  y = rect.y() + rect.height() / 2;
  return true;
}

bool SelectionModifier::ModifyWithPageGranularity(
    SelectionModifyAlteration alter,
    unsigned vertical_distance,
    SelectionModifyVerticalDirection direction) {
  if (!vertical_distance)
    return false;

  DCHECK(!GetFrame().GetDocument()->NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetFrame().GetDocument()->Lifecycle());

  selection_ = PrepareToModifySelection(
      alter, direction == SelectionModifyVerticalDirection::kUp
                 ? SelectionModifyDirection::kBackward
                 : SelectionModifyDirection::kForward);

  VisiblePositionInFlatTree pos;
  LayoutUnit x_pos;
  switch (alter) {
    case SelectionModifyAlteration::kMove:
      pos = CreateVisiblePosition(
          direction == SelectionModifyVerticalDirection::kUp
              ? selection_.Start()
              : selection_.End(),
          selection_.Affinity());
      x_pos = LineDirectionPointForBlockDirectionNavigation(
          direction == SelectionModifyVerticalDirection::kUp
              ? selection_.Start()
              : selection_.End());
      break;
    case SelectionModifyAlteration::kExtend:
      pos = ComputeVisibleFocus(selection_);
      x_pos = LineDirectionPointForBlockDirectionNavigation(selection_.Focus());
      break;
  }

  int start_y;
  DCHECK(pos.IsValid()) << pos;
  if (!AbsoluteCaretY(pos.ToPositionWithAffinity(), start_y))
    return false;
  if (direction == SelectionModifyVerticalDirection::kUp)
    start_y = -start_y;
  int last_y = start_y;

  VisiblePositionInFlatTree result;
  VisiblePositionInFlatTree next;
  unsigned iteration_count = 0;
  for (VisiblePositionInFlatTree p = pos;
       iteration_count < kMaxIterationForPageGranularityMovement; p = next) {
    ++iteration_count;

    if (direction == SelectionModifyVerticalDirection::kUp) {
      next = CreateVisiblePosition(
          PreviousLinePosition(p.ToPositionWithAffinity(), x_pos));
    } else {
      next = CreateVisiblePosition(
          NextLinePosition(p.ToPositionWithAffinity(), x_pos));
    }

    if (next.IsNull() || next.DeepEquivalent() == p.DeepEquivalent())
      break;
    int next_y;
    DCHECK(next.IsValid()) << next;
    if (!AbsoluteCaretY(next.ToPositionWithAffinity(), next_y))
      break;
    if (direction == SelectionModifyVerticalDirection::kUp)
      next_y = -next_y;
    if (next_y - start_y > static_cast<int>(vertical_distance))
      break;
    if (next_y >= last_y) {
      last_y = next_y;
      result = next;
    }
  }

  if (result.IsNull())
    return false;

  switch (alter) {
    case SelectionModifyAlteration::kMove:
      current_selection_ =
          SelectionInFlatTree::Builder()
              .Collapse(result.ToPositionWithAffinity())
              .SetAffinity(direction == SelectionModifyVerticalDirection::kUp
                               ? TextAffinity::kUpstream
                               : TextAffinity::kDownstream)
              .Build();
      break;
    case SelectionModifyAlteration::kExtend: {
      current_selection_ = SelectionInFlatTree::Builder()
                               .Collapse(selection_.Anchor())
                               .Extend(result.DeepEquivalent())
                               .Build();
      break;
    }
  }

  return true;
}

// Abs x/y position of the caret ignoring transforms.
// TODO(yosin) navigation with transforms should be smarter.
static LayoutUnit LineDirectionPointForBlockDirectionNavigationOf(
    const VisiblePositionInFlatTree& visible_position) {
  if (visible_position.IsNull())
    return LayoutUnit();

  const LocalCaretRect& caret_rect =
      LocalCaretRectOfPosition(visible_position.ToPositionWithAffinity());
  if (caret_rect.IsEmpty())
    return LayoutUnit();

  // This ignores transforms on purpose, for now. Vertical navigation is done
  // without consulting transforms, so that 'up' in transformed text is 'up'
  // relative to the text, not absolute 'up'.
  PhysicalOffset caret_point;
  if (caret_rect.layout_object->HasFlippedBlocksWritingMode()) [[unlikely]] {
    caret_point = caret_rect.rect.MaxXMinYCorner();
  } else {
    caret_point = caret_rect.rect.MinXMinYCorner();
  }
  caret_point = caret_rect.layout_object->LocalToAbsolutePoint(
      caret_point, kIgnoreTransforms);
  return caret_rect.layout_object->IsHorizontalWritingMode() ? caret_point.left
                                                             : caret_point.top;
}

LayoutUnit SelectionModifier::LineDirectionPointForBlockDirectionNavigation(
    const PositionInFlatTree& pos) {
  LayoutUnit x;

  if (selection_.IsNone())
    return x;

  if (x_pos_for_vertical_arrow_navigation_ ==
      NoXPosForVerticalArrowNavigation()) {
    VisiblePositionInFlatTree visible_position =
        CreateVisiblePosition(pos, selection_.Affinity());
    // VisiblePositionInFlatTree creation can fail here if a node containing the
    // selection becomes visibility:hidden after the selection is created and
    // before this function is called.
    x = LineDirectionPointForBlockDirectionNavigationOf(visible_position);
    x_pos_for_vertical_arrow_navigation_ = x;
  } else {
    x = x_pos_for_vertical_arrow_navigation_;
  }

  return x;
}

void SelectionModifier::UpdateAllLifecyclePhasesExceptPaint() {
  LocalFrameView* const frame_view = frame_->View();
  if (!frame_view)
    return;
  frame_view->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kSelection);
}

}  // namespace blink
```