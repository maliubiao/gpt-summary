Response:
Let's break down the thought process to analyze the `bidi_adjustment.cc` file.

**1. Initial Understanding - Core Purpose:**

The file name "bidi_adjustment.cc" immediately suggests its primary function: dealing with bidirectional text. "Adjustment" implies it modifies something related to bidi, likely cursor placement, hit testing, or selection. The copyright notice confirms it's part of the Chromium Blink engine.

**2. Key Data Structures and Concepts:**

* **`InlineCursor` and `InlineCaretPosition`:**  These appear fundamental to representing positions within inline text. The `InlineCursor` seems to be an iterator-like structure for navigating the inline layout. `InlineCaretPosition` likely represents the precise location of the cursor.
* **Bidi Levels (UBiDiLevel):** The inclusion of `<unicode/ubidi.h>` and the use of `UBiDiLevel` directly point to the Unicode Bidirectional Algorithm (UBA). This confirms the file's focus.
* **Text Direction (TextDirection):**  Related to bidi, but more basic (LTR/RTL).
* **AbstractInlineBox:** This is a crucial abstraction layer. The comments explicitly state its purpose: to handle differences between legacy and NG (Next Generation) inline layout. This signals a likely refactoring or ongoing evolution within Blink.
* **SideAffinity (kLeft, kRight):** This represents the "side" of an inline box, essential for placing the cursor correctly at boundaries.
* **Traversal Strategies (TraverseLeft, TraverseRight):**  These encapsulate the logic for moving through inline boxes in different directions, taking bidi into account.
* **Adjuster Classes (InlineCaretPositionResolutionAdjuster, HitTestAdjuster, RangeSelectionAdjuster):**  These classes implement the specific bidi adjustment logic for different operations (caret placement, hit testing, range selection).

**3. Functionality Breakdown (High-Level):**

Based on the class names and function names (`AdjustForInlineCaretPositionResolution`, `AdjustForHitTest`, `AdjustForRangeSelection`), the file seems to handle bidi adjustments in three main scenarios:

* **Cursor Placement (`AdjustForInlineCaretPositionResolution`):** Ensures the text editing cursor appears in the correct visual location when dealing with bidirectional text.
* **Hit Testing (`AdjustForHitTest`):**  When a user clicks or interacts with the text, this logic ensures the correct character or position is identified, even with bidi complexities.
* **Range Selection (`AdjustForRangeSelection`):**  When the user selects a range of text, this adjusts the selection boundaries to be visually consistent in bidirectional content.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The `dir` attribute is the primary way HTML influences bidi. The examples in the comments (e.g., `<div dir=ltr>...`) directly relate to how the code handles different text directions.
* **CSS:** CSS properties like `direction` and `unicode-bidi` influence the bidi algorithm. The code needs to respect these styles to function correctly.
* **JavaScript:** JavaScript can manipulate the DOM, including the `dir` attribute and text content, which can trigger the bidi adjustment logic. Cursor and selection APIs in JavaScript also rely on the correct bidi positioning provided by this code.

**5. Logical Reasoning and Examples:**

The comments within the code provide excellent examples. I'd focus on understanding those first. Then, I'd try to formulate my own simple test cases:

* **Input (Cursor Position):** Imagine a string "abc FED 123 CBA" (LTR, RTL, LTR, RTL). Where should the cursor go if I click *just* to the left of 'F'?  The bidi adjustment logic dictates this.
* **Output (Adjusted Cursor Position):** The code would adjust the cursor position to the *visual* left of 'F', even though logically it might be somewhere else in memory.
* **Input (Selection Range):** Select from 'c' in "abc" to '1' in "123". The bidi adjustment ensures the selection highlights the correct *visual* range, even if the underlying character order is different.
* **Output (Adjusted Selection Range):** The highlighted text would visually span from 'c' to '1'.

**6. Common User/Programming Errors:**

* **Incorrect `dir` Attribute:** Forgetting or incorrectly applying the `dir` attribute in HTML is a common mistake. This can lead to text being displayed in the wrong order.
* **Mixing LTR/RTL without Proper Markup:**  Simply pasting RTL text into an LTR context (or vice-versa) without using `<bdi>` or other appropriate markup can cause visual issues.
* **Assumptions About Logical vs. Visual Order:**  Programmers sometimes assume the order of characters in memory is the same as the visual order, which is incorrect for bidi text. This can lead to errors when manipulating text programmatically.

**7. Debugging Scenario:**

To illustrate how a user might reach this code:

1. **User Types/Pastes Text:** A user types or pastes text containing both LTR and RTL characters into a text field or editable area on a web page.
2. **Rendering:** The browser's layout engine renders the text, applying the bidi algorithm based on the HTML and CSS.
3. **Cursor Movement/Click:** The user moves the cursor using the arrow keys or clicks within the text.
4. **Hit Testing/Caret Position Calculation:** The browser needs to determine the precise location of the cursor. This involves hit testing, which calls into the `AdjustForHitTest` function in `bidi_adjustment.cc`.
5. **Bidi Adjustment:**  The `AdjustForHitTest` function analyzes the surrounding text and its bidi properties to ensure the cursor is placed in the visually correct position.

Alternatively, if the user is selecting text:

1. **User Initiates Selection:** The user starts selecting text by dragging the mouse or using keyboard shortcuts.
2. **Selection Boundary Calculation:**  As the selection changes, the browser calculates the start and end points of the selection.
3. **`AdjustForRangeSelection`:** The `AdjustForRangeSelection` function in `bidi_adjustment.cc` is called to adjust the selection boundaries based on bidi rules, ensuring a visually contiguous selection.

**Self-Correction/Refinement During Analysis:**

Initially, I might have focused too much on the low-level details of the code. However, recognizing the abstraction layers (like `AbstractInlineBox`) and the distinct adjuster classes helped me understand the higher-level organization and purpose of the file. The comments were invaluable for understanding the "why" behind certain logic, particularly the examples of bidi scenarios. Realizing the connection to specific web technologies (HTML `dir`, CSS `direction`, JavaScript selection APIs) provided further context.
这个文件 `blink/renderer/core/editing/bidi_adjustment.cc` 的主要功能是**处理在处理双向文本（Bidirectional text，简称 BiDi）时的光标位置、点击测试（hit test）和范围选择的调整**。其目标是确保在包含从左到右（LTR）和从右到左（RTL）文本的文档中，光标和选择行为符合用户的视觉预期。

以下是该文件的详细功能列表，并与 JavaScript、HTML 和 CSS 的关系进行说明：

**核心功能：**

1. **光标位置调整 (AdjustForInlineCaretPositionResolution):**
   - **功能:** 当 Blink 引擎需要确定光标的最终位置时，例如在用户输入或通过脚本设置光标位置后，此功能会根据双向文本的规则进行调整。
   - **与 JavaScript 的关系:** JavaScript 可以通过 `Selection` API 或直接操作 DOM 来设置光标位置。此调整功能确保 JavaScript 设置的光标最终出现在视觉上正确的位置。
   - **与 HTML 的关系:** HTML 的 `dir` 属性（例如 `<div dir="rtl">`）会影响文本的方向性。此调整功能会考虑这些属性。
   - **与 CSS 的关系:** CSS 的 `direction` 属性（例如 `direction: rtl;`）和 `unicode-bidi` 属性也会影响文本方向。此调整功能需要与这些 CSS 属性保持一致。
   - **假设输入与输出:**
     - **假设输入:** 光标逻辑上位于一段 RTL 文本的开始位置。
     - **输出:** 调整后的光标位置可能仍然在逻辑起始位置，但其视觉位置会反映 RTL 文本的起始（最右边）。
   - **用户或编程常见错误:**
     - **用户错误:** 用户可能期望在 RTL 文本中，通过左箭头键移动光标到“前一个字符”，但实际逻辑上的前一个字符可能在视觉上的右边。此调整有助于解决这种用户预期与实际行为的差异。
     - **编程错误:** JavaScript 代码可能简单地通过偏移量来设置光标位置，而没有考虑到文本的双向性。此调整功能作为浏览器内部机制，可以纠正这种潜在的错误。

2. **点击测试调整 (AdjustForHitTest):**
   - **功能:** 当用户点击页面上的文本时，浏览器需要确定用户实际点击的是哪个字符或位置。在双向文本中，视觉位置和逻辑位置可能不同，此功能用于将点击事件的坐标转换为正确的逻辑位置。
   - **与 JavaScript 的关系:** 当 JavaScript 监听 `click` 或 `mouseup` 等事件时，浏览器需要先通过 hit test 确定点击的目标。此调整影响了 JavaScript 事件处理程序接收到的目标信息。
   - **与 HTML 的关系:** 元素的 `dir` 属性影响文本的布局，从而影响点击测试的结果。
   - **与 CSS 的关系:** CSS 的 `direction` 和 `unicode-bidi` 属性同样会影响文本布局，从而影响点击测试。
   - **假设输入与输出:**
     - **假设输入:** 用户点击了一段 RTL 文本视觉上的左边位置。
     - **输出:** 调整后的 hit test 结果可能会指向该 RTL 文本逻辑上的末尾位置。
   - **用户或编程常见错误:**
     - **用户错误:** 用户可能点击一段 RTL 文本的左侧，期望选中该文本的开头，但在没有正确的 hit test 调整下，可能会选中其他位置。
     - **编程错误:** JavaScript 代码如果直接使用点击坐标来推断字符位置，在双向文本场景下可能会出错。浏览器的 hit test 调整是确保这类操作正确性的基础。

3. **范围选择调整 (AdjustForRangeSelection):**
   - **功能:** 当用户选择一段文本范围时，此功能会根据双向文本的规则调整选择的起始和结束位置，以确保选择的范围在视觉上是连续的。
   - **与 JavaScript 的关系:** JavaScript 可以通过 `Selection` API 获取和设置选择范围。此调整确保 JavaScript 获取到的选择范围在双向文本中是符合视觉预期的。
   - **与 HTML 的关系:** HTML 的 `dir` 属性决定了文本的基本方向，影响选择的视觉顺序。
   - **与 CSS 的关系:** CSS 的 `direction` 和 `unicode-bidi` 属性影响文本的布局，从而影响选择的视觉范围。
   - **假设输入与输出:**
     - **假设输入:** 用户从一段 LTR 文本拖动鼠标到一段 RTL 文本。
     - **输出:** 调整后的选择范围会确保视觉上连续地覆盖从 LTR 文本的起始到 RTL 文本的结尾（或反之），即使逻辑上的字符顺序不是这样。
   - **用户或编程常见错误:**
     - **用户错误:** 用户可能期望通过拖动鼠标从左到右选择文本，但在双向文本混合的情况下，没有调整的选择可能不会覆盖期望的视觉范围。
     - **编程错误:** JavaScript 代码如果简单地基于字符索引来创建选择范围，在双向文本中可能会导致选择不连贯或覆盖错误的字符。

**内部机制和抽象：**

- 文件中定义了一些辅助函数和类，例如 `AbstractInlineBox` 和 `AbstractInlineBoxAndSideAffinity`，用于抽象和处理文本布局中的不同元素和位置。
- 使用了 Unicode 的双向算法 (UBA) 相关概念，例如 Bidi Level。
- 定义了不同的“遍历策略”（TraverseLeft, TraverseRight）来处理在不同方向上的文本遍历。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载包含双向文本的网页:** 网页的 HTML 结构中可能包含带有 `dir="rtl"` 或 `direction: rtl;` 样式的元素，导致页面上出现 RTL 文本。
2. **用户进行文本交互:**
   - **输入文本:** 用户在一个可编辑区域（例如 `<textarea>` 或设置了 `contenteditable` 属性的 `div`）中输入文本，包括 LTR 和 RTL 字符的混合。
   - **移动光标:** 用户使用键盘上的箭头键或者鼠标点击来移动光标。
   - **选择文本:** 用户通过拖动鼠标或者使用 Shift 键 + 箭头键来选择文本范围。
3. **Blink 引擎处理用户操作:**
   - **光标移动:** 当用户移动光标时，Blink 引擎需要确定光标的新位置。这时会调用 `BidiAdjustment::AdjustForInlineCaretPositionResolution` 来确保光标停留在视觉上正确的位置。
   - **点击事件:** 当用户点击文本时，浏览器会进行 hit test 以确定点击的目标位置。这时会调用 `BidiAdjustment::AdjustForHitTest` 来将点击坐标转换为正确的逻辑位置。
   - **范围选择:** 当用户选择文本范围时，Blink 引擎会计算选择的起始和结束位置。这时会调用 `BidiAdjustment::AdjustForRangeSelection` 来调整选择范围，确保在双向文本中选择的视觉连续性。

**调试线索:**

如果在处理双向文本时遇到光标位置不正确、点击事件目标错误或选择范围不符合预期的问题，那么 `bidi_adjustment.cc` 文件中的代码就是关键的调试点。可以通过以下方式进行调试：

- **断点调试:** 在相关函数（例如 `AdjustForInlineCaretPositionResolution`、`AdjustForHitTest`、`AdjustForRangeSelection`）中设置断点，观察代码的执行流程和变量的值，特别是与 Bidi Level、文本方向等相关的变量。
- **日志输出:** 在关键代码路径中添加日志输出，记录中间计算结果，例如调整前后的光标位置、hit test 的结果、选择范围的起始和结束位置。
- **理解双向算法:** 熟悉 Unicode 双向算法 (UBA) 的规则，有助于理解代码的逻辑和预期行为。
- **测试用例:** 创建包含各种双向文本组合的测试用例，覆盖不同的用户交互场景，以便复现和诊断问题。

总而言之，`bidi_adjustment.cc` 文件是 Chromium Blink 引擎中处理复杂双向文本布局和用户交互的关键组件，它确保了在包含 LTR 和 RTL 文本的网页上，光标、点击和选择行为能够符合用户的直觉和预期。

### 提示词
```
这是目录为blink/renderer/core/editing/bidi_adjustment.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"

#include <unicode/ubidi.h>

#include "third_party/blink/renderer/core/editing/inline_box_position.h"
#include "third_party/blink/renderer/core/editing/ng_flat_tree_shorthands.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/layout/inline/inline_caret_position.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"

namespace blink {

namespace {

// Gets the resolved direction for any inline, including non-atomic inline
// boxes.
TextDirection ResolvedDirection(const InlineCursor& cursor) {
  if (cursor.Current().IsText() || cursor.Current().IsAtomicInline())
    return cursor.Current().ResolvedDirection();

  // TODO(abotella): We should define the |TextDirection| of an inline box,
  // which is used to determine at which edge of a non-editable box to place the
  // text editing caret. We currently use the line's base direction, but this is
  // wrong:
  //   <div dir=ltr>abc A<span>B</span>C abc</div>
  InlineCursor line_box;
  line_box.MoveTo(cursor);
  line_box.MoveToContainingLine();
  return line_box.Current().BaseDirection();
}

// Gets the bidi level for any inline, including non-atomic inline boxes.
UBiDiLevel BidiLevel(const InlineCursor& cursor) {
  if (cursor.Current().IsText() || cursor.Current().IsAtomicInline())
    return cursor.Current().BidiLevel();

  // TODO(abotella): Just like the |TextDirection| of an inline box, the bidi
  // level of an inline box should also be defined. Since |ResolvedDirection|
  // defaults to the line's base direction, though, we use the corresponding
  // base level here.
  InlineCursor line_box;
  line_box.MoveTo(cursor);
  line_box.MoveToContainingLine();
  return IsLtr(line_box.Current().BaseDirection()) ? 0 : 1;
}

// |AbstractInlineBox| provides abstraction of leaf nodes (text and atomic
// inlines) in both legacy and NG inline layout, so that the same bidi
// adjustment algorithm can be applied on both types of inline layout.
//
// TODO(1229581): Remove this abstraction.
class AbstractInlineBox {
  STACK_ALLOCATED();

 public:
  AbstractInlineBox() : type_(InstanceType::kNull) {}

  explicit AbstractInlineBox(const InlineCursor& cursor)
      : type_(InstanceType::kNG),
        line_cursor_(CreateLineRootedCursor(cursor)) {}

  bool IsNotNull() const { return type_ != InstanceType::kNull; }
  bool IsNull() const { return !IsNotNull(); }

  bool operator==(const AbstractInlineBox& other) const {
    if (type_ != other.type_)
      return false;
    switch (type_) {
      case InstanceType::kNull:
        return true;
      case InstanceType::kNG:
        return line_cursor_ == other.line_cursor_;
    }
    NOTREACHED();
  }

  // Returns containing block rooted cursor instead of line rooted cursor for
  // ease of handling, e.g. equiality check, move to next/previous line, etc.
  InlineCursor GetCursor() const {
    return line_cursor_.CursorForMovingAcrossFragmentainer();
  }

  UBiDiLevel BidiLevel() const {
    DCHECK(IsNotNull());
    return ::blink::BidiLevel(line_cursor_);
  }

  TextDirection Direction() const {
    DCHECK(IsNotNull());
    return ResolvedDirection(line_cursor_);
  }

  AbstractInlineBox PrevLeafChild() const {
    DCHECK(IsNotNull());
    InlineCursor cursor(line_cursor_);
    cursor.MoveToPreviousInlineLeaf();
    return cursor ? AbstractInlineBox(cursor) : AbstractInlineBox();
  }

  AbstractInlineBox PrevLeafChildIgnoringLineBreak() const {
    DCHECK(IsNotNull());
    InlineCursor cursor(line_cursor_);
    cursor.MoveToPreviousInlineLeafIgnoringLineBreak();
    return cursor ? AbstractInlineBox(cursor) : AbstractInlineBox();
  }

  AbstractInlineBox NextLeafChild() const {
    DCHECK(IsNotNull());
    InlineCursor cursor(line_cursor_);
    cursor.MoveToNextInlineLeaf();
    return cursor ? AbstractInlineBox(cursor) : AbstractInlineBox();
  }

  AbstractInlineBox NextLeafChildIgnoringLineBreak() const {
    DCHECK(IsNotNull());
    InlineCursor cursor(line_cursor_);
    cursor.MoveToNextInlineLeafIgnoringLineBreak();
    return cursor ? AbstractInlineBox(cursor) : AbstractInlineBox();
  }

  TextDirection ParagraphDirection() const {
    DCHECK(IsNotNull());
    return GetLineBox(line_cursor_).Current().BaseDirection();
  }

 private:
  static InlineCursor CreateLineRootedCursor(const InlineCursor& cursor) {
    InlineCursor line_cursor = GetLineBox(cursor).CursorForDescendants();
    line_cursor.MoveTo(cursor);
    return line_cursor;
  }

  // Returns containing line box of |cursor| even if |cursor| is scoped inside
  // line.
  static InlineCursor GetLineBox(const InlineCursor& cursor) {
    InlineCursor line_box;
    line_box.MoveTo(cursor);
    line_box.MoveToContainingLine();
    return line_box;
  }

  enum class InstanceType { kNull, kNG };
  InstanceType type_;

  // Because of |MoveToContainingLine()| isn't cheap and we avoid to call each
  // |MoveTo{Next,Previous}InlineLeaf()|, we hold containing line rooted cursor
  // instead of containing block rooted cursor.
  InlineCursor line_cursor_;
};

// |SideAffinity| represents the left or right side of a leaf inline
// box/fragment. For example, with text box/fragment "abc", "|abc" is the left
// side, and "abc|" is the right side.
enum SideAffinity { kLeft, kRight };

// Returns whether |caret_position| is at the start of its fragment.
bool IsAtFragmentStart(const InlineCaretPosition& caret_position) {
  switch (caret_position.position_type) {
    case InlineCaretPositionType::kBeforeBox:
      return true;
    case InlineCaretPositionType::kAfterBox:
      return false;
    case InlineCaretPositionType::kAtTextOffset:
      DCHECK(caret_position.text_offset.has_value());
      return *caret_position.text_offset ==
             caret_position.cursor.Current().TextStartOffset();
  }
  NOTREACHED();
}

// Returns whether |caret_position| is at the end of its fragment.
bool IsAtFragmentEnd(const InlineCaretPosition& caret_position) {
  switch (caret_position.position_type) {
    case InlineCaretPositionType::kBeforeBox:
      return false;
    case InlineCaretPositionType::kAfterBox:
      return true;
    case InlineCaretPositionType::kAtTextOffset:
      DCHECK(caret_position.text_offset.has_value());
      return *caret_position.text_offset ==
             caret_position.cursor.Current().TextEndOffset();
  }
  NOTREACHED();
}

// Returns whether |caret_position| is at the left or right side of fragment.
SideAffinity GetSideAffinity(const InlineCaretPosition& caret_position) {
  DCHECK(!caret_position.IsNull());
  DCHECK(IsAtFragmentStart(caret_position) || IsAtFragmentEnd(caret_position));
  const bool is_at_start = IsAtFragmentStart(caret_position);
  const bool is_at_left_side =
      is_at_start == IsLtr(ResolvedDirection(caret_position.cursor));
  return is_at_left_side ? SideAffinity::kLeft : SideAffinity::kRight;
}

// An abstraction of a caret position that is at the left or right side of a
// leaf inline box/fragment. The abstraction allows the object to be used in
// bidi adjustment algorithm for both legacy and NG.
class AbstractInlineBoxAndSideAffinity {
  STACK_ALLOCATED();

 public:
  AbstractInlineBoxAndSideAffinity(const AbstractInlineBox& box,
                                   SideAffinity side)
      : box_(box), side_(side) {
    DCHECK(box_.IsNotNull());
  }

  explicit AbstractInlineBoxAndSideAffinity(
      const InlineCaretPosition& caret_position)
      : box_(caret_position.cursor), side_(GetSideAffinity(caret_position)) {
    DCHECK(!caret_position.IsNull());
  }

  InlineCaretPosition ToInlineCaretPosition() const {
    DCHECK(box_.IsNotNull());
    const bool is_at_start = IsLtr(box_.Direction()) == AtLeftSide();
    InlineCursor cursor(box_.GetCursor());

    if (!cursor.Current().IsText()) {
      return {cursor,
              is_at_start ? InlineCaretPositionType::kBeforeBox
                          : InlineCaretPositionType::kAfterBox,
              std::nullopt};
    }

    return {cursor, InlineCaretPositionType::kAtTextOffset,
            is_at_start ? cursor.Current().TextStartOffset()
                        : cursor.Current().TextEndOffset()};
  }

  PositionInFlatTree GetPosition() const {
    DCHECK(box_.IsNotNull());
    return ToPositionInFlatTree(ToInlineCaretPosition().ToPositionInDOMTree());
  }

  AbstractInlineBox GetBox() const { return box_; }
  bool AtLeftSide() const { return side_ == SideAffinity::kLeft; }
  bool AtRightSide() const { return side_ == SideAffinity::kRight; }

 private:
  AbstractInlineBox box_;
  SideAffinity side_;
};

struct TraverseRight;

// "Left" traversal strategy
struct TraverseLeft {
  STATIC_ONLY(TraverseLeft);

  using Backwards = TraverseRight;

  static AbstractInlineBox Forward(const AbstractInlineBox& box) {
    return box.PrevLeafChild();
  }

  static AbstractInlineBox ForwardIgnoringLineBreak(
      const AbstractInlineBox& box) {
    return box.PrevLeafChildIgnoringLineBreak();
  }

  static AbstractInlineBox Backward(const AbstractInlineBox& box);
  static AbstractInlineBox BackwardIgnoringLineBreak(
      const AbstractInlineBox& box);

  static SideAffinity ForwardSideAffinity() { return SideAffinity::kLeft; }
};

// "Left" traversal strategy
struct TraverseRight {
  STATIC_ONLY(TraverseRight);

  using Backwards = TraverseLeft;

  static AbstractInlineBox Forward(const AbstractInlineBox& box) {
    return box.NextLeafChild();
  }

  static AbstractInlineBox ForwardIgnoringLineBreak(
      const AbstractInlineBox& box) {
    return box.NextLeafChildIgnoringLineBreak();
  }

  static AbstractInlineBox Backward(const AbstractInlineBox& box) {
    return Backwards::Forward(box);
  }

  static AbstractInlineBox BackwardIgnoringLineBreak(
      const AbstractInlineBox& box) {
    return Backwards::ForwardIgnoringLineBreak(box);
  }

  static SideAffinity ForwardSideAffinity() { return SideAffinity::kRight; }
};

// static
AbstractInlineBox TraverseLeft::Backward(const AbstractInlineBox& box) {
  return Backwards::Forward(box);
}

// static
AbstractInlineBox TraverseLeft::BackwardIgnoringLineBreak(
    const AbstractInlineBox& box) {
  return Backwards::ForwardIgnoringLineBreak(box);
}

template <typename TraversalStrategy>
using Backwards = typename TraversalStrategy::Backwards;

template <typename TraversalStrategy>
AbstractInlineBoxAndSideAffinity AbstractInlineBoxAndForwardSideAffinity(
    const AbstractInlineBox& box) {
  return AbstractInlineBoxAndSideAffinity(
      box, TraversalStrategy::ForwardSideAffinity());
}

template <typename TraversalStrategy>
AbstractInlineBoxAndSideAffinity AbstractInlineBoxAndBackwardSideAffinity(
    const AbstractInlineBox& box) {
  return AbstractInlineBoxAndForwardSideAffinity<Backwards<TraversalStrategy>>(
      box);
}

// Template algorithms for traversing in bidi runs

// Traverses from |start|, and returns the first box with bidi level less than
// or equal to |bidi_level| (excluding |start| itself). Returns a null box when
// such a box doesn't exist.
template <typename TraversalStrategy>
AbstractInlineBox FindBidiRun(const AbstractInlineBox& start,
                              unsigned bidi_level) {
  DCHECK(start.IsNotNull());
  for (AbstractInlineBox runner = TraversalStrategy::Forward(start);
       runner.IsNotNull(); runner = TraversalStrategy::Forward(runner)) {
    if (runner.BidiLevel() <= bidi_level)
      return runner;
  }
  return AbstractInlineBox();
}

// Traverses from |start|, and returns the last non-linebreak box with bidi
// level greater than |bidi_level| (including |start| itself).
template <typename TraversalStrategy>
AbstractInlineBox FindBoundaryOfBidiRunIgnoringLineBreak(
    const AbstractInlineBox& start,
    unsigned bidi_level) {
  DCHECK(start.IsNotNull());
  AbstractInlineBox last_runner = start;
  for (AbstractInlineBox runner =
           TraversalStrategy::ForwardIgnoringLineBreak(start);
       runner.IsNotNull();
       runner = TraversalStrategy::ForwardIgnoringLineBreak(runner)) {
    if (runner.BidiLevel() <= bidi_level)
      return last_runner;
    last_runner = runner;
  }
  return last_runner;
}

// Traverses from |start|, and returns the last box with bidi level greater than
// or equal to |bidi_level| (including |start| itself). Line break boxes may or
// may not be ignored, depending of the passed |forward| function.
AbstractInlineBox FindBoundaryOfEntireBidiRunInternal(
    const AbstractInlineBox& start,
    unsigned bidi_level,
    AbstractInlineBox (*forward)(const AbstractInlineBox&)) {
  DCHECK(start.IsNotNull());
  AbstractInlineBox last_runner = start;
  for (AbstractInlineBox runner = forward(start); runner.IsNotNull();
       runner = forward(runner)) {
    if (runner.BidiLevel() < bidi_level)
      return last_runner;
    last_runner = runner;
  }
  return last_runner;
}

// Variant of |FindBoundaryOfEntireBidiRun| preserving line break boxes.
template <typename TraversalStrategy>
AbstractInlineBox FindBoundaryOfEntireBidiRun(const AbstractInlineBox& start,
                                              unsigned bidi_level) {
  return FindBoundaryOfEntireBidiRunInternal(start, bidi_level,
                                             TraversalStrategy::Forward);
}

// Variant of |FindBoundaryOfEntireBidiRun| ignoring line break boxes.
template <typename TraversalStrategy>
AbstractInlineBox FindBoundaryOfEntireBidiRunIgnoringLineBreak(
    const AbstractInlineBox& start,
    unsigned bidi_level) {
  return FindBoundaryOfEntireBidiRunInternal(
      start, bidi_level, TraversalStrategy::ForwardIgnoringLineBreak);
}

// Adjustment algorithm at the end of caret position resolution.
template <typename TraversalStrategy>
class InlineCaretPositionResolutionAdjuster {
  STATIC_ONLY(InlineCaretPositionResolutionAdjuster);

 public:
  static AbstractInlineBoxAndSideAffinity UnadjustedInlineCaretPosition(
      const AbstractInlineBox& box) {
    return AbstractInlineBoxAndBackwardSideAffinity<TraversalStrategy>(box);
  }

  // Returns true if |box| starts different direction of embedded text run.
  // See [1] for details.
  // [1] UNICODE BIDIRECTIONAL ALGORITHM, http://unicode.org/reports/tr9/
  static bool IsStartOfDifferentDirection(const AbstractInlineBox&);

  static AbstractInlineBoxAndSideAffinity AdjustForPrimaryDirectionAlgorithm(
      const AbstractInlineBox& box) {
    if (IsStartOfDifferentDirection(box))
      return UnadjustedInlineCaretPosition(box);

    const unsigned level = TraversalStrategy::Backward(box).BidiLevel();
    const AbstractInlineBox forward_box =
        FindBidiRun<TraversalStrategy>(box, level);

    // For example, abc FED 123 ^ CBA when adjusting right side of 123
    if (forward_box.IsNotNull() && forward_box.BidiLevel() == level)
      return UnadjustedInlineCaretPosition(box);

    // For example, abc 123 ^ CBA when adjusting right side of 123
    const AbstractInlineBox result_box =
        FindBoundaryOfEntireBidiRun<Backwards<TraversalStrategy>>(box, level);
    return AbstractInlineBoxAndBackwardSideAffinity<TraversalStrategy>(
        result_box);
  }

  static AbstractInlineBoxAndSideAffinity AdjustFor(
      const AbstractInlineBox& box) {
    DCHECK(box.IsNotNull());

    const TextDirection primary_direction = box.ParagraphDirection();
    if (box.Direction() == primary_direction)
      return AdjustForPrimaryDirectionAlgorithm(box);

    const unsigned char level = box.BidiLevel();
    const AbstractInlineBox backward_box =
        TraversalStrategy::BackwardIgnoringLineBreak(box);
    if (backward_box.IsNull() || backward_box.BidiLevel() < level) {
      // Backward side of a secondary run. Set to the forward side of the entire
      // run.
      const AbstractInlineBox result_box =
          FindBoundaryOfEntireBidiRunIgnoringLineBreak<TraversalStrategy>(
              box, level);
      return AbstractInlineBoxAndForwardSideAffinity<TraversalStrategy>(
          result_box);
    }

    if (backward_box.BidiLevel() <= level)
      return UnadjustedInlineCaretPosition(box);

    // Forward side of a "tertiary" run. Set to the backward side of that run.
    const AbstractInlineBox result_box =
        FindBoundaryOfBidiRunIgnoringLineBreak<Backwards<TraversalStrategy>>(
            box, level);
    return AbstractInlineBoxAndBackwardSideAffinity<TraversalStrategy>(
        result_box);
  }
};

// TODO(editing-dev): Try to unify the algorithms for both directions.
template <>
bool InlineCaretPositionResolutionAdjuster<
    TraverseLeft>::IsStartOfDifferentDirection(const AbstractInlineBox& box) {
  DCHECK(box.IsNotNull());
  const AbstractInlineBox backward_box = TraverseRight::Forward(box);
  if (backward_box.IsNull())
    return true;
  return backward_box.BidiLevel() >= box.BidiLevel();
}

template <>
bool InlineCaretPositionResolutionAdjuster<
    TraverseRight>::IsStartOfDifferentDirection(const AbstractInlineBox& box) {
  DCHECK(box.IsNotNull());
  const AbstractInlineBox backward_box = TraverseLeft::Forward(box);
  if (backward_box.IsNull())
    return true;
  if (backward_box.Direction() == box.Direction())
    return true;
  return backward_box.BidiLevel() > box.BidiLevel();
}

// Adjustment algorithm at the end of hit tests.
template <typename TraversalStrategy>
class HitTestAdjuster {
  STATIC_ONLY(HitTestAdjuster);

 public:
  static AbstractInlineBoxAndSideAffinity UnadjustedHitTestPosition(
      const AbstractInlineBox& box) {
    return AbstractInlineBoxAndBackwardSideAffinity<TraversalStrategy>(box);
  }

  static AbstractInlineBoxAndSideAffinity AdjustFor(
      const AbstractInlineBox& box) {
    // TODO(editing-dev): Fix handling of left on 12CBA
    if (box.Direction() == box.ParagraphDirection())
      return UnadjustedHitTestPosition(box);

    const UBiDiLevel level = box.BidiLevel();

    const AbstractInlineBox backward_box =
        TraversalStrategy::BackwardIgnoringLineBreak(box);
    if (backward_box.IsNotNull() && backward_box.BidiLevel() == level)
      return UnadjustedHitTestPosition(box);

    if (backward_box.IsNotNull() && backward_box.BidiLevel() > level) {
      // e.g. left of B in aDC12BAb when adjusting left side
      const AbstractInlineBox backward_most_box =
          FindBoundaryOfBidiRunIgnoringLineBreak<Backwards<TraversalStrategy>>(
              backward_box, level);
      return AbstractInlineBoxAndForwardSideAffinity<TraversalStrategy>(
          backward_most_box);
    }

    // backward_box.IsNull() || backward_box.BidiLevel() < level
    // e.g. left of D in aDC12BAb when adjusting left side
    const AbstractInlineBox forward_most_box =
        FindBoundaryOfEntireBidiRunIgnoringLineBreak<TraversalStrategy>(box,
                                                                        level);
    return box.Direction() == forward_most_box.Direction()
               ? AbstractInlineBoxAndForwardSideAffinity<TraversalStrategy>(
                     forward_most_box)
               : AbstractInlineBoxAndBackwardSideAffinity<TraversalStrategy>(
                     forward_most_box);
  }
};

// Adjustment algorithm at the end of creating range selection
class RangeSelectionAdjuster {
  STATIC_ONLY(RangeSelectionAdjuster);

 public:
  static SelectionInFlatTree AdjustFor(
      const PositionInFlatTreeWithAffinity& visible_base,
      const PositionInFlatTreeWithAffinity& visible_extent) {
    const SelectionInFlatTree& unchanged_selection =
        SelectionInFlatTree::Builder()
            .SetBaseAndExtent(visible_base.GetPosition(),
                              visible_extent.GetPosition())
            .Build();

    if (RuntimeEnabledFeatures::BidiCaretAffinityEnabled()) {
      if (NGInlineFormattingContextOf(visible_base.GetPosition()) ||
          NGInlineFormattingContextOf(visible_extent.GetPosition()))
        return unchanged_selection;
    }

    RenderedPosition base = RenderedPosition::Create(visible_base);
    RenderedPosition extent = RenderedPosition::Create(visible_extent);

    if (base.IsNull() || extent.IsNull() || base == extent ||
        (!base.AtBidiBoundary() && !extent.AtBidiBoundary())) {
      return unchanged_selection;
    }

    if (base.AtBidiBoundary()) {
      if (ShouldAdjustBaseAtBidiBoundary(base, extent)) {
        const PositionInFlatTree adjusted_base =
            CreateVisiblePosition(base.GetPosition()).DeepEquivalent();
        return SelectionInFlatTree::Builder()
            .SetBaseAndExtent(adjusted_base, visible_extent.GetPosition())
            .Build();
      }
      return unchanged_selection;
    }

    if (ShouldAdjustExtentAtBidiBoundary(base, extent)) {
      const PositionInFlatTree adjusted_extent =
          CreateVisiblePosition(extent.GetPosition()).DeepEquivalent();
      return SelectionInFlatTree::Builder()
          .SetBaseAndExtent(visible_base.GetPosition(), adjusted_extent)
          .Build();
    }

    return unchanged_selection;
  }

 private:
  class RenderedPosition {
    STACK_ALLOCATED();

   public:
    RenderedPosition() = default;
    static RenderedPosition Create(const PositionInFlatTreeWithAffinity&);

    bool IsNull() const { return box_.IsNull(); }
    bool operator==(const RenderedPosition& other) const {
      return box_ == other.box_ &&
             bidi_boundary_type_ == other.bidi_boundary_type_;
    }

    bool AtBidiBoundary() const {
      return bidi_boundary_type_ != BidiBoundaryType::kNotBoundary;
    }

    // Given |other|, which is a boundary of a bidi run, returns true if |this|
    // can be the other boundary of that run by checking some conditions.
    bool IsPossiblyOtherBoundaryOf(const RenderedPosition& other) const {
      DCHECK(other.AtBidiBoundary());
      if (!AtBidiBoundary())
        return false;
      if (bidi_boundary_type_ == other.bidi_boundary_type_)
        return false;
      return box_.BidiLevel() >= other.box_.BidiLevel();
    }

    // Callable only when |this| is at boundary of a bidi run. Returns true if
    // |other| is in that bidi run.
    bool BidiRunContains(const RenderedPosition& other) const {
      DCHECK(AtBidiBoundary());
      DCHECK(!other.IsNull());
      UBiDiLevel level = box_.BidiLevel();
      if (level > other.box_.BidiLevel())
        return false;
      const AbstractInlineBox boundary_of_other =
          bidi_boundary_type_ == BidiBoundaryType::kLeftBoundary
              ? FindBoundaryOfEntireBidiRunIgnoringLineBreak<TraverseLeft>(
                    other.box_, level)
              : FindBoundaryOfEntireBidiRunIgnoringLineBreak<TraverseRight>(
                    other.box_, level);
      return box_ == boundary_of_other;
    }

    PositionInFlatTree GetPosition() const {
      DCHECK(AtBidiBoundary());
      DCHECK(box_.IsNotNull());
      const SideAffinity side =
          bidi_boundary_type_ == BidiBoundaryType::kLeftBoundary
              ? SideAffinity::kLeft
              : SideAffinity::kRight;
      return AbstractInlineBoxAndSideAffinity(box_, side).GetPosition();
    }

   private:
    enum class BidiBoundaryType { kNotBoundary, kLeftBoundary, kRightBoundary };
    RenderedPosition(const AbstractInlineBox& box, BidiBoundaryType type)
        : box_(box), bidi_boundary_type_(type) {}

    static BidiBoundaryType GetPotentialBidiBoundaryType(
        const InlineCaretPosition& caret_position) {
      DCHECK(!caret_position.IsNull());
      DCHECK(!RuntimeEnabledFeatures::BidiCaretAffinityEnabled());
      if (!IsAtFragmentStart(caret_position) &&
          !IsAtFragmentEnd(caret_position))
        return BidiBoundaryType::kNotBoundary;
      return GetSideAffinity(caret_position) == SideAffinity::kLeft
                 ? BidiBoundaryType::kLeftBoundary
                 : BidiBoundaryType::kRightBoundary;
    }

    // Helper function for Create().
    static RenderedPosition CreateUncanonicalized(
        const PositionInFlatTreeWithAffinity& position) {
      if (position.IsNull() || !position.AnchorNode()->GetLayoutObject())
        return RenderedPosition();
      const PositionInFlatTreeWithAffinity adjusted =
          ComputeInlineAdjustedPosition(position);
      if (adjusted.IsNull())
        return RenderedPosition();

      if (NGInlineFormattingContextOf(adjusted.GetPosition())) {
        const InlineCaretPosition caret_position =
            ComputeInlineCaretPosition(adjusted);
        if (caret_position.IsNull())
          return RenderedPosition();
        return RenderedPosition(AbstractInlineBox(caret_position.cursor),
                                GetPotentialBidiBoundaryType(caret_position));
      }
      return RenderedPosition();
    }

    AbstractInlineBox box_;
    BidiBoundaryType bidi_boundary_type_ = BidiBoundaryType::kNotBoundary;
  };

  static bool ShouldAdjustBaseAtBidiBoundary(const RenderedPosition& base,
                                             const RenderedPosition& extent) {
    DCHECK(base.AtBidiBoundary());
    if (extent.IsPossiblyOtherBoundaryOf(base))
      return false;
    return base.BidiRunContains(extent);
  }

  static bool ShouldAdjustExtentAtBidiBoundary(const RenderedPosition& base,
                                               const RenderedPosition& extent) {
    if (!extent.AtBidiBoundary())
      return false;
    return extent.BidiRunContains(base);
  }
};

RangeSelectionAdjuster::RenderedPosition
RangeSelectionAdjuster::RenderedPosition::Create(
    const PositionInFlatTreeWithAffinity& position) {
  const RenderedPosition uncanonicalized = CreateUncanonicalized(position);
  const BidiBoundaryType potential_type = uncanonicalized.bidi_boundary_type_;
  if (potential_type == BidiBoundaryType::kNotBoundary)
    return uncanonicalized;
  const AbstractInlineBox& box = uncanonicalized.box_;
  DCHECK(box.IsNotNull());

  // When at bidi boundary, ensure that |box_| belongs to the higher-level bidi
  // run.

  // For example, abc FED |ghi should be changed into abc FED| ghi
  if (potential_type == BidiBoundaryType::kLeftBoundary) {
    const AbstractInlineBox prev_box = box.PrevLeafChildIgnoringLineBreak();
    if (prev_box.IsNotNull() && prev_box.BidiLevel() > box.BidiLevel())
      return RenderedPosition(prev_box, BidiBoundaryType::kRightBoundary);
    BidiBoundaryType type =
        prev_box.IsNotNull() && prev_box.BidiLevel() == box.BidiLevel()
            ? BidiBoundaryType::kNotBoundary
            : BidiBoundaryType::kLeftBoundary;
    return RenderedPosition(box, type);
  }

  // potential_type == BidiBoundaryType::kRightBoundary
  // For example, abc| FED ghi should be changed into abc |FED ghi
  const AbstractInlineBox next_box = box.NextLeafChildIgnoringLineBreak();
  if (next_box.IsNotNull() && next_box.BidiLevel() > box.BidiLevel())
    return RenderedPosition(next_box, BidiBoundaryType::kLeftBoundary);
  BidiBoundaryType type =
      next_box.IsNotNull() && next_box.BidiLevel() == box.BidiLevel()
          ? BidiBoundaryType::kNotBoundary
          : BidiBoundaryType::kRightBoundary;
  return RenderedPosition(box, type);
}

}  // namespace

InlineCaretPosition BidiAdjustment::AdjustForInlineCaretPositionResolution(
    const InlineCaretPosition& caret_position) {
  DCHECK(!RuntimeEnabledFeatures::BidiCaretAffinityEnabled());
  const AbstractInlineBoxAndSideAffinity unadjusted(caret_position);
  const AbstractInlineBoxAndSideAffinity adjusted =
      unadjusted.AtLeftSide()
          ? InlineCaretPositionResolutionAdjuster<TraverseRight>::AdjustFor(
                unadjusted.GetBox())
          : InlineCaretPositionResolutionAdjuster<TraverseLeft>::AdjustFor(
                unadjusted.GetBox());
  return adjusted.ToInlineCaretPosition();
}

InlineCaretPosition BidiAdjustment::AdjustForHitTest(
    const InlineCaretPosition& caret_position) {
  DCHECK(!RuntimeEnabledFeatures::BidiCaretAffinityEnabled());
  const AbstractInlineBoxAndSideAffinity unadjusted(caret_position);
  const AbstractInlineBoxAndSideAffinity adjusted =
      unadjusted.AtLeftSide()
          ? HitTestAdjuster<TraverseRight>::AdjustFor(unadjusted.GetBox())
          : HitTestAdjuster<TraverseLeft>::AdjustFor(unadjusted.GetBox());
  return adjusted.ToInlineCaretPosition();
}

SelectionInFlatTree BidiAdjustment::AdjustForRangeSelection(
    const PositionInFlatTreeWithAffinity& base,
    const PositionInFlatTreeWithAffinity& extent) {
  return RangeSelectionAdjuster::AdjustFor(base, extent);
}

}  // namespace blink
```