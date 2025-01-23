Response:
My thinking process to analyze the `CachedTextInputInfo.cc` file went through these stages:

1. **Understand the Purpose:** The filename and the initial comments clearly indicate this class is about caching text input information. The "IME" in the path suggests it's related to Input Method Editors, which are used for entering text in languages with many characters. Caching implies optimizing performance by avoiding redundant computations.

2. **Identify Key Data Members:** I scanned the class definition (from the header, included in the `.cc` file) and the `.cc` file itself to identify the core data being managed:
    * `container_`:  A pointer to the `ContainerNode` (like a `div`, `textarea`, etc.) where the text input is happening.
    * `layout_object_`: A pointer to the `LayoutObject` associated with the container. Layout objects are part of the rendering engine.
    * `text_`: The actual text content of the input element.
    * `composition_`: A `CachedPlainTextRange` storing the range and offsets of the current IME composition.
    * `selection_`: A `CachedPlainTextRange` storing the range and offsets of the current text selection.
    * `offset_map_`: A map to quickly look up the starting offset of a `Text` node within the overall text content.

3. **Analyze Key Methods and Their Functionality:** I then went through the public and important private methods to understand what they do:
    * `EnsureCached()`: This is the core method for populating the cached information. It only does work if the cache is invalid. It uses `TextIterator` to walk through the content and build the `text_` and `offset_map_`.
    * `GetComposition()` and `GetSelection()`: These methods retrieve the cached composition and selection ranges, using `GetPlainTextRangeWithCache()` to manage the cached `PlainTextRange` objects.
    * `GetPlainTextRange()`:  This method calculates the `PlainTextRange` (start and end offsets) of a given `EphemeralRange` (a DOM range). It's the core logic for converting DOM ranges to text offsets.
    * `GetText()`:  Simply returns the cached text.
    * `IsValidFor()`: Checks if the cached information is still valid for the given container.
    * `Clear()` and `ClearIfNeeded()`:  Methods for invalidating the cache.
    * `DidLayoutSubtree()`, `DidUpdateLayout()`, `DidChangeVisibility()`: These are lifecycle methods that are called when the layout of the element changes, and they trigger cache invalidation if necessary.
    * `LayoutObjectWillBeDestroyed()`:  Another lifecycle method for clearing the cache when the layout object is destroyed.
    * `RangeLength()`: Calculates the length of a given `EphemeralRange`. It tries to optimize this by using the `offset_map_` if the range starts at the beginning of the container and ends within a `Text` node.

4. **Identify Relationships with Web Technologies:** I considered how the cached information relates to JavaScript, HTML, and CSS:
    * **HTML:** The `ContainerNode` represents HTML elements. The content being cached is the text content within those elements. Specifically, elements like `<input>`, `<textarea>`, and `contenteditable` divs are relevant.
    * **CSS:** CSS styling can affect the layout of the text, and layout changes are triggers for invalidating the cache. The `LayoutObject` is directly related to how the element is rendered based on CSS. Properties like `display`, `visibility`, `contain`, and even font sizes can indirectly impact this.
    * **JavaScript:** JavaScript interacts with the DOM, and changes made by JavaScript can affect the text content and selection, necessitating cache updates. Events like `input`, `keydown`, `keyup`, `select`, and `compositionstart`/`compositionupdate`/`compositionend` are all potential triggers.

5. **Consider User and Programming Errors:**  I thought about common mistakes that could lead to issues related to this code:
    * **Incorrectly manipulating the DOM:** Directly modifying the DOM in a way that bypasses Blink's update mechanisms could lead to an out-of-sync cache.
    * **Assumptions about layout:**  Making assumptions about when layout occurs and not invalidating the cache when necessary can lead to incorrect cached information.
    * **Off-by-one errors:** Calculating ranges and offsets is prone to these errors, especially when dealing with different units (DOM positions vs. text offsets).

6. **Develop Hypotheses for Input and Output:** I imagined scenarios to illustrate how the caching works:
    * **Initial Input:** When a user starts typing in a text field, `EnsureCached()` is likely called. The input text becomes the cached `text_`.
    * **IME Composition:**  When using an IME, `GetComposition()` would be used to retrieve the range of the currently composing text.
    * **Selection Change:** When the user selects text, `GetSelection()` would be used.

7. **Trace User Operations to the Code:** I walked through common user interactions to see how they might lead to this code being executed:
    * Typing in a text field.
    * Using an IME to input text.
    * Selecting text with the mouse or keyboard.
    * Programmatically changing the content or selection using JavaScript.
    * Resizing the window or causing other layout changes.

8. **Structure the Explanation:**  Finally, I organized my findings into clear sections covering functionality, relationships with web technologies, errors, hypotheses, and debugging. I used examples to make the explanations concrete.

This iterative process of understanding the code's purpose, identifying key components, analyzing methods, considering interactions, and developing concrete examples allowed me to create a comprehensive explanation of the `CachedTextInputInfo.cc` file.
这个文件 `blink/renderer/core/editing/ime/cached_text_input_info.cc` 的主要功能是**缓存与文本输入相关的信息，特别是为了优化输入法编辑器 (IME) 的操作**。 它避免了在每次需要时都重新计算这些信息，从而提高了性能。

以下是该文件的详细功能分解：

**核心功能：缓存文本输入信息**

* **缓存文本内容 (`text_`)**:  存储当前可编辑区域的完整文本内容。
* **缓存布局对象 (`layout_object_`)**:  存储与可编辑区域关联的布局对象。这对于判断缓存是否有效至关重要，因为布局的改变意味着文本内容可能已经改变。
* **缓存输入法组合 (Composition) 范围 (`composition_`)**: 存储当前正在进行的 IME 组合的文本范围 (起始和结束位置的偏移量)。
* **缓存文本选择 (Selection) 范围 (`selection_`)**: 存储当前文本选择的文本范围。
* **维护文本节点到偏移量的映射 (`offset_map_`)**:  为了快速将 DOM 结构中的文本节点位置转换为在整个缓存文本中的偏移量，该文件维护了一个从 `Text` 节点到其在缓存文本中起始偏移量的映射。

**主要方法的功能：**

* **`EnsureCached(const ContainerNode& container)`**:  这是核心方法。它检查当前缓存是否对给定的 `ContainerNode` (例如，一个可编辑的 `div` 或 `textarea`) 有效。如果无效，它会清除旧缓存并重新计算并存储新的文本内容、布局对象、组合范围、选择范围和偏移量映射。
* **`GetComposition(const EphemeralRange& range)`**: 返回给定 DOM 范围的缓存 IME 组合范围（文本偏移量）。如果缓存的组合范围与给定的 DOM 范围匹配，则直接返回缓存的值。
* **`GetSelection(const EphemeralRange& range)`**: 返回给定 DOM 范围的缓存文本选择范围（文本偏移量）。原理同 `GetComposition`。
* **`GetText()`**: 返回缓存的文本内容。
* **`IsValidFor(const ContainerNode& container)`**: 检查缓存是否对给定的 `ContainerNode` 有效（即，缓存的容器和布局对象与给定的容器匹配）。
* **`Clear()`**: 清除所有缓存的信息。
* **`ClearIfNeeded(const LayoutObject& layout_object)`**: 如果缓存的布局对象与给定的布局对象相同，则清除缓存。
* **`DidLayoutSubtree(const LayoutObject& layout_object)`**, **`DidUpdateLayout(const LayoutObject& layout_object)`**, **`DidChangeVisibility(const LayoutObject& layout_object)`**: 这些方法在关联的布局对象发生布局更新、可见性改变等事件时被调用。它们会检查这些变化是否影响到缓存的有效性，并根据需要清除缓存。
* **`LayoutObjectWillBeDestroyed(const LayoutObject& layout_object)`**: 当缓存的布局对象即将被销毁时，清除缓存。
* **`RangeLength(const EphemeralRange& range)`**:  计算给定 DOM 范围的文本长度。它会尝试利用 `offset_map_` 进行优化。
* **`GetPlainTextRange(const EphemeralRange& range)`**: 将给定的 DOM 范围转换为纯文本范围（起始和结束偏移量）。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML**:
    * `CachedTextInputInfo` 作用于可以进行文本输入的 HTML 元素，例如 `<input type="text">`, `<textarea>`, 以及设置了 `contenteditable` 属性的元素。
    * **例子**: 当用户在一个 `<textarea>` 元素中输入文本时，`EnsureCached` 会被调用来缓存该 `<textarea>` 的文本内容。
* **CSS**:
    * CSS 样式会影响元素的布局。当元素的布局发生改变时（例如，由于 CSS 规则的改变），缓存可能会失效。
    * **例子**: 如果一个可编辑 `<div>` 的 `display` 属性从 `inline` 变为 `block`，这将触发布局变化，`DidLayoutSubtree` 方法会被调用，可能导致缓存被清除。
* **JavaScript**:
    * JavaScript 可以通过 DOM API 来修改文本内容、选择范围和进行 IME 操作。
    * **例子 1 (JavaScript 修改内容)**:  JavaScript 代码 `document.getElementById('myTextarea').value = '新的文本';` 修改了 `<textarea>` 的内容，这会导致缓存失效，下次需要缓存信息时会重新计算。
    * **例子 2 (JavaScript 操作选择)**: JavaScript 代码 `document.getElementById('myInput').select();` 改变了输入框的文本选择，`EnsureCached` 可能会在处理后续 IME 事件时被调用，以更新缓存的选择范围。
    * **例子 3 (JavaScript 触发 IME 事件)**:  JavaScript 可以通过 `compositionstart`, `compositionupdate`, `compositionend` 等事件来模拟或处理 IME 输入，这些事件的处理可能需要访问 `CachedTextInputInfo` 来获取或更新组合状态。

**逻辑推理和假设输入与输出：**

**假设输入：**

1. 用户在一个空的 `<input type="text" id="myInput">` 元素中开始使用中文输入法输入 "你好"。
2. 用户首先输入拼音 "ni", 此时 IME 可能会显示候选词。
3. 用户继续输入 "hao", 此时 IME 可能会更新候选词。
4. 用户选择第一个候选词 "你好"。

**逻辑推理和输出：**

1. 当用户开始输入时，焦点会移到 `<input>` 元素，可能触发 `EnsureCached`。由于内容为空，缓存的文本也是空的。
2. 当输入 "ni" 时，IME 会触发 `compositionstart` 事件。Blink 引擎可能会调用 `GetComposition` 来获取当前的组合范围。由于是第一次组合，范围可能是空的。
3. 当继续输入 "hao" 时，IME 会触发 `compositionupdate` 事件。Blink 引擎会再次调用 `GetComposition`。`CachedTextInputInfo` 会根据当前的 DOM 状态计算出组合范围（可能覆盖 "nihao"）。
    * **假设输入 (DOM 范围)**:  组合开始位置在 "n" 之前，结束位置在 "o" 之后。
    * **输出 (PlainTextRange)**: `GetComposition` 可能返回一个 `PlainTextRange` 对象，例如 `{ start: 0, end: 4 }`，表示组合的文本在整个文本中的偏移量。
4. 当用户选择 "你好" 时，IME 会触发 `compositionend` 事件，并且 `<input>` 元素的内容会被更新为 "你好"。同时，可能会触发 `input` 事件。
    * `EnsureCached` 会被调用，缓存的文本内容会更新为 "你好"。
    * 如果用户没有进行任何选择操作，`GetSelection` 可能会返回一个空的 `PlainTextRange`，表示没有文本被选中。

**用户或编程常见的使用错误：**

1. **在没有触发布局更新的情况下修改 DOM 结构导致缓存失效**:  如果 JavaScript 代码直接操作 DOM 结构，例如插入或删除节点，而没有触发必要的布局更新，`CachedTextInputInfo` 的缓存可能与实际 DOM 状态不一致，导致 IME 操作出现异常。
    * **例子**:  一个自定义的 JavaScript 代码在可编辑 `div` 中插入一个新的 `<span>` 元素，但没有强制进行布局，此时缓存可能仍然认为该 `div` 的子节点数量没有改变。
2. **错误地假设缓存总是最新的**: 开发者可能会错误地认为 `CachedTextInputInfo` 始终持有最新的信息，而忽略了布局变化、DOM 操作等可能导致缓存失效的情况。
3. **在异步操作后使用过期的缓存信息**: 如果在执行异步操作（例如，网络请求）期间，DOM 结构或内容发生了变化，之后再使用之前缓存的信息可能会导致错误。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在可编辑元素中点击或通过 Tab 键获得焦点**: 这可能会触发对 `EnsureCached` 的调用，以便为后续的输入操作准备缓存。
2. **用户开始使用输入法输入文本**:
    * **按下键盘上的字母键 (例如，拼音输入)**: 这通常会触发 IME 的 `compositionstart` 或 `compositionupdate` 事件。Blink 引擎在处理这些事件时，可能会调用 `GetComposition` 来获取当前的输入组合状态。
    * **在 IME 候选词窗口中选择候选词**: 这会触发 `compositionend` 事件，同时更新可编辑元素的内容。Blink 引擎可能会再次调用 `EnsureCached` 来更新缓存，并可能调用 `GetSelection` 来获取最终的选择范围。
3. **用户使用鼠标或键盘选择文本**: 这会改变文本的选择范围。当 IME 需要知道当前的选择状态时（例如，在插入新的组合文本时），可能会调用 `GetSelection`。
4. **用户的操作导致布局发生变化**: 例如，调整浏览器窗口大小、修改 CSS 样式、展开或折叠 DOM 元素等。这些操作会触发布局事件，导致 `DidLayoutSubtree`, `DidUpdateLayout`, 或 `DidChangeVisibility` 被调用，可能会清除缓存。
5. **JavaScript 代码与可编辑元素交互**:
    * **修改元素的 `textContent` 或 `innerHTML`**: 这会直接改变文本内容，导致缓存失效。
    * **修改元素的 `selectionStart` 和 `selectionEnd` 属性**: 这会改变文本的选择范围，可能会导致缓存更新。
    * **监听 IME 相关的事件 (`compositionstart`, `compositionupdate`, `compositionend`) 并进行处理**: 在这些事件处理函数中，可能会间接地触发对 `CachedTextInputInfo` 中方法的调用。

**调试线索：**

* **设置断点**: 在 `EnsureCached`, `GetComposition`, `GetSelection`, 以及布局相关的回调方法中设置断点，可以观察缓存何时被创建、访问和清除。
* **查看调用堆栈**: 当在断点处暂停时，查看调用堆栈可以追踪用户操作是如何一步步触发到这些代码的。
* **日志输出**: 在关键方法中添加日志输出，记录缓存的状态、DOM 范围和计算出的文本范围，有助于理解缓存的行为。
* **检查布局树**: 使用 Chromium 的开发者工具检查布局树，可以了解布局变化何时发生，以及哪些元素受到了影响，从而判断缓存是否应该失效。
* **模拟用户操作**:  通过手动操作浏览器或编写自动化测试脚本来模拟用户的输入和交互，可以重现导致问题的场景。

总而言之，`CachedTextInputInfo.cc` 是 Blink 引擎中一个关键的性能优化模块，它通过缓存文本输入相关的各种信息来提高 IME 操作的效率。理解其功能和与 Web 技术的关系对于调试 IME 相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/ime/cached_text_input_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ime/cached_text_input_info.h"

#include "build/chromeos_buildflags.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

EphemeralRange ComputeWholeContentRange(const ContainerNode& container) {
  const auto& range = EphemeralRange::RangeOfContents(container);
  auto* const text_control_element = EnclosingTextControl(&container);
  if (!text_control_element)
    return range;
  auto* const inner_editor = text_control_element->InnerEditorElement();
  if (container != inner_editor)
    return range;
  auto* const last_child = inner_editor->lastChild();
  if (!IsA<HTMLBRElement>(last_child))
    return range;
  const Node* const before_placeholder = last_child->previousSibling();
  if (!before_placeholder) {
    // In case of <div><br></div>.
    return EphemeralRange(Position::FirstPositionInNode(container),
                          Position::FirstPositionInNode(container));
  }
  // We ignore placeholder <br> in <textarea> added by
  // |TextControlElement::AddPlaceholderBreakElementIfNecessary()|.
  // See http://crbug.com/1194349
  return EphemeralRange(Position::FirstPositionInNode(container),
                        Position::AfterNode(*before_placeholder));
}

LayoutObject* FindLayoutObject(const ContainerNode& container) {
  for (const Node& node : FlatTreeTraversal::InclusiveAncestorsOf(container)) {
    if (auto* layout_object = node.GetLayoutObject())
      return layout_object;
  }
  // Because |LayoutView| is derived from |LayoutBlockFlow|, |layout_object_|
  // should not be null.
  NOTREACHED() << container;
}

}  // namespace

// static
TextIteratorBehavior CachedTextInputInfo::Behavior() {
  return TextIteratorBehavior::Builder()
      .SetEmitsObjectReplacementCharacter(true)
      .SetEmitsSpaceForNbsp(true)
      .Build();
}

void CachedTextInputInfo::Clear() const {
  container_ = nullptr;
  layout_object_ = nullptr;
  text_ = g_empty_string;
  composition_.Clear();
  selection_.Clear();
  offset_map_.clear();
}

void CachedTextInputInfo::ClearIfNeeded(const LayoutObject& layout_object) {
  if (layout_object_ != &layout_object)
    return;
  Clear();
}

void CachedTextInputInfo::DidChangeVisibility(
    const LayoutObject& layout_object) {
  DidLayoutSubtree(layout_object);
}

void CachedTextInputInfo::DidLayoutSubtree(const LayoutObject& layout_object) {
  // <div style="contain:strict; ...">abc</div> reaches here.
  if (!container_)
    return;

  if (!layout_object_) {
    return;
  }

#if DCHECK_IS_ON()
  // TODO(crbug.com/375143253): To investigate flaky failures.
  if (layout_object_->is_destroyed_) [[unlikely]] {
    DCHECK(false) << layout_object_;
  }
#endif  // DCHECK_IS_ON()

  if (layout_object_->IsDescendantOf(&layout_object)) {
    // `<span contenteditable>...</span>` reaches here.
    return Clear();
  }

  if (layout_object.IsDescendantOf(layout_object_)) {
    // CachedTextInputInfoTest.RelayoutBoundary reaches here.
    return Clear();
  }
}

void CachedTextInputInfo::DidUpdateLayout(const LayoutObject& layout_object) {
  ClearIfNeeded(layout_object);
}

void CachedTextInputInfo::EnsureCached(const ContainerNode& container) const {
  if (IsValidFor(container))
    return;
  Clear();
  container_ = &container;
  layout_object_ = container.GetLayoutObject();

  if (!layout_object_) {
    if (auto* shadow_root = DynamicTo<ShadowRoot>(container)) {
      // See http://crbug.com/1228373
      layout_object_ = FindLayoutObject(shadow_root->host());
    } else {
      layout_object_ = FindLayoutObject(container);
    }
    // Because we use |layout_object_| as a cache key, |layout_object_| can
    // not be null.
    DCHECK(layout_object_) << container;
  }

  TextIteratorAlgorithm<EditingStrategy> it(ComputeWholeContentRange(container),
                                            Behavior());
  if (it.AtEnd())
    return;

  const bool needs_text = IsEditable(*container_);

  // The initial buffer size can be critical for performance:
  // https://bugs.webkit.org/show_bug.cgi?id=81192
  constexpr unsigned kInitialCapacity = 1 << 15;

  StringBuilder builder;
  if (needs_text) {
    unsigned capacity = kInitialCapacity;
    if (auto* block_flow =
            DynamicTo<LayoutBlockFlow>(container.GetLayoutObject())) {
      if (block_flow->GetInlineNodeData()) {
        if (const auto* mapping = InlineNode::GetOffsetMapping(block_flow)) {
          capacity = mapping->GetText().length();
        }
      }
    }
    builder.ReserveCapacity(capacity);
  }

  const Node* last_text_node = nullptr;
  unsigned length = 0;
  for (; !it.AtEnd(); it.Advance()) {
    const Node* node = it.GetTextState().PositionNode();
    if (last_text_node != node && IsA<Text>(node)) {
      last_text_node = node;
      offset_map_.insert(To<Text>(node), length);
    }
    if (needs_text)
      it.GetTextState().AppendTextToStringBuilder(builder);
    length += it.GetTextState().length();
  }

  if (!builder.empty())
    text_ = builder.ToString();
}

PlainTextRange CachedTextInputInfo::GetComposition(
    const EphemeralRange& range) const {
  DCHECK(container_);
  return GetPlainTextRangeWithCache(range, &composition_);
}

PlainTextRange CachedTextInputInfo::GetPlainTextRangeWithCache(
    const EphemeralRange& range,
    CachedPlainTextRange* text_range) const {
  if (!text_range->IsValidFor(range))
    text_range->Set(range, GetPlainTextRange(range));
  return text_range->Get();
}

PlainTextRange CachedTextInputInfo::GetPlainTextRange(
    const EphemeralRange& range) const {
  if (range.IsNull())
    return PlainTextRange();
  const Position container_start = Position(*container_, 0);
  // When selection is moved to another editable during IME composition,
  // |range| may not in |container|. See http://crbug.com/1161562
  if (container_start > range.StartPosition())
    return PlainTextRange();
  const unsigned start_offset =
      RangeLength(EphemeralRange(container_start, range.StartPosition()));
  const unsigned end_offset =
      range.IsCollapsed()
          ? start_offset
          : RangeLength(EphemeralRange(container_start, range.EndPosition()));
// TODO(crbug.com/1256635): This DCHECK is triggered by Crostini on CrOS.
#if !BUILDFLAG(IS_CHROMEOS_ASH)
  DCHECK_EQ(
      static_cast<unsigned>(TextIterator::RangeLength(
          EphemeralRange(container_start, range.EndPosition()), Behavior())),
      end_offset);
#endif
  return PlainTextRange(start_offset, end_offset);
}

PlainTextRange CachedTextInputInfo::GetSelection(
    const EphemeralRange& range) const {
  DCHECK(container_);
  if (range.IsNull())
    return PlainTextRange();
  return GetPlainTextRangeWithCache(range, &selection_);
}

String CachedTextInputInfo::GetText() const {
  DCHECK(container_);
  DCHECK(IsEditable(*container_));
  return text_;
}

bool CachedTextInputInfo::IsValidFor(const ContainerNode& container) const {
  return container_ == container &&
         layout_object_ == container.GetLayoutObject();
}

void CachedTextInputInfo::LayoutObjectWillBeDestroyed(
    const LayoutObject& layout_object) {
  ClearIfNeeded(layout_object);
}

unsigned CachedTextInputInfo::RangeLength(const EphemeralRange& range) const {
  const Node* const node = range.EndPosition().AnchorNode();
  if (range.StartPosition() == Position(*container_, 0) && IsA<Text>(node)) {
    const auto it = offset_map_.find(To<Text>(node));
    if (it != offset_map_.end()) {
      const unsigned length =
          it->value +
          TextIterator::RangeLength(
              EphemeralRange(Position(node, 0), range.EndPosition()),
              Behavior());
// TODO(crbug.com/1256635): Revert https://crrev.com/c/3221041 to re-enable this
// DCHECK on CrOS.
#if !BUILDFLAG(IS_CHROMEOS_ASH)
      DCHECK_EQ(
          static_cast<unsigned>(TextIterator::RangeLength(range, Behavior())),
          length)
          << it->value << " " << range;
#endif
      return length;
    }
  }
  return TextIterator::RangeLength(range, Behavior());
}

void CachedTextInputInfo::Trace(Visitor* visitor) const {
  visitor->Trace(container_);
  visitor->Trace(layout_object_);
  visitor->Trace(composition_);
  visitor->Trace(offset_map_);
  visitor->Trace(selection_);
}

void CachedTextInputInfo::CachedPlainTextRange::Clear() {
  start_ = end_ = Position();
  start_offset_ = end_offset_ = kNotFound;
}

PlainTextRange CachedTextInputInfo::CachedPlainTextRange::Get() const {
  if (start_offset_ == kNotFound)
    return PlainTextRange();
  return PlainTextRange(start_offset_, end_offset_);
}

bool CachedTextInputInfo::CachedPlainTextRange::IsValidFor(
    const EphemeralRange& range) const {
  return range.StartPosition() == start_ && range.EndPosition() == end_;
}

void CachedTextInputInfo::CachedPlainTextRange::Set(
    const EphemeralRange& range,
    const PlainTextRange& text_range) {
  start_ = range.StartPosition();
  end_ = range.EndPosition();
  if (text_range.IsNull()) {
    start_offset_ = end_offset_ = kNotFound;
  } else {
    start_offset_ = text_range.Start();
    end_offset_ = text_range.End();
  }
}

void CachedTextInputInfo::CachedPlainTextRange::Trace(Visitor* visitor) const {
  visitor->Trace(start_);
  visitor->Trace(end_);
}

}  // namespace blink
```