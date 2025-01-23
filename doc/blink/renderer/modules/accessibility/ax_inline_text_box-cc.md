Response:
Let's break down the thought process for analyzing the `AXInlineTextBox.cc` file.

**1. Understanding the Core Purpose:**

The first step is to identify the main responsibility of this class. The filename and the class name itself, `AXInlineTextBox`, strongly suggest it's related to representing inline text within the accessibility tree. The comments and initial includes reinforce this, mentioning "accessibility," "inline text box," and related layout concepts. Therefore, the core function is likely to be *exposing information about inline text fragments to accessibility tools*.

**2. Identifying Key Data Members:**

Looking at the class declaration, the essential data member is `inline_text_box_`. This is a pointer to an `AbstractInlineTextBox`. This immediately tells us that `AXInlineTextBox` is a *wrapper* or *adapter* around the layout engine's representation of inline text. It doesn't *contain* the text or layout information directly, but rather *accesses* it.

**3. Analyzing Key Methods and Their Functionality:**

Now, go through the methods one by one and try to understand their purpose. Look for patterns and connections to accessibility concepts.

* **`GetRelativeBounds`:** This clearly deals with geometry. The name suggests it calculates the position of the inline text relative to its parent. The code confirms this by accessing the `LocalBounds()` of the `inline_text_box_` and offsetting it based on the parent's bounds.

* **`ComputeIsIgnored`:**  This is a standard accessibility concept. It checks if the inline text box should be ignored by accessibility tools. The logic checks if the *parent* is ignored, which makes sense – if the containing element is invisible or irrelevant, the inline text likely is too.

* **`TextCharacterOffsets`:**  The name suggests it provides the horizontal position of each character within the text box. The code retrieves character widths and calculates cumulative offsets. This is crucial for screen readers and other assistive technologies to accurately position the cursor or highlight individual characters.

* **`GetWordBoundaries`:** Similar to character offsets, this identifies the start and end indices of words. This helps with navigation and text selection.

* **`TextOffsetInFormattingContext` and `TextOffsetInContainer`:** These are more complex but crucial. They calculate the text offset within different contexts. `TextOffsetInFormattingContext` appears to be relative to the block-level container, while `TextOffsetInContainer` is relative to the immediate parent (which could be another inline element). The comments highlight the potential complexity when dealing with nested inline elements.

* **`GetName`:**  This is a core accessibility method. For an inline text box, the "name" is simply its textual content.

* **`GetTextDirection`:**  This deals with internationalization and right-to-left languages. It maps the layout engine's direction values to accessibility direction values.

* **`GetDocument`:**  A standard method to access the document.

* **`GetInlineTextBox`:**  A simple accessor to get the underlying layout object.

* **`NextOnLine` and `PreviousOnLine`:** These methods are crucial for navigating linearly through the text content. They retrieve the next and previous inline text boxes on the same line. The comments about `IsAccessibilityPruneRedundantInlineConnectivityEnabled()` indicate an optimization to avoid unnecessary connections in the accessibility tree.

* **`SerializeMarkerAttributes`:** This is a more advanced feature. It deals with adding information about spelling errors, grammar suggestions, and other markers to the accessibility tree. The code retrieves these markers and translates their DOM-based offsets to offsets within the `AXInlineTextBox`. The comments highlight a potential performance issue and the dependency on flat tree calculations.

* **`Init`:** This method initializes the `AXInlineTextBox` object, setting its role and establishing the parent-child relationship in the accessibility tree.

* **`Detach`:**  This cleans up the object, breaking the connection to the underlying layout object.

* **`IsAXInlineTextBox` and `IsLineBreakingObject`:**  Type checking methods. `IsLineBreakingObject` considers explicit `<br>` tags and forced line breaks.

* **`TextLength`:**  Returns the length of the text.

* **`ClearChildren`:**  Inline text boxes don't have children in the accessibility tree, so this is a no-op.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

After understanding the individual methods, connect them to how web developers interact with these concepts:

* **HTML:**  The content of the inline text box originates from the text content of HTML elements. The structure of the HTML (paragraph breaks, inline elements like `<span>`, `<strong>`, etc.) influences how the text is broken down into inline text boxes.

* **CSS:** CSS properties like `direction`, `writing-mode`, `text-align`, and even font properties directly impact the layout and visual representation of the text, which in turn affects the bounding boxes, character offsets, and word boundaries calculated by `AXInlineTextBox`. `text-overflow` is mentioned in a TODO comment, highlighting how visual clipping might interact with accessibility information.

* **JavaScript:** JavaScript can dynamically modify the content and styling of HTML elements, leading to changes in the layout and thus triggering updates in the accessibility tree and the information exposed by `AXInlineTextBox`. JavaScript might also be used by accessibility tools to interact with the accessibility tree.

**5. Identifying Potential Issues and User Errors:**

Think about how things could go wrong or how developers might misuse features related to accessibility:

* **Incorrect `aria-` attributes:**  While `AXInlineTextBox` handles some ARIA markers, incorrect or missing ARIA attributes on parent elements could lead to an incomplete or inaccurate accessibility representation.

* **CSS that hides content visually but doesn't exclude it from the accessibility tree:**  Using CSS like `visibility: hidden` or `display: none` on parent elements can affect whether the `AXInlineTextBox` is ignored. Developers need to understand the difference between visual hiding and semantic exclusion.

* **Dynamic content updates without properly notifying accessibility:** If JavaScript modifies the text content without triggering an accessibility update, assistive technologies might have stale information.

**6. Debugging Scenario:**

Imagine a user reporting an issue with a screen reader not correctly reading a specific part of the text. The debugging process would involve:

1. **Inspecting the HTML structure:** Look at the elements containing the problematic text.
2. **Examining the CSS:** Check for any styles that might be interfering with the layout or visibility of the text.
3. **Using accessibility developer tools:**  Tools like the Chrome Accessibility Inspector can show the accessibility tree and the properties of `AXInlineTextBox` objects. This allows you to see the bounding boxes, text content, and other information directly.
4. **Setting breakpoints:** If needed, you could set breakpoints in the `AXInlineTextBox.cc` code to trace the execution and see how the accessibility information is being calculated for the specific text in question. Understanding the `TextOffsetInContainer` logic and the marker serialization would be crucial in such a scenario.

By following these steps, you can systematically analyze the code and provide a comprehensive explanation of its functionality and its relationship to web technologies and accessibility.
好的，让我们来详细分析一下 `blink/renderer/modules/accessibility/ax_inline_text_box.cc` 这个文件。

**文件功能概述**

`AXInlineTextBox.cc` 文件定义了 `AXInlineTextBox` 类，它是 Chromium Blink 渲染引擎中负责将**内联文本框（Inline Text Box）**的信息暴露给**辅助技术（Assistive Technologies, ATs）**的关键组件。

简单来说，当浏览器渲染网页时，文本内容会被分割成一个个小的内联文本框，方便布局和渲染。`AXInlineTextBox` 的作用就是把这些底层的布局信息转换成辅助技术能够理解的抽象表示，从而让屏幕阅读器等工具可以正确地识别和朗读网页上的文本。

**与 JavaScript, HTML, CSS 的关系**

`AXInlineTextBox` 直接关联着网页的 HTML 结构、CSS 样式以及可能通过 JavaScript 动态修改的内容。

* **HTML:**
    * `AXInlineTextBox` 代表了 HTML 文本节点的一部分或全部内容。例如，在以下 HTML 片段中：
      ```html
      <p>This is <strong>bold</strong> text.</p>
      ```
      `"This is "`， `"bold"` 和 `" text."` 可能会分别对应不同的 `AXInlineTextBox` 对象，因为它们有不同的样式或者被不同的元素包含。
    *  当 HTML 结构发生变化（例如，通过 DOM 操作添加或删除文本），Blink 渲染引擎会重新布局，并可能创建或销毁 `AXInlineTextBox` 对象。

* **CSS:**
    * CSS 样式决定了文本的渲染方式，这直接影响了内联文本框的布局和属性。例如：
        * `font-size` 影响每个字符的宽度，从而影响 `TextCharacterOffsets` 方法的计算。
        * `direction` 和 `writing-mode` 属性决定了文本的书写方向，这会被 `GetTextDirection` 方法获取。
        * 文本的换行和溢出属性也会影响内联文本框的划分。
    * **举例:** 如果一个 `<span>` 元素的 CSS 设置了 `font-weight: bold;`，那么包含在该 `<span>` 元素内的文本所对应的 `AXInlineTextBox` 对象的边界和属性可能会与周围普通文本的 `AXInlineTextBox` 对象不同。

* **JavaScript:**
    * JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改最终会反映在 `AXInlineTextBox` 对象中。
    * **举例:**  一个 JavaScript 脚本可能会更新一个 `<div>` 元素的 `textContent` 属性。当浏览器重新渲染时，与该 `<div>` 元素相关的 `AXInlineTextBox` 对象的内容和属性也会随之更新。

**逻辑推理示例**

假设我们有以下 HTML 和 CSS：

```html
<p id="myPara">Hello world!</p>
```

```css
#myPara {
  font-size: 16px;
}
```

**假设输入:**  当辅助技术请求 `#myPara` 元素的文本内容时，Blink 渲染引擎会遍历其子节点，并找到包含文本 "Hello world!" 的内联文本框。

**逻辑推理:**

1. **布局过程:** 渲染引擎会根据 CSS 计算出 "Hello world!" 在屏幕上的布局，包括每个字符的位置和宽度。
2. **创建 `AXInlineTextBox`:** 针对 "Hello world!" 这段文本（假设没有被进一步分割），会创建一个 `AXInlineTextBox` 对象。
3. **属性计算:**
    * `GetName()` 方法会返回 "Hello world!"。
    * `TextLength()` 方法会返回 12。
    * `TextCharacterOffsets()` 方法会根据 16px 的字体大小计算出每个字符的水平偏移量。例如，如果 "H" 的宽度是 10px，"e" 的宽度是 8px，那么偏移量可能是 `[10, 18, 26, ...]`。
    * `GetRelativeBounds()` 方法会计算出该内联文本框相对于其父元素（`<p>` 元素对应的 Accessibility Object）的边界。

**假设输出:**  辅助技术最终会接收到包含文本内容 "Hello world!" 以及其布局信息的 Accessibility Node。

**用户或编程常见的使用错误**

1. **意外地将文本分割成过多的 `AXInlineTextBox` 对象:**  如果 HTML 结构过于复杂，或者 CSS 样式导致文本被频繁地包裹在不同的内联元素中，可能会产生大量的 `AXInlineTextBox` 对象。虽然这在功能上可能没有问题，但在某些情况下可能会增加 Accessibility Tree 的复杂性，影响辅助技术的性能。
    * **举例:**  过度使用 `<span>` 标签并应用不同的内联样式。

2. **动态更新内容后未触发 Accessibility 更新:**  如果 JavaScript 修改了文本内容，但没有触发必要的 Accessibility 事件，辅助技术可能无法感知到这些变化，导致信息不一致。

3. **错误地假设 `AXInlineTextBox` 的 ParentObject:**  代码中可以看到，`AXInlineTextBox` 的父对象通常是包含该文本的 Accessibility Object (例如，一个 `AXParagraph` 或 `AXSpan`)。开发者在处理 Accessibility 信息时，需要正确理解这种父子关系。

**用户操作到达这里的调试线索**

用户执行以下操作时，可能会触发与 `AXInlineTextBox` 相关的代码执行：

1. **页面加载和渲染:** 当用户打开一个网页时，Blink 渲染引擎会解析 HTML、应用 CSS，并创建 Accessibility Tree，其中包括 `AXInlineTextBox` 对象。
2. **文本选择:** 当用户在网页上选择文本时，辅助技术可能会查询与选中文本相关的 `AXInlineTextBox` 对象，以确定选区的边界和内容。
3. **屏幕阅读器导航:** 使用屏幕阅读器（例如 NVDA, JAWS）的用户在浏览网页时，屏幕阅读器会逐个访问 Accessibility Tree 中的节点，包括 `AXInlineTextBox`，并朗读其文本内容。
4. **使用辅助功能工具:**  开发者或测试人员可以使用 Chromium 提供的 Accessibility 工具（例如，Chrome DevTools 的 Accessibility 面板）来查看 Accessibility Tree，并检查 `AXInlineTextBox` 对象的属性。

**调试步骤示例:**

假设用户报告屏幕阅读器无法正确朗读页面上的某段文本。作为开发者，可以采取以下步骤进行调试：

1. **打开 Chrome DevTools，切换到 "Inspect" 面板。**
2. **选中报告问题的文本所在的 HTML 元素。**
3. **切换到 "Accessibility" 面板。**
4. **查看该元素的 Accessibility Tree。**
5. **展开该元素下的子节点，查找对应的 `AXInlineTextBox` 对象。**
6. **检查 `AXInlineTextBox` 对象的属性，例如 Name（文本内容）、Bounds（边界）、Text Character Offsets 等。**
7. **如果发现 `AXInlineTextBox` 的内容或边界不正确，可以进一步检查相关的 HTML 结构和 CSS 样式，或者查看是否有 JavaScript 动态修改了该部分内容。**
8. **在 `AXInlineTextBox.cc` 中设置断点，例如在 `GetName()` 或 `TextCharacterOffsets()` 方法中，然后重新加载页面或执行相关操作，可以跟踪代码的执行流程，了解 Accessibility 信息的生成过程。**

总而言之，`AXInlineTextBox.cc` 文件中的 `AXInlineTextBox` 类是 Blink 渲染引擎中 Accessibility 模块的重要组成部分，它负责将底层的内联文本布局信息转化为辅助技术可以理解的抽象表示，从而实现网页内容的可访问性。理解其功能和与前端技术的关系，对于开发可访问的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_inline_text_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/accessibility/ax_inline_text_box.h"

#include <stdint.h>

#include <optional>
#include <utility>

#include "base/numerics/clamped_math.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/highlight/highlight.h"
#include "third_party/blink/renderer/core/layout/inline/abstract_inline_text_box.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_position.h"
#include "third_party/blink/renderer/modules/accessibility/ax_range.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/accessibility/accessibility_features.h"
#include "ui/accessibility/ax_role_properties.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

AXInlineTextBox::AXInlineTextBox(AbstractInlineTextBox* inline_text_box,
                                 AXObjectCacheImpl& ax_object_cache)
    : AXObject(ax_object_cache), inline_text_box_(inline_text_box) {}

void AXInlineTextBox::Trace(Visitor* visitor) const {
  visitor->Trace(inline_text_box_);
  AXObject::Trace(visitor);
}

void AXInlineTextBox::GetRelativeBounds(AXObject** out_container,
                                        gfx::RectF& out_bounds_in_container,
                                        gfx::Transform& out_container_transform,
                                        bool* clips_children) const {
  *out_container = nullptr;
  out_bounds_in_container = gfx::RectF();
  out_container_transform.MakeIdentity();

  if (!inline_text_box_ || !ParentObject() ||
      !ParentObject()->GetLayoutObject()) {
    return;
  }

  *out_container = ParentObject();
  out_bounds_in_container = gfx::RectF(inline_text_box_->LocalBounds());

  // Subtract the local bounding box of the parent because they're
  // both in the same coordinate system.
  gfx::RectF parent_bounding_box =
      ParentObject()->LocalBoundingBoxRectForAccessibility();
  out_bounds_in_container.Offset(-parent_bounding_box.OffsetFromOrigin());
}

bool AXInlineTextBox::ComputeIsIgnored(
    IgnoredReasons* ignored_reasons) const {
  AXObject* parent = ParentObject();
  if (!parent)
    return false;

  if (!parent->IsIgnored())
    return false;

  if (ignored_reasons)
    parent->ComputeIsIgnored(ignored_reasons);

  return true;
}

void AXInlineTextBox::TextCharacterOffsets(Vector<int>& offsets) const {
  if (IsDetached())
    return;

  Vector<float> widths;
  inline_text_box_->CharacterWidths(widths);
  DCHECK_EQ(static_cast<int>(widths.size()), TextLength());
  offsets.resize(TextLength());

  float width_so_far = 0;
  for (int i = 0; i < TextLength(); i++) {
    width_so_far += widths[i];
    offsets[i] = roundf(width_so_far);
  }
}

void AXInlineTextBox::GetWordBoundaries(Vector<int>& word_starts,
                                        Vector<int>& word_ends) const {
  if (!inline_text_box_ ||
      inline_text_box_->GetText().ContainsOnlyWhitespaceOrEmpty()) {
    return;
  }

  Vector<AbstractInlineTextBox::WordBoundaries> boundaries;
  inline_text_box_->GetWordBoundaries(boundaries);
  word_starts.reserve(boundaries.size());
  word_ends.reserve(boundaries.size());
  for (const auto& boundary : boundaries) {
    word_starts.push_back(boundary.start_index);
    word_ends.push_back(boundary.end_index);
  }
}

int AXInlineTextBox::TextOffsetInFormattingContext(int offset) const {
  DCHECK_GE(offset, 0);
  if (IsDetached())
    return 0;

  // Retrieve the text offset from the start of the layout block flow ancestor.
  return static_cast<int>(inline_text_box_->TextOffsetInFormattingContext(
      static_cast<unsigned int>(offset)));
}

int AXInlineTextBox::TextOffsetInContainer(int offset) const {
  DCHECK_GE(offset, 0);
  if (IsDetached())
    return 0;

  // Retrieve the text offset from the start of the layout block flow ancestor.
  int offset_in_block_flow_container = TextOffsetInFormattingContext(offset);
  const AXObject* parent = ParentObject();
  if (!parent)
    return offset_in_block_flow_container;

  // If the parent object in the accessibility tree exists, then it is either
  // a static text object or a line break. In the static text case, it is an
  // AXNodeObject associated with an inline text object. Hence the container
  // is another inline object, not a layout block flow. We need to subtract the
  // text start offset of the static text parent from the text start offset of
  // this inline text box.
  int offset_in_inline_parent = parent->TextOffsetInFormattingContext(0);
  // TODO(nektar) Figure out why this asserts in marker-hyphens.html.
  // To see error, comment out below early return and run command similar to:
  // run_web_tests.py --driver-logging -t linux-debug
  //   --additional-driver-flag=--force-renderer-accessibility
  //   external/wpt/css/css-pseudo/marker-hyphens.html
  // DCHECK_LE(offset_in_inline_parent, offset_in_block_flow_container);
  return offset_in_block_flow_container - offset_in_inline_parent;
}

String AXInlineTextBox::GetName(ax::mojom::blink::NameFrom& name_from,
                                AXObject::AXObjectVector* name_objects) const {
  if (IsDetached())
    return String();

  name_from = ax::mojom::blink::NameFrom::kContents;
  return inline_text_box_->GetText();
}

// In addition to LTR and RTL direction, edit fields also support
// top to bottom and bottom to top via the CSS writing-mode property.
ax::mojom::blink::WritingDirection AXInlineTextBox::GetTextDirection() const {
  if (IsDetached())
    return AXObject::GetTextDirection();

  switch (inline_text_box_->GetDirection()) {
    case PhysicalDirection::kRight:
      return ax::mojom::blink::WritingDirection::kLtr;
    case PhysicalDirection::kLeft:
      return ax::mojom::blink::WritingDirection::kRtl;
    case PhysicalDirection::kDown:
      return ax::mojom::blink::WritingDirection::kTtb;
    case PhysicalDirection::kUp:
      return ax::mojom::blink::WritingDirection::kBtt;
  }

  return AXObject::GetTextDirection();
}

Document* AXInlineTextBox::GetDocument() const {
  return ParentObject() ? ParentObject()->GetDocument() : nullptr;
}

AbstractInlineTextBox* AXInlineTextBox::GetInlineTextBox() const {
  return inline_text_box_.Get();
}

AXObject* AXInlineTextBox::NextOnLine() const {
  if (IsDetached())
    return nullptr;

  if (inline_text_box_->IsLast()) {
    // Do not serialize nextOnlineID if it can be inferred from the parent.
    return ::features::IsAccessibilityPruneRedundantInlineConnectivityEnabled()
               ? nullptr
               : ParentObject()->NextOnLine();
  }

  if (AbstractInlineTextBox* next_on_line = inline_text_box_->NextOnLine()) {
    return AXObjectCache().Get(next_on_line);
  }
  return nullptr;
}

AXObject* AXInlineTextBox::PreviousOnLine() const {
  if (IsDetached())
    return nullptr;

  if (inline_text_box_->IsFirst()) {
    // Do not serialize previousOnlineID if it can be inferred from the parent.
    return ::features::IsAccessibilityPruneRedundantInlineConnectivityEnabled()
               ? nullptr
               : ParentObject()->PreviousOnLine();
  }

  AbstractInlineTextBox* previous_on_line = inline_text_box_->PreviousOnLine();
  if (previous_on_line)
    return AXObjectCache().Get(previous_on_line);

  return nullptr;
}

void AXInlineTextBox::SerializeMarkerAttributes(
    ui::AXNodeData* node_data) const {
  // TODO(nektar) Address 20% performance degredation and restore code.
  // It may be necessary to add document markers as part of tree data instead
  // of computing for every node. To measure current performance, create a
  // release build without DCHECKs, and then run command similar to:
  // tools/perf/run_benchmark blink_perf.accessibility   --browser=exact \
  //   --browser-executable=path/to/chrome --story-filter="accessibility.*"
  //   --results-label="[my-branch-name]"
  // Pay attention only to rows with  ProcessDeferredAccessibilityEvents
  // and RenderAccessibilityImpl::SendPendingAccessibilityEvents.
  if (!RuntimeEnabledFeatures::
          AccessibilityUseAXPositionForDocumentMarkersEnabled())
    return;

  if (IsDetached())
    return;
  if (!GetDocument() || GetDocument()->IsSlotAssignmentDirty()) {
    // In order to retrieve the document markers we need access to the flat
    // tree. If the slot assignments in a shadow DOM subtree are dirty,
    // accessing the flat tree will cause them to be updated, which could in
    // turn cause an update to the accessibility tree, potentially causing this
    // method to be called repeatedly.
    return;  // Wait until distribution for flat tree traversal has been
             // updated.
  }

  int text_length = TextLength();
  if (!text_length)
    return;
  const auto ax_range = AXRange::RangeOfContents(*this);

  std::vector<int32_t> marker_types;
  std::vector<int32_t> highlight_types;
  std::vector<int32_t> marker_starts;
  std::vector<int32_t> marker_ends;

  // First use ARIA markers for spelling/grammar if available.
  std::optional<DocumentMarker::MarkerType> aria_marker_type =
      GetAriaSpellingOrGrammarMarker();
  if (aria_marker_type) {
    marker_types.push_back(ToAXMarkerType(aria_marker_type.value()));
    marker_starts.push_back(ax_range.Start().TextOffset());
    marker_ends.push_back(ax_range.End().TextOffset());
  }

  DocumentMarkerController& marker_controller = GetDocument()->Markers();
  const Position dom_range_start =
      ax_range.Start().ToPosition(AXPositionAdjustmentBehavior::kMoveLeft);
  const Position dom_range_end =
      ax_range.End().ToPosition(AXPositionAdjustmentBehavior::kMoveRight);
  if (dom_range_start.IsNull() || dom_range_end.IsNull())
    return;

  // TODO(nektar) Figure out why the start > end sometimes.
  // To see error, comment out below early return and run command similar to:
  // run_web_tests.py --driver-logging -t linux-debug
  //   --additional-driver-flag=--force-renderer-accessibility
  //   external/wpt/css/css-ui/text-overflow-006.html
  if (dom_range_start > dom_range_end)
    return;  // Temporary until above TODO is resolved.
  DCHECK_LE(dom_range_start, dom_range_end);
  const EphemeralRangeInFlatTree dom_range(
      ToPositionInFlatTree(dom_range_start),
      ToPositionInFlatTree(dom_range_end));
  DCHECK(dom_range.IsNotNull());
  const DocumentMarker::MarkerTypes markers_used_by_accessibility(
      DocumentMarker::kSpelling | DocumentMarker::kGrammar |
      DocumentMarker::kTextMatch | DocumentMarker::kActiveSuggestion |
      DocumentMarker::kSuggestion | DocumentMarker::kTextFragment |
      DocumentMarker::kCustomHighlight);
  // "MarkersIntersectingRange" performs a binary search through the document
  // markers list for markers in the given range and of the given types. It
  // should be of a logarithmic complexity.
  const VectorOfPairs<const Text, DocumentMarker> node_marker_pairs =
      marker_controller.MarkersIntersectingRange(dom_range,
                                                 markers_used_by_accessibility);
  const int start_text_offset_in_parent = TextOffsetInContainer(0);
  for (const auto& node_marker_pair : node_marker_pairs) {
    DCHECK_EQ(inline_text_box_->GetNode(), node_marker_pair.first);
    const DocumentMarker* marker = node_marker_pair.second;

    if (aria_marker_type == marker->GetType())
      continue;

    // The document markers are represented by DOM offsets in this object's
    // static text parent. We need to translate to text offsets in the
    // accessibility tree, first in this object's parent and then to local text
    // offsets.
    const auto start_position = AXPosition::FromPosition(
        Position(*inline_text_box_->GetNode(), marker->StartOffset()),
        TextAffinity::kDownstream, AXPositionAdjustmentBehavior::kMoveLeft);
    const auto end_position = AXPosition::FromPosition(
        Position(*inline_text_box_->GetNode(), marker->EndOffset()),
        TextAffinity::kDownstream, AXPositionAdjustmentBehavior::kMoveRight);
    if (!start_position.IsValid() || !end_position.IsValid())
      continue;

    const int local_start_offset = base::ClampMax(
        start_position.TextOffset() - start_text_offset_in_parent, 0);
    DCHECK_LE(local_start_offset, text_length);
    const int local_end_offset = base::ClampMin(
        end_position.TextOffset() - start_text_offset_in_parent, text_length);
    DCHECK_GE(local_end_offset, 0);

    int32_t highlight_type =
        static_cast<int32_t>(ax::mojom::blink::HighlightType::kNone);
    if (marker->GetType() == DocumentMarker::kCustomHighlight) {
      const auto& highlight_marker = To<CustomHighlightMarker>(*marker);
      highlight_type =
          ToAXHighlightType(highlight_marker.GetHighlight()->type());
    }

    marker_types.push_back(int32_t{ToAXMarkerType(marker->GetType())});
    highlight_types.push_back(static_cast<int32_t>(highlight_type));
    marker_starts.push_back(local_start_offset);
    marker_ends.push_back(local_end_offset);
  }

  DCHECK_EQ(marker_types.size(), marker_starts.size());
  DCHECK_EQ(marker_types.size(), marker_ends.size());

  if (marker_types.empty())
    return;

  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerTypes, marker_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kHighlightTypes, highlight_types);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerStarts, marker_starts);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kMarkerEnds, marker_ends);
}

void AXInlineTextBox::Init(AXObject* parent) {
  CHECK(!AXObjectCache().IsFrozen());
  role_ = ax::mojom::blink::Role::kInlineTextBox;
  DCHECK(parent);
  DCHECK(ui::CanHaveInlineTextBoxChildren(parent->RoleValue()))
      << "Unexpected parent of inline text box: " << parent->RoleValue();
  DCHECK(parent->CanHaveChildren())
      << "Parent cannot have children: " << parent;
  // Don't call SetParent(), which calls SetAncestorsHaveDirtyDescendants(),
  // because once inline textboxes are loaded for the parent text, it's never
  // necessary to again recompute this part of the tree.
  parent_ = parent;
  UpdateCachedAttributeValuesIfNeeded(false);
}

void AXInlineTextBox::Detach() {
  AXObject::Detach();
  inline_text_box_ = nullptr;
}

bool AXInlineTextBox::IsAXInlineTextBox() const {
  return true;
}

bool AXInlineTextBox::IsLineBreakingObject() const {
  if (IsDetached())
    return AXObject::IsLineBreakingObject();

  // If this object is a forced line break, or the parent is a <br>
  // element, then this object is line breaking.
  const AXObject* parent = ParentObject();
  return inline_text_box_->IsLineBreak() ||
         (parent && parent->RoleValue() == ax::mojom::blink::Role::kLineBreak);
}

int AXInlineTextBox::TextLength() const {
  if (IsDetached())
    return 0;
  return static_cast<int>(inline_text_box_->Len());
}

void AXInlineTextBox::ClearChildren() {
  // An AXInlineTextBox has no children to clear.
}

}  // namespace blink
```