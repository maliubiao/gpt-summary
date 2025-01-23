Response:
Let's break down the thought process for analyzing the `caret_display_item_client.cc` file.

1. **Understand the Core Purpose:** The file name immediately suggests this has to do with the visual representation of the text input cursor (caret) in the Blink rendering engine. The `DisplayItemClient` suffix hints at its role in the display list, which is how Blink organizes painting operations.

2. **Identify Key Classes and Concepts:**  Scanning the includes and the class definition reveals the important players:
    * `CaretDisplayItemClient`: The central class we're analyzing.
    * `LayoutBlock`: Represents a block-level element in the layout tree, crucial for positioning and painting.
    * `PhysicalBoxFragment`: Represents a fragment of a layout box, often used in fragmented layouts (like multi-column).
    * `LocalCaretRect`:  Encapsulates the caret's position and size relative to a specific layout object.
    * `PositionWithAffinity`: Represents a position in the document with a direction preference, important for edge cases.
    * `GraphicsContext`: The interface for drawing operations.
    * `PaintInfo`, `PaintInvalidator`, `ObjectPaintInvalidatorWithContext`:  Related to the painting and invalidation mechanisms.
    * `DisplayItem`:  A basic unit in the display list.

3. **Analyze Member Variables:**  The member variables of `CaretDisplayItemClient` are crucial for understanding its state:
    * `layout_block_`:  The `LayoutBlock` responsible for painting the caret.
    * `previous_layout_block_`: Used for invalidating the caret's previous location during updates.
    * `box_fragment_`: The specific fragment where the caret is located.
    * `local_rect_`: The caret's rectangle within the `layout_block_`.
    * `color_`: The caret's color.
    * `is_active_`: Whether the caret is currently visible.
    * `needs_paint_invalidation_`: A flag to trigger repainting.

4. **Examine Key Methods:** Focus on the public and important private methods:
    * `ComputeCaretRectAndPainterBlock()`:  A core function. The name suggests it figures out the caret's rectangle and which `LayoutBlock` should draw it. This is likely where a lot of the logic for positioning the caret lives.
    * `UpdateStyleAndLayoutIfNeeded()`:  Called when the caret's position or style might have changed. This method seems responsible for determining if a repaint is needed.
    * `PaintCaret()`:  The actual drawing logic. It takes a `GraphicsContext` and draws a rectangle.
    * `InvalidatePaint*()` methods:  These are crucial for the repaint mechanism. They mark regions as needing to be redrawn.
    * `ShouldPaintCaret()`: Determines if the caret should be painted within a specific `PhysicalBoxFragment`.
    * `SetActive()`: Controls the caret's visibility.

5. **Trace Data Flow and Logic:** For each key method, try to understand the input, the processing steps, and the output. For example, in `ComputeCaretRectAndPainterBlock()`:
    * **Input:** `PositionWithAffinity`.
    * **Processing:**  Gets the `LocalCaretRect`, determines the responsible `LayoutBlock` (handling cases where the caret might be within a nested element). Maps the `LocalCaretRect` to the coordinate system of the painter block.
    * **Output:**  The caret's rectangle and the `LayoutBlock` responsible for painting.

6. **Relate to Web Standards (HTML, CSS, JavaScript):**  Think about how user interactions and web content affect the caret:
    * **HTML:** The structure of the HTML document determines the layout and the possible positions for the caret.
    * **CSS:**  CSS properties like `caret-color`, `direction`, and layout properties (e.g., `display`, `position`) directly influence how the caret is rendered.
    * **JavaScript:**  JavaScript can move the caret programmatically (e.g., using `selection` API), trigger focus changes, and dynamically modify the DOM, all of which can lead to the code in this file being executed.

7. **Consider Potential User/Programming Errors:** Think about common mistakes that might lead to issues with the caret:
    * Incorrectly setting focus.
    * JavaScript errors that disrupt the selection.
    * CSS styles that hide or misplace the caret.
    * Issues with nested editing contexts or iframes.

8. **Imagine the Debugging Process:** How would a developer reach this code during debugging?  Think about user actions and the code path:
    * User clicks in a text field.
    * User types text.
    * User uses arrow keys to navigate.
    * JavaScript code modifies the selection.

9. **Formulate Explanations and Examples:**  Based on the analysis, construct clear explanations of the file's functions, provide concrete examples relating to web technologies, and illustrate potential errors and debugging steps. Use the code comments and variable names as clues.

10. **Iterate and Refine:**  Review the analysis, reread the code if necessary, and refine the explanations to be more accurate and easier to understand. For example, the initial thought might be "it just draws the caret," but further analysis reveals the complexities of handling different layout scenarios, invalidation, and interaction with the broader rendering pipeline.

By following this structured approach, one can effectively analyze a complex source code file like `caret_display_item_client.cc` and understand its purpose and relationships within the larger system.
好的，让我们来详细分析 `blink/renderer/core/editing/caret_display_item_client.cc` 这个文件。

**核心功能:**

这个文件的核心职责是**管理和绘制文本输入光标（caret）**。 具体来说，它负责以下几个关键功能：

1. **确定 Caret 的位置和尺寸:**  根据当前文本选择的位置，计算出 Caret 应该显示的确切矩形区域 (`local_rect_`)。这涉及到与布局引擎的交互，以获取文本节点、行框等信息。

2. **确定 Caret 的绘制者:**  决定哪个 `LayoutBlock` 对象负责实际绘制 Caret。这通常是包含 Caret 的文本节点的布局块，但也可能需要考虑包含块的情况。

3. **Caret 的绘制 (`PaintCaret` 方法):**  使用 `GraphicsContext` 对象在指定的矩形区域内绘制 Caret。这通常是一个垂直的细线，颜色由 CSS 的 `caret-color` 属性决定。

4. **Caret 的显示与隐藏:**  根据焦点状态 (`is_active_`) 和其他条件来控制 Caret 的显示与隐藏。

5. **Caret 引起的重绘管理 (`InvalidatePaint*` 方法):**  当 Caret 的位置、颜色或显示状态发生变化时，触发必要的重绘操作，以更新屏幕上的显示。这涉及到与 Blink 的渲染管道中的 invalidation 机制进行交互。

6. **与 Selection 的关联 (`RecordSelection` 方法):** 虽然主要负责 Caret 的显示，但它也参与记录与 Caret 相关的选择信息，用于辅助调试和辅助功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件深深地嵌入在浏览器渲染引擎的核心，直接响应 HTML 结构、CSS 样式以及 JavaScript 的操作：

* **HTML:**
    * **输入框和可编辑内容:** 当用户在 `<input>`, `<textarea>` 或设置了 `contenteditable` 属性的元素中点击或聚焦时，这个文件中的代码会被激活，开始管理 Caret 的显示。
    * **文本节点:**  Caret 的位置总是位于 HTML 文本节点中的某个位置。这个文件需要根据文本节点在布局树中的位置来计算 Caret 的坐标。
    * **示例:** 用户在一个 `<textarea>` 中点击，CaretDisplayItemClient 会根据点击位置的文本内容和布局信息，确定 Caret 应该出现在哪个字符之间。

* **CSS:**
    * **`caret-color` 属性:**  `CaretDisplayItemClient::UpdateStyleAndLayoutIfNeeded` 方法会读取当前元素的 `caret-color` CSS 属性，并将其应用于 Caret 的绘制。
        * **示例:**  在 CSS 中设置 `input { caret-color: red; }`，那么当输入框获得焦点时，Caret 将会显示为红色。
    * **字体和排版属性:** 字体大小、行高、字间距等 CSS 属性会影响文本的布局，进而影响 Caret 的高度和垂直位置。
    * **`direction` 属性:**  对于从右到左的语言，Caret 的行为可能会有所不同。这个文件需要考虑到 `direction` 属性的影响。
    * **示例:**  设置 `div { font-size: 20px; line-height: 1.5; }` 会影响 Caret 在该 `div` 内的高度。

* **JavaScript:**
    * **Selection API (`window.getSelection()`, `document.createRange()` 等):** JavaScript 可以通过 Selection API 来改变文本的选中范围，这会直接影响 Caret 的位置。
        * **示例:**  JavaScript 代码 `document.querySelector('input').focus(); document.querySelector('input').setSelectionRange(2, 2);` 会将输入框聚焦，并将 Caret 放置在第三个字符的位置。
    * **`contenteditable` 属性的动态修改:**  JavaScript 可以动态地设置或取消元素的 `contenteditable` 属性，这会触发 Caret 的显示或隐藏。
    * **事件处理 (如 `focus`, `blur`, `keydown`, `mouseup`):**  用户的键盘输入、鼠标点击等事件会触发 JavaScript 事件处理函数，这些函数可能会间接地导致 Caret 的位置或状态发生变化。

**逻辑推理的假设输入与输出:**

假设输入：

1. **用户在一个空的 `<input>` 元素中点击。**
2. **该 `<input>` 元素的 CSS 设置了 `caret-color: blue;`。**
3. **该 `<input>` 元素位于一个 `<div>` 中，`<div>` 的字体大小为 16px。**

逻辑推理过程：

1. `CaretDisplayItemClient::UpdateStyleAndLayoutIfNeeded` 会被调用，因为焦点状态发生了变化。
2. 它会检查 `caret-color` 属性，并获取到 `blue`。
3. 它会获取 `<input>` 元素的布局信息，包括其所在行框的高度，这会受到父 `<div>` 的字体大小影响。
4. `ComputeCaretRectAndPainterBlock` 会计算 Caret 的位置，由于输入框为空，Caret 会位于输入框的起始位置。Caret 的高度会根据行框的高度确定。
5. `PaintCaret` 方法会被调用。

假设输出：

* Caret 将会显示在 `<input>` 元素的左边缘。
* Caret 的颜色将是蓝色。
* Caret 的高度将与 `<input>` 元素内部的行高相匹配（可能与 `<div>` 的字体大小相关）。

**涉及用户或编程常见的使用错误及举例说明:**

1. **Caret 不可见:**
   * **用户错误:**  可能用户认为输入框有焦点，但实际上焦点在其他元素上。
   * **编程错误:**  可能 CSS 设置了 `caret-color: transparent;` 或 `caret-color: rgba(0, 0, 0, 0);`，导致 Caret 变成透明。或者设置了 `width: 0;` 或 `height: 0;` 导致 Caret 无法显示。
   * **调试线索:** 检查元素的焦点状态，查看 computed style 中 `caret-color` 的值，检查元素是否有设置 `width` 和 `height`。

2. **Caret 位置不正确:**
   * **用户错误:**  可能用户点击的位置不在预期的文本位置上，例如在 margin 或 padding 区域。
   * **编程错误:**  可能 JavaScript 代码错误地设置了 selection 的范围。或者在复杂的布局情况下，Blink 的布局计算出现问题。
   * **调试线索:**  使用浏览器的开发者工具检查元素的布局信息，查看 selection 的范围，逐步调试 JavaScript 代码。

3. **Caret 闪烁异常:**
   * **编程错误:**  可能存在频繁的重绘操作，导致 Caret 不断地重新绘制，引起闪烁。这可能是由于 JavaScript 代码中不必要的 DOM 操作或样式更改导致的。
   * **调试线索:**  使用浏览器的 Performance 工具分析页面性能，查看是否有大量的 paint 事件发生。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含可编辑内容的网页:**  浏览器开始解析 HTML、CSS，构建 DOM 树和渲染树。
2. **用户点击可编辑区域 (如输入框或 `contenteditable` 元素):**
   * 浏览器接收到鼠标点击事件。
   * 事件被传递到相应的 HTML 元素。
   * 该元素获得焦点。
3. **焦点事件触发:**
   * Blink 引擎会更新内部状态，标记该元素为焦点元素。
   * `CaretDisplayItemClient` 的实例可能会被创建或激活，与该焦点元素关联。
   * `UpdateStyleAndLayoutIfNeeded` 方法会被调用，以获取 Caret 的颜色和位置信息。
4. **计算 Caret 位置:**
   * `ComputeCaretRectAndPainterBlock` 方法会被调用，根据焦点位置的文本内容和布局信息计算 Caret 的矩形区域和绘制者。
5. **Caret 的绘制 (首次):**
   * 当需要绘制该元素的显示列表时，`PaintCaret` 方法会被调用，使用 `GraphicsContext` 在计算出的位置绘制 Caret。
6. **用户输入文本或移动光标:**
   * 键盘输入或光标移动事件被触发。
   * Selection 的范围发生变化。
   * `UpdateStyleAndLayoutIfNeeded` 再次被调用，检测 Caret 位置是否需要更新。
   * 如果 Caret 位置发生变化，会触发重绘 (`InvalidatePaint*`)。
7. **Caret 的重绘:**
   * 在下一次绘制循环中，`PaintCaret` 会被再次调用，以新的位置或颜色重新绘制 Caret。

**调试线索:**

* **断点:** 在 `CaretDisplayItemClient` 的关键方法（如 `UpdateStyleAndLayoutIfNeeded`, `ComputeCaretRectAndPainterBlock`, `PaintCaret`, `InvalidatePaint*`）设置断点，可以跟踪 Caret 的更新过程。
* **Performance 工具:** 使用浏览器的 Performance 工具可以查看绘制事件，了解 Caret 是否频繁重绘。
* **元素审查:** 使用浏览器的元素审查工具，查看焦点元素及其 computed style，特别是 `caret-color` 属性。
* **Layout 调试:** 使用浏览器的 Layout 面板，查看元素的布局信息，确认 Caret 的位置计算是否正确。
* **Selection 检查:**  在控制台中使用 `window.getSelection()` 查看当前的文本选中范围。

总而言之，`caret_display_item_client.cc` 是 Blink 渲染引擎中一个至关重要的文件，它负责处理用户与可编辑内容交互时，光标的显示和更新，并与 HTML 结构、CSS 样式和 JavaScript 行为紧密相关。理解这个文件的工作原理，对于调试与文本编辑相关的渲染问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/caret_display_item_client.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2008, 2009, 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/caret_display_item_client.h"

#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_filter.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"

namespace blink {

CaretDisplayItemClient::CaretDisplayItemClient() = default;
CaretDisplayItemClient::~CaretDisplayItemClient() = default;
void CaretDisplayItemClient::Trace(Visitor* visitor) const {
  visitor->Trace(layout_block_);
  visitor->Trace(previous_layout_block_);
  visitor->Trace(box_fragment_);
  DisplayItemClient::Trace(visitor);
}

namespace {

inline bool CaretRendersInsideNode(const Node* node) {
  return node && !IsDisplayInsideTable(node) && !EditingIgnoresContent(*node);
}

LayoutBlock* CaretLayoutBlock(const Node* node,
                              const LayoutObject* layout_object) {
  if (!node)
    return nullptr;

  if (!layout_object)
    return nullptr;

  auto* caret_layout_object = DynamicTo<LayoutBlock>(layout_object);
  // if caretNode is a block and caret is inside it then caret should be painted
  // by that block
  bool painted_by_block = caret_layout_object && CaretRendersInsideNode(node);
  return painted_by_block ? const_cast<LayoutBlock*>(caret_layout_object)
                          : layout_object->ContainingBlock();
}

PhysicalRect MapCaretRectToCaretPainter(const LayoutBlock* caret_block,
                                        const LocalCaretRect& caret_rect) {
  // FIXME: This shouldn't be called on un-rooted subtrees.
  // FIXME: This should probably just use mapLocalToAncestor.
  // Compute an offset between the caretLayoutItem and the caretPainterItem.

  LayoutObject* caret_layout_object =
      const_cast<LayoutObject*>(caret_rect.layout_object);
  DCHECK(caret_layout_object->IsDescendantOf(caret_block));

  PhysicalRect result_rect = caret_rect.rect;
  while (caret_layout_object != caret_block) {
    LayoutObject* container_object = caret_layout_object->Container();
    if (!container_object)
      return PhysicalRect();
    result_rect.Move(
        caret_layout_object->OffsetFromContainer(container_object));
    caret_layout_object = container_object;
  }
  return result_rect;
}

}  // namespace

CaretDisplayItemClient::CaretRectAndPainterBlock
CaretDisplayItemClient::ComputeCaretRectAndPainterBlock(
    const PositionWithAffinity& caret_position) {
  if (caret_position.IsNull())
    return {};

  if (!caret_position.AnchorNode()->GetLayoutObject())
    return {};

  // First compute a rect local to the layoutObject at the selection start.
  const LocalCaretRect& caret_rect =
      LocalCaretRectOfPosition(caret_position, kCannotCrossEditingBoundary);
  if (!caret_rect.layout_object)
    return {};

  // Get the layoutObject that will be responsible for painting the caret
  // (which is either the layoutObject we just found, or one of its containers).
  LayoutBlock* caret_block;
  if (caret_rect.root_box_fragment) {
    caret_block =
        To<LayoutBlock>(caret_rect.root_box_fragment->GetMutableLayoutObject());
    // The root box fragment's layout object should always match the one we'd
    // get from CaretLayoutBlock, except for atomic inline-level LayoutBlocks
    // (i.e. display: inline-block). In those cases, the layout object should be
    // either the caret rect's layout block, or its containing block.
    if (!(caret_rect.layout_object->IsLayoutBlock() &&
          caret_rect.layout_object->IsAtomicInlineLevel())) {
      DCHECK_EQ(caret_block, CaretLayoutBlock(caret_position.AnchorNode(),
                                              caret_rect.layout_object));
    } else if (caret_block != caret_rect.layout_object) {
      DCHECK_EQ(caret_block, caret_rect.layout_object->ContainingBlock());
    }
  } else {
    caret_block =
        CaretLayoutBlock(caret_position.AnchorNode(), caret_rect.layout_object);
  }
  return {MapCaretRectToCaretPainter(caret_block, caret_rect), caret_block,
          caret_rect.root_box_fragment};
}

void CaretDisplayItemClient::LayoutBlockWillBeDestroyed(
    const LayoutBlock& block) {
  if (block == layout_block_)
    layout_block_ = nullptr;
  if (block == previous_layout_block_)
    previous_layout_block_ = nullptr;
}

bool CaretDisplayItemClient::ShouldPaintCaret(
    const PhysicalBoxFragment& box_fragment) const {
  const auto* const block =
      DynamicTo<LayoutBlock>(box_fragment.GetLayoutObject());
  if (!block)
    return false;
  if (!ShouldPaintCaret(*block))
    return false;
  return !box_fragment_ || &box_fragment == box_fragment_;
}

void CaretDisplayItemClient::UpdateStyleAndLayoutIfNeeded(
    const PositionWithAffinity& caret_position) {
  // This method may be called multiple times (e.g. in partial lifecycle
  // updates) before a paint invalidation. We should save previous_layout_block_
  // if it has not been saved since the last paint invalidation to ensure the
  // caret painted in the previous paint invalidated block will be invalidated.
  // We don't care about intermediate changes of LayoutBlock because they are
  // not painted.
  if (!previous_layout_block_)
    previous_layout_block_ = layout_block_.Get();

  CaretRectAndPainterBlock rect_and_block =
      ComputeCaretRectAndPainterBlock(caret_position);
  LayoutBlock* new_layout_block = rect_and_block.painter_block;
  if (new_layout_block != layout_block_) {
    if (layout_block_)
      layout_block_->SetShouldCheckForPaintInvalidation();
    layout_block_ = new_layout_block;

    if (new_layout_block) {
      needs_paint_invalidation_ = true;
      // The caret property tree space may have changed.
      layout_block_->GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();
    }
  }

  if (!new_layout_block) {
    color_ = Color();
    local_rect_ = PhysicalRect();
    return;
  }

  const PhysicalBoxFragment* const new_box_fragment =
      rect_and_block.box_fragment;
  if (new_box_fragment != box_fragment_) {
    // The caret property tree space may have changed.
    layout_block_->GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();

    if (new_box_fragment)
      needs_paint_invalidation_ = true;
    box_fragment_ = new_box_fragment;
  }

  Color new_color;
  if (caret_position.AnchorNode()) {
    new_color = caret_position.AnchorNode()->GetLayoutObject()->ResolveColor(
        GetCSSPropertyCaretColor());
  }
  if (new_color != color_) {
    needs_paint_invalidation_ = true;
    color_ = new_color;
  }

  auto new_local_rect = rect_and_block.caret_rect;
  // TODO(crbug.com/1123630): Avoid paint invalidation on caret movement.
  if (new_local_rect != local_rect_) {
    needs_paint_invalidation_ = true;
    local_rect_ = new_local_rect;
  }

  if (needs_paint_invalidation_)
    new_layout_block->SetShouldCheckForPaintInvalidation();
}

void CaretDisplayItemClient::SetActive(bool active) {
  if (active == is_active_)
    return;
  is_active_ = active;
  needs_paint_invalidation_ = true;
}

void CaretDisplayItemClient::EnsureInvalidationOfPreviousLayoutBlock() {
  if (!previous_layout_block_ || previous_layout_block_ == layout_block_) {
    return;
  }

  PaintInvalidatorContext context;
  context.painting_layer = previous_layout_block_->PaintingLayer();
  InvalidatePaintInPreviousLayoutBlock(context);
}

void CaretDisplayItemClient::InvalidatePaint(
    const LayoutBlock& block,
    const PaintInvalidatorContext& context) {
  if (block == layout_block_) {
    InvalidatePaintInCurrentLayoutBlock(context);
    return;
  }

  if (block == previous_layout_block_)
    InvalidatePaintInPreviousLayoutBlock(context);
}

void CaretDisplayItemClient::InvalidatePaintInPreviousLayoutBlock(
    const PaintInvalidatorContext& context) {
  DCHECK(previous_layout_block_);

  ObjectPaintInvalidatorWithContext object_invalidator(*previous_layout_block_,
                                                       context);
  context.painting_layer->SetNeedsRepaint();
  object_invalidator.InvalidateDisplayItemClient(
      *this, PaintInvalidationReason::kCaret);
  previous_layout_block_ = nullptr;
}

void CaretDisplayItemClient::InvalidatePaintInCurrentLayoutBlock(
    const PaintInvalidatorContext& context) {
  DCHECK(layout_block_);

  if (layout_block_ == previous_layout_block_)
    previous_layout_block_ = nullptr;

  needs_paint_invalidation_ |= layout_block_->ShouldDoFullPaintInvalidation();
  needs_paint_invalidation_ |=
      context.fragment_data->PaintOffset() != context.old_paint_offset;

  if (!needs_paint_invalidation_)
    return;

  needs_paint_invalidation_ = false;
  context.painting_layer->SetNeedsRepaint();
  ObjectPaintInvalidatorWithContext(*layout_block_, context)
      .InvalidateDisplayItemClient(*this, PaintInvalidationReason::kCaret);
}

void CaretDisplayItemClient::PaintCaret(
    GraphicsContext& context,
    const PhysicalOffset& paint_offset,
    DisplayItem::Type display_item_type) const {
  PhysicalRect drawing_rect = local_rect_;
  drawing_rect.Move(paint_offset);

  // When caret is in text-combine box with scaling, |context| is already
  // associated to drawing record to apply affine transform.
  std::optional<DrawingRecorder> recorder;
  if (!context.InDrawingRecorder()) [[likely]] {
    if (DrawingRecorder::UseCachedDrawingIfPossible(context, *this,
                                                    display_item_type))
      return;
    recorder.emplace(context, *this, display_item_type,
                     ToPixelSnappedRect(drawing_rect));
  }

  gfx::Rect paint_rect = ToPixelSnappedRect(drawing_rect);
  context.FillRect(paint_rect, color_,
                   PaintAutoDarkMode(layout_block_->StyleRef(),
                                     DarkModeFilter::ElementRole::kForeground));
}

void CaretDisplayItemClient::RecordSelection(GraphicsContext& context,
                                             const PhysicalOffset& paint_offset,
                                             gfx::SelectionBound::Type type) {
  PhysicalRect drawing_rect = local_rect_;
  drawing_rect.Move(paint_offset);
  gfx::Rect paint_rect = ToPixelSnappedRect(drawing_rect);

  // For the caret, the start and end selection bounds are recorded as
  // the same edges, with the type marked as CENTER or HIDDEN.
  PaintedSelectionBound start = {type, paint_rect.origin(),
                                 paint_rect.bottom_left(), false};
  PaintedSelectionBound end = start;

  // Get real world data to help debug crbug.com/1441243.
#if DCHECK_IS_ON()
  String debug_info = drawing_rect.ToString();
#else
  String debug_info = "";
#endif

  context.GetPaintController().RecordSelection(start, end, debug_info);
}

String CaretDisplayItemClient::DebugName() const {
  return "Caret";
}

}  // namespace blink
```