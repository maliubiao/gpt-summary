Response:
Let's break down the thought process for analyzing this `custom_scrollbar.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific file within the Chromium Blink rendering engine and its interactions with web technologies (JavaScript, HTML, CSS). We also need to consider potential usage errors and any logical inferences we can make.

2. **Initial Code Scan (High-Level):**  Quickly skim through the code, paying attention to:
    * **Includes:**  These provide clues about the file's dependencies and the types of functionalities it interacts with. We see includes related to layout, CSS, painting, scrolling, and platform graphics.
    * **Class Definition:** The core class is `CustomScrollbar`. This immediately tells us the file is about handling scrollbars.
    * **Constructor/Destructor:**  These show how the object is initialized and cleaned up. The constructor takes `ScrollableArea`, `ScrollbarOrientation`, and `LayoutObject` as arguments, suggesting it's linked to a scrollable area and styled based on a layout object.
    * **Key Methods:** Look for methods with descriptive names like `UpdateScrollbarParts`, `PositionScrollbarParts`, `SetEnabled`, `StyleChanged`, `SetHoveredPart`, `SetPressedPart`, `Paint`. These hint at the core responsibilities of the class.
    * **Namespace:** It's in the `blink` namespace, indicating it's part of the Blink rendering engine.

3. **Deconstruct Functionality (Method by Method):**  Go through each method in more detail, understanding its purpose and how it interacts with other parts of the code.

    * **`HypotheticalScrollbarThickness`:** This seems like a utility function to calculate the thickness of a scrollbar without actually creating a persistent one. The comment about matching style rules is important.
    * **`DisconnectFromScrollableArea` and `DestroyScrollbarParts`:** These suggest a lifecycle aspect – scrollbars can be detached and their components destroyed.
    * **`SetEnabled`, `StyleChanged`:**  These are reactive methods, indicating the scrollbar responds to changes in its state or styling.
    * **`SetHoveredPart`, `SetPressedPart`:** These deal with user interaction and state changes based on mouse events.
    * **`GetScrollbarPseudoElementStyle`:** This is a crucial method for understanding how CSS styles the individual parts of the scrollbar (thumb, track, buttons). The interaction with `PseudoId` is key here.
    * **`UpdateScrollbarParts`, `UpdateScrollbarPart`:** These are the core methods for managing the visual components (parts) of the scrollbar based on styling. The logic around `need_layout_object` and handling different `display` values is significant.
    * **`ButtonRect`, `TrackRect`, `TrackPieceRectWithMargins`:** These methods calculate the geometry (position and size) of different scrollbar parts.
    * **`MinimumThumbLength`:** This suggests a constraint on the minimum size of the scrollbar thumb.
    * **`OffsetDidChange`, `PositionScrollbarParts`:** These methods are responsible for updating the positions of the scrollbar parts when the scrollable content is scrolled. The `DCHECK` against `DocumentLifecycle::kInPaint` is a crucial implementation detail.
    * **`GetScrollbarPartStyleForCursor`:** This method determines the cursor style based on which part of the scrollbar the mouse is over.
    * **`InvalidateDisplayItemClientsOfScrollbarParts`, `ClearPaintFlags`, `Paint`:** These are related to the rendering process, indicating how the scrollbar is visually drawn.

4. **Identify Connections to Web Technologies:**  As you analyze the methods, look for clues about how they relate to HTML, CSS, and JavaScript:

    * **CSS:** The `GetScrollbarPseudoElementStyle` method and the handling of `PseudoId` directly link to CSS pseudo-elements like `::-webkit-scrollbar`, `::-webkit-scrollbar-thumb`, etc. The `StyleChanged` method also indicates a reaction to CSS style changes.
    * **HTML:** The `ScrollableArea` and `LayoutObject` arguments in the constructor connect the scrollbar to HTML elements that can be scrolled. The overall purpose of the scrollbar is to allow navigation of content within HTML elements.
    * **JavaScript:** While this C++ file doesn't directly execute JavaScript, the actions it performs (like scrolling in response to user interaction) are triggered by events that can originate from JavaScript (e.g., setting `scrollTop` or `scrollLeft`). The event handling mentioned in `SetHoveredPart` and `SetPressedPart` links to JavaScript event processing.

5. **Logical Inferences and Examples:** Based on the understanding of the code, formulate logical inferences and provide examples:

    * **CSS Styling:**  Focus on the pseudo-element selectors and how they influence the appearance of the scrollbar parts. Provide concrete examples of CSS rules.
    * **JavaScript Interaction:** Explain how JavaScript can programmatically control scrolling, which indirectly affects the scrollbar's state and appearance.
    * **HTML Structure:**  Mention how the `overflow` property in CSS on HTML elements triggers the need for scrollbars.

6. **Identify Potential User/Programming Errors:** Think about how developers might misuse the features provided by this code:

    * **Conflicting Styles:**  Highlight potential issues with overly complex or conflicting CSS rules for scrollbar pseudo-elements.
    * **Assumption about Native Behavior:**  Explain that relying too heavily on custom scrollbar styling might lead to inconsistencies across browsers or operating systems if not handled carefully.
    * **Performance Considerations:** Briefly touch upon potential performance implications of excessively complex custom scrollbar styling.

7. **Structure the Output:** Organize the information logically with clear headings and examples. Start with a general overview of the file's purpose and then delve into specific functionalities, connections to web technologies, logical inferences, and potential errors. Use formatting (like bullet points and code blocks) to improve readability.

8. **Refine and Review:** After drafting the analysis, review it for accuracy, clarity, and completeness. Ensure the examples are relevant and easy to understand. Double-check any assumptions or inferences made. For example, ensure the pseudo-element names are correct and that the explanations of CSS interaction are accurate.

This structured approach helps in systematically understanding complex source code and extracting the relevant information needed to answer the prompt effectively. The key is to start with a broad overview and then progressively drill down into the details while constantly looking for connections to the larger web development context.
这是一个位于 Chromium Blink 渲染引擎中 `blink/renderer/core/layout/custom_scrollbar.cc` 的源代码文件。它的主要功能是 **实现自定义样式的滚动条的布局和行为**。

以下是该文件的详细功能列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及可能的逻辑推理和常见错误：

**功能列表:**

1. **创建和管理自定义滚动条的组成部分 (Parts):**
   - `CustomScrollbar` 类负责创建和管理构成自定义滚动条的各个部分，例如背景、滑块 (thumb)、轨道 (track)、按钮等。
   - 使用 `LayoutCustomScrollbarPart` 类来表示每个组成部分的布局对象。
   - `parts_` 成员变量存储了这些组成部分的映射。

2. **计算假设的滚动条厚度 (`HypotheticalScrollbarThickness`):**
   - 提供一个静态方法，用于在不实际创建完整滚动条的情况下，根据样式来源和方向计算滚动条的厚度。这在布局过程中确定空间分配很有用。

3. **处理滚动条的启用/禁用状态 (`SetEnabled`):**
   - 允许程序性地启用或禁用滚动条，并更新其组成部分的显示状态。

4. **响应样式变化 (`StyleChanged`):**
   - 当关联的 HTML 元素的样式发生变化时，该方法会被调用，并触发滚动条组成部分的更新，以反映新的样式。

5. **处理鼠标悬停 (`SetHoveredPart`):**
   - 当鼠标悬停在滚动条的某个部分时，该方法会被调用，并更新相应部分的状态以显示悬停效果。

6. **处理鼠标按下 (`SetPressedPart`):**
   - 当鼠标在滚动条的某个部分按下时，该方法会被调用，并更新相应部分的状态以显示按下效果。

7. **获取滚动条伪元素的样式 (`GetScrollbarPseudoElementStyle`):**
   - 允许获取应用于滚动条各个伪元素（例如 `::-webkit-scrollbar-thumb`， `::-webkit-scrollbar-track` 等）的 CSS 样式。

8. **销毁滚动条组成部分 (`DestroyScrollbarParts`):**
   - 清理滚动条不再需要时创建的布局对象。

9. **更新滚动条组成部分 (`UpdateScrollbarParts`, `UpdateScrollbarPart`):**
   - 根据当前的样式和状态，创建、更新或移除滚动条的各个组成部分。
   - 决定是否需要为某个部分创建布局对象，这取决于该部分的样式 `display` 属性。
   - 特殊处理滚动按钮，其显示取决于操作系统设置和样式。

10. **计算滚动条各部分的矩形区域 (`ButtonRect`, `TrackRect`, `TrackPieceRectWithMargins`):**
    - 根据滚动条的方位和各个组成部分的大小、边距等属性，计算出每个部分在屏幕上的位置和尺寸。

11. **获取最小滑块长度 (`MinimumThumbLength`):**
    - 获取滑块的最小允许长度，这通常由 CSS 样式定义。

12. **处理滚动偏移变化 (`OffsetDidChange`):**
    - 当滚动内容的偏移量发生变化时，该方法会被调用，并触发滚动条滑块位置的更新。

13. **定位滚动条组成部分 (`PositionScrollbarParts`):**
    - 根据当前的滚动位置和滚动条的尺寸，重新定位各个组成部分，特别是滑块的位置。

14. **为光标获取滚动条部分样式 (`GetScrollbarPartStyleForCursor`):**
    - 确定当鼠标悬停在滚动条的某个部分时应该显示的鼠标光标样式。

15. **使滚动条部分的显示项客户端失效 (`InvalidateDisplayItemClientsOfScrollbarParts`):**
    - 在需要重绘滚动条时，使相关的显示项客户端失效。

16. **清除绘制标志 (`ClearPaintFlags`):**
    - 清除滚动条各个部分的绘制标志。

17. **绘制滚动条 (`Paint`):**
    - 使用 `CustomScrollbarTheme` 来实际绘制滚动条的各个部分。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 该文件与 CSS 密切相关，因为它负责应用 CSS 样式到自定义滚动条的各个部分。
    * **举例:**  CSS 可以使用 WebKit 扩展的伪元素来定义滚动条的样式：
      ```css
      ::-webkit-scrollbar {
          width: 10px;
          height: 10px;
      }

      ::-webkit-scrollbar-thumb {
          background-color: rgba(0, 0, 0, 0.5);
          border-radius: 5px;
      }

      ::-webkit-scrollbar-track {
          background-color: rgba(0, 0, 0, 0.1);
      }

      ::-webkit-scrollbar-button {
          background-color: lightgray;
      }
      ```
      `CustomScrollbar::GetScrollbarPseudoElementStyle` 方法会根据这些 CSS 规则创建相应的 `LayoutCustomScrollbarPart` 对象，并应用样式。

* **HTML:**  该文件通过 `ScrollableArea` 和 `LayoutObject` 与 HTML 元素关联。当一个 HTML 元素的内容溢出并需要滚动条时，`CustomScrollbar` 的实例会被创建来渲染滚动条。
    * **举例:**  一个 `div` 元素设置了 `overflow: auto;` 或 `overflow: scroll;`，并且内容超过了其尺寸，就会触发滚动条的显示，并可能使用自定义样式。
      ```html
      <div style="width: 200px; height: 100px; overflow: auto;">
          很多很多内容...
      </div>
      ```

* **JavaScript:** JavaScript 可以通过修改元素的 CSS 样式或滚动位置来间接影响 `CustomScrollbar` 的行为。
    * **举例:**  JavaScript 可以动态改变滚动条的颜色：
      ```javascript
      const style = document.createElement('style');
      style.innerHTML = `
          ::-webkit-scrollbar-thumb {
              background-color: blue;
          }
      `;
      document.head.appendChild(style);
      ```
      或者，JavaScript 可以通过 `scrollTop` 和 `scrollLeft` 属性来滚动元素，这会触发 `CustomScrollbar::OffsetDidChange`，从而更新滑块的位置。
      ```javascript
      const div = document.querySelector('div');
      div.scrollTop = 50;
      ```

**逻辑推理与假设输入/输出:**

* **假设输入:**  一个带有 `overflow: scroll` 的 `div` 元素，并且定义了自定义滚动条的 CSS 样式，例如滑块的颜色和圆角。
* **逻辑推理:**
    1. Blink 渲染引擎会为该 `div` 创建一个 `ScrollableArea` 对象。
    2. `CustomScrollbar` 的实例会被创建，并关联到该 `ScrollableArea` 和 `div` 的 `LayoutObject`。
    3. `CustomScrollbar::GetScrollbarPseudoElementStyle` 会根据 CSS 规则（例如 `::-webkit-scrollbar-thumb`) 获取滑块的样式信息。
    4. `CustomScrollbar::UpdateScrollbarPart` 会创建一个 `LayoutCustomScrollbarPart` 对象来表示滑块。
    5. `CustomScrollbar::PositionScrollbarParts` 会根据滚动位置计算滑块的正确位置。
    6. `CustomScrollbar::Paint` 会使用 `CustomScrollbarTheme` 绘制出具有指定颜色和圆角的滑块。
* **输出:** 浏览器会渲染出一个自定义样式的滚动条，其滑块具有指定的颜色和圆角，并且可以正确地响应用户的滚动操作。

**用户或编程常见的使用错误:**

1. **忘记添加 WebKit 前缀:**  自定义滚动条的 CSS 伪元素需要添加 `-webkit-` 前缀才能在基于 Chromium 的浏览器中生效。忘记添加前缀会导致样式不生效。
   ```css
   /* 错误 */
   ::scrollbar-thumb { /* ... */ }
   /* 正确 */
   ::-webkit-scrollbar-thumb { /* ... */ }
   ```

2. **过度复杂的样式:**  为滚动条的每个部分定义过于复杂的样式可能会导致性能问题，尤其是在需要频繁重绘的情况下。

3. **样式冲突:**  不同的 CSS 规则可能会相互冲突，导致滚动条的样式不符合预期。例如，同时设置了 `width` 和 `min-width`，可能会产生意想不到的效果。

4. **JavaScript 操作不当:**  使用 JavaScript 直接修改内部的 `LayoutCustomScrollbarPart` 对象或其样式可能会导致渲染引擎的状态不一致，应该通过修改关联的 HTML 元素的样式来间接影响滚动条。

5. **假设所有平台行为一致:**  自定义滚动条的某些方面（例如按钮的显示）可能受到操作系统设置的影响。开发者不应该假设所有平台上的行为都是完全一致的。

6. **忽略可访问性:**  过度定制滚动条样式可能会影响其可访问性。例如，对比度过低的颜色可能会使滚动条难以辨认。应该始终考虑用户的可访问性需求。

总而言之，`custom_scrollbar.cc` 文件是 Chromium Blink 引擎中负责实现自定义滚动条外观和行为的关键组成部分，它与 CSS 样式紧密结合，并通过 HTML 元素和 JavaScript 操作进行交互。理解其功能有助于开发者更好地定制网页的滚动体验。

### 提示词
```
这是目录为blink/renderer/core/layout/custom_scrollbar.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2008, 2009 Apple Inc. All Rights Reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"

#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/custom_scrollbar_theme.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"

namespace blink {

CustomScrollbar::CustomScrollbar(ScrollableArea* scrollable_area,
                                 ScrollbarOrientation orientation,
                                 const LayoutObject* style_source,
                                 bool suppress_use_counters)
    : Scrollbar(scrollable_area,
                orientation,
                style_source,
                CustomScrollbarTheme::GetCustomScrollbarTheme()),
      suppress_use_counters_(suppress_use_counters) {
  DCHECK(style_source);
}

CustomScrollbar::~CustomScrollbar() {
  DCHECK(!scrollable_area_);
  DCHECK(parts_.empty());
}

int CustomScrollbar::HypotheticalScrollbarThickness(
    const ScrollableArea* scrollable_area,
    ScrollbarOrientation orientation,
    const LayoutObject* style_source) {
  // Create a temporary scrollbar so that we can match style rules like
  // ::-webkit-scrollbar:horizontal according to the scrollbar's orientation.
  auto* scrollbar = MakeGarbageCollected<CustomScrollbar>(
      const_cast<ScrollableArea*>(scrollable_area), orientation, style_source,
      /* suppress_use_counters */ true);
  scrollbar->UpdateScrollbarPart(kScrollbarBGPart);
  auto* part = scrollbar->GetPart(kScrollbarBGPart);
  int thickness = part ? part->ComputeThickness() : 0;
  scrollbar->DisconnectFromScrollableArea();
  return thickness;
}

void CustomScrollbar::Trace(Visitor* visitor) const {
  visitor->Trace(parts_);
  Scrollbar::Trace(visitor);
}

void CustomScrollbar::DisconnectFromScrollableArea() {
  DestroyScrollbarParts();
  Scrollbar::DisconnectFromScrollableArea();
}

void CustomScrollbar::SetEnabled(bool enabled) {
  if (Enabled() == enabled)
    return;
  Scrollbar::SetEnabled(enabled);
  UpdateScrollbarParts();
}

void CustomScrollbar::StyleChanged() {
  UpdateScrollbarParts();
}

void CustomScrollbar::SetHoveredPart(ScrollbarPart part) {
  // This can be called from EventHandler after the scrollbar has been
  // disconnected from the scrollable area.
  if (!scrollable_area_)
    return;

  if (part == hovered_part_)
    return;

  ScrollbarPart old_part = hovered_part_;
  hovered_part_ = part;

  UpdateScrollbarPart(old_part);
  UpdateScrollbarPart(hovered_part_);

  UpdateScrollbarPart(kScrollbarBGPart);
  UpdateScrollbarPart(kTrackBGPart);

  PositionScrollbarParts();
}

void CustomScrollbar::SetPressedPart(ScrollbarPart part,
                                     WebInputEvent::Type type) {
  // This can be called from EventHandler after the scrollbar has been
  // disconnected from the scrollable area.
  if (!scrollable_area_)
    return;

  ScrollbarPart old_part = pressed_part_;
  Scrollbar::SetPressedPart(part, type);

  UpdateScrollbarPart(old_part);
  UpdateScrollbarPart(part);

  UpdateScrollbarPart(kScrollbarBGPart);
  UpdateScrollbarPart(kTrackBGPart);

  PositionScrollbarParts();
}

const ComputedStyle* CustomScrollbar::GetScrollbarPseudoElementStyle(
    ScrollbarPart part_type,
    PseudoId pseudo_id) {
  const LayoutObject* layout_object = StyleSource();
  DCHECK(layout_object);
  Document& document = layout_object->GetDocument();
  if (!document.InStyleRecalc()) {
    // We are currently querying style for custom scrollbars on a style-dirty
    // tree outside style recalc. Update active style to make sure we don't
    // crash on null RuleSets.
    // TODO(crbug.com/1114644): We should not compute style for a dirty tree
    // outside the lifecycle update. Instead we should mark the originating
    // element for style recalc and let the next lifecycle update compute the
    // scrollbar styles.
    document.GetStyleEngine().UpdateActiveStyle();
  }
  const ComputedStyle& source_style = layout_object->StyleRef();
  const ComputedStyle* part_style =
      layout_object->GetUncachedPseudoElementStyle(
          StyleRequest(pseudo_id, this, part_type, &source_style));
  if (!part_style)
    return nullptr;
  if (part_style->DependsOnFontMetrics()) {
    if (Element* element = DynamicTo<Element>(layout_object->GetNode())) {
      element->SetScrollbarPseudoElementStylesDependOnFontMetrics(true);
    }
  }
  return part_style;
}

void CustomScrollbar::DestroyScrollbarParts() {
  for (auto& part : parts_)
    part.value->Destroy();
  parts_.clear();
}

void CustomScrollbar::UpdateScrollbarParts() {
  for (auto part :
       {kScrollbarBGPart, kBackButtonStartPart, kForwardButtonStartPart,
        kBackTrackPart, kThumbPart, kForwardTrackPart, kBackButtonEndPart,
        kForwardButtonEndPart, kTrackBGPart})
    UpdateScrollbarPart(part);

  // See if the scrollbar's thickness changed.  If so, we need to mark our
  // owning object as needing a layout.
  bool is_horizontal = Orientation() == kHorizontalScrollbar;
  int old_thickness = is_horizontal ? Height() : Width();
  int new_thickness = 0;
  auto it = parts_.find(kScrollbarBGPart);
  if (it != parts_.end())
    new_thickness = it->value->ComputeThickness();

  if (new_thickness != old_thickness) {
    SetFrameRect(gfx::Rect(
        Location(), gfx::Size(is_horizontal ? Width() : new_thickness,
                              is_horizontal ? new_thickness : Height())));
    if (LayoutBox* box = GetLayoutBox()) {
      box->SetChildNeedsLayout();
      // LayoutNG may attempt to reuse line-box fragments. It will do this even
      // if the |LayoutObject::ChildNeedsLayout| is true (set above).
      // The box itself needs to be marked as needs layout here, as conceptually
      // this is similar to border or padding changing, (which marks the box as
      // self needs layout).
      box->SetNeedsLayout(layout_invalidation_reason::kScrollbarChanged);
      scrollable_area_->SetScrollCornerNeedsPaintInvalidation();
    }
    return;
  }

  // If we didn't return above, it means that there is no change or the change
  // doesn't affect layout of the box. Update position to reflect the change if
  // any.
  if (LayoutBox* box = GetLayoutBox()) {
    // It's not ready to position scrollbar parts if the containing box has not
    // been inserted into the layout tree.
    if (box->IsLayoutView() || box->Parent())
      PositionScrollbarParts();
  }
}

static PseudoId PseudoForScrollbarPart(ScrollbarPart part) {
  switch (part) {
    case kBackButtonStartPart:
    case kForwardButtonStartPart:
    case kBackButtonEndPart:
    case kForwardButtonEndPart:
      return kPseudoIdScrollbarButton;
    case kBackTrackPart:
    case kForwardTrackPart:
      return kPseudoIdScrollbarTrackPiece;
    case kThumbPart:
      return kPseudoIdScrollbarThumb;
    case kTrackBGPart:
      return kPseudoIdScrollbarTrack;
    case kScrollbarBGPart:
      return kPseudoIdScrollbar;
    case kNoPart:
    case kAllParts:
      break;
  }
  NOTREACHED();
}

void CustomScrollbar::UpdateScrollbarPart(ScrollbarPart part_type) {
  DCHECK(scrollable_area_);
  if (part_type == kNoPart)
    return;

  const ComputedStyle* part_style = GetScrollbarPseudoElementStyle(
      part_type, PseudoForScrollbarPart(part_type));
  bool need_layout_object =
      part_style && part_style->Display() != EDisplay::kNone;

  if (need_layout_object &&
      // display:block overrides OS settings.
      part_style->Display() != EDisplay::kBlock) {
    // If not display:block, visibility of buttons depends on OS settings.
    switch (part_type) {
      case kBackButtonStartPart:
      case kForwardButtonEndPart:
        // Create buttons only if the OS theme has scrollbar buttons.
        need_layout_object = GetTheme().NativeThemeHasButtons();
        break;
      case kBackButtonEndPart:
      case kForwardButtonStartPart:
        // These buttons are not supported by any OS.
        need_layout_object = false;
        break;
      default:
        break;
    }
  }

  auto it = parts_.find(part_type);
  LayoutCustomScrollbarPart* part_layout_object =
      it != parts_.end() ? it->value : nullptr;
  if (!part_layout_object && need_layout_object && scrollable_area_) {
    part_layout_object = LayoutCustomScrollbarPart::CreateAnonymous(
        &StyleSource()->GetDocument(), scrollable_area_, this, part_type,
        suppress_use_counters_);
    parts_.Set(part_type, part_layout_object);
    SetNeedsPaintInvalidation(part_type);
  } else if (part_layout_object && !need_layout_object) {
    parts_.erase(part_type);
    part_layout_object->Destroy();
    part_layout_object = nullptr;
    SetNeedsPaintInvalidation(part_type);
  }

  if (part_layout_object)
    part_layout_object->SetStyle(part_style);
}

gfx::Rect CustomScrollbar::ButtonRect(ScrollbarPart part_type) const {
  auto it = parts_.find(part_type);
  if (it == parts_.end())
    return gfx::Rect();

  bool is_horizontal = Orientation() == kHorizontalScrollbar;
  int button_length = it->value->ComputeLength();
  gfx::Rect button_rect(Location(), is_horizontal
                                        ? gfx::Size(button_length, Height())
                                        : gfx::Size(Width(), button_length));

  switch (part_type) {
    case kBackButtonStartPart:
      break;
    case kForwardButtonEndPart:
      button_rect.Offset(is_horizontal ? Width() - button_length : 0,
                         is_horizontal ? 0 : Height() - button_length);
      break;
    case kForwardButtonStartPart: {
      gfx::Rect previous_button = ButtonRect(kBackButtonStartPart);
      button_rect.Offset(is_horizontal ? previous_button.width() : 0,
                         is_horizontal ? 0 : previous_button.height());
      break;
    }
    case kBackButtonEndPart: {
      gfx::Rect next_button = ButtonRect(kForwardButtonEndPart);
      button_rect.Offset(
          is_horizontal ? Width() - next_button.width() - button_length : 0,
          is_horizontal ? 0 : Height() - next_button.height() - button_length);
      break;
    }
    default:
      NOTREACHED();
  }
  return button_rect;
}

gfx::Rect CustomScrollbar::TrackRect(int start_length, int end_length) const {
  const LayoutCustomScrollbarPart* part = GetPart(kTrackBGPart);

  if (Orientation() == kHorizontalScrollbar) {
    int margin_left = part ? part->MarginLeft().ToInt() : 0;
    int margin_right = part ? part->MarginRight().ToInt() : 0;
    start_length += margin_left;
    end_length += margin_right;
    int total_length = start_length + end_length;
    return gfx::Rect(X() + start_length, Y(), Width() - total_length, Height());
  }

  int margin_top = part ? part->MarginTop().ToInt() : 0;
  int margin_bottom = part ? part->MarginBottom().ToInt() : 0;
  start_length += margin_top;
  end_length += margin_bottom;
  int total_length = start_length + end_length;

  return gfx::Rect(X(), Y() + start_length, Width(), Height() - total_length);
}

gfx::Rect CustomScrollbar::TrackPieceRectWithMargins(
    ScrollbarPart part_type,
    const gfx::Rect& old_rect) const {
  const LayoutCustomScrollbarPart* part_layout_object = GetPart(part_type);
  if (!part_layout_object)
    return old_rect;

  gfx::Rect rect = old_rect;
  if (Orientation() == kHorizontalScrollbar) {
    rect.set_x((rect.x() + part_layout_object->MarginLeft()).ToInt());
    rect.set_width((rect.width() - part_layout_object->MarginWidth()).ToInt());
  } else {
    rect.set_y((rect.y() + part_layout_object->MarginTop()).ToInt());
    rect.set_height(
        (rect.height() - part_layout_object->MarginHeight()).ToInt());
  }
  return rect;
}

int CustomScrollbar::MinimumThumbLength() const {
  if (const auto* part_layout_object = GetPart(kThumbPart))
    return part_layout_object->ComputeLength();
  return 0;
}

void CustomScrollbar::OffsetDidChange(mojom::blink::ScrollType scroll_type) {
  Scrollbar::OffsetDidChange(scroll_type);
  PositionScrollbarParts();
}

void CustomScrollbar::PositionScrollbarParts() {
  DCHECK_NE(
      scrollable_area_->GetLayoutBox()->GetDocument().Lifecycle().GetState(),
      DocumentLifecycle::kInPaint);

  // Update frame rect of parts.
  gfx::Rect track_rect = GetTheme().TrackRect(*this);
  gfx::Rect start_track_rect;
  gfx::Rect thumb_rect;
  gfx::Rect end_track_rect;
  GetTheme().SplitTrack(*this, track_rect, start_track_rect, thumb_rect,
                        end_track_rect);
  for (auto& part : parts_) {
    gfx::Rect part_rect;
    switch (part.key) {
      case kBackButtonStartPart:
      case kForwardButtonStartPart:
      case kBackButtonEndPart:
      case kForwardButtonEndPart:
        part_rect = ButtonRect(part.key);
        break;
      case kBackTrackPart:
        part_rect = start_track_rect;
        break;
      case kForwardTrackPart:
        part_rect = end_track_rect;
        break;
      case kThumbPart:
        part_rect = thumb_rect;
        break;
      case kTrackBGPart:
        part_rect = track_rect;
        break;
      case kScrollbarBGPart:
        part_rect = FrameRect();
        break;
      default:
        NOTREACHED();
    }
    part.value->ClearNeedsLayoutWithoutPaintInvalidation();
    // The part's paint offset is relative to the box.
    // TODO(crbug.com/1020913): This should be part of PaintPropertyTreeBuilder
    // when we support subpixel layout of overflow controls.
    part.value->GetMutableForPainting().FirstFragment().SetPaintOffset(
        PhysicalOffset(part_rect.origin()));
    part.value->SetOverriddenSize(PhysicalSize(part_rect.size()));
  }
}

const ComputedStyle* CustomScrollbar::GetScrollbarPartStyleForCursor(
    ScrollbarPart part_type) const {
  const LayoutCustomScrollbarPart* part_layout_object = GetPart(part_type);
  if (part_layout_object) {
    return part_layout_object->Style();
  }
  switch (part_type) {
    case kBackButtonStartPart:
    case kForwardButtonStartPart:
    case kBackButtonEndPart:
    case kForwardButtonEndPart:
    case kTrackBGPart:
    case kThumbPart:
      return GetScrollbarPartStyleForCursor(kScrollbarBGPart);
    case kBackTrackPart:
    case kForwardTrackPart:
      return GetScrollbarPartStyleForCursor(kTrackBGPart);
    default:
      break;
  }
  return nullptr;
}

void CustomScrollbar::InvalidateDisplayItemClientsOfScrollbarParts() {
  for (auto& part : parts_) {
    DCHECK(!part.value->PaintingLayer());
    ObjectPaintInvalidator(*part.value)
        .InvalidateDisplayItemClient(*part.value,
                                     PaintInvalidationReason::kScrollControl);
  }
}

void CustomScrollbar::ClearPaintFlags() {
  for (auto& part : parts_)
    part.value->ClearPaintFlags();
}

void CustomScrollbar::Paint(GraphicsContext& context,
                            const PhysicalOffset& paint_offset) const {
  auto& theme = GetTheme();
  // TODO(crbug.com/40105990): We should not round paint_offset but should
  // consider subpixel accumulation when painting scrollbars.
  gfx::Vector2d offset = ToRoundedVector2d(paint_offset);
  theme.PaintTrackAndButtons(context, *this, FrameRect() + offset);
  if (theme.HasThumb(*this)) {
    theme.PaintThumb(context, *this, theme.ThumbRect(*this) + offset);
  }
}

}  // namespace blink
```