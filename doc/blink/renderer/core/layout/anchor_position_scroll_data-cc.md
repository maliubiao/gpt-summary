Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary goal is to understand the functionality of `anchor_position_scroll_data.cc` in the Chromium Blink rendering engine and explain it in relation to web technologies (HTML, CSS, JavaScript). The request specifically asks for function summaries, relationships to web tech, logical reasoning (with input/output), and common usage errors.

2. **Initial Code Scan and Keyword Identification:**  Start by reading through the code, paying attention to class names, method names, and any keywords that suggest its purpose.

    * `AnchorPositionScrollData`: This is the central class, indicating it manages data related to the positioning of an anchor element and scrolling.
    * `ScrollSnapshotClient`: Suggests it takes snapshots of scroll-related information.
    * `AdjustmentData`:  Likely stores information about adjustments to scrolling.
    * `ComputeAdjustmentContainersData`, `ComputeDefaultAnchorAdjustmentData`:  These methods seem to calculate adjustments based on containers.
    * `TakeAndCompareSnapshot`:  Indicates a mechanism for tracking changes over time.
    * `InvalidateLayoutAndPaint`, `InvalidatePaint`: These are crucial for triggering rendering updates.
    * `position-anchor`, `sticky`:  These terms appear within the code and connect to CSS features.

3. **Identify Key Functionality (High-Level):** Based on the initial scan, the core functionality seems to be:

    * **Tracking Anchor Elements:**  It's associated with an `anchored_element_`.
    * **Calculating Scroll Offsets:** It computes offsets based on various factors (scroll containers, sticky elements, chained anchors).
    * **Managing Updates:** It detects changes and triggers re-rendering when necessary.

4. **Delve into Specific Methods and Logic:**  Now, examine individual methods in more detail:

    * **`PositionAnchorObject`:** This clearly deals with finding the target anchor element based on CSS properties. This directly links to the `position-anchor` CSS property.
    * **`GetNonOverflowingScrollRanges`:** This relates to how elements behave when they overflow their containers, suggesting interaction with CSS overflow properties.
    * **`CheckHasDefaultAnchorReferences`:**  This appears to determine if default anchor-based scrolling is needed, again hinting at CSS influence.
    * **Constructors/Destructors:** Standard setup and cleanup.
    * **`IsActive`:** Checks if the data is currently in use.
    * **`TotalOffset`:** Returns the calculated total scroll offset.
    * **`ComputeAdjustmentContainersData`:**  This is a key method. Trace its logic:
        * It iterates up the DOM tree from the anchor.
        * It considers scroll containers and accumulates their offsets.
        * It handles sticky positioning by subtracting sticky offsets.
        * It handles "chained" anchor positioning.
    * **`ComputeDefaultAnchorAdjustmentData`:** This calls `ComputeAdjustmentContainersData` and then potentially zeroes out adjustments along the X or Y axis based on whether adjustments are needed in those directions.
    * **`TakeAndCompareSnapshot`:** This is crucial for change tracking. It compares current data with previous snapshots to determine if and what kind of updates are needed. The different `SnapshotDiff` values are important.
    * **`IsFallbackPositionValid`:** This seems related to handling situations where the anchor element might cause overflow and a fallback position is considered. The logic here is a bit more complex, involving checking `NonOverflowingScrollRange`.
    * **`UpdateSnapshot`, `ValidateSnapshot`:** Methods for managing the snapshot lifecycle.
    * **`ShouldScheduleNextService`:** Determines if further processing is required.
    * **`EnsureAnchorPositionVisibilityObserver`:**  Suggests tracking the visibility of the anchor element.
    * **`InvalidateLayoutAndPaint`, `InvalidatePaint`:** These are the triggers for the rendering pipeline.

5. **Connect to Web Technologies:**  As you analyze the methods, actively think about how they relate to HTML, CSS, and JavaScript:

    * **HTML:**  The concept of "anchor elements" is fundamental to HTML (`<a>` tags, but in this context, it's more about elements used as references for positioning). The code interacts with the DOM (Document Object Model).
    * **CSS:**  The most prominent connection is the `position-anchor` CSS property. Sticky positioning (`position: sticky`) is also explicitly handled. Overflow properties (`overflow: auto`, `scroll`) are implicitly involved with scroll containers.
    * **JavaScript:** While this C++ code isn't directly JavaScript, it *enables* functionality that JavaScript can interact with. For instance, JavaScript can trigger layout changes that would cause this code to recalculate scroll adjustments. JavaScript might also be used to dynamically change CSS properties that affect anchor positioning.

6. **Logical Reasoning and Examples:** For more complex logic (like `TakeAndCompareSnapshot` or `IsFallbackPositionValid`), create hypothetical scenarios:

    * **Input:** Imagine an element with `position: fixed` and a `position-anchor` pointing to another element. The user scrolls.
    * **Output:**  The `AnchorPositionScrollData` would calculate the necessary offset to keep the fixed element positioned relative to its anchor, even as the viewport scrolls.

7. **Identify Potential Usage Errors:**  Think about how a web developer might misuse the related CSS features:

    * **Circular Dependencies:**  What if element A anchors to B, and B anchors to A? This could lead to infinite loops or unexpected behavior.
    * **Incorrect Anchor Selection:**  Specifying an anchor that doesn't exist or isn't in the correct part of the DOM.
    * **Performance Issues:** Overusing anchor positioning or having complex nesting could potentially impact performance.

8. **Structure the Explanation:** Organize your findings logically:

    * Start with a concise summary of the file's purpose.
    * Break down the functionality into key areas.
    * Provide concrete examples linking to web technologies.
    * Explain the logical reasoning with clear input/output.
    * List potential usage errors.

9. **Refine and Review:** Read through your explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Make sure the examples are understandable.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This seems to be about standard HTML anchors (`<a>`)."
* **Correction:**  Realize that `position-anchor` introduces a different kind of anchoring mechanism tied to CSS positioning. Adjust the explanation accordingly.
* **Initial thought:** "The snapshot logic is just about saving and restoring scroll positions."
* **Correction:** Understand that the snapshots are used for *detecting changes* that require re-rendering, not just for simple restoration.
* **Make sure the examples are relevant and illustrate the core concepts.**  Don't just list CSS properties; explain *how* the C++ code interacts with them.

By following this detailed process, combining code analysis with an understanding of web technologies, and focusing on clear explanations and examples, you can generate a comprehensive and accurate answer like the example provided in the prompt.
This C++ source file, `anchor_position_scroll_data.cc`, within the Chromium Blink engine, is responsible for managing data and logic related to the **CSS `position-anchor` property**. Its primary function is to ensure that elements using `position: fixed` or `position: absolute` and the `position-anchor` property maintain their intended relative position to their anchor element, even when scrolling occurs.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Tracking Anchored Elements:** It maintains a connection to the `anchored_element_`, the element that has the `position-anchor` property set.

2. **Identifying the Anchor Element:** It determines the target anchor element based on the `position-anchor` property's value. This could be an explicitly named element or an implicit anchor. The `PositionAnchorObject` function handles this.

3. **Calculating Scroll Offsets and Adjustments:** The core of the functionality lies in calculating the necessary adjustments to the anchored element's position based on the scrolling of its ancestor containers. This involves:
    * **Identifying Scroll Containers:** It traverses the ancestor chain of both the anchored element and the anchor element to find scrolling containers.
    * **Accumulating Scroll Offsets:** It sums up the scroll offsets of these relevant containers.
    * **Handling Sticky Positioning:** It accounts for the offsets caused by `position: sticky` elements.
    * **Chained Anchors:** It supports scenarios where the anchor element itself is also an anchor-positioned element, recursively incorporating its adjustments.

4. **Taking and Comparing Snapshots:** It takes "snapshots" of the relevant scroll data (anchor element, scroll container IDs, accumulated offsets). It then compares these snapshots to detect changes. This is crucial for determining when to trigger layout and paint updates. The `TakeAndCompareSnapshot` function performs this comparison.

5. **Invalidating Layout and Paint:** When changes are detected that affect the positioning of the anchored element, it triggers layout and paint invalidation. This ensures the browser re-renders the page with the correct positioning. `InvalidateLayoutAndPaint` and `InvalidatePaint` are the functions responsible.

6. **Visibility Observation:** It includes an `AnchorPositionVisibilityObserver` (though the details of its functionality aren't fully evident in this snippet) which likely monitors the visibility of the anchor element, potentially to optimize when to perform calculations.

**Relationship to JavaScript, HTML, and CSS:**

This code directly implements the behavior defined by the CSS `position-anchor` property.

* **CSS:**
    * **`position-anchor`:**  This file's primary purpose is to implement the logic behind this CSS property. The code parses the value of `position-anchor` (which can be an element ID) and finds the corresponding anchor element.
    * **`position: fixed` and `position: absolute`:** The `position-anchor` property only has an effect on elements with these positioning schemes. This code is specifically designed to handle these cases.
    * **`position: sticky`:** The code explicitly accounts for the offsets introduced by sticky positioned elements in the ancestor chain. The `StickyConstraints()` check and the adjustment of `accumulated_adjustment` demonstrate this.
    * **`overflow: auto`, `overflow: scroll`:** These CSS properties on ancestor elements create scroll containers, which are crucial for the calculations performed by this code. The code iterates through ancestors and checks `IsScrollContainer()`.

    **Example:**

    ```html
    <div style="overflow: auto; height: 200px;">
      <div id="anchor" style="height: 400px;"></div>
    </div>
    <div style="position: fixed; position-anchor: #anchor; top: 10px; left: 10px;">
      This element is anchored to #anchor.
    </div>
    ```

    In this example, when the user scrolls the outer `div`, the code in `anchor_position_scroll_data.cc` will calculate the necessary adjustments to keep the fixed positioned element 10px from the top and left of the `#anchor` element, even as it moves within the scrollable area.

* **HTML:**
    * The code interacts with the DOM (Document Object Model) to find the anchor element and its ancestor containers. The `Element* anchored_element_` member and the traversal of the container hierarchy demonstrate this.
    * The `position-anchor` property references HTML elements, often by their `id`.

* **JavaScript:**
    * While this is C++ code, JavaScript can indirectly influence its behavior. For instance, JavaScript can:
        * Dynamically change the `position-anchor` property or the positioning scheme of an element.
        * Modify the scroll position of ancestor containers.
        * Add or remove elements from the DOM, which can affect the ancestor hierarchy and thus the calculations in this code.

**Logical Reasoning with Assumptions:**

**Assumption:** An element with `position: fixed` and `position-anchor: #myAnchor` is present in the DOM. The element `#myAnchor` is within a scrollable container.

**Input:** The user scrolls the scrollable container.

**Processing:**

1. **`PositionAnchorObject`:**  Locates the `LayoutObject` corresponding to the HTML element with `id="myAnchor"`.
2. **`ComputeAdjustmentContainersData`:**
   * Iterates up the ancestor chain of both the fixed element and `#myAnchor`.
   * Identifies the scrollable container as a relevant adjustment container.
   * Retrieves the scroll offset of the scrollable container (e.g., scrollY = 50px).
   * Stores the scroll container's ID and its offset.
3. **`TakeAndCompareSnapshot`:** Compares the current scroll offset of the container with a previous snapshot. If the offset has changed.
4. **`InvalidatePaint` or `InvalidateLayoutAndPaint`:**  Triggers a repaint (or relayout and repaint if necessary) to reposition the fixed element.

**Output:** The fixed positioned element will be visually moved by the negative of the scroll offset change, effectively staying pinned to the relative position of `#myAnchor`. If the user scrolled down 50px, the fixed element will be moved down by 50px in the rendering, maintaining its relative position.

**Common Usage Errors:**

1. **Circular `position-anchor` Dependencies:**  If element A has `position-anchor` set to element B, and element B has `position-anchor` set to element A, this can lead to infinite loops or unpredictable behavior during layout calculations. The browser might try to resolve the positions endlessly.

    **Example:**

    ```html
    <div id="a" style="position: fixed; position-anchor: #b;">A</div>
    <div id="b" style="position: fixed; position-anchor: #a;">B</div>
    ```

2. **Specifying a Non-Existent Anchor:** If the `position-anchor` property refers to an ID that doesn't exist in the DOM, the anchoring will likely fail, and the anchored element might behave like a normally positioned fixed element (relative to the viewport).

    **Example:**

    ```html
    <div style="position: fixed; position-anchor: #nonExistentElement;">I won't be anchored.</div>
    ```

3. **Incorrectly Assuming Anchor Behavior with Static Positioning:** The `position-anchor` property only works with `position: fixed` and `position: absolute`. Applying it to elements with `position: static` or `position: relative` will have no effect.

    **Example:**

    ```html
    <div id="anchor">Anchor</div>
    <div style="position: static; position-anchor: #anchor;">This won't work as expected.</div>
    ```

4. **Performance Issues with Complex Anchor Chains:** Deeply nested anchor relationships or a large number of anchor-positioned elements can potentially impact rendering performance as the browser needs to perform calculations for each such element on every scroll.

5. **Forgetting to Define the Anchor's Position:** If the anchor element itself is not positioned in a way that allows it to be scrolled (e.g., it's not within an overflow container or is directly under the body without specific dimensions), the anchored element might not behave as expected during scrolling.

This file is a crucial part of Blink's layout engine, enabling a powerful and flexible way to create user interfaces that maintain relationships between elements even during scrolling. Understanding its functionality helps in debugging and optimizing web pages that utilize the `position-anchor` CSS property.

### 提示词
```
这是目录为blink/renderer/core/layout/anchor_position_scroll_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/layout/anchor_position_visibility_observer.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/non_overflowing_scroll_range.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

namespace blink {

namespace {

// Finds the LayoutObject of the anchor element given by position-anchor.
const LayoutObject* PositionAnchorObject(const LayoutBox& box) {
  const ComputedStyle& style = box.StyleRef();
  return style.PositionAnchor() ? box.FindTargetAnchor(*style.PositionAnchor())
                                : box.AcceptableImplicitAnchor();
}

const HeapVector<NonOverflowingScrollRange>* GetNonOverflowingScrollRanges(
    const LayoutObject* layout_object) {
  if (!layout_object || !layout_object->IsOutOfFlowPositioned()) {
    return nullptr;
  }
  CHECK(layout_object->IsBox());
  return To<LayoutBox>(layout_object)->NonOverflowingScrollRanges();
}

// First return value for x axis, second for y axis.
std::pair<bool, bool> CheckHasDefaultAnchorReferences(
    const LayoutObject* layout_object) {
  if (!layout_object || !layout_object->IsOutOfFlowPositioned()) {
    return std::make_pair(false, false);
  }
  CHECK(layout_object->IsBox());
  const LayoutBox* box = To<LayoutBox>(layout_object);
  return std::make_pair(box->NeedsAnchorPositionScrollAdjustmentInX(),
                        box->NeedsAnchorPositionScrollAdjustmentInY());
}

}  // namespace

AnchorPositionScrollData::AnchorPositionScrollData(Element* anchored_element)
    : ScrollSnapshotClient(anchored_element->GetDocument().GetFrame()),
      anchored_element_(anchored_element) {}

AnchorPositionScrollData::~AnchorPositionScrollData() = default;

bool AnchorPositionScrollData::IsActive() const {
  return anchored_element_->GetAnchorPositionScrollData() == this;
}

gfx::Vector2dF AnchorPositionScrollData::TotalOffset(
    const LayoutObject& anchor_object) const {
  if (anchor_object == default_anchor_adjustment_data_.anchor_object) {
    return default_anchor_adjustment_data_.TotalOffset();
  }

  return ComputeAdjustmentContainersData(anchor_object).TotalOffset();
}

AnchorPositionScrollData::AdjustmentData
AnchorPositionScrollData::ComputeAdjustmentContainersData(
    const LayoutObject& anchor) const {
  CHECK(anchored_element_->GetLayoutObject());
  AnchorPositionScrollData::AdjustmentData result;

  auto container_ignore_layout_view_for_fixed_pos =
      [](const LayoutObject& o) -> const LayoutObject* {
    const auto* container = o.Container();
    if (o.IsFixedPositioned() && container->IsLayoutView()) {
      return nullptr;
    }
    return container;
  };

  result.anchor_object = &anchor;
  const auto* bounding_container = container_ignore_layout_view_for_fixed_pos(
      *anchored_element_->GetLayoutObject());

  if (bounding_container && bounding_container->IsScrollContainer()) {
    result.anchored_element_container_scroll_offset =
        To<LayoutBox>(bounding_container)
            ->GetScrollableArea()
            ->GetScrollOffset();
  }

  for (const auto* container = &anchor;
       container && container != bounding_container;
       container = container_ignore_layout_view_for_fixed_pos(*container)) {
    if (container->IsScrollContainer()) {
      const PaintLayerScrollableArea* scrollable_area =
          To<LayoutBox>(container)->GetScrollableArea();
      if (container != anchor && container != bounding_container &&
          // No need to adjust if the scroll container can't scroll anything.
          To<LayoutBox>(container)->HasScrollableOverflow()) {
        result.adjustment_container_ids.push_back(
            scrollable_area->GetScrollElementId());
        result.accumulated_adjustment += scrollable_area->GetScrollOffset();
        result.accumulated_adjustment_scroll_origin +=
            scrollable_area->ScrollOrigin().OffsetFromOrigin();
        if (scrollable_area->GetLayoutBox()->IsLayoutView()) {
          result.containers_include_viewport = true;
        }
      }
    }
    if (const auto* box_model = DynamicTo<LayoutBoxModelObject>(container)) {
      if (box_model->StickyConstraints()) {
        result.adjustment_container_ids.push_back(
            CompositorElementIdFromUniqueObjectId(
                box_model->UniqueId(),
                CompositorElementIdNamespace::kStickyTranslation));
        result.accumulated_adjustment -=
            gfx::Vector2dF(box_model->StickyPositionOffset());
      }
    }
    if (const auto* box = DynamicTo<LayoutBox>(container)) {
      if (auto* data = box->GetAnchorPositionScrollData()) {
        result.has_chained_anchor = true;
        if (data->NeedsScrollAdjustment()) {
          // Add accumulated offset from chained anchor-positioned element.
          // If the data of that element is not up-to-date, when it's updated,
          // we'll schedule needed update according to the type of the change.
          result.adjustment_container_ids.push_back(
              CompositorElementIdFromUniqueObjectId(
                  box->UniqueId(), CompositorElementIdNamespace::
                                       kAnchorPositionScrollTranslation));
          result.accumulated_adjustment +=
              gfx::Vector2dF(data->ComputeDefaultAnchorAdjustmentData()
                                 .accumulated_adjustment);
        }
      }
    }
  }
  return result;
}

AnchorPositionScrollData::AdjustmentData
AnchorPositionScrollData::ComputeDefaultAnchorAdjustmentData() const {
  const LayoutObject* layout_object = anchored_element_->GetLayoutObject();
  auto [needs_scroll_adjustment_in_x, needs_scroll_adjustment_in_y] =
      CheckHasDefaultAnchorReferences(layout_object);
  if (!needs_scroll_adjustment_in_x && !needs_scroll_adjustment_in_y) {
    return AdjustmentData();
  }

  const LayoutObject* anchor_default_object =
      PositionAnchorObject(To<LayoutBox>(*layout_object));
  if (!anchor_default_object) {
    return AdjustmentData();
  }

  auto result = ComputeAdjustmentContainersData(*anchor_default_object);
  if (result.adjustment_container_ids.empty()) {
    needs_scroll_adjustment_in_x = false;
    needs_scroll_adjustment_in_y = false;
  }
  // These don't reset anchored_element_container_scroll_offset because the
  // scroll container always scrolls the anchored element.
  if (!needs_scroll_adjustment_in_x) {
    result.accumulated_adjustment.set_x(0);
    result.accumulated_adjustment_scroll_origin.set_x(0);
  }
  if (!needs_scroll_adjustment_in_y) {
    result.accumulated_adjustment.set_y(0);
    result.accumulated_adjustment_scroll_origin.set_y(0);
  }
  result.needs_scroll_adjustment_in_x = needs_scroll_adjustment_in_x;
  result.needs_scroll_adjustment_in_y = needs_scroll_adjustment_in_y;
  return result;
}

AnchorPositionScrollData::SnapshotDiff
AnchorPositionScrollData::TakeAndCompareSnapshot(bool update) {
  DCHECK(IsActive());

  AdjustmentData new_adjustment_data = ComputeDefaultAnchorAdjustmentData();

  SnapshotDiff diff = SnapshotDiff::kNone;
  if (default_anchor_adjustment_data_.anchor_object !=
          new_adjustment_data.anchor_object ||
      AdjustmentContainerIds() !=
          new_adjustment_data.adjustment_container_ids ||
      !IsFallbackPositionValid(new_adjustment_data)) {
    diff = SnapshotDiff::kScrollersOrFallbackPosition;
  } else if (NeedsScrollAdjustmentInX() !=
                 new_adjustment_data.needs_scroll_adjustment_in_x ||
             NeedsScrollAdjustmentInY() !=
                 new_adjustment_data.needs_scroll_adjustment_in_y ||
             default_anchor_adjustment_data_.TotalOffset() !=
                 new_adjustment_data.TotalOffset() ||
             AccumulatedAdjustmentScrollOrigin() !=
                 new_adjustment_data.accumulated_adjustment_scroll_origin) {
    // When needs_scroll_adjustment_in_x/y changes, we still need to update
    // paint properties so that compositor can calculate the translation
    // offset correctly.
    diff = SnapshotDiff::kOffsetOnly;
  }

  if (update && diff != SnapshotDiff::kNone) {
    default_anchor_adjustment_data_ = std::move(new_adjustment_data);
  }

  return diff;
}

bool AnchorPositionScrollData::IsFallbackPositionValid(
    const AdjustmentData& new_adjustment_data) const {
  const HeapVector<NonOverflowingScrollRange>* non_overflowing_scroll_ranges =
      GetNonOverflowingScrollRanges(anchored_element_->GetLayoutObject());
  if (!non_overflowing_scroll_ranges ||
      non_overflowing_scroll_ranges->empty()) {
    return true;
  }

  for (const NonOverflowingScrollRange& range :
       *non_overflowing_scroll_ranges) {
    if (range.anchor_object != new_adjustment_data.anchor_object) {
      // The range was calculated with a different anchor object. Check if the
      // anchored element (which previously overflowed with the try option that
      // specified that anchor) will become non-overflowing with that option.
      if (range.Contains(TotalOffset(*range.anchor_object))) {
        return false;
      }
    } else {
      // The range was calculated with the same anchor object as this data.
      // Check if the overflow status of the anchored element will change with
      // the new total offset.
      if (range.Contains(default_anchor_adjustment_data_.TotalOffset()) !=
          range.Contains(new_adjustment_data.TotalOffset())) {
        return false;
      }
    }
  }
  return true;
}

void AnchorPositionScrollData::UpdateSnapshot() {
  ValidateSnapshot();
}

bool AnchorPositionScrollData::ValidateSnapshot() {
  // If this AnchorPositionScrollData is detached in the previous style recalc,
  // we no longer need to validate it.
  if (!IsActive()) {
    return true;
  }

  SnapshotDiff diff = TakeAndCompareSnapshot(true /* update */);
  switch (diff) {
    case SnapshotDiff::kNone:
      return true;
    case SnapshotDiff::kOffsetOnly:
      InvalidatePaint();
      return true;
    case SnapshotDiff::kScrollersOrFallbackPosition:
      InvalidateLayoutAndPaint();
      return false;
  }
}

bool AnchorPositionScrollData::ShouldScheduleNextService() {
  return IsActive() &&
         TakeAndCompareSnapshot(false /*update*/) != SnapshotDiff::kNone;
}

AnchorPositionVisibilityObserver&
AnchorPositionScrollData::EnsureAnchorPositionVisibilityObserver() {
  if (!position_visibility_observer_) {
    position_visibility_observer_ =
        MakeGarbageCollected<AnchorPositionVisibilityObserver>(
            *anchored_element_);
  }
  return *position_visibility_observer_;
}

void AnchorPositionScrollData::InvalidateLayoutAndPaint() {
  DCHECK(IsActive());
  DCHECK(anchored_element_->GetLayoutObject());
  anchored_element_->GetLayoutObject()->SetNeedsLayoutAndFullPaintInvalidation(
      layout_invalidation_reason::kAnchorPositioning);
  anchored_element_->GetLayoutObject()->SetNeedsPaintPropertyUpdate();
}

void AnchorPositionScrollData::InvalidatePaint() {
  DCHECK(IsActive());
  DCHECK(anchored_element_->GetLayoutObject());
  anchored_element_->GetLayoutObject()->SetNeedsPaintPropertyUpdate();
}

void AnchorPositionScrollData::Trace(Visitor* visitor) const {
  visitor->Trace(anchored_element_);
  visitor->Trace(default_anchor_adjustment_data_);
  visitor->Trace(position_visibility_observer_);
  ScrollSnapshotClient::Trace(visitor);
  ElementRareDataField::Trace(visitor);
}

}  // namespace blink
```