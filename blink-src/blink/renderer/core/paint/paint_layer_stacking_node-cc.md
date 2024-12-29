Response:
Let's break down the thought process for analyzing this C++ source code file. The goal is to understand its functionality and its relation to web technologies (HTML, CSS, JavaScript), identify potential usage errors, and understand the debugging context.

**1. Initial Understanding - High-Level Overview:**

* **File Name and Location:** The file `blink/renderer/core/paint/paint_layer_stacking_node.cc` immediately suggests it's part of the rendering engine (blink) and specifically deals with paint layers and their stacking order. The "stacking node" part is a strong hint about its core purpose.
* **Copyright and License:**  The initial comments are boilerplate copyright and licensing information. While important legally, they don't directly contribute to understanding the code's function. We can skip over these for now.
* **Includes:** The `#include` directives give crucial clues about dependencies and related functionalities:
    * `<algorithm>`:  Indicates sorting and other algorithm-related operations are likely used.
    * `<memory>`: Suggests memory management, possibly involving smart pointers.
    * `base/types/optional_util.h`:  Hints at the use of `std::optional` or a similar construct.
    * `third_party/blink/public/platform/platform.h`: A general Blink platform header, suggesting interaction with the underlying system.
    * The remaining includes (`layout/...`, `paint/...`) confirm the file's role in the layout and painting processes. Specifically, `PaintLayer`, `PaintLayerScrollableArea`, and `Layout...` objects are directly involved.

**2. Core Class - `PaintLayerStackingNode`:**

* **Constructor:**  `PaintLayerStackingNode(PaintLayer* layer)` takes a `PaintLayer` as input and asserts that the layer is a stacking context. This is a key piece of information: this class is associated with layers that *create* a new stacking context.
* **`DirtyZOrderLists()`:** This function clears the positive and negative z-order lists (`pos_z_order_list_`, `neg_z_order_list_`) and a map related to overlay overflow controls. It also sets a `z_order_lists_dirty_` flag. This signals that the current z-order information is outdated and needs to be rebuilt.
* **`ZIndexLessThan()`:** A static helper function to compare two `PaintLayer` objects based on their effective `z-index`. This confirms the importance of the `z-index` CSS property in the stacking order.
* **`SetIfHigher()`:** Another static helper, this one seems to determine which of two layers has a higher z-index and updates a pointer accordingly. It also seems to prioritize layers appearing later in the tree if z-indices are equal or the first layer is null.
* **`HighestLayers` struct:**  This struct appears to track the "highest" layers of different types (absolute, fixed, in-flow stacked) within a subtree. The `UpdateOrderForSubtreeHighestLayers` and `Update` methods suggest a process of traversing the layer tree and identifying these highest layers based on their positioning. The `Merge` method indicates combining information from child nodes. This is related to correctly ordering overlay scrollbars.
* **`ChildOfFlexboxOrGridParentOrGrandparent()`:** A helper function to check if a layer is a direct or indirect child of a flexbox or grid container. This points to the influence of flexbox and grid layout on stacking order.
* **`OrderLessThan()`:** Compares the `order` CSS property of two layers, specifically when they are children of flexbox or grid containers. This confirms the `order` property's role in influencing paint order within these layout models.
* **`GetOrderSortedChildren()`:** Sorts the children of a `PaintLayer` based on the `order` property. This is crucial for flexbox and grid layouts.
* **`RebuildZOrderLists()`:** This is a core function that rebuilds the `pos_z_order_list_` and `neg_z_order_list_` by iterating through the children and calling `CollectLayers`. It also handles "top layer" elements.
* **`CollectLayers()`:** This recursive function traverses the paint layer tree. It determines if a layer should be added to the positive or negative z-order list based on its `z-index`. It also handles the logic for overlay overflow controls and interacts with the `HighestLayers` struct.
* **`StyleDidChange()`:** Checks if relevant style properties (stacking context, z-index, order) have changed and marks the z-order lists as dirty if so.
* **`UpdateZOrderLists()`:**  Calls `RebuildZOrderLists()` only if the lists are marked as dirty.
* **`Trace()`:** A debugging function for tracing object relationships.

**3. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **CSS `z-index`:** The code heavily relies on the `z-index` CSS property to determine the stacking order of elements. `ZIndexLessThan` and the logic in `CollectLayers` directly implement this.
* **CSS `position: absolute`, `position: fixed`:**  The `HighestLayers` struct specifically tracks absolute and fixed positioned elements, demonstrating their special handling in stacking contexts.
* **CSS `display: flex`, `display: grid` and `order`:** The `ChildOfFlexboxOrGridParentOrGrandparent`, `OrderLessThan`, and `GetOrderSortedChildren` functions show how the `order` property within flexbox and grid layouts affects painting order.
* **Stacking Contexts:** The very existence of `PaintLayerStackingNode` and its constructor's assertion highlight the concept of stacking contexts as defined by CSS. Properties like `position: relative` with a `z-index`, `position: fixed`, `opacity` less than 1, and others can create stacking contexts.
* **Overlay Scrollbars:** The logic involving `layer_to_overlay_overflow_controls_painting_after_` and the `HighestLayers` struct addresses the specific rendering challenges of overlay scrollbars, ensuring they appear above the correct content.
* **Top Layer (`<dialog>`, `<popover>`):** The code mentions handling "top layer" elements, which relates to the `<dialog>` and `<popover>` HTML elements and their special stacking behavior.

**4. Logic and Assumptions (Hypothetical Input/Output):**

* **Input:** A DOM tree with specific CSS properties applied (e.g., `z-index`, `position`, `display: flex`, `order`).
* **Process:** The browser's rendering engine processes the HTML and CSS, creating `LayoutObject` and `PaintLayer` objects. For elements that create stacking contexts, a `PaintLayerStackingNode` is created.
* **Output:**  The `PaintLayerStackingNode` manages the sorted lists of child paint layers (`pos_z_order_list_`, `neg_z_order_list_`). These lists dictate the order in which the layers are painted, ultimately determining which elements appear on top of others on the screen.

**Example:**

* **HTML:**
  ```html
  <div style="position: relative; z-index: 1;">
    <div style="position: absolute; z-index: 2;"></div>
    <div style="position: absolute; z-index: 1;"></div>
  </div>
  ```
* **CSS:** (inline styles in HTML example)
* **Blink Processing:** The `<div>` with `position: relative; z-index: 1;` creates a stacking context. A `PaintLayerStackingNode` is created for this element. The two absolutely positioned `div` elements become children in the paint tree.
* **`CollectLayers`:** The `CollectLayers` function would be called for the stacking context. The absolutely positioned divs would be added to the `pos_z_order_list_`.
* **`RebuildZOrderLists`:** The `pos_z_order_list_` would be sorted based on `z-index`, resulting in the div with `z-index: 2` appearing later in the list (and thus painted on top).

**5. Common Usage Errors and Debugging:**

* **Incorrect `z-index` Values:**  A common mistake is assigning `z-index` values without understanding stacking contexts. An element with a high `z-index` might still be painted behind another element if they are in different stacking contexts.
* **Forgetting Stacking Context Creation:** Developers might assume an element will be on top due to its `z-index`, but fail to realize that a parent element has created a stacking context, limiting the scope of the `z-index`.
* **Misunderstanding `order` in Flexbox/Grid:** Incorrect use of the `order` property can lead to unexpected painting order, especially when combined with `z-index`.
* **Debugging:**
    * **Scenario:** A developer sees an element with `z-index: 100` being painted behind another element with `z-index: 1`.
    * **Debugging Steps:**
        1. **Inspect Stacking Contexts:** Use browser developer tools to identify which elements are creating stacking contexts.
        2. **Examine Paint Order:** Browser dev tools often have features to visualize the paint order of elements.
        3. **Set Breakpoints:** A developer could set breakpoints in `RebuildZOrderLists` or `CollectLayers` in the Blink source code to inspect the contents of the z-order lists and understand why the elements are being ordered the way they are. They could inspect the `EffectiveZIndex()` of the involved `PaintLayer` objects.
        4. **Trace Execution:**  Following the execution flow through functions like `CollectLayers` can reveal how the stacking order is being determined.

**6. User Operations Leading to This Code:**

1. **User Loads a Webpage:** The initial rendering process begins when a user navigates to a webpage.
2. **HTML Parsing and DOM Tree Creation:** The browser parses the HTML, creating the Document Object Model (DOM) tree.
3. **CSS Parsing and Style Calculation:** The browser parses the CSS (both external stylesheets and inline styles) and calculates the computed styles for each element in the DOM.
4. **Layout:** The browser performs layout, determining the size and position of each element based on the computed styles. This involves creating `LayoutObject` objects.
5. **Paint Tree Creation:** The browser creates a paint tree, a structure optimized for painting. This involves creating `PaintLayer` objects.
6. **Stacking Context Identification:** During paint tree creation, the browser identifies elements that create stacking contexts.
7. **`PaintLayerStackingNode` Instantiation:** For each `PaintLayer` that represents a stacking context, a `PaintLayerStackingNode` object is created.
8. **Z-Order List Population:** When the paint information is needed, functions like `RebuildZOrderLists` and `CollectLayers` are called to populate the `pos_z_order_list_` and `neg_z_order_list_`, guiding the actual painting process.
9. **Painting:** The browser iterates through the sorted paint layers and renders them to the screen.
10. **Style Changes (JavaScript/CSS Transitions/Animations):** If JavaScript modifies styles (e.g., changing `z-index`, `position`, `display`, `order`) or CSS transitions/animations occur, the `StyleDidChange` function is called. If a relevant style change is detected, the `DirtyZOrderLists` function is called, marking the lists as needing to be rebuilt. The next paint will then trigger `UpdateZOrderLists` and `RebuildZOrderLists` to reflect the changes.

This detailed thought process combines code analysis, understanding of web standards, and reasoning about potential issues and debugging approaches to fully explain the functionality of the provided C++ source code.
This C++ source code file, `paint_layer_stacking_node.cc`, within the Chromium Blink rendering engine, is responsible for managing the **stacking order of paint layers** within a stacking context. Let's break down its functionalities and relationships:

**Core Functionalities:**

1. **Maintaining Z-Order Lists:**
   - It manages two lists: `pos_z_order_list_` for paint layers with a non-negative `z-index` and `neg_z_order_list_` for layers with a negative `z-index`.
   - These lists store pointers to `PaintLayer` objects that are children of the stacking context this node represents.
   - The order within these lists determines the painting order of these layers within the stacking context. Layers appearing later in the list are painted on top.

2. **Rebuilding Z-Order Lists (`RebuildZOrderLists`):**
   - When the stacking order needs to be recalculated (e.g., due to style changes), this function clears the existing lists and rebuilds them.
   - It iterates through the child paint layers of the associated stacking context.
   - It uses the `z-index` of each child layer to determine whether it belongs in the positive or negative z-order list.
   - It then sorts these lists based on the effective `z-index` of the layers.

3. **Collecting Layers (`CollectLayers`):**
   - This recursive function traverses the paint layer tree starting from the children of the associated stacking context.
   - It determines if a layer is "stacked" (has a `z-index` other than `auto`) and adds it to the appropriate z-order list.
   - It handles the case where a child layer is itself a stacking context (recursion stops there for z-order list collection for the current node).

4. **Handling `order` Property in Flexbox/Grid (`GetOrderSortedChildren`, `OrderLessThan`):**
   - For stacking contexts created by flexbox or grid containers, the `order` CSS property influences the painting order of direct children.
   - `GetOrderSortedChildren` retrieves the children and sorts them based on their `order` property using `std::stable_sort` and the `OrderLessThan` comparison function.
   - `OrderLessThan` compares the `order` values of two layers that are direct or indirect children of the same flexbox/grid container.

5. **Managing Overlay Overflow Controls:**
   - The code includes logic (`layer_to_overlay_overflow_controls_painting_after_`, `HighestLayers`) to handle the correct z-ordering of overlay scrollbars.
   - Overlay scrollbars should generally appear on top of most content but below fixed-position elements outside their container.
   - `HighestLayers` tracks the highest z-indexed absolute, fixed, and in-flow stacked elements within a subtree to determine where to insert the overlay controls.

6. **Detecting Style Changes (`StyleDidChange`):**
   - This function is called when the style of a paint layer changes.
   - It checks if properties relevant to stacking (e.g., `z-index`, becoming a stacking context) have changed.
   - If so, it flags the z-order lists of the current stacking node as dirty, requiring a rebuild.

7. **Updating Z-Order Lists (`UpdateZOrderLists`):**
   - This function checks if the `z_order_lists_dirty_` flag is set.
   - If it is, it calls `RebuildZOrderLists` to recalculate the stacking order.

**Relationship with JavaScript, HTML, and CSS:**

This code is a core part of how the browser visually renders web pages based on HTML, CSS, and potentially influenced by JavaScript.

* **HTML:** The structure of the HTML document creates the initial element hierarchy, which is reflected in the paint layer tree. Elements with specific properties can become stacking contexts.
* **CSS:**  CSS properties directly control the behavior managed by this code:
    * **`z-index`:** The primary driver for stacking order. This code interprets and applies the `z-index` values.
    * **`position: relative`, `position: absolute`, `position: fixed`:**  Elements with `position: relative` and a `z-index` other than `auto`, `position: absolute`, or `position: fixed` often create new stacking contexts. The type of positioning also influences the `HighestLayers` logic for overlay controls.
    * **`display: flex`, `display: grid`, `order`:** The `order` property within flexbox and grid containers is explicitly handled to determine the painting order of items within these layouts.
    * **Other properties that create stacking contexts:** `opacity` (less than 1), `transform`, `filter`, `isolation`, etc., will lead to the creation of `PaintLayerStackingNode` instances.
* **JavaScript:** JavaScript can dynamically modify the CSS properties mentioned above. When JavaScript changes `z-index`, `position`, `display`, or `order`, the `StyleDidChange` function is triggered, eventually leading to a recalculation of the stacking order.

**Examples:**

* **CSS `z-index`:**
   ```html
   <div style="position: relative; z-index: 1;">
       <div style="position: absolute; z-index: 2; background-color: red;">Red Box</div>
       <div style="position: absolute; z-index: 1; background-color: blue;">Blue Box</div>
   </div>
   ```
   In this case, the outer `div` creates a stacking context. The `PaintLayerStackingNode` for this `div` will manage the z-ordering of the red and blue boxes. The red box (higher `z-index`) will be placed later in the `pos_z_order_list_` and painted on top of the blue box.

* **CSS `order` in Flexbox:**
   ```html
   <div style="display: flex;">
       <div style="order: 2;">Item 1</div>
       <div style="order: 1;">Item 2</div>
   </div>
   ```
   The flex container creates a stacking context. `GetOrderSortedChildren` will be called, and `OrderLessThan` will ensure "Item 2" (order: 1) is processed before "Item 1" (order: 2) during painting, even though it appears first in the HTML.

**Logical Reasoning (Hypothetical Input and Output):**

**Input:** A `PaintLayer` representing a stacking context and its child `PaintLayer` objects.

**Scenario:**  Let's say the stacking context has three child layers:
   - Layer A: `z-index: 2`
   - Layer B: `z-index: -1`
   - Layer C: `z-index: 1`

**Process:**

1. `CollectLayers` would be called.
2. Layer A (`z-index: 2`) would be added to `pos_z_order_list_`.
3. Layer B (`z-index: -1`) would be added to `neg_z_order_list_`.
4. Layer C (`z-index: 1`) would be added to `pos_z_order_list_`.
5. `RebuildZOrderLists` would sort the lists:
   - `neg_z_order_list_`: [Layer B] (only one element, no sorting needed)
   - `pos_z_order_list_`: [Layer C, Layer A] (sorted by `z-index` ascending)

**Output:** The painting order within this stacking context would be: Layer B, then Layer C, then Layer A.

**User or Programming Common Usage Errors:**

1. **Incorrect `z-index` assumptions:** Developers might assume a higher `z-index` always means being on top, without understanding the concept of stacking contexts. An element with a high `z-index` might be within a stacking context that is painted behind another element with a lower `z-index` in a different stacking context.
2. **Forgetting to create a stacking context:** Sometimes developers intend for an element to be on top but forget to give it a `z-index` when its parent doesn't establish a stacking context. In such cases, the `z-index` will be ignored.
3. **Misunderstanding the `order` property:** In flexbox or grid layouts, the `order` property can override the source order. Developers might be confused when elements are painted in a different order than they appear in the HTML.
4. **Over-reliance on high `z-index`:**  Using excessively high `z-index` values can make it harder to manage the stacking order. It's generally better to use smaller, relative `z-index` values within each stacking context.

**User Operations Leading to This Code (Debugging Clues):**

1. **User loads a webpage:**  The initial rendering process involves creating paint layers and their stacking contexts.
2. **User interacts with the page:**  Hovering over elements, clicking buttons, or triggering animations can change CSS properties.
3. **JavaScript modifies styles:** JavaScript code might dynamically change the `z-index`, `position`, `display`, or `order` of elements.
4. **CSS transitions or animations occur:** These can also change CSS properties over time.
5. **Layout changes:** Resizing the browser window or changing the viewport can trigger layout recalculations and potentially affect stacking contexts.
6. **Scrolling:** When content with overlay scrollbars is scrolled, the logic to position the scrollbars correctly comes into play.

**Debugging Scenario:**

Let's say a developer notices an element with `z-index: 100` being painted behind another element with `z-index: 1`. To debug this, they might:

1. **Inspect the elements in the browser's developer tools:** Look for the computed `z-index` and identify which elements are creating stacking contexts.
2. **Set breakpoints in `RebuildZOrderLists` or `CollectLayers`:**  This allows the developer to step through the code and see how the z-order lists are being built. They can inspect the `EffectiveZIndex()` of the `PaintLayer` objects and see why they are being placed in a particular order.
3. **Trace the execution of `StyleDidChange`:**  If the issue arises after a style change, they can trace when and why this function is called and whether it correctly marks the z-order lists as dirty.
4. **Examine the paint order visualization in the developer tools:** Some browsers offer tools to visualize the order in which elements are painted, which can help identify unexpected stacking.

In summary, `paint_layer_stacking_node.cc` is a critical component in Blink's rendering engine, responsible for correctly implementing CSS stacking rules and ensuring elements are painted in the intended order based on `z-index`, `position`, `order`, and the creation of stacking contexts. It bridges the gap between CSS styles and the actual visual rendering of web pages.

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_stacking_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All rights
 * reserved.
 *
 * Portions are Copyright (C) 1998 Netscape Communications Corporation.
 *
 * Other contributors:
 *   Robert O'Callahan <roc+@cs.cmu.edu>
 *   David Baron <dbaron@dbaron.org>
 *   Christian Biesinger <cbiesinger@web.de>
 *   Randall Jesup <rjesup@wgate.com>
 *   Roland Mainz <roland.mainz@informatik.med.uni-giessen.de>
 *   Josh Soref <timeless@mac.com>
 *   Boris Zbarsky <bzbarsky@mit.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Alternatively, the contents of this file may be used under the terms
 * of either the Mozilla Public License Version 1.1, found at
 * http://www.mozilla.org/MPL/ (the "MPL") or the GNU General Public
 * License Version 2.0, found at http://www.fsf.org/copyleft/gpl.html
 * (the "GPL"), in which case the provisions of the MPL or the GPL are
 * applicable instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of one of those two
 * licenses (the MPL or the GPL) and not to allow others to use your
 * version of this file under the LGPL, indicate your decision by
 * deletingthe provisions above and replace them with the notice and
 * other provisions required by the MPL or the GPL, as the case may be.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under any of the LGPL, the MPL or the GPL.
 */

#include "third_party/blink/renderer/core/paint/paint_layer_stacking_node.h"

#include <algorithm>
#include <memory>

#include "base/types/optional_util.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

namespace blink {

// FIXME: This should not require PaintLayer. There is currently a cycle where
// in order to determine if we isStacked() we have to ask the paint
// layer about some of its state.
PaintLayerStackingNode::PaintLayerStackingNode(PaintLayer* layer)
    : layer_(layer) {
  DCHECK(layer->GetLayoutObject().IsStackingContext());
}

void PaintLayerStackingNode::DirtyZOrderLists() {
#if DCHECK_IS_ON()
  DCHECK(layer_->LayerListMutationAllowed());
#endif

  pos_z_order_list_.clear();
  neg_z_order_list_.clear();

  for (auto& entry :
       layer_to_overlay_overflow_controls_painting_after_.Values()) {
    for (PaintLayer* layer : *entry)
      layer->SetNeedsReorderOverlayOverflowControls(false);
  }
  layer_to_overlay_overflow_controls_painting_after_.clear();

  z_order_lists_dirty_ = true;
}

static bool ZIndexLessThan(const PaintLayer* first, const PaintLayer* second) {
  DCHECK(first->GetLayoutObject().IsStacked());
  DCHECK(second->GetLayoutObject().IsStacked());
  return first->GetLayoutObject().StyleRef().EffectiveZIndex() <
         second->GetLayoutObject().StyleRef().EffectiveZIndex();
}

static bool SetIfHigher(const PaintLayer*& first, const PaintLayer* second) {
  if (!second)
    return false;
  DCHECK_GE(second->GetLayoutObject().StyleRef().EffectiveZIndex(), 0);
  // |second| appears later in the tree, so it's higher than |first| if its
  // z-index >= |first|'s z-index.
  if (!first || !ZIndexLessThan(second, first)) {
    first = second;
    return true;
  }
  return false;
}

// For finding the proper z-order of reparented overlay overflow controls.
struct PaintLayerStackingNode::HighestLayers {
  STACK_ALLOCATED();

 public:
  enum LayerType {
    kAbsolutePosition,
    kFixedPosition,
    kInFlowStacked,
    kLayerTypeCount
  };
  std::array<const PaintLayer*, kLayerTypeCount> highest_layers = {
      nullptr, nullptr, nullptr};
  Vector<LayerType, kLayerTypeCount> highest_layers_order;

  void UpdateOrderForSubtreeHighestLayers(LayerType type,
                                          const PaintLayer* layer) {
    if (SetIfHigher(highest_layers[type], layer)) {
      auto new_end = std::remove(highest_layers_order.begin(),
                                 highest_layers_order.end(), type);
      if (new_end != highest_layers_order.end()) {
        // |highest_layers_order| doesn't have duplicate elements, std::remove
        // will find at most one element at a time. So we don't shrink it and
        // just update the value of the |new_end|.
        DCHECK(std::next(new_end) == highest_layers_order.end());
        *new_end = type;
      } else {
        highest_layers_order.push_back(type);
      }
    }
  }

  static LayerType GetLayerType(const PaintLayer& layer) {
    DCHECK(layer.GetLayoutObject().IsStacked());
    const auto& style = layer.GetLayoutObject().StyleRef();
    if (style.GetPosition() == EPosition::kAbsolute)
      return kAbsolutePosition;
    if (style.GetPosition() == EPosition::kFixed)
      return kFixedPosition;
    return kInFlowStacked;
  }

  void Update(const PaintLayer& layer) {
    const auto& style = layer.GetLayoutObject().StyleRef();
    // We only need to consider zero or positive z-index stacked child for
    // candidates of causing reparent of overlay scrollbars of ancestors.
    // A negative z-index child will not cause reparent of overlay scrollbars
    // because the ancestor scroller either has auto z-index which is above
    // the child or has negative z-index which is a stacking context.
    if (!layer.GetLayoutObject().IsStacked() || style.EffectiveZIndex() < 0)
      return;

    UpdateOrderForSubtreeHighestLayers(GetLayerType(layer), &layer);
  }

  void Merge(HighestLayers& child, const PaintLayer& current_layer) {
    const auto& object = current_layer.GetLayoutObject();
    for (auto layer_type : child.highest_layers_order) {
      auto layer_type_for_propagation = layer_type;
      if (object.IsStacked()) {
        if ((layer_type == kAbsolutePosition &&
             object.CanContainAbsolutePositionObjects()) ||
            (layer_type == kFixedPosition &&
             object.CanContainFixedPositionObjects()) ||
            layer_type == kInFlowStacked) {
          // If the child is contained by the current layer, then use the
          // current layer's type for propagation to ancestors.
          layer_type_for_propagation = GetLayerType(current_layer);
        }
      }
      UpdateOrderForSubtreeHighestLayers(layer_type_for_propagation,
                                         child.highest_layers[layer_type]);
    }
  }
};

static LayoutObject* ChildOfFlexboxOrGridParentOrGrandparent(
    const PaintLayer* layer) {
  LayoutObject* parent = layer->GetLayoutObject().Parent();
  if (!parent) {
    return nullptr;
  }
  if (parent->IsFlexibleBox() || parent->IsLayoutGrid()) {
    return &layer->GetLayoutObject();
  }

  LayoutObject* grandparent = parent->Parent();
  if (!grandparent) {
    return nullptr;
  }
  if (grandparent->IsFlexibleBox() || grandparent->IsLayoutGrid()) {
    return parent;
  }
  return nullptr;
}

static bool OrderLessThan(const PaintLayer* first, const PaintLayer* second) {
  // TODO(chrishtr): make this work for arbitrary ancestors, not just parent
  // and grandparent.
  LayoutObject* first_ancestor = ChildOfFlexboxOrGridParentOrGrandparent(first);
  LayoutObject* second_ancestor =
      ChildOfFlexboxOrGridParentOrGrandparent(second);
  if (!first_ancestor || !second_ancestor) {
    return false;
  }

  if (first_ancestor->Parent() != second_ancestor->Parent()) {
    return false;
  }

  auto& first_style = first_ancestor->StyleRef();
  auto& second_style = second_ancestor->StyleRef();
  int first_order = 0;
  int second_order = 0;
  // Out of flow flexbox direct children paint as if order was 0:
  // https://drafts.csswg.org/css-display-4/#order-modified-document-order
  if (first_ancestor != first->GetLayoutObject() ||
      !first_ancestor->IsOutOfFlowPositioned()) {
    first_order = first_style.Order();
  }
  if (second_ancestor != second->GetLayoutObject() ||
      !second_ancestor->IsOutOfFlowPositioned()) {
    second_order = second_style.Order();
  }
  return first_order < second_order;
}

// Returns the children of |paint_layer|, sorted by the order CSS property
// if they are the child of a flexbox. See:
// https://www.w3.org/TR/css-flexbox-1/#painting
static void GetOrderSortedChildren(
    PaintLayer* paint_layer,
    PaintLayerStackingNode::PaintLayers& sorted_children) {
  for (PaintLayer* child = paint_layer->FirstChild(); child;
       child = child->NextSibling()) {
    sorted_children.push_back(child);
  }

  std::stable_sort(sorted_children.begin(), sorted_children.end(),
                   OrderLessThan);
}

void PaintLayerStackingNode::RebuildZOrderLists() {
#if DCHECK_IS_ON()
  DCHECK(layer_->LayerListMutationAllowed());
#endif
  DCHECK(z_order_lists_dirty_);

  layer_->SetNeedsReorderOverlayOverflowControls(false);
  PaintLayers order_sorted_children;
  GetOrderSortedChildren(layer_, order_sorted_children);
  for (auto& child : order_sorted_children) {
    CollectLayers(*child, nullptr);
  }

  // Sort the two lists.
  std::stable_sort(pos_z_order_list_.begin(), pos_z_order_list_.end(),
                   ZIndexLessThan);
  std::stable_sort(neg_z_order_list_.begin(), neg_z_order_list_.end(),
                   ZIndexLessThan);

  // Append layers for top layer elements after normal layer collection, to
  // ensure they are on top regardless of z-indexes.  The layoutObjects of top
  // layer elements are children of the view, sorted in top layer stacking
  // order.
  if (layer_->IsRootLayer()) {
    LayoutBlockFlow* root_block = layer_->GetLayoutObject().View();
    // If the viewport is paginated, everything (including "top-layer" elements)
    // gets redirected to the flow thread. So that's where we have to look, in
    // that case.
    if (LayoutBlockFlow* multi_column_flow_thread =
            root_block->MultiColumnFlowThread())
      root_block = multi_column_flow_thread;
    for (LayoutObject* child = root_block->FirstChild(); child;
         child = child->NextSibling()) {
      if (child->IsInTopOrViewTransitionLayer() && child->IsStacked()) {
        pos_z_order_list_.push_back(To<LayoutBoxModelObject>(child)->Layer());
      }
    }
  }
  z_order_lists_dirty_ = false;
}

void PaintLayerStackingNode::CollectLayers(PaintLayer& paint_layer,
                                           HighestLayers* highest_layers) {
  paint_layer.SetNeedsReorderOverlayOverflowControls(false);

  if (paint_layer.IsInTopOrViewTransitionLayer()) {
    return;
  }

  if (highest_layers)
    highest_layers->Update(paint_layer);

  const auto& object = paint_layer.GetLayoutObject();
  const auto& style = object.StyleRef();

  if (object.IsStacked()) {
    auto& list =
        style.EffectiveZIndex() >= 0 ? pos_z_order_list_ : neg_z_order_list_;
    list.push_back(paint_layer);
  }

  if (object.IsStackingContext())
    return;

  std::optional<HighestLayers> subtree_highest_layers;
  bool has_overlay_overflow_controls =
      paint_layer.GetScrollableArea() &&
      paint_layer.GetScrollableArea()->HasOverlayOverflowControls();
  if (has_overlay_overflow_controls || highest_layers)
    subtree_highest_layers.emplace();

  PaintLayers order_sorted_children;
  GetOrderSortedChildren(&paint_layer, order_sorted_children);
  for (auto& child : order_sorted_children) {
    CollectLayers(*child, base::OptionalToPtr(subtree_highest_layers));
  }

  if (has_overlay_overflow_controls) {
    DCHECK(subtree_highest_layers);
    const PaintLayer* layer_to_paint_overlay_overflow_controls_after = nullptr;
    for (auto layer_type : subtree_highest_layers->highest_layers_order) {
      if (layer_type == HighestLayers::kFixedPosition &&
          !object.CanContainFixedPositionObjects())
        continue;
      if (layer_type == HighestLayers::kAbsolutePosition &&
          !object.CanContainAbsolutePositionObjects())
        continue;
      SetIfHigher(layer_to_paint_overlay_overflow_controls_after,
                  subtree_highest_layers->highest_layers[layer_type]);
    }

    if (layer_to_paint_overlay_overflow_controls_after) {
      layer_to_overlay_overflow_controls_painting_after_
          .insert(layer_to_paint_overlay_overflow_controls_after,
                  MakeGarbageCollected<PaintLayers>())
          .stored_value->value->push_back(paint_layer);
    }
    paint_layer.SetNeedsReorderOverlayOverflowControls(
        !!layer_to_paint_overlay_overflow_controls_after);
  }

  if (highest_layers)
    highest_layers->Merge(*subtree_highest_layers, paint_layer);
}

bool PaintLayerStackingNode::StyleDidChange(PaintLayer& paint_layer,
                                            const ComputedStyle* old_style) {
  bool was_stacking_context = false;
  bool was_stacked = false;
  int old_z_index = 0;
  int old_order = 0;
  if (old_style) {
    was_stacking_context =
        paint_layer.GetLayoutObject().IsStackingContext(*old_style);
    old_z_index = old_style->EffectiveZIndex();
    old_order = old_style->Order();
    was_stacked = paint_layer.GetLayoutObject().IsStacked(*old_style);
  }

  const ComputedStyle& new_style = paint_layer.GetLayoutObject().StyleRef();

  bool should_be_stacking_context =
      paint_layer.GetLayoutObject().IsStackingContext();
  bool should_be_stacked = paint_layer.GetLayoutObject().IsStacked();
  if (should_be_stacking_context == was_stacking_context &&
      was_stacked == should_be_stacked &&
      old_z_index == new_style.EffectiveZIndex() &&
      old_order == new_style.Order()) {
    return false;
  }

  paint_layer.DirtyStackingContextZOrderLists();

  if (paint_layer.StackingNode())
    paint_layer.StackingNode()->DirtyZOrderLists();
  return true;
}

void PaintLayerStackingNode::UpdateZOrderLists() {
  if (z_order_lists_dirty_)
    RebuildZOrderLists();
}

void PaintLayerStackingNode::Trace(Visitor* visitor) const {
  visitor->Trace(layer_);
  visitor->Trace(pos_z_order_list_);
  visitor->Trace(neg_z_order_list_);
  visitor->Trace(layer_to_overlay_overflow_controls_painting_after_);
}

}  // namespace blink

"""

```