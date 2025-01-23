Response:
Let's break down the thought process for analyzing this C++ source code.

**1. Understanding the Goal:**

The request is to understand the functionality of `layout_tree_builder_traversal.cc` within the Chromium Blink engine. This means figuring out what it *does* in the context of web page rendering. Key aspects to identify are its relationship to HTML, CSS, and JavaScript, common errors, and debugging strategies.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly read through the code, noting important keywords and structures. I'm looking for things like:

* **Includes:**  `style_engine.h`, `column_pseudo_element.h`, `flat_tree_traversal.h`, `pseudo_element.h`, `html_names.h`, `layout_object.h`, `layout_view.h`. These immediately tell me this file is dealing with styling, pseudo-elements, the flat tree representation of the DOM, and layout.
* **Namespace:** `blink`. This confirms we are within the Blink rendering engine.
* **Class Name:** `LayoutTreeBuilderTraversal`. The name itself strongly suggests this class is responsible for traversing the structure being built for layout.
* **Function Names:** `Parent`, `LayoutParent`, `ParentLayoutObject`, `NextSibling`, `PreviousSibling`, `FirstChild`, `LastChild`, `Next`, `Previous`, `NextSkippingChildren`, `NextLayoutSibling`, `PreviousLayoutSibling`, `FirstLayoutChild`, `NextSiblingLayoutObject`, `PreviousSiblingLayoutObject`, `NextInTopLayer`, `ComparePreorderTreePosition`. These clearly indicate operations related to navigating the tree structure.
* **Pseudo-element identifiers:** `kPseudoIdScrollPrevButton`, `kPseudoIdScrollMarkerGroupBefore`, `kPseudoIdMarker`, etc. This highlights a significant focus on handling pseudo-elements during traversal.
* **Conditional logic (`if`, `switch`):** These reveal the different cases and conditions the code handles, often related to different types of nodes or pseudo-elements.

**3. Formulating Hypotheses Based on Initial Scan:**

Based on the keywords, I can start forming hypotheses about the file's purpose:

* **Core Function:** This file likely provides utilities for navigating the DOM tree in a way that's relevant to the layout process. It's probably not just a simple DOM traversal, but one that considers layout-specific aspects like pseudo-elements and `display: contents`.
* **Pseudo-element Handling:**  A large portion of the code seems dedicated to handling different pseudo-elements correctly during traversal. This makes sense because pseudo-elements exist in the CSSOM but not directly in the DOM, so a specialized traversal is needed for layout.
* **`display: contents` Handling:** The `LayoutParent` function explicitly deals with `display: contents`, suggesting this file plays a role in how that CSS property affects the layout tree structure.
* **Layout Tree vs. DOM Tree:**  The naming (`LayoutParent`, `NextLayoutSibling`) strongly implies a distinction between the raw DOM tree and the layout tree, which is the tree structure used for calculating layout. This file likely helps bridge that gap.

**4. Deep Dive into Specific Functions:**

Now, I start examining the individual functions in more detail:

* **`Parent`, `LayoutParent`:** The difference between these is crucial. `Parent` seems to follow the standard DOM parent, while `LayoutParent` skips over elements with `display: contents`. This confirms my hypothesis about handling `display: contents`.
* **`NextSibling`, `PreviousSibling`:** The complex `switch` statements reveal the custom logic for navigating between elements and their pseudo-elements. The order of these pseudo-elements is important for layout.
* **`FirstChild`, `LastChild`:** Similar to sibling functions, these consider pseudo-elements.
* **`Next`, `Previous`, `NextSkippingChildren`:** These seem like standard tree traversal patterns, but built on top of the custom sibling and child functions.
* **`NextLayoutSibling`, `PreviousLayoutSibling`:** These are the key functions for navigating the layout tree. The logic involving `AreBoxTreeOrderSiblings` and the handling of scroll-marker groups is important here. The `limit` parameter suggests these functions can be used for limited traversal.
* **`FirstLayoutChild`:**  A convenient wrapper around `NextLayoutSiblingInternal`.
* **`NextSiblingLayoutObject`, `PreviousSiblingLayoutObject`:** These functions build on the layout sibling functions to find actual `LayoutObject` instances, skipping nodes that don't have layout objects (or whose layout objects are reparented).
* **`NextInTopLayer`:** Specifically for handling elements in the top layer (like `<dialog>` and popovers).
* **`ComparePreorderTreePosition`:**  A standard algorithm for determining the document order of two nodes.

**5. Connecting to HTML, CSS, and JavaScript:**

With an understanding of the functions, I can now connect them to web technologies:

* **HTML:** The code operates on the DOM, which is a representation of the HTML structure. The traversal helps understand the relationships between HTML elements for layout purposes.
* **CSS:** The handling of pseudo-elements (`::before`, `::after`, `::marker`, etc.) and `display: contents` directly relates to CSS styling. The `StyleEngine` dependency reinforces this. The scroll-marker group pseudo-elements are a more specific example related to CSS scrollbar styling. View Transitions are also heavily influenced by CSS.
* **JavaScript:** While this C++ code doesn't directly execute JavaScript, JavaScript often manipulates the DOM. The logic in this file is crucial for ensuring that layout is recalculated correctly after DOM changes made by JavaScript. JavaScript APIs that query the DOM structure (like `nextElementSibling`, `parentElement`) conceptually mirror some of the functionality here, though implemented differently.

**6. Identifying Potential Errors and Debugging:**

Thinking about how things could go wrong helps understand the purpose of the code further:

* **Incorrect Pseudo-element Ordering:** If the sibling functions are implemented incorrectly, pseudo-elements might be laid out in the wrong order.
* **`display: contents` Issues:** Mishandling `display: contents` could lead to elements being incorrectly included or excluded from the layout flow.
* **Scroll-marker Group Problems:**  Errors in the scroll-marker group logic could lead to incorrect rendering of scrollbars or related elements.
* **View Transition Errors:** Incorrectly traversing the view transition pseudo-elements could break the animation effect.
* **Infinite Loops:** While not immediately obvious in this specific code, complex tree traversal logic can sometimes lead to infinite loops if not carefully implemented. The `limit` parameter in some functions likely helps prevent this.

**7. Illustrative Examples and Scenarios:**

To solidify understanding, I create concrete examples:

* **`display: contents`:**  Illustrate how `LayoutParent` skips over the element.
* **Pseudo-element Ordering:** Show how the `NextSibling` function ensures `::before` comes before the element's content.
* **Scroll-marker Groups:** Explain how the traversal handles these special pseudo-elements.
* **View Transitions:**  Describe the specific handling of view transition pseudo-elements for animation purposes.

**8. Tracing User Actions to the Code:**

Finally, I consider how user actions trigger this code:

* **Page Load:** The initial parsing of HTML and CSS triggers the layout process, which uses this traversal logic.
* **Dynamic DOM Manipulation:** JavaScript adding or removing elements causes layout recalculations.
* **CSS Changes:**  Modifying styles, especially those affecting layout (like `display`, `position`, etc.), will trigger layout updates.
* **Scrolling:** The scroll-marker group logic is directly related to scrolling.
* **View Transitions:** Navigating between pages or states with view transitions will involve this code.

**Self-Correction/Refinement:**

Throughout this process, I constantly review and refine my understanding. For example, initially, I might have just thought "this is for DOM traversal." But by looking at the specifics of pseudo-element handling and `display: contents`, I realize it's a *specialized* traversal for the layout tree. Similarly, recognizing the `limit` parameter leads to understanding its role in preventing infinite loops or limiting traversal scope. The detailed handling of scroll-marker groups and view transitions requires focused attention to understand their specific purpose.
This C++ source code file, `layout_tree_builder_traversal.cc`, in the Chromium Blink engine, provides utilities for traversing the **layout tree** during its construction. It's a crucial part of the rendering engine, specifically focusing on how the DOM (Document Object Model) is transformed into the structure used for layout calculations.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Navigating the Layout Tree:**  The primary purpose is to provide functions to move up, down, and sideways within the emerging layout tree structure. This includes:
    * `Parent()`: Returns the parent node in the flat tree (usually the DOM tree).
    * `LayoutParent()`: Returns the parent node in the *layout* tree, which can differ from the DOM tree, especially with `display: contents`.
    * `ParentLayoutObject()`: Returns the layout object of the parent.
    * `NextSibling()`, `PreviousSibling()`:  Returns the next or previous sibling, taking into account pseudo-elements.
    * `FirstChild()`, `LastChild()`: Returns the first or last child, including pseudo-elements.
    * `Next()`, `Previous()`:  Performs a full pre-order/reverse pre-order traversal.
    * `NextSkippingChildren()`: Moves to the next sibling or ancestor's sibling.
    * `NextLayoutSibling()`, `PreviousLayoutSibling()`: Returns the next or previous sibling in the layout tree, handling `display: contents`.
    * `FirstLayoutChild()`: Returns the first child in the layout tree.

2. **Handling Pseudo-elements:** A significant portion of the code is dedicated to correctly navigating around and within pseudo-elements (like `::before`, `::after`, `::marker`, `::scroll-marker-group`, view-transition pseudo-elements etc.). This is critical because pseudo-elements exist in the CSSOM (CSS Object Model) and affect layout but are not actual DOM nodes.

3. **`display: contents` Handling:** The `LayoutParent()` function explicitly skips over elements with `display: contents`. This CSS property removes the element itself from the rendering tree, making its children appear as direct children of its parent in the layout.

4. **View Transition API Support:** The code includes logic for handling pseudo-elements related to the View Transitions API (`::view-transition`, `::view-transition-group`, `::view-transition-image-pair`, etc.). This API allows for smooth transitions between different states of a web page.

5. **Scroll-marker Group Handling:**  The code specifically addresses the `::scroll-marker-group` pseudo-element, which is used for styling scrollbars. It ensures correct traversal around these elements.

6. **Top-Layer Element Handling:** The `NextInTopLayer()` function deals with elements rendered in the top layer (like `<dialog>` elements or elements using the Popover API).

7. **Preorder Tree Position Comparison:** The `ComparePreorderTreePosition()` function allows comparing the document order of two nodes, which is essential for various layout and rendering algorithms.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** This code operates on the DOM, which is the in-memory representation of the HTML structure. The functions in this file help build the layout tree based on this HTML structure.
    * **Example:** When the browser encounters a `<div>` element in the HTML, this code is involved in determining its parent, siblings, and children in the layout tree.

* **CSS:** CSS styles directly influence the layout tree. Properties like `display`, `position`, and the presence of pseudo-elements dictate how the layout tree is constructed.
    * **Example:**
        *  If a CSS rule sets `display: contents` on a `<div>`, the `LayoutParent()` function will ensure that the children of this `<div>` are treated as direct children of its parent in the layout tree traversal.
        *  If an element has a `::before` pseudo-element defined in CSS, the `NextSibling()` and `PreviousSibling()` functions will correctly place this pseudo-element in the traversal order.
        *  CSS properties related to scroll-marker groups trigger the specific logic for handling `::scroll-marker-group` pseudo-elements.
        *  CSS properties related to view transitions trigger the handling of view transition pseudo-elements.

* **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, JavaScript often manipulates the DOM. When JavaScript adds, removes, or modifies DOM nodes or their styles, the layout tree needs to be updated. The functions in this file are used during this update process to traverse the potentially modified DOM and rebuild the relevant parts of the layout tree.
    * **Example:** If a JavaScript script adds a new `<span>` element inside a `<div>`, the layout tree builder will use these traversal functions to determine the new `<span>`'s position in the layout tree relative to its siblings and parent.

**Logic Reasoning and Examples:**

Let's consider the `NextSibling()` function with a focus on pseudo-elements:

**Hypothetical Input:**

Consider the following HTML structure and CSS:

```html
<div id="parent">
  <p>Some text</p>
</div>
```

```css
#parent::before {
  content: "Before ";
}
```

**Traversal within `NextSibling()` when called on the `<p>` element:**

1. The function checks the `GetPseudoId()` of the `<p>` element, which is `kPseudoIdNone`.
2. It calls `FlatTreeTraversal::NextSibling(node)`, which would normally return `nullptr` as the `<p>` is the only child.
3. The code then checks for `kPseudoIdAfter` on the parent (`#parent`), which doesn't exist in this case.
4. It then checks for `kPseudoIdSelectArrow`, `kPseudoIdScrollMarkerGroupAfter`, and `kPseudoIdScrollNextButton`, none of which are present.
5. **However**, if we called `NextSibling()` on the `::before` pseudo-element of `#parent`:
   * `pseudo_id` would be `kPseudoIdBefore`.
   * The code would then call `FlatTreeTraversal::FirstChild(*parent_element)`, which would return the `<p>` element.

**Output:**

* `NextSibling(p_element)` would return `nullptr`.
* `NextSibling(before_pseudo_element)` would return the `<p>` element.

**User/Programming Errors and Examples:**

A common area for errors related to this code involves understanding how `display: contents` affects the layout tree structure.

**Example Error:**

A developer might assume that iterating through the direct children of a DOM element will always correspond directly to the children in the layout tree. However, if one of the child elements has `display: contents`, this assumption is incorrect.

**HTML:**

```html
<div id="parent">
  <div id="contents-child" style="display: contents;">
    <span>Child 1</span>
    <span>Child 2</span>
  </div>
  <p>Direct child of parent</p>
</div>
```

**JavaScript Error:**

```javascript
const parent = document.getElementById('parent');
for (const child of parent.children) {
  console.log(child); // Will print the div with display: contents and the <p> element
}
```

If the developer expects to find "Child 1" and "Child 2" when iterating through `parent.children`, they will be mistaken. In the *layout tree*, "Child 1" and "Child 2" are direct children of `#parent`, while the `div` with `display: contents` is effectively skipped. The `LayoutTreeBuilderTraversal::FirstChild()` and sibling functions would reflect this layout tree structure, not the raw DOM structure.

**User Interaction and Debugging Clues:**

A user's actions can indirectly lead to this code being executed. Here's a step-by-step scenario that could lead a developer to debug issues within `layout_tree_builder_traversal.cc`:

1. **User Action:** The user navigates to a web page with complex styling and dynamic content updates.
2. **Browser Activity:** The browser parses the HTML and CSS.
3. **Layout Tree Construction:** The Blink rendering engine starts building the layout tree, and `layout_tree_builder_traversal.cc` is heavily involved in determining the structure.
4. **JavaScript Execution:** JavaScript on the page modifies the DOM (e.g., adds or removes elements, changes styles).
5. **Layout Recalculation:**  The browser needs to recalculate the layout based on the DOM changes. This again involves the functions in `layout_tree_builder_traversal.cc`.
6. **Rendering Issues:**  Due to a bug in the layout tree traversal logic (or a misunderstanding of how it works with `display: contents` or pseudo-elements), elements might be positioned incorrectly, not appear at all, or cause unexpected layout shifts.
7. **Developer Investigation:** The developer opens the browser's developer tools and notices rendering problems.
8. **Debugging:**  The developer might use the "Inspect" tool to examine the DOM and computed styles. They might also use performance profiling tools to see which parts of the rendering pipeline are taking time.
9. **Potential Breakpoint:** If the developer suspects an issue with layout tree construction or updates, they might set breakpoints in C++ code related to layout, potentially including functions within `layout_tree_builder_traversal.cc`, to understand how the layout tree is being built and traversed. They might look at the values returned by functions like `ParentLayoutObject()`, `NextSibling()`, etc., for specific elements to see if the traversal is happening as expected.

**In summary, `layout_tree_builder_traversal.cc` is a foundational file in the Blink rendering engine, providing the core logic for navigating and understanding the structure of the layout tree, which is essential for correctly rendering web pages with complex HTML, CSS, and dynamic JavaScript interactions.**

### 提示词
```
这是目录为blink/renderer/core/dom/layout_tree_builder_traversal.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"

#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"

namespace blink {

inline static bool HasDisplayContentsStyle(const Node& node) {
  auto* element = DynamicTo<Element>(node);
  return element && element->HasDisplayContentsStyle();
}

static bool IsLayoutObjectReparented(const LayoutObject* layout_object) {
  return layout_object->IsInTopOrViewTransitionLayer();
}

ContainerNode* LayoutTreeBuilderTraversal::Parent(const Node& node) {
  // TODO(hayato): Uncomment this once we can be sure
  // LayoutTreeBuilderTraversal::parent() is used only for a node which is
  // connected.
  // DCHECK(node.isConnected());
  if (IsA<PseudoElement>(node)) {
    DCHECK(node.parentNode());
    return node.parentNode();
  }
  return FlatTreeTraversal::Parent(node);
}

ContainerNode* LayoutTreeBuilderTraversal::LayoutParent(const Node& node) {
  // TODO(crbug.com/332396355): consider to check for ::scroll-marker-group
  // from all call sites of this function, or move the check here.
  ContainerNode* parent = LayoutTreeBuilderTraversal::Parent(node);

  while (parent && HasDisplayContentsStyle(*parent))
    parent = LayoutTreeBuilderTraversal::Parent(*parent);

  return parent;
}

LayoutObject* LayoutTreeBuilderTraversal::ParentLayoutObject(const Node& node) {
  if (node.GetPseudoId() == kPseudoIdViewTransition) {
    // The view-transition pseudo is wrapped by the anonymous
    // LayoutViewTransitionRoot but that's created by adding the
    // view-transition to the LayoutView.
    return node.GetDocument().GetLayoutView();
  }
  const Node* search_start_node = &node;
  // Parent of ::scroll-marker-group should be layout parent of its
  // originating element.
  if (node.IsScrollMarkerGroupPseudoElement()) {
    search_start_node = To<PseudoElement>(node).UltimateOriginatingElement();
  }
  ContainerNode* parent =
      LayoutTreeBuilderTraversal::LayoutParent(*search_start_node);
  return parent ? parent->GetLayoutObject() : nullptr;
}

Node* LayoutTreeBuilderTraversal::NextSibling(const Node& node) {
  PseudoId pseudo_id = node.GetPseudoId();
  Element* parent_element;
  if (pseudo_id != kPseudoIdNone) {
    parent_element = DynamicTo<Element>(*node.parentNode());
    DCHECK(parent_element);
  }
  switch (pseudo_id) {
    case kPseudoIdScrollPrevButton:
      if (Node* next = parent_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupBefore)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupBefore:
      if (Node* next = parent_element->GetPseudoElement(kPseudoIdMarker)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdMarker:
      if (const ColumnPseudoElementsVector* columns =
              parent_element->GetColumnPseudoElements();
          columns && !columns->empty()) {
        return columns->front();
      }
      [[fallthrough]];
    case kPseudoIdColumn:
      if (auto* column = DynamicTo<ColumnPseudoElement>(node)) {
        const ColumnPseudoElementsVector* columns =
            parent_element->GetColumnPseudoElements();
        if (column->Index() + 1u < columns->size()) {
          return columns->at(column->Index() + 1u);
        }
      }
      if (Node* next =
              parent_element->GetPseudoElement(kPseudoIdScrollMarker)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarker:
      if (Node* next = parent_element->GetPseudoElement(kPseudoIdCheck)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdCheck:
      if (Node* next = parent_element->GetPseudoElement(kPseudoIdBefore))
        return next;
      [[fallthrough]];
    case kPseudoIdBefore:
      if (Node* next = FlatTreeTraversal::FirstChild(*parent_element))
        return next;
      [[fallthrough]];
    case kPseudoIdNone:
      if (pseudo_id == kPseudoIdNone) {  // Not falling through
        if (Node* next = FlatTreeTraversal::NextSibling(node))
          return next;
        parent_element = DynamicTo<Element>(FlatTreeTraversal::Parent(node));
        if (!parent_element)
          return nullptr;
      }
      if (Node* next = parent_element->GetPseudoElement(kPseudoIdAfter))
        return next;
      [[fallthrough]];
    case kPseudoIdAfter:
      if (Node* next = parent_element->GetPseudoElement(kPseudoIdSelectArrow)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdSelectArrow:
      if (Node* next = parent_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupAfter)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupAfter:
      if (Node* next =
              parent_element->GetPseudoElement(kPseudoIdScrollNextButton)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollNextButton:
      return nullptr;
    case kPseudoIdViewTransition:
      return nullptr;
    case kPseudoIdViewTransitionGroup: {
      auto* pseudo_element = DynamicTo<PseudoElement>(node);
      DCHECK(pseudo_element);

      // Iterate the list of IDs until we hit the entry for |node's| ID. The
      // sibling is the next ID in the list which generates a pseudo element.
      bool found = false;
      for (const auto& view_transition_name : parent_element->GetDocument()
                                                  .GetStyleEngine()
                                                  .ViewTransitionTags()) {
        if (!found) {
          if (view_transition_name == pseudo_element->view_transition_name())
            found = true;
          continue;
        }

        if (auto* sibling = parent_element->GetPseudoElement(
                kPseudoIdViewTransitionGroup, view_transition_name)) {
          return sibling;
        }
      }
      return nullptr;
    }
    case kPseudoIdViewTransitionImagePair:
    case kPseudoIdViewTransitionOld:
    case kPseudoIdViewTransitionNew:
      return nullptr;
    default:
      NOTREACHED();
  }
}

Node* LayoutTreeBuilderTraversal::PreviousSibling(const Node& node) {
  PseudoId pseudo_id = node.GetPseudoId();
  Element* parent_element;
  if (pseudo_id != kPseudoIdNone) {
    parent_element = DynamicTo<Element>(*node.parentNode());
    DCHECK(parent_element);
  }
  switch (pseudo_id) {
    case kPseudoIdScrollNextButton:
      if (Node* previous = parent_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupAfter)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupAfter:
      if (Node* previous =
              parent_element->GetPseudoElement(kPseudoIdSelectArrow)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdSelectArrow:
      if (Node* previous = parent_element->GetPseudoElement(kPseudoIdAfter)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdAfter:
      if (Node* previous = FlatTreeTraversal::LastChild(*parent_element))
        return previous;
      [[fallthrough]];
    case kPseudoIdNone:
      if (pseudo_id == kPseudoIdNone) {  // Not falling through
        if (Node* previous = FlatTreeTraversal::PreviousSibling(node))
          return previous;
        parent_element = DynamicTo<Element>(FlatTreeTraversal::Parent(node));
        if (!parent_element)
          return nullptr;
      }
      if (Node* previous = parent_element->GetPseudoElement(kPseudoIdBefore))
        return previous;
      [[fallthrough]];
    case kPseudoIdBefore:
      if (Node* previous = parent_element->GetPseudoElement(kPseudoIdCheck)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdCheck:
      if (Node* previous =
              parent_element->GetPseudoElement(kPseudoIdScrollMarker)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarker:
      if (const ColumnPseudoElementsVector* columns =
              parent_element->GetColumnPseudoElements();
          columns && !columns->empty()) {
        return columns->back();
      }
      [[fallthrough]];
    case kPseudoIdColumn:
      if (auto* column = DynamicTo<ColumnPseudoElement>(node)) {
        const ColumnPseudoElementsVector* columns =
            parent_element->GetColumnPseudoElements();
        if (column->Index() > 0) {
          return columns->at(column->Index() - 1u);
        }
      }
      if (Node* previous = parent_element->GetPseudoElement(kPseudoIdMarker)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdMarker:
      if (Node* previous = parent_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupBefore)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupBefore:
      if (Node* previous =
              parent_element->GetPseudoElement(kPseudoIdScrollPrevButton)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollPrevButton:
      return nullptr;
    default:
      NOTREACHED();
  }
}

Node* LayoutTreeBuilderTraversal::LastChild(const Node& node) {
  const auto* current_element = DynamicTo<Element>(node);
  if (!current_element)
    return FlatTreeTraversal::LastChild(node);

  if (Node* last =
          current_element->GetPseudoElement(kPseudoIdScrollNextButton)) {
    return last;
  }
  if (Node* last =
          current_element->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
    return last;
  }
  if (Node* last = current_element->GetPseudoElement(kPseudoIdSelectArrow)) {
    return last;
  }
  if (Node* last = current_element->GetPseudoElement(kPseudoIdAfter))
    return last;
  if (Node* last = FlatTreeTraversal::LastChild(*current_element))
    return last;
  if (Node* last = current_element->GetPseudoElement(kPseudoIdBefore))
    return last;
  if (Node* last = current_element->GetPseudoElement(kPseudoIdCheck)) {
    return last;
  }
  if (const ColumnPseudoElementsVector* columns =
          current_element->GetColumnPseudoElements();
      columns && !columns->empty()) {
    if (Node* last = columns->back()) {
      return last;
    }
  }
  if (Node* last = current_element->GetPseudoElement(kPseudoIdScrollMarker)) {
    return last;
  }
  if (Node* last = current_element->GetPseudoElement(kPseudoIdMarker)) {
    return last;
  }
  if (Node* last =
          current_element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
    return last;
  }
  return current_element->GetPseudoElement(kPseudoIdScrollPrevButton);
}

Node* LayoutTreeBuilderTraversal::Previous(const Node& node,
                                           const Node* stay_within) {
  if (node == stay_within)
    return nullptr;

  if (Node* previous_node = PreviousSibling(node)) {
    while (Node* previous_last_child = LastChild(*previous_node))
      previous_node = previous_last_child;
    return previous_node;
  }
  return Parent(node);
}

Node* LayoutTreeBuilderTraversal::FirstChild(const Node& node) {
  const auto* current_element = DynamicTo<Element>(node);
  if (!current_element)
    return FlatTreeTraversal::FirstChild(node);

  if (Node* first =
          current_element->GetPseudoElement(kPseudoIdScrollPrevButton)) {
    return first;
  }
  if (Node* first =
          current_element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
    return first;
  }
  if (Node* first = current_element->GetPseudoElement(kPseudoIdMarker))
    return first;
  if (Node* first = current_element->GetPseudoElement(kPseudoIdScrollMarker)) {
    return first;
  }
  if (const ColumnPseudoElementsVector* columns =
          current_element->GetColumnPseudoElements();
      columns && !columns->empty()) {
    if (Node* first = columns->front()) {
      return first;
    }
  }
  if (Node* first = current_element->GetPseudoElement(kPseudoIdCheck)) {
    return first;
  }
  if (Node* first = current_element->GetPseudoElement(kPseudoIdBefore))
    return first;
  if (Node* first = FlatTreeTraversal::FirstChild(node))
    return first;
  if (Node* first = current_element->GetPseudoElement(kPseudoIdAfter)) {
    return first;
  }
  if (Node* first = current_element->GetPseudoElement(kPseudoIdSelectArrow)) {
    return first;
  }
  if (Node* first =
          current_element->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
    return first;
  }
  return current_element->GetPseudoElement(kPseudoIdScrollNextButton);
}

static Node* NextAncestorSibling(const Node& node, const Node* stay_within) {
  DCHECK(!LayoutTreeBuilderTraversal::NextSibling(node));
  DCHECK_NE(node, stay_within);
  for (Node* parent_node = LayoutTreeBuilderTraversal::Parent(node);
       parent_node;
       parent_node = LayoutTreeBuilderTraversal::Parent(*parent_node)) {
    if (parent_node == stay_within)
      return nullptr;
    if (Node* next_node = LayoutTreeBuilderTraversal::NextSibling(*parent_node))
      return next_node;
  }
  return nullptr;
}

Node* LayoutTreeBuilderTraversal::NextSkippingChildren(
    const Node& node,
    const Node* stay_within) {
  if (node == stay_within)
    return nullptr;
  if (Node* next_node = NextSibling(node))
    return next_node;
  return NextAncestorSibling(node, stay_within);
}

Node* LayoutTreeBuilderTraversal::Next(const Node& node,
                                       const Node* stay_within) {
  if (Node* child = FirstChild(node))
    return child;
  return NextSkippingChildren(node, stay_within);
}

// Checks if current or (next/prev) sibling is either ::scroll-marker-group
// or element with scroll-marker-group property set.
static inline bool AreBoxTreeOrderSiblings(const Node& current, Node* sibling) {
  if (current.IsScrollMarkerGroupPseudoElement()) {
    return false;
  }
  if (const auto* element = DynamicTo<Element>(current)) {
    const ComputedStyle* style = element->GetComputedStyle();
    if (style && !style->ScrollMarkerGroupNone()) {
      return false;
    }
  }
  if (Element* sibling_element = DynamicTo<Element>(sibling)) {
    if (sibling_element->IsScrollMarkerGroupPseudoElement()) {
      return false;
    }
    const ComputedStyle* sibling_style = sibling_element->GetComputedStyle();
    if (sibling_style && !sibling_style->ScrollMarkerGroupNone()) {
      return false;
    }
  }
  return true;
}

// This function correctly performs one move from `node` to next
// layout sibling. We can't just use NextSibling, as ::scroll-marker-group
// layout object is either previous or next sibling of its originating element,
// but still a node child of it, as a pseudo element.
// Layout tree:
//        (PS) (SMGB) (OE) (SMGA) (NS)
//                  (B)  (A)
// OE - originating element
// PS - previous sibling of OE
// NS - next sibling of OE
// SMGB - ::scroll-marker-group of OE with scroll-marker-group: before
// SMGA - ::scroll-marker-group of OE with scroll-marker-group: after
// B - ::before of OE
// A - ::after of OE
// Node tree:
//        (PS) (OE) (NS)
//    (SMGB) (B)  (A) (SMGA)
// Node tree is input (`node`), return output based on layout tree.
static Node* NextLayoutSiblingInBoxTreeOrder(const Node& node) {
  Node* next = LayoutTreeBuilderTraversal::NextSibling(node);
  if (AreBoxTreeOrderSiblings(node, next)) {
    return next;
  }
  // From PS to OE with SMGB, return SMGB.
  Element* next_element = DynamicTo<Element>(next);
  if (next_element && next_element->GetComputedStyle() &&
      next_element->GetComputedStyle()->HasScrollMarkerGroupBefore()) {
    if (Element* pseudo =
            next_element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
      return pseudo;
    }
  }
  // From some pseudo to any SMG, just skip SMG.
  if (next_element && next_element->IsScrollMarkerGroupPseudoElement()) {
    return LayoutTreeBuilderTraversal::NextSibling(*next_element);
  }
  // From OE with SMGA to NS, return SMGA.
  const Element* element = DynamicTo<Element>(node);
  if (!element) {
    return next;
  }
  if (element->GetComputedStyle() &&
      element->GetComputedStyle()->HasScrollMarkerGroupAfter()) {
    if (Element* pseudo = To<Element>(node).GetPseudoElement(
            kPseudoIdScrollMarkerGroupAfter)) {
      return pseudo;
    }
  }
  // From SMGB, return OE.
  if (element->IsScrollMarkerGroupBeforePseudoElement()) {
    return To<PseudoElement>(element)->UltimateOriginatingElement();
  }
  // From SMGA, return NS, but check if NS has SMGB, then return NS's SMGB.
  if (element->IsScrollMarkerGroupAfterPseudoElement()) {
    Node* originating_next = LayoutTreeBuilderTraversal::NextSibling(
        *To<PseudoElement>(element)->UltimateOriginatingElement());
    Element* originating_next_element = DynamicTo<Element>(originating_next);
    if (originating_next_element &&
        originating_next_element->GetComputedStyle() &&
        originating_next_element->GetComputedStyle()
            ->HasScrollMarkerGroupBefore()) {
      if (Element* pseudo = originating_next_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupBefore)) {
        return pseudo;
      }
    }
    return originating_next;
  }
  return next;
}

static Node* NextLayoutSiblingInternal(Node* node, int32_t& limit) {
  for (Node* sibling = node; sibling && limit-- != 0;
       sibling = NextLayoutSiblingInBoxTreeOrder(*sibling)) {
    if (!HasDisplayContentsStyle(*sibling))
      return sibling;

    if (Node* inner = NextLayoutSiblingInternal(
            LayoutTreeBuilderTraversal::FirstChild(*sibling), limit))
      return inner;

    if (limit == -1)
      return nullptr;
  }

  return nullptr;
}

Node* LayoutTreeBuilderTraversal::NextLayoutSibling(const Node& node,
                                                    int32_t& limit) {
  DCHECK_NE(limit, -1);
  if (Node* sibling = NextLayoutSiblingInternal(
          NextLayoutSiblingInBoxTreeOrder(node), limit)) {
    return sibling;
  }

  Node* parent = LayoutTreeBuilderTraversal::Parent(node);
  while (limit != -1 && parent && HasDisplayContentsStyle(*parent)) {
    if (Node* sibling = NextLayoutSiblingInternal(
            NextLayoutSiblingInBoxTreeOrder(*parent), limit)) {
      return sibling;
    }
    parent = LayoutTreeBuilderTraversal::Parent(*parent);
  }

  return nullptr;
}

// See comments in NextLayoutSiblingInBoxTreeOrder.
static Node* PreviousLayoutSiblingInBoxTreeOrder(const Node& node) {
  Node* previous = LayoutTreeBuilderTraversal::PreviousSibling(node);
  if (AreBoxTreeOrderSiblings(node, previous)) {
    return previous;
  }
  Element* previous_element = DynamicTo<Element>(previous);
  if (previous_element && previous_element->GetComputedStyle() &&
      previous_element->GetComputedStyle()->HasScrollMarkerGroupAfter()) {
    if (Element* pseudo = previous_element->GetPseudoElement(
            kPseudoIdScrollMarkerGroupAfter)) {
      return pseudo;
    }
  }
  if (previous_element &&
      previous_element->IsScrollMarkerGroupPseudoElement()) {
    return LayoutTreeBuilderTraversal::PreviousSibling(*previous_element);
  }
  const Element* element = DynamicTo<Element>(node);
  if (!element) {
    return previous;
  }
  if (element->GetComputedStyle() &&
      element->GetComputedStyle()->HasScrollMarkerGroupBefore()) {
    if (Element* pseudo =
            element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
      return pseudo;
    }
  }
  if (element->IsScrollMarkerGroupAfterPseudoElement()) {
    return To<PseudoElement>(element)->UltimateOriginatingElement();
  }
  if (element->IsScrollMarkerGroupBeforePseudoElement()) {
    Node* originating_prev = LayoutTreeBuilderTraversal::PreviousSibling(
        *To<PseudoElement>(element)->UltimateOriginatingElement());
    Element* originating_prev_element = DynamicTo<Element>(originating_prev);
    if (originating_prev_element &&
        originating_prev_element->GetComputedStyle() &&
        originating_prev_element->GetComputedStyle()
            ->HasScrollMarkerGroupAfter()) {
      if (Element* pseudo = originating_prev_element->GetPseudoElement(
              kPseudoIdScrollMarkerGroupAfter)) {
        return pseudo;
      }
    }
    return originating_prev;
  }
  return previous;
}

static Node* PreviousLayoutSiblingInternal(Node* node, int32_t& limit) {
  for (Node* sibling = node; sibling && limit-- != 0;
       sibling = PreviousLayoutSiblingInBoxTreeOrder(*sibling)) {
    if (!HasDisplayContentsStyle(*sibling))
      return sibling;

    if (Node* inner = PreviousLayoutSiblingInternal(
            LayoutTreeBuilderTraversal::LastChild(*sibling), limit))
      return inner;

    if (limit == -1)
      return nullptr;
  }

  return nullptr;
}

Node* LayoutTreeBuilderTraversal::PreviousLayoutSibling(const Node& node,
                                                        int32_t& limit) {
  DCHECK_NE(limit, -1);
  if (Node* sibling = PreviousLayoutSiblingInternal(
          PreviousLayoutSiblingInBoxTreeOrder(node), limit)) {
    return sibling;
  }

  Node* parent = LayoutTreeBuilderTraversal::Parent(node);
  while (limit != -1 && parent && HasDisplayContentsStyle(*parent)) {
    if (Node* sibling = PreviousLayoutSiblingInternal(
            PreviousLayoutSiblingInBoxTreeOrder(*parent), limit)) {
      return sibling;
    }
    parent = LayoutTreeBuilderTraversal::Parent(*parent);
  }

  return nullptr;
}

Node* LayoutTreeBuilderTraversal::FirstLayoutChild(const Node& node) {
  int32_t limit = kTraverseAllSiblings;
  return NextLayoutSiblingInternal(FirstChild(node), limit);
}

LayoutObject* LayoutTreeBuilderTraversal::NextSiblingLayoutObject(
    const Node& node,
    int32_t limit) {
  DCHECK(limit == kTraverseAllSiblings || limit >= 0) << limit;
  for (Node* sibling = NextLayoutSibling(node, limit); sibling && limit != -1;
       sibling = NextLayoutSibling(*sibling, limit)) {
    LayoutObject* layout_object = sibling->GetLayoutObject();
    if (layout_object && !IsLayoutObjectReparented(layout_object))
      return layout_object;
  }
  return nullptr;
}

LayoutObject* LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(
    const Node& node,
    int32_t limit) {
  DCHECK(limit == kTraverseAllSiblings || limit >= 0) << limit;
  for (Node* sibling = PreviousLayoutSibling(node, limit);
       sibling && limit != -1;
       sibling = PreviousLayoutSibling(*sibling, limit)) {
    LayoutObject* layout_object = sibling->GetLayoutObject();
    if (layout_object && !IsLayoutObjectReparented(layout_object))
      return layout_object;
  }
  return nullptr;
}

LayoutObject* LayoutTreeBuilderTraversal::NextInTopLayer(
    const Element& element) {
  CHECK(element.ComputedStyleRef().IsRenderedInTopLayer(element))
      << "This method should only be called with an element that is rendered in"
         " the top layer";
  const HeapVector<Member<Element>>& top_layer_elements =
      element.GetDocument().TopLayerElements();
  wtf_size_t position = top_layer_elements.Find(&element);
  DCHECK_NE(position, kNotFound);
  for (wtf_size_t i = position + 1; i < top_layer_elements.size(); ++i) {
    LayoutObject* layout_object = top_layer_elements[i]->GetLayoutObject();
    // If top_layer_elements[i] is not a LayoutView child, its LayoutObject is
    // not re-attached and not in the top layer yet, thus we can not use it as a
    // sibling LayoutObject.
    if (layout_object &&
        layout_object->StyleRef().IsRenderedInTopLayer(
            *top_layer_elements[i]) &&
        IsA<LayoutView>(layout_object->Parent())) {
      return layout_object;
    }
  }
  return nullptr;
}

int LayoutTreeBuilderTraversal::ComparePreorderTreePosition(const Node& node1,
                                                            const Node& node2) {
  if (node1 == node2) {
    return 0;
  }
  const Node* anc1 = &node1;
  const Node* anc2 = &node2;
  if (Parent(*anc1) != Parent(*anc2)) {
    wtf_size_t depth1 = 0u;
    for (; anc1; anc1 = Parent(*anc1)) {
      if (anc1 == anc2) {
        // if node2 is ancestor of node1, return 1.
        return 1;
      }
      ++depth1;
    }
    wtf_size_t depth2 = 0u;
    for (; anc2; anc2 = Parent(*anc2)) {
      if (anc2 == anc1) {
        // if node1 is ancestor of node2, return -1.
        return -1;
      }
      ++depth2;
    }
    // Find LCA.
    anc1 = &node1;
    anc2 = &node2;
    while (depth1 < depth2) {
      anc2 = Parent(*anc2);
      --depth2;
    }
    while (depth1 > depth2) {
      anc1 = Parent(*anc1);
      --depth1;
    }
    while (anc1 && anc2) {
      const Node* parent1 = Parent(*anc1);
      const Node* parent2 = Parent(*anc2);
      if (parent1 == parent2) {
        break;
      }
      anc1 = parent1;
      anc2 = parent2;
    }
  }
  // Do some quick checks.
  const Node* parent = Parent(*anc1);
  DCHECK(parent);
  if (NextSibling(*anc2) == anc1 || FirstChild(*parent) == anc2) {
    return 1;
  }
  if (FirstChild(*parent) == anc1 || LastChild(*parent) == anc2) {
    return -1;
  }
  // Compare the children of the first common ancestor and the current top-most
  // ancestors of the nodes.
  // Note: starting with anc1 here, as in most use cases of this function we
  // want to compare two elements that are close to each other with anc1 usually
  // being previously in pre-order.
  DCHECK(anc1 && anc2);
  for (const Node* child = anc1; child; child = NextSibling(*child)) {
    if (child == anc2) {
      return -1;
    }
  }
  return 1;
}

}  // namespace blink
```