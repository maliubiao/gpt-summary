Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionality of the `focusgroup_controller_utils.cc` file within the Chromium Blink rendering engine. It also asks for connections to web technologies (JavaScript, HTML, CSS), examples, logic, potential errors, and debugging clues.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and patterns. The namespace `blink`, the class name `FocusgroupControllerUtils`, and the presence of functions like `FocusgroupDirectionForEvent`, `IsDirectionForward`, `FindNearestFocusgroupAncestor`, and `AdjustElementOutOfUnrelatedFocusgroup` immediately suggest this file deals with focus management and navigation. The inclusion of headers like `keyboard_event.h`, `keywords.h`, `layout_table.h`, and `focusgroup_flags.h` provides further context.

3. **Function-by-Function Analysis:** Go through each function individually and try to understand its purpose.

    * **`FocusgroupDirectionForEvent`:**  This clearly maps keyboard events (arrow keys) to focus navigation directions. The comments about RTL are important.

    * **`IsDirectionForward/Backward/Inline/Block`:** These are simple helper functions to classify the navigation direction.

    * **`IsAxisSupported`:** This relates focus group flags to the direction, suggesting that focus groups can be configured to support movement along certain axes (horizontal/vertical).

    * **`WrapsInDirection`:**  This hints at the concept of focus wrapping within a focus group.

    * **`FocusgroupExtendsInAxis`:** This function deals with nested focus groups and whether an inner group "extends" the navigation of the outer group in a specific direction.

    * **`FindNearestFocusgroupAncestor`:** This function searches up the DOM tree for the nearest ancestor element that is a focus group. The distinction between `kGrid` and `kLinear` focus groups is notable.

    * **`NextElement/PreviousElement`:** These are utilities for traversing the DOM tree in document order, considering flat tree traversal.

    * **`LastElementWithin`:**  Finds the last element within a given element.

    * **`IsFocusgroupItem`:** Determines if an element is considered an item within a focus group.

    * **`AdjustElementOutOfUnrelatedFocusgroup`:** This is the most complex function. The comments provide a detailed explanation of its purpose in preventing focus from inadvertently entering non-extending nested focus groups during backward navigation. The example with `fg1`, `a1`, `a2`, `fg2`, `b1`, `b2` is crucial for understanding.

    * **`IsGridFocusgroupItem`:**  Specifically checks if an element is a focusable item within a *grid* focus group, often associated with table cells.

    * **`CreateGridFocusgroupStructureInfoForGridRoot`:**  This function seems to create a data structure to manage the layout of grid focus groups, particularly for tables.

4. **Identify Relationships with Web Technologies:**  As you analyze the functions, think about how these concepts map to HTML, CSS, and JavaScript.

    * **HTML:**  The concept of focus groups relates directly to how elements are structured in the HTML and how users navigate using the Tab key and arrow keys. The `<tabindex>` attribute comes to mind as it influences focusability. The mention of tables and grids is also a direct HTML connection.

    * **CSS:**  While this file is C++, it's part of the *rendering* engine. CSS properties like `display: grid` and potentially custom properties or attributes could influence the creation and behavior of focus groups (though this file itself doesn't directly parse CSS).

    * **JavaScript:**  JavaScript event listeners for keyboard events are the primary way user interactions trigger the logic in this file. JavaScript can also manipulate the DOM, potentially changing focus group structures dynamically.

5. **Develop Examples and Scenarios:**  For each function or key concept, create concrete examples. This helps solidify understanding and makes the explanation clearer. For example, the nested focus group scenario for `AdjustElementOutOfUnrelatedFocusgroup` is a great illustration.

6. **Consider Logic and Assumptions:**  Think about the inputs and outputs of the functions. What are the assumptions being made?  For instance, `FocusgroupDirectionForEvent` assumes standard keyboard layouts.

7. **Identify Potential Errors:**  Based on your understanding of the code, consider what could go wrong. User errors (incorrect HTML structure, missing `tabindex`) and programming errors (incorrectly setting focus group flags) are good starting points.

8. **Think about Debugging:**  How would you use this code to debug focus-related issues?  Understanding the flow of execution from a keyboard event to the functions in this file is key. Log statements (though not explicitly in the code) placed strategically would be useful. Knowing the user actions that lead to this code being executed is important.

9. **Structure the Explanation:** Organize your findings in a clear and logical way, following the prompts in the request. Start with a general overview, then detail the function-level behavior, and finally address the connections to web technologies, examples, errors, and debugging.

10. **Refine and Review:** Read through your explanation, checking for accuracy, clarity, and completeness. Ensure that the examples are understandable and that the connections to web technologies are well-articulated. For instance, initially I might have just said "handles keyboard events," but refining that to "maps keyboard events (arrow keys) to focus navigation directions within focus groups" is more precise.

By following this structured approach, you can effectively analyze and explain the functionality of a complex C++ source file like `focusgroup_controller_utils.cc`. The key is to break down the problem, understand the individual components, and then connect them back to the broader context of web development.
This C++ source file, `focusgroup_controller_utils.cc`, within the Chromium Blink rendering engine provides a set of utility functions to manage and navigate focus within web pages, particularly concerning the concept of **focus groups**. Focus groups are logical groupings of focusable elements that can be navigated using arrow keys, providing a more structured and intuitive way to interact with complex UI components.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Determining Focus Navigation Direction:**
   - `FocusgroupDirectionForEvent(KeyboardEvent* event)`: This function takes a keyboard event as input and determines the intended direction of focus navigation based on the pressed key. It primarily focuses on arrow keys (Up, Down, Left, Right).
   - **Example:** If the Down arrow key is pressed, it returns `FocusgroupDirection::kForwardBlock` (moving forward in a block-like direction, typically downwards).

2. **Classifying Navigation Directions:**
   - `IsDirectionForward(FocusgroupDirection direction)`: Checks if a given `FocusgroupDirection` represents forward movement.
   - `IsDirectionBackward(FocusgroupDirection direction)`: Checks if a given `FocusgroupDirection` represents backward movement.
   - `IsDirectionInline(FocusgroupDirection direction)`: Checks if a given `FocusgroupDirection` represents horizontal movement (left/right).
   - `IsDirectionBlock(FocusgroupDirection direction)`: Checks if a given `FocusgroupDirection` represents vertical movement (up/down).

3. **Focus Group Properties and Behavior:**
   - `IsAxisSupported(FocusgroupFlags flags, FocusgroupDirection direction)`: Determines if a focus group, identified by its flags, supports navigation in a particular direction (inline or block).
   - `WrapsInDirection(FocusgroupFlags flags, FocusgroupDirection direction)`: Determines if focus wraps around within a focus group when navigating in a particular direction. For instance, if you're on the last item and press the right arrow, focus might wrap to the first item.
   - `FocusgroupExtendsInAxis(FocusgroupFlags extending_focusgroup, FocusgroupFlags focusgroup, FocusgroupDirection direction)`:  Determines if a nested focus group extends the navigation of its parent focus group in a specific direction. This is crucial for managing how focus moves between nested focusable areas.

4. **Finding Focus Group Ancestors:**
   - `FindNearestFocusgroupAncestor(const Element* element, FocusgroupType type)`: Traverses up the DOM tree from a given element to find the nearest ancestor that is a focus group of a specific type (e.g., linear or grid).
   - **Example:**  If you have a table acting as a grid focus group, this function can find that table element given a cell within it.

5. **Navigating the DOM:**
   - `NextElement(const Element* current, bool skip_subtree)`: Finds the next focusable element in the DOM tree, optionally skipping the subtree of the current element.
   - `PreviousElement(const Element* current)`: Finds the previous focusable element in the DOM tree.
   - `LastElementWithin(const Element* current)`: Finds the last focusable element within a given element. These functions are fundamental for the underlying navigation logic.

6. **Identifying Focus Group Items:**
   - `IsFocusgroupItem(const Element* element)`: Checks if an element is considered an item within a focus group (i.e., a focusable child of a focus group element).

7. **Handling Nested Focus Groups:**
   - `AdjustElementOutOfUnrelatedFocusgroup(Element* element, Element* stop_ancestor, FocusgroupDirection direction)`: This is a key function for handling backward navigation in nested focus groups that *don't* extend their parent's focus. It prevents the focus from unintentionally entering a nested focus group when navigating backward from an element outside of it.
   - **Assumption:**  Backward navigation is being performed.
   - **Input:** The current element, an ancestor that belongs to the previous focus group, and the navigation direction.
   - **Output:** The adjusted element, which will be an ancestor of the original element, ensuring focus stays within the expected focus group boundaries.

8. **Grid Focus Group Specifics:**
   - `IsGridFocusgroupItem(const Element* element)`:  Specifically checks if an element is a focusable item within a *grid* focus group (often, but not exclusively, table cells).
   - `CreateGridFocusgroupStructureInfoForGridRoot(Element* root)`: Creates a data structure (`GridFocusgroupStructureInfo`) to manage the layout and navigation within a grid-based focus group, often backed by a `LayoutTable`.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:**
    - Focus groups are implicitly defined by the structure of the HTML and the presence of focusable elements (e.g., elements with a `tabindex` attribute or inherently focusable elements like `<button>`, `<input>`, `<a>`).
    - The concept of grid focus groups directly relates to HTML tables (`<table>`) and potentially elements with `display: grid` CSS.
    - The `tabindex` attribute plays a crucial role in determining the default tab order and focusability of elements, which interacts with focus group navigation.

    **Example:**
    ```html
    <div tabindex="0">Focus Group 1
      <button>Item 1</button>
      <button>Item 2</button>
    </div>
    ```
    Here, the `<div>` with `tabindex="0"` could be considered a simple focus group. Arrow key navigation within it might be handled by the logic in this file.

    ```html
    <table tabindex="0">
      <tr><td>Cell 1</td><td>Cell 2</td></tr>
      <tr><td>Cell 3</td><td>Cell 4</td></tr>
    </table>
    ```
    This table, with `tabindex="0"`, could be treated as a grid focus group, and arrow key navigation would move between the table cells.

* **CSS:**
    - While this C++ code doesn't directly parse CSS, CSS properties like `display: grid` can influence the layout and the way focus groups are structured and navigated, especially for grid focus groups.
    - CSS can visually indicate focus using pseudo-classes like `:focus`, which is triggered by the focus management logic.

* **JavaScript:**
    - JavaScript event listeners for `keydown` or `keyup` events are the primary way user interactions trigger the focus navigation logic that eventually uses these utility functions.
    - JavaScript can programmatically set focus using methods like `element.focus()`, which interacts with the underlying focus management system.
    - JavaScript can also manipulate the DOM structure, dynamically creating or removing elements and potentially affecting focus group boundaries.

    **Example:**
    ```javascript
    document.addEventListener('keydown', function(event) {
      if (event.key === 'ArrowRight') {
        // JavaScript might trigger the focus navigation logic based on the arrow key press.
      }
    });
    ```

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's consider the `AdjustElementOutOfUnrelatedFocusgroup` function:

**Assumptions:**

* The user is navigating backward using arrow keys.
* The `stop_ancestor` belongs to the focus group the user was previously in.
* The `element` has moved into a nested focus group that doesn't extend the parent's focus.

**Hypothetical Input:**

Imagine this HTML structure:

```html
<div tabindex="0" id="focusgroup1">
  <button>Item A</button>
  <div tabindex="0" id="focusgroup2">
    <button>Item B1</button>
    <button>Item B2</button>
  </div>
  <button>Item C</button>
</div>
```

Assume `focusgroup2` is configured (via Blink's internal mechanisms, not explicit HTML attributes in this simplified example) as a focus group that does *not* extend `focusgroup1` in the backward direction.

1. User focuses on "Item C".
2. User presses the Left arrow key (attempting backward navigation).
3. The focus moves to "Item B2" (the last focusable element before "Item C" in DOM order).
4. `AdjustElementOutOfUnrelatedFocusgroup` is called with:
   - `element`: The `button` element for "Item B2".
   - `stop_ancestor`: The `div` element for `focusgroup1`.
   - `direction`: `FocusgroupDirection::kBackwardInline` (assuming left arrow).

**Output:**

The function will identify that `focusgroup2` (the parent of "Item B2") is a focus group that doesn't extend `focusgroup1` backward. Therefore, it will return the `div` element for `focusgroup2` itself. The focus management logic will then likely focus on `focusgroup2`, preventing the user from getting stuck inside the nested, non-extending focus group when navigating backward from outside it.

**Common Usage Errors and Examples:**

1. **Incorrect `tabindex` usage:**
   - **Error:**  Setting `tabindex="-1"` on an element that should be part of a focus group and navigable by arrow keys. This will make the element focusable programmatically but not reachable via sequential focus navigation (Tab key) or potentially arrow key navigation within a focus group.
   - **Example:**  A button inside a custom component intended for arrow key navigation has `tabindex="-1"`. The user might expect to reach it with arrow keys but cannot.

2. **Conflicting focus management logic:**
   - **Error:** Implementing custom JavaScript focus management that interferes with Blink's built-in focus group handling. This can lead to unexpected focus behavior.
   - **Example:**  JavaScript code intercepts arrow key presses and tries to manually move focus, but it doesn't correctly account for the boundaries of focus groups, leading to focus getting "lost" or jumping to incorrect elements.

3. **Incorrect focus group flags configuration (internal Blink):**
   - **Error:**  While users don't directly set these flags, incorrect internal configuration within Blink for custom elements or components could lead to unexpected focus group behavior. A developer working on Blink might incorrectly flag a container element, causing it to behave unexpectedly as a focus group.

**User Operations Leading to This Code (Debugging Clues):**

1. **User presses an arrow key:** This is the most direct trigger. When a user presses an arrow key, the browser dispatches a `keydown` event. Blink's event handling mechanism will eventually route this event to code that determines the focus navigation direction using `FocusgroupDirectionForEvent`.

2. **Tabbing through focusable elements:** While this file focuses on arrow key navigation, the concept of focus groups also interacts with sequential focus navigation (Tab key). The order in which elements are focused via Tab might influence which focus group is active and how arrow key navigation behaves subsequently.

3. **Programmatically setting focus via JavaScript:** When JavaScript calls `element.focus()`, it can move the focus into a specific element within a focus group, and subsequent arrow key presses will then be handled by the logic in this file.

4. **Interacting with custom UI components:** Modern web development often involves custom UI components (e.g., using Shadow DOM or web components). These components might be designed to act as focus groups, and the logic in this file is essential for managing focus within and between them.

**Example Debugging Scenario:**

A user is navigating a webpage with a custom image carousel. The carousel uses arrow keys for navigation. If the arrow key navigation within the carousel is not working as expected (e.g., focus gets stuck or jumps out of the carousel prematurely), a Blink developer might investigate the execution path involving these utility functions. They might:

1. **Set breakpoints in `FocusgroupDirectionForEvent`:** To confirm that the arrow key press is being correctly interpreted.
2. **Set breakpoints in `FindNearestFocusgroupAncestor`:** To understand which element is being identified as the current focus group.
3. **Step through `AdjustElementOutOfUnrelatedFocusgroup`:** If the issue involves navigating into or out of the carousel, this function is a prime suspect. The developer would examine the values of `element`, `stop_ancestor`, and `direction` to understand why the focus is behaving unexpectedly.
4. **Examine the `FocusgroupFlags`:**  Using internal debugging tools, they would inspect the flags associated with the carousel container to see if they are correctly configured to support the desired navigation behavior (e.g., wrapping).

In summary, `focusgroup_controller_utils.cc` is a crucial part of Blink's focus management system, providing the low-level logic for navigating within and between focus groups using arrow keys. It interacts closely with HTML structure, and its behavior is triggered by user interactions and can be influenced by CSS and JavaScript. Understanding its functionality is essential for developers working on the Chromium rendering engine and for web developers building complex, accessible user interfaces.

Prompt: 
```
这是目录为blink/renderer/core/page/focusgroup_controller_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/focusgroup_controller_utils.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focusgroup_flags.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/page/grid_focusgroup_structure_info.h"

namespace blink {

FocusgroupDirection FocusgroupControllerUtils::FocusgroupDirectionForEvent(
    KeyboardEvent* event) {
  DCHECK(event);
  if (event->ctrlKey() || event->metaKey() || event->shiftKey())
    return FocusgroupDirection::kNone;

  const AtomicString key(event->key());
  // TODO(bebeaudr): Support RTL. Will it be as simple as inverting the
  // direction associated with the left and right arrows when in a RTL element?
  if (key == keywords::kArrowDown) {
    return FocusgroupDirection::kForwardBlock;
  } else if (key == keywords::kArrowRight) {
    return FocusgroupDirection::kForwardInline;
  } else if (key == keywords::kArrowUp) {
    return FocusgroupDirection::kBackwardBlock;
  } else if (key == keywords::kArrowLeft) {
    return FocusgroupDirection::kBackwardInline;
  }

  return FocusgroupDirection::kNone;
}

bool FocusgroupControllerUtils::IsDirectionForward(
    FocusgroupDirection direction) {
  return direction == FocusgroupDirection::kForwardInline ||
         direction == FocusgroupDirection::kForwardBlock;
}

bool FocusgroupControllerUtils::IsDirectionBackward(
    FocusgroupDirection direction) {
  return direction == FocusgroupDirection::kBackwardInline ||
         direction == FocusgroupDirection::kBackwardBlock;
}

bool FocusgroupControllerUtils::IsDirectionInline(
    FocusgroupDirection direction) {
  return direction == FocusgroupDirection::kBackwardInline ||
         direction == FocusgroupDirection::kForwardInline;
}

bool FocusgroupControllerUtils::IsDirectionBlock(
    FocusgroupDirection direction) {
  return direction == FocusgroupDirection::kBackwardBlock ||
         direction == FocusgroupDirection::kForwardBlock;
}

bool FocusgroupControllerUtils::IsAxisSupported(FocusgroupFlags flags,
                                                FocusgroupDirection direction) {
  return ((flags & FocusgroupFlags::kInline) && IsDirectionInline(direction)) ||
         ((flags & FocusgroupFlags::kBlock) && IsDirectionBlock(direction));
}

bool FocusgroupControllerUtils::WrapsInDirection(
    FocusgroupFlags flags,
    FocusgroupDirection direction) {
  return ((flags & FocusgroupFlags::kWrapInline) &&
          IsDirectionInline(direction)) ||
         ((flags & FocusgroupFlags::kWrapBlock) && IsDirectionBlock(direction));
}

bool FocusgroupControllerUtils::FocusgroupExtendsInAxis(
    FocusgroupFlags extending_focusgroup,
    FocusgroupFlags focusgroup,
    FocusgroupDirection direction) {
  if (focusgroup == FocusgroupFlags::kNone ||
      extending_focusgroup == FocusgroupFlags::kNone) {
    return false;
  }

  return extending_focusgroup & FocusgroupFlags::kExtend &&
         (IsAxisSupported(focusgroup, direction) ==
          IsAxisSupported(extending_focusgroup, direction));
}

Element* FocusgroupControllerUtils::FindNearestFocusgroupAncestor(
    const Element* element,
    FocusgroupType type) {
  if (!element)
    return nullptr;

  for (Element* ancestor = FlatTreeTraversal::ParentElement(*element); ancestor;
       ancestor = FlatTreeTraversal::ParentElement(*ancestor)) {
    FocusgroupFlags ancestor_flags = ancestor->GetFocusgroupFlags();
    if (ancestor_flags != FocusgroupFlags::kNone) {
      switch (type) {
        case FocusgroupType::kGrid:
          // TODO(bebeaudr): Support grid focusgroups that aren't based on the
          // table layout objects.
          if (ancestor_flags & FocusgroupFlags::kGrid &&
              IsA<LayoutTable>(ancestor->GetLayoutObject())) {
            return ancestor;
          }
          break;
        case FocusgroupType::kLinear:
          if (!(ancestor_flags & FocusgroupFlags::kGrid))
            return ancestor;
          break;
        default:
          NOTREACHED();
      }
      return nullptr;
    }
  }

  return nullptr;
}

Element* FocusgroupControllerUtils::NextElement(const Element* current,
                                                bool skip_subtree) {
  DCHECK(current);
  Node* node;
  if (skip_subtree)
    node = FlatTreeTraversal::NextSkippingChildren(*current);
  else
    node = FlatTreeTraversal::Next(*current);

  Element* next_element;
  // Here, we don't need to skip the subtree when getting the next element since
  // we've already skipped the subtree we wanted to skipped by calling
  // NextSkippingChildren above.
  for (; node; node = FlatTreeTraversal::Next(*node)) {
    next_element = DynamicTo<Element>(node);
    if (next_element)
      return next_element;
  }
  return nullptr;
}

Element* FocusgroupControllerUtils::PreviousElement(const Element* current) {
  DCHECK(current);
  Node* node = FlatTreeTraversal::Previous(*current);

  Element* previous_element;
  for (; node; node = FlatTreeTraversal::Previous(*node)) {
    previous_element = DynamicTo<Element>(node);
    if (previous_element)
      return previous_element;
  }
  return nullptr;
}

Element* FocusgroupControllerUtils::LastElementWithin(const Element* current) {
  DCHECK(current);
  Node* last_node = FlatTreeTraversal::LastWithin(*current);

  // We now have the last Node, but it might not be the last Element. Find it
  // by going to the previous element in preorder if needed.
  Element* last_element;
  for (; last_node && last_node != current;
       last_node = FlatTreeTraversal::Previous(*last_node)) {
    last_element = DynamicTo<Element>(last_node);
    if (last_element)
      return last_element;
  }
  return nullptr;
}

bool FocusgroupControllerUtils::IsFocusgroupItem(const Element* element) {
  if (!element || !element->IsFocusable())
    return false;

  // All children of a focusgroup are considered focusgroup items if they are
  // focusable.
  Element* parent = FlatTreeTraversal::ParentElement(*element);
  if (!parent)
    return false;

  FocusgroupFlags parent_flags = parent->GetFocusgroupFlags();
  return parent_flags != FocusgroupFlags::kNone;
}

// This function is called whenever the |element| passed by parameter has fallen
// into a subtree while navigating backward. Its objective is to prevent
// |element| from having descended into a non-extending focusgroup. When it
// detects its the case, it returns |element|'s first ancestor who is still part
// of the same focusgroup as |stop_ancestor|. The returned element is
// necessarily an element part of the previous focusgroup, but not necessarily a
// focusgroup item.
//
// |stop_ancestor| might be a focusgroup root itself or be a descendant of one.
// Regardless, given the assumption that |stop_ancestor| is always part of the
// previous focusgroup, we can stop going up |element|'s ancestors chain as soon
// as we reached it.
//
// Let's consider this example:
//           fg1
//      ______|_____
//      |          |
//      a1       a2
//      |
//     fg2
//    __|__
//    |   |
//    b1  b2
//
// where |fg2| is a focusgroup that doesn't extend the focusgroup |fg1|. While
// |fg2| is part of the focusgroup |fg1|, its subtree isn't. If the focus is on
// |a2|, the second item of the top-most focusgroup, and we go backward using
// the arrow keys, the focus should move to |fg2|. It shouldn't go inside of
// |fg2|, since it's a different focusgroup that doesn't extend its parent
// focusgroup.
//
// However, the previous element in preorder traversal from |a2| is |b2|, which
// isn't part of the same focusgroup. This function aims at fixing this by
// moving the current element to its parent, which is part of the previous
// focusgroup we were in (when we were on |a2|), |fg1|.
Element* FocusgroupControllerUtils::AdjustElementOutOfUnrelatedFocusgroup(
    Element* element,
    Element* stop_ancestor,
    FocusgroupDirection direction) {
  DCHECK(element);
  DCHECK(stop_ancestor);

  // Get the previous focusgroup we were part of (|stop_ancestor| was
  // necessarily part of it: it was either the focusgroup itself or a descendant
  // of that focusgroup).
  FocusgroupFlags focusgroup_flags = stop_ancestor->GetFocusgroupFlags();
  if (focusgroup_flags == FocusgroupFlags::kNone) {
    Element* focusgroup =
        FindNearestFocusgroupAncestor(stop_ancestor, FocusgroupType::kLinear);
    DCHECK(focusgroup);
    focusgroup_flags = focusgroup->GetFocusgroupFlags();
  }

  // Go over each ancestor of the |element| in order to validate that it is
  // still part of the previous focusgroup. If it isn't, set the ancestor that
  // broke one of the conditions as the |adjusted_element| and continue the
  // loop from there.
  Element* adjusted_element = element;
  for (Element* ancestor = FlatTreeTraversal::ParentElement(*element); ancestor;
       ancestor = FlatTreeTraversal::ParentElement(*ancestor)) {
    if (ancestor == stop_ancestor)
      break;

    // We consider |element| as being part of a different focusgroup than the
    // one we were previously in when one of its ancestor is a focusgroup that
    // doesn't extend the previous one.
    FocusgroupFlags ancestor_flags = ancestor->GetFocusgroupFlags();
    if (ancestor_flags != FocusgroupFlags::kNone &&
        !FocusgroupExtendsInAxis(ancestor_flags, focusgroup_flags, direction)) {
      adjusted_element = ancestor;
    }
  }

  return adjusted_element;
}

bool FocusgroupControllerUtils::IsGridFocusgroupItem(const Element* element) {
  DCHECK(element);
  if (!element->IsFocusable())
    return false;

  // TODO(bebeaudr): Add support for manual grids, where the grid focusgroup
  // items aren't necessarily on an table cell layout object.
  return IsA<LayoutTableCell>(element->GetLayoutObject());
}

GridFocusgroupStructureInfo*
FocusgroupControllerUtils::CreateGridFocusgroupStructureInfoForGridRoot(
    Element* root) {
  if (IsA<LayoutTable>(root->GetLayoutObject()) &&
      root->GetFocusgroupFlags() & FocusgroupFlags::kGrid) {
    return MakeGarbageCollected<AutomaticGridFocusgroupStructureInfo>(
        root->GetLayoutObject());
  } else {
    // TODO(bebeaudr): Handle manual-grid focusgroups.
    return nullptr;
  }
}

}  // namespace blink

"""

```