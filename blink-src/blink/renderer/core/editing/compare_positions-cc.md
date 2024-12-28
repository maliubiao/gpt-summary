Response:
Let's break down the thought process for analyzing the `compare_positions.cc` file.

1. **Understand the Core Request:** The primary goal is to understand the *functionality* of this C++ file within the Blink rendering engine. The request also asks about its relation to web technologies (JS, HTML, CSS), logical reasoning (input/output), potential user errors, and how a user's action might lead to this code.

2. **Initial Code Scan - Identify Key Components:**  The first step is a quick scan to identify the major parts of the code. I notice:
    * Header includes (`editing_utilities.h`, `editing_strategy.h`, `visible_position.h`). These give hints about the file's purpose: it's related to text editing and position concepts.
    * A namespace `blink` and a nested anonymous namespace. This is standard C++ organization.
    * A constant `kInvalidOffset`. This suggests dealing with potentially undefined or special offset values.
    * A `Comparator` template class. Templates often indicate generic algorithms that can work with different data types (in this case, likely different tree traversal methods).
    * Multiple overloaded `ComparePositions` functions. Overloading suggests flexibility in handling different input types for comparing positions.
    * Specific `ComparePositions` functions for DOM tree and flat tree. This points to the different tree structures used in Blink.
    * Usage of `DCHECK`. This indicates assertions used for debugging and internal consistency checks.

3. **Focus on the `Comparator` Class:** The `Comparator` class seems central to the file's purpose. I'd examine its methods:
    * `ComparePositions(Node*, int, Node*, int, bool*)`:  Compares positions using integer offsets.
    * `ComparePositions(Node*, int, Node*, Node*, int, Node*, bool*)`: Compares positions using a mix of integer and node offsets. The `kInvalidOffset` logic within this function is important.
    * Private helper methods like `ComparePositionsInternal`, `CompareNodesInSameParent`. These likely implement the core comparison logic.

4. **Deconstruct `ComparePositionsInternal`:** This function contains the main comparison algorithm. I'd analyze the different cases it handles:
    * **Case 1 (Same Container):**  Simple comparison of offsets within the same parent.
    * **Case 2 (Container B is Descendant of A):**  Finding the child of A that is an ancestor of B.
    * **Case 3 (Container A is Descendant of B):** Similar to case 2, but reversed.
    * **Case 4 (Containers are Siblings or Children of Siblings):** Finding the common ancestor and comparing the relevant child nodes.
    * **Disconnected Case:** Handling situations where the nodes are in different tree scopes.

5. **Connect to Web Technologies:** Now, think about how this code relates to the user and web technologies:
    * **JavaScript:**  JS can manipulate the DOM, creating and moving nodes. Functions like `Node.compareDocumentPosition()` in JavaScript directly map to the core functionality here. User selections made in the browser are also represented as DOM positions.
    * **HTML:** The structure of the HTML document defines the tree that these comparison functions operate on. Adding, removing, or moving elements in HTML will affect the outcome of these comparisons.
    * **CSS:** While CSS primarily deals with styling, properties like `display: none` or `visibility: hidden` can affect the rendered tree and, consequently, the "visible" positions (handled by `VisiblePosition`).

6. **Logical Reasoning (Input/Output):**  Create concrete examples:
    * **Simple Case:** Two text nodes within the same paragraph.
    * **More Complex Case:** Nodes nested deeply within different parts of the DOM.
    * **Disconnected Case:**  Elements in different shadow DOM trees or iframes. This helps illustrate the `disconnected` flag.

7. **User/Programming Errors:** Consider how developers might misuse or encounter issues related to position comparisons:
    * **Incorrect Node or Offset:**  Passing invalid node references or out-of-bounds offsets.
    * **Assuming DOM Tree When Flat Tree is Needed:**  For shadow DOM scenarios, the flat tree order matters for certain operations.
    * **Comparing Positions Across Different Documents/Iframes:**  Understanding the implications of tree scopes is crucial.

8. **User Interaction and Debugging:**  Trace a typical user action that would trigger this code:
    * **Text Selection:** Dragging the mouse to select text is a prime example. The browser needs to determine the start and end points of the selection.
    * **Cursor Movement:**  Moving the text cursor involves determining the correct position within the DOM.
    * **Drag and Drop:**  Figuring out where an element is being dropped requires comparing potential insertion points.
    * **JavaScript DOM Manipulation:**  JS code that programmatically inserts or moves nodes might internally use these comparison functions.

9. **Structure the Answer:** Organize the information logically into the categories requested: functionality, relationship to web technologies, logical reasoning, user errors, and debugging. Use clear and concise language. Provide code snippets or simple HTML examples where helpful.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or areas that could be explained better. For instance, initially, I might just say "compares positions."  Refining that to explicitly mention DOM tree vs. flat tree and the different offset types makes the explanation more thorough.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer that addresses all aspects of the request. The key is to combine code-level understanding with knowledge of web technologies and common development scenarios.
This C++ source file, `compare_positions.cc`, located within the Blink rendering engine, is dedicated to **comparing the relative order of two positions within the DOM tree or the flat tree (which includes shadow DOM)**.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Compares two DOM positions:** The primary goal is to determine if one position comes before, after, or is the same as another position within the document structure.
* **Handles different position representations:** It can compare positions defined by:
    * **Container node and offset:**  A position within a node, either before the first child, after the last child, or between two children.
    * **Node before position:**  A position immediately before a specific node.
* **Supports both DOM tree and flat tree:** Blink uses both a traditional DOM tree and a "flat tree" representation that flattens the shadow DOM structure. This file provides functions to compare positions in both.
* **Determines if positions are disconnected:**  It can detect if the two positions belong to entirely separate DOM trees (e.g., different iframes or shadow roots without a shared ancestor).
* **Provides different levels of comparison:**  It offers comparison functions for raw DOM positions (`Position`), positions with affinity (`PositionWithAffinity`), and visible positions (`VisiblePosition`).

**Relationship to JavaScript, HTML, and CSS:**

This file is a fundamental building block for many features that interact with the DOM and are exposed to JavaScript, influenced by HTML structure, and potentially affected by CSS.

**Examples:**

* **JavaScript's `Node.compareDocumentPosition()`:**  The functionality implemented in `compare_positions.cc` is directly related to the JavaScript DOM API method `Node.compareDocumentPosition()`. When JavaScript calls this method, the browser's internal implementation likely utilizes the logic present in this file (or similar lower-level functions).
    * **HTML:** Consider the following HTML:
      ```html
      <div id="parent">
        <span id="child1">Text 1</span>
        <span id="child2">Text 2</span>
      </div>
      ```
    * **JavaScript:**
      ```javascript
      const parent = document.getElementById('parent');
      const child1 = document.getElementById('child1');
      const child2 = document.getElementById('child2');

      // Comparing positions within the parent node
      const compareResult = parent.compareDocumentPosition(child1);
      // The logic in compare_positions.cc would be used to determine that child1
      // comes before other nodes within the parent.

      const range1 = document.createRange();
      range1.setStart(child1.firstChild, 0); // Start of "Text 1"
      const range2 = document.createRange();
      range2.setStart(child2.firstChild, 0); // Start of "Text 2"

      const compareRanges = range1.compareBoundaryPoints(Range.START_TO_START, range2);
      // Internally, this also relies on comparing positions, likely leveraging
      // the code in compare_positions.cc.
      ```

* **Text Selection:** When a user selects text on a web page, the browser needs to determine the start and end points of the selection. This involves comparing DOM positions.
    * **User Action:** User drags the mouse cursor to select the text "Text 1 Text 2" in the HTML example above.
    * **Internal Process:** The browser needs to identify the start position (beginning of "Text 1") and the end position (end of "Text 2"). `compare_positions.cc` would be used to confirm that the end position comes after the start position.

* **Cursor Movement:** When the user moves the text cursor using arrow keys or by clicking, the browser needs to determine the new cursor position within the DOM. This often involves comparing the current position with potential new positions.

* **Drag and Drop:** When implementing drag and drop functionality, the browser needs to determine valid drop locations. This requires comparing the potential drop position with existing elements in the DOM.

* **Shadow DOM:**  The functions `ComparePositionsInFlatTree` and the generic `ComparePositions` handle comparisons in the context of Shadow DOM.
    * **HTML:**
      ```html
      <my-element>
        #shadow-root
          <p>Shadow Content</p>
      </my-element>
      <p id="light">Light Content</p>
      ```
    * **Internal Process:** When comparing a position inside the shadow root with a position in the light DOM, the flat tree comparison logic in `compare_positions.cc` is used to determine their relative order as they would appear in the rendered output.

* **CSS and Layout:** While CSS doesn't directly call these functions, CSS properties like `display: none` or `visibility: hidden` can affect the rendered DOM tree. When comparing positions, the code needs to consider the actual structure, which might be influenced by CSS.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the HTML example:

```html
<div id="container">
  <span id="a">A</span>
  <span id="b">B</span>
</div>
```

**Scenario 1: Comparing node positions**

* **Input:**
    * `container_a`: The `div` element (`#container`)
    * `offset_a`: 0 (position before the first child)
    * `container_b`: The `div` element (`#container`)
    * `offset_b`: 1 (position between the first and second child)
* **Output:** `-1` (indicating position A is before position B)

**Scenario 2: Comparing positions of text nodes**

* **Input:**
    * `container_a`: The `span` element with ID `a`
    * `offset_a`: 0 (start of the text node "A")
    * `container_b`: The `span` element with ID `b`
    * `offset_b`: 0 (start of the text node "B")
* **Output:** `-1` (indicating the start of "A" comes before the start of "B")

**Scenario 3: Disconnected nodes**

* **Input:** Two `div` elements that are not related in the DOM tree (e.g., in different iframes).
* **Output:**  The `disconnected` flag passed to the function would be set to `true`. The return value might be `0` (equal) as per the logic for disconnected nodes, but the `disconnected` flag provides the crucial information.

**User or Programming Common Usage Errors:**

* **Incorrect Node or Offset:** Passing an invalid node reference or an offset that is out of bounds for the given container. This could lead to unexpected comparison results or even crashes.
    * **Example:**  Trying to get the child at index 5 of a node that only has 2 children.
* **Assuming DOM Tree Order When Flat Tree is Needed:** When dealing with Shadow DOM, developers might mistakenly use DOM tree comparison logic when they need to consider the flattened order of elements. This can lead to incorrect assumptions about the relative positions of elements within and outside shadow roots.
* **Comparing Positions Across Different Documents/Iframes Without Checking for Disconnection:**  Directly comparing positions from different documents or independent iframes without checking the `disconnected` flag can lead to meaningless or incorrect comparisons.

**How User Operation Leads to This Code (Debugging Clues):**

1. **User Selects Text:**
   - The user presses the mouse button and drags the cursor across text content.
   - The browser needs to determine the start and end points of the selection.
   - This involves identifying the DOM nodes and offsets corresponding to the mouse positions.
   - The `ComparePositions` functions are called to determine the order of these start and end points.

2. **User Moves Cursor:**
   - The user clicks at a specific location in the text or uses arrow keys to navigate.
   - The browser needs to update the cursor position.
   - This involves finding the corresponding DOM node and offset.
   - `ComparePositions` might be used to determine the new cursor position relative to existing elements or text nodes.

3. **User Drags and Drops an Element:**
   - The user starts dragging an element.
   - As the user moves the dragged element over potential drop targets, the browser needs to evaluate valid drop locations.
   - This involves comparing the potential drop position with the positions of other elements in the DOM, likely using `ComparePositionsInFlatTree` if shadow DOM is involved.

4. **JavaScript Code Manipulates the DOM:**
   - A JavaScript script uses methods like `insertBefore`, `appendChild`, `removeChild`, or sets the `innerHTML` of an element.
   - Internally, when these operations are performed, the browser needs to update the structure of the DOM.
   - While the JavaScript code doesn't directly call `compare_positions.cc`, the underlying implementation of these DOM manipulation methods might rely on position comparisons to ensure the correct ordering of nodes.

5. **Inspecting Elements in Developer Tools:**
   - When you select an element in the "Elements" tab of the browser's developer tools, the browser needs to highlight the corresponding element in the rendered page.
   - Determining the boundaries of the element for highlighting might involve comparing the positions of its start and end tags or its child nodes.

**In summary, `compare_positions.cc` provides the core logic for determining the relative order of positions within the DOM and flat tree in the Blink rendering engine. It is a fundamental piece used by many higher-level features exposed to JavaScript, influenced by HTML structure, and potentially affected by CSS, making it a crucial component for the browser's ability to understand and manipulate the structure of web pages.**

Prompt: 
```
这是目录为blink/renderer/core/editing/compare_positions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/editing_utilities.h"

#include "third_party/blink/renderer/core/editing/editing_strategy.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"

namespace blink {

namespace {

constexpr int kInvalidOffset = -1;

// The `Comparator` class implements `ComparePositions()` logic.
template <typename Traversal>
class Comparator {
  STATIC_ONLY(Comparator);

 public:
  // Integer offset version of `ComparePositions()`.
  //
  // Returns
  //  -1 if `node_a` is before `node_b`
  //   0 if `node_a == node_b`
  //   1 if `node_a` is after `node_b`
  //    where
  //      * `node_a == Traversal::ChildAt(*container_a, offset_a)`
  //      * `node_b == Traversal::ChildAt(*container_a, offset_b)`
  // and set `disconnected` to true if `node_a` and `node_b` are in different
  // tree scopes.
  static int16_t ComparePositions(const Node* container_a,
                                  int offset_a,
                                  const Node* container_b,
                                  int offset_b,
                                  bool* disconnected) {
    return ComparePositionsInternal(container_a, IntAsOffset(offset_a),
                                    container_b, IntAsOffset(offset_b),
                                    disconnected);
  }

  // Integer/Node offset version of `ComparePositions()`.
  //
  // Returns
  //  -1 if `node_a` is before `node_b`
  //   0 if `node_a == node_b`
  //   1 if `node_a` is after `node_b`
  //    where
  //      * `node_a == Traversal::ChildAt(*container_a, offset_a)`
  //      * `node_b == Traversal::ChildAt(*container_a, offset_b)`
  // and set `disconnected` to true if `node_a` and `node_b` are in different
  // tree scopes.
  static int16_t ComparePositions(const Node* container_a,
                                  int offset_a,
                                  const Node* child_a,
                                  const Node* container_b,
                                  int offset_b,
                                  const Node* child_b,
                                  bool* disconnected = nullptr) {
    if (offset_a == kInvalidOffset && offset_b == kInvalidOffset) {
      return ComparePositionsInternal(container_a, NodeAsOffset(child_a),
                                      container_b, NodeAsOffset(child_b),
                                      disconnected);
    }

    if (offset_a == kInvalidOffset) {
      return ComparePositionsInternal(container_a, NodeAsOffset(child_a),
                                      container_b, IntAsOffset(offset_b),
                                      disconnected);
    }

    if (offset_b == kInvalidOffset) {
      return ComparePositionsInternal(container_a, IntAsOffset(offset_a),
                                      container_b, NodeAsOffset(child_b),
                                      disconnected);
    }

    return ComparePositionsInternal(container_a, IntAsOffset(offset_a),
                                    container_b, IntAsOffset(offset_b),
                                    disconnected);
  }

 private:
  enum Result : int16_t {
    kAIsBeforeB = -1,
    kAIsEqualToB = 0,
    kAIsAfterB = 1,
  };

  // The wrapper class of `int` offset.
  class IntAsOffset {
    STACK_ALLOCATED();

   public:
    explicit IntAsOffset(int value) : value_(value) {}
    int Get() const { return value_; }

   private:
    int value_;
  };

  // The wrapper class of offset in `Node*` before position.
  class NodeAsOffset {
    STACK_ALLOCATED();

   public:
    explicit NodeAsOffset(const Node* value) : value_(value) {}
    const Node* Get() const { return value_; }

   private:
    const Node* value_;
  };

  // Returns
  //  -1 if `child_a` is before `child_b`
  //   0 if `child_a == child_b`
  //   1 if `child_a` is after `child_b`
  //    where
  //      * `child_a == Traversal::ChildAt(*container_a, offset_a)`
  //      * `child_b == Traversal::ChildAt(*container_a, offset_b)`
  // and set `disconnected` to true if `child_a` and `child_b` are in different
  // tree scopes.
  template <typename OffsetA, typename OffsetB>
  static int16_t ComparePositionsInternal(const Node* container_a,
                                          OffsetA offset_a,
                                          const Node* container_b,
                                          OffsetB offset_b,
                                          bool* disconnected) {
    DCHECK(container_a);
    DCHECK(container_b);

    if (disconnected)
      *disconnected = false;

    if (!container_a)
      return kAIsBeforeB;
    if (!container_b)
      return kAIsAfterB;

    // see DOM2 traversal & range section 2.5

    // Case 1: both points have the same container
    if (container_a == container_b)
      return CompareNodesInSameParent(offset_a.Get(), offset_b.Get());

    // Case 2: node C (container B or an ancestor) is a child node of A, e.g.
    //  * A < B
    //      `<a>...A...<c2>...<b>...B...</b>...</c2>...</a>`
    //  * A > B
    //      `<a>...<c2>...<b>...B...</b>...</c2>...A...</a>`
    //  * A == C2
    //             A
    //      `<a>...<c2>...<b>...B...</b>...</c2>...</a>`
    if (const Node* node_c2 =
            FindChildInAncestors(*container_b, *container_a)) {
      return CompareNodesInSameParent(
          offset_a.Get(), Traversal::PreviousSibling(*node_c2), kAIsBeforeB);
    }

    // Case 3: node C (container A or an ancestor) is a child node of B, e.g.
    //  * B < A
    //      `<b>...B....<c3>...<a>...A...</a>...</b>`
    //  * B > A
    //      `<b>...<c3>...<a>...A...</a>...</c3>...B...</b>`
    //  * B == C3
    //             B
    //      `<b>...<c3>...<a>...A...</a>...</b>`
    if (const Node* node_c3 =
            FindChildInAncestors(*container_a, *container_b)) {
      return -CompareNodesInSameParent(
          offset_b.Get(), Traversal::PreviousSibling(*node_c3), kAIsBeforeB);
    }

    // case 4: containers A & B are siblings, or children of siblings
    // ### we need to do a traversal here instead
    Node* const common_ancestor =
        Traversal::CommonAncestor(*container_a, *container_b);
    if (!common_ancestor) {
      if (disconnected)
        *disconnected = true;
      return kAIsEqualToB;
    }

    const Node* const child_a =
        FindChildInAncestors(*container_a, *common_ancestor);
    const Node* const adjusted_child_a =
        child_a ? child_a : Traversal::LastChild(*common_ancestor);
    const Node* const child_b =
        FindChildInAncestors(*container_b, *common_ancestor);
    const Node* const adjusted_child_b =
        child_b ? child_b : Traversal::LastChild(*common_ancestor);
    return CompareNodesInSameParent(adjusted_child_a, adjusted_child_b);
  }

  // Returns
  //  -1 if `offset_a < offset_b`
  //   0 if `offset_a == offset_b`
  //   1 if `offset_a > offset_b`
  //     where ```
  //        offset_b =  child_before_position_b
  //            ? Traversal::Index(*child_before_position_b) + 1
  //            : 0 ```
  // The number of iteration is `std::min(offset_a, offset_b)`.
  static Result CompareNodesInSameParent(
      int offset_a,
      const Node* child_before_position_b,
      Result result_of_a_is_equal_to_b = kAIsEqualToB) {
    if (!child_before_position_b)
      return !offset_a ? result_of_a_is_equal_to_b : kAIsAfterB;
    if (!offset_a)
      return kAIsBeforeB;
    // Starts from offset 1 and after `child_before_position_b`.
    const Node& child_b = *child_before_position_b;
    int offset = 1;
    for (const Node& child :
         Traversal::ChildrenOf(*Traversal::Parent(child_b))) {
      if (offset_a == offset)
        return child == child_b ? result_of_a_is_equal_to_b : kAIsBeforeB;
      if (child == child_b)
        return kAIsAfterB;
      ++offset;
    }
    NOTREACHED();
  }

  static int16_t CompareNodesInSameParent(
      int offset_a,
      int offset_b,
      Result result_of_a_is_equal_to_b = kAIsEqualToB) {
    if (offset_a == offset_b)
      return result_of_a_is_equal_to_b;
    return offset_a < offset_b ? kAIsBeforeB : kAIsAfterB;
  }

  static int16_t CompareNodesInSameParent(const Node* child_before_position_a,
                                          int offset_b) {
    return -CompareNodesInSameParent(offset_b, child_before_position_a);
  }

  // Returns
  //  -1 if `Traversal::Index(*child_a) < Traversal::Index(*child_b)`
  //   0 if `Traversal::Index(*child_a) == Traversal::Index(*child_b)`
  //   1 if `Traversal::Index(*child_a) > Traversal::Index(*child_b)`
  //  `child_a` and `child_b` should be in a same parent nod or `nullptr`.
  //
  //  When `child_a` < `child_b`. ```
  //                   child_a                           child_b
  ///   <-- backward_a --|-- forward_a --><-- backward_b --|-- forward_b -->
  //  |------------------+---------------------------------+----------------|
  //  ```
  //  When `child_a` > `child_b`. ```
  //                   child_b                           child_a
  ///   <-- backward_b --|-- forward_b --><-- backward_a --|-- forward_a -->
  //  |------------------+---------------------------------+----------------|
  //  ```
  //
  //  The number of iterations is: ```
  //    std::min(offset_a, offset_b,
  //             abs(offset_a - offset_b) / 2,
  //             number_of_children - offset_a,
  //             number_of_children - offset_b)
  //  where
  //    `offset_a` == `Traversal::Index(*child_a)`
  //    `offset_b` == `Traversal::Index(*child_b)`
  //
  //  ```
  // Note: this number can't exceed `number_of_children / 4`.
  //
  // Note: We call this function both "node before position" and "node after
  // position" cases. For "node after position" case, `child_a` and `child_b`
  // should not be `nullptr`.
  static int16_t CompareNodesInSameParent(
      const Node* child_a,
      const Node* child_b,
      Result result_of_a_is_equal_to_b = kAIsEqualToB) {
    if (child_a == child_b)
      return result_of_a_is_equal_to_b;
    if (!child_a)
      return kAIsBeforeB;
    if (!child_b)
      return kAIsAfterB;
    DCHECK_EQ(Traversal::Parent(*child_a), Traversal::Parent(*child_b));
    const Node* backward_a = child_a;
    const Node* forward_a = child_a;
    const Node* backward_b = child_b;
    const Node* forward_b = child_b;

    for (;;) {
      backward_a = Traversal::PreviousSibling(*backward_a);
      if (!backward_a)
        return kAIsBeforeB;
      if (backward_a == forward_b)
        return kAIsAfterB;

      forward_a = Traversal::NextSibling(*forward_a);
      if (!forward_a)
        return kAIsAfterB;
      if (forward_a == backward_b)
        return kAIsBeforeB;

      backward_b = Traversal::PreviousSibling(*backward_b);
      if (!backward_b)
        return kAIsAfterB;
      if (forward_a == backward_b)
        return kAIsBeforeB;

      forward_b = Traversal::NextSibling(*forward_b);
      if (!forward_b)
        return kAIsBeforeB;
      if (backward_a == forward_b)
        return kAIsAfterB;
    }

    NOTREACHED();
  }

  // Returns the child node in `parent` if `parent` is one of inclusive
  // ancestors of `node`, otherwise `nullptr`.
  // See https://dom.spec.whatwg.org/#boundary-points
  static const Node* FindChildInAncestors(const Node& node,
                                          const Node& parent) {
    DCHECK_NE(node, parent);
    const Node* candidate = &node;
    for (const Node& child : Traversal::AncestorsOf(node)) {
      if (child == parent)
        return candidate;
      candidate = &child;
    }
    return nullptr;
  }
};

}  // namespace

int16_t ComparePositionsInDOMTree(const Node* container_a,
                                  int offset_a,
                                  const Node* container_b,
                                  int offset_b,
                                  bool* disconnected) {
  return Comparator<NodeTraversal>::ComparePositions(
      container_a, offset_a, container_b, offset_b, disconnected);
}

int16_t ComparePositionsInFlatTree(const Node* container_a,
                                   int offset_a,
                                   const Node* container_b,
                                   int offset_b,
                                   bool* disconnected) {
  if (container_a->IsShadowRoot()) {
    container_a = container_a->OwnerShadowHost();
  }
  if (container_b->IsShadowRoot()) {
    container_b = container_b->OwnerShadowHost();
  }
  return Comparator<FlatTreeTraversal>::ComparePositions(
      container_a, offset_a, container_b, offset_b, disconnected);
}

int16_t ComparePositions(const Position& position_a,
                         const Position& position_b) {
  DCHECK(position_a.IsNotNull());
  DCHECK(position_b.IsNotNull());

  const TreeScope* common_scope =
      Position::CommonAncestorTreeScope(position_a, position_b);

  DCHECK(common_scope);
  if (!common_scope)
    return 0;

  Node* const container_a = position_a.ComputeContainerNode();
  Node* const node_a = common_scope->AncestorInThisScope(container_a);
  DCHECK(node_a);
  const bool has_descendant_a = node_a != container_a;

  Node* const container_b = position_b.ComputeContainerNode();
  Node* const node_b = common_scope->AncestorInThisScope(container_b);
  DCHECK(node_b);
  const bool has_descendant_b = node_b != container_b;

  const int offset_a = position_a.IsOffsetInAnchor() && !has_descendant_a
                           ? position_a.OffsetInContainerNode()
                           : kInvalidOffset;

  const int offset_b = position_b.IsOffsetInAnchor() && !has_descendant_b
                           ? position_b.OffsetInContainerNode()
                           : kInvalidOffset;

  Node* const child_a = position_a.IsOffsetInAnchor() || has_descendant_a
                            ? nullptr
                            : position_a.ComputeNodeBeforePosition();

  Node* const child_b = position_b.IsOffsetInAnchor() || has_descendant_b
                            ? nullptr
                            : position_b.ComputeNodeBeforePosition();

  const int16_t bias = node_a != node_b   ? 0
                       : has_descendant_a ? 1
                       : has_descendant_b ? -1
                                          : 0;

  const int16_t result = Comparator<NodeTraversal>::ComparePositions(
      node_a, offset_a, child_a, node_b, offset_b, child_b);
  return result ? result : bias;
}

int16_t ComparePositions(const PositionWithAffinity& a,
                         const PositionWithAffinity& b) {
  return ComparePositions(a.GetPosition(), b.GetPosition());
}

int16_t ComparePositions(const VisiblePosition& a, const VisiblePosition& b) {
  return ComparePositions(a.DeepEquivalent(), b.DeepEquivalent());
}

int16_t ComparePositions(const PositionInFlatTree& position_a,
                         const PositionInFlatTree& position_b) {
  DCHECK(position_a.IsNotNull());
  DCHECK(position_b.IsNotNull());

  Node* const container_a = position_a.ComputeContainerNode();
  Node* const container_b = position_b.ComputeContainerNode();

  const int offset_a = position_a.IsOffsetInAnchor()
                           ? position_a.OffsetInContainerNode()
                           : kInvalidOffset;

  const int offset_b = position_b.IsOffsetInAnchor()
                           ? position_b.OffsetInContainerNode()
                           : kInvalidOffset;

  Node* const child_a = position_a.IsOffsetInAnchor()
                            ? nullptr
                            : position_a.ComputeNodeBeforePosition();

  Node* const child_b = position_b.IsOffsetInAnchor()
                            ? nullptr
                            : position_b.ComputeNodeBeforePosition();

  return Comparator<FlatTreeTraversal>::ComparePositions(
      container_a, offset_a, child_a, container_b, offset_b, child_b);
}

}  // namespace blink

"""

```