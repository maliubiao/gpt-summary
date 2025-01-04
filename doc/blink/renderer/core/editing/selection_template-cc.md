Response:
Let's break down the thought process for analyzing the `selection_template.cc` file.

**1. Understanding the Core Purpose:**

The first step is to recognize the file name: `selection_template.cc`. The `template` suffix strongly suggests this is a generic class definition. The `selection` part clearly indicates it deals with text/content selection within a web page. The path `blink/renderer/core/editing/` further confirms it's a core part of the Blink rendering engine, specifically related to editing functionalities.

**2. Identifying Key Components:**

Scanning the code reveals several important elements:

* **Template Parameter `<typename Strategy>`:** This immediately tells us it's a template class, designed to work with different "strategies" for how selections are handled. This likely relates to the DOM tree vs. the flat tree representation in Blink.
* **Member Variables:** `anchor_`, `focus_`, `affinity_`, `direction_`. These are the fundamental data points representing a selection. The names are quite descriptive.
* **Constructors, Assignment Operator:**  Standard C++ practices for creating and copying objects.
* **Comparison Operators (`==`, `!=`):** Essential for comparing selections.
* **`Trace()`:**  Indicates this class is part of Blink's garbage collection or object lifecycle management.
* **Accessors (`Anchor()`, `Focus()`, `GetDocument()`):**  Provide ways to get information about the selection.
* **Predicates (`IsCaret()`, `IsRange()`, `IsValidFor()`):**  Functions that return boolean values indicating the state of the selection.
* **Assertions (`DCHECK`, `AssertValid()`):** Debugging aids to ensure internal consistency.
* **`ComputeStartPosition()`, `ComputeEndPosition()`, `ComputeRange()`:**  Methods to derive related information from the anchor and focus.
* **`IsAnchorFirst()`:** Determines the direction of the selection.
* **`ResetDirectionCache()`:** Optimizes the direction calculation.
* **`PrintTo()` and `operator<<`:** For debugging output.
* **Nested `Builder` Class:** A common design pattern for constructing complex objects.
* **Nested `InvalidSelectionResetter` Class:**  A mechanism to ensure selections remain valid even if the underlying DOM changes.
* **Free Functions (`ConvertToSelectionInDOMTree`, `ConvertToSelectionInFlatTree`):**  Conversion functions between different selection representations.
* **Explicit Template Instantiations:**  `template class CORE_TEMPLATE_EXPORT SelectionTemplate<EditingStrategy>;` and `template class CORE_TEMPLATE_EXPORT SelectionTemplate<EditingInFlatTreeStrategy>;` confirm the two specific strategies used.

**3. Deducing Functionality from Components:**

Based on the identified components, we can start inferring the functionality:

* **Core Data Structure for Selections:** The `SelectionTemplate` class clearly represents a selection, storing its start (`anchor_`), end (`focus_`), direction, and affinity.
* **Abstraction over Selection Strategies:** The template parameter allows the same core logic to work with different ways of representing the document structure (DOM tree vs. flat tree).
* **Maintaining Selection Validity:**  The `AssertValid()` and `InvalidSelectionResetter` suggest a focus on ensuring selections remain consistent even as the DOM changes.
* **Manipulating Selections:** The `Builder` class provides a fluent interface for creating and modifying selections (collapsing, extending, setting base/extent, etc.).
* **Information Retrieval:** The accessor and predicate methods allow querying the state and properties of a selection.
* **Conversion Between Representations:**  The conversion functions facilitate interoperability between different selection strategies.

**4. Connecting to JavaScript, HTML, and CSS:**

Now we need to bridge the gap between this C++ code and web technologies:

* **JavaScript:**  JavaScript interacts with selections through the `Selection` API. The C++ `SelectionTemplate` is the underlying implementation for how Blink handles these selections. User actions in JavaScript like `window.getSelection()` or manipulating the selection programmatically ultimately interact with this C++ code.
* **HTML:** HTML provides the content that selections operate on. The `SelectionTemplate` stores positions *within* the HTML structure.
* **CSS:** While CSS doesn't directly manipulate selections, it can *style* them (e.g., the highlight color). The C++ code needs to be aware of the DOM structure that CSS is applied to.

**5. Illustrative Examples and Reasoning:**

At this point, concrete examples are crucial for clarity. We can imagine scenarios:

* **User Double-Clicking (JavaScript):** This triggers a JavaScript event. The browser's event handling will call into Blink, which will use the `SelectionTemplate` to create a range selecting the word.
* **`document.getSelection().toString()` (JavaScript):** This JavaScript code will eventually call into the C++ layer, where the `SelectionTemplate`'s `ComputeRange()` or similar methods will be used to determine the selected text.
* **Programmatic Selection with `document.createRange()` (JavaScript):**  JavaScript creates a `Range` object. When this range is used to set the document's selection, Blink will use the `SelectionTemplate` to represent this new selection.

**6. Common User/Programming Errors:**

Think about common mistakes related to selections:

* **Assuming Selection Always Exists:**  A user might try to get the selection when nothing is selected. The `IsNone()` check in the C++ code is relevant here.
* **Manipulating Selections After DOM Changes:** The `InvalidSelectionResetter` handles cases where the DOM is modified while a selection exists, potentially making the selection invalid. A programmer might make changes to the DOM and forget to update or clear the selection.
* **Incorrectly Setting Anchor and Focus:**  A programmer might set the anchor and focus in the wrong order, leading to unexpected selection behavior. The `IsAnchorFirst()` and the builder's logic address this.

**7. Debugging Walkthrough:**

Consider how a developer might end up looking at this file:

* **Bug Report:** A user reports an issue with text selection on a particular website.
* **Blink Developer Investigation:** A Blink developer investigates the bug. They might trace the selection logic through JavaScript calls and eventually reach the C++ implementation in `selection_template.cc`.
* **Debugging Tools:**  They would use debuggers to step through the C++ code, inspect the values of `anchor_`, `focus_`, etc., and understand how the selection is being represented and manipulated.

**8. Refinement and Organization:**

Finally, organize the information into a clear and structured response, covering all the requested points. Use clear headings and bullet points for readability. Ensure the examples are concrete and easy to understand. Double-check for accuracy and completeness.
This C++ file, `selection_template.cc`, defines a template class named `SelectionTemplate` within the Chromium Blink rendering engine. This class serves as a fundamental building block for representing and manipulating text selections within a web page. The template nature allows it to work with different strategies for representing the document structure, such as the standard DOM tree or a flattened tree representation.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Represents a Text Selection:** The primary purpose of `SelectionTemplate` is to hold the essential information defining a text selection. This includes:
    * **Anchor Point (`anchor_`):** The starting point of the selection.
    * **Focus Point (`focus_`):** The ending point of the selection.
    * **Affinity (`affinity_`):**  Indicates whether the selection leans towards the start or end of a node when the anchor or focus is at a boundary.
    * **Direction (`direction_`):**  Indicates the direction of the selection (forward or backward). This is often lazily computed.

2. **Provides Methods for Querying Selection Properties:**  It offers methods to determine various characteristics of the selection:
    * `IsCaret()`: Checks if the selection is a caret (anchor and focus are the same).
    * `IsRange()`: Checks if the selection is a range (anchor and focus are different).
    * `IsValidFor(const Document& document)`: Checks if the selection's anchor and focus points are still valid within the given document.
    * `IsAnchorFirst()`: Determines if the anchor point comes before the focus point in the document order.
    * `ComputeStartPosition()` and `ComputeEndPosition()`:  Returns the start and end positions of the selection, respecting the selection direction.
    * `ComputeRange()`: Returns an `EphemeralRangeTemplate` representing the selected range.

3. **Supports Copying and Comparison:** It implements copy constructors and comparison operators (`==`, `!=`) to allow for easy duplication and comparison of selection objects.

4. **Includes Assertions and Debugging Aids:**  The code heavily utilizes `DCHECK` (Debug Check) to ensure internal consistency and identify potential errors during development. The `AssertValid()` method performs various checks to validate the selection's state. There are also debugging output methods like `PrintTo` and the overloaded `operator<<`.

5. **Provides a Builder Class:** The nested `Builder` class provides a convenient and fluent interface for constructing and modifying `SelectionTemplate` objects. This allows setting the anchor, focus, and other properties in a structured way.

6. **Offers a Mechanism for Invalidating Selections:** The nested `InvalidSelectionResetter` class is a RAII (Resource Acquisition Is Initialization) helper. It checks if the selection is still valid within its document upon destruction. If not, it resets the selection to a "none" state. This is crucial for handling scenarios where the underlying DOM structure changes.

7. **Supports Different Tree Representations:**  The template parameter `<typename Strategy>` indicates that `SelectionTemplate` can be used with different strategies for traversing and representing the document structure. The code shows explicit instantiation for `EditingStrategy` (likely the standard DOM tree) and `EditingInFlatTreeStrategy` (a flattened representation used for performance optimizations).

**Relationship with JavaScript, HTML, and CSS:**

`SelectionTemplate` is a core part of the Blink rendering engine and directly underpins the selection functionality exposed to JavaScript through the **Selection API**.

* **JavaScript:**
    * **`window.getSelection()`:** When JavaScript calls `window.getSelection()`, it retrieves a `Selection` object. Internally, this JavaScript object relies on a `SelectionTemplate` instance in the C++ layer to represent the current selection.
    * **`document.getSelection().anchorNode`, `document.getSelection().focusNode`, `document.getSelection().anchorOffset`, `document.getSelection().focusOffset`:** These JavaScript properties correspond directly to the `anchor_` and `focus_` members of the `SelectionTemplate`.
    * **`document.getSelection().toString()`:** When you get the text content of a selection, the underlying `SelectionTemplate`'s `ComputeRange()` and related methods are used to determine the boundaries of the selected text within the DOM.
    * **`document.getSelection().collapse(node, offset)`, `document.getSelection().extend(node, offset)`, `document.getSelection().setBaseAndExtent(anchorNode, anchorOffset, focusNode, focusOffset)`:** These JavaScript methods directly manipulate the properties of the underlying `SelectionTemplate` object, often using the `Builder` class.

    **Example:**  Imagine a user selects some text on a webpage. When JavaScript calls `window.getSelection()`, Blink will retrieve or create a `SelectionTemplate` object. If the user then calls `document.getSelection().toString()`, the C++ code in `selection_template.cc` (specifically methods like `ComputeRange`) will be involved in determining the text within the selected range based on the current `anchor_` and `focus_`.

* **HTML:**
    * The `SelectionTemplate` operates on the structure of the HTML document. The `anchor_` and `focus_` points refer to specific locations within the HTML tree (nodes and offsets).
    * The `IsValidFor` method checks if the selection points are still valid within the current HTML document, especially important after DOM manipulations.

    **Example:**  If a user selects text spanning across multiple HTML elements (e.g., a `<p>` and a `<span>`), the `SelectionTemplate` will store the anchor and focus positions pointing to specific locations within those elements in the HTML structure.

* **CSS:**
    * CSS can style the appearance of selections (e.g., the background color of selected text using the `::selection` pseudo-element).
    * While CSS doesn't directly manipulate the selection points, the rendering engine uses the information from `SelectionTemplate` to determine which parts of the HTML content should be styled as selected.

    **Example:**  When the browser renders the webpage, it uses the `SelectionTemplate` to identify the nodes and offsets that fall within the selected range. Then, it applies the CSS styles defined for the `::selection` pseudo-element to those specific parts of the rendered output.

**Logical Reasoning with Assumptions and Outputs:**

Let's consider a scenario where a user double-clicks on a word in a paragraph:

**Assumed Input:**

1. **User Action:** Double-click on a word within a `<p>` element in the HTML.
2. **Current Selection:** Initially, there might be no selection or a different selection.
3. **DOM Structure:** The `<p>` element contains text nodes and potentially other inline elements.

**Logical Steps (within `selection_template.cc` and related code):**

1. **Event Handling:** The browser detects the double-click event.
2. **Hit Testing:** The browser determines the exact location of the double-click within the DOM tree.
3. **Word Boundary Detection:**  Logic (likely in other files but interacting with position concepts used by `SelectionTemplate`) identifies the boundaries of the word that was double-clicked.
4. **`SelectionTemplate::Builder` Usage:**  A `SelectionTemplate::Builder` instance is created.
5. **Setting Anchor and Focus:** The builder's `Collapse()` method might be called to set both the anchor and focus to the start of the identified word. Then, the `Extend()` method is called to move the focus to the end of the word, creating a range selection.
6. **Building the `SelectionTemplate`:** The `Build()` method of the builder is called to create the final `SelectionTemplate` object representing the word selection.
7. **Updating the Document's Selection:** The newly created `SelectionTemplate` is set as the current selection for the document.

**Output (represented by the `SelectionTemplate` object):**

* **`anchor_`:** A `PositionTemplate` pointing to the beginning of the double-clicked word.
* **`focus_`:** A `PositionTemplate` pointing to the end of the double-clicked word.
* **`affinity_`:**  Likely `TextAffinity::kDownstream` or `TextAffinity::kUpstream` depending on the specific implementation details of word boundary detection.
* **`direction_`:**  `Direction::kForward`.
* **`IsRange()`:** `true`.

**Common User or Programming Usage Errors:**

1. **Manipulating Selections After DOM Changes:**
   * **User Error:** A user might perform an action that modifies the DOM (e.g., editing a text field) while a selection exists. If the selected content is removed or significantly altered, the selection might become invalid. The `InvalidSelectionResetter` is designed to handle this gracefully by resetting the selection.
   * **Programming Error (JavaScript):**  A developer might write JavaScript code that modifies the DOM and then attempts to use a previously obtained `Selection` object without checking if it's still valid. This could lead to unexpected behavior or errors.

   **Example:**
   ```javascript
   let selection = window.getSelection();
   let selectedText = selection.toString();

   // ... some code that modifies the DOM, potentially removing the selectedText ...

   console.log(selection.toString()); // Might be empty or unexpected if the DOM changed.
   ```

2. **Incorrectly Setting Anchor and Focus Programmatically (JavaScript):**
   * **Programming Error:** A developer might use `selection.setBaseAndExtent()` with the anchor and focus nodes and offsets in the wrong order, leading to a selection that appears to be going in the opposite direction or selects the wrong content.

   **Example:**
   ```javascript
   let range = document.createRange();
   let startNode = document.getElementById('start');
   let endNode = document.getElementById('end');
   range.setStart(endNode, 0); // Intentionally setting end as start
   range.setEnd(startNode, 0);   // Intentionally setting start as end

   window.getSelection().removeAllRanges();
   window.getSelection().addRange(range); // Might result in an unexpected selection.
   ```

**User Operation Steps to Reach This Code (as a debugging line):**

Imagine a scenario where a web developer is debugging an issue related to text selection:

1. **User Reports a Bug:** A user reports that selecting text on a specific webpage is behaving incorrectly (e.g., selecting the wrong range, not selecting anything, or causing crashes).
2. **Developer Starts Debugging:** The developer opens the browser's developer tools and starts investigating the issue.
3. **Suspecting Selection Logic:** Based on the bug report, the developer suspects that the problem might lie in the core selection logic of the browser.
4. **Examining JavaScript:** The developer might start by examining the JavaScript code on the webpage that interacts with the `Selection` API. They might set breakpoints in the JavaScript code to see how the selection is being manipulated.
5. **Tracing into Browser Internals:** If the JavaScript code seems correct, the developer might need to delve deeper into the browser's rendering engine. They might use browser-specific debugging tools or build a debug version of Chromium.
6. **Setting Breakpoints in C++:**  Knowing that `SelectionTemplate` is a core class for handling selections, the developer might set breakpoints within the `selection_template.cc` file. They might target specific methods like:
   * The constructor of `SelectionTemplate`.
   * Methods of the `Builder` class (e.g., `Collapse`, `Extend`, `Build`).
   * Comparison operators (`operator==`).
   * Methods that compute the selection range (`ComputeRange`).
7. **Reproducing the Bug:** The developer then tries to reproduce the user's bug in the debug environment.
8. **Stepping Through the Code:** When the breakpoints are hit, the developer can step through the C++ code in `selection_template.cc`, inspecting the values of the `anchor_`, `focus_`, and other members to understand how the selection is being represented and manipulated at the lowest level.
9. **Analyzing the Call Stack:** The developer can also examine the call stack to see how the execution reached the `SelectionTemplate` code, tracing back from JavaScript calls or internal browser events.

By following these steps, a developer can pinpoint the exact point in the `selection_template.cc` code where the selection logic might be going wrong, helping them diagnose and fix the bug.

Prompt: 
```
这是目录为blink/renderer/core/editing/selection_template.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/selection_template.h"

#include <ostream>

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"

namespace blink {

template <typename Strategy>
SelectionTemplate<Strategy>::SelectionTemplate(const SelectionTemplate& other)
    : anchor_(other.anchor_),
      focus_(other.focus_),
      affinity_(other.affinity_),
      direction_(other.direction_)
#if DCHECK_IS_ON()
      ,
      dom_tree_version_(other.dom_tree_version_)
#endif
{
  DCHECK(other.AssertValid());
}

template <typename Strategy>
SelectionTemplate<Strategy>::SelectionTemplate() = default;

template <typename Strategy>
bool SelectionTemplate<Strategy>::operator==(
    const SelectionTemplate& other) const {
  DCHECK(AssertValid());
  DCHECK(other.AssertValid());
  if (IsNone())
    return other.IsNone();
  if (other.IsNone())
    return false;
  DCHECK_EQ(anchor_.GetDocument(), other.GetDocument())
      << *this << ' ' << other;
  return anchor_ == other.anchor_ && focus_ == other.focus_ &&
         affinity_ == other.affinity_;
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::operator!=(
    const SelectionTemplate& other) const {
  return !operator==(other);
}

template <typename Strategy>
void SelectionTemplate<Strategy>::Trace(Visitor* visitor) const {
  visitor->Trace(anchor_);
  visitor->Trace(focus_);
}

template <typename Strategy>
const PositionTemplate<Strategy>& SelectionTemplate<Strategy>::Anchor() const {
  DCHECK(AssertValid());
  DCHECK(!anchor_.IsOrphan()) << anchor_;
  return anchor_;
}

template <typename Strategy>
Document* SelectionTemplate<Strategy>::GetDocument() const {
  DCHECK(AssertValid());
  return anchor_.GetDocument();
}

template <typename Strategy>
const PositionTemplate<Strategy>& SelectionTemplate<Strategy>::Focus() const {
  DCHECK(AssertValid());
  DCHECK(!focus_.IsOrphan()) << focus_;
  return focus_;
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::IsCaret() const {
  return anchor_.IsNotNull() && anchor_ == focus_;
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::IsRange() const {
  return anchor_ != focus_;
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::IsValidFor(const Document& document) const {
  if (IsNone())
    return true;
  return anchor_.IsValidFor(document) && focus_.IsValidFor(document);
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::AssertValidFor(
    const Document& document) const {
  if (!AssertValid())
    return false;
  if (anchor_.IsNull()) {
    return true;
  }
  DCHECK_EQ(anchor_.GetDocument(), document) << *this;
  return true;
}

#if DCHECK_IS_ON()
template <typename Strategy>
bool SelectionTemplate<Strategy>::AssertValid() const {
  if (anchor_.IsNull()) {
    return true;
  }
  DCHECK_EQ(anchor_.GetDocument()->DomTreeVersion(), dom_tree_version_)
      << *this;
  DCHECK(!anchor_.IsOrphan()) << *this;
  DCHECK(!focus_.IsOrphan()) << *this;
  DCHECK_EQ(anchor_.GetDocument(), focus_.GetDocument());
  return true;
}
#else
template <typename Strategy>
bool SelectionTemplate<Strategy>::AssertValid() const {
  return true;
}
#endif

#if DCHECK_IS_ON()
template <typename Strategy>
void SelectionTemplate<Strategy>::ShowTreeForThis() const {
  if (anchor_.IsNull()) {
    LOG(INFO) << "\nanchor is null";
    return;
  }

  LOG(INFO) << "\n"
            << anchor_.AnchorNode()
                   ->ToMarkedTreeString(anchor_.AnchorNode(), "B",
                                        focus_.AnchorNode(), "E")
                   .Utf8()
            << "anchor: " << anchor_.ToAnchorTypeAndOffsetString().Utf8()
            << "\n"
            << "focus: " << focus_.ToAnchorTypeAndOffsetString().Utf8();
}
#endif

template <typename Strategy>
const PositionTemplate<Strategy>&
SelectionTemplate<Strategy>::ComputeEndPosition() const {
  return IsAnchorFirst() ? focus_ : anchor_;
}

template <typename Strategy>
const PositionTemplate<Strategy>&
SelectionTemplate<Strategy>::ComputeStartPosition() const {
  return IsAnchorFirst() ? anchor_ : focus_;
}

template <typename Strategy>
EphemeralRangeTemplate<Strategy> SelectionTemplate<Strategy>::ComputeRange()
    const {
  return EphemeralRangeTemplate<Strategy>(ComputeStartPosition(),
                                          ComputeEndPosition());
}

template <typename Strategy>
bool SelectionTemplate<Strategy>::IsAnchorFirst() const {
  DCHECK(AssertValid());
  if (anchor_ == focus_) {
    DCHECK_EQ(direction_, Direction::kForward);
    return true;
  }
  if (direction_ == Direction::kForward) {
    DCHECK_LE(anchor_, focus_);
    return true;
  }
  if (direction_ == Direction::kBackward) {
    DCHECK_GT(anchor_, focus_);
    return false;
  }
  // Note: Since same position can be represented in different anchor type,
  // e.g. Position(div, 0) and BeforeNode(first-child), we use |<=| to check
  // forward selection.
  DCHECK_EQ(direction_, Direction::kNotComputed);
  direction_ = anchor_ <= focus_ ? Direction::kForward : Direction::kBackward;
  return direction_ == Direction::kForward;
}

template <typename Strategy>
void SelectionTemplate<Strategy>::ResetDirectionCache() const {
  direction_ =
      anchor_ == focus_ ? Direction::kForward : Direction::kNotComputed;
}

template <typename Strategy>
void SelectionTemplate<Strategy>::PrintTo(std::ostream* ostream,
                                          const char* type) const {
  if (IsNone()) {
    *ostream << "()";
    return;
  }
  *ostream << type << '(';
#if DCHECK_IS_ON()
  if (dom_tree_version_ != anchor_.GetDocument()->DomTreeVersion()) {
    *ostream << "Dirty: " << dom_tree_version_;
    *ostream << " != " << anchor_.GetDocument()->DomTreeVersion() << ' ';
  }
#endif
  *ostream << "anchor: " << anchor_ << ", focus: " << focus_ << ')';
}

std::ostream& operator<<(std::ostream& ostream,
                         const SelectionInDOMTree& selection) {
  selection.PrintTo(&ostream, "Selection");
  return ostream;
}

std::ostream& operator<<(std::ostream& ostream,
                         const SelectionInFlatTree& selection) {
  selection.PrintTo(&ostream, "SelectionInFlatTree");
  return ostream;
}

// --

template <typename Strategy>
SelectionTemplate<Strategy>::Builder::Builder(
    const SelectionTemplate<Strategy>& selection)
    : selection_(selection) {}

template <typename Strategy>
SelectionTemplate<Strategy>::Builder::Builder() = default;

template <typename Strategy>
SelectionTemplate<Strategy> SelectionTemplate<Strategy>::Builder::Build()
    const {
  DCHECK(selection_.AssertValid());
  if (selection_.direction_ == Direction::kBackward) {
    DCHECK_LE(selection_.focus_, selection_.anchor_);
    return selection_;
  }
  if (selection_.direction_ == Direction::kForward) {
    if (selection_.IsNone())
      return selection_;
    DCHECK_LE(selection_.anchor_, selection_.focus_);
    return selection_;
  }
  DCHECK_EQ(selection_.direction_, Direction::kNotComputed);
  selection_.ResetDirectionCache();
  return selection_;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::Collapse(
    const PositionTemplate<Strategy>& position) {
  DCHECK(position.IsConnected()) << position;
  selection_.anchor_ = position;
  selection_.focus_ = position;
#if DCHECK_IS_ON()
  selection_.dom_tree_version_ = position.GetDocument()->DomTreeVersion();
#endif
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::Collapse(
    const PositionWithAffinityTemplate<Strategy>& position_with_affinity) {
  Collapse(position_with_affinity.GetPosition());
  SetAffinity(position_with_affinity.Affinity());
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::Extend(
    const PositionTemplate<Strategy>& position) {
  DCHECK(position.IsConnected()) << position;
  DCHECK_EQ(selection_.GetDocument(), position.GetDocument());
  DCHECK(selection_.Anchor().IsConnected()) << selection_.Anchor();
  DCHECK(selection_.AssertValid());
  if (selection_.focus_.IsEquivalent(position)) {
    return *this;
  }
  selection_.focus_ = position;
  selection_.direction_ = Direction::kNotComputed;
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SelectAllChildren(const Node& node) {
  DCHECK(node.CanContainRangeEndPoint()) << node;
  return SetBaseAndExtent(
      EphemeralRangeTemplate<Strategy>::RangeOfContents(node));
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetAffinity(TextAffinity affinity) {
  selection_.affinity_ = affinity;
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetAsBackwardSelection(
    const EphemeralRangeTemplate<Strategy>& range) {
  DCHECK(range.IsNotNull());
  DCHECK(!range.IsCollapsed());
  DCHECK(selection_.IsNone()) << selection_;
  selection_.anchor_ = range.EndPosition();
  selection_.focus_ = range.StartPosition();
  selection_.direction_ = Direction::kBackward;
  DCHECK_GT(selection_.anchor_, selection_.focus_);
#if DCHECK_IS_ON()
  selection_.dom_tree_version_ = range.GetDocument().DomTreeVersion();
#endif
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetAsForwardSelection(
    const EphemeralRangeTemplate<Strategy>& range) {
  DCHECK(range.IsNotNull());
  DCHECK(selection_.IsNone()) << selection_;
  selection_.anchor_ = range.StartPosition();
  selection_.focus_ = range.EndPosition();
  selection_.direction_ = Direction::kForward;
  DCHECK_LE(selection_.anchor_, selection_.focus_);
#if DCHECK_IS_ON()
  selection_.dom_tree_version_ = range.GetDocument().DomTreeVersion();
#endif
  return *this;
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetBaseAndExtent(
    const EphemeralRangeTemplate<Strategy>& range) {
  if (range.IsNull()) {
    selection_.anchor_ = PositionTemplate<Strategy>();
    selection_.focus_ = PositionTemplate<Strategy>();
#if DCHECK_IS_ON()
    selection_.dom_tree_version_ = 0;
#endif
    return *this;
  }
  return SetAsForwardSelection(range);
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetBaseAndExtent(
    const PositionTemplate<Strategy>& base,
    const PositionTemplate<Strategy>& extent) {
  if (base.IsNull()) {
    DCHECK(extent.IsNull()) << extent;
    return SetBaseAndExtent(EphemeralRangeTemplate<Strategy>());
  }
  // TODO(crbug.com/1423127): `extent` is not expected to be `IsNull` but it
  // looks like there are such cases.
  return Collapse(base).Extend(extent);
}

template <typename Strategy>
typename SelectionTemplate<Strategy>::Builder&
SelectionTemplate<Strategy>::Builder::SetBaseAndExtentDeprecated(
    const PositionTemplate<Strategy>& base,
    const PositionTemplate<Strategy>& extent) {
  if (base.IsNotNull() && extent.IsNotNull()) {
    return SetBaseAndExtent(base, extent);
  }
  if (base.IsNotNull())
    return Collapse(base);
  if (extent.IsNotNull())
    return Collapse(extent);
  return SetBaseAndExtent(EphemeralRangeTemplate<Strategy>());
}

// ---

template <typename Strategy>
SelectionTemplate<Strategy>::InvalidSelectionResetter::InvalidSelectionResetter(
    const SelectionTemplate<Strategy>& selection)
    : document_(selection.GetDocument()),
      selection_(const_cast<SelectionTemplate&>(selection)) {
  DCHECK(selection_.AssertValid());
}

template <typename Strategy>
SelectionTemplate<
    Strategy>::InvalidSelectionResetter::~InvalidSelectionResetter() {
  if (selection_.IsNone())
    return;
  DCHECK(document_);
  if (!selection_.IsValidFor(*document_)) {
    selection_ = SelectionTemplate<Strategy>();
    return;
  }
#if DCHECK_IS_ON()
  selection_.dom_tree_version_ = document_->DomTreeVersion();
#endif
  selection_.ResetDirectionCache();
}

SelectionInDOMTree ConvertToSelectionInDOMTree(
    const SelectionInFlatTree& selection_in_flat_tree) {
  return SelectionInDOMTree::Builder()
      .SetAffinity(selection_in_flat_tree.Affinity())
      .SetBaseAndExtent(ToPositionInDOMTree(selection_in_flat_tree.Anchor()),
                        ToPositionInDOMTree(selection_in_flat_tree.Focus()))
      .Build();
}

SelectionInFlatTree ConvertToSelectionInFlatTree(
    const SelectionInDOMTree& selection) {
  SelectionInFlatTree::Builder builder;
  const PositionInFlatTree& anchor = ToPositionInFlatTree(selection.Anchor());
  const PositionInFlatTree& focus = ToPositionInFlatTree(selection.Focus());
  if (anchor.IsConnected() && focus.IsConnected()) {
    builder.SetBaseAndExtent(anchor, focus);
  } else if (anchor.IsConnected()) {
    builder.Collapse(anchor);
  } else if (focus.IsConnected()) {
    builder.Collapse(focus);
  }
  builder.SetAffinity(selection.Affinity());
  return builder.Build();
}

template <typename Strategy>
void SelectionTemplate<Strategy>::InvalidSelectionResetter::Trace(
    blink::Visitor* visitor) const {
  visitor->Trace(document_);
}

template class CORE_TEMPLATE_EXPORT SelectionTemplate<EditingStrategy>;
template class CORE_TEMPLATE_EXPORT
    SelectionTemplate<EditingInFlatTreeStrategy>;

}  // namespace blink

"""

```