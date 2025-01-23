Response:
Let's break down the thought process for analyzing this `xpath_step.cc` file.

1. **Understand the Context:** The first thing is to recognize that this is a Chromium Blink engine source file located in `blink/renderer/core/xml/`. This tells us it's dealing with XML processing within the web browser's rendering engine. The name `xpath_step.cc` strongly suggests it's related to the steps involved in evaluating XPath expressions.

2. **Identify Key Components:** Scan the file for important data structures and classes. We see:
    * `Step` class: This is the central class and likely represents a single step in an XPath expression.
    * `Axis` enum:  This clearly defines the directions of traversal in the XML tree (child, descendant, parent, etc.).
    * `NodeTest` class: This likely represents the criteria for selecting nodes at each step (e.g., node type, tag name, attributes).
    * `Predicate` class: These are conditions that filter the nodes selected by the `NodeTest`.
    * `EvaluationContext`:  This holds the state needed during the evaluation process.
    * `NodeSet`: This likely stores the collection of nodes resulting from a step evaluation.

3. **Analyze the `Step` Class:**  Focus on the methods of the `Step` class to understand its responsibilities:
    * Constructor:  Initializes the `Step` with an `Axis` and `NodeTest`, and optionally `Predicates`.
    * `Optimize()`:  Suggests a performance optimization by merging simple predicates into the `NodeTest`.
    * `OptimizeStepPair()`:  Looks for optimizations involving pairs of steps (like `//`). This is a significant optimization for common XPath patterns.
    * `PredicatesAreContextListInsensitive()`: Checks if predicates depend on the position or size of the current node list, which is important for optimization.
    * `Evaluate()`: The core method that takes a context node and returns the set of nodes matching the step.
    * `NodesInAxis()`:  A helper method within `Evaluate` that handles the actual traversal of the DOM tree based on the `Axis`.

4. **Trace Relationships with Web Technologies:** Consider how XPath relates to HTML, CSS, and JavaScript:
    * **JavaScript:** The most direct link is through the `document.evaluate()` method, which allows JavaScript code to execute XPath queries on the DOM.
    * **HTML:** XPath operates on the DOM tree, which is built from HTML. The code explicitly handles HTML documents and case-insensitive matching for HTML elements.
    * **CSS:** CSS Selectors and XPath share some similarities in their ability to select elements based on criteria. While not directly linked in this code, understanding the selection concepts helps grasp XPath's purpose.

5. **Logical Reasoning and Examples:**  Think about how the code works in practice:
    * **Input/Output:**  Imagine an XPath step like `/div[@id='myDiv']/p`. The input would be the root node, and the output would be the `<p>` elements that are children of the `<div>` with the ID "myDiv".
    * **Optimization:** The `OptimizeStepPair` function demonstrates a key optimization. Consider `//p`. This translates to `/descendant-or-self::node()/child::p`. The optimization converts this to `/descendant::p`, avoiding the intermediate creation of all nodes.

6. **Identify Potential Errors:** Think about common mistakes when using XPath:
    * **Incorrect Axis:** Choosing the wrong axis (e.g., `child` when `descendant` is needed).
    * **Case Sensitivity (XML vs. HTML):** Forgetting that XML is case-sensitive while HTML in many contexts is not. The code specifically handles this.
    * **Namespace Issues:**  Not correctly handling namespaces in XML documents.

7. **Debugging Scenario:**  Imagine a user reporting that an XPath query isn't working as expected. The steps to reach this code during debugging might be:
    * The JavaScript `document.evaluate()` function is called.
    * The browser's XPath engine parses the query.
    * The engine breaks the query down into steps, and this `xpath_step.cc` code is responsible for evaluating each step.
    * Setting breakpoints in `Evaluate()` or `NodesInAxis()` would be helpful to trace the execution and see which nodes are being selected.

8. **Structure the Explanation:**  Organize the findings into logical sections:
    * **Functionality:** Describe the core purpose of the file and the `Step` class.
    * **Relationships:** Explain how it connects to JavaScript, HTML, and CSS.
    * **Logic and Examples:** Illustrate the code's behavior with concrete examples and the optimization logic.
    * **User Errors:**  Highlight common mistakes users might make.
    * **Debugging:** Explain how a developer might end up in this code during debugging.

9. **Refine and Elaborate:** Review the explanation for clarity and completeness. Add more details where necessary. For example, explain the different `Axis` values, elaborate on the `NodeTest` types, and provide more specific examples of user errors.

This systematic approach, starting from understanding the context and drilling down into the code's details, allows for a comprehensive analysis of the `xpath_step.cc` file. The focus is not just on *what* the code does, but also *why* it does it and how it fits into the larger web development ecosystem.
This source code file `xpath_step.cc` within the Chromium Blink engine implements the functionality for evaluating a single step in an XPath expression. An XPath expression is broken down into a series of steps, and this file focuses on how to process one of those steps.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Represents an XPath Step:** The central class `Step` encapsulates all the information needed for a single step in an XPath query. This includes:
   - **Axis:**  The direction to traverse the DOM tree (e.g., `child`, `descendant`, `parent`, `attribute`).
   - **NodeTest:** Criteria for selecting nodes along the specified axis (e.g., element name, node type, namespace).
   - **Predicates:** Filtering conditions that further refine the set of nodes selected by the axis and node test.

2. **Evaluates a Step:** The `Evaluate` method is the core logic for executing an XPath step. It takes an `EvaluationContext` (which holds the current state of the evaluation), a `context` node (the starting point for the step), and a `NodeSet` (where the results are stored). It performs the following:
   - **Traverses the DOM:** Based on the `axis_`, it iterates through the relevant nodes relative to the `context` node (e.g., children, descendants, attributes).
   - **Applies Node Test:** For each node encountered during traversal, it checks if it matches the criteria defined in `node_test_`.
   - **Applies Predicates:** If a node passes the node test, it then evaluates the `predicates_`. Only nodes that satisfy all predicates are included in the result `NodeSet`.

3. **Optimizes Step Evaluation:** The `Optimize` and `OptimizeStepPair` methods implement performance optimizations:
   - **Predicate Merging:**  `Optimize` attempts to merge simple predicates directly into the `NodeTest`. This avoids building intermediate `NodeSet`s, improving efficiency. For example, instead of finding all "foo" elements and *then* filtering for those with a "bar" attribute, it can potentially check for the "bar" attribute while initially finding "foo" elements.
   - **`//` Optimization:** `OptimizeStepPair` specifically targets the common `//` pattern (descendant-or-self followed by child). It optimizes this to a direct `descendant` axis traversal, which is more efficient.

4. **Manages Node Sets:** It utilizes the `NodeSet` class to store and manipulate the collection of nodes resulting from the step evaluation.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This code is directly invoked when JavaScript code uses the `document.evaluate()` method to execute an XPath query. The JavaScript engine passes the XPath expression to the Blink rendering engine, which then uses classes like `Step` to process the query against the HTML DOM.

   **Example:**
   ```javascript
   let element = document.evaluate("//div[@id='myDiv']/p", document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
   ```
   In this example, the XPath expression `//div[@id='myDiv']/p` is evaluated. The Blink engine would create `Step` objects for each part of the path:
     - `//div[@id='myDiv']`: A `Step` with `descendant-or-self` axis, a node test for `div` elements, and a predicate checking for the `id` attribute.
     - `/p`: A `Step` with `child` axis and a node test for `p` elements.
   The `xpath_step.cc` code would be crucial in processing these steps.

* **HTML:** XPath operates on the HTML DOM (Document Object Model). The `NodesInAxis` method within `Step::Evaluate` directly interacts with the DOM structure (e.g., `firstChild()`, `nextSibling()`, `parentNode()`) to traverse the HTML elements and attributes. The code also handles HTML-specific nuances, such as case-insensitive matching for element names in HTML documents.

* **CSS:** While not a direct dependency, XPath shares the goal of selecting elements within a document, similar to CSS Selectors. However, XPath provides a more powerful and flexible way to navigate and select nodes in the DOM, including non-element nodes like attributes and text nodes. CSS is primarily for styling, while XPath is for querying and manipulating the document structure.

**Logical Reasoning and Examples:**

**Hypothetical Input and Output:**

Let's say the current step being evaluated is `/child::p[@class='important']` and the `context` node is a `div` element.

* **Input:**
    - `axis_`: `kChildAxis`
    - `node_test_`:  Matches `p` elements.
    - `predicates_`: A predicate that checks if the `class` attribute is equal to 'important'.
    - `context`: A `<div>` element in the DOM.

* **Output:**
    - A `NodeSet` containing all the direct child `<p>` elements of the `<div>` that have a `class` attribute equal to 'important'.

**Step-by-step Logic within `Evaluate` and `NodesInAxis`:**

1. `Evaluate` is called with the context and an empty `NodeSet`.
2. `NodesInAxis` is called with `kChildAxis`.
3. It iterates through the direct children of the `context` `<div>` element.
4. For each child:
   - `NodeMatchesBasicTest` checks if the child is a `<p>` element.
   - If it is a `<p>` element, the predicate (checking for `class='important'`) is evaluated.
   - If the predicate is true, the `<p>` element is added to the `NodeSet`.
5. After iterating through all children, the `NodeSet` containing the matching `<p>` elements is returned.

**User or Programming Common Usage Errors:**

1. **Incorrect Axis:**  Using the wrong axis can lead to unexpected results. For example, using `child::p` when intending to select any `<p>` element within a `div` (which requires `descendant::p`).

   **Example:**
   ```javascript
   // Assuming a div with nested p elements
   <div id="outer">
       <p>Direct child</p>
       <div><p>Nested child</p></div>
   </div>

   // Incorrect: Will only select the first <p>
   let p1 = document.evaluate("child::p", document.getElementById('outer'), null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

   // Correct: Will select both <p> elements
   let p2 = document.evaluate("descendant::p", document.getElementById('outer'), null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotItem(0);
   let p3 = document.evaluate("descendant::p", document.getElementById('outer'), null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotItem(1);
   ```

2. **Case Sensitivity in XML (but not always HTML):** XPath is case-sensitive for XML. However, when used with HTML in browsers, element names and attribute names are often treated case-insensitively. This can lead to confusion when transitioning between XML and HTML contexts.

   **Example (XML - would fail):**
   ```xml
   <Root><DIV id="myDiv"><p>Text</p></DIV></Root>
   ```
   `document.evaluate("//div[@Id='myDiv']/p", ...)` would fail because the attribute name is `Id`, not `id`.

3. **Namespace Issues:**  When dealing with XML documents that use namespaces, it's crucial to correctly specify the namespaces in the XPath query. Failure to do so will result in nodes not being matched.

   **Example (XML with namespace):**
   ```xml
   <bookstore xmlns:b="http://example.org/books">
     <b:book><b:title>The Great Gatsby</b:title></b:book>
   </bookstore>
   ```
   ```javascript
   // Incorrect: Will not find the book
   let title1 = document.evaluate("//book/title", ..., null, ...).singleNodeValue;

   // Correct: Needs namespace resolution
   let nsResolver = document.createNSResolver(document.documentElement);
   let title2 = document.evaluate("//b:book/b:title", document, nsResolver, ...).singleNodeValue;
   ```

**User Operation to Reach This Code (Debugging Scenario):**

1. **User interacts with a webpage:** A user might click a button or perform an action that triggers JavaScript code execution.
2. **JavaScript code executes an XPath query:** The JavaScript code uses `document.evaluate()` to select specific elements in the DOM.
3. **Blink's XPath engine is invoked:** The browser's rendering engine (Blink) receives the XPath query from the JavaScript engine.
4. **Parsing the XPath expression:** The XPath expression is parsed into a sequence of steps.
5. **Evaluating each step:** For each step in the parsed expression, a `Step` object is created.
6. **`xpath_step.cc` comes into play:** The `Evaluate` method of the `Step` class (implemented in `xpath_step.cc`) is called to process that specific step against the current context in the DOM.

**As a debugging clue:** If a developer is investigating why an XPath query is not returning the expected results, they might set breakpoints within the `Evaluate` or `NodesInAxis` methods in `xpath_step.cc`. This would allow them to:

* **Inspect the `axis_`, `node_test_`, and `predicates_` of the current step.**
* **Examine the `context` node at the beginning of the step evaluation.**
* **Step through the DOM traversal logic within `NodesInAxis` to see which nodes are being considered and why they are (or are not) being included in the `NodeSet`.**
* **Check the evaluation of predicates to understand why certain nodes are being filtered out.**

By stepping through this code, developers can gain a deep understanding of how the XPath engine is processing their query and pinpoint the source of any discrepancies between the expected and actual results.

### 提示词
```
这是目录为blink/renderer/core/xml/xpath_step.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2005 Frerich Raabe <raabe@kde.org>
 * Copyright (C) 2006, 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/xml/xpath_step.h"

#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/xml/xpath_parser.h"
#include "third_party/blink/renderer/core/xml/xpath_util.h"
#include "third_party/blink/renderer/core/xmlns_names.h"

namespace blink {
namespace xpath {

Step::Step(Axis axis, const NodeTest& node_test)
    : axis_(axis), node_test_(MakeGarbageCollected<NodeTest>(node_test)) {}

Step::Step(Axis axis,
           const NodeTest& node_test,
           HeapVector<Member<Predicate>>& predicates)
    : axis_(axis), node_test_(MakeGarbageCollected<NodeTest>(node_test)) {
  predicates_.swap(predicates);
}

Step::~Step() = default;

void Step::Trace(Visitor* visitor) const {
  visitor->Trace(node_test_);
  visitor->Trace(predicates_);
  ParseNode::Trace(visitor);
}

void Step::Optimize() {
  // Evaluate predicates as part of node test if possible to avoid building
  // unnecessary NodeSets.
  // E.g., there is no need to build a set of all "foo" nodes to evaluate
  // "foo[@bar]", we can check the predicate while enumerating.
  // This optimization can be applied to predicates that are not context node
  // list sensitive, or to first predicate that is only context position
  // sensitive, e.g. foo[position() mod 2 = 0].
  HeapVector<Member<Predicate>> remaining_predicates;
  for (const auto& predicate : predicates_) {
    if ((!predicate->IsContextPositionSensitive() ||
         GetNodeTest().MergedPredicates().empty()) &&
        !predicate->IsContextSizeSensitive() && remaining_predicates.empty()) {
      GetNodeTest().MergedPredicates().push_back(predicate);
    } else {
      remaining_predicates.push_back(predicate);
    }
  }
  swap(remaining_predicates, predicates_);
}

bool OptimizeStepPair(Step* first, Step* second) {
  if (first->axis_ == Step::kDescendantOrSelfAxis &&
      first->GetNodeTest().GetKind() == Step::NodeTest::kAnyNodeTest &&
      !first->predicates_.size() &&
      !first->GetNodeTest().MergedPredicates().size()) {
    DCHECK(first->GetNodeTest().Data().empty());
    DCHECK(first->GetNodeTest().NamespaceURI().empty());

    // Optimize the common case of "//" AKA
    // /descendant-or-self::node()/child::NodeTest to /descendant::NodeTest.
    if (second->axis_ == Step::kChildAxis &&
        second->PredicatesAreContextListInsensitive()) {
      first->axis_ = Step::kDescendantAxis;
      first->GetNodeTest() = Step::NodeTest(
          second->GetNodeTest().GetKind(), second->GetNodeTest().Data(),
          second->GetNodeTest().NamespaceURI());
      swap(second->GetNodeTest().MergedPredicates(),
           first->GetNodeTest().MergedPredicates());
      swap(second->predicates_, first->predicates_);
      first->Optimize();
      return true;
    }
  }
  return false;
}

bool Step::PredicatesAreContextListInsensitive() const {
  for (const auto& predicate : predicates_) {
    if (predicate->IsContextPositionSensitive() ||
        predicate->IsContextSizeSensitive())
      return false;
  }

  for (const auto& predicate : GetNodeTest().MergedPredicates()) {
    if (predicate->IsContextPositionSensitive() ||
        predicate->IsContextSizeSensitive())
      return false;
  }

  return true;
}

void Step::Evaluate(EvaluationContext& evaluation_context,
                    Node* context,
                    NodeSet& nodes) const {
  evaluation_context.position = 0;

  NodesInAxis(evaluation_context, context, nodes);

  // Check predicates that couldn't be merged into node test.
  for (const auto& predicate : predicates_) {
    NodeSet* new_nodes = NodeSet::Create();
    if (!nodes.IsSorted())
      new_nodes->MarkSorted(false);

    for (unsigned j = 0; j < nodes.size(); j++) {
      Node* node = nodes[j];

      evaluation_context.node = node;
      evaluation_context.size = nodes.size();
      evaluation_context.position = j + 1;
      if (predicate->Evaluate(evaluation_context))
        new_nodes->Append(node);
    }

    nodes.Swap(*new_nodes);
  }
}

#if DCHECK_IS_ON()
static inline Node::NodeType PrimaryNodeType(Step::Axis axis) {
  switch (axis) {
    case Step::kAttributeAxis:
      return Node::kAttributeNode;
    default:
      return Node::kElementNode;
  }
}
#endif

// Evaluate NodeTest without considering merged predicates.
static inline bool NodeMatchesBasicTest(Node* node,
                                        Step::Axis axis,
                                        const Step::NodeTest& node_test) {
  switch (node_test.GetKind()) {
    case Step::NodeTest::kTextNodeTest: {
      Node::NodeType type = node->getNodeType();
      return type == Node::kTextNode || type == Node::kCdataSectionNode;
    }
    case Step::NodeTest::kCommentNodeTest:
      return node->getNodeType() == Node::kCommentNode;
    case Step::NodeTest::kProcessingInstructionNodeTest: {
      const AtomicString& name = node_test.Data();
      return node->getNodeType() == Node::kProcessingInstructionNode &&
             (name.empty() || node->nodeName() == name);
    }
    case Step::NodeTest::kAnyNodeTest:
      return true;
    case Step::NodeTest::kNameTest: {
      const AtomicString& name = node_test.Data();
      const AtomicString& namespace_uri = node_test.NamespaceURI();

      if (axis == Step::kAttributeAxis) {
        auto* attr = To<Attr>(node);

        // In XPath land, namespace nodes are not accessible on the
        // attribute axis.
        if (attr->namespaceURI() == xmlns_names::kNamespaceURI)
          return false;

        if (name == g_star_atom)
          return namespace_uri.empty() || attr->namespaceURI() == namespace_uri;

        if (attr->GetDocument().IsHTMLDocument() && attr->ownerElement() &&
            attr->ownerElement()->IsHTMLElement() && namespace_uri.IsNull() &&
            attr->namespaceURI().IsNull())
          return EqualIgnoringASCIICase(attr->localName(), name);

        return attr->localName() == name &&
               attr->namespaceURI() == namespace_uri;
      }

      // Node test on the namespace axis is not implemented yet, the caller
      // has a check for it.
      DCHECK_NE(Step::kNamespaceAxis, axis);

// For other axes, the principal node type is element.
#if DCHECK_IS_ON()
      DCHECK_EQ(Node::kElementNode, PrimaryNodeType(axis));
#endif
      auto* element = DynamicTo<Element>(node);
      if (!element)
        return false;

      if (name == g_star_atom) {
        return namespace_uri.empty() ||
               namespace_uri == element->namespaceURI();
      }

      if (IsA<HTMLDocument>(element->GetDocument())) {
        if (element->IsHTMLElement()) {
          // Paths without namespaces should match HTML elements in HTML
          // documents despite those having an XHTML namespace. Names are
          // compared case-insensitively.
          return EqualIgnoringASCIICase(element->localName(), name) &&
                 (namespace_uri.IsNull() ||
                  namespace_uri == element->namespaceURI());
        }
        // An expression without any prefix shouldn't match no-namespace
        // nodes (because HTML5 says so).
        return element->HasLocalName(name) &&
               namespace_uri == element->namespaceURI() &&
               !namespace_uri.IsNull();
      }
      return element->HasLocalName(name) &&
             namespace_uri == element->namespaceURI();
    }
  }
  NOTREACHED();
}

static inline bool NodeMatches(EvaluationContext& evaluation_context,
                               Node* node,
                               Step::Axis axis,
                               const Step::NodeTest& node_test) {
  if (!NodeMatchesBasicTest(node, axis, node_test))
    return false;

  // Only the first merged predicate may depend on position.
  ++evaluation_context.position;

  for (const auto& predicate : node_test.MergedPredicates()) {
    evaluation_context.node = node;
    // No need to set context size - we only get here when evaluating
    // predicates that do not depend on it.
    if (!predicate->Evaluate(evaluation_context))
      return false;
  }

  return true;
}

// Result nodes are ordered in axis order. Node test (including merged
// predicates) is applied.
void Step::NodesInAxis(EvaluationContext& evaluation_context,
                       Node* context,
                       NodeSet& nodes) const {
  DCHECK(nodes.IsEmpty());
  switch (axis_) {
    case kChildAxis:
      // In XPath model, attribute nodes do not have children.
      if (context->IsAttributeNode())
        return;

      for (Node* n = context->firstChild(); n; n = n->nextSibling()) {
        if (NodeMatches(evaluation_context, n, kChildAxis, GetNodeTest()))
          nodes.Append(n);
      }
      return;

    case kDescendantAxis:
      // In XPath model, attribute nodes do not have children.
      if (context->IsAttributeNode())
        return;

      for (Node& n : NodeTraversal::DescendantsOf(*context)) {
        if (NodeMatches(evaluation_context, &n, kDescendantAxis, GetNodeTest()))
          nodes.Append(&n);
      }
      return;

    case kParentAxis:
      if (auto* attr = DynamicTo<Attr>(context)) {
        Element* n = attr->ownerElement();
        if (n && NodeMatches(evaluation_context, n, kParentAxis, GetNodeTest()))
          nodes.Append(n);
      } else {
        ContainerNode* n = context->parentNode();
        if (n && NodeMatches(evaluation_context, n, kParentAxis, GetNodeTest()))
          nodes.Append(n);
      }
      return;

    case kAncestorAxis: {
      Node* n = context;
      auto* attr = DynamicTo<Attr>(context);
      if (attr && attr->ownerElement()) {
        n = attr->ownerElement();
        if (NodeMatches(evaluation_context, n, kAncestorAxis, GetNodeTest()))
          nodes.Append(n);
      }
      for (n = n->parentNode(); n; n = n->parentNode()) {
        if (NodeMatches(evaluation_context, n, kAncestorAxis, GetNodeTest()))
          nodes.Append(n);
      }
      nodes.MarkSorted(false);
      return;
    }

    case kFollowingSiblingAxis:
      if (context->getNodeType() == Node::kAttributeNode)
        return;

      for (Node* n = context->nextSibling(); n; n = n->nextSibling()) {
        if (NodeMatches(evaluation_context, n, kFollowingSiblingAxis,
                        GetNodeTest()))
          nodes.Append(n);
      }
      return;

    case kPrecedingSiblingAxis:
      if (context->getNodeType() == Node::kAttributeNode)
        return;

      for (Node* n = context->previousSibling(); n; n = n->previousSibling()) {
        if (NodeMatches(evaluation_context, n, kPrecedingSiblingAxis,
                        GetNodeTest()))
          nodes.Append(n);
      }
      nodes.MarkSorted(false);
      return;

    case kFollowingAxis: {
      auto* attr = DynamicTo<Attr>(context);
      if (attr && attr->ownerElement()) {
        for (Node& p : NodeTraversal::StartsAfter(*attr->ownerElement())) {
          if (NodeMatches(evaluation_context, &p, kFollowingAxis,
                          GetNodeTest()))
            nodes.Append(&p);
        }
      } else {
        for (Node* p = context; !IsRootDomNode(p); p = p->parentNode()) {
          for (Node* n = p->nextSibling(); n; n = n->nextSibling()) {
            if (NodeMatches(evaluation_context, n, kFollowingAxis,
                            GetNodeTest()))
              nodes.Append(n);
            for (Node& c : NodeTraversal::DescendantsOf(*n)) {
              if (NodeMatches(evaluation_context, &c, kFollowingAxis,
                              GetNodeTest()))
                nodes.Append(&c);
            }
          }
        }
      }
      return;
    }

    case kPrecedingAxis: {
      auto* attr = DynamicTo<Attr>(context);
      if (attr && attr->ownerElement())
        context = attr->ownerElement();

      Node* n = context;
      while (ContainerNode* parent = n->parentNode()) {
        for (n = NodeTraversal::Previous(*n); n != parent;
             n = NodeTraversal::Previous(*n)) {
          if (NodeMatches(evaluation_context, n, kPrecedingAxis, GetNodeTest()))
            nodes.Append(n);
        }
        n = parent;
      }
      nodes.MarkSorted(false);
      return;
    }

    case kAttributeAxis: {
      auto* context_element = DynamicTo<Element>(context);
      if (!context_element)
        return;

      // Avoid lazily creating attribute nodes for attributes that we do not
      // need anyway.
      if (GetNodeTest().GetKind() == NodeTest::kNameTest &&
          GetNodeTest().Data() != g_star_atom) {
        Attr* attr;
        // We need this branch because getAttributeNodeNS() doesn't do
        // ignore-case matching even for an HTML element in an HTML document.
        if (GetNodeTest().NamespaceURI().IsNull()) {
          attr = context_element->getAttributeNode(GetNodeTest().Data());
        } else {
          attr = context_element->getAttributeNodeNS(
              GetNodeTest().NamespaceURI(), GetNodeTest().Data());
        }
        // In XPath land, namespace nodes are not accessible on the attribute
        // axis.
        if (attr && attr->namespaceURI() != xmlns_names::kNamespaceURI) {
          // Still need to check merged predicates.
          if (NodeMatches(evaluation_context, attr, kAttributeAxis,
                          GetNodeTest()))
            nodes.Append(attr);
        }
        return;
      }

      AttributeCollection attributes = context_element->Attributes();
      for (auto& attribute : attributes) {
        Attr* attr = context_element->EnsureAttr(attribute.GetName());
        if (NodeMatches(evaluation_context, attr, kAttributeAxis,
                        GetNodeTest()))
          nodes.Append(attr);
      }
      return;
    }

    case kNamespaceAxis:
      // XPath namespace nodes are not implemented.
      return;

    case kSelfAxis:
      if (NodeMatches(evaluation_context, context, kSelfAxis, GetNodeTest()))
        nodes.Append(context);
      return;

    case kDescendantOrSelfAxis:
      if (NodeMatches(evaluation_context, context, kDescendantOrSelfAxis,
                      GetNodeTest()))
        nodes.Append(context);
      // In XPath model, attribute nodes do not have children.
      if (context->IsAttributeNode())
        return;

      for (Node& n : NodeTraversal::DescendantsOf(*context)) {
        if (NodeMatches(evaluation_context, &n, kDescendantOrSelfAxis,
                        GetNodeTest()))
          nodes.Append(&n);
      }
      return;

    case kAncestorOrSelfAxis: {
      if (NodeMatches(evaluation_context, context, kAncestorOrSelfAxis,
                      GetNodeTest()))
        nodes.Append(context);
      Node* n = context;
      auto* attr = DynamicTo<Attr>(context);
      if (attr && attr->ownerElement()) {
        n = attr->ownerElement();
        if (NodeMatches(evaluation_context, n, kAncestorOrSelfAxis,
                        GetNodeTest()))
          nodes.Append(n);
      }
      for (n = n->parentNode(); n; n = n->parentNode()) {
        if (NodeMatches(evaluation_context, n, kAncestorOrSelfAxis,
                        GetNodeTest()))
          nodes.Append(n);
      }
      nodes.MarkSorted(false);
      return;
    }
  }
  NOTREACHED();
}

}  // namespace xpath

}  // namespace blink
```