Response:
Let's break down the thought process for analyzing this `dom_patch_support.cc` file.

1. **Understand the Purpose from Filename and Context:** The name `dom_patch_support.cc` strongly suggests this code deals with *patching* the DOM. The directory `blink/renderer/core/inspector/` indicates it's part of the DevTools integration within Blink, specifically for the DOM inspector. This immediately gives us a high-level understanding: it helps the DevTools modify the DOM efficiently.

2. **Scan the Includes:**  The included headers provide valuable clues about the functionalities used:
    *  `third_party/blink/renderer/core/inspector/dom_patch_support.h`:  Confirms the purpose and likely contains the class declaration.
    *  DOM-related headers (`core/dom/...`):  `Node`, `Document`, `Element`, `Attribute`, `DocumentFragment`, etc. These confirm it directly manipulates the DOM.
    *  HTML-specific headers (`core/html/...`): `HTMLDocument`, `HTMLBodyElement`, `HTMLHeadElement`, `HTMLDocumentParser`. Implies handling HTML-specific logic.
    *  XML-specific headers (`core/xml/...`): `XMLDocument`, `XMLDocumentParser`. Indicates support for XML-based documents as well.
    *  Inspector-related headers (`core/inspector/...`): `DOMEditor`, `InspectorHistory`. Shows interaction with other DevTools components. `DOMEditor` is particularly important, suggesting it delegates the actual DOM manipulation.
    *  Platform/utility headers (`platform/...`, `base/...`, `wtf/...`): `Platform`, `ExceptionState`, `Crypto`, various data structures (`HeapDeque`, `HeapVector`, `HashMap`). These are standard Blink/Chromium utilities for memory management, error handling, and data storage.

3. **Examine the Class Definition (`DOMPatchSupport`):**
    * **Constructor:**  Takes a `DOMEditor*` and a `Document&`. This reinforces the delegation of DOM manipulation to `DOMEditor` and operates on a specific `Document`.
    * **Key Methods:**  `PatchDocument`, `PatchNode`, `InnerPatchNode`, `InnerPatchChildren`, `Diff`, `CreateDigest`, `InsertBeforeAndMarkAsUsed`, `RemoveChildAndMoveToNew`, `MarkNodeAsUsed`. These are the core functionalities. Start trying to understand what each might do based on its name. "Patch" implies making targeted changes. "Digest" sounds like generating some kind of summary or hash. "Diff" means comparing two sets of data.

4. **Analyze Key Methods in Detail:**
    * **`PatchDocument(const String& markup)`:** This method likely replaces the entire document content. The code creates a new `Document`, parses the `markup`, and then calls `InnerPatchNode` to compare and apply changes. The fallback to `document.write()` is a safety mechanism.
    * **`PatchNode(Node* node, const String& markup, ExceptionState&)`:**  This targets a specific `Node`. It handles the special case of patching the root elements and then uses `DocumentFragment` to parse the `markup` into a set of new nodes. It constructs "old" and "new" lists of children and calls `InnerPatchChildren`. The fallback uses `DOMEditor::ReplaceChild`.
    * **`InnerPatchNode(Digest* old_digest, Digest* new_digest, ExceptionState&)`:**  This is the core of the node patching logic. It compares SHA1 hashes for quick equality checks. If hashes differ, it checks node types and names. If those also differ, it replaces the node. If only the value changes, it updates the value. It then handles attribute patching and recursively calls `InnerPatchChildren` for child nodes.
    * **`InnerPatchChildren(ContainerNode* parent_node, const HeapVector<Member<Digest>>& old_list, const HeapVector<Member<Digest>>& new_list, ExceptionState&)`:** This method implements a sophisticated diffing and patching algorithm for a list of child nodes. It uses the `Diff` method to find similarities and differences. It handles node removal, updates (merges), insertions, and reordering. The special handling of `<head>` and `<body>` is noteworthy.
    * **`Diff(const HeapVector<Member<Digest>>& old_list, const HeapVector<Member<Digest>>& new_list)`:**  This function implements a diffing algorithm to compare two lists of `Digest` objects. It aims to identify insertions, deletions, moves, and unchanged elements. It uses SHA1 hashes to efficiently compare nodes.
    * **`CreateDigest(Node* node, UnusedNodesMap* unused_nodes_map)`:** This function calculates a "digest" (essentially a fingerprint) of a DOM node and its descendants. It includes the node type, name, value, attributes, and recursively digests child nodes. The SHA1 hash is the core of the digest. The `unused_nodes_map` seems to be used for tracking nodes that are available for reuse during patching.

5. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The inspector is heavily used by developers debugging JavaScript. This code enables the "Edit as HTML" feature in the DevTools, allowing developers to make live changes to the DOM and see the effects immediately.
    * **HTML:** The code explicitly handles HTML-specific elements (`<head>`, `<body>`) and parsing. The `PatchDocument` and `PatchNode` methods take HTML markup as input.
    * **CSS:** While this code doesn't directly manipulate CSS properties, changes to the DOM structure can indirectly affect CSS rendering. Adding or removing elements or changing their attributes can trigger style recalculations.

6. **Look for Logic and Assumptions:** The diffing algorithm in `InnerPatchChildren` makes certain assumptions about how changes are made. It prioritizes efficient patching by identifying unchanged nodes and only modifying the necessary parts. The handling of `<head>` and `<body>` demonstrates a practical consideration for maintaining the basic document structure.

7. **Consider Potential Usage Errors:** The code includes `ExceptionState` parameters, indicating that DOM manipulation can fail. A common user error would be providing invalid HTML or XML markup in `PatchDocument` or `PatchNode`. The code includes error handling (fallback to full replacement) for some cases.

8. **Review Code Comments:**  The comments in the code (like the `FIXME` notes) provide additional context and insights into potential areas for improvement or limitations.

9. **Synthesize and Organize:** Finally, structure the findings into logical categories like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," and "Common Errors."  Provide concrete examples to illustrate the points.

This systematic approach, combining static analysis of the code with an understanding of the context and related technologies, allows for a comprehensive understanding of the `dom_patch_support.cc` file's purpose and functionality.
This C++ source code file, `dom_patch_support.cc`, located within the Chromium Blink engine, provides functionality to efficiently update (patch) the Document Object Model (DOM) based on changes represented as markup strings. It's a crucial component for the browser's developer tools (specifically the DOM inspector) and potentially other features that need to modify the DOM in a performant way.

Here's a breakdown of its functionalities, connections to web technologies, logical reasoning, and potential user errors:

**Functionalities:**

1. **Patching Documents (`PatchDocument`):**
   - Takes a complete HTML or XML markup string as input.
   - Parses the new markup to create a new, temporary document.
   - Computes "digests" (SHA1 hashes) of the old and new DOM trees to identify differences efficiently.
   - Uses a diffing algorithm (`Diff`) to compare the old and new DOM structures.
   - Applies the necessary changes (node insertions, removals, replacements, attribute modifications, value updates) to the original document to match the new markup.
   - If patching fails for some reason, it falls back to a full rewrite of the document using `document.write()`.

2. **Patching Nodes (`PatchNode`):**
   - Takes a specific DOM `Node` and a markup string representing the desired new content for that node (often a fragment of HTML/XML).
   - Parses the markup string into a `DocumentFragment`.
   - Constructs "old" and "new" lists of child nodes for the parent of the target node.
   - Uses the diffing algorithm to determine the changes needed.
   - Applies the changes to the parent's children to match the new fragment.
   - If patching fails, it falls back to replacing the target node with the parsed fragment.

3. **Inner Patching Logic (`InnerPatchNode`, `InnerPatchChildren`):**
   - `InnerPatchNode` recursively compares individual nodes based on their type, name, value, and attributes. It delegates actual DOM manipulations to the `DOMEditor`.
   - `InnerPatchChildren` implements the core diffing and patching logic for lists of child nodes. It identifies insertions, deletions, moves, and updates. It tries to reuse existing nodes where possible to minimize DOM manipulations.

4. **Diffing Algorithm (`Diff`):**
   - Compares two lists of "digests" representing the old and new sets of child nodes.
   - Attempts to find matching nodes based on their SHA1 hashes.
   - Identifies insertions, deletions, and moves of nodes.
   - This algorithm aims to minimize the number of actual DOM operations needed.

5. **Digest Creation (`CreateDigest`):**
   - Recursively calculates a SHA1 hash ("digest") for a given DOM `Node` and its subtree.
   - The digest includes the node's type, name, value, and the digests of its children and attributes.
   - These digests are used by the diffing algorithm to efficiently compare DOM structures.

6. **Node Management (`InsertBeforeAndMarkAsUsed`, `RemoveChildAndMoveToNew`, `MarkNodeAsUsed`):**
   - These helper functions manage the insertion, removal, and tracking of nodes during the patching process.
   - `MarkNodeAsUsed` is important to prevent the reuse of nodes that are intended to be new.
   - `RemoveChildAndMoveToNew` tries to preserve node identity if a node is moved to a different part of the DOM.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This code is part of the Blink rendering engine, which interprets and executes JavaScript. The DOM patching functionality is often triggered by JavaScript interactions, especially within developer tools or potentially by JavaScript frameworks that manipulate the DOM. For example, when a developer edits an element's HTML in the browser's inspector, this code is likely involved in applying those changes to the actual DOM.

   **Example:** Imagine a JavaScript snippet that modifies the `innerHTML` of a div:
   ```javascript
   document.getElementById('myDiv').innerHTML = '<p>New content</p>';
   ```
   While this direct manipulation bypasses the `DOMPatchSupport` in a typical scenario, the *DevTools* using "Edit as HTML" on the `myDiv` element would likely leverage this patching mechanism.

* **HTML:** The primary input for the patching functions is HTML markup. The code needs to parse and understand HTML structures (elements, attributes, text content). It also handles HTML-specific elements like `<head>` and `<body>` in a special way during patching.

   **Example:** If the original HTML is:
   ```html
   <div><span>Old text</span></div>
   ```
   And the new HTML provided to `PatchNode` for the `div` is:
   ```html
   <p>New paragraph</p>
   ```
   The `DOMPatchSupport` would identify the removal of the `span` and the insertion of the `p` element.

* **CSS:** While this code doesn't directly manipulate CSS styles, changes to the DOM structure directly impact how CSS is applied. Adding, removing, or changing elements can trigger style recalculations and reflows. The efficiency of DOM patching is important to minimize performance issues related to these updates.

   **Example:** If an element with a specific CSS class is removed via patching, the styles associated with that class will no longer be applied to that part of the document. Conversely, adding a new element with a class will cause the corresponding CSS rules to be applied.

**Logical Reasoning and Assumptions:**

* **Assumption of Well-Formed Markup:** The code assumes that the input markup strings are generally well-formed HTML or XML. While it has some basic error handling (fallback to full rewrite), providing malformed markup can lead to unpredictable behavior or parsing errors.
* **Efficiency Through Hashing and Diffing:** The core logic relies on the assumption that comparing SHA1 hashes of DOM subtrees is a fast and reliable way to identify changes. The diffing algorithm aims to find the minimal set of operations needed to transform the old DOM to the new DOM.
* **Preservation of Node Identity:** The `RemoveChildAndMoveToNew` function demonstrates an attempt to preserve the identity of nodes even if they are moved within the DOM. This is important for maintaining state and event listeners associated with those nodes.
* **Special Handling of `<head>` and `<body>`:** The code explicitly handles `<head>` and `<body>` elements during patching, likely because these elements are fundamental to the document structure and their complete replacement could have significant side effects.

**Assumptions and Example of Logic:**

Let's consider a simplified example of how `InnerPatchChildren` might work with the `Diff` algorithm:

**Input (Conceptual Digests):**

* **`old_list`:** `[A, B, C]` (where A, B, C are digests of child nodes)
* **`new_list`:** `[B, D, C, A]`

**`Diff` Algorithm Output (Conceptual Mapping):**

The `Diff` algorithm would try to find matches based on the digests:

* `B` in `old_list` matches `B` in `new_list`.
* `C` in `old_list` matches `C` in `new_list`.
* `A` in `old_list` matches `A` in `new_list`.

It would identify:

* **Insertion:** `D` is new.
* **Moves:** `A` has moved from the beginning to the end.

**`InnerPatchChildren` Logic:**

Based on the diff, `InnerPatchChildren` would:

1. **Move `B`** (if necessary to its new position).
2. **Insert `D`** before `C`.
3. **Move `C`** (if necessary).
4. **Move `A`** to the end.

**Assumptions:**  The `Diff` algorithm makes assumptions about the cost of different operations (insert, delete, move) and tries to find a solution that minimizes these costs. It might use heuristics to determine the most likely sequence of changes.

**Common User or Programming Errors:**

1. **Providing Invalid Markup:** Supplying malformed HTML or XML to `PatchDocument` or `PatchNode` will likely lead to parsing errors and potentially break the DOM.

   **Example:**
   ```c++
   // Incorrectly nested tags
   dom_patch_support->PatchNode(node, "<div><p>Text<div></div></p>");
   ```

2. **Incorrectly Targeting Nodes:**  When using `PatchNode`, ensuring the target `Node` is the correct one is crucial. Patching the wrong node can have unintended consequences.

   **Example:**  Trying to patch a text node as if it were an element.

3. **Overly Complex Patches:** While the system is designed for efficiency, making massive and highly fragmented changes might still be less performant than a full replacement in some edge cases.

4. **Race Conditions (Less likely in typical DevTools usage):** If the DOM is being modified concurrently by other scripts while a patch is being applied, it could lead to unexpected outcomes. However, this is less of a concern for typical DevTools interactions.

5. **Misunderstanding the Scope of Patching:**  `PatchNode` operates on the *children* of the target node's parent. Providing markup that expects to replace the target node itself requires careful consideration of the parent context.

**In summary, `dom_patch_support.cc` is a sophisticated and critical component of the Blink rendering engine, enabling efficient and granular updates to the DOM, primarily used by developer tools but potentially applicable in other scenarios where controlled DOM manipulation is required. It leverages hashing, diffing algorithms, and careful node management to optimize performance and minimize disruption to the rendering process.**

Prompt: 
```
这是目录为blink/renderer/core/inspector/dom_patch_support.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
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

#include "third_party/blink/renderer/core/inspector/dom_patch_support.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/inspector/dom_editor.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/hash_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {

DOMPatchSupport::DOMPatchSupport(DOMEditor* dom_editor, Document& document)
    : dom_editor_(dom_editor), document_(&document) {}

void DOMPatchSupport::PatchDocument(const String& markup) {
  Document* new_document = nullptr;
  DocumentInit init =
      DocumentInit::Create()
          .WithExecutionContext(GetDocument().GetExecutionContext())
          .WithAgent(GetDocument().GetAgent());
  if (IsA<HTMLDocument>(GetDocument()))
    new_document = MakeGarbageCollected<HTMLDocument>(init);
  else if (GetDocument().IsSVGDocument())
    new_document = XMLDocument::CreateSVG(init);
  else if (GetDocument().IsXHTMLDocument())
    new_document = XMLDocument::CreateXHTML(init);
  else if (IsA<XMLDocument>(GetDocument()))
    new_document = MakeGarbageCollected<XMLDocument>(init);

  DCHECK(new_document);
  if (!IsA<HTMLDocument>(GetDocument())) {
    DocumentParser* parser =
        MakeGarbageCollected<XMLDocumentParser>(*new_document, nullptr);
    parser->Append(markup);
    parser->Finish();
    parser->Detach();

    // Avoid breakage on non-well-formed documents.
    if (!static_cast<XMLDocumentParser*>(parser)->WellFormed())
      return;
  }
  new_document->SetContent(markup);
  Digest* old_info = CreateDigest(GetDocument().documentElement(), nullptr);
  Digest* new_info =
      CreateDigest(new_document->documentElement(), &unused_nodes_map_);

  if (!InnerPatchNode(old_info, new_info, IGNORE_EXCEPTION_FOR_TESTING)) {
    // Fall back to rewrite.
    GetDocument().write(markup);
    GetDocument().close();
  }
}

Node* DOMPatchSupport::PatchNode(Node* node,
                                 const String& markup,
                                 ExceptionState& exception_state) {
  // Don't parse <html> as a fragment.
  if (node->IsDocumentNode() ||
      (node->parentNode() && node->parentNode()->IsDocumentNode())) {
    PatchDocument(markup);
    return nullptr;
  }

  Node* previous_sibling = node->previousSibling();
  DocumentFragment* fragment = DocumentFragment::Create(GetDocument());
  Node* target_node = node->ParentElementOrShadowRoot()
                          ? node->ParentElementOrShadowRoot()
                          : GetDocument().documentElement();

  // Use the document BODY as the context element when editing immediate shadow
  // root children, as it provides an equivalent parsing context.
  if (target_node->IsShadowRoot())
    target_node = GetDocument().body();
  auto* target_element = To<Element>(target_node);

  // FIXME: This code should use one of createFragment* in Serialization.h
  if (IsA<HTMLDocument>(GetDocument()))
    fragment->ParseHTML(markup, target_element);
  else
    fragment->ParseXML(markup, target_element, IGNORE_EXCEPTION);

  // Compose the old list.
  ContainerNode* parent_node = node->parentNode();
  HeapVector<Member<Digest>> old_list;
  for (Node* child = parent_node->firstChild(); child;
       child = child->nextSibling())
    old_list.push_back(CreateDigest(child, nullptr));

  // Compose the new list.
  String markup_copy = markup.LowerASCII();
  HeapVector<Member<Digest>> new_list;
  for (Node* child = parent_node->firstChild(); child != node;
       child = child->nextSibling())
    new_list.push_back(CreateDigest(child, nullptr));
  for (Node* child = fragment->firstChild(); child;
       child = child->nextSibling()) {
    if (IsA<HTMLHeadElement>(*child) && !child->hasChildren() &&
        markup_copy.Find("</head>") == kNotFound) {
      // HTML5 parser inserts empty <head> tag whenever it parses <body>
      continue;
    }
    if (IsA<HTMLBodyElement>(*child) && !child->hasChildren() &&
        markup_copy.Find("</body>") == kNotFound) {
      // HTML5 parser inserts empty <body> tag whenever it parses </head>
      continue;
    }
    new_list.push_back(CreateDigest(child, &unused_nodes_map_));
  }
  for (Node* child = node->nextSibling(); child; child = child->nextSibling())
    new_list.push_back(CreateDigest(child, nullptr));

  if (!InnerPatchChildren(parent_node, old_list, new_list, exception_state)) {
    // Fall back to total replace.
    if (!dom_editor_->ReplaceChild(parent_node, fragment, node,
                                   exception_state))
      return nullptr;
  }
  return previous_sibling ? previous_sibling->nextSibling()
                          : parent_node->firstChild();
}

bool DOMPatchSupport::InnerPatchNode(Digest* old_digest,
                                     Digest* new_digest,
                                     ExceptionState& exception_state) {
  if (old_digest->sha1_ == new_digest->sha1_)
    return true;

  Node* old_node = old_digest->node_;
  Node* new_node = new_digest->node_;

  if (new_node->getNodeType() != old_node->getNodeType() ||
      new_node->nodeName() != old_node->nodeName())
    return dom_editor_->ReplaceChild(old_node->parentNode(), new_node, old_node,
                                     exception_state);

  if (old_node->nodeValue() != new_node->nodeValue()) {
    if (!dom_editor_->SetNodeValue(old_node, new_node->nodeValue(),
                                   exception_state))
      return false;
  }

  auto* old_element = DynamicTo<Element>(old_node);
  if (!old_element)
    return true;

  // Patch attributes
  auto* new_element = To<Element>(new_node);
  if (old_digest->attrs_sha1_ != new_digest->attrs_sha1_) {
    // FIXME: Create a function in Element for removing all properties. Take in
    // account whether did/willModifyAttribute are important.
    while (old_element->AttributesWithoutUpdate().size()) {
      const Attribute& attribute = old_element->AttributesWithoutUpdate().at(0);
      if (!dom_editor_->RemoveAttribute(
              old_element, attribute.GetName().ToString(), exception_state))
        return false;
    }

    // FIXME: Create a function in Element for copying properties.
    // cloneDataFromElement() is close but not enough for this case.
    for (auto& attribute : new_element->AttributesWithoutUpdate()) {
      if (!dom_editor_->SetAttribute(old_element,
                                     attribute.GetName().ToString(),
                                     attribute.Value(), exception_state))
        return false;
    }
  }

  bool result = InnerPatchChildren(old_element, old_digest->children_,
                                   new_digest->children_, exception_state);
  unused_nodes_map_.erase(new_digest->sha1_);
  return result;
}

std::pair<DOMPatchSupport::ResultMap, DOMPatchSupport::ResultMap>
DOMPatchSupport::Diff(const HeapVector<Member<Digest>>& old_list,
                      const HeapVector<Member<Digest>>& new_list) {
  ResultMap new_map(new_list.size());
  ResultMap old_map(old_list.size());

  for (wtf_size_t i = 0; i < old_map.size(); ++i) {
    old_map[i].first = nullptr;
    old_map[i].second = 0;
  }

  for (wtf_size_t i = 0; i < new_map.size(); ++i) {
    new_map[i].first = nullptr;
    new_map[i].second = 0;
  }

  // Trim head and tail.
  for (wtf_size_t i = 0; i < old_list.size() && i < new_list.size() &&
                         old_list[i]->sha1_ == new_list[i]->sha1_;
       ++i) {
    old_map[i].first = old_list[i].Get();
    old_map[i].second = i;
    new_map[i].first = new_list[i].Get();
    new_map[i].second = i;
  }
  for (wtf_size_t i = 0; i < old_list.size() && i < new_list.size() &&
                         old_list[old_list.size() - i - 1]->sha1_ ==
                             new_list[new_list.size() - i - 1]->sha1_;
       ++i) {
    wtf_size_t old_index = old_list.size() - i - 1;
    wtf_size_t new_index = new_list.size() - i - 1;
    old_map[old_index].first = old_list[old_index].Get();
    old_map[old_index].second = new_index;
    new_map[new_index].first = new_list[new_index].Get();
    new_map[new_index].second = old_index;
  }

  typedef HashMap<String, Vector<wtf_size_t>> DiffTable;
  DiffTable new_table;
  DiffTable old_table;

  for (wtf_size_t i = 0; i < new_list.size(); ++i) {
    new_table.insert(new_list[i]->sha1_, Vector<wtf_size_t>())
        .stored_value->value.push_back(i);
  }

  for (wtf_size_t i = 0; i < old_list.size(); ++i) {
    old_table.insert(old_list[i]->sha1_, Vector<wtf_size_t>())
        .stored_value->value.push_back(i);
  }

  for (auto& new_it : new_table) {
    if (new_it.value.size() != 1)
      continue;

    DiffTable::iterator old_it = old_table.find(new_it.key);
    if (old_it == old_table.end() || old_it->value.size() != 1)
      continue;

    new_map[new_it.value[0]] =
        std::make_pair(new_list[new_it.value[0]].Get(), old_it->value[0]);
    old_map[old_it->value[0]] =
        std::make_pair(old_list[old_it->value[0]].Get(), new_it.value[0]);
  }

  for (wtf_size_t i = 0; new_list.size() > 0 && i < new_list.size() - 1; ++i) {
    if (!new_map[i].first || new_map[i + 1].first)
      continue;

    wtf_size_t j = new_map[i].second + 1;
    if (j < old_map.size() && !old_map[j].first &&
        new_list[i + 1]->sha1_ == old_list[j]->sha1_) {
      new_map[i + 1] = std::make_pair(new_list[i + 1].Get(), j);
      old_map[j] = std::make_pair(old_list[j].Get(), i + 1);
    }
  }

  for (wtf_size_t i = new_list.size() - 1; new_list.size() > 0 && i > 0; --i) {
    if (!new_map[i].first || new_map[i - 1].first || new_map[i].second <= 0)
      continue;

    wtf_size_t j = new_map[i].second - 1;
    if (!old_map[j].first && new_list[i - 1]->sha1_ == old_list[j]->sha1_) {
      new_map[i - 1] = std::make_pair(new_list[i - 1].Get(), j);
      old_map[j] = std::make_pair(old_list[j].Get(), i - 1);
    }
  }

  return std::make_pair(old_map, new_map);
}

bool DOMPatchSupport::InnerPatchChildren(
    ContainerNode* parent_node,
    const HeapVector<Member<Digest>>& old_list,
    const HeapVector<Member<Digest>>& new_list,
    ExceptionState& exception_state) {
  std::pair<ResultMap, ResultMap> result_maps = Diff(old_list, new_list);
  ResultMap& old_map = result_maps.first;
  ResultMap& new_map = result_maps.second;

  Digest* old_head = nullptr;
  Digest* old_body = nullptr;

  // 1. First strip everything except for the nodes that retain. Collect pending
  // merges.
  HeapHashMap<Member<Digest>, Member<Digest>> merges;
  HashSet<wtf_size_t, IntWithZeroKeyHashTraits<wtf_size_t>> used_new_ordinals;
  for (wtf_size_t i = 0; i < old_list.size(); ++i) {
    if (old_map[i].first) {
      if (used_new_ordinals.insert(old_map[i].second).is_new_entry)
        continue;
      old_map[i].first = nullptr;
      old_map[i].second = 0;
    }

    // Always match <head> and <body> tags with each other - we can't remove
    // them from the DOM upon patching.
    if (IsA<HTMLHeadElement>(*old_list[i]->node_)) {
      old_head = old_list[i].Get();
      continue;
    }
    if (IsA<HTMLBodyElement>(*old_list[i]->node_)) {
      old_body = old_list[i].Get();
      continue;
    }

    // Check if this change is between stable nodes. If it is, consider it as
    // "modified".
    if (!unused_nodes_map_.Contains(old_list[i]->sha1_) &&
        (!i || old_map[i - 1].first) &&
        (i == old_map.size() - 1 || old_map[i + 1].first)) {
      wtf_size_t anchor_candidate = i ? old_map[i - 1].second + 1 : 0;
      wtf_size_t anchor_after = (i == old_map.size() - 1)
                                    ? anchor_candidate + 1
                                    : old_map[i + 1].second;
      if (anchor_after - anchor_candidate == 1 &&
          anchor_candidate < new_list.size())
        merges.Set(new_list[anchor_candidate].Get(), old_list[i].Get());
      else {
        if (!RemoveChildAndMoveToNew(old_list[i].Get(), exception_state))
          return false;
      }
    } else {
      if (!RemoveChildAndMoveToNew(old_list[i].Get(), exception_state))
        return false;
    }
  }

  // Mark retained nodes as used, do not reuse node more than once.
  HashSet<wtf_size_t, IntWithZeroKeyHashTraits<wtf_size_t>> used_old_ordinals;
  for (wtf_size_t i = 0; i < new_list.size(); ++i) {
    if (!new_map[i].first)
      continue;
    wtf_size_t old_ordinal = new_map[i].second;
    if (used_old_ordinals.Contains(old_ordinal)) {
      // Do not map node more than once
      new_map[i].first = nullptr;
      new_map[i].second = 0;
      continue;
    }
    used_old_ordinals.insert(old_ordinal);
    MarkNodeAsUsed(new_map[i].first);
  }

  // Mark <head> and <body> nodes for merge.
  if (old_head || old_body) {
    for (wtf_size_t i = 0; i < new_list.size(); ++i) {
      if (old_head && IsA<HTMLHeadElement>(*new_list[i]->node_))
        merges.Set(new_list[i].Get(), old_head);
      if (old_body && IsA<HTMLBodyElement>(*new_list[i]->node_))
        merges.Set(new_list[i].Get(), old_body);
    }
  }

  // 2. Patch nodes marked for merge.
  for (auto& merge : merges) {
    if (!InnerPatchNode(merge.value, merge.key, exception_state))
      return false;
  }

  // 3. Insert missing nodes.
  for (wtf_size_t i = 0; i < new_map.size(); ++i) {
    if (new_map[i].first || merges.Contains(new_list[i].Get()))
      continue;
    if (!InsertBeforeAndMarkAsUsed(parent_node, new_list[i].Get(),
                                   NodeTraversal::ChildAt(*parent_node, i),
                                   exception_state))
      return false;
  }

  // 4. Then put all nodes that retained into their slots (sort by new index).
  for (wtf_size_t i = 0; i < old_map.size(); ++i) {
    if (!old_map[i].first)
      continue;
    Node* node = old_map[i].first->node_;
    Node* anchor_node = NodeTraversal::ChildAt(*parent_node, old_map[i].second);
    if (node == anchor_node)
      continue;
    if (IsA<HTMLBodyElement>(*node) || IsA<HTMLHeadElement>(*node)) {
      // Never move head or body, move the rest of the nodes around them.
      continue;
    }

    if (!dom_editor_->InsertBefore(parent_node, node, anchor_node,
                                   exception_state))
      return false;
  }
  return true;
}

DOMPatchSupport::Digest* DOMPatchSupport::CreateDigest(
    Node* node,
    UnusedNodesMap* unused_nodes_map) {
  Digest* digest = MakeGarbageCollected<Digest>(node);
  Digestor digestor(kHashAlgorithmSha1);
  DigestValue digest_result;

  Node::NodeType node_type = node->getNodeType();
  digestor.Update(base::byte_span_from_ref(node_type));
  digestor.UpdateUtf8(node->nodeName());
  digestor.UpdateUtf8(node->nodeValue());

  if (auto* element = DynamicTo<Element>(node)) {
    Node* child = element->firstChild();
    while (child) {
      Digest* child_info = CreateDigest(child, unused_nodes_map);
      digestor.UpdateUtf8(child_info->sha1_);
      child = child->nextSibling();
      digest->children_.push_back(child_info);
    }

    AttributeCollection attributes = element->AttributesWithoutUpdate();
    if (!attributes.IsEmpty()) {
      Digestor attrs_digestor(kHashAlgorithmSha1);
      for (auto& attribute : attributes) {
        attrs_digestor.UpdateUtf8(attribute.GetName().ToString());
        attrs_digestor.UpdateUtf8(attribute.Value().GetString());
      }

      attrs_digestor.Finish(digest_result);
      DCHECK(!attrs_digestor.has_failed());
      digest->attrs_sha1_ =
          Base64Encode(base::make_span(digest_result).first<10>());
      digestor.UpdateUtf8(digest->attrs_sha1_);
    }
  }

  digestor.Finish(digest_result);
  DCHECK(!digestor.has_failed());
  digest->sha1_ = Base64Encode(base::make_span(digest_result).first<10>());

  if (unused_nodes_map)
    unused_nodes_map->insert(digest->sha1_, digest);
  return digest;
}

bool DOMPatchSupport::InsertBeforeAndMarkAsUsed(
    ContainerNode* parent_node,
    Digest* digest,
    Node* anchor,
    ExceptionState& exception_state) {
  bool result = dom_editor_->InsertBefore(parent_node, digest->node_, anchor,
                                          exception_state);
  MarkNodeAsUsed(digest);
  return result;
}

bool DOMPatchSupport::RemoveChildAndMoveToNew(Digest* old_digest,
                                              ExceptionState& exception_state) {
  Node* old_node = old_digest->node_;
  if (!dom_editor_->RemoveChild(old_node->parentNode(), old_node,
                                exception_state))
    return false;

  // Diff works within levels. In order not to lose the node identity when user
  // prepends their HTML with "<div>" (i.e. all nodes are shifted to the next
  // nested level), prior to dropping the original node on the floor, check
  // whether new DOM has a digest with matching sha1. If it does, replace it
  // with the original DOM chunk.  Chances are high that it will get merged back
  // into the original DOM during the further patching.
  UnusedNodesMap::iterator it = unused_nodes_map_.find(old_digest->sha1_);
  if (it != unused_nodes_map_.end()) {
    Digest* new_digest = it->value;
    Node* new_node = new_digest->node_;
    if (!dom_editor_->ReplaceChild(new_node->parentNode(), old_node, new_node,
                                   exception_state))
      return false;
    new_digest->node_ = old_node;
    MarkNodeAsUsed(new_digest);
    return true;
  }

  for (wtf_size_t i = 0; i < old_digest->children_.size(); ++i) {
    if (!RemoveChildAndMoveToNew(old_digest->children_[i].Get(),
                                 exception_state))
      return false;
  }
  return true;
}

void DOMPatchSupport::MarkNodeAsUsed(Digest* digest) {
  HeapDeque<Member<Digest>> queue;
  queue.push_back(digest);
  while (!queue.empty()) {
    Digest* first = queue.TakeFirst();
    unused_nodes_map_.erase(first->sha1_);
    for (wtf_size_t i = 0; i < first->children_.size(); ++i)
      queue.push_back(first->children_[i].Get());
  }
}

void DOMPatchSupport::Digest::Trace(Visitor* visitor) const {
  visitor->Trace(node_);
  visitor->Trace(children_);
}

}  // namespace blink

"""

```