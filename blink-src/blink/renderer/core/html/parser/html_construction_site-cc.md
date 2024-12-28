Response:
The user wants a summary of the functionalities of the `html_construction_site.cc` file in the Chromium Blink engine. I need to identify its core responsibilities related to HTML parsing and construction. The prompt also asks for connections to JavaScript, HTML, and CSS, along with examples, logical reasoning with input/output, common usage errors, and finally a general summary of the first part of the file.

**Plan:**

1. **Identify Core Functionalities:**  Scan the code for key classes, methods, and data structures to understand the primary tasks of `HTMLConstructionSite`. Look for keywords like "insert," "create," "attach," "flush," "queue," "stack," "parser," etc.
2. **Relate to Web Technologies:**  Analyze how the file interacts with HTML (structure), CSS (style application, though less directly here), and JavaScript (script execution and DOM manipulation). Provide concrete examples of how the code handles specific HTML elements or attributes.
3. **Logical Reasoning (Hypothetical Input/Output):**  Imagine a simple HTML snippet and trace how `HTMLConstructionSite` might process it. Consider the input token stream and the resulting DOM structure.
4. **Common Usage Errors:** Think about scenarios where incorrect or malformed HTML might lead to issues within this part of the parsing process. These are more about the *parser's* handling of errors rather than direct user/programmer errors in *using* this specific class.
5. **Summarize Part 1:**  Condense the identified functionalities and observations into a concise summary covering the provided code snippet.
```cpp
  gImpl::Create8BitIfPossible(token->SystemIdentifier());

  DocumentType* doctype =
      MakeGarbageCollected<DocumentType>(*document_, token->Name());
  doctype->SetPublicId(public_id);
  doctype->SetSystemId(system_id);

  AttachLater(attachment_root_, doctype, token->GetDOMPartsNeeded());

  // Set the compatibility mode as soon as we see the doctype.
  SetCompatibilityModeFromDoctype(token->Name(), public_id, system_id);

  ExecuteQueuedTasks();
  doctype->InsertedByParser();
}

void HTMLConstructionSite::InsertComment(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::COMMENT);
  Comment* comment =
      Comment::Create(OwnerDocumentForCurrentNode(), token->Comment());
  AttachLater(CurrentNode(), comment, token->GetDOMPartsNeeded());
  ExecuteQueuedTasks();
}

void HTMLConstructionSite::InsertText(bool should_decode_entities,
                                      AtomicHTMLToken* token) {
  DCHECK(token->GetType() == HTMLToken::CHARACTER ||
         token->GetType() == HTMLToken::WHITESPACE);

  ContainerNode* parent = CurrentNode();
  // If we have a bunch of text queued up, and we are about to insert more text
  // into the same parent, just append to the existing text node.
  if (parent == pending_text_.parent &&
      pending_text_.next_child == nullptr) {
    pending_text_.Append(token->Data());
    if (token->GetType() == HTMLToken::CHARACTER)
      pending_text_.SetNotAllWhitespace();
    return;
  }

  FlushPendingText();
  DCHECK(pending_text_.IsEmpty());

  HTMLConstructionSitePendingText new_pending_text(parent);
  new_pending_text.Append(token->Data());
  if (token->GetType() == HTMLToken::CHARACTER)
    new_pending_text.SetNotAllWhitespace();
  pending_text_ = new_pending_text;
}

void HTMLConstructionSite::InsertPendingText(ContainerNode* parent,
                                             Node* next_child) {
  DCHECK(!pending_text_.IsEmpty());
  DCHECK(!pending_text_.parent);
  DCHECK(!pending_text_.next_child);
  pending_text_.parent = parent;
  pending_text_.next_child = next_child;
  FlushPendingText();
}

Element* HTMLConstructionSite::CreateElement(AtomicHTMLToken* token) {
  DCHECK(token->IsStartTag());
  // We know the node is an Element, but we don't know the Element Subclass yet.
  // Let the factory create the right kind of Element.
  Element* element =
      HTMLElementFactory::CreateHTMLElement(QualifiedName(token->GetName()),
                                           OwnerDocumentForCurrentNode());
  if (IsA<HTMLScriptElement>(element) || IsA<HTMLStyleElement>(element) ||
      IsA<SVGScriptElement>(element))
    element->SetShouldPreventScriptExecution(
        !is_scripting_content_allowed_);
  return element;
}

Element* HTMLConstructionSite::CreateHTMLElementOrTemplateContent(
    AtomicHTMLToken* token) {
  DCHECK(token->IsStartTag());
  if (token->GetHTMLTag() == html_names::HTMLTag::kTemplate) {
    HTMLTemplateElement* template_element =
        MakeGarbageCollected<HTMLTemplateElement>(OwnerDocumentForCurrentNode());
    return template_element->TemplateContentOrDeclarativeShadowRoot();
  }
  return CreateElement(token);
}

void HTMLConstructionSite::InsertHTMLElement(AtomicHTMLToken* token) {
  DCHECK(token->IsStartTag());
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  FlushPendingText();
  Element* element = CreateElement(token);
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertForeignElement(AtomicHTMLToken* token,
                                               const AtomicString& namespace_uri) {
  DCHECK(token->IsStartTag());
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-a-foreign-element
  FlushPendingText();
  Element* element = document_->CreateElement(
      QualifiedName(token->GetName(), namespace_uri));
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded(),
              token->IsSelfClosing());
  open_elements_.PushForeignElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertSelfClosingHTMLElement(AtomicHTMLToken* token) {
  DCHECK(token->IsStartTag());
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#acknowledge-self-closing-flag
  FlushPendingText();
  Element* element = CreateElement(token);
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded(), true);
  if (!token->IsSelfClosing())
    open_elements_.PushHTMLElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
  if (token->IsSelfClosing())
    element->FinishParsingChildren();
}

void HTMLConstructionSite::InsertHTMLTemplateElement(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetHTMLTag(), html_names::HTMLTag::kTemplate);
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  FlushPendingText();
  HTMLTemplateElement* element =
      MakeGarbageCollected<HTMLTemplateElement>(OwnerDocumentForCurrentNode());
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertHTMLHeadElement(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetHTMLTag(), html_names::HTMLTag::kHead);
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  FlushPendingText();
  HTMLHeadElement* element = MakeGarbageCollected<HTMLHeadElement>(
      OwnerDocumentForCurrentNode());
  SetAttributes(element, token);
  AttachLater(open_elements_.HtmlElement(), element,
              token->GetDOMPartsNeeded());
  open_elements_.SetHeadElement(HTMLStackItem::Create(element, token));
  head_ = element;

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertHTMLBodyElement(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetHTMLTag(), html_names::HTMLTag::kBody);
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  FlushPendingText();
  HTMLBodyElement* element = MakeGarbageCollected<HTMLBodyElement>(
      OwnerDocumentForCurrentNode());
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.SetBodyElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertHTMLFormElement(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetHTMLTag(), html_names::HTMLTag::kForm);
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-html-element
  FlushPendingText();
  HTMLFormElement* element = MakeGarbageCollected<HTMLFormElement>(
      OwnerDocumentForCurrentNode());
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLFormElement(HTMLStackItem::Create(element, token));
  form_ = element;

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertHTMLPluginElement(AtomicHTMLToken* token) {
  DCHECK(token->GetHTMLTag() == html_names::HTMLTag::kApplet ||
         token->GetHTMLTag() == html_names::HTMLTag::kEmbed ||
         token->GetHTMLTag() == html_names::HTMLTag::kObject);
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/the-end.html#insert-an-object-element
  FlushPendingText();
  HTMLPlugInElement* element = To<HTMLPlugInElement>(CreateElement(token));
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::PopElement(
    const HTMLStackItem::ElementAndNamespace& element_and_namespace) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#generate-implied-end-tags
  while (HasImpliedEndTag(open_elements_.Top()))
    open_elements_.Pop();

  if (open_elements_.Top() != element_and_namespace) {
    // This is only for error recovery.
    return;
  }

  open_elements_.Pop();
}

void HTMLConstructionSite::InsertElement(Element* element) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-element
  FlushPendingText();
  AttachLater(CurrentNode(), element, DOMPartsNeeded());
  open_elements_.PushHTMLElement(HTMLStackItem::Create(element, nullptr));
  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::InsertFormattingElement(AtomicHTMLToken* token) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-element-for-the-token
  FlushPendingText();
  Element* element = CreateElement(token);
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushActiveFormattingElement(
      HTMLStackItem::Create(element, token));
  active_formatting_elements_.Append(element);

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::PushActiveFormattingElement(Element* element) {
  open_elements_.PushActiveFormattingElement(
      HTMLStackItem::Create(element, nullptr));
  active_formatting_elements_.Append(element);
}

void HTMLConstructionSite::InsertGenericElement(AtomicHTMLToken* token) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-an-element-for-the-token
  FlushPendingText();
  Element* element = CreateElement(token);
  SetAttributes(element, token);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::GenerateImpliedEndTagsWithExclusion(
    html_names::HTMLTag excluded_tag) {
  while (HasImpliedEndTag(open_elements_.Top()) &&
         open_elements_.Top()->GetHTMLTag() != excluded_tag)
    open_elements_.Pop();
}

void HTMLConstructionSite::GenerateImpliedEndTags() {
  while (HasImpliedEndTag(open_elements_.Top()))
    open_elements_.Pop();
}

void HTMLConstructionSite::ாதThis section of the `html_construction_site.cc` file in the Chromium Blink engine is primarily responsible for **building the Document Object Model (DOM) tree from the stream of HTML tokens generated by the HTML parser.** It acts as a stateful builder, managing the hierarchy of elements and text nodes as the parsing progresses.

Here's a breakdown of its key functionalities:

*   **Element Creation and Insertion:**
    *   It creates various DOM nodes (Elements, Text nodes, Comments, DocumentType) based on the parsed HTML tokens.
    *   It manages the insertion of these nodes into the correct location in the DOM tree, respecting the parent-child relationships.
    *   Functions like `InsertHTMLElement`, `InsertForeignElement`, `InsertText`, `InsertComment`, `InsertDoctype` directly handle the creation and attachment of these nodes.
    *   The `AttachLater` function queues up the actual DOM manipulation, allowing for batched operations and handling of scenarios like fostering.

*   **Attribute Handling:**
    *   It sets attributes on created elements using the information from the HTML tokens.
    *   The `SetAttributes` function handles this, including stripping scripting attributes when scripting is disabled.
    *   It detects and reports duplicate attributes.

*   **Maintaining the Parser State:**
    *   It keeps track of the currently open elements using the `open_elements_` stack. This stack is crucial for determining where new nodes should be inserted.
    *   It manages the "active formatting elements" list, which is used for specific HTML formatting rules.
    *   It stores information about the current `<head>` and `<form>` elements encountered.

*   **Handling Text Nodes:**
    *   It efficiently manages the creation and insertion of text nodes, merging adjacent text nodes when possible for optimization.
    *   The `FlushPendingText` function handles the actual insertion of queued text.

*   **Special Element Handling:**
    *   It includes specific logic for handling certain HTML elements like `<html>`, `<head>`, `<body>`, `<template>`, and form elements.

*   **Compatibility Mode:**
    *   It determines and sets the document's compatibility mode (Quirks Mode, Limited Quirks Mode, No Quirks Mode) based on the DOCTYPE declaration.

*   **Error Handling and Recovery:**
    *   While not explicitly focused on error reporting, some logic, like the handling of implied end tags and the `PopElement` function, contributes to error recovery during parsing.

*   **Integration with Other Blink Components:**
    *   It interacts with the `HTMLElementFactory` to create specific element types.
    *   It uses `UseCounter` to track usage of certain HTML features (like duplicate attributes or exceeding DOM tree depth).

**Relationship to JavaScript, HTML, and CSS:**

*   **HTML:** This file is fundamental to HTML parsing. It takes the raw HTML structure (represented as tokens) and transforms it into the DOM, the in-memory representation of the HTML document. The functions within this file directly correspond to the rules of HTML parsing and how different HTML elements and attributes should be handled. For example:
    *   When a `<p>` start tag token is encountered, `InsertHTMLElement` (or a similar function) is called, creating an `HTMLParagraphElement` and adding it to the DOM under the appropriate parent.
    *   When attributes like `class="my-class"` are present in a start tag token, the `SetAttributes` function adds these attributes to the newly created element.

*   **JavaScript:**  While this file itself doesn't execute JavaScript, the DOM it builds is the very structure that JavaScript interacts with. The presence and structure of elements in the DOM, as determined by this file, dictate how JavaScript can access and manipulate the page.
    *   **Example:** If the HTML contains `<div id="myDiv"></div>`, this file ensures that a `HTMLDivElement` with the ID "myDiv" is created and inserted into the DOM. Later, JavaScript code can use `document.getElementById('myDiv')` to access this element.
    *   The handling of `<script>` tags is also relevant. This file determines where the script element is placed in the DOM, which affects when and how the script will be executed by the JavaScript engine.

*   **CSS:**  The DOM built by this file is what CSS selectors target. The structure and attributes of elements determine how CSS rules are applied.
    *   **Example:** If the HTML is `<p class="important">Some text</p>`, this file creates the `<p>` element and sets its `class` attribute. A CSS rule like `.important { color: red; }` will then apply to this element based on the class attribute set by this code.
    *   The presence of `<style>` tags and the parsing of their content (handled elsewhere in Blink) also relies on the basic DOM structure being built by this file.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:** A simple HTML snippet:

```html
<div>Hello</div>
```

**Processing Steps:**

1. The HTML parser generates a start tag token for `<div>`.
2. `InsertHTMLElement` is likely called.
3. `CreateElement` creates an `HTMLDivElement`.
4. `SetAttributes` is called (no attributes in this case).
5. `AttachLater` queues the insertion of the `<div>` into the current parent (likely the `<body>`).
6. The HTML parser generates a character token for "Hello".
7. `InsertText` is called, and "Hello" is added to the `pending_text_`.
8. The HTML parser generates an end tag token for `</div>`.
9. The appropriate closing logic is triggered, and `FlushPendingText` is called, creating a text node with "Hello" as data and inserting it as a child of the `<div>`.

**Hypothetical Output (Simplified DOM structure):**

```
HTMLElement (html)
  HTMLBodyElement (body)
    HTMLDivElement (div)
      Text (Hello)
```

**Common User or Programming Usage Errors (Relating to Parser Behavior):**

It's important to note that developers don't directly interact with `HTMLConstructionSite`. The errors discussed here relate to how the *parser* handles incorrect HTML, which is what this class is designed to process.

*   **Unclosed Tags:** If the input is `<div>Hello`, the parser (and this class) will likely try to infer the closing tag based on the parsing rules. This might lead to a DOM structure that is different from what the author intended. The `GenerateImpliedEndTags` functionality is part of this error correction process.
*   **Misnested Tags:**  For example, `<p><div></p></div>`. The parser has rules to handle such cases, potentially closing the `<p>` tag prematurely when it encounters the `<div>` start tag. `HTMLConstructionSite` will follow these parsing rules to build a potentially unexpected DOM structure.
*   **Incorrect DOCTYPE:**  A malformed or missing DOCTYPE can lead to the document being rendered in Quirks Mode, as handled by the `SetCompatibilityModeFromDoctype` function. This changes how CSS is interpreted and can lead to layout differences.

**Summary of Part 1:**

The first part of `html_construction_site.cc` focuses on the foundational aspects of building the DOM tree during HTML parsing. It handles the creation and insertion of basic DOM nodes (elements and text), attribute assignment, and the management of the parser's state related to open elements. It lays the groundwork for processing various HTML constructs and interacts with other Blink components to create the correct DOM representation of the HTML document. It also includes logic for handling text efficiently and setting the document's compatibility mode based on the DOCTYPE.

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_construction_site.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 * Copyright (C) 2011 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GOOGLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_construction_site.h"

#include <limits>

#include "base/notreached.h"
#include "third_party/blink/renderer/core/dom/attribute_part.h"
#include "third_party/blink/renderer/core/dom/child_node_part.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_part.h"
#include "third_party/blink/renderer/core/dom/template_content_document_fragment.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/throw_on_dynamic_markup_insertion_count_incrementer.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/custom/ce_reactions_scope.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_descriptor.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/forms/form_associated.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/atomic_html_token.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_reentry_permit.h"
#include "third_party/blink/renderer/core/html/parser/html_stack_item.h"
#include "third_party/blink/renderer/core/html/parser/html_token.h"
#include "third_party/blink/renderer/core/html_element_factory.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/script/ignore_destructive_write_count_incrementer.h"
#include "third_party/blink/renderer/core/svg/svg_script_element.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

void HTMLConstructionSite::SetAttributes(Element* element,
                                         AtomicHTMLToken* token) {
  if (!is_scripting_content_allowed_)
    element->StripScriptingAttributes(token->Attributes());
  element->ParserSetAttributes(token->Attributes());
  if (token->HasDuplicateAttribute()) {
    // UseCounter is not free, and only the first call matters. Only call to it
    // if necessary.
    if (!reported_duplicate_attribute_) {
      reported_duplicate_attribute_ = true;
      UseCounter::Count(element->GetDocument(),
                        WebFeature::kDuplicatedAttribute);
    }
    element->SetHasDuplicateAttributes();
  }
}

static bool HasImpliedEndTag(const HTMLStackItem* item) {
  switch (item->GetHTMLTag()) {
    case html_names::HTMLTag::kDd:
    case html_names::HTMLTag::kDt:
    case html_names::HTMLTag::kLi:
    case html_names::HTMLTag::kOption:
    case html_names::HTMLTag::kOptgroup:
    case html_names::HTMLTag::kP:
    case html_names::HTMLTag::kRb:
    case html_names::HTMLTag::kRp:
    case html_names::HTMLTag::kRt:
    case html_names::HTMLTag::kRTC:
      return item->IsHTMLNamespace();
    default:
      return false;
  }
}

static bool ShouldUseLengthLimit(const ContainerNode& node) {
  if (auto* html_element = DynamicTo<HTMLElement>(&node)) {
    return !html_element->HasTagName(html_names::kScriptTag) &&
           !html_element->HasTagName(html_names::kStyleTag);
  }
  return !IsA<SVGScriptElement>(node);
}

static unsigned NextTextBreakPositionForContainer(
    const ContainerNode& node,
    unsigned current_position,
    unsigned string_length,
    std::optional<unsigned>& length_limit) {
  if (string_length < Text::kDefaultLengthLimit)
    return string_length;
  if (!length_limit) {
    length_limit = ShouldUseLengthLimit(node)
                       ? Text::kDefaultLengthLimit
                       : std::numeric_limits<unsigned>::max();
  }
  return std::min(current_position + *length_limit, string_length);
}

static inline WhitespaceMode RecomputeWhiteSpaceMode(
    const StringView& string_view) {
  DCHECK(!string_view.empty());
  if (string_view[0] != '\n') {
    return string_view.IsAllSpecialCharacters<IsHTMLSpace<UChar>>()
               ? WhitespaceMode::kAllWhitespace
               : WhitespaceMode::kNotAllWhitespace;
  }

  auto check_whitespace = [](auto* buffer, size_t length) {
    WhitespaceMode result = WhitespaceMode::kNewlineThenWhitespace;
    for (size_t i = 1; i < length; ++i) {
      if (buffer[i] == ' ') [[likely]] {
        continue;
      } else if (IsHTMLSpecialWhitespace(buffer[i])) {
        result = WhitespaceMode::kAllWhitespace;
      } else {
        return WhitespaceMode::kNotAllWhitespace;
      }
    }
    return result;
  };

  if (string_view.Is8Bit()) {
    return check_whitespace(string_view.Characters8(), string_view.length());
  } else {
    return check_whitespace(string_view.Characters16(), string_view.length());
  }
}

enum class RecomputeMode {
  kDontRecompute,
  kRecomputeIfNeeded,
};

// Strings composed entirely of whitespace are likely to be repeated. Turn them
// into AtomicString so we share a single string for each.
static String CheckWhitespaceAndConvertToString(const StringView& string,
                                                WhitespaceMode whitespace_mode,
                                                RecomputeMode recompute_mode) {
  switch (whitespace_mode) {
    case WhitespaceMode::kNewlineThenWhitespace:
      DCHECK(WTF::NewlineThenWhitespaceStringsTable::IsNewlineThenWhitespaces(
          string));
      if (string.length() <
          WTF::NewlineThenWhitespaceStringsTable::kTableSize) {
        return WTF::NewlineThenWhitespaceStringsTable::GetStringForLength(
            string.length());
      }
      [[fallthrough]];
    case WhitespaceMode::kAllWhitespace:
      return string.ToAtomicString().GetString();
    case WhitespaceMode::kNotAllWhitespace:
      // Other strings are pretty random and unlikely to repeat.
      return string.ToString();
    case WhitespaceMode::kWhitespaceUnknown:
      DCHECK_EQ(RecomputeMode::kRecomputeIfNeeded, recompute_mode);
      return CheckWhitespaceAndConvertToString(string,
                                               RecomputeWhiteSpaceMode(string),
                                               RecomputeMode::kDontRecompute);
  }
}

static String TryCanonicalizeString(const StringView& string,
                                    WhitespaceMode mode) {
  return CheckWhitespaceAndConvertToString(string, mode,
                                           RecomputeMode::kRecomputeIfNeeded);
}

static inline void Insert(HTMLConstructionSiteTask& task) {
  // https://html.spec.whatwg.org/multipage/parsing.html#appropriate-place-for-inserting-a-node
  // 3. If the adjusted insertion location is inside a template element, let it
  // instead be inside the template element's template contents, after its last
  // child (if any).
  if (auto* template_element = DynamicTo<HTMLTemplateElement>(*task.parent)) {
    task.parent = template_element->TemplateContentOrDeclarativeShadowRoot();
    // If the Document was detached in the middle of parsing, The template
    // element won't be able to initialize its contents, so bail out.
    if (!task.parent)
      return;
  }

  // https://html.spec.whatwg.org/C/#insert-a-foreign-element
  // 3.1, (3) Push (pop) an element queue
  CEReactionsScope reactions;
  if (task.next_child)
    task.parent->ParserInsertBefore(task.child.Get(), *task.next_child);
  else
    task.parent->ParserAppendChild(task.child.Get());
}

static inline void ExecuteInsertTask(HTMLConstructionSiteTask& task) {
  DCHECK_EQ(task.operation, HTMLConstructionSiteTask::kInsert);

  Insert(task);
  if (auto* child = DynamicTo<Element>(task.child.Get())) {
    child->BeginParsingChildren();
    if (task.self_closing)
      child->FinishParsingChildren();
  }
}

static inline unsigned TextFitsInContainer(const ContainerNode& node,
                                           unsigned length) {
  // Common case is all text fits in the default text limit. Only lookup length
  // limit when necessary as it is costly.
  return length < Text::kDefaultLengthLimit || !ShouldUseLengthLimit(node);
}

static inline void ExecuteInsertTextTask(HTMLConstructionSiteTask& task) {
  DCHECK_EQ(task.operation, HTMLConstructionSiteTask::kInsertText);

  // Merge text nodes into previous ones if possible:
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#insert-a-character
  auto* new_text = To<Text>(task.child.Get());
  Node* previous_child = task.next_child ? task.next_child->previousSibling()
                                         : task.parent->lastChild();
  if (auto* previous_text = DynamicTo<Text>(previous_child)) {
    if (TextFitsInContainer(*task.parent,
                            previous_text->length() + new_text->length())) {
      previous_text->ParserAppendData(new_text->data());
      return;
    }
  }

  Insert(task);
}

static inline void ExecuteReparentTask(HTMLConstructionSiteTask& task) {
  DCHECK_EQ(task.operation, HTMLConstructionSiteTask::kReparent);

  task.parent->ParserAppendChild(task.child);
}

static inline void ExecuteInsertAlreadyParsedChildTask(
    HTMLConstructionSiteTask& task) {
  DCHECK_EQ(task.operation,
            HTMLConstructionSiteTask::kInsertAlreadyParsedChild);

  Insert(task);
}

static inline void ExecuteTakeAllChildrenTask(HTMLConstructionSiteTask& task) {
  DCHECK_EQ(task.operation, HTMLConstructionSiteTask::kTakeAllChildren);

  task.parent->ParserTakeAllChildrenFrom(*task.OldParent());
}

void HTMLConstructionSite::ExecuteTask(HTMLConstructionSiteTask& task) {
  DCHECK(task_queue_.empty());
  if (task.operation == HTMLConstructionSiteTask::kInsert) {
    ExecuteInsertTask(task);
    if (pending_dom_parts_) {
      DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
      if (RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
        if (task.dom_parts_needed.needs_node_part) {
          // Just mark the node as having a node part.
          task.child->SetHasNodePart();
        }
      } else {
        pending_dom_parts_->ConstructDOMPartsIfNeeded(*task.child,
                                                      task.dom_parts_needed);
      }
    }
    return;
  }

  if (task.operation == HTMLConstructionSiteTask::kInsertText) {
    ExecuteInsertTextTask(task);
    if (pending_dom_parts_) {
      DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
      if (RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
        if (task.dom_parts_needed.needs_node_part) {
          // Just mark the node as having a node part.
          task.child->SetHasNodePart();
        }
      } else {
        pending_dom_parts_->ConstructDOMPartsIfNeeded(*task.child,
                                                      task.dom_parts_needed);
      }
    }
    return;
  }

  // All the cases below this point are only used by the adoption agency.
  DCHECK(!task.dom_parts_needed);

  if (task.operation == HTMLConstructionSiteTask::kInsertAlreadyParsedChild)
    return ExecuteInsertAlreadyParsedChildTask(task);

  if (task.operation == HTMLConstructionSiteTask::kReparent)
    return ExecuteReparentTask(task);

  if (task.operation == HTMLConstructionSiteTask::kTakeAllChildren)
    return ExecuteTakeAllChildrenTask(task);

  NOTREACHED();
}

// This is only needed for TextDocuments where we might have text nodes
// approaching the default length limit (~64k) and we don't want to break a text
// node in the middle of a combining character.
static unsigned FindBreakIndexBetween(const StringBuilder& string,
                                      unsigned current_position,
                                      unsigned proposed_break_index) {
  DCHECK_LT(current_position, proposed_break_index);
  DCHECK_LE(proposed_break_index, string.length());
  // The end of the string is always a valid break.
  if (proposed_break_index == string.length())
    return proposed_break_index;

  // Latin-1 does not have breakable boundaries. If we ever moved to a different
  // 8-bit encoding this could be wrong.
  if (string.Is8Bit())
    return proposed_break_index;

  // We need at least two characters look-ahead to account for UTF-16
  // surrogates, but can't search off the end of the buffer!
  unsigned break_search_length =
      std::min(proposed_break_index - current_position + 2,
               string.length() - current_position);
  NonSharedCharacterBreakIterator it(
      string.Span16().subspan(current_position, break_search_length));

  if (it.IsBreak(proposed_break_index - current_position))
    return proposed_break_index;

  int adjusted_break_index_in_substring =
      it.Preceding(proposed_break_index - current_position);
  if (adjusted_break_index_in_substring > 0)
    return current_position + adjusted_break_index_in_substring;
  // We failed to find a breakable point, let the caller figure out what to do.
  return 0;
}

void HTMLConstructionSite::FlushPendingText() {
  if (pending_text_.IsEmpty())
    return;

  // Splitting text nodes into smaller chunks contradicts HTML5 spec, but is
  // necessary for performance, see:
  // https://bugs.webkit.org/show_bug.cgi?id=55898

  // Lazily determine the line limit as it's non-trivial, and in the typical
  // case not necessary. Note that this is faster than using a ternary operator
  // to determine limit.
  std::optional<unsigned> length_limit;

  unsigned current_position = 0;
  const StringBuilder& string = pending_text_.string_builder;
  while (current_position < string.length()) {
    unsigned proposed_break_index = NextTextBreakPositionForContainer(
        *pending_text_.parent, current_position, string.length(), length_limit);
    unsigned break_index =
        FindBreakIndexBetween(string, current_position, proposed_break_index);
    DCHECK_LE(break_index, string.length());
    if (!break_index) {
      // FindBreakIndexBetween returns 0 if it cannot find a breakpoint. In this
      // case, just keep the entire string.
      break_index = string.length();
    }
    unsigned substring_view_length = break_index - current_position;
    StringView substring_view;
    if (!current_position && substring_view_length >= string.length())
        [[likely]] {
      substring_view = string;
    } else {
      substring_view = string.SubstringView(current_position,
                                            break_index - current_position);
    }
    String substring =
        TryCanonicalizeString(substring_view, pending_text_.whitespace_mode);

    DCHECK_GT(break_index, current_position);
    DCHECK_EQ(break_index - current_position, substring.length());
    HTMLConstructionSiteTask task(HTMLConstructionSiteTask::kInsertText);
    task.parent = pending_text_.parent;
    task.next_child = pending_text_.next_child;
    task.child = Text::Create(task.parent->GetDocument(), std::move(substring));
    QueueTask(task, false);
    DCHECK_EQ(To<Text>(task.child.Get())->length(),
              break_index - current_position);
    current_position = break_index;
  }
  pending_text_.Discard();
}

void HTMLConstructionSite::QueueTask(const HTMLConstructionSiteTask& task,
                                     bool flush_pending_text) {
  if (flush_pending_text)
    FlushPendingText();
  task_queue_.push_back(task);
}

void HTMLConstructionSite::AttachLater(ContainerNode* parent,
                                       Node* child,
                                       const DOMPartsNeeded& dom_parts_needed,
                                       bool self_closing) {
  auto* element = DynamicTo<Element>(child);
  DCHECK(is_scripting_content_allowed_ || !element ||
         !element->IsScriptElement());
  DCHECK(PluginContentIsAllowed(parser_content_policy_) ||
         !IsA<HTMLPlugInElement>(child));

  HTMLConstructionSiteTask task(HTMLConstructionSiteTask::kInsert);
  task.parent = parent;
  task.child = child;
  task.self_closing = self_closing;
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled() || !dom_parts_needed);
  task.dom_parts_needed = dom_parts_needed;

  if (ShouldFosterParent()) {
    FosterParent(task.child);
    return;
  }

  // Add as a sibling of the parent if we have reached the maximum depth
  // allowed.
  if (open_elements_.StackDepth() > kMaximumHTMLParserDOMTreeDepth &&
      task.parent->parentNode()) {
    UseCounter::Count(OwnerDocumentForCurrentNode(),
                      WebFeature::kMaximumHTMLParserDOMTreeDepthHit);
    task.parent = task.parent->parentNode();
  }

  DCHECK(task.parent);
  QueueTask(task, true);
}

void HTMLConstructionSite::ExecuteQueuedTasks() {
  // This has no affect on pendingText, and we may have pendingText remaining
  // after executing all other queued tasks.
  const size_t size = task_queue_.size();
  if (!size)
    return;

  // Fast path for when |size| is 1, which is the common case
  if (size == 1) {
    HTMLConstructionSiteTask task = task_queue_.front();
    task_queue_.pop_back();
    ExecuteTask(task);
    return;
  }

  // Copy the task queue into a local variable in case executeTask re-enters the
  // parser.
  TaskQueue queue;
  queue.swap(task_queue_);

  for (auto& task : queue)
    ExecuteTask(task);

  // We might be detached now.
}

HTMLConstructionSite::HTMLConstructionSite(
    HTMLParserReentryPermit* reentry_permit,
    Document& document,
    ParserContentPolicy parser_content_policy,
    DocumentFragment* fragment,
    Element* context_element)
    : reentry_permit_(reentry_permit),
      document_(&document),
      attachment_root_(fragment ? fragment
                                : static_cast<ContainerNode*>(&document)),
      pending_dom_parts_(
          RuntimeEnabledFeatures::DOMPartsAPIEnabled()
              ? MakeGarbageCollected<PendingDOMParts>(attachment_root_)
              : nullptr),
      parser_content_policy_(parser_content_policy),
      is_scripting_content_allowed_(
          ScriptingContentIsAllowed(parser_content_policy)),
      is_parsing_fragment_(fragment),
      redirect_attach_to_foster_parent_(false),
      in_quirks_mode_(document.InQuirksMode()) {
  DCHECK(document_->IsHTMLDocument() || document_->IsXHTMLDocument() ||
         is_parsing_fragment_);

  DCHECK_EQ(!fragment, !context_element);
  if (fragment) {
    DCHECK_EQ(document_, &fragment->GetDocument());
    DCHECK_EQ(in_quirks_mode_, fragment->GetDocument().InQuirksMode());
    if (!context_element->GetDocument().IsTemplateDocument()) {
      form_ = Traversal<HTMLFormElement>::FirstAncestorOrSelf(*context_element);
    }
  }
}

HTMLConstructionSite::~HTMLConstructionSite() {
  // Depending on why we're being destroyed it might be OK to forget queued
  // tasks, but currently we don't expect to.
  DCHECK(task_queue_.empty());
  // Currently we assume that text will never be the last token in the document
  // and that we'll always queue some additional task to cause it to flush.
  DCHECK(pending_text_.IsEmpty());
}

void HTMLConstructionSite::Trace(Visitor* visitor) const {
  visitor->Trace(reentry_permit_);
  visitor->Trace(document_);
  visitor->Trace(attachment_root_);
  visitor->Trace(head_);
  visitor->Trace(form_);
  visitor->Trace(open_elements_);
  visitor->Trace(active_formatting_elements_);
  visitor->Trace(task_queue_);
  visitor->Trace(pending_text_);
  visitor->Trace(pending_dom_parts_);
}

void HTMLConstructionSite::Detach() {
  // FIXME: We'd like to ASSERT here that we're canceling and not just
  // discarding text that really should have made it into the DOM earlier, but
  // there doesn't seem to be a nice way to do that.
  pending_text_.Discard();
  document_ = nullptr;
  attachment_root_ = nullptr;
}

HTMLFormElement* HTMLConstructionSite::TakeForm() {
  return form_.Release();
}

void HTMLConstructionSite::InsertHTMLHtmlStartTagBeforeHTML(
    AtomicHTMLToken* token) {
  DCHECK(document_);
  HTMLHtmlElement* element;
  if (const auto* is_attribute = token->GetAttributeItem(html_names::kIsAttr)) {
    element = To<HTMLHtmlElement>(document_->CreateElement(
        html_names::kHTMLTag, GetCreateElementFlags(), is_attribute->Value()));
  } else {
    element = MakeGarbageCollected<HTMLHtmlElement>(*document_);
  }
  SetAttributes(element, token);
  AttachLater(attachment_root_, element, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLHtmlElement(HTMLStackItem::Create(element, token));

  ExecuteQueuedTasks();
  element->InsertedByParser();
}

void HTMLConstructionSite::MergeAttributesFromTokenIntoElement(
    AtomicHTMLToken* token,
    Element* element) {
  if (token->Attributes().empty())
    return;

  for (const auto& token_attribute : token->Attributes()) {
    if (element->AttributesWithoutUpdate().FindIndex(
            token_attribute.GetName()) == kNotFound)
      element->setAttribute(token_attribute.GetName(), token_attribute.Value());
  }

  element->HideNonce();
}

void HTMLConstructionSite::InsertHTMLHtmlStartTagInBody(
    AtomicHTMLToken* token) {
  // Fragments do not have a root HTML element, so any additional HTML elements
  // encountered during fragment parsing should be ignored.
  if (is_parsing_fragment_)
    return;

  MergeAttributesFromTokenIntoElement(token, open_elements_.HtmlElement());
}

void HTMLConstructionSite::InsertHTMLBodyStartTagInBody(
    AtomicHTMLToken* token) {
  MergeAttributesFromTokenIntoElement(token, open_elements_.BodyElement());
}

void HTMLConstructionSite::SetDefaultCompatibilityMode() {
  if (is_parsing_fragment_)
    return;
  SetCompatibilityMode(Document::kQuirksMode);
}

void HTMLConstructionSite::SetCompatibilityMode(
    Document::CompatibilityMode mode) {
  in_quirks_mode_ = (mode == Document::kQuirksMode);
  document_->SetCompatibilityMode(mode);
}

void HTMLConstructionSite::SetCompatibilityModeFromDoctype(
    html_names::HTMLTag tag,
    const String& public_id,
    const String& system_id) {
  // There are three possible compatibility modes:
  // Quirks - quirks mode emulates WinIE and NS4. CSS parsing is also relaxed in
  // this mode, e.g., unit types can be omitted from numbers.
  // Limited Quirks - This mode is identical to no-quirks mode except for its
  // treatment of line-height in the inline box model.
  // No Quirks - no quirks apply. Web pages will obey the specifications to the
  // letter.

  DCHECK(document_->IsHTMLDocument() || document_->IsXHTMLDocument());

  // Check for Quirks Mode.
  if (tag != html_names::HTMLTag::kHTML ||
      public_id.StartsWithIgnoringASCIICase(
          "+//Silmaril//dtd html Pro v0r11 19970101//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//AdvaSoft Ltd//DTD HTML 3.0 asWedit + extensions//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//AS//DTD HTML 3.0 asWedit + extensions//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML 2.0 Level 1//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML 2.0 Level 2//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML 2.0 Strict Level 1//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML 2.0 Strict Level 2//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 2.0 Strict//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 2.0//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 2.1E//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 3.0//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 3.2 Final//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 3.2//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML 3//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML Level 0//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML Level 1//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML Level 2//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML Level 3//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML Strict Level 0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML Strict Level 1//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML Strict Level 2//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//IETF//DTD HTML Strict Level 3//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML Strict//") ||
      public_id.StartsWithIgnoringASCIICase("-//IETF//DTD HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Metrius//DTD Metrius Presentational//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 2.0 HTML Strict//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 2.0 HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 2.0 Tables//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 3.0 HTML Strict//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 3.0 HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Microsoft//DTD Internet Explorer 3.0 Tables//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Netscape Comm. Corp.//DTD HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Netscape Comm. Corp.//DTD Strict HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//O'Reilly and Associates//DTD HTML 2.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//O'Reilly and Associates//DTD HTML Extended 1.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//O'Reilly and Associates//DTD HTML Extended Relaxed 1.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//SoftQuad Software//DTD HoTMetaL PRO "
          "6.0::19990601::extensions to HTML 4.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//SoftQuad//DTD HoTMetaL PRO "
          "4.0::19971010::extensions to HTML 4.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Spyglass//DTD HTML 2.0 Extended//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//SQ//DTD HTML 2.0 HoTMetaL + extensions//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Sun Microsystems Corp.//DTD HotJava HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//Sun Microsystems Corp.//DTD HotJava Strict HTML//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD HTML 3 1995-03-24//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3C//DTD HTML 3.2 Draft//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3C//DTD HTML 3.2 Final//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3C//DTD HTML 3.2//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3C//DTD HTML 3.2S Draft//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD HTML 4.0 Frameset//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD HTML 4.0 Transitional//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD HTML Experimental 19960712//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD HTML Experimental 970421//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3C//DTD W3 HTML//") ||
      public_id.StartsWithIgnoringASCIICase("-//W3O//DTD W3 HTML 3.0//") ||
      EqualIgnoringASCIICase(public_id,
                             "-//W3O//DTD W3 HTML Strict 3.0//EN//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//WebTechs//DTD Mozilla HTML 2.0//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//WebTechs//DTD Mozilla HTML//") ||
      EqualIgnoringASCIICase(public_id, "-/W3C/DTD HTML 4.0 Transitional/EN") ||
      EqualIgnoringASCIICase(public_id, "HTML") ||
      EqualIgnoringASCIICase(
          system_id,
          "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd") ||
      (system_id.empty() && public_id.StartsWithIgnoringASCIICase(
                                "-//W3C//DTD HTML 4.01 Frameset//")) ||
      (system_id.empty() && public_id.StartsWithIgnoringASCIICase(
                                "-//W3C//DTD HTML 4.01 Transitional//"))) {
    SetCompatibilityMode(Document::kQuirksMode);
    return;
  }

  // Check for Limited Quirks Mode.
  if (public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD XHTML 1.0 Frameset//") ||
      public_id.StartsWithIgnoringASCIICase(
          "-//W3C//DTD XHTML 1.0 Transitional//") ||
      (!system_id.empty() && public_id.StartsWithIgnoringASCIICase(
                                 "-//W3C//DTD HTML 4.01 Frameset//")) ||
      (!system_id.empty() && public_id.StartsWithIgnoringASCIICase(
                                 "-//W3C//DTD HTML 4.01 Transitional//"))) {
    SetCompatibilityMode(Document::kLimitedQuirksMode);
    return;
  }

  // Otherwise we are No Quirks Mode.
  SetCompatibilityMode(Document::kNoQuirksMode);
}

void HTMLConstructionSite::ProcessEndOfFile() {
  DCHECK(CurrentNode());
  Flush();
  OpenElements()->PopAll();
}

void HTMLConstructionSite::FinishedParsing() {
  // We shouldn't have any queued tasks but we might have pending text which we
  // need to promote to tasks and execute.
  DCHECK(task_queue_.empty());
  Flush();
  document_->FinishedParsing();
}

void HTMLConstructionSite::InsertDoctype(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::DOCTYPE);

  const String& public_id =
      StringImpl::Create8BitIfPossible(token->PublicIdentifier());
  const String& system_id =
      Strin
"""


```