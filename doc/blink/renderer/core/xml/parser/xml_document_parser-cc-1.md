Response:
My thought process to answer the prompt about the `XMLDocumentParser` code snippet goes like this:

1. **Understand the Goal:** The request asks for the functions of the provided code, focusing on its relation to web technologies (JavaScript, HTML, CSS), providing examples and debugging hints, and summarizing its purpose within the larger `XMLDocumentParser`.

2. **Initial Code Scan and Keyword Identification:** I'll quickly scan the code for key terms and patterns:
    * Function names: `HandleNamespaceAttributes`, `HandleElementAttributes`, `StartElementNs`, `EndElementNs`, `Characters`, `GetProcessingInstruction`, `CdataBlock`, `Comment`, etc. These suggest different parsing events.
    * Data structures: `Vector<Attribute>`, `HashMap<AtomicString, AtomicString>`, `xmlChar**`, `xmlSAX2Namespace`, `xmlSAX2Attributes`. These indicate how XML data is represented.
    * Core web concepts: "namespace," "attribute," "element," "script," "style sheet," "CDATA," "comment," "processing instruction."
    * Control flow and state: `IsStopped()`, `parser_paused_`, `pending_callbacks_`, `StopParsing()`, `ResumeParsing()`. This suggests asynchronous or potentially interruptible parsing.
    * Libxml2 interaction: References to `libxml_namespaces`, `libxml_attributes`, `xmlSAX2Namespace`, `xmlSAX2Attributes`. This highlights the use of an external XML parsing library.

3. **Focus on Core Functionality (Based on Function Names):**

    * **`HandleNamespaceAttributes`:**  This clearly deals with processing namespace declarations within XML elements (like `xmlns:prefix="uri"`).
    * **`HandleElementAttributes`:** This handles regular attributes of an XML element.
    * **`StartElementNs`:** This function is invoked when the parser encounters the beginning of an XML element. It appears to handle namespace resolution, attribute processing, and the creation of corresponding DOM elements. The interaction with custom elements and HTML template elements is notable.
    * **`EndElementNs`:** This is called when the parser reaches the end of an XML element. It handles cleanup, script execution (if it's a `<script>` tag), and potentially pausing the parser for script execution.
    * **`Characters`:** This deals with the text content within XML elements.
    * **`GetProcessingInstruction`:**  Handles processing instructions (like `<?xml-stylesheet ... ?>`). The check for CSS and XSLT processing instructions is important.
    * **`CdataBlock`:** Processes CDATA sections, where character data is not parsed as markup.
    * **`Comment`:** Handles XML comments.

4. **Identify Relationships with Web Technologies:**

    * **HTML:** The code creates `Element` objects, and there are specific checks for `<script>` and `<template>` elements. The handling of the `is` attribute hints at custom elements, a web component feature. The `HTMLConstructionSite` mention further confirms the connection to HTML parsing.
    * **JavaScript:** The `StartElementNs` and `EndElementNs` functions manage script execution using `script_runner_`. The pausing and resuming of the parser suggest a mechanism to handle parser-blocking scripts.
    * **CSS:** The `GetProcessingInstruction` function checks for CSS processing instructions (`<?xml-stylesheet ... ?>`). The `CheckIfBlockingStyleSheetAdded` function indicates handling of stylesheets that can block parsing.

5. **Infer Logical Reasoning (Input/Output):**

    * **`HandleNamespaceAttributes`:** *Input:* A list of namespace declarations from libxml2. *Output:* A `Vector<Attribute>` containing namespace attributes in Blink's internal representation.
    * **`HandleElementAttributes`:** *Input:* A list of attributes from libxml2, and a map of initial namespace prefixes. *Output:* A `Vector<Attribute>` of element attributes. The logic handles namespace prefix resolution and throws an error if a prefix is undeclared.
    * **`StartElementNs`:** *Input:* Name, prefix, URI of the element, namespace declarations, and attributes. *Output:*  Creation of a DOM `Element`, potentially handling custom element lifecycle and inserting it into the DOM tree.
    * **`EndElementNs`:** *Input:* Implicitly the state of the parser and the current element. *Output:*  Potential script execution and moving up the DOM tree.

6. **Consider User/Programming Errors:**

    * **Undeclared Namespace Prefix:** The `HandleElementAttributes` function explicitly checks for this and throws a `NAMESPACE_ERR`. This is a common XML error.
    * **Malformed XML:** While not explicitly handled in this snippet, the underlying libxml2 parser will detect and report many malformed XML errors. The `GetError` function suggests how these errors are handled within Blink.
    * **Incorrect `is` attribute on Custom Elements:** If the `is` attribute doesn't match a registered custom element, the behavior might be unexpected (though the code handles lookup).

7. **Trace User Operations (Debugging Hints):**

    * **Loading an XML document:** The user navigates to an XML file or a page serving XML content.
    * **Dynamic XML insertion:** JavaScript code might use methods like `innerHTML` or `appendChild` to insert XML fragments.
    * **XHR requests for XML:** JavaScript code might fetch XML data using `XMLHttpRequest` or `fetch`.

8. **Synthesize and Organize the Information:** Group the findings into the requested categories: functionality, relationship to web technologies (with examples), logical reasoning (with input/output), common errors, and debugging hints.

9. **Draft the Summary (Part 2):** Based on the detailed analysis, summarize the main responsibilities of this code snippet, emphasizing its role in parsing XML elements, handling attributes and namespaces, and its interactions with the DOM, scripts, and stylesheets.

10. **Review and Refine:** Read through the drafted answer, ensuring clarity, accuracy, and completeness. Check that the examples are relevant and the explanations are easy to understand. Ensure that the summary accurately reflects the functionality described in the code. For instance, initially, I might have overlooked the detail about custom element reactions and needed to add that in. Similarly, double-checking the error handling and how libxml2 interacts is crucial.
这是 `blink/renderer/core/xml/parser/xml_document_parser.cc` 文件的第二部分，主要包含以下功能：

**1. 处理 XML 元素的属性和命名空间:**

* **`HandleNamespaceAttributes` 函数:**
    * **功能:**  将 libxml2 提供的命名空间信息（前缀和 URI）转换为 Blink 内部使用的 `Attribute` 对象。
    * **与 Web 技术的关系:**  XML 命名空间与 HTML5 的命名空间概念类似，用于避免元素和属性名称冲突。例如，SVG 和 MathML 元素通常位于不同的命名空间中。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** `libxml_namespaces` 指向一个包含两个命名空间声明的数组，分别是 `xmlns:svg="http://www.w3.org/2000/svg"` 和 `xmlns:xlink="http://www.w3.org/1999/xlink"`。
        * **输出:** `prefixed_attributes` 向量将包含两个 `Attribute` 对象：
            * `Attribute(QualifiedName(xmlns_names::kNamespaceURI, "xmlns:svg", "http://www.w3.org/2000/svg"), "http://www.w3.org/2000/svg")`
            * `Attribute(QualifiedName(xmlns_names::kNamespaceURI, "xmlns:xlink", "http://www.w3.org/1999/xlink"), "http://www.w3.org/1999/xlink")`
* **`HandleElementAttributes` 函数:**
    * **功能:** 将 libxml2 提供的元素属性信息（本地名称、前缀、URI、值）转换为 Blink 内部使用的 `Attribute` 对象。它还负责处理属性的命名空间，如果属性有前缀，则查找对应的命名空间 URI。
    * **与 Web 技术的关系:**  HTML 元素拥有各种属性，例如 `<img>` 标签的 `src` 和 `alt` 属性。CSS 可以通过属性选择器来选择元素。JavaScript 可以通过 DOM API 访问和修改元素的属性。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 当前解析的元素是 `<svg:rect width="100" height="50" fill="red"/>`，其中 `svg` 前缀已在前面声明为 `http://www.w3.org/2000/svg`。`libxml_attributes` 指向包含 `width="100"`, `height="50"`, `fill="red"` 的属性信息数组，且 `width` 和 `height` 没有前缀，`fill` 的前缀是 `svg`。`initial_prefix_to_namespace_map` 包含 `"svg"` 到 `"http://www.w3.org/2000/svg"` 的映射。
        * **输出:** `prefixed_attributes` 向量将包含三个 `Attribute` 对象：
            * `Attribute(QualifiedName(g_null_atom, "width", g_null_atom), "100")`
            * `Attribute(QualifiedName(g_null_atom, "height", g_null_atom), "50")`
            * `Attribute(QualifiedName("svg", "fill", "http://www.w3.org/2000/svg"), "red")`
    * **用户/编程常见的使用错误:**
        * **未声明的命名空间前缀:** 如果 XML 中使用了带有前缀的属性，但该前缀没有在任何父元素中声明，`HandleElementAttributes` 会抛出 `NAMESPACE_ERR` 异常。
            * **举例:**  XML 片段 `<div custom:attribute="value"></div>`，如果之前没有 `xmlns:custom="..."` 的声明。

**2. 处理 XML 元素的开始和结束标签:**

* **`StartElementNs` 函数:**
    * **功能:** 当解析器遇到元素的开始标签时调用。它负责：
        * 更新内部状态。
        * 如果解析器暂停，则将操作添加到待处理队列。
        * 处理文本节点（如果存在）。
        * 调整命名空间 URI。
        * 调用 `HandleNamespaceAttributes` 和 `HandleElementAttributes` 处理属性。
        * 创建新的 DOM `Element` 节点。
        * 处理自定义元素（Custom Elements）的创建。
        * 将新元素添加到 DOM 树中。
        * 处理 `<template>` 元素。
        * 处理根元素 (`<html>`) 的特殊情况。
    * **与 Web 技术的关系:**  这是构建 DOM 树的关键步骤。HTML 和 SVG 等文档都是由嵌套的元素组成的。JavaScript 可以通过 DOM API 创建新的元素。CSS 可以通过选择器来定位和样式化元素。
    * **用户操作如何到达这里 (调试线索):**
        1. 用户在浏览器中打开一个 XML 文档。
        2. 浏览器开始解析 XML 文档。
        3. 当 libxml2 解析器遇到一个开始标签时，会调用 `StartElementNsHandler`。
        4. `StartElementNsHandler` 将调用 `XMLDocumentParser::StartElementNs`。
* **`EndElementNs` 函数:**
    * **功能:** 当解析器遇到元素的结束标签时调用。它负责：
        * 更新内部状态。
        * 如果解析器暂停，则将操作添加到待处理队列。
        * 处理文本节点（如果存在）。
        * 检查是否需要移除当前节点（例如，模板内容）。
        * 调用 `FinishParsingChildren` 通知元素其子节点已解析完成。
        * 检查是否添加了阻塞样式表。
        * 处理 `<script>` 元素的执行。
        * 弹出当前节点，返回到父节点。
    * **与 Web 技术的关系:**  结束标签标志着元素内容的结束。对于 `<script>` 标签，`EndElementNs` 触发脚本的执行。
    * **用户操作如何到达这里 (调试线索):**
        1. 在 `StartElementNs` 之后，libxml2 解析器会继续解析元素的内容。
        2. 当 libxml2 解析器遇到一个结束标签时，会调用 `EndElementNsHandler`。
        3. `EndElementNsHandler` 将调用 `XMLDocumentParser::EndElementNs`。

**3. 处理字符数据、处理指令、CDATA 块和注释:**

* **`Characters` 函数:** 处理元素内的文本内容。
* **`GetProcessingInstruction` 函数:** 处理 XML 处理指令 (e.g., `<?xml-stylesheet ... ?>`)，并检查是否是 CSS 或 XSLT 处理指令。
    * **与 Web 技术的关系:**  `<?xml-stylesheet ... ?>` 用于在 XML 文档中链接外部 CSS 样式表。XSLT 处理指令用于指定 XML 文档的转换方式。
* **`CdataBlock` 函数:** 处理 CDATA 块，CDATA 块中的内容被视为字符数据，不会被解析为 XML 标记。
* **`Comment` 函数:** 处理 XML 注释。

**4. 处理文档的开始和结束，以及内部子集:**

* **`StartDocument` 函数:**  在解析文档开始时调用，用于获取 XML 版本、编码和 standalone 信息。
* **`EndDocument` 函数:** 在解析文档结束时调用。
* **`InternalSubset` 函数:** 处理文档类型声明 (DTD) 的内部子集。

**总结第二部分的功能:**

这部分代码主要负责 XML 文档解析过程中**元素级别的处理**，包括：

* **识别元素的开始和结束标签，并维护解析器的状态。**
* **提取和处理元素的属性，包括命名空间声明和普通属性，并将其转换为 Blink 内部的数据结构。**
* **创建和管理 DOM 树的 `Element` 节点，并处理自定义元素的特殊情况。**
* **处理元素内的各种内容，包括文本、处理指令、CDATA 块和注释。**
* **处理文档的元数据，如版本、编码和 DTD 内部子集。**

总而言之，这部分代码是 XML 解析器的核心组成部分，负责将 libxml2 解析器提供的底层事件转化为 Blink 内部的 DOM 树结构。它与 HTML、JavaScript 和 CSS 都有密切关系，因为 XML 可以作为数据格式用于 Web 应用，并且可以通过处理指令链接 CSS 样式表。对于调试来说，理解这些函数的调用时机和它们处理的数据是理解 XML 解析过程的关键。

### 提示词
```
这是目录为blink/renderer/core/xml/parser/xml_document_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tes(
    Vector<Attribute, kAttributePrealloc>& prefixed_attributes,
    const xmlChar** libxml_namespaces,
    int nb_namespaces,
    ExceptionState& exception_state) {
  xmlSAX2Namespace* namespaces =
      reinterpret_cast<xmlSAX2Namespace*>(libxml_namespaces);
  for (int i = 0; i < nb_namespaces; ++i) {
    AtomicString namespace_q_name = g_xmlns_atom;
    AtomicString namespace_uri = ToAtomicString(namespaces[i].uri);
    if (namespaces[i].prefix)
      namespace_q_name =
          WTF::g_xmlns_with_colon + ToAtomicString(namespaces[i].prefix);

    std::optional<QualifiedName> parsed_name = Element::ParseAttributeName(
        xmlns_names::kNamespaceURI, namespace_q_name, exception_state);
    if (!parsed_name) {
      DCHECK(exception_state.HadException());
      return false;
    }
    prefixed_attributes.push_back(Attribute(*parsed_name, namespace_uri));
  }
  return true;
}

struct xmlSAX2Attributes {
  const xmlChar* localname;
  const xmlChar* prefix;
  const xmlChar* uri;
  const xmlChar* value;
  const xmlChar* end;
};

static inline bool HandleElementAttributes(
    Vector<Attribute, kAttributePrealloc>& prefixed_attributes,
    const xmlChar** libxml_attributes,
    int nb_attributes,
    const HashMap<AtomicString, AtomicString>& initial_prefix_to_namespace_map,
    ExceptionState& exception_state) {
  xmlSAX2Attributes* attributes =
      reinterpret_cast<xmlSAX2Attributes*>(libxml_attributes);
  for (int i = 0; i < nb_attributes; ++i) {
    int value_length =
        static_cast<int>(attributes[i].end - attributes[i].value);
    AtomicString attr_value = ToAtomicString(attributes[i].value, value_length);
    AtomicString attr_prefix = ToAtomicString(attributes[i].prefix);
    AtomicString attr_uri;
    if (!attr_prefix.empty()) {
      // If provided, use the namespace URI from libxml2 because libxml2
      // updates its namespace table as it parses whereas the
      // initialPrefixToNamespaceMap is the initial map from namespace
      // prefixes to namespace URIs created by the XMLDocumentParser
      // constructor (in the case where we are parsing an XML fragment).
      if (attributes[i].uri) {
        attr_uri = ToAtomicString(attributes[i].uri);
      } else {
        const HashMap<AtomicString, AtomicString>::const_iterator it =
            initial_prefix_to_namespace_map.find(attr_prefix);
        if (it != initial_prefix_to_namespace_map.end()) {
          attr_uri = it->value;
        } else {
          exception_state.ThrowDOMException(DOMExceptionCode::kNamespaceError,
                                            "Namespace prefix " + attr_prefix +
                                                " for attribute " + attr_value +
                                                " is not declared.");
          return false;
        }
      }
    }
    AtomicString attr_q_name =
        attr_prefix.empty()
            ? ToAtomicString(attributes[i].localname)
            : attr_prefix + ":" + ToString(attributes[i].localname);

    std::optional<QualifiedName> parsed_name =
        Element::ParseAttributeName(attr_uri, attr_q_name, exception_state);
    if (!parsed_name) {
      return false;
    }
    prefixed_attributes.push_back(Attribute(*parsed_name, attr_value));
  }
  return true;
}

void XMLDocumentParser::StartElementNs(const AtomicString& local_name,
                                       const AtomicString& prefix,
                                       const AtomicString& uri,
                                       int nb_namespaces,
                                       const xmlChar** libxml_namespaces,
                                       int nb_attributes,
                                       int nb_defaulted,
                                       const xmlChar** libxml_attributes) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    script_start_position_ = GetTextPosition();
    pending_callbacks_.push_back(
        std::make_unique<PendingStartElementNSCallback>(
            local_name, prefix, uri, nb_namespaces, libxml_namespaces,
            nb_attributes, nb_defaulted, libxml_attributes,
            script_start_position_));
    return;
  }

  if (!UpdateLeafTextNode())
    return;

  AtomicString adjusted_uri = uri;
  if (parsing_fragment_ && adjusted_uri.IsNull()) {
    if (!prefix.IsNull()) {
      auto it = prefix_to_namespace_map_.find(prefix);
      if (it != prefix_to_namespace_map_.end())
        adjusted_uri = it->value;
    } else {
      adjusted_uri = default_namespace_uri_;
    }
  }

  bool is_first_element = !saw_first_element_;
  saw_first_element_ = true;

  Vector<Attribute, kAttributePrealloc> prefixed_attributes;
  if (!HandleNamespaceAttributes(prefixed_attributes, libxml_namespaces,
                                 nb_namespaces, IGNORE_EXCEPTION)) {
    StopParsing();
    return;
  }

  v8::Isolate* isolate = document_->GetAgent().isolate();
  v8::TryCatch try_catch(isolate);
  if (!HandleElementAttributes(prefixed_attributes, libxml_attributes,
                               nb_attributes, prefix_to_namespace_map_,
                               parsing_fragment_ ? PassThroughException(isolate)
                                                 : IGNORE_EXCEPTION)) {
    StopParsing();
    if (parsing_fragment_) {
      DCHECK(try_catch.HasCaught());
      try_catch.ReThrow();
    }
    return;
  }

  AtomicString is;
  for (const auto& attr : prefixed_attributes) {
    if (attr.GetName() == html_names::kIsAttr) {
      is = attr.Value();
      break;
    }
  }

  QualifiedName q_name(prefix, local_name, adjusted_uri);
  if (!prefix.empty() && adjusted_uri.empty())
    q_name = QualifiedName(g_null_atom, prefix + ":" + local_name, g_null_atom);

  // If we are constructing a custom element, then we must run extra steps as
  // described in the HTML spec below. This is similar to the steps in
  // HTMLConstructionSite::CreateElement.
  // https://html.spec.whatwg.org/multipage/parsing.html#create-an-element-for-the-token
  // https://html.spec.whatwg.org/multipage/xhtml.html#parsing-xhtml-documents
  std::optional<CEReactionsScope> reactions;
  std::optional<ThrowOnDynamicMarkupInsertionCountIncrementer>
      throw_on_dynamic_markup_insertions;
  if (!parsing_fragment_) {
    if (HTMLConstructionSite::LookUpCustomElementDefinition(*document_, q_name,
                                                            is)) {
      throw_on_dynamic_markup_insertions.emplace(document_);
      document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint();
      reactions.emplace();
    }
  }

  Element* new_element = current_node_->GetDocument().CreateElement(
      q_name,
      parsing_fragment_ ? CreateElementFlags::ByFragmentParser(document_)
                        : CreateElementFlags::ByParser(document_),
      is);
  // Check IsStopped() because custom element constructors may synchronously
  // trigger removal of the document and cancellation of this parser.
  if (IsStopped()) {
    return;
  }
  if (!new_element) {
    StopParsing();
    return;
  }

  SetAttributes(new_element, prefixed_attributes, GetParserContentPolicy());

  new_element->BeginParsingChildren();

  if (new_element->IsScriptElement())
    script_start_position_ = GetTextPosition();

  current_node_->ParserAppendChild(new_element);

  // Event handlers may synchronously trigger removal of the
  // document and cancellation of this parser.
  if (IsStopped()) {
    return;
  }

  if (auto* template_element = DynamicTo<HTMLTemplateElement>(*new_element))
    PushCurrentNode(template_element->content());
  else
    PushCurrentNode(new_element);

  // Note: |insertedByParser| will perform dispatching if this is an
  // HTMLHtmlElement.
  auto* html_html_element = DynamicTo<HTMLHtmlElement>(new_element);
  if (html_html_element && is_first_element) {
    html_html_element->InsertedByParser();
  } else if (!parsing_fragment_ && is_first_element &&
             GetDocument()->GetFrame()) {
    GetDocument()->GetFrame()->Loader().DispatchDocumentElementAvailable();
    GetDocument()->GetFrame()->Loader().RunScriptsAtDocumentElementAvailable();
    // runScriptsAtDocumentElementAvailable might have invalidated the document.
  }
}

void XMLDocumentParser::EndElementNs() {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(std::make_unique<PendingEndElementNSCallback>(
        script_start_position_, GetTextPosition()));
    return;
  }

  if (!UpdateLeafTextNode())
    return;

  ContainerNode* n = current_node_;
  auto* element = DynamicTo<Element>(n);
  if (!element) {
    PopCurrentNode();
    return;
  }

  element->FinishParsingChildren();

  CheckIfBlockingStyleSheetAdded();

  if (element->IsScriptElement() &&
      !ScriptingContentIsAllowed(GetParserContentPolicy())) {
    PopCurrentNode();
    n->remove(IGNORE_EXCEPTION_FOR_TESTING);
    return;
  }

  if (!script_runner_) {
    PopCurrentNode();
    return;
  }

  // The element's parent may have already been removed from document.
  // Parsing continues in this case, but scripts aren't executed.
  if (!element->isConnected()) {
    PopCurrentNode();
    return;
  }

  if (element->IsScriptElement()) {
    requesting_script_ = true;
    script_runner_->ProcessScriptElement(*GetDocument(), element,
                                         script_start_position_);
    requesting_script_ = false;
  }

  // A parser-blocking script might be set and synchronously executed in
  // ProcessScriptElement() if the script was already ready, and in that case
  // IsWaitingForScripts() is false here.
  if (IsWaitingForScripts())
    PauseParsing();

  // JavaScript may have detached the parser
  if (!IsDetached())
    PopCurrentNode();
}

void XMLDocumentParser::NotifyScriptExecuted() {
  if (!IsDetached() && !requesting_script_)
    ResumeParsing();
}

void XMLDocumentParser::SetScriptStartPosition(TextPosition text_position) {
  script_start_position_ = text_position;
}

void XMLDocumentParser::Characters(const xmlChar* chars, int length) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(std::make_unique<PendingCharactersCallback>(
        chars, length, GetTextPosition()));
    return;
  }

  CreateLeafTextNodeIfNeeded();
  buffered_text_.Append(chars, length);
}

void XMLDocumentParser::GetError(XMLErrors::ErrorType type,
                                 const char* message,
                                 va_list args) {
  if (IsStopped())
    return;

  char formatted_message[1024];
  vsnprintf(formatted_message, sizeof(formatted_message) - 1, message, args);

  if (parser_paused_) {
    pending_callbacks_.push_back(std::make_unique<PendingErrorCallback>(
        type, reinterpret_cast<const xmlChar*>(formatted_message),
        GetTextPosition()));
    return;
  }

  HandleError(type, formatted_message, GetTextPosition());
}

void XMLDocumentParser::GetProcessingInstruction(const String& target,
                                                 const String& data) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(
        std::make_unique<PendingProcessingInstructionCallback>(
            target, data, GetTextPosition()));
    return;
  }

  if (!UpdateLeafTextNode())
    return;

  // ### handle exceptions
  DummyExceptionStateForTesting exception_state;
  ProcessingInstruction* pi =
      current_node_->GetDocument().createProcessingInstruction(target, data,
                                                               exception_state);
  if (exception_state.HadException())
    return;

  current_node_->ParserAppendChild(pi);

  if (pi->IsCSS())
    saw_css_ = true;

  CheckIfBlockingStyleSheetAdded();

  saw_xsl_transform_ = !saw_first_element_ && pi->IsXSL();
  if (saw_xsl_transform_ &&
      !DocumentXSLT::HasTransformSourceDocument(*GetDocument())) {
    // This behavior is very tricky. We call stopParsing() here because we
    // want to stop processing the document until we're ready to apply the
    // transform, but we actually still want to be fed decoded string pieces
    // to accumulate in m_originalSourceForTransform. So, we call
    // stopParsing() here and check isStopped() in element callbacks.
    // FIXME: This contradicts the contract of DocumentParser.
    StopParsing();
  }
}

void XMLDocumentParser::CdataBlock(const String& text) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(
        std::make_unique<PendingCDATABlockCallback>(text, GetTextPosition()));
    return;
  }

  // `is_start_of_new_chunk_` is reset by UpdateLeafTextNode(). If it was set
  // when we entered this method, this CDATA block appears at the beginning of
  // the current input chunk.
  const bool is_start_of_new_chunk = is_start_of_new_chunk_;
  if (!UpdateLeafTextNode())
    return;

  // If the most recent child is already a CDATA node *AND* this is the first
  // parse event emitted from the current input chunk, we append this text to
  // the existing node. Otherwise we append a new CDATA node.
  // TODO(https://crbug.com/36431): Unfortunately, when a CDATA straddles
  // multiple input chunks, libxml starts to emit CDATA nodes in 300 byte
  // chunks. The MergeAdjacentCDataSections REF is an attempt to keep these
  // within a single node. However, this will also merge actual adjacent CDATA
  // sections into a single node, e.g.: `<![CDATA[foo]]><![CDATA[bar]]>` will
  // now produce one node. The REF is added to easily reverse in case this
  // isn't web compatible. Otherwise, we can remove `is_start_of_new_chunk_`
  // and this REF.
  CDATASection* cdata_tail =
      current_node_ ? DynamicTo<CDATASection>(current_node_->lastChild())
                    : nullptr;
  if (cdata_tail &&
      (RuntimeEnabledFeatures::XMLParserMergeAdjacentCDataSectionsEnabled() ||
       is_start_of_new_chunk)) {
    cdata_tail->ParserAppendData(text);
  } else {
    current_node_->ParserAppendChild(
        CDATASection::Create(current_node_->GetDocument(), text));
  }
}

void XMLDocumentParser::Comment(const String& text) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(
        std::make_unique<PendingCommentCallback>(text, GetTextPosition()));
    return;
  }

  if (!UpdateLeafTextNode())
    return;

  current_node_->ParserAppendChild(
      Comment::Create(current_node_->GetDocument(), text));
}

enum StandaloneInfo {
  kStandaloneUnspecified = -2,
  kNoXMlDeclaration,
  kStandaloneNo,
  kStandaloneYes
};

void XMLDocumentParser::StartDocument(const String& version,
                                      const String& encoding,
                                      int standalone) {
  StandaloneInfo standalone_info = static_cast<StandaloneInfo>(standalone);
  if (standalone_info == kNoXMlDeclaration) {
    GetDocument()->SetHasXMLDeclaration(false);
    return;
  }

  // Silently ignore XML version mismatch in the prologue.
  // https://www.w3.org/TR/xml/#sec-prolog-dtd note says:
  // "When an XML 1.0 processor encounters a document that specifies a 1.x
  // version number other than '1.0', it will process it as a 1.0 document. This
  // means that an XML 1.0 processor will accept 1.x documents provided they do
  // not use any non-1.0 features."
  if (!version.IsNull() && SupportsXMLVersion(version)) {
    GetDocument()->setXMLVersion(version, ASSERT_NO_EXCEPTION);
  }
  if (standalone != kStandaloneUnspecified)
    GetDocument()->setXMLStandalone(standalone_info == kStandaloneYes,
                                    ASSERT_NO_EXCEPTION);
  if (!encoding.IsNull())
    GetDocument()->SetXMLEncoding(encoding);
  GetDocument()->SetHasXMLDeclaration(true);
}

void XMLDocumentParser::EndDocument() {
  UpdateLeafTextNode();
}

void XMLDocumentParser::InternalSubset(const String& name,
                                       const String& external_id,
                                       const String& system_id) {
  if (IsStopped())
    return;

  if (parser_paused_) {
    pending_callbacks_.push_back(
        std::make_unique<PendingInternalSubsetCallback>(
            name, external_id, system_id, GetTextPosition()));
    return;
  }

  if (GetDocument()) {
    GetDocument()->ParserAppendChild(MakeGarbageCollected<DocumentType>(
        GetDocument(), name, external_id, system_id));
  }
}

static inline XMLDocumentParser* GetParser(void* closure) {
  xmlParserCtxtPtr ctxt = static_cast<xmlParserCtxtPtr>(closure);
  return static_cast<XMLDocumentParser*>(ctxt->_private);
}

static void StartElementNsHandler(void* closure,
                                  const xmlChar* local_name,
                                  const xmlChar* prefix,
                                  const xmlChar* uri,
                                  int nb_namespaces,
                                  const xmlChar** namespaces,
                                  int nb_attributes,
                                  int nb_defaulted,
                                  const xmlChar** libxml_attributes) {
  GetParser(closure)->StartElementNs(
      ToAtomicString(local_name), ToAtomicString(prefix), ToAtomicString(uri),
      nb_namespaces, namespaces, nb_attributes, nb_defaulted,
      libxml_attributes);
}

static void EndElementNsHandler(void* closure,
                                const xmlChar*,
                                const xmlChar*,
                                const xmlChar*) {
  GetParser(closure)->EndElementNs();
}

static void CharactersHandler(void* closure, const xmlChar* chars, int length) {
  GetParser(closure)->Characters(chars, length);
}

static void ProcessingInstructionHandler(void* closure,
                                         const xmlChar* target,
                                         const xmlChar* data) {
  GetParser(closure)->GetProcessingInstruction(ToString(target),
                                               ToString(data));
}

static void CdataBlockHandler(void* closure, const xmlChar* text, int length) {
  GetParser(closure)->CdataBlock(ToString(text, length));
}

static void CommentHandler(void* closure, const xmlChar* text) {
  GetParser(closure)->Comment(ToString(text));
}

PRINTF_FORMAT(2, 3)
static void WarningHandler(void* closure, const char* message, ...) {
  va_list args;
  va_start(args, message);
  GetParser(closure)->GetError(XMLErrors::kErrorTypeWarning, message, args);
  va_end(args);
}

PRINTF_FORMAT(2, 3)
static void NormalErrorHandler(void* closure, const char* message, ...) {
  va_list args;
  va_start(args, message);
  GetParser(closure)->GetError(XMLErrors::kErrorTypeNonFatal, message, args);
  va_end(args);
}

// Using a static entity and marking it XML_INTERNAL_PREDEFINED_ENTITY is a hack
// to avoid malloc/free. Using a global variable like this could cause trouble
// if libxml implementation details were to change
// TODO(https://crbug.com/344484975): The XML_INTERNAL_PREDEFINED_ENTITY is in
// fact overridden in GetXHTMLEntity() below for all uses, so it's not
// behaving as documented.
static xmlChar g_shared_xhtml_entity_result[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

static xmlEntityPtr SharedXHTMLEntity() {
  static xmlEntity entity;
  if (!entity.type) {
    entity.type = XML_ENTITY_DECL;
    entity.orig = g_shared_xhtml_entity_result;
    entity.content = g_shared_xhtml_entity_result;
    // TODO(https://crbug.com/344484975): The XML_INTERNAL_PREDEFINED_ENTITY
    // is in fact overridden in GetXHTMLEntity() below for all uses, so it's
    // not behaving as documented.  We should only set the value in one place.
    entity.etype = XML_INTERNAL_PREDEFINED_ENTITY;
  }
  return &entity;
}

template <size_t N>
static base::span<const char, N - 1> CopyToEntityBuffer(
    base::span<const char, N> expanded_entity_chars) {
  auto entity_buffer =
      base::as_writable_chars(base::span(g_shared_xhtml_entity_result));
  entity_buffer.first<N>().copy_from(expanded_entity_chars);
  return entity_buffer.first<N - 1>();
}

static base::span<const char> ConvertUTF16EntityToUTF8(
    const DecodedHTMLEntity& entity) {
  auto utf16_entity = base::span(entity.data).first(entity.length);
  auto entity_buffer =
      base::as_writable_bytes(base::span(g_shared_xhtml_entity_result));
  WTF::unicode::ConversionResult conversion_result =
      WTF::unicode::ConvertUTF16ToUTF8(utf16_entity, entity_buffer);
  if (conversion_result.status != WTF::unicode::kConversionOK) {
    return {};
  }

  DCHECK(!conversion_result.converted.empty());
  // Even though we must pass the length, libxml expects the entity string to be
  // null terminated.
  entity_buffer[conversion_result.converted.size()] = '\0';
  return base::as_chars(conversion_result.converted);
}

static xmlEntityPtr GetXHTMLEntity(const xmlChar* name) {
  std::optional<DecodedHTMLEntity> decoded_entity =
      DecodeNamedEntity(reinterpret_cast<const char*>(name));
  if (!decoded_entity) {
    return nullptr;
  }

  base::span<const char> entity_utf8;

  // Unlike the HTML parser, the XML parser parses the content of named
  // entities. So we need to escape '&' and '<'.
  if (decoded_entity->length == 1 && decoded_entity->data[0] == '&') {
    entity_utf8 = CopyToEntityBuffer(base::span_with_nul_from_cstring("&#38;"));
  } else if (decoded_entity->length == 1 && decoded_entity->data[0] == '<') {
    entity_utf8 = CopyToEntityBuffer(base::span_with_nul_from_cstring("&#60;"));
  } else if (decoded_entity->length == 2 && decoded_entity->data[0] == '<' &&
             decoded_entity->data[1] == 0x20D2) {
    entity_utf8 = CopyToEntityBuffer(
        base::span_with_nul_from_cstring("&#60;\xE2\x83\x92"));
  } else {
    entity_utf8 = ConvertUTF16EntityToUTF8(*decoded_entity);
    if (entity_utf8.empty()) {
      return nullptr;
    }
  }

  xmlEntityPtr entity = SharedXHTMLEntity();
  entity->length = static_cast<int>(entity_utf8.size());
  entity->name = name;
  return entity;
}

static xmlEntityPtr GetEntityHandler(void* closure, const xmlChar* name) {
  xmlParserCtxtPtr ctxt = static_cast<xmlParserCtxtPtr>(closure);
  xmlEntityPtr ent = xmlGetPredefinedEntity(name);
  if (ent) {
    CHECK_EQ(ent->etype, XML_INTERNAL_PREDEFINED_ENTITY);
    return ent;
  }

  ent = xmlGetDocEntity(ctxt->myDoc, name);
  if (!ent && GetParser(closure)->IsXHTMLDocument()) {
    ent = GetXHTMLEntity(name);
    if (ent) {
      // TODO(https://crbug.com/344484975): This overrides the
      // XML_INTERNAL_PREDEFINED_ENTITY value set above for every single case.
      // We should figure out which one is correct and only set it to one,
      // rather than assigning one value and then always overriding it.
      ent->etype = XML_INTERNAL_GENERAL_ENTITY;
    }
  }

  return ent;
}

static void StartDocumentHandler(void* closure) {
  xmlParserCtxt* ctxt = static_cast<xmlParserCtxt*>(closure);
  XMLDocumentParser* parser = GetParser(closure);
  // Reset the encoding back to match that of the current data block (Latin-1 /
  // UTF-16), since libxml may switch encoding based on the XML declaration -
  // which it has now seen - causing the parse to fail. We could use the
  // XML_PARSE_IGNORE_ENC option to avoid this, but we're relying on populating
  // the 'xmlEncoding' property with the value it yields.
  SwitchEncoding(ctxt, parser->IsCurrentlyParsing8BitChunk());
  parser->StartDocument(ToString(ctxt->version), ToString(ctxt->encoding),
                        ctxt->standalone);
  xmlSAX2StartDocument(closure);
}

static void EndDocumentHandler(void* closure) {
  GetParser(closure)->EndDocument();
  xmlSAX2EndDocument(closure);
}

static void InternalSubsetHandler(void* closure,
                                  const xmlChar* name,
                                  const xmlChar* external_id,
                                  const xmlChar* system_id) {
  GetParser(closure)->InternalSubset(ToString(name), ToString(external_id),
                                     ToString(system_id));
  xmlSAX2InternalSubset(closure, name, external_id, system_id);
}

static void ExternalSubsetHandler(void* closure,
                                  const xmlChar*,
                                  const xmlChar* external_id,
                                  const xmlChar*) {
  // https://html.spec.whatwg.org/C/#parsing-xhtml-documents:named-character-references
  String ext_id = ToString(external_id);
  if (ext_id == "-//W3C//DTD XHTML 1.0 Transitional//EN" ||
      ext_id == "-//W3C//DTD XHTML 1.1//EN" ||
      ext_id == "-//W3C//DTD XHTML 1.0 Strict//EN" ||
      ext_id == "-//W3C//DTD XHTML 1.0 Frameset//EN" ||
      ext_id == "-//W3C//DTD XHTML Basic 1.0//EN" ||
      ext_id == "-//W3C//DTD XHTML 1.1 plus MathML 2.0//EN" ||
      ext_id == "-//W3C//DTD XHTML 1.1 plus MathML 2.0 plus SVG 1.1//EN" ||
      ext_id == "-//W3C//DTD MathML 2.0//EN" ||
      ext_id == "-//WAPFORUM//DTD XHTML Mobile 1.0//EN" ||
      ext_id == "-//WAPFORUM//DTD XHTML Mobile 1.1//EN" ||
      ext_id == "-//WAPFORUM//DTD XHTML Mobile 1.2//EN") {
    // Controls if we replace entities or not.
    GetParser(closure)->SetIsXHTMLDocument(true);
  }
}

static void IgnorableWhitespaceHandler(void*, const xmlChar*, int) {
  // Nothing to do, but we need this to work around a crasher.
  // http://bugzilla.gnome.org/show_bug.cgi?id=172255
  // http://bugs.webkit.org/show_bug.cgi?id=5792
}

void XMLDocumentParser::InitializeParserContext(const std::string& chunk) {
  xmlSAXHandler sax;
  memset(&sax, 0, sizeof(sax));

  // According to http://xmlsoft.org/html/libxml-tree.html#xmlSAXHandler and
  // http://xmlsoft.org/html/libxml-parser.html#fatalErrorSAXFunc the SAX
  // fatalError callback is unused; error gets all the errors. Use
  // normalErrorHandler for both the error and fatalError callbacks.
  sax.error = NormalErrorHandler;
  sax.fatalError = NormalErrorHandler;
  sax.characters = CharactersHandler;
  sax.processingInstruction = ProcessingInstructionHandler;
  sax.cdataBlock = CdataBlockHandler;
  sax.comment = CommentHandler;
  sax.warning = WarningHandler;
  sax.startElementNs = StartElementNsHandler;
  sax.endElementNs = EndElementNsHandler;
  sax.getEntity = GetEntityHandler;
  sax.startDocument = StartDocumentHandler;
  sax.endDocument = EndDocumentHandler;
  sax.internalSubset = InternalSubsetHandler;
  sax.externalSubset = ExternalSubsetHandler;
  sax.ignorableWhitespace = IgnorableWhitespaceHandler;
  sax.entityDecl = xmlSAX2EntityDecl;
  sax.initialized = XML_SAX2_MAGIC;
  saw_error_ = false;
  saw_css_ = false;
  saw_xsl_transform_ = false;
  saw_first_element_ = false;

  XMLDocumentParserScope scope(GetDocument());
  if (parsing_fragment_) {
    context_ = XMLParserContext::CreateMemoryParser(&sax, this, chunk);
  } else {
    context_ = XMLParserContext::CreateStringParser(&sax, this);
  }
}

void XMLDocumentParser::DoEnd() {
  if (!IsStopped()) {
    if (context_) {
      // Tell libxml we're done.
      {
        XMLDocumentParserScope scope(GetDocument());
        FinishParsing(Context());
      }

      context_ = nullptr;
    }
  }

  bool xml_viewer_mode = !saw_error_ && !saw_css_ && !saw_xsl_transform_ &&
                         HasNoStyleInformation(GetDocument());
  if (xml_viewer_mode) {
    GetDocument()->SetIsViewSource(true);
    TransformDocumentToXMLTreeView(*GetDocument());
  } else if (saw_xsl_transform_) {
    xmlDocPtr doc = XmlDocPtrForString(
        GetDocument(), original_source_for_transform_.ToString(),
        GetDocument()->Url().GetString());
    GetDocument()->SetTransformSource(std::make_unique<TransformSource>(doc));
    DocumentParser::StopParsing();
  }
}

xmlDocPtr XmlDocPtrForString(Document* document,
                             const String& source,
                             const String& url) {
  if (source.empty())
    return nullptr;
  // Parse in a single chunk into an xmlDocPtr
  // FIXME: Hook up error handlers so that a failure to parse the main
  // document results in good error messages.
  XMLDocumentParserScope scope(document, ErrorFunc, nullptr);
  XMLParserInput input(source);
  return xmlReadMemory(input.Data(), input.size(), url.Latin1().c_str(),
                       input.Encoding(), XSLT_PARSE_OPTIONS | XML_PARSE_HUGE);
}

OrdinalNumber XMLDocumentParser::LineNumber() const {
  if (callback_)
    return callback_->LineNumber();
  return OrdinalNumber::FromOneBasedInt(Context() ? Context()->input->line : 1);
}

OrdinalNumber XMLDocumentParser::ColumnNumber() const {
  if (callback_)
    return callback_->ColumnNumber();
  return OrdinalNumber::FromOneBasedInt(Context() ? Context()->input->col : 1);
}

TextPosition XMLDocumentParser::GetTextPosition() const {
  return TextPosition(LineNumber(), ColumnNumber());
}

void XMLDocumentParser::StopParsing() {
  // See comment before InsertErrorMessageBlock() in XMLDocumentParser::end.
  if (saw_error_)
    InsertErrorMessageBlock();
  DocumentParser::StopParsing();
  if (Context())
    xmlStopParser(Context());
}

void XMLDocumentParser::ResumeParsing() {
  DCHECK(!IsDetached());
  DCHECK(parser_paused_);

  parser_paused_ = false;

  // First, execute any pending callbacks
  while (!pending_callbacks_.empty()) {
    callback_ = pending_callbacks_.TakeFirst();
    callback_->Call(this);

    // A callback paused the parser
    if (parser_paused_) {
      callback_.reset();
      return;
    }
  }
  callback_.reset();

  // Then, write any pending data
  SegmentedString rest = pending_src_;
  pending_src_.Clear();
  // There is normally only one string left, so toString() shouldn't copy.
  // In any case, the XML parser runs on the main thread and it's OK if
  // the passed string has more than one reference.
  Append(rest.ToString().Impl());

  if (IsDetached())
    return;

  // Finally, if finish() has been called and write() didn't result
  // in any further callbacks being queued, call end()
  if (finish_called_ && pending_callbacks_.empty())
    end();
}

bool XMLDocumentParser::AppendFragmentSource(const String& chunk) {
  DCHECK(!context_);
  DCHECK(parsing_fragment_);

  std::string chunk_as_utf8 = chunk.Utf8();

  // libxml2 takes an int for a length, and therefore can't handle XML chunks
  // larger than 2 GiB.
  if (chunk_as_utf8.length() > INT_MAX)
    return false;

  TRACE_EVENT0("blink", "XMLDocumentParser::appendFragmentSource");
  InitializeParserContext(chunk_as_utf8);
  xmlParseContent(Context());
  EndDocument();  // Close any open text nodes.

#if LIBXML_VERSION < 21400
  // FIXME: If this code is actually needed, it should probably move to
  // finish()
  // XMLDocumentParserQt has a similar check (m_stream.error() ==
  // QXmlStreamReader::PrematureEndOfDocumentError) in doEnd(). Check if all
  // the chunk has been processed.
  int64_t bytes_processed = xmlByteConsumed(Context());
  if (bytes_processed == -1 ||
      bytes_processed != static_cast<int64_t>(chunk_as_utf8.length())) {
    // FIXME: I don't believe we can hit this case without also having seen
    // an error or a null byte. If we hit this DCHECK, we've found a test
    // case which demonstrates the need for this code.
    DCHECK(saw_error_ ||
           (bytes_processed >= 0 && !chunk_as_utf8.data()[bytes_processed]));
    return false;
  }
#endif

  // No error if the chunk is well formed or it is not but we have no error.
  return Context()->wellFormed || !xmlCtxtGetLastError(Context());
}

void XMLDocumentParser::DidAddPendingParserBlockingStylesheet() {
  if (!context_)
    return;
  added_pending_parser_blocking_stylesheet_ = true;
}

void XMLDocumentParser::DidLoadAllPendingParserBlockingStylesheets() {
  added_pending_parser_blocking_stylesheet_ = false;
  waiting_for_stylesheets_ = false;
}

void XMLDocumentParser::CheckIfBlockingStyleSheetAdded() {
  if (!added_pending_parser_blocking_stylesheet_)
    return;
  added_pending_parser_blocking_stylesheet_ = false;
  waiting_for_stylesheets_ = true;
  PauseParsing();
}

void XMLDocumentParser::ExecuteScriptsWaitingForResources() {
  if (!IsWaitingForScripts() && !waiting_for_stylesheets_ && parser_paused_ &&
      IsParsing()) {
    ResumeParsing();
  }
}

// --------------------------------

struct AttributeParseState {
  HashMap<String, String> attributes;
  bool got_attributes;
};

static void AttributesStartElementNsHandler(void* closure,
                                            const xmlChar* xml_local_name,
                                            const xmlChar* /*xmlPrefix*/,
                                            const xmlChar* /*xmlURI*/,
                                            int /*nbNamespaces*/,
                                            const xmlChar** /*namespaces*/,
                                            int nb_attributes,
```