Response:
My thinking process to answer the request about `blink/renderer/core/dom/document.cc` goes through these stages:

1. **Understanding the Core Request:** The request asks for the *functionality* of this specific file within the Chromium Blink engine, emphasizing its relationship to web technologies (JavaScript, HTML, CSS), providing examples, inferring input/output, highlighting common usage errors, outlining user interaction flow, and summarizing its function (as part 3 of 11).

2. **Initial Code Scan and Keyword Identification:**  I quickly scan the provided code snippet, looking for key terms and function names. I notice functions like `importNode`, `adoptNode`, `createElementNS`, `readyState`, `SetReadyState`, `SetContent`, `UpdateTitle`, `setTitle`, `visibilityState`, `createRange`, `createNodeIterator`, `createTreeWalker`, `UpdateStyleAndLayoutTree`, and mentions of `DocumentLifecycle`, `StyleEngine`, etc. These keywords immediately suggest core DOM manipulation and document lifecycle management.

3. **Categorizing Functionality:**  Based on the keywords, I start grouping the identified functions into logical categories:

    * **Node Manipulation:**  `importNode`, `adoptNode` clearly deal with moving and copying nodes between documents.
    * **Document Creation/Modification:** `createElementNS`, `SetContent`, `SetContentFromDOMParser` handle creating elements and setting the document's content.
    * **Document State and Lifecycle:** `readyState`, `SetReadyState`, `IsLoadCompleted` are about the loading status of the document. `UpdateTitle`, `setTitle` manage the document's title. `visibilityState`, `hidden`, `DidChangeVisibilityState` relate to page visibility. The presence of `DocumentLifecycle` and functions like `UpdateStyleAndLayoutTree` confirm this.
    * **Namespaces:** `HasValidNamespaceForElements`, `HasValidNamespaceForAttributes` indicate handling XML namespaces.
    * **Selection and Navigation:** `caretRangeFromPoint`, `caretPositionFromPoint`, `scrollingElement` relate to user interaction and scrolling.
    * **DOM Traversal:** `createRange`, `createNodeIterator`, `createTreeWalker` are standard DOM APIs for navigating the document tree.
    * **Styling and Layout:** `UpdateStyleAndLayoutTree`, mentions of `StyleEngine`, and related enums clearly indicate involvement in the styling and layout process.

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**  For each functional category, I consider how it interacts with JavaScript, HTML, and CSS:

    * **Node Manipulation:** Directly used by JavaScript to modify the DOM structure created from HTML.
    * **Document Creation/Modification:**  JavaScript can use `createElementNS` to create elements dynamically. Setting content dynamically updates the HTML structure.
    * **Document State and Lifecycle:** JavaScript can access `document.readyState`, and events like `readystatechange` are triggered by changes in this state. HTML `<title>` elements are reflected in the document title. CSS can have rules that depend on visibility states.
    * **Namespaces:** Relevant when parsing HTML/XML that uses namespaces, and JavaScript APIs might interact with namespaced elements/attributes.
    * **Selection and Navigation:** JavaScript uses these APIs to handle user interactions like clicks and to programmatically manipulate the cursor.
    * **DOM Traversal:** JavaScript uses these APIs extensively to navigate and query the DOM.
    * **Styling and Layout:** This is a core function tightly coupled with how CSS rules are applied to the HTML structure to produce the visual rendering.

5. **Inferring Input/Output and Logical Reasoning:** I look at individual functions and reason about what they take as input and what they produce as output. For instance:

    * `importNode`: Input - a `Node`; Output - a cloned `Node`.
    * `adoptNode`: Input - a `Node`; Output - the adopted `Node` (or `nullptr` on error).
    * `SetReadyState`: Input - a `DocumentReadyState` enum value; Output - (void) but triggers events.
    * `UpdateTitle`: Input - a `String` representing the title; Output - (void) but updates the internal title and potentially dispatches events.

6. **Identifying Common Usage Errors:** I consider how developers might misuse these functions:

    * Trying to `importNode` or `adoptNode` on invalid node types (like the document itself or shadow roots).
    * Incorrectly using namespaces with `createElementNS`.
    * Setting `readyState` directly (though the code manages this internally, understanding the lifecycle is important).
    * Not handling exceptions when using methods that can throw.

7. **Tracing User Interaction (Debugging Clues):** I think about how user actions might lead to the execution of code in this file:

    * **Page Load:**  The browser parsing HTML and setting `readyState`.
    * **JavaScript DOM Manipulation:**  JavaScript code calling methods like `createElement`, `appendChild`, `importNode`, `adoptNode`, setting element attributes, etc.
    * **Setting Document Content:** JavaScript using `document.write` or `innerHTML`.
    * **Changing the Title:**  The HTML `<title>` tag being parsed or JavaScript setting `document.title`.
    * **User Scrolling:** Triggering the need to identify the `scrollingElement`.
    * **Visibility Changes:** When the user switches tabs or minimizes the window.

8. **Summarizing Functionality (Part 3 of 11):**  I synthesize the identified categories and their importance into a concise summary, emphasizing that this part of the `document.cc` file deals with core DOM manipulation, document lifecycle, and how the document interacts with the rendering engine. I note that it's foundational for how web pages are constructed and how JavaScript interacts with them.

9. **Review and Refinement:** I review my points to ensure they are accurate, well-explained, and cover the key aspects of the provided code snippet. I organize the information logically and use clear language. I make sure to address all parts of the original request.

This iterative process of scanning, categorizing, relating to web techs, inferring, identifying errors, tracing interaction, and summarizing allows me to build a comprehensive and accurate answer to the complex question about the functionality of this Blink engine source file.
好的，让我们来分析一下 `blink/renderer/core/dom/document.cc` 的第 3 部分代码的功能。

**代码片段功能归纳 (第 3 部分):**

这部分代码主要集中在以下几个关键功能上：

1. **节点导入与收养 (Importing and Adopting Nodes):**
   - 实现了 `importNode` 方法，用于从其他文档导入节点。
   - 实现了 `adoptNode` 方法，用于将节点从其原始文档移动到当前文档。

2. **命名空间验证 (Namespace Validation):**
   - 提供了 `HasValidNamespaceForElements` 和 `HasValidNamespaceForAttributes` 方法，用于检查给定的限定名是否符合 XML 命名空间规范。

3. **文档就绪状态管理 (Document Ready State Management):**
   - 提供了 `readyState` getter，返回文档的当前就绪状态 (loading, interactive, complete)。
   - 提供了 `SetReadyState` 方法，用于设置文档的就绪状态，并触发 `readystatechange` 事件。
   - 提供了 `IsLoadCompleted` 方法，用于判断文档加载是否完成。

4. **文档元数据管理 (Document Metadata Management):**
   - 提供了 `EncodingName` getter，返回文档的编码名称。
   - 提供了 `SetContentLanguage` 方法，用于设置文档的内容语言。
   - 提供了 `setXMLVersion` 和 `setXMLStandalone` 方法，用于设置 XML 文档的版本和独立性声明。

5. **动态设置文档内容 (Dynamically Setting Document Content):**
   - 提供了 `SetContent` 方法，用于替换文档的全部内容。
   - 提供了 `SetContentFromDOMParser` 方法，提供了一种优化的方式，通过 DOM 解析器快速设置 HTML 文档的内容，特别针对 `text/html` 类型。

6. **MIME 类型管理 (MIME Type Management):**
   - 提供了 `SuggestedMIMEType` 方法，根据文档类型推断建议的 MIME 类型。
   - 提供了 `SetMimeType` 方法，显式设置文档的 MIME 类型。
   - 提供了 `contentType` getter，返回文档的当前内容类型。

7. **基于坐标的操作 (Coordinate-Based Operations):**
   - 提供了 `caretRangeFromPoint` 方法，根据屏幕坐标返回包含该点的 Range 对象。
   - 提供了 `caretPositionFromPoint` 方法，根据屏幕坐标返回包含该点的 CaretPosition 对象。

8. **滚动元素获取 (Scrolling Element Retrieval):**
   - 提供了 `scrollingElement` 方法，返回文档的滚动元素（通常是 `<body>` 或 `<html>`）。
   - 提供了 `ScrollingElementNoLayout` 方法，在不触发布局的情况下返回滚动元素。
   - 提供了 `KeyboardFocusableScrollersEnabled` 方法，判断是否启用了键盘可聚焦滚动器特性。
   - 提供了 `StandardizedBrowserZoomEnabled` 方法，判断是否启用了标准化的浏览器缩放特性。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **`importNode` 和 `adoptNode`:** JavaScript 可以调用这些方法来移动或复制 DOM 节点。
        ```javascript
        // 假设 otherDocument 是另一个文档
        const newNode = otherDocument.getElementById('someId');
        document.importNode(newNode, true); // 深度复制
        document.body.appendChild(newNode);

        const detachedNode = document.getElementById('anotherId');
        document.adoptNode(detachedNode);
        document.body.appendChild(detachedNode);
        ```
    * **`readyState`:** JavaScript 可以监听 `readystatechange` 事件或访问 `document.readyState` 属性来了解文档的加载状态，以便在 DOM 完全加载后执行操作。
        ```javascript
        document.addEventListener('readystatechange', (event) => {
          if (document.readyState === 'complete') {
            console.log('文档加载完成');
            // 执行需要在 DOM 加载完成后执行的代码
          }
        });
        ```
    * **`SetContent`:**  虽然不常用，但 JavaScript 可以使用这个方法替换整个文档的内容。更常见的是使用 `innerHTML` 或 DOM 操作。
    * **`caretRangeFromPoint` 和 `caretPositionFromPoint`:** JavaScript 可以使用这些方法获取用户在页面上点击位置的光标信息，用于实现自定义的文本选择或编辑功能。
        ```javascript
        document.addEventListener('click', (event) => {
          const range = document.caretRangeFromPoint(event.clientX, event.clientY);
          if (range) {
            console.log('光标位置:', range.startContainer, range.startOffset);
          }
        });
        ```
    * **`scrollingElement`:** JavaScript 可以使用 `document.scrollingElement` 来获取页面的滚动元素，用于操作滚动位置。
        ```javascript
        const scrollElement = document.scrollingElement;
        scrollElement.scrollTop = 100; // 滚动到顶部 100 像素
        ```

* **HTML:**
    * **`readyState`:**  HTML 文档的解析过程会影响 `readyState` 的变化。浏览器解析到一定程度会触发 `interactive` 状态，所有资源加载完成后会变为 `complete` 状态。
    * **文档元数据:** HTML 中的 `<meta charset="...">` 会影响文档的编码， `<html lang="...">` 会影响文档的内容语言。这些信息可能与 `EncodingName` 和 `SetContentLanguage` 相关。 `<title>` 标签会影响文档的标题。
    * **文档内容:** HTML 结构最终会通过解析器转化为 DOM 树，而 `SetContent` 和 `SetContentFromDOMParser` 提供了设置或替换这些内容的方式。

* **CSS:**
    * **`SetContentLanguage`:** CSS 可以使用语言选择器 (`:lang()`) 来根据文档的语言应用不同的样式。
        ```css
        :lang(zh) {
          /* 中文页面的样式 */
        }
        :lang(en) {
          /* 英文页面的样式 */
        }
        ```
    * **滚动元素:** CSS 的一些特性，如 `position: fixed`，其定位的参考就是滚动元素的视口。

**逻辑推理与假设输入/输出:**

**假设输入:**

1. **`importNode(node, deep = true)`:**
   - 输入: `node` 是另一个文档中的一个 `<p id="para1">Hello</p>` 元素。
   - 输出: 一个新的 `<p id="para1">Hello</p>` 元素，它是输入节点的深拷贝，属于当前文档。

2. **`adoptNode(node)`:**
   - 输入: `node` 是当前文档中一个已经被移除的 `<div>World</div>` 元素。
   - 输出:  `node` 元素现在属于当前的文档树，可以被重新插入。

3. **`HasValidNamespaceForElements(QualifiedName("prefix", "localName", "namespaceURI"))`:**
   - 输入: `QualifiedName("my", "element", "http://example.com")`
   - 输出: `true` (假设命名空间用法正确)

4. **`readyState`:**
   - 假设文档正在加载资源。
   - 输出: `V8DocumentReadyState::kLoading`

5. **`SetReadyState(kComplete)`:**
   - 输入: `kComplete`
   - 输出: 文档的内部状态变为 `complete`，并触发 `readystatechange` 事件。

6. **`caretRangeFromPoint(100, 200)`:**
   - 输入: 屏幕坐标 `x=100`, `y=200`
   - 输出: 一个 `Range` 对象，如果该坐标位于一个文本节点中，则该 Range 会包含该文本节点的一部分。

**常见使用错误举例:**

1. **尝试导入 Shadow Root:**
   ```javascript
   const shadowHost = document.getElementById('host');
   const shadowRoot = shadowHost.attachShadow({mode: 'open'});
   // ... 在 shadowRoot 中创建一些元素 ...

   // 错误：不能直接导入 Shadow Root
   const importedShadow = document.importNode(shadowRoot, true); // 会抛出异常
   ```
   **错误原因:** 代码明确指出 Shadow Root 需要通过其宿主节点一起导入或隐式创建。

2. **在不合适的时机调用 `SetReadyState`:**
   虽然提供了 `SetReadyState` 方法，但通常浏览器的解析器会自动管理文档的就绪状态。开发者手动调用可能会导致状态不一致或其他问题。

3. **在 `adoptNode` 后未处理事件监听器:**
   当节点被 `adoptNode` 从一个文档移动到另一个文档时，其原有的事件监听器不会自动迁移。开发者需要手动将必要的事件监听器添加到新文档中的节点上。

**用户操作如何到达这里 (调试线索):**

1. **页面加载:** 用户在浏览器中输入网址或点击链接，浏览器开始请求和解析 HTML 文档。解析过程中，会涉及到 `readyState` 的管理和 DOM 树的构建，这会触发 `document.cc` 中相关代码的执行。

2. **JavaScript DOM 操作:** 用户与页面交互，例如点击按钮或填写表单，触发 JavaScript 代码执行。这些代码可能调用 `document.createElement`, `appendChild`, `importNode`, `adoptNode` 等方法来动态修改 DOM 结构，从而执行 `document.cc` 中的相关逻辑。

3. **动态设置页面内容:**  一些 Web 应用会使用 JavaScript 动态加载或生成 HTML 内容，并通过 `innerHTML` 或其他 DOM 操作将其添加到页面中。 虽然 `SetContent` 不是常用的公共 API，但在引擎内部，DOM 解析器可能会用到类似的机制。

4. **获取光标位置:**  用户点击页面，如果 JavaScript 代码中有监听点击事件并调用 `document.caretRangeFromPoint` 或 `document.caretPositionFromPoint` 的逻辑，则会触发 `document.cc` 中相应的代码。

5. **操作滚动:** 用户滚动页面，浏览器需要确定页面的滚动元素，这会涉及到 `document.scrollingElement` 的调用。

**第 3 部分功能归纳:**

总的来说，`blink/renderer/core/dom/document.cc` 的第 3 部分主要负责处理文档对象的核心生命周期管理、DOM 结构操作（特别是跨文档操作）、元数据维护以及与用户交互相关的基本功能。它提供了支撑 JavaScript 和 CSS 与 HTML 文档交互的基础设施。 这部分的功能对于构建动态和可交互的网页至关重要。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共11部分，请归纳一下它的功能

"""
explicitly importable.  Either they are
    // imported along with their host node, or created implicitly.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The node provided is a shadow root, which may not be imported.");
    return nullptr;
  }

  // 2. Return a clone of node, with context object, the clone children flag set
  // if deep is true, and the clone shadows flag set if this is a
  // DocumentFragment whose host is an HTML template element.
  NodeCloningData data;
  if (deep) {
    data.Put(CloneOption::kIncludeDescendants);
  }
  return imported_node->Clone(*this, data, /*append_to*/ nullptr);
}

Node* Document::adoptNode(Node* source, ExceptionState& exception_state) {
  EventQueueScope scope;

  switch (source->getNodeType()) {
    case kDocumentNode:
      exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                        "The node provided is of type '" +
                                            source->nodeName() +
                                            "', which may not be adopted.");
      return nullptr;
    case kAttributeNode: {
      auto* attr = To<Attr>(source);
      if (Element* owner_element = attr->ownerElement())
        owner_element->removeAttributeNode(attr, exception_state);
      break;
    }
    default:
      if (source->IsShadowRoot()) {
        // ShadowRoot cannot disconnect itself from the host node.
        exception_state.ThrowDOMException(
            DOMExceptionCode::kHierarchyRequestError,
            "The node provided is a shadow root, which may not be adopted.");
        return nullptr;
      }

      if (auto* frame_owner_element =
              DynamicTo<HTMLFrameOwnerElement>(source)) {
        if (GetFrame() && GetFrame()->Tree().IsDescendantOf(
                              frame_owner_element->ContentFrame())) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kHierarchyRequestError,
              "The node provided is a frame which contains this document.");
          return nullptr;
        }
      }
      if (source->parentNode()) {
        source->parentNode()->RemoveChild(source, exception_state);
        if (exception_state.HadException())
          return nullptr;
        // The above removeChild() can execute arbitrary JavaScript code.
        if (source->parentNode()) {
          AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
              ConsoleMessage::Source::kJavaScript,
              ConsoleMessage::Level::kWarning,
              ExceptionMessages::FailedToExecute("adoptNode", "Document",
                                                 "Unable to remove the "
                                                 "specified node from the "
                                                 "original parent.")));
          return nullptr;
        }
      }
  }

  AdoptIfNeeded(*source);

  return source;
}

bool Document::HasValidNamespaceForElements(const QualifiedName& q_name) {
  // These checks are from DOM Core Level 2, createElementNS
  // http://www.w3.org/TR/DOM-Level-2-Core/core.html#ID-DocCrElNS
  // createElementNS(null, "html:div")
  if (!q_name.Prefix().empty() && q_name.NamespaceURI().IsNull())
    return false;
  // createElementNS("http://www.example.com", "xml:lang")
  if (q_name.Prefix() == g_xml_atom &&
      q_name.NamespaceURI() != xml_names::kNamespaceURI)
    return false;

  // Required by DOM Level 3 Core and unspecified by DOM Level 2 Core:
  // http://www.w3.org/TR/2004/REC-DOM-Level-3-Core-20040407/core.html#ID-DocCrElNS
  // createElementNS("http://www.w3.org/2000/xmlns/", "foo:bar"),
  // createElementNS(null, "xmlns:bar"), createElementNS(null, "xmlns")
  if (q_name.Prefix() == g_xmlns_atom ||
      (q_name.Prefix().empty() && q_name.LocalName() == g_xmlns_atom))
    return q_name.NamespaceURI() == xmlns_names::kNamespaceURI;
  return q_name.NamespaceURI() != xmlns_names::kNamespaceURI;
}

bool Document::HasValidNamespaceForAttributes(const QualifiedName& q_name) {
  return HasValidNamespaceForElements(q_name);
}

V8DocumentReadyState Document::readyState() const {
  switch (ready_state_) {
    case kLoading:
      return V8DocumentReadyState(V8DocumentReadyState::Enum::kLoading);
    case kInteractive:
      return V8DocumentReadyState(V8DocumentReadyState::Enum::kInteractive);
    case kComplete:
      return V8DocumentReadyState(V8DocumentReadyState::Enum::kComplete);
  }
  NOTREACHED();
}

void Document::SetReadyState(DocumentReadyState ready_state) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::SetReadyState",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if (ready_state == ready_state_)
    return;

  auto* frame = GetFrame();
  switch (ready_state) {
    case kLoading:
      if (document_timing_.DomLoading().is_null()) {
        document_timing_.MarkDomLoading();
      }
      break;
    case kInteractive:
      if (document_timing_.DomInteractive().is_null())
        document_timing_.MarkDomInteractive();

      if (frame && frame->IsMainFrame()) {
        frame->GetLocalFrameHostRemote().NotifyDocumentInteractive();
      }
      break;
    case kComplete:
      if (document_timing_.DomComplete().is_null())
        document_timing_.MarkDomComplete();
      break;
  }

  ready_state_ = ready_state;
  if (frame && frame->GetPage() &&
      frame->GetPage()->GetPageScheduler()->IsInBackForwardCache()) {
    // Enqueue the event when the page is in back/forward cache, so that it
    // would not cause JavaScript execution. The event will be dispatched upon
    // restore.
    EnqueueEvent(*Event::Create(event_type_names::kReadystatechange),
                 TaskType::kInternalDefault);
  } else {
    // Synchronously dispatch event when the page is not in back/forward cache.
    DispatchEvent(*Event::Create(event_type_names::kReadystatechange));
  }
}

bool Document::IsLoadCompleted() const {
  return ready_state_ == kComplete;
}

AtomicString Document::EncodingName() const {
  return Encoding().GetName();
}

void Document::SetContentLanguage(const AtomicString& language) {
  if (content_language_ == language)
    return;
  content_language_ = language;

  // Document's style depends on the content language.
  GetStyleEngine().MarkViewportStyleDirty();
  GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kLanguage));
}

void Document::setXMLVersion(const String& version,
                             ExceptionState& exception_state) {
  if (!XMLDocumentParser::SupportsXMLVersion(version)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "This document does not support the XML version '" + version + "'.");
    return;
  }

  xml_version_ = version;
}

void Document::setXMLStandalone(bool standalone,
                                ExceptionState& exception_state) {
  xml_standalone_ = standalone ? kStandalone : kNotStandalone;
}

void Document::SetContent(const String& content) {
  // Only set the content of the document if it is ready to be set. This method
  // could be called at any time.
  if (ScriptableDocumentParser* parser = GetScriptableDocumentParser()) {
    if (parser->IsParsing() && parser->IsExecutingScript())
      return;
  }
  if (ignore_opens_during_unload_count_)
    return;

  open();
  parser_->Append(content);
  close();
}

using AllowState = blink::Document::DeclarativeShadowRootAllowState;
void Document::SetContentFromDOMParser(const String& content) {
  if (contentType() == "text/html" && IsA<HTMLDocument>(this)) {
    auto* body = MakeGarbageCollected<HTMLBodyElement>(*this);
    HTMLFragmentParsingBehaviorSet parser_behavior(
        {HTMLFragmentParsingBehavior::kStripInitialWhitespaceForBody});
    if (declarative_shadow_root_allow_state_ == AllowState::kAllow) {
      parser_behavior.Put(HTMLFragmentParsingBehavior::kIncludeShadowRoots);
    }
    // The default for html parsing is quirks mode. This is normally set during
    // parsing, but not for the fast path, so it needs to be set here. If the
    // fast-path parser fails, the full parser will adjust the mode
    // appropriately.
    SetCompatibilityMode(kQuirksMode);
    // Set the state so that the attribute cache is enabled for fragments.
    // TODO(sesse): Should we do this also for the non-fastpath parser?
    SetParsingState(kParsing);
    const bool success = TryParsingHTMLFragment(content, *this, *body, *body,
                                                kAllowScriptingContent,
                                                parser_behavior, nullptr);
    SetParsingState(kFinishedParsing);
    if (success) {
      // When DCHECK is enabled, use SetContent() and verify fast-path
      // content matches. This effectively means the results of the fast-path
      // parser aren't used with DCHECK enabled, but it provides a way to
      // catch problems.
#if DCHECK_IS_ON()
      SetContent(content);
      DCHECK(this->body());
      DCHECK_EQ(CreateMarkup(body), CreateMarkup(this->body()))
          << " supplied value " << content;
      DCHECK(body->isEqualNode(this->body()));
#else
      auto* html = MakeGarbageCollected<HTMLHtmlElement>(*this);
      auto* head = MakeGarbageCollected<HTMLHeadElement>(*this);
      html->AppendChild(head);
      AppendChild(html);
      // Append `body` last so that the newly created children of `body` only
      // get one InsertedInto().
      html->AppendChild(body);
#endif
      return;
    }
  }
  SetContent(content);
}

String Document::SuggestedMIMEType() const {
  if (IsA<XMLDocument>(this)) {
    if (IsXHTMLDocument())
      return "application/xhtml+xml";
    if (IsSVGDocument())
      return "image/svg+xml";
    return keywords::kApplicationXml;
  }
  if (xmlStandalone())
    return "text/xml";
  if (IsA<HTMLDocument>(this))
    return keywords::kTextHtml;

  if (DocumentLoader* document_loader = Loader())
    return document_loader->MimeType();
  return String();
}

void Document::SetMimeType(const AtomicString& mime_type) {
  mime_type_ = mime_type;
}

AtomicString Document::contentType() const {
  if (!mime_type_.empty())
    return mime_type_;

  if (DocumentLoader* document_loader = Loader())
    return document_loader->MimeType();

  String mime_type = SuggestedMIMEType();
  if (!mime_type.empty())
    return AtomicString(mime_type);

  return keywords::kApplicationXml;
}

Range* Document::caretRangeFromPoint(int x, int y) {
  if (!GetLayoutView())
    return nullptr;

  HitTestResult result = HitTestInDocument(this, x, y);
  PositionWithAffinity position_with_affinity = result.GetPosition();
  if (position_with_affinity.IsNull())
    return nullptr;

  Position range_compliant_position =
      position_with_affinity.GetPosition().ParentAnchoredEquivalent();
  return CreateRangeAdjustedToTreeScope(*this, range_compliant_position);
}

CaretPosition* Document::caretPositionFromPoint(
    float x,
    float y,
    const CaretPositionFromPointOptions* options) {
  if (!GetLayoutView()) {
    return nullptr;
  }

  HitTestResult result = HitTestInDocument(this, x, y);
  PositionWithAffinity position_with_affinity = result.GetPosition();
  if (position_with_affinity.IsNull()) {
    return nullptr;
  }

  Node* anchor_node = position_with_affinity.AnchorNode();
  if (TextControlElement* text_control = EnclosingTextControl(anchor_node)) {
    anchor_node = text_control;
  }
  bool adjust_position = false;
  while (anchor_node->IsInShadowTree() &&
         !(options->hasShadowRoots() &&
           options->shadowRoots().Contains(anchor_node->GetTreeScope()))) {
    anchor_node = anchor_node->OwnerShadowHost();
    adjust_position = true;
  }
  Position adjusted_position = adjust_position
                                   ? Position::InParentBeforeNode(*anchor_node)
                                   : position_with_affinity.GetPosition();
  CHECK(!adjusted_position.IsNull());

  return CreateCaretPosition(adjusted_position.ParentAnchoredEquivalent());
}

Element* Document::scrollingElement() {
  if (RuntimeEnabledFeatures::ScrollTopLeftInteropEnabled() && InQuirksMode())
    UpdateStyleAndLayoutTree();
  return ScrollingElementNoLayout();
}

Element* Document::ScrollingElementNoLayout() {
  if (RuntimeEnabledFeatures::ScrollTopLeftInteropEnabled()) {
    if (InQuirksMode()) {
      HTMLBodyElement* body = FirstBodyElement();
      if (body && body->GetLayoutObject() &&
          body->GetLayoutObject()->IsScrollContainer())
        return nullptr;

      return body;
    }

    return documentElement();
  }

  return body();
}

bool Document::KeyboardFocusableScrollersEnabled() {
  return RuntimeEnabledFeatures::KeyboardFocusableScrollersEnabled() &&
         !RuntimeEnabledFeatures::KeyboardFocusableScrollersOptOutEnabled(
             GetExecutionContext());
}

bool Document::StandardizedBrowserZoomEnabled() const {
  return RuntimeEnabledFeatures::StandardizedBrowserZoomEnabled() &&
         !RuntimeEnabledFeatures::StandardizedBrowserZoomOptOutEnabled(
             GetExecutionContext());
}

/*
 * Performs three operations:
 *  1. Convert control characters to spaces
 *  2. Trim leading and trailing spaces
 *  3. Collapse internal whitespace.
 */
template <typename CharacterType>
static inline String CanonicalizedTitle(
    base::span<const CharacterType> characters) {
  unsigned builder_index = 0;
  StringBuffer<CharacterType> buffer(
      base::checked_cast<unsigned>(characters.size()));

  // Replace control characters with spaces and collapse whitespace.
  bool pending_whitespace = false;
  for (size_t i = 0; i < characters.size(); ++i) {
    UChar32 c = characters[i];
    if ((c <= WTF::unicode::kSpaceCharacter &&
         c != WTF::unicode::kLineTabulationCharacter) ||
        c == WTF::unicode::kDeleteCharacter) {
      if (builder_index != 0)
        pending_whitespace = true;
    } else {
      if (pending_whitespace) {
        buffer[builder_index++] = ' ';
        pending_whitespace = false;
      }
      buffer[builder_index++] = c;
    }
  }
  buffer.Shrink(builder_index);

  return String::Adopt(buffer);
}

void Document::UpdateTitle(const String& title) {
  if (raw_title_ == title)
    return;

  raw_title_ = title;

  String old_title = title_;
  if (raw_title_.empty()) {
    title_ = String();
  } else {
    title_ = WTF::VisitCharacters(
        raw_title_, [](auto chars) { return CanonicalizedTitle(chars); });
  }

  if (!dom_window_ || old_title == title_)
    return;
  DispatchDidReceiveTitle();

  if (AXObjectCache* cache = ExistingAXObjectCache())
    cache->DocumentTitleChanged();
}

void Document::DispatchDidReceiveTitle() {
  if (IsInMainFrame()) {
    String shortened_title = title_.Substring(0, mojom::blink::kMaxTitleChars);
    GetFrame()->GetLocalFrameHostRemote().UpdateTitle(
        shortened_title, base::i18n::TextDirection::LEFT_TO_RIGHT);
    GetFrame()->GetPage()->GetPageScheduler()->OnTitleOrFaviconUpdated();
  }
  GetFrame()->Client()->DispatchDidReceiveTitle(title_);
}

void Document::setTitle(const String& title) {
  // Title set by JavaScript -- overrides any title elements.
  Element* element = documentElement();
  if (IsA<SVGSVGElement>(element)) {
    if (!title_element_) {
      title_element_ = MakeGarbageCollected<SVGTitleElement>(*this);
      element->InsertBefore(title_element_.Get(), element->firstChild());
    }
    if (auto* svg_title = DynamicTo<SVGTitleElement>(title_element_.Get()))
      svg_title->SetText(title);
  } else if (element && element->IsHTMLElement()) {
    if (!title_element_) {
      HTMLElement* head_element = head();
      if (!head_element)
        return;
      title_element_ = MakeGarbageCollected<HTMLTitleElement>(*this);
      head_element->AppendChild(title_element_.Get());
    }
    if (auto* html_title = DynamicTo<HTMLTitleElement>(title_element_.Get()))
      html_title->setText(title);
  }
}

void Document::SetTitleElement(Element* title_element) {
  // If the root element is an svg element in the SVG namespace, then let value
  // be the child text content of the first title element in the SVG namespace
  // that is a child of the root element.
  if (IsA<SVGSVGElement>(documentElement())) {
    title_element_ = Traversal<SVGTitleElement>::FirstChild(*documentElement());
  } else {
    if (title_element_ && title_element_ != title_element)
      title_element_ = Traversal<HTMLTitleElement>::FirstWithin(*this);
    else
      title_element_ = title_element;

    // If the root element isn't an svg element in the SVG namespace and the
    // title element is in the SVG namespace, it is ignored.
    if (IsA<SVGTitleElement>(*title_element_)) {
      title_element_ = nullptr;
      return;
    }
  }

  if (auto* html_title = DynamicTo<HTMLTitleElement>(title_element_.Get()))
    UpdateTitle(html_title->text());
  else if (auto* svg_title = DynamicTo<SVGTitleElement>(title_element_.Get()))
    UpdateTitle(svg_title->textContent());
}

void Document::RemoveTitle(Element* title_element) {
  if (title_element_ != title_element)
    return;

  title_element_ = nullptr;

  // Update title based on first title element in the document, if one exists.
  if (IsA<HTMLDocument>(this) || IsXHTMLDocument()) {
    if (HTMLTitleElement* title =
            Traversal<HTMLTitleElement>::FirstWithin(*this))
      SetTitleElement(title);
  } else if (IsSVGDocument()) {
    if (SVGTitleElement* title = Traversal<SVGTitleElement>::FirstWithin(*this))
      SetTitleElement(title);
  }

  if (!title_element_)
    UpdateTitle(String());
}

const AtomicString& Document::dir() {
  Element* root_element = documentElement();
  if (auto* html = DynamicTo<HTMLHtmlElement>(root_element))
    return html->dir();
  return g_null_atom;
}

void Document::setDir(const AtomicString& value) {
  Element* root_element = documentElement();
  if (auto* html = DynamicTo<HTMLHtmlElement>(root_element))
    html->setDir(value);
}

bool Document::IsPageVisible() const {
  // The visibility of the document is inherited from the visibility of the
  // page. If there is no page associated with the document, we will assume
  // that the page is hidden, as specified by the spec:
  // https://w3c.github.io/page-visibility/#hidden-attribute
  if (!GetFrame() || !GetFrame()->GetPage())
    return false;
  // While visibilitychange is being dispatched during unloading it is
  // expected that the visibility is hidden regardless of the page's
  // visibility.
  if (load_event_progress_ >= kUnloadVisibilityChangeInProgress)
    return false;
  return GetFrame()->GetPage()->IsPageVisible();
}

bool Document::IsPrefetchOnly() const {
  if (!GetFrame() || !GetFrame()->GetPage())
    return false;

  NoStatePrefetchClient* no_state_prefetch_client =
      NoStatePrefetchClient::From(GetFrame()->GetPage());
  return no_state_prefetch_client && no_state_prefetch_client->IsPrefetchOnly();
}

V8VisibilityState Document::visibilityState() const {
  if (hidden()) {
    return V8VisibilityState(V8VisibilityState::Enum::kHidden);
  } else {
    return V8VisibilityState(V8VisibilityState::Enum::kVisible);
  }
}

String Document::visibilityStateAsString() const {
  return visibilityState().AsString();
}

bool Document::prerendering() const {
  return IsPrerendering();
}
uint32_t Document::softNavigations() const {
  LocalDOMWindow* window = domWindow();
  if (!window) {
    return 0;
  }
  if (SoftNavigationHeuristics* heuristics =
          SoftNavigationHeuristics::From(*window)) {
    return heuristics->SoftNavigationCount();
  }
  return 0;
}

bool Document::hidden() const {
  return !IsPageVisible();
}

bool Document::wasDiscarded() const {
  return was_discarded_;
}

void Document::SetWasDiscarded(bool was_discarded) {
  was_discarded_ = was_discarded;
}

void Document::DidChangeVisibilityState() {
  if (load_event_progress_ >= kUnloadVisibilityChangeInProgress) {
    // It's possible to get here even after we've started unloading the document
    // and dispatched the visibilitychange event, e.g. when we're closing a tab,
    // where we would first try to dispatch unload events, and then close the
    // tab and update the visibility state.
    return;
  }
  DispatchEvent(*Event::CreateBubble(event_type_names::kVisibilitychange));
  // Also send out the deprecated version until it can be removed.
  DispatchEvent(
      *Event::CreateBubble(event_type_names::kWebkitvisibilitychange));

  if (IsPageVisible())
    GetDocumentAnimations().MarkAnimationsCompositorPending();

  if (hidden() && canvas_font_cache_)
    canvas_font_cache_->PruneAll();

  InteractiveDetector* interactive_detector = InteractiveDetector::From(*this);
  if (interactive_detector) {
    interactive_detector->OnPageHiddenChanged(hidden());
  }

  // Don't create a |ukm_recorder_| and |ukm_source_id_| unless necessary.
  if (hidden() && IdentifiabilityStudySettings::Get()->IsActive()) {
    // Flush UKM data here in addition to Document::Shutdown(). We want to flush
    // the UKM data before this document becomes invisible (e.g. before entering
    // back/forward cache) because we want to send the UKM data before the
    // renderer process is killed.
    IdentifiabilitySampleCollector::Get()->FlushSource(UkmRecorder(),
                                                       UkmSourceID());
  }

  ViewTransitionSupplement::From(*this)->DidChangeVisibilityState();
}

String Document::nodeName() const {
  return "#document";
}

FormController& Document::GetFormController() {
  if (!form_controller_) {
    form_controller_ = MakeGarbageCollected<FormController>(*this);
    HistoryItem* history_item = Loader() ? Loader()->GetHistoryItem() : nullptr;
    if (history_item)
      history_item->SetDocumentState(form_controller_->ControlStates());
  }
  return *form_controller_;
}

DocumentState* Document::GetDocumentState() const {
  if (!form_controller_)
    return nullptr;
  return form_controller_->ControlStates();
}

void Document::SetStateForNewControls(const Vector<String>& state_vector) {
  if (!state_vector.size() && !form_controller_)
    return;
  GetFormController().SetStateForNewControls(state_vector);
}

LocalFrameView* Document::View() const {
  return GetFrame() ? GetFrame()->View() : nullptr;
}

LocalFrame* Document::GetFrame() const {
  return dom_window_ ? dom_window_->GetFrame() : nullptr;
}

Page* Document::GetPage() const {
  return GetFrame() ? GetFrame()->GetPage() : nullptr;
}

Settings* Document::GetSettings() const {
  return GetFrame() ? GetFrame()->GetSettings() : nullptr;
}

Range* Document::createRange() {
  return Range::Create(*this);
}

NodeIterator* Document::createNodeIterator(Node* root,
                                           unsigned what_to_show,
                                           V8NodeFilter* filter) {
  DCHECK(root);
  return MakeGarbageCollected<NodeIterator>(root, what_to_show, filter);
}

TreeWalker* Document::createTreeWalker(Node* root,
                                       unsigned what_to_show,
                                       V8NodeFilter* filter) {
  DCHECK(root);
  return MakeGarbageCollected<TreeWalker>(root, what_to_show, filter);
}

Document::StyleAndLayoutTreeUpdate Document::CalculateStyleAndLayoutTreeUpdate()
    const {
  Document::StyleAndLayoutTreeUpdate local =
      CalculateStyleAndLayoutTreeUpdateForThisDocument();
  if (local == StyleAndLayoutTreeUpdate::kFull)
    return local;
  Document::StyleAndLayoutTreeUpdate parent =
      CalculateStyleAndLayoutTreeUpdateForParentFrame();
  if (parent != StyleAndLayoutTreeUpdate::kNone)
    return StyleAndLayoutTreeUpdate::kFull;
  return local;
}

Document::StyleAndLayoutTreeUpdate
Document::CalculateStyleAndLayoutTreeUpdateForThisDocument() const {
  if (!IsActive() || !View())
    return StyleAndLayoutTreeUpdate::kNone;

  if (style_engine_->NeedsFullStyleUpdate())
    return StyleAndLayoutTreeUpdate::kFull;
  if (!use_elements_needing_update_.empty())
    return StyleAndLayoutTreeUpdate::kFull;
  // We have scheduled an invalidation set on the document node which means any
  // element may need a style recalc.
  if (NeedsStyleInvalidation())
    return StyleAndLayoutTreeUpdate::kFull;
  if (IsSlotAssignmentDirty())
    return StyleAndLayoutTreeUpdate::kFull;
  if (document_animations_->NeedsAnimationTimingUpdate())
    return StyleAndLayoutTreeUpdate::kFull;

  if (style_engine_->NeedsStyleRecalc())
    return StyleAndLayoutTreeUpdate::kAnalyzed;
  if (style_engine_->NeedsStyleInvalidation())
    return StyleAndLayoutTreeUpdate::kAnalyzed;
  if (style_engine_->NeedsLayoutTreeRebuild()) {
    // TODO(futhark): there a couple of places where call back into the top
    // frame while recursively doing a lifecycle update. One of them are for the
    // RootScrollerController. These should probably be post layout tasks and
    // make this test unnecessary since the layout tree rebuild dirtiness is
    // internal to StyleEngine::UpdateStyleAndLayoutTree().
    DCHECK(InStyleRecalc());
    return StyleAndLayoutTreeUpdate::kAnalyzed;
  }

  return StyleAndLayoutTreeUpdate::kNone;
}

Document::StyleAndLayoutTreeUpdate
Document::CalculateStyleAndLayoutTreeUpdateForParentFrame() const {
  if (HTMLFrameOwnerElement* owner = LocalOwner())
    return owner->GetDocument().CalculateStyleAndLayoutTreeUpdate();
  return StyleAndLayoutTreeUpdate::kNone;
}

bool Document::ShouldScheduleLayoutTreeUpdate() const {
  if (!IsActive())
    return false;
  if (InStyleRecalc())
    return false;
  if (lifecycle_.GetState() == DocumentLifecycle::kInPerformLayout)
    return false;
  return true;
}

void Document::ScheduleLayoutTreeUpdate() {
  DCHECK(!HasPendingVisualUpdate());
  DCHECK(ShouldScheduleLayoutTreeUpdate());
  DCHECK(NeedsLayoutTreeUpdate());

  if (!View()->CanThrottleRendering() && ShouldScheduleLayout()) {
    GetPage()->Animator().ScheduleVisualUpdate(GetFrame());
  }

  // FrameSelection caches visual selection information, which must be
  // invalidated on dirty layout tree.
  GetFrame()->Selection().MarkCacheDirty();

  lifecycle_.EnsureStateAtMost(DocumentLifecycle::kVisualUpdatePending);

  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
      "ScheduleStyleRecalculation", inspector_recalculate_styles_event::Data,
      GetFrame());
  ++style_version_;
}

bool Document::HasPendingForcedStyleRecalc() const {
  return HasPendingVisualUpdate() && !InStyleRecalc() &&
         GetStyleChangeType() == kSubtreeStyleChange;
}

void Document::UpdateStyleInvalidationIfNeeded() {
  DCHECK(IsActive());
  ScriptForbiddenScope forbid_script;
  StyleEngine& style_engine = GetStyleEngine();
  if (!style_engine.NeedsStyleInvalidation()) {
    return;
  }
  TRACE_EVENT_WITH_FLOW0("blink", "Document::updateStyleInvalidationIfNeeded",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES("Style.InvalidationTime");
  style_engine.InvalidateStyle();
}

#if DCHECK_IS_ON()
static void AssertNodeClean(const Node& node) {
  DCHECK(!node.NeedsStyleRecalc());
  DCHECK(!node.ChildNeedsStyleRecalc());
  DCHECK(!node.NeedsReattachLayoutTree());
  DCHECK(!node.ChildNeedsReattachLayoutTree());
  DCHECK(!node.NeedsStyleInvalidation());
  DCHECK(!node.ChildNeedsStyleInvalidation());
  DCHECK(!node.GetForceReattachLayoutTree());
  DCHECK(!node.NeedsLayoutSubtreeUpdate());
}

static void AssertLayoutTreeUpdatedForPseudoElements(const Element& element) {
  WTF::Vector<PseudoId> pseudo_ids = {kPseudoIdFirstLetter,
                                      kPseudoIdCheck,
                                      kPseudoIdBefore,
                                      kPseudoIdAfter,
                                      kPseudoIdSelectArrow,
                                      kPseudoIdMarker,
                                      kPseudoIdBackdrop,
                                      kPseudoIdScrollMarkerGroupBefore,
                                      kPseudoIdScrollMarkerGroupAfter,
                                      kPseudoIdScrollNextButton,
                                      kPseudoIdScrollPrevButton};
  for (auto pseudo_id : pseudo_ids) {
    if (auto* pseudo_element = element.GetPseudoElement(pseudo_id))
      AssertNodeClean(*pseudo_element);
  }
}

static void AssertLayoutTreeUpdated(Node& root,
                                    bool allow_dirty_container_subtrees) {
  Node* node = &root;
  while (node) {
    if (auto* element = DynamicTo<Element>(node)) {
      if (element->ChildStyleRecalcBlockedByDisplayLock() ||
          (allow_dirty_container_subtrees && element->GetLayoutObject() &&
           element->GetLayoutObject()->StyleRef().CanMatchSizeContainerQueries(
               *element))) {
        node = FlatTreeTraversal::NextSkippingChildren(*node);
        continue;
      }
      // Check pseudo elements.
      AssertLayoutTreeUpdatedForPseudoElements(*element);
    }

    AssertNodeClean(*node);

    // Make sure there is no node which has a LayoutObject, but doesn't have a
    // parent in a flat tree. If there is such a node, we forgot to detach the
    // node. DocumentNode is only an exception.
    DCHECK((node->IsDocumentNode() || !node->GetLayoutObject() ||
            FlatTreeTraversal::Parent(*node)))
        << *node;

    node = FlatTreeTraversal::Next(*node);
  }
}

#endif

#if EXPENSIVE_DCHECKS_ARE_ON()
void Document::AssertLayoutTreeUpdatedAfterLayout() {
  AssertLayoutTreeUpdated(*this, false /* allow_dirty_container_subtrees */);
  DCHECK(!GetStyleEngine().SkippedContainerRecalc());
}
#endif

void Document::UpdateStyleAndLayoutTree() {
  DocumentLayoutUpgrade upgrade(*this);
  UpdateStyleAndLayoutTree(upgrade);
}

void Document::UpdateStyleAndLayoutTree(LayoutUpgrade& upgrade) {
  DCHECK(IsMainThread());
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  if (!IsActive() || !View() || View()->ShouldThrottleRendering() ||
      Lifecycle().LifecyclePostponed()) {
    return;
  }

  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
  ScriptForbiddenScope forbid_script;

  if (HTMLFrameOwnerElement* owner = LocalOwner()) {
    ParentLayoutUpgrade parent_upgrade(*this, *owner);
    owner->GetDocument().UpdateStyleAndLayoutTree(parent_upgrade);
  }

  PostStyleUpdateScope post_style_update_scope(*this);

  do {
    // This call has to happen even if UpdateStyleAndLayout below will be
    // called. This is because the subsequent call to ShouldUpgrade may depend
    // on the results produced by UpdateStyleAndLayoutTreeForThisDocument.
    UpdateStyleAndLayoutTreeForThisDocument();

    if (upgrade.ShouldUpgrade()) {
      GetDisplayLockDocumentState().EnsureMinimumForcedPhase(
          DisplayLockContext::ForcedPhase::kLayout);

      // TODO(crbug.com/1145970): Provide a better reason.
      UpdateStyleAndLayout(DocumentUpdateReason::kUnknown);
    }

  } while (post_style_update_scope.Apply());

  // If the above call to UpdateStyleAndLayoutTreeForThisDocument caused us to
  // skip style recalc for some node, we should have upgraded [1] and performed
  // layout to clear that flag again.
  //
  // [1] LayoutUpgrade::ShouldUpgrade
  DCHECK(!GetStyleEngine().SkippedContainerRecalc());
}

void Document::UpdateStyleAndLayoutTreeForThisDocument() {
  DCHECK(IsMainThread());
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  if (!IsActive() || !View() || View()->ShouldThrottleRendering() ||
      Lifecycle().LifecyclePostponed()) {
    return;
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  if (HTMLFrameOwnerElement* owner = LocalOwner()) {
    DCHECK(!owner->GetDocument()
                .GetSlotAssignmentEngine()
                .HasPendingSlotAssignmentRecalc());
    DCHECK(!owner->GetDocument().NeedsLayoutTreeUpdate());
    AssertLayoutTreeUpdated(owner->GetDocument(),
                            false /* allow_dirty_container_subtrees */);
  }
#endif  // EXPENSIVE_DCHECKS_ARE_ON()

  ProcessScheduledShadowTreeCreationsNow();

  auto advance_to_style_clean = [this]() {
    DocumentLifecycle& lifecycle = Lifecycle();
    if (lifecycle.GetState() < DocumentLifecycle::kStyleClean) {
      // NeedsLayoutTreeUpdateForThisDocument may change to false without any
      // actual layout tree update.  For example, NeedsAnimationTimingUpdate
      // may change to false when time elapses.  Advance lifecycle to
      // StyleClean because style is actually clean now.
      lifecycle.AdvanceTo(DocumentLifecycle::kInStyleRecalc);
      lifecycle.AdvanceTo(DocumentLifecycle::kStyleClean);
"""


```