Response:
My thinking process to analyze the provided code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code from `blink/renderer/core/dom/document.cc`, focusing on its relationship with web technologies (JavaScript, HTML, CSS), potential errors, debugging clues, and its place within a larger context.

2. **Initial Scan for Key Concepts:** I quickly read through the code, looking for recurring keywords, class names, and patterns. This helps me identify the main areas the code addresses. I noticed things like:
    * `IsValidElementNamePerHTMLParser`, `IsValidElementName`:  Suggests validation of HTML tag names.
    * `Document::UnassociatedListedElementsList`, `Document::TopLevelFormsList`: Implies managing collections of specific HTML elements (potentially related to forms and listed elements).
    * `ExplicitlySetAttrElementsMap`, `CachedAttrAssociatedElementsMap`: Points to handling element attributes.
    * `Document::Create`, `TreeScope::CreateElementForBinding`, `Document::createElementNS`:  Indicates the code is involved in creating DOM elements.
    * `DocumentFragment`, `Text`, `Comment`, `CDATASection`, `ProcessingInstruction`:  Shows support for creating various node types in the DOM.
    * `importNode`: Implies handling the importing of nodes from other documents.
    * `UseCounter`:  Suggests tracking usage of certain features.
    *  The presence of `Document` class members like `style_engine_`, `script_runner_`, `timeline_`: Indicates the code interacts with styling, scripting, and animations.

3. **Group Related Functionality:** Based on the initial scan, I start grouping related code sections together. For instance:
    * Element name validation (`IsValidElementName*`).
    * Management of specific element lists (`UnassociatedListedElementsList`, `TopLevelFormsList`).
    * Attribute-related data structures (`ExplicitlySetAttrElementsMap`, `CachedAttrAssociatedElementsMap`).
    * Element creation methods (`Create`, `CreateElementForBinding`, `createElementNS`, `CreateRawElement`).
    * Creation of other node types (`createDocumentFragment`, `createTextNode`, etc.).
    * Node importing (`importNode`).

4. **Analyze Individual Functions/Sections:** I delve deeper into each identified group, trying to understand the purpose and logic of individual functions and data structures. For example:
    * For `IsValidElementNamePerHTMLParser`, I see it checks if a string conforms to HTML parser rules for tag names, considering disallowed characters.
    * For `UnassociatedListedElementsList`, I see it maintains a list of "listed" HTML elements (like `<input>`, `<button>`) that are *not* associated with a `<form>`. The `MarkDirty` mechanism and the `Get` method with the traversal indicate lazy population of this list.
    * For `CreateElementForBinding`, I note the distinction between HTML documents (lowercase conversion) and other document types, and the handling of custom elements.

5. **Identify Relationships with Web Technologies:**  As I analyze, I look for connections to JavaScript, HTML, and CSS:
    * **HTML:**  The code directly deals with HTML elements, tag names, and form elements. The parsing validation is explicitly tied to HTML parsing rules. The creation of different element types is fundamental to building the HTML DOM.
    * **JavaScript:** The `CreateElementForBinding` functions are the primary entry points for JavaScript code using `document.createElement()` and `document.createElementNS()`. The custom element handling is also directly related to JavaScript APIs.
    * **CSS:** While this particular snippet doesn't directly manipulate CSS properties, the existence of `style_engine_` and the mention of media queries (`MediaQueryMatcher`, `MediaQueryAffectingValueChanged`) in other parts of the `Document` class (not shown here, but implied by the request's context) indicate an indirect relationship. The element creation itself is a prerequisite for CSS styling.

6. **Consider Potential Errors and Debugging:**  I think about how developers might misuse these functions and what errors could occur. For example:
    * Providing invalid tag names to `createElement` would throw an `InvalidCharacterError`.
    * Trying to import a `Document` or `ShadowRoot` would result in a `NotSupportedError`.
    * Incorrectly using namespaces with `createElementNS` could lead to `NamespaceError`.
    * The `UseCounter` calls suggest that the Blink team is tracking potential compatibility issues between DOM and HTML parser rules.

7. **Infer Input and Output (Hypothetical):**  For functions with clear input and output, I formulate simple examples to illustrate their behavior. For example, `IsValidElementNamePerHTMLParser("div")` would return `true`, while `IsValidElementNamePerHTMLParser("my-custom-element!")` would return `false`.

8. **Address User Actions and Debugging:** I consider how user actions in a browser (typing in a form, clicking a button, a website dynamically adding elements) could trigger the code in this file. This helps in understanding debugging scenarios. For example, if a user encounters an error when a script tries to create an element, a developer might set breakpoints in the `CreateElementForBinding` function.

9. **Synthesize a Summary:** Finally, I combine all the gathered information into a concise summary, highlighting the key functionalities and their relevance to the larger browser engine. I pay attention to the specific request to summarize the *provided* code (Part 2), even though I considered context from the surrounding file.

10. **Review and Refine:** I reread my analysis and summary, ensuring accuracy, clarity, and completeness, aligning with all aspects of the original request. I check if I've addressed the "Part 2" constraint effectively.

This systematic approach allows me to break down a potentially complex piece of code into manageable parts, understand its purpose, and explain its role within the broader context of a web browser engine.
这是 `blink/renderer/core/dom/document.cc` 文件第二部分的分析和功能归纳。

**核心功能归纳（第二部分）:**

这部分代码主要负责 **管理和创建 DOM 结构中的元素和节点，并进行相关的校验和优化**。具体来说，它涵盖了以下关键功能：

1. **元素名称的有效性检查:**
   - 提供了 `IsValidElementNamePerHTMLParser` 函数，用于判断给定的字符串是否符合 HTML 解析器对标签名称的要求。这与 HTML 规范密切相关。
   - 提供了 `IsValidElementName` 函数，结合了 DOM 规范和 HTML 解析器的要求来判断元素名称的有效性，并记录两者之间的差异以进行性能分析和兼容性维护。
   - **与 HTML 的关系:** 这直接关系到 HTML 标签的定义和解析。只有符合规则的字符串才能被解析为有效的 HTML 标签。

2. **可编辑性焦点判断:**
   - 提供了 `AcceptsEditingFocus` 函数，判断一个元素是否可以接受编辑焦点。这与富文本编辑等功能相关。
   - **与 HTML 的关系:** 这关系到 HTML 元素是否可以被用户选中并进行编辑，例如 `<input>`, `<textarea>` 或设置了 `contenteditable` 属性的元素。

3. **全局树版本管理:**
   - 声明并使用了 `Document::global_tree_version_`，用于跟踪 DOM 树的全局版本。这可能用于缓存失效或其他需要跟踪 DOM 结构变化的地方。

4. **ResizeObserver 的代理实现:**
   - 实现了 `IntrinsicSizeResizeObserverDelegate`，作为 `ResizeObserver` 的代理，用于监听元素的尺寸变化，特别是与 intrinsic size 相关的变化。
   - **与 JavaScript 的关系:** `ResizeObserver` 是一个 JavaScript API，允许 JavaScript 代码监听元素的尺寸变化。

5. **未关联的 `ListedElement` 列表管理:**
   - 实现了 `Document::UnassociatedListedElementsList`，用于维护一个列表中未关联到任何 `<form>` 元素的 "listed elements" (如 `<input>`, `<button>` 等)。
   - **与 HTML 的关系:** 这直接关系到 HTML 表单元素的处理。浏览器需要跟踪哪些 listed elements 没有显式地属于某个 form。

6. **顶级 `<form>` 元素列表管理:**
   - 实现了 `Document::TopLevelFormsList`，用于维护文档中顶级的 `<form>` 元素列表。
   - **与 HTML 的关系:** 这关系到 HTML 表单的处理，特别是那些没有嵌套在其他 form 里的 form 元素。

7. **元素属性相关的缓存管理:**
   - 提供了 `GetExplicitlySetAttrElementsMap` 和 `MoveElementExplicitlySetAttrElementsMapToNewDocument`，用于管理显式设置了属性的元素映射表。
   - 提供了 `GetCachedAttrAssociatedElementsMap` 和 `MoveElementCachedAttrAssociatedElementsMapToNewDocument`，用于管理与属性关联的元素的缓存映射表。
   - 这些机制可能用于优化属性查找和更新的性能。
   - **与 HTML 的关系:** 这关系到 HTML 元素的属性处理。

8. **`UnloadEventTimingInfo` 结构:**
   - 定义了 `UnloadEventTimingInfo` 结构，用于存储卸载事件相关的时序信息，可能用于性能分析或调试。

9. **`Document` 对象的创建:**
   - 提供了 `Document::Create` 和 `Document::CreateForTest` 等静态方法，用于创建 `Document` 对象。

10. **`Document` 类的构造函数:**
    - 详细展示了 `Document` 类的构造过程，包括初始化各种成员变量，例如：
        - `TreeScope`:  管理文档的树结构。
        - `token_`:  关联的唯一标识符。
        - `dom_window_`:  关联的浏览器窗口对象。
        - `execution_context_`:  执行上下文。
        - `agent_`:  用户代理。
        - `http_refresh_scheduler_`:  处理 HTTP refresh。
        - `cookie_url_`:  Cookie 相关的 URL。
        - `ready_state_`:  文档的加载状态。
        - `markers_`:  文档标记控制器。
        - `script_runner_`:  脚本执行器。
        - `style_engine_`:  样式引擎。
        - 等等。
    - 初始化了与资源加载、脚本执行、样式处理、动画等相关的各种子模块。
    - 记录了文档的创建事件 (`TRACE_EVENT_WITH_FLOW0`).
    - 针对测试环境和特定 Feature Flag 进行了特殊的初始化。

11. **`Document` 类的析构函数:**
    - 包含了 `Document` 类的析构逻辑，例如检查布局视图和父树作用域是否已清除，递减对象计数器，以及在 Web 测试环境下移除 UKM 记录器的委托。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * **假设输入:** JavaScript 代码调用 `document.createElement("div")`。
    * **输出:**  `TreeScope::CreateElementForBinding` 函数会被调用，最终会创建并返回一个表示 `<div>` 元素的 `Element` 对象。
    * **用户操作:** 用户在网页上点击一个按钮，触发一个 JavaScript 函数，该函数动态创建新的 HTML 元素并添加到 DOM 中。

* **HTML:**
    * **假设输入:** HTML 解析器遇到标签 `<p>`。
    * **输出:**  内部会调用相关的元素创建函数（可能不是这里直接展示的函数，但逻辑类似），创建一个 `HTMLParagraphElement` 对象。
    * **用户操作:** 用户加载一个包含 `<p>` 标签的 HTML 页面。

* **CSS:**
    * **功能关系:** 虽然这段代码没有直接处理 CSS，但创建的 `Document` 对象会关联一个 `StyleEngine`，负责 CSS 的解析和应用。创建的元素对象会被样式引擎用于样式计算。
    * **用户操作:** 用户加载一个网页，浏览器会解析 HTML 并创建 DOM 树，然后 `StyleEngine` 会根据 CSS 规则计算每个元素的样式。

**逻辑推理的假设输入与输出:**

* **假设输入:** `IsValidElementNamePerHTMLParser("my-element")`
* **输出:** `true` (符合 HTML 解析器对标签名称的要求)

* **假设输入:** `IsValidElementNamePerHTMLParser("my element")`
* **输出:** `false` (包含空格，不符合 HTML 解析器要求)

* **假设输入:**  一个元素没有关联到任何 `<form>` 元素被添加到 DOM 树中。
* **输出:**  在适当的时机，`Document::UnassociatedListedElementsList` 的 `Get` 方法被调用时，该元素会被添加到 `list_` 中。

**涉及用户或者编程常见的使用错误:**

* **编程错误:** 在 JavaScript 中使用 `document.createElement("my element")` 会因为标签名包含空格而抛出 `InvalidCharacterError` 异常，因为 `IsValidElementName` 会返回 `false`。
* **编程错误:** 尝试使用 `document.importNode` 导入整个 `document` 对象会导致 `NotSupportedError`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并访问一个网页。**
2. **浏览器开始解析 HTML 内容。**
3. **当解析器遇到新的 HTML 标签时，会调用相应的元素创建函数 (`TreeScope::CreateElementForBinding` 或 `Document::CreateRawElement`)。** 此时，就会进入到这段代码中进行元素对象的创建和初始化。
4. **如果网页中包含 JavaScript 代码，并且 JavaScript 代码使用了 `document.createElement()` 或 `document.createElementNS()` 方法创建新的 DOM 元素，** 也会调用到这段代码。
5. **如果网页使用了 `ResizeObserver` API，监听了某个元素的尺寸变化，** 当元素尺寸发生改变时，`IntrinsicSizeResizeObserverDelegate::OnResize` 可能会被调用。
6. **如果网页包含表单元素，** 在解析 HTML 或动态添加表单元素时，会涉及到 `Document::UnassociatedListedElementsList` 和 `Document::TopLevelFormsList` 的更新。

**总结:**

这部分代码是 Chromium Blink 引擎中处理 DOM 文档创建和管理的关键部分。它负责创建各种类型的 DOM 节点，并对元素名称的有效性进行校验。它还管理与表单元素相关的列表，并提供了 `ResizeObserver` 的代理实现。其核心目标是确保浏览器能够正确地解析和构建网页的 DOM 结构，并为 JavaScript 和 CSS 提供操作 DOM 的基础。 这部分代码的执行是网页加载和动态交互的基础。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共11部分，请归纳一下它的功能

"""
;
}

// Tests whether |name| is something the HTML parser would accept as a
// tag name.
template <typename CharType>
static inline bool IsValidElementNamePerHTMLParser(
    base::span<const CharType> characters) {
  CharType c = characters[0] | 0x20;
  if (!('a' <= c && c <= 'z'))
    return false;

  for (size_t i = 1; i < characters.size(); ++i) {
    c = characters[i];
    if (c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' ' ||
        c == '/' || c == '>')
      return false;
  }
  return true;
}

static bool IsValidElementNamePerHTMLParser(const String& name) {
  if (name.empty()) {
    return false;
  }
  return WTF::VisitCharacters(
      name, [](auto chars) { return IsValidElementNamePerHTMLParser(chars); });
}

// Tests whether |name| is a valid name per DOM spec. Also checks
// whether the HTML parser would accept this element name and counts
// cases of mismatches.
static bool IsValidElementName(Document* document, const String& name) {
  bool is_valid_dom_name = Document::IsValidName(name);
  bool is_valid_html_name = IsValidElementNamePerHTMLParser(name);
  if (is_valid_html_name != is_valid_dom_name) [[unlikely]] {
    // This is inaccurate because it will not report activity in
    // detached documents. However retrieving the frame from the
    // bindings is too slow.
    UseCounter::Count(document,
                      is_valid_dom_name
                          ? WebFeature::kElementNameDOMValidHTMLParserInvalid
                          : WebFeature::kElementNameDOMInvalidHTMLParserValid);
  }
  return is_valid_dom_name;
}

static bool AcceptsEditingFocus(const Element& element) {
  DCHECK(IsEditable(element));

  return element.GetDocument().GetFrame() && RootEditableElement(element);
}

uint64_t Document::global_tree_version_ = 0;

static bool g_force_synchronous_parsing_for_testing = false;

void IntrinsicSizeResizeObserverDelegate::OnResize(
    const HeapVector<Member<ResizeObserverEntry>>& entries) {
  for (const auto& entry : entries) {
    DCHECK_GT(entry->contentBoxSize().size(), 0u);
    entry->target()->LastRememberedSizeChanged(entry->contentBoxSize().at(0));
  }
}

ResizeObserver::DeliveryTime IntrinsicSizeResizeObserverDelegate::Delivery()
    const {
  return ResizeObserver::DeliveryTime::kBeforeOthers;
}

bool IntrinsicSizeResizeObserverDelegate::SkipNonAtomicInlineObservations()
    const {
  return true;
}

void Document::UnassociatedListedElementsList::MarkDirty() {
  dirty_ = true;
  list_.clear();
}

void Document::UnassociatedListedElementsList::Trace(Visitor* visitor) const {
  visitor->Trace(list_);
}

const ListedElement::List& Document::UnassociatedListedElementsList::Get(
    const Document& owner) {
  if (dirty_) {
    const Node& root = owner.GetTreeScope().RootNode();
    DCHECK(list_.empty());

    for (Node& current :
         ShadowIncludingTreeOrderTraversal::DescendantsOf(root)) {
      if (HTMLElement* element = DynamicTo<HTMLElement>(current)) {
        if (ListedElement* listed_element = ListedElement::From(*element);
            listed_element && !listed_element->Form()) {
          list_.push_back(listed_element);
        }
      }
    }
    dirty_ = false;
  }
  return list_;
}

const ListedElement::List& Document::UnassociatedListedElements() const {
  return const_cast<Document*>(this)->unassociated_listed_elements_.Get(*this);
}

void Document::MarkUnassociatedListedElementsDirty() {
  unassociated_listed_elements_.MarkDirty();
}

void Document::TopLevelFormsList::MarkDirty() {
  dirty_ = true;
  list_.clear();
}

void Document::TopLevelFormsList::Trace(Visitor* visitor) const {
  visitor->Trace(list_);
}

const HeapVector<Member<HTMLFormElement>>& Document::TopLevelFormsList::Get(
    Document& owner) {
  if (dirty_) {
    // Use BFS to avoid unnecessarily visiting the descendants of form elements.
    HeapDeque<Member<Node>> nodes_to_visit;
    nodes_to_visit.push_back(&owner.GetTreeScope().RootNode());
    while (!nodes_to_visit.empty()) {
      Node* current = nodes_to_visit.TakeFirst();
      if (HTMLFormElement* form = DynamicTo<HTMLFormElement>(*current)) {
        list_.push_back(form);
      } else {
        for (Node& child :
             ShadowIncludingTreeOrderTraversal::ChildrenOf(*current)) {
          nodes_to_visit.push_back(&child);
        }
      }
    }
    dirty_ = false;
  }
  return list_;
}

const HeapVector<Member<HTMLFormElement>>& Document::GetTopLevelForms() {
  return top_level_forms_.Get(*this);
}

void Document::MarkTopLevelFormsDirty() {
  top_level_forms_.MarkDirty();
}

ExplicitlySetAttrElementsMap* Document::GetExplicitlySetAttrElementsMap(
    const Element* element) {
  DCHECK(element);
  DCHECK(element->GetDocument() == this);
  auto add_result =
      element_explicitly_set_attr_elements_map_.insert(element, nullptr);
  if (add_result.is_new_entry) {
    add_result.stored_value->value =
        MakeGarbageCollected<ExplicitlySetAttrElementsMap>();
  }
  return add_result.stored_value->value.Get();
}

void Document::MoveElementExplicitlySetAttrElementsMapToNewDocument(
    const Element* element,
    Document& new_document) {
  DCHECK(element);
  auto it = element_explicitly_set_attr_elements_map_.find(element);
  if (it != element_explicitly_set_attr_elements_map_.end()) {
    new_document.element_explicitly_set_attr_elements_map_.insert(element,
                                                                  it->value);
    element_explicitly_set_attr_elements_map_.erase(it);
  }
}

CachedAttrAssociatedElementsMap* Document::GetCachedAttrAssociatedElementsMap(
    Element* element) {
  DCHECK(element);
  DCHECK(element->GetDocument() == this);
  auto add_result =
      element_cached_attr_associated_elements_map_.insert(element, nullptr);
  if (add_result.is_new_entry) {
    add_result.stored_value->value =
        MakeGarbageCollected<CachedAttrAssociatedElementsMap>();
  }
  return add_result.stored_value->value.Get();
}

void Document::MoveElementCachedAttrAssociatedElementsMapToNewDocument(
    Element* element,
    Document& new_document) {
  DCHECK(element);
  auto it = element_cached_attr_associated_elements_map_.find(element);
  if (it != element_cached_attr_associated_elements_map_.end()) {
    new_document.element_cached_attr_associated_elements_map_.insert(element,
                                                                     it->value);
    element_cached_attr_associated_elements_map_.erase(it);
  }
}

UnloadEventTimingInfo::UnloadEventTimingInfo(
    scoped_refptr<SecurityOrigin> new_document_origin)
    : new_document_origin(std::move(new_document_origin)) {}

Document* Document::Create(Document& document) {
  return MakeGarbageCollected<Document>(
      DocumentInit::Create()
          .WithExecutionContext(document.GetExecutionContext())
          .WithAgent(document.GetAgent())
          .WithURL(BlankURL()));
}

Document* Document::CreateForTest(ExecutionContext& execution_context) {
  return MakeGarbageCollected<Document>(
      DocumentInit::Create().ForTest(execution_context));
}

Document::Document(const DocumentInit& initializer,
                   DocumentClassFlags document_classes)
    : ContainerNode(nullptr, kCreateDocument),
      TreeScope(*this),
      token_(initializer.GetToken()),
      is_initial_empty_document_(initializer.IsInitialEmptyDocument()),
      is_prerendering_(initializer.IsPrerendering()),
      dom_window_(initializer.GetWindow()),
      execution_context_(initializer.GetExecutionContext()),
      agent_(initializer.GetAgent()),
      http_refresh_scheduler_(MakeGarbageCollected<HttpRefreshScheduler>(this)),
      fallback_base_url_(initializer.FallbackBaseURL()),
      cookie_url_(dom_window_ ? initializer.GetCookieUrl()
                              : KURL(g_empty_string)),
      last_focus_type_(mojom::blink::FocusType::kNone),
      clear_focused_element_timer_(
          GetTaskRunner(TaskType::kInternalUserInteraction),
          this,
          &Document::ClearFocusedElementTimerFired),
      dom_tree_version_(++global_tree_version_),
      // https://html.spec.whatwg.org/multipage/dom.html#current-document-readiness
      // says the ready state starts as 'loading' if there's an associated
      // parser and 'complete' otherwise. We don't know whether there's an
      // associated parser here (we create the parser in ImplicitOpen). But
      // waiting to set the ready state to 'loading' in ImplicitOpen fires a
      // readystatechange event, which can be observed in the case where we
      // reuse a window. If there's a window being reused, there must be an
      // associated parser, so setting based on dom_window_ here is sufficient
      // to ensure that the quirk of when we set the ready state is not
      // web-observable.
      ready_state_(dom_window_ ? kLoading : kComplete),
      markers_(MakeGarbageCollected<DocumentMarkerController>(*this)),
      script_runner_(MakeGarbageCollected<ScriptRunner>(this)),
      script_runner_delayer_(MakeGarbageCollected<ScriptRunnerDelayer>(
          script_runner_,
          ScriptRunner::DelayReason::kMilestone)),
      document_classes_(document_classes),
      is_srcdoc_document_(initializer.IsSrcdocDocument()),
      // We already intentionally fire load event asynchronously and here we use
      // kDOMManipulation to ensure that we run onload() in order with other
      // callbacks (e.g. onloadstart()) per the spec.
      // See: https://html.spec.whatwg.org/#delay-the-load-event
      load_event_delay_timer_(GetTaskRunner(TaskType::kDOMManipulation),
                              this,
                              &Document::LoadEventDelayTimerFired),
      plugin_loading_timer_(GetTaskRunner(TaskType::kInternalLoading),
                            this,
                            &Document::PluginLoadingTimerFired),
      document_timing_(*this),
      scripted_animation_controller_(
          MakeGarbageCollected<ScriptedAnimationController>(domWindow())),
      element_data_cache_clear_timer_(
          GetTaskRunner(TaskType::kInternalUserInteraction),
          this,
          &Document::ElementDataCacheClearTimerFired),
      document_animations_(MakeGarbageCollected<DocumentAnimations>(this)),
      timeline_(MakeGarbageCollected<DocumentTimeline>(this)),
      pending_animations_(MakeGarbageCollected<PendingAnimations>(*this)),
      worklet_animation_controller_(
          MakeGarbageCollected<WorkletAnimationController>(this)),
      // Use the source id from the document initializer if it is available.
      // Otherwise, generate a new source id to cover any cases that don't
      // receive a valid source id, this for example includes but is not limited
      // to SVGImage which does not have an associated RenderFrameHost. No URLs
      // will be associated to this source id. No DocumentCreated events will be
      // created either.
      ukm_source_id_(initializer.UkmSourceId() == ukm::kInvalidSourceId
                         ? ukm::UkmRecorder::GetNewSourceID()
                         : initializer.UkmSourceId()),
      viewport_data_(MakeGarbageCollected<ViewportData>(*this)),
      is_for_external_handler_(initializer.IsForExternalHandler()),
      base_auction_nonce_(initializer.BaseAuctionNonce()),
      fragment_directive_(MakeGarbageCollected<FragmentDirective>(*this)),
      display_lock_document_state_(
          MakeGarbageCollected<DisplayLockDocumentState>(this)),
      render_blocking_resource_manager_(
          dom_window_ && (initializer.GetType() == DocumentInit::Type::kHTML)
              ? MakeGarbageCollected<RenderBlockingResourceManager>(*this)
              : nullptr),
      data_(MakeGarbageCollected<DocumentData>(GetExecutionContext())) {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::Document", TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(agent_);
  if (base::FeatureList::IsEnabled(features::kDelayAsyncScriptExecution) &&
      features::kDelayAsyncScriptExecutionDelayByDefaultParam.Get()) {
    script_runner_delayer_->Activate();
  }

  if (LocalFrame* frame = GetFrame()) {
    DCHECK(frame->GetPage());
    fetcher_ = FrameFetchContext::CreateFetcherForCommittedDocument(
        *frame->Loader().GetDocumentLoader(), *this);
    cookie_jar_ = MakeGarbageCollected<CookieJar>(this);
    if (IsInMainFrame() && GetPage()->IsPartitionedPopin()) {
      CountUse(WebFeature::kPartitionedPopin_Opened);
    }
    is_vertical_scroll_enforced_ =
        RuntimeEnabledFeatures::ExperimentalPoliciesEnabled() &&
        !frame->IsOutermostMainFrame() &&
        !dom_window_->IsFeatureEnabled(
            mojom::blink::PermissionsPolicyFeature::kVerticalScroll);
    cached_top_frame_site_for_visited_links_ =
        net::SchemefulSite(TopFrameOrigin()->ToUrlOrigin());
  } else {
    // We disable fetches for frame-less Documents.
    // See https://crbug.com/961614 for details.
    auto& properties =
        *MakeGarbageCollected<DetachableResourceFetcherProperties>(
            *MakeGarbageCollected<NullResourceFetcherProperties>());
    fetcher_ = MakeGarbageCollected<ResourceFetcher>(
        ResourceFetcherInit(properties, &FetchContext::NullInstance(),
                            GetTaskRunner(TaskType::kNetworking),
                            GetTaskRunner(TaskType::kNetworkingUnfreezable),
                            nullptr /* loader_factory */, GetExecutionContext(),
                            nullptr /* back_forward_cache_loader_helper */));
  }
  DCHECK(fetcher_);

  // Since CSSFontSelector requires Document::fetcher_ and StyleEngine owns
  // CSSFontSelector, need to initialize |style_engine_| after initializing
  // |fetcher_|.
  style_engine_ = MakeGarbageCollected<StyleEngine>(*this);

  root_scroller_controller_ =
      MakeGarbageCollected<RootScrollerController>(*this);

  // We depend on the url getting immediately set in subframes, but we
  // also depend on the url NOT getting immediately set in opened windows.
  // See fast/dom/early-frame-url.html
  // and fast/dom/location-new-window-no-crash.html, respectively.
  // FIXME: Can/should we unify this behavior?
  if (initializer.ShouldSetURL()) {
    SetURL(initializer.Url());
  } else {
    // Even if this document has no URL, we need to initialize base URL with
    // fallback base URL.
    UpdateBaseURL();
  }
  should_record_sandboxed_srcdoc_baseurl_metrics_ =
      urlForBinding().IsAboutSrcdocURL() && !fallback_base_url_.IsNull() &&
      dom_window_->IsSandboxed(network::mojom::blink::WebSandboxFlags::kOrigin);

  InitDNSPrefetch();

  InstanceCounters::IncrementCounter(InstanceCounters::kDocumentCounter);

  lifecycle_.AdvanceTo(DocumentLifecycle::kInactive);

  UpdateThemeColorCache();

  // The parent's parser should be suspended together with all the other
  // objects, else this new Document would have a new ExecutionContext which
  // suspended state would not match the one from the parent, and could start
  // loading resources ignoring the defersLoading flag.
  DCHECK(!ParentDocument() ||
         !ParentDocument()->domWindow()->IsContextPaused());

#ifndef NDEBUG
  LiveDocumentSet().insert(this);
#endif
}

Document::~Document() {
  DCHECK(!GetLayoutView());
  DCHECK(!ParentTreeScope());
  // If a top document with a cache, verify that it was comprehensively
  // cleared during detach.
  DCHECK(!ax_object_cache_);

  InstanceCounters::DecrementCounter(InstanceCounters::kDocumentCounter);
  if (WebTestSupport::IsRunningWebTest() && ukm_recorder_) {
    ukm::DelegatingUkmRecorder::Get()->RemoveDelegate(ukm_recorder_.get());
  }
}

Range* Document::CreateRangeAdjustedToTreeScope(const TreeScope& tree_scope,
                                                const Position& position) {
  const Position& adjusted_position =
      PositionAdjustedToTreeScope(tree_scope, position);
  return MakeGarbageCollected<Range>(tree_scope.GetDocument(),
                                     adjusted_position, adjusted_position);
}

CaretPosition* Document::CreateCaretPosition(const Position& position) {
  return MakeGarbageCollected<CaretPosition>(
      position.AnchorNode(), position.ComputeOffsetInContainerNode());
}

const Position Document::PositionAdjustedToTreeScope(
    const TreeScope& tree_scope,
    const Position& position) {
  DCHECK(position.IsNotNull());
  // Note: Since |Position::ComputeContainerNode()| returns |nullptr| if
  // |position| is |BeforeAnchor| or |AfterAnchor|.
  Node* const anchor_node = position.AnchorNode();
  if (anchor_node->GetTreeScope() == tree_scope) {
    return position;
  }
  Node* const shadow_host = tree_scope.AncestorInThisScope(anchor_node);
  return Position::BeforeNode(*shadow_host);
}

SelectorQueryCache& Document::GetSelectorQueryCache() {
  if (!selector_query_cache_)
    selector_query_cache_ = std::make_unique<SelectorQueryCache>();
  return *selector_query_cache_;
}

MediaQueryMatcher& Document::GetMediaQueryMatcher() {
  if (!media_query_matcher_) {
    media_query_matcher_ = MakeGarbageCollected<MediaQueryMatcher>(*this);
  }
  return *media_query_matcher_;
}

void Document::MediaQueryAffectingValueChanged(MediaValueChange change) {
  GetStyleEngine().MediaQueryAffectingValueChanged(change);
  if (NeedsLayoutTreeUpdate())
    evaluate_media_queries_on_style_recalc_ = true;
  else
    EvaluateMediaQueryList();
  probe::MediaQueryResultChanged(this);
}

void Document::SetCompatibilityMode(CompatibilityMode mode) {
  if (compatibility_mode_locked_ || mode == compatibility_mode_)
    return;

  if (mode == kQuirksMode) {
    UseCounter::Count(*this, WebFeature::kQuirksModeDocument);
    if (urlForBinding().IsAboutBlankURL()) {
      UseCounter::Count(*this, WebFeature::kQuirksModeAboutBlankDocument);
    }
  } else if (mode == kLimitedQuirksMode) {
    UseCounter::Count(*this, WebFeature::kLimitedQuirksModeDocument);
  }

  compatibility_mode_ = mode;
  GetSelectorQueryCache().Invalidate();
}

String Document::compatMode() const {
  return InQuirksMode() ? "BackCompat" : "CSS1Compat";
}

void Document::SetDoctype(DocumentType* doc_type) {
  // This should never be called more than once.
  DCHECK(!doc_type_ || !doc_type);
  doc_type_ = doc_type;
  if (doc_type_) {
    AdoptIfNeeded(*doc_type_);
    if (doc_type_->publicId().StartsWithIgnoringASCIICase(
            "-//wapforum//dtd xhtml mobile 1.")) {
      is_mobile_document_ = true;
      style_engine_->ViewportStyleSettingChanged();
    }
  }
}

DOMImplementation& Document::implementation() {
  if (!implementation_)
    implementation_ = MakeGarbageCollected<DOMImplementation>(*this);
  return *implementation_;
}

Location* Document::location() const {
  if (!GetFrame())
    return nullptr;

  return domWindow()->location();
}

bool Document::DocumentPolicyFeatureObserved(
    mojom::blink::DocumentPolicyFeature feature) {
  wtf_size_t feature_index = static_cast<wtf_size_t>(feature);
  if (parsed_document_policies_.size() == 0) {
    parsed_document_policies_.resize(
        static_cast<wtf_size_t>(
            mojom::blink::DocumentPolicyFeature::kMaxValue) +
        1);
  } else if (parsed_document_policies_[feature_index]) {
    return true;
  }
  parsed_document_policies_[feature_index] = true;
  return false;
}

void Document::ChildrenChanged(const ChildrenChange& change) {
  ContainerNode::ChildrenChanged(change);
  document_element_ = ElementTraversal::FirstWithin(*this);

  // For non-HTML documents the willInsertBody notification won't happen
  // so we resume as soon as we have a document element. Even for XHTML
  // documents there may never be a <body> (since the parser won't always
  // insert one), so we resume here too. That does mean XHTML documents make
  // frames when there's only a <head>, but such documents are pretty rare.
  if (document_element_ && !IsA<HTMLDocument>(this))
    BeginLifecycleUpdatesIfRenderingReady();
}

bool Document::IsInMainFrame() const {
  return GetFrame() && GetFrame()->IsMainFrame();
}

bool Document::IsInOutermostMainFrame() const {
  return GetFrame() && GetFrame()->IsOutermostMainFrame();
}

AtomicString Document::ConvertLocalName(const AtomicString& name) {
  return IsA<HTMLDocument>(this) ? name.LowerASCII() : name;
}

// Just creates an element with specified qualified name without any
// custom element processing.
// This is a common code for step 5.2 and 7.2 of "create an element"
// <https://dom.spec.whatwg.org/#concept-create-element>
// Functions other than this one should not use HTMLElementFactory and
// SVGElementFactory because they don't support prefixes correctly.
Element* Document::CreateRawElement(const QualifiedName& qname,
                                    CreateElementFlags flags) {
  Element* element = nullptr;
  if (qname.NamespaceURI() == html_names::xhtmlNamespaceURI) {
    // https://html.spec.whatwg.org/C/#elements-in-the-dom:element-interface
    element = HTMLElementFactory::Create(qname.LocalName(), *this, flags);
    if (!element) {
      // 6. If name is a valid custom element name, then return
      // HTMLElement.
      // 7. Return HTMLUnknownElement.
      if (CustomElement::IsValidName(qname.LocalName()))
        element = MakeGarbageCollected<HTMLElement>(qname, *this);
      else
        element = MakeGarbageCollected<HTMLUnknownElement>(qname, *this);
    }
    saw_elements_in_known_namespaces_ = true;
  } else if (qname.NamespaceURI() == svg_names::kNamespaceURI) {
    element = SVGElementFactory::Create(qname.LocalName(), *this, flags);
    if (!element)
      element = MakeGarbageCollected<SVGUnknownElement>(qname, *this);
    saw_elements_in_known_namespaces_ = true;
  } else if (qname.NamespaceURI() == mathml_names::kNamespaceURI) {
    element = MathMLElementFactory::Create(qname.LocalName(), *this, flags);
    // An unknown MathML element is treated like an <mrow> element.
    // TODO(crbug.com/1021837): Determine if we need to introduce a
    // MathMLUnknownElement IDL.
    if (!element) {
      element = MakeGarbageCollected<MathMLRowElement>(qname, *this);
    }
    saw_elements_in_known_namespaces_ = true;
  } else {
    element = MakeGarbageCollected<Element>(qname, this);
  }

  if (element->prefix() != qname.Prefix())
    element->SetTagNameForCreateElementNS(qname);
  DCHECK(qname == element->TagQName());

  return element;
}

// https://dom.spec.whatwg.org/#dom-document-createelement
// TODO(crbug.com/1304439): Move it to `tree_scope.cc` if the feature
// `ScopedCustomElementRegistry` can stabilize.
Element* TreeScope::CreateElementForBinding(const AtomicString& name,
                                            ExceptionState& exception_state) {
  Document& document = GetDocument();
  if (!IsValidElementName(&document, name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "The tag name provided ('" + name + "') is not a valid name.");
    return nullptr;
  }

  if (document.IsXHTMLDocument() || IsA<HTMLDocument>(document)) {
    // 2. If the context object is an HTML document, let localName be
    // converted to ASCII lowercase.
    AtomicString local_name = document.ConvertLocalName(name);
    if (CustomElement::ShouldCreateCustomElement(local_name)) {
      return CustomElement::CreateCustomElement(
          *this,
          QualifiedName(g_null_atom, local_name, html_names::xhtmlNamespaceURI),
          IsA<ShadowRoot>(this)
              ? CreateElementFlags::ByShadowRootCreateElement()
              : CreateElementFlags::ByCreateElement());
    }
    if (auto* element = HTMLElementFactory::Create(
            local_name, document, CreateElementFlags::ByCreateElement())) {
      return element;
    }
    QualifiedName q_name(g_null_atom, local_name,
                         html_names::xhtmlNamespaceURI);
    return MakeGarbageCollected<HTMLUnknownElement>(q_name, document);
  }
  return MakeGarbageCollected<Element>(QualifiedName(name), &document);
}

AtomicString GetTypeExtension(
    Document* document,
    const V8UnionElementCreationOptionsOrString* string_or_options) {
  DCHECK(string_or_options);

  switch (string_or_options->GetContentType()) {
    case V8UnionElementCreationOptionsOrString::ContentType::
        kElementCreationOptions: {
      const ElementCreationOptions* options =
          string_or_options->GetAsElementCreationOptions();
      if (options->hasIs())
        return AtomicString(options->is());
      return AtomicString();
    }
    case V8UnionElementCreationOptionsOrString::ContentType::kString:
      UseCounter::Count(document,
                        WebFeature::kDocumentCreateElement2ndArgStringHandling);
      return AtomicString(string_or_options->GetAsString());
  }
  NOTREACHED();
}

// https://dom.spec.whatwg.org/#dom-document-createelement
// TODO(crbug.com/1304439): Move it to `tree_scope.cc` if the feature
// `ScopedCustomElementRegistry` can stabilize.
Element* TreeScope::CreateElementForBinding(
    const AtomicString& local_name,
    const V8UnionElementCreationOptionsOrString* string_or_options,
    ExceptionState& exception_state) {
  if (!string_or_options) {
    return CreateElementForBinding(local_name, exception_state);
  }

  Document& document = GetDocument();

  // 1. If localName does not match Name production, throw InvalidCharacterError
  if (!IsValidElementName(&document, local_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "The tag name provided ('" + local_name + "') is not a valid name.");
    return nullptr;
  }

  // 2. localName converted to ASCII lowercase
  const AtomicString& converted_local_name =
      document.ConvertLocalName(local_name);
  QualifiedName q_name(g_null_atom, converted_local_name,
                       document.IsXHTMLDocument() || IsA<HTMLDocument>(document)
                           ? html_names::xhtmlNamespaceURI
                           : g_null_atom);

  // 3.
  const AtomicString& is = GetTypeExtension(&document, string_or_options);

  // 5. Let element be the result of creating an element given ...
  Element* element =
      CreateElement(q_name, CreateElementFlags::ByCreateElement(), is);

  return element;
}

static inline QualifiedName CreateQualifiedName(
    const AtomicString& namespace_uri,
    const AtomicString& qualified_name,
    ExceptionState& exception_state) {
  AtomicString prefix, local_name;
  if (!Document::ParseQualifiedName(qualified_name, prefix, local_name,
                                    exception_state))
    return QualifiedName::Null();

  QualifiedName q_name(prefix, local_name, namespace_uri);
  if (!Document::HasValidNamespaceForElements(q_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNamespaceError,
        "The namespace URI provided ('" + namespace_uri +
            "') is not valid for the qualified name provided ('" +
            qualified_name + "').");
    return QualifiedName::Null();
  }

  return q_name;
}

// TODO(crbug.com/1304439): Move it to `tree_scope.cc` if the feature
// `ScopedCustomElementRegistry` can stabilize.
Element* TreeScope::createElementNS(const AtomicString& namespace_uri,
                                    const AtomicString& qualified_name,
                                    ExceptionState& exception_state) {
  QualifiedName q_name(
      CreateQualifiedName(namespace_uri, qualified_name, exception_state));
  if (q_name == QualifiedName::Null())
    return nullptr;

  CreateElementFlags flags = CreateElementFlags::ByCreateElement();
  if (CustomElement::ShouldCreateCustomElement(q_name)) {
    return CustomElement::CreateCustomElement(
        *this, q_name,
        IsA<ShadowRoot>(this) ? CreateElementFlags::ByShadowRootCreateElement()
                              : CreateElementFlags::ByCreateElement());
  }
  return GetDocument().CreateRawElement(q_name, flags);
}

// https://dom.spec.whatwg.org/#internal-createelementns-steps
// TODO(crbug.com/1304439): Move it to `tree_scope.cc` if the feature
// `ScopedCustomElementRegistry` can stabilize.
Element* TreeScope::createElementNS(
    const AtomicString& namespace_uri,
    const AtomicString& qualified_name,
    const V8UnionElementCreationOptionsOrString* string_or_options,
    ExceptionState& exception_state) {
  DCHECK(string_or_options);

  // 1. Validate and extract
  QualifiedName q_name(
      CreateQualifiedName(namespace_uri, qualified_name, exception_state));
  if (q_name == QualifiedName::Null())
    return nullptr;

  Document& document = GetDocument();

  // 2.
  const AtomicString& is = GetTypeExtension(&document, string_or_options);

  if (!IsValidElementName(&document, qualified_name)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidCharacterError,
                                      "The tag name provided ('" +
                                          qualified_name +
                                          "') is not a valid name.");
    return nullptr;
  }

  // 3. Let element be the result of creating an element
  Element* element =
      CreateElement(q_name, CreateElementFlags::ByCreateElement(), is);

  return element;
}

// Entry point of "create an element".
// https://dom.spec.whatwg.org/#concept-create-element
// TODO(crbug.com/1304439): Move it to `tree_scope.cc` if the feature
// `ScopedCustomElementRegistry` can stabilize.
Element* TreeScope::CreateElement(const QualifiedName& q_name,
                                  const CreateElementFlags flags,
                                  const AtomicString& is) {
  CustomElementDefinition* definition = nullptr;
  if (flags.IsCustomElements() &&
      q_name.NamespaceURI() == html_names::xhtmlNamespaceURI) {
    const CustomElementDescriptor desc(is.IsNull() ? q_name.LocalName() : is,
                                       q_name.LocalName());
    if (CustomElementRegistry* registry = CustomElement::Registry(*this))
      definition = registry->DefinitionFor(desc);
  }

  if (definition)
    return definition->CreateElement(GetDocument(), q_name, flags);

  return CustomElement::CreateUncustomizedOrUndefinedElement(GetDocument(),
                                                             q_name, flags, is);
}

DocumentFragment* Document::createDocumentFragment() {
  return DocumentFragment::Create(*this);
}

Text* Document::createTextNode(const String& data) {
  return Text::Create(*this, data);
}

Comment* Document::createComment(const String& data) {
  return Comment::Create(*this, data);
}

CDATASection* Document::createCDATASection(const String& data,
                                           ExceptionState& exception_state) {
  if (IsA<HTMLDocument>(this)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "This operation is not supported for HTML documents.");
    return nullptr;
  }
  if (data.Contains("]]>")) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidCharacterError,
                                      "String cannot contain ']]>' since that "
                                      "is the end delimiter of a CData "
                                      "section.");
    return nullptr;
  }
  return CDATASection::Create(*this, data);
}

ProcessingInstruction* Document::createProcessingInstruction(
    const String& target,
    const String& data,
    ExceptionState& exception_state) {
  if (!IsValidName(target)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "The target provided ('" + target + "') is not a valid name.");
    return nullptr;
  }
  if (data.Contains("?>")) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "The data provided ('" + data + "') contains '?>'.");
    return nullptr;
  }
  if (IsA<HTMLDocument>(this)) {
    UseCounter::Count(*this,
                      WebFeature::kHTMLDocumentCreateProcessingInstruction);
  }
  return MakeGarbageCollected<ProcessingInstruction>(*this, target, data);
}

Text* Document::CreateEditingTextNode(const String& text) {
  return Text::CreateEditingText(*this, text);
}

Node* Document::importNode(Node* imported_node,
                           bool deep,
                           ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#dom-document-importnode

  // 1. If node is a document or shadow root, then throw a "NotSupportedError"
  // DOMException.
  if (imported_node->IsDocumentNode()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The node provided is a document, which may not be imported.");
    return nullptr;
  }
  if (imported_node->IsShadowRoot()) {
    // ShadowRoot nodes should not be 
"""


```