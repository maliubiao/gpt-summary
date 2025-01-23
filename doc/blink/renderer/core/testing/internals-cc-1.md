Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine, specifically `blink/renderer/core/testing/internals.cc`, and describe its functionality based on the provided code snippet (which is the second part of the file). I need to explain how the functions in this part relate to JavaScript, HTML, and CSS, provide examples with hypothetical inputs and outputs if logical deductions are made, point out common user or programming errors, explain how a user's action can lead to these functions being called, and finally, summarize the functionalities covered in this specific code block.

Here’s a breakdown of how to address each requirement:

1. **List the functionalities:** I'll go through each function defined in the code snippet and describe what it does. The function names are mostly self-explanatory, which helps.

2. **Relationship with JavaScript, HTML, and CSS:** For each function, I'll consider if it interacts with or is observable through JavaScript APIs, manipulates HTML elements or the DOM structure, or deals with CSS styling and layout.

3. **Examples with hypothetical inputs and outputs:** For functions that perform calculations or have conditional logic, I'll create simple scenarios with example inputs and what the expected output would be based on the code.

4. **Common user or programming errors:**  I'll look for error handling within the functions (e.g., checks for null pointers, invalid arguments) and explain what could cause these errors from a user or developer perspective.

5. **User actions leading to function calls:** I need to think about how web developers might use the `internals` object in their testing and what user actions within a browser might trigger the underlying engine mechanisms that these `internals` functions inspect or manipulate.

6. **Summarize the functionality:** After analyzing all the individual functions, I'll provide a concise summary of the overall purpose of the code block.

Let's go through the functions in the provided snippet:

*   `styleForElementCount()`: Gets the count of styled elements. Relates to CSS styling.
*   `needsLayoutCount()`: Gets the count of elements needing layout. Relates to HTML structure and CSS.
*   `layoutCountForTesting()`: Gets the layout count for testing purposes. Relates to HTML structure and CSS.
*   `nodeNeedsStyleRecalc()`: Checks if a node needs style recalculation. Relates to DOM nodes and CSS.
*   `hitTestCount()`: Gets the count of hit tests performed. Relates to user interaction (mouse clicks) and layout.
*   `hitTestCacheHits()`: Gets the count of hit test cache hits. Relates to optimization of hit testing.
*   `elementFromPoint()`: Gets the element at a specific point. Relates to user interaction and layout.
*   `clearHitTestCache()`: Clears the hit test cache. Relates to testing hit testing mechanisms.
*   `innerEditorElement()`: Gets the inner editable element of a container. Relates to HTML form elements.
*   `isPreloaded()`/`isPreloadedBy()`: Checks if a resource is preloaded. Relates to resource loading and network requests.
*   `isLoading()`: Checks if a resource is currently loading. Relates to resource loading and network requests.
*   `isLoadingFromMemoryCache()`: Checks if a resource is loaded from the memory cache. Relates to resource caching.
*   `getInitialResourcePriority()`/`getInitialResourcePriorityOfNewLoad()`: Gets the initial priority of a resource. Relates to resource loading and network prioritization.
*   `doesWindowHaveUrlFragment()`: Checks if a window's URL has a fragment. Relates to URL handling and navigation.
*   `getResourceHeader()`: Gets a specific header of a loaded resource. Relates to network requests and responses.
*   `treeScopeRootNode()`: Gets the root node of a node's tree scope. Relates to DOM structure, especially shadow DOM.
*   `parentTreeScope()`: Gets the parent tree scope of a node. Relates to DOM structure and shadow DOM.
*   `compareTreeScopePosition()`: Compares the position of two nodes in their respective tree scopes. Relates to DOM structure and shadow DOM.
*   `pauseAnimations()`: Pauses CSS animations. Relates to CSS animations.
*   `isCompositedAnimation()`: Checks if an animation is composited. Relates to CSS animations and rendering performance.
*   `disableCompositedAnimation()`: Disables compositing for an animation. For testing purposes.
*   `advanceImageAnimation()`: Advances an image animation. Relates to image formats (e.g., GIFs, APNGs).
*   `countElementShadow()`: Counts the number of child shadow roots. Relates to shadow DOM.
*   `nextSiblingInFlatTree()`/`firstChildInFlatTree()`/`lastChildInFlatTree()`/`nextInFlatTree()`/`previousInFlatTree()`: Traverse the flat tree (including shadow DOM). Relates to shadow DOM.
*   `elementLayoutTreeAsText()`: Gets a text representation of the layout tree for an element. Relates to layout and debugging.
*   `computedStyleIncludingVisitedInfo()`: Gets the computed style, including visited link styles. Relates to CSS and privacy.
*   `createUserAgentShadowRoot()`: Creates a user-agent shadow root for an element. Relates to shadow DOM.
*   `setBrowserControlsState()`/`setBrowserControlsShownRatio()`: Controls the state of browser UI elements. Relates to browser UI and fullscreen mode.
*   `effectiveRootScroller()`: Gets the effective root scroller element. Relates to scrolling and layout.
*   `shadowRoot()`: Gets the shadow root of an element. Relates to shadow DOM.
*   `ShadowRootMode()`: Gets the mode of a shadow root. Relates to shadow DOM.
*   `shadowPseudoId()`: Gets the shadow pseudo-ID of an element. Relates to shadow DOM styling.
*   `isValidationMessageVisible()`: Checks if a form validation message is visible. Relates to HTML forms and validation.
*   `selectColorInColorChooser()`/`endColorChooser()`:  Interact with the color chooser for input elements. Relates to HTML input type="color".
*   `hasAutofocusRequest()`: Checks if there's an autofocus request. Relates to HTML attribute `autofocus`.
*   `formControlStateOfHistoryItem()`/`setFormControlStateOfHistoryItem()`: Gets/sets the state of form controls in the browser history. Relates to HTML forms and browser history.
*   `pagePopupWindow()`: Gets a reference to a popup window. Relates to JavaScript's `window.open()`.
*   `absoluteCaretBounds()`: Gets the absolute position of the text caret. Relates to text input and selection.
*   `textAffinity()`: Gets the text affinity of the selection. Relates to text selection and bidirectional text.
*   `boundingBox()`: Gets the bounding box of an element. Relates to layout.
*   `setMarker()`/`removeMarker()`: Adds/removes document markers (like spellcheck underlines). Relates to text editing and spellchecking.
*   `markerCountForNode()`/`activeMarkerCountForNode()`/`MarkerAt()`/`markerRangeForNode()`/`markerDescriptionForNode()`/`markerBackgroundColorForNode()`/`markerUnderlineColorForNode()`:  Functions for inspecting document markers. Relates to text editing and spellchecking.
*   `addTextMatchMarker()`: Adds a marker for text matches (like in "find in page").
*   `addCompositionMarker()`/`addActiveSuggestionMarker()`/`addSuggestionMarker()`: Add markers related to IME composition and suggestions. Relates to text input and IME.

Now I can synthesize the response.
这是 `blink/renderer/core/testing/internals.cc` 文件的第二部分，主要提供了一系列用于测试 Blink 渲染引擎内部状态和行为的接口。这些接口通常通过 JavaScript 的 `internals` 全局对象暴露出来，主要用于编写 web platform tests (WPT) 和 Chromium 特定的测试。

**以下是这部分代码的功能归纳：**

1. **样式和布局信息获取：**
    *   `styleForElementCount()`: 获取文档中应用了样式的元素的数量。
    *   `needsLayoutCount()`: 获取文档中需要进行布局的元素的数量。
    *   `layoutCountForTesting()`: 获取用于测试的布局计数器值。
    *   `nodeNeedsStyleRecalc()`: 检查指定的节点是否需要重新计算样式。
    *   `elementLayoutTreeAsText()`:  以文本形式返回指定元素的布局树结构。

2. **Hit-testing 相关信息获取和操作：**
    *   `hitTestCount()`: 获取指定文档中执行的 hit-test 的次数。
    *   `hitTestCacheHits()`: 获取指定文档中 hit-test 缓存命中的次数。
    *   `elementFromPoint()`: 获取指定文档中特定坐标位置的元素。
    *   `clearHitTestCache()`: 清除指定文档的 hit-test 缓存。

3. **资源加载状态查询：**
    *   `isPreloaded()`/`isPreloadedBy()`: 检查指定的 URL 是否已被预加载。
    *   `isLoading()`: 检查指定的 URL 对应的资源是否正在加载。
    *   `isLoadingFromMemoryCache()`: 检查指定的 URL 对应的资源是否从内存缓存加载。
    *   `getInitialResourcePriority()`/`getInitialResourcePriorityOfNewLoad()`: 获取指定 URL 资源的初始优先级。
    *   `getResourceHeader()`: 获取指定 URL 资源的特定 HTTP 头部信息。

4. **DOM 树和 Shadow DOM 相关操作：**
    *   `treeScopeRootNode()`: 获取指定节点的树作用域的根节点。
    *   `parentTreeScope()`: 获取指定节点的父树作用域的根节点。
    *   `compareTreeScopePosition()`: 比较两个节点在其树作用域中的位置关系。
    *   `countElementShadow()`: 获取指定节点（必须是 Shadow Root）的子 Shadow Root 的数量。
    *   `nextSiblingInFlatTree()`/`firstChildInFlatTree()`/`lastChildInFlatTree()`/`nextInFlatTree()`/`previousInFlatTree()`:  在扁平树（包含 Shadow DOM）中进行节点遍历。
    *   `createUserAgentShadowRoot()`: 为指定的元素创建 User-Agent Shadow Root。
    *   `shadowRoot()`: 获取指定元素的 Shadow Root。
    *   `ShadowRootMode()`: 获取指定 Shadow Root 的模式（Open, Closed, UserAgent）。
    *   `shadowPseudoId()`: 获取指定元素的 Shadow Pseudo ID。

5. **动画控制：**
    *   `pauseAnimations()`: 暂停文档中的动画。
    *   `isCompositedAnimation()`: 检查指定的动画是否是合成动画。
    *   `disableCompositedAnimation()`: 禁用指定动画的合成。
    *   `advanceImageAnimation()`: 手动推进指定图片元素的动画（例如 GIF）。

6. **浏览器控件状态控制：**
    *   `setBrowserControlsState()`: 设置浏览器控件（例如地址栏）的高度和收缩布局状态。
    *   `setBrowserControlsShownRatio()`: 设置浏览器控件的显示比例。

7. **滚动相关：**
    *   `effectiveRootScroller()`: 获取有效的根滚动元素。

8. **表单和历史记录状态：**
    *   `formControlStateOfHistoryItem()`: 获取历史记录项中表单控件的状态。
    *   `setFormControlStateOfHistoryItem()`: 设置历史记录项中表单控件的状态。

9. **弹窗相关：**
    *   `pagePopupWindow()`: 获取页面弹出的窗口对象。

10. **文本和选择相关：**
    *   `absoluteCaretBounds()`: 获取绝对光标边界。
    *   `textAffinity()`: 获取文本方向性（上游或下游）。

11. **元素边界信息：**
    *   `boundingBox()`: 获取指定元素的边界框。

12. **Document Marker (标记) 相关操作：**
    *   `setMarker()`/`removeMarker()`: 在指定范围内设置或移除文档标记（例如拼写或语法错误）。
    *   `markerCountForNode()`/`activeMarkerCountForNode()`: 获取节点上特定类型或激活状态的标记数量。
    *   `MarkerAt()`: 获取节点上指定索引的标记对象。
    *   `markerRangeForNode()`: 获取节点上指定标记的范围。
    *   `markerDescriptionForNode()`: 获取节点上指定标记的描述信息。
    *   `markerBackgroundColorForNode()`/`markerUnderlineColorForNode()`: 获取节点上指定标记的背景色和下划线颜色。
    *   `addTextMatchMarker()`: 添加用于文本匹配的标记。
    *   `addCompositionMarker()`/`addActiveSuggestionMarker()`/`addSuggestionMarker()`: 添加与输入法相关的标记。

13. **表单验证相关：**
    *   `isValidationMessageVisible()`: 检查指定元素的验证消息是否可见。

14. **颜色选择器相关：**
    *   `selectColorInColorChooser()`: 在颜色选择器中选择颜色。
    *   `endColorChooser()`: 结束颜色选择器。

15. **自动聚焦相关：**
    *   `hasAutofocusRequest()`: 检查文档中是否有自动聚焦请求。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:** 这些 `Internals` 方法通常通过 JavaScript 的 `internals` 对象暴露出来。例如，在 JavaScript 中可以调用 `internals.styleForElementCount()` 来获取样式元素的数量，或者使用 `internals.elementFromPoint(document, x, y)` 来获取特定坐标的元素。

*   **HTML:**  许多方法直接操作或检查 HTML 元素和文档结构。例如，`elementFromPoint()` 返回一个 HTML 元素，`needsLayoutCount()` 的结果依赖于 HTML 结构的变化，`createUserAgentShadowRoot()` 会修改元素的 Shadow DOM 结构。

    *   **假设输入:**  一个包含嵌套 `div` 元素的 HTML 文档。
    *   **输出:**  调用 `internals.needsLayoutCount()` 可能会返回一个大于 0 的值，因为初始渲染或 DOM 结构改变可能导致需要重新布局。

*   **CSS:** 一些方法用于检查和操作 CSS 样式。例如，`styleForElementCount()` 统计应用了样式的元素，`nodeNeedsStyleRecalc()` 检查是否需要重新计算样式，`isCompositedAnimation()` 检查动画是否使用了 CSS 合成技术。

    *   **假设输入:**  一个 HTML 文档，其中某些元素的样式通过 CSS 规则定义。
    *   **输出:**  调用 `internals.styleForElementCount()` 会返回被 CSS 规则影响的元素的数量。  修改 CSS 规则后，再次调用此方法可能会得到不同的结果。

**逻辑推理的假设输入与输出：**

*   **方法:** `needsLayoutCount()`
    *   **假设输入:** 一个初始渲染完成的简单 HTML 页面。
    *   **输出:** 可能为 0，因为所有元素都已经布局完成。
    *   **假设输入:** 在上述页面中，通过 JavaScript 动态添加一个新的 `div` 元素。
    *   **输出:** 再次调用 `needsLayoutCount()` 可能会返回 1 或更大的值，因为新添加的元素需要进行布局。

*   **方法:** `isPreloaded()`
    *   **假设输入:**  HTML 中包含 `<link rel="preload" href="image.png">`。
    *   **输出:**  在页面加载的早期阶段调用 `internals.isPreloaded('image.png')` 可能会返回 `true`。
    *   **假设输入:**  HTML 中不包含预加载的链接。
    *   **输出:**  调用 `internals.isPreloaded('some_random_image.jpg')` 很可能会返回 `false`。

**涉及用户或编程常见的使用错误：**

*   **错误使用场景：**  尝试在非测试环境中使用 `internals` 对象。 `internals` 对象是为了测试目的而存在的，在普通的浏览器环境中不可用。
    *   **用户操作:**  普通用户无法直接访问或使用 `internals` 对象。这是开发者工具和测试框架使用的 API。
    *   **编程错误:**  开发者可能会错误地在生产代码中依赖 `internals` 对象，导致代码在普通浏览器中无法运行。

*   **参数错误：**  某些方法需要特定的参数类型或非空的参数。
    *   **编程错误:**  例如，`internals.elementFromPoint(null, 10, 20)` 会因为 `document` 参数为 null 而抛出异常。
    *   **异常信息:**  类似 `"Must supply document to check"` 的错误信息。

*   **类型错误：** 某些方法要求参数是特定的 DOM 节点类型。
    *   **编程错误:**  例如，`internals.nodeNeedsStyleRecalc(document.body.firstChild)` 如果 `firstChild` 不是一个 `Node` 对象，可能会导致错误。
    *   **异常信息:** 类似 `"Not a node"` 的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索：**

`internals` 对象及其方法主要用于开发和测试阶段，普通用户操作不会直接触发这些代码。以下是一些可能到达这里的调试线索：

1. **Web Platform Tests (WPT):**  Chromium 团队和 W3C 使用 WPT 来测试浏览器行为。WPT 脚本会使用 `internals` 对象来断言浏览器的内部状态是否符合预期。
    *   **调试线索:**  如果一个 WPT 测试失败，开发者可能会查看测试脚本中对 `internals` 方法的调用，并分析这些方法返回的值，以找出渲染引擎的异常行为。

2. **Chromium 开发者调试:** Chromium 开发者在开发和调试 Blink 渲染引擎时，可能会编写使用 `internals` 对象的特定测试用例，以隔离和诊断问题。
    *   **调试线索:**  开发者可以通过运行这些内部测试，并结合断点调试，来跟踪代码执行路径，观察 `internals` 方法的返回值，从而理解引擎的内部运作。

3. **Layout Test (旧版 Blink 测试):**  虽然 WPT 是主要的测试方式，但可能仍有遗留的 layout test 使用 `internals`。
    *   **调试线索:**  类似于 WPT，检查 layout test 的脚本中对 `internals` 的调用。

**总结一下这部分的功能:**

这部分 `internals.cc` 代码主要提供了用于测试 Blink 渲染引擎内部状态和行为的接口，涵盖了样式布局信息、hit-testing、资源加载状态、DOM 树和 Shadow DOM 操作、动画控制、浏览器控件状态、滚动、表单和历史记录、弹窗、文本选择、元素边界以及 Document Marker 等多个方面。 这些接口主要服务于自动化测试框架，帮助开发者验证浏览器的行为是否符合预期。

### 提示词
```
这是目录为blink/renderer/core/testing/internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
"No context document is available.");
    return 0;
  }

  return document_->GetStyleEngine().StyleForElementCount();
}

unsigned Internals::needsLayoutCount(ExceptionState& exception_state) const {
  LocalFrame* context_frame = GetFrame();
  if (!context_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context frame is available.");
    return 0;
  }

  bool is_partial;
  unsigned needs_layout_objects;
  unsigned total_objects;
  context_frame->View()->CountObjectsNeedingLayout(needs_layout_objects,
                                                   total_objects, is_partial);
  return needs_layout_objects;
}

unsigned Internals::layoutCountForTesting(
    ExceptionState& exception_state) const {
  LocalFrame* context_frame = GetFrame();
  if (!context_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context frame is available.");
    return 0;
  }

  return context_frame->View()->LayoutCountForTesting();
}

bool Internals::nodeNeedsStyleRecalc(Node* node,
                                     ExceptionState& exception_state) const {
  if (!node) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidNodeTypeError,
                                      "Not a node");
    return false;
  }

  return node->NeedsStyleRecalc();
}

unsigned Internals::hitTestCount(Document* doc,
                                 ExceptionState& exception_state) const {
  if (!doc) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Must supply document to check");
    return 0;
  }

  if (!doc->GetLayoutView())
    return 0;

  return doc->GetLayoutView()->HitTestCount();
}

unsigned Internals::hitTestCacheHits(Document* doc,
                                     ExceptionState& exception_state) const {
  if (!doc) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Must supply document to check");
    return 0;
  }

  if (!doc->GetLayoutView())
    return 0;

  return doc->GetLayoutView()->HitTestCacheHits();
}

Element* Internals::elementFromPoint(Document* doc,
                                     double x,
                                     double y,
                                     bool ignore_clipping,
                                     bool allow_child_frame_content,
                                     ExceptionState& exception_state) const {
  if (!doc) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Must supply document to check");
    return nullptr;
  }

  if (!doc->GetLayoutView())
    return nullptr;

  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kReadOnly | HitTestRequest::kActive;
  if (ignore_clipping)
    hit_type |= HitTestRequest::kIgnoreClipping;
  if (allow_child_frame_content)
    hit_type |= HitTestRequest::kAllowChildFrameContent;

  HitTestRequest request(hit_type);

  return doc->HitTestPoint(x, y, request);
}

void Internals::clearHitTestCache(Document* doc,
                                  ExceptionState& exception_state) const {
  if (!doc) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Must supply document to check");
    return;
  }

  if (!doc->GetLayoutView())
    return;

  doc->GetLayoutView()->ClearHitTestCache();
}

Element* Internals::innerEditorElement(Element* container,
                                       ExceptionState& exception_state) const {
  if (auto* control = ToTextControlOrNull(container))
    return control->InnerEditorElement();

  exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                    "Not a text control element.");
  return nullptr;
}

bool Internals::isPreloaded(const String& url) {
  return isPreloadedBy(url, document_.Get());
}

bool Internals::isPreloadedBy(const String& url, Document* document) {
  if (!document)
    return false;
  return document->Fetcher()->IsPreloadedForTest(document->CompleteURL(url));
}

bool Internals::isLoading(const String& url) {
  if (!document_)
    return false;
  const KURL full_url = document_->CompleteURL(url);
  const String cache_identifier = document_->Fetcher()->GetCacheIdentifier(
      full_url, /*skip_service_worker=*/false);
  Resource* resource =
      MemoryCache::Get()->ResourceForURL(full_url, cache_identifier);
  // We check loader() here instead of isLoading(), because a multipart
  // ImageResource lies isLoading() == false after the first part is loaded.
  return resource && resource->Loader();
}

bool Internals::isLoadingFromMemoryCache(const String& url) {
  if (!document_)
    return false;
  const KURL full_url = document_->CompleteURL(url);
  const String cache_identifier = document_->Fetcher()->GetCacheIdentifier(
      full_url, /*skip_service_worker=*/false);
  Resource* resource =
      MemoryCache::Get()->ResourceForURL(full_url, cache_identifier);
  return resource && resource->GetStatus() == ResourceStatus::kCached;
}

ScriptPromise<IDLLong> Internals::getInitialResourcePriority(
    ScriptState* script_state,
    const String& url,
    Document* document,
    bool new_load_only) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLLong>>(script_state);
  auto promise = resolver->Promise();
  KURL resource_url = url_test_helpers::ToKURL(url.Utf8());

  auto callback = WTF::BindOnce(&Internals::ResolveResourcePriority,
                                WrapPersistent(this), WrapPersistent(resolver));
  document->Fetcher()->AddPriorityObserverForTesting(
      resource_url, std::move(callback), new_load_only);

  return promise;
}

ScriptPromise<IDLLong> Internals::getInitialResourcePriorityOfNewLoad(
    ScriptState* script_state,
    const String& url,
    Document* document) {
  return getInitialResourcePriority(script_state, url, document, true);
}

bool Internals::doesWindowHaveUrlFragment(DOMWindow* window) {
  if (IsA<RemoteDOMWindow>(window))
    return false;
  return To<LocalFrame>(window->GetFrame())
      ->GetDocument()
      ->Url()
      .HasFragmentIdentifier();
}

String Internals::getResourceHeader(const String& url,
                                    const String& header,
                                    Document* document) {
  if (!document)
    return String();
  Resource* resource = document->Fetcher()->AllResources().at(
      url_test_helpers::ToKURL(url.Utf8()));
  if (!resource)
    return String();
  return resource->GetResourceRequest().HttpHeaderField(AtomicString(header));
}

Node* Internals::treeScopeRootNode(Node* node) {
  DCHECK(node);
  return &node->GetTreeScope().RootNode();
}

Node* Internals::parentTreeScope(Node* node) {
  DCHECK(node);
  const TreeScope* parent_tree_scope = node->GetTreeScope().ParentTreeScope();
  return parent_tree_scope ? &parent_tree_scope->RootNode() : nullptr;
}

uint16_t Internals::compareTreeScopePosition(
    const Node* node1,
    const Node* node2,
    ExceptionState& exception_state) const {
  DCHECK(node1 && node2);
  const TreeScope* tree_scope1 =
      IsA<Document>(node1) ? static_cast<const TreeScope*>(To<Document>(node1))
      : IsA<ShadowRoot>(node1)
          ? static_cast<const TreeScope*>(To<ShadowRoot>(node1))
          : nullptr;
  const TreeScope* tree_scope2 =
      IsA<Document>(node2) ? static_cast<const TreeScope*>(To<Document>(node2))
      : IsA<ShadowRoot>(node2)
          ? static_cast<const TreeScope*>(To<ShadowRoot>(node2))
          : nullptr;
  if (!tree_scope1 || !tree_scope2) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        String::Format(
            "The %s node is neither a document node, nor a shadow root.",
            tree_scope1 ? "second" : "first"));
    return 0;
  }
  return tree_scope1->ComparePosition(*tree_scope2);
}

void Internals::pauseAnimations(double pause_time,
                                ExceptionState& exception_state) {
  if (pause_time < 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        ExceptionMessages::IndexExceedsMinimumBound("pauseTime", pause_time,
                                                    0.0));
    return;
  }

  if (!GetFrame())
    return;

  GetFrame()->View()->UpdateAllLifecyclePhasesForTest();
  GetFrame()->GetDocument()->Timeline().PauseAnimationsForTesting(
      ANIMATION_TIME_DELTA_FROM_SECONDS(pause_time));
}

bool Internals::isCompositedAnimation(Animation* animation) {
  return animation->HasActiveAnimationsOnCompositor();
}

void Internals::disableCompositedAnimation(Animation* animation) {
  animation->DisableCompositedAnimationForTesting();
}

void Internals::advanceImageAnimation(Element* image,
                                      ExceptionState& exception_state) {
  DCHECK(image);

  ImageResourceContent* content = nullptr;
  if (auto* html_image = DynamicTo<HTMLImageElement>(*image)) {
    content = html_image->CachedImage();
  } else if (auto* svg_image = DynamicTo<SVGImageElement>(*image)) {
    content = svg_image->CachedImage();
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The element provided is not a image element.");
    return;
  }

  if (!content || !content->HasImage()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The image resource is not available.");
    return;
  }

  Image* image_data = content->GetImage();
  image_data->AdvanceAnimationForTesting();
}

uint32_t Internals::countElementShadow(const Node* root,
                                       ExceptionState& exception_state) const {
  DCHECK(root);
  if (!IsA<ShadowRoot>(root)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The node argument is not a shadow root.");
    return 0;
  }
  return To<ShadowRoot>(root)->ChildShadowRootCount();
}

namespace {

bool CheckForFlatTreeExceptions(Node* node, ExceptionState& exception_state) {
  if (node && !node->IsShadowRoot())
    return false;
  exception_state.ThrowDOMException(
      DOMExceptionCode::kInvalidAccessError,
      "The node argument doesn't participate in the flat tree.");
  return true;
}

}  // namespace

Node* Internals::nextSiblingInFlatTree(Node* node,
                                       ExceptionState& exception_state) {
  if (CheckForFlatTreeExceptions(node, exception_state))
    return nullptr;
  return FlatTreeTraversal::NextSibling(*node);
}

Node* Internals::firstChildInFlatTree(Node* node,
                                      ExceptionState& exception_state) {
  if (CheckForFlatTreeExceptions(node, exception_state))
    return nullptr;
  return FlatTreeTraversal::FirstChild(*node);
}

Node* Internals::lastChildInFlatTree(Node* node,
                                     ExceptionState& exception_state) {
  if (CheckForFlatTreeExceptions(node, exception_state))
    return nullptr;
  return FlatTreeTraversal::LastChild(*node);
}

Node* Internals::nextInFlatTree(Node* node, ExceptionState& exception_state) {
  if (CheckForFlatTreeExceptions(node, exception_state))
    return nullptr;
  return FlatTreeTraversal::Next(*node);
}

Node* Internals::previousInFlatTree(Node* node,
                                    ExceptionState& exception_state) {
  if (CheckForFlatTreeExceptions(node, exception_state))
    return nullptr;
  return FlatTreeTraversal::Previous(*node);
}

String Internals::elementLayoutTreeAsText(Element* element,
                                          ExceptionState& exception_state) {
  DCHECK(element);
  element->GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  String representation = ExternalRepresentation(element);
  if (representation.empty()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The element provided has no external representation.");
    return String();
  }

  return representation;
}

CSSStyleDeclaration* Internals::computedStyleIncludingVisitedInfo(
    Element* element) const {
  DCHECK(element);
  bool allow_visited_style = true;
  return MakeGarbageCollected<CSSComputedStyleDeclaration>(element,
                                                           allow_visited_style);
}

ShadowRoot* Internals::createUserAgentShadowRoot(Element* host) {
  DCHECK(host);
  return &host->EnsureUserAgentShadowRoot();
}

void Internals::setBrowserControlsState(float top_height,
                                        float bottom_height,
                                        bool shrinks_layout) {
  document_->GetPage()->GetChromeClient().SetBrowserControlsState(
      top_height, bottom_height, shrinks_layout);
}

void Internals::setBrowserControlsShownRatio(float top_ratio,
                                             float bottom_ratio) {
  document_->GetPage()->GetChromeClient().SetBrowserControlsShownRatio(
      top_ratio, bottom_ratio);
}

Node* Internals::effectiveRootScroller(Document* document) {
  if (!document)
    document = document_;

  return &document->GetRootScrollerController().EffectiveRootScroller();
}

ShadowRoot* Internals::shadowRoot(Element* host) {
  DCHECK(host);
  if (auto* input = DynamicTo<HTMLInputElement>(*host)) {
    input->EnsureShadowSubtree();
  }
  return host->GetShadowRoot();
}

String Internals::ShadowRootMode(const Node* root,
                                 ExceptionState& exception_state) const {
  DCHECK(root);
  auto* shadow_root = DynamicTo<ShadowRoot>(root);
  if (!shadow_root) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The node provided is not a shadow root.");
    return String();
  }

  switch (shadow_root->GetMode()) {
    case ShadowRootMode::kUserAgent:
      return String("UserAgentShadowRoot");
    case ShadowRootMode::kOpen:
      return String("OpenShadowRoot");
    case ShadowRootMode::kClosed:
      return String("ClosedShadowRoot");
    default:
      NOTREACHED();
  }
}

const AtomicString& Internals::shadowPseudoId(Element* element) {
  DCHECK(element);
  return element->ShadowPseudoId();
}

bool Internals::isValidationMessageVisible(Element* element) {
  DCHECK(element);
  if (auto* page = element->GetDocument().GetPage()) {
    return page->GetValidationMessageClient().IsValidationMessageVisible(
        *element);
  }
  return false;
}

void Internals::selectColorInColorChooser(Element* element,
                                          const String& color_value) {
  DCHECK(element);
  Color color;
  if (!color.SetFromString(color_value))
    return;
  if (auto* input = DynamicTo<HTMLInputElement>(*element))
    input->SelectColorInColorChooser(color);
}

void Internals::endColorChooser(Element* element) {
  DCHECK(element);
  if (auto* input = DynamicTo<HTMLInputElement>(*element))
    input->EndColorChooserForTesting();
}

bool Internals::hasAutofocusRequest(Document* document) {
  if (!document)
    document = document_;
  return document->HasAutofocusCandidates();
}

bool Internals::hasAutofocusRequest() {
  return hasAutofocusRequest(nullptr);
}

Vector<String> Internals::formControlStateOfHistoryItem(
    ExceptionState& exception_state) {
  HistoryItem* main_item = nullptr;
  if (GetFrame())
    main_item = GetFrame()->Loader().GetDocumentLoader()->GetHistoryItem();
  if (!main_item) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No history item is available.");
    return Vector<String>();
  }
  return main_item->GetDocumentState();
}

void Internals::setFormControlStateOfHistoryItem(
    const Vector<String>& state,
    ExceptionState& exception_state) {
  HistoryItem* main_item = nullptr;
  if (GetFrame())
    main_item = GetFrame()->Loader().GetDocumentLoader()->GetHistoryItem();
  if (!main_item) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No history item is available.");
    return;
  }
  main_item->ClearDocumentState();
  main_item->SetDocumentState(state);
}

DOMWindow* Internals::pagePopupWindow() const {
  if (!document_)
    return nullptr;
  if (Page* page = document_->GetPage()) {
    return To<LocalDOMWindow>(
        page->GetChromeClient().PagePopupWindowForTesting());
  }
  return nullptr;
}

DOMRectReadOnly* Internals::absoluteCaretBounds(
    ExceptionState& exception_state) {
  if (!GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's frame cannot be retrieved.");
    return nullptr;
  }

  document_->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  return DOMRectReadOnly::FromRect(
      GetFrame()->Selection().AbsoluteCaretBounds());
}

String Internals::textAffinity() {
  if (GetFrame() && GetFrame()
                            ->GetPage()
                            ->GetFocusController()
                            .FocusedFrame()
                            ->Selection()
                            .GetSelectionInDOMTree()
                            .Affinity() == TextAffinity::kUpstream) {
    return "Upstream";
  }
  return "Downstream";
}

DOMRectReadOnly* Internals::boundingBox(Element* element) {
  DCHECK(element);

  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  LayoutObject* layout_object = element->GetLayoutObject();
  if (!layout_object)
    return DOMRectReadOnly::Create(0, 0, 0, 0);
  return DOMRectReadOnly::FromRect(layout_object->AbsoluteBoundingBoxRect());
}

void Internals::setMarker(Document* document,
                          const Range* range,
                          const String& marker_type,
                          ExceptionState& exception_state) {
  if (!document) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context document is available.");
    return;
  }

  std::optional<DocumentMarker::MarkerType> type = MarkerTypeFrom(marker_type);
  if (!type) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The marker type provided ('" + marker_type + "') is invalid.");
    return;
  }

  if (type != DocumentMarker::kSpelling && type != DocumentMarker::kGrammar) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "internals.setMarker() currently only "
                                      "supports spelling and grammar markers; "
                                      "attempted to add marker of type '" +
                                          marker_type + "'.");
    return;
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  if (type == DocumentMarker::kSpelling)
    document->Markers().AddSpellingMarker(EphemeralRange(range));
  else
    document->Markers().AddGrammarMarker(EphemeralRange(range));
}

void Internals::removeMarker(Document* document,
                             const Range* range,
                             const String& marker_type,
                             ExceptionState& exception_state) {
  if (!document) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context document is available.");
    return;
  }

  std::optional<DocumentMarker::MarkerType> type = MarkerTypeFrom(marker_type);
  if (!type) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The marker type provided ('" + marker_type + "') is invalid.");
    return;
  }

  if (type != DocumentMarker::kSpelling && type != DocumentMarker::kGrammar) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "internals.setMarker() currently only "
                                      "supports spelling and grammar markers; "
                                      "attempted to add marker of type '" +
                                          marker_type + "'.");
    return;
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  if (type == DocumentMarker::kSpelling) {
    document->Markers().RemoveMarkersInRange(
        EphemeralRange(range), DocumentMarker::MarkerTypes::Spelling());
  } else {
    document->Markers().RemoveMarkersInRange(
        EphemeralRange(range), DocumentMarker::MarkerTypes::Grammar());
  }
}

unsigned Internals::markerCountForNode(Text* text,
                                       const String& marker_type,
                                       ExceptionState& exception_state) {
  DCHECK(text);
  std::optional<DocumentMarker::MarkerTypes> marker_types =
      MarkerTypesFrom(marker_type);
  if (!marker_types) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The marker type provided ('" + marker_type + "') is invalid.");
    return 0;
  }

  return text->GetDocument()
      .Markers()
      .MarkersFor(*text, marker_types.value())
      .size();
}

unsigned Internals::activeMarkerCountForNode(Text* text) {
  DCHECK(text);

  // Only TextMatch markers can be active.
  DocumentMarkerVector markers = text->GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextMatch());

  unsigned active_marker_count = 0;
  for (const auto& marker : markers) {
    if (To<TextMatchMarker>(marker.Get())->IsActiveMatch())
      active_marker_count++;
  }

  return active_marker_count;
}

DocumentMarker* Internals::MarkerAt(Text* text,
                                    const String& marker_type,
                                    unsigned index,
                                    ExceptionState& exception_state) {
  DCHECK(text);
  std::optional<DocumentMarker::MarkerTypes> marker_types =
      MarkerTypesFrom(marker_type);
  if (!marker_types) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The marker type provided ('" + marker_type + "') is invalid.");
    return nullptr;
  }

  DocumentMarkerVector markers =
      text->GetDocument().Markers().MarkersFor(*text, marker_types.value());
  if (markers.size() <= index)
    return nullptr;
  return markers[index].Get();
}

Range* Internals::markerRangeForNode(Text* text,
                                     const String& marker_type,
                                     unsigned index,
                                     ExceptionState& exception_state) {
  DCHECK(text);
  DocumentMarker* marker = MarkerAt(text, marker_type, index, exception_state);
  if (!marker)
    return nullptr;
  return MakeGarbageCollected<Range>(text->GetDocument(), text,
                                     marker->StartOffset(), text,
                                     marker->EndOffset());
}

String Internals::markerDescriptionForNode(Text* text,
                                           const String& marker_type,
                                           unsigned index,
                                           ExceptionState& exception_state) {
  DocumentMarker* marker = MarkerAt(text, marker_type, index, exception_state);
  if (!marker || !IsSpellCheckMarker(*marker))
    return String();
  return To<SpellCheckMarker>(marker)->Description();
}

unsigned Internals::markerBackgroundColorForNode(
    Text* text,
    const String& marker_type,
    unsigned index,
    ExceptionState& exception_state) {
  DocumentMarker* marker = MarkerAt(text, marker_type, index, exception_state);
  auto* style_marker = DynamicTo<StyleableMarker>(marker);
  if (!style_marker)
    return 0;
  return style_marker->BackgroundColor().Rgb();
}

unsigned Internals::markerUnderlineColorForNode(
    Text* text,
    const String& marker_type,
    unsigned index,
    ExceptionState& exception_state) {
  DocumentMarker* marker = MarkerAt(text, marker_type, index, exception_state);
  auto* style_marker = DynamicTo<StyleableMarker>(marker);
  if (!style_marker)
    return 0;
  return style_marker->UnderlineColor().Rgb();
}

static std::optional<TextMatchMarker::MatchStatus> MatchStatusFrom(
    const String& match_status) {
  if (EqualIgnoringASCIICase(match_status, "kActive"))
    return TextMatchMarker::MatchStatus::kActive;
  if (EqualIgnoringASCIICase(match_status, "kInactive"))
    return TextMatchMarker::MatchStatus::kInactive;
  return std::nullopt;
}

void Internals::addTextMatchMarker(const Range* range,
                                   const String& match_status,
                                   ExceptionState& exception_state) {
  DCHECK(range);
  if (!range->OwnerDocument().View())
    return;

  std::optional<TextMatchMarker::MatchStatus> match_status_enum =
      MatchStatusFrom(match_status);
  if (!match_status_enum) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The match status provided ('" + match_status + "') is invalid.");
    return;
  }

  range->OwnerDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  range->OwnerDocument().Markers().AddTextMatchMarker(
      EphemeralRange(range), match_status_enum.value());

  // This simulates what the production code does after
  // DocumentMarkerController::addTextMatchMarker().
  range->OwnerDocument().GetLayoutView()->InvalidatePaintForTickmarks();
}

static bool ParseColor(const String& value,
                       Color& color,
                       ExceptionState& exception_state,
                       String error_message) {
  if (!color.SetFromString(value)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      error_message);
    return false;
  }
  return true;
}

static std::optional<ImeTextSpanThickness> ThicknessFrom(
    const String& thickness) {
  if (EqualIgnoringASCIICase(thickness, "none"))
    return ImeTextSpanThickness::kNone;
  if (EqualIgnoringASCIICase(thickness, "thin"))
    return ImeTextSpanThickness::kThin;
  if (EqualIgnoringASCIICase(thickness, "thick"))
    return ImeTextSpanThickness::kThick;
  return std::nullopt;
}

static std::optional<ImeTextSpanUnderlineStyle> UnderlineStyleFrom(
    const String& underline_style) {
  if (EqualIgnoringASCIICase(underline_style, "none"))
    return ImeTextSpanUnderlineStyle::kNone;
  if (EqualIgnoringASCIICase(underline_style, "solid"))
    return ImeTextSpanUnderlineStyle::kSolid;
  if (EqualIgnoringASCIICase(underline_style, "dot"))
    return ImeTextSpanUnderlineStyle::kDot;
  if (EqualIgnoringASCIICase(underline_style, "dash"))
    return ImeTextSpanUnderlineStyle::kDash;
  if (EqualIgnoringASCIICase(underline_style, "squiggle"))
    return ImeTextSpanUnderlineStyle::kSquiggle;
  return std::nullopt;
}

namespace {

void AddStyleableMarkerHelper(const Range* range,
                              const String& underline_color_value,
                              const String& thickness_value,
                              const String& underline_style_value,
                              const String& text_color_value,
                              const String& background_color_value,
                              ExceptionState& exception_state,
                              base::FunctionRef<void(const EphemeralRange&,
                                                     Color,
                                                     ImeTextSpanThickness,
                                                     ImeTextSpanUnderlineStyle,
                                                     Color,
                                                     Color)> create_marker) {
  DCHECK(range);
  range->OwnerDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  std::optional<ImeTextSpanThickness> thickness =
      ThicknessFrom(thickness_value);
  if (!thickness) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The thickness provided ('" + thickness_value + "') is invalid.");
    return;
  }

  std::optional<ImeTextSpanUnderlineStyle> underline_style =
      UnderlineStyleFrom(underline_style_value);
  if (!underline_style_value) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The underline style provided ('" +
                                          underline_style_value +
                                          "') is invalid.");
    return;
  }

  Color underline_color;
  Color background_color;
  Color text_color;
  if (ParseColor(underline_color_value, underline_color, exception_state,
                 "Invalid underline color.") &&
      ParseColor(text_color_value, text_color, exception_state,
                 "Invalid text color.") &&
      ParseColor(background_color_value, background_color, exception_state,
                 "Invalid background color.")) {
    create_marker(EphemeralRange(range), underline_color, thickness.value(),
                  underline_style.value(), text_color, background_color);
  }
}

}  // namespace

void Internals::addCompositionMarker(const Range* range,
                                     const String& underline_color_value,
                                     const String& thickness_value,
                                     const String& underline_style_value,
                                     const String& text_color_value,
                                     const String& background_color_value,
                                     ExceptionState& exception_state) {
  DocumentMarkerController& document_marker_controller =
      range->OwnerDocument().Markers();
  AddStyleableMarkerHelper(
      range, underline_color_value, thickness_value, underline_style_value,
      text_color_value, background_color_value, exception_state,
      [&document_marker_controller](const EphemeralRange& range,
                                    Color underline_color,
                                    ImeTextSpanThickness thickness,
                                    ImeTextSpanUnderlineStyle underline_style,
                                    Color text_color, Color background_color) {
        document_marker_controller.AddCompositionMarker(
            range, underline_color, thickness, underline_style, text_color,
            background_color);
      });
}

void Internals::addActiveSuggestionMarker(const Range* range,
                                          const String& underline_color_value,
                                          const String& thickness_value,
                                          const String& background_color_value,
                                          ExceptionState& exception_state) {
  // Underline style and text color aren't really supported for suggestions so
  // providing default values for now.
  String underline_style_value = "solid";
  String text_color_value = "transparent";
  DocumentMarkerController& document_marker_controller =
      range->OwnerDocument().Markers();
  AddStyleableMarkerHelper(
      range, underline_color_value, thickness_value, underline_style_value,
      text_color_value, background_color_value, exception_state,
      [&document_marker_controller](const EphemeralRange& range,
                                    Color underline_color,
                                    ImeTextSpanThickness thickness,
                                    ImeTextSpanUnderlineStyle underline_style,
                                    Color text_color, Color background_color) {
        document_marker_controller.AddActiveSuggestionMarker(
            range, underline_color, thickness, underline_style, text_color,
            background_color);
      });
}

void Internals::addSuggestionMarker(
    const Range* range,
    const Vector<String>& suggestions,
    const String& suggestion_highlight_color_value,
    const String& underline_color_value,
    const String& thickness_value,
    const String& background_color_value,
    ExceptionState& exception_state) {
  // Underline style and text color aren't really supported for suggestions so
  // providing default values for now.
  String underline_style_value = "solid";
  String text_color_value = "transparent";
  Color suggestion_highlight_color;
  if (!ParseColor(suggestion_highlight_color_value, suggestion_highlight_color,
                  exception_state, "Invalid suggestion highlight color."))
    return;

  DocumentMarkerController& document_marker_controller =
      range->OwnerDocument().Markers();
  AddStyleableMarkerHelper(
      ra
```