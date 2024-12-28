Response:
My thinking process to analyze the `Document.cc` file went through these stages:

1. **Understand the Core Function:** The file is named `document.cc` and resides within the `blink/renderer/core/dom` directory. This immediately tells me it's a core part of Blink's DOM implementation, specifically dealing with the `Document` object. The `Document` object represents the root of an HTML (or XML) document tree.

2. **Initial Scan for Key Areas:** I quickly scanned the code, looking for recurring themes and keywords. I noticed things like:
    * **Attributes:** `setVlinkColor`, `SetBodyAttribute`, `ShouldInvalidateNodeListCachesForAttr`. This hints at attribute handling.
    * **Style and Rendering:** `fonts()`, `PlatformColorsChanged()`, `ComputedStyleMap`, `StyleEngine`, `LayoutView`, `InStyleRecalc`, `GetColorProviderForPainting`. This clearly relates to CSS and rendering.
    * **JavaScript Execution:** `DelayAsyncScriptExecution`, `ResumeAsyncScriptExecution`, `ExecuteJavaScriptUrls`, `ProcessJavaScriptUrl`, `CancelPendingJavaScriptUrls`. This points to the document's role in running scripts.
    * **Event Handling:**  `DispatchEvent`, `EnqueueEvent`, mentions of `kBeforeunload`, `kPrerenderingchange`, `kSelectionchange`. This indicates event management.
    * **Focus Management:** `autofocus_candidates_`, `focused_element_`, `IsFocusAllowed`. This relates to how the document handles focus.
    * **Resource Loading:** `GetResourceCoordinator`, `pending_javascript_urls_`, `pending_link_header_preloads_`. This suggests responsibility for managing resources.
    * **Prerendering:** `ActivateForPrerendering`, `AddWillDispatchPrerenderingchangeCallback`, `AddPostPrerenderingActivationStep`. This indicates support for preloading pages.
    * **Other DOM elements:** Mentions of `Element`, `NodeList`, `FontFaceSet`, `HTMLInputElement`. This confirms its role as the root of the DOM tree.
    * **Feature Flags and Settings:**  References to `RuntimeEnabledFeatures`, `GetSettings`. This indicates feature gating and configuration.

3. **Categorize Functionality:** I started grouping related functions and data members to create a more structured understanding. This led to the main functional areas like:
    * **Document Properties and Attributes:**  Managing document-level attributes and properties.
    * **Style and Rendering:** Handling stylesheets, computed styles, and color schemes.
    * **JavaScript Interaction:**  Executing and managing JavaScript.
    * **DOM Manipulation and Queries:**  Invalidating node list caches, managing element focus.
    * **Resource Management:** Coordinating resource loading.
    * **Event Handling:**  Dispatching and queuing events.
    * **Navigation and Prerendering:**  Supporting prerendering and page transitions.
    * **Security and Feature Policies:**  Implementing feature policies and handling sandbox restrictions.
    * **Accessibility:**  Interacting with the accessibility tree.
    * **Performance and Optimization:**  Mechanisms like delaying script execution and managing caches.

4. **Analyze Relationships with Web Technologies:**  For each functional area, I explicitly considered its connection to JavaScript, HTML, and CSS. For example:
    * **JavaScript:**  Functions like `ExecuteJavaScriptUrls` directly interact with JavaScript execution. The `ComputedStyleMap` is used by JavaScript to get the computed styles of elements. Event handling is crucial for JavaScript interaction with the DOM.
    * **HTML:** Setting attributes (`setVlinkColor`) directly manipulates the HTML structure. The document is the root of the HTML tree. Parsing HTML is mentioned.
    * **CSS:**  Functions like `PlatformColorsChanged` and `ComputedStyleMap` are directly related to CSS. The `StyleEngine` is a core component for CSS processing. The concept of invalidating node lists is relevant when CSS selectors change.

5. **Look for Logic and Potential Issues:** I examined the conditional logic (`if` statements) and tried to infer potential scenarios and edge cases. This helped identify potential user/programming errors:
    * **Incorrect Attribute Usage:** Setting attributes that don't exist or aren't applicable.
    * **Scripting Errors:**  JavaScript URLs not being handled correctly, or errors during script execution.
    * **Focus Issues:**  Trying to focus elements when it's not allowed (e.g., in sandboxed frames without user activation).
    * **Resource Loading Problems:**  Issues with preloaded resources.

6. **Consider Debugging Context:**  I thought about how a developer might end up in this code during debugging. This led to scenarios like:
    * **Inspecting Document Properties:** Using the browser's developer tools to examine the `document` object.
    * **Debugging Style Issues:** Stepping through the code when investigating CSS problems.
    * **Investigating JavaScript Errors:**  Tracing the execution flow when a JavaScript URL is encountered.
    * **Analyzing Focus Behavior:**  Understanding why an element is or isn't being focused.

7. **Address Specific Instructions:** I made sure to explicitly address each part of the prompt:
    * **List functions:** This was a core part of the analysis.
    * **Relate to JS/HTML/CSS:**  Provided concrete examples.
    * **Logic and I/O:** Gave hypothetical examples for functions like `ShouldInvalidateNodeListCachesForAttr`.
    * **User errors:** Provided specific examples.
    * **User path to the code:** Described debugging scenarios.
    * **Part 11 of 11:** Summarized the overall role of the `Document` class.

8. **Refine and Organize:**  Finally, I reviewed and organized my thoughts into a clear and coherent explanation, using headings and bullet points to improve readability. I ensured the language was accurate and avoided jargon where possible. I also made sure to explicitly state any assumptions or interpretations I made.

By following these steps, I could systematically break down the complex code and provide a comprehensive answer that addressed all aspects of the prompt. The iterative nature of scanning, categorizing, and analyzing was key to understanding the file's purpose and its interactions with other parts of the browser engine and web technologies.
好的，我们来分析一下 `blink/renderer/core/dom/document.cc` 文件的功能。

**文件功能归纳：**

`document.cc` 文件是 Chromium Blink 引擎中 `Document` 类的实现文件。`Document` 类在 DOM (Document Object Model) 中代表一个 HTML 或 XML 文档。它是整个文档树的根节点，负责管理和维护与文档相关的各种状态、属性和功能。

**具体功能列举：**

1. **文档属性管理:**
   - 设置和获取文档的各种属性，例如链接颜色 (`setVlinkColor`)。
   - 管理文档的子元素（虽然这段代码没有直接展示添加子元素，但 `Document` 类是容器节点，负责管理其子节点）。

2. **样式管理和交互:**
   - 提供访问文档关联的字体集合 (`fonts()`)。
   - 处理平台颜色变化事件 (`PlatformColorsChanged()`)，通知样式引擎进行更新。
   - 管理元素的计算样式缓存 (`ComputedStyleMap`, `AddComputedStyleMapItem`, `RemoveComputedStyleMapItem`)，优化性能。
   - 判断是否需要进行样式重算 (`InStyleRecalc`)。
   - 获取用于绘制的颜色提供器 (`GetColorProviderForPainting`)，考虑了强制颜色模式。
   - 处理首选颜色方案变化 (`ColorSchemeChanged`) 和视觉缺陷变化 (`VisionDeficiencyChanged`)。

3. **JavaScript 交互:**
   - 延迟和恢复异步脚本执行 (`DelayAsyncScriptExecution`, `ResumeAsyncScriptExecution`)。
   - 管理待执行的 JavaScript URL 队列 (`pending_javascript_urls_`) 并执行它们 (`ExecuteJavaScriptUrls`, `ProcessJavaScriptUrl`)。
   - 取消待执行的 JavaScript URL (`CancelPendingJavaScriptUrls`)。

4. **DOM 更新和缓存失效:**
   - 管理 `NodeList` 缓存的失效 (`ShouldInvalidateNodeListCaches`, `InvalidateNodeListCaches`)，当文档发生变化时更新缓存。
   - 触发与属性更改相关的 `NodeList` 缓存失效（通过模板函数 `ShouldInvalidateNodeListCachesForAttr`）。

5. **资源管理:**
   - 提供访问文档资源协调器 (`GetResourceCoordinator`)，用于管理文档加载的资源。
   - 管理待预加载的链接头 (`pending_link_header_preloads_`)。

6. **事件处理:**
   - `EnqueueEvent`:  虽然这里没有直接展示，但 `Document` 类继承自 `ContainerNode`，具备事件处理能力。
   - 调度 `selectionchange` 事件 (`ScheduleSelectionchangeEvent`)。

7. **焦点管理:**
   - 判断是否允许设置焦点 (`IsFocusAllowed`)，考虑到沙箱和用户激活状态。
   - 管理焦点元素变化观察者 (`AddFocusedElementChangeObserver`, `RemoveFocusedElementChangeObserver`)。
   - 设置查找功能的当前匹配节点 (`SetFindInPageActiveMatchNode`)。

8. **Prerendering (预渲染) 支持:**
   - 处理文档的激活用于预渲染 (`ActivateForPrerendering`)，执行激活后的步骤。
   - 添加预渲染状态变化的回调 (`AddWillDispatchPrerenderingchangeCallback`) 和激活后的回调 (`AddPostPrerenderingActivationStep`)。

9. **性能优化:**
   - 提供获取与特定任务类型关联的任务运行器 (`GetTaskRunner`)。
   - 延迟加载事件直到布局树更新 (`DelayLoadEventUntilLayoutTreeUpdate`, `UnblockLoadEventAfterLayoutTreeUpdate`)。

10. **功能策略 (Feature Policy):**
    - 提供访问文档的功能策略对象 (`featurePolicy()`)，用于控制浏览器功能的启用和禁用。

11. **Web App Manifest 支持:**
    - 判断文档是否在 Web App 的作用域内 (`IsInWebAppScope()`)。

12. **BeforeUnload 对话框控制:**
    - 设置是否显示 `beforeunload` 对话框 (`SetShowBeforeUnloadDialog`)。

13. **Use Counter (使用计数器) 集成:**
    - 提供多种方法来统计 Web 平台特性的使用情况 (`CountUse`, `CountDeprecation`, `CountProperty`, `CountAnimatedProperty`)。

14. **渲染阻塞资源管理:**
    - 处理渲染阻塞资源的解除阻塞事件 (`RenderBlockingResourceUnblocked`)。

15. **Shadow DOM 支持:**
    - 调度 Shadow Tree 的创建 (`ScheduleShadowTreeCreation`, `UnscheduleShadowTreeCreation`, `ProcessScheduledShadowTreeCreationsNow`)。

16. **Paint Preview (绘画预览) 支持:**
    - 提供作用域来标记文档正在进行绘画预览 (`PaintPreviewScope`)。

17. **其他:**
    - 提供访问 Slot 分配引擎 (`GetSlotAssignmentEngine`)。
    - 判断 Slot 分配是否需要重新计算 (`IsSlotAssignmentDirty`)。
    - 懒加载图片观察者 (`EnsureLazyLoadImageObserver`)。
    - 累加画布数量 (`IncrementNumberOfCanvases`)。
    - 获取 Display Lock 文档状态 (`GetDisplayLockDocumentState`)。
    - 判断是否允许延迟提交合成器 (`DeferredCompositorCommitIsAllowed`)。
    - 支持传统的 DOM 突变事件 (`SupportsLegacyDOMMutations`)，并受到内容安全策略的影响。
    - 入队 Page Reveal 事件 (`EnqueuePageRevealEvent`)。
    - 处理支付链接 (`HandlePaymentLink`，Android 平台相关)。
    - 提供静态方法用于解析 HTML (`parseHTMLInternal`, `parseHTMLUnsafe`, `parseHTML`)，其中 `parseHTML` 方法使用了 Sanitizer API 来保证安全性。
    - 设置是否为 CSP 媒体覆盖 Cookie 的站点 (`SetOverrideSiteForCookiesForCSPMedia`)。
    - 处理未使用的预加载警告 (`OnWarnUnusedPreloads`)。
    - 获取访问链接状态 (`GetVisitedLinkState`) 和缓存的顶级 Frame 站点。
    - 提供 `Trace` 方法用于垃圾回收追踪。
    - `ResetAgent` 方法用于重置关联的 Agent。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **`ExecuteJavaScriptUrls()` 和 `ProcessJavaScriptUrl()`:** 当浏览器遇到 `<script>` 标签或 `javascript:` 类型的 URL 时，会调用这些方法来执行 JavaScript 代码。
        * **假设输入：** 用户点击了一个 `href="javascript:alert('Hello');"` 的链接。
        * **输出：**  `ProcessJavaScriptUrl` 会将这个 URL 加入待执行队列，`ExecuteJavaScriptUrls` 最终会调用 JavaScript 引擎执行 `alert('Hello');`，从而弹出一个警告框。
    * **`ComputedStyleMap()`:** JavaScript 可以通过 `window.getComputedStyle(element)` 获取元素的最终样式。Blink 内部会使用 `ComputedStyleMap` 来缓存这些计算结果，提高性能。
        * **假设输入：** JavaScript 代码调用 `getComputedStyle(document.getElementById('myDiv'))`。
        * **输出：** `ComputedStyleMap` 会返回与 'myDiv' 元素关联的计算样式对象，其中包含了该元素应用的所有 CSS 规则计算后的属性值。

* **HTML:**
    * **`setVlinkColor(const AtomicString& value)`:**  这个方法用于设置文档的访问过链接的颜色。它最终会操作 HTML 文档的 `<body>` 标签的 `vlink` 属性（如果文档是 HTML 并且不是 `<frameset>` 文档）。
        * **假设输入：** 调用 `document.setVlinkColor("red")`。
        * **输出：** 如果文档是 HTML 且有 `<body>` 标签，则 `<body>` 标签会被修改为 `<body vlink="red">`。
    * **`parseHTML()`:** 当 JavaScript 代码使用 `DOMParser().parseFromString()` 解析 HTML 字符串时，Blink 内部会调用 `Document::parseHTML()` 来创建 DOM 树。
        * **假设输入：** JavaScript 代码执行 `new DOMParser().parseFromString('<p>Hello</p>', 'text/html')`。
        * **输出：** `parseHTML` 会创建一个新的 `Document` 对象，其中包含一个 `<p>` 元素，其文本内容为 "Hello"。

* **CSS:**
    * **`PlatformColorsChanged()`:** 当操作系统或浏览器的主题颜色发生变化时，会触发此方法。样式引擎会根据新的颜色信息重新计算样式。这影响了 CSS 颜色关键字（如 `Canvas`, `WindowText` 等）的解析。
        * **假设输入：** 用户将操作系统的主题从亮色模式切换到暗色模式。
        * **输出：** `PlatformColorsChanged` 被调用，样式引擎会更新内部颜色映射，使得使用 CSS 系统颜色关键字的元素能够根据新的主题正确渲染。
    * **`ComputedStyleMap()`:**  CSS 规则最终会影响元素的计算样式。`ComputedStyleMap` 存储了这些计算结果，使得 JavaScript 可以查询到元素的最终渲染样式。
        * **假设输入：** CSS 规则设置了 `#myDiv { color: blue; }`。
        * **输出：** 当 JavaScript 查询 `getComputedStyle(document.getElementById('myDiv')).color` 时，`ComputedStyleMap` 会返回 "rgb(0, 0, 255)" (或相应的颜色值)。

**逻辑推理的假设输入与输出示例：**

* **`ShouldInvalidateNodeListCachesForAttr`:**
    * **假设输入：** `node_lists` 包含需要因 `id` 属性变化而失效的 `NodeList`，`attr_name` 为 "id"。
    * **输出：** 函数返回 `true`，表示当 `id` 属性发生变化时，相关的 `NodeList` 缓存需要被失效。
    * **假设输入：** `node_lists` 不包含任何需要因 `class` 属性变化而失效的 `NodeList`，`attr_name` 为 "class"。
    * **输出：** 函数返回 `false`，表示当 `class` 属性发生变化时，不需要失效任何 `NodeList` 缓存。

**用户或编程常见的使用错误举例说明：**

* **忘记处理异步 JavaScript URL 的执行顺序：**  开发者可能会假设通过 `javascript:` URL 触发的脚本会立即执行，但 Blink 会将其加入队列异步执行。
    * **错误示例：**
    ```html
    <a href="javascript:globalVar = 'test';">设置变量</a>
    <script>
      document.getElementById('myDiv').innerText = globalVar; // 可能会在变量设置之前执行
    </script>
    ```
* **在不应该设置焦点的时候尝试设置焦点：**  例如，在没有用户交互的情况下，尝试在沙箱化的 iframe 中调用 `focus()` 方法可能会被浏览器阻止。
    * **错误示例：**
    ```javascript
    // 在没有用户点击的情况下
    iframeElement.contentDocument.getElementById('someInput').focus(); // 可能不会生效
    ```
* **过度依赖 `NodeList` 缓存而不考虑其失效时机：** 开发者可能会缓存 `document.querySelectorAll()` 返回的 `NodeList`，并期望它始终保持最新。但是，当 DOM 结构发生变化时，这个缓存可能会失效，导致获取到过时的信息。
    * **错误示例：**
    ```javascript
    const nodeList = document.querySelectorAll('.my-class');
    // ... 一些 DOM 操作，可能会添加或删除 .my-class 元素 ...
    console.log(nodeList.length); // 数量可能不准确
    ```

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中加载了一个网页。**  Blink 引擎会创建一个 `Document` 对象来表示这个网页。
2. **网页包含 CSS 样式。**  样式引擎会解析 CSS，并计算元素的样式。当需要获取元素的计算样式时，可能会涉及到 `ComputedStyleMap` 的查找。
3. **网页包含 JavaScript 代码。**
   - 如果 JavaScript 代码通过 `document.body.setAttribute('vlink', '...')` 修改了链接颜色，可能会触发 `setVlinkColor`。
   - 如果 JavaScript 代码执行了 `window.open('javascript:...')` 或点击了 `href="javascript:..."` 的链接，会调用 `ProcessJavaScriptUrl`。
   - 如果 JavaScript 代码调用 `document.querySelectorAll()`，并且之后 DOM 结构发生了变化，可能会触发 `ShouldInvalidateNodeListCaches` 和 `InvalidateNodeListCaches`。
4. **用户与网页进行交互，例如点击链接。** 这可能会导致页面导航，涉及到新的 `Document` 对象的创建和旧 `Document` 对象的销毁。
5. **操作系统或浏览器的主题颜色发生变化。**  这会触发 `PlatformColorsChanged()`。
6. **开发者在 Chrome 的开发者工具中检查 DOM 结构或性能。**  这可能会涉及到对 `Document` 对象属性的检查。

**作为第 11 部分的归纳：**

作为 `blink/renderer/core/dom/document.cc` 的最后一部分，这段代码主要集中在以下功能：

* **收尾和实用工具方法:** 包含了一些文档生命周期末尾的操作，例如 `ResetAgent`。
* **传统 DOM 突变事件的支持:**  检查是否启用并允许传统的 DOM 突变事件。
* **Page Reveal 事件:**  入队 Page Reveal 事件，与页面显示相关。
* **测试辅助方法:**  提供 `GetPendingLinkPreloadForTesting` 等方法用于单元测试。
* **LCP (Largest Contentful Paint) 相关的标志位:**  设置和获取 LCP 元素是否在 HTML 中发现的标志。
* **Shadow DOM 创建的调度:**  管理需要创建 Shadow Tree 的元素队列。
* **支付链接处理 (Android 特定):**  处理页面中的支付链接。
* **`selectionchange` 事件的调度:**  管理 `selectionchange` 事件的触发。
* **静态的 HTML 解析方法:**  提供 `parseHTMLInternal` 及其变体，用于将 HTML 字符串解析为 `Document` 对象。这是创建 `Document` 对象的重要途径。
* **CSP 媒体 Cookie 的站点覆盖:**  允许为 CSP 媒体设置覆盖 Cookie 的站点。
* **未使用的预加载警告处理:**  接收并处理关于未使用预加载资源的警告。
* **访问链接状态管理:**  提供访问 `VisitedLinkState` 对象的方法。
* **缓存的顶级 Frame 站点信息:**  存储和获取用于访问链接判断的缓存顶级 Frame 站点。
* **Supplement 和 TreeScope 的模板实例化。**
* **DEBUG 代码:**  在非 Release 构建中，提供用于跟踪 Live `Document` 实例的工具。

总而言之，这最后一部分涵盖了文档对象的一些高级特性、性能优化、测试支持以及与浏览器其他组件交互的关键部分，并提供了一些调试辅助手段。它完善了 `Document` 类的功能，使其能够在一个复杂的浏览器环境中正常运作。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共11部分，请归纳一下它的功能

"""
ument::setVlinkColor(const AtomicString& value) {
  if (!IsFrameSet())
    SetBodyAttribute(html_names::kVlinkAttr, value);
}

FontFaceSet* Document::fonts() {
  return FontFaceSetDocument::From(*this);
}

template <unsigned type>
bool ShouldInvalidateNodeListCachesForAttr(
    const LiveNodeListRegistry& node_lists,
    const QualifiedName& attr_name) {
  auto invalidation_type = static_cast<NodeListInvalidationType>(type);
  if (node_lists.ContainsInvalidationType(invalidation_type) &&
      LiveNodeListBase::ShouldInvalidateTypeOnAttributeChange(invalidation_type,
                                                              attr_name))
    return true;
  return ShouldInvalidateNodeListCachesForAttr<type + 1>(node_lists, attr_name);
}

template <>
bool ShouldInvalidateNodeListCachesForAttr<kNumNodeListInvalidationTypes>(
    const LiveNodeListRegistry&,
    const QualifiedName&) {
  return false;
}

bool Document::ShouldInvalidateNodeListCaches(
    const QualifiedName* attr_name) const {
  if (attr_name) {
    return node_lists_.NeedsInvalidateOnAttributeChange() &&
           ShouldInvalidateNodeListCachesForAttr<
               kDoNotInvalidateOnAttributeChanges + 1>(node_lists_, *attr_name);
  }

  // If the invalidation is not for an attribute, invalidation is needed if
  // there is any node list present (with any invalidation type).
  return !node_lists_.IsEmpty();
}

void Document::InvalidateNodeListCaches(const QualifiedName* attr_name) {
  for (const LiveNodeListBase* list : lists_invalidated_at_document_)
    list->InvalidateCacheForAttribute(attr_name);
}

void Document::PlatformColorsChanged() {
  if (!IsActive())
    return;

  GetStyleEngine().PlatformColorsChanged();
}

PropertyRegistry& Document::EnsurePropertyRegistry() {
  if (!property_registry_)
    property_registry_ = MakeGarbageCollected<PropertyRegistry>();
  return *property_registry_;
}

DocumentResourceCoordinator* Document::GetResourceCoordinator() {
  // `resource_coordinator_` is cleared in Shutdown() and must not be recreated
  // afterwards, when the Document is no longer active.
  if (!resource_coordinator_ && IsActive()) {
    CHECK(GetFrame(), base::NotFatalUntil::M135);
    if (auto* frame = GetFrame()) {
      resource_coordinator_ = DocumentResourceCoordinator::MaybeCreate(
          frame->GetBrowserInterfaceBroker());
    }
  }
  return resource_coordinator_.get();
}

scoped_refptr<base::SingleThreadTaskRunner> Document::GetTaskRunner(
    TaskType type) {
  DCHECK(IsMainThread());
  if (GetExecutionContext())
    return GetExecutionContext()->GetTaskRunner(type);
  // GetExecutionContext() can be nullptr in unit tests and after Shutdown().
  // Fallback to the Agent's default task runner for this thread if all else
  // fails.
  return To<WindowAgent>(GetAgent())
      .GetAgentGroupScheduler()
      .DefaultTaskRunner();
}

DOMFeaturePolicy* Document::featurePolicy() {
  if (!policy_ && GetExecutionContext())
    policy_ = MakeGarbageCollected<DOMFeaturePolicy>(GetExecutionContext());
  return policy_.Get();
}

StylePropertyMapReadOnly* Document::ComputedStyleMap(Element* element) {
  ElementComputedStyleMap::AddResult add_result =
      element_computed_style_map_.insert(element, nullptr);
  if (add_result.is_new_entry) {
    add_result.stored_value->value =
        MakeGarbageCollected<ComputedStylePropertyMap>(element);
  }
  return add_result.stored_value->value;
}

void Document::AddComputedStyleMapItem(
    Element* element,
    StylePropertyMapReadOnly* computed_style) {
  element_computed_style_map_.insert(element, computed_style);
}

StylePropertyMapReadOnly* Document::RemoveComputedStyleMapItem(
    Element* element) {
  return element_computed_style_map_.Take(element);
}

void Document::DelayAsyncScriptExecution() {
  script_runner_delayer_->Activate();
}

void Document::ResumeAsyncScriptExecution() {
  script_runner_delayer_->Deactivate();
}

void Document::Trace(Visitor* visitor) const {
  visitor->Trace(doc_type_);
  visitor->Trace(implementation_);
  visitor->Trace(autofocus_candidates_);
  visitor->Trace(focused_element_);
  visitor->Trace(sequential_focus_navigation_starting_point_);
  visitor->Trace(hover_element_);
  visitor->Trace(active_element_);
  visitor->Trace(document_element_);
  visitor->Trace(root_scroller_controller_);
  visitor->Trace(title_element_);
  visitor->Trace(ax_object_cache_);
  visitor->Trace(markers_);
  visitor->Trace(css_target_);
  visitor->Trace(current_script_stack_);
  visitor->Trace(script_runner_);
  visitor->Trace(script_runner_delayer_);
  visitor->Trace(lists_invalidated_at_document_);
  visitor->Trace(node_lists_);
  visitor->Trace(top_layer_elements_);
  visitor->Trace(top_layer_elements_pending_removal_);
  visitor->Trace(popover_auto_stack_);
  visitor->Trace(popover_hint_stack_);
  visitor->Trace(popover_pointerdown_target_);
  visitor->Trace(dialog_pointerdown_target_);
  visitor->Trace(popovers_waiting_to_hide_);
  visitor->Trace(all_open_popovers_);
  visitor->Trace(all_open_dialogs_);
  visitor->Trace(document_part_root_);
  visitor->Trace(load_event_delay_timer_);
  visitor->Trace(plugin_loading_timer_);
  visitor->Trace(elem_sheet_);
  visitor->Trace(pending_javascript_urls_);
  visitor->Trace(clear_focused_element_timer_);
  visitor->Trace(node_iterators_);
  visitor->Trace(ranges_);
  visitor->Trace(document_explicit_root_intersection_observer_data_);
  visitor->Trace(style_engine_);
  visitor->Trace(form_controller_);
  visitor->Trace(visited_link_state_);
  visitor->Trace(element_computed_style_map_);
  visitor->Trace(dom_window_);
  visitor->Trace(fetcher_);
  visitor->Trace(parser_);
  visitor->Trace(http_refresh_scheduler_);
  visitor->Trace(document_timing_);
  visitor->Trace(media_query_matcher_);
  visitor->Trace(scripted_animation_controller_);
  visitor->Trace(text_autosizer_);
  visitor->Trace(element_data_cache_clear_timer_);
  visitor->Trace(element_data_cache_);
  visitor->Trace(use_elements_needing_update_);
  visitor->Trace(svg_resources_needing_invalidation_);
  visitor->Trace(template_document_);
  visitor->Trace(template_document_host_);
  visitor->Trace(user_action_elements_);
  visitor->Trace(svg_extensions_);
  visitor->Trace(layout_view_);
  visitor->Trace(document_animations_);
  visitor->Trace(timeline_);
  visitor->Trace(pending_animations_);
  visitor->Trace(worklet_animation_controller_);
  visitor->Trace(execution_context_);
  visitor->Trace(agent_);
  visitor->Trace(canvas_font_cache_);
  visitor->Trace(intersection_observer_controller_);
  visitor->Trace(property_registry_);
  visitor->Trace(policy_);
  visitor->Trace(slot_assignment_engine_);
  visitor->Trace(viewport_data_);
  visitor->Trace(lazy_load_image_observer_);
  visitor->Trace(mime_handler_view_before_unload_event_listener_);
  visitor->Trace(cookie_jar_);
  visitor->Trace(synchronous_mutation_observer_set_);
  visitor->Trace(fragment_directive_);
  visitor->Trace(element_explicitly_set_attr_elements_map_);
  visitor->Trace(element_cached_attr_associated_elements_map_);
  visitor->Trace(display_lock_document_state_);
  visitor->Trace(render_blocking_resource_manager_);
  visitor->Trace(find_in_page_active_match_node_);
  visitor->Trace(data_);
  visitor->Trace(meta_theme_color_elements_);
  visitor->Trace(unassociated_listed_elements_);
  visitor->Trace(top_level_forms_);
  visitor->Trace(intrinsic_size_observer_);
  visitor->Trace(lazy_loaded_auto_sized_img_observer_);
  visitor->Trace(anchor_element_interaction_tracker_);
  visitor->Trace(focused_element_change_observers_);
  visitor->Trace(pending_link_header_preloads_);
  visitor->Trace(elements_needing_shadow_tree_);
#if BUILDFLAG(IS_ANDROID)
  visitor->Trace(payment_link_handler_);
#endif  // BUILDFLAG(IS_ANDROID)
  Supplementable<Document>::Trace(visitor);
  TreeScope::Trace(visitor);
  ContainerNode::Trace(visitor);
}

SlotAssignmentEngine& Document::GetSlotAssignmentEngine() {
  if (!slot_assignment_engine_)
    slot_assignment_engine_ = MakeGarbageCollected<SlotAssignmentEngine>();
  return *slot_assignment_engine_;
}

bool Document::IsSlotAssignmentDirty() const {
  return slot_assignment_engine_ &&
         slot_assignment_engine_->HasPendingSlotAssignmentRecalc();
}

bool Document::IsFocusAllowed() const {
  LocalFrame* frame = GetFrame();
  if (!frame || frame->IsMainFrame() ||
      LocalFrame::HasTransientUserActivation(frame)) {
    // 'autofocus' runs Element::focus asynchronously at which point the
    // document might not have a frame (see https://crbug.com/960224).
    return true;
  }

  WebFeature uma_type;
  bool sandboxed = dom_window_->IsSandboxed(
      network::mojom::blink::WebSandboxFlags::kNavigation);
  bool ad = frame->IsAdFrame();
  if (sandboxed) {
    uma_type = ad ? WebFeature::kFocusWithoutUserActivationSandboxedAdFrame
                  : WebFeature::kFocusWithoutUserActivationSandboxedNotAdFrame;
  } else {
    uma_type =
        ad ? WebFeature::kFocusWithoutUserActivationNotSandboxedAdFrame
           : WebFeature::kFocusWithoutUserActivationNotSandboxedNotAdFrame;
  }
  CountUse(uma_type);
  if (!RuntimeEnabledFeatures::BlockingFocusWithoutUserActivationEnabled())
    return true;
  return GetExecutionContext()->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kFocusWithoutUserActivation);
}

LazyLoadImageObserver& Document::EnsureLazyLoadImageObserver() {
  if (!lazy_load_image_observer_) {
    lazy_load_image_observer_ = MakeGarbageCollected<LazyLoadImageObserver>();
  }
  return *lazy_load_image_observer_;
}

void Document::IncrementNumberOfCanvases() {
  num_canvases_++;
}

void Document::ExecuteJavaScriptUrls() {
  DCHECK(dom_window_);
  HeapVector<Member<PendingJavascriptUrl>> urls_to_execute;
  urls_to_execute.swap(pending_javascript_urls_);

  for (auto& url_to_execute : urls_to_execute) {
    dom_window_->GetScriptController().ExecuteJavaScriptURL(
        url_to_execute->url, network::mojom::CSPDisposition::CHECK,
        url_to_execute->world.Get());
    if (!GetFrame())
      break;
  }
  CheckCompleted();
}

void Document::ProcessJavaScriptUrl(const KURL& url,
                                    const DOMWrapperWorld* world) {
  DCHECK(url.ProtocolIsJavaScript());
  if (is_initial_empty_document_)
    load_event_progress_ = kLoadEventNotRun;
  GetFrame()->Loader().Progress().ProgressStarted();
  pending_javascript_urls_.push_back(
      MakeGarbageCollected<PendingJavascriptUrl>(url, world));
  if (!javascript_url_task_handle_.IsActive()) {
    javascript_url_task_handle_ =
        PostCancellableTask(*GetTaskRunner(TaskType::kNetworking), FROM_HERE,
                            WTF::BindOnce(&Document::ExecuteJavaScriptUrls,
                                          WrapWeakPersistent(this)));
  }
}

DisplayLockDocumentState& Document::GetDisplayLockDocumentState() const {
  return *display_lock_document_state_;
}

void Document::CancelPendingJavaScriptUrls() {
  if (javascript_url_task_handle_.IsActive())
    javascript_url_task_handle_.Cancel();
  pending_javascript_urls_.clear();
}

bool Document::IsInWebAppScope() const {
  if (!GetSettings())
    return false;

  const String& web_app_scope = GetSettings()->GetWebAppScope();
  if (web_app_scope.IsNull() || web_app_scope.empty())
    return false;

  DCHECK_EQ(KURL(web_app_scope).GetString(), web_app_scope);
  return Url().GetString().StartsWith(web_app_scope);
}

bool Document::ChildrenCanHaveStyle() const {
  if (LayoutObject* view = GetLayoutView())
    return view->CanHaveChildren();
  return false;
}

void Document::SetShowBeforeUnloadDialog(bool show_dialog) {
  if (!mime_handler_view_before_unload_event_listener_) {
    if (!show_dialog)
      return;

    mime_handler_view_before_unload_event_listener_ =
        MakeGarbageCollected<BeforeUnloadEventListener>(this);
    domWindow()->addEventListener(
        event_type_names::kBeforeunload,
        mime_handler_view_before_unload_event_listener_, false);
  }
  mime_handler_view_before_unload_event_listener_->SetShowBeforeUnloadDialog(
      show_dialog);
}

mojom::blink::PreferredColorScheme Document::GetPreferredColorScheme() const {
  return style_engine_->GetPreferredColorScheme();
}

void Document::ColorSchemeChanged() {
  UpdateForcedColors();
  GetStyleEngine().ColorSchemeChanged();
  MediaQueryAffectingValueChanged(MediaValueChange::kOther);
}

void Document::VisionDeficiencyChanged() {
  GetStyleEngine().VisionDeficiencyChanged();
}

void Document::UpdateForcedColors() {
  Settings* settings = GetSettings();
  if (RuntimeEnabledFeatures::ForcedColorsEnabled() && settings) {
    in_forced_colors_mode_ = settings->GetInForcedColors();
  }
  if (in_forced_colors_mode_)
    GetStyleEngine().EnsureUAStyleForForcedColors();
}

bool Document::InForcedColorsMode() const {
  return in_forced_colors_mode_ && !Printing();
}

bool Document::InDarkMode() {
  return !InForcedColorsMode() && !Printing() &&
         GetStyleEngine().GetPreferredColorScheme() ==
             mojom::blink::PreferredColorScheme::kDark;
}

const ui::ColorProvider* Document::GetColorProviderForPainting(
    mojom::blink::ColorScheme color_scheme) const {
  if (!GetPage()) {
    return nullptr;
  }

  return GetPage()->GetColorProviderForPainting(color_scheme,
                                                in_forced_colors_mode_);
}

void Document::CountUse(mojom::WebFeature feature) const {
  if (execution_context_) {
    execution_context_->CountUse(feature);
  }
}

void Document::CountUse(mojom::WebFeature feature) {
  if (execution_context_)
    execution_context_->CountUse(feature);
}

void Document::CountDeprecation(mojom::WebFeature feature) {
  if (execution_context_)
    execution_context_->CountDeprecation(feature);
}

void Document::CountWebDXFeature(mojom::blink::WebDXFeature feature) const {
  if (execution_context_) {
    execution_context_->CountWebDXFeature(feature);
  }
}

void Document::CountWebDXFeature(mojom::blink::WebDXFeature feature) {
  if (execution_context_) {
    execution_context_->CountWebDXFeature(feature);
  }
}

void Document::CountProperty(CSSPropertyID property) const {
  if (DocumentLoader* loader = Loader()) {
    loader->GetUseCounter().Count(
        property, UseCounterImpl::CSSPropertyType::kDefault, GetFrame());
  }
}

void Document::CountAnimatedProperty(CSSPropertyID property) const {
  if (DocumentLoader* loader = Loader()) {
    loader->GetUseCounter().Count(
        property, UseCounterImpl::CSSPropertyType::kAnimation, GetFrame());
  }
}

bool Document::IsUseCounted(mojom::WebFeature feature) const {
  if (DocumentLoader* loader = Loader()) {
    return loader->GetUseCounter().IsCounted(feature);
  }
  return false;
}

bool Document::IsWebDXFeatureCounted(mojom::blink::WebDXFeature feature) const {
  if (DocumentLoader* loader = Loader()) {
    return loader->GetUseCounter().IsWebDXFeatureCounted(feature);
  }
  return false;
}

bool Document::IsPropertyCounted(CSSPropertyID property) const {
  if (DocumentLoader* loader = Loader()) {
    return loader->GetUseCounter().IsCounted(
        property, UseCounterImpl::CSSPropertyType::kDefault);
  }
  return false;
}

bool Document::IsAnimatedPropertyCounted(CSSPropertyID property) const {
  if (DocumentLoader* loader = Loader()) {
    return loader->GetUseCounter().IsCounted(
        property, UseCounterImpl::CSSPropertyType::kAnimation);
  }
  return false;
}

void Document::ClearUseCounterForTesting(mojom::WebFeature feature) {
  if (DocumentLoader* loader = Loader())
    loader->GetUseCounter().ClearMeasurementForTesting(feature);
}

void Document::RenderBlockingResourceUnblocked() {
  // Only HTML documents can ever be render-blocked by external resources.
  // https://html.spec.whatwg.org/#allows-adding-render-blocking-elements
  DCHECK(IsA<HTMLDocument>(this));
  if (body())
    BeginLifecycleUpdatesIfRenderingReady();
}

void Document::SetFindInPageActiveMatchNode(Node* node) {
  blink::NotifyPriorityScrollAnchorStatusChanged(
      find_in_page_active_match_node_, node);
  find_in_page_active_match_node_ = node;
}

const Node* Document::GetFindInPageActiveMatchNode() const {
  return find_in_page_active_match_node_;
}

void Document::ActivateForPrerendering(
    const mojom::blink::PrerenderPageActivationParams& params) {
  TRACE_EVENT_WITH_FLOW0("navigation", "Document::ActivateForPrerendering",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  DCHECK(is_prerendering_);
  is_prerendering_ = false;

  if (DocumentLoader* loader = Loader()) {
    loader->NotifyPrerenderingDocumentActivated(params);
  }

  Vector<base::OnceClosure> callbacks;
  callbacks.swap(will_dispatch_prerenderingchange_callbacks_);
  for (auto& callback : callbacks) {
    std::move(callback).Run();
  }

  // https://wicg.github.io/nav-speculation/prerendering.html#prerendering-browsing-context-activate
  // Step 8.3.4 "Fire an event named prerenderingchange at doc."
  DispatchEvent(*Event::Create(event_type_names::kPrerenderingchange));

  // Step 8.3.5 "For each steps in doc’s post-prerendering activation steps
  // list:"
  RunPostPrerenderingActivationSteps();
}

void Document::AddWillDispatchPrerenderingchangeCallback(
    base::OnceClosure closure) {
  DCHECK(is_prerendering_);
  will_dispatch_prerenderingchange_callbacks_.push_back(std::move(closure));
}

void Document::AddPostPrerenderingActivationStep(base::OnceClosure callback) {
  DCHECK(is_prerendering_);
  post_prerendering_activation_callbacks_.push_back(std::move(callback));
}

void Document::RunPostPrerenderingActivationSteps() {
  TRACE_EVENT_WITH_FLOW1(
      "blink", "Document::RunPostPrerenderingActivationSteps",
      TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "deferred_callback",
      post_prerendering_activation_callbacks_.size());

  DCHECK(!is_prerendering_);
  for (auto& callback : post_prerendering_activation_callbacks_)
    std::move(callback).Run();
  post_prerendering_activation_callbacks_.clear();
}

bool Document::InStyleRecalc() const {
  return lifecycle_.GetState() == DocumentLifecycle::kInStyleRecalc ||
         style_engine_->InContainerQueryStyleRecalc() ||
         style_engine_->InPositionTryStyleRecalc() ||
         style_engine_->InEnsureComputedStyle();
}

void Document::DelayLoadEventUntilLayoutTreeUpdate() {
  if (delay_load_event_until_layout_tree_update_)
    return;
  delay_load_event_until_layout_tree_update_ = true;
  IncrementLoadEventDelayCount();
}

void Document::UnblockLoadEventAfterLayoutTreeUpdate() {
  if (delay_load_event_until_layout_tree_update_) {
    delay_load_event_until_layout_tree_update_ = false;
    DecrementLoadEventDelayCount();
  }
}

void Document::AddPendingLinkHeaderPreload(const PendingLinkPreload& preload) {
  pending_link_header_preloads_.insert(&preload);
}

void Document::RemovePendingLinkHeaderPreloadIfNeeded(
    const PendingLinkPreload& preload) {
  pending_link_header_preloads_.erase(&preload);
}

void Document::AddFocusedElementChangeObserver(
    FocusedElementChangeObserver* observer) {
  DCHECK(observer);
  focused_element_change_observers_.insert(observer);
}

void Document::RemoveFocusedElementChangeObserver(
    FocusedElementChangeObserver* observer) {
  DCHECK(focused_element_change_observers_.Contains(observer));
  focused_element_change_observers_.erase(observer);
}

void Document::WriteIntoTrace(perfetto::TracedValue ctx) const {
  perfetto::TracedDictionary dict = std::move(ctx).WriteDictionary();
  dict.Add("url", Url());
}

bool Document::DeferredCompositorCommitIsAllowed() const {
  // Don't defer commits if a transition is in progress. It requires commits to
  // send directives to the compositor and uses a separate mechanism to pause
  // all rendering when needed.
  if (ViewTransitionUtils::GetTransition(*this)) {
    return false;
  }
  return deferred_compositor_commit_is_allowed_;
}

Document::PaintPreviewScope::PaintPreviewScope(Document& document,
                                               PaintPreviewState state)
    : document_(document) {
  document_.paint_preview_ = state;
  document_.GetDisplayLockDocumentState().NotifyPrintingOrPreviewChanged();
}

Document::PaintPreviewScope::~PaintPreviewScope() {
  document_.paint_preview_ = kNotPaintingPreview;
  document_.GetDisplayLockDocumentState().NotifyPrintingOrPreviewChanged();
}

Document::PendingJavascriptUrl::PendingJavascriptUrl(
    const KURL& input_url,
    const DOMWrapperWorld* world)
    : url(input_url), world(world) {}

Document::PendingJavascriptUrl::~PendingJavascriptUrl() = default;

void Document::PendingJavascriptUrl::Trace(Visitor* visitor) const {
  visitor->Trace(world);
}

void Document::ResetAgent(Agent& agent) {
  agent_ = agent;
}

bool Document::SupportsLegacyDOMMutations() {
  if (!RuntimeEnabledFeatures::MutationEventsEnabled(GetExecutionContext())) {
    return false;
  }
  if (!legacy_dom_mutations_supported_.has_value()) {
    // We load the `LocalFrame` from the `ExecutionContext`'s so that documents
    // that do not have a frame are given the same setting consistently across
    // the `ExecutionContext`.
    auto* execution_dom_window =
        DynamicTo<LocalDOMWindow>(GetExecutionContext());
    LocalFrame* frame =
        execution_dom_window ? execution_dom_window->GetFrame() : nullptr;
    if (frame && frame->GetContentSettingsClient()) {
      legacy_dom_mutations_supported_ =
          frame->GetContentSettingsClient()->AllowMutationEvents(
              /*default_value=*/true);
    } else {
      legacy_dom_mutations_supported_ = true;
    }
  }
  return legacy_dom_mutations_supported_.value();
}

void Document::EnqueuePageRevealEvent() {
  CHECK(RuntimeEnabledFeatures::PageRevealEventEnabled());
  CHECK(dom_window_);

  dom_window_->SetHasBeenRevealed(false);
  auto* page_reveal_event = MakeGarbageCollected<PageRevealEvent>();
  page_reveal_event->SetTarget(dom_window_);
  page_reveal_event->SetCurrentTarget(dom_window_);
  EnqueueAnimationFrameEvent(page_reveal_event);
}

Resource* Document::GetPendingLinkPreloadForTesting(const KURL& url) {
  for (auto pending_preload : pending_link_header_preloads_) {
    Resource* resource = pending_preload->GetResourceForTesting();
    if (resource && resource->Url() == url) {
      return resource;
    }
  }
  return nullptr;
}

void Document::SetLcpElementFoundInHtml(bool found) {
  data_->lcpp_encountered_lcp_in_html = found;
}

bool Document::IsLcpElementFoundInHtml() {
  return data_->lcpp_encountered_lcp_in_html;
}

void Document::ScheduleShadowTreeCreation(HTMLInputElement& element) {
  elements_needing_shadow_tree_.insert(&element);
}

void Document::UnscheduleShadowTreeCreation(HTMLInputElement& element) {
  elements_needing_shadow_tree_.erase(&element);
}

#if BUILDFLAG(IS_ANDROID)
void Document::HandlePaymentLink(const KURL& href) {
  // Only the first payment link is expected to be handled in a page.
  if (payment_link_handled_) {
    return;
  }
  // TODO(crbug.com/344997566): Validate the href before triggering the IPC
  // call.
  if (!payment_link_handler_.is_bound()) {
    GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        payment_link_handler_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kDOMManipulation)));
  }
  payment_link_handled_ = true;
  payment_link_handler_->HandlePaymentLink(href);
}
#endif  // BUILDFLAG(IS_ANDROID)

void Document::ProcessScheduledShadowTreeCreationsNow() {
  if (elements_needing_shadow_tree_.empty()) {
    return;
  }
  HeapHashSet<Member<HTMLInputElement>> elements_needing_shadow_tree;
  std::swap(elements_needing_shadow_tree, elements_needing_shadow_tree_);
  for (auto& element : elements_needing_shadow_tree) {
    element->EnsureShadowSubtree();
  }
}

void Document::ScheduleSelectionchangeEvent() {
  if (RuntimeEnabledFeatures::CoalesceSelectionchangeEventEnabled()) {
    if (has_scheduled_selectionchange_event_on_document_)
      return;
    has_scheduled_selectionchange_event_on_document_ = true;
    EnqueueEvent(*Event::Create(event_type_names::kSelectionchange),
                 TaskType::kMiscPlatformAPI);
  } else {
    EnqueueEvent(*Event::Create(event_type_names::kSelectionchange),
                 TaskType::kMiscPlatformAPI);
  }
}

// static
Document* Document::parseHTMLInternal(ExecutionContext* context,
                                      const String& html,
                                      SetHTMLOptions* options,
                                      bool safe,
                                      ExceptionState& exception_state) {
  Document* doc = DocumentInit::Create()
                      .WithTypeFrom(keywords::kTextHtml)
                      .WithExecutionContext(context)
                      .WithAgent(*context->GetAgent())
                      .CreateDocument();
  doc->setAllowDeclarativeShadowRoots(true);
  doc->SetContent(html);
  doc->SetMimeType(keywords::kTextHtml);
  if (RuntimeEnabledFeatures::SanitizerAPIEnabled()) {
    if (safe) {
      SanitizerAPI::SanitizeSafeInternal(doc->body(), options, exception_state);
    } else {
      SanitizerAPI::SanitizeUnsafeInternal(doc->body(), options,
                                           exception_state);
    }
  }

  return doc;
}

// static
Document* Document::parseHTMLUnsafe(ExecutionContext* context,
                                    const String& html,
                                    ExceptionState& exception_state) {
  UseCounter::Count(context, WebFeature::kHTMLUnsafeMethods);
  return parseHTMLInternal(context, html, /*options=*/nullptr, /*safe=*/false,
                           exception_state);
}

// static
Document* Document::parseHTMLUnsafe(ExecutionContext* context,
                                    const String& html,
                                    SetHTMLOptions* options,
                                    ExceptionState& exception_state) {
  UseCounter::Count(context, WebFeature::kHTMLUnsafeMethods);
  CHECK(RuntimeEnabledFeatures::SanitizerAPIEnabled());
  return parseHTMLInternal(context, html, options, /*safe=*/false,
                           exception_state);
}

// static
Document* Document::parseHTML(ExecutionContext* context,
                              const String& html,
                              SetHTMLOptions* options,
                              ExceptionState& exception_state) {
  CHECK(RuntimeEnabledFeatures::SanitizerAPIEnabled());
  return parseHTMLInternal(context, html, options, /*safe=*/true,
                           exception_state);
}

void Document::SetOverrideSiteForCookiesForCSPMedia(bool value) {
  CHECK(IsMediaDocument());
  // Only top-level documents can use this method.
  if (!GetFrame() || !GetFrame()->IsMainFrame()) {
    return;
  }
  override_site_for_cookies_for_csp_media_ = value;
}

void Document::OnWarnUnusedPreloads(Vector<KURL> unused_preloads) {
  if (!GetFrame() || !GetFrame()->GetLCPP()) {
    return;
  }

  if (LCPCriticalPathPredictor* lcpp = GetFrame()->GetLCPP()) {
    lcpp->OnWarnedUnusedPreloads(unused_preloads);
  }
}

VisitedLinkState& Document::GetVisitedLinkState() {
  if (!visited_link_state_) [[unlikely]] {
    visited_link_state_ = MakeGarbageCollected<VisitedLinkState>(*this);
  }
  return *visited_link_state_;
}

net::SchemefulSite Document::GetCachedTopFrameSite(VisitedLinkPassKey) {
  // NOTE: frame-less Documents will have a value of std::nullopt, HOWEVER,
  // since this function can only be called from a Document associated with a
  // valid VisitedLinkState or HTMLAnchorElement, we are guaranteed to have a
  // top frame and thus a value for top frame site.
  DCHECK(cached_top_frame_site_for_visited_links_.has_value());
  return cached_top_frame_site_for_visited_links_.value();
}

template class CORE_TEMPLATE_EXPORT Supplement<Document>;

}  // namespace blink
#ifndef NDEBUG
static WeakDocumentSet& LiveDocumentSet() {
  DEFINE_STATIC_LOCAL(blink::Persistent<WeakDocumentSet>, set,
                      (blink::MakeGarbageCollected<WeakDocumentSet>()));
  return *set;
}

void ShowLiveDocumentInstances() {
  WeakDocumentSet& set = LiveDocumentSet();
  fprintf(stderr, "There are %u documents currently alive:\n", set.size());
  for (blink::Document* document : set) {
    fprintf(stderr, "- Document %p URL: %s\n", document,
            document->Url().GetString().Utf8().c_str());
  }
}
#endif

"""


```