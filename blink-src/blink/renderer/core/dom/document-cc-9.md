Response:
My thought process to answer the request about `blink/renderer/core/dom/document.cc` went something like this:

1. **Understand the Core Request:** The request asks for the *functionality* of this specific Chromium/Blink source code file. It also asks for connections to web technologies (JavaScript, HTML, CSS), examples, logical reasoning, common errors, debugging hints, and a summary of the provided code snippet.

2. **Identify the File's Role:** The file is `document.cc` within the `blink/renderer/core/dom` directory. This immediately tells me it's a core part of the Document Object Model (DOM) implementation in Blink. The `Document` class is fundamental to representing a web page in the browser.

3. **General Functionality of `Document.cc`:** I know the `Document` object is the root of the DOM tree. Therefore, this file likely contains code that manages the overall lifecycle, state, and behavior of a web page. This includes:
    * Parsing HTML and building the DOM tree.
    * Managing stylesheets and applying CSS rules.
    * Executing JavaScript.
    * Handling events.
    * Managing resources and network requests.
    * Interactions with the browser's rendering engine.
    * Providing APIs for JavaScript to interact with the page.

4. **Analyze the Provided Code Snippet:** I went through the provided code chunk by chunk, looking for key functionalities. I focused on the names of the methods and the types they interact with. My observations included:

    * **`supportsReducedMotion()` and `ShouldForceReduceMotion()`:**  This clearly relates to the `prefers-reduced-motion` CSS media feature, indicating accessibility support.
    * **`GetLinkElement()` and its usage (`LinkManifest()`, `LinkCanonical()`):**  These functions deal with `<link>` tags, specifically for manifest files (PWA) and canonical URLs (SEO).
    * **`UkmRecorder()` and `UkmSourceID()`:**  The `ukm` namespace suggests User Keyed Metrics, meaning this code is involved in collecting performance and usage data.
    * **`GetFontMatchingMetrics()`:**  This is about font selection and rendering.
    * **`MaybeRecordShapeTextElapsedTime()` and `MaybeRecordSvgImageProcessingTime()`:** Performance measurements related to text shaping and SVG rendering.
    * **`AllowInlineEventHandler()`:** This function deals with security policy (CSP) and whether inline JavaScript event handlers are allowed.
    * **`UpdateSelectionAfterLayout()`:**  Managing text selection after the layout process.
    * **`AttachRange()` and `DetachRange()`:**  Handling `Range` objects, used for selecting parts of the DOM.
    * **`InitDNSPrefetch()` and `ParseDNSPrefetchControlHeader()`:**  Optimizing page load by pre-resolving DNS for links.
    * **`GetIntersectionObserverController()` and related functions:** Implementing the Intersection Observer API, used for tracking element visibility.
    * **`EnsureEmailRegexp()`:**  Input validation for email fields.
    * **`SetMediaFeatureEvaluated()` and `WasMediaFeatureEvaluated()`:**  Tracking which CSS media features have been evaluated.
    * **`AddConsoleMessage()`:**  Logging messages to the browser's developer console.
    * **Top Layer Management (`AddToTopLayer()`, `ScheduleForTopLayerRemoval()`, etc.):**  Managing elements in the top layer, like `<dialog>` and popovers.
    * **Pointer Lock (`exitPointerLock()`, `PointerLockElement()`):** Implementing the Pointer Lock API for immersive experiences.
    * **Load Event Handling (`DecrementLoadEventDelayCount()`, `CheckLoadEventSoon()`, etc.):**  Managing the `load` event lifecycle.
    * **Animation Frame (`RequestAnimationFrame()`, `CancelAnimationFrame()`):**  Implementing the requestAnimationFrame API for smooth animations.
    * **`Loader()`:**  Accessing the document's loader, which handles fetching resources.
    * **Coordinate Adjustments (`AdjustQuadsForScrollAndAbsoluteZoom()`, `AdjustRectForScrollAndAbsoluteZoom()`):**  Handling scrolling and zooming.
    * **Hover and Active States (`UpdateHoverActiveState()`, `UpdateActiveState()`, `UpdateHoverState()`):** Managing the `:hover` and `:active` CSS pseudo-classes.
    * **Stylesheet Loading Checks (`HaveScriptBlockingStylesheetsLoaded()`, `HaveRenderBlockingStylesheetsLoaded()`, `HaveRenderBlockingResourcesLoaded()`):** Checking the loading status of stylesheets and other resources that can block rendering or script execution.
    * **Locale Handling (`GetCachedLocale()`):**  Internationalization support.
    * **Template Documents (`EnsureTemplateDocument()`):**  Handling `<template>` elements.
    * **Form Element Change Notification (`DidChangeFormRelatedElementDynamically()`):**  Notifying the browser about changes to form elements.
    * **Device Pixel Ratio (`DevicePixelRatio()`):**  Getting the screen's pixel density.
    * **Text Autosizing (`GetTextAutosizer()`):**  Potentially related to responsive font sizes.
    * **Testing Hooks (`SetPseudoStateForTesting()`):**  Functions specifically for testing purposes.
    * **Autofocus Handling (`EnqueueAutofocusCandidate()`, `FlushAutofocusCandidates()`, etc.):**  Implementing the `autofocus` attribute.
    * **Active Element (`ActiveElement()`):**  Getting the currently focused element.
    * **Focus State (`hasFocus()`):** Checking if the document has focus.
    * **Body Element Attribute Accessors (`bgColor()`, `fgColor()`, etc.):**  Providing convenient access to attributes of the `<body>` element.

5. **Categorize and Structure the Functionality:**  I grouped the identified functionalities into broader categories like:

    * **Core DOM Management:** Lifecycle, tree structure, etc.
    * **CSS and Styling:** Handling stylesheets, media features, pseudo-classes.
    * **JavaScript Interaction:** Event handling, APIs like `requestAnimationFrame`.
    * **Browser Features:**  Navigation, history, security, performance.
    * **Accessibility:** `prefers-reduced-motion`.
    * **Performance and Optimization:** DNS prefetching, resource loading checks, metrics collection.
    * **Testing:**  Testing-specific hooks.

6. **Connect to Web Technologies:** For each category, I explicitly linked the functionality to HTML, CSS, and JavaScript concepts. For example, the top layer management directly relates to the HTML `<dialog>` element and CSS styling of overlays.

7. **Provide Examples and Scenarios:**  I tried to come up with concrete examples of how these features are used in web development. For instance, the `prefers-reduced-motion` example shows how a website might adapt animations based on user preferences.

8. **Infer Logical Reasoning (Input/Output):**  For some functions, it was possible to infer the input and output. For example, `ShouldForceReduceMotion()` takes into account user preferences and the website's declared support for reduced motion to determine if animations should be suppressed.

9. **Identify Common Errors:** I considered common mistakes developers might make related to the functionalities described. For example, incorrect CSP configuration leading to blocked inline scripts.

10. **Suggest Debugging Clues:**  Based on the functionality, I thought about how a developer might end up in this code during debugging. For example, investigating why an animation isn't playing as expected might lead to examining the reduced motion logic.

11. **Summarize the Snippet:** Finally, I revisited the specific code snippet provided and summarized its main purpose, focusing on the reduced motion support, link element retrieval, and metrics collection.

12. **Iterate and Refine:** Throughout this process, I reviewed and refined my understanding and explanations to be as clear and accurate as possible. I also double-checked that I addressed all parts of the original request.
这是对 `blink/renderer/core/dom/document.cc` 文件功能的总结，基于提供的代码片段进行分析。

**归纳：`blink/renderer/core/dom/document.cc` 的功能 (基于代码片段)**

这段代码主要关注 `Document` 对象的一些特定功能，特别是以下几点：

1. **用户偏好和辅助功能支持:**
   - **`supportsReducedMotion()` 和 `ShouldForceReduceMotion()`:**  用于检测和应用用户偏好的“减少动画”设置。这与 CSS 的 `prefers-reduced-motion` 媒体查询相关。

2. **获取特定类型的 `<link>` 元素:**
   - **`GetLinkElement()`:**  一个通用的帮助函数，用于查找符合特定条件的 `<link>` 元素。
   - **`LinkManifest()`:** 获取 `rel="manifest"` 的 `<link>` 元素，通常用于 Progressive Web Apps (PWAs)。
   - **`LinkCanonical()`:** 获取 `rel="canonical"` 的 `<link>` 元素，用于 SEO 优化，指示页面的首选 URL。

3. **用户关键指标 (UKM) 记录:**
   - **`UkmRecorder()`:** 获取用于记录用户关键指标的记录器。
   - **`UkmSourceID()`:** 获取当前文档的 UKM 源 ID。这与性能分析和用户行为跟踪有关。

4. **字体匹配指标:**
   - **`GetFontMatchingMetrics()`:** 获取用于跟踪字体匹配过程的指标对象。这对于性能分析和理解字体选择的开销很有用。

5. **性能指标记录:**
   - **`MaybeRecordShapeTextElapsedTime()`:** 记录文本 shaping 过程所花费的时间。
   - **`MaybeRecordSvgImageProcessingTime()`:** 记录 SVG 图像处理所花费的时间和次数。

6. **内联事件处理器的安全策略 (CSP) 检查:**
   - **`AllowInlineEventHandler()`:** 检查是否允许在 HTML 标签中使用内联事件处理器（如 `onclick`）。这与 Content Security Policy (CSP) 相关。

7. **布局后的选择更新:**
   - **`UpdateSelectionAfterLayout()`:** 在布局完成后更新文档的选择状态。

8. **Range 对象的管理:**
   - **`AttachRange()` 和 `DetachRange()`:** 用于管理文档中存在的 `Range` 对象（用于选择文档的一部分）。

9. **DNS 预取控制:**
   - **`InitDNSPrefetch()`:** 初始化 DNS 预取功能。
   - **`ParseDNSPrefetchControlHeader()`:** 解析 HTTP 头部中的 DNS 预取控制指令。

10. **Intersection Observer API:**
    - **`GetIntersectionObserverController()` 和 `EnsureIntersectionObserverController()`:** 用于获取和创建 Intersection Observer 控制器，该 API 用于观察元素何时进入或离开视口。
    - **`DocumentExplicitRootIntersectionObserverData()` 和 `EnsureDocumentExplicitRootIntersectionObserverData()`:** 管理文档级别的 Intersection Observer 数据。

11. **邮件地址正则表达式:**
    - **`EnsureEmailRegexp()`:**  确保存在用于验证邮件地址的正则表达式。

12. **媒体特性评估跟踪:**
    - **`SetMediaFeatureEvaluated()` 和 `WasMediaFeatureEvaluated()`:** 跟踪哪些 CSS 媒体特性已经被评估过。

13. **控制台消息添加:**
    - **`AddConsoleMessage()`:** 向浏览器的开发者控制台添加消息。

14. **Top Layer 管理 (例如 `<dialog>` 元素):**
    -  一系列函数 (`AddToTopLayer`, `ScheduleForTopLayerRemoval`, `RemoveFinishedTopLayerElements`, `RemoveFromTopLayerImmediately`, `IsScheduledForTopLayerRemoval`, `ActiveModalDialog`) 用于管理元素在“顶层”（top layer）的显示，例如模态对话框。

15. **Pointer Lock API:**
    - **`exitPointerLock()` 和 `PointerLockElement()`:**  用于处理 Pointer Lock API，允许 Web 应用在用户同意的情况下接收鼠标事件的全部输入，即使鼠标指针移出浏览器窗口。

16. **加载事件延迟和触发:**
    - 一系列函数 (`DecrementLoadEventDelayCount`, `DecrementLoadEventDelayCountAndCheckLoadEvent`, `CheckLoadEventSoon`, `IsDelayingLoadEvent`, `LoadEventDelayTimerFired`) 用于管理 `load` 事件的触发时机。

17. **插件加载:**
    - **`LoadPluginsSoon()` 和 `PluginLoadingTimerFired()`:**  用于延迟插件的加载。

18. **Scripted Animation Controller (requestAnimationFrame):**
    - **`GetScriptedAnimationController()`, `RequestAnimationFrame()`, `CancelAnimationFrame()`:** 用于管理基于 `requestAnimationFrame` 的动画。

19. **获取 DocumentLoader:**
    - **`Loader()`:** 获取与此文档关联的 `DocumentLoader` 对象，负责加载文档资源。

20. **坐标调整:**
    - **`AdjustQuadsForScrollAndAbsoluteZoom()` 和 `AdjustRectForScrollAndAbsoluteZoom()`:** 用于在滚动和绝对缩放的情况下调整元素的坐标。

21. **强制同步解析 (用于测试):**
    - **`SetForceSynchronousParsingForTesting()` 和 `ForceSynchronousParsingForTesting()`:** 用于测试目的，强制文档同步解析。

22. **更新 Hover 和 Active 状态:**
    - **`UpdateHoverActiveState()`, `UpdateActiveState()`, `UpdateHoverState()`:**  用于管理 `:hover` 和 `:active` CSS 伪类的状态。

23. **检查样式表加载状态:**
    - **`HaveScriptBlockingStylesheetsLoaded()`, `HaveRenderBlockingStylesheetsLoaded()`, `HaveRenderBlockingResourcesLoaded()`:** 检查脚本阻塞和渲染阻塞的样式表及资源是否已加载完成。

24. **本地化 (Locale) 支持:**
    - **`GetCachedLocale()`:**  获取缓存的本地化信息。

25. **动画时钟:**
    - **`GetAnimationClock()`:** 获取文档的动画时钟。

26. **Template Document 管理:**
    - **`EnsureTemplateDocument()`:**  确保存在与此文档关联的模板文档（用于 `<template>` 元素）。

27. **动态表单元素变更通知:**
    - **`DidChangeFormRelatedElementDynamically()`:**  通知浏览器表单相关元素发生了动态变化。

28. **设备像素比:**
    - **`DevicePixelRatio()`:** 获取设备的像素比。

29. **文本自动调整大小:**
    - **`GetTextAutosizer()`:** 获取用于自动调整文本大小的对象。

30. **伪状态设置 (用于测试):**
    - **`SetPseudoStateForTesting()`:**  用于在测试中设置元素的伪状态（如 `:focus`, `:hover`）。

31. **Autofocus 处理:**
    - 一系列函数 (`EnqueueAutofocusCandidate`, `HasAutofocusCandidates`, `FlushAutofocusCandidates`, `FinalizeAutofocus`, `GetAutofocusDelegate`) 用于处理 HTML 的 `autofocus` 属性。

32. **获取 ActiveElement 和焦点状态:**
    - **`ActiveElement()`:** 获取当前获得焦点的元素。
    - **`hasFocus()`:** 判断文档是否拥有焦点。

33. **访问 `<body>` 元素的属性:**
    - 一系列函数 (`BodyAttributeValue`, `SetBodyAttribute`, `bgColor`, `setBgColor`, `fgColor`, `setFgColor`, `alinkColor`, `setAlinkColor`, `linkColor`, `setLinkColor`, `vlinkColor`, `setVlinkColor`) 提供了一种方便的方式来访问和设置 `<body>` 元素的属性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **`AllowInlineEventHandler()`:**  当 JavaScript 尝试执行内联事件处理程序时，此函数会被调用以检查 CSP 策略。
        * **假设输入:** 用户点击了一个带有 `onclick="alert('Hello')"` 属性的按钮。
        * **逻辑推理:** `AllowInlineEventHandler()` 会检查文档的 CSP 设置是否允许执行内联脚本。
        * **假设输出:** 如果 CSP 允许，返回 `true`，脚本执行；否则返回 `false`，脚本被阻止，并在控制台输出错误。
    * **`RequestAnimationFrame()` 和 `CancelAnimationFrame()`:**  JavaScript 代码可以使用这些方法来安排动画的执行。
        * **例子:** JavaScript 代码 `requestAnimationFrame(animate)` 会调用 Blink 的 `RequestAnimationFrame` 方法，该方法会注册一个回调函数 `animate`，以便在浏览器准备好进行动画帧时执行。
* **HTML:**
    * **`LinkManifest()` 和 `LinkCanonical()`:** 这些函数直接对应于 HTML 的 `<link>` 标签及其 `rel` 属性。
        * **例子:**  当浏览器解析到 `<link rel="manifest" href="/manifest.json">` 时，Blink 会使用 `LinkManifest()` 来获取该元素，以便加载 PWA 的清单文件。
    * **Top Layer 管理:**  与 HTML 的 `<dialog>` 元素以及未来可能出现的其他需要显示在顶层的元素（如 popover）相关。
        * **例子:** 当 JavaScript 调用 `dialog.showModal()` 时，Blink 的 `AddToTopLayer()` 会将该 `<dialog>` 元素添加到顶层，使其显示在其他内容之上。
    * **Autofocus 处理:**  对应 HTML 元素的 `autofocus` 属性。
        * **例子:** 当 HTML 中存在 `<input autofocus>` 时，Blink 的 autofocus 处理逻辑会找到该元素并在页面加载完成后尝试将焦点设置到该元素上。
* **CSS:**
    * **`supportsReducedMotion()` 和 `ShouldForceReduceMotion()`:**  直接关联到 CSS 的 `prefers-reduced-motion` 媒体查询。
        * **假设输入:**  用户的操作系统设置了“减少动画”的偏好。
        * **逻辑推理:**  浏览器会检测到这个偏好，并可能在初始化 `Document` 对象时设置 `supports_reduced_motion_` 标志。`ShouldForceReduceMotion()` 会根据这个标志和网站是否声明支持减少动画来决定是否强制减少动画。
        * **假设输出:** 如果用户偏好减少动画且网站未明确声明不支持，则 `ShouldForceReduceMotion()` 返回 `true`，浏览器可能会禁用或简化某些动画效果。
    * **Hover 和 Active 状态管理:**  直接影响 `:hover` 和 `:active` CSS 伪类的应用。
        * **例子:** 当鼠标悬停在一个链接上时，Blink 的 `UpdateHoverState()` 方法会被调用，该方法会更新该链接的内部状态，从而使得应用于 `:hover` 伪类的 CSS 规则生效。
    * **媒体特性评估:**  与 CSS 媒体查询的评估相关。
        * **例子:** 当浏览器需要确定是否应用某个包含 `@media (max-width: 600px)` 的 CSS 规则时，会调用相关的媒体特性评估机制，`SetMediaFeatureEvaluated()` 用于标记该特性已被评估。

**用户或编程常见的使用错误举例:**

* **CSP 配置错误导致内联脚本被阻止:** 用户可能错误地配置了 Content Security Policy，导致合法的内联 JavaScript 代码无法执行。
    * **例子:**  CSP 头部设置为 `Content-Security-Policy: default-src 'self'`，这意味着只允许加载来自相同源的资源。如果 HTML 中存在 `<button onclick="alert('Hello')">Click me</button>`, 点击按钮时会因为 CSP 策略阻止内联脚本执行，并在控制台输出错误。
* **忘记处理 `prefers-reduced-motion`:** 开发者可能忽略了用户的“减少动画”偏好，导致动画效果对某些用户来说过于强烈或分散注意力。
* **不正确的 DNS 预取配置:**  错误地使用或配置 DNS 预取可能导致不必要的 DNS 查询，反而降低性能。
* **过度使用或不当使用 Top Layer 功能:**  不当使用 `<dialog>` 或其他 Top Layer 元素可能导致用户界面混乱或无法交互。

**用户操作如何一步步到达这里 (调试线索):**

假设我们正在调试一个与动画相关的 bug，该 bug 可能与用户的 `prefers-reduced-motion` 设置有关。以下是一个可能的调试路径：

1. **用户操作:** 用户在操作系统中设置了“减少动画”的偏好。
2. **浏览器启动/页面加载:** 当浏览器启动或加载一个网页时，Blink 引擎会读取操作系统的辅助功能设置。
3. **`Document` 对象创建:**  在页面加载过程中，会创建一个 `Document` 对象来表示该页面。
4. **`supportsReducedMotion()` 调用:** 在 `Document` 对象的初始化或生命周期的某个阶段，可能会调用 `supportsReducedMotion()` 函数来检测用户的偏好。这可能发生在解析 HTML 头部或应用初始样式时。
5. **CSS 动画执行:** 当页面上的某个元素需要执行 CSS 动画时，Blink 可能会调用 `ShouldForceReduceMotion()` 来判断是否应该减少或禁用该动画。
6. **调试器介入:** 如果动画行为不符合预期（例如，即使设置了减少动画，动画仍然在执行），开发者可能会在 `ShouldForceReduceMotion()` 函数中设置断点，以检查用户的偏好是否被正确读取，以及是否有其他因素影响了动画的执行。

**这是第10部分，共11部分，请归纳一下它的功能:**

考虑到这是系列分析的第 10 部分，可以推断之前的部分可能已经涵盖了 `Document` 对象的其他核心功能，例如 DOM 树的构建、样式计算、布局、渲染等。

**本部分 (第 10 部分) 主要关注 `Document` 对象的以下补充功能:**

* **用户辅助功能偏好 (减少动画)。**
* **特定类型 `<link>` 元素的查找。**
* **性能监控和指标收集 (UKM, 字体匹配, 渲染时间)。**
* **安全策略 (CSP) 对内联事件处理器的控制。**
* **DOM 选择的管理。**
* **网络性能优化 (DNS 预取)。**
* **Intersection Observer API 的集成。**
* **特定数据验证 (例如邮件地址)。**
* **CSS 媒体特性评估的跟踪。**
* **浏览器控制台消息的添加。**
* **Top Layer 元素的管理 (例如模态对话框)。**
* **用户输入控制 (Pointer Lock API)。**
* **文档加载生命周期的管理。**
* **动画控制 (requestAnimationFrame)。**
* **与其他 Blink 模块的交互 (例如 `DocumentLoader`).**
* **测试支持功能。**
* **Autofocus 行为的管理。**
* **访问和修改 `<body>` 元素的属性。**

总而言之，第 10 部分深入探讨了 `Document` 对象中一些更细致但重要的功能，这些功能涉及用户体验、性能、安全性和可访问性等方面，并且提供了与 JavaScript, HTML 和 CSS 交互的关键接口。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共11部分，请归纳一下它的功能

"""
if (split_content.Contains(AtomicString("reduce"))) {
        supports_reduced_motion = true;
      }
      break;
    }
  }
  // TODO(crbug.com/1287263): Recreate existing interpolations.
  supports_reduced_motion_ = supports_reduced_motion;
}

bool Document::ShouldForceReduceMotion() const {
  if (!RuntimeEnabledFeatures::ForceReduceMotionEnabled(GetExecutionContext()))
    return false;

  return GetFrame()->GetSettings()->GetPrefersReducedMotion() &&
         !supports_reduced_motion_;
}

static HTMLLinkElement* GetLinkElement(const Document* doc,
                                       bool (*match_fn)(HTMLLinkElement&)) {
  HTMLHeadElement* head = doc->head();
  if (!head)
    return nullptr;

  // The first matching link element is used. Others are ignored.
  for (HTMLLinkElement& link_element :
       Traversal<HTMLLinkElement>::ChildrenOf(*head)) {
    if (match_fn(link_element))
      return &link_element;
  }
  return nullptr;
}

HTMLLinkElement* Document::LinkManifest() const {
  return GetLinkElement(this, [](HTMLLinkElement& link_element) {
    return link_element.RelAttribute().IsManifest();
  });
}

HTMLLinkElement* Document::LinkCanonical() const {
  return GetLinkElement(this, [](HTMLLinkElement& link_element) {
    return link_element.RelAttribute().IsCanonical();
  });
}

ukm::UkmRecorder* Document::UkmRecorder() {
  if (!ukm_recorder_) {
    mojo::Remote<ukm::mojom::UkmRecorderFactory> factory;
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        factory.BindNewPipeAndPassReceiver());
    auto mojo_recorder = ukm::MojoUkmRecorder::Create(*factory);
    if (WebTestSupport::IsRunningWebTest()) {
      ukm::DelegatingUkmRecorder::Get()->AddDelegate(
          mojo_recorder->GetWeakPtr());
    }
    ukm_recorder_ = std::move(mojo_recorder);
  }

  if (WebTestSupport::IsRunningWebTest()) {
    return ukm::DelegatingUkmRecorder::Get();
  } else {
    return ukm_recorder_.get();
  }
}

ukm::SourceId Document::UkmSourceID() const {
  return ukm_source_id_;
}

FontMatchingMetrics* Document::GetFontMatchingMetrics() {
  if (Lifecycle().GetState() >= DocumentLifecycle::LifecycleState::kStopping) {
    return nullptr;
  }
  if (font_matching_metrics_)
    return font_matching_metrics_.get();
  font_matching_metrics_ = std::make_unique<FontMatchingMetrics>(
      dom_window_, GetTaskRunner(TaskType::kInternalDefault));
  return font_matching_metrics_.get();
}

void Document::MaybeRecordShapeTextElapsedTime(base::TimeDelta elapsed_time) {
  data_->accumulated_shape_text_elapsed_time_ += elapsed_time;
  data_->max_shape_text_elapsed_time_ =
      std::max(data_->max_shape_text_elapsed_time_, elapsed_time);
}

void Document::MaybeRecordSvgImageProcessingTime(
    int data_change_count,
    base::TimeDelta data_change_elapsed_time) const {
  data_->svg_image_processed_count_ += data_change_count;
  data_->accumulated_svg_image_elapsed_time_ += data_change_elapsed_time;
}

bool Document::AllowInlineEventHandler(Node* node,
                                       EventListener* listener,
                                       const String& context_url,
                                       const WTF::OrdinalNumber& context_line) {
  auto* element = DynamicTo<Element>(node);
  // HTML says that inline script needs browsing context to create its execution
  // environment.
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/webappapis.html#event-handler-attributes
  // Also, if the listening node came from other document, which happens on
  // context-less event dispatching, we also need to ask the owner document of
  // the node.
  LocalDOMWindow* window = domWindow();
  if (!window)
    return false;

  // https://html.spec.whatwg.org/multipage/webappapis.html#event-handler-content-attributes
  // Step 5.1. If the Should element's inline behavior be blocked by Content
  // Security Policy? algorithm returns "Blocked" when executed upon element,
  // "script attribute", and value, then return. [CSP] [spec text]
  if (!window->GetContentSecurityPolicyForCurrentWorld()->AllowInline(
          ContentSecurityPolicy::InlineType::kScriptAttribute, element,
          listener->ScriptBody(), String() /* nonce */, context_url,
          context_line))
    return false;

  if (!window->CanExecuteScripts(kNotAboutToExecuteScript))
    return false;
  if (node && node->GetDocument() != this &&
      !node->GetDocument().AllowInlineEventHandler(node, listener, context_url,
                                                   context_line))
    return false;

  return true;
}

void Document::UpdateSelectionAfterLayout() {
  should_update_selection_after_layout_ = false;
  Element* element = FocusedElement();
  if (!element)
    return;
  if (element->IsFocusable())
    element->UpdateSelectionOnFocus(SelectionBehaviorOnFocus::kRestore);
}

void Document::AttachRange(Range* range) {
  DCHECK(!ranges_.Contains(range));
  ranges_.insert(range);
}

void Document::DetachRange(Range* range) {
  // We don't DCHECK ranges_.contains(range) to allow us to call this
  // unconditionally to fix: https://bugs.webkit.org/show_bug.cgi?id=26044
  ranges_.erase(range);
}

void Document::InitDNSPrefetch() {
  Settings* settings = GetSettings();

  have_explicitly_disabled_dns_prefetch_ = false;
  is_dns_prefetch_enabled_ =
      settings && settings->GetDNSPrefetchingEnabled() &&
      dom_window_->GetSecurityContext().GetSecurityOrigin()->Protocol() ==
          "http";

  // Inherit DNS prefetch opt-out from parent frame
  if (Document* parent = ParentDocument()) {
    if (!parent->IsDNSPrefetchEnabled())
      is_dns_prefetch_enabled_ = false;
  }
}

void Document::ParseDNSPrefetchControlHeader(
    const String& dns_prefetch_control) {
  if (EqualIgnoringASCIICase(dns_prefetch_control, "on") &&
      !have_explicitly_disabled_dns_prefetch_) {
    is_dns_prefetch_enabled_ = true;
    return;
  }

  is_dns_prefetch_enabled_ = false;
  have_explicitly_disabled_dns_prefetch_ = true;
}

IntersectionObserverController* Document::GetIntersectionObserverController() {
  return intersection_observer_controller_;
}

IntersectionObserverController&
Document::EnsureIntersectionObserverController() {
  if (!intersection_observer_controller_) {
    intersection_observer_controller_ =
        MakeGarbageCollected<IntersectionObserverController>(
            GetExecutionContext());
  }
  return *intersection_observer_controller_;
}

ElementIntersectionObserverData*
Document::DocumentExplicitRootIntersectionObserverData() const {
  return document_explicit_root_intersection_observer_data_.Get();
}

ElementIntersectionObserverData&
Document::EnsureDocumentExplicitRootIntersectionObserverData() {
  if (!document_explicit_root_intersection_observer_data_) {
    document_explicit_root_intersection_observer_data_ =
        MakeGarbageCollected<ElementIntersectionObserverData>();
  }
  return *document_explicit_root_intersection_observer_data_;
}

const ScriptRegexp& Document::EnsureEmailRegexp() const {
  if (!data_->email_regexp_) {
    data_->email_regexp_ =
        EmailInputType::CreateEmailRegexp(GetAgent().isolate());
  }
  return *data_->email_regexp_;
}

void Document::SetMediaFeatureEvaluated(int feature) {
  evaluated_media_features_ |= (1 << feature);
}

bool Document::WasMediaFeatureEvaluated(int feature) {
  return (evaluated_media_features_ >> feature) & 1;
}

void Document::AddConsoleMessage(ConsoleMessage* message,
                                 bool discard_duplicates) const {
  // Don't let non-attached Documents spam the console.
  if (domWindow())
    domWindow()->AddConsoleMessage(message, discard_duplicates);
}

void Document::AddToTopLayer(Element* element, const Element* before) {
  if (element->IsInTopLayer()) {
    if (IsScheduledForTopLayerRemoval(element)) {
      // Since the html spec currently says close() should remove the dialog
      // element from the top layer immediately, we need to remove any
      // transitioning elements out of the top layer in order to keep the
      // behavior of re-adding the element to the end of the top layer list for
      // cases where style change events do not happen between close() and
      // showModal():
      //
      // dialog.close();
      // dialog.showModal();
      RemoveFromTopLayerImmediately(element);
    } else {
      return;
    }
  }

  DCHECK(!IsScheduledForTopLayerRemoval(element));
  DCHECK(!before || top_layer_elements_.Contains(before));

  if (before) {
    DCHECK(element->IsBackdropPseudoElement())
        << "If this invariant changes, we might need to revisit Container "
           "Queries for top layer elements.";
    wtf_size_t before_position = top_layer_elements_.Find(before);
    top_layer_elements_.insert(before_position, element);
  } else {
    top_layer_elements_.push_back(element);
  }

  element->SetIsInTopLayer(true);
  display_lock_document_state_->ElementAddedToTopLayer(element);

  probe::TopLayerElementsChanged(this);

  // In case a top layer element is being synchronously removed and re-added,
  // we need to do the same to the backdrop in order to keep it next to this
  // element in the top layer list.
  if (PseudoElement* backdrop =
          element->GetPseudoElement(PseudoId::kPseudoIdBackdrop,
                                    /*view_transition_name=*/g_null_atom)) {
    CHECK(!backdrop->IsInTopLayer());
    AddToTopLayer(backdrop, element);
  }
}

void Document::ScheduleForTopLayerRemoval(Element* element,
                                          TopLayerReason reason) {
  if (!element->IsInTopLayer()) {
    return;
  }

  std::optional<TopLayerReason> existing_pending_removal = std::nullopt;
  for (const auto& pending_removal : top_layer_elements_pending_removal_) {
    if (pending_removal->element == element) {
      existing_pending_removal = pending_removal->reason;
      break;
    }
  }

  if (existing_pending_removal) {
    CHECK_EQ(*existing_pending_removal, reason);
  } else {
    top_layer_elements_pending_removal_.push_back(
        MakeGarbageCollected<TopLayerPendingRemoval>(element, reason));
  }
  ScheduleLayoutTreeUpdateIfNeeded();
}

void Document::RemoveFinishedTopLayerElements() {
  if (top_layer_elements_pending_removal_.empty()) {
    return;
  }
  HeapVector<Member<Element>> to_remove;
  for (const auto& pending_removal : top_layer_elements_pending_removal_) {
    Element* element = pending_removal->element;
    const ComputedStyle* style = element->GetComputedStyle();
    if (!style || style->Overlay() == EOverlay::kNone) {
      to_remove.push_back(element);
    }
  }
  for (Element* remove_element : to_remove) {
    RemoveFromTopLayerImmediately(remove_element);
  }
}

void Document::RemoveFromTopLayerImmediately(Element* element) {
  if (!element->IsInTopLayer()) {
    return;
  }
  wtf_size_t position = top_layer_elements_.Find(element);
  DCHECK_NE(position, kNotFound);
  top_layer_elements_.EraseAt(position);
  for (unsigned i = 0; i < top_layer_elements_pending_removal_.size(); i++) {
    if (top_layer_elements_pending_removal_[i]->element == element) {
      top_layer_elements_pending_removal_.EraseAt(i);
      break;
    }
  }
  element->SetIsInTopLayer(false);
  display_lock_document_state_->ElementRemovedFromTopLayer(element);
  if (RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled() ||
      RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    if (auto* html_element = DynamicTo<HTMLElement>(element)) {
      if (html_element->HasPopoverAttribute()) {
        html_element->SetImplicitAnchor(nullptr);
      }
    }
  }

  probe::TopLayerElementsChanged(this);

  // In case a top layer element is being synchronously removed and re-added,
  // we need to do the same to the backdrop in order to keep it next to this
  // element in the top layer list.
  if (PseudoElement* backdrop =
          element->GetPseudoElement(PseudoId::kPseudoIdBackdrop,
                                    /*view_transition_name=*/g_null_atom)) {
    CHECK(backdrop->IsInTopLayer());
    RemoveFromTopLayerImmediately(backdrop);
  }
}

std::optional<Document::TopLayerReason> Document::IsScheduledForTopLayerRemoval(
    Element* element) const {
  for (const auto& entry : top_layer_elements_pending_removal_) {
    if (entry->element == element) {
      return entry->reason;
    }
  }
  return std::nullopt;
}

HTMLDialogElement* Document::ActiveModalDialog() const {
  for (const auto& element : base::Reversed(top_layer_elements_)) {
    if (auto* dialog = DynamicTo<HTMLDialogElement>(*element)) {
      if (dialog->IsModal()) {
        // Modal dialogs transitioning out after being closed are not considered
        // to be active.
        if (!IsScheduledForTopLayerRemoval(dialog)) {
          return dialog;
        }
      }
    }
  }

  return nullptr;
}

HTMLElement* Document::TopmostPopoverOrHint() const {
  if (!PopoverHintStack().empty()) {
    CHECK(RuntimeEnabledFeatures::HTMLPopoverHintEnabled());
    return PopoverHintStack().back();
  }
  if (!PopoverAutoStack().empty()) {
    return PopoverAutoStack().back();
  }
  return nullptr;
}
void Document::SetPopoverPointerdownTarget(const HTMLElement* popover) {
  DCHECK(!popover || popover->HasPopoverAttribute());
  popover_pointerdown_target_ = popover;
}

const HTMLDialogElement* Document::DialogPointerdownTarget() const {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  return dialog_pointerdown_target_.Get();
}

void Document::SetDialogPointerdownTarget(const HTMLDialogElement* dialog) {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  DCHECK(!dialog || dialog->IsOpen());
  dialog_pointerdown_target_ = dialog;
}

void Document::exitPointerLock() {
  if (!GetPage())
    return;
  if (Element* target = GetPage()->GetPointerLockController().GetElement()) {
    if (target->GetDocument() != this)
      return;
    GetPage()->GetPointerLockController().ExitPointerLock();
  }
}

Element* Document::PointerLockElement() const {
  if (!GetPage() || GetPage()->GetPointerLockController().LockPending())
    return nullptr;
  if (Element* element = GetPage()->GetPointerLockController().GetElement()) {
    if (element->GetDocument() == this)
      return element;
  }
  return nullptr;
}

void Document::DecrementLoadEventDelayCount() {
  DCHECK(load_event_delay_count_);
  --load_event_delay_count_;

  if (!load_event_delay_count_)
    CheckLoadEventSoon();
}

void Document::DecrementLoadEventDelayCountAndCheckLoadEvent() {
  DCHECK(load_event_delay_count_);
  --load_event_delay_count_;

  if (!load_event_delay_count_)
    CheckCompleted();
}

void Document::CheckLoadEventSoon() {
  if (GetFrame() && !load_event_delay_timer_.IsActive())
    load_event_delay_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

bool Document::IsDelayingLoadEvent() {
  return load_event_delay_count_;
}

void Document::LoadEventDelayTimerFired(TimerBase*) {
  CheckCompleted();
}

void Document::LoadPluginsSoon() {
  // FIXME: Remove this timer once we don't need to compute layout to load
  // plugins.
  if (!plugin_loading_timer_.IsActive())
    plugin_loading_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void Document::PluginLoadingTimerFired(TimerBase*) {
  UpdateStyleAndLayout(DocumentUpdateReason::kPlugin);
}

ScriptedAnimationController& Document::GetScriptedAnimationController() {
  return *scripted_animation_controller_;
}

int Document::RequestAnimationFrame(FrameCallback* callback) {
  return scripted_animation_controller_->RegisterFrameCallback(callback);
}

void Document::CancelAnimationFrame(int id) {
  scripted_animation_controller_->CancelFrameCallback(id);
}

DocumentLoader* Document::Loader() const {
  return GetFrame() ? GetFrame()->Loader().GetDocumentLoader() : nullptr;
}

Node* EventTargetNodeForDocument(Document* doc) {
  if (!doc)
    return nullptr;
  Node* node = doc->FocusedElement();
  auto* plugin_document = DynamicTo<PluginDocument>(doc);
  if (plugin_document && !node) {
    node = plugin_document->PluginNode();
  }
  if (!node && IsA<HTMLDocument>(doc))
    node = doc->body();
  if (!node)
    node = doc->documentElement();
  return node;
}

void Document::AdjustQuadsForScrollAndAbsoluteZoom(
    Vector<gfx::QuadF>& quads,
    const LayoutObject& layout_object) const {
  if (!View()) {
    return;
  }

  for (auto& quad : quads)
    AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(quad, layout_object);
}

void Document::AdjustRectForScrollAndAbsoluteZoom(
    gfx::RectF& rect,
    const LayoutObject& layout_object) const {
  if (!View()) {
    return;
  }

  AdjustForAbsoluteZoom::AdjustRectMaybeExcludingCSSZoom(rect, layout_object);
}

void Document::SetForceSynchronousParsingForTesting(bool enabled) {
  g_force_synchronous_parsing_for_testing = enabled;
}

bool Document::ForceSynchronousParsingForTesting() {
  return g_force_synchronous_parsing_for_testing;
}

void Document::UpdateHoverActiveState(bool is_active,
                                      bool update_active_chain,
                                      Element* inner_element) {
  if (is_active && GetFrame())
    GetFrame()->GetEventHandler().NotifyElementActivated();

  Element* inner_element_in_document = inner_element;

  while (inner_element_in_document &&
         inner_element_in_document->GetDocument() != this) {
    inner_element_in_document->GetDocument().UpdateHoverActiveState(
        is_active, update_active_chain, inner_element_in_document);
    inner_element_in_document =
        inner_element_in_document->GetDocument().LocalOwner();
  }

  UpdateActiveState(is_active, update_active_chain, inner_element_in_document);
  UpdateHoverState(inner_element_in_document);
}

void Document::UpdateActiveState(bool is_active,
                                 bool update_active_chain,
                                 Element* new_active_element) {
  Element* old_active_element = GetActiveElement();
  if (old_active_element && !is_active) {
    // The oldActiveElement layoutObject is null, dropped on :active by setting
    // display: none, for instance. We still need to clear the ActiveChain as
    // the mouse is released.
    for (Element* element = old_active_element; element;
         element = FlatTreeTraversal::ParentElement(*element)) {
      element->SetActive(false);
      user_action_elements_.SetInActiveChain(element, false);
    }
    SetActiveElement(nullptr);
  } else {
    if (!old_active_element && new_active_element && is_active) {
      // We are setting the :active chain and freezing it. If future moves
      // happen, they will need to reference this chain.
      for (Element* element = new_active_element; element;
           element = FlatTreeTraversal::ParentElement(*element)) {
        user_action_elements_.SetInActiveChain(element, true);
      }
      SetActiveElement(new_active_element);
    }
  }

  // If the mouse has just been pressed, set :active on the chain. Those (and
  // only those) nodes should remain :active until the mouse is released.
  bool allow_active_changes = !old_active_element && GetActiveElement();
  if (!allow_active_changes)
    return;

  DCHECK(is_active);

  Element* new_element = SkipDisplayNoneAncestors(new_active_element);

  // Now set the active state for our new object up to the root.  If the mouse
  // is down and if this is a mouse move event, we want to restrict changes in
  // :active to only apply to elements that are in the :active chain that we
  // froze at the time the mouse went down.
  for (Element* curr = new_element; curr;
       curr = FlatTreeTraversal::ParentElement(*curr)) {
    if (update_active_chain || curr->InActiveChain())
      curr->SetActive(true);
  }
}

void Document::UpdateHoverState(Element* inner_element_in_document) {
  Element* old_hover_element = HoverElement();

  // The passed in innerElement may not be a result of a hit test for the
  // current up-to-date flat/layout tree. That means the element may be
  // display:none at this point. Skip up the ancestor chain until we reach an
  // element with a layoutObject or a display:contents element.
  Element* new_hover_element =
      SkipDisplayNoneAncestors(inner_element_in_document);

  if (old_hover_element == new_hover_element)
    return;

  // Update our current hover element.
  SetHoverElement(new_hover_element);

  Node* ancestor_element = nullptr;
  if (old_hover_element && old_hover_element->isConnected() &&
      new_hover_element) {
    Node* ancestor = FlatTreeTraversal::CommonAncestor(*old_hover_element,
                                                       *new_hover_element);
    if (auto* element = DynamicTo<Element>(ancestor))
      ancestor_element = element;
  }

  HeapVector<Member<Element>, 32> elements_to_remove_from_chain;
  HeapVector<Member<Element>, 32> elements_to_add_to_hover_chain;

  // The old hover path only needs to be cleared up to (and not including) the
  // common ancestor;
  //
  // TODO(emilio): old_hover_element may be disconnected from the tree already.
  if (old_hover_element && old_hover_element->isConnected()) {
    for (Element* curr = old_hover_element; curr && curr != ancestor_element;
         curr = FlatTreeTraversal::ParentElement(*curr)) {
      elements_to_remove_from_chain.push_back(curr);
    }
  }

  // Now set the hover state for our new object up to the root.
  for (Element* curr = new_hover_element; curr;
       curr = FlatTreeTraversal::ParentElement(*curr)) {
    elements_to_add_to_hover_chain.push_back(curr);
  }

  for (Element* element : elements_to_remove_from_chain)
    element->SetHovered(false);

  bool saw_common_ancestor = false;
  for (Element* element : elements_to_add_to_hover_chain) {
    if (element == ancestor_element)
      saw_common_ancestor = true;
    if (!saw_common_ancestor || element == hover_element_)
      element->SetHovered(true);
  }
}

bool Document::HaveScriptBlockingStylesheetsLoaded() const {
  return style_engine_->HaveScriptBlockingStylesheetsLoaded();
}

bool Document::HaveRenderBlockingStylesheetsLoaded() const {
  return !render_blocking_resource_manager_ ||
         !render_blocking_resource_manager_->HasPendingStylesheets();
}

bool Document::HaveRenderBlockingResourcesLoaded() const {
  return !render_blocking_resource_manager_ ||
         !render_blocking_resource_manager_->HasRenderBlockingResources();
}

Locale& Document::GetCachedLocale(const AtomicString& locale) {
  AtomicString locale_key = locale;
  if (locale.empty() ||
      !RuntimeEnabledFeatures::LangAttributeAwareFormControlUIEnabled())
    return Locale::DefaultLocale();
  LocaleIdentifierToLocaleMap::AddResult result =
      locale_cache_.insert(locale_key, nullptr);
  if (result.is_new_entry)
    result.stored_value->value = Locale::Create(locale_key);
  return *(result.stored_value->value);
}

AnimationClock& Document::GetAnimationClock() {
  return animation_clock_;
}

const AnimationClock& Document::GetAnimationClock() const {
  return animation_clock_;
}

Document& Document::EnsureTemplateDocument() {
  if (IsTemplateDocument())
    return *this;

  if (template_document_)
    return *template_document_;

  if (IsA<HTMLDocument>(this)) {
    template_document_ = MakeGarbageCollected<HTMLDocument>(
        DocumentInit::Create()
            .WithExecutionContext(execution_context_.Get())
            .WithAgent(GetAgent())
            .WithURL(BlankURL()));
  } else {
    template_document_ = MakeGarbageCollected<Document>(
        DocumentInit::Create()
            .WithExecutionContext(execution_context_.Get())
            .WithAgent(GetAgent())
            .WithURL(BlankURL()));
  }

  template_document_->template_document_host_ = this;  // balanced in dtor.

  return *template_document_.Get();
}

void Document::DidChangeFormRelatedElementDynamically(
    HTMLElement* element,
    WebFormRelatedChangeType form_related_change) {
  if (!GetFrame() || !GetFrame()->GetPage() || !HasFinishedParsing() ||
      !GetFrame()->IsAttached()) {
    return;
  }

  GetFrame()
      ->GetPage()
      ->GetChromeClient()
      .DidChangeFormRelatedElementDynamically(GetFrame(), element,
                                              form_related_change);
}

float Document::DevicePixelRatio() const {
  return GetFrame() ? GetFrame()->DevicePixelRatio() : 1.0;
}

TextAutosizer* Document::GetTextAutosizer() {
  if (!text_autosizer_)
    text_autosizer_ = MakeGarbageCollected<TextAutosizer>(this);
  return text_autosizer_.Get();
}

bool Document::SetPseudoStateForTesting(Element& element,
                                        const String& pseudo,
                                        bool matches) {
  DCHECK(WebTestSupport::IsRunningWebTest());
  auto& set = UserActionElements();
  if (pseudo == ":focus") {
    set.SetFocused(&element, matches);
    element.PseudoStateChangedForTesting(CSSSelector::kPseudoFocus);
  } else if (pseudo == ":focus-within") {
    set.SetHasFocusWithin(&element, matches);
    element.PseudoStateChangedForTesting(CSSSelector::kPseudoFocusWithin);
  } else if (pseudo == ":active") {
    set.SetActive(&element, matches);
    element.PseudoStateChangedForTesting(CSSSelector::kPseudoActive);
  } else if (pseudo == ":hover") {
    set.SetHovered(&element, matches);
    element.PseudoStateChangedForTesting(CSSSelector::kPseudoHover);
  } else {
    return false;
  }
  return true;
}

void Document::EnqueueAutofocusCandidate(Element& element) {
  // https://html.spec.whatwg.org/C#the-autofocus-attribute
  // 7. If topDocument's autofocus processed flag is false, then remove the
  // element from topDocument's autofocus candidates, and append the element
  // to topDocument's autofocus candidates.
  if (autofocus_processed_flag_)
    return;
  wtf_size_t index = autofocus_candidates_.Find(&element);
  if (index != WTF::kNotFound)
    autofocus_candidates_.EraseAt(index);
  autofocus_candidates_.push_back(element);
}

bool Document::HasAutofocusCandidates() const {
  return autofocus_candidates_.size() > 0;
}

// https://html.spec.whatwg.org/C/#flush-autofocus-candidates
void Document::FlushAutofocusCandidates() {
  // 1. If topDocument's autofocus processed flag is true, then return.
  if (autofocus_processed_flag_)
    return;

  // 3. If candidates is empty, then return.
  if (autofocus_candidates_.empty())
    return;

  // 4. If topDocument's focused area is not topDocument itself, or
  //    topDocument's URL's fragment is not empty, then:
  //  1. Empty candidates.
  //  2. Set topDocument's autofocus processed flag to true.
  //  3. Return.
  if (AdjustedFocusedElement()) {
    autofocus_candidates_.clear();
    autofocus_processed_flag_ = true;
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kRendering,
        mojom::ConsoleMessageLevel::kInfo,
        "Autofocus processing was blocked because a "
        "document already has a focused element."));
    return;
  }
  if (CssTarget()) {
    autofocus_candidates_.clear();
    autofocus_processed_flag_ = true;
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kRendering,
        mojom::ConsoleMessageLevel::kInfo,
        "Autofocus processing was blocked because a "
        "document's URL has a fragment '#" +
            Url().FragmentIdentifier() + "'."));
    return;
  }

  // 5. While candidates is not empty:
  while (!autofocus_candidates_.empty()) {
    // 5.1. Let element be candidates[0].
    Element& element = *autofocus_candidates_[0];

    // 5.2. Let doc be element's node document.
    Document* doc = &element.GetDocument();

    // 5.3. If doc is not fully active, then remove element from candidates,
    // and continue.
    // 5.4. If doc's browsing context's top-level browsing context is not same
    // as topDocument's browsing context, then remove element from candidates,
    // and continue.
    if (&doc->TopDocument() != this) {
      autofocus_candidates_.EraseAt(0);
      continue;
    }

    // The element is in the fallback content of an OBJECT of which
    // fallback state is not fixed yet.
    // TODO(tkent): Standardize this behavior.
    if (IsInIndeterminateObjectAncestor(&element)) {
      return;
    }

    // 5.5. If doc's script-blocking style sheet counter is greater than 0,
    // then return.
    // TODO(tkent): Is this necessary? WPT spin-by-blocking-style-sheet.html
    // doesn't hit this condition, and FlushAutofocusCandidates() is not called
    // until the stylesheet is loaded.
    if (GetStyleEngine().HasPendingScriptBlockingSheets() ||
        !HaveRenderBlockingStylesheetsLoaded()) {
      return;
    }

    // 5.6. Remove element from candidates.
    autofocus_candidates_.EraseAt(0);

    // 5.7. Let inclusiveAncestorDocuments be a list consisting of doc, plus
    // the active documents of each of doc's browsing context's ancestor
    // browsing contexts.
    // 5.8. If URL's fragment of any Document in inclusiveAncestorDocuments
    // is not empty, then continue.
    if (doc != this) {
      for (HTMLFrameOwnerElement* frameOwner = doc->LocalOwner();
           !doc->CssTarget() && frameOwner; frameOwner = doc->LocalOwner()) {
        doc = &frameOwner->GetDocument();
      }
      if (doc->CssTarget()) {
        AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kRendering,
            mojom::ConsoleMessageLevel::kInfo,
            "Autofocus processing was blocked because a "
            "document's URL has a fragment '#" +
                doc->Url().FragmentIdentifier() + "'."));
        continue;
      }
      DCHECK_EQ(doc, this);
    }

    // 9. Let target be element.
    Element* target = &element;

    // 10. If target is not a focusable area, then set target to the result of
    // getting the focusable area for target.
    element.GetDocument().UpdateStyleAndLayoutTree();
    if (!target->IsFocusable())
      target = target->GetFocusableArea();

    // 11. If target is not null, then:
    if (target) {
      // 11.1. Empty candidates.
      // 11.2. Set topDocument's autofocus processed flag to true.
      FinalizeAutofocus();
      // 11.3. Run the focusing steps for element.
      element.Focus();
    } else {
      // TODO(tkent): Show a console message, and fix LocalNTP*Test.*
      // in browser_tests.
    }
  }
}

void Document::FinalizeAutofocus() {
  autofocus_candidates_.clear();
  autofocus_processed_flag_ = true;
}

// https://html.spec.whatwg.org/C/#autofocus-delegate, although most uses are
// of Element::GetAutofocusDelegate().
Element* Document::GetAutofocusDelegate() const {
  if (HTMLElement* body_element = body())
    return body_element->GetAutofocusDelegate();

  return nullptr;
}

Element* Document::ActiveElement() const {
  return activeElement();
}

bool Document::hasFocus() const {
  return GetPage() && GetPage()->GetFocusController().IsDocumentFocused(*this);
}

const AtomicString& Document::BodyAttributeValue(
    const QualifiedName& name) const {
  if (auto* bodyElement = body())
    return bodyElement->FastGetAttribute(name);
  return g_null_atom;
}

void Document::SetBodyAttribute(const QualifiedName& name,
                                const AtomicString& value) {
  if (auto* bodyElement = body()) {
    // FIXME: This check is apparently for benchmarks that set the same value
    // repeatedly.  It's not clear what benchmarks though, it's also not clear
    // why we don't avoid causing a style recalc when setting the same value to
    // a presentational attribute in the common case.
    if (bodyElement->FastGetAttribute(name) != value)
      bodyElement->setAttribute(name, value);
  }
}

const AtomicString& Document::bgColor() const {
  return BodyAttributeValue(html_names::kBgcolorAttr);
}

void Document::setBgColor(const AtomicString& value) {
  if (!IsFrameSet())
    SetBodyAttribute(html_names::kBgcolorAttr, value);
}

const AtomicString& Document::fgColor() const {
  return BodyAttributeValue(html_names::kTextAttr);
}

void Document::setFgColor(const AtomicString& value) {
  if (!IsFrameSet())
    SetBodyAttribute(html_names::kTextAttr, value);
}

const AtomicString& Document::alinkColor() const {
  return BodyAttributeValue(html_names::kAlinkAttr);
}

void Document::setAlinkColor(const AtomicString& value) {
  if (!IsFrameSet())
    SetBodyAttribute(html_names::kAlinkAttr, value);
}

const AtomicString& Document::linkColor() const {
  return BodyAttributeValue(html_names::kLinkAttr);
}

void Document::setLinkColor(const AtomicString& value) {
  if (!IsFrameSet())
    SetBodyAttribute(html_names::kLinkAttr, value);
}

const AtomicString& Document::vlinkColor() const {
  return BodyAttributeValue(html_names::kVlinkAttr);
}

void Doc
"""


```