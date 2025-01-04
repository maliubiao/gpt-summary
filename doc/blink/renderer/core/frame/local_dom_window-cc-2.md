Response:
The user wants a summary of the functionalities of the `LocalDOMWindow` class in the provided Chromium Blink source code. I need to identify the key responsibilities and methods of this class, explain their connection to web technologies like JavaScript, HTML, and CSS with examples, detail any logical reasoning involved with potential inputs and outputs, highlight common user/programming errors, and finally, provide an overall summary of the class's purpose.

**Plan:**

1. **Identify Core Functionalities:** Go through the methods of the `LocalDOMWindow` class and categorize them based on their actions.
2. **Relate to Web Technologies:**  For each category, explain how it interacts with JavaScript, HTML, and CSS. Provide specific examples of how these methods are used in web development.
3. **Analyze Logical Reasoning:** Look for methods that involve decision-making or calculations based on input. Describe hypothetical input and output scenarios.
4. **Identify Potential Errors:** Examine the code for areas where incorrect usage might lead to errors. Provide illustrative examples of such errors.
5. **Synthesize a Summary:**  Combine the categorized functionalities into a concise overview of the `LocalDOMWindow`'s role.
这是对 `blink/renderer/core/frame/local_dom_window.cc` 文件功能的总结，延续之前的部分。以下是对本部分代码的分析和功能归纳：

**本部分的功能归纳：**

这部分 `LocalDOMWindow` 的代码主要关注以下功能：

*   **处理窗口的打开、关闭和属性修改：**  包括 `open`, `openPictureInPictureWindow`, `moveBy`, `moveTo`, `resizeBy`, `resizeTo` 等方法，允许 JavaScript 代码控制浏览器的窗口行为，例如打开新窗口、调整窗口位置和大小。
*   **管理事件监听器：** 提供了添加 (`AddedEventListener`) 和移除 (`RemovedEventListener`, `RemoveAllEventListeners`) 事件监听器的功能，以及触发 `load` 事件 (`DispatchLoadEvent`) 和通用事件 (`DispatchEvent`) 的机制。
*   **与页面加载和渲染相关的功能：**  `FinishedLoading` 方法处理页面加载完成后的操作，`PrintErrorMessage` 用于在控制台输出错误信息。
*   **提供对特定浏览器功能的访问：** 例如 `openPictureInPictureWindow` 用于打开画中画窗口。
*   **安全性相关的操作：**  例如检查安全上下文 (`isSecureContext`)，以及处理跨域隔离 (`CrossOriginIsolatedCapability`)。
*   **性能监控和用户行为追踪：**  通过集成 UKM (User Keyed Metrics) 记录器 (`UkmRecorder`, `UkmSourceID`) 来收集性能数据。
*   **管理窗口状态：** 例如记录是否在后退/前进缓存中 (`SetIsInBackForwardCache`)，以及管理导航 ID (`GenerateNewNavigationId`)。
*   **提供对实验性或特定功能的访问：** 例如 `fence()` 方法用于访问 Fenced Frames 功能。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **窗口操作 (JavaScript):**
    *   **功能:** `open()` 方法允许 JavaScript 代码打开新的浏览器窗口或标签页。
    *   **举例:**
        ```javascript
        // 在用户点击按钮后打开一个新的空白窗口
        document.getElementById('openButton').addEventListener('click', function() {
          window.open();
        });

        // 打开一个指定 URL 的新窗口，并设置一些窗口特性
        window.open('https://example.com', '_blank', 'width=600,height=400');
        ```
    *   **功能:** `moveBy()`, `moveTo()`, `resizeBy()`, `resizeTo()` 方法允许 JavaScript 改变当前窗口的位置和大小。
    *   **举例:**
        ```javascript
        // 将窗口向右移动 100 像素，向下移动 50 像素
        window.moveBy(100, 50);

        // 将窗口移动到屏幕的 (100, 100) 坐标
        window.moveTo(100, 100);

        // 将窗口宽度增加 50 像素，高度减少 20 像素
        window.resizeBy(50, -20);

        // 将窗口大小设置为 800x600
        window.resizeTo(800, 600);
        ```

2. **事件处理 (JavaScript & HTML):**
    *   **功能:** `AddedEventListener`, `RemovedEventListener` 等方法对应 JavaScript 中使用 `addEventListener` 和 `removeEventListener` 添加和移除事件监听器。`DispatchLoadEvent` 触发窗口或文档的 `load` 事件。
    *   **举例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>事件处理示例</title>
        </head>
        <body>
          <button id="myButton">点击我</button>
          <script>
            const button = document.getElementById('myButton');
            button.addEventListener('click', function() {
              console.log('按钮被点击了！');
            });

            window.addEventListener('load', function() {
              console.log('页面加载完成！');
            });
          </script>
        </body>
        </html>
        ```
        在这个例子中，`addEventListener` 对应 `LocalDOMWindow::AddedEventListener`，当页面加载完成时，会触发 `load` 事件，这与 `LocalDOMWindow::DispatchLoadEvent` 相关。

3. **获取计算样式 (JavaScript & CSS):**
    *   **功能:**  `getComputedStyle()` 方法允许 JavaScript 获取元素最终应用的所有 CSS 属性的值。
    *   **举例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>获取计算样式示例</title>
          <style>
            #myDiv {
              width: 100px;
              height: 50px;
              background-color: red;
            }
          </style>
        </head>
        <body>
          <div id="myDiv"></div>
          <script>
            const div = document.getElementById('myDiv');
            const computedStyle = window.getComputedStyle(div);
            console.log('元素的宽度:', computedStyle.width);
            console.log('元素的高度:', computedStyle.height);
            console.log('元素的背景颜色:', computedStyle.backgroundColor);
          </script>
        </body>
        </html>
        ```
        JavaScript 调用 `window.getComputedStyle(div)`，最终会调用到 `LocalDOMWindow::getComputedStyle` 方法。

**逻辑推理的假设输入与输出：**

1. **`scrollBy(double x, double y)`:**
    *   **假设输入:** JavaScript 调用 `window.scrollBy(100, -50)`。
    *   **输出:** 浏览器窗口的内容将水平向右滚动 100 像素，垂直向上滚动 50 像素。如果当前窗口没有显示在 frame 中，则不会发生滚动。

2. **`moveTo(int x, int y)`:**
    *   **假设输入:** JavaScript 调用 `window.moveTo(50, 100)`。
    *   **输出:** 浏览器主窗口（如果该 `LocalDOMWindow` 关联的是主窗口）将移动到屏幕坐标 (50, 100) 的位置。如果该窗口不是 outermost main frame 或者正在 prerendering，则不会发生移动。

3. **`open(const String& url_string, ...)`:**
    *   **假设输入:** JavaScript 调用 `window.open('https://example.com', '_blank')`.
    *   **输出:**  一个新的浏览器标签页或窗口将打开，并加载 `https://example.com`。返回新窗口的 `DOMWindow` 对象。如果 URL 无效，会抛出 `SyntaxError` 异常。

**用户或编程常见的使用错误举例说明：**

1. **不安全的 `window.open()` 调用:**
    *   **错误:** 在没有用户交互的情况下调用 `window.open()` 可能会被浏览器拦截为弹出窗口。
    *   **举例:**
        ```javascript
        // 错误的做法，可能会被浏览器拦截
        setTimeout(function() {
          window.open('https://malicious.com');
        }, 5000);
        ```
    *   **正确做法:**  `window.open()` 通常应该在用户交互（例如点击事件）的回调函数中调用。

2. **尝试在非主框架中移动或调整窗口大小:**
    *   **错误:**  `moveBy`, `moveTo`, `resizeBy`, `resizeTo` 等方法通常只对最外层的主框架有效。在 iframe 中调用这些方法可能不会产生预期的效果，或者根本不起作用。
    *   **举例:**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>iframe 示例</title>
        </head>
        <body>
          <iframe id="myIframe" src="iframe_content.html"></iframe>
          <script>
            const iframeWindow = document.getElementById('myIframe').contentWindow;
            // 尝试移动 iframe，这通常不会成功
            iframeWindow.moveBy(100, 100);
          </script>
        </body>
        </html>
        ```

3. **在画中画窗口中不通过用户激活调用 `resizeBy` 或 `resizeTo`:**
    *   **错误:** 对画中画窗口进行大小调整需要用户激活。
    *   **举例:**
        ```javascript
        // 错误的做法，没有用户激活
        if (window.isPictureInPicture) {
          window.resizeTo(400, 300); // 可能抛出 NotAllowedError
        }
        ```
    *   **正确做法:**  确保在用户交互事件处理程序中调用这些方法，或者在调用前通过 `LocalFrame::ConsumeTransientUserActivation(GetFrame())` 检查并消耗用户激活。

4. **传递无效的 URL 给 `window.open()`:**
    *   **错误:** 如果传递给 `window.open()` 的 URL 格式不正确，会导致 `SyntaxError` 异常。
    *   **举例:**
        ```javascript
        try {
          window.open('invalid url'); // 可能会抛出 SyntaxError
        } catch (e) {
          console.error('打开窗口失败:', e);
        }
        ```

总而言之，这部分代码涵盖了 `LocalDOMWindow` 类中与窗口操作、事件处理以及一些高级浏览器功能相关的核心逻辑，这些功能是构建动态和交互式网页的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_dom_window.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
t {
  return GetSecurityOrigin()->ToString();
}

Document* LocalDOMWindow::document() const {
  return document_.Get();
}

StyleMedia* LocalDOMWindow::styleMedia() {
  if (!media_)
    media_ = MakeGarbageCollected<StyleMedia>(this);
  return media_.Get();
}

CSSStyleDeclaration* LocalDOMWindow::getComputedStyle(
    Element* elt,
    const String& pseudo_elt) const {
  DCHECK(elt);
  return MakeGarbageCollected<CSSComputedStyleDeclaration>(elt, false,
                                                           pseudo_elt);
}

double LocalDOMWindow::devicePixelRatio() const {
  if (!GetFrame())
    return 0.0;

  return GetFrame()->DevicePixelRatio();
}

void LocalDOMWindow::scrollBy(double x, double y) const {
  ScrollToOptions* options = ScrollToOptions::Create();
  options->setLeft(x);
  options->setTop(y);
  scrollBy(options);
}

void LocalDOMWindow::scrollBy(const ScrollToOptions* scroll_to_options) const {
  if (!IsCurrentlyDisplayedInFrame())
    return;

  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return;

  Page* page = GetFrame()->GetPage();
  if (!page)
    return;

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  float x = 0.0f;
  float y = 0.0f;
  if (scroll_to_options->hasLeft()) {
    x = ScrollableArea::NormalizeNonFiniteScroll(
        base::saturated_cast<float>(scroll_to_options->left()));
  }
  if (scroll_to_options->hasTop()) {
    y = ScrollableArea::NormalizeNonFiniteScroll(
        base::saturated_cast<float>(scroll_to_options->top()));
  }

  PaintLayerScrollableArea* viewport = view->LayoutViewport();
  gfx::PointF current_position = viewport->ScrollPosition();
  gfx::Vector2dF scaled_delta(x * GetFrame()->LayoutZoomFactor(),
                              y * GetFrame()->LayoutZoomFactor());
  gfx::PointF new_scaled_position = current_position + scaled_delta;

  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndAndDirection(
          current_position, scaled_delta,
          RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled());
  new_scaled_position =
      viewport->GetSnapPositionAndSetTarget(*strategy).value_or(
          new_scaled_position);

  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());
  viewport->SetScrollOffset(
      viewport->ScrollPositionToOffset(new_scaled_position),
      mojom::blink::ScrollType::kProgrammatic, scroll_behavior);
}

void LocalDOMWindow::scrollTo(double x, double y) const {
  ScrollToOptions* options = ScrollToOptions::Create();
  options->setLeft(x);
  options->setTop(y);
  scrollTo(options);
}

void LocalDOMWindow::scrollTo(const ScrollToOptions* scroll_to_options) const {
  if (!IsCurrentlyDisplayedInFrame())
    return;

  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return;

  Page* page = GetFrame()->GetPage();
  if (!page)
    return;

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidSetScrollOffset();

  // It is only necessary to have an up-to-date layout if the position may be
  // clamped, which is never the case for (0, 0).
  if (!scroll_to_options->hasLeft() || !scroll_to_options->hasTop() ||
      scroll_to_options->left() || scroll_to_options->top()) {
    document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  }

  float scaled_x = 0.0f;
  float scaled_y = 0.0f;

  PaintLayerScrollableArea* viewport = view->LayoutViewport();
  ScrollOffset current_offset = viewport->GetScrollOffset();
  scaled_x = current_offset.x();
  scaled_y = current_offset.y();

  if (scroll_to_options->hasLeft()) {
    scaled_x = ScrollableArea::NormalizeNonFiniteScroll(
                   base::saturated_cast<float>(scroll_to_options->left())) *
               GetFrame()->LayoutZoomFactor();
  }

  if (scroll_to_options->hasTop()) {
    scaled_y = ScrollableArea::NormalizeNonFiniteScroll(
                   base::saturated_cast<float>(scroll_to_options->top())) *
               GetFrame()->LayoutZoomFactor();
  }

  gfx::PointF new_scaled_position = viewport->ScrollOffsetToPosition(
      SnapScrollOffsetToPhysicalPixels(ScrollOffset(scaled_x, scaled_y)));

  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndPosition(
          new_scaled_position, scroll_to_options->hasLeft(),
          scroll_to_options->hasTop());
  new_scaled_position =
      viewport->GetSnapPositionAndSetTarget(*strategy).value_or(
          new_scaled_position);
  mojom::blink::ScrollBehavior scroll_behavior =
      ScrollableArea::V8EnumToScrollBehavior(
          scroll_to_options->behavior().AsEnum());
  viewport->SetScrollOffset(
      viewport->ScrollPositionToOffset(new_scaled_position),
      mojom::blink::ScrollType::kProgrammatic, scroll_behavior);
}

void LocalDOMWindow::moveBy(int x, int y) const {
  if (!GetFrame() || !GetFrame()->IsOutermostMainFrame() ||
      document()->IsPrerendering()) {
    return;
  }

  if (IsPictureInPictureWindow())
    return;

  LocalFrame* frame = GetFrame();
  Page* page = frame->GetPage();
  if (!page)
    return;

  gfx::Rect window_rect = page->GetChromeClient().RootWindowRect(*frame);
  window_rect.Offset(x, y);
  // Security check (the spec talks about UniversalBrowserWrite to disable this
  // check...)
  page->GetChromeClient().SetWindowRect(window_rect, *frame);
}

void LocalDOMWindow::moveTo(int x, int y) const {
  if (!GetFrame() || !GetFrame()->IsOutermostMainFrame() ||
      document()->IsPrerendering()) {
    return;
  }

  if (IsPictureInPictureWindow())
    return;

  LocalFrame* frame = GetFrame();
  Page* page = frame->GetPage();
  if (!page)
    return;

  gfx::Rect window_rect = page->GetChromeClient().RootWindowRect(*frame);
  window_rect.set_origin(gfx::Point(x, y));
  // Security check (the spec talks about UniversalBrowserWrite to disable this
  // check...)
  page->GetChromeClient().SetWindowRect(window_rect, *frame);
}

void LocalDOMWindow::resizeBy(int x,
                              int y,
                              ExceptionState& exception_state) const {
  if (!GetFrame() || !GetFrame()->IsOutermostMainFrame() ||
      document()->IsPrerendering()) {
    return;
  }

  if (IsPictureInPictureWindow()) {
    if (!LocalFrame::ConsumeTransientUserActivation(GetFrame())) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "resizeBy() requires user activation in document picture-in-picture");
      return;
    }
  }

  LocalFrame* frame = GetFrame();
  Page* page = frame->GetPage();
  if (!page)
    return;

  gfx::Rect fr = page->GetChromeClient().RootWindowRect(*frame);
  gfx::Size dest(fr.width() + x, fr.height() + y);
  gfx::Rect update(fr.origin(), dest);
  page->GetChromeClient().SetWindowRect(update, *frame);
}

void LocalDOMWindow::resizeTo(int width,
                              int height,
                              ExceptionState& exception_state) const {
  if (!GetFrame() || !GetFrame()->IsOutermostMainFrame() ||
      document()->IsPrerendering()) {
    return;
  }

  if (IsPictureInPictureWindow()) {
    if (!LocalFrame::ConsumeTransientUserActivation(GetFrame())) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "resizeTo() requires user activation in document picture-in-picture");
      return;
    }
  }

  LocalFrame* frame = GetFrame();
  Page* page = frame->GetPage();
  if (!page)
    return;

  gfx::Rect fr = page->GetChromeClient().RootWindowRect(*frame);
  gfx::Size dest = gfx::Size(width, height);
  gfx::Rect update(fr.origin(), dest);
  page->GetChromeClient().SetWindowRect(update, *frame);
}

int LocalDOMWindow::requestAnimationFrame(V8FrameRequestCallback* callback) {
  return RequestAnimationFrame(document(), callback, /*legacy=*/false);
}

int LocalDOMWindow::webkitRequestAnimationFrame(
    V8FrameRequestCallback* callback) {
  return RequestAnimationFrame(document(), callback, /*legacy=*/true);
}

void LocalDOMWindow::cancelAnimationFrame(int id) {
  document()->CancelAnimationFrame(id);
}

void LocalDOMWindow::queueMicrotask(V8VoidFunction* callback) {
  GetAgent()->event_loop()->EnqueueMicrotask(
      WTF::BindOnce(&V8VoidFunction::InvokeAndReportException,
                    WrapPersistent(callback), nullptr));
}

bool LocalDOMWindow::originAgentCluster() const {
  return GetAgent()->IsOriginKeyed();
}

CustomElementRegistry* LocalDOMWindow::customElements(
    ScriptState* script_state) const {
  if (!script_state->World().IsMainWorld())
    return nullptr;
  return customElements();
}

CustomElementRegistry* LocalDOMWindow::customElements() const {
  if (!custom_elements_ && document_) {
    custom_elements_ = MakeGarbageCollected<CustomElementRegistry>(this);
    custom_elements_->AssociatedWith(*document_);
  }
  return custom_elements_.Get();
}

CustomElementRegistry* LocalDOMWindow::MaybeCustomElements() const {
  return custom_elements_.Get();
}

External* LocalDOMWindow::external() {
  if (!external_)
    external_ = MakeGarbageCollected<External>();
  return external_.Get();
}

// NOLINTNEXTLINE(bugprone-virtual-near-miss)
bool LocalDOMWindow::isSecureContext() const {
  return IsSecureContext();
}

void LocalDOMWindow::ClearIsolatedWorldCSPForTesting(int32_t world_id) {
  isolated_world_csp_map_->erase(world_id);
}

bool IsSuddenTerminationDisablerEvent(const AtomicString& event_type) {
  return event_type == event_type_names::kUnload ||
         event_type == event_type_names::kBeforeunload ||
         event_type == event_type_names::kPagehide ||
         event_type == event_type_names::kVisibilitychange;
}

void LocalDOMWindow::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  DOMWindow::AddedEventListener(event_type, registered_listener);
  if (auto* frame = GetFrame()) {
    frame->GetEventHandlerRegistry().DidAddEventHandler(
        *this, event_type, registered_listener.Options());
  }

  document()->AddListenerTypeIfNeeded(event_type, *this);
  document()->DidAddEventListeners(/*count*/ 1);

  for (auto& it : event_listener_observers_) {
    it->DidAddEventListener(this, event_type);
  }

  if (event_type == event_type_names::kUnload) {
    CountDeprecation(WebFeature::kDocumentUnloadRegistered);
  } else if (event_type == event_type_names::kBeforeunload) {
    UseCounter::Count(this, WebFeature::kDocumentBeforeUnloadRegistered);
    if (GetFrame() && !GetFrame()->IsMainFrame())
      UseCounter::Count(this, WebFeature::kSubFrameBeforeUnloadRegistered);
  } else if (event_type == event_type_names::kPagehide) {
    UseCounter::Count(this, WebFeature::kDocumentPageHideRegistered);
  } else if (event_type == event_type_names::kPageshow) {
    UseCounter::Count(this, WebFeature::kDocumentPageShowRegistered);
  }

  if (GetFrame() && IsSuddenTerminationDisablerEvent(event_type))
    GetFrame()->AddedSuddenTerminationDisablerListener(*this, event_type);
}

void LocalDOMWindow::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  DOMWindow::RemovedEventListener(event_type, registered_listener);
  document()->DidRemoveEventListeners(/*count*/ 1);
  if (auto* frame = GetFrame()) {
    frame->GetEventHandlerRegistry().DidRemoveEventHandler(
        *this, event_type, registered_listener.Options());
  }

  for (auto& it : event_listener_observers_) {
    it->DidRemoveEventListener(this, event_type);
  }

  // Update sudden termination disabler state if we removed a listener for
  // unload/beforeunload/pagehide/visibilitychange.
  if (GetFrame() && IsSuddenTerminationDisablerEvent(event_type))
    GetFrame()->RemovedSuddenTerminationDisablerListener(*this, event_type);
}

void LocalDOMWindow::DispatchLoadEvent() {
  Event& load_event = *Event::Create(event_type_names::kLoad);
  DocumentLoader* document_loader =
      GetFrame() ? GetFrame()->Loader().GetDocumentLoader() : nullptr;
  if (document_loader &&
      document_loader->GetTiming().LoadEventStart().is_null()) {
    DocumentLoadTiming& timing = document_loader->GetTiming();
    timing.MarkLoadEventStart();
    DispatchEvent(load_event, document());
    timing.MarkLoadEventEnd();
  } else {
    DispatchEvent(load_event, document());
  }

  if (LocalFrame* frame = GetFrame()) {
    WindowPerformance* performance = DOMWindowPerformance::performance(*this);
    DCHECK(performance);
    performance->NotifyNavigationTimingToObservers();

    // For load events, send a separate load event to the enclosing frame only.
    // This is a DOM extension and is independent of bubbling/capturing rules of
    // the DOM.
    if (FrameOwner* owner = frame->Owner())
      owner->DispatchLoad();

    if (frame->IsAttached()) {
      DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
          "MarkLoad", inspector_mark_load_event::Data, frame);
      probe::LoadEventFired(frame);
      frame->GetFrameScheduler()->OnDispatchLoadEvent();
    }
  }
}

DispatchEventResult LocalDOMWindow::DispatchEvent(Event& event,
                                                  EventTarget* target) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif

  event.SetTrusted(true);
  event.SetTarget(target ? target : this);
  event.SetCurrentTarget(this);
  event.SetEventPhase(Event::PhaseType::kAtTarget);

  DEVTOOLS_TIMELINE_TRACE_EVENT("EventDispatch",
                                inspector_event_dispatch_event::Data, event,
                                GetIsolate());
  return FireEventListeners(event);
}

void LocalDOMWindow::RemoveAllEventListeners() {
  int previous_unload_handlers_count =
      NumberOfEventListeners(event_type_names::kUnload);
  int previous_before_unload_handlers_count =
      NumberOfEventListeners(event_type_names::kBeforeunload);
  int previous_page_hide_handlers_count =
      NumberOfEventListeners(event_type_names::kPagehide);
  int previous_visibility_change_handlers_count =
      NumberOfEventListeners(event_type_names::kVisibilitychange);
  if (document_ && HasEventListeners()) {
    GetEventTargetData()->event_listener_map.ForAllEventListenerTypes(
        [this](const AtomicString& event_type, uint32_t count) {
          document_->DidRemoveEventListeners(count);
        });
  }
  EventTarget::RemoveAllEventListeners();

  for (auto& it : event_listener_observers_) {
    it->DidRemoveAllEventListeners(this);
  }

  if (GetFrame()) {
    GetFrame()->GetEventHandlerRegistry().DidRemoveAllEventHandlers(*this);
  }

  // Update sudden termination disabler state if we previously have listeners
  // for unload/beforeunload/pagehide/visibilitychange.
  if (GetFrame() && previous_unload_handlers_count) {
    GetFrame()->RemovedSuddenTerminationDisablerListener(
        *this, event_type_names::kUnload);
  }
  if (GetFrame() && previous_before_unload_handlers_count) {
    GetFrame()->RemovedSuddenTerminationDisablerListener(
        *this, event_type_names::kBeforeunload);
  }
  if (GetFrame() && previous_page_hide_handlers_count) {
    GetFrame()->RemovedSuddenTerminationDisablerListener(
        *this, event_type_names::kPagehide);
  }
  if (GetFrame() && previous_visibility_change_handlers_count) {
    GetFrame()->RemovedSuddenTerminationDisablerListener(
        *this, event_type_names::kVisibilitychange);
  }
}

void LocalDOMWindow::FinishedLoading(FrameLoader::NavigationFinishState state) {
  bool was_should_print_when_finished_loading =
      should_print_when_finished_loading_;
  should_print_when_finished_loading_ = false;

  if (was_should_print_when_finished_loading &&
      state == FrameLoader::NavigationFinishState::kSuccess) {
    print(nullptr);
  }
}

void LocalDOMWindow::PrintErrorMessage(const String& message) const {
  if (!IsCurrentlyDisplayedInFrame())
    return;

  if (message.empty())
    return;

  GetFrameConsole()->AddMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kError, message));
}

DOMWindow* LocalDOMWindow::open(v8::Isolate* isolate,
                                const String& url_string,
                                const AtomicString& target,
                                const String& features,
                                ExceptionState& exception_state) {
  // Get the window script is currently executing within the context of.
  // This is usually, but not necessarily the same as 'this'.
  LocalDOMWindow* entered_window = EnteredDOMWindow(isolate);

  if (!IsCurrentlyDisplayedInFrame() || !entered_window->GetFrame()) {
    return nullptr;
  }

  // If the bindings implementation is 100% correct, the current realm and the
  // entered realm should be same origin-domain. However, to be on the safe
  // side and add some defense in depth, we'll check against the entry realm
  // as well here.
  if (!BindingSecurity::ShouldAllowAccessTo(entered_window, this)) {
    NOTREACHED();
  }

  UseCounter::Count(*entered_window, WebFeature::kDOMWindowOpen);
  entered_window->CountUseOnlyInCrossOriginIframe(
      WebFeature::kDOMWindowOpenCrossOriginIframe);
  if (!features.empty())
    UseCounter::Count(*entered_window, WebFeature::kDOMWindowOpenFeatures);

  KURL completed_url = url_string.empty()
                           ? KURL(g_empty_string)
                           : entered_window->CompleteURL(url_string);
  if (!completed_url.IsEmpty() && !completed_url.IsValid()) {
    UseCounter::Count(entered_window, WebFeature::kWindowOpenWithInvalidURL);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Unable to open a window with invalid URL '" +
            completed_url.GetString() + "'.\n");
    return nullptr;
  }

  WebWindowFeatures window_features =
      GetWindowFeaturesFromString(features, entered_window);

  if (window_features.is_partitioned_popin) {
    UseCounter::Count(*entered_window,
                      WebFeature::kPartitionedPopin_OpenAttempt);
    if (!IsFeatureEnabled(
            mojom::blink::PermissionsPolicyFeature::kPartitionedPopins,
            ReportOptions::kReportOnFailure)) {
      exception_state.ThrowSecurityError(
          "Permissions-Policy: `popin` access denied.",
          "Permissions-Policy: `popin` access denied.");
      return nullptr;
    }
    if (entered_window->GetFrame()->GetPage()->IsPartitionedPopin()) {
      exception_state.ThrowSecurityError(
          "Partitioned popins cannot open their own popin.",
          "Partitioned popins cannot open their own popin.");
      return nullptr;
    }
    if (entered_window->Url().Protocol() != WTF::g_https_atom) {
      exception_state.ThrowSecurityError(
          "Partitioned popins must be opened from https URLs.",
          "Partitioned popins must be opened from https URLs.");
      return nullptr;
    }
    // We prevent redirections via PartitionedPopinsNavigationThrottle.
    if (completed_url.Protocol() != WTF::g_https_atom) {
      exception_state.ThrowSecurityError(
          "Partitioned popins can only open https URLs.",
          "Partitioned popins can only open https URLs.");
      return nullptr;
    }
  }

  // In fenced frames, we should always use `noopener`.
  if (GetFrame()->IsInFencedFrameTree()) {
    window_features.noopener = true;
  } else if (base::FeatureList::IsEnabled(
                 features::kEnforceNoopenerOnBlobURLNavigation) &&
             completed_url.ProtocolIs("blob")) {
    auto blob_url_site =
        BlinkSchemefulSite(SecurityOrigin::Create(completed_url));
    BlinkSchemefulSite top_level_site =
        entered_window->GetStorageKey().GetTopLevelSite();
    if (top_level_site != blob_url_site) {
      window_features.noopener = true;
    }
  }

  FrameLoadRequest frame_request(entered_window,
                                 ResourceRequest(completed_url));
  frame_request.SetFeaturesForWindowOpen(window_features);

  // Normally, FrameLoader would take care of setting the referrer for a
  // navigation that is triggered from javascript. However, creating a window
  // goes through sufficient processing that it eventually enters FrameLoader as
  // an embedder-initiated navigation.  FrameLoader assumes no responsibility
  // for generating an embedder-initiated navigation's referrer, so we need to
  // ensure the proper referrer is set now.
  Referrer referrer = SecurityPolicy::GenerateReferrer(
      window_features.noreferrer ? network::mojom::ReferrerPolicy::kNever
                                 : entered_window->GetReferrerPolicy(),
      completed_url, entered_window->OutgoingReferrer());
  frame_request.GetResourceRequest().SetReferrerString(referrer.referrer);
  frame_request.GetResourceRequest().SetReferrerPolicy(
      referrer.referrer_policy);

  bool has_user_gesture = LocalFrame::HasTransientUserActivation(GetFrame());
  frame_request.GetResourceRequest().SetHasUserGesture(has_user_gesture);

  if (window_features.attribution_srcs.has_value()) {
    // An impression must be attached prior to the
    // `FindOrCreateFrameForNavigation()` call, as that call may result in
    // performing a navigation if the call results in creating a new window with
    // noopener set.
    frame_request.SetImpression(entered_window->GetFrame()
                                    ->GetAttributionSrcLoader()
                                    ->RegisterNavigation(
                                        /*navigation_url=*/completed_url,
                                        *window_features.attribution_srcs,
                                        has_user_gesture,
                                        referrer.referrer_policy));
  }

  FrameTree::FindResult result =
      GetFrame()->Tree().FindOrCreateFrameForNavigation(
          frame_request, target.empty() ? AtomicString("_blank") : target);
  if (!result.frame)
    return nullptr;

  if (window_features.x_set || window_features.y_set) {
    // This runs after FindOrCreateFrameForNavigation() so blocked popups are
    // not counted.
    UseCounter::Count(*entered_window,
                      WebFeature::kDOMWindowOpenPositioningFeatures);

    // Coarsely measure whether coordinates may be requesting another screen.
    ChromeClient& chrome_client = GetFrame()->GetChromeClient();
    const gfx::Rect screen = chrome_client.GetScreenInfo(*GetFrame()).rect;
    const gfx::Rect window(window_features.x, window_features.y,
                           window_features.width, window_features.height);
    if (!screen.Contains(window)) {
      UseCounter::Count(
          *entered_window,
          WebFeature::kDOMWindowOpenPositioningFeaturesCrossScreen);
    }
  }

#if BUILDFLAG(IS_ANDROID)
  // Popup windows are handled just like new tabs on mobile today, but we might
  // want to change that. https://crbug.com/1364321
  if (window_features.is_popup) {
    UseCounter::Count(*entered_window, WebFeature::kWindowOpenPopupOnMobile);
  }
#endif

  if (!completed_url.IsEmpty() || result.new_window)
    result.frame->Navigate(frame_request, WebFrameLoadType::kStandard);

  // TODO(japhet): window-open-noopener.html?_top and several tests in
  // html/browsers/windows/browsing-context-names/ appear to require that
  // the special case target names (_top, _parent, _self) ignore opener
  // policy (by always returning a non-null window, and by never overriding
  // the opener). The spec doesn't mention this.
  if (EqualIgnoringASCIICase(target, "_top") ||
      EqualIgnoringASCIICase(target, "_parent") ||
      EqualIgnoringASCIICase(target, "_self")) {
    return result.frame->DomWindow();
  }

  if (window_features.noopener)
    return nullptr;
  if (!result.new_window)
    result.frame->SetOpener(GetFrame());
  return result.frame->DomWindow();
}

DOMWindow* LocalDOMWindow::openPictureInPictureWindow(
    v8::Isolate* isolate,
    const WebPictureInPictureWindowOptions& options) {
  LocalDOMWindow* entered_window = EnteredDOMWindow(isolate);
  DCHECK(isSecureContext());

  if (!IsCurrentlyDisplayedInFrame() || !entered_window->GetFrame()) {
    return nullptr;
  }

  // If the bindings implementation is 100% correct, the current realm and the
  // entered realm should be same origin-domain. However, to be on the safe
  // side and add some defense in depth, we'll check against the entry realm
  // as well here.
  if (!BindingSecurity::ShouldAllowAccessTo(entered_window, this)) {
    NOTREACHED();
  }

  FrameLoadRequest frame_request(entered_window,
                                 ResourceRequest(KURL(g_empty_string)));
  frame_request.SetPictureInPictureWindowOptions(options);

  // We always create a new window here.
  FrameTree::FindResult result =
      GetFrame()->Tree().FindOrCreateFrameForNavigation(frame_request,
                                                        AtomicString("_blank"));
  if (!result.frame)
    return nullptr;

  // A new window should always be created.
  DCHECK(result.new_window);

  result.frame->Navigate(frame_request, WebFrameLoadType::kStandard);
  LocalDOMWindow* pip_dom_window =
      To<LocalDOMWindow>(result.frame->DomWindow());
  pip_dom_window->SetIsPictureInPictureWindow();

  // Ensure that we're using the same compatibility mode as the opener document.
  pip_dom_window->document()->SetCompatibilityMode(
      entered_window->document()->GetCompatibilityMode());

  // Also copy any autoplay flags, since these are set on navigation commit.
  // The pip window should match whatever the opener has.
  auto* opener_page = entered_window->document()->GetPage();
  auto* pip_page = pip_dom_window->document()->GetPage();
  CHECK(opener_page);
  CHECK(pip_page);
  pip_page->ClearAutoplayFlags();
  pip_page->AddAutoplayFlags(opener_page->AutoplayFlags());

  return pip_dom_window;
}

void LocalDOMWindow::Trace(Visitor* visitor) const {
  visitor->Trace(script_controller_);
  visitor->Trace(document_);
  visitor->Trace(screen_);
  visitor->Trace(history_);
  visitor->Trace(locationbar_);
  visitor->Trace(menubar_);
  visitor->Trace(personalbar_);
  visitor->Trace(scrollbars_);
  visitor->Trace(statusbar_);
  visitor->Trace(toolbar_);
  visitor->Trace(navigator_);
  visitor->Trace(media_);
  visitor->Trace(custom_elements_);
  visitor->Trace(external_);
  visitor->Trace(navigation_);
  visitor->Trace(viewport_);
  visitor->Trace(visualViewport_);
  visitor->Trace(event_listener_observers_);
  visitor->Trace(current_event_);
  visitor->Trace(trusted_types_map_);
  visitor->Trace(input_method_controller_);
  visitor->Trace(spell_checker_);
  visitor->Trace(text_suggestion_controller_);
  visitor->Trace(isolated_world_csp_map_);
  visitor->Trace(network_state_observer_);
  visitor->Trace(fence_);
  visitor->Trace(closewatcher_stack_);
  DOMWindow::Trace(visitor);
  ExecutionContext::Trace(visitor);
  Supplementable<LocalDOMWindow>::Trace(visitor);
}

bool LocalDOMWindow::CrossOriginIsolatedCapability() const {
  return Agent::IsCrossOriginIsolated() &&
         IsFeatureEnabled(
             mojom::blink::PermissionsPolicyFeature::kCrossOriginIsolated) &&
         GetPolicyContainer()->GetPolicies().allow_cross_origin_isolation;
}

bool LocalDOMWindow::IsIsolatedContext() const {
  return Agent::IsIsolatedContext();
}

ukm::UkmRecorder* LocalDOMWindow::UkmRecorder() {
  DCHECK(document_);
  return document_->UkmRecorder();
}

ukm::SourceId LocalDOMWindow::UkmSourceID() const {
  DCHECK(document_);
  return document_->UkmSourceID();
}

void LocalDOMWindow::SetStorageKey(const BlinkStorageKey& storage_key) {
  storage_key_ = storage_key;
}

bool LocalDOMWindow::IsPaymentRequestTokenActive() const {
  return payment_request_token_.IsActive();
}

bool LocalDOMWindow::ConsumePaymentRequestToken() {
  return payment_request_token_.ConsumeIfActive();
}

bool LocalDOMWindow::IsFullscreenRequestTokenActive() const {
  return fullscreen_request_token_.IsActive();
}

bool LocalDOMWindow::ConsumeFullscreenRequestToken() {
  return fullscreen_request_token_.ConsumeIfActive();
}

bool LocalDOMWindow::IsDisplayCaptureRequestTokenActive() const {
  return display_capture_request_token_.IsActive();
}

bool LocalDOMWindow::ConsumeDisplayCaptureRequestToken() {
  return display_capture_request_token_.ConsumeIfActive();
}

void LocalDOMWindow::SetIsInBackForwardCache(bool is_in_back_forward_cache) {
  ExecutionContext::SetIsInBackForwardCache(is_in_back_forward_cache);
  if (!is_in_back_forward_cache) {
    BackForwardCacheBufferLimitTracker::Get()
        .DidRemoveFrameOrWorkerFromBackForwardCache(
            total_bytes_buffered_while_in_back_forward_cache_);
    total_bytes_buffered_while_in_back_forward_cache_ = 0;
  }
}

void LocalDOMWindow::DidBufferLoadWhileInBackForwardCache(
    bool update_process_wide_count,
    size_t num_bytes) {
  total_bytes_buffered_while_in_back_forward_cache_ += num_bytes;
  if (update_process_wide_count) {
    BackForwardCacheBufferLimitTracker::Get().DidBufferBytes(num_bytes);
  }
}

bool LocalDOMWindow::credentialless() const {
  return GetExecutionContext()
      ->GetPolicyContainer()
      ->GetPolicies()
      .is_credentialless;
}

bool LocalDOMWindow::IsInFencedFrame() const {
  return GetFrame() && GetFrame()->IsInFencedFrameTree();
}

Fence* LocalDOMWindow::fence() {
  // Return nullptr if we aren't in a fenced subtree.
  if (!GetFrame()) {
    return nullptr;
  }
  if (!GetFrame()->IsInFencedFrameTree()) {
    // We temporarily allow window.fence in iframes with fenced frame reporting
    // metadata (navigated by urn:uuids).
    // If we are in an iframe that doesn't qualify, return nullptr.
    if (!blink::features::IsAllowURNsInIframeEnabled() ||
        !GetFrame()->GetDocument()->Loader()->FencedFrameProperties() ||
        !GetFrame()
             ->GetDocument()
             ->Loader()
             ->FencedFrameProperties()
             ->has_fenced_frame_reporting()) {
      return nullptr;
    }
  }

  if (!fence_) {
    fence_ = MakeGarbageCollected<Fence>(*this);
  }

  return fence_.Get();
}

bool LocalDOMWindow::IsPictureInPictureWindow() const {
  return is_picture_in_picture_window_;
}

void LocalDOMWindow::SetIsPictureInPictureWindow() {
  is_picture_in_picture_window_ = true;
}

net::StorageAccessApiStatus LocalDOMWindow::GetStorageAccessApiStatus() const {
  return storage_access_api_status_;
}

void LocalDOMWindow::SetStorageAccessApiStatus(
    net::StorageAccessApiStatus status) {
  CHECK_GE(status, storage_access_api_status_);
  storage_access_api_status_ = status;
}

void LocalDOMWindow::GenerateNewNavigationId() {
  navigation_id_ = WTF::CreateCanonicalUUIDString();
}

void LocalDOMWindow::SetHasBeenRevealed(bool revealed) {
  if (has_been_revealed_ == revealed)
    return;
  has_been_revealed_ = revealed;
  CHECK(document_);
  ViewTransitionSupplement::From(*document_)->DidChangeRevealState();
}

void LocalDOMWindow::UpdateEventListenerCountsToDocumentForReuseIfNeeded() {
  if (!is_dom_window_reused_) {
    return;
  }
  if (document_ && HasEventListeners()) {
    GetEventTargetData()->event_listener_map.ForAllEventListenerTypes(
        [this](const AtomicString& event_type, uint32_t count) {
          document_->AddListenerTypeIfNeeded(event_type, *this);
          document_->DidAddEventListeners(count);
        });
  }
  is_dom_window_reused_ = false;
}
}  // namespace blink

"""


```