Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/document.cc`. The code focuses on event handling and some document-level properties. I need to:

1. **List the functionalities** demonstrated in the code.
2. **Explain the relationship with JavaScript, HTML, and CSS** with examples.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs.
4. **Illustrate common user/programming errors** related to this code.
5. **Describe how a user's actions can lead to this code being executed**, acting as a debugging lead.
6. **Summarize the overall purpose** of this specific section of the `Document` class.

Let's break down the code snippet section by section:

- **`EnqueueOverscrollEvent`**:  Deals with queuing overscroll events.
- **`EnqueueScrollSnapChangeEvent` and `EnqueueScrollSnapChangingEvent`**: Handle queuing scroll snap events.
- **`EnqueueMoveEvent` and `EnqueueResizeEvent`**:  Queue window move and resize events.
- **`EnqueueMediaQueryChangeListeners`**:  Manages queuing listeners for media query changes.
- **`EnqueueVisualViewportScrollEvent`, `EnqueueVisualViewportScrollEndEvent`, `EnqueueVisualViewportResizeEvent`**: Handle visual viewport-related events.
- **`DispatchEventsForPrinting`**:  Triggers event dispatch during printing.
- **`EventFactorySet` and `RegisterEventFactory`**: Mechanisms for registering custom event factories.
- **`createEvent`**:  Creates specific event objects.
- **`AddMutationEventListenerTypeIfEnabled` and `HasListenerType`**:  Manage listeners for DOM mutations.
- **`AddListenerTypeIfNeeded`**: Adds listener types based on the event type.
- **`DidAddEventListeners` and `DidRemoveEventListeners`**: Track the number of event listeners.
- **`LocalOwner`**: Gets the owner of the document (likely an iframe).
- **`WillChangeFrameOwnerProperties`**: Handles property changes of the document's frame owner.
- **`cookie` and `setCookie`**:  Get and set document cookies.
- **`CookiesEnabled`**: Checks if cookies are enabled.
- **`SetCookieManager`**:  Sets the cookie manager.
- **`base_auction_nonce`**: Returns a nonce related to auctions.
- **`referrer`**: Gets the document's referrer.
- **`domain` and `setDomain`**: Get and set the document's domain.
- **`lastModifiedTime` and `lastModified`**: Get the last modified time of the document.
- **`TopFrameOrigin`**: Gets the security origin of the top-level frame.
- **`SiteForCookies`**: Determines the site for cookies.
- **`GetPermissionService` and `PermissionServiceConnectionError`**:  Get and handle errors for the permission service.
- **`fragmentDirective`**:  Accesses the fragment directive.
- **`hasPrivateToken` and `hasRedemptionRecord`**: Methods for interacting with Private State Tokens.
- **`TrustTokenQueryAnswererConnectionError`**: Handles errors for the Trust Token query answerer.
这是 `blink/renderer/core/dom/document.cc` 文件中关于事件处理、document 属性（如 cookie、domain、referrer）、以及一些安全和特性相关的代码片段。它的主要功能是管理和触发与文档相关的事件，并提供对某些文档属性的访问和修改能力。

以下是各项功能的详细解释：

**1. 事件队列管理与触发:**

*   **`EnqueueOverscrollEvent(Node* target, float delta_x, float delta_y)`**: 将一个 overscroll 事件添加到事件队列中。
    *   **与 JavaScript 关系:**  JavaScript 可以监听 `overscroll` 事件，当用户在滚动到达边界后继续拖动时，会触发此事件。
    *   **与 HTML 关系:**  发生在任何可滚动的 HTML 元素上，尤其是 `<body>` 或设置了滚动属性的元素。
    *   **与 CSS 关系:**  CSS 的 `overflow` 属性决定了元素是否可滚动，从而影响 overscroll 事件的触发。
    *   **假设输入与输出:**
        *   **假设输入:** 用户在滚动到文档底部后继续向下拖动鼠标。
        *   **输出:**  一个 `overscroll` 事件被创建并添加到队列中，最终 JavaScript 中注册的 `overscroll` 事件监听器会被调用。
*   **`EnqueueScrollSnapChangeEvent(Node* target, Member<Node>& block_target, Member<Node>& inline_target)` 和 `EnqueueScrollSnapChangingEvent(...)`**: 将 scroll-snap 相关的事件（`scrollsnapchange` 和 `scrollsnapchanging`）添加到队列中。
    *   **与 JavaScript 关系:** JavaScript 可以监听这些事件，以便在滚动捕捉点发生变化时做出响应。
    *   **与 HTML 关系:**  与设置了 CSS Scroll Snap Modules 属性的 HTML 元素相关。
    *   **与 CSS 关系:**  CSS Scroll Snap Modules 定义了滚动捕捉点的行为，决定了这些事件何时触发。
    *   **假设输入与输出:**
        *   **假设输入:** 用户滚动到一个定义了 scroll-snap 的容器的下一个捕捉点。
        *   **输出:**  首先触发 `scrollsnapchanging` 事件，然后在滚动停止并捕捉到新位置后触发 `scrollsnapchange` 事件。
*   **`EnqueueMoveEvent()`**: 将 `move` 事件添加到队列中，通常与窗口的移动相关。
    *   **与 JavaScript 关系:** JavaScript 可以监听 `move` 事件，当浏览器窗口移动时触发。
    *   **与 HTML 关系:**  此事件与整个文档的窗口相关。
    *   **假设输入与输出:**
        *   **假设输入:** 用户拖动浏览器窗口的标题栏并移动窗口。
        *   **输出:** 一个 `move` 事件被创建并添加到队列中，最终 JavaScript 中注册的 `move` 事件监听器会被调用。
*   **`EnqueueResizeEvent()`**: 将 `resize` 事件添加到队列中，与窗口大小的改变相关。
    *   **与 JavaScript 关系:** JavaScript 可以监听 `resize` 事件，当浏览器窗口大小改变时触发。
    *   **与 HTML 关系:**  此事件与整个文档的窗口相关。
    *   **假设输入与输出:**
        *   **假设输入:** 用户拖动浏览器窗口的边框来调整窗口大小。
        *   **输出:** 一个 `resize` 事件被创建并添加到队列中，最终 JavaScript 中注册的 `resize` 事件监听器会被调用。
*   **`EnqueueMediaQueryChangeListeners(HeapVector<Member<MediaQueryListListener>>& listeners)`**:  将媒体查询变化监听器添加到队列中，用于在媒体查询结果改变时通知。
    *   **与 JavaScript 关系:**  JavaScript 通过 `window.matchMedia()` 创建 `MediaQueryList` 对象并添加监听器。
    *   **与 HTML 关系:**  与 `<link>` 标签中的 `media` 属性或 CSS 中的 `@media` 规则相关。
    *   **与 CSS 关系:**  当 CSS 媒体查询的结果发生变化时触发。
    *   **假设输入与输出:**
        *   **假设输入:** 浏览器窗口大小改变，导致一个 CSS 媒体查询从匹配变为不匹配。
        *   **输出:**  与该媒体查询关联的监听器被添加到队列中，最终 JavaScript 中注册的回调函数会被调用。
*   **`EnqueueVisualViewportScrollEvent()`, `EnqueueVisualViewportScrollEndEvent()`, `EnqueueVisualViewportResizeEvent()`**:  处理与视觉视口相关的事件。
    *   **与 JavaScript 关系:** JavaScript 可以监听 `visualviewport` 上的 `scroll`, `scrollend`, 和 `resize` 事件。
    *   **与 HTML 关系:**  涉及到移动设备上的视口缩放和滚动。
    *   **假设输入与输出:**
        *   **假设输入:** 用户在移动设备上进行双指缩放或拖动来改变视觉视口。
        *   **输出:**  相应的 `visualviewport` 事件会被创建并添加到队列中。
*   **`DispatchEventsForPrinting()`**:  在打印过程中分发事件和回调。

**2. 事件工厂:**

*   **`EventFactorySet` 和 `RegisterEventFactory(std::unique_ptr<EventFactoryBase> event_factory)`**:  提供了一种注册自定义事件工厂的机制。这允许 Blink 扩展其支持的事件类型。
*   **`createEvent(ScriptState* script_state, const String& event_type, ExceptionState& exception_state)`**:  根据给定的事件类型创建相应的事件对象。
    *   **与 JavaScript 关系:**  对应 JavaScript 中的 `document.createEvent()` 方法。
    *   **用户/编程常见的使用错误:**  传递了不支持的 `event_type` 字符串会导致抛出 `NotSupportedError` 异常。
        *   **假设输入:** JavaScript 调用 `document.createEvent('myCustomEvent')`，但没有注册对应的事件工厂。
        *   **输出:**  `createEvent` 方法会抛出一个 `DOMException`。

**3. 事件监听器管理:**

*   **`AddMutationEventListenerTypeIfEnabled(ListenerType listener_type)`**:  添加 DOM 突变事件监听器类型，需要考虑是否启用了相关特性。
    *   **与 JavaScript 关系:**  与 `MutationObserver` 或传统的 DOM 突变事件（如 `DOMNodeInserted`）相关。
*   **`HasListenerType(ListenerType listener_type) const`**:  检查文档是否注册了特定类型的事件监听器。
*   **`AddListenerTypeIfNeeded(const AtomicString& event_type, EventTarget& event_target)`**:  根据事件类型自动添加相应的内部监听器类型。
    *   **与 JavaScript 关系:** 当 JavaScript 代码调用 `addEventListener` 注册特定类型的事件监听器时，此方法会被调用。
    *   **假设输入与输出:**
        *   **假设输入:** JavaScript 代码执行 `document.addEventListener('animationstart', ...)`。
        *   **输出:**  `AddListenerTypeIfNeeded` 方法会被调用，并可能添加 `kAnimationStartListener` 类型。
*   **`DidAddEventListeners(uint32_t count)` 和 `DidRemoveEventListeners(uint32_t count)`**:  跟踪文档上事件监听器的数量。

**4. 文档属性访问与修改:**

*   **`LocalOwner() const`**:  获取拥有当前文档的 HTMLFrameOwnerElement（通常是 `<iframe>` 元素）。
    *   **与 HTML 关系:**  用于确定当前文档是否嵌入在另一个文档中。
*   **`WillChangeFrameOwnerProperties(...)`**:  当拥有当前文档的 frame 元素的属性发生变化时被调用，例如 margin、滚动条模式等。
    *   **与 HTML 关系:**  与 `<iframe>` 或 `<frame>` 元素的属性变化相关。
*   **`cookie(ExceptionState& exception_state) const` 和 `setCookie(const String& value, ExceptionState& exception_state)`**:  获取和设置文档的 cookie。
    *   **与 JavaScript 关系:**  对应 JavaScript 中的 `document.cookie` 属性。
    *   **用户/编程常见的使用错误:**
        *   尝试在禁用 cookie 的情况下设置 cookie。
        *   尝试从安全上下文不允许访问 cookie 的文档中访问 cookie。
        *   **假设输入与输出:**
            *   **假设输入:** JavaScript 代码执行 `document.cookie = 'mycookie=value'`.
            *   **输出:** `setCookie` 方法会被调用，如果权限允许，cookie 将被设置。
*   **`CookiesEnabled() const`**:  检查文档是否允许使用 cookie。
*   **`SetCookieManager(...)`**:  设置文档的 cookie 管理器。
*   **`base_auction_nonce()`**:  获取与 Private Auction 相关的 nonce。
*   **`referrer() const`**:  获取文档的 referrer URL。
    *   **与 JavaScript 关系:**  对应 JavaScript 中的 `document.referrer` 属性。
*   **`domain() const` 和 `setDomain(const String& raw_domain, ExceptionState& exception_state)`**:  获取和设置文档的域名。
    *   **与 JavaScript 关系:**  对应 JavaScript 中的 `document.domain` 属性。
    *   **用户/编程常见的使用错误:**
        *   尝试将域名设置为当前域名的非后缀，导致安全错误。
        *   尝试在沙箱化的 iframe 中设置域名，导致安全错误。
        *   **假设输入与输出:**
            *   **假设输入:**  一个域名为 `sub.example.com` 的页面执行 `document.domain = 'example.com'`.
            *   **输出:** `setDomain` 方法会被调用，如果权限允许，域名将被设置为 `example.com`。
*   **`lastModifiedTime() const` 和 `lastModified() const`**:  获取文档的最后修改时间。
    *   **与 JavaScript 关系:**  对应 JavaScript 中的 `document.lastModified` 属性。

**5. 安全与特性相关:**

*   **`TopFrameOrigin() const`**:  获取顶层 frame 的安全源。
*   **`SiteForCookies() const`**:  确定用于 cookie 的站点。
*   **`GetPermissionService(ExecutionContext* execution_context)` 和 `PermissionServiceConnectionError()`**:  获取和处理权限服务。
*   **`fragmentDirective() const`**:  获取文档的片段指令。
*   **`hasPrivateToken(...)` 和 `hasRedemptionRecord(...)`**:  用于查询与 Private State Tokens API 相关的状态。
    *   **与 JavaScript 关系:**  对应 JavaScript 中 `document` 对象上的同名方法。
    *   **用户/编程常见的使用错误:**  传递无效的 issuer URL 会导致错误。
*   **`TrustTokenQueryAnswererConnectionError()`**:  处理 Trust Token 查询服务的连接错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **加载网页:** 当用户通过浏览器访问一个网页时，Blink 引擎会解析 HTML 并创建 `Document` 对象。
2. **用户交互:**
    *   **滚动:** 用户滚动页面可能触发 `overscroll`、`scrollsnapchange` 或视觉视口相关的事件，导致相应的 `Enqueue...Event` 方法被调用。
    *   **调整窗口大小/移动窗口:** 用户调整浏览器窗口大小或移动窗口会触发 `resize` 或 `move` 事件，调用相应的 `Enqueue...Event` 方法。
    *   **与具有 scroll-snap 的元素交互:**  用户滚动到带有 CSS scroll-snap 的元素附近，会导致 `EnqueueScrollSnapChangingEvent` 和 `EnqueueScrollSnapChangeEvent` 的调用。
3. **JavaScript 调用:**
    *   **创建事件:** JavaScript 代码调用 `document.createEvent()` 会调用 `createEvent` 方法。
    *   **添加事件监听器:**  JavaScript 代码调用 `addEventListener` 会触发 `AddListenerTypeIfNeeded` 和 `DidAddEventListeners`。
    *   **访问/设置 cookie:** JavaScript 代码访问或设置 `document.cookie` 会调用 `cookie()` 或 `setCookie()` 方法。
    *   **访问/设置 domain:** JavaScript 代码访问或设置 `document.domain` 会调用 `domain()` 或 `setDomain()` 方法。
    *   **使用 Private State Tokens API:** JavaScript 代码调用 `document.hasPrivateToken()` 或 `document.hasRedemptionRecord()`。
4. **Frame 属性变化:**  如果当前文档在一个 `<iframe>` 中，父文档或脚本对 `<iframe>` 元素的属性进行修改，可能触发 `WillChangeFrameOwnerProperties`。
5. **媒体查询变化:** 浏览器窗口大小或设备方向改变可能导致媒体查询的结果发生变化，触发 `EnqueueMediaQueryChangeListeners`。

**作为第8部分，共11部分，归纳一下它的功能:**

这部分代码主要负责 **文档的事件管理和部分核心属性的控制**。它建立了从底层事件（如鼠标滚动、窗口大小变化）到 JavaScript 可监听事件的桥梁，并提供了对一些重要的文档属性（如 cookie、domain）的编程接口。此外，它还涉及到一些现代 Web 特性（如 Scroll Snap、Visual Viewport、Private State Tokens）的支持。 这部分的功能对于构建交互式网页至关重要，因为它允许 JavaScript 代码响应用户的操作和环境变化。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共11部分，请归纳一下它的功能

"""
delta_x_ += delta_x;
  overscroll_accumulated_delta_y_ += delta_y;
  bool bubbles = target->IsDocumentNode();
  Event* overscroll_event = OverscrollEvent::Create(
      event_type_names::kOverscroll, bubbles, overscroll_accumulated_delta_x_,
      overscroll_accumulated_delta_y_);
  overscroll_event->SetTarget(target);
  scripted_animation_controller_->EnqueuePerFrameEvent(overscroll_event);
}

void Document::EnqueueScrollSnapChangeEvent(Node* target,
                                            Member<Node>& block_target,
                                            Member<Node>& inline_target) {
  Event* scrollsnapchange_event = SnapEvent::Create(
      event_type_names::kScrollsnapchange,
      (target->IsDocumentNode() ? Event::Bubbles::kYes : Event::Bubbles::kNo),
      block_target, inline_target);
  scrollsnapchange_event->SetTarget(target);
  scripted_animation_controller_->EnqueuePerFrameEvent(scrollsnapchange_event);
}

void Document::EnqueueScrollSnapChangingEvent(Node* target,
                                              Member<Node>& block_target,
                                              Member<Node>& inline_target) {
  Event* scrollsnapchanging_event = SnapEvent::Create(
      event_type_names::kScrollsnapchanging,
      (target->IsDocumentNode() ? Event::Bubbles::kYes : Event::Bubbles::kNo),
      block_target, inline_target);
  scrollsnapchanging_event->SetTarget(target);
  scripted_animation_controller_->EnqueuePerFrameEvent(
      scrollsnapchanging_event);
}

void Document::EnqueueMoveEvent() {
  CHECK(RuntimeEnabledFeatures::WindowOnMoveEventEnabled());

  Event* event = Event::Create(event_type_names::kMove);
  event->SetTarget(domWindow());
  // TODO(crbug.com/379542213): This requires spec work.
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::EnqueueResizeEvent() {
  Event* event = Event::Create(event_type_names::kResize);
  event->SetTarget(domWindow());
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::EnqueueMediaQueryChangeListeners(
    HeapVector<Member<MediaQueryListListener>>& listeners) {
  scripted_animation_controller_->EnqueueMediaQueryChangeListeners(listeners);
}

void Document::EnqueueVisualViewportScrollEvent() {
  VisualViewportScrollEvent* event =
      MakeGarbageCollected<VisualViewportScrollEvent>();
  event->SetTarget(domWindow()->visualViewport());
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::EnqueueVisualViewportScrollEndEvent() {
  VisualViewportScrollEndEvent* event =
      MakeGarbageCollected<VisualViewportScrollEndEvent>();
  event->SetTarget(domWindow()->visualViewport());
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::EnqueueVisualViewportResizeEvent() {
  VisualViewportResizeEvent* event =
      MakeGarbageCollected<VisualViewportResizeEvent>();
  event->SetTarget(domWindow()->visualViewport());
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::DispatchEventsForPrinting() {
  scripted_animation_controller_->DispatchEventsAndCallbacksForPrinting();
}

Document::EventFactorySet& Document::EventFactories() {
  DEFINE_STATIC_LOCAL(EventFactorySet, event_factory, ());
  return event_factory;
}

void Document::RegisterEventFactory(
    std::unique_ptr<EventFactoryBase> event_factory) {
  DCHECK(!EventFactories().Contains(event_factory.get()));
  EventFactories().insert(std::move(event_factory));
}

Event* Document::createEvent(ScriptState* script_state,
                             const String& event_type,
                             ExceptionState& exception_state) {
  Event* event = nullptr;
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  for (const auto& factory : EventFactories()) {
    event = factory->Create(script_state, execution_context, event_type);
    if (event) {
      // createEvent for TouchEvent should throw DOM exception if touch event
      // feature detection is not enabled. See crbug.com/392584#c22
      if (EqualIgnoringASCIICase(event_type, "TouchEvent") &&
          !RuntimeEnabledFeatures::TouchEventFeatureDetectionEnabled(
              execution_context))
        break;
      return event;
    }
  }
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNotSupportedError,
      "The provided event type ('" + event_type + "') is invalid.");
  return nullptr;
}

void Document::AddMutationEventListenerTypeIfEnabled(
    ListenerType listener_type) {
  // Mutation events can be disabled by the embedder, or via the runtime enabled
  // feature.
  if (!SupportsLegacyDOMMutations()) {
    return;
  }
  AddListenerType(listener_type);
}

bool Document::HasListenerType(ListenerType listener_type) const {
  DCHECK(!execution_context_ ||
         RuntimeEnabledFeatures::MutationEventsEnabled(execution_context_) ||
         !(listener_types_ & kDOMMutationEventListener));
  return (listener_types_ & listener_type);
}

void Document::AddListenerTypeIfNeeded(const AtomicString& event_type,
                                       EventTarget& event_target) {
  auto info = event_util::IsDOMMutationEventType(event_type);
  if (info.is_mutation_event) {
    AddMutationEventListenerTypeIfEnabled(info.listener_type);
  } else if (event_type == event_type_names::kWebkitAnimationStart ||
             event_type == event_type_names::kAnimationstart) {
    AddListenerType(kAnimationStartListener);
  } else if (event_type == event_type_names::kWebkitAnimationEnd ||
             event_type == event_type_names::kAnimationend) {
    AddListenerType(kAnimationEndListener);
  } else if (event_type == event_type_names::kWebkitAnimationIteration ||
             event_type == event_type_names::kAnimationiteration) {
    AddListenerType(kAnimationIterationListener);
    if (View()) {
      // Need to re-evaluate time-to-effect-change for any running animations.
      View()->ScheduleAnimation();
    }
  } else if (event_type == event_type_names::kAnimationcancel) {
    AddListenerType(kAnimationCancelListener);
  } else if (event_type == event_type_names::kTransitioncancel) {
    AddListenerType(kTransitionCancelListener);
  } else if (event_type == event_type_names::kTransitionrun) {
    AddListenerType(kTransitionRunListener);
  } else if (event_type == event_type_names::kTransitionstart) {
    AddListenerType(kTransitionStartListener);
  } else if (event_type == event_type_names::kWebkitTransitionEnd ||
             event_type == event_type_names::kTransitionend) {
    AddListenerType(kTransitionEndListener);
  } else if (event_type == event_type_names::kScroll) {
    AddListenerType(kScrollListener);
  } else if (event_type == event_type_names::kLoad) {
    if (Node* node = event_target.ToNode()) {
      if (IsA<HTMLStyleElement>(*node)) {
        AddListenerType(kLoadListenerAtCapturePhaseOrAtStyleElement);
        return;
      }
    }
    if (event_target.HasCapturingEventListeners(event_type))
      AddListenerType(kLoadListenerAtCapturePhaseOrAtStyleElement);
  }
}

void Document::DidAddEventListeners(uint32_t count) {
  DCHECK(count);
  event_listener_counts_ += count;
}

void Document::DidRemoveEventListeners(uint32_t count) {
  DCHECK(count);
  DCHECK_GE(event_listener_counts_, count);
  event_listener_counts_ -= count;
}

HTMLFrameOwnerElement* Document::LocalOwner() const {
  if (!GetFrame())
    return nullptr;
  // FIXME: This probably breaks the attempts to layout after a load is finished
  // in implicitClose(), and probably tons of other things...
  return GetFrame()->DeprecatedLocalOwner();
}

void Document::WillChangeFrameOwnerProperties(
    int margin_width,
    int margin_height,
    mojom::blink::ScrollbarMode scrollbar_mode,
    bool is_display_none,
    mojom::blink::ColorScheme color_scheme,
    mojom::blink::PreferredColorScheme preferred_color_scheme) {
  DCHECK(GetFrame() && GetFrame()->Owner());
  FrameOwner* owner = GetFrame()->Owner();

  if (is_display_none != owner->IsDisplayNone())
    DisplayNoneChangedForFrame();
  // body() may become null as a result of modification event listeners, so we
  // check before each call.
  if (margin_width != owner->MarginWidth()) {
    if (auto* body_element = body()) {
      body_element->SetIntegralAttribute(html_names::kMarginwidthAttr,
                                         margin_width);
    }
  }
  if (margin_height != owner->MarginHeight()) {
    if (auto* body_element = body()) {
      body_element->SetIntegralAttribute(html_names::kMarginheightAttr,
                                         margin_height);
    }
  }
  if (scrollbar_mode != owner->ScrollbarMode() && View()) {
    View()->SetCanHaveScrollbars(scrollbar_mode !=
                                 mojom::blink::ScrollbarMode::kAlwaysOff);
    View()->SetNeedsLayout();
  }
  GetStyleEngine().SetOwnerColorScheme(color_scheme, preferred_color_scheme);
}

String Document::cookie(ExceptionState& exception_state) const {
  if (!dom_window_ || !GetSettings()->GetCookieEnabled())
    return String();

  CountUse(WebFeature::kCookieGet);

  if (!dom_window_->GetSecurityOrigin()->CanAccessCookies()) {
    if (dom_window_->IsSandboxed(
            network::mojom::blink::WebSandboxFlags::kOrigin)) {
      exception_state.ThrowSecurityError(
          "The document is sandboxed and lacks the 'allow-same-origin' flag.");
    } else if (Url().ProtocolIsData()) {
      exception_state.ThrowSecurityError(
          "Cookies are disabled inside 'data:' URLs.");
    } else {
      exception_state.ThrowSecurityError("Access is denied for this document.");
    }
    return String();
  } else if (dom_window_->GetSecurityOrigin()->IsLocal()) {
    CountUse(WebFeature::kFileAccessedCookies);
  }

  return cookie_jar_->Cookies();
}

void Document::setCookie(const String& value, ExceptionState& exception_state) {
  if (!dom_window_ || !GetSettings()->GetCookieEnabled())
    return;

  UseCounter::Count(*this, WebFeature::kCookieSet);

  if (!dom_window_->GetSecurityOrigin()->CanAccessCookies()) {
    if (dom_window_->IsSandboxed(
            network::mojom::blink::WebSandboxFlags::kOrigin)) {
      exception_state.ThrowSecurityError(
          "The document is sandboxed and lacks the 'allow-same-origin' flag.");
    } else if (Url().ProtocolIsData()) {
      exception_state.ThrowSecurityError(
          "Cookies are disabled inside 'data:' URLs.");
    } else {
      exception_state.ThrowSecurityError("Access is denied for this document.");
    }
    return;
  } else if (dom_window_->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(*this, WebFeature::kFileAccessedCookies);
  }

  cookie_jar_->SetCookie(value);
}

bool Document::CookiesEnabled() const {
  if (!dom_window_)
    return false;
  // Compatible behavior in contexts that don't have cookie access.
  if (!dom_window_->GetSecurityOrigin()->CanAccessCookies())
    return true;
  return cookie_jar_->CookiesEnabled();
}

void Document::SetCookieManager(
    mojo::PendingRemote<network::mojom::blink::RestrictedCookieManager>
        cookie_manager) {
  cookie_jar_->SetCookieManager(std::move(cookie_manager));
}

const base::Uuid& Document::base_auction_nonce() {
  return base_auction_nonce_;
}

const AtomicString& Document::referrer() const {
  if (Loader())
    return Loader()->GetReferrer();
  return g_null_atom;
}

String Document::domain() const {
  return GetExecutionContext()
             ? GetExecutionContext()->GetSecurityOrigin()->Domain()
             : String();
}

void Document::setDomain(const String& raw_domain,
                         ExceptionState& exception_state) {
  UseCounter::Count(*this, WebFeature::kDocumentSetDomain);

  if (!dom_window_) {
    exception_state.ThrowSecurityError(
        "A browsing context is required to set a domain.");
    return;
  }

  if (dom_window_->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kDocumentDomain)) {
    exception_state.ThrowSecurityError(
        dom_window_->GetFrame()->IsInFencedFrameTree()
            ? "Assignment is forbidden in a fenced frame tree."
            : "Assignment is forbidden for sandboxed iframes.");
    return;
  }

  if (SchemeRegistry::IsDomainRelaxationForbiddenForURLScheme(
          dom_window_->GetSecurityOrigin()->Protocol())) {
    exception_state.ThrowSecurityError(
        "Assignment is forbidden for the '" +
        dom_window_->GetSecurityOrigin()->Protocol() + "' scheme.");
    return;
  }

  bool success = false;
  String new_domain = SecurityOrigin::CanonicalizeHost(
      raw_domain, dom_window_->GetSecurityOrigin()->Protocol(), &success);
  if (!success) {
    exception_state.ThrowSecurityError("'" + raw_domain +
                                       "' could not be parsed properly.");
    return;
  }

  if (new_domain.empty()) {
    exception_state.ThrowSecurityError("'" + new_domain +
                                       "' is an empty domain.");
    return;
  }

  scoped_refptr<SecurityOrigin> new_origin =
      dom_window_->GetSecurityOrigin()->IsolatedCopy();
  new_origin->SetDomainFromDOM(new_domain);
  OriginAccessEntry access_entry(
      *new_origin, network::mojom::CorsDomainMatchMode::kAllowSubdomains);
  network::cors::OriginAccessEntry::MatchResult result =
      access_entry.MatchesOrigin(*dom_window_->GetSecurityOrigin());
  if (result == network::cors::OriginAccessEntry::kDoesNotMatchOrigin) {
    exception_state.ThrowSecurityError(
        "'" + new_domain + "' is not a suffix of '" + domain() + "'.");
    return;
  }

  if (result ==
      network::cors::OriginAccessEntry::kMatchesOriginButIsPublicSuffix) {
    exception_state.ThrowSecurityError("'" + new_domain +
                                       "' is a top-level domain.");
    return;
  }

  // We technically only need to IsOriginKeyed(), as IsCrossOriginIsolated()
  // implies IsOriginKeyed(). (The spec only checks "is origin-keyed".) But,
  // we'll check both, in order to give warning messages that are more specific
  // about the cause. Note: this means the order of the checks is important.

  if (Agent::IsCrossOriginIsolated()) {
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kWarning,
        "document.domain mutation is ignored because the surrounding agent "
        "cluster is cross-origin isolated."));
    return;
  }

  if (RuntimeEnabledFeatures::OriginIsolationHeaderEnabled(dom_window_) &&
      dom_window_->GetAgent()->IsOriginKeyed()) {
    AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kWarning,
        "document.domain mutation is ignored because the surrounding agent "
        "cluster is origin-keyed."));
    return;
  }

  if (GetFrame()) {
    // This code should never fire for fenced frames because it should be
    // blocked by permission policy.
    DCHECK(!GetFrame()->IsInFencedFrameTree());
    UseCounter::Count(*this,
                      dom_window_->GetSecurityOrigin()->Port() == 0
                          ? WebFeature::kDocumentDomainSetWithDefaultPort
                          : WebFeature::kDocumentDomainSetWithNonDefaultPort);
    bool was_cross_origin_to_nearest_main_frame =
        GetFrame()->IsCrossOriginToNearestMainFrame();
    bool was_cross_origin_to_parent_frame =
        GetFrame()->IsCrossOriginToParentOrOuterDocument();
    SecurityOrigin* security_origin = dom_window_->GetMutableSecurityOrigin();
    security_origin->SetDomainFromDOM(new_domain);
    if (security_origin->aliased_by_document_open()) {
      UseCounter::Count(*this,
                        WebFeature::kDocumentOpenAliasedOriginDocumentDomain);
    }

    bool is_cross_origin_to_nearest_main_frame =
        GetFrame()->IsCrossOriginToNearestMainFrame();
    if (FrameScheduler* frame_scheduler = GetFrame()->GetFrameScheduler()) {
      frame_scheduler->SetCrossOriginToNearestMainFrame(
          is_cross_origin_to_nearest_main_frame);
    }
    if (View() && (was_cross_origin_to_nearest_main_frame !=
                   is_cross_origin_to_nearest_main_frame)) {
      View()->CrossOriginToNearestMainFrameChanged();
    }
    if (GetFrame()->IsMainFrame()) {
      // Notify descendants if their cross-origin-to-main-frame status changed.
      // TODO(pdr): This will notify even if
      // |Frame::IsCrossOriginToNearestMainFrame| is the same. Track whether
      // each child was cross-origin to main before and after changing the
      // domain, and only notify the changed ones.
      for (Frame* child = GetFrame()->Tree().FirstChild(); child;
           child = child->Tree().TraverseNext(GetFrame())) {
        auto* child_local_frame = DynamicTo<LocalFrame>(child);
        if (child_local_frame && child_local_frame->View())
          child_local_frame->View()->CrossOriginToNearestMainFrameChanged();
      }
    }

    if (View() && was_cross_origin_to_parent_frame !=
                      GetFrame()->IsCrossOriginToParentOrOuterDocument()) {
      View()->CrossOriginToParentFrameChanged();
    }
    // Notify all child frames if their cross-origin-to-parent status changed.
    // TODO(pdr): This will notify even if
    // |Frame::IsCrossOriginToParentOrOuterDocument| is the same. Track whether
    // each child was cross-origin-to-parent before and after changing the
    // domain, and only notify the changed ones.
    for (Frame* child = GetFrame()->Tree().FirstChild(); child;
         child = child->Tree().NextSibling()) {
      auto* child_local_frame = DynamicTo<LocalFrame>(child);
      if (child_local_frame && child_local_frame->View())
        child_local_frame->View()->CrossOriginToParentFrameChanged();
    }

    dom_window_->GetScriptController().UpdateSecurityOrigin(
        dom_window_->GetSecurityOrigin());
  }
}

std::optional<base::Time> Document::lastModifiedTime() const {
  AtomicString http_last_modified = override_last_modified_;
  if (http_last_modified.empty()) {
    if (DocumentLoader* document_loader = Loader()) {
      http_last_modified = document_loader->GetResponse().HttpHeaderField(
          http_names::kLastModified);
    }
  }
  if (!http_last_modified.empty()) {
    return ParseDate(http_last_modified, const_cast<Document&>(*this));
  }
  return std::nullopt;
}

// https://html.spec.whatwg.org/C#dom-document-lastmodified
String Document::lastModified() const {
  return String(base::UnlocalizedTimeFormatWithPattern(
      lastModifiedTime().value_or(base::Time::Now()), "MM/dd/yyyy HH:mm:ss"));
}

scoped_refptr<const SecurityOrigin> Document::TopFrameOrigin() const {
  if (!GetFrame())
    return scoped_refptr<const SecurityOrigin>();

  // If this window was opened as a new partitioned popin we need to use the
  // origin of the opener's top-frame as our top-frame.
  // See https://explainers-by-googlers.github.io/partitioned-popins/
  if (GetPage()->IsPartitionedPopin()) {
    return GetPage()->GetPartitionedPopinOpenerProperties().top_frame_origin;
  }

  return GetFrame()->Tree().Top().GetSecurityContext()->GetSecurityOrigin();
}

net::SiteForCookies Document::SiteForCookies() const {
  if (!GetFrame())
    return net::SiteForCookies();

  scoped_refptr<const SecurityOrigin> origin = TopFrameOrigin();
  // TODO(yhirano): Ideally |origin| should not be null here.
  if (!origin)
    return net::SiteForCookies();

  // Fake a 1P site for cookies for top-level documents that are rendering media
  // like images or video. We do so because when third-party cookie blocking is
  // enabled, access-controlled media cannot be rendered. We only make this
  // exception in this special case to minimize security/privacy risk.
  url::Origin url_origin = origin->ToUrlOrigin();

  if (override_site_for_cookies_for_csp_media_ && url_origin.opaque() &&
      !url_origin.GetTupleOrPrecursorTupleIfOpaque().host().empty()) {
    return net::SiteForCookies::FromOrigin(url::Origin::Create(
        url_origin.GetTupleOrPrecursorTupleIfOpaque().GetURL()));
  }

  net::SiteForCookies candidate = net::SiteForCookies::FromOrigin(url_origin);

  // If true, CompareWithFrameTreeOriginAndRevise() is skipped if the
  // SecurityOrigin of the the frames is the same. If any frame has a different
  // SecurityOrigin, then this is set to false so that
  // CompareWithFrameTreeOriginAndRevise() is called for all remaining frames.
  bool can_avoid_revise_if_security_origins_match = true;

  // If this window was opened as a new partitioned popin we need to use the
  // site for cookies of the opener as our initial candidate.
  // See https://explainers-by-googlers.github.io/partitioned-popins/
  if (GetPage()->IsPartitionedPopin()) {
    candidate =
        GetPage()->GetPartitionedPopinOpenerProperties().site_for_cookies;
    // We can only skip comparisons when using the SiteForCookies from the
    // top frame. Because we reset `candidate`, we need to call
    // CompareWithFrameTreeOriginAndRevise() regardless of whether a frame
    // has the same SecurityOrigin as the top frame.
    can_avoid_revise_if_security_origins_match = false;
  }

  if (SchemeRegistry::ShouldTreatURLSchemeAsFirstPartyWhenTopLevel(
          origin->Protocol())) {
    return candidate;
  }

  const Frame* current_frame = GetFrame();
  if (SchemeRegistry::
          ShouldTreatURLSchemeAsFirstPartyWhenTopLevelEmbeddingSecure(
              origin->Protocol(), current_frame->GetSecurityContext()
                                      ->GetSecurityOrigin()
                                      ->Protocol())) {
    return candidate;
  }

  while (current_frame) {
    const SecurityOrigin* current_frame_security_origin =
        current_frame->GetSecurityContext()->GetSecurityOrigin();
    // If possible, skip revising frames that have the same security origin.
    if (!can_avoid_revise_if_security_origins_match ||
        current_frame_security_origin != origin) {
      if (!candidate.CompareWithFrameTreeOriginAndRevise(
              current_frame_security_origin->ToUrlOrigin())) {
        return candidate;
      }
      can_avoid_revise_if_security_origins_match = false;
    }
    current_frame = current_frame->Tree().Parent();
  }

  return candidate;
}

mojom::blink::PermissionService* Document::GetPermissionService(
    ExecutionContext* execution_context) {
  if (!data_->permission_service_.is_bound()) {
    execution_context->GetBrowserInterfaceBroker().GetInterface(
        data_->permission_service_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kPermission)));
    data_->permission_service_.set_disconnect_handler(WTF::BindOnce(
        &Document::PermissionServiceConnectionError, WrapWeakPersistent(this)));
  }
  return data_->permission_service_.get();
}

void Document::PermissionServiceConnectionError() {
  data_->permission_service_.reset();
}

FragmentDirective& Document::fragmentDirective() const {
  return *fragment_directive_;
}

ScriptPromise<IDLBoolean> Document::hasPrivateToken(
    ScriptState* script_state,
    const String& issuer,
    ExceptionState& exception_state) {
  // Private State Tokens state is keyed by issuer and top-frame origins that
  // are both (1) HTTP or HTTPS and (2) potentially trustworthy. Consequently,
  // we can return early if either the issuer or the top-frame origin fails to
  // satisfy either of these requirements.
  KURL issuer_url = KURL(issuer);
  auto issuer_origin = SecurityOrigin::Create(issuer_url);
  if (!issuer_url.ProtocolIsInHTTPFamily() ||
      !issuer_origin->IsPotentiallyTrustworthy()) {
    exception_state.ThrowTypeError(
        "hasPrivateToken: Private Token issuer origins must be both HTTP(S) "
        "and secure (\"potentially trustworthy\").");
    return EmptyPromise();
  }

  scoped_refptr<const SecurityOrigin> top_frame_origin = TopFrameOrigin();
  if (!top_frame_origin) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "hasPrivateToken: Cannot execute in "
                                      "documents lacking top-frame origins.");
    return EmptyPromise();
  }

  DCHECK(top_frame_origin->IsPotentiallyTrustworthy());
  if (top_frame_origin->Protocol() != url::kHttpsScheme &&
      top_frame_origin->Protocol() != url::kHttpScheme) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "hasPrivateToken: Cannot execute in "
        "documents without secure, HTTP(S), top-frame origins.");
    return EmptyPromise();
  }

  if (!data_->trust_token_query_answerer_.is_bound()) {
    GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        data_->trust_token_query_answerer_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault)));
    data_->trust_token_query_answerer_.set_disconnect_handler(
        WTF::BindOnce(&Document::TrustTokenQueryAnswererConnectionError,
                      WrapWeakPersistent(this)));
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  data_->pending_trust_token_query_resolvers_.insert(resolver);

  data_->trust_token_query_answerer_->HasTrustTokens(
      issuer_origin,
      WTF::BindOnce(
          [](WeakPersistent<ScriptPromiseResolver<IDLBoolean>> resolver,
             WeakPersistent<Document> document,
             network::mojom::blink::HasTrustTokensResultPtr result) {
            // If there was a Mojo connection error, the promise was already
            // resolved and deleted.
            if (!base::Contains(
                    document->data_->pending_trust_token_query_resolvers_,
                    resolver)) {
              return;
            }

            switch (result->status) {
              case network::mojom::blink::TrustTokenOperationStatus::kOk: {
                resolver->Resolve(result->has_trust_tokens);
                break;
              }
              case network::mojom::blink::TrustTokenOperationStatus::
                  kInvalidArgument: {
                ScriptState* state = resolver->GetScriptState();
                ScriptState::Scope scope(state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    state->GetIsolate(), DOMExceptionCode::kOperationError,
                    "Failed to retrieve hasPrivateToken response. Issuer "
                    "configuration is missing or unsuitable."));
                break;
              }
              case network::mojom::blink::TrustTokenOperationStatus::
                  kResourceExhausted: {
                ScriptState* state = resolver->GetScriptState();
                ScriptState::Scope scope(state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    state->GetIsolate(), DOMExceptionCode::kOperationError,
                    "Failed to retrieve hasPrivateToken response. Exceeded the "
                    "number-of-issuers limit."));
                break;
              }
              default: {
                ScriptState* state = resolver->GetScriptState();
                ScriptState::Scope scope(state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    state->GetIsolate(), DOMExceptionCode::kOperationError,
                    "Failed to retrieve hasPrivateToken response."));
              }
            }

            document->data_->pending_trust_token_query_resolvers_.erase(
                resolver);
          },
          WrapWeakPersistent(resolver), WrapWeakPersistent(this)));

  return resolver->Promise();
}

ScriptPromise<IDLBoolean> Document::hasRedemptionRecord(
    ScriptState* script_state,
    const String& issuer,
    ExceptionState& exception_state) {
  // Private State Tokens state is keyed by issuer and top-frame origins that
  // are both (1) HTTP or HTTPS and (2) potentially trustworthy. Consequently,
  // we can return early if either the issuer or the top-frame origin fails to
  // satisfy either of these requirements.
  KURL issuer_url = KURL(issuer);
  auto issuer_origin = SecurityOrigin::Create(issuer_url);
  if (!issuer_url.ProtocolIsInHTTPFamily() ||
      !issuer_origin->IsPotentiallyTrustworthy()) {
    exception_state.ThrowTypeError(
        "hasRedemptionRecord: Private Token issuer origins must be both "
        "HTTP(S) and secure (\"potentially trustworthy\").");
    return EmptyPromise();
  }

  scoped_refptr<const SecurityOrigin> top_frame_origin = TopFrameOrigin();
  if (!top_frame_origin) {
    // Note: One case where there might be no top frame origin is if this
    // document is destroyed. In this case, this function will return
    // `undefined`. Still bother adding the exception and rejecting, just in
    // case there are other situations in which the top frame origin might be
    // absent.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "hasRedemptionRecord: Cannot execute in "
                                      "documents lacking top-frame origins.");
    return EmptyPromise();
  }

  DCHECK(top_frame_origin->IsPotentiallyTrustworthy());
  if (top_frame_origin->Protocol() != url::kHttpsScheme &&
      top_frame_origin->Protocol() != url::kHttpScheme) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "hasRedemptionRecord: Cannot execute in "
        "documents without secure, HTTP(S), top-frame origins.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  if (!data_->trust_token_query_answerer_.is_bound()) {
    GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        data_->trust_token_query_answerer_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault)));
    data_->trust_token_query_answerer_.set_disconnect_handler(
        WTF::BindOnce(&Document::TrustTokenQueryAnswererConnectionError,
                      WrapWeakPersistent(this)));
  }

  data_->pending_trust_token_query_resolvers_.insert(resolver);

  data_->trust_token_query_answerer_->HasRedemptionRecord(
      issuer_origin,
      WTF::BindOnce(
          [](WeakPersistent<ScriptPromiseResolver<IDLBoolean>> resolver,
             WeakPersistent<Document> document,
             network::mojom::blink::HasRedemptionRecordResultPtr result) {
            // If there was a Mojo connection error, the promise was already
            // resolved and deleted.
            if (!base::Contains(
                    document->data_->pending_trust_token_query_resolvers_,
                    resolver)) {
              return;
            }

            switch (result->status) {
              case network::mojom::blink::TrustTokenOperationStatus::kOk: {
                resolver->Resolve(result->has_redemption_record);
                break;
              }
              case network::mojom::blink::TrustTokenOperationStatus::
                  kInvalidArgument: {
                ScriptState* state = resolver->GetScriptState();
                ScriptState::Scope scope(state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    state->GetIsolate(), DOMExceptionCode::kOperationError,
                    "Failed to retrieve hasRedemptionRecord response. Issuer "
                    "configuration is missing or unsuitable."));
                break;
              }
              default: {
                ScriptState* state = resolver->GetScriptState();
                ScriptState::Scope scope(state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    state->GetIsolate(), DOMExceptionCode::kOperationError,
                    "Failed to retrieve hasRedemptionRecord response."));
              }
            }

            document->data_->pending_trust_token_query_resolvers_.erase(
                resolver);
          },
          WrapWeakPersistent(resolver), WrapWeakPersistent(this)));

  return promise;
}

void Document::TrustTokenQueryAnswererConnectionError() {
  data_->trust_token_query_answerer_.reset();
  for (const auto& resolver : data_->pending_trust_token_query_resolvers_) {
    ScriptState* state = resolver->GetScriptState();
    ScriptState::Scope scope(state);
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        state->GetIsolate(), DOMExceptionCode::kOperationError,
        "Internal error retrieving trust token response."));
  }
  data_->pending_trust_token_query_resolvers_.clear();
}

void Document::ari
"""


```