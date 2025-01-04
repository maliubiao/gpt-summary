Response:
Let's break down the thought process for analyzing this C++ Chromium source code.

1. **Initial Understanding - The Big Picture:**  The filename `presentation_request.cc` immediately suggests this code is about initiating presentation sessions, likely related to features like casting or displaying content on external screens. The `#include` directives confirm this, referencing `presentation_connection.h`, `presentation_availability_state.h`, etc. The `blink` namespace confirms this is part of the Blink rendering engine.

2. **Core Functionality - Identifying Key Methods:** The `PresentationRequest` class name is a strong indicator of the primary purpose. I look for public methods, especially static `Create` methods (constructors) and methods that seem to perform actions. `start()`, `reconnect()`, and `getAvailability()` stand out. These clearly represent the main actions a `PresentationRequest` object can perform.

3. **Dissecting Key Methods - Understanding the Logic:**  I go through each key method, line by line, paying attention to:
    * **Parameters:** What information does the method need?  This gives clues about how it's used. For example, `start()` takes a `ScriptState`, implying it's called from JavaScript. `reconnect()` takes an `id`, suggesting the concept of persistent presentation sessions.
    * **Return Type:** What does the method produce? `ScriptPromise<PresentationConnection>` indicates asynchronous operations returning a connection object. `ScriptPromise<PresentationAvailability>` hints at querying the status of presentation capabilities.
    * **Key Operations:** What are the major actions happening inside the method?  Look for calls to other classes/objects (like `PresentationController`, `PresentationService`, `AvailabilityState`). This reveals the dependencies and how different parts of the system interact.
    * **Error Handling:**  Are there `ExceptionState` parameters and `ThrowDOMException` calls? This indicates how errors are reported to the JavaScript side. Security checks (like the sandbox check) are also important.
    * **Assumptions and Conditions:** Are there `if` statements or checks on input values? This reveals preconditions for the method to work correctly. The user gesture check in `start()` is a prime example.

4. **Connecting to Web Technologies - JavaScript, HTML, CSS:**  Since this is part of a web browser engine, the interaction with web technologies is crucial.
    * **JavaScript:** The use of `ScriptPromise` strongly suggests interaction with JavaScript's Promise API. The method names (`start`, `reconnect`, `getAvailability`) map directly to methods in the JavaScript Presentation API.
    * **HTML:** While this specific file doesn't directly manipulate HTML, the *purpose* of presentation is to display web content, so the link is there. The code checks for sandbox flags, which are attributes on `<iframe>` elements.
    * **CSS:**  Less direct connection here, but the presentation experience *can* be styled with CSS on the presenting screen.

5. **Logical Reasoning - Hypothetical Scenarios:**  To understand the flow, I imagine simple scenarios:
    * **Starting a presentation:** A website calls `navigator.presentation.request.start(...)`. This triggers the `PresentationRequest::start()` method. What happens? A promise is created, the `PresentationController` is involved, and a request is sent to the presentation service.
    * **Checking availability:** A website calls `navigator.presentation.request.getAvailability()`. This leads to `PresentationRequest::getAvailability()`. The code checks existing availability, and if unknown, makes a request.

6. **User and Programming Errors:**  I consider common mistakes developers might make when using the Presentation API:
    * **Incorrect URLs:**  Providing invalid or unresolvable URLs.
    * **Security issues:**  Trying to present insecure content from a secure context.
    * **User gesture requirement:** Calling `start()` without a user interaction.
    * **Sandbox restrictions:**  Using the API in a sandboxed iframe without the correct permissions.

7. **Debugging Clues - Tracing the User Journey:**  To understand how a user reaches this code, I think about the typical user interaction:
    * User visits a website.
    * The website uses JavaScript to call the Presentation API.
    * This JavaScript call eventually leads to the creation and use of a `PresentationRequest` object in the Blink engine. I try to map the JavaScript API calls to the corresponding C++ methods.

8. **Structure and Organization:** I note the use of namespaces, helper functions (`IsKnownProtocolForPresentationUrl`, `CreateMirroringUrl`, `CreateUrlFromSource`), and the separation of concerns (e.g., the `PresentationController` handles higher-level logic).

9. **Refinement and Review:** After the initial analysis, I review my understanding, check for inconsistencies, and refine the explanations to be clear and concise. I ensure that the examples are relevant and illustrate the key points. For instance, initially, I might just say "it handles errors," but I refine that to mention specific error types like `DOMExceptionCode::kSyntaxError`.

This systematic approach, moving from the general to the specific, and constantly connecting the code back to its purpose and the web technologies it interacts with, allows for a comprehensive understanding of the given source file.
这个文件 `blink/renderer/modules/presentation/presentation_request.cc` 是 Chromium Blink 渲染引擎中负责处理 **Presentation API** 中 `PresentationRequest` 接口的具体实现。`PresentationRequest` 对象允许网页发起和管理与演示显示设备的连接。

以下是该文件的主要功能：

1. **创建 `PresentationRequest` 对象:**
   - 提供静态方法 `Create()` 来创建 `PresentationRequest` 实例。
   - 接受一个或多个表示演示 URL 的字符串或 `PresentationSource` 对象作为参数。
   - 对传入的 URL 进行验证，包括 URL 的有效性、协议是否支持、以及是否在安全上下文中尝试演示不安全的内容。
   - 检查当前执行上下文是否被沙箱化，并缺少 `allow-presentation` 标志。

2. **发起演示会话 (`start()`):**
   - 提供 `start()` 方法，该方法返回一个 `Promise`，最终会 resolve 为一个 `PresentationConnection` 对象，表示与演示设备的连接。
   - 在调用 `start()` 之前，会检查是否需要用户手势才能发起演示（由浏览器设置控制）。
   - 调用 `PresentationController` 来请求启动演示会话。

3. **重新连接到已存在的演示会话 (`reconnect()`):**
   - 提供 `reconnect()` 方法，允许网页尝试重新连接到之前创建的演示会话。
   - 接收一个表示会话 ID 的字符串作为参数。
   - 查找是否存在具有给定 URL 和 ID 的现有连接，如果存在则尝试重新连接到该连接。否则，会尝试创建一个新的连接。

4. **获取演示设备的可用性 (`getAvailability()`):**
   - 提供 `getAvailability()` 方法，返回一个 `Promise`，最终会 resolve 为一个 `PresentationAvailability` 对象，表示演示设备对指定 URL 的可用性。
   - 调用 `PresentationController` 来获取或请求演示设备的可用性状态。
   - 如果可用性状态未知，则会发起一个请求，并在状态更新时 resolve Promise。

5. **事件处理:**
   - 继承自 `EventTarget`，允许 `PresentationRequest` 对象监听事件，例如 `connectionavailable`，当有可用的演示连接时触发。

6. **URL 管理:**
   - 存储用于演示的 URL 列表。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`PresentationRequest` 是一个 JavaScript API，因此与 JavaScript 有直接关系。HTML 通过 `<script>` 标签引入 JavaScript，从而间接与 `PresentationRequest` 相关。CSS 则主要负责样式，与 `PresentationRequest` 的逻辑功能关系较小。

**JavaScript 举例:**

```javascript
// 获取 PresentationRequest 对象，传入一个演示 URL
const presentationRequest = new PresentationRequest('https://example.com/presentation');

// 监听 connectionavailable 事件
presentationRequest.addEventListener('connectionavailable', event => {
  console.log('有可用的演示连接！', event.connection);
});

// 发起演示会话
presentationRequest.start()
  .then(connection => {
    console.log('演示连接已建立！', connection);
    // 在连接上发送消息
    connection.send('Hello from the web page!');
  })
  .catch(error => {
    console.error('启动演示失败：', error);
  });

// 获取演示设备的可用性
presentationRequest.getAvailability()
  .then(availability => {
    console.log('演示设备可用性：', availability.value);
    availability.onchange = () => {
      console.log('演示设备可用性已更改：', availability.value);
    };
  });

// 尝试重新连接到之前的会话
presentationRequest.reconnect('previous-session-id')
  .then(connection => {
    console.log('成功重新连接到演示会话！', connection);
  })
  .catch(error => {
    console.error('重新连接演示会话失败：', error);
  });
```

**HTML 举例:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Presentation API Example</title>
</head>
<body>
  <button id="startButton">开始演示</button>
  <script>
    const startButton = document.getElementById('startButton');
    startButton.addEventListener('click', () => {
      const presentationRequest = new PresentationRequest('https://example.com/presentation');
      presentationRequest.start()
        .then(connection => {
          console.log('演示连接已建立！', connection);
        })
        .catch(error => {
          console.error('启动演示失败：', error);
        });
    });
  </script>
</body>
</html>
```

**CSS 举例 (间接关系):**

CSS 可以用来美化网页上的按钮，用户点击按钮触发 JavaScript 代码，最终调用 `PresentationRequest` 的方法。例如：

```css
#startButton {
  padding: 10px 20px;
  background-color: #4CAF50;
  color: white;
  border: none;
  cursor: pointer;
}
```

**逻辑推理 - 假设输入与输出:**

**假设输入 (JavaScript):**

```javascript
const presentationRequest = new PresentationRequest(['https://projector1.example.com', 'https://projector2.example.com']);
presentationRequest.start();
```

**可能输出 (取决于演示设备和浏览器实现):**

- **成功:** `start()` 方法返回的 Promise resolve，并带有一个 `PresentationConnection` 对象，该对象代表与 `projector1.example.com` 或 `projector2.example.com` 其中一个设备的成功连接。
- **失败 (例如，没有可用的演示设备):** `start()` 方法返回的 Promise reject，并带有一个 `DOMException`，可能带有 `NotSupportedError` 或 `NotFoundError` 等错误码。
- **用户取消:** 如果用户在浏览器提供的选择演示设备的界面中取消了操作，`start()` 方法返回的 Promise 可能会 reject，也可能不会有任何反应（取决于具体实现）。

**涉及用户或编程常见的使用错误及举例说明:**

1. **在不安全的上下文中尝试演示安全的 URL:**

   ```javascript
   // 在一个 HTTP 页面上尝试演示 HTTPS 的 URL
   const presentationRequest = new PresentationRequest('https://secure.example.com/presentation');
   presentationRequest.start(); // 可能会抛出 SecurityError
   ```

2. **在没有用户手势的情况下调用 `start()` (如果浏览器要求):**

   ```javascript
   // 页面加载后立即调用，没有用户点击按钮等操作
   const presentationRequest = new PresentationRequest('https://example.com/presentation');
   presentationRequest.start(); // 可能会抛出 InvalidAccessError
   ```

3. **提供无效的演示 URL:**

   ```javascript
   const presentationRequest = new PresentationRequest('invalid-url');
   presentationRequest.start(); // 可能会抛出 SyntaxError 或导致后续操作失败
   ```

4. **在沙箱化的 iframe 中使用 `PresentationRequest` 但缺少 `allow-presentation` 标志:**

   ```html
   <iframe sandbox="allow-scripts" src="..."></iframe>
   ```

   ```javascript
   // 在上述 iframe 中执行
   const presentationRequest = new PresentationRequest('https://example.com/presentation');
   presentationRequest.start(); // 可能会抛出 SecurityError
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个网页:** 用户在浏览器中输入网址或点击链接访问一个包含 Presentation API 代码的网页。
2. **网页加载并执行 JavaScript:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 代码创建 `PresentationRequest` 对象:** JavaScript 代码使用 `new PresentationRequest(urls)` 创建一个 `PresentationRequest` 实例，指定了目标演示设备的 URL。
4. **JavaScript 代码调用 `presentationRequest.start()`:** 网页上的某个事件（例如用户点击按钮）触发 JavaScript 代码调用 `start()` 方法。
5. **浏览器内部调用 Blink 引擎的 C++ 代码:**
   - JavaScript 的 `start()` 方法调用会通过 Blink 的绑定机制（例如 V8 绑定）映射到 `blink::PresentationRequest::start()` 方法。
   - 在 `start()` 方法内部，会检查用户手势、调用 `PresentationController` 来发起演示会话。
6. **`PresentationController` 与底层平台交互:** `PresentationController` 进一步与操作系统或浏览器提供的演示服务进行通信，搜索可用的演示设备。
7. **（如果成功）建立连接并返回 `PresentationConnection` 对象:** 如果找到可用的设备并且用户允许连接，则会建立连接，并创建一个 `PresentationConnection` 对象返回给 JavaScript。
8. **（如果失败）返回错误:** 如果启动演示失败（例如，没有可用的设备，用户取消），则 `start()` 方法返回的 Promise 会 reject，并将错误信息传递回 JavaScript。

**调试线索:**

- **查看浏览器的开发者工具的 Console 面板:** 可以查看 JavaScript 代码的输出，包括 `console.log` 打印的连接信息或错误信息。
- **使用浏览器的断点调试功能:** 在 JavaScript 代码中设置断点，逐步执行代码，查看 `PresentationRequest` 对象的状态和 `start()` 方法的返回值。
- **检查浏览器的 Presentation API 设置:** 某些浏览器可能允许用户管理或查看演示设备的连接状态。
- **查看浏览器的内部日志 (chrome://webrtc-internals/):**  虽然不直接关联到 `PresentationRequest.cc`，但可以提供关于 WebRTC 连接的底层信息，这可能与某些类型的演示实现相关。
- **在 `blink/renderer/modules/presentation/presentation_request.cc` 中添加日志:**  为了深入了解 Blink 引擎内部的执行流程，可以在关键方法中添加 `DLOG` 或 `DVLOG` 输出，以便在 Chromium 的调试版本中查看日志信息。例如，可以在 `PresentationRequest::start()` 的开头和结尾添加日志，查看该方法是否被调用以及执行结果。
- **检查网络请求:** 如果演示涉及到加载远程资源，可以查看浏览器的 Network 面板，确认资源是否加载成功。

Prompt: 
```
这是目录为blink/renderer/modules/presentation/presentation_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/presentation/presentation_request.h"

#include <memory>

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capture_latency.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_presentation_source.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_presentationsource_usvstring.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/presentation/presentation_availability_state.h"
#include "third_party/blink/renderer/modules/presentation/presentation_connection.h"
#include "third_party/blink/renderer/modules/presentation/presentation_connection_callbacks.h"
#include "third_party/blink/renderer/modules/presentation/presentation_controller.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

bool IsKnownProtocolForPresentationUrl(const KURL& url) {
  return url.ProtocolIsInHTTPFamily() || url.ProtocolIs("cast") ||
         url.ProtocolIs("cast-dial");
}

int GetPlayoutDelay(const PresentationSource& source) {
  if (!source.hasLatencyHint() || !source.latencyHint()) {
    return 400;
  }
  switch (source.latencyHint()->AsEnum()) {
    case V8CaptureLatency::Enum::kLow:
      return 200;
    case V8CaptureLatency::Enum::kDefault:
      return 400;
    case V8CaptureLatency::Enum::kHigh:
      return 800;
  }
}

KURL CreateMirroringUrl(const PresentationSource& source) {
  int capture_audio = !source.hasAudioPlayback() || !source.audioPlayback() ||
                              (source.audioPlayback()->AsEnum() ==
                               V8AudioPlaybackDestination::Enum::kReceiver)
                          ? 1
                          : 0;
  int playout_delay = GetPlayoutDelay(source);
  // TODO(crbug.com/1267372): Instead of converting a mirroring source into a
  // URL with a hardcoded Cast receiver app ID, pass the source object directly
  // to the embedder.
  return KURL(
      String::Format("cast:0F5096E8?streamingCaptureAudio=%d&"
                     "streamingTargetPlayoutDelayMillis=%d",
                     capture_audio, playout_delay));
}

KURL CreateUrlFromSource(const ExecutionContext& execution_context,
                         const PresentationSource& source) {
  if (!source.hasType()) {
    return KURL();
  }
  switch (source.type().AsEnum()) {
    case V8PresentationSourceType::Enum::kUrl:
      return source.hasUrl() ? KURL(execution_context.Url(), source.url())
                             : KURL();
    case V8PresentationSourceType::Enum::kMirroring:
      return CreateMirroringUrl(source);
  }
}

}  // anonymous namespace

// static
PresentationRequest* PresentationRequest::Create(
    ExecutionContext* execution_context,
    const String& url,
    ExceptionState& exception_state) {
  HeapVector<Member<V8UnionPresentationSourceOrUSVString>> urls(1);
  urls[0] = MakeGarbageCollected<V8UnionPresentationSourceOrUSVString>(url);
  return Create(execution_context, urls, exception_state);
}

// static
PresentationRequest* PresentationRequest::Create(
    ExecutionContext* execution_context,
    const HeapVector<Member<V8UnionPresentationSourceOrUSVString>>& sources,
    ExceptionState& exception_state) {
  if (execution_context->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kPresentationController)) {
    exception_state.ThrowSecurityError(
        DynamicTo<LocalDOMWindow>(execution_context)
                ->GetFrame()
                ->IsInFencedFrameTree()
            ? "PresentationRequest is not supported in a fenced frame tree."
            : "The document is sandboxed and lacks the 'allow-presentation' "
              "flag.");
    return nullptr;
  }

  Vector<KURL> parsed_urls;
  for (const auto& source : sources) {
    if (source->IsPresentationSource()) {
      if (!RuntimeEnabledFeatures::SiteInitiatedMirroringEnabled()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kNotSupportedError,
            "You must pass in valid URL strings.");
        return nullptr;
      }
      const KURL source_url = CreateUrlFromSource(
          *execution_context, *source->GetAsPresentationSource());
      if (!source_url.IsValid()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kNotSupportedError,
            "You must pass in valid presentation sources.");
        return nullptr;
      }
      parsed_urls.push_back(source_url);
      continue;
    }
    DCHECK(source->IsUSVString());
    const String& url = source->GetAsUSVString();
    const KURL& parsed_url = KURL(execution_context->Url(), url);

    if (!parsed_url.IsValid()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "'" + url + "' can't be resolved to a valid URL.");
      return nullptr;
    }

    if (parsed_url.ProtocolIsInHTTPFamily() &&
        MixedContentChecker::IsMixedContent(
            execution_context->GetSecurityOrigin(), parsed_url)) {
      exception_state.ThrowSecurityError(
          "Presentation of an insecure document [" + url +
          "] is prohibited from a secure context.");
      return nullptr;
    }

    if (IsKnownProtocolForPresentationUrl(parsed_url)) {
      parsed_urls.push_back(parsed_url);
    }
  }

  if (parsed_urls.empty()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "An empty sequence of URLs is not supported.");
    return nullptr;
  }

  return MakeGarbageCollected<PresentationRequest>(execution_context,
                                                   parsed_urls);
}

const AtomicString& PresentationRequest::InterfaceName() const {
  return event_target_names::kPresentationRequest;
}

ExecutionContext* PresentationRequest::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

void PresentationRequest::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  if (event_type == event_type_names::kConnectionavailable) {
    UseCounter::Count(
        GetExecutionContext(),
        WebFeature::kPresentationRequestConnectionAvailableEventListener);
  }
}

bool PresentationRequest::HasPendingActivity() const {
  // Prevents garbage collecting of this object when not hold by another
  // object but still has listeners registered.
  if (!GetExecutionContext()) {
    return false;
  }

  return HasEventListeners();
}

ScriptPromise<PresentationConnection> PresentationRequest::start(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The PresentationRequest is no longer associated to a frame.");
    return EmptyPromise();
  }

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  if (window->GetFrame()->GetSettings()->GetPresentationRequiresUserGesture() &&
      !LocalFrame::HasTransientUserActivation(window->GetFrame())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "PresentationRequest::start() requires user gesture.");
    return EmptyPromise();
  }

  PresentationController* controller = PresentationController::From(*window);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationConnection>>(
          script_state, exception_state.GetContext());

  controller->GetPresentationService()->StartPresentation(
      urls_,
      WTF::BindOnce(
          &PresentationConnectionCallbacks::HandlePresentationResponse,
          std::make_unique<PresentationConnectionCallbacks>(resolver, this)));
  return resolver->Promise();
}

ScriptPromise<PresentationConnection> PresentationRequest::reconnect(
    ScriptState* script_state,
    const String& id,
    ExceptionState& exception_state) {
  PresentationController* controller =
      PresentationController::FromContext(GetExecutionContext());
  if (!controller) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The PresentationRequest is no longer associated to a frame.");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationConnection>>(
          script_state, exception_state.GetContext());

  ControllerPresentationConnection* existing_connection =
      controller->FindExistingConnection(urls_, id);
  if (existing_connection) {
    controller->GetPresentationService()->ReconnectPresentation(
        urls_, id,
        WTF::BindOnce(
            &PresentationConnectionCallbacks::HandlePresentationResponse,
            std::make_unique<PresentationConnectionCallbacks>(
                resolver, existing_connection)));
  } else {
    controller->GetPresentationService()->ReconnectPresentation(
        urls_, id,
        WTF::BindOnce(
            &PresentationConnectionCallbacks::HandlePresentationResponse,
            std::make_unique<PresentationConnectionCallbacks>(resolver, this)));
  }
  return resolver->Promise();
}

ScriptPromise<PresentationAvailability> PresentationRequest::getAvailability(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  PresentationController* controller =
      PresentationController::FromContext(GetExecutionContext());
  if (!controller) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The PresentationRequest is no longer associated to a frame.");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          script_state, exception_state.GetContext());
  auto screen_availability =
      controller->GetAvailabilityState()->GetScreenAvailability(urls_);
  // Reject Promise if screen availability is unsupported for all URLs.
  if (screen_availability == mojom::blink::ScreenAvailability::DISABLED) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kNotSupportedError,
        PresentationAvailability::kNotSupportedErrorInfo);
    return resolver->Promise();
  }

  // Create availability object the first time getAvailability() is called.
  if (!availability_) {
    availability_ = PresentationAvailability::Take(
        resolver->GetExecutionContext(), urls_,
        screen_availability == mojom::blink::ScreenAvailability::AVAILABLE);
  }

  if (screen_availability != mojom::blink::ScreenAvailability::UNKNOWN) {
    // Resolve Promise with availability object if screen availability is known.
    resolver->Resolve(availability_);
  } else {
    // Start request for screen availability if it is unknown.
    controller->GetAvailabilityState()->RequestAvailability(availability_);
    availability_->AddResolver(resolver);
  }

  return resolver->Promise();
}

const Vector<KURL>& PresentationRequest::Urls() const {
  return urls_;
}

void PresentationRequest::Trace(Visitor* visitor) const {
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(availability_);
}

PresentationRequest::PresentationRequest(ExecutionContext* execution_context,
                                         const Vector<KURL>& urls)
    : ActiveScriptWrappable<PresentationRequest>({}),
      ExecutionContextClient(execution_context),
      urls_(urls) {}

}  // namespace blink

"""

```