Response:
Let's break down the thought process for analyzing this `remote_playback.cc` file.

1. **Identify the Core Functionality:** The file name itself, "remote_playback.cc," strongly suggests its main purpose: handling the remote playback of media content within the Blink rendering engine. The code confirms this by interacting with `HTMLMediaElement`, `HTMLVideoElement`, and concepts like "casting" or "flinging."

2. **Analyze Includes and Namespaces:**  The `#include` directives are a goldmine of information. They reveal dependencies and the types of functionality being used. Key inclusions I'd notice immediately:
    * `third_party/blink/renderer/modules/remoteplayback/remote_playback.h`:  Indicates a header file for this class, likely containing declarations.
    * `third_party/blink/public/platform/modules/remoteplayback/remote_playback_source.h`:  Suggests a platform-level abstraction related to remote playback sources.
    * `third_party/blink/renderer/bindings/core/v8/...`:  Points to integration with the V8 JavaScript engine. Keywords like `ScriptPromise`, `V8RemotePlaybackState`, and `V8RemotePlaybackAvailabilityCallback` confirm this interaction.
    * `third_party/blink/renderer/core/dom/...`:  Signifies interaction with the Document Object Model, particularly `Document`, `DOMException`, and `Event`.
    * `third_party/blink/renderer/core/html/media/...`: Highlights direct involvement with HTML media elements like `HTMLMediaElement` and `HTMLVideoElement`.
    * `third_party/blink/renderer/modules/presentation/presentation_controller.h`:  Shows a dependency on the Presentation API, a related technology for displaying content on external screens.
    * `media/base/remoting_constants.h`:  Confirms involvement with media remoting.

3. **Examine Class Structure and Methods:** The core of the file is the `RemotePlayback` class. I'd go through its public and significant private methods:
    * **Constructor/Destructor:**  Sets up initial state and manages resources.
    * **`From(HTMLMediaElement&)`:** A static factory method, indicating a per-media-element instance.
    * **`watchAvailability()` and `cancelWatchAvailability()`:**  These immediately stand out as the primary way for JavaScript to interact with remote playback discovery.
    * **`prompt()`:**  The user-initiated action to start remote playback.
    * **`state()`:**  Returns the current remote playback state.
    * **Internal Methods (e.g., `PromptInternal`, `WatchAvailabilityInternal`):**  These likely handle the lower-level logic triggered by the public methods.
    * **Callbacks (e.g., `AvailabilityChanged`, `StateChanged`):** These respond to events from the underlying platform or Presentation API.

4. **Trace Data Flow:** I would try to follow the flow of information:
    * **JavaScript calls `watchAvailability()`:**  This triggers internal logic to register a callback and potentially start monitoring for available devices.
    * **JavaScript calls `prompt()`:** This initiates the presentation request process.
    * **Platform events:**  The system reports changes in device availability or connection state.
    * **Internal state updates:**  The `RemotePlayback` object updates its internal `state_` and `availability_` variables.
    * **Callbacks to JavaScript:**  Registered callbacks are invoked to notify the web page about availability changes.
    * **Events dispatched to the DOM:**  `connecting`, `connect`, and `disconnect` events are fired on the `RemotePlayback` object.

5. **Look for Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The presence of `ScriptPromise`, V8 callback types, and the throwing of `DOMException` clearly indicate JavaScript integration. The methods `watchAvailability`, `cancelWatchAvailability`, and `prompt` are directly exposed to JavaScript.
    * **HTML:** The interaction with `HTMLMediaElement` and `HTMLVideoElement` is central. The `disableremoteplayback` attribute is specifically checked.
    * **CSS:** While not directly manipulated, CSS could indirectly affect the visibility of UI elements related to remote playback (e.g., cast buttons) based on the availability state. However, this file primarily deals with the logic, not the presentation.

6. **Identify Potential User/Programming Errors:**
    * Calling `prompt()` without user activation.
    * Calling `prompt()` when another prompt is already active.
    * Trying to use the API when the `disableRemotePlayback` attribute is set.
    * Incorrectly managing `watchAvailability` IDs.

7. **Consider the Debugging Perspective:** How would someone end up inspecting this code during debugging?
    * A website reports an issue with remote playback.
    * A developer is implementing remote playback functionality and encounters errors.
    * A Chromium engineer is working on the remote playback feature itself.
    * Common user actions leading here include: clicking a "cast" button, initiating remote playback from a video's context menu, or the browser automatically attempting remote playback in certain scenarios.

8. **Structure the Analysis:** Organize the findings into logical categories: Functionality, Relationships with Web Technologies, Logic and Examples, Common Errors, and Debugging.

9. **Refine and Elaborate:**  Provide specific examples and explanations for each point. For instance, when explaining the URL generation, detail the purpose of the base64 encoding and the codec parameters.

By following these steps, I could systematically analyze the provided `remote_playback.cc` file and arrive at the detailed explanation you provided as an example. The process involves understanding the code's purpose, dependencies, structure, data flow, and its interactions with the broader web platform.
这个文件 `blink/renderer/modules/remoteplayback/remote_playback.cc` 是 Chromium Blink 引擎中负责处理 HTML5 媒体元素（如 `<video>` 和 `<audio>`）的**远程播放**功能的源代码。它的主要职责是允许用户将当前媒体内容投射到其他支持的设备上进行播放，例如智能电视、Chromecast 等。

下面列举一下它的主要功能，并解释其与 JavaScript, HTML, CSS 的关系，以及逻辑推理、常见错误和调试线索：

**主要功能:**

1. **管理远程播放状态:**
   - 维护当前媒体元素的远程播放状态 (例如：连接中、已连接、已断开)。
   - 提供 JavaScript 接口 (`RemotePlayback` API) 来获取和监听这些状态变化。

2. **发现可用远程播放设备:**
   - 通过与 Presentation API 的集成，扫描并发现网络中可用的远程播放设备。
   - 监听设备可用性的变化。

3. **启动远程播放会话:**
   - 响应用户的远程播放请求 (通过 JavaScript 的 `prompt()` 方法)。
   - 与远程设备建立连接。

4. **处理远程播放会话的生命周期:**
   - 管理连接的建立、保持和断开。
   - 处理连接错误。

5. **提供 JavaScript API:**
   - 暴露 `RemotePlayback` 接口，允许 JavaScript 代码监听设备可用性、启动远程播放、取消监听等。

6. **集成 Presentation API:**
   - 依赖于 Chromium 的 Presentation API 来实现设备发现和连接管理。

7. **性能监控和指标收集:**
   - 记录远程播放相关的指标，例如启动成功与否、用户交互等。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - **接口暴露:** 这个文件实现了 `RemotePlayback` Web API，JavaScript 代码可以直接调用该 API 的方法，如 `watchAvailability()`, `cancelWatchAvailability()`, 和 `prompt()`。
    - **事件触发:** 当远程播放状态发生变化（例如，连接建立、断开）或者设备可用性发生变化时，`RemotePlayback` 对象会触发相应的事件 (`connecting`, `connect`, `disconnect`)，JavaScript 可以监听这些事件并做出响应。
    - **Promise 的使用:**  `watchAvailability()` 和 `prompt()` 方法返回 Promise 对象，允许 JavaScript 代码异步处理远程播放的操作结果。

    **举例说明:**

    ```javascript
    const videoElement = document.querySelector('video');
    const remotePlayback = videoElement.remotePlayback;

    remotePlayback.watchAvailability(availability => {
      console.log('Remote playback available:', availability);
      // 根据设备可用性更新 UI
    }).then(watchId => {
      console.log('Watching availability with ID:', watchId);
    });

    remotePlayback.addEventListener('connect', () => {
      console.log('Successfully connected to remote playback device!');
    });

    remotePlayback.addEventListener('disconnect', () => {
      console.log('Disconnected from remote playback device.');
    });

    videoElement.remotePlayback.prompt()
      .then(() => console.log('Remote playback started'))
      .catch(error => console.error('Failed to start remote playback:', error));
    ```

* **HTML:**
    - **`disableRemotePlayback` 属性:**  HTML 媒体元素上的 `disableRemotePlayback` 属性会影响 `RemotePlayback` API 的行为。该文件会检查此属性，如果存在，会阻止某些操作（例如，`watchAvailability` 和 `prompt` 会抛出异常）。

    **举例说明:**

    ```html
    <video src="myvideo.mp4" controls></video>  <!-- 允许远程播放 -->
    <video src="another_video.mp4" controls disableRemotePlayback></video> <!-- 禁止远程播放 -->
    ```

* **CSS:**
    - **间接影响:** CSS 自身不直接与 `remote_playback.cc` 交互。然而，JavaScript 代码可能会根据 `RemotePlayback` API 的状态（例如，设备是否可用）来动态修改 CSS 类或样式，从而改变用户界面上远程播放相关按钮或图标的显示状态。

**逻辑推理与假设输入/输出:**

**假设输入:**

1. 用户在支持远程播放的浏览器中加载了一个包含 `<video>` 元素的网页。
2. 网页 JavaScript 代码调用了 `videoElement.remotePlayback.watchAvailability()` 来监听设备可用性。
3. 系统检测到网络中有可用的 Chromecast 设备。

**逻辑推理:**

1. `watchAvailability()` 方法内部会调用 `WatchAvailabilityInternal()`，向 PresentationController 注册一个回调。
2. PresentationController 检测到设备可用性变化，调用 `RemotePlayback` 的 `AvailabilityChanged()` 方法。
3. `AvailabilityChanged()` 方法会遍历注册的回调，并执行 JavaScript 中提供的回调函数，将设备可用性信息传递给网页。

**假设输出:**

- JavaScript 中的 `availability` 回调函数会被调用，参数为 `true` (表示设备可用)。
- 开发者可以在回调函数中更新 UI，例如显示投屏按钮。

**用户或编程常见的使用错误:**

1. **在没有用户手势的情况下调用 `prompt()`:**  出于安全考虑，`prompt()` 方法通常需要用户交互（例如，点击按钮）才能触发。如果直接在页面加载时调用，可能会抛出 `InvalidAccessError` 异常。
   - **例子:**
     ```javascript
     // 错误的做法：页面加载时直接调用
     window.onload = function() {
       document.querySelector('video').remotePlayback.prompt();
     };

     // 正确的做法：在用户点击事件中调用
     document.getElementById('castButton').addEventListener('click', () => {
       document.querySelector('video').remotePlayback.prompt();
     });
     ```

2. **在设置了 `disableRemotePlayback` 属性的元素上调用 `watchAvailability()` 或 `prompt()`:** 这会导致 `InvalidStateError` 异常。
   - **例子:**
     ```html
     <video src="video.mp4" controls disableRemotePlayback id="myVideo"></video>
     <script>
       document.getElementById('myVideo').remotePlayback.watchAvailability(() => {}); // 抛出异常
     </script>
     ```

3. **多次调用 `prompt()` 而前一个 prompt 尚未完成:**  这会导致 `OperationError` 异常。用户需要等待前一个 prompt 完成（成功连接或被取消）才能发起新的 prompt。
   - **例子:**
     ```javascript
     let isPrompting = false;
     document.getElementById('castButton').addEventListener('click', () => {
       if (!isPrompting) {
         isPrompting = true;
         document.querySelector('video').remotePlayback.prompt()
           .finally(() => isPrompting = false);
       } else {
         console.log('A prompt is already being shown.');
       }
     });
     ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含 `<video>` 或 `<audio>` 元素的网页。**  Blink 引擎会创建对应的 `HTMLMediaElement` 对象。
2. **网页 JavaScript 代码获取 `HTMLMediaElement` 上的 `remotePlayback` 属性。**  这会返回一个 `RemotePlayback` 对象，该对象由 `remote_playback.cc` 中的 `RemotePlayback::From(HTMLMediaElement&)` 方法创建或获取。
3. **用户与网页交互，例如点击一个“投屏”按钮。**  JavaScript 事件监听器被触发。
4. **JavaScript 代码调用 `remotePlayback.prompt()` 方法。**  这会触发 `remote_playback.cc` 中的 `RemotePlayback::prompt()` 方法。
5. **`prompt()` 方法会检查各种条件（例如，用户手势、`disableRemotePlayback` 属性）。**
6. **如果条件满足，`prompt()` 方法会调用 `PromptInternal()`，进而与 PresentationController 交互，启动远程播放设备的发现和连接流程。**
7. **Presentation API 的相关代码会扫描网络中的可用设备，并将结果通知 `RemotePlayback` 对象。**  这可能会触发 `AvailabilityChanged()` 方法。
8. **用户选择一个远程播放设备。**  Presentation API 尝试与该设备建立连接。
9. **连接状态发生变化，`RemotePlayback` 对象的 `StateChanged()` 方法被调用。**
10. **`StateChanged()` 方法会触发 `connect` 或 `disconnect` 事件，通知 JavaScript 代码。**

**调试线索:**

* **断点:** 在 `RemotePlayback::prompt()`, `WatchAvailabilityInternal()`, `AvailabilityChanged()`, `StateChanged()` 等关键方法上设置断点，可以跟踪代码的执行流程，查看变量的值，了解远程播放的状态变化和错误发生的位置。
* **日志:** 使用 `DLOG` 或 `DVLOG` 在关键路径上打印日志信息，例如设备发现的结果、连接状态变化、错误信息等。
* **Chrome 开发者工具:**
    - **Sources 面板:** 可以查看和调试 JavaScript 代码，了解 JavaScript 如何调用 `RemotePlayback` API。
    - **Network 面板:** 可以查看与远程播放设备通信的网络请求。
    - **Media 面板:** 可以查看媒体元素的属性和状态，包括远程播放状态。
    - **Presentation API 相关事件:**  开发者工具可能会显示 Presentation API 相关的事件，帮助理解设备发现和连接过程。
* **平台特定的调试工具:**  例如，在 Android 上可以使用 `adb logcat` 查看系统日志，其中可能包含与远程播放相关的错误或信息。

总而言之，`blink/renderer/modules/remoteplayback/remote_playback.cc` 是 Blink 引擎中实现 HTML5 远程播放功能的核心组件，它通过与 JavaScript 和 Presentation API 协同工作，使得网页能够将媒体内容投射到外部设备上播放。理解其功能和与 Web 技术的交互方式，有助于开发者正确使用远程播放 API，并进行问题排查和调试。

### 提示词
```
这是目录为blink/renderer/modules/remoteplayback/remote_playback.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/remoteplayback/remote_playback.h"

#include <memory>
#include <utility>

#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "media/base/remoting_constants.h"
#include "third_party/blink/public/platform/modules/remoteplayback/remote_playback_source.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_remote_playback_availability_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_remote_playback_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/media/remote_playback_observer.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/probe/async_task_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/presentation/presentation_availability_state.h"
#include "third_party/blink/renderer/modules/presentation/presentation_controller.h"
#include "third_party/blink/renderer/modules/remoteplayback/availability_callback_wrapper.h"
#include "third_party/blink/renderer/modules/remoteplayback/remote_playback_metrics.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/memory_pressure_listener.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {

namespace {

V8RemotePlaybackState::Enum RemotePlaybackStateToEnum(
    mojom::blink::PresentationConnectionState state) {
  switch (state) {
    case mojom::blink::PresentationConnectionState::CONNECTING:
      return V8RemotePlaybackState::Enum::kConnecting;
    case mojom::blink::PresentationConnectionState::CONNECTED:
      return V8RemotePlaybackState::Enum::kConnected;
    case mojom::blink::PresentationConnectionState::CLOSED:
    case mojom::blink::PresentationConnectionState::TERMINATED:
      return V8RemotePlaybackState::Enum::kDisconnected;
  }
  NOTREACHED();
}

void RunRemotePlaybackTask(
    ExecutionContext* context,
    base::OnceClosure task,
    std::unique_ptr<probe::AsyncTaskContext> task_context) {
  probe::AsyncTask async_task(context, task_context.get());
  std::move(task).Run();
}

KURL GetAvailabilityUrl(const KURL& source,
                        bool is_source_supported,
                        std::optional<media::VideoCodec> video_codec,
                        std::optional<media::AudioCodec> audio_codec) {
  if (source.IsEmpty() || !source.IsValid() || !is_source_supported) {
    return KURL();
  }

  // The URL for each media element's source looks like the following:
  // remote-playback:media-element?source=<encoded-data>&video_codec=<video_codec>&audio_codec=<audio_codec>
  // where |encoded-data| is base64 URL encoded string representation of the
  // source URL. |video_codec| and |audio_codec| are used for device capability
  // filter for Media Remoting based Remote Playback on Desktop. The codec
  // fields are optional.
  std::string source_string = source.GetString().Utf8();
  String encoded_source =
      WTF::Base64URLEncode(base::as_byte_span(source_string));

  std::string video_codec_str =
      video_codec.has_value()
          ? ("&video_codec=" + media::GetCodecName(video_codec.value()))
          : "";
  std::string audio_codec_str =
      audio_codec.has_value()
          ? ("&audio_codec=" + media::GetCodecName(audio_codec.value()))
          : "";
  return KURL(StringView(kRemotePlaybackPresentationUrlPath) +
              "?source=" + encoded_source + video_codec_str.c_str() +
              audio_codec_str.c_str());
}

bool IsBackgroundAvailabilityMonitoringDisabled() {
  return MemoryPressureListenerRegistry::IsLowEndDevice();
}

void RemotingStarting(HTMLMediaElement& media_element) {
  if (auto* video_element = DynamicTo<HTMLVideoElement>(&media_element)) {
    // TODO(xjz): Pass the remote device name.
    video_element->MediaRemotingStarted(WebString());
  }
  media_element.FlingingStarted();
}

}  // anonymous namespace

// static
RemotePlayback& RemotePlayback::From(HTMLMediaElement& element) {
  RemotePlayback* self =
      static_cast<RemotePlayback*>(RemotePlaybackController::From(element));
  if (!self) {
    self = MakeGarbageCollected<RemotePlayback>(element);
    RemotePlaybackController::ProvideTo(element, self);
  }
  return *self;
}

RemotePlayback::RemotePlayback(HTMLMediaElement& element)
    : ExecutionContextLifecycleObserver(element.GetExecutionContext()),
      ActiveScriptWrappable<RemotePlayback>({}),
      RemotePlaybackController(element),
      state_(mojom::blink::PresentationConnectionState::CLOSED),
      availability_(mojom::ScreenAvailability::UNKNOWN),
      media_element_(&element),
      is_listening_(false),
      presentation_connection_receiver_(this, element.GetExecutionContext()),
      target_presentation_connection_(element.GetExecutionContext()) {}

const AtomicString& RemotePlayback::InterfaceName() const {
  return event_target_names::kRemotePlayback;
}

ExecutionContext* RemotePlayback::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

ScriptPromise<IDLLong> RemotePlayback::watchAvailability(
    ScriptState* script_state,
    V8RemotePlaybackAvailabilityCallback* callback,
    ExceptionState& exception_state) {
  if (media_element_->FastHasAttribute(
          html_names::kDisableremoteplaybackAttr)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "disableRemotePlayback attribute is present.");
    return EmptyPromise();
  }

  int id = WatchAvailabilityInternal(
      MakeGarbageCollected<AvailabilityCallbackWrapper>(callback));
  if (id == kWatchAvailabilityNotSupported) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Availability monitoring is not supported on this device.");
    return EmptyPromise();
  }

  // TODO(avayvod): Currently the availability is tracked for each media element
  // as soon as it's created, we probably want to limit that to when the
  // page/element is visible (see https://crbug.com/597281) and has default
  // controls. If there are no default controls, we should also start tracking
  // availability on demand meaning the Promise returned by watchAvailability()
  // will be resolved asynchronously.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLLong>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  resolver->Resolve(id);
  return promise;
}

ScriptPromise<IDLUndefined> RemotePlayback::cancelWatchAvailability(
    ScriptState* script_state,
    int id,
    ExceptionState& exception_state) {
  if (media_element_->FastHasAttribute(
          html_names::kDisableremoteplaybackAttr)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "disableRemotePlayback attribute is present.");
    return EmptyPromise();
  }

  if (!CancelWatchAvailabilityInternal(id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "A callback with the given id is not found.");
    return EmptyPromise();
  }

  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> RemotePlayback::cancelWatchAvailability(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (media_element_->FastHasAttribute(
          html_names::kDisableremoteplaybackAttr)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "disableRemotePlayback attribute is present.");
    return EmptyPromise();
  }

  availability_callbacks_.clear();
  StopListeningForAvailability();
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> RemotePlayback::prompt(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (media_element_->FastHasAttribute(
          html_names::kDisableremoteplaybackAttr)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "disableRemotePlayback attribute is present.");
    return EmptyPromise();
  }

  if (prompt_promise_resolver_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "A prompt is already being shown for this media element.");
    return EmptyPromise();
  }

  if (!media_element_->DomWindow()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "RemotePlayback::prompt() does not work in a detached window.");
    return EmptyPromise();
  }

  if (!LocalFrame::HasTransientUserActivation(
          media_element_->DomWindow()->GetFrame())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "RemotePlayback::prompt() requires user gesture.");
    return EmptyPromise();
  }

  if (!RuntimeEnabledFeatures::RemotePlaybackBackendEnabled()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The RemotePlayback API is disabled on this platform.");
    return EmptyPromise();
  }

  if (availability_ == mojom::ScreenAvailability::UNAVAILABLE) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "No remote playback devices found.");
    return EmptyPromise();
  }

  if (availability_ == mojom::ScreenAvailability::SOURCE_NOT_SUPPORTED) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The currentSrc is not compatible with remote playback");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  prompt_promise_resolver_ = resolver;
  PromptInternal();
  RemotePlaybackMetrics::RecordRemotePlaybackLocation(
      RemotePlaybackInitiationLocation::kRemovePlaybackAPI);
  return promise;
}

V8RemotePlaybackState RemotePlayback::state() const {
  return V8RemotePlaybackState(RemotePlaybackStateToEnum(state_));
}

bool RemotePlayback::HasPendingActivity() const {
  return HasEventListeners() || !availability_callbacks_.empty() ||
         prompt_promise_resolver_;
}

void RemotePlayback::PromptInternal() {
  if (!GetExecutionContext())
    return;

  PresentationController* controller =
      PresentationController::FromContext(GetExecutionContext());
  if (controller && !availability_urls_.empty()) {
    controller->GetPresentationService()->StartPresentation(
        availability_urls_,
        WTF::BindOnce(&RemotePlayback::HandlePresentationResponse,
                      WrapPersistent(this)));
  } else {
    // TODO(yuryu): Wrapping PromptCancelled with base::OnceClosure as
    // InspectorInstrumentation requires a globally unique pointer to track
    // tasks. We can remove the wrapper if InspectorInstrumentation returns a
    // task id.
    base::OnceClosure task =
        WTF::BindOnce(&RemotePlayback::PromptCancelled, WrapPersistent(this));

    std::unique_ptr<probe::AsyncTaskContext> task_context =
        std::make_unique<probe::AsyncTaskContext>();
    task_context->Schedule(GetExecutionContext(), "promptCancelled");
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kMediaElementEvent)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(RunRemotePlaybackTask,
                                 WrapPersistent(GetExecutionContext()),
                                 std::move(task), std::move(task_context)));
  }
}

int RemotePlayback::WatchAvailabilityInternal(
    AvailabilityCallbackWrapper* callback) {
  if (RuntimeEnabledFeatures::RemotePlaybackBackendEnabled() &&
      IsBackgroundAvailabilityMonitoringDisabled()) {
    return kWatchAvailabilityNotSupported;
  }

  if (!GetExecutionContext())
    return kWatchAvailabilityNotSupported;

  int id;
  do {
    id = GetExecutionContext()->CircularSequentialID();
  } while (!availability_callbacks_.insert(id, callback).is_new_entry);

  // Report the current availability via the callback.
  // TODO(yuryu): Wrapping notifyInitialAvailability with base::OnceClosure as
  // InspectorInstrumentation requires a globally unique pointer to track tasks.
  // We can remove the wrapper if InspectorInstrumentation returns a task id.
  base::OnceClosure task = WTF::BindOnce(
      &RemotePlayback::NotifyInitialAvailability, WrapPersistent(this), id);
  std::unique_ptr<probe::AsyncTaskContext> task_context =
      std::make_unique<probe::AsyncTaskContext>();
  task_context->Schedule(GetExecutionContext(), "watchAvailabilityCallback");
  GetExecutionContext()
      ->GetTaskRunner(TaskType::kMediaElementEvent)
      ->PostTask(FROM_HERE,
                 WTF::BindOnce(RunRemotePlaybackTask,
                               WrapPersistent(GetExecutionContext()),
                               std::move(task), std::move(task_context)));

  MaybeStartListeningForAvailability();
  return id;
}

bool RemotePlayback::CancelWatchAvailabilityInternal(int id) {
  if (id <= 0)  // HashMap doesn't support the cases of key = 0 or key = -1.
    return false;
  auto iter = availability_callbacks_.find(id);
  if (iter == availability_callbacks_.end())
    return false;
  availability_callbacks_.erase(iter);
  if (availability_callbacks_.empty())
    StopListeningForAvailability();

  return true;
}

void RemotePlayback::NotifyInitialAvailability(int callback_id) {
  // May not find the callback if the website cancels it fast enough.
  auto iter = availability_callbacks_.find(callback_id);
  if (iter == availability_callbacks_.end())
    return;

  iter->value->Run(this, RemotePlaybackAvailable());
}

void RemotePlayback::StateChanged(
    mojom::blink::PresentationConnectionState state) {
  if (prompt_promise_resolver_ &&
      IsInParallelAlgorithmRunnable(
          prompt_promise_resolver_->GetExecutionContext(),
          prompt_promise_resolver_->GetScriptState())) {
    // Changing state to "CLOSED" from "CLOSED" or "CONNECTING"
    // means that establishing connection with remote playback device failed.
    // Changing state to anything else means the state change intended by
    // prompt() succeeded.
    ScriptState::Scope script_state_scope(
        prompt_promise_resolver_->GetScriptState());

    if (state_ != mojom::blink::PresentationConnectionState::CONNECTED &&
        state == mojom::blink::PresentationConnectionState::CLOSED) {
      prompt_promise_resolver_->Reject(V8ThrowDOMException::CreateOrDie(
          prompt_promise_resolver_->GetScriptState()->GetIsolate(),
          DOMExceptionCode::kAbortError,
          "Failed to connect to the remote device."));
    } else {
      prompt_promise_resolver_->Resolve();
    }
  }
  prompt_promise_resolver_ = nullptr;

  if (state_ == state)
    return;

  state_ = state;
  if (state_ == mojom::blink::PresentationConnectionState::CONNECTING) {
    DispatchEvent(*Event::Create(event_type_names::kConnecting));
    RemotingStarting(*media_element_);
  } else if (state_ == mojom::blink::PresentationConnectionState::CONNECTED) {
    DispatchEvent(*Event::Create(event_type_names::kConnect));
  } else if (state_ == mojom::blink::PresentationConnectionState::CLOSED ||
             state_ == mojom::blink::PresentationConnectionState::TERMINATED) {
    DispatchEvent(*Event::Create(event_type_names::kDisconnect));
    if (auto* video_element =
            DynamicTo<HTMLVideoElement>(media_element_.Get())) {
      video_element->MediaRemotingStopped(
          MediaPlayerClient::kMediaRemotingStopNoText);
    }
    CleanupConnections();
    presentation_id_ = "";
    presentation_url_ = KURL();
    media_element_->FlingingStopped();
  }

  for (auto observer : observers_)
    observer->OnRemotePlaybackStateChanged(state_);
}

void RemotePlayback::PromptCancelled() {
  if (!prompt_promise_resolver_ ||
      !IsInParallelAlgorithmRunnable(
          prompt_promise_resolver_->GetExecutionContext(),
          prompt_promise_resolver_->GetScriptState())) {
    prompt_promise_resolver_ = nullptr;
    return;
  }

  ScriptState::Scope script_state_scope(
      prompt_promise_resolver_->GetScriptState());

  prompt_promise_resolver_->Reject(V8ThrowDOMException::CreateOrDie(
      prompt_promise_resolver_->GetScriptState()->GetIsolate(),
      DOMExceptionCode::kNotAllowedError, "The prompt was dismissed."));
  prompt_promise_resolver_ = nullptr;
}

void RemotePlayback::SourceChanged(const KURL& source,
                                   bool is_source_supported) {
  source_ = source;
  is_source_supported_ = is_source_supported;

  UpdateAvailabilityUrlsAndStartListening();
}

void RemotePlayback::UpdateAvailabilityUrlsAndStartListening() {
  if (is_background_availability_monitoring_disabled_for_testing_ ||
      IsBackgroundAvailabilityMonitoringDisabled() ||
      !RuntimeEnabledFeatures::RemotePlaybackBackendEnabled()) {
    return;
  }

  // If the video is too short, it's unlikely to be cast. Disable availability
  // monitoring so that the cast buttons are hidden from the video player.
  if (!media_element_ || std::isnan(media_element_->duration()) ||
      media_element_->duration() <=
          media::remoting::kMinRemotingMediaDurationInSec) {
    StopListeningForAvailability();
    availability_urls_.clear();
    return;
  }

  KURL current_url =
      availability_urls_.empty() ? KURL() : availability_urls_[0];
  KURL new_url = GetAvailabilityUrl(source_, is_source_supported_, video_codec_,
                                    audio_codec_);

  if (new_url == current_url)
    return;

  // Tell PresentationController to stop listening for availability before the
  // URLs vector is updated.
  StopListeningForAvailability();

  availability_urls_.clear();
  if (!new_url.IsEmpty()) {
    availability_urls_.push_back(new_url);

    if (state_ == mojom::blink::PresentationConnectionState::CONNECTED) {
      RemotingStarting(*media_element_);
      presentation_url_ = new_url;
    }
  }

  MaybeStartListeningForAvailability();
}

String RemotePlayback::GetPresentationId() {
  return presentation_id_;
}

void RemotePlayback::MediaMetadataChanged(
    std::optional<media::VideoCodec> video_codec,
    std::optional<media::AudioCodec> audio_codec) {
  video_codec_ = video_codec;
  audio_codec_ = audio_codec;

  UpdateAvailabilityUrlsAndStartListening();
}

void RemotePlayback::AddObserver(RemotePlaybackObserver* observer) {
  observers_.insert(observer);
}

void RemotePlayback::RemoveObserver(RemotePlaybackObserver* observer) {
  observers_.erase(observer);
}

void RemotePlayback::AvailabilityChangedForTesting(bool screen_is_available) {
  // Disable the background availability monitoring so that the availability
  // won't be overridden later.
  is_background_availability_monitoring_disabled_for_testing_ = true;
  StopListeningForAvailability();

  AvailabilityChanged(screen_is_available
                          ? mojom::blink::ScreenAvailability::AVAILABLE
                          : mojom::blink::ScreenAvailability::UNAVAILABLE);
}

void RemotePlayback::StateChangedForTesting(bool is_connected) {
  StateChanged(is_connected
                   ? mojom::blink::PresentationConnectionState::CONNECTED
                   : mojom::blink::PresentationConnectionState::CLOSED);
}

bool RemotePlayback::RemotePlaybackAvailable() const {
  if (IsBackgroundAvailabilityMonitoringDisabled() &&
      RuntimeEnabledFeatures::RemotePlaybackBackendEnabled() &&
      !media_element_->currentSrc().IsEmpty()) {
    return true;
  }

  return availability_ == mojom::ScreenAvailability::AVAILABLE;
}

void RemotePlayback::RemotePlaybackDisabled() {
  if (prompt_promise_resolver_) {
    prompt_promise_resolver_->Reject(V8ThrowDOMException::CreateOrDie(
        prompt_promise_resolver_->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kInvalidStateError,
        "disableRemotePlayback attribute is present."));
    prompt_promise_resolver_ = nullptr;
  }

  availability_callbacks_.clear();
  StopListeningForAvailability();

  if (state_ == mojom::blink::PresentationConnectionState::CLOSED ||
      state_ == mojom::blink::PresentationConnectionState::TERMINATED) {
    return;
  }

  auto* controller = PresentationController::FromContext(GetExecutionContext());
  if (controller) {
    controller->GetPresentationService()->CloseConnection(presentation_url_,
                                                          presentation_id_);
  }
}

void RemotePlayback::CleanupConnections() {
  target_presentation_connection_.reset();
  presentation_connection_receiver_.reset();
}

void RemotePlayback::AvailabilityChanged(
    mojom::blink::ScreenAvailability availability) {
  DCHECK(is_listening_ ||
         is_background_availability_monitoring_disabled_for_testing_);
  DCHECK_NE(availability, mojom::ScreenAvailability::UNKNOWN);
  DCHECK_NE(availability, mojom::ScreenAvailability::DISABLED);

  if (availability_ == availability)
    return;

  bool old_availability = RemotePlaybackAvailable();
  availability_ = availability;
  bool new_availability = RemotePlaybackAvailable();
  if (new_availability == old_availability)
    return;

  // Copy the callbacks to a temporary vector to prevent iterator invalidations,
  // in case the JS callbacks invoke watchAvailability().
  HeapVector<Member<AvailabilityCallbackWrapper>> callbacks;
  CopyValuesToVector(availability_callbacks_, callbacks);

  for (auto& callback : callbacks)
    callback->Run(this, new_availability);
}

const Vector<KURL>& RemotePlayback::Urls() const {
  // TODO(avayvod): update the URL format and add frame url, mime type and
  // response headers when available.
  return availability_urls_;
}

void RemotePlayback::OnConnectionSuccess(
    mojom::blink::PresentationConnectionResultPtr result) {
  presentation_id_ = std::move(result->presentation_info->id);
  presentation_url_ = std::move(result->presentation_info->url);

  StateChanged(mojom::blink::PresentationConnectionState::CONNECTING);

  DCHECK(!presentation_connection_receiver_.is_bound());
  auto* presentation_controller =
      PresentationController::FromContext(GetExecutionContext());
  if (!presentation_controller)
    return;

#if !BUILDFLAG(IS_ANDROID)
  media_element_->Play();
  media_element_->GetWebMediaPlayer()->RequestMediaRemoting();
#endif

  // Note: Messages on |connection_receiver| are ignored.
  target_presentation_connection_.Bind(
      std::move(result->connection_remote),
      GetExecutionContext()->GetTaskRunner(TaskType::kMediaElementEvent));
  presentation_connection_receiver_.Bind(
      std::move(result->connection_receiver),
      GetExecutionContext()->GetTaskRunner(TaskType::kMediaElementEvent));
  RemotePlaybackMetrics::RecordRemotePlaybackStartSessionResult(
      GetExecutionContext(), true);
}

void RemotePlayback::OnConnectionError(
    const mojom::blink::PresentationError& error) {
  // This is called when:
  // (1) A request to start a presentation failed.
  // (2) A PresentationRequest is cancelled. i.e. the user closed the device
  // selection or the route controller dialog.

  if (error.error_type ==
      mojom::blink::PresentationErrorType::PRESENTATION_REQUEST_CANCELLED) {
    PromptCancelled();
    return;
  }

  presentation_id_ = "";
  presentation_url_ = KURL();

  StateChanged(mojom::blink::PresentationConnectionState::CLOSED);
  RemotePlaybackMetrics::RecordRemotePlaybackStartSessionResult(
      GetExecutionContext(), false);
}

void RemotePlayback::HandlePresentationResponse(
    mojom::blink::PresentationConnectionResultPtr result,
    mojom::blink::PresentationErrorPtr error) {
  if (result) {
    OnConnectionSuccess(std::move(result));
  } else {
    OnConnectionError(*error);
  }
}

void RemotePlayback::OnMessage(
    mojom::blink::PresentationConnectionMessagePtr message) {
  // Messages are ignored.
}

void RemotePlayback::DidChangeState(
    mojom::blink::PresentationConnectionState state) {
  StateChanged(state);
}

void RemotePlayback::DidClose(
    mojom::blink::PresentationConnectionCloseReason reason) {
  StateChanged(mojom::blink::PresentationConnectionState::CLOSED);
}

void RemotePlayback::StopListeningForAvailability() {
  if (!is_listening_)
    return;

  availability_ = mojom::ScreenAvailability::UNKNOWN;
  PresentationController* controller =
      PresentationController::FromContext(GetExecutionContext());
  if (!controller)
    return;

  controller->RemoveAvailabilityObserver(this);
  is_listening_ = false;
}

void RemotePlayback::MaybeStartListeningForAvailability() {
  if (IsBackgroundAvailabilityMonitoringDisabled() ||
      is_background_availability_monitoring_disabled_for_testing_) {
    return;
  }

  if (is_listening_)
    return;

  if (availability_urls_.empty() || availability_callbacks_.empty())
    return;

  PresentationController* controller =
      PresentationController::FromContext(GetExecutionContext());
  if (!controller)
    return;

  controller->AddAvailabilityObserver(this);
  is_listening_ = true;
}

void RemotePlayback::Trace(Visitor* visitor) const {
  visitor->Trace(availability_callbacks_);
  visitor->Trace(prompt_promise_resolver_);
  visitor->Trace(media_element_);
  visitor->Trace(presentation_connection_receiver_);
  visitor->Trace(target_presentation_connection_);
  visitor->Trace(observers_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  RemotePlaybackController::Trace(visitor);
}

}  // namespace blink
```