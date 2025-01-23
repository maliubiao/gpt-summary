Response:
Let's break down the thought process for analyzing the `rtc_rtp_script_transform.cc` file.

1. **Understand the Core Purpose:** The filename itself is a strong clue: `rtc_rtp_script_transform`. This suggests a mechanism to *transform* Real-time Transport Protocol (RTP) data using *script*. The `blink` namespace and `peerconnection` directory further indicate its role within the WebRTC implementation in Chromium.

2. **Identify Key Classes and their Roles:** Scan the `#include` directives and the class definition (`RTCRtpScriptTransform`). Notice these key players:
    * `RTCRtpScriptTransform`: The central class, likely responsible for managing the script-based transformation.
    * `RTCRtpScriptTransformer`:  Another related class, probably the worker-side counterpart handling the actual script execution.
    * `RTCRtpReceiver`: Represents the receiving end of an RTP stream.
    * `RTCEncodedAudioStreamTransformer::Broker` and `RTCEncodedVideoStreamTransformer::Broker`: These hint at the specific types of data being transformed (audio and video).
    * `DedicatedWorker`: The context where the transformation script will run.
    * `RTCTransformEvent`:  A custom event used to communicate with the worker.
    * `ScriptValue`: Represents JavaScript values.

3. **Analyze the `Create` Methods:**  The different `Create` methods reveal how an `RTCRtpScriptTransform` instance is instantiated. The involvement of a `DedicatedWorker` and the `PostCustomEvent` function points to asynchronous creation and communication with a worker thread. The `message` and `transfer` parameters suggest passing data to the worker.

4. **Examine the `CreateRTCTransformEvent` Function:** This function is crucial. It runs *in the worker context*. It creates an `RTCTransformEvent` and, importantly, calls `SetRtpTransformer` on the main thread. This establishes the link between the `RTCRtpScriptTransform` and its worker-side counterpart.

5. **Focus on `SetUpAudioRtpTransformer` and `SetUpVideoRtpTransformer`:** These functions are called after the `RTCRtpTransformer` is available. They are responsible for setting up the actual transformation pipeline for audio and video data, respectively, likely by connecting the `RTCRtpScriptTransformer` with the encoding/decoding mechanisms. The `Broker` classes confirm this.

6. **Understand `SetRtpTransformer`:** This method is called from the worker thread (via `PostCrossThreadTask`). It stores the `RTCRtpScriptTransformer` and its task runner, enabling communication with the worker. The logic to call `SetUpAudioRtpTransformer` or `SetUpVideoRtpTransformer` if the corresponding brokers are already available suggests a possible out-of-order initialization scenario.

7. **Analyze `AttachToReceiver` and `Detach`:** These methods manage the lifecycle of the transformation in relation to an `RTCRtpReceiver`. `AttachToReceiver` links the transform to a receiver, while `Detach` cleans up resources and disconnects the transform. The `Detach` method also clears the `RTCRtpTransformer` on the worker thread.

8. **Investigate `HandleSendKeyFrameRequestResults` and `SendKeyFrameRequestToReceiver`:** These functions deal with triggering keyframe requests. The logic within `HandleSendKeyFrameRequestResults` checks various conditions (receiver presence, track state, transceiver direction) before requesting a keyframe from the `MediaStreamVideoSource`. The request itself happens on the main thread, while the callback to the transformer happens on the worker thread.

9. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The use of `ScriptValue`, `DedicatedWorker`, and event handling (`RTCTransformEvent`) directly links this code to JavaScript's Web Workers API and the ability to pass messages between the main thread and workers. The transformation logic itself will be defined in JavaScript code executed in the worker.
    * **HTML:**  The `<video>` and `<audio>` elements are the ultimate consumers of the media streams. The transformations happening here can affect how these elements render the media.
    * **CSS:** While less direct, CSS might influence the overall layout and presentation of the video element, which in turn displays the transformed video.

10. **Consider Use Cases and Error Scenarios:**  Think about how a developer would use this API and what could go wrong:
    * Passing invalid JavaScript code to the worker.
    * Trying to access resources not available in the worker context.
    * Incorrectly handling asynchronous operations.
    * Detaching the transform prematurely.

11. **Trace User Actions:**  Imagine the steps a user takes that lead to this code being executed:
    * Opening a webpage.
    * The webpage using WebRTC APIs (`RTCPeerConnection`, `addTransceiver`).
    * Configuring a `transform` for a transceiver.
    * Starting the media flow.

12. **Refine and Organize:**  Structure the findings logically, covering functionality, relationships with web technologies, assumptions, usage errors, and debugging hints. Use clear and concise language. Provide concrete examples where applicable.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the transformation happens directly in the main thread. **Correction:** The involvement of `DedicatedWorker` and `PostCrossThreadTask` clearly indicates a worker thread.
* **Initial thought:**  The transformation applies to raw media data. **Correction:** The `RTCEncodedAudioStreamTransformer` and `RTCEncodedVideoStreamTransformer` suggest the transformation works on *encoded* media frames.
* **Focusing too much on low-level details:** **Refinement:**  Focus on the high-level purpose and the interaction between different components.

By following this detailed thought process, you can effectively analyze complex source code like `rtc_rtp_script_transform.cc` and extract valuable information about its functionality, relationships, and potential issues.
好的，我们来详细分析一下 `blink/renderer/modules/peerconnection/rtc_rtp_script_transform.cc` 文件的功能。

**文件功能概览**

`rtc_rtp_script_transform.cc` 文件定义了 `RTCRtpScriptTransform` 类，这个类是 Blink 渲染引擎中用于实现 WebRTC 中可编程媒体流变换（Transforming Media Streams）的核心组件。它允许开发者通过 JavaScript 在 Web Worker 中自定义对 RTP (Real-time Transport Protocol) 数据包的处理逻辑。

**主要功能点：**

1. **创建和管理 Worker 上下文的 RTP 变换器:**
   - `RTCRtpScriptTransform::Create` 方法负责创建 `RTCRtpScriptTransform` 对象。这个过程会涉及到在独立的 Web Worker 中创建一个 `RTCRtpScriptTransformer` 实例。
   - 通过 `DedicatedWorker::PostCustomEvent` 方法，向 Worker 线程发送一个事件，这个事件会触发在 Worker 线程中创建 `RTCTransformEvent` 和 `RTCRtpScriptTransformer` 的过程。

2. **连接主线程和 Worker 线程的变换器:**
   - `CreateRTCTransformEvent` 函数在 Worker 线程中被调用，它创建了一个 `RTCTransformEvent` 并将其传递回主线程。
   - `RTCRtpScriptTransform::SetRtpTransformer` 方法在主线程中接收到来自 Worker 的 `RTCRtpScriptTransformer` 实例，并将两者关联起来。这意味着主线程持有对 Worker 中变换器的引用，可以进行跨线程的通信和控制。

3. **建立音视频流的底层 Source 和 Sink:**
   - `RTCRtpScriptTransform::CreateAudioUnderlyingSourceAndSink` 和 `RTCRtpScriptTransform::CreateVideoUnderlyingSourceAndSink` 方法用于创建与可编程变换器交互的底层数据流。
   - 这些方法将断开连接的回调函数 (`disconnect_callback_source`) 和编码后的音视频数据流转换器 (`RTCEncodedAudioStreamTransformer::Broker`, `RTCEncodedVideoStreamTransformer::Broker`) 传递给 Worker 线程的 `RTCRtpScriptTransformer`。这使得 Worker 中的脚本能够接收和处理音视频数据。

4. **关联到 RTCRtpReceiver:**
   - `RTCRtpScriptTransform::AttachToReceiver` 方法将 `RTCRtpScriptTransform` 实例与一个 `RTCRtpReceiver` 关联起来。`RTCRtpReceiver` 代表接收到的 RTP 流。
   - 这个关联使得变换器能够处理特定接收器接收到的数据。

5. **分离变换器:**
   - `RTCRtpScriptTransform::Detach` 方法用于断开变换器与接收器的连接，并清理相关的资源。
   - 它会重置相关的成员变量，并通知 Worker 线程清理 `RTCRtpScriptTransformer`。

6. **处理关键帧请求:**
   - `RTCRtpScriptTransform::HandleSendKeyFrameRequestResults` 方法检查是否可以发送关键帧请求。它会检查接收器是否存在，是否为视频轨道，以及接收器的方向是否允许发送数据。
   - `RTCRtpScriptTransform::SendKeyFrameRequestToReceiver` 方法向 `RTCRtpScriptTransformer` 发送请求，触发 Worker 线程向视频源请求关键帧。

**与 JavaScript, HTML, CSS 的关系**

这个文件是 Blink 引擎的 C++ 代码，主要负责底层的逻辑实现。它与 JavaScript, HTML, CSS 的交互体现在以下几个方面：

* **JavaScript:**
    - **API 暴露:**  `RTCRtpScriptTransform` 类提供的功能最终会通过 WebRTC 的 JavaScript API 暴露给开发者，例如 `RTCRtpReceiver.transform` 属性。
    - **Worker 通信:** 该文件中的代码涉及到与 Web Worker 的通信。开发者在 JavaScript 中创建的 `TransformStream` 会被传递到 Worker 中，而 `RTCRtpScriptTransform` 负责在 C++ 层管理这个过程。
    - **脚本执行环境:**  开发者编写的用于处理 RTP 数据的 JavaScript 代码将在 Worker 线程中执行，而 `RTCRtpScriptTransformer` 是在 Worker 中运行该脚本的关键组件。

    **例子：**

    ```javascript
    // 在 JavaScript 中获取 RTCRtpReceiver
    const receiver = pc.getReceivers()[0];

    // 创建一个 TransformStream
    const transformStream = new TransformStream({
      transform: (chunk, controller) => {
        // 在这里处理接收到的 RTP 数据包 (chunk)
        // 例如，修改 payload 或者 header
        controller.enqueue(chunk);
      }
    });

    // 将 TransformStream 设置给 receiver 的 transform 属性
    receiver.transform = transformStream;
    ```

* **HTML:**
    - **媒体元素的呈现:**  经过 `RTCRtpScriptTransform` 处理后的媒体数据最终会渲染到 HTML 中的 `<video>` 或 `<audio>` 元素上。
    - **用户交互触发:**  用户的操作，例如点击按钮触发通话，或者调整视频质量，可能会间接地导致 `RTCRtpScriptTransform` 的创建和激活。

    **例子：**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>WebRTC with Transform</title>
    </head>
    <body>
      <video id="remoteVideo" autoplay playsinline></video>
      <script src="script.js"></script>
    </body>
    </html>
    ```

* **CSS:**
    - **样式控制:** CSS 可以控制 `<video>` 或 `<audio>` 元素的样式，例如大小、位置、边框等。虽然 CSS 不直接参与 RTP 数据的变换过程，但它影响着最终呈现给用户的媒体效果。

    **例子：**

    ```css
    #remoteVideo {
      width: 640px;
      height: 480px;
    }
    ```

**逻辑推理的假设输入与输出**

假设输入：一个接收到的 RTP 数据包。

输出：经过 Worker 中 JavaScript 代码处理后的 RTP 数据包。

**详细的假设输入与输出：**

1. **假设输入 (主线程):**  JavaScript 代码创建了一个 `TransformStream` 并将其赋值给 `RTCRtpReceiver.transform`。
2. **逻辑推理 (C++):**
   - `RTCRtpReceiver` 检测到 `transform` 属性被设置。
   - `RTCRtpScriptTransform::Create` 被调用，创建一个 `RTCRtpScriptTransform` 实例并在 Worker 线程中创建 `RTCRtpScriptTransformer`。
   - `TransformStream` 的 readable 和 writable sides 被传递到 Worker。
3. **假设输入 (Worker 线程):**  接收到来自网络的原始 RTP 数据包。
4. **逻辑推理 (Worker 线程):**
   - `RTCRtpScriptTransformer` 接收到 RTP 数据包。
   - 它将数据包通过 `TransformStream` 的 writable side 发送给用户定义的 JavaScript `transform` 函数。
   - JavaScript 代码对数据包进行处理（例如，修改时间戳，加密 payload）。
   - 处理后的数据包通过 `TransformStream` 的 readable side 返回。
5. **输出 (主线程):**  `RTCRtpScriptTransformer` 将处理后的 RTP 数据包发送给解码器进行后续处理。

**用户或编程常见的使用错误**

1. **在 Worker 脚本中抛出异常:** 如果开发者在 Worker 的 `transform` 函数中编写的代码抛出异常，可能会导致媒体流处理中断，并且难以调试。
   - **例子:**  Worker 脚本中尝试访问未定义的变量。
   - **现象:**  视频或音频流停止，控制台可能显示错误信息，但具体的错误原因可能需要查看 Worker 的日志。

2. **不正确地处理 RTP 数据包:** 开发者可能对 RTP 协议理解不足，导致在 Worker 脚本中错误地修改了 RTP 包的 header 或 payload，破坏了数据包的结构。
   - **例子:**  错误地修改了序列号或时间戳。
   - **现象:**  可能导致视频花屏、音频失真、丢包等问题。

3. **性能问题:**  在 Worker 脚本中执行过于复杂的计算可能会导致性能问题，影响实时通信的质量。
   - **例子:**  在 Worker 中进行耗时的图像处理操作。
   - **现象:**  可能导致延迟增加、帧率下降。

4. **忘记处理 `disconnect_callback_source`:**  当 `RTCRtpReceiver` 不再接收数据时，需要调用 `disconnect_callback_source` 来清理 Worker 侧的资源。忘记处理可能导致资源泄漏。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户打开一个包含 WebRTC 功能的网页:** 网页的 JavaScript 代码会使用 `navigator.mediaDevices.getUserMedia()` 获取本地媒体流，并创建一个 `RTCPeerConnection` 对象来建立连接。
2. **网页调用 `RTCPeerConnection.addTransceiver()` 或处理 `track` 事件:**  当需要接收远程媒体流时，网页会使用 `addTransceiver()` 方法，或者监听 `RTCPeerConnection` 的 `track` 事件来获取 `RTCRtpReceiver` 对象。
3. **网页获取 `RTCRtpReceiver` 对象:** 通过 `pc.getReceivers()` 可以获取到表示接收到的媒体轨道的 `RTCRtpReceiver` 对象。
4. **网页设置 `RTCRtpReceiver.transform` 属性:**  开发者创建了一个 `TransformStream` 对象，并在其 `transform` 属性中定义了处理 RTP 数据包的 JavaScript 函数。然后将这个 `TransformStream` 赋值给 `receiver.transform`。
5. **Blink 引擎创建 `RTCRtpScriptTransform`:** 当 `receiver.transform` 被设置时，Blink 引擎的 C++ 代码会创建 `RTCRtpScriptTransform` 对象，并负责在 Worker 线程中启动相应的处理逻辑。
6. **RTP 数据包到达:**  一旦 WebRTC 连接建立，远程端发送的 RTP 数据包到达本地。
7. **数据包经过 `RTCRtpScriptTransform` 处理:**  到达的 RTP 数据包会被传递到与 `RTCRtpReceiver` 关联的 `RTCRtpScriptTransform` 对象。
8. **`RTCRtpScriptTransform` 将数据包传递给 Worker:**  `RTCRtpScriptTransform` 通过内部机制将 RTP 数据包发送到在 Worker 线程中运行的 `RTCRtpScriptTransformer`。
9. **Worker 中的 JavaScript 代码处理数据包:**  Worker 中的 `transform` 函数接收到 RTP 数据包，并执行开发者定义的处理逻辑。
10. **处理后的数据包返回主线程:**  经过 Worker 处理后的数据包被返回到主线程的 `RTCRtpScriptTransform`。
11. **数据包被解码并渲染:**  最终，处理后的 RTP 数据包被 WebRTC 的解码器解码，并渲染到 HTML 的 `<video>` 或 `<audio>` 元素上。

**调试线索：**

* **检查 `chrome://webrtc-internals/`:**  这个页面提供了详细的 WebRTC 内部状态信息，包括 `RTCRtpReceiver` 的 `transform` 状态，以及可能出现的错误信息。
* **Worker 的控制台日志:**  在开发者工具中查看 Worker 的控制台日志，可以了解 Worker 脚本的执行情况，包括是否有异常抛出或日志输出。
* **断点调试:**  可以在 Worker 脚本的 `transform` 函数中设置断点，逐步查看 RTP 数据包的处理过程。
* **网络抓包:**  使用 Wireshark 等工具抓取网络包，可以查看原始的 RTP 数据包，以及经过变换后的数据包，对比两者之间的差异。

希望以上分析能够帮助你理解 `rtc_rtp_script_transform.cc` 文件的功能和它在 WebRTC 中的作用。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_script_transform.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_script_transform.h"

#include "base/functional/callback.h"
#include "base/functional/callback_forward.h"
#include "base/sequence_checker.h"
#include "rtc_rtp_script_transform.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/workers/custom_event_message.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_script_transformer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_transform_event.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

namespace {

// This method runs in the worker context, triggered by a callback.
Event* CreateRTCTransformEvent(
    CrossThreadWeakHandle<RTCRtpScriptTransform> transform,
    scoped_refptr<base::SequencedTaskRunner> transform_task_runner,
    ScriptState* script_state,
    CustomEventMessage data) {
  auto* event = MakeGarbageCollected<RTCTransformEvent>(
      script_state, std::move(data), transform_task_runner, transform);

  PostCrossThreadTask(
      *transform_task_runner, FROM_HERE,
      CrossThreadBindOnce(
          &RTCRtpScriptTransform::SetRtpTransformer,
          MakeUnwrappingCrossThreadWeakHandle(transform),
          MakeCrossThreadWeakHandle(event->transformer()),
          WrapRefCounted(ExecutionContext::From(script_state)
                             ->GetTaskRunner(TaskType::kInternalMediaRealTime)
                             .get())));
  return event;
}

bool IsValidReceiverDirection(
    std::optional<V8RTCRtpTransceiverDirection> direction) {
  if (!direction.has_value()) {
    return false;
  }
  return direction.value().AsEnum() ==
             V8RTCRtpTransceiverDirection::Enum::kSendrecv ||
         direction.value().AsEnum() ==
             V8RTCRtpTransceiverDirection::Enum::kRecvonly;
}

}  // namespace

RTCRtpScriptTransform* RTCRtpScriptTransform::Create(
    ScriptState* script_state,
    DedicatedWorker* worker,
    ExceptionState& exception_state) {
  return Create(script_state, worker, ScriptValue(), /* transfer= */ {},
                exception_state);
}

RTCRtpScriptTransform* RTCRtpScriptTransform::Create(
    ScriptState* script_state,
    DedicatedWorker* worker,
    const ScriptValue& message,
    ExceptionState& exception_state) {
  return Create(script_state, worker, message, /* transfer= */ {},
                exception_state);
}

RTCRtpScriptTransform* RTCRtpScriptTransform::Create(
    ScriptState* script_state,
    DedicatedWorker* worker,
    const ScriptValue& message,
    HeapVector<ScriptValue> transfer,
    ExceptionState& exception_state) {
  auto* transform = MakeGarbageCollected<RTCRtpScriptTransform>();
  worker->PostCustomEvent(
      TaskType::kInternalMediaRealTime, script_state,
      CrossThreadBindRepeating(
          &CreateRTCTransformEvent, MakeCrossThreadWeakHandle(transform),
          ExecutionContext::From(script_state)
              ->GetTaskRunner(TaskType::kInternalMediaRealTime)),
      CrossThreadFunction<Event*(ScriptState*)>(), message, transfer,
      exception_state);
  return transform;
}

void RTCRtpScriptTransform::CreateAudioUnderlyingSourceAndSink(
    WTF::CrossThreadOnceClosure disconnect_callback_source,
    scoped_refptr<blink::RTCEncodedAudioStreamTransformer::Broker>
        encoded_audio_transformer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (rtp_transformer_) {
    SetUpAudioRtpTransformer(std::move(disconnect_callback_source),
                             std::move(encoded_audio_transformer));
  } else {
    // Saving these fields so once the transformer is set,
    // SetUpAudioRtpTransformer can be called.
    encoded_audio_transformer_ = std::move(encoded_audio_transformer);
    disconnect_callback_source_ = std::move(disconnect_callback_source);
  }
}

void RTCRtpScriptTransform::CreateVideoUnderlyingSourceAndSink(
    WTF::CrossThreadOnceClosure disconnect_callback_source,
    scoped_refptr<blink::RTCEncodedVideoStreamTransformer::Broker>
        encoded_video_transformer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (rtp_transformer_) {
    SetUpVideoRtpTransformer(std::move(disconnect_callback_source),
                             std::move(encoded_video_transformer));
  } else {
    // Saving these fields so once the transformer is set,
    // SetUpVideoRtpTransformer can be called.
    encoded_video_transformer_ = std::move(encoded_video_transformer);
    disconnect_callback_source_ = std::move(disconnect_callback_source);
  }
}

void RTCRtpScriptTransform::SetUpAudioRtpTransformer(
    WTF::CrossThreadOnceClosure disconnect_callback_source,
    scoped_refptr<blink::RTCEncodedAudioStreamTransformer::Broker>
        encoded_audio_transformer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(rtp_transformer_);
  PostCrossThreadTask(
      *rtp_transformer_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(
          &RTCRtpScriptTransformer::SetUpAudio,
          MakeUnwrappingCrossThreadWeakHandle(*rtp_transformer_),
          std::move(disconnect_callback_source),
          std::move(encoded_audio_transformer)));
}

void RTCRtpScriptTransform::SetUpVideoRtpTransformer(
    WTF::CrossThreadOnceClosure disconnect_callback_source,
    scoped_refptr<blink::RTCEncodedVideoStreamTransformer::Broker>
        encoded_video_transformer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(rtp_transformer_);
  PostCrossThreadTask(
      *rtp_transformer_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(
          &RTCRtpScriptTransformer::SetUpVideo,
          MakeUnwrappingCrossThreadWeakHandle(*rtp_transformer_),
          std::move(disconnect_callback_source),
          std::move(encoded_video_transformer)));
}

void RTCRtpScriptTransform::SetRtpTransformer(
    CrossThreadWeakHandle<RTCRtpScriptTransformer> transformer,
    scoped_refptr<base::SingleThreadTaskRunner> transformer_task_runner) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  rtp_transformer_.emplace(std::move(transformer));
  rtp_transformer_task_runner_ = std::move(transformer_task_runner);
  if (disconnect_callback_source_ && encoded_audio_transformer_) {
    SetUpAudioRtpTransformer(std::move(disconnect_callback_source_),
                             std::move(encoded_audio_transformer_));
    return;
  }
  if (disconnect_callback_source_ && encoded_video_transformer_) {
    SetUpVideoRtpTransformer(std::move(disconnect_callback_source_),
                             std::move(encoded_video_transformer_));
  }
}

void RTCRtpScriptTransform::AttachToReceiver(RTCRtpReceiver* receiver) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!is_attached_);
  is_attached_ = true;
  receiver_ = receiver;
}

void RTCRtpScriptTransform::Detach() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_attached_ = false;
  receiver_ = nullptr;
  encoded_video_transformer_ = nullptr;
  encoded_audio_transformer_ = nullptr;
  disconnect_callback_source_.Reset();
  if (rtp_transformer_) {
    PostCrossThreadTask(
        *rtp_transformer_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(
            &RTCRtpScriptTransformer::Clear,
            MakeUnwrappingCrossThreadWeakHandle(*rtp_transformer_)));
  }
}

RTCRtpScriptTransform::SendKeyFrameRequestResult
RTCRtpScriptTransform::HandleSendKeyFrameRequestResults() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!rtp_transformer_) {
    return SendKeyFrameRequestResult::kInvalidState;
  }
  if (!receiver_) {
    return SendKeyFrameRequestResult::kNoReceiver;
  }
  if (receiver_->kind() == RTCRtpReceiver::MediaKind::kAudio) {
    return SendKeyFrameRequestResult::kNoVideo;
  }
  if (!IsValidReceiverDirection(receiver_->TransceiverDirection()) ||
      !IsValidReceiverDirection(receiver_->TransceiverCurrentDirection())) {
    return SendKeyFrameRequestResult::kInvalidState;
  }
  if (receiver_->track()->readyState() ==
      V8MediaStreamTrackState::Enum::kEnded) {
    return SendKeyFrameRequestResult::kTrackEnded;
  }
  MediaStreamVideoSource* video_source = MediaStreamVideoSource::GetVideoSource(
      receiver_->track()->Component()->Source());
  video_source->RequestKeyFrame();
  return SendKeyFrameRequestResult::kSuccess;
}

void RTCRtpScriptTransform::SendKeyFrameRequestToReceiver(
    CrossThreadFunction<void(const SendKeyFrameRequestResult)> callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  SendKeyFrameRequestResult result = HandleSendKeyFrameRequestResults();
  PostCrossThreadTask(*rtp_transformer_task_runner_, FROM_HERE,
                      WTF::CrossThreadBindOnce(std::move(callback), result));
}

void RTCRtpScriptTransform::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  visitor->Trace(receiver_);
}

}  // namespace blink
```