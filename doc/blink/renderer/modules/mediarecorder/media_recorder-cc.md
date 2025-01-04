Response:
Let's break down the thought process for analyzing this C++ code for `MediaRecorder`.

1. **Understand the Core Functionality:** The filename and the `#include` directives immediately suggest this file implements the `MediaRecorder` Web API in the Blink rendering engine. The copyright notice confirms this. The core purpose of `MediaRecorder` is to record media streams (audio and/or video).

2. **Identify Key Dependencies:** The `#include` list reveals crucial components:
    * Platform services (`platform/`) like task runners and time.
    * Core DOM (`core/dom/`, `core/events/`).
    * Bindings to JavaScript (`bindings/`). This is critical for understanding the JavaScript interaction.
    * Media-specific components (`modules/mediarecorder/`, `platform/mediastream/`).
    * File handling (`core/fileapi/`).
    * Networking (`platform/network/`).
    * Privacy budget considerations (`public/common/privacy_budget/`).

3. **Analyze Class Structure and Members:** The `MediaRecorder` class itself is the central point. Look at its member variables:
    * `stream_`: The `MediaStream` being recorded.
    * `mime_type_`: The desired recording format.
    * `state_`:  The current recording state (inactive, recording, paused).
    * `recorder_handler_`: A pointer to a separate object (`MediaRecorderHandler`) that seems to handle the lower-level recording logic. This separation of concerns is important.
    * `audio_bits_per_second_`, `video_bits_per_second_`, `overall_bits_per_second_`:  Bitrate settings.
    * `blob_data_`:  A buffer to accumulate recorded data.
    * `scheduled_events_`:  A queue for events to be dispatched to the JavaScript side.
    * `first_write_received_`: A flag.
    * `blob_event_first_chunk_timecode_`: For timing.

4. **Examine Key Methods:**  Focus on the public and important private methods:
    * **Constructors (`Create`, `MediaRecorder`)**: How is the object created and initialized?  Pay attention to parameter passing and error handling.
    * **State Management (`start`, `stop`, `pause`, `resume`)**: How is the recording lifecycle controlled?  What state transitions are allowed?  What errors can occur?
    * **Data Handling (`requestData`, `WriteData`, `CreateBlobEvent`)**: How is the recorded data processed and made available to JavaScript? The role of `Blob` is key here.
    * **Error Handling (`OnError`)**: How are errors during recording reported?
    * **Type Support (`isTypeSupported`)**: How does the browser determine if a given MIME type is supported for recording?
    * **Event Handling (`ScheduleDispatchEvent`, `DispatchScheduledEvent`)**:  How are events like `dataavailable`, `start`, `stop`, `error` communicated back to the JavaScript environment?  The use of a task queue is significant.
    * **Context Management (`ContextDestroyed`)**: What happens when the browser tab or window is closed?

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where the "why" comes in.
    * **JavaScript:** The `MediaRecorder` class is a direct implementation of the JavaScript `MediaRecorder` API. Think about how a JavaScript developer would interact with this code: creating the object, calling `start`, handling `dataavailable` events, etc. The binding code (implied by `#include "third_party/blink/renderer/bindings/..."`) is the bridge.
    * **HTML:**  The `MediaStream` being recorded often originates from HTML elements like `<video>` or `<audio>` (via APIs like `getUserMedia`).
    * **CSS:** CSS doesn't directly control the `MediaRecorder`'s functionality, but it can affect the *visual* presentation of the media being recorded (e.g., the dimensions of a video).

6. **Identify Logic and Assumptions:** Look for conditional statements, loops, and calculations. Consider edge cases and potential issues. For example, the bitrate clamping logic shows an attempt to handle invalid or out-of-range bitrate values.

7. **Infer User and Programming Errors:**  Based on the error handling and the API design, what mistakes might a user or developer make?  Examples include calling methods in the wrong order, providing unsupported MIME types, or not handling errors properly.

8. **Trace User Actions:**  Think about the sequence of user interactions that would lead to this code being executed. This is crucial for debugging. A user clicking a "Record" button, which calls a JavaScript function that uses `MediaRecorder`, is a typical scenario.

9. **Structure the Output:** Organize the findings into logical categories (functionality, relationships to web technologies, logical reasoning, common errors, debugging). Use clear language and provide specific examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file does *all* the recording.
* **Correction:**  The presence of `MediaRecorderHandler` suggests a separation of concerns. This file likely manages the API surface and event dispatching, while the handler does the heavy lifting.
* **Initial thought:** Bitrates are just passed through.
* **Correction:**  The clamping logic indicates that the browser enforces certain bitrate limits.
* **Initial thought:**  JavaScript interacts directly with this C++ code.
* **Correction:** The bindings layer handles the communication between JavaScript and C++.

By following these steps and continually refining the understanding, you can produce a comprehensive analysis like the example provided in the prompt.
好的，让我们详细分析一下 `blink/renderer/modules/mediarecorder/media_recorder.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概览:**

这个文件实现了 Web API 中的 `MediaRecorder` 接口。`MediaRecorder` 允许网页录制来自 `MediaStream` 对象（通常来自用户的摄像头、麦克风或者屏幕共享）的音频和/或视频数据。其主要功能包括：

1. **初始化和配置:**  接收一个 `MediaStream` 对象和一个可选的 `MediaRecorderOptions` 对象作为参数，用于配置录制的 MIME 类型、比特率等。
2. **开始录制:**  调用 `start()` 方法开始从 `MediaStream` 中捕获数据。可以设置一个 `timeSlice` 参数来定期触发 `dataavailable` 事件，提供录制的数据片段。
3. **停止录制:**  调用 `stop()` 方法停止录制，并触发一个 `stop` 事件。
4. **暂停和恢复录制:**  调用 `pause()` 和 `resume()` 方法暂停和恢复录制过程。
5. **请求数据:**  调用 `requestData()` 方法可以强制触发 `dataavailable` 事件，即使没有达到 `timeSlice` 设置的时间间隔。
6. **判断类型支持:**  提供静态方法 `isTypeSupported()` 来检查浏览器是否支持特定的 MIME 类型进行录制。
7. **事件派发:**  在录制的不同阶段（开始、数据可用、停止、暂停、恢复、错误）派发相应的事件给 JavaScript 代码。
8. **错误处理:**  处理录制过程中可能出现的错误，例如不支持的 MIME 类型、无效的状态等，并触发 `error` 事件。
9. **资源管理:**  在对象销毁或者执行上下文销毁时释放相关资源。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件是浏览器引擎 Blink 的一部分，它直接实现了 JavaScript 的 `MediaRecorder` API。这意味着 JavaScript 代码通过这个 C++ 代码来实现媒体录制的功能。

**JavaScript 交互：**

```javascript
navigator.mediaDevices.getUserMedia({ audio: true, video: true })
  .then(function(stream) {
    const options = { mimeType: 'video/webm; codecs=vp9' };
    const mediaRecorder = new MediaRecorder(stream, options);

    mediaRecorder.ondataavailable = function(event) {
      console.log('Data available:', event.data);
      // 将录制的数据（Blob 对象）发送到服务器或进行其他处理
    };

    mediaRecorder.onstart = function() {
      console.log('Recording started!');
    };

    mediaRecorder.onstop = function() {
      console.log('Recording stopped!');
    };

    mediaRecorder.onerror = function(event) {
      console.error('Recording error:', event.error);
    };

    mediaRecorder.start(1000); // 每秒触发一次 dataavailable 事件
    setTimeout(() => mediaRecorder.stop(), 5000); // 5秒后停止录制
  })
  .catch(function(err) {
    console.error('Could not get media:', err);
  });
```

在这个 JavaScript 例子中：

* `new MediaRecorder(stream, options)`:  JavaScript 创建 `MediaRecorder` 对象时，会调用 C++ 层的构造函数 `MediaRecorder::Create`。`stream` 和 `options` 会被传递到 C++ 代码中。
* `mediaRecorder.start(1000)`:  JavaScript 调用 `start()` 方法时，会调用 C++ 层的 `MediaRecorder::start()` 方法，并传入 `timeSlice` 参数。
* `mediaRecorder.ondataavailable = ...`: 当 C++ 代码中的 `WriteData` 方法接收到录制的数据片段并准备好一个 Blob 对象时，会创建一个 `BlobEvent` 并派发，这个事件会被 JavaScript 的 `ondataavailable` 事件处理函数捕获。
* `mediaRecorder.stop()`: JavaScript 调用 `stop()` 方法时，会调用 C++ 层的 `MediaRecorder::stop()` 方法。
* `mediaRecorder.isTypeSupported('video/mp4')`: JavaScript 调用静态方法 `MediaRecorder.isTypeSupported()` 时，会调用 C++ 层的静态方法 `MediaRecorder::isTypeSupported()`。

**HTML 交互：**

HTML 元素，尤其是 `<video>` 和 `<audio>` 元素，通常是 `MediaStream` 的来源。用户通过浏览器提供的权限提示允许网站访问这些设备后，JavaScript 代码可以获取到对应的 `MediaStream` 对象，然后传递给 `MediaRecorder`。

```html
<video id="myVideo" autoplay muted></video>
<button id="recordButton">开始录制</button>

<script>
  const videoElement = document.getElementById('myVideo');
  const recordButton = document.getElementById('recordButton');

  recordButton.addEventListener('click', () => {
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(stream => {
        videoElement.srcObject = stream; // 将摄像头画面显示在 video 元素中
        const recorder = new MediaRecorder(stream);
        // ... (录制逻辑如上)
      });
  });
</script>
```

在这个例子中，HTML 的 `<video>` 元素用于显示摄像头画面，虽然 CSS 可以控制其样式，但 `MediaRecorder` 的核心功能并不直接受 CSS 控制。HTML 主要提供了媒体流的来源。

**CSS 交互：**

CSS 不直接影响 `MediaRecorder` 的录制逻辑。但是，CSS 可以影响用户界面的呈现，例如录制按钮的样式，或者正在录制时的指示器。

**逻辑推理 (假设输入与输出):**

**假设输入：**

* 一个包含音频和视频轨道的 `MediaStream` 对象。
* `MediaRecorderOptions` 设置为录制 `video/webm` 格式，没有指定比特率。
* 调用 `start(2000)` 方法。

**逻辑推理过程：**

1. `MediaRecorder` 对象被创建，接收 `MediaStream` 和 `MediaRecorderOptions`。
2. `start(2000)` 被调用，设置 `timeSlice` 为 2000 毫秒。
3. 底层的 `MediaRecorderHandler` 开始从 `MediaStream` 中读取音频和视频数据。
4. 由于没有指定比特率，会使用默认的音频和视频比特率（`kDefaultAudioBitRate` 和 `kDefaultVideoBitRate`）。
5. 每隔 2000 毫秒，或者在内部缓冲区积累了一定的数据后，`MediaRecorderHandler` 会将数据传递给 `MediaRecorder::WriteData`。
6. `WriteData` 方法会将数据添加到内部的 `blob_data_` 中。
7. 当 `last_in_slice` 为 `true` 时（通常是 `timeSlice` 到达时），`WriteData` 会创建一个包含当前数据的 `Blob` 对象，并创建一个 `BlobEvent`。
8. 这个 `BlobEvent` 会被添加到 `scheduled_events_` 队列中，等待被派发到 JavaScript。

**预期输出：**

* 每隔大约 2 秒，JavaScript 的 `ondataavailable` 事件处理函数会被调用，接收到一个包含录制数据的 `Blob` 对象。
* `Blob` 对象的 `type` 属性应该为 `video/webm`。
* 如果在录制过程中发生错误（例如，编码失败），JavaScript 的 `onerror` 事件处理函数会被调用。
* 当调用 `stop()` 方法后，JavaScript 的 `onstop` 事件处理函数会被调用。

**用户或编程常见的使用错误及举例说明:**

1. **在 `inactive` 状态下调用 `requestData()`:**

   ```javascript
   const recorder = new MediaRecorder(stream);
   recorder.ondataavailable = (event) => console.log(event.data);
   recorder.requestData(); // 错误：此时状态为 'inactive'
   ```

   **错误说明:** `requestData()` 只能在 `recording` 或 `paused` 状态下调用。在 `inactive` 状态下调用会抛出一个 `InvalidStateError` 异常。

2. **多次调用 `start()` 而不先 `stop()`:**

   ```javascript
   const recorder = new MediaRecorder(stream);
   recorder.start();
   recorder.start(); // 错误：状态已经是 'recording'
   ```

   **错误说明:**  只能在 `inactive` 状态下调用 `start()`。如果当前状态已经是 `recording` 或 `paused`，调用 `start()` 会抛出一个 `InvalidStateError` 异常。

3. **提供浏览器不支持的 MIME 类型:**

   ```javascript
   const options = { mimeType: 'audio/flac' }; // 假设浏览器不支持录制 FLAC
   const recorder = new MediaRecorder(stream, options);
   recorder.start(); // 可能会触发 onerror 事件，或者在构造时就抛出异常
   ```

   **错误说明:**  如果浏览器不支持指定的 MIME 类型，`MediaRecorder` 的初始化可能会失败，或者在调用 `start()` 时触发 `error` 事件。开发者应该使用 `MediaRecorder.isTypeSupported()` 来检查支持性。

4. **在 `stop()` 之后尝试操作录制器:**

   ```javascript
   const recorder = new MediaRecorder(stream);
   recorder.start();
   setTimeout(() => {
     recorder.stop();
     recorder.requestData(); // 错误：状态已经是 'inactive'
   }, 2000);
   ```

   **错误说明:**  一旦调用 `stop()`，`MediaRecorder` 的状态变为 `inactive`。在 `inactive` 状态下调用 `requestData()` 等方法会抛出 `InvalidStateError` 异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在网页上点击了一个 "开始录制" 按钮，以下是可能的步骤，最终会涉及到 `media_recorder.cc` 文件中的代码：

1. **用户操作:** 用户点击网页上的 "开始录制" 按钮。
2. **JavaScript 事件处理:**  按钮的 `click` 事件被 JavaScript 代码捕获。
3. **创建 MediaStream (如果尚未存在):**  JavaScript 代码可能首先调用 `navigator.mediaDevices.getUserMedia()` 或 `getDisplayMedia()` 来获取用户的摄像头/麦克风或屏幕共享的 `MediaStream` 对象。这会涉及到浏览器引擎中处理媒体设备访问权限的代码。
4. **创建 MediaRecorder 对象:**  JavaScript 代码使用获取到的 `MediaStream` 对象和一个可选的配置对象（`MediaRecorderOptions`）创建 `MediaRecorder` 对象： `const recorder = new MediaRecorder(stream, options);`。
   * **调试线索:** 在浏览器开发者工具的 "Sources" 面板中，可以设置断点在 `new MediaRecorder()` 的位置，查看传入的 `stream` 和 `options` 的值。
5. **设置事件监听器:**  JavaScript 代码会设置 `ondataavailable`, `onstart`, `onstop`, `onerror` 等事件的监听器来处理录制过程中的事件。
   * **调试线索:**  检查这些事件监听器是否正确绑定，以及处理函数是否包含预期的逻辑。
6. **调用 `recorder.start()`:**  JavaScript 代码调用 `recorder.start()` 方法启动录制。
   * **调试线索:** 在浏览器开发者工具中，可以设置断点在 `recorder.start()` 的调用处，单步执行，观察 `MediaRecorder` 对象的状态变化。
7. **进入 Blink 引擎的 C++ 代码:**  当 JavaScript 调用 `recorder.start()` 时，V8 引擎（Chrome 的 JavaScript 引擎）会将这个调用桥接到 Blink 引擎中 `media_recorder.cc` 文件的 `MediaRecorder::start()` 方法。
   * **调试线索:** 如果需要在 C++ 代码中调试，可以使用 Chrome 提供的调试工具（例如，使用 `gdb` 连接到 Chrome 的渲染进程），并在 `MediaRecorder::start()` 方法入口处设置断点。
8. **数据处理和事件派发:**  `MediaRecorder::start()` 方法会初始化底层的 `MediaRecorderHandler`，并开始从 `MediaStream` 中接收数据。数据到达后，`MediaRecorder::WriteData()` 方法会被调用，最终触发 `dataavailable` 事件。
   * **调试线索:** 可以设置断点在 `MediaRecorder::WriteData()` 和 `MediaRecorder::ScheduleDispatchEvent()` 方法中，观察数据的流向和事件的派发过程。
9. **JavaScript 事件处理函数执行:**  当 `dataavailable` 事件被派发回 JavaScript 时，之前设置的 `ondataavailable` 事件处理函数会被执行，处理录制到的数据。
10. **用户停止录制:**  用户可能再次点击 "停止录制" 按钮，JavaScript 代码调用 `recorder.stop()`。
11. **Blink 引擎处理停止操作:**  JavaScript 的 `recorder.stop()` 调用会桥接到 `media_recorder.cc` 的 `MediaRecorder::stop()` 方法。
   * **调试线索:** 可以在 `MediaRecorder::stop()` 方法入口处设置断点，观察停止录制时的资源清理和状态更新。
12. **派发 `stop` 事件:**  `MediaRecorder::stop()` 方法会触发 `stop` 事件，JavaScript 的 `onstop` 事件处理函数会被执行。

通过上述步骤，我们可以看到用户操作如何一步步地触发 JavaScript 代码，最终调用到 Blink 引擎的 C++ 代码，完成媒体录制的功能。在调试过程中，结合浏览器开发者工具和 C++ 调试工具，可以深入理解代码的执行流程和状态变化。

Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder.h"

#include <algorithm>
#include <limits>

#include "base/time/time.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_error_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_recording_state.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/mediarecorder/blob_event.h"
#include "third_party/blink/renderer/modules/mediarecorder/video_track_recorder.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

struct MediaRecorderBitrates {
  const std::optional<uint32_t> audio_bps;
  const std::optional<uint32_t> video_bps;
  const std::optional<uint32_t> overall_bps;
};

// Boundaries of Opus SILK bitrate from https://www.opus-codec.org/.
const int kSmallestPossibleOpusBitRate = 5000;
const int kLargestPossibleOpusBitRate = 510000;

// Smallest Vpx bitrate that can be requested.
// 75kbps is the min bitrate recommended by VP9 VOD settings for 320x240 videos.
const int kSmallestPossibleVpxBitRate = 75000;

// Both values come from YouTube recommended upload encoding settings and are
// used by other browser vendors. See
// https://support.google.com/youtube/answer/1722171?hl=en#zippy=%2Cbitrate
const int kDefaultVideoBitRate = 2500e3;  // 2.5Mbps
const int kDefaultAudioBitRate = 128e3;   // 128kbps

V8RecordingState::Enum StateToV8Enum(MediaRecorder::State state) {
  switch (state) {
    case MediaRecorder::State::kInactive:
      return V8RecordingState::Enum::kInactive;
    case MediaRecorder::State::kRecording:
      return V8RecordingState::Enum::kRecording;
    case MediaRecorder::State::kPaused:
      return V8RecordingState::Enum::kPaused;
  }
  NOTREACHED();
}

V8BitrateMode::Enum BitrateModeToV8Enum(
    AudioTrackRecorder::BitrateMode bitrateMode) {
  switch (bitrateMode) {
    case AudioTrackRecorder::BitrateMode::kConstant:
      return V8BitrateMode::Enum::kConstant;
    case AudioTrackRecorder::BitrateMode::kVariable:
      return V8BitrateMode::Enum::kVariable;
  }
  NOTREACHED();
}

AudioTrackRecorder::BitrateMode GetBitrateModeFromOptions(
    const MediaRecorderOptions* const options) {
  if (options->hasAudioBitrateMode()) {
    if (options->audioBitrateMode() == V8BitrateMode::Enum::kConstant) {
      return AudioTrackRecorder::BitrateMode::kConstant;
    }
  }

  return AudioTrackRecorder::BitrateMode::kVariable;
}

void LogConsoleMessage(ExecutionContext* context, const String& message) {
  context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kWarning, message));
}

uint32_t ClampAudioBitRate(ExecutionContext* context, uint32_t audio_bps) {
  if (audio_bps > kLargestPossibleOpusBitRate) {
    LogConsoleMessage(
        context,
        String::Format(
            "Clamping calculated audio bitrate (%dbps) to the maximum (%dbps)",
            audio_bps, kLargestPossibleOpusBitRate));
    return kLargestPossibleOpusBitRate;
  }
  if (audio_bps < kSmallestPossibleOpusBitRate) {
    LogConsoleMessage(
        context,
        String::Format(
            "Clamping calculated audio bitrate (%dbps) to the minimum (%dbps)",
            audio_bps, kSmallestPossibleOpusBitRate));
    return kSmallestPossibleOpusBitRate;
  }
  return audio_bps;
}

uint32_t ClampVideoBitRate(ExecutionContext* context, uint32_t video_bps) {
  if (video_bps < kSmallestPossibleVpxBitRate) {
    LogConsoleMessage(
        context,
        String::Format(
            "Clamping calculated video bitrate (%dbps) to the minimum (%dbps)",
            video_bps, kSmallestPossibleVpxBitRate));
    return kSmallestPossibleVpxBitRate;
  }
  return video_bps;
}

// Allocates the requested bit rates from |options| into the respective
// |{audio,video}_bps| (where a value of zero indicates Platform to use
// whatever it sees fit). If |options.bitsPerSecond()| is specified, it
// overrides any specific bitrate, and the UA is free to allocate as desired:
// here a 90%/10% video/audio is used. In all cases where a value is explicited
// or calculated, values are clamped in sane ranges.
// This method throws NotSupportedError.
MediaRecorderBitrates GetBitratesFromOptions(
    ExceptionState& exception_state,
    ExecutionContext* context,
    const MediaRecorderOptions* options) {
  // Clamp incoming values into a signed integer's range.
  // TODO(mcasas): This section would no be needed if the bit rates are signed
  // or double, see https://github.com/w3c/mediacapture-record/issues/48.
  constexpr uint32_t kMaxIntAsUnsigned = std::numeric_limits<int>::max();

  std::optional<uint32_t> audio_bps;
  if (options->hasAudioBitsPerSecond()) {
    audio_bps = std::min(options->audioBitsPerSecond(), kMaxIntAsUnsigned);
  }
  std::optional<uint32_t> video_bps;
  if (options->hasVideoBitsPerSecond()) {
    video_bps = std::min(options->videoBitsPerSecond(), kMaxIntAsUnsigned);
  }
  std::optional<uint32_t> overall_bps;
  if (options->hasBitsPerSecond()) {
    overall_bps = std::min(options->bitsPerSecond(), kMaxIntAsUnsigned);
    audio_bps = ClampAudioBitRate(context, overall_bps.value() / 10);
    video_bps = overall_bps.value() >= audio_bps.value()
                    ? overall_bps.value() - audio_bps.value()
                    : 0u;
    video_bps = ClampVideoBitRate(context, video_bps.value());
  }

  return {audio_bps, video_bps, overall_bps};
}

}  // namespace

MediaRecorder* MediaRecorder::Create(ExecutionContext* context,
                                     MediaStream* stream,
                                     ExceptionState& exception_state) {
  return MakeGarbageCollected<MediaRecorder>(
      context, stream, MediaRecorderOptions::Create(), exception_state);
}

MediaRecorder* MediaRecorder::Create(ExecutionContext* context,
                                     MediaStream* stream,
                                     const MediaRecorderOptions* options,
                                     ExceptionState& exception_state) {
  return MakeGarbageCollected<MediaRecorder>(context, stream, options,
                                             exception_state);
}

MediaRecorder::MediaRecorder(ExecutionContext* context,
                             MediaStream* stream,
                             const MediaRecorderOptions* options,
                             ExceptionState& exception_state)
    : ActiveScriptWrappable<MediaRecorder>({}),
      ExecutionContextLifecycleObserver(context),
      stream_(stream),
      mime_type_(options->mimeType()) {
  if (context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (options->hasVideoKeyFrameIntervalDuration() &&
      options->hasVideoKeyFrameIntervalCount()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Both videoKeyFrameIntervalDuration and videoKeyFrameIntervalCount "
        "can't be specified.");
    return;
  }
  KeyFrameRequestProcessor::Configuration key_frame_config;
  if (options->hasVideoKeyFrameIntervalDuration()) {
    key_frame_config =
        base::Milliseconds(options->videoKeyFrameIntervalDuration());
  } else if (options->hasVideoKeyFrameIntervalCount()) {
    key_frame_config = options->videoKeyFrameIntervalCount();
  }
  recorder_handler_ = MakeGarbageCollected<MediaRecorderHandler>(
      context->GetTaskRunner(TaskType::kInternalMediaRealTime),
      key_frame_config);
  if (!recorder_handler_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "No MediaRecorder handler can be created.");
    return;
  }

  const MediaRecorderBitrates bitrates =
      GetBitratesFromOptions(exception_state, context, options);
  const ContentType content_type(mime_type_);
  if (!recorder_handler_->Initialize(this, stream->Descriptor(),
                                     content_type.GetType(),
                                     content_type.Parameter("codecs"),
                                     GetBitrateModeFromOptions(options))) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Failed to initialize native MediaRecorder the type provided (" +
            mime_type_ + ") is not supported.");
  }

  audio_bits_per_second_ = bitrates.audio_bps.value_or(kDefaultAudioBitRate);
  video_bits_per_second_ = bitrates.video_bps.value_or(kDefaultVideoBitRate);
  overall_bits_per_second_ = bitrates.overall_bps;
}

MediaRecorder::~MediaRecorder() = default;

V8RecordingState MediaRecorder::state() const {
  return V8RecordingState(StateToV8Enum(state_));
}

V8BitrateMode MediaRecorder::audioBitrateMode() const {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    // Return a valid enum value; variable is the default.
    return V8BitrateMode(V8BitrateMode::Enum::kVariable);
  }
  DCHECK(recorder_handler_);
  return V8BitrateMode(
      BitrateModeToV8Enum(recorder_handler_->AudioBitrateMode()));
}

void MediaRecorder::start(ExceptionState& exception_state) {
  start(std::numeric_limits<int>::max() /* timeSlice */, exception_state);
}

void MediaRecorder::start(int time_slice, ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (state_ != State::kInactive) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The MediaRecorder's state is '" + state().AsString() + "'.");
    return;
  }

  if (stream_->getTracks().size() == 0) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "The MediaRecorder cannot start because"
                                      "there are no audio or video tracks "
                                      "available.");
    return;
  }

  state_ = State::kRecording;

  if (stream_->getAudioTracks().size() == 0) {
    audio_bits_per_second_ = 0;
    if (overall_bits_per_second_.has_value()) {
      video_bits_per_second_ = ClampVideoBitRate(
          GetExecutionContext(), overall_bits_per_second_.value());
    }
  }

  if (stream_->getVideoTracks().size() == 0) {
    video_bits_per_second_ = 0;
    if (overall_bits_per_second_.has_value()) {
      audio_bits_per_second_ = ClampAudioBitRate(
          GetExecutionContext(), overall_bits_per_second_.value());
    }
  }

  const ContentType content_type(mime_type_);
  if (!recorder_handler_->Start(time_slice, content_type.GetType(),
                                audio_bits_per_second_,
                                video_bits_per_second_)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "There was an error starting the MediaRecorder.");
  }
}

void MediaRecorder::stop(ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (state_ == State::kInactive) {
    return;
  }

  StopRecording(/*error_event=*/nullptr);
}

void MediaRecorder::pause(ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (state_ == State::kInactive) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The MediaRecorder's state is 'inactive'.");
    return;
  }
  if (state_ == State::kPaused)
    return;

  state_ = State::kPaused;

  recorder_handler_->Pause();

  ScheduleDispatchEvent(Event::Create(event_type_names::kPause));
}

void MediaRecorder::resume(ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (state_ == State::kInactive) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The MediaRecorder's state is 'inactive'.");
    return;
  }
  if (state_ == State::kRecording)
    return;

  state_ = State::kRecording;

  recorder_handler_->Resume();
  ScheduleDispatchEvent(Event::Create(event_type_names::kResume));
}

void MediaRecorder::requestData(ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Execution context is detached.");
    return;
  }
  if (state_ == State::kInactive) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The MediaRecorder's state is 'inactive'.");
    return;
  }

  WriteData(/*data=*/{}, /*last_in_slice=*/true, /*error_event=*/nullptr);
}

bool MediaRecorder::isTypeSupported(ExecutionContext* context,
                                    const String& type) {
  MediaRecorderHandler* handler = MakeGarbageCollected<MediaRecorderHandler>(
      context->GetTaskRunner(TaskType::kInternalMediaRealTime),
      KeyFrameRequestProcessor::Configuration());
  if (!handler)
    return false;

  // If true is returned from this method, it only indicates that the
  // MediaRecorder implementation is capable of recording Blob objects for the
  // specified MIME type. Recording may still fail if sufficient resources are
  // not available to support the concrete media encoding.
  // https://w3c.github.io/mediacapture-record/#dom-mediarecorder-istypesupported
  ContentType content_type(type);
  bool result = handler->CanSupportMimeType(content_type.GetType(),
                                            content_type.Parameter("codecs"));
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kMediaRecorder_IsTypeSupported)) {
    blink::IdentifiabilityMetricBuilder(context->UkmSourceID())
        .Add(blink::IdentifiableSurface::FromTypeAndToken(
                 blink::IdentifiableSurface::Type::
                     kMediaRecorder_IsTypeSupported,
                 IdentifiabilityBenignStringToken(type)),
             result)
        .Record(context->UkmRecorder());
  }

  return result;
}

const AtomicString& MediaRecorder::InterfaceName() const {
  return event_target_names::kMediaRecorder;
}

ExecutionContext* MediaRecorder::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void MediaRecorder::ContextDestroyed() {
  if (blob_data_) {
    // Cache |blob_data_->length()| because of std::move in argument list.
    const uint64_t blob_data_length = blob_data_->length();
    CreateBlobEvent(MakeGarbageCollected<Blob>(
        BlobDataHandle::Create(std::move(blob_data_), blob_data_length)));
  }

  state_ = State::kInactive;
  stream_.Clear();
  if (recorder_handler_) {
    recorder_handler_->Stop();
    recorder_handler_ = nullptr;
  }
}

void MediaRecorder::WriteData(base::span<const uint8_t> data,
                              bool last_in_slice,
                              ErrorEvent* error_event) {
  if (!first_write_received_) {
    mime_type_ = recorder_handler_->ActualMimeType();
    ScheduleDispatchEvent(Event::Create(event_type_names::kStart));
    first_write_received_ = true;
  }

  if (error_event) {
    ScheduleDispatchEvent(error_event);
  }

  if (!blob_data_) {
    blob_data_ = std::make_unique<BlobData>();
    blob_data_->SetContentType(mime_type_);
  }
  if (!data.empty()) {
    blob_data_->AppendBytes(data);
  }

  if (!last_in_slice)
    return;

  // Cache |blob_data_->length()| because of std::move in argument list.
  const uint64_t blob_data_length = blob_data_->length();
  CreateBlobEvent(MakeGarbageCollected<Blob>(
      BlobDataHandle::Create(std::move(blob_data_), blob_data_length)));
}

void MediaRecorder::OnError(DOMExceptionCode code, const String& message) {
  DVLOG(1) << __func__ << " message=" << message.Ascii();

  ScriptState* script_state =
      ToScriptStateForMainWorld(DomWindow()->GetFrame());
  ScriptState::Scope scope(script_state);
  ScriptValue error_value = ScriptValue::From(
      script_state, MakeGarbageCollected<DOMException>(code, message));
  ErrorEventInit* event_init = ErrorEventInit::Create();
  event_init->setError(error_value);
  StopRecording(
      ErrorEvent::Create(script_state, event_type_names::kError, event_init));
}

void MediaRecorder::OnAllTracksEnded() {
  DVLOG(1) << __func__;
  StopRecording(/*error_event=*/nullptr);
}

void MediaRecorder::OnStreamChanged(const String& message) {
  DVLOG(1) << __func__ << " message=" << message.Ascii()
           << " state_=" << static_cast<int>(state_);
  if (state_ != State::kInactive) {
    OnError(DOMExceptionCode::kInvalidModificationError, message);
  }
}

void MediaRecorder::CreateBlobEvent(Blob* blob) {
  const base::TimeTicks now = base::TimeTicks::Now();
  double timecode = 0;
  if (!blob_event_first_chunk_timecode_.has_value()) {
    blob_event_first_chunk_timecode_ = now;
  } else {
    timecode =
        (now - blob_event_first_chunk_timecode_.value()).InMillisecondsF();
  }

  ScheduleDispatchEvent(MakeGarbageCollected<BlobEvent>(
      event_type_names::kDataavailable, blob, timecode));
}

void MediaRecorder::StopRecording(ErrorEvent* error_event) {
  if (state_ == State::kInactive) {
    // This may happen if all tracks have ended and recording has stopped or
    // never started.
    return;
  }
  if (!recorder_handler_) {
    // This may happen when ContextDestroyed has executed, but the
    // MediaRecorderHandler still exists and all tracks
    // have ended leading to a call to OnAllTracksEnded.
    return;
  }
  // Make sure that starting the recorder again yields an onstart event.
  state_ = State::kInactive;

  recorder_handler_->Stop();
  WriteData(/*data=*/{}, /*last_in_slice=*/true, error_event);
  ScheduleDispatchEvent(Event::Create(event_type_names::kStop));
  first_write_received_ = false;
}

void MediaRecorder::ScheduleDispatchEvent(Event* event) {
  scheduled_events_.push_back(event);
  // Only schedule a post if we are placing the first item in the queue.
  if (scheduled_events_.size() == 1) {
    if (auto* context = GetExecutionContext()) {
      // MediaStream recording should use DOM manipulation task source.
      // https://www.w3.org/TR/mediastream-recording/
      context->GetTaskRunner(TaskType::kDOMManipulation)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&MediaRecorder::DispatchScheduledEvent,
                                   WrapPersistent(this)));
    }
  }
}

void MediaRecorder::DispatchScheduledEvent() {
  HeapVector<Member<Event>> events;
  events.swap(scheduled_events_);

  for (const auto& event : events)
    DispatchEvent(*event);
}

void MediaRecorder::Trace(Visitor* visitor) const {
  visitor->Trace(stream_);
  visitor->Trace(recorder_handler_);
  visitor->Trace(scheduled_events_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void MediaRecorder::UpdateAudioBitrate(uint32_t bits_per_second) {
  audio_bits_per_second_ = bits_per_second;
}

}  // namespace blink

"""

```