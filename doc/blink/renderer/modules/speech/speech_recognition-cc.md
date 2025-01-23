Response:
Let's break down the thought process to analyze the `speech_recognition.cc` file.

**1. Understanding the Request:**

The request asks for a functional breakdown of the C++ code, focusing on its interaction with web technologies (JavaScript, HTML, CSS), logical reasoning (input/output), potential user/developer errors, and debugging hints related to user actions.

**2. Initial Code Scan and Core Functionality Identification:**

The first step is to quickly scan the code for keywords and class names that reveal its purpose. Keywords like "SpeechRecognition", "start", "stop", "abort", "result", "error", and event names like "start", "end", "audiostart" strongly suggest this file handles the Web Speech API's recognition functionality within the Blink rendering engine. The `#include` directives confirm this by referencing media-related Mojo interfaces (`speech_recognition.mojom-blink.h`) and Blink's media stream components.

**3. Deeper Dive into Key Methods:**

Now, go through the major methods and understand their roles:

* **`Create()`:**  A standard factory method for creating `SpeechRecognition` objects.
* **`start()`:**  The entry point for initiating speech recognition. Notice the `MediaStreamTrack` overload. This suggests handling both default audio input and input from a specific media stream. The prerendering check is important.
* **`stopFunction()` and `abort()`:** Methods for stopping and aborting the recognition process. The prerendering check is again present.
* **`onDeviceWebSpeechAvailable()` and `installOnDeviceSpeechRecognition()`:**  These indicate features related to on-device speech recognition capabilities. They return `ScriptPromise` objects, linking them directly to JavaScript.
* **`ResultRetrieved()`:**  Crucial for processing the results received from the speech recognition engine. The logic for separating final and provisional results is key.
* **`ErrorOccurred()`:** Handles errors from the recognition engine and dispatches appropriate events.
* **Event handlers (`Started()`, `AudioStarted()`, etc.):** These methods dispatch events corresponding to different stages of the speech recognition process. These events are how JavaScript code interacts with the C++ logic.
* **`StartInternal()` and `StartController()`:**  Internal methods involved in the setup and initiation of the recognition process, especially handling the `MediaStreamTrack` case and Mojo communication.
* **Constructor and Destructor:**  Standard lifecycle management.
* **`Trace()`:**  For debugging and memory management within Blink.
* **`GetExecutionContext()`:**  Provides access to the execution context, necessary for various Blink operations.
* **`HasPendingActivity()`:**  Used to determine if the `SpeechRecognition` object is currently active.
* **`PageVisibilityChanged()`:**  Handles visibility changes, particularly on Android.
* **`OnConnectionError()`:**  Handles communication errors with the speech recognition service.

**4. Identifying Relationships with Web Technologies:**

* **JavaScript:** The `ScriptPromise` return types (`onDeviceWebSpeechAvailable`, `installOnDeviceSpeechRecognition`), the event dispatching (using `DispatchEvent`), and the interaction with `ExecutionContext` are strong indicators of JavaScript interaction.
* **HTML:**  While not directly manipulating HTML elements, the Speech Recognition API is triggered by user interactions within the HTML context (e.g., a button click calling a JavaScript function that then calls `speechRecognition.start()`).
* **CSS:**  CSS is not directly involved in the core logic of `speech_recognition.cc`. However, the UI elements that trigger speech recognition (buttons, etc.) are styled with CSS.

**5. Logical Reasoning and Examples:**

Consider the `ResultRetrieved()` method.

* **Hypothesis Input:** A `WTF::Vector` of `media::mojom::blink::WebSpeechRecognitionResultPtr`, some marked as provisional, some not.
* **Logic:** The method separates final and provisional results, aggregates them, and then dispatches a `SpeechRecognitionEvent`.
* **Output:** A `SpeechRecognitionEvent` containing a list of `SpeechRecognitionResult` objects, each with `SpeechRecognitionAlternative` objects.

**6. Common Errors and User Actions:**

Think about how a developer or user might misuse the API:

* **Calling `start()` when already started:** The code explicitly checks for this and throws an `InvalidStateError`.
* **Permissions:** While not directly in this file, the user needs to grant microphone permissions for speech recognition to work. This is a common user error.
* **Network issues:** The `OnConnectionError()` method hints at potential network-related problems.

**7. Debugging Hints and User Actions:**

Trace the user's actions that would lead to this code being executed:

1. User interacts with a web page.
2. JavaScript code on the page creates a `SpeechRecognition` object.
3. The JavaScript calls the `start()` method.
4. This triggers the C++ `SpeechRecognition::start()` method.
5. The C++ code interacts with the browser's speech recognition service (potentially via Mojo).
6. Results are received and processed in `ResultRetrieved()`.
7. Events are dispatched back to JavaScript.

**8. Structuring the Answer:**

Organize the findings into clear categories: Functionality, Web Technology Relationships, Logical Reasoning, Common Errors, and User Actions/Debugging. Use bullet points and code snippets where helpful.

**Self-Correction/Refinement:**

* **Initially, I might have focused too narrowly on the C++ code.**  Realizing the importance of the JavaScript API and user interaction is crucial.
* **The prerendering aspect is important and needs to be highlighted.** It's a specific optimization/feature that impacts how the API functions.
* **Clarifying the role of Mojo is essential.**  It's the communication mechanism between the renderer and the browser's speech recognition service.
* **Ensuring the examples are concrete and illustrative** makes the explanation much clearer.

By following these steps, combining code analysis with understanding the broader context of the Web Speech API and browser architecture, a comprehensive answer can be constructed.
好的，让我们来分析一下 `blink/renderer/modules/speech/speech_recognition.cc` 这个文件。

**功能概述:**

`speech_recognition.cc` 文件是 Chromium Blink 引擎中实现 Web Speech API 的核心组件之一，它负责处理语音识别的逻辑。主要功能包括：

1. **接口实现:** 实现了 `SpeechRecognition` 接口，该接口是 JavaScript 中 `SpeechRecognition` 对象在 Blink 渲染引擎中的对应实现。它提供了 `start()`, `stop()`, `abort()` 等方法，供 JavaScript 调用来控制语音识别过程。

2. **语音识别会话管理:**  负责管理与底层语音识别服务的会话 (`session_`)。通过 Mojo (Chromium 的进程间通信机制) 与浏览器进程中的语音识别服务进行通信。

3. **媒体流处理:** 可以接收来自 `MediaStreamTrack` 的音频输入。特别是当 `MediaStreamTrackWebSpeech` 功能启用时，它会创建一个 `SpeechRecognitionMediaStreamAudioSink` 来处理来自媒体流的音频数据。

4. **事件派发:**  当语音识别过程中的状态发生变化时（例如，开始录音、检测到语音、识别到结果、发生错误等），会派发相应的事件（`start`, `audiostart`, `soundstart`, `result`, `error`, `end` 等）给 JavaScript。

5. **结果处理:**  接收并处理来自底层语音识别服务的识别结果，包括最终结果和临时结果（provisional results）。将这些结果转换为 `SpeechRecognitionResult` 和 `SpeechRecognitionAlternative` 对象，并最终通过事件传递给 JavaScript。

6. **错误处理:**  接收并处理来自底层语音识别服务的错误信息，并创建 `SpeechRecognitionErrorEvent` 对象派发给 JavaScript。

7. **生命周期管理:** 管理 `SpeechRecognition` 对象的生命周期，例如在页面不可见时中止识别。

8. **与平台交互:** 通过 `SpeechRecognitionController` 与平台相关的语音识别服务进行交互。

9. **On-Device 语音识别支持:** 包含 `onDeviceWebSpeechAvailable` 和 `installOnDeviceSpeechRecognition` 方法，用于查询设备是否支持本地语音识别以及安装本地语音识别功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`speech_recognition.cc` 文件是 Web Speech API 功能的底层实现，它直接响应 JavaScript 的调用，并将结果反馈给 JavaScript。

* **JavaScript:**
    * **调用 `start()` 方法:**  当 JavaScript 代码调用 `speechRecognition.start()` 时，会最终调用到 `speech_recognition.cc` 中的 `SpeechRecognition::start()` 方法，开始语音识别过程。
    ```javascript
    const recognition = new SpeechRecognition();
    recognition.lang = 'zh-CN';
    recognition.start();
    ```
    * **监听事件:** JavaScript 代码会监听 `SpeechRecognition` 对象派发的事件，以获取语音识别的状态和结果。例如，监听 `result` 事件获取识别到的文本。
    ```javascript
    recognition.onresult = function(event) {
      const transcript = event.results[0][0].transcript;
      console.log('识别结果:', transcript);
    }
    ```
    * **处理错误:** 监听 `error` 事件来处理语音识别过程中发生的错误。
    ```javascript
    recognition.onerror = function(event) {
      console.error('语音识别错误:', event.error);
    }
    ```
    * **使用 `MediaStreamTrack`:** 可以将来自 `getUserMedia` API 获取的 `MediaStreamTrack` 对象传递给 `speechRecognition.start()`，指定使用特定的音频输入。
    ```javascript
    navigator.mediaDevices.getUserMedia({ audio: true })
      .then(function(stream) {
        const audioTrack = stream.getAudioTracks()[0];
        recognition.start(audioTrack);
      });
    ```
    * **检查和安装 On-Device 语音识别:** JavaScript 可以调用 `onDeviceWebSpeechAvailable()` 和 `installOnDeviceSpeechRecognition()` 方法。
    ```javascript
    recognition.onDeviceWebSpeechAvailable('zh-CN').then(available => {
      if (available) {
        console.log('支持本地语音识别');
      } else {
        recognition.installOnDeviceSpeechRecognition('zh-CN').then(success => {
          if (success) {
            console.log('本地语音识别安装成功');
          } else {
            console.log('本地语音识别安装失败');
          }
        });
      }
    });
    ```

* **HTML:**
    * HTML 提供了用户交互的界面，例如按钮，用户点击按钮可以触发 JavaScript 代码来启动语音识别。
    ```html
    <button onclick="startRecognition()">开始录音</button>
    <script>
      const recognition = new SpeechRecognition();
      function startRecognition() {
        recognition.start();
      }
    </script>
    ```

* **CSS:**
    * CSS 负责控制 HTML 元素的样式，与 `speech_recognition.cc` 的核心功能没有直接关系。但是，用户交互的界面元素（例如按钮的样式）由 CSS 定义。

**逻辑推理及假设输入与输出:**

**假设输入:**

1. **JavaScript 调用 `recognition.start()`:** 用户点击了网页上的 "开始录音" 按钮，触发了 JavaScript 代码调用 `speechRecognition.start()`。
2. **用户对着麦克风说话:** 用户开始对着连接到设备的麦克风说话，产生音频输入。
3. **语音识别服务处理:** 底层的语音识别服务接收到音频数据并进行处理。

**逻辑推理过程 (在 `speech_recognition.cc` 中):**

1. `SpeechRecognition::start()` 方法被调用。
2. 如果当前处于 prerendering 状态，则将 `StartInternal` 的调用延迟。
3. `StartInternal()` 方法检查 `controller_` 是否存在，以及执行上下文是否有效。
4. 如果 `MediaStreamTrackWebSpeech` 启用且提供了 `stream_track_`，则创建一个 `SpeechRecognitionMediaStreamAudioSink` 来处理音频流。
5. 否则，调用 `StartController()`。
6. `StartController()` 创建与语音识别服务的 Mojo 连接 (`session_`)。
7. `StartController()` 调用底层的 `controller_->Start()` 方法，将语言、是否连续识别、是否返回临时结果等参数传递给语音识别服务。
8. 底层服务开始接收和处理音频数据。
9. 当识别到结果时，底层服务通过 Mojo 发送结果数据到 Blink 进程。
10. `SpeechRecognition::ResultRetrieved()` 方法接收到结果数据。
11. `ResultRetrieved()` 将结果数据转换为 `SpeechRecognitionResult` 和 `SpeechRecognitionAlternative` 对象。
12. `ResultRetrieved()` 派发 `SpeechRecognitionEvent` (类型为 `result`) 给 JavaScript。

**假设输出:**

1. **JavaScript 的 `onresult` 事件被触发:** 携带 `SpeechRecognitionEvent` 对象。
2. **`SpeechRecognitionEvent.results` 包含识别到的文本:** 例如，如果用户说了 "你好 世界"，则 `event.results[0][0].transcript` 的值可能是 "你好 世界"。

**涉及用户或编程常见的使用错误及举例说明:**

1. **在 `start()` 之前没有创建 `SpeechRecognition` 对象:**
   ```javascript
   // 错误示例
   recognition.start(); // ReferenceError: recognition is not defined

   // 正确示例
   const recognition = new SpeechRecognition();
   recognition.start();
   ```

2. **在已经 `start()` 的状态下再次调用 `start()`:**  这会导致 `InvalidStateError` 异常。
   ```javascript
   const recognition = new SpeechRecognition();
   recognition.start();
   recognition.start(); // 抛出 InvalidStateError
   ```
   `speech_recognition.cc` 中的 `SpeechRecognition::StartInternal()` 方法会检查 `started_` 标志来防止这种情况。

3. **没有正确处理权限问题:** 用户可能拒绝了麦克风权限，导致语音识别无法工作。这通常会在 JavaScript 中触发 `error` 事件，但错误码可能需要仔细检查。
   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true })
     .catch(function(err) {
       console.error('无法获取麦克风:', err);
     });
   ```

4. **网络问题导致连接失败:**  如果网络不稳定，可能导致与语音识别服务的连接中断。`speech_recognition.cc` 中的 `OnConnectionError()` 方法会处理这种情况，并派发一个错误事件。用户可能会看到类似 "网络错误" 的提示。

5. **使用了错误的语言代码:**  如果设置了语音识别不支持的语言代码，可能会影响识别效果，或者直接导致错误。
   ```javascript
   recognition.lang = 'xx-XX'; // 假设 'xx-XX' 是无效的语言代码
   recognition.start(); // 可能触发错误事件
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

为了调试 `speech_recognition.cc` 中的代码，了解用户操作的路径非常重要：

1. **用户在浏览器中打开一个网页:** 该网页使用了 Web Speech API。
2. **网页加载 JavaScript 代码:**  JavaScript 代码中创建了 `SpeechRecognition` 对象，并可能设置了相关属性（如 `lang`, `continuous`, `interimResults`）。
3. **用户触发某个操作，例如点击按钮:**  这个操作绑定了 JavaScript 函数。
4. **JavaScript 函数调用 `speechRecognition.start()`:**  这是进入 `speech_recognition.cc` 的关键入口点。
5. **Blink 引擎处理 JavaScript 调用:**  Blink 将 JavaScript 的 `start()` 调用映射到 C++ 的 `SpeechRecognition::start()` 方法。
6. **C++ 代码与底层服务交互:**  `speech_recognition.cc` 中的代码会建立与浏览器进程中语音识别服务的连接，并开始接收音频数据。
7. **用户对着麦克风说话:**  音频数据被捕获并传递到语音识别服务。
8. **语音识别服务返回结果或错误:**  这些数据通过 Mojo 传递回 Blink 进程。
9. **`speech_recognition.cc` 处理返回的数据:**  `ResultRetrieved()` 或 `ErrorOccurred()` 方法会被调用。
10. **事件被派发到 JavaScript:**  JavaScript 中注册的事件监听器会接收到这些事件，并执行相应的处理逻辑。

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 `recognition.start()` 和事件处理函数中设置断点，可以观察 JavaScript 的执行流程和数据。
* **在 `speech_recognition.cc` 中添加日志或断点:**  在关键方法（如 `start()`, `ResultRetrieved()`, `ErrorOccurred()`) 中添加日志输出（例如使用 `LOG(INFO)`) 或断点，可以跟踪 C++ 代码的执行流程，查看接收到的数据。
* **检查浏览器控制台的错误信息:**  查看是否有 JavaScript 错误或来自 Blink 引擎的警告/错误信息。
* **使用 Chromium 的开发者工具进行底层调试:**  可以使用 gdb 等调试器附加到 Chromium 的渲染进程，直接调试 `speech_recognition.cc` 的代码。
* **检查 Mojo 通信:**  可以使用 Chromium 提供的工具（如 `chrome://tracing`) 来查看 Mojo 消息的传递情况，了解语音识别服务与渲染进程之间的通信是否正常。

通过以上分析，我们可以更深入地了解 `blink/renderer/modules/speech/speech_recognition.cc` 文件的功能，以及它在 Web Speech API 实现中的作用。了解用户操作的路径和可能出现的错误，有助于我们更好地调试和理解语音识别功能的运行机制。

### 提示词
```
这是目录为blink/renderer/modules/speech/speech_recognition.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/speech/speech_recognition.h"

#include <algorithm>

#include "base/feature_list.h"
#include "build/build_config.h"
#include "media/base/audio_parameters.h"
#include "media/base/channel_layout.h"
#include "media/base/media_switches.h"
#include "media/mojo/mojom/speech_recognition.mojom-blink.h"
#include "media/mojo/mojom/speech_recognition_audio_forwarder.mojom-blink.h"
#include "media/mojo/mojom/speech_recognition_error.mojom-blink.h"
#include "media/mojo/mojom/speech_recognition_result.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_audio_sink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_settings.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/speech/speech_recognition_controller.h"
#include "third_party/blink/renderer/modules/speech/speech_recognition_error_event.h"
#include "third_party/blink/renderer/modules/speech/speech_recognition_event.h"
#include "third_party/blink/renderer/modules/speech/speech_recognition_media_stream_audio_sink.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

SpeechRecognition* SpeechRecognition::Create(ExecutionContext* context) {
  return MakeGarbageCollected<SpeechRecognition>(To<LocalDOMWindow>(context));
}

void SpeechRecognition::start(ExceptionState& exception_state) {
  // https://wicg.github.io/nav-speculation/prerendering.html#web-speech-patch
  // If this is called in prerendering, it should be deferred.
  if (DomWindow() && DomWindow()->document()->IsPrerendering()) {
    DomWindow()->document()->AddPostPrerenderingActivationStep(
        WTF::BindOnce(&SpeechRecognition::StartInternal,
                      WrapWeakPersistent(this), /*exception_state=*/nullptr));
    return;
  }
  StartInternal(&exception_state);
}

void SpeechRecognition::start(MediaStreamTrack* media_stream_track,
                              ExceptionState& exception_state) {
  stream_track_ = media_stream_track;
  start(exception_state);
}

void SpeechRecognition::stopFunction() {
  // https://wicg.github.io/nav-speculation/prerendering.html#web-speech-patch
  // If this is called in prerendering, it should be deferred.
  if (DomWindow() && DomWindow()->document()->IsPrerendering()) {
    DomWindow()->document()->AddPostPrerenderingActivationStep(WTF::BindOnce(
        &SpeechRecognition::stopFunction, WrapWeakPersistent(this)));
    return;
  }

  if (!controller_)
    return;

  if (started_ && !stopping_) {
    stopping_ = true;
    session_->StopCapture();
  }
}

void SpeechRecognition::abort() {
  // https://wicg.github.io/nav-speculation/prerendering.html#web-speech-patch
  // If this is called in prerendering, it should be deferred.
  if (DomWindow() && DomWindow()->document()->IsPrerendering()) {
    DomWindow()->document()->AddPostPrerenderingActivationStep(
        WTF::BindOnce(&SpeechRecognition::abort, WrapWeakPersistent(this)));
    return;
  }

  if (!controller_)
    return;

  if (started_ && !stopping_) {
    stopping_ = true;
    session_->Abort();
  }
}

ScriptPromise<IDLBoolean> SpeechRecognition::onDeviceWebSpeechAvailable(
    ScriptState* script_state,
    const String& lang,
    ExceptionState& exception_state) {
  if (!controller_ || !GetExecutionContext()) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  controller_->OnDeviceWebSpeechAvailable(
      lang, WTF::BindOnce([](SpeechRecognition*,
                             ScriptPromiseResolver<IDLBoolean>* resolver,
                             bool available) { resolver->Resolve(available); },
                          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLBoolean> SpeechRecognition::installOnDeviceSpeechRecognition(
    ScriptState* script_state,
    const String& lang,
    ExceptionState& exception_state) {
  if (!controller_ || !GetExecutionContext()) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  controller_->InstallOnDeviceSpeechRecognition(
      lang, WTF::BindOnce([](SpeechRecognition*,
                             ScriptPromiseResolver<IDLBoolean>* resolver,
                             bool success) { resolver->Resolve(success); },
                          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

void SpeechRecognition::ResultRetrieved(
    WTF::Vector<media::mojom::blink::WebSpeechRecognitionResultPtr> results) {
  auto it = std::stable_partition(
      results.begin(), results.end(),
      [](const auto& result) { return !result->is_provisional; });
  wtf_size_t provisional_count = static_cast<wtf_size_t>(results.end() - it);

  // Add the new results to the previous final results.
  HeapVector<Member<SpeechRecognitionResult>> aggregated_results =
      std::move(final_results_);
  aggregated_results.reserve(aggregated_results.size() + results.size());

  for (const auto& result : results) {
    HeapVector<Member<SpeechRecognitionAlternative>> alternatives;
    alternatives.ReserveInitialCapacity(result->hypotheses.size());
    for (const auto& hypothesis : result->hypotheses) {
      alternatives.push_back(MakeGarbageCollected<SpeechRecognitionAlternative>(
          hypothesis->utterance, hypothesis->confidence));
    }
    aggregated_results.push_back(SpeechRecognitionResult::Create(
        std::move(alternatives), !result->is_provisional));
  }

  // |aggregated_results| now contains the following (in the given order):
  //
  // (1) previous final results from |final_results_|
  // (2) new final results from |results|
  // (3) new provisional results from |results|

  // |final_results_| = (1) + (2).
  HeapVector<Member<SpeechRecognitionResult>> new_final_results;
  new_final_results.ReserveInitialCapacity(aggregated_results.size() -
                                           provisional_count);
  new_final_results.AppendRange(aggregated_results.begin(),
                                aggregated_results.end() - provisional_count);
  final_results_ = std::move(new_final_results);

  // We dispatch an event with (1) + (2) + (3).
  DispatchEvent(*SpeechRecognitionEvent::CreateResult(
      aggregated_results.size() - results.size(),
      std::move(aggregated_results)));
}

void SpeechRecognition::ErrorOccurred(
    media::mojom::blink::SpeechRecognitionErrorPtr error) {
  if (error->code ==
      media::mojom::blink::SpeechRecognitionErrorCode::kNoMatch) {
    DispatchEvent(*SpeechRecognitionEvent::CreateNoMatch(nullptr));
  } else {
    // TODO(primiano): message?
    DispatchEvent(*SpeechRecognitionErrorEvent::Create(error->code, String()));
  }
}

void SpeechRecognition::Started() {
  DispatchEvent(*Event::Create(event_type_names::kStart));
}

void SpeechRecognition::AudioStarted() {
  DispatchEvent(*Event::Create(event_type_names::kAudiostart));
}

void SpeechRecognition::SoundStarted() {
  DispatchEvent(*Event::Create(event_type_names::kSoundstart));
  DispatchEvent(*Event::Create(event_type_names::kSpeechstart));
}

void SpeechRecognition::SoundEnded() {
  DispatchEvent(*Event::Create(event_type_names::kSpeechend));
  DispatchEvent(*Event::Create(event_type_names::kSoundend));
}

void SpeechRecognition::AudioEnded() {
  DispatchEvent(*Event::Create(event_type_names::kAudioend));
}

void SpeechRecognition::Ended() {
  started_ = false;
  stopping_ = false;
  session_.reset();
  receiver_.reset();
  DispatchEvent(*Event::Create(event_type_names::kEnd));
}

const AtomicString& SpeechRecognition::InterfaceName() const {
  return event_target_names::kSpeechRecognition;
}

ExecutionContext* SpeechRecognition::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void SpeechRecognition::ContextDestroyed() {
  controller_ = nullptr;
}

bool SpeechRecognition::HasPendingActivity() const {
  return started_;
}

void SpeechRecognition::PageVisibilityChanged() {
#if BUILDFLAG(IS_ANDROID)
  if (!GetPage()->IsPageVisible())
    abort();
#endif
}

void SpeechRecognition::OnConnectionError() {
  ErrorOccurred(media::mojom::blink::SpeechRecognitionError::New(
      media::mojom::blink::SpeechRecognitionErrorCode::kNetwork,
      media::mojom::blink::SpeechAudioErrorDetails::kNone));
  Ended();
}

void SpeechRecognition::StartInternal(ExceptionState* exception_state) {
  if (!controller_ || !GetExecutionContext())
    return;

  if (started_) {
    // https://wicg.github.io/speech-api/#dom-speechrecognition-start
    // The spec says that if the start method is called on an already started
    // object (that is, start has previously been called, and no error or end
    // event has fired on the object), the user agent must throw an
    // "InvalidStateError" DOMException and ignore the call. But, if it's called
    // after prerendering activation, `exception_state` is null since it's
    // STACK_ALLOCATED and it can't be passed.
    if (exception_state) {
      exception_state->ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                         "recognition has already started.");
    }
    return;
  }
  final_results_.clear();

  if (base::FeatureList::IsEnabled(
          blink::features::kMediaStreamTrackWebSpeech) &&
      stream_track_) {
    sink_ = MakeGarbageCollected<SpeechRecognitionMediaStreamAudioSink>(
        GetExecutionContext(),
        WTF::BindOnce(&SpeechRecognition::StartController,
                      WrapPersistent(this)));
    WebMediaStreamAudioSink::AddToAudioTrack(
        sink_, WebMediaStreamTrack(stream_track_->Component()));
  } else {
    StartController();
  }

  started_ = true;
}

void SpeechRecognition::StartController(
    std::optional<media::AudioParameters> audio_parameters,
    mojo::PendingReceiver<media::mojom::blink::SpeechRecognitionAudioForwarder>
        audio_forwarder_receiver) {
  mojo::PendingRemote<media::mojom::blink::SpeechRecognitionSessionClient>
      session_client;
  // See https://bit.ly/2S0zRAS for task types.
  receiver_.Bind(
      session_client.InitWithNewPipeAndPassReceiver(),
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI));
  receiver_.set_disconnect_handler(WTF::BindOnce(
      &SpeechRecognition::OnConnectionError, WrapWeakPersistent(this)));
  controller_->Start(
      session_.BindNewPipeAndPassReceiver(
          GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI)),
      std::move(session_client), *grammars_, lang_, continuous_,
      interim_results_, max_alternatives_, local_service_,
      allow_cloud_fallback_, std::move(audio_forwarder_receiver),
      std::move(audio_parameters));
}

SpeechRecognition::SpeechRecognition(LocalDOMWindow* window)
    : ActiveScriptWrappable<SpeechRecognition>({}),
      ExecutionContextLifecycleObserver(window),
      PageVisibilityObserver(window->GetFrame() ? window->GetFrame()->GetPage()
                                                : nullptr),
      grammars_(SpeechGrammarList::Create()),  // FIXME: The spec is not clear
                                               // on the default value for the
                                               // grammars attribute.
      controller_(SpeechRecognitionController::From(*window)),
      receiver_(this, window),
      session_(window) {}

SpeechRecognition::~SpeechRecognition() = default;

void SpeechRecognition::Trace(Visitor* visitor) const {
  visitor->Trace(stream_track_);
  visitor->Trace(grammars_);
  visitor->Trace(sink_);
  visitor->Trace(controller_);
  visitor->Trace(final_results_);
  visitor->Trace(receiver_);
  visitor->Trace(session_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
}

}  // namespace blink
```