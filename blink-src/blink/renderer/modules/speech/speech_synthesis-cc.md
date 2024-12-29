Response:
Let's break down the thought process for analyzing the `speech_synthesis.cc` file.

**1. Understanding the Goal:**

The request asks for a comprehensive understanding of the `speech_synthesis.cc` file. This means identifying its core functionality, its relationships with web technologies (JavaScript, HTML, CSS), potential errors, and how users might trigger its code.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for key terms and patterns. Some initial observations:

* **`SpeechSynthesis` class:**  This is the central class, likely implementing the Web Speech API's `SpeechSynthesis` interface.
* **`SpeechSynthesisUtterance`:**  Appears related to the text being spoken.
* **`SpeechSynthesisVoice`:** Represents different voices available for speech.
* **`mojom::blink::SpeechSynthesis`:** This strongly suggests an interface to a lower-level browser component, likely implemented in C++. The `mojom` namespace points towards the Mojo IPC system used in Chromium.
* **`event_type_names::k*`:**  Indicates the file handles and dispatches events like `start`, `end`, `pause`, `resume`, `error`, and `voiceschanged`.
* **`getVoices()`, `speak()`, `cancel()`, `pause()`, `resume()`:** These methods directly correspond to the methods available in the JavaScript `SpeechSynthesis` API.
* **`AutoplayPolicy`:** Suggests interaction with browser autoplay restrictions.
* **`UseCounter`:** Indicates the file tracks usage for metrics.
* **Copyright notice:**  Shows it originated at Apple, suggesting its early integration into the WebKit/Blink engine.

**3. Dissecting Core Functionality:**

Based on the initial scan, we can start to map out the primary responsibilities:

* **Voice Management:**  Fetching and providing a list of available speech voices (`getVoices`, `OnSetVoiceList`).
* **Utterance Handling:** Managing a queue of text to be spoken (`utterance_queue_`).
* **Speech Control:**  Initiating (`speak`), stopping (`cancel`), pausing (`pause`), and resuming (`resume`) speech.
* **Event Dispatching:**  Notifying the web page about the progress and status of speech synthesis (e.g., `DidStartSpeaking`, `DidFinishSpeaking`, `FireEvent`).
* **Inter-Process Communication (IPC):** Using Mojo to communicate with the actual speech synthesis engine in the browser process.
* **Error Handling:** Reporting errors back to the web page.
* **Autoplay Integration:** Respecting browser autoplay policies.

**4. Connecting to JavaScript, HTML, and CSS:**

With the core functionality identified, we can now explain how it relates to web technologies:

* **JavaScript:** The `SpeechSynthesis` class directly implements the JavaScript `SpeechSynthesis` API. The methods and events mirror the JS interface. We can provide a simple JavaScript code example to demonstrate usage.
* **HTML:** The JavaScript API is used within HTML pages, often in `<script>` tags or linked JavaScript files.
* **CSS:** While CSS doesn't directly control speech synthesis, it can style elements related to the user interface that triggers speech actions (e.g., buttons).

**5. Logical Reasoning and Examples:**

The request specifically asks for logical reasoning with input/output examples. For this, we focus on key methods like `speak()`:

* **Input:** A `SpeechSynthesisUtterance` object containing text and language.
* **Processing:**  The `speak()` method adds the utterance to a queue, checks autoplay policy, and potentially starts speaking immediately.
* **Output:**  The `speak()` method doesn't directly return a value. The "output" is the initiation of the speech synthesis process and the eventual firing of events (`start`, `end`, `error`). We need to consider the asynchronous nature of this process.

**6. Identifying Common User/Programming Errors:**

Based on the code, we can deduce potential error scenarios:

* **Autoplay Blocked:**  Trying to call `speak()` without user interaction might be blocked by the browser.
* **Invalid Voice:**  Attempting to set a non-existent voice on an utterance could lead to unexpected behavior or errors in the underlying speech engine.
* **Rapid Calls to `speak()`:** Queueing up too many utterances might lead to performance issues or unexpected behavior.
* **Incorrect Event Handling:**  Not properly listening for and handling `error` events could leave the user unaware of failures.

**7. Tracing User Operations:**

This requires thinking about how a user interacts with a web page that uses the Speech Synthesis API:

* **User Action:** A user might click a button, hover over an element, or perform some other action that triggers a JavaScript function.
* **JavaScript Execution:** The JavaScript function uses the `SpeechSynthesis` API (e.g., `window.speechSynthesis.speak(...)`).
* **Blink Processing:** The browser's JavaScript engine calls the corresponding methods in `speech_synthesis.cc`.
* **Mojo Communication:**  `speech_synthesis.cc` communicates with the browser process via Mojo.
* **Speech Engine:** The browser process uses the operating system's speech synthesis engine to generate audio.
* **Audio Output:** The generated audio is played through the user's speakers.

**8. Debugging Clues:**

Knowing the path helps in debugging:

* **No Audio:** Check if the speech synthesis service is working on the user's system, look for errors in the browser's developer console, and verify autoplay policies.
* **Incorrect Voice:** Inspect the `getVoices()` output and ensure the desired voice is available and correctly specified.
* **Unexpected Behavior:** Use breakpoints in the JavaScript code and within `speech_synthesis.cc` (if possible for the developer) to trace the execution flow.

**9. Structuring the Answer:**

Finally, organize the information logically, using clear headings and examples. The goal is to present a comprehensive yet easy-to-understand explanation. Start with a summary of the file's function, then delve into specifics, connections to web technologies, error scenarios, and the user interaction flow.

This iterative process of scanning, understanding core functions, connecting to web technologies, considering edge cases, and structuring the information helps in creating a detailed and accurate analysis of the given source code file.
这个 `blink/renderer/modules/speech/speech_synthesis.cc` 文件是 Chromium Blink 渲染引擎中实现 **Web Speech API** 中 **SpeechSynthesis** 接口的关键部分。它的主要功能是控制文本到语音的转换（Text-to-Speech, TTS）。

以下是该文件的详细功能列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及可能的用户错误和调试线索：

**主要功能:**

1. **实现 `SpeechSynthesis` 接口:**  这个类实现了 W3C Speech API 规范中定义的 `SpeechSynthesis` 接口，允许网页通过 JavaScript 控制语音合成。
2. **管理语音合成请求队列:**  它维护一个 `utterance_queue_`，用于存储待处理的 `SpeechSynthesisUtterance` 对象。这些对象包含了要合成的文本和其他语音属性。
3. **与底层语音合成引擎通信:** 通过 Mojo IPC (Inter-Process Communication) 与浏览器进程中负责实际语音合成的组件 (`mojom::blink::SpeechSynthesis`) 进行通信。
4. **获取可用的语音列表:**  `getVoices()` 方法用于获取当前系统可用的语音列表。这些语音信息来自底层语音合成引擎。
5. **控制语音合成过程:**  提供 `speak()` (开始合成)、`cancel()` (取消合成)、`pause()` (暂停合成) 和 `resume()` (恢复合成) 方法。
6. **触发事件:**  当语音合成过程中的特定事件发生时（例如开始、结束、暂停、恢复、错误、单词边界、句子边界），它会创建并分发相应的事件 (`SpeechSynthesisEvent`, `SpeechSynthesisErrorEvent`) 到 JavaScript。
7. **处理语音合成状态:**  跟踪当前的语音合成状态，例如是否正在说话 (`Speaking()`)，是否有待处理的请求 (`pending()`)，以及是否已暂停 (`paused()`)。
8. **处理自动播放策略:** 检查浏览器的自动播放策略，决定是否允许开始语音合成。
9. **记录使用情况:**  使用 `UseCounter` 记录 `speak()` 方法的使用情况，用于统计和分析。
10. **处理隐私预算:** 记录获取语音列表的操作，用于隐私预算跟踪。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  `SpeechSynthesis.cc` 背后支撑着 JavaScript 中 `window.speechSynthesis` 对象的功能。开发者通过 JavaScript 代码调用 `speechSynthesis` 的方法，例如 `speak()`, `cancel()`, `getVoices()` 等。

   **举例:**

   ```javascript
   let utterance = new SpeechSynthesisUtterance('Hello world!');
   speechSynthesis.speak(utterance);

   speechSynthesis.getVoices().then(voices => {
       voices.forEach(voice => console.log(voice.name, voice.lang));
   });

   speechSynthesis.addEventListener('end', () => {
       console.log('Speech finished.');
   });
   ```

* **HTML:** HTML 结构提供了用户交互的界面，用户操作可能触发 JavaScript 代码，进而调用 `speechSynthesis` 的方法。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>Speech Synthesis Example</title>
   </head>
   <body>
       <button id="speakButton">Speak</button>
       <script>
           const speakButton = document.getElementById('speakButton');
           speakButton.addEventListener('click', () => {
               let utterance = new SpeechSynthesisUtterance('You clicked the button.');
               speechSynthesis.speak(utterance);
           });
       </script>
   </body>
   </html>
   ```

* **CSS:** CSS 主要负责样式，不直接控制语音合成功能。但 CSS 可以用于美化触发语音合成操作的 UI 元素（例如按钮）。

   **举例:** 可以用 CSS 样式化上面的 "Speak" 按钮。

**逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码：

```javascript
let utterance1 = new SpeechSynthesisUtterance('First sentence.');
let utterance2 = new SpeechSynthesisUtterance('Second sentence.');
speechSynthesis.speak(utterance1);
speechSynthesis.speak(utterance2);
```

**假设输入:**

* 调用 `speechSynthesis.speak(utterance1)`，其中 `utterance1` 的文本是 "First sentence."
* 调用 `speechSynthesis.speak(utterance2)`，其中 `utterance2` 的文本是 "Second sentence."

**逻辑推理:**

1. `utterance1` 被添加到 `utterance_queue_` 的末尾。
2. 由于队列之前可能为空，`StartSpeakingImmediately()` 被调用，开始处理 `utterance1`。
3. `speech_synthesis.cc` 通过 Mojo 将 `utterance1` 的文本发送给底层的语音合成引擎。
4. 语音合成引擎开始合成 "First sentence." 的语音。
5. 当合成开始时，`DidStartSpeaking(utterance1)` 被调用，触发 JavaScript 的 `start` 事件。
6. `utterance2` 被添加到 `utterance_queue_` 的末尾。
7. 当 `utterance1` 合成完成时，`DidFinishSpeaking(utterance1, ...)` 被调用，触发 JavaScript 的 `end` 事件。
8. `utterance1` 从 `utterance_queue_` 中移除。
9. 由于队列不为空，`StartSpeakingImmediately()` 再次被调用，开始处理 `utterance2`。
10. 重复步骤 3-7 处理 `utterance2`。

**可能的输出 (JavaScript 事件):**

* 针对 `utterance1`: `start` 事件 -> (可能触发 `boundary` 事件) -> `end` 事件
* 针对 `utterance2`: `start` 事件 -> (可能触发 `boundary` 事件) -> `end` 事件

**用户或编程常见的使用错误:**

1. **自动播放被阻止:**  在没有用户交互的情况下直接调用 `speak()` 可能会被浏览器的自动播放策略阻止。

   **错误示例:** 在页面加载时立即调用 `speechSynthesis.speak(utterance)`。

   **调试线索:**  查看浏览器的开发者工具控制台，可能会有关于自动播放被阻止的警告或错误信息。检查 `IsAllowedToStartByAutoplay()` 方法。

2. **重复快速调用 `speak()`:**  如果用户或程序快速连续调用 `speak()`，可能会导致大量的语音合成请求排队，影响性能或产生意外行为。

   **调试线索:** 检查 `utterance_queue_` 的大小，观察事件触发的顺序和频率。

3. **在 `voiceschanged` 事件之前调用 `getVoices()` 并使用返回的 voice:**  语音列表可能需要一些时间来加载。过早地使用 `getVoices()` 返回的空列表或不完整的列表可能导致问题。

   **错误示例:**

   ```javascript
   let voices = speechSynthesis.getVoices(); // 可能为空或不完整
   let utterance = new SpeechSynthesisUtterance('Hello');
   utterance.voice = voices[0]; // 如果 voices 为空，则报错
   speechSynthesis.speak(utterance);
   ```

   **调试线索:**  确保在 `voiceschanged` 事件触发后或使用 `speechSynthesis.getVoices().then()` 来处理异步的语音列表加载。

4. **在非活动文档或 detached frame 中调用 `speak()`:**  如果 `SpeechSynthesis` 对象所属的文档已经不可见或者 frame 已经被移除，调用 `speak()` 可能不会有任何效果或者抛出错误。

   **调试线索:** 检查调用 `speak()` 时文档和 frame 的状态。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户在网页上执行操作:** 例如点击按钮、鼠标悬停、输入文本等。
2. **JavaScript 事件监听器被触发:**  与用户操作相关的 JavaScript 事件监听器（例如 `click`, `mouseover`, `input`）被激活。
3. **JavaScript 代码调用 `speechSynthesis` 的方法:** 在事件处理函数中，JavaScript 代码调用了 `window.speechSynthesis.speak()`, `cancel()`, `pause()`, `resume()` 或 `getVoices()`。
4. **Blink 渲染引擎接收到 JavaScript 调用:**  JavaScript 的调用被传递到 Blink 渲染引擎中，`speech_synthesis.cc` 文件中的相应方法被调用。
5. **`SpeechSynthesis.cc` 处理请求:**
   * 对于 `speak()`: 创建 `SpeechSynthesisUtterance` 对象并添加到队列，如果可以立即开始则通过 Mojo 发送给浏览器进程。
   * 对于 `cancel()`, `pause()`, `resume()`: 通过 Mojo 向浏览器进程发送相应的控制指令。
   * 对于 `getVoices()`:  触发向浏览器进程请求语音列表，并等待 `OnSetVoiceList()` 回调。
6. **与浏览器进程通信:**  `speech_synthesis.cc` 使用 Mojo IPC 与浏览器进程中的语音合成服务进行通信。
7. **底层语音合成引擎工作:** 浏览器进程中的语音合成引擎实际执行文本到语音的转换。
8. **事件回调:** 当语音合成过程中的事件发生时，底层引擎会通知 `speech_synthesis.cc`，例如通过 `DidStartSpeaking()`, `DidFinishSpeaking()` 等方法。
9. **事件分发到 JavaScript:** `speech_synthesis.cc` 创建 `SpeechSynthesisEvent` 或 `SpeechSynthesisErrorEvent` 对象，并将它们分发到网页的 JavaScript 代码中。

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 `speechSynthesis` 方法的地方设置断点，查看参数和调用栈。
* **使用浏览器的开发者工具:**  查看控制台是否有错误或警告信息，特别是关于自动播放策略的提示。
* **在 `speech_synthesis.cc` 中添加日志或断点 (如果可以访问 Blink 源码):**  追踪代码的执行流程，查看变量的值，例如 `utterance_queue_` 的状态。
* **检查 Mojo 通信:**  虽然比较复杂，但可以检查 Mojo 消息的发送和接收情况，以确定是否正确地与浏览器进程通信。
* **查看 `chrome://media-internals`:**  这个 Chrome 特殊页面可能提供关于媒体和语音合成的更底层信息。

总而言之，`speech_synthesis.cc` 是 Web Speech API 在 Blink 渲染引擎中的核心实现，它负责连接 JavaScript API 和底层的语音合成能力，并管理语音合成的整个生命周期。理解这个文件的功能对于调试与语音合成相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/speech/speech_synthesis.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/speech/speech_synthesis.h"

#include <tuple>

#include "build/build_config.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_speech_synthesis_error_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_speech_synthesis_event_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/media/autoplay_policy.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/modules/speech/speech_synthesis_error_event.h"
#include "third_party/blink/renderer/modules/speech/speech_synthesis_event.h"
#include "third_party/blink/renderer/modules/speech/speech_synthesis_voice.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"

namespace blink {

const char SpeechSynthesis::kSupplementName[] = "SpeechSynthesis";

SpeechSynthesisBase* SpeechSynthesis::Create(LocalDOMWindow& window) {
  return MakeGarbageCollected<SpeechSynthesis>(window);
}

SpeechSynthesis* SpeechSynthesis::speechSynthesis(LocalDOMWindow& window) {
  SpeechSynthesis* synthesis =
      Supplement<LocalDOMWindow>::From<SpeechSynthesis>(window);
  if (!synthesis) {
    synthesis = MakeGarbageCollected<SpeechSynthesis>(window);
    ProvideTo(window, synthesis);
#if BUILDFLAG(IS_ANDROID)
    // On Android devices we lazily initialize |mojom_synthesis_| to avoid
    // needlessly binding to the TTS service, see https://crbug.com/811929.
    // TODO(crbug/811929): Consider moving this logic into the Android-
    // specific backend implementation.
#else
    std::ignore = synthesis->TryEnsureMojomSynthesis();
#endif
  }
  return synthesis;
}

void SpeechSynthesis::CreateForTesting(
    LocalDOMWindow& window,
    mojo::PendingRemote<mojom::blink::SpeechSynthesis> mojom_synthesis) {
  DCHECK(!Supplement<LocalDOMWindow>::From<SpeechSynthesis>(window));
  SpeechSynthesis* synthesis = MakeGarbageCollected<SpeechSynthesis>(window);
  ProvideTo(window, synthesis);
  synthesis->SetMojomSynthesisForTesting(std::move(mojom_synthesis));
}

SpeechSynthesis::SpeechSynthesis(LocalDOMWindow& window)
    : Supplement<LocalDOMWindow>(window),
      receiver_(this, &window),
      mojom_synthesis_(&window) {}

void SpeechSynthesis::OnSetVoiceList(
    Vector<mojom::blink::SpeechSynthesisVoicePtr> mojom_voices) {
  voice_list_.clear();
  for (auto& mojom_voice : mojom_voices) {
    voice_list_.push_back(
        MakeGarbageCollected<SpeechSynthesisVoice>(std::move(mojom_voice)));
  }
  VoicesDidChange();
}

const HeapVector<Member<SpeechSynthesisVoice>>& SpeechSynthesis::getVoices() {
  // Kick off initialization here to ensure voice list gets populated.
  std::ignore = TryEnsureMojomSynthesis();
  RecordVoicesForIdentifiability();
  return voice_list_;
}

void SpeechSynthesis::RecordVoicesForIdentifiability() const {
  constexpr IdentifiableSurface surface = IdentifiableSurface::FromTypeAndToken(
      IdentifiableSurface::Type::kWebFeature,
      WebFeature::kSpeechSynthesis_GetVoices_Method);
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleSurface(surface))
    return;
  if (!GetSupplementable()->GetFrame())
    return;

  IdentifiableTokenBuilder builder;
  for (const auto& voice : voice_list_) {
    builder.AddToken(IdentifiabilityBenignStringToken(voice->voiceURI()));
    builder.AddToken(IdentifiabilityBenignStringToken(voice->lang()));
    builder.AddToken(IdentifiabilityBenignStringToken(voice->name()));
    builder.AddToken(voice->localService());
  }
  IdentifiabilityMetricBuilder(GetSupplementable()->UkmSourceID())
      .Add(surface, builder.GetToken())
      .Record(GetSupplementable()->UkmRecorder());
}

bool SpeechSynthesis::Speaking() const {
  // If we have a current speech utterance, then that means we're assumed to be
  // in a speaking state. This state is independent of whether the utterance
  // happens to be paused.
  return CurrentSpeechUtterance();
}

bool SpeechSynthesis::pending() const {
  // This is true if there are any utterances that have not started.
  // That means there will be more than one in the queue.
  return utterance_queue_.size() > 1;
}

bool SpeechSynthesis::paused() const {
  return is_paused_;
}

void SpeechSynthesis::Speak(const String& text, const String& lang) {
  ScriptState* script_state =
      ToScriptStateForMainWorld(GetSupplementable()->GetFrame());
  SpeechSynthesisUtterance* utterance =
      SpeechSynthesisUtterance::Create(GetSupplementable(), text);
  utterance->setLang(lang);
  speak(script_state, utterance);
}

void SpeechSynthesis::speak(ScriptState* script_state,
                            SpeechSynthesisUtterance* utterance) {
  DCHECK(utterance);
  if (!script_state->ContextIsValid())
    return;

  // Note: Non-UseCounter based TTS metrics are of the form TextToSpeech.* and
  // are generally global, whereas these are scoped to a single page load.
  UseCounter::Count(GetSupplementable(), WebFeature::kTextToSpeech_Speak);
  GetSupplementable()->CountUseOnlyInCrossOriginIframe(
      WebFeature::kTextToSpeech_SpeakCrossOrigin);
  if (!IsAllowedToStartByAutoplay()) {
    Deprecation::CountDeprecation(
        GetSupplementable(),
        WebFeature::kTextToSpeech_SpeakDisallowedByAutoplay);
    FireErrorEvent(utterance, 0 /* char_index */, "not-allowed");
    return;
  }

  utterance_queue_.push_back(utterance);

  // If the queue was empty, speak this immediately.
  if (utterance_queue_.size() == 1)
    StartSpeakingImmediately();
}

void SpeechSynthesis::Cancel() {
  // Remove all the items from the utterance queue. The platform
  // may still have references to some of these utterances and may
  // fire events on them asynchronously.
  utterance_queue_.clear();

  if (mojom::blink::SpeechSynthesis* mojom_synthesis =
          TryEnsureMojomSynthesis())
    mojom_synthesis->Cancel();
}

void SpeechSynthesis::Pause() {
  if (is_paused_)
    return;

  if (mojom::blink::SpeechSynthesis* mojom_synthesis =
          TryEnsureMojomSynthesis())
    mojom_synthesis->Pause();
}

void SpeechSynthesis::Resume() {
  if (!CurrentSpeechUtterance())
    return;

  if (mojom::blink::SpeechSynthesis* mojom_synthesis =
          TryEnsureMojomSynthesis())
    mojom_synthesis->Resume();
}

void SpeechSynthesis::DidStartSpeaking(SpeechSynthesisUtterance* utterance) {
  FireEvent(event_type_names::kStart, utterance, 0, 0, String());
}

void SpeechSynthesis::DidPauseSpeaking(SpeechSynthesisUtterance* utterance) {
  is_paused_ = true;
  FireEvent(event_type_names::kPause, utterance, 0, 0, String());
}

void SpeechSynthesis::DidResumeSpeaking(SpeechSynthesisUtterance* utterance) {
  is_paused_ = false;
  FireEvent(event_type_names::kResume, utterance, 0, 0, String());
}

void SpeechSynthesis::DidFinishSpeaking(
    SpeechSynthesisUtterance* utterance,
    mojom::blink::SpeechSynthesisErrorCode error_code) {
  HandleSpeakingCompleted(utterance, error_code);
}

void SpeechSynthesis::SpeakingErrorOccurred(
    SpeechSynthesisUtterance* utterance) {
  HandleSpeakingCompleted(
      utterance, mojom::blink::SpeechSynthesisErrorCode::kErrorOccurred);
}

void SpeechSynthesis::WordBoundaryEventOccurred(
    SpeechSynthesisUtterance* utterance,
    unsigned char_index,
    unsigned char_length) {
  DEFINE_STATIC_LOCAL(const String, word_boundary_string, ("word"));
  FireEvent(event_type_names::kBoundary, utterance, char_index, char_length,
            word_boundary_string);
}

void SpeechSynthesis::SentenceBoundaryEventOccurred(
    SpeechSynthesisUtterance* utterance,
    unsigned char_index,
    unsigned char_length) {
  DEFINE_STATIC_LOCAL(const String, sentence_boundary_string, ("sentence"));
  FireEvent(event_type_names::kBoundary, utterance, char_index, char_length,
            sentence_boundary_string);
}

void SpeechSynthesis::VoicesDidChange() {
  DispatchEvent(*Event::Create(event_type_names::kVoiceschanged));
}

void SpeechSynthesis::StartSpeakingImmediately() {
  SpeechSynthesisUtterance* utterance = CurrentSpeechUtterance();
  DCHECK(utterance);

  double millis;
  if (!GetElapsedTimeMillis(&millis))
    return;

  utterance->SetStartTime(millis / 1000.0);
  is_paused_ = false;

  if (TryEnsureMojomSynthesis())
    utterance->Start(this);
}

void SpeechSynthesis::HandleSpeakingCompleted(
    SpeechSynthesisUtterance* utterance,
    mojom::blink::SpeechSynthesisErrorCode error_code) {
  DCHECK(utterance);

  // Special handling for audio descriptions.
  SpeechSynthesisBase::HandleSpeakingCompleted();

  bool should_start_speaking = false;
  // If the utterance that completed was the one we're currently speaking,
  // remove it from the queue and start speaking the next one.
  if (utterance == CurrentSpeechUtterance()) {
    utterance_queue_.pop_front();
    should_start_speaking = !utterance_queue_.empty();
  }

  // https://wicg.github.io/speech-api/#speechsynthesiserrorevent-attributes
  // The below errors are matched with SpeechSynthesisErrorCode values.
  static constexpr char kErrorCanceled[] = "canceled";
  static constexpr char kErrorInterrupted[] = "interrupted";
  static constexpr char kErrorSynthesisFailed[] = "synthesis-failed";

  // Always fire the event, because the platform may have asynchronously
  // sent an event on an utterance before it got the message that we
  // canceled it, and we should always report to the user what actually
  // happened.
  switch (error_code) {
    case mojom::blink::SpeechSynthesisErrorCode::kInterrupted:
      FireErrorEvent(utterance, 0, kErrorInterrupted);
      break;
    case mojom::blink::SpeechSynthesisErrorCode::kCancelled:
      FireErrorEvent(utterance, 0, kErrorCanceled);
      break;
    case mojom::blink::SpeechSynthesisErrorCode::kErrorOccurred:
      // TODO(csharrison): Actually pass the correct message. For now just use a
      // generic error.
      FireErrorEvent(utterance, 0, kErrorSynthesisFailed);
      break;
    case mojom::blink::SpeechSynthesisErrorCode::kNoError:
      FireEvent(event_type_names::kEnd, utterance, 0, 0, String());
      break;
  }

  // Start the next utterance if we just finished one and one was pending.
  if (should_start_speaking && !utterance_queue_.empty())
    StartSpeakingImmediately();
}

void SpeechSynthesis::FireEvent(const AtomicString& type,
                                SpeechSynthesisUtterance* utterance,
                                uint32_t char_index,
                                uint32_t char_length,
                                const String& name) {
  double millis;
  if (!GetElapsedTimeMillis(&millis))
    return;

  SpeechSynthesisEventInit* init = SpeechSynthesisEventInit::Create();
  init->setUtterance(utterance);
  init->setCharIndex(char_index);
  init->setCharLength(char_length);
  init->setElapsedTime(millis - (utterance->StartTime() * 1000.0));
  init->setName(name);
  utterance->DispatchEvent(*SpeechSynthesisEvent::Create(type, init));
}

void SpeechSynthesis::FireErrorEvent(SpeechSynthesisUtterance* utterance,
                                     uint32_t char_index,
                                     const String& error) {
  double millis;
  if (!GetElapsedTimeMillis(&millis))
    return;

  SpeechSynthesisErrorEventInit* init = SpeechSynthesisErrorEventInit::Create();
  init->setUtterance(utterance);
  init->setCharIndex(char_index);
  init->setElapsedTime(millis - (utterance->StartTime() * 1000.0));
  init->setError(error);
  utterance->DispatchEvent(
      *SpeechSynthesisErrorEvent::Create(event_type_names::kError, init));
}

SpeechSynthesisUtterance* SpeechSynthesis::CurrentSpeechUtterance() const {
  if (utterance_queue_.empty())
    return nullptr;

  return utterance_queue_.front().Get();
}

ExecutionContext* SpeechSynthesis::GetExecutionContext() const {
  return GetSupplementable();
}

void SpeechSynthesis::Trace(Visitor* visitor) const {
  visitor->Trace(receiver_);
  visitor->Trace(mojom_synthesis_);
  visitor->Trace(voice_list_);
  visitor->Trace(utterance_queue_);
  Supplement<LocalDOMWindow>::Trace(visitor);
  EventTarget::Trace(visitor);
  SpeechSynthesisBase::Trace(visitor);
}

bool SpeechSynthesis::GetElapsedTimeMillis(double* millis) {
  if (!GetSupplementable()->GetFrame())
    return false;
  if (GetSupplementable()->document()->IsStopped())
    return false;

  *millis = DOMWindowPerformance::performance(*GetSupplementable())->now();
  return true;
}

bool SpeechSynthesis::IsAllowedToStartByAutoplay() const {
  Document* document = GetSupplementable()->document();
  DCHECK(document);

  // Note: could check the utterance->volume here, but that could be overriden
  // in the case of SSML.
  if (AutoplayPolicy::GetAutoplayPolicyForDocument(*document) !=
      AutoplayPolicy::Type::kDocumentUserActivationRequired) {
    return true;
  }
  return AutoplayPolicy::IsDocumentAllowedToPlay(*document);
}

void SpeechSynthesis::SetMojomSynthesisForTesting(
    mojo::PendingRemote<mojom::blink::SpeechSynthesis> mojom_synthesis) {
  mojom_synthesis_.Bind(
      std::move(mojom_synthesis),
      GetSupplementable()->GetTaskRunner(TaskType::kMiscPlatformAPI));
  receiver_.reset();
  mojom_synthesis_->AddVoiceListObserver(receiver_.BindNewPipeAndPassRemote(
      GetSupplementable()->GetTaskRunner(TaskType::kMiscPlatformAPI)));
}

mojom::blink::SpeechSynthesis* SpeechSynthesis::TryEnsureMojomSynthesis() {
  if (mojom_synthesis_.is_bound())
    return mojom_synthesis_.get();

  // The frame could be detached. In that case, calls on mojom_synthesis_ will
  // just get dropped. That's okay and is simpler than having to null-check
  // mojom_synthesis_ before each use.
  LocalDOMWindow* window = GetSupplementable();
  if (!window->GetFrame())
    return nullptr;

  auto receiver = mojom_synthesis_.BindNewPipeAndPassReceiver(
      window->GetTaskRunner(TaskType::kMiscPlatformAPI));

  window->GetBrowserInterfaceBroker().GetInterface(std::move(receiver));

  mojom_synthesis_->AddVoiceListObserver(receiver_.BindNewPipeAndPassRemote(
      window->GetTaskRunner(TaskType::kMiscPlatformAPI)));
  return mojom_synthesis_.get();
}

const AtomicString& SpeechSynthesis::InterfaceName() const {
  return event_target_names::kSpeechSynthesis;
}

}  // namespace blink

"""

```