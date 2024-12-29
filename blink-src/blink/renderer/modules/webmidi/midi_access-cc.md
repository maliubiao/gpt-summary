Response:
Let's break down the thought process for analyzing the `midi_access.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the `MIDIAccess` class, its relationship to web technologies, examples, potential errors, and debugging information. This requires looking at the code from different angles: its purpose, its interactions, and how it could go wrong.

2. **Initial Code Scan and Keyword Spotting:**  The first step is to quickly skim the code, looking for important keywords and structures. Things that jump out are:

    * `MIDIAccess`: This is clearly the central class we need to understand.
    * `#include`:  These tell us about dependencies and the modules `MIDIAccess` interacts with (e.g., `midi_input.h`, `midi_output.h`, `document.h`, `event_target.h`).
    * `inputs_`, `outputs_`: These are likely collections of MIDI input and output ports.
    * `DidAddInputPort`, `DidAddOutputPort`, `DidSetInputPortState`, `DidSetOutputPortState`, `DidReceiveMIDIData`, `SendMIDIData`: These function names suggest the core operations of managing MIDI devices and data.
    * `onstatechange`, `setOnstatechange`:  This points to an event for when MIDI device status changes.
    * `inputs()`, `outputs()`:  These likely provide access to the collections of MIDI ports.
    * `sysex_enabled_`: This hints at a configurable option for System Exclusive messages.
    * `IdentifiableSurface`, `IdentifiabilityMetricBuilder`: These suggest telemetry or privacy-related features.

3. **Deconstruct the Class and its Methods:**  Next, focus on the `MIDIAccess` class itself and analyze its methods:

    * **Constructor (`MIDIAccess(...)`):**  What are its parameters?  `MIDIDispatcher`, `sysex_enabled`, and a vector of port descriptors. This immediately suggests its role in receiving information from a lower-level MIDI system (`MIDIDispatcher`) and initializing its internal state. The loop creating `MIDIInput` and `MIDIOutput` objects tells us how it represents connected MIDI devices. The privacy budget code hints at tracking usage of this feature.
    * **Destructor (`~MIDIAccess()`):**  It's default, so no special cleanup logic is immediately apparent in this class itself.
    * **`onstatechange()`/`setOnstatechange()`:** This clearly handles the `statechange` event, which is standard JavaScript event handling. This is a crucial link to JavaScript.
    * **`HasPendingActivity()`:**  This likely determines if the object is still active and should not be garbage collected.
    * **`inputs()`/`outputs()`:**  These methods create `MIDIInputMap` and `MIDIOutputMap` objects, suggesting a specific structure for exposing the available MIDI ports to JavaScript. The duplication check is interesting and indicates a potential edge case.
    * **`DidAddInputPort` etc.:** These methods, prefixed with "Did," suggest they are callbacks from the lower-level `MIDIDispatcher` when new MIDI devices are connected or their state changes. They update the internal lists and dispatch `MIDIConnectionEvent`s.
    * **`DidReceiveMIDIData`:**  This is the core data reception method, forwarding the data to the appropriate `MIDIInput` object.
    * **`SendMIDIData`:**  This method takes MIDI data and sends it through the `MIDIDispatcher`. The checks at the beginning are important for error handling.
    * **`Trace()`:** This is for Blink's garbage collection system, allowing it to track references.

4. **Identify Relationships to Web Technologies:** Now, connect the dots to JavaScript, HTML, and CSS:

    * **JavaScript:** The `onstatechange` event and the `inputs()`/`outputs()` methods that return `MIDIInputMap` and `MIDIOutputMap` are the primary interfaces to JavaScript. JavaScript code will call these methods and listen for the event.
    * **HTML:**  While not directly related to HTML rendering, the Web MIDI API is *accessed* through JavaScript within an HTML page. The user interaction to grant MIDI access could involve prompts triggered from JavaScript.
    * **CSS:**  No direct relationship to CSS in terms of styling or layout.

5. **Construct Examples:**  Based on the method analysis, create concrete examples of how JavaScript would interact with `MIDIAccess`. This involves calling `navigator.requestMIDIAccess()` and then accessing the `inputs` and `outputs` properties, as well as setting up an event listener.

6. **Infer Logical Reasoning (Assumptions and Outputs):**  Consider the flow of data. When a MIDI device is connected (hypothetical input to the system), the `MIDIDispatcher` would notify `MIDIAccess`, leading to the `DidAddInputPort` or `DidAddOutputPort` methods being called. The output would be the dispatch of a `MIDIConnectionEvent`. Similarly, when MIDI data arrives, it's passed to `DidReceiveMIDIData` and then to the specific `MIDIInput` object.

7. **Identify Potential User/Programming Errors:** Think about how developers might misuse the API:

    * Not checking for MIDI support.
    * Not handling the promise correctly.
    * Incorrectly handling MIDI messages.
    * Expecting immediate device availability.
    * Not understanding the asynchronous nature of MIDI.

8. **Trace User Operations (Debugging Clues):**  How does a user get to a point where this code is running?  Start with the user physically connecting a MIDI device, then opening a webpage that uses the Web MIDI API. The browser will request permission, and upon granting, the JavaScript code will interact with the Blink engine, eventually reaching `MIDIAccess`.

9. **Review and Refine:** Read through the analysis, ensuring clarity, accuracy, and completeness. Check if all aspects of the request have been addressed. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For example, explicitly stating that `MIDIDispatcher` is a lower-level component helps clarify the architecture.

This systematic approach, starting with high-level understanding and then diving into the details, allows for a comprehensive analysis of the code and its role within the larger system. The focus is not just on *what* the code does but also *why* and *how* it fits into the web development context.
好的，我们来分析一下 `blink/renderer/modules/webmidi/midi_access.cc` 文件的功能。

**功能概览**

`MIDIAccess.cc` 文件定义了 Chromium Blink 引擎中 `MIDIAccess` 类的实现。 `MIDIAccess` 类是 Web MIDI API 的核心接口，它代表了对用户系统上 MIDI 设备的访问权限。它的主要功能包括：

1. **管理 MIDI 输入和输出端口:**  `MIDIAccess` 对象维护着当前系统上可用的 MIDI 输入和输出端口的列表。
2. **监听 MIDI 设备连接和断开事件:** 当有新的 MIDI 设备连接或断开时，`MIDIAccess` 会接收到通知并更新其内部的端口列表，并触发 `statechange` 事件。
3. **提供访问 MIDI 端口的接口:**  它提供了 `inputs()` 和 `outputs()` 方法，返回 `MIDIInputMap` 和 `MIDIOutputMap` 对象，允许 JavaScript 代码访问可用的 MIDI 输入和输出端口。
4. **处理来自底层 MIDI 系统的事件:** 它接收来自 `MIDIDispatcher` 的事件，例如新的 MIDI 端口添加、端口状态改变以及接收到的 MIDI 数据。
5. **向底层 MIDI 系统发送数据:**  它提供了 `SendMIDIData()` 方法，允许将 MIDI 数据发送到指定的输出端口。
6. **触发 `statechange` 事件:** 当 MIDI 设备的连接状态发生变化时，它会触发 `statechange` 事件，通知 JavaScript 代码。
7. **集成隐私保护机制:**  该代码包含了与隐私预算相关的逻辑，用于追踪 Web MIDI API 的使用情况。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`MIDIAccess` 类是 Web MIDI API 的核心，因此与 JavaScript 关系最为密切。它允许 JavaScript 代码与用户的 MIDI 设备进行交互。

* **JavaScript:**
    * **获取 MIDI 访问权限:**  JavaScript 代码使用 `navigator.requestMIDIAccess(options)` 方法来请求 MIDI 访问权限。 这个方法的成功回调会返回一个 `MIDIAccess` 对象。
        ```javascript
        navigator.requestMIDIAccess()
          .then(onMIDISuccess, onMIDIFailure);

        function onMIDISuccess(midiAccess) {
          console.log('WebMIDI 已启用!');
          // midiAccess 是 MIDIAccess 类的实例
          const inputs = midiAccess.inputs;
          const outputs = midiAccess.outputs;

          inputs.forEach(input => {
            console.log(`输入设备: ${input.name}, ID: ${input.id}`);
            input.onmidimessage = onMIDIMessage;
          });

          outputs.forEach(output => {
            console.log(`输出设备: ${output.name}, ID: ${output.id}`);
          });

          midiAccess.onstatechange = (event) => {
            console.log('MIDI 设备状态改变:', event.port.name, event.port.state);
          };
        }

        function onMIDIFailure() {
          console.log('无法访问 MIDI 设备。');
        }

        function onMIDIMessage(midiMessage) {
          const data = midiMessage.data;
          console.log('接收到 MIDI 消息:', data);
        }
        ```
    * **监听设备状态变化:** `MIDIAccess` 对象的 `onstatechange` 属性允许 JavaScript 代码注册一个事件监听器，当 MIDI 设备的连接状态发生变化时得到通知。
    * **访问输入和输出端口:**  JavaScript 代码通过 `midiAccess.inputs` 和 `midiAccess.outputs` 属性（返回 `MIDIInputMap` 和 `MIDIOutputMap` 对象）来访问可用的 MIDI 输入和输出端口。
    * **发送 MIDI 数据:**  虽然 `MIDIAccess` 本身没有直接发送数据的方法，但它关联的 `MIDIOutput` 对象有 `send()` 方法，JavaScript 代码通过 `MIDIOutput` 对象发送 MIDI 数据。

* **HTML:**
    * HTML 文件中嵌入的 JavaScript 代码会使用 Web MIDI API，从而间接地与 `MIDIAccess` 类发生交互。 例如，一个网页可能包含一个按钮，点击后会调用 JavaScript 代码来请求 MIDI 访问权限。
    * 用户可能需要通过浏览器提供的权限提示来授权网页访问 MIDI 设备。这个用户界面是浏览器提供的，但其背后的逻辑与 `MIDIAccess` 的初始化和权限管理有关。

* **CSS:**
    * CSS 与 `MIDIAccess` 类没有直接的功能关系。CSS 负责网页的样式和布局，而 `MIDIAccess` 负责处理 MIDI 设备的访问和数据传输。

**逻辑推理、假设输入与输出**

假设用户连接了一个新的 MIDI 键盘到计算机上，并且一个网页正在运行并监听 MIDI 设备状态变化。

* **假设输入:**
    1. 用户连接了一个新的 MIDI 键盘。
    2. 底层操作系统检测到新的 MIDI 设备。
    3. Chromium 浏览器接收到操作系统关于新 MIDI 设备的通知。

* **逻辑推理:**
    1. `MIDIDispatcher` (一个负责与底层 MIDI 系统通信的模块) 会检测到新的 MIDI 设备。
    2. `MIDIDispatcher` 会通知与当前文档关联的 `MIDIAccess` 对象，调用其 `DidAddInputPort` (如果新设备是输入设备) 或 `DidAddOutputPort` (如果新设备是输出设备) 方法。
    3. 在 `DidAddInputPort` 或 `DidAddOutputPort` 方法中，会创建一个新的 `MIDIInput` 或 `MIDIOutput` 对象，并将其添加到 `MIDIAccess` 对象的内部列表中。
    4. `MIDIAccess` 对象会创建一个 `MIDIConnectionEvent` 并触发 `statechange` 事件。

* **输出:**
    1. `MIDIAccess` 对象的 `inputs()` 或 `outputs()` 方法返回的 `MIDIInputMap` 或 `MIDIOutputMap` 对象会包含新连接的 MIDI 设备。
    2. 网页中注册的 `onstatechange` 事件监听器会被触发，`event.port` 将指向新连接的 `MIDIInput` 或 `MIDIOutput` 对象，`event.port.state` 将为 "connected"。
    3. 控制台中会打印出类似 "MIDI 设备状态改变: [设备名称] connected" 的消息（假设 JavaScript 代码中有相应的 `console.log`）。

**用户或编程常见的使用错误及举例说明**

1. **用户未授权 MIDI 访问:**
   * **错误:**  JavaScript 代码调用 `navigator.requestMIDIAccess()` 但用户在浏览器提示中拒绝了权限。
   * **结果:** `Promise` 会被拒绝，`onMIDIFailure` 回调函数会被执行。
   * **代码示例:**
     ```javascript
     navigator.requestMIDIAccess()
       .then(onMIDISuccess, onMIDIFailure);

     function onMIDISuccess(midiAccess) {
       // 这段代码不会执行
     }

     function onMIDIFailure() {
       console.error('用户拒绝了 MIDI 访问权限。');
     }
     ```

2. **编程错误：未检查 MIDI 支持:**
   * **错误:**  在不支持 Web MIDI API 的浏览器中尝试使用 `navigator.requestMIDIAccess()`。
   * **结果:**  `navigator.requestMIDIAccess` 可能为 `undefined`，导致 JavaScript 错误。
   * **代码示例:**
     ```javascript
     if (navigator.requestMIDIAccess) {
       navigator.requestMIDIAccess()
         .then(onMIDISuccess, onMIDIFailure);
     } else {
       console.error('您的浏览器不支持 Web MIDI API。');
     }
     ```

3. **编程错误：假设设备总是存在:**
   * **错误:**  代码在初始化时就尝试访问特定的 MIDI 设备，而没有考虑设备可能未连接的情况。
   * **结果:**  尝试访问不存在的端口可能会导致错误或空指针异常。
   * **代码示例 (错误):**
     ```javascript
     navigator.requestMIDIAccess()
       .then(midiAccess => {
         const input = midiAccess.inputs.get("some-specific-input-id");
         input.onmidimessage = handleMIDIMessage; // 如果没有找到该 ID 的设备，input 可能为 null
       });
     ```
   * **正确做法:** 应该遍历可用的设备，或者监听 `statechange` 事件来处理设备的连接和断开。

4. **用户操作错误：未正确连接 MIDI 设备或驱动问题:**
   * **错误:** 用户连接了 MIDI 设备，但设备未被操作系统正确识别或驱动程序有问题。
   * **结果:**  即使网页请求了 MIDI 访问权限，`MIDIAccess` 对象也无法检测到该设备。`inputs` 和 `outputs` 列表中不会显示该设备。

**用户操作是如何一步步的到达这里，作为调试线索**

当开发者在调试 Web MIDI 相关问题时，理解用户操作路径至关重要。以下是用户操作如何一步步触发 `midi_access.cc` 中代码执行的流程：

1. **用户连接 MIDI 设备:**  用户将 MIDI 键盘、合成器或其他 MIDI 设备通过 USB 或其他接口连接到计算机。
2. **操作系统识别设备:** 操作系统（Windows, macOS, Linux 等）检测到新连接的硬件，并加载相应的驱动程序。
3. **用户打开网页:** 用户在 Chromium 浏览器中打开一个使用了 Web MIDI API 的网页。
4. **JavaScript 代码请求 MIDI 访问权限:** 网页的 JavaScript 代码执行 `navigator.requestMIDIAccess(options)`。
5. **浏览器处理权限请求:**
   * Chromium 浏览器接收到权限请求。
   * 浏览器可能会显示一个权限提示，询问用户是否允许该网页访问 MIDI 设备。
6. **用户授权访问:** 用户在权限提示中点击“允许”。
7. **Blink 引擎初始化 `MIDIAccess`:**
   * 如果用户授权了访问，Blink 引擎会创建一个与当前文档相关的 `MIDIAccess` 对象。
   * 在 `MIDIAccess` 的构造函数中，它会通过 `MIDIDispatcher` 查询当前系统上可用的 MIDI 端口。
   * `MIDIDispatcher` 会与底层的 MIDI 系统（例如，Core MIDI on macOS, WinRT MIDI on Windows, ALSA on Linux）通信来获取设备信息。
   * `MIDIAccess` 会根据查询到的端口信息创建 `MIDIInput` 和 `MIDIOutput` 对象。
8. **JavaScript 代码访问 MIDI 端口:**  JavaScript 代码可以通过 `midiAccess.inputs` 和 `midiAccess.outputs` 访问 MIDI 端口列表。
9. **监听 MIDI 消息:** JavaScript 代码可以为 `MIDIInput` 对象的 `onmidimessage` 属性设置回调函数，以接收来自 MIDI 设备的消息。
10. **MIDI 设备发送消息:**  用户在 MIDI 设备上进行操作（例如按下琴键），设备会生成 MIDI 消息。
11. **底层系统传递消息:** 操作系统将 MIDI 消息传递给 Chromium 浏览器。
12. **`MIDIDispatcher` 接收消息:** `MIDIDispatcher` 接收到来自底层系统的 MIDI 消息。
13. **`MIDIAccess` 处理消息:** `MIDIDispatcher` 将消息传递给相应的 `MIDIAccess` 对象，调用其 `DidReceiveMIDIData` 方法。
14. **`MIDIInput` 对象触发 `midimessage` 事件:** `MIDIAccess` 对象会将接收到的数据传递给相应的 `MIDIInput` 对象，`MIDIInput` 对象会创建一个 `MIDIMessageEvent` 并触发其 `onmidimessage` 回调函数。
15. **JavaScript 代码处理 MIDI 消息:**  JavaScript 代码中的 `onmidimessage` 回调函数被执行，从而处理接收到的 MIDI 数据。

**调试线索:**

* **检查浏览器 MIDI 支持:**  首先确认用户使用的浏览器是否支持 Web MIDI API。
* **检查 MIDI 设备连接:** 确认用户的 MIDI 设备已正确连接到计算机，并且操作系统已识别该设备。可以在操作系统的设备管理器或系统信息中查看。
* **检查浏览器权限:** 确认用户已授权该网页访问 MIDI 设备。可以在浏览器的设置中查看网站的权限。
* **使用浏览器的开发者工具:**
    * **Console:** 查看 JavaScript 代码的输出，包括 `console.log` 和错误信息。
    * **Sources:**  在 JavaScript 代码中设置断点，逐步执行代码，查看 `MIDIAccess` 对象及其属性的值。
    * **Network:** 虽然 Web MIDI 不涉及 HTTP 请求，但可以查看其他网络活动，以排除其他干扰因素。
* **查看 Chromium 的内部日志:**  可以启用 Chromium 的日志记录功能，查看与 MIDI 相关的日志信息，这可以提供更底层的调试信息。
* **测试不同的 MIDI 设备和浏览器:**  尝试使用不同的 MIDI 设备和浏览器版本，以排除特定设备或浏览器引起的问题。

理解这些步骤和潜在的错误场景，可以帮助开发者更有效地调试 Web MIDI 相关的问题。 `midi_access.cc` 文件在整个流程中扮演着核心的角色，负责连接 JavaScript 代码和底层的 MIDI 系统。

Prompt: 
```
这是目录为blink/renderer/modules/webmidi/midi_access.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webmidi/midi_access.h"

#include <memory>
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/modules/webmidi/midi_access_initializer.h"
#include "third_party/blink/renderer/modules/webmidi/midi_connection_event.h"
#include "third_party/blink/renderer/modules/webmidi/midi_input.h"
#include "third_party/blink/renderer/modules/webmidi/midi_input_map.h"
#include "third_party/blink/renderer/modules/webmidi/midi_output.h"
#include "third_party/blink/renderer/modules/webmidi/midi_output_map.h"
#include "third_party/blink/renderer/modules/webmidi/midi_port.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"

namespace blink {

namespace {

using midi::mojom::PortState;

// Since "open" status is separately managed per MIDIAccess instance, we do not
// expose service level PortState directly.
PortState ToDeviceState(PortState state) {
  if (state == PortState::OPENED)
    return PortState::CONNECTED;
  return state;
}

}  // namespace

MIDIAccess::MIDIAccess(
    MIDIDispatcher* dispatcher,
    bool sysex_enabled,
    const Vector<MIDIAccessInitializer::PortDescriptor>& ports,
    ExecutionContext* execution_context)
    : ActiveScriptWrappable<MIDIAccess>({}),
      ExecutionContextLifecycleObserver(execution_context),
      dispatcher_(dispatcher),
      sysex_enabled_(sysex_enabled),
      has_pending_activity_(false) {
  dispatcher_->SetClient(this);
  for (const auto& port : ports) {
    if (port.type == MIDIPortType::kInput) {
      inputs_.push_back(MakeGarbageCollected<MIDIInput>(
          this, port.id, port.manufacturer, port.name, port.version,
          ToDeviceState(port.state)));
    } else {
      outputs_.push_back(MakeGarbageCollected<MIDIOutput>(
          this, outputs_.size(), port.id, port.manufacturer, port.name,
          port.version, ToDeviceState(port.state)));
    }
  }
  constexpr IdentifiableSurface surface = IdentifiableSurface::FromTypeAndToken(
      IdentifiableSurface::Type::kWebFeature,
      WebFeature::kRequestMIDIAccess_ObscuredByFootprinting);
  if (IdentifiabilityStudySettings::Get()->ShouldSampleSurface(surface)) {
    IdentifiableTokenBuilder builder;
    for (const auto& port : ports) {
      builder.AddToken(IdentifiabilityBenignStringToken(port.id));
      builder.AddToken(IdentifiabilityBenignStringToken(port.name));
      builder.AddToken(IdentifiabilityBenignStringToken(port.manufacturer));
      builder.AddToken(IdentifiabilityBenignStringToken(port.version));
      builder.AddToken(port.type);
    }
    IdentifiabilityMetricBuilder(execution_context->UkmSourceID())
        .Add(surface, builder.GetToken())
        .Record(execution_context->UkmRecorder());
  }
}

MIDIAccess::~MIDIAccess() = default;

EventListener* MIDIAccess::onstatechange() {
  return GetAttributeEventListener(event_type_names::kStatechange);
}

void MIDIAccess::setOnstatechange(EventListener* listener) {
  has_pending_activity_ = listener;
  SetAttributeEventListener(event_type_names::kStatechange, listener);
}

bool MIDIAccess::HasPendingActivity() const {
  return has_pending_activity_ && GetExecutionContext() &&
         !GetExecutionContext()->IsContextDestroyed();
}

MIDIInputMap* MIDIAccess::inputs() const {
  HeapVector<Member<MIDIInput>> inputs;
  HashSet<String> ids;
  for (MIDIInput* input : inputs_) {
    if (input->GetState() != PortState::DISCONNECTED) {
      inputs.push_back(input);
      ids.insert(input->id());
    }
  }
  if (inputs.size() != ids.size()) {
    // There is id duplication that violates the spec.
    inputs.clear();
  }
  return MakeGarbageCollected<MIDIInputMap>(inputs);
}

MIDIOutputMap* MIDIAccess::outputs() const {
  HeapVector<Member<MIDIOutput>> outputs;
  HashSet<String> ids;
  for (MIDIOutput* output : outputs_) {
    if (output->GetState() != PortState::DISCONNECTED) {
      outputs.push_back(output);
      ids.insert(output->id());
    }
  }
  if (outputs.size() != ids.size()) {
    // There is id duplication that violates the spec.
    outputs.clear();
  }
  return MakeGarbageCollected<MIDIOutputMap>(outputs);
}

void MIDIAccess::DidAddInputPort(const String& id,
                                 const String& manufacturer,
                                 const String& name,
                                 const String& version,
                                 PortState state) {
  DCHECK(IsMainThread());
  auto* port = MakeGarbageCollected<MIDIInput>(this, id, manufacturer, name,
                                               version, ToDeviceState(state));
  inputs_.push_back(port);
  DispatchEvent(*MIDIConnectionEvent::Create(port));
}

void MIDIAccess::DidAddOutputPort(const String& id,
                                  const String& manufacturer,
                                  const String& name,
                                  const String& version,
                                  PortState state) {
  DCHECK(IsMainThread());
  unsigned port_index = outputs_.size();
  auto* port = MakeGarbageCollected<MIDIOutput>(
      this, port_index, id, manufacturer, name, version, ToDeviceState(state));
  outputs_.push_back(port);
  DispatchEvent(*MIDIConnectionEvent::Create(port));
}

void MIDIAccess::DidSetInputPortState(unsigned port_index, PortState state) {
  DCHECK(IsMainThread());
  if (port_index >= inputs_.size())
    return;

  PortState device_state = ToDeviceState(state);
  if (inputs_[port_index]->GetState() != device_state)
    inputs_[port_index]->SetState(device_state);
}

void MIDIAccess::DidSetOutputPortState(unsigned port_index, PortState state) {
  DCHECK(IsMainThread());
  if (port_index >= outputs_.size())
    return;

  PortState device_state = ToDeviceState(state);
  if (outputs_[port_index]->GetState() != device_state)
    outputs_[port_index]->SetState(device_state);
}

void MIDIAccess::DidReceiveMIDIData(unsigned port_index,
                                    base::span<const uint8_t> data,
                                    base::TimeTicks time_stamp) {
  DCHECK(IsMainThread());
  if (port_index >= inputs_.size())
    return;

  inputs_[port_index]->DidReceiveMIDIData(port_index, data, time_stamp);
}

void MIDIAccess::SendMIDIData(unsigned port_index,
                              base::span<const uint8_t> data,
                              base::TimeTicks time_stamp) {
  DCHECK(!time_stamp.is_null());
  if (!GetExecutionContext() || !data.data() || data.empty() ||
      port_index >= outputs_.size()) {
    return;
  }

  dispatcher_->SendMIDIData(port_index, data, time_stamp);
}

void MIDIAccess::Trace(Visitor* visitor) const {
  visitor->Trace(dispatcher_);
  visitor->Trace(inputs_);
  visitor->Trace(outputs_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink

"""

```