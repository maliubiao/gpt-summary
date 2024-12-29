Response:
Let's break down the thought process for analyzing this `RTCDataChannel.cc` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `RTCDataChannel.cc` file, covering its functionality, relationships with web technologies, logical reasoning, potential errors, and debugging information.

**2. Initial Scan and Keyword Identification:**

I started by quickly scanning the code, looking for keywords and patterns that would give me a high-level understanding:

* **Includes:**  `rtc_data_channel.h`, various Blink headers (`core/events`, `core/execution_context`, `core/fileapi`, `core/typed_arrays`), and `third_party/webrtc` headers. This immediately tells me it's a core part of the WebRTC implementation within Blink.
* **Namespaces:** `blink`, anonymous namespace. This indicates it's part of the Blink rendering engine. The anonymous namespace suggests helper functions and constants used internally.
* **Classes:** `RTCDataChannel`, `Observer`, `BlobReader`, `PendingMessage`. This hints at the main data channel class and its associated helper classes for managing asynchronous operations and events.
* **WebRTC specific terms:** `DataChannelInterface`, `DataBuffer`, `RTCError`. This confirms its direct interaction with the WebRTC native API.
* **Event related terms:** `DispatchEvent`, `event_type_names::kOpen`, `event_type_names::kMessage`, etc. This signals its role in handling and dispatching events to JavaScript.
* **Data transfer related terms:** `send`, `bufferedAmount`, `Blob`, `ArrayBuffer`. This points to its core responsibility of sending and receiving data.
* **Threading and Asynchronicity:** `PostCrossThreadTask`, `scoped_refptr`, `base::BindOnce`. This highlights the cross-thread nature of WebRTC and the use of asynchronous operations.
* **`/* ... */` comments:**  While not strictly code, the copyright notice and the comments about histograms provide valuable context.

**3. Deconstructing Functionality:**

Based on the initial scan, I started to break down the file's functionality:

* **Core Data Channel Management:** The `RTCDataChannel` class itself is responsible for managing the lifecycle and state of a WebRTC data channel.
* **WebRTC Native Interface:** It acts as a wrapper around the native WebRTC `DataChannelInterface`, translating between the Blink/JavaScript world and the native implementation.
* **Sending Data:**  The `send()` methods handle sending various data types (strings, ArrayBuffers, Blobs). The `ValidateSendLength()` function is important for preventing buffer overflows.
* **Receiving Data:** The `OnMessage()` method processes incoming data from the native layer and converts it into JavaScript-compatible types.
* **State Management:**  The `OnStateChange()` method handles changes in the data channel's state (connecting, open, closing, closed) and dispatches corresponding events.
* **Buffering and Flow Control:** The `bufferedAmount` and `bufferedAmountLowThreshold` properties, along with the `OnBufferedAmountChange()` method, manage the send buffer and trigger events for flow control.
* **Blob Handling:** The `BlobReader` class handles the asynchronous reading of Blob data before sending.
* **Error Handling:** The `OnStateChange()` method dispatches error events when the channel closes with an error.
* **Transferable Data Channels (Feature Flag):** The code includes logic related to transferable data channels, suggesting this is an experimental or newer feature.
* **Metrics and Logging:** The `IncrementCounter` and `UMA_HISTOGRAM_*` calls indicate that the code collects usage statistics.

**4. Identifying Relationships with Web Technologies:**

This involved connecting the code's functionality to how it's used in web development:

* **JavaScript:**  The `RTCDataChannel` object is directly exposed to JavaScript through the WebRTC API. The methods like `send()`, `close()`, and properties like `readyState` are part of this API. Events like `open`, `message`, `error`, and `close` are dispatched to JavaScript event listeners.
* **HTML:** While the code itself doesn't directly manipulate HTML, the data channels are created and used within the context of a web page loaded in a browser. The user interaction that triggers the creation of a data channel (e.g., clicking a button that initiates a WebRTC connection) happens in the HTML context.
* **CSS:** CSS is not directly related to the functionality of this specific C++ file, which deals with the underlying data transfer logic.

**5. Logical Reasoning and Examples:**

For logical reasoning, I focused on the data flow and state transitions:

* **Sending:** The process of validating the send buffer size, queuing messages (especially for Blobs), and sending data asynchronously.
* **Receiving:** The conversion of raw data into different JavaScript types based on the `binaryType`.
* **State Transitions:** The sequence of state changes and the events that are triggered at each stage.

I tried to provide simple examples to illustrate these processes.

**6. Identifying User and Programming Errors:**

This involved thinking about how developers might misuse the API:

* **Sending data when the channel is closed.**
* **Exceeding the send buffer limits.**
* **Incorrectly handling asynchronous operations, especially with Blobs.**

**7. Debugging Clues and User Operations:**

This required tracing back the potential user actions that could lead to this code being executed:

* **Basic WebRTC setup:** Creating an `RTCPeerConnection` and then creating a data channel.
* **Sending and receiving data.**
* **Closing the data channel.**
* **Transferring data channels (if the feature is enabled).**

I emphasized the importance of logging and breakpoints for debugging.

**8. Structuring the Output:**

Finally, I organized the information into logical sections as requested by the prompt, using clear headings and bullet points for readability. I aimed for a balance of technical detail and clear explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the class methods.
* **Correction:** Realized the importance of understanding the helper classes (`Observer`, `BlobReader`, `PendingMessage`) and the overall data flow.
* **Initial thought:** Provide very low-level technical details.
* **Correction:** Shifted to explaining the functionality in a way that connects to the higher-level JavaScript API and user experience.
* **Initial thought:**  Omit the feature flag logic.
* **Correction:** Included the transferable data channel logic because it's present in the code and could be relevant.
* **Initial thought:** Focus only on successful scenarios.
* **Correction:** Made sure to address error handling and potential misuse of the API.

By following these steps, I could systematically analyze the `RTCDataChannel.cc` file and generate a comprehensive and informative response that addresses all aspects of the request.
好的，我们来详细分析一下 `blink/renderer/modules/peerconnection/rtc_data_channel.cc` 这个文件。

**文件功能概述：**

`rtc_data_channel.cc` 文件是 Chromium Blink 引擎中负责实现 WebRTC `RTCDataChannel` API 的核心组件。它的主要功能是：

1. **封装 WebRTC 原生 DataChannel 接口：** 它作为 Blink 和底层的 WebRTC 本地实现 (位于 `third_party/webrtc`) 之间的桥梁，封装了 `webrtc::DataChannelInterface`，提供了在 Blink 渲染引擎中易于使用的 C++ 接口。

2. **管理数据通道的状态：**  跟踪数据通道的连接状态 (connecting, open, closing, closed)，并在状态改变时触发相应的 JavaScript 事件。

3. **实现数据发送功能：**  提供了 `send()` 方法，允许 JavaScript 代码通过数据通道发送不同类型的数据 (字符串、ArrayBuffer、Blob)。

4. **实现数据接收功能：**  监听底层 WebRTC 数据通道接收到的数据，并将其转换为 JavaScript 可用的类型，触发 `message` 事件。

5. **处理数据缓冲：**  维护发送缓冲区的状态 (`bufferedAmount`)，并触发 `bufferedamountlow` 事件以实现流量控制。

6. **处理数据通道的关闭：**  实现了 `close()` 方法，用于关闭数据通道，并触发 `close` 事件。

7. **处理错误：**  监听底层 WebRTC 数据通道的错误，并触发 `error` 事件。

8. **支持可转移的 RTCDataChannel (Transferable RTCDataChannel)：**  实现了允许将 `RTCDataChannel` 对象转移到 Web Workers 的功能 (通过 feature flag 控制)。

9. **收集性能指标：**  使用 UMA 宏记录数据通道的使用情况，例如创建、打开、发送消息的大小等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个 C++ 文件直接关联到 WebRTC API 中的 `RTCDataChannel` 接口，该接口是 JavaScript 中可直接调用的。

* **JavaScript:**
    * **创建 `RTCDataChannel` 对象：**  JavaScript 代码通常通过 `RTCPeerConnection.createDataChannel()` 方法创建一个 `RTCDataChannel` 对象。这个过程最终会调用到 C++ 层的 `RTCDataChannel` 的构造函数。
    * **发送数据：**  JavaScript 中调用 `dataChannel.send(data)` 方法会最终调用到 `rtc_data_channel.cc` 中的 `RTCDataChannel::send()` 方法。
        ```javascript
        let pc = new RTCPeerConnection();
        let dataChannel = pc.createDataChannel('myLabel');

        dataChannel.onopen = function(event) {
          dataChannel.send('Hello from JavaScript!');
        };

        dataChannel.onmessage = function(event) {
          console.log('Received:', event.data);
        };
        ```
        在这个例子中，`dataChannel.send('Hello from JavaScript!')` 的调用最终会由 `rtc_data_channel.cc` 处理。
    * **监听事件：**  JavaScript 可以监听 `RTCDataChannel` 上的 `open`, `message`, `error`, `close`, `bufferedamountlow` 等事件。这些事件的触发逻辑在 `rtc_data_channel.cc` 中实现。例如，当底层的 WebRTC 数据通道状态变为 `kOpen` 时，`RTCDataChannel::OnStateChange()` 会被调用，并触发 JavaScript 的 `open` 事件。
    * **获取属性：** JavaScript 可以访问 `RTCDataChannel` 的属性，如 `label`, `readyState`, `bufferedAmount` 等。这些属性的值由 `rtc_data_channel.cc` 中的对应成员变量维护并返回。

* **HTML:**
    * HTML 结构提供了 JavaScript 代码运行的环境。例如，一个按钮的点击事件可能会触发 JavaScript 代码来建立 WebRTC 连接并创建数据通道。
    * HTML 中可能包含用于显示接收到的消息或其他与数据通道状态相关的 UI 元素。

* **CSS:**
    * CSS 主要负责页面的样式和布局，与 `RTCDataChannel` 的核心功能没有直接关系。但是，CSS 可以用来美化与 WebRTC 功能相关的 UI 元素，例如显示连接状态或接收到的消息的框。

**逻辑推理、假设输入与输出：**

假设 JavaScript 代码执行以下操作：

**假设输入:**

1. 创建一个 `RTCDataChannel` 对象，`label` 为 "myChannel"。
2. 监听 `open` 事件。
3. 监听 `message` 事件。
4. 当 `open` 事件触发后，发送字符串 "TestData"。
5. 远程对等端发送字符串 "Reply"。

**逻辑推理与输出:**

1. **创建 `RTCDataChannel`:**  `RTCPeerConnection.createDataChannel("myChannel")`  会在 C++ 层创建 `RTCDataChannel` 对象，`label()` 方法会返回 "myChannel"。
2. **`open` 事件触发:** 当底层的 WebRTC 数据通道连接成功后，`RTCDataChannel::OnStateChange(kOpen)` 被调用，触发 JavaScript 的 `open` 事件。
   * **输出（JavaScript）:** `dataChannel.onopen` 回调函数被执行。
3. **发送数据:**  `dataChannel.send("TestData")` 调用 `RTCDataChannel::send()`。
   * **假设输入（C++）:** `RTCDataChannel::send()` 接收到字符串 "TestData"。
   * **输出（C++）:** `RTCDataChannel::send()` 将数据封装成 `webrtc::DataBuffer` 并发送到底层的 WebRTC 数据通道。`bufferedAmount_` 增加。
4. **接收数据:** 当远程对等端发送 "Reply" 时，底层的 WebRTC 数据通道接收到数据，并通知到 `RTCDataChannel::Observer::OnMessage()`。
   * **假设输入（C++）:** `RTCDataChannel::Observer::OnMessage()` 接收到包含 "Reply" 的 `webrtc::DataBuffer`。
   * **输出（C++）:** `RTCDataChannel::OnMessage()` 将 "Reply" 转换为 JavaScript 字符串，并触发 `message` 事件。
   * **输出（JavaScript）:** `dataChannel.onmessage` 回调函数被执行，`event.data` 为 "Reply"。

**用户或编程常见的使用错误举例说明：**

1. **在数据通道未打开时发送数据：**
   * **用户操作/编程错误：** 在 `dataChannel.readyState` 不是 "open" 的情况下调用 `dataChannel.send()`。
   * **`rtc_data_channel.cc` 中的处理：** `RTCDataChannel::send()` 方法会检查 `state_`，如果不是 `webrtc::DataChannelInterface::kOpen`，会调用 `ThrowNotOpenException()` 抛出一个 `InvalidStateError` 异常。
   * **假设输入（JavaScript）：**
     ```javascript
     let pc = new RTCPeerConnection();
     let dataChannel = pc.createDataChannel('myLabel');
     dataChannel.send('This will likely fail'); // 发送时通道可能还处于 'connecting' 状态
     ```
   * **输出（JavaScript）：**  JavaScript 代码会捕获到一个 `DOMException`，错误信息为 "RTCDataChannel.readyState is not 'open'"。

2. **发送超过缓冲区限制的数据：**
   * **用户操作/编程错误：**  尝试发送的数据量加上当前缓冲区大小超过了 WebRTC 允许的最大发送队列大小 (`webrtc::DataChannelInterface::MaxSendQueueSize()`)。
   * **`rtc_data_channel.cc` 中的处理：** `RTCDataChannel::ValidateSendLength()` 方法会进行检查，如果超过限制，会调用 `ThrowSendBufferFullException()` 抛出一个 `OperationError` 异常。
   * **假设输入（JavaScript）：**
     ```javascript
     let pc = new RTCPeerConnection();
     let dataChannel = pc.createDataChannel('myLabel');
     dataChannel.onopen = function() {
       let largeData = new Array(10 * 1024 * 1024).join('a'); // 创建一个很大的字符串
       try {
         dataChannel.send(largeData);
       } catch (e) {
         console.error(e); // 可能会捕获到 OperationError
       }
     };
     ```
   * **输出（JavaScript）：**  JavaScript 代码可能会捕获到一个 `DOMException`，错误信息为 "RTCDataChannel send queue is full"。

3. **忘记处理异步的 Blob 读取：**
   * **用户操作/编程错误：**  在发送 Blob 数据时，没有意识到 Blob 的读取是异步的，导致可能在读取完成前就尝试发送。实际上，`rtc_data_channel.cc` 内部处理了 Blob 的异步读取。
   * **`rtc_data_channel.cc` 中的处理：**  当 `send(Blob)` 被调用时，`RTCDataChannel` 会创建一个 `BlobReader` 来异步读取 Blob 的内容，并在读取完成后再发送数据。
   * **假设输入（JavaScript）：**
     ```javascript
     let pc = new RTCPeerConnection();
     let dataChannel = pc.createDataChannel('myLabel');
     dataChannel.onopen = function() {
       let blob = new Blob(['Some data'], { type: 'text/plain' });
       dataChannel.send(blob); // Blob 的读取是异步的，但 C++ 代码会处理
     };
     ```
   * **输出（预期行为）：**  虽然 JavaScript 代码看起来是同步发送，但 `rtc_data_channel.cc` 会异步读取 Blob，然后在读取完成后才将数据发送到网络。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

要调试 `rtc_data_channel.cc` 中的代码，通常需要从用户的操作开始追踪：

1. **用户打开一个包含 WebRTC 功能的网页：**  例如，一个视频会议网站或文件传输应用。
2. **用户触发创建 `RTCPeerConnection` 的操作：** 例如，点击 "开始通话" 按钮。
3. **JavaScript 代码调用 `RTCPeerConnection.createDataChannel()`：**  这会在 Blink 渲染进程中创建 `RTCDataChannel` 对象，对应的 C++ 代码被执行。
4. **JavaScript 代码监听 `RTCDataChannel` 的事件：**  例如，监听 `open` 和 `message` 事件。
5. **用户或远程对等端尝试通过数据通道发送数据：**
   * **发送数据：** 用户在输入框中输入消息并点击发送，JavaScript 调用 `dataChannel.send()`。调试时可以在 `RTCDataChannel::send()` 方法中设置断点。
   * **接收数据：** 远程对等端发送数据，底层的 WebRTC 接收到数据后会通知到 `RTCDataChannel::Observer::OnMessage()`。可以在这个方法中设置断点。
6. **数据通道的状态发生变化：** 例如，连接建立成功或连接断开。可以在 `RTCDataChannel::OnStateChange()` 中设置断点来观察状态变化。
7. **出现错误：** 例如，网络问题导致数据通道关闭。可以在 `RTCDataChannel::OnStateChange()` 中 `state_ == webrtc::DataChannelInterface::kClosed` 的分支中查看错误信息。

**调试线索：**

* **Chrome 的 `chrome://webrtc-internals` 页面：**  这是一个非常有用的工具，可以查看 WebRTC 的内部状态，包括 `RTCDataChannel` 的信息，例如连接状态、发送和接收的统计数据、错误信息等。
* **在 `rtc_data_channel.cc` 中设置断点：**  使用调试器 (例如，Visual Studio 或 gdb) 可以单步执行 C++ 代码，查看变量的值，理解代码的执行流程。
* **使用 `DVLOG` 进行详细日志输出：**  Blink 中使用了 `DVLOG` 进行详细的日志记录。可以通过设置 Chrome 的 `--vmodule` 和 `--enable-logging` 命令行参数来启用这些日志，查看 `rtc_data_channel.cc` 中的详细信息。
* **检查 JavaScript 控制台的错误信息：**  如果 `rtc_data_channel.cc` 中抛出了异常，这些异常通常会在 JavaScript 控制台中显示。
* **分析网络请求：**  虽然 `rtc_data_channel.cc` 本身不直接处理网络请求，但可以通过抓包工具 (例如，Wireshark) 来分析 WebRTC 的底层数据传输，以排除网络问题。

总而言之，`blink/renderer/modules/peerconnection/rtc_data_channel.cc` 是 WebRTC 数据通道功能在 Blink 渲染引擎中的核心实现，负责将 JavaScript 的 `RTCDataChannel` API 映射到底层的 WebRTC 本地实现，并处理数据的发送、接收、状态管理和错误处理。 理解这个文件的功能对于深入理解 WebRTC 的工作原理至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_data_channel.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"

#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "base/containers/span.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "components/webrtc/thread_wrapper.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_priority_type.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_client.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/web_rtc_cross_thread_copier.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_error_event.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/webrtc/api/priority.h"

namespace WTF {

template <>
struct CrossThreadCopier<rtc::scoped_refptr<webrtc::DataChannelInterface>>
    : public CrossThreadCopierPassThrough<
          rtc::scoped_refptr<webrtc::DataChannelInterface>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DataChannelCounters {
  kCreated = 0,
  kOpened = 1,
  kReliable = 2,
  kOrdered = 3,
  kNegotiated = 4,
  kMaxValue = kNegotiated,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DataChannelAggregateType {
  kUnReliableUnordered = 0,
  kUnReliableOrdered = 1,
  kReliableUnordered = 2,
  kReliableOrdered = 3,
  kMaxValue = kReliableOrdered,
};

void IncrementCounter(DataChannelCounters counter) {
  base::UmaHistogramEnumeration("WebRTC.DataChannelCounters", counter);
}

void IncrementCounters(const webrtc::DataChannelInterface& channel) {
  int aggregate_type = 0;

  IncrementCounter(DataChannelCounters::kCreated);
  if (channel.reliable()) {
    IncrementCounter(DataChannelCounters::kReliable);
    aggregate_type += 2;
  }
  if (channel.ordered()) {
    IncrementCounter(DataChannelCounters::kOrdered);
    aggregate_type += 1;
  }
  if (channel.negotiated())
    IncrementCounter(DataChannelCounters::kNegotiated);

  base::UmaHistogramEnumeration(
      "WebRTC.DataChannelAggregateType",
      static_cast<DataChannelAggregateType>(aggregate_type));

  // Only record max retransmits and max packet life time if set.
  if (channel.maxRetransmitsOpt()) {
    base::UmaHistogramCustomCounts("WebRTC.DataChannelMaxRetransmits",
                                   *(channel.maxRetransmitsOpt()), 1,
                                   std::numeric_limits<uint16_t>::max(), 50);
  }
  if (channel.maxPacketLifeTime()) {
    base::UmaHistogramCustomCounts("WebRTC.DataChannelMaxPacketLifeTime",
                                   *channel.maxPacketLifeTime(), 1,
                                   std::numeric_limits<uint16_t>::max(), 50);
  }
}

void RecordMessageSent(const webrtc::DataChannelInterface& channel,
                       size_t num_bytes) {
  // Currently, messages are capped at some fairly low limit (16 Kb?)
  // but we may allow unlimited-size messages at some point, so making
  // the histogram maximum quite large (100 Mb) to have some
  // granularity at the higher end in that eventuality. The histogram
  // buckets are exponentially growing in size, so we'll still have
  // good granularity at the low end.

  // This makes the last bucket in the histogram count messages from
  // 100 Mb to infinity.
  const int kMaxBucketSize = 100 * 1024 * 1024;
  const int kNumBuckets = 50;

  if (channel.reliable()) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("WebRTC.ReliableDataChannelMessageSize",
                                base::checked_cast<int>(num_bytes), 1,
                                kMaxBucketSize, kNumBuckets);
  } else {
    UMA_HISTOGRAM_CUSTOM_COUNTS("WebRTC.UnreliableDataChannelMessageSize",
                                base::checked_cast<int>(num_bytes), 1,
                                kMaxBucketSize, kNumBuckets);
  }
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DataChannelSctpErrorCode {
  kUnspecified = 0,
  kInvalidStreamIdentifier = 1,
  kMissingMandatoryParameter = 2,
  kStaleCookieError = 3,
  kOutOfResource = 4,
  kUnresolvableAddress = 5,
  kUnrecognizedChunkType = 6,
  kInvalidMandatoryParameter = 7,
  kUnrecognizedParameters = 8,
  kNoUserData = 9,
  kCookieReceivedWhileShuttingDown = 10,
  kRestartWithNewAddresses = 11,
  kUserInitiatedAbort = 12,
  kProtocolViolation = 13,
  kOther = 14,
  kMaxValue = kOther,
};

void IncrementErrorCounter(const webrtc::RTCError& error) {
  DataChannelSctpErrorCode uma_code;
  auto code = error.sctp_cause_code();
  if (!code.has_value()) {
    uma_code = DataChannelSctpErrorCode::kUnspecified;
  } else if (*code >= static_cast<int>(DataChannelSctpErrorCode::kOther)) {
    uma_code = DataChannelSctpErrorCode::kOther;
  } else {
    uma_code = static_cast<DataChannelSctpErrorCode>(*code);
  }
  base::UmaHistogramEnumeration("WebRTC.DataChannelSctpErrorCode", uma_code);
}

}  // namespace

static void ThrowNotOpenException(ExceptionState* exception_state) {
  exception_state->ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                     "RTCDataChannel.readyState is not 'open'");
}

static void ThrowSendBufferFullException(ExceptionState* exception_state) {
  exception_state->ThrowDOMException(DOMExceptionCode::kOperationError,
                                     "RTCDataChannel send queue is full");
}

RTCDataChannel::Observer::Observer(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread,
    RTCDataChannel* blink_channel,
    rtc::scoped_refptr<webrtc::DataChannelInterface> channel)
    : main_thread_(main_thread),
      blink_channel_(blink_channel),
      webrtc_channel_(std::move(channel)) {
  CHECK(webrtc_channel_.get());
}

RTCDataChannel::Observer::~Observer() {
  CHECK(!is_registered()) << "Reference to blink channel hasn't been released.";
}

const rtc::scoped_refptr<webrtc::DataChannelInterface>&
RTCDataChannel::Observer::channel() const {
  return webrtc_channel_;
}

bool RTCDataChannel::Observer::is_registered() const {
  DCHECK(main_thread_->BelongsToCurrentThread());
  return blink_channel_ != nullptr;
}

void RTCDataChannel::Observer::Unregister() {
  DCHECK(main_thread_->BelongsToCurrentThread());
  webrtc_channel_->UnregisterObserver();
  blink_channel_ = nullptr;
}

void RTCDataChannel::Observer::OnStateChange() {
  PostCrossThreadTask(
      *main_thread_, FROM_HERE,
      CrossThreadBindOnce(&RTCDataChannel::Observer::OnStateChangeImpl,
                          scoped_refptr<Observer>(this),
                          webrtc_channel_->state()));
}

void RTCDataChannel::Observer::OnBufferedAmountChange(uint64_t sent_data_size) {
  PostCrossThreadTask(
      *main_thread_, FROM_HERE,
      CrossThreadBindOnce(&RTCDataChannel::Observer::OnBufferedAmountChangeImpl,
                          scoped_refptr<Observer>(this),
                          base::checked_cast<unsigned>(sent_data_size)));
}

void RTCDataChannel::Observer::OnMessage(const webrtc::DataBuffer& buffer) {
  PostCrossThreadTask(
      *main_thread_, FROM_HERE,
      CrossThreadBindOnce(&RTCDataChannel::Observer::OnMessageImpl,
                          scoped_refptr<Observer>(this), buffer));
}

bool RTCDataChannel::Observer::IsOkToCallOnTheNetworkThread() {
  return true;
}

void RTCDataChannel::Observer::OnStateChangeImpl(
    webrtc::DataChannelInterface::DataState state) {
  DCHECK(main_thread_->BelongsToCurrentThread());
  if (blink_channel_)
    blink_channel_->OnStateChange(state);
}

void RTCDataChannel::Observer::OnBufferedAmountChangeImpl(
    unsigned sent_data_size) {
  DCHECK(main_thread_->BelongsToCurrentThread());
  if (blink_channel_)
    blink_channel_->OnBufferedAmountChange(sent_data_size);
}

void RTCDataChannel::Observer::OnMessageImpl(webrtc::DataBuffer buffer) {
  DCHECK(main_thread_->BelongsToCurrentThread());
  if (blink_channel_)
    blink_channel_->OnMessage(std::move(buffer));
}

// static
void RTCDataChannel::EnsureThreadWrappersForWorkerThread() {
  webrtc::ThreadWrapper::EnsureForCurrentMessageLoop();
  webrtc::ThreadWrapper::current()->set_send_allowed(true);
}

RTCDataChannel::RTCDataChannel(
    ExecutionContext* context,
    rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel)
    : ActiveScriptWrappable<RTCDataChannel>({}),
      ExecutionContextLifecycleObserver(context),
      observer_(base::MakeRefCounted<Observer>(
          context->GetTaskRunner(TaskType::kNetworking),
          this,
          std::move(data_channel))) {
  if (RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled()) {
    // Delay connecting to the observer to give a chance for this RTCDataChannel
    // to be transferred. See:
    // https://w3c.github.io/webrtc-extensions/#rtcdatachannel-transferable
    context->GetTaskRunner(TaskType::kNetworking)
        ->PostTask(FROM_HERE, WTF::BindOnce(&RTCDataChannel::RegisterObserver,
                                            WrapWeakPersistent(this)));
  } else {
    RegisterObserver();
  }

  IncrementCounters(*channel().get());
}

RTCDataChannel::~RTCDataChannel() {
  // `Dispose()` must have been called to clear up webrtc references.
  CHECK(!observer_->is_registered());
}

void RTCDataChannel::RegisterObserver() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_transferable_ = false;

  // Do not connect if `this` was transferred, as it should be going away soon.
  if (was_transferred_) {
    return;
  }

  // The context might have been destroyed already if registration was delayed.
  if (stopped_) {
    return;
  }

  channel()->RegisterObserver(observer_.get());
  if (channel()->state() != state_) {
    observer_->OnStateChange();
  }
}

String RTCDataChannel::label() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return String::FromUTF8(channel()->label());
}

bool RTCDataChannel::reliable() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return channel()->reliable();
}

bool RTCDataChannel::ordered() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return channel()->ordered();
}

std::optional<uint16_t> RTCDataChannel::maxPacketLifeTime() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (channel()->maxPacketLifeTime())
    return *channel()->maxPacketLifeTime();
  return std::nullopt;
}

std::optional<uint16_t> RTCDataChannel::maxRetransmits() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (channel()->maxRetransmitsOpt())
    return *channel()->maxRetransmitsOpt();
  return std::nullopt;
}

String RTCDataChannel::protocol() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return String::FromUTF8(channel()->protocol());
}

bool RTCDataChannel::negotiated() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return channel()->negotiated();
}

std::optional<uint16_t> RTCDataChannel::id() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (id_.has_value()) {
    return id_;
  }

  int id = channel()->id();
  if (id == -1) {
    return std::nullopt;
  }

  DCHECK(id >= 0 && id <= std::numeric_limits<uint16_t>::max());
  id_ = static_cast<uint16_t>(id);

  return id;
}

V8RTCPriorityType RTCDataChannel::priority() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  webrtc::PriorityValue priority = channel()->priority();
  if (priority <= webrtc::PriorityValue(webrtc::Priority::kVeryLow)) {
    return V8RTCPriorityType(V8RTCPriorityType::Enum::kVeryLow);
  }
  if (priority <= webrtc::PriorityValue(webrtc::Priority::kLow)) {
    return V8RTCPriorityType(V8RTCPriorityType::Enum::kLow);
  }
  if (priority <= webrtc::PriorityValue(webrtc::Priority::kMedium)) {
    return V8RTCPriorityType(V8RTCPriorityType::Enum::kMedium);
  }
  return V8RTCPriorityType(V8RTCPriorityType::Enum::kHigh);
}

V8RTCDataChannelState RTCDataChannel::readyState() const {
  switch (state_) {
    case webrtc::DataChannelInterface::kConnecting:
      return V8RTCDataChannelState(V8RTCDataChannelState::Enum::kConnecting);
    case webrtc::DataChannelInterface::kOpen:
      return V8RTCDataChannelState(V8RTCDataChannelState::Enum::kOpen);
    case webrtc::DataChannelInterface::kClosing:
      return V8RTCDataChannelState(V8RTCDataChannelState::Enum::kClosing);
    case webrtc::DataChannelInterface::kClosed:
      return V8RTCDataChannelState(V8RTCDataChannelState::Enum::kClosed);
  }

  NOTREACHED();
}

unsigned RTCDataChannel::bufferedAmount() const {
  return buffered_amount_;
}

unsigned RTCDataChannel::bufferedAmountLowThreshold() const {
  return buffered_amount_low_threshold_;
}

void RTCDataChannel::setBufferedAmountLowThreshold(unsigned threshold) {
  buffered_amount_low_threshold_ = threshold;
}

V8BinaryType RTCDataChannel::binaryType() const {
  return V8BinaryType(binary_type_);
}

void RTCDataChannel::setBinaryType(const V8BinaryType& binary_type) {
  binary_type_ = binary_type.AsEnum();
}

bool RTCDataChannel::ValidateSendLength(uint64_t length,
                                        ExceptionState& exception_state) {
  // Send algorithm: https://w3c.github.io/webrtc-pc/#datachannel-send

  // TODO(orphis): Throw TypeError if length > transport.maxMessageSize

  auto updated_buffered_amount =
      base::CheckedNumeric<unsigned>(buffered_amount_) + length;
  if (!updated_buffered_amount.IsValid() ||
      updated_buffered_amount.ValueOrDie() >
          webrtc::DataChannelInterface::MaxSendQueueSize()) {
    ThrowSendBufferFullException(&exception_state);
    return false;
  }

  return true;
}

void RTCDataChannel::send(const String& data, ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_transferable_ = false;

  if (state_ != webrtc::DataChannelInterface::kOpen) {
    ThrowNotOpenException(&exception_state);
    return;
  }

  webrtc::DataBuffer data_buffer(data.Utf8());

  if (!ValidateSendLength(data_buffer.size(), exception_state))
    return;

  buffered_amount_ += data_buffer.size();
  RecordMessageSent(*channel().get(), data_buffer.size());
  SendDataBuffer(std::move(data_buffer));
}

void RTCDataChannel::send(DOMArrayBuffer* data,
                          ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_transferable_ = false;

  if (state_ != webrtc::DataChannelInterface::kOpen) {
    ThrowNotOpenException(&exception_state);
    return;
  }

  size_t data_length = data->ByteLength();

  if (!ValidateSendLength(data_length, exception_state))
    return;

  buffered_amount_ += data_length;
  SendRawData(static_cast<const char*>((data->Data())), data_length);
}

void RTCDataChannel::send(NotShared<DOMArrayBufferView> data,
                          ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_transferable_ = false;

  if (state_ != webrtc::DataChannelInterface::kOpen) {
    ThrowNotOpenException(&exception_state);
    return;
  }

  if (!ValidateSendLength(data->byteLength(), exception_state))
    return;

  buffered_amount_ += data->byteLength();
  SendRawData(static_cast<const char*>(data->BaseAddress()),
              data->byteLength());
}

void RTCDataChannel::send(Blob* data, ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  is_transferable_ = false;

  if (state_ != webrtc::DataChannelInterface::kOpen) {
    ThrowNotOpenException(&exception_state);
    return;
  }

  if (!ValidateSendLength(data->size(), exception_state)) {
    return;
  }

  buffered_amount_ += data->size();

  PendingMessage* message = MakeGarbageCollected<PendingMessage>();
  message->type_ = PendingMessage::Type::kBufferPending;
  message->blob_reader_ =
      BlobReader::Create(GetExecutionContext(), this, message);
  message->blob_reader_->Start(data);
  pending_messages_.push_back(message);
}

void RTCDataChannel::close() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ == webrtc::DataChannelInterface::kClosing ||
      state_ == webrtc::DataChannelInterface::kClosed) {
    return;
  }
  closed_from_owner_ = true;
  OnStateChange(webrtc::DataChannelInterface::kClosing);

  if (pending_messages_.empty()) {
    channel()->Close();
  } else {
    PendingMessage* message = MakeGarbageCollected<PendingMessage>();
    message->type_ = PendingMessage::Type::kCloseEvent;
    pending_messages_.push_back(message);
  }
}

bool RTCDataChannel::IsTransferable() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled() &&
         is_transferable_;
}

rtc::scoped_refptr<webrtc::DataChannelInterface>
RTCDataChannel::TransferUnderlyingChannel() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!IsTransferable()) {
    return nullptr;
  }

  // Only allow a single transfer.
  was_transferred_ = true;
  is_transferable_ = false;

  // Bypass OnStateChange() to avoid emitting an event.
  state_ = webrtc::DataChannelInterface::kClosed;
  feature_handle_for_scheduler_.reset();

  return channel();
}

const AtomicString& RTCDataChannel::InterfaceName() const {
  return event_target_names::kRTCDataChannel;
}

ExecutionContext* RTCDataChannel::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void RTCDataChannel::ContextDestroyed() {
  Dispose();
  stopped_ = true;
  state_ = webrtc::DataChannelInterface::kClosed;
  feature_handle_for_scheduler_.reset();
}

// ActiveScriptWrappable
bool RTCDataChannel::HasPendingActivity() const {
  if (stopped_)
    return false;

  // A RTCDataChannel object must not be garbage collected if its
  // * readyState is connecting and at least one event listener is registered
  //   for open events, message events, error events, closing events
  //   or close events.
  // * readyState is open and at least one event listener is registered for
  //   message events, error events, closing events, or close events.
  // * readyState is closing and at least one event listener is registered for
  //   error events, or close events.
  // * underlying data transport is established and data is queued to be
  //   transmitted.
  bool has_valid_listeners = false;
  switch (state_) {
    case webrtc::DataChannelInterface::kConnecting:
      has_valid_listeners |= HasEventListeners(event_type_names::kOpen);
      [[fallthrough]];
    case webrtc::DataChannelInterface::kOpen:
      has_valid_listeners |= HasEventListeners(event_type_names::kMessage) ||
                             HasEventListeners(event_type_names::kClosing);
      [[fallthrough]];
    case webrtc::DataChannelInterface::kClosing:
      has_valid_listeners |= HasEventListeners(event_type_names::kError) ||
                             HasEventListeners(event_type_names::kClose);
      break;
    default:
      break;
  }

  if (has_valid_listeners)
    return true;

  return state_ != webrtc::DataChannelInterface::kClosed &&
         bufferedAmount() > 0;
}

void RTCDataChannel::Trace(Visitor* visitor) const {
  visitor->Trace(pending_messages_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void RTCDataChannel::SetStateToOpenWithoutEvent() {
  DCHECK_NE(state_, webrtc::DataChannelInterface::kOpen);
  IncrementCounter(DataChannelCounters::kOpened);
  state_ = webrtc::DataChannelInterface::kOpen;
  CreateFeatureHandleForScheduler();
}

void RTCDataChannel::DispatchOpenEvent() {
  DispatchEvent(*Event::Create(event_type_names::kOpen));
}

void RTCDataChannel::OnStateChange(
    webrtc::DataChannelInterface::DataState state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (state_ == webrtc::DataChannelInterface::kClosed)
    return;

  if (state_ == webrtc::DataChannelInterface::kClosing &&
      state != webrtc::DataChannelInterface::kClosed) {
    return;
  }

  if (state == state_) {
    return;
  }

  state_ = state;

  switch (state_) {
    case webrtc::DataChannelInterface::kOpen:
      IncrementCounter(DataChannelCounters::kOpened);
      CreateFeatureHandleForScheduler();
      DispatchEvent(*Event::Create(event_type_names::kOpen));
      break;
    case webrtc::DataChannelInterface::kClosing:
      if (!closed_from_owner_) {
        DispatchEvent(*Event::Create(event_type_names::kClosing));
      }
      break;
    case webrtc::DataChannelInterface::kClosed: {
      feature_handle_for_scheduler_.reset();
      auto error = channel()->error();
      if (!error.ok()) {
        LOG(ERROR) << "DataChannel error: \"" << error.message() << "\""
                   << ", code: " << error.sctp_cause_code().value_or(-1);

        if (error.error_detail() == webrtc::RTCErrorDetailType::NONE) {
          error.set_error_detail(
              webrtc::RTCErrorDetailType::DATA_CHANNEL_FAILURE);
        }

        IncrementErrorCounter(error);
        DispatchEvent(*MakeGarbageCollected<RTCErrorEvent>(
            event_type_names::kError, error));
      }
      DispatchEvent(*Event::Create(event_type_names::kClose));
      break;
    }
    default:
      break;
  }
}

void RTCDataChannel::OnBufferedAmountChange(unsigned sent_data_size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  unsigned previous_amount = buffered_amount_;
  DVLOG(1) << "OnBufferedAmountChange " << previous_amount;
  DCHECK_GE(buffered_amount_, sent_data_size);
  buffered_amount_ -= sent_data_size;

  if (previous_amount > buffered_amount_low_threshold_ &&
      buffered_amount_ <= buffered_amount_low_threshold_) {
    DispatchEvent(*Event::Create(event_type_names::kBufferedamountlow));
  }
}

void RTCDataChannel::OnMessage(webrtc::DataBuffer buffer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (buffer.binary) {
    switch (binary_type_) {
      case V8BinaryType::Enum::kBlob: {
        auto blob_data = std::make_unique<BlobData>();
        blob_data->AppendBytes(base::make_span(buffer.data));
        uint64_t blob_size = blob_data->length();
        auto* blob = MakeGarbageCollected<Blob>(
            BlobDataHandle::Create(std::move(blob_data), blob_size));
        DispatchEvent(*MessageEvent::Create(blob));
        return;
      }
      case V8BinaryType::Enum::kArraybuffer: {
        DOMArrayBuffer* dom_buffer = DOMArrayBuffer::Create(buffer.data);
        DispatchEvent(*MessageEvent::Create(dom_buffer));
        return;
      }
    }
    NOTREACHED();
  } else {
    String text =
        buffer.data.size() > 0 ? String::FromUTF8(buffer.data) : g_empty_string;
    if (!text) {
      LOG(ERROR) << "Failed convert received data to UTF16";
      return;
    }
    DispatchEvent(*MessageEvent::Create(text));
  }
}

void RTCDataChannel::Dispose() {
  if (stopped_)
    return;

  // If `this` was transferred, DelayObserverRegistration() should have never
  // registered `observer_`.
  if (!was_transferred_) {
    // Clear the weak persistent reference to this on-heap object.
    observer_->Unregister();
  }
}

const rtc::scoped_refptr<webrtc::DataChannelInterface>&
RTCDataChannel::channel() const {
  return observer_->channel();
}

void RTCDataChannel::SendRawData(const char* data, size_t length) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!was_transferred_);
  rtc::CopyOnWriteBuffer buffer(data, length);
  webrtc::DataBuffer data_buffer(buffer, true);
  RecordMessageSent(*channel().get(), data_buffer.size());

  if (pending_messages_.empty()) {
    SendDataBuffer(std::move(data_buffer));
  } else {
    PendingMessage* message = MakeGarbageCollected<PendingMessage>();
    message->type_ = PendingMessage::Type::kBufferReady;
    message->buffer_ = std::move(data_buffer);
    pending_messages_.push_back(message);
  }
}

void RTCDataChannel::SendDataBuffer(webrtc::DataBuffer data_buffer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!was_transferred_);

  // SCTP data channels queue the packet on failure and always return true, so
  // Send can be called asynchronously for them.
  channel()->SendAsync(std::move(data_buffer), [](webrtc::RTCError error) {
    // TODO(orphis): Use this callback in combination with SendAsync to report
    // completion of the send API to the JS layer.
    // The possible failures per the spec are:
    // - Channel not in open state. Although we check the state in each Send()
    // implementation, it's possible to have a short race between the WebRTC
    // state and the Chrome state, i.e. sending while a remote close event is
    // pending. In this case, it's safe to ignore send failures.
    // - Data longer than the transport maxMessageSize (not yet implemented in
    // WebRTC or Blink).
    // - Send Buffers full (buffered amount accounting in Blink layer to check
    // for it).
    if (!error.ok()) {
      // TODO(orphis): Add collect UMA stats about failure.
      // Note that when we get this callback, we're on WebRTC's network thread
      // So the callback needs to be propagated to the main (JS) thread.
      LOG(ERROR) << "Send failed" << webrtc::ToString(error.type());
    }
  });
}

void RTCDataChannel::CreateFeatureHandleForScheduler() {
  DCHECK(!feature_handle_for_scheduler_);
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  // Ideally we'd use To<LocalDOMWindow>, but in unittests the ExecutionContext
  // may not be a LocalDOMWindow.
  if (!window)
    return;
  // This can happen for detached frames.
  if (!window->GetFrame())
    return;
  feature_handle_for_scheduler_ =
      window->GetFrame()->GetFrameScheduler()->RegisterFeature(
          SchedulingPolicy::Feature::kWebRTC,
          {SchedulingPolicy::DisableAggressiveThrottling(),
           SchedulingPolicy::DisableAlignWakeUps()});
}

void RTCDataChannel::ProcessSendQueue() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool stop_processing = false;
  while (!pending_messages_.empty() && !stop_processing) {
    auto& message = pending_messages_.front();
    switch (message->type_) {
      case PendingMessage::Type::kBufferReady:
        SendDataBuffer(std::move(*message->buffer_));
        pending_messages_.pop_front();
        break;
      case PendingMessage::Type::kBufferPending:
        if (message->blob_reader_->HasFinishedLoading()) {
          SendDataBuffer(std::move(*message->buffer_));
          pending_messages_.pop_front();
        } else {
          stop_processing = true;
        }
        break;
      case PendingMessage::Type::kCloseEvent:
        channel()->Close();
        pending_messages_.pop_front();
        break;
      case PendingMessage::Type::kBlobFailure:
        pending_messages_.pop_front();
        break;
    }
  }
}

void RTCDataChannel::PendingMessage::Trace(Visitor* visitor) const {
  visitor->Trace(blob_reader_);
}

void RTCDataChannel::BlobReader::DidFinishLoading(FileReaderData data) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DOMArrayBuffer* array_buffer = std::move(data).AsDOMArrayBuffer();
  rtc::CopyOnWriteBuffer buffer(
      static_cast<const char*>((array_buffer->Data())),
      array_buffer->ByteLength());
  message_->buffer_ = webrtc::DataBuffer(buffer, true);
  message_->type_ = RTCDataChannel::PendingMessage::Type::kBufferReady;
  data_channel_->ProcessSendQueue();
  Dispose();
}

void RTCDataChannel::BlobReader::DidFail(FileErrorCode error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kError,
      "Couldn't read Blob content, skipping message."));
  message_->type_ = RTCDataChannel::PendingMessage::Type::kBlobFailure;
  data_channel_->ProcessSendQueue();
  Dispose();
}

RTCDataChannel::BlobReader::BlobReader(ExecutionContext* context,
                                       RTCDataChannel* data_channel,
                                       PendingMessage* message)
    : ExecutionContextLifecycleObserver(context),
      loader_(MakeGarbageCollected<FileReaderLoader>(
          this,
          GetExecutionContext()->GetTaskRunner(TaskType::kFileReading))),
      data_channel_(data_channel),
      message_(message),
      keep_alive_(this) {}

RTCDataChannel::BlobReader::~BlobReader() = default;

void RTCDataChannel::BlobReader::Start(Blob* blob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  loader_->Start(blob->GetBlobDataHandle());
}

void RTCDataChannel::BlobReader::Trace(Visitor* visitor) const {
  ExecutionContextLifecycleObserver::Trace(visitor);
  FileReaderAccumulator::Trace(visitor);
  visitor->Trace(loader_);
  visitor->Trace(data_channel_);
  visitor->Trace(message_);
}

bool RTCDataChannel::BlobReader::HasFinishedLoading() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return loader_->HasFinishedLoading();
}

void RTCDataChannel::BlobReader::ContextDestroyed() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  loader_->Cancel();
  Dispose();
}

void RTCDataChannel::BlobReader::Dispose() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  keep_alive_.Clear();
}

}  // namespace blink

"""

```