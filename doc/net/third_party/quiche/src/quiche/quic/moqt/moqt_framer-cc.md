Response:
The user wants to understand the functionality of the `moqt_framer.cc` file in Chromium's network stack. I need to explain its purpose, identify any connections to JavaScript, illustrate its logic with input/output examples, point out common usage errors, and describe how a user's action might lead to this code being executed.

Here's a breakdown of the steps:

1. **Core Functionality:**  The file is responsible for serializing MoQT (Media over QUIC Transport) messages into byte streams for network transmission. This involves taking structured data and converting it into a binary format that can be sent over the wire.

2. **JavaScript Relationship:** MoQT is a transport protocol. While JavaScript itself doesn't directly implement this low-level serialization, JavaScript code running in a web browser (or Node.js environment) might interact with a web server using MoQT. This interaction would be through higher-level APIs (like the Fetch API for making requests or a custom media streaming API). The browser's underlying network stack, written in C++, would handle the actual MoQT framing using this code.

3. **Logic and Examples:**  I'll pick a few representative serialization functions (e.g., `SerializeSubscribe`, `SerializeObjectHeader`) and show how the input `MoqtSubscribe` or `MoqtObject` structure is transformed into a byte sequence. I'll need to invent some example data for the input and predict the output based on the serialization logic. This requires understanding the structure of the `Wire...` classes used for serialization.

4. **Common Errors:**  The code includes several `QUIC_BUG` calls for invalid states. These represent potential programming errors or misuse of the MoQT API. I'll list some scenarios that would trigger these bugs, like providing inconsistent data in the `MoqtObject` or `MoqtSubscribe` structures.

5. **User Journey:** I need to trace a typical user interaction that would involve MoQT. A prime example is a user watching a live video stream in a web browser. I'll outline the steps: user clicks play, browser requests the stream, server responds with MoQT messages, and this file comes into play when serializing those messages.

**Pre-computation/Analysis:**

* **Message Types:**  I need to identify the various MoQT message types this framer handles (e.g., `ClientSetup`, `Subscribe`, `ObjectHeader`).
* **Serialization Logic:** I'll examine how each message type is serialized, paying attention to the `Wire...` classes and the order of fields.
* **Error Conditions:** I'll focus on the `QUIC_BUG` calls to understand common error scenarios.
* **JavaScript Interaction Point:**  The connection is indirect via browser APIs and the underlying network stack.

**Drafting the Response:**

I'll structure the response with clear headings for each of the user's requests. For the JavaScript section, I'll emphasize the indirect relationship. For the examples, I'll use code-like representations of the input and output. For the user journey, I'll provide a step-by-step description.

**Self-Correction:**

Initially, I might be tempted to explain the intricacies of the `Wire...` classes in detail. However, for the user's request, a high-level understanding of their purpose (serializing data) is sufficient. I need to avoid getting bogged down in implementation details and focus on the overall functionality and user-facing implications. Also, clearly stating the assumptions made in the input/output examples is important. Making the JavaScript explanation clear and not overstating the direct connection is crucial.
这个文件 `net/third_party/quiche/src/quiche/quic/moqt/moqt_framer.cc` 是 Chromium 网络栈中 QUIC 协议的 MoQT (Media over QUIC Transport)  部分的一个关键组件，主要负责 **MoQT 消息的序列化**。 它的功能是将程序内部表示的 MoQT 消息结构体（例如 `MoqtSubscribe`, `MoqtObject`, `MoqtAnnounce` 等）转换成可以在网络上传输的字节流。反向的操作（将接收到的字节流解析成消息结构体）通常由 `moqt_parser.cc` 文件负责。

下面详细列举一下它的功能：

**主要功能:**

1. **消息序列化:**  这是该文件最核心的功能。 它包含了许多 `Serialize...` 函数，每个函数对应一种 MoQT 消息类型。 这些函数接收一个 MoQT 消息结构体作为输入，并将其各个字段按照 MoQT 协议规范编码成字节流。

    * **控制消息序列化:**  例如 `SerializeClientSetup`, `SerializeSubscribe`, `SerializeAnnounce`, `SerializeGoAway` 等。 这些消息用于协商连接参数、订阅内容、发布内容等控制操作。
    * **数据消息序列化:**  例如 `SerializeObjectHeader`, `SerializeObjectDatagram`。 这些消息用于传输实际的媒体数据。

2. **支持不同的数据类型编码:**  文件中使用了 `quiche::ComputeLengthOnWire` 和 `quiche::SerializeIntoWriter` 等工具函数，配合 `WireVarInt62`, `WireStringWithVarInt62Length` 等“Wire”类型，来处理不同类型的字段，例如变长整数 (VarInt)，带长度前缀的字符串等，确保数据能正确地按照 MoQT 规范进行编码。

3. **处理可选字段:**  MoQT 消息中可能包含可选字段。 该文件中的序列化函数会检查这些字段是否存在，并根据情况选择性地将其编码到字节流中。例如，`MoqtSubscribe` 消息中的 `start_group` 和 `start_object` 字段只有在指定了起始位置时才会被编码。

4. **处理枚举类型:**  例如 `MoqtDeliveryOrder`，会被转换成对应的整数值进行编码。

5. **参数列表序列化:**  很多 MoQT 消息都包含参数列表，例如 `MoqtSubscribeParameters`。 文件中定义了 `WireStringParameterList` 和 `WireIntParameterList` 等辅助类来方便地序列化这些参数。

6. **错误检测 (有限):**  在序列化过程中，该文件进行了一些基本的错误检测，例如检查对象元数据是否有效 (`ValidateObjectMetadata`)。 如果检测到错误，会调用 `QUIC_BUG` 宏来记录错误并可能终止程序执行。 这主要是为了在开发和调试阶段尽早发现问题。

**与 JavaScript 的关系 (间接):**

`moqt_framer.cc` 是用 C++ 编写的，属于浏览器或服务器的底层网络栈实现，**JavaScript 代码本身并不会直接调用这个文件中的函数**。 然而，JavaScript 可以通过以下方式间接地与这个文件的功能产生关联：

* **Web 浏览器中的媒体播放:**  当用户在网页上观看使用 MoQT 协议进行传输的实时视频或音频流时，浏览器底层的网络栈会使用这个文件来将需要发送给服务器的 MoQT 控制消息（例如订阅请求）序列化成字节流。 同样，当服务器推送媒体数据时，浏览器接收到的 MoQT 数据消息（例如对象头部和数据）会被反序列化并最终传递给 JavaScript 中的媒体播放器进行渲染。

* **Node.js 服务器开发:**  如果使用 Node.js 开发了一个 MoQT 服务器，并且使用了底层的 QUIC 库（例如通过一些 C++ addon），那么这个文件会被用来序列化服务器端需要发送的 MoQT 消息。

**举例说明:**

假设一个 JavaScript 应用需要订阅一个名为 "live/sports" 的直播流。  用户在网页上点击了 "订阅" 按钮，JavaScript 代码可能会发起一个请求，最终触发浏览器底层网络栈构建一个 `MoqtSubscribe` 结构体。

**假设输入 (MoqtSubscribe 结构体):**

```c++
MoqtSubscribe subscribe_message;
subscribe_message.subscribe_id = 123;
subscribe_message.track_alias = 45;
subscribe_message.full_track_name = FullTrackName({"live", "sports"});
subscribe_message.subscriber_priority = 5;
subscribe_message.group_order = MoqtDeliveryOrder::kAscending;
// 其他字段可能为空，表示订阅最新的内容
```

**`SerializeSubscribe` 函数的逻辑推理和假设输出:**

`SerializeSubscribe` 函数会根据 `subscribe_message` 的内容，特别是是否存在 `start_group` 和 `start_object` 等字段，来决定使用哪种序列化方式。 在这个例子中，由于没有指定起始位置，它可能会使用 `MoqtFilterType::kLatestGroup` 或 `MoqtFilterType::kLatestObject`。 假设使用 `kLatestGroup`。

**假设输出 (序列化后的字节流 - 仅为示意，实际字节值会根据 VarInt 编码而变化):**

```
[MessageType: Subscribe (假设为 0x02)]
[Subscribe ID: 123 的 VarInt 编码]
[Track Alias: 45 的 VarInt 编码]
[Track Namespace 元素数量: 2 的 VarInt 编码]
[Namespace 元素 1 ("live") 的长度和内容]
[Namespace 元素 2 ("sports") 的长度和内容]
[Subscriber Priority: 5]
[Group Order: Ascending (假设编码为 0x01)]
[Filter Type: Latest Group (假设编码为 0x01)]
[Parameters 数量: 0 的 VarInt 编码]
```

**用户或编程常见的使用错误举例说明:**

1. **不一致的对象元数据:**  如果在使用 `SerializeObjectHeader` 时，提供的 `MoqtObject` 结构体中的 `payload_length` 大于 0，但 `object_status` 却不是 `kNormal`，则会触发 `QUIC_BUG(quic_bug_serialize_object_header_01)`。 这表示程序逻辑错误，尝试发送一个非正常状态（例如取消或完成）但带有有效负载的对象。

    ```c++
    MoqtObject invalid_object;
    invalid_object.payload_length = 100;
    invalid_object.object_status = MoqtObjectStatus::kCanceled;
    // ... 其他字段
    framer.SerializeObjectHeader(invalid_object, MoqtDataStreamType::kStreamHeaderTrack, true); // 这里会触发 QUIC_BUG
    ```

2. **为 Datagram 错误地调用 `SerializeObjectHeader`:**  数据报 (Datagram) 有专门的序列化函数 `SerializeObjectDatagram`。 如果尝试使用 `SerializeObjectHeader` 来序列化数据报，会触发 `QUIC_BUG(quic_bug_serialize_object_header_02)`。

    ```c++
    MoqtObject datagram_object;
    datagram_object.forwarding_preference = MoqtForwardingPreference::kDatagram;
    // ... 其他字段
    framer.SerializeObjectHeader(datagram_object, MoqtDataStreamType::kStreamHeaderTrack, true); // 这里会触发 QUIC_BUG
    ```

3. **`Subscribe` 消息缺少必要的范围信息:**  如果调用 `SerializeSubscribe`，但提供的 `MoqtSubscribe` 结构体没有指定任何有效的过滤条件（例如，既没有指定 `start_group`/`start_object`，也没有表明订阅最新的内容），则会触发 `QUICHE_BUG(MoqtFramer_invalid_subscribe)`。

    ```c++
    MoqtSubscribe invalid_subscribe;
    invalid_subscribe.subscribe_id = 1;
    // ... 其他字段，但没有设置任何过滤条件
    framer.SerializeSubscribe(invalid_subscribe); // 这里会触发 QUICHE_BUG
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个在线视频网站上点击了 "播放" 按钮观看一个直播。 以下是可能到达 `moqt_framer.cc` 的步骤：

1. **用户操作:** 用户在网页上点击了直播视频的 "播放" 按钮。

2. **JavaScript 请求:** 网页上的 JavaScript 代码接收到用户的点击事件，并调用浏览器的媒体 API (例如 `HTMLMediaElement`) 或使用 `fetch` API 发起一个请求，请求直播流的元数据或实际的媒体数据。  这个请求可能包含特定的头部信息，表明需要使用 MoQT 协议。

3. **浏览器网络栈处理:** 浏览器的网络栈接收到这个请求，识别出需要使用 QUIC 协议和 MoQT 协议进行通信。

4. **连接建立 (QUIC):** 如果还没有与服务器建立 QUIC 连接，浏览器会发起 QUIC 连接建立过程。

5. **MoQT 会话初始化:**  在 QUIC 连接建立成功后，浏览器会尝试初始化 MoQT 会话。 这通常涉及到发送一个 `ClientSetup` 消息给服务器，协商 MoQT 的版本和能力。

6. **`SerializeClientSetup` 调用:** 为了发送 `ClientSetup` 消息，Chromium 的网络栈会创建一个 `MoqtClientSetup` 结构体，并调用 `moqt_framer.cc` 中的 `SerializeClientSetup` 函数将其序列化成字节流。

7. **数据发送:** 序列化后的字节流会被通过 QUIC 连接发送到服务器。

**调试线索:**

如果在调试过程中发现 MoQT 消息发送不正确，或者服务器无法解析客户端发送的消息，可以从以下几个方面入手：

* **抓包分析:** 使用网络抓包工具 (例如 Wireshark) 抓取客户端和服务器之间的网络包，查看实际发送的 MoQT 消息的字节流，与 MoQT 协议规范进行比对，确认消息格式是否正确。

* **日志分析:** 查看 Chromium 的网络日志，通常会包含 MoQT 消息的序列化和反序列化过程的详细信息，例如调用的序列化函数、序列化的字段和值等。

* **断点调试:** 在 `moqt_framer.cc` 相关的序列化函数中设置断点，跟踪代码执行流程，查看 MoQT 消息结构体的各个字段值，以及序列化后的字节流内容，从而定位问题所在。

了解用户操作如何一步步地触发 `moqt_framer.cc` 的执行，可以帮助开发者理解网络请求的完整生命周期，并更有针对性地进行问题排查。 例如，如果用户在订阅某个特定的直播流时出现问题，可以重点关注 `SerializeSubscribe` 函数的执行过程和参数。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_framer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/container/inlined_vector.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/wire_serialization.h"

namespace moqt {

namespace {

using ::quiche::QuicheBuffer;
using ::quiche::WireBytes;
using ::quiche::WireOptional;
using ::quiche::WireSpan;
using ::quiche::WireStringWithVarInt62Length;
using ::quiche::WireUint8;
using ::quiche::WireVarInt62;

// Encoding for string parameters as described in
// https://moq-wg.github.io/moq-transport/draft-ietf-moq-transport.html#name-parameters
struct StringParameter {
  template <typename Enum>
  StringParameter(Enum type, absl::string_view data)
      : type(static_cast<uint64_t>(type)), data(data) {
    static_assert(std::is_enum_v<Enum>);
  }

  uint64_t type;
  absl::string_view data;
};
class WireStringParameter {
 public:
  using DataType = StringParameter;

  explicit WireStringParameter(const StringParameter& parameter)
      : parameter_(parameter) {}
  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        WireVarInt62(parameter_.type),
        WireStringWithVarInt62Length(parameter_.data));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(parameter_.type),
        WireStringWithVarInt62Length(parameter_.data));
  }

 private:
  const StringParameter& parameter_;
};

// Encoding for integer parameters as described in
// https://moq-wg.github.io/moq-transport/draft-ietf-moq-transport.html#name-parameters
struct IntParameter {
  template <typename Enum, typename Param>
  IntParameter(Enum type, Param value)
      : type(static_cast<uint64_t>(type)), value(static_cast<uint64_t>(value)) {
    static_assert(std::is_enum_v<Enum>);
    static_assert(std::is_enum_v<Param> || std::is_unsigned_v<Param>);
  }

  uint64_t type;
  uint64_t value;
};
class WireIntParameter {
 public:
  using DataType = IntParameter;

  explicit WireIntParameter(const IntParameter& parameter)
      : parameter_(parameter) {}
  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        WireVarInt62(parameter_.type),
        WireVarInt62(NeededVarIntLen(parameter_.value)),
        WireVarInt62(parameter_.value));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(parameter_.type),
        WireVarInt62(NeededVarIntLen(parameter_.value)),
        WireVarInt62(parameter_.value));
  }

 private:
  size_t NeededVarIntLen(const uint64_t value) {
    return static_cast<size_t>(quic::QuicDataWriter::GetVarInt62Len(value));
  }

  const IntParameter& parameter_;
};

class WireSubscribeParameterList {
 public:
  explicit WireSubscribeParameterList(const MoqtSubscribeParameters& list)
      : list_(list) {}

  size_t GetLengthOnWire() {
    auto string_parameters = StringParameters();
    auto int_parameters = IntParameters();
    return quiche::ComputeLengthOnWire(
        WireVarInt62(string_parameters.size() + int_parameters.size()),
        WireSpan<WireStringParameter>(string_parameters),
        WireSpan<WireIntParameter>(int_parameters));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    auto string_parameters = StringParameters();
    auto int_parameters = IntParameters();
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(string_parameters.size() + int_parameters.size()),
        WireSpan<WireStringParameter>(string_parameters),
        WireSpan<WireIntParameter>(int_parameters));
  }

 private:
  absl::InlinedVector<StringParameter, 1> StringParameters() const {
    absl::InlinedVector<StringParameter, 1> result;
    if (list_.authorization_info.has_value()) {
      result.push_back(
          StringParameter(MoqtTrackRequestParameter::kAuthorizationInfo,
                          *list_.authorization_info));
    }
    return result;
  }
  absl::InlinedVector<IntParameter, 3> IntParameters() const {
    absl::InlinedVector<IntParameter, 3> result;
    if (list_.delivery_timeout.has_value()) {
      QUICHE_DCHECK_GE(*list_.delivery_timeout, quic::QuicTimeDelta::Zero());
      result.push_back(IntParameter(
          MoqtTrackRequestParameter::kDeliveryTimeout,
          static_cast<uint64_t>(list_.delivery_timeout->ToMilliseconds())));
    }
    if (list_.max_cache_duration.has_value()) {
      QUICHE_DCHECK_GE(*list_.max_cache_duration, quic::QuicTimeDelta::Zero());
      result.push_back(IntParameter(
          MoqtTrackRequestParameter::kMaxCacheDuration,
          static_cast<uint64_t>(list_.max_cache_duration->ToMilliseconds())));
    }
    if (list_.object_ack_window.has_value()) {
      QUICHE_DCHECK_GE(*list_.object_ack_window, quic::QuicTimeDelta::Zero());
      result.push_back(IntParameter(
          MoqtTrackRequestParameter::kOackWindowSize,
          static_cast<uint64_t>(list_.object_ack_window->ToMicroseconds())));
    }
    return result;
  }

  const MoqtSubscribeParameters& list_;
};

class WireFullTrackName {
 public:
  using DataType = FullTrackName;

  // If |includes_name| is true, the last element in the tuple is the track
  // name and is therefore not counted in the prefix of the namespace tuple.
  WireFullTrackName(const FullTrackName& name, bool includes_name)
      : name_(name), includes_name_(includes_name) {}

  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        WireVarInt62(num_elements()),
        WireSpan<WireStringWithVarInt62Length, std::string>(name_.tuple()));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(num_elements()),
        WireSpan<WireStringWithVarInt62Length, std::string>(name_.tuple()));
  }

 private:
  size_t num_elements() const {
    return includes_name_ ? (name_.tuple().size() - 1) : name_.tuple().size();
  }

  const FullTrackName& name_;
  const bool includes_name_;
};

// Serializes data into buffer using the default allocator.  Invokes QUICHE_BUG
// on failure.
template <typename... Ts>
QuicheBuffer Serialize(Ts... data) {
  absl::StatusOr<QuicheBuffer> buffer = quiche::SerializeIntoBuffer(
      quiche::SimpleBufferAllocator::Get(), data...);
  if (!buffer.ok()) {
    QUICHE_BUG(moqt_failed_serialization)
        << "Failed to serialize MoQT frame: " << buffer.status();
    return QuicheBuffer();
  }
  return *std::move(buffer);
}

// Serializes data into buffer using the default allocator.  Invokes QUICHE_BUG
// on failure.
template <typename... Ts>
QuicheBuffer SerializeControlMessage(MoqtMessageType type, Ts... data) {
  uint64_t message_type = static_cast<uint64_t>(type);
  size_t payload_size = quiche::ComputeLengthOnWire(data...);
  size_t buffer_size =
      payload_size + quiche::ComputeLengthOnWire(WireVarInt62(message_type),
                                                 WireVarInt62(payload_size));
  if (buffer_size == 0) {
    return QuicheBuffer();
  }

  QuicheBuffer buffer(quiche::SimpleBufferAllocator::Get(), buffer_size);
  quiche::QuicheDataWriter writer(buffer.size(), buffer.data());
  absl::Status status = SerializeIntoWriter(
      writer, WireVarInt62(message_type), WireVarInt62(payload_size), data...);
  if (!status.ok() || writer.remaining() != 0) {
    QUICHE_BUG(moqt_failed_serialization)
        << "Failed to serialize MoQT frame: " << status;
    return QuicheBuffer();
  }
  return buffer;
}

WireUint8 WireDeliveryOrder(std::optional<MoqtDeliveryOrder> delivery_order) {
  if (!delivery_order.has_value()) {
    return WireUint8(0x00);
  }
  switch (*delivery_order) {
    case MoqtDeliveryOrder::kAscending:
      return WireUint8(0x01);
    case MoqtDeliveryOrder::kDescending:
      return WireUint8(0x02);
  }
  QUICHE_NOTREACHED();
  return WireUint8(0xff);
}

uint64_t SignedVarintSerializedForm(int64_t value) {
  if (value < 0) {
    return ((-value) << 1) | 0x01;
  }
  return value << 1;
}

}  // namespace

quiche::QuicheBuffer MoqtFramer::SerializeObjectHeader(
    const MoqtObject& message, MoqtDataStreamType message_type,
    bool is_first_in_stream) {
  if (!ValidateObjectMetadata(message, message_type)) {
    QUIC_BUG(quic_bug_serialize_object_header_01)
        << "Object metadata is invalid";
    return quiche::QuicheBuffer();
  }
  if (message_type == MoqtDataStreamType::kObjectDatagram) {
    QUIC_BUG(quic_bug_serialize_object_header_02)
        << "Datagrams use SerializeObjectDatagram()";
    return quiche::QuicheBuffer();
  }
  if (!is_first_in_stream) {
    switch (message_type) {
      case MoqtDataStreamType::kStreamHeaderTrack:
        return (message.payload_length == 0)
                   ? Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length),
                               WireVarInt62(message.object_status))
                   : Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length));
      case MoqtDataStreamType::kStreamHeaderSubgroup:
        return (message.payload_length == 0)
                   ? Serialize(WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length),
                               WireVarInt62(static_cast<uint64_t>(
                                   message.object_status)))
                   : Serialize(WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length));
      case MoqtDataStreamType::kStreamHeaderFetch:
        return (message.payload_length == 0)
                   ? Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(*message.subgroup_id),
                               WireVarInt62(message.object_id),
                               WireUint8(message.publisher_priority),
                               WireVarInt62(message.payload_length),
                               WireVarInt62(static_cast<uint64_t>(
                                   message.object_status)))
                   : Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(*message.subgroup_id),
                               WireVarInt62(message.object_id),
                               WireUint8(message.publisher_priority),
                               WireVarInt62(message.payload_length));
      default:
        QUICHE_NOTREACHED();
        return quiche::QuicheBuffer();
    }
  }
  switch (message_type) {
    case MoqtDataStreamType::kStreamHeaderTrack:
      return (message.payload_length == 0)
                 ? Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.group_id),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length),
                             WireVarInt62(message.object_status))
                 : Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.group_id),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length));
    case MoqtDataStreamType::kStreamHeaderSubgroup:
      return (message.payload_length == 0)
                 ? Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length),
                             WireVarInt62(message.object_status))
                 : Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length));
    case MoqtDataStreamType::kStreamHeaderFetch:
      return (message.payload_length == 0)
                 ? Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireVarInt62(message.object_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.payload_length),
                             WireVarInt62(message.object_status))
                 : Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireVarInt62(message.object_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.payload_length));
    default:
      QUICHE_NOTREACHED();
      return quiche::QuicheBuffer();
  }
}

quiche::QuicheBuffer MoqtFramer::SerializeObjectDatagram(
    const MoqtObject& message, absl::string_view payload) {
  if (!ValidateObjectMetadata(message, MoqtDataStreamType::kObjectDatagram)) {
    QUIC_BUG(quic_bug_serialize_object_datagram_01)
        << "Object metadata is invalid";
    return quiche::QuicheBuffer();
  }
  if (message.forwarding_preference != MoqtForwardingPreference::kDatagram) {
    QUIC_BUG(quic_bug_serialize_object_datagram_02)
        << "Only datagrams use SerializeObjectDatagram()";
    return quiche::QuicheBuffer();
  }
  if (message.payload_length != payload.length()) {
    QUIC_BUG(quic_bug_serialize_object_datagram_03)
        << "Payload length does not match payload";
    return quiche::QuicheBuffer();
  }
  if (message.payload_length == 0) {
    return Serialize(
        WireVarInt62(MoqtDataStreamType::kObjectDatagram),
        WireVarInt62(message.track_alias), WireVarInt62(message.group_id),
        WireVarInt62(message.object_id), WireUint8(message.publisher_priority),
        WireVarInt62(message.payload_length),
        WireVarInt62(message.object_status));
  }
  return Serialize(
      WireVarInt62(MoqtDataStreamType::kObjectDatagram),
      WireVarInt62(message.track_alias), WireVarInt62(message.group_id),
      WireVarInt62(message.object_id), WireUint8(message.publisher_priority),
      WireVarInt62(message.payload_length), WireBytes(payload));
}

quiche::QuicheBuffer MoqtFramer::SerializeClientSetup(
    const MoqtClientSetup& message) {
  absl::InlinedVector<IntParameter, 1> int_parameters;
  absl::InlinedVector<StringParameter, 1> string_parameters;
  if (message.role.has_value()) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kRole, *message.role));
  }
  if (message.max_subscribe_id.has_value()) {
    int_parameters.push_back(IntParameter(MoqtSetupParameter::kMaxSubscribeId,
                                          *message.max_subscribe_id));
  }
  if (message.supports_object_ack) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kSupportObjectAcks, 1u));
  }
  if (!using_webtrans_ && message.path.has_value()) {
    string_parameters.push_back(
        StringParameter(MoqtSetupParameter::kPath, *message.path));
  }
  return SerializeControlMessage(
      MoqtMessageType::kClientSetup,
      WireVarInt62(message.supported_versions.size()),
      WireSpan<WireVarInt62, MoqtVersion>(message.supported_versions),
      WireVarInt62(string_parameters.size() + int_parameters.size()),
      WireSpan<WireIntParameter>(int_parameters),
      WireSpan<WireStringParameter>(string_parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeServerSetup(
    const MoqtServerSetup& message) {
  absl::InlinedVector<IntParameter, 1> int_parameters;
  if (message.role.has_value()) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kRole, *message.role));
  }
  if (message.max_subscribe_id.has_value()) {
    int_parameters.push_back(IntParameter(MoqtSetupParameter::kMaxSubscribeId,
                                          *message.max_subscribe_id));
  }
  if (message.supports_object_ack) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kSupportObjectAcks, 1u));
  }
  return SerializeControlMessage(MoqtMessageType::kServerSetup,
                                 WireVarInt62(message.selected_version),
                                 WireVarInt62(int_parameters.size()),
                                 WireSpan<WireIntParameter>(int_parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribe(
    const MoqtSubscribe& message) {
  MoqtFilterType filter_type = GetFilterType(message);
  if (filter_type == MoqtFilterType::kNone) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe) << "Invalid object range";
    return quiche::QuicheBuffer();
  }
  switch (filter_type) {
    case MoqtFilterType::kLatestGroup:
    case MoqtFilterType::kLatestObject:
      return SerializeControlMessage(
          MoqtMessageType::kSubscribe, WireVarInt62(message.subscribe_id),
          WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireSubscribeParameterList(message.parameters));
    case MoqtFilterType::kAbsoluteStart:
      return SerializeControlMessage(
          MoqtMessageType::kSubscribe, WireVarInt62(message.subscribe_id),
          WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireVarInt62(*message.start_group),
          WireVarInt62(*message.start_object),
          WireSubscribeParameterList(message.parameters));
    case MoqtFilterType::kAbsoluteRange:
      return SerializeControlMessage(
          MoqtMessageType::kSubscribe, WireVarInt62(message.subscribe_id),
          WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireVarInt62(*message.start_group),
          WireVarInt62(*message.start_object), WireVarInt62(*message.end_group),
          WireVarInt62(message.end_object.has_value() ? *message.end_object + 1
                                                      : 0),
          WireSubscribeParameterList(message.parameters));
    default:
      QUICHE_BUG(MoqtFramer_end_group_missing) << "Subscribe framing error.";
      return quiche::QuicheBuffer();
  }
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeOk(
    const MoqtSubscribeOk& message) {
  if (message.parameters.authorization_info.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_ok)
        << "SUBSCRIBE_OK with delivery timeout";
  }
  if (message.largest_id.has_value()) {
    return SerializeControlMessage(
        MoqtMessageType::kSubscribeOk, WireVarInt62(message.subscribe_id),
        WireVarInt62(message.expires.ToMilliseconds()),
        WireDeliveryOrder(message.group_order), WireUint8(1),
        WireVarInt62(message.largest_id->group),
        WireVarInt62(message.largest_id->object),
        WireSubscribeParameterList(message.parameters));
  }
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeOk, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.expires.ToMilliseconds()),
      WireDeliveryOrder(message.group_order), WireUint8(0),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeError(
    const MoqtSubscribeError& message) {
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeError, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.error_code),
      WireStringWithVarInt62Length(message.reason_phrase),
      WireVarInt62(message.track_alias));
}

quiche::QuicheBuffer MoqtFramer::SerializeUnsubscribe(
    const MoqtUnsubscribe& message) {
  return SerializeControlMessage(MoqtMessageType::kUnsubscribe,
                                 WireVarInt62(message.subscribe_id));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeDone(
    const MoqtSubscribeDone& message) {
  if (message.final_id.has_value()) {
    return SerializeControlMessage(
        MoqtMessageType::kSubscribeDone, WireVarInt62(message.subscribe_id),
        WireVarInt62(message.status_code),
        WireStringWithVarInt62Length(message.reason_phrase), WireUint8(1),
        WireVarInt62(message.final_id->group),
        WireVarInt62(message.final_id->object));
  }
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeDone, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.status_code),
      WireStringWithVarInt62Length(message.reason_phrase), WireUint8(0));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeUpdate(
    const MoqtSubscribeUpdate& message) {
  if (message.parameters.authorization_info.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_update)
        << "SUBSCRIBE_UPDATE with authorization info";
  }
  uint64_t end_group =
      message.end_group.has_value() ? *message.end_group + 1 : 0;
  uint64_t end_object =
      message.end_object.has_value() ? *message.end_object + 1 : 0;
  if (end_group == 0 && end_object != 0) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_update) << "Invalid object range";
    return quiche::QuicheBuffer();
  }
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeUpdate, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.start_group), WireVarInt62(message.start_object),
      WireVarInt62(end_group), WireVarInt62(end_object),
      WireUint8(message.subscriber_priority),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounce(
    const MoqtAnnounce& message) {
  if (message.parameters.delivery_timeout.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_announce) << "ANNOUNCE with delivery timeout";
  }
  return SerializeControlMessage(
      MoqtMessageType::kAnnounce,
      WireFullTrackName(message.track_namespace, false),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceOk(
    const MoqtAnnounceOk& message) {
  return SerializeControlMessage(
      MoqtMessageType::kAnnounceOk,
      WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceError(
    const MoqtAnnounceError& message) {
  return SerializeControlMessage(
      MoqtMessageType::kAnnounceError,
      WireFullTrackName(message.track_namespace, false),
      WireVarInt62(message.error_code),
      WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceCancel(
    const MoqtAnnounceCancel& message) {
  return SerializeControlMessage(
      MoqtMessageType::kAnnounceCancel,
      WireFullTrackName(message.track_namespace, false),
      WireVarInt62(message.error_code),
      WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeTrackStatusRequest(
    const MoqtTrackStatusRequest& message) {
  return SerializeControlMessage(
      MoqtMessageType::kTrackStatusRequest,
      WireFullTrackName(message.full_track_name, true));
}

quiche::QuicheBuffer MoqtFramer::SerializeUnannounce(
    const MoqtUnannounce& message) {
  return SerializeControlMessage(
      MoqtMessageType::kUnannounce,
      WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeTrackStatus(
    const MoqtTrackStatus& message) {
  return SerializeControlMessage(
      MoqtMessageType::kTrackStatus,
      WireFullTrackName(message.full_track_name, true),
      WireVarInt62(message.status_code), WireVarInt62(message.last_group),
      WireVarInt62(message.last_object));
}

quiche::QuicheBuffer MoqtFramer::SerializeGoAway(const MoqtGoAway& message) {
  return SerializeControlMessage(
      MoqtMessageType::kGoAway,
      WireStringWithVarInt62Length(message.new_session_uri));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeAnnounces(
    const MoqtSubscribeAnnounces& message) {
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeAnnounces,
      WireFullTrackName(message.track_namespace, false),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeAnnouncesOk(
    const MoqtSubscribeAnnouncesOk& message) {
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeAnnouncesOk,
      WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeAnnouncesError(
    const MoqtSubscribeAnnouncesError& message) {
  return SerializeControlMessage(
      MoqtMessageType::kSubscribeAnnouncesError,
      WireFullTrackName(message.track_namespace, false),
      WireVarInt62(message.error_code),
      WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeUnsubscribeAnnounces(
    const MoqtUnsubscribeAnnounces& message) {
  return SerializeControlMessage(
      MoqtMessageType::kUnsubscribeAnnounces,
      WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeMaxSubscribeId(
    const MoqtMaxSubscribeId& message) {
  return SerializeControlMessage(MoqtMessageType::kMaxSubscribeId,
                                 WireVarInt62(message.max_subscribe_id));
}

quiche::QuicheBuffer MoqtFramer::SerializeFetch(const MoqtFetch& message) {
  if (message.end_group < message.start_object.group ||
      (message.end_group == message.start_object.group &&
       message.end_object.has_value() &&
       *message.end_object < message.start_object.object)) {
    QUICHE_BUG(MoqtFramer_invalid_fetch) << "Invalid FETCH object range";
    return quiche::QuicheBuffer();
  }
  return SerializeControlMessage(
      MoqtMessageType::kFetch, WireVarInt62(message.subscribe_id),
      WireFullTrackName(message.full_track_name, true),
      WireUint8(message.subscriber_priority),
      WireDeliveryOrder(message.group_order),
      WireVarInt62(message.start_object.group),
      WireVarInt62(message.start_object.object),
      WireVarInt62(message.end_group),
      WireVarInt62(message.end_object.has_value() ? *message.end_object + 1
                                                  : 0),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeFetchCancel(
    const MoqtFetchCancel& message) {
  return SerializeControlMessage(MoqtMessageType::kFetchCancel,
                                 WireVarInt62(message.subscribe_id));
}

quiche::QuicheBuffer MoqtFramer::SerializeFetchOk(const MoqtFetchOk& message) {
  return SerializeControlMessage(
      MoqtMessageType::kFetchOk, WireVarInt62(message.subscribe_id),
      WireDeliveryOrder(message.group_order),
      WireVarInt62(message.largest_id.group),
      WireVarInt62(message.largest_id.object),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeFetchError(
    const MoqtFetchError& message) {
  return SerializeControlMessage(
      MoqtMessageType::kFetchError, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.error_code),
      WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeObjectAck(
    const MoqtObjectAck& message) {
  return SerializeControlMessage(
      MoqtMessageType::kObjectAck, WireVarInt62(message.subscribe_id),
      WireVarInt62(message.group_id), WireVarInt62(message.object_id),
      WireVarInt62(SignedVarintSerializedForm(
          message.delta_from_deadline.ToMicroseconds())));
}

// static
bool MoqtFramer::ValidateObjectMetadata(const MoqtObject& object,
                                        MoqtDataStreamType message_type) {
  if (object.object_status != MoqtObjectStatus::kNormal &&
      object.payload_length > 0) {
    return false;
  }
  if ((message_type == MoqtDataStreamType::kStreamHeaderSubgroup ||
       message_type == MoqtDataStreamType::kStreamHeaderFetch) !=
      object.subgroup_id.has_value()) {
    return false;
  }
  return true;
}

}  // namespace moqt
```