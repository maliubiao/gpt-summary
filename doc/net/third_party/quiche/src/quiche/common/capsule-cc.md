Response:
Let's break down the thought process for analyzing the `capsule.cc` file.

1. **Understand the Purpose from the Filename and Path:** The path `net/third_party/quiche/src/quiche/common/capsule.cc` strongly suggests this file deals with "capsules" within the QUICHE library. QUICHE itself is a QUIC implementation, often used in Chromium's network stack, especially for WebTransport. So, the core function likely revolves around defining, serializing, and deserializing some kind of structured data unit called a "capsule."

2. **Examine Includes:** The included headers provide valuable clues:
    * Standard C++ headers (`cstddef`, `cstdint`, `limits`, etc.): Basic data types and utilities.
    * `absl/...`:  Abseil library, indicating use of status codes, string manipulation, and variants. This suggests robustness and structured error handling.
    * `quiche/common/platform/api/...`:  Platform abstraction, indicating the code might be used across different operating systems.
    * `quiche/common/...`:  Other QUICHE-specific utilities for buffer management, data reading/writing, IP addresses, and wire serialization. This points to the core function of encoding and decoding data for network transmission.
    * `quiche/web_transport/web_transport.h`:  Strongly links this file to the WebTransport protocol, suggesting the capsules are likely related to WebTransport messaging.

3. **Identify Key Data Structures:**  Look for structs and classes:
    * `CapsuleType`: An enum defining the different types of capsules. This is crucial for understanding the various functionalities.
    * `DatagramCapsule`, `LegacyDatagramCapsule`, etc.:  Structs representing the data for each specific capsule type. The names clearly indicate their purpose (datagrams, connection closure, stream data, etc.). The members within these structs (e.g., `error_code`, `stream_id`, `data`) provide more specific information about the capsule's content.
    * `Capsule`:  A central class holding a `variant` of the different capsule types. This is a common pattern for representing a type that can hold one of several possible data structures.
    * `CapsuleParser`: A class responsible for parsing raw byte streams into `Capsule` objects. This highlights the deserialization aspect.
    * Internal "Wire" classes (`WirePrefixWithId`, `WireIpAddressRange`): These are serialization helpers, indicating how data is formatted for transmission.

4. **Analyze Key Functions:**
    * `CapsuleTypeToString`:  A simple helper for converting the enum to a human-readable string, useful for logging and debugging.
    * `Capsule::[SpecificType](...)`: Static factory methods for creating `Capsule` objects of specific types. This simplifies object creation.
    * `Capsule::operator==`:  Equality comparison for capsules, essential for testing and comparing capsule instances.
    * `[CapsuleType]Capsule::ToString()`:  Methods for generating string representations of capsule contents, useful for debugging and logging. The use of `absl::BytesToHexString` suggests the data often involves raw bytes.
    * `SerializeCapsuleWithStatus`, `SerializeCapsuleFields`, `SerializeDatagramCapsuleHeader`, `SerializeWebTransportStreamCapsuleHeader`, `SerializeCapsule`: Functions related to serializing `Capsule` objects into byte buffers. This is the core of encoding the data for network transmission.
    * `CapsuleParser::IngestCapsuleFragment`, `CapsuleParser::AttemptParseCapsule`, `ParseCapsulePayload`: Functions responsible for taking raw byte data and attempting to parse it into `Capsule` objects. This is the deserialization process.
    * `CapsuleParser::Visitor`:  An interface for handling successfully parsed capsules and reporting errors. This is a common pattern for decoupling the parsing logic from the handling logic.

5. **Identify Relationships to JavaScript (and Web APIs):** The connection to JavaScript comes through WebTransport. The `WT_*` capsule types (e.g., `WT_STREAM`, `WT_RESET_STREAM`) directly correspond to WebTransport concepts. JavaScript's `WebTransport` API allows sending and receiving data streams, closing sessions, and managing stream lifecycle. The capsules are the underlying wire representation of these actions.

6. **Consider Error Handling:** The use of `absl::Status` and `absl::StatusOr` signifies a focus on robust error handling during serialization and deserialization. The `CapsuleParser` also has mechanisms for reporting parsing failures.

7. **Think About Usage Scenarios and Potential Errors:**  Consider how this code might be used in a real-world scenario. Web browsers or other network applications using WebTransport would interact with this code. Common errors could include:
    * Sending malformed capsule data (e.g., incorrect size, invalid type).
    * Receiving truncated or incomplete capsules.
    * Protocol mismatches between the sender and receiver.

8. **Outline a Debugging Scenario:**  Imagine a user reports an issue with WebTransport data not being received correctly. Tracing the network packets and then looking at how the `CapsuleParser` attempts to process those bytes would be a natural debugging step.

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to JavaScript, Logical Reasoning, Common Errors, and Debugging. Use clear headings and bullet points for readability.

10. **Refine and Elaborate:**  Review the initial analysis and add more detail and specific examples where possible. For instance, for JavaScript, provide concrete examples of `send()` and event listeners. For logical reasoning, create simple input/output scenarios. For common errors, describe specific situations.

By following these steps, you can systematically analyze the code and generate a comprehensive explanation of its functionality and context. The key is to start with the high-level purpose and then gradually drill down into the details of the code, connecting the different parts together and relating them to the broader system and relevant technologies.
这个文件 `net/third_party/quiche/src/quiche/common/capsule.cc` 是 Chromium 网络栈中 QUICHE 库的一部分，它定义了 **胶囊 (Capsule)** 的结构和处理逻辑。胶囊是 WebTransport 协议中用于封装不同类型消息的基本单元。

以下是该文件的主要功能：

**1. 定义胶囊类型 (Capsule Types):**

* 使用枚举 `CapsuleType` 定义了所有可能的胶囊类型，例如：
    * `DATAGRAM`:  用于传输 HTTP 数据报。
    * `LEGACY_DATAGRAM`, `LEGACY_DATAGRAM_WITHOUT_CONTEXT`:  旧版本的 HTTP 数据报。
    * `CLOSE_WEBTRANSPORT_SESSION`:  用于关闭 WebTransport 会话。
    * `DRAIN_WEBTRANSPORT_SESSION`:  用于指示 WebTransport 会话进入 draining 状态。
    * `ADDRESS_REQUEST`, `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT`:  用于网络地址管理相关的胶囊。
    * `WT_STREAM`, `WT_STREAM_WITH_FIN`:  用于传输 WebTransport 流数据 (带或不带 FIN 标志)。
    * `WT_RESET_STREAM`:  用于重置 WebTransport 流。
    * `WT_STOP_SENDING`:  用于停止发送 WebTransport 流数据。
    * `WT_MAX_STREAM_DATA`, `WT_MAX_STREAMS_BIDI`, `WT_MAX_STREAMS_UNIDI`: 用于 WebTransport 的流量控制。
* 提供了 `CapsuleTypeToString` 函数将胶囊类型转换为字符串，方便调试和日志记录。

**2. 定义胶囊的数据结构:**

* 使用 `absl::variant` 类型的 `Capsule` 类来表示一个通用的胶囊，它可以包含不同类型的胶囊数据。
* 为每种胶囊类型定义了相应的结构体，例如 `DatagramCapsule`, `CloseWebTransportSessionCapsule`, `WebTransportStreamDataCapsule` 等，用于存储特定类型胶囊的数据。

**3. 提供创建胶囊的静态方法:**

* `Capsule` 类提供了一系列静态方法，例如 `Capsule::Datagram()`, `Capsule::CloseWebTransportSession()` 等，用于方便地创建特定类型的胶囊实例。

**4. 实现胶囊的序列化和反序列化:**

* 提供了将 `Capsule` 对象序列化为字节流的函数，例如 `SerializeCapsuleWithStatus`, `SerializeCapsule`, 以及针对特定胶囊头部的序列化函数，如 `SerializeDatagramCapsuleHeader`, `SerializeWebTransportStreamCapsuleHeader`。
* 定义了 `CapsuleParser` 类，用于从接收到的字节流中解析出 `Capsule` 对象。`CapsuleParser` 使用访问者模式 (`Visitor`) 来处理解析出的胶囊。

**5. 提供胶囊的字符串表示:**

* 为每种胶囊类型和通用的 `Capsule` 类实现了 `ToString()` 方法，方便调试时查看胶囊的内容。

**与 JavaScript 功能的关系：**

该文件中的胶囊直接对应于 WebTransport API 在 JavaScript 中使用的概念。WebTransport 允许 JavaScript 通过 HTTP/3 连接建立双向的、基于流的数据通道。

* **`DATAGRAM` 和旧版本的 `LEGACY_DATAGRAM`:**  对应于 JavaScript WebTransport API 中的 `send()` 方法发送的数据报。当 JavaScript 代码调用 `transport.send(buffer)` 时，底层的实现可能会创建一个 `DATAGRAM` 类型的胶囊来封装 `buffer` 中的数据。
    * **举例:**
        ```javascript
        const transport = new WebTransport("https://example.com");
        await transport.ready;
        const encoder = new TextEncoder();
        const data = encoder.encode("Hello from JavaScript!");
        transport.send(data); // 这可能会导致创建一个 DATAGRAM 胶囊
        ```

* **`WT_STREAM` 和 `WT_STREAM_WITH_FIN`:** 对应于 JavaScript WebTransport API 中通过 `createUnidirectionalStream()` 或 `createBidirectionalStream()` 创建的流上发送的数据。当在流上调用 `writable.getWriter().write(data)` 或 `writable.getWriter().close()` 时，会创建 `WT_STREAM` 或 `WT_STREAM_WITH_FIN` 类型的胶囊。
    * **举例:**
        ```javascript
        const transport = new WebTransport("https://example.com");
        await transport.ready;
        const stream = await transport.createUnidirectionalStream();
        const writer = stream.writable.getWriter();
        const encoder = new TextEncoder();
        await writer.write(encoder.encode("Data for the stream.")); // 创建 WT_STREAM 胶囊
        await writer.close(); // 创建 WT_STREAM_WITH_FIN 胶囊
        ```

* **`WT_RESET_STREAM`:** 对应于 JavaScript 中调用 `stream.reset()` 或接收到对端发送的重置信号。
    * **举例:**
        ```javascript
        // 发送端
        stream.reset(300); // 发送一个 WT_RESET_STREAM 胶囊

        // 接收端
        stream.onclose = (event) => {
          console.log("Stream closed with error code:", event.applicationProtocolErrorCode);
        };
        ```

* **`WT_STOP_SENDING`:** 对应于 JavaScript 中调用 `stream.readable.cancel()` 或接收到对端发送的停止发送信号。

* **`CLOSE_WEBTRANSPORT_SESSION`:** 对应于 JavaScript 中调用 `transport.close()` 或接收到对端发送的关闭会话信号。
    * **举例:**
        ```javascript
        transport.close({ closeCode: 1000, reason: "Normal closure" }); // 发送一个 CLOSE_WEBTRANSPORT_SESSION 胶囊
        ```

* **`WT_MAX_STREAM_DATA`, `WT_MAX_STREAMS_BIDI`, `WT_MAX_STREAMS_UNIDI`:**  这些胶囊类型用于 WebTransport 的流量控制，在 JavaScript 中通常不会直接操作，而是由浏览器底层自动处理，以管理数据发送速率和并发流的数量。

**逻辑推理 (假设输入与输出):**

假设 `CapsuleParser` 接收到以下字节流 (十六进制表示)，代表一个 `DATAGRAM` 类型的胶囊，内容为 "Hello":

**假设输入:** `00 06 05 48 65 6c 6c 6f`

**推理:**

1. **`00`**:  表示胶囊类型，对应 `CapsuleType::DATAGRAM` (值为 0)。这是一个 VarInt 编码。
2. **`06`**: 表示胶囊负载的长度，值为 6 字节，也是一个 VarInt 编码。
3. **`05`**: 表示数据报内容的长度，值为 5 字节，这是 `DATAGRAM` 胶囊的内部负载长度，同样是 VarInt 编码。
4. **`48 65 6c 6c 6f`**:  表示数据报的内容，对应 "Hello" 的 ASCII 编码。

**预期输出 (通过 `CapsuleParser::Visitor` 传递):**

一个 `Capsule` 对象，其内部包含一个 `DatagramCapsule` 对象，该对象的 `http_datagram_payload` 成员为 "Hello"。

**假设输入 (WebTransport Stream Data):** `08 0a 01 00 05 77 6f 72 6c 64`

**推理:**

1. **`08`**: 表示胶囊类型，对应 `CapsuleType::WT_STREAM` (值为 8)。
2. **`0a`**: 表示胶囊负载的长度，值为 10 字节。
3. **`01`**: 表示 Stream ID，值为 0 (VarInt 编码)。
4. **`00`**: 表示流数据的长度，值为 0 (这里看起来有点问题，正常情况流数据应该有长度)。 **更正:** 这里的 `00` 可能是编码错误或者代表其他含义，根据实际协议规范，Stream ID 后面通常直接是数据。假设正确的编码应该是：
   * **`08`**: `WT_STREAM`
   * **`06`**: 负载长度 6
   * **`00`**: Stream ID 0
   * **`05`**: 数据长度 5
   * **`77 6f 72 6c 64`**: 数据 "world"

**预期输出:**

一个 `Capsule` 对象，其内部包含一个 `WebTransportStreamDataCapsule` 对象，`stream_id` 为 0，`data` 为 "world"。

**用户或编程常见的使用错误：**

1. **尝试手动构造胶囊并发送错误的数据格式:**  用户可能尝试自己创建字节流并发送，但由于对胶囊的结构不了解，导致格式错误，无法被对端正确解析。
    * **例子:**  手动构建 `DATAGRAM` 胶囊时，错误地计算了负载长度，或者使用了错误的 VarInt 编码。

2. **在不支持 WebTransport 的连接上发送 WebTransport 胶囊:**  如果底层连接不是 HTTP/3 连接，或者服务器不支持 WebTransport，发送 WebTransport 特定的胶囊类型会导致错误。

3. **在 WebTransport 会话关闭后尝试发送数据:**  在 WebTransport 会话已经关闭后，尝试通过流或数据报发送数据会导致错误，因为底层的胶囊无法被正确发送。

4. **`CapsuleParser` 的使用者没有正确处理 `OnCapsuleParseFailure` 回调:** 如果解析器遇到无法识别的胶囊或格式错误的胶囊，会调用 `OnCapsuleParseFailure`，如果使用者忽略了这个回调，可能会导致程序状态异常。

5. **缓冲区溢出或不足:**  在序列化或反序列化过程中，如果用于存储胶囊数据的缓冲区大小不正确，可能导致数据丢失或程序崩溃。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用一个基于 Chromium 的浏览器访问一个启用了 WebTransport 的网站，并且报告了数据传输问题。以下是可能的步骤，最终可能需要查看 `capsule.cc` 的代码：

1. **用户在网页上执行某个操作，触发 JavaScript 代码发送 WebTransport 数据。**  例如，点击一个按钮发送消息。
2. **JavaScript 代码调用 WebTransport API 的 `send()` 方法 (对于数据报) 或流的 `write()` 方法 (对于流数据)。**
3. **浏览器底层的网络栈开始处理这个发送请求。**  这涉及到 WebTransport 协议的实现。
4. **QUICHE 库 (包括 `capsule.cc`) 负责将要发送的数据封装成相应的胶囊。**  例如，如果发送的是数据报，会创建一个 `DATAGRAM` 类型的胶囊。
5. **封装好的胶囊被序列化成字节流。**  `SerializeCapsuleWithStatus` 等函数会被调用。
6. **序列化后的字节流通过底层的 QUIC 连接发送到服务器。**
7. **在接收端，QUIC 层接收到字节流。**
8. **QUICHE 库的 `CapsuleParser` 被用来解析接收到的字节流。**  `IngestCapsuleFragment` 和 `AttemptParseCapsule` 等方法会被调用。
9. **如果解析成功，`CapsuleParser` 的 `Visitor` 会收到解析出的 `Capsule` 对象，并进行后续处理。**
10. **如果在解析过程中发生错误，`CapsuleParser` 会调用 `OnCapsuleParseFailure`，指示解析失败。**

**调试线索:**

* **网络抓包:** 使用 Wireshark 或 Chrome 的 `chrome://webrtc-internals` 可以捕获网络数据包，查看实际发送和接收的字节流，从而判断胶囊的格式是否正确。
* **QUICHE 的日志:**  QUICHE 库通常会有详细的日志记录，可以查看日志中关于胶囊序列化、反序列化以及类型的信息，帮助定位问题。
* **断点调试:** 在 `capsule.cc` 的关键函数，例如 `SerializeCapsuleWithStatus`, `AttemptParseCapsule`, `ParseCapsulePayload` 等地方设置断点，可以逐步跟踪胶囊的创建、序列化和解析过程，查看中间变量的值，从而找到问题所在。
* **检查 JavaScript 代码:**  确保 JavaScript 代码正确使用了 WebTransport API，例如，在流上发送数据前已经创建了流，或者在会话关闭前没有尝试发送数据。

总而言之，`capsule.cc` 文件在 Chromium 的 WebTransport 实现中扮演着至关重要的角色，它定义了 WebTransport 消息的格式，并提供了序列化和反序列化的机制，使得 JavaScript 可以方便地通过网络进行双向数据传输。理解这个文件的功能对于调试 WebTransport 相关的问题至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/common/capsule.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/capsule.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/quiche_ip_address.h"
#include "quiche/common/quiche_status_utils.h"
#include "quiche/common/wire_serialization.h"
#include "quiche/web_transport/web_transport.h"

namespace quiche {

std::string CapsuleTypeToString(CapsuleType capsule_type) {
  switch (capsule_type) {
    case CapsuleType::DATAGRAM:
      return "DATAGRAM";
    case CapsuleType::LEGACY_DATAGRAM:
      return "LEGACY_DATAGRAM";
    case CapsuleType::LEGACY_DATAGRAM_WITHOUT_CONTEXT:
      return "LEGACY_DATAGRAM_WITHOUT_CONTEXT";
    case CapsuleType::CLOSE_WEBTRANSPORT_SESSION:
      return "CLOSE_WEBTRANSPORT_SESSION";
    case CapsuleType::DRAIN_WEBTRANSPORT_SESSION:
      return "DRAIN_WEBTRANSPORT_SESSION";
    case CapsuleType::ADDRESS_REQUEST:
      return "ADDRESS_REQUEST";
    case CapsuleType::ADDRESS_ASSIGN:
      return "ADDRESS_ASSIGN";
    case CapsuleType::ROUTE_ADVERTISEMENT:
      return "ROUTE_ADVERTISEMENT";
    case CapsuleType::WT_STREAM:
      return "WT_STREAM";
    case CapsuleType::WT_STREAM_WITH_FIN:
      return "WT_STREAM_WITH_FIN";
    case CapsuleType::WT_RESET_STREAM:
      return "WT_RESET_STREAM";
    case CapsuleType::WT_STOP_SENDING:
      return "WT_STOP_SENDING";
    case CapsuleType::WT_MAX_STREAM_DATA:
      return "WT_MAX_STREAM_DATA";
    case CapsuleType::WT_MAX_STREAMS_BIDI:
      return "WT_MAX_STREAMS_BIDI";
    case CapsuleType::WT_MAX_STREAMS_UNIDI:
      return "WT_MAX_STREAMS_UNIDI";
  }
  return absl::StrCat("Unknown(", static_cast<uint64_t>(capsule_type), ")");
}

std::ostream& operator<<(std::ostream& os, const CapsuleType& capsule_type) {
  os << CapsuleTypeToString(capsule_type);
  return os;
}

// static
Capsule Capsule::Datagram(absl::string_view http_datagram_payload) {
  return Capsule(DatagramCapsule{http_datagram_payload});
}

// static
Capsule Capsule::LegacyDatagram(absl::string_view http_datagram_payload) {
  return Capsule(LegacyDatagramCapsule{http_datagram_payload});
}

// static
Capsule Capsule::LegacyDatagramWithoutContext(
    absl::string_view http_datagram_payload) {
  return Capsule(LegacyDatagramWithoutContextCapsule{http_datagram_payload});
}

// static
Capsule Capsule::CloseWebTransportSession(
    webtransport::SessionErrorCode error_code,
    absl::string_view error_message) {
  return Capsule(CloseWebTransportSessionCapsule({error_code, error_message}));
}

// static
Capsule Capsule::AddressRequest() { return Capsule(AddressRequestCapsule()); }

// static
Capsule Capsule::AddressAssign() { return Capsule(AddressAssignCapsule()); }

// static
Capsule Capsule::RouteAdvertisement() {
  return Capsule(RouteAdvertisementCapsule());
}

// static
Capsule Capsule::Unknown(uint64_t capsule_type,
                         absl::string_view unknown_capsule_data) {
  return Capsule(UnknownCapsule{capsule_type, unknown_capsule_data});
}

bool Capsule::operator==(const Capsule& other) const {
  return capsule_ == other.capsule_;
}

std::string DatagramCapsule::ToString() const {
  return absl::StrCat("DATAGRAM[",
                      absl::BytesToHexString(http_datagram_payload), "]");
}

std::string LegacyDatagramCapsule::ToString() const {
  return absl::StrCat("LEGACY_DATAGRAM[",
                      absl::BytesToHexString(http_datagram_payload), "]");
}

std::string LegacyDatagramWithoutContextCapsule::ToString() const {
  return absl::StrCat("LEGACY_DATAGRAM_WITHOUT_CONTEXT[",
                      absl::BytesToHexString(http_datagram_payload), "]");
}

std::string CloseWebTransportSessionCapsule::ToString() const {
  return absl::StrCat("CLOSE_WEBTRANSPORT_SESSION(error_code=", error_code,
                      ",error_message=\"", error_message, "\")");
}

std::string DrainWebTransportSessionCapsule::ToString() const {
  return "DRAIN_WEBTRANSPORT_SESSION()";
}

std::string AddressRequestCapsule::ToString() const {
  std::string rv = "ADDRESS_REQUEST[";
  for (auto requested_address : requested_addresses) {
    absl::StrAppend(&rv, "(", requested_address.request_id, "-",
                    requested_address.ip_prefix.ToString(), ")");
  }
  absl::StrAppend(&rv, "]");
  return rv;
}

std::string AddressAssignCapsule::ToString() const {
  std::string rv = "ADDRESS_ASSIGN[";
  for (auto assigned_address : assigned_addresses) {
    absl::StrAppend(&rv, "(", assigned_address.request_id, "-",
                    assigned_address.ip_prefix.ToString(), ")");
  }
  absl::StrAppend(&rv, "]");
  return rv;
}

std::string RouteAdvertisementCapsule::ToString() const {
  std::string rv = "ROUTE_ADVERTISEMENT[";
  for (auto ip_address_range : ip_address_ranges) {
    absl::StrAppend(&rv, "(", ip_address_range.start_ip_address.ToString(), "-",
                    ip_address_range.end_ip_address.ToString(), "-",
                    static_cast<int>(ip_address_range.ip_protocol), ")");
  }
  absl::StrAppend(&rv, "]");
  return rv;
}

std::string UnknownCapsule::ToString() const {
  return absl::StrCat("Unknown(", type, ") [", absl::BytesToHexString(payload),
                      "]");
}

std::string WebTransportStreamDataCapsule::ToString() const {
  return absl::StrCat(CapsuleTypeToString(capsule_type()),
                      " [stream_id=", stream_id,
                      ", data=", absl::BytesToHexString(data), "]");
}

std::string WebTransportResetStreamCapsule::ToString() const {
  return absl::StrCat("WT_RESET_STREAM(stream_id=", stream_id,
                      ", error_code=", error_code, ")");
}

std::string WebTransportStopSendingCapsule::ToString() const {
  return absl::StrCat("WT_STOP_SENDING(stream_id=", stream_id,
                      ", error_code=", error_code, ")");
}

std::string WebTransportMaxStreamDataCapsule::ToString() const {
  return absl::StrCat("WT_MAX_STREAM_DATA (stream_id=", stream_id,
                      ", max_stream_data=", max_stream_data, ")");
}

std::string WebTransportMaxStreamsCapsule::ToString() const {
  return absl::StrCat(CapsuleTypeToString(capsule_type()),
                      " (max_streams=", max_stream_count, ")");
}

std::string Capsule::ToString() const {
  return absl::visit([](const auto& capsule) { return capsule.ToString(); },
                     capsule_);
}

std::ostream& operator<<(std::ostream& os, const Capsule& capsule) {
  os << capsule.ToString();
  return os;
}

CapsuleParser::CapsuleParser(Visitor* visitor) : visitor_(visitor) {
  QUICHE_DCHECK_NE(visitor_, nullptr);
}

// Serialization logic for quiche::PrefixWithId.
class WirePrefixWithId {
 public:
  using DataType = PrefixWithId;

  WirePrefixWithId(const PrefixWithId& prefix) : prefix_(prefix) {}

  size_t GetLengthOnWire() {
    return ComputeLengthOnWire(
        WireVarInt62(prefix_.request_id),
        WireUint8(prefix_.ip_prefix.address().IsIPv4() ? 4 : 6),
        WireBytes(prefix_.ip_prefix.address().ToPackedString()),
        WireUint8(prefix_.ip_prefix.prefix_length()));
  }

  absl::Status SerializeIntoWriter(QuicheDataWriter& writer) {
    return AppendToStatus(
        quiche::SerializeIntoWriter(
            writer, WireVarInt62(prefix_.request_id),
            WireUint8(prefix_.ip_prefix.address().IsIPv4() ? 4 : 6),
            WireBytes(prefix_.ip_prefix.address().ToPackedString()),
            WireUint8(prefix_.ip_prefix.prefix_length())),
        " while serializing a PrefixWithId");
  }

 private:
  const PrefixWithId& prefix_;
};

// Serialization logic for quiche::IpAddressRange.
class WireIpAddressRange {
 public:
  using DataType = IpAddressRange;

  explicit WireIpAddressRange(const IpAddressRange& range) : range_(range) {}

  size_t GetLengthOnWire() {
    return ComputeLengthOnWire(
        WireUint8(range_.start_ip_address.IsIPv4() ? 4 : 6),
        WireBytes(range_.start_ip_address.ToPackedString()),
        WireBytes(range_.end_ip_address.ToPackedString()),
        WireUint8(range_.ip_protocol));
  }

  absl::Status SerializeIntoWriter(QuicheDataWriter& writer) {
    return AppendToStatus(
        ::quiche::SerializeIntoWriter(
            writer, WireUint8(range_.start_ip_address.IsIPv4() ? 4 : 6),
            WireBytes(range_.start_ip_address.ToPackedString()),
            WireBytes(range_.end_ip_address.ToPackedString()),
            WireUint8(range_.ip_protocol)),
        " while serializing an IpAddressRange");
  }

 private:
  const IpAddressRange& range_;
};

template <typename... T>
absl::StatusOr<quiche::QuicheBuffer> SerializeCapsuleFields(
    CapsuleType type, QuicheBufferAllocator* allocator, T... fields) {
  size_t capsule_payload_size = ComputeLengthOnWire(fields...);
  return SerializeIntoBuffer(allocator, WireVarInt62(type),
                             WireVarInt62(capsule_payload_size), fields...);
}

absl::StatusOr<quiche::QuicheBuffer> SerializeCapsuleWithStatus(
    const Capsule& capsule, quiche::QuicheBufferAllocator* allocator) {
  switch (capsule.capsule_type()) {
    case CapsuleType::DATAGRAM:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireBytes(capsule.datagram_capsule().http_datagram_payload));
    case CapsuleType::LEGACY_DATAGRAM:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireBytes(capsule.legacy_datagram_capsule().http_datagram_payload));
    case CapsuleType::LEGACY_DATAGRAM_WITHOUT_CONTEXT:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireBytes(capsule.legacy_datagram_without_context_capsule()
                        .http_datagram_payload));
    case CapsuleType::CLOSE_WEBTRANSPORT_SESSION:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireUint32(capsule.close_web_transport_session_capsule().error_code),
          WireBytes(
              capsule.close_web_transport_session_capsule().error_message));
    case CapsuleType::DRAIN_WEBTRANSPORT_SESSION:
      return SerializeCapsuleFields(capsule.capsule_type(), allocator);
    case CapsuleType::ADDRESS_REQUEST:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireSpan<WirePrefixWithId>(absl::MakeConstSpan(
              capsule.address_request_capsule().requested_addresses)));
    case CapsuleType::ADDRESS_ASSIGN:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireSpan<WirePrefixWithId>(absl::MakeConstSpan(
              capsule.address_assign_capsule().assigned_addresses)));
    case CapsuleType::ROUTE_ADVERTISEMENT:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireSpan<WireIpAddressRange>(absl::MakeConstSpan(
              capsule.route_advertisement_capsule().ip_address_ranges)));
    case CapsuleType::WT_STREAM:
    case CapsuleType::WT_STREAM_WITH_FIN:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireVarInt62(capsule.web_transport_stream_data().stream_id),
          WireBytes(capsule.web_transport_stream_data().data));
    case CapsuleType::WT_RESET_STREAM:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireVarInt62(capsule.web_transport_reset_stream().stream_id),
          WireVarInt62(capsule.web_transport_reset_stream().error_code));
    case CapsuleType::WT_STOP_SENDING:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireVarInt62(capsule.web_transport_stop_sending().stream_id),
          WireVarInt62(capsule.web_transport_stop_sending().error_code));
    case CapsuleType::WT_MAX_STREAM_DATA:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireVarInt62(capsule.web_transport_max_stream_data().stream_id),
          WireVarInt62(
              capsule.web_transport_max_stream_data().max_stream_data));
    case CapsuleType::WT_MAX_STREAMS_BIDI:
    case CapsuleType::WT_MAX_STREAMS_UNIDI:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireVarInt62(capsule.web_transport_max_streams().max_stream_count));
    default:
      return SerializeCapsuleFields(
          capsule.capsule_type(), allocator,
          WireBytes(capsule.unknown_capsule().payload));
  }
}

QuicheBuffer SerializeDatagramCapsuleHeader(uint64_t datagram_size,
                                            QuicheBufferAllocator* allocator) {
  absl::StatusOr<QuicheBuffer> buffer =
      SerializeIntoBuffer(allocator, WireVarInt62(CapsuleType::DATAGRAM),
                          WireVarInt62(datagram_size));
  if (!buffer.ok()) {
    return QuicheBuffer();
  }
  return *std::move(buffer);
}

QUICHE_EXPORT QuicheBuffer SerializeWebTransportStreamCapsuleHeader(
    webtransport::StreamId stream_id, bool fin, uint64_t write_size,
    QuicheBufferAllocator* allocator) {
  absl::StatusOr<QuicheBuffer> buffer = SerializeIntoBuffer(
      allocator,
      WireVarInt62(fin ? CapsuleType::WT_STREAM_WITH_FIN
                       : CapsuleType::WT_STREAM),
      WireVarInt62(write_size + QuicheDataWriter::GetVarInt62Len(stream_id)),
      WireVarInt62(stream_id));
  if (!buffer.ok()) {
    return QuicheBuffer();
  }
  return *std::move(buffer);
}

QuicheBuffer SerializeCapsule(const Capsule& capsule,
                              quiche::QuicheBufferAllocator* allocator) {
  absl::StatusOr<QuicheBuffer> serialized =
      SerializeCapsuleWithStatus(capsule, allocator);
  if (!serialized.ok()) {
    QUICHE_BUG(capsule_serialization_failed)
        << "Failed to serialize the following capsule:\n"
        << capsule << "Serialization error: " << serialized.status();
    return QuicheBuffer();
  }
  return *std::move(serialized);
}

bool CapsuleParser::IngestCapsuleFragment(absl::string_view capsule_fragment) {
  if (parsing_error_occurred_) {
    return false;
  }
  absl::StrAppend(&buffered_data_, capsule_fragment);
  while (true) {
    const absl::StatusOr<size_t> buffered_data_read = AttemptParseCapsule();
    if (!buffered_data_read.ok()) {
      ReportParseFailure(buffered_data_read.status().message());
      buffered_data_.clear();
      return false;
    }
    if (*buffered_data_read == 0) {
      break;
    }
    buffered_data_.erase(0, *buffered_data_read);
  }
  static constexpr size_t kMaxCapsuleBufferSize = 1024 * 1024;
  if (buffered_data_.size() > kMaxCapsuleBufferSize) {
    buffered_data_.clear();
    ReportParseFailure("Refusing to buffer too much capsule data");
    return false;
  }
  return true;
}

namespace {
absl::Status ReadWebTransportStreamId(QuicheDataReader& reader,
                                      webtransport::StreamId& id) {
  uint64_t raw_id;
  if (!reader.ReadVarInt62(&raw_id)) {
    return absl::InvalidArgumentError("Failed to read WebTransport Stream ID");
  }
  if (raw_id > std::numeric_limits<uint32_t>::max()) {
    return absl::InvalidArgumentError("Stream ID does not fit into a uint32_t");
  }
  id = static_cast<webtransport::StreamId>(raw_id);
  return absl::OkStatus();
}

absl::StatusOr<Capsule> ParseCapsulePayload(QuicheDataReader& reader,
                                            CapsuleType type) {
  switch (type) {
    case CapsuleType::DATAGRAM:
      return Capsule::Datagram(reader.ReadRemainingPayload());
    case CapsuleType::LEGACY_DATAGRAM:
      return Capsule::LegacyDatagram(reader.ReadRemainingPayload());
    case CapsuleType::LEGACY_DATAGRAM_WITHOUT_CONTEXT:
      return Capsule::LegacyDatagramWithoutContext(
          reader.ReadRemainingPayload());
    case CapsuleType::CLOSE_WEBTRANSPORT_SESSION: {
      CloseWebTransportSessionCapsule capsule;
      if (!reader.ReadUInt32(&capsule.error_code)) {
        return absl::InvalidArgumentError(
            "Unable to parse capsule CLOSE_WEBTRANSPORT_SESSION error code");
      }
      capsule.error_message = reader.ReadRemainingPayload();
      return Capsule(std::move(capsule));
    }
    case CapsuleType::DRAIN_WEBTRANSPORT_SESSION:
      return Capsule(DrainWebTransportSessionCapsule());
    case CapsuleType::ADDRESS_REQUEST: {
      AddressRequestCapsule capsule;
      while (!reader.IsDoneReading()) {
        PrefixWithId requested_address;
        if (!reader.ReadVarInt62(&requested_address.request_id)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_REQUEST request ID");
        }
        uint8_t address_family;
        if (!reader.ReadUInt8(&address_family)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_REQUEST family");
        }
        if (address_family != 4 && address_family != 6) {
          return absl::InvalidArgumentError("Bad ADDRESS_REQUEST family");
        }
        absl::string_view ip_address_bytes;
        if (!reader.ReadStringPiece(&ip_address_bytes,
                                    address_family == 4
                                        ? QuicheIpAddress::kIPv4AddressSize
                                        : QuicheIpAddress::kIPv6AddressSize)) {
          return absl::InvalidArgumentError(
              "Unable to read capsule ADDRESS_REQUEST address");
        }
        quiche::QuicheIpAddress ip_address;
        if (!ip_address.FromPackedString(ip_address_bytes.data(),
                                         ip_address_bytes.size())) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_REQUEST address");
        }
        uint8_t ip_prefix_length;
        if (!reader.ReadUInt8(&ip_prefix_length)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_REQUEST IP prefix length");
        }
        if (ip_prefix_length > QuicheIpPrefix(ip_address).prefix_length()) {
          return absl::InvalidArgumentError("Invalid IP prefix length");
        }
        requested_address.ip_prefix =
            QuicheIpPrefix(ip_address, ip_prefix_length);
        capsule.requested_addresses.push_back(requested_address);
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::ADDRESS_ASSIGN: {
      AddressAssignCapsule capsule;
      while (!reader.IsDoneReading()) {
        PrefixWithId assigned_address;
        if (!reader.ReadVarInt62(&assigned_address.request_id)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_ASSIGN request ID");
        }
        uint8_t address_family;
        if (!reader.ReadUInt8(&address_family)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_ASSIGN family");
        }
        if (address_family != 4 && address_family != 6) {
          return absl::InvalidArgumentError("Bad ADDRESS_ASSIGN family");
        }
        absl::string_view ip_address_bytes;
        if (!reader.ReadStringPiece(&ip_address_bytes,
                                    address_family == 4
                                        ? QuicheIpAddress::kIPv4AddressSize
                                        : QuicheIpAddress::kIPv6AddressSize)) {
          return absl::InvalidArgumentError(
              "Unable to read capsule ADDRESS_ASSIGN address");
        }
        quiche::QuicheIpAddress ip_address;
        if (!ip_address.FromPackedString(ip_address_bytes.data(),
                                         ip_address_bytes.size())) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_ASSIGN address");
        }
        uint8_t ip_prefix_length;
        if (!reader.ReadUInt8(&ip_prefix_length)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ADDRESS_ASSIGN IP prefix length");
        }
        if (ip_prefix_length > QuicheIpPrefix(ip_address).prefix_length()) {
          return absl::InvalidArgumentError("Invalid IP prefix length");
        }
        assigned_address.ip_prefix =
            QuicheIpPrefix(ip_address, ip_prefix_length);
        capsule.assigned_addresses.push_back(assigned_address);
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::ROUTE_ADVERTISEMENT: {
      RouteAdvertisementCapsule capsule;
      while (!reader.IsDoneReading()) {
        uint8_t address_family;
        if (!reader.ReadUInt8(&address_family)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ROUTE_ADVERTISEMENT family");
        }
        if (address_family != 4 && address_family != 6) {
          return absl::InvalidArgumentError("Bad ROUTE_ADVERTISEMENT family");
        }
        IpAddressRange ip_address_range;
        absl::string_view start_ip_address_bytes;
        if (!reader.ReadStringPiece(&start_ip_address_bytes,
                                    address_family == 4
                                        ? QuicheIpAddress::kIPv4AddressSize
                                        : QuicheIpAddress::kIPv6AddressSize)) {
          return absl::InvalidArgumentError(
              "Unable to read capsule ROUTE_ADVERTISEMENT start address");
        }
        if (!ip_address_range.start_ip_address.FromPackedString(
                start_ip_address_bytes.data(), start_ip_address_bytes.size())) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ROUTE_ADVERTISEMENT start address");
        }
        absl::string_view end_ip_address_bytes;
        if (!reader.ReadStringPiece(&end_ip_address_bytes,
                                    address_family == 4
                                        ? QuicheIpAddress::kIPv4AddressSize
                                        : QuicheIpAddress::kIPv6AddressSize)) {
          return absl::InvalidArgumentError(
              "Unable to read capsule ROUTE_ADVERTISEMENT end address");
        }
        if (!ip_address_range.end_ip_address.FromPackedString(
                end_ip_address_bytes.data(), end_ip_address_bytes.size())) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ROUTE_ADVERTISEMENT end address");
        }
        if (!reader.ReadUInt8(&ip_address_range.ip_protocol)) {
          return absl::InvalidArgumentError(
              "Unable to parse capsule ROUTE_ADVERTISEMENT IP protocol");
        }
        capsule.ip_address_ranges.push_back(ip_address_range);
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::WT_STREAM:
    case CapsuleType::WT_STREAM_WITH_FIN: {
      WebTransportStreamDataCapsule capsule;
      capsule.fin = (type == CapsuleType::WT_STREAM_WITH_FIN);
      QUICHE_RETURN_IF_ERROR(
          ReadWebTransportStreamId(reader, capsule.stream_id));
      capsule.data = reader.ReadRemainingPayload();
      return Capsule(std::move(capsule));
    }
    case CapsuleType::WT_RESET_STREAM: {
      WebTransportResetStreamCapsule capsule;
      QUICHE_RETURN_IF_ERROR(
          ReadWebTransportStreamId(reader, capsule.stream_id));
      if (!reader.ReadVarInt62(&capsule.error_code)) {
        return absl::InvalidArgumentError(
            "Failed to parse the RESET_STREAM error code");
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::WT_STOP_SENDING: {
      WebTransportStopSendingCapsule capsule;
      QUICHE_RETURN_IF_ERROR(
          ReadWebTransportStreamId(reader, capsule.stream_id));
      if (!reader.ReadVarInt62(&capsule.error_code)) {
        return absl::InvalidArgumentError(
            "Failed to parse the STOP_SENDING error code");
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::WT_MAX_STREAM_DATA: {
      WebTransportMaxStreamDataCapsule capsule;
      QUICHE_RETURN_IF_ERROR(
          ReadWebTransportStreamId(reader, capsule.stream_id));
      if (!reader.ReadVarInt62(&capsule.max_stream_data)) {
        return absl::InvalidArgumentError(
            "Failed to parse the max stream data field");
      }
      return Capsule(std::move(capsule));
    }
    case CapsuleType::WT_MAX_STREAMS_UNIDI:
    case CapsuleType::WT_MAX_STREAMS_BIDI: {
      WebTransportMaxStreamsCapsule capsule;
      capsule.stream_type = type == CapsuleType::WT_MAX_STREAMS_UNIDI
                                ? webtransport::StreamType::kUnidirectional
                                : webtransport::StreamType::kBidirectional;
      if (!reader.ReadVarInt62(&capsule.max_stream_count)) {
        return absl::InvalidArgumentError(
            "Failed to parse the max streams field");
      }
      return Capsule(std::move(capsule));
    }
    default:
      return Capsule(UnknownCapsule{static_cast<uint64_t>(type),
                                    reader.ReadRemainingPayload()});
  }
}
}  // namespace

absl::StatusOr<size_t> CapsuleParser::AttemptParseCapsule() {
  QUICHE_DCHECK(!parsing_error_occurred_);
  if (buffered_data_.empty()) {
    return 0;
  }
  QuicheDataReader capsule_fragment_reader(buffered_data_);
  uint64_t capsule_type64;
  if (!capsule_fragment_reader.ReadVarInt62(&capsule_type64)) {
    QUICHE_DVLOG(2) << "Partial read: not enough data to read capsule type";
    return 0;
  }
  absl::string_view capsule_data;
  if (!capsule_fragment_reader.ReadStringPieceVarInt62(&capsule_data)) {
    QUICHE_DVLOG(2)
        << "Partial read: not enough data to read capsule length or "
           "full capsule data";
    return 0;
  }
  QuicheDataReader capsule_data_reader(capsule_data);
  absl::StatusOr<Capsule> capsule = ParseCapsulePayload(
      capsule_data_reader, static_cast<CapsuleType>(capsule_type64));
  QUICHE_RETURN_IF_ERROR(capsule.status());
  if (!visitor_->OnCapsule(*capsule)) {
    return absl::AbortedError("Visitor failed to process capsule");
  }
  return capsule_fragment_reader.PreviouslyReadPayload().length();
}

void CapsuleParser::ReportParseFailure(absl::string_view error_message) {
  if (parsing_error_occurred_) {
    QUICHE_BUG(multiple parse errors) << "Experienced multiple parse failures";
    return;
  }
  parsing_error_occurred_ = true;
  visitor_->OnCapsuleParseFailure(error_message);
}

void CapsuleParser::ErrorIfThereIsRemainingBufferedData() {
  if (parsing_error_occurred_) {
    return;
  }
  if (!buffered_data_.empty()) {
    ReportParseFailure("Incomplete capsule left at the end of the stream");
  }
}

bool PrefixWithId::operator==(const PrefixWithId& other) const {
  return request_id == other.request_id && ip_prefix == other.ip_prefix;
}

bool IpAddressRange::operator==(const IpAddressRange& other) const {
  return start_ip_address == other.start_ip_address &&
         end_ip_address == other.end_ip_address &&
         ip_protocol == other.ip_protocol;
}

bool AddressAssignCapsule::operator==(const AddressAssignCapsule& other) const {
  return assigned_addresses == other.assigned_addresses;
}

bool AddressRequestCapsule::operator==(
    const AddressRequestCapsule& other) const {
  return requested_addresses == other.requested_addresses;
}

bool RouteAdvertisementCapsule::operator==(
    const RouteAdvertisementCapsule& other) const {
  return ip_address_ranges == other.ip_address_ranges;
}

bool WebTransportStreamDataCapsule::operator==(
    const WebTransportStreamDataCapsule& other) const {
  return stream_id == other.stream_id && data == other.data && fin == other.fin;
}

bool WebTransportResetStreamCapsule::operator==(
    const WebTransportResetStreamCapsule& other) const {
  return stream_id == other.stream_id && error_code == other.error_code;
}

bool WebTransportStopSendingCapsule::operator==(
    const WebTransportStopSendingCapsule& other) const {
  return stream_id == other.stream_id && error_code == other.error_code;
}

bool WebTransportMaxStreamDataCapsule::operator==(
    const WebTransportMaxStreamDataCapsule& other) const {
  return stream_id == other.stream_id &&
         max_stream_data == other.max_stream_data;
}

bool WebTransportMaxStreamsCapsule::operator==(
    const WebTransportMaxStreamsCapsule& other) const {
  return stream_type == other.stream_type &&
         max_stream_count == other.max_stream_count;
}

}  // namespace quiche
```