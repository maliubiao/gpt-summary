Response:
Let's break down the thought process for analyzing the `quic_types.cc` file and answering the prompt.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of `quic_types.cc`. The request also asks for connections to JavaScript, examples of logical reasoning, common user errors, and debugging context.

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly scan the code. Keywords like `struct`, `enum`, `operator<<`, and `#include` jump out. This suggests the file primarily defines data structures (types) and provides ways to represent them as strings, especially for debugging and logging. The `#include` directives point to related QUIC concepts like error codes and string manipulation utilities.

* **Observation:** The file seems to define various data types related to the QUIC protocol. Many of these types are enums or structs that represent different aspects of a QUIC connection or packet.

**3. Deeper Dive into Key Sections:**

Now, let's examine the different sections of the code more closely.

* **`static_assert`:** This confirms the size of `StatelessResetToken`, indicating a fixed-size data structure.
* **`operator<<` overloads:**  These are crucial. They define how to convert various QUIC types into human-readable strings. This is fundamental for logging, debugging, and potentially for exposing information to higher-level APIs.
* **`ToString` functions:**  Functions like `PerspectiveToString`, `ConnectionCloseSourceToString`, etc., do the same thing as the `operator<<` overloads but as standalone functions. This offers flexibility in how the string representation is obtained.
* **Enums:**  There are many enums, like `Perspective`, `ConnectionCloseSource`, `WriteStatus`, `QuicFrameType`, `TransmissionType`, etc. These represent discrete states or categories within the QUIC protocol.
* **Structs:** `QuicConsumedData`, `AckedPacket`, `LostPacket`, `WriteResult`, `MessageResult`, and `ParsedClientHello` are defined. These structures group related data together.
* **`#define RETURN_STRING_LITERAL`:** This macro simplifies the process of converting enum values to strings. It's a common C++ technique.

**4. Identifying Functionality:**

Based on the code review, the core functionalities are:

* **Defining QUIC-related data types:** Structs and enums representing different aspects of the protocol.
* **Providing string representations of these types:**  This is the dominant purpose, achieved through `operator<<` overloads and `ToString` functions. This is crucial for debugging and logging.
* **Assertions:**  Ensuring data structure sizes meet expectations.

**5. Connecting to JavaScript (and Web Development):**

This requires thinking about where QUIC is used in a web context. The key connection is the browser. The browser uses QUIC to fetch web resources. This file, being part of the Chromium networking stack, is directly involved in handling the QUIC protocol within the browser.

* **Brainstorming:** How does the browser interact with QUIC?  Network requests, responses, connection management, etc.
* **Finding Concrete Examples:**
    * **`Perspective`:**  Client (browser) or Server. This is a fundamental concept in any client-server interaction.
    * **`QuicConsumedData`:**  Tracking how much data has been received, relevant for progress indicators or streaming.
    * **`QuicFrameType`:**  The different types of QUIC frames being exchanged (e.g., data, acknowledgements). While JavaScript doesn't directly see these, browser developer tools might expose this information.
    * **Error Handling (implicitly through types like `ConnectionCloseSource`):** If a connection fails, JavaScript might receive an error event. The underlying reason could involve the concepts defined in this file.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

The primary "logic" here is the conversion of enum values to strings.

* **Hypothesis:**  If you have a `Perspective` enum with the value `Perspective::IS_SERVER`, the `PerspectiveToString` function will return the string "IS_SERVER".
* **Testing the Hypothesis (mentally or with a quick test):** This is fairly straightforward to verify by looking at the code. The `switch` statement directly maps the enum value to the string.

**7. Common User/Programming Errors:**

Think about how developers using the QUIC library might misuse or misunderstand the types defined here.

* **Incorrect Enum Usage:**  Passing an invalid or out-of-range value for an enum. The `default` cases in the `switch` statements handle this to some extent, but it's still a potential error.
* **Mismatched Perspectives:**  Building logic that assumes the wrong perspective (client vs. server).
* **Ignoring Connection Close Reasons:** Not properly handling different connection closure reasons, leading to incomplete error handling.

**8. Debugging Context (How to Reach This Code):**

Imagine a web developer encountering a QUIC-related issue.

* **Scenario:** A website isn't loading correctly, or there are connection problems.
* **Debugging Steps:**
    1. **Browser Developer Tools:** Open the network tab and look for QUIC connections.
    2. **`chrome://net-internals`:** This powerful tool provides detailed network information, including QUIC events. You might see logs containing the string representations defined in this file.
    3. **Chromium Source Code Debugging:**  If deeper investigation is needed, a Chromium developer might set breakpoints in the QUIC code, including this file, to inspect the values of the defined types during runtime. The string conversion functions are essential for viewing these values.

**9. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the prompt. Start with a summary of the file's purpose, then go into details about its functionalities, connections to JavaScript, logical reasoning, common errors, and debugging context. Use clear examples and explanations. The iterative refinement of the answer, based on the thorough analysis of the code and the prompt, leads to a comprehensive response.这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_types.cc` 是 Chromium 网络栈中 QUIC 协议实现的核心组成部分。它的主要功能是**定义了 QUIC 协议中使用到的各种数据类型（如枚举、结构体）以及相关的辅助函数，尤其是提供了将这些类型转换为字符串的功能，方便日志记录和调试**。

让我们逐点分析其功能：

**1. 定义 QUIC 协议相关的数据类型：**

   - **枚举 (enum):** 文件中定义了大量的枚举类型，用于表示 QUIC 协议中的各种状态、类型和行为，例如：
     - `Perspective`: 表示连接的视角 (客户端或服务端)。
     - `ConnectionCloseSource`: 表示连接关闭的原因 (由对方或自身发起)。
     - `ConnectionCloseBehavior`: 表示连接关闭的行为 (静默关闭或发送关闭包)。
     - `WriteStatus`: 表示写操作的状态。
     - `QuicFrameType`: 表示 QUIC 帧的类型 (如数据帧、ACK 帧、控制帧等)。
     - `TransmissionType`: 表示数据包的传输类型 (如首次传输、重传等)。
     - `PacketHeaderFormat`: 表示数据包头的格式。
     - `EncryptionLevel`: 表示加密级别。
     - `MessageStatus`: 表示消息发送的状态。
     - 还有很多其他的枚举类型，覆盖了 QUIC 协议的各个方面。

   - **结构体 (struct):** 文件中定义了一些结构体，用于组合相关的数据：
     - `QuicConsumedData`:  表示已消耗的数据量和是否已消耗 FIN。
     - `AckedPacket`: 表示已被确认的数据包的信息。
     - `LostPacket`: 表示丢失的数据包的信息。
     - `WriteResult`: 表示写操作的结果，包含状态和写入的字节数或错误码。
     - `MessageResult`: 表示消息发送的结果。
     - `ParsedClientHello`: 表示解析后的客户端 Hello 消息。

   - **类型别名 (typedef):** 虽然代码中没有明显的 `typedef`，但 `using` 声明也起到了类似的作用，例如 `using IntType = typename std::underlying_type<AddressChangeType>::type;`。

**2. 提供将这些数据类型转换为字符串的功能：**

   - **`operator<<` 重载:**  为大多数定义的类型重载了 `operator<<`，使得可以使用 `std::cout` 或其他 ostream 对象直接打印这些类型的值，方便日志记录和调试。例如，你可以直接打印一个 `Perspective` 枚举变量，它会输出 "IS_SERVER" 或 "IS_CLIENT"。
   - **`ToString` 函数:**  为一些枚举类型提供了 `ToString` 函数，例如 `PerspectiveToString`、`ConnectionCloseSourceToString` 等，功能与 `operator<<` 类似，但可以更灵活地使用。

**与 JavaScript 的功能关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它定义的 QUIC 协议类型和功能与浏览器中运行的 JavaScript 代码有间接但重要的关系。

- **网络请求:** 当 JavaScript 代码发起一个网络请求（例如使用 `fetch` API）时，如果协议协商选择了 QUIC，那么浏览器底层的网络栈就会使用这里定义的类型来处理 QUIC 连接、数据包和帧。
- **WebTransport API:**  如果 JavaScript 使用 WebTransport API，它直接建立在 QUIC 之上。这个文件定义的类型会直接影响 WebTransport 连接的建立、数据流的管理和错误处理。
- **性能监控和调试:**  开发者工具（如 Chrome DevTools）的网络面板可能会显示与 QUIC 连接相关的状态信息和事件。这些信息很可能来源于底层 C++ 代码中对这些类型的记录和处理。例如，开发者可能会看到连接的 `Perspective`、连接关闭的 `ConnectionCloseSource` 等。
- **错误报告:** 当 QUIC 连接出现问题时，浏览器可能会向 JavaScript 抛出错误。这些错误的根源可能与这里定义的 QUIC 错误码和连接状态有关。

**举例说明 JavaScript 的关系：**

假设一个 JavaScript 应用使用 `fetch` API 向一个支持 QUIC 的服务器发起请求。

1. **连接建立:** 浏览器底层的 QUIC 实现会创建连接，此时 `Perspective` 可能被设置为 `Perspective::IS_CLIENT`。
2. **数据传输:** 数据通过 QUIC 流 (`STREAM_FRAME`) 进行传输，`QuicFrameType` 会记录帧的类型。
3. **确认应答:**  接收方会发送 ACK 帧 (`ACK_FRAME`)，涉及到 `AckedPacket` 结构体的处理。
4. **连接关闭:** 如果服务器主动关闭连接，可能会发送 `CONNECTION_CLOSE_FRAME`。浏览器会将 `ConnectionCloseSource` 记录为 `FROM_PEER`，并可能将 `ConnectionCloseBehavior` 设置为 `SEND_CONNECTION_CLOSE_PACKET`。
5. **错误处理:** 如果连接因网络问题断开，JavaScript 的 `fetch` API 可能会抛出一个网络错误。这个错误在底层可能与某个 QUIC 错误码关联，而这个错误码可能在日志中以字符串形式记录，这得益于此文件中定义的转换函数。

**逻辑推理的假设输入与输出：**

这些 `ToString` 函数和 `operator<<` 重载主要执行简单的映射逻辑。

**假设输入：** 一个 `Perspective` 枚举变量，其值为 `Perspective::IS_SERVER`。

**输出：**  `PerspectiveToString` 函数会返回字符串 `"IS_SERVER"`，或者使用 `std::cout << perspective_variable;` 会输出 `"IS_SERVER"`。

**假设输入：** 一个 `WriteStatus` 枚举变量，其值为 `WRITE_STATUS_BLOCKED_DATA_BUFFERED`.

**输出：** `HistogramEnumString` 函数会返回字符串 `"BLOCKED_DATA_BUFFERED"`，或者使用 `std::cout << write_status_variable;` 会输出 `"BLOCKED_DATA_BUFFERED"`.

**涉及用户或编程常见的使用错误：**

由于这个文件定义的是底层的数据类型，普通用户不会直接操作它们。编程错误主要发生在 QUIC 协议的实现代码中。

1. **不正确地使用枚举值:**  在处理 QUIC 事件或状态时，可能会错误地赋值或比较枚举值，导致逻辑错误。例如，错误地判断连接的 `Perspective`。
   ```c++
   // 假设错误地认为所有连接都是服务器端
   Perspective perspective = GetCurrentConnectionPerspective();
   if (perspective == Perspective::IS_SERVER) {
     // 执行服务器端的操作，但实际可能是客户端连接
   }
   ```

2. **忽略连接关闭的原因:**  在处理连接关闭事件时，没有正确地检查 `ConnectionCloseSource` 和 `ConnectionCloseBehavior`，可能导致无法正确诊断问题或采取适当的措施。
   ```c++
   void HandleConnectionClose(ConnectionCloseSource source) {
     if (source == ConnectionCloseSource::FROM_PEER) {
       // 假设总是因为对端错误关闭
       LogError("Connection closed by peer.");
     } else {
       // 忽略本地关闭的情况
     }
   }
   ```

3. **未处理所有的帧类型:** 在处理接收到的 QUIC 帧时，`switch` 语句可能没有覆盖所有的 `QuicFrameType`，导致未知的帧类型被忽略或错误处理。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个 Web 开发者或用户，你通常不会直接与这个 C++ 文件交互。但是，当出现网络问题时，这个文件中的代码会参与到问题的发生和诊断过程中。

1. **用户操作:** 用户在浏览器中访问一个网站，这个网站使用了 QUIC 协议。
2. **网络请求:** 浏览器发起 QUIC 连接请求。
3. **连接建立:** 底层 QUIC 代码会处理连接的握手过程，涉及到各种 QUIC 帧的交换。
4. **数据传输:** 网页的资源（HTML, CSS, JavaScript, 图片等）通过 QUIC 流进行传输。
5. **出现问题:**  可能出现以下几种情况：
   - **连接失败:**  由于网络问题、服务器配置错误等，QUIC 连接建立失败。这可能涉及到 `ConnectionCloseSource` 为 `FROM_SELF` 或 `FROM_PEER`，并带有特定的错误码。
   - **数据传输错误:**  数据包丢失、乱序等，导致需要重传 (`TransmissionType` 为 `LOSS_RETRANSMISSION` 或 `PTO_RETRANSMISSION`)。
   - **连接被重置:** 服务器或客户端因为某些原因主动关闭连接。

6. **调试线索:**  作为调试线索，这个文件提供的字符串转换功能非常有用：
   - **Chrome DevTools 的网络面板:**  可能会显示 QUIC 连接的状态、使用的协议版本、连接迁移事件等信息，这些信息很多来源于底层 C++ 代码的日志输出，而这些日志输出往往会使用 `operator<<` 或 `ToString` 函数将枚举和结构体转换为易读的字符串。
   - **`chrome://net-internals/#quic`:**  这个 Chrome 内部页面提供了更详细的 QUIC 连接信息，包括帧的收发、拥塞控制状态、错误信息等。这里的信息会大量使用到此文件中定义的字符串表示。
   - **Chromium 源码调试:**  如果需要深入分析问题，Chromium 开发者可以在相关代码中设置断点，查看这些数据类型的值。`operator<<` 的重载使得在调试器中查看这些变量变得容易。例如，可以查看连接关闭时的 `ConnectionCloseSource` 和 `QuicErrorCode`，以确定连接关闭的原因。

总而言之，`quic_types.cc` 文件虽然不直接与用户的 JavaScript 代码交互，但它是 QUIC 协议实现的基础，定义了关键的数据类型和辅助功能，为 QUIC 连接的建立、数据传输和错误处理提供了基础，并为调试和日志记录提供了便利。当用户遇到网络问题，特别是与使用了 QUIC 协议的网站交互时，这个文件中的定义会直接影响到问题的根本原因和调试过程中的信息呈现。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_types.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_types.h"

#include <cstdint>
#include <ostream>
#include <string>
#include <type_traits>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/common/print_elements.h"

namespace quic {

static_assert(sizeof(StatelessResetToken) == kStatelessResetTokenLength,
              "bad size");

std::ostream& operator<<(std::ostream& os, const QuicConsumedData& s) {
  os << "bytes_consumed: " << s.bytes_consumed
     << " fin_consumed: " << s.fin_consumed;
  return os;
}

std::string PerspectiveToString(Perspective perspective) {
  if (perspective == Perspective::IS_SERVER) {
    return "IS_SERVER";
  }
  if (perspective == Perspective::IS_CLIENT) {
    return "IS_CLIENT";
  }
  return absl::StrCat("Unknown(", static_cast<int>(perspective), ")");
}

std::ostream& operator<<(std::ostream& os, const Perspective& perspective) {
  os << PerspectiveToString(perspective);
  return os;
}

std::string ConnectionCloseSourceToString(
    ConnectionCloseSource connection_close_source) {
  if (connection_close_source == ConnectionCloseSource::FROM_PEER) {
    return "FROM_PEER";
  }
  if (connection_close_source == ConnectionCloseSource::FROM_SELF) {
    return "FROM_SELF";
  }
  return absl::StrCat("Unknown(", static_cast<int>(connection_close_source),
                      ")");
}

std::ostream& operator<<(std::ostream& os,
                         const ConnectionCloseSource& connection_close_source) {
  os << ConnectionCloseSourceToString(connection_close_source);
  return os;
}

std::string ConnectionCloseBehaviorToString(
    ConnectionCloseBehavior connection_close_behavior) {
  if (connection_close_behavior == ConnectionCloseBehavior::SILENT_CLOSE) {
    return "SILENT_CLOSE";
  }
  if (connection_close_behavior ==
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET) {
    return "SEND_CONNECTION_CLOSE_PACKET";
  }
  return absl::StrCat("Unknown(", static_cast<int>(connection_close_behavior),
                      ")");
}

std::ostream& operator<<(
    std::ostream& os,
    const ConnectionCloseBehavior& connection_close_behavior) {
  os << ConnectionCloseBehaviorToString(connection_close_behavior);
  return os;
}

std::ostream& operator<<(std::ostream& os, const AckedPacket& acked_packet) {
  os << "{ packet_number: " << acked_packet.packet_number
     << ", bytes_acked: " << acked_packet.bytes_acked << ", receive_timestamp: "
     << acked_packet.receive_timestamp.ToDebuggingValue() << "} ";
  return os;
}

std::ostream& operator<<(std::ostream& os, const LostPacket& lost_packet) {
  os << "{ packet_number: " << lost_packet.packet_number
     << ", bytes_lost: " << lost_packet.bytes_lost << "} ";
  return os;
}

std::string HistogramEnumString(WriteStatus enum_value) {
  switch (enum_value) {
    case WRITE_STATUS_OK:
      return "OK";
    case WRITE_STATUS_BLOCKED:
      return "BLOCKED";
    case WRITE_STATUS_BLOCKED_DATA_BUFFERED:
      return "BLOCKED_DATA_BUFFERED";
    case WRITE_STATUS_ERROR:
      return "ERROR";
    case WRITE_STATUS_MSG_TOO_BIG:
      return "MSG_TOO_BIG";
    case WRITE_STATUS_FAILED_TO_COALESCE_PACKET:
      return "WRITE_STATUS_FAILED_TO_COALESCE_PACKET";
    case WRITE_STATUS_NUM_VALUES:
      return "NUM_VALUES";
  }
  QUIC_DLOG(ERROR) << "Invalid WriteStatus value: "
                   << static_cast<int16_t>(enum_value);
  return "<invalid>";
}

std::ostream& operator<<(std::ostream& os, const WriteStatus& status) {
  os << HistogramEnumString(status);
  return os;
}

std::ostream& operator<<(std::ostream& os, const WriteResult& s) {
  os << "{ status: " << s.status;
  if (s.status == WRITE_STATUS_OK) {
    os << ", bytes_written: " << s.bytes_written;
  } else {
    os << ", error_code: " << s.error_code;
  }
  os << " }";
  return os;
}

MessageResult::MessageResult(MessageStatus status, QuicMessageId message_id)
    : status(status), message_id(message_id) {}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x;

std::string QuicFrameTypeToString(QuicFrameType t) {
  switch (t) {
    RETURN_STRING_LITERAL(PADDING_FRAME)
    RETURN_STRING_LITERAL(RST_STREAM_FRAME)
    RETURN_STRING_LITERAL(CONNECTION_CLOSE_FRAME)
    RETURN_STRING_LITERAL(GOAWAY_FRAME)
    RETURN_STRING_LITERAL(WINDOW_UPDATE_FRAME)
    RETURN_STRING_LITERAL(BLOCKED_FRAME)
    RETURN_STRING_LITERAL(STOP_WAITING_FRAME)
    RETURN_STRING_LITERAL(PING_FRAME)
    RETURN_STRING_LITERAL(CRYPTO_FRAME)
    RETURN_STRING_LITERAL(HANDSHAKE_DONE_FRAME)
    RETURN_STRING_LITERAL(STREAM_FRAME)
    RETURN_STRING_LITERAL(ACK_FRAME)
    RETURN_STRING_LITERAL(MTU_DISCOVERY_FRAME)
    RETURN_STRING_LITERAL(NEW_CONNECTION_ID_FRAME)
    RETURN_STRING_LITERAL(MAX_STREAMS_FRAME)
    RETURN_STRING_LITERAL(STREAMS_BLOCKED_FRAME)
    RETURN_STRING_LITERAL(PATH_RESPONSE_FRAME)
    RETURN_STRING_LITERAL(PATH_CHALLENGE_FRAME)
    RETURN_STRING_LITERAL(STOP_SENDING_FRAME)
    RETURN_STRING_LITERAL(MESSAGE_FRAME)
    RETURN_STRING_LITERAL(NEW_TOKEN_FRAME)
    RETURN_STRING_LITERAL(RETIRE_CONNECTION_ID_FRAME)
    RETURN_STRING_LITERAL(ACK_FREQUENCY_FRAME)
    RETURN_STRING_LITERAL(RESET_STREAM_AT_FRAME)
    RETURN_STRING_LITERAL(NUM_FRAME_TYPES)
  }
  return absl::StrCat("Unknown(", static_cast<int>(t), ")");
}

std::ostream& operator<<(std::ostream& os, const QuicFrameType& t) {
  os << QuicFrameTypeToString(t);
  return os;
}

std::string QuicIetfFrameTypeString(QuicIetfFrameType t) {
  if (IS_IETF_STREAM_FRAME(t)) {
    return "IETF_STREAM";
  }

  switch (t) {
    RETURN_STRING_LITERAL(IETF_PADDING);
    RETURN_STRING_LITERAL(IETF_PING);
    RETURN_STRING_LITERAL(IETF_ACK);
    RETURN_STRING_LITERAL(IETF_ACK_ECN);
    RETURN_STRING_LITERAL(IETF_RST_STREAM);
    RETURN_STRING_LITERAL(IETF_STOP_SENDING);
    RETURN_STRING_LITERAL(IETF_CRYPTO);
    RETURN_STRING_LITERAL(IETF_NEW_TOKEN);
    RETURN_STRING_LITERAL(IETF_MAX_DATA);
    RETURN_STRING_LITERAL(IETF_MAX_STREAM_DATA);
    RETURN_STRING_LITERAL(IETF_MAX_STREAMS_BIDIRECTIONAL);
    RETURN_STRING_LITERAL(IETF_MAX_STREAMS_UNIDIRECTIONAL);
    RETURN_STRING_LITERAL(IETF_DATA_BLOCKED);
    RETURN_STRING_LITERAL(IETF_STREAM_DATA_BLOCKED);
    RETURN_STRING_LITERAL(IETF_STREAMS_BLOCKED_BIDIRECTIONAL);
    RETURN_STRING_LITERAL(IETF_STREAMS_BLOCKED_UNIDIRECTIONAL);
    RETURN_STRING_LITERAL(IETF_NEW_CONNECTION_ID);
    RETURN_STRING_LITERAL(IETF_RETIRE_CONNECTION_ID);
    RETURN_STRING_LITERAL(IETF_PATH_CHALLENGE);
    RETURN_STRING_LITERAL(IETF_PATH_RESPONSE);
    RETURN_STRING_LITERAL(IETF_CONNECTION_CLOSE);
    RETURN_STRING_LITERAL(IETF_APPLICATION_CLOSE);
    RETURN_STRING_LITERAL(IETF_EXTENSION_MESSAGE_NO_LENGTH);
    RETURN_STRING_LITERAL(IETF_EXTENSION_MESSAGE);
    RETURN_STRING_LITERAL(IETF_EXTENSION_MESSAGE_NO_LENGTH_V99);
    RETURN_STRING_LITERAL(IETF_EXTENSION_MESSAGE_V99);
    default:
      return absl::StrCat("Private value (", t, ")");
  }
}
std::ostream& operator<<(std::ostream& os, const QuicIetfFrameType& c) {
  os << QuicIetfFrameTypeString(c);
  return os;
}

std::string TransmissionTypeToString(TransmissionType transmission_type) {
  switch (transmission_type) {
    RETURN_STRING_LITERAL(NOT_RETRANSMISSION);
    RETURN_STRING_LITERAL(HANDSHAKE_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_ZERO_RTT_RETRANSMISSION);
    RETURN_STRING_LITERAL(LOSS_RETRANSMISSION);
    RETURN_STRING_LITERAL(PTO_RETRANSMISSION);
    RETURN_STRING_LITERAL(PATH_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_INITIAL_RETRANSMISSION);
    default:
      // Some varz rely on this behavior for statistic collection.
      if (transmission_type == LAST_TRANSMISSION_TYPE + 1) {
        return "INVALID_TRANSMISSION_TYPE";
      }
      return absl::StrCat("Unknown(", static_cast<int>(transmission_type), ")");
  }
}

std::ostream& operator<<(std::ostream& os, TransmissionType transmission_type) {
  os << TransmissionTypeToString(transmission_type);
  return os;
}

std::string PacketHeaderFormatToString(PacketHeaderFormat format) {
  switch (format) {
    RETURN_STRING_LITERAL(IETF_QUIC_LONG_HEADER_PACKET);
    RETURN_STRING_LITERAL(IETF_QUIC_SHORT_HEADER_PACKET);
    RETURN_STRING_LITERAL(GOOGLE_QUIC_PACKET);
    default:
      return absl::StrCat("Unknown (", static_cast<int>(format), ")");
  }
}

std::string QuicLongHeaderTypeToString(QuicLongHeaderType type) {
  switch (type) {
    RETURN_STRING_LITERAL(VERSION_NEGOTIATION);
    RETURN_STRING_LITERAL(INITIAL);
    RETURN_STRING_LITERAL(ZERO_RTT_PROTECTED);
    RETURN_STRING_LITERAL(HANDSHAKE);
    RETURN_STRING_LITERAL(RETRY);
    RETURN_STRING_LITERAL(INVALID_PACKET_TYPE);
    default:
      return absl::StrCat("Unknown (", static_cast<int>(type), ")");
  }
}

std::string MessageStatusToString(MessageStatus message_status) {
  switch (message_status) {
    RETURN_STRING_LITERAL(MESSAGE_STATUS_SUCCESS);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_ENCRYPTION_NOT_ESTABLISHED);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_UNSUPPORTED);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_BLOCKED);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_TOO_LARGE);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_SETTINGS_NOT_RECEIVED);
    RETURN_STRING_LITERAL(MESSAGE_STATUS_INTERNAL_ERROR);
    default:
      return absl::StrCat("Unknown(", static_cast<int>(message_status), ")");
  }
}

std::string MessageResultToString(MessageResult message_result) {
  if (message_result.status != MESSAGE_STATUS_SUCCESS) {
    return absl::StrCat("{", MessageStatusToString(message_result.status), "}");
  }
  return absl::StrCat("{MESSAGE_STATUS_SUCCESS,id=", message_result.message_id,
                      "}");
}

std::ostream& operator<<(std::ostream& os, const MessageResult& mr) {
  os << MessageResultToString(mr);
  return os;
}

std::string PacketNumberSpaceToString(PacketNumberSpace packet_number_space) {
  switch (packet_number_space) {
    RETURN_STRING_LITERAL(INITIAL_DATA);
    RETURN_STRING_LITERAL(HANDSHAKE_DATA);
    RETURN_STRING_LITERAL(APPLICATION_DATA);
    default:
      return absl::StrCat("Unknown(", static_cast<int>(packet_number_space),
                          ")");
  }
}

std::string SerializedPacketFateToString(SerializedPacketFate fate) {
  switch (fate) {
    RETURN_STRING_LITERAL(DISCARD);
    RETURN_STRING_LITERAL(COALESCE);
    RETURN_STRING_LITERAL(BUFFER);
    RETURN_STRING_LITERAL(SEND_TO_WRITER);
  }
  return absl::StrCat("Unknown(", static_cast<int>(fate), ")");
}

std::ostream& operator<<(std::ostream& os, SerializedPacketFate fate) {
  os << SerializedPacketFateToString(fate);
  return os;
}

std::string CongestionControlTypeToString(CongestionControlType cc_type) {
  switch (cc_type) {
    case kCubicBytes:
      return "CUBIC_BYTES";
    case kRenoBytes:
      return "RENO_BYTES";
    case kBBR:
      return "BBR";
    case kBBRv2:
      return "BBRv2";
    case kPCC:
      return "PCC";
    case kGoogCC:
      return "GoogCC";
    case kPragueCubic:
      return "PRAGUE_CUBIC";
  }
  return absl::StrCat("Unknown(", static_cast<int>(cc_type), ")");
}

std::string EncryptionLevelToString(EncryptionLevel level) {
  switch (level) {
    RETURN_STRING_LITERAL(ENCRYPTION_INITIAL);
    RETURN_STRING_LITERAL(ENCRYPTION_HANDSHAKE);
    RETURN_STRING_LITERAL(ENCRYPTION_ZERO_RTT);
    RETURN_STRING_LITERAL(ENCRYPTION_FORWARD_SECURE);
    default:
      return absl::StrCat("Unknown(", static_cast<int>(level), ")");
  }
}

std::ostream& operator<<(std::ostream& os, EncryptionLevel level) {
  os << EncryptionLevelToString(level);
  return os;
}

absl::string_view ClientCertModeToString(ClientCertMode mode) {
#define RETURN_REASON_LITERAL(x) \
  case ClientCertMode::x:        \
    return #x
  switch (mode) {
    RETURN_REASON_LITERAL(kNone);
    RETURN_REASON_LITERAL(kRequest);
    RETURN_REASON_LITERAL(kRequire);
    default:
      return "<invalid>";
  }
#undef RETURN_REASON_LITERAL
}

std::ostream& operator<<(std::ostream& os, ClientCertMode mode) {
  os << ClientCertModeToString(mode);
  return os;
}

std::string QuicConnectionCloseTypeString(QuicConnectionCloseType type) {
  switch (type) {
    RETURN_STRING_LITERAL(GOOGLE_QUIC_CONNECTION_CLOSE);
    RETURN_STRING_LITERAL(IETF_QUIC_TRANSPORT_CONNECTION_CLOSE);
    RETURN_STRING_LITERAL(IETF_QUIC_APPLICATION_CONNECTION_CLOSE);
    default:
      return absl::StrCat("Unknown(", static_cast<int>(type), ")");
  }
}

std::ostream& operator<<(std::ostream& os, const QuicConnectionCloseType type) {
  os << QuicConnectionCloseTypeString(type);
  return os;
}

std::string AddressChangeTypeToString(AddressChangeType type) {
  using IntType = typename std::underlying_type<AddressChangeType>::type;
  switch (type) {
    RETURN_STRING_LITERAL(NO_CHANGE);
    RETURN_STRING_LITERAL(PORT_CHANGE);
    RETURN_STRING_LITERAL(IPV4_SUBNET_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV4_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV6_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV4_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV6_CHANGE);
    default:
      return absl::StrCat("Unknown(", static_cast<IntType>(type), ")");
  }
}

std::ostream& operator<<(std::ostream& os, AddressChangeType type) {
  os << AddressChangeTypeToString(type);
  return os;
}

std::string KeyUpdateReasonString(KeyUpdateReason reason) {
#define RETURN_REASON_LITERAL(x) \
  case KeyUpdateReason::x:       \
    return #x
  switch (reason) {
    RETURN_REASON_LITERAL(kInvalid);
    RETURN_REASON_LITERAL(kRemote);
    RETURN_REASON_LITERAL(kLocalForTests);
    RETURN_REASON_LITERAL(kLocalForInteropRunner);
    RETURN_REASON_LITERAL(kLocalAeadConfidentialityLimit);
    RETURN_REASON_LITERAL(kLocalKeyUpdateLimitOverride);
    default:
      return absl::StrCat("Unknown(", static_cast<int>(reason), ")");
  }
#undef RETURN_REASON_LITERAL
}

std::ostream& operator<<(std::ostream& os, const KeyUpdateReason reason) {
  os << KeyUpdateReasonString(reason);
  return os;
}

std::string ParsedClientHello::ToString() const {
  std::ostringstream oss;
  oss << *this;
  return oss.str();
}

bool operator==(const ParsedClientHello& a, const ParsedClientHello& b) {
  return a.sni == b.sni && a.uaid == b.uaid &&
         a.supported_groups == b.supported_groups &&
         a.cert_compression_algos == b.cert_compression_algos &&
         a.alpns == b.alpns && a.retry_token == b.retry_token &&
         a.resumption_attempted == b.resumption_attempted &&
         a.early_data_attempted == b.early_data_attempted;
}

std::ostream& operator<<(std::ostream& os,
                         const ParsedClientHello& parsed_chlo) {
  os << "{ sni:" << parsed_chlo.sni << ", uaid:" << parsed_chlo.uaid
     << ", alpns:" << quiche::PrintElements(parsed_chlo.alpns)
     << ", supported_groups:"
     << quiche::PrintElements(parsed_chlo.supported_groups)
     << ", cert_compression_algos:"
     << quiche::PrintElements(parsed_chlo.cert_compression_algos)
     << ", resumption_attempted:" << parsed_chlo.resumption_attempted
     << ", early_data_attempted:" << parsed_chlo.early_data_attempted
     << ", len(retry_token):" << parsed_chlo.retry_token.size() << " }";
  return os;
}

QUICHE_EXPORT std::string QuicPriorityTypeToString(QuicPriorityType type) {
  switch (type) {
    case quic::QuicPriorityType::kHttp:
      return "HTTP (RFC 9218)";
    case quic::QuicPriorityType::kWebTransport:
      return "WebTransport (W3C API)";
  }
  return "(unknown)";
}
QUICHE_EXPORT std::ostream& operator<<(std::ostream& os,
                                       QuicPriorityType type) {
  os << QuicPriorityTypeToString(type);
  return os;
}

std::string EcnCodepointToString(QuicEcnCodepoint ecn) {
  switch (ecn) {
    case ECN_NOT_ECT:
      return "Not-ECT";
    case ECN_ECT0:
      return "ECT(0)";
    case ECN_ECT1:
      return "ECT(1)";
    case ECN_CE:
      return "CE";
  }
  return "";  // Handle compilation on windows for invalid enums
}

bool operator==(const QuicSSLConfig& lhs, const QuicSSLConfig& rhs) {
  return lhs.early_data_enabled == rhs.early_data_enabled &&
         lhs.disable_ticket_support == rhs.disable_ticket_support &&
         lhs.signing_algorithm_prefs == rhs.signing_algorithm_prefs &&
         lhs.client_cert_mode == rhs.client_cert_mode &&
         lhs.ech_config_list == rhs.ech_config_list &&
         lhs.ech_grease_enabled == rhs.ech_grease_enabled;
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds

}  // namespace quic

"""

```