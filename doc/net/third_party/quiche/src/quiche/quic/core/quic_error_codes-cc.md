Response:
The user wants to understand the functionality of the C++ source code file `quic_error_codes.cc` in the Chromium network stack.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name `quic_error_codes.cc` strongly suggests that it's responsible for defining and managing error codes within the QUIC protocol implementation.

2. **Analyze the code structure:**
    * **Includes:**  The included headers (`<cstdint>`, `<cstring>`, `<ostream>`, `<string>`, `absl/strings/str_cat.h`, `openssl/ssl.h`, `quiche/quic/platform/api/quic_logging.h`) indicate the file's dependencies. Notably, `openssl/ssl.h` hints at interaction with TLS/SSL error codes, and `absl/strings/str_cat.h` suggests string manipulation.
    * **Namespaces:** The code is within the `quic` namespace, confirming its role within the QUIC library.
    * **Macros:** The `RETURN_STRING_LITERAL` macro is a code simplification for returning string representations of enum values.
    * **Functions:** The file contains multiple functions: `QuicRstStreamErrorCodeToString`, `QuicErrorCodeToString`, `QuicIetfTransportErrorCodeString`, the overloaded `operator<<` for `QuicIetfTransportErrorCodes`, and `QuicErrorCodeToTransportErrorCode`. This structure suggests the file provides ways to convert error codes to human-readable strings and to map between different error code sets.

3. **Examine each function's role:**
    * `QuicRstStreamErrorCodeToString`:  This function takes a `QuicRstStreamErrorCode` enum value as input and returns its string representation. These error codes are specific to stream resets within QUIC.
    * `QuicErrorCodeToString`: Similar to the previous function, but it handles general `QuicErrorCode` values, covering a broader range of QUIC connection errors.
    * `QuicIetfTransportErrorCodeString`: This function deals with IETF QUIC transport error codes. It includes special handling for `CRYPTO_ERROR_FIRST` and `CRYPTO_ERROR_LAST`, which map to TLS/SSL alert descriptions. This confirms the connection to lower-level security protocols.
    * `operator<<`: This overloaded operator allows `QuicIetfTransportErrorCodes` to be directly printed to an output stream (like `std::cout`).
    * `QuicErrorCodeToTransportErrorCode`: This function is crucial. It takes a Chromium QUIC error code (`QuicErrorCode`) and attempts to map it to an IETF QUIC transport error code. The return type `QuicErrorCodeToIetfMapping` (likely a struct containing a boolean and an integer) suggests that not all Chromium error codes have a direct IETF equivalent.

4. **Address the specific questions in the prompt:**
    * **Functionality:**  The primary function is to provide string representations for various QUIC error codes and facilitate mapping between different error code sets (Chromium's internal and IETF's).
    * **Relationship to JavaScript:**  QUIC is a transport protocol, and JavaScript running in a browser interacts with it indirectly via browser APIs (like `fetch` or WebSockets). If a QUIC connection encounters an error, the browser might expose a generic network error in JavaScript. It's unlikely that JavaScript will directly see these specific `QuicErrorCode` values. Example: A `fetch` request might fail with a generic network error in JavaScript if the QUIC connection experienced a `QUIC_HANDSHAKE_FAILED` error.
    * **Logic and Input/Output:** The functions mainly use switch statements for mapping.
        * **Assumption:** Input is a valid enum value.
        * **Input (Example):** `QUIC_STREAM_CANCELLED` for `QuicRstStreamErrorCodeToString`.
        * **Output (Example):** `"QUIC_STREAM_CANCELLED"`.
        * **Input (Example):** `QUIC_PACKET_TOO_LARGE` for `QuicErrorCodeToString`.
        * **Output (Example):** `"QUIC_PACKET_TOO_LARGE"`.
        * **Input (Example):** `INTERNAL_ERROR` for `QuicIetfTransportErrorCodeString`.
        * **Output (Example):** `"INTERNAL_ERROR"`.
        * **Input (Example):** `QUIC_HANDSHAKE_FAILED` for `QuicErrorCodeToTransportErrorCode`.
        * **Output (Example):** `{true, static_cast<uint64_t>(PROTOCOL_VIOLATION)}`.
    * **User/Programming Errors:** Incorrectly handling or interpreting these error codes in higher-level code could lead to issues. For example, a server might not properly respond to a `QUIC_REFUSED_STREAM` error, leading to retries or unexpected behavior.
    * **User Operation and Debugging:**  A user action (like clicking a link) triggers a network request. If the QUIC connection fails, this code might be involved in generating error messages logged by the browser or server. A developer debugging a network issue could look at these logs to understand the specific QUIC error that occurred.
    * **Summary of Functionality (for Part 1):**  The code defines and provides string representations for QUIC stream reset error codes and general QUIC connection error codes. It also includes functions for handling and converting IETF QUIC transport error codes.

5. **Structure the answer:** Organize the information logically, addressing each point in the user's request clearly and concisely. Use examples to illustrate the concepts. Clearly label the "Summary of Functionality" as requested for part 1.
这是 Chromium 网络栈中 QUIC 协议核心库的一个源代码文件，它的主要功能是**定义和管理 QUIC 协议中使用的各种错误码，并将这些错误码转换为人类可读的字符串形式**。 这有助于调试和错误处理。

以下是更详细的功能说明：

**1. 定义 QUIC 流重置错误码 (QuicRstStreamErrorCode):**

* 文件中定义了一个枚举类型 `QuicRstStreamErrorCode`，包含了在 QUIC 流被重置时可能出现的各种错误情况。
* `RETURN_STRING_LITERAL` 宏简化了将枚举值转换为对应字符串的过程。
* `QuicRstStreamErrorCodeToString` 函数接收一个 `QuicRstStreamErrorCode` 枚举值作为输入，并返回其对应的字符串表示。

**2. 定义 QUIC 连接错误码 (QuicErrorCode):**

* 类似地，定义了一个枚举类型 `QuicErrorCode`，包含了 QUIC 连接过程中可能发生的各种错误。
* `QuicErrorCodeToString` 函数接收一个 `QuicErrorCode` 枚举值，并返回其字符串表示。

**3. 定义 IETF QUIC 传输层错误码 (QuicIetfTransportErrorCodes):**

* 定义了 `QuicIetfTransportErrorCodes` 枚举，用于表示 IETF 标准中定义的 QUIC 传输层错误码。
* `QuicIetfTransportErrorCodeString` 函数将 `QuicIetfTransportErrorCodes` 枚举值转换为字符串。
* 该函数特殊处理了 `CRYPTO_ERROR_FIRST` 和 `CRYPTO_ERROR_LAST` 范围内的错误码，将它们映射到 OpenSSL 库中的 TLS 警报描述。

**4. 提供将 Chromium QUIC 错误码映射到 IETF QUIC 传输层错误码的功能:**

* `QuicErrorCodeToTransportErrorCode` 函数接收一个 Chromium 的 `QuicErrorCode` 枚举值，并尝试将其映射到对应的 IETF `QuicIetfTransportErrorCodes`。
* 返回值 `QuicErrorCodeToIetfMapping`  可能包含一个布尔值，指示是否成功映射，以及映射后的 IETF 错误码。 这说明并非所有的 Chromium 错误码都有直接对应的 IETF 标准错误码。

**与 JavaScript 的关系：**

该 C++ 文件本身不直接与 JavaScript 代码交互。 然而，它定义的错误码在浏览器内部处理 QUIC 连接时会被使用。 当 JavaScript 通过浏览器 API (例如 `fetch` 或 WebSocket) 发起网络请求时，如果底层的 QUIC 连接遇到错误，这些错误码可能会被记录下来，或者最终导致浏览器抛出一个通用的网络错误给 JavaScript。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向服务器发送请求。如果服务器由于某种原因拒绝建立 QUIC 连接，QUIC 层可能会返回一个 `QUIC_HANDSHAKE_FAILED` 错误。  虽然 JavaScript 代码不会直接看到 `QUIC_HANDSHAKE_FAILED`，但 `fetch` 操作可能会失败，并抛出一个 `TypeError: Failed to fetch` 类型的错误。开发者可以通过浏览器的开发者工具中的 "Network" 标签查看更详细的错误信息，其中可能包含与 QUIC 相关的错误指示。

**逻辑推理，假设输入与输出:**

* **假设输入 (QuicRstStreamErrorCodeToString):** `QUIC_STREAM_CANCELLED`
* **输出:** `"QUIC_STREAM_CANCELLED"`

* **假设输入 (QuicErrorCodeToString):** `QUIC_PACKET_TOO_LARGE`
* **输出:** `"QUIC_PACKET_TOO_LARGE"`

* **假设输入 (QuicIetfTransportErrorCodeString):** `INTERNAL_ERROR`
* **输出:** `"INTERNAL_ERROR"`

* **假设输入 (QuicIetfTransportErrorCodeString):**  一个在 `CRYPTO_ERROR_FIRST` 和 `CRYPTO_ERROR_LAST` 之间的值，例如对应 `SSL_AD_BAD_CERTIFICATE` 的值。
* **输出:**  类似于 `"CRYPTO_ERROR(Bad certificate)"` 或 `"CRYPTO_ERROR(unknown(数值))"`

* **假设输入 (QuicErrorCodeToTransportErrorCode):** `QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA`
* **输出:** `{true, 3}`  (假设 `FLOW_CONTROL_ERROR` 在 `QuicIetfTransportErrorCodes` 中对应的值是 3)

* **假设输入 (QuicErrorCodeToTransportErrorCode):**  一个没有对应 IETF 错误码的 `QuicErrorCode`，例如 `QUIC_HTTP_DECODER_ERROR`。
* **输出:** `{false,  一个数值}` (数值可能不重要，重要的是布尔值是 false)

**用户或编程常见的使用错误:**

* **编程错误:** 开发者在处理 QUIC 连接错误时，可能会错误地假设所有的 Chromium `QuicErrorCode` 都有直接对应的 IETF `QuicIetfTransportErrorCodes`。 使用 `QuicErrorCodeToTransportErrorCode` 的返回值时，应该检查映射是否成功 (布尔值是否为 true)。
* **用户错误导致的编程错误:**  用户网络环境不稳定可能导致 QUIC 连接断开，产生例如 `QUIC_NETWORK_IDLE_TIMEOUT` 或 `QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK` 等错误。  开发者可能没有充分考虑到这些网络环境因素，导致应用程序在这些情况下处理不当。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网站或进行网络操作，该网站或操作使用了 QUIC 协议。**  例如，用户在 Chrome 浏览器中打开一个支持 HTTP/3 (基于 QUIC) 的网站。
2. **在 QUIC 连接建立或数据传输过程中，发生了一个错误。**  例如，服务器突然关闭连接，或者网络连接中断。
3. **QUIC 协议栈检测到错误，并设置相应的 `QuicErrorCode` 或 `QuicRstStreamErrorCode`。**  例如，如果服务器发送了一个 RST_STREAM 帧，则会设置 `QUIC_STREAM_CANCELLED`。
4. **QUIC 协议栈的某些部分需要将这个错误码转换为字符串进行日志记录或错误报告。** 这时就会调用 `QuicErrorCodeToString` 或 `QuicRstStreamErrorCodeToString`。
5. **如果需要将 Chromium 的错误码转换为 IETF 标准的错误码，则会调用 `QuicErrorCodeToTransportErrorCode`。** 这在与外部系统或标准进行交互时可能发生。

**调试线索:** 当开发者在调试 QUIC 相关问题时，他们可能会：

* **查看浏览器或服务器的 QUIC 日志。** 这些日志中会包含通过 `QuicErrorCodeToString` 等函数转换后的错误码字符串，帮助开发者了解错误的具体原因。
* **使用网络抓包工具 (例如 Wireshark) 分析 QUIC 数据包。**  如果连接关闭，可能会看到包含错误码的 CONNECTION_CLOSE 帧或 RST_STREAM 帧。  这些帧中的数值可以与这里定义的枚举值进行比对。
* **在 QUIC 协议栈的源代码中设置断点。**  开发者可以在 `QuicErrorCodeToString` 等函数中设置断点，来观察在特定错误发生时，哪个错误码被设置，以及如何被处理。

**这是第1部分，共2部分，请归纳一下它的功能:**

总而言之，这个 C++ 源代码文件 `quic_error_codes.cc` 的主要功能是 **集中定义和管理 Chromium QUIC 协议中使用的各种错误码，并提供将其转换为人类可读字符串以及映射到 IETF QUIC 传输层错误码的功能**。 这对于 QUIC 协议的内部运作、错误处理、日志记录和调试至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_error_codes.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_error_codes.h"

#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>

#include "absl/strings/str_cat.h"
#include "openssl/ssl.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x;

const char* QuicRstStreamErrorCodeToString(QuicRstStreamErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_STREAM_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_ERROR_PROCESSING_STREAM);
    RETURN_STRING_LITERAL(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    RETURN_STRING_LITERAL(QUIC_BAD_APPLICATION_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_STREAM_CONNECTION_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_STREAM_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_RST_ACKNOWLEDGEMENT);
    RETURN_STRING_LITERAL(QUIC_REFUSED_STREAM);
    RETURN_STRING_LITERAL(QUIC_INVALID_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_UNAUTHORIZED_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_DUPLICATE_PROMISE_URL);
    RETURN_STRING_LITERAL(QUIC_PROMISE_VARY_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_INVALID_PROMISE_METHOD);
    RETURN_STRING_LITERAL(QUIC_PUSH_STREAM_TIMED_OUT);
    RETURN_STRING_LITERAL(QUIC_HEADERS_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_STREAM_TTL_EXPIRED);
    RETURN_STRING_LITERAL(QUIC_DATA_AFTER_CLOSE_OFFSET);
    RETURN_STRING_LITERAL(QUIC_STREAM_GENERAL_PROTOCOL_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_STREAM_CREATION_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_CLOSED_CRITICAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_STREAM_FRAME_UNEXPECTED);
    RETURN_STRING_LITERAL(QUIC_STREAM_FRAME_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_EXCESSIVE_LOAD);
    RETURN_STRING_LITERAL(QUIC_STREAM_ID_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_SETTINGS_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_MISSING_SETTINGS);
    RETURN_STRING_LITERAL(QUIC_STREAM_REQUEST_REJECTED);
    RETURN_STRING_LITERAL(QUIC_STREAM_REQUEST_INCOMPLETE);
    RETURN_STRING_LITERAL(QUIC_STREAM_CONNECT_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_VERSION_FALLBACK);
    RETURN_STRING_LITERAL(QUIC_STREAM_DECOMPRESSION_FAILED);
    RETURN_STRING_LITERAL(QUIC_STREAM_ENCODER_STREAM_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_DECODER_STREAM_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_UNKNOWN_APPLICATION_ERROR_CODE);
    RETURN_STRING_LITERAL(QUIC_STREAM_WEBTRANSPORT_SESSION_GONE);
    RETURN_STRING_LITERAL(
        QUIC_STREAM_WEBTRANSPORT_BUFFERED_STREAMS_LIMIT_EXCEEDED);
    RETURN_STRING_LITERAL(QUIC_APPLICATION_DONE_WITH_STREAM);
    RETURN_STRING_LITERAL(QUIC_STREAM_LAST_ERROR);
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicRstStreamErrorCodes. This can happen when the RstStream
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_RST_STREAM_ERROR_CODE";
}

const char* QuicErrorCodeToString(QuicErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_DATA_AFTER_TERMINATION);
    RETURN_STRING_LITERAL(QUIC_INVALID_PACKET_HEADER);
    RETURN_STRING_LITERAL(QUIC_INVALID_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_MISSING_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_INVALID_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_OVERLAPPING_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_UNENCRYPTED_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_RST_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_CONNECTION_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_GOAWAY_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_WINDOW_UPDATE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STOP_WAITING_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_ACK_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    RETURN_STRING_LITERAL(QUIC_INVALID_PUBLIC_RST_PACKET);
    RETURN_STRING_LITERAL(QUIC_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_ENCRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_PACKET_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_PACKETS_BUFFERED_TOO_LONG);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_INVALID_HOSTNAME);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_REJECTING_ALL_CONNECTIONS);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_INVALID_CONNECTION);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED_CID_COLLISION);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TAGS_OUT_OF_ORDER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_ENTRIES);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_REJECTS);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INVALID_VALUE_LENGTH)
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_VERSION_NOT_SUPPORTED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_NO_SUPPORT);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_TYPE);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_UNSUPPORTED_PROOF_DEMAND);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_PRIORITY);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OPEN_STREAMS);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESET);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION);
    RETURN_STRING_LITERAL(QUIC_PACKET_WRONG_VERSION);
    RETURN_STRING_LITERAL(QUIC_INVALID_0RTT_PACKET_NUMBER_OUT_OF_ORDER);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADER_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEGOTIATED_VALUE);
    RETURN_STRING_LITERAL(QUIC_DECOMPRESSION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_NETWORK_IDLE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_ERROR_MIGRATING_ADDRESS);
    RETURN_STRING_LITERAL(QUIC_ERROR_MIGRATING_PORT);
    RETURN_STRING_LITERAL(QUIC_PACKET_WRITE_ERROR);
    RETURN_STRING_LITERAL(QUIC_PACKET_READ_ERROR);
    RETURN_STRING_LITERAL(QUIC_EMPTY_STREAM_FRAME_NO_FIN);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADERS_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_INVALID_WINDOW);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_IP_POOLED);
    RETURN_STRING_LITERAL(QUIC_PROOF_INVALID);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_DUPLICATE_TAG);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SERVER_CONFIG_EXPIRED);
    RETURN_STRING_LITERAL(QUIC_INVALID_CHANNEL_ID_SIGNATURE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_VERSION_NEGOTIATION_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_BAD_PACKET_LOSS_RATE);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESETS_POST_HANDSHAKE);
    RETURN_STRING_LITERAL(QUIC_FAILED_TO_SERIALIZE_PACKET);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_AVAILABLE_STREAMS);
    RETURN_STRING_LITERAL(QUIC_UNENCRYPTED_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_BAD_MULTIPATH_FLAG);
    RETURN_STRING_LITERAL(QUIC_IP_ADDRESS_CHANGED);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_RTOS);
    RETURN_STRING_LITERAL(QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_MAYBE_CORRUPTED_MEMORY);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_CHLO_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_MULTIPATH_PATH_DOES_NOT_EXIST);
    RETURN_STRING_LITERAL(QUIC_MULTIPATH_PATH_NOT_ACTIVE);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_STREAM_DATA_INTERVALS);
    RETURN_STRING_LITERAL(QUIC_STREAM_SEQUENCER_INVALID_STATE);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_SESSIONS_ON_SERVER);
    RETURN_STRING_LITERAL(QUIC_STREAM_LENGTH_OVERFLOW);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_INVALID_MAX_DATA_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_MAX_STREAM_DATA_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_MAX_STREAMS_DATA);
    RETURN_STRING_LITERAL(QUIC_STREAMS_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEW_CONNECTION_ID_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_RETIRE_CONNECTION_ID_DATA);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_ID_LIMIT_ERROR);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_CONNECTION_ID_WAITING_TO_RETIRE);
    RETURN_STRING_LITERAL(QUIC_INVALID_STOP_SENDING_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_CHALLENGE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_PATH_RESPONSE_DATA);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED);
    RETURN_STRING_LITERAL(QUIC_PEER_PORT_CHANGE_HANDSHAKE_UNCONFIRMED);
    RETURN_STRING_LITERAL(QUIC_INVALID_MESSAGE_DATA);
    RETURN_STRING_LITERAL(IETF_QUIC_PROTOCOL_VIOLATION);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEW_TOKEN);
    RETURN_STRING_LITERAL(QUIC_DATA_RECEIVED_ON_WRITE_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_STREAMS_BLOCKED_ERROR);
    RETURN_STRING_LITERAL(QUIC_MAX_STREAMS_ERROR);
    RETURN_STRING_LITERAL(QUIC_HTTP_DECODER_ERROR);
    RETURN_STRING_LITERAL(QUIC_STALE_CONNECTION_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_IETF_GQUIC_ERROR_MISSING);
    RETURN_STRING_LITERAL(
        QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_BUFFERED_CONTROL_FRAMES);
    RETURN_STRING_LITERAL(QUIC_TRANSPORT_INVALID_CLIENT_INDICATION);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECOMPRESSION_FAILED);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_ERROR);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_ERROR);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_INTEGER_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_STRING_LITERAL_TOO_LONG);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_HUFFMAN_ENCODING_ERROR);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_INVALID_STATIC_ENTRY);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_STATIC);
    RETURN_STRING_LITERAL(
        QUIC_QPACK_ENCODER_STREAM_INSERTION_INVALID_RELATIVE_INDEX);
    RETURN_STRING_LITERAL(
        QUIC_QPACK_ENCODER_STREAM_INSERTION_DYNAMIC_ENTRY_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_DYNAMIC);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_LITERAL);
    RETURN_STRING_LITERAL(
        QUIC_QPACK_ENCODER_STREAM_DUPLICATE_INVALID_RELATIVE_INDEX);
    RETURN_STRING_LITERAL(
        QUIC_QPACK_ENCODER_STREAM_DUPLICATE_DYNAMIC_ENTRY_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_QPACK_ENCODER_STREAM_SET_DYNAMIC_TABLE_CAPACITY);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_INTEGER_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_INVALID_ZERO_INCREMENT);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_INCREMENT_OVERFLOW);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_IMPOSSIBLE_INSERT_COUNT);
    RETURN_STRING_LITERAL(QUIC_QPACK_DECODER_STREAM_INCORRECT_ACKNOWLEDGEMENT);
    RETURN_STRING_LITERAL(QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET);
    RETURN_STRING_LITERAL(QUIC_STREAM_MULTIPLE_OFFSET);
    RETURN_STRING_LITERAL(QUIC_HTTP_FRAME_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_HTTP_FRAME_ERROR);
    RETURN_STRING_LITERAL(QUIC_HTTP_FRAME_UNEXPECTED_ON_SPDY_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_SERVER_INITIATED_BIDIRECTIONAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_STREAM_WRONG_DIRECTION);
    RETURN_STRING_LITERAL(QUIC_HTTP_CLOSED_CRITICAL_STREAM);
    RETURN_STRING_LITERAL(QUIC_HTTP_MISSING_SETTINGS_FRAME);
    RETURN_STRING_LITERAL(QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER);
    RETURN_STRING_LITERAL(QUIC_HTTP_INVALID_MAX_PUSH_ID);
    RETURN_STRING_LITERAL(QUIC_HTTP_STREAM_LIMIT_TOO_LOW);
    RETURN_STRING_LITERAL(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_HTTP_GOAWAY_INVALID_STREAM_ID);
    RETURN_STRING_LITERAL(QUIC_HTTP_GOAWAY_ID_LARGER_THAN_PREVIOUS);
    RETURN_STRING_LITERAL(QUIC_HTTP_RECEIVE_SPDY_SETTING);
    RETURN_STRING_LITERAL(QUIC_HTTP_RECEIVE_SPDY_FRAME);
    RETURN_STRING_LITERAL(QUIC_HTTP_RECEIVE_SERVER_PUSH);
    RETURN_STRING_LITERAL(QUIC_HTTP_INVALID_SETTING_VALUE);
    RETURN_STRING_LITERAL(QUIC_HPACK_INDEX_VARINT_ERROR);
    RETURN_STRING_LITERAL(QUIC_HPACK_NAME_LENGTH_VARINT_ERROR);
    RETURN_STRING_LITERAL(QUIC_HPACK_VALUE_LENGTH_VARINT_ERROR);
    RETURN_STRING_LITERAL(QUIC_HPACK_NAME_TOO_LONG);
    RETURN_STRING_LITERAL(QUIC_HPACK_VALUE_TOO_LONG);
    RETURN_STRING_LITERAL(QUIC_HPACK_NAME_HUFFMAN_ERROR);
    RETURN_STRING_LITERAL(QUIC_HPACK_VALUE_HUFFMAN_ERROR);
    RETURN_STRING_LITERAL(QUIC_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE);
    RETURN_STRING_LITERAL(QUIC_HPACK_INVALID_INDEX);
    RETURN_STRING_LITERAL(QUIC_HPACK_INVALID_NAME_INDEX);
    RETURN_STRING_LITERAL(QUIC_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED);
    RETURN_STRING_LITERAL(
        QUIC_HPACK_INITIAL_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK);
    RETURN_STRING_LITERAL(
        QUIC_HPACK_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING);
    RETURN_STRING_LITERAL(QUIC_HPACK_TRUNCATED_BLOCK);
    RETURN_STRING_LITERAL(QUIC_HPACK_FRAGMENT_TOO_LONG);
    RETURN_STRING_LITERAL(QUIC_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT);
    RETURN_STRING_LITERAL(QUIC_ZERO_RTT_UNRETRANSMITTABLE);
    RETURN_STRING_LITERAL(QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED);
    RETURN_STRING_LITERAL(QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED);
    RETURN_STRING_LITERAL(QUIC_SILENT_IDLE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_MISSING_WRITE_KEYS);
    RETURN_STRING_LITERAL(QUIC_KEY_UPDATE_ERROR);
    RETURN_STRING_LITERAL(QUIC_AEAD_LIMIT_REACHED);
    RETURN_STRING_LITERAL(QUIC_MAX_AGE_TIMEOUT);
    RETURN_STRING_LITERAL(QUIC_INVALID_PRIORITY_UPDATE);
    RETURN_STRING_LITERAL(QUIC_TLS_BAD_CERTIFICATE);
    RETURN_STRING_LITERAL(QUIC_TLS_UNSUPPORTED_CERTIFICATE);
    RETURN_STRING_LITERAL(QUIC_TLS_CERTIFICATE_REVOKED);
    RETURN_STRING_LITERAL(QUIC_TLS_CERTIFICATE_EXPIRED);
    RETURN_STRING_LITERAL(QUIC_TLS_CERTIFICATE_UNKNOWN);
    RETURN_STRING_LITERAL(QUIC_TLS_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_TLS_UNRECOGNIZED_NAME);
    RETURN_STRING_LITERAL(QUIC_TLS_CERTIFICATE_REQUIRED);
    RETURN_STRING_LITERAL(QUIC_INVALID_CHARACTER_IN_FIELD_VALUE);
    RETURN_STRING_LITERAL(QUIC_TLS_UNEXPECTED_KEYING_MATERIAL_EXPORT_LABEL);
    RETURN_STRING_LITERAL(QUIC_TLS_KEYING_MATERIAL_EXPORTS_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_TLS_KEYING_MATERIAL_EXPORT_NOT_AVAILABLE);
    RETURN_STRING_LITERAL(QUIC_UNEXPECTED_DATA_BEFORE_ENCRYPTION_ESTABLISHED);
    RETURN_STRING_LITERAL(QUIC_SERVER_UNHEALTHY);
    RETURN_STRING_LITERAL(QUIC_CLIENT_LOST_NETWORK_ACCESS);

    RETURN_STRING_LITERAL(QUIC_LAST_ERROR);
    // Intentionally have no default case, so we'll break the build
    // if we add errors and don't put them here.
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicErrorCodes. This can happen when the ConnectionClose
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_ERROR_CODE";
}

std::string QuicIetfTransportErrorCodeString(QuicIetfTransportErrorCodes c) {
  if (c >= CRYPTO_ERROR_FIRST && c <= CRYPTO_ERROR_LAST) {
    const int tls_error = static_cast<int>(c - CRYPTO_ERROR_FIRST);
    const char* tls_error_description = SSL_alert_desc_string_long(tls_error);
    if (strcmp("unknown", tls_error_description) != 0) {
      return absl::StrCat("CRYPTO_ERROR(", tls_error_description, ")");
    }
    return absl::StrCat("CRYPTO_ERROR(unknown(", tls_error, "))");
  }

  switch (c) {
    RETURN_STRING_LITERAL(NO_IETF_QUIC_ERROR);
    RETURN_STRING_LITERAL(INTERNAL_ERROR);
    RETURN_STRING_LITERAL(SERVER_BUSY_ERROR);
    RETURN_STRING_LITERAL(FLOW_CONTROL_ERROR);
    RETURN_STRING_LITERAL(STREAM_LIMIT_ERROR);
    RETURN_STRING_LITERAL(STREAM_STATE_ERROR);
    RETURN_STRING_LITERAL(FINAL_SIZE_ERROR);
    RETURN_STRING_LITERAL(FRAME_ENCODING_ERROR);
    RETURN_STRING_LITERAL(TRANSPORT_PARAMETER_ERROR);
    RETURN_STRING_LITERAL(CONNECTION_ID_LIMIT_ERROR);
    RETURN_STRING_LITERAL(PROTOCOL_VIOLATION);
    RETURN_STRING_LITERAL(INVALID_TOKEN);
    RETURN_STRING_LITERAL(CRYPTO_BUFFER_EXCEEDED);
    RETURN_STRING_LITERAL(KEY_UPDATE_ERROR);
    RETURN_STRING_LITERAL(AEAD_LIMIT_REACHED);
    // CRYPTO_ERROR is handled in the if before this switch, these cases do not
    // change behavior and are only here to make the compiler happy.
    case CRYPTO_ERROR_FIRST:
    case CRYPTO_ERROR_LAST:
      QUICHE_DCHECK(false) << "Unexpected error " << static_cast<uint64_t>(c);
      break;
  }

  return absl::StrCat("Unknown(", static_cast<uint64_t>(c), ")");
}

std::ostream& operator<<(std::ostream& os,
                         const QuicIetfTransportErrorCodes& c) {
  os << QuicIetfTransportErrorCodeString(c);
  return os;
}

QuicErrorCodeToIetfMapping QuicErrorCodeToTransportErrorCode(
    QuicErrorCode error) {
  switch (error) {
    case QUIC_NO_ERROR:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_INTERNAL_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_STREAM_DATA_AFTER_TERMINATION:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_PACKET_HEADER:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_FRAME_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_MISSING_PAYLOAD:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_FEC_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_STREAM_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_OVERLAPPING_STREAM_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_UNENCRYPTED_STREAM_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_MAYBE_CORRUPTED_MEMORY:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_UNENCRYPTED_FEC_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_RST_STREAM_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_CONNECTION_CLOSE_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_GOAWAY_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_WINDOW_UPDATE_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_BLOCKED_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_STOP_WAITING_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_PATH_CLOSE_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_ACK_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_MESSAGE_DATA:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_VERSION_NEGOTIATION_PACKET:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_PUBLIC_RST_PACKET:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_DECRYPTION_FAILURE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_ENCRYPTION_FAILURE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_PACKET_TOO_LARGE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_PEER_GOING_AWAY:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_STREAM_ID:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_PRIORITY:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_OPEN_STREAMS:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_TOO_MANY_AVAILABLE_STREAMS:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_PUBLIC_RESET:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_VERSION:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_PACKET_WRONG_VERSION:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_0RTT_PACKET_NUMBER_OUT_OF_ORDER:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_HEADER_ID:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_NEGOTIATED_VALUE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_DECOMPRESSION_FAILURE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_NETWORK_IDLE_TIMEOUT:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_SILENT_IDLE_TIMEOUT:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_TIMEOUT:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_ERROR_MIGRATING_ADDRESS:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_ERROR_MIGRATING_PORT:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_PACKET_WRITE_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_PACKET_READ_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_EMPTY_STREAM_FRAME_NO_FIN:
      return {true, static_cast<uint64_t>(FRAME_ENCODING_ERROR)};
    case QUIC_INVALID_HEADERS_STREAM_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA:
      return {true, static_cast<uint64_t>(FLOW_CONTROL_ERROR)};
    case QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_FLOW_CONTROL_INVALID_WINDOW:
      return {true, static_cast<uint64_t>(FLOW_CONTROL_ERROR)};
    case QUIC_CONNECTION_IP_POOLED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_CANCELLED:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_BAD_PACKET_LOSS_RATE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_PUBLIC_RESETS_POST_HANDSHAKE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_FAILED_TO_SERIALIZE_PACKET:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_RTOS:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_TAGS_OUT_OF_ORDER:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_TOO_MANY_ENTRIES:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_INVALID_VALUE_LENGTH:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_CRYPTO_MESSAGE_TYPE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_CHANNEL_ID_SIGNATURE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_UNSUPPORTED_PROOF_DEMAND:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_INTERNAL_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CRYPTO_VERSION_NOT_SUPPORTED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_NO_SUPPORT:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_TOO_MANY_REJECTS:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_PROOF_INVALID:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_DUPLICATE_TAG:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_SERVER_CONFIG_EXPIRED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_CRYPTO_CHLO_TOO_LARGE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_VERSION_NEGOTIATION_MISMATCH:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_BAD_MULTIPATH_FLAG:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_MULTIPATH_PATH_DOES_NOT_EXIST:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_MULTIPATH_PATH_NOT_ACTIVE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_IP_ADDRESS_CHANGED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_PEER_PORT_CHANGE_HANDSHAKE_UNCONFIRMED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_STREAM_DATA_INTERVALS:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_STREAM_SEQUENCER_INVALID_STATE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_TOO_MANY_SESSIONS_ON_SERVER:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_STREAM_LENGTH_OVERFLOW:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_MAX_DATA_FRAME_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_MAX_STREAM_DATA_FRAME_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_MAX_STREAMS_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_STREAMS_BLOCKED_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_STREAM_BLOCKED_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_NEW_CONNECTION_ID_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_STOP_SENDING_FRAME_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_PATH_CHALLENGE_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_PATH_RESPONSE_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case IETF_QUIC_PROTOCOL_VIOLATION:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_INVALID_NEW_TOKEN:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_DATA_RECEIVED_ON_WRITE_UNIDIRECTIONAL_STREAM:
      return {true, static_cast<uint64_t>(STREAM_STATE_ERROR)};
    case QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_RETIRE_CONNECTION_ID_DATA:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_STREAMS_BLOCKED_ERROR:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_MAX_STREAMS_ERROR:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_HTTP_DECODER_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_STALE_CONNECTION_CANCELLED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_IETF_GQUIC_ERROR_MISSING:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_TOO_MANY_BUFFERED_CONTROL_FRAMES:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_TRANSPORT_INVALID_CLIENT_INDICATION:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_QPACK_DECOMPRESSION_FAILED:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECOMPRESSION_FAILED)};
    case QUIC_QPACK_ENCODER_STREAM_ERROR:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_ERROR:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_INTEGER_TOO_LARGE:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_STRING_LITERAL_TOO_LONG:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_HUFFMAN_ENCODING_ERROR:
      return {false, static_cast<u
```