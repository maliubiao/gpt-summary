Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the Chromium network stack, specifically related to QUIC error code handling.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose:** The code primarily focuses on converting between different types of error codes used within the QUIC protocol and its related sub-protocols (like HTTP/3 and QPACK). This includes mapping internal QUIC error codes to IETF QUIC application error codes and TLS alert descriptions.

2. **Analyze the main functions:**
    * `ToQuicErrorCode`:  This function takes a `net::QuicErrorCode` and converts it into a pair indicating if the error is a connection error and its corresponding IETF QUIC error code. This is a central mapping function.
    * `TlsAlertToQuicErrorCode`: This function maps TLS alert descriptions (numeric codes) to `net::QuicErrorCode`. This handles errors originating from the TLS handshake.
    * `RstStreamErrorCodeToIetfResetStreamErrorCode`: Converts internal QUIC stream reset error codes to IETF QUIC `RESET_STREAM` frame error codes (which are HTTP/3 error codes).
    * `IetfResetStreamErrorCodeToRstStreamErrorCode`:  The reverse of the previous function, converting IETF `RESET_STREAM` frame error codes back to internal QUIC stream reset error codes.
    * `QuicResetStreamError::FromInternal`, `QuicResetStreamError::FromIetf`: These are static factory methods to create `QuicResetStreamError` objects, which encapsulate both the internal and IETF error codes for stream resets.

3. **Relate to networking concepts:**  Recognize that QUIC is a transport layer protocol, often used for HTTP/3. The code handles errors at different layers:
    * **QUIC core:** General QUIC protocol errors (e.g., `QUIC_INVALID_PACKET_HEADER`).
    * **HTTP/3:** Application-level errors within HTTP/3 (e.g., `QUIC_HTTP_FRAME_TOO_LARGE`).
    * **QPACK:** Header compression errors (e.g., `QUIC_QPACK_ENCODER_STREAM_ERROR`).
    * **TLS:**  Secure connection establishment errors (e.g., `QUIC_TLS_BAD_CERTIFICATE`).

4. **Consider the JavaScript connection:**  Think about how these low-level networking errors might surface in a web browser environment where JavaScript is the primary scripting language. JavaScript doesn't directly deal with these specific error codes. Instead, it receives higher-level error indications, like network connection failures, timeouts, or specific HTTP error responses. The browser's underlying network stack (including this C++ code) handles the translation.

5. **Illustrate with examples:** Create concrete examples to show how the error code conversions might work. This helps clarify the purpose of the functions. Think of a scenario where an HTTP/3 request fails due to a large header, and trace how the `QUIC_HTTP_FRAME_TOO_LARGE` error is handled.

6. **Identify user/programming errors:** Consider what actions by a user or programmer could lead to these errors. For instance, a user might try to access a website with an expired certificate, or a developer might send an oversized HTTP header.

7. **Explain debugging context:**  Describe how these error codes could be used in a debugging scenario. If a connection fails, these codes provide specific information about the cause, which can help pinpoint the problem.

8. **Address the "Part 2" instruction:**  Recognize that this is the second part of the explanation and needs to summarize the overall functionality. The core function is mapping between different error code representations within the QUIC stack.

9. **Structure the answer:** Organize the information logically, starting with a general overview, then delving into specifics, and finally summarizing. Use headings and bullet points to improve readability.

10. **Refine and clarify:** Review the generated explanation to ensure accuracy, clarity, and completeness. Make sure the JavaScript connections and examples are well-explained. For example, explicitly state that JavaScript doesn't directly see these codes, but rather experiences the *consequences* of them.
这是对Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_error_codes.cc` 文件功能的归纳总结。结合之前第一部分的内容，我们可以得出以下结论：

**整体功能归纳：**

这个 `quic_error_codes.cc` 文件的核心功能是 **定义和转换 QUIC 协议及其相关协议（如 HTTP/3 和 QPACK）中使用的各种错误代码。**  它提供了一个集中的位置来管理和映射不同类型的错误，以便系统能够理解和处理各种网络异常情况。

**具体功能点:**

1. **`ToQuicErrorCode(net::QuicErrorCode error)` 函数:**
   - **功能:** 将底层的 `net::QuicErrorCode` 枚举值转换为一个包含两个元素的结构体：
     - `bool is_connection_error`: 指示该错误是否会导致整个 QUIC 连接关闭。
     - `uint64_t ietf_error_code`: 对应的 IETF QUIC 规范中定义的应用程序级别的错误码。
   - **作用:**  这是将 Chromium 内部 QUIC 错误码映射到标准的 IETF QUIC 错误码的关键函数，用于在网络上传输和与其他 QUIC 实现互操作。

2. **`TlsAlertToQuicErrorCode(uint8_t desc)` 函数:**
   - **功能:** 将 TLS (Transport Layer Security) 握手过程中产生的告警描述符 (TLS Alert Description) 转换为对应的 `net::QuicErrorCode` 枚举值。
   - **作用:** 用于处理 TLS 握手失败的情况，将 TLS 层的错误信息转换为 QUIC 协议层可以理解的错误码。

3. **`RstStreamErrorCodeToIetfResetStreamErrorCode(QuicRstStreamErrorCode rst_stream_error_code)` 函数:**
   - **功能:** 将 QUIC 流重置错误码 (`QuicRstStreamErrorCode`) 转换为 IETF QUIC `RESET_STREAM` 帧中使用的应用程序错误码。  这些应用程序错误码通常是 HTTP/3 的错误码。
   - **作用:**  当需要主动关闭或重置一个 QUIC 流时，这个函数用于生成标准的 `RESET_STREAM` 帧，告知对端流关闭的原因。

4. **`IetfResetStreamErrorCodeToRstStreamErrorCode(uint64_t ietf_error_code)` 函数:**
   - **功能:**  与上一个函数相反，它将 IETF QUIC `RESET_STREAM` 帧中接收到的应用程序错误码转换回内部的 `QuicRstStreamErrorCode` 枚举值。
   - **作用:**  当接收到对端发送的 `RESET_STREAM` 帧时，使用此函数将帧中的错误码转换为内部表示，方便程序处理。

5. **`QuicResetStreamError` 结构体及其静态工厂方法 (`FromInternal`, `FromIetf`)**
   - **功能:**  `QuicResetStreamError` 结构体用于封装 QUIC 流重置错误的信息，包括内部的 `QuicRstStreamErrorCode` 和对应的 IETF 错误码。
   - **作用:**  提供了一种方便的方式来创建和管理流重置错误信息，并提供静态工厂方法来从内部错误码或 IETF 错误码创建该结构体实例。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所定义和处理的错误信息最终会影响到基于浏览器的 JavaScript 应用。

**举例说明:**

假设用户在浏览器中访问一个使用 QUIC 和 HTTP/3 的网站，但服务器返回了一个过大的 HTTP 头部。

1. **C++ 层:**  服务器的 QUIC 实现会检测到头部过大，并产生一个内部的 `QUIC_HTTP_FRAME_TOO_LARGE` 错误码。
2. **错误码转换:**  `ToQuicErrorCode` 函数会将 `QUIC_HTTP_FRAME_TOO_LARGE` 转换为对应的 IETF HTTP/3 错误码 `EXCESSIVE_LOAD`，并将 `is_connection_error` 设置为 `false` (可能只需要重置该流)。
3. **通知浏览器:**  Chromium 的网络栈会将此错误信息传递给浏览器进程。
4. **JavaScript 层面:** JavaScript 代码无法直接访问到 `QUIC_HTTP_FRAME_TOO_LARGE` 或 `EXCESSIVE_LOAD` 这样的底层错误码。  但是，浏览器可能会将此错误转换为一个更通用的网络错误事件，例如 `net::ERR_HTTP2_PROTOCOL_ERROR` 或 `net::ERR_FAILED`，并提供更高级别的错误信息，例如 "请求失败，头部过大"。  开发者可以通过捕获这些浏览器提供的网络错误事件来处理这种情况。

**假设输入与输出 (针对 `ToQuicErrorCode`):**

**假设输入:** `net::QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET`

**逻辑推理:**  此错误表示接收到的数据超过了流的关闭偏移量，这是一种协议违规行为。

**输出:** `{true, static_cast<uint64_t>(PROTOCOL_VIOLATION)}`
   - `true`:  这是一个连接级别的错误，可能需要关闭连接。
   - `PROTOCOL_VIOLATION`: 对应的 IETF QUIC 错误码。

**用户或编程常见的使用错误举例：**

1. **用户操作导致 `QUIC_TLS_BAD_CERTIFICATE`:** 用户访问了一个使用 HTTPS (通过 QUIC) 的网站，但该网站的 SSL 证书无效（例如，过期、自签名但未被信任）。  Chromium 的 QUIC 客户端在 TLS 握手阶段会遇到此错误。

2. **编程错误导致 `QUIC_HTTP_FRAME_TOO_LARGE`:**  开发者编写的服务器端代码生成了过大的 HTTP 响应头部，超过了 QUIC 或 HTTP/3 允许的最大值。

**用户操作如何一步步到达这里作为调试线索 (以 `QUIC_HTTP_FRAME_TOO_LARGE` 为例):**

1. **用户在浏览器地址栏输入 URL 并访问。**
2. **浏览器发起 QUIC 连接到服务器。**
3. **服务器开始发送 HTTP/3 响应。**
4. **服务器发送的响应头部数据过大，超过了客户端配置的限制。**
5. **Chromium 的 QUIC 接收端检测到头部大小超过限制。**
6. **代码执行到 `ToQuicErrorCode(QUIC_HTTP_FRAME_TOO_LARGE)` 分支。**
7. **该函数返回 `{false, static_cast<uint64_t>(QuicHttp3ErrorCode::EXCESSIVE_LOAD)}`。**
8. **Chromium 网络栈会根据这个错误信息采取相应的措施，例如重置该流或关闭连接，并可能向开发者工具报告错误信息。**

通过查看调试日志或网络抓包，开发者可以追踪到这个错误码，从而定位问题是由于服务器发送了过大的 HTTP 头部。

总而言之，`quic_error_codes.cc` 是 QUIC 协议实现中至关重要的一个文件，它确保了不同层级和不同规范的错误码能够被正确地映射和理解，从而保证了 QUIC 连接的健壮性和互操作性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_error_codes.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
int64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_INVALID_STATIC_ENTRY:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_STATIC:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_INSERTION_INVALID_RELATIVE_INDEX:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_INSERTION_DYNAMIC_ENTRY_NOT_FOUND:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_DYNAMIC:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_LITERAL:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_DUPLICATE_INVALID_RELATIVE_INDEX:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_DUPLICATE_DYNAMIC_ENTRY_NOT_FOUND:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_ENCODER_STREAM_SET_DYNAMIC_TABLE_CAPACITY:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_INTEGER_TOO_LARGE:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_INVALID_ZERO_INCREMENT:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_INCREMENT_OVERFLOW:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_IMPOSSIBLE_INSERT_COUNT:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_QPACK_DECODER_STREAM_INCORRECT_ACKNOWLEDGEMENT:
      return {false, static_cast<uint64_t>(
                         QuicHttpQpackErrorCode::DECODER_STREAM_ERROR)};
    case QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_STREAM_MULTIPLE_OFFSET:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_HTTP_FRAME_TOO_LARGE:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::EXCESSIVE_LOAD)};
    case QUIC_HTTP_FRAME_ERROR:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_ERROR)};
    case QUIC_HTTP_FRAME_UNEXPECTED_ON_SPDY_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED)};
    case QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED)};
    case QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED)};
    case QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED)};
    case QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR)};
    case QUIC_HTTP_SERVER_INITIATED_BIDIRECTIONAL_STREAM:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR)};
    case QUIC_HTTP_STREAM_WRONG_DIRECTION:
      return {true, static_cast<uint64_t>(STREAM_STATE_ERROR)};
    case QUIC_HTTP_CLOSED_CRITICAL_STREAM:
      return {false, static_cast<uint64_t>(
                         QuicHttp3ErrorCode::CLOSED_CRITICAL_STREAM)};
    case QUIC_HTTP_MISSING_SETTINGS_FRAME:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::MISSING_SETTINGS)};
    case QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR)};
    case QUIC_HTTP_INVALID_MAX_PUSH_ID:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR)};
    case QUIC_HTTP_STREAM_LIMIT_TOO_LOW:
      return {false, static_cast<uint64_t>(
                         QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR)};
    case QUIC_HTTP_RECEIVE_SERVER_PUSH:
      return {false, static_cast<uint64_t>(
                         QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR)};
    case QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR)};
    case QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HTTP_GOAWAY_INVALID_STREAM_ID:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR)};
    case QUIC_HTTP_GOAWAY_ID_LARGER_THAN_PREVIOUS:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR)};
    case QUIC_HTTP_RECEIVE_SPDY_SETTING:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR)};
    case QUIC_HTTP_INVALID_SETTING_VALUE:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR)};
    case QUIC_HTTP_RECEIVE_SPDY_FRAME:
      return {false,
              static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED)};
    case QUIC_HPACK_INDEX_VARINT_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_NAME_LENGTH_VARINT_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_VALUE_LENGTH_VARINT_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_NAME_TOO_LONG:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_VALUE_TOO_LONG:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_NAME_HUFFMAN_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_VALUE_HUFFMAN_ERROR:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_INVALID_INDEX:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_INVALID_NAME_INDEX:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_INITIAL_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_TRUNCATED_BLOCK:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_FRAGMENT_TOO_LONG:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_ZERO_RTT_UNRETRANSMITTABLE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_MISSING_WRITE_KEYS:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_KEY_UPDATE_ERROR:
      return {true, static_cast<uint64_t>(KEY_UPDATE_ERROR)};
    case QUIC_AEAD_LIMIT_REACHED:
      return {true, static_cast<uint64_t>(AEAD_LIMIT_REACHED)};
    case QUIC_MAX_AGE_TIMEOUT:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR)};
    case QUIC_INVALID_PRIORITY_UPDATE:
      return {false, static_cast<uint64_t>(
                         QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR)};
    case QUIC_TLS_BAD_CERTIFICATE:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_BAD_CERTIFICATE)};
    case QUIC_TLS_UNSUPPORTED_CERTIFICATE:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_UNSUPPORTED_CERTIFICATE)};
    case QUIC_TLS_CERTIFICATE_REVOKED:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_CERTIFICATE_REVOKED)};
    case QUIC_TLS_CERTIFICATE_EXPIRED:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_CERTIFICATE_EXPIRED)};
    case QUIC_TLS_CERTIFICATE_UNKNOWN:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_CERTIFICATE_UNKNOWN)};
    case QUIC_TLS_INTERNAL_ERROR:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_INTERNAL_ERROR)};
    case QUIC_TLS_UNRECOGNIZED_NAME:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_UNRECOGNIZED_NAME)};
    case QUIC_TLS_CERTIFICATE_REQUIRED:
      return {true, static_cast<uint64_t>(CRYPTO_ERROR_FIRST +
                                          SSL_AD_CERTIFICATE_REQUIRED)};
    case QUIC_CONNECTION_ID_LIMIT_ERROR:
      return {true, static_cast<uint64_t>(CONNECTION_ID_LIMIT_ERROR)};
    case QUIC_TOO_MANY_CONNECTION_ID_WAITING_TO_RETIRE:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_INVALID_CHARACTER_IN_FIELD_VALUE:
      return {false, static_cast<uint64_t>(QuicHttp3ErrorCode::MESSAGE_ERROR)};
    case QUIC_TLS_UNEXPECTED_KEYING_MATERIAL_EXPORT_LABEL:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_TLS_KEYING_MATERIAL_EXPORTS_MISMATCH:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_TLS_KEYING_MATERIAL_EXPORT_NOT_AVAILABLE:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_UNEXPECTED_DATA_BEFORE_ENCRYPTION_ESTABLISHED:
      return {true, static_cast<uint64_t>(PROTOCOL_VIOLATION)};
    case QUIC_SERVER_UNHEALTHY:
      return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
    case QUIC_HANDSHAKE_FAILED_PACKETS_BUFFERED_TOO_LONG:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_CLIENT_LOST_NETWORK_ACCESS:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED_INVALID_HOSTNAME:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED_REJECTING_ALL_CONNECTIONS:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED_INVALID_CONNECTION:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_HANDSHAKE_FAILED_CID_COLLISION:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
    case QUIC_LAST_ERROR:
      return {false, static_cast<uint64_t>(QUIC_LAST_ERROR)};
  }
  // This function should not be called with unknown error code.
  return {true, static_cast<uint64_t>(INTERNAL_ERROR)};
}

std::optional<QuicErrorCode> TlsAlertToQuicErrorCode(uint8_t desc) {
  switch (desc) {
    case SSL_AD_BAD_CERTIFICATE:
      return QUIC_TLS_BAD_CERTIFICATE;
    case SSL_AD_UNSUPPORTED_CERTIFICATE:
      return QUIC_TLS_UNSUPPORTED_CERTIFICATE;
    case SSL_AD_CERTIFICATE_REVOKED:
      return QUIC_TLS_CERTIFICATE_REVOKED;
    case SSL_AD_CERTIFICATE_EXPIRED:
      return QUIC_TLS_CERTIFICATE_EXPIRED;
    case SSL_AD_CERTIFICATE_UNKNOWN:
      return QUIC_TLS_CERTIFICATE_UNKNOWN;
    case SSL_AD_INTERNAL_ERROR:
      return QUIC_TLS_INTERNAL_ERROR;
    case SSL_AD_UNRECOGNIZED_NAME:
      return QUIC_TLS_UNRECOGNIZED_NAME;
    case SSL_AD_CERTIFICATE_REQUIRED:
      return QUIC_TLS_CERTIFICATE_REQUIRED;
    default:
      return std::nullopt;
  }
}

// Convert a QuicRstStreamErrorCode to an application error code to be used in
// an IETF QUIC RESET_STREAM frame
uint64_t RstStreamErrorCodeToIetfResetStreamErrorCode(
    QuicRstStreamErrorCode rst_stream_error_code) {
  switch (rst_stream_error_code) {
    case QUIC_STREAM_NO_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::HTTP3_NO_ERROR);
    case QUIC_ERROR_PROCESSING_STREAM:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_MULTIPLE_TERMINATION_OFFSETS:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_BAD_APPLICATION_PAYLOAD:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_STREAM_CONNECTION_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR);
    case QUIC_STREAM_PEER_GOING_AWAY:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_STREAM_CANCELLED:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED);
    case QUIC_RST_ACKNOWLEDGEMENT:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::HTTP3_NO_ERROR);
    case QUIC_REFUSED_STREAM:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR);
    case QUIC_INVALID_PROMISE_URL:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR);
    case QUIC_UNAUTHORIZED_PROMISE_URL:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR);
    case QUIC_DUPLICATE_PROMISE_URL:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR);
    case QUIC_PROMISE_VARY_MISMATCH:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED);
    case QUIC_INVALID_PROMISE_METHOD:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR);
    case QUIC_PUSH_STREAM_TIMED_OUT:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED);
    case QUIC_HEADERS_TOO_LARGE:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::EXCESSIVE_LOAD);
    case QUIC_STREAM_TTL_EXPIRED:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED);
    case QUIC_DATA_AFTER_CLOSE_OFFSET:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_STREAM_GENERAL_PROTOCOL_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_STREAM_INTERNAL_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR);
    case QUIC_STREAM_STREAM_CREATION_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR);
    case QUIC_STREAM_CLOSED_CRITICAL_STREAM:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::CLOSED_CRITICAL_STREAM);
    case QUIC_STREAM_FRAME_UNEXPECTED:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED);
    case QUIC_STREAM_FRAME_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_ERROR);
    case QUIC_STREAM_EXCESSIVE_LOAD:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::EXCESSIVE_LOAD);
    case QUIC_STREAM_ID_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR);
    case QUIC_STREAM_SETTINGS_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR);
    case QUIC_STREAM_MISSING_SETTINGS:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::MISSING_SETTINGS);
    case QUIC_STREAM_REQUEST_REJECTED:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_REJECTED);
    case QUIC_STREAM_REQUEST_INCOMPLETE:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_INCOMPLETE);
    case QUIC_STREAM_CONNECT_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::CONNECT_ERROR);
    case QUIC_STREAM_VERSION_FALLBACK:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::VERSION_FALLBACK);
    case QUIC_STREAM_DECOMPRESSION_FAILED:
      return static_cast<uint64_t>(
          QuicHttpQpackErrorCode::DECOMPRESSION_FAILED);
    case QUIC_STREAM_ENCODER_STREAM_ERROR:
      return static_cast<uint64_t>(
          QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR);
    case QUIC_STREAM_DECODER_STREAM_ERROR:
      return static_cast<uint64_t>(
          QuicHttpQpackErrorCode::DECODER_STREAM_ERROR);
    case QUIC_STREAM_UNKNOWN_APPLICATION_ERROR_CODE:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR);
    case QUIC_STREAM_WEBTRANSPORT_SESSION_GONE:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::CONNECT_ERROR);
    case QUIC_STREAM_WEBTRANSPORT_BUFFERED_STREAMS_LIMIT_EXCEEDED:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::CONNECT_ERROR);
    case QUIC_APPLICATION_DONE_WITH_STREAM:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR);
    case QUIC_STREAM_LAST_ERROR:
      return static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR);
  }
  return static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR);
}

// Convert the application error code of an IETF QUIC RESET_STREAM frame
// to QuicRstStreamErrorCode.
QuicRstStreamErrorCode IetfResetStreamErrorCodeToRstStreamErrorCode(
    uint64_t ietf_error_code) {
  switch (ietf_error_code) {
    case static_cast<uint64_t>(QuicHttp3ErrorCode::HTTP3_NO_ERROR):
      return QUIC_STREAM_NO_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR):
      return QUIC_STREAM_GENERAL_PROTOCOL_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::INTERNAL_ERROR):
      return QUIC_STREAM_INTERNAL_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR):
      return QUIC_STREAM_STREAM_CREATION_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::CLOSED_CRITICAL_STREAM):
      return QUIC_STREAM_CLOSED_CRITICAL_STREAM;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_UNEXPECTED):
      return QUIC_STREAM_FRAME_UNEXPECTED;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_ERROR):
      return QUIC_STREAM_FRAME_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::EXCESSIVE_LOAD):
      return QUIC_STREAM_EXCESSIVE_LOAD;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR):
      return QUIC_STREAM_ID_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::SETTINGS_ERROR):
      return QUIC_STREAM_SETTINGS_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::MISSING_SETTINGS):
      return QUIC_STREAM_MISSING_SETTINGS;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_REJECTED):
      return QUIC_STREAM_REQUEST_REJECTED;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED):
      return QUIC_STREAM_CANCELLED;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_INCOMPLETE):
      return QUIC_STREAM_REQUEST_INCOMPLETE;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::CONNECT_ERROR):
      return QUIC_STREAM_CONNECT_ERROR;
    case static_cast<uint64_t>(QuicHttp3ErrorCode::VERSION_FALLBACK):
      return QUIC_STREAM_VERSION_FALLBACK;
    case static_cast<uint64_t>(QuicHttpQpackErrorCode::DECOMPRESSION_FAILED):
      return QUIC_STREAM_DECOMPRESSION_FAILED;
    case static_cast<uint64_t>(QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR):
      return QUIC_STREAM_ENCODER_STREAM_ERROR;
    case static_cast<uint64_t>(QuicHttpQpackErrorCode::DECODER_STREAM_ERROR):
      return QUIC_STREAM_DECODER_STREAM_ERROR;
  }
  return QUIC_STREAM_UNKNOWN_APPLICATION_ERROR_CODE;
}

// static
QuicResetStreamError QuicResetStreamError::FromInternal(
    QuicRstStreamErrorCode code) {
  return QuicResetStreamError(
      code, RstStreamErrorCodeToIetfResetStreamErrorCode(code));
}

// static
QuicResetStreamError QuicResetStreamError::FromIetf(uint64_t code) {
  return QuicResetStreamError(
      IetfResetStreamErrorCodeToRstStreamErrorCode(code), code);
}

// static
QuicResetStreamError QuicResetStreamError::FromIetf(QuicHttp3ErrorCode code) {
  return FromIetf(static_cast<uint64_t>(code));
}

// static
QuicResetStreamError QuicResetStreamError::FromIetf(
    QuicHttpQpackErrorCode code) {
  return FromIetf(static_cast<uint64_t>(code));
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds

}  // namespace quic
```