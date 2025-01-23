Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicFramer` class in Chromium's QUIC implementation.

Here's a breakdown of the code's key actions:

1. **Frame Type Handling:** The code reads the frame type from the incoming data.
2. **Dispatching:** Based on the frame type, it calls the appropriate processing function.
3. **Special Frame Types:** It handles "special" frame types like Stream and ACK frames based on bitmasks.
4. **Regular Frame Types:** It uses a `switch` statement to handle various control frames like PADDING, RST_STREAM, CONNECTION_CLOSE, etc.
5. **IETF Frame Types:** It also includes logic to handle IETF QUIC frame types, which are identified by variable-length integers.
6. **Visitor Pattern:**  After processing a frame, it calls a `visitor_` object's corresponding `On...Frame` method to notify the higher-level code about the parsed frame.
7. **Error Handling:** If there's an error during parsing, it sets an error message and returns an error code.
8. **Encryption Level Checks (for IETF):** It verifies if certain IETF frame types are allowed at the current encryption level.

Relating this to JavaScript:  JavaScript in a browser interacting with a QUIC server would *receive* and *send* data packets that are structured according to the QUIC protocol. This C++ code is responsible for the *parsing* of these incoming packets on the Chromium side.

Common errors involve malformed packets or incorrect frame types. The debugging scenario involves tracing how data received by the network stack eventually reaches this `ProcessFrameData` or `ProcessIetfFrameData` function.

The request explicitly asks for a summary of the *current* code snippet, which focuses on the frame processing loop.
这是提供的C++代码片段是 `QuicFramer` 类中的一部分，负责**解析接收到的 QUIC 数据包中的帧 (frames)**。 具体来说，它做了以下几件事：

1. **读取帧类型:** 从 `QuicDataReader` 中读取一个字节来确定帧的类型。
2. **处理特殊帧类型 (Stream 和 ACK):**  通过检查帧类型字节的特定位，判断是否为 Stream 帧或 ACK 帧，并调用相应的处理函数 `ProcessStreamFrame` 或 `ProcessAckFrame`。
3. **处理标准帧类型:**  使用 `switch` 语句根据读取到的帧类型，调用相应的 `Process...Frame` 函数来解析不同类型的控制帧，例如：
    - `PADDING_FRAME`:  填充帧
    - `RST_STREAM_FRAME`: 重置流帧
    - `CONNECTION_CLOSE_FRAME`: 连接关闭帧
    - `GOAWAY_FRAME`:  GoAway 帧
    - `WINDOW_UPDATE_FRAME`: 窗口更新帧
    - `BLOCKED_FRAME`:  阻塞帧
    - `STOP_WAITING_FRAME`: 停止等待帧
    - `PING_FRAME`: Ping 帧
    - `IETF_EXTENSION_MESSAGE(_NO_LENGTH)`: 消息帧 (旧版本)
    - `CRYPTO_FRAME`: 加密帧
    - `HANDSHAKE_DONE_FRAME`: 握手完成帧
4. **处理 IETF QUIC 帧:**  `ProcessIetfFrameData` 函数负责解析 IETF QUIC 草案中定义的帧类型，这些帧类型使用变长整数进行编码。它也根据加密级别检查帧类型的合法性。
5. **调用 Visitor 接口:** 在成功解析一个帧后，会调用 `visitor_` 对象的相应 `On...Frame` 方法，将解析出的帧数据传递给上层模块进行处理。
6. **错误处理:** 如果在读取帧类型或解析帧数据时发生错误，会设置详细的错误信息并通过 `RaiseError` 返回相应的 QUIC 错误码。

**与 JavaScript 的关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的一部分，负责处理接收到的 QUIC 数据包。当一个 JavaScript 应用程序（例如，使用 `fetch` API 或 WebSocket）与支持 QUIC 的服务器进行通信时，服务器发送的 QUIC 数据包最终会被 Chromium 的网络栈接收并由 `QuicFramer` 进行解析。

**举例说明:**

假设一个 JavaScript 应用通过 `fetch` 向服务器请求一个资源。服务器响应的数据可能会以多个 QUIC Stream 帧的形式发送回来。

- **假设输入 (服务器发送的 QUIC 数据包):**  包含一个或多个 Stream 帧，每个帧包含一部分响应数据。
- **`quic_framer.cc` 的处理:**  `ProcessFrameData` 或 `ProcessIetfFrameData` 会读取每个 Stream 帧的类型、流 ID、偏移量和数据，并调用 `visitor_->OnStreamFrame(frame)`。
- **输出 (传递给上层模块):**  `visitor_` 会将解析出的 `QuicStreamFrame` 对象（包含流 ID、偏移量和数据）传递给上层处理流数据的模块。最终，这些数据会被组合起来，通过 Chromium 的内部机制传递给 JavaScript 的 `fetch` API 的响应处理程序。

**逻辑推理的假设输入与输出:**

**场景 1:  解析一个 PING 帧 (非 IETF)**

- **假设输入 (帧数据):**  一个字节，其值为 `PING_FRAME` 对应的枚举值 (例如 0x07)。
- **`ProcessFrameData` 的处理:**
    - 读取第一个字节，`frame_type` 等于 `PING_FRAME`。
    - 进入 `switch` 语句的 `case PING_FRAME:` 分支。
    - 创建一个空的 `QuicPingFrame` 对象。
    - 调用 `visitor_->OnPingFrame(ping_frame)`。
- **输出:**  `visitor_` 接收到一个 `QuicPingFrame` 对象。

**场景 2:  解析一个 IETF STREAM 帧**

- **假设输入 (帧数据):**  变长整数表示的帧类型 (以 `0b000000..` 开头表示 STREAM 帧), 变长整数表示的 Stream ID, 可能的变长整数表示的偏移量和数据长度，以及实际的数据。
- **`ProcessIetfFrameData` 的处理:**
    - 读取变长整数，解析出帧类型为 IETF STREAM。
    - 读取变长整数，解析出 Stream ID。
    - 根据帧类型标志位判断是否存在偏移量和长度，并读取。
    - 读取指定长度的数据。
    - 创建一个 `QuicStreamFrame` 对象并填充解析出的信息。
    - 调用 `visitor_->OnStreamFrame(frame)`。
- **输出:** `visitor_` 接收到一个包含解析后数据的 `QuicStreamFrame` 对象。

**用户或编程常见的使用错误:**

1. **服务器发送了错误的帧类型:**  如果服务器发送了一个 `QuicFramer` 不认识或不支持的帧类型，代码会进入 `default` 分支或 IETF 的 `default` 分支，设置 "Illegal frame type." 错误并返回 `QUIC_INVALID_FRAME_DATA`。
   - **用户操作:**  这通常是服务器端实现错误，用户无法直接操作导致。
   - **调试线索:** 在 Chromium 的网络日志中会看到 `Illegal frame type` 的警告。

2. **服务器发送的帧数据格式不正确:**  例如，Stream 帧的长度字段与实际数据长度不符，或者 ACK 帧的确认范围格式错误。
   - **用户操作:**  同样，这主要是服务器端的问题。
   - **调试线索:**  代码中会设置像 "Unable to read stream_id." 或 "Invalid ACK range." 这样的详细错误信息。

3. **IETF 帧类型在错误的加密级别发送:** 例如，在 `ENCRYPTION_INITIAL` 阶段发送了 `IETF_NEW_TOKEN` 帧。
   - **用户操作:**  服务器端配置或实现错误。
   - **调试线索:**  代码会设置类似于 "IETF frame type ... is unexpected at encryption level ..." 的错误信息，并返回 `IETF_QUIC_PROTOCOL_VIOLATION`。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个 HTTPS 网站或执行一个网络请求。**
2. **浏览器与服务器进行 TLS 握手，协商使用 QUIC 协议。**
3. **连接建立后，服务器开始发送 QUIC 数据包给浏览器。**
4. **操作系统的网络驱动程序接收到这些数据包。**
5. **数据包被传递给 Chromium 的网络栈。**
6. **QUIC 会话的接收处理逻辑开始工作。**
7. **接收到的数据包中的 payload 被传递给 `QuicFramer` 的 `ProcessPacket` 或 `ProcessIetfPacket` 方法。**
8. **`ProcessPacket` 或 `ProcessIetfPacket` 进一步调用此代码片段中的 `ProcessFrameData` 或 `ProcessIetfFrameData` 来解析数据包中的各个帧。**

**作为调试线索，你需要关注以下几点:**

- **网络抓包:** 使用 Wireshark 等工具捕获网络数据包，查看服务器发送的 QUIC 数据包的内容，包括帧类型和帧数据。
- **Chromium 网络日志:** 启用 Chromium 的网络日志（chrome://net-export/），可以查看详细的 QUIC 连接信息，包括发送和接收的帧类型和相关错误信息。
- **断点调试:** 在 `QuicFramer::ProcessFrameData` 或 `QuicFramer::ProcessIetfFrameData` 函数中设置断点，查看接收到的 `frame_type` 和 `reader` 中的数据，以及代码的执行流程。
- **检查 `visitor_` 的实现:**  了解上层模块如何处理 `QuicFramer` 解析出的帧数据，有助于理解问题是否出在帧解析阶段还是后续处理阶段。

**归纳一下它的功能 (本部分代码):**

这段代码的核心功能是 **解析接收到的 QUIC 数据包中的帧，识别帧类型并提取帧数据，然后将解析出的帧信息传递给上层模块进行处理。**  它处理了 QUIC 协议中定义的各种控制帧和数据帧，并具备基本的错误处理能力，能够识别格式错误的帧数据。对于支持 IETF QUIC 的版本，它还负责解析 IETF QUIC 定义的帧类型并进行加密级别的校验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
uint8_t frame_type;
    if (!reader->ReadBytes(&frame_type, 1)) {
      set_detailed_error("Unable to read frame type.");
      return RaiseError(QUIC_INVALID_FRAME_DATA);
    }
    if (frame_type & kQuicFrameTypeSpecialMask) {
      // Stream Frame
      if (frame_type & kQuicFrameTypeStreamMask) {
        QuicStreamFrame frame;
        if (!ProcessStreamFrame(reader, frame_type, &frame)) {
          return RaiseError(QUIC_INVALID_STREAM_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing stream frame " << frame;
        if (!visitor_->OnStreamFrame(frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      // Ack Frame
      if (frame_type & kQuicFrameTypeAckMask) {
        if (!ProcessAckFrame(reader, frame_type)) {
          return RaiseError(QUIC_INVALID_ACK_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing ACK frame";
        continue;
      }

      // This was a special frame type that did not match any
      // of the known ones. Error.
      set_detailed_error("Illegal frame type.");
      QUIC_DLOG(WARNING) << ENDPOINT << "Illegal frame type: "
                         << static_cast<int>(frame_type);
      return RaiseError(QUIC_INVALID_FRAME_DATA);
    }

    switch (frame_type) {
      case PADDING_FRAME: {
        QuicPaddingFrame frame;
        ProcessPaddingFrame(reader, &frame);
        QUIC_DVLOG(2) << ENDPOINT << "Processing padding frame " << frame;
        if (!visitor_->OnPaddingFrame(frame)) {
          QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case RST_STREAM_FRAME: {
        QuicRstStreamFrame frame;
        if (!ProcessRstStreamFrame(reader, &frame)) {
          return RaiseError(QUIC_INVALID_RST_STREAM_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing reset stream frame " << frame;
        if (!visitor_->OnRstStreamFrame(frame)) {
          QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case CONNECTION_CLOSE_FRAME: {
        QuicConnectionCloseFrame frame;
        if (!ProcessConnectionCloseFrame(reader, &frame)) {
          return RaiseError(QUIC_INVALID_CONNECTION_CLOSE_DATA);
        }

        QUIC_DVLOG(2) << ENDPOINT << "Processing connection close frame "
                      << frame;
        if (!visitor_->OnConnectionCloseFrame(frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case GOAWAY_FRAME: {
        QuicGoAwayFrame goaway_frame;
        if (!ProcessGoAwayFrame(reader, &goaway_frame)) {
          return RaiseError(QUIC_INVALID_GOAWAY_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing go away frame "
                      << goaway_frame;
        if (!visitor_->OnGoAwayFrame(goaway_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case WINDOW_UPDATE_FRAME: {
        QuicWindowUpdateFrame window_update_frame;
        if (!ProcessWindowUpdateFrame(reader, &window_update_frame)) {
          return RaiseError(QUIC_INVALID_WINDOW_UPDATE_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing window update frame "
                      << window_update_frame;
        if (!visitor_->OnWindowUpdateFrame(window_update_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case BLOCKED_FRAME: {
        QuicBlockedFrame blocked_frame;
        if (!ProcessBlockedFrame(reader, &blocked_frame)) {
          return RaiseError(QUIC_INVALID_BLOCKED_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing blocked frame "
                      << blocked_frame;
        if (!visitor_->OnBlockedFrame(blocked_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case STOP_WAITING_FRAME: {
        QuicStopWaitingFrame stop_waiting_frame;
        if (!ProcessStopWaitingFrame(reader, header, &stop_waiting_frame)) {
          return RaiseError(QUIC_INVALID_STOP_WAITING_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing stop waiting frame "
                      << stop_waiting_frame;
        if (!visitor_->OnStopWaitingFrame(stop_waiting_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }
      case PING_FRAME: {
        // Ping has no payload.
        QuicPingFrame ping_frame;
        if (!visitor_->OnPingFrame(ping_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing ping frame " << ping_frame;
        continue;
      }
      case IETF_EXTENSION_MESSAGE_NO_LENGTH:
        ABSL_FALLTHROUGH_INTENDED;
      case IETF_EXTENSION_MESSAGE: {
        QUIC_CODE_COUNT(quic_legacy_message_frame_codepoint_read);
        QuicMessageFrame message_frame;
        if (!ProcessMessageFrame(reader,
                                 frame_type == IETF_EXTENSION_MESSAGE_NO_LENGTH,
                                 &message_frame)) {
          return RaiseError(QUIC_INVALID_MESSAGE_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing message frame "
                      << message_frame;
        if (!visitor_->OnMessageFrame(message_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        break;
      }
      case CRYPTO_FRAME: {
        if (!QuicVersionUsesCryptoFrames(version_.transport_version)) {
          set_detailed_error("Illegal frame type.");
          return RaiseError(QUIC_INVALID_FRAME_DATA);
        }
        QuicCryptoFrame frame;
        if (!ProcessCryptoFrame(reader, GetEncryptionLevel(header), &frame)) {
          return RaiseError(QUIC_INVALID_FRAME_DATA);
        }
        QUIC_DVLOG(2) << ENDPOINT << "Processing crypto frame " << frame;
        if (!visitor_->OnCryptoFrame(frame)) {
          QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        break;
      }
      case HANDSHAKE_DONE_FRAME: {
        // HANDSHAKE_DONE has no payload.
        QuicHandshakeDoneFrame handshake_done_frame;
        QUIC_DVLOG(2) << ENDPOINT << "Processing handshake done frame "
                      << handshake_done_frame;
        if (!visitor_->OnHandshakeDoneFrame(handshake_done_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        break;
      }

      default:
        set_detailed_error("Illegal frame type.");
        QUIC_DLOG(WARNING) << ENDPOINT << "Illegal frame type: "
                           << static_cast<int>(frame_type);
        return RaiseError(QUIC_INVALID_FRAME_DATA);
    }
  }

  return true;
}

// static
bool QuicFramer::IsIetfFrameTypeExpectedForEncryptionLevel(
    uint64_t frame_type, EncryptionLevel level) {
  // IETF_CRYPTO is allowed for any level here and is separately checked in
  // QuicCryptoStream::OnCryptoFrame.
  switch (level) {
    case ENCRYPTION_INITIAL:
    case ENCRYPTION_HANDSHAKE:
      return frame_type == IETF_CRYPTO || frame_type == IETF_ACK ||
             frame_type == IETF_ACK_ECN ||
             frame_type == IETF_ACK_RECEIVE_TIMESTAMPS ||
             frame_type == IETF_PING || frame_type == IETF_PADDING ||
             frame_type == IETF_CONNECTION_CLOSE;
    case ENCRYPTION_ZERO_RTT:
      return !(frame_type == IETF_ACK || frame_type == IETF_ACK_ECN ||
               frame_type == IETF_ACK_RECEIVE_TIMESTAMPS ||
               frame_type == IETF_HANDSHAKE_DONE ||
               frame_type == IETF_NEW_TOKEN ||
               frame_type == IETF_PATH_RESPONSE ||
               frame_type == IETF_RETIRE_CONNECTION_ID);
    case ENCRYPTION_FORWARD_SECURE:
      return true;
    default:
      QUIC_BUG(quic_bug_10850_57) << "Unknown encryption level: " << level;
  }
  return false;
}

bool QuicFramer::ProcessIetfFrameData(QuicDataReader* reader,
                                      const QuicPacketHeader& header,
                                      EncryptionLevel decrypted_level) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(version_.transport_version))
      << "Attempt to process frames as IETF frames but version ("
      << version_.transport_version << ") does not support IETF Framing.";

  if (reader->IsDoneReading()) {
    set_detailed_error("Packet has no frames.");
    return RaiseError(QUIC_MISSING_PAYLOAD);
  }

  QUIC_DVLOG(2) << ENDPOINT << "Processing IETF packet with header " << header;
  while (!reader->IsDoneReading()) {
    uint64_t frame_type;
    // Will be the number of bytes into which frame_type was encoded.
    size_t encoded_bytes = reader->BytesRemaining();
    if (!reader->ReadVarInt62(&frame_type)) {
      set_detailed_error("Unable to read frame type.");
      return RaiseError(QUIC_INVALID_FRAME_DATA);
    }
    if (!IsIetfFrameTypeExpectedForEncryptionLevel(frame_type,
                                                   decrypted_level)) {
      set_detailed_error(absl::StrCat(
          "IETF frame type ",
          QuicIetfFrameTypeString(static_cast<QuicIetfFrameType>(frame_type)),
          " is unexpected at encryption level ",
          EncryptionLevelToString(decrypted_level)));
      return RaiseError(IETF_QUIC_PROTOCOL_VIOLATION);
    }
    previously_received_frame_type_ = current_received_frame_type_;
    current_received_frame_type_ = frame_type;

    // Is now the number of bytes into which the frame type was encoded.
    encoded_bytes -= reader->BytesRemaining();

    // Check that the frame type is minimally encoded.
    if (encoded_bytes !=
        static_cast<size_t>(QuicDataWriter::GetVarInt62Len(frame_type))) {
      // The frame type was not minimally encoded.
      set_detailed_error("Frame type not minimally encoded.");
      return RaiseError(IETF_QUIC_PROTOCOL_VIOLATION);
    }

    if (IS_IETF_STREAM_FRAME(frame_type)) {
      QuicStreamFrame frame;
      if (!ProcessIetfStreamFrame(reader, frame_type, &frame)) {
        return RaiseError(QUIC_INVALID_STREAM_DATA);
      }
      QUIC_DVLOG(2) << ENDPOINT << "Processing IETF stream frame " << frame;
      if (!visitor_->OnStreamFrame(frame)) {
        QUIC_DVLOG(1) << ENDPOINT
                      << "Visitor asked to stop further processing.";
        // Returning true since there was no parsing error.
        return true;
      }
    } else {
      switch (frame_type) {
        case IETF_PADDING: {
          QuicPaddingFrame frame;
          ProcessPaddingFrame(reader, &frame);
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF padding frame "
                        << frame;
          if (!visitor_->OnPaddingFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_RST_STREAM: {
          QuicRstStreamFrame frame;
          if (!ProcessIetfResetStreamFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_RST_STREAM_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF reset stream frame "
                        << frame;
          if (!visitor_->OnRstStreamFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_APPLICATION_CLOSE:
        case IETF_CONNECTION_CLOSE: {
          QuicConnectionCloseFrame frame;
          if (!ProcessIetfConnectionCloseFrame(
                  reader,
                  (frame_type == IETF_CONNECTION_CLOSE)
                      ? IETF_QUIC_TRANSPORT_CONNECTION_CLOSE
                      : IETF_QUIC_APPLICATION_CONNECTION_CLOSE,
                  &frame)) {
            return RaiseError(QUIC_INVALID_CONNECTION_CLOSE_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF connection close frame "
                        << frame;
          if (!visitor_->OnConnectionCloseFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_MAX_DATA: {
          QuicWindowUpdateFrame frame;
          if (!ProcessMaxDataFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_MAX_DATA_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF max data frame "
                        << frame;
          if (!visitor_->OnWindowUpdateFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_MAX_STREAM_DATA: {
          QuicWindowUpdateFrame frame;
          if (!ProcessMaxStreamDataFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_MAX_STREAM_DATA_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF max stream data frame "
                        << frame;
          if (!visitor_->OnWindowUpdateFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_MAX_STREAMS_BIDIRECTIONAL:
        case IETF_MAX_STREAMS_UNIDIRECTIONAL: {
          QuicMaxStreamsFrame frame;
          if (!ProcessMaxStreamsFrame(reader, &frame, frame_type)) {
            return RaiseError(QUIC_MAX_STREAMS_DATA);
          }
          QUIC_CODE_COUNT_N(quic_max_streams_received, 1, 2);
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF max streams frame "
                        << frame;
          if (!visitor_->OnMaxStreamsFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_PING: {
          // Ping has no payload.
          QuicPingFrame ping_frame;
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF ping frame "
                        << ping_frame;
          if (!visitor_->OnPingFrame(ping_frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_DATA_BLOCKED: {
          QuicBlockedFrame frame;
          if (!ProcessDataBlockedFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_BLOCKED_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF blocked frame "
                        << frame;
          if (!visitor_->OnBlockedFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_STREAM_DATA_BLOCKED: {
          QuicBlockedFrame frame;
          if (!ProcessStreamDataBlockedFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_STREAM_BLOCKED_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF stream blocked frame "
                        << frame;
          if (!visitor_->OnBlockedFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_STREAMS_BLOCKED_UNIDIRECTIONAL:
        case IETF_STREAMS_BLOCKED_BIDIRECTIONAL: {
          QuicStreamsBlockedFrame frame;
          if (!ProcessStreamsBlockedFrame(reader, &frame, frame_type)) {
            return RaiseError(QUIC_STREAMS_BLOCKED_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF streams blocked frame "
                        << frame;
          if (!visitor_->OnStreamsBlockedFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_NEW_CONNECTION_ID: {
          QuicNewConnectionIdFrame frame;
          if (!ProcessNewConnectionIdFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_NEW_CONNECTION_ID_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT
                        << "Processing IETF new connection ID frame " << frame;
          if (!visitor_->OnNewConnectionIdFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_RETIRE_CONNECTION_ID: {
          QuicRetireConnectionIdFrame frame;
          if (!ProcessRetireConnectionIdFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_RETIRE_CONNECTION_ID_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT
                        << "Processing IETF retire connection ID frame "
                        << frame;
          if (!visitor_->OnRetireConnectionIdFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_NEW_TOKEN: {
          QuicNewTokenFrame frame;
          if (!ProcessNewTokenFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_NEW_TOKEN);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF new token frame "
                        << frame;
          if (!visitor_->OnNewTokenFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_STOP_SENDING: {
          QuicStopSendingFrame frame;
          if (!ProcessStopSendingFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_STOP_SENDING_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF stop sending frame "
                        << frame;
          if (!visitor_->OnStopSendingFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_ACK_RECEIVE_TIMESTAMPS:
          if (!process_timestamps_) {
            set_detailed_error("Unsupported frame type.");
            QUIC_DLOG(WARNING)
                << ENDPOINT << "IETF_ACK_RECEIVE_TIMESTAMPS not supported";
            return RaiseError(QUIC_INVALID_FRAME_DATA);
          }
          ABSL_FALLTHROUGH_INTENDED;
        case IETF_ACK_ECN:
        case IETF_ACK: {
          QuicAckFrame frame;
          if (!ProcessIetfAckFrame(reader, frame_type, &frame)) {
            return RaiseError(QUIC_INVALID_ACK_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF ACK frame " << frame;
          break;
        }
        case IETF_PATH_CHALLENGE: {
          QuicPathChallengeFrame frame;
          if (!ProcessPathChallengeFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_PATH_CHALLENGE_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF path challenge frame "
                        << frame;
          if (!visitor_->OnPathChallengeFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_PATH_RESPONSE: {
          QuicPathResponseFrame frame;
          if (!ProcessPathResponseFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_PATH_RESPONSE_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF path response frame "
                        << frame;
          if (!visitor_->OnPathResponseFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_EXTENSION_MESSAGE_NO_LENGTH_V99:
          ABSL_FALLTHROUGH_INTENDED;
        case IETF_EXTENSION_MESSAGE_V99: {
          QuicMessageFrame message_frame;
          if (!ProcessMessageFrame(
                  reader, frame_type == IETF_EXTENSION_MESSAGE_NO_LENGTH_V99,
                  &message_frame)) {
            return RaiseError(QUIC_INVALID_MESSAGE_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF message frame "
                        << message_frame;
          if (!visitor_->OnMessageFrame(message_frame)) {
            QUIC_DVLOG(1) << ENDPOINT
                          << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_CRYPTO: {
          QuicCryptoFrame frame;
          if (!ProcessCryptoFrame(reader, GetEncryptionLevel(header), &frame)) {
            return RaiseError(QUIC_INVALID_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF crypto frame " << frame;
          if (!visitor_->OnCryptoFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_HANDSHAKE_DONE: {
          // HANDSHAKE_DONE has no payload.
          QuicHandshakeDoneFrame handshake_done_frame;
          if (!visitor_->OnHandshakeDoneFrame(handshake_done_frame)) {
            QUIC_DVLOG(1) << ENDPOINT
                          << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing handshake done frame "
                        << handshake_done_frame;
          break;
        }
        case IETF_ACK_FREQUENCY: {
          QuicAckFrequencyFrame frame;
          if (!ProcessAckFrequencyFrame(reader, &frame)) {
            return RaiseError(QUIC_INVALID_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing IETF ack frequency frame "
                        << frame;
          if (!visitor_->OnAckFrequencyFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        case IETF_RESET_STREAM_AT: {
          if (!process_reset_stream_at_) {
            set_detailed_error("RESET_STREAM_AT not enabled.");
            return RaiseError(QUIC_INVALID_FRAME_DATA);
          }
          QuicResetStreamAtFrame frame;
          if (!ProcessResetStreamAtFrame(*reader, frame)) {
            return RaiseError(QUIC_INVALID_FRAME_DATA);
          }
          QUIC_DVLOG(2) << ENDPOINT << "Processing RESET_STREAM_AT frame "
                        << frame;
          if (!visitor_->OnResetStreamAtFrame(frame)) {
            QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
            // Returning true since there was no parsing error.
            return true;
          }
          break;
        }
        default:
          set_detailed_error("Illegal frame type.");
          QUIC_DLOG(WARNING)
              << ENDPOINT
              << "Illegal frame type: " << static_cast<int>(frame_type);
          return RaiseError(QUIC_INVALID_FRAME_DATA);
      }
    }
  }
  return true;
}

namespace {
// Create a mask that sets the last |num_bits| to 1 and the rest to 0.
inline uint8_t GetMaskFromNumBits(uint8_t num_bits) {
  return (1u << num_bits) - 1;
}

// Extract |num_bits| from |flags| offset by |offset|.
uint8_t ExtractBits(uint8_t flags, uint8_t num_bits, uint8_t offset) {
  return (flags >> offset) & GetMaskFromNumBits(num_bits);
}

// Extract the bit at position |offset| from |flags| as a bool.
bool ExtractBit(uint8_t flags, uint8_t offset) {
  return ((flags >> offset) & GetMaskFromNumBits(1)) != 0;
}

// Set |num_bits|, offset by |offset| to |val| in |flags|.
void SetBits(uint8_t* flags, uint8_t val, uint8_t num_bits, uint8_t offset) {
  QUICHE_DCHECK_LE(val, GetMaskFromNumBits(num_bits));
  *flags |= val << offset;
}

// Set the bit at position |offset| to |val| in |flags|.
void SetBit(uint8_t* flags, bool val, uint8_t offset) {
  SetBits(flags, val ? 1 : 0, 1, offset);
}
}  // namespace

bool QuicFramer::ProcessStreamFrame(QuicDataReader* reader, uint8_t frame_type,
                                    QuicStreamFrame* frame) {
  uint8_t stream_flags = frame_type;

  uint8_t stream_id_length = 0;
  uint8_t offset_length = 4;
  bool has_data_length = true;
  stream_flags &= ~kQuicFrameTypeStreamMask;

  // Read from right to left: StreamID, Offset, Data Length, Fin.
  stream_id_length = (stream_flags & kQuicStreamIDLengthMask) + 1;
  stream_flags >>= kQuicStreamIdShift;

  offset_length = (stream_flags & kQuicStreamOffsetMask);
  // There is no encoding for 1 byte, only 0 and 2 through 8.
  if (offset_length > 0) {
    offset_length += 1;
  }
  stream_flags >>= kQuicStreamShift;

  has_data_length =
      (stream_flags & kQuicStreamDataLengthMask) == kQuicStreamDataLengthMask;
  stream_flags >>= kQuicStreamDataLengthShift;

  frame->fin = (stream_flags & kQuicStreamFinMask) == kQuicStreamFinShift;

  uint64_t stream_id;
  if (!reader->ReadBytesToUInt64(stream_id_length, &stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }
  frame->stream_id = static_cast<QuicStreamId>(stream_id);

  if (!reader->ReadBytesToUInt64(offset_length, &frame->offset)) {
    set_detailed_error("Unable to read offset.");
    return false;
  }

  // TODO(ianswett): Don't use absl::string_view as an intermediary.
  absl::string_view data;
  if (has_data_length) {
    if (!reader->ReadStringPiece16(&data)) {
      set_detailed_error("Unable to read frame data.");
      return false;
    }
  } else {
    if (!reader->ReadStringPiece(&data, reader->BytesRemaining())) {
      set_detailed_error("Unable to read frame data.");
      return false;
    }
  }
  frame->data_buffer = data.data();
  frame->data_length = static_cast<uint16_t>(data.length());

  return true;
}

bool QuicFramer::ProcessIetfStreamFrame(QuicDataReader* reader,
                                        uint8_t frame_type,
                                        QuicStreamFrame* frame) {
  // Read stream id from the frame. It's always present.
  if (!ReadUint32FromVarint62(reader, IETF_STREAM, &frame->stream_id)) {
    return false;
  }

  // If we have a data offset, read it. If not, set to 0.
  if (frame_type & IETF_STREAM_FRAME_OFF_BIT) {
    if (!reader->ReadVarInt62(&frame->offset)) {
      set_detailed_error("Unable to read stream data offset.");
      return false;
    }
  } else {
    // no offset in the frame, ensure it's 0 in the Frame.
    frame->offset = 0;
  }

  // If we have a data length, read it. If not, set to 0.
  if (frame_type & IETF_STREAM_FRAME_LEN_BIT) {
    uint64_t length;
    if (!reader->ReadVarInt62(&length)) {
      set_detailed_error("Unable to read stream data length.");
      return false;
    }
    if (length > std::numeric_limits<decltype(frame->data_length)>::max()) {
      set_detailed_error("Stream data length is too large.");
      return false;
    }
    frame->data_length = length;
  } else {
    // no length in the frame, it is the number of bytes remaining in the
    // packet.
    frame->data_length = reader->BytesRemaining();
  }

  if (frame_type & IETF_STREAM_FRAME_FIN_BIT) {
    frame->fin = true;
  } else {
    frame->fin = false;
  }

  // TODO(ianswett): Don't use absl::string_view as an intermediary.
  absl::string_view data;
  if (!reader->ReadStringPiece(&data, frame->data_length)) {
    set_detailed_error("Unable to read frame data.");
    return false;
  }
  frame->data_buffer = data.data();
  QUICHE_DCHECK_EQ(frame->data_length, data.length());

  return true;
}

bool QuicFramer::ProcessCryptoFrame(QuicDataReader* reader,
                                    EncryptionLevel encryption_level,
                                    QuicCryptoFrame* frame) {
  frame->level = encryption_level;
  if (!reader->ReadVarInt62(&frame->offset)) {
    set_detailed_error("Unable to read crypto data offset.");
    return false;
  }
  uint64_t len;
  if (!reader->ReadVarInt62(&len) ||
      len > std::numeric_limits<QuicPacketLength>::max()) {
    set_detailed_error("Invalid data length.");
    return false;
  }
  frame->data_length = len;

  // TODO(ianswett): Don't use absl::string_view as an intermediary.
  absl::string_view data;
  if (!reader->ReadStringPiece(&data, frame->data_length)) {
    set_detailed_error("Unable to read frame data.");
    return false;
  }
  frame->data_buffer = data.data();
  return true;
}

bool QuicFramer::ProcessAckFrequencyFrame(QuicDataReader* reader,
                                          QuicAckFrequencyFrame* frame) {
  if (!reader->ReadVarInt62(&frame->sequence_number)) {
    set_detailed_error("Unable to read sequence number.");
    return false;
  }

  if (!reader->ReadVarInt62(&frame->packet_tolerance)) {
    set_detailed_error("Unable to read packet tolerance.");
    return false;
  }
  if (frame->packet_tolerance == 0) {
    set_detailed_error("Invalid packet tolerance.");
    return false;
  }
  uint64_t max_ack_delay_us;
  if (!reader->ReadVarInt62(&max_ack_delay_us)) {
    set_detailed_error("Unable to read max_ack_delay_us.");
    return false;
  }
  constexpr uint64_t kMaxAckDelayUsBound = 1u << 24;
  if (max_ack_delay_us > kMaxAckDelayUsBound) {
    set_detailed_error("Invalid max_ack_delay_us.");
    return false;
  }
  frame->max_ack_delay = QuicTime::Delta::FromMicroseconds(max_ack_delay_us);

  uint8_t ignore_order;
  if (!reader->ReadUInt8(&ignore_order)) {
    set_detailed_error("Unable to read ignore_order.");
    return false;
  }
  if (ignore_order > 1) {
    set_detailed_error("Invalid ignore_order.");
    return false;
  }
  frame->ignore_order = ignore_order;

  return true;
}

bool QuicFramer::ProcessResetStreamAtFrame(QuicDataReader& reader,
                                           QuicResetStreamAtFrame& frame) {
  if (!ReadUint32FromVarint62(&reader, IETF_RESET_STREAM_AT,
                              &frame.stream_id)) {
    return false;
  }
  if (!reader.ReadVarInt62(&frame.error)) {
    set_detailed_error("Failed to read the error code.");
    return false;
  }
  if (!reader.ReadVarInt62(&frame.final_offset)) {
    set_detailed_error("Failed to read the final offset.");
    return false;
  }
  if (!reader.
```