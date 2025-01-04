Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicFramer` class in Chromium's QUIC implementation.

Here's a breakdown of the code's actions:

1. **Frame Serialization:** The core function is to take a list of `QuicFrame` objects and write their binary representation into a buffer using `QuicDataWriter`. It handles different QUIC versions (IETF and Google QUIC) and their respective frame formats.

2. **Version Handling:** It checks the QUIC version to determine which serialization logic to use (`AppendIetfFrames` for IETF QUIC, or the older format).

3. **Frame Type Dispatch:**  A `switch` statement is used to handle each `QuicFrame` type (e.g., `STREAM_FRAME`, `ACK_FRAME`, `PADDING_FRAME`). For each type, it calls a specific `Append...Frame` function to serialize its contents.

4. **Error Handling:**  Throughout the serialization process, it checks for errors and uses `QUIC_BUG` for internal errors and `RaiseError` to signal invalid frame data or other issues. It also sets a detailed error message.

5. **IETF QUIC Specifics:**  The `AppendIetfFrames` function handles the serialization of IETF QUIC frame types, which are different from the older Google QUIC types. It also has checks for frames that are not valid in IETF QUIC.

6. **Length Encoding:** For IETF QUIC, it handles writing the length of the packet payload in the header.

7. **Public Reset and Stateless Reset:**  The code includes static methods for building public reset and stateless reset packets, which are used for connection termination.

8. **Version Negotiation:**  There's logic for building version negotiation packets, which are exchanged at the start of a connection to agree on a QUIC version. It handles both the older Google QUIC format and the IETF QUIC format.

9. **Packet Processing (Partial):** The code begins the process of receiving and parsing QUIC packets (`ProcessPacket`, `ProcessPacketInternal`, `ProcessIetfPacketHeader`). It handles version negotiation, retry packets, and the initial steps of processing data packets. It also touches on coalesced packets (multiple QUIC packets in a single UDP datagram).

**Relationship to Javascript:**

While this is C++ code, it directly relates to the underlying implementation of QUIC, which is the protocol used by modern web browsers (including Chrome, which uses this code) for faster and more reliable connections.

* **Web Browsers and Network Requests:**  When a Javascript application in a browser makes an HTTP/3 request (which uses QUIC), this C++ code is responsible for constructing and parsing the QUIC packets that carry the HTTP/3 data.

* **WebSockets over QUIC:** If WebSockets are used over QUIC, this code will handle the framing of WebSocket messages within QUIC streams.

* **Service Workers and Push Notifications:**  Service workers and push notifications often rely on efficient network connections, and QUIC (and thus this code) plays a role in enabling those features.

**Hypothetical Input and Output (Serialization):**

* **Input (frames):**  A `QuicFrames` object containing a `STREAM_FRAME` with stream ID 1, offset 0, and data "Hello", and a `PING_FRAME`.
* **Output (bytes written):** The function would return the number of bytes written to the `QuicDataWriter` representing the serialized `STREAM_FRAME` and `PING_FRAME`. The exact byte sequence depends on the QUIC version.

**User/Programming Errors:**

* **Appending IETF-specific frames in older QUIC versions:** The code explicitly checks for this and returns an error. For example, trying to append a `NEW_CONNECTION_ID_FRAME` when `VersionHasIetfQuicFrames` is false will trigger an error.

* **Incorrect frame data:** If the data within a `QuicFrame` is invalid (e.g., a negative stream ID), the corresponding `Append...Frame` function might fail, leading to a `QUIC_BUG` or a `RaiseError`.

* **Trying to append CRYPTO frames in older QUIC versions:** The code checks if the version supports crypto frames and returns an error if it doesn't.

**User Operations leading here (Debugging):**

1. **User opens a website that uses HTTP/3:** The browser initiates a QUIC connection to the server.
2. **Browser needs to send data:** The browser's networking stack (including this `quic_framer.cc` code) assembles the data into QUIC frames (e.g., `STREAM_FRAME` for HTTP request body).
3. **`AppendFrames` is called:**  The code snippet you provided is part of the process of serializing these QUIC frames into a packet to be sent over the network.
4. **Debugging scenario:** A developer might be debugging a network issue where packets are not being formed correctly. They might set a breakpoint in `AppendFrames` to inspect the frames being serialized and the output buffer.

**Summary of Functionality (Part 2):**

This part of `quic_framer.cc` focuses on the **serialization of a collection of `QuicFrame` objects into a raw byte stream.** It handles different QUIC versions, dispatches to specific serialization logic for each frame type, and includes error handling for invalid frame data or version mismatches. It is a crucial part of the QUIC implementation responsible for formatting the data to be sent over the network.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_framer.cc` 文件的一部分，它主要负责 **将多个 QUIC 帧（QuicFrame）序列化成字节流，以便将它们放入 QUIC 数据包中发送出去**。

具体来说，这部分代码的功能可以归纳为：

1. **根据 QUIC 版本选择序列化方法：** 代码首先检查当前使用的 QUIC 版本是否支持 IETF QUIC 帧格式 (`VersionHasIetfQuicFrames(transport_version())`)。
2. **IETF QUIC 帧序列化 (`AppendIetfFrames`)：** 如果是 IETF QUIC，则调用 `AppendIetfFrames` 函数来处理帧的序列化。这个函数会遍历 `frames` 列表，并根据每个帧的类型调用相应的 `AppendIetf...Frame` 函数进行序列化。
3. **旧版本 QUIC 帧序列化：** 如果不是 IETF QUIC，则代码会遍历 `frames` 列表，并根据每个帧的类型使用 `switch` 语句来调用相应的 `Append...Frame` 函数进行序列化。
4. **处理各种 QUIC 帧类型：** 代码支持序列化多种 QUIC 帧类型，例如：
    * `PADDING_FRAME` (填充帧)
    * `STREAM_FRAME` (流数据帧)
    * `ACK_FRAME` (确认帧)
    * `PING_FRAME` (心跳帧)
    * `RST_STREAM_FRAME` (重置流帧)
    * `CONNECTION_CLOSE_FRAME` (连接关闭帧)
    * `GOAWAY_FRAME` (停止接收新连接帧)
    * `WINDOW_UPDATE_FRAME` (窗口更新帧)
    * `BLOCKED_FRAME` (阻塞帧)
    * `NEW_CONNECTION_ID_FRAME` (新连接 ID 帧)
    * `RETIRE_CONNECTION_ID_FRAME` (废弃连接 ID 帧)
    * `NEW_TOKEN_FRAME` (新令牌帧)
    * `MAX_STREAMS_FRAME` (最大并发流帧)
    * `STREAMS_BLOCKED_FRAME` (流阻塞帧)
    * `PATH_RESPONSE_FRAME` (路径响应帧)
    * `PATH_CHALLENGE_FRAME` (路径挑战帧)
    * `STOP_SENDING_FRAME` (停止发送帧)
    * `MESSAGE_FRAME` (消息帧)
    * `CRYPTO_FRAME` (加密帧)
    * `HANDSHAKE_DONE_FRAME` (握手完成帧)
    * `ACK_FREQUENCY_FRAME` (确认频率帧)
    * `RESET_STREAM_AT_FRAME` (在指定偏移量重置流帧)
5. **错误处理：**  在序列化过程中，如果遇到不支持的帧类型或者在不兼容的 QUIC 版本中使用了特定的帧，代码会设置详细的错误信息并通过 `RaiseError` 函数抛出错误。
6. **写入数据到 `QuicDataWriter`：**  所有的帧数据都通过 `QuicDataWriter` 对象写入到缓冲区中。
7. **写入 IETF 长包头长度：**  在处理完所有帧后，如果是 IETF QUIC，代码还会调用 `WriteIetfLongHeaderLength` 来写入长包头的长度字段。

**与 Javascript 的功能关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的一部分，它直接负责 QUIC 协议的底层实现。虽然 Javascript 本身不直接操作这些底层的网络协议细节，但它通过浏览器提供的 API (例如 `fetch` API 或 WebSocket API) 发起网络请求时，底层的网络栈（包括这段 C++ 代码）会负责将 Javascript 的请求数据封装成 QUIC 数据包发送出去，并将接收到的 QUIC 数据包解析成 Javascript 可以理解的数据。

**举例说明：**

假设一个 Javascript 应用使用 `fetch` API 发起一个 HTTP/3 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，当浏览器需要发送请求头和请求体时，Chromium 的网络栈会创建 `STREAM_FRAME` 来承载这些数据。`AppendFrames` 函数就会被调用，并将这些 `STREAM_FRAME` 序列化成字节流，然后封装到 QUIC 数据包中发送到服务器。

**逻辑推理、假设输入与输出 (以 `STREAM_FRAME` 为例)：**

**假设输入：**

* `frames`: 一个包含单个 `STREAM_FRAME` 的 `QuicFrames` 对象。
    * `stream_id`: 1
    * `offset`: 0
    * `data`: "Hello"
    * `fin`: true (表示这是流的最后一个数据帧)
* `writer`: 一个空的 `QuicDataWriter` 对象。
* `transport_version()`: 返回一个不支持 IETF QUIC 的版本 (例如旧版本的 Google QUIC)。

**输出：**

* `writer` 的内容将会包含序列化后的 `STREAM_FRAME` 数据，具体格式取决于 QUIC 版本，可能包括：
    * 类型字节（标识这是一个 `STREAM_FRAME`，并可能包含 FIN 标志）
    * 流 ID (1)
    * 偏移量 (0)
    * 数据长度 (5)
    * 数据 ("Hello")
* 函数的返回值是写入 `writer` 的字节数。

**用户或编程常见的使用错误举例说明：**

* **错误地在旧版本 QUIC 中尝试添加 IETF 特有的帧：**  如果开发者错误地尝试在不支持 IETF QUIC 的版本中添加 `NEW_CONNECTION_ID_FRAME`，`AppendFrames` 函数会进入相应的 `case` 分支，设置错误信息，并返回错误代码。

   ```c++
   case NEW_CONNECTION_ID_FRAME:
     set_detailed_error(
         "Attempt to append NEW_CONNECTION_ID frame and not in IETF QUIC.");
     return RaiseError(QUIC_INTERNAL_ERROR);
   ```

* **构造了不合法的 `QuicFrame` 对象：** 例如，创建一个 `STREAM_FRAME`，其偏移量大于已发送的数据量，可能会导致 `AppendStreamFrame` 函数内部出现错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定目标服务器的 IP 地址和端口。**
3. **如果使用 HTTP/3，浏览器会尝试与服务器建立 QUIC 连接。**
4. **在数据传输阶段，当浏览器需要发送数据时 (例如 HTTP 请求的 body)，网络栈会创建 `QuicFrame` 对象来承载这些数据。**
5. **`QuicFramer::AppendFrames` 函数被调用，将这些 `QuicFrame` 序列化成字节流。**
6. **序列化后的数据会被传递给更底层的网络层进行发送。**

在调试过程中，如果怀疑数据包的格式有问题，开发者可能会在 `QuicFramer::AppendFrames` 函数中设置断点，查看传入的 `frames` 内容，以及 `QuicDataWriter` 的内容，来确定帧是否被正确序列化。

总而言之，这段代码是 QUIC 协议实现的核心部分，负责将抽象的 QUIC 帧结构转换为可以在网络上传输的二进制数据。理解它的功能有助于理解浏览器如何使用 QUIC 协议进行网络通信。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共9部分，请归纳一下它的功能

"""
0;
  }

  if (VersionHasIetfQuicFrames(transport_version())) {
    if (AppendIetfFrames(frames, &writer) == 0) {
      return 0;
    }
    if (!WriteIetfLongHeaderLength(header, &writer, length_field_offset,
                                   level)) {
      return 0;
    }
    return writer.length();
  }

  size_t i = 0;
  for (const QuicFrame& frame : frames) {
    // Determine if we should write stream frame length in header.
    const bool last_frame_in_packet = i == frames.size() - 1;
    if (!AppendTypeByte(frame, last_frame_in_packet, &writer)) {
      QUIC_BUG(quic_bug_10850_17) << "AppendTypeByte failed";
      return 0;
    }

    switch (frame.type) {
      case PADDING_FRAME:
        if (!AppendPaddingFrame(frame.padding_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_18)
              << "AppendPaddingFrame of "
              << frame.padding_frame.num_padding_bytes << " failed";
          return 0;
        }
        break;
      case STREAM_FRAME:
        if (!AppendStreamFrame(frame.stream_frame, last_frame_in_packet,
                               &writer)) {
          QUIC_BUG(quic_bug_10850_19) << "AppendStreamFrame failed";
          return 0;
        }
        break;
      case ACK_FRAME:
        if (!AppendAckFrameAndTypeByte(*frame.ack_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_20)
              << "AppendAckFrameAndTypeByte failed: " << detailed_error_;
          return 0;
        }
        break;
      case MTU_DISCOVERY_FRAME:
        // MTU discovery frames are serialized as ping frames.
        ABSL_FALLTHROUGH_INTENDED;
      case PING_FRAME:
        // Ping has no payload.
        break;
      case RST_STREAM_FRAME:
        if (!AppendRstStreamFrame(*frame.rst_stream_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_22) << "AppendRstStreamFrame failed";
          return 0;
        }
        break;
      case CONNECTION_CLOSE_FRAME:
        if (!AppendConnectionCloseFrame(*frame.connection_close_frame,
                                        &writer)) {
          QUIC_BUG(quic_bug_10850_23) << "AppendConnectionCloseFrame failed";
          return 0;
        }
        break;
      case GOAWAY_FRAME:
        if (!AppendGoAwayFrame(*frame.goaway_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_24) << "AppendGoAwayFrame failed";
          return 0;
        }
        break;
      case WINDOW_UPDATE_FRAME:
        if (!AppendWindowUpdateFrame(frame.window_update_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_25) << "AppendWindowUpdateFrame failed";
          return 0;
        }
        break;
      case BLOCKED_FRAME:
        if (!AppendBlockedFrame(frame.blocked_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_26) << "AppendBlockedFrame failed";
          return 0;
        }
        break;
      case NEW_CONNECTION_ID_FRAME:
        set_detailed_error(
            "Attempt to append NEW_CONNECTION_ID frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case RETIRE_CONNECTION_ID_FRAME:
        set_detailed_error(
            "Attempt to append RETIRE_CONNECTION_ID frame and not in IETF "
            "QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case NEW_TOKEN_FRAME:
        set_detailed_error(
            "Attempt to append NEW_TOKEN_ID frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case MAX_STREAMS_FRAME:
        set_detailed_error(
            "Attempt to append MAX_STREAMS frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case STREAMS_BLOCKED_FRAME:
        set_detailed_error(
            "Attempt to append STREAMS_BLOCKED frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case PATH_RESPONSE_FRAME:
        set_detailed_error(
            "Attempt to append PATH_RESPONSE frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case PATH_CHALLENGE_FRAME:
        set_detailed_error(
            "Attempt to append PATH_CHALLENGE frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case STOP_SENDING_FRAME:
        set_detailed_error(
            "Attempt to append STOP_SENDING frame and not in IETF QUIC.");
        return RaiseError(QUIC_INTERNAL_ERROR);
      case MESSAGE_FRAME:
        if (!AppendMessageFrameAndTypeByte(*frame.message_frame,
                                           last_frame_in_packet, &writer)) {
          QUIC_BUG(quic_bug_10850_27) << "AppendMessageFrame failed";
          return 0;
        }
        break;
      case CRYPTO_FRAME:
        if (!QuicVersionUsesCryptoFrames(version_.transport_version)) {
          set_detailed_error(
              "Attempt to append CRYPTO frame in version prior to 47.");
          return RaiseError(QUIC_INTERNAL_ERROR);
        }
        if (!AppendCryptoFrame(*frame.crypto_frame, &writer)) {
          QUIC_BUG(quic_bug_10850_28) << "AppendCryptoFrame failed";
          return 0;
        }
        break;
      case HANDSHAKE_DONE_FRAME:
        // HANDSHAKE_DONE has no payload.
        break;
      default:
        RaiseError(QUIC_INVALID_FRAME_DATA);
        QUIC_BUG(quic_bug_10850_29) << "QUIC_INVALID_FRAME_DATA";
        return 0;
    }
    ++i;
  }

  if (!WriteIetfLongHeaderLength(header, &writer, length_field_offset, level)) {
    return 0;
  }

  return writer.length();
}

size_t QuicFramer::AppendIetfFrames(const QuicFrames& frames,
                                    QuicDataWriter* writer) {
  size_t i = 0;
  for (const QuicFrame& frame : frames) {
    // Determine if we should write stream frame length in header.
    const bool last_frame_in_packet = i == frames.size() - 1;
    if (!AppendIetfFrameType(frame, last_frame_in_packet, writer)) {
      QUIC_BUG(quic_bug_10850_30)
          << "AppendIetfFrameType failed: " << detailed_error();
      return 0;
    }

    switch (frame.type) {
      case PADDING_FRAME:
        if (!AppendPaddingFrame(frame.padding_frame, writer)) {
          QUIC_BUG(quic_bug_10850_31) << "AppendPaddingFrame of "
                                      << frame.padding_frame.num_padding_bytes
                                      << " failed: " << detailed_error();
          return 0;
        }
        break;
      case STREAM_FRAME:
        if (!AppendStreamFrame(frame.stream_frame, last_frame_in_packet,
                               writer)) {
          QUIC_BUG(quic_bug_10850_32)
              << "AppendStreamFrame " << frame.stream_frame
              << " failed: " << detailed_error();
          return 0;
        }
        break;
      case ACK_FRAME:
        if (!AppendIetfAckFrameAndTypeByte(*frame.ack_frame, writer)) {
          QUIC_BUG(quic_bug_10850_33)
              << "AppendIetfAckFrameAndTypeByte failed: " << detailed_error();
          return 0;
        }
        break;
      case STOP_WAITING_FRAME:
        set_detailed_error(
            "Attempt to append STOP WAITING frame in IETF QUIC.");
        RaiseError(QUIC_INTERNAL_ERROR);
        QUIC_BUG(quic_bug_10850_34) << detailed_error();
        return 0;
      case MTU_DISCOVERY_FRAME:
        // MTU discovery frames are serialized as ping frames.
        ABSL_FALLTHROUGH_INTENDED;
      case PING_FRAME:
        // Ping has no payload.
        break;
      case RST_STREAM_FRAME:
        if (!AppendRstStreamFrame(*frame.rst_stream_frame, writer)) {
          QUIC_BUG(quic_bug_10850_35)
              << "AppendRstStreamFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case CONNECTION_CLOSE_FRAME:
        if (!AppendIetfConnectionCloseFrame(*frame.connection_close_frame,
                                            writer)) {
          QUIC_BUG(quic_bug_10850_36)
              << "AppendIetfConnectionCloseFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case GOAWAY_FRAME:
        set_detailed_error("Attempt to append GOAWAY frame in IETF QUIC.");
        RaiseError(QUIC_INTERNAL_ERROR);
        QUIC_BUG(quic_bug_10850_37) << detailed_error();
        return 0;
      case WINDOW_UPDATE_FRAME:
        // Depending on whether there is a stream ID or not, will be either a
        // MAX STREAM DATA frame or a MAX DATA frame.
        if (frame.window_update_frame.stream_id ==
            QuicUtils::GetInvalidStreamId(transport_version())) {
          if (!AppendMaxDataFrame(frame.window_update_frame, writer)) {
            QUIC_BUG(quic_bug_10850_38)
                << "AppendMaxDataFrame failed: " << detailed_error();
            return 0;
          }
        } else {
          if (!AppendMaxStreamDataFrame(frame.window_update_frame, writer)) {
            QUIC_BUG(quic_bug_10850_39)
                << "AppendMaxStreamDataFrame failed: " << detailed_error();
            return 0;
          }
        }
        break;
      case BLOCKED_FRAME:
        if (!AppendBlockedFrame(frame.blocked_frame, writer)) {
          QUIC_BUG(quic_bug_10850_40)
              << "AppendBlockedFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case MAX_STREAMS_FRAME:
        if (!AppendMaxStreamsFrame(frame.max_streams_frame, writer)) {
          QUIC_BUG(quic_bug_10850_41)
              << "AppendMaxStreamsFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case STREAMS_BLOCKED_FRAME:
        if (!AppendStreamsBlockedFrame(frame.streams_blocked_frame, writer)) {
          QUIC_BUG(quic_bug_10850_42)
              << "AppendStreamsBlockedFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case NEW_CONNECTION_ID_FRAME:
        if (!AppendNewConnectionIdFrame(*frame.new_connection_id_frame,
                                        writer)) {
          QUIC_BUG(quic_bug_10850_43)
              << "AppendNewConnectionIdFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case RETIRE_CONNECTION_ID_FRAME:
        if (!AppendRetireConnectionIdFrame(*frame.retire_connection_id_frame,
                                           writer)) {
          QUIC_BUG(quic_bug_10850_44)
              << "AppendRetireConnectionIdFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case NEW_TOKEN_FRAME:
        if (!AppendNewTokenFrame(*frame.new_token_frame, writer)) {
          QUIC_BUG(quic_bug_10850_45)
              << "AppendNewTokenFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case STOP_SENDING_FRAME:
        if (!AppendStopSendingFrame(frame.stop_sending_frame, writer)) {
          QUIC_BUG(quic_bug_10850_46)
              << "AppendStopSendingFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case PATH_CHALLENGE_FRAME:
        if (!AppendPathChallengeFrame(frame.path_challenge_frame, writer)) {
          QUIC_BUG(quic_bug_10850_47)
              << "AppendPathChallengeFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case PATH_RESPONSE_FRAME:
        if (!AppendPathResponseFrame(frame.path_response_frame, writer)) {
          QUIC_BUG(quic_bug_10850_48)
              << "AppendPathResponseFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case MESSAGE_FRAME:
        if (!AppendMessageFrameAndTypeByte(*frame.message_frame,
                                           last_frame_in_packet, writer)) {
          QUIC_BUG(quic_bug_10850_49)
              << "AppendMessageFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case CRYPTO_FRAME:
        if (!AppendCryptoFrame(*frame.crypto_frame, writer)) {
          QUIC_BUG(quic_bug_10850_50)
              << "AppendCryptoFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case HANDSHAKE_DONE_FRAME:
        // HANDSHAKE_DONE has no payload.
        break;
      case ACK_FREQUENCY_FRAME:
        if (!AppendAckFrequencyFrame(*frame.ack_frequency_frame, writer)) {
          QUIC_BUG(quic_bug_10850_51)
              << "AppendAckFrequencyFrame failed: " << detailed_error();
          return 0;
        }
        break;
      case RESET_STREAM_AT_FRAME:
        QUIC_BUG_IF(reset_stream_at_appended_while_disabled,
                    !process_reset_stream_at_)
            << "Requested serialization of RESET_STREAM_AT_FRAME while it is "
               "not explicitly enabled in the framer";
        if (!AppendResetFrameAtFrame(*frame.reset_stream_at_frame, *writer)) {
          QUIC_BUG(cannot_append_reset_stream_at)
              << "AppendResetStreamAtFram failed: " << detailed_error();
          return 0;
        }
        break;
      default:
        set_detailed_error("Tried to append unknown frame type.");
        RaiseError(QUIC_INVALID_FRAME_DATA);
        QUIC_BUG(quic_bug_10850_52)
            << "QUIC_INVALID_FRAME_DATA: " << frame.type;
        return 0;
    }
    ++i;
  }

  return writer->length();
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildPublicResetPacket(
    const QuicPublicResetPacket& packet) {
  CryptoHandshakeMessage reset;
  reset.set_tag(kPRST);
  reset.SetValue(kRNON, packet.nonce_proof);
  if (packet.client_address.host().address_family() !=
      IpAddressFamily::IP_UNSPEC) {
    // packet.client_address is non-empty.
    QuicSocketAddressCoder address_coder(packet.client_address);
    std::string serialized_address = address_coder.Encode();
    if (serialized_address.empty()) {
      return nullptr;
    }
    reset.SetStringPiece(kCADR, serialized_address);
  }
  if (!packet.endpoint_id.empty()) {
    reset.SetStringPiece(kEPID, packet.endpoint_id);
  }
  const QuicData& reset_serialized = reset.GetSerialized();

  size_t len = kPublicFlagsSize + packet.connection_id.length() +
               reset_serialized.length();
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());

  uint8_t flags = static_cast<uint8_t>(PACKET_PUBLIC_FLAGS_RST |
                                       PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID);
  // This hack makes post-v33 public reset packet look like pre-v33 packets.
  flags |= static_cast<uint8_t>(PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD);
  if (!writer.WriteUInt8(flags)) {
    return nullptr;
  }

  if (!writer.WriteConnectionId(packet.connection_id)) {
    return nullptr;
  }

  if (!writer.WriteBytes(reset_serialized.data(), reset_serialized.length())) {
    return nullptr;
  }

  return std::make_unique<QuicEncryptedPacket>(buffer.release(), len, true);
}

// static
size_t QuicFramer::GetMinStatelessResetPacketLength() {
  // 5 bytes (40 bits) = 2 Fixed Bits (01) + 38 Unpredictable bits
  return 5 + kStatelessResetTokenLength;
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildIetfStatelessResetPacket(
    QuicConnectionId connection_id, size_t received_packet_length,
    StatelessResetToken stateless_reset_token) {
  return BuildIetfStatelessResetPacket(connection_id, received_packet_length,
                                       stateless_reset_token,
                                       QuicRandom::GetInstance());
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildIetfStatelessResetPacket(
    QuicConnectionId /*connection_id*/, size_t received_packet_length,
    StatelessResetToken stateless_reset_token, QuicRandom* random) {
  QUIC_DVLOG(1) << "Building IETF stateless reset packet.";
  if (received_packet_length <= GetMinStatelessResetPacketLength()) {
    QUICHE_DLOG(ERROR)
        << "Tried to build stateless reset packet with received packet "
           "length "
        << received_packet_length;
    return nullptr;
  }
  // To ensure stateless reset is indistinguishable from a valid packet,
  // include the max connection ID length.
  size_t len = std::min(received_packet_length - 1,
                        GetMinStatelessResetPacketLength() + 1 +
                            kQuicMaxConnectionIdWithLengthPrefixLength);
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());
  // Append random bytes. This randomness only exists to prevent middleboxes
  // from comparing the entire packet to a known value. Therefore it has no
  // cryptographic use, and does not need a secure cryptographic pseudo-random
  // number generator. It's therefore safe to use WriteInsecureRandomBytes.
  const size_t random_bytes_size = len - kStatelessResetTokenLength;
  if (!writer.WriteInsecureRandomBytes(random, random_bytes_size)) {
    QUIC_BUG(362045737_2) << "Failed to append random bytes of length: "
                          << random_bytes_size;
    return nullptr;
  }
  // Change first 2 fixed bits to 01.
  buffer[0] &= ~FLAGS_LONG_HEADER;
  buffer[0] |= FLAGS_FIXED_BIT;

  // Append stateless reset token.
  if (!writer.WriteBytes(&stateless_reset_token,
                         sizeof(stateless_reset_token))) {
    QUIC_BUG(362045737_3) << "Failed to write stateless reset token";
    return nullptr;
  }
  return std::make_unique<QuicEncryptedPacket>(buffer.release(), len,
                                               /*owns_buffer=*/true);
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildVersionNegotiationPacket(
    QuicConnectionId server_connection_id,
    QuicConnectionId client_connection_id, bool ietf_quic,
    bool use_length_prefix, const ParsedQuicVersionVector& versions) {
  QUIC_CODE_COUNT(quic_build_version_negotiation);
  if (use_length_prefix) {
    QUICHE_DCHECK(ietf_quic);
    QUIC_CODE_COUNT(quic_build_version_negotiation_ietf);
  } else if (ietf_quic) {
    QUIC_CODE_COUNT(quic_build_version_negotiation_old_ietf);
  } else {
    QUIC_CODE_COUNT(quic_build_version_negotiation_old_gquic);
  }
  ParsedQuicVersionVector wire_versions = versions;
  // Add a version reserved for negotiation as suggested by the
  // "Using Reserved Versions" section of draft-ietf-quic-transport.
  if (wire_versions.empty()) {
    // Ensure that version negotiation packets we send have at least two
    // versions. This guarantees that, under all circumstances, all QUIC
    // packets we send are at least 14 bytes long.
    wire_versions = {QuicVersionReservedForNegotiation(),
                     QuicVersionReservedForNegotiation()};
  } else {
    // This is not uniformely distributed but is acceptable since no security
    // depends on this randomness.
    size_t version_index = 0;
    const bool disable_randomness =
        GetQuicFlag(quic_disable_version_negotiation_grease_randomness);
    if (!disable_randomness) {
      version_index =
          QuicRandom::GetInstance()->RandUint64() % (wire_versions.size() + 1);
    }
    wire_versions.insert(wire_versions.begin() + version_index,
                         QuicVersionReservedForNegotiation());
  }
  if (ietf_quic) {
    return BuildIetfVersionNegotiationPacket(
        use_length_prefix, server_connection_id, client_connection_id,
        wire_versions);
  }

  // The GQUIC encoding does not support encoding client connection IDs.
  QUICHE_DCHECK(client_connection_id.IsEmpty());
  // The GQUIC encoding does not support length-prefixed connection IDs.
  QUICHE_DCHECK(!use_length_prefix);

  QUICHE_DCHECK(!wire_versions.empty());
  size_t len = kPublicFlagsSize + server_connection_id.length() +
               wire_versions.size() * kQuicVersionSize;
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());

  uint8_t flags = static_cast<uint8_t>(
      PACKET_PUBLIC_FLAGS_VERSION | PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID |
      PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD);
  if (!writer.WriteUInt8(flags)) {
    return nullptr;
  }

  if (!writer.WriteConnectionId(server_connection_id)) {
    return nullptr;
  }

  for (const ParsedQuicVersion& version : wire_versions) {
    if (!writer.WriteUInt32(CreateQuicVersionLabel(version))) {
      return nullptr;
    }
  }

  return std::make_unique<QuicEncryptedPacket>(buffer.release(), len, true);
}

// static
std::unique_ptr<QuicEncryptedPacket>
QuicFramer::BuildIetfVersionNegotiationPacket(
    bool use_length_prefix, QuicConnectionId server_connection_id,
    QuicConnectionId client_connection_id,
    const ParsedQuicVersionVector& versions) {
  QUIC_DVLOG(1) << "Building IETF version negotiation packet with"
                << (use_length_prefix ? "" : "out")
                << " length prefix, server_connection_id "
                << server_connection_id << " client_connection_id "
                << client_connection_id << " versions "
                << ParsedQuicVersionVectorToString(versions);
  QUICHE_DCHECK(!versions.empty());
  size_t len = kPacketHeaderTypeSize + kConnectionIdLengthSize +
               client_connection_id.length() + server_connection_id.length() +
               (versions.size() + 1) * kQuicVersionSize;
  if (use_length_prefix) {
    // When using length-prefixed connection IDs, packets carry two lengths
    // instead of one.
    len += kConnectionIdLengthSize;
  }
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());

  // TODO(fayang): Randomly select a value for the type.
  uint8_t type = static_cast<uint8_t>(FLAGS_LONG_HEADER | FLAGS_FIXED_BIT);
  if (!writer.WriteUInt8(type)) {
    return nullptr;
  }

  if (!writer.WriteUInt32(0)) {
    return nullptr;
  }

  if (!AppendIetfConnectionIds(true, use_length_prefix, client_connection_id,
                               server_connection_id, &writer)) {
    return nullptr;
  }

  for (const ParsedQuicVersion& version : versions) {
    if (!writer.WriteUInt32(CreateQuicVersionLabel(version))) {
      return nullptr;
    }
  }

  return std::make_unique<QuicEncryptedPacket>(buffer.release(), len, true);
}

bool QuicFramer::ProcessPacket(const QuicEncryptedPacket& packet) {
  QUICHE_DCHECK(!is_processing_packet_) << ENDPOINT << "Nested ProcessPacket";
  is_processing_packet_ = true;
  bool result = ProcessPacketInternal(packet);
  is_processing_packet_ = false;
  return result;
}

bool QuicFramer::ProcessPacketInternal(const QuicEncryptedPacket& packet) {
  QuicDataReader reader(packet.data(), packet.length());
  QUIC_DVLOG(1) << ENDPOINT << "Processing IETF QUIC packet.";

  visitor_->OnPacket();

  QuicPacketHeader header;
  if (!ProcessIetfPacketHeader(&reader, &header)) {
    QUICHE_DCHECK_NE("", detailed_error_);
    QUIC_DVLOG(1) << ENDPOINT << "Unable to process public header. Error: "
                  << detailed_error_;
    QUICHE_DCHECK_NE("", detailed_error_);
    RecordDroppedPacketReason(DroppedPacketReason::INVALID_PUBLIC_HEADER);
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  if (!visitor_->OnUnauthenticatedPublicHeader(header)) {
    // The visitor suppresses further processing of the packet.
    return true;
  }

  if (IsVersionNegotiation(header)) {
    if (perspective_ == Perspective::IS_CLIENT) {
      QUIC_DVLOG(1) << "Client received version negotiation packet";
      return ProcessVersionNegotiationPacket(&reader, header);
    } else {
      QUIC_DLOG(ERROR) << "Server received version negotiation packet";
      set_detailed_error("Server received version negotiation packet.");
      return RaiseError(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    }
  }

  if (header.version_flag && header.version != version_) {
    if (perspective_ == Perspective::IS_SERVER) {
      if (!visitor_->OnProtocolVersionMismatch(header.version)) {
        RecordDroppedPacketReason(DroppedPacketReason::VERSION_MISMATCH);
        return true;
      }
    } else {
      // A client received a packet of a different version but that packet is
      // not a version negotiation packet. It is therefore invalid and dropped.
      QUIC_DLOG(ERROR) << "Client received unexpected version "
                       << ParsedQuicVersionToString(header.version)
                       << " instead of " << ParsedQuicVersionToString(version_);
      set_detailed_error("Client received unexpected version.");
      return RaiseError(QUIC_PACKET_WRONG_VERSION);
    }
  }

  bool rv;
  if (header.long_packet_type == RETRY) {
    rv = ProcessRetryPacket(&reader, header);
  } else if (packet.length() <= kMaxIncomingPacketSize) {
    // The optimized decryption algorithm implementations run faster when
    // operating on aligned memory.
    ABSL_CACHELINE_ALIGNED char buffer[kMaxIncomingPacketSize];
    rv = ProcessIetfDataPacket(&reader, &header, packet, buffer,
                               ABSL_ARRAYSIZE(buffer));
  } else {
    std::unique_ptr<char[]> large_buffer(new char[packet.length()]);
    rv = ProcessIetfDataPacket(&reader, &header, packet, large_buffer.get(),
                               packet.length());
    QUIC_BUG_IF(quic_bug_10850_53, rv)
        << "QUIC should never successfully process packets larger"
        << "than kMaxIncomingPacketSize. packet size:" << packet.length();
  }
  return rv;
}

bool QuicFramer::ProcessVersionNegotiationPacket(
    QuicDataReader* reader, const QuicPacketHeader& header) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);

  QuicVersionNegotiationPacket packet(
      GetServerConnectionIdAsRecipient(header, perspective_));
  // Try reading at least once to raise error if the packet is invalid.
  do {
    QuicVersionLabel version_label;
    if (!ProcessVersionLabel(reader, &version_label)) {
      set_detailed_error("Unable to read supported version in negotiation.");
      RecordDroppedPacketReason(
          DroppedPacketReason::INVALID_VERSION_NEGOTIATION_PACKET);
      return RaiseError(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    }
    ParsedQuicVersion parsed_version = ParseQuicVersionLabel(version_label);
    if (parsed_version != UnsupportedQuicVersion()) {
      packet.versions.push_back(parsed_version);
    }
  } while (!reader->IsDoneReading());

  QUIC_DLOG(INFO) << ENDPOINT << "parsed version negotiation: "
                  << ParsedQuicVersionVectorToString(packet.versions);

  visitor_->OnVersionNegotiationPacket(packet);
  return true;
}

bool QuicFramer::ProcessRetryPacket(QuicDataReader* reader,
                                    const QuicPacketHeader& header) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
  if (drop_incoming_retry_packets_) {
    QUIC_DLOG(INFO) << "Ignoring received RETRY packet";
    return true;
  }

  if (version_.UsesTls()) {
    QUICHE_DCHECK(version_.HasLengthPrefixedConnectionIds()) << version_;
    const size_t bytes_remaining = reader->BytesRemaining();
    if (bytes_remaining <= kRetryIntegrityTagLength) {
      set_detailed_error("Retry packet too short to parse integrity tag.");
      return false;
    }
    const size_t retry_token_length =
        bytes_remaining - kRetryIntegrityTagLength;
    QUICHE_DCHECK_GT(retry_token_length, 0u);
    absl::string_view retry_token;
    if (!reader->ReadStringPiece(&retry_token, retry_token_length)) {
      set_detailed_error("Failed to read retry token.");
      return false;
    }
    absl::string_view retry_without_tag = reader->PreviouslyReadPayload();
    absl::string_view integrity_tag = reader->ReadRemainingPayload();
    QUICHE_DCHECK_EQ(integrity_tag.length(), kRetryIntegrityTagLength);
    visitor_->OnRetryPacket(EmptyQuicConnectionId(),
                            header.source_connection_id, retry_token,
                            integrity_tag, retry_without_tag);
    return true;
  }

  QuicConnectionId original_destination_connection_id;
  if (version_.HasLengthPrefixedConnectionIds()) {
    // Parse Original Destination Connection ID.
    if (!reader->ReadLengthPrefixedConnectionId(
            &original_destination_connection_id)) {
      set_detailed_error("Unable to read Original Destination ConnectionId.");
      return false;
    }
  } else {
    // Parse Original Destination Connection ID Length.
    uint8_t odcil = header.type_byte & 0xf;
    if (odcil != 0) {
      odcil += kConnectionIdLengthAdjustment;
    }

    // Parse Original Destination Connection ID.
    if (!reader->ReadConnectionId(&original_destination_connection_id, odcil)) {
      set_detailed_error("Unable to read Original Destination ConnectionId.");
      return false;
    }
  }

  if (!QuicUtils::IsConnectionIdValidForVersion(
          original_destination_connection_id, transport_version())) {
    set_detailed_error(
        "Received Original Destination ConnectionId with invalid length.");
    return false;
  }

  absl::string_view retry_token = reader->ReadRemainingPayload();
  visitor_->OnRetryPacket(original_destination_connection_id,
                          header.source_connection_id, retry_token,
                          /*retry_integrity_tag=*/absl::string_view(),
                          /*retry_without_tag=*/absl::string_view());
  return true;
}

// Seeks the current packet to check for a coalesced packet at the end.
// If the IETF length field only spans part of the outer packet,
// then there is a coalesced packet after this one.
void QuicFramer::MaybeProcessCoalescedPacket(
    const QuicDataReader& encrypted_reader, uint64_t remaining_bytes_length,
    const QuicPacketHeader& header) {
  if (header.remaining_packet_length >= remaining_bytes_length) {
    // There is no coalesced packet.
    return;
  }

  absl::string_view remaining_data = encrypted_reader.PeekRemainingPayload();
  QUICHE_DCHECK_EQ(remaining_data.length(), remaining_bytes_length);

  const char* coalesced_data =
      remaining_data.data() + header.remaining_packet_length;
  uint64_t coalesced_data_length =
      remaining_bytes_length - header.remaining_packet_length;
  QuicDataReader coalesced_reader(coalesced_data, coalesced_data_length);

  QuicPacketHeader coalesced_header;
  if (!ProcessIetfPacketHeader(&coalesced_reader, &coalesced_header)) {
    // Some implementations pad their INITIAL packets by sending random invalid
    // data after the INITIAL, and that is allowed by the specification. If we
    // fail to parse a subsequent coalesced packet, simply ignore it.
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Failed to parse received coalesced header of length "
                    << coalesced_data_length
                    << " with error: " << detailed_error_ << ": "
                    << absl::BytesToHexString(absl::string_view(
                           coalesced_data, coalesced_data_length))
                    << " previous header was " << header;
    return;
  }

  if (coalesced_header.destination_connection_id !=
      header.destination_connection_id) {
    // Drop coalesced packets with mismatched connection IDs.
    QUIC_DLOG(INFO) << ENDPOINT << "Received mismatched coalesced header "
                    << coalesced_header << " previous header was " << header;
    QUIC_CODE_COUNT(
        quic_received_coalesced_packets_with_mismatched_connection_id);
    return;
  }

  QuicEncryptedPacket coalesced_packet(coalesced_data, coalesced_data_length,
                                       /*owns_buffer=*/false);
  visitor_->OnCoalescedPacket(coalesced_packet);
}

bool QuicFramer::MaybeProcessIetfLength(QuicDataReader* encrypted_reader,
                                        QuicPacketHeader* header) {
  if (!QuicVersionHasLongHeaderLengths(header->version.transport_version) ||
      header->form != IETF_QUIC_LONG_HEADER_PACKET ||
      (header->long_packet_type != INITIAL &&
       header->long_packet_type != HANDSHAKE &&
       header->long_packet_type != ZERO_RTT_PROTECTED)) {
    return true;
  }
  header->length_length = encrypted_reader->PeekVarInt62Length();
  if (!encrypted_reader->ReadVarInt62(&header->remaining_packet_length)) {
    set_detailed_error("Unable to read long header payload length.");
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }
  uint64_t remaining_bytes_length = encrypted_reader->BytesRemaining();
  if (header->remaining_packet_length > remaining_bytes_length) {
    set_detailed_error("Long header payload length longer than packet.");
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  MaybeProcessCoalescedPacket(*encrypted_reader, remaining_bytes_length,
                              *header);

  if (!encrypted_reader->TruncateRemaining(header->remaining_packet_length)) {
    set_detailed_error("Length TruncateRemaining failed.");
    QUIC_BUG(quic_bug_10850_54) << "Length TruncateRemaining failed.";
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }
  return true;
}

bool QuicFramer::ProcessIetfDataPacket(QuicDataReader* encrypted_reader,
                                       QuicPacketHeader* header,
                                       const QuicEncryptedPacket& packet,
 
"""


```