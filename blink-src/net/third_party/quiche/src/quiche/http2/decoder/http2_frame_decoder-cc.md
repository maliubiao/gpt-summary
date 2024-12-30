Response:
Let's break down the thought process for analyzing this C++ code.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `Http2FrameDecoder` class, its relation to JavaScript (if any), examples of logical reasoning, common usage errors, and how a user's actions lead to this code.

**2. Initial Code Scan and Identification of Core Functionality:**

The first step is to skim the code, looking for keywords and structure. Key observations:

* **Class Definition:** `Http2FrameDecoder` is the central entity.
* **Includes:**  Headers like `quiche/http2/decoder/decode_status.h`, `quiche/http2/hpack/varint/hpack_varint_decoder.h`, and `quiche/http2/http2_constants.h` hint at its role in HTTP/2 decoding.
* **State Machine:** The `State` enum and the `state_` member suggest a state machine for processing frames. The `switch (state_)` statements in `DecodeFrame` confirm this.
* **Frame Structure:** References to `Http2FrameHeader` and payload decoding methods (`StartDecoding...Payload`, `ResumeDecoding...Payload`) clearly indicate this class deals with the structure of HTTP/2 frames.
* **Listener Pattern:** The `Http2FrameDecoderListener` suggests a callback mechanism to inform other parts of the system about decoded frames.
* **Payload-Specific Decoders:**  Instances like `data_payload_decoder_`, `headers_payload_decoder_`, etc., indicate that the class delegates the actual payload decoding to specialized components.
* **Error Handling:**  `DecodeStatus` and checks for `maximum_payload_size_` point to error handling.

**3. Deeper Dive into Key Methods:**

* **`DecodeFrame(DecodeBuffer* db)`:** This is the main entry point for processing incoming data. The state machine logic is concentrated here. It manages transitioning between header and payload decoding.
* **`StartDecoding...Payload` and `ResumeDecoding...Payload`:**  These methods handle the different HTTP/2 frame types. They often call corresponding methods on the payload-specific decoder instances. The `DecodeBufferSubset` usage is important – it ensures that payload decoders only see the data relevant to the current frame.
* **`DiscardPayload(DecodeBuffer* db)`:**  This handles the case where a frame is invalid or rejected.
* **`set_listener()` and `listener()`:** Standard setter and getter for the listener interface.

**4. Connecting to JavaScript (or Lack Thereof):**

Considering the context (Chromium network stack), it's likely this code is low-level and deals directly with network protocols. JavaScript interacts with the network through higher-level APIs (like `fetch` or WebSockets). The connection is *indirect*. The decoded HTTP/2 frames would eventually be used by JavaScript, but this specific C++ code doesn't directly interact with JavaScript. The example given illustrates this indirect relationship.

**5. Logical Reasoning Examples:**

The request specifically asks for this. The `StartDecodingPayload` method provides clear examples:

* **Assumption:**  A frame header has been successfully decoded.
* **Input:** The decoded `Http2FrameHeader`.
* **Logic:** Check if the header is valid (e.g., within size limits). If not, transition to the `kDiscardPayload` state. If valid, determine the frame type and call the appropriate payload decoding method.
* **Output:** A `DecodeStatus` indicating success, progress, or error, and a potential state transition.

**6. Identifying Common Usage Errors:**

This requires thinking about how a programmer might misuse this class.

* **Incorrect Listener Implementation:**  A listener might not handle frame types or errors correctly.
* **Providing Insufficient Data:** The `DecodeFrame` method expects a `DecodeBuffer`. Not providing enough data for the current decoding state would lead to errors or unexpected behavior.
* **Ignoring `DecodeStatus`:** Failing to check the return value of `DecodeFrame` could lead to ignoring errors and continuing processing with corrupted state.

**7. Tracing User Actions to the Code:**

This requires thinking about the network request lifecycle:

* **User Action:** The user initiates a network request (e.g., clicks a link, loads a page).
* **Browser Processing:** The browser resolves the domain, establishes a connection (potentially using HTTP/2), and starts sending the request.
* **Network Stack Involvement:** The Chromium network stack (where this code resides) handles the low-level details of sending and receiving data.
* **Data Reception and Decoding:**  As data arrives, it's passed to the `Http2FrameDecoder` to parse the HTTP/2 frames.

**8. Structuring the Answer:**

Organize the information into the requested sections:

* **Functionality:** Provide a high-level overview and then break down the core methods and their roles.
* **Relationship to JavaScript:**  Explain the indirect connection and provide an example.
* **Logical Reasoning:**  Choose a clear example (like `StartDecodingPayload`) and explicitly state the assumptions, input, logic, and output.
* **Common Usage Errors:** Provide specific examples with explanations.
* **User Actions and Debugging:** Describe the typical request flow leading to this code and how a developer might use this information for debugging.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just decodes HTTP/2 frames."  **Refinement:**  Realize it's more than just parsing raw bytes. It manages state, delegates to sub-decoders, and interacts with a listener.
* **Initial thought on JavaScript:** "It's not directly related." **Refinement:**  Acknowledge the indirect relationship and provide a concrete example of how the decoded data *is* used by JavaScript.
* **Logical Reasoning:**  Initially thought of just describing the `DecodeFrame` method. **Refinement:** Focus on a specific internal method like `StartDecodingPayload` for a clearer illustration of logic.
* **Debugging:** Initially focused on code-level debugging. **Refinement:**  Connect it back to user actions to show the broader context of how this code is involved in the user experience.

By following this systematic thought process, combining code analysis with understanding the broader context of network communication and web development, we can arrive at a comprehensive and accurate answer to the request.
Based on the provided C++ source code for `net/third_party/quiche/src/quiche/http2/decoder/http2_frame_decoder.cc`, here's a breakdown of its functionality:

**Functionality of `Http2FrameDecoder`:**

This class is responsible for **decoding HTTP/2 frames** from a stream of bytes. It acts as a state machine to parse the incoming data and extract meaningful information according to the HTTP/2 protocol specification. Here's a more detailed breakdown:

1. **State Management:** It maintains an internal state (`state_`) to track the progress of decoding a frame. The states are:
   - `kStartDecodingHeader`:  Beginning the process of decoding a new frame's header.
   - `kResumeDecodingHeader`: Continuing the decoding of a frame's header (if the header wasn't fully available in the previous read).
   - `kResumeDecodingPayload`: Continuing the decoding of a frame's payload.
   - `kDiscardPayload`: Discarding the remaining payload of an invalid or rejected frame.

2. **Frame Header Decoding:** It uses an internal `frame_decoder_state_` (likely an instance of another class responsible for header-specific decoding) to decode the initial 9 bytes of an HTTP/2 frame header (length, type, flags, stream identifier).

3. **Payload Decoding:** Based on the decoded frame type from the header, it dispatches the payload decoding to specialized decoders for each frame type (e.g., `data_payload_decoder_`, `headers_payload_decoder_`, `settings_payload_decoder_`, etc.).

4. **Frame Type Handling:** It supports decoding all standard HTTP/2 frame types:
   - `DATA`
   - `HEADERS`
   - `PRIORITY`
   - `RST_STREAM`
   - `SETTINGS`
   - `PUSH_PROMISE`
   - `PING`
   - `GOAWAY`
   - `WINDOW_UPDATE`
   - `CONTINUATION`
   - `ALTSVC`
   - `PRIORITY_UPDATE`
   - It also handles unknown frame types.

5. **Listener Notification:** It uses an `Http2FrameDecoderListener` interface to notify other parts of the system about the decoded frames. This listener receives callbacks like `OnFrameHeader` and methods specific to each frame type's payload.

6. **Error Handling:** It checks for errors like exceeding the maximum allowed frame size and provides a `DecodeStatus` to indicate the outcome of the decoding process (success, in progress, error).

7. **Payload Discarding:** It provides a mechanism to discard the payload of invalid or rejected frames to continue processing subsequent frames.

8. **Padding Handling:**  For frame types that support padding, it manages the decoding and skipping of padding bytes.

9. **Flag Management:** It provides methods to retain or clear specific flags within the frame header based on the frame type.

**Relationship to JavaScript Functionality:**

This C++ code is part of the Chromium's network stack, which is a low-level component. JavaScript, running in the browser's rendering engine, interacts with the network through higher-level APIs. The relationship is **indirect**.

**Example:**

1. **JavaScript `fetch()` API:** When a JavaScript application uses the `fetch()` API to make an HTTP/2 request:
   ```javascript
   fetch('https://example.com/data')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **Network Request Initiation:** The browser's rendering engine translates this `fetch()` call into a network request.

3. **HTTP/2 Connection:** If the connection to `example.com` uses HTTP/2, the request will be framed into HTTP/2 frames (HEADERS for the request headers, potentially DATA for the request body).

4. **Transmission:** These HTTP/2 frames are serialized into bytes and sent over the network.

5. **Reception in Chromium:**  On the receiving end (if this code were running on a server), the incoming bytes would be fed into the `Http2FrameDecoder`.

6. **Decoding:**  The `Http2FrameDecoder` would parse these bytes, identify the frame types (HEADERS, DATA), and extract the relevant information (request headers, request body).

7. **Listener Callbacks:** The `Http2FrameDecoderListener` would be notified about the decoded frames.

8. **Higher-Level Processing:**  The information extracted by the decoder would then be passed to higher-level components of the network stack, which eventually deliver the response back to the JavaScript `fetch()` promise.

**In essence, the `Http2FrameDecoder` is a crucial low-level component that enables the browser (or a server built with Chromium's networking stack) to understand and process HTTP/2 network communication initiated by JavaScript or other parts of the system.**

**Logical Reasoning Examples:**

Let's consider the `StartDecodingPayload` function:

**Assumption:** The frame header has been successfully decoded and is available in `frame_header()`.

**Input:** A `DecodeBuffer* db` containing the remaining bytes of the frame (the payload).

**Logic:**

1. **Check for Listener Rejection:**  The code first calls `listener()->OnFrameHeader(header)`.
   - **Hypothetical Input:** A frame with `header.type = HEADERS` and `header.stream_id = 5`. The listener, for some reason, is configured to reject HEADERS frames for stream ID 5.
   - **Output:** `listener()->OnFrameHeader()` returns `false`.
   - **Internal Action:** The state is set to `kDiscardPayload`, and `DecodeStatus::kDecodeError` is returned. The remaining payload for this frame will be skipped.

2. **Check for Payload Size Exceeded:** The code checks if `header.payload_length > maximum_payload_size_`.
   - **Hypothetical Input:** A frame with `header.type = DATA` and `header.payload_length = 17000`, while `maximum_payload_size_` is 16384.
   - **Output:** The condition is true.
   - **Internal Action:** The state is set to `kDiscardPayload`, `listener()->OnFrameSizeError(header)` is called (notifying the listener about the error), and `DecodeStatus::kDecodeError` is returned.

3. **Dispatch to Payload-Specific Decoder:** If the header is accepted and the size is valid, the code uses a `switch` statement based on `header.type` to call the appropriate `StartDecoding...Payload` function.
   - **Hypothetical Input:** A frame with `header.type = SETTINGS`.
   - **Output:** The code calls `StartDecodingSettingsPayload(&subset)`, where `subset` is a `DecodeBufferSubset` limited to the frame's payload length.
   - **Internal Action:** The `settings_payload_decoder_` will attempt to decode the settings payload. The returned `DecodeStatus` will determine the next state.

**Common User or Programming Errors:**

1. **Incorrect Listener Implementation:**
   - **Example:** A programmer implementing `Http2FrameDecoderListener` might forget to handle a specific frame type, leading to unexpected behavior or crashes when that frame type is encountered.
   - **How to reach the code:** A remote peer sends an HTTP/2 frame of the unhandled type. The `Http2FrameDecoder` decodes the header and calls the corresponding listener method, which might not be implemented or might throw an exception.

2. **Providing Insufficient Data to `DecodeFrame`:**
   - **Example:** The `DecodeBuffer* db` passed to `DecodeFrame` might not contain enough bytes to decode the full frame header or payload.
   - **How to reach the code:** The network connection might be slow or fragmented, resulting in partial reads. The calling code might prematurely call `DecodeFrame` with an incomplete buffer. This could lead to the decoder getting stuck in `kResumeDecodingHeader` or `kResumeDecodingPayload` states.

3. **Ignoring the `DecodeStatus`:**
   - **Example:** A programmer might call `DecodeFrame` but not check the returned `DecodeStatus`. If the status is `kDecodeError`, the calling code might proceed with invalid or incomplete data.
   - **How to reach the code:**  Any scenario where an invalid HTTP/2 frame is received (e.g., due to network corruption, a malicious peer, or a bug in the peer's implementation). The decoder would return `kDecodeError`, but if ignored, the system might enter an inconsistent state.

4. **Not Handling Frame Size Limits:**
   - **Example:** A server might send a frame exceeding the client's advertised `SETTINGS_MAX_FRAME_SIZE`.
   - **How to reach the code:** The `StartDecodingPayload` function checks for this. If the limit is exceeded, `OnFrameSizeError` is called on the listener. If the listener doesn't handle this error gracefully, it could lead to connection termination or other issues.

**User Operations and Debugging线索 (Debugging Clues):**

Let's trace a user action and how it might lead to this code being executed:

1. **User Action:** A user clicks a link on a website that initiates an HTTP/2 request for a large image.

2. **Browser Processing:**
   - The browser resolves the domain name.
   - It establishes an HTTP/2 connection with the server.
   - It sends a `HEADERS` frame containing the request headers.
   - The server starts sending the image data in multiple `DATA` frames.

3. **Data Reception:**
   - The browser's network stack receives chunks of data from the server.

4. **`Http2FrameDecoder` Invocation:**
   - As data arrives, it's passed to the `Http2FrameDecoder::DecodeFrame` method.

5. **Decoding Process:**
   - **Initial Invocation:**  The first call to `DecodeFrame` might receive enough data for the `DATA` frame header. The state transitions to `kStartDecodingHeader`, then `kResumeDecodingPayload`.
   - **Subsequent Invocations:**  If the full payload of the `DATA` frame isn't available in the first chunk, `DecodeFrame` will return `kDecodeInProgress`, and the state will remain `kResumeDecodingPayload`. The next invocation of `DecodeFrame` with more data will continue decoding the payload.
   - **Large Image:** For a large image, this process of receiving data chunks and invoking `DecodeFrame` will repeat multiple times until the entire `DATA` frame is decoded.

6. **Debugging Clues:**

   - **Breakpoints:** A developer debugging network issues related to this image loading could set breakpoints in `Http2FrameDecoder::DecodeFrame`, `StartDecodingDataPayload`, or `ResumeDecodingDataPayload` to observe the state transitions, the amount of data being processed, and the frame headers.
   - **Logging:** The `QUICHE_DVLOG(2)` statements in the code can be enabled to provide detailed logs about the decoding process, frame headers, and state changes. This can help understand if frames are being received and parsed correctly.
   - **Network Inspection Tools:** Tools like Chrome DevTools can show the raw HTTP/2 frames being exchanged, allowing developers to verify if the sent and received frames match expectations. Comparing the raw frame data with the decoded information in the debugger can help pinpoint issues.
   - **Listener Inspection:**  Breakpoints or logging in the `Http2FrameDecoderListener` implementation can reveal if the listener is receiving the expected frame data and if any errors are being reported.
   - **Error Status:** Observing the `DecodeStatus` returned by `DecodeFrame` can indicate if any decoding errors occurred.

By understanding the flow of execution and the role of `Http2FrameDecoder`, developers can use these debugging techniques to diagnose network-related problems in their applications.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/decoder/http2_frame_decoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/decoder/http2_frame_decoder.h"

#include <ostream>

#include "quiche/http2/decoder/decode_status.h"
#include "quiche/http2/hpack/varint/hpack_varint_decoder.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace http2 {

std::ostream& operator<<(std::ostream& out, Http2FrameDecoder::State v) {
  switch (v) {
    case Http2FrameDecoder::State::kStartDecodingHeader:
      return out << "kStartDecodingHeader";
    case Http2FrameDecoder::State::kResumeDecodingHeader:
      return out << "kResumeDecodingHeader";
    case Http2FrameDecoder::State::kResumeDecodingPayload:
      return out << "kResumeDecodingPayload";
    case Http2FrameDecoder::State::kDiscardPayload:
      return out << "kDiscardPayload";
  }
  // Since the value doesn't come over the wire, only a programming bug should
  // result in reaching this point.
  int unknown = static_cast<int>(v);
  QUICHE_BUG(http2_bug_155_1) << "Http2FrameDecoder::State " << unknown;
  return out << "Http2FrameDecoder::State(" << unknown << ")";
}

Http2FrameDecoder::Http2FrameDecoder(Http2FrameDecoderListener* listener)
    : state_(State::kStartDecodingHeader),
      maximum_payload_size_(Http2SettingsInfo::DefaultMaxFrameSize()) {
  set_listener(listener);
}

void Http2FrameDecoder::set_listener(Http2FrameDecoderListener* listener) {
  if (listener == nullptr) {
    listener = &no_op_listener_;
  }
  frame_decoder_state_.set_listener(listener);
}

Http2FrameDecoderListener* Http2FrameDecoder::listener() const {
  return frame_decoder_state_.listener();
}

DecodeStatus Http2FrameDecoder::DecodeFrame(DecodeBuffer* db) {
  QUICHE_DVLOG(2) << "Http2FrameDecoder::DecodeFrame state=" << state_;
  switch (state_) {
    case State::kStartDecodingHeader:
      if (frame_decoder_state_.StartDecodingFrameHeader(db)) {
        return StartDecodingPayload(db);
      }
      state_ = State::kResumeDecodingHeader;
      return DecodeStatus::kDecodeInProgress;

    case State::kResumeDecodingHeader:
      if (frame_decoder_state_.ResumeDecodingFrameHeader(db)) {
        return StartDecodingPayload(db);
      }
      return DecodeStatus::kDecodeInProgress;

    case State::kResumeDecodingPayload:
      return ResumeDecodingPayload(db);

    case State::kDiscardPayload:
      return DiscardPayload(db);
  }

  QUICHE_NOTREACHED();
  return DecodeStatus::kDecodeError;
}

size_t Http2FrameDecoder::remaining_payload() const {
  return frame_decoder_state_.remaining_payload();
}

uint32_t Http2FrameDecoder::remaining_padding() const {
  return frame_decoder_state_.remaining_padding();
}

DecodeStatus Http2FrameDecoder::StartDecodingPayload(DecodeBuffer* db) {
  const Http2FrameHeader& header = frame_header();

  // TODO(jamessynge): Remove OnFrameHeader once done with supporting
  // SpdyFramer's exact states.
  if (!listener()->OnFrameHeader(header)) {
    QUICHE_DVLOG(2)
        << "OnFrameHeader rejected the frame, will discard; header: " << header;
    state_ = State::kDiscardPayload;
    frame_decoder_state_.InitializeRemainders();
    return DecodeStatus::kDecodeError;
  }

  if (header.payload_length > maximum_payload_size_) {
    QUICHE_DVLOG(2) << "Payload length is greater than allowed: "
                    << header.payload_length << " > " << maximum_payload_size_
                    << "\n   header: " << header;
    state_ = State::kDiscardPayload;
    frame_decoder_state_.InitializeRemainders();
    listener()->OnFrameSizeError(header);
    return DecodeStatus::kDecodeError;
  }

  // The decode buffer can extend across many frames. Make sure that the
  // buffer we pass to the start method that is specific to the frame type
  // does not exend beyond this frame.
  DecodeBufferSubset subset(db, header.payload_length);
  DecodeStatus status;
  switch (header.type) {
    case Http2FrameType::DATA:
      status = StartDecodingDataPayload(&subset);
      break;

    case Http2FrameType::HEADERS:
      status = StartDecodingHeadersPayload(&subset);
      break;

    case Http2FrameType::PRIORITY:
      status = StartDecodingPriorityPayload(&subset);
      break;

    case Http2FrameType::RST_STREAM:
      status = StartDecodingRstStreamPayload(&subset);
      break;

    case Http2FrameType::SETTINGS:
      status = StartDecodingSettingsPayload(&subset);
      break;

    case Http2FrameType::PUSH_PROMISE:
      status = StartDecodingPushPromisePayload(&subset);
      break;

    case Http2FrameType::PING:
      status = StartDecodingPingPayload(&subset);
      break;

    case Http2FrameType::GOAWAY:
      status = StartDecodingGoAwayPayload(&subset);
      break;

    case Http2FrameType::WINDOW_UPDATE:
      status = StartDecodingWindowUpdatePayload(&subset);
      break;

    case Http2FrameType::CONTINUATION:
      status = StartDecodingContinuationPayload(&subset);
      break;

    case Http2FrameType::ALTSVC:
      status = StartDecodingAltSvcPayload(&subset);
      break;

    case Http2FrameType::PRIORITY_UPDATE:
      status = StartDecodingPriorityUpdatePayload(&subset);
      break;

    default:
      status = StartDecodingUnknownPayload(&subset);
      break;
  }

  if (status == DecodeStatus::kDecodeDone) {
    state_ = State::kStartDecodingHeader;
    return status;
  } else if (status == DecodeStatus::kDecodeInProgress) {
    state_ = State::kResumeDecodingPayload;
    return status;
  } else {
    state_ = State::kDiscardPayload;
    return status;
  }
}

DecodeStatus Http2FrameDecoder::ResumeDecodingPayload(DecodeBuffer* db) {
  // The decode buffer can extend across many frames. Make sure that the
  // buffer we pass to the start method that is specific to the frame type
  // does not exend beyond this frame.
  size_t remaining = frame_decoder_state_.remaining_total_payload();
  QUICHE_DCHECK_LE(remaining, frame_header().payload_length);
  DecodeBufferSubset subset(db, remaining);
  DecodeStatus status;
  switch (frame_header().type) {
    case Http2FrameType::DATA:
      status = ResumeDecodingDataPayload(&subset);
      break;

    case Http2FrameType::HEADERS:
      status = ResumeDecodingHeadersPayload(&subset);
      break;

    case Http2FrameType::PRIORITY:
      status = ResumeDecodingPriorityPayload(&subset);
      break;

    case Http2FrameType::RST_STREAM:
      status = ResumeDecodingRstStreamPayload(&subset);
      break;

    case Http2FrameType::SETTINGS:
      status = ResumeDecodingSettingsPayload(&subset);
      break;

    case Http2FrameType::PUSH_PROMISE:
      status = ResumeDecodingPushPromisePayload(&subset);
      break;

    case Http2FrameType::PING:
      status = ResumeDecodingPingPayload(&subset);
      break;

    case Http2FrameType::GOAWAY:
      status = ResumeDecodingGoAwayPayload(&subset);
      break;

    case Http2FrameType::WINDOW_UPDATE:
      status = ResumeDecodingWindowUpdatePayload(&subset);
      break;

    case Http2FrameType::CONTINUATION:
      status = ResumeDecodingContinuationPayload(&subset);
      break;

    case Http2FrameType::ALTSVC:
      status = ResumeDecodingAltSvcPayload(&subset);
      break;

    case Http2FrameType::PRIORITY_UPDATE:
      status = ResumeDecodingPriorityUpdatePayload(&subset);
      break;

    default:
      status = ResumeDecodingUnknownPayload(&subset);
      break;
  }

  if (status == DecodeStatus::kDecodeDone) {
    state_ = State::kStartDecodingHeader;
    return status;
  } else if (status == DecodeStatus::kDecodeInProgress) {
    return status;
  } else {
    state_ = State::kDiscardPayload;
    return status;
  }
}

// Clear any of the flags in the frame header that aren't set in valid_flags.
void Http2FrameDecoder::RetainFlags(uint8_t valid_flags) {
  frame_decoder_state_.RetainFlags(valid_flags);
}

// Clear all of the flags in the frame header; for use with frame types that
// don't define any flags, such as WINDOW_UPDATE.
void Http2FrameDecoder::ClearFlags() { frame_decoder_state_.ClearFlags(); }

DecodeStatus Http2FrameDecoder::StartDecodingAltSvcPayload(DecodeBuffer* db) {
  ClearFlags();
  return altsvc_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                      db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingAltSvcPayload(DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return altsvc_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                       db);
}

DecodeStatus Http2FrameDecoder::StartDecodingContinuationPayload(
    DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::END_HEADERS);
  return continuation_payload_decoder_.StartDecodingPayload(
      &frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingContinuationPayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return continuation_payload_decoder_.ResumeDecodingPayload(
      &frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingDataPayload(DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::END_STREAM | Http2FrameFlag::PADDED);
  return data_payload_decoder_.StartDecodingPayload(&frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingDataPayload(DecodeBuffer* db) {
  return data_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingGoAwayPayload(DecodeBuffer* db) {
  ClearFlags();
  return goaway_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                      db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingGoAwayPayload(DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return goaway_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                       db);
}

DecodeStatus Http2FrameDecoder::StartDecodingHeadersPayload(DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::END_STREAM | Http2FrameFlag::END_HEADERS |
              Http2FrameFlag::PADDED | Http2FrameFlag::PRIORITY);
  return headers_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                       db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingHeadersPayload(DecodeBuffer* db) {
  QUICHE_DCHECK_LE(frame_decoder_state_.remaining_payload_and_padding(),
                   frame_header().payload_length);
  return headers_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                        db);
}

DecodeStatus Http2FrameDecoder::StartDecodingPingPayload(DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::ACK);
  return ping_payload_decoder_.StartDecodingPayload(&frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingPingPayload(DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return ping_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingPriorityPayload(DecodeBuffer* db) {
  ClearFlags();
  return priority_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                        db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingPriorityPayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return priority_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                         db);
}

DecodeStatus Http2FrameDecoder::StartDecodingPriorityUpdatePayload(
    DecodeBuffer* db) {
  ClearFlags();
  return priority_payload_update_decoder_.StartDecodingPayload(
      &frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingPriorityUpdatePayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return priority_payload_update_decoder_.ResumeDecodingPayload(
      &frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingPushPromisePayload(
    DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::END_HEADERS | Http2FrameFlag::PADDED);
  return push_promise_payload_decoder_.StartDecodingPayload(
      &frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingPushPromisePayload(
    DecodeBuffer* db) {
  QUICHE_DCHECK_LE(frame_decoder_state_.remaining_payload_and_padding(),
                   frame_header().payload_length);
  return push_promise_payload_decoder_.ResumeDecodingPayload(
      &frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingRstStreamPayload(
    DecodeBuffer* db) {
  ClearFlags();
  return rst_stream_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                          db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingRstStreamPayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return rst_stream_payload_decoder_.ResumeDecodingPayload(
      &frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::StartDecodingSettingsPayload(DecodeBuffer* db) {
  RetainFlags(Http2FrameFlag::ACK);
  return settings_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                        db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingSettingsPayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return settings_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                         db);
}

DecodeStatus Http2FrameDecoder::StartDecodingUnknownPayload(DecodeBuffer* db) {
  // We don't known what type of frame this is, so we don't know which flags
  // are valid, so we don't touch them.
  return unknown_payload_decoder_.StartDecodingPayload(&frame_decoder_state_,
                                                       db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingUnknownPayload(DecodeBuffer* db) {
  // We don't known what type of frame this is, so we treat it as not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return unknown_payload_decoder_.ResumeDecodingPayload(&frame_decoder_state_,
                                                        db);
}

DecodeStatus Http2FrameDecoder::StartDecodingWindowUpdatePayload(
    DecodeBuffer* db) {
  ClearFlags();
  return window_update_payload_decoder_.StartDecodingPayload(
      &frame_decoder_state_, db);
}
DecodeStatus Http2FrameDecoder::ResumeDecodingWindowUpdatePayload(
    DecodeBuffer* db) {
  // The frame is not paddable.
  QUICHE_DCHECK_EQ(frame_decoder_state_.remaining_total_payload(),
                   frame_decoder_state_.remaining_payload());
  return window_update_payload_decoder_.ResumeDecodingPayload(
      &frame_decoder_state_, db);
}

DecodeStatus Http2FrameDecoder::DiscardPayload(DecodeBuffer* db) {
  QUICHE_DVLOG(2) << "remaining_payload="
                  << frame_decoder_state_.remaining_payload_
                  << "; remaining_padding="
                  << frame_decoder_state_.remaining_padding_;
  frame_decoder_state_.remaining_payload_ +=
      frame_decoder_state_.remaining_padding_;
  frame_decoder_state_.remaining_padding_ = 0;
  const size_t avail = frame_decoder_state_.AvailablePayload(db);
  QUICHE_DVLOG(2) << "avail=" << avail;
  if (avail > 0) {
    frame_decoder_state_.ConsumePayload(avail);
    db->AdvanceCursor(avail);
  }
  if (frame_decoder_state_.remaining_payload_ == 0) {
    state_ = State::kStartDecodingHeader;
    return DecodeStatus::kDecodeDone;
  }
  return DecodeStatus::kDecodeInProgress;
}

}  // namespace http2

"""

```