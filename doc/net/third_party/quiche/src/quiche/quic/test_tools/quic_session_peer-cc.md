Response:
Let's break down the thought process for analyzing this C++ file and addressing the prompt.

**1. Understanding the Core Purpose:**

The first thing I notice is the file path: `net/third_party/quiche/src/quiche/quic/test_tools/quic_session_peer.cc`. The `test_tools` directory immediately signals that this code isn't part of the core QUIC implementation but rather a utility for *testing* QUIC. The name `QuicSessionPeer` suggests it interacts with `QuicSession` objects, likely providing access to internal details.

**2. Analyzing the Code Structure:**

I scan through the code and see a series of `static` methods within the `quic::test::QuicSessionPeer` namespace. The `static` keyword is crucial here. It means these methods don't operate on an instance of `QuicSessionPeer` but take a `QuicSession*` as an argument. This reinforces the idea of a utility class providing access to (and sometimes modification of) `QuicSession` internals.

**3. Identifying Key Functionalities:**

I go through each function and try to understand its purpose:

* **`GetNextOutgoing...StreamId`**:  Retrieving the next available stream ID.
* **`SetNextOutgoing...StreamId`**:  Setting the next available stream ID (important for testing scenarios where you need specific IDs).
* **`SetMaxOpenIncoming/Outgoing...Streams`**: Modifying the limits on the number of open streams.
* **`GetMutableCryptoStream`**: Accessing the crypto stream.
* **`GetWriteBlockedStreams`**:  Getting the list of streams blocked on writing.
* **`GetOrCreateStream`, `GetStream`**:  Accessing streams.
* **`GetLocallyClosedStreamsHighestOffset`**:  Examining closed streams.
* **`stream_map`, `closed_streams`**: Direct access to internal data structures.
* **`ActivateStream`**:  Adding a stream to the session.
* **`IsStreamClosed`, `IsStreamCreated`, `IsStreamAvailable`, `IsStreamWriteBlocked`**: Checking stream status.
* **`GetCleanUpClosedStreamsAlarm`, `GetStreamCountResetAlarm`**: Accessing internal alarms (likely related to timeouts and cleanup).
* **`GetStreamIdManager`, `ietf_streamid_manager`, etc.**: Accessing internal stream ID management objects.
* **`GetPendingStream`**:  Retrieving streams that are in a pending state.
* **`set_is_configured`**:  Modifying the configuration status.
* **`SetPerspective`**:  Changing whether the session is acting as a client or server.
* **`GetNumOpenDynamicStreams`, `GetNumDrainingStreams`**:  Getting counts of certain stream types.

**4. Categorizing the Functionality:**

Based on the analysis, I can group the functionalities into:

* **Accessors (Getters):** Retrieving internal state (stream IDs, stream lists, alarms, etc.).
* **Mutators (Setters):** Modifying internal state (next stream IDs, stream limits, configuration).
* **Status Checks (Is...):**  Querying the state of streams.
* **Direct Access:**  Providing raw access to internal data structures.

**5. Considering the "Peer" Aspect:**

The name "Peer" in the class name is interesting. It suggests this class allows you to interact with a `QuicSession` as if you were an external entity observing or manipulating its internal workings. This is common in testing where you need fine-grained control.

**6. Relating to JavaScript (and Web Development):**

This is where I need to bridge the gap between low-level C++ QUIC implementation and higher-level JavaScript/web development. The connection isn't direct, but I can think in terms of the *effects* these functions would have on a web application using QUIC:

* **Stream Management:** The stream ID manipulation and limit setting directly affect how many concurrent requests a browser can make or how many push streams a server can initiate. This is crucial for web performance.
* **Crypto Stream:** While not directly exposed in typical web APIs, the crypto stream is fundamental to TLS/QUIC handshakes, which are essential for secure web connections.
* **Write Blocking:**  Understanding how streams become write-blocked helps in debugging scenarios where data transfer stalls. This could manifest in JavaScript as a stalled `fetch()` request or WebSocket connection.
* **Stream Closure:**  The mechanisms for closing streams relate to how HTTP/3 connections are managed and how errors are handled in web applications.

**7. Developing Examples and Scenarios:**

Now I can create concrete examples:

* **JavaScript Connection Limits:**  Relate the `SetMaxOpen...Streams` functions to how a browser might limit concurrent requests.
* **Stream Creation and `fetch()`:** Show how `GetNextOutgoingBidirectionalStreamId` conceptually ties to the creation of a new stream when a JavaScript `fetch()` call is made.
* **Debugging Stalled Requests:** Explain how the "write blocked" concept relates to situations where a web request appears to hang.

**8. Thinking about User/Programming Errors:**

This naturally flows from the understanding of the functions. Incorrectly setting stream limits or trying to access non-existent streams are potential errors.

**9. Tracing User Actions:**

This involves imagining a sequence of events in a web browser that would lead to the QUIC code being executed. This involves the initial connection, subsequent requests, and potentially error scenarios.

**10. Refining and Structuring the Output:**

Finally, I organize the information into clear sections as requested by the prompt, using headings and bullet points for readability. I make sure to explain the C++ concepts clearly and then connect them to JavaScript/web development with relevant examples. I also focus on providing actionable information, like how these functions can be used for debugging.

By following this systematic approach, I can effectively analyze the C++ code and address all aspects of the prompt, even the parts that require bridging the gap to JavaScript and user-level interactions.
这个C++源代码文件 `quic_session_peer.cc` 的功能是为 **QUIC 会话 (QuicSession)** 提供一个 **测试辅助工具 (test peer)**。  它允许测试代码访问和操作 `QuicSession` 对象的内部状态和方法，而这些状态和方法在正常情况下是受保护或私有的。

**具体功能列举:**

这个文件定义了一个名为 `QuicSessionPeer` 的类，其中包含一系列静态方法，每个方法都旨在访问或修改 `QuicSession` 对象的特定内部属性或行为。  主要功能包括：

* **获取下一个可用的流 ID (Stream ID):**
    * `GetNextOutgoingBidirectionalStreamId`: 获取下一个用于双向流的 ID。
    * `GetNextOutgoingUnidirectionalStreamId`: 获取下一个用于单向流的 ID。

* **设置流 ID 的状态:**
    * `SetNextOutgoingBidirectionalStreamId`:  强制设置下一个要使用的双向流 ID。

* **管理最大并发流的数量:**
    * `SetMaxOpenIncomingStreams`: 设置允许打开的最大传入流数量 (已废弃对 IETF QUIC)。
    * `SetMaxOpenIncomingBidirectionalStreams`: 设置允许打开的最大传入双向流数量 (仅限 IETF QUIC)。
    * `SetMaxOpenIncomingUnidirectionalStreams`: 设置允许打开的最大传入单向流数量 (仅限 IETF QUIC)。
    * `SetMaxOpenOutgoingStreams`: 设置允许打开的最大传出流数量 (已废弃对 IETF QUIC)。
    * `SetMaxOpenOutgoingBidirectionalStreams`: 设置允许打开的最大传出双向流数量 (仅限 IETF QUIC)。
    * `SetMaxOpenOutgoingUnidirectionalStreams`: 设置允许打开的最大传出单向流数量 (仅限 IETF QUIC)。

* **访问内部组件:**
    * `GetMutableCryptoStream`: 获取可修改的加密流对象。
    * `GetWriteBlockedStreams`: 获取写阻塞的流列表接口。
    * `GetOrCreateStream`: 获取或创建一个流对象。
    * `GetLocallyClosedStreamsHighestOffset`: 获取本地关闭的流及其最高偏移量。
    * `stream_map`: 直接访问流映射表。
    * `closed_streams`: 直接访问已关闭的流列表。
    * `GetStreamIdManager`: 获取传统的流 ID 管理器。
    * `ietf_streamid_manager`: 获取 IETF QUIC 的流 ID 管理器。
    * `ietf_bidirectional_stream_id_manager`: 获取 IETF QUIC 的双向流 ID 管理器。
    * `ietf_unidirectional_stream_id_manager`: 获取 IETF QUIC 的单向流 ID 管理器。
    * `GetPendingStream`: 获取等待中的流。
    * `GetCleanUpClosedStreamsAlarm`: 获取用于清理关闭流的定时器。
    * `GetStreamCountResetAlarm`: 获取流计数重置定时器。

* **操作流:**
    * `ActivateStream`: 激活一个流。

* **查询流的状态:**
    * `IsStreamClosed`: 检查流是否已关闭。
    * `IsStreamCreated`: 检查流是否已创建。
    * `IsStreamAvailable`: 检查流 ID 是否可用。
    * `GetStream`: 获取一个流对象。
    * `IsStreamWriteBlocked`: 检查流是否被写阻塞。

* **修改会话状态:**
    * `set_is_configured`: 设置会话是否已配置完成。
    * `SetPerspective`: 设置会话的视角 (客户端或服务器)。

* **获取会话统计信息:**
    * `GetNumOpenDynamicStreams`: 获取打开的动态流的数量。
    * `GetNumDrainingStreams`: 获取正在排空的流的数量。

**与 JavaScript 功能的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所操作的 QUIC 协议是现代 Web 技术的基础，与 JavaScript 的功能有密切关系。  JavaScript 通过浏览器提供的 API (如 `fetch`, WebSocket) 与服务器进行网络通信，而这些通信底层可能使用 QUIC 协议。

例如：

1. **流的管理 (Stream Management):**
   - `GetNextOutgoingBidirectionalStreamId` 和 `SetMaxOpenOutgoingBidirectionalStreams` 等方法直接影响着 QUIC 连接上可以并发打开多少个双向流。
   - **JavaScript 例子:** 当 JavaScript 代码执行多个 `fetch()` 请求或创建一个 WebSocket 连接时，浏览器底层会为每个请求或连接分配一个 QUIC 流。 `QuicSessionPeer` 提供的功能可以用来测试当并发请求数量达到或超过服务器或客户端设置的最大值时，QUIC 的行为是否符合预期。

   ```javascript
   // 假设浏览器底层使用了 QUIC

   // 模拟发起多个并发请求
   const promises = [];
   for (let i = 0; i < 10; i++) {
     promises.push(fetch('https://example.com/api'));
   }
   Promise.all(promises)
     .then(responses => {
       console.log('所有请求完成', responses);
     })
     .catch(error => {
       console.error('请求失败', error);
     });
   ```
   在测试中，可以使用 `QuicSessionPeer::SetMaxOpenOutgoingBidirectionalStreams` 来模拟服务器或客户端限制并发流的数量，观察 JavaScript 代码在这种情况下的表现。

2. **流的阻塞 (Stream Blocking):**
   - `GetWriteBlockedStreams` 和 `IsStreamWriteBlocked` 可以用来检查哪些流因为发送缓冲区满等原因被阻塞。
   - **JavaScript 例子:**  如果 JavaScript 代码通过 WebSocket 发送大量数据，而网络带宽有限，或者服务器处理速度较慢，就可能导致 QUIC 流被写阻塞。  测试代码可以使用 `QuicSessionPeer` 来观察和验证这种阻塞状态。

   ```javascript
   // 假设有一个 WebSocket 连接 ws

   for (let i = 0; i < 1000; i++) {
     ws.send('大量数据...');
   }
   ```
   在测试中，可以检查特定流是否因为发送了大量数据而被阻塞。

3. **流的创建和关闭 (Stream Creation and Closure):**
   - `GetOrCreateStream`, `ActivateStream`, `IsStreamClosed` 等方法用于管理 QUIC 流的生命周期。
   - **JavaScript 例子:**  每次发起 `fetch()` 请求或关闭 WebSocket 连接，底层都会创建和关闭 QUIC 流。 `QuicSessionPeer` 可以用来验证流的创建和关闭逻辑是否正确。

**逻辑推理的假设输入与输出:**

假设我们使用 `QuicSessionPeer::SetNextOutgoingBidirectionalStreamId` 设置下一个传出的双向流 ID 为 4：

* **假设输入:**
    * `QuicSession* session`: 一个有效的 `QuicSession` 对象。
    * `QuicStreamId id`: 4

* **执行的操作:**
    `QuicSessionPeer::SetNextOutgoingBidirectionalStreamId(session, 4);`

* **预期输出:**
    * 在调用之后，当 `session` 对象需要创建新的传出双向流时，它会分配的下一个流 ID 将是 4。

假设我们使用 `QuicSessionPeer::IsStreamAvailable` 检查流 ID 5 是否可用：

* **假设输入:**
    * `QuicSession* session`: 一个有效的 `QuicSession` 对象。
    * `QuicStreamId id`: 5

* **执行的操作:**
    `bool isAvailable = QuicSessionPeer::IsStreamAvailable(session, 5);`

* **预期输出:**
    * `isAvailable` 的值将取决于 `session` 的内部状态，例如流 ID 管理器中是否已存在或预留了流 ID 5。如果 5 是下一个可以被分配的流 ID，则 `isAvailable` 为 `true`，否则为 `false`。

**用户或编程常见的使用错误及举例说明:**

1. **错误地设置流 ID:**  如果测试代码尝试使用 `SetNextOutgoingBidirectionalStreamId` 设置一个已经被使用或不合法的流 ID，可能会导致会话进入错误状态或者引发断言失败。
   ```c++
   // 错误示例：假设已经有流 ID 为 4 的流存在
   QuicSessionPeer::SetNextOutgoingBidirectionalStreamId(session, 4); // 可能会导致错误
   ```

2. **并发流数量超出限制:**  如果测试代码没有正确处理最大并发流数量的限制，尝试创建超出限制的流可能会导致连接失败或性能下降。
   ```c++
   // 错误示例：假设最大并发双向流设置为 2
   for (int i = 0; i < 5; ++i) {
     session->CreateOutgoingBidirectionalStream(); // 第 3, 4, 5 次创建可能会失败
   }
   ```

3. **在错误的会话状态下操作:**  有些方法只能在特定的会话状态下调用。例如，在会话完成握手之前尝试发送数据可能会导致错误。  `QuicSessionPeer` 可以帮助测试这些状态转换的边界情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发人员或测试人员，你通常不会直接与 `quic_session_peer.cc` 中的代码交互。这个文件是 Chromium 网络栈 QUIC 实现的测试辅助工具。  到达这里进行调试的步骤通常是：

1. **用户行为触发网络请求:** 用户在 Chrome 浏览器中访问一个使用 QUIC 协议的网站，或者执行某些导致网络请求的操作 (例如，点击链接、提交表单、加载资源)。

2. **浏览器发起 QUIC 连接:** Chrome 浏览器会尝试与服务器建立 QUIC 连接。

3. **QUIC 会话的创建和管理:** 在建立连接的过程中，`QuicSession` 对象会被创建和管理。

4. **测试需求:**  网络栈的开发人员或测试人员可能需要编写单元测试或集成测试来验证 `QuicSession` 的特定行为，例如：
   - 测试并发流控制的逻辑。
   - 测试流的创建、关闭和状态转换。
   - 测试错误处理机制。

5. **使用 `QuicSessionPeer` 进行测试:** 为了更深入地测试 `QuicSession` 的内部行为，测试代码会使用 `quic_session_peer.cc` 中提供的静态方法来访问和操作 `QuicSession` 对象，例如：
   - 设置特定的流 ID，以便测试流 ID 分配逻辑。
   - 模拟流被写阻塞的情况。
   - 检查内部数据结构的状态。

6. **调试 `QuicSession` 的行为:** 如果测试失败，或者在实际运行中发现了与 QUIC 会话相关的 bug，开发人员可能会在调试器中设置断点，跟踪代码执行流程，查看 `QuicSession` 对象的内部状态，并可能使用 `QuicSessionPeer` 提供的功能来辅助诊断问题。

**总结:**

`quic_session_peer.cc` 是一个关键的测试工具，它允许 Chromium 网络栈的开发人员深入了解和测试 QUIC 会话的内部工作机制。它通过提供对 `QuicSession` 内部状态和方法的访问，使得编写细粒度的测试用例成为可能，从而确保 QUIC 协议在各种场景下的正确性和健壮性。 虽然普通用户或 JavaScript 开发者不会直接接触到这个文件，但它在幕后支撑着现代 Web 技术的可靠运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_session_peer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/quic_session_peer.h"

#include <memory>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_utils.h"

namespace quic {
namespace test {

// static
QuicStreamId QuicSessionPeer::GetNextOutgoingBidirectionalStreamId(
    QuicSession* session) {
  return session->GetNextOutgoingBidirectionalStreamId();
}

// static
QuicStreamId QuicSessionPeer::GetNextOutgoingUnidirectionalStreamId(
    QuicSession* session) {
  return session->GetNextOutgoingUnidirectionalStreamId();
}

// static
void QuicSessionPeer::SetNextOutgoingBidirectionalStreamId(QuicSession* session,
                                                           QuicStreamId id) {
  if (VersionHasIetfQuicFrames(session->transport_version())) {
    session->ietf_streamid_manager_.bidirectional_stream_id_manager_
        .next_outgoing_stream_id_ = id;
    return;
  }
  session->stream_id_manager_.next_outgoing_stream_id_ = id;
}

// static
void QuicSessionPeer::SetMaxOpenIncomingStreams(QuicSession* session,
                                                uint32_t max_streams) {
  if (VersionHasIetfQuicFrames(session->transport_version())) {
    QUIC_BUG(quic_bug_10193_1)
        << "SetmaxOpenIncomingStreams deprecated for IETF QUIC";
    session->ietf_streamid_manager_.SetMaxOpenIncomingUnidirectionalStreams(
        max_streams);
    session->ietf_streamid_manager_.SetMaxOpenIncomingBidirectionalStreams(
        max_streams);
    return;
  }
  session->stream_id_manager_.set_max_open_incoming_streams(max_streams);
}

// static
void QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(
    QuicSession* session, uint32_t max_streams) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(session->transport_version()))
      << "SetmaxOpenIncomingBidirectionalStreams not supported for Google "
         "QUIC";
  session->ietf_streamid_manager_.SetMaxOpenIncomingBidirectionalStreams(
      max_streams);
}
// static
void QuicSessionPeer::SetMaxOpenIncomingUnidirectionalStreams(
    QuicSession* session, uint32_t max_streams) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(session->transport_version()))
      << "SetmaxOpenIncomingUnidirectionalStreams not supported for Google "
         "QUIC";
  session->ietf_streamid_manager_.SetMaxOpenIncomingUnidirectionalStreams(
      max_streams);
}

// static
void QuicSessionPeer::SetMaxOpenOutgoingStreams(QuicSession* session,
                                                uint32_t max_streams) {
  if (VersionHasIetfQuicFrames(session->transport_version())) {
    QUIC_BUG(quic_bug_10193_2)
        << "SetmaxOpenOutgoingStreams deprecated for IETF QUIC";
    return;
  }
  session->stream_id_manager_.set_max_open_outgoing_streams(max_streams);
}

// static
void QuicSessionPeer::SetMaxOpenOutgoingBidirectionalStreams(
    QuicSession* session, uint32_t max_streams) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(session->transport_version()))
      << "SetmaxOpenOutgoingBidirectionalStreams not supported for Google "
         "QUIC";
  session->ietf_streamid_manager_.MaybeAllowNewOutgoingBidirectionalStreams(
      max_streams);
}
// static
void QuicSessionPeer::SetMaxOpenOutgoingUnidirectionalStreams(
    QuicSession* session, uint32_t max_streams) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(session->transport_version()))
      << "SetmaxOpenOutgoingUnidirectionalStreams not supported for Google "
         "QUIC";
  session->ietf_streamid_manager_.MaybeAllowNewOutgoingUnidirectionalStreams(
      max_streams);
}

// static
QuicCryptoStream* QuicSessionPeer::GetMutableCryptoStream(
    QuicSession* session) {
  return session->GetMutableCryptoStream();
}

// static
QuicWriteBlockedListInterface* QuicSessionPeer::GetWriteBlockedStreams(
    QuicSession* session) {
  return session->write_blocked_streams();
}

// static
QuicStream* QuicSessionPeer::GetOrCreateStream(QuicSession* session,
                                               QuicStreamId stream_id) {
  return session->GetOrCreateStream(stream_id);
}

// static
absl::flat_hash_map<QuicStreamId, QuicStreamOffset>&
QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(QuicSession* session) {
  return session->locally_closed_streams_highest_offset_;
}

// static
QuicSession::StreamMap& QuicSessionPeer::stream_map(QuicSession* session) {
  return session->stream_map_;
}

// static
const QuicSession::ClosedStreams& QuicSessionPeer::closed_streams(
    QuicSession* session) {
  return *session->closed_streams();
}

// static
void QuicSessionPeer::ActivateStream(QuicSession* session,
                                     std::unique_ptr<QuicStream> stream) {
  return session->ActivateStream(std::move(stream));
}

// static
bool QuicSessionPeer::IsStreamClosed(QuicSession* session, QuicStreamId id) {
  return session->IsClosedStream(id);
}

// static
bool QuicSessionPeer::IsStreamCreated(QuicSession* session, QuicStreamId id) {
  return session->stream_map_.contains(id);
}

// static
bool QuicSessionPeer::IsStreamAvailable(QuicSession* session, QuicStreamId id) {
  if (VersionHasIetfQuicFrames(session->transport_version())) {
    if (id % QuicUtils::StreamIdDelta(session->transport_version()) < 2) {
      return session->ietf_streamid_manager_.bidirectional_stream_id_manager_
          .available_streams_.contains(id);
    }
    return session->ietf_streamid_manager_.unidirectional_stream_id_manager_
        .available_streams_.contains(id);
  }
  return session->stream_id_manager_.available_streams_.contains(id);
}

// static
QuicStream* QuicSessionPeer::GetStream(QuicSession* session, QuicStreamId id) {
  return session->GetStream(id);
}

// static
bool QuicSessionPeer::IsStreamWriteBlocked(QuicSession* session,
                                           QuicStreamId id) {
  return session->write_blocked_streams()->IsStreamBlocked(id);
}

// static
QuicAlarm* QuicSessionPeer::GetCleanUpClosedStreamsAlarm(QuicSession* session) {
  return session->closed_streams_clean_up_alarm_.get();
}

// static
LegacyQuicStreamIdManager* QuicSessionPeer::GetStreamIdManager(
    QuicSession* session) {
  return &session->stream_id_manager_;
}

// static
UberQuicStreamIdManager* QuicSessionPeer::ietf_streamid_manager(
    QuicSession* session) {
  return &session->ietf_streamid_manager_;
}

// static
QuicStreamIdManager* QuicSessionPeer::ietf_bidirectional_stream_id_manager(
    QuicSession* session) {
  return &session->ietf_streamid_manager_.bidirectional_stream_id_manager_;
}

// static
QuicStreamIdManager* QuicSessionPeer::ietf_unidirectional_stream_id_manager(
    QuicSession* session) {
  return &session->ietf_streamid_manager_.unidirectional_stream_id_manager_;
}

// static
PendingStream* QuicSessionPeer::GetPendingStream(QuicSession* session,
                                                 QuicStreamId stream_id) {
  auto it = session->pending_stream_map_.find(stream_id);
  return it == session->pending_stream_map_.end() ? nullptr : it->second.get();
}

// static
void QuicSessionPeer::set_is_configured(QuicSession* session, bool value) {
  session->is_configured_ = value;
}

// static
void QuicSessionPeer::SetPerspective(QuicSession* session,
                                     Perspective perspective) {
  session->perspective_ = perspective;
}

// static
size_t QuicSessionPeer::GetNumOpenDynamicStreams(QuicSession* session) {
  size_t result = 0;
  for (const auto& it : session->stream_map_) {
    if (!it.second->is_static()) {
      ++result;
    }
  }
  // Exclude draining streams.
  result -= session->num_draining_streams_;
  // Add locally closed streams.
  result += session->locally_closed_streams_highest_offset_.size();

  return result;
}

// static
size_t QuicSessionPeer::GetNumDrainingStreams(QuicSession* session) {
  return session->num_draining_streams_;
}

// static
QuicAlarm* QuicSessionPeer::GetStreamCountResetAlarm(QuicSession* session) {
  return session->stream_count_reset_alarm_.get();
}

}  // namespace test
}  // namespace quic
```