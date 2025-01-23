Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request is to analyze the `rtp_contributing_source_cache.cc` file, explaining its purpose, its relation to web technologies (JavaScript, HTML, CSS), potential errors, and debugging hints.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for recognizable terms:
    * `RtpContributingSourceCache`:  This is the central class, so its name is a strong clue. "RTP" suggests Real-time Transport Protocol, likely related to media streaming. "Contributing Source" and "Cache" suggest it stores information about media sources.
    * `RTCRtpSynchronizationSource`, `RTCRtpContributingSource`, `RTCRtpSource`:  These seem to be data structures representing different types of RTP sources. The naming suggests a distinction between "synchronization" and "contributing."
    * `RTCPeerConnection`, `RTCRtpReceiver`: These are clearly WebRTC-related. `RTCPeerConnection` is the core interface for establishing peer-to-peer connections, and `RTCRtpReceiver` handles incoming media streams.
    * `ScriptState`, `ExecutionContext`, `LocalDOMWindow`, `DocumentLoadTiming`: These are Blink-specific classes related to the browser environment and JavaScript execution. This reinforces the connection to web technologies.
    * `MaybeUpdateRtpSources`, `GetRtpSources`, `UpdateRtpSourcesOnWorkerThread`, `ClearCache`: These are the main methods of the cache, giving insights into its lifecycle and operations.
    * `worker_thread_runner_`:  Indicates asynchronous operations are involved, potentially for performance.
    * `DOMExceptionCode::kInvalidStateError`: Suggests error handling related to the state of the web page.

3. **Infer Functionality Based on Keywords:** Based on the initial scan, a reasonable initial hypothesis is:  This class manages a cache of information about the sources of RTP media streams received through a WebRTC connection. It distinguishes between synchronization and contributing sources. It likely updates this cache asynchronously.

4. **Analyze Key Functions:** Dive into the important functions:

    * **`RTCRtpSynchronizationSourcesFromRTCRtpSources` and `RTCRtpContributingSourcesFromRTCRtpSources`:** These functions clearly convert from a common `RTCRtpSources` type to the specific synchronization and contributing source types. They extract information like timestamp, source ID, audio level, capture timestamps, and RTP timestamp. The use of `DocumentLoadTiming` suggests the timestamps are being related to the page's timeline. The filtering by `rtp_source->SourceType()` confirms the distinction between SSRC and CSRC.

    * **`RtpContributingSourceCache` constructor:** Takes an `RTCPeerConnection` and a thread runner. This confirms its association with a specific connection and its use of a separate thread.

    * **`getSynchronizationSources` and `getContributingSources`:** These are the public interfaces for accessing the cached data. They take a `ScriptState` and `RTCRtpReceiver`, implying they are called from the JavaScript context when an application needs this information. They also include error checking for detached windows.

    * **`MaybeUpdateRtpSources`:** This is where the caching logic lives. It checks if the cache for a given receiver is already populated. It has a heuristic: if the cache is empty, only update for the requesting receiver; otherwise, update for *all* receivers of that media kind. This is an important optimization detail. It uses `PostCrossThreadTask` to perform the actual update on the worker thread.

    * **`UpdateRtpSourcesOnWorkerThread`:** This function retrieves the actual source information from the platform receiver. The comment about avoiding a "per-receiver block-invoke" explains the motivation for doing this on a separate thread.

    * **`ClearCache`:**  Clears the cached data, likely to be called when the data is no longer needed or to ensure freshness.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** The functions like `getSynchronizationSources` and `getContributingSources` are clearly intended to be called from JavaScript. The return types (`HeapVector<Member<RTCRtp...>>`) will be translated into JavaScript objects representing these sources. The parameters `ScriptState` and `ExceptionState` confirm this interaction. Think about *when* JavaScript would need this information – for monitoring media streams, displaying participant information in a video conference, etc.

    * **HTML:**  While this C++ code doesn't directly manipulate HTML, the information it provides (about media sources) can be used by JavaScript to dynamically update the HTML. For instance, displaying the names or avatars of participants in a video call.

    * **CSS:** Similar to HTML, CSS is used for styling. The JavaScript, using the data from this cache, might change CSS classes or inline styles to reflect the status of media sources (e.g., highlighting the active speaker).

6. **Logic and Assumptions:**

    * **Assumption:** The code assumes that retrieving source information can be potentially slow or blocking, hence the use of a worker thread.
    * **Input/Output:** Consider the inputs to the `get...Sources` functions (a `ScriptState` and `RTCRtpReceiver`) and their outputs (vectors of `RTCRtpSynchronizationSource` or `RTCRtpContributingSource` objects). Think about the data contained within those output objects (SSRC/CSRC, timestamps, audio level, etc.).

7. **User Errors and Debugging:**

    * **User Error:**  Focus on common WebRTC usage patterns that might trigger issues. Forgetting to get receivers, calling these methods at the wrong time (e.g., before the connection is established), or not handling the asynchronous nature of WebRTC operations are good examples.
    * **Debugging:** Trace the flow of execution. Start with a JavaScript call to `getSynchronizationSources`. See how it triggers `MaybeUpdateRtpSources`, which might involve a cross-thread call. Look for breakpoints in both the main thread and the worker thread. Inspect the contents of the caches.

8. **Structure and Refine:** Organize the findings logically. Start with the core functionality, then connect to web technologies, explain the logic, and finally address errors and debugging. Use clear headings and examples. Ensure the language is accessible to someone who might not be a C++ expert.

9. **Review and Iterate:** Read through the analysis to ensure clarity and accuracy. Are there any ambiguities? Could the explanations be improved?  For example, initially, I might not have explicitly linked the timestamp conversion to displaying relative times in the UI, but that's a valuable connection to make.
好的，让我们来详细分析一下 `blink/renderer/modules/peerconnection/rtp_contributing_source_cache.cc` 这个文件。

**功能概述:**

这个文件的主要功能是为一个 `RTCPeerConnection` 对象缓存接收到的 RTP 数据包的源信息（Sources）。它主要关注两种类型的源：

* **Synchronization Sources (SSRC):**  标识 RTP 会话中单个媒体流的源。例如，视频通话中你的摄像头就是一个 SSRC。
* **Contributing Sources (CSRC):**  标识参与了混合（mixing）操作的多个媒体流的源。例如，在会议桥接中，多个参与者的音频流被混合在一起，每个参与者的音频流就是一个 CSRC。

`RtpContributingSourceCache` 维护了一个缓存，以便在 JavaScript 代码需要获取这些源信息时，能够快速提供，而无需每次都通过底层的 WebRTC 引擎去获取。这有助于提高性能，特别是当需要频繁访问这些信息时。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的一部分，它为 WebRTC API 提供了底层的实现。JavaScript 代码通过 WebRTC API 与这个缓存进行交互。

1. **JavaScript:**
   - **`RTCRtpReceiver.getSynchronizationSources()` 和 `RTCRtpReceiver.getContributingSources()` 方法:**  这是 JavaScript 中直接与 `RtpContributingSourceCache` 交互的接口。当 JavaScript 代码调用这些方法时，Blink 引擎会查询 `RtpContributingSourceCache` 以获取缓存的源信息。
   - **事件处理:** JavaScript 代码可能会监听与 `RTCRtpReceiver` 相关的事件（例如 `track` 事件），并在事件处理程序中调用上述方法来获取源信息。
   - **UI 更新:**  获取到的源信息（例如 SSRC 或 CSRC 的 ID、时间戳、音频级别等）可以用于在 Web 页面上展示参与者信息、音频指示器等 UI 元素。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   const peerConnection = new RTCPeerConnection();
   peerConnection.ontrack = (event) => {
     const receiver = event.receiver;
     const syncSources = receiver.getSynchronizationSources();
     const contribSources = receiver.getContributingSources();

     console.log("同步源:", syncSources);
     console.log("贡献源:", contribSources);

     // 假设我们有一个用于显示参与者信息的 HTML 元素
     const participantsDiv = document.getElementById('participants');
     participantsDiv.innerHTML = ''; // 清空之前的显示

     syncSources.forEach(source => {
       const participantInfo = document.createElement('div');
       participantInfo.textContent = `参与者 (SSRC: ${source.source})`;
       participantsDiv.appendChild(participantInfo);
     });

     contribSources.forEach(source => {
       const contributorInfo = document.createElement('div');
       contributorInfo.textContent = `贡献者 (CSRC: ${source.source})`;
       participantsDiv.appendChild(contributorInfo);
     });
   };
   // ... (其他 WebRTC 代码，例如创建 offer/answer，添加 ice candidate 等)
   ```

2. **HTML:**
   - HTML 提供了页面的结构。JavaScript 代码可以使用从 `RtpContributingSourceCache` 获取的数据来动态地修改 HTML 结构，例如添加或更新参与者列表。

3. **CSS:**
   - CSS 用于页面的样式。JavaScript 可以根据从 `RtpContributingSourceCache` 获取的数据，动态地改变 CSS 样式。例如，可以根据音频级别高亮显示正在说话的参与者。

   **举例说明:**

   ```javascript
   // JavaScript 代码 (在上面的 ontack 事件处理程序中)
   contribSources.forEach(source => {
     const contributorElement = document.createElement('div');
     contributorElement.textContent = `贡献者 (CSRC: ${source.source})`;
     if (source.audioLevel > 0.5) { // 假设音频级别超过 0.5 则高亮
       contributorElement.classList.add('speaking'); // 添加 CSS 类
     }
     participantsDiv.appendChild(contributorElement);
   });
   ```

   ```css
   /* CSS 代码 */
   .speaking {
     background-color: yellow;
     font-weight: bold;
   }
   ```

**逻辑推理 (假设输入与输出):**

假设我们有一个 `RTCPeerConnection` 接收到一个包含音频 track 的 RTP 流。这个流中可能包含 SSRC 和 CSRC 信息。

**假设输入:**

* **`RTCRtpReceiver` 对象:**  对应接收到的音频 track。
* **缓存状态:**  假设该 `RTCRtpReceiver` 的源信息尚未缓存。
* **底层 WebRTC 引擎提供的源信息:** 假设该音频 track 有一个 SSRC (例如 12345) 和两个 CSRC (例如 67890 和 13579)，以及它们各自的时间戳和可能的音频级别。

**处理流程 (`MaybeUpdateRtpSources` 方法):**

1. 当 JavaScript 调用 `receiver.getSynchronizationSources()` 或 `receiver.getContributingSources()` 时，会触发 `RtpContributingSourceCache::MaybeUpdateRtpSources` 方法。
2. `MaybeUpdateRtpSources` 检查缓存中是否已存在该 `RTCRtpReceiver` 的源信息。由于是首次请求，缓存中不存在。
3. 它会创建一个任务，将 `UpdateRtpSourcesOnWorkerThread` 方法 पोस्ट 到工作线程上执行。
4. 在工作线程中，`UpdateRtpSourcesOnWorkerThread` 调用底层的 WebRTC 引擎接口（`receiver->platform_receiver()->GetSources()`）来获取最新的源信息。
5. 获取到的源信息 (包含 SSRC 12345 和 CSRC 67890, 13579 的信息) 被存储到 `cached_sources_by_audio_receiver_` 哈希表中，以 `RTCRtpReceiverPlatform*` 为键。
6. 主线程等待工作线程完成。
7. `MaybeUpdateRtpSources` 将一个微任务添加到事件循环中，以调用 `ClearCache`，但由于是在微任务中调用，通常在当前任务执行完毕后才会执行，这意味着本次 `getSynchronizationSources` 或 `getContributingSources` 调用仍然可以从刚刚更新的缓存中获取数据。

**预期输出 (在 JavaScript 中):**

* `receiver.getSynchronizationSources()` 将返回一个包含一个 `RTCRtpSynchronizationSource` 对象的数组，该对象具有 `source` 属性值为 12345，以及其他相关的时间戳等信息。
* `receiver.getContributingSources()` 将返回一个包含两个 `RTCRtpContributingSource` 对象的数组，分别具有 `source` 属性值为 67890 和 13579，以及其他相关信息。

**用户或编程常见的使用错误：**

1. **在 `RTCPeerConnection` 关闭后访问源信息:** 如果在 `RTCPeerConnection` 已经关闭或正在关闭的过程中尝试获取源信息，可能会导致错误或返回过时的信息。这个文件中的 `if (!script_state->ContextIsValid())` 检查可以防止在窗口被卸载后访问，但用户代码仍然需要在合适的生命周期内进行操作。
   - **错误示例 (JavaScript):**
     ```javascript
     peerConnection.close();
     setTimeout(() => {
       // 错误：peerConnection 可能已经关闭
       const receivers = peerConnection.getReceivers();
       if (receivers.length > 0) {
         receivers[0].getSynchronizationSources();
       }
     }, 1000);
     ```

2. **频繁调用 `getSynchronizationSources` 或 `getContributingSources`:**  虽然缓存是为了提高性能，但如果在一个紧密的循环中频繁调用这些方法，仍然可能导致不必要的开销。开发者应该考虑事件驱动的方式，例如在 `track` 事件或接收到新的 RTP 数据包时更新 UI，而不是轮询。

3. **假设源信息是静态的:**  SSRC 通常是固定的，但 CSRC 可能会随着媒体流的混合而变化。开发者需要意识到这一点，并在 UI 上正确处理源信息的更新。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户发起或接收到一个 WebRTC 连接:** 用户可能点击了一个视频通话按钮，或者接受了一个呼叫邀请。这会导致 JavaScript 代码创建 `RTCPeerConnection` 对象。
2. **远端发送媒体流:**  远端 peer 发送包含音频或视频数据的 RTP 数据包。
3. **Blink 引擎接收到 RTP 数据包:**  Chromium 的网络层接收到这些数据包，并将它们传递给 Blink 渲染引擎的 WebRTC 实现。
4. **创建 `RTCRtpReceiver` 对象:**  对于接收到的每个媒体 track，Blink 会创建一个 `RTCRtpReceiver` 对象来处理接收到的数据。
5. **JavaScript 代码尝试获取源信息:**  开发者编写的 JavaScript 代码调用 `receiver.getSynchronizationSources()` 或 `receiver.getContributingSources()` 来获取有关媒体源的信息，以便在 UI 上显示。
6. **调用到 `RtpContributingSourceCache`:**  JavaScript 的调用会最终到达 `blink/renderer/modules/peerconnection/rtp_contributing_source_cache.cc` 文件中的相应方法。

**调试线索:**

* **断点:** 在 `RtpContributingSourceCache::getSynchronizationSources`、`RtpContributingSourceCache::getContributingSources` 和 `RtpContributingSourceCache::MaybeUpdateRtpSources` 等方法中设置断点，可以观察代码的执行流程和缓存的状态。
* **日志:** 在这些方法中添加日志输出，可以记录何时更新了缓存，以及缓存的内容。
* **WebRTC 内部日志:**  启用 Chromium 的 WebRTC 内部日志 (通过 `chrome://webrtc-internals/`) 可以查看更底层的 RTP 包信息和源标识符，有助于验证 `RtpContributingSourceCache` 中缓存的数据是否与实际接收到的数据一致。
* **检查 `RTCPeerConnection` 和 `RTCRtpReceiver` 的状态:**  确保在调用 `getSynchronizationSources` 或 `getContributingSources` 时，`RTCPeerConnection` 和相关的 `RTCRtpReceiver` 对象处于有效状态。

总而言之，`rtp_contributing_source_cache.cc` 是 Blink 引擎中负责高效管理 WebRTC RTP 源信息缓存的关键组件，它直接支持 JavaScript WebRTC API，并影响着 Web 页面上实时通信功能的实现。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtp_contributing_source_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtp_contributing_source_cache.h"

#include "base/check.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

HeapVector<Member<RTCRtpSynchronizationSource>>
RTCRtpSynchronizationSourcesFromRTCRtpSources(
    ScriptState* script_state,
    const RtpContributingSourceCache::RTCRtpSources* rtp_sources) {
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  DocumentLoadTiming& time_converter =
      window->GetFrame()->Loader().GetDocumentLoader()->GetTiming();

  HeapVector<Member<RTCRtpSynchronizationSource>> synchronization_sources;
  if (!rtp_sources)
    return synchronization_sources;
  for (const auto& rtp_source : *rtp_sources) {
    if (rtp_source->SourceType() != RTCRtpSource::Type::kSSRC)
      continue;
    RTCRtpSynchronizationSource* synchronization_source =
        MakeGarbageCollected<RTCRtpSynchronizationSource>();
    synchronization_source->setTimestamp(
        time_converter.MonotonicTimeToPseudoWallTime(rtp_source->Timestamp())
            .InMilliseconds());
    synchronization_source->setSource(rtp_source->Source());
    if (rtp_source->AudioLevel().has_value()) {
      synchronization_source->setAudioLevel(rtp_source->AudioLevel().value());
    }
    if (rtp_source->CaptureTimestamp().has_value()) {
      synchronization_source->setCaptureTimestamp(
          rtp_source->CaptureTimestamp().value());
    }
    if (rtp_source->SenderCaptureTimeOffset().has_value()) {
      synchronization_source->setSenderCaptureTimeOffset(
          rtp_source->SenderCaptureTimeOffset().value());
    }
    synchronization_source->setRtpTimestamp(rtp_source->RtpTimestamp());
    synchronization_sources.push_back(synchronization_source);
  }
  return synchronization_sources;
}

HeapVector<Member<RTCRtpContributingSource>>
RTCRtpContributingSourcesFromRTCRtpSources(
    ScriptState* script_state,
    const RtpContributingSourceCache::RTCRtpSources* rtp_sources) {
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  DocumentLoadTiming& time_converter =
      window->GetFrame()->Loader().GetDocumentLoader()->GetTiming();

  HeapVector<Member<RTCRtpContributingSource>> contributing_sources;
  if (!rtp_sources)
    return contributing_sources;
  for (const auto& rtp_source : *rtp_sources) {
    if (rtp_source->SourceType() != RTCRtpSource::Type::kCSRC)
      continue;
    RTCRtpContributingSource* contributing_source =
        MakeGarbageCollected<RTCRtpContributingSource>();
    contributing_source->setTimestamp(
        time_converter.MonotonicTimeToPseudoWallTime(rtp_source->Timestamp())
            .InMilliseconds());
    contributing_source->setSource(rtp_source->Source());
    if (rtp_source->AudioLevel().has_value()) {
      contributing_source->setAudioLevel(rtp_source->AudioLevel().value());
    }
    if (rtp_source->CaptureTimestamp().has_value()) {
      contributing_source->setCaptureTimestamp(
          rtp_source->CaptureTimestamp().value());
    }
    if (rtp_source->SenderCaptureTimeOffset().has_value()) {
      contributing_source->setSenderCaptureTimeOffset(
          rtp_source->SenderCaptureTimeOffset().value());
    }
    contributing_source->setRtpTimestamp(rtp_source->RtpTimestamp());
    contributing_sources.push_back(contributing_source);
  }
  return contributing_sources;
}

}  // namespace

RtpContributingSourceCache::RtpContributingSourceCache(
    RTCPeerConnection* pc,
    scoped_refptr<base::SingleThreadTaskRunner> worker_thread_runner)
    : pc_(pc), worker_thread_runner_(worker_thread_runner) {
  DCHECK(pc_);
  DCHECK(worker_thread_runner_);
}

void RtpContributingSourceCache::Shutdown() {
  weak_factory_.InvalidateWeakPtrs();
}

HeapVector<Member<RTCRtpSynchronizationSource>>
RtpContributingSourceCache::getSynchronizationSources(
    ScriptState* script_state,
    ExceptionState& exception_state,
    RTCRtpReceiver* receiver) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Window is detached");
    return HeapVector<Member<RTCRtpSynchronizationSource>>();
  }
  MaybeUpdateRtpSources(script_state, receiver);
  return RTCRtpSynchronizationSourcesFromRTCRtpSources(script_state,
                                                       GetRtpSources(receiver));
}

HeapVector<Member<RTCRtpContributingSource>>
RtpContributingSourceCache::getContributingSources(
    ScriptState* script_state,
    ExceptionState& exception_state,
    RTCRtpReceiver* receiver) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Window is detached");
    return HeapVector<Member<RTCRtpContributingSource>>();
  }
  MaybeUpdateRtpSources(script_state, receiver);
  return RTCRtpContributingSourcesFromRTCRtpSources(script_state,
                                                    GetRtpSources(receiver));
}

void RtpContributingSourceCache::MaybeUpdateRtpSources(
    ScriptState* script_state,
    RTCRtpReceiver* requesting_receiver) {
  if (!pc_) {
    return;
  }
  HashMap<RTCRtpReceiverPlatform*, RTCRtpSources>* cached_sources_by_receiver;
  switch (requesting_receiver->kind()) {
    case RTCRtpReceiver::MediaKind::kAudio:
      cached_sources_by_receiver = &cached_sources_by_audio_receiver_;
      break;
    case RTCRtpReceiver::MediaKind::kVideo:
      cached_sources_by_receiver = &cached_sources_by_video_receiver_;
      break;
  }
  if (cached_sources_by_receiver->find(
          requesting_receiver->platform_receiver()) !=
      cached_sources_by_receiver->end()) {
    // The sources are already cached for this receiver, no action needed.
    return;
  }

  // Receivers whose cache to update.
  Vector<RTCRtpReceiverPlatform*> receivers;
  if (cached_sources_by_receiver->empty()) {
    // If the cache is empty then we only update the cache for this one
    // receiver. This avoids updating the cache for all receivers in cases where
    // the app is only interested in a single receiver per kind.
    receivers.push_back(requesting_receiver->platform_receiver());
  } else {
    // If the cache is not empty, the app is interested in multiple
    // RTCRtpReceiver objects. In this case, pay the cost up-front to update the
    // cache for all receivers of this kind under the assumption that the app
    // will be interested in all receivers of this kind. This heuristic limits
    // the number of block-invoke in common use cases, but may increase overhead
    // in edge cases where a subset of receivers are polled per microtask.
    for (const Member<RTCRtpReceiver>& receiver : pc_->getReceivers()) {
      if (receiver->kind() != requesting_receiver->kind())
        continue;
      receivers.push_back(receiver->platform_receiver());
    }
  }
  base::WaitableEvent event;
  // Unretained is safe because we're waiting for the operation to complete.
  PostCrossThreadTask(
      *worker_thread_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(
          &RtpContributingSourceCache::UpdateRtpSourcesOnWorkerThread,
          WTF::CrossThreadUnretained(this),
          WTF::CrossThreadUnretained(&receivers),
          WTF::CrossThreadUnretained(cached_sources_by_receiver),
          WTF::CrossThreadUnretained(&event)));
  event.Wait();

  ExecutionContext::From(script_state)
      ->GetAgent()
      ->event_loop()
      ->EnqueueMicrotask(WTF::BindOnce(&RtpContributingSourceCache::ClearCache,
                                       weak_factory_.GetWeakPtr()));
}

void RtpContributingSourceCache::UpdateRtpSourcesOnWorkerThread(
    Vector<RTCRtpReceiverPlatform*>* receivers,
    HashMap<RTCRtpReceiverPlatform*, RTCRtpSources>* cached_sources_by_receiver,
    base::WaitableEvent* event) {
  // Calling GetSources() while on the worker thread avoids a per-receiver
  // block-invoke inside the webrtc::RtpReceiverInterface PROXY.
  for (RTCRtpReceiverPlatform* receiver : *receivers) {
    if (cached_sources_by_receiver->find(receiver) ==
        cached_sources_by_receiver->end()) {
      cached_sources_by_receiver->insert(receiver, receiver->GetSources());
    }
  }
  event->Signal();
}

void RtpContributingSourceCache::ClearCache() {
  cached_sources_by_audio_receiver_.clear();
  cached_sources_by_video_receiver_.clear();
}

const RtpContributingSourceCache::RTCRtpSources*
RtpContributingSourceCache::GetRtpSources(RTCRtpReceiver* receiver) const {
  const HashMap<RTCRtpReceiverPlatform*, RTCRtpSources>*
      cached_sources_by_receiver =
          receiver->kind() == RTCRtpReceiver::MediaKind::kAudio
              ? &cached_sources_by_audio_receiver_
              : &cached_sources_by_video_receiver_;
  auto it = cached_sources_by_receiver->find(receiver->platform_receiver());
  if (it == cached_sources_by_receiver->end())
    return nullptr;
  return &it->value;
}

}  // namespace blink
```