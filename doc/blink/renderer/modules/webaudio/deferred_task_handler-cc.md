Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ code snippet for `DeferredTaskHandler.cc` within the Chromium Blink engine. The request specifically asks for its functions, relationships with web technologies (JS, HTML, CSS), logical inferences, potential user/programmer errors, and debugging context.

2. **Initial Code Scan and Keyword Identification:** I'll first quickly scan the code, looking for keywords and class/method names that hint at the purpose of the class. I see things like `lock`, `unlock`, `BreakConnections`, `MarkDirty`, `Add/Remove`, `Update`, `Process`, `TailProcessing`, `AudioNode`, `AudioContext`. These terms strongly suggest this class manages tasks related to the Web Audio API and its internal graph processing.

3. **Functionality Breakdown (Iterative Process):**  I'll go through the code method by method and try to summarize each function's purpose.

    * **Synchronization Primitives (`lock`, `TryLock`, `unlock`, `OfflineLock`):** Clearly related to thread safety and managing concurrent access to the audio graph. The `OfflineLock` specifically points to the `OfflineAudioContext`.
    * **Graph Manipulation (`BreakConnections`, `MarkSummingJunctionDirty`, `RemoveMarkedSummingJunction`, `MarkAudioNodeOutputDirty`, `RemoveMarkedAudioNodeOutput`):** These indicate managing the structure and state of the audio processing graph. "Dirty" likely means needing updates.
    * **Automatic Pull Nodes (`AddAutomaticPullNode`, `RemoveAutomaticPullNode`, `HasAutomaticPullNodes`, `UpdateAutomaticPullNodes`, `ProcessAutomaticPullNodes`):** This seems like a specific type of audio node that needs periodic processing. The "pull" likely refers to how data is fetched.
    * **Tail Processing (`AddTailProcessingHandler`, `RemoveTailProcessingHandler`, `UpdateTailProcessingHandlers`, `FinishTailProcessing`, `DisableOutputsForTailProcessing`):** This is a crucial concept in Web Audio, dealing with nodes that have latency and need special handling at the end of processing.
    * **Channel Configuration (`AddChangedChannelCountMode`, `RemoveChangedChannelCountMode`, `AddChangedChannelInterpretation`, `RemoveChangedChannelInterpretation`, `UpdateChangedChannelCountMode`, `UpdateChangedChannelInterpretation`):** Deals with dynamically changing the number of channels and their interpretation within audio nodes.
    * **Object Lifecycle Management (`AddRenderingOrphanHandler`, `RequestToDeleteHandlersOnMainThread`, `DeleteHandlersOnMainThread`, `ClearHandlersToBeDeleted`, `ClearContextFromOrphanHandlers`):**  Manages the creation and destruction of audio graph objects, including handling objects that might be held by different threads.
    * **Thread Management (`SetAudioThreadToCurrentThread`, `IsAudioThread`, `IsMainThread`):**  Confirms the class is involved in multi-threading.
    * **Constructors/Destructors:** Standard object lifecycle management.
    * **Helper Classes (`GraphAutoLocker`, `OfflineGraphAutoLocker`):** RAII wrappers for managing locks, ensuring they are released.
    * **`HandleDeferredTasks`:**  A central function to perform a batch of updates.

4. **Relating to Web Technologies (JS, HTML, CSS):** This requires understanding how the Web Audio API is used in web development.

    * **JavaScript:** The primary interface for developers. I'll think about how JS calls would trigger actions that eventually lead to this C++ code. Examples: creating audio nodes, connecting them, starting/stopping audio, changing node parameters.
    * **HTML:**  Not directly related, but the `<audio>` or `<video>` elements could be sources for Web Audio.
    * **CSS:**  Generally not related to Web Audio's core functionality.

5. **Logical Inferences and Examples:** I'll look for patterns and dependencies in the code to create hypothetical scenarios.

    * **Dirty Flags:** The "dirty" flags and their update methods suggest a mechanism for optimizing updates. Only nodes that have changed need to be processed.
    * **Tail Processing:**  The handling of tail time and latency is essential for correct audio rendering, especially with effects like reverb or delay. I'll think about what would happen if tail processing wasn't handled correctly.

6. **User and Programmer Errors:** I'll consider common mistakes when using the Web Audio API that might surface issues related to this code.

    * **Incorrect Threading:** Trying to modify the audio graph from the wrong thread is a classic concurrency error. The `DCHECK`s in the code highlight this.
    * **Resource Management:** Failing to disconnect nodes or release resources could lead to memory leaks or unexpected behavior.

7. **Debugging Context:** How would a developer end up looking at this code?

    * **Performance Issues:** If there are glitches or slowdowns in the audio, this class might be a point of investigation.
    * **Unexpected Behavior:** If audio isn't processing correctly, understanding how tasks are deferred and handled is crucial.
    * **Crashes:**  Concurrency issues could lead to crashes, and the locking mechanisms here would be relevant.

8. **Structure and Refine:** I'll organize my findings into the categories requested by the prompt. I'll use clear and concise language, providing examples where possible. I will also emphasize the separation of concerns between the main thread and the audio thread. I'll double-check that I've addressed each part of the prompt.

9. **Self-Correction/Review:** After drafting the answer, I'll reread the code and my explanation to ensure accuracy and completeness. I'll look for any inconsistencies or areas where I could provide more clarity. For example, I might initially forget to explicitly mention the role of the task runner and how it facilitates cross-thread communication. I'll also ensure the examples provided are relevant and easy to understand.
好的，我们来详细分析一下 `blink/renderer/modules/webaudio/deferred_task_handler.cc` 文件的功能。

**文件功能概述**

`DeferredTaskHandler` 类是 Chromium Blink 引擎中 Web Audio API 的核心组件之一，它主要负责**管理和执行需要在特定时机（通常是非实时的）处理的任务**，这些任务通常涉及到音频图的修改和状态更新。它的主要目的是确保音频处理的**线程安全性和性能**，避免在实时音频渲染线程中进行耗时的操作。

**核心功能点：**

1. **线程安全管理：**
   - 使用互斥锁 (`context_graph_mutex_`) 来保护对音频图的并发访问，确保在多线程环境下数据的一致性。
   - 区分主线程和音频线程，并使用 `DCHECK` 断言来确保某些操作在正确的线程执行。
   - 提供 `lock()`, `TryLock()`, `unlock()`, `OfflineLock()` 等方法来控制锁的获取和释放。`OfflineLock()` 专门用于离线音频上下文，它将离线渲染线程视为音频线程。

2. **延迟任务处理：**
   - 维护多个集合来记录需要延迟处理的任务，例如：
     - `dirty_summing_junctions_`: 标记需要更新渲染状态的 summing junction。
     - `dirty_audio_node_outputs_`: 标记需要更新渲染状态的音频节点输出。
     - `deferred_count_mode_change_`: 存储 channel count mode 发生变化的音频节点。
     - `deferred_channel_interpretation_change_`: 存储 channel interpretation 发生变化的音频节点。
   - 提供 `Mark...Dirty()` 和 `AddChanged...()` 方法来将需要处理的对象添加到相应的集合中。
   - 提供 `HandleDirty...()` 和 `UpdateChanged...()` 方法来实际执行这些延迟的任务。这些方法通常在主线程上调用。

3. **自动拉取节点 (Automatic Pull Nodes) 管理：**
   -  维护 `automatic_pull_handlers_` 集合来管理需要周期性拉取数据的音频节点（例如，ScriptProcessorNode）。
   -  提供添加、删除和更新自动拉取节点的方法。
   -  `ProcessAutomaticPullNodes()` 方法在音频线程上调用，实际触发这些节点的处理。

4. **尾部处理 (Tail Processing) 管理：**
   -  维护 `tail_processing_handlers_` 集合来管理具有尾部时间（latency）的音频节点，这些节点在停止后仍需处理一段时间。
   -  提供添加、删除和更新尾部处理节点的方法。
   -  `UpdateTailProcessingHandlers()` 检查哪些尾部处理节点可以停止处理。
   -  `FinishTailProcessing()` 和 `DisableOutputsForTailProcessing()` 负责最终停止尾部处理节点的输出。

5. **孤立节点 (Orphan Handlers) 管理：**
   -  维护 `rendering_orphan_handlers_` 和 `deletable_orphan_handlers_` 来管理不再使用的音频节点，这些节点需要在主线程上安全地清理。
   -  提供方法将孤立节点添加到列表中，并在主线程上删除它们。

6. **上下文生命周期管理：**
   -  `ContextWillBeDestroyed()` 方法用于在音频上下文即将销毁时清理相关的资源。
   -  `ClearHandlersToBeDeleted()` 和 `ClearContextFromOrphanHandlers()` 执行具体的清理操作。

**与 JavaScript, HTML, CSS 的关系**

`DeferredTaskHandler` 主要在 Blink 引擎内部工作，与 JavaScript 的 Web Audio API 直接相关，而与 HTML 和 CSS 的关系较为间接。

**JavaScript 层面的交互：**

- **创建和连接音频节点：** 当 JavaScript 代码使用 `create...()` 方法创建音频节点并通过 `connect()` 方法连接它们时，这些操作可能会触发 `DeferredTaskHandler` 中的方法。例如，连接操作可能需要更新节点的连接状态，这可能被标记为延迟任务。
  ```javascript
  const audioContext = new AudioContext();
  const oscillator = audioContext.createOscillator();
  const gainNode = audioContext.createGain();
  oscillator.connect(gainNode); // 这里可能会触发 DeferredTaskHandler 的操作
  gainNode.connect(audioContext.destination);
  oscillator.start();
  ```

- **修改节点参数：** 当 JavaScript 代码修改音频节点的参数（例如，音量、频率等）时，这些修改可能需要在音频渲染线程之外进行初步处理，然后再同步到音频线程。`DeferredTaskHandler` 可以用来处理这些参数的更新。
  ```javascript
  gainNode.gain.setValueAtTime(0.5, audioContext.currentTime); // 修改增益，可能触发延迟任务
  ```

- **控制音频播放状态：** 当 JavaScript 代码调用 `start()` 或 `stop()` 方法控制音频源节点的播放时，这会涉及到音频图的结构变化，可能需要 `DeferredTaskHandler` 来协调这些变化。

- **使用 ScriptProcessorNode:** `ScriptProcessorNode` 的 `onaudioprocess` 事件处理函数在音频线程中执行，但与主线程的交互（例如，更新 UI）可能需要借助 `DeferredTaskHandler` 进行同步。

- **使用 OfflineAudioContext:**  `OfflineAudioContext` 的渲染过程不依赖于实时的音频硬件，`DeferredTaskHandler` 中的 `OfflineLock()` 方法用于在这种上下文中进行同步。

**HTML 层面的间接关系：**

- HTML 的 `<audio>` 或 `<video>` 元素可以作为 Web Audio API 的音频源。当 JavaScript 使用 `createMediaElementSource()` 方法从这些元素创建音频源时，`DeferredTaskHandler` 可能会参与到音频图的构建过程中。

**CSS 层面：**

- CSS 与 `DeferredTaskHandler` 的关系非常弱，几乎没有直接联系。CSS 主要负责页面的样式和布局，不直接参与音频处理逻辑。

**逻辑推理与假设输入输出**

假设我们有以下 JavaScript 代码：

```javascript
const audioContext = new AudioContext();
const oscillator = audioContext.createOscillator();
const gainNode = audioContext.createGain();
oscillator.connect(gainNode);
gainNode.connect(audioContext.destination);
oscillator.start();

// 一段时间后修改增益
gainNode.gain.setValueAtTime(0.2, audioContext.currentTime + 1);
```

**假设输入：**

1. 用户在页面加载后创建了一个 `AudioContext`。
2. 用户创建了一个 `OscillatorNode` 和一个 `GainNode`。
3. 用户将 `OscillatorNode` 连接到 `GainNode`，再连接到 `AudioContext.destination`。
4. 用户启动了 `OscillatorNode`。
5. 用户在 1 秒后将 `GainNode` 的增益值设置为 0.2。

**逻辑推理与可能的输出/操作：**

1. 当 `connect()` 方法被调用时，`DeferredTaskHandler` 可能会将相关的连接信息添加到内部数据结构中，确保音频图的正确构建。这可能涉及到更新 `AudioNodeOutput` 的状态。
2. 当 `gainNode.gain.setValueAtTime()` 被调用时，这个操作发生在主线程。`DeferredTaskHandler` 的 `MarkAudioNodeOutputDirty()` 可能会被调用，将 `gainNode` 的输出标记为 "dirty"，表示其渲染状态需要更新。
3. 在音频渲染过程中（发生在音频线程），`DeferredTaskHandler::HandleDirtyAudioNodeOutputs()` 方法会被调用。遍历 `dirty_audio_node_outputs_` 集合，并调用 `gainNode` 输出的 `UpdateRenderingState()` 方法，从而使得增益的变化生效。

**用户或编程常见的使用错误**

1. **在错误的线程上操作音频图：** 这是最常见的错误。例如，尝试在音频渲染线程中直接修改音频节点的连接关系，或者在主线程中执行耗时的音频处理逻辑。`DeferredTaskHandler` 中的 `DCHECK(!IsAudioThread())` 和 `DCHECK(IsAudioThread())` 可以帮助开发者发现这类错误。

   **示例：**

   ```c++
   // 假设这是在音频渲染线程中执行的代码
   void AudioThreadRenderCallback() {
       // 错误的做法：直接修改音频图连接
       // audio_node->ConnectTo(another_node); // 可能会导致崩溃或数据不一致
   }
   ```

   **正确做法：** 将需要修改音频图的操作提交到主线程执行，或者使用 `DeferredTaskHandler` 提供的机制进行延迟处理。

2. **忘记释放资源或断开连接：**  如果音频节点不再使用，但其连接没有断开，可能会导致内存泄漏或意外的音频输出。`DeferredTaskHandler` 中的孤立节点管理机制可以帮助清理这些不再使用的节点。

   **示例：**

   ```javascript
   // 创建并连接节点
   const oscillator = audioContext.createOscillator();
   const gainNode = audioContext.createGain();
   oscillator.connect(gainNode);
   gainNode.connect(audioContext.destination);
   oscillator.start();

   // ... 一段时间后不再需要 oscillator，但忘记断开连接
   // oscillator.disconnect(); // 应该调用
   ```

3. **不正确的尾部处理理解：** 对于具有尾部时间的节点（例如，混响器），如果过早地停止处理，可能会导致音频截断。`DeferredTaskHandler` 的尾部处理机制确保这些节点在停止后仍能完成其尾部时间的处理。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在使用网页时遇到了 Web Audio 相关的错误或性能问题，开发者可能会进行以下调试：

1. **用户交互触发事件：** 用户在网页上执行了某些操作，例如点击按钮播放音频、拖动滑块调整音量等。这些操作会触发 JavaScript 代码的执行。

2. **JavaScript 调用 Web Audio API：**  JavaScript 代码调用 Web Audio API 的方法，例如 `createOscillator()`, `connect()`, `start()`, `setValueAtTime()` 等。

3. **Blink 引擎接收 API 调用：**  这些 JavaScript 调用会通过 Blink 引擎的 bindings 层传递到 C++ 代码中。相关的 Web Audio API 实现（例如 `OscillatorNode::connect()`, `AudioParam::setValueAtTime()`）会被调用。

4. **`DeferredTaskHandler` 参与处理：** 在这些 C++ 方法的实现中，如果涉及到需要在特定时机处理的任务（例如，更新音频图的连接，标记节点状态为 dirty），就会调用 `DeferredTaskHandler` 的相应方法。

   - 例如，在 `AudioNode::Connect()` 的实现中，可能会调用 `DeferredTaskHandler::MarkAudioNodeOutputDirty()`。
   - 在 `AudioParam::SetValueAtTime()` 的实现中，可能会调用 `DeferredTaskHandler::MarkAudioNodeOutputDirty()`。

5. **延迟任务的执行：**
   - 对于标记为 "dirty" 的节点，`DeferredTaskHandler::HandleDirtyAudioNodeOutputs()` 或 `DeferredTaskHandler::HandleDirtySummingJunctions()` 会在主线程的适当时间被调用，执行实际的更新操作。
   - 对于自动拉取节点，`DeferredTaskHandler::ProcessAutomaticPullNodes()` 会在音频线程周期性地调用。
   - 对于尾部处理节点，`DeferredTaskHandler::UpdateTailProcessingHandlers()` 和 `DeferredTaskHandler::FinishTailProcessing()` 会在音频停止后进行处理。

6. **调试线索：**

   - **断点调试：** 开发者可以在 `DeferredTaskHandler.cc` 中的关键方法（例如 `lock()`, `HandleDirtyAudioNodeOutputs()`, `ProcessAutomaticPullNodes()`) 设置断点，跟踪代码的执行流程，查看哪些任务被添加，何时被执行。
   - **日志输出：**  在 `DeferredTaskHandler` 中添加日志输出，记录任务的添加和执行，可以帮助理解任务的处理顺序和时机。
   - **Web Inspector 的 Timeline 工具：**  Chrome 的开发者工具中的 Timeline (Performance) 面板可以显示音频处理相关的事件和耗时，帮助识别性能瓶颈。
   - **查看 Web Audio 的内部状态：**  虽然不容易直接查看 `DeferredTaskHandler` 的内部状态，但可以通过观察音频的输出、连接关系等来推断其行为。

总而言之，`DeferredTaskHandler.cc` 是 Web Audio API 实现中至关重要的一个文件，它负责管理和协调音频处理任务的执行，确保音频的稳定性和性能。理解其功能有助于深入理解 Web Audio API 的内部工作机制，并能帮助开发者诊断和解决相关的 Bug。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/deferred_task_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/modules/webaudio/deferred_task_handler.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/modules/webaudio/audio_node.h"
#include "third_party/blink/renderer/modules/webaudio/audio_node_output.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

void DeferredTaskHandler::lock() {
  // Don't allow regular lock in real-time audio thread.
  DCHECK(!IsAudioThread());
  context_graph_mutex_.lock();
}

bool DeferredTaskHandler::TryLock() {
  // Try to catch cases of using try lock on main thread
  // - it should use regular lock.
  DCHECK(IsAudioThread());
  if (!IsAudioThread()) {
    // In release build treat tryLock() as lock() (since above
    // DCHECK(isAudioThread) never fires) - this is the best we can do.
    lock();
    return true;
  }
  return context_graph_mutex_.TryLock();
}

void DeferredTaskHandler::unlock() {
  context_graph_mutex_.unlock();
}

void DeferredTaskHandler::OfflineLock() {
  // CHECK is here to make sure to explicitly crash if this is called from
  // other than the offline render thread, which is considered as the audio
  // thread in OfflineAudioContext.
  CHECK(IsAudioThread()) << "DeferredTaskHandler::offlineLock() must be called "
                            "within the offline audio thread.";

  context_graph_mutex_.lock();
}

void DeferredTaskHandler::BreakConnections() {
  DCHECK(IsAudioThread());
  AssertGraphOwner();

  // Remove any finished handlers from the active handlers list and break the
  // connection.
  wtf_size_t size = finished_source_handlers_.size();
  if (size > 0) {
    for (auto finished : finished_source_handlers_) {
      finished->BreakConnectionWithLock();
      active_source_handlers_.erase(finished);
    }
    finished_source_handlers_.clear();
  }
}

void DeferredTaskHandler::MarkSummingJunctionDirty(
    AudioSummingJunction* summing_junction) {
  AssertGraphOwner();
  dirty_summing_junctions_.insert(summing_junction);
}

void DeferredTaskHandler::RemoveMarkedSummingJunction(
    AudioSummingJunction* summing_junction) {
  DCHECK(IsMainThread());
  AssertGraphOwner();
  dirty_summing_junctions_.erase(summing_junction);
}

void DeferredTaskHandler::MarkAudioNodeOutputDirty(AudioNodeOutput* output) {
  DCHECK(IsMainThread());
  AssertGraphOwner();
  dirty_audio_node_outputs_.insert(output);
}

void DeferredTaskHandler::RemoveMarkedAudioNodeOutput(AudioNodeOutput* output) {
  DCHECK(IsMainThread());
  AssertGraphOwner();
  dirty_audio_node_outputs_.erase(output);
}

void DeferredTaskHandler::HandleDirtyAudioSummingJunctions() {
  AssertGraphOwner();
  for (AudioSummingJunction* junction : dirty_summing_junctions_) {
    junction->UpdateRenderingState();
  }
  dirty_summing_junctions_.clear();
}

void DeferredTaskHandler::HandleDirtyAudioNodeOutputs() {
  AssertGraphOwner();

  HashSet<AudioNodeOutput*> dirty_outputs;
  dirty_audio_node_outputs_.swap(dirty_outputs);

  // Note: the updating of rendering state may cause output nodes
  // further down the chain to be marked as dirty. These will not
  // be processed in this render quantum.
  for (AudioNodeOutput* output : dirty_outputs) {
    output->UpdateRenderingState();
  }
}

void DeferredTaskHandler::AddAutomaticPullNode(
    scoped_refptr<AudioHandler> node) {
  AssertGraphOwner();

  if (!automatic_pull_handlers_.Contains(node)) {
    automatic_pull_handlers_.insert(node);
    automatic_pull_handlers_need_updating_ = true;
  }
}

void DeferredTaskHandler::RemoveAutomaticPullNode(AudioHandler* node) {
  AssertGraphOwner();

  auto it = automatic_pull_handlers_.find(node);
  if (it != automatic_pull_handlers_.end()) {
    automatic_pull_handlers_.erase(it);
    automatic_pull_handlers_need_updating_ = true;
  }
}

bool DeferredTaskHandler::HasAutomaticPullNodes() {
  DCHECK(IsAudioThread());

  base::AutoTryLock try_locker(automatic_pull_handlers_lock_);

  // This assumes there is one or more automatic pull nodes when the mutex
  // is held by AddAutomaticPullNode() or RemoveAutomaticPullNode() method.
  return try_locker.is_acquired() ? automatic_pull_handlers_.size() > 0 : true;
}

void DeferredTaskHandler::UpdateAutomaticPullNodes() {
  DCHECK(IsAudioThread());
  AssertGraphOwner();

  if (automatic_pull_handlers_need_updating_) {
    base::AutoTryLock try_locker(automatic_pull_handlers_lock_);
    if (try_locker.is_acquired()) {
      rendering_automatic_pull_handlers_.assign(automatic_pull_handlers_);

      // In rare cases, it is possible for automatic pull nodes' output bus
      // to become stale. Make sure update their rendering output counts.
      // crbug.com/1505080.
      for (auto& handler : rendering_automatic_pull_handlers_) {
        for (unsigned i = 0; i < handler->NumberOfOutputs(); ++i) {
          handler->Output(i).UpdateRenderingState();
        }
      }

      automatic_pull_handlers_need_updating_ = false;
    }
  }
}

void DeferredTaskHandler::ProcessAutomaticPullNodes(
    uint32_t frames_to_process) {
  DCHECK(IsAudioThread());

  base::AutoTryLock try_locker(automatic_pull_handlers_lock_);
  if (try_locker.is_acquired()) {
    for (auto& rendering_automatic_pull_handler :
         rendering_automatic_pull_handlers_) {
      rendering_automatic_pull_handler->ProcessIfNecessary(frames_to_process);
    }
  }
}

void DeferredTaskHandler::AddTailProcessingHandler(
    scoped_refptr<AudioHandler> handler) {
  DCHECK(accepts_tail_processing_);
  AssertGraphOwner();

  if (!tail_processing_handlers_.Contains(handler)) {
#if DEBUG_AUDIONODE_REFERENCES > 1
    handler->AddTailProcessingDebug();
#endif
    tail_processing_handlers_.push_back(handler);
  }
}

void DeferredTaskHandler::RemoveTailProcessingHandler(AudioHandler* handler,
                                                      bool disable_outputs) {
  AssertGraphOwner();

  wtf_size_t index = tail_processing_handlers_.Find(handler);
  if (index != kNotFound) {
#if DEBUG_AUDIONODE_REFERENCES > 1
    handler->RemoveTailProcessingDebug(disable_outputs);
#endif

    if (disable_outputs) {
      // Disabling of outputs should happen on the main thread so save this
      // handler so it can be processed there.
      finished_tail_processing_handlers_.push_back(
          std::move(tail_processing_handlers_[index]));
    }
    tail_processing_handlers_.EraseAt(index);

    return;
  }

  // Check finished tail handlers and remove this handler from the list so that
  // we don't disable outputs later when these are processed.
  index = finished_tail_processing_handlers_.Find(handler);
  if (index != kNotFound) {
#if DEBUG_AUDIONODE_REFERENCES > 1
    handler->RemoveTailProcessingDebug(disable_outputs);
#endif
    finished_tail_processing_handlers_.EraseAt(index);
    return;
  }
}

void DeferredTaskHandler::UpdateTailProcessingHandlers() {
  DCHECK(IsAudioThread());

  for (unsigned k = tail_processing_handlers_.size(); k > 0; --k) {
    scoped_refptr<AudioHandler> handler = tail_processing_handlers_[k - 1];
    if (handler->PropagatesSilence()) {
#if DEBUG_AUDIONODE_REFERENCES
      fprintf(stderr,
              "[%16p]: %16p: %2d: updateTail @%.15g (tail = %.15g + %.15g)\n",
              handler->Context(), handler.get(), handler->GetNodeType(),
              handler->Context()->currentTime(), handler->TailTime(),
              handler->LatencyTime());
#endif
      RemoveTailProcessingHandler(handler.get(), true);
    }
  }
}

void DeferredTaskHandler::AddChangedChannelCountMode(AudioHandler* node) {
  DCHECK(IsMainThread());
  AssertGraphOwner();
  deferred_count_mode_change_.insert(node);
}

void DeferredTaskHandler::RemoveChangedChannelCountMode(AudioHandler* node) {
  AssertGraphOwner();
  deferred_count_mode_change_.erase(node);
}

void DeferredTaskHandler::AddChangedChannelInterpretation(AudioHandler* node) {
  DCHECK(IsMainThread());
  AssertGraphOwner();
  deferred_channel_interpretation_change_.insert(node);
}

void DeferredTaskHandler::RemoveChangedChannelInterpretation(
    AudioHandler* node) {
  AssertGraphOwner();
  deferred_channel_interpretation_change_.erase(node);
}

void DeferredTaskHandler::UpdateChangedChannelCountMode() {
  AssertGraphOwner();
  for (AudioHandler* node : deferred_count_mode_change_) {
    node->UpdateChannelCountMode();
  }
  deferred_count_mode_change_.clear();
}

void DeferredTaskHandler::UpdateChangedChannelInterpretation() {
  AssertGraphOwner();
  for (AudioHandler* node : deferred_channel_interpretation_change_) {
    node->UpdateChannelInterpretation();
  }
  deferred_channel_interpretation_change_.clear();
}

DeferredTaskHandler::DeferredTaskHandler(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(std::move(task_runner)), audio_thread_(0) {}

scoped_refptr<DeferredTaskHandler> DeferredTaskHandler::Create(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return base::AdoptRef(new DeferredTaskHandler(std::move(task_runner)));
}

DeferredTaskHandler::~DeferredTaskHandler() = default;

void DeferredTaskHandler::HandleDeferredTasks() {
  UpdateChangedChannelCountMode();
  UpdateChangedChannelInterpretation();
  HandleDirtyAudioSummingJunctions();
  HandleDirtyAudioNodeOutputs();
  UpdateAutomaticPullNodes();
  UpdateTailProcessingHandlers();
}

void DeferredTaskHandler::ContextWillBeDestroyed() {
  ClearContextFromOrphanHandlers();
  ClearHandlersToBeDeleted();
  // Some handlers might live because of their cross thread tasks.
}

DeferredTaskHandler::GraphAutoLocker::GraphAutoLocker(
    const BaseAudioContext* context)
    : handler_(context->GetDeferredTaskHandler()) {
  handler_.lock();
}

DeferredTaskHandler::OfflineGraphAutoLocker::OfflineGraphAutoLocker(
    OfflineAudioContext* context)
    : handler_(context->GetDeferredTaskHandler()) {
  handler_.OfflineLock();
}

void DeferredTaskHandler::AddRenderingOrphanHandler(
    scoped_refptr<AudioHandler> handler) {
  DCHECK(handler);
  DCHECK(!rendering_orphan_handlers_.Contains(handler));
  rendering_orphan_handlers_.push_back(std::move(handler));
}

void DeferredTaskHandler::RequestToDeleteHandlersOnMainThread() {
  DCHECK(IsAudioThread());
  AssertGraphOwner();

  // Quick exit if there are no handlers that need to be deleted so that we
  // don't unnecessarily post a task.  Be consistent with
  // `DeleteHandlersOnMainThread()` so we don't accidentally return early when
  // there are handlers that could be deleted.
  if (rendering_orphan_handlers_.empty() &&
      finished_tail_processing_handlers_.size() == 0) {
    return;
  }

  deletable_orphan_handlers_.AppendVector(rendering_orphan_handlers_);
  rendering_orphan_handlers_.clear();
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&DeferredTaskHandler::DeleteHandlersOnMainThread,
                          weak_ptr_factory_.GetWeakPtr()));
}

void DeferredTaskHandler::DeleteHandlersOnMainThread() {
  DCHECK(IsMainThread());
  GraphAutoLocker locker(*this);
  deletable_orphan_handlers_.clear();
  DisableOutputsForTailProcessing();
}

void DeferredTaskHandler::ClearHandlersToBeDeleted() {
  DCHECK(IsMainThread());
  // crbug 1370091: Acquire graph lock before clearing
  // rendering_automatic_pull_handlers_ to avoid race conditions on
  // teardown.
  GraphAutoLocker graph_locker(*this);

  {
    base::AutoLock locker(automatic_pull_handlers_lock_);
    rendering_automatic_pull_handlers_.clear();
  }

  tail_processing_handlers_.clear();
  rendering_orphan_handlers_.clear();
  deletable_orphan_handlers_.clear();
  automatic_pull_handlers_.clear();
  finished_source_handlers_.clear();
  active_source_handlers_.clear();
}

void DeferredTaskHandler::ClearContextFromOrphanHandlers() {
  DCHECK(IsMainThread());

  // `rendering_orphan_handlers_` and `deletable_orphan_handlers_` can
  // be modified on the audio thread.
  GraphAutoLocker locker(*this);

  for (auto& handler : rendering_orphan_handlers_) {
    handler->ClearContext();
  }
  for (auto& handler : deletable_orphan_handlers_) {
    handler->ClearContext();
  }
}

void DeferredTaskHandler::SetAudioThreadToCurrentThread() {
  DCHECK(!IsMainThread());
  audio_thread_.store(CurrentThread(), std::memory_order_relaxed);
}

void DeferredTaskHandler::DisableOutputsForTailProcessing() {
  DCHECK(IsMainThread());
  // Tail processing nodes have finished processing their tails so we need to
  // disable their outputs to indicate to downstream nodes that they're done.
  // This has to be done in the main thread because DisableOutputs() can cause
  // summing juctions to go away, which must be done on the main thread.
  for (auto handler : finished_tail_processing_handlers_) {
#if DEBUG_AUDIONODE_REFERENCES > 1
    fprintf(stderr, "[%16p]: %16p: %2d: DisableOutputsForTailProcessing @%g\n",
            handler->Context(), handler.get(), handler->GetNodeType(),
            handler->Context()->currentTime());
#endif
    handler->DisableOutputs();
  }
  finished_tail_processing_handlers_.clear();
}

void DeferredTaskHandler::FinishTailProcessing() {
  DCHECK(IsMainThread());
  // DisableOutputs must run with the graph lock.
  GraphAutoLocker locker(*this);

  // TODO(crbug.com/832200): Simplify this!

  // `DisableOutputs()` can cause new handlers to start tail processing, which
  // in turn can cause hte handler to want to disable outputs.  For the former
  // case, the handler is added to `tail_processing_handlers_`.  In the latter
  // case, the handler is added to `finished_tail_processing_handlers_`.  So, we
  // need to loop around until these vectors are completely empty.
  do {
    while (tail_processing_handlers_.size() > 0) {
      // `DisableOutputs()` can modify `tail_processing_handlers_`, so
      // swap it out before processing it.  And keep running this until
      // nothing gets added to `tail_processing_handlers_`.
      Vector<scoped_refptr<AudioHandler>> handlers_to_be_disabled;

      handlers_to_be_disabled.swap(tail_processing_handlers_);
      for (auto& handler : handlers_to_be_disabled) {
        handler->DisableOutputs();
      }
    }
    DisableOutputsForTailProcessing();
  } while (tail_processing_handlers_.size() > 0 ||
           finished_tail_processing_handlers_.size() > 0);
}

}  // namespace blink
```