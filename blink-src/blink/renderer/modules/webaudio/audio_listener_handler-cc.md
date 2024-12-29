Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its functionality, relate it to web technologies, analyze its logic, identify potential errors, and understand its place in a user's interaction.

**1. Initial Scan and Keyword Recognition:**

*   The filename `audio_listener_handler.cc` immediately suggests it's about handling the audio listener in a Web Audio context.
*   Keywords like `AudioListenerHandler`, `AudioParamHandler`, `PannerHandler`, `HRTFDatabaseLoader`, `position`, `forward`, `up`, `render_quantum_frames`, `sample_rate` jump out. These are strong indicators of Web Audio API related functionality.
*   The namespace `blink` confirms this is part of the Chromium rendering engine.
*   The copyright notice reinforces this is Chromium code.

**2. Deciphering the Core Functionality:**

*   **Constructor and `Create` method:**  The constructor takes multiple `AudioParamHandler` objects and `render_quantum_frames`. The `Create` method acts as a factory, making instantiation easier. This suggests the `AudioListenerHandler` manages parameters related to the listener.
*   **Member Variables:** The presence of `position_x_handler_`, `forward_x_handler_`, `up_x_handler_`, etc., and corresponding `*_values_` arrays indicates that the class manages the listener's position and orientation. The `AudioParamHandler` suggests these parameters can be dynamically controlled.
*   **`GetPosition*Values`, `GetForward*Values`, `GetUp*Values` methods:** These methods return arrays of float values, seemingly representing the listener's position and orientation over a small time interval (`frames_to_process`). The `UpdateValuesIfNeeded` call within these methods points to a mechanism for updating these values.
*   **`UpdateValuesIfNeeded`:** This method is crucial. It checks if the time has advanced and then calculates "sample accurate values" for position and orientation based on the associated `AudioParamHandler` objects. This highlights the importance of time-based animation or changes to the listener's properties.
*   **`AddPannerHandler`, `RemovePannerHandler`, `MarkPannersAsDirty`:** These methods suggest a relationship with `PannerHandler` objects. The `AudioListenerHandler` likely informs `PannerHandler` instances about changes in the listener's state so they can update their spatialization.
*   **`UpdateState`:** This method, called on the audio thread, checks if the listener's position or orientation has changed since the last check. It uses a lock to prevent race conditions with the main thread.
*   **`CreateAndLoadHRTFDatabaseLoader`, `WaitForHRTFDatabaseLoaderThreadCompletion`:**  These methods deal with loading Head-Related Transfer Function (HRTF) data, which is essential for realistic spatial audio. The asynchronous loading is a performance consideration.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

*   **JavaScript (Direct Interaction):** The most direct link is through the Web Audio API in JavaScript. The code implements the underlying logic for the `AudioListener` interface. JavaScript code using `AudioContext.listener` and its properties (`positionX`, `positionY`, `positionZ`, `forwardX`, etc.) directly manipulates the `AudioParamHandler` objects that this C++ class manages.
*   **HTML (Indirect):** HTML elements like `<audio>` or `<video>` can be sources for Web Audio. The spatialization provided by this class affects how audio from these elements is perceived.
*   **CSS (No Direct Relation):** While CSS can influence visual elements that *might* be associated with audio sources (e.g., a 3D scene), there's no direct functional relationship between CSS and this specific C++ code. Audio processing is a separate domain.

**4. Logical Reasoning and Assumptions:**

*   **Assumption:** The `AudioParamHandler` objects are responsible for generating the actual values for position and orientation, potentially based on automation curves or direct JavaScript manipulation.
*   **Input to `UpdateValuesIfNeeded`:** `frames_to_process` (the number of audio frames in the current processing block) and the internal state of the `AudioParamHandler` objects.
*   **Output of `UpdateValuesIfNeeded`:** Populated `position_*_values_`, `forward_*_values_`, and `up_*_values_` arrays with sample-accurate values for the current time interval.
*   **Input to `UpdateState`:** The current values of the listener's position and orientation obtained from the `AudioParamHandler` objects.
*   **Output of `UpdateState`:**  The `is_listener_dirty_` flag being set if a change is detected.

**5. Identifying User/Programming Errors:**

*   **Incorrect Parameter Values:** Setting nonsensical or extreme values for position or orientation in JavaScript can lead to unexpected audio spatialization. For example, setting `positionX` to `Infinity` or very large negative numbers.
*   **Not Updating Listener Position:** Forgetting to update the listener's position in a dynamic scene will result in the audio sources appearing static relative to the listener.
*   **Race Conditions (Less Common for Users):** Although the code uses locking, incorrect locking strategies elsewhere in the Web Audio implementation could lead to race conditions if the listener's parameters are accessed or modified concurrently from multiple threads without proper synchronization.

**6. Tracing User Operations to the Code:**

*   **Scenario:** A user is playing a web game with spatial audio.
*   **Steps:**
    1. **Page Load:** The HTML page containing the game and JavaScript loads.
    2. **Web Audio Initialization:** The JavaScript code initializes an `AudioContext`.
    3. **Audio Source Creation:** An audio source is created (e.g., using `<audio>` or `createBufferSource`).
    4. **Panner Node Creation:** A `PannerNode` is created to spatialize the audio source.
    5. **Connecting Nodes:** The audio source is connected to the panner node, and the panner node is connected to the destination (speakers).
    6. **Listener Access:** The JavaScript code might access `audioContext.listener` to get the `AudioListener` object.
    7. **Setting Listener Properties:** The JavaScript code updates the listener's position and orientation based on the player's movement in the game (e.g., `audioContext.listener.positionX.setValueAtTime(newX, audioContext.currentTime)`).
    8. **C++ Execution:** This JavaScript interaction triggers calls into the Blink rendering engine, eventually reaching the `AudioListenerHandler`. The `setValueAtTime` calls manipulate the `AudioParamHandler` objects. During audio processing, the `AudioListenerHandler::UpdateValuesIfNeeded` and `AudioListenerHandler::UpdateState` methods are called to retrieve and check the listener's state, which is then used by the `PannerHandler` to spatialize the audio.

This detailed process combines code analysis, knowledge of Web Audio concepts, and a bit of educated guessing about the surrounding architecture to provide a comprehensive understanding of the given C++ code.
这个文件 `audio_listener_handler.cc` 是 Chromium Blink 引擎中 Web Audio 模块的一部分，它负责 **管理和处理音频监听器的状态和参数**。  音频监听器代表了音频场景中“听者”的位置和朝向，影响着空间音频的感知。

以下是该文件的主要功能：

**1. 管理监听器的位置和朝向:**

*   它维护了监听器在 3D 空间中的位置 (x, y, z) 和朝向（forward 和 up 向量）。
*   这些位置和朝向信息是通过 `AudioParamHandler` 对象来管理的。`AudioParamHandler` 允许这些参数随时间变化，实现动画效果。
*   它缓存了上一帧的位置和朝向，用于检测监听器是否发生了移动或旋转。

**2. 向 Panner 节点通知监听器的变化:**

*   它维护了一个 `PannerHandler` 对象的集合。`PannerHandler` 负责对音频源进行空间化处理。
*   当监听器的位置或朝向发生变化时，`AudioListenerHandler` 会通知所有关联的 `PannerHandler`，以便它们重新计算音频源的空间位置和声音效果。
*   通过 `MarkPannersAsDirty` 方法通知 Panner 节点，并传递一个 `panning_change_type` 指示变化的类型。

**3. 管理 HRTF 数据库的加载:**

*   它负责创建和管理 `HRTFDatabaseLoader` 对象。 HRTF (Head-Related Transfer Function) 数据库用于模拟声音到达人耳的方式，提供更真实的 3D 音频体验。
*   它支持异步加载 HRTF 数据库，避免阻塞音频处理线程。

**4. 提供监听器参数的访问:**

*   它提供了 `GetPositionXValues`、`GetForwardYValues` 等方法，用于获取监听器在当前渲染量子 (render quantum) 内的位置和朝向值。
*   这些方法会调用 `UpdateValuesIfNeeded` 来确保返回的值是最新的。

**5. 判断参数是否是音频速率的:**

*   通过 `IsAudioRate` 方法判断监听器的位置和朝向参数是否以音频速率变化。这意味着这些参数可以在每个音频帧都发生变化，从而实现更平滑的动画效果。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:** 这是该文件最直接的关联。Web Audio API 是通过 JavaScript 暴露给开发者的，开发者可以使用 JavaScript 代码来控制音频监听器的属性，例如位置和朝向。
    *   **举例说明:** 在 JavaScript 中，可以使用 `AudioContext.listener` 对象来访问和修改监听器的属性：
        ```javascript
        const audioCtx = new AudioContext();
        const listener = audioCtx.listener;

        // 设置监听器的位置
        listener.positionX.setValueAtTime(0, audioCtx.currentTime);
        listener.positionY.setValueAtTime(0, audioCtx.currentTime);
        listener.positionZ.setValueAtTime(0, audioCtx.currentTime);

        // 设置监听器的朝向
        listener.forwardX.setValueAtTime(0, audioCtx.currentTime);
        listener.forwardY.setValueAtTime(0, audioCtx.currentTime);
        listener.forwardZ.setValueAtTime(-1, audioCtx.currentTime); // 朝向前方

        listener.upX.setValueAtTime(0, audioCtx.currentTime);
        listener.upY.setValueAtTime(1, audioCtx.currentTime);
        listener.upZ.setValueAtTime(0, audioCtx.currentTime); // 上方向
        ```
        这些 JavaScript 代码的调用最终会影响到 `AudioListenerHandler` 管理的 `AudioParamHandler` 对象的值。

*   **HTML:**  HTML 主要用于构建网页结构，并可能包含音频或视频元素。虽然 HTML 本身不直接与 `AudioListenerHandler` 交互，但通过 JavaScript 和 Web Audio API，可以对 HTML 中音频元素的空间化效果进行控制。
    *   **举例说明:**  一个 `<audio>` 元素作为音频源，其输出可以连接到一个 `PannerNode`，然后 `PannerNode` 的行为会受到 `AudioContext.listener` 的影响。

*   **CSS:** CSS 主要负责网页的样式和布局，与音频处理的核心逻辑没有直接关系。CSS 无法直接控制音频监听器的行为。

**逻辑推理 (假设输入与输出):**

假设在 JavaScript 中设置了监听器的位置和朝向，并且这些参数是音频速率的：

*   **假设输入:**
    *   `frames_to_process` (当前音频渲染量的大小，例如 128 帧)
    *   `AudioParamHandler` 对象（positionX, positionY, positionZ, forwardX, forwardY, forwardZ, upX, upY, upZ）在当前渲染量内的值会因时间推移而变化。例如，`positionX` 的值可能从 0 线性变化到 0.1。

*   **输出:**
    *   调用 `GetPositionXValues(128)` 将返回一个包含 128 个浮点数的数组，这些浮点数代表监听器在当前渲染量的每一帧的 X 坐标值（从 0 到 0.1 线性变化）。
    *   类似地，`GetForwardYValues(128)` 等方法也会返回对应的数组。
    *   如果监听器的位置或朝向发生了显著变化，`UpdateState` 方法会将 `is_listener_dirty_` 标记设置为 `true`。

**用户或编程常见的使用错误:**

1. **忘记更新监听器的位置:**  如果开发者在动画或交互过程中没有及时更新 `AudioContext.listener` 的位置，音频的 3D 效果将不会随着用户的视角或场景的变化而变化。
    *   **举例:**  在一个第一人称游戏中，如果玩家移动了，但没有更新监听器的位置，所有的声音听起来都像是固定在世界坐标系中，而不是相对于玩家的位置。

2. **设置了不合理的参数值:**  设置过大或过小的位置坐标，或者不正确的 forward/up 向量，可能导致意外的音频效果。
    *   **举例:**  将监听器的 Z 坐标设置为一个非常大的负数，可能会导致所有声音听起来都非常遥远。

3. **在音频处理线程中直接修改监听器参数:**  监听器的参数应该主要在主线程中修改。虽然代码中使用了锁 (`listener_lock_`) 来保护多线程访问，但在不理解其工作原理的情况下，直接在音频处理线程中修改可能会导致竞争条件或其他未定义行为。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问一个使用了 Web Audio API 的网页:** 例如，一个包含 3D 音频效果的在线游戏或音乐播放器。
2. **网页的 JavaScript 代码创建了一个 `AudioContext` 对象:**  这是使用 Web Audio API 的入口。
3. **JavaScript 代码获取或创建了一个 `PannerNode`:** 用于对音频源进行空间化处理。
4. **JavaScript 代码访问 `audioContext.listener`:**  以获取音频监听器对象。
5. **JavaScript 代码通过 `listener.positionX.setValueAtTime(...)` 等方法设置监听器的位置或朝向:** 这些 JavaScript 调用会触发 Blink 引擎中的相应 C++ 代码执行，最终涉及到 `AudioListenerHandler` 对象及其管理的 `AudioParamHandler` 对象。
6. **音频处理线程开始处理音频数据:**  在音频处理过程中，`AudioListenerHandler::UpdateValuesIfNeeded` 会被调用，根据 `AudioParamHandler` 的值计算出当前音频帧监听器的位置和朝向。
7. **`AudioListenerHandler::UpdateState` 可能在音频处理线程或主线程中被调用:** 用于检测监听器的状态是否发生变化。
8. **如果监听器的状态发生变化，`AudioListenerHandler::MarkPannersAsDirty` 会被调用:** 通知关联的 `PannerHandler` 节点重新计算空间化效果。

**调试线索:**

*   如果用户反馈音频的空间定位不准确或没有随着视角变化，可以检查 JavaScript 代码中是否正确更新了 `audioContext.listener` 的位置和朝向。
*   可以使用浏览器的开发者工具中的 Web Audio Inspector 来查看 `AudioListener` 节点的属性值，以及与它连接的 `PannerNode` 的状态。
*   在 Blink 引擎的调试版本中，可以设置断点在 `AudioListenerHandler` 的相关方法中，例如 `UpdateValuesIfNeeded` 和 `MarkPannersAsDirty`，来跟踪监听器状态的变化和通知过程。
*   检查 HRTF 数据库是否成功加载，这也会影响空间音频的质量。

总而言之，`blink/renderer/modules/webaudio/audio_listener_handler.cc` 文件在 Web Audio API 中扮演着核心角色，它负责管理音频监听器的状态，并将这些状态变化通知给负责实际空间化处理的 Panner 节点，从而实现 3D 音频效果。

Prompt: 
```
这是目录为blink/renderer/modules/webaudio/audio_listener_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webaudio/audio_listener_handler.h"

#include "third_party/blink/renderer/modules/webaudio/panner_handler.h"
#include "third_party/blink/renderer/platform/audio/hrtf_database_loader.h"

namespace blink {

scoped_refptr<AudioListenerHandler> AudioListenerHandler::Create(
    AudioParamHandler& position_x_handler,
    AudioParamHandler& position_y_handler,
    AudioParamHandler& position_z_handler,
    AudioParamHandler& forward_x_handler,
    AudioParamHandler& forward_y_handler,
    AudioParamHandler& forward_z_handler,
    AudioParamHandler& up_x_handler,
    AudioParamHandler& up_y_handler,
    AudioParamHandler& up_z_handler,
    unsigned int render_quantum_frames) {
  return base::AdoptRef(new AudioListenerHandler(
      position_x_handler, position_y_handler, position_z_handler,
      forward_x_handler, forward_y_handler, forward_z_handler,
      up_x_handler, up_y_handler, up_z_handler, render_quantum_frames));
}

AudioListenerHandler::AudioListenerHandler(
    AudioParamHandler& position_x_handler,
    AudioParamHandler& position_y_handler,
    AudioParamHandler& position_z_handler,
    AudioParamHandler& forward_x_handler,
    AudioParamHandler& forward_y_handler,
    AudioParamHandler& forward_z_handler,
    AudioParamHandler& up_x_handler,
    AudioParamHandler& up_y_handler,
    AudioParamHandler& up_z_handler,
    unsigned int render_quantum_frames)
    : position_x_handler_(&position_x_handler),
      position_y_handler_(&position_y_handler),
      position_z_handler_(&position_z_handler),
      forward_x_handler_(&forward_x_handler),
      forward_y_handler_(&forward_y_handler),
      forward_z_handler_(&forward_z_handler),
      up_x_handler_(&up_x_handler),
      up_y_handler_(&up_y_handler),
      up_z_handler_(&up_z_handler),
      position_x_values_(render_quantum_frames),
      position_y_values_(render_quantum_frames),
      position_z_values_(render_quantum_frames),
      forward_x_values_(render_quantum_frames),
      forward_y_values_(render_quantum_frames),
      forward_z_values_(render_quantum_frames),
      up_x_values_(render_quantum_frames),
      up_y_values_(render_quantum_frames),
      up_z_values_(render_quantum_frames) {
  // Initialize the cached values with the current values.  Thus, we don't need
  // to notify any panners because we haved moved.
  last_position_ = GetPosition();
  last_forward_ = GetOrientation();
  last_up_ = GetUpVector();
}

AudioListenerHandler::~AudioListenerHandler() {
  position_x_handler_ = nullptr;
  position_y_handler_ = nullptr;
  position_z_handler_ = nullptr;
  forward_x_handler_ = nullptr;
  forward_y_handler_ = nullptr;
  forward_z_handler_ = nullptr;
  up_x_handler_ = nullptr;
  up_y_handler_ = nullptr;
  up_z_handler_ = nullptr;
  hrtf_database_loader_ = nullptr;
  panner_handlers_.clear();
}

const float* AudioListenerHandler::GetPositionXValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return position_x_values_.Data();
}

const float* AudioListenerHandler::GetPositionYValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return position_y_values_.Data();
}

const float* AudioListenerHandler::GetPositionZValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return position_z_values_.Data();
}

const float* AudioListenerHandler::GetForwardXValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return forward_x_values_.Data();
}

const float* AudioListenerHandler::GetForwardYValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return forward_y_values_.Data();
}

const float* AudioListenerHandler::GetForwardZValues(
    uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return forward_z_values_.Data();
}

const float* AudioListenerHandler::GetUpXValues(uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return up_x_values_.Data();
}

const float* AudioListenerHandler::GetUpYValues(uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return up_y_values_.Data();
}

const float* AudioListenerHandler::GetUpZValues(uint32_t frames_to_process) {
  UpdateValuesIfNeeded(frames_to_process);
  return up_z_values_.Data();
}

bool AudioListenerHandler::HasSampleAccurateValues() const {
  return position_x_handler_->HasSampleAccurateValues() ||
         position_y_handler_->HasSampleAccurateValues() ||
         position_z_handler_->HasSampleAccurateValues() ||
         forward_x_handler_->HasSampleAccurateValues() ||
         forward_y_handler_->HasSampleAccurateValues() ||
         forward_z_handler_->HasSampleAccurateValues() ||
         up_x_handler_->HasSampleAccurateValues() ||
         up_y_handler_->HasSampleAccurateValues() ||
         up_z_handler_->HasSampleAccurateValues();
}

bool AudioListenerHandler::IsAudioRate() const {
  return position_x_handler_->IsAudioRate() ||
         position_y_handler_->IsAudioRate() ||
         position_z_handler_->IsAudioRate() ||
         forward_x_handler_->IsAudioRate() ||
         forward_y_handler_->IsAudioRate() ||
         forward_z_handler_->IsAudioRate() ||
         up_x_handler_->IsAudioRate() ||
         up_y_handler_->IsAudioRate() ||
         up_z_handler_->IsAudioRate();
}

void AudioListenerHandler::AddPannerHandler(PannerHandler& panner_handler) {
  DCHECK(IsMainThread());

  panner_handlers_.insert(&panner_handler);
}

void AudioListenerHandler::RemovePannerHandler(PannerHandler& panner_handler) {
  DCHECK(IsMainThread());

  DCHECK(panner_handlers_.Contains(&panner_handler));
  panner_handlers_.erase(&panner_handler);
}

void AudioListenerHandler::MarkPannersAsDirty(unsigned panning_change_type) {
  DCHECK(IsMainThread());

  for (PannerHandler* panner_handler : panner_handlers_) {
    panner_handler->MarkPannerAsDirty(panning_change_type);
  }
}

void AudioListenerHandler::UpdateState() {
  DCHECK(!IsMainThread());

  const base::AutoTryLock try_locker(listener_lock_);
  if (try_locker.is_acquired()) {
    const gfx::Point3F current_position = GetPosition();
    const gfx::Vector3dF current_forward = GetOrientation();
    const gfx::Vector3dF current_up = GetUpVector();

    is_listener_dirty_ = current_position != last_position_ ||
                         current_forward != last_forward_ ||
                         current_up != last_up_;

    if (is_listener_dirty_) {
      last_position_ = current_position;
      last_forward_ = current_forward;
      last_up_ = current_up;
    }
  } else {
    // The main thread must be updating the position, the forward, or the up
    // vector; assume the listener is dirty.  At worst, we'll do a little more
    // work than necessary for one render quantum.
    is_listener_dirty_ = true;
  }
}

void AudioListenerHandler::CreateAndLoadHRTFDatabaseLoader(float sample_rate) {
  DCHECK(IsMainThread());

  if (hrtf_database_loader_) {
    return;
  }

  hrtf_database_loader_ =
      HRTFDatabaseLoader::CreateAndLoadAsynchronouslyIfNecessary(sample_rate);
}

void AudioListenerHandler::WaitForHRTFDatabaseLoaderThreadCompletion() {
  // This can be called from both main and audio threads.

  if (!hrtf_database_loader_) {
    return;
  }

  hrtf_database_loader_->WaitForLoaderThreadCompletion();
}

HRTFDatabaseLoader* AudioListenerHandler::HrtfDatabaseLoader() {
  DCHECK(IsMainThread());

  return hrtf_database_loader_.get();
}

void AudioListenerHandler::UpdateValuesIfNeeded(uint32_t frames_to_process) {
  double current_time = position_x_handler_->DestinationHandler().CurrentTime();

  if (last_update_time_ != current_time) {
    // The time has passed. Update all of the automation values.
    last_update_time_ = current_time;

    DCHECK_LE(frames_to_process, position_x_values_.size());
    DCHECK_LE(frames_to_process, position_y_values_.size());
    DCHECK_LE(frames_to_process, position_z_values_.size());
    DCHECK_LE(frames_to_process, forward_x_values_.size());
    DCHECK_LE(frames_to_process, forward_y_values_.size());
    DCHECK_LE(frames_to_process, forward_z_values_.size());
    DCHECK_LE(frames_to_process, up_x_values_.size());
    DCHECK_LE(frames_to_process, up_y_values_.size());
    DCHECK_LE(frames_to_process, up_z_values_.size());

    position_x_handler_->CalculateSampleAccurateValues(
        position_x_values_.Data(), frames_to_process);
    position_y_handler_->CalculateSampleAccurateValues(
        position_y_values_.Data(), frames_to_process);
    position_z_handler_->CalculateSampleAccurateValues(
        position_z_values_.Data(), frames_to_process);
    forward_x_handler_->CalculateSampleAccurateValues(
        forward_x_values_.Data(), frames_to_process);
    forward_y_handler_->CalculateSampleAccurateValues(
        forward_y_values_.Data(), frames_to_process);
    forward_z_handler_->CalculateSampleAccurateValues(
        forward_z_values_.Data(), frames_to_process);
    up_x_handler_->CalculateSampleAccurateValues(
        up_x_values_.Data(), frames_to_process);
    up_y_handler_->CalculateSampleAccurateValues(
        up_y_values_.Data(), frames_to_process);
    up_z_handler_->CalculateSampleAccurateValues(
        up_z_values_.Data(), frames_to_process);
  }
}

}  // namespace blink

"""

```