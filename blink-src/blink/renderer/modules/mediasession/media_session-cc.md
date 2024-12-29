Response:
Let's break down the thought process for analyzing the `media_session.cc` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this specific Chromium Blink engine source file (`media_session.cc`). We need to identify what it *does*, how it interacts with other web technologies, potential issues, and how one might end up debugging this code.

**2. Initial Scan and Keyword Recognition:**

The first step is a quick skim of the code, looking for familiar keywords and patterns:

* **`// Copyright`**: Standard copyright notice, less informative about functionality.
* **`#include`**:  This is crucial. It tells us what other parts of the codebase this file depends on. We see includes related to:
    * Time (`base/time/...`)
    * Mojo interfaces (`public/mojom/...`) - indicating inter-process communication.
    * V8 bindings (`bindings/modules/v8/...`) -  direct interaction with JavaScript.
    * Core Blink components (`core/frame/...`) - ties to the browser's frame structure.
    * Media-specific components (`modules/mediasession/...`) - self-referential and hinting at the file's domain.
    * Platform utilities (`platform/...`).
* **`namespace blink`**:  Confirms this is part of the Blink rendering engine.
* **`class MediaSession`**:  The core class of this file. This is where most of the functionality will be defined.
* **Methods with names like `setPlaybackState`, `setMetadata`, `setActionHandler`, `setPositionState`**: These clearly suggest the file is responsible for managing the state and actions of a media session.
* **`MediaSession::mediaSession(Navigator& navigator)`**:  A static method suggesting a way to access the `MediaSession` object, possibly as a per-document or per-frame singleton.
* **`V8MediaSessionAction`, `V8MediaSessionPlaybackState`**:  Strong indicators of the connection to JavaScript APIs.
* **`mojom::blink::MediaSessionService`**:  Highlights communication with a separate service, likely in the browser process.

**3. Deeper Dive into Key Sections:**

After the initial scan, we focus on the important parts:

* **`MojomActionToActionEnum` and `ActionEnumToMojomAction`**: These functions clearly translate between internal Mojo representations of media actions and the JavaScript-exposed enum values. This confirms the file acts as a bridge.
* **`MediaSessionPlaybackStateToEnum` and `EnumToMediaSessionPlaybackState`**: Similar to the action enums, this confirms the management of playback state exposed to JavaScript.
* **`MediaSession::MediaSession(Navigator& navigator)`**: The constructor tells us how a `MediaSession` is created and associated with a `Navigator` (which is tied to a frame/document). The initialization of `service_` and `client_receiver_` is important for understanding the communication setup.
* **`setPlaybackState` and `playbackState`**:  Getters and setters for the playback state, showing how JavaScript can influence the internal state and vice-versa. The call to `RecalculatePositionState` highlights the dependency between playback and position.
* **`setMetadata` and `metadata`**: Management of media metadata (title, artist, etc.). The call to `MediaMetadataSanitizer` is a crucial detail for security and data integrity.
* **`setActionHandler`**:  The core of the media session API, allowing web pages to respond to media key presses and other events. The checks for `RuntimeEnabledFeatures` are important for understanding feature gating.
* **`setPositionState`**:  More complex, with validation logic. This confirms the file handles the current playback position, duration, and playback rate.
* **`DidReceiveAction`**:  The entry point for handling actions initiated *outside* the web page (e.g., from media keys). This is where the registered action handlers are invoked.
* **`GetService()`**:  Handles the lazy initialization of the Mojo service connection.

**4. Inferring Functionality and Connections:**

Based on the code and keywords, we can start inferring the overall purpose:

* **Central Media Control:** `MediaSession` acts as a central point for managing media playback and metadata within a web page.
* **JavaScript API Bridge:** It exposes functionality to JavaScript through the `MediaSession` API, using V8 bindings.
* **Platform Integration:** It communicates with the browser process (and potentially the operating system) through Mojo to handle media actions and display notifications.
* **State Management:** It maintains the current playback state (playing, paused), position, and metadata.
* **Action Handling:** It allows web pages to define custom handlers for media actions.

**5. Constructing Examples and Scenarios:**

Now we can create concrete examples to illustrate the interactions:

* **JavaScript Interaction:**  Demonstrate how JavaScript code uses `navigator.mediaSession.setMetadata()` or `navigator.mediaSession.setActionHandler()`.
* **HTML/CSS Relationship:** Explain how the metadata might be displayed in browser UI (not directly managed by this file, but related).
* **Logic Reasoning:** Create a simple scenario showing how `setPlaybackState` and `RecalculatePositionState` interact.
* **User Errors:** Identify common mistakes developers might make when using the API (e.g., invalid duration).
* **Debugging Scenario:** Describe the steps a user might take that would lead to this code being executed.

**6. Addressing Specific Questions:**

Finally, we organize the information to answer the specific questions in the prompt:

* **List functions:** Summarize the key functionalities identified.
* **Relationship with JS/HTML/CSS:**  Provide the concrete examples.
* **Logic Reasoning:**  Present the input/output scenario for `setPlaybackState`.
* **User/Programming Errors:** List potential pitfalls with examples.
* **User Steps to Reach Here:**  Describe a typical media playback scenario.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Maybe this file directly handles media playback."  **Correction:** The presence of Mojo communication suggests it delegates actual playback to the browser process. This file focuses on *control* and *metadata*.
* **Initial thought:** "The examples should be very technical." **Correction:**  Make the JavaScript examples more user-friendly and illustrate common use cases.
* **Missing Link:**  Realized the need to explicitly connect the `MediaSession` object to the `Navigator` and thus to a specific web page/frame.

By following this structured approach, we can thoroughly analyze the source code and provide a comprehensive and informative explanation of its functionality and context.
好的，让我们来分析一下 `blink/renderer/modules/mediasession/media_session.cc` 这个文件。

**文件功能概述**

`media_session.cc` 文件实现了 Blink 渲染引擎中 `MediaSession` 接口的核心逻辑。`MediaSession` API 允许网页应用声明它们正在处理媒体内容，并自定义响应来自浏览器或操作系统的媒体控制事件（例如，播放/暂停按钮，上一曲/下一曲按钮，锁屏界面上的控制等）。

**主要功能点：**

1. **媒体会话管理:**  负责创建和管理当前页面的媒体会话。一个页面可以有一个关联的 `MediaSession` 对象。
2. **媒体元数据设置:** 允许网页设置媒体的元数据信息，如标题、艺术家、专辑封面等，这些信息可以被操作系统或浏览器用于展示。
3. **媒体播放状态控制:**  允许网页设置和获取当前的媒体播放状态（播放中、暂停、停止）。
4. **媒体操作处理:**  允许网页注册针对特定媒体操作（例如，播放、暂停、快进、快退等）的处理函数。当用户通过硬件媒体按键、操作系统媒体控制或浏览器 UI 触发这些操作时，注册的处理函数会被调用。
5. **媒体位置状态同步:** 允许网页设置和同步媒体的当前播放位置、总时长以及播放速率。这有助于操作系统或浏览器显示精确的播放进度。
6. **麦克风和摄像头状态控制:** 允许网页声明麦克风和摄像头是否处于活动状态。
7. **与浏览器进程通信:**  通过 Mojo 接口与浏览器进程中的 `MediaSessionService` 通信，将网页的媒体会话信息同步到浏览器层面，以便浏览器能够处理全局的媒体控制事件。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`MediaSession` 是一个 JavaScript API，因此 `media_session.cc` 的功能直接服务于 JavaScript 代码。

**JavaScript:**

* **设置元数据:**  JavaScript 代码可以使用 `navigator.mediaSession.metadata = new MediaMetadata({...})` 来设置媒体的标题、艺术家、专辑封面等。
   ```javascript
   navigator.mediaSession.metadata = new MediaMetadata({
     title: 'Awesome Song',
     artist: 'Cool Band',
     album: 'Greatest Hits',
     artwork: [
       { src: 'https://example.com/cover.png', sizes: '96x96', type: 'image/png' }
     ]
   });
   ```
   这个操作最终会调用 `media_session.cc` 中的 `MediaSession::setMetadata()` 方法，将元数据信息传递给浏览器进程。

* **设置播放状态:** JavaScript 代码可以使用 `navigator.mediaSession.playbackState = 'playing' | 'paused' | 'none'` 来设置播放状态。
   ```javascript
   navigator.mediaSession.playbackState = 'playing';
   ```
   这个操作会调用 `media_session.cc` 中的 `MediaSession::setPlaybackState()` 方法，更新内部状态并通知浏览器进程。

* **注册操作处理函数:** JavaScript 代码可以使用 `navigator.mediaSession.setActionHandler()` 来注册媒体操作的处理函数。
   ```javascript
   navigator.mediaSession.setActionHandler('play', function() {
     console.log('Play action triggered!');
     // 实际的播放逻辑
   });

   navigator.mediaSession.setActionHandler('pause', function() {
     console.log('Pause action triggered!');
     // 实际的暂停逻辑
   });
   ```
   这些调用会调用 `media_session.cc` 中的 `MediaSession::setActionHandler()` 方法，将 JavaScript 函数与特定的媒体操作关联起来。当浏览器收到相应的媒体控制事件时，`media_session.cc` 会调用这些注册的 JavaScript 函数。

* **设置位置状态:** JavaScript 代码可以使用 `navigator.mediaSession.setPositionState({...})` 来设置媒体的播放位置、时长和速率。
   ```javascript
   navigator.mediaSession.setPositionState({
     duration: 300, // 总时长 300 秒
     position: 150, // 当前播放位置 150 秒
     playbackRate: 1.0 // 播放速率
   });
   ```
   这个操作会调用 `media_session.cc` 中的 `MediaSession::setPositionState()` 方法，同步媒体的位置信息。

**HTML:**

HTML 本身不直接与 `media_session.cc` 交互。但是，HTML 中 `<audio>` 或 `<video>` 元素触发的媒体播放行为是使用 `MediaSession` API 的前提。例如，当用户点击 HTML5 视频的播放按钮时，相关的 JavaScript 代码可能会设置 `navigator.mediaSession` 的状态和处理函数。

**CSS:**

CSS 同样不直接与 `media_session.cc` 交互。但是，CSS 可以用于美化网页中的媒体播放器，而 `MediaSession` API 提供的元数据信息可能会被用于动态更新这些播放器的显示内容。例如，JavaScript 获取到通过 `MediaSession` 设置的标题和封面后，可以使用 CSS 来调整这些元素的样式。

**逻辑推理与假设输入输出**

**假设输入:**

1. JavaScript 调用 `navigator.mediaSession.setPlaybackState('playing')`。
2. JavaScript 调用 `navigator.mediaSession.setPositionState({ duration: 60, position: 10, playbackRate: 1.0 })`。
3. 用户按下键盘上的 "播放/暂停" 媒体按键。

**`media_session.cc` 中的逻辑推理与输出:**

1. 当 `setPlaybackState('playing')` 被调用时，`MediaSession::setPlaybackState()` 方法会被执行，内部的 `playback_state_` 成员变量会被设置为 `mojom::blink::MediaSessionPlaybackState::PLAYING`。同时，会调用 `RecalculatePositionState(false)` 来更新位置状态，并通知浏览器进程。

    *   **输出 (对浏览器进程):**  发送 Mojo 消息 `SetPlaybackState(PLAYING)`。

2. 当 `setPositionState({...})` 被调用时，`MediaSession::setPositionState()` 方法会进行一系列校验（例如，时长不能为负，位置不能超过时长等）。如果校验通过，会将传入的位置信息转换为 Mojo 类型并存储，并调用 `RecalculatePositionState(true)` 更新位置状态，并通知浏览器进程。

    *   **输出 (对浏览器进程):** 发送 Mojo 消息 `SetPositionState({duration: 60, position: 10, playback_rate: 1.0, ...})`。

3. 当用户按下 "播放/暂停" 媒体按键时，操作系统或浏览器会捕获到这个事件，并将其传递给渲染进程。如果当前页面声明了一个 `MediaSession` 并且没有被操作系统级别的其他媒体会话覆盖，浏览器会触发与 "播放/暂停" 操作关联的事件。

    *   `MediaSession::DidReceiveAction(MediaSessionAction::kPlay, ...)` (如果当前状态是暂停) 或 `MediaSession::DidReceiveAction(MediaSessionAction::kPause, ...)` (如果当前状态是播放) 方法会被调用。
    *   该方法会查找是否通过 `setActionHandler` 注册了相应的处理函数。
    *   **假设输入:** 之前 JavaScript 调用了 `navigator.mediaSession.setActionHandler('play', playHandler)` 和 `navigator.mediaSession.setActionHandler('pause', pauseHandler)`。
    *   **输出 (执行 JavaScript):** 如果当前状态是暂停，则调用 JavaScript 的 `playHandler` 函数；如果当前状态是播放，则调用 JavaScript 的 `pauseHandler` 函数。

**用户或编程常见的使用错误及举例说明**

1. **未设置必需的元数据:** 开发者可能忘记设置关键的元数据信息，例如标题或艺术家，导致操作系统或浏览器无法正确显示媒体信息。
    ```javascript
    // 错误示例：缺少标题
    navigator.mediaSession.metadata = new MediaMetadata({
      artist: 'Some Artist'
    });
    ```

2. **设置了无效的播放状态值:**  `playbackState` 只能设置为 `'playing'`, `'paused'`, 或 `'none'`，使用其他值会导致错误。
    ```javascript
    // 错误示例：使用了无效的状态值
    navigator.mediaSession.playbackState = 'stopped'; // 应该用 'none'
    ```

3. **在 `setPositionState` 中提供无效的值:** 例如，提供负数的时长或播放位置，或者播放位置大于时长。`media_session.cc` 中会进行校验并抛出异常。
    ```javascript
    // 错误示例：位置大于时长
    navigator.mediaSession.setPositionState({
      duration: 100,
      position: 150
    }); // 这将抛出一个 TypeError
    ```

4. **忘记注册操作处理函数:**  即使声明了 `MediaSession`，如果没有使用 `setActionHandler` 注册相应的处理函数，当用户触发媒体控制事件时，网页不会做出任何响应。
    ```javascript
    // 错误示例：没有注册 'play' 操作的处理函数
    navigator.mediaSession.setActionHandler('pause', () => { /* ... */ });
    // 当用户点击播放按钮时，没有对应的处理逻辑
    ```

5. **在没有用户激活的情况下尝试设置 MediaSession (可能因浏览器策略而受限):**  某些浏览器可能限制在没有用户交互的情况下设置 `MediaSession` 的某些属性或操作，以防止恶意行为。

**用户操作是如何一步步到达这里 (作为调试线索)**

以下是一些用户操作可能导致 `media_session.cc` 中的代码被执行的场景：

1. **用户访问包含媒体的网页并开始播放:**
    *   用户在浏览器中输入网址或点击链接，导航到包含 `<audio>` 或 `<video>` 元素的网页。
    *   网页加载，JavaScript 代码执行。
    *   JavaScript 代码创建或获取 `navigator.mediaSession` 对象。
    *   当用户点击网页上的播放按钮（或自动播放启动）时，JavaScript 代码可能会调用 `navigator.mediaSession.setPlaybackState('playing')` 和 `navigator.mediaSession.setPositionState({...})`。这些调用会触发 `media_session.cc` 中相应的方法。
    *   JavaScript 代码可能会使用 `navigator.mediaSession.setMetadata({...})` 设置媒体信息。

2. **用户使用硬件媒体按键或操作系统媒体控制:**
    *   用户在播放媒体的网页处于活动状态时，按下键盘上的 "播放/暂停"、"上一曲"、"下一曲" 等媒体按键。
    *   操作系统捕获到这些按键事件。
    *   操作系统或浏览器将这些媒体控制事件传递给渲染进程中负责该网页的 `MediaSession` 对象。
    *   `media_session.cc` 中的 `MediaSession::DidReceiveAction()` 方法被调用，根据接收到的 `action` 类型，执行相应的逻辑，包括调用通过 `setActionHandler` 注册的 JavaScript 函数。

3. **用户与浏览器的媒体控制 UI 交互:**
    *   某些浏览器会在 UI 中显示当前页面的媒体控制信息（例如，在标签页上方，或全局媒体控制中心）。
    *   用户点击这些 UI 上的 "播放/暂停" 等按钮。
    *   浏览器的 UI 操作会触发相应的媒体控制事件，最终也会到达 `media_session.cc` 的 `DidReceiveAction()` 方法。

**调试线索:**

如果需要调试 `media_session.cc` 中的问题，可以关注以下几点：

*   **JavaScript 调用栈:**  查看 JavaScript 代码中哪些地方调用了 `navigator.mediaSession` 的方法。
*   **Mojo 消息:**  使用 Chromium 的 tracing 工具 (如 `chrome://tracing`) 观察渲染进程与浏览器进程之间关于 `MediaSessionService` 的 Mojo 消息传递，查看发送了哪些元数据、状态或操作请求。
*   **断点调试:** 在 `media_session.cc` 中设置断点，例如在 `setPlaybackState`、`setMetadata`、`DidReceiveAction` 等关键方法上，观察代码执行流程和变量值。
*   **日志输出:**  可以在 `media_session.cc` 中添加日志输出 (`DLOG` 或 `DVLOG`)，记录关键事件和状态变化。
*   **浏览器策略和权限:** 检查浏览器的媒体策略设置，确认是否存在阻止或限制 `MediaSession` 功能的策略。

希望以上分析能够帮助你理解 `blink/renderer/modules/mediasession/media_session.cc` 的功能及其与 Web 技术的关系。

Prompt: 
```
这是目录为blink/renderer/modules/mediasession/media_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediasession/media_session.h"

#include <memory>
#include <optional>

#include "base/notreached.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_position_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_session_action_details.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_session_action_handler.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_session_playback_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_session_seek_to_action_details.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/mediasession/media_metadata.h"
#include "third_party/blink/renderer/modules/mediasession/media_metadata_sanitizer.h"
#include "third_party/blink/renderer/modules/mediasession/media_session_type_converters.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

using ::media_session::mojom::blink::MediaSessionAction;

V8MediaSessionAction::Enum MojomActionToActionEnum(MediaSessionAction action) {
  switch (action) {
    case MediaSessionAction::kPlay:
      return V8MediaSessionAction::Enum::kPlay;
    case MediaSessionAction::kPause:
      return V8MediaSessionAction::Enum::kPause;
    case MediaSessionAction::kPreviousTrack:
      return V8MediaSessionAction::Enum::kPrevioustrack;
    case MediaSessionAction::kNextTrack:
      return V8MediaSessionAction::Enum::kNexttrack;
    case MediaSessionAction::kSeekBackward:
      return V8MediaSessionAction::Enum::kSeekbackward;
    case MediaSessionAction::kSeekForward:
      return V8MediaSessionAction::Enum::kSeekforward;
    case MediaSessionAction::kSkipAd:
      return V8MediaSessionAction::Enum::kSkipad;
    case MediaSessionAction::kStop:
      return V8MediaSessionAction::Enum::kStop;
    case MediaSessionAction::kSeekTo:
      return V8MediaSessionAction::Enum::kSeekto;
    case MediaSessionAction::kToggleMicrophone:
      return V8MediaSessionAction::Enum::kTogglemicrophone;
    case MediaSessionAction::kToggleCamera:
      return V8MediaSessionAction::Enum::kTogglecamera;
    case MediaSessionAction::kHangUp:
      return V8MediaSessionAction::Enum::kHangup;
    case MediaSessionAction::kPreviousSlide:
      return V8MediaSessionAction::Enum::kPreviousslide;
    case MediaSessionAction::kNextSlide:
      return V8MediaSessionAction::Enum::kNextslide;
    case MediaSessionAction::kEnterPictureInPicture:
      return V8MediaSessionAction::Enum::kEnterpictureinpicture;
    case MediaSessionAction::kScrubTo:
    case MediaSessionAction::kExitPictureInPicture:
    case MediaSessionAction::kSwitchAudioDevice:
    case MediaSessionAction::kEnterAutoPictureInPicture:
    case MediaSessionAction::kSetMute:
    case MediaSessionAction::kRaise:
      NOTREACHED();
  }
  NOTREACHED();
}

MediaSessionAction ActionEnumToMojomAction(V8MediaSessionAction::Enum action) {
  switch (action) {
    case V8MediaSessionAction::Enum::kPlay:
      return MediaSessionAction::kPlay;
    case V8MediaSessionAction::Enum::kPause:
      return MediaSessionAction::kPause;
    case V8MediaSessionAction::Enum::kPrevioustrack:
      return MediaSessionAction::kPreviousTrack;
    case V8MediaSessionAction::Enum::kNexttrack:
      return MediaSessionAction::kNextTrack;
    case V8MediaSessionAction::Enum::kSeekbackward:
      return MediaSessionAction::kSeekBackward;
    case V8MediaSessionAction::Enum::kSeekforward:
      return MediaSessionAction::kSeekForward;
    case V8MediaSessionAction::Enum::kSkipad:
      return MediaSessionAction::kSkipAd;
    case V8MediaSessionAction::Enum::kStop:
      return MediaSessionAction::kStop;
    case V8MediaSessionAction::Enum::kSeekto:
      return MediaSessionAction::kSeekTo;
    case V8MediaSessionAction::Enum::kTogglemicrophone:
      return MediaSessionAction::kToggleMicrophone;
    case V8MediaSessionAction::Enum::kTogglecamera:
      return MediaSessionAction::kToggleCamera;
    case V8MediaSessionAction::Enum::kHangup:
      return MediaSessionAction::kHangUp;
    case V8MediaSessionAction::Enum::kPreviousslide:
      return MediaSessionAction::kPreviousSlide;
    case V8MediaSessionAction::Enum::kNextslide:
      return MediaSessionAction::kNextSlide;
    case V8MediaSessionAction::Enum::kEnterpictureinpicture:
      return MediaSessionAction::kEnterPictureInPicture;
  }
  NOTREACHED();
}

V8MediaSessionPlaybackState::Enum MediaSessionPlaybackStateToEnum(
    mojom::blink::MediaSessionPlaybackState state) {
  switch (state) {
    case mojom::blink::MediaSessionPlaybackState::NONE:
      return V8MediaSessionPlaybackState::Enum::kNone;
    case mojom::blink::MediaSessionPlaybackState::PAUSED:
      return V8MediaSessionPlaybackState::Enum::kPaused;
    case mojom::blink::MediaSessionPlaybackState::PLAYING:
      return V8MediaSessionPlaybackState::Enum::kPlaying;
  }
  NOTREACHED();
}

mojom::blink::MediaSessionPlaybackState EnumToMediaSessionPlaybackState(
    const V8MediaSessionPlaybackState::Enum& state) {
  switch (state) {
    case V8MediaSessionPlaybackState::Enum::kNone:
      return mojom::blink::MediaSessionPlaybackState::NONE;
    case V8MediaSessionPlaybackState::Enum::kPaused:
      return mojom::blink::MediaSessionPlaybackState::PAUSED;
    case V8MediaSessionPlaybackState::Enum::kPlaying:
      return mojom::blink::MediaSessionPlaybackState::PLAYING;
  }
  NOTREACHED();
}

}  // anonymous namespace

const char MediaSession::kSupplementName[] = "MediaSession";

MediaSession* MediaSession::mediaSession(Navigator& navigator) {
  MediaSession* supplement =
      Supplement<Navigator>::From<MediaSession>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<MediaSession>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

MediaSession::MediaSession(Navigator& navigator)
    : Supplement<Navigator>(navigator),
      clock_(base::DefaultTickClock::GetInstance()),
      playback_state_(mojom::blink::MediaSessionPlaybackState::NONE),
      service_(navigator.GetExecutionContext()),
      client_receiver_(this, navigator.DomWindow()) {}

void MediaSession::setPlaybackState(
    const V8MediaSessionPlaybackState& playback_state) {
  playback_state_ = EnumToMediaSessionPlaybackState(playback_state.AsEnum());

  RecalculatePositionState(/*was_set=*/false);

  mojom::blink::MediaSessionService* service = GetService();
  if (service)
    service->SetPlaybackState(playback_state_);
}

V8MediaSessionPlaybackState MediaSession::playbackState() {
  return V8MediaSessionPlaybackState(
      MediaSessionPlaybackStateToEnum(playback_state_));
}

void MediaSession::setMetadata(MediaMetadata* metadata) {
  if (metadata)
    metadata->SetSession(this);

  if (metadata_)
    metadata_->SetSession(nullptr);

  metadata_ = metadata;
  OnMetadataChanged();
}

MediaMetadata* MediaSession::metadata() const {
  return metadata_.Get();
}

void MediaSession::OnMetadataChanged() {
  mojom::blink::MediaSessionService* service = GetService();
  if (!service)
    return;

  // OnMetadataChanged() is called from a timer. The Window/ExecutionContext
  // might detaches in the meantime. See https://crbug.com/1269522
  ExecutionContext* context = GetSupplementable()->DomWindow();
  if (!context)
    return;

  service->SetMetadata(
      MediaMetadataSanitizer::SanitizeAndConvertToMojo(metadata_, context));
}

void MediaSession::setActionHandler(const V8MediaSessionAction& action,
                                    V8MediaSessionActionHandler* handler,
                                    ExceptionState& exception_state) {
  auto action_value = action.AsEnum();
  if (action_value == V8MediaSessionAction::Enum::kSkipad) {
    LocalDOMWindow* window = GetSupplementable()->DomWindow();
    if (!RuntimeEnabledFeatures::SkipAdEnabled(window)) {
      exception_state.ThrowTypeError(
          "The provided value 'skipad' is not a valid enum "
          "value of type MediaSessionAction.");
      return;
    }

    UseCounter::Count(window, WebFeature::kMediaSessionSkipAd);
  }

  if (!RuntimeEnabledFeatures::MediaSessionEnterPictureInPictureEnabled()) {
    if (action_value == V8MediaSessionAction::Enum::kEnterpictureinpicture) {
      exception_state.ThrowTypeError(
          "The provided value 'enterpictureinpicture'"
          " is not a valid enum "
          "value of type MediaSessionAction.");
      return;
    }
  }

  if (handler) {
    auto add_result = action_handlers_.Set(action_value, handler);

    if (!add_result.is_new_entry)
      return;

    NotifyActionChange(action_value, ActionChangeType::kActionEnabled);
  } else {
    if (action_handlers_.find(action_value) == action_handlers_.end()) {
      return;
    }

    action_handlers_.erase(action_value);

    NotifyActionChange(action_value, ActionChangeType::kActionDisabled);
  }
}

void MediaSession::setPositionState(MediaPositionState* position_state,
                                    ExceptionState& exception_state) {
  // If the dictionary is empty / null then we should reset the position state.
  if (!position_state->hasDuration() && !position_state->hasPlaybackRate() &&
      !position_state->hasPosition()) {
    position_state_ = nullptr;
    declared_playback_rate_ = 0.0;

    if (auto* service = GetService())
      service->SetPositionState(nullptr);

    return;
  }

  // The duration cannot be missing.
  if (!position_state->hasDuration()) {
    exception_state.ThrowTypeError("The duration must be provided.");
    return;
  }

  // The duration cannot be NaN.
  if (std::isnan(position_state->duration())) {
    exception_state.ThrowTypeError("The provided duration cannot be NaN.");
    return;
  }

  // The duration cannot be negative.
  if (position_state->duration() < 0) {
    exception_state.ThrowTypeError(
        "The provided duration cannot be less than zero.");
    return;
  }

  // The position cannot be negative.
  if (position_state->hasPosition() && position_state->position() < 0) {
    exception_state.ThrowTypeError(
        "The provided position cannot be less than zero.");
    return;
  }

  // The position cannot be greater than the duration.
  if (position_state->hasPosition() &&
      position_state->position() > position_state->duration()) {
    exception_state.ThrowTypeError(
        "The provided position cannot be greater than the duration.");
    return;
  }

  // The playback rate cannot be equal to zero.
  if (position_state->hasPlaybackRate() &&
      position_state->playbackRate() == 0) {
    exception_state.ThrowTypeError(
        "The provided playbackRate cannot be equal to zero.");
    return;
  }

  position_state_ =
      mojo::ConvertTo<media_session::mojom::blink::MediaPositionPtr>(
          position_state);

  declared_playback_rate_ = position_state_->playback_rate;

  RecalculatePositionState(/*was_set=*/true);
}

void MediaSession::setMicrophoneActive(bool active) {
  auto* service = GetService();
  if (!service)
    return;

  if (active) {
    service->SetMicrophoneState(
        media_session::mojom::MicrophoneState::kUnmuted);
  } else {
    service->SetMicrophoneState(media_session::mojom::MicrophoneState::kMuted);
  }
}

void MediaSession::setCameraActive(bool active) {
  auto* service = GetService();
  if (!service)
    return;

  if (active) {
    service->SetCameraState(media_session::mojom::CameraState::kTurnedOn);
  } else {
    service->SetCameraState(media_session::mojom::CameraState::kTurnedOff);
  }
}

void MediaSession::NotifyActionChange(V8MediaSessionAction::Enum action,
                                      ActionChangeType type) {
  mojom::blink::MediaSessionService* service = GetService();
  if (!service)
    return;

  auto mojom_action = ActionEnumToMojomAction(action);
  switch (type) {
    case ActionChangeType::kActionEnabled:
      service->EnableAction(mojom_action);
      break;
    case ActionChangeType::kActionDisabled:
      service->DisableAction(mojom_action);
      break;
  }
}

base::TimeDelta MediaSession::GetPositionNow() const {
  const base::TimeTicks now = clock_->NowTicks();

  const base::TimeDelta elapsed_time =
      position_state_->playback_rate *
      (now - position_state_->last_updated_time);
  const base::TimeDelta updated_position =
      position_state_->position + elapsed_time;
  const base::TimeDelta start = base::Seconds(0);

  if (updated_position <= start)
    return start;
  else if (updated_position >= position_state_->duration)
    return position_state_->duration;
  else
    return updated_position;
}

void MediaSession::RecalculatePositionState(bool was_set) {
  if (!position_state_)
    return;

  double new_playback_rate =
      playback_state_ == mojom::blink::MediaSessionPlaybackState::PAUSED
          ? 0.0
          : declared_playback_rate_;

  if (!was_set && new_playback_rate == position_state_->playback_rate)
    return;

  // If we updated the position state because of the playback rate then we
  // should update the time.
  if (!was_set) {
    position_state_->position = GetPositionNow();
  }

  position_state_->playback_rate = new_playback_rate;
  position_state_->last_updated_time = clock_->NowTicks();

  if (auto* service = GetService())
    service->SetPositionState(position_state_.Clone());
}

mojom::blink::MediaSessionService* MediaSession::GetService() {
  if (service_) {
    return service_.get();
  }
  LocalDOMWindow* window = GetSupplementable()->DomWindow();
  if (!window) {
    return nullptr;
  }

  // See https://bit.ly/2S0zRAS for task types.
  auto task_runner = window->GetTaskRunner(TaskType::kMiscPlatformAPI);
  window->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(task_runner));
  if (service_.get())
    service_->SetClient(client_receiver_.BindNewPipeAndPassRemote(task_runner));
  return service_.get();
}

void MediaSession::DidReceiveAction(
    media_session::mojom::blink::MediaSessionAction action,
    mojom::blink::MediaSessionActionDetailsPtr details) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();
  if (!window)
    return;
  LocalFrame::NotifyUserActivation(
      window->GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);

  auto v8_action = MojomActionToActionEnum(action);

  auto iter = action_handlers_.find(v8_action);
  if (iter == action_handlers_.end())
    return;

  const auto* blink_details =
      mojo::TypeConverter<const blink::MediaSessionActionDetails*,
                          blink::mojom::blink::MediaSessionActionDetailsPtr>::
          ConvertWithV8Action(details, v8_action);

  iter->value->InvokeAndReportException(this, blink_details);
}

void MediaSession::Trace(Visitor* visitor) const {
  visitor->Trace(client_receiver_);
  visitor->Trace(metadata_);
  visitor->Trace(action_handlers_);
  visitor->Trace(service_);
  ScriptWrappable::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);
}

}  // namespace blink

"""

```