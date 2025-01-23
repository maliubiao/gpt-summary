Response:
The user wants to understand the functionality of the `fullscreen_controller.cc` file in the Chromium Blink rendering engine. I need to:

1. **Identify the core purpose** of this file. Based on the name, it likely manages the fullscreen functionality for web pages within the Blink engine.
2. **List specific functionalities** implemented in the file, analyzing the provided code.
3. **Explain the relationship** between this file and web technologies like JavaScript, HTML, and CSS, providing illustrative examples.
4. **Infer logical reasoning** within the code and present it with hypothetical inputs and outputs.
5. **Identify potential user or programming errors** related to fullscreen functionality that this file might handle or where issues might arise.
`blink/renderer/core/frame/fullscreen_controller.cc` 文件在 Chromium Blink 引擎中负责管理网页的 **全屏显示** 功能。它的主要功能包括处理和协调网页内容进入和退出全屏模式的请求和状态变化。

以下是它的具体功能列表以及与 JavaScript, HTML, CSS 的关系、逻辑推理和常见错误示例：

**功能列表:**

1. **接收和处理全屏请求:** 接收来自网页内容 (通过 JavaScript API) 或浏览器自身的进入全屏模式的请求。
2. **管理全屏状态:** 跟踪当前浏览上下文 (frame) 的全屏状态 (例如：是否正在进入、退出或已进入全屏)。
3. **与浏览器进程通信:**  通过 `LocalFrameHostRemote` 接口与浏览器进程进行通信，请求进入或退出全屏模式，并将全屏状态的变化通知浏览器。
4. **处理跨域 iframe 的全屏请求:**  处理来自跨域 iframe 的全屏请求，确保父 frame 也能进入全屏。
5. **更新页面缩放约束:**  在进入和退出全屏时调整页面的缩放约束，以确保内容正确显示。
6. **管理全屏元素:**  跟踪当前处于全屏状态的 DOM 元素。
7. **通知 frame 全屏状态变化:**  通知相关的 frame (包括子 frame) 全屏状态的改变，以便它们可以做出相应的调整。
8. **处理屏幕变化:** 支持在多显示器环境下将全屏内容切换到不同的屏幕。
9. **处理 XR (增强现实/虚拟现实) 全屏:** 支持用于 XR 叠加层的全屏模式。
10. **处理带状态栏/导航栏的全屏:**  处理用户希望显示状态栏或导航栏的全屏请求。
11. **处理视频元素的全屏:**  对 `HTMLVideoElement` 进入和退出全屏进行特殊处理，例如在视频全屏时可以覆盖背景颜色。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  该控制器响应 JavaScript 代码发起的全屏请求。例如，当 JavaScript 调用 `element.requestFullscreen()` 时，Blink 引擎会调用 `FullscreenController::EnterFullscreen()` 来处理这个请求。
    * **例子:**
        ```javascript
        const element = document.getElementById('myVideo');
        element.requestFullscreen(); // JavaScript 发起全屏请求
        ```
        当上述代码执行时，`FullscreenController` 会接收到请求并与浏览器进程通信。
* **HTML:**  HTML 元素是进入全屏的目标。通过 JavaScript 可以让特定的 HTML 元素进入全屏。
    * **例子:**  `<video id="myVideo" src="video.mp4"></video>`  这个视频元素可以通过 JavaScript 进入全屏。
* **CSS:**  CSS 可以影响全屏元素的样式，尽管全屏状态本身是由浏览器控制的。例如，可以使用 CSS 选择器 `:fullscreen` 来定义全屏元素的特定样式。
    * **例子:**
        ```css
        :fullscreen {
          background-color: black;
        }
        #myVideo:fullscreen {
          object-fit: contain; /* 确保视频在全屏时完整显示 */
        }
        ```
        当元素进入全屏时，浏览器会自动应用 `:fullscreen` 伪类定义的样式。

**逻辑推理 (假设输入与输出):**

**假设输入 1:** 用户在网页上点击了一个按钮，该按钮触发 JavaScript 代码调用 `document.getElementById('myDiv').requestFullscreen();`

**处理流程:**

1. JavaScript 调用 `requestFullscreen()`。
2. Blink 引擎的 `Fullscreen` 类接收到请求。
3. `Fullscreen` 类调用 `FullscreenController::EnterFullscreen()`，并将 `myDiv` 所在的 `LocalFrame` 和相关选项传递给它。
4. `FullscreenController` 检查当前全屏状态。
5. `FullscreenController` 通过 `LocalFrameHostRemote` 向浏览器进程发送进入全屏的请求，包含全屏选项 (例如，是否显示导航栏等)。
6. 浏览器进程响应该请求，可能会进行一些安全检查和用户提示。
7. 如果浏览器允许进入全屏，它会通知渲染进程。
8. `FullscreenController::DidEnterFullscreen()` 被调用，更新渲染进程的全屏状态，并通知相关的 frame。
9. `myDiv` 元素进入全屏显示。

**假设输出 1:**  `myDiv` 元素占据整个屏幕（或浏览器窗口），用户界面可能发生变化以适应全屏模式。

**假设输入 2:** 用户按下 Esc 键或者浏览器提供了退出全屏的按钮。

**处理流程:**

1. 浏览器进程检测到用户想要退出全屏。
2. 浏览器进程通知渲染进程退出全屏。
3. `FullscreenController::DidExitFullscreen()` 被调用。
4. `FullscreenController` 更新渲染进程的全屏状态。
5. `FullscreenController` 遍历主 frame 及其子 frame，调用 `Fullscreen::DidExitFullscreen()` 通知它们退出全屏。
6. 全屏元素恢复到原来的显示状态。

**假设输出 2:** 网页内容不再以全屏模式显示，恢复到之前的窗口大小和布局。

**用户或编程常见的使用错误：**

1. **权限问题:**  在某些情况下，浏览器可能因为安全原因拒绝进入全屏，例如，如果请求不是由用户手势触发的。
    * **错误示例:** 在页面的 `onload` 事件中立即调用 `requestFullscreen()`，很可能会被浏览器阻止。
    * **正确做法:** 只有在用户交互 (例如点击按钮) 后才能调用 `requestFullscreen()`。
2. **错误的元素选择:**  尝试让文档本身 (`document.documentElement`) 进入全屏，但没有正确处理跨浏览器兼容性。
    * **错误示例:**  只使用 `document.documentElement.requestFullscreen()` 而不考虑其他浏览器可能需要的特定方法。
    * **正确做法:** 使用统一的封装函数来处理不同浏览器的全屏 API 前缀。
3. **忘记处理全屏变化事件:**  没有监听 `fullscreenchange` 事件来执行全屏状态变化后的操作，例如调整布局或更新 UI。
    * **错误示例:**  调用 `requestFullscreen()` 后，假设全屏一定会成功，而没有监听 `fullscreenchange` 事件来处理失败的情况。
    * **正确做法:** 添加 `fullscreenchange` 事件监听器来处理全屏状态的改变，包括成功进入和退出全屏的情况。
4. **在 iframe 中发起全屏请求的上下文错误:**  在 iframe 中调用 `requestFullscreen()` 时，如果没有正确处理跨域权限，可能会导致全屏失败。
    * **错误示例:**  在跨域 iframe 中直接调用 `element.requestFullscreen()`，父 frame 没有允许 iframe 进入全屏。
    * **正确做法:** 父 frame 需要通过 `allowfullscreen` 属性允许 iframe 进入全屏。
5. **假设全屏总是会成功:**  没有处理 `requestFullscreen()` 返回的 Promise 的 rejection 情况，或者没有捕获 `fullscreenchange` 事件中可能出现的错误。
    * **错误示例:**  只调用 `element.requestFullscreen()`，没有 `.then()` 或 `.catch()` 来处理结果。
    * **正确做法:** 使用 Promise 的 `.then()` 和 `.catch()` 方法来处理全屏请求的结果。

总而言之，`fullscreen_controller.cc` 是 Blink 引擎中实现和管理网页全屏功能的核心组件，它负责接收请求、协调状态变化并与浏览器进程进行通信，从而实现用户在网页上进入和退出全屏模式的功能。理解这个文件的工作原理有助于开发者更好地理解和使用 JavaScript 全屏 API。

### 提示词
```
这是目录为blink/renderer/core/frame/fullscreen_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/fullscreen_controller.h"

#include "base/memory/ptr_util.h"
#include "third_party/blink/public/mojom/frame/fullscreen.mojom-blink.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fullscreen_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen_request_type.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"

namespace blink {

namespace {

mojom::blink::FullscreenOptionsPtr ToMojoOptions(
    LocalFrame* frame,
    const FullscreenOptions* options,
    FullscreenRequestType request_type) {
  auto fullscreen_options = mojom::blink::FullscreenOptions::New();
  fullscreen_options->prefers_navigation_bar =
      options->navigationUI() == "show";
  if (options->hasScreen() &&
      options->screen()->DisplayId() != Screen::kInvalidDisplayId) {
    fullscreen_options->display_id = options->screen()->DisplayId();
  }

  // Propagate the type of fullscreen request (prefixed or unprefixed) to
  // OOPIF ancestor frames so that they fire matching prefixed or unprefixed
  // fullscreen events.
  fullscreen_options->is_prefixed =
      request_type & FullscreenRequestType::kPrefixed;
  fullscreen_options->is_xr_overlay =
      request_type & FullscreenRequestType::kForXrOverlay;
  fullscreen_options->prefers_status_bar =
      request_type & FullscreenRequestType::kForXrArWithCamera;

  return fullscreen_options;
}

}  // namespace

FullscreenController::FullscreenController(WebViewImpl* web_view_base)
    : web_view_base_(web_view_base),
      pending_frames_(MakeGarbageCollected<PendingFullscreenSet>()) {}

void FullscreenController::DidEnterFullscreen() {
  // |Browser::EnterFullscreenModeForTab()| can enter fullscreen without going
  // through |Fullscreen::RequestFullscreen()|, in which case there will be no
  // fullscreen element. Do nothing.
  if (state_ != State::kEnteringFullscreen &&
      state_ != State::kChangingFullscreenDisplays) {
    return;
  }

  UpdatePageScaleConstraints(false);

  // Only reset the scale for the local main frame.
  if (web_view_base_->MainFrameImpl()) {
    web_view_base_->SetPageScaleFactor(1.0f);
    web_view_base_->SetVisualViewportOffset(gfx::PointF());
  }

  state_ = State::kFullscreen;

  NotifyFramesOfFullscreenEntry(true /* success */);

  // TODO(foolip): If the top level browsing context (main frame) ends up with
  // no fullscreen element, exit fullscreen again to recover.
}

void FullscreenController::DidExitFullscreen() {
  // The browser process can exit fullscreen at any time, e.g. if the user
  // presses Esc. After |Browser::EnterFullscreenModeForTab()|,
  // |Browser::ExitFullscreenModeForTab()| will make it seem like we exit when
  // not even in fullscreen. Do nothing.
  if (state_ == State::kInitial)
    return;

  UpdatePageScaleConstraints(true);

  state_ = State::kInitial;

  // Notify the topmost local frames that we have exited fullscreen.
  // |Fullscreen::DidExitFullscreen()| will take care of descendant frames.
  for (Frame* frame = web_view_base_->GetPage()->MainFrame(); frame;) {
    Frame* next_frame = frame->Tree().TraverseNext();

    if (frame->IsRemoteFrame()) {
      frame = next_frame;
      continue;
    }

    auto* local_frame = To<LocalFrame>(frame);
    DCHECK(local_frame->IsLocalRoot());
    if (Document* document = local_frame->GetDocument())
      Fullscreen::DidExitFullscreen(*document);

    // Skip over all descendant frames.
    while (next_frame && next_frame->Tree().IsDescendantOf(frame))
      next_frame = next_frame->Tree().TraverseNext();
    frame = next_frame;
  }
}

void FullscreenController::EnterFullscreen(LocalFrame& frame,
                                           const FullscreenOptions* options,
                                           FullscreenRequestType request_type) {
  const auto& screen_info = frame.GetChromeClient().GetScreenInfo(frame);

  const bool requesting_other_screen =
      options->hasScreen() &&
      options->screen()->DisplayId() != Screen::kInvalidDisplayId &&
      options->screen()->DisplayId() != screen_info.display_id;
  bool requesting_fullscreen_screen_change =
      state_ == State::kFullscreen && requesting_other_screen;

  // TODO(dtapuska): If we are already in fullscreen. If the options are
  // different than the currently requested one we may wish to request
  // fullscreen mode again.
  // If already fullscreen or exiting fullscreen, synchronously call
  // |DidEnterFullscreen()|. When exiting, the coming |DidExitFullscreen()| call
  // will again notify all frames.
  if ((state_ == State::kFullscreen && !requesting_fullscreen_screen_change) ||
      state_ == State::kExitingFullscreen) {
    State old_state = state_;
    state_ = State::kEnteringFullscreen;
    DidEnterFullscreen();
    state_ = old_state;
    return;
  }

  pending_frames_->insert(&frame);

  // If already entering fullscreen, just wait until the first request settles.
  // TODO(enne): currently, if you request fullscreen with different display ids
  // (or one with and one without display ids), then only the first request will
  // be considered, and all others will be ignored and be settled when the first
  // is resolved.  One way to fix this might be to queue up requests in
  // blink::Fullscreen such that we never have simultaneous requests with
  // conflicting options.
  if (state_ == State::kEnteringFullscreen ||
      state_ == State::kChangingFullscreenDisplays) {
    return;
  }

  DCHECK(state_ == State::kInitial || requesting_fullscreen_screen_change);
  auto fullscreen_options = ToMojoOptions(&frame, options, request_type);

  // We want to disallow entering fullscreen with status and navigation bars
  // both visible, as this would translate into "no fullscreen at all".
  DCHECK(!(fullscreen_options->prefers_status_bar &&
           fullscreen_options->prefers_navigation_bar));

#if DCHECK_IS_ON()
  DVLOG(2) << __func__ << ": request_type="
           << FullscreenRequestTypeToDebugString(request_type)
           << " fullscreen_options={display_id="
           << fullscreen_options->display_id << ", prefers_navigation_bar="
           << fullscreen_options->prefers_navigation_bar
           << ", prefers_status_bar=" << fullscreen_options->prefers_status_bar
           << ", is_prefixed=" << fullscreen_options->is_prefixed
           << ", is_xr_overlay=" << fullscreen_options->is_xr_overlay << "}";
#endif

  // Don't send redundant EnterFullscreen message to the browser for the
  // ancestor frames if the subframe has already entered fullscreen.
  if (!(request_type & FullscreenRequestType::kForCrossProcessDescendant)) {
    frame.GetLocalFrameHostRemote().EnterFullscreen(
        std::move(fullscreen_options),
        WTF::BindOnce(&FullscreenController::EnterFullscreenCallback,
                      WTF::Unretained(this)));
  }

  if (state_ == State::kInitial)
    state_ = State::kEnteringFullscreen;
  else  // if state_ == State::kFullscreen
    state_ = State::kChangingFullscreenDisplays;
}

void FullscreenController::ExitFullscreen(LocalFrame& frame) {
  // If not in fullscreen, ignore any attempt to exit. In particular, when
  // entering fullscreen, allow the transition into fullscreen to complete. Note
  // that the browser process is ultimately in control and can still exit
  // fullscreen at any time.
  if (state_ != State::kFullscreen)
    return;

  frame.GetLocalFrameHostRemote().ExitFullscreen();

  state_ = State::kExitingFullscreen;
}

void FullscreenController::FullscreenElementChanged(
    Element* old_element,
    Element* new_element,
    const FullscreenOptions* options,
    FullscreenRequestType request_type) {
  DCHECK_NE(old_element, new_element);

  // We only override the WebView's background color for overlay fullscreen
  // video elements, so have to restore the override when the element changes.
  auto* old_video_element = DynamicTo<HTMLVideoElement>(old_element);
  if (old_video_element)
    RestoreBackgroundColorOverride();

  if (new_element) {
    DCHECK(Fullscreen::IsFullscreenElement(*new_element));

    if (auto* video_element = DynamicTo<HTMLVideoElement>(*new_element)) {
      video_element->DidEnterFullscreen();
    }
  }

  if (old_element) {
    DCHECK(!Fullscreen::IsFullscreenElement(*old_element));

    if (old_video_element)
      old_video_element->DidExitFullscreen();
  }

  // Tell the browser the fullscreen state has changed.
  if (Element* owner = new_element ? new_element : old_element) {
    Document& doc = owner->GetDocument();
    bool in_fullscreen = !!new_element;
    if (LocalFrame* frame = doc.GetFrame()) {
      mojom::blink::FullscreenOptionsPtr mojo_options;
      if (in_fullscreen)
        mojo_options = ToMojoOptions(frame, options, request_type);

      frame->GetLocalFrameHostRemote().FullscreenStateChanged(
          in_fullscreen, std::move(mojo_options));
    }
  }
}

void FullscreenController::RestoreBackgroundColorOverride() {
  web_view_base_->SetBackgroundColorOverrideForFullscreenController(
      std::nullopt);
}

void FullscreenController::NotifyFramesOfFullscreenEntry(bool granted) {
  // Notify all pending local frames in order whether or not we successfully
  // entered fullscreen.
  for (LocalFrame* frame : *pending_frames_) {
    if (frame) {
      if (Document* document = frame->GetDocument()) {
        Fullscreen::DidResolveEnterFullscreenRequest(*document, granted);
      }
    }
  }

  // Notify all local frames whether or not we successfully entered fullscreen.
  for (Frame* frame = web_view_base_->GetPage()->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    if (Document* document = local_frame->GetDocument()) {
      Fullscreen::DidResolveEnterFullscreenRequest(*document, granted);
    }
  }
  pending_frames_->clear();
}

void FullscreenController::EnterFullscreenCallback(bool granted) {
  if (granted) {
    // If the fullscreen is granted, then the VisualPropertiesUpdated message
    // will later be fired and the state will be updated then.
    //
    // TODO(enne): the visual property updates *must* call DidEnterFullscreen
    // in order for the requestFullscreen promise to be resolved.
    // There are early outs in FullscreenController::EnterFullscreenModeForTab
    // that may prevent this from happening, especially with stale display id
    // differences, where a renderer might think the display id is changing
    // but the browser thinks it is the same and early outs.  This communication
    // needs to be more explicit in those cases to avoid hanging promises.
  } else {
    state_ = State::kInitial;
    NotifyFramesOfFullscreenEntry(false /* granted */);
  }
}

void FullscreenController::UpdateSize() {
  DCHECK(web_view_base_->GetPage());

  if (state_ != State::kFullscreen && state_ != State::kExitingFullscreen)
    return;

  UpdatePageScaleConstraints(false);
}

void FullscreenController::UpdatePageScaleConstraints(bool reset_constraints) {
  PageScaleConstraints fullscreen_constraints;
  if (reset_constraints) {
    web_view_base_->GetPageScaleConstraintsSet().SetNeedsReset(true);
  } else {
    fullscreen_constraints = PageScaleConstraints(1.0, 1.0, 1.0);
    fullscreen_constraints.layout_size = gfx::SizeF(web_view_base_->Size());
  }
  web_view_base_->GetPageScaleConstraintsSet().SetFullscreenConstraints(
      fullscreen_constraints);
  web_view_base_->GetPageScaleConstraintsSet().ComputeFinalConstraints();

  // Although we called |ComputeFinalConstraints()| above, the "final"
  // constraints are not actually final. They are still subject to scale factor
  // clamping by contents size. Normally they should be dirtied due to contents
  // size mutation after layout, however the contents size is not guaranteed to
  // mutate, and the scale factor may remain unclamped. Just fire the event
  // again to ensure the final constraints pick up the latest contents size.
  web_view_base_->DidChangeContentsSize();
  if (web_view_base_->MainFrameImpl() &&
      web_view_base_->MainFrameImpl()->GetFrameView())
    web_view_base_->MainFrameImpl()->GetFrameView()->SetNeedsLayout();

  web_view_base_->UpdateMainFrameLayoutSize();
}

}  // namespace blink
```