Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Core Request:** The request asks for the functionality of `gpu_external_texture.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of its use, common errors, and how a user might trigger this code.

2. **Initial Scan and Keyword Identification:**  Read through the code, looking for key terms and concepts related to WebGPU, media, and browser internals. I'd immediately notice:

    * **WebGPU:** The directory name and many class names (`GPUExternalTexture`, `GPUDevice`, etc.) scream WebGPU.
    * **External Texture:** This is the central concept. What does it mean?  The code mentions importing textures.
    * **Video:**  `HTMLVideoElement`, `VideoFrame`, `media::VideoFrame`, `WebMediaPlayer`. This strongly suggests handling video as a source for WebGPU textures.
    * **Cache:** `ExternalTextureCache`. Caching implies performance optimization and managing the lifetime of `GPUExternalTexture` objects.
    * **Dawn:**  The `#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"` hints at the underlying graphics API being used (Dawn is a cross-platform WebGPU implementation).
    * **JavaScript Bindings:**  The presence of `#include "third_party/blink/renderer/bindings/modules/v8/..."` files indicates this C++ code is exposed to JavaScript.

3. **Focus on Key Classes and Methods:** Identify the most important classes and their core methods:

    * **`GPUExternalTexture`:**  Likely represents a WebGPU external texture object in Blink. Key methods: `CreateImpl`, `FromHTMLVideoElement`, `FromVideoFrame`, `Refresh`, `Expire`, `Destroy`, `NeedsToUpdate`. These methods suggest creation from different sources, lifecycle management, and update logic.
    * **`ExternalTextureCache`:** Manages the `GPUExternalTexture` objects. Key methods: `Import`, `Add`, `Remove`, `Destroy`, `ExpireAtEndOfTask`. This confirms its role in caching and lifetime management.

4. **Infer Functionality:** Based on the identified keywords and methods, start inferring the file's purpose:

    * It bridges the gap between media resources (like `<video>` elements and `VideoFrame` objects) and WebGPU external textures.
    * It provides a way to use video frames as texture sources in WebGPU.
    * It handles the lifecycle of these textures, especially the complexities of dealing with potentially changing video content.
    * The caching mechanism likely prevents redundant creation of external textures for the same video source.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  The V8 binding includes suggest that JavaScript code can create `GPUExternalTexture` objects using methods like `importExternalTexture` on a `GPUDevice`. The descriptor would likely specify the source (e.g., a `<video>` element).
    * **HTML:** The `<video>` element is explicitly mentioned as a source. This makes sense, as users would likely want to use video as textures in WebGPU-powered graphics.
    * **CSS:** While not directly involved in the *creation* of `GPUExternalTexture`, CSS can influence the *visibility* of the `<video>` element, which might indirectly affect when the texture needs to be updated (though the code doesn't directly handle CSS visibility).

6. **Develop Examples:**  Think about how a developer would use this API. This leads to concrete examples:

    * **JavaScript:**  `navigator.gpu.getDevice().importExternalTexture({ source: videoElement });`
    * **HTML:** The need for a `<video>` element in the HTML.

7. **Consider Logic and Assumptions (Input/Output):**

    * **Input:** A `GPUExternalTextureDescriptor` specifying a `<video>` element or a `VideoFrame`.
    * **Output:** A `GPUExternalTexture` object, or an error if the import fails.
    * **Logic:** The code checks the type of the source, retrieves the underlying media data, creates a Dawn external texture, and manages its lifecycle.

8. **Identify Potential User Errors:** Think about common mistakes developers might make:

    * Not having a playing video.
    * Destroying the video element prematurely.
    * Incorrect color space settings.
    * Using an already closed `VideoFrame`.

9. **Trace User Actions (Debugging Clues):**  How does a user's interaction lead to this code being executed?

    * A user loads a webpage with WebGPU code.
    * The JavaScript code calls `importExternalTexture`.
    * The browser's rendering engine (Blink) processes this call and executes the C++ code in `gpu_external_texture.cc`.

10. **Refine and Organize:** Structure the answer logically, using headings and bullet points for clarity. Ensure the language is clear and addresses all aspects of the prompt. Emphasize the key functionalities and relationships.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Might have initially focused solely on the Dawn API calls. Realized the importance of the caching and lifecycle management aspects.
* **Connecting to CSS:** Initially considered a direct link, but realized the connection is more indirect (CSS affects visibility, which *could* trigger updates, but the code doesn't explicitly watch CSS).
* **Error Handling:**  Went back through the code to identify where exceptions are thrown and the conditions that trigger them.

By following these steps, moving from high-level understanding to detailed code analysis and considering the user's perspective, a comprehensive and accurate answer can be constructed.
这个文件 `blink/renderer/modules/webgpu/gpu_external_texture.cc` 的主要功能是 **在 Chromium Blink 渲染引擎中实现 WebGPU 的 `GPUExternalTexture` 接口**。  `GPUExternalTexture` 允许 WebGPU 从外部资源（目前主要是 HTML `<video>` 元素和 `VideoFrame` 对象）导入纹理，以便在 GPU 上进行渲染。

以下是该文件的主要功能点：

**1. 创建和管理 `GPUExternalTexture` 对象:**

* **从 HTMLVideoElement 创建:**  `GPUExternalTexture::FromHTMLVideoElement` 方法负责从 HTML `<video>` 元素创建一个 `GPUExternalTexture` 对象。它会获取视频的当前帧，并将其转换为 WebGPU 可以使用的外部纹理。
* **从 VideoFrame 创建:** `GPUExternalTexture::FromVideoFrame` 方法负责从 `VideoFrame` 对象（通常来自 WebCodecs API）创建一个 `GPUExternalTexture` 对象。
* **创建已过期的纹理:** `GPUExternalTexture::CreateExpired` 方法用于创建一个立即失效的 `GPUExternalTexture` 对象，这通常发生在尝试从已经销毁的设备创建纹理时。
* **内部创建实现:** `GPUExternalTexture::CreateImpl` 是实际创建 `GPUExternalTexture` 对象的底层实现，它会处理颜色空间转换、创建 Dawn 的外部纹理对象等。
* **缓存管理:** `ExternalTextureCache` 类负责缓存已创建的 `GPUExternalTexture` 对象，以避免为同一个视频源重复创建纹理，提高性能。它使用两个哈希表 (`from_html_video_element_` 和 `from_video_frame_`) 来分别存储从 HTMLVideoElement 和 VideoFrame 创建的纹理。

**2. 处理纹理的生命周期:**

* **刷新 (Refresh):** `GPUExternalTexture::Refresh` 方法用于激活一个之前可能失效的外部纹理。
* **过期 (Expire):** `GPUExternalTexture::Expire` 方法用于标记一个外部纹理为过期，意味着它引用的底层资源可能已经失效。
* **销毁 (Destroy):** `GPUExternalTexture::Destroy` 方法负责释放 `GPUExternalTexture` 对象所持有的资源，包括底层的 Dawn 外部纹理对象。
* **到期任务 (ExpireTask):** `ExternalTextureCache::ExpireTask` 方法会在任务队列中定期执行，用于清理过期的 `GPUExternalTexture` 对象。
* **检查是否需要更新 (NeedsToUpdate):** `GPUExternalTexture::NeedsToUpdate` 方法会检查从 HTMLVideoElement 创建的纹理是否需要更新，例如当视频播放到新的帧时。

**3. 与底层图形 API (Dawn) 的交互:**

* 文件中使用了 `third_party/blink/renderer/modules/webgpu/dawn_conversions.h` 和 `third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h`，表明它与 Dawn 集成，Dawn 是 Chromium 中 WebGPU 的实现层。
* `CreateExternalTexture` 函数 (在 `third_party/blink/renderer/modules/webgpu/external_texture_helper.h` 中声明) 负责调用 Dawn 的 API 创建底层的外部纹理对象。

**4. 处理视频帧的更新和失效:**

* 当从 HTML `<video>` 元素创建纹理时，需要跟踪视频的播放状态。如果视频播放到新的帧，之前的纹理可能需要更新。
* 当 `VideoFrame` 对象被关闭或销毁时，使用该 `VideoFrame` 创建的 `GPUExternalTexture` 也应该失效。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  WebGPU API 主要通过 JavaScript 暴露给开发者。开发者可以使用 JavaScript 代码调用 `GPUDevice.importExternalTexture()` 方法来创建 `GPUExternalTexture` 对象，并将 HTML `<video>` 元素或 `VideoFrame` 对象作为源传递进去。
    ```javascript
    // 获取 GPU 设备
    const gpu = navigator.gpu;
    const adapter = await gpu.requestAdapter();
    const device = await adapter.requestDevice();

    // 获取 HTMLVideoElement
    const videoElement = document.getElementById('myVideo');

    // 导入外部纹理
    const externalTexture = device.importExternalTexture({
      source: videoElement,
    });

    // 在渲染通道中使用 externalTexture 创建的纹理视图
    const textureView = externalTexture.createView();
    ```
* **HTML:**  `GPUExternalTexture` 的一个重要来源是 HTML `<video>` 元素。开发者需要在 HTML 中嵌入 `<video>` 标签，并确保视频源正确。
    ```html
    <video id="myVideo" src="my-video.mp4" autoplay muted loop></video>
    ```
* **CSS:**  CSS 可以控制 HTML `<video>` 元素的样式和布局，但这与 `gpu_external_texture.cc` 的核心功能没有直接关系。然而，CSS 可能会影响视频元素的可见性，这可能会间接影响浏览器处理视频帧的方式，但 `gpu_external_texture.cc` 主要关注的是 WebGPU 层的纹理导入和管理。

**逻辑推理、假设输入与输出:**

假设输入一个正在播放的 HTML `<video>` 元素，并且 JavaScript 代码调用了 `device.importExternalTexture({ source: videoElement })`。

* **假设输入:**
    * `descriptor->source()->GetContentType()` 返回 `V8UnionHTMLVideoElementOrVideoFrame::ContentType::kHTMLVideoElement`。
    * `descriptor->source()->GetAsHTMLVideoElement()` 返回一个有效的 `HTMLVideoElement` 指针。
* **逻辑推理:**
    1. `ExternalTextureCache::Import` 方法会被调用。
    2. 代码会检查缓存中是否已存在与该 `HTMLVideoElement` 关联的 `GPUExternalTexture`。
    3. 如果不存在或需要更新，`GPUExternalTexture::FromHTMLVideoElement` 会被调用。
    4. `GPUExternalTexture::FromHTMLVideoElement` 会获取 `HTMLVideoElement` 的当前视频帧。
    5. `GPUExternalTexture::CreateImpl` 会被调用，它会调用 Dawn 的 API 创建一个外部纹理。
    6. 新创建的 `GPUExternalTexture` 会被添加到缓存中。
* **输出:**  成功创建一个 `GPUExternalTexture` 对象，该对象可以用于在 WebGPU 渲染通道中采样视频帧。

**用户或编程常见的使用错误:**

* **尝试从未加载或加载失败的 `<video>` 元素导入纹理:**  如果视频元素没有可用的视频帧，`importExternalTexture` 可能会失败或返回一个无效的纹理。
* **在视频播放前或播放过程中过早地销毁 `<video>` 元素:**  这会导致 `GPUExternalTexture` 引用的资源失效。
* **在 `VideoFrame` 关闭后尝试使用由它创建的 `GPUExternalTexture`:**  WebCodecs 的 `VideoFrame` 有自己的生命周期，一旦关闭，相关的 `GPUExternalTexture` 就不能再使用。
* **忘记处理纹理的过期:**  从 `<video>` 元素创建的纹理可能会因为视频播放到新的帧而过期，开发者需要意识到这一点并在渲染循环中进行处理。
* **错误地管理 `GPUExternalTexture` 的生命周期:**  没有适当地销毁 `GPUExternalTexture` 对象可能导致资源泄漏。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问包含 WebGPU 内容的网页:**  用户在浏览器中打开一个使用 WebGPU API 的网页。
2. **JavaScript 代码执行:** 网页加载后，JavaScript 代码开始执行。
3. **调用 `importExternalTexture()`:**  JavaScript 代码调用了 `GPUDevice` 对象的 `importExternalTexture()` 方法，并将一个 HTML `<video>` 元素或 `VideoFrame` 对象作为参数传递进去。
4. **Blink 引擎处理 WebGPU API 调用:**  Blink 渲染引擎接收到这个 WebGPU API 调用。
5. **调用 C++ 代码:**  `importExternalTexture()` 的 JavaScript 调用会最终映射到 `blink/renderer/modules/webgpu/gpu_device.cc` 中的实现，然后会调用到 `blink/renderer/modules/webgpu/gpu_external_texture.cc` 中的相关方法，例如 `ExternalTextureCache::Import`。
6. **创建 `GPUExternalTexture` 对象:**  `gpu_external_texture.cc` 中的代码会根据传入的源创建或检索 `GPUExternalTexture` 对象。
7. **纹理对象在 WebGPU 渲染管线中使用:**  创建的 `GPUExternalTexture` 对象可以在 WebGPU 的渲染管线中被使用，例如作为采样器的输入，将视频帧渲染到 3D 场景中。

通过调试器，开发者可以在 `gpu_external_texture.cc` 中的关键方法设置断点，例如 `ExternalTextureCache::Import`、`GPUExternalTexture::FromHTMLVideoElement` 等，来跟踪 `GPUExternalTexture` 的创建过程，查看传入的参数，以及了解缓存的管理情况。 这有助于诊断与外部纹理相关的 WebGPU 问题。

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/gpu_external_texture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu_external_texture.h"

#include "media/base/video_frame.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_external_texture_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_view_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_htmlvideoelement_videoframe.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/external_texture_helper.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_queue.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {
ExternalTextureCache::ExternalTextureCache(GPUDevice* device)
    : device_(device) {}

GPUExternalTexture* ExternalTextureCache::Import(
    const GPUExternalTextureDescriptor* descriptor,
    ExceptionState& exception_state) {
  // Ensure the GPUExternalTexture created from a destroyed GPUDevice will be
  // expired immediately.
  if (device()->destroyed()) {
    return GPUExternalTexture::CreateExpired(this, descriptor, exception_state);
  }

  GPUExternalTexture* external_texture = nullptr;
  switch (descriptor->source()->GetContentType()) {
    case V8UnionHTMLVideoElementOrVideoFrame::ContentType::kHTMLVideoElement: {
      HTMLVideoElement* video = descriptor->source()->GetAsHTMLVideoElement();
      auto cache = from_html_video_element_.find(video);
      if (cache != from_html_video_element_.end()) {
        external_texture = cache->value;

        // If we got a cache miss, or `ContinueCheckingCurrentVideoFrame`
        // returned false, make a new external texture.
        // `ContinueCheckingCurrentVideoFrame` returns false if the frame has
        // expired and it no longer needs to be checked for expiry.
        if (external_texture->NeedsToUpdate()) {
          external_texture = GPUExternalTexture::FromHTMLVideoElement(
              this, video, descriptor, exception_state);
        }
      } else {
        external_texture = GPUExternalTexture::FromHTMLVideoElement(
            this, video, descriptor, exception_state);
      }

      // GPUExternalTexture imported from HTMLVideoElement should be expired
      // at the end of task.
      if (external_texture) {
        external_texture->Refresh();
        ExpireAtEndOfTask(external_texture);
      }
      break;
    }
    case V8UnionHTMLVideoElementOrVideoFrame::ContentType::kVideoFrame: {
      VideoFrame* frame = descriptor->source()->GetAsVideoFrame();

      auto cache = from_video_frame_.find(frame);
      if (cache != from_video_frame_.end()) {
        external_texture = cache->value;
      } else {
        external_texture = GPUExternalTexture::FromVideoFrame(
            this, frame, descriptor, exception_state);
      }
      break;
    }
  }

  return external_texture;
}

void ExternalTextureCache::Destroy() {
  // Skip pending expiry tasks to destroy all pending external textures.
  expire_task_scheduled_ = false;

  for (auto& cache : from_html_video_element_) {
    cache.value->Destroy();
  }
  from_html_video_element_.clear();

  for (auto& cache : from_video_frame_) {
    cache.value->Destroy();
  }
  from_video_frame_.clear();

  // GPUExternalTexture in expire list should be in from_html_video_element_ and
  // from_video_frame_. It has been destroyed when clean up the cache. Clear
  // list here is enough.
  expire_set_.clear();
}

void ExternalTextureCache::Add(HTMLVideoElement* video,
                               GPUExternalTexture* external_texture) {
  from_html_video_element_.insert(video, external_texture);
}

void ExternalTextureCache::Remove(HTMLVideoElement* video) {
  from_html_video_element_.erase(video);
}

void ExternalTextureCache::Add(VideoFrame* frame,
                               GPUExternalTexture* external_texture) {
  from_video_frame_.insert(frame, external_texture);
}

void ExternalTextureCache::Remove(VideoFrame* frame) {
  from_video_frame_.erase(frame);
}

void ExternalTextureCache::Trace(Visitor* visitor) const {
  visitor->Trace(from_html_video_element_);
  visitor->Trace(from_video_frame_);
  visitor->Trace(expire_set_);
  visitor->Trace(device_);
}

GPUDevice* ExternalTextureCache::device() const {
  return device_.Get();
}

void ExternalTextureCache::ExpireAtEndOfTask(
    GPUExternalTexture* external_texture) {
  CHECK(external_texture);
  expire_set_.insert(external_texture);

  if (expire_task_scheduled_) {
    return;
  }

  device()
      ->GetExecutionContext()
      ->GetTaskRunner(TaskType::kWebGPU)
      ->PostTask(FROM_HERE, WTF::BindOnce(&ExternalTextureCache::ExpireTask,
                                          WrapWeakPersistent(this)));
  expire_task_scheduled_ = true;
}

void ExternalTextureCache::ExpireTask() {
  // GPUDevice.destroy() call has destroyed all pending external textures.
  if (!expire_task_scheduled_) {
    return;
  }

  expire_task_scheduled_ = false;

  auto external_textures = std::move(expire_set_);
  for (auto& external_texture : external_textures) {
    external_texture->Expire();
  }
}

void ExternalTextureCache::ReferenceUntilGPUIsFinished(
    scoped_refptr<WebGPUMailboxTexture> mailbox_texture) {
  CHECK(mailbox_texture);
  ExecutionContext* execution_context = device()->GetExecutionContext();

  // If device has no valid execution context. Release
  // the mailbox immediately.
  if (!execution_context) {
    return;
  }

  // Keep mailbox texture alive until callback returns.
  auto* callback = BindWGPUOnceCallback(
      [](scoped_refptr<WebGPUMailboxTexture> mailbox_texture,
         WGPUQueueWorkDoneStatus) {},
      std::move(mailbox_texture));

  device()->queue()->GetHandle().OnSubmittedWorkDone(
      callback->UnboundCallback(), callback->AsUserdata());

  // Ensure commands are flushed.
  device()->EnsureFlush(ToEventLoop(execution_context));
}

// static
GPUExternalTexture* GPUExternalTexture::CreateImpl(
    ExternalTextureCache* cache,
    const GPUExternalTextureDescriptor* webgpu_desc,
    scoped_refptr<media::VideoFrame> media_video_frame,
    media::PaintCanvasVideoRenderer* video_renderer,
    std::optional<media::VideoFrame::ID> media_video_frame_unique_id,
    ExceptionState& exception_state) {
  CHECK(media_video_frame);

  PredefinedColorSpace dst_predefined_color_space;
  if (!ValidateAndConvertColorSpace(webgpu_desc->colorSpace(),
                                    dst_predefined_color_space,
                                    exception_state)) {
    return nullptr;
  }

  ExternalTexture external_texture =
      CreateExternalTexture(cache->device(), dst_predefined_color_space,
                            media_video_frame, video_renderer);

  if (external_texture.wgpu_external_texture == nullptr ||
      external_texture.mailbox_texture == nullptr) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Failed to import texture from video");
    return nullptr;
  }

  GPUExternalTexture* gpu_external_texture =
      MakeGarbageCollected<GPUExternalTexture>(
          cache, std::move(external_texture.wgpu_external_texture),
          external_texture.mailbox_texture, external_texture.is_zero_copy,
          media_video_frame->metadata().read_lock_fences_enabled,
          media_video_frame_unique_id, webgpu_desc->label());

  return gpu_external_texture;
}

// static
GPUExternalTexture* GPUExternalTexture::CreateExpired(
    ExternalTextureCache* cache,
    const GPUExternalTextureDescriptor* webgpu_desc,
    ExceptionState& exception_state) {
  // Validate GPUExternalTextureDescriptor.
  ExternalTextureSource source;
  switch (webgpu_desc->source()->GetContentType()) {
    case V8UnionHTMLVideoElementOrVideoFrame::ContentType::kHTMLVideoElement: {
      HTMLVideoElement* video = webgpu_desc->source()->GetAsHTMLVideoElement();
      source = GetExternalTextureSourceFromVideoElement(video, exception_state);
      break;
    }
    case V8UnionHTMLVideoElementOrVideoFrame::ContentType::kVideoFrame: {
      VideoFrame* frame = webgpu_desc->source()->GetAsVideoFrame();
      source = GetExternalTextureSourceFromVideoFrame(frame, exception_state);
      break;
    }
  }
  if (!source.valid)
    return nullptr;

  // Bypass importing video frame into Dawn.
  GPUExternalTexture* external_texture =
      MakeGarbageCollected<GPUExternalTexture>(
          cache, cache->device()->GetHandle().CreateErrorExternalTexture(),
          nullptr /*mailbox_texture*/, false /*is_zero_copy*/,
          false /*read_lock_fences_enabled*/,
          std::nullopt /*media_video_frame_unique_id*/, webgpu_desc->label());

  return external_texture;
}

// static
GPUExternalTexture* GPUExternalTexture::FromHTMLVideoElement(
    ExternalTextureCache* cache,
    HTMLVideoElement* video,
    const GPUExternalTextureDescriptor* webgpu_desc,
    ExceptionState& exception_state) {
  ExternalTextureSource source =
      GetExternalTextureSourceFromVideoElement(video, exception_state);
  if (!source.valid)
    return nullptr;

  // Ensure that video playback remains unaffected by preventing any
  // throttling when the video is not visible on the screen.
  DCHECK(video);
  if (auto* wmp = video->GetWebMediaPlayer()) {
    wmp->RequestVideoFrameCallback();
  }

  GPUExternalTexture* external_texture = GPUExternalTexture::CreateImpl(
      cache, webgpu_desc, source.media_video_frame, source.video_renderer,
      source.media_video_frame_unique_id, exception_state);

  // WebGPU Spec requires that If the latest presented frame of video is not
  // the same frame from which texture was imported, set expired to true and
  // releasing ownership of the underlying resource and remove the texture from
  // active list. Listen to HTMLVideoElement and insert the texture into active
  // list for management.
  if (external_texture) {
    external_texture->SetVideo(video);
    cache->Add(video, external_texture);
  }

  return external_texture;
}

// static
GPUExternalTexture* GPUExternalTexture::FromVideoFrame(
    ExternalTextureCache* cache,
    VideoFrame* frame,
    const GPUExternalTextureDescriptor* webgpu_desc,
    ExceptionState& exception_state) {
  ExternalTextureSource source =
      GetExternalTextureSourceFromVideoFrame(frame, exception_state);
  if (!source.valid)
    return nullptr;

  GPUExternalTexture* external_texture = GPUExternalTexture::CreateImpl(
      cache, webgpu_desc, source.media_video_frame, source.video_renderer,
      std::nullopt, exception_state);

  // If the webcodec video frame has been closed or destroyed, set expired to
  // true, releasing ownership of the underlying resource and remove the texture
  // from active list. Listen to the VideoFrame and insert the texture into
  // active list for management.
  if (external_texture) {
    if (!external_texture->ListenToVideoFrame(frame)) {
      return nullptr;
    }

    cache->Add(frame, external_texture);
  }

  return external_texture;
}

GPUExternalTexture::GPUExternalTexture(
    ExternalTextureCache* cache,
    wgpu::ExternalTexture external_texture,
    scoped_refptr<WebGPUMailboxTexture> mailbox_texture,
    bool is_zero_copy,
    bool read_lock_fences_enabled,
    std::optional<media::VideoFrame::ID> media_video_frame_unique_id,
    const String& label)
    : DawnObject<wgpu::ExternalTexture>(cache->device(),
                                        external_texture,
                                        label),
      mailbox_texture_(std::move(mailbox_texture)),
      is_zero_copy_(is_zero_copy),
      read_lock_fences_enabled_(read_lock_fences_enabled),
      media_video_frame_unique_id_(media_video_frame_unique_id),
      cache_(cache) {
  task_runner_ =
      device()->GetExecutionContext()->GetTaskRunner(TaskType::kWebGPU);

  // Mark GPUExternalTexture without back resources as destroyed because no need
  // to do real resource releasing.
  if (!mailbox_texture_)
    status_ = Status::Destroyed;
}

void GPUExternalTexture::Refresh() {
  CHECK(status_ != Status::Destroyed);

  if (active()) {
    return;
  }

  GetHandle().Refresh();
  status_ = Status::Active;
}

void GPUExternalTexture::Expire() {
  if (expired() || destroyed()) {
    return;
  }

  GetHandle().Expire();
  status_ = Status::Expired;
}

void GPUExternalTexture::Destroy() {
  DCHECK(!destroyed());
  DCHECK(mailbox_texture_);

  // One copy path finished video frame access after GPUExternalTexture
  // construction. Zero copy path needs to ensure all gpu commands
  // execution finished before destroy.
  if (isZeroCopy() && isReadLockFenceEnabled()) {
    cache_->ReferenceUntilGPUIsFinished(std::move(mailbox_texture_));
  }

  status_ = Status::Destroyed;
  mailbox_texture_.reset();
}

void GPUExternalTexture::SetVideo(HTMLVideoElement* video) {
  CHECK(video);
  video_ = video;
}

bool GPUExternalTexture::NeedsToUpdate() {
  CHECK(media_video_frame_unique_id_.has_value());
  CHECK(video_);

  if (IsCurrentFrameFromHTMLVideoElementValid()) {
    return false;
  }

  // Schedule source invalid task to remove GPUExternalTexture
  // from cache.
  OnSourceInvalidated();

  // If GPUExternalTexture is used in current task scope, don't do
  // reimport until current task scope finished.
  if (active()) {
    return false;
  }

  return true;
}

void GPUExternalTexture::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(video_);
  visitor->Trace(cache_);
  DawnObject<wgpu::ExternalTexture>::Trace(visitor);
}

bool GPUExternalTexture::IsCurrentFrameFromHTMLVideoElementValid() {
  CHECK(video_);
  CHECK(media_video_frame_unique_id_.has_value());

  WebMediaPlayer* media_player = video_->GetWebMediaPlayer();

  // HTMLVideoElement transition from having a WMP to not having one.
  if (!media_player) {
    return false;
  }

  // VideoFrame unique id is unique in the same process. Compare the unique id
  // with current video frame from compositor to detect a new presented
  // video frame and expire the GPUExternalTexture.
  if (media_video_frame_unique_id_ != media_player->CurrentFrameId()) {
    return false;
  }

  return true;
}

void GPUExternalTexture::OnSourceInvalidated() {
  CHECK(task_runner_);
  CHECK(task_runner_->BelongsToCurrentThread());

  // OnSourceInvalidated is called for both VideoFrame and HTMLVE.
  // VideoFrames are invalidated with and explicit close() call that
  // should mark the ExternalTexture destroyed immediately.
  // However HTMLVE could decide to advance in the middle of the task
  // that imported the ExternalTexture. In that case defer the invalidation
  // until the end of the task to preserve the semantic of ExternalTexture.
  if (status_ == Status::Active && video_) {
    if (!remove_from_cache_task_scheduled_) {
      task_runner_->PostTask(FROM_HERE,
                             WTF::BindOnce(&GPUExternalTexture::RemoveFromCache,
                                           WrapWeakPersistent(this)));
    }
    remove_from_cache_task_scheduled_ = true;
  } else {
    RemoveFromCache();
  }
}

void GPUExternalTexture::RemoveFromCache() {
  if (video_) {
    cache_->Remove(video_);
  } else if (frame_) {
    cache_->Remove(frame_);
  }

  Destroy();
}

bool GPUExternalTexture::ListenToVideoFrame(VideoFrame* frame) {
  if (!frame->handle()->WebGPURegisterExternalTextureExpireCallback(
          CrossThreadBindOnce(&GPUExternalTexture::OnVideoFrameClosed,
                              WrapCrossThreadWeakPersistent(this)))) {
    OnSourceInvalidated();
    return false;
  }

  frame_ = frame;
  return true;
}

void GPUExternalTexture::OnVideoFrameClosed() {
  CHECK(task_runner_);

  if (destroyed())
    return;

  // Expire the GPUExternalTexture here in the main thread to prevent it from
  // being used again (because WebGPU runs on the main thread). Expiring the
  // texture later in ExpireExternalTextureFromVideoFrame() could occur on a
  // worker thread and cause a race condition.
  Expire();

  if (task_runner_->BelongsToCurrentThread()) {
    OnSourceInvalidated();
    return;
  }

  // If current thread is not the one that creates GPUExternalTexture. Post task
  // to that thread to destroy the GPUExternalTexture.
  task_runner_->PostTask(FROM_HERE,
                         ConvertToBaseOnceCallback(CrossThreadBindOnce(
                             &GPUExternalTexture::OnVideoFrameClosed,
                             WrapCrossThreadWeakPersistent(this))));
}

bool GPUExternalTexture::active() const {
  return status_ == Status::Active;
}

bool GPUExternalTexture::expired() const {
  return status_ == Status::Expired;
}

bool GPUExternalTexture::isZeroCopy() const {
  return is_zero_copy_;
}

bool GPUExternalTexture::isReadLockFenceEnabled() const {
  return read_lock_fences_enabled_;
}

bool GPUExternalTexture::destroyed() const {
  return status_ == Status::Destroyed;
}

}  // namespace blink

"""

```