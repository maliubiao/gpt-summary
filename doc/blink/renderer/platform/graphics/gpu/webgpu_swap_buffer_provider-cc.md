Response:
Let's break down the thought process for analyzing this C++ source code and fulfilling the request.

**1. Understanding the Core Functionality:**

* **Keywords and Imports:** The initial scan of `#include` statements is crucial. Seeing `webgpu_swap_buffer_provider.h`, `gpu/command_buffer/client/webgpu_interface.h`, `viz/`, `cc/`, and `wgpu/` immediately points to this being related to WebGPU rendering within the Chromium compositor. The "swap buffer" part hints at the double-buffering or similar mechanism used for smooth animation.
* **Class Name:** `WebGPUSwapBufferProvider` clearly suggests its role: providing swap buffers for WebGPU.
* **Constructor Arguments:**  The constructor takes `wgpu::Device`, `wgpu::TextureUsage`, `wgpu::TextureFormat`, etc. This reinforces the WebGPU connection and indicates the class manages textures with specific properties.
* **Key Methods:**  `GetNewTexture`, `PrepareTransferableResource`, `CopyToVideoFrame`, `DiscardCurrentSwapBuffer`. These suggest creating textures, passing them to the compositor, and handling video frame output.
* **`cc::TextureLayer`:** The interaction with `cc::TextureLayer` signifies that this class is involved in integrating WebGPU rendering into the Chromium compositing architecture.

**2. Identifying Core Responsibilities:**

Based on the initial understanding, the core functions are:

* **Managing Swap Buffers:**  Creating, storing, and cycling through textures used for rendering.
* **Interfacing with WebGPU:** Using `wgpu::Device` and related types to create and manage WebGPU textures.
* **Integrating with the Compositor:** Providing textures to the compositor via `cc::TextureLayer` and `viz::TransferableResource`.
* **Handling Synchronization:** Managing sync tokens to ensure proper ordering of operations between WebGPU and the compositor.
* **Optional Video Frame Output:**  Supporting copying the rendered output to video frames.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **The "Why":**  Why does this code exist?  It's to enable WebGPU rendering in web pages. Therefore, it *must* have connections to the technologies that initiate rendering.
* **JavaScript:** WebGPU is exposed to JavaScript. JavaScript code using the WebGPU API will ultimately trigger the creation and presentation of these swap buffers.
* **HTML `<canvas>`:**  The most common target for WebGPU rendering is a `<canvas>` element. The `WebGPUSwapBufferProvider` likely provides the backing store for the canvas when using a WebGPU context.
* **CSS:** While less direct, CSS properties like `opacity`, `transform`, and filters applied to a canvas containing WebGPU content will interact with the compositing process that this class is a part of.

**4. Developing Examples:**

* **JavaScript:** A simple WebGPU rendering loop is the most direct example. Focus on the part where the rendered texture is presented to the canvas.
* **HTML:**  A basic HTML page with a `<canvas>` element is sufficient to illustrate the connection.
* **CSS:**  Show how CSS properties can affect the appearance of the rendered WebGPU content.

**5. Logical Reasoning (Hypothetical Inputs and Outputs):**

* **Scenario:** Consider the lifecycle of rendering a single frame.
* **Input:** A JavaScript request to render something using WebGPU on a canvas. This triggers the `GetNewTexture` call.
* **Processing:**  The `WebGPUSwapBufferProvider` allocates a texture, connects it to a `cc::TextureLayer`, and prepares it for the compositor.
* **Output:** A `viz::TransferableResource` containing the texture information and a release callback, which is then passed to the compositor. The `cc::TextureLayer` is updated to display this texture.

**6. Identifying Potential User/Programming Errors:**

* **Texture Size:** The code explicitly checks for `max_texture_size_`. Exceeding this is a common error.
* **Incorrect Texture Usage:**  The `DCHECK` statements in `GetNewTexture` highlight the importance of providing the correct usage flags. A mismatch can lead to errors.
* **Resource Management (Implicit):** Although not explicitly throwing errors, incorrect usage or premature disposal of WebGPU objects could indirectly cause issues that this class might encounter (e.g., trying to use a destroyed texture). The `Neuter` method addresses the cleanup aspect.

**7. Structuring the Answer:**

Organize the findings logically:

* **Core Functionality:** Start with a high-level overview.
* **Relationship to Web Technologies:** Explain the connections with JavaScript, HTML, and CSS with concrete examples.
* **Logical Reasoning:** Present a clear scenario with inputs and outputs.
* **Common Errors:** Provide specific, actionable examples of mistakes.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe focus solely on the graphics pipeline.
* **Correction:** Realize the importance of connecting this low-level code to the higher-level web technologies that developers interact with.
* **Initial example:** A complex WebGPU rendering example might be overwhelming.
* **Correction:** Simplify the JavaScript example to focus on the essential parts related to presentation.
* **Initial description of errors:**  Too generic ("something might go wrong").
* **Correction:** Focus on specific checks and potential mismatches in the code.

By following this thought process, systematically analyzing the code, and connecting it to the broader web development context, a comprehensive and accurate answer can be generated.
这个文件 `webgpu_swap_buffer_provider.cc` 是 Chromium Blink 渲染引擎中负责 **WebGPU 渲染内容与 Chromium 合成器之间交换缓冲区** 的关键组件。它的主要功能是管理用于 WebGPU 渲染的纹理，并将这些纹理提供给 Chromium 的合成器 (Compositor) 进行显示。

以下是它的详细功能分解：

**核心功能:**

1. **管理 WebGPU 交换链 (Swap Chain) 的纹理:**
   - 它负责创建和管理用于 WebGPU 渲染的后台缓冲区（通常是纹理）。
   - 它使用 `gpu::SharedImagePool` 来高效地管理这些纹理，以便重复使用并减少内存分配开销。
   - 它与 Dawn (Chromium 使用的 WebGPU 实现) 交互，创建和管理 `wgpu::Texture` 对象。

2. **作为 WebGPU 渲染内容到 Chromium 合成器的桥梁:**
   - 它实现了 `cc::TextureLayer::Client` 接口，使得它可以为 `cc::TextureLayer` 提供纹理数据。
   - 它通过 `PrepareTransferableResource` 方法将当前的渲染纹理打包成 `viz::TransferableResource`，以便发送到合成器进程。
   - `viz::TransferableResource` 包含了纹理的句柄、大小、格式以及同步信息，允许合成器安全地访问和显示 WebGPU 渲染的内容。

3. **处理帧的呈现和同步:**
   - 它维护一个当前的交换缓冲区 (`current_swap_buffer_`) 和上一个交换缓冲区 (`last_swap_buffer_`)。
   - 它使用 GPU 同步令牌 (Sync Token) 来确保 WebGPU 渲染和合成器之间的操作顺序正确，避免数据竞争。
   - `ReleaseWGPUTextureAccessIfNeeded` 方法用于在纹理需要被合成器使用时，释放 WebGPU 对纹理的访问。

4. **支持不同的纹理格式和颜色空间:**
   - 它接收 `wgpu::TextureFormat` 和 `PredefinedColorSpace` 等参数，以支持各种不同的渲染需求。
   - 它将 WebGPU 的纹理格式转换为 Chromium 合成器理解的 `viz::SharedImageFormat`。

5. **处理纹理的丢弃和清理:**
   - `DiscardCurrentSwapBuffer` 方法用于标记当前纹理不再需要呈现。
   - `Neuter` 方法用于释放所有资源，包括纹理和相关的合成层。

6. **支持将 WebGPU 渲染结果复制到视频帧:**
   - `CopyToVideoFrame` 方法允许将当前的渲染纹理复制到 `WebGraphicsContext3DVideoFramePool` 管理的视频帧中，用于视频处理或其他目的。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

1. **JavaScript (WebGPU API):**
   - **功能关系:** JavaScript 代码使用 WebGPU API (例如 `navigator.gpu.requestAdapter()`, `device.createCommandEncoder()`, `renderPass.draw()`, `swapChain.getCurrentTexture().present()`) 来进行渲染。 `WebGPUSwapBufferProvider` 负责提供 `swapChain.getCurrentTexture()` 返回的纹理。
   - **举例说明:** 当 JavaScript 代码调用 `swapChain.getCurrentTexture()` 获取用于绘制的纹理时， Dawn 内部会调用 `WebGPUSwapBufferProvider::GetNewTexture` 来获取一个新的或复用的纹理。在渲染完成后，调用 `swapChain.present()` 会触发纹理的提交，最终由 `WebGPUSwapBufferProvider::PrepareTransferableResource` 将纹理传递给合成器。

2. **HTML (`<canvas>` 元素):**
   - **功能关系:** WebGPU 的渲染通常发生在 HTML 的 `<canvas>` 元素上。 `WebGPUSwapBufferProvider` 提供的纹理就是用于显示 `<canvas>` 元素中 WebGPU 渲染内容的。
   - **举例说明:** 当一个 `<canvas>` 元素被用于 WebGPU 上下文时， Blink 会创建一个与该 `<canvas>` 关联的 `WebGPUSwapBufferProvider` 实例。 这个 Provider 产生的纹理最终会作为 `cc::TextureLayer` 的内容，渲染到屏幕上的 `<canvas>` 区域。

3. **CSS (影响 `<canvas>` 元素的渲染):**
   - **功能关系:** CSS 属性可以影响包含 WebGPU 渲染内容的 `<canvas>` 元素的显示效果，例如 `opacity`, `transform`, `filter` 等。 `WebGPUSwapBufferProvider` 提供的纹理被合成器使用时，会受到这些 CSS 属性的影响。
   - **举例说明:** 如果一个包含 WebGPU 渲染的 `<canvas>` 元素设置了 `opacity: 0.5;` 的 CSS 样式，那么 `WebGPUSwapBufferProvider` 提供的纹理在被合成器绘制到屏幕上时，会被应用半透明的效果。 `SetFilterQuality` 方法也允许根据 CSS 的 `image-rendering` 属性来设置纹理采样的质量。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码在一个 `<canvas>` 上使用 WebGPU 进行简单的清屏操作，并将颜色设置为红色。

**假设输入:**

- 一个已创建的 `wgpu::Device` 对象。
- 一个与 `<canvas>` 关联的 `WebGPUSwapBufferProvider` 实例。
- JavaScript 代码执行 WebGPU 命令，请求获取一个用于渲染的纹理 (通过 `swapChain.getCurrentTexture()`)。

**逻辑推理过程:**

1. JavaScript 调用 `swapChain.getCurrentTexture()`。
2. Dawn 内部调用 `WebGPUSwapBufferProvider::GetNewTexture`，请求一个新的纹理。
3. `GetNewTexture` 方法会尝试从 `shared_image_pool_` 中获取一个可用的 `SwapBuffer`。如果池中没有，则创建一个新的 `gpu::ClientSharedImage` 并包装成 `SwapBuffer`。
4. `GetNewTexture` 创建一个 `WebGPUMailboxTexture`，它关联到 `gpu::ClientSharedImage`，并返回给 Dawn。
5. JavaScript 使用返回的纹理进行渲染，将画布清为红色。
6. JavaScript 调用 `swapChain.present()`。
7. Dawn 内部调用 `WebGPUSwapBufferProvider::PrepareTransferableResource`。
8. `PrepareTransferableResource` 方法将当前的 `SwapBuffer` 的 `gpu::ClientSharedImage` 打包成 `viz::TransferableResource`，包含纹理的 mailbox, 同步令牌等信息。
9. 该 `viz::TransferableResource` 被发送到合成器进程。

**预期输出:**

- `PrepareTransferableResource` 方法返回 `true`，表示成功创建了可传输的资源。
- 输出的 `viz::TransferableResource` 包含一个指向包含红色渲染结果的 GPU 纹理的 mailbox。
- 合成器进程接收到该资源后，会使用其包含的纹理信息来更新屏幕上对应 `<canvas>` 元素的显示，最终用户看到 `<canvas>` 区域变为红色。

**用户或编程常见的使用错误 (举例说明):**

1. **纹理尺寸过大:**
   - **错误:** JavaScript 代码请求创建非常大的纹理，超过了 `max_texture_size_` 的限制。
   - **现象:** `GetNewTexture` 方法中的尺寸检查会失败，返回 `nullptr`，导致 WebGPU 渲染失败，可能会抛出错误或导致页面显示异常。
   - **代码示例 (JavaScript):**
     ```javascript
     const texture = device.createTexture({
       size: [8192, 8192], // 假设 max_texture_size_ 小于 8192
       format: 'rgba8unorm',
       usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC,
     });
     ```

2. **不正确的纹理 Usage:**
   - **错误:** 在创建纹理时指定了错误的 `usage` 标志，与 `WebGPUSwapBufferProvider` 的预期不符。
   - **现象:** `GetNewTexture` 方法中的 `DCHECK_EQ(desc.usage, usage_);` 会触发断言失败（在 Debug 构建中），或者导致后续的 WebGPU 操作失败。
   - **代码示例 (JavaScript):**
     ```javascript
     // WebGPUSwapBufferProvider 预期 usage_ 包含 RENDER_ATTACHMENT
     const texture = device.createTexture({
       size: [256, 256],
       format: 'rgba8unorm',
       usage: GPUTextureUsage.COPY_SRC, // 缺少 RENDER_ATTACHMENT
     });
     ```

3. **过早释放 WebGPU 对象:**
   - **错误:** JavaScript 代码过早地销毁了与交换链纹理相关的 WebGPU 对象 (例如 `GPUCommandEncoder`, `GPURenderPassEncoder`)，导致在合成器尝试使用纹理时出现问题。
   - **现象:** 可能导致渲染内容丢失、黑屏或其他图形错误。由于合成是异步的，如果在合成器使用纹理之前就释放了相关的 WebGPU 对象，会导致访问已释放的资源。

4. **未调用 `present()`:**
   - **错误:** JavaScript 代码完成了渲染，但忘记调用 `swapChain.present()` 来提交帧。
   - **现象:** 渲染结果不会显示在屏幕上，因为 `WebGPUSwapBufferProvider::PrepareTransferableResource` 没有被触发，纹理没有被发送到合成器。

5. **在不合适的时机调用方法:**
   - **错误:** 例如，在 `Neuter()` 方法被调用后，尝试继续使用 `WebGPUSwapBufferProvider` 的方法。
   - **现象:**  可能会触发断言失败 (`DCHECK(!neutered_);`) 或者导致程序崩溃，因为资源已经被释放。

总而言之，`webgpu_swap_buffer_provider.cc` 是 Blink 渲染引擎中连接 WebGPU 和 Chromium 合成器的关键纽带，它负责管理渲染缓冲区，并确保 WebGPU 渲染的内容能够正确、高效地显示在屏幕上。 理解其功能有助于理解 WebGPU 在 Chromium 中的渲染流程。

### 提示词
```
这是目录为blink/renderer/platform/graphics/gpu/webgpu_swap_buffer_provider.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_swap_buffer_provider.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "gpu/command_buffer/common/shared_image_usage.h"

namespace blink {

namespace {
viz::SharedImageFormat WGPUFormatToViz(wgpu::TextureFormat format) {
  switch (format) {
    case wgpu::TextureFormat::BGRA8Unorm:
      return viz::SinglePlaneFormat::kBGRA_8888;
    case wgpu::TextureFormat::RGBA8Unorm:
      return viz::SinglePlaneFormat::kRGBA_8888;
    case wgpu::TextureFormat::RGBA16Float:
      return viz::SinglePlaneFormat::kRGBA_F16;
    default:
      NOTREACHED();
  }
}

}  // namespace

WebGPUSwapBufferProvider::WebGPUSwapBufferProvider(
    Client* client,
    scoped_refptr<DawnControlClientHolder> dawn_control_client,
    const wgpu::Device& device,
    wgpu::TextureUsage usage,
    wgpu::TextureUsage internal_usage,
    wgpu::TextureFormat format,
    PredefinedColorSpace color_space,
    const gfx::HDRMetadata& hdr_metadata)
    : dawn_control_client_(dawn_control_client),
      client_(client),
      device_(device),
      shared_image_format_(WGPUFormatToViz(format)),
      format_(format),
      usage_(usage),
      internal_usage_(internal_usage),
      color_space_(color_space),
      hdr_metadata_(hdr_metadata) {
  wgpu::SupportedLimits limits = {};
  auto get_limits_succeeded = device_.GetLimits(&limits);
  CHECK(get_limits_succeeded);

  max_texture_size_ = limits.limits.maxTextureDimension2D;
}

WebGPUSwapBufferProvider::~WebGPUSwapBufferProvider() {
  Neuter();
}

viz::SharedImageFormat WebGPUSwapBufferProvider::Format() const {
  return shared_image_format_;
}

gfx::Size WebGPUSwapBufferProvider::Size() const {
  if (current_swap_buffer_)
    return current_swap_buffer_->GetSharedImage()->size();
  return gfx::Size();
}

cc::Layer* WebGPUSwapBufferProvider::CcLayer() {
  DCHECK(!neutered_);
  return layer_.get();
}

void WebGPUSwapBufferProvider::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (filter_quality != filter_quality_) {
    filter_quality_ = filter_quality;
    if (layer_) {
      layer_->SetNearestNeighbor(filter_quality ==
                                 cc::PaintFlags::FilterQuality::kNone);
    }
  }
}

void WebGPUSwapBufferProvider::ReleaseWGPUTextureAccessIfNeeded() {
  if (!current_swap_buffer_ || !current_swap_buffer_->mailbox_texture) {
    return;
  }

  // The client's lifetime is independent of the swap buffers that can be kept
  // alive longer due to pending shared image callbacks.
  if (client_) {
    client_->OnTextureTransferred();
  }

  current_swap_buffer_->mailbox_texture->Dissociate();
  current_swap_buffer_->mailbox_texture = nullptr;
}

void WebGPUSwapBufferProvider::DiscardCurrentSwapBuffer() {
  if (current_swap_buffer_ && current_swap_buffer_->mailbox_texture) {
    current_swap_buffer_->mailbox_texture->SetNeedsPresent(false);
  }
  ReleaseWGPUTextureAccessIfNeeded();
  current_swap_buffer_ = nullptr;
}

void WebGPUSwapBufferProvider::Neuter() {
  if (neutered_) {
    return;
  }

  if (layer_) {
    layer_->ClearClient();
    layer_ = nullptr;
  }

  DiscardCurrentSwapBuffer();
  client_ = nullptr;
  neutered_ = true;
}

scoped_refptr<WebGPUMailboxTexture> WebGPUSwapBufferProvider::GetNewTexture(
    const wgpu::TextureDescriptor& desc,
    SkAlphaType alpha_mode) {
  DCHECK_EQ(desc.usage, usage_);
  DCHECK_EQ(desc.format, format_);
  DCHECK_EQ(desc.dimension, wgpu::TextureDimension::e2D);
  DCHECK_EQ(desc.size.depthOrArrayLayers, 1u);
  DCHECK_EQ(desc.mipLevelCount, 1u);
  DCHECK_EQ(desc.sampleCount, 1u);

  if (desc.nextInChain) {
    // The internal usage descriptor is the only valid struct to chain.
    CHECK_EQ(desc.nextInChain->sType,
             wgpu::SType::DawnTextureInternalUsageDescriptor);
    CHECK_EQ(desc.nextInChain->nextInChain, nullptr);
    const auto* internal_usage_desc =
        static_cast<const wgpu::DawnTextureInternalUsageDescriptor*>(
            desc.nextInChain);
    DCHECK_EQ(internal_usage_desc->internalUsage, internal_usage_);
  } else {
    DCHECK_EQ(internal_usage_, wgpu::TextureUsage::None);
  }

  auto context_provider = GetContextProviderWeakPtr();
  if (!context_provider) {
    return nullptr;
  }

  gfx::Size size(desc.size.width, desc.size.height);
  if (size.IsEmpty()) {
    return nullptr;
  }

  if (size.width() > max_texture_size_ || size.height() > max_texture_size_) {
    LOG(ERROR) << "GetNewTexture(): invalid size " << size.width() << "x"
               << size.height();
    return nullptr;
  }

  // These SharedImages are read and written by WebGPU clients and can then be
  // sent off to the display compositor.
  gpu::SharedImageUsageSet usage =
      gpu::SHARED_IMAGE_USAGE_WEBGPU_READ |
      gpu::SHARED_IMAGE_USAGE_WEBGPU_WRITE |
      gpu::SHARED_IMAGE_USAGE_WEBGPU_SWAP_CHAIN_TEXTURE |
      GetSharedImageUsagesForDisplay();
  if (usage_ & wgpu::TextureUsage::StorageBinding) {
    usage |= gpu::SHARED_IMAGE_USAGE_WEBGPU_STORAGE_TEXTURE;
  }

  wgpu::AdapterInfo adapter_info;
  device_.GetAdapter().GetInfo(&adapter_info);
  if (adapter_info.adapterType == wgpu::AdapterType::CPU) {
    // When using the fallback adapter, service-side reads and writes of the
    // SharedImage occur via Skia with copies from/to Dawn textures.
    usage |= gpu::SHARED_IMAGE_USAGE_RASTER_READ |
             gpu::SHARED_IMAGE_USAGE_RASTER_WRITE;
  }

  gpu::ImageInfo info = {size,
                         Format(),
                         usage,
                         PredefinedColorSpaceToGfxColorSpace(color_space_),
                         kTopLeft_GrSurfaceOrigin,
                         alpha_mode};

  // Note that if the pool already exists but have different ImageInfo than what
  // is required, we reconfigure the same pool with new ImageInfo instead of
  // deleting old pool and creating a new one. This is required to take
  // advantage of the temporal information the pool might have from its previous
  // use.
  if (!swap_buffer_pool_) {
    swap_buffer_pool_ = gpu::SharedImagePool<SwapBuffer>::Create(
        info, context_provider->ContextProvider()->SharedImageInterface(),
        /*max_pool_size=*/4);
  } else if (swap_buffer_pool_->GetImageInfo() != info) {
    swap_buffer_pool_->Reconfigure(info);
  }

  // Get a swap buffer from pool.
  CHECK(swap_buffer_pool_);
  current_swap_buffer_ = swap_buffer_pool_->GetImage();

  // Make a mailbox texture from the swap buffer.
  // NOTE: Passing WEBGPU_MAILBOX_DISCARD to request clearing requires passing a
  // usage that supports clearing. Swapbuffer textures will always be
  // renderable, so we can pass RenderAttachment.
  current_swap_buffer_->mailbox_texture =
      WebGPUMailboxTexture::FromExistingSharedImage(
          dawn_control_client_, device_, desc,
          current_swap_buffer_->GetSharedImage(),
          // Wait on the last usage of this swap buffer.
          current_swap_buffer_->GetSyncToken(),
          gpu::webgpu::WEBGPU_MAILBOX_DISCARD,
          wgpu::TextureUsage::RenderAttachment,
          // When the mailbox texture is dissociated, set the access finished
          // token back on the swap buffer for the next time it is used.
          base::BindOnce(
              [](scoped_refptr<SwapBuffer> swap_buffer,
                 const gpu::SyncToken& access_finished_token) {
                swap_buffer->SetReleaseSyncToken(access_finished_token);
              },
              current_swap_buffer_));

  if (!layer_) {
    // Create a layer that will be used by the canvas and will ask for a
    // SharedImage each frame.
    layer_ = cc::TextureLayer::CreateForMailbox(this);
    layer_->SetIsDrawable(true);
    layer_->SetFlipped(false);
    layer_->SetNearestNeighbor(filter_quality_ ==
                               cc::PaintFlags::FilterQuality::kNone);
    // TODO(cwallez@chromium.org): These flags aren't taken into account when
    // the layer is promoted to an overlay. Make sure we have fallback /
    // emulation paths to keep the rendering correct in that cases.
    layer_->SetPremultipliedAlpha(true);

    if (client_) {
      client_->SetNeedsCompositingUpdate();
    }
  }

  // When the page request a texture it means we'll need to present it on the
  // next animation frame.
  layer_->SetNeedsDisplay();
  layer_->SetContentsOpaque(alpha_mode == kOpaque_SkAlphaType);
  layer_->SetBlendBackgroundColor(alpha_mode != kOpaque_SkAlphaType);

  return current_swap_buffer_->mailbox_texture;
}
scoped_refptr<WebGPUMailboxTexture>
WebGPUSwapBufferProvider::GetLastWebGPUMailboxTexture() const {
  // It's possible this is called after the canvas context current texture has
  // been destroyed, but `current_swap_buffer_` is still available e.g. when the
  // context is used offscreen only.
  auto latest_swap_buffer =
      current_swap_buffer_ ? current_swap_buffer_ : last_swap_buffer_;
  auto context_provider = GetContextProviderWeakPtr();
  if (!latest_swap_buffer || !context_provider) {
    return nullptr;
  }

  wgpu::DawnTextureInternalUsageDescriptor internal_usage;
  internal_usage.internalUsage = internal_usage_;
  wgpu::TextureDescriptor desc = {
      .nextInChain = &internal_usage,
      .usage = usage_,
      .size = {static_cast<uint32_t>(
                   latest_swap_buffer->GetSharedImage()->size().width()),
               static_cast<uint32_t>(
                   latest_swap_buffer->GetSharedImage()->size().height())},
      .format = format_,
  };

  return WebGPUMailboxTexture::FromExistingSharedImage(
      dawn_control_client_, device_, desc, latest_swap_buffer->GetSharedImage(),
      latest_swap_buffer->GetSyncToken(), gpu::webgpu::WEBGPU_MAILBOX_NONE);
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
WebGPUSwapBufferProvider::GetContextProviderWeakPtr() const {
  return dawn_control_client_->GetContextProviderWeakPtr();
}

bool WebGPUSwapBufferProvider::PrepareTransferableResource(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  DCHECK(!neutered_);
  if (!current_swap_buffer_ || neutered_ || !GetContextProviderWeakPtr()) {
    return false;
  }

  ReleaseWGPUTextureAccessIfNeeded();

  // Populate the output resource.
  uint32_t texture_target =
      current_swap_buffer_->GetSharedImage()->GetTextureTarget();

  *out_resource = viz::TransferableResource::MakeGpu(
      current_swap_buffer_->GetSharedImage(), texture_target,
      current_swap_buffer_->GetSyncToken(),
      current_swap_buffer_->GetSharedImage()->size(), Format(),
      current_swap_buffer_->GetSharedImage()->usage().Has(
          gpu::SHARED_IMAGE_USAGE_SCANOUT),
      viz::TransferableResource::ResourceSource::kWebGPUSwapBuffer);
  out_resource->color_space = PredefinedColorSpaceToGfxColorSpace(color_space_);
  out_resource->hdr_metadata = hdr_metadata_;

  // This holds a ref on the SwapBuffers that will keep it alive until the
  // mailbox is released (and while the release callback is running).
  *out_release_callback =
      WTF::BindOnce(&WebGPUSwapBufferProvider::MailboxReleased,
                    scoped_refptr<WebGPUSwapBufferProvider>(this),
                    std::move(current_swap_buffer_));

  return true;
}

bool WebGPUSwapBufferProvider::CopyToVideoFrame(
    WebGraphicsContext3DVideoFramePool* frame_pool,
    SourceDrawingBuffer src_buffer,
    const gfx::ColorSpace& dst_color_space,
    WebGraphicsContext3DVideoFramePool::FrameReadyCallback callback) {
  DCHECK(!neutered_);
  if (!current_swap_buffer_ || neutered_ || !GetContextProviderWeakPtr()) {
    return false;
  }

  DCHECK(frame_pool);

  auto* frame_pool_ri = frame_pool->GetRasterInterface();
  DCHECK(frame_pool_ri);

  // Copy kFrontBuffer to a video frame is not supported
  DCHECK_EQ(src_buffer, kBackBuffer);

  // For a conversion from swap buffer's texture to video frame, we do it
  // using WebGraphicsContext3DVideoFramePool's graphics context. Thus, we
  // need to release WebGPU/Dawn's context's access to the texture.
  ReleaseWGPUTextureAccessIfNeeded();

  if (frame_pool->CopyRGBATextureToVideoFrame(
          current_swap_buffer_->GetSharedImage()->size(),
          current_swap_buffer_->GetSharedImage(),
          current_swap_buffer_->GetSyncToken(), dst_color_space,
          std::move(callback))) {
    // Subsequent access to this swap buffer (either webgpu or compositor) must
    // wait for the copy operation to finish.
    gpu::SyncToken sync_token;
    frame_pool_ri->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());
    current_swap_buffer_->SetReleaseSyncToken(std::move(sync_token));
    return true;
  }
  return false;
}

void WebGPUSwapBufferProvider::MailboxReleased(
    scoped_refptr<SwapBuffer> swap_buffer,
    const gpu::SyncToken& sync_token,
    bool lost_resource) {
  // Update the SyncToken to ensure that we will wait for it even if we
  // immediately destroy this buffer.
  swap_buffer->SetReleaseSyncToken(sync_token);

  if (lost_resource)
    return;

  if (last_swap_buffer_) {
    swap_buffer_pool_->ReleaseImage(std::move(last_swap_buffer_));
  }

  last_swap_buffer_ = std::move(swap_buffer);
}

WebGPUSwapBufferProvider::SwapBuffer::SwapBuffer(
    scoped_refptr<gpu::ClientSharedImage> shared_image)
    : ClientImage(std::move(shared_image)) {}

WebGPUSwapBufferProvider::SwapBuffer::~SwapBuffer() = default;

gpu::SharedImageUsageSet
WebGPUSwapBufferProvider::GetSharedImageUsagesForDisplay() {
#if BUILDFLAG(IS_MAC)
  // On Mac it is safe to allow SharedImages created with WebGPU usage that will
  // be sent to the display to be used as overlays, as specifying WebGPU usage
  // when creating a SharedImage forces that SharedImage to be backed by an
  // IOSurface.
  return gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;
#else
  // On other platforms we cannot assume and do not require that a SharedImage
  // created with WebGPU usage be backed by a native buffer.
  return gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
#endif
}

scoped_refptr<gpu::ClientSharedImage>
WebGPUSwapBufferProvider::GetCurrentSharedImage() {
  return current_swap_buffer_ ? current_swap_buffer_->GetSharedImage()
                              : nullptr;
}

gpu::Mailbox WebGPUSwapBufferProvider::GetCurrentMailboxForTesting() const {
  DCHECK(current_swap_buffer_);
  DCHECK(current_swap_buffer_->GetSharedImage());
  return current_swap_buffer_->GetSharedImage()->mailbox();
}
}  // namespace blink
```