Response:
My thinking process to answer the request about `drawing_buffer.cc` went something like this:

1. **Understand the Core Purpose:** The filename `drawing_buffer.cc` immediately suggests its primary function: managing the buffer where rendering happens for WebGL. Keywords like "GPU," "graphics," and "renderer" reinforce this. The mention of `blink` points to its role in the Chromium rendering engine.

2. **Break Down the Code Snippet:** I scanned the provided code for key functionalities and patterns. I looked for:
    * **Function Names:**  `ResolveIfNeeded`, `ReallocateMultisampleRenderbuffer`, `PaintRenderingResultsToDataArray`, `ReadBackFramebuffer`, `ResolveAndPresentSwapChainIfNeeded`, `CreateColorBuffer`, `AttachColorBufferToReadFramebuffer`, `Bind`. These names are very descriptive and hint at the actions the code performs.
    * **Variables:** `fbo_`, `multisample_fbo_`, `back_color_buffer_`, `front_color_buffer_`, `staging_texture_`, `size_`, `sample_count_`, `gl_`. These variables give clues about what data the class manages (framebuffers, textures, size, etc.). The `gl_` clearly indicates OpenGL interaction.
    * **Conditional Logic (if/else):**  The presence of `if (WantExplicitResolve())`, `if (using_swap_chain_)`, `if (ShouldUseChromiumImage())` and GPU switch detection suggests branching logic based on different rendering configurations and platform specifics.
    * **OpenGL Calls:**  `gl_->BindFramebuffer`, `gl_->RenderbufferStorageMultisampleCHROMIUM`, `gl_->ReadPixels`, `gl_->CopySubTextureCHROMIUM`, etc., directly point to the interaction with the OpenGL API.
    * **SharedImageInterface:** The frequent use of `ContextProvider()->SharedImageInterface()` highlights the management of shared GPU resources, crucial for inter-process communication and efficient rendering.
    * **Error Handling:** The check for `gl_->GetError() == GL_OUT_OF_MEMORY` indicates attention to potential issues.
    * **macOS Specific Code:** The comments about GPU switching on macOS stand out as platform-specific behavior.
    * **Feature Flags:**  `RuntimeEnabledFeatures::WebGLDrawingBufferStorageEnabled()` and `base::FeatureList::IsEnabled(features::kLowLatencyWebGLImageChromium)` show how the functionality can be controlled by feature flags.

3. **Categorize Functionalities:** Based on the code analysis, I grouped the functionalities into logical categories:
    * **Framebuffer Management:**  Creating, binding, discarding framebuffers (including multisampling).
    * **Multisampling (Anti-aliasing):** Handling different multisampling modes (explicit and implicit resolve), allocating multisample renderbuffers.
    * **Rendering Results Readback:** Functions for reading pixel data from the framebuffer.
    * **Swap Chain Management:**  Presenting and managing swap chains for efficient rendering.
    * **Color Buffer Management:** Creating and attaching color buffers (backed by SharedImages).
    * **State Management:**  Restoring OpenGL state.
    * **GPU Switching Handling:**  Specifically addressing GPU switching on macOS.
    * **Feature Flags:** Controlling certain behaviors with feature flags.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  I connected the low-level drawing buffer operations to their high-level counterparts in web technologies:
    * **JavaScript/WebGL:** The primary consumer of `DrawingBuffer`. WebGL API calls directly translate to operations on this buffer. Drawing commands in JavaScript end up manipulating this buffer.
    * **HTML `<canvas>`:** The element where WebGL rendering takes place. The `DrawingBuffer` is intrinsically linked to the `<canvas>` element when a WebGL context is created.
    * **CSS:** Indirectly related. CSS styling affects the size and layout of the `<canvas>` element, which in turn influences the dimensions of the `DrawingBuffer`. CSS properties like `opacity` might trigger the need for alpha blending handled by the buffer.

5. **Construct Examples:** For each relationship with web technologies, I devised simple, illustrative examples demonstrating the connection.

6. **Consider Logic and Assumptions:** I examined the code for logical branches and made assumptions about the inputs and outputs. For instance, when `WantExplicitResolve()` is true, the output is written to `multisample_fbo_` initially.

7. **Identify Potential Errors:** I looked for patterns that could lead to common user or programming errors:
    * **Context Loss:** The code explicitly handles context loss scenarios.
    * **Incorrect State Management:** The `ScopedStateRestorer` is a mechanism to prevent errors related to incorrect OpenGL state.
    * **Resource Exhaustion:** The check for `GL_OUT_OF_MEMORY` highlights a potential error case.
    * **Premultiplied Alpha Issues:** The logic around `requested_alpha_type_` and `staging_texture_needed_` points to complexities in handling alpha blending correctly.

8. **Summarize the Functionality:** Finally, I synthesized a concise summary of the `DrawingBuffer`'s role, emphasizing its core responsibility in managing the rendering target for WebGL within the Blink rendering engine.

By following these steps, I could systematically analyze the provided code snippet and generate a comprehensive and informative response addressing all aspects of the user's request. The iterative process of breaking down the code, categorizing functionalities, and then connecting them to higher-level concepts and potential issues is key to understanding complex systems like a rendering engine component.
这是 `blink/renderer/platform/graphics/gpu/drawing_buffer.cc` 文件的第 3 部分，在之前的两个部分中，我们已经了解了 `DrawingBuffer` 类的主要功能是管理用于 WebGL 渲染的帧缓冲区。现在，让我们总结一下这部分代码的功能，并结合之前的理解进行归纳。

**本部分代码的功能归纳:**

这部分代码主要集中在以下几个方面：

1. **读取渲染结果:**  提供了将渲染结果从帧缓冲区读取到内存（`SkData`）的方法 `PaintRenderingResultsToDataArray` 和 `ReadBackFramebuffer`。这使得可以将渲染的内容用于其他目的，例如保存为图片或进行进一步处理。
2. **处理渲染结果的 Alpha 通道:** `ReadBackFramebuffer` 方法中包含了对读取到的像素数据进行 Alpha 预乘处理的逻辑。
3. **处理 Swap Chain 和前后缓冲区:** 实现了 `ResolveAndPresentSwapChainIfNeeded` 方法，用于处理使用 Swap Chain 的渲染流程。这包括解决多重采样、将后台缓冲区的内容复制到前台缓冲区以进行显示。
4. **创建和管理 Color Buffer:** 提供了 `CreateColorBuffer` 方法，用于创建用于渲染的颜色缓冲区，并考虑了 SharedImage 的使用，以实现更高效的资源共享和跨进程通信。
5. **将 Color Buffer 附加到帧缓冲区:** `AttachColorBufferToReadFramebuffer` 方法负责将创建的颜色缓冲区附加到用于读取的帧缓冲区。
6. **判断是否需要显式解决多重采样:** `WantExplicitResolve` 方法用于判断当前的抗锯齿模式是否需要显式地解决多重采样。
7. **判断是否需要深度或模板缓冲区:** `WantDepthOrStencil` 方法用于判断是否需要深度或模板缓冲区。
8. **ScopedStateRestorer 类:** 定义了一个内部类 `ScopedStateRestorer`，用于在执行操作前后保存和恢复 OpenGL 状态，以避免状态污染。
9. **判断是否应该使用 ChromiumImage:** `ShouldUseChromiumImage` 方法用于判断是否应该使用 ChromiumImage 作为颜色缓冲区的后端。

**结合前两部分进行整体功能归纳:**

综合来看，`DrawingBuffer` 类在 Blink 渲染引擎中扮演着核心角色，其主要功能可以归纳为：

* **帧缓冲区管理:**  负责创建、绑定、配置和管理用于 WebGL 渲染的帧缓冲区对象（FBO），包括默认帧缓冲区和用于多重采样的帧缓冲区。
* **多重采样抗锯齿支持:**  支持多种多重采样模式，并提供了解决多重采样的功能，以提升渲染质量。
* **后台缓冲区管理:**  管理用于渲染的后台颜色缓冲区，可能使用纹理或 SharedImage 作为其存储。
* **前台缓冲区管理 (Swap Chain):**  在启用 Swap Chain 的情况下，管理用于显示的颜色缓冲区。
* **深度和模板缓冲区管理:**  根据需要创建和管理深度和模板缓冲区。
* **渲染结果读取:**  提供将渲染结果读取回内存的功能，支持不同的像素格式和 Alpha 处理方式。
* **状态管理:**  通过 `ScopedStateRestorer` 管理 OpenGL 状态，确保操作的正确性。
* **GPU 切换处理:**  处理 macOS 等平台上 GPU 切换的情况，并采取必要的措施以避免渲染错误，例如重新分配资源或强制上下文丢失。
* **SharedImage 集成:**  利用 `gpu::SharedImageInterface` 创建和管理 GPU 共享内存中的纹理，以提高性能和实现跨进程共享。
* **平台和功能特性适配:**  根据不同的平台和功能特性（例如是否启用 Swap Chain、是否支持 ChromiumImage 等）采取不同的处理逻辑。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript/WebGL:** `DrawingBuffer` 是 WebGL API 的底层实现基础。当 JavaScript 代码调用 WebGL 的绘图命令（如 `gl.drawArrays()`, `gl.drawElements()`）时，最终的渲染结果会被写入到 `DrawingBuffer` 管理的帧缓冲区中。
    * **假设输入:** JavaScript 代码执行 `gl.clearColor(1, 0, 0, 1); gl.clear(gl.COLOR_BUFFER_BIT);`
    * **输出:** `DrawingBuffer` 对应的帧缓冲区的颜色会被清除为红色。
* **HTML `<canvas>`:**  `DrawingBuffer` 与 `<canvas>` 元素紧密关联。当在 `<canvas>` 上创建 WebGL 渲染上下文时，`DrawingBuffer` 会被创建并与该上下文关联。
    * **假设输入:** 一个 HTML 页面包含 `<canvas id="myCanvas" width="500" height="300"></canvas>`，并且 JavaScript 代码获取该 canvas 并创建 WebGL 上下文。
    * **输出:**  `DrawingBuffer` 会被创建，其大小通常会根据 canvas 的 `width` 和 `height` 属性进行初始化。
* **CSS:** CSS 可以影响 `<canvas>` 元素的大小和布局，从而间接地影响 `DrawingBuffer` 的尺寸。例如，通过 CSS 设置 canvas 的 `width` 和 `height` 会导致 `DrawingBuffer` 需要重新分配内存。
    * **假设输入:** CSS 样式设置 `#myCanvas { width: 800px; height: 600px; }`。
    * **输出:** 如果 WebGL 上下文已经创建，并且 `DrawingBuffer` 的尺寸与之前的 canvas 尺寸不一致，则可能需要重新分配 `DrawingBuffer` 的内存。

**用户或编程常见的使用错误举例:**

* **在上下文丢失后继续使用 DrawingBuffer:**  WebGL 上下文可能会因为各种原因丢失（例如 GPU 驱动崩溃、资源耗尽等）。在上下文丢失后，尝试继续调用与 `DrawingBuffer` 相关的操作会导致错误。
    * **错误示例 (JavaScript):**
      ```javascript
      const gl = canvas.getContext('webgl');
      // ... 一些渲染操作 ...
      gl.getExtension('WEBGL_lose_context').loseContext(); // 模拟上下文丢失
      gl.clearColor(0, 0, 1, 1); // 在上下文丢失后尝试操作
      ```
    * **后果:**  可能会抛出异常或产生未定义的行为。正确的做法是在上下文丢失事件发生后，重新获取上下文并重新初始化资源。
* **不匹配的帧缓冲区绑定:**  在执行 OpenGL 操作时，需要确保当前绑定的帧缓冲区是期望的目标。如果绑定了错误的帧缓冲区，渲染结果可能会输出到错误的位置。
    * **错误示例 (C++ 逻辑推断):**  假设 `WantExplicitResolve()` 返回 `true`，但代码错误地绑定了 `fbo_` 而不是 `multisample_fbo_` 来进行渲染。
    * **后果:**  多重采样效果可能不会生效，或者渲染结果会丢失。
* **未正确处理 Alpha 预乘:**  在读取渲染结果时，如果没有正确处理 Alpha 预乘，可能会导致颜色显示不正确。
    * **错误示例 (假设用户期望读取未预乘的 RGBA 数据，但未进行相应的处理):**  调用 `ReadBackFramebuffer` 后，直接将数据用于创建图片，而没有考虑可能需要进行反预乘操作。
    * **后果:**  透明度会受到颜色值的影响，导致半透明区域颜色偏暗。

**总结:**

`blink/renderer/platform/graphics/gpu/drawing_buffer.cc` 的这部分代码，连同之前的部分，共同实现了 WebGL 渲染管线中至关重要的帧缓冲区管理和渲染结果处理功能。它连接了底层的 OpenGL API 和上层的 WebGL API，并负责处理各种复杂的渲染场景和平台特性，确保 WebGL 内容能够正确且高效地渲染到屏幕上。理解 `DrawingBuffer` 的工作原理对于深入理解 WebGL 的渲染机制至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/drawing_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
      state_restorer_->SetFramebufferBindingDirty();
      gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
      gl_->DiscardFramebufferEXT(GL_FRAMEBUFFER, 2, kAttachments);
      transient_framebuffers_discarded_ = true;
    }
    if (!contents_change_resolved_) {
      ResolveMultisampleFramebufferInternal();
    }
  }
  contents_change_resolved_ = true;

  auto* gl = ContextProvider()->ContextGL();
  gl::GpuPreference active_gpu = gl::GpuPreference::kDefault;
  if (gl->DidGpuSwitch(&active_gpu) == GL_TRUE) {
    // This code path is mainly taken on macOS (the only platform which, as of
    // this writing, dispatches the GPU-switched notifications), and the
    // comments below focus only on macOS.
    //
    // The code below attempts to deduce whether, if a GPU switch occurred,
    // it's really necessary to lose the context because certain GPU resources
    // are no longer accessible. Resources only become inaccessible if
    // CGLSetVirtualScreen is explicitly called against a GL context to change
    // its renderer ID. GPU switching notifications are highly asynchronous.
    //
    // The tests below, of the initial and currently active GPU, replicate
    // some logic in GLContextCGL::ForceGpuSwitchIfNeeded. Basically, if a
    // context requests the high-performance GPU, then CGLSetVirtualScreen
    // will never be called to migrate that context to the low-power
    // GPU. However, contexts that were allocated on the integrated GPU will
    // be migrated to the discrete GPU, and back, when the discrete GPU is
    // activated and deactivated. Also, if the high-performance GPU was
    // requested, then that request took effect during context bringup, even
    // though the GPU switching notification is generally dispatched a couple
    // of seconds after that, so it's not necessary to either lose the context
    // or reallocate the multisampled renderbuffers when that initial
    // notification is received.
    if (initial_gpu_ == gl::GpuPreference::kLowPower &&
        current_active_gpu_ != active_gpu) {
      if ((WantExplicitResolve() && preserve_drawing_buffer_ == kPreserve) ||
          client_
              ->DrawingBufferClientUserAllocatedMultisampledRenderbuffers()) {
        // In these situations there are multisampled renderbuffers whose
        // content the application expects to be preserved, but which can not
        // be. Forcing a lost context is the only option to keep applications
        // rendering correctly.
        client_->DrawingBufferClientForceLostContextWithAutoRecovery(
            "Losing WebGL context because multisampled renderbuffers were "
            "allocated, to work around macOS OpenGL driver bugs");
      } else if (WantExplicitResolve()) {
        ReallocateMultisampleRenderbuffer(size_);

        // This does a bit more work than desired - clearing any depth and
        // stencil renderbuffers is unnecessary, since they weren't reallocated
        // - but reusing this code reduces complexity. Note that we do not clear
        // the non-multisampled framebuffer, as doing so can cause users'
        // content to disappear unexpectedly.
        //
        // TODO(crbug.com/1046146): perform this clear at the beginning rather
        // than at the end of a frame in order to eliminate rendering glitches.
        // This should also simplify the code, allowing removal of the
        // ClearOption.
        ClearNewlyAllocatedFramebuffers(kClearOnlyMultisampledFBO);
      }
    }
    current_active_gpu_ = active_gpu;
  }
}

bool DrawingBuffer::ReallocateMultisampleRenderbuffer(const gfx::Size& size) {
  state_restorer_->SetFramebufferBindingDirty();
  state_restorer_->SetRenderbufferBindingDirty();
  gl_->BindFramebuffer(GL_FRAMEBUFFER, multisample_fbo_);
  gl_->BindRenderbuffer(GL_RENDERBUFFER, multisample_renderbuffer_);

  // Note that the multisample rendertarget will allocate an alpha channel
  // based on the ColorBuffer's format, since it will resolve into the
  // ColorBuffer.
  GLenum internal_format = requested_format_;
  if (requested_format_ == GL_RGB8) {
    internal_format = color_buffer_format_.HasAlpha() ? GL_RGBA8 : GL_RGB8;
  }

  if (has_eqaa_support) {
    gl_->RenderbufferStorageMultisampleAdvancedAMD(
        GL_RENDERBUFFER, sample_count_, eqaa_storage_sample_count_,
        internal_format, size.width(), size.height());
  } else {
    gl_->RenderbufferStorageMultisampleCHROMIUM(GL_RENDERBUFFER, sample_count_,
                                                internal_format, size.width(),
                                                size.height());
  }

  if (gl_->GetError() == GL_OUT_OF_MEMORY)
    return false;

  gl_->FramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_RENDERBUFFER, multisample_renderbuffer_);
  return true;
}

void DrawingBuffer::RestoreFramebufferBindings() {
  // Can be called with ScopedDrawingBufferBinder on the stack after
  // context loss. Null checking client_ is insufficient.
  if (destruction_in_progress_) {
    return;
  }
  client_->DrawingBufferClientRestoreFramebufferBinding();
}

void DrawingBuffer::RestoreAllState() {
  client_->DrawingBufferClientRestoreScissorTest();
  client_->DrawingBufferClientRestoreMaskAndClearValues();
  client_->DrawingBufferClientRestorePixelPackParameters();
  client_->DrawingBufferClientRestoreTexture2DBinding();
  client_->DrawingBufferClientRestoreTextureCubeMapBinding();
  client_->DrawingBufferClientRestoreRenderbufferBinding();
  client_->DrawingBufferClientRestoreFramebufferBinding();
  client_->DrawingBufferClientRestorePixelUnpackBufferBinding();
  client_->DrawingBufferClientRestorePixelPackBufferBinding();
}

bool DrawingBuffer::Multisample() const {
  return anti_aliasing_mode_ != kAntialiasingModeNone;
}

void DrawingBuffer::Bind(GLenum target) {
  gl_->BindFramebuffer(target, WantExplicitResolve() ? multisample_fbo_ : fbo_);
}

GLenum DrawingBuffer::StorageFormat() const {
  return requested_format_;
}

sk_sp<SkData> DrawingBuffer::PaintRenderingResultsToDataArray(
    SourceDrawingBuffer source_buffer) {
  ScopedStateRestorer scoped_state_restorer(this);

  // Readback in native GL byte order (RGBA).
  SkColorType color_type = kRGBA_8888_SkColorType;
  base::CheckedNumeric<size_t> row_bytes = 4;
  if (RuntimeEnabledFeatures::WebGLDrawingBufferStorageEnabled() &&
      back_color_buffer_->format == viz::SinglePlaneFormat::kRGBA_F16) {
    color_type = kRGBA_F16_SkColorType;
    row_bytes *= 2;
  }
  row_bytes *= Size().width();

  base::CheckedNumeric<size_t> num_rows = Size().height();
  base::CheckedNumeric<size_t> data_size = num_rows * row_bytes;
  if (!data_size.IsValid())
    return nullptr;

  sk_sp<SkData> dst_buffer = TryAllocateSkData(data_size.ValueOrDie());
  if (!dst_buffer)
    return nullptr;

  GLuint fbo = 0;
  state_restorer_->SetFramebufferBindingDirty();
  if (source_buffer == kFrontBuffer && front_color_buffer_) {
    gl_->GenFramebuffers(1, &fbo);
    gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo);
    front_color_buffer_->BeginAccess(gpu::SyncToken(), /*readonly=*/true);
    gl_->FramebufferTexture2D(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        front_color_buffer_->shared_image->GetTextureTarget(),
        front_color_buffer_->texture_id(), 0);
  } else {
    gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
  }

  auto pixels = base::span<uint8_t>(
      static_cast<uint8_t*>(dst_buffer->writable_data()), dst_buffer->size());
  ReadBackFramebuffer(pixels, color_type,
                      WebGLImageConversion::kAlphaDoNothing);
  FlipVertically(pixels, num_rows.ValueOrDie(), row_bytes.ValueOrDie());

  if (fbo) {
    // The front buffer was used as the source of the pixels via |fbo|; clean up
    // |fbo| and release access to the front buffer's SharedImage now that the
    // readback is finished.
    gl_->FramebufferTexture2D(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        front_color_buffer_->shared_image->GetTextureTarget(), 0, 0);
    gl_->DeleteFramebuffers(1, &fbo);
    front_color_buffer_->EndAccess();
  }

  return dst_buffer;
}

void DrawingBuffer::ReadBackFramebuffer(base::span<uint8_t> pixels,
                                        SkColorType color_type,
                                        WebGLImageConversion::AlphaOp op) {
  DCHECK(state_restorer_);
  state_restorer_->SetPixelPackParametersDirty();
  gl_->PixelStorei(GL_PACK_ALIGNMENT, 1);
  if (webgl_version_ > kWebGL1) {
    gl_->PixelStorei(GL_PACK_SKIP_ROWS, 0);
    gl_->PixelStorei(GL_PACK_SKIP_PIXELS, 0);
    gl_->PixelStorei(GL_PACK_ROW_LENGTH, 0);

    state_restorer_->SetPixelPackBufferBindingDirty();
    gl_->BindBuffer(GL_PIXEL_PACK_BUFFER, 0);
  }

  GLenum data_type = GL_UNSIGNED_BYTE;

  base::CheckedNumeric<size_t> expected_data_size = 4;
  expected_data_size *= Size().width();
  expected_data_size *= Size().height();

  if (RuntimeEnabledFeatures::WebGLDrawingBufferStorageEnabled() &&
      color_type == kRGBA_F16_SkColorType) {
    data_type = (webgl_version_ > kWebGL1) ? GL_HALF_FLOAT : GL_HALF_FLOAT_OES;
    expected_data_size *= 2;
  }

  DCHECK_EQ(expected_data_size.ValueOrDie(), pixels.size());

  gl_->ReadPixels(0, 0, Size().width(), Size().height(), GL_RGBA, data_type,
                  pixels.data());

  // For half float storage Skia order is RGBA, hence no swizzling is needed.
  if (color_type == kBGRA_8888_SkColorType) {
    // Swizzle red and blue channels to match SkBitmap's byte ordering.
    // TODO(kbr): expose GL_BGRA as extension.
    for (size_t i = 0; i < pixels.size(); i += 4) {
      std::swap(pixels[i], pixels[i + 2]);
    }
  }

  if (op == WebGLImageConversion::kAlphaDoPremultiply) {
    for (size_t i = 0; i < pixels.size(); i += 4) {
      uint8_t alpha = pixels[i + 3];
      for (size_t j = 0; j < 3; j++)
        pixels[i + j] = (pixels[i + j] * alpha + 127) / 255;
    }
  } else if (op != WebGLImageConversion::kAlphaDoNothing) {
    NOTREACHED();
  }
}

void DrawingBuffer::ResolveAndPresentSwapChainIfNeeded() {
  if (!contents_changed_)
    return;

  ScopedStateRestorer scoped_state_restorer(this);
  ResolveIfNeeded(kDiscardAllowed);

  if (!using_swap_chain_) {
    return;
  }

  CopyStagingTextureToBackColorBufferIfNeeded();
  gpu::SyncToken sync_token;
  gl_->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());

  auto* sii = ContextProvider()->SharedImageInterface();
  sii->PresentSwapChain(sync_token,
                        back_color_buffer_->shared_image->mailbox());

  sync_token = sii->GenUnverifiedSyncToken();
  gl_->WaitSyncTokenCHROMIUM(sync_token.GetConstData());

  // If a multisample fbo is used it already preserves the previous contents.
  if (preserve_drawing_buffer_ == kPreserve && !WantExplicitResolve()) {
    // If premultiply alpha is false rendering results are in
    // |staging_texture_|.
    GLenum dest_texture_target =
        staging_texture_ ? GL_TEXTURE_2D
                         : back_color_buffer_->shared_image->GetTextureTarget();
    GLuint dest_texture_id =
        staging_texture_ ? staging_texture_ : back_color_buffer_->texture_id();
    front_color_buffer_->BeginAccess(gpu::SyncToken(), /*readonly=*/true);
    ;
    gl_->CopySubTextureCHROMIUM(front_color_buffer_->texture_id(), 0,
                                dest_texture_target, dest_texture_id, 0, 0, 0,
                                0, 0, size_.width(), size_.height(), GL_FALSE,
                                GL_FALSE, GL_FALSE);
    front_color_buffer_->EndAccess();
  }
  contents_changed_ = false;
  if (preserve_drawing_buffer_ == kDiscard) {
    SetBufferClearNeeded(true);
  }
}

scoped_refptr<DrawingBuffer::ColorBuffer> DrawingBuffer::CreateColorBuffer(
    const gfx::Size& size) {
  if (size.IsEmpty()) {
    // Context is likely lost.
    return nullptr;
  }

  DCHECK(state_restorer_);
  state_restorer_->SetFramebufferBindingDirty();
  state_restorer_->SetTextureBindingDirty();

  gpu::SharedImageInterface* sii = ContextProvider()->SharedImageInterface();

  scoped_refptr<gpu::ClientSharedImage> back_buffer_shared_image;
  // Set only when using swap chains.
  scoped_refptr<gpu::ClientSharedImage> front_buffer_shared_image;
  GLenum texture_target = GL_TEXTURE_2D;
  bool created_mappable_si = false;

  // The SharedImages created here are read to and written from by WebGL. They
  // may also be read via the raster interface for WebGL->video and/or
  // WebGL->canvas conversions.
  gpu::SharedImageUsageSet usage = gpu::SHARED_IMAGE_USAGE_GLES2_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_WRITE |
                                   gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_READ;
  if (initial_gpu_ == gl::GpuPreference::kHighPerformance)
    usage |= gpu::SHARED_IMAGE_USAGE_HIGH_PERFORMANCE_GPU;
  GrSurfaceOrigin origin = opengl_flip_y_extension_
                               ? kTopLeft_GrSurfaceOrigin
                               : kBottomLeft_GrSurfaceOrigin;

#if BUILDFLAG(IS_MAC)
  // For Mac, explicitly specify BGRA/X instead of RGBA/X so that IOSurface
  // format matches shared image format. This is necessary for Graphite where
  // IOSurfaces are always used to allow sharing between ANGLE and Dawn.
  if (color_buffer_format_ == viz::SinglePlaneFormat::kRGBA_8888 &&
      gpu::IsImageFromGpuMemoryBufferFormatSupported(
          gfx::BufferFormat::BGRA_8888, ContextProvider()->GetCapabilities())) {
    color_buffer_format_ = viz::SinglePlaneFormat::kBGRA_8888;
  } else if (color_buffer_format_ == viz::SinglePlaneFormat::kRGBX_8888 &&
             gpu::IsImageFromGpuMemoryBufferFormatSupported(
                 gfx::BufferFormat::BGRX_8888,
                 ContextProvider()->GetCapabilities())) {
    color_buffer_format_ = viz::SinglePlaneFormat::kBGRX_8888;
  }
#endif  // BUILDFLAG(IS_MAC)

  SkAlphaType back_buffer_alpha_type = kPremul_SkAlphaType;
  if (using_swap_chain_) {
    gpu::SharedImageInterface::SwapChainSharedImages shared_images =
        sii->CreateSwapChain(
            color_buffer_format_, size, color_space_, origin,
            back_buffer_alpha_type,
            gpu::SharedImageUsageSet(usage | gpu::SHARED_IMAGE_USAGE_SCANOUT));
    back_buffer_shared_image = std::move(shared_images.back_buffer);
    front_buffer_shared_image = std::move(shared_images.front_buffer);
  } else {
    if (ShouldUseChromiumImage()) {
#if !BUILDFLAG(IS_ANDROID)
      // Android's SharedImage backing for ChromiumImage does not support BGRX.

      // TODO(b/286417069): BGRX has issues when Vulkan is used for raster and
      // composite. Using BGRX is technically possible but will require a lot
      // of work given the current state of the codebase. There are projects in
      // flight that will make using BGRX a lot easier, but until then, simply
      // use RGBX when Vulkan is enabled.
      const auto& gpu_feature_info = ContextProvider()->GetGpuFeatureInfo();
      const bool allow_bgrx =
          gpu_feature_info.status_values[gpu::GPU_FEATURE_TYPE_VULKAN] !=
          gpu::kGpuFeatureStatusEnabled;

      // For ChromeOS explicitly specify BGRX instead of RGBX since some older
      // Intel GPUs (i8xx) don't support RGBX overlays.
      if (color_buffer_format_ == viz::SinglePlaneFormat::kRGBX_8888 &&
          allow_bgrx &&
          gpu::IsImageFromGpuMemoryBufferFormatSupported(
              gfx::BufferFormat::BGRX_8888,
              ContextProvider()->GetCapabilities())) {
        color_buffer_format_ = viz::SinglePlaneFormat::kBGRX_8888;
      }
#endif  // !BUILDFLAG(IS_ANDROID)

      // TODO(crbug.com/911176): When RGB emulation is not needed, we should use
      // the non-GMB CreateSharedImage with gpu::SHARED_IMAGE_USAGE_SCANOUT in
      // order to allocate the GMB service-side and avoid a synchronous
      // round-trip to the browser process here.
      gpu::SharedImageUsageSet additional_usage_flags =
          gpu::SHARED_IMAGE_USAGE_SCANOUT;
      if (low_latency_enabled()) {
        additional_usage_flags |= gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;
      }

      if (gpu::IsImageFromGpuMemoryBufferFormatSupported(
              viz::SinglePlaneSharedImageFormatToBufferFormat(
                  color_buffer_format_),
              ContextProvider()->GetCapabilities())) {
        auto client_shared_image = sii->CreateSharedImage(
            {color_buffer_format_, size, color_space_, origin,
             back_buffer_alpha_type,
             gpu::SharedImageUsageSet(usage | additional_usage_flags),
             "WebGLDrawingBuffer"},
            gpu::kNullSurfaceHandle);
        if (client_shared_image) {
          created_mappable_si = true;
          back_buffer_shared_image = std::move(client_shared_image);
          texture_target = back_buffer_shared_image->GetTextureTarget();
        }
      }
    }

    // Create a normal SharedImage if Mappable SharedImage is not needed or the
    // allocation above failed.
    if (!created_mappable_si) {
      // We want to set the correct SkAlphaType on the new shared image but in
      // the case of ShouldUseChromiumImage() we instead keep this buffer
      // premultiplied, draw to |premultiplied_alpha_false_mailbox_|, and
      // convert during copy.
      if (requested_alpha_type_ == kUnpremul_SkAlphaType) {
        back_buffer_alpha_type = kUnpremul_SkAlphaType;
      }

      back_buffer_shared_image = sii->CreateSharedImage(
          {color_buffer_format_, size, color_space_, origin,
           back_buffer_alpha_type, gpu::SharedImageUsageSet(usage),
           "WebGLDrawingBuffer"},
          gpu::kNullSurfaceHandle);
      CHECK(back_buffer_shared_image);
    }
  }

  staging_texture_needed_ = false;
  if (requested_alpha_type_ == kUnpremul_SkAlphaType &&
      requested_alpha_type_ != back_buffer_alpha_type) {
    // If it was requested that our format be unpremultiplied, but the
    // backbuffer that we will use for compositing will be premultiplied (e.g,
    // because it be used as an overlay), then we will need to create a separate
    // unpremultiplied staging backbuffer for WebGL to render to.
    staging_texture_needed_ = true;
  }
  if (requested_format_ == GL_SRGB8_ALPHA8) {
    // SharedImages do not support sRGB texture formats, so a staging texture is
    // always needed for them.
    staging_texture_needed_ = true;
  }

  if (front_buffer_shared_image) {
    DCHECK(using_swap_chain_);
    // Import frontbuffer of swap chain into GL.
    std::unique_ptr<gpu::SharedImageTexture> si_texture =
        front_buffer_shared_image->CreateGLTexture(gl_);
    front_color_buffer_ = base::MakeRefCounted<ColorBuffer>(
        weak_factory_.GetWeakPtr(), size, color_space_, color_buffer_format_,
        back_buffer_alpha_type,
        /*is_overlay_candidate=*/true, std::move(front_buffer_shared_image),
        std::move(si_texture));
  }

  // Import the backbuffer of swap chain or allocated SharedImage into GL.
  std::unique_ptr<gpu::SharedImageTexture> si_texture =
      back_buffer_shared_image->CreateGLTexture(gl_);
  const bool is_overlay_candidate = created_mappable_si || using_swap_chain_;
  scoped_refptr<DrawingBuffer::ColorBuffer> color_buffer =
      base::MakeRefCounted<ColorBuffer>(
          weak_factory_.GetWeakPtr(), size, color_space_, color_buffer_format_,
          back_buffer_alpha_type, is_overlay_candidate,
          std::move(back_buffer_shared_image), std::move(si_texture));
  color_buffer->BeginAccess(gpu::SyncToken(), /*readonly=*/false);
  gl_->BindTexture(texture_target, color_buffer->texture_id());

  // Clear the alpha channel if RGB emulation is required.
  if (DefaultBufferRequiresAlphaChannelToBePreserved()) {
    GLuint fbo = 0;

    state_restorer_->SetClearStateDirty();
    gl_->GenFramebuffers(1, &fbo);
    gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo);
    gl_->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                              texture_target, color_buffer->texture_id(), 0);
    gl_->ClearColor(0, 0, 0, 1);
    gl_->ColorMask(false, false, false, true);
    gl_->Disable(GL_SCISSOR_TEST);
    gl_->Clear(GL_COLOR_BUFFER_BIT);
    gl_->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                              texture_target, 0, 0);
    gl_->DeleteFramebuffers(1, &fbo);
  }

  return color_buffer;
}

void DrawingBuffer::AttachColorBufferToReadFramebuffer() {
  DCHECK(state_restorer_);
  state_restorer_->SetFramebufferBindingDirty();
  state_restorer_->SetTextureBindingDirty();

  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);

  GLenum id = 0;
  GLenum texture_target = 0;

  if (staging_texture_) {
    id = staging_texture_;
    texture_target = GL_TEXTURE_2D;
  } else {
    id = back_color_buffer_->texture_id();
    texture_target = back_color_buffer_->shared_image->GetTextureTarget();
  }

  gl_->BindTexture(texture_target, id);

  if (anti_aliasing_mode_ == kAntialiasingModeMSAAImplicitResolve) {
    gl_->FramebufferTexture2DMultisampleEXT(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, texture_target, id, 0,
        sample_count_);
  } else {
    gl_->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                              texture_target, id, 0);
  }
}

bool DrawingBuffer::WantExplicitResolve() {
  return anti_aliasing_mode_ == kAntialiasingModeMSAAExplicitResolve;
}

bool DrawingBuffer::WantDepthOrStencil() {
  return want_depth_ || want_stencil_;
}

DrawingBuffer::ScopedStateRestorer::ScopedStateRestorer(
    DrawingBuffer* drawing_buffer)
    : drawing_buffer_(drawing_buffer) {
  // If this is a nested restorer, save the previous restorer.
  previous_state_restorer_ = drawing_buffer->state_restorer_;
  drawing_buffer_->state_restorer_ = this;

  Client* client = drawing_buffer_->client_;
  if (!client) {
    return;
  }
  client->DrawingBufferClientInterruptPixelLocalStorage();
}

DrawingBuffer::ScopedStateRestorer::~ScopedStateRestorer() {
  DCHECK_EQ(drawing_buffer_->state_restorer_, this);
  drawing_buffer_->state_restorer_ = previous_state_restorer_;
  Client* client = drawing_buffer_->client_;
  if (!client)
    return;

  if (clear_state_dirty_) {
    client->DrawingBufferClientRestoreScissorTest();
    client->DrawingBufferClientRestoreMaskAndClearValues();
  }
  if (pixel_pack_parameters_dirty_)
    client->DrawingBufferClientRestorePixelPackParameters();
  if (texture_binding_dirty_)
    client->DrawingBufferClientRestoreTexture2DBinding();
  if (renderbuffer_binding_dirty_)
    client->DrawingBufferClientRestoreRenderbufferBinding();
  if (framebuffer_binding_dirty_)
    client->DrawingBufferClientRestoreFramebufferBinding();
  if (pixel_unpack_buffer_binding_dirty_)
    client->DrawingBufferClientRestorePixelUnpackBufferBinding();
  if (pixel_pack_buffer_binding_dirty_)
    client->DrawingBufferClientRestorePixelPackBufferBinding();
  client->DrawingBufferClientRestorePixelLocalStorage();
}

bool DrawingBuffer::ShouldUseChromiumImage() {
  if (chromium_image_usage_ != kAllowChromiumImage) {
    return false;
  }
#if BUILDFLAG(IS_ANDROID)
  if (ContextProvider()
          ->GetGpuFeatureInfo()
          .status_values[gpu::GPU_FEATURE_TYPE_ANDROID_SURFACE_CONTROL] !=
      gpu::kGpuFeatureStatusEnabled) {
    return false;
  }
#endif
  if (RuntimeEnabledFeatures::WebGLImageChromiumEnabled()) {
    return true;
  }
  return low_latency_enabled() &&
         base::FeatureList::IsEnabled(features::kLowLatencyWebGLImageChromium);
}

}  // namespace blink

"""


```