Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The main objective is to analyze the provided C++ source code snippet for the `DrawingBuffer` class in Chromium's Blink rendering engine and explain its functionalities, relationships with web technologies, and potential usage errors. The request specifically mentions a multi-part breakdown and asks for a summary of the first part.

2. **Initial Scan for Keywords and Structure:** I quickly scanned the code for prominent keywords and structural elements. I noticed:
    * Copyright information (irrelevant to functionality).
    * `#ifdef` directives for specific build configurations.
    * `#include` statements indicating dependencies on other Chromium/Blink components. This immediately tells me `DrawingBuffer` is not a standalone entity.
    * Class declaration: `class DrawingBuffer`.
    * Public and private members, methods, and nested classes/structs.
    * Use of OpenGL ES (`gpu::gles2::GLES2Interface`).
    * Mention of `javascript`, `html`, and `css` in the request. This requires connecting the low-level graphics code to high-level web concepts.

3. **Identify Core Functionality by Analyzing Public Methods and Key Members:**  I focused on the publicly accessible methods as they represent the primary interface of the `DrawingBuffer`. I looked for methods that hinted at core responsibilities. Key methods I identified early on include:
    * `Create()`:  This is a static factory method, strongly suggesting object instantiation and configuration. The parameters hint at the different options and requirements for creating a drawing buffer.
    * Constructor (`DrawingBuffer(...)`):  Shows the basic initialization parameters.
    * `MarkContentsChanged()`: Indicates tracking of changes to the buffer's content.
    * `BufferClearNeeded()`, `SetBufferClearNeeded()`:  Related to managing buffer clearing strategies.
    * `ContextGL()`, `ContextProvider()`: Accessors for the underlying OpenGL context.
    * `SetIsInHiddenPage()`:  Manages resource usage based on page visibility.
    * `SetHdrMetadata()`, `SetFilterQuality()`: Configuration of rendering properties.
    * `PrepareTransferableResource()`:  A crucial method for transferring the buffer's contents for compositing, indicating its role in the rendering pipeline.
    * `GetUnacceleratedStaticBitmapImage()`:  Allows retrieval of the buffer's content as a software bitmap.
    * `TransferToStaticBitmapImage()`: Another way to obtain the content as an image, potentially using GPU resources.
    * `ExportLowLatencyCanvasResource()`:  Suggests optimized handling for certain canvas scenarios.

4. **Infer Relationships with Web Technologies:** Based on the function names and the Blink context, I started to connect the low-level operations to higher-level web technologies:
    * **JavaScript:** The `DrawingBuffer` likely serves as the backing store for `<canvas>` elements, which are manipulated via JavaScript. The methods for transferring resources (`PrepareTransferableResource`, `TransferToStaticBitmapImage`) are critical for operations like `getImageData()` or `transferToImageBitmap()`.
    * **HTML:** The `<canvas>` element in HTML triggers the creation and use of a `DrawingBuffer`.
    * **CSS:** CSS properties can influence how the canvas is rendered (e.g., scaling, transformations). The `filter_quality_` member suggests a direct link.

5. **Consider Logic and Potential Usage Errors:**  I looked for patterns or conditions that might lead to specific outcomes or errors:
    * The `preserve_drawing_buffer_` flag and the different `DiscardBehavior` options suggest different strategies for managing the buffer's contents. Misconfiguring this could lead to visual artifacts or performance issues.
    * The checks for context loss (`gl_->GetGraphicsResetStatusKHR()`) are important for handling errors gracefully.
    * The caching mechanisms for color buffers and bitmaps imply an attempt to optimize resource usage, but incorrect usage or unexpected scenarios could lead to issues.

6. **Structure the Answer:** I organized the information into logical sections as requested:
    * **Core Functionality:**  A high-level overview.
    * **Relationship to JavaScript, HTML, CSS:**  Providing specific examples of how the `DrawingBuffer` interacts with these web technologies.
    * **Logical Inference (Hypothetical Input/Output):** Illustrating the behavior of specific methods with concrete examples. This helps demonstrate understanding of the code's logic.
    * **Common Usage Errors:**  Highlighting potential pitfalls for developers using the underlying APIs (though direct manipulation of `DrawingBuffer` is unlikely for web developers).
    * **Summary of Part 1:**  A concise recap of the key functionalities covered in the provided code snippet.

7. **Refine and Elaborate:**  I went back through my initial observations and expanded on them, providing more detail and explanation. For example, when discussing the relationship with JavaScript, I mentioned specific canvas API calls. When talking about errors, I gave concrete scenarios.

8. **Address Multi-Part Nature:** I noted that this was part 1 and focused on summarizing the functionality present in *this specific code snippet*. I avoided speculating too much about what might come in parts 2 and 3.

By following this process, I could break down the C++ code, understand its purpose within the larger Blink engine, and effectively communicate its functionality and relevance to web technologies as requested. The key is to combine a technical understanding of the code with a broader knowledge of how web browsers work.
```
/*
 * Copyright (c) 2010, Google Inc. All rights reserved.
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
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/gpu/drawing_buffer.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/logging.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/ostream_operators.h"
#include "build/build_config.h"
#include "cc/layers/texture_layer.h"
#include "components/viz/common/resources/bitmap_allocation.h"
#include "components/viz/common/resources/resource_sizes.h"
#include "components/viz/common/resources/shared_bitmap.h"
#include "components/viz/common/resources/shared_image_format.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/gpu_memory_buffer_support.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "gpu/config/gpu_feature_info.h"
#include "gpu/config/gpu_finch_features.h"
#include "media/base/video_frame.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_shared_image_interface_provider.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"
#include "third_party/blink/renderer/platform/graphics/gpu/extensions_3d_util.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_wrapper.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLTypes.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

const float kResourceAdjustedRatio = 0.5;

bool g_should_fail_drawing_buffer_creation_for_testing = false;

void FlipVertically(base::span<uint8_t> framebuffer,
                    size_t num_rows,
                    size_t row_bytes) {
  DCHECK_EQ(framebuffer.size(), num_rows * row_bytes);
  std::vector<uint8_t> scanline(row_bytes);
  for (size_t i = 0; i < num_rows / 2; i++) {
    uint8_t* row_a = framebuffer.data() + i * row_bytes;
    uint8_t* row_b = framebuffer.data() + (num_rows - i - 1) * row_bytes;
    memcpy(scanline.data(), row_b, row_bytes);
    memcpy(row_b, row_a, row_bytes);
    memcpy(row_a, scanline.data(), row_bytes);
  }
}

class ScopedDrawBuffer {
  STACK_ALLOCATED();

 public:
  explicit ScopedDrawBuffer(gpu::gles2::GLES2Interface* gl,
                            GLenum prev_draw_buffer,
                            GLenum new_draw_buffer)
      : gl_(gl),
        prev_draw_buffer_(prev_draw_buffer),
        new_draw_buffer_(new_draw_buffer) {
    if (prev_draw_buffer_ != new_draw_buffer_) {
      gl_->DrawBuffersEXT(1, &new_draw_buffer_);
    }
  }

  ~ScopedDrawBuffer() {
    if (prev_draw_buffer_ != new_draw_buffer_) {
      gl_->DrawBuffersEXT(1, &prev_draw_buffer_);
    }
  }

 private:
  gpu::gles2::GLES2Interface* gl_;
  GLenum prev_draw_buffer_;
  GLenum new_draw_buffer_;
};

}  // namespace

// Increase cache to avoid reallocation on fuchsia, see
// https://crbug.com/1087941.
#if BUILDFLAG(IS_FUCHSIA)
const size_t DrawingBuffer::kDefaultColorBufferCacheLimit = 2;
#else
const size_t DrawingBuffer::kDefaultColorBufferCacheLimit = 1;
#endif

// Function defined in third_party/blink/public/web/blink.h.
void ForceNextDrawingBufferCreationToFailForTest() {
  g_should_fail_drawing_buffer_creation_for_testing = true;
}

scoped_refptr<DrawingBuffer> DrawingBuffer::Create(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    bool using_swap_chain,
    Client* client,
    const gfx::Size& size,
    bool premultiplied_alpha,
    bool want_alpha_channel,
    bool want_depth_buffer,
    bool want_stencil_buffer,
    bool want_antialiasing,
    bool desynchronized,
    PreserveDrawingBuffer preserve,
    WebGLVersion webgl_version,
    ChromiumImageUsage chromium_image_usage,
    cc::PaintFlags::FilterQuality filter_quality,
    PredefinedColorSpace color_space,
    gl::GpuPreference gpu_preference) {
  if (g_should_fail_drawing_buffer_creation_for_testing) {
    g_should_fail_drawing_buffer_creation_for_testing = false;
    return nullptr;
  }

  base::CheckedNumeric<int> data_size =
      SkColorTypeBytesPerPixel(kRGBA_8888_SkColorType);
  data_size *= size.width();
  data_size *= size.height();
  if (!data_size.IsValid() ||
      data_size.ValueOrDie() > v8::TypedArray::kMaxByteLength) {
    return nullptr;
  }

  DCHECK(context_provider);
  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(context_provider->ContextGL());
  if (!extensions_util->IsValid()) {
    // This might be the first time we notice that the GL context is lost.
    return nullptr;
  }
  DCHECK(extensions_util->SupportsExtension("GL_OES_packed_depth_stencil"));
  extensions_util->EnsureExtensionEnabled("GL_OES_packed_depth_stencil");
  bool multisample_supported =
      want_antialiasing &&
      (extensions_util->SupportsExtension(
           "GL_CHROMIUM_framebuffer_multisample") ||
       extensions_util->SupportsExtension(
           "GL_EXT_multisampled_render_to_texture")) &&
      extensions_util->SupportsExtension("GL_OES_rgb8_rgba8");
  if (multisample_supported) {
    extensions_util->EnsureExtensionEnabled("GL_OES_rgb8_rgba8");
    if (extensions_util->SupportsExtension(
            "GL_CHROMIUM_framebuffer_multisample")) {
      extensions_util->EnsureExtensionEnabled(
          "GL_CHROMIUM_framebuffer_multisample");
    } else {
      extensions_util->EnsureExtensionEnabled(
          "GL_EXT_multisampled_render_to_texture");
    }
  }
  bool discard_framebuffer_supported =
      extensions_util->SupportsExtension("GL_EXT_discard_framebuffer");
  if (discard_framebuffer_supported)
    extensions_util->EnsureExtensionEnabled("GL_EXT_discard_framebuffer");

  bool texture_storage_enabled =
      extensions_util->IsExtensionEnabled("GL_EXT_texture_storage");

  scoped_refptr<DrawingBuffer> drawing_buffer =
      base::AdoptRef(new DrawingBuffer(
          std::move(context_provider), graphics_info, using_swap_chain,
          desynchronized, std::move(extensions_util), client,
          discard_framebuffer_supported, texture_storage_enabled,
          want_alpha_channel, premultiplied_alpha, preserve, webgl_version,
          want_depth_buffer, want_stencil_buffer, chromium_image_usage,
          filter_quality, color_space, gpu_preference));
  if (!drawing_buffer->Initialize(size, multisample_supported)) {
    drawing_buffer->BeginDestruction();
    return scoped_refptr<DrawingBuffer>();
  }
  return drawing_buffer;
}

DrawingBuffer::DrawingBuffer(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    bool using_swap_chain,
    bool desynchronized,
    std::unique_ptr<Extensions3DUtil> extensions_util,
    Client* client,
    bool discard_framebuffer_supported,
    bool texture_storage_enabled,
    bool want_alpha_channel,
    bool premultiplied_alpha,
    PreserveDrawingBuffer preserve,
    WebGLVersion webgl_version,
    bool want_depth,
    bool want_stencil,
    ChromiumImageUsage chromium_image_usage,
    cc::PaintFlags::FilterQuality filter_quality,
    PredefinedColorSpace color_space,
    gl::GpuPreference gpu_preference)
    : client_(client),
      preserve_drawing_buffer_(preserve),
      webgl_version_(webgl_version),
      context_provider_(std::make_unique<WebGraphicsContext3DProviderWrapper>(
          std::move(context_provider))),
      gl_(ContextProvider()->ContextGL()),
      extensions_util_(std::move(extensions_util)),
      discard_framebuffer_supported_(discard_framebuffer_supported),
      texture_storage_enabled_(texture_storage_enabled),
      requested_alpha_type_(want_alpha_channel
                                ? (premultiplied_alpha ? kPremul_SkAlphaType
                                                       : kUnpremul_SkAlphaType)
                                : kOpaque_SkAlphaType),
      requested_format_(want_alpha_channel ? GL_RGBA8 : GL_RGB8),
      graphics_info_(graphics_info),
      using_swap_chain_(using_swap_chain),
      low_latency_enabled_(desynchronized),
      want_depth_(want_depth),
      want_stencil_(want_stencil),
      color_space_(PredefinedColorSpaceToGfxColorSpace(color_space)),
      filter_quality_(filter_quality),
      chromium_image_usage_(chromium_image_usage),
      opengl_flip_y_extension_(
          ContextProvider()->GetCapabilities().mesa_framebuffer_flip_y),
      initial_gpu_(gpu_preference),
      current_active_gpu_(gpu_preference),
      weak_factory_(this) {
  // Used by browser tests to detect the use of a DrawingBuffer.
  TRACE_EVENT_INSTANT0("test_gpu", "DrawingBufferCreation",
                       TRACE_EVENT_SCOPE_GLOBAL);
  // PowerPreferenceToGpuPreference should have resolved the meaning
  // of the "default" GPU already.
  DCHECK(gpu_preference != gl::GpuPreference::kDefault);
}

DrawingBuffer::~DrawingBuffer() {
  DCHECK(destruction_in_progress_);
  if (layer_) {
    layer_->ClearClient();
    layer_ = nullptr;
  }

  for (auto& color_buffer : exported_color_buffers_) {
    color_buffer->ForceCleanUp();
  }
  context_provider_ = nullptr;
}

bool DrawingBuffer::MarkContentsChanged() {
  if (contents_change_resolved_ || !contents_changed_) {
    contents_change_resolved_ = false;
    transient_framebuffers_discarded_ = false;
    contents_changed_ = true;
    return true;
  }
  return false;
}

bool DrawingBuffer::BufferClearNeeded() const {
  return buffer_clear_needed_;
}

void DrawingBuffer::SetBufferClearNeeded(bool flag) {
  if (preserve_drawing_buffer_ == kDiscard) {
    buffer_clear_needed_ = flag;
  } else {
    DCHECK(!buffer_clear_needed_);
  }
}

gpu::gles2::GLES2Interface* DrawingBuffer::ContextGL() {
  return gl_;
}

WebGraphicsContext3DProvider* DrawingBuffer::ContextProvider() {
  return context_provider_->ContextProvider();
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
DrawingBuffer::ContextProviderWeakPtr() {
  return context_provider_->GetWeakPtr();
}

void DrawingBuffer::SetIsInHiddenPage(bool hidden) {
  if (is_hidden_ == hidden)
    return;
  is_hidden_ = hidden;
  if (is_hidden_) {
    recycled_color_buffer_queue_.clear();
    recycled_bitmaps_.clear();
  }

  // Make sure to interrupt pixel local storage.
  ScopedStateRestorer scoped_state_restorer(this);

  auto* context_support = ContextProvider()->ContextSupport();
  if (context_support) {
    context_support->SetAggressivelyFreeResources(hidden);
  }

  gl_->ContextVisibilityHintCHROMIUM(is_hidden_ ? GL_FALSE : GL_TRUE);
  gl_->Flush();
}

void DrawingBuffer::SetHdrMetadata(const gfx::HDRMetadata& hdr_metadata) {
  hdr_metadata_ = hdr_metadata;
}

void DrawingBuffer::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (filter_quality_ != filter_quality) {
    filter_quality_ = filter_quality;
    if (layer_) {
      layer_->SetNearestNeighbor(filter_quality ==
                                 cc::PaintFlags::FilterQuality::kNone);
    }
  }
}

bool DrawingBuffer::RequiresAlphaChannelToBePreserved() {
  return client_->DrawingBufferClientIsBoundForDraw() &&
         DefaultBufferRequiresAlphaChannelToBePreserved();
}

bool DrawingBuffer::DefaultBufferRequiresAlphaChannelToBePreserved() {
  return requested_alpha_type_ == kOpaque_SkAlphaType &&
         color_buffer_format_.HasAlpha();
}

void DrawingBuffer::SetDrawBuffer(GLenum draw_buffer) {
  draw_buffer_ = draw_buffer;
}

void DrawingBuffer::SetSharedImageInterfaceProviderForBitmapTest(
    std::unique_ptr<WebGraphicsSharedImageInterfaceProvider> sii_provider) {
  shared_image_interface_provider_for_bitmap_test_ = std::move(sii_provider);
}

WebGraphicsSharedImageInterfaceProvider*
DrawingBuffer::GetSharedImageInterfaceProviderForBitmap() {
  if (shared_image_interface_provider_for_bitmap_test_) {
    return shared_image_interface_provider_for_bitmap_test_.get();
  }
  return SharedGpuContext::SharedImageInterfaceProvider();
}

DrawingBuffer::RegisteredBitmap DrawingBuffer::CreateOrRecycleBitmap() {
  const viz::SharedImageFormat format = viz::SinglePlaneFormat::kBGRA_8888;
  // Must call GetSharedImageInterfaceProvider first so all base::WeakPtr
  // restored in |registered.sii_provider| is updated.
  auto* sii_provider = GetSharedImageInterfaceProviderForBitmap();

  auto it = std::remove_if(recycled_bitmaps_.begin(), recycled_bitmaps_.end(),
                           [this](const RegisteredBitmap& registered) {
                             return registered.bitmap->size() != size_ ||
                                    !registered.sii_provider;
                           });
  recycled_bitmaps_.Shrink(
      static_cast<wtf_size_t>(it - recycled_bitmaps_.begin()));

  if (!recycled_bitmaps_.empty()) {
    RegisteredBitmap recycled = std::move(recycled_bitmaps_.back());
    recycled_bitmaps_.pop_back();
    return recycled;
  }

  // There are no bitmaps to recycle so allocate a new one.
  auto* shared_image_interface = sii_provider->SharedImageInterface();
  if (!shared_image_interface) {
    return RegisteredBitmap();
  }
  auto shared_image_mapping = shared_image_interface->CreateSharedImage(
      {format, size_, gfx::ColorSpace(), gpu::SHARED_IMAGE_USAGE_CPU_WRITE,
       "DrawingBufferBitmap"});
  auto bitmap = base::MakeRefCounted<cc::CrossThreadSharedBitmap>(
      viz::SharedBitmapId(), base::ReadOnlySharedMemoryRegion(),
      std::move(shared_image_mapping.mapping), size_, format);

  RegisteredBitmap registered = {std::move(bitmap),
                                 std::move(shared_image_mapping.shared_image),
                                 shared_image_interface->GenVerifiedSyncToken(),
                                 sii_provider->GetWeakPtr()};

  return registered;
}

bool DrawingBuffer::PrepareTransferableResource(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  ScopedStateRestorer scoped_state_restorer(this);
  bool force_gpu_result = false;
  return PrepareTransferableResourceInternal(
      /*client_si=*/nullptr, out_resource, out_release_callback,
      force_gpu_result);
}

DrawingBuffer::CheckForDestructionResult
DrawingBuffer::CheckForDestructionAndChangeAndResolveIfNeeded(
    DiscardBehavior discardBehavior) {
  DCHECK(state_restorer_);
  if (destruction_in_progress_) {
    // It can be hit in the following sequence.
    // 1. WebGL draws something.
    // 2. The compositor begins the frame.
    // 3. Javascript makes a context lost using WEBGL_lose_context extension.
    // 4. Here.
    return kDestroyedOrLost;
  }

  // There used to be a DCHECK(!is_hidden_) here, but in some tab
  // switching scenarios, it seems that this can racily be called for
  // backgrounded tabs.

  if (!contents_changed_)
    return kContentsUnchanged;

  // If the context is lost, we don't know if we should be producing GPU or
  // software frames, until we get a new context, since the compositor will
  // be trying to get a new context and may change modes.
  if (gl_->GetGraphicsResetStatusKHR() != GL_NO_ERROR)
    return kDestroyedOrLost;

  TRACE_EVENT0("blink,rail", "DrawingBuffer::prepareMailbox");

  // Resolve the multisampled buffer into the texture attached to fbo_.
  ResolveIfNeeded(discardBehavior);

  return kContentsResolvedIfNeeded;
}

bool DrawingBuffer::PrepareTransferableResourceInternal(
    scoped_refptr<gpu::ClientSharedImage>* client_si,
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback,
    bool force_gpu_result) {
  if (CheckForDestructionAndChangeAndResolveIfNeeded(kDiscardAllowed) !=
      kContentsResolvedIfNeeded) {
    return false;
  }

  if (!IsUsingGpuCompositing() && !force_gpu_result) {
    return FinishPrepareTransferableResourceSoftware(out_resource,
                                                     out_release_callback);
  }

  return FinishPrepareTransferableResourceGpu(out_resource, client_si,
                                              out_release_callback);
}

scoped_refptr<StaticBitmapImage>
DrawingBuffer::GetUnacceleratedStaticBitmapImage() {
  ScopedStateRestorer scoped_state_restorer(this);

  if (CheckForDestructionAndChangeAndResolveIfNeeded(kDontDiscard) ==
      kDestroyedOrLost) {
    return nullptr;
  }

  SkBitmap bitmap;
  if (!bitmap.tryAllocN32Pixels(size_.width(), size_.height()))
    return nullptr;
  ReadFramebufferIntoBitmapPixels(static_cast<uint8_t*>(bitmap.getPixels()));
  auto sk_image = SkImages::RasterFromBitmap(bitmap);

  // GL Framebuffer is bottom-left origin by default and the
  // mesa_framebuffer_flip_y extension doesn't affect glReadPixels, so
  // `ReadFramebufferIntoBitmapPixels` always returns bottom left images.
  return sk_image ? UnacceleratedStaticBitmapImage::Create(
                        sk_image, ImageOrientationEnum::kOriginBottomLeft)
                  : nullptr;
}

void DrawingBuffer::ReadFramebufferIntoBitmapPixels(uint8_t* pixels) {
  DCHECK(pixels);
  DCHECK(state_restorer_);
  bool need_premultiply = requested_alpha_type_ == kUnpremul_SkAlphaType;
  WebGLImageConversion::AlphaOp op =
      need_premultiply ? WebGLImageConversion::kAlphaDoPremultiply
                       : WebGLImageConversion::kAlphaDoNothing;
  state_restorer_->SetFramebufferBindingDirty();
  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);

  // Readback in Skia native byte order (RGBA or BGRA) with kN32_SkColorType.
  const size_t buffer_size = viz::ResourceSizes::CheckedSizeInBytes<size_t>(
      size_, viz::SinglePlaneFormat::kRGBA_8888);
  ReadBackFramebuffer(base::span<uint8_t>(pixels, buffer_size),
                      kN32_SkColorType, op);
}

bool DrawingBuffer::FinishPrepareTransferableResourceSoftware(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  DCHECK(state_restorer_);
  RegisteredBitmap registered = CreateOrRecycleBitmap();
  if (!registered.bitmap) {
    return false;
  }

  ReadFramebufferIntoBitmapPixels(
      static_cast<uint8_t*>(registered.bitmap->memory()));

  if (registered.shared_image) {
    *out_resource = viz::TransferableResource::MakeSoftwareSharedImage(
        registered.shared_image, registered.sync_token, size_,
        viz::SinglePlaneFormat::kBGRA_8888,
        viz::TransferableResource::ResourceSource::kImageLayerBridge);
  } else {
    *out_resource = viz::TransferableResource::MakeSoftwareSharedBitmap(
        registered.bitmap->id(), gpu::SyncToken(), size_,
        viz::SinglePlaneFormat::kRGBA_8888,
        viz::TransferableResource::ResourceSource::kDrawingBuffer);
  }
  out_resource->color_space = back_color_buffer_->color_space;
  out_resource->hdr_metadata = hdr_metadata_;

  // This holds a ref on the DrawingBuffer that will keep it alive until the
  // mailbox is released (and while the release callback is running). It also
  // owns the SharedBitmap.
  *out_release_callback =
      base::BindOnce(&DrawingBuffer::MailboxReleasedSoftware,
                     weak_factory_.GetWeakPtr(), std::move(registered));

  contents_changed_ = false;
  if (preserve_drawing_buffer_ == kDiscard) {
    SetBufferClearNeeded(true);
  }
  return true;
}
```

### 功能概括

`DrawingBuffer` 类在 Chromium Blink 引擎中负责管理用于渲染的图形缓冲区，特别是在 GPU 加速的场景下。它封装了与 OpenGL ES 上下文交互的细节，并提供了将缓冲区内容传递给合成器（compositor）或其他组件的机制。

**核心功能可以归纳为:**

1. **管理图形缓冲区:**  `DrawingBuffer` 维护用于绘制的颜色缓冲区、深度缓冲区和模板缓冲区。它可以创建、回收和管理这些缓冲区在 GPU 内存中的生命周期。
2. **与 OpenGL ES 上下文交互:** 它持有 `WebGraphicsContext3DProvider`，并通过 `gpu::gles2::GLES2Interface` 与底层的 OpenGL ES API 进行交互，执行如绑定帧缓冲区、绘制调用、读取像素等操作。
3. **支持不同的配置:**  `DrawingBuffer` 的创建可以根据需求配置是否需要 Alpha 通道、深度/模板缓冲区、抗锯齿等特性。它还支持不同的 WebGL 版本和图像使用场景。
4. **内容跟踪和更新:**  它可以跟踪缓冲区内容是否发生变化，并根据策略（是否保留缓冲区内容）决定是否需要清除缓冲区。
5. **资源共享和传递:**  它提供将缓冲区内容转换为可传递的资源（`viz::TransferableResource`）的机制，以便将渲染结果传递给合成器进行最终显示。这包括 GPU 纹理和软件位图两种方式。
6. **处理页面可见性:**  当页面隐藏时，它可以释放一些资源以节省内存。
7. **支持 HDR 和滤镜:**  它可以处理高动态范围（HDR）元数据，并应用滤镜质量设置。
8. **测试支持:** 提供了用于测试目的的功能，例如模拟缓冲区创建失败。

### 与 JavaScript, HTML, CSS 的关系

`DrawingBuffer` 位于 Blink 渲染引擎的底层图形处理部分，虽然 web 开发者通常不会直接操作它，但它的功能直接支持了 HTML5 Canvas 和 WebGL API 的实现。

**举例说明:**

* **JavaScript 和 HTML Canvas:**
    * 当 JavaScript 代码在 `<canvas>` 元素上调用 `getContext('webgl')` 或 `getContext('2d')` 时，Blink 内部会创建一个 `DrawingBuffer` (对于 WebGL) 或相关的后端（对于 2D Canvas）。
    * JavaScript 通过 WebGL 或 Canvas 2D API 进行的绘制操作，最终会修改 `DrawingBuffer` 中管理的图形缓冲区的内容。
    * 当需要将 Canvas 内容作为图像数据获取时（例如，通过 `canvas.toDataURL()` 或 `getImageData()`），`DrawingBuffer` 会提供其缓冲区的内容。`PrepareTransferableResource` 和相关方法用于将 GPU 缓冲区的内容读取回 CPU 内存或者创建可以共享的 GPU 纹理。
    * **假设输入:** JavaScript 代码在 Canvas 上绘制了一个红色的矩形。
    * **逻辑推理 (DrawingBuffer 内部操作):** `DrawingBuffer` 会接收来自 WebGL 或 2D Canvas 实现的绘制指令，并使用 OpenGL ES API 在其管理的颜色缓冲区中填充相应的像素。
    * **假设输出:** 后续调用 `canvas.toDataURL()` 会生成一个包含红色矩形的 base64 编码的图像。

* **JavaScript 和 WebGL:**
    * WebGL API 直接操作由 `DrawingBuffer` 管理的 OpenGL ES 上下文和缓冲区。例如，WebGL 的帧缓冲区对象 (FBO)
Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/drawing_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2010, Google Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/gpu/drawing_buffer.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/logging.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/ostream_operators.h"
#include "build/build_config.h"
#include "cc/layers/texture_layer.h"
#include "components/viz/common/resources/bitmap_allocation.h"
#include "components/viz/common/resources/resource_sizes.h"
#include "components/viz/common/resources/shared_bitmap.h"
#include "components/viz/common/resources/shared_image_format.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/gpu_memory_buffer_support.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "gpu/config/gpu_feature_info.h"
#include "gpu/config/gpu_finch_features.h"
#include "media/base/video_frame.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_shared_image_interface_provider.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"
#include "third_party/blink/renderer/platform/graphics/gpu/extensions_3d_util.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_wrapper.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLTypes.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

const float kResourceAdjustedRatio = 0.5;

bool g_should_fail_drawing_buffer_creation_for_testing = false;

void FlipVertically(base::span<uint8_t> framebuffer,
                    size_t num_rows,
                    size_t row_bytes) {
  DCHECK_EQ(framebuffer.size(), num_rows * row_bytes);
  std::vector<uint8_t> scanline(row_bytes);
  for (size_t i = 0; i < num_rows / 2; i++) {
    uint8_t* row_a = framebuffer.data() + i * row_bytes;
    uint8_t* row_b = framebuffer.data() + (num_rows - i - 1) * row_bytes;
    memcpy(scanline.data(), row_b, row_bytes);
    memcpy(row_b, row_a, row_bytes);
    memcpy(row_a, scanline.data(), row_bytes);
  }
}

class ScopedDrawBuffer {
  STACK_ALLOCATED();

 public:
  explicit ScopedDrawBuffer(gpu::gles2::GLES2Interface* gl,
                            GLenum prev_draw_buffer,
                            GLenum new_draw_buffer)
      : gl_(gl),
        prev_draw_buffer_(prev_draw_buffer),
        new_draw_buffer_(new_draw_buffer) {
    if (prev_draw_buffer_ != new_draw_buffer_) {
      gl_->DrawBuffersEXT(1, &new_draw_buffer_);
    }
  }

  ~ScopedDrawBuffer() {
    if (prev_draw_buffer_ != new_draw_buffer_) {
      gl_->DrawBuffersEXT(1, &prev_draw_buffer_);
    }
  }

 private:
  gpu::gles2::GLES2Interface* gl_;
  GLenum prev_draw_buffer_;
  GLenum new_draw_buffer_;
};

}  // namespace

// Increase cache to avoid reallocation on fuchsia, see
// https://crbug.com/1087941.
#if BUILDFLAG(IS_FUCHSIA)
const size_t DrawingBuffer::kDefaultColorBufferCacheLimit = 2;
#else
const size_t DrawingBuffer::kDefaultColorBufferCacheLimit = 1;
#endif

// Function defined in third_party/blink/public/web/blink.h.
void ForceNextDrawingBufferCreationToFailForTest() {
  g_should_fail_drawing_buffer_creation_for_testing = true;
}

scoped_refptr<DrawingBuffer> DrawingBuffer::Create(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    bool using_swap_chain,
    Client* client,
    const gfx::Size& size,
    bool premultiplied_alpha,
    bool want_alpha_channel,
    bool want_depth_buffer,
    bool want_stencil_buffer,
    bool want_antialiasing,
    bool desynchronized,
    PreserveDrawingBuffer preserve,
    WebGLVersion webgl_version,
    ChromiumImageUsage chromium_image_usage,
    cc::PaintFlags::FilterQuality filter_quality,
    PredefinedColorSpace color_space,
    gl::GpuPreference gpu_preference) {
  if (g_should_fail_drawing_buffer_creation_for_testing) {
    g_should_fail_drawing_buffer_creation_for_testing = false;
    return nullptr;
  }

  base::CheckedNumeric<int> data_size =
      SkColorTypeBytesPerPixel(kRGBA_8888_SkColorType);
  data_size *= size.width();
  data_size *= size.height();
  if (!data_size.IsValid() ||
      data_size.ValueOrDie() > v8::TypedArray::kMaxByteLength) {
    return nullptr;
  }

  DCHECK(context_provider);
  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(context_provider->ContextGL());
  if (!extensions_util->IsValid()) {
    // This might be the first time we notice that the GL context is lost.
    return nullptr;
  }
  DCHECK(extensions_util->SupportsExtension("GL_OES_packed_depth_stencil"));
  extensions_util->EnsureExtensionEnabled("GL_OES_packed_depth_stencil");
  bool multisample_supported =
      want_antialiasing &&
      (extensions_util->SupportsExtension(
           "GL_CHROMIUM_framebuffer_multisample") ||
       extensions_util->SupportsExtension(
           "GL_EXT_multisampled_render_to_texture")) &&
      extensions_util->SupportsExtension("GL_OES_rgb8_rgba8");
  if (multisample_supported) {
    extensions_util->EnsureExtensionEnabled("GL_OES_rgb8_rgba8");
    if (extensions_util->SupportsExtension(
            "GL_CHROMIUM_framebuffer_multisample")) {
      extensions_util->EnsureExtensionEnabled(
          "GL_CHROMIUM_framebuffer_multisample");
    } else {
      extensions_util->EnsureExtensionEnabled(
          "GL_EXT_multisampled_render_to_texture");
    }
  }
  bool discard_framebuffer_supported =
      extensions_util->SupportsExtension("GL_EXT_discard_framebuffer");
  if (discard_framebuffer_supported)
    extensions_util->EnsureExtensionEnabled("GL_EXT_discard_framebuffer");

  bool texture_storage_enabled =
      extensions_util->IsExtensionEnabled("GL_EXT_texture_storage");

  scoped_refptr<DrawingBuffer> drawing_buffer =
      base::AdoptRef(new DrawingBuffer(
          std::move(context_provider), graphics_info, using_swap_chain,
          desynchronized, std::move(extensions_util), client,
          discard_framebuffer_supported, texture_storage_enabled,
          want_alpha_channel, premultiplied_alpha, preserve, webgl_version,
          want_depth_buffer, want_stencil_buffer, chromium_image_usage,
          filter_quality, color_space, gpu_preference));
  if (!drawing_buffer->Initialize(size, multisample_supported)) {
    drawing_buffer->BeginDestruction();
    return scoped_refptr<DrawingBuffer>();
  }
  return drawing_buffer;
}

DrawingBuffer::DrawingBuffer(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    bool using_swap_chain,
    bool desynchronized,
    std::unique_ptr<Extensions3DUtil> extensions_util,
    Client* client,
    bool discard_framebuffer_supported,
    bool texture_storage_enabled,
    bool want_alpha_channel,
    bool premultiplied_alpha,
    PreserveDrawingBuffer preserve,
    WebGLVersion webgl_version,
    bool want_depth,
    bool want_stencil,
    ChromiumImageUsage chromium_image_usage,
    cc::PaintFlags::FilterQuality filter_quality,
    PredefinedColorSpace color_space,
    gl::GpuPreference gpu_preference)
    : client_(client),
      preserve_drawing_buffer_(preserve),
      webgl_version_(webgl_version),
      context_provider_(std::make_unique<WebGraphicsContext3DProviderWrapper>(
          std::move(context_provider))),
      gl_(ContextProvider()->ContextGL()),
      extensions_util_(std::move(extensions_util)),
      discard_framebuffer_supported_(discard_framebuffer_supported),
      texture_storage_enabled_(texture_storage_enabled),
      requested_alpha_type_(want_alpha_channel
                                ? (premultiplied_alpha ? kPremul_SkAlphaType
                                                       : kUnpremul_SkAlphaType)
                                : kOpaque_SkAlphaType),
      requested_format_(want_alpha_channel ? GL_RGBA8 : GL_RGB8),
      graphics_info_(graphics_info),
      using_swap_chain_(using_swap_chain),
      low_latency_enabled_(desynchronized),
      want_depth_(want_depth),
      want_stencil_(want_stencil),
      color_space_(PredefinedColorSpaceToGfxColorSpace(color_space)),
      filter_quality_(filter_quality),
      chromium_image_usage_(chromium_image_usage),
      opengl_flip_y_extension_(
          ContextProvider()->GetCapabilities().mesa_framebuffer_flip_y),
      initial_gpu_(gpu_preference),
      current_active_gpu_(gpu_preference),
      weak_factory_(this) {
  // Used by browser tests to detect the use of a DrawingBuffer.
  TRACE_EVENT_INSTANT0("test_gpu", "DrawingBufferCreation",
                       TRACE_EVENT_SCOPE_GLOBAL);
  // PowerPreferenceToGpuPreference should have resolved the meaning
  // of the "default" GPU already.
  DCHECK(gpu_preference != gl::GpuPreference::kDefault);
}

DrawingBuffer::~DrawingBuffer() {
  DCHECK(destruction_in_progress_);
  if (layer_) {
    layer_->ClearClient();
    layer_ = nullptr;
  }

  for (auto& color_buffer : exported_color_buffers_) {
    color_buffer->ForceCleanUp();
  }
  context_provider_ = nullptr;
}

bool DrawingBuffer::MarkContentsChanged() {
  if (contents_change_resolved_ || !contents_changed_) {
    contents_change_resolved_ = false;
    transient_framebuffers_discarded_ = false;
    contents_changed_ = true;
    return true;
  }
  return false;
}

bool DrawingBuffer::BufferClearNeeded() const {
  return buffer_clear_needed_;
}

void DrawingBuffer::SetBufferClearNeeded(bool flag) {
  if (preserve_drawing_buffer_ == kDiscard) {
    buffer_clear_needed_ = flag;
  } else {
    DCHECK(!buffer_clear_needed_);
  }
}

gpu::gles2::GLES2Interface* DrawingBuffer::ContextGL() {
  return gl_;
}

WebGraphicsContext3DProvider* DrawingBuffer::ContextProvider() {
  return context_provider_->ContextProvider();
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
DrawingBuffer::ContextProviderWeakPtr() {
  return context_provider_->GetWeakPtr();
}

void DrawingBuffer::SetIsInHiddenPage(bool hidden) {
  if (is_hidden_ == hidden)
    return;
  is_hidden_ = hidden;
  if (is_hidden_) {
    recycled_color_buffer_queue_.clear();
    recycled_bitmaps_.clear();
  }

  // Make sure to interrupt pixel local storage.
  ScopedStateRestorer scoped_state_restorer(this);

  auto* context_support = ContextProvider()->ContextSupport();
  if (context_support) {
    context_support->SetAggressivelyFreeResources(hidden);
  }

  gl_->ContextVisibilityHintCHROMIUM(is_hidden_ ? GL_FALSE : GL_TRUE);
  gl_->Flush();
}

void DrawingBuffer::SetHdrMetadata(const gfx::HDRMetadata& hdr_metadata) {
  hdr_metadata_ = hdr_metadata;
}

void DrawingBuffer::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (filter_quality_ != filter_quality) {
    filter_quality_ = filter_quality;
    if (layer_) {
      layer_->SetNearestNeighbor(filter_quality ==
                                 cc::PaintFlags::FilterQuality::kNone);
    }
  }
}

bool DrawingBuffer::RequiresAlphaChannelToBePreserved() {
  return client_->DrawingBufferClientIsBoundForDraw() &&
         DefaultBufferRequiresAlphaChannelToBePreserved();
}

bool DrawingBuffer::DefaultBufferRequiresAlphaChannelToBePreserved() {
  return requested_alpha_type_ == kOpaque_SkAlphaType &&
         color_buffer_format_.HasAlpha();
}

void DrawingBuffer::SetDrawBuffer(GLenum draw_buffer) {
  draw_buffer_ = draw_buffer;
}

void DrawingBuffer::SetSharedImageInterfaceProviderForBitmapTest(
    std::unique_ptr<WebGraphicsSharedImageInterfaceProvider> sii_provider) {
  shared_image_interface_provider_for_bitmap_test_ = std::move(sii_provider);
}

WebGraphicsSharedImageInterfaceProvider*
DrawingBuffer::GetSharedImageInterfaceProviderForBitmap() {
  if (shared_image_interface_provider_for_bitmap_test_) {
    return shared_image_interface_provider_for_bitmap_test_.get();
  }
  return SharedGpuContext::SharedImageInterfaceProvider();
}

DrawingBuffer::RegisteredBitmap DrawingBuffer::CreateOrRecycleBitmap() {
  const viz::SharedImageFormat format = viz::SinglePlaneFormat::kBGRA_8888;
  // Must call GetSharedImageInterfaceProvider first so all base::WeakPtr
  // restored in |registered.sii_provider| is updated.
  auto* sii_provider = GetSharedImageInterfaceProviderForBitmap();

  auto it = std::remove_if(recycled_bitmaps_.begin(), recycled_bitmaps_.end(),
                           [this](const RegisteredBitmap& registered) {
                             return registered.bitmap->size() != size_ ||
                                    !registered.sii_provider;
                           });
  recycled_bitmaps_.Shrink(
      static_cast<wtf_size_t>(it - recycled_bitmaps_.begin()));

  if (!recycled_bitmaps_.empty()) {
    RegisteredBitmap recycled = std::move(recycled_bitmaps_.back());
    recycled_bitmaps_.pop_back();
    return recycled;
  }

  // There are no bitmaps to recycle so allocate a new one.
  auto* shared_image_interface = sii_provider->SharedImageInterface();
  if (!shared_image_interface) {
    return RegisteredBitmap();
  }
  auto shared_image_mapping = shared_image_interface->CreateSharedImage(
      {format, size_, gfx::ColorSpace(), gpu::SHARED_IMAGE_USAGE_CPU_WRITE,
       "DrawingBufferBitmap"});
  auto bitmap = base::MakeRefCounted<cc::CrossThreadSharedBitmap>(
      viz::SharedBitmapId(), base::ReadOnlySharedMemoryRegion(),
      std::move(shared_image_mapping.mapping), size_, format);

  RegisteredBitmap registered = {std::move(bitmap),
                                 std::move(shared_image_mapping.shared_image),
                                 shared_image_interface->GenVerifiedSyncToken(),
                                 sii_provider->GetWeakPtr()};

  return registered;
}

bool DrawingBuffer::PrepareTransferableResource(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  ScopedStateRestorer scoped_state_restorer(this);
  bool force_gpu_result = false;
  return PrepareTransferableResourceInternal(
      /*client_si=*/nullptr, out_resource, out_release_callback,
      force_gpu_result);
}

DrawingBuffer::CheckForDestructionResult
DrawingBuffer::CheckForDestructionAndChangeAndResolveIfNeeded(
    DiscardBehavior discardBehavior) {
  DCHECK(state_restorer_);
  if (destruction_in_progress_) {
    // It can be hit in the following sequence.
    // 1. WebGL draws something.
    // 2. The compositor begins the frame.
    // 3. Javascript makes a context lost using WEBGL_lose_context extension.
    // 4. Here.
    return kDestroyedOrLost;
  }

  // There used to be a DCHECK(!is_hidden_) here, but in some tab
  // switching scenarios, it seems that this can racily be called for
  // backgrounded tabs.

  if (!contents_changed_)
    return kContentsUnchanged;

  // If the context is lost, we don't know if we should be producing GPU or
  // software frames, until we get a new context, since the compositor will
  // be trying to get a new context and may change modes.
  if (gl_->GetGraphicsResetStatusKHR() != GL_NO_ERROR)
    return kDestroyedOrLost;

  TRACE_EVENT0("blink,rail", "DrawingBuffer::prepareMailbox");

  // Resolve the multisampled buffer into the texture attached to fbo_.
  ResolveIfNeeded(discardBehavior);

  return kContentsResolvedIfNeeded;
}

bool DrawingBuffer::PrepareTransferableResourceInternal(
    scoped_refptr<gpu::ClientSharedImage>* client_si,
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback,
    bool force_gpu_result) {
  if (CheckForDestructionAndChangeAndResolveIfNeeded(kDiscardAllowed) !=
      kContentsResolvedIfNeeded) {
    return false;
  }

  if (!IsUsingGpuCompositing() && !force_gpu_result) {
    return FinishPrepareTransferableResourceSoftware(out_resource,
                                                     out_release_callback);
  }

  return FinishPrepareTransferableResourceGpu(out_resource, client_si,
                                              out_release_callback);
}

scoped_refptr<StaticBitmapImage>
DrawingBuffer::GetUnacceleratedStaticBitmapImage() {
  ScopedStateRestorer scoped_state_restorer(this);

  if (CheckForDestructionAndChangeAndResolveIfNeeded(kDontDiscard) ==
      kDestroyedOrLost) {
    return nullptr;
  }

  SkBitmap bitmap;
  if (!bitmap.tryAllocN32Pixels(size_.width(), size_.height()))
    return nullptr;
  ReadFramebufferIntoBitmapPixels(static_cast<uint8_t*>(bitmap.getPixels()));
  auto sk_image = SkImages::RasterFromBitmap(bitmap);

  // GL Framebuffer is bottom-left origin by default and the
  // mesa_framebuffer_flip_y extension doesn't affect glReadPixels, so
  // `ReadFramebufferIntoBitmapPixels` always returns bottom left images.
  return sk_image ? UnacceleratedStaticBitmapImage::Create(
                        sk_image, ImageOrientationEnum::kOriginBottomLeft)
                  : nullptr;
}

void DrawingBuffer::ReadFramebufferIntoBitmapPixels(uint8_t* pixels) {
  DCHECK(pixels);
  DCHECK(state_restorer_);
  bool need_premultiply = requested_alpha_type_ == kUnpremul_SkAlphaType;
  WebGLImageConversion::AlphaOp op =
      need_premultiply ? WebGLImageConversion::kAlphaDoPremultiply
                       : WebGLImageConversion::kAlphaDoNothing;
  state_restorer_->SetFramebufferBindingDirty();
  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);

  // Readback in Skia native byte order (RGBA or BGRA) with kN32_SkColorType.
  const size_t buffer_size = viz::ResourceSizes::CheckedSizeInBytes<size_t>(
      size_, viz::SinglePlaneFormat::kRGBA_8888);
  ReadBackFramebuffer(base::span<uint8_t>(pixels, buffer_size),
                      kN32_SkColorType, op);
}

bool DrawingBuffer::FinishPrepareTransferableResourceSoftware(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  DCHECK(state_restorer_);
  RegisteredBitmap registered = CreateOrRecycleBitmap();
  if (!registered.bitmap) {
    return false;
  }

  ReadFramebufferIntoBitmapPixels(
      static_cast<uint8_t*>(registered.bitmap->memory()));

  if (registered.shared_image) {
    *out_resource = viz::TransferableResource::MakeSoftwareSharedImage(
        registered.shared_image, registered.sync_token, size_,
        viz::SinglePlaneFormat::kBGRA_8888,
        viz::TransferableResource::ResourceSource::kImageLayerBridge);
  } else {
    *out_resource = viz::TransferableResource::MakeSoftwareSharedBitmap(
        registered.bitmap->id(), gpu::SyncToken(), size_,
        viz::SinglePlaneFormat::kRGBA_8888,
        viz::TransferableResource::ResourceSource::kDrawingBuffer);
  }
  out_resource->color_space = back_color_buffer_->color_space;
  out_resource->hdr_metadata = hdr_metadata_;

  // This holds a ref on the DrawingBuffer that will keep it alive until the
  // mailbox is released (and while the release callback is running). It also
  // owns the SharedBitmap.
  *out_release_callback =
      base::BindOnce(&DrawingBuffer::MailboxReleasedSoftware,
                     weak_factory_.GetWeakPtr(), std::move(registered));

  contents_changed_ = false;
  if (preserve_drawing_buffer_ == kDiscard) {
    SetBufferClearNeeded(true);
  }
  return true;
}

bool DrawingBuffer::FinishPrepareTransferableResourceGpu(
    viz::TransferableResource* out_resource,
    scoped_refptr<gpu::ClientSharedImage>* client_si,
    viz::ReleaseCallback* out_release_callback) {
  DCHECK(state_restorer_);
  if (webgl_version_ > kWebGL1) {
    state_restorer_->SetPixelUnpackBufferBindingDirty();
    gl_->BindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
  }

  CopyStagingTextureToBackColorBufferIfNeeded();

  // Specify the buffer that we will put in the mailbox.
  scoped_refptr<ColorBuffer> color_buffer_for_mailbox;
  if (preserve_drawing_buffer_ == kDiscard) {
    // Send the old backbuffer directly into the mailbox, and allocate
    // (or recycle) a new backbuffer.
    color_buffer_for_mailbox = back_color_buffer_;
    back_color_buffer_ = CreateOrRecycleColorBuffer();
    if (!back_color_buffer_) {
      // Context is likely lost.
      return false;
    }
    AttachColorBufferToReadFramebuffer();

    // Explicitly specify that m_fbo (which is now bound to the just-allocated
    // m_backColorBuffer) is not initialized, to save GPU memory bandwidth on
    // tile-based GPU architectures. Note that the depth and stencil attachments
    // are also discarded before multisample resolves, implicit or explicit.
    if (discard_framebuffer_supported_) {
      const GLenum kAttachments[3] = {GL_COLOR_ATTACHMENT0, GL_DEPTH_ATTACHMENT,
                                      GL_STENCIL_ATTACHMENT};
      state_restorer_->SetFramebufferBindingDirty();
      gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
      gl_->DiscardFramebufferEXT(GL_FRAMEBUFFER, 3, kAttachments);
    }
  } else {
    // If we can't discard the backbuffer, create (or recycle) a buffer to put
    // in the mailbox, and copy backbuffer's contents there.
    // TODO(sunnyps): We can skip this test if explicit resolve is used since
    // we'll render to the multisample fbo which will be preserved.
    color_buffer_for_mailbox = CreateOrRecycleColorBuffer();
    if (!color_buffer_for_mailbox) {
      // Context is likely lost.
      return false;
    }
    gl_->CopySubTextureCHROMIUM(
        back_color_buffer_->texture_id(), 0,
        color_buffer_for_mailbox->shared_image->GetTextureTarget(),
        color_buffer_for_mailbox->texture_id(), 0, 0, 0, 0, 0, size_.width(),
        size_.height(), GL_FALSE, GL_FALSE, GL_FALSE);
  }

  // Signal we will no longer access |color_buffer_for_mailbox| before exporting
  // it.
  // Put colorBufferForMailbox into its mailbox, and populate its
  // produceSyncToken with that point.
  {
    // It's critical to order the execution of this context's work relative
    // to other contexts, in particular the compositor. Previously this
    // used to be a Flush, and there was a bug that we didn't flush before
    // synchronizing with the composition, and on some platforms this caused
    // incorrect rendering with complex WebGL content that wasn't always
    // properly flushed to the driver. There is now a basic assumption that
    // there are implicit flushes between contexts at the lowest level.
    color_buffer_for_mailbox->produce_sync_token =
        color_buffer_for_mailbox->EndAccess();
#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_ANDROID)
    // Needed for GPU back-pressure on macOS and Android. Used to be in the
    // middle of the commands above; try to move it to the bottom to allow them
    // to be treated atomically.
    gl_->DescheduleUntilFinishedCHROMIUM();
#endif
  }

  // Populate the output mailbox and callback.
  {
    if (client_si) {
      *client_si = color_buffer_for_mailbox->shared_image;
    }

    *out_resource = viz::TransferableResource::MakeGpu(
        color_buffer_for_mailbox->shared_image,
        color_buffer_for_mailbox->shared_image->GetTextureTarget(),
        color_buffer_for_mailbox->produce_sync_token, size_,
        color_buffer_for_mailbox->format,
        color_buffer_for_mailbox->is_overlay_candidate,
        viz::TransferableResource::ResourceSource::kDrawingBuffer);
    out_resource->color_space = color_buffer_for_mailbox->color_space;
    out_resource->hdr_metadata = hdr_metadata_;
    // This holds a ref on the DrawingBuffer that will keep it alive until the
    // mailbox is released (and while the release callback is running).
    auto func = base::BindOnce(&DrawingBuffer::NotifyMailboxReleasedGpu,
                               color_buffer_for_mailbox);
    exported_color_buffers_.insert(color_buffer_for_mailbox);
    *out_release_callback = std::move(func);
  }

  // Point |m_frontColorBuffer| to the buffer that we are now presenting.
  front_color_buffer_ = color_buffer_for_mailbox;

  contents_changed_ = false;
  if (preserve_drawing_buffer_ == kDiscard) {
    SetBufferClearNeeded(true);
  }
  return true;
}

// static
void DrawingBuffer::NotifyMailboxReleasedGpu(
    scoped_refptr<ColorBuffer> color_buffer,
    const gpu::SyncToken& sync_token,
    bool lost_resource) {
  DCHECK(color_buffer->owning_thread_ref == base::PlatformThread::CurrentRef());

  // Update the SyncToken to ensure that we will wait for it even if we
  // immediately destroy this buffer.
  color_buffer->receive_sync_token = sync_token;
  if (color_buffer->drawing_buffer) {
    color_buffer->drawing_buffer->MailboxReleasedGpu(color_buffer,
                                                     lost_resource);
  }
}

void DrawingBuffer::MailboxReleasedGpu(scoped_refptr<ColorBuffer> color_buffer,
                                       bool lost_resource) {
  exported_color_buffers_.erase(color_buffer);

  // If the mailbox has been returned by the compositor then it is no
  // longer being presented, and so is no longer the front buffer.
  if (color_buffer == front_color_buffer_)
    front_color_buffer_ = nullptr;

  if (destruction_in_progress_ || color_buffer->size != size_ ||
      color_buffer->format != color_buffer_format_ ||
      color_buffer->color_space != color_space_ ||
      gl_->GetGraphicsResetStatusKHR() != GL_NO_ERROR || lost_resource ||
      is_hidden_) {
    return;
  }

  // Creation of image backed mailboxes is very expensive, so be less
  // aggressive about pruning them. Pruning is done in FIFO order.
  size_t cache_limit = kDefaultColorBufferCacheLimit;
  if (color_buffer->is_overlay_candidate) {
    cache_limit = 4;
  }
  while (recycled_color_buffer_queue_.size() >= cache_limit)
    recycled_color_buffer_queue_.TakeLast();

  recycled_color_buffer_queue_.push_front(color_buffer);
}

void DrawingBuffer::MailboxReleasedSoftware(RegisteredBitmap registered,
                                            const gpu::SyncToken& sync_token,
                                            bool lost_resource) {
  if (destruction_in_progress_ || lost_resource || is_hidden_ ||
      registered.bitmap->size() != size_) {
    // Just delete the RegisteredBitmap, which will free the memory and
    // unregister it with the compositor.
    return;
  }

  recycled_bitmaps_.push_back(std::move(registered));
}

scoped_refptr<StaticBitmapImage> DrawingBuffer::TransferToStaticBitmapImage() {
  ScopedStateRestorer scoped_state_restorer(this);

  scoped_refptr<gpu::ClientSharedImage> client_si;
  viz::TransferableResource transferable_resource;
  viz::ReleaseCallback release_callback;
  constexpr bool force_gpu_result = true;
  if (!PrepareTransferableResourceInternal(&client_si, &transferable_resource,
                                           &release_callback,
                                           force_gpu_result)) {
    // If we can't get a mailbox, return an transparent black ImageBitmap.
    // The only situation in which this could happen is when two or more calls
    // to transferToImageBitmap are made back-to-back, or when the context gets
    // lost. We intentionally leave the transparent black image in legacy color
    // space.
    SkBitmap black_bitmap;
    if (!black_bitmap.tryAllocN32Pixels(size_.width(), size_.height()))
      return nullptr;
    black_bitmap.eraseARGB(0, 0, 0, 0);
    sk_sp<SkImage> black_image = SkImages::RasterFromBitmap(black_bitmap);
    if (!black_image)
      return nullptr;
    return UnacceleratedStaticBitmapImage::Create(black_image);
  }

  DCHECK(release_callback);
  DCHECK_EQ(size_.width(), transferable_resource.size.width());
  DCHECK_EQ(size_.height(), transferable_resource.size.height());
  CHECK(client_si);

  // Use the sync token generated after producing the mailbox. Waiting for this
  // before trying to use the mailbox with some other context will ensure it is
  // valid. We wouldn't need to wait for the consume done in this function
  // because the texture id it generated would only be valid for the
  // DrawingBuffer's context anyways.
  const auto& sk_image_sync_token = transferable_resource.sync_token();

  auto sk_color_type = viz::ToClosestSkColorType(
      /*gpu_compositing=*/true, transferable_resource.format);

  const SkImageInfo sk_image_info = SkImageInfo::Make(
      size_.width(), size_.height(), sk_color_type, kPremul_SkAlphaType);

  // TODO(xidachen): Create a small pool of recycled textures from
  // ImageBitmapRenderingContext's transferFromImageBitmap, and try to use them
  // in DrawingBuffer.
  const bool is_origin_top_left =
      client_si->surface_origin() == kTopLeft_GrSurfaceOrigin;
  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      std::move(client_si), sk_image_sync_token,
      /* shared_image_texture_id = */ 0, sk_image_info,
      transferable_resource.texture_target(),
      /*is_origin_top_left=*/is_origin_top_left,
      context_provider_->GetWeakPtr(), base::PlatformThread::CurrentRef(),
      ThreadScheduler::Current()->CleanupTaskRunner(),
      std::move(release_callback),
      /*supports_display_compositing=*/true,
      transferable_resource.is_overlay_candidate);
}

scoped_refptr<DrawingBuffer::ColorBuffer>
DrawingBuffer::CreateOrRecycleColorBuffer() {
  DCHECK(state_restorer_);
  if (!recycled_color_buffer_queue_.empty()) {
    scoped_refptr<ColorBuffer> recycled =
        recycled_color_buffer_queue_.TakeLast();
    DCHECK(recycled->size == size_);
    DCHECK(recycled->color_space == color_space_);
    recycled->BeginAccess(recycled->receive_sync_token, /*readonly=*/false);
    return recycled;
  }
  return CreateColorBuffer(size_);
}

scoped_refptr<CanvasResource> DrawingBuffer::ExportLowLatencyCanvasResource(
    base::WeakPtr<CanvasResourceProvider> resource_provider) {
  // Swap chain must be presented before resource is exported.
  ResolveAndPresentSwapChainIfNeeded();

  scoped_refptr<ColorBuffer> color_buffer =
      using_swap_chain_ ? front_color_buffer_ : back_color_buffer_;
  viz::TransferableResou
"""


```