Response:
The user is asking for a summary of the functionality of the provided C++ code snippet for a Chromium Blink engine file related to WebGL2. I need to identify the core responsibilities of this file based on the included headers and the function definitions within the snippet.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the core class:** The filename `webgl2_rendering_context_base.cc` and the constructor `WebGL2RenderingContextBase` clearly indicate this file defines the base class for the WebGL 2 rendering context in Blink.

2. **Analyze included headers:** The `#include` directives provide clues about the functionalities this class interacts with:
    * `gpu/command_buffer/client/gles2_interface.h`:  Interaction with the underlying OpenGL ES 2.0 (or higher) command buffer. This implies managing GL state and issuing GL calls.
    * `third_party/blink/public/common/privacy_budget/...`: Integration with privacy-related features.
    * `third_party/blink/public/platform/web_graphics_context_3d_provider.h`:  Abstraction for obtaining the underlying graphics context.
    * `third_party/blink/renderer/bindings/modules/v8/webgl_any.h`:  Interaction with JavaScript through V8 bindings.
    * `third_party/blink/renderer/core/html/canvas/...`:  Integration with the HTML `<canvas>` element.
    * `third_party/blink/renderer/core/html/html_image_element.h`, `third_party/blink/renderer/core/html/media/html_video_element.h`, `third_party/blink/renderer/core/imagebitmap/image_bitmap.h`: Handling various image sources for WebGL textures.
    * `third_party/blink/renderer/modules/webgl/...`:  Definitions for WebGL-specific objects like buffers, textures, framebuffers, programs, etc. This points to the class's role in managing the lifecycle and state of these WebGL resources.
    * `third_party/blink/renderer/platform/heap/garbage_collected.h`:  Memory management using Blink's garbage collection.
    * `third_party/blink/renderer/platform/wtf/text/wtf_string.h`: String manipulation.

3. **Examine defined macros:** The `POPULATE_TEX_IMAGE_...` and `POPULATE_TEX_SUB_IMAGE_...` macros suggest this class handles texture uploads and updates. They encapsulate parameters related to different texture dimensions and data sources.

4. **Analyze function definitions:**  The provided snippet includes implementations for functions like `bufferData`, `bufferSubData`, `copyBufferSubData`, `getBufferSubData`, `blitFramebuffer`, `framebufferTextureLayer`, `getInternalformatParameter`, `invalidateFramebuffer`, `readBuffer`, `pixelStorei`, `readPixels`. These functions directly correspond to WebGL 2 API calls, indicating the class is responsible for implementing the core WebGL 2 functionality.

5. **Look for state management:** The presence of member variables like `read_framebuffer_binding_`, `bound_copy_read_buffer_`, `sampler_units_`, `pack_row_length_`, etc., suggests this class maintains the current WebGL state.

6. **Identify error handling:** The `SynthesizeGLError` calls highlight the class's responsibility for error reporting and handling based on WebGL specifications.

7. **Consider the "Base" suffix:** The `Base` suffix in the class name implies this class provides common infrastructure and functionality that might be inherited by more specific WebGL 2 context implementations (though not shown in this snippet).

8. **Connect to JavaScript/HTML/CSS:** The interaction with `HTMLCanvasElement` is evident from the headers. The `bufferData`, `texImage2D`, `readPixels`, and other functions are the bridge between JavaScript WebGL API calls and the underlying graphics system. CSS doesn't directly interact with this *specific* file, but CSS properties can influence the rendering that WebGL performs on the canvas.

9. **Formulate the summary:** Based on the above observations, a comprehensive summary can be constructed, covering resource management, state management, implementation of WebGL 2 API functions, integration with HTML, and error handling.

10. **Structure the answer:** Organize the summary into logical categories like core functionality, relationship with web technologies, and debugging hints to provide a clear and informative response. Acknowledge the "Part 1 of 7" indication and focus the summary on the provided snippet.
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgl/webgl2_rendering_context_base.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/containers/heap_array.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/bindings/modules/v8/webgl_any.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/modules/webgl/webgl_active_info.h"
#include "third_party/blink/renderer/modules/webgl/webgl_buffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_fence_sync.h"
#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_program.h"
#include "third_party/blink/renderer/modules/webgl/webgl_query.h"
#include "third_party/blink/renderer/modules/webgl/webgl_renderbuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_sampler.h"
#include "third_party/blink/renderer/modules/webgl/webgl_sync.h"
#include "third_party/blink/renderer/modules/webgl/webgl_texture.h"
#include "third_party/blink/renderer/modules/webgl/webgl_transform_feedback.h"
#include "third_party/blink/renderer/modules/webgl/webgl_uniform_location.h"
#include "third_party/blink/renderer/modules/webgl/webgl_vertex_array_object.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

// Populates all parameters for texImage2D, including width, height, depth (set
// to 1), and border. Many callers will need to zero-out border in order to
// preserve existing behavior (see https://crbug.com/1313604).
#define POPULATE_TEX_IMAGE_2D_PARAMS(params, src_type) \
  params = {                                           \
      .source_type = src_type,                         \
      .function_id = kTexImage2D,                      \
      .target = target,                                \
      .level = level,                                  \
      .internalformat = internalformat,                \
      .width = width,                                  \
      .height = height,                                \
      .depth = 1,                                      \
      .border = border,                                \
      .format = format,                                \
      .type = type,                                    \
  };                                                   \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, src_type) \
  params = {                                               \
      .source_type = src_type,                             \
      .function_id = kTexSubImage2D,                       \
      .target = target,                                    \
      .level = level,                                      \
      .xoffset = xoffset,                                  \
      .yoffset = yoffset,                                  \
      .width = width,                                      \
      .height = height,                                    \
      .depth = 1,                                          \
      .format = format,                                    \
      .type = type,                                        \
  };                                                       \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_IMAGE_3D_PARAMS(params, src_type) \
  params = {                                           \
      .source_type = src_type,                         \
      .function_id = kTexImage3D,                      \
      .target = target,                                \
      .level = level,                                  \
      .internalformat = internalformat,                \
      .width = width,                                  \
      .height = height,                                \
      .depth = depth,                                  \
      .border = border,                                \
      .format = format,                                \
      .type = type,                                    \
  };                                                   \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, src_type) \
  params = {                                               \
      .source_type = src_type,                             \
      .function_id = kTexSubImage3D,                       \
      .target = target,                                    \
      .level = level,                                      \
      .xoffset = xoffset,                                  \
      .yoffset = yoffset,                                  \
      .zoffset = zoffset,                                  \
      .width = width,                                      \
      .height = height,                                    \
      .depth = depth,                                      \
      .format = format,                                    \
      .type = type,                                        \
  };                                                       \
  GetCurrentUnpackState(params)

namespace blink {

namespace {

const GLuint64 kMaxClientWaitTimeout = 0u;

// TODO(kainino): Change outByteLength to GLuint and change the associated
// range checking (and all uses) - overflow becomes possible in cases below
bool ValidateSubSourceAndGetData(DOMArrayBufferView* view,
                                 int64_t sub_offset,
                                 int64_t sub_length,
                                 void** out_base_address,
                                 int64_t* out_byte_length) {
  // This is guaranteed to be non-null by DOM.
  DCHECK(view);

  size_t type_size = view->TypeSize();
  DCHECK_GE(8u, type_size);
  int64_t byte_length = 0;
  if (sub_length) {
    // type size is at most 8, so no overflow.
    byte_length = sub_length * type_size;
  }
  int64_t byte_offset = 0;
  if (sub_offset) {
    // type size is at most 8, so no overflow.
    byte_offset = sub_offset * type_size;
  }
  base::CheckedNumeric<size_t> total = byte_offset;
  total += byte_length;
  if (!total.IsValid() || total.ValueOrDie() > view->byteLength()) {
    return false;
  }
  if (!byte_length) {
    byte_length = view->byteLength() - byte_offset;
  }
  const auto data =
      view->ByteSpanMaybeShared().subspan(static_cast<size_t>(byte_offset));
  *out_base_address = data.data();
  *out_byte_length = byte_length;
  return true;
}

class PointableStringArray {
 public:
  PointableStringArray(const Vector<String>& strings)
      : data_(std::make_unique<std::string[]>(strings.size())),
        pointers_(strings.size()) {
    DCHECK(strings.size() < std::numeric_limits<GLsizei>::max());
    for (wtf_size_t i = 0; i < strings.size(); ++i) {
      // Strings must never move once they are stored in data_...
      data_[i] = strings[i].Ascii();
      // ... so that the c_str() remains valid.
      pointers_[i] = data_[i].c_str();
    }
  }

  GLsizei size() const { return pointers_.size(); }
  char const* const* data() const { return pointers_.data(); }

 private:
  std::unique_ptr<std::string[]> data_;
  Vector<const char*> pointers_;
};

}  // namespace

// These enums are from manual pages for glTexStorage2D/glTexStorage3D.
static constexpr auto kSupportedInternalFormatsStorage = std::to_array<GLenum>({
    GL_R8,
    GL_R8_SNORM,
    GL_R16F,
    GL_R32F,
    GL_R8UI,
    GL_R8I,
    GL_R16UI,
    GL_R16I,
    GL_R32UI,
    GL_R32I,
    GL_RG8,
    GL_RG8_SNORM,
    GL_RG16F,
    GL_RG32F,
    GL_RG8UI,
    GL_RG8I,
    GL_RG16UI,
    GL_RG16I,
    GL_RG32UI,
    GL_RG32I,
    GL_RGB8,
    GL_SRGB8,
    GL_RGB565,
    GL_RGB8_SNORM,
    GL_R11F_G11F_B10F,
    GL_RGB9_E5,
    GL_RGB16F,
    GL_RGB32F,
    GL_RGB8UI,
    GL_RGB8I,
    GL_RGB16UI,
    GL_RGB16I,
    GL_RGB32UI,
    GL_RGB32I,
    GL_RGBA8,
    GL_SRGB8_ALPHA8,
    GL_RGBA8_SNORM,
    GL_RGB5_A1,
    GL_RGBA4,
    GL_RGB10_A2,
    GL_RGBA16F,
    GL_RGBA32F,
    GL_RGBA8UI,
    GL_RGBA8I,
    GL_RGB10_A2UI,
    GL_RGBA16UI,
    GL_RGBA16I,
    GL_RGBA32UI,
    GL_RGBA32I,
    GL_DEPTH_COMPONENT16,
    GL_DEPTH_COMPONENT24,
    GL_DEPTH_COMPONENT32F,
    GL_DEPTH24_STENCIL8,
    GL_DEPTH32F_STENCIL8,
});

WebGL2RenderingContextBase::WebGL2RenderingContextBase(
    CanvasRenderingContextHost* host,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    const CanvasContextCreationAttributesCore& requested_attributes,
    Platform::ContextType context_type)
    : WebGLRenderingContextBase(host,
                                std::move(context_provider),
                                graphics_info,
                                requested_attributes,
                                context_type) {
  for (size_t i = 0; i < std::size(kSupportedInternalFormatsStorage); ++i) {
    supported_internal_formats_storage_.insert(
        kSupportedInternalFormatsStorage[i]);
  }
}

void WebGL2RenderingContextBase::DestroyContext() {
  WebGLRenderingContextBase::DestroyContext();
}

void WebGL2RenderingContextBase::InitializeNewContext() {
  DCHECK(!isContextLost());
  DCHECK(GetDrawingBuffer());

  read_framebuffer_binding_ = nullptr;

  bound_copy_read_buffer_ = nullptr;
  bound_copy_write_buffer_ = nullptr;
  bound_pixel_pack_buffer_ = nullptr;
  bound_pixel_unpack_buffer_ = nullptr;
  bound_transform_feedback_buffer_ = nullptr;
  bound_uniform_buffer_ = nullptr;

  current_boolean_occlusion_query_ = nullptr;
  current_transform_feedback_primitives_written_query_ = nullptr;
  current_elapsed_query_ = nullptr;

  GLint num_combined_texture_image_units = 0;
  ContextGL()->GetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS,
                           &num_combined_texture_image_units);
  sampler_units_.clear();
  sampler_units_.resize(num_combined_texture_image_units);

  max_transform_feedback_separate_attribs_ = 0;
  // This must be queried before instantiating any transform feedback
  // objects.
  ContextGL()->GetIntegerv(GL_MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS,
                           &max_transform_feedback_separate_attribs_);
  // Create a default transform feedback object so there is a place to
  // hold any bound buffers.
  default_transform_feedback_ = MakeGarbageCollected<WebGLTransformFeedback>(
      this, WebGLTransformFeedback::TFType::kDefault);
  transform_feedback_binding_ = default_transform_feedback_;

  GLint max_uniform_buffer_bindings = 0;
  ContextGL()->GetIntegerv(GL_MAX_UNIFORM_BUFFER_BINDINGS,
                           &max_uniform_buffer_bindings);
  bound_indexed_uniform_buffers_.clear();
  bound_indexed_uniform_buffers_.resize(max_uniform_buffer_bindings);

  pack_row_length_ = 0;
  pack_skip_pixels_ = 0;
  pack_skip_rows_ = 0;
  unpack_row_length_ = 0;
  unpack_image_height_ = 0;
  unpack_skip_pixels_ = 0;
  unpack_skip_rows_ = 0;
  unpack_skip_images_ = 0;

  WebGLRenderingContextBase::InitializeNewContext();
}

void WebGL2RenderingContextBase::bufferData(
    GLenum target,
    MaybeShared<DOMArrayBufferView> src_data,
    GLenum usage,
    int64_t src_offset,
    GLuint length) {
  if (isContextLost())
    return;
  void* sub_base_address = nullptr;
  int64_t sub_byte_length = 0;
  if (!ValidateSubSourceAndGetData(src_data.Get(), src_offset, length,
                                   &sub_base_address, &sub_byte_length)) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferData",
                      "srcOffset + length too large");
    return;
  }
  BufferDataImpl(target, static_cast<GLsizeiptr>(sub_byte_length),
                 sub_base_address, usage);
}

void WebGL2RenderingContextBase::bufferData(GLenum target,
                                            int64_t size,
                                            GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, size, usage);
}

void WebGL2RenderingContextBase::bufferData(GLenum target,
                                            DOMArrayBufferBase* data,
                                            GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, data, usage);
}

void WebGL2RenderingContextBase::bufferData(
    GLenum target,
    MaybeShared<DOMArrayBufferView> data,
    GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, data, usage);
}

void WebGL2RenderingContextBase::bufferSubData(
    GLenum target,
    int64_t dst_byte_offset,
    MaybeShared<DOMArrayBufferView> src_data,
    int64_t src_offset,
    GLuint length) {
  if (isContextLost())
    return;
  void* sub_base_address = nullptr;
  int64_t sub_byte_length = 0;
  if (!ValidateSubSourceAndGetData(src_data.Get(), src_offset, length,
                                   &sub_base_address, &sub_byte_length)) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferSubData",
                      "srcOffset + length too large");
    return;
  }
  BufferSubDataImpl(target, dst_byte_offset,
                    static_cast<GLsizeiptr>(sub_byte_length), sub_base_address);
}

void WebGL2RenderingContextBase::bufferSubData(GLenum target,
                                               int64_t offset,
                                               base::span<const uint8_t> data) {
  WebGLRenderingContextBase::bufferSubData(target, offset, data);
}

void WebGL2RenderingContextBase::copyBufferSubData(GLenum read_target,
                                                   GLenum write_target,
                                                   int64_t read_offset,
                                                   int64_t write_offset,
                                                   int64_t size) {
  if (isContextLost())
    return;

  if (!ValidateValueFitNonNegInt32("copyBufferSubData", "readOffset",
                                   read_offset) ||
      !ValidateValueFitNonNegInt32("copyBufferSubData", "writeOffset",
                                   write_offset) ||
      !ValidateValueFitNonNegInt32("copyBufferSubData", "size", size)) {
    return;
  }

  WebGLBuffer* read_buffer =
      ValidateBufferDataTarget("copyBufferSubData", read_target);
  if (!read_buffer)
    return;

  WebGLBuffer* write_buffer =
      ValidateBufferDataTarget("copyBufferSubData", write_target);
  if (!write_buffer)
    return;

  if (read_offset + size > read_buffer->GetSize() ||
      write_offset + size > write_buffer->GetSize()) {
    SynthesizeGLError(GL_INVALID_VALUE, "copyBufferSubData", "buffer overflow");
    return;
  }

  if ((write_buffer->GetInitialTarget() == GL_ELEMENT_ARRAY_BUFFER &&
       read_buffer->GetInitialTarget() != GL_ELEMENT_ARRAY_BUFFER) ||
      (write_buffer->GetInitialTarget() != GL_ELEMENT_ARRAY_BUFFER &&
       read_buffer->GetInitialTarget() == GL_ELEMENT_ARRAY_BUFFER)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "copyBufferSubData",
                      "Cannot copy into an element buffer destination from a "
                      "non-element buffer source");
    return;
  }

  if (write_buffer->GetInitialTarget() == 0)
    write_buffer->SetInitialTarget(read_buffer->GetInitialTarget());

  ContextGL()->CopyBufferSubData(
      read_target, write_target, static_cast<GLintptr>(read_offset),
      static_cast<GLintptr>(write_offset), static_cast<GLsizeiptr>(size));
}

void WebGL2RenderingContextBase::getBufferSubData(
    GLenum target,
    int64_t src_byte_offset,
    MaybeShared<DOMArrayBufferView> dst_data,
    int64_t dst_offset,
    GLuint length) {
  WebGLBuffer* source_buffer = nullptr;
  void* destination_data_ptr = nullptr;
  int64_t destination_byte_length = 0;
  const char* message = ValidateGetBufferSubData(
      __FUNCTION__, target, src_byte_offset, dst_data.Get(), dst_offset, length,
      &source_buffer, &destination_data_ptr, &destination_byte_length);
  if (message) {
    // If there was a GL error, it was already synthesized in
    // validateGetBufferSubData, so it's not done here.
    return;
  }
  if (!ValidateBufferDataBufferSize("getBufferSubData",
                                    destination_byte_length)) {
    return;
  }

  // If the length of the copy is zero, this is a no-op.
  if (!destination_byte_length) {
    return;
  }

  void* mapped_data = ContextGL()->MapBufferRange(
      target, static_cast<GLintptr>(src_byte_offset),
      static_cast<GLsizeiptr>(destination_byte_length), GL_MAP_READ_BIT);

  if (!mapped_data)
    return;

  memcpy(destination_data_ptr, mapped_data,
         static_cast<size_t>(destination_byte_length));

  ContextGL()->UnmapBuffer(target);
}

void WebGL2RenderingContextBase::blitFramebuffer(GLint src_x0,
                                                 GLint src_y0,
                                                 GLint src_x1,
                                                 GLint src_y1,
                                                 GLint dst_x0,
                                                 GLint dst_y0,
                                                 GLint dst_x1,
                                                 GLint dst_y1,
                                                 GLbitfield mask,
                                                 GLenum filter) {
  if (isContextLost())
    return;

  ContextGL()->BlitFramebufferCHROMIUM(src_x0, src_y0, src_x1, src_y1, dst_x0,
                                       dst_y0, dst_x1, dst_y1, mask, filter);
  MarkContextChanged(kCanvasChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
}

bool WebGL2RenderingContextBase::ValidateTexFuncLayer(const char* function_name,
                                                      GLenum tex_target,
                                                      GLint layer) {
  if (layer < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "layer out of range");
    return false;
  }
  switch (tex_target) {
    case GL_TEXTURE_3D:
      if (layer > max3d_texture_size_ - 1) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "layer out of range");
        return false;
      }
      break;
    case GL_TEXTURE_2D_ARRAY:
      if (layer > max_array_texture_layers_ - 1) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "layer out of range");
        return false;
      }
      break;
    default:
      NOTREACHED();
  }
  return true;
}

void WebGL2RenderingContextBase::framebufferTextureLayer(GLenum target,
                                                         GLenum attachment,
                                                         WebGLTexture* texture,
                                                         GLint level,
                                                         GLint layer) {
  if (isContextLost() ||
      !ValidateFramebufferFuncParameters("framebufferTextureLayer", target,
                                         attachment) ||
      !ValidateNullableWebGLObject("framebufferTextureLayer", texture))
    return;
  GLenum textarget = texture ? texture->GetTarget() : 0;
  if (texture) {
    if (textarget != GL_TEXTURE_3D && textarget != GL_TEXTURE_2D_ARRAY) {
      SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                        "invalid texture type");
      return;
    }
    if (!ValidateTexFuncLayer("framebufferTextureLayer", textarget, layer))
      return;
    if (!ValidateTexFuncLevel("framebufferTextureLayer", textarget, level))
      return;
  }

  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (!framebuffer_binding || !framebuffer_binding->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                      "no framebuffer bound");
    return;
  }
  // Don't allow modifications to opaque framebuffer attachements.
  if (framebuffer_binding && framebuffer_binding->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                      "opaque framebuffer bound");
    return;
  }
  framebuffer_binding->SetAttachmentForBoundFramebuffer(
      target, attachment, textarget, texture, level, layer, 0);
  ApplyDepthAndStencilTest();
}

ScriptValue WebGL2RenderingContextBase::getInternalformatParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum internalformat,
    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());

  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                      "invalid target");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (internalformat) {
    // Renderbuffer doesn't support unsized internal formats,
    // though GL_RGB and GL_RGBA are color-renderable.
    case GL_RGB:
    case GL_RGBA:
    // Multisampling is not supported for signed and unsigned integer internal
    // formats.
    case GL_R8UI:
    case GL_R8I:
    case GL_R16UI:
    case GL_R16I:
    case GL_R32UI:
    case GL_R32I:
    case GL_RG8UI:
    case GL_RG8I:
    case GL_RG16UI:
    case GL_RG16I:
    case GL_RG32UI:
    case GL_RG32I:
    case GL_RGBA8UI:
    case GL_RGBA8I:
    case GL_RGB10_A2UI:
    case GL_RGBA16UI:
    case GL_RGBA16I:
    case GL_RGBA32UI:
    case GL_RGBA32I:
      return WebGLAny(script_state, DOMInt32Array::Create(0));
    case GL_R8:
    case GL_RG8:
    case GL_RGB8:
    case GL_RGB565:
    case GL_RGBA8:
    case GL_SRGB8_ALPHA8:
    case GL_RGB5_A1:
    case GL_RGBA4:
    case GL_RGB10_A2:
    case GL_DEPTH_COMPONENT16:
    case GL_DEPTH_COMPONENT24:
    case GL_DEPTH_COMPONENT32F:
    case GL_DEPTH24_STENCIL8:
    case GL_DEPTH32F_STENCIL8:
    case GL_STENCIL_INDEX8:
      break;
    case GL_R16_EXT:
    case GL_RG16_EXT:
    case GL_RGBA16_EXT:
      if (!ExtensionEnabled(kEXTTextureNorm16Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                          "invalid internalformat when EXT_texture_norm16 "
                          "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    case GL_R16F:
    case GL_RG16F:
    case GL_RGBA16F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName) &&
          !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
        SynthesizeGLError(
            GL_INVALID_ENUM, "getInternalformatParameter",
            "invalid internalformat when EXT_color_buffer_[half_]float "
            "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    case GL_R32F:
    case GL_RG32F:
    case GL_RGBA32F:
    case GL_R11F_G11F_B10F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                          "invalid internalformat when EXT_color_buffer_float "
                          "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                        "invalid internalformat");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (pname) {
    case GL_SAMPLES: {
      GLint length = -1;
      ContextGL()->GetInternalformativ(target, internalformat,
                                       GL_NUM_SAMPLE_COUNTS, 1, &length);
      if (length <= 0) {
        return WebGLAny(script_state, DOMInt32Array::Create(0));
      }
      auto values = base::HeapArray<GLint>::WithSize(length);
      ContextGL()->GetInternalformativ(target, internalformat, GL_SAMPLES,
                                       length, values.data());
      RecordInternalFormatParameter(internalformat, values.data(), length);
      return WebGLAny(script_state, DOMInt32Array::Create(values));
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

// TODO(crbug.com/351564777): should be UNSAFE_BUFFER_USAGE.
void WebGL2RenderingContextBase::RecordInternalFormatParameter(
    GLenum internalformat,
    GLint* values,
    
Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgl/webgl2_rendering_context_base.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/containers/heap_array.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/bindings/modules/v8/webgl_any.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/modules/webgl/webgl_active_info.h"
#include "third_party/blink/renderer/modules/webgl/webgl_buffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_fence_sync.h"
#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_program.h"
#include "third_party/blink/renderer/modules/webgl/webgl_query.h"
#include "third_party/blink/renderer/modules/webgl/webgl_renderbuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_sampler.h"
#include "third_party/blink/renderer/modules/webgl/webgl_sync.h"
#include "third_party/blink/renderer/modules/webgl/webgl_texture.h"
#include "third_party/blink/renderer/modules/webgl/webgl_transform_feedback.h"
#include "third_party/blink/renderer/modules/webgl/webgl_uniform_location.h"
#include "third_party/blink/renderer/modules/webgl/webgl_vertex_array_object.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

// Populates all parameters for texImage2D, including width, height, depth (set
// to 1), and border. Many callers will need to zero-out border in order to
// preserve existing behavior (see https://crbug.com/1313604).
#define POPULATE_TEX_IMAGE_2D_PARAMS(params, src_type) \
  params = {                                           \
      .source_type = src_type,                         \
      .function_id = kTexImage2D,                      \
      .target = target,                                \
      .level = level,                                  \
      .internalformat = internalformat,                \
      .width = width,                                  \
      .height = height,                                \
      .depth = 1,                                      \
      .border = border,                                \
      .format = format,                                \
      .type = type,                                    \
  };                                                   \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, src_type) \
  params = {                                               \
      .source_type = src_type,                             \
      .function_id = kTexSubImage2D,                       \
      .target = target,                                    \
      .level = level,                                      \
      .xoffset = xoffset,                                  \
      .yoffset = yoffset,                                  \
      .width = width,                                      \
      .height = height,                                    \
      .depth = 1,                                          \
      .format = format,                                    \
      .type = type,                                        \
  };                                                       \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_IMAGE_3D_PARAMS(params, src_type) \
  params = {                                           \
      .source_type = src_type,                         \
      .function_id = kTexImage3D,                      \
      .target = target,                                \
      .level = level,                                  \
      .internalformat = internalformat,                \
      .width = width,                                  \
      .height = height,                                \
      .depth = depth,                                  \
      .border = border,                                \
      .format = format,                                \
      .type = type,                                    \
  };                                                   \
  GetCurrentUnpackState(params)

#define POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, src_type) \
  params = {                                               \
      .source_type = src_type,                             \
      .function_id = kTexSubImage3D,                       \
      .target = target,                                    \
      .level = level,                                      \
      .xoffset = xoffset,                                  \
      .yoffset = yoffset,                                  \
      .zoffset = zoffset,                                  \
      .width = width,                                      \
      .height = height,                                    \
      .depth = depth,                                      \
      .format = format,                                    \
      .type = type,                                        \
  };                                                       \
  GetCurrentUnpackState(params)

namespace blink {

namespace {

const GLuint64 kMaxClientWaitTimeout = 0u;

// TODO(kainino): Change outByteLength to GLuint and change the associated
// range checking (and all uses) - overflow becomes possible in cases below
bool ValidateSubSourceAndGetData(DOMArrayBufferView* view,
                                 int64_t sub_offset,
                                 int64_t sub_length,
                                 void** out_base_address,
                                 int64_t* out_byte_length) {
  // This is guaranteed to be non-null by DOM.
  DCHECK(view);

  size_t type_size = view->TypeSize();
  DCHECK_GE(8u, type_size);
  int64_t byte_length = 0;
  if (sub_length) {
    // type size is at most 8, so no overflow.
    byte_length = sub_length * type_size;
  }
  int64_t byte_offset = 0;
  if (sub_offset) {
    // type size is at most 8, so no overflow.
    byte_offset = sub_offset * type_size;
  }
  base::CheckedNumeric<size_t> total = byte_offset;
  total += byte_length;
  if (!total.IsValid() || total.ValueOrDie() > view->byteLength()) {
    return false;
  }
  if (!byte_length) {
    byte_length = view->byteLength() - byte_offset;
  }
  const auto data =
      view->ByteSpanMaybeShared().subspan(static_cast<size_t>(byte_offset));
  *out_base_address = data.data();
  *out_byte_length = byte_length;
  return true;
}

class PointableStringArray {
 public:
  PointableStringArray(const Vector<String>& strings)
      : data_(std::make_unique<std::string[]>(strings.size())),
        pointers_(strings.size()) {
    DCHECK(strings.size() < std::numeric_limits<GLsizei>::max());
    for (wtf_size_t i = 0; i < strings.size(); ++i) {
      // Strings must never move once they are stored in data_...
      data_[i] = strings[i].Ascii();
      // ... so that the c_str() remains valid.
      pointers_[i] = data_[i].c_str();
    }
  }

  GLsizei size() const { return pointers_.size(); }
  char const* const* data() const { return pointers_.data(); }

 private:
  std::unique_ptr<std::string[]> data_;
  Vector<const char*> pointers_;
};

}  // namespace

// These enums are from manual pages for glTexStorage2D/glTexStorage3D.
static constexpr auto kSupportedInternalFormatsStorage = std::to_array<GLenum>({
    GL_R8,
    GL_R8_SNORM,
    GL_R16F,
    GL_R32F,
    GL_R8UI,
    GL_R8I,
    GL_R16UI,
    GL_R16I,
    GL_R32UI,
    GL_R32I,
    GL_RG8,
    GL_RG8_SNORM,
    GL_RG16F,
    GL_RG32F,
    GL_RG8UI,
    GL_RG8I,
    GL_RG16UI,
    GL_RG16I,
    GL_RG32UI,
    GL_RG32I,
    GL_RGB8,
    GL_SRGB8,
    GL_RGB565,
    GL_RGB8_SNORM,
    GL_R11F_G11F_B10F,
    GL_RGB9_E5,
    GL_RGB16F,
    GL_RGB32F,
    GL_RGB8UI,
    GL_RGB8I,
    GL_RGB16UI,
    GL_RGB16I,
    GL_RGB32UI,
    GL_RGB32I,
    GL_RGBA8,
    GL_SRGB8_ALPHA8,
    GL_RGBA8_SNORM,
    GL_RGB5_A1,
    GL_RGBA4,
    GL_RGB10_A2,
    GL_RGBA16F,
    GL_RGBA32F,
    GL_RGBA8UI,
    GL_RGBA8I,
    GL_RGB10_A2UI,
    GL_RGBA16UI,
    GL_RGBA16I,
    GL_RGBA32UI,
    GL_RGBA32I,
    GL_DEPTH_COMPONENT16,
    GL_DEPTH_COMPONENT24,
    GL_DEPTH_COMPONENT32F,
    GL_DEPTH24_STENCIL8,
    GL_DEPTH32F_STENCIL8,
});

WebGL2RenderingContextBase::WebGL2RenderingContextBase(
    CanvasRenderingContextHost* host,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    const CanvasContextCreationAttributesCore& requested_attributes,
    Platform::ContextType context_type)
    : WebGLRenderingContextBase(host,
                                std::move(context_provider),
                                graphics_info,
                                requested_attributes,
                                context_type) {
  for (size_t i = 0; i < std::size(kSupportedInternalFormatsStorage); ++i) {
    supported_internal_formats_storage_.insert(
        kSupportedInternalFormatsStorage[i]);
  }
}

void WebGL2RenderingContextBase::DestroyContext() {
  WebGLRenderingContextBase::DestroyContext();
}

void WebGL2RenderingContextBase::InitializeNewContext() {
  DCHECK(!isContextLost());
  DCHECK(GetDrawingBuffer());

  read_framebuffer_binding_ = nullptr;

  bound_copy_read_buffer_ = nullptr;
  bound_copy_write_buffer_ = nullptr;
  bound_pixel_pack_buffer_ = nullptr;
  bound_pixel_unpack_buffer_ = nullptr;
  bound_transform_feedback_buffer_ = nullptr;
  bound_uniform_buffer_ = nullptr;

  current_boolean_occlusion_query_ = nullptr;
  current_transform_feedback_primitives_written_query_ = nullptr;
  current_elapsed_query_ = nullptr;

  GLint num_combined_texture_image_units = 0;
  ContextGL()->GetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS,
                           &num_combined_texture_image_units);
  sampler_units_.clear();
  sampler_units_.resize(num_combined_texture_image_units);

  max_transform_feedback_separate_attribs_ = 0;
  // This must be queried before instantiating any transform feedback
  // objects.
  ContextGL()->GetIntegerv(GL_MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS,
                           &max_transform_feedback_separate_attribs_);
  // Create a default transform feedback object so there is a place to
  // hold any bound buffers.
  default_transform_feedback_ = MakeGarbageCollected<WebGLTransformFeedback>(
      this, WebGLTransformFeedback::TFType::kDefault);
  transform_feedback_binding_ = default_transform_feedback_;

  GLint max_uniform_buffer_bindings = 0;
  ContextGL()->GetIntegerv(GL_MAX_UNIFORM_BUFFER_BINDINGS,
                           &max_uniform_buffer_bindings);
  bound_indexed_uniform_buffers_.clear();
  bound_indexed_uniform_buffers_.resize(max_uniform_buffer_bindings);

  pack_row_length_ = 0;
  pack_skip_pixels_ = 0;
  pack_skip_rows_ = 0;
  unpack_row_length_ = 0;
  unpack_image_height_ = 0;
  unpack_skip_pixels_ = 0;
  unpack_skip_rows_ = 0;
  unpack_skip_images_ = 0;

  WebGLRenderingContextBase::InitializeNewContext();
}

void WebGL2RenderingContextBase::bufferData(
    GLenum target,
    MaybeShared<DOMArrayBufferView> src_data,
    GLenum usage,
    int64_t src_offset,
    GLuint length) {
  if (isContextLost())
    return;
  void* sub_base_address = nullptr;
  int64_t sub_byte_length = 0;
  if (!ValidateSubSourceAndGetData(src_data.Get(), src_offset, length,
                                   &sub_base_address, &sub_byte_length)) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferData",
                      "srcOffset + length too large");
    return;
  }
  BufferDataImpl(target, static_cast<GLsizeiptr>(sub_byte_length),
                 sub_base_address, usage);
}

void WebGL2RenderingContextBase::bufferData(GLenum target,
                                            int64_t size,
                                            GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, size, usage);
}

void WebGL2RenderingContextBase::bufferData(GLenum target,
                                            DOMArrayBufferBase* data,
                                            GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, data, usage);
}

void WebGL2RenderingContextBase::bufferData(
    GLenum target,
    MaybeShared<DOMArrayBufferView> data,
    GLenum usage) {
  WebGLRenderingContextBase::bufferData(target, data, usage);
}

void WebGL2RenderingContextBase::bufferSubData(
    GLenum target,
    int64_t dst_byte_offset,
    MaybeShared<DOMArrayBufferView> src_data,
    int64_t src_offset,
    GLuint length) {
  if (isContextLost())
    return;
  void* sub_base_address = nullptr;
  int64_t sub_byte_length = 0;
  if (!ValidateSubSourceAndGetData(src_data.Get(), src_offset, length,
                                   &sub_base_address, &sub_byte_length)) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferSubData",
                      "srcOffset + length too large");
    return;
  }
  BufferSubDataImpl(target, dst_byte_offset,
                    static_cast<GLsizeiptr>(sub_byte_length), sub_base_address);
}

void WebGL2RenderingContextBase::bufferSubData(GLenum target,
                                               int64_t offset,
                                               base::span<const uint8_t> data) {
  WebGLRenderingContextBase::bufferSubData(target, offset, data);
}

void WebGL2RenderingContextBase::copyBufferSubData(GLenum read_target,
                                                   GLenum write_target,
                                                   int64_t read_offset,
                                                   int64_t write_offset,
                                                   int64_t size) {
  if (isContextLost())
    return;

  if (!ValidateValueFitNonNegInt32("copyBufferSubData", "readOffset",
                                   read_offset) ||
      !ValidateValueFitNonNegInt32("copyBufferSubData", "writeOffset",
                                   write_offset) ||
      !ValidateValueFitNonNegInt32("copyBufferSubData", "size", size)) {
    return;
  }

  WebGLBuffer* read_buffer =
      ValidateBufferDataTarget("copyBufferSubData", read_target);
  if (!read_buffer)
    return;

  WebGLBuffer* write_buffer =
      ValidateBufferDataTarget("copyBufferSubData", write_target);
  if (!write_buffer)
    return;

  if (read_offset + size > read_buffer->GetSize() ||
      write_offset + size > write_buffer->GetSize()) {
    SynthesizeGLError(GL_INVALID_VALUE, "copyBufferSubData", "buffer overflow");
    return;
  }

  if ((write_buffer->GetInitialTarget() == GL_ELEMENT_ARRAY_BUFFER &&
       read_buffer->GetInitialTarget() != GL_ELEMENT_ARRAY_BUFFER) ||
      (write_buffer->GetInitialTarget() != GL_ELEMENT_ARRAY_BUFFER &&
       read_buffer->GetInitialTarget() == GL_ELEMENT_ARRAY_BUFFER)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "copyBufferSubData",
                      "Cannot copy into an element buffer destination from a "
                      "non-element buffer source");
    return;
  }

  if (write_buffer->GetInitialTarget() == 0)
    write_buffer->SetInitialTarget(read_buffer->GetInitialTarget());

  ContextGL()->CopyBufferSubData(
      read_target, write_target, static_cast<GLintptr>(read_offset),
      static_cast<GLintptr>(write_offset), static_cast<GLsizeiptr>(size));
}

void WebGL2RenderingContextBase::getBufferSubData(
    GLenum target,
    int64_t src_byte_offset,
    MaybeShared<DOMArrayBufferView> dst_data,
    int64_t dst_offset,
    GLuint length) {
  WebGLBuffer* source_buffer = nullptr;
  void* destination_data_ptr = nullptr;
  int64_t destination_byte_length = 0;
  const char* message = ValidateGetBufferSubData(
      __FUNCTION__, target, src_byte_offset, dst_data.Get(), dst_offset, length,
      &source_buffer, &destination_data_ptr, &destination_byte_length);
  if (message) {
    // If there was a GL error, it was already synthesized in
    // validateGetBufferSubData, so it's not done here.
    return;
  }
  if (!ValidateBufferDataBufferSize("getBufferSubData",
                                    destination_byte_length)) {
    return;
  }

  // If the length of the copy is zero, this is a no-op.
  if (!destination_byte_length) {
    return;
  }

  void* mapped_data = ContextGL()->MapBufferRange(
      target, static_cast<GLintptr>(src_byte_offset),
      static_cast<GLsizeiptr>(destination_byte_length), GL_MAP_READ_BIT);

  if (!mapped_data)
    return;

  memcpy(destination_data_ptr, mapped_data,
         static_cast<size_t>(destination_byte_length));

  ContextGL()->UnmapBuffer(target);
}

void WebGL2RenderingContextBase::blitFramebuffer(GLint src_x0,
                                                 GLint src_y0,
                                                 GLint src_x1,
                                                 GLint src_y1,
                                                 GLint dst_x0,
                                                 GLint dst_y0,
                                                 GLint dst_x1,
                                                 GLint dst_y1,
                                                 GLbitfield mask,
                                                 GLenum filter) {
  if (isContextLost())
    return;

  ContextGL()->BlitFramebufferCHROMIUM(src_x0, src_y0, src_x1, src_y1, dst_x0,
                                       dst_y0, dst_x1, dst_y1, mask, filter);
  MarkContextChanged(kCanvasChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
}

bool WebGL2RenderingContextBase::ValidateTexFuncLayer(const char* function_name,
                                                      GLenum tex_target,
                                                      GLint layer) {
  if (layer < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "layer out of range");
    return false;
  }
  switch (tex_target) {
    case GL_TEXTURE_3D:
      if (layer > max3d_texture_size_ - 1) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "layer out of range");
        return false;
      }
      break;
    case GL_TEXTURE_2D_ARRAY:
      if (layer > max_array_texture_layers_ - 1) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "layer out of range");
        return false;
      }
      break;
    default:
      NOTREACHED();
  }
  return true;
}

void WebGL2RenderingContextBase::framebufferTextureLayer(GLenum target,
                                                         GLenum attachment,
                                                         WebGLTexture* texture,
                                                         GLint level,
                                                         GLint layer) {
  if (isContextLost() ||
      !ValidateFramebufferFuncParameters("framebufferTextureLayer", target,
                                         attachment) ||
      !ValidateNullableWebGLObject("framebufferTextureLayer", texture))
    return;
  GLenum textarget = texture ? texture->GetTarget() : 0;
  if (texture) {
    if (textarget != GL_TEXTURE_3D && textarget != GL_TEXTURE_2D_ARRAY) {
      SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                        "invalid texture type");
      return;
    }
    if (!ValidateTexFuncLayer("framebufferTextureLayer", textarget, layer))
      return;
    if (!ValidateTexFuncLevel("framebufferTextureLayer", textarget, level))
      return;
  }

  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (!framebuffer_binding || !framebuffer_binding->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                      "no framebuffer bound");
    return;
  }
  // Don't allow modifications to opaque framebuffer attachements.
  if (framebuffer_binding && framebuffer_binding->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTextureLayer",
                      "opaque framebuffer bound");
    return;
  }
  framebuffer_binding->SetAttachmentForBoundFramebuffer(
      target, attachment, textarget, texture, level, layer, 0);
  ApplyDepthAndStencilTest();
}

ScriptValue WebGL2RenderingContextBase::getInternalformatParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum internalformat,
    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());

  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                      "invalid target");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (internalformat) {
    // Renderbuffer doesn't support unsized internal formats,
    // though GL_RGB and GL_RGBA are color-renderable.
    case GL_RGB:
    case GL_RGBA:
    // Multisampling is not supported for signed and unsigned integer internal
    // formats.
    case GL_R8UI:
    case GL_R8I:
    case GL_R16UI:
    case GL_R16I:
    case GL_R32UI:
    case GL_R32I:
    case GL_RG8UI:
    case GL_RG8I:
    case GL_RG16UI:
    case GL_RG16I:
    case GL_RG32UI:
    case GL_RG32I:
    case GL_RGBA8UI:
    case GL_RGBA8I:
    case GL_RGB10_A2UI:
    case GL_RGBA16UI:
    case GL_RGBA16I:
    case GL_RGBA32UI:
    case GL_RGBA32I:
      return WebGLAny(script_state, DOMInt32Array::Create(0));
    case GL_R8:
    case GL_RG8:
    case GL_RGB8:
    case GL_RGB565:
    case GL_RGBA8:
    case GL_SRGB8_ALPHA8:
    case GL_RGB5_A1:
    case GL_RGBA4:
    case GL_RGB10_A2:
    case GL_DEPTH_COMPONENT16:
    case GL_DEPTH_COMPONENT24:
    case GL_DEPTH_COMPONENT32F:
    case GL_DEPTH24_STENCIL8:
    case GL_DEPTH32F_STENCIL8:
    case GL_STENCIL_INDEX8:
      break;
    case GL_R16_EXT:
    case GL_RG16_EXT:
    case GL_RGBA16_EXT:
      if (!ExtensionEnabled(kEXTTextureNorm16Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                          "invalid internalformat when EXT_texture_norm16 "
                          "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    case GL_R16F:
    case GL_RG16F:
    case GL_RGBA16F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName) &&
          !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
        SynthesizeGLError(
            GL_INVALID_ENUM, "getInternalformatParameter",
            "invalid internalformat when EXT_color_buffer_[half_]float "
            "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    case GL_R32F:
    case GL_RG32F:
    case GL_RGBA32F:
    case GL_R11F_G11F_B10F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                          "invalid internalformat when EXT_color_buffer_float "
                          "is not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                        "invalid internalformat");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (pname) {
    case GL_SAMPLES: {
      GLint length = -1;
      ContextGL()->GetInternalformativ(target, internalformat,
                                       GL_NUM_SAMPLE_COUNTS, 1, &length);
      if (length <= 0) {
        return WebGLAny(script_state, DOMInt32Array::Create(0));
      }
      auto values = base::HeapArray<GLint>::WithSize(length);
      ContextGL()->GetInternalformativ(target, internalformat, GL_SAMPLES,
                                       length, values.data());
      RecordInternalFormatParameter(internalformat, values.data(), length);
      return WebGLAny(script_state, DOMInt32Array::Create(values));
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getInternalformatParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

// TODO(crbug.com/351564777): should be UNSAFE_BUFFER_USAGE.
void WebGL2RenderingContextBase::RecordInternalFormatParameter(
    GLenum internalformat,
    GLint* values,
    GLint length) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kWebGLInternalFormatParameter))
    return;
  // SAFETY: required from caller.
  const base::span<GLint> values_span =
      UNSAFE_BUFFERS(base::span(values, base::checked_cast<size_t>(length)));
  const auto& ukm_params = GetUkmParameters();
  IdentifiableTokenBuilder builder;
  for (const auto& value : values_span) {
    builder.AddValue(value);
  }
  IdentifiabilityMetricBuilder(ukm_params.source_id)
      .Add(IdentifiableSurface::FromTypeAndToken(
               IdentifiableSurface::Type::kWebGLInternalFormatParameter,
               internalformat),
           builder.GetToken())
      .Record(ukm_params.ukm_recorder);
}

bool WebGL2RenderingContextBase::CheckAndTranslateAttachments(
    const char* function_name,
    GLenum target,
    Vector<GLenum>& attachments) {
  if (!ValidateFramebufferTarget(target)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
    return false;
  }

  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  DCHECK(framebuffer_binding || GetDrawingBuffer());
  if (!framebuffer_binding) {
    // For the default framebuffer, translate GL_COLOR/GL_DEPTH/GL_STENCIL.
    // The default framebuffer of WebGL is not fb 0, it is an internal fbo.
    for (wtf_size_t i = 0; i < attachments.size(); ++i) {
      switch (attachments[i]) {
        case GL_COLOR:
          attachments[i] = GL_COLOR_ATTACHMENT0;
          break;
        case GL_DEPTH:
          attachments[i] = GL_DEPTH_ATTACHMENT;
          break;
        case GL_STENCIL:
          attachments[i] = GL_STENCIL_ATTACHMENT;
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, function_name,
                            "invalid attachment");
          return false;
      }
    }
  }
  return true;
}

gfx::Rect WebGL2RenderingContextBase::GetTextureSourceSubRectangle(
    GLsizei width,
    GLsizei height) {
  return gfx::Rect(unpack_skip_pixels_, unpack_skip_rows_, width, height);
}

void WebGL2RenderingContextBase::invalidateFramebuffer(
    GLenum target,
    const Vector<GLenum>& attachments) {
  if (isContextLost())
    return;

  Vector<GLenum> translated_attachments = attachments;
  if (!CheckAndTranslateAttachments("invalidateFramebuffer", target,
                                    translated_attachments))
    return;
  ContextGL()->InvalidateFramebuffer(target, translated_attachments.size(),
                                     translated_attachments.data());
}

void WebGL2RenderingContextBase::invalidateSubFramebuffer(
    GLenum target,
    const Vector<GLenum>& attachments,
    GLint x,
    GLint y,
    GLsizei width,
    GLsizei height) {
  if (isContextLost())
    return;

  Vector<GLenum> translated_attachments = attachments;
  if (!CheckAndTranslateAttachments("invalidateSubFramebuffer", target,
                                    translated_attachments))
    return;
  ContextGL()->InvalidateSubFramebuffer(target, translated_attachments.size(),
                                        translated_attachments.data(), x, y,
                                        width, height);
}

void WebGL2RenderingContextBase::readBuffer(GLenum mode) {
  if (isContextLost())
    return;

  switch (mode) {
    case GL_BACK:
    case GL_NONE:
    case GL_COLOR_ATTACHMENT0:
      break;
    default:
      if (mode < GL_COLOR_ATTACHMENT0 && mode > GL_COLOR_ATTACHMENT0 + 31) {
        SynthesizeGLError(GL_INVALID_ENUM, "readBuffer", "invalid read buffer");
        return;
      } else if (mode >= static_cast<GLenum>(GL_COLOR_ATTACHMENT0 +
                                             MaxColorAttachments())) {
        SynthesizeGLError(GL_INVALID_OPERATION, "readBuffer",
                          "value exceeds MAX_COLOR_ATTACHMENTS");
        return;
      }
      break;
  }

  WebGLFramebuffer* read_framebuffer_binding =
      GetFramebufferBinding(GL_READ_FRAMEBUFFER);
  if (!read_framebuffer_binding) {
    DCHECK(GetDrawingBuffer());
    if (mode != GL_BACK && mode != GL_NONE) {
      SynthesizeGLError(GL_INVALID_OPERATION, "readBuffer",
                        "invalid read buffer");
      return;
    }
    read_buffer_of_default_framebuffer_ = mode;
    // translate GL_BACK to GL_COLOR_ATTACHMENT0, because the default
    // framebuffer for WebGL is not fb 0, it is an internal fbo.
    if (mode == GL_BACK)
      mode = GL_COLOR_ATTACHMENT0;
  } else {
    if (mode == GL_BACK) {
      SynthesizeGLError(GL_INVALID_OPERATION, "readBuffer",
                        "invalid read buffer");
      return;
    }
    read_framebuffer_binding->ReadBuffer(mode);
  }
  ContextGL()->ReadBuffer(mode);
}

void WebGL2RenderingContextBase::pixelStorei(GLenum pname, GLint param) {
  if (isContextLost())
    return;
  if (param < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, "pixelStorei", "negative value");
    return;
  }
  switch (pname) {
    case GL_PACK_ROW_LENGTH:
      pack_row_length_ = param;
      break;
    case GL_PACK_SKIP_PIXELS:
      pack_skip_pixels_ = param;
      break;
    case GL_PACK_SKIP_ROWS:
      pack_skip_rows_ = param;
      break;
    case GL_UNPACK_ROW_LENGTH:
      unpack_row_length_ = param;
      break;
    case GL_UNPACK_IMAGE_HEIGHT:
      unpack_image_height_ = param;
      break;
    case GL_UNPACK_SKIP_PIXELS:
      unpack_skip_pixels_ = param;
      break;
    case GL_UNPACK_SKIP_ROWS:
      unpack_skip_rows_ = param;
      break;
    case GL_UNPACK_SKIP_IMAGES:
      unpack_skip_images_ = param;
      break;
    default:
      WebGLRenderingContextBase::pixelStorei(pname, param);
      return;
  }
  ContextGL()->PixelStorei(pname, param);
}

void WebGL2RenderingContextBase::readPixels(
    GLint x,
    GLint y,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  if (isContextLost())
    return;
  if (bound_pixel_pack_buffer_.Get()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                      "PIXEL_PACK buffer should not be bound");
    return;
  }

  ReadPixelsHelper(x, y, width, height, format, type, pixels.Get(), 0);
}

void WebGL2RenderingContextBase::readPixels(
    GLint x,
    GLint y,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels,
    int64_t offset) {
  if (isContextLost())
    return;
  if (bound_pixel_pack_buffer_.Get()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                      "PIXEL_PACK buffer should not be bound");
    return;
  }

  ReadPixelsHelper(x, y, width, height, format, type, pixels.Get(), offset);
}

void WebGL2RenderingContextBase::readPixels(GLint x,
                                            GLint y,
                                            GLsizei width,
                                            GLsizei height,
                                            GLenum format,
                                            GLenum type,
                                            int64_t offset) {
  if (isContextLost())
    return;

  // Due to WebGL's same-origin restrictions, it is not possible to
  // taint the origin using the WebGL API.
  DCHECK(Host()->OriginClean());

  if (!ValidateValueFitNonNegInt32("readPixels", "offset", offset))
    return;

  WebGLBuffer* buffer = bound_pixel_pack_buffer_.Get();
  if (!buffer) {
    SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                      "no PIXEL_PACK buffer bound");
    return;
  }

  const char* reason = "framebuffer incomplete";
  WebGLFramebuffer* 
"""


```