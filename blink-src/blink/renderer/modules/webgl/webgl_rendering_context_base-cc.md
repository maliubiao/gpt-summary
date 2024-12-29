Response:
The user wants to understand the functionality of the `webgl_rendering_context_base.cc` file in the Chromium Blink engine. I need to:

1. **List its functionalities**:  Based on the provided code snippet and its includes, this file seems to handle the core logic for WebGL rendering contexts.
2. **Explain its relationship with Javascript, HTML, and CSS**:  WebGL is accessed through Javascript APIs within an HTML `<canvas>` element. CSS can influence the canvas's size and position.
3. **Provide examples of logic and its inputs/outputs**: Look for functions performing operations and infer their possible inputs and outputs.
4. **Illustrate common user/programming errors**: Identify potential issues related to WebGL usage based on the code.
5. **Describe user actions leading to this code**: Trace back how user interactions trigger WebGL context creation and operations.
6. **Summarize the functionality of this first part**:  Focus on the aspects covered in the provided snippet.
这是`blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的前一部分代码，其主要功能可以归纳为：

**核心功能： WebGL 渲染上下文的基础管理和创建**

这个文件定义了 `WebGLRenderingContextBase` 类，它是 WebGL 渲染上下文的基类，负责处理与 WebGL 上下文生命周期和状态管理相关的核心逻辑。具体来说，这部分代码主要关注以下几个方面：

1. **WebGL 上下文的创建和初始化**:
   - 实现了创建 `WebGraphicsContext3DProvider` 的逻辑，这是与底层图形系统交互的关键接口。
   - 处理了 WebGL 上下文创建过程中的错误情况，并触发 `webglcontextcreationerror` 事件。
   - 考虑了企业策略、命令行开关以及由于页面导致上下文丢失而被阻止创建的情况。
   - 提供了测试时强制上下文创建失败的机制 (`ForceNextWebGLContextCreationToFail`)。

2. **WebGL 上下文的激活和失活管理**:
   - 维护了当前活跃的 WebGL 上下文集合 (`ActiveContexts`)，用于限制同时活跃的上下文数量。
   - 实现了 `ActivateContext` 和 `DeactivateContext` 方法，用于管理上下文的激活和失活状态。
   - 当活跃上下文数量超过限制时，能够强制丢失最老的上下文 (`ForciblyLoseOldestContext`)，并向控制台输出警告信息。

3. **WebGL 上下文的强制丢失和恢复机制**:
   - 维护了被强制移除的上下文集合 (`ForciblyEvictedContexts`)。
   - 实现了 `AddToEvictedList` 和 `RemoveFromEvictedList` 方法来管理被移除的上下文。
   - 提供了 `RestoreEvictedContext` 方法，尝试恢复被移除的上下文，受到最大上下文数量和像素预算的限制。

4. **与底层图形 API 的交互**:
   - 包含了与 `gpu::gles2::GLES2Interface` 交互的代码，这是与 GPU 硬件进行通信的接口。
   - 处理了获取和设置各种 WebGL 状态的逻辑，例如 `ColorMask`。

5. **扩展支持**:
   - 包含了对各种 WebGL 扩展的支持，例如 `EXT_sRGB`、`EXT_color_buffer_float` 等。

6. **性能和资源管理**:
   - 实现了 `InitializeWebGLContextLimits` 方法，用于初始化 WebGL 上下文数量的限制。

7. **错误处理和调试**:
   - 提供了 `SynthesizeGLError` 方法，用于在 WebGL 操作过程中发生错误时生成相应的 GL 错误。
   - 包含了用于记录 WebGL 相关信息的代码，例如 ANGLE 的实现方式。

8. **与其他 Blink 模块的集成**:
   - 引入了许多其他 Blink 模块的头文件，例如 `core/html/canvas/html_canvas_element.h`，表明了 `WebGLRenderingContextBase` 与 HTML Canvas 元素紧密相关。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript**: `WebGLRenderingContextBase` 提供的功能最终会通过 JavaScript API 暴露给开发者。开发者使用 JavaScript 代码来获取 WebGL 上下文，调用其方法来执行渲染操作。例如，`canvas.getContext('webgl')` 或 `canvas.getContext('webgl2')` 会触发 WebGL 上下文的创建，这部分代码就负责处理这个过程。
* **HTML**:  WebGL 内容通常渲染在 HTML 的 `<canvas>` 元素上。用户需要在 HTML 中定义 `<canvas>` 元素，并通过 JavaScript 获取该元素并获取 WebGL 上下文。`WebGLRenderingContextBase` 类中包含了与 `HTMLCanvasElement` 相关的代码，例如获取 Canvas 的尺寸。
* **CSS**: CSS 可以用来控制 `<canvas>` 元素在页面上的样式和布局，例如设置 Canvas 的大小、位置等。虽然 CSS 不直接影响 WebGL 的渲染逻辑，但 Canvas 的尺寸变化可能会影响 WebGL 上下文的缓冲大小。这部分代码中的 `drawingBufferStorage` 方法就与 Canvas 的尺寸调整有关。

**逻辑推理的假设输入与输出：**

假设用户在 JavaScript 中请求创建一个 WebGL 上下文：

* **假设输入**:
    * 用户 JavaScript 代码: `const gl = canvas.getContext('webgl');`
    * `canvas` 是一个 HTMLCanvasElement 对象。
    * 当前活跃的 WebGL 上下文数量少于 `max_active_webgl_contexts_`。
* **逻辑推理**:
    1. `canvas.getContext('webgl')` 会触发 Blink 引擎中的上下文创建流程。
    2. `CreateWebGraphicsContext3DProvider` 方法会被调用，尝试创建底层的图形上下文。
    3. 如果创建成功，会创建一个 `WebGLRenderingContextBase` 的实例（或者其子类）。
    4. `ActivateContext` 方法会被调用，将新创建的上下文添加到活跃上下文集合中。
* **预期输出**:
    * 返回一个 `WebGLRenderingContext` 对象（或 null 如果创建失败）。
    * 新创建的 WebGL 上下文被添加到 `ActiveContexts` 集合中。

**用户或编程常见的使用错误：**

1. **尝试创建过多的 WebGL 上下文**:  如果用户或者页面脚本尝试创建的 WebGL 上下文数量超过 `max_active_webgl_contexts_`，会导致旧的上下文被强制丢失。这会导致意外的渲染结果或者程序崩溃。
   * **示例**: 循环创建多个 Canvas 元素并尝试获取 WebGL 上下文。
2. **在不支持 WebGL 的浏览器中尝试使用**:  虽然代码本身会尝试创建上下文，但在不支持 WebGL 的浏览器中，`CreateWebGraphicsContext3DProvider` 会返回空指针，导致上下文创建失败。
3. **不正确的 Canvas 尺寸设置**:  如果 Canvas 的尺寸设置不当（例如宽度或高度为负数），可能会导致 `drawingBufferStorage` 方法抛出 `GL_INVALID_VALUE` 错误。
4. **在 Worker 线程中超出上下文限制**:  Worker 线程有独立的上下文数量限制 (`max_active_webgl_contexts_on_worker_`)，超出限制也会导致上下文被强制丢失。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个包含 `<canvas>` 元素的网页**:  HTML 解析器会解析到 `<canvas>` 元素。
2. **JavaScript 代码执行**: 网页中的 JavaScript 代码尝试获取 WebGL 渲染上下文，例如 `canvas.getContext('webgl')`。
3. **Blink 引擎接收到上下文创建请求**:  这个请求会触发 `HTMLCanvasElement::getContext` 方法。
4. **`HTMLCanvasElement::getContext` 调用 `WebGLRenderingContextBase::Create` 或其子类的创建方法**:  根据请求的上下文类型（'webgl' 或 'webgl2'），会创建相应的 WebGL 上下文对象。
5. **`CreateWebGraphicsContext3DProvider` 被调用**:  尝试创建底层的图形上下文。
6. **`ActivateContext` 被调用**: 将新创建的上下文添加到活跃上下文中。
7. **后续的 WebGL API 调用**:  用户 JavaScript 代码会继续调用 WebGL API，这些调用最终会与 `WebGLRenderingContextBase` 或其子类中的方法关联，进而调用底层的图形 API。

**总结这部分代码的功能**:

总的来说，这部分 `webgl_rendering_context_base.cc` 代码主要负责 **WebGL 渲染上下文的创建、初始化和生命周期管理**，包括限制活跃上下文数量、处理创建错误、以及在资源紧张时强制丢失和尝试恢复上下文。它是 Blink 引擎中 WebGL 功能的核心组成部分，连接了 JavaScript API 和底层的图形系统。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共11部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"

#include <memory>
#include <utility>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/numerics/checked_math.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "device/vr/buildflags/buildflags.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/shared_image_capabilities.h"
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "gpu/config/gpu_feature_info.h"
#include "media/base/video_frame.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/gpu/gpu.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_htmlcanvaselement_offscreencanvas.h"
#include "third_party/blink/renderer/bindings/modules/v8/webgl_any.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/dactyloscoper.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer/array_buffer_contents.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webgl/angle_instanced_arrays.h"
#include "third_party/blink/renderer/modules/webgl/ext_blend_min_max.h"
#include "third_party/blink/renderer/modules/webgl/ext_frag_depth.h"
#include "third_party/blink/renderer/modules/webgl/ext_shader_texture_lod.h"
#include "third_party/blink/renderer/modules/webgl/ext_texture_filter_anisotropic.h"
#include "third_party/blink/renderer/modules/webgl/gl_string_query.h"
#include "third_party/blink/renderer/modules/webgl/oes_element_index_uint.h"
#include "third_party/blink/renderer/modules/webgl/oes_standard_derivatives.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_float.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_float_linear.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_half_float.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_half_float_linear.h"
#include "third_party/blink/renderer/modules/webgl/oes_vertex_array_object.h"
#include "third_party/blink/renderer/modules/webgl/webgl_active_info.h"
#include "third_party/blink/renderer/modules/webgl/webgl_buffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_astc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_etc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_etc1.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_pvrtc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_s3tc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_s3tc_srgb.h"
#include "third_party/blink/renderer/modules/webgl/webgl_context_attribute_helpers.h"
#include "third_party/blink/renderer/modules/webgl/webgl_context_event.h"
#include "third_party/blink/renderer/modules/webgl/webgl_context_group.h"
#include "third_party/blink/renderer/modules/webgl/webgl_debug_renderer_info.h"
#include "third_party/blink/renderer/modules/webgl/webgl_debug_shaders.h"
#include "third_party/blink/renderer/modules/webgl/webgl_depth_texture.h"
#include "third_party/blink/renderer/modules/webgl/webgl_draw_buffers.h"
#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_lose_context.h"
#include "third_party/blink/renderer/modules/webgl/webgl_program.h"
#include "third_party/blink/renderer/modules/webgl/webgl_renderbuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_shader.h"
#include "third_party/blink/renderer/modules/webgl/webgl_shader_precision_format.h"
#include "third_party/blink/renderer/modules/webgl/webgl_uniform_location.h"
#include "third_party/blink/renderer/modules/webgl/webgl_vertex_array_object.h"
#include "third_party/blink/renderer/modules/webgl/webgl_vertex_array_object_oes.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/image_extractor.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/skia/sk_image_info_hash.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_transform.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_util.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/skia/include/core/SkImage.h"
#include "ui/gfx/geometry/size.h"

// Populates parameters from texImage2D except for border, width, height, and
// depth (which are not present for all texImage2D functions).
#define POPULATE_TEX_IMAGE_2D_PARAMS(params, src_type) \
  params = {                                           \
      .source_type = src_type,                         \
      .function_id = kTexImage2D,                      \
      .target = target,                                \
      .level = level,                                  \
      .internalformat = internalformat,                \
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
      .format = format,                                    \
      .type = type,                                        \
  };                                                       \
  GetCurrentUnpackState(params)

namespace blink {

bool WebGLRenderingContextBase::webgl_context_limits_initialized_ = false;
unsigned WebGLRenderingContextBase::max_active_webgl_contexts_ = 0;
unsigned WebGLRenderingContextBase::max_active_webgl_contexts_on_worker_ = 0;

namespace {

enum class WebGLANGLEImplementation {
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.

  // vWebGL = 0 (for WebGL1) or 2 (for WebGL2).
  // vWebGLANGLEImplementation = vWebGL * 10 + vANGLEImplementation
  // where vANGLEImplementation is aligned with ANGLEImplementation enum
  // values defined in ui/gl/gl_implementation.h.

  kWebGL1_None = 0,
  kWebGL1_D3D9 = 1,
  kWebGL1_D3D11 = 2,
  kWebGL1_OpenGL = 3,
  kWebGL1_OpenGLES = 4,
  kWebGL1_Null = 5,
  kWebGL1_Vulkan = 6,
  kWebGL1_SwiftShader = 7,
  kWebGL1_Metal = 8,
  kWebGL1_Default = 9,

  // Leave some space between WebGL1 and WebGL2 enums in case ANGLE has
  // new implementations, say ANGLE/Dawn.

  kWebGL2_None = 20,
  kWebGL2_D3D9 = 21,  // Should never happen
  kWebGL2_D3D11 = 22,
  kWebGL2_OpenGL = 23,
  kWebGL2_OpenGLES = 24,
  kWebGL2_Null = 25,
  kWebGL2_Vulkan = 26,
  kWebGL2_SwiftShader = 27,
  kWebGL2_Metal = 28,
  kWebGL2_Default = 29,

  kMaxValue = kWebGL2_Default,
};

constexpr base::TimeDelta kDurationBetweenRestoreAttempts = base::Seconds(1);
const int kMaxGLErrorsAllowedToConsole = 256;

base::Lock& WebGLContextLimitLock() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(base::Lock, lock, ());
  return lock;
}

using WebGLRenderingContextBaseSet =
    HeapHashSet<WeakMember<WebGLRenderingContextBase>>;
WebGLRenderingContextBaseSet& ActiveContexts() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<WebGLRenderingContextBaseSet>>, active_contexts,
      ());
  Persistent<WebGLRenderingContextBaseSet>& active_contexts_persistent =
      *active_contexts;
  if (!active_contexts_persistent) {
    active_contexts_persistent =
        MakeGarbageCollected<WebGLRenderingContextBaseSet>();
    LEAK_SANITIZER_IGNORE_OBJECT(&active_contexts_persistent);
  }
  return *active_contexts_persistent;
}

using WebGLRenderingContextBaseMap =
    HeapHashMap<WeakMember<WebGLRenderingContextBase>, int>;
WebGLRenderingContextBaseMap& ForciblyEvictedContexts() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<Persistent<WebGLRenderingContextBaseMap>>,
      forcibly_evicted_contexts, ());
  Persistent<WebGLRenderingContextBaseMap>&
      forcibly_evicted_contexts_persistent = *forcibly_evicted_contexts;
  if (!forcibly_evicted_contexts_persistent) {
    forcibly_evicted_contexts_persistent =
        MakeGarbageCollected<WebGLRenderingContextBaseMap>();
    LEAK_SANITIZER_IGNORE_OBJECT(&forcibly_evicted_contexts_persistent);
  }
  return *forcibly_evicted_contexts_persistent;
}

}  // namespace

ScopedRGBEmulationColorMask::ScopedRGBEmulationColorMask(
    WebGLRenderingContextBase* context,
    GLboolean* color_mask,
    DrawingBuffer* drawing_buffer)
    : context_(context),
      requires_emulation_(drawing_buffer->RequiresAlphaChannelToBePreserved()) {
  if (requires_emulation_) {
    context_->active_scoped_rgb_emulation_color_masks_++;
    memcpy(color_mask_.data(), color_mask, 4 * sizeof(GLboolean));
    context_->ContextGL()->ColorMask(color_mask_[0], color_mask_[1],
                                     color_mask_[2], false);
  }
}

ScopedRGBEmulationColorMask::~ScopedRGBEmulationColorMask() {
  if (requires_emulation_) {
    DCHECK(context_->active_scoped_rgb_emulation_color_masks_);
    context_->active_scoped_rgb_emulation_color_masks_--;
    context_->ContextGL()->ColorMask(color_mask_[0], color_mask_[1],
                                     color_mask_[2], color_mask_[3]);
  }
}

void WebGLRenderingContextBase::InitializeWebGLContextLimits(
    WebGraphicsContext3DProvider* context_provider) {
  base::AutoLock locker(WebGLContextLimitLock());
  if (!webgl_context_limits_initialized_) {
    // These do not change over the lifetime of the browser.
    auto webgl_preferences = context_provider->GetWebglPreferences();
    max_active_webgl_contexts_ = webgl_preferences.max_active_webgl_contexts;
    max_active_webgl_contexts_on_worker_ =
        webgl_preferences.max_active_webgl_contexts_on_worker;
    webgl_context_limits_initialized_ = true;
  }
}

unsigned WebGLRenderingContextBase::CurrentMaxGLContexts() {
  base::AutoLock locker(WebGLContextLimitLock());
  DCHECK(webgl_context_limits_initialized_);
  return IsMainThread() ? max_active_webgl_contexts_
                        : max_active_webgl_contexts_on_worker_;
}

void WebGLRenderingContextBase::ForciblyLoseOldestContext(
    const String& reason) {
  WebGLRenderingContextBase* candidate = OldestContext();
  if (!candidate)
    return;

  candidate->PrintWarningToConsole(reason);
  probe::DidFireWebGLWarning(candidate->canvas());

  // This will call deactivateContext once the context has actually been lost.
  candidate->ForceLostContext(WebGLRenderingContextBase::kSyntheticLostContext,
                              WebGLRenderingContextBase::kWhenAvailable);
}

WebGLRenderingContextBase* WebGLRenderingContextBase::OldestContext() {
  if (ActiveContexts().empty())
    return nullptr;

  WebGLRenderingContextBase* candidate = *(ActiveContexts().begin());
  DCHECK(!candidate->isContextLost());
  for (WebGLRenderingContextBase* context : ActiveContexts()) {
    DCHECK(!context->isContextLost());
    if (context->ContextGL()->GetLastFlushIdCHROMIUM() <
        candidate->ContextGL()->GetLastFlushIdCHROMIUM()) {
      candidate = context;
    }
  }

  return candidate;
}

WebGLRenderingContextBase* WebGLRenderingContextBase::OldestEvictedContext() {
  if (ForciblyEvictedContexts().empty())
    return nullptr;

  WebGLRenderingContextBase* candidate = nullptr;
  int generation = -1;
  for (WebGLRenderingContextBase* context : ForciblyEvictedContexts().Keys()) {
    if (!candidate || ForciblyEvictedContexts().at(context) < generation) {
      candidate = context;
      generation = ForciblyEvictedContexts().at(context);
    }
  }

  return candidate;
}

void WebGLRenderingContextBase::ActivateContext(
    WebGLRenderingContextBase* context) {
  unsigned max_gl_contexts = CurrentMaxGLContexts();
  unsigned removed_contexts = 0;
  while (ActiveContexts().size() >= max_gl_contexts &&
         removed_contexts < max_gl_contexts) {
    ForciblyLoseOldestContext(
        "WARNING: Too many active WebGL contexts. Oldest context will be "
        "lost.");
    removed_contexts++;
  }

  DCHECK(!context->isContextLost());
  ActiveContexts().insert(context);
}

void WebGLRenderingContextBase::DeactivateContext(
    WebGLRenderingContextBase* context) {
  ActiveContexts().erase(context);
}

void WebGLRenderingContextBase::AddToEvictedList(
    WebGLRenderingContextBase* context) {
  static int generation = 0;
  ForciblyEvictedContexts().Set(context, generation++);
}

void WebGLRenderingContextBase::RemoveFromEvictedList(
    WebGLRenderingContextBase* context) {
  ForciblyEvictedContexts().erase(context);
}

void WebGLRenderingContextBase::RestoreEvictedContext(
    WebGLRenderingContextBase* context) {
  // These two sets keep weak references to their contexts;
  // verify that the GC already removed the |context| entries.
  DCHECK(!ForciblyEvictedContexts().Contains(context));
  DCHECK(!ActiveContexts().Contains(context));

  unsigned max_gl_contexts = CurrentMaxGLContexts();
  // Try to re-enable the oldest inactive contexts.
  while (ActiveContexts().size() < max_gl_contexts &&
         ForciblyEvictedContexts().size()) {
    WebGLRenderingContextBase* evicted_context = OldestEvictedContext();
    if (!evicted_context->restore_allowed_) {
      ForciblyEvictedContexts().erase(evicted_context);
      continue;
    }

    gfx::Size desired_size = DrawingBuffer::AdjustSize(
        evicted_context->ClampedCanvasSize(), gfx::Size(),
        evicted_context->max_texture_size_);

    // If there's room in the pixel budget for this context, restore it.
    if (!desired_size.IsEmpty()) {
      ForciblyEvictedContexts().erase(evicted_context);
      evicted_context->ForceRestoreContext();
    }
    break;
  }
}

namespace {

GLint Clamp(GLint value, GLint min, GLint max) {
  if (value < min)
    value = min;
  if (value > max)
    value = max;
  return value;
}

// Replaces non-ASCII characters with a placeholder. Given
// shaderSource's new rules as of
// https://github.com/KhronosGroup/WebGL/pull/3206 , the browser must
// not generate INVALID_VALUE for these out-of-range characters.
// Shader compilation must fail for invalid constructs farther in the
// pipeline.
class ReplaceNonASCII {
 public:
  ReplaceNonASCII(const String& str) { Parse(str); }

  String Result() { return builder_.ToString(); }

 private:
  void Parse(const String& source_string) {
    unsigned len = source_string.length();
    for (unsigned i = 0; i < len; ++i) {
      UChar current = source_string[i];
      if (WTF::IsASCII(current))
        builder_.Append(current);
      else
        builder_.Append('?');
    }
  }

  StringBuilder builder_;
};

static bool g_should_fail_context_creation_for_testing = false;
}  // namespace

// This class interrupts any active pixel local storage rendering pass, if the
// extension has been used by the context.
class ScopedPixelLocalStorageInterrupt {
  STACK_ALLOCATED();

 public:
  explicit ScopedPixelLocalStorageInterrupt(WebGLRenderingContextBase* context)
      : context_(context),
        needs_interrupt_(context_->has_activated_pixel_local_storage_) {
    if (needs_interrupt_) {
      context_->ContextGL()->FramebufferPixelLocalStorageInterruptANGLE();
    }
  }

  ~ScopedPixelLocalStorageInterrupt() {
    // The context should never activate PLS during an interrupt.
    DCHECK_EQ(context_->has_activated_pixel_local_storage_, needs_interrupt_);
    if (needs_interrupt_) {
      context_->ContextGL()->FramebufferPixelLocalStorageRestoreANGLE();
    }
  }

 private:
  WebGLRenderingContextBase* context_;
  bool needs_interrupt_;
};

class ScopedTexture2DRestorer {
  STACK_ALLOCATED();

 public:
  explicit ScopedTexture2DRestorer(WebGLRenderingContextBase* context)
      : context_(context) {}

  ~ScopedTexture2DRestorer() { context_->RestoreCurrentTexture2D(); }

 private:
  WebGLRenderingContextBase* context_;
};

class ScopedFramebufferRestorer {
  STACK_ALLOCATED();

 public:
  explicit ScopedFramebufferRestorer(WebGLRenderingContextBase* context)
      : context_(context) {}

  ~ScopedFramebufferRestorer() { context_->RestoreCurrentFramebuffer(); }

 private:
  WebGLRenderingContextBase* context_;
};

class ScopedUnpackParametersResetRestore {
  STACK_ALLOCATED();

 public:
  explicit ScopedUnpackParametersResetRestore(
      WebGLRenderingContextBase* context,
      bool enabled = true)
      : context_(context), enabled_(enabled) {
    if (enabled)
      context_->ResetUnpackParameters();
  }

  ~ScopedUnpackParametersResetRestore() {
    if (enabled_)
      context_->RestoreUnpackParameters();
  }

 private:
  WebGLRenderingContextBase* context_;
  bool enabled_;
};

class ScopedDisableRasterizerDiscard {
  STACK_ALLOCATED();

 public:
  explicit ScopedDisableRasterizerDiscard(WebGLRenderingContextBase* context,
                                          bool was_enabled)
      : context_(context), was_enabled_(was_enabled) {
    if (was_enabled_) {
      context_->disable(GL_RASTERIZER_DISCARD);
    }
  }

  ~ScopedDisableRasterizerDiscard() {
    if (was_enabled_) {
      context_->enable(GL_RASTERIZER_DISCARD);
    }
  }

 private:
  WebGLRenderingContextBase* context_;
  bool was_enabled_;
};

static void FormatWebGLStatusString(const StringView& gl_info,
                                    const StringView& info_string,
                                    StringBuilder& builder) {
  if (info_string.empty())
    return;
  builder.Append(", ");
  builder.Append(gl_info);
  builder.Append(" = ");
  builder.Append(info_string);
}

static String ExtractWebGLContextCreationError(
    const Platform::GraphicsInfo& info) {
  StringBuilder builder;
  builder.Append("Could not create a WebGL context");
  FormatWebGLStatusString(
      "VENDOR",
      info.vendor_id ? String::Format("0x%04x", info.vendor_id) : "0xffff",
      builder);
  FormatWebGLStatusString(
      "DEVICE",
      info.device_id ? String::Format("0x%04x", info.device_id) : "0xffff",
      builder);
  FormatWebGLStatusString("GL_VENDOR", info.vendor_info, builder);
  FormatWebGLStatusString("GL_RENDERER", info.renderer_info, builder);
  FormatWebGLStatusString("GL_VERSION", info.driver_version, builder);
  FormatWebGLStatusString("Sandboxed", info.sandboxed ? "yes" : "no", builder);
  FormatWebGLStatusString("Optimus", info.optimus ? "yes" : "no", builder);
  FormatWebGLStatusString("AMD switchable", info.amd_switchable ? "yes" : "no",
                          builder);
  FormatWebGLStatusString(
      "Reset notification strategy",
      String::Format("0x%04x", info.reset_notification_strategy).Utf8().c_str(),
      builder);
  FormatWebGLStatusString("ErrorMessage", info.error_message.Utf8().c_str(),
                          builder);
  builder.Append('.');
  return builder.ToString();
}

std::unique_ptr<WebGraphicsContext3DProvider>
WebGLRenderingContextBase::CreateContextProviderInternal(
    CanvasRenderingContextHost* host,
    const CanvasContextCreationAttributesCore& attributes,
    Platform::ContextType context_type,
    Platform::GraphicsInfo* graphics_info) {
  DCHECK(host);
  ExecutionContext* execution_context = host->GetTopExecutionContext();
  DCHECK(execution_context);

  Platform::ContextAttributes context_attributes =
      ToPlatformContextAttributes(attributes, context_type);

  // To run our tests with Chrome rendering on the low power GPU and WebGL on
  // the high performance GPU, we need to force the power preference attribute.
  if (base::FeatureList::IsEnabled(
          blink::features::kForceHighPerformanceGPUForWebGL)) {
    context_attributes.prefer_low_power_gpu = false;
  }

  const auto& url = execution_context->Url();
  std::unique_ptr<WebGraphicsContext3DProvider> context_provider =
      CreateOffscreenGraphicsContext3DProvider(context_attributes,
                                               graphics_info, url);
  if (context_provider && !context_provider->BindToCurrentSequence()) {
    context_provider = nullptr;
    graphics_info->error_message = String("BindToCurrentSequence failed: " +
                                          String(graphics_info->error_message));
  }
  if (!context_provider || g_should_fail_context_creation_for_testing) {
    g_should_fail_context_creation_for_testing = false;
    host->HostDispatchEvent(WebGLContextEvent::Create(
        event_type_names::kWebglcontextcreationerror,
        ExtractWebGLContextCreationError(*graphics_info)));
    return nullptr;
  }
  gpu::gles2::GLES2Interface* gl = context_provider->ContextGL();
  if (!String(gl->GetString(GL_EXTENSIONS))
           .Contains("GL_OES_packed_depth_stencil")) {
    host->HostDispatchEvent(WebGLContextEvent::Create(
        event_type_names::kWebglcontextcreationerror,
        "OES_packed_depth_stencil support is required."));
    return nullptr;
  }
  return context_provider;
}

std::unique_ptr<WebGraphicsContext3DProvider>
WebGLRenderingContextBase::CreateWebGraphicsContext3DProvider(
    CanvasRenderingContextHost* host,
    const CanvasContextCreationAttributesCore& attributes,
    Platform::ContextType context_type,
    Platform::GraphicsInfo* graphics_info) {
  if ((context_type == Platform::kWebGL1ContextType &&
       !host->IsWebGL1Enabled()) ||
      (context_type == Platform::kWebGL2ContextType &&
       !host->IsWebGL2Enabled())) {
    host->HostDispatchEvent(WebGLContextEvent::Create(
        event_type_names::kWebglcontextcreationerror,
        "disabled by enterprise policy or commandline switch"));
    return nullptr;
  }

  // We create a context *before* checking whether WebGL is blocked. This is
  // because new context creation is effectively synchronized against the
  // browser having a working GPU process connection, and that is in turn
  // synchronized against any updates to the browser's set of blocked domains.
  // See https://crbug.com/1215907#c10 for more details.
  auto provider = CreateContextProviderInternal(host, attributes, context_type,
                                                graphics_info);

  // The host might block creation of a new WebGL context despite the
  // page settings; in particular, if WebGL contexts were lost one or
  // more times via the GL_ARB_robustness extension.
  if (!host->IsWebGLBlocked())
    return provider;

  host->SetContextCreationWasBlocked();
  host->HostDispatchEvent(WebGLContextEvent::Create(
      event_type_names::kWebglcontextcreationerror,
      "Web page caused context loss and was blocked"));
  return nullptr;
}

void WebGLRenderingContextBase::ForceNextWebGLContextCreationToFail() {
  g_should_fail_context_creation_for_testing = true;
}

ImageBitmap* WebGLRenderingContextBase::TransferToImageBitmapBase(
    ScriptState* script_state) {
  WebFeature feature = WebFeature::kOffscreenCanvasTransferToImageBitmapWebGL;
  UseCounter::Count(ExecutionContext::From(script_state), feature);
  if (!GetDrawingBuffer()) {
    // Context is lost.
    return nullptr;
  }

  return MakeGarbageCollected<ImageBitmap>(
      GetDrawingBuffer()->TransferToStaticBitmapImage());
}

void WebGLRenderingContextBase::drawingBufferStorage(GLenum sizedformat,
                                                     GLsizei width,
                                                     GLsizei height) {
  if (!GetDrawingBuffer())
    return;

  const char* function_name = "drawingBufferStorage";
  const CanvasContextCreationAttributesCore& attrs = CreationAttributes();

  // Ensure that the width and height are valid.
  if (width <= 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "width < 0");
    return;
  }
  if (height <= 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "height < 0");
    return;
  }
  if (width > max_renderbuffer_size_) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "width > MAX_RENDERBUFFER_SIZE");
    return;
  }
  if (height > max_renderbuffer_size_) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "height > MAX_RENDERBUFFER_SIZE");
    return;
  }
  if (!attrs.alpha) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "alpha is required for drawingBufferStorage");
    return;
  }

  // Ensure that the format is supported, and set the corresponding alpha
  // type.
  SkAlphaType alpha_type =
      attrs.premultiplied_alpha ? kPremul_SkAlphaType : kUnpremul_SkAlphaType;
  switch (sizedformat) {
    case GL_RGBA8:
      break;
    case GL_SRGB8_ALPHA8:
      if (!IsWebGL2() && !ExtensionEnabled(kEXTsRGBName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_sRGB not enabled");
        return;
      }
      break;
    case GL_RGBA16F:
      if (base::FeatureList::IsEnabled(
              blink::features::kCorrectFloatExtensionTestForWebGL)) {
        // Correct float extension testing for WebGL1/2.
        // See: https://github.com/KhronosGroup/WebGL/pull/3222
        if (IsWebGL2()) {
          if (!ExtensionEnabled(kEXTColorBufferFloatName) &&
              !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
            SynthesizeGLError(GL_INVALID_ENUM, function_name,
                              "EXT_color_buffer_float/"
                              "EXT_color_buffer_half_float not enabled");
            return;
          }
        } else {
          if (!ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
            SynthesizeGLError(GL_INVALID_ENUM, function_name,
                              "EXT_color_buffer_half_float not enabled");
            return;
          }
        }
      } else {
        // This is the original incorrect extension testing. Remove this code
        // once this correction safely launches.
        if (IsWebGL2()) {
          if (!ExtensionEnabled(kEXTColorBufferFloatName) &&
              !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
            SynthesizeGLError(GL_INVALID_ENUM, function_name,
                              "EXT_color_buffer_float/"
                              "EXT_color_buffer_half_float not enabled");
            return;
          } else {
            if (!ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
              SynthesizeGLError(GL_INVALID_ENUM, function_name,
                                "EXT_color_buffer_half_float not enabled");
              return;
            }
          }
        }
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid sizedformat");
      return;
  }

  GetDrawingBuffer()->ResizeWithFormat(sizedformat, alpha_type,
                                       gfx::Size(width, height));
}

void WebGLRenderingContextBase::commit() {
  if (!GetDrawingBuffer() || (Host() && Host()->IsOffscreenCanvas()))
    return;

  int width = GetDrawingBuffer()->Size().width();
  int height = GetDrawingBuffer()->Size().height();

  if (PaintRenderingResultsToCanvas(kBackBuffer)) {
    if (Host()->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)) {
      Host()->Commit(
          Host()->ResourceProvider()->ProduceCanvasResource(FlushReason::kNone),
          SkIRect::MakeWH(width, height));
    }
  }
  MarkLayerComposited();
}

scoped_refptr<StaticBitmapImage> WebGLRenderingContextBase::GetImage(
    FlushReason reason) {
  if (!GetDrawingBuffer())
    return nullptr;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedFramebufferRestorer fbo_restorer(this);
  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve pro
"""


```