Response:
The user is asking for a summary of the provided C++ source code file `canvas_rendering_context_2d_test.cc`. The goal is to understand the file's purpose and its relationship to web technologies like JavaScript, HTML, and CSS. The request also asks for examples of logical reasoning, common user errors, and debugging steps, within the context of this file.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name itself, `canvas_rendering_context_2d_test.cc`, strongly suggests that this file contains tests for the `CanvasRenderingContext2D` functionality within the Blink rendering engine. Blink is Chromium's rendering engine.

2. **Analyze Key Includes:**  The `#include` directives at the beginning of the file provide crucial information. Look for includes related to:
    * **Testing Frameworks:**  `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h` indicate the use of Google Test for unit testing.
    * **Canvas Functionality:**  `"third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h"` confirms the file's focus.
    * **Blink Core:** Includes like `"third_party/blink/renderer/core/dom/document.h"`, `"third_party/blink/renderer/core/html/canvas/html_canvas_element.h"`, etc., point to the file's integration within the broader Blink architecture.
    * **Platform Graphics:** Includes like `"third_party/blink/renderer/platform/graphics/graphics_types.h"` and Skia headers (`"third_party/skia/include/core/SkCanvas.h"`) indicate interaction with graphics rendering.
    * **JavaScript Bindings:** Includes like `"third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"` suggest interaction with JavaScript through V8.

3. **Identify Key Classes and Structures:** Scan the file for class definitions and prominent data structures. `CanvasRenderingContext2DTest` itself is the main test fixture. Pay attention to helper classes like `FakeImageSource` and `FakeCanvasResourceProvider`, as they provide insight into the testing strategies.

4. **Infer Functionality from Tests:**  While the code *is* tests, the *types* of tests being performed reveal the functionalities of the class being tested. Look for test names like `FillRect_FullCoverage`, `ClearRect_Exact`, etc. These directly correspond to methods and operations of the `CanvasRenderingContext2D` API.

5. **Relate to Web Technologies:** Connect the C++ concepts to their counterparts in JavaScript, HTML, and CSS.
    * **JavaScript:** The `CanvasRenderingContext2D` in C++ directly implements the JavaScript `CanvasRenderingContext2D` object. Examples of JavaScript code manipulating the canvas are relevant.
    * **HTML:** The tests create and interact with `<canvas>` elements.
    * **CSS:** While this specific file doesn't directly *implement* CSS, canvas drawing can be influenced by CSS styles applied to the canvas element. Mentioning this indirect relationship is important.

6. **Consider Logical Reasoning:**  Look for test cases that seem to explore specific scenarios or edge cases. For instance, tests related to rate limiting based on canvas visibility or compositing state demonstrate logical checks within the `CanvasRenderingContext2D` implementation. Constructing hypothetical input and output for these tests helps illustrate the logic.

7. **Think About User Errors:**  Based on the tested functionalities, brainstorm potential user mistakes. For example, incorrect function parameters, using incompatible image sources, or not handling exceptions are common issues.

8. **Simulate Debugging:** Imagine a scenario where a canvas isn't rendering correctly. Trace the steps a developer might take to investigate, potentially leading to inspecting the Blink rendering process and this test file.

9. **Address Part 1 and Summarization:**  Focus on summarizing the core purpose of the file, which is to test the `CanvasRenderingContext2D` implementation. Highlight the key functionalities being tested.

10. **Structure the Output:** Organize the information logically, using headings and bullet points for clarity. Provide specific code examples and clear explanations.

**Self-Correction/Refinement:**

* **Initial thought:**  Focus solely on the technical aspects of the C++ code.
* **Correction:** Realize the prompt specifically asks for connections to web technologies and user-facing aspects. Adjust the focus to include these.
* **Initial thought:**  Only list the tested methods.
* **Correction:**  Group related functionalities (like state management, drawing primitives, image manipulation) for a more comprehensive summary.
* **Initial thought:**  Provide generic examples of user errors.
* **Correction:** Tailor the examples to the specific canvas functionalities being tested.
好的，这是对你提供的 blink 引擎源代码文件 `canvas_rendering_context_2d_test.cc` 第一部分的分析和功能归纳：

**文件功能概述:**

`blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc` 文件是 Chromium Blink 引擎中用于测试 `CanvasRenderingContext2D` 类的单元测试文件。 `CanvasRenderingContext2D` 类是 HTML5 Canvas 2D API 的核心实现，负责在 `<canvas>` 元素上进行 2D 图形绘制。

**主要功能点:**

1. **单元测试框架:** 该文件使用 Google Test (gtest) 框架来编写和执行测试用例，以验证 `CanvasRenderingContext2D` 类的各项功能是否按预期工作。

2. **测试覆盖范围:** 从文件中包含的头文件和测试用例名称（尽管你只提供了第一部分，但可以推测），该文件旨在测试 `CanvasRenderingContext2D` 的各种方法和属性，例如：
    * **状态管理:**  例如，保存和恢复绘图状态。
    * **基本图形绘制:** 例如，`fillRect` (填充矩形), `clearRect` (清除矩形)。
    * **路径操作:** 例如，`beginPath`, `moveTo`, `lineTo`, `closePath`, `stroke`, `fill` (尽管这部分可能在后续部分)。
    * **变换:** 例如，`translate`, `rotate`, `scale`, `transform` (可能在后续部分)。
    * **样式和颜色:** 例如，`fillStyle`, `strokeStyle`, `lineWidth` (可能在后续部分)。
    * **图像绘制:** 例如，`drawImage` (后续部分会详细测试)。
    * **文本绘制:** 例如，`fillText`, `strokeText` (可能在后续部分)。
    * **像素操作:** 例如，`getImageData`, `putImageData` (后续部分会详细测试)。
    * **合成操作:** 例如，`globalAlpha`, `globalCompositeOperation` (可能在后续部分)。
    * **性能相关:** 例如，测试在不同情况下的性能表现和资源管理（从代码中的 `kCanvas2DAutoFlushParams` 等常量可以推断）。

3. **模拟和辅助类:** 文件中定义了一些辅助类，用于模拟浏览器环境和资源，以便进行更 изолированного 测试：
    * `FakeImageSource`:  用于模拟图像资源，避免依赖真实的图像加载。
    * `FakeCanvasResourceProvider`: 用于模拟 Canvas 的资源提供者，可以控制是否启用硬件加速等。
    * `AcceleratedCompositingTestPlatform`: 用于模拟支持硬件加速的环境。

4. **度量和监控:**  文件中使用了 `base::HistogramTester` 来记录和断言某些操作的发生次数，例如过度绘制 (`OverdrawOp`)，这有助于分析性能和优化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 该测试文件直接测试的是 JavaScript 中 `CanvasRenderingContext2D` API 在 Blink 引擎中的实现。  例如，测试 `fillRect` 方法，对应的 JavaScript 代码如下：

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   ctx.fillRect(10, 10, 100, 50); // 调用 JavaScript 的 fillRect 方法
   ```

   此测试文件中的 `TEST_P(CanvasRenderingContext2DTest, FillRect_FullCoverage)`  这样的测试用例会调用 C++ 的 `Context2D()->fillRect(3, 3, 1, 1);`，来验证 Blink 引擎中 `fillRect` 的实现是否正确。

* **HTML:**  `<canvas>` 元素是 `CanvasRenderingContext2D` 的宿主。测试文件中会创建和操作 `<canvas>` 元素。例如，代码中通过 `GetDocument().documentElement()->setInnerHTML(...)` 创建了一个包含 `<canvas>` 元素的 HTML 结构。

   ```html
   <canvas id="myCanvas" width="200" height="100"></canvas>
   ```

* **CSS:**  虽然此测试文件主要关注 Canvas API 的逻辑，但 CSS 可以影响 Canvas 元素的布局和某些渲染特性。例如，Canvas 的尺寸可以通过 CSS 设置，这可能会影响测试结果。  测试中可能需要考虑不同 CSS 样式下 Canvas 的行为。

**逻辑推理的假设输入与输出 (基于第一部分):**

* **假设输入 (例如 `FillRect_FullCoverage` 测试):**
    * Canvas 元素尺寸： 10x10
    * 调用 `fillRect(3, 3, 1, 1)`
    * 调用 `fillRect(-1, -1, 12, 12)`
* **预期输出:**
    * 底层的 Skia 绘制记录 (`cc::PaintRecord`) 中应该包含两个 `DrawRectOp` 操作，分别对应两个 `fillRect` 调用，并具有正确的矩形参数。

**用户或编程常见的使用错误及举例说明:**

* **不正确的参数:** 用户在 JavaScript 中调用 Canvas API 时，可能会传递错误的参数类型或超出范围的值。例如，`fillRect("abc", 10, 100, 50)` 会导致错误，而测试文件会验证 Blink 引擎是否能正确处理这些错误（例如抛出异常或忽略无效参数，但这部分在当前提供的代码中看不出来）。
* **未获取 Context:**  在操作 Canvas 之前，必须先获取 2D 渲染上下文。如果用户忘记调用 `canvas.getContext('2d')`，尝试调用绘图方法会出错。测试用例会确保在创建 `CanvasRenderingContext2D` 对象后才能进行操作。
* **性能问题:**  用户可能会在短时间内进行大量的 Canvas 绘制操作，导致性能问题。测试文件中包含了一些性能相关的测试（例如自动刷新机制的测试），以确保 Blink 引擎在这些情况下能有效管理资源。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上与 Canvas 元素交互:** 用户可能正在浏览一个包含动画、游戏或数据可视化的网页，这些网页使用了 HTML5 Canvas 进行渲染。
2. **Canvas 渲染出现问题:**  用户可能会发现 Canvas 内容显示不正确、性能下降或出现意外的错误。
3. **Web 开发者尝试调试:**  开发者会使用浏览器开发者工具检查 Canvas 的状态，查看 JavaScript 代码中 Canvas API 的调用，并可能怀疑是 Blink 引擎的 Canvas 实现存在问题。
4. **Blink 开发者进行底层调试:** 如果问题很复杂，可能需要 Blink 引擎的开发者深入到 C++ 代码层面进行调试。他们可能会查看 `canvas_rendering_context_2d_test.cc` 文件，寻找相关的测试用例，或者编写新的测试用例来复现和修复 bug。
5. **运行测试用例:**  Blink 开发者会运行这些单元测试，以验证他们对问题的修复是否有效，以及是否引入了新的回归错误。

**第一部分功能归纳:**

这部分代码主要建立了 `CanvasRenderingContext2D` 单元测试的基础框架。它定义了测试类 `CanvasRenderingContext2DTest`，包含了测试环境的初始化（例如创建 Canvas 元素，设置测试平台），以及一些基础的测试用例，初步验证了 `fillRect` 和 `clearRect` 等基本绘图功能，并开始关注性能和资源管理方面的问题 (例如自动刷新机制、是否开启硬件加速等)。  它还引入了用于模拟和辅助测试的类，为后续更复杂的 Canvas 功能测试奠定了基础。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h"

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <memory>
#include <optional>
#include <unordered_set>
#include <utility>

#include "base/check.h"
#include "base/check_deref.h"
#include "base/check_op.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_base.h"
#include "base/notreached.h"
#include "base/pending_task.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "cc/base/features.h"
#include "cc/paint/paint_flags.h"
#include "cc/paint/paint_image.h"
#include "cc/paint/paint_op.h"
#include "cc/test/paint_op_matchers.h"
#include "components/viz/common/resources/release_callback.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "components/viz/test/test_context_provider.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/shared_image_capabilities.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/public/mojom/page/page_visibility_state.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_data_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_float32array_uint16array_uint8clampedarray.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2043)
#include "third_party/blink/renderer/bindings/modules/v8/v8_begin_layer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_rendering_context_2d_settings.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_will_read_frequently.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_canvasfilter_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_image_source.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/canvas/recording_test_utils.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_gradient.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_style_test_utils.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/canvas_color_params.h"
#include "third_party/blink/renderer/platform/graphics/canvas_hibernation_handler.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/color_correction_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types_3d.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_memory_buffer_test_platform.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_status.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/skia/include/core/SkAlphaType.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkColorType.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkM44.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "third_party/skia/include/gpu/ganesh/GrDirectContext.h"
#include "ui/gfx/buffer_types.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_f.h"
#include "ui/gfx/skia_util.h"

// Including "base/time/time.h" triggers a bug in IWYU:
// https://github.com/include-what-you-use/include-what-you-use/issues/1122
// IWYU pragma: no_include "base/numerics/clamped_math.h"

// GoogleTest expectation macros trigger a bug in IWYU:
// https://github.com/include-what-you-use/include-what-you-use/issues/1546
// IWYU pragma: no_include <string>

class GrDirectContext;

namespace blink {
class CanvasResourceHost;
class ExecutionContext;
}  // namespace blink

using ::base::test::ScopedFeatureList;
using ::blink_testing::ClearRectFlags;
using ::blink_testing::FillFlags;
using ::blink_testing::RecordedOpsAre;
using ::cc::ClipRectOp;
using ::cc::DrawColorOp;
using ::cc::DrawImageRectOp;
using ::cc::DrawPathOp;
using ::cc::DrawRectOp;
using ::cc::PaintOpEq;
using ::cc::PaintOpIs;
using ::cc::RestoreOp;
using ::cc::SaveLayerAlphaOp;
using ::cc::SaveLayerOp;
using ::cc::SaveOp;
using ::cc::SetMatrixOp;
using ::cc::TranslateOp;
using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Message;
using ::testing::Mock;
using ::testing::Optional;
using ::testing::SaveArg;

namespace blink {

enum BitmapOpacity { kOpaqueBitmap, kTransparentBitmap };

class AcceleratedCompositingTestPlatform
    : public blink::TestingPlatformSupport {
 public:
  bool IsGpuCompositingDisabled() const override { return false; }
};

class FakeImageSource : public CanvasImageSource {
 public:
  FakeImageSource(gfx::Size, BitmapOpacity);

  scoped_refptr<Image> GetSourceImageForCanvas(FlushReason,
                                               SourceImageStatus*,
                                               const gfx::SizeF&,
                                               const AlphaDisposition) override;

  bool WouldTaintOrigin() const override { return false; }
  gfx::SizeF ElementSize(const gfx::SizeF&,
                         const RespectImageOrientationEnum) const override {
    return gfx::SizeF(size_);
  }
  bool IsOpaque() const override { return is_opaque_; }
  bool IsAccelerated() const override { return false; }

  ~FakeImageSource() override = default;

 private:
  gfx::Size size_;
  scoped_refptr<Image> image_;
  bool is_opaque_;
};

FakeImageSource::FakeImageSource(gfx::Size size, BitmapOpacity opacity)
    : size_(size), is_opaque_(opacity == kOpaqueBitmap) {
  sk_sp<SkSurface> surface(SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(size_.width(), size_.height())));
  surface->getCanvas()->clear(opacity == kOpaqueBitmap ? SK_ColorWHITE
                                                       : SK_ColorTRANSPARENT);
  image_ = UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot());
}

scoped_refptr<Image> FakeImageSource::GetSourceImageForCanvas(
    FlushReason,
    SourceImageStatus* status,
    const gfx::SizeF&,
    const AlphaDisposition alpha_disposition = kPremultiplyAlpha) {
  // Only cover premultiply alpha cases.
  DCHECK_EQ(alpha_disposition, kPremultiplyAlpha);

  if (status)
    *status = kNormalSourceImageStatus;
  return image_;
}

//============================================================================

class CanvasRenderingContext2DTest : public ::testing::Test,
                                     public PaintTestConfigurations {
 public:
  CanvasRenderingContext2DTest();
  void SetUp() override;
  virtual bool AllowsAcceleration() { return false; }

  virtual scoped_refptr<viz::TestContextProvider> CreateContextProvider() {
    return viz::TestContextProvider::Create();
  }

  HTMLCanvasElement& CanvasElement() const { return *canvas_element_; }
  cc::PaintCanvas& Canvas() {
    return CanvasElement().ResourceProvider()->Canvas();
  }
  CanvasRenderingContext2D* Context2D() const {
    return static_cast<CanvasRenderingContext2D*>(
        CanvasElement().RenderingContext());
  }

  CanvasRenderingContext2DState& GetContext2DState() {
    return Context2D()->GetState();
  }

  void DrawSomething() {
    CanvasElement().DidDraw();
    CanvasElement().PreFinalizeFrame();
    Context2D()->FinalizeFrame(FlushReason::kTesting);
    CanvasElement().PostFinalizeFrame(FlushReason::kTesting);
    // Grabbing an image forces a flush
    CanvasElement().Snapshot(FlushReason::kTesting, kBackBuffer);
  }

  enum LatencyMode { kNormalLatency, kLowLatency };

  static constexpr size_t kMaxPinnedImageKB = 1;
  static constexpr size_t kMaxRecordedOpKB = 10;

  void CreateContext(
      OpacityMode,
      LatencyMode = kNormalLatency,
      CanvasContextCreationAttributesCore::WillReadFrequently =
          CanvasContextCreationAttributesCore::WillReadFrequently::kUndefined,
      HTMLCanvasElement* canvas = nullptr);

  ScriptState* GetScriptState() {
    return ToScriptStateForMainWorld(canvas_element_->DomWindow()->GetFrame());
  }

  ExecutionContext* GetExecutionContext() {
    return GetDocument().GetExecutionContext();
  }

  void TearDown() override;

  void TearDownHost() {
    // To tear down the host it is both necessary and sufficient to tear down
    // the document, as the document effectively owns the host.
    web_view_helper_ = nullptr;
  }

  Document& GetDocument() const {
    return *web_view_helper_->GetWebView()
                ->MainFrameImpl()
                ->GetFrame()
                ->DomWindow()
                ->document();
  }

  void UpdateAllLifecyclePhasesForTest() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<frame_test_helpers::WebViewHelper> web_view_helper_;
  Persistent<HTMLCanvasElement> canvas_element_;

 private:
  Persistent<MemoryCache> global_memory_cache_;
  std::unique_ptr<ScopedAccelerated2dCanvasForTest> allow_accelerated_;

  class WrapGradients final : public GarbageCollected<WrapGradients> {
   public:
    void Trace(Visitor* visitor) const {
      visitor->Trace(opaque_gradient_);
      visitor->Trace(alpha_gradient_);
    }

    Member<CanvasGradient> opaque_gradient_;
    Member<CanvasGradient> alpha_gradient_;
  };

  // TODO(Oilpan): avoid tedious part-object wrapper by supporting on-heap
  // testing::Tests.
  Persistent<WrapGradients> wrap_gradients_;

 protected:
  // Pre-canned objects for testing
  Persistent<ImageData> full_image_data_;
  Persistent<ImageData> partial_image_data_;
  FakeImageSource opaque_bitmap_;
  FakeImageSource alpha_bitmap_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;

  Member<CanvasGradient>& OpaqueGradient() {
    return wrap_gradients_->opaque_gradient_;
  }
  Member<CanvasGradient>& AlphaGradient() {
    return wrap_gradients_->alpha_gradient_;
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(CanvasRenderingContext2DTest);

CanvasRenderingContext2DTest::CanvasRenderingContext2DTest()
    : wrap_gradients_(MakeGarbageCollected<WrapGradients>()),
      opaque_bitmap_(gfx::Size(10, 10), kOpaqueBitmap),
      alpha_bitmap_(gfx::Size(10, 10), kTransparentBitmap) {}

void CanvasRenderingContext2DTest::CreateContext(
    OpacityMode opacity_mode,
    LatencyMode latency_mode,
    CanvasContextCreationAttributesCore::WillReadFrequently
        will_read_frequently,
    HTMLCanvasElement* canvas) {
  String canvas_type("2d");
  CanvasContextCreationAttributesCore attributes;
  attributes.alpha = opacity_mode == kNonOpaque;
  attributes.desynchronized = latency_mode == kLowLatency;
  attributes.will_read_frequently = will_read_frequently;
  if (!canvas) {
    canvas = canvas_element_;
  }
  canvas->GetCanvasRenderingContext(canvas_type, attributes);
}

void CanvasRenderingContext2DTest::SetUp() {
  base::FieldTrialParams auto_flush_params;
  auto_flush_params["max_pinned_image_kb"] =
      base::NumberToString(kMaxPinnedImageKB);
  auto_flush_params["max_recorded_op_kb"] =
      base::NumberToString(kMaxRecordedOpKB);
  feature_list_.InitAndEnableFeatureWithParameters(kCanvas2DAutoFlushParams,
                                                   auto_flush_params);

  test_context_provider_ = CreateContextProvider();
  InitializeSharedGpuContextGLES2(test_context_provider_.get());
  allow_accelerated_ =
      std::make_unique<ScopedAccelerated2dCanvasForTest>(AllowsAcceleration());
  web_view_helper_ = std::make_unique<frame_test_helpers::WebViewHelper>();
  web_view_helper_->Initialize();

  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(
      "<body><canvas id='c'></canvas><canvas id='d'></canvas></body>"));
  UpdateAllLifecyclePhasesForTest();

  // Simulate that we allow scripts, so that HTMLCanvasElement uses
  // LayoutHTMLCanvas.
  GetDocument().GetPage()->GetSettings().SetScriptEnabled(true);

  canvas_element_ =
      To<HTMLCanvasElement>(GetDocument().getElementById(AtomicString("c")));

  ImageDataSettings* settings = ImageDataSettings::Create();
  full_image_data_ = ImageData::Create(10, 10, settings, ASSERT_NO_EXCEPTION);
  partial_image_data_ = ImageData::Create(2, 2, settings, ASSERT_NO_EXCEPTION);

  NonThrowableExceptionState exception_state;
  auto* opaque_gradient = MakeGarbageCollected<CanvasGradient>(
      gfx::PointF(0, 0), gfx::PointF(10, 0));
  opaque_gradient->addColorStop(0, String("green"), exception_state);
  EXPECT_FALSE(exception_state.HadException());
  opaque_gradient->addColorStop(1, String("blue"), exception_state);
  EXPECT_FALSE(exception_state.HadException());
  OpaqueGradient() = opaque_gradient;

  auto* alpha_gradient = MakeGarbageCollected<CanvasGradient>(
      gfx::PointF(0, 0), gfx::PointF(10, 0));
  alpha_gradient->addColorStop(0, String("green"), exception_state);
  EXPECT_FALSE(exception_state.HadException());
  alpha_gradient->addColorStop(1, String("rgba(0, 0, 255, 0.5)"),
                               exception_state);
  EXPECT_FALSE(exception_state.HadException());
  AlphaGradient() = alpha_gradient;

  global_memory_cache_ =
      ReplaceMemoryCacheForTesting(MakeGarbageCollected<MemoryCache>(
          blink::scheduler::GetSingleThreadTaskRunnerForTesting()));
}

void CanvasRenderingContext2DTest::TearDown() {
  feature_list_.Reset();
  ThreadState::Current()->CollectAllGarbageForTesting(
      ThreadState::StackState::kNoHeapPointers);

  ReplaceMemoryCacheForTesting(global_memory_cache_.Release());

  // Tear down WebViewHelper because we override Platform in some tests which
  // must be torn down after WebViewHelper.
  web_view_helper_ = nullptr;

  // Must be torn down after WebViewHelper since its destructor can create a
  // fresh context provider otherwise.
  SharedGpuContext::Reset();

  // Prevent CanvasPerformanceMonitor state from leaking between tests.
  CanvasRenderingContext::GetCanvasPerformanceMonitor().ResetForTesting();
}

//============================================================================

enum class CompositingMode {
  kDoesNotSupportDirectCompositing,
  kSupportsDirectCompositing
};

class FakeCanvasResourceProvider : public CanvasResourceProvider {
 public:
  FakeCanvasResourceProvider(const SkImageInfo& info,
                             RasterModeHint hint,
                             CanvasResourceHost* resource_host,
                             CompositingMode compositing_mode)
      : CanvasResourceProvider(CanvasResourceProvider::kSharedImage,
                               info,
                               cc::PaintFlags::FilterQuality::kLow,
                               SharedGpuContext::ContextProviderWrapper(),
                               /*resource_dispatcher=*/nullptr,
                               resource_host),
        is_accelerated_(hint != RasterModeHint::kPreferCPU),
        supports_direct_compositing_(
            compositing_mode == CompositingMode::kSupportsDirectCompositing) {
    ON_CALL(*this, Snapshot)
        .WillByDefault(
            [this](FlushReason reason, ImageOrientation orientation) {
              return SnapshotInternal(orientation, reason);
            });
  }
  ~FakeCanvasResourceProvider() override = default;
  bool IsAccelerated() const override { return is_accelerated_; }
  scoped_refptr<CanvasResource> ProduceCanvasResource(FlushReason) override {
    const SkImageInfo& info = GetSkImageInfo();
    return scoped_refptr<CanvasResource>(CanvasResourceSharedImage::Create(
        gfx::Size(info.width(), info.height()), info.colorInfo().colorType(),
        info.colorInfo().alphaType(), info.colorInfo().refColorSpace(),
        SharedGpuContext::ContextProviderWrapper(), CreateWeakPtr(),
        cc::PaintFlags::FilterQuality::kLow, IsAccelerated(),
        gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
            gpu::SHARED_IMAGE_USAGE_RASTER_WRITE));
  }
  bool SupportsDirectCompositing() const override {
    return supports_direct_compositing_;
  }
  bool IsValid() const override { return true; }
  sk_sp<SkSurface> CreateSkSurface() const override {
    return SkSurfaces::Raster(GetSkImageInfo());
  }

  MOCK_METHOD((void), RasterRecord, (cc::PaintRecord last_recording));

  MOCK_METHOD((scoped_refptr<StaticBitmapImage>),
              Snapshot,
              (FlushReason reason, ImageOrientation orientation));

  MOCK_METHOD(bool,
              WritePixels,
              (const SkImageInfo& orig_info,
               const void* pixels,
               size_t row_bytes,
               int x,
               int y));

 private:
  bool is_accelerated_;
  bool supports_direct_compositing_;
};

// Sets up an accelerated CanvasResourceProvider, accelerated compositing,
// and a CcLayer on the passed-in HTMLCanvasElement. Returns false if the
// CcLayer couldn't be created.
bool SetUpFullAccelerationAndCcLayer(HTMLCanvasElement& canvas_element) {
  // Install a CanvasResourceProvider that is accelerated and supports direct
  // compositing (the latter is necessary for GetOrCreateCcLayerIfNeeded() to
  // succeed).
  gfx::Size size = canvas_element.Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &canvas_element,
      CompositingMode::kSupportsDirectCompositing);
  canvas_element.SetResourceProviderForTesting(std::move(provider), size);

  // Put the host in GPU compositing mode.
  canvas_element.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);

  // Create the CcLayer.
  return canvas_element.GetOrCreateCcLayerIfNeeded() != nullptr;
}

//============================================================================

MATCHER_P(OverdrawOpAreMatcher, expected_overdraw_ops, "") {
  constexpr int last_bucket =
      static_cast<int>(BaseRenderingContext2D::OverdrawOp::kMaxValue);
  for (int bucket = 0; bucket <= last_bucket; ++bucket) {
    SCOPED_TRACE(Message() << "Checking overdraw bucket: " << bucket);
    arg.ExpectBucketCount(
        "Blink.Canvas.OverdrawOp", bucket,
        static_cast<base::HistogramBase::Count>(expected_overdraw_ops.count(
            static_cast<BaseRenderingContext2D::OverdrawOp>(bucket))));
  }
  return true;
}

template <typename... Args>
testing::Matcher<base::HistogramTester> OverdrawOpAre(Args... args) {
  return OverdrawOpAreMatcher(
      std::unordered_set<BaseRenderingContext2D::OverdrawOp>{args...});
}

TEST_P(CanvasRenderingContext2DTest, NoRecreationOfResourceProviderAfterDraw) {
  CreateContext(kNonOpaque);
  EXPECT_TRUE(CanvasElement().IsResourceValid());
  uint32_t gen_id =
      CanvasElement()
          .GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)
          ->ContentUniqueID();
  Context2D()->fillRect(3, 3, 1, 1);
  EXPECT_EQ(gen_id,
            CanvasElement()
                .GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)
                ->ContentUniqueID());
}

TEST_P(CanvasRenderingContext2DTest, NonDisplayedCanvasIsNotRateLimited) {
  CreateContext(kNonOpaque);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  CanvasElement().SetIsDisplayed(false);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Invoking FinalizeFrame() twice should not result in rate limiting as the
  // canvas is not displayed.
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());
}

TEST_P(CanvasRenderingContext2DTest,
       DisplayedNonPaintableCanvasIsNotRateLimited) {
  CreateContext(kNonOpaque);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  CanvasElement().SetIsDisplayed(true);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Invoking FinalizeFrame() twice should not result in rate limiting as the
  // canvas is not paintable.
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());
}

TEST_P(CanvasRenderingContext2DTest,
       DisplayedPaintableNonCompositedCanvasIsNotRateLimited) {
  CreateContext(kNonOpaque);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Install a CanvasResourceProvider that does not support direct compositing.
  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kDoesNotSupportDirectCompositing);
  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  CanvasElement().SetIsDisplayed(true);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Invoking FinalizeFrame() twice should not result in rate limiting as the
  // canvas is not composited.
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());
}

TEST_P(CanvasRenderingContext2DTest,
       DisplayedPaintableCompositedCanvasIsRateLimited) {
  CreateContext(kNonOpaque);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Install a CanvasResourceProvider that supports direct compositing to make
  // the canvas composited.
  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);
  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  CanvasElement().SetIsDisplayed(true);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Invoking FinalizeFrame() twice should result in rate limiting.
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_TRUE(!!CanvasElement().RateLimiter());
}

TEST_P(CanvasRenderingContext2DTest, HidingCanvasTurnsOffRateLimiting) {
  CreateContext(kNonOpaque);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  // Install a CanvasResourceProvider that supports direct compositing to make
  // the canvas composited.
  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);
  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  CanvasElement().SetIsDisplayed(true);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_TRUE(!!CanvasElement().RateLimiter());

  CanvasElement().SetIsDisplayed(false);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());

  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  Context2D()->FinalizeFrame(FlushReason::kCanvasPushFrame);
  EXPECT_FALSE(!!CanvasElement().RateLimiter());
}

TEST_P(CanvasRenderingContext2DTest, GetImageWithAccelerationDisabled) {
  CreateContext(kNonOpaque);

  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferCPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);
  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);
  ASSERT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  ASSERT_TRUE(CanvasElement().IsResourceValid());

  EXPECT_FALSE(Context2D()
                   ->GetImage(FlushReason::kTesting)
                   ->PaintImageForCurrentFrame()
                   .IsTextureBacked());

  // The GetImage() call should have preserved the rasterization mode as well as
  // the validity of the resource.
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(CanvasElement().IsResourceValid());
}

TEST_P(CanvasRenderingContext2DTest, FallbackToSoftwareOnFailedTextureAlloc) {
  CreateContext(kNonOpaque);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);

  // As no CanvasResourceProvider has yet been created, the host should default
  // to the raster mode that has been set as preferred.
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  // This will cause SkSurface_Gpu creation to fail.
  SharedGpuContext::ContextProviderWrapper()
      ->ContextProvider()
      ->GetGrContext()
      ->abandonContext();

  // Drawing to the canvas should cause a CanvasResourceProvider to be created.
  // It is not possible to create a valid CanvasResourceProviderSharedImage
  // instance without a GrContext as creating an SkSurface will fail, so the
  // created provider should be unaccelerated (and hence downgrade the raster
  // mode to CPU).
  Context2D()->fillRect(3, 3, 1, 1);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);

  // Without GPU rasterization, snapshots should not be texture-backed.
  EXPECT_FALSE(Context2D()
                   ->GetImage(FlushReason::kTesting)
                   ->PaintImageForCurrentFrame()
                   .IsTextureBacked());

  // Verify that taking the snapshot did not alter the raster mode.
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest, FillRect_FullCoverage) {
  // Fill rect no longer supports overdraw optimizations
  // Reason: low real world incidence not worth the test overhead.
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->fillRect(-1, -1, 12, 12);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 1, 1), FillFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(-1, -1, 12, 12),
                                FillFlags()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DisableOverdrawOptimization) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(kDisableCanvasOverdrawOptimization);

  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 1, 1), FillFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 10),
                                ClearRectFlags()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_Exact
```