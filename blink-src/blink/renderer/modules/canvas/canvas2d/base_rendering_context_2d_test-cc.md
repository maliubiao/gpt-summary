Response:
The user is asking for a summary of the functionality of the provided C++ source code file. I need to analyze the code and identify its purpose, its relation to web technologies like JavaScript, HTML, and CSS, provide examples of logic, usage errors, and the steps to reach this code during debugging.

**Plan:**

1. **Identify the core functionality:** Analyze the included headers and the test class implementation to understand what the code is testing.
2. **Relate to web technologies:** Determine how the tested functionalities relate to JavaScript Canvas API, HTML `<canvas>` element, and CSS styling.
3. **Provide logic examples:**  Look for test cases that demonstrate specific functionalities and create simplified examples with inputs and expected outputs.
4. **Identify potential usage errors:**  Think about common mistakes developers might make when using the Canvas API that these tests might be addressing.
5. **Describe debugging steps:** Outline a typical user interaction flow that would eventually involve this code.
6. **Summarize the functionality:**  Provide a concise overview of the file's purpose based on the analysis.
这是对 Chromium Blink 引擎中 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc` 文件的功能归纳：

**功能归纳:**

这个 C++ 文件包含了一系列针对 `BaseRenderingContext2D` 类的单元测试。 `BaseRenderingContext2D` 是 HTML `<canvas>` 元素 2D 渲染上下文的核心抽象基类。因此，这个测试文件主要用于验证 `BaseRenderingContext2D` 及其子类（在测试中用 `TestRenderingContext2D` 代替）在进行各种 2D 图形绘制操作时的行为是否符合预期。

**具体功能点包括但不限于：**

*   **基本的图形绘制操作测试:**  例如 `fillRect` (填充矩形)。测试验证了在应用平移变换后，`fillRect` 操作能否正确地记录下绘制指令。
*   **CanvasPattern 测试:** 验证使用 `CanvasPattern` 作为填充样式时，绘制操作的记录方式。
*   **drawImage 测试:** 验证 `drawImage` 方法在不同参数下的记录。
*   **滤镜 (Filter) 测试:** 重点测试了 `filter` 属性的应用，包括单独应用滤镜和在存在变换的情况下应用滤镜，验证了 `SaveLayerOp` 和 `RestoreOp` 的使用以及滤镜效果的正确记录。
*   **阴影 (Shadow) 测试:** 测试了 `shadowBlur`, `shadowOffsetX`, `shadowOffsetY`, `shadowColor` 等属性对绘制的影响，以及阴影的渲染方式。
*   **全局合成操作 (Global Composite Operation) 测试:**  测试了 `globalCompositeOperation` 属性的不同取值（如 "copy", "multiply", "destination-out", "source-in" 等）对绘制结果的影响，特别是 "copy" 操作的特殊处理。
*   **滤镜和合成操作的组合测试:** 验证了当滤镜和合成操作同时应用时，绘制指令的记录顺序和方式。
*   **阴影和合成操作的组合测试:** 测试了阴影与不同合成操作的结合，以及在 "copy" 合成操作下的特殊行为。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件直接测试了 Blink 引擎中 Canvas 2D API 的底层实现，该 API 是通过 Javascript 暴露给 Web 开发者的。

*   **Javascript:** 文件中的每个测试用例都对应着 Canvas 2D API 中 Javascript 方法和属性的行为。
    *   例如，`TEST(BaseRenderingContextCompositingTests, FillRect)` 测试了 Javascript 中 `CanvasRenderingContext2D.fillRect()` 方法的行为。
        *   **Javascript 代码示例:**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            ctx.translate(4, 5);
            ctx.fillRect(1, 1, 5, 5);
            ```
        *   此测试用例验证了当 Javascript 代码执行这段逻辑时，Blink 引擎是否正确地记录了 `TranslateOp` 和 `DrawRectOp` 绘制指令。
    *   `TEST(BaseRenderingContextCompositingTests, Filter)` 测试了 Javascript 中 `CanvasRenderingContext2D.filter` 属性的行为。
        *   **Javascript 代码示例:**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            ctx.filter = 'blur(20px)';
            ctx.fillRect(1, 1, 5, 5);
            ```
        *   此测试用例验证了设置 `filter` 属性后，Blink 引擎是否正确地使用了 `SaveLayerOp` 来应用滤镜效果。
    *   `TEST(BaseRenderingContextCompositingTests, ShadowCopyOp)` 测试了 Javascript 中阴影属性和 `globalCompositeOperation = 'copy'` 的组合行为。
        *   **Javascript 代码示例:**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            ctx.shadowBlur = 2;
            ctx.shadowOffsetX = 2;
            ctx.shadowOffsetY = 3;
            ctx.shadowColor = 'red';
            ctx.globalCompositeOperation = 'copy';
            ctx.fillRect(1, 1, 5, 5);
            ```
        *   此测试用例验证了在 `copy` 操作下，阴影是否被忽略，只记录了清除画布和绘制矩形的操作。

*   **HTML:** `<canvas>` 元素是 Canvas 2D API 的载体。测试中创建的 `TestRenderingContext2D` 对象通常关联着一个模拟的或实际的 `HTMLCanvasElement`。
    *   **HTML 代码示例:**
        ```html
        <canvas id="myCanvas" width="300" height="300"></canvas>
        ```
        用户在 HTML 中定义的 `<canvas>` 元素会通过 Javascript 获取到，并用于获取 2D 渲染上下文。

*   **CSS:** 虽然 Canvas 2D API 的核心功能不依赖 CSS，但 CSS 样式可以影响 `<canvas>` 元素本身的大小和布局。此外，像 `filter` 这样的属性，其语法和概念与 CSS 滤镜类似。

**逻辑推理、假设输入与输出:**

以 `TEST(BaseRenderingContextCompositingTests, FillRect)` 为例：

*   **假设输入:**
    *   Javascript 代码执行了 `ctx.translate(4, 5);` 和 `ctx.fillRect(1, 1, 5, 5);`。
*   **逻辑推理:**  `translate(4, 5)` 会将后续的绘制操作平移 (4, 5) 个单位。 `fillRect(1, 1, 5, 5)` 会绘制一个起始于 (1, 1)，宽度为 5，高度为 5 的矩形。应用平移后，实际绘制的矩形在画布上的位置会发生改变。
*   **预期输出 (通过 `FlushRecorder()` 获取的绘制指令):**
    *   `PaintOpEq<TranslateOp>(4, 5)`:  记录了一个平移操作。
    *   `PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags())`: 记录了一个绘制矩形的操作，其参数是相对于平移前的坐标。

**用户或编程常见的使用错误举例说明:**

*   **忘记应用 `save()` 和 `restore()` 包裹状态改变:** 用户可能会在设置了变换、滤镜或合成操作后，忘记使用 `save()` 保存当前状态，并在操作完成后使用 `restore()` 恢复状态，导致后续的绘制操作受到意外的影响。
    *   **错误示例 (Javascript):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.translate(10, 10);
        ctx.fillRect(0, 0, 50, 50); // 期望绘制在 (10, 10)
        ctx.fillStyle = 'red';
        ctx.fillRect(0, 0, 20, 20); // 期望绘制红色矩形，但可能仍然受到之前的 translate 影响
        ```
    *   这个测试文件中的某些用例可能间接地测试了 `save()` 和 `restore()` 的行为，通过检查 `SaveOp` 和 `RestoreOp` 的出现来验证状态管理是否正确。

*   **对 `globalCompositeOperation = 'copy'` 的误解:** 用户可能认为 'copy' 操作只是简单地覆盖，而忽略了它会清除目标区域的特性。
    *   **错误示例 (Javascript):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.fillRect(0, 0, 50, 50); // 先绘制一个矩形
        ctx.globalCompositeOperation = 'copy';
        ctx.fillStyle = 'red';
        ctx.fillRect(10, 10, 30, 30); // 期望在之前的矩形上绘制红色矩形，但 'copy' 会先清除区域
        ```
    *   `TEST(BaseRenderingContextCompositingTests, CopyOp)` 明确测试了 'copy' 操作会先记录一个 `DrawColorOp` 来清除画布。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载包含 `<canvas>` 元素的网页。**
2. **Javascript 代码通过 `document.getElementById()` 获取 `<canvas>` 元素。**
3. **Javascript 代码调用 `canvas.getContext('2d')` 获取 2D 渲染上下文对象。**
4. **Javascript 代码调用 2D 渲染上下文的各种方法和属性，例如 `translate()`, `fillRect()`, `filter`, `globalCompositeOperation` 等。**
5. **当这些 Javascript 代码执行时，Blink 引擎会调用相应的 C++ 代码来实现这些操作。**  `BaseRenderingContext2D` 类及其子类（如 `CanvasRenderingContext2D` 的实现）负责处理这些调用，并将绘制指令记录到 `cc::PaintRecord` 中。
6. **在渲染过程中，`cc::PaintRecord` 中的绘制指令会被用于实际的图形绘制。**

**调试线索:** 如果开发者在 Canvas 绘制中遇到问题，例如：

*   绘制位置不正确：可能是 `translate()`, `rotate()`, `scale()` 等变换函数使用错误。可以检查是否正确使用了 `save()` 和 `restore()`。
*   滤镜效果不符合预期：检查 `filter` 属性的语法是否正确，或者是否与其他属性（如 `globalCompositeOperation`) 产生了冲突。
*   合成效果异常：检查 `globalCompositeOperation` 的值是否设置正确，理解不同合成模式的含义。
*   性能问题：过多的状态切换或复杂的滤镜可能导致性能下降。可以使用浏览器的开发者工具来分析 Canvas 的绘制调用和性能瓶颈。

当需要深入调试 Blink 引擎的 Canvas 2D 实现时，开发者可能会查看 `base_rendering_context_2d_test.cc` 这样的测试文件，来理解特定 API 的预期行为和内部实现逻辑。测试用例可以作为理解代码功能和调试问题的参考。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "cc/paint/paint_canvas.h"
#include "cc/paint/paint_flags.h"
#include "cc/paint/paint_image.h"
#include "cc/paint/paint_op.h"
#include "cc/paint/paint_record.h"
#include "cc/paint/paint_shader.h"
#include "cc/paint/refcounted_buffer.h"
#include "cc/test/paint_op_matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_begin_layer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_canvasfilter_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/font_style_resolver.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_performance_monitor.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/recording_test_utils.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/style/filter_operation.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter_test_utils.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_index_buffer.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_uv_buffer.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_vertex_buffer.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/graphics/draw_looper_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_canvas.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_filter.h"
#include "third_party/blink/renderer/platform/graphics/pattern.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/skia/include/core/SkBlendMode.h"
#include "third_party/skia/include/core/SkClipOp.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkM44.h"
#include "third_party/skia/include/core/SkMatrix.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkTileMode.h"
#include "third_party/skia/include/private/base/SkPoint_impl.h"
#include "ui/gfx/geometry/size.h"

namespace blink {
namespace {

using ::blink_testing::ClearRectFlags;
using ::blink_testing::FillFlags;
using ::blink_testing::ParseFilter;
using ::blink_testing::RecordedOpsAre;
using ::blink_testing::RecordedOpsView;
using ::cc::ClipPathOp;
using ::cc::ClipRectOp;
using ::cc::ConcatOp;
using ::cc::DrawColorOp;
using ::cc::DrawImageRectOp;
using ::cc::DrawRectOp;
using ::cc::DrawVerticesOp;
using ::cc::PaintFlags;
using ::cc::PaintImage;
using ::cc::PaintOpEq;
using ::cc::PaintOpIs;
using ::cc::PaintShader;
using ::cc::RestoreOp;
using ::cc::SaveLayerAlphaOp;
using ::cc::SaveLayerFiltersOp;
using ::cc::SaveLayerOp;
using ::cc::SaveOp;
using ::cc::ScaleOp;
using ::cc::SetMatrixOp;
using ::cc::TranslateOp;
using ::cc::UsePaintCache;
using ::testing::IsEmpty;

// Test version of BaseRenderingContext2D. BaseRenderingContext2D can't be
// tested directly because it's an abstract class. This test class essentially
// just gives a definition to all pure virtual method, making it instantiable.
class TestRenderingContext2D final
    : public GarbageCollected<TestRenderingContext2D>,
      public BaseRenderingContext2D,
      public MemoryManagedPaintRecorder::Client {
 public:
  explicit TestRenderingContext2D(V8TestingScope& scope)
      : BaseRenderingContext2D(
            scheduler::GetSingleThreadTaskRunnerForTesting()),
        execution_context_(scope.GetExecutionContext()),
        recorder_(gfx::Size(Width(), Height()), this),
        host_canvas_element_(nullptr) {}
  ~TestRenderingContext2D() override = default;

  // Returns the content of the paint recorder, leaving it empty.
  cc::PaintRecord FlushRecorder() { return recorder_.ReleaseMainRecording(); }

  int StateStackDepth() {
    // Subtract the extra save that gets added when the context is initialized.
    return state_stack_.size() - 1;
  }

  int OpenedLayerCount() { return layer_count_; }

  bool OriginClean() const override { return true; }
  void SetOriginTainted() override {}

  int Width() const override { return 300; }
  int Height() const override { return 300; }

  bool CanCreateCanvas2dResourceProvider() const override { return false; }

  RespectImageOrientationEnum RespectImageOrientation() const override {
    return kRespectImageOrientation;
  }

  Color GetCurrentColor() const override { return Color::kBlack; }

  cc::PaintCanvas* GetOrCreatePaintCanvas() override {
    return &recorder_.getRecordingCanvas();
  }
  using BaseRenderingContext2D::GetPaintCanvas;  // Pull the non-const overload.
  const cc::PaintCanvas* GetPaintCanvas() const override {
    return &recorder_.getRecordingCanvas();
  }
  void WillDraw(const SkIRect& dirty_rect,
                CanvasPerformanceMonitor::DrawType) override {}

  sk_sp<PaintFilter> StateGetFilter() override {
    return GetState().GetFilterForOffscreenCanvas({}, this);
  }

  ExecutionContext* GetTopExecutionContext() const override {
    return execution_context_.Get();
  }

  bool HasAlpha() const override { return true; }

  void SetContextLost(bool context_lost) { context_lost_ = context_lost; }
  bool isContextLost() const override { return context_lost_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(execution_context_);
    visitor->Trace(host_canvas_element_);
    BaseRenderingContext2D::Trace(visitor);
  }

  void SetRestoreMatrixEnabled(bool enabled) {
    restore_matrix_enabled_ = enabled;
  }

  void SetHostHTMLCanvas(HTMLCanvasElement* host_canvas_element) {
    host_canvas_element_ = host_canvas_element;
  }

 protected:
  PredefinedColorSpace GetDefaultImageDataColorSpace() const override {
    return PredefinedColorSpace::kSRGB;
  }

  HTMLCanvasElement* HostAsHTMLCanvasElement() const override {
    return host_canvas_element_;
  }

 private:
  void InitializeForRecording(cc::PaintCanvas* canvas) const override {
    if (restore_matrix_enabled_) {
      RestoreMatrixClipStack(canvas);
    }
  }
  void RecordingCleared() override {}

  std::optional<cc::PaintRecord> FlushCanvas(FlushReason) override {
    return recorder_.ReleaseMainRecording();
  }

  const MemoryManagedPaintRecorder* Recorder() const override {
    return &recorder_;
  }

  bool ResolveFont(const String& new_font) override {
    if (host_canvas_element_ == nullptr) {
      return false;
    }
    auto* style = CSSParser::ParseFont(new_font, execution_context_);
    if (style == nullptr) {
      return false;
    }
    FontDescription font_description = FontStyleResolver::ComputeFont(
        *style, host_canvas_element_->GetFontSelector());
    GetState().SetFont(font_description,
                       host_canvas_element_->GetFontSelector());
    return true;
  }

  Member<ExecutionContext> execution_context_;
  bool restore_matrix_enabled_ = true;
  bool context_lost_ = false;
  MemoryManagedPaintRecorder recorder_;
  Member<HTMLCanvasElement> host_canvas_element_;
};

V8UnionCanvasFilterOrString* MakeBlurCanvasFilter(float std_deviation) {
  FilterOperations ops;
  ops.Operations().push_back(
      MakeGarbageCollected<BlurFilterOperation>(Length::Fixed(std_deviation)));

  return MakeGarbageCollected<V8UnionCanvasFilterOrString>(
      MakeGarbageCollected<CanvasFilter>(ops));
}

BeginLayerOptions* FilterOption(blink::V8TestingScope& scope,
                                const std::string& filter) {
  BeginLayerOptions* options = BeginLayerOptions::Create();
  options->setFilter(ParseFilter(scope, filter));
  return options;
}

// Tests a plain fillRect.
TEST(BaseRenderingContextCompositingTests, FillRect) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   FillFlags())));
}

// Tests a fillRect with a CanvasPattern.
TEST(BaseRenderingContextCompositingTests, Pattern) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  auto* pattern = MakeGarbageCollected<CanvasPattern>(
      Image::NullImage(), Pattern::kRepeatModeXY, /*origin_clean=*/true);

  context->setFillStyle(scope.GetIsolate(),
                        pattern->ToV8(scope.GetScriptState()),
                        scope.GetExceptionState());
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags flags = FillFlags();
  flags.setShader(PaintShader::MakeColor(SkColors::kTransparent));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(
                  PaintOpEq<TranslateOp>(4, 5),
                  PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), flags)));
}

// Tests a plain drawImage.
TEST(BaseRenderingContextCompositingTests, DrawImage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  auto* bitmap = MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  context->translate(4, 5);
  context->drawImage(bitmap, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpIs<DrawImageRectOp>()));
}

// Tests drawing with context filter.
TEST(BaseRenderingContextCompositingTests, Filter) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(20.0f));
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - Evaluate whether the filter could be
          // applied on the DrawRectOp directly.
          PaintOpEq<SaveLayerOp>(filter_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests drawing with context filter and a transform.
TEST(BaseRenderingContextCompositingTests, FilterTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(20.0f));
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                                          0, 1, 0, 0,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<SaveLayerOp>(filter_flags),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                          0, 1, 0, 5,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   FillFlags()),
                             PaintOpEq<RestoreOp>(),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                          0, 1, 0, 5,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1))));
}

// Tests drawing with a shadow.
TEST(BaseRenderingContextCompositingTests, Shadow) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags shadow_flags = FillFlags();
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  draw_looper_builder.AddUnmodifiedContent();
  shadow_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   shadow_flags)));
}

// Tests the "copy" composite operation, which is handled as a special case
// clearing the canvas before draw.
TEST(BaseRenderingContextCompositingTests, CopyOp) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setGlobalCompositeOperation("copy");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags = FillFlags();
  composite_flags.setBlendMode(SkBlendMode::kSrc);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          // TODO: crbug.com/364549423 - Evaluate which is faster between
          // clearing the frame buffer manually and using a layer with a `kSrc`
          // blend mode.
          PaintOpEq<DrawColorOp>(SkColors::kTransparent, SkBlendMode::kSrc),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                composite_flags)));
}

// Tests drawing with a blending operation.
TEST(BaseRenderingContextCompositingTests, Multiply) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setGlobalCompositeOperation("multiply");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags = FillFlags();
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   composite_flags)));
}

// Tests drawing with a composite operation.
TEST(BaseRenderingContextCompositingTests, DstOut) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setGlobalCompositeOperation("destination-out");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags = FillFlags();
  composite_flags.setBlendMode(SkBlendMode::kDstOut);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   composite_flags)));
}

// Tests drawing with a composite operation operating on the full surface. These
// ops impact all pixels, even those outside the drawn shape.
TEST(BaseRenderingContextCompositingTests, SrcIn) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setGlobalCompositeOperation("source-in");
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests composite ops operating on the full surface. These ops impact all
// pixels, even those outside the drawn shape.
TEST(BaseRenderingContextCompositingTests, SrcInTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setGlobalCompositeOperation("source-in");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          // TODO: crbug.com/364549423 - No need to reset matrix, source-in
          // isn't impacted by transforms.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - Evaluate whether the composite op could
          // be applied on the DrawRectOp directly.
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests drawing with context filter and a "copy" composite operation. The copy
// op should clear previous drawing but the filter should be applied as normal.
TEST(BaseRenderingContextCompositingTests, FilterCopyOp) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(20.0f));
  context->setGlobalCompositeOperation("copy");
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags filter_flags;
  filter_flags.setBlendMode(SkBlendMode::kSrc);
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - Evaluate which is faster between
          // clearing the frame buffer manually and using a layer with a `kSrc`
          // blend mode.
          PaintOpEq<SaveLayerOp>(filter_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests drawing with context filter, a shadow and a "copy" composite operation.
// The copy op should clear previous drawing and the shadow shouldn't be
// rasterized, but the filter should be applied as normal.
TEST(BaseRenderingContextCompositingTests, FilterShadowCopyOp) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(20.0f));
  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("copy");
  context->fillRect(1, 1, 5, 5);

  sk_sp<cc::PaintFilter> blur_filter =
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr);

  cc::PaintFlags shadow_flags = FillFlags();
  shadow_flags.setBlendMode(SkBlendMode::kSrc);
  // TODO: crbug.com/364549423 - The `ComposePaintFilter`s are useless here.
  shadow_flags.setImageFilter(sk_make_sp<ComposePaintFilter>(
      sk_make_sp<ComposePaintFilter>(nullptr, nullptr), blur_filter));

  // TODO: crbug.com/364549423 - Remove draw-looper.
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  shadow_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  cc::PaintFlags foreground_flags;
  foreground_flags.setBlendMode(SkBlendMode::kSrc);
  foreground_flags.setImageFilter(blur_filter);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - There is no need to draw a shadow, it
          // will be overwritten by the foreground right afterwards.
          PaintOpEq<SaveLayerOp>(shadow_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),  //
          PaintOpEq<SaveLayerOp>(foreground_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a shadow with a "copy" composite operation, which is handled as a
// special case clearing the canvas before draw. Thus, the shadow shouldn't be
// drawn since the foreground overwrites it.
TEST(BaseRenderingContextCompositingTests, ShadowCopyOp) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("copy");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags = FillFlags();
  composite_flags.setBlendMode(SkBlendMode::kSrc);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<DrawColorOp>(SkColors::kTransparent,
                                                    SkBlendMode::kSrc),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   composite_flags)));
}

// Tests fillRect with a shadow and a globalCompositeOperator that can't be
// implemented using a `DropShadowPaintFilter` (it requires separate compositing
// of the shadow and foreground.
TEST(BaseRenderingContextCompositingTests, ShadowMultiply) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("multiply");
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags shadow_only_flags = FillFlags();
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  shadow_only_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  cc::PaintFlags foreground_flags = FillFlags();

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                shadow_only_flags),
          PaintOpEq<RestoreOp>(),  //
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), foreground_flags),
          PaintOpEq<RestoreOp>(),                   //
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests fillRect with a shadow and a globalCompositeOperator that can't be
// implemented using a `DropShadowPaintFilter` (it requires separate compositing
// of the shadow and foreground.
TEST(BaseRenderingContextCompositingTests, ShadowMultiplyTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("multiply");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags shadow_only_flags = FillFlags();
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  shadow_only_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  cc::PaintFlags foreground_flags = FillFlags();

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                                          0, 1, 0, 0,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<SaveLayerOp>(composite_flags),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                   
"""


```