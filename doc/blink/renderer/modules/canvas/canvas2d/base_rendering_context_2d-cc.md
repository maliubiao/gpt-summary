Response:
The user wants to understand the functionality of the provided C++ source code file, `base_rendering_context_2d.cc`, which is part of the Chromium Blink rendering engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core functionality:** The file name itself, "base_rendering_context_2d.cc", strongly suggests this file implements the base class for 2D canvas rendering. This implies managing the drawing state, handling transformations, and interacting with the underlying graphics library (Skia in this case).

2. **Scan for key data structures and methods:**  Look for prominent data structures like `state_stack_`, which clearly manages the canvas state. Methods like `save()`, `restore()`, `fillRect()`, `strokeRect()`, `drawImage()`, `fillText()`, etc. (though not fully present in this snippet) are likely central to the class's purpose. Also note methods related to layers (`beginLayerImpl`, `endLayer`).

3. **Analyze includes:** The included header files provide clues about the file's dependencies and capabilities. For instance:
    * `"cc/paint/paint_canvas.h"` and related headers point to interaction with Chromium's compositing and painting system.
    * Headers from `third_party/skia` indicate the usage of the Skia graphics library.
    * Headers related to `html/canvas` and `modules/canvas/canvas2d` confirm its role in implementing the HTML `<canvas>` element's 2D rendering context.
    * Headers involving `bindings/core/v8` and `bindings/modules/v8` suggest interaction with JavaScript.
    * Headers like `core/css` and `core/dom` link it to CSS styling and the Document Object Model.

4. **Connect to web technologies (HTML, CSS, JavaScript):**  Based on the includes and the perceived core functionality, establish the relationships:
    * **HTML:** The `<canvas>` element in HTML is the target for this rendering context.
    * **JavaScript:** JavaScript code uses the Canvas 2D API (e.g., `getContext('2d')`) to obtain an instance of this class (or a derived class) and call its methods for drawing.
    * **CSS:** CSS properties can affect the canvas, such as `width`, `height`, and potentially styles inherited by text drawn on the canvas.

5. **Provide concrete examples:** Illustrate the connections with simple code snippets:
    * HTML: Showing how to create a canvas element.
    * JavaScript: Demonstrating basic drawing operations like `fillRect`, `strokeStyle`, and `drawImage`.
    * CSS: Showing how to style the canvas element.

6. **Infer logical reasoning and assumptions:**  Consider how the code might handle drawing operations. The `state_stack_` suggests a stack-based approach for managing transformations and styles. Assume that methods like `fillRect` will internally interact with the Skia library to perform the actual drawing.

7. **Identify potential user errors:** Think about common mistakes developers make when working with the Canvas 2D API:
    * Incorrectly balanced `save()` and `restore()` calls.
    * Using methods after the context has been lost.
    * Providing invalid arguments to drawing methods (though this specific file might not handle the immediate validation).

8. **Explain the debugging process:**  Describe how a developer might end up examining this file during debugging. This involves understanding the call stack when a canvas-related JavaScript function is executed. Highlighting the role of developer tools and breakpoints.

9. **Summarize the functionality (for Part 1):** Condense the findings into a concise summary that captures the main responsibilities of the `BaseRenderingContext2D` class. Focus on its role as the foundation for 2D canvas rendering, managing state, and interacting with lower-level graphics.

10. **Structure the response:** Organize the information logically with clear headings and bullet points for better readability. Use the provided keywords ("功能", "javascript", "html", "css", "逻辑推理", "假设输入与输出", "用户或者编程常见的使用错误", "用户操作是如何一步步的到达这里", "调试线索") as a guide.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on specific drawing methods like `fillRect`. However, the provided snippet emphasizes state management (`save`, `restore`, layers). Therefore, I adjusted the focus to highlight state management as a primary function.
*  I made sure to explicitly connect the C++ code to the corresponding JavaScript API elements and HTML constructs to make the explanation more understandable for a web developer.
* I initially considered discussing the details of Skia integration, but decided to keep it at a higher level for this initial part, as going into too much detail might be overwhelming.
这是对 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 文件功能的归纳总结。

**功能归纳 (Summary of Functionality):**

`BaseRenderingContext2D` 类是 Chromium Blink 引擎中用于实现 HTML5 Canvas 2D 渲染上下文的核心基类。它主要负责以下功能：

1. **状态管理 (State Management):**
   - 维护 Canvas 2D 渲染的各种状态，例如变换矩阵 (transform)、裁剪区域 (clip)、线条样式 (strokeStyle, lineWidth)、填充样式 (fillStyle)、阴影 (shadow)、全局透明度 (globalAlpha)、合成操作 (globalCompositeOperation) 等。
   - 使用栈 (`state_stack_`) 来管理状态的保存 (`save()`) 和恢复 (`restore()`)。
   - 实现了 `save()` 方法来将当前渲染状态推入栈中。
   - 实现了 `restore()` 方法来从栈中弹出最近保存的状态并恢复。
   - 限制了状态栈的最大深度 (`max_state_stack_depth_`) 并进行统计。

2. **图层管理 (Layer Management):**
   - 实现了 Canvas 2D 的图层功能 (`beginLayerImpl()`, `endLayer()`)，允许将一系列绘制操作组合成一个独立的图层，可以应用滤镜和合成模式。
   - 使用 `layer_count_` 跟踪当前活跃的图层数量。
   - 在图层开始时保存当前状态，并在图层结束时恢复。
   - 支持对图层应用滤镜 (`PaintFilter`)。

3. **底层绘图接口抽象 (Abstraction of Underlying Drawing Interface):**
   - 充当 Canvas 2D API 和底层图形库 (Skia) 之间的桥梁。
   - 提供了获取 `cc::PaintCanvas` 对象的方法 (`GetOrCreatePaintCanvas()`)，用于实际的绘制操作。
   - 管理 `MemoryManagedPaintRecorder` 来记录绘制操作，以便进行优化和重放。

4. **路径管理 (Path Management):**
   - 维护当前的路径 (`CanvasPath`)，用于绘制形状。
   - 提供了操作路径的方法，例如 `moveTo()`, `lineTo()`, `arc()`, `closePath()` 等 (这些方法的实现在其他地方，但基类负责管理路径对象)。

5. **字体和文本渲染 (Font and Text Rendering):**
   - 存储和管理与文本渲染相关的状态，例如字体 (font)、文本对齐方式 (textAlign)、文本基线 (textBaseline)、文本方向 (direction) 等。
   - 与 `CanvasFontCache` 交互以缓存和获取字体信息。

6. **图像和视频处理 (Image and Video Handling):**
   - 提供了绘制图像 (`drawImage()`) 和视频帧的功能。
   - 与 `CanvasImageSource` 和 `VideoFrame` 等对象交互。

7. **事件处理 (Event Handling):**
   - 实现了处理上下文丢失 (`contextlost`) 和恢复 (`contextrestored`) 事件的机制。
   - 使用定时器来延迟上下文丢失事件的派发和尝试恢复上下文。

8. **性能监控 (Performance Monitoring):**
   - 与 `CanvasPerformanceMonitor` 交互，用于跟踪和分析 Canvas 的性能。

9. **特性开关 (Feature Flags):**
   - 使用特性开关 (`base::FeatureList`) 来控制某些功能的启用或禁用，例如 `kPath2DPaintCache` 和 `kDisableCanvasOverdrawOptimization`。

10. **数据一致性检查 (Data Consistency Checks):**
    - 包含 `ValidateStateStack()` 方法，用于在开发和调试期间检查状态栈的完整性和一致性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**  `BaseRenderingContext2D` 实现了 JavaScript 中 Canvas 2D API 的底层逻辑。当 JavaScript 代码调用 Canvas 2D API 的方法时，最终会调用到这个类（或其派生类）中的相应 C++ 方法。
   * **例子:**  JavaScript 代码 `ctx.fillRect(10, 10, 50, 50);`  最终会触发 `BaseRenderingContext2D` 或其派生类中处理矩形填充的方法，该方法会使用 `cc::PaintCanvas` 在底层进行绘制。
   * **例子:** JavaScript 代码 `ctx.save(); ctx.translate(20, 20); ctx.fillRect(0, 0, 30, 30); ctx.restore();` 会调用 `BaseRenderingContext2D::save()` 保存当前状态，然后修改变换矩阵，绘制矩形，最后调用 `BaseRenderingContext2D::restore()` 恢复之前的变换矩阵。

* **HTML:**  `BaseRenderingContext2D` 与 HTML 的 `<canvas>` 元素紧密相关。当 JavaScript 获取 `<canvas>` 元素的 2D 渲染上下文时 (`canvas.getContext('2d')`)，Blink 引擎会创建一个 `BaseRenderingContext2D` 或其派生类的实例来管理该画布的绘制。
   * **例子:**  HTML 代码 `<canvas id="myCanvas" width="200" height="100"></canvas>` 定义了一个画布元素。JavaScript 通过 `document.getElementById('myCanvas').getContext('2d')` 获取到与此画布关联的 `BaseRenderingContext2D` 实例。

* **CSS:** CSS 可以影响 Canvas 元素本身的一些属性，例如 `width` 和 `height`。虽然 CSS 不能直接控制 Canvas 2D 渲染上下文的绘制状态，但 Canvas 内容可以受到父元素样式的影响，例如字体继承。
   * **例子:**  CSS 代码 `#myCanvas { border: 1px solid black; }` 会给 Canvas 元素添加边框。虽然这与 `BaseRenderingContext2D` 的核心功能无关，但它影响了 Canvas 元素在页面上的呈现。
   * **例子 (字体继承):**  如果 Canvas 元素的父元素设置了 `font-family: Arial;`，并且 Canvas 绘制文本时没有明确设置字体，则可能会继承父元素的字体样式。`BaseRenderingContext2D` 需要处理这种字体信息的获取和应用。

**逻辑推理与假设输入输出：**

假设用户在 JavaScript 中执行以下操作：

```javascript
const canvas = document.getElementById('myCanvas');
const ctx = canvas.getContext('2d');

ctx.fillStyle = 'red';
ctx.fillRect(10, 10, 50, 50);

ctx.save();
ctx.fillStyle = 'blue';
ctx.translate(70, 0);
ctx.fillRect(10, 10, 50, 50);
ctx.restore();

ctx.fillRect(130, 10, 50, 50);
```

**假设输入:** 上述 JavaScript 代码片段。

**逻辑推理与输出:**

1. **`ctx.fillStyle = 'red';`**:  `BaseRenderingContext2D` 的状态会被更新，`fillStyle` 变为红色。
2. **`ctx.fillRect(10, 10, 50, 50);`**:  `BaseRenderingContext2D` 会调用底层绘图接口，使用红色填充一个位于 (10, 10)，宽度和高度都为 50 的矩形。
3. **`ctx.save();`**:  当前渲染状态（包括 `fillStyle` 为红色和当前的变换矩阵）会被推入 `state_stack_`。
4. **`ctx.fillStyle = 'blue';`**:  `BaseRenderingContext2D` 的状态被更新，`fillStyle` 变为蓝色。
5. **`ctx.translate(70, 0);`**:  `BaseRenderingContext2D` 的状态被更新，变换矩阵会加上一个水平平移。
6. **`ctx.fillRect(10, 10, 50, 50);`**:  `BaseRenderingContext2D` 会调用底层绘图接口，使用蓝色填充一个位于经过平移后的 (10, 10)，宽度和高度都为 50 的矩形。这个矩形在画布上的实际位置会是 (80, 10)。
7. **`ctx.restore();`**:  之前保存的状态从 `state_stack_` 中弹出并恢复。这会将 `fillStyle` 恢复为红色，并将变换矩阵恢复到 `save()` 之前的状态。
8. **`ctx.fillRect(130, 10, 50, 50);`**:  `BaseRenderingContext2D` 会调用底层绘图接口，使用红色填充一个位于 (130, 10)，宽度和高度都为 50 的矩形。

**用户或编程常见的使用错误举例：**

1. **`save()` 和 `restore()` 不匹配:**
   ```javascript
   ctx.save();
   ctx.translate(50, 50);
   // 忘记调用 restore()
   ```
   这会导致后续的绘制操作仍然受到 `translate()` 的影响，因为状态没有被正确恢复。`BaseRenderingContext2D` 在 `restore()` 方法中会检查状态栈，但无法在编译时或运行时阻止所有此类错误。

2. **在上下文丢失后尝试操作:**
   ```javascript
   canvas.addEventListener('webglcontextlost', function(event) {
       console.log('Context lost');
   }, false);

   // ... 触发上下文丢失 ...

   ctx.fillRect(10, 10, 50, 50); // 可能会报错或不执行
   ```
   如果 Canvas 的渲染上下文因为某些原因丢失（例如 GPU 错误），尝试继续使用 `ctx` 进行绘制可能会导致错误。`BaseRenderingContext2D::isContextLost()` 方法用于检查上下文状态，并在上下文丢失时阻止某些操作。

3. **错误的图层使用:**
   ```javascript
   ctx.beginLayer();
   // ... 绘制操作 ...
   // 忘记调用 endLayer()
   ```
   未正确闭合的图层可能导致意外的渲染结果或性能问题。`BaseRenderingContext2D::endLayer()` 会检查状态栈以确保与 `beginLayer()` 匹配，并在不匹配时抛出异常。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个包含 `<canvas>` 元素的网页。**
2. **网页的 JavaScript 代码获取了该 Canvas 元素的 2D 渲染上下文 (`canvas.getContext('2d')`)。** 这会在 Blink 引擎中创建一个 `BaseRenderingContext2D` 或其派生类的实例。
3. **JavaScript 代码调用 Canvas 2D API 的方法，例如 `fillRect()`, `save()`, `restore()` 等。**
4. **当调用这些方法时，JavaScript 代码会通过 Blink 的绑定机制 (bindings) 调用到 `BaseRenderingContext2D.cc` 文件中相应的 C++ 方法。**

**调试线索:**

* **设置断点:** 可以在 `BaseRenderingContext2D.cc` 中关键方法（例如 `save()`, `restore()`, `fillRect()`, `beginLayerImpl()`, `endLayer()`）的入口处设置断点。当 JavaScript 代码执行到相应的 Canvas API 调用时，调试器会在此处暂停，允许开发者检查状态和执行流程。
* **查看调用堆栈:** 当断点触发时，可以查看调用堆栈，了解从 JavaScript 代码到 `BaseRenderingContext2D` 的完整调用路径。这有助于理解用户操作是如何最终触发到这部分代码的。
* **检查状态栈:** 在 `save()` 和 `restore()` 方法中，可以观察 `state_stack_` 的变化，确认状态是否按预期保存和恢复。
* **查看 `cc::PaintCanvas` 的操作:**  可以进一步跟踪 `GetOrCreatePaintCanvas()` 返回的 `cc::PaintCanvas` 对象上的操作，了解底层的绘制过程。
* **使用 DevTools 的 Canvas inspection 功能:**  Chrome DevTools 提供了 Canvas inspection 功能，可以捕获 Canvas 的绘制调用，并显示每一步的 API 调用和状态变化，这可以帮助理解用户操作序列如何影响 `BaseRenderingContext2D` 的状态。

**总结（针对 Part 1）:**

`blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 文件定义了 `BaseRenderingContext2D` 类，它是 HTML5 Canvas 2D 渲染上下文的核心基类。它负责管理 Canvas 的渲染状态（包括变换、样式、裁剪等）、处理状态的保存和恢复、管理图层、并作为 JavaScript Canvas 2D API 和底层图形库 (Skia) 之间的桥梁。该类通过 C++ 代码实现了 JavaScript 中 Canvas 2D API 的核心功能，使得开发者可以通过 JavaScript 在 HTML 的 `<canvas>` 元素上进行 2D 图形绘制。 理解这个类的功能是理解浏览器如何渲染 Canvas 内容的关键。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <ostream>  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2053)
#include <string>  // IWYU pragma: keep (for String::Utf8())
#include <type_traits>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/check_deref.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/location.h"
#include "base/memory/raw_ref.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "cc/paint/paint_canvas.h"
#include "cc/paint/paint_flags.h"
#include "cc/paint/paint_image.h"
#include "cc/paint/record_paint_canvas.h"
#include "cc/paint/refcounted_buffer.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/command_buffer/common/sync_token.h"
#include "media/base/video_frame.h"
#include "media/base/video_frame_metadata.h"
#include "media/base/video_transformation.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/color_scheme.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_object_objectarray_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_begin_layer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_2d_gpu_transfer_option.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_font_stretch.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_text_rendering.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_texture_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_canvasfilter_string.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/text_link_colors.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_font_cache.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_image_source.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_performance_monitor.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/canvas/text_cluster.h"
#include "third_party/blink/renderer/core/html/canvas/text_metrics.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/paint/filter_effect_builder.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/cached_color.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_gradient.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_image_source_util.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_path.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_pattern.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_state.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_style.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/identifiability_study_helper.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_index_buffer.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_uv_buffer.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/mesh_2d_vertex_buffer.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/path_2d.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/v8_canvas_style.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_enum_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_selection_types.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/filters/paint_filter_builder.h"
#include "third_party/blink/renderer/platform/graphics/gpu/dawn_control_client_holder.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_cpp.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/image_data_buffer.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/interpolation_space.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_canvas.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_filter.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/graphics/pattern.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/text/unicode_bidi.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/perfetto/include/perfetto/tracing/event_context.h"
#include "third_party/perfetto/include/perfetto/tracing/track_event_args.h"
#include "third_party/skia/include/core/SkAlphaType.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkBlendMode.h"
#include "third_party/skia/include/core/SkClipOp.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkM44.h"
#include "third_party/skia/include/core/SkMatrix.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkPathTypes.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkPoint.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkSamplingOptions.h"
#include "third_party/skia/include/core/SkScalar.h"
#include "third_party/skia/include/private/base/SkTo.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_f.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "ui/gfx/geometry/vector2d.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "v8/include/v8-local-handle.h"

// Including "base/time/time.h" triggers a bug in IWYU.
// https://github.com/include-what-you-use/include-what-you-use/issues/1122
// IWYU pragma: no_include "base/numerics/clamped_math.h"

// UMA Histogram macros trigger a bug in IWYU.
// https://github.com/include-what-you-use/include-what-you-use/issues/1546
// IWYU pragma: no_include <atomic>
// IWYU pragma: no_include <string_view>
// IWYU pragma: no_include "base/metrics/histogram_base.h"

// `base::HashingLRUCache` uses a std::list internally and a bug in IWYU leaks
// that implementation detail.
// https://github.com/include-what-you-use/include-what-you-use/issues/1539
// IWYU pragma: no_include <list>

enum SkColorType : int;

namespace gpu {
struct Mailbox;
}  // namespace gpu

namespace v8 {
class Isolate;
class Value;
}  // namespace v8

namespace blink {

class DOMMatrixInit;
class FontSelector;
class ImageDataSettings;
class ScriptState;
class SimpleFontData;

using ::cc::UsePaintCache;

BASE_FEATURE(kDisableCanvasOverdrawOptimization,
             "DisableCanvasOverdrawOptimization",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Maximum number of colors in the color cache
// (`BaseRenderingContext2D::color_cache_`).
constexpr size_t kColorCacheMaxSize = 8;

const char BaseRenderingContext2D::kDefaultFont[] = "10px sans-serif";
const char BaseRenderingContext2D::kInheritDirectionString[] = "inherit";
const char BaseRenderingContext2D::kRtlDirectionString[] = "rtl";
const char BaseRenderingContext2D::kLtrDirectionString[] = "ltr";
const char BaseRenderingContext2D::kAutoKerningString[] = "auto";
const char BaseRenderingContext2D::kNormalKerningString[] = "normal";
const char BaseRenderingContext2D::kNoneKerningString[] = "none";
const char BaseRenderingContext2D::kUltraCondensedString[] = "ultra-condensed";
const char BaseRenderingContext2D::kExtraCondensedString[] = "extra-condensed";
const char BaseRenderingContext2D::kCondensedString[] = "condensed";
const char BaseRenderingContext2D::kSemiCondensedString[] = "semi-condensed";
const char BaseRenderingContext2D::kNormalStretchString[] = "normal";
const char BaseRenderingContext2D::kSemiExpandedString[] = "semi-expanded";
const char BaseRenderingContext2D::kExpandedString[] = "expanded";
const char BaseRenderingContext2D::kExtraExpandedString[] = "extra-expanded";
const char BaseRenderingContext2D::kUltraExpandedString[] = "ultra-expanded";
const char BaseRenderingContext2D::kNormalVariantString[] = "normal";
const char BaseRenderingContext2D::kSmallCapsVariantString[] = "small-caps";
const char BaseRenderingContext2D::kAllSmallCapsVariantString[] =
    "all-small-caps";
const char BaseRenderingContext2D::kPetiteVariantString[] = "petite-caps";
const char BaseRenderingContext2D::kAllPetiteVariantString[] =
    "all-petite-caps";
const char BaseRenderingContext2D::kUnicaseVariantString[] = "unicase";
const char BaseRenderingContext2D::kTitlingCapsVariantString[] = "titling-caps";

// Dummy overdraw test for ops that do not support overdraw detection
const auto kNoOverdraw = [](const SkIRect& clip_bounds) { return false; };

// After context lost, it waits |kTryRestoreContextInterval| before start the
// restore the context. This wait needs to be long enough to avoid spamming the
// GPU process with retry attempts and short enough to provide decent UX. It's
// currently set to 500ms.
const base::TimeDelta kTryRestoreContextInterval = base::Milliseconds(500);

BaseRenderingContext2D::BaseRenderingContext2D(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : dispatch_context_lost_event_timer_(
          task_runner,
          this,
          &BaseRenderingContext2D::DispatchContextLostEvent),
      dispatch_context_restored_event_timer_(
          task_runner,
          this,
          &BaseRenderingContext2D::DispatchContextRestoredEvent),
      try_restore_context_event_timer_(
          task_runner,
          this,
          &BaseRenderingContext2D::TryRestoreContextEvent),
      clip_antialiasing_(kNotAntiAliased),
      path2d_use_paint_cache_(
          base::FeatureList::IsEnabled(features::kPath2DPaintCache)
              ? UsePaintCache::kEnabled
              : UsePaintCache::kDisabled) {
  state_stack_.push_back(MakeGarbageCollected<CanvasRenderingContext2DState>());
}

BaseRenderingContext2D::~BaseRenderingContext2D() {
  UMA_HISTOGRAM_CUSTOM_COUNTS("Blink.Canvas.MaximumStateStackDepth",
                              max_state_stack_depth_, 1, 33, 32);
}

void BaseRenderingContext2D::save() {
  if (isContextLost()) [[unlikely]] {
    return;
  }
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kSave);
  }

  ValidateStateStack();

  // GetOrCreatePaintCanvas() can call RestoreMatrixClipStack which syncs
  // canvas to state_stack_. Get the canvas before adjusting state_stack_ to
  // ensure canvas is synced prior to adjusting state_stack_.
  cc::PaintCanvas* canvas = GetOrCreatePaintCanvas();

  state_stack_.push_back(MakeGarbageCollected<CanvasRenderingContext2DState>(
      GetState(), CanvasRenderingContext2DState::kDontCopyClipList,
      CanvasRenderingContext2DState::SaveType::kSaveRestore));
  max_state_stack_depth_ =
      std::max(state_stack_.size(), max_state_stack_depth_);

  if (canvas)
    canvas->save();

  ValidateStateStack();
}

void BaseRenderingContext2D::restore(ExceptionState& exception_state) {
  if (isContextLost()) [[unlikely]] {
    return;
  }

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kRestore);
  }
  ValidateStateStack();
  if (state_stack_.size() <= 1)
    // State stack is empty. Extra `restore()` are silently ignored.
    return;

  // Verify that the top of the stack was pushed with Save.
  if (GetState().GetSaveType() !=
      CanvasRenderingContext2DState::SaveType::kSaveRestore) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Called `restore()` with no matching `save()` inside layer.");
    return;
  }

  cc::PaintCanvas* canvas = GetOrCreatePaintCanvas();
  if (!canvas) {
    return;
  }

  PopAndRestore(*canvas);
  ValidateStateStack();
}

void BaseRenderingContext2D::beginLayerImpl(ScriptState* script_state,
                                            const BeginLayerOptions* options,
                                            ExceptionState* exception_state) {
  if (isContextLost()) [[unlikely]] {
    return;
  }
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();

  // Make sure we have a recorder and paint canvas.
  if (!GetOrCreatePaintCanvas()) {
    return;
  }

  MemoryManagedPaintRecorder* recorder = Recorder();
  if (!recorder) {
    return;
  }

  ValidateStateStack();

  sk_sp<PaintFilter> filter;
  if (options != nullptr) {
    CHECK(exception_state != nullptr);
    if (const V8CanvasFilterInput* filter_input = options->filter();
        filter_input != nullptr) {
      AddLayerFilterUserCount(filter_input);

      HTMLCanvasElement* canvas_for_filter = HostAsHTMLCanvasElement();
      FilterOperations filter_operations = CanvasFilter::CreateFilterOperations(
          *filter_input, AccessFont(canvas_for_filter), canvas_for_filter,
          CHECK_DEREF(ExecutionContext::From(script_state)), *exception_state);
      if (exception_state->HadException()) {
        return;
      }

      const gfx::SizeF canvas_viewport(Width(), Height());
      FilterEffectBuilder filter_effect_builder(
          gfx::RectF(canvas_viewport), canvas_viewport,
          1.0f,  // Deliberately ignore zoom on the canvas element.
          Color::kBlack, mojom::blink::ColorScheme::kLight);

      filter = paint_filter_builder::Build(
          filter_effect_builder.BuildFilterEffect(std::move(filter_operations),
                                                  !OriginClean()),
          kInterpolationSpaceSRGB);
    }
  }

  if (layer_count_ == 0) {
    recorder->BeginSideRecording();
  }

  ++layer_count_;

  // Layers are recorded on a side canvas to allow flushes with unclosed layers.
  // When calling `BeginSideRecording()` for the top level layer,
  // `getRecordingCanvas()` goes from returning the main canvas to returning the
  // side canvas storing layer content.
  cc::PaintCanvas& layer_canvas = recorder->getRecordingCanvas();

  const CanvasRenderingContext2DState& state = GetState();
  CanvasRenderingContext2DState::SaveType save_type =
      SaveLayerForState(state, filter, layer_canvas);
  state_stack_.push_back(MakeGarbageCollected<CanvasRenderingContext2DState>(
      state, CanvasRenderingContext2DState::kDontCopyClipList, save_type));
  max_state_stack_depth_ =
      std::max(state_stack_.size(), max_state_stack_depth_);

  ValidateStateStack();

  // Reset compositing attributes.
  setShadowOffsetX(0);
  setShadowOffsetY(0);
  setShadowBlur(0);
  CanvasRenderingContext2DState& layer_state = GetState();
  layer_state.SetShadowColor(Color::kTransparent);
  DCHECK(!layer_state.ShouldDrawShadows());
  setGlobalAlpha(1.0);
  setGlobalCompositeOperation("source-over");
  setFilter(script_state,
            MakeGarbageCollected<V8UnionCanvasFilterOrString>("none"));
}

void BaseRenderingContext2D::AddLayerFilterUserCount(
    const V8CanvasFilterInput* filter_input) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvas2DLayersFilters);
  if (filter_input->GetContentType() ==
      V8CanvasFilterInput::ContentType::kString) {
    UseCounter::Count(GetTopExecutionContext(),
                      WebFeature::kCanvas2DLayersCSSFilters);
  } else {
    UseCounter::Count(GetTopExecutionContext(),
                      WebFeature::kCanvas2DLayersFilterObjects);
  }
}

class ScopedResetCtm {
 public:
  ScopedResetCtm(const CanvasRenderingContext2DState& state,
                 cc::PaintCanvas& canvas)
      : canvas_(canvas) {
    if (!state.GetTransform().IsIdentity()) {
      ctm_to_restore_ = canvas_->getLocalToDevice();
      canvas_->save();
      canvas_->setMatrix(SkM44());
    }
  }
  ~ScopedResetCtm() {
    if (ctm_to_restore_.has_value()) {
      canvas_->setMatrix(*ctm_to_restore_);
    }
  }

 private:
  const raw_ref<cc::PaintCanvas> canvas_;
  std::optional<SkM44> ctm_to_restore_;
};

namespace {
sk_sp<PaintFilter> CombineFilters(sk_sp<PaintFilter> first,
                                  sk_sp<PaintFilter> second) {
  if (second) {
    return sk_make_sp<ComposePaintFilter>(std::move(first), std::move(second));
  }
  return first;
}
}  // namespace

CanvasRenderingContext2DState::SaveType
BaseRenderingContext2D::SaveLayerForState(
    const CanvasRenderingContext2DState& state,
    sk_sp<PaintFilter> layer_filter,
    cc::PaintCanvas& canvas) {
  if (!IsTransformInvertible()) {
    canvas.saveLayerAlphaf(1.0f);
    return CanvasRenderingContext2DState::SaveType::kBeginEndLayerOneSave;
  }

  const int initial_save_count = canvas.getSaveCount();
  bool needs_compositing = state.GlobalComposite() != SkBlendMode::kSrcOver;
  sk_sp<PaintFilter> context_filter = StateGetFilter();

  // The "copy" globalCompositeOperation replaces everything that was in the
  // canvas. We therefore have to clear the canvas before proceeding. Since the
  // shadow and foreground are composited one after the other, the foreground
  // gets composited over the shadow itself. This means that in "copy"
  // compositing mode, drawing the foreground will clear the shadow. There's
  // therefore no need to draw the shadow at all.
  //
  // Global states must be applied on the result of the layer's filter, so the
  // filter has to go in a nested layer.
  //
  // For globalAlpha + (shadows or compositing), we must use two nested layers.
  // The inner one applies the alpha and the outer one applies the shadow and/or
  // compositing. This is needed to get a transparent foreground, as the alpha
  // would otherwise be applied to the result of foreground+background.
  if (state.GlobalComposite() == SkBlendMode::kSrc) {
    canvas.clear(HasAlpha() ? SkColors::kTransparent : SkColors::kBlack);
    if (context_filter) {
      ScopedResetCtm scoped_reset_ctm(state, canvas);
      cc::PaintFlags flags;
      flags.setImageFilter(std::move(context_filter));
      canvas.saveLayer(flags);
    }
    needs_compositing = false;
  } else if (bool should_draw_shadow = state.ShouldDrawShadows(),
             needs_composited_draw = BlendModeRequiresCompositedDraw(state);
             context_filter || should_draw_shadow || needs_composited_draw) {
    if (should_draw_shadow && (context_filter || needs_composited_draw)) {
      ScopedResetCtm scoped_reset_ctm(state, canvas);
      // According to the WHATWG spec, the shadow and foreground need to be
      // composited independently to the canvas, one after the other
      // (https://html.spec.whatwg.org/multipage/canvas.html#drawing-model).
      // This is done by drawing twice, once for the background and once more
      // for the foreground. For layers, we can do this by passing two filters
      // that will each do a composite pass of the input to the destination.
      // Passing `nullptr` for the second pass means no filter is applied to the
      // foreground.
      cc::PaintFlags flags;
      flags.setBlendMode(state.GlobalComposite());
      sk_sp<PaintFilter> shadow_filter =
          CombineFilters(state.ShadowOnlyImageFilter(), context_filter);
      canvas.saveLayerFilters(
          {{std::move(shadow_filter), std::move(context_filter)}}, flags);
    } else if (should_draw_shadow) {
      ScopedResetCtm scoped_reset_ctm(state, canvas);
      cc::PaintFlags flags;
      flags.setImageFilter(state.ShadowAndForegroundImageFilter());
      flags.setBlendMode(state.GlobalComposite());
      canvas.saveLayer(flags);
    } else if (context_filter) {
      ScopedResetCtm scoped_reset_ctm(state, canvas);
      cc::PaintFlags flags;
      flags.setBlendMode(state.GlobalComposite());
      flags.setImageFilter(std::move(context_filter));
      canvas.saveLayer(flags);
    } else {
      cc::PaintFlags flags;
      flags.setBlendMode(state.GlobalComposite());
      canvas.saveLayer(flags);
    }
    needs_compositing = false;
  }

  if (layer_filter || needs_compositing) {
    cc::PaintFlags flags;
    flags.setAlphaf(static_cast<float>(state.GlobalAlpha()));
    flags.setImageFilter(layer_filter);
    if (needs_compositing) {
      flags.setBlendMode(state.GlobalComposite());
    }
    canvas.saveLayer(flags);
  } else if (state.GlobalAlpha() != 1 ||
             initial_save_count == canvas.getSaveCount()) {
    canvas.saveLayerAlphaf(state.GlobalAlpha());
  }

  const int save_diff = canvas.getSaveCount() - initial_save_count;
  return CanvasRenderingContext2DState::LayerSaveCountToSaveType(save_diff);
}

void BaseRenderingContext2D::endLayer(ExceptionState& exception_state) {
  if (isContextLost()) [[unlikely]] {
    return;
  }
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();

  ValidateStateStack();
  if (state_stack_.size() <= 1 || layer_count_ <= 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Called `endLayer()` with no matching `beginLayer()`.");
    return;
  }

  // Verify that the top of the stack was pushed with `beginLayer`.
  if (!GetState().IsLayerSaveType()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Called `endLayer()` with no matching `beginLayer()` inside parent "
        "`save()`/`restore()` pair.");
    return;
  }

  // Make sure we have a recorder and paint canvas.
  if (!GetOrCreatePaintCanvas()) {
    return;
  }

  MemoryManagedPaintRecorder* recorder = Recorder();
  if (!recorder) {
    return;
  }

  cc::PaintCanvas& layer_canvas = recorder->getRecordingCanvas();
  PopAndRestore(layer_canvas);

  --layer_count_;
  if (layer_count_ == 0) {
    recorder->EndSideRecording();
  }

  // Layers are recorded on a side canvas to allow flushes with unclosed layers.
  // When calling `EndSideRecording()` for the lop layer, `getRecordingCanvas()`
  // goes from returning the side canvas storing the layers content to returning
  // the main canvas.
  cc::PaintCanvas& parent_canvas = recorder->getRecordingCanvas();
  SkIRect clip_bounds;
  if (parent_canvas.getDeviceClipBounds(&clip_bounds)) {
    WillDraw(clip_bounds, CanvasPerformanceMonitor::DrawType::kOther);
  }

  ValidateStateStack();
}

void BaseRenderingContext2D::PopAndRestore(cc::PaintCanvas& canvas) {
  if (IsTransformInvertible() && !GetState().GetTransform().IsIdentity()) {
    GetModifiablePath().Transform(GetState().GetTransform());
  }

  for (int i = 0, to_restore = state_stack_.back()->LayerSaveCount() - 1;
       i < to_restore; ++i) {
    canvas.restore();
  }

  canvas.restore();
  state_stack_.pop_back();
  CanvasRenderingContext2DState& state = GetState();
  state.ClearResolvedFilter();

  SetIsTransformInvertible(state.IsTransformInvertible());
  if (IsTransformInvertible() && !GetState().GetTransform().IsIdentity()) {
    GetModifiablePath().Transform(state.GetTransform().Inverse());
  }
}

void BaseRenderingContext2D::ValidateStateStackImpl(
    const cc::PaintCanvas* canvas) const {
  DCHECK_GE(state_stack_.size(), 1u);
  DCHECK_GT(state_stack_.size(),
            base::checked_cast<WTF::wtf_size_t>(layer_count_));

  using SaveType = CanvasRenderingContext2DState::SaveType;
  DCHECK_EQ(state_stack_[0]->GetSaveType(), SaveType::kInitial);

  int actual_layer_count = 0;
  int extra_layer_saves = 0;
  for (wtf_size_t i = 1; i < state_stack_.size(); ++i) {
    if (RuntimeEnabledFeatures::Canvas2dLayersEnabled()) {
      DCHECK_NE(state_stack_[i]->GetSaveType(), SaveType::kInitial);
    } else {
      DCHECK_EQ(state_stack_[i]->GetSaveType(), SaveType::kSaveRestore);
    }

    if (state_stack_[i]->IsLayerSaveType()) {
      ++actual_layer_count;
      extra_layer_saves += state_stack_[i]->LayerSaveCount() - 1;
    }
  }
  DCHECK_EQ(layer_count_, actual_layer_count);

  if (const MemoryManagedPaintRecorder* recorder = Recorder();
      recorder != nullptr) {
    if (canvas == nullptr) {
      canvas = &recorder->GetMainCanvas();
    }
    const cc::PaintCanvas* layer_canvas = recorder->GetSideCanvas();

    // The canvas should always have an initial save frame, to support
    // resetting the top level matrix and clip.
    DCHECK_GT(canvas->getSaveCount(), 1);

    if (context_lost_mode_ == CanvasRenderingContext::kNotLostContext) {
      // Recording canvases always starts with a baseline save that we have to
      // account for here.
      int main_saves = canvas->getSaveCount() - 1;
      int layer_saves = layer_canvas ? layer_canvas->getSaveCount() - 1 : 0;

      // The state stack depth should match the number of saves in the
      // recording (taking in to account that some layers require two saves).
      DCHECK_EQ(base::checked_cast<WTF::wtf_size_t>(main_saves + layer_saves),
                state_stack_.size() + extra_layer_saves);
    }
  }
}

void BaseRenderingContext2D::RestoreMatrixClipStack(cc::PaintCanvas* c) const {
  if (!c)
    return;
  AffineTransform prev_transform;
  for (Member<CanvasRenderingContext2DState> curr_state : state_stack_) {
    if (curr_state->IsLayerSaveType()) {
      // Layers are stored in a separate recording that never gets flushed, so
      // we are done restoring the main recording.
      break;
    }

    c->save();

    if (curr_state->HasClip()) {
      if (!prev_transform.IsIdentity()) {
        c->setMatrix(SkM44());
        prev_transform = AffineTransform();
      }
      curr_state->PlaybackClips(c);
    }

    if (AffineTransform curr_transform = curr_state->GetTransform();
        prev_transform != curr_transform) {
      c->setMatrix(AffineTransformToSkM44(curr_transform));
      prev_transform = curr_transform;
    }
  }
  ValidateStateStack(c);
}

void BaseRenderingContext2D::ResetInternal() {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kReset);
  }
  ValidateStateStack();
  state_stack_.resize(1);
  state_stack_.front() = MakeGarbageCollected<CanvasRenderingContext2DState>();
  layer_count_ = 0;
  SetIsTransformInvertible(true);
  CanvasPath::Clear();
  if (MemoryManagedPaintRecorder* recorder = Recorder(); recorder != nullptr) {
    recorder->RestartRecording();
  }

  // If a WebGPU transfer texture exists, we must destroy it immediately. We
  // can't allow it to continue to exist, as it would be subject to Javascript
  // garbage-collect
```