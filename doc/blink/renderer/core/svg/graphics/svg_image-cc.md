Response:
Let's break down the thought process for analyzing the `svg_image.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the `SVGImage` class, its relationships with web technologies (HTML, CSS, JavaScript), common errors, debugging hints, and reasoning behind its behavior.

2. **Identify the Core Entity:** The file is `svg_image.cc`, and the primary class within it is `SVGImage`. This is the central point of investigation.

3. **Scan for Key Functionality Indicators:**  Look for methods and member variables that suggest the class's purpose. Keywords like `Draw`, `Paint`, `Animation`, `Load`, `Size`, `View`, and interactions with other classes (e.g., `SVGSVGElement`, `LayoutSVGRoot`, `GraphicsContext`) are strong clues.

4. **Group Related Functionalities:**  As you scan, group related methods. For instance:
    * **Drawing/Rendering:**  `DrawForContainer`, `DrawInternal`, `PaintRecordForCurrentFrame`, `ApplyShader`, `PopulatePaintRecordForCurrentFrameForContainer`.
    * **Animation:** `StartAnimation`, `StopAnimation`, `ResetAnimation`, `ServiceAnimations`, `AdvanceAnimationForTesting`, `ScheduleTimelineRewind`, `FlushPendingTimelineRewind`.
    * **Loading/Initialization:** `SVGImage` (constructor), `DataChanged`, interaction with `IsolatedSVGDocumentHost`.
    * **Sizing:** `SizeWithConfig`, `GetIntrinsicSizingInfo`.
    * **View Management (Fragments/Anchors):** `CreateViewInfo`, `ApplyViewInfo`.
    * **Resource Handling:** `GetResourceElement`.
    * **Other:**  `IsInSVGImage`, `GetFrame`, `RootElement`, `LayoutRoot`, `CurrentFrameHasSingleSecurityOrigin`, `SetPreferredColorScheme`, `UpdateUseCounters`.

5. **Analyze Relationships with Web Technologies:**
    * **HTML:**  Think about how SVG images are included in HTML. The `<image>` tag and inline SVG `<svg>` element are the main connections. The `SVGImage` class *renders* these elements. The `src` attribute of `<img>` points to SVG files.
    * **CSS:**  Consider how CSS styles SVG images. Properties like `width`, `height`, `background-image` (with SVG URLs), `mask`, and transforms can affect the rendering. The `container_size_` and the `dst_rect` in the drawing methods are key points where CSS sizing influences the SVG.
    * **JavaScript:** How can JavaScript interact with SVG images?  Manipulating the DOM of the embedded SVG, animating SVG elements via JavaScript, and using SVG as a texture or pattern via canvas or WebGL are possibilities. Methods like `StartAnimation`, `StopAnimation`, and potentially direct DOM manipulation within the SVG document are relevant. Also, consider the use of fragments (`#`) to target specific SVG elements.

6. **Consider Logical Reasoning (Hypothetical Inputs/Outputs):** For specific methods, imagine what would happen given certain inputs.
    * `GetIntrinsicSizingInfo`:  Input: an SVG document with or without `viewBox` and intrinsic dimensions. Output: `IntrinsicSizingInfo` structure containing width, height, and aspect ratio information.
    * `CreateViewInfo`: Input: a URL fragment (e.g., `#elementId` or `#viewBox(0,0,100,100)`). Output: An `SVGImageViewInfo` object containing the target element or the parsed view specification. If the fragment is invalid, the output would be `nullptr`.
    * `DrawInternal`: Input:  a `PaintCanvas`, `PaintFlags`, destination rectangle, source rectangle. Output: The SVG content rendered onto the canvas within the specified rectangles, respecting the flags.

7. **Identify Common User/Programming Errors:**  Think about mistakes developers might make when using SVGs.
    * **Incorrect Fragment Identifiers:**  Referring to non-existent IDs in the SVG using `#`.
    * **Cross-Origin Issues:** Trying to use SVG images from different domains without proper CORS headers, particularly if the SVG contains `<foreignObject>` or other embedded resources.
    * **Animation Problems:**  Not understanding how SVG animations (SMIL or CSS/JS) are controlled and potentially conflicting animation triggers.
    * **Sizing Issues:** Difficulty in getting the SVG to scale correctly within its container, especially with different `preserveAspectRatio` settings.

8. **Construct Debugging Clues (User Actions):** Trace back how a user's actions could lead to the execution of the code in `svg_image.cc`. This typically involves:
    * **Loading an HTML Page:** The initial trigger.
    * **Encountering an SVG Image:** This could be via `<img>`, inline `<svg>`, or as a CSS `background-image`.
    * **Browser Rendering Engine Processing:** The browser parses the HTML/CSS and creates the render tree.
    * **Layout Calculation:** The browser determines the size and position of the SVG image.
    * **Painting:** This is where the `SVGImage` class comes into play to actually draw the SVG content onto the screen.
    * **Animation (if present):**  The animation logic within `SVGImage` will be executed during the rendering loop.
    * **Interaction (e.g., clicking on a link with a fragment):** This can trigger the view management logic (`CreateViewInfo`, `ApplyViewInfo`).

9. **Organize and Refine:** Structure the findings logically, using clear headings and bullet points. Ensure that the explanations are easy to understand and directly address the request's points. Provide concrete examples where possible.

10. **Self-Critique and Review:** Read through the generated response and ask:
    * Does it accurately describe the functionalities of `SVGImage.cc`?
    * Are the connections to HTML, CSS, and JavaScript clearly explained with examples?
    * Are the hypothetical input/output examples helpful?
    * Are the common errors and debugging tips relevant?
    * Is the explanation of user actions leading to the code execution clear?
    * Is the language precise and avoids jargon where possible?

By following these steps, you can systematically analyze a complex source file and provide a comprehensive and informative answer. The key is to break down the problem, focus on the core entity, and then explore its interactions and potential issues.
这个文件 `blink/renderer/core/svg/graphics/svg_image.cc` 定义了 Blink 渲染引擎中用于处理和渲染 SVG 图像的 `SVGImage` 类。它负责加载、解析、动画和绘制 SVG 内容。

下面是它的主要功能及其与 JavaScript、HTML 和 CSS 的关系，以及一些使用错误和调试线索：

**`SVGImage` 的主要功能：**

1. **SVG 内容加载和解析:**
   - `DataChanged()` 方法负责接收 SVG 图像数据，并触发内部的 SVG 文档解析和初始化。
   - 它创建并管理一个 `IsolatedSVGDocumentHost` 对象，该对象负责托管一个独立的 SVG 文档上下文。

2. **SVG 渲染:**
   - `Draw()` 和 `DrawInternal()` 方法是核心的渲染函数，负责将 SVG 内容绘制到 `cc::PaintCanvas` 上。
   - 它会考虑容器的大小、缩放级别、以及可能存在的视口信息 (`SVGImageViewInfo`)。
   - `PaintRecordForCurrentFrame()` 方法生成用于绘制的 `PaintRecord`，这是一个记录了绘制操作的数据结构，可以被缓存和重放。
   - 支持暗黑模式 (`DrawInfo::is_dark_mode_enabled_`)。

3. **SVG 动画控制:**
   - 实现了对 SMIL 动画的支持 (`HasSmilAnimations()`)。
   - `StartAnimation()`, `StopAnimation()`, `ResetAnimation()` 方法用于控制 SVG 动画的播放状态。
   - `ServiceAnimations()` 方法在渲染循环中被调用，用于驱动 SVG 动画的更新。
   - `AdvanceAnimationForTesting()` 用于测试目的，可以手动推进动画帧。
   - `ScheduleTimelineRewind()` 和 `FlushPendingTimelineRewind()` 用于在某些情况下重置动画时间线。

4. **处理 SVG 视口和片段标识符:**
   - `CreateViewInfo()` 方法解析 URL 中的片段标识符（例如 `#fragment` 或 `#viewBox(...)`），以确定要显示的 SVG 部分。
   - `ApplyViewInfo()` 方法将解析后的视口信息应用到 SVG 文档，从而改变渲染的内容。

5. **获取 SVG 的固有尺寸:**
   - `GetIntrinsicSizingInfo()` 方法用于计算 SVG 图像的固有宽度和高度，这对于布局计算非常重要。

6. **处理 SVG 中的资源引用:**
   - `GetResourceElement()` 方法允许根据 ID 获取 SVG 文档中的元素。

7. **管理独立的 SVG 文档上下文:**
   - 使用 `IsolatedSVGDocumentHost` 来隔离 SVG 文档，防止其脚本和样式影响主文档，并提供一个独立的安全上下文。

**与 JavaScript、HTML 和 CSS 的关系：**

1. **HTML:**
   - `SVGImage` 负责渲染通过以下 HTML 元素引入的 SVG 内容：
     - `<image>` 元素：`src` 属性指向 SVG 文件。`SVGImage` 会加载并渲染这个 SVG 文件。
     - `<object>` 元素：当 `type` 属性设置为 `image/svg+xml` 时，`SVGImage` 也会处理。
     - `<iframe>` 元素：虽然 `<iframe>` 会加载一个完整的 HTML 文档，但如果该文档的内容是 SVG，那么 `SVGImage` 的相关机制也会参与渲染。
     - 内联 SVG `<svg>` 元素：虽然 `SVGImage` 主要处理外部 SVG 文件，但其内部的渲染逻辑与内联 SVG 的渲染是相似的。

   **举例:**
   ```html
   <img src="image.svg">  <!-- 加载并渲染 image.svg -->
   <object data="vector.svg" type="image/svg+xml"></object> <!-- 加载并渲染 vector.svg -->
   ```

2. **CSS:**
   - CSS 可以影响 SVG 图像的显示方式：
     - `width` 和 `height` 属性：控制 SVG 图像在其容器中的尺寸。`SVGImage` 的渲染会根据这些尺寸进行缩放。
     - `background-image` 属性：可以使用 SVG 文件作为背景图像。`SVGImage` 会被用来渲染这个背景图像。
     - `mask-image` 属性：可以使用 SVG 文件作为遮罩。`SVGImage` 会被用来渲染这个遮罩。
     - `clip-path` 属性：可以使用 SVG 图形定义裁剪路径。
     - `transform` 属性：可以对 SVG 图像进行旋转、缩放等变换。

   **举例:**
   ```css
   .icon {
     width: 32px;
     height: 32px;
     background-image: url('icon.svg');
   }

   .mask {
     mask-image: url('mask.svg');
   }
   ```

3. **JavaScript:**
   - JavaScript 可以通过 DOM API 与嵌入到 HTML 中的 SVG 内容进行交互：
     - 获取和修改 SVG 元素的属性。
     - 添加、删除 SVG 元素。
     - 触发和监听 SVG 事件。
     - 控制 SVG 动画（SMIL 或 JavaScript 动画）。

   - 对于通过 `<img>` 或 `<object>` 嵌入的 SVG，JavaScript 通常无法直接访问其内部的 DOM 结构（出于安全原因，特别是跨域情况）。但是，可以使用一些技巧，例如将 SVG 内联到 HTML 中，或者使用 `fetch` API 获取 SVG 内容并动态插入。

   - `SVGImage` 提供的 `StartAnimation()`, `StopAnimation()`, `ResetAnimation()` 等方法可以通过 Blink 的内部机制被 JavaScript 触发，例如当 SVG 元素通过 JavaScript 被添加到 DOM 中或属性发生变化时。

   **举例:**
   ```javascript
   // 假设有一个 id 为 "mySVG" 的 <object> 元素加载了 SVG
   const svgObject = document.getElementById('mySVG');
   if (svgObject.contentDocument) {
     const circle = svgObject.contentDocument.getElementById('myCircle');
     circle.setAttribute('fill', 'red'); // 修改 SVG 内部元素的属性
   }
   ```

**逻辑推理 (假设输入与输出):**

假设有一个简单的 SVG 文件 `circle.svg`：

```xml
<svg width="100" height="100" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40" fill="blue" />
</svg>
```

**场景 1：通过 `<img>` 加载**

- **假设输入：** HTML 中有 `<img src="circle.svg" width="50" height="50">`。
- **逻辑推理：**
    - 浏览器会请求 `circle.svg` 文件。
    - `SVGImage::DataChanged()` 会接收 SVG 数据。
    - `SVGImage` 会解析 SVG 内容，获取宽度、高度和 `viewBox` 信息。
    - 由于 `<img>` 标签指定了 `width="50"` 和 `height="50"`，`SVGImage::Draw()` 会将 SVG 内容缩放到 50x50 的区域进行渲染。
- **预期输出：** 在页面上渲染出一个蓝色的圆形，大小为 50x50 像素。

**场景 2：通过带有片段标识符的 `<img>` 加载**

- **假设输入：**  `circle.svg` 中有一个 id 为 `myCircle` 的元素，HTML 中有 `<img src="circle.svg#myCircle">`。
- **逻辑推理：**
    - `SVGImage::CreateViewInfo()` 会解析 URL 中的 `#myCircle` 片段标识符。
    - `SVGImage` 会尝试在 SVG 文档中找到 id 为 `myCircle` 的元素。
    - 如果找到，`SVGImage::ApplyViewInfo()` 会更新渲染上下文，可能只显示包含该元素的区域（具体行为取决于 SVG 文档的结构和浏览器实现）。
- **预期输出：**  显示的可能是仅包含 `myCircle` 元素的区域，而不是整个 100x100 的 SVG 画布。

**用户或编程常见的使用错误：**

1. **错误的 SVG 文件路径或 URL：** 导致 `SVGImage` 无法加载 SVG 数据，页面上可能显示 broken image 图标。
2. **SVG 内容格式错误：**  如果 SVG 文件包含 XML 语法错误或无效的 SVG 元素，`SVGImage` 的解析过程可能会失败，导致渲染错误或无法渲染。
3. **跨域问题：**  如果 HTML 页面和 SVG 文件位于不同的域，浏览器可能会阻止加载 SVG 资源，除非服务器设置了正确的 CORS 头。这在 `<image>`、`<object>` 或 CSS `background-image` 中使用 SVG 时常见。
4. **不正确的片段标识符：** 在 URL 中使用了不存在于 SVG 文档中的 ID，导致 `CreateViewInfo()` 无法找到目标元素，视口可能不会按预期改变。
5. **动画控制错误：**  在 JavaScript 中错误地调用 `StartAnimation()`, `StopAnimation()`, `ResetAnimation()`，或者与 SMIL 动画的逻辑冲突，导致动画无法正常播放或状态不一致。
6. **忽略 `viewBox` 属性：**  不理解 `viewBox` 属性的作用，可能导致 SVG 在不同尺寸的容器中缩放行为不符合预期。
7. **在 `<foreignObject>` 中使用跨域内容：**  `SVGImage::CurrentFrameHasSingleSecurityOrigin()` 会检查是否存在 `SVGForeignObjectElement`，如果其内容来自不同的源，可能会导致安全问题。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个包含 SVG 图像的 HTML 页面。**
2. **浏览器解析 HTML 代码，遇到 `<img>`、`<object>` 或 CSS 中引用 SVG 文件的声明。**
3. **浏览器发起网络请求，下载 SVG 文件。**
4. **`SVGImage::DataChanged()` 方法接收到下载的 SVG 数据。**
5. **`SVGImage` 内部的 SVG 解析器开始解析 SVG 内容，构建 SVG DOM 树。**
6. **布局引擎计算 SVG 图像在页面上的尺寸和位置。**
7. **渲染引擎执行绘制操作，调用 `SVGImage::Draw()` 或 `SVGImage::DrawInternal()` 方法。**
8. **`PaintRecordForCurrentFrame()` 方法被调用，生成用于绘制的指令。**
9. **这些指令被传递给底层的图形库 (例如 Skia) 进行实际的像素绘制。**

**调试线索：**

- **检查网络请求：**  确认 SVG 文件是否成功加载，HTTP 状态码是否为 200，以及是否存在 CORS 错误。
- **查看控制台错误：**  浏览器控制台可能会显示 SVG 解析错误或与安全相关的错误。
- **使用浏览器开发者工具的 "Elements" 面板：**  查看渲染出的 SVG 元素的属性和样式，确认尺寸、`viewBox` 等是否符合预期。
- **使用 "Sources" 或 "Debugger" 面板：**  设置断点在 `SVGImage::DataChanged()`, `SVGImage::Draw()`, `PaintRecordForCurrentFrame()` 等关键方法中，跟踪 SVG 数据的加载、解析和渲染过程。
- **检查 SVG 文件内容：**  使用文本编辑器或 SVG 编辑器打开 SVG 文件，确认其语法是否正确，是否存在预期的元素和属性。
- **检查 URL 片段标识符：**  确认 URL 中的片段标识符是否正确拼写，并且对应的 ID 存在于 SVG 文档中。
- **对于动画问题，检查 SMIL 代码或 JavaScript 动画逻辑。**
- **查看 Blink 渲染引擎的日志或 tracing 信息，** 如果你有 Blink 的开发环境，可以更深入地了解渲染过程。

总而言之，`blink/renderer/core/svg/graphics/svg_image.cc` 文件是 Blink 渲染引擎中处理 SVG 图像的核心组件，它连接了 HTML、CSS 和 JavaScript，负责将 SVG 内容转化为用户在浏览器中看到的图像。理解其功能和相关接口对于调试和理解 SVG 渲染问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/svg/graphics/svg_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Apple Inc. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/svg/animation/smil_time_container.h"
#include "third_party/blink/renderer/core/svg/graphics/isolated_svg_document_host.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_chrome_client.h"
#include "third_party/blink/renderer/core/svg/svg_animated_preserve_aspect_ratio.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_fe_image_element.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_view_spec.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/image_observer.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_shader.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

namespace {

bool HasSmilAnimations(const Document& document) {
  const SVGDocumentExtensions* extensions = document.SvgExtensions();
  return extensions && extensions->HasSmilAnimations();
}

}  // namespace

void SVGImageViewInfo::Trace(Visitor* visitor) const {
  visitor->Trace(view_spec_);
  visitor->Trace(target_);
}

SVGImage::SVGImage(ImageObserver* observer, bool is_multipart)
    : Image(observer, is_multipart),
      // TODO(chikamune): use an existing AgentGroupScheduler
      // SVG will be shared via MemoryCache (which is renderer process
      // global cache) across multiple AgentSchedulingGroups. That's
      // why we can't use an existing AgentSchedulingGroup for now. If
      // we incorrectly use the existing ASG/AGS and if we freeze task
      // queues on a AGS, it will affect SVGs on other AGS. To
      // mitigate this problem, we need to split the MemoryCache into
      // smaller granularity. There is an active effort to mitigate
      // this which is called "Memory Cache Per Context"
      // (https://crbug.com/1127971).
      agent_group_scheduler_(Thread::MainThread()
                                 ->Scheduler()
                                 ->ToMainThreadScheduler()
                                 ->CreateAgentGroupScheduler()),
      has_pending_timeline_rewind_(false) {}

SVGImage::~SVGImage() {
  if (document_host_) {
    // Store `document_host_` in a local variable and clear it so that
    // SVGImageChromeClient knows we're destructed.
    auto* document_host = document_host_.Release();
    document_host->Shutdown();
  }

  // Verify that page teardown destroyed the Chrome
  DCHECK(!chrome_client_ || !chrome_client_->GetImage());
}

bool SVGImage::IsInSVGImage(const Node* node) {
  DCHECK(node);

  Page* page = node->GetDocument().GetPage();
  if (!page)
    return false;

  return page->GetChromeClient().IsIsolatedSVGChromeClient();
}

LocalFrame* SVGImage::GetFrame() const {
  DCHECK(document_host_);
  return document_host_->GetFrame();
}

SVGSVGElement* SVGImage::RootElement() const {
  if (!document_host_) {
    return nullptr;
  }
  return document_host_->RootElement();
}

LayoutSVGRoot* SVGImage::LayoutRoot() const {
  if (SVGSVGElement* root_element = RootElement())
    return To<LayoutSVGRoot>(root_element->GetLayoutObject());
  return nullptr;
}

Page* SVGImage::GetPageForTesting() {
  return GetFrame()->GetPage();
}

void SVGImage::CheckLoaded() const {
  CHECK(document_host_);
  // Failures of this assertion might result in wrong origin tainting checks,
  // because CurrentFrameHasSingleSecurityOrigin() assumes all subresources of
  // the SVG are loaded and thus ready for origin checks.
  CHECK(GetFrame()->GetDocument()->LoadEventFinished());
}

bool SVGImage::CurrentFrameHasSingleSecurityOrigin() const {
  if (!document_host_) {
    return true;
  }

  SVGSVGElement* root_element = RootElement();
  if (!root_element)
    return true;

  // Don't allow foreignObject elements or images that are not known to be
  // single-origin since these can leak cross-origin information.
  for (Node* node = root_element; node; node = FlatTreeTraversal::Next(*node)) {
    if (IsA<SVGForeignObjectElement>(*node))
      return false;
    if (auto* image = DynamicTo<SVGImageElement>(*node)) {
      if (!image->CurrentFrameHasSingleSecurityOrigin())
        return false;
    } else if (auto* fe_image = DynamicTo<SVGFEImageElement>(*node)) {
      if (!fe_image->CurrentFrameHasSingleSecurityOrigin())
        return false;
    }
  }

  // Because SVG image rendering disallows external resources and links, these
  // images effectively are restricted to a single security origin.
  return true;
}

gfx::Size SVGImage::SizeWithConfig(SizeConfig) const {
  return ToRoundedSize(intrinsic_size_);
}

const SVGImageViewInfo* SVGImage::CreateViewInfo(const String& fragment) const {
  if (fragment.empty()) {
    return nullptr;
  }
  const SVGSVGElement* root_element = RootElement();
  if (!root_element) {
    return nullptr;
  }
  String decoded_fragment =
      DecodeURLEscapeSequences(fragment, DecodeURLMode::kUTF8);
  Element* target = DynamicTo<Element>(
      root_element->GetDocument().FindAnchor(decoded_fragment));
  const SVGViewSpec* view_spec =
      root_element->ParseViewSpec(decoded_fragment, target);
  if (!view_spec && !target) {
    return nullptr;
  }
  return MakeGarbageCollected<SVGImageViewInfo>(view_spec, target);
}

void SVGImage::ApplyViewInfo(const SVGImageViewInfo* viewinfo) {
  SVGSVGElement* root_element = RootElement();
  if (!root_element) {
    return;
  }
  Element* target = viewinfo ? viewinfo->Target() : nullptr;
  root_element->GetDocument().SetCSSTarget(target);
  const SVGViewSpec* viewspec = viewinfo ? viewinfo->ViewSpec() : nullptr;
  root_element->SetViewSpec(viewspec);
}

bool SVGImage::GetIntrinsicSizingInfo(
    const SVGViewSpec* override_viewspec,
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  const LayoutSVGRoot* layout_root = LayoutRoot();
  if (!layout_root)
    return false;
  layout_root->UnscaledIntrinsicSizingInfo(
      override_viewspec ? override_viewspec->ViewBox() : nullptr,
      intrinsic_sizing_info);

  if (!intrinsic_sizing_info.has_width || !intrinsic_sizing_info.has_height) {
    // We're not using an intrinsic aspect ratio to resolve a missing
    // intrinsic width or height when preserveAspectRatio is none.
    // (Ref: crbug.com/584172)
    SVGSVGElement* svg = RootElement();
    if (svg->preserveAspectRatio()->CurrentValue()->Align() ==
        SVGPreserveAspectRatio::kSvgPreserveaspectratioNone) {
      // Clear all the fields so that the concrete object size will equal the
      // default object size.
      intrinsic_sizing_info = IntrinsicSizingInfo();
      intrinsic_sizing_info.has_width = false;
      intrinsic_sizing_info.has_height = false;
    }
  }
  return true;
}

SVGImage::DrawInfo::DrawInfo(const gfx::SizeF& container_size,
                             float zoom,
                             const SVGImageViewInfo* viewinfo,
                             bool is_dark_mode_enabled)
    : container_size_(container_size),
      rounded_container_size_(gfx::ToRoundedSize(container_size)),
      zoom_(zoom),
      viewinfo_(viewinfo),
      is_dark_mode_enabled_(is_dark_mode_enabled) {}

gfx::SizeF SVGImage::DrawInfo::CalculateResidualScale() const {
  return gfx::SizeF(
      rounded_container_size_.width() / container_size_.width(),
      rounded_container_size_.height() / container_size_.height());
}

void SVGImage::DrawForContainer(const DrawInfo& draw_info,
                                cc::PaintCanvas* canvas,
                                const cc::PaintFlags& flags,
                                const gfx::RectF& dst_rect,
                                const gfx::RectF& src_rect) {
  gfx::RectF unzoomed_src = src_rect;
  unzoomed_src.InvScale(draw_info.Zoom());

  // Compensate for the container size rounding by adjusting the source rect.
  gfx::SizeF residual_scale = draw_info.CalculateResidualScale();
  unzoomed_src.set_size(gfx::ScaleSize(
      unzoomed_src.size(), residual_scale.width(), residual_scale.height()));

  DrawInternal(draw_info, canvas, flags, dst_rect, unzoomed_src);
}

PaintImage SVGImage::PaintImageForCurrentFrame() {
  const DrawInfo draw_info(gfx::SizeF(intrinsic_size_), 1, nullptr, false);
  auto builder = CreatePaintImageBuilder();
  PopulatePaintRecordForCurrentFrameForContainer(draw_info, builder);
  return builder.TakePaintImage();
}

void SVGImage::SetPreferredColorScheme(
    mojom::blink::PreferredColorScheme preferred_color_scheme) {
  if (document_host_) {
    GetFrame()->GetPage()->GetSettings().SetPreferredColorScheme(
        preferred_color_scheme);
  }
}

void SVGImage::DrawPatternForContainer(const DrawInfo& draw_info,
                                       GraphicsContext& context,
                                       const cc::PaintFlags& base_flags,
                                       const gfx::RectF& dst_rect,
                                       const ImageTilingInfo& tiling_info) {
  // Tile adjusted for scaling/stretch.
  gfx::RectF tile = tiling_info.image_rect;
  tile.Scale(tiling_info.scale.x(), tiling_info.scale.y());

  // Expand the tile to account for repeat spacing.
  gfx::RectF spaced_tile(tile.origin(), tile.size() + tiling_info.spacing);

  SkMatrix pattern_transform;
  pattern_transform.setTranslate(tiling_info.phase.x() + spaced_tile.x(),
                                 tiling_info.phase.y() + spaced_tile.y());

  PaintRecorder recorder;
  cc::PaintCanvas* tile_canvas = recorder.beginRecording();
  // When generating an expanded tile, make sure we don't draw into the
  // spacing area.
  if (!tiling_info.spacing.IsZero()) {
    tile_canvas->clipRect(gfx::RectFToSkRect(tile));
  }
  DrawForContainer(draw_info, tile_canvas, cc::PaintFlags(), tile,
                   tiling_info.image_rect);
  sk_sp<PaintShader> tile_shader = PaintShader::MakePaintRecord(
      recorder.finishRecordingAsPicture(), gfx::RectFToSkRect(spaced_tile),
      SkTileMode::kRepeat, SkTileMode::kRepeat, &pattern_transform);

  // If the shader could not be instantiated (e.g. non-invertible matrix),
  // draw transparent.
  // Note: we can't simply bail, because of arbitrary blend mode.
  cc::PaintFlags flags = base_flags;
  flags.setColor(tile_shader ? SK_ColorBLACK : SK_ColorTRANSPARENT);
  flags.setShader(std::move(tile_shader));
  // Reset filter quality.
  flags.setFilterQuality(cc::PaintFlags::FilterQuality::kNone);

  context.DrawRect(gfx::RectFToSkRect(dst_rect), flags,
                   PaintAutoDarkMode(DarkModeFilter::ElementRole::kSVG,
                                     draw_info.IsDarkModeEnabled()));

  StartAnimation();
}

void SVGImage::PopulatePaintRecordForCurrentFrameForContainer(
    const DrawInfo& draw_info,
    PaintImageBuilder& builder) {
  PaintRecorder recorder;
  const gfx::SizeF size =
      gfx::ScaleSize(draw_info.ContainerSize(), draw_info.Zoom());
  const gfx::Rect dest_rect(gfx::ToRoundedSize(size));
  cc::PaintCanvas* canvas = recorder.beginRecording();
  DrawForContainer(draw_info, canvas, cc::PaintFlags(), gfx::RectF(dest_rect),
                   gfx::RectF(size));
  builder.set_paint_record(recorder.finishRecordingAsPicture(), dest_rect,
                           PaintImage::GetNextContentId());

  builder.set_completion_state(
      document_host_ && document_host_->IsLoaded()
          ? PaintImage::CompletionState::kDone
          : PaintImage::CompletionState::kPartiallyDone);
}

bool SVGImage::ApplyShaderInternal(const DrawInfo& draw_info,
                                   cc::PaintFlags& flags,
                                   const gfx::RectF& unzoomed_src_rect,
                                   const SkMatrix& local_matrix) {
  if (draw_info.ContainerSize().IsEmpty())
    return false;
  const gfx::Rect cull_rect(gfx::ToEnclosingRect(unzoomed_src_rect));
  std::optional<PaintRecord> record =
      PaintRecordForCurrentFrame(draw_info, &cull_rect);
  if (!record)
    return false;

  const SkRect bounds =
      SkRect::MakeSize(gfx::SizeFToSkSize(draw_info.ContainerSize()));
  flags.setShader(PaintShader::MakePaintRecord(
      std::move(*record), bounds, SkTileMode::kClamp, SkTileMode::kClamp,
      &local_matrix));

  // Animation is normally refreshed in Draw() impls, which we don't reach when
  // painting via shaders.
  StartAnimation();
  return true;
}

bool SVGImage::ApplyShader(cc::PaintFlags& flags,
                           const SkMatrix& local_matrix,
                           const gfx::RectF& src_rect,
                           const ImageDrawOptions& draw_options) {
  const DrawInfo draw_info(gfx::SizeF(intrinsic_size_), 1, nullptr,
                           draw_options.apply_dark_mode);
  return ApplyShaderInternal(draw_info, flags, src_rect, local_matrix);
}

bool SVGImage::ApplyShaderForContainer(const DrawInfo& draw_info,
                                       cc::PaintFlags& flags,
                                       const gfx::RectF& src_rect,
                                       const SkMatrix& local_matrix) {
  gfx::RectF unzoomed_src = src_rect;
  unzoomed_src.InvScale(draw_info.Zoom());

  // Compensate for the container size rounding by adjusting the source rect.
  const gfx::SizeF residual_scale = draw_info.CalculateResidualScale();
  unzoomed_src.set_size(gfx::ScaleSize(
      unzoomed_src.size(), residual_scale.width(), residual_scale.height()));

  // Compensate for the container size rounding.
  const gfx::SizeF zoomed_residual_scale =
      gfx::ScaleSize(residual_scale, draw_info.Zoom());
  auto adjusted_local_matrix = local_matrix;
  adjusted_local_matrix.preScale(zoomed_residual_scale.width(),
                                 zoomed_residual_scale.height());
  return ApplyShaderInternal(draw_info, flags, unzoomed_src,
                             adjusted_local_matrix);
}

void SVGImage::Draw(cc::PaintCanvas* canvas,
                    const cc::PaintFlags& flags,
                    const gfx::RectF& dst_rect,
                    const gfx::RectF& src_rect,
                    const ImageDrawOptions& draw_options) {
  const DrawInfo draw_info(gfx::SizeF(intrinsic_size_), 1, nullptr,
                           draw_options.apply_dark_mode);
  DrawInternal(draw_info, canvas, flags, dst_rect, src_rect);
}

std::optional<PaintRecord> SVGImage::PaintRecordForCurrentFrame(
    const DrawInfo& draw_info,
    const gfx::Rect* cull_rect) {
  if (!document_host_) {
    return std::nullopt;
  }
  // Temporarily disable the image observer to prevent ChangeInRect() calls due
  // re-laying out the image.
  ImageObserverDisabler disable_image_observer(this);

  if (LayoutSVGRoot* layout_root = LayoutRoot()) {
    layout_root->SetContainerSize(
        PhysicalSize::FromSizeFFloor(draw_info.ContainerSize()));
  }
  LocalFrame* frame = GetFrame();
  LocalFrameView* view = frame->View();
  const gfx::Size rounded_container_size = draw_info.RoundedContainerSize();
  view->Resize(rounded_container_size);
  frame->GetPage()->GetVisualViewport().SetSize(rounded_container_size);

  // Always call ApplyViewInfo, even if there's no view specification, because
  // there may have been a previous view info that needs to be reset.
  ApplyViewInfo(draw_info.View());

  // If the image was reset, we need to rewind the timeline back to 0. This
  // needs to be done before painting, or else we wouldn't get the correct
  // reset semantics (we'd paint the "last" frame rather than the one at
  // time=0.) The reason we do this here and not in resetAnimation() is to
  // avoid setting timers from the latter.
  FlushPendingTimelineRewind();

  frame->GetPage()->GetSettings().SetForceDarkModeEnabled(
      draw_info.IsDarkModeEnabled());

  view->UpdateAllLifecyclePhases(DocumentUpdateReason::kSVGImage);

  return view->GetPaintRecord(cull_rect);
}

static bool DrawNeedsLayer(const cc::PaintFlags& flags) {
  if (SkColorGetA(flags.getColor()) < 255)
    return true;

  // This is needed to preserve the dark mode filter that
  // has been set in GraphicsContext.
  if (flags.getColorFilter())
    return true;

  return flags.getBlendMode() != SkBlendMode::kSrcOver;
}

void SVGImage::DrawInternal(const DrawInfo& draw_info,
                            cc::PaintCanvas* canvas,
                            const cc::PaintFlags& flags,
                            const gfx::RectF& dst_rect,
                            const gfx::RectF& unzoomed_src_rect) {
  const gfx::Rect cull_rect(gfx::ToEnclosingRect(unzoomed_src_rect));
  std::optional<PaintRecord> record =
      PaintRecordForCurrentFrame(draw_info, &cull_rect);
  if (!record)
    return;

  {
    PaintCanvasAutoRestore ar(canvas, false);
    if (DrawNeedsLayer(flags)) {
      SkRect layer_rect = gfx::RectFToSkRect(dst_rect);
      canvas->saveLayer(layer_rect, flags);
    }
    // We can only draw the entire frame, clipped to the rect we want. So
    // compute where the top left of the image would be if we were drawing
    // without clipping, and translate accordingly.
    canvas->save();
    canvas->clipRect(gfx::RectToSkRect(gfx::ToEnclosingRect(dst_rect)));
    canvas->concat(SkM44::RectToRect(gfx::RectFToSkRect(unzoomed_src_rect),
                                     gfx::RectFToSkRect(dst_rect)));
    canvas->drawPicture(std::move(*record));
    canvas->restore();
  }

  // Start any (SMIL) animations if needed. This will restart or continue
  // animations if preceded by calls to resetAnimation or stopAnimation
  // respectively.
  StartAnimation();
}

void SVGImage::ScheduleTimelineRewind() {
  has_pending_timeline_rewind_ = true;
}

void SVGImage::FlushPendingTimelineRewind() {
  if (!has_pending_timeline_rewind_)
    return;
  if (SVGSVGElement* root_element = RootElement())
    root_element->setCurrentTime(0);
  has_pending_timeline_rewind_ = false;
}

void SVGImage::StartAnimation() {
  SVGSVGElement* root_element = RootElement();
  if (!root_element)
    return;
  chrome_client_->ResumeAnimation();
  if (root_element->animationsPaused())
    root_element->unpauseAnimations();
}

void SVGImage::StopAnimation() {
  SVGSVGElement* root_element = RootElement();
  if (!root_element)
    return;
  chrome_client_->SuspendAnimation();
  root_element->pauseAnimations();
}

void SVGImage::ResetAnimation() {
  SVGSVGElement* root_element = RootElement();
  if (!root_element)
    return;
  chrome_client_->SuspendAnimation();
  root_element->pauseAnimations();
  ScheduleTimelineRewind();
}

void SVGImage::RestoreAnimation() {
  // If the image has no animations then do nothing.
  if (!MaybeAnimated())
    return;
  // If there are no clients, or no client is going to render, then do nothing.
  ImageObserver* image_observer = GetImageObserver();
  if (!image_observer || image_observer->ShouldPauseAnimation(this))
    return;
  StartAnimation();
}

bool SVGImage::MaybeAnimated() {
  SVGSVGElement* root_element = RootElement();
  if (!root_element)
    return false;
  const Document& document = root_element->GetDocument();
  return HasSmilAnimations(document) || document.Timeline().HasPendingUpdates();
}

void SVGImage::ServiceAnimations(
    base::TimeTicks monotonic_animation_start_time) {
  if (!GetImageObserver())
    return;

  // If none of our observers (sic!) are visible, or for some other reason
  // does not want us to keep running animations, stop them until further
  // notice (next paint.)
  if (GetImageObserver()->ShouldPauseAnimation(this)) {
    StopAnimation();
    return;
  }

  // serviceScriptedAnimations runs requestAnimationFrame callbacks, but SVG
  // images can't have any so we assert there's no script.
  ScriptForbiddenScope forbid_script;

  LocalFrame* frame = GetFrame();

  // The calls below may trigger GCs, so set up the required persistent
  // reference on the ImageResourceContent which owns this SVGImage. By
  // transitivity, that will keep the associated SVGImageChromeClient object
  // alive.
  Persistent<ImageObserver> protect(GetImageObserver());
  frame->GetPage()->Animator().ServiceScriptedAnimations(
      monotonic_animation_start_time);

  // Do *not* update the paint phase. It's critical to paint only when
  // actually generating painted output, not only for performance reasons,
  // but to preserve correct coherence of the cache of the output with
  // the needsRepaint bits of the PaintLayers in the image.
  LocalFrameView* frame_view = frame->View();
  frame_view->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kSVGImage);

  // We run UpdateAnimations after the paint phase, but per the above comment,
  // we don't want to run lifecycle through to paint for SVG images. Since we
  // know SVG images never have composited animations, we can update animations
  // directly without worrying about including PaintArtifactCompositor's
  // analysis of whether animations should be composited.
  frame->GetDocument()->GetDocumentAnimations().UpdateAnimations(
      DocumentLifecycle::kLayoutClean, nullptr, false);
}

void SVGImage::AdvanceAnimationForTesting() {
  if (SVGSVGElement* root_element = RootElement()) {
    root_element->TimeContainer()->AdvanceFrameForTesting();

    // The following triggers animation updates which can issue a new draw
    // and temporarily change the animation timeline. It's necessary to call
    // reset before changing to a time value as animation clock does not
    // expect to go backwards.
    PageAnimator& animator = root_element->GetDocument().GetPage()->Animator();
    base::TimeTicks current_animation_time = animator.Clock().CurrentTime();
    animator.Clock().ResetTimeForTesting();
    if (root_element->TimeContainer()->IsStarted())
      root_element->TimeContainer()->ResetDocumentTime();
    animator.ServiceScriptedAnimations(
        root_element->GetDocument().Timeline().CalculateZeroTime() +
        base::Seconds(root_element->getCurrentTime()));
    GetImageObserver()->Changed(this);
    animator.Clock().ResetTimeForTesting();
    animator.Clock().UpdateTime(current_animation_time);
  }
}

SVGImageChromeClient& SVGImage::ChromeClientForTesting() {
  return *chrome_client_;
}

void SVGImage::UpdateUseCounters(const Document& document) const {
  if (SVGSVGElement* root_element = RootElement()) {
    if (HasSmilAnimations(root_element->GetDocument())) {
      document.CountUse(WebFeature::kSVGSMILAnimationInImageRegardlessOfCache);
    }
  }
}

void SVGImage::MaybeRecordSvgImageProcessingTime(const Document& document) {
  if (data_change_count_ > 0) {
    document.MaybeRecordSvgImageProcessingTime(data_change_count_,
                                               data_change_elapsed_time_);
    data_change_count_ = 0;
    data_change_elapsed_time_ = base::TimeDelta();
  }
}

Element* SVGImage::GetResourceElement(const AtomicString& id) const {
  if (!document_host_) {
    return nullptr;
  }
  return GetFrame()->GetDocument()->getElementById(id);
}

void SVGImage::NotifyAsyncLoadCompleted() {
  if (GetImageObserver())
    GetImageObserver()->AsyncLoadCompleted(this);
}

Image::SizeAvailability SVGImage::DataChanged(bool all_data_received) {
  TRACE_EVENT("blink", "SVGImage::DataChanged");

  // Don't do anything if is an empty image.
  if (!DataSize())
    return kSizeAvailable;

  if (!all_data_received)
    return document_host_ ? kSizeAvailable : kSizeUnavailable;

  SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES("Blink.SVGImage.DataChanged");
  base::ElapsedTimer elapsed_timer;

  CHECK(!document_host_);
  chrome_client_ = MakeGarbageCollected<SVGImageChromeClient>(this);
  chrome_client_->InitAnimationTimer(
      agent_group_scheduler_->CompositorTaskRunner());

  // Because an SVGImage has no relation to a normal Page, it can't get default
  // font settings from the embedder. Copy settings for fonts and other things
  // so we have sensible defaults. These settings are fixed and will not update
  // if changed.
  const auto& pages = Page::OrdinaryPages();
  const Settings* settings_to_use =
      !pages.empty() ? &(*pages.begin())->GetSettings() : nullptr;

  // FIXME: If this SVG ends up loading itself, we might leak the world.
  // The Cache code does not know about ImageResources holding Frames and
  // won't know to break the cycle.
  // This will become an issue when SVGImage will be able to load other
  // SVGImage objects, but we're safe now, because SVGImage can only be
  // loaded by a top-level document.
  document_host_ = MakeGarbageCollected<IsolatedSVGDocumentHost>(
      *chrome_client_, *agent_group_scheduler_, Data(),
      WTF::BindOnce(&SVGImage::NotifyAsyncLoadCompleted,
                    weak_ptr_factory_.GetWeakPtr()),
      settings_to_use, IsolatedSVGDocumentHost::ProcessingMode::kAnimated);

  if (!RootElement())
    return kSizeUnavailable;

  // Set the concrete object size before a container size is available.
  // TODO(fs): Make this just set/copy width and height directly. See
  // crbug.com/789511.
  IntrinsicSizingInfo sizing_info;
  if (GetIntrinsicSizingInfo(nullptr, sizing_info)) {
    intrinsic_size_ = PhysicalSize::FromSizeFFloor(blink::ConcreteObjectSize(
        sizing_info, gfx::SizeF(LayoutReplaced::kDefaultWidth,
                                LayoutReplaced::kDefaultHeight)));
  }

  ++data_change_count_;
  data_change_elapsed_time_ += elapsed_timer.Elapsed();

  if (!document_host_->IsLoaded()) {
    return kSizeAvailableAndLoadingAsynchronously;
  }
  return kSizeAvailable;
}

bool SVGImage::IsSizeAvailable() {
  return RootElement();
}

String SVGImage::FilenameExtension() const {
  return "svg";
}

const AtomicString& SVGImage::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, svg_mime_type, ("image/svg+xml"));
  return svg_mime_type;
}

}  // namespace blink
```