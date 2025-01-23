Response:
Let's break down the thought process for analyzing the `webgl_framebuffer.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this specific source code file within the Chromium Blink rendering engine. The analysis should cover its purpose, relationships with other web technologies (JavaScript, HTML, CSS), logical reasoning, potential user errors, and how user actions lead to this code.

2. **Initial Reading and Identification of Key Components:**  Start by reading the code and identifying the major classes and concepts:
    * `WebGLFramebuffer`: The core class of the file. It likely represents a framebuffer object in WebGL.
    * `WebGLRenderbufferAttachment` and `WebGLTextureAttachment`: Classes that manage attaching renderbuffers and textures to the framebuffer. These suggest the fundamental operations of a framebuffer.
    * `WebGLRenderbuffer` and `WebGLTexture`:  These are likely separate classes representing renderbuffers and textures in WebGL, indicating a dependency.
    * `WebGLRenderingContextBase`:  This suggests that `WebGLFramebuffer` is associated with a WebGL rendering context.
    * `gpu::gles2::GLES2Interface`:  This clearly shows the underlying OpenGL ES 2.0 API interaction.
    * The `#include` directives confirm these dependencies.

3. **Deconstruct Functionality - Method by Method (or Grouping by Purpose):**  Go through the methods and understand their individual roles:
    * **Constructors and Destructor:** `WebGLFramebuffer::WebGLFramebuffer`, `~WebGLFramebuffer`:  Initialization and cleanup of the framebuffer, including generating and deleting OpenGL framebuffer objects.
    * **Attachment Management:**  `SetAttachmentForBoundFramebuffer` (both for textures and renderbuffers), `GetAttachmentObject`, `GetAttachment`, `RemoveAttachmentFromBoundFramebuffer`, `SetAttachmentInternal`, `RemoveAttachmentInternal`. These are crucial for understanding how attachments are added and removed. Pay attention to the differences between WebGL1 and WebGL2.
    * **Completeness Checks:** `CheckDepthStencilStatus`:  Determining if the framebuffer is ready for rendering. The mention of "opaque" framebuffers and XRWebGLLayer is important.
    * **Depth and Stencil Buffer Information:** `HasDepthBuffer`, `HasStencilBuffer`:  Checking for the presence of these buffers.
    * **Binding and State:** `IsBound`, `DrawBuffers`, `DrawBuffersIfNecessary`: Managing the framebuffer's binding state and draw buffer configurations.
    * **WebGL1 Specific Logic:** `CommitWebGL1DepthStencilIfConsistent`:  Handling the complexities of depth and stencil attachments in WebGL1.
    * **PLS Texture Support:** `SetPLSTexture`, `GetPLSTexture`:  This hints at support for Plane Layout Standard textures, likely for video or image processing.
    * **Tracing:** `Trace`:  Used for garbage collection and debugging.
    * **Static Factory:** `WebGLFramebuffer::CreateOpaque`: A way to create specific types of framebuffers.

4. **Identify Relationships with Web Technologies:**
    * **JavaScript:**  The `WebGLFramebuffer` class is a direct representation of the JavaScript `WebGLFramebuffer` object. JavaScript calls methods like `gl.createFramebuffer()`, `gl.bindFramebuffer()`, `gl.framebufferTexture2D()`, `gl.framebufferRenderbuffer()`, etc., which map to the functionalities within this C++ file.
    * **HTML:** The `<canvas>` element is the entry point for WebGL. The `WebGLRenderingContextBase` is obtained from a canvas.
    * **CSS:**  CSS can indirectly influence the rendering target size (and thus the framebuffer size) if the canvas size is manipulated with CSS.

5. **Infer Logical Reasoning and Examples:**
    * **Attachment Logic:**  The `SetAttachmentForBoundFramebuffer` methods demonstrate conditional logic based on the attachment type (depth, stencil, color) and WebGL version. The need for separate `WebGLRenderbufferAttachment` and `WebGLTextureAttachment` classes highlights the different nature of these attachments.
    * **Completeness:** The `CheckDepthStencilStatus` method, especially the "opaque" framebuffer logic, suggests a specific use case (XRWebGLLayer) with constraints.
    * **WebGL1 Depth/Stencil:** The `CommitWebGL1DepthStencilIfConsistent` method illustrates the more restrictive rules in WebGL1 regarding combined depth and stencil attachments.

6. **Consider User and Programming Errors:**
    * **Invalid Attachment Points:** Trying to attach a texture to an unsupported attachment point (e.g., attaching a color texture to `DEPTH_ATTACHMENT`).
    * **Incorrect Texture/Renderbuffer Types:**  Attaching a renderbuffer where a texture is expected, or vice-versa.
    * **Framebuffer Incompleteness:**  Not attaching necessary buffers (e.g., no color attachment when rendering). The error message `kIncompleteOpaque` provides a specific example.
    * **WebGL1 Depth/Stencil Conflicts:**  Violating the WebGL1 rule of at most one depth/stencil attachment.
    * **Operating on Unbound Framebuffer:**  Trying to set attachments on a framebuffer that isn't currently bound.

7. **Trace User Operations to Code:**
    * Start with the JavaScript WebGL API calls. A sequence like `gl.createFramebuffer()`, `gl.bindFramebuffer()`, `gl.framebufferTexture2D()`, and then rendering commands would directly involve this `webgl_framebuffer.cc` file. The browser needs to handle these JavaScript calls and translate them into the corresponding C++ logic.
    * Consider the asynchronous nature of XR sessions and the message about rendering outside animation frames.

8. **Structure the Analysis:** Organize the findings into logical sections like "Functionality," "Relationship to Web Technologies," "Logical Reasoning," "User Errors," and "Debugging."  Use clear and concise language. Provide specific code snippets or examples where appropriate.

9. **Review and Refine:** Read through the analysis to ensure accuracy, clarity, and completeness. Check for any missing points or areas that could be explained better. For instance, initially, I might not have emphasized the WebGL1 vs. WebGL2 differences strongly enough, prompting a revision.

This systematic approach, combining code reading, conceptual understanding of WebGL, and thinking from the user's perspective, allows for a comprehensive analysis of the `webgl_framebuffer.cc` file.
好的，让我们来详细分析一下 `blink/renderer/modules/webgl/webgl_framebuffer.cc` 这个 Chromium Blink 引擎源代码文件的功能。

**文件功能概述:**

`webgl_framebuffer.cc` 文件实现了 WebGL 中 `WebGLFramebuffer` 对象的逻辑。`WebGLFramebuffer` 对象是 WebGL API 的核心组成部分，它允许开发者将渲染结果输出到屏幕以外的目标，例如纹理或渲染缓冲区。这对于实现各种高级渲染技术至关重要，例如：

* **离屏渲染 (Off-screen Rendering):**  先将场景渲染到一个帧缓冲区，然后再将帧缓冲区的纹理用作后续渲染的输入，实现各种特效，比如后期处理、阴影贴图等。
* **渲染到纹理 (Render to Texture):**  将渲染结果直接写入一个纹理对象，用于动态纹理生成。
* **多渲染目标 (Multiple Render Targets, MRT):**  在 WebGL2 中，可以同时渲染到多个颜色附件。

**具体功能点:**

1. **Framebuffer 对象的创建和销毁:**
   - 提供了创建 `WebGLFramebuffer` 对象的工厂方法 (`CreateOpaque`) 和构造函数。
   - 负责在对象不再使用时，释放相关的 OpenGL framebuffer 对象 (`glDeleteFramebuffers`)。

2. **Framebuffer 的绑定和解绑:**
   - 维护了 framebuffer 的绑定状态（通过 `IsBound` 方法）。
   - 虽然这个文件本身没有直接处理绑定操作，但它依赖于 `WebGLRenderingContextBase` 来管理当前的 framebuffer 绑定状态。

3. **Framebuffer 附件的管理:**
   - **连接纹理 (Attaching Textures):** 提供了将 `WebGLTexture` 对象连接到 framebuffer 的不同附件点（例如颜色附件、深度附件、模板附件）的功能 (`SetAttachmentForBoundFramebuffer`)。这包括对 2D 纹理、3D 纹理和纹理数组的支持。
   - **连接渲染缓冲区 (Attaching Renderbuffers):** 提供了将 `WebGLRenderbuffer` 对象连接到 framebuffer 的功能 (`SetAttachmentForBoundFramebuffer`)。渲染缓冲区主要用于存储深度信息、模板信息或不需要作为纹理采样的颜色信息。
   - **获取附件对象:** 允许获取指定附件点的 `WebGLTexture` 或 `WebGLRenderbuffer` 对象 (`GetAttachmentObject`, `GetAttachment`)。
   - **移除附件:** 提供了从 framebuffer 上移除附件的功能 (`RemoveAttachmentFromBoundFramebuffer`, `RemoveAttachmentInternal`)。

4. **Framebuffer 完整性检查:**
   - 实现了 `CheckDepthStencilStatus` 方法，用于检查 framebuffer 的深度和模板附件是否配置正确，以确保 framebuffer 可以用于渲染。
   - 特别处理了 "opaque" framebuffer 的情况，这与 XRWebGLLayer 相关，在非 XR 会话动画帧回调中无法渲染。

5. **深度和模板缓冲区状态查询:**
   - 提供了 `HasDepthBuffer` 和 `HasStencilBuffer` 方法，用于查询 framebuffer 是否连接了深度缓冲区或模板缓冲区。

6. **Draw Buffers 的管理 (WebGL2 和 `EXT_draw_buffers` 扩展):**
   - 实现了 `DrawBuffers` 和 `DrawBuffersIfNecessary` 方法，用于设置渲染到多个颜色附件的目标，这是 WebGL2 和 `EXT_draw_buffers` 扩展的功能。它还包含一些针对 macOS 驱动程序 bug 的 workaround。

7. **WebGL1 深度和模板附件一致性处理:**
   - `CommitWebGL1DepthStencilIfConsistent` 方法处理了 WebGL1 中深度和模板附件的特殊规则，即只能同时存在一个深度附件、一个模板附件或一个深度模板附件。

8. **PLS 纹理支持 (Plane Layout Standard):**
   - 提供了 `SetPLSTexture` 和 `GetPLSTexture` 方法，用于管理连接到 framebuffer 的 PLS 纹理。这可能用于视频处理或其他需要特定纹理布局的场景。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  `WebGLFramebuffer` 对象是 JavaScript WebGL API 的直接映射。JavaScript 代码会调用 WebGL API 来创建、绑定和操作 framebuffer。
   ```javascript
   // JavaScript 代码
   const canvas = document.getElementById('myCanvas');
   const gl = canvas.getContext('webgl');

   const framebuffer = gl.createFramebuffer();
   gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);

   const texture = gl.createTexture();
   gl.bindTexture(gl.TEXTURE_2D, texture);
   gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 512, 512, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
   gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);

   // ... 进行渲染到 framebuffer 的操作 ...

   gl.bindFramebuffer(gl.FRAMEBUFFER, null); // 解绑 framebuffer，渲染到屏幕
   ```
   在这个例子中，JavaScript 代码调用了 `gl.createFramebuffer()`, `gl.bindFramebuffer()`, 和 `gl.framebufferTexture2D()` 这些 API，这些操作最终会调用到 `webgl_framebuffer.cc` 中的相关 C++ 代码。

* **HTML:** HTML 的 `<canvas>` 元素是 WebGL 内容的载体。JavaScript 通过获取 `<canvas>` 元素的上下文来获得 WebGLRenderingContext，从而操作 WebGLFramebuffer。
   ```html
   <!-- HTML 代码 -->
   <canvas id="myCanvas" width="500" height="500"></canvas>
   ```

* **CSS:** CSS 可以影响 `<canvas>` 元素的尺寸，但这主要是影响 WebGL 上下文的视口大小。Framebuffer 的尺寸通常是在 JavaScript 中创建纹理或渲染缓冲区时确定的，并不会直接受 CSS 的影响。但是，如果 canvas 的大小改变，开发者可能需要在 JavaScript 中重新创建或调整 framebuffer 及其附件的大小。

**逻辑推理、假设输入与输出:**

假设输入：JavaScript 代码尝试创建一个 framebuffer 并将一个 2D 纹理作为颜色附件连接到它。

```javascript
const framebuffer = gl.createFramebuffer();
gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
const texture = gl.createTexture();
gl.bindTexture(gl.TEXTURE_2D, texture);
gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 256, 256, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);
```

逻辑推理和 `webgl_framebuffer.cc` 的行为：

1. 当 JavaScript 调用 `gl.createFramebuffer()` 时，会创建一个 `WebGLFramebuffer` 对象，并在底层生成一个 OpenGL framebuffer ID。
2. 当 JavaScript 调用 `gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer)` 时，会将这个 `WebGLFramebuffer` 对象设置为当前 WebGL 上下文的帧缓冲区绑定。
3. 当 JavaScript 调用 `gl.framebufferTexture2D()` 时，`webgl_framebuffer.cc` 中的 `SetAttachmentForBoundFramebuffer` 方法会被调用。
4. `SetAttachmentForBoundFramebuffer` 会创建一个 `WebGLTextureAttachment` 对象，并将 `texture` 和相关的附件点信息存储起来。
5. 底层 OpenGL 函数 `glFramebufferTexture2D` 会被调用，将纹理连接到 OpenGL framebuffer 对象上。

假设输出：

* `WebGLFramebuffer` 对象内部维护了一个映射，记录了 `GL_COLOR_ATTACHMENT0` 附件点连接的是特定的 `WebGLTexture` 对象。
* OpenGL 状态中，对应的 OpenGL framebuffer 对象的颜色附件点已经指向了与 `texture` 关联的 OpenGL 纹理对象。

**用户或编程常见的使用错误及举例:**

1. **尝试在未绑定的 framebuffer 上设置附件:**
   ```javascript
   const framebuffer = gl.createFramebuffer();
   const texture = gl.createTexture();
   // ... 初始化 texture ...
   gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0); // 错误：framebuffer 未绑定
   ```
   **结果:**  WebGL 会产生错误，因为 OpenGL 操作通常需要在 framebuffer 被绑定后才能进行。

2. **将不兼容的纹理或渲染缓冲区连接到附件点:**
   ```javascript
   const framebuffer = gl.createFramebuffer();
   gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
   const renderbuffer = gl.createRenderbuffer();
   gl.bindRenderbuffer(gl.RENDERBUFFER, renderbuffer);
   gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, 256, 256);
   gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, renderbuffer, 0); // 错误：尝试将 renderbuffer 连接到 texture 附件点
   ```
   **结果:** WebGL 会产生错误，提示附件类型不匹配。正确的做法是使用 `gl.framebufferRenderbuffer` 将渲染缓冲区连接到 `DEPTH_ATTACHMENT`。

3. **Framebuffer 不完整:**  Framebuffer 必须满足一定的完整性条件才能用于渲染。常见的错误是缺少必要的附件。
   ```javascript
   const framebuffer = gl.createFramebuffer();
   gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
   // 没有添加颜色附件、深度附件或模板附件
   const status = gl.checkFramebufferStatus(gl.FRAMEBUFFER);
   if (status !== gl.FRAMEBUFFER_COMPLETE) {
       console.error("Framebuffer is not complete:", status);
   }
   ```
   **结果:** `gl.checkFramebufferStatus` 会返回一个非 `gl.FRAMEBUFFER_COMPLETE` 的状态码，表明 framebuffer 无法用于渲染。

4. **在 WebGL1 中错误地组合深度和模板附件:**
   ```javascript
   const framebuffer = gl.createFramebuffer();
   gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);

   const depthBuffer = gl.createRenderbuffer();
   gl.bindRenderbuffer(gl.RENDERBUFFER, depthBuffer);
   gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, 256, 256);
   gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, depthBuffer);

   const stencilBuffer = gl.createRenderbuffer();
   gl.bindRenderbuffer(gl.RENDERBUFFER, stencilBuffer);
   gl.renderbufferStorage(gl.RENDERBUFFER, gl.STENCIL_INDEX8, 256, 256);
   gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.STENCIL_ATTACHMENT, gl.RENDERBUFFER, stencilBuffer); // 在 WebGL1 中，不能同时有独立的深度和模板附件
   ```
   **结果:** 在 WebGL1 中，这种组合会导致 framebuffer 不完整。应该使用 `gl.DEPTH_STENCIL_ATTACHMENT` 和一个支持深度和模板的渲染缓冲区或纹理。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个包含 WebGL 内容的网页。**
2. **网页中的 JavaScript 代码获取 `<canvas>` 元素的 WebGL 上下文。**
3. **JavaScript 代码调用 `gl.createFramebuffer()` 来创建一个新的 framebuffer 对象。**  这会触发 Blink 引擎中创建 `WebGLFramebuffer` 对象的代码。
4. **JavaScript 代码调用 `gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer)` 来绑定新创建的 framebuffer。**  Blink 引擎会更新其内部状态，记录当前绑定的 framebuffer。
5. **JavaScript 代码调用 `gl.createTexture()` 创建一个纹理对象。**
6. **JavaScript 代码配置纹理的属性，例如大小、格式、数据。**
7. **JavaScript 代码调用 `gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0)`。**
   - 这会触发 `webgl_framebuffer.cc` 中的 `SetAttachmentForBoundFramebuffer` 方法。
   - 在该方法中，会检查当前绑定的 framebuffer，并将指定的纹理作为颜色附件连接到该 framebuffer。
   - 底层 OpenGL 函数会被调用，修改 OpenGL 的 framebuffer 对象状态。
8. **如果用户触发了需要渲染到这个 framebuffer 的操作（例如，调用 `gl.drawArrays` 或 `gl.drawElements`，并且 framebuffer 处于绑定状态），那么 GPU 的渲染命令会输出到这个 framebuffer 的附件上。**
9. **后续，JavaScript 代码可能会将 framebuffer 的附件（例如，连接的纹理）用作其他渲染过程的输入，或者将渲染结果显示到屏幕上。**
10. **当 framebuffer 不再需要时，JavaScript 代码可能会调用 `gl.deleteFramebuffer(framebuffer)`，这将触发 `webgl_framebuffer.cc` 中 `WebGLFramebuffer` 对象的销毁，并释放相关的 OpenGL 资源。**

**调试线索:**

* **在 Chrome 开发者工具的 "Sources" 面板中设置断点:**  在 `webgl_framebuffer.cc` 的关键方法（例如 `SetAttachmentForBoundFramebuffer`, `CheckFramebufferStatus`, 构造函数和析构函数）设置断点，可以跟踪 framebuffer 的创建、绑定、附件设置和状态变化。
* **使用 WebGL 错误报告:**  WebGL API 提供了错误报告机制。检查 `gl.getError()` 的返回值可以帮助识别在 framebuffer 操作过程中发生的错误。
* **利用图形调试工具:**  像 apitrace 或 RenderDoc 这样的工具可以捕获和回放 OpenGL 的调用序列，让你详细查看 framebuffer 的创建、绑定和附件操作，以及相关的 OpenGL 状态。
* **查看 Chrome 的 `chrome://gpu` 页面:**  该页面提供了关于 GPU 和图形驱动程序的信息，以及 WebGL 的状态。这有助于排除由于 GPU 或驱动程序问题导致的错误。
* **审查 JavaScript 代码:**  仔细检查调用 WebGL framebuffer 相关 API 的顺序和参数，确保逻辑正确。

希望以上分析能够帮助你理解 `webgl_framebuffer.cc` 文件的功能和它在 WebGL 工作流程中的作用。

### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_framebuffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
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

#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"

#include "gpu/command_buffer/client/gles2_interface.h"
#include "third_party/blink/renderer/modules/webgl/webgl_renderbuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"
#include "third_party/blink/renderer/modules/webgl/webgl_texture.h"

namespace blink {

namespace {

const char kIncompleteOpaque[] =
    "Cannot render to a XRWebGLLayer framebuffer outside of an XRSession "
    "animation frame callback.";

class WebGLRenderbufferAttachment final
    : public WebGLFramebuffer::WebGLAttachment {
 public:
  explicit WebGLRenderbufferAttachment(WebGLRenderbuffer*);

  void Trace(Visitor*) const override;
  const char* NameInHeapSnapshot() const override { return "WebGLAttachment"; }

 private:
  WebGLSharedObject* Object() const override;
  bool IsSharedObject(WebGLSharedObject*) const override;
  bool Valid() const override;
  void OnDetached(gpu::gles2::GLES2Interface*) override;
  void Attach(gpu::gles2::GLES2Interface*,
              GLenum target,
              GLenum attachment) override;
  void Unattach(gpu::gles2::GLES2Interface*,
                GLenum target,
                GLenum attachment) override;

  Member<WebGLRenderbuffer> renderbuffer_;
};

void WebGLRenderbufferAttachment::Trace(Visitor* visitor) const {
  visitor->Trace(renderbuffer_);
  WebGLFramebuffer::WebGLAttachment::Trace(visitor);
}

WebGLRenderbufferAttachment::WebGLRenderbufferAttachment(
    WebGLRenderbuffer* renderbuffer)
    : renderbuffer_(renderbuffer) {}

WebGLSharedObject* WebGLRenderbufferAttachment::Object() const {
  return renderbuffer_->Object() ? renderbuffer_.Get() : nullptr;
}

bool WebGLRenderbufferAttachment::IsSharedObject(
    WebGLSharedObject* object) const {
  return object == renderbuffer_;
}

bool WebGLRenderbufferAttachment::Valid() const {
  return renderbuffer_->Object();
}

void WebGLRenderbufferAttachment::OnDetached(gpu::gles2::GLES2Interface* gl) {
  renderbuffer_->OnDetached(gl);
}

void WebGLRenderbufferAttachment::Attach(gpu::gles2::GLES2Interface* gl,
                                         GLenum target,
                                         GLenum attachment) {
  GLuint object = ObjectOrZero(renderbuffer_.Get());
  gl->FramebufferRenderbuffer(target, attachment, GL_RENDERBUFFER, object);
}

void WebGLRenderbufferAttachment::Unattach(gpu::gles2::GLES2Interface* gl,
                                           GLenum target,
                                           GLenum attachment) {
  gl->FramebufferRenderbuffer(target, attachment, GL_RENDERBUFFER, 0);
}

class WebGLTextureAttachment final : public WebGLFramebuffer::WebGLAttachment {
 public:
  WebGLTextureAttachment(WebGLTexture*,
                         GLenum target,
                         GLint level,
                         GLint layer);

  void Trace(Visitor*) const override;
  const char* NameInHeapSnapshot() const override {
    return "WebGLTextureAttachment";
  }

 private:
  WebGLSharedObject* Object() const override;
  bool IsSharedObject(WebGLSharedObject*) const override;
  bool Valid() const override;
  void OnDetached(gpu::gles2::GLES2Interface*) override;
  void Attach(gpu::gles2::GLES2Interface*,
              GLenum target,
              GLenum attachment) override;
  void Unattach(gpu::gles2::GLES2Interface*,
                GLenum target,
                GLenum attachment) override;

  Member<WebGLTexture> texture_;
  GLenum target_;
  GLint level_;
  GLint layer_;
};

void WebGLTextureAttachment::Trace(Visitor* visitor) const {
  visitor->Trace(texture_);
  WebGLFramebuffer::WebGLAttachment::Trace(visitor);
}

WebGLTextureAttachment::WebGLTextureAttachment(WebGLTexture* texture,
                                               GLenum target,
                                               GLint level,
                                               GLint layer)
    : texture_(texture), target_(target), level_(level), layer_(layer) {}

WebGLSharedObject* WebGLTextureAttachment::Object() const {
  return texture_->Object() ? texture_.Get() : nullptr;
}

bool WebGLTextureAttachment::IsSharedObject(WebGLSharedObject* object) const {
  return object == texture_;
}

bool WebGLTextureAttachment::Valid() const {
  return texture_->Object();
}

void WebGLTextureAttachment::OnDetached(gpu::gles2::GLES2Interface* gl) {
  texture_->OnDetached(gl);
}

void WebGLTextureAttachment::Attach(gpu::gles2::GLES2Interface* gl,
                                    GLenum target,
                                    GLenum attachment) {
  GLuint object = ObjectOrZero(texture_.Get());
  if (target_ == GL_TEXTURE_3D || target_ == GL_TEXTURE_2D_ARRAY) {
    gl->FramebufferTextureLayer(target, attachment, object, level_, layer_);
  } else {
    gl->FramebufferTexture2D(target, attachment, target_, object, level_);
  }
}

void WebGLTextureAttachment::Unattach(gpu::gles2::GLES2Interface* gl,
                                      GLenum target,
                                      GLenum attachment) {
  // GL_DEPTH_STENCIL_ATTACHMENT attachment is valid in ES3.
  if (target_ == GL_TEXTURE_3D || target_ == GL_TEXTURE_2D_ARRAY) {
    gl->FramebufferTextureLayer(target, attachment, 0, level_, layer_);
  } else {
    gl->FramebufferTexture2D(target, attachment, target_, 0, level_);
  }
}

}  // anonymous namespace

WebGLFramebuffer::WebGLAttachment::WebGLAttachment() = default;

WebGLFramebuffer* WebGLFramebuffer::CreateOpaque(WebGLRenderingContextBase* ctx,
                                                 bool has_depth,
                                                 bool has_stencil) {
  WebGLFramebuffer* const fb =
      MakeGarbageCollected<WebGLFramebuffer>(ctx, true);
  fb->SetOpaqueHasDepth(has_depth);
  fb->SetOpaqueHasStencil(has_stencil);
  return fb;
}

WebGLFramebuffer::WebGLFramebuffer(WebGLRenderingContextBase* ctx, bool opaque)
    : WebGLContextObject(ctx),
      object_(0),
      has_ever_been_bound_(false),
      web_gl1_depth_stencil_consistent_(true),
      opaque_(opaque),
      read_buffer_(GL_COLOR_ATTACHMENT0) {
  ctx->ContextGL()->GenFramebuffers(1, &object_);
}

WebGLFramebuffer::~WebGLFramebuffer() = default;

void WebGLFramebuffer::SetAttachmentForBoundFramebuffer(GLenum target,
                                                        GLenum attachment,
                                                        GLenum tex_target,
                                                        WebGLTexture* texture,
                                                        GLint level,
                                                        GLint layer,
                                                        GLsizei num_views) {
  DCHECK(object_);
  DCHECK(IsBound(target));
  if (Context()->IsWebGL2()) {
    if (attachment == GL_DEPTH_STENCIL_ATTACHMENT) {
      SetAttachmentInternal(target, GL_DEPTH_ATTACHMENT, tex_target, texture,
                            level, layer);
      SetAttachmentInternal(target, GL_STENCIL_ATTACHMENT, tex_target, texture,
                            level, layer);
    } else {
      SetAttachmentInternal(target, attachment, tex_target, texture, level,
                            layer);
    }
    GLuint texture_id = ObjectOrZero(texture);
    // texTarget can be 0 if detaching using framebufferTextureLayer.
    DCHECK(tex_target || !texture_id);
    switch (tex_target) {
      case 0:
      case GL_TEXTURE_3D:
      case GL_TEXTURE_2D_ARRAY:
        if (num_views > 0) {
          DCHECK_EQ(static_cast<GLenum>(GL_TEXTURE_2D_ARRAY), tex_target);
          Context()->ContextGL()->FramebufferTextureMultiviewOVR(
              target, attachment, texture_id, level, layer, num_views);
        } else {
          Context()->ContextGL()->FramebufferTextureLayer(
              target, attachment, texture_id, level, layer);
        }
        break;
      default:
        DCHECK_EQ(layer, 0);
        DCHECK_EQ(num_views, 0);
        Context()->ContextGL()->FramebufferTexture2D(
            target, attachment, tex_target, texture_id, level);
        break;
    }
  } else {
    DCHECK_EQ(layer, 0);
    DCHECK_EQ(num_views, 0);
    SetAttachmentInternal(target, attachment, tex_target, texture, level,
                          layer);
    switch (attachment) {
      case GL_DEPTH_ATTACHMENT:
      case GL_STENCIL_ATTACHMENT:
      case GL_DEPTH_STENCIL_ATTACHMENT:
        CommitWebGL1DepthStencilIfConsistent(target);
        break;
      default:
        Context()->ContextGL()->FramebufferTexture2D(
            target, attachment, tex_target, ObjectOrZero(texture), level);
        break;
    }
  }
}

void WebGLFramebuffer::SetAttachmentForBoundFramebuffer(
    GLenum target,
    GLenum attachment,
    WebGLRenderbuffer* renderbuffer) {
  DCHECK(object_);
  DCHECK(IsBound(target));
  if (Context()->IsWebGL2()) {
    if (attachment == GL_DEPTH_STENCIL_ATTACHMENT) {
      SetAttachmentInternal(target, GL_DEPTH_ATTACHMENT, renderbuffer);
      SetAttachmentInternal(target, GL_STENCIL_ATTACHMENT, renderbuffer);
    } else {
      SetAttachmentInternal(target, attachment, renderbuffer);
    }
    Context()->ContextGL()->FramebufferRenderbuffer(
        target, attachment, GL_RENDERBUFFER, ObjectOrZero(renderbuffer));
  } else {
    SetAttachmentInternal(target, attachment, renderbuffer);
    switch (attachment) {
      case GL_DEPTH_ATTACHMENT:
      case GL_STENCIL_ATTACHMENT:
      case GL_DEPTH_STENCIL_ATTACHMENT:
        CommitWebGL1DepthStencilIfConsistent(target);
        break;
      default:
        Context()->ContextGL()->FramebufferRenderbuffer(
            target, attachment, GL_RENDERBUFFER, ObjectOrZero(renderbuffer));
        break;
    }
  }
}

WebGLSharedObject* WebGLFramebuffer::GetAttachmentObject(
    GLenum attachment) const {
  if (!object_)
    return nullptr;
  WebGLAttachment* attachment_object = GetAttachment(attachment);
  return attachment_object ? attachment_object->Object() : nullptr;
}

WebGLFramebuffer::WebGLAttachment* WebGLFramebuffer::GetAttachment(
    GLenum attachment) const {
  const AttachmentMap::const_iterator it = attachments_.find(attachment);
  return (it != attachments_.end()) ? it->value.Get() : nullptr;
}

void WebGLFramebuffer::RemoveAttachmentFromBoundFramebuffer(
    GLenum target,
    WebGLSharedObject* attachment) {
  DCHECK(IsBound(target));
  if (!object_)
    return;
  if (!attachment)
    return;

  bool check_more = true;
  bool is_web_gl1 = !Context()->IsWebGL2();
  bool check_web_gl1_depth_stencil = false;
  while (check_more) {
    check_more = false;
    for (const auto& it : attachments_) {
      WebGLAttachment* attachment_object = it.value.Get();
      if (attachment_object->IsSharedObject(attachment)) {
        GLenum attachment_type = it.key;
        switch (attachment_type) {
          case GL_DEPTH_ATTACHMENT:
          case GL_STENCIL_ATTACHMENT:
          case GL_DEPTH_STENCIL_ATTACHMENT:
            if (is_web_gl1) {
              check_web_gl1_depth_stencil = true;
            } else {
              attachment_object->Unattach(Context()->ContextGL(), target,
                                          attachment_type);
            }
            break;
          default:
            attachment_object->Unattach(Context()->ContextGL(), target,
                                        attachment_type);
            break;
        }
        RemoveAttachmentInternal(target, attachment_type);
        check_more = true;
        break;
      }
    }
  }
  if (check_web_gl1_depth_stencil)
    CommitWebGL1DepthStencilIfConsistent(target);
}

GLenum WebGLFramebuffer::CheckDepthStencilStatus(const char** reason) const {
  // This function is called any time framebuffer completeness is checked, which
  // makes it the most convenient place to add this check.
  if (opaque_) {
    if (opaque_complete_)
      return GL_FRAMEBUFFER_COMPLETE;
    *reason = kIncompleteOpaque;
    return GL_FRAMEBUFFER_UNSUPPORTED;
  }
  if (Context()->IsWebGL2() || web_gl1_depth_stencil_consistent_)
    return GL_FRAMEBUFFER_COMPLETE;
  *reason = "conflicting DEPTH/STENCIL/DEPTH_STENCIL attachments";
  return GL_FRAMEBUFFER_UNSUPPORTED;
}

bool WebGLFramebuffer::HasDepthBuffer() const {
  if (opaque_) {
    return opaque_has_depth_;
  } else {
    WebGLAttachment* attachment = GetAttachment(GL_DEPTH_ATTACHMENT);
    if (!attachment) {
      attachment = GetAttachment(GL_DEPTH_STENCIL_ATTACHMENT);
    }
    return attachment && attachment->Valid();
  }
}

bool WebGLFramebuffer::HasStencilBuffer() const {
  if (opaque_) {
    return opaque_has_stencil_;
  } else {
    WebGLAttachment* attachment = GetAttachment(GL_STENCIL_ATTACHMENT);
    if (!attachment)
      attachment = GetAttachment(GL_DEPTH_STENCIL_ATTACHMENT);
    return attachment && attachment->Valid();
  }
}

void WebGLFramebuffer::DeleteObjectImpl(gpu::gles2::GLES2Interface* gl) {
  // Both the AttachmentMap and its WebGLAttachment objects are GCed
  // objects and cannot be accessed after the destructor has been
  // entered, as they may have been finalized already during the
  // same GC sweep. These attachments' OpenGL objects will be fully
  // destroyed once their JavaScript wrappers are collected.
  if (!DestructionInProgress()) {
    for (const auto& attachment : attachments_)
      attachment.value->OnDetached(gl);
    for (const auto& tex : pls_textures_) {
      tex.value->OnDetached(gl);
    }
  }

  gl->DeleteFramebuffers(1, &object_);
  object_ = 0;
}

bool WebGLFramebuffer::IsBound(GLenum target) const {
  return (Context()->GetFramebufferBinding(target) == this);
}

void WebGLFramebuffer::DrawBuffers(const Vector<GLenum>& bufs) {
  draw_buffers_ = bufs;
  filtered_draw_buffers_.resize(draw_buffers_.size());
  for (wtf_size_t i = 0; i < filtered_draw_buffers_.size(); ++i)
    filtered_draw_buffers_[i] = GL_NONE;
  DrawBuffersIfNecessary(true);
}

void WebGLFramebuffer::DrawBuffersIfNecessary(bool force) {
  if (Context()->IsWebGL2() ||
      Context()->ExtensionEnabled(kWebGLDrawBuffersName)) {
    bool reset = force;
    // This filtering works around graphics driver bugs on Mac OS X.
    for (wtf_size_t i = 0; i < draw_buffers_.size(); ++i) {
      if (draw_buffers_[i] != GL_NONE && GetAttachment(draw_buffers_[i])) {
        if (filtered_draw_buffers_[i] != draw_buffers_[i]) {
          filtered_draw_buffers_[i] = draw_buffers_[i];
          reset = true;
        }
      } else {
        if (filtered_draw_buffers_[i] != GL_NONE) {
          filtered_draw_buffers_[i] = GL_NONE;
          reset = true;
        }
      }
    }
    if (reset) {
      Context()->ContextGL()->DrawBuffersEXT(filtered_draw_buffers_.size(),
                                             filtered_draw_buffers_.data());
    }
  }
}

void WebGLFramebuffer::SetAttachmentInternal(GLenum target,
                                             GLenum attachment,
                                             GLenum tex_target,
                                             WebGLTexture* texture,
                                             GLint level,
                                             GLint layer) {
  DCHECK(IsBound(target));
  DCHECK(object_);
  RemoveAttachmentInternal(target, attachment);
  if (texture && texture->Object()) {
    attachments_.insert(attachment,
                        MakeGarbageCollected<WebGLTextureAttachment>(
                            texture, tex_target, level, layer));
    DrawBuffersIfNecessary(false);
    texture->OnAttached();
  }
}

void WebGLFramebuffer::SetAttachmentInternal(GLenum target,
                                             GLenum attachment,
                                             WebGLRenderbuffer* renderbuffer) {
  DCHECK(IsBound(target));
  DCHECK(object_);
  RemoveAttachmentInternal(target, attachment);
  if (renderbuffer && renderbuffer->Object()) {
    attachments_.insert(
        attachment,
        MakeGarbageCollected<WebGLRenderbufferAttachment>(renderbuffer));
    DrawBuffersIfNecessary(false);
    renderbuffer->OnAttached();
  }
}

void WebGLFramebuffer::RemoveAttachmentInternal(GLenum target,
                                                GLenum attachment) {
  DCHECK(IsBound(target));
  DCHECK(object_);

  WebGLAttachment* attachment_object = GetAttachment(attachment);
  if (attachment_object) {
    attachment_object->OnDetached(Context()->ContextGL());
    attachments_.erase(attachment);
    DrawBuffersIfNecessary(false);
  }
}

void WebGLFramebuffer::CommitWebGL1DepthStencilIfConsistent(GLenum target) {
  DCHECK(!Context()->IsWebGL2());
  WebGLAttachment* depth_attachment = nullptr;
  WebGLAttachment* stencil_attachment = nullptr;
  WebGLAttachment* depth_stencil_attachment = nullptr;
  int count = 0;
  for (const auto& it : attachments_) {
    WebGLAttachment* attachment = it.value.Get();
    DCHECK(attachment);
    switch (it.key) {
      case GL_DEPTH_ATTACHMENT:
        depth_attachment = attachment;
        ++count;
        break;
      case GL_STENCIL_ATTACHMENT:
        stencil_attachment = attachment;
        ++count;
        break;
      case GL_DEPTH_STENCIL_ATTACHMENT:
        depth_stencil_attachment = attachment;
        ++count;
        break;
      default:
        break;
    }
  }

  web_gl1_depth_stencil_consistent_ = count <= 1;
  if (!web_gl1_depth_stencil_consistent_)
    return;

  gpu::gles2::GLES2Interface* gl = Context()->ContextGL();
  if (depth_attachment) {
    gl->FramebufferRenderbuffer(target, GL_DEPTH_STENCIL_ATTACHMENT,
                                GL_RENDERBUFFER, 0);
    depth_attachment->Attach(gl, target, GL_DEPTH_ATTACHMENT);
    gl->FramebufferRenderbuffer(target, GL_STENCIL_ATTACHMENT, GL_RENDERBUFFER,
                                0);
  } else if (stencil_attachment) {
    gl->FramebufferRenderbuffer(target, GL_DEPTH_STENCIL_ATTACHMENT,
                                GL_RENDERBUFFER, 0);
    gl->FramebufferRenderbuffer(target, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER,
                                0);
    stencil_attachment->Attach(gl, target, GL_STENCIL_ATTACHMENT);
  } else if (depth_stencil_attachment) {
    gl->FramebufferRenderbuffer(target, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER,
                                0);
    gl->FramebufferRenderbuffer(target, GL_STENCIL_ATTACHMENT, GL_RENDERBUFFER,
                                0);
    depth_stencil_attachment->Attach(gl, target, GL_DEPTH_STENCIL_ATTACHMENT);
  } else {
    gl->FramebufferRenderbuffer(target, GL_DEPTH_STENCIL_ATTACHMENT,
                                GL_RENDERBUFFER, 0);
    gl->FramebufferRenderbuffer(target, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER,
                                0);
    gl->FramebufferRenderbuffer(target, GL_STENCIL_ATTACHMENT, GL_RENDERBUFFER,
                                0);
  }
}

GLenum WebGLFramebuffer::GetDrawBuffer(GLenum draw_buffer) {
  int index = static_cast<int>(draw_buffer - GL_DRAW_BUFFER0_EXT);
  DCHECK_GE(index, 0);
  if (index < static_cast<int>(draw_buffers_.size()))
    return draw_buffers_[index];
  if (draw_buffer == GL_DRAW_BUFFER0_EXT)
    return GL_COLOR_ATTACHMENT0;
  return GL_NONE;
}

// HeapHashMap does not allow keys with a value of 0.
constexpr static GLint PlaneKey(GLint plane) {
  return plane + 1;
}

void WebGLFramebuffer::SetPLSTexture(GLint plane, WebGLTexture* texture) {
  if (texture == nullptr) {
    pls_textures_.erase(PlaneKey(plane));
  } else {
    pls_textures_.Set(PlaneKey(plane), texture);
  }
}

WebGLTexture* WebGLFramebuffer::GetPLSTexture(GLint plane) const {
  const auto it = pls_textures_.find(PlaneKey(plane));
  return (it != pls_textures_.end()) ? it->value.Get() : nullptr;
}

void WebGLFramebuffer::Trace(Visitor* visitor) const {
  visitor->Trace(attachments_);
  visitor->Trace(pls_textures_);
  WebGLContextObject::Trace(visitor);
}

}  // namespace blink
```