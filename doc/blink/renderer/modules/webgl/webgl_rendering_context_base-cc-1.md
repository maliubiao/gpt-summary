Response:
My thinking process for analyzing the code snippet and generating the summary involved these steps:

1. **Understand the Goal:** The request is to summarize the functionality of the provided C++ code snippet from the `webgl_rendering_context_base.cc` file in the Chromium Blink engine. It also asks to identify relationships with JavaScript, HTML, CSS, provide examples with hypothetical inputs/outputs, common user errors, and debugging clues related to how a user might reach this code. Crucially, it specifies that this is *part 2 of 11* and asks for a summary of *this specific part*.

2. **Initial Skimming and Keyword Identification:** I quickly scanned the code, looking for key method names, variable names, and comments. Terms like `Snapshot`, `makeXRCompatible`, `IsXRCompatible`, `MakeXrCompatibleAsync`, `OnMakeXrCompatibleFinished`, `CompleteXrCompatiblePromiseIfPending`, and the various `kSupportedInternalFormats*` constants stood out. The comments about "automatic graphics switching" and "WebXR" also caught my attention.

3. **Focus on the Core Functionality:** The bulk of this snippet clearly revolves around two main features:
    * **Taking Snapshots:** The `GetSnapshot` method deals with capturing the current rendering state of the WebGL context.
    * **Making the Context XR Compatible:** The `makeXRCompatible` and related methods handle the process of ensuring the WebGL context can be used with WebXR (Virtual/Augmented Reality) experiences.

4. **Analyze Individual Methods:** I examined each significant method in more detail:
    * **`GetSnapshot`:**  I noted the steps involved: checking for context loss, resolving and binding the drawing buffer, determining the size, creating a `CanvasResourceProvider`, copying rendering results, and finally taking the snapshot. The comments about avoiding compositing-specific resources and handling both hardware and software cases were important.
    * **`makeXRCompatible`:**  I followed the logic: checking for context loss, checking if already compatible, handling pending promises, creating a new promise, and calling `MakeXrCompatibleAsync`.
    * **`IsXRCompatible`:**  A simple getter for the `xr_compatible_` flag.
    * **`IsXrCompatibleFromResult` and `DidGpuRestart`:**  Helper functions for interpreting the results of the XR compatibility check.
    * **`GetXrSystemFromHost`:**  Retrieving the `XRSystem` object based on whether the context is on an `HTMLCanvasElement` or an `OffscreenCanvas`.
    * **`MakeXrCompatibleSync` and `MakeXrCompatibleAsync`:** The synchronous and asynchronous pathways to making the context XR compatible, involving communication with the `XRSystem`.
    * **`OnMakeXrCompatibleFinished`:**  The callback for the asynchronous process, handling different results and completing the promise.
    * **`CompleteXrCompatiblePromiseIfPending`:** Resolving or rejecting the promise based on the outcome of the XR compatibility check.
    * **`UpdateNumberOfUserAllocatedMultisampledRenderbuffers`:** A simple counter update.
    * **The `kSupportedInternalFormats*` constants:** These define the various texture formats and types supported by WebGL, broken down by ES versions and extensions.

5. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The `ScriptPromise` return type of `makeXRCompatible` directly links to JavaScript Promises. The entire XR compatibility feature is exposed to JavaScript via the WebGL API.
    * **HTML:** The code interacts with `HTMLCanvasElement` and `OffscreenCanvas`, which are HTML elements. The `GetXrSystemFromHost` method specifically differentiates between these.
    * **CSS:** While not directly manipulated, the size of the canvas (and thus the rendering buffer) is potentially influenced by CSS styles. The comments mentioning downsizing in `Reshape()` and the link to `crbug.com/845742` hint at this indirect relationship.

6. **Consider Hypothetical Inputs and Outputs:**  For `GetSnapshot`, a simple scenario would be a WebGL context with some rendered content. The output would be an `SkImage` representing that content. For `makeXRCompatible`, the input is a call from JavaScript. The output is a Promise that resolves if the context becomes XR compatible and rejects otherwise.

7. **Think About Common User Errors:**  Calling `makeXRCompatible` on a lost context is an obvious error. Also, repeatedly calling it before the promise resolves could lead to unexpected behavior (though the code handles this by returning the existing promise).

8. **Trace User Actions for Debugging:** I imagined a developer building a WebXR application and needing to debug why their WebGL content isn't appearing in VR. This led to the step-by-step scenario involving creating a canvas, getting the WebGL context, attempting to enter VR, and potentially encountering issues with XR compatibility.

9. **Address the "Part 2 of 11" Constraint:**  This was crucial. I avoided summarizing the *entire* file and focused only on the functionality present in the provided snippet. This is why the summary emphasizes snapshots and XR compatibility, as those are the primary topics covered in this specific section.

10. **Structure the Summary:** I organized the information logically, starting with the main functions, then moving to the relationships with web technologies, hypothetical examples, potential errors, debugging clues, and finally a concise summary of this specific part of the code. Using bullet points and clear headings makes the information easier to digest.

11. **Refine and Edit:** I reviewed the generated summary for clarity, accuracy, and completeness, ensuring it directly addressed all parts of the original request. I paid attention to using precise terminology and avoiding jargon where possible.
这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第二部分代码，主要关注以下功能：

**核心功能：**

1. **获取渲染结果快照 (`GetSnapshot`)**:
   - 允许获取当前 WebGL 渲染结果的图像快照。
   - 涉及处理图形切换和确保大小一致性。
   - 使用 `CanvasResourceProvider` 来管理图像资源，并区分用于合成和非合成的情况。
   - 可以回退到使用位图提供程序，如果共享图像提供程序创建失败。
   - 最终调用 `CopyRenderingResultsFromDrawingBuffer` 来实际拷贝数据。

2. **使 WebGL 上下文与 WebXR 兼容 (`makeXRCompatible`)**:
   - 提供异步方法使 WebGL 上下文能够与 WebXR (虚拟/增强现实) API 一起使用。
   - 检查上下文是否已丢失。
   - 如果已经兼容则立即返回 resolved 的 Promise。
   - 如果有正在进行的请求，则返回相同的 Promise。
   - 使用 `MakeXrCompatibleAsync` 执行异步兼容性检查。

3. **查询 WebGL 上下文的 WebXR 兼容性 (`IsXRCompatible`)**:
   - 返回一个布尔值，指示当前 WebGL 上下文是否与 WebXR 兼容。

4. **辅助判断 WebXR 兼容性结果 (`IsXrCompatibleFromResult`, `DidGpuRestart`)**:
   - `IsXrCompatibleFromResult`:  根据 `device::mojom::blink::XrCompatibleResult` 枚举值判断上下文是否兼容。
   - `DidGpuRestart`:  根据 `device::mojom::blink::XrCompatibleResult` 枚举值判断 GPU 进程是否重启过。

5. **获取与上下文关联的 XRSystem 对象 (`GetXrSystemFromHost`)**:
   - 根据上下文宿主 (`CanvasRenderingContextHost`) 是 `HTMLCanvasElement` 还是 `OffscreenCanvas` 来获取对应的 `XRSystem` 对象。

6. **同步和异步执行 WebXR 兼容性检查 (`MakeXrCompatibleSync`, `MakeXrCompatibleAsync`)**:
   - `MakeXrCompatibleSync`:  同步地检查并使上下文与 WebXR 兼容。
   - `MakeXrCompatibleAsync`:  异步地检查并使上下文与 WebXR 兼容，通过回调函数 `OnMakeXrCompatibleFinished` 处理结果。

7. **处理 WebXR 兼容性检查完成的回调 (`OnMakeXrCompatibleFinished`)**:
   - 在异步 WebXR 兼容性检查完成后被调用。
   - 根据结果更新内部状态 `xr_compatible_`。
   - 处理 GPU 重启的情况。
   - 根据不同的 `XrCompatibleResult` 设置不同的 DOMException 代码。
   - 调用 `CompleteXrCompatiblePromiseIfPending` 完成 Promise。

8. **完成 WebXR 兼容性 Promise (`CompleteXrCompatiblePromiseIfPending`)**:
   - 根据 `xr_compatible_` 状态 resolve 或 reject `make_xr_compatible_resolver_` 持有的 Promise。
   - 如果是成功状态，则 resolve Promise。
   - 如果是失败状态，则 reject Promise 并创建一个 `DOMException` 对象。
   - 记录 UMA 指标。

9. **更新用户分配的多采样渲染缓冲区的数量 (`UpdateNumberOfUserAllocatedMultisampledRenderbuffers`)**:
   - 维护一个计数器，用于跟踪用户显式分配的多采样渲染缓冲区的数量。

10. **定义支持的内部格式和类型 (`kSupportedInternalFormats*`, `kSupportedFormats*`, `kSupportedTypes*`)**:
    - 定义了各种 WebGL 支持的纹理内部格式和数据类型，根据不同的 WebGL 版本和扩展进行分类，例如 ES2, ES3, `GL_ANGLE_depth_texture`, `GL_EXT_sRGB` 等。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * `makeXRCompatible` 返回一个 `ScriptPromise<IDLUndefined>`，这是一个 JavaScript Promise 对象，允许 JavaScript 代码异步等待 WebGL 上下文变为 XR 兼容。
    * JavaScript 代码可以通过调用 `canvas.getContext('webgl').makeXRCompatible()` 来触发此功能。
    * JavaScript 可以使用 WebXR API (例如 `navigator.xr.requestSession()`)，而 `makeXRCompatible` 确保 WebGL 内容可以在 WebXR 会话中渲染。
    * **假设输入与输出:**
        * **输入:** JavaScript 调用 `gl.makeXRCompatible()`.
        * **输出:**  返回一个 Promise。如果成功，Promise 将 resolve。如果失败 (例如上下文丢失或设备不支持 WebXR)，Promise 将 reject 并抛出 `InvalidStateError` 或其他 `DOMException`。

* **HTML:**
    * 这些功能与 `<canvas>` 元素密切相关。WebGL 上下文是基于 HTMLCanvasElement 创建的。
    * `GetXrSystemFromHost` 方法会根据宿主是 `HTMLCanvasElement` 还是 `OffscreenCanvas` 来获取 `XRSystem`。
    * **用户操作如何到达这里:** 用户在 HTML 中创建一个 `<canvas>` 元素，然后通过 JavaScript 获取 WebGL 上下文，并可能调用 `makeXRCompatible()` 方法。

* **CSS:**
    * CSS 可以影响 `<canvas>` 元素的尺寸，这间接影响了 `GetSnapshot` 中获取的快照大小。
    * 虽然 CSS 不直接调用这些 C++ 代码，但它影响了 WebGL 内容的呈现，而这些代码处理了渲染结果的捕获和 XR 兼容性。

**逻辑推理与假设输入/输出：**

* **`GetSnapshot`:**
    * **假设输入:** 一个已经渲染了一些内容的 WebGL 上下文。
    * **输出:**  一个 `SkImage` 对象，包含了当前渲染缓冲区的像素数据。如果发生错误（例如上下文丢失），则返回 `nullptr`。

* **`makeXRCompatible`:**
    * **假设输入:**  在 JavaScript 中调用 `gl.makeXRCompatible()`。
    * **输出:** 一个 `ScriptPromise`。
        * **成功输出:**  Promise resolves (不带任何值，因为是 `IDLUndefined`)，并且内部 `xr_compatible_` 标志设置为 `true`。
        * **失败输出:** Promise rejects，并抛出一个 `DOMException`，例如 `InvalidStateError` (如果上下文已丢失) 或 `AbortError` (如果无法获取 XRSystem)。

**用户或编程常见的使用错误：**

* **在上下文丢失后调用 `makeXRCompatible`:** 这会导致抛出 `InvalidStateError` 异常。
* **多次调用 `makeXRCompatible` 而不等待 Promise 完成:**  虽然代码中做了处理，会返回相同的 Promise，但理解异步操作是很重要的，避免不必要的重复操作。
* **期望在非 WebXR 支持的浏览器或设备上 `makeXRCompatible` 成功:** 这会导致 Promise 被 reject。

**用户操作如何一步步的到达这里 (调试线索)：**

1. **用户创建一个包含 `<canvas>` 元素的 HTML 页面。**
2. **JavaScript 代码获取该 `<canvas>` 元素的 WebGL 渲染上下文 (`canvas.getContext('webgl')` 或 `canvas.getContext('webgl2')`)。**
3. **对于 `GetSnapshot`:**
   - 用户可能通过 JavaScript 调用一个自定义的函数或库，该函数内部调用了 WebGL 的 `readPixels` 或其他机制来获取像素数据。虽然这个 C++ 代码没有直接暴露给 JavaScript，但它是 Blink 内部实现快照功能的一部分。
   - 浏览器内部可能因为某些操作（例如标签页切换、最小化）触发自动图形切换，从而间接调用 `GetSnapshot`。
4. **对于 `makeXRCompatible`:**
   - 用户在尝试创建一个 WebXR 会话之前，或者在 WebXR 应用初始化时，可能会调用 `gl.makeXRCompatible()`。
   - 例如，用户点击一个 "进入 VR" 的按钮，JavaScript 代码会尝试 `navigator.xr.requestSession('immersive-vr')`，在此之前可能需要确保 WebGL 上下文是 XR 兼容的。

**本部分功能归纳：**

这部分代码主要负责以下两个核心功能：

1. **提供获取 WebGL 渲染结果快照的机制，**用于例如保存图像或在其他地方使用渲染内容。
2. **实现使 WebGL 上下文能够与 WebXR API 协同工作的逻辑，**包括异步的兼容性检查和状态管理，是构建 WebXR 应用的关键步骤。

此外，它还定义了 WebGL 支持的各种纹理格式和类型，为后续的纹理操作提供了基础。

### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
cess, specifically during automatic
  // graphics switching. Guard against this.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return nullptr;

  // Use the drawing buffer size here instead of the canvas size to ensure that
  // sizing is consistent. The forced downsizing logic in Reshape() can lead to
  // the drawing buffer being smaller than the canvas size.
  // See https://crbug.com/845742.
  gfx::Size size = GetDrawingBuffer()->Size();
  // We are grabbing a snapshot that is generally not for compositing, so use a
  // custom resource provider. This avoids consuming compositing-specific
  // resources (e.g. GpuMemoryBuffer). We tag the SharedImage with display usage
  // since there are uncommon paths which may use this snapshot for compositing.
  const auto image_info =
      SkImageInfo::Make(SkISize::Make(size.width(), size.height()),
                        CanvasRenderingContextSkColorInfo());
  constexpr auto kShouldInitialize =
      CanvasResourceProvider::ShouldInitialize::kNo;
  std::unique_ptr<CanvasResourceProvider> resource_provider =
      CanvasResourceProvider::CreateSharedImageProvider(
          image_info, GetDrawingBuffer()->FilterQuality(), kShouldInitialize,
          SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
          gpu::SHARED_IMAGE_USAGE_DISPLAY_READ);
  if (!resource_provider || !resource_provider->IsValid()) {
    resource_provider = CanvasResourceProvider::CreateBitmapProvider(
        image_info, GetDrawingBuffer()->FilterQuality(),
        CanvasResourceProvider::ShouldInitialize::kNo);
  }

  if (!resource_provider || !resource_provider->IsValid())
    return nullptr;

  if (!CopyRenderingResultsFromDrawingBuffer(resource_provider.get(),
                                             kBackBuffer)) {
    // CopyRenderingResultsFromDrawingBuffer handles both the
    // hardware-accelerated and software cases, so there is no
    // possible additional fallback for failures seen at this point.
    return nullptr;
  }
  return resource_provider->Snapshot(reason);
}

ScriptPromise<IDLUndefined> WebGLRenderingContextBase::makeXRCompatible(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (isContextLost()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context lost.");
    return EmptyPromise();
  }

  // Return a resolved promise if we're already xr compatible. Once we're
  // compatible, we should always be compatible unless a context lost occurs.
  // DispatchContextLostEvent() resets this flag to false.
  if (xr_compatible_)
    return ToResolvedUndefinedPromise(script_state);

  // If there's a request currently in progress, return the same promise.
  if (make_xr_compatible_resolver_)
    return make_xr_compatible_resolver_->Promise();

  make_xr_compatible_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto promise = make_xr_compatible_resolver_->Promise();

  MakeXrCompatibleAsync();

  return promise;
}

bool WebGLRenderingContextBase::IsXRCompatible() const {
  return xr_compatible_;
}

bool WebGLRenderingContextBase::IsXrCompatibleFromResult(
    device::mojom::blink::XrCompatibleResult result) {
  return result ==
             device::mojom::blink::XrCompatibleResult::kAlreadyCompatible ||
         result ==
             device::mojom::blink::XrCompatibleResult::kCompatibleAfterRestart;
}

bool WebGLRenderingContextBase::DidGpuRestart(
    device::mojom::blink::XrCompatibleResult result) {
  return result == device::mojom::blink::XrCompatibleResult::
                       kCompatibleAfterRestart ||
         result == device::mojom::blink::XrCompatibleResult::
                       kNotCompatibleAfterRestart;
}

XRSystem* WebGLRenderingContextBase::GetXrSystemFromHost(
    CanvasRenderingContextHost* host) {
  XRSystem* xr = nullptr;

  if (host->IsOffscreenCanvas()) {
    OffscreenCanvas* offscreen_canvas = static_cast<OffscreenCanvas*>(host);
    if (auto* window = DynamicTo<LocalDOMWindow>(
            offscreen_canvas->GetExecutionContext())) {
      if (Document* document = window->document()) {
        xr = XRSystem::From(*document);
      }
    }
  } else {
    HTMLCanvasElement* canvas = static_cast<HTMLCanvasElement*>(host);
    xr = XRSystem::From(canvas->GetDocument());
  }

  return xr;
}

bool WebGLRenderingContextBase::MakeXrCompatibleSync(
    CanvasRenderingContextHost* host) {
  device::mojom::blink::XrCompatibleResult xr_compatible_result =
      device::mojom::blink::XrCompatibleResult::kNoDeviceAvailable;

  if constexpr (BUILDFLAG(ENABLE_VR)) {
    if (XRSystem* xr = GetXrSystemFromHost(host)) {
      xr->MakeXrCompatibleSync(&xr_compatible_result);
    }
  }

  return IsXrCompatibleFromResult(xr_compatible_result);
}

void WebGLRenderingContextBase::MakeXrCompatibleAsync() {
  if (XRSystem* xr = GetXrSystemFromHost(Host())) {
    // The promise will be completed on the callback.
    xr->MakeXrCompatibleAsync(
        WTF::BindOnce(&WebGLRenderingContextBase::OnMakeXrCompatibleFinished,
                      WrapWeakPersistent(this)));
  } else {
    xr_compatible_ = false;
    CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kAbortError);
  }
}

void WebGLRenderingContextBase::OnMakeXrCompatibleFinished(
    device::mojom::blink::XrCompatibleResult xr_compatible_result) {
  xr_compatible_ = IsXrCompatibleFromResult(xr_compatible_result);

  // If the gpu process is restarted, MaybeRestoreContext will resolve the
  // promise on the subsequent restore.
  if (!DidGpuRestart(xr_compatible_result)) {
    DOMExceptionCode exception_code = DOMExceptionCode::kUnknownError;
    switch (xr_compatible_result) {
      case device::mojom::blink::XrCompatibleResult::kAlreadyCompatible:
        exception_code = DOMExceptionCode::kNoError;
        break;
      case device::mojom::blink::XrCompatibleResult::kNoDeviceAvailable:
        // Per WebXR spec, reject with an InvalidStateError if device is null.
        exception_code = DOMExceptionCode::kInvalidStateError;
        break;
      case device::mojom::blink::XrCompatibleResult::kWebXrFeaturePolicyBlocked:
        exception_code = DOMExceptionCode::kSecurityError;
        break;
      case device::mojom::blink::XrCompatibleResult::kCompatibleAfterRestart:
      case device::mojom::blink::XrCompatibleResult::kNotCompatibleAfterRestart:
        NOTREACHED();
    }
    CompleteXrCompatiblePromiseIfPending(exception_code);
  }
}

void WebGLRenderingContextBase::CompleteXrCompatiblePromiseIfPending(
    DOMExceptionCode exception_code) {
  if (make_xr_compatible_resolver_) {
    if (xr_compatible_) {
      DCHECK(exception_code == DOMExceptionCode::kNoError);
      make_xr_compatible_resolver_->Resolve();
    } else {
      DCHECK(exception_code != DOMExceptionCode::kNoError);
      make_xr_compatible_resolver_->Reject(
          MakeGarbageCollected<DOMException>(exception_code));
    }

    make_xr_compatible_resolver_ = nullptr;

    if (IdentifiabilityStudySettings::Get()->ShouldSampleSurface(
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kWebFeature,
                WebFeature::kWebGLRenderingContextMakeXRCompatible))) {
      const auto& ukm_params = GetUkmParameters();
      IdentifiabilityMetricBuilder(ukm_params.source_id)
          .AddWebFeature(WebFeature::kWebGLRenderingContextMakeXRCompatible,
                         exception_code == DOMExceptionCode::kNoError)
          .Record(ukm_params.ukm_recorder);
    }
  }
}

void WebGLRenderingContextBase::
    UpdateNumberOfUserAllocatedMultisampledRenderbuffers(int delta) {
  DCHECK(delta >= -1 && delta <= 1);
  number_of_user_allocated_multisampled_renderbuffers_ += delta;
  DCHECK_GE(number_of_user_allocated_multisampled_renderbuffers_, 0);
}

namespace {

// Exposed by GL_ANGLE_depth_texture
static constexpr std::array<GLenum, 2> kSupportedInternalFormatsOESDepthTex = {
    GL_DEPTH_COMPONENT,
    GL_DEPTH_STENCIL,
};

// Exposed by GL_EXT_sRGB
static constexpr std::array<GLenum, 2> kSupportedInternalFormatsEXTsRGB = {
    GL_SRGB,
    GL_SRGB_ALPHA_EXT,
};

// ES3 enums supported by both CopyTexImage and TexImage.
static constexpr auto kSupportedInternalFormatsES3 = std::to_array<GLenum>({
    GL_R8,           GL_RG8,      GL_RGB565,   GL_RGB8,       GL_RGBA4,
    GL_RGB5_A1,      GL_RGBA8,    GL_RGB10_A2, GL_RGB10_A2UI, GL_SRGB8,
    GL_SRGB8_ALPHA8, GL_R8I,      GL_R8UI,     GL_R16I,       GL_R16UI,
    GL_R32I,         GL_R32UI,    GL_RG8I,     GL_RG8UI,      GL_RG16I,
    GL_RG16UI,       GL_RG32I,    GL_RG32UI,   GL_RGBA8I,     GL_RGBA8UI,
    GL_RGBA16I,      GL_RGBA16UI, GL_RGBA32I,  GL_RGBA32UI,   GL_RGB32I,
    GL_RGB32UI,      GL_RGB8I,    GL_RGB8UI,   GL_RGB16I,     GL_RGB16UI,
});

// ES3 enums only supported by TexImage
static constexpr auto kSupportedInternalFormatsTexImageES3 =
    std::to_array<GLenum>({
        GL_R8_SNORM,
        GL_R16F,
        GL_R32F,
        GL_RG8_SNORM,
        GL_RG16F,
        GL_RG32F,
        GL_RGB8_SNORM,
        GL_R11F_G11F_B10F,
        GL_RGB9_E5,
        GL_RGB16F,
        GL_RGB32F,
        GL_RGBA8_SNORM,
        GL_RGBA16F,
        GL_RGBA32F,
        GL_DEPTH_COMPONENT16,
        GL_DEPTH_COMPONENT24,
        GL_DEPTH_COMPONENT32F,
        GL_DEPTH24_STENCIL8,
        GL_DEPTH32F_STENCIL8,
    });

// Exposed by EXT_texture_norm16
static constexpr auto kSupportedInternalFormatsEXTTextureNorm16ES3 =
    std::to_array<GLenum>({GL_R16_EXT, GL_RG16_EXT, GL_RGB16_EXT, GL_RGBA16_EXT,
                           GL_R16_SNORM_EXT, GL_RG16_SNORM_EXT,
                           GL_RGB16_SNORM_EXT, GL_RGBA16_SNORM_EXT});

static constexpr std::array<GLenum, 2> kSupportedFormatsEXTTextureNorm16ES3 = {
    GL_RED, GL_RG};

static constexpr std::array<GLenum, 2> kSupportedTypesEXTTextureNorm16ES3 = {
    GL_SHORT, GL_UNSIGNED_SHORT};

// Exposed by EXT_color_buffer_float
static constexpr auto kSupportedInternalFormatsCopyTexImageFloatES3 =
    std::to_array<GLenum>({GL_R16F, GL_R32F, GL_RG16F, GL_RG32F, GL_RGB16F,
                           GL_RGB32F, GL_RGBA16F, GL_RGBA32F,
                           GL_R11F_G11F_B10F});

// Exposed by EXT_color_buffer_half_float
static constexpr std::array<GLenum, 4>
    kSupportedInternalFormatsCopyTexImageHalfFloatES3 = {
        GL_R16F,
        GL_RG16F,
        GL_RGB16F,
        GL_RGBA16F,
};

// ES3 enums supported by TexImageSource
static constexpr auto kSupportedInternalFormatsTexImageSourceES3 =
    std::to_array<GLenum>({
        GL_R8,      GL_R16F,           GL_R32F,         GL_R8UI,     GL_RG8,
        GL_RG16F,   GL_RG32F,          GL_RG8UI,        GL_RGB8,     GL_SRGB8,
        GL_RGB565,  GL_R11F_G11F_B10F, GL_RGB9_E5,      GL_RGB16F,   GL_RGB32F,
        GL_RGB8UI,  GL_RGBA8,          GL_SRGB8_ALPHA8, GL_RGB5_A1,  GL_RGBA4,
        GL_RGBA16F, GL_RGBA32F,        GL_RGBA8UI,      GL_RGB10_A2,
    });

// ES2 enums
// Internalformat must equal format in ES2.
static constexpr auto kSupportedFormatsES2 = std::to_array<GLenum>({
    GL_RGB,
    GL_RGBA,
    GL_LUMINANCE_ALPHA,
    GL_LUMINANCE,
    GL_ALPHA,
});

// Exposed by GL_ANGLE_depth_texture
static constexpr std::array<GLenum, 2> kSupportedFormatsOESDepthTex = {
    GL_DEPTH_COMPONENT,
    GL_DEPTH_STENCIL,
};

// Exposed by GL_EXT_sRGB
static constexpr std::array<GLenum, 2> kSupportedFormatsEXTsRGB = {
    GL_SRGB,
    GL_SRGB_ALPHA_EXT,
};

// ES3 enums
static constexpr auto kSupportedFormatsES3 = std::to_array<GLenum>({
    GL_RED,
    GL_RED_INTEGER,
    GL_RG,
    GL_RG_INTEGER,
    GL_RGB,
    GL_RGB_INTEGER,
    GL_RGBA,
    GL_RGBA_INTEGER,
    GL_DEPTH_COMPONENT,
    GL_DEPTH_STENCIL,
});

// ES3 enums supported by TexImageSource
static constexpr auto kSupportedFormatsTexImageSourceES3 =
    std::to_array<GLenum>({
        GL_RED,
        GL_RED_INTEGER,
        GL_RG,
        GL_RG_INTEGER,
        GL_RGB,
        GL_RGB_INTEGER,
        GL_RGBA,
        GL_RGBA_INTEGER,
    });

// ES2 enums
static constexpr std::array<GLenum, 4> kSupportedTypesES2 = {
    GL_UNSIGNED_BYTE,
    GL_UNSIGNED_SHORT_5_6_5,
    GL_UNSIGNED_SHORT_4_4_4_4,
    GL_UNSIGNED_SHORT_5_5_5_1,
};

// Exposed by GL_OES_texture_float
static constexpr std::array<GLenum, 1> kSupportedTypesOESTexFloat = {
    GL_FLOAT,
};

// Exposed by GL_OES_texture_half_float
static constexpr std::array<GLenum, 1> kSupportedTypesOESTexHalfFloat = {
    GL_HALF_FLOAT_OES,
};

// Exposed by GL_ANGLE_depth_texture
static constexpr std::array<GLenum, 3> kSupportedTypesOESDepthTex = {
    GL_UNSIGNED_SHORT,
    GL_UNSIGNED_INT,
    GL_UNSIGNED_INT_24_8,
};

// ES3 enums
static constexpr auto kSupportedTypesES3 = std::to_array<GLenum>({
    GL_BYTE,
    GL_UNSIGNED_SHORT,
    GL_SHORT,
    GL_UNSIGNED_INT,
    GL_INT,
    GL_HALF_FLOAT,
    GL_FLOAT,
    GL_UNSIGNED_INT_2_10_10_10_REV,
    GL_UNSIGNED_INT_10F_11F_11F_REV,
    GL_UNSIGNED_INT_5_9_9_9_REV,
    GL_UNSIGNED_INT_24_8,
    GL_FLOAT_32_UNSIGNED_INT_24_8_REV,
});

// ES3 enums supported by TexImageSource
static constexpr std::array<GLenum, 4> kSupportedTypesTexImageSourceES3 = {
    GL_HALF_FLOAT,
    GL_FLOAT,
    GL_UNSIGNED_INT_10F_11F_11F_REV,
    GL_UNSIGNED_INT_2_10_10_10_REV,
};

}  // namespace

WebGLRenderingContextBase::WebGLRenderingContextBase(
    CanvasRenderingContextHost* host,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    const CanvasContextCreationAttributesCore& requested_attributes,
    Platform::ContextType version)
    : WebGLRenderingContextBase(
          host,
          host->GetTopExecutionContext()->GetTaskRunner(TaskType::kWebGL),
          std::move(context_provider),
          graphics_info,
          requested_attributes,
          version) {}

WebGLRenderingContextBase::WebGLRenderingContextBase(
    CanvasRenderingContextHost* host,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    const CanvasContextCreationAttributesCore& requested_attributes,
    Platform::ContextType context_type)
    : CanvasRenderingContext(host,
                             requested_attributes,
                             context_type == Platform::kWebGL2ContextType
                                 ? CanvasRenderingAPI::kWebgl2
                                 : CanvasRenderingAPI::kWebgl),
      context_group_(MakeGarbageCollected<WebGLContextGroup>()),
      dispatch_context_lost_event_timer_(
          task_runner,
          this,
          &WebGLRenderingContextBase::DispatchContextLostEvent),
      restore_timer_(task_runner,
                     this,
                     &WebGLRenderingContextBase::MaybeRestoreContext),
      task_runner_(task_runner),
      num_gl_errors_to_console_allowed_(kMaxGLErrorsAllowedToConsole),
      context_type_(context_type),
      number_of_user_allocated_multisampled_renderbuffers_(0) {
  DCHECK(context_provider);

  xr_compatible_ = requested_attributes.xr_compatible;

  context_group_->AddContext(this);

  max_viewport_dims_ = {};
  context_provider->ContextGL()->GetIntegerv(GL_MAX_VIEWPORT_DIMS,
                                             max_viewport_dims_.data());
  InitializeWebGLContextLimits(context_provider.get());

  scoped_refptr<DrawingBuffer> buffer =
      CreateDrawingBuffer(std::move(context_provider), graphics_info);
  if (!buffer) {
    context_lost_mode_ = kSyntheticLostContext;
    return;
  }

  drawing_buffer_ = std::move(buffer);
  GetDrawingBuffer()->Bind(GL_FRAMEBUFFER);
  SetupFlags();

  String disabled_webgl_extensions(GetDrawingBuffer()
                                       ->ContextProvider()
                                       ->GetGpuFeatureInfo()
                                       .disabled_webgl_extensions.c_str());
  Vector<String> disabled_extension_list;
  disabled_webgl_extensions.Split(' ', disabled_extension_list);
  for (const auto& entry : disabled_extension_list) {
    disabled_extensions_.insert(entry);
  }

#define ADD_VALUES_TO_SET(set, values)             \
  for (size_t i = 0; i < std::size(values); ++i) { \
    set.insert(values[i]);                         \
  }

  ADD_VALUES_TO_SET(supported_internal_formats_, kSupportedFormatsES2);
  ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                    kSupportedFormatsES2);
  ADD_VALUES_TO_SET(supported_internal_formats_copy_tex_image_,
                    kSupportedFormatsES2);
  ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsES2);
  ADD_VALUES_TO_SET(supported_tex_image_source_formats_, kSupportedFormatsES2);
  ADD_VALUES_TO_SET(supported_types_, kSupportedTypesES2);
  ADD_VALUES_TO_SET(supported_tex_image_source_types_, kSupportedTypesES2);
}

scoped_refptr<DrawingBuffer> WebGLRenderingContextBase::CreateDrawingBuffer(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info) {
  const CanvasContextCreationAttributesCore& attrs = CreationAttributes();
  bool premultiplied_alpha = attrs.premultiplied_alpha;
  bool want_alpha_channel = attrs.alpha;
  bool want_depth_buffer = attrs.depth;
  bool want_stencil_buffer = attrs.stencil;
  bool want_antialiasing = attrs.antialias;
  bool desynchronized = attrs.desynchronized;
  DrawingBuffer::PreserveDrawingBuffer preserve = attrs.preserve_drawing_buffer
                                                      ? DrawingBuffer::kPreserve
                                                      : DrawingBuffer::kDiscard;
  DrawingBuffer::WebGLVersion web_gl_version = DrawingBuffer::kWebGL1;
  if (context_type_ == Platform::kWebGL1ContextType) {
    web_gl_version = DrawingBuffer::kWebGL1;
  } else if (context_type_ == Platform::kWebGL2ContextType) {
    web_gl_version = DrawingBuffer::kWebGL2;
  } else {
    NOTREACHED();
  }

  // On Mac OS, DrawingBuffer is using an IOSurface as its backing storage, this
  // allows WebGL-rendered canvases to be composited by the OS rather than
  // Chrome.
  // IOSurfaces are only compatible with the GL_TEXTURE_RECTANGLE_ARB binding
  // target. So to avoid the knowledge of GL_TEXTURE_RECTANGLE_ARB type textures
  // being introduced into more areas of the code, we use the code path of
  // non-WebGLImageChromium for OffscreenCanvas.
  // See detailed discussion in crbug.com/649668.
  DrawingBuffer::ChromiumImageUsage chromium_image_usage =
      Host()->IsOffscreenCanvas() ? DrawingBuffer::kDisallowChromiumImage
                                  : DrawingBuffer::kAllowChromiumImage;

  bool using_swap_chain = context_provider->SharedImageInterface()
                              ->GetCapabilities()
                              .shared_image_swap_chain &&
                          desynchronized;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  return DrawingBuffer::Create(
      std::move(context_provider), graphics_info, using_swap_chain, this,
      ClampedCanvasSize(), premultiplied_alpha, want_alpha_channel,
      want_depth_buffer, want_stencil_buffer, want_antialiasing, desynchronized,
      preserve, web_gl_version, chromium_image_usage, Host()->FilterQuality(),
      drawing_buffer_color_space_,
      PowerPreferenceToGpuPreference(attrs.power_preference));
}

void WebGLRenderingContextBase::InitializeNewContext() {
  DCHECK(!isContextLost());
  DCHECK(GetDrawingBuffer());

  marked_canvas_dirty_ = false;
  must_paint_to_canvas_ = false;
  active_texture_unit_ = 0;
  pack_alignment_ = 4;
  unpack_alignment_ = 4;
  unpack_flip_y_ = false;
  unpack_premultiply_alpha_ = false;
  unpack_colorspace_conversion_ = GC3D_BROWSER_DEFAULT_WEBGL;
  bound_array_buffer_ = nullptr;
  current_program_ = nullptr;
  framebuffer_binding_ = nullptr;
  renderbuffer_binding_ = nullptr;
  depth_mask_ = true;
  depth_enabled_ = false;
  stencil_enabled_ = false;
  stencil_mask_ = 0xFFFFFFFF;
  stencil_mask_back_ = 0xFFFFFFFF;
  stencil_func_ref_ = 0;
  stencil_func_ref_back_ = 0;
  stencil_func_mask_ = 0xFFFFFFFF;
  stencil_func_mask_back_ = 0xFFFFFFFF;
  num_gl_errors_to_console_allowed_ = kMaxGLErrorsAllowedToConsole;

  rasterizer_discard_enabled_ = false;

  clear_color_[0] = clear_color_[1] = clear_color_[2] = clear_color_[3] = 0;
  scissor_enabled_ = false;
  clear_depth_ = 1;
  clear_stencil_ = 0;
  color_mask_[0] = color_mask_[1] = color_mask_[2] = color_mask_[3] = true;

  GLint num_combined_texture_image_units = 0;
  ContextGL()->GetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS,
                           &num_combined_texture_image_units);
  texture_units_.clear();
  texture_units_.resize(num_combined_texture_image_units);

  GLint num_vertex_attribs = 0;
  ContextGL()->GetIntegerv(GL_MAX_VERTEX_ATTRIBS, &num_vertex_attribs);
  max_vertex_attribs_ = num_vertex_attribs;

  max_texture_size_ = 0;
  ContextGL()->GetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture_size_);
  max_texture_level_ =
      WebGLTexture::ComputeLevelCount(max_texture_size_, max_texture_size_, 1);
  max_cube_map_texture_size_ = 0;
  ContextGL()->GetIntegerv(GL_MAX_CUBE_MAP_TEXTURE_SIZE,
                           &max_cube_map_texture_size_);
  max3d_texture_size_ = 0;
  max3d_texture_level_ = 0;
  max_array_texture_layers_ = 0;
  if (IsWebGL2()) {
    ContextGL()->GetIntegerv(GL_MAX_3D_TEXTURE_SIZE, &max3d_texture_size_);
    max3d_texture_level_ = WebGLTexture::ComputeLevelCount(
        max3d_texture_size_, max3d_texture_size_, max3d_texture_size_);
    ContextGL()->GetIntegerv(GL_MAX_ARRAY_TEXTURE_LAYERS,
                             &max_array_texture_layers_);
  }
  max_cube_map_texture_level_ = WebGLTexture::ComputeLevelCount(
      max_cube_map_texture_size_, max_cube_map_texture_size_, 1);
  max_renderbuffer_size_ = 0;
  ContextGL()->GetIntegerv(GL_MAX_RENDERBUFFER_SIZE, &max_renderbuffer_size_);

  // These two values from EXT_draw_buffers are lazily queried.
  max_draw_buffers_ = 0;
  max_color_attachments_ = 0;

  back_draw_buffer_ = GL_BACK;

  read_buffer_of_default_framebuffer_ = GL_BACK;

  default_vertex_array_object_ = MakeGarbageCollected<WebGLVertexArrayObject>(
      this, WebGLVertexArrayObjectBase::kVaoTypeDefault);

  bound_vertex_array_object_ = default_vertex_array_object_;

  vertex_attrib_type_.resize(max_vertex_attribs_);

  ContextGL()->Viewport(0, 0, drawingBufferWidth(), drawingBufferHeight());
  scissor_box_[0] = scissor_box_[1] = 0;
  scissor_box_[2] = drawingBufferWidth();
  scissor_box_[3] = drawingBufferHeight();
  ContextGL()->Scissor(scissor_box_[0], scissor_box_[1], scissor_box_[2],
                       scissor_box_[3]);

  GetDrawingBuffer()->ContextProvider()->SetLostContextCallback(
      WTF::BindRepeating(&WebGLRenderingContextBase::ForceLostContext,
                         WrapWeakPersistent(this),
                         WebGLRenderingContextBase::kRealLostContext,
                         WebGLRenderingContextBase::kAuto));
  GetDrawingBuffer()->ContextProvider()->SetErrorMessageCallback(
      WTF::BindRepeating(&WebGLRenderingContextBase::OnErrorMessage,
                         WrapWeakPersistent(this)));

  // If WebGL 2, the PRIMITIVE_RESTART_FIXED_INDEX should be always enabled.
  // See the section <Primitive Restart is Always Enabled> in WebGL 2 spec:
  // https://www.khronos.org/registry/webgl/specs/latest/2.0/#4.1.4
  if (IsWebGL2())
    ContextGL()->Enable(GL_PRIMITIVE_RESTART_FIXED_INDEX);

  // This ensures that the context has a valid "lastFlushID" and won't be
  // mistakenly identified as the "least recently used" context.
  ContextGL()->Flush();

  for (int i = 0; i < kWebGLExtensionNameCount; ++i)
    extension_enabled_[i] = false;

  // This limits the count of threads if the extension is yet to be requested.
  if (String(ContextGL()->GetString(GL_EXTENSIONS))
          .Contains("GL_KHR_parallel_shader_compile")) {
    ContextGL()->MaxShaderCompilerThreadsKHR(2);
  }
  is_web_gl2_formats_types_added_ = false;
  is_web_gl2_tex_image_source_formats_types_added_ = false;
  is_web_gl2_internal_formats_copy_tex_image_added_ = false;
  is_oes_texture_float_formats_types_added_ = false;
  is_oes_texture_half_float_formats_types_added_ = false;
  is_web_gl_depth_texture_formats_types_added_ = false;
  is_ext_srgb_formats_types_added_ = false;
  is_ext_color_buffer_float_formats_added_ = false;
  is_ext_color_buffer_half_float_formats_added_ = false;
  is_ext_texture_norm16_added_ = false;

  supported_internal_formats_.clear();
  ADD_VALUES_TO_SET(supported_internal_formats_, kSupportedFormatsES2);
  supported_tex_image_source_internal_formats_.clear();
  ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                    kSupportedFormatsES2);
  supported_internal_formats_copy_tex_image_.clear();
  ADD_VALUES_TO_SET(supported_internal_formats_copy_tex_image_,
                    kSupportedFormatsES2);
  supported_formats_.clear();
  ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsES2);
  supported_tex_image_source_formats_.clear();
  ADD_VALUES_TO_SET(supported_tex_image_source_formats_, kSupportedFormatsES2);
  supported_types_.clear();
  ADD_VALUES_TO_SET(supported_types_, kSupportedTypesES2);
  supported_tex_image_source_types_.clear();
  ADD_VALUES_TO_SET(supported_tex_image_source_types_, kSupportedTypesES2);

  number_of_user_allocated_multisampled_renderbuffers_ = 0;

  // The DrawingBuffer was unable to store the state that dirtied when it was
  // initialized. Restore it now.
  GetDrawingBuffer()->RestoreAllState();
  ActivateContext(this);
}

void WebGLRenderingContextBase::SetupFlags() {
  DCHECK(GetDrawingBuffer());
  if (canvas()) {
    synthesized_errors_to_console_ =
        canvas()->GetSettings()->GetWebGLErrorsToConsoleEnabled();
  }

  is_depth_stencil_supported_ =
      ExtensionsUtil()->IsExtensionEnabled("GL_OES_packed_depth_stencil");
}

void WebGLRenderingContextBase::AddCompressedTextureFormat(GLenum format) {
  if (!compressed_texture_formats_.Contains(format))
    compressed_texture_formats_.push_back(format);
}

void WebGLRenderingContextBase::RemoveAllCompressedTextureFormats() {
  compressed_texture_formats_.clear();
}

// Helper function for V8 bindings to identify what version of WebGL a
// CanvasRenderingContext supports.
unsigned WebGLRenderingContextBase::GetWebGLVersion(
    const CanvasRenderingContext* context) {
  if (!context->IsWebGL())
    return 0;
  return static_cast<const WebGLRenderingContextBase*>(context)->ContextType();
}

WebGLRenderingContextBase::~WebGLRenderingContextBase() {
  // It's forbidden to refer to other GC'd objects in a GC'd object's
  // destructor. It's useful for DrawingBuffer to guarantee that it
  // calls its DrawingBufferClient during its own destruction, but if
  // the WebGL context is also being destroyed, then it's essential
  // that the DrawingBufferClient methods not try to touch other
  // objects like WebGLTextures that were previously hooked into the
  // context state.
  destruction_in_progress_ = true;

  // Now that the context and context group no longer hold on to the
  // objects they create, and now that the objects are eagerly finalized
  // rather than the context, there is very little useful work that this
  // destructor can do, since it's not allowed to touch other on-heap
  // objects. All it can do is destroy its underlying context, which, if
  // there are no other contexts in the same share group, will cause all of
  // the underlying graphics resources to be deleted. (Currently, it's
  // always the case that there are no other contexts in the same share
  // group -- resource sharing between WebGL contexts is not yet
  // implemented, and due to its complex semantics, it's doubtful that it
  // ever will be.)
  DestroyContext();

  // Now that this context is destroyed, see if there's a
  // previously-evicted one that should be restored.
  RestoreEvictedContext(this);
}

void WebGLRenderingContextBase::DestroyContext() {
  if (!GetDrawingBuffer())
    return;

  // Ensure pixel local storage isn't active and blocking calls during our
  // destruction process.
  if (has_activated_pixel_local_storage_) {
    ContextGL()->FramebufferPixelLocalStorageInterruptANGLE();
  }

  clearProgramCompletionQueries();

  extensions_util_.reset();

  base::RepeatingClosure null_closure;
  base::RepeatingCallback<void(const char*, int32_t)> null_function;
  GetDrawingBuffer()->ContextProvider()->SetLostContextCallback(
      std::move(null_closure));
  GetDrawingBuffer()->ContextProvider()->SetErrorMessageCallback(
      std::move(null_function));

  DCHECK(GetDrawingBuffer());
  drawing_buffer_->BeginDestruction();
  drawing_buffer_ = nullptr;
}

void WebGLRenderingContextBase::MarkContextChanged(
    ContentChangeType change_type,
    CanvasPerformanceMonitor::DrawType draw_type) {
  if (isContextLost())
    return;

  if (framebuffer_binding_) {
    framebuffer_binding_->SetContentsChanged(true);
    return;
  }

  // Regardless of whether dirty propagations are optimized away, the back
  // buffer is now out of sync with respect to the canvas's internal backing
  // store -- which is only used for certain purposes, like printing.
  must_paint_to_canvas_ = true;

  if (!GetDrawingBuffer()->MarkContentsChanged() && marked_canvas_dirty_) {
    return;
  }

  if (Host()->IsOffscreenCanvas()) {
    marked_canvas_dirty_ = true;
    DidDraw(draw_type);
    return;
  }

  if (!canvas())
    return;

  if (!marked_canvas_dirty_) {
    marked_canvas_dirty_ = true;
    if (auto* cc_layer = CcLayer())
      cc_layer->SetNeedsDisplay();
    DidDraw(draw_type);
  }
}

scoped_refptr<base::SingleThreadTaskRunner>
WebGLRenderingContextBase::GetContextTaskRunner() {
  return task_runner_;
}

bool WebGLRenderingContextBase::PushFrame() {
  TRACE_EVENT0("blink", "WebGLRenderingContextBase::PushFrame");
  DCHECK(Host());
  DCHECK(Host()->IsOffscreenCanvas());
  if (isContextLost() || !GetDrawingBuffer())
    return false;

  bool must_clear_now = ClearIfComposited(kClearCallerOther) != kSkipped;
  if (!must_paint_to_canvas_ && !must_clear_now)
    return false;

  if (!Host()->LowLatencyEnabled() &&
      GetDrawingBuffer()->IsUsingGpuCompositing()) {
    // If LowLatency is not enabled, and it's using Gpu Compositing, it will try
    // to export the mailbox, synctoken and callback mechanism for the
    // compositor to present the frame in the offscrencanvas.
    if (PushFrameNoCopy())
      return true;
  }

  return PushFrameWithCopy();
}

bool WebGLRenderingContextBase::PushFrameNoCopy() {
  auto canvas_resource = GetDrawingBuffer()->ExportCanvasResource();
  if (!canvas_resource)
    return false;
  const int width = GetDrawingBuffer()->Size().width();
  const int height = GetDrawingBuffer()->Size().height();
  const bool submitted_frame = Host()->PushFrame(
      std::move(canvas_resource), SkIRect::MakeWH(width, height));

  MarkLayerComposited();
  return submitted_frame;
}

bool WebGLRenderingContextBase::PushFrameWithCopy() {
  bool submitted_frame = false;
  if (PaintRenderingResultsToCanvas(kBackBuffer)) {
    if (Host()->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)) {
      const int width = GetDrawingBuffer()->Size().width();
      const int height = GetDrawingBuffer()->Size().height();
      submitted_frame =
          Host()->PushFrame(Host()->ResourceProvider()->ProduceCanvasResource(
                                FlushReason::kNon2DCanvas),
                            SkIRect::MakeWH(width, height));
    }
  }
  MarkLayerComposited();
  return submitted_frame;
}

void WebGLRenderingContextBase::FinalizeFrame(FlushReason) {
  if (Host()->LowLatencyEnabled()) {
    // PaintRenderingResultsToCanvas will export drawing buffer if the resource
    // provider is single buffered.  Otherwise it will copy the drawing buffer.
    PaintRenderingResultsToCanvas(kBackBuffer);
  }
  marked_canvas_dirty_ = false;
}

void WebGLRenderingContextBase::OnErrorMessage(const char* message,
                                               int32_t id) {
  if (synthesized_errors_to_console_)
    PrintGLErrorToConsole(message);
  NotifyWebGLErrorOrWarning(message);
}

WebGLRenderingContextBase::HowToClear
WebGLRenderingContextBase::ClearIfComposited(
    WebGLRenderingContextBase::ClearCaller caller,
    GLbitfield mask) {
  if (isContextLost())
    return kSkipped;

  if (!GetDrawingBuffer()->BufferClearNeeded() ||
      (mask && framebuffer_binding_) ||
      (rasterizer_discard_enabled_ && caller == kClearCallerDrawOrClear))
    return kSkipped;

  if (isContextLost()) {
    // Unlik
```