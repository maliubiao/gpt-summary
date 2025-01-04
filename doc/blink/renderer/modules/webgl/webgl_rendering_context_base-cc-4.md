Response:
The user wants to understand the functionality of the `webgl_rendering_context_base.cc` file in the Chromium Blink engine, focusing on its interactions with JavaScript, HTML, and CSS. The user also requests examples of logic, common user errors, debugging steps, and a summary of the provided code snippet. This is part 5 of 11.

**Plan:**

1. **General Functionality:** Based on the file name and content, the primary function is to manage the core state and operations of a WebGL rendering context. It handles getting various parameters and states related to WebGL.

2. **JavaScript Interaction:**  The `getParameter`, `getProgramParameter`, `getShaderParameter`, `getRenderbufferParameter`, `getTexParameter`, and `getUniform` methods are directly called from JavaScript WebGL API calls.

3. **HTML/CSS Interaction:**  While this file doesn't directly manipulate HTML or CSS, the WebGL context it manages is rendered onto a `<canvas>` element in HTML. The size and potentially other style properties of the canvas can influence the WebGL rendering.

4. **Logic and Examples:** Focus on the `getParameter` function's switch statement, illustrating how different `GLenum` values trigger different underlying OpenGL calls and data retrieval.

5. **User Errors:** Highlight common mistakes when calling `getParameter` or related functions with invalid `GLenum` values or on a lost context.

6. **Debugging:** Describe how a developer might end up investigating this file, likely starting from a JavaScript WebGL call that isn't behaving as expected.

7. **Snippet Summary:** Summarize the functionality of the provided code block, noting its role in retrieving and managing various WebGL parameters, and its involvement in experiments by recording identifiable parameters.

**Mental Sandbox:**

*   Consider a JavaScript call like `gl.getParameter(gl.MAX_TEXTURE_SIZE)`. This file's `getParameter` function will handle this, fetching the corresponding OpenGL value.
*   Think about what happens if a user calls `gl.getParameter(9999)` (an invalid enum). The code should handle this and potentially generate an error.
*   Imagine a developer seeing unexpected rendering results. They might start debugging by inspecting the values returned by `gl.getParameter` to understand the current WebGL state.

**Key Observations from the Code Snippet:**

*   The code defines a set of `kIdentifiableGLParams` for an identifiability study.
*   It includes functions like `RecordIdentifiableGLParameterDigest` and `RecordShaderPrecisionFormatForStudy`, suggesting data collection for experiments.
*   The `getParameter` function uses a large switch statement to handle different `GLenum` values.
*   Error handling (using `SynthesizeGLError`) is present for invalid parameters.
*   Extension support is checked before accessing certain parameters.

By focusing on these aspects, I can create a comprehensive answer that addresses all parts of the user's query.
这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第 5 部分，主要功能是实现 WebGL 上下文对象的 `getParameter`、`getProgramParameter`、`getShaderParameter`、`getRenderbufferParameter`、`getTexParameter` 和 `getUniform` 等方法。这些方法允许 JavaScript 代码查询当前 WebGL 上下文的状态、程序、着色器、渲染缓冲区、纹理和 uniform 变量的信息。

**功能归纳：**

这部分代码主要负责实现 WebGL 上下文的各种“getter”方法，用于检索 WebGL 的状态信息。它包含了：

*   **获取各种 WebGL 参数：** `getParameter` 方法实现了获取各种 WebGL 上下文参数的功能，例如当前绑定的缓冲区、启用的特性、支持的纹理大小、视口尺寸等等。它通过一个大的 `switch` 语句，根据传入的 `pname` (parameter name) 来调用相应的底层 OpenGL ES 函数或者返回缓存的状态。
*   **获取程序对象参数：** `getProgramParameter` 方法用于获取 WebGLProgram 对象的特定参数，例如链接状态、删除状态、激活的 uniform 变量数量等。
*   **获取着色器对象参数：** `getShaderParameter` 方法用于获取 WebGLShader 对象的特定参数，例如编译状态、删除状态、着色器类型等。
*   **获取渲染缓冲区对象参数：** `getRenderbufferParameter` 方法用于获取 WebGLRenderbuffer 对象的特定参数，例如宽度、高度、内部格式等。
*   **获取纹理对象参数：** `getTexParameter` 方法用于获取 WebGLTexture 对象的特定参数，例如放大/缩小滤波器、纹理环绕模式等。
*   **获取 Uniform 变量的值：** `getUniform` 方法用于获取 WebGLProgram 中指定 uniform 变量的当前值。

**与 JavaScript, HTML, CSS 的关系：**

这些方法是 WebGL API 的一部分，直接暴露给 JavaScript。

*   **JavaScript:**  JavaScript 代码通过调用这些方法来获取 WebGL 的状态信息，例如：
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const gl = canvas.getContext('webgl');

    const maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    console.log('Max texture size:', maxTextureSize);

    const program = gl.createProgram();
    // ... attach and link shaders ...
    const linkStatus = gl.getProgramParameter(program, gl.LINK_STATUS);
    console.log('Program link status:', linkStatus);

    const vertexShader = gl.createShader(gl.VERTEX_SHADER);
    // ... shader source ...
    gl.compileShader(vertexShader);
    const compileStatus = gl.getShaderParameter(vertexShader, gl.COMPILE_STATUS);
    console.log('Vertex shader compile status:', compileStatus);
    ```
*   **HTML:**  WebGL 的渲染结果会显示在 HTML 的 `<canvas>` 元素上。JavaScript 代码需要先获取 `<canvas>` 元素，然后通过 `getContext('webgl')` 或 `getContext('webgl2')` 来获取 WebGLRenderingContext 或 WebGL2RenderingContext 对象，才能调用这些 `getParameter` 等方法。
*   **CSS:** CSS 可以控制 `<canvas>` 元素的样式，例如大小、边框等。虽然 CSS 不直接影响这些 `getParameter` 方法返回的 WebGL 内部状态，但 canvas 的尺寸可能会影响一些 WebGL 参数，例如视口尺寸。

**逻辑推理与假设输入输出：**

**假设输入（getParameter）：**  `gl.getParameter(gl.BLEND_SRC_ALPHA)`

**逻辑推理：**  `getParameter` 方法中的 `switch` 语句会匹配到 `GL_BLEND_SRC_ALPHA` 这个 `pname`。然后，它会调用 `GetUnsignedIntParameter(script_state, pname)`，最终会从底层的 OpenGL ES 驱动获取当前混合模式的源 alpha 通道参数，并将其封装成 JavaScript 可以理解的值返回。

**假设输出：**  假设当前 WebGL 上下文的混合源 alpha 通道设置为 `GL_ONE_MINUS_SRC_ALPHA`，则该方法会返回对应的数值 (例如 0x0303)。

**假设输入（getProgramParameter）：**  `gl.getProgramParameter(program, gl.LINK_STATUS)`

**逻辑推理：** `getProgramParameter` 方法会检查 `program` 的有效性。然后，`switch` 语句会匹配到 `GL_LINK_STATUS`。如果程序已经链接，它会返回程序对象的链接状态，这个状态可能由 Blink 引擎缓存，或者需要调用底层的 OpenGL ES 函数 `ContextGL()->GetProgramiv()` 获取。

**假设输出：** 如果程序链接成功，返回 `true`，否则返回 `false`。

**用户或编程常见的使用错误：**

*   **使用无效的 `pname` 值：**
    ```javascript
    const invalidParam = gl.getParameter(9999); // 9999 不是一个有效的 GLenum
    console.log(invalidParam); // 通常会返回 null 或抛出错误
    ```
    **说明：** 调用 `getParameter` 时，如果传入的 `pname` 不是 WebGL 标准定义的常量，WebGL 上下文会产生 `GL_INVALID_ENUM` 错误，并可能返回 `null`。文件中可以看到 `SynthesizeGLError` 函数用于处理这类错误。
*   **在上下文丢失后调用这些方法：**
    ```javascript
    canvas.addEventListener('webglcontextlost', function(event) {
      event.preventDefault();
      console.log(gl.getParameter(gl.MAX_TEXTURE_SIZE)); // 上下文已丢失
    }, false);
    ```
    **说明：** 当 WebGL 上下文丢失（例如由于 GPU 错误或用户操作）后，调用这些方法通常会返回默认值（例如 `null`）或某些特定的值（例如 `getProgramParameter` 中 `GL_COMPLETION_STATUS_KHR` 在上下文丢失时会返回 `true`，防止无限轮询）。
*   **在错误的对象上调用方法：**
    ```javascript
    const texture = gl.createTexture();
    gl.getProgramParameter(texture, gl.LINK_STATUS); // 纹理对象不能调用 getProgramParameter
    ```
    **说明：** 尝试在不适用的 WebGL 对象上调用相应的方法会导致 `GL_INVALID_VALUE` 或 `GL_INVALID_OPERATION` 错误。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中打开一个使用了 WebGL 的网页。**
2. **网页的 JavaScript 代码获取了 WebGL 上下文。**
3. **JavaScript 代码调用了 `gl.getParameter(gl.MAX_TEXTURE_SIZE)` 或其他类似的 `getParameter` 方法。**
4. **浏览器引擎接收到这个 JavaScript 调用，并将其路由到 Blink 引擎的 WebGL 实现。**
5. **`WebGLRenderingContextBase::getParameter` 方法被调用。**
6. **`getParameter` 方法根据传入的 `GLenum` 值，执行相应的逻辑，可能需要调用底层的 OpenGL ES 驱动。**
7. **获取到的参数值被返回给 JavaScript 代码。**

**调试线索：**

当开发者遇到与 WebGL 状态相关的问题时，他们可能会使用 `console.log` 打印这些 `getParameter` 方法的返回值来检查当前的 WebGL 状态。例如：

*   如果纹理显示异常，开发者可能会检查 `gl.getParameter(gl.MAX_TEXTURE_SIZE)` 来确认支持的最大纹理尺寸。
*   如果程序链接失败，开发者可能会检查 `gl.getProgramParameter(program, gl.LINK_STATUS)` 和 `gl.getProgramInfoLog(program)` 来获取链接错误信息。
*   如果着色器编译失败，开发者可能会检查 `gl.getShaderParameter(shader, gl.COMPILE_STATUS)` 和 `gl.getShaderInfoLog(shader)` 来获取编译错误信息。

通过在 JavaScript 代码中插入断点或者使用浏览器的开发者工具，开发者可以逐步执行代码，观察这些 `getParameter` 方法的返回值，从而定位问题。如果怀疑是 Blink 引擎的实现问题，他们可能会深入到 Blink 的源代码中，查看 `webgl_rendering_context_base.cc` 文件中这些方法的实现细节。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共11部分，请归纳一下它的功能

"""
ter
    GL_GREEN_BITS,                        // GetIntParameter
    GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS,  // GetIntParameter
    GL_MAX_CUBE_MAP_TEXTURE_SIZE,         // GetIntParameter
    GL_MAX_FRAGMENT_UNIFORM_VECTORS,      // GetIntParameter
    GL_MAX_RENDERBUFFER_SIZE,             // GetIntParameter
    GL_MAX_TEXTURE_IMAGE_UNITS,           // GetIntParameter
    GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT,    // GetFloatParameter
    GL_MAX_TEXTURE_SIZE,                  // GetIntParameter
    GL_MAX_VARYING_VECTORS,               // GetIntParameter
    GL_MAX_VERTEX_ATTRIBS,                // GetIntParameter
    GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS,    // GetIntParameter
    GL_MAX_VERTEX_UNIFORM_VECTORS,        // GetIntParameter
    GL_MAX_VIEWPORT_DIMS,                 // GetWebGLIntArrayParameter
    GL_RED_BITS,                          // GetIntParameter
    GL_SHADING_LANGUAGE_VERSION,
    GL_STENCIL_BITS,  // GetIntParameter
    GL_VERSION,
    WebGLDebugRendererInfo::kUnmaskedRendererWebgl,
    WebGLDebugRendererInfo::kUnmaskedVendorWebgl,

    // getRenderBufferParameter()
    GL_RENDERBUFFER_GREEN_SIZE,
    GL_RENDERBUFFER_BLUE_SIZE,
    GL_RENDERBUFFER_RED_SIZE,
    GL_RENDERBUFFER_ALPHA_SIZE,
    GL_RENDERBUFFER_DEPTH_SIZE,
    GL_RENDERBUFFER_STENCIL_SIZE,
    GL_RENDERBUFFER_SAMPLES,
};

bool ShouldMeasureGLParam(GLenum pname) {
  return IdentifiabilityStudySettings::Get()->ShouldSampleType(
             blink::IdentifiableSurface::Type::kWebGLParameter) &&
         base::Contains(kIdentifiableGLParams, pname);
}

}  // namespace

void WebGLRenderingContextBase::RecordIdentifiableGLParameterDigest(
    GLenum pname,
    IdentifiableToken value) {
  DCHECK(IdentifiabilityStudySettings::Get()->ShouldSampleType(
      blink::IdentifiableSurface::Type::kWebGLParameter));
  const auto ukm_params = GetUkmParameters();
  blink::IdentifiabilityMetricBuilder(ukm_params.source_id)
      .Add(blink::IdentifiableSurface::FromTypeAndToken(
               blink::IdentifiableSurface::Type::kWebGLParameter, pname),
           value)
      .Record(ukm_params.ukm_recorder);
}

void WebGLRenderingContextBase::RecordShaderPrecisionFormatForStudy(
    GLenum shader_type,
    GLenum precision_type,
    WebGLShaderPrecisionFormat* format) {
  DCHECK(IdentifiabilityStudySettings::Get()->ShouldSampleType(
      blink::IdentifiableSurface::Type::kWebGLShaderPrecisionFormat));

  const auto& ukm_params = GetUkmParameters();
  IdentifiableTokenBuilder builder;
  auto surface_token =
      builder.AddValue(shader_type).AddValue(precision_type).GetToken();
  auto sample_token = builder.AddValue(format->rangeMin())
                          .AddValue(format->rangeMax())
                          .AddValue(format->precision())
                          .GetToken();

  blink::IdentifiabilityMetricBuilder(ukm_params.source_id)
      .Add(blink::IdentifiableSurface::FromTypeAndToken(
               blink::IdentifiableSurface::Type::kWebGLShaderPrecisionFormat,
               surface_token),
           sample_token)
      .Record(ukm_params.ukm_recorder);
}

void WebGLRenderingContextBase::RecordANGLEImplementation() {
  DCHECK(drawing_buffer_.get());
  const Platform::GraphicsInfo& graphics_info =
      drawing_buffer_->GetGraphicsInfo();
  // For mapping mathematics, see WebGLANGLEImplementation definition above.
  int webgl_version_multiplier =
      (context_type_ == Platform::kWebGL2ContextType ? 2 : 0);
  WebGLANGLEImplementation webgl_angle_implementation =
      static_cast<WebGLANGLEImplementation>(
          webgl_version_multiplier * 10 +
          static_cast<int>(graphics_info.angle_implementation));
  UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.WebGLANGLEImplementation",
                            webgl_angle_implementation);
}

ScriptValue WebGLRenderingContextBase::getParameter(ScriptState* script_state,
                                                    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());
  const int kIntZero = 0;
  switch (pname) {
    case GL_ACTIVE_TEXTURE:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_ALIASED_LINE_WIDTH_RANGE:
      return GetWebGLFloatArrayParameter(script_state, pname);
    case GL_ALIASED_POINT_SIZE_RANGE:
      return GetWebGLFloatArrayParameter(script_state, pname);
    case GL_ALPHA_BITS:
      if (drawing_buffer_->RequiresAlphaChannelToBePreserved())
        return WebGLAny(script_state, 0);
      return GetIntParameter(script_state, pname);
    case GL_ARRAY_BUFFER_BINDING:
      return WebGLAny(script_state, bound_array_buffer_.Get());
    case GL_BLEND:
      return GetBooleanParameter(script_state, pname);
    case GL_BLEND_COLOR:
      return GetWebGLFloatArrayParameter(script_state, pname);
    case GL_BLEND_DST_ALPHA:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLEND_DST_RGB:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLEND_EQUATION_ALPHA:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLEND_EQUATION_RGB:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLEND_SRC_ALPHA:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLEND_SRC_RGB:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_BLUE_BITS:
      return GetIntParameter(script_state, pname);
    case GL_COLOR_CLEAR_VALUE:
      return GetWebGLFloatArrayParameter(script_state, pname);
    case GL_COLOR_WRITEMASK:
      return GetBooleanArrayParameter(script_state, pname);
    case GL_COMPRESSED_TEXTURE_FORMATS:
      return WebGLAny(script_state,
                      DOMUint32Array::Create(compressed_texture_formats_));
    case GL_CULL_FACE:
      return GetBooleanParameter(script_state, pname);
    case GL_CULL_FACE_MODE:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_CURRENT_PROGRAM:
      return WebGLAny(script_state, current_program_.Get());
    case GL_DEPTH_BITS:
      if (!framebuffer_binding_ && !CreationAttributes().depth)
        return WebGLAny(script_state, kIntZero);
      return GetIntParameter(script_state, pname);
    case GL_DEPTH_CLEAR_VALUE:
      return GetFloatParameter(script_state, pname);
    case GL_DEPTH_FUNC:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_DEPTH_RANGE:
      return GetWebGLFloatArrayParameter(script_state, pname);
    case GL_DEPTH_TEST:
      return WebGLAny(script_state, depth_enabled_);
    case GL_DEPTH_WRITEMASK:
      return GetBooleanParameter(script_state, pname);
    case GL_DITHER:
      return GetBooleanParameter(script_state, pname);
    case GL_ELEMENT_ARRAY_BUFFER_BINDING:
      return WebGLAny(script_state,
                      bound_vertex_array_object_->BoundElementArrayBuffer());
    case GL_FRAMEBUFFER_BINDING:
      return WebGLAny(script_state, framebuffer_binding_.Get());
    case GL_FRONT_FACE:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_GENERATE_MIPMAP_HINT:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_GREEN_BITS:
      return GetIntParameter(script_state, pname);
    case GL_IMPLEMENTATION_COLOR_READ_FORMAT:
      return GetIntParameter(script_state, pname);
    case GL_IMPLEMENTATION_COLOR_READ_TYPE:
      return GetIntParameter(script_state, pname);
    case GL_LINE_WIDTH:
      return GetFloatParameter(script_state, pname);
    case GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_CUBE_MAP_TEXTURE_SIZE:
      return GetIntParameter(script_state, pname);
    case GL_MAX_FRAGMENT_UNIFORM_VECTORS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_RENDERBUFFER_SIZE:
      return GetIntParameter(script_state, pname);
    case GL_MAX_TEXTURE_IMAGE_UNITS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_TEXTURE_SIZE:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VARYING_VECTORS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_ATTRIBS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_UNIFORM_VECTORS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VIEWPORT_DIMS:
      return GetWebGLIntArrayParameter(script_state, pname);
    case GL_NUM_SHADER_BINARY_FORMATS:
      // FIXME: should we always return 0 for this?
      return GetIntParameter(script_state, pname);
    case GL_PACK_ALIGNMENT:
      return GetIntParameter(script_state, pname);
    case GL_POLYGON_OFFSET_FACTOR:
      return GetFloatParameter(script_state, pname);
    case GL_POLYGON_OFFSET_FILL:
      return GetBooleanParameter(script_state, pname);
    case GL_POLYGON_OFFSET_UNITS:
      return GetFloatParameter(script_state, pname);
    case GL_RED_BITS:
      return GetIntParameter(script_state, pname);
    case GL_RENDERBUFFER_BINDING:
      return WebGLAny(script_state, renderbuffer_binding_.Get());
    case GL_RENDERER:
      return WebGLAny(script_state, String("WebKit WebGL"));
    case GL_SAMPLE_ALPHA_TO_COVERAGE:
      return GetBooleanParameter(script_state, pname);
    case GL_SAMPLE_BUFFERS:
      return GetIntParameter(script_state, pname);
    case GL_SAMPLE_COVERAGE:
      return GetBooleanParameter(script_state, pname);
    case GL_SAMPLE_COVERAGE_INVERT:
      return GetBooleanParameter(script_state, pname);
    case GL_SAMPLE_COVERAGE_VALUE:
      return GetFloatParameter(script_state, pname);
    case GL_SAMPLES:
      return GetIntParameter(script_state, pname);
    case GL_SCISSOR_BOX:
      return GetWebGLIntArrayParameter(script_state, pname);
    case GL_SCISSOR_TEST:
      return GetBooleanParameter(script_state, pname);
    case GL_SHADING_LANGUAGE_VERSION:
      if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
              blink::IdentifiableSurface::Type::kWebGLParameter)) {
        RecordIdentifiableGLParameterDigest(
            pname, IdentifiabilityBenignStringToken(String(
                       ContextGL()->GetString(GL_SHADING_LANGUAGE_VERSION))));
      }
      return WebGLAny(
          script_state,
          "WebGL GLSL ES 1.0 (" +
              String(ContextGL()->GetString(GL_SHADING_LANGUAGE_VERSION)) +
              ")");
    case GL_STENCIL_BACK_FAIL:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BACK_FUNC:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BACK_PASS_DEPTH_FAIL:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BACK_PASS_DEPTH_PASS:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BACK_REF:
      return GetIntParameter(script_state, pname);
    case GL_STENCIL_BACK_VALUE_MASK:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BACK_WRITEMASK:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_BITS:
      if (!framebuffer_binding_ && !CreationAttributes().stencil)
        return WebGLAny(script_state, kIntZero);
      return GetIntParameter(script_state, pname);
    case GL_STENCIL_CLEAR_VALUE:
      return GetIntParameter(script_state, pname);
    case GL_STENCIL_FAIL:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_FUNC:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_PASS_DEPTH_FAIL:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_PASS_DEPTH_PASS:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_REF:
      return GetIntParameter(script_state, pname);
    case GL_STENCIL_TEST:
      return WebGLAny(script_state, stencil_enabled_);
    case GL_STENCIL_VALUE_MASK:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_STENCIL_WRITEMASK:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_SUBPIXEL_BITS:
      return GetIntParameter(script_state, pname);
    case GL_TEXTURE_BINDING_2D:
      return WebGLAny(
          script_state,
          texture_units_[active_texture_unit_].texture2d_binding_.Get());
    case GL_TEXTURE_BINDING_CUBE_MAP:
      return WebGLAny(
          script_state,
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get());
    case GL_UNPACK_ALIGNMENT:
      return GetIntParameter(script_state, pname);
    case GC3D_UNPACK_FLIP_Y_WEBGL:
      return WebGLAny(script_state, unpack_flip_y_);
    case GC3D_UNPACK_PREMULTIPLY_ALPHA_WEBGL:
      return WebGLAny(script_state, unpack_premultiply_alpha_);
    case GC3D_UNPACK_COLORSPACE_CONVERSION_WEBGL:
      return WebGLAny(script_state, unpack_colorspace_conversion_);
    case GL_VENDOR:
      return WebGLAny(script_state, String("WebKit"));
    case GL_VERSION:
      if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
              blink::IdentifiableSurface::Type::kWebGLParameter)) {
        RecordIdentifiableGLParameterDigest(
            pname, IdentifiabilityBenignStringToken(
                       String(ContextGL()->GetString(GL_VERSION))));
      }
      return WebGLAny(
          script_state,
          "WebGL 1.0 (" + String(ContextGL()->GetString(GL_VERSION)) + ")");
    case GL_VIEWPORT:
      return GetWebGLIntArrayParameter(script_state, pname);
    case GL_FRAGMENT_SHADER_DERIVATIVE_HINT_OES:  // OES_standard_derivatives
      if (ExtensionEnabled(kOESStandardDerivativesName) || IsWebGL2())
        return GetUnsignedIntParameter(script_state,
                                       GL_FRAGMENT_SHADER_DERIVATIVE_HINT_OES);
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, OES_standard_derivatives not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case WebGLDebugRendererInfo::kUnmaskedRendererWebgl:
      if (ExtensionEnabled(kWebGLDebugRendererInfoName)) {
        if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
                blink::IdentifiableSurface::Type::kWebGLParameter)) {
          RecordIdentifiableGLParameterDigest(
              pname, IdentifiabilityBenignStringToken(
                         String(ContextGL()->GetString(GL_RENDERER))));
        }
        return WebGLAny(script_state,
                        String(ContextGL()->GetString(GL_RENDERER)));
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_debug_renderer_info not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case WebGLDebugRendererInfo::kUnmaskedVendorWebgl:
      if (ExtensionEnabled(kWebGLDebugRendererInfoName)) {
        if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
                blink::IdentifiableSurface::Type::kWebGLParameter)) {
          RecordIdentifiableGLParameterDigest(
              pname, IdentifiabilityBenignStringToken(
                         String(ContextGL()->GetString(GL_VENDOR))));
        }
        return WebGLAny(script_state,
                        String(ContextGL()->GetString(GL_VENDOR)));
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_debug_renderer_info not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_VERTEX_ARRAY_BINDING_OES:  // OES_vertex_array_object
      if (ExtensionEnabled(kOESVertexArrayObjectName) || IsWebGL2()) {
        if (!bound_vertex_array_object_->IsDefaultObject())
          return WebGLAny(script_state, bound_vertex_array_object_.Get());
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, OES_vertex_array_object not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT:  // EXT_texture_filter_anisotropic
      if (ExtensionEnabled(kEXTTextureFilterAnisotropicName)) {
        return GetFloatParameter(script_state,
                                 GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, EXT_texture_filter_anisotropic not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_DEPTH_CLAMP_EXT:  // EXT_depth_clamp
      if (ExtensionEnabled(kEXTDepthClampName)) {
        return GetBooleanParameter(script_state, pname);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, EXT_depth_clamp not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_POLYGON_MODE_ANGLE:  // WEBGL_polygon_mode
    case GL_POLYGON_OFFSET_LINE_ANGLE:
      if (ExtensionEnabled(kWebGLPolygonModeName)) {
        if (pname == GL_POLYGON_OFFSET_LINE_ANGLE) {
          return GetBooleanParameter(script_state, pname);
        }
        return GetUnsignedIntParameter(script_state, pname);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_polygon_mode not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_POLYGON_OFFSET_CLAMP_EXT:  // EXT_polygon_offset_clamp
      if (ExtensionEnabled(kEXTPolygonOffsetClampName)) {
        return GetFloatParameter(script_state, pname);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, EXT_polygon_offset_clamp not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_CLIP_ORIGIN_EXT:  // EXT_clip_control
    case GL_CLIP_DEPTH_MODE_EXT:
      if (ExtensionEnabled(kEXTClipControlName)) {
        return GetUnsignedIntParameter(script_state, pname);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, EXT_clip_control not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_DUAL_SOURCE_DRAW_BUFFERS_EXT:  // WEBGL_blend_func_extended
      if (ExtensionEnabled(kWebGLBlendFuncExtendedName)) {
        return GetUnsignedIntParameter(script_state, pname);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_blend_func_extended not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_COLOR_ATTACHMENTS_EXT:  // EXT_draw_buffers BEGIN
      if (ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2())
        return WebGLAny(script_state, MaxColorAttachments());
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_draw_buffers not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_DRAW_BUFFERS_EXT:
      if (ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2())
        return WebGLAny(script_state, MaxDrawBuffers());
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, WEBGL_draw_buffers not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_TIMESTAMP_EXT:
      if (ExtensionEnabled(kEXTDisjointTimerQueryName))
        return WebGLAny(script_state, 0);
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, EXT_disjoint_timer_query not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_GPU_DISJOINT_EXT:
      if (ExtensionEnabled(kEXTDisjointTimerQueryName))
        return GetBooleanParameter(script_state, GL_GPU_DISJOINT_EXT);
      SynthesizeGLError(
          GL_INVALID_ENUM, "getParameter",
          "invalid parameter name, EXT_disjoint_timer_query not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_VIEWS_OVR:
      if (ExtensionEnabled(kOVRMultiview2Name))
        return GetIntParameter(script_state, pname);
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, OVR_multiview2 not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    default:
      if ((ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2()) &&
          pname >= GL_DRAW_BUFFER0_EXT &&
          pname < static_cast<GLenum>(GL_DRAW_BUFFER0_EXT + MaxDrawBuffers())) {
        GLint value = GL_NONE;
        if (framebuffer_binding_)
          value = framebuffer_binding_->GetDrawBuffer(pname);
        else  // emulated backbuffer
          value = back_draw_buffer_;
        return WebGLAny(script_state, value);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

ScriptValue WebGLRenderingContextBase::getProgramParameter(
    ScriptState* script_state,
    WebGLProgram* program,
    GLenum pname) {
  // Completion status queries always return true on a lost context. This is
  // intended to prevent applications from entering an infinite polling loop.
  if (isContextLost() && pname == GL_COMPLETION_STATUS_KHR)
    return WebGLAny(script_state, true);
  if (!ValidateWebGLProgramOrShader("getProgramParamter", program)) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  GLint value = 0;
  switch (pname) {
    case GL_DELETE_STATUS:
      return WebGLAny(script_state, program->MarkedForDeletion());
    case GL_VALIDATE_STATUS:
      ContextGL()->GetProgramiv(ObjectOrZero(program), pname, &value);
      return WebGLAny(script_state, static_cast<bool>(value));
    case GL_LINK_STATUS:
      return WebGLAny(script_state, program->LinkStatus(this));
    case GL_COMPLETION_STATUS_KHR:
      if (!ExtensionEnabled(kKHRParallelShaderCompileName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getProgramParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      bool completed;
      if (checkProgramCompletionQueryAvailable(program, &completed)) {
        return WebGLAny(script_state, completed);
      }
      return WebGLAny(script_state, program->CompletionStatus(this));
    case GL_ACTIVE_UNIFORM_BLOCKS:
    case GL_TRANSFORM_FEEDBACK_VARYINGS:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, "getProgramParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      [[fallthrough]];
    case GL_ATTACHED_SHADERS:
    case GL_ACTIVE_ATTRIBUTES:
    case GL_ACTIVE_UNIFORMS:
      ContextGL()->GetProgramiv(ObjectOrZero(program), pname, &value);
      return WebGLAny(script_state, value);
    case GL_TRANSFORM_FEEDBACK_BUFFER_MODE:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, "getProgramParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      ContextGL()->GetProgramiv(ObjectOrZero(program), pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getProgramParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

String WebGLRenderingContextBase::getProgramInfoLog(WebGLProgram* program) {
  if (!ValidateWebGLProgramOrShader("getProgramInfoLog", program))
    return String();
  GLStringQuery query(ContextGL());
  return query.Run<GLStringQuery::ProgramInfoLog>(ObjectNonZero(program));
}

ScriptValue WebGLRenderingContextBase::getRenderbufferParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());
  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "getRenderbufferParameter",
                      "invalid target");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  if (!renderbuffer_binding_ || !renderbuffer_binding_->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getRenderbufferParameter",
                      "no renderbuffer bound");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  GLint value = 0;
  switch (pname) {
    case GL_RENDERBUFFER_SAMPLES:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, "getRenderbufferParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      [[fallthrough]];
    case GL_RENDERBUFFER_WIDTH:
    case GL_RENDERBUFFER_HEIGHT:
    case GL_RENDERBUFFER_RED_SIZE:
    case GL_RENDERBUFFER_GREEN_SIZE:
    case GL_RENDERBUFFER_BLUE_SIZE:
    case GL_RENDERBUFFER_ALPHA_SIZE:
    case GL_RENDERBUFFER_DEPTH_SIZE:
    case GL_RENDERBUFFER_STENCIL_SIZE:
      ContextGL()->GetRenderbufferParameteriv(target, pname, &value);
      if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
              blink::IdentifiableSurface::Type::kWebGLParameter)) {
        RecordIdentifiableGLParameterDigest(pname, value);
      }
      return WebGLAny(script_state, value);
    case GL_RENDERBUFFER_INTERNAL_FORMAT:
      return WebGLAny(script_state, renderbuffer_binding_->InternalFormat());
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getRenderbufferParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

ScriptValue WebGLRenderingContextBase::getShaderParameter(
    ScriptState* script_state,
    WebGLShader* shader,
    GLenum pname) {
  // Completion status queries always return true on a lost context. This is
  // intended to prevent applications from entering an infinite polling loop.
  if (isContextLost() && pname == GL_COMPLETION_STATUS_KHR)
    return WebGLAny(script_state, true);
  if (!ValidateWebGLProgramOrShader("getShaderParameter", shader)) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  GLint value = 0;
  switch (pname) {
    case GL_DELETE_STATUS:
      return WebGLAny(script_state, shader->MarkedForDeletion());
    case GL_COMPILE_STATUS:
      ContextGL()->GetShaderiv(ObjectOrZero(shader), pname, &value);
      return WebGLAny(script_state, static_cast<bool>(value));
    case GL_COMPLETION_STATUS_KHR:
      if (!ExtensionEnabled(kKHRParallelShaderCompileName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "getShaderParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      ContextGL()->GetShaderiv(ObjectOrZero(shader), pname, &value);
      return WebGLAny(script_state, static_cast<bool>(value));
    case GL_SHADER_TYPE:
      ContextGL()->GetShaderiv(ObjectOrZero(shader), pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getShaderParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

String WebGLRenderingContextBase::getShaderInfoLog(WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("getShaderInfoLog", shader))
    return String();
  GLStringQuery query(ContextGL());
  return query.Run<GLStringQuery::ShaderInfoLog>(ObjectNonZero(shader));
}

WebGLShaderPrecisionFormat* WebGLRenderingContextBase::getShaderPrecisionFormat(
    GLenum shader_type,
    GLenum precision_type) {
  if (isContextLost())
    return nullptr;
  if (!ValidateShaderType("getShaderPrecisionFormat", shader_type)) {
    return nullptr;
  }
  switch (precision_type) {
    case GL_LOW_FLOAT:
    case GL_MEDIUM_FLOAT:
    case GL_HIGH_FLOAT:
    case GL_LOW_INT:
    case GL_MEDIUM_INT:
    case GL_HIGH_INT:
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getShaderPrecisionFormat",
                        "invalid precision type");
      return nullptr;
  }

  GLint range[2] = {0, 0};
  GLint precision = 0;
  ContextGL()->GetShaderPrecisionFormat(shader_type, precision_type, range,
                                        &precision);
  auto* result = MakeGarbageCollected<WebGLShaderPrecisionFormat>(
      range[0], range[1], precision);
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kWebGLShaderPrecisionFormat)) {
    RecordShaderPrecisionFormatForStudy(shader_type, precision_type, result);
  }
  return result;
}

String WebGLRenderingContextBase::getShaderSource(WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("getShaderSource", shader))
    return String();
  return EnsureNotNull(shader->Source());
}

std::optional<Vector<String>>
WebGLRenderingContextBase::getSupportedExtensions() {
  if (isContextLost())
    return std::nullopt;

  Vector<String> result;

  for (ExtensionTracker* tracker : extensions_) {
    if (ExtensionSupportedAndAllowed(tracker)) {
      result.push_back(tracker->ExtensionName());
    }
  }

  return result;
}

ScriptValue WebGLRenderingContextBase::getTexParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());
  if (!ValidateTextureBinding("getTexParameter", target))
    return ScriptValue::CreateNull(script_state->GetIsolate());
  switch (pname) {
    case GL_TEXTURE_MAG_FILTER:
    case GL_TEXTURE_MIN_FILTER:
    case GL_TEXTURE_WRAP_S:
    case GL_TEXTURE_WRAP_T: {
      GLint value = 0;
      ContextGL()->GetTexParameteriv(target, pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    case GL_TEXTURE_MAX_ANISOTROPY_EXT:  // EXT_texture_filter_anisotropic
      if (ExtensionEnabled(kEXTTextureFilterAnisotropicName)) {
        GLfloat value = 0.f;
        ContextGL()->GetTexParameterfv(target, pname, &value);
        return WebGLAny(script_state, value);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getTexParameter",
          "invalid parameter name, EXT_texture_filter_anisotropic not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getTexParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

ScriptValue WebGLRenderingContextBase::getUniform(
    ScriptState* script_state,
    WebGLProgram* program,
    const WebGLUniformLocation* uniform_location) {
  if (!ValidateWebGLProgramOrShader("getUniform", program))
    return ScriptValue::CreateNull(script_state->GetIsolate());
  DCHECK(uniform_location);
  if (!ValidateUniformLocation("getUniform", uniform_location, program)) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  GLint location = uniform_location->Location();

  GLuint program_id = ObjectNonZero(program);
  GLint max_name_length = -1;
  ContextGL()->GetProgramiv(program_id, GL_ACTIVE_UNIFORM_MAX_LENGTH,
                            &max_name_length);
  if (max_name_length < 0)
    return ScriptValue::CreateNull(script_state->GetIsolate());
  if (max_name_length == 0) {
    SynthesizeGLError(GL_INVALID_VALUE, "getUniform",
                      "no active uniforms exist");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  // FIXME: make this more efficient using WebGLUniformLocation and caching
  // types in it.
  GLint active_uniforms = 0;
  ContextGL()->GetProgramiv(program_id, GL_ACTIVE_UNIFORMS, &active_uniforms);
  for (GLint i = 0; i < active_uniforms; i++) {
    base::span<LChar> name_buffer;
    scoped_refptr<StringImpl> name_impl =
        StringImpl::CreateUninitialized(max_name_length, name_buffer);
    GLsizei name_length = 0;
    GLint size = -1;
    GLenum type = 0;
    ContextGL()->GetActiveUniform(
        program_id, i, max_name_length, &name_length, &size, &type,
        reinterpret_cast<GLchar*>(name_buffer.data()));
    if (size < 0)
      return ScriptValue::CreateNull(script_state->GetIsolate());
    String name(name_impl->Substring(0, name_length));
    // Strip "[0]" from the name if it's an array.
    if (size > 1 && name.EndsWith("[0]"))
      name = name.Left(name.length() - 3);
    // If it's an array, we need to iterate through each element, appending
    // "[index]" to the name.
    StringBuilder name_builder;
    for (GLint index = 0; index < size; ++index) {
      name_
"""


```