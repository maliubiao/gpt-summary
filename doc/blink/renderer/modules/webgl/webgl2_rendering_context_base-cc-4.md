Response:
My thinking process to analyze the provided code snippet and answer the prompt follows these steps:

1. **Understand the Core Task:** The prompt asks for an analysis of a specific C++ source file (`webgl2_rendering_context_base.cc`) within the Chromium Blink engine. The focus is on its functionality related to WebGL2.

2. **Identify Key Code Sections:** I scan the provided code looking for distinct blocks of functionality. The `endQuery`, `getQuery`, `getQueryParameter`, `createSampler`, `deleteSampler`, `isSampler`, `bindSampler`, `SamplerParameter` (and its variations), `getSamplerParameter`, `fenceSync`, `isSync`, `deleteSync`, `clientWaitSync`, `waitSync`, `getSyncParameter`, `createTransformFeedback`, `deleteTransformFeedback`, `isTransformFeedback`, `bindTransformFeedback`, `beginTransformFeedback`, `endTransformFeedback`, `transformFeedbackVaryings`, `getTransformFeedbackVarying`, `pauseTransformFeedback`, `resumeTransformFeedback`, `bindBufferBase`, `bindBufferRange`, `getIndexedParameter`, `getUniformIndices`, `getActiveUniforms`, `getUniformBlockIndex`, and `ValidateUniformBlockIndex` function definitions clearly demarcate functional areas.

3. **Analyze Individual Function Blocks:**  For each function, I try to understand its purpose and how it interacts with the WebGL API. I look for:
    * **OpenGL Calls:**  Functions like `ContextGL()->EndQueryEXT()`, `ContextGL()->BindSampler()`, `ContextGL()->FenceSync()`, etc., indicate direct interaction with the underlying OpenGL implementation.
    * **WebGL Object Management:**  Creation (`MakeGarbageCollected<WebGLSampler>`), deletion (`DeleteObject(sampler)`), validation (`ValidateWebGLObject`), and binding of WebGL objects (samplers, queries, transform feedbacks, sync objects).
    * **Error Handling:** Calls to `SynthesizeGLError` signal potential issues and the corresponding OpenGL error codes.
    * **State Management:**  Variables like `current_boolean_occlusion_query_`, `current_transform_feedback_primitives_written_query_`, `transform_feedback_binding_`, and `sampler_units_` suggest internal state tracking.
    * **Extension Handling:**  Checks for `ExtensionEnabled()` indicate support for optional WebGL features.
    * **Script Value Interaction:**  Functions returning `ScriptValue` and taking `ScriptState*` demonstrate interaction with the JavaScript environment.

4. **Identify Relationships with JavaScript, HTML, and CSS:**
    * **JavaScript:** The core function of this code is to implement the WebGL2 API, which is directly exposed to JavaScript. Every function corresponds to a JavaScript method of the `WebGL2RenderingContext` object. For instance, the `endQuery` C++ function is called when the `endQuery()` method is invoked in JavaScript. The `ScriptValue` return type is crucial for passing data back to the JavaScript side.
    * **HTML:**  The `<canvas>` element in HTML is the host for WebGL rendering. JavaScript code running in the HTML page interacts with the WebGL context.
    * **CSS:** While CSS doesn't directly interact with the low-level WebGL functions in this file, it can influence the canvas element's size and layout, indirectly affecting the rendering.

5. **Look for Logic and Assumptions:** I analyze the conditional statements (`if`, `switch`) to understand the logic flow. I identify assumptions, such as that a query must be active before it can be ended, or that a program must be linked before querying transform feedback varyings. I consider potential inputs and the corresponding outputs (e.g., calling `endQuery` with an inactive query target will trigger a `GL_INVALID_OPERATION` error).

6. **Identify Potential User/Programming Errors:**  The frequent calls to `SynthesizeGLError` pinpoint common mistakes developers might make when using the WebGL2 API. Examples include trying to end an inactive query, binding a sampler to an out-of-range unit, or deleting an active transform feedback.

7. **Consider the User's Journey (Debugging Clues):**  I think about how a user's actions in a web page could lead to the execution of code within this file. The sequence would typically involve:
    * User opens a web page with a `<canvas>` element.
    * JavaScript code retrieves a WebGL2 rendering context.
    * JavaScript calls WebGL2 API methods (e.g., `beginQuery`, `endQuery`, `createSampler`, `bindSampler`, `beginTransformFeedback`, `drawArrays`, etc.).
    * These JavaScript calls are routed to the corresponding C++ functions in this file.
    * If errors occur, the `SynthesizeGLError` calls provide information that can be surfaced in the browser's developer console.

8. **Synthesize and Summarize:** Finally, I organize my findings into a coherent summary, addressing each part of the prompt: functionality, relationships with web technologies, logic and assumptions, common errors, and debugging clues. Since this is part 5 of 7, I focus on the functionalities present in this specific snippet and avoid repeating information from previous parts (assuming previous parts covered other aspects of the file).

By following this structured approach, I can effectively analyze the provided C++ code and generate a comprehensive and informative response to the prompt. The process involves both low-level code understanding and higher-level knowledge of how WebGL works within the browser environment.
这是提供的 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的第 5 部分，它主要负责实现 WebGL2 上下文中的以下功能，专注于**查询对象 (Queries), 采样器对象 (Samplers), 同步对象 (Sync Objects) 和转换反馈 (Transform Feedback)**：

**主要功能归纳 (基于提供的代码片段):**

1. **查询对象 (Queries):**
   - **结束查询 (`endQuery`)**: 停止特定类型的查询（例如，遮挡查询、转换反馈写入的图元数量、经过的时间）。会检查查询是否已激活，如果未激活则会生成错误。
   - **获取查询对象 (`getQuery`)**:  返回当前激活的指定类型查询对象。
   - **获取查询参数 (`getQueryParameter`)**:  获取查询对象的特定参数，例如查询结果是否可用 (`GL_QUERY_RESULT_AVAILABLE`) 或查询结果值 (`GL_QUERY_RESULT`)。会检查查询对象是否有效以及是否处于激活状态。

2. **采样器对象 (Samplers):**
   - **创建采样器 (`createSampler`)**: 创建一个新的采样器对象，用于定义纹理采样的行为。
   - **删除采样器 (`deleteSampler`)**: 删除一个采样器对象，并解除其与纹理单元的绑定。
   - **判断是否是采样器 (`isSampler`)**: 检查给定的对象是否是一个有效的采样器对象。
   - **绑定采样器 (`bindSampler`)**: 将一个采样器对象绑定到指定的纹理单元。
   - **设置采样器参数 (`samplerParameteri`, `samplerParameterf`, `SamplerParameter`)**: 设置采样器对象的各种参数，例如滤波模式、环绕模式、比较模式等。会进行参数有效性检查。
   - **获取采样器参数 (`getSamplerParameter`)**: 获取采样器对象的特定参数值。

3. **同步对象 (Sync Objects):**
   - **创建栅栏同步对象 (`fenceSync`)**:  创建一个栅栏同步对象，用于在 GPU 命令流中插入一个栅栏。CPU 可以等待这个栅栏被触发，以了解 GPU 何时完成了之前的命令。
   - **判断是否是同步对象 (`isSync`)**: 检查给定的对象是否是一个有效的同步对象。
   - **删除同步对象 (`deleteSync`)**: 删除一个同步对象。
   - **客户端等待同步 (`clientWaitSync`)**: 客户端（CPU）等待同步对象被触发，可以设置超时时间。
   - **GPU 端等待同步 (`waitSync`)**:  在 WebGL2 中被有意地设为无操作 (no-op)。
   - **获取同步对象参数 (`getSyncParameter`)**: 获取同步对象的特定参数，例如状态、条件等。

4. **转换反馈 (Transform Feedback):**
   - **创建转换反馈对象 (`createTransformFeedback`)**: 创建一个新的转换反馈对象，用于捕获顶点着色器的输出。
   - **删除转换反馈对象 (`deleteTransformFeedback`)**: 删除一个转换反馈对象。如果转换反馈对象当前处于激活状态，则会产生错误。
   - **判断是否是转换反馈对象 (`isTransformFeedback`)**: 检查给定的对象是否是一个有效的转换反馈对象。
   - **绑定转换反馈对象 (`bindTransformFeedback`)**: 绑定一个转换反馈对象，用于后续的转换反馈操作。
   - **开始转换反馈 (`beginTransformFeedback`)**: 开始记录顶点着色器的输出到绑定的缓冲区中。会检查程序是否激活、转换反馈是否已激活、以及是否有足够的缓冲区绑定。
   - **结束转换反馈 (`endTransformFeedback`)**: 停止记录顶点着色器的输出。
   - **设置转换反馈变量 (`transformFeedbackVaryings`)**:  指定顶点着色器中哪些 `out` 变量需要被记录到转换反馈缓冲区中。需要在程序链接之前调用。
   - **获取转换反馈变量信息 (`getTransformFeedbackVarying`)**: 获取指定索引的转换反馈变量的信息（名称、类型、大小）。
   - **暂停转换反馈 (`pauseTransformFeedback`)**: 暂停转换反馈的记录。
   - **恢复转换反馈 (`resumeTransformFeedback`)**: 恢复之前暂停的转换反馈记录。
   - **绑定缓冲区基 (`bindBufferBase`)**:  将缓冲区对象绑定到特定的索引绑定点，通常用于 Uniform Buffer Objects 或 Transform Feedback Buffers。
   - **绑定缓冲区范围 (`bindBufferRange`)**: 将缓冲区对象的一部分范围绑定到特定的索引绑定点。
   - **获取索引参数 (`getIndexedParameter`)**: 获取与索引绑定点相关的参数值。
   - **获取 Uniform 索引 (`getUniformIndices`)**: 获取 Uniform 变量的索引。
   - **获取激活的 Uniforms 参数 (`getActiveUniforms`)**: 获取多个 Uniform 变量的指定参数值。
   - **获取 Uniform 块索引 (`getUniformBlockIndex`)**: 获取 Uniform 块的索引。
   - **验证 Uniform 块索引 (`ValidateUniformBlockIndex`)**: 验证 Uniform 块索引的有效性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些 C++ 函数是 WebGL2 API 在 Blink 渲染引擎中的底层实现。JavaScript 代码通过 `WebGL2RenderingContext` 对象调用这些方法。

* **JavaScript:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const gl = canvas.getContext('webgl2');

    // 查询对象
    const query = gl.createQuery();
    gl.beginQuery(gl.ANY_SAMPLES_PASSED, query);
    // ... 绘制操作 ...
    gl.endQuery(gl.ANY_SAMPLES_PASSED);
    gl.getQueryParameter(query, gl.QUERY_RESULT_AVAILABLE);

    // 采样器对象
    const sampler = gl.createSampler();
    gl.samplerParameteri(sampler, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.bindSampler(0, sampler);

    // 同步对象
    const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
    gl.clientWaitSync(sync, 0, 100);

    // 转换反馈
    const tf = gl.createTransformFeedback();
    gl.bindTransformFeedback(gl.TRANSFORM_FEEDBACK, tf);
    // ... 绑定缓冲区 ...
    gl.beginTransformFeedback(gl.POINTS);
    // ... 绘制操作 ...
    gl.endTransformFeedback();
    ```
    上述 JavaScript 代码中的 `gl.createQuery()`, `gl.endQuery()`, `gl.createSampler()`, `gl.bindSampler()`, `gl.fenceSync()`, `gl.beginTransformFeedback()` 等方法调用，最终会路由到 `webgl2_rendering_context_base.cc` 中相应的 C++ 函数。

* **HTML:** HTML 中的 `<canvas>` 元素是 WebGL 内容的渲染目标。JavaScript 代码通过获取 canvas 的 WebGL2 上下文来与这些底层功能交互。

* **CSS:** CSS 可以影响 `<canvas>` 元素的样式和布局，但不会直接影响 `webgl2_rendering_context_base.cc` 中 WebGL2 API 的逻辑。

**逻辑推理、假设输入与输出:**

**假设输入 (针对 `endQuery` 函数):**

* **场景 1:**  调用 `endQuery(gl.ANY_SAMPLES_PASSED)`，且之前已经使用相同的目标 (`gl.ANY_SAMPLES_PASSED`) 调用了 `beginQuery`。
    * **假设输入:** `target = GL_ANY_SAMPLES_PASSED`, `current_boolean_occlusion_query_` 指向一个有效的查询对象，且 `current_boolean_occlusion_query_->GetTarget()` 返回 `GL_ANY_SAMPLES_PASSED`。
    * **输出:**  `current_boolean_occlusion_query_->ResetCachedResult()` 被调用，`current_boolean_occlusion_query_` 被设置为 `nullptr`，并且调用 `ContextGL()->EndQueryEXT(target)`。

* **场景 2:** 调用 `endQuery(gl.ANY_SAMPLES_PASSED)`，但之前没有使用相同的目标调用 `beginQuery`。
    * **假设输入:** `target = GL_ANY_SAMPLES_PASSED`, `current_boolean_occlusion_query_` 为 `nullptr` 或其目标与 `target` 不同。
    * **输出:** 调用 `SynthesizeGLError(GL_INVALID_OPERATION, "endQuery", "target query is not active");`，函数返回。

**用户或编程常见的使用错误举例:**

1. **尝试结束一个未开始的查询:**
   ```javascript
   const gl = canvas.getContext('webgl2');
   const query = gl.createQuery();
   gl.endQuery(gl.ANY_SAMPLES_PASSED); // 错误：没有调用 beginQuery
   ```
   这会导致 `webgl2_rendering_context_base.cc` 中的 `endQuery` 函数因为检测到查询未激活而生成 `GL_INVALID_OPERATION` 错误。

2. **在转换反馈激活时尝试删除转换反馈对象:**
   ```javascript
   const gl = canvas.getContext('webgl2');
   const tf = gl.createTransformFeedback();
   gl.bindTransformFeedback(gl.TRANSFORM_FEEDBACK, tf);
   gl.beginTransformFeedback(gl.POINTS);
   gl.deleteTransformFeedback(tf); // 错误：转换反馈正在激活
   ```
   `deleteTransformFeedback` 函数会检查转换反馈是否处于活动状态，如果是，则会生成 `GL_INVALID_OPERATION` 错误。

3. **绑定采样器到超出范围的纹理单元:**
   ```javascript
   const gl = canvas.getContext('webgl2');
   const sampler = gl.createSampler();
   gl.bindSampler(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS, sampler); // 错误：超出范围
   ```
   `bindSampler` 函数会检查纹理单元索引是否在有效范围内，超出范围会生成 `GL_INVALID_VALUE` 错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个包含 WebGL2 内容的网页。**
2. **网页的 JavaScript 代码获取了 `WebGL2RenderingContext` 对象。**
3. **JavaScript 代码调用了 WebGL2 API 中与查询对象、采样器对象、同步对象或转换反馈相关的函数，例如：**
   - `gl.beginQuery()`, `gl.endQuery()`, `gl.getQueryParameter()`
   - `gl.createSampler()`, `gl.bindSampler()`, `gl.samplerParameteri()`
   - `gl.fenceSync()`, `gl.clientWaitSync()`
   - `gl.createTransformFeedback()`, `gl.beginTransformFeedback()`, `gl.endTransformFeedback()`
4. **这些 JavaScript 方法调用会被 Blink 渲染引擎路由到 `webgl2_rendering_context_base.cc` 文件中相应的 C++ 函数。**
5. **如果在 JavaScript 代码中存在逻辑错误或不符合 WebGL2 规范的操作，例如上面列举的常见错误，那么 `webgl2_rendering_context_base.cc` 中的函数会检测到这些错误，并调用 `SynthesizeGLError()` 函数来生成相应的 OpenGL 错误。**
6. **这些错误信息会被传递回 JavaScript 环境，通常会在浏览器的开发者工具控制台中显示出来，帮助开发者进行调试。**

**总结第 5 部分的功能:**

这部分代码主要负责实现 WebGL2 中关于**查询对象 (Queries)**，**采样器对象 (Samplers)**，**同步对象 (Sync Objects)** 和 **转换反馈 (Transform Feedback)** 的核心功能。它处理了这些 WebGL2 特性的创建、删除、绑定、参数设置和状态管理，并负责在用户代码出现错误时生成相应的 OpenGL 错误，为开发者提供了使用这些高级功能的底层支持。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能

"""
TIVE: {
      if (current_boolean_occlusion_query_ &&
          current_boolean_occlusion_query_->GetTarget() == target) {
        current_boolean_occlusion_query_->ResetCachedResult();
        current_boolean_occlusion_query_ = nullptr;
      } else {
        SynthesizeGLError(GL_INVALID_OPERATION, "endQuery",
                          "target query is not active");
        return;
      }
    } break;
    case GL_TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN: {
      if (current_transform_feedback_primitives_written_query_) {
        current_transform_feedback_primitives_written_query_
            ->ResetCachedResult();
        current_transform_feedback_primitives_written_query_ = nullptr;
      } else {
        SynthesizeGLError(GL_INVALID_OPERATION, "endQuery",
                          "target query is not active");
        return;
      }
    } break;
    case GL_TIME_ELAPSED_EXT: {
      if (!ExtensionEnabled(kEXTDisjointTimerQueryWebGL2Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, "endQuery", "invalid target");
        return;
      }
      if (current_elapsed_query_) {
        current_elapsed_query_->ResetCachedResult();
        current_elapsed_query_ = nullptr;
      } else {
        SynthesizeGLError(GL_INVALID_OPERATION, "endQuery",
                          "target query is not active");
        return;
      }
    } break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "endQuery", "invalid target");
      return;
  }

  ContextGL()->EndQueryEXT(target);
}

ScriptValue WebGL2RenderingContextBase::getQuery(ScriptState* script_state,
                                                 GLenum target,
                                                 GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());

  if (ExtensionEnabled(kEXTDisjointTimerQueryWebGL2Name)) {
    if (pname == GL_QUERY_COUNTER_BITS_EXT) {
      if (target == GL_TIMESTAMP_EXT || target == GL_TIME_ELAPSED_EXT) {
        GLint value = 0;
        ContextGL()->GetQueryivEXT(target, pname, &value);
        return WebGLAny(script_state, value);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getQuery",
                        "invalid target/pname combination");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    }

    if (target == GL_TIME_ELAPSED_EXT && pname == GL_CURRENT_QUERY) {
      return current_elapsed_query_
                 ? WebGLAny(script_state, current_elapsed_query_)
                 : ScriptValue::CreateNull(script_state->GetIsolate());
    }

    if (target == GL_TIMESTAMP_EXT && pname == GL_CURRENT_QUERY) {
      return ScriptValue::CreateNull(script_state->GetIsolate());
    }
  }

  if (pname != GL_CURRENT_QUERY) {
    SynthesizeGLError(GL_INVALID_ENUM, "getQuery", "invalid parameter name");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (target) {
    case GL_ANY_SAMPLES_PASSED:
    case GL_ANY_SAMPLES_PASSED_CONSERVATIVE:
      if (current_boolean_occlusion_query_ &&
          current_boolean_occlusion_query_->GetTarget() == target)
        return WebGLAny(script_state, current_boolean_occlusion_query_);
      break;
    case GL_TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN:
      return WebGLAny(script_state,
                      current_transform_feedback_primitives_written_query_);
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getQuery", "invalid target");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  return ScriptValue::CreateNull(script_state->GetIsolate());
}

ScriptValue WebGL2RenderingContextBase::getQueryParameter(
    ScriptState* script_state,
    WebGLQuery* query,
    GLenum pname) {
  if (!ValidateWebGLObject("getQueryParameter", query))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  // Query is non-null at this point.
  if (!query->GetTarget()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getQueryParameter",
                      "'query' is not a query object yet, since it has't been "
                      "used by beginQuery");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  if (query == current_boolean_occlusion_query_ ||
      query == current_transform_feedback_primitives_written_query_ ||
      query == current_elapsed_query_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getQueryParameter",
                      "query is currently active");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  switch (pname) {
    case GL_QUERY_RESULT: {
      query->UpdateCachedResult(ContextGL());
      return WebGLAny(script_state, query->GetQueryResult());
    }
    case GL_QUERY_RESULT_AVAILABLE: {
      query->UpdateCachedResult(ContextGL());
      return WebGLAny(script_state, query->IsQueryResultAvailable());
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getQueryParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

WebGLSampler* WebGL2RenderingContextBase::createSampler() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLSampler>(this);
}

void WebGL2RenderingContextBase::deleteSampler(WebGLSampler* sampler) {
  if (isContextLost())
    return;

  for (wtf_size_t i = 0; i < sampler_units_.size(); ++i) {
    if (sampler == sampler_units_[i]) {
      sampler_units_[i] = nullptr;
      ContextGL()->BindSampler(i, 0);
    }
  }

  DeleteObject(sampler);
}

bool WebGL2RenderingContextBase::isSampler(WebGLSampler* sampler) {
  if (!sampler || isContextLost() || !sampler->Validate(ContextGroup(), this))
    return false;

  if (sampler->MarkedForDeletion())
    return false;

  return ContextGL()->IsSampler(sampler->Object());
}

void WebGL2RenderingContextBase::bindSampler(GLuint unit,
                                             WebGLSampler* sampler) {
  if (!ValidateNullableWebGLObject("bindSampler", sampler))
    return;

  if (unit >= sampler_units_.size()) {
    SynthesizeGLError(GL_INVALID_VALUE, "bindSampler",
                      "texture unit out of range");
    return;
  }

  sampler_units_[unit] = sampler;

  ContextGL()->BindSampler(unit, ObjectOrZero(sampler));
}

void WebGL2RenderingContextBase::SamplerParameter(WebGLSampler* sampler,
                                                  GLenum pname,
                                                  GLfloat paramf,
                                                  GLint parami,
                                                  bool is_float) {
  if (!ValidateWebGLObject("samplerParameter", sampler))
    return;

  GLint param;
  if (is_float) {
    param = base::saturated_cast<GLint>(paramf);
  } else {
    param = parami;
  }
  switch (pname) {
    case GL_TEXTURE_MAX_LOD:
    case GL_TEXTURE_MIN_LOD:
      break;
    case GL_TEXTURE_COMPARE_FUNC:
      switch (param) {
        case GL_LEQUAL:
        case GL_GEQUAL:
        case GL_LESS:
        case GL_GREATER:
        case GL_EQUAL:
        case GL_NOTEQUAL:
        case GL_ALWAYS:
        case GL_NEVER:
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                            "invalid parameter");
          return;
      }
      break;
    case GL_TEXTURE_COMPARE_MODE:
      switch (param) {
        case GL_COMPARE_REF_TO_TEXTURE:
        case GL_NONE:
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                            "invalid parameter");
          return;
      }
      break;
    case GL_TEXTURE_MAG_FILTER:
      switch (param) {
        case GL_NEAREST:
        case GL_LINEAR:
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                            "invalid parameter");
          return;
      }
      break;
    case GL_TEXTURE_MIN_FILTER:
      switch (param) {
        case GL_NEAREST:
        case GL_LINEAR:
        case GL_NEAREST_MIPMAP_NEAREST:
        case GL_LINEAR_MIPMAP_NEAREST:
        case GL_NEAREST_MIPMAP_LINEAR:
        case GL_LINEAR_MIPMAP_LINEAR:
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                            "invalid parameter");
          return;
      }
      break;
    case GL_TEXTURE_WRAP_R:
    case GL_TEXTURE_WRAP_S:
    case GL_TEXTURE_WRAP_T:
      switch (param) {
        case GL_CLAMP_TO_EDGE:
        case GL_MIRRORED_REPEAT:
        case GL_REPEAT:
          break;
        case GL_MIRROR_CLAMP_TO_EDGE_EXT:
          if (!ExtensionEnabled(kEXTTextureMirrorClampToEdgeName)) {
            SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                              "invalid parameter, "
                              "EXT_texture_mirror_clamp_to_edge not enabled");
            return;
          }
          break;
        default:
          SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                            "invalid parameter");
          return;
      }
      break;
    case GL_TEXTURE_MAX_ANISOTROPY_EXT:
      if (!ExtensionEnabled(kEXTTextureFilterAnisotropicName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                          "EXT_texture_filter_anisotropic not enabled");
        return;
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                        "invalid parameter name");
      return;
  }

  if (is_float) {
    ContextGL()->SamplerParameterf(ObjectOrZero(sampler), pname, paramf);
  } else {
    ContextGL()->SamplerParameteri(ObjectOrZero(sampler), pname, parami);
  }
}

void WebGL2RenderingContextBase::samplerParameteri(WebGLSampler* sampler,
                                                   GLenum pname,
                                                   GLint param) {
  SamplerParameter(sampler, pname, 0, param, false);
}

void WebGL2RenderingContextBase::samplerParameterf(WebGLSampler* sampler,
                                                   GLenum pname,
                                                   GLfloat param) {
  SamplerParameter(sampler, pname, param, 0, true);
}

ScriptValue WebGL2RenderingContextBase::getSamplerParameter(
    ScriptState* script_state,
    WebGLSampler* sampler,
    GLenum pname) {
  if (!ValidateWebGLObject("getSamplerParameter", sampler))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (pname) {
    case GL_TEXTURE_COMPARE_FUNC:
    case GL_TEXTURE_COMPARE_MODE:
    case GL_TEXTURE_MAG_FILTER:
    case GL_TEXTURE_MIN_FILTER:
    case GL_TEXTURE_WRAP_R:
    case GL_TEXTURE_WRAP_S:
    case GL_TEXTURE_WRAP_T: {
      GLint value = 0;
      ContextGL()->GetSamplerParameteriv(ObjectOrZero(sampler), pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    case GL_TEXTURE_MAX_LOD:
    case GL_TEXTURE_MIN_LOD: {
      GLfloat value = 0.f;
      ContextGL()->GetSamplerParameterfv(ObjectOrZero(sampler), pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_TEXTURE_MAX_ANISOTROPY_EXT: {
      if (!ExtensionEnabled(kEXTTextureFilterAnisotropicName)) {
        SynthesizeGLError(GL_INVALID_ENUM, "samplerParameter",
                          "EXT_texture_filter_anisotropic not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      GLfloat value = 0.f;
      ContextGL()->GetSamplerParameterfv(ObjectOrZero(sampler), pname, &value);
      return WebGLAny(script_state, value);
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getSamplerParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

WebGLSync* WebGL2RenderingContextBase::fenceSync(GLenum condition,
                                                 GLbitfield flags) {
  if (isContextLost())
    return nullptr;

  if (condition != GL_SYNC_GPU_COMMANDS_COMPLETE) {
    SynthesizeGLError(GL_INVALID_ENUM, "fenceSync",
                      "condition must be SYNC_GPU_COMMANDS_COMPLETE");
    return nullptr;
  }
  if (flags != 0) {
    SynthesizeGLError(GL_INVALID_VALUE, "fenceSync", "flags must be zero");
    return nullptr;
  }
  return MakeGarbageCollected<WebGLFenceSync>(this, condition, flags);
}

bool WebGL2RenderingContextBase::isSync(WebGLSync* sync) {
  if (!sync || isContextLost() || !sync->Validate(ContextGroup(), this))
    return false;

  if (sync->MarkedForDeletion())
    return false;

  return sync->Object() != 0;
}

void WebGL2RenderingContextBase::deleteSync(WebGLSync* sync) {
  DeleteObject(sync);
}

GLenum WebGL2RenderingContextBase::clientWaitSync(WebGLSync* sync,
                                                  GLbitfield flags,
                                                  GLuint64 timeout) {
  if (!ValidateWebGLObject("clientWaitSync", sync))
    return GL_WAIT_FAILED;

  if (timeout > kMaxClientWaitTimeout) {
    SynthesizeGLError(GL_INVALID_OPERATION, "clientWaitSync",
                      "timeout > MAX_CLIENT_WAIT_TIMEOUT_WEBGL");
    return GL_WAIT_FAILED;
  }

  // clientWaitSync must poll for updates no more than once per
  // requestAnimationFrame, so all validation, and the implementation,
  // must be done inline.
  if (!(flags == 0 || flags == GL_SYNC_FLUSH_COMMANDS_BIT)) {
    SynthesizeGLError(GL_INVALID_VALUE, "clientWaitSync", "invalid flags");
    return GL_WAIT_FAILED;
  }

  if (sync->IsSignaled()) {
    return GL_ALREADY_SIGNALED;
  }

  sync->UpdateCache(ContextGL());

  if (sync->IsSignaled()) {
    return GL_CONDITION_SATISFIED;
  }

  return GL_TIMEOUT_EXPIRED;
}

void WebGL2RenderingContextBase::waitSync(WebGLSync* sync,
                                          GLbitfield flags,
                                          GLint64 timeout) {
  if (!ValidateWebGLObject("waitSync", sync))
    return;

  if (flags) {
    SynthesizeGLError(GL_INVALID_VALUE, "waitSync", "invalid flags");
    return;
  }

  if (timeout != -1) {
    SynthesizeGLError(GL_INVALID_VALUE, "waitSync", "invalid timeout");
    return;
  }

  // This is intentionally changed to an no-op in WebGL2.
}

ScriptValue WebGL2RenderingContextBase::getSyncParameter(
    ScriptState* script_state,
    WebGLSync* sync,
    GLenum pname) {
  if (!ValidateWebGLObject("getSyncParameter", sync))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (pname) {
    case GL_OBJECT_TYPE:
    case GL_SYNC_STATUS:
    case GL_SYNC_CONDITION:
    case GL_SYNC_FLAGS: {
      sync->UpdateCache(ContextGL());
      return WebGLAny(script_state, sync->GetCachedResult(pname));
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getSyncParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

WebGLTransformFeedback* WebGL2RenderingContextBase::createTransformFeedback() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLTransformFeedback>(
      this, WebGLTransformFeedback::TFType::kUser);
}

void WebGL2RenderingContextBase::deleteTransformFeedback(
    WebGLTransformFeedback* feedback) {
  // We have to short-circuit the deletion process if the transform feedback is
  // active. This requires duplication of some validation logic.
  if (!isContextLost() && feedback &&
      feedback->Validate(ContextGroup(), this)) {
    if (feedback->active()) {
      SynthesizeGLError(
          GL_INVALID_OPERATION, "deleteTransformFeedback",
          "attempt to delete an active transform feedback object");
      return;
    }
  }

  if (!DeleteObject(feedback))
    return;

  if (feedback == transform_feedback_binding_)
    transform_feedback_binding_ = default_transform_feedback_;
}

bool WebGL2RenderingContextBase::isTransformFeedback(
    WebGLTransformFeedback* feedback) {
  if (!feedback || isContextLost() || !feedback->Validate(ContextGroup(), this))
    return false;

  if (!feedback->HasEverBeenBound())
    return false;

  if (feedback->MarkedForDeletion())
    return false;

  return ContextGL()->IsTransformFeedback(feedback->Object());
}

void WebGL2RenderingContextBase::bindTransformFeedback(
    GLenum target,
    WebGLTransformFeedback* feedback) {
  if (!ValidateNullableWebGLObject("bindTransformFeedback", feedback))
    return;

  if (target != GL_TRANSFORM_FEEDBACK) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTransformFeedback",
                      "target must be TRANSFORM_FEEDBACK");
    return;
  }

  if (transform_feedback_binding_->active() &&
      !transform_feedback_binding_->paused()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindTransformFeedback",
                      "transform feedback is active and not paused");
    return;
  }

  WebGLTransformFeedback* feedback_to_be_bound;
  if (feedback) {
    feedback_to_be_bound = feedback;
    feedback_to_be_bound->SetTarget(target);
  } else {
    feedback_to_be_bound = default_transform_feedback_.Get();
  }

  transform_feedback_binding_ = feedback_to_be_bound;
  ContextGL()->BindTransformFeedback(target,
                                     ObjectOrZero(feedback_to_be_bound));
}

void WebGL2RenderingContextBase::beginTransformFeedback(GLenum primitive_mode) {
  if (isContextLost())
    return;
  if (!ValidateTransformFeedbackPrimitiveMode("beginTransformFeedback",
                                              primitive_mode))
    return;
  if (!current_program_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "beginTransformFeedback",
                      "no program object is active");
    return;
  }
  if (transform_feedback_binding_->active()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "beginTransformFeedback",
                      "transform feedback is already active");
    return;
  }
  int required_buffer_count =
      current_program_->GetRequiredTransformFeedbackBufferCount(this);
  if (required_buffer_count == 0) {
    SynthesizeGLError(GL_INVALID_OPERATION, "beginTransformFeedback",
                      "current active program does not specify any transform "
                      "feedback varyings to record");
    return;
  }
  if (!transform_feedback_binding_->HasEnoughBuffers(required_buffer_count)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "beginTransformFeedback",
                      "not enough transform feedback buffers bound");
    return;
  }

  ContextGL()->BeginTransformFeedback(primitive_mode);
  current_program_->IncreaseActiveTransformFeedbackCount();
  transform_feedback_binding_->SetProgram(current_program_);
  transform_feedback_binding_->SetActive(true);
  transform_feedback_binding_->SetPaused(false);
}

void WebGL2RenderingContextBase::endTransformFeedback() {
  if (isContextLost())
    return;
  if (!transform_feedback_binding_->active()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "endTransformFeedback",
                      "transform feedback is not active");
    return;
  }

  ContextGL()->EndTransformFeedback();

  transform_feedback_binding_->SetPaused(false);
  transform_feedback_binding_->SetActive(false);
  if (current_program_)
    current_program_->DecreaseActiveTransformFeedbackCount();
}

void WebGL2RenderingContextBase::transformFeedbackVaryings(
    WebGLProgram* program,
    const Vector<String>& varyings,
    GLenum buffer_mode) {
  if (!ValidateWebGLProgramOrShader("transformFeedbackVaryings", program))
    return;

  switch (buffer_mode) {
    case GL_SEPARATE_ATTRIBS:
      if (varyings.size() >
          static_cast<size_t>(max_transform_feedback_separate_attribs_)) {
        SynthesizeGLError(GL_INVALID_VALUE, "transformFeedbackVaryings",
                          "too many varyings");
        return;
      }
      break;
    case GL_INTERLEAVED_ATTRIBS:
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "transformFeedbackVaryings",
                        "invalid buffer mode");
      return;
  }

  PointableStringArray varying_strings(varyings);

  program->SetRequiredTransformFeedbackBufferCount(
      buffer_mode == GL_INTERLEAVED_ATTRIBS
          ? std::min(static_cast<wtf_size_t>(1), varyings.size())
          : varyings.size());

  ContextGL()->TransformFeedbackVaryings(ObjectOrZero(program), varyings.size(),
                                         varying_strings.data(), buffer_mode);
}

WebGLActiveInfo* WebGL2RenderingContextBase::getTransformFeedbackVarying(
    WebGLProgram* program,
    GLuint index) {
  if (!ValidateWebGLProgramOrShader("getTransformFeedbackVarying", program))
    return nullptr;

  if (!program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getTransformFeedbackVarying",
                      "program not linked");
    return nullptr;
  }
  GLint max_index = 0;
  ContextGL()->GetProgramiv(ObjectOrZero(program),
                            GL_TRANSFORM_FEEDBACK_VARYINGS, &max_index);
  if (index >= static_cast<GLuint>(max_index)) {
    SynthesizeGLError(GL_INVALID_VALUE, "getTransformFeedbackVarying",
                      "invalid index");
    return nullptr;
  }

  GLint max_name_length = -1;
  ContextGL()->GetProgramiv(ObjectOrZero(program),
                            GL_TRANSFORM_FEEDBACK_VARYING_MAX_LENGTH,
                            &max_name_length);
  if (max_name_length <= 0) {
    return nullptr;
  }
  auto name = base::HeapArray<GLchar>::WithSize(max_name_length);
  GLsizei length = 0;
  GLsizei size = 0;
  GLenum type = 0;
  ContextGL()->GetTransformFeedbackVarying(ObjectOrZero(program), index,
                                           max_name_length, &length, &size,
                                           &type, name.data());

  if (length <= 0 || size == 0 || type == 0) {
    return nullptr;
  }

  return MakeGarbageCollected<WebGLActiveInfo>(
      String(base::span(name).first(static_cast<uint32_t>(length))), type,
      size);
}

void WebGL2RenderingContextBase::pauseTransformFeedback() {
  if (isContextLost())
    return;

  if (!transform_feedback_binding_->active()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "pauseTransformFeedback",
                      "transform feedback is not active");
    return;
  }
  if (transform_feedback_binding_->paused()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "pauseTransformFeedback",
                      "transform feedback is already paused");
    return;
  }

  transform_feedback_binding_->SetPaused(true);
  ContextGL()->PauseTransformFeedback();
}

void WebGL2RenderingContextBase::resumeTransformFeedback() {
  if (isContextLost())
    return;

  if (!transform_feedback_binding_->ValidateProgramForResume(
          current_program_)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "resumeTransformFeedback",
                      "the current program is not the same as when "
                      "beginTransformFeedback was called");
    return;
  }
  if (!transform_feedback_binding_->active() ||
      !transform_feedback_binding_->paused()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "resumeTransformFeedback",
                      "transform feedback is not active or not paused");
    return;
  }

  transform_feedback_binding_->SetPaused(false);
  ContextGL()->ResumeTransformFeedback();
}

bool WebGL2RenderingContextBase::ValidateTransformFeedbackPrimitiveMode(
    const char* function_name,
    GLenum primitive_mode) {
  switch (primitive_mode) {
    case GL_POINTS:
    case GL_LINES:
    case GL_TRIANGLES:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid transform feedback primitive mode");
      return false;
  }
}

void WebGL2RenderingContextBase::OnBeforeDrawCall(
    CanvasPerformanceMonitor::DrawType draw_type) {
  if (transform_feedback_binding_->active() &&
      !transform_feedback_binding_->paused()) {
    for (WebGLBuffer* buffer :
         transform_feedback_binding_
             ->bound_indexed_transform_feedback_buffers()) {
      if (buffer) {
        ContextGL()->InvalidateReadbackBufferShadowDataCHROMIUM(
            buffer->Object());
      }
    }
  }

  WebGLRenderingContextBase::OnBeforeDrawCall(draw_type);
}

void WebGL2RenderingContextBase::bindBufferBase(GLenum target,
                                                GLuint index,
                                                WebGLBuffer* buffer) {
  if (isContextLost())
    return;
  if (!ValidateNullableWebGLObject("bindBufferBase", buffer))
    return;
  if (target == GL_TRANSFORM_FEEDBACK_BUFFER &&
      transform_feedback_binding_->active()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindBufferBase",
                      "transform feedback is active");
    return;
  }
  if (!ValidateAndUpdateBufferBindBaseTarget("bindBufferBase", target, index,
                                             buffer))
    return;

  ContextGL()->BindBufferBase(target, index, ObjectOrZero(buffer));
}

void WebGL2RenderingContextBase::bindBufferRange(GLenum target,
                                                 GLuint index,
                                                 WebGLBuffer* buffer,
                                                 int64_t offset,
                                                 int64_t size) {
  if (isContextLost())
    return;
  if (!ValidateNullableWebGLObject("bindBufferRange", buffer))
    return;
  if (target == GL_TRANSFORM_FEEDBACK_BUFFER &&
      transform_feedback_binding_->active()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindBufferBase",
                      "transform feedback is active");
    return;
  }
  if (!ValidateValueFitNonNegInt32("bindBufferRange", "offset", offset) ||
      !ValidateValueFitNonNegInt32("bindBufferRange", "size", size)) {
    return;
  }

  if (!ValidateAndUpdateBufferBindBaseTarget("bindBufferRange", target, index,
                                             buffer))
    return;

  ContextGL()->BindBufferRange(target, index, ObjectOrZero(buffer),
                               static_cast<GLintptr>(offset),
                               static_cast<GLsizeiptr>(size));
}

ScriptValue WebGL2RenderingContextBase::getIndexedParameter(
    ScriptState* script_state,
    GLenum target,
    GLuint index) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (target) {
    case GL_TRANSFORM_FEEDBACK_BUFFER_BINDING: {
      WebGLBuffer* buffer = nullptr;
      if (!transform_feedback_binding_->GetBoundIndexedTransformFeedbackBuffer(
              index, &buffer)) {
        SynthesizeGLError(GL_INVALID_VALUE, "getIndexedParameter",
                          "index out of range");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      return WebGLAny(script_state, buffer);
    }
    case GL_UNIFORM_BUFFER_BINDING:
      if (index >= bound_indexed_uniform_buffers_.size()) {
        SynthesizeGLError(GL_INVALID_VALUE, "getIndexedParameter",
                          "index out of range");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      return WebGLAny(script_state,
                      bound_indexed_uniform_buffers_[index].Get());
    case GL_TRANSFORM_FEEDBACK_BUFFER_SIZE:
    case GL_TRANSFORM_FEEDBACK_BUFFER_START:
    case GL_UNIFORM_BUFFER_SIZE:
    case GL_UNIFORM_BUFFER_START: {
      GLint64 value = -1;
      ContextGL()->GetInteger64i_v(target, index, &value);
      return WebGLAny(script_state, value);
    }
    case GL_BLEND_EQUATION_RGB:
    case GL_BLEND_EQUATION_ALPHA:
    case GL_BLEND_SRC_RGB:
    case GL_BLEND_SRC_ALPHA:
    case GL_BLEND_DST_RGB:
    case GL_BLEND_DST_ALPHA: {
      if (!ExtensionEnabled(kOESDrawBuffersIndexedName)) {
        // return null
        SynthesizeGLError(GL_INVALID_ENUM, "getIndexedParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      GLint value = -1;
      ContextGL()->GetIntegeri_v(target, index, &value);
      return WebGLAny(script_state, value);
    }
    case GL_COLOR_WRITEMASK: {
      if (!ExtensionEnabled(kOESDrawBuffersIndexedName)) {
        // Enum validation has to happen here to return null
        // instead of an array to pass
        // conformance2/state/gl-object-get-calls.html
        SynthesizeGLError(GL_INVALID_ENUM, "getIndexedParameter",
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      Vector<bool> values(4);
      ContextGL()->GetBooleani_v(target, index,
                                 reinterpret_cast<GLboolean*>(values.data()));
      return WebGLAny(script_state, values);
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getIndexedParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

std::optional<Vector<GLuint>> WebGL2RenderingContextBase::getUniformIndices(
    WebGLProgram* program,
    const Vector<String>& uniform_names) {
  // TODO(https://crbug.com/1465002): This should return std::nullopt
  // if there is an error.
  Vector<GLuint> result;
  if (!ValidateWebGLProgramOrShader("getUniformIndices", program))
    return result;

  PointableStringArray uniform_strings(uniform_names);

  result.resize(uniform_names.size());
  ContextGL()->GetUniformIndices(ObjectOrZero(program), uniform_strings.size(),
                                 uniform_strings.data(), result.data());
  return result;
}

ScriptValue WebGL2RenderingContextBase::getActiveUniforms(
    ScriptState* script_state,
    WebGLProgram* program,
    const Vector<GLuint>& uniform_indices,
    GLenum pname) {
  if (!ValidateWebGLProgramOrShader("getActiveUniforms", program))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  enum ReturnType { kEnumType, kUnsignedIntType, kIntType, kBoolType };

  int return_type;
  switch (pname) {
    case GL_UNIFORM_TYPE:
      return_type = kEnumType;
      break;
    case GL_UNIFORM_SIZE:
      return_type = kUnsignedIntType;
      break;
    case GL_UNIFORM_BLOCK_INDEX:
    case GL_UNIFORM_OFFSET:
    case GL_UNIFORM_ARRAY_STRIDE:
    case GL_UNIFORM_MATRIX_STRIDE:
      return_type = kIntType;
      break;
    case GL_UNIFORM_IS_ROW_MAJOR:
      return_type = kBoolType;
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getActiveUniforms",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  GLint active_uniforms = -1;
  ContextGL()->GetProgramiv(ObjectOrZero(program), GL_ACTIVE_UNIFORMS,
                            &active_uniforms);

  GLuint active_uniforms_unsigned = active_uniforms;
  wtf_size_t size = uniform_indices.size();
  for (GLuint index : uniform_indices) {
    if (index >= active_uniforms_unsigned) {
      SynthesizeGLError(GL_INVALID_VALUE, "getActiveUniforms",
                        "uniform index greater than ACTIVE_UNIFORMS");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    }
  }

  Vector<GLint> result(size);
  ContextGL()->GetActiveUniformsiv(
      ObjectOrZero(program), uniform_indices.size(), uniform_indices.data(),
      pname, result.data());
  switch (return_type) {
    case kEnumType: {
      Vector<GLenum> enum_result(size);
      for (wtf_size_t i = 0; i < size; ++i)
        enum_result[i] = static_cast<GLenum>(result[i]);
      return WebGLAny(script_state, enum_result);
    }
    case kUnsignedIntType: {
      Vector<GLuint> uint_result(size);
      for (wtf_size_t i = 0; i < size; ++i)
        uint_result[i] = static_cast<GLuint>(result[i]);
      return WebGLAny(script_state, uint_result);
    }
    case kIntType: {
      return WebGLAny(script_state, result);
    }
    case kBoolType: {
      Vector<bool> bool_result(size);
      for (wtf_size_t i = 0; i < size; ++i)
        bool_result[i] = static_cast<bool>(result[i]);
      return WebGLAny(script_state, bool_result);
    }
    default:
      NOTREACHED();
  }
}

GLuint WebGL2RenderingContextBase::getUniformBlockIndex(
    WebGLProgram* program,
    const String& uniform_block_name) {
  if (!ValidateWebGLProgramOrShader("getUniformBlockIndex", program))
    return 0;
  if (!ValidateString("getUniformBlockIndex", uniform_block_name))
    return 0;

  return ContextGL()->GetUniformBlockIndex(ObjectOrZero(program),
                                           uniform_block_name.Utf8().c_str());
}

bool WebGL2RenderingContextBase::ValidateUniformBlockIndex(
    const char* function_name,
    WebGLProgram* program,
    GLuint block_index) {
  DCHECK(program);
  if (!program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "program not linked
"""


```