Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The code is part of the `WebGLRenderingContextBase` class, focusing on various WebGL API functions related to uniform variables, program usage, vertex attributes, viewport settings, and context loss/restoration.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class:** The code belongs to `WebGLRenderingContextBase`. This immediately tells us it's a fundamental part of the WebGL implementation in Blink.

2. **Group Functions by Purpose:**  Scan the function names and their arguments to identify logical groupings:
    * **Uniforms:** Functions starting with `uniformMatrix` (setting matrix uniforms).
    * **Programs:** `useProgram`, `validateProgram` (managing shader programs).
    * **Vertex Attributes:** Functions starting with `vertexAttrib` and `vertexAttribPointer` (setting up vertex data).
    * **Viewport:** `viewport` (defining the rendering area).
    * **Context Loss/Restoration:** Functions like `LoseContext`, `ForceLostContext`, `ForceRestoreContext` (managing the WebGL context lifecycle).
    * **Internal Helpers:**  Functions like `SetVertexAttribType`, and the `DrawingBufferClientRestore...` family of functions which appear to be related to synchronizing with the drawing buffer.
    * **Parameter Retrieval:** Functions like `GetBooleanParameter`, `GetIntParameter`, etc. (reading WebGL state).
    * **Validation:**  Functions starting with `Validate` (checking the validity of arguments and states).
    * **Texture Validation:**  `ValidateTexture2DBinding`, `ValidateTextureBinding`.
    * **String/Value Validation:** `ValidateLocationLength`, `ValidateSize`, `ValidateCharacter`, `ValidateString`.
    * **Shader Type Validation:** `ValidateShaderType`.
    * **Format/Type Validation (Textures):** `ValidateTexImageSourceFormatAndType`, `ValidateTexFuncFormatAndType`.
    * **Texture Level Validation:** `ValidateTexFuncLevel`.
    * **Texture Dimension Validation:** `ValidateTexFuncDimensions`.

3. **Summarize Functionality within Each Group:**  For each group, concisely explain what the functions do:
    * **Uniforms:** Setting uniform matrix values in shaders.
    * **Programs:** Selecting and validating the currently active shader program.
    * **Vertex Attributes:**  Providing data to vertex shaders.
    * **Viewport:** Setting the region of the canvas to render to.
    * **Context Loss/Restoration:** Handling events where the WebGL context becomes invalid and potentially recovering it.
    * **Internal Helpers:**  Setting vertex attribute types, restoring drawing buffer state.
    * **Parameter Retrieval:**  Getting the current values of various WebGL settings.
    * **Validation:**  Ensuring that input values to WebGL functions are valid.
    * **Texture Validation:** Verifying that textures are bound correctly.
    * **String/Value Validation:**  Checking the validity of string and numeric inputs.
    * **Shader Type Validation:** Confirming the correct shader type is used.
    * **Format/Type Validation (Textures):**  Ensuring valid combinations of texture formats and data types.
    * **Texture Level Validation:**  Checking if the specified texture level is valid.
    * **Texture Dimension Validation:**  Verifying the dimensions of texture images.

4. **Identify Relationships with JavaScript, HTML, and CSS:**
    * **JavaScript:** WebGL APIs are directly called from JavaScript. The functions in this file are the *implementation* of those APIs. Examples involve setting uniform values, using programs, and providing vertex data via JavaScript arrays.
    * **HTML:** The `<canvas>` element in HTML is where WebGL rendering happens. The `WebGLRenderingContextBase` is associated with a canvas. The `viewport` function relates to the size of the rendering area within the canvas.
    * **CSS:** CSS can indirectly affect WebGL by influencing the size and layout of the `<canvas>` element.

5. **Provide Examples (Hypothetical):**  Create simple, illustrative JavaScript code snippets that would trigger the C++ functions being discussed. Focus on showing the direct connection between JavaScript API calls and the corresponding C++ functions.

6. **Illustrate Common Errors:** Think about how developers might misuse the WebGL API and how the validation logic in the C++ code would catch those errors. Provide JavaScript examples of these incorrect usages.

7. **Describe the User Path to This Code (Debugging):** Explain the steps a user might take that would eventually lead to the execution of these C++ functions. Focus on the user's interaction with a web page that uses WebGL.

8. **Address the "Part 9 of 11" Instruction:** Acknowledge this context and summarize the overall functionality of this specific section within the larger codebase. Emphasize the focus on core rendering and state management functions.

9. **Review and Refine:**  Read through the generated summary, ensuring clarity, accuracy, and completeness. Check for any jargon that needs explanation. Ensure the examples are easy to understand. Make sure all the instructions in the prompt have been addressed.
```cpp
mMatrix2fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::uniformMatrix3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformMatrixParameters("uniformMatrix3fv", location, transpose,
                                       v, 9, 0, v.size(), &data, &length)) {
    return;
  }
  ContextGL()->UniformMatrix3fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::uniformMatrix4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformMatrixParameters("uniformMatrix4fv", location, transpose,
                                       v, 16, 0, v.size(), &data, &length)) {
    return;
  }
  ContextGL()->UniformMatrix4fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::useProgram(WebGLProgram* program) {
  if (!ValidateNullableWebGLObject("useProgram", program))
    return;
  if (program && !program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "useProgram", "program not valid");
    return;
  }

  if (current_program_ != program) {
    if (current_program_)
      current_program_->OnDetached(ContextGL());
    current_program_ = program;
    ContextGL()->UseProgram(ObjectOrZero(program));
    if (program)
      program->OnAttached();
  }
}

void WebGLRenderingContextBase::validateProgram(WebGLProgram* program) {
  if (!ValidateWebGLProgramOrShader("validateProgram", program))
    return;
  ContextGL()->ValidateProgram(ObjectOrZero(program));
}

void WebGLRenderingContextBase::SetVertexAttribType(
    GLuint index,
    VertexAttribValueType type) {
  if (index < max_vertex_attribs_)
    vertex_attrib_type_[index] = type;
}

void WebGLRenderingContextBase::vertexAttrib1f(GLuint index, GLfloat v0) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib1f(index, v0);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib1fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 1) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib1fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib1fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib2f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib2f(index, v0, v1);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib2fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 2) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib2fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib2fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib3f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1,
                                               GLfloat v2) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib3f(index, v0, v1, v2);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib3fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 3) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib3fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib3fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib4f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1,
                                               GLfloat v2,
                                               GLfloat v3) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib4f(index, v0, v1, v2, v3);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib4fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 4) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib4fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib4fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttribPointer(GLuint index,
                                                    GLint size,
                                                    GLenum type,
                                                    GLboolean normalized,
                                                    GLsizei stride,
                                                    int64_t offset) {
  if (isContextLost())
    return;
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribPointer",
                      "index out of range");
    return;
  }
  if (!ValidateValueFitNonNegInt32("vertexAttribPointer", "offset", offset))
    return;
  if (!bound_array_buffer_ && offset != 0) {
    SynthesizeGLError(GL_INVALID_OPERATION, "vertexAttribPointer",
                      "no ARRAY_BUFFER is bound and offset is non-zero");
    return;
  }

  bound_vertex_array_object_->SetArrayBufferForAttrib(
      index, bound_array_buffer_.Get());
  ContextGL()->VertexAttribPointer(
      index, size, type, normalized, stride,
      reinterpret_cast<void*>(static_cast<intptr_t>(offset)));
}

void WebGLRenderingContextBase::VertexAttribDivisorANGLE(GLuint index,
                                                         GLuint divisor) {
  if (isContextLost())
    return;

  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribDivisorANGLE",
                      "index out of range");
    return;
  }

  ContextGL()->VertexAttribDivisorANGLE(index, divisor);
}

void WebGLRenderingContextBase::viewport(GLint x,
                                         GLint y,
                                         GLsizei width,
                                         GLsizei height) {
  if (isContextLost())
    return;
  ContextGL()->Viewport(x, y, width, height);
}

// Added to provide a unified interface with CanvasRenderingContext2D. Prefer
// calling forceLostContext instead.
void WebGLRenderingContextBase::LoseContext(LostContextMode mode) {
  ForceLostContext(mode, kManual);
}

void WebGLRenderingContextBase::ForceLostContext(
    LostContextMode mode,
    AutoRecoveryMethod auto_recovery_method) {
  if (isContextLost()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "loseContext",
                      "context already lost");
    return;
  }

  context_group_->LoseContextGroup(mode, auto_recovery_method);
}

void WebGLRenderingContextBase::LoseContextImpl(
    WebGLRenderingContextBase::LostContextMode mode,
    AutoRecoveryMethod auto_recovery_method) {
  if (isContextLost())
    return;

  context_lost_mode_ = mode;
  DCHECK_NE(context_lost_mode_, kNotLostContext);
  auto_recovery_method_ = auto_recovery_method;

  // Lose all the extensions.
  for (ExtensionTracker* tracker : extensions_) {
    tracker->LoseExtension(false);
  }

  for (wtf_size_t i = 0; i < kWebGLExtensionNameCount; ++i)
    extension_enabled_[i] = false;

  // This resolver is non-null during a makeXRCompatible call, while waiting
  // for a response from the browser and XR process. If the WebGL context is
  // lost before we get a response, the resolver has to be rejected to be
  // be properly disposed of.
  xr_compatible_ = false;
  CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kInvalidStateError);

  RemoveAllCompressedTextureFormats();

  if (mode == kRealLostContext) {
    // If it is a real context loss, the signal needs to be propagated to the
    // context host so that it knows all resources are dropped. Otherwise,
    // OffscreenCanvases on Workers would wait indefinitely for reources to be
    // returned by the compositor, which would stall requestAnimationFrame.
    Host()->NotifyGpuContextLost();

    // If the DrawingBuffer is destroyed during a real lost context event it
    // causes the CommandBufferProxy that the DrawingBuffer owns, which is what
    // issued the lost context event in the first place, to be destroyed before
    // the event is done being handled. This causes a crash when an outstanding
    // AutoLock goes out of scope. To avoid this, we create a no-op task to hold
    // a reference to the DrawingBuffer until this function is done executing.
    task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&WebGLRenderingContextBase::HoldReferenceToDrawingBuffer,
                      WrapWeakPersistent(this),
                      WTF::RetainedRef(drawing_buffer_)));
  }

  // Always destroy the context, regardless of context loss mode. This will
  // set drawing_buffer_ to null, but it won't actually be destroyed until the
  // above task is executed. drawing_buffer_ is recreated in the event that the
  // context is restored by MaybeRestoreContext. If this was a real lost context
  // the OpenGL calls done during DrawingBuffer destruction will be ignored.
  DestroyContext();

  ConsoleDisplayPreference display =
      (mode == kRealLostContext) ? kDisplayInConsole : kDontDisplayInConsole;
  SynthesizeGLError(GC3D_CONTEXT_LOST_WEBGL, "loseContext", "context lost",
                    display);

  // Don't allow restoration unless the context lost event has both been
  // dispatched and its default behavior prevented.
  restore_allowed_ = false;
  DeactivateContext(this);
  if (auto_recovery_method_ == kWhenAvailable)
    AddToEvictedList(this);

  // Always defer the dispatch of the context lost event, to implement
  // the spec behavior of queueing a task.
  dispatch_context_lost_event_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void WebGLRenderingContextBase::HoldReferenceToDrawingBuffer(DrawingBuffer*) {
  // This function intentionally left blank.
}

void WebGLRenderingContextBase::ForceRestoreContext() {
  if (!isContextLost()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "restoreContext",
                      "context not lost");
    return;
  }

  if (!restore_allowed_) {
    if (context_lost_mode_ == kWebGLLoseContextLostContext)
      SynthesizeGLError(GL_INVALID_OPERATION, "restoreContext",
                        "context restoration not allowed");
    return;
  }

  if (!restore_timer_.IsActive())
    restore_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

uint32_t WebGLRenderingContextBase::NumberOfContextLosses() const {
  return context_group_->NumberOfContextLosses();
}

cc::Layer* WebGLRenderingContextBase::CcLayer() const {
  return isContextLost() ? nullptr : GetDrawingBuffer()->CcLayer();
}

void WebGLRenderingContextBase::SetHdrMetadata(
    const gfx::HDRMetadata& hdr_metadata) {
  if (!isContextLost() && GetDrawingBuffer()) {
    GetDrawingBuffer()->SetHdrMetadata(hdr_metadata);
  }
}

void WebGLRenderingContextBase::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (!isContextLost() && GetDrawingBuffer()) {
    GetDrawingBuffer()->SetFilterQuality(filter_quality);
  }
}

Extensions3DUtil* WebGLRenderingContextBase::ExtensionsUtil() {
  if (!extensions_util_) {
    gpu::gles2::GLES2Interface* gl = ContextGL();
    extensions_util_ = Extensions3DUtil::Create(gl);
    // The only reason the ExtensionsUtil should be invalid is if the gl context
    // is lost.
    DCHECK(extensions_util_->IsValid() ||
           gl->GetGraphicsResetStatusKHR() != GL_NO_ERROR);
  }
  return extensions_util_.get();
}

void WebGLRenderingContextBase::Stop() {
  if (!isContextLost()) {
    // Never attempt to restore the context because the page is being torn down.
    ForceLostContext(kSyntheticLostContext, kManual);
  }
}

void WebGLRenderingContextBase::
    DrawingBufferClientInterruptPixelLocalStorage() {
  if (destruction_in_progress_) {
    return;
  }
  if (!ContextGL()) {
    return;
  }
  if (!has_activated_pixel_local_storage_) {
    return;
  }
  ContextGL()->FramebufferPixelLocalStorageInterruptANGLE();
}

void WebGLRenderingContextBase::DrawingBufferClientRestorePixelLocalStorage() {
  if (destruction_in_progress_) {
    return;
  }
  if (!ContextGL()) {
    return;
  }
  if (!has_activated_pixel_local_storage_) {
    return;
  }
  ContextGL()->FramebufferPixelLocalStorageRestoreANGLE();
}

bool WebGLRenderingContextBase::DrawingBufferClientIsBoundForDraw() {
  return !framebuffer_binding_;
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreScissorTest() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  if (scissor_enabled_)
    ContextGL()->Enable(GL_SCISSOR_TEST);
  else
    ContextGL()->Disable(GL_SCISSOR_TEST);
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreMaskAndClearValues() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  bool color_mask_alpha =
      color_mask_[3] && active_scoped_rgb_emulation_color_masks_ == 0;
  if (ExtensionEnabled(kOESDrawBuffersIndexedName)) {
    ContextGL()->ColorMaskiOES(0, color_mask_[0], color_mask_[1],
                               color_mask_[2], color_mask_alpha);
  } else {
    ContextGL()->ColorMask(color_mask_[0], color_mask_[1], color_mask_[2],
                           color_mask_alpha);
  }
  ContextGL()->DepthMask(depth_mask_);
  ContextGL()->StencilMaskSeparate(GL_FRONT, stencil_mask_);

  ContextGL()->ClearColor(clear_color_[0], clear_color_[1], clear_color_[2],
                          clear_color_[3]);
  ContextGL()->ClearDepthf(clear_depth_);
  ContextGL()->ClearStencil(clear_stencil_);
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelPackParameters() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->PixelStorei(GL_PACK_ALIGNMENT, pack_alignment_);
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreTexture2DBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentTexture2D();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestoreTextureCubeMapBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentTextureCubeMap();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestoreRenderbufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->BindRenderbuffer(GL_RENDERBUFFER,
                                ObjectOrZero(renderbuffer_binding_.Get()));
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreFramebufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentFramebuffer();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelUnpackBufferBinding() {}
void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelPackBufferBinding() {}

bool WebGLRenderingContextBase::
    DrawingBufferClientUserAllocatedMultisampledRenderbuffers() {
  return number_of_user_allocated_multisampled_renderbuffers_ > 0;
}

void WebGLRenderingContextBase::
    DrawingBufferClientForceLostContextWithAutoRecovery(const char* reason) {
  ForceLostContext(WebGLRenderingContextBase::kSyntheticLostContext,
                   WebGLRenderingContextBase::kAuto);
  if (reason) {
    PrintWarningToConsole(reason);
  }
}

ScriptValue WebGLRenderingContextBase::GetBooleanParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLboolean value = 0;
  if (!isContextLost())
    ContextGL()->GetBooleanv(pname, &value);
  return WebGLAny(script_state, static_cast<bool>(value));
}

ScriptValue WebGLRenderingContextBase::GetBooleanArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  if (pname != GL_COLOR_WRITEMASK) {
    NOTIMPLEMENTED();
    return WebGLAny(script_state, nullptr, 0);
  }
  std::array<GLboolean, 4> value = {0};
  if (!isContextLost()) {
    ContextGL()->GetBooleanv(pname, value.data());
  }
  std::array<bool, 4> bool_value = {};
  for (int ii = 0; ii < 4; ++ii)
    bool_value[ii] = static_cast<bool>(value[ii]);
  return WebGLAny(script_state, bool_value.data(), 4);
}

ScriptValue WebGLRenderingContextBase::GetFloatParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLfloat value = 0;
  if (!isContextLost())
    ContextGL()->GetFloatv(pname, &value);
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kWebGLParameter)) {
    RecordIdentifiableGLParameterDigest(pname, value);
  }
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetIntParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint value = 0;
  if (!isContextLost()) {
    ContextGL()->GetIntegerv(pname, &value);
    switch (pname) {
      case GL_IMPLEMENTATION_COLOR_READ_FORMAT:
      case GL_IMPLEMENTATION_COLOR_READ_TYPE:
        if (value == 0) {
          // This indicates read framebuffer is incomplete and an
          // INVALID_OPERATION has been generated.
          return ScriptValue::CreateNull(script_state->GetIsolate());
        }
        break;
      default:
        break;
    }
  }
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kWebGLParameter)) {
    RecordIdentifiableGLParameterDigest(pname, value);
  }
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetInt64Parameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint64 value = 0;
  if (!isContextLost())
    ContextGL()->GetInteger64v(pname, &value);
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetUnsignedIntParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint value = 0;
  if (!isContextLost())
    ContextGL()->GetIntegerv(pname, &value);
  return WebGLAny(script_state, static_cast<unsigned>(value));
}

ScriptValue WebGLRenderingContextBase::GetWebGLFloatArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  std::array<GLfloat, 4> value = {0};
  if (!isContextLost())
    ContextGL()->GetFloatv(pname, value.data());
  unsigned length = 0;
  switch (pname) {
    case GL_ALIASED_POINT_SIZE_RANGE:
    case GL_ALIASED_LINE_WIDTH_RANGE:
    case GL_DEPTH_RANGE:
      length = 2;
      break;
    case GL_BLEND_COLOR:
    case GL_COLOR_CLEAR_VALUE:
      length = 4;
      break;
    default:
      NOTIMPLEMENTED();
  }
  if (ShouldMeasureGLParam(pname)) {
    blink::IdentifiableTokenBuilder builder;
    for (unsigned i = 0; i < length; i++) {
      builder.AddValue(value[i]);
    }
    RecordIdentifiableGLParameterDigest(pname, builder.GetToken());
  }
  return WebGLAny(script_state,
                  DOMFloat32Array::Create(base::span(value).first(length)));
}

ScriptValue WebGLRenderingContextBase::GetWebGLIntArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  std::array<GLint, 4> value = {0};
  if (!isContextLost())
    ContextGL()->GetIntegerv(pname, value.data());
  unsigned length = 0;
  switch (pname) {
    case GL_MAX_VIEWPORT_DIMS:
      length = 2;
      break;
    case GL_SCISSOR_BOX:
    case GL_VIEWPORT:
      length = 4;
      break;
    default:
      NOTIMPLEMENTED();
  }
  if (ShouldMeasureGLParam(pname)) {
    blink::IdentifiableTokenBuilder builder;
    for (unsigned i = 0; i < length; i++) {
      builder.AddValue(value[i]);
    }
    RecordIdentifiableGLParameterDigest(pname, builder.GetToken());
  }
  return WebGLAny(script_state,
                  DOMInt32Array::Create(base::span(value).first(length)));
}

WebGLTexture* WebGLRenderingContextBase::ValidateTexture2DBinding(
    const char* function_name,
    GLenum target,
    bool validate_opaque_textures) {
  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D:
      tex = texture_units_[active_texture_unit_].texture2d_binding_.Get();
      break;
    case GL_TEXTURE_CUBE_MAP_POSITIVE_X:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_X:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Y:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Y:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Z:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Z:
      tex =
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid texture target");
      return nullptr;
  }
  if (!tex) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no texture bound to target");
  } else if (validate_opaque_textures && tex->IsOpaqueTexture()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "cannot invoke function with an opaque texture");
    return nullptr;
  }
  return tex;
}

WebGLTexture* WebGLRenderingContextBase::ValidateTextureBinding(
    const char* function_name,
    GLenum target) {
  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D:
      tex = texture_units_[active_texture_unit_].texture2d_binding_.Get();
      break;
    case GL_TEXTURE_CUBE_MAP:
      tex =
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get();
      break;
    case GL_TEXTURE_3D:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "invalid texture target");
        return nullptr;
      }
      tex = texture_units_[active_texture_unit_].texture3d_binding_.Get();
      break;
    case GL_TEXTURE_2D_ARRAY:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "invalid texture target");
        return nullptr;
      }
      tex = texture_units_[active_texture_unit_].texture2d_array_binding_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid texture target");
      return nullptr;
  }
  if (!tex) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no texture bound to target");
  }
  return tex;
}

bool WebGLRenderingContextBase::ValidateLocationLength(
    const char* function_name,
    const String& string) {
  const unsigned max_web_gl_location_length = GetMaxWebGLLocationLength();
  if (string.length() > max_web_gl_location_length) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "location length > 256");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateSize(const char* function_name,
                                             GLint x,
                                             GLint y,
                                             GLint z) {
  if (x < 0 || y < 0 || z < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "size < 0");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateCharacter(unsigned char c) {
  // Printing characters are valid except " $ ` @ \ ' DEL.
  if (c >= 32 && c <= 126 && c != '"' && c != '$' && c != '`' && c != '@' &&
      c != '\\' && c != '\'')
    return true;
  // Horizontal tab, line feed, vertical tab, form feed, carriage return
  // are also valid.
  if (c >= 9 && c <= 13)
    return true;
  return false;
}

bool WebGLRenderingContextBase::ValidateString(const char* function_name,
                                               const String& string) {
  for (wtf_size_t i = 0; i < string.length(); ++i) {
    if (!ValidateCharacter(string[i])) {
      SynthesizeGLError(GL_INVALID_VALUE, function_name, "string not ASCII");
      return false;
    }
  }
  return true;
}

bool WebGLRenderingContextBase::IsPrefixReserved(const String& name) {
  if (name.StartsWith("gl_") || name.StartsWith("webgl_") ||
      name.StartsWith("_webgl_"))
    return true;
  return false;
}

bool WebGLRenderingContextBase::ValidateShaderType(const char* function_name,
                                                   GLenum shader_type) {
  switch (shader_type) {
    case GL_VERTEX_SHADER:
    case GL_FRAGMENT_SHADER:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid shader type");
      return false;
  }
}

void WebGLRenderingContextBase::AddExtensionSupportedFormatsTypes() {
  if (!is_oes_texture_float_formats_types_added_ &&
      ExtensionEnabled(kOESTextureFloatName)) {
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesOESTexFloat);
    ADD_VALUES_TO_SET(supported_tex_image_source_types_,
                      kSupportedTypesOESTexFloat);
    is_oes_texture_float_formats_types_added_ = true;
  }

  if (!
### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
mMatrix2fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::uniformMatrix3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformMatrixParameters("uniformMatrix3fv", location, transpose,
                                       v, 9, 0, v.size(), &data, &length)) {
    return;
  }
  ContextGL()->UniformMatrix3fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::uniformMatrix4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformMatrixParameters("uniformMatrix4fv", location, transpose,
                                       v, 16, 0, v.size(), &data, &length)) {
    return;
  }
  ContextGL()->UniformMatrix4fv(location->Location(), length, transpose, data);
}

void WebGLRenderingContextBase::useProgram(WebGLProgram* program) {
  if (!ValidateNullableWebGLObject("useProgram", program))
    return;
  if (program && !program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "useProgram", "program not valid");
    return;
  }

  if (current_program_ != program) {
    if (current_program_)
      current_program_->OnDetached(ContextGL());
    current_program_ = program;
    ContextGL()->UseProgram(ObjectOrZero(program));
    if (program)
      program->OnAttached();
  }
}

void WebGLRenderingContextBase::validateProgram(WebGLProgram* program) {
  if (!ValidateWebGLProgramOrShader("validateProgram", program))
    return;
  ContextGL()->ValidateProgram(ObjectOrZero(program));
}

void WebGLRenderingContextBase::SetVertexAttribType(
    GLuint index,
    VertexAttribValueType type) {
  if (index < max_vertex_attribs_)
    vertex_attrib_type_[index] = type;
}

void WebGLRenderingContextBase::vertexAttrib1f(GLuint index, GLfloat v0) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib1f(index, v0);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib1fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 1) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib1fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib1fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib2f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib2f(index, v0, v1);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib2fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 2) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib2fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib2fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib3f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1,
                                               GLfloat v2) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib3f(index, v0, v1, v2);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib3fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 3) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib3fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib3fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib4f(GLuint index,
                                               GLfloat v0,
                                               GLfloat v1,
                                               GLfloat v2,
                                               GLfloat v3) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttrib4f(index, v0, v1, v2, v3);
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttrib4fv(GLuint index,
                                                base::span<const GLfloat> v) {
  if (isContextLost())
    return;
  if (v.size() < 4) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttrib4fv", "invalid array");
    return;
  }
  ContextGL()->VertexAttrib4fv(index, v.data());
  SetVertexAttribType(index, kFloat32ArrayType);
}

void WebGLRenderingContextBase::vertexAttribPointer(GLuint index,
                                                    GLint size,
                                                    GLenum type,
                                                    GLboolean normalized,
                                                    GLsizei stride,
                                                    int64_t offset) {
  if (isContextLost())
    return;
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribPointer",
                      "index out of range");
    return;
  }
  if (!ValidateValueFitNonNegInt32("vertexAttribPointer", "offset", offset))
    return;
  if (!bound_array_buffer_ && offset != 0) {
    SynthesizeGLError(GL_INVALID_OPERATION, "vertexAttribPointer",
                      "no ARRAY_BUFFER is bound and offset is non-zero");
    return;
  }

  bound_vertex_array_object_->SetArrayBufferForAttrib(
      index, bound_array_buffer_.Get());
  ContextGL()->VertexAttribPointer(
      index, size, type, normalized, stride,
      reinterpret_cast<void*>(static_cast<intptr_t>(offset)));
}

void WebGLRenderingContextBase::VertexAttribDivisorANGLE(GLuint index,
                                                         GLuint divisor) {
  if (isContextLost())
    return;

  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribDivisorANGLE",
                      "index out of range");
    return;
  }

  ContextGL()->VertexAttribDivisorANGLE(index, divisor);
}

void WebGLRenderingContextBase::viewport(GLint x,
                                         GLint y,
                                         GLsizei width,
                                         GLsizei height) {
  if (isContextLost())
    return;
  ContextGL()->Viewport(x, y, width, height);
}

// Added to provide a unified interface with CanvasRenderingContext2D. Prefer
// calling forceLostContext instead.
void WebGLRenderingContextBase::LoseContext(LostContextMode mode) {
  ForceLostContext(mode, kManual);
}

void WebGLRenderingContextBase::ForceLostContext(
    LostContextMode mode,
    AutoRecoveryMethod auto_recovery_method) {
  if (isContextLost()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "loseContext",
                      "context already lost");
    return;
  }

  context_group_->LoseContextGroup(mode, auto_recovery_method);
}

void WebGLRenderingContextBase::LoseContextImpl(
    WebGLRenderingContextBase::LostContextMode mode,
    AutoRecoveryMethod auto_recovery_method) {
  if (isContextLost())
    return;

  context_lost_mode_ = mode;
  DCHECK_NE(context_lost_mode_, kNotLostContext);
  auto_recovery_method_ = auto_recovery_method;

  // Lose all the extensions.
  for (ExtensionTracker* tracker : extensions_) {
    tracker->LoseExtension(false);
  }

  for (wtf_size_t i = 0; i < kWebGLExtensionNameCount; ++i)
    extension_enabled_[i] = false;

  // This resolver is non-null during a makeXRCompatible call, while waiting
  // for a response from the browser and XR process. If the WebGL context is
  // lost before we get a response, the resolver has to be rejected to be
  // be properly disposed of.
  xr_compatible_ = false;
  CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kInvalidStateError);

  RemoveAllCompressedTextureFormats();

  if (mode == kRealLostContext) {
    // If it is a real context loss, the signal needs to be propagated to the
    // context host so that it knows all resources are dropped.  Otherwise,
    // OffscreenCanvases on Workers would wait indefinitely for reources to be
    // returned by the compositor, which would stall requestAnimationFrame.
    Host()->NotifyGpuContextLost();

    // If the DrawingBuffer is destroyed during a real lost context event it
    // causes the CommandBufferProxy that the DrawingBuffer owns, which is what
    // issued the lost context event in the first place, to be destroyed before
    // the event is done being handled. This causes a crash when an outstanding
    // AutoLock goes out of scope. To avoid this, we create a no-op task to hold
    // a reference to the DrawingBuffer until this function is done executing.
    task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&WebGLRenderingContextBase::HoldReferenceToDrawingBuffer,
                      WrapWeakPersistent(this),
                      WTF::RetainedRef(drawing_buffer_)));
  }

  // Always destroy the context, regardless of context loss mode. This will
  // set drawing_buffer_ to null, but it won't actually be destroyed until the
  // above task is executed. drawing_buffer_ is recreated in the event that the
  // context is restored by MaybeRestoreContext. If this was a real lost context
  // the OpenGL calls done during DrawingBuffer destruction will be ignored.
  DestroyContext();

  ConsoleDisplayPreference display =
      (mode == kRealLostContext) ? kDisplayInConsole : kDontDisplayInConsole;
  SynthesizeGLError(GC3D_CONTEXT_LOST_WEBGL, "loseContext", "context lost",
                    display);

  // Don't allow restoration unless the context lost event has both been
  // dispatched and its default behavior prevented.
  restore_allowed_ = false;
  DeactivateContext(this);
  if (auto_recovery_method_ == kWhenAvailable)
    AddToEvictedList(this);

  // Always defer the dispatch of the context lost event, to implement
  // the spec behavior of queueing a task.
  dispatch_context_lost_event_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void WebGLRenderingContextBase::HoldReferenceToDrawingBuffer(DrawingBuffer*) {
  // This function intentionally left blank.
}

void WebGLRenderingContextBase::ForceRestoreContext() {
  if (!isContextLost()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "restoreContext",
                      "context not lost");
    return;
  }

  if (!restore_allowed_) {
    if (context_lost_mode_ == kWebGLLoseContextLostContext)
      SynthesizeGLError(GL_INVALID_OPERATION, "restoreContext",
                        "context restoration not allowed");
    return;
  }

  if (!restore_timer_.IsActive())
    restore_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

uint32_t WebGLRenderingContextBase::NumberOfContextLosses() const {
  return context_group_->NumberOfContextLosses();
}

cc::Layer* WebGLRenderingContextBase::CcLayer() const {
  return isContextLost() ? nullptr : GetDrawingBuffer()->CcLayer();
}

void WebGLRenderingContextBase::SetHdrMetadata(
    const gfx::HDRMetadata& hdr_metadata) {
  if (!isContextLost() && GetDrawingBuffer()) {
    GetDrawingBuffer()->SetHdrMetadata(hdr_metadata);
  }
}

void WebGLRenderingContextBase::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (!isContextLost() && GetDrawingBuffer()) {
    GetDrawingBuffer()->SetFilterQuality(filter_quality);
  }
}

Extensions3DUtil* WebGLRenderingContextBase::ExtensionsUtil() {
  if (!extensions_util_) {
    gpu::gles2::GLES2Interface* gl = ContextGL();
    extensions_util_ = Extensions3DUtil::Create(gl);
    // The only reason the ExtensionsUtil should be invalid is if the gl context
    // is lost.
    DCHECK(extensions_util_->IsValid() ||
           gl->GetGraphicsResetStatusKHR() != GL_NO_ERROR);
  }
  return extensions_util_.get();
}

void WebGLRenderingContextBase::Stop() {
  if (!isContextLost()) {
    // Never attempt to restore the context because the page is being torn down.
    ForceLostContext(kSyntheticLostContext, kManual);
  }
}

void WebGLRenderingContextBase::
    DrawingBufferClientInterruptPixelLocalStorage() {
  if (destruction_in_progress_) {
    return;
  }
  if (!ContextGL()) {
    return;
  }
  if (!has_activated_pixel_local_storage_) {
    return;
  }
  ContextGL()->FramebufferPixelLocalStorageInterruptANGLE();
}

void WebGLRenderingContextBase::DrawingBufferClientRestorePixelLocalStorage() {
  if (destruction_in_progress_) {
    return;
  }
  if (!ContextGL()) {
    return;
  }
  if (!has_activated_pixel_local_storage_) {
    return;
  }
  ContextGL()->FramebufferPixelLocalStorageRestoreANGLE();
}

bool WebGLRenderingContextBase::DrawingBufferClientIsBoundForDraw() {
  return !framebuffer_binding_;
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreScissorTest() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  if (scissor_enabled_)
    ContextGL()->Enable(GL_SCISSOR_TEST);
  else
    ContextGL()->Disable(GL_SCISSOR_TEST);
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreMaskAndClearValues() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  bool color_mask_alpha =
      color_mask_[3] && active_scoped_rgb_emulation_color_masks_ == 0;
  if (ExtensionEnabled(kOESDrawBuffersIndexedName)) {
    ContextGL()->ColorMaskiOES(0, color_mask_[0], color_mask_[1],
                               color_mask_[2], color_mask_alpha);
  } else {
    ContextGL()->ColorMask(color_mask_[0], color_mask_[1], color_mask_[2],
                           color_mask_alpha);
  }
  ContextGL()->DepthMask(depth_mask_);
  ContextGL()->StencilMaskSeparate(GL_FRONT, stencil_mask_);

  ContextGL()->ClearColor(clear_color_[0], clear_color_[1], clear_color_[2],
                          clear_color_[3]);
  ContextGL()->ClearDepthf(clear_depth_);
  ContextGL()->ClearStencil(clear_stencil_);
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelPackParameters() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->PixelStorei(GL_PACK_ALIGNMENT, pack_alignment_);
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreTexture2DBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentTexture2D();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestoreTextureCubeMapBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentTextureCubeMap();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestoreRenderbufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->BindRenderbuffer(GL_RENDERBUFFER,
                                ObjectOrZero(renderbuffer_binding_.Get()));
}

void WebGLRenderingContextBase::DrawingBufferClientRestoreFramebufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  RestoreCurrentFramebuffer();
}

void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelUnpackBufferBinding() {}
void WebGLRenderingContextBase::
    DrawingBufferClientRestorePixelPackBufferBinding() {}

bool WebGLRenderingContextBase::
    DrawingBufferClientUserAllocatedMultisampledRenderbuffers() {
  return number_of_user_allocated_multisampled_renderbuffers_ > 0;
}

void WebGLRenderingContextBase::
    DrawingBufferClientForceLostContextWithAutoRecovery(const char* reason) {
  ForceLostContext(WebGLRenderingContextBase::kSyntheticLostContext,
                   WebGLRenderingContextBase::kAuto);
  if (reason) {
    PrintWarningToConsole(reason);
  }
}

ScriptValue WebGLRenderingContextBase::GetBooleanParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLboolean value = 0;
  if (!isContextLost())
    ContextGL()->GetBooleanv(pname, &value);
  return WebGLAny(script_state, static_cast<bool>(value));
}

ScriptValue WebGLRenderingContextBase::GetBooleanArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  if (pname != GL_COLOR_WRITEMASK) {
    NOTIMPLEMENTED();
    return WebGLAny(script_state, nullptr, 0);
  }
  std::array<GLboolean, 4> value = {0};
  if (!isContextLost()) {
    ContextGL()->GetBooleanv(pname, value.data());
  }
  std::array<bool, 4> bool_value = {};
  for (int ii = 0; ii < 4; ++ii)
    bool_value[ii] = static_cast<bool>(value[ii]);
  return WebGLAny(script_state, bool_value.data(), 4);
}

ScriptValue WebGLRenderingContextBase::GetFloatParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLfloat value = 0;
  if (!isContextLost())
    ContextGL()->GetFloatv(pname, &value);
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kWebGLParameter)) {
    RecordIdentifiableGLParameterDigest(pname, value);
  }
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetIntParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint value = 0;
  if (!isContextLost()) {
    ContextGL()->GetIntegerv(pname, &value);
    switch (pname) {
      case GL_IMPLEMENTATION_COLOR_READ_FORMAT:
      case GL_IMPLEMENTATION_COLOR_READ_TYPE:
        if (value == 0) {
          // This indicates read framebuffer is incomplete and an
          // INVALID_OPERATION has been generated.
          return ScriptValue::CreateNull(script_state->GetIsolate());
        }
        break;
      default:
        break;
    }
  }
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kWebGLParameter)) {
    RecordIdentifiableGLParameterDigest(pname, value);
  }
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetInt64Parameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint64 value = 0;
  if (!isContextLost())
    ContextGL()->GetInteger64v(pname, &value);
  return WebGLAny(script_state, value);
}

ScriptValue WebGLRenderingContextBase::GetUnsignedIntParameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint value = 0;
  if (!isContextLost())
    ContextGL()->GetIntegerv(pname, &value);
  return WebGLAny(script_state, static_cast<unsigned>(value));
}

ScriptValue WebGLRenderingContextBase::GetWebGLFloatArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  std::array<GLfloat, 4> value = {0};
  if (!isContextLost())
    ContextGL()->GetFloatv(pname, value.data());
  unsigned length = 0;
  switch (pname) {
    case GL_ALIASED_POINT_SIZE_RANGE:
    case GL_ALIASED_LINE_WIDTH_RANGE:
    case GL_DEPTH_RANGE:
      length = 2;
      break;
    case GL_BLEND_COLOR:
    case GL_COLOR_CLEAR_VALUE:
      length = 4;
      break;
    default:
      NOTIMPLEMENTED();
  }
  if (ShouldMeasureGLParam(pname)) {
    blink::IdentifiableTokenBuilder builder;
    for (unsigned i = 0; i < length; i++) {
      builder.AddValue(value[i]);
    }
    RecordIdentifiableGLParameterDigest(pname, builder.GetToken());
  }
  return WebGLAny(script_state,
                  DOMFloat32Array::Create(base::span(value).first(length)));
}

ScriptValue WebGLRenderingContextBase::GetWebGLIntArrayParameter(
    ScriptState* script_state,
    GLenum pname) {
  std::array<GLint, 4> value = {0};
  if (!isContextLost())
    ContextGL()->GetIntegerv(pname, value.data());
  unsigned length = 0;
  switch (pname) {
    case GL_MAX_VIEWPORT_DIMS:
      length = 2;
      break;
    case GL_SCISSOR_BOX:
    case GL_VIEWPORT:
      length = 4;
      break;
    default:
      NOTIMPLEMENTED();
  }
  if (ShouldMeasureGLParam(pname)) {
    blink::IdentifiableTokenBuilder builder;
    for (unsigned i = 0; i < length; i++) {
      builder.AddValue(value[i]);
    }
    RecordIdentifiableGLParameterDigest(pname, builder.GetToken());
  }
  return WebGLAny(script_state,
                  DOMInt32Array::Create(base::span(value).first(length)));
}

WebGLTexture* WebGLRenderingContextBase::ValidateTexture2DBinding(
    const char* function_name,
    GLenum target,
    bool validate_opaque_textures) {
  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D:
      tex = texture_units_[active_texture_unit_].texture2d_binding_.Get();
      break;
    case GL_TEXTURE_CUBE_MAP_POSITIVE_X:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_X:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Y:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Y:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Z:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Z:
      tex =
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid texture target");
      return nullptr;
  }
  if (!tex) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no texture bound to target");
  } else if (validate_opaque_textures && tex->IsOpaqueTexture()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "cannot invoke function with an opaque texture");
    return nullptr;
  }
  return tex;
}

WebGLTexture* WebGLRenderingContextBase::ValidateTextureBinding(
    const char* function_name,
    GLenum target) {
  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D:
      tex = texture_units_[active_texture_unit_].texture2d_binding_.Get();
      break;
    case GL_TEXTURE_CUBE_MAP:
      tex =
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get();
      break;
    case GL_TEXTURE_3D:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "invalid texture target");
        return nullptr;
      }
      tex = texture_units_[active_texture_unit_].texture3d_binding_.Get();
      break;
    case GL_TEXTURE_2D_ARRAY:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "invalid texture target");
        return nullptr;
      }
      tex = texture_units_[active_texture_unit_].texture2d_array_binding_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid texture target");
      return nullptr;
  }
  if (!tex) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no texture bound to target");
  }
  return tex;
}

bool WebGLRenderingContextBase::ValidateLocationLength(
    const char* function_name,
    const String& string) {
  const unsigned max_web_gl_location_length = GetMaxWebGLLocationLength();
  if (string.length() > max_web_gl_location_length) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "location length > 256");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateSize(const char* function_name,
                                             GLint x,
                                             GLint y,
                                             GLint z) {
  if (x < 0 || y < 0 || z < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "size < 0");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateCharacter(unsigned char c) {
  // Printing characters are valid except " $ ` @ \ ' DEL.
  if (c >= 32 && c <= 126 && c != '"' && c != '$' && c != '`' && c != '@' &&
      c != '\\' && c != '\'')
    return true;
  // Horizontal tab, line feed, vertical tab, form feed, carriage return
  // are also valid.
  if (c >= 9 && c <= 13)
    return true;
  return false;
}

bool WebGLRenderingContextBase::ValidateString(const char* function_name,
                                               const String& string) {
  for (wtf_size_t i = 0; i < string.length(); ++i) {
    if (!ValidateCharacter(string[i])) {
      SynthesizeGLError(GL_INVALID_VALUE, function_name, "string not ASCII");
      return false;
    }
  }
  return true;
}

bool WebGLRenderingContextBase::IsPrefixReserved(const String& name) {
  if (name.StartsWith("gl_") || name.StartsWith("webgl_") ||
      name.StartsWith("_webgl_"))
    return true;
  return false;
}

bool WebGLRenderingContextBase::ValidateShaderType(const char* function_name,
                                                   GLenum shader_type) {
  switch (shader_type) {
    case GL_VERTEX_SHADER:
    case GL_FRAGMENT_SHADER:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid shader type");
      return false;
  }
}

void WebGLRenderingContextBase::AddExtensionSupportedFormatsTypes() {
  if (!is_oes_texture_float_formats_types_added_ &&
      ExtensionEnabled(kOESTextureFloatName)) {
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesOESTexFloat);
    ADD_VALUES_TO_SET(supported_tex_image_source_types_,
                      kSupportedTypesOESTexFloat);
    is_oes_texture_float_formats_types_added_ = true;
  }

  if (!is_oes_texture_half_float_formats_types_added_ &&
      ExtensionEnabled(kOESTextureHalfFloatName)) {
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesOESTexHalfFloat);
    ADD_VALUES_TO_SET(supported_tex_image_source_types_,
                      kSupportedTypesOESTexHalfFloat);
    is_oes_texture_half_float_formats_types_added_ = true;
  }

  if (!is_web_gl_depth_texture_formats_types_added_ &&
      ExtensionEnabled(kWebGLDepthTextureName)) {
    ADD_VALUES_TO_SET(supported_internal_formats_,
                      kSupportedInternalFormatsOESDepthTex);
    ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                      kSupportedInternalFormatsOESDepthTex);
    ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsOESDepthTex);
    ADD_VALUES_TO_SET(supported_tex_image_source_formats_,
                      kSupportedFormatsOESDepthTex);
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesOESDepthTex);
    ADD_VALUES_TO_SET(supported_tex_image_source_types_,
                      kSupportedTypesOESDepthTex);
    is_web_gl_depth_texture_formats_types_added_ = true;
  }

  if (!is_ext_srgb_formats_types_added_ && ExtensionEnabled(kEXTsRGBName)) {
    ADD_VALUES_TO_SET(supported_internal_formats_,
                      kSupportedInternalFormatsEXTsRGB);
    ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                      kSupportedInternalFormatsEXTsRGB);
    ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsEXTsRGB);
    ADD_VALUES_TO_SET(supported_tex_image_source_formats_,
                      kSupportedFormatsEXTsRGB);
    is_ext_srgb_formats_types_added_ = true;
  }
}

void WebGLRenderingContextBase::AddExtensionSupportedFormatsTypesWebGL2() {
  if (!is_ext_texture_norm16_added_ &&
      ExtensionEnabled(kEXTTextureNorm16Name)) {
    ADD_VALUES_TO_SET(supported_internal_formats_,
                      kSupportedInternalFormatsEXTTextureNorm16ES3);
    ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                      kSupportedInternalFormatsEXTTextureNorm16ES3);
    ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsEXTTextureNorm16ES3);
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesEXTTextureNorm16ES3);
    is_ext_texture_norm16_added_ = true;
  }
}

bool WebGLRenderingContextBase::ValidateTexImageSourceFormatAndType(
    const TexImageParams& params) {
  const char* function_name = GetTexImageFunctionName(params.function_id);

  if (!is_web_gl2_tex_image_source_formats_types_added_ && IsWebGL2()) {
    ADD_VALUES_TO_SET(supported_tex_image_source_internal_formats_,
                      kSupportedInternalFormatsTexImageSourceES3);
    ADD_VALUES_TO_SET(supported_tex_image_source_formats_,
                      kSupportedFormatsTexImageSourceES3);
    ADD_VALUES_TO_SET(supported_tex_image_source_types_,
                      kSupportedTypesTexImageSourceES3);
    is_web_gl2_tex_image_source_formats_types_added_ = true;
  }

  if (!IsWebGL2()) {
    AddExtensionSupportedFormatsTypes();
  } else {
    AddExtensionSupportedFormatsTypesWebGL2();
  }

  if (params.internalformat != 0 &&
      !base::Contains(supported_tex_image_source_internal_formats_,
                      params.internalformat)) {
    if (GetTexImageFunctionType(params.function_id) == kTexImage) {
      SynthesizeGLError(GL_INVALID_VALUE, function_name,
                        "invalid internalformat");
    } else {
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid internalformat");
    }
    return false;
  }
  if (!base::Contains(supported_tex_image_source_formats_, params.format)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid format");
    return false;
  }
  if (!base::Contains(supported_tex_image_source_types_, params.type)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid type");
    return false;
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateTexFuncFormatAndType(
    const TexImageParams& params) {
  const char* function_name = GetTexImageFunctionName(params.function_id);

  if (!is_web_gl2_formats_types_added_ && IsWebGL2()) {
    ADD_VALUES_TO_SET(supported_internal_formats_,
                      kSupportedInternalFormatsES3);
    ADD_VALUES_TO_SET(supported_internal_formats_,
                      kSupportedInternalFormatsTexImageES3);
    ADD_VALUES_TO_SET(supported_formats_, kSupportedFormatsES3);
    ADD_VALUES_TO_SET(supported_types_, kSupportedTypesES3);
    is_web_gl2_formats_types_added_ = true;
  }

  if (!IsWebGL2()) {
    AddExtensionSupportedFormatsTypes();
  } else {
    AddExtensionSupportedFormatsTypesWebGL2();
  }

  if (params.internalformat != 0 &&
      !base::Contains(supported_internal_formats_, params.internalformat)) {
    if (GetTexImageFunctionType(params.function_id) == kTexImage) {
      if (compressed_texture_formats_.Contains(
              static_cast<GLenum>(params.internalformat))) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "compressed texture formats are not accepted");
      } else {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "invalid internalformat");
      }
    } else {
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid internalformat");
    }
    return false;
  }
  if (!base::Contains(supported_formats_, params.format)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid format");
    return false;
  }
  if (!base::Contains(supported_types_, params.type)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid type");
    return false;
  }

  if (params.format == GL_DEPTH_COMPONENT && params.level > 0 && !IsWebGL2()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "level must be 0 for DEPTH_COMPONENT format");
    return false;
  }
  if (params.format == GL_DEPTH_STENCIL_OES && params.level > 0 &&
      !IsWebGL2()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "level must be 0 for DEPTH_STENCIL format");
    return false;
  }

  return true;
}

GLint WebGLRenderingContextBase::GetMaxTextureLevelForTarget(GLenum target) {
  switch (target) {
    case GL_TEXTURE_2D:
      return max_texture_level_;
    case GL_TEXTURE_CUBE_MAP:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_X:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_X:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Y:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Y:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Z:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Z:
      return max_cube_map_texture_level_;
  }
  return 0;
}

bool WebGLRenderingContextBase::ValidateTexFuncLevel(const char* function_name,
                                                     GLenum target,
                                                     GLint level) {
  if (level < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "level < 0");
    return false;
  }
  GLint max_level = GetMaxTextureLevelForTarget(target);
  if (max_level && level >= max_level) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "level out of range");
    return false;
  }
  // This function only checks if level is legal, so we return true and don't
  // generate INVALID_ENUM if target is illegal.
  return true;
}

bool WebGLRenderingContextBase::ValidateTexFuncDimensions(
    const char* function_name,
    TexImageFunctionType function_type,
    GLenum target,
    GLint level,
    GLsizei width,
    GLsizei height,
    GLsizei depth) {
  if (width < 0 || height < 0 || depth < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, functi
```