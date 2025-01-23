Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium WebGL implementation. They are particularly interested in:

1. **General Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and Data Flow:**  Can we infer input/output based on the code?
4. **Common User Errors:** What mistakes might a developer make that would lead to this code being executed?
5. **Debugging Context:** How does a user's actions in a web browser lead to this code being reached?
6. **Summary of Functionality:**  A concise overview of the code's purpose.

Since this is part 3 of 11, it's likely this file handles a subset of the WebGL rendering context's responsibilities.

**Plan:**

1. **Analyze the functions:** Go through each function in the provided snippet and determine its purpose based on its name, parameters, and the OpenGL calls it makes.
2. **Identify web technology links:** Look for functions that directly relate to concepts in JavaScript WebGL APIs (like `clear`, `colorMask`, `bindTexture`, etc.) and how they might affect the rendering pipeline represented by this C++ code.
3. **Infer logic and data flow:**  For functions that perform operations, try to understand what data they take as input (e.g., clear colors, masks, texture data) and what they output (e.g., modifying OpenGL state, potentially writing to the drawing buffer).
4. **Brainstorm potential user errors:** Think about common mistakes developers make when using the WebGL API that would trigger the execution of these functions.
5. **Trace user actions:**  Consider the sequence of user interactions and JavaScript calls that would eventually lead to the execution of these C++ functions within the browser's rendering process.
6. **Summarize the findings:** Condense the analysis into a brief overview of the code's main role.
```cpp
ely, but context was lost.
    return kSkipped;
  }

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);

  // Determine if it's possible to combine the clear the user asked for and this
  // clear.
  bool combined_clear =
      mask && !scissor_enabled_ && back_draw_buffer_ == GL_BACK;

  ContextGL()->Disable(GL_SCISSOR_TEST);
  if (combined_clear && (mask & GL_COLOR_BUFFER_BIT)) {
    ContextGL()->ClearColor(color_mask_[0] ? clear_color_[0] : 0,
                            color_mask_[1] ? clear_color_[1] : 0,
                            color_mask_[2] ? clear_color_[2] : 0,
                            color_mask_[3] ? clear_color_[3] : 0);
  } else {
    ContextGL()->ClearColor(0, 0, 0, 0);
  }

  GLbitfield clear_mask = GL_COLOR_BUFFER_BIT;

  const bool has_depth =
      CreationAttributes().depth && GetDrawingBuffer()->HasDepthBuffer();
  const bool has_stencil =
      CreationAttributes().stencil && GetDrawingBuffer()->HasStencilBuffer();

  if (has_depth) {
    if (!combined_clear || !depth_mask_ || !(mask & GL_DEPTH_BUFFER_BIT))
      ContextGL()->ClearDepthf(1.0f);
    clear_mask |= GL_DEPTH_BUFFER_BIT;
    ContextGL()->DepthMask(true);
  }
  if (has_stencil || GetDrawingBuffer()->HasImplicitStencilBuffer()) {
    if (combined_clear && (mask & GL_STENCIL_BUFFER_BIT))
      ContextGL()->ClearStencil(clear_stencil_ & stencil_mask_);
    else
      ContextGL()->ClearStencil(0);
    clear_mask |= GL_STENCIL_BUFFER_BIT;
    ContextGL()->StencilMaskSeparate(GL_FRONT, 0xFFFFFFFF);
  }

  if (ExtensionEnabled(kOESDrawBuffersIndexedName)) {
    ContextGL()->ColorMaskiOES(
        0, true, true, true,
        !GetDrawingBuffer()->DefaultBufferRequiresAlphaChannelToBePreserved());
  } else {
    ContextGL()->ColorMask(
        true, true, true,
        !GetDrawingBuffer()->DefaultBufferRequiresAlphaChannelToBePreserved());
  }
  {
    ScopedDisableRasterizerDiscard scoped_disable(this,
                                                  rasterizer_discard_enabled_);
    GetDrawingBuffer()->ClearFramebuffers(clear_mask);
  }

  // Call the DrawingBufferClient method to restore scissor test, mask, and
  // clear values, because we dirtied them above.
  DrawingBufferClientRestoreScissorTest();
  DrawingBufferClientRestoreMaskAndClearValues();

  GetDrawingBuffer()->SetBufferClearNeeded(false);

  return combined_clear ? kCombinedClear : kJustClear;
}

void WebGLRenderingContextBase::RestoreScissorEnabled() {
  if (isContextLost())
    return;

  if (scissor_enabled_) {
    ContextGL()->Enable(GL_SCISSOR_TEST);
  } else {
    ContextGL()->Disable(GL_SCISSOR_TEST);
  }
}

void WebGLRenderingContextBase::RestoreScissorBox() {
  if (isContextLost())
    return;

  ContextGL()->Scissor(scissor_box_[0], scissor_box_[1], scissor_box_[2],
                       scissor_box_[3]);
}

void WebGLRenderingContextBase::RestoreClearColor() {
  if (isContextLost())
    return;

  ContextGL()->ClearColor(clear_color_[0], clear_color_[1], clear_color_[2],
                          clear_color_[3]);
}

void WebGLRenderingContextBase::RestoreColorMask() {
  if (isContextLost())
    return;

  ContextGL()->ColorMask(color_mask_[0], color_mask_[1], color_mask_[2],
                         color_mask_[3]);
}

void WebGLRenderingContextBase::MarkLayerComposited() {
  if (!isContextLost())
    GetDrawingBuffer()->SetBufferClearNeeded(true);
}

bool WebGLRenderingContextBase::UsingSwapChain() const {
  return GetDrawingBuffer() && GetDrawingBuffer()->UsingSwapChain();
}

bool WebGLRenderingContextBase::IsOriginTopLeft() const {
  if (isContextLost())
    return false;
  return GetDrawingBuffer()->IsOriginTopLeft();
}

void WebGLRenderingContextBase::PageVisibilityChanged() {
  if (GetDrawingBuffer())
    GetDrawingBuffer()->SetIsInHiddenPage(!Host()->IsPageVisible());
}

bool WebGLRenderingContextBase::PaintRenderingResultsToCanvas(
    SourceDrawingBuffer source_buffer) {
  TRACE_EVENT0("blink",
               "WebGLRenderingContextBase::PaintRenderingResultsToCanvas");
  if (isContextLost() || !GetDrawingBuffer())
    return false;

  bool must_clear_now = ClearIfComposited(kClearCallerOther) != kSkipped;

  if (Host()->ResourceProvider() &&
      Host()->ResourceProvider()->Size() != GetDrawingBuffer()->Size()) {
    Host()->DiscardResourceProvider();
  }

  // The host's ResourceProvider is purged to save memory when the tab
  // is backgrounded.

  if (!must_paint_to_canvas_ && !must_clear_now && Host()->ResourceProvider())
    return false;

  must_paint_to_canvas_ = false;

  CanvasResourceProvider* resource_provider =
      Host()->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  if (!resource_provider)
    return false;

  if (Host()->LowLatencyEnabled() &&
      resource_provider->SupportsSingleBuffering()) {
    // It's possible single buffering isn't enabled yet because we haven't
    // finished the first frame e.g. this gets called first due to drawImage.
    resource_provider->TryEnableSingleBuffering();
    DCHECK(resource_provider->IsSingleBuffered());
    // Single buffered passthrough resource provider doesn't have backing
    // texture. We need to export the backbuffer mailbox directly without
    // copying.
    if (!resource_provider->ImportResource(
            GetDrawingBuffer()->ExportLowLatencyCanvasResource(
                resource_provider->CreateWeakPtr()))) {
      // This isn't expected to fail for single buffered resource provider.
      NOTREACHED();
    }
    return true;
  }

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  // TODO(sunnyps): Why is a texture restorer needed? See if it can be removed.
  ScopedTexture2DRestorer restorer(this);
  ScopedFramebufferRestorer fbo_restorer(this);

  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return false;
  if (!CopyRenderingResultsFromDrawingBuffer(Host()->ResourceProvider(),
                                             source_buffer)) {
    // CopyRenderingResultsFromDrawingBuffer handles both the
    // hardware-accelerated and software cases, so there is no
    // possible additional fallback for failures seen at this point.
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::CopyRenderingResultsFromDrawingBuffer(
    CanvasResourceProvider* resource_provider,
    SourceDrawingBuffer source_buffer) {
  DCHECK(resource_provider);
  DCHECK(!resource_provider->IsSingleBuffered());

  // Early-out if the context has been lost.
  if (!GetDrawingBuffer())
    return false;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedFramebufferRestorer fbo_restorer(this);
  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  // This is a no-op if already called higher up the stack from here.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return false;

  if (resource_provider->IsAccelerated()) {
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> shared_context_wrapper =
        SharedGpuContext::ContextProviderWrapper();
    if (!shared_context_wrapper) {
      return false;
    }
    gpu::raster::RasterInterface* raster_interface =
        shared_context_wrapper->ContextProvider()->RasterInterface();
    auto client_si =
        resource_provider->GetBackingClientSharedImageForOverwrite();
    if (!client_si) {
      return false;
    }

    // TODO(xlai): Flush should not be necessary if the synchronization in
    // CopyToPlatformTexture is done correctly. See crbug.com/794706.
    raster_interface->Flush();

    return GetDrawingBuffer()->CopyToPlatformMailbox(
        raster_interface, client_si->mailbox(), gfx::Point(0, 0),
        gfx::Rect(drawing_buffer_->Size()), source_buffer);
  }

  // As the resource provider is not accelerated, we don't need an accelerated
  // image.
  scoped_refptr<StaticBitmapImage> image =
      GetDrawingBuffer()->GetUnacceleratedStaticBitmapImage();

  if (!image || !image->PaintImageForCurrentFrame())
    return false;

  gfx::Rect src_rect(image->Size());
  gfx::Rect dest_rect(resource_provider->Size());
  cc::PaintFlags flags;
  flags.setBlendMode(SkBlendMode::kSrc);
  // We use this draw helper as we need to take into account the
  // ImageOrientation of the UnacceleratedStaticBitmapImage.
  ImageDrawOptions draw_options;
  draw_options.clamping_mode = Image::kDoNotClampImageToSourceRect;
  image->Draw(&resource_provider->Canvas(), flags, gfx::RectF(dest_rect),
              gfx::RectF(src_rect), draw_options);
  return true;
}

bool WebGLRenderingContextBase::CopyRenderingResultsToVideoFrame(
    WebGraphicsContext3DVideoFramePool* frame_pool,
    SourceDrawingBuffer src_buffer,
    const gfx::ColorSpace& dst_color_space,
    VideoFrameCopyCompletedCallback callback) {
  if (!frame_pool)
    return false;

  auto* drawing_buffer = GetDrawingBuffer();
  if (!drawing_buffer)
    return false;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedFramebufferRestorer fbo_restorer(this);
  if (!drawing_buffer->ResolveAndBindForReadAndDraw())
    return false;

  return drawing_buffer->CopyToVideoFrame(frame_pool, src_buffer,
                                          dst_color_space, std::move(callback));
}

gfx::Size WebGLRenderingContextBase::DrawingBufferSize() const {
  if (isContextLost())
    return gfx::Size(0, 0);
  return GetDrawingBuffer()->Size();
}

sk_sp<SkData> WebGLRenderingContextBase::PaintRenderingResultsToDataArray(
    SourceDrawingBuffer source_buffer) {
  if (isContextLost())
    return nullptr;
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ClearIfComposited(kClearCallerOther);
  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return nullptr;
  ScopedFramebufferRestorer restorer(this);
  return GetDrawingBuffer()->PaintRenderingResultsToDataArray(source_buffer);
}

void WebGLRenderingContextBase::Reshape(int width, int height) {
  if (isContextLost())
    return;

  GLint buffer = 0;
  if (IsWebGL2()) {
    // This query returns client side cached binding, so it's trivial.
    // If it changes in the future, such query is heavy and should be avoided.
    ContextGL()->GetIntegerv(GL_PIXEL_UNPACK_BUFFER_BINDING, &buffer);
    if (buffer) {
      ContextGL()->BindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
    }
  }

  // This is an approximation because at WebGLRenderingContextBase level we
  // don't know if the underlying FBO uses textures or renderbuffers.
  GLint max_size = std::min(max_texture_size_, max_renderbuffer_size_);
  GLint max_width = std::min(max_size, max_viewport_dims_[0]);
  GLint max_height = std::min(max_size, max_viewport_dims_[1]);
  width = Clamp(width, 1, max_width);
  height = Clamp(height, 1, max_height);

  // Limit drawing buffer area to the resolution of an 8K monitor to avoid
  // memory exhaustion. Width or height may be larger than that size as long as
  // it's within the max viewport dimensions and total area remains within the
  // limit. For example: 7680x4320 should be fine.
  const int kMaxArea = 5760 * 5760;
  int current_area = width * height;
  if (current_area > kMaxArea) {
    // If we've exceeded the area limit scale the buffer down, preserving
    // ascpect ratio, until it fits.
    float scale_factor =
        sqrtf(static_cast<float>(kMaxArea) / static_cast<float>(current_area));
    width = std::max(1, static_cast<int>(width * scale_factor));
    height = std::max(1, static_cast<int>(height * scale_factor));
  }

  // We don't have to mark the canvas as dirty, since the newly created image
  // buffer will also start off clear (and this matches what reshape will do).
  GetDrawingBuffer()->set_low_latency_enabled(Host()->LowLatencyEnabled());
  GetDrawingBuffer()->Resize(gfx::Size(width, height));
  GetDrawingBuffer()->MarkContentsChanged();

  if (buffer) {
    ContextGL()->BindBuffer(GL_PIXEL_UNPACK_BUFFER,
                            static_cast<GLuint>(buffer));
  }
}

int WebGLRenderingContextBase::drawingBufferWidth() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->Size().width();
}

int WebGLRenderingContextBase::drawingBufferHeight() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->Size().height();
}

GLenum WebGLRenderingContextBase::drawingBufferFormat() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->StorageFormat();
}

V8PredefinedColorSpace WebGLRenderingContextBase::drawingBufferColorSpace()
    const {
  return PredefinedColorSpaceToV8(drawing_buffer_color_space_);
}

void WebGLRenderingContextBase::setDrawingBufferColorSpace(
    const V8PredefinedColorSpace& v8_color_space,
    ExceptionState& exception_state) {
  // Some values for PredefinedColorSpace are supposed to be guarded behind
  // runtime flags. Use `ValidateAndConvertColorSpace` to throw an exception if
  // `v8_color_space` should not be exposed.
  PredefinedColorSpace color_space = PredefinedColorSpace::kSRGB;
  if (!ValidateAndConvertColorSpace(v8_color_space, color_space,
                                    exception_state)) {
    return;
  }
  if (drawing_buffer_color_space_ == color_space)
    return;
  drawing_buffer_color_space_ = color_space;
  if (GetDrawingBuffer())
    GetDrawingBuffer()->SetColorSpace(drawing_buffer_color_space_);
}

V8PredefinedColorSpace WebGLRenderingContextBase::unpackColorSpace() const {
  return PredefinedColorSpaceToV8(unpack_color_space_);
}

void WebGLRenderingContextBase::setUnpackColorSpace(
    const V8PredefinedColorSpace& v8_color_space,
    ExceptionState& exception_state) {
  PredefinedColorSpace color_space = PredefinedColorSpace::kSRGB;
  if (!ValidateAndConvertColorSpace(v8_color_space, color_space,
                                    exception_state)) {
    return;
  }
  NOTIMPLEMENTED();
  unpack_color_space_ = color_space;
}

void WebGLRenderingContextBase::activeTexture(GLenum texture) {
  if (isContextLost())
    return;
  if (texture - GL_TEXTURE0 >= texture_units_.size()) {
    SynthesizeGLError(GL_INVALID_ENUM, "activeTexture",
                      "texture unit out of range");
    return;
  }
  active_texture_unit_ = texture - GL_TEXTURE0;
  ContextGL()->ActiveTexture(texture);
}

void WebGLRenderingContextBase::attachShader(WebGLProgram* program,
                                             WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("attachShader", program) ||
      !ValidateWebGLProgramOrShader("attachShader", shader))
    return;
  if (!program->AttachShader(shader)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "attachShader",
                      "shader attachment already has shader");
    return;
  }
  ContextGL()->AttachShader(ObjectOrZero(program), ObjectOrZero(shader));
  shader->OnAttached();
}

void WebGLRenderingContextBase::bindAttribLocation(WebGLProgram* program,
                                                   GLuint index,
                                                   const String& name) {
  if (!ValidateWebGLProgramOrShader("bindAttribLocation", program))
    return;
  if (!ValidateLocationLength("bindAttribLocation", name))
    return;
  if (IsPrefixReserved(name)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindAttribLocation",
                      "reserved prefix");
    return;
  }
  ContextGL()->BindAttribLocation(ObjectOrZero(program), index,
                                  name.Utf8().c_str());
}

bool WebGLRenderingContextBase::ValidateAndUpdateBufferBindTarget(
    const char* function_name,
    GLenum target,
    WebGLBuffer* buffer) {
  if (!ValidateBufferTarget(function_name, target))
    return false;

  if (buffer && buffer->GetInitialTarget() &&
      buffer->GetInitialTarget() != target) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "buffers can not be used with multiple targets");
    return false;
  }

  switch (target) {
    case GL_ARRAY_BUFFER:
      bound_array_buffer_ = buffer;
      break;
    case GL_ELEMENT_ARRAY_BUFFER:
      bound_vertex_array_object_->SetElementArrayBuffer(buffer);
      break;
    default:
      NOTREACHED();
  }

  if (buffer && !buffer->GetInitialTarget())
    buffer->SetInitialTarget(target);
  return true;
}

void WebGLRenderingContextBase::bindBuffer(GLenum target, WebGLBuffer* buffer) {
  if (!ValidateNullableWebGLObject("bindBuffer", buffer))
    return;
  if (!ValidateAndUpdateBufferBindTarget("bindBuffer", target, buffer))
    return;
  ContextGL()->BindBuffer(target, ObjectOrZero(buffer));
}

void WebGLRenderingContextBase::bindFramebuffer(GLenum target,
                                                WebGLFramebuffer* buffer) {
  if (!ValidateNullableWebGLObject("bindFramebuffer", buffer))
    return;

  if (target != GL_FRAMEBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindFramebuffer", "invalid target");
    return;
  }

  SetFramebuffer(target, buffer);
}

void WebGLRenderingContextBase::bindRenderbuffer(
    GLenum target,
    WebGLRenderbuffer* render_buffer) {
  if (!ValidateNullableWebGLObject("bindRenderbuffer", render_buffer))
    return;
  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindRenderbuffer", "invalid target");
    return;
  }
  renderbuffer_binding_ = render_buffer;
  ContextGL()->BindRenderbuffer(target, ObjectOrZero(render_buffer));
  if (render_buffer)
    render_buffer->SetHasEverBeenBound();
}

void WebGLRenderingContextBase::bindTexture(GLenum target,
                                            WebGLTexture* texture) {
  if (!ValidateNullableWebGLObject("bindTexture", texture))
    return;
  if (texture && texture->GetTarget() && texture->GetTarget() != target) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindTexture",
                      "textures can not be used with multiple targets");
    return;
  }

  if (target == GL_TEXTURE_2D) {
    texture_units_[active_texture_unit_].texture2d_binding_ = texture;
  } else if (target == GL_TEXTURE_CUBE_MAP) {
    texture_units_[active_texture_unit_].texture_cube_map_binding_ = texture;
  } else if (IsWebGL2() && target == GL_TEXTURE_2D_ARRAY) {
    texture_units_[active_texture_unit_].texture2d_array_binding_ = texture;
  } else if (IsWebGL2() && target == GL_TEXTURE_3D) {
    texture_units_[active_texture_unit_].texture3d_binding_ = texture;
  } else if (target == GL_TEXTURE_EXTERNAL_OES) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture",
                      "GL_TEXTURE_EXTERNAL_OES textures not supported");
    return;
  } else if (target == GL_TEXTURE_RECTANGLE_ARB) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture",
                      "GL_TEXTURE_RECTANGLE_ARB textures not supported");
    return;
  } else {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture", "invalid target");
    return;
  }

  ContextGL()->BindTexture(target, ObjectOrZero(texture));
  if (texture) {
    texture->SetTarget(target);
    one_plus_max_non_default_texture_unit_ =
        max(active_texture_unit_ + 1, one_plus_max_non_default_texture_unit_);
  } else {
    // If the disabled index is the current maximum, trace backwards to find the
    // new max enabled texture index
    if (one_plus_max_non_default_texture_unit_ == active_texture_unit_ + 1) {
      FindNewMaxNonDefaultTextureUnit();
    }
  }

  // Note: previously we used to automatically set the TEXTURE_WRAP_R
  // repeat mode to CLAMP_TO_EDGE for cube map textures, because OpenGL
  // ES 2.0 doesn't expose this flag (a bug in the specification) and
  // otherwise the application has no control over the seams in this
  // dimension. However, it appears that supporting this properly on all
  // platforms is fairly involved (will require a HashMap from texture ID
  // in all ports), and we have not had any complaints, so the logic has
  // been removed.
}

void WebGLRenderingContextBase::blendColor(GLfloat red,
                                           GLfloat green,
                                           GLfloat blue,
                                           GLfloat alpha) {
  if (isContextLost())
    return;
  ContextGL()->BlendColor(red, green, blue, alpha);
}

void WebGLRenderingContextBase::blendEquation(GLenum mode) {
  if (isContextLost() || !ValidateBlendEquation("blendEquation", mode))
    return;
  ContextGL()->BlendEquation(mode);
}

void WebGLRenderingContextBase::blendEquationSeparate(GLenum mode_rgb,
                                                      GLenum mode_alpha) {
  if (isContextLost() ||
      !ValidateBlendEquation("blendEquationSeparate", mode_rgb) ||
      !ValidateBlendEquation("blendEquationSeparate", mode_alpha))
    return;
  ContextGL()->BlendEquationSeparate(mode_rgb, mode_alpha);
}

void WebGLRenderingContextBase::blendFunc(GLenum sfactor, GLenum dfactor) {
  if (isContextLost() ||
      !ValidateBlendFuncFactors("blendFunc", sfactor, dfactor))
    return;
  ContextGL()->BlendFunc(sfactor, dfactor);
}

void WebGLRenderingContextBase::blendFuncSeparate(GLenum src_rgb,
                                                  GLenum dst_rgb,
                                                  GLenum src_alpha,
                                                  GLenum dst_alpha) {
  // Note: Alpha does not have the same restrictions as RGB.
  if (isContextLost() ||
      !ValidateBlendFuncFactors("blendFuncSeparate", src_rgb, dst_rgb))
    return;

  if (!ValidateBlendFuncExtendedFactors("blendFuncSeparate", src_alpha,
                                        dst_alpha)) {
    return;
  }

  ContextGL()->BlendFuncSeparate(src_rgb, dst_rgb, src_alpha, dst_alpha);
}

bool WebGLRenderingContextBase::ValidateBufferDataBufferSize(
    const char* function_name,
    int64_t size) {
  if (size < 0) {
    String error_msg = "data size is invalid";
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  if (static_cast<size_t>(size) > kMaximumSupportedArrayBufferSize) {
    String error_msg = "data size exceeds the maximum supported size";
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  return true;
}

void WebGLRenderingContextBase::BufferDataImpl(GLenum target,
                                               int64_t size,
                                               const void* data,
                                               GLenum usage) {
  WebGLBuffer* buffer = ValidateBufferDataTarget("bufferData", target);
  if (!buffer)
    return;

  if (!ValidateBufferDataUsage("bufferData", usage))
    return;

  if (!ValidateValueFitNonNegInt32("bufferData", "size", size))
    return;

  if (!ValidateBufferDataBufferSize("bufferData", size))
    return;

  buffer->SetSize(size);

  ContextGL()->BufferData(target, static_cast<GLsizeiptr>(size), data, usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           int64_t size,
                                           GLenum usage) {
  if (isContextLost())
    return;
  BufferDataImpl(target, size, nullptr, usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           DOMArrayBufferBase* data,
                                           GLenum usage) {
  if (isContextLost())
    return;
  if (!data) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferData", "no data");
    return;
  }
  BufferDataImpl(target, data->ByteLength(), data->DataMaybeShared(), usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           MaybeShared<DOMArrayBufferView> data,
                                           GLenum usage) {
  if (isContextLost())
    return;
  DCHECK(data);
  BufferDataImpl(target, data->byteLength(), data->BaseAddressMaybeShared(),
                 usage);
}

void WebGLRenderingContextBase::BufferSubDataImpl(GLenum target,
                                                  int64_t offset,
                                                  int64_t size,
                                                  const void* data) {
  WebGLBuffer* buffer = ValidateBufferDataTarget("bufferSubData", target);
  if (!buffer)
    return;
  if (!ValidateValueFitNonNegInt32("bufferSubData", "offset", offset))
    return;
  if (!ValidateValueFitNonNegInt32("bufferSubData", "size", size))
    return;
  if (!ValidateBufferDataBufferSize("bufferSubData", size))
    return;

  if (!data)
    return;
  if (offset + static_cast<int64_t>(size) > buffer->GetSize()) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferSubData", "buffer overflow");
    return;
  }

  ContextGL()->BufferSubData(target, static_cast<GLintptr>(offset),
                             static_cast<GLintptr>(size), data);
}

void WebGLRenderingContextBase::bufferSubData(GLenum target,
                                              int64_t offset,
                                              base::span<const uint8_t> data) {
  if (isContextLost())
    return;
  BufferSubDataImpl(target, offset, data.size(), data.data());
}

bool WebGLRenderingContextBase::ValidateFramebufferTarget(GLenum target) {
  if (target == GL_FRAMEBUFFER)
    return true;
  return false;
}

WebGLFramebuffer* WebGLRenderingContextBase::GetFramebufferBinding(
    GLenum target) {
  if (target == GL_FRAMEBUFFER)
    return framebuffer_binding_.Get();
  return nullptr;
}

WebGLFramebuffer* WebGLRenderingContextBase::GetReadFramebufferBinding() {
  return framebuffer_binding_.Get();
}

GLenum WebGLRenderingContextBase::checkFramebufferStatus(GLenum target) {
  if (isContextLost())
    return GL_FRAMEBUFFER_UNSUPPORTED;
  if (!ValidateFramebufferTarget(target)) {
    SynthesizeGLError(GL_INVALID_ENUM, "checkFramebufferStatus",
                      "invalid target");
    return 0;
  }
  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (framebuffer_binding) {
    const char* reason = "framebuffer incomplete";
    GLenum status = framebuffer_binding->CheckDepthStencilStatus(&reason);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
      EmitGLWarning("checkFramebufferStatus", reason);
      return status;
    }
  }
  return ContextGL()->CheckFramebufferStatus(target);
}

void WebGLRenderingContextBase::clear(GLbitfield mask) {
  if (isContextLost())
    return;
  if (mask &
      ~(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT)) {
    SynthesizeGLError(GL_INVALID_VALUE, "clear", "invalid mask");
    return;
  }
  const char* reason = "framebuffer incomplete";
  if (framebuffer_binding_ && framebuffer_binding_->CheckDepthStencilStatus(
                                  &reason) != GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, "clear", reason);
    return;
  }

  if (!mask) {
    // Use OnErrorMessage because it's both rate-limited and obeys the
    // webGLErrorsToConsole setting.
    OnErrorMessage(
        "Performance warning: clear() called with no buffers in bitmask", 0);
    // Don't skip the call to ClearIfComposited below; it has side
    // effects even without the user requesting to clear any buffers.
  }

  ScopedRGBEmulationColorMask emulation_color_mask(this, color_mask_.data(),
                                                   drawing_buffer_.get());

  if (ClearIfComposited(kClearCallerDrawOrClear, mask) != kCombinedClear) {
    // If clearing the default back buffer's depth buffer, also clear the
    // stencil buffer, if one was allocated implicitly. This avoids performance
    // problems on some GPUs.
    if (!framebuffer_binding_ &&
        GetDrawingBuffer()->HasImplicitStencilBuffer() &&
        (mask & GL_DEPTH_BUFFER_BIT)) {
      // It shouldn't matter what value it's cleared to, since in other queries
      // in the API, we claim that the stencil buffer doesn't exist.
      mask |= GL_STENCIL_BUFFER_BIT;
    }
    ContextGL()->Clear(mask);
  }
  MarkContextChanged(kCanvasChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
}

void WebGLRenderingContextBase::clearColor(GLfloat r,
                                           GLfloat g,
                                           GLfloat b,
                                           GLfloat a) {
  if (isContextLost())
    return;
  if (std::isnan(r))
    r = 0;
  if (std::isnan(g))
    g = 0;
  if (std::isnan(b))
    b = 0;
  if (std::isnan(a))
    a = 1;
  clear
### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
ely, but context was lost.
    return kSkipped;
  }

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);

  // Determine if it's possible to combine the clear the user asked for and this
  // clear.
  bool combined_clear =
      mask && !scissor_enabled_ && back_draw_buffer_ == GL_BACK;

  ContextGL()->Disable(GL_SCISSOR_TEST);
  if (combined_clear && (mask & GL_COLOR_BUFFER_BIT)) {
    ContextGL()->ClearColor(color_mask_[0] ? clear_color_[0] : 0,
                            color_mask_[1] ? clear_color_[1] : 0,
                            color_mask_[2] ? clear_color_[2] : 0,
                            color_mask_[3] ? clear_color_[3] : 0);
  } else {
    ContextGL()->ClearColor(0, 0, 0, 0);
  }

  GLbitfield clear_mask = GL_COLOR_BUFFER_BIT;

  const bool has_depth =
      CreationAttributes().depth && GetDrawingBuffer()->HasDepthBuffer();
  const bool has_stencil =
      CreationAttributes().stencil && GetDrawingBuffer()->HasStencilBuffer();

  if (has_depth) {
    if (!combined_clear || !depth_mask_ || !(mask & GL_DEPTH_BUFFER_BIT))
      ContextGL()->ClearDepthf(1.0f);
    clear_mask |= GL_DEPTH_BUFFER_BIT;
    ContextGL()->DepthMask(true);
  }
  if (has_stencil || GetDrawingBuffer()->HasImplicitStencilBuffer()) {
    if (combined_clear && (mask & GL_STENCIL_BUFFER_BIT))
      ContextGL()->ClearStencil(clear_stencil_ & stencil_mask_);
    else
      ContextGL()->ClearStencil(0);
    clear_mask |= GL_STENCIL_BUFFER_BIT;
    ContextGL()->StencilMaskSeparate(GL_FRONT, 0xFFFFFFFF);
  }

  if (ExtensionEnabled(kOESDrawBuffersIndexedName)) {
    ContextGL()->ColorMaskiOES(
        0, true, true, true,
        !GetDrawingBuffer()->DefaultBufferRequiresAlphaChannelToBePreserved());
  } else {
    ContextGL()->ColorMask(
        true, true, true,
        !GetDrawingBuffer()->DefaultBufferRequiresAlphaChannelToBePreserved());
  }
  {
    ScopedDisableRasterizerDiscard scoped_disable(this,
                                                  rasterizer_discard_enabled_);
    GetDrawingBuffer()->ClearFramebuffers(clear_mask);
  }

  // Call the DrawingBufferClient method to restore scissor test, mask, and
  // clear values, because we dirtied them above.
  DrawingBufferClientRestoreScissorTest();
  DrawingBufferClientRestoreMaskAndClearValues();

  GetDrawingBuffer()->SetBufferClearNeeded(false);

  return combined_clear ? kCombinedClear : kJustClear;
}

void WebGLRenderingContextBase::RestoreScissorEnabled() {
  if (isContextLost())
    return;

  if (scissor_enabled_) {
    ContextGL()->Enable(GL_SCISSOR_TEST);
  } else {
    ContextGL()->Disable(GL_SCISSOR_TEST);
  }
}

void WebGLRenderingContextBase::RestoreScissorBox() {
  if (isContextLost())
    return;

  ContextGL()->Scissor(scissor_box_[0], scissor_box_[1], scissor_box_[2],
                       scissor_box_[3]);
}

void WebGLRenderingContextBase::RestoreClearColor() {
  if (isContextLost())
    return;

  ContextGL()->ClearColor(clear_color_[0], clear_color_[1], clear_color_[2],
                          clear_color_[3]);
}

void WebGLRenderingContextBase::RestoreColorMask() {
  if (isContextLost())
    return;

  ContextGL()->ColorMask(color_mask_[0], color_mask_[1], color_mask_[2],
                         color_mask_[3]);
}

void WebGLRenderingContextBase::MarkLayerComposited() {
  if (!isContextLost())
    GetDrawingBuffer()->SetBufferClearNeeded(true);
}

bool WebGLRenderingContextBase::UsingSwapChain() const {
  return GetDrawingBuffer() && GetDrawingBuffer()->UsingSwapChain();
}

bool WebGLRenderingContextBase::IsOriginTopLeft() const {
  if (isContextLost())
    return false;
  return GetDrawingBuffer()->IsOriginTopLeft();
}

void WebGLRenderingContextBase::PageVisibilityChanged() {
  if (GetDrawingBuffer())
    GetDrawingBuffer()->SetIsInHiddenPage(!Host()->IsPageVisible());
}

bool WebGLRenderingContextBase::PaintRenderingResultsToCanvas(
    SourceDrawingBuffer source_buffer) {
  TRACE_EVENT0("blink",
               "WebGLRenderingContextBase::PaintRenderingResultsToCanvas");
  if (isContextLost() || !GetDrawingBuffer())
    return false;

  bool must_clear_now = ClearIfComposited(kClearCallerOther) != kSkipped;

  if (Host()->ResourceProvider() &&
      Host()->ResourceProvider()->Size() != GetDrawingBuffer()->Size()) {
    Host()->DiscardResourceProvider();
  }

  // The host's ResourceProvider is purged to save memory when the tab
  // is backgrounded.

  if (!must_paint_to_canvas_ && !must_clear_now && Host()->ResourceProvider())
    return false;

  must_paint_to_canvas_ = false;

  CanvasResourceProvider* resource_provider =
      Host()->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  if (!resource_provider)
    return false;

  if (Host()->LowLatencyEnabled() &&
      resource_provider->SupportsSingleBuffering()) {
    // It's possible single buffering isn't enabled yet because we haven't
    // finished the first frame e.g. this gets called first due to drawImage.
    resource_provider->TryEnableSingleBuffering();
    DCHECK(resource_provider->IsSingleBuffered());
    // Single buffered passthrough resource provider doesn't have backing
    // texture. We need to export the backbuffer mailbox directly without
    // copying.
    if (!resource_provider->ImportResource(
            GetDrawingBuffer()->ExportLowLatencyCanvasResource(
                resource_provider->CreateWeakPtr()))) {
      // This isn't expected to fail for single buffered resource provider.
      NOTREACHED();
    }
    return true;
  }

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  // TODO(sunnyps): Why is a texture restorer needed? See if it can be removed.
  ScopedTexture2DRestorer restorer(this);
  ScopedFramebufferRestorer fbo_restorer(this);

  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return false;
  if (!CopyRenderingResultsFromDrawingBuffer(Host()->ResourceProvider(),
                                             source_buffer)) {
    // CopyRenderingResultsFromDrawingBuffer handles both the
    // hardware-accelerated and software cases, so there is no
    // possible additional fallback for failures seen at this point.
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::CopyRenderingResultsFromDrawingBuffer(
    CanvasResourceProvider* resource_provider,
    SourceDrawingBuffer source_buffer) {
  DCHECK(resource_provider);
  DCHECK(!resource_provider->IsSingleBuffered());

  // Early-out if the context has been lost.
  if (!GetDrawingBuffer())
    return false;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedFramebufferRestorer fbo_restorer(this);
  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  // This is a no-op if already called higher up the stack from here.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return false;

  if (resource_provider->IsAccelerated()) {
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> shared_context_wrapper =
        SharedGpuContext::ContextProviderWrapper();
    if (!shared_context_wrapper) {
      return false;
    }
    gpu::raster::RasterInterface* raster_interface =
        shared_context_wrapper->ContextProvider()->RasterInterface();
    auto client_si =
        resource_provider->GetBackingClientSharedImageForOverwrite();
    if (!client_si) {
      return false;
    }

    // TODO(xlai): Flush should not be necessary if the synchronization in
    // CopyToPlatformTexture is done correctly. See crbug.com/794706.
    raster_interface->Flush();

    return GetDrawingBuffer()->CopyToPlatformMailbox(
        raster_interface, client_si->mailbox(), gfx::Point(0, 0),
        gfx::Rect(drawing_buffer_->Size()), source_buffer);
  }

  // As the resource provider is not accelerated, we don't need an accelerated
  // image.
  scoped_refptr<StaticBitmapImage> image =
      GetDrawingBuffer()->GetUnacceleratedStaticBitmapImage();

  if (!image || !image->PaintImageForCurrentFrame())
    return false;

  gfx::Rect src_rect(image->Size());
  gfx::Rect dest_rect(resource_provider->Size());
  cc::PaintFlags flags;
  flags.setBlendMode(SkBlendMode::kSrc);
  // We use this draw helper as we need to take into account the
  // ImageOrientation of the UnacceleratedStaticBitmapImage.
  ImageDrawOptions draw_options;
  draw_options.clamping_mode = Image::kDoNotClampImageToSourceRect;
  image->Draw(&resource_provider->Canvas(), flags, gfx::RectF(dest_rect),
              gfx::RectF(src_rect), draw_options);
  return true;
}

bool WebGLRenderingContextBase::CopyRenderingResultsToVideoFrame(
    WebGraphicsContext3DVideoFramePool* frame_pool,
    SourceDrawingBuffer src_buffer,
    const gfx::ColorSpace& dst_color_space,
    VideoFrameCopyCompletedCallback callback) {
  if (!frame_pool)
    return false;

  auto* drawing_buffer = GetDrawingBuffer();
  if (!drawing_buffer)
    return false;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedFramebufferRestorer fbo_restorer(this);
  if (!drawing_buffer->ResolveAndBindForReadAndDraw())
    return false;

  return drawing_buffer->CopyToVideoFrame(frame_pool, src_buffer,
                                          dst_color_space, std::move(callback));
}

gfx::Size WebGLRenderingContextBase::DrawingBufferSize() const {
  if (isContextLost())
    return gfx::Size(0, 0);
  return GetDrawingBuffer()->Size();
}

sk_sp<SkData> WebGLRenderingContextBase::PaintRenderingResultsToDataArray(
    SourceDrawingBuffer source_buffer) {
  if (isContextLost())
    return nullptr;
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ClearIfComposited(kClearCallerOther);
  // In rare situations on macOS the drawing buffer can be destroyed
  // during the resolve process, specifically during automatic
  // graphics switching. Guard against this.
  if (!GetDrawingBuffer()->ResolveAndBindForReadAndDraw())
    return nullptr;
  ScopedFramebufferRestorer restorer(this);
  return GetDrawingBuffer()->PaintRenderingResultsToDataArray(source_buffer);
}

void WebGLRenderingContextBase::Reshape(int width, int height) {
  if (isContextLost())
    return;

  GLint buffer = 0;
  if (IsWebGL2()) {
    // This query returns client side cached binding, so it's trivial.
    // If it changes in the future, such query is heavy and should be avoided.
    ContextGL()->GetIntegerv(GL_PIXEL_UNPACK_BUFFER_BINDING, &buffer);
    if (buffer) {
      ContextGL()->BindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
    }
  }

  // This is an approximation because at WebGLRenderingContextBase level we
  // don't know if the underlying FBO uses textures or renderbuffers.
  GLint max_size = std::min(max_texture_size_, max_renderbuffer_size_);
  GLint max_width = std::min(max_size, max_viewport_dims_[0]);
  GLint max_height = std::min(max_size, max_viewport_dims_[1]);
  width = Clamp(width, 1, max_width);
  height = Clamp(height, 1, max_height);

  // Limit drawing buffer area to the resolution of an 8K monitor to avoid
  // memory exhaustion.  Width or height may be larger than that size as long as
  // it's within the max viewport dimensions and total area remains within the
  // limit. For example: 7680x4320 should be fine.
  const int kMaxArea = 5760 * 5760;
  int current_area = width * height;
  if (current_area > kMaxArea) {
    // If we've exceeded the area limit scale the buffer down, preserving
    // ascpect ratio, until it fits.
    float scale_factor =
        sqrtf(static_cast<float>(kMaxArea) / static_cast<float>(current_area));
    width = std::max(1, static_cast<int>(width * scale_factor));
    height = std::max(1, static_cast<int>(height * scale_factor));
  }

  // We don't have to mark the canvas as dirty, since the newly created image
  // buffer will also start off clear (and this matches what reshape will do).
  GetDrawingBuffer()->set_low_latency_enabled(Host()->LowLatencyEnabled());
  GetDrawingBuffer()->Resize(gfx::Size(width, height));
  GetDrawingBuffer()->MarkContentsChanged();

  if (buffer) {
    ContextGL()->BindBuffer(GL_PIXEL_UNPACK_BUFFER,
                            static_cast<GLuint>(buffer));
  }
}

int WebGLRenderingContextBase::drawingBufferWidth() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->Size().width();
}

int WebGLRenderingContextBase::drawingBufferHeight() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->Size().height();
}

GLenum WebGLRenderingContextBase::drawingBufferFormat() const {
  return isContextLost() ? 0 : GetDrawingBuffer()->StorageFormat();
}

V8PredefinedColorSpace WebGLRenderingContextBase::drawingBufferColorSpace()
    const {
  return PredefinedColorSpaceToV8(drawing_buffer_color_space_);
}

void WebGLRenderingContextBase::setDrawingBufferColorSpace(
    const V8PredefinedColorSpace& v8_color_space,
    ExceptionState& exception_state) {
  // Some values for PredefinedColorSpace are supposed to be guarded behind
  // runtime flags. Use `ValidateAndConvertColorSpace` to throw an exception if
  // `v8_color_space` should not be exposed.
  PredefinedColorSpace color_space = PredefinedColorSpace::kSRGB;
  if (!ValidateAndConvertColorSpace(v8_color_space, color_space,
                                    exception_state)) {
    return;
  }
  if (drawing_buffer_color_space_ == color_space)
    return;
  drawing_buffer_color_space_ = color_space;
  if (GetDrawingBuffer())
    GetDrawingBuffer()->SetColorSpace(drawing_buffer_color_space_);
}

V8PredefinedColorSpace WebGLRenderingContextBase::unpackColorSpace() const {
  return PredefinedColorSpaceToV8(unpack_color_space_);
}

void WebGLRenderingContextBase::setUnpackColorSpace(
    const V8PredefinedColorSpace& v8_color_space,
    ExceptionState& exception_state) {
  PredefinedColorSpace color_space = PredefinedColorSpace::kSRGB;
  if (!ValidateAndConvertColorSpace(v8_color_space, color_space,
                                    exception_state)) {
    return;
  }
  NOTIMPLEMENTED();
  unpack_color_space_ = color_space;
}

void WebGLRenderingContextBase::activeTexture(GLenum texture) {
  if (isContextLost())
    return;
  if (texture - GL_TEXTURE0 >= texture_units_.size()) {
    SynthesizeGLError(GL_INVALID_ENUM, "activeTexture",
                      "texture unit out of range");
    return;
  }
  active_texture_unit_ = texture - GL_TEXTURE0;
  ContextGL()->ActiveTexture(texture);
}

void WebGLRenderingContextBase::attachShader(WebGLProgram* program,
                                             WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("attachShader", program) ||
      !ValidateWebGLProgramOrShader("attachShader", shader))
    return;
  if (!program->AttachShader(shader)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "attachShader",
                      "shader attachment already has shader");
    return;
  }
  ContextGL()->AttachShader(ObjectOrZero(program), ObjectOrZero(shader));
  shader->OnAttached();
}

void WebGLRenderingContextBase::bindAttribLocation(WebGLProgram* program,
                                                   GLuint index,
                                                   const String& name) {
  if (!ValidateWebGLProgramOrShader("bindAttribLocation", program))
    return;
  if (!ValidateLocationLength("bindAttribLocation", name))
    return;
  if (IsPrefixReserved(name)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindAttribLocation",
                      "reserved prefix");
    return;
  }
  ContextGL()->BindAttribLocation(ObjectOrZero(program), index,
                                  name.Utf8().c_str());
}

bool WebGLRenderingContextBase::ValidateAndUpdateBufferBindTarget(
    const char* function_name,
    GLenum target,
    WebGLBuffer* buffer) {
  if (!ValidateBufferTarget(function_name, target))
    return false;

  if (buffer && buffer->GetInitialTarget() &&
      buffer->GetInitialTarget() != target) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "buffers can not be used with multiple targets");
    return false;
  }

  switch (target) {
    case GL_ARRAY_BUFFER:
      bound_array_buffer_ = buffer;
      break;
    case GL_ELEMENT_ARRAY_BUFFER:
      bound_vertex_array_object_->SetElementArrayBuffer(buffer);
      break;
    default:
      NOTREACHED();
  }

  if (buffer && !buffer->GetInitialTarget())
    buffer->SetInitialTarget(target);
  return true;
}

void WebGLRenderingContextBase::bindBuffer(GLenum target, WebGLBuffer* buffer) {
  if (!ValidateNullableWebGLObject("bindBuffer", buffer))
    return;
  if (!ValidateAndUpdateBufferBindTarget("bindBuffer", target, buffer))
    return;
  ContextGL()->BindBuffer(target, ObjectOrZero(buffer));
}

void WebGLRenderingContextBase::bindFramebuffer(GLenum target,
                                                WebGLFramebuffer* buffer) {
  if (!ValidateNullableWebGLObject("bindFramebuffer", buffer))
    return;

  if (target != GL_FRAMEBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindFramebuffer", "invalid target");
    return;
  }

  SetFramebuffer(target, buffer);
}

void WebGLRenderingContextBase::bindRenderbuffer(
    GLenum target,
    WebGLRenderbuffer* render_buffer) {
  if (!ValidateNullableWebGLObject("bindRenderbuffer", render_buffer))
    return;
  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindRenderbuffer", "invalid target");
    return;
  }
  renderbuffer_binding_ = render_buffer;
  ContextGL()->BindRenderbuffer(target, ObjectOrZero(render_buffer));
  if (render_buffer)
    render_buffer->SetHasEverBeenBound();
}

void WebGLRenderingContextBase::bindTexture(GLenum target,
                                            WebGLTexture* texture) {
  if (!ValidateNullableWebGLObject("bindTexture", texture))
    return;
  if (texture && texture->GetTarget() && texture->GetTarget() != target) {
    SynthesizeGLError(GL_INVALID_OPERATION, "bindTexture",
                      "textures can not be used with multiple targets");
    return;
  }

  if (target == GL_TEXTURE_2D) {
    texture_units_[active_texture_unit_].texture2d_binding_ = texture;
  } else if (target == GL_TEXTURE_CUBE_MAP) {
    texture_units_[active_texture_unit_].texture_cube_map_binding_ = texture;
  } else if (IsWebGL2() && target == GL_TEXTURE_2D_ARRAY) {
    texture_units_[active_texture_unit_].texture2d_array_binding_ = texture;
  } else if (IsWebGL2() && target == GL_TEXTURE_3D) {
    texture_units_[active_texture_unit_].texture3d_binding_ = texture;
  } else if (target == GL_TEXTURE_EXTERNAL_OES) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture",
                      "GL_TEXTURE_EXTERNAL_OES textures not supported");
    return;
  } else if (target == GL_TEXTURE_RECTANGLE_ARB) {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture",
                      "GL_TEXTURE_RECTANGLE_ARB textures not supported");
    return;
  } else {
    SynthesizeGLError(GL_INVALID_ENUM, "bindTexture", "invalid target");
    return;
  }

  ContextGL()->BindTexture(target, ObjectOrZero(texture));
  if (texture) {
    texture->SetTarget(target);
    one_plus_max_non_default_texture_unit_ =
        max(active_texture_unit_ + 1, one_plus_max_non_default_texture_unit_);
  } else {
    // If the disabled index is the current maximum, trace backwards to find the
    // new max enabled texture index
    if (one_plus_max_non_default_texture_unit_ == active_texture_unit_ + 1) {
      FindNewMaxNonDefaultTextureUnit();
    }
  }

  // Note: previously we used to automatically set the TEXTURE_WRAP_R
  // repeat mode to CLAMP_TO_EDGE for cube map textures, because OpenGL
  // ES 2.0 doesn't expose this flag (a bug in the specification) and
  // otherwise the application has no control over the seams in this
  // dimension. However, it appears that supporting this properly on all
  // platforms is fairly involved (will require a HashMap from texture ID
  // in all ports), and we have not had any complaints, so the logic has
  // been removed.
}

void WebGLRenderingContextBase::blendColor(GLfloat red,
                                           GLfloat green,
                                           GLfloat blue,
                                           GLfloat alpha) {
  if (isContextLost())
    return;
  ContextGL()->BlendColor(red, green, blue, alpha);
}

void WebGLRenderingContextBase::blendEquation(GLenum mode) {
  if (isContextLost() || !ValidateBlendEquation("blendEquation", mode))
    return;
  ContextGL()->BlendEquation(mode);
}

void WebGLRenderingContextBase::blendEquationSeparate(GLenum mode_rgb,
                                                      GLenum mode_alpha) {
  if (isContextLost() ||
      !ValidateBlendEquation("blendEquationSeparate", mode_rgb) ||
      !ValidateBlendEquation("blendEquationSeparate", mode_alpha))
    return;
  ContextGL()->BlendEquationSeparate(mode_rgb, mode_alpha);
}

void WebGLRenderingContextBase::blendFunc(GLenum sfactor, GLenum dfactor) {
  if (isContextLost() ||
      !ValidateBlendFuncFactors("blendFunc", sfactor, dfactor))
    return;
  ContextGL()->BlendFunc(sfactor, dfactor);
}

void WebGLRenderingContextBase::blendFuncSeparate(GLenum src_rgb,
                                                  GLenum dst_rgb,
                                                  GLenum src_alpha,
                                                  GLenum dst_alpha) {
  // Note: Alpha does not have the same restrictions as RGB.
  if (isContextLost() ||
      !ValidateBlendFuncFactors("blendFuncSeparate", src_rgb, dst_rgb))
    return;

  if (!ValidateBlendFuncExtendedFactors("blendFuncSeparate", src_alpha,
                                        dst_alpha)) {
    return;
  }

  ContextGL()->BlendFuncSeparate(src_rgb, dst_rgb, src_alpha, dst_alpha);
}

bool WebGLRenderingContextBase::ValidateBufferDataBufferSize(
    const char* function_name,
    int64_t size) {
  if (size < 0) {
    String error_msg = "data size is invalid";
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  if (static_cast<size_t>(size) > kMaximumSupportedArrayBufferSize) {
    String error_msg = "data size exceeds the maximum supported size";
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  return true;
}

void WebGLRenderingContextBase::BufferDataImpl(GLenum target,
                                               int64_t size,
                                               const void* data,
                                               GLenum usage) {
  WebGLBuffer* buffer = ValidateBufferDataTarget("bufferData", target);
  if (!buffer)
    return;

  if (!ValidateBufferDataUsage("bufferData", usage))
    return;

  if (!ValidateValueFitNonNegInt32("bufferData", "size", size))
    return;

  if (!ValidateBufferDataBufferSize("bufferData", size))
    return;

  buffer->SetSize(size);

  ContextGL()->BufferData(target, static_cast<GLsizeiptr>(size), data, usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           int64_t size,
                                           GLenum usage) {
  if (isContextLost())
    return;
  BufferDataImpl(target, size, nullptr, usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           DOMArrayBufferBase* data,
                                           GLenum usage) {
  if (isContextLost())
    return;
  if (!data) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferData", "no data");
    return;
  }
  BufferDataImpl(target, data->ByteLength(), data->DataMaybeShared(), usage);
}

void WebGLRenderingContextBase::bufferData(GLenum target,
                                           MaybeShared<DOMArrayBufferView> data,
                                           GLenum usage) {
  if (isContextLost())
    return;
  DCHECK(data);
  BufferDataImpl(target, data->byteLength(), data->BaseAddressMaybeShared(),
                 usage);
}

void WebGLRenderingContextBase::BufferSubDataImpl(GLenum target,
                                                  int64_t offset,
                                                  int64_t size,
                                                  const void* data) {
  WebGLBuffer* buffer = ValidateBufferDataTarget("bufferSubData", target);
  if (!buffer)
    return;
  if (!ValidateValueFitNonNegInt32("bufferSubData", "offset", offset))
    return;
  if (!ValidateValueFitNonNegInt32("bufferSubData", "size", size))
    return;
  if (!ValidateBufferDataBufferSize("bufferSubData", size))
    return;

  if (!data)
    return;
  if (offset + static_cast<int64_t>(size) > buffer->GetSize()) {
    SynthesizeGLError(GL_INVALID_VALUE, "bufferSubData", "buffer overflow");
    return;
  }

  ContextGL()->BufferSubData(target, static_cast<GLintptr>(offset),
                             static_cast<GLintptr>(size), data);
}

void WebGLRenderingContextBase::bufferSubData(GLenum target,
                                              int64_t offset,
                                              base::span<const uint8_t> data) {
  if (isContextLost())
    return;
  BufferSubDataImpl(target, offset, data.size(), data.data());
}

bool WebGLRenderingContextBase::ValidateFramebufferTarget(GLenum target) {
  if (target == GL_FRAMEBUFFER)
    return true;
  return false;
}

WebGLFramebuffer* WebGLRenderingContextBase::GetFramebufferBinding(
    GLenum target) {
  if (target == GL_FRAMEBUFFER)
    return framebuffer_binding_.Get();
  return nullptr;
}

WebGLFramebuffer* WebGLRenderingContextBase::GetReadFramebufferBinding() {
  return framebuffer_binding_.Get();
}

GLenum WebGLRenderingContextBase::checkFramebufferStatus(GLenum target) {
  if (isContextLost())
    return GL_FRAMEBUFFER_UNSUPPORTED;
  if (!ValidateFramebufferTarget(target)) {
    SynthesizeGLError(GL_INVALID_ENUM, "checkFramebufferStatus",
                      "invalid target");
    return 0;
  }
  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (framebuffer_binding) {
    const char* reason = "framebuffer incomplete";
    GLenum status = framebuffer_binding->CheckDepthStencilStatus(&reason);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
      EmitGLWarning("checkFramebufferStatus", reason);
      return status;
    }
  }
  return ContextGL()->CheckFramebufferStatus(target);
}

void WebGLRenderingContextBase::clear(GLbitfield mask) {
  if (isContextLost())
    return;
  if (mask &
      ~(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT)) {
    SynthesizeGLError(GL_INVALID_VALUE, "clear", "invalid mask");
    return;
  }
  const char* reason = "framebuffer incomplete";
  if (framebuffer_binding_ && framebuffer_binding_->CheckDepthStencilStatus(
                                  &reason) != GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, "clear", reason);
    return;
  }

  if (!mask) {
    // Use OnErrorMessage because it's both rate-limited and obeys the
    // webGLErrorsToConsole setting.
    OnErrorMessage(
        "Performance warning: clear() called with no buffers in bitmask", 0);
    // Don't skip the call to ClearIfComposited below; it has side
    // effects even without the user requesting to clear any buffers.
  }

  ScopedRGBEmulationColorMask emulation_color_mask(this, color_mask_.data(),
                                                   drawing_buffer_.get());

  if (ClearIfComposited(kClearCallerDrawOrClear, mask) != kCombinedClear) {
    // If clearing the default back buffer's depth buffer, also clear the
    // stencil buffer, if one was allocated implicitly. This avoids performance
    // problems on some GPUs.
    if (!framebuffer_binding_ &&
        GetDrawingBuffer()->HasImplicitStencilBuffer() &&
        (mask & GL_DEPTH_BUFFER_BIT)) {
      // It shouldn't matter what value it's cleared to, since in other queries
      // in the API, we claim that the stencil buffer doesn't exist.
      mask |= GL_STENCIL_BUFFER_BIT;
    }
    ContextGL()->Clear(mask);
  }
  MarkContextChanged(kCanvasChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
}

void WebGLRenderingContextBase::clearColor(GLfloat r,
                                           GLfloat g,
                                           GLfloat b,
                                           GLfloat a) {
  if (isContextLost())
    return;
  if (std::isnan(r))
    r = 0;
  if (std::isnan(g))
    g = 0;
  if (std::isnan(b))
    b = 0;
  if (std::isnan(a))
    a = 1;
  clear_color_[0] = r;
  clear_color_[1] = g;
  clear_color_[2] = b;
  clear_color_[3] = a;
  ContextGL()->ClearColor(r, g, b, a);
}

void WebGLRenderingContextBase::clearDepth(GLfloat depth) {
  if (isContextLost())
    return;
  clear_depth_ = depth;
  ContextGL()->ClearDepthf(depth);
}

void WebGLRenderingContextBase::clearStencil(GLint s) {
  if (isContextLost())
    return;
  clear_stencil_ = s;
  ContextGL()->ClearStencil(s);
}

void WebGLRenderingContextBase::colorMask(GLboolean red,
                                          GLboolean green,
                                          GLboolean blue,
                                          GLboolean alpha) {
  if (isContextLost())
    return;
  color_mask_[0] = red;
  color_mask_[1] = green;
  color_mask_[2] = blue;
  color_mask_[3] = alpha;
  ContextGL()->ColorMask(red, green, blue, alpha);
}

void WebGLRenderingContextBase::compileShader(WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("compileShader", shader))
    return;
  ContextGL()->CompileShader(ObjectOrZero(shader));
}

void WebGLRenderingContextBase::compressedTexImage2D(
    GLenum target,
    GLint level,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    MaybeShared<DOMArrayBufferView> data) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("compressedTexImage2D", target, true))
    return;
  if (!ValidateCompressedTexFormat("compressedTexImage2D", internalformat))
    return;
  GLsizei data_length;
  if (!ExtractDataLengthIfValid("compressedTexImage2D", data, &data_length))
    return;
  if (static_cast<size_t>(data_length) > kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "ArrayBufferView size exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexImage2D(target, level, internalformat, width,
                                    height, border, data_length,
                                    data->BaseAddressMaybeShared());
}

void WebGLRenderingContextBase::compressedTexSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    MaybeShared<DOMArrayBufferView> data) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("compressedTexSubImage2D", target))
    return;
  if (!ValidateCompressedTexFormat("compressedTexSubImage2D", format))
    return;
  GLsizei data_length;
  if (!ExtractDataLengthIfValid("compressedTexSubImage2D", data, &data_length))
    return;
  if (static_cast<size_t>(data_length) > kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "ArrayBufferView size exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexSubImage2D(target, level, xoffset, yoffset, width,
                                       height, format, data_length,
                                       data->BaseAddressMaybeShared());
}

bool WebGLRenderingContextBase::ValidateSettableTexFormat(
    const char* function_name,
    GLenum format) {
  if (IsWebGL2())
    return true;

  if (WebGLImageConversion::GetChannelBitsByFormat(format) &
      WebGLImageConversion::kChannelDepthStencil) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "format can not be set, only rendered to");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateCopyTexFormat(const char* function_name,
                                                      GLenum internalformat) {
  if (!is_web_gl2_internal_formats_copy_tex_image_added_ && IsWebGL2()) {
    ADD_VALUES_TO_SET(supported_internal_formats_copy_tex_image_,
                      kSupportedInternalFormatsES3);
    is_web_gl2_internal_formats_copy_tex_image_added_ = true;
  }
  if (!is_ext_color_buffer_float_formats_added_ &&
      ExtensionEnabled(kEXTColorBufferFloa
```