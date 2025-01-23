Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. This file seems to contain tests for the `CanvasRenderingContext2D` class. I need to analyze the code and explain its purpose, its relation to web technologies, provide examples, discuss potential errors, outline user interaction leading to these tests, and summarize the functionality of this specific part.

Here's a breakdown of the steps:

1. **Identify the main purpose:** The code consists of test cases for `CanvasRenderingContext2D`.
2. **Analyze individual test functions:** Understand what each test function is verifying. Look for patterns and common themes.
3. **Relate to web technologies:** Connect the functionalities being tested (drawing images, manipulating pixel data, handling color spaces, managing rendering modes, etc.) to corresponding JavaScript APIs, HTML elements, and CSS properties.
4. **Provide examples:**  Illustrate how the tested functionalities are used in a web context with simple HTML and JavaScript snippets.
5. **Infer assumptions and outputs:** For tests involving logical operations or data processing, make assumptions about the input and predict the output based on the code.
6. **Identify potential user/programmer errors:** Based on the tested functionalities, list common mistakes developers might make when using the Canvas 2D API.
7. **Trace user operations:** Describe the steps a user would take in a web browser to trigger the execution of the code being tested.
8. **Summarize the functionality:** Concisely describe the overall purpose of this specific code segment.
这是 `blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc` 文件的第 3 部分，主要包含以下功能：

**核心功能：测试 Canvas 2D 渲染上下文的功能，特别是以下方面：**

* **绘制高位深度的 PNG 图片:** 测试在不同的 Canvas 色彩空间（P3 和 Rec2020）上绘制高位深度 PNG 图片的功能，包括对隔行扫描、色彩配置和 alpha 通道的处理。
* **`putImageData()` 的色彩管理:**  测试在不同色彩空间的 Canvas 上使用 `putImageData()` 方法时的色彩管理行为，包括处理不同色彩空间和存储格式的 `ImageData` 对象。
* **Canvas 的渲染模式和性能特性:**
    * 测试未加速的 Canvas 在低延迟模式下的行为。
    * 测试 `willReadFrequently` 属性对未加速 Canvas 的影响。
    * 测试 `getImageData()` 操作在默认 `willReadFrequently` 设置下可能导致 Canvas 回退到 CPU 渲染模式的情况。
    * 测试 Canvas 自动刷新机制，包括基于操作数量和内存使用的自动刷新。
    * 测试当绘制大量相同或不同图片时，Canvas 的自动刷新和内存管理机制。
    * 测试当使用 Canvas 2D Layers 时，自动刷新是否会被延迟。
* **软件 Canvas 的合成:** 测试在启用或禁用 `ImageChromium` 特性时，软件 Canvas 是否会被合成。
* **文本渲染:** 测试 `textRendering` 属性的不同值（`geometricPrecision`, `optimizeLegibility`, `optimizeSpeed`）对文本渲染的影响。
* **加速 Canvas 的资源管理和上下文丢失处理:**
    * 测试加速 Canvas 的 `getImage()` 方法是否返回加速的图片。
    * 测试当加速 Canvas 已经在合成层中时，是否会避免重复生成可转移资源。
    * 测试加速 Canvas 在上下文丢失后获取资源提供者的情况。
    * 测试加速 Canvas 在上下文丢失后准备可转移资源的情况。
    * 测试加速 Canvas 在上下文丢失后回退到软件渲染的情况。
    * 测试加速 Canvas 在上下文丢失后 `getImage()` 方法的行为。
    * 测试加速 Canvas 在上下文丢失且恢复失败后，准备 Mailbox 的情况。
    * 测试在设置 `willNotReadFrequently` 的情况下，加速 Canvas 在调用 `getImageData()` 后是否仍然保持加速状态。
* **Canvas 的休眠和唤醒:** 测试在启用 Canvas 休眠功能后，当 Canvas 进入休眠和唤醒状态时，是否会请求合成更新。
* **页面进入前台和后台对 Canvas 休眠的影响:** 测试页面在后台时 Canvas 是否会休眠，以及页面回到前台时是否会结束休眠。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

1. **绘制高位深度的 PNG 图片:**
   * **JavaScript:** 使用 `drawImage()` 方法将 PNG 图片绘制到 Canvas 上。
   * **HTML:** 使用 `<canvas>` 元素创建 Canvas 画布。
   * **CSS:** 可以使用 CSS 设置 Canvas 的尺寸和样式。
   * **举例:**
     ```html
     <canvas id="myCanvas" width="200"
### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
interlace_status) {
    for (auto color_profile : color_profiles) {
      for (auto alpha : alpha_status) {
        StringBuilder full_path;
        full_path.Append(path);
        full_path.Append("2x2_16bit");
        full_path.Append(interlace);
        full_path.Append(color_profile);
        full_path.Append(alpha);
        full_path.Append(".png");
        TestDrawSingleHighBitDepthPNGOnCanvas(full_path.ToString(), context,
                                              color_space, document,
                                              color_setting, script_state);
      }
    }
  }
}

TEST_P(CanvasRenderingContext2DTest, DrawHighBitDepthPngOnP3Canvas) {
  TestDrawHighBitDepthPNGsOnWideGamutCanvas(
      PredefinedColorSpace::kP3, GetDocument(),
      Persistent<HTMLCanvasElement>(CanvasElement()), GetScriptState());
}

TEST_P(CanvasRenderingContext2DTest, DrawHighBitDepthPngOnRec2020Canvas) {
  TestDrawHighBitDepthPNGsOnWideGamutCanvas(
      PredefinedColorSpace::kRec2020, GetDocument(),
      Persistent<HTMLCanvasElement>(CanvasElement()), GetScriptState());
}

// The color settings of the surface of the canvas always remaines loyal to the
// first created context 2D. Therefore, we have to test different canvas color
// space settings for CanvasRenderingContext2D::putImageData() in different
// tests.
enum class PredefinedColorSpaceSettings : uint8_t {
  CANVAS_SRGB = 0,
  CANVAS_REC2020 = 1,
  CANVAS_P3 = 2,

  LAST = CANVAS_P3
};

// This test verifies the correct behavior of putImageData member function in
// color managed mode.
void TestPutImageDataOnCanvasWithColorSpaceSettings(
    HTMLCanvasElement& canvas_element,
    PredefinedColorSpaceSettings canvas_colorspace_setting) {
  unsigned num_image_data_color_spaces = 3;
  PredefinedColorSpace image_data_color_spaces[] = {
      PredefinedColorSpace::kSRGB,
      PredefinedColorSpace::kRec2020,
      PredefinedColorSpace::kP3,
  };

  unsigned num_image_data_storage_formats = 3;
  ImageDataStorageFormat image_data_storage_formats[] = {
      ImageDataStorageFormat::kUint8,
      ImageDataStorageFormat::kUint16,
      ImageDataStorageFormat::kFloat32,
  };

  PredefinedColorSpace predefined_color_spaces[] = {
      PredefinedColorSpace::kSRGB,
      PredefinedColorSpace::kSRGB,
      PredefinedColorSpace::kRec2020,
      PredefinedColorSpace::kP3,
  };

  CanvasPixelFormat canvas_pixel_formats[] = {
      CanvasPixelFormat::kUint8,
      CanvasPixelFormat::kF16,
      CanvasPixelFormat::kF16,
      CanvasPixelFormat::kF16,
  };

  // Source pixels in RGBA32
  uint8_t u8_pixels[] = {255, 0,   0,   255,  // Red
                         0,   0,   0,   0,    // Transparent
                         255, 192, 128, 64,   // Decreasing values
                         93,  117, 205, 41};  // Random values
  constexpr size_t data_length = std::size(u8_pixels);

  std::array<uint16_t, data_length> u16_pixels;
  for (size_t i = 0; i < data_length; i++)
    u16_pixels[i] = u8_pixels[i] * 257;

  std::array<float, data_length> f32_pixels;
  for (size_t i = 0; i < data_length; i++)
    f32_pixels[i] = u8_pixels[i] / 255.0;

  NotShared<DOMUint8ClampedArray> data_u8(
      DOMUint8ClampedArray::Create(u8_pixels));
  DCHECK(data_u8);
  EXPECT_EQ(data_length, data_u8->length());
  NotShared<DOMUint16Array> data_u16(DOMUint16Array::Create(u16_pixels));
  DCHECK(data_u16);
  EXPECT_EQ(data_length, data_u16->length());
  NotShared<DOMFloat32Array> data_f32(DOMFloat32Array::Create(f32_pixels));
  DCHECK(data_f32);
  EXPECT_EQ(data_length, data_f32->length());

  ImageData* image_data = nullptr;
  size_t num_pixels = data_length / 4;

  // At most four bytes are needed for Float32 output per color component.
  std::unique_ptr<uint8_t[]> pixels_converted_manually(
      new uint8_t[data_length * 4]());

  // Loop through different possible combinations of image data color space and
  // storage formats and create the respective test image data objects.
  for (unsigned i = 0; i < num_image_data_color_spaces; i++) {
    for (unsigned j = 0; j < num_image_data_storage_formats; j++) {
      NotShared<DOMArrayBufferView> data_array;
      switch (image_data_storage_formats[j]) {
        case ImageDataStorageFormat::kUint8:
          data_array = data_u8;
          break;
        case ImageDataStorageFormat::kUint16:
          data_array = data_u16;
          break;
        case ImageDataStorageFormat::kFloat32:
          data_array = data_f32;
          break;
        default:
          NOTREACHED();
      }

      image_data = ImageData::CreateForTest(gfx::Size(2, 2), data_array,
                                            image_data_color_spaces[i],
                                            image_data_storage_formats[j]);
      unsigned k = static_cast<unsigned>(canvas_colorspace_setting);
      ImageDataSettings* canvas_color_setting = ImageDataSettings::Create();
      canvas_color_setting->setColorSpace(
          PredefinedColorSpaceName(predefined_color_spaces[k]));
      switch (canvas_pixel_formats[k]) {
        case CanvasPixelFormat::kUint8:
          canvas_color_setting->setStorageFormat(
              ImageDataStorageFormatName(ImageDataStorageFormat::kUint8));
          break;
        case CanvasPixelFormat::kF16:
          canvas_color_setting->setStorageFormat(
              ImageDataStorageFormatName(ImageDataStorageFormat::kFloat32));
          break;
        default:
          NOTREACHED();
      }

      // Convert the original data used to create ImageData to the
      // canvas color space and canvas pixel format.
      EXPECT_TRUE(
          ColorCorrectionTestUtils::
              ConvertPixelsToColorSpaceAndPixelFormatForTest(
                  data_array->BaseAddress(), data_length,
                  image_data_color_spaces[i], image_data_storage_formats[j],
                  predefined_color_spaces[k], canvas_pixel_formats[k],
                  pixels_converted_manually, kPixelFormat_ffff));

      // Create a canvas and call putImageData and getImageData to make sure
      // the conversion is done correctly.
      CanvasContextCreationAttributesCore attributes;
      attributes.alpha = true;
      attributes.color_space = predefined_color_spaces[k];
      attributes.pixel_format = canvas_pixel_formats[k];
      CanvasRenderingContext2D* context =
          static_cast<CanvasRenderingContext2D*>(
              canvas_element.GetCanvasRenderingContext("2d", attributes));
      NonThrowableExceptionState exception_state;
      context->putImageData(image_data, 0, 0, exception_state);

      const void* pixels_from_get_image_data =
          context
              ->getImageData(0, 0, 2, 2, canvas_color_setting, exception_state)
              ->GetSkPixmap()
              .addr();
      ColorCorrectionTestUtils::CompareColorCorrectedPixels(
          pixels_from_get_image_data, pixels_converted_manually.get(),
          num_pixels,
          (canvas_pixel_formats[k] == CanvasPixelFormat::kUint8)
              ? kPixelFormat_8888
              : kPixelFormat_ffff,
          kAlphaUnmultiplied, kUnpremulRoundTripTolerance);
    }
  }
}

// Test disabled due to crbug.com/780925
TEST_P(CanvasRenderingContext2DTest, ColorManagedPutImageDataOnSRGBCanvas) {
  TestPutImageDataOnCanvasWithColorSpaceSettings(
      CanvasElement(), PredefinedColorSpaceSettings::CANVAS_SRGB);
}

TEST_P(CanvasRenderingContext2DTest, ColorManagedPutImageDataOnRec2020Canvas) {
  TestPutImageDataOnCanvasWithColorSpaceSettings(
      CanvasElement(), PredefinedColorSpaceSettings::CANVAS_REC2020);
}

TEST_P(CanvasRenderingContext2DTest, ColorManagedPutImageDataOnP3Canvas) {
  TestPutImageDataOnCanvasWithColorSpaceSettings(
      CanvasElement(), PredefinedColorSpaceSettings::CANVAS_P3);
}

TEST_P(CanvasRenderingContext2DTest,
       UnacceleratedLowLatencyIsNotSingleBuffered) {
  CreateContext(kNonOpaque, kLowLatency);
  // No need to set-up the layer bridge when testing low latency mode.
  DrawSomething();
  EXPECT_TRUE(Context2D()->getContextAttributes()->desynchronized());
  EXPECT_TRUE(CanvasElement().LowLatencyEnabled());
  EXPECT_FALSE(
      CanvasElement()
          .GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferCPU)
          ->SupportsSingleBuffering());
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest,
       UnacceleratedIfNormalLatencyWillReadFrequently) {
  CreateContext(kNonOpaque, kNormalLatency,
                CanvasContextCreationAttributesCore::WillReadFrequently::kTrue);
  DrawSomething();
  EXPECT_EQ(Context2D()->getContextAttributes()->willReadFrequently(),
            V8CanvasWillReadFrequently::Enum::kTrue);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest,
       UnacceleratedIfLowLatencyWillReadFrequently) {
  CreateContext(kNonOpaque, kLowLatency,
                CanvasContextCreationAttributesCore::WillReadFrequently::kTrue);
  // No need to set-up the layer bridge when testing low latency mode.
  DrawSomething();
  EXPECT_EQ(Context2D()->getContextAttributes()->willReadFrequently(),
            V8CanvasWillReadFrequently::Enum::kTrue);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest,
       UnacceleratedAfterGetImageDataWithDefaultWillReadFrequently) {
  base::test::ScopedFeatureList feature_list_;
  CreateContext(kNonOpaque, kNormalLatency);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  DrawSomething();
  NonThrowableExceptionState exception_state;
  ImageDataSettings* settings = ImageDataSettings::Create();
  int read_count = BaseRenderingContext2D::kFallbackToCPUAfterReadbacks;
  while (read_count--) {
    Context2D()->getImageData(0, 0, 1, 1, settings, exception_state);
  }
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest, AutoFlush) {
  CreateContext(kNonOpaque);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);
  Context2D()->fillRect(0, 0, 1, 1);  // Ensure resource provider is created.
  const size_t initial_op_count = Context2D()->Recorder()->TotalOpCount();

  while (Context2D()->Recorder()->TotalOpBytesUsed() <=
         kMaxRecordedOpKB * 1024) {
    Context2D()->fillRect(0, 0, 1, 1);
    // Verify that auto-flush did not happen
    ASSERT_GT(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
  }
  Context2D()->fillRect(0, 0, 1, 1);
  // Verify that auto-flush happened
  ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
}

TEST_P(CanvasRenderingContext2DTest, AutoFlushPinnedImages) {
  CreateContext(kNonOpaque);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  Context2D()->fillRect(0, 0, 1, 1);  // Ensure resource provider is created.

  constexpr unsigned int kImageSize = 10;
  constexpr unsigned int kBytesPerImage = 400;

  const size_t initial_op_count = Context2D()->Recorder()->TotalOpCount();

  // We repeat the test twice to verify that the state was properly
  // reset by the Flush.
  for (int repeat = 0; repeat < 2; ++repeat) {
    size_t expected_op_count = initial_op_count;
    for (size_t pinned_bytes = 0; pinned_bytes <= kMaxPinnedImageKB * 1024;
         pinned_bytes += kBytesPerImage) {
      FakeImageSource unique_image(gfx::Size(kImageSize, kImageSize),
                                   kOpaqueBitmap);
      NonThrowableExceptionState exception_state;
      Context2D()->drawImage(&unique_image, 0, 0, 1, 1, 0, 0, 1, 1,
                             exception_state);
      EXPECT_FALSE(exception_state.HadException());
      ++expected_op_count;
      ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), expected_op_count);
    }
    Context2D()->fillRect(0, 0, 1, 1);  // Trigger flush due to memory limit
    ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
  }
}

TEST_P(CanvasRenderingContext2DTest, OverdrawResetsPinnedImageBytes) {
  CreateContext(kNonOpaque);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  constexpr unsigned int kImageSize = 10;
  constexpr unsigned int kBytesPerImage = 400;

  FakeImageSource unique_image(gfx::Size(kImageSize, kImageSize),
                               kOpaqueBitmap);
  NonThrowableExceptionState exception_state;
  Context2D()->drawImage(&unique_image, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);
  size_t initial_op_count = Context2D()->Recorder()->TotalOpCount();
  ASSERT_EQ(Context2D()->Recorder()->ReleasableImageBytesUsed(),
            kBytesPerImage);

  Context2D()->clearRect(0, 0, 10, 10);  // Overdraw
  ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
  ASSERT_EQ(Context2D()->Recorder()->ReleasableImageBytesUsed(), 0u);
}

TEST_P(CanvasRenderingContext2DTest, AutoFlushSameImage) {
  CreateContext(kNonOpaque);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  Context2D()->fillRect(0, 0, 1, 1);  // Ensure resource provider is created.
  size_t expected_op_count = Context2D()->Recorder()->TotalOpCount();

  constexpr unsigned int kImageSize = 10;
  constexpr unsigned int kBytesPerImage = 400;

  FakeImageSource image(gfx::Size(kImageSize, kImageSize), kOpaqueBitmap);

  for (size_t pinned_bytes = 0; pinned_bytes <= 2 * kMaxPinnedImageKB * 1024;
       pinned_bytes += kBytesPerImage) {
    NonThrowableExceptionState exception_state;
    Context2D()->drawImage(&image, 0, 0, 1, 1, 0, 0, 1, 1, exception_state);
    EXPECT_FALSE(exception_state.HadException());
    ++expected_op_count;
    ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), expected_op_count);
  }
}

TEST_P(CanvasRenderingContext2DTest, AutoFlushDelayedByLayer) {
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  CreateContext(kNonOpaque);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);
  NonThrowableExceptionState exception_state;
  Context2D()->beginLayer(ToScriptStateForMainWorld(GetDocument().GetFrame()),
                          BeginLayerOptions::Create(), exception_state);
  const size_t initial_op_count = Context2D()->Recorder()->TotalOpCount();
  while (Context2D()->Recorder()->TotalOpBytesUsed() <=
         kMaxRecordedOpKB * 1024 * 2) {
    Context2D()->fillRect(0, 0, 1, 1);
    ASSERT_GT(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
  }
  // Closing the layer means next op can trigger auto flush
  Context2D()->endLayer(exception_state);
  Context2D()->fillRect(0, 0, 1, 1);
  ASSERT_EQ(Context2D()->Recorder()->TotalOpCount(), initial_op_count);
}

TEST_P(CanvasRenderingContext2DTest,
       SoftwareCanvasIsCompositedIfImageChromium) {
  ScopedCanvas2dImageChromiumForTest canvas_2d_image_chromium(true);

  // Ensure that native support for BGRA GMBs is present, as otherwise
  // compositing will not occur irrespective of whether
  // `ScopedCanvas2dImageChromium` is enabled.
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  const_cast<gpu::Capabilities&>(SharedGpuContext::ContextProviderWrapper()
                                     ->ContextProvider()
                                     ->GetCapabilities())
      .gpu_memory_buffer_formats.Put(gfx::BufferFormat::BGRA_8888);

  CreateContext(kNonOpaque);
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  // Draw to the canvas and verify that the canvas is composited.
  Context2D()->fillRect(0, 0, 1, 1);
  EXPECT_TRUE(CanvasElement().IsComposited());
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest,
       SoftwareCanvasIsNotCompositedIfNotImageChromium) {
  ScopedCanvas2dImageChromiumForTest canvas_2d_image_chromium(false);

  CreateContext(kNonOpaque);
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  // Ensure that native support for BGRA GMBs is present, as otherwise
  // compositing will not occur irrespective of whether
  // `ScopedCanvas2dImageChromium` is enabled.
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  const_cast<gpu::Capabilities&>(SharedGpuContext::ContextProviderWrapper()
                                     ->ContextProvider()
                                     ->GetCapabilities())
      .gpu_memory_buffer_formats.Put(gfx::BufferFormat::BGRA_8888);

  // Draw to the canvas and verify that the canvas is not composited.
  Context2D()->fillRect(0, 0, 1, 1);
  EXPECT_FALSE(CanvasElement().IsComposited());
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
}

TEST_P(CanvasRenderingContext2DTest, TextRenderingTest) {
  CreateContext(kNonOpaque, kLowLatency);
  Context2D()->setFont("10px sans-serif");
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kAutoTextRendering);
  // Update the textRendering to "geometricPrecision"
  std::optional<V8CanvasTextRendering> textRendering =
      V8CanvasTextRendering::Create("geometricPrecision");
  Context2D()->setTextRendering(textRendering.value());
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kGeometricPrecision);
  Context2D()->setFont("12px sans-serif");
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kGeometricPrecision);

  // Update the textRendering to "optimizeLegibility"
  textRendering = V8CanvasTextRendering::Create("optimizeLegibility");
  Context2D()->setTextRendering(textRendering.value());
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kOptimizeLegibility);
  Context2D()->setFont("12px sans-serif");
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kOptimizeLegibility);

  // Update the textRendering to "optimizeSpeed"
  textRendering = V8CanvasTextRendering::Create("optimizeSpeed");
  Context2D()->setTextRendering(textRendering.value());
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kOptimizeSpeed);
  Context2D()->setFont("12px sans-serif");
  EXPECT_EQ(GetContext2DState().GetFontDescription().TextRendering(),
            TextRenderingMode::kOptimizeSpeed);
}

class CanvasRenderingContext2DTestAccelerated
    : public CanvasRenderingContext2DTest {
 protected:
  bool AllowsAcceleration() override { return true; }

  void CreateAlotOfCanvasesWithAccelerationExplicitlyDisabled() {
    for (int i = 0; i < 200; ++i) {
      auto* canvas = MakeGarbageCollected<HTMLCanvasElement>(GetDocument());
      CreateContext(
          kNonOpaque, kNormalLatency,
          CanvasContextCreationAttributesCore::WillReadFrequently::kUndefined,
          canvas);
      canvas->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
      // Expect that at least the first 10 are accelerated. The exact number
      // depends on the feature params.
      if (i < 10) {
        EXPECT_TRUE(canvas->IsAccelerated());
      }
      canvas->DisableAcceleration();
    }
  }

 private:
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(CanvasRenderingContext2DTestAccelerated);

TEST_P(CanvasRenderingContext2DTestAccelerated, GetImage) {
  CreateContext(kNonOpaque);

  ASSERT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));
  ASSERT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  ASSERT_TRUE(CanvasElement().IsResourceValid());

  // Verify that CanvasRenderingContext2D::GetImage() creates an accelerated
  // image given that the underlying CanvasResourceProvider does so.
  EXPECT_TRUE(Context2D()
                  ->GetImage(FlushReason::kTesting)
                  ->PaintImageForCurrentFrame()
                  .IsTextureBacked());

  // The GetImage() call should have preserved the rasterization mode as well as
  // the validity of the resource.
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  EXPECT_TRUE(CanvasElement().IsResourceValid());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       NoRegenerationOfTransferableResourceWhenAlreadyInCcLayer) {
  CreateContext(kNonOpaque);

  ASSERT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));

  // Invoking PrepareTransferableResource() has a precondition that a CC layer
  // is present.
  ASSERT_TRUE(CanvasElement().GetOrCreateCcLayerIfNeeded());

  Context2D()->fillRect(3, 3, 1, 1);

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;
  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resource,
                                                          &release_callback));

  // Put the resource in the Cc layer and then make a second call to prepare a
  // TransferableResource without modifying the canvas in between. This new call
  // should not generate a new TransferableResource as the canvas' resource is
  // already present in the CC layer.
  CanvasElement().CcLayer()->SetTransferableResource(
      resource, std::move(release_callback));
  viz::ReleaseCallback release_callback2;
  EXPECT_FALSE(CanvasElement().PrepareTransferableResource(&resource,
                                                           &release_callback2));
  EXPECT_FALSE(release_callback2);
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       GetResourceProviderAfterContextLoss) {
  CreateContext(kNonOpaque);

  EXPECT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  test_context_provider_->TestContextGL()->set_context_lost(true);
  EXPECT_EQ(nullptr, CanvasElement().GetOrCreateCanvasResourceProvider(
                         RasterModeHint::kPreferGPU));
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       PrepareTransferableResourceAfterContextLoss) {
  CreateContext(kNonOpaque);

  ASSERT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));

  // Invoking PrepareTransferableResource() has a precondition that a CC layer
  // is present.
  ASSERT_TRUE(CanvasElement().GetOrCreateCcLayerIfNeeded());

  EXPECT_TRUE(CanvasElement().GetRasterMode() == RasterMode::kGPU);

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;
  EXPECT_TRUE(CanvasElement().PrepareTransferableResource(&resource,
                                                          &release_callback));

  // When the context is lost we are not sure if we should still be producing
  // GL frames for the compositor or not, so fail to generate frames.
  test_context_provider_->TestContextGL()->set_context_lost(true);
  EXPECT_FALSE(CanvasElement().PrepareTransferableResource(&resource,
                                                           &release_callback));
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       FallbackToSoftwareIfContextLost) {
  CreateContext(kNonOpaque);

  test_context_provider_->TestContextGL()->set_context_lost(true);

  ASSERT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(CanvasElement().IsResourceValid());
}

TEST_P(CanvasRenderingContext2DTestAccelerated, GetImageAfterContextLoss) {
  CreateContext(kNonOpaque);

  // For CanvasResourceHost to check for the GPU context being lost as part of
  // checking resource validity, it is necessary to have both accelerated
  // raster/compositing and a CC layer.
  ASSERT_TRUE(SetUpFullAccelerationAndCcLayer(CanvasElement()));

  EXPECT_TRUE(CanvasElement().IsResourceValid());
  EXPECT_TRUE(Context2D()->GetImage(FlushReason::kTesting));

  test_context_provider_->TestContextGL()->set_context_lost(true);

  EXPECT_FALSE(Context2D()->GetImage(FlushReason::kTesting));
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       PrepareMailboxWhenContextIsLostWithFailedRestore) {
  CreateContext(kNonOpaque);

  // For CanvasResourceHost to check for the GPU context being lost as part of
  // checking resource validity, it is necessary to have both accelerated
  // raster/compositing and a CC layer.
  ASSERT_TRUE(SetUpFullAccelerationAndCcLayer(CanvasElement()));

  // The resource should start off valid.
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;
  EXPECT_TRUE(CanvasElement().PrepareTransferableResource(&resource,
                                                          &release_callback));

  // Losing the context should result in the resource becoming invalid and the
  // host being unable to produce a TransferableResource from it.
  test_context_provider_->TestContextGL()->set_context_lost(true);
  EXPECT_FALSE(CanvasElement().IsResourceValid());
  EXPECT_FALSE(CanvasElement().PrepareTransferableResource(&resource,
                                                           &release_callback));

  // Restoration of the context should fail because
  // Platform::createSharedOffscreenGraphicsContext3DProvider() is stubbed in
  // unit tests. This simulates what would happen when attempting to restore
  // while the GPU process is down.
  Context2D()->TryRestoreContextEvent(/*timer=*/nullptr);
  EXPECT_FALSE(CanvasElement().IsResourceValid());
  EXPECT_FALSE(CanvasElement().PrepareTransferableResource(&resource,
                                                           &release_callback));
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       RemainAcceleratedAfterGetImageDataWithWillNotReadFrequently) {
  base::test::ScopedFeatureList feature_list_;
  CreateContext(
      kNonOpaque, kNormalLatency,
      CanvasContextCreationAttributesCore::WillReadFrequently::kFalse);
  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  DrawSomething();
  NonThrowableExceptionState exception_state;
  ImageDataSettings* settings = ImageDataSettings::Create();
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  Context2D()->getImageData(0, 0, 1, 1, settings, exception_state);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
}

// https://crbug.com/708445: When the canvas hibernates or wakes up from
// hibernation, the compositing reasons for the canvas element may change. In
// these cases, the element should request a compositing update.
TEST_P(CanvasRenderingContext2DTestAccelerated,
       ElementRequestsCompositingUpdateOnHibernateAndWakeUp) {
  CreateContext(kNonOpaque);
  gfx::Size size(300, 300);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  // Take a snapshot to trigger lazy resource provider creation
  Context2D()->GetImage(FlushReason::kTesting);
  EXPECT_TRUE(!!CanvasElement().ResourceProvider());
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  auto* box = CanvasElement().GetLayoutBoxModelObject();
  EXPECT_TRUE(box);
  PaintLayer* painting_layer = box->PaintingLayer();
  EXPECT_TRUE(painting_layer);
  UpdateAllLifecyclePhasesForTest();

  // Hide element to trigger hibernation (if enabled).
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);
  // Run hibernation task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();
  // If enabled, hibernation should cause repaint of the painting layer.
  EXPECT_FALSE(box->NeedsPaintPropertyUpdate());
  EXPECT_EQ(features::IsCanvas2DHibernationEnabled(),
            painting_layer->SelfNeedsRepaint());
  EXPECT_EQ(features::IsCanvas2DHibernationEnabled(),
            !CanvasElement().ResourceProvider());

  // The page is hidden so it doesn't make sense to paint, and doing so will
  // DCHECK. Update all other lifecycle phases.
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);

  // Wake up again, which should request repaint of the painting layer.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kVisible,
      /*is_initial_state=*/false);
  EXPECT_FALSE(box->NeedsPaintPropertyUpdate());
  EXPECT_EQ(features::IsCanvas2DHibernationEnabled(),
            painting_layer->SelfNeedsRepaint());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       PageComingToForegroundEndsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());
  base::RunLoop run_loop;

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Run the task that initiates hibernation, which has been posted as an idle
  // task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  // Verify that coming to the foreground ends hibernation synchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kVisible,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationEndedNormally,
        1);
    EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
    EXPECT_FALSE(handler.IsHibernating());
    EXPECT_TRUE(CanvasElement().IsResourceValid());
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       HibernationPostForegroundBackgroundToggleOccursNormally) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Toggle visibility to foreground before the task that enters hibernation
  // gets a chance to run.
  GetDocument().GetPage()->SetVis
```