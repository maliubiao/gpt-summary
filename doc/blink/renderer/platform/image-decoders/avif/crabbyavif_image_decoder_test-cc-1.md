Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is a test file for the AVIF image decoder within the Chromium Blink rendering engine.

To summarize the functionality, I need to identify the main purpose of the tests and the specific scenarios they cover. The tests seem to focus on:

1. **Basic decoding of valid AVIF images (both static and animated).**  This includes checking the number of frames and animation repetitions.
2. **Handling of sub-images (still and animated within the same file).**
3. **Extraction of timing information (timestamps and durations).**
4. **Robustness against incomplete or corrupted data.**
5. **Support for gain maps (metadata and decoding).**
6. **Handling of different color spaces and bit depths.**
7. **Progressive and incremental decoding.**
8. **Concurrency safety in decoding.**
9. **Handling of image properties like `clap` (clean aperture) and `colr` (color information).**
10. **Collection of image density statistics.**

Regarding the relationship with JavaScript, HTML, and CSS:

* **HTML:** The image decoder is crucial for displaying AVIF images embedded in HTML using the `<img>` tag or as background images via CSS.
* **CSS:**  As mentioned above, the decoder enables the use of AVIF images in CSS `background-image` properties. The tests involving gain maps could relate to CSS features for HDR image display.
* **JavaScript:** While the decoder itself is C++, JavaScript APIs in the browser (like the `Image` object or `fetch` API) rely on the underlying decoder to process AVIF image data. JavaScript might be used to trigger the loading and decoding of AVIF images.

For logical reasoning, I can infer the expected outputs based on the test names and the structure of the `AVIFImageParam`. For example, a test named `ByteByByteDecode` likely tests if the decoder can handle receiving image data incrementally.

Common usage errors could involve providing incorrect or corrupted AVIF data, which the tests aim to cover.

Since this is part 2 of a 3-part request, the goal is to summarize the functionality *based on this specific snippet*.
这是目录为blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder_test.cc的chromium blink引擎源代码文件的一部分，延续了之前代码的功能， 专注于测试 CrabbyAVIFImageDecoder 的以下功能：

**1. 动画 AVIF 图像的解码和属性测试:**

* **测试动画帧数和循环次数:**  `kAnimatedTestParams` 定义了一系列动画 AVIF 文件，并指定了预期的帧数 (`expected_frame_count`) 和循环次数 (`expected_repetition_count`)。`INSTANTIATE_TEST_SUITE_P(AnimatedAVIF, ...)` 将这些参数应用于 `CrabbyAVIFValidImagesTest`，并通过 `TEST_P(CrabbyAVIFValidImagesTest, ByteByByteDecode)` 进行逐字节解码测试，验证解码器是否能正确处理动画帧和循环。
* **测试是否包含多个子图像:** `TEST(CrabbyAnimatedAVIFTests, HasMultipleSubImages)`  检查动画 AVIF 文件是否被识别为同时包含静态和动画子图像。

**2. 静态 AVIF 图像的解码和属性测试:**

* **测试静态图像的基本解码:** `kStaticTestParams` 定义了一系列静态 AVIF 文件，并指定了预期的帧数（通常为 1）和无动画循环 (`kAnimationNone`)。同样通过 `INSTANTIATE_TEST_SUITE_P(StaticAVIF, ...)` 和 `TEST_P(CrabbyAVIFValidImagesTest, ByteByByteDecode)` 进行测试。
* **测试是否不包含多个子图像:** `TEST(CrabbyStaticAVIFTests, DoesNotHaveMultipleSubImages)` 检查静态 AVIF 文件是否被识别为不包含动画子图像。
* **测试时间信息:** `TEST(CrabbyStaticAVIFTests, HasTimingInformation)` 验证静态图像解码后是否包含时间戳信息（预期为 0）和持续时间信息（libavif 提供的占位符值）。
* **测试不存在多个子图像时不会崩溃:** `TEST(CrabbyStaticAVIFTests, NoCrashWhenCheckingForMultipleSubImages)` 针对特定格式的静态图像头信息，确保在检查多个子图像时不会发生崩溃。
* **测试无效图像的处理:** `TEST(CrabbyStaticAVIFTests, invalidImages)` 测试解码器如何处理截断的图像数据以及帧头信息错误的图像数据，并验证是否会进入预期的错误处理阶段 (`ErrorPhase::kParse` 或 `ErrorPhase::kDecode`)。

**3. Gain Map (增益图) 功能测试:**

* **测试获取 Gain Map 信息和数据 (SDR Base):** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapInfoAndData)` 启用了 `kAvifGainmapHdrImages` 功能后，测试解码器能否正确解析和提取包含 Gain Map 的 AVIF 图像的元数据 (`SkGainmapInfo`) 和数据 (`SegmentReader`)，并验证 Gain Map 的元数据是否符合预期，以及 Gain Map 本身是否可以被解码。假设输入是一个包含 Gain Map 的 AVIF 文件，输出是 `SkGainmapInfo` 对象包含了 Gain Map 的元数据信息（例如最小/最大增益率，Gamma值等），并且能够获得 Gain Map 的图像数据。
* **测试获取 Gain Map 信息和数据 (HDR to SDR Base):** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapInfoAndDataHdrToSdr)` 与上一个测试类似，但针对的是 HDR 图像作为 base image 的情况，同样验证 Gain Map 的元数据和解码。
* **测试 Gain Map 的颜色空间处理 (相同 ICC Profile):** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceSameICC)` 测试当 base image 和 Gain Map 的 ICC Profile 相同时，Gain Map 的颜色空间信息是否被正确处理 (预期 `fGainmapMathColorSpace` 为空)。
* **测试 Gain Map 的颜色空间处理 (不同 ICC Profile):** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceDifferentICC)` 测试当 base image 和 Gain Map 的 ICC Profile 不同时，Gain Map 的颜色空间信息是否被设置为 Gain Map 的 ICC Profile。假设输入是具有不同 ICC Profile 的 base image 和 Gain Map，输出是 `gainmap_info.fGainmapMathColorSpace` 指向 Gain Map 的颜色空间信息。
* **测试 Gain Map 的颜色空间处理 (不同 CICP):** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceDifferentCICP)` 测试当 base image 和 Gain Map 没有 ICC Profile 但有不同的 CICP 值时，Gain Map 的颜色空间信息是否被设置为 Gain Map 的 CICP 值对应的颜色空间。
* **测试 Gain Map 功能禁用时的处理:** `TEST(CrabbyStaticAVIFTests, GetGainmapInfoAndDataWithFeatureDisabled)` 禁用了 `kAvifGainmapHdrImages` 功能后，测试解码器是否会忽略 Gain Map 信息。假设输入是一个包含 Gain Map 的 AVIF 文件，输出是 `has_gainmap` 为 `false`。
* **测试 Gain Map 数据截断时的处理:** `TEST(CrabbyStaticAVIFTests, GetGainmapInfoAndDataWithTruncatedData)` 测试当 Gain Map 数据被截断时，解码器是否能正确处理。
* **测试 Gain Map 的 Gamma 值为零时的处理:** `TEST(CrabbyStaticAVIFTests, GetGainmapWithGammaZero)` 测试当 Gain Map 的 Gamma 值为零这种无效情况时，解码器是否能正确处理。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接关系到浏览器如何渲染 HTML 页面中的 AVIF 图像。

* **HTML:**  当 HTML 中使用 `<img src="image.avif">` 标签或 `<picture>` 元素加载 AVIF 图片时，CrabbyAVIFImageDecoder 负责解码这些图像数据。测试动画 AVIF 图像的功能确保了浏览器能够正确播放动画 AVIF。
* **CSS:**  当 CSS 中使用 `background-image: url("image.avif");` 时，也会使用此解码器。Gain Map 相关的测试尤其与 CSS 中未来可能支持 HDR 图像显示有关，因为 Gain Map 是实现 HDR 图像显示的一种技术。
* **JavaScript:** 虽然 JavaScript 不直接操作解码器，但 JavaScript 可以通过 Image 对象或 Fetch API 请求 AVIF 图像，浏览器会调用底层的解码器进行处理。例如，JavaScript 可以动态加载 AVIF 图像并在 Canvas 上渲染。

**逻辑推理的假设输入与输出：**

* **假设输入:**  一个合法的动画 AVIF 文件 `/resources/avif/star-animated-8bpc.avif`。
* **预期输出:**  `TEST(CrabbyAnimatedAVIFTests, HasMultipleSubImages)`  会返回 `true`，因为这个文件包含动画。`TEST(CrabbyAnimatedAVIFTests, HasTimingInformation)` 会验证第一帧的时间戳为 `base::TimeDelta()` (0毫秒)，持续时间为 `base::Milliseconds(100)`。
* **假设输入:** 一个截断的静态 AVIF 文件 `/images/resources/avif/red-at-12-oclock-with-color-profile-truncated.avif`。
* **预期输出:** `TEST(CrabbyStaticAVIFTests, invalidImages)` 中对该文件的测试会触发 `ErrorPhase::kParse` 错误阶段，表明解码在解析阶段失败。
* **假设输入:** 一个包含 Gain Map 的 AVIF 文件 `/images/resources/avif/small-with-gainmap-iso.avif`。
* **预期输出:** `TEST(CrabbyStaticAVIFTests, GetIsoGainmapInfoAndData)` 会成功解析 Gain Map 的元数据，例如 `gainmap_info.fGainmapRatioMin` 的值接近 1.0。

**涉及用户或者编程常见的使用错误：**

* **提供损坏的 AVIF 文件:** 用户或程序可能会提供不完整的或者格式错误的 AVIF 文件，这会导致解码失败。例如，`TEST(CrabbyStaticAVIFTests, invalidImages)` 就是测试这种情况。
* **假设所有 AVIF 文件都是静态的:** 开发者可能会错误地认为所有 AVIF 文件都是静态图像，而忽略了动画的可能性，这会导致动画图像只显示第一帧。测试中对动画帧数的验证可以帮助避免这种错误。
* **在不支持 Gain Map 的环境下使用 Gain Map:**  如果浏览器或平台不支持 Gain Map 功能，尝试加载包含 Gain Map 的 AVIF 图像可能不会得到预期的显示效果。`TEST(CrabbyStaticAVIFTests, GetGainmapInfoAndDataWithFeatureDisabled)` 模拟了这种情况。

**归纳一下它的功能 (第2部分):**

这部分代码主要测试了 `CrabbyAVIFImageDecoder` 对动画和静态 AVIF 图像的基本解码能力，包括帧数、循环次数、是否包含多个子图像、时间信息等。此外，重点测试了 Gain Map 功能的解析和提取，涵盖了不同类型的 Gain Map (SDR/HDR base)，以及在启用和禁用 Gain Map 功能时的行为。这部分测试旨在确保解码器能够正确处理各种合法的 AVIF 文件，并能优雅地处理一些非法的或有特殊属性的 AVIF 文件。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/resources/avif/star-animated-10bpc.avif", 5u, 0},
    {"/images/resources/avif/star-animated-10bpc-with-alpha.avif", 5u,
     kAnimationLoopInfinite},
    {"/images/resources/avif/star-animated-12bpc.avif", 5u, 0},
    {"/images/resources/avif/star-animated-12bpc-with-alpha.avif", 5u,
     kAnimationLoopInfinite},
    {"/images/resources/avif/star-animated-8bpc-1-repetition.avif", 5u, 1},
    {"/images/resources/avif/star-animated-8bpc-10-repetition.avif", 5u, 10},
    {"/images/resources/avif/star-animated-8bpc-infinite-repetition.avif", 5u,
     kAnimationLoopInfinite},
};

constexpr AVIFImageParam kStaticTestParams[] = {
    {"/images/resources/avif/red-at-12-oclock-with-color-profile-lossy.avif", 1,
     kAnimationNone},
    {"/images/resources/avif/red-at-12-oclock-with-color-profile-8bpc.avif", 1,
     kAnimationNone},
    {"/images/resources/avif/red-at-12-oclock-with-color-profile-10bpc.avif", 1,
     kAnimationNone},
    {"/images/resources/avif/red-at-12-oclock-with-color-profile-12bpc.avif", 1,
     kAnimationNone},
    {"/images/resources/avif/tiger_3layer_1res.avif", 1, kAnimationNone},
    {"/images/resources/avif/tiger_3layer_3res.avif", 1, kAnimationNone},
    {"/images/resources/avif/tiger_420_8b_grid1x13.avif", 1, kAnimationNone},
    {"/images/resources/avif/dice_444_10b_grid4x3.avif", 1, kAnimationNone},
    {"/images/resources/avif/gracehopper_422_12b_grid2x4.avif", 1,
     kAnimationNone},
    {"/images/resources/avif/small-with-gainmap-iso.avif", 1, kAnimationNone},
};

using CrabbyAVIFValidImagesTest = ::testing::TestWithParam<AVIFImageParam>;

INSTANTIATE_TEST_SUITE_P(AnimatedAVIF,
                         CrabbyAVIFValidImagesTest,
                         ::testing::ValuesIn(kAnimatedTestParams));

INSTANTIATE_TEST_SUITE_P(StaticAVIF,
                         CrabbyAVIFValidImagesTest,
                         ::testing::ValuesIn(kStaticTestParams));

TEST_P(CrabbyAVIFValidImagesTest, ByteByByteDecode) {
  TestByteByByteDecode(&CreateAVIFDecoder, GetParam().path,
                       GetParam().expected_frame_count,
                       GetParam().expected_repetition_count);
}

TEST(CrabbyAnimatedAVIFTests, HasMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/star-animated-8bpc.avif"),
      true);
  EXPECT_TRUE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

TEST(CrabbyStaticAVIFTests, DoesNotHaveMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/"
                             "red-at-12-oclock-with-color-profile-8bpc.avif"),
      true);
  EXPECT_FALSE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

TEST(CrabbyStaticAVIFTests, HasTimingInformation) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/"
                             "red-at-12-oclock-with-color-profile-8bpc.avif"),
      true);
  EXPECT_TRUE(!!decoder->DecodeFrameBufferAtIndex(0));

  // libavif has placeholder values for timestamp and duration on still images,
  // so any duration value is valid, but the timestamp should be zero.
  EXPECT_EQ(base::TimeDelta(), decoder->FrameTimestampAtIndex(0));
}

TEST(CrabbyAnimatedAVIFTests, HasTimingInformation) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/star-animated-8bpc.avif"),
      true);

  constexpr auto kDuration = base::Milliseconds(100);

  EXPECT_TRUE(!!decoder->DecodeFrameBufferAtIndex(0));
  EXPECT_EQ(base::TimeDelta(), decoder->FrameTimestampAtIndex(0));
  EXPECT_EQ(kDuration, decoder->FrameDurationAtIndex(0));

  EXPECT_TRUE(!!decoder->DecodeFrameBufferAtIndex(1));
  EXPECT_EQ(kDuration, decoder->FrameTimestampAtIndex(1));
  EXPECT_EQ(kDuration, decoder->FrameDurationAtIndex(1));
}

TEST(CrabbyStaticAVIFTests, NoCrashWhenCheckingForMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  constexpr char kHeader[] = {0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70};
  auto buffer = SharedBuffer::Create();
  buffer->Append(kHeader, std::size(kHeader));
  decoder->SetData(std::move(buffer), false);
  EXPECT_FALSE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

// TODO(ryoh): Add corrupted video tests.

TEST(CrabbyStaticAVIFTests, invalidImages) {
  // Image data is truncated.
  TestInvalidStaticImage(
      "/images/resources/avif/"
      "red-at-12-oclock-with-color-profile-truncated.avif",
      ErrorPhase::kParse);
  // Chunk size in AV1 frame header doesn't match the file size.
  TestInvalidStaticImage(
      "/images/resources/avif/"
      "red-at-12-oclock-with-color-profile-with-wrong-frame-header.avif",
      ErrorPhase::kDecode);
}

TEST(CrabbyStaticAVIFTests, GetIsoGainmapInfoAndData) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      "/images/resources/avif/small-with-gainmap-iso.avif");
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->Size(), gfx::Size(134, 100));
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_TRUE(has_gainmap);

  // Check gainmap metadata.
  constexpr double kEpsilon = 0.00001;
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[0], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[1], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[2], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[0], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[1], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[2], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[3], 1., kEpsilon);

  EXPECT_NEAR(gainmap_info.fGainmapGamma[0], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[1], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[2], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fEpsilonSdr[0], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[1], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[2], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fEpsilonHdr[0], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[1], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[2], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fDisplayRatioSdr, 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fDisplayRatioHdr, std::exp2(1.4427), kEpsilon);

  EXPECT_EQ(gainmap_info.fBaseImageType, SkGainmapInfo::BaseImageType::kSDR);

  EXPECT_EQ(gainmap_info.fGainmapMathColorSpace, nullptr);

  // Check that the gainmap can be decoded.
  std::unique_ptr<ImageDecoder> gainmap_decoder = CreateGainMapAVIFDecoder();
  gainmap_decoder->SetData(gainmap_data, true);
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(gainmap_decoder->Size(), gfx::Size(33, 25));
  ImageFrame* gainmap_frame = gainmap_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(gainmap_frame);
}

TEST(CrabbyStaticAVIFTests, GetIsoGainmapInfoAndDataHdrToSdr) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      "/images/resources/avif/small-with-gainmap-iso-hdrbase.avif");
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->Size(), gfx::Size(134, 100));
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_TRUE(has_gainmap);

  // Check gainmap metadata.
  constexpr double kEpsilon = 0.00001;
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[0], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[1], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[2], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMin[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[0], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[1], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[2], std::exp2(1.4427), kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapRatioMax[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fGainmapGamma[0], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[1], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[2], 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fGainmapGamma[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fEpsilonSdr[0], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[1], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[2], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonSdr[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fEpsilonHdr[0], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[1], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[2], 0.015625, kEpsilon);
  EXPECT_NEAR(gainmap_info.fEpsilonHdr[3], 1.0, kEpsilon);

  EXPECT_NEAR(gainmap_info.fDisplayRatioSdr, 1.0, kEpsilon);
  EXPECT_NEAR(gainmap_info.fDisplayRatioHdr, std::exp2(1.4427), kEpsilon);

  EXPECT_EQ(gainmap_info.fBaseImageType, SkGainmapInfo::BaseImageType::kHDR);

  // Check that the gainmap can be decoded.
  std::unique_ptr<ImageDecoder> gainmap_decoder = CreateGainMapAVIFDecoder();
  gainmap_decoder->SetData(gainmap_data, true);
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(gainmap_decoder->Size(), gfx::Size(33, 25));
  ImageFrame* gainmap_frame = gainmap_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(gainmap_frame);
}

TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceSameICC) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  // The image has use_base_color_space set to false (i.e. use the alternate
  // image's color space), and the base and alternate image ICC profiles are the
  // same, so the alternate image color space should be ignored.
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      "/images/resources/avif/small-with-gainmap-iso-usealtcolorspace.avif");
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_TRUE(has_gainmap);

  EXPECT_EQ(gainmap_info.fGainmapMathColorSpace, nullptr);
}

void ExpectMatrixNear(const skcms_Matrix3x3& lhs,
                      const skcms_Matrix3x3& rhs,
                      float epsilon) {
  for (int r = 0; r < 3; r++) {
    for (int c = 0; c < 3; c++) {
      EXPECT_NEAR(lhs.vals[r][c], rhs.vals[r][c], epsilon);
    }
  }
}

TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceDifferentICC) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  // The image has use_base_color_space set to false (i.e. use the alternate
  // image's color space), and the base and alternate image ICC profiles are
  // different, so the alternate ICC profile should be set as
  // fGainmapMathColorSpace.
  // Base is sRGB, alternate is P3.
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      "/images/resources/avif/"
      "small-with-gainmap-iso-usealtcolorspace-differenticc.avif");
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_TRUE(has_gainmap);

  // Check that the gain map color space is specified.
  EXPECT_NE(gainmap_info.fGainmapMathColorSpace, nullptr);
  // Only compare the color primaries, the transfer function is irrelevant.
  skcms_Matrix3x3 matrix;
  ASSERT_TRUE(gainmap_info.fGainmapMathColorSpace->toXYZD50(&matrix));
  ExpectMatrixNear(matrix, SkNamedGamut::kDisplayP3, 0.001);
}

TEST(CrabbyStaticAVIFTests, GetIsoGainmapColorSpaceDifferentCICP) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  // The image has use_base_color_space set to false (i.e. use the alternate
  // image's color space), and the base and alternate images don't have ICC
  // but CICP values instead. The alternate image's CICP values should be used.
  // Base is sRGB, alternate is Rec 2020.
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      "/images/resources/avif/gainmap-sdr-srgb-to-hdr-wcg-rec2020.avif");
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_TRUE(has_gainmap);

  // Check that the gain map color space is specified.
  EXPECT_NE(gainmap_info.fGainmapMathColorSpace, nullptr);
  // Only compare the color primaries, the transfer function is irrelevant.
  skcms_Matrix3x3 matrix;
  ASSERT_TRUE(gainmap_info.fGainmapMathColorSpace->toXYZD50(&matrix));
  ExpectMatrixNear(matrix, SkNamedGamut::kRec2020, 0.0001);
}

TEST(CrabbyStaticAVIFTests, GetGainmapInfoAndDataWithFeatureDisabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{},
      /*disabled_features=*/{features::kAvifGainmapHdrImages});

  const std::string image = "small-with-gainmap-iso.avif";
  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("web_tests/images/resources/avif", image.c_str());
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_FALSE(has_gainmap);
}

TEST(CrabbyStaticAVIFTests, GetGainmapInfoAndDataWithTruncatedData) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  const std::string image = "small-with-gainmap-iso.avif";
  const Vector<char> data_vector =
      ReadFile("web_tests/images/resources/avif", image.c_str());
  scoped_refptr<SharedBuffer> half_data =
      SharedBuffer::Create(data_vector.data(), data_vector.size() / 2);

  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(half_data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_FALSE(has_gainmap);
}

TEST(CrabbyStaticAVIFTests, GetGainmapWithGammaZero) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kAvifGainmapHdrImages},
      /*disabled_features=*/{});

  const std::string image = "small-with-gainmap-iso-gammazero.avif";
  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("web_tests/images/resources/avif", image.c_str());
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(data, true);
  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  const bool has_gainmap =
      decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data);
  ASSERT_FALSE(has_gainmap);
}

TEST(CrabbyStaticAVIFTests, YUV) {
  // 3x3, YUV 4:2:0
  constexpr gfx::Size kUVSize420(2, 2);
  TestYUVRed("red-limited-range-420-8bpc.avif", kUVSize420);
  TestYUVRed("red-full-range-420-8bpc.avif", kUVSize420);

  // 3x3, YUV 4:2:2
  constexpr gfx::Size kUVSize422(2, 3);
  TestYUVRed("red-limited-range-422-8bpc.avif", kUVSize422);

  // 3x3, YUV 4:4:4
  constexpr gfx::Size kUVSize444(3, 3);
  TestYUVRed("red-limited-range-444-8bpc.avif", kUVSize444);

  // Full range BT709 color space is uncommon, but should be supported.
  TestYUVRed("red-full-range-bt709-444-8bpc.avif", kUVSize444);

  for (const auto ct : {kA16_unorm_SkColorType, kA16_float_SkColorType}) {
    // 3x3, YUV 4:2:0, 10bpc
    TestYUVRed("red-limited-range-420-10bpc.avif", kUVSize420, ct, 10);

    // 3x3, YUV 4:2:2, 10bpc
    TestYUVRed("red-limited-range-422-10bpc.avif", kUVSize422, ct, 10);

    // 3x3, YUV 4:4:4, 10bpc
    TestYUVRed("red-limited-range-444-10bpc.avif", kUVSize444, ct, 10);

    // 3x3, YUV 4:2:0, 12bpc
    TestYUVRed("red-limited-range-420-12bpc.avif", kUVSize420, ct, 12);

    // 3x3, YUV 4:2:2, 12bpc
    TestYUVRed("red-limited-range-422-12bpc.avif", kUVSize422, ct, 12);

    // 3x3, YUV 4:4:4, 12bpc
    TestYUVRed("red-limited-range-444-12bpc.avif", kUVSize444, ct, 12);

    // Various common color spaces should be supported.
    TestYUVRed("red-full-range-bt2020-pq-444-10bpc.avif", kUVSize444, ct, 10);
    TestYUVRed("red-full-range-bt2020-pq-444-12bpc.avif", kUVSize444, ct, 12);
    TestYUVRed("red-full-range-bt2020-hlg-444-10bpc.avif", kUVSize444, ct, 10);
    TestYUVRed("red-full-range-bt2020-hlg-444-12bpc.avif", kUVSize444, ct, 12);
  }
}

TEST(CrabbyStaticAVIFTests, SizeAvailableBeforeAllDataReceived) {
  scoped_refptr<SharedBuffer> stream_buffer = WTF::SharedBuffer::Create();
  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromSharedBuffer(stream_buffer);
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::CreateByMimeType(
      "image/avif", segment_reader, /*data_complete=*/false,
      ImageDecoder::kAlphaPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTag, cc::AuxImage::kDefault,
      Platform::GetMaxDecodedImageBytes(), SkISize::MakeEmpty(),
      ImageDecoder::AnimationOption::kUnspecified);
  EXPECT_FALSE(decoder->IsSizeAvailable());

  Vector<char> data =
      ReadFile("/images/resources/avif/red-limited-range-420-8bpc.avif");
  stream_buffer->Append(data.data(), data.size());
  EXPECT_EQ(stream_buffer->size(), 318u);
  decoder->SetData(stream_buffer, /*all_data_received=*/false);
  // All bytes are appended so we should have size, even though we pass
  // all_data_received=false.
  EXPECT_TRUE(decoder->IsSizeAvailable());

  decoder->SetData(stream_buffer, /*all_data_received=*/true);
  EXPECT_TRUE(decoder->IsSizeAvailable());
}

TEST(CrabbyStaticAVIFTests, ProgressiveDecoding) {
  base::HistogramTester histogram_tester;
  scoped_refptr<SharedBuffer> stream_buffer = WTF::SharedBuffer::Create();
  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromSharedBuffer(stream_buffer);
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::CreateByMimeType(
      "image/avif", segment_reader, /*data_complete=*/false,
      ImageDecoder::kAlphaPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTag, cc::AuxImage::kDefault,
      Platform::GetMaxDecodedImageBytes(), SkISize::MakeEmpty(),
      ImageDecoder::AnimationOption::kUnspecified);

  Vector<char> data = ReadFile("/images/resources/avif/tiger_3layer_1res.avif");
  ASSERT_EQ(data.size(), 70944u);

  // This image has three layers. The first layer is 8299 bytes. Because of
  // image headers and other overhead, if we pass exactly 8299 bytes to the
  // decoder, the decoder does not have enough data to decode the first layer.
  stream_buffer->Append(data.data(), 8299u);
  decoder->SetData(stream_buffer, /*all_data_received=*/false);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->FrameCount(), 1u);
  histogram_tester.ExpectTotalCount("Blink.DecodedImage.AvifDensity.Count.02MP",
                                    0);
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameEmpty);
  EXPECT_FALSE(decoder->Failed());

  // An additional 301 bytes are enough data for the decoder to decode the first
  // layer. With progressive decoding, the frame buffer status will transition
  // to ImageFrame::kFramePartial.
  stream_buffer->Append(data.data() + 8299u, 301u);
  decoder->SetData(stream_buffer, /*all_data_received=*/false);
  EXPECT_FALSE(decoder->Failed());
  frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFramePartial);
  EXPECT_FALSE(decoder->Failed());

  base::HistogramTester::CountsMap expected_counts;
  EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(
                  "Blink.DecodedImage.AvifDensity.Count."),
              testing::ContainerEq(expected_counts));

  // Now send the rest of the data.
  stream_buffer->Append(data.data() + 8299u + 301u, 62344u);
  decoder->SetData(stream_buffer, /*all_data_received=*/true);
  EXPECT_FALSE(decoder->Failed());
  frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
  EXPECT_FALSE(decoder->Failed());

  constexpr int kImageArea = 1216 * 832;  // = 1011712
  constexpr int kFileSize = 70944;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 56
  histogram_tester.ExpectUniqueSample(
      "Blink.DecodedImage.AvifDensity.Count.02MP", kSample, 1);
  expected_counts["Blink.DecodedImage.AvifDensity.Count.02MP"] = 1;
  EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(
                  "Blink.DecodedImage.AvifDensity.Count."),
              testing::ContainerEq(expected_counts));
}

TEST(CrabbyStaticAVIFTests, IncrementalDecoding) {
  base::HistogramTester histogram_tester;
  scoped_refptr<SharedBuffer> stream_buffer = WTF::SharedBuffer::Create();
  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromSharedBuffer(stream_buffer);
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::CreateByMimeType(
      "image/avif", segment_reader, /*data_complete=*/false,
      ImageDecoder::kAlphaPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTag, cc::AuxImage::kDefault,
      Platform::GetMaxDecodedImageBytes(), SkISize::MakeEmpty(),
      ImageDecoder::AnimationOption::kUnspecified);

  Vector<char> data =
      ReadFile("/images/resources/avif/tiger_420_8b_grid1x13.avif");

  constexpr int kImageArea = 1216 * 832;  // = 1011712
  constexpr int kFileSize = 72257;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 57

  struct Step {
    size_t size;  // In bytes.
    ImageFrame::Status status;
    int num_decoded_rows;  // In pixels.
  };
  // There are 13 tiles. Tiles are as wide as the image and 64 pixels tall.
  // |num_decoded_rows| may be odd due to an output pixel row missing the
  // following upsampled decoded chroma row (belonging to the next tile).
  const Step steps[] = {
      {2000, ImageFrame::kFrameEmpty, 0},
      // Decoding half of the bytes gives 6 tile rows.
      {data.size() / 2, ImageFrame::kFramePartial, 6 * 64 - 1},
      // Decoding all bytes but one gives 12 tile rows.
      {data.size() - 1, ImageFrame::kFramePartial, 12 * 64 - 1},
      // Decoding all bytes gives all 13 tile rows.
      {data.size(), ImageFrame::kFrameComplete, 13 * 64}};
  size_t previous_size = 0;
  for (const Step& step : steps) {
    stream_buffer->Append(data.data() + previous_size,
                          step.size - previous_size);
    decoder->SetData(stream_buffer, step.status == ImageFrame::kFrameComplete);

    EXPECT_EQ(decoder->FrameCount(), 1u);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    ASSERT_TRUE(frame);
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(frame->GetStatus(), step.status);

    const SkBitmap& bitmap = frame->Bitmap();
    for (int y = 0; y < bitmap.height(); ++y) {
      const uint32_t* row = bitmap.getAddr32(0, y);
      const bool is_row_decoded = y < step.num_decoded_rows;
      for (int x = 0; x < bitmap.width(); ++x) {
        // The input image is opaque. Pixels outside the decoded area are fully
        // transparent black pixels, with each channel value being 0.
        const bool is_pixel_decoded = row[x] != 0x00000000u;
        ASSERT_EQ(is_pixel_decoded, is_row_decoded);
      }
    }
    previous_size = step.size;

    base::HistogramTester::CountsMap expected_counts;
    if (step.status == ImageFrame::kFrameComplete) {
      histogram_tester.ExpectUniqueSample(
          "Blink.DecodedImage.AvifDensity.Count.02MP", kSample, 1);
      expected_counts["Blink.DecodedImage.AvifDensity.Count.02MP"] = 1;
    }
    EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(
                    "Blink.DecodedImage.AvifDensity.Count."),
                testing::ContainerEq(expected_counts));
  }
}

// Reproduces crbug.com/1402841. Decodes a large AVIF image 104 times in
// parallel from base::ThreadPool. Should not cause temporary deadlock of
// base::ThreadPool.
TEST(CrabbyStaticAVIFTests, ParallelDecoding) {
  // The base::test::TaskEnvironment constructor creates a base::ThreadPool
  // instance with 4 foreground threads. The number 4 comes from the
  // test::TaskEnvironment::kNumForegroundThreadPoolThreads constant.
  base::test::TaskEnvironment task_environment;

  // This test image is fast to decode (all neutral gray pixels) and its
  // allocation size is large enough to cause
  // media::PaintCanvasVideoRenderer::ConvertVideoFrameToRGBPixels() to pick
  // n_tasks > 1 if CrabbyAVIFImageDecoder did not pass disable_threading=true
  // to it.
  Vector<char> data = ReadFile("/images/resources/avif/gray1024x704.avif");

  // Task timeout in tests is 30 seconds (see https://crrev.com/c/1949028).
  // Four blocking tasks cause a temporary deadlock (1.2 seconds) of
  // base::ThreadPool, so we need at least 30 / 1.2 * 4 = 100 decodes for the
  // test to time out without the bug fix. We add a margin of 4 decodes, i.e.,
  // (30 / 1.2 + 1) * 4 = 104.
  const size_t n_decodes = 104;
  base::WaitableEvent event;
  base::RepeatingClosure barrier = base::BarrierClosure(
      n_decodes,
      base::BindOnce(&base::WaitableEvent::Signal, base::Unretained(&event)));

  for (size_t i = 0; i < n_decodes; ++i) {
    base::ThreadPool::PostTask(
        FROM_HERE,
        base::BindOnce(DecodeTask, base::Unretained(&data), &barrier));
  }

  event.Wait();
}

TEST(CrabbyStaticAVIFTests, AlphaHasNoIspeProperty) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/green-no-alpha-ispe.avif"),
      true);
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_TRUE(decoder->Failed());
}

TEST(CrabbyStaticAVIFTests, UnsupportedTransferFunctionInColrProperty) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(ReadFileToSharedBuffer(
                       "/images/resources/avif/red-unsupported-transfer.avif"),
                   true);
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_TRUE(decoder->Failed());
}

TEST(CrabbyStaticAVIFTests, ClapPropertyZeroOrigin) {
  constexpr int kClapWidth = 200;
  constexpr int kClapHeight = 50;
  std::unique_ptr<ImageDecoder> decoder1 = CreateAVIFDecoder();
  decoder1->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/red-and-purple-crop.avif"),
      true);
  ASSERT_TRUE(decoder1->IsSizeAvailable());
  gfx::Size size1 = decoder1->Size();
  ASSERT_EQ(size1.width(), kClapWidth);
  ASSERT_EQ(size1.height(), kClapHeight);
  ImageFrame* frame1 = decoder1->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame1);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame1->GetStatus());
  EXPECT_FALSE(decoder1->Failed());
  const SkBitmap& bitmap1 = frame1->Bitmap();

  // The second image is the uncropped version of the first image.
  std::unique_ptr<ImageDecoder> decoder2 = CreateAVIFDecoder();
  decoder2->SetData(ReadFileToSharedBuffer(
                        "/images/resources/avif/red-and-purple-and-blue.avif"),
                    true);
  ASSERT_TRUE(decoder2->IsSizeAvailable());
  gfx::Size size2 = decoder2->Size();
  ASSERT_EQ(size2.width(), 300);
  ASSERT_EQ(size2.height(), 100);
  ImageFrame* frame2 = decoder2->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame2);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame2->GetStatus());
  EXPECT_FALSE(decoder2->Failed());
  const SkBitmap& bitmap2 = frame2->Bitmap();

  // Compare pixel data.
  for (int row = 0; row < kClapHeight; ++row) {
    for (int col = 0; col < kClapWidth; ++col) {
      EXPECT_EQ(bitmap1.getColor(/*x=*/col, /*y=*/row),
                bitmap2.getColor(/*x=*/col, /*y=*/row));
    }
  }
}

// Verifies that an invalid 'clap' (clean aperture) image property is handled by
// ignoring the 'clap' property and showing the full image.
TEST(CrabbyStaticAVIFTests, InvalidClapPropertyHandling) {
  // The first image has a valid 'clap' property. The full image has size
  // 320x280. The clean aperture has size 180x100, located at (40, 80) of the
  // full image.
  //
  // Since the origin of the clean aperture is not located at (0, 0), we treat
  // the 'clap' property as invalid. So the full image is shown.
  std::unique_ptr<ImageDecoder> decoder1 = CreateAVIFDecoder();
  decoder1->SetData(ReadFileToSharedBuffer(
                        "/images/resources/avif/blue-and-magenta-crop.avif"),
                    true);
  ASSERT_TRUE(decoder1->IsSizeAvailable());
  gfx::Size size1 = decoder1->Size();
  ASSERT_EQ(size1.width(), 320);
  ASSERT_EQ(size1.height(), 280);
  ImageFrame* frame1 = decoder1->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame1);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame1->GetStatus());
  EXPECT_FALSE(decoder1->Failed());
  const SkBitmap& bitmap1 = frame1->Bitmap();

  // The second image is the same as the first image except that the 'clap'
  // property is invalid. In this case the full image is shown.
  std::unique_ptr<ImageDecoder> decoder2 = CreateAVIFDecoder();
  decoder2->SetData(
      ReadFileToSharedBuffer(
          "/images/resources/avif/blue-and-magenta-crop-invalid.avif"),
      true);
  ASSERT_TRUE(decoder2->IsSizeAvailable());
  gfx::Size size2 = decoder2->Size();
  ASSERT_EQ(size2.width(), 320);
  ASSERT_EQ(size2.height(), 280);
  ImageFrame* frame2 = decoder2->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame2);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame2->GetStatus());
  EXPECT_FALSE(decoder2->Failed());
  const SkBitmap& bitmap2 = frame2->Bitmap();

  // Compare pixel data.
  for (int row = 0; row < size1.height(); ++row) {
    for (int col = 0; col < size1.width(); ++col) {
      EXPECT_EQ(bitmap1.getColor(/*x=*/col, /*y=*/row),
                bitmap2.getColor(/*x=*/col, /*y=*/row));
    }
  }
}

TEST(CrabbyStaticAVIFTests, BppHistogramSmall) {
  constexpr int kImageArea = 768 * 512;  // = 393216
  constexpr int kFileSize = 25724;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 52
  TestAvifBppHistogram("/images/resources/avif/kodim03.avif",
                       "Blink.DecodedImage.AvifDensity.Count.0.4MP", kSample);
}

TEST(CrabbyStaticAVIFTests, BppHistogramSmall3x3) {
  // The centi bpp = 318 * 100 * 8 / (3 * 3) ~= 28267, which is greater than the
  // histogram's max value (1000), so this sample goes into the overflow bucket.
  constexpr int kSample = 1000;
  TestAvifBppHistogram("/images/resources/avif/red-full-range-420-8bpc.avif",
                       "Blink.DecodedImage.AvifDensity.Count.0.1MP", kSample);
}

TEST(CrabbyStaticAVIFTests, BppHistogramSmall900000) {
  constexpr int kImageArea = 1200 * 750;  // = 900000
  constexpr int kFileSize = 8144;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 7
  TestAvifBppHistogram(
```