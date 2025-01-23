Response:
The user wants to understand the functionality of the provided C++ source code file, which is a test file for the AVIF image decoder in the Chromium Blink engine.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The filename `avif_image_decoder_test.cc` immediately suggests that this file contains tests for the `AVIFImageDecoder`. The `#include` directives and the use of `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, and `TEST` macros confirm this is a Google Test-based unit test file.

2. **Analyze the Test Cases:** Scan through the `TEST` and `TEST_P` blocks. Each test function focuses on a specific aspect of the AVIF decoder's functionality. Group similar tests together to identify broader functional areas.

3. **Examine Test Parameters:** The `kAnimatedTestParams` and `kStaticTestParams` arrays define sets of test images. These arrays, along with the `AVIFImageParam` struct, reveal the types of images being tested (animated vs. static) and the expected outcomes (frame count, repetition count).

4. **Look for Key Function Calls:** Identify the key functions being called within the tests. `CreateAVIFDecoder()`, `SetData()`, `DecodeFrameBufferAtIndex()`, `ImageHasBothStillAndAnimatedSubImages()`, `FrameTimestampAtIndex()`, `FrameDurationAtIndex()`, `GetGainmapInfoAndData()`, and the helper functions like `TestByteByByteDecode`, `TestInvalidStaticImage`, `TestYUVRed`, `TestAvifBppHistogram`. These functions reveal the primary functionalities being verified.

5. **Infer Functionality from Test Names and Operations:**  The test names are often self-explanatory (e.g., `HasMultipleSubImages`, `HasTimingInformation`, `ByteByByteDecode`). The operations within the tests (setting data, decoding frames, comparing expected values) further clarify the functionalities being tested.

6. **Consider Relationships to Web Technologies (HTML, CSS, JavaScript):** Think about how image decoding relates to these technologies.
    * **HTML:**  The `<image>` tag and the `<img>` element's `src` attribute are the primary ways images are displayed. The decoder's output is what gets rendered.
    * **CSS:**  CSS properties like `background-image` also load images. Image decoders play a crucial role here as well. Animated images can be controlled to some extent with CSS animations or transitions.
    * **JavaScript:** JavaScript can dynamically load and manipulate images, often using the `Image()` constructor or fetching APIs. The underlying decoding process is still handled by components like `AVIFImageDecoder`.

7. **Identify Potential User/Programming Errors:** Based on the tests, identify common mistakes developers might make when dealing with images or the AVIF format. Truncated files, corrupted data, incorrect headers, and assumptions about image properties are potential pitfalls.

8. **Address the "Logic and Reasoning" Prompt:**  For specific tests, consider what the input is (the AVIF image file) and what the expected output is (frame data, metadata, error conditions). This is especially relevant for tests that check for specific values or states.

9. **Synthesize and Organize:** Group the identified functionalities into logical categories. Start with the core purpose (testing the decoder) and then break down the specific aspects being tested (animation, static images, metadata, error handling, gainmaps, YUV decoding, progressive decoding, etc.).

10. **Refine and Elaborate:**  Provide concise descriptions of each functionality. Use examples where applicable to illustrate the connection to HTML, CSS, or JavaScript, or to demonstrate potential errors. For logic and reasoning, explicitly state the assumed input and expected output.

11. **Address the "Part 2" Instruction:** Since this is part 2 of 3, focus on summarizing the functionalities covered in this specific code snippet. Avoid introducing entirely new concepts that might be covered in other parts.

Self-Correction/Refinement during the process:

* **Initial thought:** Focus only on the direct decoding functionality.
* **Correction:**  Expand to include related aspects like metadata extraction (timing, gainmaps), error handling, and different decoding modes (progressive, incremental).
* **Initial thought:**  Provide very technical descriptions of the code.
* **Correction:**  Balance technical details with explanations relevant to web developers and how these functionalities manifest in web browsers. Use simpler language where possible.
* **Initial thought:**  Treat each test case in isolation.
* **Correction:** Group related test cases together to identify broader functional areas and avoid redundancy in the summary.

By following this thought process, the detailed breakdown of the `avif_image_decoder_test.cc` file's functionality can be effectively generated, addressing all aspects of the user's request.
这是文件 `blink/renderer/platform/image-decoders/avif/avif_image_decoder_test.cc` 的第二部分，延续了第一部分对 AVIF 图像解码器功能的测试。

**本部分的功能归纳如下:**

本部分主要集中在以下几个方面的 AVIF 图像解码器测试：

1. **Gain Map 支持测试:**
   - 测试 AVIF 图像中包含 Gain Map 时的信息提取和解码能力。Gain Map 用于扩展图像的动态范围 (HDR)，使其能在标准动态范围 (SDR) 显示器上显示，并保留 HDR 信息。
   - 测试了不同 Gain Map 元数据 (如最小/最大增益比率、Gamma 值、Epsilon 值、显示比率) 的解析是否正确。
   - 测试了 Gain Map 图像本身的解码是否成功。
   - 测试了 Gain Map 的色彩空间处理，包括与主图像色彩空间相同、不同以及使用 CICP (色彩信息代码点) 的情况。
   - 测试了在禁用 Gain Map 功能的情况下，解码器是否能正确处理包含 Gain Map 的图像（应该忽略 Gain Map）。
   - 测试了 Gain Map 数据不完整或 Gamma 值为零时的处理情况（应该失败）。

2. **YUV 色彩空间支持测试:**
   - 测试了对不同 YUV 采样格式 (4:2:0, 4:2:2, 4:4:4) 和位深度 (8bpc, 10bpc, 12bpc) 的 AVIF 图像的解码能力。
   - 测试了对不同色彩空间 (如 BT.709, BT.2020) 和传输特性 (如 PQ, HLG) 的支持。
   - 这些测试确保解码器能正确处理各种常见的 YUV 编码的 AVIF 图像。

3. **尺寸信息可用性测试:**
   - 测试了在接收到所有图像数据之前，解码器是否能够尽早地提供图像的尺寸信息。这对于优化页面加载和渲染非常重要。

4. **渐进式解码测试:**
   - 测试了解码器在接收到部分图像数据时，能否逐步解码并提供部分图像帧的能力。这对于显示大型图像非常有用，可以提高用户体验。
   - 测试了 `ImageFrame::kFramePartial` 状态，表示帧已部分解码。
   - 使用 `base::HistogramTester` 检查了与解码图像密度相关的直方图数据。

5. **增量解码 (分块解码) 测试:**
   - 测试了解码器能否在接收到图像数据的不同部分 (tile) 时，逐步解码并显示图像的不同区域。这对于大型分块编码的图像非常有效。
   - 测试了 `ImageFrame::kFrameEmpty` 和 `ImageFrame::kFramePartial` 状态，以及解码后的像素数据是否与预期一致。
   - 再次使用 `base::HistogramTester` 检查了与解码图像密度相关的直方图数据。

6. **并行解码测试:**
   - 通过模拟并行解码多个大型 AVIF 图像的情况，测试了解码器的线程安全性以及在高并发场景下的稳定性，以避免出现死锁等问题。

7. **错误处理测试 (延续):**
   - 测试了当 AVIF 图像的 Alpha 通道没有 `ispe` 属性时的处理情况 (应该失败)。
   - 测试了当 `colr` 属性中包含不支持的传输函数时的处理情况 (应该失败)。

8. **Clap (Clean Aperture) 属性测试:**
   - 测试了 `clap` 属性的正确处理，该属性定义了图像的有效显示区域。
   - 测试了当 `clap` 属性的起始坐标不为零时的处理情况，在这种情况下，该属性应该被忽略，显示完整图像。
   - 对比了裁剪后的图像和原始图像的像素数据，以验证 `clap` 属性的生效。

9. **BPP (Bits Per Pixel) 直方图测试:**
   - 使用 `base::HistogramTester` 测试了不同尺寸和复杂度的 AVIF 图像的 BPP 值是否被正确记录到直方图中，用于性能分析和优化。

**与 Javascript, HTML, CSS 的关系:**

本部分测试的功能直接影响浏览器在渲染包含 AVIF 图像的网页时的行为：

* **HTML `<img>` 标签和 CSS `background-image`:**  如果网页中使用了 AVIF 格式的图片 (通过 `<img>` 标签的 `src` 属性或 CSS 的 `background-image` 属性引用)，`AVIFImageDecoder` 的功能决定了图片能否被正确解码和显示。Gain Map 的支持使得 HDR AVIF 图像能在支持的浏览器上提供更丰富的色彩和亮度信息。
   * **示例 (HTML):** `<img src="image.avif">`
   * **示例 (CSS):** `.element { background-image: url('image.avif'); }`

* **Javascript 操作图像:**  Javascript 可以通过 `Image()` 构造函数创建图像对象，或者通过 Fetch API 获取图像数据。浏览器内部会调用 `AVIFImageDecoder` 来解码这些 AVIF 数据。渐进式解码功能可以让 Javascript 在图像加载过程中逐步渲染，提供更好的用户体验。
   * **假设输入 (Javascript):**
     ```javascript
     const img = new Image();
     img.src = 'animated.avif';
     document.body.appendChild(img);
     ```
     * **输出:**  如果 `animated.avif` 是一个多帧动画，本部分测试确保解码器能正确提取帧数和循环次数。

* **CSS 动画:**  对于动画 AVIF 图像，CSS 动画或过渡可能影响动画的播放。本部分测试的循环次数信息会被浏览器用于控制动画的重复行为。
   * **假设输入 (CSS):**
     ```css
     .animated-image {
       animation: spin 5s infinite;
     }
     ```
     * **输出:** 如果 `animated.avif` 的 `kAnimationLoopInfinite` 被正确解码，CSS 的 `infinite` 关键字将按预期工作。

**逻辑推理的假设输入与输出:**

* **Gain Map 测试:**
    * **假设输入:**  一个包含 Gain Map 的 AVIF 文件 `/images/resources/avif/small-with-gainmap-iso.avif`。
    * **预期输出:** `decoder->GetGainmapInfoAndData()` 应该返回 `true`，并且 `gainmap_info` 包含正确的 Gain Map 元数据 (例如 `fGainmapRatioMin`, `fGainmapRatioMax`, `fGainmapGamma` 等)。 Gain Map 图像本身也能被成功解码。

* **渐进式解码测试:**
    * **假设输入:**  一个多图层的 AVIF 文件 `/images/resources/avif/tiger_3layer_1res.avif`，分批次提供给解码器。
    * **预期输出:** 在接收到部分数据时，`decoder->DecodeFrameBufferAtIndex(0)` 返回的 `ImageFrame` 的状态为 `ImageFrame::kFramePartial`。当接收到全部数据后，状态变为 `ImageFrame::kFrameComplete`。

* **Clap 属性测试 (有效):**
    * **假设输入:**  一个包含有效 `clap` 属性的 AVIF 文件 `/images/resources/avif/red-and-purple-crop.avif`。
    * **预期输出:** `decoder->Size()` 返回的尺寸应该与 `clap` 属性定义的裁剪后尺寸一致。解码后的图像内容应该与原始未裁剪图像的裁剪区域内容一致。

**用户或编程常见的使用错误举例说明:**

* **未处理 Gain Map 的情况:**  用户可能在一个不支持 Gain Map 的旧浏览器上查看包含 Gain Map 的 AVIF 图像，可能会看到颜色失真或亮度异常。
* **错误地假设动画循环次数:** 开发者可能错误地假设所有动画 AVIF 都是无限循环的，而没有正确读取解码后的循环次数信息，导致动画行为不符合预期。
* **渐进式加载时过早访问未解码区域:**  开发者可能在图像加载完成前就尝试访问部分解码的图像数据，可能会导致显示不完整或空白的区域。
* **假设所有 AVIF 图像都是静态的:**  如果代码假设所有解码的 AVIF 图像都是静态的，而没有处理动画图像的情况，可能会导致动画无法播放。
* **使用不完整的 AVIF 数据进行解码:**  如果程序在 AVIF 数据下载完成前就尝试解码，可能会导致解码失败或崩溃。本部分测试的 "invalidImages" 就模拟了这种情况。

总而言之，本部分测试着重验证了 AVIF 图像解码器在处理 Gain Map、不同 YUV 格式、渐进式/增量式解码以及 `clap` 属性等方面的功能和鲁棒性，确保浏览器能够正确高效地渲染各种复杂的 AVIF 图像。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/avif_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
th-alpha.avif", 5u,
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

using AVIFValidImagesTest = ::testing::TestWithParam<AVIFImageParam>;

INSTANTIATE_TEST_SUITE_P(AnimatedAVIF,
                         AVIFValidImagesTest,
                         ::testing::ValuesIn(kAnimatedTestParams));

INSTANTIATE_TEST_SUITE_P(StaticAVIF,
                         AVIFValidImagesTest,
                         ::testing::ValuesIn(kStaticTestParams));

TEST_P(AVIFValidImagesTest, ByteByByteDecode) {
  TestByteByByteDecode(&CreateAVIFDecoder, GetParam().path,
                       GetParam().expected_frame_count,
                       GetParam().expected_repetition_count);
}

TEST(AnimatedAVIFTests, HasMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/star-animated-8bpc.avif"),
      true);
  EXPECT_TRUE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

TEST(StaticAVIFTests, DoesNotHaveMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/"
                             "red-at-12-oclock-with-color-profile-8bpc.avif"),
      true);
  EXPECT_FALSE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

TEST(StaticAVIFTests, HasTimingInformation) {
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

TEST(AnimatedAVIFTests, HasTimingInformation) {
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

TEST(StaticAVIFTests, NoCrashWhenCheckingForMultipleSubImages) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  constexpr char kHeader[] = {0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70};
  auto buffer = SharedBuffer::Create();
  buffer->Append(kHeader, std::size(kHeader));
  decoder->SetData(std::move(buffer), false);
  EXPECT_FALSE(decoder->ImageHasBothStillAndAnimatedSubImages());
}

// TODO(ryoh): Add corrupted video tests.

TEST(StaticAVIFTests, invalidImages) {
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

TEST(StaticAVIFTests, GetIsoGainmapInfoAndData) {
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

TEST(StaticAVIFTests, GetIsoGainmapInfoAndDataHdrToSdr) {
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

TEST(StaticAVIFTests, GetIsoGainmapColorSpaceSameICC) {
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

TEST(StaticAVIFTests, GetIsoGainmapColorSpaceDifferentICC) {
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

TEST(StaticAVIFTests, GetIsoGainmapColorSpaceDifferentCICP) {
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

TEST(StaticAVIFTests, GetGainmapInfoAndDataWithFeatureDisabled) {
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

TEST(StaticAVIFTests, GetGainmapInfoAndDataWithTruncatedData) {
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

TEST(StaticAVIFTests, GetGainmapWithGammaZero) {
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

TEST(StaticAVIFTests, YUV) {
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

TEST(StaticAVIFTests, SizeAvailableBeforeAllDataReceived) {
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

TEST(StaticAVIFTests, ProgressiveDecoding) {
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

TEST(StaticAVIFTests, IncrementalDecoding) {
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
TEST(StaticAVIFTests, ParallelDecoding) {
  // The base::test::TaskEnvironment constructor creates a base::ThreadPool
  // instance with 4 foreground threads. The number 4 comes from the
  // test::TaskEnvironment::kNumForegroundThreadPoolThreads constant.
  base::test::TaskEnvironment task_environment;

  // This test image is fast to decode (all neutral gray pixels) and its
  // allocation size is large enough to cause
  // media::PaintCanvasVideoRenderer::ConvertVideoFrameToRGBPixels() to pick
  // n_tasks > 1 if AVIFImageDecoder did not pass disable_threading=true to it.
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

TEST(StaticAVIFTests, AlphaHasNoIspeProperty) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/avif/green-no-alpha-ispe.avif"),
      true);
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_TRUE(decoder->Failed());
}

TEST(StaticAVIFTests, UnsupportedTransferFunctionInColrProperty) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();
  decoder->SetData(ReadFileToSharedBuffer(
                       "/images/resources/avif/red-unsupported-transfer.avif"),
                   true);
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_TRUE(decoder->Failed());
}

TEST(StaticAVIFTests, ClapPropertyZeroOrigin) {
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
TEST(StaticAVIFTests, InvalidClapPropertyHandling) {
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

TEST(StaticAVIFTests, BppHistogramSmall) {
  constexpr int kImageArea = 768 * 512;  // = 393216
  constexpr int kFileSize = 25724;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 52
  TestAvifBppHistogram("/images/resources/avif/kodim03.avif",
                       "Blink.DecodedImage.AvifDensity.Count.0.4MP", kSample);
}

TEST(StaticAVIFTests, BppHistogramSmall3x3) {
  // The centi bpp = 318 * 100 * 8 / (3 * 3) ~= 28267, which is greater than the
  // histogram's max value (1000), so this sample goes into the overflow bucket.
  constexpr int kSample = 1000;
  TestAvifBppHistogram("/images/resources/avif/red-full-range-420-8bpc.avif",
                       "Blink.DecodedImage.AvifDensity.Count.0.1MP", kSample);
}

TEST(StaticAVIFTests, BppHistogramSmall900000) {
  constexpr int kImageArea = 1200 * 750;  // = 900000
  constexpr int kFileSize = 8144;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 7
  TestAvifBppHistogram("/images/resources/avif/peach_900000.avif",
                       "Blink.DecodedImage.AvifDensity.Count.0.9MP", kSample);
}

TEST(StaticAVIFTests, BppHistogramBig) {
  constexpr int kImageArea = 4032 * 3024;  // = 12192768
  constexpr int kFileSize = 88692;
  constexpr int kSample =
      (k
```