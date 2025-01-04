Response:
The user wants a summary of the functionality of the provided C++ code. The code is a test file for a PNG image decoder in the Chromium Blink rendering engine. I need to identify the different test cases and what aspects of the PNG decoder they are verifying. Specifically, I should look for tests related to:

- Animated PNGs (APNGs)
- Handling of malformed or incomplete PNG data
- Frame counting and decoding
- Error conditions like missing IEND chunks or incorrect chunk ordering
- Disposal methods and alpha blending
- Progressive decoding
- Decoding of subset frames
- Handling of offsets in PNG data
- Extra chunks before the IHDR chunk
- Static PNGs
- Repetition count and size of static PNGs
- Metadata extraction
- Handling of specific PNG features like tRNS and PLTE chunks
- High bit-depth PNG decoding
- The `FrameIsReceivedAtIndex` behavior

I will go through each `TEST_P` and `TEST` block and summarize its purpose.
这个C++代码文件 `png_image_decoder_test.cc` 是 Chromium Blink 引擎中 PNG 图片解码器的测试文件，其主要功能是 **验证 PNG 解码器在各种情况下的正确性和健壮性**。

以下是对其功能的归纳：

**主要功能归纳：**

1. **动画 PNG (APNG) 解码测试:**
    *   测试基本的 APNG 解码流程，包括获取帧数、解码每一帧、检查解码状态等。
    *   测试 APNG 重复次数 (repetition count) 的解析。
    *   测试 APNG 中帧的持续时间 (frame duration) 的解析。
    *   测试 APNG 中不同帧的偏移量 (offset) 的处理。

2. **错误处理和健壮性测试:**
    *   测试解码器在遇到**不完整或截断的 APNG 数据**时的行为，例如缺少 IEND chunk。
    *   测试解码器在遇到**格式错误的 APNG 数据**时的行为，例如 IEND chunk 出现在 IDAT chunk 之前，或者 IDAT 和 fdAT chunk 混合出现。
    *   测试解码器在遇到**帧控制块 (fcTL) 中无效的处置方法 (disposal method) 和混合模式 (blend op)** 时的行为。
    *   测试解码器在遇到 **IHDR chunk 错误**时的行为。
    *   测试解码器在 **PNG 签名之前存在额外数据块** 时的行为。

3. **渐进式解码测试:**
    *   测试解码器**逐步接收 PNG 数据**时的解码能力。
    *   验证在接收到完整数据后，仍然可以继续进行渐进式解码。

4. **子集帧 (Subset Frame) 解码测试:**
    *   测试解码器正确解码**仅包含部分图像的帧**的能力。
    *   验证解码器可以正确解码**不依赖于前一帧的独立子集帧**。
    *   测试当**第一个帧是 IHDR 的子集**时解码器的行为。

5. **静态 PNG 解码测试:**
    *   测试基本的静态 PNG 解码流程，包括获取图像尺寸、解码图像、检查解码状态等。
    *   测试静态 PNG 的重复次数 (repetition count)，静态 PNG 的重复次数应为 `kAnimationNone`。
    *   测试静态 PNG 的尺寸 (size) 获取是否正确。
    *   测试静态 PNG 元数据 (metadata) 的提取，例如帧数和帧持续时间。

6. **特定 PNG 特性测试:**
    *   测试处理 **tRNS chunk 出现在 PLTE chunk 之前** 的情况（针对特定的 libpng 版本行为）。

7. **高位深度 PNG 解码测试:**
    *   测试解码 **16 位 PNG** 图像到半精度浮点格式 (RGBA\_F16) 的能力。
    *   验证解码后的像素值是否与预期值接近。
    *   测试 `ImageIsHighBitDepth()` 方法是否能正确判断图像是否为高位深度。

8. **帧完成状态测试:**
    *   测试 `FrameIsReceivedAtIndex()` 方法在不同解码阶段的返回值是否符合预期。

**与 JavaScript, HTML, CSS 的关系举例说明：**

虽然这个 C++ 代码文件本身不直接涉及 JavaScript, HTML, CSS，但它测试的 PNG 解码器是浏览器渲染引擎的核心组成部分，负责将 PNG 图片数据转换为浏览器可以显示的内容。 因此，它的功能与这三者有密切关系：

*   **HTML `<img>` 标签:** 当 HTML 中使用 `<img>` 标签引用一个 PNG 图片时，Blink 引擎会调用 PNG 解码器来解析图片数据。此测试文件验证了解码器是否能正确处理各种 PNG 图片，确保图片能在网页上正确显示。
*   **CSS `background-image` 属性:**  类似地，当 CSS 中使用 `background-image` 属性指定 PNG 图片作为背景时，也会使用 PNG 解码器。此测试保证了解码器能够处理 CSS 中引用的 PNG 图片。
*   **JavaScript `Canvas API`:**  JavaScript 可以使用 `Canvas API` 来绘制和操作图片，包括 PNG 图片。解码器正确解码 PNG 图片是 JavaScript 能够成功操作这些图片的前提。例如，使用 `drawImage()` 方法将解码后的 PNG 图片绘制到 canvas 上。

**逻辑推理举例说明：**

**假设输入:**  一个截断的 APNG 文件，缺少最后的 IEND chunk。

**输出:**

*   **`FrameCount()`:**  根据已解析到的帧控制信息，返回已发现的完整帧的数量。由于缺少 IEND，可能比实际帧数少一个。
*   **`Failed()`:**  在非 Rusty PNG 的情况下，如果无法完整解析到所有帧，解码器会进入失败状态。在 Rusty PNG 的情况下，除非所有帧都失败，否则不会报告整体失败。
*   **`DecodeFrameBufferAtIndex(i)`:**  尝试解码不完整的最后一帧会失败，返回一个状态为非完整的 `ImageFrame` 对象。

**用户或编程常见的使用错误举例说明：**

1. **错误地认为不完整的 PNG 文件可以完全解码:** 用户或开发者可能会尝试加载一个损坏或下载未完成的 PNG 文件，并期望它能正常显示。此测试文件中的 "FailureMissingIendChunk" 测试就模拟了这种情况，并验证解码器在这种情况下不会崩溃，而是返回错误状态。

2. **在 APNG 中错误地混合 IDAT 和 fdAT chunk:**  PNG 规范要求 IDAT chunk 必须在 fdAT chunk 之前。开发者如果错误地生成了混合的 chunk 顺序的 APNG 文件，可能会导致解码失败。此测试文件中的 "MixedDataChunks" 测试验证了解码器能够正确识别并处理这种错误。

3. **在帧控制块中设置了无效的处置方法或混合模式:**  开发者在生成 APNG 时，可能会错误地设置了超出规范允许范围的处置方法或混合模式值。此测试文件中的 "VerifyInvalidDisposalAndBlending" 测试验证了解码器能够检测到这些无效值并进入失败状态，避免潜在的渲染错误或安全问题。

通过这些测试用例，可以有效地确保 Blink 引擎中的 PNG 解码器能够可靠地处理各种合法的和非法的 PNG 文件，从而提升网页浏览的稳定性和用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/png/png_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
-of-animation.png");
}

// This tests if the frame count gets set correctly when parsing FrameCount
// fails in one of the parsing queries.
//
// First, enough data is provided such that two frames should be registered.
// The decoder should at this point not be in the failed status.
//
// Then, we provide the rest of the data except for the last IEND chunk, but
// tell the decoder that this is all the data we have.  The frame count should
// be three, since one extra frame should be discovered. The fourth frame
// should *not* be registered since the reader should not be able to determine
// where the frame ends. The decoder should *not* be in the failed state since
// there are three frames which can be shown.
// Attempting to decode the third frame should fail, since the file is
// truncated.
TEST_P(AnimatedPNGTests, FailureMissingIendChunk) {
  Vector<char> full_data = ReadFile(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png");
  ASSERT_FALSE(full_data.empty());
  auto decoder = CreatePNGDecoder();

  const size_t kOffsetTwoFrames = 249;
  const size_t kExpectedFramesAfter249Bytes = 2;
  scoped_refptr<SharedBuffer> temp_data =
      SharedBuffer::Create(full_data.data(), kOffsetTwoFrames);
  decoder->SetData(temp_data.get(), false);
  EXPECT_EQ(kExpectedFramesAfter249Bytes, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  // Provide the rest of the data except for the last IEND chunk.
  temp_data = SharedBuffer::Create(full_data.data(), full_data.size() - 12);
  decoder->SetData(temp_data.get(), true);

  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    EXPECT_FALSE(decoder->Failed());
    decoder->DecodeFrameBufferAtIndex(i);
  }

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 4u);
  } else {
    ASSERT_TRUE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 3u);
  }
}

// Verify that a malformatted PNG, where the IEND appears before any frame data
// (IDAT), invalidates the decoder.
TEST_P(AnimatedPNGTests, VerifyIENDBeforeIDATInvalidatesDecoder) {
  Vector<char> full_data = ReadFile(
      "/images/resources/"
      "png-animated-idat-part-of-animation.png");
  ASSERT_FALSE(full_data.empty());
  auto decoder = CreatePNGDecoder();

  const size_t kOffsetIDAT = 133;
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), kOffsetIDAT);
  data->Append(full_data.data() + full_data.size() - 12u, 12u);
  data->Append(full_data.data() + kOffsetIDAT, full_data.size() - kOffsetIDAT);
  decoder->SetData(data.get(), true);

  const size_t kExpectedFrameCount = 0u;
  EXPECT_EQ(kExpectedFrameCount, decoder->FrameCount());
  EXPECT_TRUE(decoder->Failed());
}

// All IDAT chunks must be before all fdAT chunks
TEST_P(AnimatedPNGTests, MixedDataChunks) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> full_data = ReadFile(png_file);
  ASSERT_FALSE(full_data.empty());

  // Add an extra fdAT after the first IDAT, skipping fcTL.
  const size_t kPostIDAT = 172u;
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), kPostIDAT);
  const size_t kFcTLSize = 38u;
  const size_t kFdATSize = 31u;
  png_byte fdat[kFdATSize];
  memcpy(fdat, full_data.data() + kPostIDAT + kFcTLSize, kFdATSize);
  // Modify the sequence number
  WriteUint32(1u, fdat + 8);
  data->Append((const char*)fdat, kFdATSize);
  const size_t kIENDOffset = 422u;
  data->Append(full_data.data() + kIENDOffset, full_data.size() - kIENDOffset);
  auto decoder = CreatePNGDecoder();
  decoder->SetData(data.get(), true);
  decoder->FrameCount();

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    EXPECT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 1u);
  } else {
    EXPECT_TRUE(decoder->Failed());
  }

  // Insert an IDAT after an fdAT.
  const size_t kPostfdAT = kPostIDAT + kFcTLSize + kFdATSize;
  data = SharedBuffer::Create(full_data.data(), kPostfdAT);
  const size_t kIDATOffset = 133u;
  data->Append(full_data.data() + kIDATOffset, kPostIDAT - kIDATOffset);
  // Append the rest.
  data->Append(full_data.data() + kPostIDAT, full_data.size() - kPostIDAT);
  decoder = CreatePNGDecoder();
  decoder->SetData(data.get(), true);
  decoder->FrameCount();

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    EXPECT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 2u);
  } else {
    EXPECT_TRUE(decoder->Failed());
  }
}

// Verify that erroneous values for the disposal method and alpha blending
// cause the decoder to fail.
TEST_P(AnimatedPNGTests, VerifyInvalidDisposalAndBlending) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> full_data = ReadFile(png_file);
  ASSERT_FALSE(full_data.empty());
  auto decoder = CreatePNGDecoder();

  // The disposal byte in the frame control chunk is the 24th byte, alpha
  // blending the 25th. |kOffsetDisposalOp| is 241 bytes to get to the third
  // fctl chunk, 8 bytes to skip the length and tag bytes, and 24 bytes to get
  // to the disposal op.
  //
  // Write invalid values to the disposal and alpha blending byte, correct the
  // crc and append the rest of the buffer.
  const size_t kOffsetDisposalOp = 241 + 8 + 24;
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), kOffsetDisposalOp);
  png_byte disposal_and_blending[6u];
  disposal_and_blending[0] = 7;
  disposal_and_blending[1] = 9;
  WriteUint32(2408835439u, disposal_and_blending + 2u);
  data->Append(reinterpret_cast<char*>(disposal_and_blending), 6u);
  data->Append(full_data.data() + kOffsetDisposalOp + 6u,
               full_data.size() - kOffsetDisposalOp - 6u);

  decoder->SetData(data.get(), true);
  decoder->FrameCount();

  if (skia::IsRustyPngEnabled()) {
    // `SkiaImageDecoderBase` doesn't report an overall failure, unless *all*
    // frames fail.  This is by design - see
    // https://crbug.com/371592786#comment3.
    ASSERT_FALSE(decoder->Failed());
    EXPECT_EQ(decoder->FrameCount(), 2u);
  } else {
    ASSERT_TRUE(decoder->Failed());
  }
}

// This test verifies that the following situation does not invalidate the
// decoder:
// - Frame 0 is decoded progressively, but there's not enough data to fully
//   decode it.
// - The rest of the image data is received.
// - Frame X, with X > 0, and X does not depend on frame 0, is decoded.
// - Frame 0 is decoded.
// This is a tricky case since the decoder resets the png struct for each frame,
// and this test verifies that it does not break the decoding of frame 0, even
// though it already started in the first call.
TEST_P(AnimatedPNGTests, VerifySuccessfulFirstFrameDecodeAfterLaterFrame) {
  const char* png_file =
      "/images/resources/"
      "png-animated-three-independent-frames.png";
  auto decoder = CreatePNGDecoder();
  Vector<char> full_data = ReadFile(png_file);
  ASSERT_FALSE(full_data.empty());

  // 160u is a randomly chosen offset in the IDAT chunk of the first frame.
  const size_t kMiddleFirstFrame = 160u;
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), kMiddleFirstFrame);
  decoder->SetData(data.get(), false);

  ASSERT_EQ(1u, decoder->FrameCount());
  ASSERT_EQ(ImageFrame::kFramePartial,
            decoder->DecodeFrameBufferAtIndex(0)->GetStatus());

  decoder->SetData(SharedBuffer::Create(full_data), true);
  if (skia::IsRustyPngEnabled()) {
    // `SkPngRustCodec` cannot discover new frames when in the middle of an
    // incremental decode (see http://review.skia.org/913917).  To make
    // progress, we need to finish the previous decode.
    EXPECT_EQ(ImageFrame::kFrameComplete,
              decoder->DecodeFrameBufferAtIndex(0)->GetStatus());
  }
  ASSERT_EQ(3u, decoder->FrameCount());
  ASSERT_EQ(ImageFrame::kFrameComplete,
            decoder->DecodeFrameBufferAtIndex(1)->GetStatus());
  // The point is that this call does not decode frame 0, which it won't do if
  // it does not have it as its required previous frame.
  ASSERT_EQ(kNotFound,
            decoder->DecodeFrameBufferAtIndex(1)->RequiredPreviousFrameIndex());

  EXPECT_EQ(ImageFrame::kFrameComplete,
            decoder->DecodeFrameBufferAtIndex(0)->GetStatus());
  EXPECT_FALSE(decoder->Failed());
}

// If the decoder attempts to decode a non-first frame which is subset and
// independent, it needs to discard its png_struct so it can use a modified
// IHDR. Test this by comparing a decode of frame 1 after frame 0 to a decode
// of frame 1 without decoding frame 0.
TEST_P(AnimatedPNGTests, DecodeFromIndependentFrame) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-part-of-animation.png";
  Vector<char> original_data = ReadFile(png_file);
  ASSERT_FALSE(original_data.empty());

  // This file almost fits the bill. Modify it to dispose frame 0, making
  // frame 1 independent.
  const size_t kDisposeOffset = 127u;
  auto data = SharedBuffer::Create(original_data.data(), kDisposeOffset);
  // 1 Corresponds to APNG_DISPOSE_OP_BACKGROUND
  const char kOne = '\001';
  data->Append(&kOne, 1u);
  // No need to modify the blend op
  data->Append(original_data.data() + kDisposeOffset + 1, 1u);
  // Modify the CRC
  png_byte crc[4];
  WriteUint32(2226670956, crc);
  data->Append(reinterpret_cast<const char*>(crc), 4u);
  data->Append(original_data.data() + data->size(),
               original_data.size() - data->size());
  ASSERT_EQ(original_data.size(), data->size());

  auto decoder = CreatePNGDecoder();
  decoder->SetData(data.get(), true);

  ASSERT_EQ(4u, decoder->FrameCount());
  ASSERT_FALSE(decoder->Failed());

  auto* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  ASSERT_EQ(ImageFrame::kDisposeOverwriteBgcolor, frame->GetDisposalMethod());

  frame = decoder->DecodeFrameBufferAtIndex(1);
  ASSERT_TRUE(frame);
  ASSERT_FALSE(decoder->Failed());
  ASSERT_NE(gfx::Rect(decoder->Size()), frame->OriginalFrameRect());
  ASSERT_EQ(kNotFound, frame->RequiredPreviousFrameIndex());

  const auto hash = HashBitmap(frame->Bitmap());

  // Now decode starting from frame 1.
  decoder = CreatePNGDecoder();
  decoder->SetData(data.get(), true);

  frame = decoder->DecodeFrameBufferAtIndex(1);
  ASSERT_TRUE(frame);
  EXPECT_EQ(hash, HashBitmap(frame->Bitmap()));
}

// If the first frame is subset from IHDR (only allowed if the first frame is
// not the default image), the decoder has to destroy the png_struct it used
// for parsing so it can use a modified IHDR.
TEST_P(AnimatedPNGTests, SubsetFromIHDR) {
  const char* png_file =
      "/images/resources/"
      "png-animated-idat-not-part-of-animation.png";
  Vector<char> original_data = ReadFile(png_file);
  ASSERT_FALSE(original_data.empty());

  const size_t kFcTLOffset = 2519u;
  auto data = SharedBuffer::Create(original_data.data(), kFcTLOffset);

  const size_t kFcTLSize = 38u;
  png_byte fc_tl[kFcTLSize];
  memcpy(fc_tl, original_data.data() + kFcTLOffset, kFcTLSize);
  // Modify to have a subset frame (yOffset 1, height 34 out of 35).
  WriteUint32(34, fc_tl + 16u);
  WriteUint32(1, fc_tl + 24u);
  WriteUint32(3972842751, fc_tl + 34u);
  data->Append(reinterpret_cast<const char*>(fc_tl), kFcTLSize);

  // Append the rest of the data.
  // Note: If PNGImageDecoder changes to reject an image with too many
  // rows, the fdAT data will need to be modified as well.
  data->Append(original_data.data() + kFcTLOffset + kFcTLSize,
               original_data.size() - data->size());
  ASSERT_EQ(original_data.size(), data->size());

  // This will test both byte by byte and using the full data, and compare.
  TestByteByByteDecode(CreatePNGDecoder, data.get(), 1, kAnimationNone);
}

TEST_P(AnimatedPNGTests, Offset) {
  const char* png_file = "/images/resources/apng18.png";
  Vector<char> original_data = ReadFile(png_file);
  ASSERT_FALSE(original_data.empty());

  Vector<unsigned> baseline_hashes;
  scoped_refptr<SharedBuffer> original_data_buffer =
      SharedBuffer::Create(original_data);
  CreateDecodingBaseline(CreatePNGDecoder, original_data_buffer.get(),
                         &baseline_hashes);
  constexpr size_t kExpectedFrameCount = 13;
  ASSERT_EQ(kExpectedFrameCount, baseline_hashes.size());

  constexpr size_t kOffset = 37;
  char buffer[kOffset] = {};

  auto data = SharedBuffer::Create(buffer, kOffset);
  data->Append(original_data);

  // Use the same defaults as CreatePNGDecoder, except use the (arbitrary)
  // non-zero offset.
  auto decoder = CreatePngImageDecoder(
      ImageDecoder::kAlphaNotPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTransformToSRGB, ImageDecoder::kNoDecodedImageByteLimit,
      kOffset);
  decoder->SetData(data, true);
  ASSERT_EQ(kExpectedFrameCount, decoder->FrameCount());

  for (size_t i = 0; i < kExpectedFrameCount; ++i) {
    auto* frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(baseline_hashes[i], HashBitmap(frame->Bitmap()));
  }
}

TEST_P(AnimatedPNGTests, ExtraChunksBeforeIHDR) {
  const char* png_file = "/images/resources/apng18.png";
  Vector<char> original_data = ReadFile(png_file);
  ASSERT_FALSE(original_data.empty());

  Vector<unsigned> baseline_hashes;
  scoped_refptr<SharedBuffer> original_data_buffer =
      SharedBuffer::Create(original_data);
  CreateDecodingBaseline(CreatePNGDecoder, original_data_buffer.get(),
                         &baseline_hashes);
  constexpr size_t kExpectedFrameCount = 13;
  ASSERT_EQ(kExpectedFrameCount, baseline_hashes.size());

  constexpr size_t kPngSignatureSize = 8;
  auto data = SharedBuffer::Create(original_data.data(), kPngSignatureSize);

  // Arbitrary chunk of data.
  constexpr size_t kExtraChunkSize = 13;
  constexpr png_byte kExtraChunk[kExtraChunkSize] = {
      0, 0, 0, 1, 't', 'R', 'c', 'N', 68, 82, 0, 87, 10};
  data->Append(reinterpret_cast<const char*>(kExtraChunk), kExtraChunkSize);

  // Append the rest of the data from the original.
  data->Append(original_data.data() + kPngSignatureSize,
               original_data.size() - kPngSignatureSize);
  ASSERT_EQ(original_data.size() + kExtraChunkSize, data->size());

  auto decoder = CreatePNGDecoder();
  decoder->SetData(data, true);

  if (skia::IsRustyPngEnabled()) {
    // https://www.w3.org/TR/2003/REC-PNG-20031110/#5ChunkOrdering says that the
    // IHDR chunk "shall be first". Rust `png` crate treats this situation as an
    // error in accordance with the spec.
    //
    // FWIW the `ExtraChunksBeforeIHDR` test was added for
    // https://crbug.com/40090523 and the test input was found by a fuzzer.
    // Reporting a failure seems like a valid way to handle such inputs
    // (as long as there are no heap buffer overflows or other memory safety
    // issues).
    EXPECT_EQ(0u, decoder->FrameCount());
    EXPECT_TRUE(decoder->Failed());
  } else {
    ASSERT_EQ(kExpectedFrameCount, decoder->FrameCount());
    for (size_t i = 0; i < kExpectedFrameCount; ++i) {
      auto* frame = decoder->DecodeFrameBufferAtIndex(i);
      EXPECT_EQ(baseline_hashes[i], HashBitmap(frame->Bitmap()));
    }
    EXPECT_FALSE(decoder->Failed());
  }
}

// Static PNG tests

using StaticPNGTests = PNGTests;
TEST_P(StaticPNGTests, repetitionCountTest) {
  TestRepetitionCount("/images/resources/png-simple.png", kAnimationNone);
}

TEST_P(StaticPNGTests, sizeTest) {
  TestSize("/images/resources/png-simple.png", gfx::Size(111, 29));
}

TEST_P(StaticPNGTests, MetaDataTest) {
  const size_t kExpectedFrameCount = 1;
  const base::TimeDelta kExpectedDuration;
  auto decoder =
      CreatePNGDecoderWithPngData("/images/resources/png-simple.png");
  EXPECT_EQ(kExpectedFrameCount, decoder->FrameCount());
  EXPECT_EQ(kExpectedDuration, decoder->FrameDurationAtIndex(0));
}

// circle-trns-before-plte.png is of color type 2 (PNG_COLOR_TYPE_RGB) and has
// a tRNS chunk before a PLTE chunk. The image has an opaque blue circle on a
// transparent green background.
//
// The PNG specification version 1.2 says:
//   When present, the tRNS chunk must precede the first IDAT chunk, and must
//   follow the PLTE chunk, if any.
// Therefore, in the default libpng configuration (which defines the
// PNG_READ_OPT_PLTE_SUPPORTED macro), the tRNS chunk is considered invalid and
// ignored. However, png_get_valid(png, info, PNG_INFO_tRNS) still returns a
// nonzero value, so an application may call png_set_tRNS_to_alpha(png) and
// assume libpng's output has alpha, resulting in memory errors. See
// https://github.com/glennrp/libpng/issues/482.
//
// Since Chromium chooses to undefine PNG_READ_OPT_PLTE_SUPPORTED in
// pnglibconf.h, it is not affected by this potential bug. For extra assurance,
// this test decodes this image and makes sure there are no errors.
TEST_P(StaticPNGTests, ColorType2TrnsBeforePlte) {
  auto decoder = CreatePNGDecoderWithPngData(
      "/images/resources/circle-trns-before-plte.png");
  ASSERT_EQ(decoder->FrameCount(), 1u);
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  ASSERT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
  ASSERT_EQ(frame->GetPixelFormat(), ImageFrame::kN32);
#ifdef PNG_READ_OPT_PLTE_SUPPORTED
  // When the color type is not PNG_COLOR_TYPE_PALETTE, the PLTE chunk is
  // optional. If PNG_READ_OPT_PLTE_SUPPORTED is defined, libpng performs full
  // processing of an optional PLTE chunk. In particular, it checks if there is
  // a tRNS chunk before the PLTE chunk and ignores any such tRNS chunks.
  // Therefore the tRNS chunk in this image is ignored and the frame should not
  // have alpha.
  EXPECT_FALSE(frame->HasAlpha());
  // The background is opaque green.
  EXPECT_EQ(*frame->GetAddr(1, 1), SkPackARGB32(0xFF, 0, 0xFF, 0));
#else
  // If PNG_READ_OPT_PLTE_SUPPORTED is not defined, libpng performs only minimum
  // processing of an optional PLTE chunk. In particular, it doesn't check if
  // there is a tRNS chunk before the PLTE chunk (which would make the tRNS
  // chunk invalid). Therefore the tRNS chunk in this image is considered valid
  // and the frame should have alpha.
  EXPECT_TRUE(frame->HasAlpha());
  // The background is transparent green.
  EXPECT_EQ(*frame->GetAddr(1, 1), SkPackARGB32(0, 0, 0xFF, 0));
#endif
}

TEST_P(StaticPNGTests, InvalidIHDRChunk) {
  TestMissingDataBreaksDecoding("/images/resources/png-simple.png", 20u, 2u);
}

TEST_P(StaticPNGTests, ProgressiveDecoding) {
  TestProgressiveDecoding(&CreatePNGDecoder, "/images/resources/png-simple.png",
                          11u);
}

TEST_P(StaticPNGTests, ProgressiveDecodingContinuesAfterFullData) {
  TestProgressiveDecodingContinuesAfterFullData(
      "/images/resources/png-simple.png", 1000u);
}

struct PNGSample {
  String filename;
  String color_space;
  bool is_transparent;
  bool is_high_bit_depth;
  scoped_refptr<SharedBuffer> png_contents;
  Vector<float> expected_pixels;
};

static void TestHighBitDepthPNGDecoding(const PNGSample& png_sample,
                                        ImageDecoder* decoder) {
  scoped_refptr<SharedBuffer> png = png_sample.png_contents;
  ASSERT_TRUE(png.get());
  decoder->SetData(png.get(), true);
  ASSERT_TRUE(decoder->IsSizeAvailable());
  ASSERT_TRUE(decoder->IsDecodedSizeAvailable());

  gfx::Size size(2, 2);
  ASSERT_EQ(size, decoder->Size());
  ASSERT_EQ(size, decoder->DecodedSize());
  ASSERT_EQ(true, decoder->ImageIsHighBitDepth());

  ASSERT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  ASSERT_EQ(size, decoder->FrameSizeAtIndex(0));

  ASSERT_EQ(1u, decoder->FrameCount());
  ASSERT_EQ(kAnimationNone, decoder->RepetitionCount());

  auto* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  ASSERT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  ASSERT_EQ(ImageFrame::kRGBA_F16, frame->GetPixelFormat());

  sk_sp<SkImage> image = frame->FinalizePixelsAndGetImage();
  ASSERT_TRUE(image);

  ASSERT_EQ(2, image->width());
  ASSERT_EQ(2, image->height());
  ASSERT_EQ(kRGBA_F16_SkColorType, image->colorType());

  // Readback pixels and convert color components from half float to float.
  SkImageInfo info =
      SkImageInfo::Make(2, 2, kRGBA_F16_SkColorType, kUnpremul_SkAlphaType,
                        image->refColorSpace());
  std::unique_ptr<uint8_t[]> decoded_pixels(
      new uint8_t[info.computeMinByteSize()]());
  ASSERT_TRUE(
      image->readPixels(info, decoded_pixels.get(), info.minRowBytes(), 0, 0));

  float decoded_pixels_float_32[16];
  ASSERT_TRUE(skcms_Transform(
      decoded_pixels.get(), skcms_PixelFormat_RGBA_hhhh,
      skcms_AlphaFormat_Unpremul, nullptr, decoded_pixels_float_32,
      skcms_PixelFormat_RGBA_ffff, skcms_AlphaFormat_Unpremul, nullptr, 4));

  Vector<float> expected_pixels = png_sample.expected_pixels;
  const float decoding_tolerance = 0.001;
  for (int i = 0; i < 16; i++) {
    if (fabs(decoded_pixels_float_32[i] - expected_pixels[i]) >
        decoding_tolerance) {
      FAIL() << "Pixel comparison failed. File: " << png_sample.filename
             << ", component index: " << i
             << ", actual: " << decoded_pixels_float_32[i]
             << ", expected: " << expected_pixels[i]
             << ", tolerance: " << decoding_tolerance;
    }
  }
}

static void FillPNGSamplesSourcePixels(Vector<PNGSample>& png_samples) {
  // Color components of opaque and transparent 16 bit PNG, read with libpng
  // in BigEndian and scaled to [0,1]. The values are read from non-interlaced
  // samples, but used for both interlaced and non-interlaced test cases.
  // The sample pngs were all created by color converting the 8 bit sRGB source
  // in Adobe Photoshop 18. The only exception is e-sRGB test case, for which
  // Adobe software created a non-matching color profile (see crbug.com/874939).
  // Hence, SkEncoder was used to generate the e-sRGB file (see the skia fiddle
  // here: https://fiddle.skia.org/c/17beedfd66dac1ec930f0c414c50f847).
  static const Vector<float> source_pixels_opaque_srgb = {
      0.4986953536, 0.5826657511, 0.7013199054, 1,   // Top left pixel
      0.907988098,  0.8309605554, 0.492011902,  1,   // Top right pixel
      0.6233157855, 0.9726558328, 0.9766536965, 1,   // Bottom left pixel
      0.8946517128, 0.9663080797, 0.9053025101, 1};  // Bottom right pixel
  static const Vector<float> source_pixels_opaque_adobe_rgb = {
      0.4448004883, 0.5216296635, 0.6506294347, 1,   // Top left pixel
      0.8830548562, 0.7978179599, 0.4323186084, 1,   // Top right pixel
      0.6841992828, 0.9704280156, 0.9711299306, 1,   // Bottom left pixel
      0.8874799725, 0.96099794,   0.8875715267, 1};  // Bottom right pixel
  static const Vector<float> source_pixels_opaque_p3 = {
      0.515648127,  0.5802243076, 0.6912489509, 1,   // Top left pixel
      0.8954146639, 0.8337987335, 0.5691767758, 1,   // Top right pixel
      0.772121767,  0.9671625849, 0.973510338,  1,   // Bottom left pixel
      0.9118944076, 0.9645685512, 0.9110704204, 1};  // Bottom right pixel
  static const Vector<float> source_pixels_opaque_e_srgb = {
      0.6977539062, 0.5839843750, 0.4978027344, 1,   // Top left pixel
      0.4899902344, 0.8310546875, 0.9096679688, 1,   // Top right pixel
      0.9760742188, 0.9721679688, 0.6230468750, 1,   // Bottom left pixel
      0.9057617188, 0.9643554688, 0.8940429688, 1};  // Bottom right pixel
  static const Vector<float> source_pixels_opaque_prophoto = {
      0.5032883192, 0.5191271839, 0.6309147784, 1,   // Top left pixel
      0.8184176394, 0.8002899214, 0.5526970321, 1,   // Top right pixel
      0.842526894,  0.945616846,  0.9667048142, 1,   // Bottom left pixel
      0.9119554437, 0.9507133593, 0.9001754788, 1};  // Bottom right pixel
  static const Vector<float> source_pixels_opaque_rec2020 = {
      0.5390554665, 0.5766842145, 0.6851758602, 1,   // Top left pixel
      0.871061265,  0.831326772,  0.5805294881, 1,   // Top right pixel
      0.8386205844, 0.9599603265, 0.9727168688, 1,   // Bottom left pixel
      0.9235217823, 0.9611200122, 0.9112840467, 1};  // Bottom right pixel

  static const Vector<float> source_pixels_transparent_srgb = {
      0.3733272297,  0.4783093004, 0.6266422522, 0.8,   // Top left pixel
      0.8466468299,  0.7182879377, 0.153322652,  0.6,   // Top right pixel
      0.05831998169, 0.9316395819, 0.9416495003, 0.4,   // Bottom left pixel
      0.4733043412,  0.8316319524, 0.5266346227, 0.2};  // Bottom right pixel
  static const Vector<float> source_pixels_transparent_adobe_rgb = {
      0.305943389,  0.4019836728, 0.5632867933,  0.8,   // Top left pixel
      0.8051117723, 0.6630197604, 0.05374227512, 0.6,   // Top right pixel
      0.210482948,  0.926115816,  0.9278248264,  0.4,   // Bottom left pixel
      0.4374456397, 0.8050812543, 0.4379644465,  0.2};  // Bottom right pixel
  static const Vector<float> source_pixels_transparent_p3 = {
      0.3945372702, 0.475257496,  0.6140383001, 0.8,   // Top left pixel
      0.8257114519, 0.7230182345, 0.2819256886, 0.6,   // Top right pixel
      0.4302738994, 0.9179064622, 0.933806363,  0.4,   // Bottom left pixel
      0.5595330739, 0.8228122377, 0.5554436561, 0.2};  // Bottom right pixel
  static const Vector<float> source_pixels_transparent_e_srgb = {
      0.6230468750, 0.4782714844, 0.3723144531, 0.8,   // Top left pixel
      0.1528320312, 0.7172851562, 0.8466796875, 0.6,   // Top right pixel
      0.9409179688, 0.9331054688, 0.0588073730, 0.4,   // Bottom left pixel
      0.5253906250, 0.8310546875, 0.4743652344, 0.2};  // Bottom right pixel
  static const Vector<float> source_pixels_transparent_prophoto = {
      0.379064622,  0.3988708324, 0.5386282139, 0.8,   // Top left pixel
      0.6973525597, 0.6671396963, 0.2544289311, 0.6,   // Top right pixel
      0.6063477531, 0.864103151,  0.9168078126, 0.4,   // Bottom left pixel
      0.5598077363, 0.7536278325, 0.5009384298, 0.2};  // Bottom right pixel
  static const Vector<float> source_pixels_transparent_rec2020 = {
      0.4237735561, 0.4708323796, 0.6064698253, 0.8,   // Top left pixel
      0.7851224537, 0.7188677806, 0.3008468757, 0.6,   // Top right pixel
      0.5965819791, 0.8999618524, 0.9318532082, 0.4,   // Bottom left pixel
      0.6176699474, 0.805600061,  0.5565117876, 0.2};  // Bottom right pixel

  for (PNGSample& png_sample : png_samples) {
    if (png_sample.color_space == "sRGB") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_srgb
                                       : source_pixels_opaque_srgb;
    } else if (png_sample.color_space == "AdobeRGB") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_adobe_rgb
                                       : source_pixels_opaque_adobe_rgb;
    } else if (png_sample.color_space == "DisplayP3") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_p3
                                       : source_pixels_opaque_p3;
    } else if (png_sample.color_space == "e-sRGB") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_e_srgb
                                       : source_pixels_opaque_e_srgb;
    } else if (png_sample.color_space == "ProPhoto") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_prophoto
                                       : source_pixels_opaque_prophoto;
    } else if (png_sample.color_space == "Rec2020") {
      png_sample.expected_pixels = png_sample.is_transparent
                                       ? source_pixels_transparent_rec2020
                                       : source_pixels_opaque_rec2020;
    } else {
      NOTREACHED();
    }
  }
}

static Vector<PNGSample> GetPNGSamplesInfo(bool include_8bit_pngs) {
  Vector<PNGSample> png_samples;
  Vector<String> interlace_status = {"", "_interlaced"};
  Vector<String> color_spaces = {"sRGB",   "AdobeRGB", "DisplayP3",
                                 "e-sRGB", "ProPhoto", "Rec2020"};
  Vector<String> alpha_status = {"_opaque", "_transparent"};

  for (String color_space : color_spaces) {
    for (String alpha : alpha_status) {
      PNGSample png_sample;
      StringBuilder filename;
      filename.Append("_");
      filename.Append(color_space);
      filename.Append(alpha);
      filename.Append(".png");
      png_sample.filename = filename.ToString();
      png_sample.color_space = color_space;
      png_sample.is_transparent = (alpha == "_transparent");

      for (String interlace : interlace_status) {
        PNGSample high_bit_depth_sample(png_sample);
        high_bit_depth_sample.filename =
            "2x2_16bit" + interlace + high_bit_depth_sample.filename;
        high_bit_depth_sample.is_high_bit_depth = true;
        png_samples.push_back(high_bit_depth_sample);
      }
      if (include_8bit_pngs) {
        PNGSample regular_bit_depth_sample(png_sample);
        regular_bit_depth_sample.filename =
            "2x2_8bit" + regular_bit_depth_sample.filename;
        regular_bit_depth_sample.is_high_bit_depth = false;
        png_samples.push_back(regular_bit_depth_sample);
      }
    }
  }

  return png_samples;
}

TEST_P(StaticPNGTests, DecodeHighBitDepthPngToHalfFloat) {
  const bool include_8bit_pngs = false;
  Vector<PNGSample> png_samples = GetPNGSamplesInfo(include_8bit_pngs);
  FillPNGSamplesSourcePixels(png_samples);
  String path = "/images/resources/png-16bit/";
  for (PNGSample& png_sample : png_samples) {
    SCOPED_TRACE(testing::Message()
                 << "Testing '" << png_sample.filename << "'");
    String full_path = path + png_sample.filename;
    png_sample.png_contents = ReadFileToSharedBuffer(full_path);
    auto decoder = Create16BitPNGDecoder();
    TestHighBitDepthPNGDecoding(png_sample, decoder.get());
  }
}

TEST_P(StaticPNGTests, ImageIsHighBitDepth) {
  const bool include_8bit_pngs = true;
  Vector<PNGSample> png_samples = GetPNGSamplesInfo(include_8bit_pngs);
  gfx::Size size(2, 2);

  String path = "/images/resources/png-16bit/";
  for (PNGSample& png_sample : png_samples) {
    String full_path = path + png_sample.filename;
    png_sample.png_contents = ReadFileToSharedBuffer(full_path);
    ASSERT_TRUE(png_sample.png_contents.get());

    std::unique_ptr<ImageDecoder> decoders[] = {CreatePNGDecoder(),
                                                Create16BitPNGDecoder()};
    for (auto& decoder : decoders) {
      decoder->SetData(png_sample.png_contents.get(), true);
      ASSERT_TRUE(decoder->IsSizeAvailable());
      ASSERT_TRUE(decoder->IsDecodedSizeAvailable());
      ASSERT_EQ(size, decoder->Size());
      ASSERT_EQ(size, decoder->DecodedSize());
      ASSERT_EQ(png_sample.is_high_bit_depth, decoder->ImageIsHighBitDepth());
    }
  }
}

TEST_P(PNGTests, VerifyFrameCompleteBehavior) {
  struct {
    const char* name;
    size_t expected_frame_count;
    size_t offset_in_first_frame;
  } g_recs[] = {
      {"/images/resources/"
       "png-animated-three-independent-frames.png",
       3u, 150u},
      {"/images/resources/"
       "png-animated-idat-part-of-animation.png",
       4u, 160u},

      {"/images/resources/png-simple.png", 1u, 700u},
      {"/images/resources/gracehopper.png", 1u, 40000u},
  };
  for (const auto& rec : g_recs) {
    Vector<char> full_data = ReadFile(rec.name);

    // Create with enough data for part of the first frame.
    auto decoder = CreatePNGDecoder();
    auto data =
        SharedBuffer::Create(full_data.data(), rec.offset_in_first_frame);
    decoder->SetData(data.get(), false);

    EXPECT_FALSE(decoder->FrameIsReceivedAtIndex(0));

    // Parsing the size is not enough to mark the frame as complete.
    EXPECT_TRUE(decoder->IsSizeAvailable());
    EXPECT_FALSE(decoder->FrameIsReceivedAtIndex(0));

    const auto partial_frame_count = decoder->FrameCount();
    EXPECT_EQ(1u, partial_frame_count);

    // Frame is not complete, even after decoding partially.
    EXPECT_FALSE(decoder->FrameIsReceivedAtIndex(0));
    auto* frame = decoder->DecodeFrameBufferAtIndex(0);
    ASSERT_TRUE(frame);
    EXPECT_NE(
"""


```