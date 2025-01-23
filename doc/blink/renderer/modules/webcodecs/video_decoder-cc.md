Response:
Let's break down the thought process for analyzing this `video_decoder.cc` file.

1. **Understanding the Goal:** The request asks for the file's functionality, its relation to web technologies, logical reasoning, common errors, and debugging information. This requires a multi-faceted analysis.

2. **Initial Scan and Keywords:**  I'll first scan the file for prominent keywords and sections. Things that jump out are:
    * `#include`: This tells me about dependencies on other Chromium components and external libraries (like `libvpx`, `libgav1`).
    * `VideoDecoder`, `VideoDecoderConfig`, `EncodedVideoChunk`, `VideoFrame`: These are the core WebCodecs API elements the file deals with.
    * `media::`:  This indicates interaction with Chromium's media pipeline.
    * `blink::`: This confirms it's part of the Blink rendering engine.
    * `ScriptPromise`, `ScriptPromiseResolver`:  This points to asynchronous operations and interactions with JavaScript.
    * `isConfigSupported`, `configure`, `decode`, `flush`, `reset`: These are the main methods of the `VideoDecoder` class.
    * `HardwareAcceleration`, `OptimizeForLatency`: These are configuration options.
    * `ParseCodecString`, `MakeMediaVideoDecoderConfig`:  These suggest logic for handling codec information.
    * Error messages like "Invalid codec", "Invalid config", "A key frame is required": These are crucial for identifying potential user errors.

3. **Dissecting Functionality (High-Level):**  Based on the keywords, I can infer the main purpose: This file implements the `VideoDecoder` WebCodecs API in Blink. It takes encoded video data and configuration information, interacts with the underlying Chromium media pipeline to decode it, and provides the decoded frames back to the web page.

4. **Delving into Specific Functions:** Now, I'll look at individual functions to understand their roles:
    * `isConfigSupported`:  Crucial for checking if the browser can decode a given video configuration. The interaction with `GpuVideoAcceleratorFactories` suggests hardware acceleration is considered.
    * `Create`:  The factory method for creating `VideoDecoder` instances.
    * `configure`: Sets up the decoder with the provided configuration. It involves parsing the configuration and creating a `media::VideoDecoderConfig`. The logic around `VideoDecoderHelper` indicates handling of different codec formats (like Annex B for H.264/HEVC).
    * `decode`: The core decoding function. It takes `EncodedVideoChunk`s, converts them to `media::DecoderBuffer`s, and potentially performs format conversion. The keyframe checking logic is important.
    * `flush`, `reset`: Methods for managing the decoder's state.
    * Helper functions like `ParseCodecString`, `CopyConfig`, `MakeMediaVideoDecoderConfig`: These handle the details of parsing and converting configuration data between the JavaScript API and the internal media structures.
    * Functions like `ParseAv1KeyFrame`, `ParseVpxKeyFrame`, `ParseH264KeyFrame`, `ParseH265KeyFrame`:  Specific logic for identifying keyframes in different video codecs.

5. **Relating to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The primary interface. The `VideoDecoder` class is exposed to JavaScript, allowing developers to interact with it. The use of `ScriptPromise` highlights asynchronous operations triggered by JavaScript. The configuration objects (`VideoDecoderConfig`, `EncodedVideoChunk`) are JavaScript objects.
    * **HTML:** The `<video>` element is a likely use case. JavaScript using `VideoDecoder` might process video data obtained from `<video>` elements or other sources.
    * **CSS:** Indirectly related. CSS styles the presentation of the decoded video within the HTML page. The video dimensions in the configuration could influence how the video is displayed.

6. **Logical Reasoning and Examples:**  For functions like `isConfigSupported` and `decode`, it's helpful to provide examples of input and output.
    * **`isConfigSupported`:** Input would be a `VideoDecoderConfig` object. The output would be a `VideoDecoderSupport` object indicating whether the configuration is supported. The logic considers hardware acceleration.
    * **`decode`:** Input is an `EncodedVideoChunk`. Output is a `VideoFrame`. The keyframe requirement logic provides an opportunity for a reasoning example.

7. **Common User Errors:**  Focusing on the error messages within the code is key here. Examples include:
    * Providing an invalid codec string.
    * Incorrectly specifying coded or display dimensions.
    * Forgetting the `description` field for AVC/HEVC.
    * Providing non-keyframe data after initialization or flushing.

8. **Debugging and User Steps:** To understand how a user might reach this code, think about the typical workflow of using the WebCodecs API:
    1. Create a `VideoDecoder` instance in JavaScript.
    2. Configure the decoder using a `VideoDecoderConfig`.
    3. Feed encoded video data using the `decode` method with `EncodedVideoChunk`s.
    4. Handle the decoded frames through the `output` callback.

9. **Structure and Refinement:**  Organize the findings into the requested categories. Use clear and concise language. Provide specific code examples where helpful (even if they are conceptual JavaScript snippets). Ensure the explanation of the internal workings is accurate but also understandable to someone familiar with web development concepts. Review and refine the explanation for clarity and completeness. For example, initially, I might just say "handles video decoding."  But refining it to "implements the `VideoDecoder` WebCodecs API, taking encoded video data and configuration, interacting with the Chromium media pipeline, and providing decoded frames" is much more informative.

By following these steps, combining code analysis with an understanding of the WebCodecs API and common web development practices, I can generate a comprehensive and accurate explanation of the `video_decoder.cc` file.
这个文件是 Chromium Blink 引擎中 `webcodecs` 模块下 `video_decoder.cc` 的源代码文件。它的主要功能是 **实现 WebCodecs API 中的 `VideoDecoder` 接口**，该接口允许 Web 应用程序解码视频帧。

以下是该文件的详细功能分解：

**1. WebCodecs `VideoDecoder` 接口的实现：**

*   **创建 `VideoDecoder` 对象：**  提供了 `Create` 静态方法，用于在 JavaScript 中创建 `VideoDecoder` 实例。
*   **配置解码器 (`configure`)：**  实现了 `configure` 方法（通过继承的 `DecoderTemplate`），接收一个 `VideoDecoderConfig` 对象作为参数，用于设置解码器的参数，例如视频编解码器、分辨率、颜色空间等。
*   **解码视频块 (`decode`)：** 实现了 `decode` 方法（通过继承的 `DecoderTemplate`），接收一个 `EncodedVideoChunk` 对象作为输入，包含需要解码的编码视频数据。
*   **刷新解码器 (`flush`)：** 实现了 `flush` 方法（通过继承的 `DecoderTemplate`），用于清空解码器内部的缓冲区，确保所有已提交的帧都被解码。
*   **重置解码器 (`reset`)：** 实现了 `reset` 方法（通过继承的 `DecoderTemplate`），将解码器恢复到初始状态。
*   **查询配置支持 (`isConfigSupported`)：** 提供了 `isConfigSupported` 静态方法，允许 JavaScript 查询给定的 `VideoDecoderConfig` 是否被当前浏览器支持。

**2. 与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:** 该文件通过 Blink 的绑定机制，将 `VideoDecoder` 类暴露给 JavaScript。Web 开发者可以使用 JavaScript 代码创建和操作 `VideoDecoder` 对象，例如：

    ```javascript
    const decoder = new VideoDecoder({
      output: (frame) => {
        // 处理解码后的视频帧
        console.log('Decoded frame:', frame);
        frame.close(); // 释放资源
      },
      error: (e) => {
        console.error('Decoding error:', e);
      }
    });

    const config = {
      codec: 'vp8',
      codedWidth: 640,
      codedHeight: 480,
    };

    VideoDecoder.isConfigSupported(config).then((support) => {
      if (support.supported) {
        decoder.configure(config);
        // ... 获取编码的视频数据 chunk 并解码
      } else {
        console.error('Configuration not supported.');
      }
    });

    const chunk = new EncodedVideoChunk({
      type: 'key',
      timestamp: 0,
      duration: 33000,
      data: encodedData // ArrayBuffer 包含编码的视频数据
    });

    decoder.decode(chunk);
    ```

*   **HTML:**  `VideoDecoder` 通常用于处理从 `<video>` 元素或其他来源（如网络）获取的编码视频数据。例如，可以使用 `fetch` API 获取视频文件，然后将编码的数据传递给 `VideoDecoder` 进行解码，并将解码后的帧绘制到 Canvas 或其他渲染目标上。

*   **CSS:**  CSS 主要负责样式控制，与 `VideoDecoder` 的功能没有直接的关联。但是，解码后的视频帧最终可能会渲染到 HTML 元素上，这些元素的样式会受到 CSS 的影响。

**3. 逻辑推理与示例：**

*   **`isConfigSupported` 方法的逻辑推理：**
    *   **假设输入：** 一个 `VideoDecoderConfig` 对象，例如：
        ```javascript
        {
          codec: 'avc1.42E01E', // H.264 Baseline Profile level 3.0
          codedWidth: 1920,
          codedHeight: 1080,
        }
        ```
    *   **输出：** 一个 `Promise`，resolve 的值是一个 `VideoDecoderSupport` 对象，其中 `supported` 属性为 `true` 或 `false`，指示配置是否被支持。
    *   **内部逻辑：**  该方法会解析 `codec` 字符串，检查浏览器是否支持指定的编解码器和配置参数（例如，分辨率是否在支持的范围内），并考虑硬件加速的可用性。它还会调用底层的媒体管道接口进行检查。

*   **`decode` 方法的逻辑推理：**
    *   **假设输入：** 一个 `EncodedVideoChunk` 对象，包含编码的 H.264 视频数据，时间戳为 100000 微秒，时长为 33000 微秒。
    *   **输出：**  通过 `VideoDecoder` 构造函数中 `output` 回调函数接收解码后的 `VideoFrame` 对象。
    *   **内部逻辑：**  `decode` 方法会将 `EncodedVideoChunk` 中的数据转换为媒体管道可以理解的 `DecoderBuffer`，并传递给底层的视频解码器进行解码。如果需要，还会进行格式转换（例如，将 Annex B 格式的 H.264 数据转换为解码器需要的格式）。对于某些编解码器，还会检查是否是关键帧。

**4. 用户或编程常见的使用错误：**

*   **配置不支持的编解码器：**  用户可能会尝试配置浏览器不支持的 `codec` 字符串，导致 `isConfigSupported` 返回 `false` 或在 `configure` 时抛出异常。
    *   **示例：**  配置 `codec: 'my-super-new-codec'`，但浏览器没有实现或支持该编解码器。
*   **配置无效的参数：**  `VideoDecoderConfig` 中的某些参数可能无效，例如，`codedWidth` 或 `codedHeight` 为 0，或者 `displayAspectWidth` 或 `displayAspectHeight` 为 0。
    *   **示例：**  配置 `codedWidth: 0, codedHeight: 720`。
*   **解码非关键帧数据在需要关键帧之后：**  在 `configure` 或 `flush` 之后，解码器通常需要接收一个关键帧才能开始解码。如果用户在此时提交非关键帧数据，解码器可能会返回错误。
    *   **示例：**  对于 H.264 视频，如果配置中没有提供 `description` (SPS/PPS 数据)，解码器可能无法识别关键帧，导致解码失败。
*   **忘记提供 `description` 对于 AVC/HEVC：**  对于 AVC (H.264) 和 HEVC (H.265) 视频，如果编码数据是 Annex B 格式（通常没有起始码），则必须在 `VideoDecoderConfig` 的 `description` 字段中提供 SPS (Sequence Parameter Set) 和 PPS (Picture Parameter Set) 或 VPS/SPS/PPS 数据。否则，解码器可能无法正确初始化。
    *   **示例：**  使用 Annex B 格式的 H.264 数据，但 `config.description` 为空。
*   **资源未释放：**  解码后的 `VideoFrame` 对象需要调用 `close()` 方法来释放其持有的资源。如果用户忘记调用 `close()`，可能会导致内存泄漏。

**5. 用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 JavaScript 代码，使用 WebCodecs API：**  开发者在网页中使用 `new VideoDecoder()` 创建一个 `VideoDecoder` 实例。
2. **调用 `isConfigSupported()` 检查配置：**  开发者可能会调用 `VideoDecoder.isConfigSupported(config)` 来检查给定的视频配置是否被支持。这会触发 `video_decoder.cc` 中的 `isConfigSupported` 静态方法。
3. **调用 `configure()` 配置解码器：**  如果配置被支持，开发者会调用 `decoder.configure(config)`，这会触发 `VideoDecoder::MakeMediaConfig` 和底层的初始化逻辑。
4. **获取编码的视频数据：**  用户通过某种方式（例如，从 `<video>` 元素、`fetch` API 或 WebSocket）获取编码的视频数据。
5. **创建 `EncodedVideoChunk`：**  开发者将编码的数据封装到 `EncodedVideoChunk` 对象中。
6. **调用 `decode()` 解码数据：**  开发者调用 `decoder.decode(chunk)`，这会触发 `video_decoder.cc` 中的 `decode` 方法，将 `EncodedVideoChunk` 转换为 `DecoderBuffer` 并提交给底层的解码器。
7. **接收解码后的帧：**  底层解码器解码成功后，会调用 `VideoDecoder` 构造函数中提供的 `output` 回调函数，并将解码后的 `VideoFrame` 对象作为参数传递给回调函数。
8. **处理解码错误：**  如果解码过程中发生错误，会调用 `VideoDecoder` 构造函数中提供的 `error` 回调函数。

**调试线索：**

*   如果在 JavaScript 中创建 `VideoDecoder` 时发生错误，检查 `VideoDecoder` 的构造函数参数是否正确。
*   如果在调用 `isConfigSupported()` 后发现配置不支持，检查 `VideoDecoderConfig` 对象中的 `codec` 和其他参数是否正确，并查阅浏览器支持的编解码器列表。
*   如果在调用 `configure()` 时发生错误，检查 `VideoDecoderConfig` 对象是否有效，特别是对于 AVC/HEVC，检查是否提供了正确的 `description`。
*   如果在调用 `decode()` 时发生错误，检查 `EncodedVideoChunk` 的 `type` (是否是关键帧)、`timestamp`、`duration` 和 `data` 是否正确。
*   如果在 `output` 回调中没有收到预期的帧，或者收到的帧不正确，可能是解码配置或输入数据有问题。可以检查解码器的状态，查看是否有错误信息。
*   可以使用浏览器的开发者工具中的 "Media" 面板来查看解码器的状态和错误信息。

总而言之，`blink/renderer/modules/webcodecs/video_decoder.cc` 文件是 WebCodecs `VideoDecoder` API 在 Chromium Blink 引擎中的核心实现，负责处理视频解码的配置、数据输入、解码执行和结果输出，并与 JavaScript 和底层的媒体管道进行交互。 理解这个文件有助于深入了解 WebCodecs API 的工作原理和排查相关的解码问题。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/video_decoder.h"

#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/metrics/histogram_functions.h"
#include "base/time/time.h"
#include "media/base/decoder_buffer.h"
#include "media/base/limits.h"
#include "media/base/media_util.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_aspect_ratio.h"
#include "media/base/video_decoder.h"
#include "media/base/video_frame.h"
#include "media/media_buildflags.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_color_space_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_support.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/decrypt_config_util.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"
#include "third_party/blink/renderer/modules/webcodecs/video_color_space.h"
#include "third_party/blink/renderer/modules/webcodecs/video_decoder_broker.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/libgav1/src/src/buffer_pool.h"
#include "third_party/libgav1/src/src/decoder_state.h"
#include "third_party/libgav1/src/src/gav1/status_code.h"
#include "third_party/libgav1/src/src/obu_parser.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

#if BUILDFLAG(ENABLE_LIBVPX)
#include "third_party/libvpx/source/libvpx/vpx/vp8dx.h"        // nogncheck
#include "third_party/libvpx/source/libvpx/vpx/vpx_decoder.h"  // nogncheck
#endif

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
#include "media/filters/h264_to_annex_b_bitstream_converter.h"  // nogncheck
#include "media/formats/mp4/box_definitions.h"                  // nogncheck
#if BUILDFLAG(ENABLE_PLATFORM_HEVC)
#include "media/filters/h265_to_annex_b_bitstream_converter.h"  // nogncheck
#include "media/formats/mp4/hevc.h"                             // nogncheck
#endif
#endif

namespace blink {

namespace {

void DecoderSupport_OnKnown(
    VideoDecoderSupport* support,
    std::unique_ptr<VideoDecoder::MediaConfigType> media_config,
    ScriptPromiseResolver<VideoDecoderSupport>* resolver,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  if (!gpu_factories) {
    support->setSupported(false);
    resolver->Resolve(support);
    return;
  }

  DCHECK(gpu_factories->IsDecoderSupportKnown());
  support->setSupported(
      gpu_factories->IsDecoderConfigSupportedOrUnknown(*media_config) ==
      media::GpuVideoAcceleratorFactories::Supported::kTrue);
  resolver->Resolve(support);
}

bool ParseCodecString(const String& codec_string,
                      media::VideoType& out_video_type,
                      String& js_error_message) {
  if (codec_string.LengthWithStrippedWhiteSpace() == 0) {
    js_error_message = "Invalid codec; codec is required.";
    return false;
  }

  auto result = media::ParseVideoCodecString("", codec_string.Utf8(),
                                             /*allow_ambiguous_matches=*/false);

  if (!result) {
    js_error_message = "Unknown or ambiguous codec name.";
    out_video_type = {media::VideoCodec::kUnknown,
                      media::VIDEO_CODEC_PROFILE_UNKNOWN,
                      media::kNoVideoCodecLevel, media::VideoColorSpace()};
    return true;
  }

  out_video_type = {result->codec, result->profile, result->level,
                    result->color_space};
  return true;
}

VideoDecoderConfig* CopyConfig(const VideoDecoderConfig& config) {
  VideoDecoderConfig* copy = VideoDecoderConfig::Create();
  copy->setCodec(config.codec());

  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());
    if (!desc_wrapper.data()) {
      // Checked by IsValidVideoDecoderConfig.
      NOTREACHED();
    }
    DOMArrayBuffer* buffer_copy = DOMArrayBuffer::Create(desc_wrapper);
    copy->setDescription(
        MakeGarbageCollected<AllowSharedBufferSource>(buffer_copy));
  }

  if (config.hasCodedWidth())
    copy->setCodedWidth(config.codedWidth());

  if (config.hasCodedHeight())
    copy->setCodedHeight(config.codedHeight());

  if (config.hasDisplayAspectWidth())
    copy->setDisplayAspectWidth(config.displayAspectWidth());

  if (config.hasDisplayAspectHeight())
    copy->setDisplayAspectHeight(config.displayAspectHeight());

  if (config.hasColorSpace()) {
    VideoColorSpace* color_space =
        MakeGarbageCollected<VideoColorSpace>(config.colorSpace());
    copy->setColorSpace(color_space->toJSON());
  }

  if (config.hasHardwareAcceleration())
    copy->setHardwareAcceleration(config.hardwareAcceleration());

  if (config.hasOptimizeForLatency())
    copy->setOptimizeForLatency(config.optimizeForLatency());

  return copy;
}

void ParseAv1KeyFrame(const media::DecoderBuffer& buffer,
                      libgav1::BufferPool* buffer_pool,
                      bool* is_key_frame) {
  libgav1::DecoderState decoder_state;
  libgav1::ObuParser parser(buffer.data(), buffer.size(),
                            /*operating_point=*/0, buffer_pool, &decoder_state);
  libgav1::RefCountedBufferPtr frame;
  libgav1::StatusCode status_code = parser.ParseOneFrame(&frame);
  *is_key_frame = status_code == libgav1::kStatusOk &&
                  parser.frame_header().frame_type == libgav1::kFrameKey;
}

void ParseVpxKeyFrame(const media::DecoderBuffer& buffer,
                      media::VideoCodec codec,
                      bool* is_key_frame) {
#if BUILDFLAG(ENABLE_LIBVPX)
  vpx_codec_stream_info_t stream_info = {0};
  stream_info.sz = sizeof(vpx_codec_stream_info_t);
  auto status = vpx_codec_peek_stream_info(
      codec == media::VideoCodec::kVP8 ? vpx_codec_vp8_dx()
                                       : vpx_codec_vp9_dx(),
      buffer.data(), static_cast<uint32_t>(buffer.size()), &stream_info);
  *is_key_frame = (status == VPX_CODEC_OK) && stream_info.is_kf;
#endif
}

void ParseH264KeyFrame(const media::DecoderBuffer& buffer, bool* is_key_frame) {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  auto result = media::mp4::AVC::AnalyzeAnnexB(
      buffer.data(), buffer.size(), std::vector<media::SubsampleEntry>());
  *is_key_frame = result.is_keyframe.value_or(false);
#endif
}

void ParseH265KeyFrame(const media::DecoderBuffer& buffer, bool* is_key_frame) {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
#if BUILDFLAG(ENABLE_PLATFORM_HEVC)
  auto result = media::mp4::HEVC::AnalyzeAnnexB(
      buffer.data(), buffer.size(), std::vector<media::SubsampleEntry>());
  *is_key_frame = result.is_keyframe.value_or(false);
#endif  // BUILDFLAG(ENABLE_PLATFORM_HEVC)
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
}

}  // namespace

struct VideoDecoder::DecoderSpecificData {
  void Reset() {
    decoder_helper.reset();
    av1_buffer_pool.reset();
  }

  // Bitstream converter to annex B for AVC/HEVC.
  std::unique_ptr<VideoDecoderHelper> decoder_helper;

  // Buffer pool for use with libgav1::ObuParser.
  std::unique_ptr<libgav1::BufferPool> av1_buffer_pool;
};

// static
std::unique_ptr<VideoDecoderTraits::MediaDecoderType>
VideoDecoderTraits::CreateDecoder(
    ExecutionContext& execution_context,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    media::MediaLog* media_log) {
  return std::make_unique<VideoDecoderBroker>(execution_context, gpu_factories,
                                              media_log);
}

// static
HardwarePreference VideoDecoder::GetHardwareAccelerationPreference(
    const ConfigType& config) {
  // The IDL defines a default value of "allow".
  DCHECK(config.hasHardwareAcceleration());
  return StringToHardwarePreference(
      IDLEnumAsString(config.hardwareAcceleration()));
}

// static
void VideoDecoderTraits::InitializeDecoder(
    MediaDecoderType& decoder,
    bool low_delay,
    const MediaConfigType& media_config,
    MediaDecoderType::InitCB init_cb,
    MediaDecoderType::OutputCB output_cb) {
  decoder.Initialize(media_config, low_delay, nullptr /* cdm_context */,
                     std::move(init_cb), output_cb, media::WaitingCB());
}

// static
void VideoDecoderTraits::UpdateDecoderLog(const MediaDecoderType& decoder,
                                          const MediaConfigType& media_config,
                                          media::MediaLog* media_log) {
  media_log->SetProperty<media::MediaLogProperty::kVideoDecoderName>(
      decoder.GetDecoderType());
  media_log->SetProperty<media::MediaLogProperty::kIsPlatformVideoDecoder>(
      decoder.IsPlatformDecoder());
  media_log->SetProperty<media::MediaLogProperty::kVideoTracks>(
      std::vector<MediaConfigType>{media_config});
  MEDIA_LOG(INFO, media_log)
      << "Initialized VideoDecoder: " << media_config.AsHumanReadableString();
  base::UmaHistogramEnumeration("Blink.WebCodecs.VideoDecoder.Codec",
                                media_config.codec());
}

// static
int VideoDecoderTraits::GetMaxDecodeRequests(const MediaDecoderType& decoder) {
  return decoder.GetMaxDecodeRequests();
}

// static
const char* VideoDecoderTraits::GetName() {
  return "VideoDecoder";
}

// static
VideoDecoder* VideoDecoder::Create(ScriptState* script_state,
                                   const VideoDecoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result =
      MakeGarbageCollected<VideoDecoder>(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

// static
ScriptPromise<VideoDecoderSupport> VideoDecoder::isConfigSupported(
    ScriptState* script_state,
    const VideoDecoderConfig* config,
    ExceptionState& exception_state) {
  // Run the "check if a config is a valid VideoDecoderConfig" algorithm.
  String js_error_message;
  std::optional<media::VideoType> video_type =
      IsValidVideoDecoderConfig(*config, &js_error_message /* out */);
  if (!video_type) {
    exception_state.ThrowTypeError(js_error_message);
    return EmptyPromise();
  }

  // Run the "Clone Configuration" algorithm.
  auto* config_copy = CopyConfig(*config);

  // Run the "Check Configuration Support" algorithm.
  HardwarePreference hw_pref = GetHardwareAccelerationPreference(*config_copy);
  VideoDecoderSupport* support = VideoDecoderSupport::Create();
  support->setConfig(config_copy);

  if ((hw_pref == HardwarePreference::kPreferSoftware &&
       !media::IsDecoderBuiltInVideoCodec(video_type->codec)) ||
      !media::IsDecoderSupportedVideoType(*video_type)) {
    support->setSupported(false);
    return ToResolvedPromise<VideoDecoderSupport>(script_state, support);
  }

  // Check that we can make a media::VideoDecoderConfig. The |js_error_message|
  // is ignored, we report only via |support.supported|.
  std::optional<MediaConfigType> media_config;
  media_config = MakeMediaVideoDecoderConfig(*config_copy, &js_error_message);
  if (!media_config) {
    support->setSupported(false);
    return ToResolvedPromise<VideoDecoderSupport>(script_state, support);
  }

  // If hardware is preferred, asynchronously check for a hardware decoder.
  if (hw_pref == HardwarePreference::kPreferHardware) {
    auto* resolver =
        MakeGarbageCollected<ScriptPromiseResolver<VideoDecoderSupport>>(
            script_state, exception_state.GetContext());
    auto promise = resolver->Promise();
    RetrieveGpuFactoriesWithKnownDecoderSupport(CrossThreadBindOnce(
        &DecoderSupport_OnKnown, MakeUnwrappingCrossThreadHandle(support),
        std::make_unique<MediaConfigType>(*media_config),
        MakeUnwrappingCrossThreadHandle(resolver)));
    return promise;
  }

  // Otherwise, the config is supported.
  support->setSupported(true);
  return ToResolvedPromise<VideoDecoderSupport>(script_state, support);
}

HardwarePreference VideoDecoder::GetHardwarePreference(
    const ConfigType& config) {
  return GetHardwareAccelerationPreference(config);
}

bool VideoDecoder::GetLowDelayPreference(const ConfigType& config) {
  return config.hasOptimizeForLatency() && config.optimizeForLatency();
}

void VideoDecoder::SetHardwarePreference(HardwarePreference preference) {
  static_cast<VideoDecoderBroker*>(decoder())->SetHardwarePreference(
      preference);
}

// static
// TODO(crbug.com/1198324): Merge shared logic with VideoFramePlaneInit.
std::optional<media::VideoType> VideoDecoder::IsValidVideoDecoderConfig(
    const VideoDecoderConfig& config,
    String* js_error_message) {
  media::VideoType video_type;
  if (!ParseCodecString(config.codec(), video_type, *js_error_message))
    return std::nullopt;

  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());
    if (!desc_wrapper.data()) {
      *js_error_message = "Invalid config, description is detached.";
      return std::nullopt;
    }
  }

  if (config.hasCodedWidth() || config.hasCodedHeight()) {
    if (!config.hasCodedWidth()) {
      *js_error_message =
          "Invalid config, codedHeight specified without codedWidth.";
      return std::nullopt;
    }
    if (!config.hasCodedHeight()) {
      *js_error_message =
          "Invalid config, codedWidth specified without codedHeight.";
      return std::nullopt;
    }

    const uint32_t coded_width = config.codedWidth();
    const uint32_t coded_height = config.codedHeight();
    if (!coded_width || !coded_height) {
      *js_error_message = String::Format("Invalid coded size (%u, %u).",
                                         coded_width, coded_height);
      return std::nullopt;
    }
  }

  if (config.hasDisplayAspectWidth() || config.hasDisplayAspectHeight()) {
    if (!config.hasDisplayAspectWidth()) {
      *js_error_message =
          "Invalid config, displayAspectHeight specified without "
          "displayAspectWidth.";
      return std::nullopt;
    }
    if (!config.hasDisplayAspectHeight()) {
      *js_error_message =
          "Invalid config, displayAspectWidth specified without "
          "displayAspectHeight.";
      return std::nullopt;
    }

    uint32_t display_aspect_width = config.displayAspectWidth();
    uint32_t display_aspect_height = config.displayAspectHeight();
    if (display_aspect_width == 0 || display_aspect_height == 0) {
      *js_error_message =
          String::Format("Invalid display aspect (%u, %u).",
                         display_aspect_width, display_aspect_height);
      return std::nullopt;
    }
  }

  return video_type;
}

// static
std::optional<media::VideoDecoderConfig>
VideoDecoder::MakeMediaVideoDecoderConfig(const ConfigType& config,
                                          String* js_error_message,
                                          bool* needs_converter_out) {
  std::unique_ptr<VideoDecoderHelper> decoder_helper;
  VideoDecoder::DecoderSpecificData decoder_specific_data;
  return MakeMediaVideoDecoderConfigInternal(
      config, decoder_specific_data, js_error_message, needs_converter_out);
}

// static
std::optional<media::VideoDecoderConfig>
VideoDecoder::MakeMediaVideoDecoderConfigInternal(
    const ConfigType& config,
    DecoderSpecificData& decoder_specific_data,
    String* js_error_message,
    bool* needs_converter_out) {
  decoder_specific_data.Reset();
  media::VideoType video_type;
  if (!ParseCodecString(config.codec(), video_type, *js_error_message)) {
    // Checked by IsValidVideoDecoderConfig().
    NOTREACHED();
  }
  if (video_type.codec == media::VideoCodec::kUnknown) {
    return std::nullopt;
  }

  std::vector<uint8_t> extra_data;
  if (config.hasDescription()) {
    auto desc_wrapper = AsSpan<const uint8_t>(config.description());
    if (!desc_wrapper.data()) {
      // Checked by IsValidVideoDecoderConfig().
      NOTREACHED();
    }
    if (!desc_wrapper.empty()) {
      const uint8_t* start = desc_wrapper.data();
      const size_t size = desc_wrapper.size();
      extra_data.assign(start, start + size);
    }
  }
  if (needs_converter_out) {
    *needs_converter_out = (extra_data.size() > 0);
  }

  if ((extra_data.size() > 0) &&
      (video_type.codec == media::VideoCodec::kH264 ||
       video_type.codec == media::VideoCodec::kHEVC)) {
    VideoDecoderHelper::Status status;
    decoder_specific_data.decoder_helper = VideoDecoderHelper::Create(
        video_type, extra_data.data(), static_cast<int>(extra_data.size()),
        &status);
    if (status != VideoDecoderHelper::Status::kSucceed) {
      if (video_type.codec == media::VideoCodec::kH264) {
        if (status == VideoDecoderHelper::Status::kDescriptionParseFailed) {
          *js_error_message = "Failed to parse avcC.";
        } else if (status == VideoDecoderHelper::Status::kUnsupportedCodec) {
          *js_error_message = "H.264 decoding is not supported.";
        }
      } else if (video_type.codec == media::VideoCodec::kHEVC) {
        if (status == VideoDecoderHelper::Status::kDescriptionParseFailed) {
          *js_error_message = "Failed to parse hvcC.";
        } else if (status == VideoDecoderHelper::Status::kUnsupportedCodec) {
          *js_error_message = "HEVC decoding is not supported.";
        }
      }
      return std::nullopt;
    }
    // The description should not be provided to the decoder because the stream
    // will be converted to Annex B format.
    extra_data.clear();
  }

  if (video_type.codec == media::VideoCodec::kAV1) {
    decoder_specific_data.av1_buffer_pool =
        std::make_unique<libgav1::BufferPool>(
            /*on_frame_buffer_size_changed=*/nullptr,
            /*get_frame_buffer=*/nullptr,
            /*release_frame_buffer=*/nullptr,
            /*callback_private_data=*/nullptr);
  }

  // Guess 720p if no coded size hint is provided. This choice should result in
  // a preference for hardware decode.
  gfx::Size coded_size = gfx::Size(1280, 720);
  if (config.hasCodedWidth() && config.hasCodedHeight())
    coded_size = gfx::Size(config.codedWidth(), config.codedHeight());

  // These are meaningless.
  // TODO(crbug.com/1214061): Remove.
  gfx::Rect visible_rect(gfx::Point(), coded_size);
  gfx::Size natural_size = coded_size;

  // Note: Using a default-constructed VideoAspectRatio allows decoders to
  // override using in-band metadata.
  media::VideoAspectRatio aspect_ratio;
  if (config.hasDisplayAspectWidth() && config.hasDisplayAspectHeight()) {
    aspect_ratio = media::VideoAspectRatio::DAR(config.displayAspectWidth(),
                                                config.displayAspectHeight());
  }

  // TODO(crbug.com/1138680): Ensure that this default value is acceptable
  // under the WebCodecs spec. Should be BT.709 for YUV, sRGB for RGB, or
  // whatever was explicitly set for codec strings that include a color space.
  media::VideoColorSpace media_color_space = video_type.color_space;
  if (config.hasColorSpace()) {
    VideoColorSpace* color_space =
        MakeGarbageCollected<VideoColorSpace>(config.colorSpace());
    media_color_space = color_space->ToMediaColorSpace();
  }

  auto encryption_scheme = media::EncryptionScheme::kUnencrypted;
  if (config.hasEncryptionScheme()) {
    auto scheme = ToMediaEncryptionScheme(config.encryptionScheme());
    if (!scheme) {
      *js_error_message = "Unsupported encryption scheme";
      return std::nullopt;
    }
    encryption_scheme = scheme.value();
  }

  media::VideoDecoderConfig media_config;
  media_config.Initialize(video_type.codec, video_type.profile,
                          media::VideoDecoderConfig::AlphaMode::kIsOpaque,
                          media_color_space, media::kNoTransformation,
                          coded_size, visible_rect, natural_size, extra_data,
                          encryption_scheme);
  media_config.set_aspect_ratio(aspect_ratio);
  if (!media_config.IsValidConfig()) {
    *js_error_message = "Unsupported config.";
    return std::nullopt;
  }

  return media_config;
}

VideoDecoder::VideoDecoder(ScriptState* script_state,
                           const VideoDecoderInit* init,
                           ExceptionState& exception_state)
    : DecoderTemplate<VideoDecoderTraits>(script_state, init, exception_state),
      decoder_specific_data_(std::make_unique<DecoderSpecificData>()) {
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebCodecs);
}

VideoDecoder::~VideoDecoder() = default;

bool VideoDecoder::IsValidConfig(const ConfigType& config,
                                 String* js_error_message) {
  return IsValidVideoDecoderConfig(config, js_error_message /* out */)
      .has_value();
}

std::optional<media::VideoDecoderConfig> VideoDecoder::MakeMediaConfig(
    const ConfigType& config,
    String* js_error_message) {
  DCHECK(js_error_message);
  std::optional<media::VideoDecoderConfig> media_config =
      MakeMediaVideoDecoderConfigInternal(
          config, *decoder_specific_data_.get() /* out */,
          js_error_message /* out */);
  if (media_config)
    current_codec_ = media_config->codec();
  return media_config;
}

media::DecoderStatus::Or<scoped_refptr<media::DecoderBuffer>>
VideoDecoder::MakeInput(const InputType& chunk, bool verify_key_frame) {
  scoped_refptr<media::DecoderBuffer> decoder_buffer = chunk.buffer();
  if (decoder_specific_data_->decoder_helper) {
    const uint8_t* src = chunk.buffer()->data();
    size_t src_size = chunk.buffer()->size();

    // Note: this may not be safe if support for SharedArrayBuffers is added.
    uint32_t output_size =
        decoder_specific_data_->decoder_helper->CalculateNeededOutputBufferSize(
            src, static_cast<uint32_t>(src_size), verify_key_frame);
    if (!output_size) {
      return media::DecoderStatus(
          media::DecoderStatus::Codes::kMalformedBitstream,
          "Unable to determine size of bitstream buffer.");
    }

    std::vector<uint8_t> buf(output_size);
    if (decoder_specific_data_->decoder_helper
            ->ConvertNalUnitStreamToByteStream(
                src, static_cast<uint32_t>(src_size), buf.data(), &output_size,
                verify_key_frame) != VideoDecoderHelper::Status::kSucceed) {
      return media::DecoderStatus(
          media::DecoderStatus::Codes::kMalformedBitstream,
          "Unable to convert NALU to byte stream.");
    }

    decoder_buffer =
        media::DecoderBuffer::CopyFrom(base::span(buf).first(output_size));
    decoder_buffer->set_timestamp(chunk.buffer()->timestamp());
    decoder_buffer->set_duration(chunk.buffer()->duration());
  }

  bool is_key_frame = chunk.type() == V8EncodedVideoChunkType::Enum::kKey;
  if (verify_key_frame) {
    if (current_codec_ == media::VideoCodec::kVP9 ||
        current_codec_ == media::VideoCodec::kVP8) {
      ParseVpxKeyFrame(*decoder_buffer, current_codec_, &is_key_frame);
    } else if (current_codec_ == media::VideoCodec::kAV1) {
      ParseAv1KeyFrame(*decoder_buffer,
                       decoder_specific_data_->av1_buffer_pool.get(),
                       &is_key_frame);
    } else if (current_codec_ == media::VideoCodec::kH264) {
      ParseH264KeyFrame(*decoder_buffer, &is_key_frame);

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      // Use a more helpful error message if we think the user may have forgot
      // to provide a description for AVC H.264. We could try to guess at the
      // NAL unit size and see if a NAL unit parses out, but this seems fine.
      if (!is_key_frame && !decoder_specific_data_->decoder_helper) {
        return media::DecoderStatus(
            media::DecoderStatus::Codes::kKeyFrameRequired,
            "A key frame is required after configure() or flush(). If you're "
            "using AVC formatted H.264 you must fill out the description field "
            "in the VideoDecoderConfig.");
      }
#endif
    } else if (current_codec_ == media::VideoCodec::kHEVC) {
      ParseH265KeyFrame(*decoder_buffer, &is_key_frame);

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
#if BUILDFLAG(ENABLE_PLATFORM_HEVC)
      if (!is_key_frame && !decoder_specific_data_->decoder_helper) {
        return media::DecoderStatus(
            media::DecoderStatus::Codes::kKeyFrameRequired,
            "A key frame is required after configure() or flush(). If you're "
            "using HEVC formatted H.265 you must fill out the description "
            "field in the VideoDecoderConfig.");
      }
#endif  // BUILDFLAG(ENABLE_PLATFORM_HEVC)
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
    }

    if (!is_key_frame) {
      return media::DecoderStatus(
          media::DecoderStatus::Codes::kKeyFrameRequired,
          "A key frame is required after configure() or flush().");
    }
  }

  chunk_metadata_[chunk.buffer()->timestamp()] =
      ChunkMetadata{chunk.buffer()->duration()};

  return decoder_buffer;
}

media::DecoderStatus::Or<VideoDecoder::OutputType*> VideoDecoder::MakeOutput(
    scoped_refptr<MediaOutputType> output,
    ExecutionContext* context) {
  const auto it = chunk_metadata_.find(output->timestamp());
  if (it != chunk_metadata_.end()) {
    const auto duration = it->second.duration;
    if (!duration.is_zero() && duration != media::kNoTimestamp) {
      auto wrapped_output = media::VideoFrame::WrapVideoFrame(
          output, output->format(), output->visible_rect(),
          output->natural_size());
      wrapped_output->set_color_space(output->ColorSpace());
      wrapped_output->metadata().frame_duration = duration;
      output = wrapped_output;
    }

    // We erase from the beginning onward to our target frame since frames
    // should be returned in presentation order.
    chunk_metadata_.erase(chunk_metadata_.begin(), it + 1);
  }
  return MakeGarbageCollected<OutputType>(std::move(output), context);
}

const AtomicString& VideoDecoder::InterfaceName() const {
  return event_target_names::kVideoDecoder;
}

}  // namespace blink
```