Response: The user wants to understand the functionality of the C++ unit test file `h265_parameter_sets_tracker_unittest.cc`. I need to analyze the test cases and the code they exercise to determine the purpose of the `H265ParameterSetsTracker` class.

Here's a breakdown of the thought process:

1. **Identify the core component under test:** The file name and the `#include` directive clearly indicate that the tests are for `H265ParameterSetsTracker`.

2. **Analyze the test case names:** The names of the test functions provide valuable clues about the functionality being tested. Keywords like "NoNalus", "StreamFromMissMatchingH26xCodec", "AllParameterSets...", "MissingForIdr", "SingleDeltaSlice...", "ParameterSetsInPreviousIdr...", "TwoGops..." suggest different scenarios related to H.265 bitstreams and parameter sets.

3. **Examine the test setup and assertions:**  Each test case sets up input data (often representing H.265 NAL units like VPS, SPS, PPS, IDR, TRAIL, CRA) and then calls `tracker_.MaybeFixBitstream()`. The assertions using `EXPECT_THAT` verify the `action` returned by the method (e.g., `kPassThrough`, `kRequestKeyframe`, `kInsert`) and sometimes the modified bitstream content.

4. **Infer the purpose of `H265ParameterSetsTracker::MaybeFixBitstream()`:** Based on the test cases, this method seems to analyze an incoming H.265 bitstream and decide how to handle it. It can either:
    * `kPassThrough`: Let the bitstream pass unchanged.
    * `kRequestKeyframe`: Signal that a keyframe is needed.
    * `kInsert`: Modify the bitstream by inserting missing parameter sets.

5. **Determine the role of parameter sets (VPS, SPS, PPS):** The tests frequently involve checking for the presence or absence of VPS, SPS, and PPS. This strongly suggests that the tracker is concerned with ensuring these essential parameter sets are available for decoding.

6. **Connect to WebRTC/PeerConnection:** The file path `blink/renderer/platform/peerconnection/` suggests this tracker is used within the context of WebRTC in the Chromium browser. Parameter sets are crucial for decoding video streams transmitted over a peer connection.

7. **Consider the relationship to JavaScript/HTML/CSS:**  While the C++ code itself doesn't directly interact with JavaScript/HTML/CSS, it plays a vital role in the underlying video processing pipeline of a web browser. When a website uses WebRTC to send or receive video, this tracker helps ensure the video stream is decodable.

8. **Identify potential user/programming errors:** The tests reveal scenarios where the encoder might not include all necessary parameter sets in every keyframe or when a stream starts with delta frames. These are common issues in video streaming, and the tracker helps to mitigate them.

9. **Construct examples for assumptions and error handling:**  Based on the tested scenarios, I can create hypothetical inputs and outputs and illustrate common errors like a missing VPS in an IDR frame.

By following these steps, I can arrive at a comprehensive understanding of the `H265ParameterSetsTracker`'s functionality and its role within the Blink rendering engine.
这个C++源代码文件 `h265_parameter_sets_tracker_unittest.cc` 是 Chromium Blink 引擎中用于测试 `H265ParameterSetsTracker` 类的单元测试文件。 `H265ParameterSetsTracker` 的主要功能是 **跟踪和管理 H.265 视频流中的参数集 (Parameter Sets)，并在必要时修复缺失的参数集，以确保视频解码器能够正确解码视频帧。**

具体来说，`H265ParameterSetsTracker` 关注以下类型的网络抽象层单元 (NAL unit):

* **VPS (Video Parameter Set):**  包含适用于整个视频序列的全局参数。
* **SPS (Sequence Parameter Set):** 包含适用于一个或多个编码视频序列的参数。
* **PPS (Picture Parameter Set):** 包含适用于一个或多个单独编码图像的参数。
* **IDR (Instantaneous Decoding Refresh) 图片:**  关键帧，解码器可以从这里开始解码，不需要依赖之前的帧。
* **CRA (Clean Random Access) 图片:** 一种随机接入点，解码器可以从这里开始解码，但可能会显示一些不完整的帧。
* **TRAIL_R 图片 (Trailing picture):**  非关键帧，依赖于之前的帧进行解码。

**功能列表:**

1. **检测 H.265 视频流:**  `MaybeFixBitstream` 方法能够识别输入的比特流是否为 H.265 格式。
2. **识别参数集 NAL 单元:**  能够从输入的比特流中识别出 VPS、SPS 和 PPS NAL 单元。
3. **跟踪已接收的参数集:** 记录最近接收到的 VPS、SPS 和 PPS 的内容。
4. **判断 IDR/CRA 帧是否包含必要的参数集:** 当接收到 IDR 或 CRA 帧时，检查是否包含了最新的 VPS、SPS 和 PPS。
5. **请求关键帧:** 如果接收到的 IDR 帧缺少必要的参数集，则指示需要请求一个新的关键帧。
6. **插入缺失的参数集:** 如果之前的帧已经接收到了有效的 VPS、SPS 和 PPS，而当前的 IDR/CRA 帧缺少这些参数集，则可以将之前存储的参数集插入到当前帧的前面，以便解码器能够正确解码。
7. **对非 H.265 流进行透传:** 如果输入的不是 H.265 比特流，则直接将其传递出去不做修改。

**与 JavaScript, HTML, CSS 的关系:**

`H265ParameterSetsTracker` 位于 Blink 引擎的底层，主要负责视频数据的处理。它不直接与 JavaScript, HTML, CSS 代码交互，但其功能对于 WebRTC 应用的视频播放至关重要。

* **JavaScript (WebRTC API):**  当 JavaScript 代码使用 WebRTC API (例如 `RTCPeerConnection`) 接收到远程视频流时，底层的 C++ 代码会处理这些视频数据。 `H265ParameterSetsTracker` 在这个过程中确保接收到的 H.265 视频帧能够被解码。如果缺少必要的参数集，Tracker 可能会触发请求关键帧的操作，最终可能导致 WebRTC 连接重新协商或发送请求关键帧的信令。
* **HTML (`<video>` 元素):**  解码后的视频帧最终会被渲染到 HTML 的 `<video>` 元素上。 `H265ParameterSetsTracker` 的功能保证了 `<video>` 元素能够流畅地播放接收到的 H.265 视频流。 如果参数集缺失导致解码失败，用户可能会在 `<video>` 元素中看到卡顿、花屏或无法播放的现象。
* **CSS:** CSS 负责 `<video>` 元素的样式控制，与 `H265ParameterSetsTracker` 的功能没有直接关系。

**逻辑推理 (假设输入与输出):**

**假设输入 1:** 一个只包含 IDR 帧的 H.265 比特流，但缺少 VPS、SPS 和 PPS。

```
输入: {0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaf, ...} // IDR 帧数据
```

**预期输出 1:**  `fixed.action` 为 `H265ParameterSetsTracker::PacketAction::kRequestKeyframe`。因为解码器无法解码 IDR 帧，需要请求包含参数集的关键帧。

**假设输入 2:**  先接收到包含 VPS、SPS 和 PPS 的 IDR 帧，然后接收到一个只包含 IDR 帧数据（没有 VPS/SPS/PPS）的后续 IDR 帧。

```
输入 2.1: {0x00, 0x00, 0x00, 0x01, 0x40, ...} // VPS
         {0x00, 0x00, 0x00, 0x01, 0x42, ...} // SPS
         {0x00, 0x00, 0x00, 0x01, 0x44, ...} // PPS
         {0x00, 0x00, 0x00, 0x01, 0x28, ...} // IDR 帧数据
输入 2.2: {0x00, 0x00, 0x00, 0x01, 0x28, ...} // 后续 IDR 帧数据 (缺少 VPS/SPS/PPS)
```

**预期输出 2.1:** `fixed.action` 为 `H265ParameterSetsTracker::PacketAction::kPassThrough`，因为初始帧包含了所有必要的参数集。

**预期输出 2.2:** `fixed.action` 为 `H265ParameterSetsTracker::PacketAction::kInsert`，并且 `fixed.bitstream` 会在 IDR 帧数据前插入之前存储的 VPS、SPS 和 PPS 数据。

**用户或编程常见的使用错误:**

1. **编码器配置错误，没有在关键帧中发送参数集:** 视频编码器可能被错误配置，导致关键帧 (IDR/CRA) 没有携带必要的 VPS、SPS 或 PPS。这会导致 `H265ParameterSetsTracker` 请求关键帧，最终可能导致视频播放失败。
   * **例子:** 使用 FFmpeg 编码 H.265 视频时，忘记设置 `-x265-params` 来强制在每个 IDR 帧中包含参数集。

2. **网络丢包导致参数集丢失:** 在网络传输过程中，包含 VPS、SPS 或 PPS 的数据包可能会丢失。如果后续的 IDR/CRA 帧没有携带这些参数集，`H265ParameterSetsTracker` 会尝试插入之前收到的参数集，但如果之前也没有收到过，则只能请求关键帧。
   * **例子:** 在不稳定的网络环境下进行 WebRTC 通信，初始的包含参数集的视频包丢失，导致后续的视频无法解码。

3. **假设所有关键帧都包含参数集:**  开发者在编写 WebRTC 应用时，可能会错误地假设每个关键帧都会包含完整的参数集。如果没有考虑到参数集可能丢失或编码器配置错误的情况，就可能导致视频播放出现问题。
   * **例子:**  在处理接收到的视频帧时，直接将帧数据传递给解码器，而没有先通过类似 `H265ParameterSetsTracker` 的机制进行检查和修复，可能会导致解码失败。

总而言之，`h265_parameter_sets_tracker_unittest.cc` 这个文件通过各种测试用例，验证了 `H265ParameterSetsTracker` 能够正确处理 H.265 视频流中参数集缺失的情况，保证了视频解码的可靠性，这对于基于 WebRTC 的视频应用至关重要。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/h265_parameter_sets_tracker_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/peerconnection/h265_parameter_sets_tracker.h"

#include <string.h>
#include <vector>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {
namespace {

// VPS/SPS/PPS/IDR for a 1280x720 camera capture from ffmpeg on linux.
// Contains emulation bytes but no cropping. This buffer is generated with
// following command: 1) ffmpeg -i /dev/video0 -r 30 -c:v libx265 -s 1280x720
// camera.h265
//
// The VPS/SPS/PPS are kept intact while idr1/idr2/cra1/cra2/trail1/trail2 are
// created by changing the NALU type of original IDR/TRAIL_R NALUs, and
// truncated only for testing of the tracker.
uint8_t vps[] = {0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01, 0xff, 0xff,
                 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03,
                 0x00, 0x00, 0x03, 0x00, 0x5d, 0x95, 0x98, 0x09};
uint8_t sps[] = {0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01, 0x60,
                 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00,
                 0x00, 0x03, 0x00, 0x5d, 0xa0, 0x02, 0x80, 0x80, 0x2d,
                 0x16, 0x59, 0x59, 0xa4, 0x93, 0x2b, 0xc0, 0x5a, 0x70,
                 0x80, 0x00, 0x01, 0xf4, 0x80, 0x00, 0x3a, 0x98, 0x04};
uint8_t pps[] = {0x00, 0x00, 0x00, 0x01, 0x44, 0x01,
                 0xc1, 0x72, 0xb4, 0x62, 0x40};
uint8_t idr1[] = {0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaf,
                  0x08, 0x46, 0x0c, 0x92, 0xa3, 0xf4, 0x77};
uint8_t idr2[] = {0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaf,
                  0x08, 0x46, 0x0c, 0x92, 0xa3, 0xf4, 0x77};
uint8_t trail1[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xa4, 0x04, 0x55,
                    0xa2, 0x6d, 0xce, 0xc0, 0xc3, 0xed, 0x0b, 0xac, 0xbc,
                    0x00, 0xc4, 0x44, 0x2e, 0xf7, 0x55, 0xfd, 0x05, 0x86};
uint8_t trail2[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x23, 0xfc, 0x20,
                    0x22, 0xad, 0x13, 0x68, 0xce, 0xc3, 0x5a, 0x00, 0x01,
                    0x80, 0xe9, 0xc6, 0x38, 0x13, 0xec, 0xef, 0x0f, 0xff};
uint8_t cra[] = {0x00, 0x00, 0x00, 0x01, 0x2A, 0x01, 0xad, 0x00, 0x58, 0x81,
                 0x04, 0x11, 0xc2, 0x00, 0x44, 0x3f, 0x34, 0x46, 0x3e, 0xcc,
                 0x86, 0xd9, 0x3f, 0xf1, 0xe1, 0xda, 0x26, 0xb1, 0xc5, 0x50,
                 0xf2, 0x8b, 0x8d, 0x0c, 0xe9, 0xe1, 0xd3, 0xe0, 0xa7, 0x3e};

// Below two H264 binaries are copied from h264 bitstream parser unittests,
// to check the behavior of the tracker on stream from mismatched encoder.
uint8_t sps_pps_h264[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x80, 0x20, 0xda,
                          0x01, 0x40, 0x16, 0xe8, 0x06, 0xd0, 0xa1, 0x35, 0x00,
                          0x00, 0x00, 0x01, 0x68, 0xce, 0x06, 0xe2};
uint8_t idr_h264[] = {
    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x80, 0x20, 0xda, 0x01, 0x40, 0x16,
    0xe8, 0x06, 0xd0, 0xa1, 0x35, 0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x06,
    0xe2, 0x00, 0x00, 0x00, 0x01, 0x65, 0xb8, 0x40, 0xf0, 0x8c, 0x03, 0xf2,
    0x75, 0x67, 0xad, 0x41, 0x64, 0x24, 0x0e, 0xa0, 0xb2, 0x12, 0x1e, 0xf8,
};

using ::testing::ElementsAreArray;

rtc::ArrayView<const uint8_t> Bitstream(
    const H265ParameterSetsTracker::FixedBitstream& fixed) {
  return rtc::ArrayView<const uint8_t>(fixed.bitstream->data(),
                                       fixed.bitstream->size());
}

}  // namespace

class H265ParameterSetsTrackerTest : public ::testing::Test {
 public:
  H265ParameterSetsTracker tracker_;
};

TEST_F(H265ParameterSetsTrackerTest, NoNalus) {
  uint8_t data[] = {1, 2, 3};

  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest, StreamFromMissMatchingH26xCodec) {
  std::vector<uint8_t> data;
  unsigned sps_pps_size = sizeof(sps_pps_h264) / sizeof(sps_pps_h264[0]);
  unsigned idr_size = sizeof(idr_h264) / sizeof(idr_h264[0]);
  data.insert(data.end(), sps_pps_h264, sps_pps_h264 + sps_pps_size);
  data.insert(data.end(), idr_h264, idr_h264 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  // This is not an H.265 stream. We simply pass through it.
  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest, AllParameterSetsInCurrentIdrSingleSlice) {
  std::vector<uint8_t> data;
  data.clear();
  unsigned vps_size = sizeof(vps) / sizeof(uint8_t);
  unsigned sps_size = sizeof(sps) / sizeof(uint8_t);
  unsigned pps_size = sizeof(pps) / sizeof(uint8_t);
  unsigned idr_size = sizeof(idr1) / sizeof(uint8_t);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size - 1);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest, AllParameterSetsMissingForIdr) {
  std::vector<uint8_t> data;
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kRequestKeyframe);
}

TEST_F(H265ParameterSetsTrackerTest, VpsMissingForIdr) {
  std::vector<uint8_t> data;
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kRequestKeyframe);
}

TEST_F(H265ParameterSetsTrackerTest,
       ParameterSetsSeenBeforeButRepeatedVpsMissingForCurrentIdr) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  // Second IDR but encoder only repeats SPS/PPS(unlikely to happen).
  std::vector<uint8_t> frame2;
  unsigned sps2_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps2_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr2_size = sizeof(idr2) / sizeof(idr2[0]);
  frame2.insert(frame2.end(), sps, sps + sps2_size);
  frame2.insert(frame2.end(), pps, pps + pps2_size);
  frame2.insert(frame2.end(), idr2, idr2 + idr2_size);
  fixed = tracker_.MaybeFixBitstream(frame2);

  // If any of the parameter set is missing, we append all of VPS/SPS/PPS and it
  // is fine to repeat any of the parameter set twice for current IDR.
  EXPECT_THAT(fixed.action, H265ParameterSetsTracker::PacketAction::kInsert);
  std::vector<uint8_t> expected;
  expected.insert(expected.end(), vps, vps + vps_size);
  expected.insert(expected.end(), sps, sps + sps_size);
  expected.insert(expected.end(), pps, pps + pps_size);
  expected.insert(expected.end(), sps, sps + sps_size);
  expected.insert(expected.end(), pps, pps + pps_size);
  expected.insert(expected.end(), idr2, idr2 + idr2_size);
  EXPECT_THAT(Bitstream(fixed), ElementsAreArray(expected));
}

TEST_F(H265ParameterSetsTrackerTest,
       AllParameterSetsInCurrentIdrMulitpleSlices) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr1_size = sizeof(idr1) / sizeof(idr1[0]);
  unsigned idr2_size = sizeof(idr2) / sizeof(idr2[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr1_size);
  data.insert(data.end(), idr2, idr2 + idr2_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest,
       SingleDeltaSliceWithoutParameterSetsBefore) {
  std::vector<uint8_t> data;
  unsigned trail_size = sizeof(trail1) / sizeof(trail1[0]);
  data.insert(data.end(), trail1, trail1 + trail_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest,
       MultipleDeltaSlicseWithoutParameterSetsBefore) {
  std::vector<uint8_t> data;
  unsigned trail1_size = sizeof(trail1) / sizeof(trail1[0]);
  unsigned trail2_size = sizeof(trail2) / sizeof(trail2[0]);
  data.insert(data.end(), trail1, trail1 + trail1_size);
  data.insert(data.end(), trail2, trail2 + trail2_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest,
       ParameterSetsInPreviousIdrNotInCurrentIdr) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  std::vector<uint8_t> frame2;
  unsigned idr2_size = sizeof(idr2) / sizeof(idr2[0]);
  frame2.insert(frame2.end(), idr2, idr2 + idr2_size);
  fixed = tracker_.MaybeFixBitstream(frame2);

  EXPECT_THAT(fixed.action, H265ParameterSetsTracker::PacketAction::kInsert);

  std::vector<uint8_t> expected;
  expected.insert(expected.end(), vps, vps + vps_size);
  expected.insert(expected.end(), sps, sps + sps_size);
  expected.insert(expected.end(), pps, pps + pps_size);
  expected.insert(expected.end(), idr2, idr2 + idr2_size);
  EXPECT_THAT(Bitstream(fixed), ElementsAreArray(expected));
}

TEST_F(H265ParameterSetsTrackerTest,
       ParameterSetsInPreviousIdrNotInCurrentCra) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  std::vector<uint8_t> frame2;
  unsigned cra_size = sizeof(cra) / sizeof(cra[0]);
  frame2.insert(frame2.end(), cra, cra + cra_size);
  fixed = tracker_.MaybeFixBitstream(frame2);

  EXPECT_THAT(fixed.action, H265ParameterSetsTracker::PacketAction::kInsert);
  std::vector<uint8_t> expected;
  expected.insert(expected.end(), vps, vps + vps_size);
  expected.insert(expected.end(), sps, sps + sps_size);
  expected.insert(expected.end(), pps, pps + pps_size);
  expected.insert(expected.end(), cra, cra + cra_size);
  EXPECT_THAT(Bitstream(fixed), ElementsAreArray(expected));
}

TEST_F(H265ParameterSetsTrackerTest, ParameterSetsInBothPreviousAndCurrentIdr) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  std::vector<uint8_t> frame2;
  unsigned idr2_size = sizeof(idr2) / sizeof(idr2[0]);
  frame2.insert(frame2.end(), vps, vps + vps_size);
  frame2.insert(frame2.end(), sps, sps + sps_size);
  frame2.insert(frame2.end(), pps, pps + pps_size);
  frame2.insert(frame2.end(), idr2, idr2 + idr2_size);
  fixed = tracker_.MaybeFixBitstream(frame2);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

TEST_F(H265ParameterSetsTrackerTest, TwoGopsWithIdrTrailAndCra) {
  std::vector<uint8_t> data;
  unsigned vps_size = sizeof(vps) / sizeof(vps[0]);
  unsigned sps_size = sizeof(sps) / sizeof(sps[0]);
  unsigned pps_size = sizeof(pps) / sizeof(pps[0]);
  unsigned idr_size = sizeof(idr1) / sizeof(idr1[0]);
  data.insert(data.end(), vps, vps + vps_size);
  data.insert(data.end(), sps, sps + sps_size);
  data.insert(data.end(), pps, pps + pps_size);
  data.insert(data.end(), idr1, idr1 + idr_size);
  H265ParameterSetsTracker::FixedBitstream fixed =
      tracker_.MaybeFixBitstream(data);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  // Second frame, a TRAIL_R picture.
  std::vector<uint8_t> frame2;
  unsigned trail_size = sizeof(trail1) / sizeof(trail1[0]);
  frame2.insert(frame2.end(), trail1, trail1 + trail_size);
  fixed = tracker_.MaybeFixBitstream(frame2);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  // Third frame, a TRAIL_R picture.
  std::vector<uint8_t> frame3;
  unsigned trail2_size = sizeof(trail2) / sizeof(trail2[0]);
  frame3.insert(frame3.end(), trail2, trail2 + trail2_size);
  fixed = tracker_.MaybeFixBitstream(frame3);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);

  // Fourth frame, a CRA picture.
  std::vector<uint8_t> frame4;
  unsigned cra_size = sizeof(cra) / sizeof(cra[0]);
  frame4.insert(frame4.end(), cra, cra + cra_size);
  fixed = tracker_.MaybeFixBitstream(frame4);

  EXPECT_THAT(fixed.action, H265ParameterSetsTracker::PacketAction::kInsert);

  std::vector<uint8_t> expected;
  expected.insert(expected.end(), vps, vps + vps_size);
  expected.insert(expected.end(), sps, sps + sps_size);
  expected.insert(expected.end(), pps, pps + pps_size);
  expected.insert(expected.end(), cra, cra + cra_size);
  EXPECT_THAT(Bitstream(fixed), ElementsAreArray(expected));

  // Last frame, a TRAIL_R picture with 2 slices.
  std::vector<uint8_t> frame5;
  unsigned trail3_size = sizeof(trail1) / sizeof(trail1[0]);
  unsigned trail4_size = sizeof(trail2) / sizeof(trail2[0]);
  frame5.insert(frame5.end(), trail1, trail1 + trail3_size);
  frame5.insert(frame5.end(), trail2, trail2 + trail4_size);
  fixed = tracker_.MaybeFixBitstream(frame5);

  EXPECT_THAT(fixed.action,
              H265ParameterSetsTracker::PacketAction::kPassThrough);
}

}  // namespace blink
```