Response:
The user wants to understand the functionality of the `media_recorder_handler.cc` file in the Chromium Blink engine. They are interested in:
1. **Functionality:** A summary of what the code does.
2. **Relationship to web technologies:** How it interacts with JavaScript, HTML, and CSS.
3. **Logic and data flow:**  Examples of input and output based on logical reasoning.
4. **Common errors:**  Examples of mistakes users or programmers might make.
5. **User journey:**  Steps a user might take to trigger this code.
6. **Debugging:** How this information can be used for debugging.
7. **Summary:** A concise overview of the file's purpose.

Let's break down the provided code to address each of these points.

**1. Functionality:**

The code implements the `MediaRecorderHandler` class, which is responsible for managing the recording process initiated by the JavaScript `MediaRecorder` API. Its core functionalities include:

* **MIME type and codec negotiation:** Determining if a given MIME type and codec combination is supported for recording.
* **Muxing:**  Orchestrating the process of combining audio and video data into a container format (like WebM or MP4).
* **Interfacing with encoders:**  Managing `VideoTrackRecorder` and `AudioTrackRecorder` instances to handle the actual encoding of individual media tracks.
* **Handling start, stop, pause, and resume recording:** Managing the lifecycle of a recording session.
* **Responding to stream changes:**  Being notified when tracks are added or removed from the `MediaStream`.
* **Providing encoding capabilities information:** Answering queries about the supported encoding configurations.

**2. Relationship to web technologies:**

This C++ code directly supports the JavaScript `MediaRecorder` API.

* **JavaScript:** The `MediaRecorder` API in JavaScript allows web developers to record audio and video from a `MediaStream`. This C++ code is the underlying implementation that makes that API functional. When a JavaScript calls methods like `start()`, `stop()`, or queries supported MIME types, the corresponding logic is executed in this C++ file.
* **HTML:**  HTML elements like `<video>` or `<audio>` can be used to display or capture media that is then passed to the `MediaRecorder`. The `MediaRecorderHandler` works with the `MediaStream` obtained from these elements (or other sources).
* **CSS:** CSS does not directly interact with the recording process managed by this code. CSS styles the presentation of the media elements, but the recording logic is separate.

**Examples:**

* **JavaScript `start()`:** When JavaScript calls `mediaRecorder.start()`, the `MediaRecorderHandler::Start()` method is invoked. This method sets up the muxer and initializes the audio and video recorders.
* **JavaScript MIME type check:**  If JavaScript calls `MediaRecorder.isTypeSupported('video/webm; codecs="vp9"')`, the `MediaRecorderHandler::CanSupportMimeType()` method is called to determine if the browser can record using that specific codec.
* **HTML `<video>` capture:** If a user grants permission for a web page to access their camera via `<video>` and JavaScript uses `MediaRecorder` on the stream from that video element, the frames from the video element will eventually be processed by the `VideoTrackRecorderImpl` instantiated by `MediaRecorderHandler`.

**3. Logic and data flow:**

* **Assumption:** A user wants to record a video and audio stream into an MP4 container using the H.264 video codec and AAC audio codec.
* **Input (Conceptual):**
    * `type`: "video/mp4"
    * `codecs`: "avc1.42E01E,mp4a.40.2"
    * A `MediaStream` containing a video track and an audio track.
* **Processing:**
    1. `CanSupportMimeType()` checks if "video/mp4" with "avc1.42E01E,mp4a.40.2" is supported. It parses the codec strings and verifies support for H.264 and AAC within MP4.
    2. `Initialize()` is called, storing the type and extracting codec information.
    3. `Start()` is called:
        * An `Mp4Muxer` is created.
        * `VideoTrackRecorderImpl` is created for the video track, configured to use the H.264 encoder.
        * `AudioTrackRecorder` is created for the audio track, configured to use the AAC encoder.
        * As data arrives from the `MediaStreamTrack`s, the `VideoTrackRecorderImpl` and `AudioTrackRecorder` encode the data.
        * The encoded data is passed to the `Mp4Muxer` to be combined into the MP4 container.
        * The `Mp4Muxer` periodically calls `WriteData()` to provide the encoded data chunks.
* **Output (Conceptual):**  A series of data chunks in the MP4 format.

**4. Common errors:**

* **Unsupported MIME type or codecs:**
    * **User Error (JavaScript):**  The JavaScript code might specify a combination of `type` and `codecs` that the browser doesn't support (e.g., trying to record to `video/webm` with the `h264` codec in some browsers).
    * **Debugging:** The `CanSupportMimeType()` method will return `false`, and the `MediaRecorder` API will likely throw an error. Logging within `CanSupportMimeType()` would show which check failed.
* **Starting recording without tracks:**
    * **User Error (JavaScript):**  Trying to start recording on a `MediaRecorder` that isn't associated with a `MediaStream` or whose `MediaStream` has no active audio or video tracks.
    * **Debugging:** The `Start()` method checks for empty track lists and logs a warning. The recording will fail to start.
* **Incorrect codec string formatting:**
    * **Programmer Error (JavaScript):**  Providing malformed codec strings in the `MediaRecorder` options. For example, misspelling a codec name.
    * **Debugging:** The `VideoStringToCodecProfile()` and `AudioStringToCodecId()` functions might fail to parse the strings correctly, potentially leading to the use of fallback codecs or recording failure.

**5. User journey:**

1. **User opens a web page:** The user navigates to a website that uses the `MediaRecorder` API.
2. **Website requests media access:** The website's JavaScript uses `navigator.mediaDevices.getUserMedia()` to request access to the user's camera and/or microphone.
3. **User grants permission:** The user allows the website to access their media devices.
4. **Website creates a `MediaRecorder`:** The JavaScript code creates a new `MediaRecorder` object, passing the `MediaStream` obtained in the previous step and optionally specifying the desired MIME type and codecs. This leads to the creation of a `MediaRecorderHandler` instance in the background.
5. **Website starts recording:** The JavaScript calls `mediaRecorder.start()`. This triggers the `MediaRecorderHandler::Start()` method.
6. **User interacts with the page/media:** The user might be speaking into the microphone or their camera is capturing video.
7. **Media data is processed:** The browser captures audio and video frames, which are processed by the audio and video encoder components managed by the `MediaRecorderHandler`.
8. **Website stops recording:** The JavaScript calls `mediaRecorder.stop()`. This triggers the `MediaRecorderHandler::Stop()` method.
9. **Data is available:** The recorded data is made available to the JavaScript code through the `ondataavailable` event of the `MediaRecorder`.

**6. Debugging:**

* **Logging:** The code includes `DLOG` and `LOG` statements that can be enabled during development to track the flow of execution and identify potential issues. For example, logging within `CanSupportMimeType()` can help determine why a specific MIME type or codec combination is not supported.
* **Breakpoints:** Setting breakpoints in methods like `Start()`, `Stop()`, `CanSupportMimeType()`, and the data processing methods of `VideoTrackRecorderImpl` and `AudioTrackRecorder` allows developers to inspect the state of the application and the data being processed at critical points.
* **Inspecting `MediaStream` and Tracks:** Examining the state of the `MediaStream` and its associated `MediaStreamTrack`s can reveal problems with the source of the media data.
* **Checking browser compatibility:** Ensuring that the target browser supports the specified MIME types and codecs is crucial.

**7. Summary of Functionality:**

The `media_recorder_handler.cc` file in Chromium's Blink engine provides the core logic for the `MediaRecorder` API. It handles the complex tasks of negotiating supported recording formats, managing audio and video encoders, and muxing the encoded data into a container format (WebM or MP4). It acts as the bridge between the JavaScript `MediaRecorder` API and the underlying media processing components of the browser. It ensures that user requests to record media are handled correctly, efficiently, and with consideration for supported formats and potential errors.

```c++
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.h"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/system/sys_info.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_codecs.h"
#include "media/base/audio_parameters.h"
#include "media/base/decoder_buffer.h"
#include "media/base/media_switches.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/video_codec_string_parsers.h"
#include "media/base/video_codecs.h"
#include "media/base/video_frame.h"
#include "media/formats/mp4/mp4_status.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_audio_encoder.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/muxers/live_webm_muxer_delegate.h"
#include "media/muxers/mp4_muxer.h"
#include "media/muxers/mp4_muxer_delegate.h"
#include "media/muxers/muxer.h"
#include "media/muxers/muxer_timestamp_adapter.h"
#include "media/muxers/webm_muxer.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_capabilities_info.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_configuration.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#if BUILDFLAG(IS_WIN)
#include "media/gpu/windows/mf_audio_encoder.h"
#endif

using base::TimeTicks;

namespace blink {

BASE_FEATURE(kMediaRecorderEnableMp4Muxer,
             "MediaRecorderEnableMp4Muxer",
             base::FEATURE_ENABLED_BY_DEFAULT);
namespace {

constexpr double kDefaultVideoFrameRate = 30.0;

// Encoding smoothness depends on a number of parameters, namely: frame rate,
// resolution, hardware support availability, platform and IsLowEndDevice(); to
// simplify calculations we compare the amount of pixels per second (i.e.
// resolution times frame rate). Software based encoding on Desktop can run
// fine up and until HD resolution at 30fps, whereas if IsLowEndDevice() we set
// the cut at VGA at 30fps (~27Mpps and ~9Mpps respectively).
// TODO(mcasas): The influence of the frame rate is not exactly linear, so this
// threshold might be oversimplified, https://crbug.com/709181.
const float kNumPixelsPerSecondSmoothnessThresholdLow = 640 * 480 * 30.0;
const float kNumPixelsPerSecondSmoothnessThresholdHigh = 1280 * 720 * 30.0;

VideoTrackRecorder::CodecId CodecIdFromMediaVideoCodec(media::VideoCodec id) {
  switch (id) {
    case media::VideoCodec::kVP8:
      return VideoTrackRecorder::CodecId::kVp8;
    case media::VideoCodec::kVP9:
      return VideoTrackRecorder::CodecId::kVp9;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    case media::VideoCodec::kH264:
      return VideoTrackRecorder::CodecId::kH264;
#endif
    case media::VideoCodec::kAV1:
      return VideoTrackRecorder::CodecId::kAv1;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
    case media::VideoCodec::kHEVC:
      return VideoTrackRecorder::CodecId::kHevc;
#endif
    default:
      return VideoTrackRecorder::CodecId::kLast;
  }
}

media::AudioCodec CodecIdToMediaAudioCodec(AudioTrackRecorder::CodecId id) {
  switch (id) {
    case AudioTrackRecorder::CodecId::kPcm:
      return media::AudioCodec::kPCM;
    case AudioTrackRecorder::CodecId::kOpus:
      return media::AudioCodec::kOpus;
    case AudioTrackRecorder::CodecId::kAac:
      return media::AudioCodec::kAAC;
    case AudioTrackRecorder::CodecId::kLast:
      return media::AudioCodec::kUnknown;
  }
  NOTREACHED() << "Unsupported audio codec";
}

#if BUILDFLAG(USE_PROPRIETARY_CODECS) || \
    BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
std::optional<VideoTrackRecorder::CodecProfile> VideoStringTagToCodecProfile(
    const String& codecs,
    const StringView& codecs_tag) {
  std::optional<VideoTrackRecorder::CodecProfile> codec_profile;
  wtf_size_t codecs_start = codecs.Find(codecs_tag);
  if (codecs_start != kNotFound) {
    wtf_size_t codecs_end = codecs.Find(",");
    auto codec_id =
        codecs
            .Substring(codecs_start,
                       codecs_end == kNotFound ? UINT_MAX : codecs_end)
            .StripWhiteSpace()
            .Ascii();
    // Do not use lowercase `codecId` here, as `codecId` is case sensitive when
    // parsing.
    if (auto result = media::ParseCodec(codec_id)) {
      codec_profile = {CodecIdFromMediaVideoCodec(result->codec),
                       result->profile, result->level};
    }
  }
  return codec_profile;
}
#endif

AudioTrackRecorder::CodecId AudioStringToCodecId(const String& codecs) {
  String codecs_str = codecs.LowerASCII();

  if (codecs_str.Find("opus") != kNotFound)
    return AudioTrackRecorder::CodecId::kOpus;
  if (codecs_str.Find("pcm") != kNotFound)
    return AudioTrackRecorder::CodecId::kPcm;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  if (codecs_str.Find("mp4a.40.2") != kNotFound) {
    return AudioTrackRecorder::CodecId::kAac;
  }
#endif
  return AudioTrackRecorder::CodecId::kLast;
}

bool CanSupportVideoType(const String& type) {
  bool support = EqualIgnoringASCIICase(type, "video/webm") ||
                 EqualIgnoringASCIICase(type, "video/x-matroska");
  if (support) {
    return true;
  }

  if (base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return EqualStringView(type, "video/mp4");
  }

  return false;
}

bool CanSupportAudioType(const String& type) {
  bool support = EqualIgnoringASCIICase(type, "audio/webm");
  if (support) {
    return true;
  }

  if (base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return EqualStringView(type, "audio/mp4");
  }

  return false;
}

bool IsAllowedMp4Type(const String& type) {
  return EqualIgnoringASCIICase(type, "video/mp4") ||
         EqualIgnoringASCIICase(type, "audio/mp4");
}

bool IsMp4MuxerRequired(const String& type) {
  // The function should be called only after type and codecs are validated
  // by `CanSupportMimeType()` first in code path.
  if (!base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return false;
  }
  return IsAllowedMp4Type(type);
}

}  // anonymous namespace

media::VideoCodec MediaVideoCodecFromCodecId(VideoTrackRecorder::CodecId id) {
  switch (id) {
    case VideoTrackRecorder::CodecId::kVp8:
      return media::VideoCodec::kVP8;
    case VideoTrackRecorder::CodecId::kVp9:
      return media::VideoCodec::kVP9;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    case VideoTrackRecorder::CodecId::kH264:
      return media::VideoCodec::kH264;
#endif
    case VideoTrackRecorder::CodecId::kAv1:
      return media::VideoCodec::kAV1;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
    case VideoTrackRecorder::CodecId::kHevc:
      return media::VideoCodec::kHEVC;
#endif
    case VideoTrackRecorder::CodecId::kLast:
      return media::VideoCodec::kUnknown;
  }
  NOTREACHED() << "Unsupported video codec";
}

// Extracts the first recognised CodecId of |codecs| or CodecId::LAST if none
// of them is known. Sets codec profile and level if the information can be
// parsed from codec suffix.
VideoTrackRecorder::CodecProfile VideoStringToCodecProfile(
    const String& codecs) {
  String codecs_str = codecs.LowerASCII();
  VideoTrackRecorder::CodecId codec_id = VideoTrackRecorder::CodecId::kLast;

  if (codecs_str.Find("vp8") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kVp8;
  }
  if (codecs_str.Find("vp9") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kVp9;
  }
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  if (codecs_str.Find("h264") != kNotFound ||
      codecs_str.Find("avc1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kH264;
  }
  if (auto codec_profile = VideoStringTagToCodecProfile(codecs, "avc1")) {
    return *codec_profile;
  }
#endif
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
  if (codecs_str.Find("hvc1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kHevc;
  }
  if (auto codec_profile = VideoStringTagToCodecProfile(codecs, "hvc1")) {
    return *codec_profile;
  }
#endif
  // TODO(crbug.com/40923648): Remove the wrong AV1 codecs string, "av1", once
  // we confirm nobody uses this in product.
  if (codecs_str.Find("av01") != kNotFound ||
      codecs_str.Find("av1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kAv1;
  }
  return VideoTrackRecorder::CodecProfile(codec_id);
}

MediaRecorderHandler::MediaRecorderHandler(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    KeyFrameRequestProcessor::Configuration key_frame_config)
    : key_frame_config_(key_frame_config),
      main_thread_task_runner_(std::move(main_thread_task_runner)) {}

bool MediaRecorderHandler::CanSupportMimeType(const String& type,
                                              const String& web_codecs) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  // An empty |type| means MediaRecorderHandler can choose its preferred codecs.
  if (type.empty())
    return true;

  const bool video = CanSupportVideoType(type);
  const bool audio = !video && CanSupportAudioType(type);
  if (!video && !audio)
    return false;

  // Both |video| and |audio| support empty |codecs|; |type| == "video" supports
  // vp8, vp9, h264, avc1, av01, av1, hvc1, opus, or pcm; |type| = "audio",
  // supports opus or pcm (little-endian 32-bit float).
  // http://www.webmproject.org/docs/container Sec:"HTML5 Video Type Parameters"
  static const char* const kVideoCodecs[] = {
      "vp8", "vp9",
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      "h264", "avc1",
#endif
      "av01",
      // TODO(crbug.com/40923648): Remove the wrong AV1 codecs string, "av1",
      // once we confirm nobody uses this in product.
      "av1",
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      "hvc1",
#endif
      "opus", "pcm"};
  static const char* const kAudioCodecs[] = {"opus", "pcm"};

  auto* const* relevant_codecs_begin =
      video ? std::begin(kVideoCodecs) : std::begin(kAudioCodecs);
  auto* const* relevant_codecs_end =
      video ? std::end(kVideoCodecs) : std::end(kAudioCodecs);

  bool mp4_mime_type = false;

  mp4_mime_type = IsAllowedMp4Type(type);
  if (mp4_mime_type) {
    static const char* const kVideoCodecsForMP4[] = {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        "avc1", "mp4a.40.2",
#endif
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
        "hvc1",
#endif
        "vp9",  "av01",      "opus",
    };
    static const char* const kAudioCodecsForMp4[] = {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        "mp4a.40.2",
#endif
        "opus"};

    relevant_codecs_begin =
        video ? std::begin(kVideoCodecsForMP4) : std::begin(kAudioCodecsForMp4);
    relevant_codecs_end =
        video ? std::end(kVideoCodecsForMP4) : std::end(kAudioCodecsForMp4);
  }

  std::vector<std::string> codecs_list;
  media::SplitCodecs(web_codecs.Utf8(), &codecs_list);

  for (const auto& codec : codecs_list) {
    // For `video/x-matroska`, `video/webm`, and `audio/webm`, trim the content
    // after first '.' to do the case insensitive match based on historical
    // logic. For `video/mp4`, and `audio/mp4`, preserve the whole string to do
    // the case sensitive match.
    String codec_string = String::FromUTF8(codec);
    if (!mp4_mime_type) {
      auto str_index = codec.find_first_of('.');
      if (str_index != std::string::npos) {
        codec_string = String::FromUTF8(codec.substr(0, str_index));
      }
    }

    bool match =
        std::any_of(relevant_codecs_begin, relevant_codecs_end,
                    [&codec_string, &mp4_mime_type](const char* name) {
                      if (mp4_mime_type) {
                        return EqualStringView(codec_string, name);
                      } else {
                        return EqualIgnoringASCIICase(codec_string, name);
                      }
                    });

    if (video) {
      // Currently `video/x-matroska` is not supported by mime util, replace to
      // `video/mp4` instead.
      //
      // TODO(crbug.com/40276507): rework MimeUtil such that clients can inject
      // their own supported mime+codec types.
      std::string mime_type = EqualIgnoringASCIICase(type, "video/x-matroska")
                                  ? "video/mp4"
                                  : type.Ascii();
      // It supports full qualified string for `avc1`, `hvc1`, and `av01`
      // codecs, e.g.
      //  `avc1.<profile>.<level>`,
      //  `hvc1.<profile>.<profile_compatibility>.<tier and level>.*`,
      //  `av01.<profile>.<level>.<color depth>.*`.
      auto parsed_result =
          media::ParseVideoCodecString(mime_type, codec,
                                       /*allow_ambiguous_matches=*/false);
      if (!match && mp4_mime_type) {
        match = parsed_result &&
                (parsed_result->codec == media::VideoCodec::kH264 ||
                 parsed_result->codec == media::VideoCodec::kAV1);
      }

#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      // Only support HEVC main profile with `hvc1` tag instead of `hev1` tag
      // for better compatibility given the fact that QuickTime and Safari only
      // support playing `hvc1` tag mp4 videos, and Apple only recommend using
      // `hvc1` for HLS.
      // https://developer.apple.com/documentation/http-live-streaming/hls-authoring-specification-for-apple-devices#2969487
      if (codec_string.StartsWith("hvc1", kTextCaseASCIIInsensitive)) {
        const bool is_legacy_type = codec == "hvc1";
        match =
            // If the profile can be parsed, ensure it must be HEVC main
            // profile, otherwise ensure codec strictly equals to `hvc1`.
            ((parsed_result &&
              parsed_result->profile ==
                  media::VideoCodecProfile::HEVCPROFILE_MAIN) ||
             is_legacy_type) &&
            // Only if the feature is enabled.
            base::FeatureList::IsEnabled(media::kMediaRecorderHEVCSupport) &&
            // Only `mkv` and `mp4` are supported, `webm` is not supported.
            !EqualIgnoringASCIICase(type, "video/webm") &&
            // Only if there are platform HEVC main profile support.
            media::IsEncoderSupportedVideoType(
                {media::VideoCodec::kHEVC,
                 media::VideoCodecProfile::HEVCPROFILE_MAIN});
      }
#endif
    }

    if (!match) {
      return false;
    }

    if (codec_string == "mp4a.40.2" &&
        !media::MojoAudioEncoder::IsSupported(media::AudioCodec::kAAC)) {
      return false;
    }

    if (codec_string == "av01" || codec_string == "av1") {
      base::UmaHistogramBoolean("Media.MediaRecorder.HasCorrectAV1CodecString",
                                codec_string == "av01");
#if !BUILDFLAG(ENABLE_LIBAOM)
      // The software encoder is unable to process the kAV1 codec if
      // ENABLE_LIBAOM is not defined. It verifies hardware encoding supports is
      // doable.
      VideoTrackRecorder::CodecProfile codec_profile =
          VideoStringToCodecProfile(codec_string);
      if (!VideoTrackRecorderImpl::CanUseAcceleratedEncoder(
              // The CanUseAcceleratedEncoder function requires a frame size for
              // validation. However, at this point, we don’t have the frame
              // size available. We’re making an assumption that it exceeds the
              // minimum size.
              codec_profile,
              video_track_recorder::kVEAEncoderMinResolutionWidth,
              video_track_recorder::kVEAEncoderMinResolutionHeight)) {
        return false;
      }
#endif
    }
  }
  return true;
}

bool MediaRecorderHandler::Initialize(
    MediaRecorder* recorder,
    MediaStreamDescriptor* media_stream,
    const String& type,
    const String& codecs,
    AudioTrackRecorder::BitrateMode audio_bitrate_mode) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  // Save histogram data so we can see how much MediaStream Recorder is used.
  // The histogram counts the number of calls to the JS API.
  UpdateWebRTCMethodCount(RTCAPIName::kMediaStreamRecorder);

  type_ = type;

  if (!CanSupportMimeType(type_, codecs)) {
    DLOG(ERROR) << "Unsupported " << type.Utf8() << ";codecs=" << codecs.Utf8();
    return false;
  }

  passthrough_enabled_ = type_.empty();

  // Once established that we support the codec(s), hunt then individually.
  video_codec_profile_ = VideoStringToCodecProfile(codecs);
  if (video_codec_profile_.codec_id == VideoTrackRecorder::CodecId::kLast) {
    MediaTrackContainerType container_type =
        GetMediaContainerTypeFromString(type_);
    video_codec_profile_.codec_id =
        VideoTrackRecorderImpl::GetPreferredCodecId(container_type);
    DVLOG(1) << "Falling back to preferred video codec id "
             << static_cast<int>(video_codec_profile_.codec_id);
  }

  // Do the same for the audio codec(s).
  const AudioTrackRecorder::CodecId audio_codec_id =
      AudioStringToCodecId(codecs);

  if (audio_codec_id == AudioTrackRecorder::CodecId::kLast) {
    MediaTrackContainerType container_type =
        GetMediaContainerTypeFromString(type_);
    audio_codec_id_ = AudioTrackRecorder::GetPreferredCodecId(container_type);
  } else {
    audio_codec_id_ = audio_codec_id;
  }

  DVLOG_IF(1, audio_codec_id == AudioTrackRecorder::CodecId::kLast)
      << "Falling back to preferred audio codec id "
      << static_cast<int>(audio_codec_id_);

  media_stream_ = media_stream;
  DCHECK(recorder);
  recorder_ = recorder;

  audio_bitrate_mode_ = audio_bitrate_mode;
  return true;
}

AudioTrackRecorder::BitrateMode MediaRecorderHandler::AudioBitrateMode() {
  return audio_bitrate_mode_;
}

bool MediaRecorderHandler::Start(int timeslice,
                                 const String& type,
                                 uint32_t audio_bits_per_second,
                                 uint32_t video_bits_per_second) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!recording_);
  DCHECK(media_stream_);
  DCHECK(timeslice_.is_zero());
  DCHECK(!muxer_adapter_);

  DCHECK(!is_media_stream_observer_);
  media_stream_->AddObserver(this);
  is_media_
Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.h"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/system/sys_info.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_codecs.h"
#include "media/base/audio_parameters.h"
#include "media/base/decoder_buffer.h"
#include "media/base/media_switches.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/video_codec_string_parsers.h"
#include "media/base/video_codecs.h"
#include "media/base/video_frame.h"
#include "media/formats/mp4/mp4_status.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_audio_encoder.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/muxers/live_webm_muxer_delegate.h"
#include "media/muxers/mp4_muxer.h"
#include "media/muxers/mp4_muxer_delegate.h"
#include "media/muxers/muxer.h"
#include "media/muxers/muxer_timestamp_adapter.h"
#include "media/muxers/webm_muxer.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_capabilities_info.h"
#include "third_party/blink/renderer/platform/media_capabilities/web_media_configuration.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#if BUILDFLAG(IS_WIN)
#include "media/gpu/windows/mf_audio_encoder.h"
#endif

using base::TimeTicks;

namespace blink {

BASE_FEATURE(kMediaRecorderEnableMp4Muxer,
             "MediaRecorderEnableMp4Muxer",
             base::FEATURE_ENABLED_BY_DEFAULT);
namespace {

constexpr double kDefaultVideoFrameRate = 30.0;

// Encoding smoothness depends on a number of parameters, namely: frame rate,
// resolution, hardware support availability, platform and IsLowEndDevice(); to
// simplify calculations we compare the amount of pixels per second (i.e.
// resolution times frame rate). Software based encoding on Desktop can run
// fine up and until HD resolution at 30fps, whereas if IsLowEndDevice() we set
// the cut at VGA at 30fps (~27Mpps and ~9Mpps respectively).
// TODO(mcasas): The influence of the frame rate is not exactly linear, so this
// threshold might be oversimplified, https://crbug.com/709181.
const float kNumPixelsPerSecondSmoothnessThresholdLow = 640 * 480 * 30.0;
const float kNumPixelsPerSecondSmoothnessThresholdHigh = 1280 * 720 * 30.0;

VideoTrackRecorder::CodecId CodecIdFromMediaVideoCodec(media::VideoCodec id) {
  switch (id) {
    case media::VideoCodec::kVP8:
      return VideoTrackRecorder::CodecId::kVp8;
    case media::VideoCodec::kVP9:
      return VideoTrackRecorder::CodecId::kVp9;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    case media::VideoCodec::kH264:
      return VideoTrackRecorder::CodecId::kH264;
#endif
    case media::VideoCodec::kAV1:
      return VideoTrackRecorder::CodecId::kAv1;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
    case media::VideoCodec::kHEVC:
      return VideoTrackRecorder::CodecId::kHevc;
#endif
    default:
      return VideoTrackRecorder::CodecId::kLast;
  }
}

media::AudioCodec CodecIdToMediaAudioCodec(AudioTrackRecorder::CodecId id) {
  switch (id) {
    case AudioTrackRecorder::CodecId::kPcm:
      return media::AudioCodec::kPCM;
    case AudioTrackRecorder::CodecId::kOpus:
      return media::AudioCodec::kOpus;
    case AudioTrackRecorder::CodecId::kAac:
      return media::AudioCodec::kAAC;
    case AudioTrackRecorder::CodecId::kLast:
      return media::AudioCodec::kUnknown;
  }
  NOTREACHED() << "Unsupported audio codec";
}

#if BUILDFLAG(USE_PROPRIETARY_CODECS) || \
    BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
std::optional<VideoTrackRecorder::CodecProfile> VideoStringTagToCodecProfile(
    const String& codecs,
    const StringView& codecs_tag) {
  std::optional<VideoTrackRecorder::CodecProfile> codec_profile;
  wtf_size_t codecs_start = codecs.Find(codecs_tag);
  if (codecs_start != kNotFound) {
    wtf_size_t codecs_end = codecs.Find(",");
    auto codec_id =
        codecs
            .Substring(codecs_start,
                       codecs_end == kNotFound ? UINT_MAX : codecs_end)
            .StripWhiteSpace()
            .Ascii();
    // Do not use lowercase `codecId` here, as `codecId` is case sensitive when
    // parsing.
    if (auto result = media::ParseCodec(codec_id)) {
      codec_profile = {CodecIdFromMediaVideoCodec(result->codec),
                       result->profile, result->level};
    }
  }
  return codec_profile;
}
#endif

AudioTrackRecorder::CodecId AudioStringToCodecId(const String& codecs) {
  String codecs_str = codecs.LowerASCII();

  if (codecs_str.Find("opus") != kNotFound)
    return AudioTrackRecorder::CodecId::kOpus;
  if (codecs_str.Find("pcm") != kNotFound)
    return AudioTrackRecorder::CodecId::kPcm;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  if (codecs_str.Find("mp4a.40.2") != kNotFound) {
    return AudioTrackRecorder::CodecId::kAac;
  }
#endif
  return AudioTrackRecorder::CodecId::kLast;
}

bool CanSupportVideoType(const String& type) {
  bool support = EqualIgnoringASCIICase(type, "video/webm") ||
                 EqualIgnoringASCIICase(type, "video/x-matroska");
  if (support) {
    return true;
  }

  if (base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return EqualStringView(type, "video/mp4");
  }

  return false;
}

bool CanSupportAudioType(const String& type) {
  bool support = EqualIgnoringASCIICase(type, "audio/webm");
  if (support) {
    return true;
  }

  if (base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return EqualStringView(type, "audio/mp4");
  }

  return false;
}

bool IsAllowedMp4Type(const String& type) {
  return EqualIgnoringASCIICase(type, "video/mp4") ||
         EqualIgnoringASCIICase(type, "audio/mp4");
}

bool IsMp4MuxerRequired(const String& type) {
  // The function should be called only after type and codecs are validated
  // by `CanSupportMimeType()` first in code path.
  if (!base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
    return false;
  }
  return IsAllowedMp4Type(type);
}

}  // anonymous namespace

media::VideoCodec MediaVideoCodecFromCodecId(VideoTrackRecorder::CodecId id) {
  switch (id) {
    case VideoTrackRecorder::CodecId::kVp8:
      return media::VideoCodec::kVP8;
    case VideoTrackRecorder::CodecId::kVp9:
      return media::VideoCodec::kVP9;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    case VideoTrackRecorder::CodecId::kH264:
      return media::VideoCodec::kH264;
#endif
    case VideoTrackRecorder::CodecId::kAv1:
      return media::VideoCodec::kAV1;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
    case VideoTrackRecorder::CodecId::kHevc:
      return media::VideoCodec::kHEVC;
#endif
    case VideoTrackRecorder::CodecId::kLast:
      return media::VideoCodec::kUnknown;
  }
  NOTREACHED() << "Unsupported video codec";
}

// Extracts the first recognised CodecId of |codecs| or CodecId::LAST if none
// of them is known. Sets codec profile and level if the information can be
// parsed from codec suffix.
VideoTrackRecorder::CodecProfile VideoStringToCodecProfile(
    const String& codecs) {
  String codecs_str = codecs.LowerASCII();
  VideoTrackRecorder::CodecId codec_id = VideoTrackRecorder::CodecId::kLast;

  if (codecs_str.Find("vp8") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kVp8;
  }
  if (codecs_str.Find("vp9") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kVp9;
  }
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  if (codecs_str.Find("h264") != kNotFound ||
      codecs_str.Find("avc1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kH264;
  }
  if (auto codec_profile = VideoStringTagToCodecProfile(codecs, "avc1")) {
    return *codec_profile;
  }
#endif
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
  if (codecs_str.Find("hvc1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kHevc;
  }
  if (auto codec_profile = VideoStringTagToCodecProfile(codecs, "hvc1")) {
    return *codec_profile;
  }
#endif
  // TODO(crbug.com/40923648): Remove the wrong AV1 codecs string, "av1", once
  // we confirm nobody uses this in product.
  if (codecs_str.Find("av01") != kNotFound ||
      codecs_str.Find("av1") != kNotFound) {
    codec_id = VideoTrackRecorder::CodecId::kAv1;
  }
  return VideoTrackRecorder::CodecProfile(codec_id);
}

MediaRecorderHandler::MediaRecorderHandler(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    KeyFrameRequestProcessor::Configuration key_frame_config)
    : key_frame_config_(key_frame_config),
      main_thread_task_runner_(std::move(main_thread_task_runner)) {}

bool MediaRecorderHandler::CanSupportMimeType(const String& type,
                                              const String& web_codecs) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  // An empty |type| means MediaRecorderHandler can choose its preferred codecs.
  if (type.empty())
    return true;

  const bool video = CanSupportVideoType(type);
  const bool audio = !video && CanSupportAudioType(type);
  if (!video && !audio)
    return false;

  // Both |video| and |audio| support empty |codecs|; |type| == "video" supports
  // vp8, vp9, h264, avc1, av01, av1, hvc1, opus, or pcm; |type| = "audio",
  // supports opus or pcm (little-endian 32-bit float).
  // http://www.webmproject.org/docs/container Sec:"HTML5 Video Type Parameters"
  static const char* const kVideoCodecs[] = {
      "vp8", "vp9",
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      "h264", "avc1",
#endif
      "av01",
      // TODO(crbug.com/40923648): Remove the wrong AV1 codecs string, "av1",
      // once we confirm nobody uses this in product.
      "av1",
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      "hvc1",
#endif
      "opus", "pcm"};
  static const char* const kAudioCodecs[] = {"opus", "pcm"};

  auto* const* relevant_codecs_begin =
      video ? std::begin(kVideoCodecs) : std::begin(kAudioCodecs);
  auto* const* relevant_codecs_end =
      video ? std::end(kVideoCodecs) : std::end(kAudioCodecs);

  bool mp4_mime_type = false;

  mp4_mime_type = IsAllowedMp4Type(type);
  if (mp4_mime_type) {
    static const char* const kVideoCodecsForMP4[] = {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        "avc1", "mp4a.40.2",
#endif
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
        "hvc1",
#endif
        "vp9",  "av01",      "opus",
    };
    static const char* const kAudioCodecsForMp4[] = {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        "mp4a.40.2",
#endif
        "opus"};

    relevant_codecs_begin =
        video ? std::begin(kVideoCodecsForMP4) : std::begin(kAudioCodecsForMp4);
    relevant_codecs_end =
        video ? std::end(kVideoCodecsForMP4) : std::end(kAudioCodecsForMp4);
  }

  std::vector<std::string> codecs_list;
  media::SplitCodecs(web_codecs.Utf8(), &codecs_list);

  for (const auto& codec : codecs_list) {
    // For `video/x-matroska`, `video/webm`, and `audio/webm`, trim the content
    // after first '.' to do the case insensitive match based on historical
    // logic. For `video/mp4`, and `audio/mp4`, preserve the whole string to do
    // the case sensitive match.
    String codec_string = String::FromUTF8(codec);
    if (!mp4_mime_type) {
      auto str_index = codec.find_first_of('.');
      if (str_index != std::string::npos) {
        codec_string = String::FromUTF8(codec.substr(0, str_index));
      }
    }

    bool match =
        std::any_of(relevant_codecs_begin, relevant_codecs_end,
                    [&codec_string, &mp4_mime_type](const char* name) {
                      if (mp4_mime_type) {
                        return EqualStringView(codec_string, name);
                      } else {
                        return EqualIgnoringASCIICase(codec_string, name);
                      }
                    });

    if (video) {
      // Currently `video/x-matroska` is not supported by mime util, replace to
      // `video/mp4` instead.
      //
      // TODO(crbug.com/40276507): rework MimeUtil such that clients can inject
      // their own supported mime+codec types.
      std::string mime_type = EqualIgnoringASCIICase(type, "video/x-matroska")
                                  ? "video/mp4"
                                  : type.Ascii();
      // It supports full qualified string for `avc1`, `hvc1`, and `av01`
      // codecs, e.g.
      //  `avc1.<profile>.<level>`,
      //  `hvc1.<profile>.<profile_compatibility>.<tier and level>.*`,
      //  `av01.<profile>.<level>.<color depth>.*`.
      auto parsed_result =
          media::ParseVideoCodecString(mime_type, codec,
                                       /*allow_ambiguous_matches=*/false);
      if (!match && mp4_mime_type) {
        match = parsed_result &&
                (parsed_result->codec == media::VideoCodec::kH264 ||
                 parsed_result->codec == media::VideoCodec::kAV1);
      }

#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      // Only support HEVC main profile with `hvc1` tag instead of `hev1` tag
      // for better compatibility given the fact that QuickTime and Safari only
      // support playing `hvc1` tag mp4 videos, and Apple only recommend using
      // `hvc1` for HLS.
      // https://developer.apple.com/documentation/http-live-streaming/hls-authoring-specification-for-apple-devices#2969487
      if (codec_string.StartsWith("hvc1", kTextCaseASCIIInsensitive)) {
        const bool is_legacy_type = codec == "hvc1";
        match =
            // If the profile can be parsed, ensure it must be HEVC main
            // profile, otherwise ensure codec strictly equals to `hvc1`.
            ((parsed_result &&
              parsed_result->profile ==
                  media::VideoCodecProfile::HEVCPROFILE_MAIN) ||
             is_legacy_type) &&
            // Only if the feature is enabled.
            base::FeatureList::IsEnabled(media::kMediaRecorderHEVCSupport) &&
            // Only `mkv` and `mp4` are supported, `webm` is not supported.
            !EqualIgnoringASCIICase(type, "video/webm") &&
            // Only if there are platform HEVC main profile support.
            media::IsEncoderSupportedVideoType(
                {media::VideoCodec::kHEVC,
                 media::VideoCodecProfile::HEVCPROFILE_MAIN});
      }
#endif
    }

    if (!match) {
      return false;
    }

    if (codec_string == "mp4a.40.2" &&
        !media::MojoAudioEncoder::IsSupported(media::AudioCodec::kAAC)) {
      return false;
    }

    if (codec_string == "av01" || codec_string == "av1") {
      base::UmaHistogramBoolean("Media.MediaRecorder.HasCorrectAV1CodecString",
                                codec_string == "av01");
#if !BUILDFLAG(ENABLE_LIBAOM)
      // The software encoder is unable to process the kAV1 codec if
      // ENABLE_LIBAOM is not defined. It verifies hardware encoding supports is
      // doable.
      VideoTrackRecorder::CodecProfile codec_profile =
          VideoStringToCodecProfile(codec_string);
      if (!VideoTrackRecorderImpl::CanUseAcceleratedEncoder(
              // The CanUseAcceleratedEncoder function requires a frame size for
              // validation. However, at this point, we don’t have the frame
              // size available. We’re making an assumption that it exceeds the
              // minimum size.
              codec_profile,
              video_track_recorder::kVEAEncoderMinResolutionWidth,
              video_track_recorder::kVEAEncoderMinResolutionHeight)) {
        return false;
      }
#endif
    }
  }
  return true;
}

bool MediaRecorderHandler::Initialize(
    MediaRecorder* recorder,
    MediaStreamDescriptor* media_stream,
    const String& type,
    const String& codecs,
    AudioTrackRecorder::BitrateMode audio_bitrate_mode) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  // Save histogram data so we can see how much MediaStream Recorder is used.
  // The histogram counts the number of calls to the JS API.
  UpdateWebRTCMethodCount(RTCAPIName::kMediaStreamRecorder);

  type_ = type;

  if (!CanSupportMimeType(type_, codecs)) {
    DLOG(ERROR) << "Unsupported " << type.Utf8() << ";codecs=" << codecs.Utf8();
    return false;
  }

  passthrough_enabled_ = type_.empty();

  // Once established that we support the codec(s), hunt then individually.
  video_codec_profile_ = VideoStringToCodecProfile(codecs);
  if (video_codec_profile_.codec_id == VideoTrackRecorder::CodecId::kLast) {
    MediaTrackContainerType container_type =
        GetMediaContainerTypeFromString(type_);
    video_codec_profile_.codec_id =
        VideoTrackRecorderImpl::GetPreferredCodecId(container_type);
    DVLOG(1) << "Falling back to preferred video codec id "
             << static_cast<int>(video_codec_profile_.codec_id);
  }

  // Do the same for the audio codec(s).
  const AudioTrackRecorder::CodecId audio_codec_id =
      AudioStringToCodecId(codecs);

  if (audio_codec_id == AudioTrackRecorder::CodecId::kLast) {
    MediaTrackContainerType container_type =
        GetMediaContainerTypeFromString(type_);
    audio_codec_id_ = AudioTrackRecorder::GetPreferredCodecId(container_type);
  } else {
    audio_codec_id_ = audio_codec_id;
  }

  DVLOG_IF(1, audio_codec_id == AudioTrackRecorder::CodecId::kLast)
      << "Falling back to preferred audio codec id "
      << static_cast<int>(audio_codec_id_);

  media_stream_ = media_stream;
  DCHECK(recorder);
  recorder_ = recorder;

  audio_bitrate_mode_ = audio_bitrate_mode;
  return true;
}

AudioTrackRecorder::BitrateMode MediaRecorderHandler::AudioBitrateMode() {
  return audio_bitrate_mode_;
}

bool MediaRecorderHandler::Start(int timeslice,
                                 const String& type,
                                 uint32_t audio_bits_per_second,
                                 uint32_t video_bits_per_second) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!recording_);
  DCHECK(media_stream_);
  DCHECK(timeslice_.is_zero());
  DCHECK(!muxer_adapter_);

  DCHECK(!is_media_stream_observer_);
  media_stream_->AddObserver(this);
  is_media_stream_observer_ = true;

  timeslice_ = base::Milliseconds(timeslice);
  slice_origin_timestamp_ = base::TimeTicks::Now();

  audio_bits_per_second_ = audio_bits_per_second;
  video_bits_per_second_ = video_bits_per_second;

  video_tracks_ = media_stream_->VideoComponents();
  audio_tracks_ = media_stream_->AudioComponents();

  if (video_tracks_.empty() && audio_tracks_.empty()) {
    LOG(WARNING) << __func__ << ": no media tracks.";
    return false;
  }

  const bool use_video_tracks =
      !video_tracks_.empty() &&
      video_tracks_[0]->GetReadyState() != MediaStreamSource::kReadyStateEnded;
  const bool use_audio_tracks =
      !audio_tracks_.empty() && audio_tracks_[0]->GetPlatformTrack() &&
      audio_tracks_[0]->GetReadyState() != MediaStreamSource::kReadyStateEnded;

  if (!use_video_tracks && !use_audio_tracks) {
    LOG(WARNING) << __func__ << ": no tracks to be recorded.";
    return false;
  }

  const bool use_mp4_muxer = IsMp4MuxerRequired(type);

  // For each track in tracks, if the User Agent cannot record the track using
  // the current configuration, abort. See step 14 in
  // https://w3c.github.io/mediacapture-record/MediaRecorder.html#dom-mediarecorder-start
  if (!type.empty()) {
    const bool video_type_supported = CanSupportVideoType(type);
    const bool audio_type_supported = CanSupportAudioType(type);
    if (use_video_tracks && !video_type_supported) {
      return false;
    }
    if (use_audio_tracks && !(video_type_supported || audio_type_supported)) {
      return false;
    }

    if (use_mp4_muxer &&
        !base::FeatureList::IsEnabled(kMediaRecorderEnableMp4Muxer)) {
      return false;
    }
  }

  std::unique_ptr<media::Muxer> muxer;
  media::AudioCodec audio_codec = CodecIdToMediaAudioCodec(audio_codec_id_);
  std::optional<base::TimeDelta> optional_timeslice;
  if (timeslice > 0) {
    optional_timeslice = timeslice_;
  }

  auto write_callback =
      WTF::BindRepeating(&MediaRecorderHandler::WriteData,
                         WrapPersistent(weak_factory_.GetWeakCell()));
  if (use_mp4_muxer) {
    muxer = std::make_unique<media::Mp4Muxer>(
        audio_codec, use_video_tracks, use_audio_tracks,
        std::make_unique<media::Mp4MuxerDelegate>(
            audio_codec,
            MediaVideoCodecFromCodecId(video_codec_profile_.codec_id),
            video_codec_profile_.profile, video_codec_profile_.level,
            write_callback),
        optional_timeslice);

#if BUILDFLAG(IS_WIN)
    // Windows OS uses MediaFoundation for MP4 muxing, which requires the
    // specific audio bit rate for AAC encoding.
    if (audio_bits_per_second_ != 0u) {
      audio_bits_per_second_ =
          media::MFAudioEncoder::ClampAccCodecBitrate(audio_bits_per_second_);
      recorder_->UpdateAudioBitrate(audio_bits_per_second_);
    }
#endif
  } else {
    muxer = std::make_unique<media::WebmMuxer>(
        audio_codec, use_video_tracks, use_audio_tracks,
        std::make_unique<media::LiveWebmMuxerDelegate>(write_callback),
        optional_timeslice);
  }
  muxer_adapter_ = std::make_unique<media::MuxerTimestampAdapter>(
      std::move(muxer), use_video_tracks, use_audio_tracks);

  if (use_video_tracks) {
    // TODO(mcasas): The muxer API supports only one video track. Extend it to
    // several video tracks, see http://crbug.com/528523.
    LOG_IF(WARNING, video_tracks_.size() > 1u)
        << "Recording multiple video tracks is not implemented. "
        << "Only recording first video track.";
    if (!video_tracks_[0])
      return false;
    UpdateTrackLiveAndEnabled(*video_tracks_[0], /*is_video=*/true);

    MediaStreamVideoTrack* const video_track =
        static_cast<MediaStreamVideoTrack*>(
            video_tracks_[0]->GetPlatformTrack());
    const bool use_encoded_source_output =
        video_track->source() != nullptr &&
        video_track->source()->SupportsEncodedOutput();
    if (passthrough_enabled_ && use_encoded_source_output) {
      video_recorders_.emplace_back(
          std::make_unique<VideoTrackRecorderPassthrough>(
              main_thread_task_runner_, video_tracks_[0],
              weak_video_factory_.GetWeakCell(), key_frame_config_));
    } else {
      video_recorders_.emplace_back(std::make_unique<VideoTrackRecorderImpl>(
          main_thread_task_runner_, video_codec_profile_, video_tracks_[0],
          weak_video_factory_.GetWeakCell(), video_bits_per_second_,
          key_frame_config_));
    }
  }

  if (use_audio_tracks) {
    // TODO(ajose): The muxer API supports only one audio track. Extend it to
    // several tracks.
    LOG_IF(WARNING, audio_tracks_.size() > 1u)
        << "Recording multiple audio"
        << " tracks is not implemented.  Only recording first audio track.";
    if (!audio_tracks_[0])
      return false;
    UpdateTrackLiveAndEnabled(*audio_tracks_[0], /*is_video=*/false);

    audio_recorders_.emplace_back(std::make_unique<AudioTrackRecorder>(
        main_thread_task_runner_, audio_codec_id_, audio_tracks_[0],
        weak_audio_factory_.GetWeakCell(), audio_bits_per_second_,
        audio_bitrate_mode_));
  }

  recording_ = true;
  return true;
}

void MediaRecorderHandler::Stop() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  // Don't check |recording_| since we can go directly from pause() to stop().

  // TODO(crbug.com/719023): The video recorder needs to be flushed to retrieve
  // the last N frames with some codecs.

  // Unregister from media stream notifications.
  if (media_stream_ && is_media_stream_observer_) {
    media_stream_->RemoveObserver(this);
  }
  is_media_stream_observer_ = false;

  // Ensure any stored data inside the muxer is flushed out before invalidation.
  muxer_adapter_ = nullptr;
  weak_audio_factory_.Invalidate();
  weak_video_factory_.Invalidate();
  weak_factory_.Invalidate();

  recording_ = false;
  timeslice_ = base::Milliseconds(0);
  video_recorders_.clear();
  audio_recorders_.clear();
}

void MediaRecorderHandler::Pause() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(recording_);
  recording_ = false;
  for (const auto& video_recorder : video_recorders_)
    video_recorder->Pause();
  for (const auto& audio_recorder : audio_recorders_)
    audio_recorder->Pause();
  if (muxer_adapter_) {
    muxer_adapter_->Pause();
  }
}

void MediaRecorderHandler::Resume() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!recording_);
  recording_ = true;
  for (const auto& video_recorder : video_recorders_)
    video_recorder->Resume();
  for (const auto& audio_recorder : audio_recorders_)
    audio_recorder->Resume();
  if (muxer_adapter_) {
    muxer_adapter_->Resume();
  }
}

void MediaRecorderHandler::EncodingInfo(
    const WebMediaConfiguration& configuration,
    OnMediaCapabilitiesEncodingInfoCallback callback) {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(configuration.video_configuration ||
         configuration.audio_configuration);

  std::unique_ptr<WebMediaCapabilitiesInfo> info(
      new WebMediaCapabilitiesInfo());

  // TODO(mcasas): Support the case when both video and audio configurations are
  // specified: https://crbug.com/709181.
  String mime_type;
  String codec;
  if (configuration.video_configuration) {
    mime_type = configuration.video_configuration->mime_type;
    codec = configuration.video_configuration->codec;
  } else {
    mime_type = configuration.audio_configuration->mime_type;
    codec = configuration.audio_configuration->codec;
  }

  info->supported = CanSupportMimeType(mime_type, codec);

  if (configuration.video_configuration && info->supported) {
    VideoTrackRecorder::CodecProfile codec_profile =
        VideoStringToCodecProfile(codec);
    const bool is_likely_accelerated =
        VideoTrackRecorderImpl::CanUseAcceleratedEncoder(
            codec_profile, configuration.video_configuration->width,
            configuration.video_configuration->height,
            configuration.video_configuration->framerate);

    const float pixels_per_second =
        configuration.video_configuration->width *
        configuration.video_configuration->height *
        configuration.video_configuration->framerate;
    // Encoding is considered |smooth| up and until the pixels per second
    // threshold or if it's likely to be accelerated.
    const float threshold = base::SysInfo::IsLowEndDevice()
                                ? kNumPixelsPerSecondSmoothnessThresholdLow
                                : kNumPixelsPerSecondSmoothnessThresholdHigh;
    info->smooth = is_likely_accelerated || pixels_per_second <= threshold;

    // TODO(mcasas): revisit what |power_efficient| means
    // https://crbug.com/709181.
    info->power_efficient = info->smooth;
  }
  DVLOG(1) << "type: " << mime_type.Ascii() << ", params:" << codec.Ascii()
           << " is" << (info->supported ? " supported" : " NOT supported")
           << " and" << (info->smooth ? " smooth" : " NOT smooth");

  std::move(callback).Run(std::move(info));
}

String MediaRecorderHandler::ActualMimeType() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(recorder_) << __func__ << " should be called after Initialize()";

  const bool has_video_tracks = media_stream_->NumberOfVideoComponents();
  const bool has_audio_tracks = media_stream_->NumberOfAudioComponents();
  if (!has_video_tracks && !has_audio_tracks)
    return String();

  StringBuilder mime_type;
  if (!has_video_tracks && has_audio_tracks) {
    if (passthrough_enabled_) {
      DCHECK(type_.empty());
      mime_type.Append("audio/webm");
    } else {
      mime_type.Append(type_.Span8());
    }
    mime_type.Append(";codecs=");
  } else {
    switch (video_codec_profile_.codec_id) {
      case VideoTrackRecorder::CodecId::kVp8:
      case VideoTrackRecorder::CodecId::kVp9:
      case VideoTrackRecorder::CodecId::kAv1:
        if (passthrough_enabled_) {
          mime_type.Append("video/webm");
        } else {
          mime_type.Append(type_.Span8());
        }
        mime_type.Append(";codecs=");
        break;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      case VideoTrackRecorder::CodecId::kH264:
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      case VideoTrackRecorder::CodecId::kHevc:
#endif
        if (!passthrough_enabled_ &&
            EqualIgnoringASCIICase(type_, "video/mp4")) {
          mime_type.Append(type_.Span8());
        } else {
          mime_type.Append("video/x-matroska");
        }
        mime_type.Append(";codecs=");
        break;
#endif
      case VideoTrackRecorder::CodecId::kLast:
        // Do nothing.
        break;
    }
  }
  if (has_video_tracks) {
    switch (video_codec_profile_.codec_id) {
      case VideoTrackRecorder::CodecId::kVp8:
        mime_type.Append("vp8");
        break;
      case VideoTrackRecorder::CodecId::kVp9:
        mime_type.Append("vp9");
        break;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      case VideoTrackRecorder::CodecId::kH264:
        mime_type.Append("avc1");
        if (video_codec_profile_.profile && video_codec_profile_.level) {
          mime_type.Append(
              media::BuildH264MimeSuffix(*video_codec_profile_.profile,
                                         *video_codec_profile_.level)
                  .c_str());
        }
        break;
#endif
      case VideoTrackRecorder::CodecId::kAv1:
        mime_type.Append("av01");
        break;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      case VideoTrackRecorder::CodecId::kHevc:
        mime_type.Append("hvc1");
        break;
#endif
      case VideoTrackRecorder::CodecId::kLast:
        DCHECK_NE(audio_codec_id_, AudioTrackRecorder::CodecId::kLast);
    }
  }
  if (has_video_tracks && has_audio_tracks) {
    if (video_codec_profile_.codec_id != VideoTrackRecorder::CodecId::kLast &&
        audio_codec_id_ != AudioTrackRecorder::CodecId::kLast) {
      mime_type.Append(",");
    }
  }
  if (has_audio_tracks) {
    switch (audio_codec_id_) {
      case AudioTrackRecorder::CodecId::kOpus:
        mime_type.Append("opus");
        break;
      case AudioTrackRecorder::CodecId::kPcm:
        mime_type.Append("pcm");
        break;
      case AudioTrackRecorder::CodecId::kAac:
        mime_type.Append("mp4a.40.2");
        break;
      case AudioTrackRecorder::CodecId::kLast:
        DCHECK_NE(video_codec_profile_.codec_id,
                  VideoTrackRecorder::CodecId::kLast);
    }
  }
  return mime_type.ToString();
}

void MediaRecorderHandler::TrackAdded(const WebString& track_id) {
  OnStreamChanged("Tracks in MediaStream were added.");
}

void MediaRecorderHandler::TrackRemoved(const WebString& track_id) {
  OnStreamChanged("Tracks in MediaStream were removed.");
}

void MediaRecorderHandler::OnStreamChanged(const String& message) {
  if (recorder_) {
    // The call to MediaRecorder::OnStreamChanged has to be posted because
    // otherwise stream track set changing leads to the MediaRecorder
    // synchronously 
"""


```