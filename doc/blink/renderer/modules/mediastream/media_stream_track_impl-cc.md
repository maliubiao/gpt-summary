Response:
The user wants a summary of the provided C++ source code file `media_stream_track_impl.cc`. Specifically, they're interested in:

1. **Functionality:** What does this file do?
2. **Relationship to web technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logical inferences:**  Any examples of input/output scenarios.
4. **Common usage errors:** Mistakes developers might make.
5. **Debugging context:** How does a user reach this code during a debugging session?
6. **Overall function (for this first part):**  A high-level summary.

Let's break down the code to address these points.

**Functionality:**

- The file implements the `MediaStreamTrackImpl` class. This class seems to be a core part of the media streaming functionality in Blink.
- It deals with managing the state of a media stream track (audio or video).
- It handles applying constraints to media tracks.
- It interacts with the underlying platform's media stream capabilities.
- It handles cloning media tracks.
- It supports the Image Capture API for video tracks.
- It provides methods to get track capabilities, constraints, and settings.
- It manages the 'enabled' and 'muted' states of a track.
- It handles stopping a media track.

**Relationship to web technologies:**

- **JavaScript:**  The file heavily uses Blink's binding infrastructure (`third_party/blink/renderer/bindings`). The presence of `V8MediaStreamTrackState`, `V8MediaTrackCapabilities`, `V8MediaTrackConstraints`, etc., strongly indicates that this C++ code is the underlying implementation for JavaScript APIs related to `MediaStreamTrack`. Methods like `getCapabilities`, `getConstraints`, `getSettings`, and `applyConstraints` directly correspond to JavaScript methods on the `MediaStreamTrack` object.
- **HTML:**  When a web page uses the `<video>` or `<audio>` elements and sources media from a `MediaStreamTrack`, this C++ code is involved in managing that track.
- **CSS:** While this file itself doesn't directly interact with CSS, the media streams it manages might influence how video or audio elements are rendered or behave, which could be styled with CSS.

**Logical inferences (Hypothetical Input/Output):**

- **Input:** A JavaScript call to `track.applyConstraints({ width: 640 })`.
- **Output:** The `applyConstraints` method in this C++ file would be invoked. It would attempt to apply the width constraint to the underlying media source. If successful, the promise would resolve. If the constraint cannot be satisfied, the promise would reject with an `OverconstrainedError`.

**Common usage errors:**

- Trying to apply incompatible constraints (e.g., both Image Capture and non-Image Capture constraints simultaneously).
- Not handling the promise rejection from `applyConstraints`, which could lead to unexpected behavior if constraints cannot be met.

**User operation to reach here (Debugging Context):**

1. A user visits a web page that uses the WebRTC or Media Capture APIs.
2. JavaScript code on the page calls `navigator.mediaDevices.getUserMedia()` or `navigator.mediaDevices.getDisplayMedia()` to obtain a media stream.
3. The returned `MediaStream` object contains one or more `MediaStreamTrack` objects.
4. The JavaScript code might then call methods on these `MediaStreamTrack` objects, such as `getCapabilities()`, `getConstraints()`, `applyConstraints()`, or `stop()`.
5. During debugging, a developer might set a breakpoint in the corresponding C++ methods within `media_stream_track_impl.cc` to inspect the internal state or execution flow.

**Overall function (for this first part):**

This first part of the `media_stream_track_impl.cc` file focuses on the core functionality of the `MediaStreamTrackImpl` class. It handles the basic lifecycle and state management of a media stream track, including creation, enabling/disabling, muting, stopping, and cloning. It also lays the groundwork for constraint application and interactions with the underlying platform media components and the Image Capture API. It's a crucial component in bridging the gap between the JavaScript `MediaStreamTrack` API and the platform's media capabilities.

Now, let's generate the detailed answer based on this analysis.
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2011 Ericsson AB. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"

#include <memory>

#include "base/check_op.h"
#include "base/functional/callback_helpers.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_double_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_capabilities.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_settings.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_point_2d.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_mediastreamtrackaudiostats_mediastreamtrackvideostats.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/imagecapture/image_capture.h"
#include "third_party/blink/renderer/modules/mediastream/apply_constraints_request.h"
#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_audio_stats.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_video_stats.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/overconstrained_error.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/transferred_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/modules/mediastream/webaudio_media_stream_audio_sink.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_web_audio_source.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// The set of constrainable properties for image capture is available at
// https://w3c.github.io/mediacapture-image/#constrainable-properties
// TODO(guidou): Integrate image-capture constraints processing with the
// spec-compliant main implementation and remove these support functions.
// http://crbug.com/708723
bool ConstraintSetHasImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  return constraint_set->hasWhiteBalanceMode() ||
         constraint_set->hasExposureMode() || constraint_set->hasFocusMode() ||
         constraint_set->hasPointsOfInterest() ||
         constraint_set->hasExposureCompensation() ||
         constraint_set->hasExposureTime() ||
         constraint_set->hasColorTemperature() || constraint_set->hasIso() ||
         constraint_set->hasBrightness() || constraint_set->hasContrast() ||
         constraint_set->hasSaturation() || constraint_set->hasSharpness() ||
         constraint_set->hasFocusDistance() || constraint_set->hasPan() ||
         constraint_set->hasTilt() || constraint_set->hasZoom() ||
         constraint_set->hasTorch() || constraint_set->hasBackgroundBlur() ||
         constraint_set->hasBackgroundSegmentationMask() ||
         constraint_set->hasEyeGazeCorrection() ||
         constraint_set->hasFaceFraming();
}

bool ConstraintSetHasNonImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  // TODO(crbug.com/1381959): Add hasSuppressLocalAudioPlayback() to this list
  // and complete support for toggling suppressLocalAudioPlayback using
  // the applyConstraints() API.
  return constraint_set->hasAspectRatio() ||
         constraint_set->hasChannelCount() || constraint_set->hasDeviceId() ||
         constraint_set->hasEchoCancellation() ||
         constraint_set->hasNoiseSuppression() ||
         constraint_set->hasVoiceIsolation() ||
         constraint_set->hasAutoGainControl() ||
         constraint_set->hasFacingMode() || constraint_set->hasResizeMode() ||
         constraint_set->hasFrameRate() || constraint_set->hasGroupId() ||
         constraint_set->hasHeight() || constraint_set->hasLatency() ||
         constraint_set->hasSampleRate() || constraint_set->hasSampleSize() ||
         constraint_set->hasWidth();
}

bool ConstraintSetHasImageAndNonImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  return ConstraintSetHasImageCapture(constraint_set) &&
         ConstraintSetHasNonImageCapture(constraint_set);
}

bool ConstraintSetIsNonEmpty(const MediaTrackConstraintSet* constraint_set) {
  return ConstraintSetHasImageCapture(constraint_set) ||
         ConstraintSetHasNonImageCapture(constraint_set);
}

template <typename ConstraintSetCondition>
bool ConstraintsSatisfyCondition(ConstraintSetCondition condition,
                                 const MediaTrackConstraints* constraints) {
  if (condition(constraints)) {
    return true;
  }

  if (!constraints->hasAdvanced()) {
    return false;
  }

  for (const auto& advanced_set : constraints->advanced()) {
    if (condition(advanced_set)) {
      return true;
    }
  }

  return false;
}

bool ConstraintsHaveImageAndNonImageCapture(
    const MediaTrackConstraints* constraints) {
  return ConstraintsSatisfyCondition(ConstraintSetHasImageAndNonImageCapture,
                                     constraints);
}

bool ConstraintsAreEmpty(const MediaTrackConstraints* constraints) {
  return !ConstraintsSatisfyCondition(ConstraintSetIsNonEmpty, constraints);
}

bool ConstraintsHaveImageCapture(const MediaTrackConstraints* constraints) {
  return ConstraintsSatisfyCondition(ConstraintSetHasImageCapture, constraints);
}

// Caller must take the ownership of the returned |WebAudioSourceProvider|
// object.
std::unique_ptr<WebAudioSourceProvider>
CreateWebAudioSourceFromMediaStreamTrack(
    MediaStreamComponent* component,
    int context_sample_rate,
    base::TimeDelta platform_buffer_duration) {
  MediaStreamTrackPlatform* media_stream_track = component->GetPlatformTrack();
  if (!media_stream_track) {
    DLOG(ERROR) << "Native track missing for webaudio source.";
    return nullptr;
  }

  MediaStreamSource* source = component->Source();
  DCHECK_EQ(source->GetType(), MediaStreamSource::kTypeAudio);

  return std::make_unique<WebAudioMediaStreamAudioSink>(
      component, context_sample_rate, platform_buffer_duration);
}

void DidCloneMediaStreamTrack(MediaStreamComponent* clone) {
  DCHECK(clone);
  DCHECK(clone->Source());

  if (clone->GetSourceType() == MediaStreamSource::kTypeAudio) {
    MediaStreamAudioSource::From(clone->Source())
        ->ConnectToInitializedTrack(clone);
  }
}

// Returns the DisplayCaptureSurfaceType for display-capture tracks,
// std::nullopt for non-display-capture tracks.
std::optional<media::mojom::DisplayCaptureSurfaceType> GetDisplayCaptureType(
    const MediaStreamComponent* component) {
  const MediaStreamTrackPlatform* const platform_track =
      component->GetPlatformTrack();
  if (!platform_track) {
    return std::nullopt;
  }

  MediaStreamTrackPlatform::Settings settings;
  component->GetPlatformTrack()->GetSettings(settings);
  return settings.display_surface;
}

WebString GetDisplaySurfaceString(
    media::mojom::DisplayCaptureSurfaceType value) {
  switch (value) {
    case media::mojom::DisplayCaptureSurfaceType::MONITOR:
      return WebString::FromUTF8("monitor");
    case media::mojom::DisplayCaptureSurfaceType::WINDOW:
      return WebString::FromUTF8("window");
    case media::mojom::DisplayCaptureSurfaceType::BROWSER:
      return WebString::FromUTF8("browser");
  }
  NOTREACHED();
}

}  // namespace

MediaStreamTrack* MediaStreamTrackImpl::Create(ExecutionContext* context,
                                               MediaStreamComponent* component,
                                               base::OnceClosure callback) {
  DCHECK(context);
  DCHECK(component);

  const std::optional<media::mojom::DisplayCaptureSurfaceType>
      display_surface_type = GetDisplayCaptureType(component);
  const bool is_tab_capture =
      (display_surface_type ==
       media::mojom::DisplayCaptureSurfaceType::BROWSER);

  if (is_tab_capture && RuntimeEnabledFeatures::RegionCaptureEnabled(context)) {
    return MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
        context, component, std::move(callback));
  } else {
    return MakeGarbageCollected<MediaStreamTrackImpl>(context, component,
                                                      std::move(callback));
  }
}

MediaStreamTrackImpl::MediaStreamTrackImpl(ExecutionContext* context,
                                           MediaStreamComponent* component)
    : MediaStreamTrackImpl(context,
                           component,
                           component->GetReadyState(),
                           /*callback=*/base::DoNothing()) {}

MediaStreamTrackImpl::MediaStreamTrackImpl(ExecutionContext* context,
                                           MediaStreamComponent* component,
                                           base::OnceClosure callback)
    : MediaStreamTrackImpl(context,
                           component,
                           component->GetReadyState(),
                           std::move(callback)) {}

MediaStreamTrackImpl::MediaStreamTrackImpl(
    ExecutionContext* context,
    MediaStreamComponent* component,
    MediaStreamSource::ReadyState ready_state,
    base::OnceClosure callback,
    bool is_clone)
    : ready_state_(ready_state),
      component_(component),
      execution_context_(context) {
  DCHECK(component_);
  component_->AddSourceObserver(this);

  // If the source is already non-live at this point, the observer won't have
  // been called. Update the muted state manually.
  muted_ = ready_state_ == MediaStreamSource::kReadyStateMuted;

  SendLogMessage(String::Format("%s()", __func__));

  MediaStreamVideoTrack* const video_track =
      MediaStreamVideoTrack::From(Component());
  if (video_track && component_->Source() &&
      component_->GetSourceType() == MediaStreamSource::kTypeVideo) {
    image_capture_ = MakeGarbageCollected<ImageCapture>(
        context, this, video_track->pan_tilt_zoom_allowed(),
        std::move(callback));
  } else {
    if (execution_context_) {
      execution_context_->GetTaskRunner(TaskType::kInternalMedia)
          ->PostTask(FROM_HERE, std::move(callback));
    } else {
      std::move(callback).Run();
    }
  }

  // Note that both 'live' and 'muted' correspond to a 'live' ready state in the
  // web API.
  if (ready_state_ != MediaStreamSource::kReadyStateEnded) {
    EnsureFeatureHandleForScheduler();
  }
}

MediaStreamTrackImpl::~MediaStreamTrackImpl() = default;

String MediaStreamTrackImpl::kind() const {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(String, audio_kind, ("audio"));
  DEFINE_THREAD_SAFE_STATIC_LOCAL(String, video_kind, ("video"));

  switch (component_->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      return audio_kind;
    case MediaStreamSource::kTypeVideo:
      return video_kind;
  }

  NOTREACHED();
}

String MediaStreamTrackImpl::id() const {
  return component_->Id();
}

String MediaStreamTrackImpl::label() const {
  return component_->GetSourceName();
}

bool MediaStreamTrackImpl::enabled() const {
  return component_->Enabled();
}

void MediaStreamTrackImpl::setEnabled(bool enabled) {
  if (enabled == component_->Enabled()) {
    return;
  }

  component_->SetEnabled(enabled);

  SendLogMessage(
      String::Format("%s({enabled=%s})", __func__, enabled ? "true" : "false"));
}

bool MediaStreamTrackImpl::muted() const {
  return muted_;
}

String MediaStreamTrackImpl::ContentHint() const {
  return ContentHintToString(component_->ContentHint());
}

void MediaStreamTrackImpl::SetContentHint(const String& hint) {
  SendLogMessage(
      String::Format("%s({hint=%s})", __func__, hint.Utf8().c_str()));
  WebMediaStreamTrack::ContentHintType translated_hint =
      WebMediaStreamTrack::ContentHintType::kNone;
  switch (component_->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      if (hint == kContentHintStringNone) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kNone;
      } else if (hint == kContentHintStringAudioSpeech) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kAudioSpeech;
      } else if (hint == kContentHintStringAudioMusic) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kAudioMusic;
      } else {
        // TODO(pbos): Log warning?
        // Invalid values for audio are to be ignored (similar to invalid enum
        // values).
        return;
      }
      break;
    case MediaStreamSource::kTypeVideo:
      if (hint == kContentHintStringNone) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kNone;
      } else if (hint == kContentHintStringVideoMotion) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoMotion;
      } else if (hint == kContentHintStringVideoDetail) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoDetail;
      } else if (hint == kContentHintStringVideoText) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoText;
      } else {
        // TODO(pbos): Log warning?
        // Invalid values for video are to be ignored (similar to invalid enum
        // values).
        return;
      }
  }

  component_->SetContentHint(translated_hint);
}

V8MediaStreamTrackState MediaStreamTrackImpl::readyState() const {
  if (Ended()) {
    return V8MediaStreamTrackState(V8MediaStreamTrackState::Enum::kEnded);
  }
  return ReadyStateToV8TrackState(ready_state_);
}

void MediaStreamTrackImpl::setReadyState(
    MediaStreamSource::ReadyState ready_state) {
  if (ready_state_ != MediaStreamSource::kReadyStateEnded &&
      ready_state_ != ready_state) {
    ready_state_ = ready_state;
    SendLogMessage(String::Format("%s({ready_state=%s})", __func__,
                                  readyState().AsCStr()));

    // Observers may dispatch events which create and add new Observers;
    // take a snapshot so as to safely iterate.
    HeapVector<Member<MediaStreamTrack::Observer>> observers(observers_);
    for (auto observer : observers) {
      observer->TrackChangedState();
    }
  }
}

void MediaStreamTrackImpl::stopTrack(ExecutionContext* execution_context) {
  SendLogMessage(String::Format("%s()", __func__));
  if (Ended()) {
    return;
  }

  if (auto* track = Component()->GetPlatformTrack()) {
    // Synchronously disable the platform track to prevent media from flowing,
    // even if the stopTrack() below is completed asynchronously.
    // See https://crbug.com/1320312.
    track->SetEnabled(false);
  }

  setReadyState(MediaStreamSource::kReadyStateEnded);
  feature_handle_for_scheduler_.reset();
  feature_handle_for_scheduler_on_live_media_stream_track_.reset();
  UserMediaClient* user_media_client =
      UserMediaClient::From(To<LocalDOMWindow>(execution_context));
  if (user_media_client) {
    user_media_client->StopTrack(Component());
  }

  PropagateTrackEnded();
}

MediaStreamTrack* MediaStreamTrackImpl::clone(
    ExecutionContext* execution_context) {
  SendLogMessage(String::Format("%s()", __func__));

  // Instantiate the clone.
  MediaStreamTrackImpl* cloned_track =
      MakeGarbageCollected<MediaStreamTrackImpl>(
          execution_context, Component()->Clone(), ready_state_,
          base::DoNothing(), /*is_clone=*/true);

  // Copy state.
  CloneInternal(cloned_track);

  return cloned_track;
}

MediaTrackCapabilities* MediaStreamTrackImpl::getCapabilities() const {
  MediaTrackCapabilities* capabilities = MediaTrackCapabilities::Create();
  if (image_capture_) {
    image_capture_->GetMediaTrackCapabilities(capabilities);
  }
  auto platform_capabilities = component_->Source()->GetCapabilities();

  capabilities->setDeviceId(platform_capabilities.device_id);
  if (!platform_capabilities.group_id.IsNull()) {
    capabilities->setGroupId(platform_capabilities.group_id);
  }

  if (component_->GetSourceType() == MediaStreamSource::kTypeAudio) {
    Vector<bool> echo_cancellation, auto_gain_control, noise_suppression,
        voice_isolation;
    for (bool value : platform_capabilities.echo_cancellation) {
      echo_cancellation.push_back(value);
    }
    capabilities->setEchoCancellation(echo_cancellation);
    for (bool value : platform_capabilities.auto_gain_control) {
      auto_gain_control.push_back(value);
    }
    capabilities->setAutoGainControl(auto_gain_control);
    for (bool value : platform_capabilities.noise_suppression) {
      noise_suppression.push_back(value);
    }
    capabilities->setNoiseSuppression(noise_suppression);
    for (bool value : platform_capabilities.voice_isolation) {
      voice_isolation.push_back(value);
    }
    capabilities->setVoiceIsolation(voice_isolation);
    // Sample size.
    if (platform_capabilities.sample_size.size() == 2) {
      LongRange* sample_size = LongRange::Create();
      sample_size->setMin(platform_capabilities.sample_size[0]);
      sample_size->setMax(platform_capabilities.sample_size[1]);
      capabilities->setSampleSize(sample_size);
    }
    // Channel count.
    if (platform_capabilities.channel_count.size() == 2) {
      LongRange* channel_count = LongRange::Create();
      channel_count->setMin(platform_capabilities.channel_count[0]);
      channel_count->setMax(platform_capabilities.channel_count[1]);
      capabilities->setChannelCount(channel_count);
    }
    // Sample rate.
    if (platform_capabilities.sample_rate.size() == 2) {
      LongRange* sample_rate = LongRange::Create();
      sample_rate->setMin(platform_capabilities.sample_rate[0]);
      sample_rate->setMax(platform_capabilities.sample_rate[1]);
      capabilities->setSampleRate(sample_rate);
    }
    // Latency.
    if (platform_capabilities.latency.size() == 2) {
      DoubleRange* latency = DoubleRange::Create();
      latency->setMin(platform_capabilities.latency[0]);
      latency->setMax(platform_capabilities.latency[1]);
      capabilities->setLatency(latency);
    }
  }

  if (component_->GetSourceType() == MediaStreamSource::kTypeVideo) {
    if (platform_capabilities.width.size() == 2) {
      LongRange* width = LongRange::Create();
      width->setMin(platform_capabilities.width[0]);
      width->setMax(platform_capabilities.width[1]);
      capabilities->setWidth(width);
    }
    if (platform_capabilities.height.size() == 2) {
      LongRange* height = LongRange::Create();
      height->setMin(platform_capabilities.height[0]);
      height->setMax(platform_capabilities.height[1]);
      capabilities->setHeight(height);
    }
    if (platform_capabilities.aspect_ratio.size() == 2) {
      DoubleRange* aspect_ratio = DoubleRange::Create();
      aspect_ratio->setMin(platform_capabilities.aspect_ratio[0]);
      aspect_ratio->setMax(platform_capabilities.aspect_ratio[1]);
      capabilities->setAspectRatio(aspect_ratio);
    }
    if (platform_capabilities.frame_rate.size() == 2) {
      DoubleRange* frame_rate = DoubleRange::Create();
      frame_rate->setMin(platform_capabilities.frame_rate[0]);
      frame_rate->setMax(platform_capabilities.frame_rate[1]);
      capabilities->setFrameRate(frame_rate);
    }
    Vector<String> facing_mode;
    switch (platform_capabilities.facing_mode) {
      case MediaStreamTrackPlatform::FacingMode::kUser:
        facing_mode.push_back("user");
        break;
      case MediaStreamTrackPlatform::FacingMode::kEnvironment:
        facing_mode.push_back("environment");
        break;
      case MediaStreamTrackPlatform::FacingMode::kLeft:
        facing_mode.push_back("left");
        break;
      case MediaStreamTrackPlatform::FacingMode::kRight:
        facing_mode.push_back("right");
        break;
      default:
        break;
    }
    capabilities->setFacingMode(facing_mode);
    capabilities->setResizeMode({WebMediaStreamTrack::kResizeModeNone,
                                 WebMediaStreamTrack::kResizeModeRescale});
    const std::optional<const MediaStreamDevice> source_device = device();
    if (source_device && source_device->display_media_info) {
      capabilities->setDisplaySurface(GetDisplaySurfaceString(
          source_device->display_media_info->display_surface));
    }
  }
  return capabilities;
}

MediaTrackConstraints* MediaStreamTrackImpl::getConstraints() const {
  if (image_capture_) {
    if (auto* image_capture_constraints =
            image_capture_->GetMediaTrackConstraints()) {
      return image_capture_constraints;
    }
  }

  return media_constraints_impl::ConvertConstraints(constraints_);
}

MediaTrackSettings* MediaStreamTrackImpl::getSettings() const {
  MediaTrackSettings* settings = MediaTrackSettings::Create();
  MediaStreamTrackPlatform::Settings platform_settings;
  component_->GetSettings(platform_settings);
  if (platform_settings.HasFrameRate()) {
    settings->setFrameRate(platform_settings.frame_rate);
  }
  if (platform_settings.HasWidth()) {
    settings->setWidth(platform_settings.width);
  }
  if (platform_settings.HasHeight()) {
    settings->setHeight(platform_settings.height);
  }
  if (platform_settings.HasAspectRatio()) {
    settings->setAspectRatio(platform_settings.aspect_ratio);
  }
  settings->setDeviceId(platform_settings.device_id);
  if (!platform_settings.group_id.IsNull()) {
    settings->setGroupId(platform_settings.group_id);
  }
  if (platform_settings.HasFacingMode()) {
    switch (platform_settings.facing_mode) {
      case MediaStreamTrackPlatform::FacingMode::kUser:
        settings->setFacingMode("user");
        break;
      case MediaStreamTrackPlatform::FacingMode::kEnvironment:
        settings->setFacingMode("environment");
        break;
      case MediaStreamTrackPlatform::FacingMode::kLeft:
        settings->setFacingMode("left");
        break;
      case MediaStreamTrackPlatform::FacingMode::kRight:
        settings->setFacingMode("right");
        break;
      default:
        // None, or unknown facing mode. Ignore.
        break;
    }
  }
  if (!platform_settings.resize_mode.IsNull()) {
    settings->setResizeMode(platform_settings.resize_mode);
  }

  if (platform_settings.echo_cancellation) {
    settings->setEchoCancellation(*platform_settings.echo_cancellation);
  }
  if (platform_settings.auto_gain_control) {
    settings->setAutoGainControl(*platform_settings.auto_gain_control);
  }
  if (platform_settings.noise_supression) {
    settings->setNoiseSuppression(*platform_settings.noise_supression);
  }
  if (platform_settings.voice_isolation) {
    settings->setVoiceIsolation(*platform_settings.voice_isolation);
  }
  if (platform_settings.HasSampleRate()) {
    settings->setSampleRate(platform_settings.sample_rate);
  }
  if (platform_settings.HasSampleSize()) {
    settings->setSampleSize(platform_settings.sample_size);
  }
  if (platform_settings.HasChannelCount()) {
    settings->setChannelCount(platform_settings.channel_count);
  }
  if (platform_settings.HasLatency()) {
    settings->setLatency(platform_settings.latency);
  }

  if (image_capture_) {
    image_capture_->GetMediaTrackSettings(settings);
  }

  if (platform_settings.display_surface) {
    settings->setDisplaySurface(
        GetDisplaySurfaceString(platform_settings.display_surface.value()));
  }
  if (platform_settings.logical_surface) {
    settings->setLogicalSurface(platform_settings.logical_surface.value());
  }
  if (platform_settings.cursor) {
    WTF::String value;
    switch (platform_settings.cursor.value()) {
      case media::mojom::CursorCaptureType::NEVER:
        value = "never";
        break;
      case media::mojom::CursorCaptureType::ALWAYS:
        value = "always";
        break;
      case media::mojom::CursorCaptureType::MOTION:
        value = "motion";
        break;
    }
    settings->setCursor(value);
  }

  if (suppress_local_audio_playback_setting_.has_value()) {
### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_track_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2011 Ericsson AB. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"

#include <memory>

#include "base/check_op.h"
#include "base/functional/callback_helpers.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_double_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_capabilities.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_settings.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_point_2d.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_mediastreamtrackaudiostats_mediastreamtrackvideostats.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/imagecapture/image_capture.h"
#include "third_party/blink/renderer/modules/mediastream/apply_constraints_request.h"
#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_audio_stats.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_video_stats.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/overconstrained_error.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/transferred_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/modules/mediastream/webaudio_media_stream_audio_sink.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_web_audio_source.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// The set of constrainable properties for image capture is available at
// https://w3c.github.io/mediacapture-image/#constrainable-properties
// TODO(guidou): Integrate image-capture constraints processing with the
// spec-compliant main implementation and remove these support functions.
// http://crbug.com/708723
bool ConstraintSetHasImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  return constraint_set->hasWhiteBalanceMode() ||
         constraint_set->hasExposureMode() || constraint_set->hasFocusMode() ||
         constraint_set->hasPointsOfInterest() ||
         constraint_set->hasExposureCompensation() ||
         constraint_set->hasExposureTime() ||
         constraint_set->hasColorTemperature() || constraint_set->hasIso() ||
         constraint_set->hasBrightness() || constraint_set->hasContrast() ||
         constraint_set->hasSaturation() || constraint_set->hasSharpness() ||
         constraint_set->hasFocusDistance() || constraint_set->hasPan() ||
         constraint_set->hasTilt() || constraint_set->hasZoom() ||
         constraint_set->hasTorch() || constraint_set->hasBackgroundBlur() ||
         constraint_set->hasBackgroundSegmentationMask() ||
         constraint_set->hasEyeGazeCorrection() ||
         constraint_set->hasFaceFraming();
}

bool ConstraintSetHasNonImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  // TODO(crbug.com/1381959): Add hasSuppressLocalAudioPlayback() to this list
  // and complete support for toggling suppressLocalAudioPlayback using
  // the applyConstraints() API.
  return constraint_set->hasAspectRatio() ||
         constraint_set->hasChannelCount() || constraint_set->hasDeviceId() ||
         constraint_set->hasEchoCancellation() ||
         constraint_set->hasNoiseSuppression() ||
         constraint_set->hasVoiceIsolation() ||
         constraint_set->hasAutoGainControl() ||
         constraint_set->hasFacingMode() || constraint_set->hasResizeMode() ||
         constraint_set->hasFrameRate() || constraint_set->hasGroupId() ||
         constraint_set->hasHeight() || constraint_set->hasLatency() ||
         constraint_set->hasSampleRate() || constraint_set->hasSampleSize() ||
         constraint_set->hasWidth();
}

bool ConstraintSetHasImageAndNonImageCapture(
    const MediaTrackConstraintSet* constraint_set) {
  return ConstraintSetHasImageCapture(constraint_set) &&
         ConstraintSetHasNonImageCapture(constraint_set);
}

bool ConstraintSetIsNonEmpty(const MediaTrackConstraintSet* constraint_set) {
  return ConstraintSetHasImageCapture(constraint_set) ||
         ConstraintSetHasNonImageCapture(constraint_set);
}

template <typename ConstraintSetCondition>
bool ConstraintsSatisfyCondition(ConstraintSetCondition condition,
                                 const MediaTrackConstraints* constraints) {
  if (condition(constraints)) {
    return true;
  }

  if (!constraints->hasAdvanced()) {
    return false;
  }

  for (const auto& advanced_set : constraints->advanced()) {
    if (condition(advanced_set)) {
      return true;
    }
  }

  return false;
}

bool ConstraintsHaveImageAndNonImageCapture(
    const MediaTrackConstraints* constraints) {
  return ConstraintsSatisfyCondition(ConstraintSetHasImageAndNonImageCapture,
                                     constraints);
}

bool ConstraintsAreEmpty(const MediaTrackConstraints* constraints) {
  return !ConstraintsSatisfyCondition(ConstraintSetIsNonEmpty, constraints);
}

bool ConstraintsHaveImageCapture(const MediaTrackConstraints* constraints) {
  return ConstraintsSatisfyCondition(ConstraintSetHasImageCapture, constraints);
}

// Caller must take the ownership of the returned |WebAudioSourceProvider|
// object.
std::unique_ptr<WebAudioSourceProvider>
CreateWebAudioSourceFromMediaStreamTrack(
    MediaStreamComponent* component,
    int context_sample_rate,
    base::TimeDelta platform_buffer_duration) {
  MediaStreamTrackPlatform* media_stream_track = component->GetPlatformTrack();
  if (!media_stream_track) {
    DLOG(ERROR) << "Native track missing for webaudio source.";
    return nullptr;
  }

  MediaStreamSource* source = component->Source();
  DCHECK_EQ(source->GetType(), MediaStreamSource::kTypeAudio);

  return std::make_unique<WebAudioMediaStreamAudioSink>(
      component, context_sample_rate, platform_buffer_duration);
}

void DidCloneMediaStreamTrack(MediaStreamComponent* clone) {
  DCHECK(clone);
  DCHECK(clone->Source());

  if (clone->GetSourceType() == MediaStreamSource::kTypeAudio) {
    MediaStreamAudioSource::From(clone->Source())
        ->ConnectToInitializedTrack(clone);
  }
}

// Returns the DisplayCaptureSurfaceType for display-capture tracks,
// std::nullopt for non-display-capture tracks.
std::optional<media::mojom::DisplayCaptureSurfaceType> GetDisplayCaptureType(
    const MediaStreamComponent* component) {
  const MediaStreamTrackPlatform* const platform_track =
      component->GetPlatformTrack();
  if (!platform_track) {
    return std::nullopt;
  }

  MediaStreamTrackPlatform::Settings settings;
  component->GetPlatformTrack()->GetSettings(settings);
  return settings.display_surface;
}

WebString GetDisplaySurfaceString(
    media::mojom::DisplayCaptureSurfaceType value) {
  switch (value) {
    case media::mojom::DisplayCaptureSurfaceType::MONITOR:
      return WebString::FromUTF8("monitor");
    case media::mojom::DisplayCaptureSurfaceType::WINDOW:
      return WebString::FromUTF8("window");
    case media::mojom::DisplayCaptureSurfaceType::BROWSER:
      return WebString::FromUTF8("browser");
  }
  NOTREACHED();
}

}  // namespace

MediaStreamTrack* MediaStreamTrackImpl::Create(ExecutionContext* context,
                                               MediaStreamComponent* component,
                                               base::OnceClosure callback) {
  DCHECK(context);
  DCHECK(component);

  const std::optional<media::mojom::DisplayCaptureSurfaceType>
      display_surface_type = GetDisplayCaptureType(component);
  const bool is_tab_capture =
      (display_surface_type ==
       media::mojom::DisplayCaptureSurfaceType::BROWSER);

  if (is_tab_capture && RuntimeEnabledFeatures::RegionCaptureEnabled(context)) {
    return MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
        context, component, std::move(callback));
  } else {
    return MakeGarbageCollected<MediaStreamTrackImpl>(context, component,
                                                      std::move(callback));
  }
}

MediaStreamTrackImpl::MediaStreamTrackImpl(ExecutionContext* context,
                                           MediaStreamComponent* component)
    : MediaStreamTrackImpl(context,
                           component,
                           component->GetReadyState(),
                           /*callback=*/base::DoNothing()) {}

MediaStreamTrackImpl::MediaStreamTrackImpl(ExecutionContext* context,
                                           MediaStreamComponent* component,
                                           base::OnceClosure callback)
    : MediaStreamTrackImpl(context,
                           component,
                           component->GetReadyState(),
                           std::move(callback)) {}

MediaStreamTrackImpl::MediaStreamTrackImpl(
    ExecutionContext* context,
    MediaStreamComponent* component,
    MediaStreamSource::ReadyState ready_state,
    base::OnceClosure callback,
    bool is_clone)
    : ready_state_(ready_state),
      component_(component),
      execution_context_(context) {
  DCHECK(component_);
  component_->AddSourceObserver(this);

  // If the source is already non-live at this point, the observer won't have
  // been called. Update the muted state manually.
  muted_ = ready_state_ == MediaStreamSource::kReadyStateMuted;

  SendLogMessage(String::Format("%s()", __func__));

  MediaStreamVideoTrack* const video_track =
      MediaStreamVideoTrack::From(Component());
  if (video_track && component_->Source() &&
      component_->GetSourceType() == MediaStreamSource::kTypeVideo) {
    image_capture_ = MakeGarbageCollected<ImageCapture>(
        context, this, video_track->pan_tilt_zoom_allowed(),
        std::move(callback));
  } else {
    if (execution_context_) {
      execution_context_->GetTaskRunner(TaskType::kInternalMedia)
          ->PostTask(FROM_HERE, std::move(callback));
    } else {
      std::move(callback).Run();
    }
  }

  // Note that both 'live' and 'muted' correspond to a 'live' ready state in the
  // web API.
  if (ready_state_ != MediaStreamSource::kReadyStateEnded) {
    EnsureFeatureHandleForScheduler();
  }
}

MediaStreamTrackImpl::~MediaStreamTrackImpl() = default;

String MediaStreamTrackImpl::kind() const {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(String, audio_kind, ("audio"));
  DEFINE_THREAD_SAFE_STATIC_LOCAL(String, video_kind, ("video"));

  switch (component_->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      return audio_kind;
    case MediaStreamSource::kTypeVideo:
      return video_kind;
  }

  NOTREACHED();
}

String MediaStreamTrackImpl::id() const {
  return component_->Id();
}

String MediaStreamTrackImpl::label() const {
  return component_->GetSourceName();
}

bool MediaStreamTrackImpl::enabled() const {
  return component_->Enabled();
}

void MediaStreamTrackImpl::setEnabled(bool enabled) {
  if (enabled == component_->Enabled()) {
    return;
  }

  component_->SetEnabled(enabled);

  SendLogMessage(
      String::Format("%s({enabled=%s})", __func__, enabled ? "true" : "false"));
}

bool MediaStreamTrackImpl::muted() const {
  return muted_;
}

String MediaStreamTrackImpl::ContentHint() const {
  return ContentHintToString(component_->ContentHint());
}

void MediaStreamTrackImpl::SetContentHint(const String& hint) {
  SendLogMessage(
      String::Format("%s({hint=%s})", __func__, hint.Utf8().c_str()));
  WebMediaStreamTrack::ContentHintType translated_hint =
      WebMediaStreamTrack::ContentHintType::kNone;
  switch (component_->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      if (hint == kContentHintStringNone) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kNone;
      } else if (hint == kContentHintStringAudioSpeech) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kAudioSpeech;
      } else if (hint == kContentHintStringAudioMusic) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kAudioMusic;
      } else {
        // TODO(pbos): Log warning?
        // Invalid values for audio are to be ignored (similar to invalid enum
        // values).
        return;
      }
      break;
    case MediaStreamSource::kTypeVideo:
      if (hint == kContentHintStringNone) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kNone;
      } else if (hint == kContentHintStringVideoMotion) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoMotion;
      } else if (hint == kContentHintStringVideoDetail) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoDetail;
      } else if (hint == kContentHintStringVideoText) {
        translated_hint = WebMediaStreamTrack::ContentHintType::kVideoText;
      } else {
        // TODO(pbos): Log warning?
        // Invalid values for video are to be ignored (similar to invalid enum
        // values).
        return;
      }
  }

  component_->SetContentHint(translated_hint);
}

V8MediaStreamTrackState MediaStreamTrackImpl::readyState() const {
  if (Ended()) {
    return V8MediaStreamTrackState(V8MediaStreamTrackState::Enum::kEnded);
  }
  return ReadyStateToV8TrackState(ready_state_);
}

void MediaStreamTrackImpl::setReadyState(
    MediaStreamSource::ReadyState ready_state) {
  if (ready_state_ != MediaStreamSource::kReadyStateEnded &&
      ready_state_ != ready_state) {
    ready_state_ = ready_state;
    SendLogMessage(String::Format("%s({ready_state=%s})", __func__,
                                  readyState().AsCStr()));

    // Observers may dispatch events which create and add new Observers;
    // take a snapshot so as to safely iterate.
    HeapVector<Member<MediaStreamTrack::Observer>> observers(observers_);
    for (auto observer : observers) {
      observer->TrackChangedState();
    }
  }
}

void MediaStreamTrackImpl::stopTrack(ExecutionContext* execution_context) {
  SendLogMessage(String::Format("%s()", __func__));
  if (Ended()) {
    return;
  }

  if (auto* track = Component()->GetPlatformTrack()) {
    // Synchronously disable the platform track to prevent media from flowing,
    // even if the stopTrack() below is completed asynchronously.
    // See https://crbug.com/1320312.
    track->SetEnabled(false);
  }

  setReadyState(MediaStreamSource::kReadyStateEnded);
  feature_handle_for_scheduler_.reset();
  feature_handle_for_scheduler_on_live_media_stream_track_.reset();
  UserMediaClient* user_media_client =
      UserMediaClient::From(To<LocalDOMWindow>(execution_context));
  if (user_media_client) {
    user_media_client->StopTrack(Component());
  }

  PropagateTrackEnded();
}

MediaStreamTrack* MediaStreamTrackImpl::clone(
    ExecutionContext* execution_context) {
  SendLogMessage(String::Format("%s()", __func__));

  // Instantiate the clone.
  MediaStreamTrackImpl* cloned_track =
      MakeGarbageCollected<MediaStreamTrackImpl>(
          execution_context, Component()->Clone(), ready_state_,
          base::DoNothing(), /*is_clone=*/true);

  // Copy state.
  CloneInternal(cloned_track);

  return cloned_track;
}

MediaTrackCapabilities* MediaStreamTrackImpl::getCapabilities() const {
  MediaTrackCapabilities* capabilities = MediaTrackCapabilities::Create();
  if (image_capture_) {
    image_capture_->GetMediaTrackCapabilities(capabilities);
  }
  auto platform_capabilities = component_->Source()->GetCapabilities();

  capabilities->setDeviceId(platform_capabilities.device_id);
  if (!platform_capabilities.group_id.IsNull()) {
    capabilities->setGroupId(platform_capabilities.group_id);
  }

  if (component_->GetSourceType() == MediaStreamSource::kTypeAudio) {
    Vector<bool> echo_cancellation, auto_gain_control, noise_suppression,
        voice_isolation;
    for (bool value : platform_capabilities.echo_cancellation) {
      echo_cancellation.push_back(value);
    }
    capabilities->setEchoCancellation(echo_cancellation);
    for (bool value : platform_capabilities.auto_gain_control) {
      auto_gain_control.push_back(value);
    }
    capabilities->setAutoGainControl(auto_gain_control);
    for (bool value : platform_capabilities.noise_suppression) {
      noise_suppression.push_back(value);
    }
    capabilities->setNoiseSuppression(noise_suppression);
    for (bool value : platform_capabilities.voice_isolation) {
      voice_isolation.push_back(value);
    }
    capabilities->setVoiceIsolation(voice_isolation);
    // Sample size.
    if (platform_capabilities.sample_size.size() == 2) {
      LongRange* sample_size = LongRange::Create();
      sample_size->setMin(platform_capabilities.sample_size[0]);
      sample_size->setMax(platform_capabilities.sample_size[1]);
      capabilities->setSampleSize(sample_size);
    }
    // Channel count.
    if (platform_capabilities.channel_count.size() == 2) {
      LongRange* channel_count = LongRange::Create();
      channel_count->setMin(platform_capabilities.channel_count[0]);
      channel_count->setMax(platform_capabilities.channel_count[1]);
      capabilities->setChannelCount(channel_count);
    }
    // Sample rate.
    if (platform_capabilities.sample_rate.size() == 2) {
      LongRange* sample_rate = LongRange::Create();
      sample_rate->setMin(platform_capabilities.sample_rate[0]);
      sample_rate->setMax(platform_capabilities.sample_rate[1]);
      capabilities->setSampleRate(sample_rate);
    }
    // Latency.
    if (platform_capabilities.latency.size() == 2) {
      DoubleRange* latency = DoubleRange::Create();
      latency->setMin(platform_capabilities.latency[0]);
      latency->setMax(platform_capabilities.latency[1]);
      capabilities->setLatency(latency);
    }
  }

  if (component_->GetSourceType() == MediaStreamSource::kTypeVideo) {
    if (platform_capabilities.width.size() == 2) {
      LongRange* width = LongRange::Create();
      width->setMin(platform_capabilities.width[0]);
      width->setMax(platform_capabilities.width[1]);
      capabilities->setWidth(width);
    }
    if (platform_capabilities.height.size() == 2) {
      LongRange* height = LongRange::Create();
      height->setMin(platform_capabilities.height[0]);
      height->setMax(platform_capabilities.height[1]);
      capabilities->setHeight(height);
    }
    if (platform_capabilities.aspect_ratio.size() == 2) {
      DoubleRange* aspect_ratio = DoubleRange::Create();
      aspect_ratio->setMin(platform_capabilities.aspect_ratio[0]);
      aspect_ratio->setMax(platform_capabilities.aspect_ratio[1]);
      capabilities->setAspectRatio(aspect_ratio);
    }
    if (platform_capabilities.frame_rate.size() == 2) {
      DoubleRange* frame_rate = DoubleRange::Create();
      frame_rate->setMin(platform_capabilities.frame_rate[0]);
      frame_rate->setMax(platform_capabilities.frame_rate[1]);
      capabilities->setFrameRate(frame_rate);
    }
    Vector<String> facing_mode;
    switch (platform_capabilities.facing_mode) {
      case MediaStreamTrackPlatform::FacingMode::kUser:
        facing_mode.push_back("user");
        break;
      case MediaStreamTrackPlatform::FacingMode::kEnvironment:
        facing_mode.push_back("environment");
        break;
      case MediaStreamTrackPlatform::FacingMode::kLeft:
        facing_mode.push_back("left");
        break;
      case MediaStreamTrackPlatform::FacingMode::kRight:
        facing_mode.push_back("right");
        break;
      default:
        break;
    }
    capabilities->setFacingMode(facing_mode);
    capabilities->setResizeMode({WebMediaStreamTrack::kResizeModeNone,
                                 WebMediaStreamTrack::kResizeModeRescale});
    const std::optional<const MediaStreamDevice> source_device = device();
    if (source_device && source_device->display_media_info) {
      capabilities->setDisplaySurface(GetDisplaySurfaceString(
          source_device->display_media_info->display_surface));
    }
  }
  return capabilities;
}

MediaTrackConstraints* MediaStreamTrackImpl::getConstraints() const {
  if (image_capture_) {
    if (auto* image_capture_constraints =
            image_capture_->GetMediaTrackConstraints()) {
      return image_capture_constraints;
    }
  }

  return media_constraints_impl::ConvertConstraints(constraints_);
}

MediaTrackSettings* MediaStreamTrackImpl::getSettings() const {
  MediaTrackSettings* settings = MediaTrackSettings::Create();
  MediaStreamTrackPlatform::Settings platform_settings;
  component_->GetSettings(platform_settings);
  if (platform_settings.HasFrameRate()) {
    settings->setFrameRate(platform_settings.frame_rate);
  }
  if (platform_settings.HasWidth()) {
    settings->setWidth(platform_settings.width);
  }
  if (platform_settings.HasHeight()) {
    settings->setHeight(platform_settings.height);
  }
  if (platform_settings.HasAspectRatio()) {
    settings->setAspectRatio(platform_settings.aspect_ratio);
  }
  settings->setDeviceId(platform_settings.device_id);
  if (!platform_settings.group_id.IsNull()) {
    settings->setGroupId(platform_settings.group_id);
  }
  if (platform_settings.HasFacingMode()) {
    switch (platform_settings.facing_mode) {
      case MediaStreamTrackPlatform::FacingMode::kUser:
        settings->setFacingMode("user");
        break;
      case MediaStreamTrackPlatform::FacingMode::kEnvironment:
        settings->setFacingMode("environment");
        break;
      case MediaStreamTrackPlatform::FacingMode::kLeft:
        settings->setFacingMode("left");
        break;
      case MediaStreamTrackPlatform::FacingMode::kRight:
        settings->setFacingMode("right");
        break;
      default:
        // None, or unknown facing mode. Ignore.
        break;
    }
  }
  if (!platform_settings.resize_mode.IsNull()) {
    settings->setResizeMode(platform_settings.resize_mode);
  }

  if (platform_settings.echo_cancellation) {
    settings->setEchoCancellation(*platform_settings.echo_cancellation);
  }
  if (platform_settings.auto_gain_control) {
    settings->setAutoGainControl(*platform_settings.auto_gain_control);
  }
  if (platform_settings.noise_supression) {
    settings->setNoiseSuppression(*platform_settings.noise_supression);
  }
  if (platform_settings.voice_isolation) {
    settings->setVoiceIsolation(*platform_settings.voice_isolation);
  }
  if (platform_settings.HasSampleRate()) {
    settings->setSampleRate(platform_settings.sample_rate);
  }
  if (platform_settings.HasSampleSize()) {
    settings->setSampleSize(platform_settings.sample_size);
  }
  if (platform_settings.HasChannelCount()) {
    settings->setChannelCount(platform_settings.channel_count);
  }
  if (platform_settings.HasLatency()) {
    settings->setLatency(platform_settings.latency);
  }

  if (image_capture_) {
    image_capture_->GetMediaTrackSettings(settings);
  }

  if (platform_settings.display_surface) {
    settings->setDisplaySurface(
        GetDisplaySurfaceString(platform_settings.display_surface.value()));
  }
  if (platform_settings.logical_surface) {
    settings->setLogicalSurface(platform_settings.logical_surface.value());
  }
  if (platform_settings.cursor) {
    WTF::String value;
    switch (platform_settings.cursor.value()) {
      case media::mojom::CursorCaptureType::NEVER:
        value = "never";
        break;
      case media::mojom::CursorCaptureType::ALWAYS:
        value = "always";
        break;
      case media::mojom::CursorCaptureType::MOTION:
        value = "motion";
        break;
    }
    settings->setCursor(value);
  }

  if (suppress_local_audio_playback_setting_.has_value()) {
    settings->setSuppressLocalAudioPlayback(
        suppress_local_audio_playback_setting_.value());
  }

  return settings;
}

V8UnionMediaStreamTrackAudioStatsOrMediaStreamTrackVideoStats*
MediaStreamTrackImpl::stats() {
  switch (component_->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      if (!stats_) {
        stats_ = MakeGarbageCollected<
            V8UnionMediaStreamTrackAudioStatsOrMediaStreamTrackVideoStats>(
            MakeGarbageCollected<MediaStreamTrackAudioStats>(this));
      }
      return stats_.Get();
    case MediaStreamSource::kTypeVideo: {
      std::optional<const MediaStreamDevice> source_device = device();
      if (!source_device.has_value() ||
          source_device->type == mojom::blink::MediaStreamType::NO_SERVICE) {
        // If the track is backed by a getUserMedia or getDisplayMedia device,
        // a service will be set. Other sources may have default initialized
        // devices, but these have type NO_SERVICE.
        // TODO(https://github.com/w3c/mediacapture-extensions/issues/102): This
        // is an unnecessary restriction - if the W3C Working Group can be
        // convinced otherwise, simply don't throw this exception. Some sources
        // may need to wire up the OnFrameDropped callback in order for
        // totalFrames to include "early" frame drops, but this is probably N/A
        // for most (if not all) sources that are not backed by a gUM/gDM device
        // since non-device sources aren't real-time in which case FPS can be
        // reduced by not generating the frame in the first place, so then there
        // is no need to drop it.
        return nullptr;
      }
      if (!stats_) {
        stats_ = MakeGarbageCollected<
            V8UnionMediaStreamTrackAudioStatsOrMediaStreamTrackVideoStats>(
            MakeGarbageCollected<MediaStreamTrackVideoStats>(this));
      }
      return stats_.Get();
    }
  }
}

MediaStreamTrackPlatform::VideoFrameStats
MediaStreamTrackImpl::GetVideoFrameStats() const {
  CHECK_EQ(component_->GetSourceType(), MediaStreamSource::kTypeVideo);
  return component_->GetPlatformTrack()->GetVideoFrameStats();
}

void MediaStreamTrackImpl::TransferAudioFrameStatsTo(
    MediaStreamTrackPlatform::AudioFrameStats& destination) {
  CHECK_EQ(component_->GetSourceType(), MediaStreamSource::kTypeAudio);
  component_->GetPlatformTrack()->TransferAudioFrameStatsTo(destination);
}

CaptureHandle* MediaStreamTrackImpl::getCaptureHandle() const {
  MediaStreamTrackPlatform::CaptureHandle platform_capture_handle =
      component_->GetCaptureHandle();

  if (platform_capture_handle.IsEmpty()) {
    return nullptr;
  }

  auto* capture_handle = CaptureHandle::Create();
  if (platform_capture_handle.origin) {
    capture_handle->setOrigin(platform_capture_handle.origin);
  }
  capture_handle->setHandle(platform_capture_handle.handle);

  return capture_handle;
}

ScriptPromise<IDLUndefined> MediaStreamTrackImpl::applyConstraints(
    ScriptState* script_state,
    const MediaTrackConstraints* constraints) {
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  applyConstraints(resolver, constraints);
  return promise;
}

void MediaStreamTrackImpl::SetInitialConstraints(
    const MediaConstraints& constraints) {
  SetConstraintsInternal(constraints, /*initial_values=*/true);
}

void MediaStreamTrackImpl::SetConstraints(const MediaConstraints& constraints) {
  SetConstraintsInternal(constraints, /*initial_values=*/false);
}

// TODO(crbug.com/1381959): Remove this helper.
void MediaStreamTrackImpl::SetConstraintsInternal(
    const MediaConstraints& constraints,
    bool initial_values) {
  constraints_ = constraints;

  if (!initial_values) {
    return;
  }

  DCHECK(!suppress_local_audio_playback_setting_.has_value());
  if (!constraints_.IsNull() &&
      constraints_.Basic().suppress_local_audio_playback.HasIdeal()) {
    suppress_local_audio_playback_setting_ =
        constraints_.Basic().suppress_local_audio_playback.Ideal();
  }
}

void MediaStreamTrackImpl::applyConstraints(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    const MediaTrackConstraints* constraints) {
  String error_message;
  ExecutionContext* execution_context =
      ExecutionContext::From(resolver->GetScriptState());
  MediaConstraints web_constraints = media_constraints_impl::Create(
      execution_context, constraints, error_message);
  if (web_constraints.IsNull()) {
    resolver->Reject(
        OverconstrainedError::Create(String(), "Cannot parse constraints"));
    return;
  }

  if (image_capture_) {
    // TODO(guidou): Integrate image-capture constraints processing with the
    // spec-compliant main implementation. http://crbug.com/708723
    if (ConstraintsHaveImageAndNonImageCapture(constraints)) {
      resolver->Reject(OverconstrainedError::Create(
          String(),
          "Mixing ImageCapture and non-ImageCapture "
          "constraints is not currently supported"));
      return;
    }

    if (ConstraintsAreEmpty(constraints)) {
      // Do not resolve the promise. Instead, just clear the ImageCapture
      // constraints and then pass the empty constraints to the general
      // implementation.
      image_capture_->ClearMediaTrackConstraints();
    } else if (ConstraintsHaveImageCapture(constraints)) {
      image_capture_->SetMediaTrackConstraints(resolver, constraints);
      return;
    }
  }

  // Resolve empty constraints here instead of relying on UserMediaClient
  // because the empty constraints have already been applied to image capture
  // and the promise must resolve. Empty constraints do not change any setting,
  // so resolving here is OK.
  if (ConstraintsAreEmpty(co
```