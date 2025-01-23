Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. I need to analyze the code and identify its purpose, highlighting any connections to web technologies (JavaScript, HTML, CSS). I should also look for logical reasoning sections and provide example inputs and outputs. Furthermore, I need to identify common user/programming errors related to this code and explain how a user's actions can lead to this code being executed, providing debugging clues. Finally, I need to summarize the identified functionalities.

Here's a breakdown of the code's main components and their probable roles:

1. **Headers and Namespaces:** The code includes several headers related to media, WebRTC, and Blink's media stream implementation, indicating its role in handling audio constraints for media streams. The `blink` namespace confirms this.

2. **Type Aliases:**  Aliases like `ConstraintSet`, `BooleanConstraint`, etc., simplify the code and improve readability.

3. **Helper Functions:** Functions like `GetSampleSize()` suggest basic utility operations related to audio processing.

4. **`Score` struct:** This struct seems crucial for ranking different audio configurations based on their fitness against user constraints. It considers fitness, default device status, echo cancellation mode, and processing priority.

5. **`SourceInfo` class:** This class likely holds information about active audio sources, including their type (processed/unprocessed), properties, channel count, sample rate, and latency.

6. **Constraint Containers:** The code defines several container classes (`BooleanContainer`, `StringContainer`, `NumericRangeSetContainer`, `NumericDiscreteSetContainer`, `EchoCancellationContainer`, `AutoGainControlContainer`, `VoiceIsolationContainer`). These classes are responsible for managing and applying constraints to individual audio properties (like echo cancellation, gain control, sample rate, etc.). They track allowed values and determine the best settings based on user constraints.

7. **`ProcessingBasedContainer` class:** This class appears to group together the individual constraint containers to represent the supported audio settings for different types of audio sources (processed with APM, processed without APM, and unprocessed).

8. **Constraint Application Logic:** The `ApplyConstraintSet` methods within the container classes implement the core logic of filtering allowed values based on user-provided constraints.

9. **Setting Selection Logic:** The `SelectSettingsAndScore` methods determine the best audio settings based on the applied constraints and calculate a score representing the fitness of the selected settings.

**Connections to Web Technologies:**

* **JavaScript:** This code directly supports the `getUserMedia()` API in JavaScript. JavaScript code uses `getUserMedia()` to request access to the user's microphone, specifying audio constraints. This C++ code is responsible for processing those constraints and selecting the best matching audio device and settings.
* **HTML:**  While not directly interacting, HTML elements like `<audio>` or `<video>` tags are used to consume the media streams generated after the constraints are processed by this code.
* **CSS:** CSS has no direct functional relationship with this specific C++ code, which deals with backend audio processing logic.

**Logical Reasoning and Examples:**

Consider the `EchoCancellationContainer`.

* **Input (Hypothetical):**
    * `allowed_values`: `{ EchoCancellationType::kEchoCancellationAec3, EchoCancellationType::kEchoCancellationSystem }` (The device supports AEC3 and system echo cancellation)
    * `constraint`: `{ ideal: true }` (The user ideally wants echo cancellation enabled)
* **Output:**
    * `selected_ec_mode`: `EchoCancellationType::kEchoCancellationAec3` (AEC3 is preferred if available and the user wants echo cancellation)
    * `score`: A `Score` object with a high fitness value.

* **Input (Hypothetical):**
    * `allowed_values`: `{ EchoCancellationType::kEchoCancellationDisabled }` (The device only supports disabling echo cancellation)
    * `constraint`: `{ ideal: true }` (The user ideally wants echo cancellation enabled)
* **Output:**
    * `selected_ec_mode`: `EchoCancellationType::kEchoCancellationDisabled` (The only option available, even though it doesn't match the ideal)
    * `score`: A `Score` object with a lower fitness value.

**Common User/Programming Errors:**

* **Conflicting Constraints:**  A user might specify constraints that are impossible to satisfy simultaneously. For example, requesting a sample rate that the device doesn't support while also requiring a specific number of channels that only that unsupported sample rate provides. The `ApplyConstraintSet` methods aim to detect these conflicts.
* **Requesting Unsupported Features:** A user might request features that the browser or the audio device doesn't support (e.g., a specific echo cancellation algorithm).

**User Operations Leading to This Code:**

1. **User opens a website:** A website wants to access the user's microphone.
2. **Website calls `navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true } })`:** The JavaScript code on the website requests microphone access with a constraint for echo cancellation.
3. **Browser processes the `getUserMedia` call:** The browser's rendering engine (Blink in this case) receives the request and starts processing the audio constraints.
4. **Blink's media stream implementation:** The code in `media_stream_constraints_util_audio.cc` is invoked to evaluate the provided audio constraints against the available audio input devices and their capabilities. It will iterate through devices, apply constraints using the container classes, and score the different possible configurations to select the best match.

**Summary of Functionality (Part 1):**

This code file (`media_stream_constraints_util_audio.cc`) in the Chromium Blink engine is responsible for **processing and evaluating audio constraints provided by web applications through the `getUserMedia()` API**. It defines a system for:

* **Representing audio constraints:** Using classes like `BooleanConstraint`, `StringConstraint`, and numeric range constraints.
* **Managing allowed values for audio properties:** Through container classes like `BooleanContainer`, `StringContainer`, `NumericRangeSetContainer`, and `EchoCancellationContainer`.
* **Applying constraints to filter available audio settings:** Using the `ApplyConstraintSet` methods.
* **Scoring different audio configurations based on how well they match the constraints:** Using the `Score` struct and the `SelectSettingsAndScore` methods.
* **Handling different types of audio sources:** Including processed (with and without APM) and unprocessed sources, managed by the `ProcessingBasedContainer`.

In essence, it's a crucial component in the browser's audio capture pipeline, ensuring that when a website requests microphone access, the browser can intelligently select the best audio input device and settings that satisfy the user's (or website's) requirements as closely as possible.

```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_audio.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <tuple>
#include <utility>

#include "base/strings/string_number_conversions.h"
#include "build/build_config.h"
#include "media/audio/audio_features.h"
#include "media/base/audio_parameters.h"
#include "media/base/limits.h"
#include "media/base/media_switches.h"
#include "media/webrtc/constants.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/mediastream/media_stream_controls.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using blink::AudioCaptureSettings;
using blink::AudioProcessingProperties;
using ConstraintSet = MediaTrackConstraintSetPlatform;
using BooleanConstraint = blink::BooleanConstraint;
using EchoCancellationType = AudioProcessingProperties::EchoCancellationType;
using VoiceIsolationType = AudioProcessingProperties::VoiceIsolationType;
using ProcessingType = AudioCaptureSettings::ProcessingType;
using StringConstraint = blink::StringConstraint;

template <class T>
using NumericRangeSet = blink::media_constraints::NumericRangeSet<T>;

namespace {

using BoolSet = blink::media_constraints::DiscreteSet<bool>;
using DoubleRangeSet = blink::media_constraints::NumericRangeSet<double>;
using EchoCancellationTypeSet =
    blink::media_constraints::DiscreteSet<EchoCancellationType>;
using VoiceIsolationTypeSet =
    blink::media_constraints::DiscreteSet<VoiceIsolationType>;
using IntRangeSet = blink::media_constraints::NumericRangeSet<int>;
using StringSet = blink::media_constraints::DiscreteSet<std::string>;

// The presence of a MediaStreamAudioSource object indicates whether the source
// in question is currently in use, or not. This convenience enum helps
// identifying whether a source is available and, if so, whether it has audio
// processing enabled or disabled.
enum class SourceType { kNone, kUnprocessed, kNoApmProcessed, kApmProcessed };

// The sample size is set to 16 due to the Signed-16 format representation.
int32_t GetSampleSize() {
  return media::SampleFormatToBitsPerChannel(media::kSampleFormatS16);
}

// This class encapsulates two values that together build up the score of each
// processed candidate.
// - Fitness, similarly defined by the W3C specification
//   (https://w3c.github.io/mediacapture-main/#dfn-fitness-distance);
// - Distance from the default device ID;
// - The priority associated to the echo cancellation type selected.
// - The priority of the associated processing-based container.
//
// Differently from the definition in the W3C specification, the present
// algorithm maximizes the score.
struct Score {
 public:
  enum class EcModeScore : int {
    kDisabled = 1,
    kSystem = 2,
    kAec3 = 3,
  };

  explicit Score(double fitness,
                 bool is_default_device_id = false,
                 EcModeScore ec_mode_score = EcModeScore::kDisabled,
                 int processing_priority = -1) {
    score = std::make_tuple(fitness, is_default_device_id, ec_mode_score,
                            processing_priority);
  }

  bool operator>(const Score& other) const { return score > other.score; }

  Score& operator+=(const Score& other) {
    std::get<0>(score) += std::get<0>(other.score);
    std::get<1>(score) |= std::get<1>(other.score);
    // Among the priorities in the two score objects, we store the highest one.
    std::get<2>(score) = std::max(std::get<2>(score), std::get<2>(other.score));
    // Select the highest processing priority.
    std::get<3>(score) = std::max(std::get<3>(score), std::get<3>(other.score));
    return *this;
  }

  Score& operator+=(double fitness) {
    std::get<0>(score) += fitness;
    return *this;
  }

  Score& operator+=(bool is_default_device) {
    std::get<1>(score) |= is_default_device;
    return *this;
  }

  void set_ec_mode_score(EcModeScore ec_mode_score) {
    std::get<2>(score) = ec_mode_score;
  }

  void set_processing_priority(int priority) { std::get<3>(score) = priority; }

  std::tuple<double, bool, EcModeScore, int> score;
};

// This class represents the output of DeviceContainer::InfoFromSource and is
// used to obtain information regarding an active source, if that exists.
class SourceInfo {
 public:
  SourceInfo(SourceType type,
             const AudioProcessingProperties& properties,
             std::optional<int> channels,
             std::optional<int> sample_rate,
             std::optional<double> latency)
      : type_(type),
        properties_(properties),
        channels_(std::move(channels)),
        sample_rate_(std::move(sample_rate)),
        latency_(latency) {}

  bool HasActiveSource() { return type_ != SourceType::kNone; }

  SourceType type() { return type_; }
  const AudioProcessingProperties& properties() { return properties_; }
  const std::optional<int>& channels() { return channels_; }
  const std::optional<int>& sample_rate() { return sample_rate_; }
  const std::optional<double>& latency() { return latency_; }

 private:
  const SourceType type_;
  const AudioProcessingProperties properties_;
  const std::optional<int> channels_;
  const std::optional<int> sample_rate_;
  const std::optional<double> latency_;
};

// Container for each independent boolean constrainable property.
class BooleanContainer {
 public:
  explicit BooleanContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const BooleanConstraint& constraint) {
    allowed_values_ = allowed_values_.Intersection(
        blink::media_constraints::BoolSetFromConstraint(constraint));
    return allowed_values_.IsEmpty() ? constraint.GetName() : nullptr;
  }

  std::tuple<double, bool> SelectSettingsAndScore(
      const BooleanConstraint& constraint,
      bool default_setting) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal() && allowed_values_.Contains(constraint.Ideal()))
      return std::make_tuple(1.0, constraint.Ideal());

    if (allowed_values_.is_universal())
      return std::make_tuple(0.0, default_setting);

    DCHECK_EQ(allowed_values_.elements().size(), 1U);
    return std::make_tuple(0.0, allowed_values_.FirstElement());
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  BoolSet allowed_values_;
};

// Container for each independent string constrainable property.
class StringContainer {
 public:
  explicit StringContainer(StringSet allowed_values = StringSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const StringConstraint& constraint) {
    allowed_values_ = allowed_values_.Intersection(
        blink::media_constraints::StringSetFromConstraint(constraint));
    return allowed_values_.IsEmpty() ? constraint.GetName() : nullptr;
  }

  // Selects the best value from the nonempty |allowed_values_|, subject to
  // |constraint_set.*constraint_member_| and determines the associated fitness.
  // The first selection criteria is inclusion in the constraint's ideal value,
  // followed by equality to |default_value|. There is always a single best
  // value.
  std::tuple<double, std::string> SelectSettingsAndScore(
      const StringConstraint& constraint,
      std::string default_setting) const {
    DCHECK(!IsEmpty());
    if (constraint.HasIdeal()) {
      for (const WTF::String& ideal_candidate : constraint.Ideal()) {
        std::string candidate = ideal_candidate.Utf8();
        if (allowed_values_.Contains(candidate))
          return std::make_tuple(1.0, candidate);
      }
    }

    std::string setting = allowed_values_.Contains(default_setting)
                              ? default_setting
                              : allowed_values_.FirstElement();

    return std::make_tuple(0.0, setting);
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  StringSet allowed_values_;
};

// Container for each independent numeric constrainable property.
template <class T, class C>
class NumericRangeSetContainer {
 public:
  explicit NumericRangeSetContainer(
      NumericRangeSet<T> allowed_values = NumericRangeSet<T>())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const C& constraint) {
    auto constraint_set = NumericRangeSet<T>::FromConstraint(constraint);
    allowed_values_ = allowed_values_.Intersection(constraint_set);
    return IsEmpty() ? constraint.GetName() : nullptr;
  }

  // This function will return a fitness with the associated setting.
  // The setting will be the ideal value, if such value is provided and
  // admitted, or the closest value to it.
  // When no ideal is available and |default_setting| is provided, the setting
  // will be |default_setting| or the closest value to it.
  // When |default_setting| is **not** provided, the setting will be a value iff
  // |allowed_values_| contains only a single value, otherwise std::nullopt is
  // returned to signal that it was not possible to make a decision.
  std::tuple<double, std::optional<T>> SelectSettingsAndScore(
      const C& constraint,
      const std::optional<T>& default_setting = std::nullopt) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal()) {
      if (allowed_values_.Contains(constraint.Ideal()))
        return std::make_tuple(1.0, constraint.Ideal());

      T value = SelectClosestValueTo(constraint.Ideal());
      double fitness = 1.0 - blink::NumericConstraintFitnessDistance(
                                 value, constraint.Ideal());
      return std::make_tuple(fitness, value);
    }

    if (default_setting) {
      if (allowed_values_.Contains(*default_setting))
        return std::make_tuple(0.0, *default_setting);

      // If the default value provided is not contained, select the value
      // closest to it.
      return std::make_tuple(0.0, SelectClosestValueTo(*default_setting));
    }

    if (allowed_values_.Min() && allowed_values_.Max() &&
        *allowed_values_.Min() == *allowed_values_.Max()) {
      return std::make_tuple(0.0, *allowed_values_.Min());
    }

    return std::make_tuple(0.0, std::nullopt);
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  T SelectClosestValueTo(T value) const {
    DCHECK(allowed_values_.Min() || allowed_values_.Max());
    DCHECK(!allowed_values_.Contains(value));
    return allowed_values_.Min() && value < *allowed_values_.Min()
               ? *allowed_values_.Min()
               : *allowed_values_.Max();
  }

  NumericRangeSet<T> allowed_values_;
};

using IntegerRangeContainer =
    NumericRangeSetContainer<int, blink::LongConstraint>;
using DoubleRangeContainer =
    NumericRangeSetContainer<double, blink::DoubleConstraint>;

// Container for numeric constrainable properties that allow a fixed set of
// values.
template <class T, class C>
class NumericDiscreteSetContainer {
 public:
  // It's the responsibility of the caller to ensure there are no repeated
  // values.
  explicit NumericDiscreteSetContainer(Vector<T> allowed_values)
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const C& constraint) {
    auto constraint_set = NumericRangeSet<T>::FromConstraint(constraint);
    for (auto it = allowed_values_.begin(); it != allowed_values_.end();) {
      if (!constraint_set.Contains(*it))
        it = allowed_values_.erase(it);
      else
        ++it;
    }

    return IsEmpty() ? constraint.GetName() : nullptr;
  }

  // This function will return a fitness with the associated setting. The
  // setting will be the ideal value, if ideal is provided and
  // allowed, or the closest value to it (using fitness distance).
  // When no ideal is available and |default_setting| is provided, the setting
  // will be |default_setting| or the closest value to it (using fitness
  // distance).
  // When |default_setting| is **not** provided, the setting will be a value iff
  // |allowed_values_| contains only a single value, otherwise std::nullopt is
  // returned to signal that it was not possible to make a decision.
  std::tuple<double, std::optional<T>> SelectSettingsAndScore(
      const C& constraint,
      const std::optional<T>& default_setting = std::nullopt) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal()) {
      if (allowed_values_.Contains(constraint.Ideal()))
        return std::make_tuple(1.0, constraint.Ideal());

      T value = SelectClosestValueTo(constraint.Ideal());
      double fitness =
          1.0 - NumericConstraintFitnessDistance(value, constraint.Ideal());
      return std::make_tuple(fitness, value);
    }

    if (default_setting) {
      if (allowed_values_.Contains(*default_setting))
        return std::make_tuple(0.0, *default_setting);

      // If the default value provided is not contained, select the value
      // closest to it.
      return std::make_tuple(0.0, SelectClosestValueTo(*default_setting));
    }

    if (allowed_values_.size() == 1) {
      return std::make_tuple(0.0, *allowed_values_.begin());
    }

    return std::make_tuple(0.0, std::nullopt);
  }

  bool IsEmpty() const { return allowed_values_.empty(); }

 private:
  T SelectClosestValueTo(T target) const {
    DCHECK(!IsEmpty());
    T best_value = *allowed_values_.begin();
    double best_distance = HUGE_VAL;
    for (auto value : allowed_values_) {
      double distance = blink::NumericConstraintFitnessDistance(value, target);
      if (distance < best_distance) {
        best_value = value;
        best_distance = distance;
      }
    }
    return best_value;
  }

  Vector<T> allowed_values_;
};

using IntegerDiscreteContainer =
    NumericDiscreteSetContainer<int, blink::LongConstraint>;

// Container to manage the properties related to echo cancellation:
// echoCancellation and echoCancellationType.
class EchoCancellationContainer {
 public:
  // Default constructor intended to temporarily create an empty object.
  EchoCancellationContainer()
      : ec_mode_allowed_values_(EchoCancellationTypeSet::EmptySet()),
        device_parameters_(media::AudioParameters::UnavailableDeviceParams()),
        is_device_capture_(true) {}

  EchoCancellationContainer(Vector<EchoCancellationType> allowed_values,
                            bool has_active_source,
                            bool is_device_capture,
                            media::AudioParameters device_parameters,
                            AudioProcessingProperties properties,
                            bool is_reconfiguration_allowed)
      : ec_mode_allowed_values_(
            EchoCancellationTypeSet(std::move(allowed_values))),
        device_parameters_(device_parameters),
        is_device_capture_(is_device_capture) {
    if (!has_active_source)
      return;

    // If HW echo cancellation is used, reconfiguration is not always supported
    // and only the current values are allowed. Otherwise, allow all possible
    // values for echo cancellation.
    // TODO(crbug.com/1481032): Consider extending to other platforms. It is not
    // known at the moment what OSes support this behavior.
    const bool is_aec_reconfiguration_supported =
#if BUILDFLAG(IS_CHROMEOS)
        // ChromeOS is currently the only platform where we have confirmed
        // support for simultaneous streams with and without hardware AEC on the
        // same device.
        true;
#else
        // Allowing it when the system echo cancellation is enforced via flag,
        // for evaluation purposes.
        media::IsSystemEchoCancellationEnforced() ||
        properties.echo_cancellation_type !=
            EchoCancellationType::kEchoCancellationSystem;
#endif
    if (is_reconfiguration_allowed && is_aec_reconfiguration_supported) {
      return;
    }

    ec_mode_allowed_values_ =
        EchoCancellationTypeSet({properties.echo_cancellation_type});
    ec_allowed_values_ =
        BoolSet({properties.echo_cancellation_type !=
                 EchoCancellationType::kEchoCancellationDisabled});
  }

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    // Convert the constraints into discrete sets.
    BoolSet ec_set = blink::media_constraints::BoolSetFromConstraint(
        constraint_set.echo_cancellation);

    // Apply echoCancellation constraint.
    ec_allowed_values_ = ec_allowed_values_.Intersection(ec_set);
    if (ec_allowed_values_.IsEmpty())
      return constraint_set.echo_cancellation.GetName();
    // Translate the boolean values into EC modes.
    ec_mode_allowed_values_ = ec_mode_allowed_values_.Intersection(
        ToEchoCancellationTypes(ec_allowed_values_));

    // Finally, if this container is empty, fail due to contradiction of the
    // resulting allowed values for goog_ec, ec, and/or ec_type.
    return IsEmpty() ? constraint_set.echo_cancellation.GetName() : nullptr;
  }

  std::tuple<Score, EchoCancellationType> SelectSettingsAndScore(
      const ConstraintSet& constraint_set) const {
    EchoCancellationType selected_ec_mode = SelectBestEcMode(constraint_set);
    double fitness =
        Fitness(selected_ec_mode, constraint_set.echo_cancellation);
    Score score(fitness);
    score.set_ec_mode_score(GetEcModeScore(selected_ec_mode));
    return std::make_tuple(score, selected_ec_mode);
  }

  bool IsEmpty() const { return ec_mode_allowed_values_.IsEmpty(); }

  // Audio-processing properties are disabled by default for content capture,
  // or if the |echo_cancellation| constraint is false.
  void UpdateDefaultValues(
      const BooleanConstraint& echo_cancellation_constraint,
      AudioProcessingProperties* properties) const {
    bool default_audio_processing_value =
        GetDefaultValueForAudioProperties(echo_cancellation_constraint);

    properties->auto_gain_control &= default_audio_processing_value;

    properties->noise_suppression &= default_audio_processing_value;
    properties->voice_isolation = VoiceIsolationType::kVoiceIsolationDefault;
  }

  bool GetDefaultValueForAudioProperties(
      const BooleanConstraint& ec_constraint) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec_constraint.HasIdeal() &&
        ec_allowed_values_.Contains(ec_constraint.Ideal()))
      return is_device_capture_ && ec_constraint.Ideal();

    if (ec_allowed_values_.Contains(true))
      return is_device_capture_;

    return false;
  }

 private:
  static Score::EcModeScore GetEcModeScore(EchoCancellationType mode) {
    switch (mode) {
      case EchoCancellationType::kEchoCancellationDisabled:
        return Score::EcModeScore::kDisabled;
      case EchoCancellationType::kEchoCancellationSystem:
        return Score::EcModeScore::kSystem;
      case EchoCancellationType::kEchoCancellationAec3:
        return Score::EcModeScore::kAec3;
    }
  }

  static EchoCancellationTypeSet ToEchoCancellationTypes(const BoolSet ec_set) {
    Vector<EchoCancellationType> types;

    if (ec_set.Contains(false))
      types.push_back(EchoCancellationType::kEchoCancellationDisabled);

    if (ec_set.Contains(true)) {
      types.push_back(EchoCancellationType::kEchoCancellationAec3);
      types.push_back(EchoCancellationType::kEchoCancellationSystem);
    }

    return EchoCancellationTypeSet(std::move(types));
  }

  EchoCancellationType SelectBestEcMode(
      const ConstraintSet& constraint_set) const {
    DCHECK(!IsEmpty());
    DCHECK(!ec_mode_allowed_values_.is_universal());

    // Try to use an ideal candidate, if supplied.
    bool is_ec_preferred =
        ShouldUseEchoCancellation(constraint_set.echo_cancellation);

    if (!is_ec_preferred &&
        ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationDisabled)) {
      return EchoCancellationType::kEchoCancellationDisabled;
    }

    // If no ideal could be selected and the set contains only one value, pick
    // that one.
    if (ec_mode_allowed_values_.elements().size() == 1)
      return ec_mode_allowed_values_.FirstElement();

    // If no type has been selected, choose system if the device has the
    // ECHO_CANCELLER flag set. Never automatically enable an experimental
    // system echo canceller.
    if (device_parameters_.IsValid() &&
        ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationSystem) &&
        (device_parameters_.effects() &
         media::AudioParameters::ECHO_CANCELLER)) {
      return EchoCancellationType::kEchoCancellationSystem;
    }

    // At this point we have at least two elements, hence the only two options
    // from which to select are either AEC3 or System, where AEC3 has higher
    // priority.
    if (ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationAec3)) {
      return EchoCancellationType::kEchoCancellationAec3;
    }

    DCHECK(ec_mode_allowed_values_.Contains(
        EchoCancellationType::kEchoCancellationDisabled));
    return EchoCancellationType::kEchoCancellationDisabled;
  }

  // This function computes the fitness score of the given |ec_mode|. The
  // fitness is determined by the ideal values of |ec_constraint|. If |ec_mode|
  // satisfies the constraint, the fitness score results in a value of 1, and 0
  // otherwise. If no ideal value is specified, the fitness is 1.
  double Fitness(const EchoCancellationType& ec_mode,
                 const BooleanConstraint& ec_constraint) const {
    return ec_constraint.HasIdeal()
               ? ((ec_constraint.Ideal() &&
                   ec_mode !=
                       EchoCancellationType::kEchoCancellationDisabled) ||
                  (!ec_constraint.Ideal() &&
                   ec_mode == EchoCancellationType::kEchoCancellationDisabled))
               : 1.0;
  }

  bool EchoCancellationModeContains(bool ec) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec) {
      return ec_mode_allowed_values_.Contains(
                 EchoCancellationType::kEchoCancellationAec3) ||
             ec_mode_allowed_values_.Contains(
                 EchoCancellationType::kEchoCancellationSystem);
    }

    return ec_mode_allowed_values_.Contains(
        EchoCancellationType::kEchoCancellationDisabled);
  }

  bool ShouldUseEchoCancellation(const BooleanConstraint& ec_constraint) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec_constraint.HasIdeal() &&
        EchoCancellationModeContains(ec_constraint.Ideal()))
      return ec_constraint.Ideal();

    // Echo cancellation is enabled by default for device capture and disabled
    // by default for content capture.
    if (EchoCancellationModeContains(true) &&
        EchoCancellationModeContains(false))
      return is_device_capture_;

    return EchoCancellationModeContains(true);
  }

  BoolSet ec_allowed_values_;
  EchoCancellationTypeSet ec_mode_allowed_values_;
  media::AudioParameters device_parameters_;
  bool is_device_capture_;
};

class AutoGainControlContainer {
 public:
  explicit AutoGainControlContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    BoolSet agc_set = blink::media_constraints::BoolSetFromConstraint(
        constraint_set.auto_gain_control);
    // Apply autoGainControl/googAutoGainControl constraint.
    allowed_values_ = allowed_values_.Intersection(agc_set);
    return IsEmpty() ? constraint_set.auto_gain_control.GetName() : nullptr;
  }

  std::tuple<double, bool> SelectSettingsAndScore(
      const ConstraintSet& constraint_set,
      bool default_setting) const {
    BooleanConstraint agc_constraint = constraint_set.auto_gain_control;

    if (agc_constraint.HasIdeal()) {
      bool agc_ideal = agc_constraint.Ideal();
      if (allowed_values_.Contains(agc_ideal))
        return std::make_tuple(1.0, agc_ideal);
    }

    if (allowed_values_.is_universal()) {
      return std::make_tuple(0.0, default_setting);
    }

    return std::make_tuple(0.0, allowed_values_.FirstElement());
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  BoolSet allowed_values_;
};

class VoiceIsolationContainer {
 public:
  // Default constructor intended to temporarily create an empty object.
  VoiceIsolationContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    BoolSet voice_isolation_set =
        blink::media_constraints::BoolSetFromConstraint(
            constraint_set.voice_isolation);
    // Apply voice isolation constraint.
    allowed_values_ = allowed_values_.Intersection(voice_isolation_set);
    return
### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_audio.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_audio.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <tuple>
#include <utility>

#include "base/strings/string_number_conversions.h"
#include "build/build_config.h"
#include "media/audio/audio_features.h"
#include "media/base/audio_parameters.h"
#include "media/base/limits.h"
#include "media/base/media_switches.h"
#include "media/webrtc/constants.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/mediastream/media_stream_controls.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using blink::AudioCaptureSettings;
using blink::AudioProcessingProperties;
using ConstraintSet = MediaTrackConstraintSetPlatform;
using BooleanConstraint = blink::BooleanConstraint;
using EchoCancellationType = AudioProcessingProperties::EchoCancellationType;
using VoiceIsolationType = AudioProcessingProperties::VoiceIsolationType;
using ProcessingType = AudioCaptureSettings::ProcessingType;
using StringConstraint = blink::StringConstraint;

template <class T>
using NumericRangeSet = blink::media_constraints::NumericRangeSet<T>;

namespace {

using BoolSet = blink::media_constraints::DiscreteSet<bool>;
using DoubleRangeSet = blink::media_constraints::NumericRangeSet<double>;
using EchoCancellationTypeSet =
    blink::media_constraints::DiscreteSet<EchoCancellationType>;
using VoiceIsolationTypeSet =
    blink::media_constraints::DiscreteSet<VoiceIsolationType>;
using IntRangeSet = blink::media_constraints::NumericRangeSet<int>;
using StringSet = blink::media_constraints::DiscreteSet<std::string>;

// The presence of a MediaStreamAudioSource object indicates whether the source
// in question is currently in use, or not. This convenience enum helps
// identifying whether a source is available and, if so, whether it has audio
// processing enabled or disabled.
enum class SourceType { kNone, kUnprocessed, kNoApmProcessed, kApmProcessed };

// The sample size is set to 16 due to the Signed-16 format representation.
int32_t GetSampleSize() {
  return media::SampleFormatToBitsPerChannel(media::kSampleFormatS16);
}

// This class encapsulates two values that together build up the score of each
// processed candidate.
// - Fitness, similarly defined by the W3C specification
//   (https://w3c.github.io/mediacapture-main/#dfn-fitness-distance);
// - Distance from the default device ID;
// - The priority associated to the echo cancellation type selected.
// - The priority of the associated processing-based container.
//
// Differently from the definition in the W3C specification, the present
// algorithm maximizes the score.
struct Score {
 public:
  enum class EcModeScore : int {
    kDisabled = 1,
    kSystem = 2,
    kAec3 = 3,
  };

  explicit Score(double fitness,
                 bool is_default_device_id = false,
                 EcModeScore ec_mode_score = EcModeScore::kDisabled,
                 int processing_priority = -1) {
    score = std::make_tuple(fitness, is_default_device_id, ec_mode_score,
                            processing_priority);
  }

  bool operator>(const Score& other) const { return score > other.score; }

  Score& operator+=(const Score& other) {
    std::get<0>(score) += std::get<0>(other.score);
    std::get<1>(score) |= std::get<1>(other.score);
    // Among the priorities in the two score objects, we store the highest one.
    std::get<2>(score) = std::max(std::get<2>(score), std::get<2>(other.score));
    // Select the highest processing priority.
    std::get<3>(score) = std::max(std::get<3>(score), std::get<3>(other.score));
    return *this;
  }

  Score& operator+=(double fitness) {
    std::get<0>(score) += fitness;
    return *this;
  }

  Score& operator+=(bool is_default_device) {
    std::get<1>(score) |= is_default_device;
    return *this;
  }

  void set_ec_mode_score(EcModeScore ec_mode_score) {
    std::get<2>(score) = ec_mode_score;
  }

  void set_processing_priority(int priority) { std::get<3>(score) = priority; }

  std::tuple<double, bool, EcModeScore, int> score;
};

// This class represents the output of DeviceContainer::InfoFromSource and is
// used to obtain information regarding an active source, if that exists.
class SourceInfo {
 public:
  SourceInfo(SourceType type,
             const AudioProcessingProperties& properties,
             std::optional<int> channels,
             std::optional<int> sample_rate,
             std::optional<double> latency)
      : type_(type),
        properties_(properties),
        channels_(std::move(channels)),
        sample_rate_(std::move(sample_rate)),
        latency_(latency) {}

  bool HasActiveSource() { return type_ != SourceType::kNone; }

  SourceType type() { return type_; }
  const AudioProcessingProperties& properties() { return properties_; }
  const std::optional<int>& channels() { return channels_; }
  const std::optional<int>& sample_rate() { return sample_rate_; }
  const std::optional<double>& latency() { return latency_; }

 private:
  const SourceType type_;
  const AudioProcessingProperties properties_;
  const std::optional<int> channels_;
  const std::optional<int> sample_rate_;
  const std::optional<double> latency_;
};

// Container for each independent boolean constrainable property.
class BooleanContainer {
 public:
  explicit BooleanContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const BooleanConstraint& constraint) {
    allowed_values_ = allowed_values_.Intersection(
        blink::media_constraints::BoolSetFromConstraint(constraint));
    return allowed_values_.IsEmpty() ? constraint.GetName() : nullptr;
  }

  std::tuple<double, bool> SelectSettingsAndScore(
      const BooleanConstraint& constraint,
      bool default_setting) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal() && allowed_values_.Contains(constraint.Ideal()))
      return std::make_tuple(1.0, constraint.Ideal());

    if (allowed_values_.is_universal())
      return std::make_tuple(0.0, default_setting);

    DCHECK_EQ(allowed_values_.elements().size(), 1U);
    return std::make_tuple(0.0, allowed_values_.FirstElement());
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  BoolSet allowed_values_;
};

// Container for each independent string constrainable property.
class StringContainer {
 public:
  explicit StringContainer(StringSet allowed_values = StringSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const StringConstraint& constraint) {
    allowed_values_ = allowed_values_.Intersection(
        blink::media_constraints::StringSetFromConstraint(constraint));
    return allowed_values_.IsEmpty() ? constraint.GetName() : nullptr;
  }

  // Selects the best value from the nonempty |allowed_values_|, subject to
  // |constraint_set.*constraint_member_| and determines the associated fitness.
  // The first selection criteria is inclusion in the constraint's ideal value,
  // followed by equality to |default_value|. There is always a single best
  // value.
  std::tuple<double, std::string> SelectSettingsAndScore(
      const StringConstraint& constraint,
      std::string default_setting) const {
    DCHECK(!IsEmpty());
    if (constraint.HasIdeal()) {
      for (const WTF::String& ideal_candidate : constraint.Ideal()) {
        std::string candidate = ideal_candidate.Utf8();
        if (allowed_values_.Contains(candidate))
          return std::make_tuple(1.0, candidate);
      }
    }

    std::string setting = allowed_values_.Contains(default_setting)
                              ? default_setting
                              : allowed_values_.FirstElement();

    return std::make_tuple(0.0, setting);
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  StringSet allowed_values_;
};

// Container for each independent numeric constrainable property.
template <class T, class C>
class NumericRangeSetContainer {
 public:
  explicit NumericRangeSetContainer(
      NumericRangeSet<T> allowed_values = NumericRangeSet<T>())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const C& constraint) {
    auto constraint_set = NumericRangeSet<T>::FromConstraint(constraint);
    allowed_values_ = allowed_values_.Intersection(constraint_set);
    return IsEmpty() ? constraint.GetName() : nullptr;
  }

  // This function will return a fitness with the associated setting.
  // The setting will be the ideal value, if such value is provided and
  // admitted, or the closest value to it.
  // When no ideal is available and |default_setting| is provided, the setting
  // will be |default_setting| or the closest value to it.
  // When |default_setting| is **not** provided, the setting will be a value iff
  // |allowed_values_| contains only a single value, otherwise std::nullopt is
  // returned to signal that it was not possible to make a decision.
  std::tuple<double, std::optional<T>> SelectSettingsAndScore(
      const C& constraint,
      const std::optional<T>& default_setting = std::nullopt) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal()) {
      if (allowed_values_.Contains(constraint.Ideal()))
        return std::make_tuple(1.0, constraint.Ideal());

      T value = SelectClosestValueTo(constraint.Ideal());
      double fitness = 1.0 - blink::NumericConstraintFitnessDistance(
                                 value, constraint.Ideal());
      return std::make_tuple(fitness, value);
    }

    if (default_setting) {
      if (allowed_values_.Contains(*default_setting))
        return std::make_tuple(0.0, *default_setting);

      // If the default value provided is not contained, select the value
      // closest to it.
      return std::make_tuple(0.0, SelectClosestValueTo(*default_setting));
    }

    if (allowed_values_.Min() && allowed_values_.Max() &&
        *allowed_values_.Min() == *allowed_values_.Max()) {
      return std::make_tuple(0.0, *allowed_values_.Min());
    }

    return std::make_tuple(0.0, std::nullopt);
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  T SelectClosestValueTo(T value) const {
    DCHECK(allowed_values_.Min() || allowed_values_.Max());
    DCHECK(!allowed_values_.Contains(value));
    return allowed_values_.Min() && value < *allowed_values_.Min()
               ? *allowed_values_.Min()
               : *allowed_values_.Max();
  }

  NumericRangeSet<T> allowed_values_;
};

using IntegerRangeContainer =
    NumericRangeSetContainer<int, blink::LongConstraint>;
using DoubleRangeContainer =
    NumericRangeSetContainer<double, blink::DoubleConstraint>;

// Container for numeric constrainable properties that allow a fixed set of
// values.
template <class T, class C>
class NumericDiscreteSetContainer {
 public:
  // It's the responsibility of the caller to ensure there are no repeated
  // values.
  explicit NumericDiscreteSetContainer(Vector<T> allowed_values)
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const C& constraint) {
    auto constraint_set = NumericRangeSet<T>::FromConstraint(constraint);
    for (auto it = allowed_values_.begin(); it != allowed_values_.end();) {
      if (!constraint_set.Contains(*it))
        it = allowed_values_.erase(it);
      else
        ++it;
    }

    return IsEmpty() ? constraint.GetName() : nullptr;
  }

  // This function will return a fitness with the associated setting. The
  // setting will be the ideal value, if ideal is provided and
  // allowed, or the closest value to it (using fitness distance).
  // When no ideal is available and |default_setting| is provided, the setting
  // will be |default_setting| or the closest value to it (using fitness
  // distance).
  // When |default_setting| is **not** provided, the setting will be a value iff
  // |allowed_values_| contains only a single value, otherwise std::nullopt is
  // returned to signal that it was not possible to make a decision.
  std::tuple<double, std::optional<T>> SelectSettingsAndScore(
      const C& constraint,
      const std::optional<T>& default_setting = std::nullopt) const {
    DCHECK(!IsEmpty());

    if (constraint.HasIdeal()) {
      if (allowed_values_.Contains(constraint.Ideal()))
        return std::make_tuple(1.0, constraint.Ideal());

      T value = SelectClosestValueTo(constraint.Ideal());
      double fitness =
          1.0 - NumericConstraintFitnessDistance(value, constraint.Ideal());
      return std::make_tuple(fitness, value);
    }

    if (default_setting) {
      if (allowed_values_.Contains(*default_setting))
        return std::make_tuple(0.0, *default_setting);

      // If the default value provided is not contained, select the value
      // closest to it.
      return std::make_tuple(0.0, SelectClosestValueTo(*default_setting));
    }

    if (allowed_values_.size() == 1) {
      return std::make_tuple(0.0, *allowed_values_.begin());
    }

    return std::make_tuple(0.0, std::nullopt);
  }

  bool IsEmpty() const { return allowed_values_.empty(); }

 private:
  T SelectClosestValueTo(T target) const {
    DCHECK(!IsEmpty());
    T best_value = *allowed_values_.begin();
    double best_distance = HUGE_VAL;
    for (auto value : allowed_values_) {
      double distance = blink::NumericConstraintFitnessDistance(value, target);
      if (distance < best_distance) {
        best_value = value;
        best_distance = distance;
      }
    }
    return best_value;
  }

  Vector<T> allowed_values_;
};

using IntegerDiscreteContainer =
    NumericDiscreteSetContainer<int, blink::LongConstraint>;

// Container to manage the properties related to echo cancellation:
// echoCancellation and echoCancellationType.
class EchoCancellationContainer {
 public:
  // Default constructor intended to temporarily create an empty object.
  EchoCancellationContainer()
      : ec_mode_allowed_values_(EchoCancellationTypeSet::EmptySet()),
        device_parameters_(media::AudioParameters::UnavailableDeviceParams()),
        is_device_capture_(true) {}

  EchoCancellationContainer(Vector<EchoCancellationType> allowed_values,
                            bool has_active_source,
                            bool is_device_capture,
                            media::AudioParameters device_parameters,
                            AudioProcessingProperties properties,
                            bool is_reconfiguration_allowed)
      : ec_mode_allowed_values_(
            EchoCancellationTypeSet(std::move(allowed_values))),
        device_parameters_(device_parameters),
        is_device_capture_(is_device_capture) {
    if (!has_active_source)
      return;

    // If HW echo cancellation is used, reconfiguration is not always supported
    // and only the current values are allowed. Otherwise, allow all possible
    // values for echo cancellation.
    // TODO(crbug.com/1481032): Consider extending to other platforms. It is not
    // known at the moment what OSes support this behavior.
    const bool is_aec_reconfiguration_supported =
#if BUILDFLAG(IS_CHROMEOS)
        // ChromeOS is currently the only platform where we have confirmed
        // support for simultaneous streams with and without hardware AEC on the
        // same device.
        true;
#else
        // Allowing it when the system echo cancellation is enforced via flag,
        // for evaluation purposes.
        media::IsSystemEchoCancellationEnforced() ||
        properties.echo_cancellation_type !=
            EchoCancellationType::kEchoCancellationSystem;
#endif
    if (is_reconfiguration_allowed && is_aec_reconfiguration_supported) {
      return;
    }

    ec_mode_allowed_values_ =
        EchoCancellationTypeSet({properties.echo_cancellation_type});
    ec_allowed_values_ =
        BoolSet({properties.echo_cancellation_type !=
                 EchoCancellationType::kEchoCancellationDisabled});
  }

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    // Convert the constraints into discrete sets.
    BoolSet ec_set = blink::media_constraints::BoolSetFromConstraint(
        constraint_set.echo_cancellation);

    // Apply echoCancellation constraint.
    ec_allowed_values_ = ec_allowed_values_.Intersection(ec_set);
    if (ec_allowed_values_.IsEmpty())
      return constraint_set.echo_cancellation.GetName();
    // Translate the boolean values into EC modes.
    ec_mode_allowed_values_ = ec_mode_allowed_values_.Intersection(
        ToEchoCancellationTypes(ec_allowed_values_));

    // Finally, if this container is empty, fail due to contradiction of the
    // resulting allowed values for goog_ec, ec, and/or ec_type.
    return IsEmpty() ? constraint_set.echo_cancellation.GetName() : nullptr;
  }

  std::tuple<Score, EchoCancellationType> SelectSettingsAndScore(
      const ConstraintSet& constraint_set) const {
    EchoCancellationType selected_ec_mode = SelectBestEcMode(constraint_set);
    double fitness =
        Fitness(selected_ec_mode, constraint_set.echo_cancellation);
    Score score(fitness);
    score.set_ec_mode_score(GetEcModeScore(selected_ec_mode));
    return std::make_tuple(score, selected_ec_mode);
  }

  bool IsEmpty() const { return ec_mode_allowed_values_.IsEmpty(); }

  // Audio-processing properties are disabled by default for content capture,
  // or if the |echo_cancellation| constraint is false.
  void UpdateDefaultValues(
      const BooleanConstraint& echo_cancellation_constraint,
      AudioProcessingProperties* properties) const {
    bool default_audio_processing_value =
        GetDefaultValueForAudioProperties(echo_cancellation_constraint);

    properties->auto_gain_control &= default_audio_processing_value;

    properties->noise_suppression &= default_audio_processing_value;
    properties->voice_isolation = VoiceIsolationType::kVoiceIsolationDefault;
  }

  bool GetDefaultValueForAudioProperties(
      const BooleanConstraint& ec_constraint) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec_constraint.HasIdeal() &&
        ec_allowed_values_.Contains(ec_constraint.Ideal()))
      return is_device_capture_ && ec_constraint.Ideal();

    if (ec_allowed_values_.Contains(true))
      return is_device_capture_;

    return false;
  }

 private:
  static Score::EcModeScore GetEcModeScore(EchoCancellationType mode) {
    switch (mode) {
      case EchoCancellationType::kEchoCancellationDisabled:
        return Score::EcModeScore::kDisabled;
      case EchoCancellationType::kEchoCancellationSystem:
        return Score::EcModeScore::kSystem;
      case EchoCancellationType::kEchoCancellationAec3:
        return Score::EcModeScore::kAec3;
    }
  }

  static EchoCancellationTypeSet ToEchoCancellationTypes(const BoolSet ec_set) {
    Vector<EchoCancellationType> types;

    if (ec_set.Contains(false))
      types.push_back(EchoCancellationType::kEchoCancellationDisabled);

    if (ec_set.Contains(true)) {
      types.push_back(EchoCancellationType::kEchoCancellationAec3);
      types.push_back(EchoCancellationType::kEchoCancellationSystem);
    }

    return EchoCancellationTypeSet(std::move(types));
  }

  EchoCancellationType SelectBestEcMode(
      const ConstraintSet& constraint_set) const {
    DCHECK(!IsEmpty());
    DCHECK(!ec_mode_allowed_values_.is_universal());

    // Try to use an ideal candidate, if supplied.
    bool is_ec_preferred =
        ShouldUseEchoCancellation(constraint_set.echo_cancellation);

    if (!is_ec_preferred &&
        ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationDisabled)) {
      return EchoCancellationType::kEchoCancellationDisabled;
    }

    // If no ideal could be selected and the set contains only one value, pick
    // that one.
    if (ec_mode_allowed_values_.elements().size() == 1)
      return ec_mode_allowed_values_.FirstElement();

    // If no type has been selected, choose system if the device has the
    // ECHO_CANCELLER flag set. Never automatically enable an experimental
    // system echo canceller.
    if (device_parameters_.IsValid() &&
        ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationSystem) &&
        (device_parameters_.effects() &
         media::AudioParameters::ECHO_CANCELLER)) {
      return EchoCancellationType::kEchoCancellationSystem;
    }

    // At this point we have at least two elements, hence the only two options
    // from which to select are either AEC3 or System, where AEC3 has higher
    // priority.
    if (ec_mode_allowed_values_.Contains(
            EchoCancellationType::kEchoCancellationAec3)) {
      return EchoCancellationType::kEchoCancellationAec3;
    }

    DCHECK(ec_mode_allowed_values_.Contains(
        EchoCancellationType::kEchoCancellationDisabled));
    return EchoCancellationType::kEchoCancellationDisabled;
  }

  // This function computes the fitness score of the given |ec_mode|. The
  // fitness is determined by the ideal values of |ec_constraint|. If |ec_mode|
  // satisfies the constraint, the fitness score results in a value of 1, and 0
  // otherwise. If no ideal value is specified, the fitness is 1.
  double Fitness(const EchoCancellationType& ec_mode,
                 const BooleanConstraint& ec_constraint) const {
    return ec_constraint.HasIdeal()
               ? ((ec_constraint.Ideal() &&
                   ec_mode !=
                       EchoCancellationType::kEchoCancellationDisabled) ||
                  (!ec_constraint.Ideal() &&
                   ec_mode == EchoCancellationType::kEchoCancellationDisabled))
               : 1.0;
  }

  bool EchoCancellationModeContains(bool ec) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec) {
      return ec_mode_allowed_values_.Contains(
                 EchoCancellationType::kEchoCancellationAec3) ||
             ec_mode_allowed_values_.Contains(
                 EchoCancellationType::kEchoCancellationSystem);
    }

    return ec_mode_allowed_values_.Contains(
        EchoCancellationType::kEchoCancellationDisabled);
  }

  bool ShouldUseEchoCancellation(const BooleanConstraint& ec_constraint) const {
    DCHECK(!ec_mode_allowed_values_.is_universal());

    if (ec_constraint.HasIdeal() &&
        EchoCancellationModeContains(ec_constraint.Ideal()))
      return ec_constraint.Ideal();

    // Echo cancellation is enabled by default for device capture and disabled
    // by default for content capture.
    if (EchoCancellationModeContains(true) &&
        EchoCancellationModeContains(false))
      return is_device_capture_;

    return EchoCancellationModeContains(true);
  }

  BoolSet ec_allowed_values_;
  EchoCancellationTypeSet ec_mode_allowed_values_;
  media::AudioParameters device_parameters_;
  bool is_device_capture_;
};

class AutoGainControlContainer {
 public:
  explicit AutoGainControlContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    BoolSet agc_set = blink::media_constraints::BoolSetFromConstraint(
        constraint_set.auto_gain_control);
    // Apply autoGainControl/googAutoGainControl constraint.
    allowed_values_ = allowed_values_.Intersection(agc_set);
    return IsEmpty() ? constraint_set.auto_gain_control.GetName() : nullptr;
  }

  std::tuple<double, bool> SelectSettingsAndScore(
      const ConstraintSet& constraint_set,
      bool default_setting) const {
    BooleanConstraint agc_constraint = constraint_set.auto_gain_control;

    if (agc_constraint.HasIdeal()) {
      bool agc_ideal = agc_constraint.Ideal();
      if (allowed_values_.Contains(agc_ideal))
        return std::make_tuple(1.0, agc_ideal);
    }

    if (allowed_values_.is_universal()) {
      return std::make_tuple(0.0, default_setting);
    }

    return std::make_tuple(0.0, allowed_values_.FirstElement());
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  BoolSet allowed_values_;
};

class VoiceIsolationContainer {
 public:
  // Default constructor intended to temporarily create an empty object.
  VoiceIsolationContainer(BoolSet allowed_values = BoolSet())
      : allowed_values_(std::move(allowed_values)) {}

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    BoolSet voice_isolation_set =
        blink::media_constraints::BoolSetFromConstraint(
            constraint_set.voice_isolation);
    // Apply voice isolation constraint.
    allowed_values_ = allowed_values_.Intersection(voice_isolation_set);
    return IsEmpty() ? constraint_set.voice_isolation.GetName() : nullptr;
  }

  std::tuple<double, VoiceIsolationType> SelectSettingsAndScore(
      const ConstraintSet& constraint_set,
      VoiceIsolationType default_setting) const {
    BooleanConstraint voice_isolation_constraint =
        constraint_set.voice_isolation;

    if (voice_isolation_constraint.HasIdeal()) {
      VoiceIsolationType voice_isolation_type_ideal =
          voice_isolation_constraint.Ideal()
              ? VoiceIsolationType::kVoiceIsolationEnabled
              : VoiceIsolationType::kVoiceIsolationDisabled;

      return std::make_tuple(1.0, voice_isolation_type_ideal);
    }

    if (allowed_values_.is_universal()) {
      return std::make_tuple(0.0, default_setting);
    }

    VoiceIsolationType voice_isolation_first =
        allowed_values_.FirstElement()
            ? VoiceIsolationType::kVoiceIsolationEnabled
            : VoiceIsolationType::kVoiceIsolationDisabled;

    return std::make_tuple(0.0, voice_isolation_first);
  }

  bool IsEmpty() const { return allowed_values_.IsEmpty(); }

 private:
  BoolSet allowed_values_;
};

Vector<int> GetApmSupportedChannels(
    const media::AudioParameters& device_params) {
  Vector<int> result;
  // APM always supports mono output;
  result.push_back(1);
  const int channels = device_params.channels();
  if (channels > 1)
    result.push_back(channels);
  return result;
}

// This container represents the supported audio settings for a given type of
// audio source. In practice, there are three types of sources: processed using
// APM, processed without APM, and unprocessed. Processing using APM has two
// flavors: one for the systems where audio processing is done in the renderer,
// another for the systems where audio processing is done in the audio service.
class ProcessingBasedContainer {
 public:
  // Creates an instance of ProcessingBasedContainer for the WebRTC processed
  // source type. The source type allows (a) any type of echo cancellation,
  // though the system echo cancellation type depends on the availability of the
  // related |parameters.effects()|, and (b) any combination of processing
  // properties settings.
  static ProcessingBasedContainer CreateApmProcessedContainer(
      const SourceInfo& source_info,
      mojom::blink::MediaStreamType stream_type,
      bool is_device_capture,
      const media::AudioParameters& device_parameters,
      bool is_reconfiguration_allowed) {
    return ProcessingBasedContainer(
        ProcessingType::kApmProcessed,
        {EchoCancellationType::kEchoCancellationAec3,
         EchoCancellationType::kEchoCancellationDisabled},
        BoolSet(),                               /* auto_gain_control_set */
        BoolSet(),                               /* goog_audio_mirroring_set */
        BoolSet(),                               /* noise_suppression_set */
        BoolSet(),                               /* voice_isolation_set */
        IntRangeSet::FromValue(GetSampleSize()), /* sample_size_range */
        GetApmSupportedChannels(device_parameters), /* channels_set */
        IntRangeSet::FromValue(
            media::WebRtcAudioProcessingSampleRateHz()), /* sample_rate_range */
        source_info, is_device_capture, device_parameters,
        is_reconfiguration_allowed);
  }

  // Creates an instance of ProcessingBasedContainer for the processed source
  // type. The source type allows (a) either system echo cancellation, if
  // allowed by the |parameters.effects()|, or none, (b) enabled or disabled
  // audio mirroring, while (c) all other processing properties settings cannot
  // be enabled.
  static ProcessingBasedContainer CreateNoApmProcessedContainer(
      const SourceInfo& source_info,
      bool is_device_capture,
      const media::AudioParameters& device_parameters,
      bool is_reconfiguration_allowed) {
    return ProcessingBasedContainer(
        ProcessingType::kNoApmProcessed,
        {EchoCancellationType::kEchoCancellationDisabled},
        BoolSet({false}),                        /* auto_gain_control_set */
        BoolSet(),                               /* goog_audio_mirroring_set */
        BoolSet({false}),                        /* noise_suppression_set */
        BoolSet(),                               /* voice_isolation_set */
        IntRangeSet::FromValue(GetSampleSize()), /* sample_size_range */
        {device_parameters.channels()},          /* channels_set */
        IntRangeSet::FromValue(
            device_parameters.sample_rate()), /* sample_rate_range */
        source_info, is_device_capture, device_parameters,
        is_reconfiguration_allowed);
  }

  // Creates an instance of ProcessingBasedContainer for the unprocessed source
  // type. The source type allows (a) either system echo cancellation, if
  // allowed by the |parameters.effects()|, or none, while (c) all processing
  // properties settings cannot be enabled.
  static ProcessingBasedContainer CreateUnprocessedContainer(
      const SourceInfo& source_info,
      bool is_device_capture,
      const media::AudioParameters& device_parameters,
      bool is_reconfiguration_allowed) {
    return ProcessingBasedContainer(
        ProcessingType::kUnprocessed,
        {EchoCancellationType::kEchoCancellationDisabled},
        BoolSet({false}),                        /* auto_gain_control_set */
        BoolSet({false}),                        /* goog_audio_mirroring_set */
        BoolSet({false}),                        /* noise_suppression_set */
        BoolSet({false}),                        /* voice_isolation_set */
        IntRangeSet::FromValue(GetSampleSize()), /* sample_size_range */
        {device_parameters.channels()},          /* channels_set */
        IntRangeSet::FromValue(
            device_parameters.sample_rate()), /* sample_rate_range */
        source_info, is_device_capture, device_parameters,
        is_reconfiguration_allowed);
  }

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    const char* failed_constraint_name = nullptr;

    failed_constraint_name =
        echo_cancellation_container_.ApplyConstraintSet(constraint_set);
    if (failed_constraint_name)
      return failed_constraint_name;

    failed_constraint_name =
        auto_gain_control_container_.ApplyConstraintSet(constraint_set);
    if (failed_constraint_name)
      return failed_constraint_name;

    failed_constraint_name =
        voice_isolation_container_.ApplyConstraintSet(constraint_set);
    if (failed_constraint_name) {
      return failed_constraint_name;
    }

    failed_constraint_name =
        sample_size_container_.ApplyConstraintSet(constraint_set.sample_size);
    if (failed_constraint_name)
      return failed_constraint_name;

    failed_constraint_name =
        channels_container_.ApplyConstraintSet(constraint_set.channel_count);
    if (failed_constraint_name)
      return failed_constraint_name;

    failed_constraint_name =
        sample_rate_container_.ApplyConstraintSet(constraint_set.sample_rate);
    if (failed_constraint_name)
      return failed_constraint_name;

    fail
```