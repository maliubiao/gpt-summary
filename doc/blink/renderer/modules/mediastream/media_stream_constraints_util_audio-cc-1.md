Response:
The user wants me to summarize the functionality of the provided C++ code snippet from a Chromium file.
This code seems to be responsible for selecting the best audio capture settings based on constraints provided by a web application.

Here's a breakdown of the code's key components and their roles:

1. **`ProcessingBasedContainer`**: This class manages constraints and selection logic for audio processing related settings (like noise suppression, echo cancellation, etc.). It exists in different variations depending on the type of audio processing (unprocessed, processed by WebRTC, or otherwise processed).

2. **`DeviceContainer`**: This class represents a single audio capture device and holds constraints related to the device itself (device ID, group ID) and contains `ProcessingBasedContainer` instances for different processing options.

3. **`CandidatesContainer`**: This class manages a collection of `DeviceContainer` instances, representing all available audio capture devices. It applies constraints across all devices to narrow down the viable options.

4. **Constraint Application**: The code implements logic to apply both basic and advanced constraints specified in the `MediaConstraints` object.

5. **Settings Selection**: The code uses a scoring mechanism to select the best audio capture settings that satisfy the applied constraints.

6. **Interaction with Web APIs**: The code interacts with web APIs like `getUserMedia` by processing constraints originating from JavaScript and ultimately providing audio capture settings that will be used by the browser.

7. **Handling Different Audio Processing Scenarios**: The code explicitly handles different audio processing scenarios (e.g., unprocessed audio, WebRTC processed audio), suggesting it's designed to provide flexibility in how audio is captured and processed.

Now, I will formulate the summary based on this understanding.
```
ProcessingBasedContainer::ApplyConstraintSet
```
该函数的功能是**将一组音频约束应用到 `ProcessingBasedContainer` 所管理的各个音频处理属性容器中**。它会遍历不同的音频属性（例如延迟、布尔类型的属性如噪声抑制），并调用相应容器的 `ApplyConstraintSet` 方法来应用约束。如果任何一个约束应用失败，该函数会立即返回失败的约束名称。

**功能归纳:**

`ProcessingBasedContainer::ApplyConstraintSet` 函数的核心功能是**根据提供的约束条件，筛选出 `ProcessingBasedContainer` 中有效的音频处理配置**。它通过对其内部管理的各种音频属性容器施加约束来实现这一目标。

**与 JavaScript, HTML, CSS 的关系：**

这个函数直接参与了 WebRTC API `getUserMedia` 的实现过程。

*   **JavaScript:** 当 JavaScript 代码调用 `getUserMedia` 并指定了音频约束（例如，`{ audio: { echoCancellation: true } }`），这些约束会被传递到 Blink 引擎。
*   **HTML:** HTML 元素如 `<audio>` 和 `<video>` 标签可以通过 JavaScript 与 `getUserMedia` 获取的媒体流进行关联。
*   **CSS:** CSS 不直接与此代码交互，但可以影响包含音频或视频流的 HTML 元素的呈现。

**举例说明:**

假设 JavaScript 代码请求一个开启回声消除的音频流：

```javascript
navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true } })
  .then(function(stream) {
    // 使用 stream
  })
  .catch(function(err) {
    // 处理错误
  });
```

1. Blink 引擎接收到 `echoCancellation: true` 的约束。
2. `ProcessingBasedContainer::ApplyConstraintSet` 会被调用，`constraint_set.echoCancellation` 对应于 `echoCancellation: true`。
3. `echo_cancellation_container_.ApplyConstraintSet(constraint_set)` 会被执行，该容器会检查其允许的回声消除类型是否包含 `true`（即启用）。
4. 如果该容器支持回声消除，则约束应用成功，函数返回 `nullptr`。否则，返回指示回声消除约束失败的名称。

**逻辑推理（假设输入与输出）:**

**假设输入:**

*   `constraint_set.latency`: 一个包含延迟约束的对象，例如 `{ ideal: 0.1 }` (理想延迟为 0.1 秒)。
*   `constraint_set.noise_suppression`: 一个布尔约束对象，例如 `{ exact: true }` (必须启用噪声抑制)。
*   `kBooleanPropertyContainerInfoMap` 中包含 `noise_suppression` 的信息。
*   `boolean_containers_[对应的索引]` 是一个用于管理噪声抑制约束的 `BooleanContainer` 实例。

**输出:**

*   如果 `latency_container_` 可以满足理想延迟 0.1 秒的约束，并且 `boolean_containers_[对应的索引]` 支持且能够强制启用噪声抑制，则函数返回 `nullptr`。
*   如果 `latency_container_` 无法满足 0.1 秒的理想延迟，则返回类似 "latency" 的字符串。
*   如果 `boolean_containers_[对应的索引]` 不支持强制启用噪声抑制，则返回类似 "noiseSuppression" 的字符串。

**用户或编程常见的使用错误:**

*   **约束冲突:** 用户在 JavaScript 中设置了相互冲突的约束，例如既要求低延迟又要求高质量的音频处理，但某些处理会增加延迟。
*   **设备不支持的约束:** 用户要求的约束条件，例如特定的采样率或通道数，当前音频设备不支持。

**用户操作如何一步步到达这里（调试线索）:**

1. 用户打开一个网页，该网页包含使用 `getUserMedia` API 获取音频流的 JavaScript 代码。
2. JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: { /* 音频约束 */ } })`。
3. 浏览器接收到 `getUserMedia` 请求，并将音频约束传递给 Blink 引擎。
4. Blink 引擎的媒体流实现开始处理这些约束。
5. `blink/renderer/modules/mediastream/MediaStreamDevice.cc` 或类似的模块会创建或获取音频设备能力信息。
6. `blink/renderer/modules/mediastream/media_stream_constraints_util_audio.cc` 中的相关函数（例如 `SelectSettingsAudioCapture`）会被调用来根据约束选择合适的音频设置。
7. 在选择设置的过程中，会创建 `ProcessingBasedContainer` 实例来管理不同处理类型的约束。
8. 最终，`ProcessingBasedContainer::ApplyConstraintSet` 被调用，以应用来自 JavaScript 的具体音频约束。

总而言之，`ProcessingBasedContainer::ApplyConstraintSet` 就像一个过滤器，它根据用户在 JavaScript 中指定的音频约束，来判断当前支持的音频处理配置是否符合要求。如果所有约束都满足，则这个配置是可行的，否则需要告知用户哪些约束无法满足。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_audio.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ed_constraint_name =
        latency_container_.ApplyConstraintSet(constraint_set.latency);
    if (failed_constraint_name)
      return failed_constraint_name;

    for (auto& info : kBooleanPropertyContainerInfoMap) {
      failed_constraint_name =
          boolean_containers_[info.index].ApplyConstraintSet(
              constraint_set.*(info.constraint_member));
      if (failed_constraint_name)
        return failed_constraint_name;
    }
    return failed_constraint_name;
  }

  std::tuple<Score,
             AudioProcessingProperties,
             std::optional<int> /* requested_buffer_size */,
             int /* num_channels */>
  SelectSettingsAndScore(const ConstraintSet& constraint_set,
                         bool should_disable_hardware_noise_suppression,
                         const media::AudioParameters& parameters) const {
    DCHECK(!IsEmpty());

    Score score(0.0);
    double sub_score(0.0);

    std::tie(sub_score, std::ignore) =
        sample_size_container_.SelectSettingsAndScore(
            constraint_set.sample_size, GetSampleSize());
    score += sub_score;

    std::optional<int> num_channels;
    std::tie(sub_score, num_channels) =
        channels_container_.SelectSettingsAndScore(constraint_set.channel_count,
                                                   /*default_setting=*/1);
    DCHECK(num_channels);
    score += sub_score;

    std::optional<int> sample_size;
    std::tie(sub_score, sample_size) =
        sample_rate_container_.SelectSettingsAndScore(
            constraint_set.sample_rate);
    DCHECK(sample_size != std::nullopt);
    score += sub_score;

    std::optional<double> latency;
    std::tie(sub_score, latency) =
        latency_container_.SelectSettingsAndScore(constraint_set.latency);
    score += sub_score;

    // Only request an explicit change to the buffer size for the unprocessed
    // container, and only if it's based on a specific user constraint.
    std::optional<int> requested_buffer_size;
    if (processing_type_ == ProcessingType::kUnprocessed && latency &&
        !constraint_set.latency.IsUnconstrained()) {
      auto [min_buffer_size, max_buffer_size] =
          GetMinMaxBufferSizesForAudioParameters(parameters);
      requested_buffer_size = media::AudioLatency::GetExactBufferSize(
          base::Seconds(*latency), parameters.sample_rate(),
          parameters.frames_per_buffer(), min_buffer_size, max_buffer_size,
          max_buffer_size);
    }

    AudioProcessingProperties properties;
    Score ec_score(0.0);
    std::tie(ec_score, properties.echo_cancellation_type) =
        echo_cancellation_container_.SelectSettingsAndScore(constraint_set);
    score += ec_score;

    // Update the default settings for each audio-processing properties
    // according to |echo_cancellation| and whether the source considered is
    // device capture.
    echo_cancellation_container_.UpdateDefaultValues(
        constraint_set.echo_cancellation, &properties);

    std::tie(sub_score, properties.auto_gain_control) =
        auto_gain_control_container_.SelectSettingsAndScore(
            constraint_set, properties.auto_gain_control);
    score += sub_score;

    std::tie(sub_score, properties.voice_isolation) =
        voice_isolation_container_.SelectSettingsAndScore(
            constraint_set, properties.voice_isolation);
    score += sub_score;

    for (size_t i = 0; i < kNumBooleanContainerIds; ++i) {
      auto& info = kBooleanPropertyContainerInfoMap[i];
      std::tie(sub_score, properties.*(info.property_member)) =
          boolean_containers_[info.index].SelectSettingsAndScore(
              constraint_set.*(info.constraint_member),
              properties.*(info.property_member));
      score += sub_score;
    }

    score.set_processing_priority(
        GetProcessingPriority(constraint_set.echo_cancellation));
    return std::make_tuple(score, properties, requested_buffer_size,
                           *num_channels);
  }

  // The ProcessingBasedContainer is considered empty if at least one of the
  // containers owned by it is empty.
  bool IsEmpty() const {
    DCHECK(!boolean_containers_.empty());

    for (auto& container : boolean_containers_) {
      if (container.IsEmpty())
        return true;
    }
    return echo_cancellation_container_.IsEmpty() ||
           auto_gain_control_container_.IsEmpty() ||
           sample_size_container_.IsEmpty() || channels_container_.IsEmpty() ||
           sample_rate_container_.IsEmpty() || latency_container_.IsEmpty();
  }

  ProcessingType processing_type() const { return processing_type_; }

 private:
  enum BooleanContainerId {
    kGoogNoiseSuppression,
    kGoogHighpassFilter,
    kNumBooleanContainerIds
  };

  // This struct groups related fields or entries from
  // AudioProcessingProperties,
  // ProcessingBasedContainer::boolean_containers_, and
  // MediaTrackConstraintSetPlatform.
  struct BooleanPropertyContainerInfo {
    BooleanContainerId index;
    BooleanConstraint ConstraintSet::*constraint_member;
    bool AudioProcessingProperties::*property_member;
  };

  static constexpr BooleanPropertyContainerInfo
      kBooleanPropertyContainerInfoMap[] = {
          {kGoogNoiseSuppression, &ConstraintSet::noise_suppression,
           &AudioProcessingProperties::noise_suppression},
  };

  // Private constructor intended to instantiate different variants of this
  // class based on the initial values provided. The appropriate way to
  // instantiate this class is via the three factory methods provided.
  // System echo cancellation should not be explicitly included in
  // |echo_cancellation_type|. It is added automatically based on the value of
  // |device_parameters|.
  ProcessingBasedContainer(ProcessingType processing_type,
                           Vector<EchoCancellationType> echo_cancellation_types,
                           BoolSet auto_gain_control_set,
                           BoolSet goog_audio_mirroring_set,
                           BoolSet noise_suppression_set,
                           BoolSet voice_isolation_set,
                           IntRangeSet sample_size_range,
                           Vector<int> channels_set,
                           IntRangeSet sample_rate_range,
                           SourceInfo source_info,
                           bool is_device_capture,
                           media::AudioParameters device_parameters,
                           bool is_reconfiguration_allowed)
      : processing_type_(processing_type),
        sample_size_container_(sample_size_range),
        channels_container_(std::move(channels_set)),
        sample_rate_container_(sample_rate_range),
        latency_container_(
            GetAllowedLatency(processing_type, device_parameters)) {
    // If the parameters indicate that system echo cancellation is available, we
    // add such value in the allowed values for the EC type.
    if (device_parameters.effects() & media::AudioParameters::ECHO_CANCELLER) {
      echo_cancellation_types.push_back(
          EchoCancellationType::kEchoCancellationSystem);
    }
    echo_cancellation_container_ = EchoCancellationContainer(
        std::move(echo_cancellation_types), source_info.HasActiveSource(),
        is_device_capture, device_parameters, source_info.properties(),
        is_reconfiguration_allowed);

    auto_gain_control_container_ =
        AutoGainControlContainer(auto_gain_control_set);

    voice_isolation_container_ = VoiceIsolationContainer(voice_isolation_set);

    boolean_containers_[kGoogNoiseSuppression] =
        BooleanContainer(noise_suppression_set);

    // Allow the full set of supported values when the device is not open or
    // when the candidate settings would open the device using an unprocessed
    // source.
    if (!source_info.HasActiveSource() ||
        (is_reconfiguration_allowed &&
         processing_type_ == ProcessingType::kUnprocessed)) {
      return;
    }

    // If the device is already opened, restrict supported values for
    // non-reconfigurable settings to what is already configured. The rationale
    // for this is that opening multiple instances of the APM is costly.
    // TODO(crbug.com/1147928): Consider removing this restriction.
    auto_gain_control_container_ = AutoGainControlContainer(
        BoolSet({source_info.properties().auto_gain_control}));

    for (size_t i = 0; i < kNumBooleanContainerIds; ++i) {
      auto& info = kBooleanPropertyContainerInfoMap[i];
      boolean_containers_[info.index] = BooleanContainer(
          BoolSet({source_info.properties().*(info.property_member)}));
    }

    DCHECK(source_info.channels());
    channels_container_ = IntegerDiscreteContainer({*source_info.channels()});
    DCHECK(source_info.sample_rate() != std::nullopt);
    sample_rate_container_ = IntegerRangeContainer(
        IntRangeSet::FromValue(*source_info.sample_rate()));
    DCHECK(source_info.latency() != std::nullopt);
    latency_container_ =
        DoubleRangeContainer(DoubleRangeSet::FromValue(*source_info.latency()));
  }

  // The allowed latency is expressed in a range latencies in seconds.
  static const DoubleRangeSet GetAllowedLatency(
      ProcessingType processing_type,
      const media::AudioParameters& device_parameters) {
    double fallback_latency =
        static_cast<double>(blink::kFallbackAudioLatencyMs) / 1000;
    double device_latency = device_parameters.GetBufferDuration().InSecondsF();
    double allowed_latency = device_parameters.frames_per_buffer() > 0
                                 ? device_latency
                                 : fallback_latency;
    switch (processing_type) {
      case ProcessingType::kApmProcessed:
        return DoubleRangeSet::FromValue(fallback_latency);
      case ProcessingType::kNoApmProcessed:
        return DoubleRangeSet::FromValue(allowed_latency);
      case ProcessingType::kUnprocessed:
        auto [min_latency, max_latency] =
            GetMinMaxLatenciesForAudioParameters(device_parameters);
        return DoubleRangeSet(min_latency, max_latency);
    }
  }

  // The priority of each processing-based container depends on the default
  // value assigned to the audio processing properties. When the value is true
  // the preference gives higher priority to the WebRTC processing.
  // On the contrary, if the value is false the preference is flipped towards
  // the option without processing.
  int GetProcessingPriority(const BooleanConstraint& ec_constraint) const {
    bool use_processing_by_default =
        echo_cancellation_container_.GetDefaultValueForAudioProperties(
            ec_constraint);

    switch (processing_type_) {
      case ProcessingType::kUnprocessed:
        return use_processing_by_default ? 1 : 3;
      case ProcessingType::kNoApmProcessed:
        return 2;
      case ProcessingType::kApmProcessed:
        return use_processing_by_default ? 3 : 1;
    }
  }

  ProcessingType processing_type_;
  std::array<BooleanContainer, kNumBooleanContainerIds> boolean_containers_;
  EchoCancellationContainer echo_cancellation_container_;
  AutoGainControlContainer auto_gain_control_container_;
  VoiceIsolationContainer voice_isolation_container_;
  IntegerRangeContainer sample_size_container_;
  IntegerDiscreteContainer channels_container_;
  IntegerRangeContainer sample_rate_container_;
  DoubleRangeContainer latency_container_;
};

constexpr ProcessingBasedContainer::BooleanPropertyContainerInfo
    ProcessingBasedContainer::kBooleanPropertyContainerInfoMap[];

// Container for the constrainable properties of a single audio device.
class DeviceContainer {
 public:
  DeviceContainer(const AudioDeviceCaptureCapability& capability,
                  mojom::blink::MediaStreamType stream_type,
                  bool is_device_capture,
                  bool is_reconfiguration_allowed)
      : device_parameters_(capability.Parameters()) {
    if (!capability.DeviceID().empty()) {
      device_id_container_ =
          StringContainer(StringSet({capability.DeviceID().Utf8()}));
    }

    if (!capability.GroupID().empty()) {
      group_id_container_ =
          StringContainer(StringSet({capability.GroupID().Utf8()}));
    }

    // If the device is in use, a source will be provided and all containers
    // must be initialized such that their only supported values correspond to
    // the source settings. Otherwise, the containers are initialized to contain
    // all possible values.
    SourceInfo source_info =
        InfoFromSource(capability.source(), device_parameters_.effects());

    // Three variations of the processing-based container. Each variant is
    // associated to a different type of audio processing configuration, namely
    // unprocessed, processed by WebRTC, or processed by other means.
    processing_based_containers_.push_back(
        ProcessingBasedContainer::CreateUnprocessedContainer(
            source_info, is_device_capture, device_parameters_,
            is_reconfiguration_allowed));
    processing_based_containers_.push_back(
        ProcessingBasedContainer::CreateNoApmProcessedContainer(
            source_info, is_device_capture, device_parameters_,
            is_reconfiguration_allowed));
      processing_based_containers_.push_back(
          ProcessingBasedContainer::CreateApmProcessedContainer(
              source_info, stream_type, is_device_capture, device_parameters_,
              is_reconfiguration_allowed));
      DCHECK_EQ(processing_based_containers_.size(), 3u);

    if (source_info.type() == SourceType::kNone)
      return;

    blink::MediaStreamAudioSource* source = capability.source();
    boolean_containers_[kDisableLocalEcho] =
        BooleanContainer(BoolSet({source->disable_local_echo()}));

    boolean_containers_[kRenderToAssociatedSink] =
        BooleanContainer(BoolSet({source->RenderToAssociatedSinkEnabled()}));

#if DCHECK_IS_ON()
    for (const auto& container : boolean_containers_)
      DCHECK(!container.IsEmpty());
#endif
  }

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    const char* failed_constraint_name;

    failed_constraint_name =
        device_id_container_.ApplyConstraintSet(constraint_set.device_id);
    if (failed_constraint_name)
      return failed_constraint_name;

    failed_constraint_name =
        group_id_container_.ApplyConstraintSet(constraint_set.group_id);
    if (failed_constraint_name)
      return failed_constraint_name;

    for (size_t i = 0; i < kNumBooleanContainerIds; ++i) {
      auto& info = kBooleanPropertyContainerInfoMap[i];
      failed_constraint_name =
          boolean_containers_[info.index].ApplyConstraintSet(
              constraint_set.*(info.constraint_member));
      if (failed_constraint_name)
        return failed_constraint_name;
    }

    // For each processing based container, apply the constraints and only fail
    // if all of them failed.
    for (auto it = processing_based_containers_.begin();
         it != processing_based_containers_.end();) {
      DCHECK(!it->IsEmpty());
      failed_constraint_name = it->ApplyConstraintSet(constraint_set);
      if (failed_constraint_name)
        it = processing_based_containers_.erase(it);
      else
        ++it;
    }
    if (processing_based_containers_.empty()) {
      DCHECK_NE(failed_constraint_name, nullptr);
      return failed_constraint_name;
    }

    return nullptr;
  }

  std::tuple<Score, AudioCaptureSettings> SelectSettingsAndScore(
      const ConstraintSet& constraint_set,
      bool is_destkop_source,
      bool should_disable_hardware_noise_suppression,
      std::string default_device_id) const {
    DCHECK(!IsEmpty());
    Score score(0.0);

    auto [sub_score, device_id] = device_id_container_.SelectSettingsAndScore(
        constraint_set.device_id, default_device_id);
    score += sub_score;

    std::tie(sub_score, std::ignore) =
        group_id_container_.SelectSettingsAndScore(constraint_set.group_id,
                                                   std::string());
    score += sub_score;

    bool disable_local_echo;
    std::tie(sub_score, disable_local_echo) =
        boolean_containers_[kDisableLocalEcho].SelectSettingsAndScore(
            constraint_set.disable_local_echo, !is_destkop_source);
    score += sub_score;

    bool render_to_associated_sink;
    std::tie(sub_score, render_to_associated_sink) =
        boolean_containers_[kRenderToAssociatedSink].SelectSettingsAndScore(
            constraint_set.render_to_associated_sink, false);
    score += sub_score;

    // To determine which properties to use, we have to compare and compute the
    // scores of each properties set and use the best performing one. In this
    // loop we are also determining the best settings that should be applied to
    // the best performing candidate.
    Score best_score(-1.0);
    AudioProcessingProperties best_properties;
    const ProcessingBasedContainer* best_container = nullptr;
    std::optional<int> best_requested_buffer_size;
    int best_num_channels = 1;
    for (const auto& container : processing_based_containers_) {
      if (container.IsEmpty())
        continue;

      auto [container_score, container_properties, requested_buffer_size,
            num_channels] =
          container.SelectSettingsAndScore(
              constraint_set, should_disable_hardware_noise_suppression,
              device_parameters_);
      if (container_score > best_score) {
        best_score = container_score;
        best_properties = container_properties;
        best_container = &container;
        best_requested_buffer_size = requested_buffer_size;
        best_num_channels = num_channels;
      }
    }

    DCHECK_NE(best_container, nullptr);
    score += best_score;

    // Update |properties.disable_hw_noise_suppression| depending on a related
    // experiment that can force-disable HW noise suppression.
    best_properties.disable_hw_noise_suppression =
        should_disable_hardware_noise_suppression &&
        best_properties.echo_cancellation_type ==
            EchoCancellationType::kEchoCancellationDisabled;

    // The score at this point can be considered complete only when the settings
    // are compared against the default device id, which is used as arbitrator
    // in case multiple candidates are available.
    return std::make_tuple(
        score, AudioCaptureSettings(
                   device_id, best_requested_buffer_size, disable_local_echo,
                   render_to_associated_sink, best_container->processing_type(),
                   best_properties, best_num_channels));
  }

  // The DeviceContainer is considered empty if at least one of the
  // containers owned is empty.
  bool IsEmpty() const {
    DCHECK(!boolean_containers_.empty());

    for (auto& container : boolean_containers_) {
      if (container.IsEmpty())
        return true;
    }

    return device_id_container_.IsEmpty() || group_id_container_.IsEmpty();
  }

 private:
  enum BooleanContainerId {
    kDisableLocalEcho,
    kRenderToAssociatedSink,
    kNumBooleanContainerIds
  };

  // This struct groups related fields or entries from
  // DeviceContainer::boolean_containers_ and MediaTrackConstraintSetPlatform.
  struct BooleanPropertyContainerInfo {
    BooleanContainerId index;
    BooleanConstraint ConstraintSet::*constraint_member;
  };

  static constexpr BooleanPropertyContainerInfo
      kBooleanPropertyContainerInfoMap[] = {
          {kDisableLocalEcho, &ConstraintSet::disable_local_echo},
          {kRenderToAssociatedSink, &ConstraintSet::render_to_associated_sink}};

  // Utility function to determine which version of this class should be
  // allocated depending on the |source| provided.
  static SourceInfo InfoFromSource(blink::MediaStreamAudioSource* source,
                                   int effects) {
    SourceType source_type;
    AudioProcessingProperties properties;
    auto* processed_source = ProcessedLocalAudioSource::From(source);
    std::optional<int> channels;
    std::optional<int> sample_rate;
    std::optional<double> latency;

    if (!source) {
      source_type = SourceType::kNone;
    } else {
      media::AudioParameters source_parameters = source->GetAudioParameters();
      channels = source_parameters.channels();
      sample_rate = source_parameters.sample_rate();
      latency = source_parameters.GetBufferDuration().InSecondsF();
      properties = *(source->GetAudioProcessingProperties());

      if (!processed_source) {
        source_type = SourceType::kUnprocessed;
        properties.DisableDefaultProperties();

        // It is possible, however, that the HW echo canceller is enabled. In
        // such case the property for echo cancellation type should be updated
        // accordingly.
        if (effects & media::AudioParameters::ECHO_CANCELLER) {
          properties.echo_cancellation_type =
              EchoCancellationType::kEchoCancellationSystem;
        }
      } else {
        source_type = properties.EchoCancellationIsWebRtcProvided()
                          ? SourceType::kApmProcessed
                          : SourceType::kNoApmProcessed;
        properties = processed_source->audio_processing_properties();
      }
    }

    return SourceInfo(source_type, properties, channels, sample_rate, latency);
  }

  media::AudioParameters device_parameters_;
  StringContainer device_id_container_;
  StringContainer group_id_container_;
  std::array<BooleanContainer, kNumBooleanContainerIds> boolean_containers_;
  Vector<ProcessingBasedContainer> processing_based_containers_;
};

constexpr DeviceContainer::BooleanPropertyContainerInfo
    DeviceContainer::kBooleanPropertyContainerInfoMap[];

// This class represents a set of possible candidate settings.  The
// SelectSettings algorithm starts with a set containing all possible candidates
// based on system/hardware capabilities and/or allowed values for supported
// properties. The set is then reduced progressively as the basic and advanced
// constraint sets are applied. In the end, if the set of candidates is empty,
// SelectSettings fails. If not, the ideal values (if any) or tie breaker rules
// are used to select the final settings based on the candidates that survived
// the application of the constraint sets. This class is implemented as a
// collection of more specific sets for the various supported properties. If any
// of the specific sets is empty, the whole CandidatesContainer is considered
// empty as well.
class CandidatesContainer {
 public:
  CandidatesContainer(const AudioDeviceCaptureCapabilities& capabilities,
                      mojom::blink::MediaStreamType stream_type,
                      std::string& media_stream_source,
                      std::string& default_device_id,
                      bool is_reconfiguration_allowed)
      : default_device_id_(default_device_id) {
    const bool is_device_capture = media_stream_source.empty();
    for (const auto& capability : capabilities) {
      devices_.emplace_back(capability, stream_type, is_device_capture,
                            is_reconfiguration_allowed);
      DCHECK(!devices_.back().IsEmpty());
    }
  }

  const char* ApplyConstraintSet(const ConstraintSet& constraint_set) {
    const char* latest_failed_constraint_name = nullptr;
    for (auto it = devices_.begin(); it != devices_.end();) {
      DCHECK(!it->IsEmpty());
      auto* failed_constraint_name = it->ApplyConstraintSet(constraint_set);
      if (failed_constraint_name) {
        latest_failed_constraint_name = failed_constraint_name;
        it = devices_.erase(it);
      } else {
        ++it;
      }
    }
    return IsEmpty() ? latest_failed_constraint_name : nullptr;
  }

  std::tuple<Score, AudioCaptureSettings> SelectSettingsAndScore(
      const ConstraintSet& constraint_set,
      bool is_desktop_source,
      bool should_disable_hardware_noise_suppression) const {
    DCHECK(!IsEmpty());
    // Make a copy of the settings initially provided, to track the default
    // settings.
    AudioCaptureSettings best_settings;
    Score best_score(-1.0);
    for (const auto& candidate : devices_) {
      auto [score, settings] = candidate.SelectSettingsAndScore(
          constraint_set, is_desktop_source,
          should_disable_hardware_noise_suppression, default_device_id_);

      score += default_device_id_ == settings.device_id();
      if (score > best_score) {
        best_score = score;
        best_settings = std::move(settings);
      }
    }
    return std::make_tuple(best_score, best_settings);
  }

  bool IsEmpty() const { return devices_.empty(); }

 private:
  std::string default_device_id_;
  Vector<DeviceContainer> devices_;
};

std::string GetMediaStreamSource(const MediaConstraints& constraints) {
  std::string source;
  if (constraints.Basic().media_stream_source.HasIdeal() &&
      constraints.Basic().media_stream_source.Ideal().size() > 0) {
    source = constraints.Basic().media_stream_source.Ideal()[0].Utf8();
  }
  if (constraints.Basic().media_stream_source.HasExact() &&
      constraints.Basic().media_stream_source.Exact().size() > 0) {
    source = constraints.Basic().media_stream_source.Exact()[0].Utf8();
  }

  return source;
}

}  // namespace

AudioDeviceCaptureCapability::AudioDeviceCaptureCapability()
    : parameters_(media::AudioParameters::UnavailableDeviceParams()) {}

AudioDeviceCaptureCapability::AudioDeviceCaptureCapability(
    blink::MediaStreamAudioSource* source)
    : source_(source) {}

AudioDeviceCaptureCapability::AudioDeviceCaptureCapability(
    String device_id,
    String group_id,
    const media::AudioParameters& parameters)
    : device_id_(std::move(device_id)),
      group_id_(std::move(group_id)),
      parameters_(parameters) {
  DCHECK(!device_id_.empty());
}

AudioDeviceCaptureCapability::AudioDeviceCaptureCapability(
    const AudioDeviceCaptureCapability&) = default;

AudioDeviceCaptureCapability& AudioDeviceCaptureCapability::operator=(
    const AudioDeviceCaptureCapability&) = default;

String AudioDeviceCaptureCapability::DeviceID() const {
  return source_ ? String(source_->device().id.data()) : device_id_;
}

String AudioDeviceCaptureCapability::GroupID() const {
  return source_ && source_->device().group_id
             ? String(source_->device().group_id->data())
             : group_id_;
}

const media::AudioParameters& AudioDeviceCaptureCapability::Parameters() const {
  return source_ ? source_->device().input : parameters_;
}

AudioCaptureSettings SelectSettingsAudioCapture(
    const AudioDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    mojom::blink::MediaStreamType stream_type,
    bool should_disable_hardware_noise_suppression,
    bool is_reconfiguration_allowed) {
  if (capabilities.empty())
    return AudioCaptureSettings();

  std::string media_stream_source = GetMediaStreamSource(constraints);
  std::string default_device_id;
  bool is_device_capture = media_stream_source.empty();
  if (is_device_capture)
    default_device_id = capabilities.begin()->DeviceID().Utf8();

  CandidatesContainer candidates(capabilities, stream_type, media_stream_source,
                                 default_device_id, is_reconfiguration_allowed);
  DCHECK(!candidates.IsEmpty());

  auto* failed_constraint_name =
      candidates.ApplyConstraintSet(constraints.Basic());
  if (failed_constraint_name)
    return AudioCaptureSettings(failed_constraint_name);

  for (const auto& advanced_set : constraints.Advanced()) {
    CandidatesContainer copy = candidates;
    failed_constraint_name = candidates.ApplyConstraintSet(advanced_set);
    if (failed_constraint_name)
      candidates = std::move(copy);
  }
  DCHECK(!candidates.IsEmpty());

  // Score is ignored as it is no longer needed.
  AudioCaptureSettings settings;
  std::tie(std::ignore, settings) = candidates.SelectSettingsAndScore(
      constraints.Basic(),
      media_stream_source == blink::kMediaStreamSourceDesktop,
      should_disable_hardware_noise_suppression);

  return settings;
}

AudioCaptureSettings SelectSettingsAudioCapture(
    blink::MediaStreamAudioSource* source,
    const MediaConstraints& constraints) {
  DCHECK(source);
  if (source->device().type !=
          blink::mojom::MediaStreamType::DEVICE_AUDIO_CAPTURE &&
      source->device().type !=
          blink::mojom::MediaStreamType::GUM_TAB_AUDIO_CAPTURE &&
      source->device().type !=
          blink::mojom::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE) {
    return AudioCaptureSettings();
  }

  std::string media_stream_source = GetMediaStreamSource(constraints);
  if (source->device().type ==
          blink::mojom::MediaStreamType::DEVICE_AUDIO_CAPTURE &&
      !media_stream_source.empty()) {
    return AudioCaptureSettings(
        constraints.Basic().media_stream_source.GetName());
  }

  if (source->device().type ==
          blink::mojom::MediaStreamType::GUM_TAB_AUDIO_CAPTURE &&
      !media_stream_source.empty() &&
      media_stream_source != blink::kMediaStreamSourceTab) {
    return AudioCaptureSettings(
        constraints.Basic().media_stream_source.GetName());
  }
  if (source->device().type ==
          blink::mojom::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE &&
      !media_stream_source.empty() &&
      media_stream_source != blink::kMediaStreamSourceSystem &&
      media_stream_source != blink::kMediaStreamSourceDesktop) {
    return AudioCaptureSettings(
        constraints.Basic().media_stream_source.GetName());
  }

  AudioDeviceCaptureCapabilities capabilities = {
      AudioDeviceCaptureCapability(source)};
  bool should_disable_hardware_noise_suppression =
      !(source->device().input.effects() &
        media::AudioParameters::NOISE_SUPPRESSION);

  return SelectSettingsAudioCapture(capabilities, constraints,
                                    source->device().type,
                                    should_disable_hardware_noise_suppression);
}

MODULES_EXPORT base::expected<Vector<blink::AudioCaptureSettings>, std::string>
SelectEligibleSettingsAudioCapture(
    const AudioDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints,
    mojom::blink::MediaStreamType stream_type,
    bool should_disable_hardware_noise_suppression,
    bool is_reconfiguration_allowed) {
  Vector<AudioCaptureSettings> settings;
  std::string failed_constraint_name;
  for (const auto& device : capabilities) {
    const auto device_settings = SelectSettingsAudioCapture(
        {device}, constraints, stream_type,
        should_disable_hardware_noise_suppression, is_reconfiguration_allowed);
    if (device_settings.HasValue()) {
      settings.push_back(device_settings);
    } else {
      failed_constraint_name = device_settings.failed_constraint_name();
    }
  }

  if (settings.empty()) {
    return base::unexpected(failed_constraint_name);
  }
  return settings;
}

std::tuple<int, int> GetMinMaxBufferSizesForAudioParameters(
    const media::AudioParameters& parameters) {
  const int default_buffer_size = parameters.frames_per_buffer();
  DCHECK_GT(default_buffer_size, 0);

  const std::optional<media::AudioParameters::HardwareCapabilities>
      hardware_capabilities = parameters.hardware_capabilities();

  // Only support platforms where we have both fixed min and max buffer size
  // values in order to simplify comparison logic.
  DCHECK(!hardware_capabilities ||
         (hardware_capabilities &&
          // Windows returns a HardwareCapabilities with both values set to 0 if
          // they're unknown rather than returning null.
          ((hardware_capabilities->min_frames_per_buffer == 0 &&
            hardware_capabilities->max_frames_per_buffer == 0) ||
           (hardware_capabilities->min_frames_per_buffer > 0 &&
            hardware_capabilities->max_frames_per_buffer > 0))))
      << "Variable input latency requires both a min and max to be set";

  return (hardware_capabilities &&
          hardware_capabilities->min_frames_per_buffer > 0 &&
          hardware_capabilities->max_frames_per_buffer > 0)
             ? std::make_tuple(hardware_capabilities->min_frames_per_buffer,
                               hardware_capabilities->max_frames_per_buffer)
             : std::make_tuple(default_buffer_size, default_buffer_size);
}

std::tuple<double, double> GetMinMaxLatenciesForAudioParameters(
    const media::AudioParameters& parameters) {
  auto [min_buffer_size, max_buffer_size] =
      GetMinMaxBufferSizesForAudioParameters(parameters);

  // Doing the microseconds conversion to match what is done in
  // AudioParameters::GetBufferDuration() so that values reported to the user
  // are truncated consistently to 
"""


```