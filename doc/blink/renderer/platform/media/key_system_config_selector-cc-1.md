Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the Chromium Blink rendering engine and resides in the `key_system_config_selector.cc` file. It appears to be involved in selecting a suitable configuration for Encrypted Media Extensions (EME).

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The filename itself, `KeySystemConfigSelector`, strongly suggests that the primary responsibility is to select a configuration. The presence of functions like `SelectConfig` and `GetSupportedConfiguration` reinforces this.

2. **Understand the Context (EME):**  The code deals with concepts like "key system," "session types," "persistent state," "distinctive identifier," and "capabilities" (audio/video). These are all related to EME, which enables DRM in web browsers.

3. **Analyze Key Functions:**
    * **`SelectConfig`:** This is the entry point. It takes a key system and a list of candidate configurations. It performs initial checks (key system support, enabled state) and then calls `SelectConfigInternal`.
    * **`SelectConfigInternal`:** This function iterates through the candidate configurations and calls `GetSupportedConfiguration` for each. It also handles permission requests (for protected media identifiers and hardware secure decryption).
    * **`GetSupportedConfiguration`:** This is the core logic for determining if a candidate configuration is supported. It compares the requested configuration against the capabilities of the underlying key system and applies various rules and checks.

4. **Identify Key Concepts and Logic:**
    * **Configuration Negotiation:** The code tries to find a configuration that satisfies both the web page's requirements and the browser/CDM's capabilities.
    * **Feature Requirements:**  Concepts like `distinctiveIdentifier` and `persistentState` have requirements (e.g., "required," "optional," "not-allowed"). The code checks if these requirements can be met.
    * **Session Types:** Different types of media sessions (temporary, persistent license) have different implications and are checked for support.
    * **Media Capabilities:** The code considers audio and video capabilities and uses the `GetSupportedCapabilities` function (not shown in the snippet but implied) to determine compatibility.
    * **Permissions:** The code handles user permission requests for accessing protected media identifiers and using hardware secure decryption.
    * **Error Handling:** The code returns different status codes (e.g., `kUnsupportedKeySystem`, `kUnsupportedConfigs`, `kConfigurationRequiresPermission`) to indicate why a configuration might be rejected.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** This code is the underlying implementation for the JavaScript EME API (`requestMediaKeySystemAccess`). When a web page calls this API, this C++ code is executed to find a suitable configuration.
    * **HTML:**  The `<video>` or `<audio>` elements are where EME is typically used. The `src` attribute of these elements might point to encrypted media content.
    * **CSS:** CSS is not directly related to the *functionality* of this code, but styling might be applied to the video player UI.

6. **Construct Input/Output Examples:**  Consider scenarios that would lead to different outcomes:
    * **Supported Configuration:** A candidate configuration matches the key system's capabilities and user permissions.
    * **Unsupported Key System:** The requested key system is not recognized by the browser.
    * **Unsupported Configuration:**  No candidate configuration matches the key system's capabilities.
    * **Permission Required:** A configuration requires a protected media identifier, and the user needs to grant permission.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using EME:
    * Specifying an unsupported key system.
    * Providing incompatible or missing configurations.
    * Not handling permission requests correctly.

8. **Summarize the Functionality (Part 2):**  Combine the observations from the previous steps into a concise summary. Focus on the high-level purpose and the key operations performed by the code.

9. **Review and Refine:** Ensure the summary is clear, accurate, and addresses all aspects of the prompt.

By following these steps, we can arrive at a comprehensive and informative summary of the `key_system_config_selector.cc` code.
好的，根据提供的代码片段，这是 `blink/renderer/platform/media/key_system_config_selector.cc` 文件的第二部分，延续了第一部分的功能，主要负责**选择一个与给定条件匹配的加密媒体配置 (EME Configuration)**。

**核心功能归纳:**

1. **处理候选配置并进行筛选:**  `SelectConfigInternal` 函数接收一个包含多个候选配置的请求，并逐个调用 `GetSupportedConfiguration` 来判断每个配置是否被支持。

2. **`GetSupportedConfiguration` 的核心逻辑延续:** 这部分代码继续实现了 `GetSupportedConfiguration` 函数中的步骤，该函数负责评估一个给定的候选配置是否被当前系统和密钥系统支持。

3. **处理 `persistentState` (持久化状态) 要求:**  代码检查并设置累积配置的 `persistentState` 属性，确保其与候选配置的要求和密钥系统的支持情况一致。 如果需要持久化状态，还会检查 IndexedDB 的访问权限。

4. **处理 `sessionTypes` (会话类型) 要求:** 代码遍历候选配置中指定的会话类型（例如 "temporary" 或 "persistent-license"），并检查密钥系统是否支持这些类型与当前累积配置的组合。如果 `persistentState` 为 "not-allowed"，则拒绝持久会话类型。

5. **处理 `videoCapabilities` 和 `audioCapabilities` (视频和音频能力) 要求:**  代码分别处理视频和音频能力，调用 `GetSupportedCapabilities` (代码片段中未完全展示) 来确定密钥系统是否支持候选配置中指定的编解码器、加密方案等。如果同时为空则直接返回不支持。

6. **处理 `distinctiveIdentifier` (唯一标识符) 要求:**  如果累积配置的 `distinctiveIdentifier` 为 "optional"，代码会根据密钥系统的支持情况以及是否需要唯一标识符来将其设置为 "required" 或 "not-allowed"。

7. **处理权限请求:** 如果在评估过程中发现需要用户权限（例如访问唯一标识符），并且尚未请求过权限，则会发起权限请求 (`media_permission_->RequestPermission`)。

8. **硬件安全解码的考量 (Windows 平台):**  在 Windows 平台上，如果启用了硬件安全解码回退功能，代码会检查是否允许使用硬件安全解码，并可能根据用户偏好禁用。

9. **返回支持的配置:** 如果找到一个被支持的配置，则会将该配置和相应的 CDM 配置信息 (例如密钥系统、是否允许唯一标识符、是否允许持久化状态、是否使用硬件安全解码) 通过回调函数返回。

10. **返回不支持:** 如果遍历完所有候选配置后都没有找到支持的配置，则通过回调函数返回不支持的状态。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**  这段 C++ 代码是浏览器内部实现的一部分，当 JavaScript 代码调用 `navigator.requestMediaKeySystemAccess()` API 时，会最终调用到这里的 `SelectConfig` 函数。  JavaScript 代码负责传递候选配置到这个 C++ 层进行评估。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm', [
     {
       initDataTypes: ['cenc'],
       videoCapabilities: [
         { mimeType: 'video/mp4; codecs="avc1.42E01E"' }
       ],
       audioCapabilities: [
         { mimeType: 'audio/mp4; codecs="mp4a.40.2"' }
       ],
       persistentState: 'optional',
       sessionTypes: ['temporary', 'persistent-license']
     }
   ]).then(function(access) {
     // 获取到 MediaKeySystemAccess 对象
   }).catch(function(error) {
     // 处理错误，例如配置不支持
   });
   ```

* **HTML:**  HTML 的 `<video>` 或 `<audio>` 元素是 EME 的应用场景。当视频或音频需要 DRM 保护时，JavaScript 会使用 EME API 来协商密钥系统和配置。这段 C++ 代码就是为了找到与 HTML 中使用的媒体格式和 DRM 方案兼容的配置。

   ```html
   <video id="myVideo" controls>
     <source src="encrypted_video.mp4" type="video/mp4">
   </video>
   ```

* **CSS:** CSS 与此代码的直接功能关系不大，但 CSS 可以用于控制播放器 UI 的样式，例如在等待密钥或许可证时显示加载动画。

**逻辑推理的假设输入与输出:**

**假设输入:**

* `key_system`: "com.widevine.alpha"
* `candidate_configurations`: 包含两个配置：
    1. `persistentState`: "required", `sessionTypes`: ["persistent-license"], `videoCapabilities`: [{ `mimeType`: "video/webm; codecs=\"vp9\"" }]
    2. `persistentState`: "optional", `sessionTypes`: ["temporary"], `audioCapabilities`: [{ `mimeType`: "audio/mp4; codecs=\"mp4a.40.2\"" }]
* 假设用户已授权访问受保护的媒体标识符。
* 假设 Widevine 密钥系统支持 VP9 视频和 AAC 音频，但只在需要持久化状态时才支持持久化会话。

**可能输出:**

如果第一个配置被评估：

* **输入到 `GetSupportedConfiguration`:** key_system = "com.widevine.alpha", candidate_configuration = { `persistentState`: "required", `sessionTypes`: ["persistent-license"], `videoCapabilities`: [{ `mimeType`: "video/webm; codecs=\"vp9\"" }] }
* **`GetSupportedConfiguration` 的内部逻辑可能判断:**
    * 持久化状态 "required" 被支持。
    * 持久会话类型 "persistent-license" 被支持。
    * VP9 视频能力被支持。
* **最终 `GetSupportedConfiguration` 返回:** `CONFIGURATION_SUPPORTED`，并填充 `accumulated_configuration` 包含以上配置信息。

如果第一个配置不满足 (例如 Widevine 不支持 VP9 的持久化会话):

* **`GetSupportedConfiguration` 返回:** `CONFIGURATION_NOT_SUPPORTED`。

然后评估第二个配置：

* **输入到 `GetSupportedConfiguration`:** key_system = "com.widevine.alpha", candidate_configuration = { `persistentState`: "optional", `sessionTypes`: ["temporary"], `audioCapabilities`: [{ `mimeType`: "audio/mp4; codecs=\"mp4a.40.2\"" }] }
* **`GetSupportedConfiguration` 的内部逻辑可能判断:**
    * 持久化状态 "optional" 可以被支持。
    * 临时会话类型 "temporary" 被支持。
    * AAC 音频能力被支持。
* **最终 `GetSupportedConfiguration` 返回:** `CONFIGURATION_SUPPORTED`，并填充 `accumulated_configuration` 包含以上配置信息。

**涉及用户或编程常见的使用错误:**

1. **指定不支持的密钥系统:** JavaScript 代码中传递了浏览器不支持的 `keySystem` 字符串，会导致 `SelectConfig` 中直接返回 `kUnsupportedKeySystem`。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.unsupported.drm', ...); // 错误
   ```

2. **提供的候选配置与密钥系统能力不匹配:**  例如，指定了需要某种特定的编解码器或加密方案，但用户的浏览器或 CDM 不支持。这将导致 `GetSupportedConfiguration` 返回 `CONFIGURATION_NOT_SUPPORTED`。

   ```javascript
   navigator.requestMediaKeySystemAccess('com.widevine.alpha', [
     { videoCapabilities: [{ mimeType: 'video/x-unsupported' }] } // 错误
   ]);
   ```

3. **未处理权限请求:** 如果配置需要用户授权 (例如访问唯一标识符)，但 JavaScript 代码没有正确处理 `requestMediaKeySystemAccess` 返回的 Promise 的 rejection 分支，用户可能会遇到错误或功能无法正常工作。

4. **在不允许持久化状态时请求持久会话:**  如果密钥系统或用户设置不允许持久化状态，但 JavaScript 代码请求了 "persistent-license" 会话类型，则会被这段 C++ 代码拒绝。

**总结:**

这段代码是 Chromium 浏览器中 EME 功能的核心组成部分，负责根据 JavaScript 代码提供的候选配置，结合浏览器和底层密钥系统的能力，选择一个最合适的加密媒体配置。它涉及到复杂的逻辑判断，包括对持久化状态、会话类型、音视频能力以及用户权限的管理。 它的目标是安全且有效地为 Web 上的加密媒体内容提供播放能力。

### 提示词
```
这是目录为blink/renderer/platform/media/key_system_config_selector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
AccessSync(
          WebContentSettingsClient::StorageType::kIndexedDB)) {
    if (persistent_state_support == EmeFeatureSupport::ALWAYS_ENABLED)
      return CONFIGURATION_NOT_SUPPORTED;
    persistent_state_support = EmeFeatureSupport::NOT_SUPPORTED;
  }
  EmeConfig::Rule ps_rule =
      GetPersistentStateConfigRule(persistent_state_support, persistent_state);
  if (!config_state->IsRuleSupported(ps_rule)) {
    DVLOG(2) << "Rejecting requested configuration because "
             << "the persistentState requirement was not supported.";
    return CONFIGURATION_NOT_SUPPORTED;
  }
  config_state->AddRule(ps_rule);

  // 11. Set the persistentState member of accumulated configuration to equal
  //     the value of persistent state requirement.
  accumulated_configuration->persistent_state = persistent_state;

  // 12. Follow the steps for the first matching condition from the following
  //     list:
  //       - If the sessionTypes member is present in candidate configuration,
  //         let session types be candidate configuration's sessionTypes member.
  //       - Otherwise, let session types be [ "temporary" ].
  //         (Done in MediaKeySystemAccessInitializer.)
  WebVector<WebEncryptedMediaSessionType> session_types =
      candidate.session_types;

  // 13. For each value in session types:
  for (size_t i = 0; i < session_types.size(); i++) {
    // 13.1. Let session type be the value.
    WebEncryptedMediaSessionType session_type = session_types[i];
    if (session_type == WebEncryptedMediaSessionType::kUnknown) {
      DVLOG(2) << "Rejecting requested configuration because the session type "
                  "was not recognized.";
      return CONFIGURATION_NOT_SUPPORTED;
    }

    // 13.2. If accumulated configuration's persistentState value is
    //       "not-allowed" and the Is persistent session type? algorithm
    //       returns true for session type return NotSupported.
    if (accumulated_configuration->persistent_state ==
            EmeFeatureRequirement::kNotAllowed &&
        IsPersistentSessionType(session_type)) {
      DVLOG(2) << "Rejecting requested configuration because persistent state "
                  "is not allowed.";
      return CONFIGURATION_NOT_SUPPORTED;
    }

    // 13.3. If the implementation does not support session type in combination
    //       with accumulated configuration and restrictions for other reasons,
    //       return NotSupported.
    EmeConfig::Rule session_type_rule = EmeConfig::UnsupportedRule();
    switch (session_type) {
      case WebEncryptedMediaSessionType::kUnknown:
        NOTREACHED();
      case WebEncryptedMediaSessionType::kTemporary:
        session_type_rule = EmeConfig::SupportedRule();
        break;
      case WebEncryptedMediaSessionType::kPersistentLicense:
        session_type_rule =
            key_systems_->GetPersistentLicenseSessionSupport(key_system);
        break;
    }

    if (!config_state->IsRuleSupported(session_type_rule)) {
      DVLOG(2) << "Rejecting requested configuration because "
               << "a required session type was not supported.";
      return CONFIGURATION_NOT_SUPPORTED;
    }
    config_state->AddRule(session_type_rule);

    // 13.4. If accumulated configuration's persistentState value is "optional"
    //       and the result of running the Is persistent session type?
    //       algorithm on session type is true, change accumulated
    //       configuration's persistentState value to "required".
    if (accumulated_configuration->persistent_state ==
            EmeFeatureRequirement::kOptional &&
        IsPersistentSessionType(session_type)) {
      accumulated_configuration->persistent_state =
          EmeFeatureRequirement::kRequired;
    }
  }

  // 14. Set the sessionTypes member of accumulated configuration to
  //     session types.
  accumulated_configuration->session_types = session_types;

  // 15. If the videoCapabilities and audioCapabilities members in candidate
  //     configuration are both empty, return NotSupported.
  if (candidate.video_capabilities.empty() &&
      candidate.audio_capabilities.empty()) {
    DVLOG(2) << "Rejecting requested configuration because "
             << "neither audioCapabilities nor videoCapabilities is specified";
    return CONFIGURATION_NOT_SUPPORTED;
  }

  // 16. If the videoCapabilities member in candidate configuration is
  //     non-empty:
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities;
  if (!candidate.video_capabilities.empty()) {
    // 16.1. Let video capabilities be the result of executing the Get
    //       Supported Capabilities for Audio/Video Type algorithm on Video,
    //       candidate configuration's videoCapabilities member, accumulated
    //       configuration, and restrictions.
    // 16.2. If video capabilities is null, return NotSupported.
    if (!GetSupportedCapabilities(key_system, EmeMediaType::VIDEO,
                                  candidate.video_capabilities, config_state,
                                  &video_capabilities)) {
      DVLOG(2) << "Rejecting requested configuration because the specified "
                  "videoCapabilities are not supported.";
      return CONFIGURATION_NOT_SUPPORTED;
    }

    // 16.3. Set the videoCapabilities member of accumulated configuration
    //       to video capabilities.
    accumulated_configuration->video_capabilities = video_capabilities;
  } else {
    // Otherwise set the videoCapabilities member of accumulated configuration
    // to an empty sequence.
    accumulated_configuration->video_capabilities = video_capabilities;
  }

  // 17. If the audioCapabilities member in candidate configuration is
  //     non-empty:
  std::vector<WebMediaKeySystemMediaCapability> audio_capabilities;
  if (!candidate.audio_capabilities.empty()) {
    // 17.1. Let audio capabilities be the result of executing the Get
    //       Supported Capabilities for Audio/Video Type algorithm on Audio,
    //       candidate configuration's audioCapabilities member, accumulated
    //       configuration, and restrictions.
    // 17.2. If audio capabilities is null, return NotSupported.
    if (!GetSupportedCapabilities(key_system, EmeMediaType::AUDIO,
                                  candidate.audio_capabilities, config_state,
                                  &audio_capabilities)) {
      DVLOG(2) << "Rejecting requested configuration because the specified "
                  "audioCapabilities are not supported.";
      return CONFIGURATION_NOT_SUPPORTED;
    }

    // 17.3. Set the audioCapabilities member of accumulated configuration
    //       to audio capabilities.
    accumulated_configuration->audio_capabilities = audio_capabilities;
  } else {
    // Otherwise set the audioCapabilities member of accumulated configuration
    // to an empty sequence.
    accumulated_configuration->audio_capabilities = audio_capabilities;
  }

  // 18. If accumulated configuration's distinctiveIdentifier value is
  //     "optional", follow the steps for the first matching condition
  //      from the following list:
  //       - If the implementation requires use Distinctive Identifier(s) or
  //         Distinctive Permanent Identifier(s) for any of the combinations
  //         in accumulated configuration, change accumulated configuration's
  //         distinctiveIdentifier value to "required".
  //       - Otherwise, change accumulated configuration's
  //         distinctiveIdentifier value to "not-allowed".
  if (accumulated_configuration->distinctive_identifier ==
      EmeFeatureRequirement::kOptional) {
    EmeConfig::Rule not_allowed_rule = GetDistinctiveIdentifierConfigRule(
        key_systems_->GetDistinctiveIdentifierSupport(key_system),
        EmeFeatureRequirement::kNotAllowed);
    EmeConfig::Rule required_rule = GetDistinctiveIdentifierConfigRule(
        key_systems_->GetDistinctiveIdentifierSupport(key_system),
        EmeFeatureRequirement::kRequired);
    bool not_allowed_supported =
        config_state->IsRuleSupported(not_allowed_rule);
    bool required_supported = config_state->IsRuleSupported(required_rule);
    // If a distinctive identifier is recommend and that is a possible outcome,
    // prefer that.
    if (required_supported && config_state->IsIdentifierRecommended() &&
        config_state->IsPermissionPossible()) {
      not_allowed_supported = false;
    }
    if (not_allowed_supported) {
      accumulated_configuration->distinctive_identifier =
          EmeFeatureRequirement::kNotAllowed;
      config_state->AddRule(not_allowed_rule);
    } else if (required_supported) {
      accumulated_configuration->distinctive_identifier =
          EmeFeatureRequirement::kRequired;
      config_state->AddRule(required_rule);
    } else {
      // We should not have passed step 6.
      NOTREACHED();
    }
  }

  // 19. If accumulated configuration's persistentState value is "optional",
  //     follow the steps for the first matching condition from the following
  //     list:
  //       - If the implementation requires persisting state for any of the
  //         combinations in accumulated configuration, change accumulated
  //         configuration's persistentState value to "required".
  //       - Otherwise, change accumulated configuration's persistentState
  //         value to "not-allowed".
  if (accumulated_configuration->persistent_state ==
      EmeFeatureRequirement::kOptional) {
    EmeConfig::Rule not_allowed_rule = GetPersistentStateConfigRule(
        key_systems_->GetPersistentStateSupport(key_system),
        EmeFeatureRequirement::kNotAllowed);
    EmeConfig::Rule required_rule = GetPersistentStateConfigRule(
        key_systems_->GetPersistentStateSupport(key_system),
        EmeFeatureRequirement::kRequired);
    // |persistent_state| should not be affected after it is decided.
    DCHECK(!not_allowed_rule.has_value() ||
           not_allowed_rule->persistence == EmeConfigRuleState::kNotAllowed);
    DCHECK(!required_rule.has_value() ||
           required_rule->persistence == EmeConfigRuleState::kRequired);
    bool not_allowed_supported =
        config_state->IsRuleSupported(not_allowed_rule);
    bool required_supported = config_state->IsRuleSupported(required_rule);
    if (not_allowed_supported) {
      accumulated_configuration->persistent_state =
          EmeFeatureRequirement::kNotAllowed;
      config_state->AddRule(not_allowed_rule);
    } else if (required_supported) {
      accumulated_configuration->persistent_state =
          EmeFeatureRequirement::kRequired;
      config_state->AddRule(required_rule);
    } else {
      // We should not have passed step 5.
      NOTREACHED();
    }
  }

  // 20. If implementation in the configuration specified by the combination of
  //     the values in accumulated configuration is not supported or not allowed
  //     in the origin, return NotSupported.
  // 21. If accumulated configuration's distinctiveIdentifier value is
  //     "required" and the Distinctive Identifier(s) associated with
  //     accumulated configuration are not unique per origin and profile
  //     and clearable:
  // 21.1. Update restrictions to reflect that all configurations described
  //       by accumulated configuration do not have user consent.
  // 21.2. Return ConsentDenied and restrictions.
  // (Not required as data is unique per origin and clearable.)

  // 22. Let consent status and updated restrictions be the result of running
  //     the Get Consent Status algorithm on accumulated configuration,
  //     restrictions and origin and follow the steps for the value of consent
  //     status from the following list:
  //       - "ConsentDenied": Return ConsentDenied and updated restrictions.
  //       - "InformUser": Inform the user that accumulated configuration is
  //         in use in the origin including, specifically, the information
  //         that Distinctive Identifier(s) and/or Distinctive Permanent
  //         Identifier(s) as appropriate will be used if the
  //         distinctiveIdentifier member of accumulated configuration is
  //         "required". Continue to the next step.
  //       - "Allowed": Continue to the next step.
  // Accumulated configuration's distinctiveIdentifier should be "required" or
  // "notallowed"" due to step 18. If it is "required", prompt the user for
  // consent unless it has already been granted.
  if (accumulated_configuration->distinctive_identifier ==
      EmeFeatureRequirement::kRequired) {
    // The caller is responsible for resolving what to do if permission is
    // required but has been denied (it should treat it as NOT_SUPPORTED).
    if (!config_state->IsPermissionGranted())
      return CONFIGURATION_REQUIRES_PERMISSION;
  }

  // 23. Return accumulated configuration.
  return CONFIGURATION_SUPPORTED;
}

void KeySystemConfigSelector::SelectConfig(
    const WebString& key_system,
    const WebVector<WebMediaKeySystemConfiguration>& candidate_configurations,
    SelectConfigCB cb) {
  // Continued from requestMediaKeySystemAccess(), step 6, from
  // https://w3c.github.io/encrypted-media/#requestmediakeysystemaccess
  //
  // 6.1 If keySystem is not one of the Key Systems supported by the user
  //     agent, reject promise with a NotSupportedError. String comparison
  //     is case-sensitive.
  if (!key_system.ContainsOnlyASCII()) {
    DVLOG(1) << "Rejecting requested configuration because "
             << "key system contains unsupported characters.";
    std::move(cb).Run(Status::kUnsupportedKeySystem, nullptr, nullptr);
    return;
  }

  std::string key_system_ascii = key_system.Ascii();
  if (!key_systems_->IsSupportedKeySystem(key_system_ascii)) {
    DVLOG(1) << "Rejecting requested configuration because "
             << "key system " << key_system_ascii << " is not supported.";
    std::move(cb).Run(Status::kUnsupportedKeySystem, nullptr, nullptr);
    return;
  }

  const bool is_encrypted_media_enabled =
      media_permission_->IsEncryptedMediaEnabled();

  // Only report this UMA at most once per renderer process.
  static bool has_reported_encrypted_media_enabled_uma = false;
  if (!has_reported_encrypted_media_enabled_uma) {
    has_reported_encrypted_media_enabled_uma = true;
    UMA_HISTOGRAM_BOOLEAN("Media.EME.EncryptedMediaEnabled",
                          is_encrypted_media_enabled);
  }

  // According to Section 9 "Common Key Systems": All user agents MUST support
  // the common key systems described in this section.
  //   9.1 Clear Key
  //
  // Therefore, always support Clear Key key system and only check settings for
  // other key systems.
  if (!is_encrypted_media_enabled && !media::IsClearKey(key_system_ascii)) {
    std::move(cb).Run(Status::kUnsupportedKeySystem, nullptr, nullptr);
    return;
  }

  // 6.2-6.4. Implemented by OnSelectConfig().
  // TODO(sandersd): This should be async, ideally not on the main thread.
  auto request = std::make_unique<SelectionRequest>();
  request->key_system = key_system_ascii;
  request->candidate_configurations = candidate_configurations;
  request->cb = std::move(cb);

  SelectConfigInternal(std::move(request));
}

void KeySystemConfigSelector::SelectConfigInternal(
    std::unique_ptr<SelectionRequest> request) {
  DVLOG(3) << __func__;

  // Continued from requestMediaKeySystemAccess(), step 6, from
  // https://w3c.github.io/encrypted-media/#requestmediakeysystemaccess
  //
  // 6.2. Let implementation be the implementation of keySystem.
  //      (|key_systems_| fills this role.)
  // 6.3. For each value in supportedConfigurations:
  for (size_t i = 0; i < request->candidate_configurations.size(); i++) {
    // 6.3.1. Let candidate configuration be the value.
    // 6.3.2. Let supported configuration be the result of executing the Get
    //        Supported Configuration algorithm on implementation, candidate
    //        configuration, and origin.
    // 6.3.3. If supported configuration is not NotSupported, [initialize
    //        and return a new MediaKeySystemAccess object.]
    ConfigState config_state(
        request->was_permission_requested, request->is_permission_granted,
        request->was_hardware_secure_decryption_preferences_requested,
        request->is_hardware_secure_decryption_allowed);
    WebMediaKeySystemConfiguration accumulated_configuration;
    media::CdmConfig cdm_config;
    ConfigurationSupport support = GetSupportedConfiguration(
        request->key_system, request->candidate_configurations[i],
        &config_state, &accumulated_configuration);
    switch (support) {
      case CONFIGURATION_NOT_SUPPORTED:
        continue;
      case CONFIGURATION_REQUIRES_PERMISSION:
        if (request->was_permission_requested) {
          DVLOG(2) << "Rejecting requested configuration because "
                   << "permission was denied.";
          continue;
        }
        DVLOG(3) << "Request permission.";
        media_permission_->RequestPermission(
            media::MediaPermission::Type::kProtectedMediaIdentifier,
            base::BindOnce(&KeySystemConfigSelector::OnPermissionResult,
                           weak_factory_.GetWeakPtr(), std::move(request)));
        return;
      case CONFIGURATION_SUPPORTED:
        std::string key_system = request->key_system;
        if (key_systems_->ShouldUseBaseKeySystemName(key_system)) {
          key_system = key_systems_->GetBaseKeySystemName(key_system);
        }
        cdm_config.key_system = key_system;

        cdm_config.allow_distinctive_identifier =
            (accumulated_configuration.distinctive_identifier ==
             EmeFeatureRequirement::kRequired);
        cdm_config.allow_persistent_state =
            (accumulated_configuration.persistent_state ==
             EmeFeatureRequirement::kRequired);
        cdm_config.use_hw_secure_codecs =
            config_state.AreHwSecureCodecsRequired();
#if BUILDFLAG(IS_WIN)
        // Check whether hardware secure decryption CDM should be disabled.
        if (cdm_config.use_hw_secure_codecs &&
            base::FeatureList::IsEnabled(
                media::kHardwareSecureDecryptionFallback) &&
            media::kHardwareSecureDecryptionFallbackPerSite.Get()) {
          if (!request->was_hardware_secure_decryption_preferences_requested) {
            media_permission_->IsHardwareSecureDecryptionAllowed(
                base::BindOnce(&KeySystemConfigSelector::
                                   OnHardwareSecureDecryptionAllowedResult,
                               weak_factory_.GetWeakPtr(), std::move(request)));
            return;
          }

          if (!config_state.IsHardwareSecureDecryptionAllowed()) {
            DVLOG(2) << "Rejecting requested configuration because "
                     << "Hardware secure decryption is not allowed.";
            continue;
          }
        }
#endif  // BUILDFLAG(IS_WIN)

        std::move(request->cb)
            .Run(Status::kSupported, &accumulated_configuration, &cdm_config);
        return;
    }
  }

  // 6.4. Reject promise with a NotSupportedError.
  std::move(request->cb).Run(Status::kUnsupportedConfigs, nullptr, nullptr);
}

void KeySystemConfigSelector::OnPermissionResult(
    std::unique_ptr<SelectionRequest> request,
    bool is_permission_granted) {
  DVLOG(3) << __func__;

  request->was_permission_requested = true;
  request->is_permission_granted = is_permission_granted;
  SelectConfigInternal(std::move(request));
}

#if BUILDFLAG(IS_WIN)
void KeySystemConfigSelector::OnHardwareSecureDecryptionAllowedResult(
    std::unique_ptr<SelectionRequest> request,
    bool is_hardware_secure_decryption_allowed) {
  DVLOG(3) << __func__;

  request->was_hardware_secure_decryption_preferences_requested = true;
  request->is_hardware_secure_decryption_allowed =
      is_hardware_secure_decryption_allowed;
  SelectConfigInternal(std::move(request));
}
#endif  // BUILDFLAG(IS_WIN)

}  // namespace blink
```