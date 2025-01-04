Response: The user wants to understand the functionality of the `key_system_config_selector_unittest.cc` file in the Chromium Blink engine.

Here's a breakdown of the request:

1. **List the functionality:**  The core purpose of the file.
2. **Relationship to web technologies:** Explain how it relates to JavaScript, HTML, and CSS.
3. **Logical reasoning with examples:** Provide hypothetical inputs and outputs for key functionalities.
4. **Common usage errors:** Illustrate potential mistakes developers might make.
5. **Summarize functionality (Part 1):** A concise overview of the file's role based on the provided code.

Let's analyze the provided code snippet to address these points.

- **Includes:** The file includes headers related to media, EME (Encrypted Media Extensions), and testing. This strongly suggests it's testing the logic for selecting appropriate key system configurations.
- **Test Key Systems:** It defines `FakeKeySystems` which mimics the behavior of a real key system, allowing for controlled testing scenarios. This includes defining supported/unsupported key systems, init data types, content types, robustness, and session types.
- **Test Media Permission:**  `FakeMediaPermission` simulates the user granting or denying media permissions, crucial for testing features like persistent state and distinctive identifier.
- **Test WebLocalFrameDelegate:** `FakeWebLocalFrameDelegate` helps simulate cross-origin scenarios and storage access, relevant for security and privacy considerations in EME.
- **`KeySystemConfigSelectorTest` Class:** This is the main test fixture, containing various test cases.
- **`SelectConfig` Method:**  This method appears to be the core function under test. It takes a key system and configurations, and then uses `KeySystemConfigSelector` to choose the best configuration.
- **Test Cases:** The numerous `TEST_F` macros indicate a wide range of scenarios being tested, covering different configurations, key system support, permissions, and feature flags.

Based on this analysis, the file's main function is to test the `KeySystemConfigSelector` class, which is responsible for determining the best `WebMediaKeySystemConfiguration` based on the available configurations and the underlying key system's capabilities.
这是对 Chromium Blink 引擎中 `blink/renderer/platform/media/key_system_config_selector_unittest.cc` 文件功能的归纳（第 1 部分）：

**功能归纳：**

这个文件是 `KeySystemConfigSelector` 类的单元测试文件。`KeySystemConfigSelector` 类的主要功能是：

1. **根据给定的密钥系统 (keySystem) 和一系列可能的配置 (configs)，选择一个最合适的 `WebMediaKeySystemConfiguration`。** 这个选择过程会考虑到密钥系统本身的支持能力、浏览器的功能支持（例如持久化存储、唯一标识符）、用户权限以及配置本身的特性（例如支持的媒体类型、编解码器、初始化数据类型、会话类型、安全级别等）。

2. **模拟和验证在不同条件下 `KeySystemConfigSelector` 的行为。**  测试覆盖了各种场景，包括：
    - 不同类型的密钥系统（支持、不支持、Clear Key）。
    - 不同的配置参数组合（初始化数据类型、媒体能力、唯一标识符、持久化状态、会话类型等）。
    - 用户权限的影响（是否授予访问唯一标识符或持久化状态的权限）。
    - 跨域场景的影响。
    - 特定编解码器或容器的支持情况。
    - 硬件安全编解码器的要求。
    - 加密方案的支持。

**与 JavaScript, HTML, CSS 的关系举例：**

虽然此文件是 C++ 代码，直接测试的是 Blink 引擎的内部逻辑，但它所测试的功能与 Web 开发中使用的 Encrypted Media Extensions (EME) API 息息相关。 EME API 允许 Web 应用程序与数字版权管理 (DRM) 系统交互，以播放受保护的媒体内容。

1. **JavaScript:**  Web 开发者使用 JavaScript 的 `navigator.requestMediaKeySystemAccess()` 方法来请求访问特定的密钥系统。传递给此方法的第二个参数就是一个 `MediaKeySystemConfiguration` 数组，对应于此测试文件中的 `configs_`。 `KeySystemConfigSelector` 的作用就是在内部从这些配置中选出一个最合适的。

   **举例：** 在 JavaScript 中，开发者可能会这样写：

   ```javascript
   navigator.requestMediaKeySystemAccess('com.example.drm', [
     {
       initDataTypes: ['cenc'],
       videoCapabilities: [
         { mimeType: 'video/mp4', codecs: 'avc1.42E01E' },
         { mimeType: 'video/webm', codecs: 'vp9' }
       ],
       distinctiveIdentifier: 'optional',
       persistentState: 'optional',
       sessionTypes: ['temporary']
     },
     {
       initDataTypes: ['webm'],
       videoCapabilities: [
         { mimeType: 'video/webm', codecs: 'vp9' }
       ],
       distinctiveIdentifier: 'required',
       persistentState: 'required',
       sessionTypes: ['persistent-license']
     }
   ]).then(function(mediaKeys) {
     // ...
   }).catch(function(error) {
     // ...
   });
   ```

   `KeySystemConfigSelector` 的测试会模拟这个过程中，当传入不同的 `MediaKeySystemConfiguration` 对象时，引擎内部是如何选择的。例如，如果密钥系统不支持 'webm' 类型的初始化数据，那么包含 `initDataTypes: ['webm']` 的配置可能就不会被选中。

2. **HTML:**  HTML 的 `<video>` 或 `<audio>` 元素用于播放媒体。EME API 通过 JavaScript 与这些元素集成，以处理加密的媒体数据。`KeySystemConfigSelector` 确保了当 HTML 中请求播放加密内容时，浏览器能够选择一个兼容的密钥系统配置。

   **举例：** HTML 中可能会有如下的视频元素：

   ```html
   <video id="myVideo" controls>
     <source src="encrypted_video.mp4" type='video/mp4; codecs="avc1.42E01E"' />
   </video>
   ```

   当 JavaScript 代码尝试使用 EME 为此视频元素配置加密时，`KeySystemConfigSelector` 的逻辑会确保选择的配置与视频的 `type` 属性中指定的媒体类型和编解码器相匹配。

3. **CSS:**  CSS 主要用于样式控制，与 `KeySystemConfigSelector` 的功能没有直接关系。然而，如果某些 DRM 方案需要在 UI 上显示特定的提示或控件，那么 CSS 可能会用于这些元素的样式。但 `KeySystemConfigSelector` 本身不涉及 CSS 的处理。

**逻辑推理的假设输入与输出举例：**

**假设输入 1:**

* `keySystem_`: "keysystem.test.supported"
* `configs_`: 包含两个配置：
    * 配置 A: 支持 "video/supported" 容器和 "video_codec" 编解码器， `distinctiveIdentifier` 为 "optional"。
    * 配置 B: 支持 "video/supported" 容器和 "video_codec" 编解码器， `distinctiveIdentifier` 为 "required"。
* `key_systems_->distinctive_identifier`: `EmeFeatureSupport::REQUESTABLE` （密钥系统支持请求唯一标识符）。
* `media_permission_->is_granted`: `false` （用户未授权访问唯一标识符）。

**逻辑推理:** `KeySystemConfigSelector` 会尝试选择一个满足所有条件的配置。配置 B 要求 `distinctiveIdentifier`，但用户未授权，因此配置 B 不会被选中。配置 A 没有此要求，因此会被选中。

**预期输出:** `OnConfigSelected` 的 `status` 为 `kSupported`，选择的配置是配置 A，`cdm_config_.allow_distinctive_identifier` 为 `false`。

**假设输入 2:**

* `keySystem_`: "keysystem.test.supported"
* `configs_`: 包含一个配置：支持 "video/supported" 容器和 "require_hw_secure_codec" 编解码器。
* 底层平台支持硬件安全解码。

**逻辑推理:**  配置中指定了 `require_hw_secure_codec`，这意味着只有在支持硬件安全解码的情况下才能使用此配置。

**预期输出:** `OnConfigSelected` 的 `status` 为 `kSupported`，选择的配置是唯一的那个配置，`cdm_config_.use_hw_secure_codecs` 为 `true`。

**用户或编程常见的使用错误举例：**

1. **Web 开发者提供的配置与密钥系统能力不匹配:**  开发者在 JavaScript 中提供的 `MediaKeySystemConfiguration` 对象指定了密钥系统不支持的功能或媒体格式。例如，配置中声明支持某个特定的编解码器，但实际的密钥系统或浏览器不支持。`KeySystemConfigSelector` 会拒绝这些不匹配的配置。

   **举例：**  如果开发者提供的配置中包含一个 `videoCapabilities`，指定了 `codecs: 'unsupported_codec'`，而底层密钥系统并不支持这个编解码器，`KeySystemConfigSelector` 将不会选择这个配置，并可能导致 `navigator.requestMediaKeySystemAccess()` 返回一个拒绝的 Promise。

2. **未处理 `navigator.requestMediaKeySystemAccess()` 返回的错误:**  如果 `KeySystemConfigSelector` 找不到合适的配置（例如，提供的所有配置都不被支持），`navigator.requestMediaKeySystemAccess()` 将会抛出一个错误。开发者需要正确地捕获和处理这些错误，以便提供友好的用户体验。

3. **对持久化状态或唯一标识符的权限处理不当:** 某些配置可能要求访问用户的唯一标识符或持久化存储。如果用户拒绝了这些权限，即使配置本身是有效的，`KeySystemConfigSelector` 也可能因为缺少必要的权限而无法选择该配置。开发者需要在用户界面上适当地处理这些权限请求和拒绝的情况。

   **举例：** 如果一个配置的 `distinctiveIdentifier` 设置为 "required"，但用户在浏览器中阻止了网站访问唯一标识符的权限，`KeySystemConfigSelector` 将不会选择这个配置。开发者应该考虑到这种情况，并可能提供降级方案或提示用户授予相应的权限。

Prompt: 
```
这是目录为blink/renderer/platform/media/key_system_config_selector_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/platform/media/key_system_config_selector.h"

#include <optional>
#include <string>
#include <vector>

#include "base/functional/bind.h"
#include "base/strings/pattern.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "media/base/cdm_config.h"
#include "media/base/eme_constants.h"
#include "media/base/key_systems.h"
#include "media/base/media_permission.h"
#include "media/base/media_switches.h"
#include "media/base/mime_util.h"
#include "media/cdm/clear_key_cdm_common.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_encrypted_media_types.h"
#include "third_party/blink/public/platform/web_media_key_system_configuration.h"
#include "third_party/blink/public/platform/web_string.h"

namespace blink {
namespace {

using ::media::EmeConfig;
using ::media::EmeConfigRuleState;
using ::media::EmeFeatureSupport;
using ::media::EmeInitDataType;
using ::media::EmeMediaType;
using MediaKeysRequirement = WebMediaKeySystemConfiguration::Requirement;
using EncryptionScheme = WebMediaKeySystemMediaCapability::EncryptionScheme;

// Key system strings. Clear Key support is hardcoded in KeySystemConfigSelector
// so media::kClearKeyKeySystem is the real key system string. The rest key
// system strings are for testing purpose only.
const char kSupportedKeySystem[] = "keysystem.test.supported";
const char kSupportedSubKeySystem[] = "keysystem.test.supported.sub";
const char kUnsupportedKeySystem[] = "keysystem.test.unsupported";

// Robustness strings for kSupportedKeySystem.
const char kSupportedRobustness[] = "supported";
const char kRecommendIdentifierRobustness[] = "recommend_identifier";
const char kRequireIdentifierRobustness[] = "require_identifier";
const char kDisallowHwSecureCodecRobustness[] = "disallow_hw_secure_codec";
const char kRequireHwSecureCodecRobustness[] = "require_hw_secure_codec";
const char kRequireIdentifierAndHwSecureCodecRobustness[] =
    "require_identifier_and_hw_secure_codec";
const char kRequireIdentifierPersistenceAndHwSecureCodecRobustness[] =
    "require_identifier_persistence_and_hw_secure_codec";
const char kUnsupportedRobustness[] = "unsupported";

// Test container mime types. Supported types are prefixed with audio/video so
// that the test can perform EmeMediaType check.
const char kSupportedVideoContainer[] = "video/supported";
const char kSupportedAudioContainer[] = "audio/supported";
const char kUnsupportedContainer[] = "video/unsupported";
const char kInvalidContainer[] = "video/invalid";

// The codec strings. Supported types are prefixed with audio/video so
// that the test can perform EmeMediaType check.
// TODO(sandersd): Extended codec variants (requires proprietary codec support).
// TODO(xhwang): Platform Opus is not available on all Android versions, where
// some encrypted Opus related tests may fail. See
// MediaCodecUtil::IsOpusDecoderAvailable() for more details.
const char kSupportedAudioCodec[] = "audio_codec";
const char kSupportedVideoCodec[] = "video_codec";
const char kUnsupportedCodec[] = "unsupported_codec";
const char kInvalidCodec[] = "foo";
const char kRequireHwSecureCodec[] = "require_hw_secure_codec";
const char kDisallowHwSecureCodec[] = "disallow_hw_secure_codec";
const char kExtendedVideoCodec[] = "video_extended_codec.extended";
const char kExtendedVideoCodecStripped[] = "video_extended_codec";
// A special codec that is supported by the key systems, but is not supported
// in IsSupportedMediaType() when |use_aes_decryptor| is true.
const char kUnsupportedByAesDecryptorCodec[] = "unsupported_by_aes_decryptor";

// Encryption schemes. For testing 'cenc' is supported, while 'cbcs' is not.
// Note that WebMediaKeySystemMediaCapability defaults to kNotSpecified,
// which is treated as 'cenc' by KeySystemConfigSelector.
constexpr EncryptionScheme kSupportedEncryptionScheme = EncryptionScheme::kCenc;
constexpr EncryptionScheme kDisallowHwSecureCodecEncryptionScheme =
    EncryptionScheme::kCbcs;

media::EncryptionScheme ConvertEncryptionScheme(
    EncryptionScheme encryption_scheme) {
  switch (encryption_scheme) {
    case EncryptionScheme::kNotSpecified:
    case EncryptionScheme::kCenc:
      return media::EncryptionScheme::kCenc;
    case EncryptionScheme::kCbcs:
    case EncryptionScheme::kCbcs_1_9:
      return media::EncryptionScheme::kCbcs;
    case EncryptionScheme::kUnrecognized:
      // Not used in these tests.
      break;
  }

  NOTREACHED();
}

WebString MakeCodecs(const std::string& a, const std::string& b) {
  return WebString::FromUTF8(a + "," + b);
}

WebString GetSupportedVideoCodecs() {
  return MakeCodecs(kSupportedVideoCodec, kSupportedVideoCodec);
}

WebString GetSubsetSupportedVideoCodecs() {
  return MakeCodecs(kSupportedVideoCodec, kUnsupportedCodec);
}

WebString GetSubsetInvalidVideoCodecs() {
  return MakeCodecs(kSupportedVideoCodec, kInvalidCodec);
}

bool IsValidContainerMimeType(const std::string& container_mime_type) {
  return container_mime_type != kInvalidContainer;
}

bool IsValidCodec(const std::string& codec) {
  return codec != kInvalidCodec;
}

// Returns whether |type| is compatible with |media_type|.
bool IsCompatibleWithEmeMediaType(EmeMediaType media_type,
                                  const std::string& type) {
  if (media_type == EmeMediaType::AUDIO && base::MatchPattern(type, "video*"))
    return false;

  if (media_type == EmeMediaType::VIDEO && base::MatchPattern(type, "audio*"))
    return false;

  return true;
}

// Pretend that we support all |container_mime_type| and |codecs| except for
// those explicitly marked as invalid.
bool IsSupportedMediaType(const std::string& container_mime_type,
                          const std::string& codecs,
                          bool use_aes_decryptor) {
  if (container_mime_type == kInvalidContainer)
    return false;

  std::vector<std::string> codec_vector;
  media::SplitCodecs(codecs, &codec_vector);
  for (const std::string& codec : codec_vector) {
    DCHECK_NE(codec, kExtendedVideoCodecStripped)
        << "codecs passed into this function should not be stripped";

    if (codec == kInvalidCodec)
      return false;

    if (use_aes_decryptor && codec == kUnsupportedByAesDecryptorCodec)
      return false;
  }

  return true;
}

// The IDL for MediaKeySystemConfiguration specifies some defaults, so
// create a config object that mimics what would be created if an empty
// dictionary was passed in.
WebMediaKeySystemConfiguration EmptyConfiguration() {
  // http://w3c.github.io/encrypted-media/#mediakeysystemconfiguration-dictionary
  // If this member (sessionTypes) is not present when the dictionary
  // is passed to requestMediaKeySystemAccess(), the dictionary will
  // be treated as if this member is set to [ "temporary" ].
  std::vector<WebEncryptedMediaSessionType> session_types;
  session_types.push_back(WebEncryptedMediaSessionType::kTemporary);

  WebMediaKeySystemConfiguration config;
  config.label = "";
  config.session_types = session_types;
  return config;
}

// EME spec requires that at least one of |video_capabilities| and
// |audio_capabilities| be specified. Add a single valid audio capability
// to the EmptyConfiguration().
WebMediaKeySystemConfiguration UsableConfiguration() {
  // Blink code parses the contentType into mimeType and codecs, so mimic
  // that here.
  std::vector<WebMediaKeySystemMediaCapability> audio_capabilities(1);
  audio_capabilities[0].mime_type = kSupportedAudioContainer;
  audio_capabilities[0].codecs = kSupportedAudioCodec;

  auto config = EmptyConfiguration();
  config.audio_capabilities = audio_capabilities;
  return config;
}

class FakeKeySystems : public media::KeySystems {
 public:
  ~FakeKeySystems() override = default;

  void UpdateIfNeeded(base::OnceClosure done_cb) override {
    // Call the callback directly since it's always up to date.
    std::move(done_cb).Run();
  }

  std::string GetBaseKeySystemName(
      const std::string& key_system) const override {
    DCHECK(IsSupportedKeySystem(key_system));
    return key_system == kSupportedSubKeySystem ? kSupportedKeySystem
                                                : key_system;
  }

  bool IsSupportedKeySystem(const std::string& key_system) const override {
    // Based on EME spec, Clear Key key system is always supported.
    return key_system == media::kClearKeyKeySystem ||
           key_system == kSupportedKeySystem ||
           key_system == kSupportedSubKeySystem;
  }

  bool ShouldUseBaseKeySystemName(
      const std::string& key_system) const override {
    return key_system == kSupportedSubKeySystem;
  }

  bool CanUseAesDecryptor(const std::string& key_system) const override {
    return key_system == media::kClearKeyKeySystem;
  }

  // TODO(sandersd): Move implementation into KeySystemConfigSelector?
  bool IsSupportedInitDataType(const std::string& key_system,
                               EmeInitDataType init_data_type) const override {
    switch (init_data_type) {
      case EmeInitDataType::UNKNOWN:
        return false;
      case EmeInitDataType::WEBM:
        return init_data_type_webm_supported_;
      case EmeInitDataType::CENC:
        return init_data_type_cenc_supported_;
      case EmeInitDataType::KEYIDS:
        return init_data_type_keyids_supported_;
    }
    NOTREACHED();
  }

  EmeConfig::Rule GetEncryptionSchemeConfigRule(
      const std::string& key_system,
      media::EncryptionScheme encryption_scheme) const override {
    if (encryption_scheme ==
        ConvertEncryptionScheme(kSupportedEncryptionScheme)) {
      return EmeConfig::SupportedRule();
    }

    if (encryption_scheme ==
        ConvertEncryptionScheme(kDisallowHwSecureCodecEncryptionScheme)) {
      return EmeConfig{.hw_secure_codecs = EmeConfigRuleState::kNotAllowed};
    }

    return EmeConfig::UnsupportedRule();
  }

  EmeConfig::Rule GetContentTypeConfigRule(
      const std::string& key_system,
      EmeMediaType media_type,
      const std::string& container_mime_type,
      const std::vector<std::string>& codecs) const override {
    DCHECK(IsValidContainerMimeType(container_mime_type))
        << "Invalid container mime type should not be passed in";

    if (container_mime_type == kUnsupportedContainer ||
        !IsCompatibleWithEmeMediaType(media_type, container_mime_type)) {
      return EmeConfig::UnsupportedRule();
    }

    bool hw_secure_codec_required_ = false;
    bool hw_secure_codec_not_allowed_ = false;

    for (const std::string& codec : codecs) {
      DCHECK(IsValidCodec(codec)) << "Invalid codec should not be passed in";

      if (codec == kUnsupportedCodec ||
          !IsCompatibleWithEmeMediaType(media_type, codec)) {
        return EmeConfig::UnsupportedRule();
      } else if (codec == kRequireHwSecureCodec) {
        hw_secure_codec_required_ = true;
      } else if (codec == kDisallowHwSecureCodec) {
        hw_secure_codec_not_allowed_ = true;
      }
    }

    if (hw_secure_codec_required_) {
      if (hw_secure_codec_not_allowed_) {
        return EmeConfig::UnsupportedRule();
      } else {
        return EmeConfig{.hw_secure_codecs = EmeConfigRuleState::kRequired};
      }
    }

    if (hw_secure_codec_not_allowed_) {
      return EmeConfig{.hw_secure_codecs = EmeConfigRuleState::kNotAllowed};
    }

    return EmeConfig::SupportedRule();
  }

  EmeConfig::Rule GetRobustnessConfigRule(
      const std::string& key_system,
      EmeMediaType media_type,
      const std::string& requested_robustness,
      const bool* hw_secure_requirement) const override {
    // TODO(crbug.com/1204284): Remove the `hw_secure_requirement` parameter.
    // This only exists as a temporary solution until a larger refactoring is
    // done. We are only testing the explicit thing it is fixing here.
    if (hw_secure_requirement && *hw_secure_requirement &&
        distinctive_identifier == EmeFeatureSupport::NOT_SUPPORTED) {
      return EmeConfig::UnsupportedRule();
    }
    if (requested_robustness.empty() ||
        requested_robustness == kSupportedRobustness) {
      return EmeConfig::SupportedRule();
    }
    if (requested_robustness == kRequireIdentifierRobustness) {
      return EmeConfig{.identifier = EmeConfigRuleState::kRequired};
    }
    if (requested_robustness == kRecommendIdentifierRobustness) {
      return EmeConfig{.identifier = EmeConfigRuleState::kRecommended};
    }
    if (requested_robustness == kDisallowHwSecureCodecRobustness) {
      return EmeConfig{.hw_secure_codecs = EmeConfigRuleState::kNotAllowed};
    }
    if (requested_robustness == kRequireHwSecureCodecRobustness) {
      return EmeConfig{.hw_secure_codecs = EmeConfigRuleState::kRequired};
    }
    if (requested_robustness == kRequireIdentifierAndHwSecureCodecRobustness) {
      return EmeConfig{.identifier = EmeConfigRuleState::kRequired,
                       .hw_secure_codecs = EmeConfigRuleState::kRequired};
    }
    if (requested_robustness ==
        kRequireIdentifierPersistenceAndHwSecureCodecRobustness) {
      return EmeConfig{.identifier = EmeConfigRuleState::kRequired,
                       .persistence = EmeConfigRuleState::kRequired,
                       .hw_secure_codecs = EmeConfigRuleState::kRequired};
    }
    if (requested_robustness == kUnsupportedRobustness) {
      return EmeConfig::UnsupportedRule();
    }

    NOTREACHED();
  }

  EmeConfig::Rule GetPersistentLicenseSessionSupport(
      const std::string& key_system) const override {
    return persistent_license;
  }

  EmeFeatureSupport GetPersistentStateSupport(
      const std::string& key_system) const override {
    return persistent_state;
  }

  EmeFeatureSupport GetDistinctiveIdentifierSupport(
      const std::string& key_system) const override {
    return distinctive_identifier;
  }

  bool init_data_type_webm_supported_ = false;
  bool init_data_type_cenc_supported_ = false;
  bool init_data_type_keyids_supported_ = false;

  EmeConfig::Rule persistent_license = EmeConfig::UnsupportedRule();

  // Every test implicitly requires these, so they must be set. They are set to
  // values that are likely to cause tests to fail if they are accidentally
  // depended on. Test cases explicitly depending on them should set them, as
  // the default values may be changed.
  EmeFeatureSupport persistent_state = EmeFeatureSupport::NOT_SUPPORTED;
  EmeFeatureSupport distinctive_identifier = EmeFeatureSupport::REQUESTABLE;
};

class FakeMediaPermission : public media::MediaPermission {
 public:
  // MediaPermission implementation.
  void HasPermission(Type type,
                     PermissionStatusCB permission_status_cb) override {
    std::move(permission_status_cb).Run(is_granted);
  }

  void RequestPermission(Type type,
                         PermissionStatusCB permission_status_cb) override {
    requests++;
    std::move(permission_status_cb).Run(is_granted);
  }

  bool IsEncryptedMediaEnabled() override { return is_encrypted_media_enabled; }

#if BUILDFLAG(IS_WIN)
  void IsHardwareSecureDecryptionAllowed(
      IsHardwareSecureDecryptionAllowedCB cb) override {
    std::move(cb).Run(is_hardware_secure_decryption_allowed);
  }
#endif  // BUILDFLAG(IS_WIN)

  int requests = 0;
  bool is_granted = false;
  bool is_encrypted_media_enabled = true;
#if BUILDFLAG(IS_WIN)
  bool is_hardware_secure_decryption_allowed = true;
#endif  // BUILDFLAG(IS_WIN)
};

class FakeWebLocalFrameDelegate
    : public KeySystemConfigSelector::WebLocalFrameDelegate {
 public:
  FakeWebLocalFrameDelegate()
      : KeySystemConfigSelector::WebLocalFrameDelegate(nullptr) {}
  bool IsCrossOriginToOutermostMainFrame() override { return is_cross_origin_; }
  bool AllowStorageAccessSync(
      WebContentSettingsClient::StorageType storage_type) override {
    if (storage_type == WebContentSettingsClient::StorageType::kIndexedDB) {
      return local_storage_allowed_;
    }
    return true;
  }

  bool is_cross_origin_ = false;
  bool local_storage_allowed_ = true;
};

}  // namespace

class KeySystemConfigSelectorTest : public testing::Test {
 public:
  KeySystemConfigSelectorTest()
      : key_systems_(std::make_unique<FakeKeySystems>()),
        media_permission_(std::make_unique<FakeMediaPermission>()),
        web_frame_delegate_(std::make_unique<FakeWebLocalFrameDelegate>()) {}
  KeySystemConfigSelectorTest(const KeySystemConfigSelectorTest&) = delete;
  KeySystemConfigSelectorTest& operator=(const KeySystemConfigSelectorTest&) =
      delete;

  void SelectConfig() {
    media_permission_->requests = 0;
    succeeded_count_ = 0;
    not_supported_count_ = 0;
    KeySystemConfigSelector key_system_config_selector(
        key_systems_.get(), media_permission_.get(),
        std::move(web_frame_delegate_));
    // Replace the delegate with a new one to handle tests that call this
    // method multiple times. This is safe because they don't use the delegate
    // in testing.
    web_frame_delegate_ = std::make_unique<FakeWebLocalFrameDelegate>();

    key_system_config_selector.SetIsSupportedMediaTypeCBForTesting(
        base::BindRepeating(&IsSupportedMediaType));

    key_system_config_selector.SelectConfig(
        key_system_, configs_,
        base::BindOnce(&KeySystemConfigSelectorTest::OnConfigSelected,
                       base::Unretained(this)));
  }

  void SelectConfigReturnsConfig() {
    SelectConfig();
    EXPECT_EQ(0, media_permission_->requests);
    EXPECT_EQ(1, succeeded_count_);
    EXPECT_EQ(0, not_supported_count_);
    ASSERT_NE(succeeded_count_, 0);
  }

  void SelectConfigReturnsError() {
    SelectConfig();
    EXPECT_EQ(0, media_permission_->requests);
    EXPECT_EQ(0, succeeded_count_);
    EXPECT_EQ(1, not_supported_count_);
    ASSERT_NE(not_supported_count_, 0);
  }

  void SelectConfigRequestsPermissionAndReturnsConfig() {
    SelectConfig();
    EXPECT_EQ(1, media_permission_->requests);
    EXPECT_EQ(1, succeeded_count_);
    EXPECT_EQ(0, not_supported_count_);
    ASSERT_NE(media_permission_->requests, 0);
    ASSERT_NE(succeeded_count_, 0);
  }

  void SelectConfigRequestsPermissionAndReturnsError() {
    SelectConfig();
    EXPECT_EQ(1, media_permission_->requests);
    EXPECT_EQ(0, succeeded_count_);
    EXPECT_EQ(1, not_supported_count_);
    ASSERT_NE(media_permission_->requests, 0);
    ASSERT_NE(not_supported_count_, 0);
  }

  void OnConfigSelected(KeySystemConfigSelector::Status status,
                        WebMediaKeySystemConfiguration* config,
                        media::CdmConfig* cdm_config) {
    if (status == KeySystemConfigSelector::Status::kSupported) {
      succeeded_count_++;
      config_ = *config;
      cdm_config_ = *cdm_config;
    } else {
      not_supported_count_++;
    }
  }

  std::unique_ptr<FakeKeySystems> key_systems_;
  std::unique_ptr<FakeMediaPermission> media_permission_;
  std::unique_ptr<FakeWebLocalFrameDelegate> web_frame_delegate_;

  // Held values for the call to SelectConfig().
  WebString key_system_ = WebString::FromUTF8(kSupportedKeySystem);
  std::vector<WebMediaKeySystemConfiguration> configs_;

  // Holds the selected key system, configuration and CdmConfig.
  WebMediaKeySystemConfiguration config_;
  media::CdmConfig cdm_config_;

  int succeeded_count_;
  int not_supported_count_;
};

// --- Basics ---

TEST_F(KeySystemConfigSelectorTest, NoConfigs) {
  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, DefaultConfig) {
  auto config = EmptyConfiguration();

  // label = "";
  ASSERT_EQ("", config.label);

  // initDataTypes = [];
  ASSERT_EQ(0u, config.init_data_types.size());

  // audioCapabilities = [];
  ASSERT_EQ(0u, config.audio_capabilities.size());

  // videoCapabilities = [];
  ASSERT_EQ(0u, config.video_capabilities.size());

  // distinctiveIdentifier = "optional";
  ASSERT_EQ(MediaKeysRequirement::kOptional, config.distinctive_identifier);

  // persistentState = "optional";
  ASSERT_EQ(MediaKeysRequirement::kOptional, config.persistent_state);

  // If this member is not present when the dictionary is passed to
  // requestMediaKeySystemAccess(), the dictionary will be treated as
  // if this member is set to [ "temporary" ].
  ASSERT_EQ(1u, config.session_types.size());
  ASSERT_EQ(WebEncryptedMediaSessionType::kTemporary, config.session_types[0]);
}

TEST_F(KeySystemConfigSelectorTest, EmptyConfig) {
  // EME spec requires that at least one of |video_capabilities| and
  // |audio_capabilities| be specified.
  configs_.push_back(EmptyConfiguration());
  SelectConfigReturnsError();
}

// Most of the tests below assume that the the usable config is valid.
// Tests that touch |video_capabilities| and/or |audio_capabilities| can
// modify the empty config.

TEST_F(KeySystemConfigSelectorTest, UsableConfig) {
  configs_.push_back(UsableConfiguration());

  SelectConfigReturnsConfig();

  EXPECT_EQ("", config_.label);
  EXPECT_TRUE(config_.init_data_types.empty());
  EXPECT_EQ(1u, config_.audio_capabilities.size());
  EXPECT_TRUE(config_.video_capabilities.empty());
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.distinctive_identifier);
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.persistent_state);
  ASSERT_EQ(1u, config_.session_types.size());
  EXPECT_EQ(WebEncryptedMediaSessionType::kTemporary, config_.session_types[0]);

  EXPECT_FALSE(cdm_config_.allow_distinctive_identifier);
  EXPECT_FALSE(cdm_config_.allow_persistent_state);
  EXPECT_FALSE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, Label) {
  auto config = UsableConfiguration();
  config.label = "foo";
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ("foo", config_.label);
}

// --- keySystem ---
// Empty is not tested because the empty check is in Blink.

TEST_F(KeySystemConfigSelectorTest, KeySystem_NonAscii) {
  key_system_ = "\xde\xad\xbe\xef";
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, KeySystem_Unsupported) {
  key_system_ = kUnsupportedKeySystem;
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, KeySystem_ClearKey) {
  key_system_ = media::kClearKeyKeySystem;
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsConfig();
  DCHECK_EQ(cdm_config_.key_system, media::kClearKeyKeySystem);
}

TEST_F(KeySystemConfigSelectorTest, KeySystem_SubKeySystem) {
  key_system_ = kSupportedSubKeySystem;
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsConfig();
  DCHECK_EQ(cdm_config_.key_system, kSupportedKeySystem);
}

// --- Disable EncryptedMedia ---

TEST_F(KeySystemConfigSelectorTest, EncryptedMediaDisabled_ClearKey) {
  media_permission_->is_encrypted_media_enabled = false;

  // Clear Key key system is always supported.
  key_system_ = media::kClearKeyKeySystem;
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsConfig();
}

TEST_F(KeySystemConfigSelectorTest, EncryptedMediaDisabled_Supported) {
  media_permission_->is_encrypted_media_enabled = false;

  // Other key systems are not supported.
  key_system_ = kSupportedKeySystem;
  configs_.push_back(UsableConfiguration());
  SelectConfigReturnsError();
}

// --- initDataTypes ---

TEST_F(KeySystemConfigSelectorTest, InitDataTypes_Empty) {
  auto config = UsableConfiguration();
  configs_.push_back(config);

  SelectConfigReturnsConfig();
}

TEST_F(KeySystemConfigSelectorTest, InitDataTypes_NoneSupported) {
  key_systems_->init_data_type_webm_supported_ = true;

  std::vector<EmeInitDataType> init_data_types;
  init_data_types.push_back(EmeInitDataType::UNKNOWN);
  init_data_types.push_back(EmeInitDataType::CENC);

  auto config = UsableConfiguration();
  config.init_data_types = init_data_types;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, InitDataTypes_SubsetSupported) {
  key_systems_->init_data_type_webm_supported_ = true;

  std::vector<EmeInitDataType> init_data_types;
  init_data_types.push_back(EmeInitDataType::UNKNOWN);
  init_data_types.push_back(EmeInitDataType::CENC);
  init_data_types.push_back(EmeInitDataType::WEBM);

  auto config = UsableConfiguration();
  config.init_data_types = init_data_types;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.init_data_types.size());
  EXPECT_EQ(EmeInitDataType::WEBM, config_.init_data_types[0]);
}

// --- distinctiveIdentifier ---

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_Default) {
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.distinctive_identifier);
  EXPECT_FALSE(cdm_config_.allow_distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_Forced) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::ALWAYS_ENABLED;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  EXPECT_TRUE(cdm_config_.allow_distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_Blocked) {
  key_systems_->distinctive_identifier = EmeFeatureSupport::NOT_SUPPORTED;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_RequestsPermission) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  EXPECT_TRUE(cdm_config_.allow_distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_RespectsPermission) {
  media_permission_->is_granted = false;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, DistinctiveIdentifier_DefaultCrossOrigin) {
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;
  web_frame_delegate_->is_cross_origin_ = true;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.distinctive_identifier);
  EXPECT_FALSE(cdm_config_.allow_distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest,
       DistinctiveIdentifier_ForcedBlockedByCrossOrigin) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::ALWAYS_ENABLED;
  web_frame_delegate_->is_cross_origin_ = true;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

#if BUILDFLAG(IS_ANDROID)
  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  EXPECT_TRUE(cdm_config_.allow_distinctive_identifier);
#else
  SelectConfigReturnsError();
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(KeySystemConfigSelectorTest,
       DistinctiveIdentifier_RequestsPermissionBlockedByCrossOrigin) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;
  web_frame_delegate_->is_cross_origin_ = true;

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

#if BUILDFLAG(IS_ANDROID)
  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  EXPECT_TRUE(cdm_config_.allow_distinctive_identifier);
#else
  SelectConfigReturnsError();
#endif  // BUILDFLAG(IS_ANDROID)
}

// --- persistentState ---

TEST_F(KeySystemConfigSelectorTest, PersistentState_Default) {
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.persistent_state);
  EXPECT_FALSE(cdm_config_.allow_persistent_state);
}

TEST_F(KeySystemConfigSelectorTest, PersistentState_Forced) {
  key_systems_->persistent_state = EmeFeatureSupport::ALWAYS_ENABLED;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.persistent_state);
  EXPECT_TRUE(cdm_config_.allow_persistent_state);
}

TEST_F(KeySystemConfigSelectorTest, PersistentState_Required) {
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.persistent_state);
  EXPECT_TRUE(cdm_config_.allow_persistent_state);
}

TEST_F(KeySystemConfigSelectorTest, PersistentState_Blocked) {
  key_systems_->persistent_state = EmeFeatureSupport::ALWAYS_ENABLED;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kNotAllowed;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, PersistentState_BlockedByContentSettings) {
  key_systems_->persistent_state = EmeFeatureSupport::ALWAYS_ENABLED;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  web_frame_delegate_->local_storage_allowed_ = false;
  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       PersistentState_ForcedBlockedByContentSettings) {
  key_systems_->persistent_state = EmeFeatureSupport::ALWAYS_ENABLED;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kOptional;
  configs_.push_back(config);

  web_frame_delegate_->local_storage_allowed_ = false;
  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       PersistentState_RequiredBlockedByContentSettings) {
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kRequired;
  configs_.push_back(config);

  web_frame_delegate_->local_storage_allowed_ = false;
  SelectConfigReturnsError();
}

// --- sessionTypes ---

TEST_F(KeySystemConfigSelectorTest, SessionTypes_Empty) {
  auto config = UsableConfiguration();

  // Usable configuration has [ "temporary" ].
  std::vector<WebEncryptedMediaSessionType> session_types;
  config.session_types = session_types;

  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_TRUE(config_.session_types.empty());
}

TEST_F(KeySystemConfigSelectorTest, SessionTypes_SubsetSupported) {
  // Allow persistent state, as it would be required to be successful.
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;
  key_systems_->persistent_license = EmeConfig::UnsupportedRule();

  std::vector<WebEncryptedMediaSessionType> session_types;
  session_types.push_back(WebEncryptedMediaSessionType::kTemporary);
  session_types.push_back(WebEncryptedMediaSessionType::kPersistentLicense);

  auto config = UsableConfiguration();
  config.session_types = session_types;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, SessionTypes_AllSupported) {
  // Allow persistent state, and expect it to be required.
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;
  key_systems_->persistent_license = EmeConfig::SupportedRule();

  std::vector<WebEncryptedMediaSessionType> session_types;
  session_types.push_back(WebEncryptedMediaSessionType::kTemporary);
  session_types.push_back(WebEncryptedMediaSessionType::kPersistentLicense);

  auto config = UsableConfiguration();
  config.persistent_state = MediaKeysRequirement::kOptional;
  config.session_types = session_types;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.persistent_state);
  ASSERT_EQ(2u, config_.session_types.size());
  EXPECT_EQ(WebEncryptedMediaSessionType::kTemporary, config_.session_types[0]);
  EXPECT_EQ(WebEncryptedMediaSessionType::kPersistentLicense,
            config_.session_types[1]);
}

TEST_F(KeySystemConfigSelectorTest, SessionTypes_PermissionCanBeRequired) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;
  key_systems_->persistent_license =
      EmeConfig{.identifier = EmeConfigRuleState::kRequired,
                .persistence = EmeConfigRuleState::kRequired};

  std::vector<WebEncryptedMediaSessionType> session_types;
  session_types.push_back(WebEncryptedMediaSessionType::kPersistentLicense);

  auto config = UsableConfiguration();
  config.distinctive_identifier = MediaKeysRequirement::kOptional;
  config.persistent_state = MediaKeysRequirement::kOptional;
  config.session_types = session_types;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
}

// --- videoCapabilities ---

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Empty) {
  auto config = UsableConfiguration();
  configs_.push_back(config);

  SelectConfigReturnsConfig();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_ExtendedCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kExtendedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_InvalidContainer) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kInvalidContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_UnsupportedContainer) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kUnsupportedContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_IncompatibleContainer) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedAudioContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_InvalidCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kInvalidCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_UnsupportedCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kInvalidContainer;
  video_capabilities[0].codecs = kUnsupportedCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_IncompatibleCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedAudioCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_UnsupportedByAesDecryptorCodec_ClearKey) {
  key_system_ = media::kClearKeyKeySystem;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kUnsupportedByAesDecryptorCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_UnsupportedByAesDecryptorCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kUnsupportedByAesDecryptorCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_SubsetSupported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kInvalidContainer;
  video_capabilities[1].content_type = "b";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("b", config_.video_capabilities[0].content_type);
  EXPECT_EQ(kSupportedVideoContainer, config_.video_capabilities[0].mime_type);
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_AllSupported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = GetSupportedVideoCodecs();
  video_capabilities[1].content_type = "b";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = GetSupportedVideoCodecs();

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(2u, config_.video_capabilities.size());
  EXPECT_EQ("a", config_.video_capabilities[0].content_type);
  EXPECT_EQ("b", config_.video_capabilities[1].content_type);
}

// --- videoCapabilities Codecs ---

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Codecs_SubsetInvalid) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = GetSubsetInvalidVideoCodecs();

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Codecs_SubsetSupported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = GetSubsetSupportedVideoCodecs();

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Codecs_AllSupported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = GetSupportedVideoCodecs();

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ(GetSupportedVideoCodecs(), config_.video_capabilities[0].codecs);
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Missing_Codecs) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

// --- videoCapabilities Robustness ---

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Robustness_Empty) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  ASSERT_TRUE(video_capabilities[0].robustness.IsEmpty());

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_TRUE(config_.video_capabilities[0].robustness.IsEmpty());
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Robustness_Supported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kSupportedRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ(kSupportedRobustness, config_.video_capabilities[0].robustness);
}

TEST_F(KeySystemConfigSelectorTest, VideoCapabilities_Robustness_Unsupported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kUnsupportedRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_Robustness_PermissionCanBeRequired) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kRequireIdentifierRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_Robustness_PermissionCanBeRecommended) {
  media_permission_->is_granted = false;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kRecommendIdentifierRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_Robustness_PermissionCanBeRecommendedAndGranted) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kRecommendIdentifierRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_Robustness_NoPermissionRecommendedCrossOrigin) {
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;
  web_frame_delegate_->is_cross_origin_ = true;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kRecommendIdentifierRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

#if BUILDFLAG(IS_ANDROID)
  SelectConfigRequestsPermissionAndReturnsConfig();
#else
  SelectConfigReturnsConfig();
#endif  // BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(MediaKeysRequirement::kNotAllowed, config_.distinctive_identifier);
  ASSERT_EQ(1u, config_.video_capabilities.size());
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_EncryptionScheme_Supported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].encryption_scheme = kSupportedEncryptionScheme;

  WebMediaKeySystemConfiguration config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ(kSupportedEncryptionScheme,
            config_.video_capabilities[0].encryption_scheme);
}

TEST_F(KeySystemConfigSelectorTest,
       VideoCapabilities_EncryptionScheme_DisallowHwSecureCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].encryption_scheme =
      kDisallowHwSecureCodecEncryptionScheme;

  WebMediaKeySystemConfiguration config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ(kDisallowHwSecureCodecEncryptionScheme,
            config_.video_capabilities[0].encryption_scheme);
}

// --- HW Secure Codecs and Robustness ---

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_RequireHwSecureCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_DisallowHwSecureCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_FALSE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       HwSecureCodec_IncompatibleCodecAndRobustness) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;
  video_capabilities[0].robustness = kRequireHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_CompatibleCodecs) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs =
      MakeCodecs(kRequireHwSecureCodec, kSupportedVideoCodec);

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_IncompatibleCodecs) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs =
      MakeCodecs(kRequireHwSecureCodec, kDisallowHwSecureCodec);

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_CompatibleCapabilityCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;
  video_capabilities[1].content_type = "supported_video_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(2u, config_.video_capabilities.size());
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_RequireAndDisallow) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;
  video_capabilities[1].content_type = "disallow_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kDisallowHwSecureCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_DisallowAndRequire) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "disallow_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;
  video_capabilities[1].content_type = "require_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kRequireHwSecureCodec;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("disallow_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_FALSE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_IncompatibleCapabilities) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness = kRequireHwSecureCodecRobustness;
  video_capabilities[1].content_type = "disallow_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kDisallowHwSecureCodec;
  video_capabilities[1].robustness = kUnsupportedRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       HwSecureCodec_UnsupportedCapabilityNotAffectingRules) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "unsupported_robustness";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;
  video_capabilities[0].robustness = kUnsupportedRobustness;
  video_capabilities[1].content_type = "require_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kRequireHwSecureCodec;
  video_capabilities[1].robustness = kRequireHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest, HwSecureCodec_EncryptionScheme_Supported) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;
  video_capabilities[0].encryption_scheme = kSupportedEncryptionScheme;

  WebMediaKeySystemConfiguration config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ(kSupportedEncryptionScheme,
            config_.video_capabilities[0].encryption_scheme);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       HwSecureCodec_EncryptionScheme_DisallowHwSecureCodec) {
  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;
  video_capabilities[0].encryption_scheme =
      kDisallowHwSecureCodecEncryptionScheme;

  WebMediaKeySystemConfiguration config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

// --- Identifier and HW Secure Robustness ---

TEST_F(KeySystemConfigSelectorTest,
       IdentifierAndHwSecureCodec_IncompatibleCodecAndRobustness) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "a";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;
  video_capabilities[0].robustness =
      kRequireIdentifierAndHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

TEST_F(KeySystemConfigSelectorTest,
       IdentifierAndHwSecureCodec_IncompatibleCapabilities) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness =
      kRequireIdentifierAndHwSecureCodecRobustness;
  video_capabilities[1].content_type = "disallow_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kDisallowHwSecureCodec;
  video_capabilities[1].robustness = kUnsupportedRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       IdentifierAndHwSecureCodec_UnsupportedCapabilityNotAffectingRules) {
  media_permission_->is_granted = true;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "unsupported_robustness";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kDisallowHwSecureCodec;
  video_capabilities[0].robustness = kUnsupportedRobustness;
  video_capabilities[1].content_type = "require_hw_secure_codec";
  video_capabilities[1].mime_type = kSupportedVideoContainer;
  video_capabilities[1].codecs = kRequireHwSecureCodec;
  video_capabilities[1].robustness =
      kRequireIdentifierAndHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       HwSecureCodecAndIdentifier_IdentifierAndHwSecureCodecsDisjoint) {
  media_permission_->is_granted = false;
  key_systems_->distinctive_identifier = EmeFeatureSupport::NOT_SUPPORTED;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(2);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kRequireHwSecureCodec;
  video_capabilities[0].robustness = "";

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

// --- Identifier, Persistence and HW Secure Robustness ---

TEST_F(KeySystemConfigSelectorTest,
       IdentifierPersistenceAndHwSecureCodec_Supported) {
  media_permission_->is_granted = true;
  key_systems_->persistent_state = EmeFeatureSupport::REQUESTABLE;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness =
      kRequireIdentifierPersistenceAndHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigRequestsPermissionAndReturnsConfig();
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.distinctive_identifier);
  EXPECT_EQ(MediaKeysRequirement::kRequired, config_.persistent_state);
  ASSERT_EQ(1u, config_.video_capabilities.size());
  EXPECT_EQ("require_hw_secure_codec",
            config_.video_capabilities[0].content_type);
  EXPECT_TRUE(cdm_config_.use_hw_secure_codecs);
}

TEST_F(KeySystemConfigSelectorTest,
       IdentifierPersistenceAndHwSecureCodec_NotSupported) {
  media_permission_->is_granted = true;
  key_systems_->persistent_state = EmeFeatureSupport::NOT_SUPPORTED;
  key_systems_->distinctive_identifier = EmeFeatureSupport::REQUESTABLE;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "require_hw_secure_codec";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;
  video_capabilities[0].robustness =
      kRequireIdentifierPersistenceAndHwSecureCodecRobustness;

  auto config = EmptyConfiguration();
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsError();
}

// --- audioCapabilities ---
// These are handled by the same code as |videoCapabilities|, so only minimal
// additional testing is done.

TEST_F(KeySystemConfigSelectorTest, AudioCapabilities_SubsetSupported) {
  std::vector<WebMediaKeySystemMediaCapability> audio_capabilities(2);
  audio_capabilities[0].content_type = "a";
  audio_capabilities[0].mime_type = kInvalidContainer;
  audio_capabilities[1].content_type = "b";
  audio_capabilities[1].mime_type = kSupportedAudioContainer;
  audio_capabilities[1].codecs = kSupportedAudioCodec;

  auto config = EmptyConfiguration();
  config.audio_capabilities = audio_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.audio_capabilities.size());
  EXPECT_EQ("b", config_.audio_capabilities[0].content_type);
  EXPECT_EQ(kSupportedAudioContainer, config_.audio_capabilities[0].mime_type);
}

// --- audioCapabilities and videoCapabilities ---

TEST_F(KeySystemConfigSelectorTest, AudioAndVideoCapabilities_AllSupported) {
  std::vector<WebMediaKeySystemMediaCapability> audio_capabilities(1);
  audio_capabilities[0].content_type = "a";
  audio_capabilities[0].mime_type = kSupportedAudioContainer;
  audio_capabilities[0].codecs = kSupportedAudioCodec;

  std::vector<WebMediaKeySystemMediaCapability> video_capabilities(1);
  video_capabilities[0].content_type = "b";
  video_capabilities[0].mime_type = kSupportedVideoContainer;
  video_capabilities[0].codecs = kSupportedVideoCodec;

  auto config = EmptyConfiguration();
  config.audio_capabilities = audio_capabilities;
  config.video_capabilities = video_capabilities;
  configs_.push_back(config);

  SelectConfigReturnsConfig();
  ASSERT_EQ(1u, config_.audio_capabilities.size());
  ASSERT_EQ(1u, config_.video_capabilities.size());
}

TEST_F(KeySystemConfigSelectorTest,
       AudioAndVideoCapabilities_AudioUnsupported) {
  std::vector<WebMediaKeySystemMediaCapability> audio_capabilities(1);
  audio_capabilities[0].content_type = "a";
  audio_capabilities
"""


```