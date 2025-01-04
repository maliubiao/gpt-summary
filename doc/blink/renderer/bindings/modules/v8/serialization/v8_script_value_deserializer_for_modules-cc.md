Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional analysis of the given C++ file, focusing on its purpose, relationship with web technologies (JavaScript, HTML, CSS), logical reasoning, potential user errors, and debugging context.

2. **Identify the Core Functionality:** The file name `v8_script_value_deserializer_for_modules.cc` immediately suggests its primary role: deserializing script values (likely JavaScript objects) within the Blink rendering engine, specifically for "modules." This implies handling objects that might be transferred between different parts of the browser or within a web page, particularly those related to newer web platform features often exposed through modules.

3. **Analyze Includes:** Examining the included header files provides crucial clues about the types of objects being handled:
    * `v8_script_value_deserializer_for_modules.h`:  Confirms this file's role as a deserializer.
    * `base/feature_list.h`, `third_party/blink/public/common/features.h`:  Indicates the use of feature flags, meaning some functionality might be conditional.
    * `mojom` files (e.g., `file_system_access_manager.mojom-blink.h`): Points to the use of Mojo for inter-process communication, specifically for features like File System Access API.
    * `platform/web_crypto.h`, `bindings/modules/v8/v8_crypto_key.h`, `modules/crypto/crypto_key.h`:  Clearly relates to the Web Crypto API.
    * `bindings/modules/v8/v8_dom_file_system.h`, `modules/filesystem/dom_file_system.h`, `modules/file_system_access/...`:  Indicates support for file system access APIs.
    * `bindings/modules/v8/v8_media_stream_track.h`, `modules/mediastream/...`:  Deals with Media Streams and related APIs.
    * `bindings/modules/v8/v8_rtc...h`, `modules/peerconnection/...`:  Handles WebRTC related objects.
    * `bindings/modules/v8/v8_encoded_audio_chunk.h`, `bindings/modules/v8/v8_encoded_video_chunk.h`, `modules/webcodecs/...`:  Supports the WebCodecs API.
    * `core/execution_context/execution_context.h`, `core/frame/local_dom_window.h`:  Relates to the core Blink rendering engine and execution environments.

4. **Examine the `ReadDOMObject` Function:** This is the central function for deserializing various types. The `switch` statement based on `SerializationTag` reveals the different object types handled. The calls to `Read...()` methods for each tag further solidify the understanding of which specific modules and APIs are supported. The initial call to the base class `V8ScriptValueDeserializer::ReadDOMObject` suggests a hierarchical deserialization process, with core types handled first.

5. **Analyze Helper Functions (e.g., `AlgorithmIdFromWireFormat`, `KeyUsagesFromWireFormat`):** These functions show how serialized data is interpreted and converted back into meaningful Web Crypto API concepts. This demonstrates the low-level details of the deserialization process.

6. **Identify Web Technology Relationships:** Based on the included headers and the types handled in `ReadDOMObject`, establish the connections to JavaScript, HTML, and CSS:
    * **JavaScript:** This is the primary interaction point. The deserializer converts serialized JavaScript objects back into their native Blink/C++ representations. Examples include `CryptoKey`, `FileSystemFileHandle`, `MediaStreamTrack`, etc., all of which have corresponding JavaScript APIs.
    * **HTML:** File system access relates to `<input type="file">` and drag-and-drop. Media streams are used with `<video>` and `<audio>` elements. WebRTC powers real-time communication features.
    * **CSS:** While not directly related in this *specific* file, the features handled (like media streams and file access) can influence how content is displayed and interacted with, which indirectly involves CSS styling.

7. **Consider Logical Reasoning (Hypothetical Input/Output):** For specific deserialization cases (like `CryptoKey`), imagine the serialized data format (implied by the `Read...` calls) and the resulting C++ object. This helps understand the data transformation.

8. **Identify Potential User/Programming Errors:** Think about what could go wrong during the serialization/deserialization process or when using these APIs in JavaScript:
    * Incorrect serialization format.
    * Feature flags being disabled.
    * Security restrictions (e.g., trying to access files without user permission).
    * Incorrect usage of the JavaScript APIs that lead to these objects being serialized.

9. **Trace User Operations (Debugging Clues):**  Think about how a user's actions in a web browser might lead to this deserialization code being executed. This often involves scenarios where data is being transferred or persisted:
    * Using `postMessage` to send complex objects between frames or workers.
    * Using IndexedDB to store and retrieve objects.
    * Using the File System Access API to interact with the local file system.
    * Establishing WebRTC connections.
    * Using the WebCodecs API for media processing.

10. **Structure the Answer:** Organize the findings into the requested categories: functionality, relationships with web technologies (with examples), logical reasoning (with hypothetical input/output), user/programming errors, and debugging clues.

11. **Refine and Elaborate:** Flesh out the descriptions with specific details. For instance, instead of just saying "Web Crypto API," mention specific key types and algorithms. For debugging, provide concrete steps a developer might take to reach this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file handles all kinds of deserialization.
* **Correction:** The name clearly states "for modules," indicating a specific subset of deserialization logic. The call to the base class deserializer confirms a layered approach.

* **Initial thought:** CSS is completely unrelated.
* **Refinement:** While not direct, recognize the indirect influence of these features on visual presentation and interaction.

* **Missing Detail:** Initially, I might not have fully grasped the significance of the Mojo pipes in the `FileSystemHandle` deserialization. Further analysis of the code reveals the inter-process communication aspect.

By following this structured thought process, iterating through the code, and making connections to web technologies, a comprehensive and accurate analysis can be generated.
这个C++源代码文件 `v8_script_value_deserializer_for_modules.cc` 是 Chromium Blink 引擎中负责反序列化（deserialization）特定类型 JavaScript 值的关键组件，尤其针对那些在模块 (modules) 上下文中使用的值。它的主要功能是将序列化后的二进制数据转换回 Blink 引擎可以理解的 C++ 对象，这些对象通常对应于 JavaScript 中的特定 API 类型。

**主要功能:**

1. **反序列化模块相关的 JavaScript 值:**  此文件专门处理与 Web 平台模块功能相关的 JavaScript 值的反序列化。这包括但不限于：
    * **Web Crypto API 对象:** `CryptoKey` (加密密钥)。
    * **File System Access API 对象:** `FileSystemFileHandle` (文件句柄), `FileSystemDirectoryHandle` (目录句柄)。
    * **WebRTC API 对象:** `RTCCertificate` (RTC 证书), `RTCDataChannel` (RTC 数据通道), `RTCEncodedAudioFrame` (RTC 编码音频帧), `RTCEncodedVideoFrame` (RTC 编码视频帧)。
    * **WebCodecs API 对象:** `AudioData` (音频数据), `VideoFrame` (视频帧), `EncodedAudioChunk` (编码音频块), `EncodedVideoChunk` (编码视频块)。
    * **Media Streams API 对象:** `MediaStreamTrack` (媒体流轨道), `CropTarget` (裁剪目标), `RestrictionTarget` (限制目标)。
    * **Media Source Extensions API 对象:** `MediaSourceHandle` (媒体源句柄)。
    * **FileSystem API (legacy):** `DOMFileSystem` (文件系统)。

2. **读取序列化数据:**  它从一个 `SerializedScriptValue` 对象中读取序列化的二进制数据，并根据数据的类型标签 (SerializationTag) 决定如何反序列化。

3. **创建 C++ 对象:**  根据读取到的数据，创建对应的 Blink 引擎内部的 C++ 对象实例。这些对象随后可以被 Blink 引擎用于渲染、处理用户交互或其他操作。

4. **处理附件 (Attachments):** 一些复杂对象可能包含额外的非结构化数据，例如 `RTCDataChannel` 的底层实现或 `AudioData` 的音频缓冲区。此反序列化器也负责处理这些“附件”。

5. **检查功能是否启用:**  通过 `RuntimeEnabledFeatures` 检查相关 Web 平台特性是否已启用。如果特性未启用，则不会尝试反序列化相应的对象，避免潜在的错误或安全问题。

**与 JavaScript, HTML, CSS 的关系及举例:**

此文件直接关联 JavaScript，因为它负责反序列化 JavaScript 值的 C++ 表示。间接与 HTML 和 CSS 相关，因为这些 JavaScript 值通常用于操作或表示 HTML 结构和 CSS 样式。

* **JavaScript:**
    * **例 1 (Web Crypto API):**  JavaScript 代码使用 `crypto.subtle.generateKey()` 生成一个加密密钥，这个密钥可以通过 `postMessage` 等机制传递到另一个上下文。在接收端，`V8ScriptValueDeserializerForModules` 会将序列化的密钥数据反序列化为 `CryptoKey` 对象。
    ```javascript
    // 发送端
    crypto.subtle.generateKey({
        name: "AES-CBC",
        length: 256
    }, true, ["encrypt", "decrypt"]).then(function(key){
        postMessage({ type: "cryptoKey", key: key });
    });

    // 接收端 (在 Blink 内部，当接收到消息时会触发反序列化)
    // ... V8ScriptValueDeserializerForModules 将 'key' 反序列化为 CryptoKey 对象 ...
    ```
    * **例 2 (File System Access API):** 用户通过 `<input type="file" multiple>` 选择文件后，JavaScript 可以获取 `FileSystemFileHandle` 对象。如果这个对象被序列化并传递，`V8ScriptValueDeserializerForModules` 会将其反序列化回 `FileSystemFileHandle`。
    ```html
    <input type="file" id="fileElem" multiple>
    <script>
    fileElem.addEventListener('change', function(e) {
        const files = e.target.files;
        for (const file of files) {
            file.getFile().then(fileHandle => {
                postMessage({ type: "fileHandle", handle: fileHandle });
            });
        }
    });
    </script>
    ```
    * **例 3 (WebRTC):**  在建立 WebRTC 连接时，`RTCCertificate` 对象会被创建和交换。当通过某些机制传递 `RTCCertificate` 时，此反序列化器会将其还原。

* **HTML:**
    * 当 JavaScript 使用反序列化后的 `FileSystemFileHandle` 读取文件内容时，这些内容可能最终用于更新 HTML 元素的内容（例如显示图片或文本）。
    * 反序列化的 `MediaStreamTrack` 对象可以被赋值给 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，从而在 HTML 中显示或播放媒体流。

* **CSS:**
    * 虽然此文件不直接操作 CSS，但反序列化后的数据可能会影响页面的布局和样式。例如，通过 `MediaStreamTrack` 获取的视频流的分辨率可能会影响包含它的 `<video>` 元素的默认尺寸，而 CSS 可以进一步调整其样式。

**逻辑推理及假设输入与输出:**

假设输入是一个包含序列化的 `CryptoKey` 数据的 `SerializedScriptValue` 对象，并且该密钥是使用 AES-CBC 算法生成的。

**假设输入 (序列化数据结构示意):**

```
SerializationTag::kCryptoKeyTag
kAesKeyTag // 表示 AES 密钥
kWebCryptoAlgorithmIdAesCbc 的枚举值 // AES 算法
256 / 8 // 密钥长度 (字节)
[密钥的原始二进制数据]
kEncryptUsage | kDecryptUsage // 密钥用途
true // 可导出
```

**输出:**

一个指向新创建的 `CryptoKey` 对象的指针，该对象是 `blink::CryptoKey` 的实例，其内部包含了反序列化后的密钥数据，算法为 AES-CBC，长度为 256 位，用途为加密和解密，并且可导出。

**用户或编程常见的使用错误及举例:**

1. **尝试反序列化不支持的类型:** 如果序列化数据中的 `SerializationTag` 不被 `V8ScriptValueDeserializerForModules` 处理（例如，属于核心 Blink 的类型但被错误地传递到模块反序列化器），则反序列化会失败，可能导致程序崩溃或逻辑错误。

2. **功能未启用:**  如果尝试反序列化某个类型，但该类型对应的 Web 平台特性在当前上下文中未启用（例如，尝试反序列化 `FileSystemFileHandle` 但 File System Access API 未启用），则反序列化会返回 `nullptr`。开发者需要确保在合适的上下文中使用这些 API。

3. **序列化数据损坏或不完整:** 如果传递的序列化数据在传输过程中损坏或被截断，反序列化过程可能会失败，导致读取错误或创建不完整的对象。

4. **类型版本不匹配:** 在极少数情况下，如果序列化和反序列化时 Blink 引擎的版本存在重大差异，导致序列化格式发生变化，可能会导致反序列化失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户操作触发 JavaScript API:** 用户在网页上执行操作，例如：
    * 点击按钮触发 Web Crypto API 的密钥生成或导入。
    * 通过 `<input type="file">` 选择文件，触发 File System Access API 获取文件句柄。
    * 建立 WebRTC 连接。
    * 使用 `postMessage` 在不同的浏览上下文（如 iframe 或 Web Worker）之间传递数据。
    * 使用 IndexedDB 存储和检索包含特定类型对象的 JavaScript 值。

2. **JavaScript 值被序列化:** 当这些 JavaScript 值需要跨越执行上下文边界（例如发送到 Web Worker）或需要持久化存储时，它们会被 Blink 引擎序列化为二进制数据。序列化的过程通常由 `V8ScriptValueSerializerForModules` 或类似的序列化器完成。

3. **序列化数据被传递或存储:**
    * 对于 `postMessage`，序列化后的数据会作为消息的一部分发送。
    * 对于 IndexedDB，序列化后的数据会被存储在数据库中。

4. **反序列化过程触发:** 当接收到包含序列化数据的消息（`postMessage`）或从 IndexedDB 读取数据时，Blink 引擎需要将这些二进制数据转换回 JavaScript 可以使用的对象。

5. **`V8ScriptValueDeserializerForModules` 被调用:**  Blink 引擎根据序列化数据中的类型标签，判断应该使用哪个反序列化器。对于模块相关的类型，会调用 `V8ScriptValueDeserializerForModules::ReadDOMObject`。

6. **读取和创建 C++ 对象:** `ReadDOMObject` 函数根据具体的 `SerializationTag` 调用相应的读取函数（例如 `ReadCryptoKey`, `ReadFileSystemHandle` 等），从序列化数据中读取必要的参数，并创建对应的 Blink 内部 C++ 对象。

**调试线索:**

* **断点:** 在 `V8ScriptValueDeserializerForModules::ReadDOMObject` 函数的 `switch` 语句中设置断点，可以观察正在反序列化的对象类型。
* **检查 `SerializationTag`:** 查看序列化数据中的 `SerializationTag`，确认期望反序列化的类型是否正确。
* **检查 Feature Flags:** 确认相关的 Web 平台特性是否已启用。
* **查看序列化数据内容:**  如果可能，查看原始的序列化二进制数据，分析其结构和内容，判断是否存在损坏或格式错误。
* **跟踪 JavaScript 代码:**  从触发序列化的 JavaScript 代码开始，逐步跟踪，确保传递的数据类型和内容是预期的。
* **检查错误日志:**  Blink 引擎可能会在反序列化失败时输出错误日志。

总而言之，`v8_script_value_deserializer_for_modules.cc` 是 Blink 引擎中一个至关重要的组件，它使得在模块化 Web 应用中能够安全有效地传递和恢复复杂 JavaScript 对象的状态，支撑了现代 Web 平台的诸多核心功能。

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/serialization/v8_script_value_deserializer_for_modules.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/modules/v8/serialization/v8_script_value_deserializer_for_modules.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_manager.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_transfer_token.mojom-blink.h"
#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_crypto.h"
#include "third_party/blink/public/platform/web_crypto_key_algorithm.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/modules/v8/serialization/serialized_track_params.h"
#include "third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crop_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crypto_key.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_dom_file_system.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_directory_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_file_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_source_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_restriction_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_certificate.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/crypto/crypto_key.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_attachment_supplement.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_attachment.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_impl.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate_generator.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel_attachment.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame_delegate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame_delegate.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data_attachment.h"
#include "third_party/blink/renderer/modules/webcodecs/decoder_buffer_attachment.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_audio_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_attachment.h"

namespace blink {

ScriptWrappable* V8ScriptValueDeserializerForModules::ReadDOMObject(
    SerializationTag tag,
    ExceptionState& exception_state) {
  // Give the core/ implementation a chance to try first.
  // If it didn't recognize the kind of wrapper, try the modules types.
  if (ScriptWrappable* wrappable =
          V8ScriptValueDeserializer::ReadDOMObject(tag, exception_state))
    return wrappable;

  if (!ExecutionContextExposesInterface(
          ExecutionContext::From(GetScriptState()), tag)) {
    return nullptr;
  }
  switch (tag) {
    case kCryptoKeyTag:
      return ReadCryptoKey();
    case kDOMFileSystemTag: {
      uint32_t raw_type;
      String name;
      String root_url;
      if (!ReadUint32(&raw_type) ||
          raw_type >
              static_cast<int32_t>(mojom::blink::FileSystemType::kMaxValue) ||
          !ReadUTF8String(&name) || !ReadUTF8String(&root_url))
        return nullptr;
      return MakeGarbageCollected<DOMFileSystem>(
          ExecutionContext::From(GetScriptState()), name,
          static_cast<mojom::blink::FileSystemType>(raw_type), KURL(root_url));
    }
    case kFileSystemFileHandleTag:
    case kFileSystemDirectoryHandleTag:
      return ReadFileSystemHandle(tag);
    case kRTCCertificateTag: {
      String pem_private_key;
      String pem_certificate;
      if (!ReadUTF8String(&pem_private_key) ||
          !ReadUTF8String(&pem_certificate))
        return nullptr;
      std::unique_ptr<RTCCertificateGenerator> certificate_generator =
          std::make_unique<RTCCertificateGenerator>();
      if (!certificate_generator)
        return nullptr;
      rtc::scoped_refptr<rtc::RTCCertificate> certificate =
          certificate_generator->FromPEM(pem_private_key, pem_certificate);
      if (!certificate)
        return nullptr;
      return MakeGarbageCollected<RTCCertificate>(std::move(certificate));
    }
    case kRTCDataChannel:
      return ReadRTCDataChannel();
    case kRTCEncodedAudioFrameTag:
      return ReadRTCEncodedAudioFrame();
    case kRTCEncodedVideoFrameTag:
      return ReadRTCEncodedVideoFrame();
    case kAudioDataTag:
      return ReadAudioData();
    case kVideoFrameTag:
      return ReadVideoFrame();
    case kEncodedAudioChunkTag:
      return ReadEncodedAudioChunk();
    case kEncodedVideoChunkTag:
      return ReadEncodedVideoChunk();
    case kMediaStreamTrack:
      return ReadMediaStreamTrack();
    case kCropTargetTag:
      return ReadCropTarget();
    case kRestrictionTargetTag:
      return ReadRestrictionTarget();
    case kMediaSourceHandleTag:
      return ReadMediaSourceHandle();
    default:
      break;
  }
  return nullptr;
}

namespace {

bool AlgorithmIdFromWireFormat(uint32_t raw_id, WebCryptoAlgorithmId* id) {
  switch (static_cast<CryptoKeyAlgorithmTag>(raw_id)) {
    case kAesCbcTag:
      *id = kWebCryptoAlgorithmIdAesCbc;
      return true;
    case kHmacTag:
      *id = kWebCryptoAlgorithmIdHmac;
      return true;
    case kRsaSsaPkcs1v1_5Tag:
      *id = kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5;
      return true;
    case kSha1Tag:
      *id = kWebCryptoAlgorithmIdSha1;
      return true;
    case kSha256Tag:
      *id = kWebCryptoAlgorithmIdSha256;
      return true;
    case kSha384Tag:
      *id = kWebCryptoAlgorithmIdSha384;
      return true;
    case kSha512Tag:
      *id = kWebCryptoAlgorithmIdSha512;
      return true;
    case kAesGcmTag:
      *id = kWebCryptoAlgorithmIdAesGcm;
      return true;
    case kRsaOaepTag:
      *id = kWebCryptoAlgorithmIdRsaOaep;
      return true;
    case kAesCtrTag:
      *id = kWebCryptoAlgorithmIdAesCtr;
      return true;
    case kAesKwTag:
      *id = kWebCryptoAlgorithmIdAesKw;
      return true;
    case kRsaPssTag:
      *id = kWebCryptoAlgorithmIdRsaPss;
      return true;
    case kEcdsaTag:
      *id = kWebCryptoAlgorithmIdEcdsa;
      return true;
    case kEcdhTag:
      *id = kWebCryptoAlgorithmIdEcdh;
      return true;
    case kHkdfTag:
      *id = kWebCryptoAlgorithmIdHkdf;
      return true;
    case kPbkdf2Tag:
      *id = kWebCryptoAlgorithmIdPbkdf2;
      return true;
    case kEd25519Tag:
      *id = kWebCryptoAlgorithmIdEd25519;
      return true;
    case kX25519Tag:
      *id = kWebCryptoAlgorithmIdX25519;
      return true;
  }
  return false;
}

bool AsymmetricKeyTypeFromWireFormat(uint32_t raw_key_type,
                                     WebCryptoKeyType* key_type) {
  switch (static_cast<AsymmetricCryptoKeyType>(raw_key_type)) {
    case kPublicKeyType:
      *key_type = kWebCryptoKeyTypePublic;
      return true;
    case kPrivateKeyType:
      *key_type = kWebCryptoKeyTypePrivate;
      return true;
  }
  return false;
}

bool NamedCurveFromWireFormat(uint32_t raw_named_curve,
                              WebCryptoNamedCurve* named_curve) {
  switch (static_cast<NamedCurveTag>(raw_named_curve)) {
    case kP256Tag:
      *named_curve = kWebCryptoNamedCurveP256;
      return true;
    case kP384Tag:
      *named_curve = kWebCryptoNamedCurveP384;
      return true;
    case kP521Tag:
      *named_curve = kWebCryptoNamedCurveP521;
      return true;
  }
  return false;
}

bool KeyUsagesFromWireFormat(uint32_t raw_usages,
                             WebCryptoKeyUsageMask* usages,
                             bool* extractable) {
  // Reminder to update this when adding new key usages.
  static_assert(kEndOfWebCryptoKeyUsage == (1 << 7) + 1,
                "update required when adding new key usages");
  const uint32_t kAllPossibleUsages =
      kExtractableUsage | kEncryptUsage | kDecryptUsage | kSignUsage |
      kVerifyUsage | kDeriveKeyUsage | kWrapKeyUsage | kUnwrapKeyUsage |
      kDeriveBitsUsage;
  if (raw_usages & ~kAllPossibleUsages)
    return false;

  *usages = 0;
  *extractable = raw_usages & kExtractableUsage;
  if (raw_usages & kEncryptUsage)
    *usages |= kWebCryptoKeyUsageEncrypt;
  if (raw_usages & kDecryptUsage)
    *usages |= kWebCryptoKeyUsageDecrypt;
  if (raw_usages & kSignUsage)
    *usages |= kWebCryptoKeyUsageSign;
  if (raw_usages & kVerifyUsage)
    *usages |= kWebCryptoKeyUsageVerify;
  if (raw_usages & kDeriveKeyUsage)
    *usages |= kWebCryptoKeyUsageDeriveKey;
  if (raw_usages & kWrapKeyUsage)
    *usages |= kWebCryptoKeyUsageWrapKey;
  if (raw_usages & kUnwrapKeyUsage)
    *usages |= kWebCryptoKeyUsageUnwrapKey;
  if (raw_usages & kDeriveBitsUsage)
    *usages |= kWebCryptoKeyUsageDeriveBits;
  return true;
}

}  // namespace

CryptoKey* V8ScriptValueDeserializerForModules::ReadCryptoKey() {
  // Read params.
  uint8_t raw_key_byte;
  if (!ReadOneByte(&raw_key_byte))
    return nullptr;
  WebCryptoKeyAlgorithm algorithm;
  WebCryptoKeyType key_type = kWebCryptoKeyTypeSecret;
  switch (raw_key_byte) {
    case kAesKeyTag: {
      uint32_t raw_id;
      WebCryptoAlgorithmId id;
      uint32_t length_bytes;
      if (!ReadUint32(&raw_id) || !AlgorithmIdFromWireFormat(raw_id, &id) ||
          !ReadUint32(&length_bytes) ||
          length_bytes > std::numeric_limits<uint16_t>::max() / 8u)
        return nullptr;
      algorithm = WebCryptoKeyAlgorithm::CreateAes(id, length_bytes * 8);
      key_type = kWebCryptoKeyTypeSecret;
      break;
    }
    case kHmacKeyTag: {
      uint32_t length_bytes;
      uint32_t raw_hash;
      WebCryptoAlgorithmId hash;
      if (!ReadUint32(&length_bytes) ||
          length_bytes > std::numeric_limits<unsigned>::max() / 8 ||
          !ReadUint32(&raw_hash) || !AlgorithmIdFromWireFormat(raw_hash, &hash))
        return nullptr;
      algorithm = WebCryptoKeyAlgorithm::CreateHmac(hash, length_bytes * 8);
      key_type = kWebCryptoKeyTypeSecret;
      break;
    }
    case kRsaHashedKeyTag: {
      uint32_t raw_id;
      WebCryptoAlgorithmId id;
      uint32_t raw_key_type;
      uint32_t modulus_length_bits;
      uint32_t public_exponent_size;
      const void* public_exponent_bytes;
      uint32_t raw_hash;
      WebCryptoAlgorithmId hash;
      if (!ReadUint32(&raw_id) || !AlgorithmIdFromWireFormat(raw_id, &id) ||
          !ReadUint32(&raw_key_type) ||
          !AsymmetricKeyTypeFromWireFormat(raw_key_type, &key_type) ||
          !ReadUint32(&modulus_length_bits) ||
          !ReadUint32(&public_exponent_size) ||
          !ReadRawBytes(public_exponent_size, &public_exponent_bytes) ||
          !ReadUint32(&raw_hash) || !AlgorithmIdFromWireFormat(raw_hash, &hash))
        return nullptr;
      algorithm = WebCryptoKeyAlgorithm::CreateRsaHashed(
          id, modulus_length_bits,
          reinterpret_cast<const unsigned char*>(public_exponent_bytes),
          public_exponent_size, hash);
      break;
    }
    case kEcKeyTag: {
      uint32_t raw_id;
      WebCryptoAlgorithmId id;
      uint32_t raw_key_type;
      uint32_t raw_named_curve;
      WebCryptoNamedCurve named_curve;
      if (!ReadUint32(&raw_id) || !AlgorithmIdFromWireFormat(raw_id, &id) ||
          !ReadUint32(&raw_key_type) ||
          !AsymmetricKeyTypeFromWireFormat(raw_key_type, &key_type) ||
          !ReadUint32(&raw_named_curve) ||
          !NamedCurveFromWireFormat(raw_named_curve, &named_curve))
        return nullptr;
      algorithm = WebCryptoKeyAlgorithm::CreateEc(id, named_curve);
      break;
    }
    case kEd25519KeyTag:
    case kX25519KeyTag: {
      if (!RuntimeEnabledFeatures::WebCryptoCurve25519Enabled())
        break;
      uint32_t raw_id;
      WebCryptoAlgorithmId id;
      uint32_t raw_key_type;
      if (!ReadUint32(&raw_id) || !AlgorithmIdFromWireFormat(raw_id, &id) ||
          !ReadUint32(&raw_key_type) ||
          !AsymmetricKeyTypeFromWireFormat(raw_key_type, &key_type))
        return nullptr;
      algorithm = raw_key_byte == kEd25519KeyTag
                      ? WebCryptoKeyAlgorithm::CreateEd25519(id)
                      : WebCryptoKeyAlgorithm::CreateX25519(id);
      break;
    }
    case kNoParamsKeyTag: {
      uint32_t raw_id;
      WebCryptoAlgorithmId id;
      if (!ReadUint32(&raw_id) || !AlgorithmIdFromWireFormat(raw_id, &id))
        return nullptr;
      algorithm = WebCryptoKeyAlgorithm::CreateWithoutParams(id);
      break;
    }
  }
  if (algorithm.IsNull())
    return nullptr;

  // Read key usages.
  uint32_t raw_usages;
  WebCryptoKeyUsageMask usages;
  bool extractable;
  if (!ReadUint32(&raw_usages) ||
      !KeyUsagesFromWireFormat(raw_usages, &usages, &extractable))
    return nullptr;

  // Read key data.
  uint32_t key_data_length;
  const void* key_data;
  if (!ReadUint32(&key_data_length) ||
      !ReadRawBytes(key_data_length, &key_data))
    return nullptr;

  WebCryptoKey key = WebCryptoKey::CreateNull();
  if (!Platform::Current()->Crypto()->DeserializeKeyForClone(
          algorithm, key_type, extractable, usages,
          reinterpret_cast<const unsigned char*>(key_data), key_data_length,
          key))
    return nullptr;

  return MakeGarbageCollected<CryptoKey>(key);
}

FileSystemHandle* V8ScriptValueDeserializerForModules::ReadFileSystemHandle(
    SerializationTag tag) {
  if (!RuntimeEnabledFeatures::FileSystemAccessEnabled(
          ExecutionContext::From(GetScriptState()))) {
    return nullptr;
  }

  String name;
  uint32_t token_index;
  if (!ReadUTF8String(&name) || !ReadUint32(&token_index)) {
    return nullptr;
  }

  // Find the FileSystemHandle's token.
  SerializedScriptValue::FileSystemAccessTokensArray& tokens_array =
      GetSerializedScriptValue()->FileSystemAccessTokens();
  if (token_index >= tokens_array.size()) {
    return nullptr;
  }

  // IndexedDB code assumes that deserializing a SSV is non-destructive. So
  // rather than consuming the token here instead we clone it.
  mojo::Remote<mojom::blink::FileSystemAccessTransferToken> token(
      std::move(tokens_array[token_index]));
  if (!token) {
    return nullptr;
  }

  mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> token_clone;
  token->Clone(token_clone.InitWithNewPipeAndPassReceiver());
  tokens_array[token_index] = std::move(token_clone);

  // Use the FileSystemAccessManager to redeem the token to clone the
  // FileSystemHandle.
  ExecutionContext* execution_context =
      ExecutionContext::From(GetScriptState());
  mojo::Remote<mojom::blink::FileSystemAccessManager>
      file_system_access_manager;
  execution_context->GetBrowserInterfaceBroker().GetInterface(
      file_system_access_manager.BindNewPipeAndPassReceiver());

  // Clone the FileSystemHandle object.
  switch (tag) {
    case kFileSystemFileHandleTag: {
      mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle> file_handle;

      file_system_access_manager->GetFileHandleFromToken(
          token.Unbind(), file_handle.InitWithNewPipeAndPassReceiver());

      return MakeGarbageCollected<FileSystemFileHandle>(execution_context, name,
                                                        std::move(file_handle));
    }
    case kFileSystemDirectoryHandleTag: {
      mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle>
          directory_handle;

      file_system_access_manager->GetDirectoryHandleFromToken(
          token.Unbind(), directory_handle.InitWithNewPipeAndPassReceiver());

      return MakeGarbageCollected<FileSystemDirectoryHandle>(
          execution_context, name, std::move(directory_handle));
    }
    default: {
      NOTREACHED();
    }
  }
}

RTCDataChannel* V8ScriptValueDeserializerForModules::ReadRTCDataChannel() {
  if (!RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled(
          ExecutionContext::From(GetScriptState()))) {
    return nullptr;
  }

  uint32_t index;
  if (!ReadUint32(&index)) {
    return nullptr;
  }

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<RTCDataChannelAttachment>();
  if (!attachment) {
    return nullptr;
  }

  using NativeDataChannelVector =
      Vector<rtc::scoped_refptr<webrtc::DataChannelInterface>>;

  const NativeDataChannelVector& channels = attachment->DataChannels();
  if (index >= attachment->size() || !channels[index]) {
    return nullptr;
  }

  RTCDataChannel::EnsureThreadWrappersForWorkerThread();

  return MakeGarbageCollected<RTCDataChannel>(
      ExecutionContext::From(GetScriptState()), std::move(channels[index]));
}

RTCEncodedAudioFrame*
V8ScriptValueDeserializerForModules::ReadRTCEncodedAudioFrame() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<RTCEncodedAudioFramesAttachment>();
  if (!attachment)
    return nullptr;

  const auto& frames = attachment->EncodedAudioFrames();
  if (index >= frames.size())
    return nullptr;

  return MakeGarbageCollected<RTCEncodedAudioFrame>(frames[index]);
}

RTCEncodedVideoFrame*
V8ScriptValueDeserializerForModules::ReadRTCEncodedVideoFrame() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<RTCEncodedVideoFramesAttachment>();
  if (!attachment)
    return nullptr;

  const auto& frames = attachment->EncodedVideoFrames();
  if (index >= frames.size())
    return nullptr;

  return MakeGarbageCollected<RTCEncodedVideoFrame>(frames[index]);
}

AudioData* V8ScriptValueDeserializerForModules::ReadAudioData() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()->GetAttachmentIfExists<AudioDataAttachment>();
  if (!attachment)
    return nullptr;

  const auto& audio_buffers = attachment->AudioBuffers();
  if (index >= attachment->size())
    return nullptr;

  return MakeGarbageCollected<AudioData>(audio_buffers[index]);
}

VideoFrame* V8ScriptValueDeserializerForModules::ReadVideoFrame() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()->GetAttachmentIfExists<VideoFrameAttachment>();
  if (!attachment)
    return nullptr;

  const auto& handles = attachment->Handles();
  if (index >= attachment->size())
    return nullptr;

  return MakeGarbageCollected<VideoFrame>(handles[index]);
}

EncodedAudioChunk*
V8ScriptValueDeserializerForModules::ReadEncodedAudioChunk() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<DecoderBufferAttachment>();
  if (!attachment)
    return nullptr;

  const auto& buffers = attachment->Buffers();
  if (index >= attachment->size())
    return nullptr;

  return MakeGarbageCollected<EncodedAudioChunk>(buffers[index]);
}

EncodedVideoChunk*
V8ScriptValueDeserializerForModules::ReadEncodedVideoChunk() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<DecoderBufferAttachment>();
  if (!attachment)
    return nullptr;

  const auto& buffers = attachment->Buffers();
  if (index >= attachment->size())
    return nullptr;

  return MakeGarbageCollected<EncodedVideoChunk>(buffers[index]);
}

MediaStreamTrack* V8ScriptValueDeserializerForModules::ReadMediaStreamTrack() {
  if (!RuntimeEnabledFeatures::MediaStreamTrackTransferEnabled(
          ExecutionContext::From(GetScriptState()))) {
    return nullptr;
  }

  base::UnguessableToken session_id, transfer_id;
  String kind, id, label;
  uint8_t enabled, muted;
  SerializedTrackImplSubtype track_impl_subtype;
  SerializedContentHintType contentHint;
  SerializedReadyState readyState;

  if (!ReadUint32Enum(&track_impl_subtype) ||
      !ReadUnguessableToken(&session_id) ||
      !ReadUnguessableToken(&transfer_id) || !ReadUTF8String(&kind) ||
      (kind != "audio" && kind != "video") || !ReadUTF8String(&id) ||
      !ReadUTF8String(&label) || !ReadOneByte(&enabled) || enabled > 1 ||
      !ReadOneByte(&muted) || muted > 1 || !ReadUint32Enum(&contentHint) ||
      !ReadUint32Enum(&readyState)) {
    return nullptr;
  }

  std::optional<uint32_t> sub_capture_target_version;
  // Using `switch` to ensure new enum values are handled.
  switch (track_impl_subtype) {
    case SerializedTrackImplSubtype::kTrackImplSubtypeBase:
      // No additional data to be deserialized.
      break;
    case SerializedTrackImplSubtype::kTrackImplSubtypeCanvasCapture:
    case SerializedTrackImplSubtype::kTrackImplSubtypeGenerator:
      NOTREACHED();
    case SerializedTrackImplSubtype::kTrackImplSubtypeBrowserCapture:
      uint32_t read_sub_capture_target_version;
      if (!ReadUint32(&read_sub_capture_target_version)) {
        return nullptr;
      }
      sub_capture_target_version = read_sub_capture_target_version;
      break;
  }

  return MediaStreamTrack::FromTransferredState(
      GetScriptState(),
      MediaStreamTrack::TransferredValues{
          .track_impl_subtype = DeserializeTrackImplSubtype(track_impl_subtype),
          .session_id = session_id,
          .transfer_id = transfer_id,
          .kind = kind,
          .id = id,
          .label = label,
          .enabled = static_cast<bool>(enabled),
          .muted = static_cast<bool>(muted),
          .content_hint = DeserializeContentHint(contentHint),
          .ready_state = DeserializeReadyState(readyState),
          .sub_capture_target_version = sub_capture_target_version});
}

CropTarget* V8ScriptValueDeserializerForModules::ReadCropTarget() {
  if (!RuntimeEnabledFeatures::RegionCaptureEnabled(
          ExecutionContext::From(GetScriptState()))) {
    return nullptr;
  }

  String crop_id;
  if (!ReadUTF8String(&crop_id) || crop_id.empty()) {
    return nullptr;
  }

  return MakeGarbageCollected<CropTarget>(crop_id);
}

RestrictionTarget*
V8ScriptValueDeserializerForModules::ReadRestrictionTarget() {
  if (!RuntimeEnabledFeatures::ElementCaptureEnabled(
          ExecutionContext::From(GetScriptState()))) {
    return nullptr;
  }

  String restriction_id;
  if (!ReadUTF8String(&restriction_id) || restriction_id.empty()) {
    return nullptr;
  }

  return MakeGarbageCollected<RestrictionTarget>(restriction_id);
}

MediaSourceHandleImpl*
V8ScriptValueDeserializerForModules::ReadMediaSourceHandle() {
  uint32_t index;
  if (!ReadUint32(&index))
    return nullptr;

  const auto* attachment =
      GetSerializedScriptValue()
          ->GetAttachmentIfExists<MediaSourceHandleAttachment>();
  if (!attachment)
    return nullptr;

  const auto& attachments = attachment->Attachments();
  if (index >= attachment->size())
    return nullptr;

  auto& handle_internals = attachments[index];
  return MakeGarbageCollected<MediaSourceHandleImpl>(
      std::move(handle_internals.attachment_provider),
      std::move(handle_internals.internal_blob_url));
}

// static
bool V8ScriptValueDeserializerForModules::ExecutionContextExposesInterface(
    ExecutionContext* execution_context,
    SerializationTag interface_tag) {
  // If you're updating this, consider whether you should also update
  // V8ScriptValueSerializerForModules to call
  // TrailerWriter::RequireExposedInterface (generally via
  // WriteAndRequireInterfaceTag). Any interface which might potentially not be
  // exposed on all realms, even if not currently (i.e., most or all) should
  // probably be listed here.
  if (V8ScriptValueDeserializer::ExecutionContextExposesInterface(
          execution_context, interface_tag)) {
    return true;
  }
  switch (interface_tag) {
    case kCryptoKeyTag:
      return V8CryptoKey::IsExposed(execution_context);
    case kDOMFileSystemTag:
      // TODO(crbug.com/1366065): In theory this should be the result of
      // V8DOMFileSystem::IsExposed, but that's actually _nowhere_ right now.
      // This is an attempt to preserve things that might be working while
      // someone with actual file system API expertise looks into it.
      return execution_context->IsWindow() ||
             execution_context->IsWorkerGlobalScope();
    case kFileSystemFileHandleTag:
      return V8FileSystemFileHandle::IsExposed(execution_context);
    case kFileSystemDirectoryHandleTag:
      return V8FileSystemDirectoryHandle::IsExposed(execution_context);
    case kRTCCertificateTag:
      return V8RTCCertificate::IsExposed(execution_context);
    case kRTCEncodedAudioFrameTag:
      return V8RTCEncodedAudioFrame::IsExposed(execution_context);
    case kRTCEncodedVideoFrameTag:
      return V8RTCEncodedVideoFrame::IsExposed(execution_context);
    case kRTCDataChannel:
      return V8RTCDataChannel::IsExposed(execution_context);
    case kAudioDataTag:
      return V8AudioData::IsExposed(execution_context);
    case kVideoFrameTag:
      return V8VideoFrame::IsExposed(execution_context);
    case kEncodedAudioChunkTag:
      return V8EncodedAudioChunk::IsExposed(execution_context);
    case kEncodedVideoChunkTag:
      return V8EncodedVideoChunk::IsExposed(execution_context);
    case kMediaStreamTrack:
      return V8MediaStreamTrack::IsExposed(execution_context);
    case kCropTargetTag:
      return V8CropTarget::IsExposed(execution_context);
    case kRestrictionTargetTag:
      return V8RestrictionTarget::IsExposed(execution_context);
    case kMediaSourceHandleTag:
      return V8MediaSourceHandle::IsExposed(execution_context);
    default:
      return false;
  }
}

}  // namespace blink

"""

```