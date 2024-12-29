Response:
The user is asking for a summary of the provided C++ code file. The file is a test file for the `V8ScriptValueSerializerForModules` class in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core class under test:** The filename `v8_script_value_serializer_for_modules_test.cc` clearly indicates that the primary focus is testing the `V8ScriptValueSerializerForModules` class.

2. **Determine the purpose of the serializer:** The name "serializer" suggests the class is responsible for converting JavaScript values into a format suitable for storage or transmission. The "for modules" part hints that this serializer is specifically designed to handle values related to JavaScript modules.

3. **Look for related classes:** The `#include` directives at the beginning of the file point to other relevant classes. `V8ScriptValueDeserializerForModules` is a strong indicator that there's a complementary class for converting the serialized data back into JavaScript values. The inclusion of various `v8_*` files suggests interaction with the V8 JavaScript engine.

4. **Examine the test structure:** The `TEST()` macros indicate the presence of unit tests. The names of the test cases often reveal the specific functionalities being tested. For example, `RoundTripRTCCertificate` suggests testing the serialization and deserialization of `RTCCertificate` objects. The "RoundTrip" pattern is common for testing serialization/deserialization.

5. **Identify the types of data being tested:**  By looking at the included headers and the test case names, we can see various JavaScript types and Web API objects being tested, including:
    * `RTCCertificate` (related to WebRTC)
    * `CryptoKey` and related WebCrypto API objects
    * Basic JavaScript values (implicitly tested by the round-trip mechanism)

6. **Understand the "round trip" concept:**  The `RoundTripForModules` helper function encapsulates the process of serializing a value and then immediately deserializing it. This is a standard technique for verifying that the serialization and deserialization processes are correctly implemented and preserve the original data.

7. **Infer the role of `V8ScriptValueSerializerForModules`:** Based on the tests, it's clear that the serializer handles the conversion of JavaScript objects (wrappers around native Blink objects) into a serializable format and back. The "for modules" aspect likely means it correctly handles the specific requirements of module-related data, which might involve special handling of dependencies or scopes.

8. **Consider the context within Blink:** The file resides in the `blink/renderer/bindings/modules/v8/serialization/` directory. This indicates its role in the data exchange between the JavaScript environment (V8) and the native Blink rendering engine, specifically for features implemented as JavaScript modules.

9. **Formulate the summary:** Combine the observations from the previous steps to create a concise description of the file's purpose. Emphasize the serialization and deserialization of JavaScript values, its connection to modules, and the types of data being tested.

By following these steps, we can deduce that the file tests the functionality of the `V8ScriptValueSerializerForModules` class, which is responsible for serializing and deserializing JavaScript values, particularly those related to JavaScript modules, within the Blink rendering engine. The tests cover various data types like `RTCCertificate` and `CryptoKey`, ensuring the serialization and deserialization process is lossless.
这个文件是 Chromium Blink 引擎中用于测试 `V8ScriptValueSerializerForModules` 类的单元测试文件。它的主要功能是：

**1. 测试 JavaScript 值的序列化和反序列化：**

   - 该文件包含多个测试用例，用于验证 `V8ScriptValueSerializerForModules` 能否正确地将各种 JavaScript 值（包括与模块相关的对象）转换为可序列化的格式，并且 `V8ScriptValueDeserializerForModules` 能否将其成功地反序列化回原始的 JavaScript 值。
   - 这种“往返”（round trip）测试是确保序列化和反序列化过程无损的关键方法。

**2. 测试特定 Web API 对象的序列化和反序列化：**

   - 该文件特别关注与 JavaScript 模块相关的 Web API 对象的序列化和反序列化，例如：
     - **WebRTC API 相关对象:** `RTCCertificate` (用于安全连接)。
     - **Web Crypto API 相关对象:** `CryptoKey` (用于加密操作)。
     - **Media Streams API 相关对象:**  虽然没有直接的 "RoundTrip" 测试用例，但引入了 `AudioData`, `BrowserCaptureMediaStreamTrack`, `CropTarget`, `MediaStreamTrack`, `RestrictionTarget`, `VideoFrame` 等与媒体相关的对象，暗示了对这些类型的支持。
     - **File System API 相关对象:** `DOMFileSystem`。
     - **WebCodecs API 相关对象:** `AudioData`, `VideoFrame`。

**3. 验证序列化和反序列化的正确性：**

   - 测试用例会检查反序列化后的对象是否与原始对象具有相同的属性和状态。例如，对于 `RTCCertificate`，会检查其私钥和证书内容是否一致；对于 `CryptoKey`，会检查其类型、是否可提取以及用途是否一致。

**4. 测试错误处理：**

   - 其中一个测试用例 `DecodeInvalidRTCCertificate` 专门用于测试当反序列化无效数据时，代码是否能够正确处理并返回预期结果（在这种情况下是 `null`）。

**与 JavaScript, HTML, CSS 的功能关系：**

虽然这个 C++ 文件本身不直接处理 JavaScript, HTML 或 CSS 的解析或执行，但它测试的序列化机制对于这些技术在浏览器中的协同工作至关重要，特别是在涉及模块化 JavaScript 代码时：

* **JavaScript 模块:**  该测试文件名称中的 "for modules" 表明其主要关注点是与 JavaScript 模块相关的对象序列化。当 JavaScript 模块需要在不同的上下文（例如，不同的 worker 或不同的浏览上下文）之间传递数据时，就需要进行序列化。
    * **举例:**  假设一个 JavaScript模块创建了一个 `RTCCertificate` 对象用于建立 WebRTC 连接。如果需要将这个模块的状态传递给一个 Service Worker，就需要将 `RTCCertificate` 对象序列化。
* **Web Workers 和 Service Workers:** Web Workers 和 Service Workers 运行在独立的线程中，需要通过消息传递机制与主线程通信。序列化是跨线程传递复杂 JavaScript 对象的必要步骤。
    * **举例:**  一个 Service Worker 可以缓存一些加密密钥 (`CryptoKey`)。当主线程需要使用这些密钥时，Service Worker 需要将它们序列化后发送给主线程。
* **`postMessage` API:**  `postMessage` API 允许不同源的窗口或 worker 之间进行通信。传递的数据需要能够被序列化和反序列化。
    * **举例:** 一个嵌入在 iframe 中的页面可能需要向父页面发送一个包含 `MediaStreamTrack` 状态的消息。这需要对 `MediaStreamTrack` 对象进行序列化。
* **状态保存和恢复:**  浏览器的某些功能可能需要在页面重新加载或会话恢复时保存和恢复 JavaScript 对象的状态。序列化可以将这些对象转换为可以存储的格式。

**逻辑推理 (假设输入与输出):**

以 `RoundTripRTCCertificate` 测试用例为例：

* **假设输入 (在 JavaScript 中):** 一个通过 `RTCCertificate.generateCertificate()` 或使用 PEM 字符串创建的 `RTCCertificate` 对象。
* **内部过程:**
    1. 测试代码将 JavaScript 的 `RTCCertificate` 对象传递给 `V8ScriptValueSerializerForModules` 进行序列化。
    2. 序列化器将 `RTCCertificate` 对象转换为二进制数据。
    3. 测试代码将序列化后的二进制数据传递给 `V8ScriptValueDeserializerForModules` 进行反序列化。
    4. 反序列化器将二进制数据重新构建为 JavaScript 的 `RTCCertificate` 对象。
* **预期输出 (在 JavaScript 中):**  反序列化后的 `RTCCertificate` 对象，其私钥和证书内容与原始对象完全一致。

**用户或编程常见的使用错误：**

* **尝试序列化不可序列化的对象:**  某些 JavaScript 对象（例如，包含循环引用的对象或某些特定的 DOM 节点）可能无法被正确序列化。这会导致错误或意外的结果。
    * **举例:**  尝试使用 `postMessage` 发送一个包含对自身引用的复杂对象。
* **序列化和反序列化上下文不一致:**  如果序列化和反序列化发生在不同的 JavaScript 引擎版本或不同的浏览器实现中，可能会出现兼容性问题。
* **传输过程中数据损坏:**  如果在序列化后的数据传输过程中发生损坏，反序列化可能会失败或产生错误的对象。
* **忘记处理异步操作:**  对于某些涉及到异步操作的对象（例如，与 IndexedDB 交互的对象），直接序列化可能不会捕获其完成状态。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户操作触发需要跨上下文传递数据的场景:**
   - 用户在网页上操作，导致一个 Web Worker 被创建并需要接收主线程中的数据。
   - 用户操作导致一个页面需要向嵌入的 iframe 发送消息。
   - 用户关闭并重新打开浏览器，浏览器尝试恢复之前的会话状态。
2. **JavaScript 代码尝试传递数据:**
   - JavaScript 代码使用 `postMessage` 方法向 worker 或 iframe 发送数据。
   - JavaScript 代码尝试将数据存储到 `sessionStorage` 或 `localStorage` 中。
   - JavaScript 代码在 Service Worker 中接收来自页面的消息。
3. **Blink 引擎尝试序列化 JavaScript 值:**
   - 当 JavaScript 引擎遇到需要跨上下文传递的复杂对象时，会调用 Blink 引擎的序列化机制。
   - 在这个过程中，`V8ScriptValueSerializerForModules` 类会被调用，将 JavaScript 值转换为二进制数据。
4. **如果出现问题，开发者可能会进行调试:**
   - 如果反序列化失败或产生意外结果，开发者可能会检查序列化后的数据，或者尝试单步调试 Blink 引擎的序列化和反序列化代码。
   - 这个测试文件 `v8_script_value_serializer_for_modules_test.cc` 中定义的测试用例就为 Blink 引擎的开发者提供了调试和验证序列化/反序列化功能的工具。

**总结 (功能归纳):**

总而言之，`blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc` 的主要功能是**测试 `V8ScriptValueSerializerForModules` 类及其相关的 `V8ScriptValueDeserializerForModules` 类的正确性，确保它们能够可靠地序列化和反序列化与 JavaScript 模块相关的各种 JavaScript 值和 Web API 对象**。这对于浏览器中 JavaScript 模块的跨上下文数据传递、Web Workers/Service Workers 的通信以及状态保存等功能至关重要。

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_crypto_algorithm_params.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/serialization/v8_script_value_deserializer_for_modules.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crop_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crypto_key.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_dom_file_system.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_restriction_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_certificate.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/crypto/crypto_key.h"
#include "third_party/blink/renderer/modules/crypto/crypto_result_impl.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system.h"
#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/mock_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/modules/mediastream/test/transfer_test_utils.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate_generator.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel_transfer_list.h"
#include "third_party/blink/renderer/modules/peerconnection/testing/fake_webrtc_data_channel.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data_transfer_list.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_transfer_list.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

using testing::ElementsAre;
using testing::ElementsAreArray;
using testing::UnorderedElementsAre;

namespace blink {
namespace {

v8::Local<v8::Value> RoundTripForModules(
    v8::Local<v8::Value> value,
    V8TestingScope& scope,
    Transferables* transferables = nullptr) {
  ScriptState* script_state = scope.GetScriptState();
  ExceptionState& exception_state = scope.GetExceptionState();
  V8ScriptValueSerializer::Options serialize_options;
  DCHECK(!transferables || transferables->message_ports.empty());
  serialize_options.transferables = transferables;
  scoped_refptr<SerializedScriptValue> serialized_script_value =
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(value, exception_state);
  DCHECK_EQ(!serialized_script_value, exception_state.HadException());
  EXPECT_TRUE(serialized_script_value);
  if (!serialized_script_value)
    return v8::Local<v8::Value>();
  return V8ScriptValueDeserializerForModules(script_state,
                                             serialized_script_value)
      .Deserialize();
}

// Checks for a DOM exception, including a rethrown one.
testing::AssertionResult HadDOMExceptionInModulesTest(const StringView& name,
                                                      ScriptState* script_state,
                                                      v8::TryCatch& try_catch) {
  if (!try_catch.HasCaught()) {
    return testing::AssertionFailure() << "no exception thrown";
  }
  DOMException* dom_exception = V8DOMException::ToWrappable(
      script_state->GetIsolate(), try_catch.Exception());
  if (!dom_exception) {
    return testing::AssertionFailure()
           << "exception thrown was not a DOMException";
  }
  if (dom_exception->name() != name)
    return testing::AssertionFailure() << "was " << dom_exception->name();
  return testing::AssertionSuccess();
}

static const char kEcdsaPrivateKey[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghHwQ1xYtCoEhFk7r\n"
    "92u3ozy/MFR4I+9FiN8RYv5J96GhRANCAATLfi7OZLD9sIe5UMfMQnHQgAFaQD8h\n"
    "/cy6tB8wXZcixp7bZDp5t0GCDHqAUZT3Sa/NHaCelmmgPp3zW3lszXKP\n"
    "-----END PRIVATE KEY-----\n";

static const char kEcdsaCertificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBFjCBvaADAgECAgkApnGS+DzNWkUwCgYIKoZIzj0EAwIwETEPMA0GA1UEAwwG\n"
    "V2ViUlRDMB4XDTE2MDkxNTE4MDcxMloXDTE2MTAxNjE4MDcxMlowETEPMA0GA1UE\n"
    "AwwGV2ViUlRDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy34uzmSw/bCHuVDH\n"
    "zEJx0IABWkA/If3MurQfMF2XIsae22Q6ebdBggx6gFGU90mvzR2gnpZpoD6d81t5\n"
    "bM1yjzAKBggqhkjOPQQDAgNIADBFAiBcTOyiexG0QHa5WhJuGtY6FhVZ5GyBMW+7\n"
    "LkH2QmxICwIhAJCujozN3gjIu7NMxSXuTqueuVz58SefCMA7/vj1TgfV\n"
    "-----END CERTIFICATE-----\n";

static const uint8_t kEcdsaCertificateEncoded[] = {
    0xff, 0x09, 0x3f, 0x00, 0x6b, 0xf1, 0x01, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54,
    0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d,
    0x49, 0x47, 0x48, 0x41, 0x67, 0x45, 0x41, 0x4d, 0x42, 0x4d, 0x47, 0x42,
    0x79, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x41, 0x67, 0x45, 0x47, 0x43,
    0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x41, 0x77, 0x45, 0x48, 0x42,
    0x47, 0x30, 0x77, 0x61, 0x77, 0x49, 0x42, 0x41, 0x51, 0x51, 0x67, 0x68,
    0x48, 0x77, 0x51, 0x31, 0x78, 0x59, 0x74, 0x43, 0x6f, 0x45, 0x68, 0x46,
    0x6b, 0x37, 0x72, 0x0a, 0x39, 0x32, 0x75, 0x33, 0x6f, 0x7a, 0x79, 0x2f,
    0x4d, 0x46, 0x52, 0x34, 0x49, 0x2b, 0x39, 0x46, 0x69, 0x4e, 0x38, 0x52,
    0x59, 0x76, 0x35, 0x4a, 0x39, 0x36, 0x47, 0x68, 0x52, 0x41, 0x4e, 0x43,
    0x41, 0x41, 0x54, 0x4c, 0x66, 0x69, 0x37, 0x4f, 0x5a, 0x4c, 0x44, 0x39,
    0x73, 0x49, 0x65, 0x35, 0x55, 0x4d, 0x66, 0x4d, 0x51, 0x6e, 0x48, 0x51,
    0x67, 0x41, 0x46, 0x61, 0x51, 0x44, 0x38, 0x68, 0x0a, 0x2f, 0x63, 0x79,
    0x36, 0x74, 0x42, 0x38, 0x77, 0x58, 0x5a, 0x63, 0x69, 0x78, 0x70, 0x37,
    0x62, 0x5a, 0x44, 0x70, 0x35, 0x74, 0x30, 0x47, 0x43, 0x44, 0x48, 0x71,
    0x41, 0x55, 0x5a, 0x54, 0x33, 0x53, 0x61, 0x2f, 0x4e, 0x48, 0x61, 0x43,
    0x65, 0x6c, 0x6d, 0x6d, 0x67, 0x50, 0x70, 0x33, 0x7a, 0x57, 0x33, 0x6c,
    0x73, 0x7a, 0x58, 0x4b, 0x50, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45,
    0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b,
    0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0xb4, 0x03, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52,
    0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x42, 0x46, 0x6a, 0x43, 0x42, 0x76, 0x61,
    0x41, 0x44, 0x41, 0x67, 0x45, 0x43, 0x41, 0x67, 0x6b, 0x41, 0x70, 0x6e,
    0x47, 0x53, 0x2b, 0x44, 0x7a, 0x4e, 0x57, 0x6b, 0x55, 0x77, 0x43, 0x67,
    0x59, 0x49, 0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x45, 0x41, 0x77,
    0x49, 0x77, 0x45, 0x54, 0x45, 0x50, 0x4d, 0x41, 0x30, 0x47, 0x41, 0x31,
    0x55, 0x45, 0x41, 0x77, 0x77, 0x47, 0x0a, 0x56, 0x32, 0x56, 0x69, 0x55,
    0x6c, 0x52, 0x44, 0x4d, 0x42, 0x34, 0x58, 0x44, 0x54, 0x45, 0x32, 0x4d,
    0x44, 0x6b, 0x78, 0x4e, 0x54, 0x45, 0x34, 0x4d, 0x44, 0x63, 0x78, 0x4d,
    0x6c, 0x6f, 0x58, 0x44, 0x54, 0x45, 0x32, 0x4d, 0x54, 0x41, 0x78, 0x4e,
    0x6a, 0x45, 0x34, 0x4d, 0x44, 0x63, 0x78, 0x4d, 0x6c, 0x6f, 0x77, 0x45,
    0x54, 0x45, 0x50, 0x4d, 0x41, 0x30, 0x47, 0x41, 0x31, 0x55, 0x45, 0x0a,
    0x41, 0x77, 0x77, 0x47, 0x56, 0x32, 0x56, 0x69, 0x55, 0x6c, 0x52, 0x44,
    0x4d, 0x46, 0x6b, 0x77, 0x45, 0x77, 0x59, 0x48, 0x4b, 0x6f, 0x5a, 0x49,
    0x7a, 0x6a, 0x30, 0x43, 0x41, 0x51, 0x59, 0x49, 0x4b, 0x6f, 0x5a, 0x49,
    0x7a, 0x6a, 0x30, 0x44, 0x41, 0x51, 0x63, 0x44, 0x51, 0x67, 0x41, 0x45,
    0x79, 0x33, 0x34, 0x75, 0x7a, 0x6d, 0x53, 0x77, 0x2f, 0x62, 0x43, 0x48,
    0x75, 0x56, 0x44, 0x48, 0x0a, 0x7a, 0x45, 0x4a, 0x78, 0x30, 0x49, 0x41,
    0x42, 0x57, 0x6b, 0x41, 0x2f, 0x49, 0x66, 0x33, 0x4d, 0x75, 0x72, 0x51,
    0x66, 0x4d, 0x46, 0x32, 0x58, 0x49, 0x73, 0x61, 0x65, 0x32, 0x32, 0x51,
    0x36, 0x65, 0x62, 0x64, 0x42, 0x67, 0x67, 0x78, 0x36, 0x67, 0x46, 0x47,
    0x55, 0x39, 0x30, 0x6d, 0x76, 0x7a, 0x52, 0x32, 0x67, 0x6e, 0x70, 0x5a,
    0x70, 0x6f, 0x44, 0x36, 0x64, 0x38, 0x31, 0x74, 0x35, 0x0a, 0x62, 0x4d,
    0x31, 0x79, 0x6a, 0x7a, 0x41, 0x4b, 0x42, 0x67, 0x67, 0x71, 0x68, 0x6b,
    0x6a, 0x4f, 0x50, 0x51, 0x51, 0x44, 0x41, 0x67, 0x4e, 0x49, 0x41, 0x44,
    0x42, 0x46, 0x41, 0x69, 0x42, 0x63, 0x54, 0x4f, 0x79, 0x69, 0x65, 0x78,
    0x47, 0x30, 0x51, 0x48, 0x61, 0x35, 0x57, 0x68, 0x4a, 0x75, 0x47, 0x74,
    0x59, 0x36, 0x46, 0x68, 0x56, 0x5a, 0x35, 0x47, 0x79, 0x42, 0x4d, 0x57,
    0x2b, 0x37, 0x0a, 0x4c, 0x6b, 0x48, 0x32, 0x51, 0x6d, 0x78, 0x49, 0x43,
    0x77, 0x49, 0x68, 0x41, 0x4a, 0x43, 0x75, 0x6a, 0x6f, 0x7a, 0x4e, 0x33,
    0x67, 0x6a, 0x49, 0x75, 0x37, 0x4e, 0x4d, 0x78, 0x53, 0x58, 0x75, 0x54,
    0x71, 0x75, 0x65, 0x75, 0x56, 0x7a, 0x35, 0x38, 0x53, 0x65, 0x66, 0x43,
    0x4d, 0x41, 0x37, 0x2f, 0x76, 0x6a, 0x31, 0x54, 0x67, 0x66, 0x56, 0x0a,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52,
    0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x0a};

TEST(V8ScriptValueSerializerForModulesTest, RoundTripRTCCertificate) {
  test::TaskEnvironment task_environment;
  // If WebRTC is not supported in this build, this test is meaningless.
  std::unique_ptr<RTCCertificateGenerator> certificate_generator =
      std::make_unique<RTCCertificateGenerator>();
  if (!certificate_generator)
    return;

  V8TestingScope scope;

  // Make a certificate with the existing key above.
  rtc::scoped_refptr<rtc::RTCCertificate> web_certificate =
      certificate_generator->FromPEM(WebString::FromUTF8(kEcdsaPrivateKey),
                                     WebString::FromUTF8(kEcdsaCertificate));
  ASSERT_TRUE(web_certificate);
  RTCCertificate* certificate =
      MakeGarbageCollected<RTCCertificate>(std::move(web_certificate));

  // Round trip test.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<RTCCertificate>::ToV8(scope.GetScriptState(), certificate);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  RTCCertificate* new_certificate =
      V8RTCCertificate::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_certificate, nullptr);
  rtc::RTCCertificatePEM pem = new_certificate->Certificate()->ToPEM();
  EXPECT_EQ(kEcdsaPrivateKey, pem.private_key());
  EXPECT_EQ(kEcdsaCertificate, pem.certificate());
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeRTCCertificate) {
  test::TaskEnvironment task_environment;
  // If WebRTC is not supported in this build, this test is meaningless.
  std::unique_ptr<RTCCertificateGenerator> certificate_generator =
      std::make_unique<RTCCertificateGenerator>();
  if (!certificate_generator)
    return;

  V8TestingScope scope;

  // This is encoded data generated from Chromium (around M55).
  ScriptState* script_state = scope.GetScriptState();
  Vector<uint8_t> encoded_data;
  encoded_data.Append(kEcdsaCertificateEncoded,
                      sizeof(kEcdsaCertificateEncoded));
  scoped_refptr<SerializedScriptValue> input = SerializedValue(encoded_data);

  // Decode test.
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  RTCCertificate* new_certificate =
      V8RTCCertificate::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_certificate, nullptr);
  rtc::RTCCertificatePEM pem = new_certificate->Certificate()->ToPEM();
  EXPECT_EQ(kEcdsaPrivateKey, pem.private_key());
  EXPECT_EQ(kEcdsaCertificate, pem.certificate());
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeInvalidRTCCertificate) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  // This is valid, except that "private" is not a valid private key PEM and
  // "certificate" is not a valid certificate PEM. This checks what happens if
  // these fail validation inside WebRTC.
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x6b, 0x07, 'p', 'r', 'i', 'v', 'a', 't', 'e',
       0x0b, 'c',  'e',  'r',  't',  'i',  'f', 'i', 'c', 'a', 't', 'e', 0x00});

  // Decode test.
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

// A bunch of voodoo which allows the asynchronous WebCrypto operations to be
// called synchronously, with the resulting JavaScript values extracted.

using CryptoKeyPair = std::pair<CryptoKey*, CryptoKey*>;

template <typename T>
T ConvertCryptoResult(v8::Isolate*, const ScriptValue&);
template <>
CryptoKey* ConvertCryptoResult<CryptoKey*>(v8::Isolate* isolate,
                                           const ScriptValue& value) {
  return V8CryptoKey::ToWrappable(isolate, value.V8Value());
}
template <>
CryptoKeyPair ConvertCryptoResult<CryptoKeyPair>(v8::Isolate* isolate,
                                                 const ScriptValue& value) {
  NonThrowableExceptionState exception_state;
  Dictionary dictionary(isolate, value.V8Value(), exception_state);
  v8::Local<v8::Value> private_key, public_key;
  EXPECT_TRUE(dictionary.Get("publicKey", public_key));
  EXPECT_TRUE(dictionary.Get("privateKey", private_key));
  return std::make_pair(V8CryptoKey::ToWrappable(isolate, public_key),
                        V8CryptoKey::ToWrappable(isolate, private_key));
}
template <>
DOMException* ConvertCryptoResult<DOMException*>(v8::Isolate* isolate,
                                                 const ScriptValue& value) {
  return V8DOMException::ToWrappable(isolate, value.V8Value());
}
template <>
WebVector<unsigned char> ConvertCryptoResult<WebVector<unsigned char>>(
    v8::Isolate* isolate,
    const ScriptValue& value) {
  WebVector<unsigned char> vector;
  DummyExceptionStateForTesting exception_state;
  if (DOMArrayBuffer* buffer = NativeValueTraits<DOMArrayBuffer>::NativeValue(
          isolate, value.V8Value(), exception_state)) {
    vector.Assign(buffer->ByteSpan());
  }
  return vector;
}
template <>
bool ConvertCryptoResult<bool>(v8::Isolate*, const ScriptValue& value) {
  return value.V8Value()->IsTrue();
}

template <typename IDLType, typename T>
class WebCryptoResultAdapter
    : public ThenCallable<IDLType, WebCryptoResultAdapter<IDLType, T>> {
 public:
  explicit WebCryptoResultAdapter(base::RepeatingCallback<void(T)> function)
      : function_(std::move(function)) {}

  template <typename I = IDLType>
    requires(std::is_same_v<I, IDLAny>)
  void React(ScriptState* script_state, ScriptValue value) {
    function_.Run(ConvertCryptoResult<T>(script_state->GetIsolate(), value));
  }
  template <typename I = IDLType>
    requires(std::is_same_v<I, CryptoKey>)
  void React(ScriptState* script_state, CryptoKey* crypto_key) {
    function_.Run(crypto_key);
  }
  template <typename I = IDLType>
    requires(std::is_same_v<I, DOMArrayBuffer>)
  void React(ScriptState* script_state, DOMArrayBuffer* buffer) {
    WebVector<unsigned char> vector;
    vector.Assign(buffer->ByteSpan());
    function_.Run(vector);
  }

 private:
  base::RepeatingCallback<void(T)> function_;
  template <typename U>
  friend WebCryptoResult ToWebCryptoResult(ScriptState*,
                                           base::RepeatingCallback<void(U)>);
};

template <typename IDLType, typename T>
WebCryptoResult ToWebCryptoResult(ScriptState* script_state,
                                  base::RepeatingCallback<void(T)> function) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLType>>(script_state);
  auto* result = MakeGarbageCollected<CryptoResultImpl>(script_state, resolver);
  resolver->Promise().Then(
      script_state,
      MakeGarbageCollected<WebCryptoResultAdapter<IDLType, T>>(
          std::move(function)),
      MakeGarbageCollected<WebCryptoResultAdapter<IDLAny, DOMException*>>(
          WTF::BindRepeating([](DOMException* exception) {
            CHECK(false) << "crypto operation failed";
          })));
  return result->Result();
}

template <typename T, typename IDLType, typename PMF, typename... Args>
T SubtleCryptoSync(ScriptState* script_state, PMF func, Args&&... args) {
  T result;
  base::RunLoop run_loop;
  (Platform::Current()->Crypto()->*func)(
      std::forward<Args>(args)...,
      ToWebCryptoResult<IDLType>(
          script_state,
          WTF::BindRepeating(
              [](T* out, base::OnceClosure quit_closure, T result) {
                *out = result;
                std::move(quit_closure).Run();
              },
              WTF::Unretained(&result), run_loop.QuitClosure())),
      scheduler::GetSingleThreadTaskRunnerForTesting());
  run_loop.Run();
  return result;
}

CryptoKey* SyncGenerateKey(ScriptState* script_state,
                           const WebCryptoAlgorithm& algorithm,
                           bool extractable,
                           WebCryptoKeyUsageMask usages) {
  return SubtleCryptoSync<CryptoKey*, IDLAny>(
      script_state, &WebCrypto::GenerateKey, algorithm, extractable, usages);
}

CryptoKeyPair SyncGenerateKeyPair(ScriptState* script_state,
                                  const WebCryptoAlgorithm& algorithm,
                                  bool extractable,
                                  WebCryptoKeyUsageMask usages) {
  return SubtleCryptoSync<CryptoKeyPair, IDLAny>(
      script_state, &WebCrypto::GenerateKey, algorithm, extractable, usages);
}

CryptoKey* SyncImportKey(ScriptState* script_state,
                         WebCryptoKeyFormat format,
                         WebVector<unsigned char> data,
                         const WebCryptoAlgorithm& algorithm,
                         bool extractable,
                         WebCryptoKeyUsageMask usages) {
  return SubtleCryptoSync<CryptoKey*, CryptoKey>(
      script_state, &WebCrypto::ImportKey, format, data, algorithm, extractable,
      usages);
}

WebVector<uint8_t> SyncExportKey(ScriptState* script_state,
                                 WebCryptoKeyFormat format,
                                 const WebCryptoKey& key) {
  return SubtleCryptoSync<WebVector<uint8_t>, IDLAny>(
      script_state, &WebCrypto::ExportKey, format, key);
}

WebVector<uint8_t> SyncEncrypt(ScriptState* script_state,
                               const WebCryptoAlgorithm& algorithm,
                               const WebCryptoKey& key,
                               WebVector<unsigned char> data) {
  return SubtleCryptoSync<WebVector<uint8_t>, IDLAny>(
      script_state, &WebCrypto::Encrypt, algorithm, key, data);
}

WebVector<uint8_t> SyncDecrypt(ScriptState* script_state,
                               const WebCryptoAlgorithm& algorithm,
                               const WebCryptoKey& key,
                               WebVector<unsigned char> data) {
  return SubtleCryptoSync<WebVector<uint8_t>, IDLAny>(
      script_state, &WebCrypto::Decrypt, algorithm, key, data);
}

WebVector<uint8_t> SyncSign(ScriptState* script_state,
                            const WebCryptoAlgorithm& algorithm,
                            const WebCryptoKey& key,
                            WebVector<unsigned char> message) {
  return SubtleCryptoSync<WebVector<uint8_t>, IDLAny>(
      script_state, &WebCrypto::Sign, algorithm, key, message);
}

bool SyncVerifySignature(ScriptState* script_state,
                         const WebCryptoAlgorithm& algorithm,
                         const WebCryptoKey& key,
                         WebVector<unsigned char> signature,
                         WebVector<unsigned char> message) {
  return SubtleCryptoSync<bool, IDLAny>(script_state,
                                        &WebCrypto::VerifySignature, algorithm,
                                        key, signature, message);
}

WebVector<uint8_t> SyncDeriveBits(ScriptState* script_state,
                                  const WebCryptoAlgorithm& algorithm,
                                  const WebCryptoKey& key,
                                  unsigned length) {
  return SubtleCryptoSync<WebVector<uint8_t>, DOMArrayBuffer>(
      script_state, &WebCrypto::DeriveBits, algorithm, key, length);
}

// AES-128-CBC uses AES key params.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyAES) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate a 128-bit AES key.
  std::unique_ptr<WebCryptoAlgorithmParams> params(
      new WebCryptoAesKeyGenParams(128));
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdAesCbc, std::move(params));
  CryptoKey* key =
      SyncGenerateKey(script_state, algorithm, true,
                      kWebCryptoKeyUsageEncrypt | kWebCryptoKeyUsageDecrypt);

  // Round trip it and check the visible attributes.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<CryptoKey>::ToV8(scope.GetScriptState(), key);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_TRUE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageEncrypt | kWebCryptoKeyUsageDecrypt,
            new_key->Key().Usages());

  // Check that the keys have the same raw representation.
  WebVector<uint8_t> key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatRaw, key->Key());
  WebVector<uint8_t> new_key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatRaw, new_key->Key());
  EXPECT_THAT(new_key_raw, ElementsAreArray(key_raw));

  // Check that one can decrypt data encrypted with the other.
  Vector<unsigned char> iv(16, 0);
  WebCryptoAlgorithm encrypt_algorithm(
      kWebCryptoAlgorithmIdAesCbc, std::make_unique<WebCryptoAesCbcParams>(iv));
  Vector<unsigned char> plaintext{1, 2, 3};
  WebVector<uint8_t> ciphertext =
      SyncEncrypt(script_state, encrypt_algorithm, key->Key(), plaintext);
  WebVector<uint8_t> new_plaintext =
      SyncDecrypt(script_state, encrypt_algorithm, new_key->Key(), ciphertext);
  EXPECT_THAT(new_plaintext, ElementsAre(1, 2, 3));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyAES) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode a 128-bit AES key (non-extractable, decrypt only).
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x01, 0x01, 0x10, 0x04,
                       0x10, 0x7e, 0x25, 0xb2, 0xe8, 0x62, 0x3e, 0xd7, 0x83,
                       0x70, 0xa2, 0xae, 0x98, 0x79, 0x1b, 0xc5, 0xf7});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_FALSE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageDecrypt, new_key->Key().Usages());

  // Check that it can successfully decrypt data.
  Vector<uint8_t> iv(16, 0);
  Vector<uint8_t> ciphertext{0x33, 0x26, 0xe7, 0x64, 0x11, 0x5e, 0xf4, 0x60,
                             0x96, 0x08, 0x11, 0xaf, 0x65, 0x8b, 0x87, 0x04};
  WebCryptoAlgorithm encrypt_algorithm(
      kWebCryptoAlgorithmIdAesCbc, std::make_unique<WebCryptoAesCbcParams>(iv));
  WebVector<uint8_t> plaintext =
      SyncDecrypt(script_state, encrypt_algorithm, new_key->Key(), ciphertext);
  EXPECT_THAT(plaintext, ElementsAre(1, 2, 3));
}

// HMAC-SHA256 uses HMAC key params.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyHMAC) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate an HMAC-SHA256 key.
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  std::unique_ptr<WebCryptoAlgorithmParams> generate_key_params(
      new WebCryptoHmacKeyGenParams(hash, false, 0));
  WebCryptoAlgorithm generate_key_algorithm(kWebCryptoAlgorithmIdHmac,
                                            std::move(generate_key_params));
  CryptoKey* key =
      SyncGenerateKey(script_state, generate_key_algorithm, true,
                      kWebCryptoKeyUsageSign | kWebCryptoKeyUsageVerify);

  // Round trip it and check the visible attributes.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<CryptoKey>::ToV8(scope.GetScriptState(), key);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_TRUE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageSign | kWebCryptoKeyUsageVerify,
            new_key->Key().Usages());

  // Check that the keys have the same raw representation.
  WebVector<uint8_t> key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatRaw, key->Key());
  WebVector<uint8_t> new_key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatRaw, new_key->Key());
  EXPECT_THAT(new_key_raw, ElementsAreArray(key_raw));

  // Check that one can verify a message signed by the other.
  Vector<uint8_t> message{1, 2, 3};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdHmac, nullptr);
  WebVector<uint8_t> signature =
      SyncSign(script_state, algorithm, key->Key(), message);
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm, new_key->Key(),
                                  signature, message));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyHMAC) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode an HMAC-SHA256 key (non-extractable, verify only).
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x4b, 0x02, 0x40, 0x06, 0x10, 0x40, 0xd9,
       0xbd, 0x0e, 0x84, 0x24, 0x3c, 0xb0, 0xbc, 0xee, 0x36, 0x61, 0xdc,
       0xd0, 0xb0, 0xf5, 0x62, 0x09, 0xab, 0x93, 0x8c, 0x21, 0xaf, 0xb7,
       0x66, 0xa9, 0xfc, 0xd2, 0xaa, 0xd8, 0xd4, 0x79, 0xf2, 0x55, 0x3a,
       0xef, 0x46, 0x03, 0xec, 0x64, 0x2f, 0x68, 0xea, 0x9f, 0x9d, 0x1d,
       0xd2, 0x42, 0xd0, 0x13, 0x6c, 0xe0, 0xe1, 0xed, 0x9c, 0x59, 0x46,
       0x85, 0xaf, 0x41, 0xc4, 0x6a, 0x2d, 0x06, 0x7a});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_FALSE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageVerify, new_key->Key().Usages());

  // Check that it can successfully verify a signature.
  Vector<uint8_t> message{1, 2, 3};
  Vector<uint8_t> signature{0x91, 0xc8, 0x54, 0xc3, 0x19, 0x4e, 0xc5, 0x6c,
                            0x2d, 0x18, 0x91, 0x88, 0xd0, 0x56, 0x4d, 0xb6,
                            0x46, 0xc8, 0xb2, 0xa4, 0x2e, 0x1f, 0x0d, 0xe2,
                            0xd6, 0x60, 0xf9, 0xee, 0xb7, 0xd4, 0x55, 0x12};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdHmac, nullptr);
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm, new_key->Key(),
                                  signature, message));
}

// RSA-PSS-SHA256 uses RSA hashed key params.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyRSAHashed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate an RSA-PSS-SHA256 key pair.
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  std::unique_ptr<WebCryptoAlgorithmParams> generate_key_params(
      new WebCryptoRsaHashedKeyGenParams(hash, 1024, Vector<uint8_t>{1, 0, 1}));
  WebCryptoAlgorithm generate_key_algorithm(kWebCryptoAlgorithmIdRsaPss,
                                            std::move(generate_key_params));
  CryptoKey* public_key;
  CryptoKey* private_key;
  std::tie(public_key, private_key) =
      SyncGenerateKeyPair(script_state, generate_key_algorithm, true,
                          kWebCryptoKeyUsageSign | kWebCryptoKeyUsageVerify);

  // Round trip the private key and check the visible attributes.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<CryptoKey>::ToV8(scope.GetScriptState(), private_key);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  CryptoKey* new_private_key =
      V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_private_key, nullptr);
  EXPECT_EQ("private", new_private_key->type());
  EXPECT_TRUE(new_private_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageSign, new_private_key->Key().Usages());

  // Check that the keys have the same PKCS8 representation.
  WebVector<uint8_t> key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatPkcs8, private_key->Key());
  WebVector<uint8_t> new_key_raw = SyncExportKey(
      script_state, kWebCryptoKeyFormatPkcs8, new_private_key->Key());
  EXPECT_THAT(new_key_raw, Element
"""


```