Response:
The user is asking for a summary of the functionality of a C++ source code file for the Chromium Blink engine. This is the second of three parts of the file. I need to identify the main purpose of the code within this segment and explain it in relation to web technologies like JavaScript, HTML, and CSS, if applicable. I also need to consider potential usage errors and provide a possible debugging scenario.

Based on the test names (`RoundTripCryptoKeyRSA`, `DecodeCryptoKeyRSAHashed`, `RoundTripCryptoKeyEC`, `DecodeCryptoKeyEC`, `RoundTripCryptoKeyEd25519`, `DecodeCryptoKeyEd25519`, `RoundTripCryptoKeyX25519`, `DecodeCryptoKeyX25519`, `RoundTripCryptoKeyNoParams`, `DecodeCryptoKeyNoParams`, `DecodeCryptoKeyInvalid`, `RoundTripDOMFileSystem`, `RoundTripDOMFileSystemNotClonable`, `DecodeDOMFileSystem`, `DecodeInvalidDOMFileSystem`, `RoundTripVideoFrame`, `TransferVideoFrame`, `ClosedVideoFrameThrows`), it seems like this part of the file focuses on testing the serialization and deserialization of various JavaScript objects, particularly `CryptoKey`, `DOMFileSystem`, and `VideoFrame`, when using the module system in Chromium.

Here's a breakdown of what I can infer:

1. **CryptoKey Serialization/Deserialization:** The code tests the ability to serialize and then deserialize `CryptoKey` objects of different types (RSA, EC, EdDSA, X25519) and with different parameters. This involves ensuring the round-tripped keys have the same properties (type, extractability, usages) and can perform the same cryptographic operations (signing, verifying, deriving). The "Decode" tests check the deserialization of pre-serialized key data. The "Invalid" tests verify that the deserializer correctly handles malformed or invalid serialized key data. This directly relates to the Web Crypto API in JavaScript.

2. **DOMFileSystem Serialization/Deserialization:** The code tests the serialization and deserialization of `DOMFileSystem` objects. It checks if the properties of the file system (name, type, root URL) are preserved after the round trip. It also tests the behavior when a `DOMFileSystem` is not clonable, which is relevant for security and performance considerations in web applications.

3. **VideoFrame Serialization/Deserialization:** The code tests the serialization and deserialization of `VideoFrame` objects. It verifies that the frame size is maintained after serialization and deserialization. It also tests the transfer of `VideoFrame` objects, which is a mechanism to efficiently move data between different JavaScript contexts (like Web Workers). The "ClosedVideoFrameThrows" test likely verifies that operations on a closed `VideoFrame` result in the expected error. This relates to the `<video>` element and the Canvas API in HTML and JavaScript.

Now, let's formulate the summary based on these observations.
This代码片段主要的功能是**测试在Chromium的模块环境中使用`V8ScriptValueSerializerForModules`进行序列化和反序列化特定JavaScript对象的能力**。具体来说，它测试了以下几种类型的对象：

1. **CryptoKey (加密密钥):**  测试了各种加密算法生成的密钥的序列化和反序列化，包括：
    * **RSA:**  包括 `RSA-PSS` 签名算法的公钥和私钥。测试了密钥的往返序列化（序列化后再反序列化，验证属性是否一致）以及反序列化预先生成的密钥数据。还测试了使用序列化前后的密钥进行签名和验证的功能是否正常。
    * **EC (椭圆曲线):** 包括 `ECDSA` 签名算法的公钥和私钥，使用 NIST P-256 曲线。同样测试了往返序列化和反序列化预先生成的密钥数据，并验证了签名和验证功能。
    * **Ed25519:** 一种快速的椭圆曲线签名算法。测试了密钥对的往返序列化和反序列化，以及使用序列化前后的密钥进行签名和验证。也测试了解析预先生成的 Ed25519 公钥。
    * **X25519:** 一种用于密钥交换的椭圆曲线算法。测试了密钥对的往返序列化和反序列化，以及使用序列化前后的密钥进行密钥推导 (deriveBits)。也测试了解析预先生成的 X25519 私钥和公钥。
    * **No Params (无参数密钥):**  测试了像 `PBKDF2` 这种不需要特定参数就能生成或导入的密钥的序列化和反序列化。验证了密钥的属性，并测试了使用序列化前后的密钥进行密钥推导。
    * **Invalid CryptoKey:** 测试了反序列化各种无效的 `CryptoKey` 数据的情况，例如无效的算法 ID、参数类型不匹配、无效的密钥类型、无效的曲线名称、未知的用途 (usage) 等。

2. **DOMFileSystem (DOM文件系统):** 测试了 `DOMFileSystem` 对象的序列化和反序列化。验证了序列化和反序列化后文件系统的属性 (名称, 类型, 根URL) 是否保持一致。也测试了当 `DOMFileSystem` 对象不可克隆时序列化会抛出异常的情况。

3. **VideoFrame (视频帧):** 测试了 `VideoFrame` 对象的序列化和反序列化。验证了序列化和反序列化后视频帧的大小是否一致。还测试了视频帧的转移 (transfer) 功能，这涉及到在不同的执行上下文之间高效地移动视频帧数据。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  这些测试直接关系到 JavaScript 中的 Web Crypto API 和 File System API。
    * **Web Crypto API:**  `CryptoKey` 对象是 Web Crypto API 的核心组成部分，用于执行加密、解密、签名、验证等操作。这些测试确保了通过结构化克隆 (structured clone) 或消息传递 (message passing) 传输 `CryptoKey` 对象时，其状态能够正确保存和恢复。例如，在 JavaScript 中，你可以使用 `crypto.subtle.generateKey()` 生成密钥，然后通过 `postMessage` 将其发送到 Web Worker。这些测试确保了 Worker 端能够正确接收并使用这个密钥。
    * **File System API:** `DOMFileSystem` 对象是 File System API 的表示，允许 Web 应用访问用户的本地文件系统（在沙箱环境中）。这些测试确保了可以在不同的 JavaScript 上下文之间传递文件系统对象的引用。例如，一个主页面可能需要将一个文件系统的引用传递给一个 iframe 或 Web Worker。

* **HTML:**  `VideoFrame` 对象通常与 HTML 的 `<video>` 元素和 Canvas API 相关。
    * **`<video>` 元素:**  JavaScript 可以从 `<video>` 元素获取视频帧数据。
    * **Canvas API:**  可以使用 Canvas API 来操作和渲染视频帧。这些测试确保了视频帧数据可以通过结构化克隆或转移列表在不同的 JavaScript 环境中传递，例如，将主线程中的视频帧数据传递给一个用于进行图像处理的 Web Worker。

* **CSS:**  这个文件中的测试与 CSS 的功能没有直接关系。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `RoundTripCryptoKeyRSA` 测试):**

1. **在 JavaScript 中生成一个 RSA-PSS 密钥对：**
    ```javascript
    crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
      },
      true, // 是否可导出
      ["sign", "verify"]
    ).then(keyPair => {
      // 将 keyPair.privateKey 传递给序列化函数
    });
    ```
2. **使用 `V8ScriptValueSerializerForModules` 序列化该私钥。**
3. **使用 `V8ScriptValueDeserializerForModules` 反序列化序列化的数据。**

**预期输出:**

1. 反序列化得到的 `CryptoKey` 对象（`new_private_key`）应该是一个 "private" 类型的 RSA 密钥。
2. `new_private_key.extractable` 应该为 `true` (因为生成密钥时 `extractable` 设置为 `true`)。
3. `new_private_key` 的用途 (`Usages()`) 应该包含 `kWebCryptoKeyUsageSign`。
4. 导出原始密钥数据 (`SyncExportKey`) 后，原始密钥和反序列化后的密钥的 PKCS8 表示应该相同。
5. 使用反序列化后的私钥进行签名，然后使用原始公钥进行验证，应该成功。

**用户或编程常见的使用错误：**

1. **尝试序列化不可克隆的对象：** 例如，如果 `DOMFileSystem` 对象在创建时没有设置为可克隆，尝试将其传递给 Web Worker 或进行结构化克隆将会失败，并抛出 `DataCloneError`。测试 `RoundTripDOMFileSystemNotClonable` 就覆盖了这种情况。

    ```javascript
    // 假设 fileSystem 是一个不可克隆的 DOMFileSystem 对象
    worker.postMessage(fileSystem); // 可能抛出异常
    ```

2. **反序列化无效的密钥数据：**  如果尝试反序列化一个被篡改或者格式错误的密钥数据，反序列化过程应该返回 `null` 或者抛出错误。测试 `DecodeCryptoKeyInvalid` 覆盖了多种无效密钥数据的情况。

    ```javascript
    const invalidKeyData = new Uint8Array([...]); // 一段无效的密钥数据
    const deserializedKey = deserializeKey(invalidKeyData);
    if (!deserializedKey) {
      console.error("反序列化密钥失败");
    }
    ```

3. **在错误的上下文中使用已转移的对象：**  如果一个 `VideoFrame` 对象被转移 (transfer)，那么原始的上下文将无法再访问该对象，尝试访问会导致错误。

    ```javascript
    const videoFrame = ...;
    worker.postMessage({ frame: videoFrame }, [videoFrame]); // 转移 videoFrame 到 worker
    console.log(videoFrame.width); // 报错，因为 videoFrame 已被转移
    ```

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在一个网页上使用了需要进行加密操作的功能，并且这个网页使用了 Web Worker 来执行耗时的加密任务。

1. **用户操作触发加密请求：** 用户点击了一个按钮或者执行了某个操作，导致网页的 JavaScript 代码需要生成一个加密密钥，例如用于加密用户数据。
2. **生成密钥：**  网页的主线程 JavaScript 使用 `crypto.subtle.generateKey()` 生成一个 `CryptoKey` 对象。
3. **将密钥发送到 Web Worker：** 为了不阻塞主线程，主线程使用 `postMessage()` 将生成的 `CryptoKey` 对象发送到 Web Worker 进行进一步的加密操作。 这就需要对 `CryptoKey` 对象进行序列化。
4. **Web Worker 接收密钥并使用：** Web Worker 接收到消息，并尝试反序列化接收到的数据以获取 `CryptoKey` 对象。
5. **加密操作：** Web Worker 使用反序列化得到的 `CryptoKey` 对象执行加密操作。

如果在上述步骤中出现问题，例如 Web Worker 无法成功反序列化密钥，那么开发者可能需要查看 `blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc` 这个文件中的测试用例，来理解序列化和反序列化的机制，以及可能出现的错误情况。  开发者可以根据测试用例中提供的示例数据和预期行为，来分析他们自己的代码中哪里出了问题。例如，他们可以检查发送到 Web Worker 的数据的格式是否正确，或者检查他们使用的加密算法和参数是否与测试用例中的一致。

**归纳一下它的功能 (第2部分):**

这部分代码的功能是**详细测试了在 Chromium 的模块环境下，`V8ScriptValueSerializerForModules` 对各种类型的加密密钥 (`CryptoKey`) 和特定 DOM 对象 (`DOMFileSystem`, `VideoFrame`) 进行序列化和反序列化的正确性**。 它涵盖了密钥的创建、导出、导入、签名、验证、密钥推导等操作的序列化和反序列化，以及有效和无效数据情况的处理。 对于 `DOMFileSystem` 和 `VideoFrame`，它测试了基本属性的保持以及对象转移的机制。 这些测试确保了在模块环境中使用结构化克隆或消息传递传递这些对象时，其状态和功能能够得到正确的保留和恢复。

### 提示词
```
这是目录为blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
sAreArray(key_raw));

  // Check that one can verify a message signed by the other.
  Vector<uint8_t> message{1, 2, 3};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdRsaPss,
                               std::make_unique<WebCryptoRsaPssParams>(16));
  WebVector<uint8_t> signature =
      SyncSign(script_state, algorithm, new_private_key->Key(), message);
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm, public_key->Key(),
                                  signature, message));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyRSAHashed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode an RSA-PSS-SHA256 public key (extractable, verify only).
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x4b, 0x04, 0x0d, 0x01, 0x80, 0x08, 0x03, 0x01,
       0x00, 0x01, 0x06, 0x11, 0xa2, 0x01, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06,
       0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
       0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xae,
       0xef, 0x7f, 0xee, 0x3a, 0x48, 0x48, 0xea, 0xce, 0x18, 0x0b, 0x86, 0x34,
       0x6c, 0x1d, 0xc5, 0xe8, 0xea, 0xab, 0x33, 0xd0, 0x6f, 0x63, 0x82, 0x37,
       0x18, 0x83, 0x01, 0x3d, 0x11, 0xe3, 0x03, 0x79, 0x2c, 0x0a, 0x79, 0xe6,
       0xf5, 0x14, 0x73, 0x5f, 0x50, 0xa8, 0x17, 0x10, 0x58, 0x59, 0x20, 0x09,
       0x54, 0x56, 0xe0, 0x86, 0x07, 0x5f, 0xab, 0x9c, 0x86, 0xb1, 0x80, 0xcb,
       0x72, 0x5e, 0x55, 0x8b, 0x83, 0x98, 0xbf, 0xed, 0xbe, 0xdf, 0xdc, 0x6b,
       0xff, 0xcf, 0x50, 0xee, 0xcc, 0x7c, 0xb4, 0x8c, 0x68, 0x75, 0x66, 0xf2,
       0x21, 0x0d, 0xf5, 0x50, 0xdd, 0x06, 0x29, 0x57, 0xf7, 0x44, 0x42, 0x3d,
       0xd9, 0x30, 0xb0, 0x8a, 0x5e, 0x8f, 0xea, 0xff, 0x45, 0xa0, 0x1d, 0x04,
       0xbe, 0xc5, 0x82, 0xd3, 0x69, 0x4e, 0xcd, 0x14, 0x7b, 0xf5, 0x00, 0x3c,
       0xb1, 0x19, 0x24, 0xae, 0x8d, 0x22, 0xb5, 0x02, 0x03, 0x01, 0x00, 0x01});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_public_key =
      V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_public_key, nullptr);
  EXPECT_EQ("public", new_public_key->type());
  EXPECT_TRUE(new_public_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageVerify, new_public_key->Key().Usages());

  // Check that it can successfully verify a signature.
  Vector<uint8_t> message{1, 2, 3};
  Vector<uint8_t> signature{
      0x9b, 0x61, 0xc8, 0x4b, 0x1c, 0xe5, 0x24, 0xe6, 0x54, 0x73, 0x1a, 0xb5,
      0xe3, 0x22, 0xc7, 0xd1, 0x36, 0x3d, 0x85, 0x99, 0x26, 0x45, 0xcc, 0x54,
      0x98, 0x1f, 0xf3, 0x9d, 0x32, 0x87, 0xdc, 0xbb, 0xb6, 0x3a, 0xa4, 0x6d,
      0xd4, 0xb5, 0x52, 0x83, 0x24, 0x02, 0xc7, 0x62, 0x1f, 0xb7, 0x27, 0x2b,
      0x5a, 0x54, 0x59, 0x17, 0x81, 0x8a, 0xf5, 0x0c, 0x17, 0x01, 0x45, 0x3f,
      0x14, 0xf2, 0x3c, 0x27, 0x4d, 0xfa, 0xc0, 0x0a, 0x82, 0x4b, 0xb2, 0xf4,
      0x7b, 0x14, 0x1b, 0xd8, 0xbc, 0xe9, 0x2e, 0xd4, 0x55, 0x27, 0x62, 0x83,
      0x11, 0xed, 0xc2, 0x81, 0x7d, 0xa9, 0x4f, 0xe0, 0xef, 0x0e, 0xa5, 0xa5,
      0xc6, 0x40, 0x46, 0xbf, 0x90, 0x19, 0xfc, 0xc8, 0x51, 0x0e, 0x0f, 0x62,
      0xeb, 0x17, 0x68, 0x1f, 0xbd, 0xfa, 0xf7, 0xd6, 0x1f, 0xa4, 0x7c, 0x9e,
      0x9e, 0xb1, 0x96, 0x8f, 0xe6, 0x5e, 0x89, 0x99};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdRsaPss,
                               std::make_unique<WebCryptoRsaPssParams>(16));
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm,
                                  new_public_key->Key(), signature, message));
}

// ECDSA uses EC key params.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyEC) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate an ECDSA key pair with the NIST P-256 curve.
  std::unique_ptr<WebCryptoAlgorithmParams> generate_key_params(
      new WebCryptoEcKeyGenParams(kWebCryptoNamedCurveP256));
  WebCryptoAlgorithm generate_key_algorithm(kWebCryptoAlgorithmIdEcdsa,
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
  EXPECT_THAT(new_key_raw, ElementsAreArray(key_raw));

  // Check that one can verify a message signed by the other.
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  Vector<uint8_t> message{1, 2, 3};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdEcdsa,
                               std::make_unique<WebCryptoEcdsaParams>(hash));
  WebVector<uint8_t> signature =
      SyncSign(script_state, algorithm, new_private_key->Key(), message);
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm, public_key->Key(),
                                  signature, message));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyEC) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode an ECDSA public key with the NIST P-256 curve (extractable).
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x4b, 0x05, 0x0e, 0x01, 0x01, 0x11, 0x5b, 0x30,
       0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
       0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
       0x00, 0x04, 0xfe, 0x16, 0x70, 0x29, 0x07, 0x2c, 0x11, 0xbf, 0xcf, 0xb7,
       0x9d, 0x54, 0x35, 0x3d, 0xc7, 0x85, 0x66, 0x26, 0xa5, 0xda, 0x69, 0x4c,
       0x07, 0xd5, 0x74, 0xcb, 0x93, 0xf4, 0xdb, 0x7e, 0x38, 0x3c, 0xa8, 0x98,
       0x2a, 0x6f, 0xb2, 0xf5, 0x48, 0x73, 0x2f, 0x59, 0x21, 0xa0, 0xa9, 0xf5,
       0x6e, 0x37, 0x0c, 0xfc, 0x5b, 0x68, 0x0e, 0x19, 0x5b, 0xd3, 0x4f, 0xb4,
       0x0e, 0x1c, 0x31, 0x5a, 0xaa, 0x2d});

  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_public_key =
      V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_public_key, nullptr);
  EXPECT_EQ("public", new_public_key->type());
  EXPECT_TRUE(new_public_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageVerify, new_public_key->Key().Usages());

  // Check that it can successfully verify a signature.
  Vector<uint8_t> message{1, 2, 3};
  Vector<uint8_t> signature{
      0xee, 0x63, 0xa2, 0xa3, 0x87, 0x6c, 0x9f, 0xc5, 0x64, 0x12, 0x87,
      0x0d, 0xc7, 0xff, 0x3c, 0xd2, 0x6c, 0x2b, 0x2c, 0x0b, 0x2b, 0x8d,
      0x3c, 0xe0, 0x3f, 0xd3, 0xfc, 0x28, 0xf0, 0xa1, 0x22, 0x69, 0x0a,
      0x33, 0x4d, 0x48, 0x97, 0xad, 0x67, 0xa9, 0x6e, 0x24, 0xe7, 0x31,
      0x09, 0xdb, 0xa8, 0x92, 0x48, 0x70, 0xa6, 0x6c, 0x46, 0x4d, 0x0b,
      0x83, 0x27, 0x37, 0x69, 0x4d, 0x32, 0x63, 0x1e, 0x82};
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdEcdsa,
                               std::make_unique<WebCryptoEcdsaParams>(hash));
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm,
                                  new_public_key->Key(), signature, message));
}

// Ed25519 uses no params.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyEd25519) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate an Ed25519 key pair.
  WebCryptoAlgorithm generate_key_algorithm(kWebCryptoAlgorithmIdEd25519,
                                            nullptr);
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
  EXPECT_THAT(new_key_raw, ElementsAreArray(key_raw));

  // Check that one can verify a message signed by the other.
  Vector<uint8_t> message{1, 2, 3};
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdEd25519, nullptr);
  WebVector<uint8_t> signature =
      SyncSign(script_state, algorithm, new_private_key->Key(), message);

  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm, public_key->Key(),
                                  signature, message));
}

// Ed25519 uses no params.
TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyEd25519) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode an Ed25519 public key (extractable).
  // TEST 3 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x14, 0xff, 0x0f, 0x5c, 0x4b, 0x07, 0x12, 0x01, 0x11, 0x2c,
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
      0x00, 0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4,
      0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba,
      0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_public_key =
      V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_public_key, nullptr);
  EXPECT_EQ("public", new_public_key->type());
  EXPECT_TRUE(new_public_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageVerify, new_public_key->Key().Usages());

  // Check that it can successfully verify a signature.
  Vector<uint8_t> message{0xaf, 0x82};
  Vector<uint8_t> signature{
      0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6,
      0x9c, 0x3a, 0xbe, 0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74,
      0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac, 0x18,
      0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60,
      0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2,
      0x8d, 0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
  };
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdEd25519, nullptr);
  EXPECT_TRUE(SyncVerifySignature(script_state, algorithm,
                                  new_public_key->Key(), signature, message));
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyX25519) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Generate an X25519 key pair.
  WebCryptoAlgorithm generate_key_algorithm(kWebCryptoAlgorithmIdX25519,
                                            nullptr);
  auto [public_key, private_key] = SyncGenerateKeyPair(
      script_state, generate_key_algorithm, true,
      kWebCryptoKeyUsageDeriveKey | kWebCryptoKeyUsageDeriveBits);

  // Round trip the private key and check the visible attributes.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<CryptoKey>::ToV8(scope.GetScriptState(), private_key);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  CryptoKey* new_private_key =
      V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_private_key, nullptr);
  EXPECT_EQ("private", new_private_key->type());
  EXPECT_TRUE(new_private_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageDeriveKey | kWebCryptoKeyUsageDeriveBits,
            new_private_key->Key().Usages());

  // Check that the keys have the same PKCS8 representation.
  WebVector<uint8_t> key_raw =
      SyncExportKey(script_state, kWebCryptoKeyFormatPkcs8, private_key->Key());
  WebVector<uint8_t> new_key_raw = SyncExportKey(
      script_state, kWebCryptoKeyFormatPkcs8, new_private_key->Key());
  EXPECT_THAT(new_key_raw, ElementsAreArray(key_raw));

  // Check that the keys derive the same bits.
  auto params =
      std::make_unique<WebCryptoEcdhKeyDeriveParams>(public_key->Key());
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdX25519, std::move(params));
  WebVector<uint8_t> bits_raw =
      SyncDeriveBits(script_state, algorithm, private_key->Key(), 32);
  WebVector<uint8_t> new_bits_raw =
      SyncDeriveBits(script_state, algorithm, new_private_key->Key(), 32);
  EXPECT_EQ(4u, bits_raw.size());
  EXPECT_THAT(new_bits_raw, ElementsAreArray(bits_raw));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyX25519) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode an X25519 private key (non-extractable).
  // TEST from https://www.rfc-editor.org/rfc/rfc7748#section-6.1
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x14, 0xff, 0x0f, 0x5c, 0x4b, 0x08, 0x13, 0x02, 0x80, 0x02, 0x30,
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
      0x04, 0x22, 0x04, 0x20, 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
      0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87,
      0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* private_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(private_key, nullptr);
  EXPECT_EQ("private", private_key->type());
  EXPECT_FALSE(private_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageDeriveBits, private_key->Key().Usages());

  // Decode an X25519 public key (extractable).
  // TEST from https://www.rfc-editor.org/rfc/rfc7748#section-6.1
  input = SerializedValue({
      0xff, 0x14, 0xff, 0x0f, 0x5c, 0x4b, 0x08, 0x13, 0x01, 0x01, 0x2c,
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21,
      0x00, 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b,
      0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b,
      0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
  });
  result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* public_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(public_key, nullptr);
  EXPECT_EQ("public", public_key->type());
  EXPECT_TRUE(public_key->extractable());
  EXPECT_EQ(0, public_key->Key().Usages());

  // Check that it derives the right bits.
  auto params =
      std::make_unique<WebCryptoEcdhKeyDeriveParams>(public_key->Key());
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdX25519, std::move(params));
  WebVector<uint8_t> bits_raw =
      SyncDeriveBits(script_state, algorithm, private_key->Key(), 32);
  // Shared secret key.
  // TEST from https://www.rfc-editor.org/rfc/rfc7748#section-6.1
  auto expected_bits = ElementsAre(0x4a, 0x5d, 0x9d, 0x5b);
  EXPECT_THAT(bits_raw, expected_bits);
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripCryptoKeyNoParams) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Import some data into a PBKDF2 state.
  WebCryptoAlgorithm import_key_algorithm(kWebCryptoAlgorithmIdPbkdf2, nullptr);
  CryptoKey* key = SyncImportKey(script_state, kWebCryptoKeyFormatRaw,
                                 Vector<uint8_t>{1, 2, 3}, import_key_algorithm,
                                 false, kWebCryptoKeyUsageDeriveBits);

  // Round trip the key and check the visible attributes.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<CryptoKey>::ToV8(scope.GetScriptState(), key);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_FALSE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageDeriveBits, new_key->Key().Usages());

  // Check that the keys derive the same bits.
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  WebVector<uint8_t> salt(static_cast<size_t>(16));
  std::unique_ptr<WebCryptoAlgorithmParams> params(
      new WebCryptoPbkdf2Params(hash, salt, 1));
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdPbkdf2, std::move(params));
  WebVector<uint8_t> bits_raw =
      SyncDeriveBits(script_state, algorithm, key->Key(), 16);
  WebVector<uint8_t> new_bits_raw =
      SyncDeriveBits(script_state, algorithm, new_key->Key(), 16);
  EXPECT_EQ(2u, bits_raw.size());
  EXPECT_THAT(new_bits_raw, ElementsAreArray(bits_raw));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyNoParams) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Decode PBKDF2 state seeded with {1,2,3}.
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x06, 0x11, 0xa0, 0x02,
                       0x03, 0x01, 0x02, 0x03, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  CryptoKey* new_key = V8CryptoKey::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_key, nullptr);
  EXPECT_EQ("secret", new_key->type());
  EXPECT_FALSE(new_key->extractable());
  EXPECT_EQ(kWebCryptoKeyUsageDeriveKey | kWebCryptoKeyUsageDeriveBits,
            new_key->Key().Usages());

  // Check that it derives the right bits.
  WebCryptoAlgorithm hash(kWebCryptoAlgorithmIdSha256, nullptr);
  WebVector<uint8_t> salt(static_cast<size_t>(16));
  std::unique_ptr<WebCryptoAlgorithmParams> params(
      new WebCryptoPbkdf2Params(hash, salt, 3));
  WebCryptoAlgorithm algorithm(kWebCryptoAlgorithmIdPbkdf2, std::move(params));
  WebVector<uint8_t> bits_raw =
      SyncDeriveBits(script_state, algorithm, new_key->Key(), 32);
  EXPECT_THAT(bits_raw, ElementsAre(0xd8, 0x0e, 0x2f, 0x69));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeCryptoKeyInvalid) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("https://secure.context/"));
  ScriptState* script_state = scope.GetScriptState();

  // Invalid algorithm ID.
  EXPECT_TRUE(V8ScriptValueDeserializerForModules(
                  script_state,
                  SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x06, 0x7f,
                                   0xa0, 0x02, 0x03, 0x01, 0x02, 0x03, 0x00}))
                  .Deserialize()
                  ->IsNull());

  // Algorithm ID / params type mismatch (AES params, RSA-OEAP ID).
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state,
          SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x01, 0x0a, 0x10, 0x04,
                           0x10, 0x7e, 0x25, 0xb2, 0xe8, 0x62, 0x3e, 0xd7, 0x83,
                           0x70, 0xa2, 0xae, 0x98, 0x79, 0x1b, 0xc5, 0xf7}))
          .Deserialize()
          ->IsNull());

  // Invalid asymmetric key type.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state,
          SerializedValue(
              {0xff, 0x09, 0x3f, 0x00, 0x4b, 0x05, 0x0e, 0x7f, 0x01, 0x11, 0x5b,
               0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
               0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
               0x07, 0x03, 0x42, 0x00, 0x04, 0xfe, 0x16, 0x70, 0x29, 0x07, 0x2c,
               0x11, 0xbf, 0xcf, 0xb7, 0x9d, 0x54, 0x35, 0x3d, 0xc7, 0x85, 0x66,
               0x26, 0xa5, 0xda, 0x69, 0x4c, 0x07, 0xd5, 0x74, 0xcb, 0x93, 0xf4,
               0xdb, 0x7e, 0x38, 0x3c, 0xa8, 0x98, 0x2a, 0x6f, 0xb2, 0xf5, 0x48,
               0x73, 0x2f, 0x59, 0x21, 0xa0, 0xa9, 0xf5, 0x6e, 0x37, 0x0c, 0xfc,
               0x5b, 0x68, 0x0e, 0x19, 0x5b, 0xd3, 0x4f, 0xb4, 0x0e, 0x1c, 0x31,
               0x5a, 0xaa, 0x2d}))
          .Deserialize()
          ->IsNull());

  // Invalid named curve.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state,
          SerializedValue(
              {0xff, 0x09, 0x3f, 0x00, 0x4b, 0x05, 0x0e, 0x01, 0x7f, 0x11, 0x5b,
               0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
               0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
               0x07, 0x03, 0x42, 0x00, 0x04, 0xfe, 0x16, 0x70, 0x29, 0x07, 0x2c,
               0x11, 0xbf, 0xcf, 0xb7, 0x9d, 0x54, 0x35, 0x3d, 0xc7, 0x85, 0x66,
               0x26, 0xa5, 0xda, 0x69, 0x4c, 0x07, 0xd5, 0x74, 0xcb, 0x93, 0xf4,
               0xdb, 0x7e, 0x38, 0x3c, 0xa8, 0x98, 0x2a, 0x6f, 0xb2, 0xf5, 0x48,
               0x73, 0x2f, 0x59, 0x21, 0xa0, 0xa9, 0xf5, 0x6e, 0x37, 0x0c, 0xfc,
               0x5b, 0x68, 0x0e, 0x19, 0x5b, 0xd3, 0x4f, 0xb4, 0x0e, 0x1c, 0x31,
               0x5a, 0xaa, 0x2d}))
          .Deserialize()
          ->IsNull());

  // Unknown usage.
  EXPECT_TRUE(V8ScriptValueDeserializerForModules(
                  script_state,
                  SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x06, 0x11,
                                   0x80, 0x40, 0x03, 0x01, 0x02, 0x03, 0x00}))
                  .Deserialize()
                  ->IsNull());

  // AES key length (16384) that would overflow unsigned short after multiply by
  // 8 (to convert from bytes to bits).
  EXPECT_TRUE(V8ScriptValueDeserializerForModules(
                  script_state,
                  SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x01, 0x01,
                                   0x80, 0x80, 0x02, 0x04, 0x10, 0x7e, 0x25,
                                   0xb2, 0xe8, 0x62, 0x3e, 0xd7, 0x83, 0x70,
                                   0xa2, 0xae, 0x98, 0x79, 0x1b, 0xc5, 0xf7}))
                  .Deserialize()
                  ->IsNull());

  // HMAC length (1073741824) that would overflow 32-bit unsigned after multiply
  // by 8 (to convert from bytes to bits).
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state,
          SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x02, 0x80, 0x80, 0x80,
                           0x80, 0x04, 0x06, 0x10, 0x40, 0xd9, 0xbd, 0x0e, 0x84,
                           0x24, 0x3c, 0xb0, 0xbc, 0xee, 0x36, 0x61, 0xdc, 0xd0,
                           0xb0, 0xf5, 0x62, 0x09, 0xab, 0x93, 0x8c, 0x21, 0xaf,
                           0xb7, 0x66, 0xa9, 0xfc, 0xd2, 0xaa, 0xd8, 0xd4, 0x79,
                           0xf2, 0x55, 0x3a, 0xef, 0x46, 0x03, 0xec, 0x64, 0x2f,
                           0x68, 0xea, 0x9f, 0x9d, 0x1d, 0xd2, 0x42, 0xd0, 0x13,
                           0x6c, 0xe0, 0xe1, 0xed, 0x9c, 0x59, 0x46, 0x85, 0xaf,
                           0x41, 0xc4, 0x6a, 0x2d, 0x06, 0x7a}))
          .Deserialize()
          ->IsNull());

  // Input ends before end of declared public exponent size.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state, SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x04,
                                         0x0d, 0x01, 0x80, 0x08, 0x03, 0x01}))
          .Deserialize()
          ->IsNull());

  // ECDH key with invalid key data.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state, SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x05,
                                         0x0e, 0x01, 0x01, 0x4b, 0x00, 0x00}))
          .Deserialize()
          ->IsNull());

  // Public RSA key with invalid key data.
  // The key data is a single byte (0x00), which is not a valid SPKI.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state, SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4b, 0x04,
                                         0x0d, 0x01, 0x80, 0x08, 0x03, 0x01,
                                         0x00, 0x01, 0x06, 0x11, 0x01, 0x00}))
          .Deserialize()
          ->IsNull());
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripDOMFileSystem) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto* fs = MakeGarbageCollected<DOMFileSystem>(
      scope.GetExecutionContext(), "http_example.com_0:Persistent",
      mojom::blink::FileSystemType::kPersistent,
      KURL("filesystem:http://example.com/persistent/"));
  // At time of writing, this can only happen for filesystems from PPAPI.
  fs->MakeClonable();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMFileSystem>::ToV8(scope.GetScriptState(), fs);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);
  ASSERT_FALSE(result.IsEmpty());
  DOMFileSystem* new_fs =
      V8DOMFileSystem::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_fs, nullptr);
  EXPECT_EQ("http_example.com_0:Persistent", new_fs->name());
  EXPECT_EQ(mojom::blink::FileSystemType::kPersistent, new_fs->GetType());
  EXPECT_EQ("filesystem:http://example.com/persistent/",
            new_fs->RootURL().GetString());
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripDOMFileSystemNotClonable) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  auto* fs = MakeGarbageCollected<DOMFileSystem>(
      scope.GetExecutionContext(), "http_example.com_0:Persistent",
      mojom::blink::FileSystemType::kPersistent,
      KURL("filesystem:http://example.com/persistent/0/"));
  ASSERT_FALSE(fs->Clonable());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMFileSystem>::ToV8(scope.GetScriptState(), fs);
  EXPECT_FALSE(
      V8ScriptValueSerializer(scope.GetScriptState())
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(HadDOMExceptionInModulesTest("DataCloneError",
                                           scope.GetScriptState(), try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeDOMFileSystem) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  // This is encoded data generated from Chromium (around M56).
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x64, 0x01, 0x1d, 0x68, 0x74, 0x74, 0x70, 0x5f,
       0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x5f,
       0x30, 0x3a, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74,
       0x29, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3a,
       0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70,
       0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65, 0x72, 0x73, 0x69,
       0x73, 0x74, 0x65, 0x6e, 0x74, 0x2f});

  // Decode test.
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializerForModules(script_state, input).Deserialize();
  DOMFileSystem* new_fs =
      V8DOMFileSystem::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_fs, nullptr);
  EXPECT_EQ("http_example.com_0:Persistent", new_fs->name());
  EXPECT_EQ(mojom::blink::FileSystemType::kPersistent, new_fs->GetType());
  EXPECT_EQ("filesystem:http://example.com/persistent/",
            new_fs->RootURL().GetString());
}

TEST(V8ScriptValueSerializerForModulesTest, DecodeInvalidDOMFileSystem) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  // Filesystem type out of range.
  EXPECT_TRUE(
      V8ScriptValueDeserializerForModules(
          script_state,
          SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x64, 0x04, 0x1d, 0x68, 0x74,
                           0x74, 0x70, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
                           0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x5f, 0x30, 0x3a, 0x50,
                           0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74,
                           0x29, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74,
                           0x65, 0x6d, 0x3a, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
                           0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
                           0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65, 0x72, 0x73, 0x69,
                           0x73, 0x74, 0x65, 0x6e, 0x74, 0x2f

          }))
          .Deserialize()
          ->IsNull());
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripVideoFrame) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const gfx::Size kFrameSize(600, 480);
  scoped_refptr<media::VideoFrame> media_frame =
      media::VideoFrame::CreateBlackFrame(kFrameSize);

  auto* blink_frame = MakeGarbageCollected<VideoFrame>(
      media_frame, scope.GetExecutionContext());

  // Round trip the frame and make sure the size is the same.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<VideoFrame>::ToV8(scope.GetScriptState(), blink_frame);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);

  VideoFrame* new_frame = V8VideoFrame::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_frame, nullptr);
  EXPECT_EQ(new_frame->frame()->natural_size(), kFrameSize);

  EXPECT_FALSE(media_frame->HasOneRef());

  // Closing |blink_frame| and |new_frame| should remove all references
  // to |media_frame|.
  blink_frame->close();
  EXPECT_FALSE(media_frame->HasOneRef());

  new_frame->close();
  EXPECT_TRUE(media_frame->HasOneRef());
}

TEST(V8ScriptValueSerializerForModulesTest, TransferVideoFrame) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const gfx::Size kFrameSize(600, 480);
  scoped_refptr<media::VideoFrame> media_frame =
      media::VideoFrame::CreateBlackFrame(kFrameSize);

  auto* blink_frame = MakeGarbageCollected<VideoFrame>(
      media_frame, scope.GetExecutionContext());

  // Transfer the frame and make sure the size is the same.
  Transferables transferables;
  VideoFrameTransferList* transfer_list =
      transferables.GetOrCreateTransferList<VideoFrameTransferList>();
  transfer_list->video_frames.push_back(blink_frame);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<VideoFrame>::ToV8(scope.GetScriptState(), blink_frame);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  VideoFrame* new_frame = V8VideoFrame::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_frame, nullptr);
  EXPECT_EQ(new_frame->frame()->natural_size(), kFrameSize);

  EXPECT_FALSE(media_frame->HasOneRef());

  // The transfer should have closed the source frame.
  EXPECT_EQ(blink_frame->frame(), nullptr);

  // Closing |new_frame| should remove all references to |media_frame|.
  new_frame->close();
  EXPECT_TRUE(media_frame->HasOneRef());
}

TEST(V8ScriptValueSerializerForModulesTest, ClosedVideoFrameThrows) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  const gfx::Size kFrameSize(600, 480);
  scoped_refptr<media::VideoFrame> media_frame =
      media::VideoFrame::CreateBlackFrame(kFrameSize);

  // Create and close the frame.
  auto* blink_frame = MakeGarbageCollected<VideoFrame>(
      media_frame, scope.GetExecutionContext());
  blink_frame-
```