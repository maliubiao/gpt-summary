Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Context:**

The first thing to note is the directory: `net/third_party/quiche/src/quiche/quic/test_tools/`. This immediately signals that this code is related to testing within the QUIC implementation (likely the Chromium QUIC implementation as indicated by the "net" prefix and the presence of "quiche"). The name "test_certificates.cc" strongly suggests that the file deals with cryptographic certificates used in testing.

**2. Examining the Code - First Pass (Scanning for Keywords and Patterns):**

I'd scan the code for recognizable patterns:

* **Large String Literals:**  The code is dominated by large, seemingly random sequences of hexadecimal escape codes (`\x...`). This is a strong indicator that these represent binary data, and given the file name, these are likely encoded certificates and private keys.
* **`ABSL_CONST_INIT`:** This macro from the Abseil library suggests that these are global constants initialized at compile time. This reinforces the idea that these are static test resources.
* **`absl::string_view`:**  This confirms that the data is being treated as string-like data without unnecessary copying. It's a lightweight way to refer to the underlying character arrays.
* **Variable Naming:**  The variable names (`kSelfSignedCert...Raw`, `kWildcardCert...Raw`, `kTestEcPrivateKeyLegacyPem`) are very descriptive and point to the purpose of each data block. "Raw" suggests the binary representation, and the other parts indicate the type of certificate/key.
* **`R"(...)"`:**  This is a raw string literal, commonly used for multi-line strings, particularly helpful for PEM-encoded data.

**3. Deducing Functionality (Initial Hypotheses):**

Based on the initial scan, I can form some hypotheses:

* **Purpose:** This file provides pre-generated cryptographic certificates and private keys for testing the QUIC protocol.
* **Types of Certificates:** It likely includes self-signed certificates (for basic connection testing), wildcard certificates (for testing domain matching), and potentially other types (like the EC private key).
* **Usage:**  These constants will be used in test code to simulate different TLS/QUIC handshake scenarios, likely involving server and client authentication.

**4. Deep Dive - Analyzing Specific Data:**

Now, I'd look at the specifics:

* **`kSelfSignedCert...`:** The name clearly indicates a self-signed certificate. This is the most basic type for initial testing.
* **`kWildcardCertificate...`:**  A wildcard certificate is used for domains like `*.example.com`, allowing a single certificate to cover multiple subdomains. This is important for testing more realistic scenarios. The data itself looks like a binary representation of an X.509 certificate.
* **`kWildcardCertificatePrivateKey...`:** This is the corresponding private key for the wildcard certificate. Private keys are essential for proving ownership of the certificate.
* **`kTestEcPrivateKeyLegacyPem`:**  The "PEM" suffix and the `BEGIN EC PRIVATE KEY` markers clearly identify this as a PEM-encoded Elliptic Curve private key. "Legacy" suggests it might be an older format or used for compatibility testing.

**5. Connecting to JavaScript (If Applicable):**

The prompt specifically asks about the relationship to JavaScript. While this C++ code itself doesn't directly *execute* JavaScript, it provides resources *used* by networking components that *interact* with JavaScript in a browser context.

* **TLS Handshake in Browsers:**  When a browser (running JavaScript) makes an HTTPS connection using QUIC, the underlying C++ networking stack (including code that might use these test certificates) performs the TLS handshake. JavaScript uses APIs like `fetch` or `XMLHttpRequest`, but the certificate validation and key exchange happen in the lower layers.
* **Testing in Development:**  Developers might use these test certificates during local development or automated testing of web applications that use QUIC. While they wouldn't directly manipulate these C++ constants from JavaScript, the *behavior* they enable (successful or failed TLS handshakes) would be observable in the JavaScript code.

**6. Logical Reasoning (Input/Output):**

* **Input (Hypothetical):** Imagine a QUIC server in a test environment configured to use `kSelfSignedCert...` and `kSelfSignedCertPrivateKey...`. A QUIC client attempts to connect.
* **Output:** The TLS handshake *should* succeed because the client is likely configured to trust or ignore self-signed certificates in the test environment. If the client *wasn't* configured to trust self-signed certificates, the handshake would fail. For the wildcard certificate, if a client tries to connect to `www.foo.test`, the handshake should succeed because the wildcard matches. Connecting to `bar.foo.test` would also succeed. Connecting to `foo.test` directly might depend on the specific configuration of the certificate.

**7. Common Usage Errors:**

* **Mismatching Certificates and Keys:**  A common error would be trying to use `kSelfSignedCertPrivateKey` with `kWildcardCertificate`. This would lead to TLS handshake failures because the private key wouldn't correspond to the public key in the certificate.
* **Incorrect Certificate Configuration:** In a real-world scenario (not just testing), using these self-signed or test certificates in production would lead to security warnings in browsers because they wouldn't be trusted by standard Certificate Authorities.
* **Forgetting Private Keys:**  When setting up a test server, forgetting to provide the private key would prevent the server from proving its identity, and the handshake would fail.

**8. User Operations Leading Here (Debugging):**

* **Network Issues:** A developer might be debugging why a QUIC connection is failing. They might suspect certificate issues and start examining the configuration of the QUIC server or client.
* **Test Failures:**  Automated tests using QUIC might be failing due to certificate validation problems. This would lead developers to investigate the test setup and the certificates being used.
* **Security Audits:** Security engineers might review the codebase, including test code, to understand how TLS is handled and identify potential vulnerabilities.

**9. 归纳功能 (Summarizing):**

Finally, to summarize (as requested by part 2 of the prompt), the core function of `test_certificates.cc` is to provide a collection of pre-generated, constant cryptographic certificates and their corresponding private keys specifically for use in testing the QUIC protocol implementation. This allows developers to simulate various TLS handshake scenarios and ensure the QUIC stack handles different certificate types correctly.

This detailed breakdown shows the kind of layered analysis required to understand the purpose and implications of even a relatively small code snippet like this. It involves understanding the context, the data structures, and how this code fits into a larger system.
这是目录为 `net/third_party/quiche/src/quiche/quic/test_tools/test_certificates.cc` 的 Chromium 网络栈的源代码文件，并且是第二部分，需要归纳其功能。

由于您提供了第一部分的内容，我可以结合两部分的信息来归纳 `test_certificates.cc` 的功能。

**结合第一部分的分析，`net/third_party/quiche/src/quiche/quic/test_tools/test_certificates.cc` 文件的主要功能是提供一组预定义的、硬编码的 TLS 证书和私钥，专门用于 QUIC 协议的单元测试和集成测试。**

**具体来说，这个文件包含以下内容：**

* **硬编码的证书和私钥数据:**  文件中定义了多个常量字符串，这些字符串包含了不同类型的 TLS 证书（例如，自签名证书、通配符证书）及其对应的私钥。这些数据通常是二进制的 ASN.1 DER 编码，有时也包含 PEM 编码的私钥。
* **用于测试的预配置资源:** 这些证书和私钥不是用于生产环境的，而是为了在测试环境中模拟不同的 TLS 握手场景，例如：
    * 成功的 TLS 握手。
    * 客户端或服务器身份验证。
    * 使用通配符证书的域名匹配。
    * 使用特定类型的密钥（例如，RSA 或 EC）。
* **方便测试代码使用的常量:**  使用 `ABSL_CONST_INIT` 宏确保这些常量在编译时初始化，并可以方便地在测试代码中引用，而无需在运行时生成或读取证书文件。
* **覆盖多种测试场景:** 文件中提供的不同类型的证书可以覆盖 QUIC 协议中与证书相关的各种测试场景，确保 QUIC 实现的健壮性和正确性。

**与 JavaScript 的关系：**

虽然此 C++ 文件本身不包含 JavaScript 代码，但它提供的证书和私钥在涉及 Web 浏览器的 QUIC 测试中起着关键作用。

* **模拟 HTTPS 连接:** 当 JavaScript 代码（例如，在浏览器中运行的 Web 应用）尝试通过 QUIC 建立 HTTPS 连接时，底层的 Chromium 网络栈会使用这些测试证书来模拟服务器的身份。
* **测试 TLS 握手流程:**  测试代码可能会使用这些证书来验证浏览器是否正确处理了 QUIC 的 TLS 握手过程，包括证书的验证和加密连接的建立。
* **本地开发和测试:**  在本地开发和测试 Web 应用时，开发者可以使用这些测试证书来搭建本地的 QUIC 服务器，以便在没有有效 CA 签名的证书的情况下进行测试。

**逻辑推理（假设输入与输出）：**

假设测试代码配置一个 QUIC 服务器使用 `kWildcardCertificate` 和 `kWildcardCertificatePrivateKey`。

* **假设输入：** 一个 QUIC 客户端尝试连接到 `www.foo.test`。
* **预期输出：** TLS 握手成功，因为 `kWildcardCertificate` 是为 `*.foo.test` 颁发的通配符证书，可以匹配 `www.foo.test`。

* **假设输入：** 一个 QUIC 客户端尝试连接到 `bar.example.com`。
* **预期输出：** TLS 握手失败，因为 `kWildcardCertificate` 是为 `*.foo.test` 颁发的，不能匹配 `bar.example.com`。

**用户或编程常见的使用错误：**

* **在生产环境中使用测试证书:**  这是非常严重的错误。测试证书通常不被信任的证书颁发机构（CA）签名，因此在生产环境中使用会导致浏览器显示安全警告，甚至阻止连接。
* **私钥泄露:** 虽然这些是用于测试的私钥，但如果意外泄露，可能会被滥用。开发者需要注意不要将这些测试资源泄露到公共环境中。
* **证书和私钥不匹配:**  在配置测试服务器时，如果使用了不匹配的证书和私钥，会导致 TLS 握手失败。例如，使用 `kSelfSignedCertificatePrivateKey` 去匹配 `kWildcardCertificate`。

**用户操作如何一步步到达这里（调试线索）：**

一个开发者可能在调试一个 QUIC 连接问题，例如：

1. **用户报告网站连接问题：** 用户可能遇到无法通过 QUIC 连接到某个网站的情况。
2. **开发者检查网络日志：** 开发者可能会查看 Chromium 的网络日志（`chrome://net-export/` 或命令行参数）来分析连接过程。
3. **发现 TLS 握手失败：** 日志可能显示 TLS 握手失败，并指出证书验证或密钥协商的问题。
4. **怀疑证书配置错误：** 开发者开始怀疑服务器的证书配置是否正确，或者客户端是否信任该证书。
5. **查看测试代码和工具：** 为了重现问题或编写新的测试用例，开发者可能会查看 QUIC 相关的测试代码，并找到 `test_certificates.cc` 文件，了解如何使用预定义的证书进行测试。
6. **分析证书内容：** 开发者可能会分析 `test_certificates.cc` 中定义的证书内容，例如 Common Name、Subject Alternative Names 等，来确认证书是否符合预期。

**总结 `test_certificates.cc` 的功能（第二部分归纳）：**

`net/third_party/quiche/src/quiche/quic/test_tools/test_certificates.cc` 文件的核心功能是 **为 Chromium QUIC 协议的测试提供了一组预定义的、静态的 TLS 证书和私钥。**  这些资源用于模拟各种 TLS 握手场景，验证 QUIC 实现的正确性和健壮性，并方便开发者进行本地开发和测试。 它是一个关键的测试基础设施组件，确保 QUIC 协议在各种情况下的可靠运行。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/test_certificates.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
, '\x15', '\x30', '\x13', '\x06', '\x03', '\x55', '\x04', '\x03',
    '\x0c', '\x0c', '\x77', '\x77', '\x77', '\x2e', '\x66', '\x6f', '\x6f',
    '\x2e', '\x74', '\x65', '\x73', '\x74', '\x30', '\x82', '\x01', '\x22',
    '\x30', '\x0d', '\x06', '\x09', '\x2a', '\x86', '\x48', '\x86', '\xf7',
    '\x0d', '\x01', '\x01', '\x01', '\x05', '\x00', '\x03', '\x82', '\x01',
    '\x0f', '\x00', '\x30', '\x82', '\x01', '\x0a', '\x02', '\x82', '\x01',
    '\x01', '\x00', '\xcc', '\xd5', '\x5d', '\xa0', '\x4a', '\x03', '\x9d',
    '\x89', '\xa2', '\xae', '\x7a', '\x59', '\x15', '\xf7', '\x27', '\x67',
    '\x49', '\xa4', '\xc1', '\x87', '\xcd', '\x9c', '\x02', '\x9e', '\xb9',
    '\x2f', '\xd1', '\xa1', '\x0d', '\x57', '\xff', '\xd6', '\xc0', '\x6a',
    '\x7b', '\xaa', '\x52', '\xb2', '\x6e', '\xa6', '\x12', '\x34', '\xcf',
    '\xdc', '\xd3', '\x1e', '\x32', '\xc1', '\x8d', '\x42', '\xa3', '\x0b',
    '\xd6', '\xaf', '\xe9', '\x37', '\x42', '\xf8', '\x78', '\xdc', '\xcb',
    '\x2d', '\x0e', '\x42', '\x5a', '\xe2', '\xbf', '\xd2', '\xe4', '\x9c',
    '\xb4', '\x34', '\x38', '\x97', '\x5e', '\x4d', '\x5e', '\x8a', '\x0b',
    '\xd8', '\x42', '\x11', '\x88', '\x19', '\xa2', '\x23', '\x4b', '\xec',
    '\x3b', '\x0a', '\xc9', '\x67', '\x49', '\x2c', '\x8e', '\x1c', '\x5e',
    '\x7f', '\x42', '\xe7', '\x73', '\x0b', '\x86', '\x68', '\xf0', '\xaa',
    '\x3f', '\x1e', '\x17', '\x3e', '\x29', '\xc4', '\x57', '\x6e', '\x34',
    '\x78', '\xaf', '\x15', '\x03', '\x39', '\x32', '\x27', '\x80', '\x76',
    '\xb1', '\xda', '\x08', '\xe5', '\x4d', '\x3f', '\x4c', '\xfc', '\x1e',
    '\x23', '\x5a', '\xb3', '\xd4', '\x99', '\xdc', '\x5c', '\x2b', '\xf1',
    '\xa8', '\xe3', '\x02', '\x0a', '\xc8', '\x4d', '\x63', '\x27', '\xb9',
    '\x0d', '\x6c', '\xc2', '\x34', '\x82', '\x82', '\x5d', '\x56', '\xa8',
    '\x93', '\x44', '\x8b', '\xf4', '\x8b', '\xf0', '\x63', '\xe5', '\x23',
    '\x7f', '\x8d', '\x5f', '\x3a', '\x4a', '\xa5', '\x50', '\xb9', '\xc6',
    '\x5c', '\xe6', '\x33', '\xe3', '\xfc', '\xc8', '\x96', '\x88', '\x88',
    '\xe9', '\x53', '\xaf', '\x0d', '\xbb', '\x80', '\x9c', '\xbb', '\xed',
    '\x4d', '\x06', '\xfa', '\xe9', '\x7c', '\x25', '\x1c', '\x59', '\xee',
    '\x19', '\xcc', '\xa9', '\x7c', '\x1d', '\x86', '\xd9', '\x95', '\x78',
    '\x2d', '\x3a', '\x95', '\x49', '\x11', '\x45', '\xfa', '\xd6', '\xef',
    '\xd5', '\x07', '\x1c', '\x23', '\xeb', '\xad', '\xd3', '\x3b', '\x95',
    '\xcf', '\x53', '\xa3', '\x47', '\xa9', '\xa7', '\x90', '\xde', '\x34',
    '\xa4', '\xbb', '\x05', '\xdc', '\x54', '\x87', '\x97', '\x30', '\xea',
    '\x25', '\xf0', '\xfd', '\xba', '\xa1', '\x1b', '\x02', '\x03', '\x01',
    '\x00', '\x01', '\xa3', '\x81', '\x88', '\x30', '\x81', '\x85', '\x30',
    '\x1d', '\x06', '\x03', '\x55', '\x1d', '\x0e', '\x04', '\x16', '\x04',
    '\x14', '\x09', '\xfb', '\x77', '\xbb', '\xc8', '\x8f', '\xd6', '\xa4',
    '\xf0', '\x74', '\xb2', '\x90', '\x46', '\x0a', '\x8d', '\x09', '\x4b',
    '\x89', '\x2e', '\x41', '\x30', '\x1f', '\x06', '\x03', '\x55', '\x1d',
    '\x23', '\x04', '\x18', '\x30', '\x16', '\x80', '\x14', '\x09', '\xfb',
    '\x77', '\xbb', '\xc8', '\x8f', '\xd6', '\xa4', '\xf0', '\x74', '\xb2',
    '\x90', '\x46', '\x0a', '\x8d', '\x09', '\x4b', '\x89', '\x2e', '\x41',
    '\x30', '\x0f', '\x06', '\x03', '\x55', '\x1d', '\x13', '\x01', '\x01',
    '\xff', '\x04', '\x05', '\x30', '\x03', '\x01', '\x01', '\xff', '\x30',
    '\x32', '\x06', '\x03', '\x55', '\x1d', '\x11', '\x04', '\x2b', '\x30',
    '\x29', '\x82', '\x08', '\x66', '\x6f', '\x6f', '\x2e', '\x74', '\x65',
    '\x73', '\x74', '\x82', '\x0c', '\x77', '\x77', '\x77', '\x2e', '\x66',
    '\x6f', '\x6f', '\x2e', '\x74', '\x65', '\x73', '\x74', '\x82', '\x0f',
    '\x2a', '\x2e', '\x77', '\x69', '\x6c', '\x64', '\x63', '\x61', '\x72',
    '\x64', '\x2e', '\x74', '\x65', '\x73', '\x74', '\x30', '\x0d', '\x06',
    '\x09', '\x2a', '\x86', '\x48', '\x86', '\xf7', '\x0d', '\x01', '\x01',
    '\x0b', '\x05', '\x00', '\x03', '\x82', '\x01', '\x01', '\x00', '\x93',
    '\xbc', '\x33', '\x4c', '\xa4', '\xdf', '\xdc', '\xed', '\x4b', '\x4d',
    '\x5e', '\xdb', '\xdd', '\x4a', '\xb7', '\xbc', '\x50', '\x1f', '\xca',
    '\x66', '\x4d', '\x28', '\x96', '\x42', '\x4e', '\x84', '\x44', '\x80',
    '\x25', '\x17', '\x2c', '\x05', '\x93', '\xe0', '\x2a', '\x29', '\xef',
    '\xe4', '\x26', '\x19', '\x63', '\xdf', '\xb2', '\x72', '\xb1', '\x82',
    '\x7e', '\x5f', '\xce', '\x82', '\x41', '\xad', '\x96', '\x78', '\x94',
    '\xa8', '\x21', '\xee', '\xf2', '\x4a', '\xf5', '\x41', '\xa8', '\xfb',
    '\xe0', '\xe1', '\x22', '\x89', '\xf1', '\x40', '\x85', '\x86', '\x53',
    '\x61', '\x57', '\x0f', '\x31', '\xae', '\x0c', '\xc3', '\x8d', '\xe8',
    '\x29', '\xac', '\xe0', '\x03', '\x2d', '\x69', '\x44', '\x3d', '\xd6',
    '\x3b', '\x2b', '\x0f', '\xb3', '\xf5', '\x83', '\x1b', '\x4e', '\x65',
    '\x60', '\x6b', '\xa2', '\x01', '\x03', '\x1e', '\x98', '\xca', '\xca',
    '\x32', '\xd4', '\x5b', '\xde', '\x45', '\xe2', '\x35', '\xd2', '\x54',
    '\x1a', '\x2a', '\x38', '\xa7', '\x42', '\xa0', '\xf3', '\xef', '\x28',
    '\xe3', '\x6e', '\x23', '\x77', '\x07', '\xd5', '\xef', '\xfd', '\x30',
    '\xd6', '\x31', '\xfa', '\xf2', '\x94', '\x95', '\x2f', '\x03', '\x7a',
    '\x43', '\xe0', '\xb3', '\x82', '\xca', '\x7e', '\xb4', '\x00', '\xc9',
    '\x08', '\x15', '\x7b', '\x2e', '\x51', '\xec', '\xab', '\x68', '\xca',
    '\xc2', '\xca', '\x44', '\xe1', '\xbe', '\xe4', '\x06', '\x98', '\x87',
    '\x9b', '\x58', '\xbc', '\xf1', '\xea', '\x55', '\xf6', '\x64', '\x92',
    '\xe6', '\x73', '\xc9', '\xf6', '\xc5', '\x7a', '\x90', '\x42', '\x83',
    '\x39', '\x9e', '\xd0', '\xca', '\x85', '\x6c', '\x53', '\x99', '\x64',
    '\xbb', '\x49', '\xdc', '\xae', '\x1c', '\xe5', '\x00', '\x65', '\x13',
    '\xdd', '\xdc', '\xde', '\x3f', '\xf9', '\x14', '\x91', '\x0d', '\xe6',
    '\xba', '\xc1', '\x7d', '\x5f', '\xd5', '\x6d', '\xe8', '\x65', '\x9c',
    '\xfb', '\xda', '\x82', '\xf7', '\x4d', '\x45', '\x81', '\x8c', '\x54',
    '\xec', '\x50', '\xbb', '\x14', '\xe9', '\x06', '\xda', '\x76', '\xb3',
    '\xf0', '\xb7', '\xbb', '\x58', '\x4c', '\x8f', '\x6a', '\x5d', '\x8e',
    '\x93', '\x5f', '\x35'};

ABSL_CONST_INIT const absl::string_view kWildcardCertificate(
    kWildcardCertificateRaw, sizeof(kWildcardCertificateRaw));

ABSL_CONST_INIT const char kWildcardCertificatePrivateKeyRaw[] = {
    '\x30', '\x82', '\x04', '\xbe', '\x02', '\x01', '\x00', '\x30', '\x0d',
    '\x06', '\x09', '\x2a', '\x86', '\x48', '\x86', '\xf7', '\x0d', '\x01',
    '\x01', '\x01', '\x05', '\x00', '\x04', '\x82', '\x04', '\xa8', '\x30',
    '\x82', '\x04', '\xa4', '\x02', '\x01', '\x00', '\x02', '\x82', '\x01',
    '\x01', '\x00', '\xcc', '\xd5', '\x5d', '\xa0', '\x4a', '\x03', '\x9d',
    '\x89', '\xa2', '\xae', '\x7a', '\x59', '\x15', '\xf7', '\x27', '\x67',
    '\x49', '\xa4', '\xc1', '\x87', '\xcd', '\x9c', '\x02', '\x9e', '\xb9',
    '\x2f', '\xd1', '\xa1', '\x0d', '\x57', '\xff', '\xd6', '\xc0', '\x6a',
    '\x7b', '\xaa', '\x52', '\xb2', '\x6e', '\xa6', '\x12', '\x34', '\xcf',
    '\xdc', '\xd3', '\x1e', '\x32', '\xc1', '\x8d', '\x42', '\xa3', '\x0b',
    '\xd6', '\xaf', '\xe9', '\x37', '\x42', '\xf8', '\x78', '\xdc', '\xcb',
    '\x2d', '\x0e', '\x42', '\x5a', '\xe2', '\xbf', '\xd2', '\xe4', '\x9c',
    '\xb4', '\x34', '\x38', '\x97', '\x5e', '\x4d', '\x5e', '\x8a', '\x0b',
    '\xd8', '\x42', '\x11', '\x88', '\x19', '\xa2', '\x23', '\x4b', '\xec',
    '\x3b', '\x0a', '\xc9', '\x67', '\x49', '\x2c', '\x8e', '\x1c', '\x5e',
    '\x7f', '\x42', '\xe7', '\x73', '\x0b', '\x86', '\x68', '\xf0', '\xaa',
    '\x3f', '\x1e', '\x17', '\x3e', '\x29', '\xc4', '\x57', '\x6e', '\x34',
    '\x78', '\xaf', '\x15', '\x03', '\x39', '\x32', '\x27', '\x80', '\x76',
    '\xb1', '\xda', '\x08', '\xe5', '\x4d', '\x3f', '\x4c', '\xfc', '\x1e',
    '\x23', '\x5a', '\xb3', '\xd4', '\x99', '\xdc', '\x5c', '\x2b', '\xf1',
    '\xa8', '\xe3', '\x02', '\x0a', '\xc8', '\x4d', '\x63', '\x27', '\xb9',
    '\x0d', '\x6c', '\xc2', '\x34', '\x82', '\x82', '\x5d', '\x56', '\xa8',
    '\x93', '\x44', '\x8b', '\xf4', '\x8b', '\xf0', '\x63', '\xe5', '\x23',
    '\x7f', '\x8d', '\x5f', '\x3a', '\x4a', '\xa5', '\x50', '\xb9', '\xc6',
    '\x5c', '\xe6', '\x33', '\xe3', '\xfc', '\xc8', '\x96', '\x88', '\x88',
    '\xe9', '\x53', '\xaf', '\x0d', '\xbb', '\x80', '\x9c', '\xbb', '\xed',
    '\x4d', '\x06', '\xfa', '\xe9', '\x7c', '\x25', '\x1c', '\x59', '\xee',
    '\x19', '\xcc', '\xa9', '\x7c', '\x1d', '\x86', '\xd9', '\x95', '\x78',
    '\x2d', '\x3a', '\x95', '\x49', '\x11', '\x45', '\xfa', '\xd6', '\xef',
    '\xd5', '\x07', '\x1c', '\x23', '\xeb', '\xad', '\xd3', '\x3b', '\x95',
    '\xcf', '\x53', '\xa3', '\x47', '\xa9', '\xa7', '\x90', '\xde', '\x34',
    '\xa4', '\xbb', '\x05', '\xdc', '\x54', '\x87', '\x97', '\x30', '\xea',
    '\x25', '\xf0', '\xfd', '\xba', '\xa1', '\x1b', '\x02', '\x03', '\x01',
    '\x00', '\x01', '\x02', '\x82', '\x01', '\x01', '\x00', '\xa3', '\xb3',
    '\x01', '\x98', '\x50', '\x8e', '\x83', '\x20', '\xb4', '\x3a', '\xec',
    '\xdc', '\xb5', '\x89', '\x48', '\x9c', '\x6b', '\x66', '\x98', '\xa4',
    '\x87', '\xd5', '\xde', '\xe2', '\x2a', '\xed', '\xe4', '\x82', '\xe9',
    '\xbf', '\x22', '\x5f', '\xe6', '\x77', '\x33', '\x4d', '\xf3', '\xb9',
    '\x56', '\x64', '\xb2', '\xb8', '\x32', '\x47', '\x31', '\x12', '\x39',
    '\x4e', '\x26', '\x2e', '\xd3', '\x4f', '\x6a', '\xcc', '\x3b', '\x7e',
    '\x46', '\xaf', '\x7d', '\x28', '\x37', '\xd8', '\x52', '\x45', '\x05',
    '\x8d', '\xa1', '\xf0', '\x51', '\x74', '\x4b', '\x30', '\x50', '\xe9',
    '\xe8', '\x1b', '\xbd', '\x2a', '\x66', '\x3c', '\xf6', '\xd0', '\x3c',
    '\x0d', '\x00', '\x5f', '\x65', '\x15', '\xee', '\x39', '\xb8', '\xac',
    '\x2a', '\xf6', '\xc8', '\xbc', '\x33', '\x69', '\x51', '\x76', '\xd7',
    '\xa2', '\xa6', '\x50', '\xc7', '\xc5', '\xc7', '\x9b', '\xac', '\xc7',
    '\xa9', '\x69', '\x98', '\xd6', '\x22', '\x69', '\x30', '\xc3', '\x82',
    '\x47', '\xfb', '\xa5', '\x46', '\x2d', '\x96', '\x05', '\xc2', '\x84',
    '\xd1', '\x1d', '\xd5', '\xa7', '\x5c', '\xdb', '\x6d', '\x35', '\x7b',
    '\x1b', '\x80', '\xe4', '\x42', '\x1f', '\x4d', '\x68', '\x2e', '\xbc',
    '\x58', '\xb6', '\x7c', '\x7e', '\xc5', '\x07', '\xe1', '\xf5', '\x30',
    '\xa9', '\x8f', '\x14', '\x76', '\xad', '\xe2', '\xdf', '\xaf', '\xd3',
    '\xf1', '\xba', '\xd5', '\x98', '\xf3', '\x5e', '\x30', '\x79', '\xcb',
    '\xe7', '\x7a', '\x83', '\xba', '\xf7', '\x71', '\xb0', '\xb2', '\xd1',
    '\xf4', '\x34', '\x5b', '\xe1', '\xe8', '\x60', '\x39', '\x96', '\x12',
    '\xdc', '\xb4', '\x0d', '\xf9', '\x8d', '\x8c', '\xd8', '\xbb', '\xb7',
    '\xd2', '\x1b', '\x83', '\x10', '\xbd', '\x86', '\xef', '\x5c', '\x6c',
    '\xe3', '\xb1', '\x96', '\x7f', '\xab', '\x58', '\xce', '\x87', '\xc9',
    '\x48', '\x69', '\xbb', '\xb1', '\xec', '\xa4', '\x3a', '\x06', '\xa3',
    '\x33', '\xad', '\x7a', '\xe5', '\x88', '\x6d', '\x32', '\x67', '\x1c',
    '\x03', '\xda', '\x9d', '\x3c', '\x73', '\xe0', '\xd7', '\x6c', '\x00',
    '\xe4', '\x8d', '\x7d', '\xf2', '\xac', '\xa5', '\xb8', '\x35', '\xb9',
    '\xac', '\x81', '\x02', '\x81', '\x81', '\x00', '\xe8', '\xd5', '\x5b',
    '\xd0', '\x4f', '\x7c', '\xfc', '\x4b', '\xe6', '\xe8', '\x3c', '\x4c',
    '\x24', '\xce', '\x68', '\x73', '\x3b', '\x4b', '\xa0', '\xfb', '\x79',
    '\xa5', '\x72', '\x1d', '\x77', '\xb2', '\xdf', '\x2b', '\x0a', '\x11',
    '\x28', '\xe8', '\x02', '\x7f', '\x26', '\x40', '\x34', '\x8f', '\x78',
    '\x18', '\xad', '\xf4', '\x11', '\x78', '\x45', '\x9f', '\x66', '\x4e',
    '\x78', '\x71', '\x60', '\x40', '\xeb', '\x64', '\x28', '\x06', '\xae',
    '\x9b', '\x32', '\x73', '\xb5', '\xe1', '\x7e', '\x3c', '\x07', '\x31',
    '\x8d', '\x82', '\xed', '\x6a', '\xe6', '\x1e', '\x65', '\x9e', '\x81',
    '\x29', '\x08', '\x56', '\x17', '\x4b', '\x31', '\xc3', '\xf5', '\x27',
    '\xef', '\xb8', '\xda', '\x58', '\xff', '\x36', '\x47', '\x12', '\xb0',
    '\xef', '\x14', '\x20', '\x5c', '\x48', '\xb3', '\x84', '\x0d', '\x64',
    '\x22', '\x3e', '\xfe', '\x94', '\x17', '\x6c', '\x45', '\xe7', '\x3f',
    '\x4c', '\x90', '\x67', '\x13', '\x1a', '\xa8', '\xbc', '\x5b', '\xd0',
    '\xc1', '\x8a', '\xa9', '\x42', '\xbe', '\xe4', '\x0e', '\x59', '\x02',
    '\x81', '\x81', '\x00', '\xe1', '\x36', '\xcd', '\x86', '\x1e', '\xcb',
    '\x8b', '\x68', '\x65', '\x6b', '\x42', '\xec', '\x50', '\x29', '\xa0',
    '\xab', '\x3a', '\xe5', '\x6f', '\xe1', '\x13', '\xe8', '\xa3', '\x6b',
    '\x7c', '\x2b', '\xd3', '\x69', '\x89', '\x47', '\x07', '\x39', '\xb2',
    '\x0f', '\x03', '\x4e', '\x6f', '\x28', '\x94', '\x1d', '\x1f', '\x22',
    '\x47', '\xf9', '\x95', '\xff', '\x3e', '\xa4', '\x26', '\x38', '\x07',
    '\x5b', '\xdd', '\xef', '\x0a', '\xa5', '\xe8', '\x99', '\xad', '\x91',
    '\x68', '\x83', '\xf2', '\xf5', '\xa5', '\x3d', '\x21', '\x88', '\xa5',
    '\x6a', '\x39', '\x3b', '\xca', '\x4c', '\xc9', '\xd1', '\x9a', '\x74',
    '\xb2', '\xe3', '\x73', '\x5d', '\xfe', '\xbd', '\x05', '\x1b', '\x9a',
    '\x13', '\x98', '\x39', '\x93', '\xf3', '\x88', '\x55', '\x61', '\x85',
    '\x7a', '\x53', '\x5a', '\xd9', '\x2c', '\xdb', '\x15', '\x69', '\xa6',
    '\x31', '\x09', '\xbb', '\xd1', '\xe8', '\x6e', '\x8c', '\x47', '\x77',
    '\x1e', '\x9b', '\xbe', '\xb7', '\x57', '\xd4', '\xaa', '\xd5', '\x92',
    '\xa1', '\xd5', '\x55', '\x04', '\x93', '\x02', '\x81', '\x80', '\x06',
    '\x84', '\x01', '\xff', '\xc0', '\x59', '\xb5', '\x0d', '\xc2', '\xb6',
    '\x79', '\x09', '\x80', '\x76', '\x2e', '\x42', '\x1b', '\x44', '\xb0',
    '\x8a', '\x99', '\x0a', '\xe2', '\x38', '\xa4', '\xe2', '\xe2', '\x8f',
    '\xe7', '\xc6', '\x37', '\x28', '\xd6', '\xf9', '\x0b', '\xee', '\xfc',
    '\x09', '\x8f', '\xc8', '\xd1', '\x05', '\x65', '\x7f', '\xc2', '\x23',
    '\x05', '\xcf', '\xe8', '\x5a', '\xf3', '\xe0', '\x9d', '\x35', '\xbe',
    '\x51', '\x01', '\x8d', '\xe2', '\x49', '\x8e', '\xab', '\x72', '\xc6',
    '\xe7', '\x44', '\xa1', '\xbb', '\x2a', '\x3d', '\xb5', '\x96', '\xe0',
    '\x2d', '\x21', '\x5c', '\x2e', '\x99', '\x8a', '\x29', '\x56', '\x89',
    '\x2f', '\x51', '\x20', '\xca', '\x41', '\x82', '\x00', '\x12', '\x5a',
    '\xc6', '\xd1', '\x20', '\xbf', '\xa5', '\x70', '\x2f', '\xb0', '\xa6',
    '\x5f', '\x61', '\x8f', '\xfb', '\xc7', '\x50', '\x09', '\x9f', '\xc4',
    '\x0d', '\x06', '\x9e', '\x73', '\xe4', '\x0e', '\x8a', '\xce', '\x72',
    '\x06', '\xf7', '\xbe', '\x92', '\xcc', '\xcd', '\xcb', '\x5d', '\xc2',
    '\x71', '\x02', '\x81', '\x80', '\x26', '\xf3', '\xba', '\x92', '\x52',
    '\xeb', '\x33', '\x7e', '\x67', '\xe4', '\x28', '\x5c', '\x04', '\xf5',
    '\x5e', '\x33', '\x9f', '\x69', '\x25', '\x73', '\x91', '\x64', '\xf0',
    '\x36', '\xdb', '\xf0', '\x1c', '\x8d', '\xa9', '\x4f', '\x9e', '\xa1',
    '\x4c', '\xf9', '\xa9', '\xc1', '\xbc', '\x1a', '\x11', '\x9c', '\x03',
    '\xd1', '\x83', '\x0f', '\x58', '\xf1', '\x1f', '\x9d', '\x76', '\x7a',
    '\xc4', '\x53', '\x10', '\x4c', '\x92', '\xd3', '\xe5', '\x2a', '\x07',
    '\x4a', '\x1a', '\x00', '\x90', '\x5a', '\x0a', '\x2d', '\x4b', '\x8a',
    '\x7d', '\xc9', '\xa4', '\x82', '\x81', '\xd7', '\xcc', '\x24', '\x33',
    '\x89', '\xb1', '\x93', '\x03', '\x56', '\x23', '\x83', '\xff', '\xc9',
    '\x29', '\x59', '\xf0', '\x3f', '\x2d', '\x26', '\xb6', '\xd2', '\xc5',
    '\x9e', '\x37', '\x6d', '\x09', '\x4e', '\x7c', '\xa2', '\x9b', '\xce',
    '\x7d', '\x0f', '\x08', '\x36', '\xf2', '\xf4', '\x37', '\x82', '\x8d',
    '\xad', '\xbd', '\x9e', '\x84', '\x5a', '\xe3', '\x97', '\x05', '\xc1',
    '\x10', '\xae', '\x6a', '\xde', '\x5c', '\x7f', '\x02', '\x81', '\x81',
    '\x00', '\x9b', '\x8e', '\xa4', '\x2b', '\xcf', '\xb6', '\x30', '\x1c',
    '\xb5', '\x82', '\x50', '\x08', '\xc0', '\x0b', '\x57', '\xf4', '\x2d',
    '\x82', '\x39', '\x11', '\x1b', '\x02', '\xe6', '\xbe', '\x14', '\x26',
    '\x77', '\xd7', '\x26', '\x1f', '\x0d', '\x92', '\xc6', '\x67', '\xa0',
    '\x01', '\x6c', '\xd9', '\x7a', '\xdf', '\xc3', '\x3d', '\x50', '\x8d',
    '\x43', '\xef', '\x95', '\x50', '\x72', '\x25', '\x06', '\x28', '\x7a',
    '\x7e', '\x99', '\xea', '\x4d', '\xe8', '\x87', '\xe5', '\xca', '\x71',
    '\x36', '\x8a', '\xce', '\x18', '\x55', '\xe4', '\x87', '\x39', '\x3d',
    '\xea', '\x9a', '\x22', '\x99', '\x1a', '\xab', '\xe3', '\x6f', '\x48',
    '\x78', '\x49', '\x8f', '\xf6', '\xfa', '\xb1', '\xb8', '\x68', '\xae',
    '\xc3', '\x47', '\x1d', '\x8f', '\x1d', '\x11', '\xa1', '\x06', '\xf5',
    '\xc0', '\x0d', '\xcf', '\x7b', '\x33', '\xfe', '\x0c', '\x69', '\xca',
    '\x46', '\xfe', '\x2c', '\xac', '\xd8', '\x4d', '\x02', '\x79', '\xfe',
    '\x47', '\xca', '\x21', '\x30', '\x65', '\xa4', '\xe5', '\xaa', '\x4e',
    '\x9c', '\xbc', '\xa5'};

ABSL_CONST_INIT const absl::string_view kWildcardCertificatePrivateKey(
    kWildcardCertificatePrivateKeyRaw,
    sizeof(kWildcardCertificatePrivateKeyRaw));

ABSL_CONST_INIT const char kTestEcPrivateKeyLegacyPem[] =
    R"(-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMdjXX0hg399DlccZuYFXPKq+dMGduXWmQYClDYJNDGroAoGCCqGSM49
AwEHoUQDQgAENCuPQTywFI8hbsGo68AeN1KVWmd09buzlu/2CAtsJcNoECUmpVXH
4dwvWMv6zWn9RJ5EzI72R/5FVcO485s5MQ==
-----END EC PRIVATE KEY-----)";

}  // namespace test
}  // namespace quic

"""


```