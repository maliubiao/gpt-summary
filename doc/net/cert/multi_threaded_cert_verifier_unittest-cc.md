Response:
Let's break down the thought process for analyzing the given C++ unittest file.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Chromium source file (`multi_threaded_cert_verifier_unittest.cc`). The core tasks are:

* **Summarize Functionality:** What does this code *do*?  Specifically, what is being tested?
* **JavaScript Relevance:** Is there any connection to JavaScript functionality?
* **Logical Reasoning (Input/Output):**  For the tests, what are the inputs and expected outputs?
* **Common Usage Errors:** What mistakes could developers make when using the code being tested?
* **Debugging Context:** How does a user's actions lead to this code being involved (as a debugging aid)?

**2. Initial Code Scan and Identification of Key Components:**

The first step is to quickly scan the code for important keywords and structures:

* **`#include` directives:** These tell us the dependencies. We see things like `net/cert/multi_threaded_cert_verifier.h`, which is the core class being tested. We also see testing frameworks like `gtest/gtest.h` and `gmock/gmock.h`.
* **Class definition:**  `MultiThreadedCertVerifierTest` stands out as the main test fixture.
* **`TEST_F` macros:** These are the individual test cases. Reading their names gives a high-level idea of what's being tested (e.g., `CancelRequest`, `DeleteVerifier`, `ConvertsConfigToFlags`).
* **Mocking:**  The presence of `MockCertVerifyProc` and the use of `EXPECT_CALL` indicate that the tests are using mocking to isolate the `MultiThreadedCertVerifier` and control the behavior of its dependencies.
* **Asynchronous Operations:**  The use of `ERR_IO_PENDING`, `TestCompletionCallback`, and the general structure of initiating a verification and waiting for a callback suggest asynchronous operations are involved.
* **Certificate Handling:** Keywords like `X509Certificate`, `CertVerifyResult`, and importing certificates from files are present.
* **Configuration:**  The `CertVerifier::Config` struct is used, and tests seem to focus on how these configurations are applied.

**3. Deeper Dive into Each Test Case:**

For each `TEST_F`, I would analyze its specific purpose:

* **`CancelRequest`:** This test checks if cancelling a pending verification request prevents the callback from being executed. It also simulates other requests to potentially trigger race conditions.
* **`DeleteVerifier`:**  This test verifies that if the `MultiThreadedCertVerifier` object is destroyed while a request is pending, the callback is not invoked. This is important for memory safety and preventing crashes.
* **`DeleteVerifierCallbackOwnsResult`:**  Similar to the previous test, but focuses on the scenario where the callback takes ownership of the `CertVerifier::Request`. This tests a specific contract of the API.
* **`CancelRequestThenQuit`:** This test, with the `ANNOTATE_SCOPED_MEMORY_LEAK`, explicitly checks for potential memory leaks when a request is canceled and the verifier is destroyed.
* **`ConvertsConfigToFlags`:** This test systematically checks if the configuration options set on the `MultiThreadedCertVerifier` are correctly translated into flags passed to the underlying `CertVerifyProc`.
* **`ConvertsFlagsToFlags`:**  Similar to the previous test, but focuses on flags passed directly to the `Verify` method.
* **`VerifyProcChangeChromeRootStore`:** This test examines how the `MultiThreadedCertVerifier` handles updates to the underlying certificate verification logic (mocked here by `mock_new_verify_proc_`). It checks if new requests use the updated logic.
* **`VerifyProcChangeRequest`:**  This test verifies that in-flight requests continue to use the original `CertVerifyProc` even if an update occurs.

**4. Identifying Functionality and Connections:**

Based on the analysis of the test cases, I could then summarize the functionality of `MultiThreadedCertVerifier`:

* **Asynchronous Certificate Verification:** It performs certificate verification in a separate thread to avoid blocking the main thread.
* **Request Management:** It manages a queue of verification requests and allows for cancellation.
* **Configuration:** It allows for configuration options that affect the verification process.
* **Updating Underlying Verification Logic:** It supports updating the `CertVerifyProc` used for verification, which might be necessary for things like updating root certificates.

**5. Addressing JavaScript Relevance:**

At this point, I would consider how certificate verification relates to web browsers and JavaScript:

* **HTTPS:**  Certificate verification is a core part of HTTPS, which is essential for secure web browsing.
* **JavaScript APIs:** While JavaScript itself doesn't directly perform the low-level certificate verification, browser APIs like `fetch` and `XMLHttpRequest` rely on the underlying network stack (including certificate verification) when making HTTPS requests.
* **Error Handling:** JavaScript code might receive errors related to certificate verification (e.g., when a website has an invalid certificate).

**6. Logical Reasoning (Input/Output):**

For each test, I would think about the key inputs (e.g., a certificate, a hostname, configuration flags) and the expected outcomes (e.g., `ERR_IO_PENDING`, `ERR_CERT_COMMON_NAME_INVALID`, no callback). The examples provided in the initial prompt were derived through this process.

**7. Common Usage Errors:**

Consider how a developer might misuse the `MultiThreadedCertVerifier`:

* **Not handling `ERR_IO_PENDING` correctly:**  Failing to wait for the callback when the `Verify` method returns `ERR_IO_PENDING`.
* **Memory management issues:**  Incorrectly managing the `CertVerifier::Request` object.
* **Ignoring errors:** Not checking the return value of the callback.

**8. Debugging Context:**

Think about scenarios where this code would be involved in a debugging session:

* **HTTPS connection failures:** When a user encounters an error when accessing a website over HTTPS, the certificate verification process is likely involved.
* **Certificate-related security warnings:**  When the browser displays warnings about invalid certificates, this code is responsible for detecting those issues.
* **Performance issues:**  If certificate verification is slow, this component might be a point of investigation.

**9. Structuring the Output:**

Finally, organize the information clearly, using headings and bullet points as in the example answer. Provide concrete examples and explanations to make the analysis easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial Oversimplification:**  At first glance, I might just say "it tests certificate verification." But the prompt asks for *specific* functionalities being tested. I need to go deeper into each test case.
* **JavaScript Connection Nuances:** I need to be careful not to overstate the direct involvement of JavaScript. It's more about how JavaScript *uses* the results of this code.
* **Clarity of Examples:** Ensure the input/output examples are clear and directly related to the test being discussed. Avoid ambiguity.

By following these steps, combining code analysis with an understanding of the broader context of certificate verification in a web browser, and iteratively refining the analysis, a comprehensive answer can be constructed.
这个 C++ 源代码文件 `multi_threaded_cert_verifier_unittest.cc` 是 Chromium 网络栈中 `net/cert/multi_threaded_cert_verifier.h` 头文件中定义的 `MultiThreadedCertVerifier` 类的单元测试文件。它的主要功能是 **测试 `MultiThreadedCertVerifier` 类的各种功能和行为是否符合预期**。

以下是它测试的几个核心方面：

**1. 异步证书验证:**

* **功能:** `MultiThreadedCertVerifier` 允许在后台线程执行证书验证，以避免阻塞主线程，提高网络操作的响应速度。
* **测试用例:**
    * `CancelRequest`: 测试取消正在进行的证书验证请求是否能够成功，并且取消后不会调用回调函数。
    * `DeleteVerifier`: 测试在证书验证请求仍在进行时，销毁 `MultiThreadedCertVerifier` 对象是否安全，并且不会导致回调函数被调用。
    * `DeleteVerifierCallbackOwnsResult`:  与 `DeleteVerifier` 类似，但测试回调函数拥有 `CertVerifier::Request` 对象的情况，验证在这种情况下销毁 `MultiThreadedCertVerifier` 的安全性。
    * `CancelRequestThenQuit`: 测试取消请求后立即退出程序，是否会发生内存泄漏。

**2. 配置选项传递:**

* **功能:** `MultiThreadedCertVerifier` 接收 `CertVerifier::Config` 对象来配置证书验证的行为，例如是否启用吊销检查、是否需要本地锚点的吊销检查等。
* **测试用例:**
    * `ConvertsConfigToFlags`: 测试 `CertVerifier::Config` 中的配置选项是否正确地转换为 `CertVerifyProc` 需要的标志。

**3. 标志传递:**

* **功能:** `MultiThreadedCertVerifier::Verify` 方法允许直接传递标志来控制单次证书验证的行为。
* **测试用例:**
    * `ConvertsFlagsToFlags`: 测试传递给 `Verify` 方法的标志是否正确地传递给底层的 `CertVerifyProc`。

**4. 动态更新证书验证处理器:**

* **功能:** `MultiThreadedCertVerifier` 允许在运行时更新底层的证书验证处理器 (`CertVerifyProc`)，例如当 Chrome Root Store 数据更新时。
* **测试用例:**
    * `VerifyProcChangeChromeRootStore`: 测试当更新证书验证处理器后，新的证书验证请求是否会使用新的处理器。
    * `VerifyProcChangeRequest`: 测试在证书验证请求进行中更新证书验证处理器，旧的请求是否仍然使用旧的处理器。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但 `MultiThreadedCertVerifier` 是 Chromium 网络栈的一部分，负责处理 HTTPS 连接的证书验证。当 JavaScript 代码通过浏览器提供的 API（例如 `fetch` 或 `XMLHttpRequest`）发起 HTTPS 请求时，底层的网络栈会使用 `MultiThreadedCertVerifier` 来验证服务器的 SSL/TLS 证书。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 请求一个 HTTPS 网站：

```javascript
fetch('https://www.example.com')
  .then(response => {
    // 处理响应
    console.log('请求成功', response);
  })
  .catch(error => {
    // 处理错误
    console.error('请求失败', error);
  });
```

在这个过程中，浏览器会调用底层的 C++ 网络栈来建立连接，其中包括证书验证。`MultiThreadedCertVerifier` 可能会被用来执行以下操作：

1. **接收证书:** 从服务器接收到的 SSL/TLS 证书。
2. **验证证书链:** 检查证书是否由受信任的根证书颁发机构签名，以及证书链是否完整且有效。
3. **执行吊销检查:**  根据配置，可能检查证书是否已被吊销。
4. **返回验证结果:** 将验证结果（成功或失败，以及失败的原因）返回给网络栈。

如果证书验证失败，`fetch` API 的 `catch` 回调函数将会被调用，并且 `error` 对象可能包含与证书错误相关的信息。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理：

**测试用例: `CancelRequest`**

* **假设输入:**
    * 一个有效的证书 `test_cert`。
    * 一个主机名 `"www.example.com"`。
    * 调用 `verifier_->Verify` 发起一个异步证书验证请求。
    * 立即调用 `request.reset()` 取消该请求。
* **预期输出:**
    * `verifier_->Verify` 返回 `ERR_IO_PENDING`，表示请求正在进行中。
    * 取消请求后，提供给 `verifier_->Verify` 的 `FailTest` 回调函数 **不会** 被调用。
    * 后续的几个验证请求会正常完成，以确保取消操作不会影响其他请求。

**测试用例: `ConvertsConfigToFlags`**

* **假设输入:**
    * 一个有效的证书 `test_cert`。
    * 一个主机名 `"www.example.com"`。
    * 设置 `CertVerifier::Config` 的不同配置选项（例如，启用吊销检查）。
    * 调用 `verifier_->SetConfig` 应用配置。
    * 调用 `verifier_->Verify` 发起证书验证请求。
* **预期输出:**
    * `mock_verify_proc_->VerifyInternal` 方法会被调用，并且其 `flags` 参数会包含与设置的配置选项对应的标志。例如，如果启用了吊销检查，`flags` 参数应该包含 `CertVerifyProc::VERIFY_REV_CHECKING_ENABLED`。
    * 如果模拟的 `MockCertVerifyProc` 返回一个错误（例如 `ERR_CERT_REVOKED`），则 `verifier_->Verify` 的回调函数也会返回相应的错误。

**用户或编程常见的使用错误:**

* **忘记处理 `ERR_IO_PENDING`:** `MultiThreadedCertVerifier::Verify` 方法是异步的，如果它返回 `ERR_IO_PENDING`，则需要等待回调函数执行才能获取验证结果。用户可能会错误地认为验证已经完成。
    ```c++
    int error;
    CertVerifyResult verify_result;
    std::unique_ptr<CertVerifier::Request> request;
    TestCompletionCallback callback;

    error = verifier_->Verify(..., &verify_result, callback.callback(), &request, ...);
    if (error == ERR_IO_PENDING) {
        // 正确的做法：等待回调函数
        error = callback.WaitForResult();
        // 现在可以处理 verify_result 和 error
    } else {
        // 错误的做法：假设验证已经完成
        // 可能会使用未初始化的 verify_result
    }
    ```
* **在请求完成前销毁 `MultiThreadedCertVerifier` 对象:** 如果在异步验证请求完成之前销毁 `MultiThreadedCertVerifier` 对象，可能会导致程序崩溃或未定义的行为。测试用例 `DeleteVerifier` 和 `DeleteVerifierCallbackOwnsResult` 就是为了防止这种情况。用户应该确保在销毁 `MultiThreadedCertVerifier` 之前，所有待处理的请求都已经完成或被取消。
* **不检查回调函数的返回值:** 即使 `verifier_->Verify` 返回 `ERR_IO_PENDING`，回调函数也可能返回错误码，指示证书验证失败。用户应该始终检查回调函数的返回值以获取最终的验证结果。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中访问一个 HTTPS 网站:** 例如，在地址栏输入 `https://www.example.com` 并按下回车键。
2. **浏览器发起网络请求:** 浏览器会创建一个网络请求，请求 `www.example.com` 的内容。
3. **建立 TLS 连接:** 为了建立安全的 HTTPS 连接，浏览器需要与服务器进行 TLS 握手。
4. **服务器提供 SSL/TLS 证书:** 在 TLS 握手过程中，服务器会将它的 SSL/TLS 证书发送给浏览器。
5. **证书验证触发:** 浏览器接收到证书后，会调用网络栈中的证书验证模块，其中就包括 `MultiThreadedCertVerifier`。
6. **`MultiThreadedCertVerifier` 处理验证请求:**
   *  接收服务器提供的证书。
   *  构建证书链。
   *  调用底层的 `CertVerifyProc` (通过多线程方式) 执行实际的验证操作，包括检查签名、有效期、吊销状态等。
7. **验证结果返回:** `MultiThreadedCertVerifier` 将验证结果返回给网络栈。
8. **根据验证结果采取行动:**
   * **验证成功:** 浏览器继续完成 TLS 握手，并开始下载网页内容。
   * **验证失败:** 浏览器会显示安全警告或错误页面，阻止用户访问该网站。

**作为调试线索:**

当用户遇到 HTTPS 连接问题时，例如看到 "您的连接不是私密连接" 的错误，开发人员可能会需要调试证书验证过程。以下是一些调试线索：

* **检查 NetLog:** Chromium 的 NetLog 包含了详细的网络事件日志，可以查看证书验证的详细过程，包括调用 `MultiThreadedCertVerifier` 的时间、传递的参数、以及返回的错误信息。
* **使用 `--ignore-certificate-errors` 命令行标志 (仅用于开发/测试):**  这个标志可以绕过证书验证，帮助确定问题是否确实与证书有关。但请注意，在生产环境中绝对不能使用此标志。
* **检查证书详细信息:** 在浏览器中可以查看网站的证书详细信息，例如颁发者、有效期、使用者等，这可以帮助识别证书本身是否存在问题。
* **断点调试:**  对于 Chromium 的开发人员，可以在 `MultiThreadedCertVerifier` 相关的代码中设置断点，逐步跟踪证书验证的流程，查看中间状态和变量值，以定位问题所在。
* **检查系统时间:** 证书的有效期是根据系统时间判断的，如果用户的系统时间不正确，可能会导致证书验证失败。

总而言之，`multi_threaded_cert_verifier_unittest.cc` 这个文件通过各种测试用例，确保了 `MultiThreadedCertVerifier` 类的正确性和可靠性，而这个类在 Chromium 中扮演着至关重要的角色，负责保障 HTTPS 连接的安全性。 当用户访问 HTTPS 网站遇到问题时，理解 `MultiThreadedCertVerifier` 的工作原理和相关的调试方法，对于诊断和解决问题非常有帮助。

### 提示词
```
这是目录为net/cert/multi_threaded_cert_verifier_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/multi_threaded_cert_verifier.h"

#include <memory>

#include "base/debug/leak_annotations.h"
#include "base/files/file_path.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log_with_source.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;
using testing::_;
using testing::DoAll;
using testing::Return;

namespace net {

class ChromeRootStoreData;
class CertNetFetcher;

namespace {

void FailTest(int /* result */) {
  FAIL();
}

class MockCertVerifyProc : public CertVerifyProc {
 public:
  MockCertVerifyProc() : CertVerifyProc(CRLSet::BuiltinCRLSet()) {}
  MOCK_METHOD7(VerifyInternal,
               int(X509Certificate*,
                   const std::string&,
                   const std::string&,
                   const std::string&,
                   int,
                   CertVerifyResult*,
                   const NetLogWithSource&));
  MOCK_CONST_METHOD0(SupportsAdditionalTrustAnchors, bool());

 private:
  ~MockCertVerifyProc() override = default;
};

ACTION(SetCertVerifyResult) {
  X509Certificate* cert = arg0;
  CertVerifyResult* result = arg5;
  result->Reset();
  result->verified_cert = cert;
  result->cert_status = CERT_STATUS_COMMON_NAME_INVALID;
}

ACTION(SetCertVerifyRevokedResult) {
  X509Certificate* cert = arg0;
  CertVerifyResult* result = arg5;
  result->Reset();
  result->verified_cert = cert;
  result->cert_status = CERT_STATUS_REVOKED;
}

class SwapWithNewProcFactory : public CertVerifyProcFactory {
 public:
  explicit SwapWithNewProcFactory(scoped_refptr<CertVerifyProc> new_mock_proc)
      : mock_verify_proc_(std::move(new_mock_proc)) {}

  scoped_refptr<net::CertVerifyProc> CreateCertVerifyProc(
      scoped_refptr<CertNetFetcher> cert_net_fetcher,
      const CertVerifyProc::ImplParams& impl_params,
      const CertVerifyProc::InstanceParams& instance_params) override {
    return mock_verify_proc_;
  }

 protected:
  ~SwapWithNewProcFactory() override = default;
  scoped_refptr<CertVerifyProc> mock_verify_proc_;
};

}  // namespace

class MultiThreadedCertVerifierTest : public TestWithTaskEnvironment {
 public:
  MultiThreadedCertVerifierTest()
      : mock_verify_proc_(base::MakeRefCounted<MockCertVerifyProc>()),
        mock_new_verify_proc_(base::MakeRefCounted<MockCertVerifyProc>()),
        verifier_(std::make_unique<MultiThreadedCertVerifier>(
            mock_verify_proc_,
            base::MakeRefCounted<SwapWithNewProcFactory>(
                mock_new_verify_proc_))) {
    EXPECT_CALL(*mock_verify_proc_, SupportsAdditionalTrustAnchors())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_verify_proc_, VerifyInternal(_, _, _, _, _, _, _))
        .WillRepeatedly(
            DoAll(SetCertVerifyResult(), Return(ERR_CERT_COMMON_NAME_INVALID)));
  }
  ~MultiThreadedCertVerifierTest() override = default;

 protected:
  scoped_refptr<MockCertVerifyProc> mock_verify_proc_;
  // The new verify_proc_ swapped in if the proc is updated.
  scoped_refptr<MockCertVerifyProc> mock_new_verify_proc_;
  std::unique_ptr<MultiThreadedCertVerifier> verifier_;
};

// Tests that the callback of a canceled request is never made.
TEST_F(MultiThreadedCertVerifierTest, CancelRequest) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  int error;
  CertVerifyResult verify_result;
  std::unique_ptr<CertVerifier::Request> request;

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, base::BindOnce(&FailTest), &request, NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  ASSERT_TRUE(request);
  request.reset();

  // Issue a few more requests to the worker pool and wait for their
  // completion, so that the task of the canceled request (which runs on a
  // worker thread) is likely to complete by the end of this test.
  TestCompletionCallback callback;
  for (int i = 0; i < 5; ++i) {
    error = verifier_->Verify(
        CertVerifier::RequestParams(test_cert, "www2.example.com", 0,
                                    /*ocsp_response=*/std::string(),
                                    /*sct_list=*/std::string()),
        &verify_result, callback.callback(), &request, NetLogWithSource());
    ASSERT_THAT(error, IsError(ERR_IO_PENDING));
    EXPECT_TRUE(request);
    error = callback.WaitForResult();
  }
}

// Tests that the callback of a request is never made if the |verifier_| itself
// is deleted.
TEST_F(MultiThreadedCertVerifierTest, DeleteVerifier) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  int error;
  CertVerifyResult verify_result;
  std::unique_ptr<CertVerifier::Request> request;

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, base::BindOnce(&FailTest), &request, NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  ASSERT_TRUE(request);
  verifier_.reset();

  RunUntilIdle();
}

namespace {

struct CertVerifyResultHelper {
  void FailTest(int /* result */) { FAIL(); }
  std::unique_ptr<CertVerifier::Request> request;
};

}  // namespace

// The same as the above "DeleteVerifier" test, except the callback provided
// will own the CertVerifier::Request as allowed by the CertVerifier contract.
// This is a regression test for https://crbug.com/1157562.
TEST_F(MultiThreadedCertVerifierTest, DeleteVerifierCallbackOwnsResult) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  int error;
  CertVerifyResult verify_result;
  std::unique_ptr<CertVerifyResultHelper> result_helper =
      std::make_unique<CertVerifyResultHelper>();
  CertVerifyResultHelper* result_helper_ptr = result_helper.get();
  CompletionOnceCallback callback = base::BindOnce(
      &CertVerifyResultHelper::FailTest, std::move(result_helper));

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, std::move(callback), &result_helper_ptr->request,
      NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  ASSERT_TRUE(result_helper_ptr->request);
  verifier_.reset();

  RunUntilIdle();
}

// Tests that a canceled request is not leaked.
TEST_F(MultiThreadedCertVerifierTest, CancelRequestThenQuit) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  int error;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  {
    // Because shutdown intentionally doesn't join worker threads, memory may
    // be leaked if the main thread shuts down before the worker thread
    // completes. In particular MultiThreadedCertVerifier calls
    // base::WorkerPool::PostTaskAndReply(), which leaks its "relay" when it
    // can't post the reply back to the origin thread. See
    // https://crbug.com/522514
    ANNOTATE_SCOPED_MEMORY_LEAK;
    error = verifier_->Verify(
        CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                    /*ocsp_response=*/std::string(),
                                    /*sct_list=*/std::string()),
        &verify_result, callback.callback(), &request, NetLogWithSource());
  }
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request);
  request.reset();
  // Destroy |verifier_| by going out of scope.
}

// Tests propagation of configuration options into CertVerifyProc flags
TEST_F(MultiThreadedCertVerifierTest, ConvertsConfigToFlags) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert);

  const struct TestConfig {
    bool CertVerifier::Config::*config_ptr;
    int expected_flag;
  } kTestConfig[] = {
      {&CertVerifier::Config::enable_rev_checking,
       CertVerifyProc::VERIFY_REV_CHECKING_ENABLED},
      {&CertVerifier::Config::require_rev_checking_local_anchors,
       CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS},
      {&CertVerifier::Config::enable_sha1_local_anchors,
       CertVerifyProc::VERIFY_ENABLE_SHA1_LOCAL_ANCHORS},
      {&CertVerifier::Config::disable_symantec_enforcement,
       CertVerifyProc::VERIFY_DISABLE_SYMANTEC_ENFORCEMENT},
  };
  for (const auto& test_config : kTestConfig) {
    CertVerifier::Config config;
    config.*test_config.config_ptr = true;

    verifier_->SetConfig(config);

    EXPECT_CALL(*mock_verify_proc_,
                VerifyInternal(_, _, _, _, test_config.expected_flag, _, _))
        .WillRepeatedly(
            DoAll(SetCertVerifyRevokedResult(), Return(ERR_CERT_REVOKED)));

    CertVerifyResult verify_result;
    TestCompletionCallback callback;
    std::unique_ptr<CertVerifier::Request> request;
    int error = verifier_->Verify(
        CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                    /*ocsp_response=*/std::string(),
                                    /*sct_list=*/std::string()),
        &verify_result, callback.callback(), &request, NetLogWithSource());
    ASSERT_THAT(error, IsError(ERR_IO_PENDING));
    EXPECT_TRUE(request);
    error = callback.WaitForResult();
    EXPECT_TRUE(IsCertificateError(error));
    EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

    testing::Mock::VerifyAndClearExpectations(mock_verify_proc_.get());
  }
}

// Tests propagation of CertVerifier flags into CertVerifyProc flags
TEST_F(MultiThreadedCertVerifierTest, ConvertsFlagsToFlags) {
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(test_cert);

  EXPECT_CALL(
      *mock_verify_proc_,
      VerifyInternal(_, _, _, _, CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES,
                     _, _))
      .WillRepeatedly(
          DoAll(SetCertVerifyRevokedResult(), Return(ERR_CERT_REVOKED)));

  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;
  int error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com",
                                  CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request);
  error = callback.WaitForResult();
  EXPECT_TRUE(IsCertificateError(error));
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  testing::Mock::VerifyAndClearExpectations(mock_verify_proc_.get());
}

// Tests swapping in new Chrome Root Store Data.
TEST_F(MultiThreadedCertVerifierTest, VerifyProcChangeChromeRootStore) {
  CertVerifierObserverCounter observer_counter(verifier_.get());

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert);

  EXPECT_EQ(observer_counter.change_count(), 0u);

  EXPECT_CALL(*mock_new_verify_proc_, VerifyInternal(_, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetCertVerifyRevokedResult(), Return(ERR_CERT_REVOKED)));
  verifier_->UpdateVerifyProcData(nullptr, {}, {});

  EXPECT_EQ(observer_counter.change_count(), 1u);

  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;
  int error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request);
  error = callback.WaitForResult();
  EXPECT_TRUE(IsCertificateError(error));
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  testing::Mock::VerifyAndClearExpectations(mock_verify_proc_.get());
  testing::Mock::VerifyAndClearExpectations(mock_new_verify_proc_.get());
}

// Tests swapping out a new proc while a request is pending still uses
// the old proc for the old request.
TEST_F(MultiThreadedCertVerifierTest, VerifyProcChangeRequest) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert);

  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;
  int error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_THAT(error, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request);
  verifier_->UpdateVerifyProcData(nullptr, {}, {});
  error = callback.WaitForResult();
  EXPECT_TRUE(IsCertificateError(error));
  EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));

  testing::Mock::VerifyAndClearExpectations(mock_verify_proc_.get());
  testing::Mock::VerifyAndClearExpectations(mock_new_verify_proc_.get());
}

}  // namespace net
```