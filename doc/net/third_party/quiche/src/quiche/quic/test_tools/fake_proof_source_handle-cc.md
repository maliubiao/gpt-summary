Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `fake_proof_source_handle.cc` file within the Chromium QUIC stack. This means identifying its purpose, how it interacts with other components, and any implications for developers or users.

2. **Identify Key Components:**  The first step is to scan the code for important classes, structs, and functions. I see:
    * `FakeProofSourceHandle`: This looks like the main class. The name "Fake" and "Handle" suggests it's a testing or abstraction layer.
    * `ProofSource`:  This is likely an interface or base class for providing cryptographic proofs (certificates, signatures). The `delegate_` member confirms this.
    * `ProofSourceHandleCallback`: This suggests an asynchronous pattern where the `FakeProofSourceHandle` communicates results back.
    * `Action` enum:  This clearly controls the behavior of the fake implementation (delegate, fail synchronously/asynchronously).
    * `SelectCertificate`, `ComputeSignature`: These are the core operations the `FakeProofSourceHandle` manages.
    * `SelectCertArgs`, `ComputeSignatureArgs`: Data structures holding the arguments for these operations.
    * `SelectCertOperation`, `ComputeSignatureOperation`:  These seem to handle the asynchronous delegation or failure logic.
    * `ComputeSignatureResult`, `ResultSavingSignatureCallback`: Support structures for synchronous signature computation.

3. **Infer the Purpose:**  Based on the names and the "Fake" prefix, it's highly probable that `FakeProofSourceHandle` is designed for *testing*. It allows simulating different outcomes of proof source operations (success, synchronous failure, asynchronous failure, delegation) without needing a real, complex `ProofSource` implementation.

4. **Analyze the Core Functions:**
    * **Constructor:**  Initializes the `FakeProofSourceHandle` with a delegate `ProofSource`, a callback, and actions for certificate selection and signature computation. This confirms the testing/mocking purpose.
    * **`SelectCertificate`:**  This function takes parameters related to TLS handshake and certificate selection. It checks the `select_cert_action_` and either delegates to the real `ProofSource`, fails synchronously, or initiates an asynchronous operation. The arguments are stored in `all_select_cert_args_`, suggesting a way to inspect the calls during testing.
    * **`ComputeSignature`:** Similar to `SelectCertificate`, this function handles signature computation based on `compute_signature_action_`.
    * **`CloseHandle`:**  Resets the pending operations, indicating resource management.
    * **`callback()`:** Returns the callback interface.
    * **`HasPendingOperation()` and `CompletePendingOperation()`:** These are crucial for managing asynchronous operations in tests, allowing the test to control the flow of execution.
    * **`NumPendingOperations()`:** Returns the number of ongoing asynchronous operations.
    * **Inner Classes (`SelectCertOperation`, `ComputeSignatureOperation`):**  These handle the asynchronous delegation or failure, using the stored arguments and the callback.

5. **Relate to JavaScript (if applicable):**  The prompt asks about JavaScript relevance. QUIC is a network protocol, and while JavaScript in a browser uses it indirectly, the C++ code itself doesn't directly interact with JavaScript. The connection is that this code is part of Chrome, which *runs* JavaScript. Therefore, the *effects* of this code (how the browser establishes secure QUIC connections) will be relevant to web pages using HTTPS. This requires a nuanced explanation, as it's not a direct code-level interaction.

6. **Consider Logic and Examples:**
    * **Assumptions:**  Think about the different `Action` enum values and how they affect the execution flow. For example, if `select_cert_action_` is `DELEGATE_SYNC`, `GetCertChain` on the delegate will be called immediately.
    * **Input/Output:** Imagine a test scenario calling `SelectCertificate`. The input would be the function arguments (server address, hostname, etc.). The output would be the return value (`QUIC_SUCCESS`, `QUIC_FAILURE`, or `QUIC_PENDING`) and the calls made to the `ProofSourceHandleCallback`.
    * **User/Programming Errors:**  Consider how developers using this *testing* utility might misuse it. Forgetting to call `CompletePendingOperation` in an asynchronous scenario is a likely mistake. Also, misconfiguring the `Action` enum could lead to unexpected test behavior.

7. **Debugging Perspective:**  How would someone end up looking at this file while debugging?  This often happens when investigating TLS handshake issues, certificate problems, or general QUIC connection failures. Tracing the execution flow related to certificate selection or signature generation might lead a developer here if they suspect a problem in the proof source logic.

8. **Structure the Explanation:** Organize the findings into logical sections:
    * Overview of functionality.
    * Detailed explanation of key functions and their actions.
    * Relationship to JavaScript (with the caveat of indirect interaction).
    * Examples of logical flow with input/output.
    * Common errors.
    * Debugging context.

9. **Refine and Elaborate:**  Go back through the explanation and add details, clarify any ambiguous points, and ensure the language is clear and concise. For example, explicitly mentioning the testing purpose in the overview is important. Explaining the meaning of synchronous vs. asynchronous failure is crucial.

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate explanation of its functionality and context. The iterative process of identifying components, inferring purpose, analyzing functions, and then considering the broader context (JavaScript, errors, debugging) is key to a thorough understanding.
这个C++文件 `fake_proof_source_handle.cc` 的主要功能是为 Chromium QUIC 协议栈提供一个**用于测试目的的、可控制的 `ProofSourceHandle` 的实现**。

`ProofSourceHandle` 在 QUIC 中负责处理与证书和签名相关的操作，例如选择合适的证书链和计算 TLS 签名。这个 "fake" 的实现允许测试人员模拟不同的场景和结果，而无需依赖真实的、复杂的 `ProofSource` 实现。

**以下是其功能的详细说明:**

1. **模拟 `ProofSourceHandle` 的行为:** `FakeProofSourceHandle` 类实现了 `ProofSourceHandle` 接口，但其行为可以通过构造函数中传入的 `Action` 枚举值进行控制。这使得测试可以模拟以下几种情况：
    * **`DELEGATE_SYNC`:** 同步地将操作委托给真实的 `ProofSource` 对象 (`delegate_`)。
    * **`DELEGATE_ASYNC`:** 异步地将操作委托给真实的 `ProofSource` 对象。
    * **`FAIL_SYNC`:** 同步地返回失败。
    * **`FAIL_ASYNC`:** 异步地返回失败。
    * **`FAIL_SYNC_DO_NOT_CHECK_CLOSED`:**  同步返回失败，并且不检查句柄是否已关闭（用于特定测试场景）。

2. **控制证书选择 (`SelectCertificate`):**  当调用 `SelectCertificate` 时，`FakeProofSourceHandle` 会根据 `select_cert_action_` 的值执行不同的操作：
    * 如果设置为 `DELEGATE_SYNC` 或 `DELEGATE_ASYNC`，它会调用真实 `ProofSource` 的 `GetCertChain` 方法来获取证书链。
    * 如果设置为 `FAIL_SYNC` 或 `FAIL_ASYNC`，它会直接调用回调函数返回失败。
    * 它可以记录所有 `SelectCertificate` 调用的参数 (`all_select_cert_args_`)，方便后续断言和检查。

3. **控制签名计算 (`ComputeSignature`):**  类似地，当调用 `ComputeSignature` 时，`FakeProofSourceHandle` 会根据 `compute_signature_action_` 的值执行不同的操作：
    * 如果设置为 `DELEGATE_SYNC` 或 `DELEGATE_ASYNC`，它会调用一个辅助函数 `ComputeSignatureNow`，该函数会同步或异步地调用真实 `ProofSource` 的 `ComputeTlsSignature` 方法。
    * 如果设置为 `FAIL_SYNC` 或 `FAIL_ASYNC`，它会直接调用回调函数返回失败。
    * 它可以记录所有 `ComputeSignature` 调用的参数 (`all_compute_signature_args_`)。

4. **处理异步操作:**  对于异步操作 (`DELEGATE_ASYNC` 和 `FAIL_ASYNC`)，`FakeProofSourceHandle` 使用内部的 `SelectCertOperation` 和 `ComputeSignatureOperation` 类来模拟异步行为。它会存储操作的状态，并提供 `CompletePendingOperation` 方法来触发异步操作的完成，调用相应的回调函数。

5. **提供回调机制:** `FakeProofSourceHandle` 通过 `ProofSourceHandleCallback` 接口将操作结果通知给调用方。

**与 JavaScript 的关系:**

这个 C++ 文件本身与 JavaScript 代码没有直接的交互。然而，它在 Chromium 网络栈中扮演着重要的角色，而 Chromium 是一个支持运行 JavaScript 的浏览器。

具体来说，当浏览器通过 HTTPS 使用 QUIC 协议与服务器建立安全连接时，底层的 QUIC 实现会使用 `ProofSourceHandle` 来获取服务器的证书并验证其签名。`FakeProofSourceHandle` 的存在允许开发人员在测试 QUIC 相关功能时，无需搭建真实的 TLS 环境，就可以模拟各种证书选择和签名验证的场景。

**举例说明 JavaScript 的关联:**

假设一个 JavaScript 应用程序尝试通过 `fetch` API 发起一个 HTTPS 请求到一个使用 QUIC 协议的服务器。当浏览器尝试建立连接时，Chromium 的 QUIC 实现可能会调用 `ProofSourceHandle` 的方法来获取服务器证书。

* **测试场景:**  如果正在进行 QUIC 的功能测试，可以使用 `FakeProofSourceHandle` 并将其配置为 `FAIL_SYNC` 模式。这样，当 QUIC 代码尝试获取服务器证书时，`FakeProofSourceHandle` 会立即返回失败。测试代码可以断言在这种情况下，连接建立失败，并且 JavaScript 的 `fetch` API 会返回一个相应的错误。
* **调试场景:** 如果在浏览器中访问某个网站时遇到 QUIC 连接问题，开发人员可能会查看 Chromium 的网络日志，这些日志可能会显示与 `ProofSourceHandle` 相关的操作，例如证书选择失败或签名验证失败。虽然不能直接在 JavaScript 中操作 `FakeProofSourceHandle`，但它的行为会影响到 JavaScript 发起的网络请求的结果。

**逻辑推理与假设输入/输出:**

**假设输入:**

* `FakeProofSourceHandle` 实例被创建，`select_cert_action_` 被设置为 `DELEGATE_SYNC`。
* 调用 `SelectCertificate` 方法，传入以下参数：
    * `server_address`:  服务器地址 (例如: `192.168.1.1:443`)
    * `client_address`: 客户端地址 (例如: `192.168.1.100:12345`)
    * `hostname`:  服务器主机名 (例如: `example.com`)
    * 其他证书选择相关的参数...

**预期输出:**

1. `FakeProofSourceHandle` 会调用其内部 `delegate_` 指向的真实 `ProofSource` 对象的 `GetCertChain` 方法，并将 `server_address`, `client_address`, 和 `hostname` 传递给它。
2. `GetCertChain` 方法会返回一个证书链（`quiche::QuicheReferenceCountedPointer<ProofSource::Chain>`）和一个指示证书是否匹配 SNI 的布尔值。
3. `FakeProofSourceHandle` 会调用其 `callback_` 指向的 `ProofSourceHandleCallback` 对象的 `OnSelectCertificateDone` 方法，并将以下参数传递给它：
    * `ok`: 如果 `GetCertChain` 返回的证书链不为空，则为 `true`，否则为 `false`。
    * `is_sync`: `true` (因为 `select_cert_action_` 是 `DELEGATE_SYNC`)。
    * `local_ssl_config`: 包含从 `GetCertChain` 获取的证书链和 `delayed_ssl_config_`。
    * `ticket_encryption_key`: 空字符串。
    * `cert_matched_sni`: 从 `GetCertChain` 获取的布尔值。
4. `SelectCertificate` 方法本身会返回 `QUIC_SUCCESS` 或 `QUIC_FAILURE`，取决于证书链是否获取成功。

**用户或编程常见的使用错误:**

1. **在异步操作后忘记调用 `CompletePendingOperation`:** 如果将 `Action` 设置为 `DELEGATE_ASYNC` 或 `FAIL_ASYNC`，`FakeProofSourceHandle` 会返回 `QUIC_PENDING`，并且操作不会立即完成。测试代码需要显式调用 `CompletePendingOperation` 来触发回调函数的执行。忘记调用会导致测试卡住或行为不符合预期。

   ```c++
   // 错误示例：
   FakeProofSourceHandle handle(..., Action::DELEGATE_ASYNC, ...);
   handle.SelectCertificate(...);
   // ... 缺少 handle.CompletePendingOperation(); ...
   ```

2. **对已关闭的句柄进行操作:** 调用 `CloseHandle` 后，再调用 `SelectCertificate` 或 `ComputeSignature` 会导致断言失败（除非 `Action` 被设置为 `FAIL_SYNC_DO_NOT_CHECK_CLOSED`）。

   ```c++
   FakeProofSourceHandle handle(...);
   handle.CloseHandle();
   handle.SelectCertificate(...); // 错误：句柄已关闭
   ```

3. **在同步操作的情况下错误地假设异步行为:** 如果 `Action` 被设置为 `DELEGATE_SYNC` 或 `FAIL_SYNC`，操作会立即完成，回调函数也会同步调用。测试代码不应该在这种情况下期望异步行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问一个使用 QUIC 协议的网站时遇到了连接问题，例如 "连接不是私密的" 或连接超时。作为一名 Chromium 开发人员，为了调试这个问题，可能会采取以下步骤：

1. **启用 QUIC 日志:**  首先，可能会启用 Chromium 的 QUIC 内部日志 (`chrome://net-internals/#quic`) 来查看 QUIC 连接的详细信息。
2. **查看网络事件:** 在 `chrome://net-internals/#events` 中，可以找到与该连接相关的网络事件。
3. **定位证书相关的错误:**  如果在日志中看到与证书选择 (`SelectCertificate`) 或签名计算 (`ComputeSignature`) 相关的错误，例如 "Certificate selection failed" 或 "Signature verification failed"，这可能表明问题出在 `ProofSourceHandle` 的实现上。
4. **检查 `FakeProofSourceHandle` 的使用:**  如果怀疑问题与测试环境有关，或者想了解在特定测试场景下 `ProofSourceHandle` 的行为，可能会查看 `fake_proof_source_handle.cc` 的代码。
5. **设置断点和跟踪:**  可以在 `fake_proof_source_handle.cc` 中的 `SelectCertificate` 或 `ComputeSignature` 方法中设置断点，并跟踪代码的执行流程，查看 `Action` 的值，以及 `delegate_` 指向的真实 `ProofSource` 的行为。
6. **分析参数和回调:**  可以检查传递给 `SelectCertificate` 和 `ComputeSignature` 的参数，以及 `ProofSourceHandleCallback` 的调用情况，以确定问题发生的具体原因。

总而言之，`fake_proof_source_handle.cc` 是 Chromium QUIC 测试框架中的一个关键组件，它允许开发人员以可控的方式模拟证书和签名相关的操作，从而方便进行各种测试和调试工作。虽然普通用户不会直接接触到这个文件，但它的正确性和可靠性对于确保 QUIC 连接的安全性至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/fake_proof_source_handle.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/fake_proof_source_handle.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"

namespace quic {
namespace test {
namespace {

struct ComputeSignatureResult {
  bool ok;
  std::string signature;
  std::unique_ptr<ProofSource::Details> details;
};

class ResultSavingSignatureCallback : public ProofSource::SignatureCallback {
 public:
  explicit ResultSavingSignatureCallback(
      std::optional<ComputeSignatureResult>* result)
      : result_(result) {
    QUICHE_DCHECK(!result_->has_value());
  }
  void Run(bool ok, std::string signature,
           std::unique_ptr<ProofSource::Details> details) override {
    result_->emplace(
        ComputeSignatureResult{ok, std::move(signature), std::move(details)});
  }

 private:
  std::optional<ComputeSignatureResult>* result_;
};

ComputeSignatureResult ComputeSignatureNow(
    ProofSource* delegate, const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address, const std::string& hostname,
    uint16_t signature_algorithm, absl::string_view in) {
  std::optional<ComputeSignatureResult> result;
  delegate->ComputeTlsSignature(
      server_address, client_address, hostname, signature_algorithm, in,
      std::make_unique<ResultSavingSignatureCallback>(&result));
  QUICHE_CHECK(result.has_value())
      << "delegate->ComputeTlsSignature must computes a "
         "signature immediately";
  return std::move(result.value());
}
}  // namespace

FakeProofSourceHandle::FakeProofSourceHandle(
    ProofSource* delegate, ProofSourceHandleCallback* callback,
    Action select_cert_action, Action compute_signature_action,
    QuicDelayedSSLConfig delayed_ssl_config)
    : delegate_(delegate),
      callback_(callback),
      select_cert_action_(select_cert_action),
      compute_signature_action_(compute_signature_action),
      delayed_ssl_config_(delayed_ssl_config) {}

void FakeProofSourceHandle::CloseHandle() {
  select_cert_op_.reset();
  compute_signature_op_.reset();
  closed_ = true;
}

QuicAsyncStatus FakeProofSourceHandle::SelectCertificate(
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address,
    const QuicConnectionId& original_connection_id,
    absl::string_view ssl_capabilities, const std::string& hostname,
    absl::string_view client_hello, const std::string& alpn,
    std::optional<std::string> alps,
    const std::vector<uint8_t>& quic_transport_params,
    const std::optional<std::vector<uint8_t>>& early_data_context,
    const QuicSSLConfig& ssl_config) {
  if (select_cert_action_ != Action::FAIL_SYNC_DO_NOT_CHECK_CLOSED) {
    QUICHE_CHECK(!closed_);
  }
  all_select_cert_args_.push_back(
      SelectCertArgs(server_address, client_address, original_connection_id,
                     ssl_capabilities, hostname, client_hello, alpn, alps,
                     quic_transport_params, early_data_context, ssl_config));

  if (select_cert_action_ == Action::DELEGATE_ASYNC ||
      select_cert_action_ == Action::FAIL_ASYNC) {
    select_cert_op_.emplace(delegate_, callback_, select_cert_action_,
                            all_select_cert_args_.back(), delayed_ssl_config_);
    return QUIC_PENDING;
  } else if (select_cert_action_ == Action::FAIL_SYNC ||
             select_cert_action_ == Action::FAIL_SYNC_DO_NOT_CHECK_CLOSED) {
    callback()->OnSelectCertificateDone(
        /*ok=*/false,
        /*is_sync=*/true,
        ProofSourceHandleCallback::LocalSSLConfig{nullptr, delayed_ssl_config_},
        /*ticket_encryption_key=*/absl::string_view(),
        /*cert_matched_sni=*/false);
    return QUIC_FAILURE;
  }

  QUICHE_DCHECK(select_cert_action_ == Action::DELEGATE_SYNC);
  bool cert_matched_sni;
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain =
      delegate_->GetCertChain(server_address, client_address, hostname,
                              &cert_matched_sni);

  bool ok = chain && !chain->certs.empty();
  callback_->OnSelectCertificateDone(
      ok, /*is_sync=*/true,
      ProofSourceHandleCallback::LocalSSLConfig{chain.get(),
                                                delayed_ssl_config_},
      /*ticket_encryption_key=*/absl::string_view(),
      /*cert_matched_sni=*/cert_matched_sni);
  return ok ? QUIC_SUCCESS : QUIC_FAILURE;
}

QuicAsyncStatus FakeProofSourceHandle::ComputeSignature(
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address, const std::string& hostname,
    uint16_t signature_algorithm, absl::string_view in,
    size_t max_signature_size) {
  if (compute_signature_action_ != Action::FAIL_SYNC_DO_NOT_CHECK_CLOSED) {
    QUICHE_CHECK(!closed_);
  }
  all_compute_signature_args_.push_back(
      ComputeSignatureArgs(server_address, client_address, hostname,
                           signature_algorithm, in, max_signature_size));

  if (compute_signature_action_ == Action::DELEGATE_ASYNC ||
      compute_signature_action_ == Action::FAIL_ASYNC) {
    compute_signature_op_.emplace(delegate_, callback_,
                                  compute_signature_action_,
                                  all_compute_signature_args_.back());
    return QUIC_PENDING;
  } else if (compute_signature_action_ == Action::FAIL_SYNC ||
             compute_signature_action_ ==
                 Action::FAIL_SYNC_DO_NOT_CHECK_CLOSED) {
    callback()->OnComputeSignatureDone(/*ok=*/false, /*is_sync=*/true,
                                       /*signature=*/"", /*details=*/nullptr);
    return QUIC_FAILURE;
  }

  QUICHE_DCHECK(compute_signature_action_ == Action::DELEGATE_SYNC);
  ComputeSignatureResult result =
      ComputeSignatureNow(delegate_, server_address, client_address, hostname,
                          signature_algorithm, in);
  callback_->OnComputeSignatureDone(
      result.ok, /*is_sync=*/true, result.signature, std::move(result.details));
  return result.ok ? QUIC_SUCCESS : QUIC_FAILURE;
}

ProofSourceHandleCallback* FakeProofSourceHandle::callback() {
  return callback_;
}

bool FakeProofSourceHandle::HasPendingOperation() const {
  int num_pending_operations = NumPendingOperations();
  return num_pending_operations > 0;
}

void FakeProofSourceHandle::CompletePendingOperation() {
  QUICHE_DCHECK_LE(NumPendingOperations(), 1);

  if (select_cert_op_.has_value()) {
    select_cert_op_->Run();
    select_cert_op_.reset();
  } else if (compute_signature_op_.has_value()) {
    compute_signature_op_->Run();
    compute_signature_op_.reset();
  }
}

int FakeProofSourceHandle::NumPendingOperations() const {
  return static_cast<int>(select_cert_op_.has_value()) +
         static_cast<int>(compute_signature_op_.has_value());
}

FakeProofSourceHandle::SelectCertOperation::SelectCertOperation(
    ProofSource* delegate, ProofSourceHandleCallback* callback, Action action,
    SelectCertArgs args, QuicDelayedSSLConfig delayed_ssl_config)
    : PendingOperation(delegate, callback, action),
      args_(std::move(args)),
      delayed_ssl_config_(delayed_ssl_config) {}

void FakeProofSourceHandle::SelectCertOperation::Run() {
  if (action_ == Action::FAIL_ASYNC) {
    callback_->OnSelectCertificateDone(
        /*ok=*/false,
        /*is_sync=*/false,
        ProofSourceHandleCallback::LocalSSLConfig{nullptr, delayed_ssl_config_},
        /*ticket_encryption_key=*/absl::string_view(),
        /*cert_matched_sni=*/false);
  } else if (action_ == Action::DELEGATE_ASYNC) {
    bool cert_matched_sni;
    quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain =
        delegate_->GetCertChain(args_.server_address, args_.client_address,
                                args_.hostname, &cert_matched_sni);
    bool ok = chain && !chain->certs.empty();
    callback_->OnSelectCertificateDone(
        ok, /*is_sync=*/false,
        ProofSourceHandleCallback::LocalSSLConfig{chain.get(),
                                                  delayed_ssl_config_},
        /*ticket_encryption_key=*/absl::string_view(),
        /*cert_matched_sni=*/cert_matched_sni);
  } else {
    QUIC_BUG(quic_bug_10139_1)
        << "Unexpected action: " << static_cast<int>(action_);
  }
}

FakeProofSourceHandle::ComputeSignatureOperation::ComputeSignatureOperation(
    ProofSource* delegate, ProofSourceHandleCallback* callback, Action action,
    ComputeSignatureArgs args)
    : PendingOperation(delegate, callback, action), args_(std::move(args)) {}

void FakeProofSourceHandle::ComputeSignatureOperation::Run() {
  if (action_ == Action::FAIL_ASYNC) {
    callback_->OnComputeSignatureDone(
        /*ok=*/false, /*is_sync=*/false,
        /*signature=*/"", /*details=*/nullptr);
  } else if (action_ == Action::DELEGATE_ASYNC) {
    ComputeSignatureResult result = ComputeSignatureNow(
        delegate_, args_.server_address, args_.client_address, args_.hostname,
        args_.signature_algorithm, args_.in);
    callback_->OnComputeSignatureDone(result.ok, /*is_sync=*/false,
                                      result.signature,
                                      std::move(result.details));
  } else {
    QUIC_BUG(quic_bug_10139_2)
        << "Unexpected action: " << static_cast<int>(action_);
  }
}

}  // namespace test
}  // namespace quic
```