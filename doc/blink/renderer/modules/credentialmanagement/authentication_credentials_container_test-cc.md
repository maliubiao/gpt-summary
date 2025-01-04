Response:
The user wants to understand the functionality of the given C++ source code file. I need to analyze the code and explain its purpose. The file name suggests it's a test file for `AuthenticationCredentialsContainer`. This class is likely related to the Credential Management API in Blink.

Here's a plan:
1. **Identify the core functionality:** Determine what aspects of `AuthenticationCredentialsContainer` are being tested.
2. **Explain the tests:** Describe what each test case aims to verify.
3. **Relate to web technologies:** Connect the tested functionalities to JavaScript, HTML, and CSS, if applicable.
4. **Illustrate with examples:** Provide hypothetical inputs and outputs for logical deductions.
5. **Highlight potential user errors:** Identify common mistakes users might make when interacting with the tested API.
6. **Describe the user journey:** Explain how a user's actions can lead to the execution of this code.
这个C++源代码文件 `authentication_credentials_container_test.cc` 是 Chromium Blink 引擎中用于测试 `AuthenticationCredentialsContainer` 类的单元测试文件。 `AuthenticationCredentialsContainer` 类是 Credential Management API 的一部分，该 API 允许网站与用户的凭据（如密码、联合身份凭据和公钥凭据）进行交互。

以下是该文件列举的功能：

1. **测试 `get()` 方法的功能:**  测试 `AuthenticationCredentialsContainer` 的 `get()` 方法，该方法用于请求用户的凭据。测试涵盖了不同的凭据类型（密码、联合身份、公钥）以及不同的 mediation 需求。
2. **测试 `store()` 方法的行为:**  测试 `AuthenticationCredentialsContainer` 的 `store()` 方法，该方法用于存储新的凭据。  测试了尝试存储 `PublicKeyCredential` 是否会被拒绝。
3. **测试在请求进行中时，文档被销毁的情况:**  测试当一个 `get()` 请求正在进行中，但关联的文档被销毁时，是否能正确处理，避免崩溃和内存泄漏。
4. **测试 `get()` 方法的 use counter:** 验证在调用 `get()` 方法请求不同类型的凭据时，相应的 use counter (用于跟踪 Web 功能的使用情况) 是否被正确记录。 例如，当请求密码凭据时，`kCredentialManagerGetPasswordCredential` use counter 会增加。
5. **测试 PublicKey Credential 的条件式媒介 (conditional mediation) UKM 记录:**  验证当使用条件式媒介请求公钥凭据时，是否会生成相应的 User Keyed Metrics (UKM) 日志。
6. **测试在启用多身份提供商模式下，`get()` 方法对 "active" 模式的拒绝:** 测试在 FedCM (Federated Credential Management) 功能启用了多身份提供商支持和按钮模式的情况下，尝试使用 "active" 模式请求身份凭据是否会被拒绝。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**  这个测试文件直接测试了 JavaScript 中 `navigator.credentials` 对象下的方法，例如 `navigator.credentials.get()` 和 `navigator.credentials.store()`。开发者可以使用这些 JavaScript API 与用户的凭据管理器进行交互。例如：

   ```javascript
   // 请求密码凭据
   navigator.credentials.get({ password: true })
     .then(credential => {
       console.log("获取到密码凭据:", credential);
     })
     .catch(error => {
       console.error("获取密码凭据失败:", error);
     });

   // 请求联合身份凭据
   navigator.credentials.get({ federated: { providers: ["https://idp.example"] } })
     .then(credential => {
       console.log("获取到联合身份凭据:", credential);
     })
     .catch(error => {
       console.error("获取联合身份凭据失败:", error);
     });

   // 尝试存储一个公钥凭据 (虽然会被拒绝，但在 JavaScript 中可以调用)
   navigator.credentials.store(new PublicKeyCredential({ // ... 公钥凭据的参数 }))
     .then(() => {
       console.log("公钥凭据存储成功");
     })
     .catch(error => {
       console.error("公钥凭据存储失败:", error);
     });
   ```

* **HTML:** HTML 用于触发 JavaScript 代码的执行。例如，一个按钮的点击事件可能调用 `navigator.credentials.get()`。

   ```html
   <button onclick="requestPassword()">请求密码登录</button>
   <script>
     function requestPassword() {
       navigator.credentials.get({ password: true });
     }
   </script>
   ```

* **CSS:** CSS 本身与 Credential Management API 的核心功能没有直接关系，但可以用于控制与凭据交互相关的用户界面元素的外观和行为。例如，在 FedCM 流中，CSS 可以用来样式化身份提供商的选择界面。

**逻辑推理的假设输入与输出：**

**示例 1: 测试 `get()` 方法请求密码凭据的 use counter**

* **假设输入:** JavaScript 代码调用 `navigator.credentials.get({ password: true })`。
* **预期输出:**  在 Chromium 内部，`WebFeature::kCredentialManagerGetPasswordCredential` 这个 use counter 的值会增加。测试代码会验证这个 use counter 是否被标记为已使用。

**示例 2: 测试尝试存储 `PublicKeyCredential`**

* **假设输入:** JavaScript 代码调用 `navigator.credentials.store(new PublicKeyCredential(...))`。
* **预期输出:** `store()` 方法返回的 Promise 会被 rejected，因为 `AuthenticationCredentialsContainer` 不允许直接存储 `PublicKeyCredential` 对象。

**涉及用户或者编程常见的使用错误举例说明：**

1. **在不安全的上下文中使用 Credential Management API:**  Credential Management API 的许多功能（特别是涉及敏感凭据的操作）只能在安全的上下文 (HTTPS) 中使用。用户如果在 HTTP 页面上尝试调用 `navigator.credentials.get()` 或 `navigator.credentials.store()`，可能会导致错误或功能被禁用。
2. **不正确地配置 `CredentialRequestOptions`:**  开发者可能会错误地设置 `CredentialRequestOptions` 对象，导致无法获取预期的凭据。例如，请求联合身份凭据时，没有提供有效的身份提供商列表。
3. **在 FedCM 的 "active" 模式下，错误地配置了多个身份提供商:** 如测试用例 `RejectActiveModeWithMultipleIdps` 所示，在启用了多身份提供商支持和按钮模式的 FedCM 中，"active" 模式不支持多个身份提供商。尝试这样做会导致 Promise 被 rejected。 用户可能错误地认为 "active" 模式可以同时处理多个 IDP。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问一个网站:** 用户在浏览器中输入网址或点击链接访问一个网站。
2. **网站加载并执行 JavaScript 代码:** 网站的前端代码（HTML 和 JavaScript）被加载到用户的浏览器中并开始执行。
3. **网站调用 Credential Management API:** 网站的 JavaScript 代码调用 `navigator.credentials.get()` 或 `navigator.credentials.store()` 方法，例如，在用户点击 "登录" 按钮后，网站可能会尝试调用 `navigator.credentials.get({ password: true })` 来请求用户的密码凭据。
4. **Blink 引擎处理 API 调用:**  浏览器引擎（Blink）接收到 JavaScript 的 API 调用。对于 `navigator.credentials.get()`，Blink 会创建 `AuthenticationCredentialsContainer` 的实例并调用其 `get()` 方法。
5. **进入测试代码路径 (调试):** 如果开发者正在 Chromium 的开发环境中进行调试，并且设置了断点或执行了相关的测试用例，那么当代码执行到 `AuthenticationCredentialsContainer` 的 `get()` 或 `store()` 方法时，就会命中测试代码中的逻辑，例如 `authentication_credentials_container_test.cc` 中模拟的 `MockCredentialManager` 的方法会被调用。
6. **测试验证行为:**  测试代码会模拟不同的场景和输入，验证 `AuthenticationCredentialsContainer` 的行为是否符合预期，例如是否正确地与底层的 Credential Manager 服务交互，是否正确处理错误情况，以及是否记录了相应的 use counter 和 UKM 日志。

因此，调试线索可能是：用户在特定网站执行了登录或凭据相关的操作，触发了网站的 JavaScript 代码调用了 Credential Management API，从而导致 Blink 引擎中 `AuthenticationCredentialsContainer` 的代码被执行，最终进入到相关的测试代码路径进行验证。 开发者可以通过查看浏览器的开发者工具中的控制台输出、网络请求以及内部的日志记录来追踪这些步骤。

Prompt: 
```
这是目录为blink/renderer/modules/credentialmanagement/authentication_credentials_container_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/authentication_credentials_container.h"

#include <memory>
#include <utility>

#include "base/test/scoped_feature_list.h"
#include "components/ukm/test_ukm_recorder.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/credentialmanagement/credential_manager.mojom-blink.h"
#include "third_party/blink/public/mojom/webauthn/authenticator.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_federated_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_user_entity.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/testing/gc_object_liveness_observer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_proxy.h"
#include "third_party/blink/renderer/modules/credentialmanagement/federated_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/password_credential.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/wrapper_type_info.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

class MockCredentialManager : public mojom::blink::CredentialManager {
 public:
  MockCredentialManager() = default;

  MockCredentialManager(const MockCredentialManager&) = delete;
  MockCredentialManager& operator=(const MockCredentialManager&) = delete;

  ~MockCredentialManager() override {}

  void Bind(mojo::PendingReceiver<::blink::mojom::blink::CredentialManager>
                receiver) {
    receiver_.Bind(std::move(receiver));
    receiver_.set_disconnect_handler(WTF::BindOnce(
        &MockCredentialManager::Disconnected, WTF::Unretained(this)));
  }

  void Disconnected() { disconnected_ = true; }

  bool IsDisconnected() const { return disconnected_; }

  void WaitForCallToGet() {
    if (get_callback_)
      return;

    loop_.Run();
  }

  void InvokeGetCallback() {
    EXPECT_TRUE(receiver_.is_bound());

    auto info = blink::mojom::blink::CredentialInfo::New();
    info->type = blink::mojom::blink::CredentialType::EMPTY;
    std::move(get_callback_)
        .Run(blink::mojom::blink::CredentialManagerError::SUCCESS,
             std::move(info));
  }

 protected:
  void Store(blink::mojom::blink::CredentialInfoPtr credential,
             StoreCallback callback) override {}
  void PreventSilentAccess(PreventSilentAccessCallback callback) override {}
  void Get(blink::mojom::blink::CredentialMediationRequirement mediation,
           int requested_credential_types,
           const WTF::Vector<::blink::KURL>& federations,
           GetCallback callback) override {
    get_callback_ = std::move(callback);
    loop_.Quit();
  }

 private:
  mojo::Receiver<::blink::mojom::blink::CredentialManager> receiver_{this};

  GetCallback get_callback_;
  bool disconnected_ = false;
  base::RunLoop loop_;
};

class MockAuthenticatorInterface : public mojom::blink::Authenticator {
 public:
  MockAuthenticatorInterface() { loop_ = std::make_unique<base::RunLoop>(); }

  MockAuthenticatorInterface(const MockAuthenticatorInterface&) = delete;
  MockAuthenticatorInterface& operator=(const MockAuthenticatorInterface&) =
      delete;

  void Bind(
      mojo::PendingReceiver<::blink::mojom::blink::Authenticator> receiver) {
    receiver_.Bind(std::move(receiver));
  }

  void WaitForCallToGet() {
    if (get_callback_) {
      return;
    }

    loop_->Run();
  }

  void InvokeGetCallback() {
    EXPECT_TRUE(receiver_.is_bound());
    std::move(get_callback_)
        .Run(blink::mojom::blink::AuthenticatorStatus::NOT_ALLOWED_ERROR,
             nullptr, nullptr);
  }

  void Reset() { loop_ = std::make_unique<base::RunLoop>(); }

 protected:
  void MakeCredential(
      blink::mojom::blink::PublicKeyCredentialCreationOptionsPtr options,
      MakeCredentialCallback callback) override {}
  void GetAssertion(
      blink::mojom::blink::PublicKeyCredentialRequestOptionsPtr options,
      GetAssertionCallback callback) override {
    get_callback_ = std::move(callback);
    loop_->Quit();
  }
  void IsUserVerifyingPlatformAuthenticatorAvailable(
      IsUserVerifyingPlatformAuthenticatorAvailableCallback callback) override {
  }
  void IsConditionalMediationAvailable(
      IsConditionalMediationAvailableCallback callback) override {}
  void Report(blink::mojom::blink::PublicKeyCredentialReportOptionsPtr options,
              ReportCallback callback) override {}
  void GetClientCapabilities(GetClientCapabilitiesCallback callback) override {}
  void Cancel() override {}

 private:
  mojo::Receiver<::blink::mojom::blink::Authenticator> receiver_{this};

  GetAssertionCallback get_callback_;
  std::unique_ptr<base::RunLoop> loop_;
};

class CredentialManagerTestingContext {
  STACK_ALLOCATED();

 public:
  explicit CredentialManagerTestingContext(
      MockCredentialManager* mock_credential_manager,
      MockAuthenticatorInterface* mock_authenticator = nullptr)
      : dummy_context_(KURL("https://example.test")) {
    if (mock_credential_manager) {
      DomWindow().GetBrowserInterfaceBroker().SetBinderForTesting(
          ::blink::mojom::blink::CredentialManager::Name_,
          WTF::BindRepeating(
              [](MockCredentialManager* mock_credential_manager,
                 mojo::ScopedMessagePipeHandle handle) {
                mock_credential_manager->Bind(
                    mojo::PendingReceiver<
                        ::blink::mojom::blink::CredentialManager>(
                        std::move(handle)));
              },
              WTF::Unretained(mock_credential_manager)));
    }
    if (mock_authenticator) {
      DomWindow().GetBrowserInterfaceBroker().SetBinderForTesting(
          ::blink::mojom::blink::Authenticator::Name_,
          WTF::BindRepeating(
              [](MockAuthenticatorInterface* mock_authenticator,
                 mojo::ScopedMessagePipeHandle handle) {
                mock_authenticator->Bind(
                    mojo::PendingReceiver<::blink::mojom::blink::Authenticator>(
                        std::move(handle)));
              },
              WTF::Unretained(mock_authenticator)));
    }
  }

  ~CredentialManagerTestingContext() {
    DomWindow().GetBrowserInterfaceBroker().SetBinderForTesting(
        ::blink::mojom::blink::CredentialManager::Name_, {});
    DomWindow().GetBrowserInterfaceBroker().SetBinderForTesting(
        ::blink::mojom::blink::Authenticator::Name_, {});
  }

  LocalDOMWindow& DomWindow() { return dummy_context_.GetWindow(); }
  ScriptState* GetScriptState() { return dummy_context_.GetScriptState(); }

 private:
  V8TestingScope dummy_context_;
};

}  // namespace

class MockPublicKeyCredential : public Credential {
 public:
  MockPublicKeyCredential() : Credential("test", "public-key") {}
  bool IsPublicKeyCredential() const override { return true; }
};

// The completion callbacks for pending mojom::CredentialManager calls each own
// a persistent handle to a ScriptPromiseResolverBase instance. Ensure that if
// the document is destroyed while a call is pending, it can still be freed up.
TEST(AuthenticationCredentialsContainerTest, PendingGetRequest_NoGCCycles) {
  test::TaskEnvironment task_environment;
  MockCredentialManager mock_credential_manager;
  GCObjectLivenessObserver<Document> document_observer;

  {
    CredentialManagerTestingContext context(&mock_credential_manager);
    document_observer.Observe(context.DomWindow().document());
    AuthenticationCredentialsContainer::credentials(*context.DomWindow().navigator())
        ->get(context.GetScriptState(), CredentialRequestOptions::Create(),
              IGNORE_EXCEPTION_FOR_TESTING);
    mock_credential_manager.WaitForCallToGet();
  }
  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(document_observer.WasCollected());

  mock_credential_manager.InvokeGetCallback();
  ASSERT_TRUE(mock_credential_manager.IsDisconnected());
}

// If the document is detached before the request is resolved, the promise
// should be left unresolved, and there should be no crashes.
TEST(AuthenticationCredentialsContainerTest,
     PendingGetRequest_NoCrashOnResponseAfterDocumentShutdown) {
  test::TaskEnvironment task_environment;
  MockCredentialManager mock_credential_manager;
  CredentialManagerTestingContext context(&mock_credential_manager);

  auto promise =
      AuthenticationCredentialsContainer::credentials(*context.DomWindow().navigator())
          ->get(context.GetScriptState(), CredentialRequestOptions::Create(),
                IGNORE_EXCEPTION_FOR_TESTING);
  mock_credential_manager.WaitForCallToGet();

  context.DomWindow().FrameDestroyed();

  mock_credential_manager.InvokeGetCallback();

  EXPECT_EQ(v8::Promise::kPending, promise.V8Promise()->State());
}

TEST(AuthenticationCredentialsContainerTest, RejectPublicKeyCredentialStoreOperation) {
  test::TaskEnvironment task_environment;
  MockCredentialManager mock_credential_manager;
  CredentialManagerTestingContext context(&mock_credential_manager);

  auto promise = AuthenticationCredentialsContainer::credentials(
                     *context.DomWindow().navigator())
                     ->store(context.GetScriptState(),
                             MakeGarbageCollected<MockPublicKeyCredential>(),
                             IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_EQ(v8::Promise::kRejected, promise.V8Promise()->State());
}

TEST(AuthenticationCredentialsContainerTest,
     GetPasswordAndFederatedCredentialUseCounters) {
  test::TaskEnvironment task_environment;
  {
    // Password only.
    MockCredentialManager mock_credential_manager;
    CredentialManagerTestingContext context(&mock_credential_manager);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetPasswordCredential);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential);
    auto* request_options = CredentialRequestOptions::Create();
    request_options->setPassword(true);
    AuthenticationCredentialsContainer::credentials(
        *context.DomWindow().navigator())
        ->get(context.GetScriptState(), request_options,
              IGNORE_EXCEPTION_FOR_TESTING);
    mock_credential_manager.WaitForCallToGet();
    EXPECT_TRUE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetPasswordCredential));
    EXPECT_FALSE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential));

    mock_credential_manager.InvokeGetCallback();
  }

  {
    // Federated only.
    MockCredentialManager mock_credential_manager;
    CredentialManagerTestingContext context(&mock_credential_manager);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetPasswordCredential);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential);
    auto* request_options = CredentialRequestOptions::Create();
    auto* federated_cred_options = FederatedCredentialRequestOptions::Create();
    federated_cred_options->setProviders({"idp.example"});
    request_options->setFederated(federated_cred_options);
    AuthenticationCredentialsContainer::credentials(
        *context.DomWindow().navigator())
        ->get(context.GetScriptState(), request_options,
              IGNORE_EXCEPTION_FOR_TESTING);
    mock_credential_manager.WaitForCallToGet();
    EXPECT_FALSE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetPasswordCredential));
    EXPECT_TRUE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential));

    mock_credential_manager.InvokeGetCallback();
  }

  {
    // Federated and Password.
    MockCredentialManager mock_credential_manager;
    CredentialManagerTestingContext context(&mock_credential_manager);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetPasswordCredential);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential);
    auto* request_options = CredentialRequestOptions::Create();
    auto* federated_cred_options = FederatedCredentialRequestOptions::Create();
    federated_cred_options->setProviders({"idp.example"});
    request_options->setFederated(federated_cred_options);
    request_options->setPassword(true);
    AuthenticationCredentialsContainer::credentials(
        *context.DomWindow().navigator())
        ->get(context.GetScriptState(), request_options,
              IGNORE_EXCEPTION_FOR_TESTING);
    mock_credential_manager.WaitForCallToGet();
    EXPECT_TRUE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetPasswordCredential));
    EXPECT_TRUE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential));

    mock_credential_manager.InvokeGetCallback();
  }

  {
    // Federated and Password but empty federated providers.
    MockCredentialManager mock_credential_manager;
    CredentialManagerTestingContext context(&mock_credential_manager);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetPasswordCredential);
    context.DomWindow().document()->ClearUseCounterForTesting(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential);
    auto* request_options = CredentialRequestOptions::Create();
    auto* federated_cred_options = FederatedCredentialRequestOptions::Create();
    federated_cred_options->setProviders({});
    request_options->setFederated(federated_cred_options);
    request_options->setPassword(true);
    AuthenticationCredentialsContainer::credentials(
        *context.DomWindow().navigator())
        ->get(context.GetScriptState(), request_options,
              IGNORE_EXCEPTION_FOR_TESTING);
    mock_credential_manager.WaitForCallToGet();
    EXPECT_TRUE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetPasswordCredential));
    EXPECT_FALSE(context.DomWindow().document()->IsUseCounted(
        WebFeature::kCredentialManagerGetLegacyFederatedCredential));

    mock_credential_manager.InvokeGetCallback();
  }
}

TEST(AuthenticationCredentialsContainerTest, PublicKeyConditionalMediationUkm) {
  test::TaskEnvironment task_environment;

  MockAuthenticatorInterface mock_authenticator;
  CredentialManagerTestingContext context(/*mock_credential_manager=*/nullptr,
                                          &mock_authenticator);

  ukm::TestAutoSetUkmRecorder recorder;
  context.DomWindow().document()->View()->ResetUkmAggregatorForTesting();

  auto* request_options = CredentialRequestOptions::Create();
  request_options->setMediation("conditional");
  auto* public_key_request_options =
      PublicKeyCredentialRequestOptions::Create();
  public_key_request_options->setTimeout(10000);
  public_key_request_options->setRpId("https://www.example.com");
  public_key_request_options->setUserVerification("preferred");
  const Vector<uint8_t> challenge = {1, 2, 3, 4};
  public_key_request_options->setChallenge(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
          DOMArrayBuffer::Create(challenge)));
  request_options->setPublicKey(public_key_request_options);

  auto promise = AuthenticationCredentialsContainer::credentials(
                     *context.DomWindow().navigator())
                     ->get(context.GetScriptState(), request_options,
                           IGNORE_EXCEPTION_FOR_TESTING);
  mock_authenticator.WaitForCallToGet();

  auto entries = recorder.GetEntriesByName("WebAuthn.ConditionalUiGetCall");
  ASSERT_EQ(entries.size(), 1u);

  mock_authenticator.InvokeGetCallback();
  mock_authenticator.Reset();

  // Verify that a second request does not get reported.
  promise = AuthenticationCredentialsContainer::credentials(
                *context.DomWindow().navigator())
                ->get(context.GetScriptState(), request_options,
                      IGNORE_EXCEPTION_FOR_TESTING);
  mock_authenticator.WaitForCallToGet();

  entries = recorder.GetEntriesByName("WebAuthn.ConditionalUiGetCall");
  ASSERT_EQ(entries.size(), 1u);

  mock_authenticator.InvokeGetCallback();
}

class AuthenticationCredentialsContainerActiveModeMultiIdpTest
    : public testing::Test,
      private ScopedFedCmMultipleIdentityProvidersForTest,
      ScopedFedCmButtonModeForTest {
 protected:
  AuthenticationCredentialsContainerActiveModeMultiIdpTest()
      : ScopedFedCmMultipleIdentityProvidersForTest(true),
        ScopedFedCmButtonModeForTest(true) {}
};

TEST_F(AuthenticationCredentialsContainerActiveModeMultiIdpTest,
       RejectActiveModeWithMultipleIdps) {
  test::TaskEnvironment task_environment;
  MockCredentialManager mock_credential_manager;
  CredentialManagerTestingContext context(&mock_credential_manager);

  CredentialRequestOptions* options = CredentialRequestOptions::Create();
  IdentityCredentialRequestOptions* identity =
      IdentityCredentialRequestOptions::Create();

  auto* idp1 = IdentityProviderRequestOptions::Create();
  idp1->setConfigURL("https://idp1.example/config.json");
  idp1->setClientId("clientId");

  auto* idp2 = IdentityProviderRequestOptions::Create();
  idp2->setConfigURL("https://idp2.example/config.json");
  idp2->setClientId("clientId");

  identity->setProviders({idp1, idp2});
  identity->setMode("active");
  options->setIdentity(identity);

  auto promise = AuthenticationCredentialsContainer::credentials(
                     *context.DomWindow().navigator())
                     ->get(context.GetScriptState(), options,
                           IGNORE_EXCEPTION_FOR_TESTING);

  task_environment.RunUntilIdle();

  EXPECT_EQ(v8::Promise::kRejected, promise.V8Promise()->State());
}

}  // namespace blink

"""

```