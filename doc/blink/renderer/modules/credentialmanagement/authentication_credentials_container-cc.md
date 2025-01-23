Response:
The user wants a summary of the functionality of the provided C++ source code file.
I need to identify the main purpose of the file and its key features based on the included headers, namespaces, and the structure of the code.

The file `authentication_credentials_container.cc` seems to be responsible for implementing the JavaScript `navigator.credentials` API in the Blink rendering engine. It handles operations like creating, getting, and storing credentials of various types (Password, Federated, PublicKey, Identity, OTP).

Here's a breakdown of the steps to achieve the user's request:

1. **Identify Core Functionality:** Look for the primary classes and methods implemented in the file. The name of the file itself (`AuthenticationCredentialsContainer`) strongly suggests it manages credentials.
2. **Analyze Included Headers:** The included headers reveal the types of credentials and related functionalities the file deals with (e.g., `password_credential.h`, `federated_credential.h`, `public_key_credential.h`, `webotp_constants.h`). They also point to interactions with JavaScript (`bindings/core/v8/*`, `bindings/modules/v8/*`).
3. **Examine Namespaces:** The `blink` namespace confirms this is part of the Blink rendering engine. The nested anonymous namespace contains helper functions for security checks and callbacks, which are crucial for the credential management API.
4. **Look for Key Methods:**  While the code snippet doesn't show the actual method implementations, the presence of callbacks like `OnRequestToken`, `OnStoreComplete`, `OnGetComplete`, and `OnMakePublicKeyCredentialComplete` strongly indicates the file handles asynchronous operations related to credential management.
5. **Infer Relationships with Web Technologies:** Based on the included headers and the names of the methods and types, deduce the interaction with JavaScript (via the V8 bindings), HTML (as it's part of the browser's rendering engine), and potentially CSS (indirectly, as credential management can influence UI).
6. **Consider Security Aspects:** The presence of functions like `CheckSecurityRequirementsBeforeRequest` and `AssertSecurityRequirementsBeforeResponse` highlights the importance of security in this API.
7. **Formulate a Summary:** Combine the observations from the previous steps to create a concise summary of the file's functionality.
```
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/authentication_credentials_container.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/sms/webotp_constants.h"
#include "third_party/blink/public/mojom/credentialmanagement/credential_manager.mojom-blink.h"
#include "third_party/blink/public/mojom/credentialmanagement/credential_type_flags.mojom-blink.h"
#include "third_party/blink/public/mojom/payments/payment_credential.mojom-blink.h"
#include "third_party/blink/public/mojom/sms/webotp_service.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_all_accepted_credentials_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_large_blob_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_large_blob_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_payment_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_values.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_supplemental_pub_keys_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_supplemental_pub_keys_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authenticator_selection_criteria.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_properties_output.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_current_user_details_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_federated_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_otp_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_user_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_htmlformelement_passwordcredentialdata.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/scoped_abort_state.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/credentialmanagement/authenticator_assertion_response.h"
#include "third_party/blink/renderer/modules/credentialmanagement/authenticator_attestation_response.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_proxy.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_type_converters.h"  // IWYU pragma: keep
#include "third_party/blink/renderer/modules/credentialmanagement/credential_metrics.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_utils.h"
#include "third_party/blink/renderer/modules/credentialmanagement/digital_identity_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/federated_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential_error.h"
#include "third_party/blink/renderer/modules/credentialmanagement/otp_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/password_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/public_key_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/scoped_promise_resolver.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#endif

namespace blink {

namespace {

using mojom::blink::AttestationConveyancePreference;
using mojom::blink::AuthenticationExtensionsClientOutputsPtr;
using mojom::blink::AuthenticatorAttachment;
using mojom::blink::AuthenticatorStatus;
using mojom::blink::CredentialInfo;
using mojom::blink::CredentialInfoPtr;
using mojom::blink::CredentialManagerError;
using mojom::blink::CredentialMediationRequirement;
using mojom::blink::PaymentCredentialInstrument;
using mojom::blink::WebAuthnDOMExceptionDetailsPtr;
using MojoPublicKeyCredentialCreationOptions =
    mojom::blink::PublicKeyCredentialCreationOptions;
using mojom::blink::MakeCredentialAuthenticatorResponsePtr;
using MojoPublicKeyCredentialRequestOptions =
    mojom::blink::PublicKeyCredentialRequestOptions;
using mojom::blink::GetAssertionAuthenticatorResponsePtr;
using mojom::blink::RequestTokenStatus;
using payments::mojom::blink::PaymentCredentialStorageStatus;

constexpr size_t kMaxLargeBlobSize = 2048;  // 2kb.

// RequiredOriginType enumerates the requirements on the environment to perform
// an operation.
enum class RequiredOriginType {
  // Must be a secure origin.
  kSecure,
  // Must be a secure origin and be same-origin with all ancestor frames.
  kSecureAndSameWithAncestors,
  // Must be a secure origin and the "publickey-credentials-get" permissions
  // policy must be enabled. By default "publickey-credentials-get" is not
  // inherited by cross-origin child frames, so if that policy is not
  // explicitly enabled, behavior is the same as that of
  // |kSecureAndSameWithAncestors|. Note that permissions policies can be
  // expressed in various ways, e.g.: |allow| iframe attribute and/or
  // permissions-policy header, and may be inherited from parent browsing
  // contexts. See Permissions Policy spec.
  kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy,
  // Must be a secure origin and the "publickey-credentials-create" permissions
  // policy must be enabled. By default "publickey-credentials-create" is not
  // inherited by cross-origin child frames, so if that policy is not
  // explicitly enabled, behavior is the same as that of
  // |kSecureAndSameWithAncestors|. Note that permissions policies can be
  // expressed in various ways, e.g.: |allow| iframe attribute and/or
  // permissions-policy header, and may be inherited from parent browsing
  // contexts. See Permissions Policy spec.
  kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy,
  // Similar to the enum above, checks the "otp-credentials" permissions policy.
  kSecureAndPermittedByWebOTPAssertionPermissionsPolicy,
  // Similar to the enum above, checks the "identity-credentials-get"
  // permissions policy.
  kSecureAndPermittedByFederatedPermissionsPolicy,
  // Must be a secure origin with either the "payment" or
  // "publickey-credentials-create" permission policy.
  kSecureWithPaymentOrCreateCredentialPermissionPolicy,
};

// Returns whether the number of unique origins in the ancestor chain, including
// the current origin are less or equal to |max_unique_origins|.
//
// Examples:
// A.com = 1 unique origin
// A.com -> A.com = 1 unique origin
// A.com -> A.com -> B.com = 2 unique origins
// A.com -> B.com -> B.com = 2 unique origins
// A.com -> B.com -> A.com = 3 unique origins
bool AreUniqueOriginsLessOrEqualTo(const Frame* frame, int max_unique_origins) {
  const SecurityOrigin* current_origin =
      frame->GetSecurityContext()->GetSecurityOrigin();
  int num_unique_origins = 1;

  const Frame* parent = frame->Tree().Parent();
  while (parent) {
    auto* parent_origin = parent->GetSecurityContext()->GetSecurityOrigin();
    if (!parent_origin->IsSameOriginWith(current_origin)) {
      ++num_unique_origins;
      current_origin = parent_origin;
    }
    if (num_unique_origins > max_unique_origins) {
      return false;
    }
    parent = parent->Tree().Parent();
  }
  return true;
}

const SecurityOrigin* GetSecurityOrigin(const Frame* frame) {
  const SecurityContext* frame_security_context = frame->GetSecurityContext();
  if (!frame_security_context) {
    return nullptr;
  }
  return frame_security_context->GetSecurityOrigin();
}

bool IsSameSecurityOriginWithAncestors(const Frame* frame) {
  const Frame* current = frame;
  const SecurityOrigin* frame_origin = GetSecurityOrigin(frame);
  if (!frame_origin) {
    return false;
  }

  while (current->Tree().Parent()) {
    current = current->Tree().Parent();
    const SecurityOrigin* current_security_origin = GetSecurityOrigin(current);
    if (!current_security_origin ||
        !frame_origin->IsSameOriginWith(current_security_origin)) {
      return false;
    }
  }
  return true;
}

bool IsAncestorChainValidForWebOTP(const Frame* frame) {
  return AreUniqueOriginsLessOrEqualTo(
      frame, kMaxUniqueOriginInAncestorChainForWebOTP);
}

bool CheckSecurityRequirementsBeforeRequest(
    ScriptPromiseResolverBase* resolver,
    RequiredOriginType required_origin_type) {
  if (!CheckGenericSecurityRequirementsForCredentialsContainerRequest(
          resolver)) {
    return false;
  }

  switch (required_origin_type) {
    case RequiredOriginType::kSecure:
      // This has already been checked.
      break;

    case RequiredOriginType::kSecureAndSameWithAncestors:
      if (!IsSameSecurityOriginWithAncestors(
              To<LocalDOMWindow>(resolver->GetExecutionContext())
                  ->GetFrame())) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The following credential operations can only occur in a document "
            "which is same-origin with all of its ancestors: storage/retrieval "
            "of 'PasswordCredential' and 'FederatedCredential', storage of "
            "'PublicKeyCredential'."));
        return false;
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy:
      // The 'publickey-credentials-get' feature's "default allowlist" is
      // "self", which means the webauthn feature is allowed by default in
      // same-origin child browsing contexts.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsGet)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'publickey-credentials-get' feature is not enabled in this "
            "document. Permissions Policy may be used to delegate Web "
            "Authentication capabilities to cross-origin child frames."));
        return false;
      } else if (!IsSameSecurityOriginWithAncestors(
                     To<LocalDOMWindow>(resolver->GetExecutionContext())
                         ->GetFrame())) {
        UseCounter::Count(
            resolver->GetExecutionContext(),
            WebFeature::kCredentialManagerCrossOriginPublicKeyGetRequest);
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy:
      // The 'publickey-credentials-create' feature's "default allowlist" is
      // "self", which means the webauthn feature is allowed by default in
      // same-origin child browsing contexts.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsCreate)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'publickey-credentials-create' feature is not enabled in this "
            "document. Permissions Policy may be used to delegate Web "
            "Authentication capabilities to cross-origin child frames."));
        return false;
      } else if (!IsSameSecurityOriginWithAncestors(
                     To<LocalDOMWindow>(resolver->GetExecutionContext())
                         ->GetFrame())) {
        UseCounter::Count(
            resolver->GetExecutionContext(),
            WebFeature::kCredentialManagerCrossOriginPublicKeyCreateRequest);
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebOTPAssertionPermissionsPolicy:
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kOTPCredentials)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'otp-credentials' feature is not enabled in this document."));
        return false;
      }
      if (!IsAncestorChainValidForWebOTP(
              To<LocalDOMWindow>(resolver->GetExecutionContext())
                  ->GetFrame())) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "More than two unique origins are detected in the origin chain."));
        return false;
      }
      break;
    case RequiredOriginType::kSecureAndPermittedByFederatedPermissionsPolicy:
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kIdentityCredentialsGet)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'identity-credentials-get' feature is not enabled in this "
            "document."));
        return false;
      }
      break;

    case RequiredOriginType::
        kSecureWithPaymentOrCreateCredentialPermissionPolicy:
      // For backwards compatibility, SPC credentials (that is, credentials with
      // the "payment" extension set) can be created in a cross-origin iframe
      // with either the 'payment' or 'publickey-credentials-create' permission
      // set.
      //
      // Note that SPC only goes through the credentials API for creation and
      // not authentication. Authentication flows via the Payment Request API,
      // which checks for the 'payment' permission separately.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kPayment) &&
          !resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsCreate)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "The 'payment' or 'publickey-credentials-create' features are not "
            "enabled in this document. Permissions Policy may be used to "
            "delegate Web Payment capabilities to cross-origin child frames."));
        return false;
      }
      break;
  }

  return true;
}

void AssertSecurityRequirementsBeforeResponse(
    ScriptPromiseResolverBase* resolver,
    RequiredOriginType require_origin) {
  // The |resolver| will blanket ignore Reject/Resolve calls if the context is
  // gone -- nevertheless, call Reject() to be on the safe side.
  if (!resolver->GetExecutionContext()) {
    resolver->Reject();
    return;
  }

  SECURITY_CHECK(To<LocalDOMWindow>(resolver->GetExecutionContext()));
  SECURITY_CHECK(resolver->GetExecutionContext()->IsSecureContext());
  switch (require_origin) {
    case RequiredOriginType::kSecure:
      // This has already been checked.
      break;

    case RequiredOriginType::kSecureAndSameWithAncestors:
      SECURITY_CHECK(IsSameSecurityOriginWithAncestors(
          To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame()));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kPublicKeyCredentialsGet));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kPublicKeyCredentialsCreate));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebOTPAssertionPermissionsPolicy:
      SECURITY_CHECK(
          resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kOTPCredentials) &&
          IsAncestorChainValidForWebOTP(
              To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame()));
      break;

    case RequiredOriginType::kSecureAndPermittedByFederatedPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kIdentityCredentialsGet));
      break;

    case RequiredOriginType::
        kSecureWithPaymentOrCreateCredentialPermissionPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
                         mojom::blink::PermissionsPolicyFeature::kPayment) ||
                     resolver->GetExecutionContext()->IsFeatureEnabled(
                         mojom::blink::PermissionsPolicyFeature::
                             kPublicKeyCredentialsCreate));
      break;
  }
}

// Checks if the icon URL is an a-priori authenticated URL.
// https://w3c.github.io/webappsec-credential-management/#dom-credentialuserdata-iconurl
bool IsIconURLNullOrSecure(const KURL& url) {
  if (url.IsNull()) {
    return true;
  }

  if (!url.IsValid()) {
    return false;
  }

  return network::IsUrlPotentiallyTrustworthy(GURL(url));
}

// Checks if the size of the supplied ArrayBuffer or ArrayBufferView is at most
// the maximum size allowed.
bool IsArrayBufferOrViewBelowSizeLimit(
    const V8UnionArrayBufferOrArrayBufferView* buffer_or_view) {
  if (!buffer_or_view) {
    return true;
  }
  return base::CheckedNumeric<wtf_size_t>(
             DOMArrayPiece(buffer_or_view).ByteLength())
      .IsValid();
}

bool IsCredentialDescriptorListBelowSizeLimit(
    const HeapVector<Member<PublicKeyCredentialDescriptor>>& list) {
  return list.size() <= mojom::blink::kPublicKeyCredentialDescriptorListMaxSize;
}

DOMException* CredentialManagerErrorToDOMException(
    CredentialManagerError reason) {
  switch (reason) {
    case CredentialManagerError::PENDING_REQUEST:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "A request is already pending.");
    case CredentialManagerError::PASSWORD_STORE_UNAVAILABLE:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The password store is unavailable.");
    case CredentialManagerError::UNKNOWN:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotReadableError,
          "An unknown error occurred while talking "
          "to the credential manager.");
    case CredentialManagerError::SUCCESS:
      NOTREACHED();
  }
  return nullptr;
}

// Abort an ongoing IdentityCredential request. This will only be called before
// the request finishes due to `scoped_abort_state`.
void AbortIdentityCredentialRequest(ScriptState* script_state) {
  if (!script_state->ContextIsValid()) {
    return;
  }

  auto* auth_request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  auth_request->CancelTokenRequest();
}

void OnRequestToken(std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
                    std::unique_ptr<ScopedAbortState> scoped_abort_state,
                    const CredentialRequestOptions* options,
                    RequestTokenStatus status,
                    const std::optional<KURL>& selected_idp_config_url,
                    const WTF::String& token,
                    mojom::blink::TokenErrorPtr error,
                    bool is_auto_selected) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();
  switch (status) {
    case RequestTokenStatus::kErrorTooManyRequests: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "Only one navigator.credentials.get request may be outstanding at "
          "one time."));
      return;
    }
    case RequestTokenStatus::kErrorCanceled: {
      AbortSignal* signal =
          scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
      if (signal && signal->aborted()) {
        auto* script_state = resolver->GetScriptState();
        ScriptState::Scope script_state_scope(script_state);
        resolver->Reject(signal->reason(script_state));
      } else {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kAbortError, "The request has been aborted."));
      }
      return;
    }
    case RequestTokenStatus::kError: {
      if (!RuntimeEnabledFeatures::FedCmErrorEnabled() || !error) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNetworkError, "Error retrieving a token."));
        return;
      }
      resolver->Reject(MakeGarbageCollected<IdentityCredentialError>(
          "Error retrieving a token.", error->code, error->url));
      return;
    }
    case RequestTokenStatus::kSuccess: {
      CHECK(selected_idp_config_url);
      IdentityCredential* credential = IdentityCredential::Create(
          token, is_auto_selected, *selected_idp_config_url);
      resolver->Resolve(credential);
      return;
    }
    default: {
      NOTREACHED();
    }
  }
}

void OnStoreComplete(std::unique_ptr<ScopedPromiseResolver> scoped_resolver) {
  auto* resolver = scoped_resolver->Release()->DowncastTo<Credential>();
  AssertSecurityRequirementsBeforeResponse(
      resolver, RequiredOriginType::kSecureAndSameWithAncestors);
  resolver->Resolve();
}

void OnPreventSilentAccessComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver) {
  auto* resolver = scoped_resolver->Release()->DowncastTo<IDLUndefined>();
  const auto required_origin_type = RequiredOriginType::kSecure;
  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);

  resolver->Resolve();
}

void OnGetComplete(std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
                   RequiredOriginType required_origin_type,
                   CredentialManagerError error,
                   CredentialInfoPtr credential_info) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();

  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);
  if (error != CredentialManagerError::SUCCESS) {
    DCHECK(!credential_info);
    resolver->Reject(CredentialManagerErrorToDOMException(error));
    return;
  }
  DCHECK(credential_info);
  UseCounter::Count(resolver->GetExecutionContext(),
                    WebFeature::kCredentialManagerGetReturnedCredential);
  resolver->Resolve(mojo::ConvertTo<Credential*>(std::move(credential_info)));
}

DOMArrayBuffer* VectorToDOMArrayBuffer(const Vector<uint8_t> buffer) {
  return DOMArrayBuffer::Create(buffer);
}

AuthenticationExtensionsPRFValues* GetPRFExtensionResults(
    const mojom::blink::PRFValuesPtr& prf_results) {
  auto* values = AuthenticationExtensionsPRFValues::Create();
  values->setFirst(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      VectorToDOMArrayBuffer(std::move(prf_results->first))));
  if (prf_results->second) {
    values->setSecond(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
        VectorToDOMArrayBuffer(std::move(prf_results->second.value()))));
  }
  return values;
}

void OnMakePublicKeyCredentialComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    RequiredOriginType required_origin_type,
    bool is_rk_required,
    AuthenticatorStatus status,
    MakeCredentialAuthenticatorResponsePtr credential,
    WebAuthnDOMExceptionDetailsPtr dom_exception_details) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();
  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);
  if (status != AuthenticatorStatus::SUCCESS) {
    DCHECK(!credential);
    AbortSignal* signal =
        scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
    if (signal && signal->aborted()) {
      auto* script_state = resolver->GetScriptState();
      ScriptState::Scope script_state_scope(script_state);
      resolver->Reject(signal->reason(script_state));
    } else {
      resolver->Reject(
          AuthenticatorStatusToDOMException(status, dom_exception_details));
    }
    return;
  }
  DCHECK(credential);
  DCHECK(!credential->info->client_data_json.empty());
  DCHECK(!credential->attestation_object.empty());
  UseCounter::Count(
      resolver->GetExecutionContext(),
      WebFeature::kCredentialManagerMakePublicKeyCredentialSuccess);
  if (is_rk_required) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kWebAuthnRkRequiredCreationSuccess);
  }
  DOMArrayBuffer* client_data_buffer =
      VectorToDOMArrayBuffer(std::move(credential->info->client_data_json));
  DOMArrayBuffer* raw_id =
      VectorToDOMArrayBuffer(std::move(credential->info->raw_id));
  DOMArrayBuffer* attestation_buffer =
      VectorToDOMArrayBuffer(std::move(credential->attestation_object));
  DOMArrayBuffer* authenticator_data =
      VectorToDOMArrayBuffer(std::move(credential->info->authenticator_data));
  DOMArrayBuffer* public_key_der = nullptr;
  if (credential->public_key_der) {
    public_key_der =
        VectorToDOMArrayBuffer(std::move(credential->public_key_der.value()));
  }
  auto* authenticator_response =
      MakeGarbageCollected<AuthenticatorAttestationResponse>(
          client_data_buffer, attestation_buffer, credential->transports,
          authenticator_data, public_key_der, credential->public_key_algo);

  AuthenticationExtensionsClientOutputs* extension_outputs =
      AuthenticationExtensionsClientOutputs::Create();
  if (credential->echo_hmac_create_secret) {
    extension_outputs->setHmacCreateSecret(credential->hmac_create_secret);
  }
  if (credential->echo_cred_props) {
    CredentialPropertiesOutput* cred_props_output =
        CredentialPropertiesOutput::Create();
    if (credential->has_cred_props_rk) {
      cred_props_output->setRk
### 提示词
```
这是目录为blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/credentialmanagement/authentication_credentials_container.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/sms/webotp_constants.h"
#include "third_party/blink/public/mojom/credentialmanagement/credential_manager.mojom-blink.h"
#include "third_party/blink/public/mojom/credentialmanagement/credential_type_flags.mojom-blink.h"
#include "third_party/blink/public/mojom/payments/payment_credential.mojom-blink.h"
#include "third_party/blink/public/mojom/sms/webotp_service.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_all_accepted_credentials_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_client_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_large_blob_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_large_blob_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_payment_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_prf_values.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_supplemental_pub_keys_inputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authentication_extensions_supplemental_pub_keys_outputs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_authenticator_selection_criteria.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_properties_output.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_current_user_details_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_federated_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_identity_provider_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_otp_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_request_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_user_entity.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_htmlformelement_passwordcredentialdata.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/scoped_abort_state.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/credentialmanagement/authenticator_assertion_response.h"
#include "third_party/blink/renderer/modules/credentialmanagement/authenticator_attestation_response.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_proxy.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_manager_type_converters.h"  // IWYU pragma: keep
#include "third_party/blink/renderer/modules/credentialmanagement/credential_metrics.h"
#include "third_party/blink/renderer/modules/credentialmanagement/credential_utils.h"
#include "third_party/blink/renderer/modules/credentialmanagement/digital_identity_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/federated_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/identity_credential_error.h"
#include "third_party/blink/renderer/modules/credentialmanagement/otp_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/password_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/public_key_credential.h"
#include "third_party/blink/renderer/modules/credentialmanagement/scoped_promise_resolver.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/bindings/modules/v8/v8_public_key_credential_rp_entity.h"
#endif

namespace blink {

namespace {

using mojom::blink::AttestationConveyancePreference;
using mojom::blink::AuthenticationExtensionsClientOutputsPtr;
using mojom::blink::AuthenticatorAttachment;
using mojom::blink::AuthenticatorStatus;
using mojom::blink::CredentialInfo;
using mojom::blink::CredentialInfoPtr;
using mojom::blink::CredentialManagerError;
using mojom::blink::CredentialMediationRequirement;
using mojom::blink::PaymentCredentialInstrument;
using mojom::blink::WebAuthnDOMExceptionDetailsPtr;
using MojoPublicKeyCredentialCreationOptions =
    mojom::blink::PublicKeyCredentialCreationOptions;
using mojom::blink::MakeCredentialAuthenticatorResponsePtr;
using MojoPublicKeyCredentialRequestOptions =
    mojom::blink::PublicKeyCredentialRequestOptions;
using mojom::blink::GetAssertionAuthenticatorResponsePtr;
using mojom::blink::RequestTokenStatus;
using payments::mojom::blink::PaymentCredentialStorageStatus;

constexpr size_t kMaxLargeBlobSize = 2048;  // 2kb.

// RequiredOriginType enumerates the requirements on the environment to perform
// an operation.
enum class RequiredOriginType {
  // Must be a secure origin.
  kSecure,
  // Must be a secure origin and be same-origin with all ancestor frames.
  kSecureAndSameWithAncestors,
  // Must be a secure origin and the "publickey-credentials-get" permissions
  // policy must be enabled. By default "publickey-credentials-get" is not
  // inherited by cross-origin child frames, so if that policy is not
  // explicitly enabled, behavior is the same as that of
  // |kSecureAndSameWithAncestors|. Note that permissions policies can be
  // expressed in various ways, e.g.: |allow| iframe attribute and/or
  // permissions-policy header, and may be inherited from parent browsing
  // contexts. See Permissions Policy spec.
  kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy,
  // Must be a secure origin and the "publickey-credentials-create" permissions
  // policy must be enabled. By default "publickey-credentials-create" is not
  // inherited by cross-origin child frames, so if that policy is not
  // explicitly enabled, behavior is the same as that of
  // |kSecureAndSameWithAncestors|. Note that permissions policies can be
  // expressed in various ways, e.g.: |allow| iframe attribute and/or
  // permissions-policy header, and may be inherited from parent browsing
  // contexts. See Permissions Policy spec.
  kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy,
  // Similar to the enum above, checks the "otp-credentials" permissions policy.
  kSecureAndPermittedByWebOTPAssertionPermissionsPolicy,
  // Similar to the enum above, checks the "identity-credentials-get"
  // permissions policy.
  kSecureAndPermittedByFederatedPermissionsPolicy,
  // Must be a secure origin with either the "payment" or
  // "publickey-credentials-create" permission policy.
  kSecureWithPaymentOrCreateCredentialPermissionPolicy,
};

// Returns whether the number of unique origins in the ancestor chain, including
// the current origin are less or equal to |max_unique_origins|.
//
// Examples:
// A.com = 1 unique origin
// A.com -> A.com = 1 unique origin
// A.com -> A.com -> B.com = 2 unique origins
// A.com -> B.com -> B.com = 2 unique origins
// A.com -> B.com -> A.com = 3 unique origins
bool AreUniqueOriginsLessOrEqualTo(const Frame* frame, int max_unique_origins) {
  const SecurityOrigin* current_origin =
      frame->GetSecurityContext()->GetSecurityOrigin();
  int num_unique_origins = 1;

  const Frame* parent = frame->Tree().Parent();
  while (parent) {
    auto* parent_origin = parent->GetSecurityContext()->GetSecurityOrigin();
    if (!parent_origin->IsSameOriginWith(current_origin)) {
      ++num_unique_origins;
      current_origin = parent_origin;
    }
    if (num_unique_origins > max_unique_origins) {
      return false;
    }
    parent = parent->Tree().Parent();
  }
  return true;
}

const SecurityOrigin* GetSecurityOrigin(const Frame* frame) {
  const SecurityContext* frame_security_context = frame->GetSecurityContext();
  if (!frame_security_context) {
    return nullptr;
  }
  return frame_security_context->GetSecurityOrigin();
}

bool IsSameSecurityOriginWithAncestors(const Frame* frame) {
  const Frame* current = frame;
  const SecurityOrigin* frame_origin = GetSecurityOrigin(frame);
  if (!frame_origin) {
    return false;
  }

  while (current->Tree().Parent()) {
    current = current->Tree().Parent();
    const SecurityOrigin* current_security_origin = GetSecurityOrigin(current);
    if (!current_security_origin ||
        !frame_origin->IsSameOriginWith(current_security_origin)) {
      return false;
    }
  }
  return true;
}

bool IsAncestorChainValidForWebOTP(const Frame* frame) {
  return AreUniqueOriginsLessOrEqualTo(
      frame, kMaxUniqueOriginInAncestorChainForWebOTP);
}

bool CheckSecurityRequirementsBeforeRequest(
    ScriptPromiseResolverBase* resolver,
    RequiredOriginType required_origin_type) {
  if (!CheckGenericSecurityRequirementsForCredentialsContainerRequest(
          resolver)) {
    return false;
  }

  switch (required_origin_type) {
    case RequiredOriginType::kSecure:
      // This has already been checked.
      break;

    case RequiredOriginType::kSecureAndSameWithAncestors:
      if (!IsSameSecurityOriginWithAncestors(
              To<LocalDOMWindow>(resolver->GetExecutionContext())
                  ->GetFrame())) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The following credential operations can only occur in a document "
            "which is same-origin with all of its ancestors: storage/retrieval "
            "of 'PasswordCredential' and 'FederatedCredential', storage of "
            "'PublicKeyCredential'."));
        return false;
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy:
      // The 'publickey-credentials-get' feature's "default allowlist" is
      // "self", which means the webauthn feature is allowed by default in
      // same-origin child browsing contexts.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsGet)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'publickey-credentials-get' feature is not enabled in this "
            "document. Permissions Policy may be used to delegate Web "
            "Authentication capabilities to cross-origin child frames."));
        return false;
      } else if (!IsSameSecurityOriginWithAncestors(
                     To<LocalDOMWindow>(resolver->GetExecutionContext())
                         ->GetFrame())) {
        UseCounter::Count(
            resolver->GetExecutionContext(),
            WebFeature::kCredentialManagerCrossOriginPublicKeyGetRequest);
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy:
      // The 'publickey-credentials-create' feature's "default allowlist" is
      // "self", which means the webauthn feature is allowed by default in
      // same-origin child browsing contexts.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsCreate)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'publickey-credentials-create' feature is not enabled in this "
            "document. Permissions Policy may be used to delegate Web "
            "Authentication capabilities to cross-origin child frames."));
        return false;
      } else if (!IsSameSecurityOriginWithAncestors(
                     To<LocalDOMWindow>(resolver->GetExecutionContext())
                         ->GetFrame())) {
        UseCounter::Count(
            resolver->GetExecutionContext(),
            WebFeature::kCredentialManagerCrossOriginPublicKeyCreateRequest);
      }
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebOTPAssertionPermissionsPolicy:
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kOTPCredentials)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'otp-credentials' feature is not enabled in this document."));
        return false;
      }
      if (!IsAncestorChainValidForWebOTP(
              To<LocalDOMWindow>(resolver->GetExecutionContext())
                  ->GetFrame())) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "More than two unique origins are detected in the origin chain."));
        return false;
      }
      break;
    case RequiredOriginType::kSecureAndPermittedByFederatedPermissionsPolicy:
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kIdentityCredentialsGet)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "The 'identity-credentials-get' feature is not enabled in this "
            "document."));
        return false;
      }
      break;

    case RequiredOriginType::
        kSecureWithPaymentOrCreateCredentialPermissionPolicy:
      // For backwards compatibility, SPC credentials (that is, credentials with
      // the "payment" extension set) can be created in a cross-origin iframe
      // with either the 'payment' or 'publickey-credentials-create' permission
      // set.
      //
      // Note that SPC only goes through the credentials API for creation and
      // not authentication. Authentication flows via the Payment Request API,
      // which checks for the 'payment' permission separately.
      if (!resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kPayment) &&
          !resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::
                  kPublicKeyCredentialsCreate)) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotSupportedError,
            "The 'payment' or 'publickey-credentials-create' features are not "
            "enabled in this document. Permissions Policy may be used to "
            "delegate Web Payment capabilities to cross-origin child frames."));
        return false;
      }
      break;
  }

  return true;
}

void AssertSecurityRequirementsBeforeResponse(
    ScriptPromiseResolverBase* resolver,
    RequiredOriginType require_origin) {
  // The |resolver| will blanket ignore Reject/Resolve calls if the context is
  // gone -- nevertheless, call Reject() to be on the safe side.
  if (!resolver->GetExecutionContext()) {
    resolver->Reject();
    return;
  }

  SECURITY_CHECK(To<LocalDOMWindow>(resolver->GetExecutionContext()));
  SECURITY_CHECK(resolver->GetExecutionContext()->IsSecureContext());
  switch (require_origin) {
    case RequiredOriginType::kSecure:
      // This has already been checked.
      break;

    case RequiredOriginType::kSecureAndSameWithAncestors:
      SECURITY_CHECK(IsSameSecurityOriginWithAncestors(
          To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame()));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthGetAssertionPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kPublicKeyCredentialsGet));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebAuthCreateCredentialPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kPublicKeyCredentialsCreate));
      break;

    case RequiredOriginType::
        kSecureAndPermittedByWebOTPAssertionPermissionsPolicy:
      SECURITY_CHECK(
          resolver->GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kOTPCredentials) &&
          IsAncestorChainValidForWebOTP(
              To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame()));
      break;

    case RequiredOriginType::kSecureAndPermittedByFederatedPermissionsPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kIdentityCredentialsGet));
      break;

    case RequiredOriginType::
        kSecureWithPaymentOrCreateCredentialPermissionPolicy:
      SECURITY_CHECK(resolver->GetExecutionContext()->IsFeatureEnabled(
                         mojom::blink::PermissionsPolicyFeature::kPayment) ||
                     resolver->GetExecutionContext()->IsFeatureEnabled(
                         mojom::blink::PermissionsPolicyFeature::
                             kPublicKeyCredentialsCreate));
      break;
  }
}

// Checks if the icon URL is an a-priori authenticated URL.
// https://w3c.github.io/webappsec-credential-management/#dom-credentialuserdata-iconurl
bool IsIconURLNullOrSecure(const KURL& url) {
  if (url.IsNull()) {
    return true;
  }

  if (!url.IsValid()) {
    return false;
  }

  return network::IsUrlPotentiallyTrustworthy(GURL(url));
}

// Checks if the size of the supplied ArrayBuffer or ArrayBufferView is at most
// the maximum size allowed.
bool IsArrayBufferOrViewBelowSizeLimit(
    const V8UnionArrayBufferOrArrayBufferView* buffer_or_view) {
  if (!buffer_or_view) {
    return true;
  }
  return base::CheckedNumeric<wtf_size_t>(
             DOMArrayPiece(buffer_or_view).ByteLength())
      .IsValid();
}

bool IsCredentialDescriptorListBelowSizeLimit(
    const HeapVector<Member<PublicKeyCredentialDescriptor>>& list) {
  return list.size() <= mojom::blink::kPublicKeyCredentialDescriptorListMaxSize;
}

DOMException* CredentialManagerErrorToDOMException(
    CredentialManagerError reason) {
  switch (reason) {
    case CredentialManagerError::PENDING_REQUEST:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "A request is already pending.");
    case CredentialManagerError::PASSWORD_STORE_UNAVAILABLE:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The password store is unavailable.");
    case CredentialManagerError::UNKNOWN:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotReadableError,
          "An unknown error occurred while talking "
          "to the credential manager.");
    case CredentialManagerError::SUCCESS:
      NOTREACHED();
  }
  return nullptr;
}

// Abort an ongoing IdentityCredential request. This will only be called before
// the request finishes due to `scoped_abort_state`.
void AbortIdentityCredentialRequest(ScriptState* script_state) {
  if (!script_state->ContextIsValid()) {
    return;
  }

  auto* auth_request =
      CredentialManagerProxy::From(script_state)->FederatedAuthRequest();
  auth_request->CancelTokenRequest();
}

void OnRequestToken(std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
                    std::unique_ptr<ScopedAbortState> scoped_abort_state,
                    const CredentialRequestOptions* options,
                    RequestTokenStatus status,
                    const std::optional<KURL>& selected_idp_config_url,
                    const WTF::String& token,
                    mojom::blink::TokenErrorPtr error,
                    bool is_auto_selected) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();
  switch (status) {
    case RequestTokenStatus::kErrorTooManyRequests: {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "Only one navigator.credentials.get request may be outstanding at "
          "one time."));
      return;
    }
    case RequestTokenStatus::kErrorCanceled: {
      AbortSignal* signal =
          scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
      if (signal && signal->aborted()) {
        auto* script_state = resolver->GetScriptState();
        ScriptState::Scope script_state_scope(script_state);
        resolver->Reject(signal->reason(script_state));
      } else {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kAbortError, "The request has been aborted."));
      }
      return;
    }
    case RequestTokenStatus::kError: {
      if (!RuntimeEnabledFeatures::FedCmErrorEnabled() || !error) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNetworkError, "Error retrieving a token."));
        return;
      }
      resolver->Reject(MakeGarbageCollected<IdentityCredentialError>(
          "Error retrieving a token.", error->code, error->url));
      return;
    }
    case RequestTokenStatus::kSuccess: {
      CHECK(selected_idp_config_url);
      IdentityCredential* credential = IdentityCredential::Create(
          token, is_auto_selected, *selected_idp_config_url);
      resolver->Resolve(credential);
      return;
    }
    default: {
      NOTREACHED();
    }
  }
}

void OnStoreComplete(std::unique_ptr<ScopedPromiseResolver> scoped_resolver) {
  auto* resolver = scoped_resolver->Release()->DowncastTo<Credential>();
  AssertSecurityRequirementsBeforeResponse(
      resolver, RequiredOriginType::kSecureAndSameWithAncestors);
  resolver->Resolve();
}

void OnPreventSilentAccessComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver) {
  auto* resolver = scoped_resolver->Release()->DowncastTo<IDLUndefined>();
  const auto required_origin_type = RequiredOriginType::kSecure;
  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);

  resolver->Resolve();
}

void OnGetComplete(std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
                   RequiredOriginType required_origin_type,
                   CredentialManagerError error,
                   CredentialInfoPtr credential_info) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();

  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);
  if (error != CredentialManagerError::SUCCESS) {
    DCHECK(!credential_info);
    resolver->Reject(CredentialManagerErrorToDOMException(error));
    return;
  }
  DCHECK(credential_info);
  UseCounter::Count(resolver->GetExecutionContext(),
                    WebFeature::kCredentialManagerGetReturnedCredential);
  resolver->Resolve(mojo::ConvertTo<Credential*>(std::move(credential_info)));
}

DOMArrayBuffer* VectorToDOMArrayBuffer(const Vector<uint8_t> buffer) {
  return DOMArrayBuffer::Create(buffer);
}

AuthenticationExtensionsPRFValues* GetPRFExtensionResults(
    const mojom::blink::PRFValuesPtr& prf_results) {
  auto* values = AuthenticationExtensionsPRFValues::Create();
  values->setFirst(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      VectorToDOMArrayBuffer(std::move(prf_results->first))));
  if (prf_results->second) {
    values->setSecond(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
        VectorToDOMArrayBuffer(std::move(prf_results->second.value()))));
  }
  return values;
}

void OnMakePublicKeyCredentialComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    RequiredOriginType required_origin_type,
    bool is_rk_required,
    AuthenticatorStatus status,
    MakeCredentialAuthenticatorResponsePtr credential,
    WebAuthnDOMExceptionDetailsPtr dom_exception_details) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();
  AssertSecurityRequirementsBeforeResponse(resolver, required_origin_type);
  if (status != AuthenticatorStatus::SUCCESS) {
    DCHECK(!credential);
    AbortSignal* signal =
        scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
    if (signal && signal->aborted()) {
      auto* script_state = resolver->GetScriptState();
      ScriptState::Scope script_state_scope(script_state);
      resolver->Reject(signal->reason(script_state));
    } else {
      resolver->Reject(
          AuthenticatorStatusToDOMException(status, dom_exception_details));
    }
    return;
  }
  DCHECK(credential);
  DCHECK(!credential->info->client_data_json.empty());
  DCHECK(!credential->attestation_object.empty());
  UseCounter::Count(
      resolver->GetExecutionContext(),
      WebFeature::kCredentialManagerMakePublicKeyCredentialSuccess);
  if (is_rk_required) {
    UseCounter::Count(resolver->GetExecutionContext(),
                      WebFeature::kWebAuthnRkRequiredCreationSuccess);
  }
  DOMArrayBuffer* client_data_buffer =
      VectorToDOMArrayBuffer(std::move(credential->info->client_data_json));
  DOMArrayBuffer* raw_id =
      VectorToDOMArrayBuffer(std::move(credential->info->raw_id));
  DOMArrayBuffer* attestation_buffer =
      VectorToDOMArrayBuffer(std::move(credential->attestation_object));
  DOMArrayBuffer* authenticator_data =
      VectorToDOMArrayBuffer(std::move(credential->info->authenticator_data));
  DOMArrayBuffer* public_key_der = nullptr;
  if (credential->public_key_der) {
    public_key_der =
        VectorToDOMArrayBuffer(std::move(credential->public_key_der.value()));
  }
  auto* authenticator_response =
      MakeGarbageCollected<AuthenticatorAttestationResponse>(
          client_data_buffer, attestation_buffer, credential->transports,
          authenticator_data, public_key_der, credential->public_key_algo);

  AuthenticationExtensionsClientOutputs* extension_outputs =
      AuthenticationExtensionsClientOutputs::Create();
  if (credential->echo_hmac_create_secret) {
    extension_outputs->setHmacCreateSecret(credential->hmac_create_secret);
  }
  if (credential->echo_cred_props) {
    CredentialPropertiesOutput* cred_props_output =
        CredentialPropertiesOutput::Create();
    if (credential->has_cred_props_rk) {
      cred_props_output->setRk(credential->cred_props_rk);
    }
    extension_outputs->setCredProps(cred_props_output);
  }
  if (credential->echo_cred_blob) {
    extension_outputs->setCredBlob(credential->cred_blob);
  }
  if (credential->echo_large_blob) {
    DCHECK(
        RuntimeEnabledFeatures::WebAuthenticationLargeBlobExtensionEnabled());
    AuthenticationExtensionsLargeBlobOutputs* large_blob_outputs =
        AuthenticationExtensionsLargeBlobOutputs::Create();
    large_blob_outputs->setSupported(credential->supports_large_blob);
    extension_outputs->setLargeBlob(large_blob_outputs);
  }
  if (credential->supplemental_pub_keys) {
    extension_outputs->setSupplementalPubKeys(
        ConvertTo<AuthenticationExtensionsSupplementalPubKeysOutputs*>(
            credential->supplemental_pub_keys));
  }
  if (credential->echo_prf) {
    auto* prf_outputs = AuthenticationExtensionsPRFOutputs::Create();
    prf_outputs->setEnabled(credential->prf);
    if (credential->prf_results) {
      prf_outputs->setResults(GetPRFExtensionResults(credential->prf_results));
    }
    extension_outputs->setPrf(prf_outputs);
  }
  resolver->Resolve(MakeGarbageCollected<PublicKeyCredential>(
      credential->info->id, raw_id, authenticator_response,
      credential->authenticator_attachment, extension_outputs));
}

bool IsForPayment(const CredentialCreationOptions* options,
                  ExecutionContext* context) {
  return RuntimeEnabledFeatures::SecurePaymentConfirmationEnabled(context) &&
         options->hasPublicKey() && options->publicKey()->hasExtensions() &&
         options->publicKey()->extensions()->hasPayment() &&
         options->publicKey()->extensions()->payment()->hasIsPayment() &&
         options->publicKey()->extensions()->payment()->isPayment();
}

void OnSaveCredentialIdForPaymentExtension(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    MakeCredentialAuthenticatorResponsePtr credential,
    PaymentCredentialStorageStatus storage_status) {
  auto status = AuthenticatorStatus::SUCCESS;
  if (storage_status != PaymentCredentialStorageStatus::SUCCESS) {
    status =
        AuthenticatorStatus::FAILED_TO_SAVE_CREDENTIAL_ID_FOR_PAYMENT_EXTENSION;
    credential = nullptr;
  }
  OnMakePublicKeyCredentialComplete(
      std::move(scoped_resolver), std::move(scoped_abort_state),
      RequiredOriginType::kSecureWithPaymentOrCreateCredentialPermissionPolicy,
      /*is_rk_required=*/false, status, std::move(credential),
      /*dom_exception_details=*/nullptr);
}

void OnMakePublicKeyCredentialWithPaymentExtensionComplete(
    std::unique_ptr<ScopedPromiseResolver> scoped_resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    const String& rp_id_for_payment_extension,
    const WTF::Vector<uint8_t>& user_id_for_payment_extension,
    AuthenticatorStatus status,
    MakeCredentialAuthenticatorResponsePtr credential,
    WebAuthnDOMExceptionDetailsPtr dom_exception_details) {
  auto* resolver =
      scoped_resolver->Release()->DowncastTo<IDLNullable<Credential>>();

  AssertSecurityRequirementsBeforeResponse(
      resolver,
      RequiredOriginType::kSecureWithPaymentOrCreateCredentialPermissionPolicy);
  if (status != AuthenticatorStatus::SUCCESS) {
    DCHECK(!credential);
    AbortSignal* signal =
```