Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `content_security_policy.cc`. I need to identify the core purpose of this file and how it relates to web technologies like JavaScript, HTML, and CSS. The prompt also asks for examples involving logic, user errors, and program errors related to CSP. Finally, I need to explicitly state that this is only the first part of the summary.

Here’s a breakdown of the code’s functionalities:

1. **CSP Policy Handling:** The core of this file is managing Content Security Policy (CSP) rules. It parses, stores, and enforces these policies.
2. **Directive Processing:** It handles various CSP directives like `script-src`, `style-src`, `object-src`, etc.
3. **Source Checking:** It determines if a requested resource violates the CSP based on the policy's allowed sources, nonces, and hashes.
4. **Inline Script/Style Handling:**  It manages how inline scripts and styles are treated based on CSP.
5. **`eval()` and WebAssembly Restrictions:** It enforces restrictions on the use of `eval()` and WebAssembly code generation.
6. **Reporting Violations:** It's involved in reporting CSP violations to the browser's developer console or a designated reporting endpoint.
7. **Sandbox Enforcement:**  It can enforce sandbox attributes specified in the CSP.
8. **Trusted Types:**  It handles the enforcement of Trusted Types policies.
9. **Mixed Content Blocking:** It manages the blocking of mixed content based on the CSP.
10. **Use Counters:** It tracks usage of CSP features for analytics.

Now, let's connect these to JavaScript, HTML, and CSS:

* **JavaScript:** CSP directly controls where JavaScript code can be loaded from (`script-src`), whether inline scripts are allowed, and if `eval()` is permitted.
* **HTML:** CSP can restrict the sources of various HTML elements like `<script>`, `<img>`, `<object>`, etc. The `nonce` attribute on `<script>` and `<style>` tags is crucial for CSP.
* **CSS:** CSP controls where stylesheets can be loaded from (`style-src`) and whether inline styles are allowed. Similar to scripts, CSS can also use `nonce`.

Examples:

* **Logic/Decision Making:** When a `<script>` tag with a `src` attribute is encountered, the code checks the `script-src` directive to see if the source is allowed.
* **User/Programming Errors:**  A common mistake is not including `'unsafe-inline'` in `script-src` when using inline scripts, leading to them being blocked.
* **Assumptions for Input/Output:**  If a policy has `script-src 'self'`, and the browser tries to load a script from `https://example.com`, the output will be a CSP violation.

Finally, I need to wrap up this information into a concise summary for Part 1.
```cpp
/*
 * Copyright (C) 2011 Google, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/contains.h"
#include "base/debug/dump_without_crashing.h"
#include "base/ranges/algorithm.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink-forward.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-shared.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_security_policy_violation_event_init.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"
#include "third_party/blink/renderer/core/frame/csp/csp_source.h"
#include "third_party/blink/renderer/core/frame/frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/securitypolicyviolation_disposition_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "v8/include/v8.h"

namespace blink {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;

namespace {

enum ContentSecurityPolicyHashAlgorithm {
  kContentSecurityPolicyHashAlgorithmNone = 0,
  kContentSecurityPolicyHashAlgorithmSha256 = 1 << 2,
  kContentSecurityPolicyHashAlgorithmSha384 = 1 << 3,
  kContentSecurityPolicyHashAlgorithmSha512 = 1 << 4
};

// Returns true if the given `header_type` should be checked given
// `check_header_type` and `reporting_disposition`.
bool CheckHeaderTypeMatches(
    ContentSecurityPolicy::CheckHeaderType check_header_type,
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicyType header_type) {
  switch (reporting_disposition) {
    case ReportingDisposition::kSuppressReporting:
      switch (check_header_type) {
        case ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly:
          return false;
        case ContentSecurityPolicy::CheckHeaderType::kCheckAll:
        case ContentSecurityPolicy::CheckHeaderType::kCheckEnforce:
          return header_type == ContentSecurityPolicyType::kEnforce;
      }
    case ReportingDisposition::kReport:
      switch (check_header_type) {
        case ContentSecurityPolicy::CheckHeaderType::kCheckAll:
          return true;
        case ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly:
          return header_type == ContentSecurityPolicyType::kReport;
        case ContentSecurityPolicy::CheckHeaderType::kCheckEnforce:
          return header_type == ContentSecurityPolicyType::kEnforce;
      }
  }
  NOTREACHED();
}

int32_t HashAlgorithmsUsed(
    const network::mojom::blink::CSPSourceList* source_list) {
  int32_t hash_algorithms_used = 0;
  if (!source_list)
    return hash_algorithms_used;
  for (const auto& hash : source_list->hashes) {
    hash_algorithms_used |= static_cast<int32_t>(hash->algorithm);
  }
  return hash_algorithms_used;
}

// 3. If request’s destination is "fencedframe", and this directive’s value does
//    not contain either "https:", "https://*:*", or "*", return "Blocked".
// https://wicg.github.io/fenced-frame/#csp-algorithms
bool AllowOpaqueFencedFrames(
    const network::mojom::blink::CSPSourcePtr& source) {
  if (source->scheme != url::kHttpsScheme) {
    return false;
  }

  // "https:" is allowed.
  if (source->host.empty() && !source->is_host_wildcard) {
    return true;
  }

  // "https://*:*" is allowed.
  if (source->is_host_wildcard && source->is_port_wildcard) {
    return true;
  }

  // "https://*" is not allowed as it could leak data about ports.

  return false;
}

// Returns true if the CSP for the document loading the fenced frame allows all
// HTTPS origins for "fenced-frame-src".
bool AllowOpaqueFencedFrames(
    const network::mojom::blink::ContentSecurityPolicyPtr& policy) {
  CSPOperativeDirective directive = CSPDirectiveListOperativeDirective(
      *policy, network::mojom::CSPDirectiveName::FencedFrameSrc);
  if (directive.type == network::mojom::CSPDirectiveName::Unknown) {
    return true;
  }

  // "*" is allowed.
  if (directive.source_list->allow_star) {
    return true;
  }

  for (const auto& source : directive.source_list->sources) {
    if (AllowOpaqueFencedFrames(source)) {
      return true;
    }
  }

  return false;
}

}  // namespace

bool ContentSecurityPolicy::IsNonceableElement(const Element* element) {
  if (element->nonce().IsNull())
    return false;

  bool nonceable = true;

  // To prevent an attacker from hijacking an existing nonce via a dangling
  // markup injection, we walk through the attributes of each nonced script
  // element: if their names or values contain "<script" or "<style", we won't
  // apply the nonce when loading script.
  //
  // See http://blog.innerht.ml/csp-2015/#danglingmarkupinjection for an example
  // of the kind of attack this is aimed at mitigating.

  if (element->HasDuplicateAttribute())
    nonceable = false;

  if (nonceable) {
    static const char kScriptString[] = "<SCRIPT";
    static const char kStyleString[] = "<STYLE";
    for (const Attribute& attr : element->Attributes()) {
      const AtomicString& name = attr.LocalName();
      const AtomicString& value = attr.Value();
      if (name.FindIgnoringASCIICase(kScriptString) != WTF::kNotFound ||
          name.FindIgnoringASCIICase(kStyleString) != WTF::kNotFound ||
          value.FindIgnoringASCIICase(kScriptString) != WTF::kNotFound ||
          value.FindIgnoringASCIICase(kStyleString) != WTF::kNotFound) {
        nonceable = false;
        break;
      }
    }
  }

  UseCounter::Count(
      element->GetExecutionContext(),
      nonceable ? WebFeature::kCleanScriptElementWithNonce
                : WebFeature::kPotentiallyInjectedScriptElementWithNonce);

  return nonceable;
}

static WebFeature GetUseCounterType(ContentSecurityPolicyType type) {
  switch (type) {
    case ContentSecurityPolicyType::kEnforce:
      return WebFeature::kContentSecurityPolicy;
    case ContentSecurityPolicyType::kReport:
      return WebFeature::kContentSecurityPolicyReportOnly;
  }
  NOTREACHED();
}

ContentSecurityPolicy::ContentSecurityPolicy()
    : delegate_(nullptr),
      override_inline_style_allowed_(false),
      script_hash_algorithms_used_(kContentSecurityPolicyHashAlgorithmNone),
      style_hash_algorithms_used_(kContentSecurityPolicyHashAlgorithmNone),
      sandbox_mask_(network::mojom::blink::WebSandboxFlags::kNone),
      require_trusted_types_(false),
      insecure_request_policy_(
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone) {}

bool ContentSecurityPolicy::IsBound() {
  return delegate_ != nullptr;
}

void ContentSecurityPolicy::BindToDelegate(
    ContentSecurityPolicyDelegate& delegate) {
  // TODO(crbug.com/915954): Add DCHECK(!delegate_). It seems some call sites
  // call this function multiple times.
  delegate_ = &delegate;
  ApplyPolicySideEffectsToDelegate();

  // Report use counters for all the policies that have been parsed until now.
  ReportUseCounters(policies_);
  delegate_->DidAddContentSecurityPolicies(mojo::Clone(GetParsedPolicies()));
}

void ContentSecurityPolicy::ApplyPolicySideEffectsToDelegate() {
  DCHECK(delegate_);

  // Set mixed content checking and sandbox flags, then dump all the parsing
  // error messages, then poke at histograms.
  if (sandbox_mask_ != network::mojom::blink::WebSandboxFlags::kNone) {
    Count(WebFeature::kSandboxViaCSP);
    delegate_->SetSandboxFlags(sandbox_mask_);
  }

  if (require_trusted_types_) {
    delegate_->SetRequireTrustedTypes();
    Count(WebFeature::kTrustedTypesEnabled);
  }

  delegate_->AddInsecureRequestPolicy(insecure_request_policy_);

  for (const auto& console_message : console_messages_)
    delegate_->AddConsoleMessage(console_message);
  console_messages_.clear();

  // We disable 'eval()' even in the case of report-only policies, and rely on
  // the check in the V8Initializer::codeGenerationCheckCallbackInMainThread
  // callback to determine whether the call should execute or not.
  if (!disable_eval_error_message_.IsNull())
    delegate_->DisableEval(disable_eval_error_message_);

  if (!disable_wasm_eval_error_message_.IsNull())
    delegate_->SetWasmEvalErrorMessage(disable_wasm_eval_error_message_);
}

void ContentSecurityPolicy::ReportUseCounters(
    const Vector<network::mojom::blink::ContentSecurityPolicyPtr>& policies) {
  for (const auto& policy : policies) {
    Count(GetUseCounterType(policy->header->type));
    if (CSPDirectiveListAllowDynamic(*policy,
                                     CSPDirectiveName::ScriptSrcAttr) ||
        CSPDirectiveListAllowDynamic(*policy,
                                     CSPDirectiveName::ScriptSrcElem)) {
      Count(WebFeature::kCSPWithStrictDynamic);
    }

    if (CSPDirectiveListAllowEval(*policy, this,
                                  ReportingDisposition::kSuppressReporting,
                                  kWillNotThrowException, g_empty_string)) {
      Count(WebFeature::kCSPWithUnsafeEval);
    }

    // We consider a policy to be "reasonably secure" if it:
    //
    // 1. Asserts `object-src 'none'`.
    // 2. Asserts `base-uri 'none'` or `base-uri 'self'`.
    // 3. Avoids URL-based matching, in favor of hashes and nonces.
    //
    // https://chromium.googlesource.com/chromium/src/+/main/docs/security/web-mitigation-metrics.md
    // has more detail.
    if (CSPDirectiveListIsObjectRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableObjectRestrictions
                : WebFeature::kCSPROWithReasonableObjectRestrictions);
    }
    if (CSPDirectiveListIsBaseRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableBaseRestrictions
                : WebFeature::kCSPROWithReasonableBaseRestrictions);
    }
    if (CSPDirectiveListIsScriptRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableScriptRestrictions
                : WebFeature::kCSPROWithReasonableScriptRestrictions);
    }
    if (CSPDirectiveListIsObjectRestrictionReasonable(*policy) &&
        CSPDirectiveListIsBaseRestrictionReasonable(*policy) &&
        CSPDirectiveListIsScriptRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableRestrictions
                : WebFeature::kCSPROWithReasonableRestrictions);

      if (!CSPDirectiveListAllowDynamic(*policy,
                                        CSPDirectiveName::ScriptSrcElem)) {
        Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                  ? WebFeature::kCSPWithBetterThanReasonableRestrictions
                  : WebFeature::kCSPROWithBetterThanReasonableRestrictions);
      }
    }
    if (CSPDirectiveListRequiresTrustedTypes(*policy)) {
      Count(CSPDirectiveListIsReportOnly(*policy)
                ? WebFeature::kTrustedTypesEnabledReportOnly
                : WebFeature::kTrustedTypesEnabledEnforcing);
    }
    if (policy->trusted_types && policy->trusted_types->allow_duplicates) {
      Count(WebFeature::kTrustedTypesAllowDuplicates);
    }
  }
}

ContentSecurityPolicy::~ContentSecurityPolicy() = default;

void ContentSecurityPolicy::Trace(Visitor* visitor) const {
  visitor->Trace(delegate_);
  visitor->Trace(console_messages_);
}

void ContentSecurityPolicy::AddPolicies(
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies) {
  Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies_to_report;
  if (delegate_) {
    policies_to_report = mojo::Clone(policies);
  }

  for (network::mojom::blink::ContentSecurityPolicyPtr& policy : policies) {
    ComputeInternalStateForParsedPolicy(*policy);

    // Report parsing errors in the console.
    for (const String& message : policy->parsing_errors)
      LogToConsole(message);

    policies_.push_back(std::move(policy));
  }

  // Reevaluate whether the composite set of enforced policies are "strict"
  // after these new policies have been added. Since additional policies can
  // only tighten the composite policy, we only need to check this if the policy
  // isn't already "strict".
  if (!enforces_strict_policy_) {
    const bool is_object_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsObjectRestrictionReasonable(*policy);
        });
    const bool is_base_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsBaseRestrictionReasonable(*policy);
        });
    const bool is_script_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsScriptRestrictionReasonable(*policy);
        });
    enforces_strict_policy_ = is_object_restriction_reasonable &&
                              is_base_restriction_reasonable &&
                              is_script_restriction_reasonable;
  }

  // If this ContentSecurityPolicy is not bound to a delegate yet, return. The
  // following logic will be executed in BindToDelegate when that will happen.
  if (!delegate_)
    return;

  ApplyPolicySideEffectsToDelegate();
  ReportUseCounters(policies_to_report);

  delegate_->DidAddContentSecurityPolicies(std::move(policies_to_report));
}

void ContentSecurityPolicy::ComputeInternalStateForParsedPolicy(
    const network::mojom::blink::ContentSecurityPolicy& csp) {
  if (csp.header->source == ContentSecurityPolicySource::kHTTP)
    header_delivered_ = true;

  if (csp.block_all_mixed_content && !CSPDirectiveListIsReportOnly(csp))
    EnforceStrictMixedContentChecking();

  if (CSPDirectiveListRequiresTrustedTypes(csp))
    RequireTrustedTypes();

  EnforceSandboxFlags(csp.sandbox);

  if (csp.upgrade_insecure_requests)
    UpgradeInsecureRequests();

  String disable_eval_message;
  if (CSPDirectiveListShouldDisableEval(csp, disable_eval_message) &&
      disable_eval_error_message_.IsNull()) {
    disable_eval_error_message_ = disable_eval_message;
  }

  String disable_wasm_eval_message;
  if (CSPDirectiveListShouldDisableWasmEval(csp, this,
                                            disable_wasm_eval_message) &&
      disable_wasm_eval_error_message_.IsNull()) {
    disable_wasm_eval_message_ = disable_wasm_eval_message;
  }

  for (const auto& directive : csp.directives) {
    switch (directive.key) {
      case CSPDirectiveName::DefaultSrc:
        // TODO(mkwst) It seems unlikely that developers would use different
        // algorithms for scripts and styles. We may want to combine the
        // usesScriptHashAlgorithms() and usesStyleHashAlgorithms.
        UsesScriptHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        UsesStyleHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      case CSPDirectiveName::ScriptSrc:
      case CSPDirectiveName::ScriptSrcAttr:
      case CSPDirectiveName::ScriptSrcElem:
        UsesScriptHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      case CSPDirectiveName::StyleSrc:
      case CSPDirectiveName::StyleSrcAttr:
      case CSPDirectiveName::StyleSrcElem:
        UsesStyleHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      default:
        break;
    }
  }
}

void ContentSecurityPolicy::SetOverrideAllowInlineStyle(bool value) {
  override_inline_style_allowed_ = value;
}

// static
void ContentSecurityPolicy::FillInCSPHashValues(
    const String& source,
    uint8_t hash_algorithms_used,
    Vector<network::mojom::blink::CSPHashSourcePtr>& csp_hash_values) {
  // Any additions or subtractions from this struct should also modify the
  // respective entries in the kSupportedPrefixes array in
  // SourceListDirective::parseHash().
  static const struct {
    network::mojom::blink::CSPHashAlgorithm csp_hash_algorithm;
    HashAlgorithm algorithm;
  } kAlgorithmMap[] = {
      {network::mojom::blink::CSPHashAlgorithm::SHA256, kHashAlgorithmSha256},
      {network::mojom::blink::CSPHashAlgorithm::SHA384, kHashAlgorithmSha384},
      {network::mojom::blink::CSPHashAlgorithm::SHA512, kHashAlgorithmSha512}};

  // Only bother normalizing the source/computing digests if there are any
  // checks to be done.
  if (hash_algorithms_used == kContentSecurityPolicyHashAlgorithmNone)
    return;

  StringUTF8Adaptor utf8_source(
      source, kStrictUTF8ConversionReplacingUnpairedSurrogatesWithFFFD);

  for (const auto& algorithm_map : kAlgorithmMap) {
    DigestValue digest;
    if (static_cast<int32_t>(algorithm_map.csp_hash_algorithm) &
        hash_algorithms_used) {
      bool digest_success = ComputeDigest(
          algorithm_map.algorithm, base::as_byte_span(utf8_source), digest);
      if (digest_success) {
        csp_hash_values.push_back(network::mojom::blink::CSPHashSource::New(
            algorithm_map.csp_hash_algorithm, Vector<uint8_t>(digest)));
      }
    }
  }
}

// static
bool ContentSecurityPolicy::CheckHashAgainstPolicy(
    Vector<network::mojom::blink::CSPHashSourcePtr>& csp_hash_values,
    const network::mojom::blink::ContentSecurityPolicy& csp,
    InlineType inline_type) {
  for (const auto& csp_hash_value : csp_hash_values) {
    if (CSPDirectiveListAllowHash(csp, *csp_hash_value, inline_type))
      return true;
  }
  return false;
}

// https://w3c.github.io/webappsec-csp/#should-block-inline
bool ContentSecurityPolicy::AllowInline(
    InlineType inline_type,
    Element* element,
    const String& content,
    const String& nonce,
    const String& context_url,
    const WTF::OrdinalNumber& context_line,
    ReportingDisposition reporting_disposition) {
  DCHECK(element || inline_type == InlineType::kScriptAttribute ||
         inline_type == InlineType::kNavigation);

  const bool is_script = IsScriptInlineType(inline_type);
  if (!is_script && override_inline_style_allowed_) {
    return true;
  }

  Vector<network::mojom::blink::CSPHashSourcePtr> csp_hash_values;
  FillInCSPHashValues(
      content,
      is_script ? script_hash_algorithms_used_ : style_hash_algorithms_used_,
      csp_hash_values);

  // Step 2. Let result be "Allowed". [spec text]
  bool is_allowed = true;

  // Step 3. For each policy in element’s Document's global object’s CSP list:
  // [spec text]
  for (const auto& policy : policies_) {
    // May be allowed by hash, if 'unsafe-hashes' is present in a policy.
    // Check against the digest of the |content| and also check whether inline
    // script is allowed.
    is_allowed &=
        CheckHashAgainstPolicy(csp_hash_values, *policy, inline_type) ||
        CSPDirectiveListAllowInline(*policy, this, inline_type, element,
                                    content, nonce, context_url, context_line,
                                    reporting_disposition);
  }

  return is_allowed;
}

bool ContentSecurityPolicy::IsScriptInlineType(InlineType inline_type) {
  switch (inline_type) {
    case ContentSecurityPolicy::InlineType::kNavigation:
    case ContentSecurityPolicy::InlineType::kScriptSpeculationRules:
    case ContentSecurityPolicy::InlineType::kScriptAttribute:
    case ContentSecurityPolicy::InlineType::kScript:
      return true;

    case ContentSecurityPolicy::InlineType::kStyleAttribute:
    case ContentSecurityPolicy::InlineType::kStyle:
      return false;
  }
}

bool ContentSecurityPolicy::ShouldCheckEval() const {
  for (const auto& policy : policies_) {
    if (CSPDirectiveListShouldCheckEval(*policy))
      return true;
  }
  return IsRequireTrustedTypes();
}

bool ContentSecurityPolicy::AllowEval(
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicy::ExceptionStatus exception_status,
    const String& script_content) {
  bool is_allowed = true;
  for (const auto& policy : policies_) {
    is_allowed &= CSPDirectiveListAllowEval(
        *policy, this, reporting_disposition, exception_status, script_content);
  }
  return is_allowed;
}

bool ContentSecurityPolicy::AllowWasmCodeGeneration(
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicy::ExceptionStatus exception_status,
    const String& script_content) {
  bool is_allowed = true;
  for (const auto& policy : policies_) {
    is_allowed &= CSPDirectiveListAllowWasmCodeGeneration(
        *policy, this, reporting_disposition, exception_status, script_content);
  }
  return is_allowed;
}

String ContentSecurityPolicy::EvalDisabledErrorMessage() const {
  for (const auto& policy : policies_) {
    String message;
    if (CSPDirectiveListShouldDisableEval(*policy, message))
      return message;
  }
  return String();
}

String ContentSecurityPolicy::WasmEvalDisabledErrorMessage() const {
  for (const auto& policy : policies_) {
    String message;
    if (CSPDirectiveListShouldDisableWasmEval(*policy, this, message))
      return message;
  }
  return String();
}

namespace {
std::optional<CSPDirectiveName> GetDirectiveTypeFromRequestContextType(
    mojom::blink::RequestContextType context) {
  switch (context) {
    case mojom::blink::RequestContextType::AUDIO:
    case mojom::blink::RequestContextType::TRACK:
    case mojom::blink::RequestContextType::VIDEO:
      return CSPDirectiveName::MediaSrc;

    case mojom::blink::RequestContextType::ATTRIBUTION_SRC:
    case mojom::blink::RequestContextType::BEACON:
    case mojom::blink::RequestContextType::EVENT_SOURCE:
    case mojom::blink::RequestContextType::FETCH:
    case mojom::blink::RequestContextType::JSON:
    case mojom::blink::RequestContextType::PING:
    case mojom::blink::RequestContextType::XML_HTTP_REQUEST:
    case mojom::blink::RequestContextType::SUBRESOURCE:
    case mojom::blink::RequestContextType::SUBRESOURCE_WEBBUNDLE:
      return CSPDirectiveName::ConnectSrc;

    case mojom::blink::RequestContextType::EMBED:
    case mojom::blink::RequestContextType::OBJECT:
      return CSPDirectiveName::ObjectSrc;

    case mojom::blink::RequestContextType::FAVICON:
    case mojom::blink::RequestContextType::IMAGE:
    case mojom::blink::RequestContextType::IMAGE_SET:
      return CSPDirectiveName::ImgSrc;

    case mojom::blink::RequestContextType::FONT:
      return CSPDirectiveName::FontSrc;

    case mojom::blink::RequestContextType::FORM:
      return CSPDirectiveName::FormAction;

    case mojom::blink::RequestContextType::FRAME:
    case mojom::blink::RequestContextType::IFRAME:
      return CSPDirectiveName::FrameSrc;

    case mojom::blink::RequestContextType::SCRIPT:
    case mojom::blink::RequestContextType::XSLT:
      return CSPDirectiveName::ScriptSrcElem;

    case mojom::blink::RequestContextType::MANIFEST:
      return CSPDirectiveName::ManifestSrc;

    case mojom::blink::RequestContextType::SERVICE_WORKER:
    case mojom::blink::RequestContextType::SHARED_WORKER:
    case mojom::blink::RequestContextType::WORKER:
      return CSPDirectiveName::WorkerSrc;

    case mojom::blink::RequestContextType::STYLE:
      return CSPDirectiveName::StyleSrcElem;

    case mojom::blink::RequestContextType::PREFETCH:
      return CSPDirectiveName::DefaultSrc;

    case mojom::blink::RequestContextType::SPECULATION_RULES:
      // If speculation rules ever supports <script src>, then it will
      // probably be necessary to use ScriptSrcElem in such cases.
      if (!base::FeatureList::IsEnabled(
              features::kExemptSpeculationRulesHeaderFromCSP)) {
        return CSPDirectiveName::ScriptSrc;
      }
      // Speculation
### 提示词
```
这是目录为blink/renderer/core/frame/csp/content_security_policy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/contains.h"
#include "base/debug/dump_without_crashing.h"
#include "base/ranges/algorithm.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink-forward.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-shared.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_security_policy_violation_event_init.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"
#include "third_party/blink/renderer/core/frame/csp/csp_source.h"
#include "third_party/blink/renderer/core/frame/frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/securitypolicyviolation_disposition_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "v8/include/v8.h"

namespace blink {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;

namespace {

enum ContentSecurityPolicyHashAlgorithm {
  kContentSecurityPolicyHashAlgorithmNone = 0,
  kContentSecurityPolicyHashAlgorithmSha256 = 1 << 2,
  kContentSecurityPolicyHashAlgorithmSha384 = 1 << 3,
  kContentSecurityPolicyHashAlgorithmSha512 = 1 << 4
};

// Returns true if the given `header_type` should be checked given
// `check_header_type` and `reporting_disposition`.
bool CheckHeaderTypeMatches(
    ContentSecurityPolicy::CheckHeaderType check_header_type,
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicyType header_type) {
  switch (reporting_disposition) {
    case ReportingDisposition::kSuppressReporting:
      switch (check_header_type) {
        case ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly:
          return false;
        case ContentSecurityPolicy::CheckHeaderType::kCheckAll:
        case ContentSecurityPolicy::CheckHeaderType::kCheckEnforce:
          return header_type == ContentSecurityPolicyType::kEnforce;
      }
    case ReportingDisposition::kReport:
      switch (check_header_type) {
        case ContentSecurityPolicy::CheckHeaderType::kCheckAll:
          return true;
        case ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly:
          return header_type == ContentSecurityPolicyType::kReport;
        case ContentSecurityPolicy::CheckHeaderType::kCheckEnforce:
          return header_type == ContentSecurityPolicyType::kEnforce;
      }
  }
  NOTREACHED();
}

int32_t HashAlgorithmsUsed(
    const network::mojom::blink::CSPSourceList* source_list) {
  int32_t hash_algorithms_used = 0;
  if (!source_list)
    return hash_algorithms_used;
  for (const auto& hash : source_list->hashes) {
    hash_algorithms_used |= static_cast<int32_t>(hash->algorithm);
  }
  return hash_algorithms_used;
}

// 3. If request’s destination is "fencedframe", and this directive’s value does
//    not contain either "https:", "https://*:*", or "*", return "Blocked".
// https://wicg.github.io/fenced-frame/#csp-algorithms
bool AllowOpaqueFencedFrames(
    const network::mojom::blink::CSPSourcePtr& source) {
  if (source->scheme != url::kHttpsScheme) {
    return false;
  }

  // "https:" is allowed.
  if (source->host.empty() && !source->is_host_wildcard) {
    return true;
  }

  // "https://*:*" is allowed.
  if (source->is_host_wildcard && source->is_port_wildcard) {
    return true;
  }

  // "https://*" is not allowed as it could leak data about ports.

  return false;
}

// Returns true if the CSP for the document loading the fenced frame allows all
// HTTPS origins for "fenced-frame-src".
bool AllowOpaqueFencedFrames(
    const network::mojom::blink::ContentSecurityPolicyPtr& policy) {
  CSPOperativeDirective directive = CSPDirectiveListOperativeDirective(
      *policy, network::mojom::CSPDirectiveName::FencedFrameSrc);
  if (directive.type == network::mojom::CSPDirectiveName::Unknown) {
    return true;
  }

  // "*" is allowed.
  if (directive.source_list->allow_star) {
    return true;
  }

  for (const auto& source : directive.source_list->sources) {
    if (AllowOpaqueFencedFrames(source)) {
      return true;
    }
  }

  return false;
}

}  // namespace

bool ContentSecurityPolicy::IsNonceableElement(const Element* element) {
  if (element->nonce().IsNull())
    return false;

  bool nonceable = true;

  // To prevent an attacker from hijacking an existing nonce via a dangling
  // markup injection, we walk through the attributes of each nonced script
  // element: if their names or values contain "<script" or "<style", we won't
  // apply the nonce when loading script.
  //
  // See http://blog.innerht.ml/csp-2015/#danglingmarkupinjection for an example
  // of the kind of attack this is aimed at mitigating.

  if (element->HasDuplicateAttribute())
    nonceable = false;

  if (nonceable) {
    static const char kScriptString[] = "<SCRIPT";
    static const char kStyleString[] = "<STYLE";
    for (const Attribute& attr : element->Attributes()) {
      const AtomicString& name = attr.LocalName();
      const AtomicString& value = attr.Value();
      if (name.FindIgnoringASCIICase(kScriptString) != WTF::kNotFound ||
          name.FindIgnoringASCIICase(kStyleString) != WTF::kNotFound ||
          value.FindIgnoringASCIICase(kScriptString) != WTF::kNotFound ||
          value.FindIgnoringASCIICase(kStyleString) != WTF::kNotFound) {
        nonceable = false;
        break;
      }
    }
  }

  UseCounter::Count(
      element->GetExecutionContext(),
      nonceable ? WebFeature::kCleanScriptElementWithNonce
                : WebFeature::kPotentiallyInjectedScriptElementWithNonce);

  return nonceable;
}

static WebFeature GetUseCounterType(ContentSecurityPolicyType type) {
  switch (type) {
    case ContentSecurityPolicyType::kEnforce:
      return WebFeature::kContentSecurityPolicy;
    case ContentSecurityPolicyType::kReport:
      return WebFeature::kContentSecurityPolicyReportOnly;
  }
  NOTREACHED();
}

ContentSecurityPolicy::ContentSecurityPolicy()
    : delegate_(nullptr),
      override_inline_style_allowed_(false),
      script_hash_algorithms_used_(kContentSecurityPolicyHashAlgorithmNone),
      style_hash_algorithms_used_(kContentSecurityPolicyHashAlgorithmNone),
      sandbox_mask_(network::mojom::blink::WebSandboxFlags::kNone),
      require_trusted_types_(false),
      insecure_request_policy_(
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone) {}

bool ContentSecurityPolicy::IsBound() {
  return delegate_ != nullptr;
}

void ContentSecurityPolicy::BindToDelegate(
    ContentSecurityPolicyDelegate& delegate) {
  // TODO(crbug.com/915954): Add DCHECK(!delegate_). It seems some call sites
  // call this function multiple times.
  delegate_ = &delegate;
  ApplyPolicySideEffectsToDelegate();

  // Report use counters for all the policies that have been parsed until now.
  ReportUseCounters(policies_);
  delegate_->DidAddContentSecurityPolicies(mojo::Clone(GetParsedPolicies()));
}

void ContentSecurityPolicy::ApplyPolicySideEffectsToDelegate() {
  DCHECK(delegate_);

  // Set mixed content checking and sandbox flags, then dump all the parsing
  // error messages, then poke at histograms.
  if (sandbox_mask_ != network::mojom::blink::WebSandboxFlags::kNone) {
    Count(WebFeature::kSandboxViaCSP);
    delegate_->SetSandboxFlags(sandbox_mask_);
  }

  if (require_trusted_types_) {
    delegate_->SetRequireTrustedTypes();
    Count(WebFeature::kTrustedTypesEnabled);
  }

  delegate_->AddInsecureRequestPolicy(insecure_request_policy_);

  for (const auto& console_message : console_messages_)
    delegate_->AddConsoleMessage(console_message);
  console_messages_.clear();

  // We disable 'eval()' even in the case of report-only policies, and rely on
  // the check in the V8Initializer::codeGenerationCheckCallbackInMainThread
  // callback to determine whether the call should execute or not.
  if (!disable_eval_error_message_.IsNull())
    delegate_->DisableEval(disable_eval_error_message_);

  if (!disable_wasm_eval_error_message_.IsNull())
    delegate_->SetWasmEvalErrorMessage(disable_wasm_eval_error_message_);
}

void ContentSecurityPolicy::ReportUseCounters(
    const Vector<network::mojom::blink::ContentSecurityPolicyPtr>& policies) {
  for (const auto& policy : policies) {
    Count(GetUseCounterType(policy->header->type));
    if (CSPDirectiveListAllowDynamic(*policy,
                                     CSPDirectiveName::ScriptSrcAttr) ||
        CSPDirectiveListAllowDynamic(*policy,
                                     CSPDirectiveName::ScriptSrcElem)) {
      Count(WebFeature::kCSPWithStrictDynamic);
    }

    if (CSPDirectiveListAllowEval(*policy, this,
                                  ReportingDisposition::kSuppressReporting,
                                  kWillNotThrowException, g_empty_string)) {
      Count(WebFeature::kCSPWithUnsafeEval);
    }

    // We consider a policy to be "reasonably secure" if it:
    //
    // 1.  Asserts `object-src 'none'`.
    // 2.  Asserts `base-uri 'none'` or `base-uri 'self'`.
    // 3.  Avoids URL-based matching, in favor of hashes and nonces.
    //
    // https://chromium.googlesource.com/chromium/src/+/main/docs/security/web-mitigation-metrics.md
    // has more detail.
    if (CSPDirectiveListIsObjectRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableObjectRestrictions
                : WebFeature::kCSPROWithReasonableObjectRestrictions);
    }
    if (CSPDirectiveListIsBaseRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableBaseRestrictions
                : WebFeature::kCSPROWithReasonableBaseRestrictions);
    }
    if (CSPDirectiveListIsScriptRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableScriptRestrictions
                : WebFeature::kCSPROWithReasonableScriptRestrictions);
    }
    if (CSPDirectiveListIsObjectRestrictionReasonable(*policy) &&
        CSPDirectiveListIsBaseRestrictionReasonable(*policy) &&
        CSPDirectiveListIsScriptRestrictionReasonable(*policy)) {
      Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                ? WebFeature::kCSPWithReasonableRestrictions
                : WebFeature::kCSPROWithReasonableRestrictions);

      if (!CSPDirectiveListAllowDynamic(*policy,
                                        CSPDirectiveName::ScriptSrcElem)) {
        Count(policy->header->type == ContentSecurityPolicyType::kEnforce
                  ? WebFeature::kCSPWithBetterThanReasonableRestrictions
                  : WebFeature::kCSPROWithBetterThanReasonableRestrictions);
      }
    }
    if (CSPDirectiveListRequiresTrustedTypes(*policy)) {
      Count(CSPDirectiveListIsReportOnly(*policy)
                ? WebFeature::kTrustedTypesEnabledReportOnly
                : WebFeature::kTrustedTypesEnabledEnforcing);
    }
    if (policy->trusted_types && policy->trusted_types->allow_duplicates) {
      Count(WebFeature::kTrustedTypesAllowDuplicates);
    }
  }
}

ContentSecurityPolicy::~ContentSecurityPolicy() = default;

void ContentSecurityPolicy::Trace(Visitor* visitor) const {
  visitor->Trace(delegate_);
  visitor->Trace(console_messages_);
}

void ContentSecurityPolicy::AddPolicies(
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies) {
  Vector<network::mojom::blink::ContentSecurityPolicyPtr> policies_to_report;
  if (delegate_) {
    policies_to_report = mojo::Clone(policies);
  }

  for (network::mojom::blink::ContentSecurityPolicyPtr& policy : policies) {
    ComputeInternalStateForParsedPolicy(*policy);

    // Report parsing errors in the console.
    for (const String& message : policy->parsing_errors)
      LogToConsole(message);

    policies_.push_back(std::move(policy));
  }

  // Reevaluate whether the composite set of enforced policies are "strict"
  // after these new policies have been added. Since additional policies can
  // only tighten the composite policy, we only need to check this if the policy
  // isn't already "strict".
  if (!enforces_strict_policy_) {
    const bool is_object_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsObjectRestrictionReasonable(*policy);
        });
    const bool is_base_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsBaseRestrictionReasonable(*policy);
        });
    const bool is_script_restriction_reasonable =
        base::ranges::any_of(policies_, [](const auto& policy) {
          return !CSPDirectiveListIsReportOnly(*policy) &&
                 CSPDirectiveListIsScriptRestrictionReasonable(*policy);
        });
    enforces_strict_policy_ = is_object_restriction_reasonable &&
                              is_base_restriction_reasonable &&
                              is_script_restriction_reasonable;
  }

  // If this ContentSecurityPolicy is not bound to a delegate yet, return. The
  // following logic will be executed in BindToDelegate when that will happen.
  if (!delegate_)
    return;

  ApplyPolicySideEffectsToDelegate();
  ReportUseCounters(policies_to_report);

  delegate_->DidAddContentSecurityPolicies(std::move(policies_to_report));
}

void ContentSecurityPolicy::ComputeInternalStateForParsedPolicy(
    const network::mojom::blink::ContentSecurityPolicy& csp) {
  if (csp.header->source == ContentSecurityPolicySource::kHTTP)
    header_delivered_ = true;

  if (csp.block_all_mixed_content && !CSPDirectiveListIsReportOnly(csp))
    EnforceStrictMixedContentChecking();

  if (CSPDirectiveListRequiresTrustedTypes(csp))
    RequireTrustedTypes();

  EnforceSandboxFlags(csp.sandbox);

  if (csp.upgrade_insecure_requests)
    UpgradeInsecureRequests();

  String disable_eval_message;
  if (CSPDirectiveListShouldDisableEval(csp, disable_eval_message) &&
      disable_eval_error_message_.IsNull()) {
    disable_eval_error_message_ = disable_eval_message;
  }

  String disable_wasm_eval_message;
  if (CSPDirectiveListShouldDisableWasmEval(csp, this,
                                            disable_wasm_eval_message) &&
      disable_wasm_eval_error_message_.IsNull()) {
    disable_wasm_eval_error_message_ = disable_wasm_eval_message;
  }

  for (const auto& directive : csp.directives) {
    switch (directive.key) {
      case CSPDirectiveName::DefaultSrc:
        // TODO(mkwst) It seems unlikely that developers would use different
        // algorithms for scripts and styles. We may want to combine the
        // usesScriptHashAlgorithms() and usesStyleHashAlgorithms.
        UsesScriptHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        UsesStyleHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      case CSPDirectiveName::ScriptSrc:
      case CSPDirectiveName::ScriptSrcAttr:
      case CSPDirectiveName::ScriptSrcElem:
        UsesScriptHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      case CSPDirectiveName::StyleSrc:
      case CSPDirectiveName::StyleSrcAttr:
      case CSPDirectiveName::StyleSrcElem:
        UsesStyleHashAlgorithms(HashAlgorithmsUsed(directive.value.get()));
        break;
      default:
        break;
    }
  }
}

void ContentSecurityPolicy::SetOverrideAllowInlineStyle(bool value) {
  override_inline_style_allowed_ = value;
}

// static
void ContentSecurityPolicy::FillInCSPHashValues(
    const String& source,
    uint8_t hash_algorithms_used,
    Vector<network::mojom::blink::CSPHashSourcePtr>& csp_hash_values) {
  // Any additions or subtractions from this struct should also modify the
  // respective entries in the kSupportedPrefixes array in
  // SourceListDirective::parseHash().
  static const struct {
    network::mojom::blink::CSPHashAlgorithm csp_hash_algorithm;
    HashAlgorithm algorithm;
  } kAlgorithmMap[] = {
      {network::mojom::blink::CSPHashAlgorithm::SHA256, kHashAlgorithmSha256},
      {network::mojom::blink::CSPHashAlgorithm::SHA384, kHashAlgorithmSha384},
      {network::mojom::blink::CSPHashAlgorithm::SHA512, kHashAlgorithmSha512}};

  // Only bother normalizing the source/computing digests if there are any
  // checks to be done.
  if (hash_algorithms_used == kContentSecurityPolicyHashAlgorithmNone)
    return;

  StringUTF8Adaptor utf8_source(
      source, kStrictUTF8ConversionReplacingUnpairedSurrogatesWithFFFD);

  for (const auto& algorithm_map : kAlgorithmMap) {
    DigestValue digest;
    if (static_cast<int32_t>(algorithm_map.csp_hash_algorithm) &
        hash_algorithms_used) {
      bool digest_success = ComputeDigest(
          algorithm_map.algorithm, base::as_byte_span(utf8_source), digest);
      if (digest_success) {
        csp_hash_values.push_back(network::mojom::blink::CSPHashSource::New(
            algorithm_map.csp_hash_algorithm, Vector<uint8_t>(digest)));
      }
    }
  }
}

// static
bool ContentSecurityPolicy::CheckHashAgainstPolicy(
    Vector<network::mojom::blink::CSPHashSourcePtr>& csp_hash_values,
    const network::mojom::blink::ContentSecurityPolicy& csp,
    InlineType inline_type) {
  for (const auto& csp_hash_value : csp_hash_values) {
    if (CSPDirectiveListAllowHash(csp, *csp_hash_value, inline_type))
      return true;
  }
  return false;
}

// https://w3c.github.io/webappsec-csp/#should-block-inline
bool ContentSecurityPolicy::AllowInline(
    InlineType inline_type,
    Element* element,
    const String& content,
    const String& nonce,
    const String& context_url,
    const WTF::OrdinalNumber& context_line,
    ReportingDisposition reporting_disposition) {
  DCHECK(element || inline_type == InlineType::kScriptAttribute ||
         inline_type == InlineType::kNavigation);

  const bool is_script = IsScriptInlineType(inline_type);
  if (!is_script && override_inline_style_allowed_) {
    return true;
  }

  Vector<network::mojom::blink::CSPHashSourcePtr> csp_hash_values;
  FillInCSPHashValues(
      content,
      is_script ? script_hash_algorithms_used_ : style_hash_algorithms_used_,
      csp_hash_values);

  // Step 2. Let result be "Allowed". [spec text]
  bool is_allowed = true;

  // Step 3. For each policy in element’s Document's global object’s CSP list:
  // [spec text]
  for (const auto& policy : policies_) {
    // May be allowed by hash, if 'unsafe-hashes' is present in a policy.
    // Check against the digest of the |content| and also check whether inline
    // script is allowed.
    is_allowed &=
        CheckHashAgainstPolicy(csp_hash_values, *policy, inline_type) ||
        CSPDirectiveListAllowInline(*policy, this, inline_type, element,
                                    content, nonce, context_url, context_line,
                                    reporting_disposition);
  }

  return is_allowed;
}

bool ContentSecurityPolicy::IsScriptInlineType(InlineType inline_type) {
  switch (inline_type) {
    case ContentSecurityPolicy::InlineType::kNavigation:
    case ContentSecurityPolicy::InlineType::kScriptSpeculationRules:
    case ContentSecurityPolicy::InlineType::kScriptAttribute:
    case ContentSecurityPolicy::InlineType::kScript:
      return true;

    case ContentSecurityPolicy::InlineType::kStyleAttribute:
    case ContentSecurityPolicy::InlineType::kStyle:
      return false;
  }
}

bool ContentSecurityPolicy::ShouldCheckEval() const {
  for (const auto& policy : policies_) {
    if (CSPDirectiveListShouldCheckEval(*policy))
      return true;
  }
  return IsRequireTrustedTypes();
}

bool ContentSecurityPolicy::AllowEval(
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicy::ExceptionStatus exception_status,
    const String& script_content) {
  bool is_allowed = true;
  for (const auto& policy : policies_) {
    is_allowed &= CSPDirectiveListAllowEval(
        *policy, this, reporting_disposition, exception_status, script_content);
  }
  return is_allowed;
}

bool ContentSecurityPolicy::AllowWasmCodeGeneration(
    ReportingDisposition reporting_disposition,
    ContentSecurityPolicy::ExceptionStatus exception_status,
    const String& script_content) {
  bool is_allowed = true;
  for (const auto& policy : policies_) {
    is_allowed &= CSPDirectiveListAllowWasmCodeGeneration(
        *policy, this, reporting_disposition, exception_status, script_content);
  }
  return is_allowed;
}

String ContentSecurityPolicy::EvalDisabledErrorMessage() const {
  for (const auto& policy : policies_) {
    String message;
    if (CSPDirectiveListShouldDisableEval(*policy, message))
      return message;
  }
  return String();
}

String ContentSecurityPolicy::WasmEvalDisabledErrorMessage() const {
  for (const auto& policy : policies_) {
    String message;
    if (CSPDirectiveListShouldDisableWasmEval(*policy, this, message))
      return message;
  }
  return String();
}

namespace {
std::optional<CSPDirectiveName> GetDirectiveTypeFromRequestContextType(
    mojom::blink::RequestContextType context) {
  switch (context) {
    case mojom::blink::RequestContextType::AUDIO:
    case mojom::blink::RequestContextType::TRACK:
    case mojom::blink::RequestContextType::VIDEO:
      return CSPDirectiveName::MediaSrc;

    case mojom::blink::RequestContextType::ATTRIBUTION_SRC:
    case mojom::blink::RequestContextType::BEACON:
    case mojom::blink::RequestContextType::EVENT_SOURCE:
    case mojom::blink::RequestContextType::FETCH:
    case mojom::blink::RequestContextType::JSON:
    case mojom::blink::RequestContextType::PING:
    case mojom::blink::RequestContextType::XML_HTTP_REQUEST:
    case mojom::blink::RequestContextType::SUBRESOURCE:
    case mojom::blink::RequestContextType::SUBRESOURCE_WEBBUNDLE:
      return CSPDirectiveName::ConnectSrc;

    case mojom::blink::RequestContextType::EMBED:
    case mojom::blink::RequestContextType::OBJECT:
      return CSPDirectiveName::ObjectSrc;

    case mojom::blink::RequestContextType::FAVICON:
    case mojom::blink::RequestContextType::IMAGE:
    case mojom::blink::RequestContextType::IMAGE_SET:
      return CSPDirectiveName::ImgSrc;

    case mojom::blink::RequestContextType::FONT:
      return CSPDirectiveName::FontSrc;

    case mojom::blink::RequestContextType::FORM:
      return CSPDirectiveName::FormAction;

    case mojom::blink::RequestContextType::FRAME:
    case mojom::blink::RequestContextType::IFRAME:
      return CSPDirectiveName::FrameSrc;

    case mojom::blink::RequestContextType::SCRIPT:
    case mojom::blink::RequestContextType::XSLT:
      return CSPDirectiveName::ScriptSrcElem;

    case mojom::blink::RequestContextType::MANIFEST:
      return CSPDirectiveName::ManifestSrc;

    case mojom::blink::RequestContextType::SERVICE_WORKER:
    case mojom::blink::RequestContextType::SHARED_WORKER:
    case mojom::blink::RequestContextType::WORKER:
      return CSPDirectiveName::WorkerSrc;

    case mojom::blink::RequestContextType::STYLE:
      return CSPDirectiveName::StyleSrcElem;

    case mojom::blink::RequestContextType::PREFETCH:
      return CSPDirectiveName::DefaultSrc;

    case mojom::blink::RequestContextType::SPECULATION_RULES:
      // If speculation rules ever supports <script src>, then it will
      // probably be necessary to use ScriptSrcElem in such cases.
      if (!base::FeatureList::IsEnabled(
              features::kExemptSpeculationRulesHeaderFromCSP)) {
        return CSPDirectiveName::ScriptSrc;
      }
      // Speculation Rules loaded from Speculation-Rules header are exempt
      // from CSP checks.
      [[fallthrough]];
    case mojom::blink::RequestContextType::CSP_REPORT:
    case mojom::blink::RequestContextType::DOWNLOAD:
    case mojom::blink::RequestContextType::HYPERLINK:
    case mojom::blink::RequestContextType::INTERNAL:
    case mojom::blink::RequestContextType::LOCATION:
    case mojom::blink::RequestContextType::PLUGIN:
    case mojom::blink::RequestContextType::UNSPECIFIED:
      return std::nullopt;
  }
}

// [spec] https://w3c.github.io/webappsec-csp/#does-resource-hint-violate-policy
bool AllowResourceHintRequestForPolicy(
    network::mojom::blink::ContentSecurityPolicy& csp,
    ContentSecurityPolicy* policy,
    const KURL& url,
    const String& nonce,
    const IntegrityMetadataSet& integrity_metadata,
    ParserDisposition parser_disposition,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition) {
  // The loop ignores default-src directives, which is the directive to report
  // for resource hints. So we don't need to check report-only policies.
  if (csp.header->type == ContentSecurityPolicyType::kEnforce) {
    for (CSPDirectiveName type : {
             CSPDirectiveName::ChildSrc,
             CSPDirectiveName::ConnectSrc,
             CSPDirectiveName::FontSrc,
             CSPDirectiveName::FrameSrc,
             CSPDirectiveName::ImgSrc,
             CSPDirectiveName::ManifestSrc,
             CSPDirectiveName::MediaSrc,
             CSPDirectiveName::ObjectSrc,
             CSPDirectiveName::ScriptSrc,
             CSPDirectiveName::ScriptSrcElem,
             CSPDirectiveName::StyleSrc,
             CSPDirectiveName::StyleSrcElem,
             CSPDirectiveName::WorkerSrc,
         }) {
      if (CSPDirectiveListAllowFromSource(
              csp, policy, type, url, url_before_redirects, redirect_status,
              ReportingDisposition::kSuppressReporting, nonce,
              integrity_metadata, parser_disposition)) {
        return true;
      }
    }
  }
  // Check default-src with the given reporting disposition, to allow reporting
  // if needed.
  return CSPDirectiveListAllowFromSource(
             csp, policy, CSPDirectiveName::DefaultSrc, url,
             url_before_redirects, redirect_status, reporting_disposition,
             nonce, integrity_metadata, parser_disposition)
      .IsAllowed();
}
}  // namespace

// https://w3c.github.io/webappsec-csp/#does-request-violate-policy
bool ContentSecurityPolicy::AllowRequest(
    mojom::blink::RequestContextType context,
    network::mojom::RequestDestination request_destination,
    const KURL& url,
    const String& nonce,
    const IntegrityMetadataSet& integrity_metadata,
    ParserDisposition parser_disposition,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition,
    CheckHeaderType check_header_type) {
  // [spec] https://w3c.github.io/webappsec-csp/#does-request-violate-policy
  // 1. If request’s initiator is "prefetch", then return the result of
  // executing "Does resource hint request violate policy?" on request and
  // policy.
  if (context == mojom::blink::RequestContextType::PREFETCH) {
    return base::ranges::all_of(policies_, [&](const auto& policy) {
      return !CheckHeaderTypeMatches(check_header_type, reporting_disposition,
                                     policy->header->type) ||
             AllowResourceHintRequestForPolicy(
                 *policy, this, url, nonce, integrity_metadata,
                 parser_disposition, url_before_redirects, redirect_status,
                 reporting_disposition);
    });
  }

  std::optional<CSPDirectiveName> type =
      GetDirectiveTypeFromRequestContextType(context);

  if (!type)
    return true;
  return AllowFromSource(*type, url, url_before_redirects, redirect_status,
                         reporting_disposition, check_header_type, nonce,
                         integrity_metadata, parser_disposition);
}

void ContentSecurityPolicy::UsesScriptHashAlgorithms(uint8_t algorithms) {
  script_hash_algorithms_used_ |= algorithms;
}

void ContentSecurityPolicy::UsesStyleHashAlgorithms(uint8_t algorithms) {
  style_hash_algorithms_used_ |= algorithms;
}

bool ContentSecurityPolicy::AllowFromSource(
    CSPDirectiveName type,
    const KURL& url,
    const KURL& url_before_redirects,
    RedirectStatus redirect_status,
    ReportingDisposition reporting_disposition,
    CheckHeaderType check_header_type,
    const String& nonce,
    const IntegrityMetadataSet& hashes,
    ParserDisposition parser_disposition) {
  SchemeRegistry::PolicyAreas area = SchemeRegistry::kPolicyAreaAll;
  if (type == CSPDirectiveName::ImgSrc)
    area = SchemeRegistry::kPolicyAreaImage;
  else if (type == CSPDirectiveName::StyleSrcElem)
    area = SchemeRegistry
```