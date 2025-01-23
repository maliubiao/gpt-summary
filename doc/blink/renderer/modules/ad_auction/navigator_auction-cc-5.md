Response:
My thinking process to arrive at the summary of `navigator_auction.cc` went something like this:

1. **Understand the Request:** The request asks for the file's functionality, its relationship to web technologies, logical reasoning examples, common errors, debugging steps, and a final summary, considering this is part 6 of 6.

2. **Initial Scan for Keywords:** I immediately looked for prominent keywords related to its domain: "auction," "ads," "interest group," "fenced frame," and terms like "join," "leave," "bid," "sell," "resolve," "promise," "JavaScript," "HTML," "CSS."  These give a high-level understanding of the code's purpose.

3. **Identify Key Classes and Methods:** I focused on the main class `NavigatorAuction` and its public methods, like `runAdAuction`, `joinAdInterestGroup`, `leaveAdInterestGroup`, `finalizeAd`, `getInterestGroupAdAuctionData`, and helper methods like `AuctionComplete`, `JoinComplete`, etc. The names of these methods directly suggest their functions. The nested class `AuctionHandle` also stood out as central to the auction process.

4. **Trace Data Flow:** I started to follow the flow of data and control. For example, `runAdAuction` takes JavaScript arguments, creates a Mojo call (`ad_auction_service_->RunAuction`), and eventually resolves a JavaScript Promise. This reveals the interaction between JavaScript and the underlying browser service.

5. **Identify Interactions with Web Technologies:**
    * **JavaScript:** The file heavily uses `ScriptPromise`, `ScriptState`, and interacts directly with JavaScript objects like `Ads` and `AuctionAdConfig`. The functions are exposed to JavaScript.
    * **HTML:** The mention of "fenced frames" directly connects to HTML elements. The ability to load ads in fenced frames is explicitly checked (`canLoadAdAuctionFencedFrame`).
    * **CSS:** While not as direct, the *result* of an ad auction (a URL or a fenced frame configuration) will ultimately be used to load content that *can* be styled with CSS. The connection is indirect but important.

6. **Analyze Logical Reasoning:**  I looked for conditional statements (`if`, `else`), checks (e.g., `ValidateAdsObject`, security checks), and error handling (throwing `DOMException`). The `MaybeResolveAuction` method illustrates a two-step resolution process based on the completion of different asynchronous operations.

7. **Consider Potential Errors:**  I looked for error conditions, especially those that would result in rejecting Promises. Invalid arguments, permission denials, unimplemented features, and security violations stood out.

8. **Map User Actions to Code Execution:** I thought about how a user interacts with a webpage that uses these APIs. Actions like visiting a site, interacting with content, or a website attempting to join an interest group are the triggers that lead to these functions being called.

9. **Pay Attention to Asynchronous Operations:** The extensive use of Promises and callbacks signals asynchronous operations. Understanding how these callbacks are handled is crucial.

10. **Address the "Part 6 of 6" Constraint:**  Knowing this is the final part, the summary needs to be comprehensive, covering the main functionalities of the file as a whole.

11. **Structure the Summary:**  I organized the information into logical categories: Core Functionality, Web Technology Relationships, Logical Reasoning, User Errors, Debugging, and the final overall Summary. This provides a clear and structured explanation.

12. **Refine and Elaborate:** I went back through my notes and added more detail and specific examples to each section. For instance, for JavaScript interaction, I mentioned the types of data being exchanged. For HTML, I specifically mentioned fenced frames.

13. **Focus on the "Why":**  Beyond just listing the functions, I aimed to explain *why* these functions exist and how they contribute to the overall ad auction process.

By following these steps, I could dissect the code, understand its purpose, identify its connections to web technologies, and formulate a comprehensive and informative summary that addresses all aspects of the request, while keeping in mind the context of it being the final part of a larger exploration.
Let's break down the functionality of `blink/renderer/modules/ad_auction/navigator_auction.cc`, considering it's the final part of a series.

**Core Functionality of `navigator_auction.cc`**

This file implements the `NavigatorAuction` class, which provides the JavaScript API for interacting with the Privacy Sandbox's Ad Auction functionality (specifically, the FLEDGE/Protected Audience API). It acts as a bridge between JavaScript code running in a web page and the underlying browser's ad auction service.

Here's a breakdown of its key responsibilities:

1. **Initiating and Managing Ad Auctions (`runAdAuction`):**
   - Takes an `AuctionConfig` object from JavaScript as input.
   - Converts this JavaScript configuration into a Mojo IPC message.
   - Sends a request to the browser's `AdAuctionServiceImpl` to start an ad auction.
   - Handles the asynchronous response from the browser, which can be a winning ad URL or a fenced frame configuration.
   - Resolves the JavaScript Promise returned by `runAdAuction` with the auction result.

2. **Joining and Leaving Interest Groups (`joinAdInterestGroup`, `leaveAdInterestGroup`):**
   - Implements the `navigator.joinAdInterestGroup()` and `navigator.leaveAdInterestGroup()` JavaScript methods.
   - Takes interest group data from JavaScript.
   - Sends requests to the browser's `AdAuctionServiceImpl` to add or remove the browsing context from an interest group.
   - Handles cross-origin join/leave operations, potentially waiting for well-known checks.
   - Resolves the JavaScript Promise when the operation completes.

3. **Finalizing Ad Impressions (`finalizeAd`):**
   - Implements the `navigator.finalizeAd()` JavaScript method.
   - Takes information about the displayed ad (the `Ads` object and `AuctionAdConfig`).
   - Sends a request to the browser to record the winning ad impression and potentially trigger post-auction actions.
   - Resolves the JavaScript Promise with the creative URL.

4. **Clearing Interest Groups (`clearOriginJoinedInterestGroups`):**
   - Implements a mechanism to clear interest groups joined by the current origin.

5. **Managing Fenced Frame Loading Permissions (`canLoadAdAuctionFencedFrame`):**
   - Determines if a fenced frame can be loaded in the current context, considering security policies (CSP, sandbox flags), and fenced frame nesting rules.

6. **Providing Access to Protected Audience API (`protectedAudience`):**
   - Returns an instance of the `ProtectedAudience` object, which exposes additional functionality related to interest group management.

7. **Retrieving Interest Group Auction Data (`getInterestGroupAdAuctionData`):**
   - Implements the `navigator.getInterestGroupAdAuctionData()` method.
   - Allows retrieving data to be used in the bidding process.
   - Handles configuration options like request size and per-buyer configurations.
   - Returns a JavaScript Promise resolving with the auction data.

**Relationships with JavaScript, HTML, and CSS**

* **JavaScript:** This file is fundamentally about providing JavaScript APIs. The methods in `NavigatorAuction` are directly callable from JavaScript code running on a web page. It handles JavaScript objects (`AuctionConfig`, `Ads`), resolves JavaScript Promises, and throws JavaScript exceptions.

   * **Example:** A website's JavaScript could call `navigator.runAdAuction(config)` to initiate an auction. The `config` object would be created and populated in JavaScript. The result of the auction (a URL or `FencedFrameConfig`) is then returned to the JavaScript as a Promise resolution.

* **HTML:** The concept of **fenced frames** is central to the ad auction functionality, especially for displaying the winning ad. The `canLoadAdAuctionFencedFrame` method directly checks conditions related to loading content within a `<fencedframe>`.

   * **Example:**  If `runAdAuction` resolves with a `FencedFrameConfig`, the website's JavaScript would then create a `<fencedframe>` element and set its `config` attribute using the returned configuration.

* **CSS:** While this file doesn't directly manipulate CSS, the *outcome* of an ad auction often involves displaying an ad, which is styled using CSS. The URL returned by a successful auction will point to content that can be styled. Fenced frames also have their own isolated styling context.

   * **Example:** The winning ad creative loaded within a fenced frame would have its own CSS rules applied, isolated from the embedding page's CSS.

**Logical Reasoning Examples (Hypothetical)**

Let's consider the `MaybeResolveAuction` method within `AuctionHandle`:

* **Assumption:**  The `runAdAuction` call has completed, and the browser has returned an `auction_config_` (containing the winning ad details). Separately, the website's JavaScript might have called `resolveToConfig(true)` or `resolveToConfig(false)` on the `AuctionHandle` object (though this specific part isn't directly shown in this snippet).

* **Input 1 (resolveToConfig_ is true):**
    - `resolve_to_config_` has the value `true`.
    - `auction_resolver_` is a valid `ScriptPromiseResolver`.
    - `auction_config_` contains a valid `FencedFrameConfig`.

* **Output 1:** The `auction_resolver_`'s Promise will be resolved with a `V8UnionFencedFrameConfigOrUSVString` object containing the full `FencedFrameConfig`.

* **Input 2 (resolveToConfig_ is false):**
    - `resolve_to_config_` has the value `false`.
    - `auction_resolver_` is a valid `ScriptPromiseResolver`.
    - `auction_config_` contains a valid `FencedFrameConfig` with a `urn_uuid`.

* **Output 2:** The `auction_resolver_`'s Promise will be resolved with a `V8UnionFencedFrameConfigOrUSVString` object containing the URN (Uniform Resource Name) representing the fenced frame content.

**User and Programming Errors**

* **Incorrect `AuctionConfig`:**  If the JavaScript code provides an invalid `AuctionConfig` object (e.g., missing required fields, incorrect data types), the `ValidateAuctionConfig` function (not shown in this snippet but likely exists) would return an error, and the Promise would be rejected with a TypeError.

   * **Example:** Forgetting to specify the `seller` or providing an invalid URL for the `seller`.

* **Permissions Policy Errors:** If the website is embedded in a context that disallows the `run-ad-auction` feature via Permissions Policy, calling `navigator.runAdAuction()` will result in a `NotAllowedError` DOMException.

   * **Example:** An `<iframe>` with an attribute like `allow="camera"` but not `allow="run-ad-auction"`.

* **Security Context Errors:**  Many ad auction APIs require a secure context (HTTPS). Calling these APIs on an insecure page (HTTP) will lead to errors.

   * **Example:** Trying to call `navigator.joinAdInterestGroup()` on an `http://` page.

* **Unimplemented Features:** The code contains `TODO` comments indicating that some functionality is not yet fully implemented. Trying to use these unimplemented parts might result in a `NotSupportedError`.

   * **Example:** The `FinalizeAdComplete` function currently rejects with a `NotSupportedError`.

**User Operations Leading Here (Debugging Clues)**

To reach the code in `navigator_auction.cc`, the following steps would typically occur:

1. **User visits a website:** The user navigates to a webpage in their Chromium-based browser.
2. **Website JavaScript execution:** The website's JavaScript code runs.
3. **Ad Auction API call:** The JavaScript code calls one of the `navigator.adAuction.*` methods, such as:
   - `navigator.runAdAuction(config)` to initiate an auction.
   - `navigator.joinAdInterestGroup(interestGroup)` to join an interest group.
   - `navigator.leaveAdInterestGroup(interestGroup)` to leave an interest group.
   - `navigator.finalizeAd(ads, config)` to finalize an ad impression.
   - `navigator.getInterestGroupAdAuctionData(config)` to get auction data.
4. **Blink rendering engine processes the call:** The Blink rendering engine receives this JavaScript call and routes it to the appropriate implementation, which is the `NavigatorAuction` class in this file.
5. **Mojo IPC call:** The `NavigatorAuction` class then communicates with the browser process (specifically, the `AdAuctionServiceImpl`) using Mojo Inter-Process Communication (IPC).
6. **Browser process handles the request:** The browser process performs the actual auction logic, interacts with storage for interest groups, etc.
7. **Response and Promise resolution:** The browser process sends a response back to the renderer process, which is handled by the `NavigatorAuction` class, eventually resolving the JavaScript Promise.

**Summary of `navigator_auction.cc` Functionality (as Part 6 of 6)**

Given this is the final part, we can synthesize a comprehensive summary:

`navigator_auction.cc` is the **cornerstone** of the client-side implementation of the Privacy Sandbox's Ad Auction API (FLEDGE/Protected Audience) within the Chromium Blink rendering engine. It serves as the **primary interface** between JavaScript running on a webpage and the browser's underlying ad auction capabilities. This file encapsulates the logic for:

* **Initiating and managing the entire ad auction lifecycle**, from receiving the initial configuration from JavaScript to resolving with the winning ad creative (URL or fenced frame configuration).
* **Enabling websites to participate in the Protected Audience API** by joining and leaving interest groups on behalf of the user.
* **Facilitating the reporting of ad impressions** through the `finalizeAd` API.
* **Enforcing security and privacy considerations** by checking permissions, secure contexts, and fenced frame loading rules.
* **Providing access to auxiliary features** like retrieving auction-specific data.

In essence, `navigator_auction.cc` is the **glue** that binds the JavaScript API exposed to web developers with the complex, privacy-preserving ad auction mechanisms implemented within the browser. It handles the translation and communication between these two layers, ensuring the Ad Auction API can be utilized effectively and securely by web pages. This file is crucial for enabling the core functionality of the Privacy Sandbox's efforts to provide interest-based advertising in a privacy-respecting manner.

### 提示词
```
这是目录为blink/renderer/modules/ad_auction/navigator_auction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
/*auction_id=*/nullptr, *config,
                                   *mojo_config);

  if (!ValidateAdsObject(exception_state, ads)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ad_auction_service_->FinalizeAd(
      ads->GetGuid(), std::move(mojo_config),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &NavigatorAuction::FinalizeAdComplete, WrapPersistent(this))));
  return promise;
}

/* static */
ScriptPromise<IDLString> NavigatorAuction::finalizeAd(
    ScriptState* script_state,
    Navigator& navigator,
    const Ads* ads,
    const AuctionAdConfig* config,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  return From(ExecutionContext::From(script_state), navigator)
      .finalizeAd(script_state, ads, config, exception_state);
}

void NavigatorAuction::FinalizeAdComplete(
    ScriptPromiseResolver<IDLString>* resolver,
    const std::optional<KURL>& creative_url) {
  if (creative_url) {
    resolver->Resolve(*creative_url);
  } else {
    // TODO(https://crbug.com/1249186): Add full impl of methods.
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotSupportedError,
        "finalizeAd API not yet implemented"));
  }
}

void NavigatorAuction::StartJoin(PendingJoin&& pending_join) {
  ad_auction_service_->JoinInterestGroup(std::move(pending_join.interest_group),
                                         std::move(pending_join.callback));
}

void NavigatorAuction::JoinComplete(
    bool is_cross_origin,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool failed_well_known_check) {
  if (is_cross_origin) {
    queued_cross_site_joins_.OnComplete();
  }

  if (failed_well_known_check) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotAllowedError,
        "Permission to join interest group denied."));
    return;
  }
  resolver->Resolve();
}

void NavigatorAuction::StartLeave(PendingLeave&& pending_leave) {
  ad_auction_service_->LeaveInterestGroup(pending_leave.owner,
                                          pending_leave.name,
                                          std::move(pending_leave.callback));
}

void NavigatorAuction::LeaveComplete(
    bool is_cross_origin,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool failed_well_known_check) {
  if (is_cross_origin) {
    queued_cross_site_leaves_.OnComplete();
  }

  if (failed_well_known_check) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotAllowedError,
        "Permission to leave interest group denied."));
    return;
  }
  resolver->Resolve();
}

void NavigatorAuction::StartClear(PendingClear&& pending_clear) {
  ad_auction_service_->ClearOriginJoinedInterestGroups(
      pending_clear.owner, pending_clear.interest_groups_to_keep,
      std::move(pending_clear.callback));
}

void NavigatorAuction::ClearComplete(
    bool is_cross_origin,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool failed_well_known_check) {
  if (is_cross_origin) {
    queued_cross_site_clears_.OnComplete();
  }

  if (failed_well_known_check) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotAllowedError,
        "Permission to leave interest groups denied."));
    return;
  }
  resolver->Resolve();
}

void NavigatorAuction::AuctionHandle::AuctionComplete(
    ScriptPromiseResolver<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>*
        resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    base::TimeTicks start_time,
    bool is_server_auction,
    bool aborted_by_script,
    const std::optional<FencedFrame::RedactedFencedFrameConfig>&
        result_config) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  AbortSignal* abort_signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
  ScriptState* script_state = resolver->GetScriptState();
  ScriptState::Scope script_state_scope(script_state);
  bool resolved_auction = false;
  if (aborted_by_script) {
    if (abort_signal && abort_signal->aborted()) {
      resolver->Reject(abort_signal->reason(script_state));
    } else {
      // TODO(morlovich): It would probably be better to wire something more
      // precise.
      resolver->RejectWithTypeError(
          "Promise argument rejected or resolved to invalid value.");
    }
  } else if (result_config) {
    DCHECK(result_config->mapped_url().has_value());
    DCHECK(!result_config->mapped_url()->potentially_opaque_value.has_value());

    auction_resolver_ = resolver;
    auction_config_ = result_config;

    resolved_auction = MaybeResolveAuction();
  } else {
    resolver->Resolve(nullptr);
    resolved_auction = true;
  }
  if (resolved_auction) {
    std::string uma_prefix = "Ads.InterestGroup.Auction.";
    if (is_server_auction) {
      uma_prefix = "Ads.InterestGroup.ServerAuction.";
    }
    base::UmaHistogramTimes(uma_prefix + "TimeToResolve",
                            base::TimeTicks::Now() - start_time);
  }
}

bool NavigatorAuction::AuctionHandle::MaybeResolveAuction() {
  if (!resolve_to_config_.has_value() || !auction_resolver_ ||
      !auction_config_.has_value()) {
    // Once both the resolveToConfig promise is resolved and the auction is
    // completed, this function will be called again to actually
    // complete the auction.
    return false;
  }

  if (resolve_to_config_.value() == true) {
    auction_resolver_->Resolve(
        MakeGarbageCollected<V8UnionFencedFrameConfigOrUSVString>(
            FencedFrameConfig::From(auction_config_.value())));
  } else {
    auction_resolver_->Resolve(
        MakeGarbageCollected<V8UnionFencedFrameConfigOrUSVString>(
            KURL(auction_config_->urn_uuid().value())));
  }
  return true;
}

void NavigatorAuction::GetURLFromURNComplete(
    ScriptPromiseResolver<IDLUSVString>* resolver,
    const std::optional<KURL>& decoded_url) {
  if (decoded_url) {
    resolver->Resolve(*decoded_url);
  } else {
    resolver->Resolve(String());
  }
}

void NavigatorAuction::ReplaceInURNComplete(
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  resolver->Resolve();
}

bool NavigatorAuction::canLoadAdAuctionFencedFrame(ScriptState* script_state) {
  if (!script_state->ContextIsValid()) {
    return false;
  }

  LocalFrame* frame_to_check = LocalDOMWindow::From(script_state)->GetFrame();
  ExecutionContext* context = ExecutionContext::From(script_state);
  DCHECK(frame_to_check && context);

  // "A fenced frame tree of one mode cannot contain a child fenced frame of
  // another mode."
  // See: https://github.com/WICG/fenced-frame/blob/master/explainer/modes.md
  if (frame_to_check->GetPage()->IsMainFrameFencedFrameRoot() &&
      frame_to_check->GetPage()->DeprecatedFencedFrameMode() !=
          blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds) {
    return false;
  }

  if (!context->IsSecureContext()) {
    return false;
  }

  // Check that the flags specified in kFencedFrameMandatoryUnsandboxedFlags
  // are not set in this context. Fenced frames loaded in a sandboxed document
  // require these flags to remain unsandboxed.
  if (context->IsSandboxed(kFencedFrameMandatoryUnsandboxedFlags)) {
    return false;
  }

  // Check the results of the browser checks for the current frame.
  // If the embedding frame is an iframe with CSPEE set, or any ancestor
  // iframes has CSPEE set, the fenced frame will not be allowed to load.
  // The renderer has no knowledge of CSPEE up the ancestor chain, so we defer
  // to the browser to determine the existence of CSPEE outside of the scope
  // we can see here.
  if (frame_to_check->AncestorOrSelfHasCSPEE()) {
    return false;
  }

  // Ensure that if any CSP headers are set that will affect a fenced frame,
  // they allow all https urls to load. Opaque-ads fenced frames do not
  // support allowing/disallowing specific hosts, as that could reveal
  // information to a fenced frame about its embedding page. See design doc
  // for more info:
  // https://github.com/WICG/fenced-frame/blob/master/explainer/interaction_with_content_security_policy.md
  // This is being checked in the renderer because processing of <meta> tags
  // (including CSP) happen in the renderer after navigation commit, so we
  // can't piggy-back off of the ancestor_or_self_has_cspee bit being sent
  // from the browser (which is sent at commit time) since it doesn't know
  // about all the CSP headers yet.
  ContentSecurityPolicy* csp = context->GetContentSecurityPolicy();
  DCHECK(csp);
  if (!csp->AllowFencedFrameOpaqueURL()) {
    return false;
  }

  return true;
}

/* static */
bool NavigatorAuction::canLoadAdAuctionFencedFrame(ScriptState* script_state,
                                                   Navigator& navigator) {
  if (!navigator.DomWindow()) {
    return false;
  }
  return From(ExecutionContext::From(script_state), navigator)
      .canLoadAdAuctionFencedFrame(script_state);
}

bool NavigatorAuction::deprecatedRunAdAuctionEnforcesKAnonymity(
    ScriptState* script_state,
    Navigator&) {
  return base::FeatureList::IsEnabled(
      blink::features::kFledgeEnforceKAnonymity);
}

// static
ProtectedAudience* NavigatorAuction::protectedAudience(
    ScriptState* script_state,
    Navigator& navigator) {
  if (!navigator.DomWindow()) {
    return nullptr;
  }
  return From(ExecutionContext::From(script_state), navigator)
      .protected_audience_;
}

ScriptPromise<AdAuctionData> NavigatorAuction::getInterestGroupAdAuctionData(
    ScriptState* script_state,
    const AdAuctionDataConfig* config,
    ExceptionState& exception_state,
    base::TimeTicks start_time) {
  CHECK(config);
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }

  scoped_refptr<const SecurityOrigin> seller = ParseOrigin(config->seller());
  if (!seller) {
    exception_state.ThrowTypeError(String::Format(
        "seller '%s' for AdAuctionDataConfig must be a valid https origin.",
        config->seller().Utf8().c_str()));
    return EmptyPromise();
  }

  scoped_refptr<const SecurityOrigin> coordinator;
  if (config->hasCoordinatorOrigin()) {
    coordinator = ParseOrigin(config->coordinatorOrigin());
    if (!coordinator) {
      exception_state.ThrowTypeError(String::Format(
          "coordinatorOrigin '%s' for AdAuctionDataConfig must be "
          "a valid https origin.",
          config->coordinatorOrigin().Utf8().c_str()));
      return EmptyPromise();
    }
  }

  mojom::blink::AuctionDataConfigPtr config_ptr =
      mojom::blink::AuctionDataConfig::New();

  if (config->hasRequestSize()) {
    config_ptr->request_size = config->requestSize();
  }

  base::CheckedNumeric<uint32_t> default_request_size = 0;
  if (config->hasPerBuyerConfig()) {
    bool all_have_target_size = true;
    for (const auto& per_buyer_config : config->perBuyerConfig()) {
      scoped_refptr<const SecurityOrigin> buyer =
          ParseOrigin(per_buyer_config.first);
      if (!buyer) {
        exception_state.ThrowTypeError(String::Format(
            "buyer origin '%s' for AdAuctionDataConfig must be a valid "
            "https origin.",
            per_buyer_config.first.Utf8().c_str()));
        return EmptyPromise();
      }

      mojom::blink::AuctionDataBuyerConfigPtr per_buyer_config_ptr =
          mojom::blink::AuctionDataBuyerConfig::New();
      if (per_buyer_config.second->hasTargetSize()) {
        per_buyer_config_ptr->target_size =
            per_buyer_config.second->targetSize();
        default_request_size += per_buyer_config.second->targetSize();
      } else {
        all_have_target_size = false;
      }
      config_ptr->per_buyer_configs.insert(std::move(buyer),
                                           std::move(per_buyer_config_ptr));
    }

    // If there is no request size specified, use the sum of all target sizes
    // as the request size.
    if (!config->hasRequestSize()) {
      if (!all_have_target_size) {
        exception_state.ThrowTypeError(
            "All per-buyer configs must have a target size when request size "
            "is not specified.");
        return EmptyPromise();
      }
      if (!default_request_size.IsValid()) {
        exception_state.ThrowTypeError("Computed request size is invalid.");
        return EmptyPromise();
      }
      config_ptr->request_size = default_request_size.ValueOrDie();
    }
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<AdAuctionData>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  ad_auction_service_->GetInterestGroupAdAuctionData(
      seller, coordinator, std::move(config_ptr),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &NavigatorAuction::GetInterestGroupAdAuctionDataComplete,
          WrapPersistent(this), std::move(start_time))));
  return promise;
}

void NavigatorAuction::GetInterestGroupAdAuctionDataComplete(
    base::TimeTicks start_time,
    ScriptPromiseResolver<AdAuctionData>* resolver,
    mojo_base::BigBuffer data,
    const std::optional<base::Uuid>& request_id,
    const WTF::String& error_message) {
  if (!error_message.empty()) {
    CHECK(!request_id);
    resolver->RejectWithTypeError(error_message);
    return;
  }

  AdAuctionData* result = AdAuctionData::Create();
  auto not_shared = NotShared<DOMUint8Array>(DOMUint8Array::Create(data));
  result->setRequest(std::move(not_shared));
  std::string request_id_str;
  if (request_id) {
    request_id_str = request_id->AsLowercaseString();
  }
  result->setRequestId(WebString::FromLatin1(request_id_str));
  resolver->Resolve(result);
  base::UmaHistogramTimes(
      "Ads.InterestGroup.GetInterestGroupAdAuctionData.TimeToResolve",
      base::TimeTicks::Now() - start_time);
}

/* static */
ScriptPromise<AdAuctionData> NavigatorAuction::getInterestGroupAdAuctionData(
    ScriptState* script_state,
    Navigator& navigator,
    const AdAuctionDataConfig* config,
    ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  const ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->IsFeatureEnabled(
          blink::mojom::PermissionsPolicyFeature::kRunAdAuction)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Feature run-ad-auction is not enabled by Permissions Policy");
    return EmptyPromise();
  }

  return From(ExecutionContext::From(script_state), navigator)
      .getInterestGroupAdAuctionData(script_state, config, exception_state,
                                     std::move(start_time));
}

}  // namespace blink
```