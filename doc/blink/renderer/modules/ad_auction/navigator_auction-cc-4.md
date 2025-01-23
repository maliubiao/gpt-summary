Response:
The user wants a summary of the functionality of the provided C++ source code file. I need to identify the main tasks performed by the code, and if they relate to web technologies like JavaScript, HTML, and CSS. I also need to look for logical deductions based on inputs and outputs, common user errors, and the steps a user might take to reach this code. Finally, since this is part 5 of 6, I should focus on summarizing the functionalities within this specific code snippet.

Here's a breakdown of the code's functionality:

1. **Managing Ad Interest Groups:** The code defines methods for joining, leaving, and clearing ad interest groups. These operations are core to the FLEDGE/Protected Audience API.
2. **Running Ad Auctions:** The code includes the `runAdAuction` method, which initiates the process of selecting an ad through an auction.
3. **Generating Auction Nonces:** The `createAuctionNonce` method produces unique identifiers for auctions.
4. **URN Handling (Deprecated):**  The code contains deprecated functions for converting URNs to URLs and replacing parts of URNs. These seem related to how ad creatives are referenced.
5. **Creating Ad Requests:** The `createAdRequest` function is intended to create requests for ads (though marked as not yet fully implemented).
6. **Finalizing Ads:** The `finalizeAd` function appears to be part of the process of preparing a selected ad for display.
7. **Internal Mechanics:** The code also handles communication with the browser process (`AdAuctionService`), manages queues for cross-site operations, and performs data conversion between JavaScript and C++ types.
Based on the provided code snippet from `blink/renderer/modules/ad_auction/navigator_auction.cc`, here's a summary of its functionality:

**Core Functionality:**

This part of the `NavigatorAuction` class in Blink is primarily responsible for implementing the JavaScript APIs related to managing ad interest groups and initiating ad auctions. It acts as an intermediary, translating JavaScript calls into corresponding actions within the Chromium browser process.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This file directly implements the JavaScript APIs exposed through the `navigator.joinAdInterestGroup()`, `navigator.leaveAdInterestGroup()`, `navigator.clearOriginJoinedAdInterestGroups()`, `navigator.runAdAuction()`, `navigator.createAuctionNonce()`, and other related methods. These methods are called from JavaScript code within web pages.
    * **Example:** A website's JavaScript code might call `navigator.joinAdInterestGroup({...})` to add the user to an interest group. This call will eventually be handled by the `NavigatorAuction::joinAdInterestGroup` method in this file.
* **HTML:** While this specific C++ file doesn't directly manipulate HTML, the results of ad auctions orchestrated by this code often lead to the rendering of HTML elements, such as `<iframe>` or `<fencedframe>`, to display the winning ad.
* **CSS:** Similarly, this C++ code doesn't directly interact with CSS. However, the rendered ads (which are the outcome of the auctions) will often utilize CSS for styling.

**Logical Inference Examples:**

* **Assumption:** A website calls `navigator.joinAdInterestGroup()` with a valid `AuctionAdInterestGroup` object.
    * **Input:** A JavaScript object representing the ad interest group (e.g., name, owner, bidding logic URL).
    * **Output:** The C++ code will create a corresponding `mojom::blink::InterestGroup` object and send it to the browser process via the `ad_auction_service_`. If successful, the JavaScript promise returned by `joinAdInterestGroup()` will resolve.
* **Assumption:** A website calls `navigator.runAdAuction()` with a valid `AuctionAdConfig` object.
    * **Input:** A JavaScript object configuring the ad auction (e.g., seller, decision logic URL, interest group buyers).
    * **Output:** The C++ code will create a `mojom::blink::AdAuctionConfig` object and initiate the auction in the browser process via `ad_auction_service_->RunAdAuction()`. The JavaScript promise returned by `runAdAuction()` will eventually resolve with the auction result (either a `FencedFrameConfig` or a URL).

**User or Programming Common Usage Errors:**

* **Invalid Origin for Interest Group:** If a website attempts to join an interest group with an `owner` that is not a valid HTTPS origin, the `ParseOrigin()` function will return null, and a `TypeError` will be thrown in JavaScript.
    * **Example:**  `navigator.joinAdInterestGroup({ owner: 'http://example.com', ... })` will fail because the owner is not HTTPS.
* **Calling FLEDGE APIs from Non-HTTPS Contexts:**  Many FLEDGE APIs, like `leaveAdInterestGroup` and `clearOriginJoinedAdInterestGroups`, enforce that they can only be called from secure (HTTPS) origins. Attempting to call them from an HTTP page will result in a `SecurityError`.
    * **Example:** JavaScript code on an `http://example.com` page calling `navigator.leaveAdInterestGroup(...)` will throw an error.
* **Permissions Policy Blocking:** If the necessary Permissions Policy headers are not set, attempting to call FLEDGE APIs might result in a `NotAllowedError`.
    * **Example:** If the `join-ad-interest-group` feature is not allowed by the Permissions Policy, calling `navigator.joinAdInterestGroup()` will throw an error.

**User Operation Steps to Reach Here (as a debugging clue):**

1. **User visits a website:** The user navigates to a webpage in their Chromium browser.
2. **Website JavaScript interacts with FLEDGE APIs:** The website's JavaScript code calls one of the `navigator.adAuction.*` methods (e.g., `joinAdInterestGroup`, `runAdAuction`).
3. **Blink processes the JavaScript call:** The Blink rendering engine (specifically, the JavaScript engine) executes the JavaScript code.
4. **Call to `NavigatorAuction` methods:** The JavaScript call is routed to the corresponding C++ method within the `NavigatorAuction` class in this file.
5. **Communication with the Browser Process:** The `NavigatorAuction` methods prepare data and use the `ad_auction_service_` (an interface to the browser process) to initiate the requested action.

**Summary of Functionality in this Part (Part 5):**

This section of `NavigatorAuction.cc` focuses on providing the JavaScript API implementations for:

* **Joining and leaving ad interest groups:**  Handling both same-origin and cross-origin requests with queuing for cross-origin operations.
* **Clearing ad interest groups:** Allowing a website to remove specific interest groups associated with an origin.
* **Updating ad interest groups:** Triggering the browser to fetch updates for interest groups.
* **Generating auction nonces:** Creating unique identifiers for ad auctions.
* **Running ad auctions:** Initiating the ad auction process based on a provided configuration.
* **Accessing ad auction components:**  Retrieving URLs of ad components from a previous auction result.
* **Deprecated URN to URL conversion and replacement:**  Older mechanisms for handling ad creative URLs.
* **Creating ad requests:**  An interface to request ads (currently not fully implemented).
* **Finalizing ads:** Preparing a selected ad for rendering based on auction configuration.

In essence, this part of the code bridges the gap between JavaScript code running in a web page and the underlying browser functionalities responsible for managing ad interest groups and orchestrating the ad auction process within the FLEDGE/Protected Audience framework.

### 提示词
```
这是目录为blink/renderer/modules/ad_auction/navigator_auction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
etIsolate()));
  }

  auction_handle()->MaybeResolveAuction();
}

NavigatorAuction::NavigatorAuction(Navigator& navigator)
    : Supplement(navigator),
      queued_cross_site_joins_(kMaxActiveCrossSiteJoins,
                               WTF::BindRepeating(&NavigatorAuction::StartJoin,
                                                  WrapWeakPersistent(this))),
      queued_cross_site_leaves_(
          kMaxActiveCrossSiteLeaves,
          WTF::BindRepeating(&NavigatorAuction::StartLeave,
                             WrapWeakPersistent(this))),
      queued_cross_site_clears_(
          kMaxActiveCrossSiteClears,
          WTF::BindRepeating(&NavigatorAuction::StartClear,
                             WrapWeakPersistent(this))),
      ad_auction_service_(navigator.GetExecutionContext()),
      protected_audience_(MakeGarbageCollected<ProtectedAudience>(
          navigator.GetExecutionContext())) {
  navigator.GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
      ad_auction_service_.BindNewPipeAndPassReceiver(
          navigator.GetExecutionContext()->GetTaskRunner(
              TaskType::kMiscPlatformAPI)));
}

NavigatorAuction& NavigatorAuction::From(ExecutionContext* context,
                                         Navigator& navigator) {
  NavigatorAuction* supplement =
      Supplement<Navigator>::From<NavigatorAuction>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<NavigatorAuction>(navigator);
    ProvideTo(navigator, supplement);
  }
  return *supplement;
}

const char NavigatorAuction::kSupplementName[] = "NavigatorAuction";

ScriptPromise<IDLUndefined> NavigatorAuction::joinAdInterestGroup(
    ScriptState* script_state,
    AuctionAdInterestGroup* mutable_group,
    std::optional<double> lifetime_seconds,
    ExceptionState& exception_state) {
  const ExecutionContext* context = ExecutionContext::From(script_state);

  // TODO(crbug.com/1441988): Remove this code after rename is complete.
  if (!HandleOldDictNamesJoin(mutable_group, exception_state)) {
    return EmptyPromise();
  }
  const AuctionAdInterestGroup* group = mutable_group;

  auto mojo_group = mojom::blink::InterestGroup::New();
  if (!CopyLifetimeIdlToMojo(exception_state, lifetime_seconds, *group,
                             *mojo_group)) {
    return EmptyPromise();
  }
  if (!CopyOwnerFromIdlToMojo(*context, exception_state, *group, *mojo_group)) {
    return EmptyPromise();
  }
  mojo_group->name = group->name();
  mojo_group->priority = (group->hasPriority()) ? group->priority() : 0.0;

  mojo_group->enable_bidding_signals_prioritization =
      group->hasEnableBiddingSignalsPrioritization()
          ? group->enableBiddingSignalsPrioritization()
          : false;
  if (group->hasPriorityVector()) {
    mojo_group->priority_vector =
        ConvertSparseVectorIdlToMojo(group->priorityVector());
  }
  if (group->hasPrioritySignalsOverrides()) {
    mojo_group->priority_signals_overrides =
        ConvertSparseVectorIdlToMojo(group->prioritySignalsOverrides());
  }

  if (!CopySellerCapabilitiesFromIdlToMojo(*context, exception_state, *group,
                                           *mojo_group) ||
      !CopyExecutionModeFromIdlToMojo(*context, exception_state, *group,
                                      *mojo_group) ||
      !CopyBiddingLogicUrlFromIdlToMojo(*context, exception_state, *group,
                                        *mojo_group) ||
      !CopyWasmHelperUrlFromIdlToMojo(*context, exception_state, *group,
                                      *mojo_group) ||
      !CopyUpdateUrlFromIdlToMojo(*context, exception_state, *group,
                                  *mojo_group) ||
      !CopyTrustedBiddingSignalsUrlFromIdlToMojo(*context, exception_state,
                                                 *group, *mojo_group) ||
      !CopyTrustedBiddingSignalsKeysFromIdlToMojo(*group, *mojo_group) ||
      !CopyTrustedBiddingSignalsSlotSizeModeFromIdlToMojo(*group,
                                                          *mojo_group) ||
      !CopyMaxTrustedBiddingSignalsURLLengthFromIdlToMojo(
          exception_state, *group, *mojo_group) ||
      !CopyTrustedBiddingSignalsCoordinatorFromIdlToMojo(exception_state,
                                                         *group, *mojo_group) ||
      !CopyUserBiddingSignalsFromIdlToMojo(*script_state, exception_state,
                                           *group, *mojo_group) ||
      !CopyAdsFromIdlToMojo(*context, *script_state, exception_state, *group,
                            *mojo_group) ||
      !CopyAdComponentsFromIdlToMojo(*context, *script_state, exception_state,
                                     *group, *mojo_group) ||
      !CopyAdSizesFromIdlToMojo(*context, *script_state, exception_state,
                                *group, *mojo_group) ||
      !CopySizeGroupsFromIdlToMojo(*context, *script_state, exception_state,
                                   *group, *mojo_group) ||
      !CopyAuctionServerRequestFlagsFromIdlToMojo(*context, exception_state,
                                                  *group, *mojo_group) ||
      !CopyAdditionalBidKeyFromIdlToMojo(*context, exception_state, *group,
                                         *mojo_group) ||
      !CopyAggregationCoordinatorOriginFromIdlToMojo(exception_state, *group,
                                                     *mojo_group)) {
    return EmptyPromise();
  }

  String error_field_name;
  String error_field_value;
  String error;
  if (!ValidateBlinkInterestGroup(*mojo_group, error_field_name,
                                  error_field_value, error)) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        *group, error_field_name, error_field_value, error));
    return EmptyPromise();
  }

  bool is_cross_origin =
      !context->GetSecurityOrigin()->IsSameOriginWith(mojo_group->owner.get());

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  mojom::blink::AdAuctionService::JoinInterestGroupCallback callback =
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&NavigatorAuction::JoinComplete,
                        WrapWeakPersistent(this), is_cross_origin));

  PendingJoin pending_join{std::move(mojo_group), std::move(callback)};
  if (is_cross_origin) {
    queued_cross_site_joins_.Enqueue(std::move(pending_join));
  } else {
    StartJoin(std::move(pending_join));
  }

  return promise;
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::joinAdInterestGroup(
    ScriptState* script_state,
    Navigator& navigator,
    AuctionAdInterestGroup* group,
    double duration_seconds,
    ExceptionState& exception_state) {
  return JoinAdInterestGroupInternal(script_state, navigator, group,
                                     duration_seconds, exception_state);
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::joinAdInterestGroup(
    ScriptState* script_state,
    Navigator& navigator,
    AuctionAdInterestGroup* group,
    ExceptionState& exception_state) {
  return JoinAdInterestGroupInternal(script_state, navigator, group,
                                     /*duration_seconds=*/std::nullopt,
                                     exception_state);
}

ScriptPromise<IDLUndefined> NavigatorAuction::leaveAdInterestGroup(
    ScriptState* script_state,
    const AuctionAdInterestGroupKey* group_key,
    ExceptionState& exception_state) {
  scoped_refptr<const SecurityOrigin> owner = ParseOrigin(group_key->owner());
  if (!owner) {
    exception_state.ThrowTypeError("owner '" + group_key->owner() +
                                   "' for AuctionAdInterestGroup with name '" +
                                   group_key->name() +
                                   "' must be a valid https origin.");
    return EmptyPromise();
  }

  if (ExecutionContext::From(script_state)->GetSecurityOrigin()->Protocol() !=
      url::kHttpsScheme) {
    exception_state.ThrowSecurityError(
        "May only leaveAdInterestGroup from an https origin.");
    return EmptyPromise();
  }

  bool is_cross_origin = !ExecutionContext::From(script_state)
                              ->GetSecurityOrigin()
                              ->IsSameOriginWith(owner.get());

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  mojom::blink::AdAuctionService::LeaveInterestGroupCallback callback =
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&NavigatorAuction::LeaveComplete,
                        WrapWeakPersistent(this), is_cross_origin));

  PendingLeave pending_leave{std::move(owner), std::move(group_key->name()),
                             std::move(callback)};
  if (is_cross_origin) {
    queued_cross_site_leaves_.Enqueue(std::move(pending_leave));
  } else {
    StartLeave(std::move(pending_leave));
  }

  return promise;
}

ScriptPromise<IDLUndefined> NavigatorAuction::leaveAdInterestGroupForDocument(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();
  if (!window) {
    exception_state.ThrowSecurityError(
        "May not leaveAdInterestGroup from a Document that is not fully "
        "active");
    return EmptyPromise();
  }
  if (ExecutionContext::From(script_state)->GetSecurityOrigin()->Protocol() !=
      url::kHttpsScheme) {
    exception_state.ThrowSecurityError(
        "May only leaveAdInterestGroup from an https origin.");
    return EmptyPromise();
  }
  // The renderer does not have enough information to verify that this document
  // is the result of a FLEDGE auction. The browser will silently ignore
  // this request if this document is not the result of a FLEDGE auction.
  ad_auction_service_->LeaveInterestGroupForDocument();

  // Return resolved promise. The browser-side code doesn't do anything
  // meaningful in this case (no .well-known fetches), and if it ever does do
  // them, likely don't want to expose timing information to the fenced frame,
  // anyways.
  return ToResolvedUndefinedPromise(script_state);
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::leaveAdInterestGroup(
    ScriptState* script_state,
    Navigator& navigator,
    const AuctionAdInterestGroupKey* group_key,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->IsFeatureEnabled(
          blink::mojom::PermissionsPolicyFeature::kJoinAdInterestGroup)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Feature join-ad-interest-group is not enabled by Permissions Policy");
    return EmptyPromise();
  }

  return From(context, navigator)
      .leaveAdInterestGroup(script_state, group_key, exception_state);
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::leaveAdInterestGroup(
    ScriptState* script_state,
    Navigator& navigator,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  // According to the spec, implicit leave bypasses permission policy.
  return From(ExecutionContext::From(script_state), navigator)
      .leaveAdInterestGroupForDocument(script_state, exception_state);
}

ScriptPromise<IDLUndefined> NavigatorAuction::clearOriginJoinedAdInterestGroups(
    ScriptState* script_state,
    const String& owner_string,
    Vector<String> interest_groups_to_keep,
    ExceptionState& exception_state) {
  scoped_refptr<const SecurityOrigin> owner = ParseOrigin(owner_string);
  if (!owner) {
    exception_state.ThrowTypeError("owner '" + owner_string +
                                   "' must be a valid https origin.");
    return EmptyPromise();
  }

  if (ExecutionContext::From(script_state)->GetSecurityOrigin()->Protocol() !=
      url::kHttpsScheme) {
    exception_state.ThrowSecurityError(
        "May only clearOriginJoinedAdInterestGroups from an https origin.");
    return EmptyPromise();
  }

  bool is_cross_origin = !ExecutionContext::From(script_state)
                              ->GetSecurityOrigin()
                              ->IsSameOriginWith(owner.get());

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  mojom::blink::AdAuctionService::LeaveInterestGroupCallback callback =
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&NavigatorAuction::ClearComplete,
                        WrapWeakPersistent(this), is_cross_origin));

  PendingClear pending_clear{owner, std::move(interest_groups_to_keep),
                             std::move(callback)};
  if (is_cross_origin) {
    queued_cross_site_clears_.Enqueue(std::move(pending_clear));
  } else {
    StartClear(std::move(pending_clear));
  }

  return promise;
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::clearOriginJoinedAdInterestGroups(
    ScriptState* script_state,
    Navigator& navigator,
    const String owner,
    ExceptionState& exception_state) {
  return clearOriginJoinedAdInterestGroups(script_state, navigator, owner,
                                           Vector<String>(), exception_state);
}

/* static */
ScriptPromise<IDLUndefined> NavigatorAuction::clearOriginJoinedAdInterestGroups(
    ScriptState* script_state,
    Navigator& navigator,
    const String owner,
    Vector<String> interest_groups_to_keep,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kJoinAdInterestGroup)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Feature join-ad-interest-group is not enabled by Permissions Policy");
    return EmptyPromise();
  }

  return From(context, navigator)
      .clearOriginJoinedAdInterestGroups(script_state, owner,
                                         std::move(interest_groups_to_keep),
                                         exception_state);
}

void NavigatorAuction::updateAdInterestGroups() {
  ad_auction_service_->UpdateAdInterestGroups();
}

/* static */
void NavigatorAuction::updateAdInterestGroups(ScriptState* script_state,
                                              Navigator& navigator,
                                              ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return;
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->IsFeatureEnabled(
          blink::mojom::PermissionsPolicyFeature::kJoinAdInterestGroup)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Feature join-ad-interest-group is not enabled by Permissions Policy");
    return;
  }

  return From(context, navigator).updateAdInterestGroups();
}

namespace {
// Combines the base auction nonce with the auction nonce counter as follows:
// - Retain the first 30 characters of the base auction nonce exactly as is
// - For the last six hexadecimal characters, add the value of those from the
//   base auction nonce to the value of the auction nonce counter, truncating
//   anything that overflows the resulting 24-bit unsigned integer.
//
// As such, given a base auction nonce of c1cf78b5-fa6e-4bfb-a215-896c6aedd9f1,
// this function will produce the following return value given each of the
// following argument values for auction_nonce_counter:
// 0                 --> c1cf78b5-fa6e-4bfb-a215-896c6aedd9f1
// 1                 --> c1cf78b5-fa6e-4bfb-a215-896c6aedd9f2
// 1189390           --> c1cf78b5-fa6e-4bfb-a215-896c6affffff
// 1189391           --> c1cf78b5-fa6e-4bfb-a215-896c6a000000
// 16777215 (2^24-1) --> c1cf78b5-fa6e-4bfb-a215-896c6aedd9f0
// 16777216 (2^24)   --> c1cf78b5-fa6e-4bfb-a215-896c6aedd9f1
// 16777217 (2^24+1) --> c1cf78b5-fa6e-4bfb-a215-896c6aedd9f2
//
// This function CHECK-fails if the provided base auction nonce is not valid.
String CombineAuctionNonce(base::Uuid base_auction_nonce,
                           uint32_t auction_nonce_counter) {
  CHECK(base_auction_nonce.is_valid());
  String base_nonce_string(base_auction_nonce.AsLowercaseString());
  bool ok;
  uint32_t base_nonce_suffix = base_nonce_string.Right(6).HexToUIntStrict(&ok);
  CHECK(ok) << "Unexpected: invalid base auction nonce.";
  uint32_t nonce_suffix = base_nonce_suffix + auction_nonce_counter;

  StringBuilder nonce_builder;
  nonce_builder.Append(base_nonce_string.Left(30));
  nonce_builder.AppendFormat("%06x", nonce_suffix & 0x00FFFFFF);
  return nonce_builder.ReleaseString();
}
}  // namespace

ScriptPromise<IDLString> NavigatorAuction::createAuctionNonce(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  resolver->Resolve(CombineAuctionNonce(
      GetSupplementable()->DomWindow()->document()->base_auction_nonce(),
      auction_nonce_counter_++));
  return promise;
}

/* static */
ScriptPromise<IDLString> NavigatorAuction::createAuctionNonce(
    ScriptState* script_state,
    Navigator& navigator,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }

  return From(ExecutionContext::From(script_state), navigator)
      .createAuctionNonce(script_state, exception_state);
}

ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>
NavigatorAuction::runAdAuction(ScriptState* script_state,
                               AuctionAdConfig* mutable_config,
                               ExceptionState& exception_state,
                               base::TimeTicks start_time) {
  ExecutionContext* context = ExecutionContext::From(script_state);

  if (!HandleOldDictNamesRun(mutable_config, exception_state)) {
    return ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>();
  }
  const AuctionAdConfig* config = mutable_config;

  mojo::PendingReceiver<mojom::blink::AbortableAdAuction> abort_receiver;
  auto* auction_handle = MakeGarbageCollected<AuctionHandle>(
      context, abort_receiver.InitWithNewPipeAndPassRemote());
  auto mojo_config = IdlAuctionConfigToMojo(
      auction_handle,
      /*is_top_level=*/true, /*nested_pos=*/0, *script_state, *context,
      exception_state,
      /*resource_fetcher=*/
      *GetSupplementable()->DomWindow()->document()->Fetcher(), *config);
  if (!mojo_config) {
    return ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
  if (auto* signal = config->getSignalOr(nullptr)) {
    if (signal->aborted()) {
      resolver->Reject(signal->reason(script_state));
      return promise;
    }
    auto* abort_handle = signal->AddAlgorithm(auction_handle);
    scoped_abort_state =
        std::make_unique<ScopedAbortState>(signal, abort_handle);
  }

  if (config->hasResolveToConfig()) {
    auction_handle->QueueAttachPromiseHandler(
        MakeGarbageCollected<
            NavigatorAuction::AuctionHandle::ResolveToConfigResolved>(
            auction_handle, config->resolveToConfig()));
  } else {
    auction_handle->SetResolveToConfig(false);
  }

  auction_handle->AttachQueuedPromises(script_state);
  bool is_server_auction = config->hasServerResponse();
  ad_auction_service_->RunAdAuction(
      std::move(mojo_config), std::move(abort_receiver),
      WTF::BindOnce(&NavigatorAuction::AuctionHandle::AuctionComplete,
                    WrapPersistent(auction_handle), WrapPersistent(resolver),
                    std::move(scoped_abort_state), std::move(start_time),
                    std::move(is_server_auction)));
  return promise;
}

/* static */
ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>
NavigatorAuction::runAdAuction(ScriptState* script_state,
                               Navigator& navigator,
                               AuctionAdConfig* config,
                               ExceptionState& exception_state) {
  base::TimeTicks start_time = base::TimeTicks::Now();
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>();
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  const ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->IsFeatureEnabled(
          blink::mojom::PermissionsPolicyFeature::kRunAdAuction)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Feature run-ad-auction is not enabled by Permissions Policy");
    return ScriptPromise<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>();
  }

  return From(ExecutionContext::From(script_state), navigator)
      .runAdAuction(script_state, config, exception_state, start_time);
}

/* static */
Vector<String> NavigatorAuction::adAuctionComponents(
    ScriptState* script_state,
    Navigator& navigator,
    uint16_t num_ad_components,
    ExceptionState& exception_state) {
  Vector<String> out;
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return out;
  }
  RecordCommonFledgeUseCounters(navigator.DomWindow()->document());
  const auto& ad_auction_components =
      navigator.DomWindow()->document()->Loader()->AdAuctionComponents();
  if (!ad_auction_components) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "This frame was not loaded with the "
                                      "result of an interest group auction.");
    return out;
  }

  // Clamp the number of ad components at blink::MaxAdAuctionAdComponents().
  const uint16_t kMaxAdAuctionAdComponents =
      static_cast<uint16_t>(blink::MaxAdAuctionAdComponents());
  if (num_ad_components > kMaxAdAuctionAdComponents) {
    num_ad_components = kMaxAdAuctionAdComponents;
  }

  DCHECK_EQ(kMaxAdAuctionAdComponents, ad_auction_components->size());

  for (int i = 0; i < num_ad_components; ++i) {
    out.push_back((*ad_auction_components)[i].GetString());
  }
  return out;
}

ScriptPromise<IDLUSVString> NavigatorAuction::deprecatedURNToURL(
    ScriptState* script_state,
    const String& uuid_url_string,
    bool send_reports,
    ExceptionState& exception_state) {
  KURL uuid_url(uuid_url_string);
  if (!blink::IsValidUrnUuidURL(GURL(uuid_url))) {
    exception_state.ThrowTypeError("Passed URL must be a valid URN URL.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ad_auction_service_->DeprecatedGetURLFromURN(
      std::move(uuid_url), send_reports,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &NavigatorAuction::GetURLFromURNComplete, WrapPersistent(this))));
  return promise;
}

ScriptPromise<IDLUSVString> NavigatorAuction::deprecatedURNToURL(
    ScriptState* script_state,
    Navigator& navigator,
    const V8UnionFencedFrameConfigOrUSVString* urn_or_config,
    bool send_reports,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  String uuid_url_string;
  switch (urn_or_config->GetContentType()) {
    case V8UnionFencedFrameConfigOrUSVString::ContentType::kUSVString:
      uuid_url_string = urn_or_config->GetAsUSVString();
      break;
    case V8UnionFencedFrameConfigOrUSVString::ContentType::kFencedFrameConfig:
      std::optional<KURL> uuid_url_opt =
          urn_or_config->GetAsFencedFrameConfig()->urn_uuid(
              base::PassKey<NavigatorAuction>());
      if (!uuid_url_opt.has_value()) {
        exception_state.ThrowTypeError("Passed config must have a mapped URL.");
        return EmptyPromise();
      }
      uuid_url_string = uuid_url_opt->GetString();
      break;
  }
  return From(ExecutionContext::From(script_state), navigator)
      .deprecatedURNToURL(script_state, uuid_url_string, send_reports,
                          exception_state);
}

ScriptPromise<IDLUndefined> NavigatorAuction::deprecatedReplaceInURN(
    ScriptState* script_state,
    const String& uuid_url_string,
    const Vector<std::pair<String, String>>& replacements,
    ExceptionState& exception_state) {
  KURL uuid_url(uuid_url_string);
  if (!blink::IsValidUrnUuidURL(GURL(uuid_url))) {
    exception_state.ThrowTypeError("Passed URL must be a valid URN URL.");
    return EmptyPromise();
  }
  Vector<mojom::blink::AdKeywordReplacementPtr> replacements_list;
  for (const auto& replacement : replacements) {
    if (!(replacement.first.StartsWith("${") &&
          replacement.first.EndsWith("}")) &&
        !(replacement.first.StartsWith("%%") &&
          replacement.first.EndsWith("%%"))) {
      exception_state.ThrowTypeError(
          "Replacements must be of the form '${...}' or '%%...%%'");
      return EmptyPromise();
    }
    replacements_list.push_back(mojom::blink::AdKeywordReplacement::New(
        replacement.first, replacement.second));
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ad_auction_service_->DeprecatedReplaceInURN(
      std::move(uuid_url), std::move(replacements_list),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &NavigatorAuction::ReplaceInURNComplete, WrapPersistent(this))));
  return promise;
}

ScriptPromise<IDLUndefined> NavigatorAuction::deprecatedReplaceInURN(
    ScriptState* script_state,
    Navigator& navigator,
    const V8UnionFencedFrameConfigOrUSVString* urn_or_config,
    const Vector<std::pair<String, String>>& replacements,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  String uuid_url_string;
  switch (urn_or_config->GetContentType()) {
    case V8UnionFencedFrameConfigOrUSVString::ContentType::kUSVString:
      uuid_url_string = urn_or_config->GetAsUSVString();
      break;
    case V8UnionFencedFrameConfigOrUSVString::ContentType::kFencedFrameConfig:
      std::optional<KURL> uuid_url_opt =
          urn_or_config->GetAsFencedFrameConfig()->urn_uuid(
              base::PassKey<NavigatorAuction>());
      if (!uuid_url_opt.has_value()) {
        exception_state.ThrowTypeError("Passed config must have a mapped URL.");
        return EmptyPromise();
      }
      uuid_url_string = uuid_url_opt->GetString();
      break;
  }
  return From(ExecutionContext::From(script_state), navigator)
      .deprecatedReplaceInURN(script_state, uuid_url_string,
                              std::move(replacements), exception_state);
}

ScriptPromise<Ads> NavigatorAuction::createAdRequest(
    ScriptState* script_state,
    const AdRequestConfig* config,
    ExceptionState& exception_state) {
  const ExecutionContext* context = ExecutionContext::From(script_state);
  auto mojo_config = mojom::blink::AdRequestConfig::New();

  if (!CopyAdRequestUrlFromIdlToMojo(*context, exception_state, *config,
                                     *mojo_config)) {
    return EmptyPromise();
  }

  if (!CopyAdPropertiesFromIdlToMojo(*context, exception_state, *config,
                                     *mojo_config)) {
    return EmptyPromise();
  }

  if (config->hasPublisherCode()) {
    mojo_config->publisher_code = config->publisherCode();
  }

  if (!CopyTargetingFromIdlToMojo(*context, exception_state, *config,
                                  *mojo_config)) {
    return EmptyPromise();
  }

  if (!CopyAdSignalsFromIdlToMojo(*context, exception_state, *config,
                                  *mojo_config)) {
    return EmptyPromise();
  }

  if (!CopyFallbackSourceFromIdlToMojo(*context, exception_state, *config,
                                       *mojo_config)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<Ads>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ad_auction_service_->CreateAdRequest(
      std::move(mojo_config),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &NavigatorAuction::AdsRequested, WrapPersistent(this))));
  return promise;
}

/* static */
ScriptPromise<Ads> NavigatorAuction::createAdRequest(
    ScriptState* script_state,
    Navigator& navigator,
    const AdRequestConfig* config,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document has no window associated.");
    return EmptyPromise();
  }
  return From(ExecutionContext::From(script_state), navigator)
      .createAdRequest(script_state, config, exception_state);
}

void NavigatorAuction::AdsRequested(ScriptPromiseResolver<Ads>* resolver,
                                    const WTF::String&) {
  // TODO(https://crbug.com/1249186): Add full impl of methods.
  resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
      resolver->GetScriptState()->GetIsolate(),
      DOMExceptionCode::kNotSupportedError,
      "createAdRequest API not yet implemented"));
}

ScriptPromise<IDLString> NavigatorAuction::finalizeAd(
    ScriptState* script_state,
    const Ads* ads,
    const AuctionAdConfig* config,
    ExceptionState& exception_state) {
  const ExecutionContext* context = ExecutionContext::From(script_state);
  auto mojo_config = mojom::blink::AuctionAdConfig::New();

  // For finalizing an Ad PARAKEET only really cares about the decisionLogicURL,
  // auctionSignals, sellerSignals, and perBuyerSignals. Also need seller, since
  // it's used to validate the decision logic URL. We can ignore
  // copying/validating other fields on AuctionAdConfig.
  if (!CopySellerFromIdlToMojo(exception_state, *config, *mojo_config) ||
      !CopyDecisionLogicUrlFromIdlToMojo(*context, exception_state, *config,
                                         *mojo_config)) {
    return EmptyPromise();
  }

  // TODO(morlovich): These no longer work since promise-capable type handling
  // requires non-null auction_handle.
  CopyAuctionSignalsFromIdlToMojo(/*auction_handle=*/nullptr,
                                  /*auction_id=*/nullptr, *config,
                                  *mojo_config);
  CopySellerSignalsFromIdlToMojo(/*auction_handle=*/nullptr,
                                 /*auction_id=*/nullptr, *config, *mojo_config);
  CopyPerBuyerSignalsFromIdlToMojo(/*auction_handle=*/nullptr,
```