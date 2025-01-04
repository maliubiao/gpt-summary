Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a part of the Chromium Blink rendering engine and belongs to the shared storage module. I need to analyze the code and explain what it does.

Here's a breakdown of the code's functionality:

1. **Processing Interest Groups:** The code iterates through a list of interest groups (`mojom_group`) and converts their data into a format usable within the shared storage worklet (`AuctionAdInterestGroup`). This involves extracting various properties like trusted bidding signals, user bidding signals, ads, ad components, ad sizes, and privacy settings.
2. **Handling Previous Wins:** It processes information about previous auction wins, converting the ad data from JSON strings and including timestamps.
3. **Setting Timestamps:** It calculates and sets various time-related properties for each interest group, like time since joined, lifetime remaining, and time since last update.
4. **Managing Module Loading:** It handles the downloading and execution of the shared storage worklet's module script, including error handling and caching.
5. **Providing Navigator Access:** It provides access to a `SharedStorageWorkletNavigator` object, but only after the module script has been loaded.
6. **Tracking Operations:** It assigns and manages unique IDs for operations performed within the worklet.
7. **Private Aggregation:** It handles configuration and initiation of private aggregation operations, a privacy-preserving mechanism for reporting data.

Based on this analysis, I can now summarize the code's functions and address the user's requests.
这段代码是`blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.cc`文件的第二部分，它主要负责以下功能：

**1. 处理和转换兴趣组数据 (Interest Group Processing and Conversion):**

* **功能:** 这部分代码遍历从浏览器进程接收到的兴趣组数据 (`mojom_group`)，并将其转换成可以在 Shared Storage Worklet 中使用的 `AuctionAdInterestGroup` 对象。这包括设置各种属性，例如：
    * `trustedBiddingSignalsSlotSizeMode`: 可信出价信号的槽位大小模式 (none, slot-size, all-slots-requested-sizes)。
    * `maxTrustedBiddingSignalsURLLength`: 可信出价信号 URL 的最大长度。
    * `trustedBiddingSignalsCoordinator`: 可信出价信号协调器的 URL。
    * `userBiddingSignals`: 用户出价信号（从 JSON 字符串转换为 JavaScript 对象）。
    * `ads`, `adComponents`: 广告和广告组件（从 Mojom 格式转换为 IDL 格式）。
    * `adSizes`: 允许的广告尺寸。
    * `sizeGroups`: 尺寸分组。
    * `auctionServerRequestFlags`: 拍卖服务器请求标志 (例如 "omit-ads", "include-full-ads", "omit-user-bidding-signals")。
    * `additionalBidKey`: 额外的出价密钥（Base64 编码）。
    * `privateAggregationConfig`: 私有聚合配置，包括聚合协调器的 Origin。
    * `joinCount`, `bidCount`: 加入次数和出价次数。
    * `prevWinsMs`: 之前的胜出信息，包括胜出时间和广告数据（JSON 字符串转换为 JavaScript 对象）。
    * `joiningOrigin`: 加入的 Origin。
    * 时间相关的属性，如 `timeSinceGroupJoinedMs`, `lifetimeRemainingMs`, `timeSinceLastUpdateMs`, `timeUntilNextUpdateMs`。
    * `estimatedSize`: 估计的大小。

* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:**  `userBiddingSignals` 和 `ads` 等属性最终会以 JavaScript 对象的形式暴露给 Shared Storage Worklet 中的 JavaScript 代码使用。Worklet 的 JavaScript 代码可以读取这些信息来决定如何进行操作。例如，一个 JavaScript 函数可能会根据 `userBiddingSignals` 的值来执行不同的逻辑。
    * **HTML:**  兴趣组通常与广告展示相关。`adSizes` 可能会影响广告在 HTML 页面上的布局。
    * **CSS:** 广告的样式可能由 CSS 定义，而这里处理的广告尺寸信息可能会间接地影响最终渲染的 CSS。

* **假设输入与输出:**
    * **假设输入:** 一个 `mojom::blink::SharedStorageGetInterestGroupsResultPtr` 对象，包含一个或多个 `mojom::blink::SharedStorageInterestGroupWithBiddingSignalsPtr` 对象，每个对象包含各种兴趣组的属性。
    * **输出:** 一个 `HeapVector<Member<AuctionAdInterestGroup>>`，包含转换后的 `AuctionAdInterestGroup` 对象，这些对象可以在 JavaScript 中访问。

**2. 提供 Navigator 对象 (Providing Navigator Object):**

* **功能:**  `Navigator()` 方法返回一个 `SharedStorageWorkletNavigator` 对象，该对象提供了一些浏览器级别的功能给 Worklet 使用。但只有在模块脚本加载完成后才能访问。

* **与 JavaScript, HTML, CSS 的关系:** `SharedStorageWorkletNavigator` 可能会提供一些与浏览器导航相关的 API，例如访问浏览器的用户代理字符串等，这些可能间接与网页的呈现或行为有关。

* **用户或编程常见的使用错误:**  如果在 `addModule()` 执行完成之前尝试访问 `navigator`，将会抛出一个 `NotAllowedError` 异常。

* **调试线索:** 如果在 Worklet 代码中发现 `navigator` 为空或者访问时报错，需要检查 `addModule()` 是否成功完成。

**3. 获取当前操作 ID (Getting Current Operation ID):**

* **功能:** `GetCurrentOperationId()` 方法返回当前正在运行的操作的唯一 ID。这个 ID 是通过在 Worklet 的 JavaScript 执行上下文中保存的 embedder data 获取的。

* **与 JavaScript, HTML, CSS 的关系:** 这个 ID 对于内部追踪和管理 Worklet 的操作很重要，但通常不会直接暴露给 JavaScript 代码或影响 HTML/CSS 的渲染。

**4. 处理模块脚本下载 (Handling Module Script Download):**

* **功能:** `OnModuleScriptDownloaded()` 方法处理 Shared Storage Worklet 模块脚本的下载结果。它负责：
    * 清理下载器 (`module_script_downloader_`).
    * 如果还在等待代码缓存，则延迟处理。
    * 获取代码缓存数据 (`cached_metadata`)。
    * 创建 `ClassicScript` 对象来表示下载的脚本。
    * 在 Worklet 的 JavaScript 上下文中执行脚本。
    * 处理脚本执行过程中出现的异常。
    * 调用回调函数 (`AddModuleCallback`) 通知模块加载是否成功。

* **与 JavaScript, HTML, CSS 的关系:** 这是加载和执行 Worklet JavaScript 代码的核心部分。下载的 JavaScript 代码会定义 Worklet 的行为。

* **假设输入与输出:**
    * **假设输入:**  下载的脚本内容 (`response_body`)，脚本的 URL (`script_source_url`)，以及可能存在的错误信息 (`error_message`)。
    * **输出:**  如果脚本执行成功，则 Worklet 的模块会被加载；如果失败，则会通过回调通知错误信息。

* **用户或编程常见的使用错误:**
    * 模块脚本 URL 不正确或无法访问。
    * 模块脚本中存在语法错误或其他运行时错误。

* **调试线索:** 如果 `addModule()` 失败，检查网络请求是否成功，以及浏览器控制台是否有 JavaScript 错误信息。

**5. 记录模块加载完成 (Recording Module Load Finished):**

* **功能:** `RecordAddModuleFinished()` 标记模块脚本加载完成。

**6. 执行通用操作检查 (Performing Common Operation Checks):**

* **功能:** `PerformCommonOperationChecks()` 在执行 Shared Storage 操作之前执行一些通用检查，例如：
    * 确保模块脚本已加载。
    * 检查是否存在指定名称的操作定义。
    * 确保操作定义的实例不为空。

* **与 JavaScript, HTML, CSS 的关系:**  这些检查确保 Worklet 的状态正确，可以安全地执行操作。

* **用户或编程常见的使用错误:**
    * 在 `addModule()` 完成之前调用 Worklet 的操作方法。
    * 调用不存在的操作名称。

* **调试线索:** 如果 Worklet 操作失败并提示模块未加载或操作未找到，需要检查 Worklet 的加载流程和操作名称是否正确。

**7. 启动和完成操作 (Starting and Finishing Operations):**

* **功能:**
    * `StartOperation()`:  为当前操作分配一个唯一的 ID，并设置到 JavaScript 执行上下文中。如果启用了私有聚合，则会开始私有聚合操作。
    * `FinishOperation()`: 在操作完成后执行清理工作，例如结束私有聚合操作。

* **与 JavaScript, HTML, CSS 的关系:** 这些方法管理 Worklet 中操作的生命周期，但通常不会直接影响网页的呈现。

**8. 获取或创建私有聚合对象 (Getting or Creating Private Aggregation Object):**

* **功能:** `GetOrCreatePrivateAggregation()` 返回一个 `PrivateAggregation` 对象，如果不存在则创建它。私有聚合用于在 Shared Storage 中进行隐私保护的数据聚合。

* **与 JavaScript, HTML, CSS 的关系:** 私有聚合是 Privacy Sandbox 的一部分，用于在保护用户隐私的前提下收集有用的数据。它不会直接影响 HTML 或 CSS 的渲染，但会影响网站可以收集到的数据类型。

**归纳一下它的功能:**

这段代码的核心功能是 **初始化和管理 Shared Storage Worklet 的运行环境，并处理来自浏览器进程的指令和数据**。它负责：

* **加载和执行 Worklet 的 JavaScript 代码。**
* **将浏览器提供的兴趣组数据转换为 Worklet 可以使用的格式。**
* **提供浏览器级别的功能给 Worklet (通过 `navigator`)。**
* **管理 Worklet 中执行的操作的生命周期。**
* **支持私有聚合功能。**

总的来说，这段 C++ 代码是 Shared Storage Worklet 功能实现的关键部分，它连接了浏览器进程和 Worklet 的 JavaScript 执行环境，使得 Worklet 能够访问必要的数据和功能，并执行其预定的任务。

Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
_signals_slot_size_mode_string;
              switch (mojom_group->interest_group
                          ->trusted_bidding_signals_slot_size_mode) {
                case mojom::blink::InterestGroup::
                    TrustedBiddingSignalsSlotSizeMode ::kNone:
                  trusted_bidding_signals_slot_size_mode_string = "none";
                  break;
                case mojom::blink::InterestGroup::
                    TrustedBiddingSignalsSlotSizeMode::kSlotSize:
                  trusted_bidding_signals_slot_size_mode_string = "slot-size";
                  break;
                case mojom::blink::InterestGroup::
                    TrustedBiddingSignalsSlotSizeMode::kAllSlotsRequestedSizes:
                  trusted_bidding_signals_slot_size_mode_string =
                      "all-slots-requested-sizes";
                  break;
              }

              group->setTrustedBiddingSignalsSlotSizeMode(
                  trusted_bidding_signals_slot_size_mode_string);

              group->setMaxTrustedBiddingSignalsURLLength(
                  mojom_group->interest_group
                      ->max_trusted_bidding_signals_url_length);

              if (mojom_group->interest_group
                      ->trusted_bidding_signals_coordinator) {
                group->setTrustedBiddingSignalsCoordinator(
                    mojom_group->interest_group
                        ->trusted_bidding_signals_coordinator->ToString());
              }

              if (mojom_group->interest_group->user_bidding_signals) {
                group->setUserBiddingSignals(JsonStringToScriptValue(
                    resolver->GetScriptState(),
                    mojom_group->interest_group->user_bidding_signals));
              }

              if (mojom_group->interest_group->ads) {
                group->setAds(
                    ConvertMojomAdsToIDLAds(resolver->GetScriptState(),
                                            *mojom_group->interest_group->ads));
              }

              if (mojom_group->interest_group->ad_components) {
                group->setAdComponents(ConvertMojomAdsToIDLAds(
                    resolver->GetScriptState(),
                    *mojom_group->interest_group->ad_components));
              }

              if (mojom_group->interest_group->ad_sizes) {
                HeapVector<
                    std::pair<String, Member<AuctionAdInterestGroupSize>>>
                    ad_sizes;
                ad_sizes.reserve(mojom_group->interest_group->ad_sizes->size());

                for (const auto& entry :
                     *mojom_group->interest_group->ad_sizes) {
                  const mojom::blink::AdSizePtr& mojom_ad_size = entry.value;
                  AuctionAdInterestGroupSize* ad_size =
                      AuctionAdInterestGroupSize::Create();
                  ad_size->setWidth(String(ConvertAdDimensionToString(
                      mojom_ad_size->width, mojom_ad_size->width_units)));
                  ad_size->setHeight(String(ConvertAdDimensionToString(
                      mojom_ad_size->height, mojom_ad_size->height_units)));

                  ad_sizes.emplace_back(entry.key, ad_size);
                }

                group->setAdSizes(std::move(ad_sizes));
              }

              if (mojom_group->interest_group->size_groups) {
                Vector<std::pair<String, Vector<String>>> size_groups;
                size_groups.reserve(
                    mojom_group->interest_group->size_groups->size());
                for (const auto& entry :
                     *mojom_group->interest_group->size_groups) {
                  size_groups.emplace_back(entry.key, entry.value);
                }
                group->setSizeGroups(std::move(size_groups));
              }

              Vector<String> auction_server_request_flags;
              auction_server_request_flags.reserve(3);
              if (mojom_group->interest_group->auction_server_request_flags
                      ->omit_ads) {
                auction_server_request_flags.push_back("omit-ads");
              }
              if (mojom_group->interest_group->auction_server_request_flags
                      ->include_full_ads) {
                auction_server_request_flags.push_back("include-full-ads");
              }
              if (mojom_group->interest_group->auction_server_request_flags
                      ->omit_user_bidding_signals) {
                auction_server_request_flags.push_back(
                    "omit-user-bidding-signals");
              }
              group->setAuctionServerRequestFlags(
                  std::move(auction_server_request_flags));

              if (mojom_group->interest_group->additional_bid_key) {
                Vector<char> original_additional_bid_key;
                WTF::Base64Encode(
                    base::make_span(
                        *mojom_group->interest_group->additional_bid_key),
                    original_additional_bid_key);

                group->setAdditionalBidKey(String(original_additional_bid_key));
              }

              ProtectedAudiencePrivateAggregationConfig* pa_config =
                  ProtectedAudiencePrivateAggregationConfig::Create();
              if (mojom_group->interest_group->aggregation_coordinator_origin) {
                pa_config->setAggregationCoordinatorOrigin(
                    mojom_group->interest_group->aggregation_coordinator_origin
                        ->ToString());
              }
              group->setPrivateAggregationConfig(pa_config);

              group->setJoinCount(
                  mojom_group->bidding_browser_signals->join_count);
              group->setBidCount(
                  mojom_group->bidding_browser_signals->bid_count);

              HeapVector<HeapVector<Member<V8UnionAuctionAdOrLongLong>>>
                  previous_wins;
              previous_wins.reserve(
                  mojom_group->bidding_browser_signals->prev_wins.size());

              for (const auto& mojom_previous_win :
                   mojom_group->bidding_browser_signals->prev_wins) {
                ScriptValue ad_script_value = JsonStringToScriptValue(
                    resolver->GetScriptState(), mojom_previous_win->ad_json);

                ScriptState::Scope scope(resolver->GetScriptState());
                auto* isolate = resolver->GetScriptState()->GetIsolate();

                // If the 'metadata' field is set, update it with the parsed
                // JSON object.
                {
                  auto context = resolver->GetScriptState()->GetContext();

                  v8::Local<v8::Object> ad_dict;
                  ScriptValueToObject(resolver->GetScriptState(),
                                      ad_script_value, &ad_dict);

                  v8::Local<v8::Value> v8_metadata_string;
                  if (ad_dict->Get(context, V8AtomicString(isolate, "metadata"))
                          .ToLocal(&v8_metadata_string)) {
                    ScriptValue metadata_script_value = JsonStringToScriptValue(
                        resolver->GetScriptState(),
                        String(gin::V8ToString(isolate, v8_metadata_string)));

                    v8::MicrotasksScope microtasks(
                        context, v8::MicrotasksScope::kDoNotRunMicrotasks);

                    std::ignore = ad_dict->Set(
                        context, V8AtomicString(isolate, "metadata"),
                        metadata_script_value.V8Value());
                  }
                }

                AuctionAd* ad = AuctionAd::Create(
                    isolate, ad_script_value.V8Value(), ASSERT_NO_EXCEPTION);

                HeapVector<Member<V8UnionAuctionAdOrLongLong>> previous_win;
                previous_wins.reserve(2);
                previous_win.push_back(
                    MakeGarbageCollected<V8UnionAuctionAdOrLongLong>(
                        (now - mojom_previous_win->time).InMilliseconds()));
                previous_win.push_back(
                    MakeGarbageCollected<V8UnionAuctionAdOrLongLong>(ad));

                previous_wins.push_back(std::move(previous_win));
              }

              group->setPrevWinsMs(std::move(previous_wins));

              group->setJoiningOrigin(mojom_group->joining_origin->ToString());

              group->setTimeSinceGroupJoinedMs(
                  (now - mojom_group->join_time).InMilliseconds());
              group->setLifetimeRemainingMs(
                  (mojom_group->interest_group->expiry - now).InMilliseconds());
              group->setTimeSinceLastUpdateMs(
                  (now - mojom_group->last_updated).InMilliseconds());
              group->setTimeUntilNextUpdateMs(
                  (mojom_group->next_update_after - now).InMilliseconds());

              group->setEstimatedSize(mojom_group->estimated_size);

              groups.push_back(group);
            }

            base::UmaHistogramTimes(
                "Storage.SharedStorage.InterestGroups.TimeToResolve",
                timer.Elapsed());

            RecordInterestGroupsResultStatusUma(
                InterestGroupsResultStatus::kSuccess);
            resolver->Resolve(groups);
          },
          base::ElapsedTimer())));

  return promise;
}

SharedStorageWorkletNavigator* SharedStorageWorkletGlobalScope::Navigator(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!add_module_finished_) {
    CHECK(!navigator_);

    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "navigator cannot be accessed during addModule().");

    return nullptr;
  }

  if (!navigator_) {
    navigator_ = MakeGarbageCollected<SharedStorageWorkletNavigator>(
        GetExecutionContext());
  }
  return navigator_.Get();
}

// Returns the unique ID for the currently running operation.
int64_t SharedStorageWorkletGlobalScope::GetCurrentOperationId() {
  ScriptState* script_state = ScriptController()->GetScriptState();
  DCHECK(script_state);

  v8::Local<v8::Value> data =
      script_state->GetIsolate()->GetContinuationPreservedEmbedderData();
  return data.As<v8::BigInt>()->Int64Value();
}

void SharedStorageWorkletGlobalScope::OnModuleScriptDownloaded(
    const KURL& script_source_url,
    mojom::blink::SharedStorageWorkletService::AddModuleCallback callback,
    std::unique_ptr<std::string> response_body,
    std::string error_message,
    network::mojom::URLResponseHeadPtr response_head) {
  module_script_downloader_.reset();

  // If we haven't received the code cache data, defer handing the response.
  if (code_cache_fetcher_ && code_cache_fetcher_->is_waiting()) {
    handle_script_download_response_after_code_cache_response_ = WTF::BindOnce(
        &SharedStorageWorkletGlobalScope::OnModuleScriptDownloaded,
        WrapPersistent(this), script_source_url, std::move(callback),
        std::move(response_body), std::move(error_message),
        std::move(response_head));
    return;
  }

  // Note: There's no need to check the `cached_metadata` param from
  // `URLLoaderClient::OnReceiveResponse`. This param is only set for data
  // fetched from ServiceWorker caches. Today, shared storage script fetch
  // cannot be intercepted by service workers.

  std::optional<mojo_base::BigBuffer> cached_metadata =
      (code_cache_fetcher_ && response_head)
          ? code_cache_fetcher_->TakeCodeCacheForResponse(*response_head)
          : std::nullopt;
  code_cache_fetcher_.reset();

  mojom::blink::SharedStorageWorkletService::AddModuleCallback
      add_module_finished_callback = std::move(callback).Then(WTF::BindOnce(
          &SharedStorageWorkletGlobalScope::RecordAddModuleFinished,
          WrapPersistent(this)));

  if (!response_body) {
    std::move(add_module_finished_callback)
        .Run(false, String(error_message.c_str()));
    return;
  }

  DCHECK(error_message.empty());
  DCHECK(response_head);

  if (!ScriptController()) {
    std::move(add_module_finished_callback)
        .Run(false, /*error_message=*/"Worklet is being destroyed.");
    return;
  }

  WebURLResponse response =
      WebURLResponse::Create(script_source_url, *response_head.get(),
                             /*report_security_info=*/false, /*request_id=*/0);

  const ResourceResponse& resource_response = response.ToResourceResponse();

  // Create a `ScriptCachedMetadataHandler` for http family URLs. This
  // replicates the core logic from `ScriptResource::ResponseReceived`,
  // simplified since shared storage doesn't require
  // `ScriptCachedMetadataHandlerWithHashing` which is only used for certain
  // schemes.
  ScriptCachedMetadataHandler* cached_metadata_handler = nullptr;

  if (script_source_url.ProtocolIsInHTTPFamily()) {
    std::unique_ptr<CachedMetadataSender> sender = CachedMetadataSender::Create(
        resource_response, mojom::blink::CodeCacheType::kJavascript,
        GetSecurityOrigin());

    cached_metadata_handler = MakeGarbageCollected<ScriptCachedMetadataHandler>(
        WTF::TextEncoding(response_head->charset.c_str()), std::move(sender));

    if (cached_metadata) {
      cached_metadata_handler->SetSerializedCachedMetadata(
          std::move(*cached_metadata));
    }
  }

  // TODO(crbug.com/1419253): Using a classic script with the custom script
  // loader is tentative. Eventually, this should migrate to the blink-worklet's
  // script loading infrastructure.
  ClassicScript* worker_script = ClassicScript::Create(
      String(*response_body),
      /*source_url=*/script_source_url,
      /*base_url=*/KURL(), ScriptFetchOptions(),
      ScriptSourceLocationType::kUnknown, SanitizeScriptErrors::kSanitize,
      cached_metadata_handler);

  ScriptState* script_state = ScriptController()->GetScriptState();
  DCHECK(script_state);

  v8::HandleScope handle_scope(script_state->GetIsolate());
  ScriptEvaluationResult result =
      worker_script->RunScriptOnScriptStateAndReturnValue(script_state);

  if (result.GetResultType() ==
      ScriptEvaluationResult::ResultType::kException) {
    v8::Local<v8::Value> exception = result.GetExceptionForWorklet();

    std::move(add_module_finished_callback)
        .Run(false,
             /*error_message=*/ExceptionToString(script_state, exception));
    return;
  } else if (result.GetResultType() !=
             ScriptEvaluationResult::ResultType::kSuccess) {
    std::move(add_module_finished_callback)
        .Run(false, /*error_message=*/"Internal Failure");
    return;
  }

  std::move(add_module_finished_callback)
      .Run(true, /*error_message=*/g_empty_string);
}

void SharedStorageWorkletGlobalScope::DidReceiveCachedCode() {
  if (handle_script_download_response_after_code_cache_response_) {
    std::move(handle_script_download_response_after_code_cache_response_).Run();
  }
}

void SharedStorageWorkletGlobalScope::RecordAddModuleFinished() {
  add_module_finished_ = true;
}

bool SharedStorageWorkletGlobalScope::PerformCommonOperationChecks(
    const String& operation_name,
    String& error_message,
    SharedStorageOperationDefinition*& operation_definition) {
  DCHECK(error_message.empty());
  DCHECK_EQ(operation_definition, nullptr);

  if (!add_module_finished_) {
    // TODO(http://crbug/1249581): if this operation comes while fetching the
    // module script, we might want to queue the operation to be handled later
    // after addModule completes.
    error_message = kSharedStorageModuleScriptNotLoadedErrorMessage;
    return false;
  }

  auto it = operation_definition_map_.find(operation_name);
  if (it == operation_definition_map_.end()) {
    error_message = kSharedStorageOperationNotFoundErrorMessage;
    return false;
  }

  operation_definition = it->value;

  ScriptState* script_state = operation_definition->GetScriptState();

  ScriptState::Scope scope(script_state);

  TraceWrapperV8Reference<v8::Value> instance =
      operation_definition->GetInstance();
  if (instance.IsEmpty()) {
    error_message = kSharedStorageEmptyOperationDefinitionInstanceErrorMessage;
    return false;
  }

  return true;
}

base::OnceClosure SharedStorageWorkletGlobalScope::StartOperation(
    mojom::blink::PrivateAggregationOperationDetailsPtr pa_operation_details) {
  CHECK(add_module_finished_);
  CHECK_EQ(!!pa_operation_details,
           ShouldDefinePrivateAggregationInSharedStorage());

  int64_t operation_id = operation_counter_++;

  ScriptState* script_state = ScriptController()->GetScriptState();
  DCHECK(script_state);

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  isolate->SetContinuationPreservedEmbedderData(
      v8::BigInt::New(isolate, operation_id));

  if (ShouldDefinePrivateAggregationInSharedStorage()) {
    GetOrCreatePrivateAggregation()->OnOperationStarted(
        operation_id, std::move(pa_operation_details));
  }

  return WTF::BindOnce(&SharedStorageWorkletGlobalScope::FinishOperation,
                       WrapPersistent(this), operation_id);
}

void SharedStorageWorkletGlobalScope::FinishOperation(int64_t operation_id) {
  if (ShouldDefinePrivateAggregationInSharedStorage()) {
    CHECK(private_aggregation_);
    private_aggregation_->OnOperationFinished(operation_id);
  }
}

PrivateAggregation*
SharedStorageWorkletGlobalScope::GetOrCreatePrivateAggregation() {
  CHECK(ShouldDefinePrivateAggregationInSharedStorage());
  CHECK(add_module_finished_);

  if (!private_aggregation_) {
    private_aggregation_ = MakeGarbageCollected<PrivateAggregation>(this);
  }

  return private_aggregation_.Get();
}

}  // namespace blink

"""


```