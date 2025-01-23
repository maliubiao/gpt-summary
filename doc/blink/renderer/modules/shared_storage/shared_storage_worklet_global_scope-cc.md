Response:
The user wants a summary of the provided C++ source code file `shared_storage_worklet_global_scope.cc`. I need to identify the main functionalities implemented in this file and relate them to web technologies like JavaScript, HTML, and CSS if applicable. I also need to consider potential user errors and how a user might end up triggering this code.

Here's a plan:

1. **Identify Core Functionalities:** Analyze the class `SharedStorageWorkletGlobalScope` and its methods to understand its primary responsibilities. Look for interactions with other Blink components and external services.
2. **Relate to Web Technologies:**  Determine how the functionalities interact with JavaScript (e.g., through V8 bindings), HTML (though likely indirect), and CSS (less likely in this specific file, but worth considering).
3. **Infer Logic and Provide Examples:** Where the code performs actions based on input, create hypothetical scenarios with input and expected output.
4. **Identify Potential User Errors:** Consider common mistakes developers might make when using the related APIs, which might trigger errors handled in this code.
5. **Trace User Operations:** Outline the steps a user would take in a web browser to eventually invoke the code in this file.
6. **Summarize Functionality:** Based on the above points, provide a concise summary of the file's role.
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**功能归纳:**

`SharedStorageWorkletGlobalScope.cc` 文件定义了 `SharedStorageWorkletGlobalScope` 类，这个类是 Blink 渲染引擎中为 Shared Storage Worklet 提供全局作用域的关键组件。 它的主要功能可以归纳为：

1. **Worklet 环境的建立和管理:**
   - 作为 Shared Storage Worklet 的全局上下文，负责 Worklet 的生命周期管理，包括初始化、执行和销毁。
   - 绑定 `SharedStorageWorkletService` Mojo 接口，接收来自浏览器进程的指令。
   - 管理与 Worklet 相关的权限策略状态 (`permissions_policy_state_`) 和嵌入器上下文 (`embedder_context_`).

2. **模块脚本的加载和执行:**
   - 负责加载和执行 Worklet 的主模块脚本 (`AddModule` 方法)。
   - 使用 `ModuleScriptDownloader` 下载脚本。
   - 使用 `CodeCacheFetcher` 管理脚本的代码缓存。

3. **注册和调用 Shared Storage 操作:**
   - 允许在 Worklet 中注册自定义的 Shared Storage 操作 (`Register` 方法)。
   - 每个操作都关联一个 JavaScript 类和其 `run` 方法。
   - 提供 `RunURLSelectionOperation` 和 `RunOperation` 方法来执行已注册的操作。

4. **提供 Shared Storage API 访问:**
   - 通过 `sharedStorage()` 方法向 Worklet 脚本暴露 `SharedStorage` API，允许 Worklet 访问和操作 Shared Storage 数据。
   - 该 API 的访问在 `addModule` 完成后才被允许。

5. **提供 Private Aggregation API 访问:**
   - 通过 `privateAggregation()` 方法向 Worklet 脚本暴露 `PrivateAggregation` API，允许 Worklet 进行私有聚合操作。
   - 该 API 的访问在 `addModule` 完成后才被允许。

6. **提供 Crypto API 访问:**
   - 通过 `crypto()` 方法向 Worklet 脚本暴露 `Crypto` API，提供加密相关的功能。

7. **提供 Interest Groups API 访问:**
   - 通过 `interestGroups()` 方法向 Worklet 脚本暴露访问用户当前所属的兴趣组信息的功能。
   - 从浏览器进程获取兴趣组信息 (`GetInterestGroups`)。

8. **错误处理和日志记录:**
   - 处理脚本执行期间的异常，并将错误信息传递回调用方。
   - 使用 UMA 记录与 Interest Groups API 相关的状态。
   - 通过 `OnConsoleApiMessage` 将 Worklet 中的 console 输出转发到浏览器。

9. **与 JavaScript 的交互:**
   - 通过 V8 引擎与 JavaScript 代码进行交互。
   - 使用 `V8NoArgumentConstructor` 注册 JavaScript 类。
   - 使用 `ScriptFunction` 调用 JavaScript 方法。
   - 使用 `ScriptValue` 和 `UnpackedSerializedScriptValue` 处理 JavaScript 值。
   - 将 Mojo 传递的数据转换为 JavaScript 可用的对象 (`ConvertMojomAdToIDLAd`, `ConvertMojomAdsToIDLAds`).
   - 处理 JavaScript Promise 的 resolve 和 reject。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  这个文件是 Worklet 执行 JavaScript 代码的底层支撑。
    - **例子:** `Register` 方法允许开发者在 JavaScript 中定义一个类，例如：
      ```javascript
      class MyOperation {
        async run(data) {
          // 执行一些操作
          return 1;
        }
      }
      register('my-operation', MyOperation);
      ```
      然后在 Worklet 外部可以通过 `sharedStorage.run('my-operation', data)` 来调用这个 JavaScript 代码。`SharedStorageWorkletGlobalScope.cc` 中的 `RunOperation` 方法负责接收这个调用并执行 JavaScript 代码。
    - **例子:** `interestGroups()` 方法在 JavaScript 中返回一个 Promise，resolve 的值是一个包含用户兴趣组信息的数组。这是 JavaScript 通过 Shared Storage API 获取用户兴趣数据的入口。

* **HTML:**  HTML 用于触发 Shared Storage Worklet 的执行。
    - **例子:**  一个网站的 JavaScript 代码可以通过 `HTMLIFrameElement.sharedStorage.run(...)` 或 `HTMLIFrameElement.sharedStorage.selectURL(...)` 来触发在 Shared Storage Worklet 中注册的操作。这个 HTML 元素 (例如 `<iframe>`) 需要是允许访问 Shared Storage 的上下文。

* **CSS:**  这个文件直接与 CSS 的功能关系不大。CSS 主要负责页面的样式，而 Shared Storage Worklet 专注于数据处理和隐私相关的操作。虽然 Shared Storage 的结果可能会间接影响页面的渲染，但这个文件本身不涉及 CSS 的解析或应用。

**逻辑推理的假设输入与输出:**

假设一个名为 `my-operation` 的操作已注册，其 JavaScript 代码如下：

```javascript
class MyOperation {
  async run(data) {
    if (data.value > 10) {
      return "success";
    } else {
      throw new Error("Value is too small");
    }
  }
}
```

**假设输入 (在 Worklet 外部调用):**

1. **场景 1 (成功):** `sharedStorage.run('my-operation', { value: 15 })`
   - **假设输出:** `RunOperationCallback` 的回调函数被调用，`success` 为 `true`， `error_message` 为空字符串。

2. **场景 2 (失败 - JavaScript 抛出异常):** `sharedStorage.run('my-operation', { value: 5 })`
   - **假设输出:** `RunOperationCallback` 的回调函数被调用，`success` 为 `false`，`error_message` 包含 "Value is too small" 以及 JavaScript 的堆栈信息。

**用户或编程常见的使用错误:**

1. **在 `addModule` 完成前访问 `sharedStorage` 或 `privateAggregation`:**
   - **错误:** 开发者在 Worklet 的主模块脚本加载完成之前尝试访问 `sharedStorage` 或 `privateAggregation` 对象。
   - **例子:**
     ```javascript
     // worklet.js
     console.log(sharedStorage); // 错误！在 addModule 期间无法访问
     ```
   - **结果:**  `sharedStorage()` 和 `privateAggregation()` 方法会抛出 `NotAllowedError` 异常。

2. **注册已存在的操作名称:**
   - **错误:** 开发者尝试使用相同的名称注册多个 Shared Storage 操作。
   - **例子:**
     ```javascript
     register('my-operation', MyOperation1);
     register('my-operation', MyOperation2); // 错误！名称已存在
     ```
   - **结果:** `Register` 方法会抛出 `DataError` 异常。

3. **`selectURL` 操作的 `run` 方法返回无效的索引:**
   - **错误:** `selectURL` 操作的 JavaScript `run` 方法返回的索引值超出了提供的 URL 数组的范围。
   - **例子:** 如果 `selectURL` 提供了 3 个 URL，但 `run` 方法返回了 `5`。
   - **结果:** `SelectURLResolutionSuccessCallback` 会检查索引范围，如果超出则调用 callback 时 `success` 为 `false`，`error_message` 为 `kSharedStorageReturnValueOutOfRangeErrorMessage`。

**用户操作到达这里的调试线索:**

以下步骤描述了用户操作如何一步步触发 `SharedStorageWorkletGlobalScope.cc` 中的代码执行，可以作为调试线索：

1. **用户访问一个网页:** 用户在浏览器中打开一个包含 Shared Storage 功能的网页。
2. **网页 JavaScript 调用 Shared Storage API:** 网页的 JavaScript 代码通过以下方式之一与 Shared Storage 交互：
   - `document.sharedStorage.run(...)`
   - `document.sharedStorage.selectURL(...)`
   - `iframeElement.sharedStorage.run(...)`
   - `iframeElement.sharedStorage.selectURL(...)`
3. **浏览器进程处理 Shared Storage API 调用:** 浏览器进程接收到 JavaScript 的调用，并确定需要执行哪个 Worklet 和操作。
4. **浏览器进程向渲染器进程发送消息:** 浏览器进程通过 Mojo 接口 (`SharedStorageWorkletService`) 向负责该网页的渲染器进程发送执行 Worklet 操作的请求。
5. **渲染器进程接收消息并找到对应的 `SharedStorageWorkletGlobalScope`:** 渲染器进程接收到消息，并将其路由到负责该 Shared Storage Worklet 的 `SharedStorageWorkletGlobalScope` 实例。
6. **`SharedStorageWorkletGlobalScope` 调用相应的方法:**
   - 如果是 `run` 操作，则调用 `RunOperation` 方法。
   - 如果是 `selectURL` 操作，则调用 `RunURLSelectionOperation` 方法。
7. **Worklet 脚本执行:**  `RunOperation` 或 `RunURLSelectionOperation` 方法会调用已注册的 JavaScript 操作的 `run` 方法，从而执行 Worklet 脚本。

在调试时，可以在以下位置设置断点：

- `SharedStorageWorkletGlobalScope::AddModule`:  查看 Worklet 模块的加载过程。
- `SharedStorageWorkletGlobalScope::Register`: 查看操作的注册。
- `SharedStorageWorkletGlobalScope::RunURLSelectionOperation` 和 `SharedStorageWorkletGlobalScope::RunOperation`:  查看操作的执行过程，包括参数的传递和 JavaScript 代码的调用。
- `SelectURLResolutionSuccessCallback::React` 和 `SelectURLResolutionFailureCallback::React`:  查看 `selectURL` 操作 Promise 的 resolve 和 reject 处理。
- `RunResolutionSuccessCallback::React` 和 `RunResolutionFailureCallback::React`: 查看 `run` 操作 Promise 的 resolve 和 reject 处理。

通过以上分析，可以更深入地理解 `SharedStorageWorkletGlobalScope.cc` 在 Chromium Blink 引擎中扮演的角色以及它与 Web 技术栈的联系。

### 提示词
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.h"

#include <stdint.h>

#include <memory>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/callback.h"
#include "base/metrics/histogram_functions.h"
#include "base/timer/elapsed_timer.h"
#include "gin/converter.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/url_loader_factory.mojom-blink.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/interest_group/ad_display_size_utils.h"
#include "third_party/blink/public/common/shared_storage/module_script_downloader.h"
#include "third_party/blink/public/common/shared_storage/shared_storage_utils.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom-blink.h"
#include "third_party/blink/public/mojom/private_aggregation/private_aggregation_host.mojom-blink.h"
#include "third_party/blink/public/mojom/shared_storage/shared_storage_worklet_service.mojom-blink.h"
#include "third_party/blink/public/platform/cross_variant_mojo_util.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/unpacked_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_no_argument_constructor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad_interest_group_size.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_protected_audience_private_aggregation_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_run_function_for_shared_storage_run_operation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_run_function_for_shared_storage_select_url_operation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_interest_group.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_auctionad_longlong.h"
#include "third_party/blink/renderer/core/context_features/context_feature_settings.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/threaded_messaging_proxy_base.h"
#include "third_party/blink/renderer/modules/crypto/crypto.h"
#include "third_party/blink/renderer/modules/shared_storage/private_aggregation.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_operation_definition.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_navigator.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_thread.h"
#include "third_party/blink/renderer/platform/bindings/callback_method_retriever.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/code_cache_fetcher.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "v8/include/v8-context.h"
#include "v8/include/v8-isolate.h"
#include "v8/include/v8-local-handle.h"
#include "v8/include/v8-primitive.h"
#include "v8/include/v8-value.h"

namespace blink {

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class InterestGroupsResultStatus {
  kFailureDuringAddModule = 0,
  kFailurePermissionsPolicyDenied = 1,
  kFailureBrowserDenied = 2,
  kSuccess = 3,

  kMaxValue = kSuccess,
};

void RecordInterestGroupsResultStatusUma(InterestGroupsResultStatus status) {
  base::UmaHistogramEnumeration(
      "Storage.SharedStorage.InterestGroups.ResultStatus", status);
}

void ScriptValueToObject(ScriptState* script_state,
                         ScriptValue value,
                         v8::Local<v8::Object>* object) {
  auto* isolate = script_state->GetIsolate();
  DCHECK(!value.IsEmpty());
  auto v8_value = value.V8Value();
  // All the object parameters in the standard are default-initialised to an
  // empty object.
  if (v8_value->IsUndefined()) {
    *object = v8::Object::New(isolate);
    return;
  }
  std::ignore = v8_value->ToObject(script_state->GetContext()).ToLocal(object);
}

ScriptValue JsonStringToScriptValue(ScriptState* script_state,
                                    const String& json_string) {
  DCHECK(script_state->ContextIsValid());
  ScriptState::Scope scope(script_state);
  return ScriptValue(script_state->GetIsolate(),
                     FromJSONString(script_state, json_string));
}

Member<AuctionAd> ConvertMojomAdToIDLAd(
    ScriptState* script_state,
    const mojom::blink::InterestGroupAdPtr& mojom_ad) {
  AuctionAd* ad = AuctionAd::Create();
  ad->setRenderURL(mojom_ad->render_url);
  ad->setRenderUrlDeprecated(mojom_ad->render_url);
  if (mojom_ad->size_group) {
    ad->setSizeGroup(mojom_ad->size_group);
  }
  if (mojom_ad->buyer_reporting_id) {
    ad->setBuyerReportingId(mojom_ad->buyer_reporting_id);
  }
  if (mojom_ad->buyer_and_seller_reporting_id) {
    ad->setBuyerAndSellerReportingId(mojom_ad->buyer_and_seller_reporting_id);
  }
  if (mojom_ad->selectable_buyer_and_seller_reporting_ids) {
    ad->setSelectableBuyerAndSellerReportingIds(
        *mojom_ad->selectable_buyer_and_seller_reporting_ids);
  }
  if (mojom_ad->metadata) {
    ad->setMetadata(JsonStringToScriptValue(script_state, mojom_ad->metadata));
  }
  if (mojom_ad->ad_render_id) {
    ad->setAdRenderId(mojom_ad->ad_render_id);
  }
  if (mojom_ad->allowed_reporting_origins) {
    Vector<String> allowed_reporting_origins;
    allowed_reporting_origins.reserve(
        mojom_ad->allowed_reporting_origins->size());
    for (const scoped_refptr<const blink::SecurityOrigin>& origin :
         *mojom_ad->allowed_reporting_origins) {
      allowed_reporting_origins.push_back(origin->ToString());
    }
    ad->setAllowedReportingOrigins(std::move(allowed_reporting_origins));
  }

  return ad;
}

HeapVector<Member<AuctionAd>> ConvertMojomAdsToIDLAds(
    ScriptState* script_state,
    const Vector<mojom::blink::InterestGroupAdPtr>& mojom_ads) {
  HeapVector<Member<AuctionAd>> ads;
  ads.reserve(mojom_ads.size());
  for (const mojom::blink::InterestGroupAdPtr& mojom_ad : mojom_ads) {
    ads.push_back(ConvertMojomAdToIDLAd(script_state, mojom_ad));
  }
  return ads;
}

std::optional<ScriptValue> Deserialize(
    v8::Isolate* isolate,
    ExecutionContext* execution_context,
    const BlinkCloneableMessage& serialized_data) {
  if (!serialized_data.message->CanDeserializeIn(execution_context)) {
    return std::nullopt;
  }

  Member<UnpackedSerializedScriptValue> unpacked =
      SerializedScriptValue::Unpack(serialized_data.message);
  if (!unpacked) {
    return std::nullopt;
  }

  return ScriptValue(isolate, unpacked->Deserialize(isolate));
}

// We try to use .stack property so that the error message contains a stack
// trace, but otherwise fallback to .toString().
String ExceptionToString(ScriptState* script_state,
                         v8::Local<v8::Value> exception) {
  v8::Isolate* isolate = script_state->GetIsolate();

  if (!exception.IsEmpty()) {
    v8::Local<v8::Context> context = script_state->GetContext();
    v8::Local<v8::Value> value =
        v8::TryCatch::StackTrace(context, exception).FromMaybe(exception);
    v8::Local<v8::String> value_string;
    if (value->ToString(context).ToLocal(&value_string)) {
      return String(gin::V8ToString(isolate, value_string));
    }
  }

  return "Unknown Failure";
}

struct UnresolvedSelectURLRequest final
    : public GarbageCollected<UnresolvedSelectURLRequest> {
  UnresolvedSelectURLRequest(size_t urls_size,
                             blink::mojom::blink::SharedStorageWorkletService::
                                 RunURLSelectionOperationCallback callback)
      : urls_size(urls_size), callback(std::move(callback)) {}
  ~UnresolvedSelectURLRequest() = default;

  void Trace(Visitor* visitor) const {}

  size_t urls_size;
  blink::mojom::blink::SharedStorageWorkletService::
      RunURLSelectionOperationCallback callback;
};

struct UnresolvedRunRequest final
    : public GarbageCollected<UnresolvedRunRequest> {
  explicit UnresolvedRunRequest(
      blink::mojom::blink::SharedStorageWorkletService::RunOperationCallback
          callback)
      : callback(std::move(callback)) {}
  ~UnresolvedRunRequest() = default;

  void Trace(Visitor* visitor) const {}

  blink::mojom::blink::SharedStorageWorkletService::RunOperationCallback
      callback;
};

class SelectURLResolutionSuccessCallback final
    : public ThenCallable<IDLAny, SelectURLResolutionSuccessCallback> {
 public:
  explicit SelectURLResolutionSuccessCallback(
      UnresolvedSelectURLRequest* request)
      : request_(request) {}

  void Trace(Visitor* visitor) const final {
    visitor->Trace(request_);
    ThenCallable<IDLAny, SelectURLResolutionSuccessCallback>::Trace(visitor);
  }

  void React(ScriptState* script_state, ScriptValue value) {
    ScriptState::Scope scope(script_state);

    v8::Local<v8::Context> context = value.GetIsolate()->GetCurrentContext();
    v8::Local<v8::Value> v8_value = value.V8Value();

    v8::Local<v8::Uint32> v8_result_index;
    if (!v8_value->ToUint32(context).ToLocal(&v8_result_index)) {
      std::move(request_->callback)
          .Run(/*success=*/false, kSharedStorageReturnValueToIntErrorMessage,
               /*index=*/0);
    } else {
      uint32_t result_index = v8_result_index->Value();
      if (result_index >= request_->urls_size) {
        std::move(request_->callback)
            .Run(/*success=*/false,
                 kSharedStorageReturnValueOutOfRangeErrorMessage,
                 /*index=*/0);
      } else {
        std::move(request_->callback)
            .Run(/*success=*/true,
                 /*error_message=*/g_empty_string, result_index);
      }
    }
  }

 private:
  Member<UnresolvedSelectURLRequest> request_;
};

class SelectURLResolutionFailureCallback final
    : public ThenCallable<IDLAny, SelectURLResolutionFailureCallback> {
 public:
  explicit SelectURLResolutionFailureCallback(
      UnresolvedSelectURLRequest* request)
      : request_(request) {}

  void Trace(Visitor* visitor) const final {
    visitor->Trace(request_);
    ThenCallable<IDLAny, SelectURLResolutionFailureCallback>::Trace(visitor);
  }

  void React(ScriptState* script_state, ScriptValue value) {
    ScriptState::Scope scope(script_state);
    v8::Local<v8::Value> v8_value = value.V8Value();
    std::move(request_->callback)
        .Run(/*success=*/false, ExceptionToString(script_state, v8_value),
             /*index=*/0);
  }

 private:
  Member<UnresolvedSelectURLRequest> request_;
};

class RunResolutionSuccessCallback final
    : public ThenCallable<IDLAny, RunResolutionSuccessCallback> {
 public:
  explicit RunResolutionSuccessCallback(UnresolvedRunRequest* request)
      : request_(request) {}

  void Trace(Visitor* visitor) const final {
    visitor->Trace(request_);
    ThenCallable<IDLAny, RunResolutionSuccessCallback>::Trace(visitor);
  }

  void React(ScriptState*, ScriptValue) {
    std::move(request_->callback)
        .Run(/*success=*/true,
             /*error_message=*/g_empty_string);
  }

 private:
  Member<UnresolvedRunRequest> request_;
};

class RunResolutionFailureCallback final
    : public ThenCallable<IDLAny, RunResolutionFailureCallback> {
 public:
  explicit RunResolutionFailureCallback(UnresolvedRunRequest* request)
      : request_(request) {}

  void Trace(Visitor* visitor) const final {
    visitor->Trace(request_);
    ThenCallable<IDLAny, RunResolutionFailureCallback>::Trace(visitor);
  }

  void React(ScriptState* script_state, ScriptValue value) {
    ScriptState::Scope scope(script_state);
    v8::Local<v8::Value> v8_value = value.V8Value();
    std::move(request_->callback)
        .Run(/*success=*/false, ExceptionToString(script_state, v8_value));
  }

 private:
  Member<UnresolvedRunRequest> request_;
};

}  // namespace

SharedStorageWorkletGlobalScope::SharedStorageWorkletGlobalScope(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    WorkerThread* thread)
    : WorkletGlobalScope(std::move(creation_params),
                         thread->GetWorkerReportingProxy(),
                         thread) {
  ContextFeatureSettings::From(
      this, ContextFeatureSettings::CreationMode::kCreateIfNotExists)
      ->EnablePrivateAggregationInSharedStorage(
          ShouldDefinePrivateAggregationInSharedStorage());
}

SharedStorageWorkletGlobalScope::~SharedStorageWorkletGlobalScope() = default;

void SharedStorageWorkletGlobalScope::BindSharedStorageWorkletService(
    mojo::PendingReceiver<mojom::blink::SharedStorageWorkletService> receiver,
    base::OnceClosure disconnect_handler) {
  receiver_.Bind(std::move(receiver),
                 GetTaskRunner(blink::TaskType::kMiscPlatformAPI));

  // When `SharedStorageWorkletHost` is destroyed, the disconnect handler will
  // be called, and we rely on this explicit signal to clean up the worklet
  // environment.
  receiver_.set_disconnect_handler(std::move(disconnect_handler));
}

void SharedStorageWorkletGlobalScope::Register(
    const String& name,
    V8NoArgumentConstructor* operation_ctor,
    ExceptionState& exception_state) {
  if (name.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "Operation name cannot be empty.");
    return;
  }

  if (operation_definition_map_.Contains(name)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      "Operation name already registered.");
    return;
  }

  // If the result of Type(argument=prototype) is not Object, throw a TypeError.
  CallbackMethodRetriever retriever(operation_ctor);
  retriever.GetPrototypeObject(exception_state);
  if (exception_state.HadException()) {
    return;
  }

  v8::Local<v8::Function> v8_run =
      retriever.GetMethodOrThrow("run", exception_state);
  if (exception_state.HadException()) {
    return;
  }

  auto* operation_definition =
      MakeGarbageCollected<SharedStorageOperationDefinition>(
          ScriptController()->GetScriptState(), name, operation_ctor, v8_run);

  operation_definition_map_.Set(name, operation_definition);
}

void SharedStorageWorkletGlobalScope::OnConsoleApiMessage(
    mojom::ConsoleMessageLevel level,
    const String& message,
    SourceLocation* location) {
  WorkerOrWorkletGlobalScope::OnConsoleApiMessage(level, message, location);

  client_->DidAddMessageToConsole(level, message);
}

void SharedStorageWorkletGlobalScope::NotifyContextDestroyed() {
  if (private_aggregation_) {
    CHECK(ShouldDefinePrivateAggregationInSharedStorage());
    private_aggregation_->OnWorkletDestroyed();
  }

  WorkletGlobalScope::NotifyContextDestroyed();
}

void SharedStorageWorkletGlobalScope::Trace(Visitor* visitor) const {
  visitor->Trace(receiver_);
  visitor->Trace(shared_storage_);
  visitor->Trace(private_aggregation_);
  visitor->Trace(crypto_);
  visitor->Trace(navigator_);
  visitor->Trace(operation_definition_map_);
  visitor->Trace(client_);
  WorkletGlobalScope::Trace(visitor);
  Supplementable<SharedStorageWorkletGlobalScope>::Trace(visitor);
}

void SharedStorageWorkletGlobalScope::Initialize(
    mojo::PendingAssociatedRemote<
        mojom::blink::SharedStorageWorkletServiceClient> client,
    mojom::blink::SharedStorageWorkletPermissionsPolicyStatePtr
        permissions_policy_state,
    const String& embedder_context) {
  client_.Bind(std::move(client),
               GetTaskRunner(blink::TaskType::kMiscPlatformAPI));

  permissions_policy_state_ = std::move(permissions_policy_state);
  embedder_context_ = embedder_context;
}

void SharedStorageWorkletGlobalScope::AddModule(
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        pending_url_loader_factory,
    const KURL& script_source_url,
    AddModuleCallback callback) {
  mojo::Remote<network::mojom::URLLoaderFactory> url_loader_factory(
      CrossVariantMojoRemote<network::mojom::URLLoaderFactoryInterfaceBase>(
          std::move(pending_url_loader_factory)));

  module_script_downloader_ = std::make_unique<ModuleScriptDownloader>(
      url_loader_factory.get(), GURL(script_source_url),
      WTF::BindOnce(&SharedStorageWorkletGlobalScope::OnModuleScriptDownloaded,
                    WrapWeakPersistent(this), script_source_url,
                    std::move(callback)));

  // Create a ResourceRequest and populate only the fields needed by
  // `CodeCacheFetcher`.
  //
  // TODO(yaoxia): Move `code_cache_fetcher_` to `ModuleScriptDownloader` to
  // avoid replicating the ResourceRequest here. This isn't viable today because
  // `ModuleScriptDownloader` lives in blink/public/common, due to its use of
  // `network::SimpleURLLoader`.
  auto resource_request = std::make_unique<network::ResourceRequest>();
  resource_request->url = GURL(script_source_url);
  resource_request->destination =
      network::mojom::RequestDestination::kSharedStorageWorklet;

  CHECK(GetCodeCacheHost());
  code_cache_fetcher_ = CodeCacheFetcher::TryCreateAndStart(
      *resource_request, *GetCodeCacheHost(),
      WTF::BindOnce(&SharedStorageWorkletGlobalScope::DidReceiveCachedCode,
                    WrapWeakPersistent(this)));
}

void SharedStorageWorkletGlobalScope::RunURLSelectionOperation(
    const String& name,
    const Vector<KURL>& urls,
    BlinkCloneableMessage serialized_data,
    mojom::blink::PrivateAggregationOperationDetailsPtr pa_operation_details,
    RunURLSelectionOperationCallback callback) {
  String error_message;
  SharedStorageOperationDefinition* operation_definition = nullptr;
  if (!PerformCommonOperationChecks(name, error_message,
                                    operation_definition)) {
    std::move(callback).Run(
        /*success=*/false, error_message,
        /*length=*/0);
    return;
  }

  base::OnceClosure operation_completion_cb =
      StartOperation(std::move(pa_operation_details));
  RunURLSelectionOperationCallback combined_operation_completion_cb =
      std::move(callback).Then(std::move(operation_completion_cb));

  DCHECK(operation_definition);

  ScriptState* script_state = operation_definition->GetScriptState();
  ScriptState::Scope scope(script_state);

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);

  TraceWrapperV8Reference<v8::Value> instance =
      operation_definition->GetInstance();
  V8RunFunctionForSharedStorageSelectURLOperation* registered_run_function =
      operation_definition->GetRunFunctionForSharedStorageSelectURLOperation();

  Vector<String> urls_param;
  base::ranges::transform(urls, std::back_inserter(urls_param),
                          [](const KURL& url) { return url.GetString(); });

  base::ElapsedTimer deserialization_timer;

  std::optional<ScriptValue> data_param =
      Deserialize(isolate, /*execution_context=*/this, serialized_data);
  if (!data_param) {
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false, kSharedStorageCannotDeserializeDataErrorMessage,
             /*index=*/0);
    return;
  }

  base::UmaHistogramTimes(
      "Storage.SharedStorage.SelectURL.DataDeserialization.Time",
      deserialization_timer.Elapsed());

  v8::Maybe<ScriptPromise<IDLAny>> result = registered_run_function->Invoke(
      instance.Get(isolate), urls_param, *data_param);

  if (try_catch.HasCaught()) {
    v8::Local<v8::Value> exception = try_catch.Exception();
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false, ExceptionToString(script_state, exception),
             /*index=*/0);
    return;
  }

  if (result.IsNothing()) {
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false, kSharedStorageEmptyScriptResultErrorMessage,
             /*index=*/0);
    return;
  }

  auto* unresolved_request = MakeGarbageCollected<UnresolvedSelectURLRequest>(
      urls.size(), std::move(combined_operation_completion_cb));

  ScriptPromise<IDLAny> promise = result.FromJust();

  auto* success_callback =
      MakeGarbageCollected<SelectURLResolutionSuccessCallback>(
          unresolved_request);
  auto* failure_callback =
      MakeGarbageCollected<SelectURLResolutionFailureCallback>(
          unresolved_request);

  promise.Then(script_state, success_callback, failure_callback);
}

void SharedStorageWorkletGlobalScope::RunOperation(
    const String& name,
    BlinkCloneableMessage serialized_data,
    mojom::blink::PrivateAggregationOperationDetailsPtr pa_operation_details,
    RunOperationCallback callback) {
  String error_message;
  SharedStorageOperationDefinition* operation_definition = nullptr;
  if (!PerformCommonOperationChecks(name, error_message,
                                    operation_definition)) {
    std::move(callback).Run(
        /*success=*/false, error_message);
    return;
  }

  base::OnceClosure operation_completion_cb =
      StartOperation(std::move(pa_operation_details));
  mojom::blink::SharedStorageWorkletService::RunOperationCallback
      combined_operation_completion_cb =
          std::move(callback).Then(std::move(operation_completion_cb));

  DCHECK(operation_definition);

  ScriptState* script_state = operation_definition->GetScriptState();
  ScriptState::Scope scope(script_state);

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);

  TraceWrapperV8Reference<v8::Value> instance =
      operation_definition->GetInstance();
  V8RunFunctionForSharedStorageRunOperation* registered_run_function =
      operation_definition->GetRunFunctionForSharedStorageRunOperation();

  base::ElapsedTimer deserialization_timer;

  std::optional<ScriptValue> data_param =
      Deserialize(isolate, /*execution_context=*/this, serialized_data);
  if (!data_param) {
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false,
             kSharedStorageCannotDeserializeDataErrorMessage);
    return;
  }

  base::UmaHistogramTimes("Storage.SharedStorage.Run.DataDeserialization.Time",
                          deserialization_timer.Elapsed());

  v8::Maybe<ScriptPromise<IDLAny>> result =
      registered_run_function->Invoke(instance.Get(isolate), *data_param);

  if (try_catch.HasCaught()) {
    v8::Local<v8::Value> exception = try_catch.Exception();
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false, ExceptionToString(script_state, exception));
    return;
  }

  if (result.IsNothing()) {
    std::move(combined_operation_completion_cb)
        .Run(/*success=*/false, kSharedStorageEmptyScriptResultErrorMessage);
    return;
  }

  auto* unresolved_request = MakeGarbageCollected<UnresolvedRunRequest>(
      std::move(combined_operation_completion_cb));

  ScriptPromise<IDLAny> promise = result.FromJust();

  auto* success_callback =
      MakeGarbageCollected<RunResolutionSuccessCallback>(unresolved_request);
  auto* failure_callback =
      MakeGarbageCollected<RunResolutionFailureCallback>(unresolved_request);

  promise.Then(script_state, success_callback, failure_callback);
}

SharedStorage* SharedStorageWorkletGlobalScope::sharedStorage(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!add_module_finished_) {
    CHECK(!shared_storage_);

    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "sharedStorage cannot be accessed during addModule().");

    return nullptr;
  }

  // As long as `addModule()` has finished, it should be fine to expose
  // `sharedStorage`: on the browser side, we already enforce that `addModule()`
  // can only be called once, so there's no way to expose the storage data to
  // the associated `Document`.
  if (!shared_storage_) {
    shared_storage_ = MakeGarbageCollected<SharedStorage>();
  }

  return shared_storage_.Get();
}

PrivateAggregation* SharedStorageWorkletGlobalScope::privateAggregation(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  CHECK(ShouldDefinePrivateAggregationInSharedStorage());

  if (!add_module_finished_) {
    CHECK(!private_aggregation_);

    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "privateAggregation cannot be accessed during addModule().");

    return nullptr;
  }

  return GetOrCreatePrivateAggregation();
}

Crypto* SharedStorageWorkletGlobalScope::crypto(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!crypto_) {
    crypto_ = MakeGarbageCollected<Crypto>();
  }

  return crypto_.Get();
}

ScriptPromise<IDLSequence<StorageInterestGroup>>
SharedStorageWorkletGlobalScope::interestGroups(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!add_module_finished_) {
    RecordInterestGroupsResultStatusUma(
        InterestGroupsResultStatus::kFailureDuringAddModule);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "interestGroups() cannot be called during addModule().");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<StorageInterestGroup>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  GetSharedStorageWorkletServiceClient()->GetInterestGroups(
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](base::ElapsedTimer timer,
             ScriptPromiseResolver<IDLSequence<StorageInterestGroup>>* resolver,
             mojom::blink::GetInterestGroupsResultPtr result) {
            ScriptState* script_state = resolver->GetScriptState();
            DCHECK(script_state->ContextIsValid());

            if (result->is_error_message()) {
              RecordInterestGroupsResultStatusUma(
                  InterestGroupsResultStatus::kFailureBrowserDenied);
              ScriptState::Scope scope(script_state);
              resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                  script_state->GetIsolate(), DOMExceptionCode::kOperationError,
                  result->get_error_message()));
              return;
            }

            CHECK(result->is_groups());

            Vector<mojom::blink::StorageInterestGroupPtr>& mojom_groups =
                result->get_groups();

            base::Time now = base::Time::Now();

            HeapVector<Member<StorageInterestGroup>> groups;
            groups.reserve(mojom_groups.size());

            for (const auto& mojom_group : mojom_groups) {
              StorageInterestGroup* group = StorageInterestGroup::Create();

              group->setOwner(mojom_group->interest_group->owner->ToString());
              group->setName(mojom_group->interest_group->name);
              group->setPriority(mojom_group->interest_group->priority);

              group->setEnableBiddingSignalsPrioritization(
                  mojom_group->interest_group
                      ->enable_bidding_signals_prioritization);

              if (mojom_group->interest_group->priority_vector) {
                Vector<std::pair<String, double>> priority_vector;
                priority_vector.reserve(
                    mojom_group->interest_group->priority_vector->size());
                for (const auto& entry :
                     *mojom_group->interest_group->priority_vector) {
                  priority_vector.emplace_back(entry.key, entry.value);
                }
                group->setPriorityVector(std::move(priority_vector));
              }

              if (mojom_group->interest_group->priority_signals_overrides) {
                Vector<std::pair<String, double>> priority_signals_overrides;
                priority_signals_overrides.reserve(
                    mojom_group->interest_group->priority_signals_overrides
                        ->size());
                for (const auto& entry :
                     *mojom_group->interest_group->priority_signals_overrides) {
                  priority_signals_overrides.emplace_back(entry.key,
                                                          entry.value);
                }
                group->setPrioritySignalsOverrides(
                    std::move(priority_signals_overrides));
              }

              if (mojom_group->interest_group->seller_capabilities) {
                Vector<std::pair<String, Vector<String>>> seller_capabilities;
                seller_capabilities.reserve(
                    mojom_group->interest_group->seller_capabilities->size());
                for (const auto& entry :
                     *mojom_group->interest_group->seller_capabilities) {
                  Vector<String> capabilities;
                  capabilities.reserve(2);
                  if (entry.value->allows_interest_group_counts) {
                    capabilities.push_back("interest-group-counts");
                  }
                  if (entry.value->allows_latency_stats) {
                    capabilities.push_back("latency-stats");
                  }

                  seller_capabilities.emplace_back(entry.key->ToString(),
                                                   std::move(capabilities));
                }
                group->setSellerCapabilities(std::move(seller_capabilities));
              }

              String execution_mode_string;
              switch (mojom_group->interest_group->execution_mode) {
                case mojom::blink::InterestGroup::ExecutionMode::
                    kGroupedByOriginMode:
                  execution_mode_string = "group-by-origin";
                  break;
                case mojom::blink::InterestGroup::ExecutionMode::kFrozenContext:
                  execution_mode_string = "frozen-context";
                  break;
                case mojom::blink::InterestGroup::ExecutionMode::
                    kCompatibilityMode:
                  execution_mode_string = "compatibility";
                  break;
              }

              group->setExecutionMode(execution_mode_string);

              if (mojom_group->interest_group->bidding_url) {
                group->setBiddingLogicURL(
                    *mojom_group->interest_group->bidding_url);
                group->setBiddingLogicUrlDeprecated(
                    *mojom_group->interest_group->bidding_url);
              }

              if (mojom_group->interest_group->bidding_wasm_helper_url) {
                group->setBiddingWasmHelperURL(
                    *mojom_group->interest_group->bidding_wasm_helper_url);
                group->setBiddingWasmHelperUrlDeprecated(
                    *mojom_group->interest_group->bidding_wasm_helper_url);
              }

              if (mojom_group->interest_group->update_url) {
                group->setUpdateURL(*mojom_group->interest_group->update_url);
                group->setUpdateUrlDeprecated(
                    *mojom_group->interest_group->update_url);
              }

              if (mojom_group->interest_group->trusted_bidding_signals_url) {
                group->setTrustedBiddingSignalsURL(
                    *mojom_group->interest_group->trusted_bidding_signals_url);
                group->setTrustedBiddingSignalsUrlDeprecated(
                    *mojom_group->interest_group->trusted_bidding_signals_url);
              }

              if (mojom_group->interest_group->trusted_bidding_signals_keys) {
                group->setTrustedBiddingSignalsKeys(
                    *mojom_group->interest_group->trusted_bidding_signals_keys);
              }

              String trusted_bidding
```