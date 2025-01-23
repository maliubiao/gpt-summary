Response:
Let's break down the thought process for analyzing this code and answering the prompt.

1. **Understand the Goal:** The core request is to understand the functionality of `sub_apps.cc`, its relationships with web technologies (HTML, CSS, JavaScript), common errors, and how users might trigger its execution.

2. **Initial Code Scan - Identifying Key Elements:**  First, quickly read through the code, looking for keywords and patterns. I noticed:
    * `#include`: Standard C++ includes. Several relate to Blink internals (bindings, core, platform). `v8_sub_apps_add_params.h`, `v8_sub_apps_list_result.h`, `v8_sub_apps_result_code.h` immediately suggest interactions with JavaScript.
    * `namespace blink`: This is within the Blink rendering engine's namespace.
    * `class SubApps`: This is the main class we're interested in.
    * `Supplement<Navigator>`:  Indicates this class adds functionality to the `Navigator` object (accessible in JavaScript as `navigator`).
    * `GetService()`:  This suggests an interaction with an external service, likely through Mojo (inter-process communication in Chromium). The `mojom::blink::SubAppsService` confirms this.
    * `add()`, `list()`, `remove()`: These are clearly methods that correspond to operations on sub-apps. Their signatures take `ScriptState*` and `ExceptionState&`, further solidifying their connection to JavaScript bindings.
    * `ScriptPromise`: Return type of `add`, `list`, and `remove` strongly indicates these are asynchronous operations exposed to JavaScript.
    * `CheckPreconditionsMaybeThrow()`: This function checks for various conditions before executing the main logic, likely related to security and context.
    * `AddOptionsToMojo`, `AddResultsFromMojo`, `ListResultsFromMojo`, `RemoveResultsFromMojo`: These functions convert between Blink's internal representation and Mojo message structures.
    * Constants like `kMaximumNumberOfSubappsPerAddCall`.

3. **Infer Functionality (High-Level):** Based on the class name, the method names, and the interaction with a `SubAppsService`, the core functionality is clearly related to managing "sub-apps."  This likely involves adding, listing, and removing them. The use of Mojo suggests this interaction might be with a browser process or another part of Chromium.

4. **Relate to Web Technologies:**  The presence of `ScriptPromise`, `ScriptState`, and the parameter types (like `HeapVector<std::pair<String, Member<SubAppsAddParams>>>`) immediately screams "JavaScript API."  The association with `Navigator` further confirms this. The operations deal with "manifest ID paths" and "install URLs," which are concepts directly related to web apps and their installation. While the code itself doesn't directly manipulate HTML or CSS, the *result* of these operations (installing/managing sub-apps) will definitely affect the web page's behavior and potentially the user's experience with related web content.

5. **Illustrate with Examples (JavaScript):** Now, formulate concrete JavaScript examples. Think about how a web developer would use this API. The `navigator.subApps` object (inferred from `Supplement<Navigator>`) is the entry point. Then, call the `add`, `list`, and `remove` methods, providing sample data matching the expected types (strings, objects with `installURL`). Show both successful and potentially failing scenarios (like exceeding the limit or providing invalid URLs).

6. **Reasoning and Assumptions (Input/Output):**  For the logical flow, focus on the `add` method as it's more complex. Trace the execution path:
    * **Input:**  A JavaScript call to `navigator.subApps.add()` with a list of sub-app information.
    * **Preconditions:** Checks for secure context, permissions policy, and user activation.
    * **Mojo Interaction:**  Conversion of input to Mojo messages and sending to the `SubAppsService`.
    * **Mojo Response:** Receiving the results (success or failure for each sub-app).
    * **Output:** A JavaScript Promise that resolves with a list of results (manifest ID and status) or rejects if any sub-app addition failed.

7. **Common Errors:** Consider what could go wrong from a developer's perspective:
    * **Incorrect API Usage:**  Calling the methods with the wrong types or formats for the arguments.
    * **Security and Context Issues:** Not being in a secure context, violating the permissions policy.
    * **User Activation:**  Calling `add` without recent user interaction.
    * **Limits:** Exceeding the maximum number of sub-apps in a single `add` call.
    * **Invalid Paths:**  Providing absolute URLs instead of root-relative paths.

8. **User Interaction and Debugging:**  Think about how a user's actions lead to this code being executed. The user needs to interact with a web page that uses the Sub Apps API. This involves navigation, clicking buttons, etc. For debugging, the key is to inspect the JavaScript calls, check for errors in the browser's developer console, and potentially trace the network requests (although this API might not involve direct network requests in the traditional sense). Looking at the "call stack" in the debugger when the `add`, `list`, or `remove` methods are called would pinpoint the user's initiating action.

9. **Structure and Refine:** Organize the information logically under the requested headings. Use clear and concise language. Provide specific code examples. Ensure the explanation flows well and is easy to understand. Review for accuracy and completeness. Make sure to explicitly state any assumptions made. For example, the assumption that `navigator.subApps` is the JavaScript API entry point.

This structured approach helps to systematically analyze the code, identify its key features, and explain its relationship to the broader web development ecosystem. It moves from a high-level understanding to specific details and examples.
这个文件 `sub_apps.cc` 是 Chromium Blink 引擎中实现 **Sub Apps API** 的核心逻辑。Sub Apps API 允许一个 Web 应用声明并管理其他作为 "sub-apps" 的 Web 应用。

**功能列举:**

1. **提供 JavaScript API:**  它通过 `SubApps` 类向 JavaScript 暴露了 `navigator.subApps` 对象，使得 Web 开发者可以在页面脚本中调用相关方法来管理子应用。
2. **`add()` 方法:**  允许 Web 应用请求将其他 Web 应用添加为子应用。
    * 接收一个包含要添加的子应用信息的列表，每个子应用信息包括 `manifest_id_path` (子应用 manifest 文件的相对路径) 和 `installURL` (子应用的安装 URL)。
    * 内部通过 Mojo 与浏览器进程中的 `SubAppsService` 进行通信，发起添加子应用的请求。
    * 返回一个 Promise，该 Promise 在子应用添加操作完成后 resolve 或 reject。
3. **`list()` 方法:** 允许 Web 应用列出已经添加的子应用。
    * 内部通过 Mojo 与 `SubAppsService` 通信，获取已添加子应用的列表。
    * 返回一个 Promise，该 Promise 在获取子应用列表成功后 resolve，返回包含子应用信息的列表（`manifest_id_path` 和 `appName`）。
4. **`remove()` 方法:** 允许 Web 应用请求移除已添加的子应用。
    * 接收一个包含要移除的子应用的 `manifest_id_path` 列表。
    * 内部通过 Mojo 与 `SubAppsService` 通信，发起移除子应用的请求。
    * 返回一个 Promise，该 Promise 在子应用移除操作完成后 resolve 或 reject。
5. **权限和安全检查:** 在执行 `add`、`list` 和 `remove` 操作前，会进行一系列的权限和安全检查，例如：
    * **Secure Context:**  API 只能在安全上下文 (HTTPS) 中使用。
    * **Permissions Policy:** 检查当前顶层浏览上下文是否被授予了 "sub-apps" 权限策略。
    * **主 Frame:** API 只能在主 Frame 中调用。
    * **用户激活 (User Activation):**  `add()` 方法可能需要用户激活，以防止未经用户同意就添加子应用。
6. **与浏览器进程通信:** 使用 Chromium 的 IPC 机制 Mojo 与浏览器进程中的 `SubAppsService` 进行通信，将子应用管理的操作委托给浏览器进程处理。
7. **数据转换:**  在 JavaScript 的数据类型和 Mojo 定义的数据类型之间进行转换，例如 `AddOptionsToMojo` 和 `AddResultsFromMojo` 等函数。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这个文件直接为 JavaScript 提供了 API (`navigator.subApps`)。开发者可以使用 JavaScript 代码来调用 `add()`, `list()`, 和 `remove()` 方法。

   ```javascript
   // 假设用户点击了一个按钮触发添加子应用
   async function addSubApp() {
     try {
       const results = await navigator.subApps.add([
         { manifestURL: './sub-app-manifest.json', installURL: '/sub-app' }
       ]);
       results.forEach(result => {
         if (result.resultCode === 'success') {
           console.log(`Successfully added sub-app: ${result.manifestURL}`);
         } else {
           console.error(`Failed to add sub-app: ${result.manifestURL}`);
         }
       });
     } catch (error) {
       console.error('Error adding sub-app:', error);
     }
   }

   // 列出已添加的子应用
   async function listSubApps() {
     try {
       const results = await navigator.subApps.list();
       results.forEach(result => {
         console.log(`Sub-app: ${result.appName} (${result.manifestURL})`);
       });
     } catch (error) {
       console.error('Error listing sub-apps:', error);
     }
   }

   // 移除一个子应用
   async function removeSubApp(manifestURL) {
     try {
       const results = await navigator.subApps.remove([manifestURL]);
       results.forEach(result => {
         if (result.resultCode === 'success') {
           console.log(`Successfully removed sub-app: ${result.manifestURL}`);
         } else {
           console.error(`Failed to remove sub-app: ${result.manifestURL}`);
         }
       });
     } catch (error) {
       console.error('Error removing sub-app:', error);
     }
   }
   ```

* **HTML:** HTML 定义了触发 JavaScript 代码的 UI 元素，例如按钮。用户与 HTML 元素的交互会调用上面示例中的 JavaScript 函数。

   ```html
   <button onclick="addSubApp()">添加子应用</button>
   <button onclick="listSubApps()">列出子应用</button>
   <button onclick="removeSubApp('./another-sub-app-manifest.json')">移除另一个子应用</button>
   ```

* **CSS:** CSS 负责控制 HTML 元素的样式，但与 `sub_apps.cc` 的功能没有直接的逻辑关系。然而，CSS 可以影响用户体验，从而间接地影响用户如何与触发 Sub Apps API 的 UI 交互。

**逻辑推理 (假设输入与输出):**

**假设输入 (JavaScript 调用):**

```javascript
navigator.subApps.add([
  { manifestURL: './my-sub-app-manifest.json', installURL: '/my-sub-app' },
  { manifestURL: './another-sub-app-manifest.json', installURL: '/another-sub-app' }
]);
```

**逻辑推理:**

1. `SubApps::add()` 方法被调用，接收到包含两个子应用信息的列表。
2. 进行安全检查，例如是否在安全上下文，是否具有相应的权限策略。
3. 检查是否需要用户激活，如果需要，并且没有用户激活，则 Promise 会 reject。
4. 将 JavaScript 传递的参数转换为 Mojo 可以理解的格式 (`AddOptionsToMojo`)。
5. 通过 `GetService()->Add()` 将添加子应用的请求发送到浏览器进程。
6. 浏览器进程处理请求，可能会显示安装提示给用户。
7. 浏览器进程完成添加操作后，会将结果通过 Mojo 返回给渲染进程。
8. `SubApps::add()` 的回调函数接收到 Mojo 返回的结果 (`results_mojo`)。
9. 将 Mojo 的结果转换为 JavaScript 可以理解的格式 (`AddResultsFromMojo`)。
10. 如果所有子应用都添加成功，Promise 将 resolve，并返回一个包含每个子应用添加结果的数组，例如：

**假设输出 (Promise resolve 的值):**

```json
[
  { "manifestURL": "./my-sub-app-manifest.json", "resultCode": "success" },
  { "manifestURL": "./another-sub-app-manifest.json", "resultCode": "success" }
]
```

**假设输入 (JavaScript 调用，添加失败的情况):**

```javascript
navigator.subApps.add([
  { manifestURL: './invalid-manifest.json', installURL: '/invalid-sub-app' }
]);
```

**假设输出 (Promise reject 的值):**

```json
[
  { "manifestURL": "./invalid-manifest.json", "resultCode": "failure" }
]
```

**用户或编程常见的使用错误及举例说明:**

1. **未在安全上下文中使用:** 在非 HTTPS 页面调用 `navigator.subApps.add()` 等方法会导致安全错误。

   ```javascript
   // 在 HTTP 页面尝试调用
   navigator.subApps.add([...]); // 会抛出 SecurityError
   ```

2. **缺少必要的权限策略:** 页面所在的顶层浏览上下文没有 "sub-apps" 权限策略，调用 API 会抛出错误。

3. **`add()` 方法在需要用户激活时未进行用户交互:**  在没有用户最近点击或交互的情况下调用 `add()`，可能会导致 `NotAllowedError`。

   ```javascript
   // 页面加载后立即尝试添加，可能失败
   window.onload = () => {
     navigator.subApps.add([...]); // 可能抛出 NotAllowedError
   };
   ```

4. **传递非根相对路径:** `manifestURL` 和 `installURL` 必须是根相对路径。传递绝对 URL 或其他非根相对路径会导致 `NotSupportedError`。

   ```javascript
   navigator.subApps.add([
     { manifestURL: 'https://example.com/sub-app-manifest.json', installURL: '/sub-app' } // 错误：绝对 URL
   ]);
   ```

5. **`add()` 方法一次添加过多子应用:**  出于用户体验考虑，`add()` 方法可能会限制一次添加的子应用数量 (`kMaximumNumberOfSubappsPerAddCall`)。超出限制会抛出 `DataError`。

   ```javascript
   const manySubApps = Array(10).fill({ manifestURL: './...', installURL: '/...' });
   navigator.subApps.add(manySubApps); // 可能抛出 DataError
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码被执行。**
3. **JavaScript 代码调用了 `navigator.subApps.add()`, `navigator.subApps.list()`, 或 `navigator.subApps.remove()` 方法。**  这通常是由于用户的某些操作触发了 JavaScript 函数的执行，例如：
    * **点击按钮:** 用户点击了一个绑定了调用 `navigator.subApps` 方法的事件处理器的按钮。
    * **页面加载完成:** 页面加载完成后，JavaScript 代码自动执行 `navigator.subApps` 相关操作。
    * **其他用户交互:**  例如，用户提交表单、滚动页面等触发的事件。
4. **浏览器接收到 JavaScript 的 API 调用。**
5. **Blink 渲染引擎处理该调用，并执行 `sub_apps.cc` 文件中对应的方法 (例如 `SubApps::add`)。**
6. **`sub_apps.cc` 中的代码会进行权限检查和参数验证。**
7. **如果需要，Blink 会通过 Mojo 与浏览器进程的 `SubAppsService` 进行通信。**
8. **浏览器进程执行实际的子应用管理操作 (例如安装、列出、卸载)。**
9. **操作结果通过 Mojo 返回给渲染进程。**
10. **`sub_apps.cc` 中的回调函数处理返回结果，并将结果传递给 JavaScript 的 Promise。**
11. **JavaScript 的 Promise resolve 或 reject，开发者可以根据结果进行后续处理。**

**调试线索:**

* **JavaScript Console:** 查看浏览器的开发者工具控制台，检查是否有 JavaScript 错误信息，例如 `SecurityError`, `NotAllowedError`, `DataError`, `NotSupportedError` 等。这些错误通常会指出 API 调用失败的原因。
* **断点调试:** 在浏览器的开发者工具中，可以在 JavaScript 代码中设置断点，查看 `navigator.subApps.add()` 等方法的参数和返回值。
* **Blink 内部调试:** 如果需要更深入的调试，可以在 Blink 渲染引擎的源代码中设置断点，例如在 `sub_apps.cc` 的 `SubApps::add`, `SubApps::list`, `SubApps::remove` 方法中设置断点，跟踪代码的执行流程，查看 Mojo 消息的传递和处理。
* **Mojo Inspector:** Chromium 提供了 Mojo Inspector 工具，可以用来查看 Mojo 消息的传递，帮助理解渲染进程和浏览器进程之间的通信过程。
* **网络请求:** 虽然 Sub Apps API 本身不涉及直接的网络请求来添加子应用（它依赖于已知的 manifest 文件），但可以检查 manifest 文件的加载是否成功。
* **Permissions Policy:** 检查页面的 Permissions Policy header 或 iframe 的 `allow` 属性，确认 "sub-apps" 权限策略是否被正确授予。

总而言之，`blink/renderer/modules/subapps/sub_apps.cc` 是 Blink 引擎中实现 Sub Apps API 的关键文件，它将浏览器底层的子应用管理能力暴露给 JavaScript，使得 Web 开发者可以通过脚本来管理其 Web 应用的子应用。

### 提示词
```
这是目录为blink/renderer/modules/subapps/sub_apps.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/subapps/sub_apps.h"

#include <utility>

#include "base/check.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sub_apps_add_params.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sub_apps_list_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sub_apps_result_code.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using mojom::blink::SubAppsService;
using mojom::blink::SubAppsServiceAddParameters;
using mojom::blink::SubAppsServiceAddParametersPtr;
using mojom::blink::SubAppsServiceAddResultPtr;
using mojom::blink::SubAppsServiceListResultEntryPtr;
using mojom::blink::SubAppsServiceListResultPtr;
using mojom::blink::SubAppsServiceRemoveResultPtr;
using mojom::blink::SubAppsServiceResultCode;

namespace {

const int kMaximumNumberOfSubappsPerAddCall = 7;

Vector<std::pair<String, V8SubAppsResultCode>> AddResultsFromMojo(
    Vector<SubAppsServiceAddResultPtr> add_results_mojo) {
  Vector<std::pair<String, V8SubAppsResultCode>> add_results_idl;
  for (auto& add_result : add_results_mojo) {
    auto result_code =
        add_result->result_code == SubAppsServiceResultCode::kSuccess
            ? V8SubAppsResultCode(V8SubAppsResultCode::Enum::kSuccess)
            : V8SubAppsResultCode(V8SubAppsResultCode::Enum::kFailure);
    add_results_idl.emplace_back(add_result->manifest_id_path, result_code);
  }
  return add_results_idl;
}

Vector<std::pair<String, V8SubAppsResultCode>> RemoveResultsFromMojo(
    Vector<SubAppsServiceRemoveResultPtr> remove_results_mojo) {
  Vector<std::pair<String, V8SubAppsResultCode>> results;
  for (auto& remove_result : remove_results_mojo) {
    auto result_code =
        remove_result->result_code == SubAppsServiceResultCode::kSuccess
            ? V8SubAppsResultCode(V8SubAppsResultCode::Enum::kSuccess)
            : V8SubAppsResultCode(V8SubAppsResultCode::Enum::kFailure);
    results.emplace_back(remove_result->manifest_id_path, result_code);
  }
  return results;
}

Vector<SubAppsServiceAddParametersPtr> AddOptionsToMojo(
    HeapVector<std::pair<String, Member<SubAppsAddParams>>>
        sub_apps_to_add_idl) {
  Vector<SubAppsServiceAddParametersPtr> sub_apps_to_add_mojo;
  for (auto& [manifest_id_path, add_params] : sub_apps_to_add_idl) {
    sub_apps_to_add_mojo.emplace_back(SubAppsServiceAddParameters::New(
        manifest_id_path, add_params->installURL()));
  }
  return sub_apps_to_add_mojo;
}

HeapVector<std::pair<String, Member<SubAppsListResult>>> ListResultsFromMojo(
    Vector<SubAppsServiceListResultEntryPtr> sub_apps_list_mojo) {
  HeapVector<std::pair<String, Member<SubAppsListResult>>> sub_apps_list_idl;
  for (auto& sub_app_entry : sub_apps_list_mojo) {
    SubAppsListResult* list_result = SubAppsListResult::Create();
    list_result->setAppName(std::move(sub_app_entry->app_name));
    sub_apps_list_idl.emplace_back(std::move(sub_app_entry->manifest_id_path),
                                   list_result);
  }
  return sub_apps_list_idl;
}

}  // namespace

// static
const char SubApps::kSupplementName[] = "SubApps";

SubApps::SubApps(Navigator& navigator)
    : Supplement<Navigator>(navigator),
      service_(navigator.GetExecutionContext()) {}

// static
SubApps* SubApps::subApps(Navigator& navigator) {
  SubApps* subapps = Supplement<Navigator>::From<SubApps>(navigator);
  if (!subapps) {
    subapps = MakeGarbageCollected<SubApps>(navigator);
    ProvideTo(navigator, subapps);
  }
  return subapps;
}

void SubApps::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);
  visitor->Trace(service_);
}

HeapMojoRemote<SubAppsService>& SubApps::GetService() {
  if (!service_.is_bound()) {
    auto* context = GetSupplementable()->GetExecutionContext();
    context->GetBrowserInterfaceBroker().GetInterface(
        service_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    // In case the other endpoint gets disconnected, we want to reset our end of
    // the pipe as well so that we don't remain connected to a half-open pipe.
    service_.set_disconnect_handler(
        WTF::BindOnce(&SubApps::OnConnectionError, WrapWeakPersistent(this)));
  }
  return service_;
}

void SubApps::OnConnectionError() {
  service_.reset();
}

ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>> SubApps::add(
    ScriptState* script_state,
    const HeapVector<std::pair<String, Member<SubAppsAddParams>>>&
        sub_apps_to_add,
    ExceptionState& exception_state) {
  // [SecureContext] from the IDL ensures this.
  DCHECK(ExecutionContext::From(script_state)->IsSecureContext());

  if (!CheckPreconditionsMaybeThrow(script_state, exception_state)) {
    return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
  }

  auto* frame = GetSupplementable()->DomWindow()->GetFrame();
  bool needsUserActivation =
      frame->GetSettings()
          ->GetRequireTransientActivationAndAuthorizationForSubAppsAPI();

  // We don't need user activation if the right policy is set.
  if (needsUserActivation &&
      !LocalFrame::ConsumeTransientUserActivation(frame)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Unable to add sub-app. This API can only be called shortly after a "
        "user activation.");
    return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
  }

  // We don't need to limit add() if the right policy is set, we mainly want to
  // avoid overwhelming the user with a permissions prompt that lists dozens of
  // apps to install.
  if (needsUserActivation &&
      sub_apps_to_add.size() > kMaximumNumberOfSubappsPerAddCall) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        "Unable to add sub-apps. The maximum number of apps added per call "
        "is " +
            String::Number(kMaximumNumberOfSubappsPerAddCall) + ", but " +
            String::Number(sub_apps_to_add.size()) + " were provided.");
    return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
  }

  // Check that the arguments are root-relative paths.
  for (const auto& [manifest_id_path, add_params] : sub_apps_to_add) {
    if (KURL(manifest_id_path).IsValid() ||
        KURL(add_params->installURL()).IsValid()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "Arguments must be root-relative paths.");
      return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
    }
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLRecord<IDLString, V8SubAppsResultCode>>>(
      script_state);
  GetService()->Add(
      AddOptionsToMojo(std::move(sub_apps_to_add)),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](ScriptPromiseResolver<IDLRecord<IDLString, V8SubAppsResultCode>>*
                 resolver,
             Vector<SubAppsServiceAddResultPtr> results_mojo) {
            for (const auto& add_result : results_mojo) {
              if (add_result->result_code ==
                  SubAppsServiceResultCode::kFailure) {
                return resolver
                    ->Reject<IDLRecord<IDLString, V8SubAppsResultCode>>(
                        AddResultsFromMojo(std::move(results_mojo)));
              }
            }
            resolver->Resolve(AddResultsFromMojo(std::move(results_mojo)));
          })));
  return resolver->Promise();
}

ScriptPromise<IDLRecord<IDLString, SubAppsListResult>> SubApps::list(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!CheckPreconditionsMaybeThrow(script_state, exception_state)) {
    return ScriptPromise<IDLRecord<IDLString, SubAppsListResult>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLRecord<IDLString, SubAppsListResult>>>(
      script_state);
  GetService()->List(resolver->WrapCallbackInScriptScope(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLRecord<IDLString, SubAppsListResult>>*
             resolver,
         SubAppsServiceListResultPtr result) {
        if (result->result_code == SubAppsServiceResultCode::kSuccess) {
          resolver->Resolve(
              ListResultsFromMojo(std::move(result->sub_apps_list)));
        } else {
          resolver->Reject(V8ThrowDOMException::CreateOrDie(
              resolver->GetScriptState()->GetIsolate(),
              DOMExceptionCode::kOperationError,
              "Unable to list sub-apps. Check whether the calling app is "
              "installed."));
        }
      })));

  return resolver->Promise();
}

ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>> SubApps::remove(
    ScriptState* script_state,
    const Vector<String>& manifest_id_paths,
    ExceptionState& exception_state) {
  if (!CheckPreconditionsMaybeThrow(script_state, exception_state)) {
    return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
  }

  // Check that the arguments are root-relative paths.
  for (const auto& manifest_id_path : manifest_id_paths) {
    if (KURL(manifest_id_path).IsValid()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "Arguments must be root-relative paths.");
      return ScriptPromise<IDLRecord<IDLString, V8SubAppsResultCode>>();
    }
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLRecord<IDLString, V8SubAppsResultCode>>>(
      script_state);
  GetService()->Remove(
      manifest_id_paths,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](ScriptPromiseResolver<IDLRecord<IDLString, V8SubAppsResultCode>>*
                 resolver,
             Vector<SubAppsServiceRemoveResultPtr> results_mojo) {
            for (const auto& remove_result : results_mojo) {
              if (remove_result->result_code ==
                  SubAppsServiceResultCode::kFailure) {
                return resolver
                    ->Reject<IDLRecord<IDLString, V8SubAppsResultCode>>(
                        RemoveResultsFromMojo(std::move(results_mojo)));
              }
            }
            resolver->Resolve(RemoveResultsFromMojo(std::move(results_mojo)));
          })));
  return resolver->Promise();
}

bool SubApps::CheckPreconditionsMaybeThrow(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  if (!ExecutionContext::From(script_state)
           ->IsFeatureEnabled(
               mojom::blink::PermissionsPolicyFeature::kSubApps)) {
    exception_state.ThrowSecurityError(
        "The executing top-level browsing context is not granted the "
        "\"sub-apps\" permissions policy.");
    return false;
  }

  Navigator* const navigator = GetSupplementable();

  if (!navigator->DomWindow()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The object is no longer associated to a document.");
    return false;
  }

  if (!navigator->DomWindow()->GetFrame()->IsMainFrame() ||
      navigator->DomWindow()->GetFrame()->GetPage()->IsPrerendering() ||
      navigator->DomWindow()->GetFrame()->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "API is only supported in primary top-level browsing contexts.");
    return false;
  }

  return true;
}

}  // namespace blink
```