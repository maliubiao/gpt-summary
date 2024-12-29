Response:
Let's break down the request and the provided C++ code to generate a comprehensive explanation.

**1. Understanding the Goal:**

The core task is to analyze the given C++ code (`shared_storage_worklet.cc`) and explain its functionalities, connections to web technologies (JavaScript, HTML, CSS), logical reasoning, potential errors, and how a user might trigger this code.

**2. Initial Code Scan and Keyword Identification:**

I first scanned the code, looking for key terms and patterns:

* **`SharedStorageWorklet`**:  The central class. Likely involved in executing some kind of work within the shared storage context.
* **`addModule`**:  Suggests loading and running code, probably JavaScript modules.
* **`selectURL`**:  Implies a selection process based on URLs. The return type `V8SharedStorageResponse` and connection to `FencedFrameConfig` hints at involvement with Fenced Frames.
* **`run`**:  A general execution method, likely running a named operation within the worklet.
* **`ScriptPromise`**: Indicates asynchronous operations and interaction with JavaScript.
* **`WorkletOptions`**: Configuration for worklet execution.
* **`SharedStorageRunOperationMethodOptions`**:  Options specific to the `selectURL` and `run` methods, including `data` and `keepAlive`.
* **`PermissionsPolicy`**:  Security checks related to Shared Storage features.
* **`ExecutionContext`**:  Represents the context in which code runs (e.g., a window).
* **`SecurityOrigin`**:  Crucial for enforcing same-origin policy and other security restrictions.
* **`FencedFrameConfig`**: Strongly links to the Fenced Frames API.
* **`PrivateAggregationConfig`**: Indicates interaction with the Private Aggregation API.
* **Error messages (e.g., "addModule() can only be invoked once...")**: Indicate potential usage errors.

**3. Deconstructing Function by Function:**

I then analyzed each public method of the `SharedStorageWorklet` class:

* **`Create`**: A static factory method for creating `SharedStorageWorklet` instances. The `cross_origin_script_allowed` parameter is important for security.
* **`addModule`**: This seems to be the entry point for loading a JavaScript module into the shared storage worklet. The checks for same-origin and permissions policy are significant. The `resolve_to_worklet` parameter suggests different return behaviors.
* **`AddModuleHelper`**:  The internal implementation of `addModule`. It handles URL validation, security origin checks, permissions policy enforcement, and communication with the browser process via `SharedStorageDocumentService`.
* **`selectURL` (overloads)**:  This method is about selecting a URL from a list, possibly based on some logic in the worklet. The `options` parameter allows passing data and controlling behavior like `resolveToConfig`. The interaction with `FencedFrameConfig` is a key point. The handling of `reportingMetadata` is also important.
* **`run` (overloads)**:  A more general mechanism to execute code within the worklet. It also takes options and handles data passing.

**4. Identifying Relationships with Web Technologies:**

Based on the function analysis, I mapped the C++ code to JavaScript, HTML, and CSS concepts:

* **JavaScript:** The `addModule` method directly involves loading and executing JavaScript modules. The `selectURL` and `run` methods are called from JavaScript and return promises. Data is passed between JavaScript and C++ through serialization.
* **HTML:** The `selectURL` method's potential to return a `FencedFrameConfig` directly links to the `<fencedframe>` HTML element. The reporting metadata also interacts with the Fenced Frames reporting mechanism.
* **CSS:**  While not directly interacting with CSS *styling*, the Fenced Frames API (which this code touches) can influence layout and rendering, and potentially interact with CSS through mechanisms like container queries (though the provided code doesn't show direct CSS interaction).

**5. Logical Reasoning and Assumptions:**

I looked for places where the code makes decisions and what the inputs and outputs would be:

* **`addModule`**:
    * **Input:** A URL to a JavaScript module.
    * **Output:** A promise that resolves when the module is loaded successfully or rejects on failure.
* **`selectURL`**:
    * **Input:** A name, a list of URLs with optional metadata, and options (including data).
    * **Output:** A promise that resolves with a UUID or a `FencedFrameConfig` based on the `resolveToConfig` option.
* **`run`**:
    * **Input:** A name and optional data.
    * **Output:** A promise that resolves when the named operation completes successfully or rejects on failure.

**6. Identifying User/Programming Errors:**

I focused on the error messages and the logic that could lead to them:

* Calling `addModule` more than once.
* Providing an invalid module URL.
* Trying to use `selectURL` or `run` before calling `addModule`.
* Violating the "shared-storage" or "shared-storage-select-url" permissions policy.
* Providing an invalid length for the `urls` array in `selectURL`.
* Using non-HTTPS URLs for reporting in `selectURL`.
* Not setting `keepAlive: true` for subsequent operations.

**7. Tracing User Operations (Debugging Clues):**

I imagined the sequence of user actions and code execution that would lead to this C++ code being invoked:

1. A website (HTML) uses JavaScript.
2. The JavaScript calls `sharedStorage.worklet.addModule('module.js')`. This triggers the C++ `SharedStorageWorklet::addModule` method.
3. Later, the JavaScript might call `sharedStorage.worklet.selectURL('myOperation', [...], { data: ..., resolveToConfig: true })`. This invokes the C++ `SharedStorageWorklet::selectURL` method.
4. Alternatively, the JavaScript might call `sharedStorage.worklet.run('anotherOperation', { data: ... })`. This invokes the C++ `SharedStorageWorklet::run` method.

**8. Structuring the Output:**

Finally, I organized the information into the requested categories: functionalities, relationships with web technologies, logical reasoning, common errors, and user operation tracing. I aimed for clarity, providing concrete examples where relevant. The use of bullet points, code snippets (even conceptual ones), and clear headings helps with readability.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the lower-level C++ details. I then shifted to emphasize the connections to the web platform.
* I made sure to explicitly connect the `FencedFrameConfig` to the `<fencedframe>` element in HTML.
* I reviewed the error messages to ensure I accurately described the user actions that would trigger them.
* I double-checked the assumptions made in the logical reasoning section and ensured the inputs and outputs aligned with the code.
* I refined the "User Operation Tracing" to be a step-by-step narrative, making it easier to understand how the code gets invoked.

By following these steps, I could systematically analyze the code and generate a comprehensive and accurate explanation that addresses all aspects of the original request.
好的， 让我们来分析一下 `blink/renderer/modules/shared_storage/shared_storage_worklet.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述:**

这个文件定义了 `SharedStorageWorklet` 类，它在 Blink 渲染引擎中负责处理与 Shared Storage API 相关的 Worklet。Shared Storage API 允许网站存储跨站点的数据，用于特定的隐私保护的用例，例如 A/B 测试、内容选择等。

`SharedStorageWorklet` 的主要功能包括：

1. **加载和执行 Shared Storage Worklet 模块:**  通过 `addModule()` 方法加载 JavaScript 模块到 Worklet 中执行。
2. **执行 Worklet 中的操作:** 提供 `selectURL()` 和 `run()` 方法，允许 JavaScript 调用 Worklet 中定义的特定操作。
3. **管理 Worklet 的生命周期:**  控制 Worklet 的创建和销毁。
4. **处理权限策略:** 检查与 Shared Storage 相关的权限策略。
5. **与浏览器进程通信:**  通过 `worklet_host_` 与浏览器进程中的 Shared Storage 服务进行通信。
6. **数据序列化和反序列化:**  处理在 JavaScript 和 C++ 之间传递的数据的序列化和反序列化。
7. **集成 Fenced Frames:**  `selectURL()` 方法可以返回用于创建 Fenced Frame 的配置信息。
8. **支持 Private Aggregation:**  `selectURL()` 和 `run()` 方法支持配置 Private Aggregation。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 Blink 引擎的 C++ 代码，它为 Web 开发者使用的 JavaScript API 提供了底层实现。

* **JavaScript:**
    * **`sharedStorage.worklet.addModule(url, options)`:**  `SharedStorageWorklet::addModule()` 方法直接对应了这个 JavaScript API。当 JavaScript 调用 `addModule()` 时，Blink 会解析 URL，获取 JavaScript 代码，并在 Worklet 上下文中执行。
        ```javascript
        // JavaScript 示例
        sharedStorage.worklet.addModule('/path/to/my-shared-storage-module.js');
        ```
    * **`sharedStorage.worklet.selectURL(name, urls, options)`:** `SharedStorageWorklet::selectURL()` 方法实现了此功能。JavaScript 调用此方法来请求 Worklet 从提供的 URL 列表中选择一个 URL，并可能携带一些数据。这通常用于 Fenced Frames 的内容选择。
        ```javascript
        // JavaScript 示例
        sharedStorage.worklet.selectURL('my-selection-operation', [
          { url: 'https://example.com/content1', data: { id: 1 } },
          { url: 'https://example.net/content2', data: { id: 2 } }
        ], { data: { userSegment: 'A' }, resolveToConfig: true });
        ```
    * **`sharedStorage.worklet.run(name, options)`:** `SharedStorageWorklet::run()` 方法对应。JavaScript 调用此方法来执行 Worklet 中定义的命名操作，并可以传递数据。
        ```javascript
        // JavaScript 示例
        sharedStorage.worklet.run('my-counter-update', { data: { incrementBy: 1 } });
        ```
* **HTML:**
    * **`<fencedframe>`:**  `SharedStorageWorklet::selectURL()` 方法的 `resolveToConfig: true` 选项允许 JavaScript 获取一个 `FencedFrameConfig` 对象。这个对象可以用来配置和创建 `<fencedframe>` 元素。Shared Storage Worklet 可以在 Fenced Frame 中选择要展示的内容 URL。
        ```html
        <!-- HTML 示例 -->
        <script>
          sharedStorage.worklet.addModule('/path/to/my-shared-storage-module.js')
            .then(worklet => {
              return worklet.selectURL('content-selector', [
                { url: 'https://example.com/content1' },
                { url: 'https://example.net/content2' }
              ], { resolveToConfig: true });
            })
            .then(config => {
              const fencedFrame = document.createElement('fencedframe');
              fencedFrame.config = config;
              document.body.appendChild(fencedFrame);
            });
        </script>
        ```
* **CSS:**
    * **间接影响:** 虽然此 C++ 文件本身不直接处理 CSS，但 Shared Storage 和 Fenced Frames 的功能会影响最终页面的渲染。例如，通过 `selectURL()` 选择的不同 URL 可能会加载不同的 CSS 样式，从而改变页面的外观。

**逻辑推理 (假设输入与输出):**

**场景 1:  `addModule()`**

* **假设输入:**
    * `module_url`:  字符串 "https://example.com/my_worklet_module.js"
    * `options`:  空或包含凭据选项的对象。
* **逻辑推理:**
    1. 检查浏览上下文是否有效。
    2. 解析 `module_url`。
    3. 检查是否允许跨域脚本（取决于构造函数参数）。
    4. 检查权限策略是否允许 Shared Storage。
    5. 如果 Worklet Host 尚未创建，则创建一个新的 Worklet Host，并通过 IPC 将模块 URL 发送到浏览器进程加载。
* **预期输出:**
    * 如果成功加载模块，Promise 将解析为 `undefined`。
    * 如果加载失败（例如，URL 无效，跨域错误，权限被拒绝），Promise 将被拒绝，并抛出 `DOMException`。

**场景 2: `selectURL()`**

* **假设输入:**
    * `name`: 字符串 "choose-ad"
    * `urls`:  `HeapVector` 包含两个 `SharedStorageUrlWithMetadata` 对象：
        * URL: "https://advertiser1.com/creative1", reportingMetadata: { "click": "https://reporter.com/report_click_1" }
        * URL: "https://advertiser2.com/creative2", reportingMetadata: { "click": "https://reporter.com/report_click_2" }
    * `options`:  `SharedStorageRunOperationMethodOptions` 对象，包含 `data: { campaign: "summer-sale" }, keepAlive: true, resolveToConfig: true`
* **逻辑推理:**
    1. 检查浏览上下文是否有效。
    2. 检查是否已调用 `addModule()`。
    3. 检查 "shared-storage" 和 "shared-storage-select-url" 权限策略。
    4. 验证 `urls` 数组的长度和 URL 的有效性。
    5. 序列化 `options.data`。
    6. 如果 `keepAlive` 为 true，则标记 Worklet 可以继续执行后续操作。
    7. 将操作请求（包括名称、URL 列表、序列化数据、`keepAlive` 标志和 `resolveToConfig` 标志）通过 IPC 发送到浏览器进程。
* **预期输出:**
    * 如果 Worklet 成功执行选择操作，Promise 将解析为一个 `FencedFrameConfig` 对象，该对象包含所选 URL 和其他配置信息。
    * 如果发生错误（例如，Worklet 未加载，权限被拒绝，URL 无效），Promise 将被拒绝，并抛出 `DOMException`。

**场景 3: `run()`**

* **假设输入:**
    * `name`: 字符串 "increment-counter"
    * `options`: `SharedStorageRunOperationMethodOptions` 对象，包含 `data: { value: 5 }, keepAlive: false`
* **逻辑推理:**
    1. 检查浏览上下文是否有效。
    2. 检查是否已调用 `addModule()`。
    3. 检查 "shared-storage" 权限策略。
    4. 序列化 `options.data`。
    5. 如果 `keepAlive` 为 false，则标记 Worklet 在此操作后过期。
    6. 将操作请求（包括名称、序列化数据和 `keepAlive` 标志）通过 IPC 发送到浏览器进程。
* **预期输出:**
    * 如果 Worklet 成功执行操作，Promise 将解析为 `undefined`。
    * 如果发生错误，Promise 将被拒绝，并抛出 `DOMException`。

**用户或编程常见的使用错误举例说明:**

1. **未先调用 `addModule()` 就调用 `selectURL()` 或 `run()`:**
   ```javascript
   // 错误示例
   sharedStorage.worklet.selectURL('my-operation', []); // 报错，因为 Worklet 尚未加载
   ```
   **错误信息 (C++ 中产生):** `"sharedStorage.worklet.addModule() has to be called before selectURL()."` 或 `"sharedStorage.worklet.addModule() has to be called before run()."`

2. **多次调用 `addModule()`:**
   ```javascript
   // 错误示例
   sharedStorage.worklet.addModule('/module1.js');
   sharedStorage.worklet.addModule('/module2.js'); // 报错，Worklet 只能加载一个模块
   ```
   **错误信息 (C++ 中产生):** `"addModule() can only be invoked once per worklet."`

3. **提供无效的模块 URL:**
   ```javascript
   // 错误示例
   sharedStorage.worklet.addModule('invalid-url'); // 报错，URL 无法解析
   ```
   **错误信息 (C++ 中产生):** `"The module script url is invalid."`

4. **跨域调用 `addModule()` (如果 `cross_origin_script_allowed_` 为 false):**
   ```html
   <!-- 在 https://example.com 下的页面 -->
   <script>
     sharedStorage.worklet.addModule('https://another-domain.com/module.js'); // 报错
   </script>
   ```
   **错误信息 (C++ 中产生):** `"Only same origin module script is allowed."`

5. **在 `selectURL()` 中提供无效的 URL 或 Reporting Metadata URL:**
   ```javascript
   // 错误示例
   sharedStorage.worklet.selectURL('op', [{ url: 'invalid-url' }]); // URL 无效

   sharedStorage.worklet.selectURL('op', [{
     url: 'https://valid.com',
     reportingMetadata: { click: 'http://non-https.com/report' } // Reporting URL 必须是 HTTPS
   }]);
   ```
   **错误信息 (C++ 中产生):** `"The url \"invalid-url\" is invalid."` 或 `"The metadata for the url at index ... has an invalid or non-HTTPS report_url parameter ..."`

6. **在 `selectURL()` 或 `run()` 操作后 Worklet 过期，但仍尝试调用操作 (未设置 `keepAlive: true`):**
   ```javascript
   // 示例：第一个操作没有设置 keepAlive
   sharedStorage.worklet.run('first-op');
   sharedStorage.worklet.selectURL('second-op', []); // 报错，Worklet 已过期
   ```
   **错误信息 (C++ 中产生):** `"The sharedStorage worklet cannot execute further operations because the previous operation did not include the option \'keepAlive: true\'."`

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个网页 `https://example.com/index.html`。为了理解用户操作如何一步步触发到 `SharedStorageWorklet.cc` 中的代码，我们可以跟踪以下步骤：

1. **网页加载和 JavaScript 执行:** 用户在浏览器地址栏输入 `https://example.com/index.html` 或点击一个链接。浏览器加载 HTML 内容，并开始解析和执行其中包含的 JavaScript 代码。

2. **JavaScript 调用 Shared Storage API:**  网页的 JavaScript 代码可能包含了对 Shared Storage API 的调用，例如：
   ```javascript
   // index.html 中的 JavaScript
   navigator.sharedStorage.worklet.addModule('/my-shared-storage-worklet.js')
     .then(worklet => {
       return worklet.selectURL('choose-content', [
         { url: 'https://content-provider.com/item1' },
         { url: 'https://content-provider.com/item2' }
       ], { resolveToConfig: true });
     })
     .then(config => {
       const fencedFrame = document.createElement('fencedframe');
       fencedFrame.config = config;
       document.body.appendChild(fencedFrame);
     });
   ```

3. **Blink 引擎处理 JavaScript API 调用:** 当 JavaScript 引擎执行到 `navigator.sharedStorage.worklet.addModule()` 时，Blink 引擎会将这个调用路由到相应的 C++ 代码。具体来说：
    * `navigator.sharedStorage` 映射到 `SharedStorage` 接口的实现。
    * `worklet` 属性会访问到与当前文档关联的 `SharedStorageWorklet` 对象。
    * `addModule()` 方法的调用最终会触发 `blink::SharedStorageWorklet::addModule()` 方法的执行。

4. **`addModule()` 内部流程:**  `SharedStorageWorklet::addModule()` 方法会执行以下操作：
    * 检查权限和参数。
    * 创建一个 `worklet_host_` 对象，用于与浏览器进程通信。
    * 通过 Mojo IPC 将模块的 URL 发送到浏览器进程的 Shared Storage 服务。浏览器进程负责下载和编译 JavaScript 模块。
    * 当模块加载成功或失败时，浏览器进程会通过 IPC 通知渲染进程。

5. **后续的 `selectURL()` 调用:** 如果 `addModule()` 成功，并且 JavaScript 代码继续执行到 `worklet.selectURL()`，Blink 引擎会将此调用路由到 `blink::SharedStorageWorklet::selectURL()` 方法。

6. **`selectURL()` 内部流程:** `SharedStorageWorklet::selectURL()` 方法会执行：
    * 再次进行权限检查。
    * 序列化传递给 `selectURL()` 的数据。
    * 通过 Mojo IPC 将 `selectURL()` 操作的请求发送到浏览器进程的 Shared Storage 服务。

7. **浏览器进程中的 Shared Storage 服务:** 浏览器进程接收到来自渲染进程的请求后，会执行 Worklet 中的 JavaScript 代码（之前通过 `addModule()` 加载的）。Worklet 代码会根据其逻辑选择一个 URL。

8. **响应返回渲染进程:** 浏览器进程将操作的结果（例如，选定的 URL 或 `FencedFrameConfig`）通过 Mojo IPC 发送回渲染进程。

9. **Promise 解析和后续 JavaScript 执行:**  渲染进程的 `SharedStorageWorklet` 接收到响应后，会解析相应的 JavaScript Promise。在上面的例子中，`selectURL()` 返回的 Promise 会解析为 `FencedFrameConfig` 对象，然后 JavaScript 代码使用这个配置创建并插入 `<fencedframe>` 元素。

**调试线索:**

当开发者在调试 Shared Storage 相关问题时，可以关注以下线索：

* **JavaScript 控制台错误:**  如果 `addModule()`, `selectURL()`, 或 `run()` 调用失败，通常会在浏览器的 JavaScript 控制台中看到错误信息，这些信息往往对应着 `SharedStorageWorklet.cc` 中抛出的 `DOMException`。
* **`chrome://shared-storage-internals`:**  这个 Chrome 内部页面可以提供关于 Shared Storage 操作的详细信息，包括 Worklet 的加载状态、操作的执行情况等。
* **Blink 调试日志:**  通过设置 Blink 的调试标志（例如 `--enable-logging --v=1`），可以获取更详细的 Shared Storage 操作日志，包括 C++ 层的执行流程和错误信息。
* **Mojo IPC 消息:**  可以使用 Chrome 的 `about:tracing` 工具来查看渲染进程和浏览器进程之间传递的 Mojo IPC 消息，这有助于理解请求和响应的流程。
* **断点调试:**  开发者可以在 `SharedStorageWorklet.cc` 中设置断点，以便在代码执行到特定位置时暂停，并检查变量的值和调用堆栈，从而深入了解问题的根本原因。

总而言之，`blink/renderer/modules/shared_storage/shared_storage_worklet.cc` 是 Blink 引擎中实现 Shared Storage Worklet 功能的关键 C++ 文件，它负责加载、执行和管理 Worklet，并与 JavaScript API 和浏览器进程紧密协作，为 Web 开发者提供在浏览器中进行隐私保护的数据存储和处理能力。

Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet.h"

#include <optional>

#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/shared_storage/shared_storage_utils.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"
#include "third_party/blink/public/mojom/shared_storage/shared_storage.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_worklet_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_run_operation_method_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shared_storage_url_with_metadata.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_window_supplement.h"
#include "third_party/blink/renderer/modules/shared_storage/util.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "url/origin.h"

namespace blink {

namespace {

const char kSharedStorageWorkletExpiredMessage[] =
    "The sharedStorage worklet cannot execute further operations because the "
    "previous operation did not include the option \'keepAlive: true\'.";

std::optional<BlinkCloneableMessage> Serialize(
    const SharedStorageRunOperationMethodOptions* options,
    const ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  scoped_refptr<SerializedScriptValue> serialized_value =
      options->hasData()
          ? SerializedScriptValue::Serialize(
                options->data().GetIsolate(), options->data().V8Value(),
                SerializedScriptValue::SerializeOptions(), exception_state)
          : SerializedScriptValue::UndefinedValue();
  if (exception_state.HadException()) {
    return std::nullopt;
  }

  BlinkCloneableMessage output;
  output.message = std::move(serialized_value);
  output.sender_agent_cluster_id = execution_context.GetAgentClusterID();
  output.sender_origin = execution_context.GetSecurityOrigin()->IsolatedCopy();
  // TODO(yaoxia): do we need to set `output.sender_stack_trace_id`?

  return output;
}

// TODO(crbug.com/1335504): Consider moving this function to
// third_party/blink/common/fenced_frame/fenced_frame_utils.cc.
bool IsValidFencedFrameReportingURL(const KURL& url) {
  if (!url.IsValid()) {
    return false;
  }
  return url.ProtocolIs("https");
}

}  // namespace

// static
SharedStorageWorklet* SharedStorageWorklet::Create(
    ScriptState* script_state,
    bool cross_origin_script_allowed) {
  return MakeGarbageCollected<SharedStorageWorklet>(
      cross_origin_script_allowed);
}

void SharedStorageWorklet::Trace(Visitor* visitor) const {
  visitor->Trace(worklet_host_);
  ScriptWrappable::Trace(visitor);
}

ScriptPromise<IDLUndefined> SharedStorageWorklet::addModule(
    ScriptState* script_state,
    const String& module_url,
    const WorkletOptions* options,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  AddModuleHelper(script_state, resolver, module_url, options, exception_state,
                  /*resolve_to_worklet=*/false,
                  SharedStorageDataOrigin::kContextOrigin);
  return promise;
}

void SharedStorageWorklet::AddModuleHelper(
    ScriptState* script_state,
    ScriptPromiseResolverBase* resolver,
    const String& module_url,
    const WorkletOptions* options,
    ExceptionState& exception_state,
    bool resolve_to_worklet,
    SharedStorageDataOrigin data_origin_type) {
  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kAddModuleWebVisible);
    return;
  }

  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow());

  // An opaque data origin is not allowed. Here we reject the case where the
  // context origin is opaque and used as the data origin. Below we will address
  // the case where the script origin is opaque and used as the data origin.
  bool use_script_origin_as_data_origin =
      resolve_to_worklet &&
      (!base::FeatureList::IsEnabled(
           features::kSharedStorageCreateWorkletUseContextOriginByDefault) ||
       data_origin_type == SharedStorageDataOrigin::kScriptOrigin);

  if (!use_script_origin_as_data_origin &&
      execution_context->GetSecurityOrigin()->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueContextOriginCheckErrorMessage));
    return;
  }

  KURL script_source_url = execution_context->CompleteURL(module_url);

  if (!script_source_url.IsValid()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "The module script url is invalid."));
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kAddModuleWebVisible);
    return;
  }

  scoped_refptr<SecurityOrigin> script_security_origin =
      SecurityOrigin::Create(script_source_url);

  if (!resolve_to_worklet &&
      !execution_context->GetSecurityOrigin()->IsSameOriginWith(
          script_security_origin.get())) {
    // This `addModule()` call could be affected by the breaking change
    // proposed in https://github.com/WICG/shared-storage/pull/158 and now
    // implemented behind `blink::features::kSharedStorageCrossOriginScript`.
    // Measure its usage.
    execution_context->CountUse(
        WebFeature::kSharedStorageAPI_AddModule_CrossOriginScript);
  }

  if (!cross_origin_script_allowed_ &&
      !execution_context->GetSecurityOrigin()->IsSameOriginWith(
          script_security_origin.get())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Only same origin module script is allowed."));
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kAddModuleWebVisible);
    return;
  }

  if (worklet_host_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kOperationError,
        "addModule() can only be invoked once per worklet."));
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kAddModuleWebVisible);
    return;
  }

  if (resolve_to_worklet &&
      !execution_context->GetSecurityOrigin()->IsSameOriginWith(
          script_security_origin.get()) &&
      data_origin_type != SharedStorageDataOrigin::kScriptOrigin) {
    // This `createWorklet()` call could be affected by the breaking change
    // proposed in https://github.com/WICG/shared-storage/pull/158 and now
    // implemented behind
    // `blink::features::kSharedStorageCreateWorkletUseContextOriginByDefault`.
    // Increment the use counter.
    execution_context->CountUse(
        WebFeature::
            kSharedStorageAPI_CreateWorklet_CrossOriginScriptDefaultDataOrigin);
  }

  scoped_refptr<SecurityOrigin> shared_storage_security_origin =
      use_script_origin_as_data_origin
          ? script_security_origin->IsolatedCopy()
          : execution_context->GetSecurityOrigin()->IsolatedCopy();

  // Opaque data origins are not allowed. Earlier we rejected the case where the
  // context origin was both opaque and used as the data origin. Here we reject
  // the case where the script origin is opaque and used as the data origin.
  if (use_script_origin_as_data_origin &&
      shared_storage_security_origin->IsOpaque()) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        kOpaqueDataOriginCheckErrorMessage));
    return;
  }

  url::Origin shared_storage_origin =
      shared_storage_security_origin->ToUrlOrigin();

  const PermissionsPolicy* policy =
      execution_context->GetSecurityContext().GetPermissionsPolicy();
  if (!policy || !policy->IsFeatureEnabledForOrigin(
                     mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                     shared_storage_origin)) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        "The \"shared-storage\" Permissions Policy denied the method for the "
        "worklet origin."));

    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kAddModuleWebVisible);
    return;
  }

  shared_storage_origin_ = std::move(shared_storage_origin);

  network::mojom::CredentialsMode credentials_mode =
      Request::V8RequestCredentialsToCredentialsMode(
          options->credentials().AsEnum());

  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
      origin_trial_features =
          OriginTrialContext::GetInheritedTrialFeatures(execution_context);

  SharedStorageWindowSupplement::From(To<LocalDOMWindow>(*execution_context))
      ->GetSharedStorageDocumentService()
      ->CreateWorklet(
          script_source_url, shared_storage_security_origin, credentials_mode,
          origin_trial_features ? *origin_trial_features
                                : Vector<mojom::blink::OriginTrialFeature>(),
          worklet_host_.BindNewEndpointAndPassReceiver(
              execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI)),
          WTF::BindOnce(
              [](ScriptPromiseResolverBase* resolver,
                 SharedStorageWorklet* shared_storage_worklet,
                 base::TimeTicks start_time, bool resolve_to_worklet,
                 bool success, const String& error_message) {
                DCHECK(resolver);
                ScriptState* script_state = resolver->GetScriptState();

                if (!success) {
                  if (IsInParallelAlgorithmRunnable(
                          resolver->GetExecutionContext(), script_state)) {
                    ScriptState::Scope scope(script_state);
                    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                        script_state->GetIsolate(),
                        DOMExceptionCode::kOperationError, error_message));
                  }

                  LogSharedStorageWorkletError(
                      SharedStorageWorkletErrorType::kAddModuleWebVisible);
                  return;
                }

                base::UmaHistogramMediumTimes(
                    "Storage.SharedStorage.Document.Timing.AddModule",
                    base::TimeTicks::Now() - start_time);

                if (resolve_to_worklet) {
                  resolver->DowncastTo<SharedStorageWorklet>()->Resolve(
                      shared_storage_worklet);
                } else {
                  resolver->DowncastTo<IDLUndefined>()->Resolve();
                }

                // `SharedStorageWorkletErrorType::kSuccess` is logged in the
                // browser process for `addModule()` and `createWorklet()`.
              },
              WrapPersistent(resolver), WrapPersistent(this), start_time,
              resolve_to_worklet));
}

// This C++ overload is called by JavaScript:
// sharedStorage.selectURL('foo', [{url: "bar.com"}]);
//
// It returns a JavaScript promise that resolves to an urn::uuid.
ScriptPromise<V8SharedStorageResponse> SharedStorageWorklet::selectURL(
    ScriptState* script_state,
    const String& name,
    HeapVector<Member<SharedStorageUrlWithMetadata>> urls,
    ExceptionState& exception_state) {
  return selectURL(script_state, name, urls,
                   SharedStorageRunOperationMethodOptions::Create(),
                   exception_state);
}

// This C++ overload is called by JavaScript:
// 1. sharedStorage.selectURL('foo', [{url: "bar.com"}], {data: {'option': 0}});
// 2. sharedStorage.selectURL('foo', [{url: "bar.com"}], {data: {'option': 0},
// resolveToConfig: true});
//
// It returns a JavaScript promise:
// 1. that resolves to an urn::uuid, when `resolveToConfig` is false or
// unspecified.
// 2. that resolves to a fenced frame config, when `resolveToConfig` is true.
//
// This function implements the other overload, with `resolveToConfig`
// defaulting to false.
ScriptPromise<V8SharedStorageResponse> SharedStorageWorklet::selectURL(
    ScriptState* script_state,
    const String& name,
    HeapVector<Member<SharedStorageUrlWithMetadata>> urls,
    const SharedStorageRunOperationMethodOptions* options,
    ExceptionState& exception_state) {
  CHECK(options);
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);
    return EmptyPromise();
  }

  LocalFrame* frame = To<LocalDOMWindow>(execution_context)->GetFrame();
  DCHECK(frame);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8SharedStorageResponse>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (!worklet_host_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kOperationError,
        "sharedStorage.worklet.addModule() has to be called before "
        "selectURL()."));

    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);

    return promise;
  }

  // The `kSharedStorage` permissions policy should have been checked in
  // addModule() already.
  const PermissionsPolicy* policy =
      execution_context->GetSecurityContext().GetPermissionsPolicy();
  CHECK(policy);
  CHECK(policy->IsFeatureEnabledForOrigin(
      mojom::blink::PermissionsPolicyFeature::kSharedStorage,
      shared_storage_origin_));

  if (!policy->IsFeatureEnabledForOrigin(
          mojom::blink::PermissionsPolicyFeature::kSharedStorageSelectUrl,
          shared_storage_origin_)) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kInvalidAccessError,
        "The \"shared-storage-select-url\" Permissions Policy denied the "
        "method for the worklet origin."));

    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);

    return promise;
  }

  if (!cross_origin_script_allowed_) {
    // The opaque origin should have been checked in addModule() already.
    CHECK(!execution_context->GetSecurityOrigin()->IsOpaque());
  }

  if (!IsValidSharedStorageURLsArrayLength(urls.size())) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataError,
        "Length of the \"urls\" parameter is not valid."));
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);
    return promise;
  }

  v8::Local<v8::Context> v8_context =
      script_state->GetIsolate()->GetCurrentContext();

  Vector<mojom::blink::SharedStorageUrlWithMetadataPtr> converted_urls;
  converted_urls.ReserveInitialCapacity(urls.size());

  wtf_size_t index = 0;
  for (const auto& url_with_metadata : urls) {
    DCHECK(url_with_metadata->hasUrl());

    KURL converted_url =
        execution_context->CompleteURL(url_with_metadata->url());

    // TODO(crbug.com/1318970): Use `IsValidFencedFrameURL()` or equivalent
    // logic here.
    if (!converted_url.IsValid()) {
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kDataError,
          "The url \"" + url_with_metadata->url() + "\" is invalid."));
      LogSharedStorageWorkletError(
          SharedStorageWorkletErrorType::kSelectURLWebVisible);
      return promise;
    }

    HashMap<String, KURL> converted_reporting_metadata;

    if (url_with_metadata->hasReportingMetadata()) {
      DCHECK(url_with_metadata->reportingMetadata().V8Value()->IsObject());

      v8::Local<v8::Object> obj =
          url_with_metadata->reportingMetadata().V8Value().As<v8::Object>();

      v8::MaybeLocal<v8::Array> maybe_fields =
          obj->GetOwnPropertyNames(v8_context);
      v8::Local<v8::Array> fields;
      if (!maybe_fields.ToLocal(&fields) || fields->Length() == 0) {
        resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
            script_state->GetIsolate(), DOMExceptionCode::kDataError,
            "selectURL could not get reportingMetadata object attributes"));
        LogSharedStorageWorkletError(
            SharedStorageWorkletErrorType::kSelectURLWebVisible);
        return promise;
      }

      converted_reporting_metadata.ReserveCapacityForSize(fields->Length());

      for (wtf_size_t idx = 0; idx < fields->Length(); idx++) {
        v8::Local<v8::Value> report_event =
            fields->Get(v8_context, idx).ToLocalChecked();
        String report_event_string;
        if (!StringFromV8(script_state->GetIsolate(), report_event,
                          &report_event_string)) {
          resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
              script_state->GetIsolate(), DOMExceptionCode::kDataError,
              "selectURL reportingMetadata object attributes must be "
              "strings"));
          LogSharedStorageWorkletError(
              SharedStorageWorkletErrorType::kSelectURLWebVisible);
          return promise;
        }

        v8::Local<v8::Value> report_url =
            obj->Get(v8_context, report_event).ToLocalChecked();
        String report_url_string;
        if (!StringFromV8(script_state->GetIsolate(), report_url,
                          &report_url_string)) {
          resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
              script_state->GetIsolate(), DOMExceptionCode::kDataError,
              "selectURL reportingMetadata object attributes must be "
              "strings"));
          LogSharedStorageWorkletError(
              SharedStorageWorkletErrorType::kSelectURLWebVisible);
          return promise;
        }

        KURL converted_report_url =
            execution_context->CompleteURL(report_url_string);

        if (!IsValidFencedFrameReportingURL(converted_report_url)) {
          resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
              script_state->GetIsolate(), DOMExceptionCode::kDataError,
              "The metadata for the url at index " +
                  String::NumberToStringECMAScript(index) +
                  " has an invalid or non-HTTPS report_url parameter \"" +
                  report_url_string + "\"."));
          LogSharedStorageWorkletError(
              SharedStorageWorkletErrorType::kSelectURLWebVisible);
          return promise;
        }

        converted_reporting_metadata.Set(report_event_string,
                                         converted_report_url);
      }
    }

    converted_urls.push_back(mojom::blink::SharedStorageUrlWithMetadata::New(
        converted_url, std::move(converted_reporting_metadata)));
    index++;
  }

  base::ElapsedTimer serialization_timer;

  std::optional<BlinkCloneableMessage> serialized_data =
      Serialize(options, *execution_context, exception_state);
  if (!serialized_data) {
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);
    return promise;
  }

  base::UmaHistogramTimes(
      "Storage.SharedStorage.SelectURL.DataSerialization.Time",
      serialization_timer.Elapsed());

  if (serialized_data->message) {
    base::UmaHistogramMemoryKB(
        "Storage.SharedStorage.SelectURL.DataSerialization.SizeKB",
        serialized_data->message->DataLengthInBytes() / 1024);
  }

  bool resolve_to_config = options->resolveToConfig();
  if (!RuntimeEnabledFeatures::FencedFramesAPIChangesEnabled(
          execution_context)) {
    // If user specifies returning a `FencedFrameConfig` but the feature is not
    // enabled, fall back to return a urn::uuid.
    resolve_to_config = false;
  }

  if (!keep_alive_after_operation_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kOperationError,
        kSharedStorageWorkletExpiredMessage));

    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);

    return promise;
  }

  bool keep_alive = options->keepAlive();
  keep_alive_after_operation_ = keep_alive;

  mojom::blink::PrivateAggregationConfigPtr private_aggregation_config;
  if (!CheckPrivateAggregationConfig(*options, *script_state, *resolver,
                                     /*out_private_aggregation_config=*/
                                     private_aggregation_config)) {
    LogSharedStorageWorkletError(
        SharedStorageWorkletErrorType::kSelectURLWebVisible);
    return promise;
  }

  worklet_host_->SelectURL(
      name, std::move(converted_urls), std::move(*serialized_data), keep_alive,
      std::move(private_aggregation_config), options->savedQuery(),
      WTF::BindOnce(
          [](ScriptPromiseResolver<V8SharedStorageResponse>* resolver,
             SharedStorageWorklet* shared_storage_worklet,
             base::TimeTicks start_time, bool resolve_to_config, bool success,
             const String& error_message,
             const std::optional<FencedFrame::RedactedFencedFrameConfig>&
                 result_config) {
            DCHECK(resolver);
            ScriptState* script_state = resolver->GetScriptState();

            if (!success) {
              if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                                script_state)) {
                ScriptState::Scope scope(script_state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    script_state->GetIsolate(),
                    DOMExceptionCode::kOperationError, error_message));
              }
              LogSharedStorageWorkletError(
                  SharedStorageWorkletErrorType::kSelectURLWebVisible);
              return;
            }

            base::UmaHistogramMediumTimes(
                "Storage.SharedStorage.Document.Timing.SelectURL",
                base::TimeTicks::Now() - start_time);
            // `result_config` must have value. Otherwise `success` should
            // be false and program should not reach here.
            DCHECK(result_config.has_value());
            if (resolve_to_config) {
              resolver->Resolve(FencedFrameConfig::From(result_config.value()));
            } else {
              resolver->Resolve(KURL(result_config->urn_uuid().value()));
            }

            // `SharedStorageWorkletErrorType::kSuccess` is logged in the
            // browser process for `selectURL()`.
          },
          WrapPersistent(resolver), WrapPersistent(this), start_time,
          resolve_to_config));

  return promise;
}

ScriptPromise<IDLAny> SharedStorageWorklet::run(
    ScriptState* script_state,
    const String& name,
    ExceptionState& exception_state) {
  return run(script_state, name,
             SharedStorageRunOperationMethodOptions::Create(), exception_state);
}

ScriptPromise<IDLAny> SharedStorageWorklet::run(
    ScriptState* script_state,
    const String& name,
    const SharedStorageRunOperationMethodOptions* options,
    ExceptionState& exception_state) {
  CHECK(options);
  base::TimeTicks start_time = base::TimeTicks::Now();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  CHECK(execution_context->IsWindow());

  if (!CheckBrowsingContextIsValid(*script_state, exception_state)) {
    LogSharedStorageWorkletError(SharedStorageWorkletErrorType::kRunWebVisible);
    return EmptyPromise();
  }

  base::ElapsedTimer serialization_timer;

  std::optional<BlinkCloneableMessage> serialized_data =
      Serialize(options, *execution_context, exception_state);
  if (!serialized_data) {
    LogSharedStorageWorkletError(SharedStorageWorkletErrorType::kRunWebVisible);
    return EmptyPromise();
  }

  base::UmaHistogramTimes("Storage.SharedStorage.Run.DataSerialization.Time",
                          serialization_timer.Elapsed());

  if (serialized_data->message) {
    base::UmaHistogramMemoryKB(
        "Storage.SharedStorage.Run.DataSerialization.SizeKB",
        serialized_data->message->DataLengthInBytes() / 1024);
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (!worklet_host_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kOperationError,
        "sharedStorage.worklet.addModule() has to be called before run()."));

    LogSharedStorageWorkletError(SharedStorageWorkletErrorType::kRunWebVisible);

    return promise;
  }

  // The `kSharedStorage` permissions policy should have been checked in
  // addModule() already.
  const PermissionsPolicy* policy =
      execution_context->GetSecurityContext().GetPermissionsPolicy();
  CHECK(policy);
  CHECK(policy->IsFeatureEnabledForOrigin(
      mojom::blink::PermissionsPolicyFeature::kSharedStorage,
      shared_storage_origin_));

  if (!cross_origin_script_allowed_) {
    // The opaque origin should have been checked in addModule() already.
    CHECK(!execution_context->GetSecurityOrigin()->IsOpaque());
  }

  if (!keep_alive_after_operation_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kOperationError,
        kSharedStorageWorkletExpiredMessage));

    LogSharedStorageWorkletError(SharedStorageWorkletErrorType::kRunWebVisible);

    return promise;
  }

  bool keep_alive = options->keepAlive();
  keep_alive_after_operation_ = keep_alive;

  mojom::blink::PrivateAggregationConfigPtr private_aggregation_config;
  if (!CheckPrivateAggregationConfig(
          *options, *script_state, *resolver,
          /*out_private_aggregation_config=*/private_aggregation_config)) {
    LogSharedStorageWorkletError(SharedStorageWorkletErrorType::kRunWebVisible);
    return promise;
  }

  worklet_host_->Run(
      name, std::move(*serialized_data), keep_alive,
      std::move(private_aggregation_config),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             SharedStorageWorklet* shared_storage_worklet,
             base::TimeTicks start_time, bool success,
             const String& error_message) {
            DCHECK(resolver);
            ScriptState* script_state = resolver->GetScriptState();

            if (!success) {
              if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                                script_state)) {
                ScriptState::Scope scope(script_state);
                resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
                    script_state->GetIsolate(),
                    DOMExceptionCode::kOperationError, error_message));
              }

              LogSharedStorageWorkletError(
                  SharedStorageWorkletErrorType::kRunWebVisible);
              return;
            }

            base::UmaHistogramMediumTimes(
                "Storage.SharedStorage.Document.Timing.Run",
                base::TimeTicks::Now() - start_time);
            resolver->Resolve();

            // `SharedStorageWorkletErrorType::kSuccess` is logged in the
            // browser process for `run()`.
          },
          WrapPersistent(resolver), WrapPersistent(this), start_time));

  return promise;
}

SharedStorageWorklet::SharedStorageWorklet(bool cross_origin_script_allowed)
    : cross_origin_script_allowed_(cross_origin_script_allowed) {}

}  // namespace blink

"""

```