Response:
Let's break down the thought process to analyze the `module_tree_linker.cc` file.

1. **Initial Understanding - Core Purpose:** The file name itself, "module_tree_linker," strongly suggests it's responsible for linking together a tree of JavaScript modules. The "linker" part indicates resolving dependencies and connecting them. The "tree" suggests a hierarchical structure.

2. **High-Level Functionality (Reading the Code Top-Down):**
    * **Includes:** Look at the included headers. These provide clues to the file's responsibilities:
        * `mojom/fetch/fetch_api_request.mojom-blink.h`:  Deals with network requests.
        * `bindings/core/v8/module_record.h`, `bindings/core/v8/module_request.h`: Interaction with V8's module representation. This confirms it's about JavaScript modules.
        * `core/execution_context/execution_context.h`: Operates within a scripting context.
        * `core/loader/...`:  Located within the loader directory, indicating it's part of the resource loading process.
        * `platform/loader/fetch/...`: More loading and fetching related components.
        * `v8/include/v8.h`: Direct interaction with the V8 JavaScript engine.
    * **Spec Definitions:** The `specdef` comments point to sections in the HTML specification related to fetching module scripts. This confirms its adherence to web standards.
    * **Class Definition: `ModuleTreeLinker`:** This is the main class. Its constructor takes parameters related to fetching (`ResourceFetcher`, `RequestContextType`, `RequestDestination`), module management (`Modulator`, `ModuleTreeLinkerRegistry`), and a client for notifications (`ModuleTreeClient`). This hints at its role in orchestrating the loading process.
    * **State Machine:** The `State` enum and `AdvanceState` method suggest that the linker goes through different stages during the linking process (Initial, FetchingSelf, FetchingDependencies, Instantiating, Finished). This is typical for asynchronous operations.
    * **`FetchRoot` and `FetchRootInline`:** These methods seem to be the starting points for fetching module trees, one for network requests and the other for inline scripts.
    * **`NotifyModuleLoadFinished`:**  A callback likely invoked when individual module fetches complete.
    * **`FetchDescendants`:**  This is where dependency resolution and fetching of child modules likely happens.
    * **`Instantiate`:**  The stage where the JavaScript module is actually instantiated within the V8 engine.
    * **`FindFirstParseError`:**  Deals with error handling related to module parsing.

3. **Connecting to JavaScript, HTML, CSS:**
    * **JavaScript:** The core function revolves around loading and linking JavaScript modules. The interaction with V8 (`ModuleRecord`, `v8::Module`) is the primary connection.
    * **HTML:** The process is triggered by `<script type="module">` tags or dynamic `import()` statements in HTML. The `original_url` parameter in `FetchRoot` would likely correspond to the `src` attribute of a `<script>` tag.
    * **CSS:** While this specific file is primarily about JavaScript modules, the presence of `ModuleType::kCSS` suggests that the module loading infrastructure might be extensible to handle CSS modules as well. The file handles the *fetching* and *linking* of modules, regardless of the type.

4. **Logical Reasoning (Hypothetical Input/Output):**
    * **Input:** A `<script type="module" src="main.js">` tag in an HTML file. `main.js` contains `import './moduleA.js'`.
    * **Process:**
        1. `FetchRoot` is called for `main.js`.
        2. `main.js` is fetched.
        3. `NotifyModuleLoadFinished` is called with the loaded `main.js`.
        4. `FetchDescendants` is called for `main.js`.
        5. `FetchDescendants` parses `main.js`, finds the import for `./moduleA.js`, resolves the URL.
        6. A new fetch is initiated for `moduleA.js`.
        7. `NotifyModuleLoadFinished` is called for `moduleA.js`.
        8. `Instantiate` is called, which uses V8 to instantiate both modules, connecting their exports and imports.
    * **Output:** The JavaScript code in `main.js` and `moduleA.js` is executed within the browser.

5. **User/Programming Errors:**
    * **Incorrect Module Specifier:**  `import './moduleB.js'` when `moduleB.js` doesn't exist or the path is wrong. This would lead to a fetch error or a module resolution error. The `FindFirstParseError` function would likely be involved.
    * **Circular Dependencies:**  `moduleA.js` imports `moduleB.js`, and `moduleB.js` imports `moduleA.js`. This could lead to issues during instantiation. The linker needs to handle such scenarios gracefully (though the provided code doesn't explicitly show circular dependency detection, it's a common challenge in module systems).
    * **Mismatched `type` Attribute:** Using `<script src="script.js">` when `script.js` contains `import` statements. The browser wouldn't treat it as a module, and the linker wouldn't be invoked correctly.

6. **Debugging Clues (User Actions to Reach the Code):**
    * The most direct way is through a `<script type="module">` tag in an HTML page.
    * A dynamic `import()` statement in JavaScript code running in the browser would also trigger this code path.
    * For worker scripts, using `importScripts()` with module scripts would involve this linker.

7. **Refinement and Detail:** After the initial pass, review the code for specific details:
    * **Visited Set:** The `visited_set_` prevents infinite loops in case of circular dependencies by keeping track of already fetched modules.
    * **Error Handling:** The `found_parse_error_` flag and `FindFirstParseError` function handle cases where module parsing fails.
    * **Asynchronous Nature:**  The use of callbacks (`NotifyModuleLoadFinished`) and the state machine emphasize the asynchronous nature of module loading.
    * **Modulator:** The `Modulator` likely handles interactions with the browser's module map and import maps.

By following this kind of systematic analysis, starting with the big picture and gradually drilling down into the details, one can effectively understand the functionality of a complex source code file like `module_tree_linker.cc`.
好的，让我们详细分析一下 `blink/renderer/core/loader/modulescript/module_tree_linker.cc` 这个文件。

**文件功能概要**

`ModuleTreeLinker` 的核心功能是**负责加载和链接 JavaScript 模块及其依赖项**，形成一个模块依赖树。它遵循 HTML 规范中定义的模块脚本加载和链接过程，确保模块按照正确的顺序和方式被获取、解析和实例化。

更具体地说，`ModuleTreeLinker` 负责：

1. **发起模块脚本的获取请求**: 根据给定的 URL、模块类型（JavaScript, JSON, CSS 等）以及其他加载选项，向网络层发起获取模块脚本内容的请求。
2. **管理模块依赖关系**:  解析已加载的模块脚本，找出其中 `import` 语句引用的其他模块，并递归地获取这些依赖项。
3. **维护已访问模块的集合**:  防止重复加载同一个模块，避免循环依赖导致的无限循环。
4. **处理内联模块脚本**:  支持直接在 HTML 中定义的 `<script type="module">` 标签。
5. **处理模块加载完成的通知**:  接收单个模块加载完成的通知，并根据当前状态推进整个模块树的加载和链接过程。
6. **实例化模块**: 当所有依赖项都加载完成后，负责在 V8 JavaScript 引擎中实例化这些模块，建立模块之间的导入导出关系。
7. **处理模块解析错误**:  如果在模块加载或解析过程中发生错误，`ModuleTreeLinker` 负责检测并记录这些错误。
8. **与 `Modulator` 和 `ModuleTreeLinkerRegistry` 协作**:  `Modulator` 负责模块映射和 import maps 等功能，`ModuleTreeLinkerRegistry` 用于管理 `ModuleTreeLinker` 实例的生命周期。
9. **通知客户端加载完成**:  当整个模块树加载和链接完成后，通知 `ModuleTreeClient`。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ModuleTreeLinker` 与这三种 Web 核心技术都有密切关系：

* **JavaScript**: 这是 `ModuleTreeLinker` 主要处理的对象。它负责加载和链接 JavaScript 模块，并确保这些模块能在浏览器中正确执行。
    * **例子**: 当你在 JavaScript 代码中使用 `import` 语句引入其他模块时，`ModuleTreeLinker` 会解析这个 `import` 语句，并根据模块标识符（specifier）解析出模块的 URL，然后发起加载请求。

    ```javascript
    // main.js
    import { myFunction } from './moduleA.js';

    myFunction();
    ```

    在这个例子中，`ModuleTreeLinker` 会负责加载 `moduleA.js`，并在 `main.js` 实例化时，将 `moduleA.js` 中导出的 `myFunction` 连接到 `main.js`。

* **HTML**:  HTML 通过 `<script type="module">` 标签声明一个模块脚本的入口点。`ModuleTreeLinker` 会根据这个标签的 `src` 属性（或内联代码）开始模块树的加载过程。
    * **例子**:

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Module Example</title>
    </head>
    <body>
      <script type="module" src="main.js"></script>
    </body>
    </html>
    ```

    当浏览器解析到这个 `<script type="module">` 标签时，会创建一个 `ModuleTreeLinker` 实例来加载 `main.js` 及其依赖项。

* **CSS**:  虽然这个文件主要处理 JavaScript 模块，但现代 Web 开发中也存在 CSS 模块的概念。从代码中可以看出，`ModuleType` 枚举包含了 `kCSS`，这意味着 `ModuleTreeLinker` 的设计可以扩展到处理 CSS 模块的加载和链接。
    * **例子**:  虽然 `module_tree_linker.cc` 自身可能不直接处理 CSS 的解析和实例化，但它负责 CSS 模块的加载。一个假设的场景是，如果 JavaScript 模块导入了一个 CSS 模块：

    ```javascript
    // component.js
    import styles from './component.css';

    console.log(styles.className); // 假设 CSS 模块导出了类名
    ```

    `ModuleTreeLinker` 会负责加载 `component.css` 文件。至于如何解析和应用 CSS，则由其他的 Blink 组件负责。

**逻辑推理 (假设输入与输出)**

假设我们有以下模块：

* **index.html**:
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <title>Module Example</title>
  </head>
  <body>
    <script type="module" src="app.js"></script>
  </body>
  </html>
  ```
* **app.js**:
  ```javascript
  import { greet } from './greeter.js';
  import data from './data.json' assert { type: "json" };

  greet('World');
  console.log(data.message);
  ```
* **greeter.js**:
  ```javascript
  export function greet(name) {
    console.log(`Hello, ${name}!`);
  }
  ```
* **data.json**:
  ```json
  {
    "message": "This is JSON data."
  }
  ```

**假设输入**: 浏览器加载 `index.html`，遇到 `<script type="module" src="app.js">`。

**`ModuleTreeLinker` 的处理步骤 (简化版)**:

1. **`FetchRoot`**:  为 `app.js` 创建一个 `ModuleTreeLinker` 实例，开始加载 `app.js`。
2. **加载 `app.js`**:  发起网络请求获取 `app.js` 的内容。
3. **`NotifyModuleLoadFinished` (app.js)**:  `app.js` 加载完成。
4. **`FetchDescendants` (app.js)**: 解析 `app.js`，发现两个 `import` 语句：
   * `import { greet } from './greeter.js';`
   * `import data from './data.json' assert { type: "json" };`
5. **加载 `greeter.js`**: `ModuleTreeLinker` 发起网络请求获取 `greeter.js`。
6. **加载 `data.json`**: `ModuleTreeLinker` 发起网络请求获取 `data.json`。
7. **`NotifyModuleLoadFinished` (greeter.js)**: `greeter.js` 加载完成。
8. **`NotifyModuleLoadFinished` (data.json)**: `data.json` 加载完成。
9. **`Instantiate`**:  所有依赖项加载完成，`ModuleTreeLinker` 通知 V8 引擎实例化 `app.js`, `greeter.js`, 和 `data.json` 模块，建立模块间的导入导出关系。
10. **执行代码**:  V8 引擎开始执行 `app.js` 中的代码，最终会在控制台输出 "Hello, World!" 和 "This is JSON data."。

**假设输出**:  JavaScript 代码成功执行，并在控制台输出预期结果。

**用户或编程常见的使用错误及举例说明**

1. **错误的模块标识符 (Specifier)**:  `import` 语句中引用的模块路径不正确，导致模块加载失败。
   * **例子**:  `app.js` 中写成 `import { greet } from './greet.js';`，但实际上文件名为 `greeter.js`。这将导致 `ModuleTreeLinker` 无法找到对应的模块。

2. **循环依赖**:  模块之间存在互相依赖的关系，导致加载过程陷入无限循环。
   * **例子**:
     * `moduleA.js`: `import './moduleB.js';`
     * `moduleB.js`: `import './moduleA.js';`
     `ModuleTreeLinker` 会尝试加载 `moduleA.js`，发现依赖 `moduleB.js`，然后尝试加载 `moduleB.js`，又发现依赖 `moduleA.js`，从而形成循环。`visited_set_` 的作用就是防止这种情况。

3. **服务器未配置正确的 MIME 类型**:  服务器返回的模块脚本的 Content-Type 不正确（例如，返回 `text/plain` 而不是 `application/javascript` 或 `text/javascript`），浏览器会拒绝执行。

4. **跨域问题 (CORS)**:  当模块脚本从不同的域加载时，如果服务器没有设置正确的 CORS 头，浏览器会阻止加载。

5. **Import Maps 配置错误**: 如果使用了 Import Maps，配置不当可能导致模块标识符无法正确解析到对应的 URL。

**用户操作是如何一步步的到达这里 (作为调试线索)**

当开发者在浏览器中加载一个包含模块脚本的 HTML 页面时，Blink 引擎会经历以下步骤，最终涉及到 `ModuleTreeLinker`：

1. **HTML 解析器**:  浏览器开始解析 HTML 页面。
2. **遇到 `<script type="module">` 标签**:  当解析器遇到带有 `type="module"` 的 `<script>` 标签时，会触发模块脚本的加载流程。
3. **创建 `ModuleTreeLinker`**: Blink 会创建一个 `ModuleTreeLinker` 实例，用于管理这个模块及其依赖项的加载和链接。
4. **`FetchRoot` 调用**:  根据 `<script>` 标签的 `src` 属性或内联代码，调用 `ModuleTreeLinker::FetchRoot` 或 `ModuleTreeLinker::FetchRootInline` 方法，启动加载过程。
5. **网络请求**:  `ModuleTreeLinker` 使用 `ResourceFetcher` 发起网络请求，获取模块脚本的内容。
6. **接收响应**:  网络层接收到服务器的响应，并将模块内容传递给 `ModuleTreeLinker`。
7. **解析模块**:  `ModuleTreeLinker` 解析模块内容，查找 `import` 语句。
8. **递归加载依赖**:  如果发现 `import` 语句，`ModuleTreeLinker` 会为每个依赖项重复步骤 5-7。
9. **实例化模块**: 当所有依赖项都加载完成后，`ModuleTreeLinker` 通知 V8 引擎实例化这些模块。
10. **执行脚本**:  V8 引擎执行模块中的代码。

**调试线索**:

* **网络面板**:  开发者可以使用浏览器的开发者工具中的 "网络" 面板来查看模块的加载请求和响应，检查 URL 是否正确、MIME 类型是否正确、是否存在 CORS 问题等。
* **控制台**:  控制台会显示 JavaScript 的错误信息，例如模块加载失败、模块解析错误等。
* **断点调试**:  如果需要深入了解 `ModuleTreeLinker` 的内部工作原理，开发者可以在 Blink 引擎的源代码中设置断点，跟踪模块加载和链接的过程。在 `module_tree_linker.cc` 文件中的关键方法（如 `FetchRoot`, `NotifyModuleLoadFinished`, `FetchDescendants`, `Instantiate`）设置断点可以帮助理解模块加载的流程。
* **`UseCounter`**: 代码中使用了 `UseCounter`，这表明 Blink 引擎会收集一些关于模块加载的统计信息，这些信息在内部调试和分析中可能很有用。
* **Resource Loading Log**: 代码中引用了 `ResourceLoadingLog`，这意味着 Blink 引擎可能会记录详细的资源加载日志，这些日志可以提供更底层的调试信息。

总而言之，`blink/renderer/core/loader/modulescript/module_tree_linker.cc` 是 Blink 引擎中负责 JavaScript 模块加载和链接的核心组件，它确保模块化的 JavaScript 代码能够按照规范在浏览器中正确执行。理解它的功能对于调试模块加载问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/modulescript/module_tree_linker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/modulescript/module_tree_linker.h"

#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/module_record.h"
#include "third_party/blink/renderer/bindings/core/v8/module_request.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_tree_linker_registry.h"
#include "third_party/blink/renderer/core/script/module_script.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loading_log.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8.h"

// <specdef label="IMSGF"
// href="https://html.spec.whatwg.org/C/#internal-module-script-graph-fetching-procedure">

// <specdef label="fetch-a-module-script-tree"
// href="https://html.spec.whatwg.org/C/#fetch-a-module-script-tree">

// <specdef
// label="fetch-a-module-worker-script-tree"
// href="https://html.spec.whatwg.org/C/#fetch-a-module-worker-script-tree">

// <specdef label="fetch-an-import()-module-script-graph"
// href="https://html.spec.whatwg.org/C/#fetch-an-import()-module-script-graph">

namespace blink {

namespace {

struct ModuleScriptFetchTarget {
  ModuleScriptFetchTarget(KURL url,
                          ModuleType module_type,
                          TextPosition position)
      : url(url), module_type(module_type), position(position) {}

  KURL url;
  ModuleType module_type;
  TextPosition position;
};

}  // namespace

ModuleTreeLinker::ModuleTreeLinker(
    ResourceFetcher* fetch_client_settings_object_fetcher,
    mojom::blink::RequestContextType context_type,
    network::mojom::RequestDestination destination,
    Modulator* modulator,
    ModuleScriptCustomFetchType custom_fetch_type,
    ModuleTreeLinkerRegistry* registry,
    ModuleTreeClient* client,
    base::PassKey<ModuleTreeLinkerRegistry>)
    : fetch_client_settings_object_fetcher_(
          fetch_client_settings_object_fetcher),
      context_type_(context_type),
      destination_(destination),
      modulator_(modulator),
      custom_fetch_type_(custom_fetch_type),
      registry_(registry),
      client_(client) {
  CHECK(modulator);
  CHECK(registry);
  CHECK(client);
}

void ModuleTreeLinker::Trace(Visitor* visitor) const {
  visitor->Trace(fetch_client_settings_object_fetcher_);
  visitor->Trace(modulator_);
  visitor->Trace(registry_);
  visitor->Trace(client_);
  visitor->Trace(result_);
  SingleModuleClient::Trace(visitor);
}

#if DCHECK_IS_ON()
const char* ModuleTreeLinker::StateToString(ModuleTreeLinker::State state) {
  switch (state) {
    case State::kInitial:
      return "Initial";
    case State::kFetchingSelf:
      return "FetchingSelf";
    case State::kFetchingDependencies:
      return "FetchingDependencies";
    case State::kInstantiating:
      return "Instantiating";
    case State::kFinished:
      return "Finished";
  }
  NOTREACHED();
}
#endif

void ModuleTreeLinker::AdvanceState(State new_state) {
#if DCHECK_IS_ON()
  RESOURCE_LOADING_DVLOG(1)
      << *this << "::advanceState(" << StateToString(state_) << " -> "
      << StateToString(new_state) << ")";
#endif

  switch (state_) {
    case State::kInitial:
      CHECK_EQ(num_incomplete_fetches_, 0u);
      CHECK_EQ(new_state, State::kFetchingSelf);
      break;
    case State::kFetchingSelf:
      CHECK_EQ(num_incomplete_fetches_, 0u);
      CHECK(new_state == State::kFetchingDependencies ||
            new_state == State::kFinished);
      break;
    case State::kFetchingDependencies:
      CHECK(new_state == State::kInstantiating ||
            new_state == State::kFinished);
      break;
    case State::kInstantiating:
      CHECK_EQ(new_state, State::kFinished);
      break;
    case State::kFinished:
      NOTREACHED();
  }

  state_ = new_state;

  if (state_ == State::kFinished) {
#if DCHECK_IS_ON()
    if (result_) {
      RESOURCE_LOADING_DVLOG(1)
          << *this << " finished with final result " << *result_;
    } else {
      RESOURCE_LOADING_DVLOG(1) << *this << " finished with nullptr.";
    }
#endif

    registry_->ReleaseFinishedLinker(this);

    // <spec label="IMSGF" step="6">When the appropriate algorithm
    // asynchronously completes with final result, asynchronously complete this
    // algorithm with final result.</spec>
    client_->NotifyModuleTreeLoadFinished(result_);
  }
}

// #fetch-a-module-script-tree, #fetch-an-import()-module-script-graph, and
// #fetch-a-module-worker-script-tree.
void ModuleTreeLinker::FetchRoot(const KURL& original_url,
                                 ModuleType module_type,
                                 const ScriptFetchOptions& options,
                                 base::PassKey<ModuleTreeLinkerRegistry>,
                                 String referrer) {
#if DCHECK_IS_ON()
  original_url_ = original_url;
  module_type_ = module_type;
  root_is_inline_ = false;
#endif

  // https://wicg.github.io/import-maps/#wait-for-import-maps
  // 1.2. Set document’s acquiring import maps to false. [spec text]
  modulator_->SetAcquiringImportMapsState(
      Modulator::AcquiringImportMapsState::kAfterModuleScriptLoad);

  AdvanceState(State::kFetchingSelf);

  KURL url = original_url;

#if DCHECK_IS_ON()
  url_ = url;
#endif

  // <spec label="fetch-a-module-script-tree" step="2">If result is null,
  // asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  //
  // <spec label="fetch-an-import()-module-script-graph" step="4">If result is
  // null, asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  //
  // <spec label="fetch-a-module-worker-script-tree" step="3">If result is null,
  // asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  if (!url.IsValid()) {
    result_ = nullptr;
    modulator_->TaskRunner()->PostTask(
        FROM_HERE, WTF::BindOnce(&ModuleTreeLinker::AdvanceState,
                                 WrapPersistent(this), State::kFinished));
    return;
  }

  CHECK_NE(module_type, ModuleType::kInvalid);

  // <spec label="fetch-a-module-script-tree" step="3">Let visited set be « url
  // ».</spec>
  //
  // <spec label="fetch-an-import()-module-script-graph" step="5">Let visited
  // set be « url ».</spec>
  //
  // <spec label="fetch-a-module-worker-script-tree" step="4">Let visited set be
  // « url ».</spec>
  visited_set_.insert(std::make_pair(url, module_type));

  // <spec label="fetch-a-module-script-tree" step="4">Fetch a single module
  // script given url, settings object, "script", options, settings object,
  // "client", and with the top-level module fetch flag set. ...</spec>
  //
  // <spec label="fetch-an-import()-module-script-graph" step="3">Fetch a single
  // module script given url, settings object, "script", options, settings
  // object, "client", and with the top-level module fetch flag set. ...</spec>
  //
  // <spec label="fetch-a-module-worker-script-tree" step="2">Fetch a single
  // module script given url, fetch client settings object, destination,
  // options, module map settings object, "client", and with the top-level
  // module fetch flag set. ...</spec>
  //
  // Note that we don't *always* pass in "client" for the referrer string, as
  // mentioned in the spec prose above. Because our implementation is organized
  // slightly different from the spec, this path is hit for dynamic imports as
  // well, so we pass through `referrer` which is usually the client string
  // (`Referrer::ClientReferrerString()`), but isn't for the dynamic import
  // case.
  ModuleScriptFetchRequest request(url, module_type, context_type_,
                                   destination_, options, referrer,
                                   TextPosition::MinimumPosition());
  ++num_incomplete_fetches_;

  // <spec label="fetch-a-module-script-tree" step="2">Fetch a single module
  // script given...
  // </spec>
  modulator_->FetchSingle(request, fetch_client_settings_object_fetcher_.Get(),
                          ModuleGraphLevel::kTopLevelModuleFetch,
                          custom_fetch_type_, this);
}

// <specdef
// href="https://html.spec.whatwg.org/C/#fetch-an-inline-module-script-graph">
void ModuleTreeLinker::FetchRootInline(
    ModuleScript* module_script,
    base::PassKey<ModuleTreeLinkerRegistry>) {
  DCHECK(module_script);
#if DCHECK_IS_ON()
  original_url_ = module_script->BaseUrl();
  url_ = original_url_;
  module_type_ = ModuleType::kJavaScript;
  root_is_inline_ = true;
#endif

  // https://wicg.github.io/import-maps/#wait-for-import-maps
  // 1.2. Set document’s acquiring import maps to false. [spec text]
  //
  // TODO(hiroshige): This should be done before |module_script| is created.
  modulator_->SetAcquiringImportMapsState(
      Modulator::AcquiringImportMapsState::kAfterModuleScriptLoad);

  AdvanceState(State::kFetchingSelf);

  // Store the |module_script| here which will be used as result of the
  // algorithm when success. Also, this ensures that the |module_script| is
  // traced via ModuleTreeLinker.
  result_ = module_script;
  AdvanceState(State::kFetchingDependencies);

  // <spec step="1">Let script be the result of creating a JavaScript module
  // script using sourceText, settingsObject, baseURL, options, and
  // importMap.</spec>
  //
  // The script was already created as part of ScriptLoader::PrepareScript.

  // <spec step="2">Fetch the descendants of and link script, ...</spec>
  modulator_->TaskRunner()->PostTask(
      FROM_HERE,
      WTF::BindOnce(&ModuleTreeLinker::FetchDescendants, WrapPersistent(this),
                    WrapPersistent(module_script)));
}

// Returning from #fetch-a-single-module-script, calling from
// #fetch-a-module-script-tree, #fetch-an-import()-module-script-graph, and
// #fetch-a-module-worker-script-tree, and IMSGF.
void ModuleTreeLinker::NotifyModuleLoadFinished(ModuleScript* module_script) {
  CHECK_GT(num_incomplete_fetches_, 0u);
  --num_incomplete_fetches_;

#if DCHECK_IS_ON()
  if (module_script) {
    RESOURCE_LOADING_DVLOG(1)
        << *this << "::NotifyModuleLoadFinished() with " << *module_script;
  } else {
    RESOURCE_LOADING_DVLOG(1)
        << *this << "::NotifyModuleLoadFinished() with nullptr.";
  }
#endif

  if (state_ == State::kFetchingSelf) {
    // non-IMSGF cases: |module_script| is the top-level module, and will be
    // instantiated and returned later.
    result_ = module_script;
    AdvanceState(State::kFetchingDependencies);
  }

  if (state_ != State::kFetchingDependencies) {
    // We may reach here if one of the descendant failed to load, and the other
    // descendants fetches were in flight.
    return;
  }

  // <spec label="fetch-a-module-script-tree" step="2">If result is null,
  // asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  //
  // <spec label="fetch-an-import()-module-script-graph" step="4">If result is
  // null, asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  //
  // <spec label="fetch-a-module-worker-script-tree" step="3">If result is null,
  // asynchronously complete this algorithm with null, and abort these
  // steps.</spec>
  //
  // <spec label="IMSGF" step="4">If result is null, asynchronously complete
  // this algorithm with null, and abort these steps.</spec>
  if (!module_script) {
    result_ = nullptr;
    AdvanceState(State::kFinished);
    return;
  }

  // <spec label="fetch-a-module-script-tree" step="4">Fetch the descendants of
  // and instantiate ...</spec>
  //
  // <spec label="fetch-an-import()-module-script-graph" step="6">Fetch the
  // descendants of and instantiate result ...</spec>
  //
  // <spec label="fetch-a-module-worker-script-tree" step="5">Fetch the
  // descendants of and instantiate result given fetch client settings object,
  // ...</spec>
  //
  // <spec label="IMSGF" step="5">Fetch the descendants of result given fetch
  // client settings object, destination, and visited set.</spec>
  FetchDescendants(module_script);
}

// <specdef
// href="https://html.spec.whatwg.org/C/#fetch-the-descendants-of-a-module-script">
// See also https://github.com/whatwg/html/pull/5658/ which adds ModuleRequest
// and module type to the HTML spec.
void ModuleTreeLinker::FetchDescendants(const ModuleScript* module_script) {
  DCHECK(module_script);

  // [nospec] Abort the steps if the browsing context is discarded.
  if (!modulator_->HasValidContext()) {
    result_ = nullptr;
    AdvanceState(State::kFinished);
    return;
  }
  ScriptState* script_state = modulator_->GetScriptState();
  v8::HandleScope scope(script_state->GetIsolate());

  // <spec step="2">Let record be module script's record.</spec>
  v8::Local<v8::Module> record = module_script->V8Module();

  // <spec step="1">If module script's record is null, then asynchronously
  // complete this algorithm with module script and abort these steps.</spec>
  if (record.IsEmpty()) {
    found_parse_error_ = true;
    // We don't early-exit here and wait until all module scripts to be
    // loaded, because we might be not sure which error to be reported.
    //
    // It is possible to determine whether the error to be reported can be
    // determined without waiting for loading module scripts, and thus to
    // early-exit here if possible. However, the complexity of such early-exit
    // implementation might be high, and optimizing error cases with the
    // implementation cost might be not worth doing.
    FinalizeFetchDescendantsForOneModuleScript();
    return;
  }

  // <spec step="3">... if record.[[RequestedModules]] is empty, asynchronously
  // complete this algorithm with module script.</spec>
  //
  // Note: We defer this bail-out until the end of the procedure. The rest of
  // the procedure will be no-op anyway if record.[[RequestedModules]] is empty.

  // <spec step="4">Let moduleRequests be a new empty list.</spec>
  Vector<ModuleScriptFetchTarget> module_requests;

  // <spec step="5">For each ModuleRequest Record requested of
  // record.[[RequestedModules]],</spec>
  Vector<ModuleRequest> record_requested_modules =
      ModuleRecord::ModuleRequests(script_state, record);

  for (const auto& requested : record_requested_modules) {
    // <spec step="5.1">Let url be the result of resolving a module specifier
    // given module script's base URL and requested.[[Specifier]].</spec>
    KURL url = module_script->ResolveModuleSpecifier(requested.specifier);
    ModuleType module_type = modulator_->ModuleTypeFromRequest(requested);

    // <spec step="5.2">Assert: url is never failure, because resolving a module
    // specifier must have been previously successful with these same two
    // arguments.</spec>
    CHECK(url.IsValid()) << "ModuleScript::ResolveModuleSpecifier() impl must "
                            "return a valid url.";
    CHECK_NE(module_type, ModuleType::kInvalid);

    // <spec step="5.4">If visited set does not contain (url, module type),
    // then:</spec>
    if (!visited_set_.Contains(std::make_pair(url, module_type))) {
      // <spec step="5.4.1">Append (url, module type) to moduleRequests.</spec>
      module_requests.emplace_back(url, module_type, requested.position);

      // <spec step="5.4.2">Append (url, module type) to visited set.</spec>
      visited_set_.insert(std::make_pair(url, module_type));
    }
  }

  if (module_requests.empty()) {
    // <spec step="3">... if record.[[RequestedModules]] is empty,
    // asynchronously complete this algorithm with module script.</spec>
    //
    // Also, if record.[[RequestedModules]] is not empty but |module_requests|
    // is empty here, we complete this algorithm.
    FinalizeFetchDescendantsForOneModuleScript();
    return;
  }

  // <spec step="8">For each moduleRequest in moduleRequests, ...</spec>
  //
  // <spec step="8">... These invocations of the internal module script graph
  // fetching procedure should be performed in parallel to each other.
  // ...</spec>
  for (const auto& module_request : module_requests) {
    // <spec
    // href="https://html.spec.whatwg.org/C/#descendant-script-fetch-options">
    // For any given script fetch options options, the descendant script fetch
    // options are a new script fetch options whose items all have the same
    // values, except for the integrity metadata, which is instead the empty
    // string.</spec>
    //
    // <spec
    // href="https://wicg.github.io/priority-hints/#script">
    // descendant scripts get "auto" fetchpriority (only the main script
    // resource is affected by Priority Hints).
    ScriptFetchOptions options(
        module_script->FetchOptions().Nonce(),
        modulator_->GetIntegrityMetadata(module_request.url),
        modulator_->GetIntegrityMetadataString(module_request.url),
        module_script->FetchOptions().ParserState(),
        module_script->FetchOptions().CredentialsMode(),
        module_script->FetchOptions().GetReferrerPolicy(),
        mojom::blink::FetchPriorityHint::kAuto,
        RenderBlockingBehavior::kNonBlocking);
    // <spec step="8">... perform the internal module script graph fetching
    // procedure given moduleRequest, fetch client settings object, destination,
    // options, module script's settings object, visited set, and module
    // script's base URL. ...</spec>
    ModuleScriptFetchRequest request(
        module_request.url, module_request.module_type, context_type_,
        destination_, options, module_script->BaseUrl().GetString(),
        module_request.position);

    // <spec label="IMSGF" step="1">Assert: visited set contains url.</spec>
    DCHECK(visited_set_.Contains(
        std::make_pair(request.Url(), request.GetExpectedModuleType())));

    ++num_incomplete_fetches_;

    // <spec label="IMSGF" step="2">Fetch a single module script given url,
    // fetch client settings object, destination, options, module map settings
    // object, referrer, and with the top-level module fetch flag unset.
    // ...</spec>
    modulator_->FetchSingle(
        request, fetch_client_settings_object_fetcher_.Get(),
        ModuleGraphLevel::kDependentModuleFetch, custom_fetch_type_, this);
  }

  // Asynchronously continue processing after NotifyModuleLoadFinished() is
  // called num_incomplete_fetches_ times.
  CHECK_GT(num_incomplete_fetches_, 0u);
}

void ModuleTreeLinker::FinalizeFetchDescendantsForOneModuleScript() {
  // [FD] of a single module script is completed here:
  //
  // <spec step="8">... Otherwise, wait until all of the internal module script
  // graph fetching procedure invocations have asynchronously completed.
  // ...</spec>

  // And, if |num_incomplete_fetches_| is 0, all the invocations of
  // #fetch-the-descendants-of-a-module-script is completed here and we proceed
  // to #fetch-the-descendants-of-and-instantiate-a-module-script Step 3
  // implemented by Instantiate().
  if (num_incomplete_fetches_ == 0)
    Instantiate();
}

// <specdef
// href="https://html.spec.whatwg.org/C/#fetch-the-descendants-of-and-link-a-module-script">
void ModuleTreeLinker::Instantiate() {
  // [nospec] Abort the steps if the browsing context is discarded.
  if (!modulator_->HasValidContext()) {
    result_ = nullptr;
    AdvanceState(State::kFinished);
    return;
  }

  // <spec step="3">If result is null, then asynchronously complete this
  // algorithm with result.</spec>
  if (!result_) {
    AdvanceState(State::kFinished);
    return;
  }

  // <spec step="5">If parse error is null, then:</spec>
  //
  // [Optimization] If |found_parse_error_| is false (i.e. no parse errors
  // were found during fetching), we are sure that |parse error| is null and
  // thus skip FindFirstParseError() call.
  if (!found_parse_error_) {
#if DCHECK_IS_ON()
    HeapHashSet<Member<const ModuleScript>> discovered_set;
    DCHECK(FindFirstParseError(result_, &discovered_set).IsEmpty());
#endif

    // <spec step="5.1">Let record be result's record.</spec>
    v8::Local<v8::Module> record = result_->V8Module();

    // <spec step="5.2">Perform record.Instantiate(). ...</spec>
    AdvanceState(State::kInstantiating);

    ScriptState* script_state = modulator_->GetScriptState();
    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kInstantiateModuleScript);

    ScriptState::Scope scope(script_state);
    ScriptValue instantiation_error =
        ModuleRecord::Instantiate(script_state, record, result_->SourceUrl());

    // <spec step="5.2">... If this throws an exception, set result's error to
    // rethrow to that exception.</spec>
    if (!instantiation_error.IsEmpty())
      result_->SetErrorToRethrow(instantiation_error);
  } else {
    // <spec step="6">Otherwise, ...</spec>

    // <spec
    // href="https://html.spec.whatwg.org/C/#finding-the-first-parse-error"
    // step="2">If discoveredSet was not given, let it be an empty set.</spec>
    HeapHashSet<Member<const ModuleScript>> discovered_set;

    // <spec step="4">Let parse error be the result of finding the first parse
    // error given result.</spec>
    ScriptValue parse_error = FindFirstParseError(result_, &discovered_set);
    DCHECK(!parse_error.IsEmpty());

    // <spec step="6">... set result's error to rethrow to parse error.</spec>
    result_->SetErrorToRethrow(parse_error);
  }

  // <spec step="7">Asynchronously complete this algorithm with result.</spec>
  AdvanceState(State::kFinished);
}

// <specdef
// href="https://html.spec.whatwg.org/C/#finding-the-first-parse-error">
// This returns non-empty ScriptValue iff a parse error is found.
ScriptValue ModuleTreeLinker::FindFirstParseError(
    const ModuleScript* module_script,
    HeapHashSet<Member<const ModuleScript>>* discovered_set) const {
  // FindFirstParseError() is called only when there is no fetch errors, i.e.
  // all module scripts in the graph are non-null.
  DCHECK(module_script);

  // <spec step="1">Let moduleMap be moduleScript's settings object's module
  // map.</spec>
  //
  // This is accessed via |modulator_|.

  // [FFPE] Step 2 is done before calling this in Instantiate().

  // <spec step="3">Append moduleScript to discoveredSet.</spec>
  discovered_set->insert(module_script);

  // <spec step="4">If moduleScript's record is null, then return moduleScript's
  // parse error.</spec>
  v8::Local<v8::Module> record = module_script->V8Module();
  if (record.IsEmpty())
    return module_script->CreateParseError();

  // <spec step="5.1">Let childSpecifiers be the value of moduleScript's
  // record's [[RequestedModules]] internal slot.</spec>
  Vector<ModuleRequest> child_specifiers =
      ModuleRecord::ModuleRequests(modulator_->GetScriptState(), record);

  for (const auto& module_request : child_specifiers) {
    // <spec step="5.2">Let childURLs be the list obtained by calling resolve a
    // module specifier once for each item of childSpecifiers, given
    // moduleScript's base URL and that item. ...</spec>
    KURL child_url =
        module_script->ResolveModuleSpecifier(module_request.specifier);
    ModuleType child_module_type =
        modulator_->ModuleTypeFromRequest(module_request);

    // <spec step="5.2">... (None of these will ever fail, as otherwise
    // moduleScript would have been marked as itself having a parse
    // error.)</spec>
    CHECK(child_url.IsValid())
        << "ModuleScript::ResolveModuleSpecifier() impl must "
           "return a valid url.";
    CHECK_NE(child_module_type, ModuleType::kInvalid);

    // <spec step="5.3">Let childModules be the list obtained by getting each
    // value in moduleMap whose key is given by an item of childURLs.</spec>
    //
    // <spec step="5.4">For each childModule of childModules:</spec>
    const ModuleScript* child_module =
        modulator_->GetFetchedModuleScript(child_url, child_module_type);

    // <spec step="5.4.1">Assert: childModule is a module script (i.e., it is
    // not "fetching" or null); ...</spec>
    CHECK(child_module);

    // <spec step="5.4.2">If discoveredSet already contains childModule,
    // continue.</spec>
    if (discovered_set->Contains(child_module))
      continue;

    // <spec step="5.4.3">Let childParseError be the result of finding the first
    // parse error given childModule and discoveredSet.</spec>
    ScriptValue child_parse_error =
        FindFirstParseError(child_module, discovered_set);

    // <spec step="5.4.4">If childParseError is not null, return
    // childParseError.</spec>
    if (!child_parse_error.IsEmpty())
      return child_parse_error;
  }

  // <spec step="6">Return null.</spec>
  return ScriptValue();
}

#if DCHECK_IS_ON()
std::ostream& operator<<(std::ostream& stream, ModuleType module_type) {
  switch (module_type) {
    case ModuleType::kInvalid:
      stream << "Invalid";
      break;
    case ModuleType::kJavaScript:
      stream << "JavaScript";
      break;
    case ModuleType::kJSON:
      stream << "JSON";
      break;
    case ModuleType::kCSS:
      stream << "CSS";
      break;
  }
  return stream;
}

std::ostream& operator<<(std::ostream& stream, const ModuleTreeLinker& linker) {
  stream << "ModuleTreeLinker[" << &linker
         << ", original_url=" << linker.original_url_.GetString()
         << ", url=" << linker.url_.GetString()
         << ", module_type=" << linker.module_type_
         << ", inline=" << linker.root_is_inline_ << "]";
  return stream;
}
#endif

}  // namespace blink
```