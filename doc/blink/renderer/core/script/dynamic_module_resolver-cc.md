Response:
Let's break down the thought process for analyzing the `dynamic_module_resolver.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to web technologies, logic examples, common errors, and debugging tips. Essentially, a comprehensive understanding of its role within Blink.

2. **Initial Skim and Keywords:**  Read through the code quickly to identify key terms and concepts. "DynamicModuleResolver," "import()", "ModuleScript," "promise," "fetch," "URL," "specifier," "Modulator," "ScriptState," "V8," "TypeError,"  "top-level await" stand out. This immediately suggests involvement in JavaScript's dynamic import feature and module loading.

3. **Identify Core Functionality:** The function `ResolveDynamically` is the central entry point. Its arguments (`ModuleRequest`, `ReferrerScriptInfo`, `ScriptPromiseResolver`) and the overall flow (resolving a module specifier, fetching, executing, and resolving a promise) clearly indicate it handles the core logic of `import()`.

4. **Dissect `ResolveDynamically`:**  Go through `ResolveDynamically` step-by-step, relating the code comments back to the HTML specification references (`https://html.spec.whatwg.org/C/#hostimportmoduledynamically`). This helps understand *why* the code is doing what it's doing.

    * **Base URL Handling:**  Notice the logic for determining the base URL. This connects to how relative module specifiers are resolved.
    * **Module Specifier Resolution:** The call to `modulator_->ResolveModuleSpecifier` is crucial. This likely involves import maps and other resolution mechanisms.
    * **Fetch Options:** The construction of `ScriptFetchOptions` is important. It shows how fetch requests for modules are configured (CORS, credentials, etc.).
    * **`DynamicImportTreeClient`:** The creation and use of this class signals the asynchronous nature of module loading and the need for a callback mechanism.
    * **Error Handling:**  The checks for invalid URLs and module types, and the creation of `TypeError` exceptions, are significant.

5. **Analyze Helper Classes:** Examine the other classes and their methods:

    * **`DynamicImportTreeClient`:** Its `NotifyModuleTreeLoadFinished` method is the callback that gets executed after the module is fetched. It handles success (running the module script and resolving the promise) and failure (rejecting the promise). The `top-level await` handling is evident here.
    * **`ModuleResolutionCallback`, `ModuleResolutionSuccessCallback`, `ModuleResolutionFailureCallback`:** These classes represent different states of the asynchronous module resolution process and how the promise is resolved or rejected.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  The entire file revolves around JavaScript modules and the `import()` syntax. Provide concrete examples of `import()` statements.
    * **HTML:**  Explain how `<script type="module">` sets the stage for dynamic imports and how import maps in HTML influence module resolution.
    * **CSS:** While not directly involved, acknowledge that JavaScript modules can load CSS (e.g., via CSS Modules), thus creating an indirect link.

7. **Construct Logic Examples (Input/Output):**  Think of common scenarios and trace the execution flow:

    * **Successful Import:** A valid specifier leads to a successful fetch and execution, resulting in the module's namespace being the output.
    * **Failed Import (Resolution):** An invalid specifier leads to a `TypeError`.
    * **Failed Import (Fetch):** A network error or CORS issue results in a `TypeError`.

8. **Identify Common Usage Errors:**  Consider what mistakes developers might make when using dynamic imports:

    * **Incorrect Specifiers:**  Typographical errors or incorrect paths.
    * **CORS Issues:**  Trying to import modules from different origins without proper CORS headers.
    * **Network Problems:**  Connectivity issues.
    * **Import Maps Configuration:**  Errors in the import map.

9. **Outline Debugging Steps:**  Think about how a developer would arrive at this code during debugging:

    * **`import()` statement in JavaScript code.**
    * **Browser Developer Tools (Network tab, Console).**
    * **Breakpoints in the `DynamicModuleResolver::ResolveDynamically` function.**

10. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Use precise language and avoid jargon where possible, or explain it clearly. Ensure the examples are concrete and illustrative. Review for clarity and completeness.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus heavily on the `Modulator` class.
* **Correction:**  Realize that while `Modulator` is important, the core focus is the *resolution* process handled by `DynamicModuleResolver`. `Modulator` is a dependency.
* **Initial thought:**  Just list the functions.
* **Correction:** Explain the *purpose* of each function and class and how they contribute to the overall functionality.
* **Initial thought:**  Provide very technical code examples.
* **Correction:** Offer simplified, illustrative examples that are easier to understand for a broader audience.
* **Initial thought:**  Not explicitly connect to the HTML spec.
* **Correction:** Emphasize the spec references in the code to provide a deeper understanding of the implementation.

By following these steps and continually refining the understanding, a comprehensive and accurate analysis of the `dynamic_module_resolver.cc` file can be achieved.
This C++ source code file, `dynamic_module_resolver.cc`, located within the Blink rendering engine of Chromium, is responsible for handling the dynamic import of JavaScript modules. The dynamic import feature, accessed via the `import()` syntax in JavaScript, allows for loading modules on demand during runtime.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Initiating Module Fetching:** When JavaScript code executes an `import()` statement, this file's `ResolveDynamically` function is invoked. It takes the module specifier (the string path to the module), information about the referencing script, and a promise resolver as input.

2. **Resolving Module Specifiers:**  It resolves the provided module specifier (e.g., `./my-module.js`, `some-package`) into a full URL. This involves:
    * **Base URL Determination:**  Determining the base URL from which to resolve the specifier. This is usually the URL of the current document or the referencing script.
    * **Using the `Modulator`:**  It utilizes the `Modulator` class (a central component for module management in Blink) to perform the actual resolution, potentially taking into account import maps and other resolution mechanisms.

3. **Fetching the Module:** Once the full URL is resolved, it initiates the fetching of the module's source code. This involves creating a fetch request with appropriate options (e.g., CORS settings, credentials, integrity checks).

4. **Managing the Promise:** The `import()` syntax in JavaScript returns a Promise. This file manages the lifecycle of that Promise:
    * **Creating a `ScriptPromiseResolver`:**  It receives a `ScriptPromiseResolver` object, which is the mechanism for resolving or rejecting the JavaScript Promise.
    * **Handling Fetch Completion:** Upon successful fetching and parsing of the module, it executes the module's code within the appropriate JavaScript context.
    * **Resolving or Rejecting the Promise:**
        * **Success:** If the module loads and executes successfully, the Promise is resolved with the module's namespace object (containing its exported members).
        * **Failure:** If fetching fails (e.g., 404 error), resolution fails (e.g., invalid specifier), or the module throws an error during execution, the Promise is rejected with an appropriate error.

5. **Handling Top-Level Await:** The code specifically handles modules that utilize top-level `await`. This means the module's execution might involve asynchronous operations, and the Promise associated with the dynamic import will not resolve until these operations are complete.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file is a core part of implementing JavaScript's dynamic `import()` functionality. The `ResolveDynamically` function is directly triggered by JavaScript code. The success and failure of the operations in this file directly impact the resolution of the JavaScript Promise returned by `import()`.

    * **Example:**  Consider the JavaScript code:
      ```javascript
      async function loadModule() {
        try {
          const module = await import('./my-module.js');
          console.log(module.myExport);
        } catch (error) {
          console.error("Failed to load module:", error);
        }
      }
      loadModule();
      ```
      When `import('./my-module.js')` is encountered, the `DynamicModuleResolver` takes over to fetch and evaluate `my-module.js`. If `my-module.js` has an export named `myExport`, the `console.log` will output its value. If the import fails, the `catch` block will be executed.

* **HTML:**  While this file doesn't directly parse HTML, the context in which dynamic imports occur is within an HTML document. The base URL for resolving module specifiers is often derived from the HTML document's URL. Furthermore, `<script type="module">` elements in HTML define module contexts where dynamic imports can be used.

    * **Example:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <title>Dynamic Import Example</title>
      </head>
      <body>
        <script type="module">
          import('./another-module.js').then(module => {
            console.log("Loaded another module", module);
          });
        </script>
      </body>
      </html>
      ```
      In this HTML, the `<script type="module">` allows the use of `import()`. The `DynamicModuleResolver` will use the URL of this HTML file as the base URL to resolve `./another-module.js`.

* **CSS:**  While this file primarily deals with JavaScript modules, JavaScript modules can import or load CSS in various ways (e.g., using CSS Modules or dynamically creating `<link>` elements). Therefore, the successful loading of a JavaScript module handled by this file might indirectly lead to the loading of CSS.

**Logic Reasoning with Assumptions (Hypothetical Input and Output):**

**Assumption:** The JavaScript code in a web page contains:

```javascript
import('./my-component.js').then(module => {
  module.render();
}).catch(error => {
  console.error("Failed to load component:", error);
});
```

**Scenario 1: Successful Import**

* **Input:**
    * `module_request.specifier`: "./my-component.js"
    * `referrer_info.BaseURL()`: "https://example.com/page.html" (assuming the script is in `page.html`)
* **Processing within `DynamicModuleResolver`:**
    1. The specifier "./my-component.js" is resolved against the base URL "https://example.com/page.html" resulting in "https://example.com/my-component.js".
    2. A fetch request is made for "https://example.com/my-component.js".
    3. The server responds with the JavaScript code of `my-component.js`.
    4. The code is parsed and executed.
    5. If execution is successful, the module's namespace object is created.
* **Output:** The Promise associated with `import('./my-component.js')` resolves with the namespace object of `my-component.js`. The `then` callback in the JavaScript code is executed.

**Scenario 2: Failed Import (Resolution Error)**

* **Input:**
    * `module_request.specifier`: "./non-existent-component.js"
    * `referrer_info.BaseURL()`: "https://example.com/page.html"
* **Processing within `DynamicModuleResolver`:**
    1. The `Modulator` fails to resolve "./non-existent-component.js" against the base URL, potentially because no such file exists or import maps are misconfigured.
* **Output:** The Promise associated with `import('./non-existent-component.js')` is rejected with a `TypeError` indicating the failure to resolve the module specifier. The `catch` callback in the JavaScript code is executed.

**Scenario 3: Failed Import (Fetch Error)**

* **Input:**
    * `module_request.specifier`: "./my-component.js"
    * `referrer_info.BaseURL()`: "https://example.com/page.html"
* **Processing within `DynamicModuleResolver`:**
    1. The specifier is resolved to "https://example.com/my-component.js".
    2. A fetch request is made.
    3. The server responds with a 404 Not Found error.
* **Output:** The Promise associated with `import('./my-component.js')` is rejected with a `TypeError` indicating the failure to fetch the module. The `catch` callback in the JavaScript code is executed.

**Common Usage Errors and Examples:**

1. **Incorrect Module Specifier:**
   * **Error:** Providing a specifier that cannot be resolved.
   * **Example:** `import('my-component.js')` when the file is actually in a subdirectory like `import('./components/my-component.js')`. This will likely lead to a resolution error.

2. **CORS Issues:**
   * **Error:** Attempting to dynamically import a module from a different origin without proper CORS headers on the server serving the module.
   * **Example:**  A script on `https://example.com` tries to `import('https://another-domain.com/module.js')`, and `https://another-domain.com` does not send appropriate `Access-Control-Allow-Origin` headers. This will result in a fetch error due to CORS restrictions.

3. **Network Connectivity Problems:**
   * **Error:** The user's browser cannot connect to the server hosting the module.
   * **Example:** The user is offline or has a poor network connection. This will lead to a fetch error.

4. **Server-Side Errors:**
   * **Error:** The server responds with an error status code (e.g., 500 Internal Server Error) when trying to fetch the module.
   * **Example:** The module file exists, but the server has an issue processing the request. This will result in a fetch error.

**User Operations Leading to This Code (Debugging Clues):**

1. **User interacts with a web page:**  The user navigates to a web page that contains JavaScript code using dynamic `import()`.
2. **JavaScript execution reaches an `import()` statement:** The browser's JavaScript engine starts executing the script. When it encounters an `import()` statement, it needs to fetch and load the specified module.
3. **`DynamicModuleResolver::ResolveDynamically` is called:** The JavaScript engine in Blink calls this function to handle the dynamic import request.
4. **Debugging steps:**
   * **Setting a breakpoint:** A developer debugging the dynamic import process might set a breakpoint within the `DynamicModuleResolver::ResolveDynamically` function or in the `DynamicImportTreeClient::NotifyModuleTreeLoadFinished` callback to inspect the module specifier, resolved URL, fetch options, or the state of the Promise.
   * **Observing network requests:** The developer would use the browser's developer tools (Network tab) to examine the network request made for the module, checking the URL, headers (including CORS), and response status.
   * **Checking the console:**  Error messages generated during module resolution or fetching (e.g., `TypeError: Failed to resolve module specifier`) would provide clues about where the process failed.
   * **Examining import maps:** If import maps are involved, the developer would inspect the configured import maps to ensure they are correctly mapping specifiers to URLs.

In essence, `dynamic_module_resolver.cc` is a crucial component in Blink's implementation of JavaScript modules, specifically responsible for the asynchronous process of fetching and loading modules initiated by the `import()` syntax. It bridges the gap between JavaScript code and the underlying network and module loading mechanisms of the browser.

### 提示词
```
这是目录为blink/renderer/core/script/dynamic_module_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/script/dynamic_module_resolver.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/module_script.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class DynamicImportTreeClient final : public ModuleTreeClient {
 public:
  DynamicImportTreeClient(const KURL& url,
                          Modulator* modulator,
                          ScriptPromiseResolver<IDLAny>* promise_resolver)
      : url_(url), modulator_(modulator), promise_resolver_(promise_resolver) {}

  void Trace(Visitor*) const override;

 private:
  // Implements ModuleTreeClient:
  void NotifyModuleTreeLoadFinished(ModuleScript*) final;

  const KURL url_;
  const Member<Modulator> modulator_;
  const Member<ScriptPromiseResolver<IDLAny>> promise_resolver_;
};

// Abstract callback for modules resolution.
class ModuleResolutionCallback
    : public ThenCallable<IDLAny, ModuleResolutionCallback> {
 public:
  explicit ModuleResolutionCallback(
      ScriptPromiseResolver<IDLAny>* promise_resolver)
      : promise_resolver_(promise_resolver) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(promise_resolver_);
    ThenCallable<IDLAny, ModuleResolutionCallback>::Trace(visitor);
  }

  virtual void React(ScriptState* script_state, ScriptValue value) = 0;

 protected:
  Member<ScriptPromiseResolver<IDLAny>> promise_resolver_;
};

// Callback for modules with top-level await.
// Called on successful resolution.
class ModuleResolutionSuccessCallback final : public ModuleResolutionCallback {
 public:
  ModuleResolutionSuccessCallback(
      ScriptPromiseResolver<IDLAny>* promise_resolver,
      ModuleScript* module_script)
      : ModuleResolutionCallback(promise_resolver),
        module_script_(module_script) {}

  void Trace(Visitor* visitor) const final {
    visitor->Trace(module_script_);
    ModuleResolutionCallback::Trace(visitor);
  }

 private:
  void React(ScriptState* script_state, ScriptValue value) final {
    ScriptState::Scope scope(script_state);
    v8::Local<v8::Module> record = module_script_->V8Module();
    v8::Local<v8::Value> module_namespace = ModuleRecord::V8Namespace(record);
    promise_resolver_->Resolve(module_namespace);
  }

  Member<ModuleScript> module_script_;
};

// Callback for modules with top-level await.
// Called on unsuccessful resolution.
class ModuleResolutionFailureCallback final : public ModuleResolutionCallback {
 public:
  explicit ModuleResolutionFailureCallback(
      ScriptPromiseResolver<IDLAny>* promise_resolver)
      : ModuleResolutionCallback(promise_resolver) {}

 private:
  void React(ScriptState* script_state, ScriptValue exception) final {
    ScriptState::Scope scope(script_state);
    promise_resolver_->Reject(exception);
  }
};

// Implements steps 2 and 9-10 of
// <specdef
// href="https://html.spec.whatwg.org/C/#hostimportmoduledynamically(referencingscriptormodule,-specifier,-promisecapability)">
void DynamicImportTreeClient::NotifyModuleTreeLoadFinished(
    ModuleScript* module_script) {
  // [nospec] Abort the steps if the browsing context is discarded.
  if (!modulator_->HasValidContext()) {
    // The promise_resolver_ should have ::Detach()-ed at this point,
    // so ::Reject() is not necessary.
    return;
  }

  ScriptState* script_state = modulator_->GetScriptState();
  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();

  // <spec step="2">If settings object's ...</spec>
  if (!module_script) {
    // <spec step="2.1">Let completion be Completion { [[Type]]: throw,
    // [[Value]]: a new TypeError, [[Target]]: empty }.</spec>
    v8::Local<v8::Value> error = V8ThrowException::CreateTypeError(
        isolate,
        "Failed to fetch dynamically imported module: " + url_.GetString());

    // <spec step="2.2">Perform FinishDynamicImport(referencingScriptOrModule,
    // specifier, promiseCapability, completion).</spec>
    promise_resolver_->Reject(error);

    // <spec step="2.3">Return.</spec>
    return;
  }

  // <spec step="9">Otherwise, set promise to the result of running a module
  // script given result and true.</spec>
  ScriptEvaluationResult result =
      module_script->RunScriptOnScriptStateAndReturnValue(
          script_state,
          ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled,
          V8ScriptRunner::RethrowErrorsOption::Rethrow(String()));

  switch (result.GetResultType()) {
    case ScriptEvaluationResult::ResultType::kException:
      // With top-level await, even though according to spec a promise is always
      // returned, the kException case is still reachable when there is a parse
      // or instantiation error.
      promise_resolver_->Reject(result.GetExceptionForModule());
      break;

    case ScriptEvaluationResult::ResultType::kNotRun:
    case ScriptEvaluationResult::ResultType::kAborted:
      // Do nothing when script is disabled or after a script is aborted.
      break;

    case ScriptEvaluationResult::ResultType::kSuccess: {
      // <spec step="10">Perform
      // FinishDynamicImport(referencingScriptOrModule, specifier,
      // promiseCapability, promise).</spec>
      result.GetPromise(script_state)
          .Then(script_state,
                MakeGarbageCollected<ModuleResolutionSuccessCallback>(
                    promise_resolver_, module_script),
                MakeGarbageCollected<ModuleResolutionFailureCallback>(
                    promise_resolver_));
      break;
    }
  }
}

void DynamicImportTreeClient::Trace(Visitor* visitor) const {
  visitor->Trace(modulator_);
  visitor->Trace(promise_resolver_);
  ModuleTreeClient::Trace(visitor);
}

}  // namespace

void DynamicModuleResolver::Trace(Visitor* visitor) const {
  visitor->Trace(modulator_);
}

// <specdef
// href="https://html.spec.whatwg.org/C/#hostimportmoduledynamically(referencingscriptormodule,-specifier,-promisecapability)">
void DynamicModuleResolver::ResolveDynamically(
    const ModuleRequest& module_request,
    const ReferrerScriptInfo& referrer_info,
    ScriptPromiseResolver<IDLAny>* promise_resolver) {
  DCHECK(modulator_->GetScriptState()->GetIsolate()->InContext())
      << "ResolveDynamically should be called from V8 callback, within a valid "
         "context.";

  // <spec step="4.1">Let referencing script be
  // referencingScriptOrModule.[[HostDefined]].</spec>

  // <spec step="4.3">Set base URL to referencing script's base URL.</spec>
  KURL base_url = referrer_info.BaseURL();
  if (base_url.IsNull()) {
    // The case where "referencing script" doesn't exist.
    //
    // <spec step="1">Let settings object be the current settings object.</spec>
    //
    // <spec step="2">Let base URL be settings object's API base URL.</spec>
    base_url = ExecutionContext::From(modulator_->GetScriptState())->BaseURL();
  }
  DCHECK(!base_url.IsNull());

  // <spec step="5">Fetch an import() module script graph given specifier, base
  // URL, settings object, and fetch options. Wait until the algorithm
  // asynchronously completes with result.</spec>
  //
  // <specdef label="fetch-an-import()-module-script-graph"
  // href="https://html.spec.whatwg.org/C/#fetch-an-import()-module-script-graph">

  // https://wicg.github.io/import-maps/#wait-for-import-maps
  // 1.2. Set document’s acquiring import maps to false. [spec text]
  modulator_->SetAcquiringImportMapsState(
      Modulator::AcquiringImportMapsState::kAfterModuleScriptLoad);

  // <spec label="fetch-an-import()-module-script-graph" step="1">Let url be the
  // result of resolving a module specifier given base URL and specifier.</spec>
  KURL url = modulator_->ResolveModuleSpecifier(
      module_request.specifier, base_url, /*failure_reason=*/nullptr);

  ModuleType module_type = modulator_->ModuleTypeFromRequest(module_request);

  // <spec label="fetch-an-import()-module-script-graph" step="2">If url is
  // failure, then asynchronously complete this algorithm with null, and abort
  // these steps.</spec>
  if (!url.IsValid() || module_type == ModuleType::kInvalid) {
    // <spec step="6">If result is null, then:</spec>
    String error_message;
    if (!url.IsValid()) {
      error_message = "Failed to resolve module specifier '" +
                      module_request.specifier + "'";
      if (referrer_info.BaseURL().IsAboutBlankURL() &&
          base_url.IsAboutBlankURL()) {
        error_message =
            error_message +
            ". The base URL is about:blank because import() is called from a "
            "CORS-cross-origin script.";
      }

    } else {
      error_message = "\"" + module_request.GetModuleTypeString() +
                      "\" is not a valid module type.";
    }

    // <spec step="6.1">Let completion be Completion { [[Type]]: throw,
    // [[Value]]: a new TypeError, [[Target]]: empty }.</spec>
    v8::Isolate* isolate = modulator_->GetScriptState()->GetIsolate();
    v8::Local<v8::Value> error =
        V8ThrowException::CreateTypeError(isolate, error_message);

    // <spec step="6.2">Perform FinishDynamicImport(referencingScriptOrModule,
    // specifier, promiseCapability, completion).</spec>
    //
    // <spec
    // href="https://tc39.github.io/proposal-dynamic-import/#sec-finishdynamicimport"
    // step="1">If completion is an abrupt completion, then perform !
    // Call(promiseCapability.[[Reject]], undefined, « completion.[[Value]]
    // »).</spec>
    promise_resolver->Reject(error);

    // <spec step="6.3">Return.</spec>
    return;
  }

  // <spec step="4.4">Set fetch options to the descendant script fetch options
  // for referencing script's fetch options.</spec>
  //
  // <spec
  // href="https://html.spec.whatwg.org/C/#descendant-script-fetch-options"> For
  // any given script fetch options options, the descendant script fetch options
  // are a new script fetch options whose items all have the same values, except
  // for the integrity metadata, which is instead the empty string.</spec>
  //
  // <spec href="https://wicg.github.io/priority-hints/#script">
  // dynamic imports get kAuto. Only the main script resource is impacted by
  // Priority Hints.
  //
  ScriptFetchOptions options(
      referrer_info.Nonce(), modulator_->GetIntegrityMetadata(url),
      modulator_->GetIntegrityMetadataString(url), referrer_info.ParserState(),
      referrer_info.CredentialsMode(), referrer_info.GetReferrerPolicy(),
      mojom::blink::FetchPriorityHint::kAuto,
      RenderBlockingBehavior::kNonBlocking);

  // <spec label="fetch-an-import()-module-script-graph" step="3">Fetch a single
  // module script given url, settings object, "script", options, settings
  // object, "client", and with the top-level module fetch flag set. If the
  // caller of this algorithm specified custom perform the fetch steps, pass
  // those along as well. Wait until the algorithm asynchronously completes with
  // result.</spec>
  auto* tree_client = MakeGarbageCollected<DynamicImportTreeClient>(
      url, modulator_.Get(), promise_resolver);
  // TODO(kouhei): ExecutionContext::From(modulator_->GetScriptState()) is
  // highly discouraged since it breaks layering. Rewrite this.
  auto* execution_context =
      ExecutionContext::From(modulator_->GetScriptState());
  modulator_->FetchTree(url, module_type, execution_context->Fetcher(),
                        mojom::blink::RequestContextType::SCRIPT,
                        network::mojom::RequestDestination::kScript, options,
                        ModuleScriptCustomFetchType::kNone, tree_client,
                        referrer_info.BaseURL().GetString());

  // Steps 6-9 are implemented at
  // DynamicImportTreeClient::NotifyModuleLoadFinished.

  // <spec step="10">Return undefined.</spec>
}

}  // namespace blink
```